//! QEMU virtual smart card integration.
//!
//! Bridges the simrs SIM simulator to QEMU via shared-memory transport.
//! The [`QemuBridge`] struct wraps a [`Sim`] and processes commands from
//! the shared-memory command ring, writing responses to the response ring.
//!
//! # Architecture
//!
//! ```text
//! QEMU guest (Shannon firmware)
//!   -> writes APDU to shmem cmd ring
//!   -> QemuBridge::step() reads cmd, calls Sim::process()
//!   -> writes response to shmem rsp ring
//!   -> guest reads response
//! ```
//!
//! The shared-memory region is borrowed (`&'a mut [u8]`), so `mmap()`
//! is deferred to the caller. The bridge operates on raw byte slices.
//!
//! # Message framing
//!
//! Each message in the ring buffers is framed with the standard 2-byte LE
//! length prefix (from `simrs-transport-shmem`). The first byte of the
//! payload is a [`ShmemMsgType`] tag, followed by the message-specific data.
//!
//! # Example
//!
//! ```rust,ignore
//! let mut shmem = vec![0u8; ShmemHeader::new(4096).total_size()];
//! let sim = Sim::new(&ATR, &MF);
//! let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
//! // Event loop:
//! while bridge.step().unwrap() { }
//! ```

use simrs_sim::{Sim, SimEvent, SimResponse};
use simrs_transport_shmem::{ring_read, ring_write, ShmemHeader, HEADER_SIZE};

// ---------------------------------------------------------------------------
// ShmemMsgType
// ---------------------------------------------------------------------------

/// Message type tag prepended to ring buffer payloads.
///
/// This is a 1-byte discriminator placed as the first byte of every
/// message payload inside the ring.
///
/// # Example
///
/// ```
/// use simrs_qemu::ShmemMsgType;
///
/// assert_eq!(ShmemMsgType::Apdu as u8, 0x01);
/// assert_eq!(ShmemMsgType::from_u8(0x02), Some(ShmemMsgType::PowerOn));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ShmemMsgType {
    /// APDU command (cmd ring) or response (rsp ring).
    Apdu = 0x01,
    /// Power-on request (cmd ring) or ATR response (rsp ring).
    PowerOn = 0x02,
    /// Power-off notification.
    PowerOff = 0x03,
    /// Warm reset request (cmd ring) or ATR response (rsp ring).
    WarmReset = 0x04,
    /// ATR response (rsp ring only).
    Atr = 0x05,
}

impl ShmemMsgType {
    /// Parse from a `u8`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Apdu),
            0x02 => Some(Self::PowerOn),
            0x03 => Some(Self::PowerOff),
            0x04 => Some(Self::WarmReset),
            0x05 => Some(Self::Atr),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// QemuBridgeError
// ---------------------------------------------------------------------------

/// Errors from [`QemuBridge`] operations.
///
/// # Example
///
/// ```
/// use simrs_qemu::QemuBridgeError;
/// let e = QemuBridgeError::InvalidHeader;
/// assert_eq!(e, QemuBridgeError::InvalidHeader);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuBridgeError {
    /// The shmem header is invalid (wrong magic, version, or ring size).
    InvalidHeader,
    /// A message in the ring has an unrecognized type tag.
    InvalidMessage,
    /// The response ring is full; cannot write the response.
    RingFull,
    /// The response buffer is too small for the outgoing data.
    BufferTooSmall,
}

impl core::fmt::Display for QemuBridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidHeader => f.write_str("invalid shmem header"),
            Self::InvalidMessage => f.write_str("invalid message in ring"),
            Self::RingFull => f.write_str("response ring full"),
            Self::BufferTooSmall => f.write_str("response buffer too small"),
        }
    }
}

// ---------------------------------------------------------------------------
// QemuBridge
// ---------------------------------------------------------------------------

/// Maximum message payload (1 type byte + 261 APDU bytes).
const MSG_PAYLOAD_MAX: usize = 262;

// Shmem header field offsets (must match `ShmemHeader` layout).
const HDR_CMD_HEAD: usize = 12;
const HDR_CMD_TAIL: usize = 16;
const HDR_RSP_HEAD: usize = 20;
const HDR_RSP_TAIL: usize = 24;

/// Pre-encoded fallback APDU response: type=Apdu(0x01), SW=6F00 (no precise diagnosis).
/// Sent when `Sim::process` returns `Ignored` so the guest is not left waiting.
const FALLBACK_APDU_RSP: [u8; 3] = [ShmemMsgType::Apdu as u8, 0x6F, 0x00];

/// QEMU-to-simrs bridge over borrowed shared memory.
///
/// Holds a [`Sim`] instance and processes commands from the shared-memory
/// command ring one at a time via [`step`](Self::step).
pub struct QemuBridge<'a, const RSP_CAP: usize = 256> {
    sim: Sim<RSP_CAP>,
    shmem: &'a mut [u8],
    ring_size: u32,
    cmd_head: u32,
    cmd_tail: u32,
    rsp_head: u32,
    rsp_tail: u32,
}

impl<const RSP_CAP: usize> core::fmt::Debug for QemuBridge<'_, RSP_CAP> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QemuBridge")
            .field("ring_size", &self.ring_size)
            .field("cmd_head", &self.cmd_head)
            .field("cmd_tail", &self.cmd_tail)
            .field("rsp_head", &self.rsp_head)
            .field("rsp_tail", &self.rsp_tail)
            .finish_non_exhaustive()
    }
}

impl<'a, const RSP_CAP: usize> QemuBridge<'a, RSP_CAP> {
    /// Create a new bridge from a [`Sim`] and a borrowed shmem region.
    ///
    /// Validates the shmem header and initializes local ring indices.
    ///
    /// # Errors
    ///
    /// Returns [`QemuBridgeError::InvalidHeader`] if the shmem header
    /// cannot be decoded or the region is too small.
    pub fn new(sim: Sim<RSP_CAP>, shmem: &'a mut [u8]) -> Result<Self, QemuBridgeError> {
        let hdr = ShmemHeader::decode(shmem).ok_or(QemuBridgeError::InvalidHeader)?;

        if shmem.len() < hdr.total_size() {
            return Err(QemuBridgeError::InvalidHeader);
        }

        Ok(Self {
            sim,
            shmem,
            ring_size: hdr.ring_size,
            cmd_head: hdr.cmd_head,
            cmd_tail: hdr.cmd_tail,
            rsp_head: hdr.rsp_head,
            rsp_tail: hdr.rsp_tail,
        })
    }

    /// Process one command from the cmd ring.
    ///
    /// Returns `Ok(true)` if a command was processed, `Ok(false)` if
    /// the command ring is empty, or an error.
    ///
    /// # Errors
    ///
    /// - [`QemuBridgeError::InvalidMessage`] if the message type tag is
    ///   unrecognized.
    /// - [`QemuBridgeError::RingFull`] if the response cannot be written.
    pub fn step(&mut self) -> Result<bool, QemuBridgeError> {
        // Refresh cmd_head from shmem (producer may have advanced it).
        self.cmd_head = read_u32_le(self.shmem, HDR_CMD_HEAD);

        let cmd_ring_start = HEADER_SIZE;
        let cmd_ring_end = cmd_ring_start + self.ring_size as usize;
        let cmd_ring = &self.shmem[cmd_ring_start..cmd_ring_end];

        let mut msg_buf = [0u8; MSG_PAYLOAD_MAX];
        let Some((new_tail, len)) = ring_read(
            cmd_ring,
            self.cmd_head,
            self.cmd_tail,
            self.ring_size,
            &mut msg_buf,
        ) else {
            return Ok(false);
        };
        self.cmd_tail = new_tail;

        // Write back cmd_tail to shmem.
        write_u32_le(self.shmem, HDR_CMD_TAIL, self.cmd_tail);

        if len == 0 {
            return Err(QemuBridgeError::InvalidMessage);
        }

        let msg_type =
            ShmemMsgType::from_u8(msg_buf[0]).ok_or(QemuBridgeError::InvalidMessage)?;

        // Copy command payload into a stack buffer (needed because
        // process() borrows self.sim mutably, and we need the payload
        // to outlive that borrow).
        let mut cmd_payload = [0u8; MSG_PAYLOAD_MAX];
        let payload_len = len - 1;
        cmd_payload[..payload_len].copy_from_slice(&msg_buf[1..len]);

        match msg_type {
            ShmemMsgType::PowerOn => {
                let rsp = self.sim.process(SimEvent::PowerOn);
                let mut rsp_buf = [0u8; MSG_PAYLOAD_MAX];
                if let Some(n) = encode_response(ShmemMsgType::Atr, &rsp, &mut rsp_buf) {
                    self.write_rsp_ring(&rsp_buf[..n])?;
                }
            }
            ShmemMsgType::WarmReset => {
                let rsp = self.sim.process(SimEvent::Reset);
                let mut rsp_buf = [0u8; MSG_PAYLOAD_MAX];
                if let Some(n) = encode_response(ShmemMsgType::Atr, &rsp, &mut rsp_buf) {
                    self.write_rsp_ring(&rsp_buf[..n])?;
                }
            }
            ShmemMsgType::PowerOff => {
                // No response needed for power-off.
            }
            ShmemMsgType::Apdu => {
                let rsp = self.sim.process(SimEvent::Apdu(&cmd_payload[..payload_len]));
                let mut rsp_buf = [0u8; MSG_PAYLOAD_MAX];
                if let Some(n) = encode_response(ShmemMsgType::Apdu, &rsp, &mut rsp_buf) {
                    self.write_rsp_ring(&rsp_buf[..n])?;
                } else {
                    // SimResponse::Ignored -- send pre-encoded 6F 00
                    // ("no precise diagnosis") so the guest is not left waiting.
                    self.write_rsp_ring(&FALLBACK_APDU_RSP)?;
                }
            }
            ShmemMsgType::Atr => {
                // ATR in the cmd ring is unexpected.
                return Err(QemuBridgeError::InvalidMessage);
            }
        }

        Ok(true)
    }

    /// Write local ring indices back to the shmem header.
    ///
    /// Call this after processing to make indices visible to the peer.
    pub fn flush_indices(&mut self) {
        write_u32_le(self.shmem, HDR_CMD_HEAD, self.cmd_head);
        write_u32_le(self.shmem, HDR_CMD_TAIL, self.cmd_tail);
        write_u32_le(self.shmem, HDR_RSP_HEAD, self.rsp_head);
        write_u32_le(self.shmem, HDR_RSP_TAIL, self.rsp_tail);
    }

    /// Access the inner [`Sim`] for configuration.
    pub const fn sim_mut(&mut self) -> &mut Sim<RSP_CAP> {
        &mut self.sim
    }

    // -- internal helpers --

    /// Write an already-encoded response to the rsp ring.
    fn write_rsp_ring(&mut self, data: &[u8]) -> Result<(), QemuBridgeError> {
        // Refresh rsp_tail from shmem (consumer may have advanced it).
        self.rsp_tail = read_u32_le(self.shmem, HDR_RSP_TAIL);

        let rsp_ring_start = HEADER_SIZE + self.ring_size as usize;
        let rsp_ring_end = rsp_ring_start + self.ring_size as usize;
        let rsp_ring = &mut self.shmem[rsp_ring_start..rsp_ring_end];

        let new_head = ring_write(rsp_ring, self.rsp_head, self.rsp_tail, self.ring_size, data)
            .ok_or(QemuBridgeError::RingFull)?;

        self.rsp_head = new_head;
        // Write back rsp_head to shmem.
        write_u32_le(self.shmem, HDR_RSP_HEAD, self.rsp_head);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Encode a [`SimResponse`] into a ring message payload.
///
/// Format: `[msg_type_byte] [payload_bytes...]`
///
/// Returns the total number of bytes written, or `None` if `buf` is too small.
fn encode_response(
    msg_type: ShmemMsgType,
    response: &SimResponse<'_>,
    buf: &mut [u8],
) -> Option<usize> {
    match response {
        SimResponse::Atr(atr) => {
            let total = 1 + atr.len();
            if buf.len() < total {
                return None;
            }
            buf[0] = msg_type as u8;
            buf[1..total].copy_from_slice(atr);
            Some(total)
        }
        SimResponse::Apdu { data, sw1, sw2 } => {
            let total = 1 + data.len() + 2;
            if buf.len() < total {
                return None;
            }
            buf[0] = msg_type as u8;
            buf[1..=data.len()].copy_from_slice(data);
            buf[data.len() + 1] = *sw1;
            buf[data.len() + 2] = *sw2;
            Some(total)
        }
        SimResponse::Ignored => {
            // Nothing to write for Ignored.
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_fs::{DfDef, EfDef, EfStructure, FileRef};
    use simrs_sim::Sim;
    use simrs_transport_shmem::{ShmemHeader, MAGIC, VERSION};

    const RING_SIZE: u32 = 512;

    // -- Test filesystem statics --

    static ICCID_DATA: [u8; 10] =
        [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

    static EF_ICCID: EfDef = EfDef {
        fid: 0x2FE2,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &ICCID_DATA,
    };

    static MF: DfDef = DfDef {
        fid: 0x3F00,
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

    fn make_sim() -> Sim<256> {
        Sim::<256>::new(&ATR, &MF)
    }

    /// Create a shmem region with a valid header and empty rings.
    fn make_shmem() -> Vec<u8> {
        let hdr = ShmemHeader::new(RING_SIZE);
        let mut buf = vec![0u8; hdr.total_size()];
        hdr.encode(&mut buf).unwrap();
        buf
    }

    /// Write a command message to the cmd ring.
    fn push_cmd(shmem: &mut [u8], msg_type: ShmemMsgType, payload: &[u8]) {
        let mut msg = vec![msg_type as u8];
        msg.extend_from_slice(payload);

        let ring_start = HEADER_SIZE;
        let ring_end = ring_start + RING_SIZE as usize;

        let head = read_u32_le(shmem, 12);
        let tail = read_u32_le(shmem, 16);

        let new_head = ring_write(
            &mut shmem[ring_start..ring_end],
            head,
            tail,
            RING_SIZE,
            &msg,
        )
        .expect("ring_write failed");

        write_u32_le(shmem, 12, new_head);
    }

    /// Read a response message from the rsp ring.
    fn pop_rsp(shmem: &mut [u8]) -> Option<(ShmemMsgType, Vec<u8>)> {
        let ring_start = HEADER_SIZE + RING_SIZE as usize;
        let ring_end = ring_start + RING_SIZE as usize;

        let head = read_u32_le(shmem, 20);
        let tail = read_u32_le(shmem, 24);

        let mut out = [0u8; MSG_PAYLOAD_MAX];
        let (new_tail, len) = ring_read(
            &shmem[ring_start..ring_end],
            head,
            tail,
            RING_SIZE,
            &mut out,
        )?;

        write_u32_le(shmem, 24, new_tail);

        let msg_type = ShmemMsgType::from_u8(out[0])?;
        Some((msg_type, out[1..len].to_vec()))
    }

    // -- ShmemMsgType --

    #[test]
    fn msg_type_from_u8_valid() {
        assert_eq!(ShmemMsgType::from_u8(0x01), Some(ShmemMsgType::Apdu));
        assert_eq!(ShmemMsgType::from_u8(0x02), Some(ShmemMsgType::PowerOn));
        assert_eq!(ShmemMsgType::from_u8(0x03), Some(ShmemMsgType::PowerOff));
        assert_eq!(ShmemMsgType::from_u8(0x04), Some(ShmemMsgType::WarmReset));
        assert_eq!(ShmemMsgType::from_u8(0x05), Some(ShmemMsgType::Atr));
    }

    #[test]
    fn msg_type_from_u8_invalid() {
        assert_eq!(ShmemMsgType::from_u8(0x00), None);
        assert_eq!(ShmemMsgType::from_u8(0x06), None);
        assert_eq!(ShmemMsgType::from_u8(0xFF), None);
    }

    // -- QemuBridgeError --

    #[test]
    fn error_display() {
        assert_eq!(
            format!("{}", QemuBridgeError::InvalidHeader),
            "invalid shmem header"
        );
        assert_eq!(
            format!("{}", QemuBridgeError::InvalidMessage),
            "invalid message in ring"
        );
        assert_eq!(
            format!("{}", QemuBridgeError::RingFull),
            "response ring full"
        );
        assert_eq!(
            format!("{}", QemuBridgeError::BufferTooSmall),
            "response buffer too small"
        );
    }

    #[test]
    fn error_equality() {
        assert_eq!(
            QemuBridgeError::InvalidHeader,
            QemuBridgeError::InvalidHeader
        );
        assert_ne!(QemuBridgeError::InvalidHeader, QemuBridgeError::RingFull);
    }

    // -- QemuBridge construction --

    #[test]
    fn new_with_valid_shmem() {
        let mut shmem = make_shmem();
        let sim = make_sim();
        let bridge = QemuBridge::new(sim, &mut shmem);
        assert!(bridge.is_ok());
    }

    #[test]
    fn new_with_invalid_header() {
        let mut shmem = vec![0u8; 1024];
        let sim = make_sim();
        let err = QemuBridge::new(sim, &mut shmem).unwrap_err();
        assert_eq!(err, QemuBridgeError::InvalidHeader);
    }

    #[test]
    fn new_with_truncated_shmem() {
        let hdr = ShmemHeader::new(RING_SIZE);
        // Encode header but allocate less than total_size.
        let mut shmem = vec![0u8; HEADER_SIZE + 10];
        hdr.encode(&mut shmem).unwrap();
        let sim = make_sim();
        let err = QemuBridge::new(sim, &mut shmem).unwrap_err();
        assert_eq!(err, QemuBridgeError::InvalidHeader);
    }

    // -- step() empty ring --

    #[test]
    fn step_empty_returns_false() {
        let mut shmem = make_shmem();
        let sim = make_sim();
        let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
        assert!(!bridge.step().unwrap());
    }

    // -- PowerOn --

    #[test]
    fn step_power_on_returns_atr() {
        let mut shmem = make_shmem();
        push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);

        {
            let sim = make_sim();
            let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
            assert!(bridge.step().unwrap());
        }

        let (msg_type, payload) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(msg_type, ShmemMsgType::Atr);
        assert_eq!(payload, &ATR);
    }

    // -- WarmReset --

    #[test]
    fn step_warm_reset_returns_atr() {
        let mut shmem = make_shmem();
        // Push PowerOn + WarmReset upfront.
        push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);
        push_cmd(&mut shmem, ShmemMsgType::WarmReset, &[]);

        {
            let sim = make_sim();
            let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
            assert!(bridge.step().unwrap()); // PowerOn
            assert!(bridge.step().unwrap()); // WarmReset
        }

        // Pop ATR from PowerOn.
        let (mt1, _) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(mt1, ShmemMsgType::Atr);
        // Pop ATR from WarmReset.
        let (mt2, payload) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(mt2, ShmemMsgType::Atr);
        assert_eq!(payload, &ATR);
    }

    // -- PowerOff --

    #[test]
    fn step_power_off_no_response() {
        let mut shmem = make_shmem();
        push_cmd(&mut shmem, ShmemMsgType::PowerOff, &[]);

        {
            let sim = make_sim();
            let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
            assert!(bridge.step().unwrap());
        }

        // No response should be in the rsp ring.
        assert!(pop_rsp(&mut shmem).is_none());
    }

    // -- APDU exchange --

    #[test]
    fn step_apdu_returns_response() {
        let mut shmem = make_shmem();
        // Push PowerOn + APDU upfront.
        push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);
        let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        push_cmd(&mut shmem, ShmemMsgType::Apdu, &select_mf);

        {
            let sim = make_sim();
            let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
            assert!(bridge.step().unwrap()); // PowerOn
            assert!(bridge.step().unwrap()); // APDU
        }

        // Pop ATR.
        let (mt1, _) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(mt1, ShmemMsgType::Atr);
        // Pop APDU response.
        let (mt2, payload) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(mt2, ShmemMsgType::Apdu);
        // Response should be at least 2 bytes (SW1 SW2).
        assert!(payload.len() >= 2);
    }

    // -- Invalid message type --

    #[test]
    fn step_atr_in_cmd_ring_is_error() {
        let mut shmem = make_shmem();
        push_cmd(&mut shmem, ShmemMsgType::Atr, &[0x3B, 0x00]);

        let sim = make_sim();
        let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
        let err = bridge.step().unwrap_err();
        assert_eq!(err, QemuBridgeError::InvalidMessage);
    }

    // -- Multiple commands --

    #[test]
    fn step_multiple_commands() {
        let mut shmem = make_shmem();

        // Push all commands upfront.
        push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);
        let apdu = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        push_cmd(&mut shmem, ShmemMsgType::Apdu, &apdu);
        push_cmd(&mut shmem, ShmemMsgType::WarmReset, &[]);

        {
            let sim = make_sim();
            let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();

            assert!(bridge.step().unwrap()); // 1: PowerOn
            assert!(bridge.step().unwrap()); // 2: APDU
            assert!(bridge.step().unwrap()); // 3: WarmReset
            assert!(!bridge.step().unwrap()); // 4: empty
        }

        // Pop all responses.
        let (mt1, _) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(mt1, ShmemMsgType::Atr);

        let (mt2, _) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(mt2, ShmemMsgType::Apdu);

        let (mt3, _) = pop_rsp(&mut shmem).unwrap();
        assert_eq!(mt3, ShmemMsgType::Atr);

        // No more responses.
        assert!(pop_rsp(&mut shmem).is_none());
    }

    // -- flush_indices --

    #[test]
    fn flush_indices_updates_shmem() {
        let mut shmem = make_shmem();
        push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);

        {
            let sim = make_sim();
            let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
            bridge.step().unwrap();
            bridge.flush_indices();
        }

        // Verify header indices were updated.
        let hdr = ShmemHeader::decode(&shmem).unwrap();
        // cmd_tail should have advanced.
        assert!(hdr.cmd_tail > 0);
        // rsp_head should have advanced (ATR response written).
        assert!(hdr.rsp_head > 0);
    }

    // -- sim_mut --

    #[test]
    fn sim_mut_accessible() {
        let mut shmem = make_shmem();
        let sim = make_sim();
        let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
        let _sim = bridge.sim_mut();
    }

    // -- encode_response --

    #[test]
    fn encode_atr_response() {
        let atr = [0x3B, 0x9F, 0x96];
        let rsp = SimResponse::Atr(&atr);
        let mut buf = [0u8; 10];
        let n = encode_response(ShmemMsgType::Atr, &rsp, &mut buf).unwrap();
        assert_eq!(n, 4); // 1 type + 3 ATR
        assert_eq!(buf[0], ShmemMsgType::Atr as u8);
        assert_eq!(&buf[1..4], &atr);
    }

    #[test]
    fn encode_apdu_response_sw_only() {
        let rsp = SimResponse::Apdu {
            data: &[],
            sw1: 0x90,
            sw2: 0x00,
        };
        let mut buf = [0u8; 10];
        let n = encode_response(ShmemMsgType::Apdu, &rsp, &mut buf).unwrap();
        assert_eq!(n, 3); // 1 type + 0 data + 2 SW
        assert_eq!(buf[0], ShmemMsgType::Apdu as u8);
        assert_eq!(buf[1], 0x90);
        assert_eq!(buf[2], 0x00);
    }

    #[test]
    fn encode_apdu_response_with_data() {
        let rsp = SimResponse::Apdu {
            data: &[0x6F, 0x10],
            sw1: 0x90,
            sw2: 0x00,
        };
        let mut buf = [0u8; 10];
        let n = encode_response(ShmemMsgType::Apdu, &rsp, &mut buf).unwrap();
        assert_eq!(n, 5); // 1 type + 2 data + 2 SW
        assert_eq!(buf[0], ShmemMsgType::Apdu as u8);
        assert_eq!(&buf[1..3], &[0x6F, 0x10]);
        assert_eq!(buf[3], 0x90);
        assert_eq!(buf[4], 0x00);
    }

    #[test]
    fn encode_ignored_returns_none() {
        let rsp = SimResponse::Ignored;
        let mut buf = [0u8; 10];
        assert!(encode_response(ShmemMsgType::Apdu, &rsp, &mut buf).is_none());
    }

    #[test]
    fn encode_buffer_too_small() {
        let rsp = SimResponse::Atr(&[0x3B, 0x9F, 0x96, 0x80]);
        let mut buf = [0u8; 2]; // too small for 1 + 4
        assert!(encode_response(ShmemMsgType::Atr, &rsp, &mut buf).is_none());
    }

    // -- ShmemMsgType repr --

    #[test]
    fn msg_type_repr_values() {
        assert_eq!(ShmemMsgType::Apdu as u8, 0x01);
        assert_eq!(ShmemMsgType::PowerOn as u8, 0x02);
        assert_eq!(ShmemMsgType::PowerOff as u8, 0x03);
        assert_eq!(ShmemMsgType::WarmReset as u8, 0x04);
        assert_eq!(ShmemMsgType::Atr as u8, 0x05);
    }

    // -- header constants --

    #[test]
    fn shmem_magic_and_version_match() {
        let shmem = make_shmem();
        assert_eq!(read_u32_le(&shmem, 0), MAGIC);
        assert_eq!(read_u32_le(&shmem, 4), VERSION);
    }
}
