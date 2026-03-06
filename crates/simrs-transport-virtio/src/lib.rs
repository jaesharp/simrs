//! `VirtIO` smart card transport protocol types.
//!
//! Provides protocol-level types for `VirtIO` virtqueue-based smart card
//! transport, enabling a guest OS (e.g. Shannon baseband firmware in QEMU)
//! to communicate with a simrs SIM peripheral on the host.
//!
//! This crate does **not** implement the `Transport` or `CardTransport`
//! traits; it provides the wire-level building blocks that a concrete
//! driver crate (e.g. `simrs-peripheral-shannon`) assembles.
//!
//! # Architecture
//!
//! The transport uses two virtqueues (standard `VirtIO` split virtqueues):
//!
//! - **TX queue** (guest -> host): Guest places APDU commands + control
//!   messages for the host SIM to process.
//! - **RX queue** (host -> guest): Host places APDU responses + events
//!   (ATR, card insertion/removal) for the guest to consume.
//!
//! Each message is framed with a [`VirtSmartcardHeader`] followed by
//! a variable-length payload.
//!
//! # Standards
//!
//! - OASIS `VirtIO` Specification 1.2 -- virtqueue mechanics
//! - [ETSI TS 102 600 V10.1.0](https://www.etsi.org/deliver/etsi_ts/102600_102699/102600/10.01.00_60/ts_102600v100100p.pdf) / ISO/IEC 7816-3 -- T=0 framing carried over virtqueue
//!
//! # `no_std`
//!
//! This crate is fully `no_std` -- intended for bare-metal guest drivers.
//! Platform-specific MMIO register access requires `unsafe` and is deferred
//! to the consuming crate (`simrs-peripheral-shannon`).
//!
//! # Example
//!
//! ```
//! use simrs_transport_virtio::{VirtSmartcardHeader, MessageType};
//!
//! let hdr = VirtSmartcardHeader::new(MessageType::Apdu, 7);
//! assert_eq!(hdr.msg_type, MessageType::Apdu);
//! assert_eq!(hdr.length, 7);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Device ID for a virtual smart card device (project-local convention).
pub const DEVICE_ID: u32 = 0x1D;

/// Maximum virtqueue descriptor count (standard `VirtIO` maximum is 32768).
pub const QUEUE_SIZE_MAX: u16 = 256;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 8;

/// Maximum APDU payload size (short APDUs).
pub const APDU_MAX: usize = 261;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Message type for the virtqueue smart card protocol.
///
/// # Example
///
/// ```
/// use simrs_transport_virtio::MessageType;
///
/// let mt = MessageType::Apdu;
/// assert_eq!(mt as u32, 1);
/// assert_eq!(MessageType::from_u32(1), Some(MessageType::Apdu));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MessageType {
    /// APDU command (TX) or response (RX).
    Apdu = 1,
    /// Card power-on (cold reset). RX: carries ATR in payload.
    PowerOn = 2,
    /// Card power-off. No payload.
    PowerOff = 3,
    /// Warm reset. RX: carries ATR in payload.
    WarmReset = 4,
    /// Card insertion notification (RX only).
    CardInserted = 5,
    /// Card removal notification (RX only).
    CardRemoved = 6,
    /// Error notification. Payload is a 4-byte LE error code.
    Error = 7,
}

impl MessageType {
    /// Parse from a `u32`.
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Apdu),
            2 => Some(Self::PowerOn),
            3 => Some(Self::PowerOff),
            4 => Some(Self::WarmReset),
            5 => Some(Self::CardInserted),
            6 => Some(Self::CardRemoved),
            7 => Some(Self::Error),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Message header
// ---------------------------------------------------------------------------

/// Header for virtqueue smart card messages.
///
/// Precedes every message in both TX and RX virtqueues. All fields are
/// little-endian (matching `VirtIO` convention).
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
///   0      4    msg_type   (MessageType as u32 LE)
///   4      4    length     (payload byte count, LE)
/// ```
///
/// # Example
///
/// ```
/// use simrs_transport_virtio::{VirtSmartcardHeader, MessageType, HEADER_SIZE};
///
/// let hdr = VirtSmartcardHeader::new(MessageType::PowerOn, 0);
/// let mut buf = [0u8; HEADER_SIZE];
/// hdr.encode(&mut buf).unwrap();
/// let decoded = VirtSmartcardHeader::decode(&buf).unwrap();
/// assert_eq!(decoded, hdr);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtSmartcardHeader {
    /// Message type.
    pub msg_type: MessageType,
    /// Payload byte count following this header.
    pub length: u32,
}

impl VirtSmartcardHeader {
    /// Create a new header.
    pub const fn new(msg_type: MessageType, length: u32) -> Self {
        Self { msg_type, length }
    }

    /// Encode the header into a byte buffer (little-endian).
    ///
    /// # Errors
    ///
    /// Returns `None` if `buf` is shorter than [`HEADER_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        buf[0..4].copy_from_slice(&(self.msg_type as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&self.length.to_le_bytes());
        Some(())
    }

    /// Decode a header from a byte buffer (little-endian).
    ///
    /// # Errors
    ///
    /// Returns `None` if `buf` is too short or the message type is unknown.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        let msg_type_raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let msg_type = MessageType::from_u32(msg_type_raw)?;
        let length = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(Self { msg_type, length })
    }

    /// Total message size: header + payload.
    ///
    /// Uses saturating addition to prevent overflow on 32-bit targets
    /// when `length` is large.
    pub const fn total_size(&self) -> usize {
        HEADER_SIZE.saturating_add(self.length as usize)
    }
}

// ---------------------------------------------------------------------------
// Virtqueue descriptor (protocol-level, no MMIO)
// ---------------------------------------------------------------------------

/// A `VirtIO` split virtqueue descriptor.
///
/// Represents a single buffer descriptor in the virtqueue descriptor table.
/// This is the in-memory layout per OASIS `VirtIO` 1.2 section 2.7.5.
///
/// In a real driver, `addr` would be a physical (guest-physical) address.
/// Here we model it as a `u64` for protocol correctness without requiring
/// `unsafe` pointer operations.
///
/// # Example
///
/// ```
/// use simrs_transport_virtio::{VirtqDesc, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
///
/// let desc = VirtqDesc {
///     addr: 0x1000,
///     len: 261,
///     flags: VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
///     next: 1,
/// };
/// assert!(desc.has_next());
/// assert!(desc.is_write());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtqDesc {
    /// Guest-physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags.
    pub flags: u16,
    /// Index of the next descriptor in the chain (valid if `VIRTQ_DESC_F_NEXT` set).
    pub next: u16,
}

/// Descriptor flag: another descriptor follows in the chain.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
/// Descriptor flag: buffer is device-writable (host writes, guest reads).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Descriptor byte size per `VirtIO` spec: 16 bytes.
pub const VIRTQ_DESC_SIZE: usize = 16;

impl VirtqDesc {
    /// Whether another descriptor follows in the chain.
    pub const fn has_next(self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0
    }

    /// Whether this buffer is device-writable (for RX).
    pub const fn is_write(self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// Encode into a byte buffer (little-endian).
    ///
    /// # Errors
    ///
    /// Returns `None` if `buf` is shorter than [`VIRTQ_DESC_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < VIRTQ_DESC_SIZE {
            return None;
        }
        buf[0..8].copy_from_slice(&self.addr.to_le_bytes());
        buf[8..12].copy_from_slice(&self.len.to_le_bytes());
        buf[12..14].copy_from_slice(&self.flags.to_le_bytes());
        buf[14..16].copy_from_slice(&self.next.to_le_bytes());
        Some(())
    }

    /// Decode from a byte buffer (little-endian).
    ///
    /// # Errors
    ///
    /// Returns `None` if `buf` is shorter than [`VIRTQ_DESC_SIZE`].
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < VIRTQ_DESC_SIZE {
            return None;
        }
        Some(Self {
            addr: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            len: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            flags: u16::from_le_bytes([buf[12], buf[13]]),
            next: u16::from_le_bytes([buf[14], buf[15]]),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- MessageType --

    #[test]
    fn message_type_from_u32_valid() {
        assert_eq!(MessageType::from_u32(1), Some(MessageType::Apdu));
        assert_eq!(MessageType::from_u32(2), Some(MessageType::PowerOn));
        assert_eq!(MessageType::from_u32(3), Some(MessageType::PowerOff));
        assert_eq!(MessageType::from_u32(4), Some(MessageType::WarmReset));
        assert_eq!(MessageType::from_u32(5), Some(MessageType::CardInserted));
        assert_eq!(MessageType::from_u32(6), Some(MessageType::CardRemoved));
        assert_eq!(MessageType::from_u32(7), Some(MessageType::Error));
    }

    #[test]
    fn message_type_from_u32_invalid() {
        assert_eq!(MessageType::from_u32(0), None);
        assert_eq!(MessageType::from_u32(8), None);
        assert_eq!(MessageType::from_u32(0xFF), None);
    }

    // -- VirtSmartcardHeader --

    #[test]
    fn header_new() {
        let hdr = VirtSmartcardHeader::new(MessageType::Apdu, 7);
        assert_eq!(hdr.msg_type, MessageType::Apdu);
        assert_eq!(hdr.length, 7);
        assert_eq!(hdr.total_size(), HEADER_SIZE + 7);
    }

    #[test]
    fn header_encode_decode_roundtrip() {
        let hdr = VirtSmartcardHeader::new(MessageType::PowerOn, 25);
        let mut buf = [0u8; HEADER_SIZE];
        hdr.encode(&mut buf).unwrap();
        let decoded = VirtSmartcardHeader::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn header_encode_all_types() {
        for (raw, mt) in [
            (1, MessageType::Apdu),
            (2, MessageType::PowerOn),
            (3, MessageType::PowerOff),
            (4, MessageType::WarmReset),
            (5, MessageType::CardInserted),
            (6, MessageType::CardRemoved),
            (7, MessageType::Error),
        ] {
            let hdr = VirtSmartcardHeader::new(mt, 0);
            let mut buf = [0u8; HEADER_SIZE];
            hdr.encode(&mut buf).unwrap();
            assert_eq!(
                u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
                raw
            );
            let decoded = VirtSmartcardHeader::decode(&buf).unwrap();
            assert_eq!(decoded.msg_type, mt);
        }
    }

    #[test]
    fn header_encode_too_short() {
        let hdr = VirtSmartcardHeader::new(MessageType::Apdu, 0);
        let mut buf = [0u8; 4];
        assert!(hdr.encode(&mut buf).is_none());
    }

    #[test]
    fn header_decode_too_short() {
        assert!(VirtSmartcardHeader::decode(&[0u8; 4]).is_none());
    }

    #[test]
    fn header_decode_unknown_type() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(VirtSmartcardHeader::decode(&buf).is_none());
    }

    // -- VirtqDesc --

    #[test]
    fn desc_encode_decode_roundtrip() {
        let desc = VirtqDesc {
            addr: 0x0000_1000_DEAD_BEEF,
            len: 261,
            flags: VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            next: 5,
        };
        let mut buf = [0u8; VIRTQ_DESC_SIZE];
        desc.encode(&mut buf).unwrap();
        let decoded = VirtqDesc::decode(&buf).unwrap();
        assert_eq!(desc, decoded);
    }

    #[test]
    fn desc_has_next() {
        let desc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        assert!(desc.has_next());
        assert!(!desc.is_write());
    }

    #[test]
    fn desc_is_write() {
        let desc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        assert!(!desc.has_next());
        assert!(desc.is_write());
    }

    #[test]
    fn desc_no_flags() {
        let desc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        assert!(!desc.has_next());
        assert!(!desc.is_write());
    }

    #[test]
    fn desc_encode_too_short() {
        let desc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        let mut buf = [0u8; 8];
        assert!(desc.encode(&mut buf).is_none());
    }

    #[test]
    fn desc_decode_too_short() {
        assert!(VirtqDesc::decode(&[0u8; 8]).is_none());
    }

    #[test]
    fn desc_endianness() {
        let desc = VirtqDesc {
            addr: 0x0102_0304_0506_0708,
            len: 0x0A0B_0C0D,
            flags: 0x0E0F,
            next: 0x1011,
        };
        let mut buf = [0u8; VIRTQ_DESC_SIZE];
        desc.encode(&mut buf).unwrap();
        // Verify little-endian encoding.
        assert_eq!(buf[0], 0x08); // addr low byte
        assert_eq!(buf[7], 0x01); // addr high byte
        assert_eq!(buf[8], 0x0D); // len low byte
        assert_eq!(buf[11], 0x0A); // len high byte
    }
}
