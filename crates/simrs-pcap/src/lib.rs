//! PCAP + GSMTAP SIM frame encoder.
//!
//! Encodes PCAP file headers and packet records with either GSMTAP or
//! simplified `User0` framing for SIM APDU and ATR captures.
//!
//! All encoding writes to caller-provided `&mut [u8]` slices.
//! No allocation, no I/O.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation, zero dependencies.
#![no_std]
#![warn(missing_docs)]
#![allow(clippy::similar_names)] // ts_sec / ts_usec are standard PCAP field names

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PCAP magic number (little-endian native byte order).
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;

/// PCAP major version.
pub const PCAP_MAJOR: u16 = 2;

/// PCAP minor version.
pub const PCAP_MINOR: u16 = 4;

/// Size of the PCAP global (file) header in bytes.
pub const GLOBAL_HEADER_SIZE: usize = 24;

/// Size of a PCAP record (per-packet) header in bytes.
pub const RECORD_HEADER_SIZE: usize = 16;

/// Size of a GSMTAP header in bytes.
pub const GSMTAP_HEADER_SIZE: usize = 16;

/// Size of the simplified `User0` frame header in bytes.
pub const SIMPLE_FRAME_SIZE: usize = 1;

/// PCAP link-layer type for GSMTAP.
pub const LINKTYPE_GSMTAP: u32 = 2342;

/// PCAP link-layer type for `DLT_USER0`.
pub const LINKTYPE_USER0: u32 = 147;

/// GSMTAP protocol version.
pub const GSMTAP_VERSION: u8 = 0x02;

/// GSMTAP type value for SIM frames.
pub const GSMTAP_TYPE_SIM: u8 = 0x04;

/// GSMTAP ARFCN flag indicating uplink direction.
pub const GSMTAP_ARFCN_F_UPLINK: u16 = 0x4000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// PCAP link-layer header type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    /// GSMTAP framing (link type 2342).
    GsmTap,
    /// Simplified `User0` framing (link type 147).
    User0,
}

impl LinkType {
    /// Returns the numeric link-type value for this variant.
    const fn as_u32(self) -> u32 {
        match self {
            Self::GsmTap => LINKTYPE_GSMTAP,
            Self::User0 => LINKTYPE_USER0,
        }
    }
}

/// Direction of a SIM APDU exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Command APDU (terminal to card / uplink).
    Command,
    /// Response APDU (card to terminal / downlink).
    Response,
}

/// GSMTAP SIM sub-type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GsmTapSimSubType {
    /// Regular APDU exchange.
    Apdu = 0x00,
    /// Answer-To-Reset.
    Atr = 0x01,
}

/// Simplified one-byte frame flags for `User0` link type.
///
/// Bit layout:
/// - bit 0: direction  (0 = command, 1 = response)
/// - bit 1: ATR flag   (0 = APDU, 1 = ATR)
/// - bit 2: mismatch   (0 = match, 1 = divergence)
///
/// ```
/// use simrs_pcap::{SimpleFlags, Direction};
///
/// // Command APDU, no mismatch
/// let f = SimpleFlags::new(Direction::Command, false, false);
/// assert_eq!(f.as_byte(), 0x00);
/// assert_eq!(f.direction(), Direction::Command);
/// assert!(!f.is_atr());
/// assert!(!f.is_mismatch());
///
/// // Response ATR with mismatch
/// let f = SimpleFlags::new(Direction::Response, true, true);
/// assert_eq!(f.as_byte(), 0x07);
/// assert_eq!(SimpleFlags::from_byte(f.as_byte()), f);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimpleFlags(u8);

impl SimpleFlags {
    /// Construct flags from individual booleans.
    pub const fn new(direction: Direction, is_atr: bool, is_mismatch: bool) -> Self {
        let mut v: u8 = 0;
        if matches!(direction, Direction::Response) {
            v |= 1;
        }
        if is_atr {
            v |= 1 << 1;
        }
        if is_mismatch {
            v |= 1 << 2;
        }
        Self(v)
    }

    /// Return the raw byte value.
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Reconstruct flags from a raw byte.
    pub const fn from_byte(b: u8) -> Self {
        Self(b & 0x07)
    }

    /// Direction encoded in bit 0.
    pub const fn direction(self) -> Direction {
        if self.0 & 1 == 0 {
            Direction::Command
        } else {
            Direction::Response
        }
    }

    /// Whether this is an ATR (bit 1).
    pub const fn is_atr(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    /// Whether this is a mismatch/divergence (bit 2).
    pub const fn is_mismatch(self) -> bool {
        self.0 & (1 << 2) != 0
    }
}

// ---------------------------------------------------------------------------
// Byte-order helpers
// ---------------------------------------------------------------------------

/// Write a `u16` in little-endian at `buf[off..]`. Returns `off + 2`.
const fn put_le16(buf: &mut [u8], off: usize, v: u16) -> usize {
    let bytes = v.to_le_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
    off + 2
}

/// Write a `u32` in little-endian at `buf[off..]`. Returns `off + 4`.
const fn put_le32(buf: &mut [u8], off: usize, v: u32) -> usize {
    let bytes = v.to_le_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
    buf[off + 2] = bytes[2];
    buf[off + 3] = bytes[3];
    off + 4
}

/// Write a `u16` in big-endian at `buf[off..]`. Returns `off + 2`.
const fn put_be16(buf: &mut [u8], off: usize, v: u16) -> usize {
    let bytes = v.to_be_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
    off + 2
}

/// Write a `u32` in big-endian at `buf[off..]`. Returns `off + 4`.
const fn put_be32(buf: &mut [u8], off: usize, v: u32) -> usize {
    let bytes = v.to_be_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
    buf[off + 2] = bytes[2];
    buf[off + 3] = bytes[3];
    off + 4
}

// ---------------------------------------------------------------------------
// Low-level encoding functions
// ---------------------------------------------------------------------------

/// Encode a 24-byte PCAP global (file) header in little-endian.
///
/// Returns [`GLOBAL_HEADER_SIZE`] on success, or `0` if `buf` is too small.
///
/// ```
/// use simrs_pcap::{encode_global_header, LinkType, GLOBAL_HEADER_SIZE, PCAP_MAGIC};
///
/// let mut buf = [0u8; 24];
/// let n = encode_global_header(&mut buf, LinkType::GsmTap, 65535);
/// assert_eq!(n, GLOBAL_HEADER_SIZE);
///
/// // First 4 bytes are the PCAP magic number in little-endian
/// let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
/// assert_eq!(magic, PCAP_MAGIC);
///
/// // Returns 0 if buffer is too small
/// let mut small = [0u8; 23];
/// assert_eq!(encode_global_header(&mut small, LinkType::GsmTap, 65535), 0);
/// ```
pub const fn encode_global_header(buf: &mut [u8], link_type: LinkType, snap_len: u32) -> usize {
    if buf.len() < GLOBAL_HEADER_SIZE {
        return 0;
    }
    let mut off = 0;
    off = put_le32(buf, off, PCAP_MAGIC);
    off = put_le16(buf, off, PCAP_MAJOR);
    off = put_le16(buf, off, PCAP_MINOR);
    off = put_le32(buf, off, 0); // reserved1 (thiszone)
    off = put_le32(buf, off, 0); // reserved2 (sigfigs)
    off = put_le32(buf, off, snap_len);
    let _ = put_le32(buf, off, link_type.as_u32());
    GLOBAL_HEADER_SIZE
}

/// Encode a 16-byte PCAP record (per-packet) header in little-endian.
///
/// Returns [`RECORD_HEADER_SIZE`] on success, or `0` if `buf` is too small.
///
/// ```
/// use simrs_pcap::{encode_record_header, RECORD_HEADER_SIZE};
///
/// let mut buf = [0u8; 16];
/// let n = encode_record_header(&mut buf, 1_700_000_000, 123_456, 100, 100);
/// assert_eq!(n, RECORD_HEADER_SIZE);
///
/// // Verify timestamp (little-endian u32 at offset 0)
/// let ts = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
/// assert_eq!(ts, 1_700_000_000);
/// ```
pub const fn encode_record_header(
    buf: &mut [u8],
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
) -> usize {
    if buf.len() < RECORD_HEADER_SIZE {
        return 0;
    }
    let mut off = 0;
    off = put_le32(buf, off, ts_sec);
    off = put_le32(buf, off, ts_usec);
    off = put_le32(buf, off, incl_len);
    let _ = put_le32(buf, off, orig_len);
    RECORD_HEADER_SIZE
}

/// Encode a 16-byte GSMTAP SIM header in network (big-endian) byte order.
///
/// Returns [`GSMTAP_HEADER_SIZE`] on success, or `0` if `buf` is too small.
pub const fn encode_gsmtap_sim(
    buf: &mut [u8],
    sub_type: GsmTapSimSubType,
    direction: Direction,
) -> usize {
    if buf.len() < GSMTAP_HEADER_SIZE {
        return 0;
    }
    // byte 0: version
    buf[0] = GSMTAP_VERSION;
    // byte 1: hdr_len in 32-bit words (16 bytes / 4 = 4)
    buf[1] = 0x04;
    // byte 2: type (SIM)
    buf[2] = GSMTAP_TYPE_SIM;
    // byte 3: timeslot
    buf[3] = 0x00;
    // bytes 4-5: arfcn (BE u16), bit 14 = uplink for Command
    let arfcn: u16 = match direction {
        Direction::Command => GSMTAP_ARFCN_F_UPLINK,
        Direction::Response => 0,
    };
    let mut off = put_be16(buf, 4, arfcn);
    // byte 6: signal_dbm
    buf[off] = 0;
    off += 1;
    // byte 7: snr_db
    buf[off] = 0;
    off += 1;
    // bytes 8-11: frame_number (BE u32)
    off = put_be32(buf, off, 0);
    // byte 12: sub_type
    buf[off] = sub_type as u8;
    off += 1;
    // bytes 13-15: reserved
    buf[off] = 0;
    buf[off + 1] = 0;
    buf[off + 2] = 0;
    GSMTAP_HEADER_SIZE
}

// ---------------------------------------------------------------------------
// High-level encoder
// ---------------------------------------------------------------------------

/// Stateful PCAP encoder that knows the chosen link type.
///
/// ```
/// use simrs_pcap::{PcapEncoder, LinkType, Direction, GLOBAL_HEADER_SIZE};
///
/// let enc = PcapEncoder::new(LinkType::User0);
///
/// // Write the global header
/// let mut buf = [0u8; 512];
/// let ghdr_len = enc.global_header(&mut buf);
/// assert_eq!(ghdr_len, GLOBAL_HEADER_SIZE);
///
/// // Encode a command APDU packet after the global header
/// let apdu = [0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00];
/// let pkt_len = enc.encode_apdu(
///     &mut buf[ghdr_len..], 1_700_000_000, 0, Direction::Command, &apdu,
/// );
/// assert!(pkt_len > 0);
///
/// // Total file size so far
/// let total = ghdr_len + pkt_len;
/// assert!(total < 512);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapEncoder {
    link_type: LinkType,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // &self is idiomatic even for Copy types
impl PcapEncoder {
    /// Create a new encoder for the given link type.
    pub const fn new(link_type: LinkType) -> Self {
        Self { link_type }
    }

    /// Write the PCAP global header with `snap_len = 65535`.
    pub const fn global_header(&self, buf: &mut [u8]) -> usize {
        encode_global_header(buf, self.link_type, 65535)
    }

    /// Maximum buffer size needed for a single packet with the given payload.
    ///
    /// `RECORD_HEADER_SIZE + max(GSMTAP_HEADER_SIZE, SIMPLE_FRAME_SIZE) + payload_len`
    pub const fn max_packet_size(payload_len: usize) -> usize {
        // GSMTAP_HEADER_SIZE (16) > SIMPLE_FRAME_SIZE (1), so max is 16
        RECORD_HEADER_SIZE + GSMTAP_HEADER_SIZE + payload_len
    }

    /// Encode an APDU packet (record header + frame header + payload).
    ///
    /// Returns total bytes written, or `0` if `buf` is too small.
    pub fn encode_apdu(
        &self,
        buf: &mut [u8],
        ts_sec: u32,
        ts_usec: u32,
        direction: Direction,
        apdu: &[u8],
    ) -> usize {
        self.encode_packet(
            buf,
            ts_sec,
            ts_usec,
            direction,
            GsmTapSimSubType::Apdu,
            false,
            apdu,
        )
    }

    /// Encode an ATR packet (record header + frame header + ATR bytes).
    ///
    /// Direction is always [`Direction::Response`]; sub-type is
    /// [`GsmTapSimSubType::Atr`].
    ///
    /// Returns total bytes written, or `0` if `buf` is too small.
    pub fn encode_atr(&self, buf: &mut [u8], ts_sec: u32, ts_usec: u32, atr: &[u8]) -> usize {
        self.encode_packet(
            buf,
            ts_sec,
            ts_usec,
            Direction::Response,
            GsmTapSimSubType::Atr,
            false,
            atr,
        )
    }

    /// Encode an APDU mismatch packet.
    ///
    /// For `User0` link type the mismatch bit (bit 2) is set in the flags byte.
    /// For `GsmTap` this behaves identically to [`encode_apdu`](Self::encode_apdu)
    /// since GSMTAP has no mismatch concept.
    ///
    /// Returns total bytes written, or `0` if `buf` is too small.
    pub fn encode_apdu_mismatch(
        &self,
        buf: &mut [u8],
        ts_sec: u32,
        ts_usec: u32,
        direction: Direction,
        apdu: &[u8],
    ) -> usize {
        self.encode_packet(
            buf,
            ts_sec,
            ts_usec,
            direction,
            GsmTapSimSubType::Apdu,
            true,
            apdu,
        )
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Shared implementation for all packet types.
    #[allow(clippy::too_many_arguments)]
    fn encode_packet(
        &self,
        buf: &mut [u8],
        ts_sec: u32,
        ts_usec: u32,
        direction: Direction,
        sub_type: GsmTapSimSubType,
        mismatch: bool,
        payload: &[u8],
    ) -> usize {
        let frame_hdr_size = match self.link_type {
            LinkType::GsmTap => GSMTAP_HEADER_SIZE,
            LinkType::User0 => SIMPLE_FRAME_SIZE,
        };
        let data_len = frame_hdr_size + payload.len();
        let total = RECORD_HEADER_SIZE + data_len;

        if buf.len() < total {
            return 0;
        }

        // data_len is at most GSMTAP_HEADER_SIZE (16) + payload.len().
        // In practice payload will never exceed snap_len (65535), so this
        // truncation is safe; the field is u32 in the PCAP format.
        #[allow(clippy::cast_possible_truncation)]
        let incl_len = data_len as u32;
        let orig_len = incl_len;
        let mut off = encode_record_header(buf, ts_sec, ts_usec, incl_len, orig_len);

        // -- frame header --
        match self.link_type {
            LinkType::GsmTap => {
                off += encode_gsmtap_sim(&mut buf[off..], sub_type, direction);
            }
            LinkType::User0 => {
                let is_atr = matches!(sub_type, GsmTapSimSubType::Atr);
                let flags = SimpleFlags::new(direction, is_atr, mismatch);
                buf[off] = flags.as_byte();
                off += SIMPLE_FRAME_SIZE;
            }
        }

        // -- payload --
        buf[off..off + payload.len()].copy_from_slice(payload);
        total
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]

    use super::*;
    use alloc::vec;

    // -- helper: read LE u16 --
    fn le16(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([buf[off], buf[off + 1]])
    }

    // -- helper: read LE u32 --
    fn le32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    // -- helper: read BE u16 --
    fn be16(buf: &[u8], off: usize) -> u16 {
        u16::from_be_bytes([buf[off], buf[off + 1]])
    }

    // -- helper: read BE u32 --
    fn be32(buf: &[u8], off: usize) -> u32 {
        u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    // -----------------------------------------------------------------------
    // 1. global_header_gsmtap
    // -----------------------------------------------------------------------
    #[test]
    fn global_header_gsmtap() {
        let mut buf = [0u8; 24];
        let n = encode_global_header(&mut buf, LinkType::GsmTap, 65535);
        assert_eq!(n, GLOBAL_HEADER_SIZE);
        assert_eq!(le32(&buf, 0), PCAP_MAGIC);
        assert_eq!(le16(&buf, 4), PCAP_MAJOR);
        assert_eq!(le16(&buf, 6), PCAP_MINOR);
        assert_eq!(le32(&buf, 8), 0); // reserved1
        assert_eq!(le32(&buf, 12), 0); // reserved2
        assert_eq!(le32(&buf, 16), 65535); // snap_len
        assert_eq!(le32(&buf, 20), LINKTYPE_GSMTAP);
    }

    // -----------------------------------------------------------------------
    // 2. global_header_user0
    // -----------------------------------------------------------------------
    #[test]
    fn global_header_user0() {
        let mut buf = [0u8; 24];
        let n = encode_global_header(&mut buf, LinkType::User0, 65535);
        assert_eq!(n, GLOBAL_HEADER_SIZE);
        assert_eq!(le32(&buf, 20), LINKTYPE_USER0);
    }

    // -----------------------------------------------------------------------
    // 3. global_header_buf_too_small
    // -----------------------------------------------------------------------
    #[test]
    fn global_header_buf_too_small() {
        let mut buf = [0u8; 23];
        assert_eq!(encode_global_header(&mut buf, LinkType::GsmTap, 65535), 0);
    }

    // -----------------------------------------------------------------------
    // 4. record_header_basic
    // -----------------------------------------------------------------------
    #[test]
    fn record_header_basic() {
        let mut buf = [0u8; 16];
        let n = encode_record_header(&mut buf, 1_700_000_000, 123_456, 100, 100);
        assert_eq!(n, RECORD_HEADER_SIZE);
        assert_eq!(le32(&buf, 0), 1_700_000_000);
        assert_eq!(le32(&buf, 4), 123_456);
        assert_eq!(le32(&buf, 8), 100);
        assert_eq!(le32(&buf, 12), 100);
    }

    // -----------------------------------------------------------------------
    // 5. record_header_max_values
    // -----------------------------------------------------------------------
    #[test]
    fn record_header_max_values() {
        let mut buf = [0u8; 16];
        let n = encode_record_header(&mut buf, u32::MAX, u32::MAX, u32::MAX, u32::MAX);
        assert_eq!(n, RECORD_HEADER_SIZE);
        assert_eq!(le32(&buf, 0), u32::MAX);
        assert_eq!(le32(&buf, 4), u32::MAX);
        assert_eq!(le32(&buf, 8), u32::MAX);
        assert_eq!(le32(&buf, 12), u32::MAX);
    }

    // -----------------------------------------------------------------------
    // 6. record_header_buf_too_small
    // -----------------------------------------------------------------------
    #[test]
    fn record_header_buf_too_small() {
        let mut buf = [0u8; 15];
        assert_eq!(encode_record_header(&mut buf, 0, 0, 0, 0), 0);
    }

    // -----------------------------------------------------------------------
    // 7. gsmtap_sim_apdu_command
    // -----------------------------------------------------------------------
    #[test]
    fn gsmtap_sim_apdu_command() {
        let mut buf = [0u8; 16];
        let n = encode_gsmtap_sim(&mut buf, GsmTapSimSubType::Apdu, Direction::Command);
        assert_eq!(n, GSMTAP_HEADER_SIZE);
        assert_eq!(buf[0], GSMTAP_VERSION);
        assert_eq!(buf[1], 0x04); // hdr_len in 32-bit words
        assert_eq!(buf[2], GSMTAP_TYPE_SIM);
        assert_eq!(buf[3], 0x00); // timeslot
        assert_eq!(be16(&buf, 4), GSMTAP_ARFCN_F_UPLINK); // uplink bit set
        assert_eq!(buf[6], 0); // signal_dbm
        assert_eq!(buf[7], 0); // snr_db
        assert_eq!(be32(&buf, 8), 0); // frame_number
        assert_eq!(buf[12], GsmTapSimSubType::Apdu as u8);
        assert_eq!(buf[13], 0); // reserved
        assert_eq!(buf[14], 0);
        assert_eq!(buf[15], 0);
    }

    // -----------------------------------------------------------------------
    // 8. gsmtap_sim_apdu_response
    // -----------------------------------------------------------------------
    #[test]
    fn gsmtap_sim_apdu_response() {
        let mut buf = [0u8; 16];
        let n = encode_gsmtap_sim(&mut buf, GsmTapSimSubType::Apdu, Direction::Response);
        assert_eq!(n, GSMTAP_HEADER_SIZE);
        assert_eq!(be16(&buf, 4), 0); // no uplink bit
    }

    // -----------------------------------------------------------------------
    // 9. gsmtap_sim_atr
    // -----------------------------------------------------------------------
    #[test]
    fn gsmtap_sim_atr() {
        let mut buf = [0u8; 16];
        let n = encode_gsmtap_sim(&mut buf, GsmTapSimSubType::Atr, Direction::Response);
        assert_eq!(n, GSMTAP_HEADER_SIZE);
        assert_eq!(buf[12], GsmTapSimSubType::Atr as u8);
    }

    // -----------------------------------------------------------------------
    // 10. gsmtap_buf_too_small
    // -----------------------------------------------------------------------
    #[test]
    fn gsmtap_buf_too_small() {
        let mut buf = [0u8; 15];
        assert_eq!(
            encode_gsmtap_sim(&mut buf, GsmTapSimSubType::Apdu, Direction::Command),
            0,
        );
    }

    // -----------------------------------------------------------------------
    // 11. simple_flags_command_apdu
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_command_apdu() {
        let f = SimpleFlags::new(Direction::Command, false, false);
        assert_eq!(f.as_byte(), 0x00);
    }

    // -----------------------------------------------------------------------
    // 12. simple_flags_response_apdu
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_response_apdu() {
        let f = SimpleFlags::new(Direction::Response, false, false);
        assert_eq!(f.as_byte(), 0x01);
    }

    // -----------------------------------------------------------------------
    // 13. simple_flags_command_atr
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_command_atr() {
        let f = SimpleFlags::new(Direction::Command, true, false);
        assert_eq!(f.as_byte(), 0x02);
    }

    // -----------------------------------------------------------------------
    // 14. simple_flags_response_atr
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_response_atr() {
        let f = SimpleFlags::new(Direction::Response, true, false);
        assert_eq!(f.as_byte(), 0x03);
    }

    // -----------------------------------------------------------------------
    // 15. simple_flags_mismatch_command
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_mismatch_command() {
        let f = SimpleFlags::new(Direction::Command, false, true);
        assert_eq!(f.as_byte(), 0x04);
    }

    // -----------------------------------------------------------------------
    // 16. simple_flags_mismatch_response
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_mismatch_response() {
        let f = SimpleFlags::new(Direction::Response, false, true);
        assert_eq!(f.as_byte(), 0x05);
    }

    // -----------------------------------------------------------------------
    // 17. simple_flags_all_set
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_all_set() {
        let f = SimpleFlags::new(Direction::Response, true, true);
        assert_eq!(f.as_byte(), 0x07);
    }

    // -----------------------------------------------------------------------
    // 18. simple_flags_roundtrip
    // -----------------------------------------------------------------------
    #[test]
    fn simple_flags_roundtrip() {
        for raw in 0u8..=7 {
            let f = SimpleFlags::from_byte(raw);
            assert_eq!(f.as_byte(), raw);
            // Also verify field accessors
            let reconstructed = SimpleFlags::new(f.direction(), f.is_atr(), f.is_mismatch());
            assert_eq!(reconstructed.as_byte(), raw);
        }
    }

    // -----------------------------------------------------------------------
    // 19. encoder_gsmtap_apdu_command
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_gsmtap_apdu_command() {
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x07];
        let enc = PcapEncoder::new(LinkType::GsmTap);
        let mut buf = [0u8; 256];
        let n = enc.encode_apdu(&mut buf, 100, 200, Direction::Command, &apdu);
        let expected_data_len = GSMTAP_HEADER_SIZE + apdu.len();
        let expected_total = RECORD_HEADER_SIZE + expected_data_len;
        assert_eq!(n, expected_total);

        // record header
        assert_eq!(le32(&buf, 0), 100); // ts_sec
        assert_eq!(le32(&buf, 4), 200); // ts_usec
        assert_eq!(le32(&buf, 8), expected_data_len as u32); // incl_len
        assert_eq!(le32(&buf, 12), expected_data_len as u32); // orig_len

        // GSMTAP header
        let gh = RECORD_HEADER_SIZE;
        assert_eq!(buf[gh], GSMTAP_VERSION);
        assert_eq!(buf[gh + 2], GSMTAP_TYPE_SIM);
        assert_eq!(be16(&buf, gh + 4), GSMTAP_ARFCN_F_UPLINK); // command = uplink
        assert_eq!(buf[gh + 12], GsmTapSimSubType::Apdu as u8);

        // payload
        let payload_off = gh + GSMTAP_HEADER_SIZE;
        assert_eq!(&buf[payload_off..payload_off + apdu.len()], &apdu);
    }

    // -----------------------------------------------------------------------
    // 20. encoder_gsmtap_apdu_response
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_gsmtap_apdu_response() {
        let apdu = [0x90, 0x00];
        let enc = PcapEncoder::new(LinkType::GsmTap);
        let mut buf = [0u8; 256];
        let n = enc.encode_apdu(&mut buf, 100, 200, Direction::Response, &apdu);
        let expected_data_len = GSMTAP_HEADER_SIZE + apdu.len();
        assert_eq!(n, RECORD_HEADER_SIZE + expected_data_len);

        let gh = RECORD_HEADER_SIZE;
        assert_eq!(be16(&buf, gh + 4), 0); // response = no uplink bit

        let payload_off = gh + GSMTAP_HEADER_SIZE;
        assert_eq!(&buf[payload_off..payload_off + apdu.len()], &apdu);
    }

    // -----------------------------------------------------------------------
    // 21. encoder_user0_apdu_command
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_user0_apdu_command() {
        let apdu = [0x00, 0xA4, 0x04, 0x00];
        let enc = PcapEncoder::new(LinkType::User0);
        let mut buf = [0u8; 256];
        let n = enc.encode_apdu(&mut buf, 50, 100, Direction::Command, &apdu);
        let expected_data_len = SIMPLE_FRAME_SIZE + apdu.len();
        assert_eq!(n, RECORD_HEADER_SIZE + expected_data_len);

        // record header
        assert_eq!(le32(&buf, 0), 50);
        assert_eq!(le32(&buf, 4), 100);
        assert_eq!(le32(&buf, 8), expected_data_len as u32);
        assert_eq!(le32(&buf, 12), expected_data_len as u32);

        // flags byte: command, not ATR, not mismatch = 0x00
        let flags_off = RECORD_HEADER_SIZE;
        assert_eq!(buf[flags_off], 0x00);

        // payload
        let payload_off = flags_off + SIMPLE_FRAME_SIZE;
        assert_eq!(&buf[payload_off..payload_off + apdu.len()], &apdu);
    }

    // -----------------------------------------------------------------------
    // 22. encoder_user0_apdu_response
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_user0_apdu_response() {
        let apdu = [0x90, 0x00];
        let enc = PcapEncoder::new(LinkType::User0);
        let mut buf = [0u8; 256];
        let n = enc.encode_apdu(&mut buf, 50, 100, Direction::Response, &apdu);
        let expected_data_len = SIMPLE_FRAME_SIZE + apdu.len();
        assert_eq!(n, RECORD_HEADER_SIZE + expected_data_len);

        // flags byte: response=1, not ATR, not mismatch = 0x01
        assert_eq!(buf[RECORD_HEADER_SIZE], 0x01);

        let payload_off = RECORD_HEADER_SIZE + SIMPLE_FRAME_SIZE;
        assert_eq!(&buf[payload_off..payload_off + apdu.len()], &apdu);
    }

    // -----------------------------------------------------------------------
    // 23. encoder_atr_gsmtap
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_atr_gsmtap() {
        let atr = [0x3B, 0x9F, 0x95, 0x80, 0x1F];
        let enc = PcapEncoder::new(LinkType::GsmTap);
        let mut buf = [0u8; 256];
        let n = enc.encode_atr(&mut buf, 10, 20, &atr);
        let expected_data_len = GSMTAP_HEADER_SIZE + atr.len();
        assert_eq!(n, RECORD_HEADER_SIZE + expected_data_len);

        let gh = RECORD_HEADER_SIZE;
        assert_eq!(buf[gh + 12], GsmTapSimSubType::Atr as u8); // sub_type
        assert_eq!(be16(&buf, gh + 4), 0); // response = downlink, no uplink bit

        let payload_off = gh + GSMTAP_HEADER_SIZE;
        assert_eq!(&buf[payload_off..payload_off + atr.len()], &atr);
    }

    // -----------------------------------------------------------------------
    // 24. encoder_atr_user0
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_atr_user0() {
        let atr = [0x3B, 0x9F];
        let enc = PcapEncoder::new(LinkType::User0);
        let mut buf = [0u8; 256];
        let n = enc.encode_atr(&mut buf, 10, 20, &atr);
        let expected_data_len = SIMPLE_FRAME_SIZE + atr.len();
        assert_eq!(n, RECORD_HEADER_SIZE + expected_data_len);

        // flags: response(1) | is_atr(2) = 0x03
        assert_eq!(buf[RECORD_HEADER_SIZE], 0x03);

        let payload_off = RECORD_HEADER_SIZE + SIMPLE_FRAME_SIZE;
        assert_eq!(&buf[payload_off..payload_off + atr.len()], &atr);
    }

    // -----------------------------------------------------------------------
    // 25. encoder_mismatch_gsmtap
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_mismatch_gsmtap() {
        let apdu = [0x00, 0xB0, 0x00, 0x00, 0x10];
        let enc = PcapEncoder::new(LinkType::GsmTap);
        let mut buf_normal = [0u8; 256];
        let mut buf_mismatch = [0u8; 256];
        let n1 = enc.encode_apdu(&mut buf_normal, 1, 2, Direction::Command, &apdu);
        let n2 = enc.encode_apdu_mismatch(&mut buf_mismatch, 1, 2, Direction::Command, &apdu);
        // GSMTAP has no mismatch concept: both should be identical
        assert_eq!(n1, n2);
        assert_eq!(&buf_normal[..n1], &buf_mismatch[..n2]);
    }

    // -----------------------------------------------------------------------
    // 26. encoder_mismatch_user0
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_mismatch_user0() {
        let apdu = [0x00, 0xB0, 0x00, 0x00];
        let enc = PcapEncoder::new(LinkType::User0);
        let mut buf = [0u8; 256];
        let n = enc.encode_apdu_mismatch(&mut buf, 1, 2, Direction::Command, &apdu);
        let expected_data_len = SIMPLE_FRAME_SIZE + apdu.len();
        assert_eq!(n, RECORD_HEADER_SIZE + expected_data_len);

        // flags: command(0) | not_atr(0) | mismatch(4) = 0x04
        assert_eq!(buf[RECORD_HEADER_SIZE], 0x04);

        // Also test response mismatch
        let n2 = enc.encode_apdu_mismatch(&mut buf, 1, 2, Direction::Response, &apdu);
        assert_eq!(n2, RECORD_HEADER_SIZE + expected_data_len);
        // flags: response(1) | not_atr(0) | mismatch(4) = 0x05
        assert_eq!(buf[RECORD_HEADER_SIZE], 0x05);
    }

    // -----------------------------------------------------------------------
    // 27. encoder_empty_apdu
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_empty_apdu() {
        let enc = PcapEncoder::new(LinkType::GsmTap);
        let mut buf = [0u8; 256];
        let n = enc.encode_apdu(&mut buf, 0, 0, Direction::Command, &[]);
        assert_eq!(n, RECORD_HEADER_SIZE + GSMTAP_HEADER_SIZE);
        assert_eq!(le32(&buf, 8), GSMTAP_HEADER_SIZE as u32); // incl_len

        let enc2 = PcapEncoder::new(LinkType::User0);
        let n2 = enc2.encode_apdu(&mut buf, 0, 0, Direction::Command, &[]);
        assert_eq!(n2, RECORD_HEADER_SIZE + SIMPLE_FRAME_SIZE);
        assert_eq!(le32(&buf, 8), SIMPLE_FRAME_SIZE as u32);
    }

    // -----------------------------------------------------------------------
    // 28. encoder_max_apdu
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_max_apdu() {
        // 258-byte APDU payload (e.g. extended Le)
        let apdu = [0xAB; 258];
        let enc = PcapEncoder::new(LinkType::GsmTap);
        let total = PcapEncoder::max_packet_size(258);
        let mut buf = vec![0u8; total];
        let n = enc.encode_apdu(&mut buf, 99, 88, Direction::Response, &apdu);
        let expected_data_len = GSMTAP_HEADER_SIZE + 258;
        assert_eq!(n, RECORD_HEADER_SIZE + expected_data_len);
        assert_eq!(le32(&buf, 8), expected_data_len as u32);

        // Verify payload bytes
        let payload_off = RECORD_HEADER_SIZE + GSMTAP_HEADER_SIZE;
        assert!(buf[payload_off..payload_off + 258]
            .iter()
            .all(|&b| b == 0xAB));
    }

    // -----------------------------------------------------------------------
    // 29. encoder_buf_too_small
    // -----------------------------------------------------------------------
    #[test]
    fn encoder_buf_too_small() {
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x07];
        let enc = PcapEncoder::new(LinkType::GsmTap);
        // Need RECORD_HEADER_SIZE + GSMTAP_HEADER_SIZE + 5 = 37 bytes
        let needed = RECORD_HEADER_SIZE + GSMTAP_HEADER_SIZE + apdu.len();
        let mut buf = vec![0u8; needed - 1];
        assert_eq!(
            enc.encode_apdu(&mut buf, 0, 0, Direction::Command, &apdu),
            0
        );

        // User0 needs RECORD_HEADER_SIZE + SIMPLE_FRAME_SIZE + 5 = 22
        let enc2 = PcapEncoder::new(LinkType::User0);
        let needed2 = RECORD_HEADER_SIZE + SIMPLE_FRAME_SIZE + apdu.len();
        let mut buf2 = vec![0u8; needed2 - 1];
        assert_eq!(
            enc2.encode_apdu(&mut buf2, 0, 0, Direction::Command, &apdu),
            0
        );
    }

    // -----------------------------------------------------------------------
    // 30. max_packet_size_calculation
    // -----------------------------------------------------------------------
    #[test]
    fn max_packet_size_calculation() {
        assert_eq!(
            PcapEncoder::max_packet_size(0),
            RECORD_HEADER_SIZE + GSMTAP_HEADER_SIZE
        );
        assert_eq!(PcapEncoder::max_packet_size(0), 16 + 16);
        assert_eq!(PcapEncoder::max_packet_size(100), 16 + 16 + 100);
        assert_eq!(PcapEncoder::max_packet_size(258), 16 + 16 + 258);
    }
}
