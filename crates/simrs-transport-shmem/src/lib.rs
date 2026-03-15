//! Shared-memory SIM transport protocol types.
//!
//! Provides the header layout and SPSC ring buffer helpers for a
//! shared-memory APDU channel. Suitable for low-latency APDU exchange
//! between a QEMU host process and simrs, or between two processes on
//! the same machine.
//!
//! # Architecture
//!
//! The shared memory region contains a fixed-layout header followed by
//! two ring buffers (one per direction). Each ring uses a single-producer
//! single-consumer (SPSC) design with atomic head/tail indices.
//!
//! ```text
//! Offset  Size   Field
//! ------  -----  -----
//!   0       4    magic       ("SIMR" as LE u32)
//!   4       4    version     (1)
//!   8       4    ring_size   (power of 2, e.g. 4096)
//!  12       4    cmd_head    (producer: terminal, consumer: card)
//!  16       4    cmd_tail
//!  20       4    rsp_head    (producer: card, consumer: terminal)
//!  24       4    rsp_tail
//!  28       4    reserved
//!  32       N    cmd_ring[ring_size]
//!  32+N     N    rsp_ring[ring_size]
//! ```
//!
//! Messages within each ring are framed with a 2-byte little-endian length
//! prefix followed by the payload bytes.
//!
//! # `no_std` + platform
//!
//! Core protocol types and ring buffer logic are `no_std` and safe.
//! Platform integration (`mmap`, `futex`) requires `unsafe` and is
//! deferred to a future implementation behind the `std` feature.
//!
//! # Example
//!
//! ```
//! use simrs_transport_shmem::{ShmemHeader, MAGIC, VERSION};
//!
//! let hdr = ShmemHeader::new(4096);
//! assert_eq!(hdr.magic, MAGIC);
//! assert_eq!(hdr.version, VERSION);
//! assert_eq!(hdr.ring_size, 4096);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying a simrs shared-memory region: `"SIMR"` as LE u32.
pub const MAGIC: u32 = u32::from_le_bytes(*b"SIMR");

/// Protocol version.
pub const VERSION: u32 = 1;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 32;

/// Minimum ring size (must be power of 2).
pub const RING_SIZE_MIN: u32 = 512;

/// Maximum ring size.
pub const RING_SIZE_MAX: u32 = 65536;

/// Maximum message payload within a ring slot (APDU + framing).
/// 2-byte length prefix + 261 bytes max APDU command.
pub const MSG_MAX: usize = 263;

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// Shared-memory region header.
///
/// Laid out at offset 0 of the mapped region. All fields are little-endian.
/// The two ring buffers follow immediately after the header.
///
/// # Example
///
/// ```
/// use simrs_transport_shmem::ShmemHeader;
///
/// let hdr = ShmemHeader::new(4096);
/// assert_eq!(hdr.total_size(), 32 + 4096 * 2);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShmemHeader {
    /// Magic identifier ([`MAGIC`]).
    pub magic: u32,
    /// Protocol version ([`VERSION`]).
    pub version: u32,
    /// Size of each ring buffer in bytes (must be power of 2).
    pub ring_size: u32,
    /// Command ring write index (terminal writes, card reads).
    pub cmd_head: u32,
    /// Command ring read index.
    pub cmd_tail: u32,
    /// Response ring write index (card writes, terminal reads).
    pub rsp_head: u32,
    /// Response ring read index.
    pub rsp_tail: u32,
    /// Reserved for future use.
    pub reserved: u32,
}

impl ShmemHeader {
    /// Create a new header with the given ring size.
    ///
    /// # Panics
    ///
    /// Panics if `ring_size` is not a power of 2 or is outside
    /// [`RING_SIZE_MIN`]..=[`RING_SIZE_MAX`].
    pub const fn new(ring_size: u32) -> Self {
        assert!(ring_size.is_power_of_two(), "ring_size must be power of 2");
        assert!(
            ring_size >= RING_SIZE_MIN && ring_size <= RING_SIZE_MAX,
            "ring_size out of range"
        );
        Self {
            magic: MAGIC,
            version: VERSION,
            ring_size,
            cmd_head: 0,
            cmd_tail: 0,
            rsp_head: 0,
            rsp_tail: 0,
            reserved: 0,
        }
    }

    /// Total shared-memory region size: header + 2 rings.
    pub const fn total_size(&self) -> usize {
        HEADER_SIZE + (self.ring_size as usize) * 2
    }

    /// Byte offset of the command ring within the shared region.
    pub const fn cmd_ring_offset(&self) -> usize {
        HEADER_SIZE
    }

    /// Byte offset of the response ring within the shared region.
    pub const fn rsp_ring_offset(&self) -> usize {
        HEADER_SIZE + self.ring_size as usize
    }

    /// Encode the header into a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns `None` if `buf` is shorter than [`HEADER_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..12].copy_from_slice(&self.ring_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.cmd_head.to_le_bytes());
        buf[16..20].copy_from_slice(&self.cmd_tail.to_le_bytes());
        buf[20..24].copy_from_slice(&self.rsp_head.to_le_bytes());
        buf[24..28].copy_from_slice(&self.rsp_tail.to_le_bytes());
        buf[28..32].copy_from_slice(&self.reserved.to_le_bytes());
        Some(())
    }

    /// Decode a header from a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns `None` if `buf` is too short, magic is wrong, or
    /// `ring_size` is invalid.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != MAGIC {
            return None;
        }
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != VERSION {
            return None;
        }
        let ring_size = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if !ring_size.is_power_of_two() || !(RING_SIZE_MIN..=RING_SIZE_MAX).contains(&ring_size) {
            return None;
        }
        Some(Self {
            magic,
            version,
            ring_size,
            cmd_head: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            cmd_tail: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            rsp_head: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
            rsp_tail: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
            reserved: u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
        })
    }
}

// ---------------------------------------------------------------------------
// Ring buffer helpers (pure, safe, no_std)
// ---------------------------------------------------------------------------

/// Compute the number of bytes available to read in a ring.
///
/// `head` is the write index, `tail` is the read index, `mask` = `ring_size` - 1.
pub const fn ring_readable(head: u32, tail: u32, mask: u32) -> u32 {
    (head.wrapping_sub(tail)) & mask
}

/// Compute the number of bytes available to write in a ring.
///
/// One byte is always reserved to distinguish full from empty.
pub const fn ring_writable(head: u32, tail: u32, mask: u32) -> u32 {
    mask.wrapping_sub(head.wrapping_sub(tail) & mask)
}

/// Encode a message into a ring buffer slice.
///
/// Writes a 2-byte LE length prefix followed by `data`. Returns the
/// new head index, or `None` if there is not enough space.
///
/// `ring` is the full ring buffer, `head`/`tail` are current indices,
/// and `ring_size` must be a power of 2.
pub fn ring_write(
    ring: &mut [u8],
    head: u32,
    tail: u32,
    ring_size: u32,
    data: &[u8],
) -> Option<u32> {
    if ring.len() < ring_size as usize {
        return None;
    }
    let mask = ring_size - 1;
    let msg_len = 2 + data.len();
    // msg_len bounded by ring_size (max 65536) -- fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let msg_len_u32 = msg_len as u32;
    if msg_len_u32 > ring_writable(head, tail, mask) {
        return None;
    }
    let rs = ring_size as usize;

    // Write 2-byte LE length prefix.
    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (data.len() as u16).to_le_bytes();
    let h = head as usize;
    ring[h & (rs - 1)] = len_bytes[0];
    ring[(h + 1) & (rs - 1)] = len_bytes[1];

    // Write payload byte-by-byte with index masking. Cannot use
    // copy_from_slice because the write may wrap around the ring end.
    for (i, &b) in data.iter().enumerate() {
        ring[(h + 2 + i) & (rs - 1)] = b;
    }

    Some(head.wrapping_add(msg_len_u32))
}

/// Read a message from a ring buffer slice.
///
/// Returns `(new_tail, data_length)` on success, or `None` if the ring
/// is empty. The payload bytes are written into `out`.
pub fn ring_read(
    ring: &[u8],
    head: u32,
    tail: u32,
    ring_size: u32,
    out: &mut [u8],
) -> Option<(u32, usize)> {
    if ring.len() < ring_size as usize {
        return None;
    }
    let mask = ring_size - 1;
    let readable = ring_readable(head, tail, mask);
    if readable < 2 {
        return None; // Not enough for length prefix.
    }
    let rs = ring_size as usize;
    let t = tail as usize;

    // Read 2-byte LE length prefix.
    let len = u16::from_le_bytes([ring[t & (rs - 1)], ring[(t + 1) & (rs - 1)]]) as usize;

    // (2 + len) bounded by ring_size (max 65536) -- fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let frame_len = (2 + len) as u32;
    if frame_len > readable {
        return None; // Incomplete message.
    }
    if len > out.len() {
        return None; // Output buffer too small.
    }

    // Read payload byte-by-byte with index masking. Cannot use
    // copy_from_slice because the read may wrap around the ring end.
    for i in 0..len {
        out[i] = ring[(t + 2 + i) & (rs - 1)];
    }

    let new_tail = tail.wrapping_add(frame_len);
    Some((new_tail, len))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_new_valid() {
        let hdr = ShmemHeader::new(4096);
        assert_eq!(hdr.magic, MAGIC);
        assert_eq!(hdr.version, VERSION);
        assert_eq!(hdr.ring_size, 4096);
        assert_eq!(hdr.total_size(), 32 + 4096 * 2);
    }

    #[test]
    fn header_new_min_size() {
        let hdr = ShmemHeader::new(RING_SIZE_MIN);
        assert_eq!(hdr.ring_size, RING_SIZE_MIN);
    }

    #[test]
    fn header_new_max_size() {
        let hdr = ShmemHeader::new(RING_SIZE_MAX);
        assert_eq!(hdr.ring_size, RING_SIZE_MAX);
    }

    #[test]
    #[should_panic(expected = "ring_size must be power of 2")]
    fn header_new_non_power_of_2() {
        ShmemHeader::new(1000);
    }

    #[test]
    #[should_panic(expected = "ring_size out of range")]
    fn header_new_too_small() {
        ShmemHeader::new(256); // below RING_SIZE_MIN
    }

    #[test]
    fn header_encode_decode_roundtrip() {
        let hdr = ShmemHeader::new(4096);
        let mut buf = [0u8; HEADER_SIZE];
        hdr.encode(&mut buf).unwrap();
        let decoded = ShmemHeader::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn header_encode_decode_with_indices() {
        let mut hdr = ShmemHeader::new(1024);
        hdr.cmd_head = 100;
        hdr.cmd_tail = 50;
        hdr.rsp_head = 200;
        hdr.rsp_tail = 150;
        let mut buf = [0u8; HEADER_SIZE];
        hdr.encode(&mut buf).unwrap();
        let decoded = ShmemHeader::decode(&buf).unwrap();
        assert_eq!(decoded.cmd_head, 100);
        assert_eq!(decoded.cmd_tail, 50);
        assert_eq!(decoded.rsp_head, 200);
        assert_eq!(decoded.rsp_tail, 150);
    }

    #[test]
    fn header_decode_wrong_magic() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(ShmemHeader::decode(&buf).is_none());
    }

    #[test]
    fn header_decode_wrong_version() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(ShmemHeader::decode(&buf).is_none());
    }

    #[test]
    fn header_decode_bad_ring_size() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&1000u32.to_le_bytes()); // not power of 2
        assert!(ShmemHeader::decode(&buf).is_none());
    }

    #[test]
    fn header_decode_too_short() {
        let buf = [0u8; 16];
        assert!(ShmemHeader::decode(&buf).is_none());
    }

    #[test]
    fn header_encode_buffer_too_small() {
        let hdr = ShmemHeader::new(4096);
        let mut buf = [0u8; 16];
        assert!(hdr.encode(&mut buf).is_none());
    }

    #[test]
    fn header_offsets() {
        let hdr = ShmemHeader::new(4096);
        assert_eq!(hdr.cmd_ring_offset(), HEADER_SIZE);
        assert_eq!(hdr.rsp_ring_offset(), HEADER_SIZE + 4096);
    }

    // -- Ring buffer tests --

    #[test]
    fn ring_readable_empty() {
        assert_eq!(ring_readable(0, 0, 0xFF), 0);
    }

    #[test]
    fn ring_readable_with_data() {
        assert_eq!(ring_readable(10, 5, 0xFF), 5);
    }

    #[test]
    fn ring_readable_wrapped() {
        // head wrapped past ring size.
        assert_eq!(ring_readable(3, 250, 0xFF), 9);
    }

    #[test]
    fn ring_writable_empty() {
        // Full ring minus 1 reserved byte.
        assert_eq!(ring_writable(0, 0, 0xFF), 0xFF);
    }

    #[test]
    fn ring_writable_partial() {
        assert_eq!(ring_writable(10, 0, 0xFF), 0xFF - 10);
    }

    #[test]
    fn ring_write_and_read() {
        let ring_size: u32 = 512;
        let mut ring = [0u8; 512];
        let data = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];

        // Write message.
        let new_head = ring_write(&mut ring, 0, 0, ring_size, &data).unwrap();
        assert_eq!(new_head, 9); // 2 (len) + 7 (data)

        // Read message back.
        let mut out = [0u8; 261];
        let (new_tail, len) = ring_read(&ring, new_head, 0, ring_size, &mut out).unwrap();
        assert_eq!(new_tail, 9);
        assert_eq!(len, 7);
        assert_eq!(&out[..7], &data);
    }

    #[test]
    fn ring_write_wrapping() {
        let ring_size: u32 = 512;
        let mut ring = [0u8; 512];
        let data = [0xAA; 10];

        // Start near the end of the ring.
        let head = 506;
        let tail = 506; // empty
        let new_head = ring_write(&mut ring, head, tail, ring_size, &data).unwrap();

        // Head is monotonically increasing: 506 + 12 = 518 (not masked).
        assert_eq!(new_head, 518);

        // Read it back.
        let mut out = [0u8; 261];
        let (new_tail, len) = ring_read(&ring, new_head, tail, ring_size, &mut out).unwrap();
        assert_eq!(len, 10);
        assert_eq!(&out[..10], &data);
        assert_eq!(new_tail, new_head);
    }

    #[test]
    fn ring_write_full() {
        let ring_size: u32 = 512;
        let mut ring = [0u8; 512];

        // Fill the ring.
        let mut head: u32 = 0;
        let tail: u32 = 0;
        let data = [0xBB; 50]; // 52 bytes per message (2 + 50)
        for _ in 0..9 {
            // 9 * 52 = 468 < 511 writable
            head = ring_write(&mut ring, head, tail, ring_size, &data).unwrap();
        }

        // 10th should fail (468 + 52 = 520 > 511).
        assert!(ring_write(&mut ring, head, tail, ring_size, &data).is_none());
    }

    #[test]
    fn ring_read_empty() {
        let ring = [0u8; 512];
        let mut out = [0u8; 261];
        assert!(ring_read(&ring, 0, 0, 512, &mut out).is_none());
    }

    #[test]
    fn ring_multiple_messages() {
        let ring_size: u32 = 512;
        let mut ring = [0u8; 512];

        let msg1 = [0x01, 0x02, 0x03];
        let msg2 = [0x04, 0x05, 0x06, 0x07, 0x08];

        let h1 = ring_write(&mut ring, 0, 0, ring_size, &msg1).unwrap();
        let h2 = ring_write(&mut ring, h1, 0, ring_size, &msg2).unwrap();

        let mut out = [0u8; 261];
        let (t1, len1) = ring_read(&ring, h2, 0, ring_size, &mut out).unwrap();
        assert_eq!(len1, 3);
        assert_eq!(&out[..3], &msg1);

        let (t2, len2) = ring_read(&ring, h2, t1, ring_size, &mut out).unwrap();
        assert_eq!(len2, 5);
        assert_eq!(&out[..5], &msg2);

        // Ring now empty.
        assert!(ring_read(&ring, h2, t2, ring_size, &mut out).is_none());
    }
}
