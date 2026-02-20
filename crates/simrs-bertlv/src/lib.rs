//! BER-TLV encoding and decoding.
//!
//! Provides `Encoder` (write TLV objects into a buffer, with dry-run mode)
//! and `Decoder` (iterate TLV objects from a byte slice). Used throughout
//! simrs for FCP construction, proactive command encoding, and AUTHENTICATE
//! response parsing.
//!
//! # Dry-Run Mode
//!
//! The `Encoder` supports a dry-run mode that counts bytes without writing.
//! This enables the size-first pattern used in FCP construction:
//! compute total length, then write.
//!
//! ```ignore
//! use simrs_bertlv::Encoder;
//!
//! // Dry run: count bytes
//! let mut dry = Encoder::dry_run();
//! dry.tag_length_value(0x80, &[0x01, 0x02]).unwrap();
//! let needed = dry.len();
//!
//! // Real write
//! let mut buf = [0u8; 64];
//! let mut enc = Encoder::new(&mut buf);
//! enc.tag_length_value(0x80, &[0x01, 0x02]).unwrap();
//! assert_eq!(enc.len(), needed);
//! ```
//!
//! # BER Length Encoding
//!
//! | Value Range | Encoding | Bytes |
//! |-------------|----------|-------|
//! | 0--127 | `len` | 1 |
//! | 128--255 | `0x81, len` | 2 |
//! | 256--65535 | `0x82, hi, lo` | 3 |
//!
//! # Standards
//! - ETSI TS 101 220 V17.1.0 -- BER-TLV tag assignments
//! - ISO/IEC 8825-1 -- Basic Encoding Rules
//! - ETSI TS 102 221 V16.4.0 clause 11.1 -- FCP BER-TLV
//!
//! # `no_std`
//! Fully `no_std`. No heap allocation.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

/// BER-TLV error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    /// Output buffer is full (encoder).
    BufferFull,
    /// Tag encoding is invalid or unsupported (decoder: multi-byte tag).
    InvalidTag,
    /// Length encoding is invalid or uses unsupported long form (decoder).
    InvalidLength,
    /// Input data is truncated (fewer bytes than length field indicates).
    Truncated,
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// BER-TLV encoder that writes into a caller-supplied buffer.
///
/// Two modes:
/// - **Real:** `Encoder::new(&mut buf)` writes TLV bytes.
/// - **Dry-run:** `Encoder::dry_run()` counts bytes without writing.
///
/// Both modes track position via `len()`.
///
/// ```ignore
/// use simrs_bertlv::Encoder;
///
/// let mut buf = [0u8; 32];
/// let mut enc = Encoder::new(&mut buf);
/// enc.tag_length_value(0x62, &[0x80, 0x02, 0x00, 0x10]).unwrap();
/// assert_eq!(enc.len(), 6); // tag(1) + length(1) + value(4)
/// assert_eq!(&buf[..6], &[0x62, 0x04, 0x80, 0x02, 0x00, 0x10]);
/// ```
pub struct Encoder<'buf> {
    buf: Option<&'buf mut [u8]>,
    pos: usize,
}

impl<'buf> Encoder<'buf> {
    /// Create an encoder that writes into `buf`.
    pub fn new(buf: &'buf mut [u8]) -> Self {
        todo!("Encoder::new")
    }

    /// Create a dry-run encoder that counts bytes without writing.
    pub fn dry_run() -> Self {
        todo!("Encoder::dry_run")
    }

    /// Number of bytes written (or counted in dry-run mode).
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// Whether any bytes have been written.
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Write a complete TLV: single-byte tag + BER length + value.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::BufferFull`] if the buffer cannot fit the TLV.
    pub fn tag_length_value(&mut self, tag: u8, value: &[u8]) -> Result<(), BerError> {
        todo!("Encoder::tag_length_value")
    }

    /// Write a complete TLV with a 2-byte tag.
    ///
    /// # Errors
    ///
    /// Returns [`BerError::BufferFull`] if the buffer cannot fit the TLV.
    pub fn tag2_length_value(
        &mut self,
        tag_hi: u8,
        tag_lo: u8,
        value: &[u8],
    ) -> Result<(), BerError> {
        todo!("Encoder::tag2_length_value")
    }

    /// Write raw bytes (no tag/length envelope).
    ///
    /// # Errors
    ///
    /// Returns [`BerError::BufferFull`] if the buffer cannot fit the bytes.
    pub fn raw(&mut self, data: &[u8]) -> Result<(), BerError> {
        todo!("Encoder::raw")
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// A single decoded TLV object (borrowed from input).
///
/// ```ignore
/// use simrs_bertlv::{Decoder, TlvObject};
///
/// let data = [0x80, 0x02, 0x00, 0x10];
/// let mut dec = Decoder::new(&data);
/// let obj = dec.next().unwrap().unwrap();
/// assert_eq!(obj.tag, 0x80);
/// assert_eq!(obj.value, &[0x00, 0x10]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvObject<'a> {
    /// Tag byte (single-byte tags; multi-byte tags return `BerError::InvalidTag`).
    pub tag: u8,
    /// Value bytes (borrowed from input slice).
    pub value: &'a [u8],
}

/// BER-TLV decoder: iterates `TlvObject` items from a byte slice.
///
/// Handles single-byte tags and BER definite-length (short + long forms).
/// Multi-byte tags are skipped with `BerError::InvalidTag`.
///
/// ```ignore
/// use simrs_bertlv::Decoder;
///
/// let data = [0x62, 0x04, 0x80, 0x02, 0x00, 0x10];
/// let mut dec = Decoder::new(&data);
/// let fcp = dec.next().unwrap().unwrap();
/// assert_eq!(fcp.tag, 0x62);
/// assert_eq!(fcp.value.len(), 4);
///
/// // Nest into the FCP template
/// let mut inner = Decoder::new(fcp.value);
/// let size = inner.next().unwrap().unwrap();
/// assert_eq!(size.tag, 0x80);
/// ```
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Create a decoder over the given byte slice.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Remaining undecoded bytes.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

impl<'a> Iterator for Decoder<'a> {
    type Item = Result<TlvObject<'a>, BerError>;

    fn next(&mut self) -> Option<Self::Item> {
        todo!("Decoder::next")
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Number of bytes needed to BER-encode a length value.
///
/// ```
/// use simrs_bertlv::length_of_length;
///
/// assert_eq!(length_of_length(0), 1);     // short form
/// assert_eq!(length_of_length(127), 1);
/// assert_eq!(length_of_length(128), 2);   // 0x81 + 1 byte
/// assert_eq!(length_of_length(255), 2);
/// assert_eq!(length_of_length(256), 3);   // 0x82 + 2 bytes
/// ```
pub const fn length_of_length(len: usize) -> usize {
    if len <= 0x7F { 1 } else if len <= 0xFF { 2 } else { 3 }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Encoder --

    #[test]
    fn encode_simple_tlv() {
        let mut buf = [0u8; 16];
        let mut enc = Encoder::new(&mut buf);
        enc.tag_length_value(0x80, &[0x01, 0x02]).unwrap();
        assert_eq!(enc.len(), 4); // tag(1) + len(1) + value(2)
        assert_eq!(&buf[..4], &[0x80, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn encode_empty_value() {
        let mut buf = [0u8; 16];
        let mut enc = Encoder::new(&mut buf);
        enc.tag_length_value(0x8A, &[]).unwrap();
        assert_eq!(enc.len(), 2);
        assert_eq!(&buf[..2], &[0x8A, 0x00]);
    }

    #[test]
    fn encode_buffer_full() {
        let mut buf = [0u8; 3];
        let mut enc = Encoder::new(&mut buf);
        assert_eq!(
            enc.tag_length_value(0x80, &[0x01, 0x02, 0x03]),
            Err(BerError::BufferFull)
        );
    }

    #[test]
    fn dry_run_counts_match_real_write() {
        let value = &[0x01, 0x02, 0x03, 0x04];

        let mut dry = Encoder::dry_run();
        dry.tag_length_value(0x62, value).unwrap();
        dry.tag_length_value(0x80, &[0x00, 0x10]).unwrap();
        let needed = dry.len();

        let mut buf = [0u8; 64];
        let mut enc = Encoder::new(&mut buf);
        enc.tag_length_value(0x62, value).unwrap();
        enc.tag_length_value(0x80, &[0x00, 0x10]).unwrap();
        assert_eq!(enc.len(), needed);
    }

    // -- Decoder --

    #[test]
    fn decode_single_tlv() {
        let data = [0x80, 0x02, 0x00, 0x10];
        let mut dec = Decoder::new(&data);
        let obj = dec.next().unwrap().unwrap();
        assert_eq!(obj.tag, 0x80);
        assert_eq!(obj.value, &[0x00, 0x10]);
        assert!(dec.next().is_none());
    }

    #[test]
    fn decode_nested_fcp() {
        let data = [0x62, 0x04, 0x80, 0x02, 0x00, 0x10];
        let mut outer = Decoder::new(&data);
        let fcp = outer.next().unwrap().unwrap();
        assert_eq!(fcp.tag, 0x62);

        let mut inner = Decoder::new(fcp.value);
        let size = inner.next().unwrap().unwrap();
        assert_eq!(size.tag, 0x80);
        assert_eq!(size.value, &[0x00, 0x10]);
    }

    #[test]
    fn decode_truncated_is_error() {
        let data = [0x80, 0x05, 0x01, 0x02];
        let mut dec = Decoder::new(&data);
        assert_eq!(dec.next().unwrap(), Err(BerError::Truncated));
    }

    #[test]
    fn decode_empty_input() {
        let mut dec = Decoder::new(&[]);
        assert!(dec.next().is_none());
    }

    #[test]
    fn decode_empty_value() {
        let data = [0x8A, 0x00];
        let mut dec = Decoder::new(&data);
        let obj = dec.next().unwrap().unwrap();
        assert_eq!(obj.tag, 0x8A);
        assert!(obj.value.is_empty());
    }

    // -- Roundtrip --

    #[test]
    fn encode_decode_roundtrip() {
        let mut buf = [0u8; 64];
        let mut enc = Encoder::new(&mut buf);
        enc.tag_length_value(0x80, &[0xDE, 0xAD]).unwrap();
        enc.tag_length_value(0x83, &[0xBE, 0xEF]).unwrap();
        let written = enc.len();

        let mut dec = Decoder::new(&buf[..written]);
        let obj1 = dec.next().unwrap().unwrap();
        assert_eq!(obj1.tag, 0x80);
        assert_eq!(obj1.value, &[0xDE, 0xAD]);
        let obj2 = dec.next().unwrap().unwrap();
        assert_eq!(obj2.tag, 0x83);
        assert_eq!(obj2.value, &[0xBE, 0xEF]);
        assert!(dec.next().is_none());
    }

    // -- length_of_length --

    #[test]
    fn length_of_length_values() {
        assert_eq!(length_of_length(0), 1);
        assert_eq!(length_of_length(127), 1);
        assert_eq!(length_of_length(128), 2);
        assert_eq!(length_of_length(255), 2);
        assert_eq!(length_of_length(256), 3);
    }
}
