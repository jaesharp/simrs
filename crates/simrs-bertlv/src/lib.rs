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
//! ```
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

/// Maximum length value encodable in BER short form (single byte, bit 8 = 0).
///
/// Per ISO/IEC 8825-1 clause 8.1.3.4, values 0..=127 use short form;
/// 128 and above require long form (`0x81` + 1 byte, or `0x82` + 2 bytes).
pub const BER_SHORT_FORM_MAX: usize = 0x7F;

/// BER long-form length prefix: 1 subsequent length byte follows.
///
/// Per ISO/IEC 8825-1 clause 8.1.3.5. Encodes lengths 128..=255.
pub const BER_LONG_FORM_1: u8 = 0x81;

/// BER long-form length prefix: 2 subsequent length bytes follow.
///
/// Per ISO/IEC 8825-1 clause 8.1.3.5. Encodes lengths 256..=65535.
pub const BER_LONG_FORM_2: u8 = 0x82;

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

impl core::fmt::Display for BerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferFull => f.write_str("buffer full"),
            Self::InvalidTag => f.write_str("invalid tag"),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::Truncated => f.write_str("truncated"),
        }
    }
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
/// ```
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
    pub const fn new(buf: &'buf mut [u8]) -> Self {
        Self { buf: Some(buf), pos: 0 }
    }

    /// Create a dry-run encoder that counts bytes without writing.
    pub const fn dry_run() -> Self {
        Self { buf: None, pos: 0 }
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
        // Check total size before writing anything (atomicity).
        let total = 1 + length_of_length(value.len()) + value.len();
        if let Some(ref buf) = self.buf {
            if self.pos + total > buf.len() {
                return Err(BerError::BufferFull);
            }
        }
        self.raw(&[tag])?;
        self.write_ber_length(value.len())?;
        self.raw(value)
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
        let total = 2 + length_of_length(value.len()) + value.len();
        if let Some(ref buf) = self.buf {
            if self.pos + total > buf.len() {
                return Err(BerError::BufferFull);
            }
        }
        self.raw(&[tag_hi, tag_lo])?;
        self.write_ber_length(value.len())?;
        self.raw(value)
    }

    /// Write raw bytes (no tag/length envelope).
    ///
    /// # Errors
    ///
    /// Returns [`BerError::BufferFull`] if the buffer cannot fit the bytes.
    pub fn raw(&mut self, data: &[u8]) -> Result<(), BerError> {
        if let Some(ref mut buf) = self.buf {
            if self.pos + data.len() > buf.len() {
                return Err(BerError::BufferFull);
            }
            buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        }
        self.pos += data.len();
        Ok(())
    }

    /// Write BER-encoded length field.
    #[allow(clippy::cast_possible_truncation)] // guarded by if-branches
    fn write_ber_length(&mut self, len: usize) -> Result<(), BerError> {
        if len <= BER_SHORT_FORM_MAX {
            self.raw(&[len as u8])
        } else if len <= 0xFF {
            self.raw(&[BER_LONG_FORM_1, len as u8])
        } else {
            let hi = (len >> 8) as u8;
            let lo = len as u8;
            self.raw(&[BER_LONG_FORM_2, hi, lo])
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// A single decoded TLV object (borrowed from input).
///
/// ```
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
/// ```
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
        if self.pos >= self.data.len() {
            return None;
        }

        // -- Tag --
        let tag = self.data[self.pos];
        self.pos += 1;

        // Multi-byte tag: low 5 bits of first byte are all 1s.
        if tag & 0x1F == 0x1F {
            return Some(Err(BerError::InvalidTag));
        }

        // -- Length --
        if self.pos >= self.data.len() {
            return Some(Err(BerError::Truncated));
        }
        let first = self.data[self.pos];
        self.pos += 1;

        let len = if usize::from(first) <= BER_SHORT_FORM_MAX {
            // Short form.
            first as usize
        } else if first == BER_LONG_FORM_1 {
            // Long form: 1 subsequent byte.
            if self.pos >= self.data.len() {
                return Some(Err(BerError::Truncated));
            }
            let l = self.data[self.pos] as usize;
            self.pos += 1;
            l
        } else if first == BER_LONG_FORM_2 {
            // Long form: 2 subsequent bytes.
            if self.pos + 1 >= self.data.len() {
                return Some(Err(BerError::Truncated));
            }
            let l = ((self.data[self.pos] as usize) << 8)
                | (self.data[self.pos + 1] as usize);
            self.pos += 2;
            l
        } else {
            return Some(Err(BerError::InvalidLength));
        };

        // -- Value --
        if self.pos + len > self.data.len() {
            return Some(Err(BerError::Truncated));
        }
        let value = &self.data[self.pos..self.pos + len];
        self.pos += len;

        Some(Ok(TlvObject { tag, value }))
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
    if len <= BER_SHORT_FORM_MAX { 1 } else if len <= 0xFF { 2 } else { 3 }
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

    // -- BER long-form lengths --

    #[test]
    fn encode_decode_two_byte_length() {
        // 200-byte value needs 0x81 length encoding
        let value = [0xAA; 200];
        let mut buf = [0u8; 256];
        let mut enc = Encoder::new(&mut buf);
        enc.tag_length_value(0x80, &value).unwrap();
        // tag(1) + 0x81(1) + len(1) + value(200) = 203
        assert_eq!(enc.len(), 203);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x81);
        assert_eq!(buf[2], 200);

        let mut dec = Decoder::new(&buf[..203]);
        let obj = dec.next().unwrap().unwrap();
        assert_eq!(obj.tag, 0x80);
        assert_eq!(obj.value.len(), 200);
        assert!(obj.value.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn encode_decode_three_byte_length() {
        // 300-byte value needs 0x82 length encoding
        let value = [0xBB; 300];
        let mut buf = [0u8; 512];
        let mut enc = Encoder::new(&mut buf);
        enc.tag_length_value(0x62, &value).unwrap();
        // tag(1) + 0x82(1) + hi(1) + lo(1) + value(300) = 304
        assert_eq!(enc.len(), 304);
        assert_eq!(buf[0], 0x62);
        assert_eq!(buf[1], 0x82);
        assert_eq!(buf[2], 0x01); // 300 >> 8
        assert_eq!(buf[3], 0x2C); // 300 & 0xFF

        let mut dec = Decoder::new(&buf[..304]);
        let obj = dec.next().unwrap().unwrap();
        assert_eq!(obj.tag, 0x62);
        assert_eq!(obj.value.len(), 300);
    }

    // -- 2-byte tag --

    #[test]
    fn encode_decode_two_byte_tag() {
        let mut buf = [0u8; 16];
        let mut enc = Encoder::new(&mut buf);
        enc.tag2_length_value(0xDF, 0x21, &[0x01]).unwrap();
        assert_eq!(enc.len(), 4); // tag(2) + len(1) + value(1)
        assert_eq!(&buf[..4], &[0xDF, 0x21, 0x01, 0x01]);
    }

    // -- Decoder: multi-byte tag rejection --

    #[test]
    fn decode_multibyte_tag_is_error() {
        // Tag byte 0x1F means "multi-byte tag follows"
        let data = [0x1F, 0x80, 0x02, 0x00, 0x10];
        let mut dec = Decoder::new(&data);
        assert_eq!(dec.next().unwrap(), Err(BerError::InvalidTag));
    }

    // -- Encoder: raw --

    #[test]
    fn raw_writes_bytes() {
        let mut buf = [0u8; 8];
        let mut enc = Encoder::new(&mut buf);
        enc.raw(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(enc.len(), 3);
        assert_eq!(&buf[..3], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn raw_buffer_full() {
        let mut buf = [0u8; 2];
        let mut enc = Encoder::new(&mut buf);
        assert_eq!(enc.raw(&[0x01, 0x02, 0x03]), Err(BerError::BufferFull));
    }

    // -- Encoder: atomicity --

    #[test]
    fn tag_length_value_does_not_partial_write_on_overflow() {
        let mut buf = [0u8; 4];
        let mut enc = Encoder::new(&mut buf);
        // This fits: tag(1) + len(1) + value(1) = 3
        enc.tag_length_value(0x80, &[0x01]).unwrap();
        assert_eq!(enc.len(), 3);
        // This won't fit: tag(1) + len(1) + value(1) = 3, only 1 byte left
        let err = enc.tag_length_value(0x81, &[0x02]);
        assert_eq!(err, Err(BerError::BufferFull));
        // Original write is still intact, position unchanged
        assert_eq!(enc.len(), 3);
        assert_eq!(&buf[..3], &[0x80, 0x01, 0x01]);
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Any single TLV with a valid single-byte tag (low 5 bits != 0x1F)
    // roundtrips through encode then decode.
    proptest! {
        #[test]
        fn roundtrip_single_tlv(
            tag in (0u8..=0xFE).prop_filter("not multi-byte tag indicator",
                |t| t & 0x1F != 0x1F),
            value in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut buf = [0u8; 512];
            let mut enc = Encoder::new(&mut buf);
            enc.tag_length_value(tag, &value).unwrap();
            let written = enc.len();

            let mut dec = Decoder::new(&buf[..written]);
            let obj = dec.next().unwrap().unwrap();
            prop_assert_eq!(obj.tag, tag);
            prop_assert_eq!(obj.value, &value[..]);
            prop_assert!(dec.next().is_none());
        }
    }

    // Dry-run byte count always equals real write byte count.
    proptest! {
        #[test]
        fn dry_run_matches_real(
            tag in (0u8..=0xFE).prop_filter("not multi-byte",
                |t| t & 0x1F != 0x1F),
            value in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut dry = Encoder::dry_run();
            dry.tag_length_value(tag, &value).unwrap();
            let expected = dry.len();

            let mut buf = [0u8; 512];
            let mut enc = Encoder::new(&mut buf);
            enc.tag_length_value(tag, &value).unwrap();
            prop_assert_eq!(enc.len(), expected);
        }
    }

    // Encoded length field uses the correct BER encoding form.
    proptest! {
        #[test]
        #[allow(clippy::cast_possible_truncation)]
        fn ber_length_encoding_correct(
            value in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut buf = [0u8; 512];
            let mut enc = Encoder::new(&mut buf);
            enc.tag_length_value(0x80, &value).unwrap();

            // Check the length field after the tag byte
            let vlen = value.len();
            if vlen <= 0x7F {
                prop_assert_eq!(buf[1], vlen as u8);
            } else if vlen <= 0xFF {
                prop_assert_eq!(buf[1], 0x81);
                prop_assert_eq!(buf[2], vlen as u8);
            } else {
                prop_assert_eq!(buf[1], 0x82);
                prop_assert_eq!(buf[2], (vlen >> 8) as u8);
                prop_assert_eq!(buf[3], vlen as u8);
            }
        }
    }

    // Multiple TLVs roundtrip: encode N TLVs, decode them all back.
    proptest! {
        #[test]
        fn roundtrip_multiple_tlvs(
            tlvs in proptest::collection::vec(
                (
                    (0u8..=0xFE).prop_filter("not multi-byte",
                        |t| t & 0x1F != 0x1F),
                    proptest::collection::vec(any::<u8>(), 0..64),
                ),
                1..8,
            ),
        ) {
            let mut buf = [0u8; 2048];
            let mut enc = Encoder::new(&mut buf);
            for (tag, ref value) in &tlvs {
                enc.tag_length_value(*tag, value).unwrap();
            }
            let written = enc.len();

            let mut dec = Decoder::new(&buf[..written]);
            for (tag, ref value) in &tlvs {
                let obj = dec.next().unwrap().unwrap();
                prop_assert_eq!(obj.tag, *tag);
                prop_assert_eq!(obj.value, &value[..]);
            }
            prop_assert!(dec.next().is_none());
        }
    }
}
