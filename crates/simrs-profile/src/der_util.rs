//! DER TLV iteration helpers.
//!
//! Thin utilities over raw DER bytes for parsing TCA Profile Packages.
//! The TCA spec uses ASN.1 DER with AUTOMATIC TAGS and IMPLICIT tagging.

use crate::error::ProfileError;

/// A parsed DER tag-length-value triple (zero-copy).
#[derive(Clone, Debug)]
pub struct Tlv<'a> {
    /// Raw tag byte(s). For context-specific: class bits + number.
    pub tag: u8,
    /// Whether the tag is constructed (bit 5 set).
    pub constructed: bool,
    /// Tag class: 0=universal, 1=application, 2=context-specific, 3=private.
    pub class: u8,
    /// Tag number (low 5 bits for single-byte tags).
    pub number: u8,
    /// Value bytes (the content after tag+length).
    pub value: &'a [u8],
}

/// Decode a DER length field starting at `data[0]`.
///
/// Returns `(length_value, bytes_consumed)`.
///
/// # Errors
///
/// Returns [`ProfileError::Truncated`] if the data is too short, or
/// [`ProfileError::InvalidTag`] for unsupported length forms.
pub fn decode_length(data: &[u8]) -> Result<(usize, usize), ProfileError> {
    if data.is_empty() {
        return Err(ProfileError::Truncated);
    }
    let first = data[0];
    if first < 0x80 {
        // Short form: length in one byte.
        Ok((first as usize, 1))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err(ProfileError::Truncated);
        }
        Ok((data[1] as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err(ProfileError::Truncated);
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((len, 3))
    } else if first == 0x83 {
        if data.len() < 4 {
            return Err(ProfileError::Truncated);
        }
        let len = ((data[1] as usize) << 16)
            | ((data[2] as usize) << 8)
            | (data[3] as usize);
        Ok((len, 4))
    } else {
        // Indefinite length (0x80) or longer forms not used in DER profiles.
        Err(ProfileError::InvalidTag(first))
    }
}

/// Parse a single TLV from the start of `data`.
///
/// Returns the parsed TLV and the number of bytes consumed.
///
/// # Errors
///
/// Returns [`ProfileError::Truncated`] if the data is too short, or
/// [`ProfileError::InvalidTag`] for unsupported tag encodings.
pub fn parse_tlv(data: &[u8]) -> Result<(Tlv<'_>, usize), ProfileError> {
    if data.is_empty() {
        return Err(ProfileError::Truncated);
    }

    let tag_byte = data[0];
    let class = (tag_byte >> 6) & 0x03;
    let constructed = (tag_byte & 0x20) != 0;
    let number = tag_byte & 0x1F;

    // For simplicity, handle single-byte tags only (tag number < 31).
    // Multi-byte tags (number == 31) are rare in TCA profiles but we
    // handle the common case of tag numbers up to 30.
    let tag_len = if number == 0x1F {
        // Multi-byte tag: subsequent bytes until one without bit 7 set.
        // For TCA profiles with AUTOMATIC TAGS, tag numbers go up to ~28,
        // which fits in a single continuation byte.
        if data.len() < 2 {
            return Err(ProfileError::Truncated);
        }
        // Read continuation byte(s).
        let mut i = 1;
        while i < data.len() && (data[i] & 0x80) != 0 {
            i += 1;
        }
        if i >= data.len() {
            return Err(ProfileError::Truncated);
        }
        i + 1 // include the final byte (bit 7 clear)
    } else {
        1
    };

    // For multi-byte tags, extract the actual number.
    let actual_number = if number == 0x1F {
        // Simple case: one continuation byte (tag number < 128).
        if tag_len == 2 {
            data[1] & 0x7F
        } else {
            // For larger numbers, we only support up to 127 for now.
            return Err(ProfileError::InvalidTag(tag_byte));
        }
    } else {
        number
    };

    let (value_len, len_bytes) = decode_length(&data[tag_len..])?;
    let total_header = tag_len + len_bytes;

    if data.len() < total_header + value_len {
        return Err(ProfileError::Truncated);
    }

    let value = &data[total_header..total_header + value_len];

    Ok((
        Tlv {
            tag: tag_byte,
            constructed,
            class,
            number: actual_number,
            value,
        },
        total_header + value_len,
    ))
}

/// Iterate over TLV children inside a constructed (SEQUENCE/SET) value.
///
/// The `data` parameter is the value bytes of the outer SEQUENCE (not
/// including the outer tag+length).
#[must_use]
pub const fn iter_tlvs(data: &[u8]) -> TlvIter<'_> {
    TlvIter { remaining: data }
}

/// Iterator over TLV elements in a byte slice.
pub struct TlvIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<Tlv<'a>, ProfileError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match parse_tlv(self.remaining) {
            Ok((tlv, consumed)) => {
                self.remaining = &self.remaining[consumed..];
                Some(Ok(tlv))
            }
            Err(e) => {
                self.remaining = &[]; // stop iteration on error
                Some(Err(e))
            }
        }
    }
}

/// Decode an unsigned integer from big-endian bytes (1-4 bytes).
pub fn decode_uint(data: &[u8]) -> u32 {
    let mut val: u32 = 0;
    for &b in data {
        val = (val << 8) | u32::from(b);
    }
    val
}

/// Unwrap a SEQUENCE: verify the outer tag is 0x30, return inner bytes.
///
/// # Errors
///
/// Returns [`ProfileError::InvalidTag`] if the outer tag is not 0x30,
/// or [`ProfileError::Truncated`] if the data is too short.
pub fn unwrap_sequence(data: &[u8]) -> Result<&[u8], ProfileError> {
    let (tlv, consumed) = parse_tlv(data)?;
    if tlv.tag != 0x30 {
        return Err(ProfileError::InvalidTag(tlv.tag));
    }
    if consumed != data.len() {
        // Trailing bytes after the SEQUENCE -- tolerate for forward
        // compatibility with profile packages that have outer envelope
        // framing or padding. DER strictly forbids trailing bytes, but
        // real-world tooling (pySim, GSMA test suites) sometimes emits them.
    }
    Ok(tlv.value)
}

/// Peel an optional SEQUENCE wrapper from PE value bytes.
///
/// TCA Profile Element parsers receive value bytes that may or may not
/// still carry their outer SEQUENCE (tag 0x30) wrapper, depending on
/// whether `parse_profile_package` stripped it. This helper normalizes
/// both forms: if `data` starts with 0x30 it unwraps; otherwise it
/// returns `data` as-is.
///
/// # Errors
///
/// Returns [`ProfileError`] if a 0x30-tagged wrapper is present but
/// its length encoding is malformed.
pub fn peel_optional_sequence(data: &[u8]) -> Result<&[u8], ProfileError> {
    if data.first() == Some(&0x30) {
        unwrap_sequence(data)
    } else {
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_short_length() {
        assert_eq!(decode_length(&[0x05]).unwrap(), (5, 1));
        assert_eq!(decode_length(&[0x7F]).unwrap(), (127, 1));
    }

    #[test]
    fn decode_long_length_one_byte() {
        assert_eq!(decode_length(&[0x81, 0x80]).unwrap(), (128, 2));
        assert_eq!(decode_length(&[0x81, 0xFF]).unwrap(), (255, 2));
    }

    #[test]
    fn decode_long_length_two_bytes() {
        assert_eq!(decode_length(&[0x82, 0x01, 0x00]).unwrap(), (256, 3));
        assert_eq!(decode_length(&[0x82, 0x10, 0x00]).unwrap(), (4096, 3));
    }

    #[test]
    fn parse_simple_tlv() {
        // OCTET STRING, length 3, value [01, 02, 03]
        let data = [0x04, 0x03, 0x01, 0x02, 0x03];
        let (tlv, consumed) = parse_tlv(&data).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(tlv.class, 0); // universal
        assert!(!tlv.constructed);
        assert_eq!(tlv.number, 4); // OCTET STRING
        assert_eq!(tlv.value, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn parse_context_specific_constructed() {
        // Context [14] CONSTRUCTED, length 2, value [FF, FF]
        // Tag: 0xA0 | 14 = 0xAE
        let data = [0xAE, 0x02, 0xFF, 0xFF];
        let (tlv, consumed) = parse_tlv(&data).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(tlv.class, 2); // context-specific
        assert!(tlv.constructed);
        assert_eq!(tlv.number, 14);
        assert_eq!(tlv.value, &[0xFF, 0xFF]);
    }

    #[test]
    fn parse_multi_byte_tag() {
        // Context constructed, tag number 23 (> 30 requires multi-byte)
        // Actually tag number 23 < 31 so single byte: 0xA0 | 0x17 = 0xB7
        // Let's test tag number 31+ which requires multi-byte encoding
        // Context constructed [31]: 0xBF 0x1F, length 1, value [0x00]
        let data = [0xBF, 0x1F, 0x01, 0x00];
        let (tlv, consumed) = parse_tlv(&data).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(tlv.class, 2);
        assert!(tlv.constructed);
        assert_eq!(tlv.number, 31);
    }

    #[test]
    fn iter_two_tlvs() {
        // Two OCTET STRINGs: [04 01 AA] [04 02 BB CC]
        let data = [0x04, 0x01, 0xAA, 0x04, 0x02, 0xBB, 0xCC];
        let tlvs: Vec<_> = iter_tlvs(&data).collect::<Result<_, _>>().unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].value, &[0xAA]);
        assert_eq!(tlvs[1].value, &[0xBB, 0xCC]);
    }

    #[test]
    fn truncated_data_returns_error() {
        assert!(parse_tlv(&[0x04, 0x05, 0x01]).is_err());
        assert!(decode_length(&[0x82, 0x01]).is_err());
    }
}
