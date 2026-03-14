//! GSM 7-bit default alphabet pack/unpack per [3GPP TS 23.038 V19.0.0](../../../docs/specs/3gpp/ts-23.038/ts_123038v190000p.pdf).
//!
//! The GSM 7-bit default alphabet maps common ASCII-range characters to
//! 7-bit codes. Packing compresses 7-bit codes into 8-bit octets by
//! bit-shifting: the first character occupies bits 0--6 of the first byte,
//! the second character starts at bit 7 of the first byte and continues
//! into bits 0--5 of the second byte, etc.
//!
//! # Standards
//! - [3GPP TS 23.038 V19.0.0 clause 6.1.2](../../../docs/specs/3gpp/ts-23.038/ts_123038v190000p.pdf#%5B%7B%22num%22%3A37%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C443%5D) -- GSM 7 bit Default Alphabet
//! - [3GPP TS 23.038 V19.0.0 clause 6.1.2.1](../../../docs/specs/3gpp/ts-23.038/ts_123038v190000p.pdf#%5B%7B%22num%22%3A37%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C410%5D) -- Packing of 7-bit characters

/// GSM 7-bit default alphabet to ASCII mapping table.
///
/// Index = GSM 7-bit code (0x00..0x7F), value = ASCII equivalent.
/// Characters with no clean ASCII equivalent map to `b'?'`.
///
/// Per [3GPP TS 23.038 V19.0.0 clause 6.2.1](../../../docs/specs/3gpp/ts-23.038/ts_123038v190000p.pdf#%5B%7B%22num%22%3A47%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C673%5D), Table 6.2.1.
const GSM7_TO_ASCII_TABLE: [u8; 128] = [
    b'@',  // 0x00
    0xA3,  // 0x01  pound sign (not pure ASCII, mapped to 0xA3 Latin-1)
    b'$',  // 0x02
    0xA5,  // 0x03  yen sign
    0xE8,  // 0x04  e-grave
    0xE9,  // 0x05  e-acute
    0xF9,  // 0x06  u-grave
    0xEC,  // 0x07  i-grave
    0xF2,  // 0x08  o-grave
    0xC7,  // 0x09  C-cedilla
    b'\n', // 0x0A  LF
    0xD8,  // 0x0B  O-stroke
    0xF8,  // 0x0C  o-stroke
    b'\r', // 0x0D  CR
    0xC5,  // 0x0E  A-ring
    0xE5,  // 0x0F  a-ring
    b'?',  // 0x10  Greek Delta -> ?
    b'_',  // 0x11  underscore
    b'?',  // 0x12  Greek Phi -> ?
    b'?',  // 0x13  Greek Gamma -> ?
    b'?',  // 0x14  Greek Lambda -> ?
    b'?',  // 0x15  Greek Omega -> ?
    b'?',  // 0x16  Greek Pi -> ?
    b'?',  // 0x17  Greek Psi -> ?
    b'?',  // 0x18  Greek Sigma -> ?
    b'?',  // 0x19  Greek Theta -> ?
    b'?',  // 0x1A  Greek Xi -> ?
    b'?',  // 0x1B  ESCAPE (extension table indicator)
    0xC6,  // 0x1C  AE ligature
    0xE6,  // 0x1D  ae ligature
    0xDF,  // 0x1E  sharp s
    0xC9,  // 0x1F  E-acute
    b' ',  // 0x20
    b'!',  // 0x21
    b'"',  // 0x22
    b'#',  // 0x23
    0xA4,  // 0x24  currency sign
    b'%',  // 0x25
    b'&',  // 0x26
    b'\'', // 0x27
    b'(',  // 0x28
    b')',  // 0x29
    b'*',  // 0x2A
    b'+',  // 0x2B
    b',',  // 0x2C
    b'-',  // 0x2D
    b'.',  // 0x2E
    b'/',  // 0x2F
    b'0',  // 0x30
    b'1',  // 0x31
    b'2',  // 0x32
    b'3',  // 0x33
    b'4',  // 0x34
    b'5',  // 0x35
    b'6',  // 0x36
    b'7',  // 0x37
    b'8',  // 0x38
    b'9',  // 0x39
    b':',  // 0x3A
    b';',  // 0x3B
    b'<',  // 0x3C
    b'=',  // 0x3D
    b'>',  // 0x3E
    b'?',  // 0x3F
    0xA1,  // 0x40  inverted !
    b'A',  // 0x41
    b'B',  // 0x42
    b'C',  // 0x43
    b'D',  // 0x44
    b'E',  // 0x45
    b'F',  // 0x46
    b'G',  // 0x47
    b'H',  // 0x48
    b'I',  // 0x49
    b'J',  // 0x4A
    b'K',  // 0x4B
    b'L',  // 0x4C
    b'M',  // 0x4D
    b'N',  // 0x4E
    b'O',  // 0x4F
    b'P',  // 0x50
    b'Q',  // 0x51
    b'R',  // 0x52
    b'S',  // 0x53
    b'T',  // 0x54
    b'U',  // 0x55
    b'V',  // 0x56
    b'W',  // 0x57
    b'X',  // 0x58
    b'Y',  // 0x59
    b'Z',  // 0x5A
    0xC4,  // 0x5B  A-diaeresis
    0xD6,  // 0x5C  O-diaeresis
    0xD1,  // 0x5D  N-tilde
    0xDC,  // 0x5E  U-diaeresis
    0xA7,  // 0x5F  section sign
    0xBF,  // 0x60  inverted ?
    b'a',  // 0x61
    b'b',  // 0x62
    b'c',  // 0x63
    b'd',  // 0x64
    b'e',  // 0x65
    b'f',  // 0x66
    b'g',  // 0x67
    b'h',  // 0x68
    b'i',  // 0x69
    b'j',  // 0x6A
    b'k',  // 0x6B
    b'l',  // 0x6C
    b'm',  // 0x6D
    b'n',  // 0x6E
    b'o',  // 0x6F
    b'p',  // 0x70
    b'q',  // 0x71
    b'r',  // 0x72
    b's',  // 0x73
    b't',  // 0x74
    b'u',  // 0x75
    b'v',  // 0x76
    b'w',  // 0x77
    b'x',  // 0x78
    b'y',  // 0x79
    b'z',  // 0x7A
    0xE4,  // 0x7B  a-diaeresis
    0xF6,  // 0x7C  o-diaeresis
    0xF1,  // 0x7D  n-tilde
    0xFC,  // 0x7E  u-diaeresis
    0xE0,  // 0x7F  a-grave
];

/// Convert a single ASCII character to its GSM 7-bit code.
///
/// Returns `None` if the character has no direct GSM 7-bit mapping.
///
/// Per [3GPP TS 23.038 V19.0.0 Table 6.2.1](../../../docs/specs/3gpp/ts-23.038/ts_123038v190000p.pdf#%5B%7B%22num%22%3A47%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C673%5D). Note that `@` maps to GSM code `0x00`.
///
/// # Example
///
/// ```
/// use simrs_proactive::gsm7;
///
/// assert_eq!(gsm7::ascii_to_gsm7(b'@'), Some(0x00));
/// assert_eq!(gsm7::ascii_to_gsm7(b'A'), Some(0x41));
/// ```
pub const fn ascii_to_gsm7(ch: u8) -> Option<u8> {
    // Linear scan of the mapping table.
    let mut i = 0u8;
    while (i as usize) < GSM7_TO_ASCII_TABLE.len() {
        if GSM7_TO_ASCII_TABLE[i as usize] == ch {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Convert a single GSM 7-bit code to its ASCII/Latin-1 equivalent.
///
/// Codes 0x00--0x7F are mapped per [3GPP TS 23.038 V19.0.0 Table 6.2.1](../../../docs/specs/3gpp/ts-23.038/ts_123038v190000p.pdf#%5B%7B%22num%22%3A47%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C673%5D).
/// Codes >= 0x80 return `b'?'`.
///
/// # Example
///
/// ```
/// use simrs_proactive::gsm7;
///
/// assert_eq!(gsm7::gsm7_to_ascii(0x00), b'@');
/// assert_eq!(gsm7::gsm7_to_ascii(0x41), b'A');
/// ```
pub const fn gsm7_to_ascii(code: u8) -> u8 {
    if (code as usize) < GSM7_TO_ASCII_TABLE.len() {
        GSM7_TO_ASCII_TABLE[code as usize]
    } else {
        b'?'
    }
}

/// Pack ASCII text into GSM 7-bit encoding.
///
/// Each input byte is converted to its GSM 7-bit code via [`ascii_to_gsm7`].
/// Characters without a mapping are replaced with `b'?'` (GSM code `0x3F`).
/// The 7-bit codes are then packed into octets per [3GPP TS 23.038 V19.0.0 clause 6.1.2.1](../../../docs/specs/3gpp/ts-23.038/ts_123038v190000p.pdf#%5B%7B%22num%22%3A37%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C410%5D).
///
/// Returns the number of bytes written to `output`.
///
/// # Packing layout
///
/// ```text
/// Char 0: bits 0-6 of byte 0
/// Char 1: bit 7 of byte 0, bits 0-5 of byte 1
/// Char 2: bits 6-7 of byte 1, bits 0-4 of byte 2
/// ...
/// ```
///
/// For N characters: output size = ceil(N * 7 / 8) bytes.
///
/// # Example
///
/// ```
/// use simrs_proactive::gsm7;
///
/// let mut out = [0u8; 8];
/// let n = gsm7::pack(b"Hello", &mut out);
/// assert!(n > 0);
/// ```
#[allow(clippy::cast_possible_truncation)]
pub fn pack(input: &[u8], output: &mut [u8]) -> usize {
    if input.is_empty() {
        return 0;
    }

    let out_len = (input.len() * 7).div_ceil(8);
    if output.len() < out_len {
        return 0;
    }

    // Zero out the output region first.
    for b in &mut output[..out_len] {
        *b = 0;
    }

    let mut bit_pos: usize = 0;
    for &ch in input {
        let gsm_code = ascii_to_gsm7(ch).unwrap_or(0x3F);

        let byte_idx = bit_pos / 8;
        let bit_offset = bit_pos % 8;

        // Place the 7-bit code starting at bit_offset within byte_idx.
        output[byte_idx] |= gsm_code << bit_offset;

        // If the code spans two bytes, write the upper bits into the next byte.
        if bit_offset > 1 {
            // bit_offset > 1 means some bits spill into next byte
            // (7 bits starting at offset > 1 means > 8 bits total)
            output[byte_idx + 1] |= gsm_code >> (8 - bit_offset);
        }

        bit_pos += 7;
    }

    out_len
}

/// Unpack GSM 7-bit encoded data back to ASCII.
///
/// Reads `num_chars` 7-bit codes from the packed `input` and writes
/// their ASCII equivalents to `output`. Returns the number of bytes
/// written to `output`.
///
/// # Example
///
/// ```
/// use simrs_proactive::gsm7;
///
/// let mut packed = [0u8; 8];
/// let n = gsm7::pack(b"Hello", &mut packed);
/// let mut unpacked = [0u8; 16];
/// let m = gsm7::unpack(&packed[..n], 5, &mut unpacked);
/// assert_eq!(&unpacked[..m], b"Hello");
/// ```
#[allow(clippy::cast_possible_truncation)]
pub fn unpack(input: &[u8], num_chars: usize, output: &mut [u8]) -> usize {
    if num_chars == 0 || output.len() < num_chars {
        return 0;
    }

    let mut bit_pos: usize = 0;
    let mut out_idx: usize = 0;

    for _ in 0..num_chars {
        let byte_idx = bit_pos / 8;
        let bit_offset = bit_pos % 8;

        if byte_idx >= input.len() {
            break;
        }

        let mut code = (input[byte_idx] >> bit_offset) & 0x7F;

        // If the code spans two bytes, read the remaining bits.
        if bit_offset > 1 && byte_idx + 1 < input.len() {
            code |= (input[byte_idx + 1] << (8 - bit_offset)) & 0x7F;
        }

        output[out_idx] = gsm7_to_ascii(code);
        out_idx += 1;
        bit_pos += 7;
    }

    out_idx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_hello() {
        let mut out = [0u8; 8];
        let n = pack(b"Hello", &mut out);
        assert!(n > 0);
        // "Hello" in GSM 7-bit packed is a well-known test vector.
        // H=0x48, e=0x65, l=0x6C, l=0x6C, o=0x6F
        // GSM codes: H=0x48, e=0x65, l=0x6C, l=0x6C, o=0x6F
        // (same as ASCII for these characters)
        // Packed: 5 chars * 7 bits = 35 bits = 5 bytes (ceil(35/8)=5)
        assert_eq!(n, 5);
    }

    #[test]
    fn unpack_hello_roundtrip() {
        let mut packed = [0u8; 8];
        let n = pack(b"Hello", &mut packed);
        let mut unpacked = [0u8; 16];
        let m = unpack(&packed[..n], 5, &mut unpacked);
        assert_eq!(m, 5);
        assert_eq!(&unpacked[..m], b"Hello");
    }

    #[test]
    fn pack_empty() {
        let mut out = [0u8; 8];
        let n = pack(b"", &mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn pack_single_char() {
        let mut out = [0u8; 4];
        let n = pack(b"A", &mut out);
        // 1 char * 7 bits = 7 bits = 1 byte
        assert_eq!(n, 1);
        // A = GSM code 0x41, bits 0-6 of byte 0
        assert_eq!(out[0], 0x41);

        // Roundtrip
        let mut unpacked = [0u8; 4];
        let m = unpack(&out[..n], 1, &mut unpacked);
        assert_eq!(m, 1);
        assert_eq!(unpacked[0], b'A');
    }

    #[test]
    fn ascii_to_gsm7_at_sign() {
        // @ = GSM code 0x00 per 3GPP TS 23.038 V19.0.0
        assert_eq!(ascii_to_gsm7(b'@'), Some(0x00));
    }

    #[test]
    fn gsm7_to_ascii_roundtrip() {
        // For printable ASCII characters that exist in GSM7, roundtrip should work.
        for ch in b'A'..=b'Z' {
            let code = ascii_to_gsm7(ch).expect("A-Z should be in GSM7");
            assert_eq!(gsm7_to_ascii(code), ch);
        }
        for ch in b'a'..=b'z' {
            let code = ascii_to_gsm7(ch).expect("a-z should be in GSM7");
            assert_eq!(gsm7_to_ascii(code), ch);
        }
        for ch in b'0'..=b'9' {
            let code = ascii_to_gsm7(ch).expect("0-9 should be in GSM7");
            assert_eq!(gsm7_to_ascii(code), ch);
        }
    }

    #[test]
    fn pack_7chars_fits_in_7_bytes() {
        // 7 chars * 7 bits = 49 bits. ceil(49/8) = 7 bytes.
        // But actually: 49/8 = 6.125, ceil = 7.
        // Wait: (7*7+7)/8 = (49+7)/8 = 56/8 = 7. Yes, 7 bytes.
        let mut out = [0u8; 8];
        let n = pack(b"ABCDEFG", &mut out);
        assert_eq!(n, 7);

        let mut unpacked = [0u8; 8];
        let m = unpack(&out[..n], 7, &mut unpacked);
        assert_eq!(m, 7);
        assert_eq!(&unpacked[..m], b"ABCDEFG");
    }

    #[test]
    fn pack_8chars_needs_7_bytes() {
        // 8 chars * 7 bits = 56 bits = exactly 7 bytes.
        let mut out = [0u8; 8];
        let n = pack(b"ABCDEFGH", &mut out);
        assert_eq!(n, 7);

        let mut unpacked = [0u8; 16];
        let m = unpack(&out[..n], 8, &mut unpacked);
        assert_eq!(m, 8);
        assert_eq!(&unpacked[..m], b"ABCDEFGH");
    }
}
