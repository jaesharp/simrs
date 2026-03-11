//! TUAK reference test vectors per [3GPP TS 35.232 V19.0.0](../../../docs/specs/3gpp/ts-35.232/ts_135232v190000p.pdf) / [3GPP TS 35.231 V19.0.0](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf).
//!
//! TUAK is the authentication algorithm for 3G/4G networks in some regions.
//! Vectors sourced from [3GPP TS 35.233 V19.0.0](../../../docs/specs/3gpp/ts-35.233/ts_135233v190000p.pdf) (conformance test data).

use crate::ReferenceSource;

/// TUAK test vector supporting both 128-bit and 256-bit keys.
#[derive(Debug, Clone, Copy)]
pub struct TuakVector {
    /// Key K (16 bytes for 128-bit, 32 bytes for 256-bit).
    /// Stored as 32 bytes, with first 16 bytes used for 128-bit keys.
    pub k: [u8; 32],
    /// Key length in bits (128 or 256).
    pub key_bits: u8,
    /// TOP (32 bytes) or TOPc (32 bytes).
    pub top: [u8; 32],
    /// Whether TOPc is pre-computed (true) or TOP (false).
    pub use_topc: bool,
    /// 16-byte random challenge RAND.
    pub rand: [u8; 16],
    /// 6-byte sequence number SQN.
    pub sqn: [u8; 6],
    /// 2-byte authentication management field AMF.
    pub amf: [u8; 2],
    /// Expected f1 (MAC-A) output, 8 bytes.
    pub expected_f1: [u8; 8],
    /// Expected f1* (MAC-S) output, 8 bytes.
    pub expected_f1_star: [u8; 8],
    /// Expected f2 (RES) output, 8 bytes.
    pub expected_f2: [u8; 8],
    /// Expected f3 (CK) output, 16 bytes.
    pub expected_f3: [u8; 16],
    /// Expected f4 (IK) output, 16 bytes.
    pub expected_f4: [u8; 16],
    /// Expected f5 (AK) output, 6 bytes.
    pub expected_f5: [u8; 6],
    /// Expected f5* (AK*) output, 6 bytes.
    pub expected_f5_star: [u8; 6],
    /// Source of this test vector.
    pub source: ReferenceSource,
}

/// Returns all TUAK reference test vectors from [3GPP TS 35.233 V19.0.0](../../../docs/specs/3gpp/ts-35.233/ts_135233v190000p.pdf).
#[inline]
pub fn vectors() -> &'static [TuakVector] {
    &VECTORS
}

/// [3GPP TS 35.233 V19.0.0 clause 6.3](../../../docs/specs/3gpp/ts-35.233/ts_135233v190000p.pdf#%5B%7B%22num%22%3A33%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C543%5D) Test Set 1: 128-bit key, standard output sizes
static VECTORS: [TuakVector; 1] = [TuakVector {
    k: [
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
    key_bits: 128,
    top: [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    ],
    use_topc: false, // Use TOP, will derive TOPc
    rand: [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    ],
    sqn: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
    amf: [0xFF, 0xFF],
    expected_f1: [0xF9, 0xA5, 0x4E, 0x6A, 0xEA, 0xA8, 0x61, 0x8D],
    expected_f1_star: [0xE9, 0x4B, 0x4D, 0xC6, 0xC7, 0x29, 0x7D, 0xF3],
    // f2/f3/f4/f5 expected values below are for 3GPP TS 35.233 V19.0.0 INSTANCE=0x40
    // (RES=32). TuakParams uses standard USIM INSTANCE=0x48 (RES=64) which
    // yields different f2345 output. Tests validate f1/f1*/f5* only since
    // those use separate INSTANCE bytes unaffected by RES size.
    expected_f2: [0x65, 0x7A, 0xCD, 0x64, 0x00, 0x00, 0x00, 0x00], // 32-bit RES
    expected_f3: [
        0xD7, 0x1A, 0x1E, 0x5C, 0x6C, 0xAF, 0xFE, 0x98,
        0x6A, 0x26, 0xF7, 0x83, 0xE5, 0xC7, 0x8B, 0xE1,
    ],
    expected_f4: [
        0xBE, 0x84, 0x9F, 0xA2, 0x56, 0x4F, 0x86, 0x9A,
        0xEC, 0xEE, 0x6F, 0x62, 0xD4, 0x33, 0x7E, 0x72,
    ],
    expected_f5: [0x71, 0x9F, 0x1E, 0x9B, 0x90, 0x54],
    expected_f5_star: [0xE7, 0xAF, 0x6B, 0x3D, 0x0E, 0x38],
    source: ReferenceSource::Standards("3GPP TS 35.233"),
}];

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_milenage::SubscriberKey;
    use simrs_secret::Secret;
    use simrs_tuak::{TuakParams, OperatorVariant};

    /// Validate f1 and f1* which use INSTANCE bytes independent of RES size.
    #[test]
    fn all_128bit_vectors_f1() {
        for (i, v) in VECTORS.iter().enumerate() {
            if v.key_bits != 128 {
                continue;
            }
            let mut k16 = [0u8; 16];
            k16.copy_from_slice(&v.k[..16]);
            let top_variant = if v.use_topc {
                OperatorVariant::topc(Secret::new(v.top))
            } else {
                OperatorVariant::top(Secret::new(v.top))
            };
            let p = TuakParams::new(SubscriberKey::new(Secret::new(k16)), top_variant);
            assert_eq!(
                p.compute_auth_mac(&v.rand, &v.sqn, &v.amf), v.expected_f1,
                "Vector {} f1 mismatch", i
            );
            assert_eq!(
                p.compute_resync_mac(&v.rand, &v.sqn, &v.amf), v.expected_f1_star,
                "Vector {} f1* mismatch", i
            );
        }
    }

    /// Validate f5* which uses its own INSTANCE byte independent of RES size.
    #[test]
    fn all_128bit_vectors_f5_star() {
        for (i, v) in VECTORS.iter().enumerate() {
            if v.key_bits != 128 {
                continue;
            }
            let mut k16 = [0u8; 16];
            k16.copy_from_slice(&v.k[..16]);
            let top_variant = if v.use_topc {
                OperatorVariant::topc(Secret::new(v.top))
            } else {
                OperatorVariant::top(Secret::new(v.top))
            };
            let p = TuakParams::new(SubscriberKey::new(Secret::new(k16)), top_variant);
            assert_eq!(
                p.compute_resync_anonymity_key(&v.rand), v.expected_f5_star,
                "Vector {} f5* mismatch", i
            );
        }
    }
}
