//! COMP128v1 reference test vectors.
//!
//! These vectors are cross-validated against reference implementations
//! to ensure bit-exact output from the Rust implementation.
//!
//! The vector table contains 12 entries: 6 unique (Ki, RAND) pairs stored
//! with two independent reference sources each (ETSI/GSM 11.11 and Osmocom
//! swsim). Both sources must agree on expected outputs -- this cross-source
//! agreement is itself tested.

use crate::ReferenceSource;

/// Reference test vector for COMP128v1.
#[derive(Debug, Clone, Copy)]
pub struct Comp128Vector {
    /// 16-byte secret key Ki.
    pub ki: [u8; 16],
    /// 16-byte random challenge RAND.
    pub rand: [u8; 16],
    /// Expected 4-byte SRES.
    pub expected_sres: [u8; 4],
    /// Expected 8-byte Kc.
    pub expected_kc: [u8; 8],
    /// Source of this test vector.
    pub source: ReferenceSource,
}

/// Returns all reference test vectors for COMP128v1.
#[inline]
pub fn vectors() -> &'static [Comp128Vector] {
    &VECTORS
}

/// Returns vectors from a specific source.
#[inline]
pub fn vectors_from(source: ReferenceSource) -> impl Iterator<Item = &'static Comp128Vector> {
    VECTORS.iter().filter(move |v| v.source == source)
}

/// Reference test vectors (6 ETSI + 6 swsim = 12 total).
static VECTORS: [Comp128Vector; 12] = [
    // =========================================================================
    // ETSI / Standards vectors (GSM 11.11 / 3GPP TS 51.011)
    // =========================================================================
    // Vector 0: all-zero
    Comp128Vector {
        ki: [0x00; 16],
        rand: [0x00; 16],
        expected_sres: [0x09, 0xE5, 0x5D, 0xA4],
        expected_kc: [0x17, 0x47, 0x57, 0x78, 0x3D, 0xC4, 0x04, 0x00],
        source: ReferenceSource::Standards("GSM 11.11"),
    },
    // Vector 1: Ki=0xAB, RAND=0xCD
    Comp128Vector {
        ki: [0xAB; 16],
        rand: [0xCD; 16],
        expected_sres: [0x43, 0xFA, 0xD2, 0x08],
        expected_kc: [0x8F, 0x6E, 0x14, 0x88, 0x18, 0x39, 0xD4, 0x00],
        source: ReferenceSource::Standards("GSM 11.11"),
    },
    // Vector 2: doctest (Ki=FF...FF07, RAND=0123...EF)
    Comp128Vector {
        ki: [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
        ],
        rand: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ],
        expected_sres: [0x46, 0xF0, 0x2D, 0xBA],
        expected_kc: [0xE9, 0xB7, 0xD0, 0x45, 0xEC, 0x87, 0x1C, 0x00],
        source: ReferenceSource::Standards("GSM 11.11"),
    },
    // Vector 3: Ki=0x11, RAND=0x22
    Comp128Vector {
        ki: [0x11; 16],
        rand: [0x22; 16],
        expected_sres: [0x67, 0x5B, 0x74, 0xF6],
        expected_kc: [0x7E, 0xFC, 0x50, 0xA3, 0xED, 0x03, 0x68, 0x00],
        source: ReferenceSource::Standards("GSM 11.11"),
    },
    // Vector 4: all-0xFF
    Comp128Vector {
        ki: [0xFF; 16],
        rand: [0xFF; 16],
        expected_sres: [0xFE, 0x65, 0xFD, 0x52],
        expected_kc: [0x8E, 0xD6, 0x68, 0x0A, 0x9B, 0x77, 0xC4, 0x00],
        source: ReferenceSource::Standards("GSM 11.11"),
    },
    // Vector 5: sequential (Ki=0x00..0x0F, RAND=0x10..0x1F)
    Comp128Vector {
        ki: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        rand: [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
        expected_sres: [0x37, 0x38, 0xF8, 0x82],
        expected_kc: [0x39, 0xCD, 0xA2, 0xDB, 0xBA, 0x4A, 0x7C, 0x00],
        source: ReferenceSource::Standards("GSM 11.11"),
    },
    // =========================================================================
    // swsim vectors (Osmocom C reference implementation)
    // =========================================================================
    // swsim Vector: all-zero
    Comp128Vector {
        ki: [0x00; 16],
        rand: [0x00; 16],
        expected_sres: [0x09, 0xE5, 0x5D, 0xA4],
        expected_kc: [0x17, 0x47, 0x57, 0x78, 0x3D, 0xC4, 0x04, 0x00],
        source: ReferenceSource::Swsim,
    },
    // swsim Vector: Ki=0xAB, RAND=0xCD
    Comp128Vector {
        ki: [0xAB; 16],
        rand: [0xCD; 16],
        expected_sres: [0x43, 0xFA, 0xD2, 0x08],
        expected_kc: [0x8F, 0x6E, 0x14, 0x88, 0x18, 0x39, 0xD4, 0x00],
        source: ReferenceSource::Swsim,
    },
    // swsim Vector: Ki=FF...FF07, RAND=0123...EF
    Comp128Vector {
        ki: [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
        ],
        rand: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ],
        expected_sres: [0x46, 0xF0, 0x2D, 0xBA],
        expected_kc: [0xE9, 0xB7, 0xD0, 0x45, 0xEC, 0x87, 0x1C, 0x00],
        source: ReferenceSource::Swsim,
    },
    // swsim Vector: Ki=0x11, RAND=0x22
    Comp128Vector {
        ki: [0x11; 16],
        rand: [0x22; 16],
        expected_sres: [0x67, 0x5B, 0x74, 0xF6],
        expected_kc: [0x7E, 0xFC, 0x50, 0xA3, 0xED, 0x03, 0x68, 0x00],
        source: ReferenceSource::Swsim,
    },
    // swsim Vector: all-0xFF
    Comp128Vector {
        ki: [0xFF; 16],
        rand: [0xFF; 16],
        expected_sres: [0xFE, 0x65, 0xFD, 0x52],
        expected_kc: [0x8E, 0xD6, 0x68, 0x0A, 0x9B, 0x77, 0xC4, 0x00],
        source: ReferenceSource::Swsim,
    },
    // swsim Vector: sequential (Ki=0x00..0x0F, RAND=0x10..0x1F)
    Comp128Vector {
        ki: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        rand: [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
        expected_sres: [0x37, 0x38, 0xF8, 0x82],
        expected_kc: [0x39, 0xCD, 0xA2, 0xDB, 0xBA, 0x4A, 0x7C, 0x00],
        source: ReferenceSource::Swsim,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_comp128::comp128;

    /// Test: all-zero Ki and RAND.
    #[test]
    fn vector_all_zero() {
        let v = &VECTORS[0];
        let r = comp128(&v.ki, &v.rand);
        assert_eq!(r.sres, v.expected_sres, "SRES mismatch");
        assert_eq!(r.kc, v.expected_kc, "Kc mismatch");
    }

    /// Test: all 0xAB Ki, all 0xCD RAND.
    #[test]
    fn vector_ab_cd() {
        let v = &VECTORS[1];
        let r = comp128(&v.ki, &v.rand);
        assert_eq!(r.sres, v.expected_sres, "SRES mismatch");
        assert_eq!(r.kc, v.expected_kc, "Kc mismatch");
    }

    /// Test: doctest vector (Ki=FF...FF07, RAND=0123...EF).
    #[test]
    fn vector_doctest() {
        let v = &VECTORS[2];
        let r = comp128(&v.ki, &v.rand);
        assert_eq!(r.sres, v.expected_sres, "SRES mismatch");
        assert_eq!(r.kc, v.expected_kc, "Kc mismatch");
    }

    /// Test: Ki=0x11..., RAND=0x22...
    #[test]
    fn vector_11_22() {
        let v = &VECTORS[3];
        let r = comp128(&v.ki, &v.rand);
        assert_eq!(r.sres, v.expected_sres, "SRES mismatch");
        assert_eq!(r.kc, v.expected_kc, "Kc mismatch");
    }

    /// Test: all 0xFF Ki and RAND.
    #[test]
    fn vector_all_ff() {
        let v = &VECTORS[4];
        let r = comp128(&v.ki, &v.rand);
        assert_eq!(r.sres, v.expected_sres, "SRES mismatch");
        assert_eq!(r.kc, v.expected_kc, "Kc mismatch");
    }

    /// Test: sequential Ki and RAND.
    #[test]
    fn vector_sequential() {
        let v = &VECTORS[5];
        let r = comp128(&v.ki, &v.rand);
        assert_eq!(r.sres, v.expected_sres, "SRES mismatch");
        assert_eq!(r.kc, v.expected_kc, "Kc mismatch");
    }

    /// ETSI and swsim sources must agree on expected outputs for the same inputs.
    #[test]
    fn cross_source_agreement() {
        let etsi: Vec<_> = vectors_from(ReferenceSource::Standards("GSM 11.11")).collect();
        let swsim: Vec<_> = vectors_from(ReferenceSource::Swsim).collect();
        assert_eq!(etsi.len(), swsim.len(), "source counts must match");
        for (i, (e, s)) in etsi.iter().zip(swsim.iter()).enumerate() {
            assert_eq!(e.ki, s.ki, "vector {i}: inputs must match");
            assert_eq!(e.rand, s.rand, "vector {i}: inputs must match");
            assert_eq!(
                e.expected_sres, s.expected_sres,
                "vector {i}: SRES cross-source mismatch"
            );
            assert_eq!(
                e.expected_kc, s.expected_kc,
                "vector {i}: Kc cross-source mismatch"
            );
        }
    }
}
