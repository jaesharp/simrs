//! Keccak-f\[1600\] permutation.
//!
//! Pure Rust implementation of the Keccak-f\[1600\] permutation used as
//! the core primitive of SHA-3 ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf)) and TUAK ([3GPP TS 35.231 V19.0.0](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf)).
//!
//! This crate implements only the raw permutation function, not the
//! sponge construction. TUAK uses Keccak-f\[1600\] directly.
//!
//! # Standards
//! - [NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) -- SHA-3 Standard
//! - [NIST SP 800-185](../../../docs/specs/nist/sp-800-185/NIST.SP.800-185.pdf) -- SHA-3 Derived Functions
//!
//! # `no_std`
//! This crate is `no_std`. No heap allocation.
//!
//! # Example
//! ```
//! use simrs_keccak::keccak_f1600;
//! let mut state = [0u64; 25];
//! keccak_f1600(&mut state);
//! assert_ne!(state, [0u64; 25]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

/// Round constants for Keccak-f\[1600\] ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.5).
///
/// 24 constants, one per round, derived from a degree-8 LFSR.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for each of the 25 lanes ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.2).
///
/// Indexed as `OFFSETS[x + 5*y]` in row-major order.
const RHO_OFFSETS: [u32; 25] = [
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
];

/// Theta step mapping ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.1).
///
/// Computes the column parity and XORs an adjustment into every lane.
fn theta(state: &mut [u64; 25]) {
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for x in 0..5 {
        let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            state[x + 5 * y] ^= d;
        }
    }
}

/// Rho step mapping ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.2).
///
/// Rotates each lane by a fixed offset.
fn rho(state: &mut [u64; 25]) {
    for i in 0..25 {
        state[i] = state[i].rotate_left(RHO_OFFSETS[i]);
    }
}

/// Pi step mapping ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.3).
///
/// Rearranges lanes: `A'[y, 2x+3y] = A[x, y]`.
fn pi(state: &mut [u64; 25]) {
    let tmp = *state;
    for x in 0..5 {
        for y in 0..5 {
            state[y + 5 * ((2 * x + 3 * y) % 5)] = tmp[x + 5 * y];
        }
    }
}

/// Chi step mapping ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.4).
///
/// Non-linear step: `A'[x] = A[x] XOR ((NOT A[x+1]) AND A[x+2])`.
fn chi(state: &mut [u64; 25]) {
    for y in 0..5 {
        let base = 5 * y;
        let t = [
            state[base],
            state[base + 1],
            state[base + 2],
            state[base + 3],
            state[base + 4],
        ];
        for x in 0..5 {
            state[base + x] = t[x] ^ (!t[(x + 1) % 5] & t[(x + 2) % 5]);
        }
    }
}

/// Iota step mapping ([NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.5).
///
/// XORs a round constant into lane (0,0).
const fn iota(state: &mut [u64; 25], round: usize) {
    state[0] ^= RC[round];
}

/// Apply the Keccak-f\[1600\] permutation to a 1600-bit state.
///
/// The state is represented as 25 64-bit lanes (5x5 array, row-major).
/// The permutation consists of 24 rounds, each applying five step mappings:
/// theta, rho, pi, chi, and iota.
///
/// # Example
///
/// ```
/// use simrs_keccak::keccak_f1600;
/// let mut state = [0u64; 25];
/// keccak_f1600(&mut state);
/// assert_ne!(state, [0u64; 25]);
/// ```
pub fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..24 {
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, round);
    }
}

/// Apply Keccak-f\[1600\] to a 200-byte state buffer.
///
/// Converts between little-endian byte representation and the internal
/// lane representation, applies the permutation, and writes back.
///
/// # Example
///
/// ```
/// use simrs_keccak::{keccak_f1600, keccak_f1600_bytes};
///
/// // Byte interface and lane interface must produce the same result.
/// let mut bytes = [0u8; 200];
/// keccak_f1600_bytes(&mut bytes);
///
/// let mut lanes = [0u64; 25];
/// keccak_f1600(&mut lanes);
///
/// for i in 0..25 {
///     assert_eq!(lanes[i].to_le_bytes(), bytes[8*i..8*i+8]);
/// }
/// ```
pub fn keccak_f1600_bytes(state: &mut [u8; 200]) {
    let mut lanes = [0u64; 25];
    for (lane, chunk) in lanes.iter_mut().zip(state.chunks_exact(8)) {
        *lane = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3],
            chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }
    keccak_f1600(&mut lanes);
    for (lane, chunk) in lanes.iter().zip(state.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test: Keccak-f\[1600\] applied to the all-zero state.
    ///
    /// Reference: `KeccakCodePackage` / `RustCrypto` keccak crate test vectors.
    /// These 25 lanes are the universally agreed-upon output of a single
    /// Keccak-f\[1600\] permutation of the zero state.
    #[test]
    fn keccak_f1600_zero_state() {
        let expected: [u64; 25] = [
            0xF125_8F79_40E1_DDE7,
            0x84D5_CCF9_33C0_478A,
            0xD598_261E_A65A_A9EE,
            0xBD15_4730_6F80_494D,
            0x8B28_4E05_6253_D057,
            0xFF97_A42D_7F8E_6FD4,
            0x90FE_E5A0_A446_47C4,
            0x8C5B_DA0C_D619_2E76,
            0xAD30_A6F7_1B19_059C,
            0x3093_5AB7_D08F_FC64,
            0xEB5A_A93F_2317_D635,
            0xA9A6_E626_0D71_2103,
            0x81A5_7C16_DBCF_555F,
            0x43B8_31CD_0347_C826,
            0x01F2_2F1A_11A5_569F,
            0x05E5_635A_21D9_AE61,
            0x64BE_FEF2_8CC9_70F2,
            0x6136_7095_7BC4_6611,
            0xB87C_5A55_4FD0_0ECB,
            0x8C3E_E88A_1CCF_32C8,
            0x940C_7922_AE3A_2614,
            0x1841_F924_A2C5_09E4,
            0x16F5_3526_E704_65C2,
            0x75F6_44E9_7F30_A13B,
            0xEAF1_FF7B_5CEC_A249,
        ];

        let mut state = [0u64; 25];
        keccak_f1600(&mut state);

        for (i, (&got, &want)) in state.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "lane {i}: got {got:#018X}, want {want:#018X}");
        }
    }

    /// Byte-level and lane-level interfaces must produce identical results.
    ///
    /// Starting from all-zero input, both paths should yield the same
    /// 200-byte output when compared lane-by-lane.
    #[test]
    fn keccak_f1600_bytes_roundtrip() {
        let mut bytes = [0u8; 200];
        keccak_f1600_bytes(&mut bytes);

        let mut lanes = [0u64; 25];
        keccak_f1600(&mut lanes);

        for (i, (lane, chunk)) in lanes.iter().zip(bytes.chunks_exact(8)).enumerate() {
            assert_eq!(
                chunk,
                &lane.to_le_bytes(),
                "lane {i} mismatch between byte and lane interfaces"
            );
        }
    }

    /// Applying the permutation twice yields a different state than
    /// applying it once. This catches trivial no-op or self-inverse bugs.
    #[test]
    fn keccak_f1600_not_identity() {
        let mut once = [0u64; 25];
        keccak_f1600(&mut once);

        let mut twice = [0u64; 25];
        keccak_f1600(&mut twice);
        keccak_f1600(&mut twice);

        assert_ne!(once, twice, "two applications must differ from one");
    }

    /// Determinism: the same input must always produce the same output.
    #[test]
    fn keccak_f1600_deterministic() {
        let mut a = [0x42u64; 25];
        let mut b = [0x42u64; 25];

        keccak_f1600(&mut a);
        keccak_f1600(&mut b);

        assert_eq!(a, b, "identical inputs must produce identical outputs");
    }

    /// Known-answer test: Keccak-f\[1600\] with lane[0] = 0x01 (rest zero).
    ///
    /// A single-bit input state exercises all steps (theta parity is non-trivial,
    /// rho rotates non-zero lanes, pi rearranges them, chi applies non-linear mixing).
    ///
    /// Reference: independently verified via Python and standalone Rust implementations
    /// cross-checked against the zero-state KAT from `KeccakCodePackage`.
    #[test]
    fn keccak_f1600_single_bit_input() {
        let expected: [u64; 25] = [
            0xE2A9_4439_6F0B_13C6,
            0x70FE_C06C_EB0B_06C4,
            0x721D_FC50_18F2_7A42,
            0x64A2_AF57_149F_7096,
            0xD3BC_0B3F_2712_E2E6,
            0x25B8_444D_0AEA_8B74,
            0x9396_EF81_30F1_BE5C,
            0x87A9_8F12_B6AD_542C,
            0x7270_7804_1F4F_63F7,
            0x92CB_EC31_74D6_F74A,
            0x23FB_ED32_ED72_0767,
            0xAC23_29D6_93B1_0D76,
            0x493D_4A7A_941B_2026,
            0x7000_69B7_97E2_F86C,
            0x95D8_E3AE_E6FC_4B8C,
            0x0BCA_1B8D_9D0D_82FC,
            0xE2AD_3392_6D47_4C63,
            0x6A54_15A4_EBED_8DFE,
            0xED6A_86E4_FECB_AC62,
            0xD86E_73C1_B945_A137,
            0x3332_56C2_5284_0104,
            0x9F11_1FAA_6A08_D2E5,
            0x6D1F_6A87_4F91_6FEB,
            0xF716_AE69_D3A5_7F06,
            0xF5A8_4375_5D53_74AF,
        ];

        let mut state = [0u64; 25];
        state[0] = 0x01;
        keccak_f1600(&mut state);

        for (i, (&got, &want)) in state.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "lane {i}: got {got:#018X}, want {want:#018X}");
        }
    }

    /// Known-answer test: Keccak-f\[1600\] with all-ones input (every lane = `0xFFFF_FFFF_FFFF_FFFF`).
    ///
    /// This input exercises the full dynamic range of all step mappings.
    /// Theta with all-ones parity produces a specific XOR pattern, rho
    /// rotates max-value lanes, and chi with max values has distinctive
    /// non-linear behavior.
    ///
    /// Reference: independently verified via Python and standalone Rust implementations
    /// cross-checked against the zero-state KAT from `KeccakCodePackage`.
    #[test]
    fn keccak_f1600_all_ones_input() {
        let expected: [u64; 25] = [
            0x9F00_F21B_BA68_17C4,
            0xCDF5_AA0D_21AF_5E78,
            0xD653_9ABF_2409_5B97,
            0x8BB6_F30A_010F_8228,
            0xF0F7_11BA_0547_331D,
            0x4F44_3305_58EB_182F,
            0x2213_B79D_9055_207C,
            0xEB5E_5B55_CA4F_B490,
            0x0BFA_EB81_A299_B5D4,
            0x9E5D_924F_1A65_ED48,
            0x0046_50C5_33B7_BFB3,
            0xDDAD_454B_84D7_AB05,
            0xF03C_E565_03E8_2921,
            0xCE44_2E92_C672_8660,
            0x1A9C_E5E4_B37D_DCD3,
            0xF63B_60E2_7CEA_6F0E,
            0xCC4C_C7FC_A665_BFAD,
            0x40CF_4EBA_54A2_285D,
            0x2725_F1F1_4230_4213,
            0x554D_327D_E6FB_AD9B,
            0x1986_6A26_CBC8_BDC2,
            0xE8C3_C28F_AF02_C7F5,
            0xC6BC_1F35_12A6_65AE,
            0xCAA8_31F1_A5DC_86CE,
            0x3F82_AFE9_1CA4_B9B0,
        ];

        let mut state = [0xFFFF_FFFF_FFFF_FFFFu64; 25];
        keccak_f1600(&mut state);

        for (i, (&got, &want)) in state.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "lane {i}: got {got:#018X}, want {want:#018X}");
        }
    }

    /// Verify that the iota step correctly applies round constants by testing
    /// that lane\[0\] = RC\[0\] (= 1) as initial state produces a different
    /// result than the all-zero state. This exercises the round constant table
    /// matching [NIST FIPS 202](../../../docs/specs/nist/fips-202/NIST.FIPS.202.pdf) Section 3.2.5.
    #[test]
    fn keccak_f1600_round_constant_lane0_propagation() {
        let mut state_rc0 = [0u64; 25];
        state_rc0[0] = 0x0000_0000_0000_0001; // RC[0]

        keccak_f1600(&mut state_rc0);

        let mut state_zero = [0u64; 25];
        keccak_f1600(&mut state_zero);

        assert_ne!(state_rc0, state_zero,
            "state with lane[0]=RC[0] must produce different output than all-zero state");

        assert_ne!(state_rc0, [0u64; 25], "result must not be all-zeros");
        let nonzero = state_rc0.iter().filter(|&&x| x != 0).count();
        assert!(nonzero >= 20,
            "expected good diffusion: at least 20/25 non-zero lanes, got {nonzero}");
    }

    /// Verify that the permutation is NOT the identity for multiple distinct
    /// non-trivial input patterns. Also verifies that different inputs produce
    /// different outputs (injectivity for a proper permutation).
    #[test]
    fn keccak_f1600_not_identity_for_diverse_inputs() {
        // Pattern 1: incrementing lanes (0, 1, 2, ..., 24).
        let mut state1: [u64; 25] = core::array::from_fn(|i| i as u64);
        let input1 = state1;
        keccak_f1600(&mut state1);
        assert_ne!(state1, input1,
            "incrementing lanes: permutation must not be identity");

        // Pattern 2: alternating bits (0xAAAA..., 0x5555..., ...).
        let mut state2: [u64; 25] = core::array::from_fn(|i| {
            if i % 2 == 0 { 0xAAAA_AAAA_AAAA_AAAA } else { 0x5555_5555_5555_5555 }
        });
        let input2 = state2;
        keccak_f1600(&mut state2);
        assert_ne!(state2, input2,
            "alternating bits: permutation must not be identity");

        // Pattern 3: single high bit in each lane.
        let mut state3: [u64; 25] = core::array::from_fn(|i| 1u64 << (i % 64));
        let input3 = state3;
        keccak_f1600(&mut state3);
        assert_ne!(state3, input3,
            "single high bits: permutation must not be identity");

        // Pattern 4: large prime-derived values (non-trivial, irrational-like).
        let mut state4: [u64; 25] = core::array::from_fn(|i| {
            let v = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0x6A09_E667_F3BC_C908);
            v ^ v.rotate_right(17)
        });
        let input4 = state4;
        keccak_f1600(&mut state4);
        assert_ne!(state4, input4,
            "prime-derived pattern: permutation must not be identity");

        // All four outputs must be mutually distinct.
        assert_ne!(state1, state2, "pattern 1 and 2 outputs must differ");
        assert_ne!(state1, state3, "pattern 1 and 3 outputs must differ");
        assert_ne!(state1, state4, "pattern 1 and 4 outputs must differ");
        assert_ne!(state2, state3, "pattern 2 and 3 outputs must differ");
        assert_ne!(state2, state4, "pattern 2 and 4 outputs must differ");
        assert_ne!(state3, state4, "pattern 3 and 4 outputs must differ");
    }

    /// Verify the byte interface produces correct results for a non-zero input.
    ///
    /// Sets the first byte of the 200-byte state to 0x01 (lane\[0\] = 0x01 in LE),
    /// applies the permutation through both interfaces, and verifies they match.
    #[test]
    fn keccak_f1600_bytes_nonzero_input() {
        let mut bytes = [0u8; 200];
        bytes[0] = 0x01; // lane[0] = 0x01 in LE
        keccak_f1600_bytes(&mut bytes);

        let mut lanes = [0u64; 25];
        lanes[0] = 0x01;
        keccak_f1600(&mut lanes);

        for (i, (lane, chunk)) in lanes.iter().zip(bytes.chunks_exact(8)).enumerate() {
            assert_eq!(
                chunk,
                &lane.to_le_bytes(),
                "lane {i}: byte and lane interfaces must agree for non-zero input"
            );
        }

        // Output must not be all-zeros (non-trivial computation).
        assert_ne!(bytes, [0u8; 200],
            "non-zero input must produce non-zero output via byte interface");
    }
}
