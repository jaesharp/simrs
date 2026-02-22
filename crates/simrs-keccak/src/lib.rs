//! Keccak-f[1600] permutation.
//!
//! Pure Rust implementation of the Keccak-f[1600] permutation used as
//! the core primitive of SHA-3 (FIPS 202) and TUAK (3GPP TS 35.231).
//!
//! This crate implements only the raw permutation function, not the
//! sponge construction. TUAK uses Keccak-f[1600] directly.
//!
//! # Standards
//! - NIST FIPS 202 -- SHA-3 Standard
//! - NIST SP 800-185 -- SHA-3 Derived Functions
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

/// Round constants for Keccak-f[1600] (FIPS 202 Section 3.2.5).
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

/// Rotation offsets for each of the 25 lanes (FIPS 202 Section 3.2.2).
///
/// Indexed as `OFFSETS[x + 5*y]` in row-major order.
const RHO_OFFSETS: [u32; 25] = [
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
];

/// Theta step mapping (FIPS 202 Section 3.2.1).
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

/// Rho step mapping (FIPS 202 Section 3.2.2).
///
/// Rotates each lane by a fixed offset.
fn rho(state: &mut [u64; 25]) {
    for i in 0..25 {
        state[i] = state[i].rotate_left(RHO_OFFSETS[i]);
    }
}

/// Pi step mapping (FIPS 202 Section 3.2.3).
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

/// Chi step mapping (FIPS 202 Section 3.2.4).
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

/// Iota step mapping (FIPS 202 Section 3.2.5).
///
/// XORs a round constant into lane (0,0).
const fn iota(state: &mut [u64; 25], round: usize) {
    state[0] ^= RC[round];
}

/// Apply the Keccak-f[1600] permutation to a 1600-bit state.
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

/// Apply Keccak-f[1600] to a 200-byte state buffer.
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

    /// Known-answer test: Keccak-f[1600] applied to the all-zero state.
    ///
    /// Reference: `KeccakCodePackage` / `RustCrypto` keccak crate test vectors.
    /// These 25 lanes are the universally agreed-upon output of a single
    /// Keccak-f[1600] permutation of the zero state.
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
}
