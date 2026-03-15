//! AES-128 (Rijndael) block cipher -- encryption and decryption.
//!
//! Self-contained implementation with no heap allocation. Used as the
//! underlying primitive for Milenage UMTS authentication and OTA secured
//! packet decoding.
//!
//! # Constant-time implementation
//!
//! All operations on secret data (S-box substitution, GF(2^8) multiplication)
//! use constant-time primitives from `simrs-consttime` to prevent
//! cache-timing side-channel attacks:
//! - S-box / inverse S-box lookups use [`ct_select`], which reads all 256
//!   table entries and masks the result, making the memory access pattern
//!   independent of the secret index byte.
//! - `xtime` (multiplication by {02} in GF(2^8)) uses [`ct_xtime`], a
//!   branchless arithmetic computation with no table lookup.
//!
//! # Standards
//! - [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) -- Advanced Encryption Standard (AES)
//! - [ETSI TS 135 206 V19.0.0 Annex 3](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#page=19) -- Rijndael as used in Milenage
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All state lives in a fixed-size [`Rijndael`] struct.
//!
//! # Example
//! ```
//! use simrs_rijndael::Rijndael;
//! use simrs_secret::Secret;
//!
//! // NIST FIPS 197 Appendix B test vector
//! let key = Secret::new([
//!     0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
//!     0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
//! ]);
//! let input = [
//!     0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
//!     0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
//! ];
//! let expected = [
//!     0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
//!     0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32,
//! ];
//!
//! let rij = Rijndael::new(&key);
//! assert_eq!(rij.encrypt(&input), expected);
//! assert_eq!(rij.decrypt(&expected), input);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::{ct_select, ct_xtime};
use simrs_secret::Secret;

/// AES S-box substitution table.
/// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.1.1, Figure 7.
const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

/// AES inverse S-box substitution table.
/// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.3.2, Figure 14.
/// Computed as the functional inverse of SBOX: for all i, `INV_SBOX[SBOX[i]] = i`.
#[allow(clippy::cast_possible_truncation)]
const INV_SBOX: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0u16;
    while i < 256 {
        table[SBOX[i as usize] as usize] = i as u8;
        i += 1;
    }
    table
};

/// AES-128 (Rijndael) block cipher state.
///
/// Holds the 11 expanded round keys derived from a 16-byte key.
/// Supports both encryption and decryption.
///
/// # Standards
/// - [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5 -- Algorithm specification
/// - [ETSI TS 135 206 V19.0.0 Annex 3](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#page=19) -- Rijndael for Milenage
///
/// # Size
/// 176 bytes (11 round keys x 16 bytes each).
#[derive(Clone)]
pub struct Rijndael {
    /// Round keys in column-major layout: `round_keys[round][row][col]`.
    round_keys: Secret<[[[u8; 4]; 4]; 11]>,
}

impl Rijndael {
    /// Create a new Rijndael cipher from a 128-bit key.
    ///
    /// Performs the AES-128 key expansion ([NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.2).
    ///
    /// # Example
    /// ```
    /// use simrs_rijndael::Rijndael;
    /// use simrs_secret::Secret;
    /// let rij = Rijndael::new(&Secret::new([0u8; 16]));
    /// ```
    pub const fn new(key: &Secret<[u8; 16]>) -> Self {
        let key = key.declassify_ref();
        let mut rk = [[[0u8; 4]; 4]; 11];

        // Round 0: key bytes arranged in column-major order.
        // key[i] -> rk[0][i & 3][i >> 2]
        let mut i = 0;
        while i < 16 {
            rk[0][i & 3][i >> 2] = key[i];
            i += 1;
        }

        let mut round_const: u8 = 1;
        let mut round = 1u8;
        while round < 11 {
            let r = round as usize;
            let p = r - 1;

            // First column: RotWord + SubWord + Rcon
            rk[r][0][0] = ct_select(&SBOX, rk[p][1][3]) ^ rk[p][0][0] ^ round_const;
            rk[r][1][0] = ct_select(&SBOX, rk[p][2][3]) ^ rk[p][1][0];
            rk[r][2][0] = ct_select(&SBOX, rk[p][3][3]) ^ rk[p][2][0];
            rk[r][3][0] = ct_select(&SBOX, rk[p][0][3]) ^ rk[p][3][0];

            // Remaining columns: XOR with previous
            let mut j = 0;
            while j < 4 {
                rk[r][j][1] = rk[p][j][1] ^ rk[r][j][0];
                rk[r][j][2] = rk[p][j][2] ^ rk[r][j][1];
                rk[r][j][3] = rk[p][j][3] ^ rk[r][j][2];
                j += 1;
            }

            round_const = ct_xtime(round_const);
            round += 1;
        }

        Self {
            round_keys: Secret::new(rk),
        }
    }

    /// Encrypt a single 128-bit block.
    ///
    /// Performs 10 rounds of `ByteSub` + `ShiftRow` + `MixColumn` + `KeyAdd`
    /// (last round omits `MixColumn`) per [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.1.
    ///
    /// # Example
    /// ```
    /// use simrs_rijndael::Rijndael;
    /// use simrs_secret::Secret;
    /// let rij = Rijndael::new(&Secret::new([0u8; 16]));
    /// let ct = rij.encrypt(&[0u8; 16]);
    /// // Deterministic: same key + input always yields same output
    /// assert_eq!(ct, rij.encrypt(&[0u8; 16]));
    /// ```
    pub const fn encrypt(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = [[0u8; 4]; 4];

        // Load input into state array (column-major).
        let mut i = 0;
        while i < 16 {
            state[i & 3][i >> 2] = input[i];
            i += 1;
        }

        let rk = self.round_keys.declassify_ref();

        // Initial round key addition.
        Self::key_add(&mut state, &rk[0]);

        // Rounds 1..=9: ByteSub + ShiftRow + MixColumn + KeyAdd
        let mut round = 1;
        while round <= 9 {
            Self::byte_sub(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::key_add(&mut state, &rk[round]);
            round += 1;
        }

        // Round 10: ByteSub + ShiftRow + KeyAdd (no MixColumn)
        Self::byte_sub(&mut state);
        Self::shift_rows(&mut state);
        Self::key_add(&mut state, &rk[10]);

        // Extract output from state array.
        let mut output = [0u8; 16];
        i = 0;
        while i < 16 {
            output[i] = state[i & 3][i >> 2];
            i += 1;
        }
        output
    }

    /// Decrypt a single 128-bit block.
    ///
    /// Performs the AES-128 inverse cipher ([NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.3):
    /// `AddRoundKey(10)`, then for rounds 9..=1: `InvShiftRows` +
    /// `InvSubBytes` + `AddRoundKey` + `InvMixColumns`, then final
    /// `InvShiftRows` + `InvSubBytes` + `AddRoundKey(0)`.
    ///
    /// # Example
    /// ```
    /// use simrs_rijndael::Rijndael;
    /// use simrs_secret::Secret;
    /// let rij = Rijndael::new(&Secret::new([0u8; 16]));
    /// let pt = [0x42u8; 16];
    /// assert_eq!(rij.decrypt(&rij.encrypt(&pt)), pt);
    /// ```
    pub const fn decrypt(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = [[0u8; 4]; 4];

        // Load input into state array (column-major).
        let mut i = 0;
        while i < 16 {
            state[i & 3][i >> 2] = input[i];
            i += 1;
        }

        let rk = self.round_keys.declassify_ref();

        // Initial round key addition with round 10 key.
        Self::key_add(&mut state, &rk[10]);

        // Rounds 9..=1: InvShiftRows + InvSubBytes + AddRoundKey + InvMixColumns
        let mut round = 9;
        while round >= 1 {
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);
            Self::key_add(&mut state, &rk[round]);
            Self::inv_mix_columns(&mut state);
            round -= 1;
        }

        // Final round: InvShiftRows + InvSubBytes + AddRoundKey(0)
        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        Self::key_add(&mut state, &rk[0]);

        // Extract output from state array.
        let mut output = [0u8; 16];
        i = 0;
        while i < 16 {
            output[i] = state[i & 3][i >> 2];
            i += 1;
        }
        output
    }

    /// `AddRoundKey`: XOR state with round key.
    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.1.4.
    #[inline]
    const fn key_add(state: &mut [[u8; 4]; 4], round_key: &[[u8; 4]; 4]) {
        let mut i = 0;
        while i < 4 {
            let mut j = 0;
            while j < 4 {
                state[i][j] ^= round_key[i][j];
                j += 1;
            }
            i += 1;
        }
    }

    /// `SubBytes`: apply S-box to every byte of state (constant-time).
    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.1.1.
    #[inline]
    const fn byte_sub(state: &mut [[u8; 4]; 4]) {
        let mut i = 0;
        while i < 4 {
            let mut j = 0;
            while j < 4 {
                state[i][j] = ct_select(&SBOX, state[i][j]);
                j += 1;
            }
            i += 1;
        }
    }

    /// `ShiftRows`: cyclically left-shift rows by 0, 1, 2, 3 positions.
    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.1.2.
    #[inline]
    const fn shift_rows(state: &mut [[u8; 4]; 4]) {
        // Row 0: no shift
        // Row 1: left rotate by 1
        let t = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = t;

        // Row 2: left rotate by 2 (swap pairs)
        let t0 = state[2][0];
        let t1 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = t0;
        state[2][3] = t1;

        // Row 3: left rotate by 3 (= right rotate by 1)
        let t = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = t;
    }

    /// `MixColumns`: multiply each column by the MDS matrix in GF(2^8).
    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.1.3.
    #[inline]
    const fn mix_columns(state: &mut [[u8; 4]; 4]) {
        let mut col = 0;
        while col < 4 {
            let s0 = state[0][col];
            let s1 = state[1][col];
            let s2 = state[2][col];
            let s3 = state[3][col];
            let t = s0 ^ s1 ^ s2 ^ s3;

            state[0][col] ^= t ^ ct_xtime(s0 ^ s1);
            state[1][col] ^= t ^ ct_xtime(s1 ^ s2);
            state[2][col] ^= t ^ ct_xtime(s2 ^ s3);
            state[3][col] ^= t ^ ct_xtime(s3 ^ s0);

            col += 1;
        }
    }

    /// `InvSubBytes`: apply inverse S-box to every byte of state (constant-time).
    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.3.2.
    #[inline]
    const fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
        let mut i = 0;
        while i < 4 {
            let mut j = 0;
            while j < 4 {
                state[i][j] = ct_select(&INV_SBOX, state[i][j]);
                j += 1;
            }
            i += 1;
        }
    }

    /// `InvShiftRows`: cyclically right-shift rows by 0, 1, 2, 3 positions.
    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.3.1.
    #[inline]
    const fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
        // Row 0: no shift
        // Row 1: right rotate by 1
        let t = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = t;

        // Row 2: right rotate by 2 (swap pairs)
        let t0 = state[2][0];
        let t1 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = t0;
        state[2][3] = t1;

        // Row 3: right rotate by 3 (= left rotate by 1)
        let t = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = t;
    }

    /// Multiply by {09} in GF(2^8) (constant-time).
    /// 9 = 8 + 1, so `mul_by_9(b) = xtime(xtime(xtime(b))) ^ b`.
    #[inline]
    const fn mul_by_9(b: u8) -> u8 {
        let x2 = ct_xtime(b);
        let x4 = ct_xtime(x2);
        let x8 = ct_xtime(x4);
        x8 ^ b
    }

    /// Multiply by {0B} in GF(2^8) (constant-time).
    /// 11 = 8 + 2 + 1, so `mul_by_11(b) = xtime(xtime(xtime(b))) ^ xtime(b) ^ b`.
    #[inline]
    const fn mul_by_11(b: u8) -> u8 {
        let x2 = ct_xtime(b);
        let x4 = ct_xtime(x2);
        let x8 = ct_xtime(x4);
        x8 ^ x2 ^ b
    }

    /// Multiply by {0D} in GF(2^8) (constant-time).
    /// 13 = 8 + 4 + 1, so `mul_by_13(b) = xtime(xtime(xtime(b))) ^ xtime(xtime(b)) ^ b`.
    #[inline]
    const fn mul_by_13(b: u8) -> u8 {
        let x2 = ct_xtime(b);
        let x4 = ct_xtime(x2);
        let x8 = ct_xtime(x4);
        x8 ^ x4 ^ b
    }

    /// Multiply by {0E} in GF(2^8) (constant-time).
    /// 14 = 8 + 4 + 2, so `mul_by_14(b) = xtime(xtime(xtime(b))) ^ xtime(xtime(b)) ^ xtime(b)`.
    #[inline]
    const fn mul_by_14(b: u8) -> u8 {
        let x2 = ct_xtime(b);
        let x4 = ct_xtime(x2);
        let x8 = ct_xtime(x4);
        x8 ^ x4 ^ x2
    }

    /// `InvMixColumns`: multiply each column by the inverse MDS matrix in GF(2^8).
    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 5.3.3.
    ///
    /// The inverse MDS matrix is:
    /// ```text
    /// [0E 0B 0D 09]
    /// [09 0E 0B 0D]
    /// [0D 09 0E 0B]
    /// [0B 0D 09 0E]
    /// ```
    #[inline]
    const fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
        let mut col = 0;
        while col < 4 {
            let s0 = state[0][col];
            let s1 = state[1][col];
            let s2 = state[2][col];
            let s3 = state[3][col];

            state[0][col] = Self::mul_by_14(s0)
                ^ Self::mul_by_11(s1)
                ^ Self::mul_by_13(s2)
                ^ Self::mul_by_9(s3);
            state[1][col] = Self::mul_by_9(s0)
                ^ Self::mul_by_14(s1)
                ^ Self::mul_by_11(s2)
                ^ Self::mul_by_13(s3);
            state[2][col] = Self::mul_by_13(s0)
                ^ Self::mul_by_9(s1)
                ^ Self::mul_by_14(s2)
                ^ Self::mul_by_11(s3);
            state[3][col] = Self::mul_by_11(s0)
                ^ Self::mul_by_13(s1)
                ^ Self::mul_by_9(s2)
                ^ Self::mul_by_14(s3);

            col += 1;
        }
    }
}

impl core::fmt::Debug for Rijndael {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rijndael")
            .field("round_keys", &"[...; 11 x 4 x 4]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) Appendix B: AES-128 test vector.
    /// This is the single canonical test vector from the AES standard itself.
    #[test]
    fn fips197_appendix_b() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let input = [
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ];
        let expected = [
            0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A,
            0x0B, 0x32,
        ];

        let rij = Rijndael::new(&Secret::new(key));
        assert_eq!(rij.encrypt(&input), expected);
    }

    /// [NIST SP 800-38A](../../../docs/specs/nist/sp-800-38a/NIST.SP.800-38A.pdf) Section F.1.1: AES-128 ECB test vector.
    /// Verifies a different key/plaintext/ciphertext triple.
    #[test]
    fn nist_sp800_38a_ecb_block1() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let plaintext = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        let expected = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
            0xEF, 0x97,
        ];

        let rij = Rijndael::new(&Secret::new(key));
        assert_eq!(rij.encrypt(&plaintext), expected);
    }

    /// Zero key, zero plaintext. Not from a standard -- regression test to
    /// verify we don't accidentally produce all-zero output (which would
    /// indicate a broken implementation).
    #[test]
    fn zero_key_zero_input_not_zero() {
        let rij = Rijndael::new(&Secret::new([0u8; 16]));
        let ct = rij.encrypt(&[0u8; 16]);
        assert_ne!(ct, [0u8; 16], "zero input must not produce zero output");
        // Known value for AES-128(0...0, 0...0):
        let expected = [
            0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34,
            0x2B, 0x2E,
        ];
        assert_eq!(ct, expected);
    }

    /// Determinism: same key + input always produces same output.
    #[test]
    fn deterministic() {
        let key = [0x01; 16];
        let input = [0x02; 16];
        let rij = Rijndael::new(&Secret::new(key));
        assert_eq!(rij.encrypt(&input), rij.encrypt(&input));
    }

    /// Different keys produce different ciphertexts for the same plaintext.
    #[test]
    fn different_keys_different_output() {
        let input = [0xAA; 16];
        let r1 = Rijndael::new(&Secret::new([0x00; 16]));
        let r2 = Rijndael::new(&Secret::new([0x01; 16]));
        assert_ne!(r1.encrypt(&input), r2.encrypt(&input));
    }

    /// Different plaintexts produce different ciphertexts for the same key.
    #[test]
    fn different_inputs_different_output() {
        let rij = Rijndael::new(&Secret::new([0x00; 16]));
        assert_ne!(rij.encrypt(&[0x00; 16]), rij.encrypt(&[0x01; 16]));
    }

    /// Verify const construction works at compile time.
    #[test]
    fn const_construction() {
        const RIJ: Rijndael = Rijndael::new(&Secret::new([0u8; 16]));
        let ct = RIJ.encrypt(&[0u8; 16]);
        assert_ne!(ct, [0u8; 16]);
    }

    /// Verify `ct_xtime` matches the GF(2^8) xtime formula for all 256 inputs.
    /// xtime(b) = (b << 1) XOR 0x1B if high bit set, per [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 4.2.1.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn ct_xtime_all_values() {
        for i in 0u16..256 {
            let b = i as u8;
            let expected = (b << 1) ^ (if b & 0x80 != 0 { 0x1B } else { 0 });
            assert_eq!(ct_xtime(b), expected, "ct_xtime({b:#04X}) mismatch");
        }
    }

    /// Verify `ct_select` returns the correct table element for all indices.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn ct_select_correctness() {
        // Verify against SBOX for all 256 indices
        for i in 0u16..256 {
            let b = i as u8;
            assert_eq!(
                ct_select(&SBOX, b),
                SBOX[b as usize],
                "ct_select(SBOX, {b:#04X}) mismatch"
            );
        }
        // Verify against INV_SBOX for all 256 indices
        for i in 0u16..256 {
            let b = i as u8;
            assert_eq!(
                ct_select(&INV_SBOX, b),
                INV_SBOX[b as usize],
                "ct_select(INV_SBOX, {b:#04X}) mismatch"
            );
        }
    }

    /// Verify `INV_SBOX` is the functional inverse of SBOX.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn inv_sbox_is_inverse_of_sbox() {
        for i in 0u16..256 {
            let b = i as u8;
            assert_eq!(
                INV_SBOX[SBOX[b as usize] as usize], b,
                "INV_SBOX[SBOX[{b:#04X}]] != {b:#04X}"
            );
            assert_eq!(
                SBOX[INV_SBOX[b as usize] as usize], b,
                "SBOX[INV_SBOX[{b:#04X}]] != {b:#04X}"
            );
        }
    }

    /// [NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) Appendix B decryption: decrypt the known ciphertext
    /// and verify it matches the original plaintext.
    #[test]
    fn fips197_appendix_b_decrypt() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let plaintext = [
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ];
        let ciphertext = [
            0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A,
            0x0B, 0x32,
        ];

        let rij = Rijndael::new(&Secret::new(key));
        assert_eq!(rij.decrypt(&ciphertext), plaintext);
    }

    /// [NIST SP 800-38A](../../../docs/specs/nist/sp-800-38a/NIST.SP.800-38A.pdf) Section F.1.2: AES-128 ECB decryption test vector.
    /// Uses the same key/plaintext/ciphertext as the encryption test.
    #[test]
    fn nist_sp800_38a_ecb_block1_decrypt() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let plaintext = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        let ciphertext = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
            0xEF, 0x97,
        ];

        let rij = Rijndael::new(&Secret::new(key));
        assert_eq!(rij.decrypt(&ciphertext), plaintext);
    }

    /// Round-trip: encrypt then decrypt recovers original plaintext.
    /// Uses three non-trivial key/plaintext pairs with no identity or zero elements.
    #[test]
    fn round_trip_encrypt_decrypt() {
        // Pair 1: NIST FIPS 197 Appendix B key with arbitrary plaintext
        let key1 = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let pt1 = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let r1 = Rijndael::new(&Secret::new(key1));
        assert_eq!(r1.decrypt(&r1.encrypt(&pt1)), pt1);

        // Pair 2: different key and plaintext with irrational-like byte patterns
        let key2 = [
            0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84, 0x62, 0x64, 0x33, 0x83,
            0x27, 0x95,
        ];
        let pt2 = [
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71,
            0x35, 0x26,
        ];
        let r2 = Rijndael::new(&Secret::new(key2));
        assert_eq!(r2.decrypt(&r2.encrypt(&pt2)), pt2);

        // Pair 3: all-high-bit pattern
        let key3 = [
            0xA5, 0x5A, 0xC3, 0x3C, 0x96, 0x69, 0xF0, 0x0F, 0x71, 0x8E, 0xD4, 0x2B, 0xE3, 0x1C,
            0xB7, 0x48,
        ];
        let pt3 = [
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        let r3 = Rijndael::new(&Secret::new(key3));
        assert_eq!(r3.decrypt(&r3.encrypt(&pt3)), pt3);
    }

    /// Anti-theater: decrypt(ciphertext) must not equal ciphertext for
    /// non-trivial inputs. This guards against an identity/no-op implementation.
    #[test]
    fn decrypt_is_not_identity() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let ciphertext = [
            0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A,
            0x0B, 0x32,
        ];

        let rij = Rijndael::new(&Secret::new(key));
        let decrypted = rij.decrypt(&ciphertext);
        assert_ne!(
            decrypted, ciphertext,
            "decrypt must not be the identity function"
        );
    }

    /// Zero key decryption: AES-128(key=0, ct) round-trip.
    /// Verifies decrypt inverts encrypt even for the zero key.
    #[test]
    fn zero_key_round_trip() {
        let rij = Rijndael::new(&Secret::new([0u8; 16]));
        let ct = [
            0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34,
            0x2B, 0x2E,
        ];
        // This is AES-128(0...0, 0...0) from the zero_key_zero_input_not_zero test.
        assert_eq!(rij.decrypt(&ct), [0u8; 16]);
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Encrypt/decrypt roundtrip: decrypt(encrypt(pt, key), key) == pt.
        #[test]
        fn encrypt_decrypt_roundtrip(key in any::<[u8; 16]>(), pt in any::<[u8; 16]>()) {
            let cipher = Rijndael::new(&Secret::new(key));
            let ct = cipher.encrypt(&pt);
            let recovered = cipher.decrypt(&ct);
            prop_assert_eq!(recovered, pt);
        }
    }

    proptest! {
        // Different keys must produce different ciphertext.
        #[test]
        fn different_keys_different_ciphertext(
            k1 in any::<[u8; 16]>(),
            k2 in any::<[u8; 16]>(),
            pt in any::<[u8; 16]>(),
        ) {
            prop_assume!(k1 != k2);
            let c1 = Rijndael::new(&Secret::new(k1)).encrypt(&pt);
            let c2 = Rijndael::new(&Secret::new(k2)).encrypt(&pt);
            prop_assert_ne!(c1, c2, "different keys must produce different ciphertext");
        }
    }

    proptest! {
        // Permutation: encrypt is a bijection -- two distinct plaintexts under
        // the same key must produce distinct ciphertexts.
        #[test]
        fn encrypt_is_bijection(
            key in any::<[u8; 16]>(),
            pt1 in any::<[u8; 16]>(),
            pt2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(pt1 != pt2);
            let cipher = Rijndael::new(&Secret::new(key));
            let c1 = cipher.encrypt(&pt1);
            let c2 = cipher.encrypt(&pt2);
            prop_assert_ne!(c1, c2, "encrypt must be a bijection: different plaintexts => different ciphertexts");
        }
    }
}

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    /// Timing test for AES-128 encryption.
    ///
    /// Class 0: fixed key [0u8; 16], random plaintext.
    /// Class 1: random key, random plaintext.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_aes_encrypt_ct() {
        let outcome = ct_test(
            0xAE5E_0CC7,
            |rng| {
                let key = [0u8; 16];
                let mut plaintext = [0u8; 16];
                rng.fill_bytes(&mut plaintext);
                (key, plaintext)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut plaintext = [0u8; 16];
                rng.fill_bytes(&mut plaintext);
                (key, plaintext)
            },
            |(key, plaintext)| {
                let cipher = Rijndael::new(&Secret::new(*key));
                let ct = cipher.encrypt(plaintext);
                black_box(ct);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Timing test for AES-128 decryption.
    ///
    /// Class 0: fixed key [0u8; 16], random ciphertext.
    /// Class 1: random key, random ciphertext.
    ///
    /// The inverse cipher must also be constant-time: `InvSubBytes`,
    /// `InvMixColumns`, and key schedule must not leak through timing.
    #[test]
    fn test_aes_decrypt_ct() {
        let outcome = ct_test(
            0xAE5D_ECC7,
            |rng| {
                let key = [0u8; 16];
                let mut ciphertext = [0u8; 16];
                rng.fill_bytes(&mut ciphertext);
                (key, ciphertext)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut ciphertext = [0u8; 16];
                rng.fill_bytes(&mut ciphertext);
                (key, ciphertext)
            },
            |(key, ciphertext)| {
                let cipher = Rijndael::new(&Secret::new(*key));
                let pt = cipher.decrypt(ciphertext);
                black_box(pt);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
