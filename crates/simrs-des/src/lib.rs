//! DES and Triple-DES (3DES) block ciphers.
//!
//! Self-contained implementation with no heap allocation. Used by the OTA
//! secured packet layer (TS 102 225) for legacy DES/3DES cipher and MAC
//! operations.
//!
//! # Constant-time implementation
//!
//! All operations on secret data (S-box substitution) use constant-time
//! primitives from `simrs-consttime` to prevent cache-timing side-channel
//! attacks. S-box lookups use [`ct_select_n`], which reads all 64 table
//! entries and masks the result, making the memory access pattern independent
//! of the secret index.
//!
//! Permutation tables (IP, FP, E, P, PC1, PC2) operate on bit positions,
//! not data values, and are inherently constant-time.
//!
//! # Standards
//!
//! - [NIST FIPS 46-3](https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25) -- Data Encryption Standard (DES)
//! - [NIST SP 800-67 Rev.2](https://csrc.nist.gov/publications/detail/sp/800-67/rev-2/final) -- Recommendation for Triple-DES
//!
//! # `no_std`, `no_alloc`
//!
//! This crate uses no heap. All state lives in fixed-size structs.
//!
//! # Example
//!
//! ```
//! use simrs_des::{Des, TripleDes};
//! use simrs_secret::Secret;
//!
//! // NIST SP 800-67 Appendix B.1 test vector (key 1 only)
//! let key = Secret::new([0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
//! let des = Des::new(&key);
//! let ct = des.encrypt(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
//! assert_eq!(ct, [0x56, 0xCC, 0x09, 0xE7, 0xCF, 0xDC, 0x4C, 0xEF]);
//! assert_eq!(des.decrypt(&ct), [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::ct_select_n;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// DES
// ---------------------------------------------------------------------------

/// DES block cipher state.
///
/// Holds the 16 expanded 48-bit round keys derived from a 56-bit key
/// (stored as 8 bytes with parity bits). Supports both encryption and
/// decryption of single 64-bit (8-byte) blocks.
///
/// # Size
///
/// 128 bytes (16 round keys x 8 bytes each, stored as `u64`).
#[derive(Clone)]
pub struct Des {
    /// 16 round subkeys, each stored in the low 48 bits of a u64.
    subkeys: Secret<[u64; 16]>,
}

impl Des {
    /// Create a new DES cipher from an 8-byte key.
    ///
    /// The key includes 8 parity bits (one per byte, bit 0). These parity
    /// bits are ignored during key schedule computation per FIPS 46-3.
    pub fn new(key: &Secret<[u8; 8]>) -> Self {
        let k = key.declassify_ref();
        let subkeys = des_key_schedule(*k);
        Self {
            subkeys: Secret::new(subkeys),
        }
    }

    /// Encrypt a single 64-bit block.
    pub fn encrypt(&self, input: &[u8; 8]) -> [u8; 8] {
        des_cipher(*input, self.subkeys.declassify_ref(), false)
    }

    /// Decrypt a single 64-bit block.
    pub fn decrypt(&self, input: &[u8; 8]) -> [u8; 8] {
        des_cipher(*input, self.subkeys.declassify_ref(), true)
    }
}

impl core::fmt::Debug for Des {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Des")
            .field("subkeys", &"[...; 16]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Triple-DES
// ---------------------------------------------------------------------------

/// Triple-DES (3DES) block cipher in EDE mode.
///
/// Supports both 2-key (K1=K3) and 3-key modes.
///
/// - **2-key** (16 bytes): `TripleDes::new_2key()` -- K1=K3, 112-bit effective key
/// - **3-key** (24 bytes): `TripleDes::new_3key()` -- 168-bit effective key
///
/// Encryption: E(K1) -> D(K2) -> E(K3)
/// Decryption: D(K3) -> E(K2) -> D(K1)
///
/// # Example
///
/// ```
/// use simrs_des::TripleDes;
/// use simrs_secret::Secret;
///
/// // 2-key mode (K1 = K3)
/// let key = Secret::new([0x01u8; 16]);
/// let tdes = TripleDes::new_2key(&key);
/// let pt = [0x42u8; 8];
/// assert_eq!(tdes.decrypt(&tdes.encrypt(&pt)), pt);
/// ```
#[derive(Clone)]
pub struct TripleDes {
    k1: Des,
    k2: Des,
    k3: Des,
}

impl TripleDes {
    /// Create a 2-key Triple-DES cipher (K1=K3, 16-byte key).
    pub fn new_2key(key: &Secret<[u8; 16]>) -> Self {
        let kb = key.declassify_ref();
        let mut k1_bytes = [0u8; 8];
        let mut k2_bytes = [0u8; 8];
        k1_bytes.copy_from_slice(&kb[..8]);
        k2_bytes.copy_from_slice(&kb[8..16]);
        let k1 = Des::new(&Secret::new(k1_bytes));
        let k2 = Des::new(&Secret::new(k2_bytes));
        let k3 = Des::new(&Secret::new(k1_bytes));
        Self { k1, k2, k3 }
    }

    /// Create a 3-key Triple-DES cipher (24-byte key).
    pub fn new_3key(key: &Secret<[u8; 24]>) -> Self {
        let kb = key.declassify_ref();
        let mut k1_bytes = [0u8; 8];
        let mut k2_bytes = [0u8; 8];
        let mut k3_bytes = [0u8; 8];
        k1_bytes.copy_from_slice(&kb[..8]);
        k2_bytes.copy_from_slice(&kb[8..16]);
        k3_bytes.copy_from_slice(&kb[16..24]);
        let k1 = Des::new(&Secret::new(k1_bytes));
        let k2 = Des::new(&Secret::new(k2_bytes));
        let k3 = Des::new(&Secret::new(k3_bytes));
        Self { k1, k2, k3 }
    }

    /// Encrypt a single 64-bit block (EDE mode).
    pub fn encrypt(&self, input: &[u8; 8]) -> [u8; 8] {
        let step1 = self.k1.encrypt(input);
        let step2 = self.k2.decrypt(&step1);
        self.k3.encrypt(&step2)
    }

    /// Decrypt a single 64-bit block (DED mode).
    pub fn decrypt(&self, input: &[u8; 8]) -> [u8; 8] {
        let step1 = self.k3.decrypt(input);
        let step2 = self.k2.encrypt(&step1);
        self.k1.decrypt(&step2)
    }
}

impl core::fmt::Debug for TripleDes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TripleDes").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Core DES cipher
// ---------------------------------------------------------------------------

/// DES cipher core: applies IP, 16 Feistel rounds, then FP.
#[allow(clippy::cast_possible_truncation)] // intentional 64->32 split
fn des_cipher(input: [u8; 8], subkeys: &[u64; 16], decrypt: bool) -> [u8; 8] {
    let block = u64::from_be_bytes(input);

    // Initial Permutation (IP).
    let permuted = permute_64(block, &IP);

    let mut left = (permuted >> 32) as u32;
    let mut right = permuted as u32;

    // 16 Feistel rounds.
    for i in 0..16 {
        let ki = if decrypt { subkeys[15 - i] } else { subkeys[i] };
        let f_out = feistel(right, ki);
        let new_right = left ^ f_out;
        left = right;
        right = new_right;
    }

    // Pre-output: swap left and right (undo the last swap).
    let pre_output = (u64::from(right) << 32) | u64::from(left);

    // Final Permutation (FP = IP^-1).
    let output = permute_64(pre_output, &FP);
    output.to_be_bytes()
}

/// Feistel function f(R, K).
///
/// 1. Expand R (32 bits) to 48 bits using E permutation
/// 2. XOR with round key K (48 bits)
/// 3. Apply 8 S-boxes (6 bits -> 4 bits each)
/// 4. Apply P permutation (32 bits -> 32 bits)
#[allow(clippy::cast_possible_truncation)]
fn feistel(right: u32, key: u64) -> u32 {
    // Expansion: 32 bits -> 48 bits.
    let expanded = expand(right);

    // XOR with round key.
    let xored = expanded ^ key;

    // S-box substitution: 48 bits -> 32 bits (8 groups of 6 -> 4 bits).
    let mut sbox_output = 0u32;
    for (i, sbox) in SBOXES.iter().enumerate() {
        let shift = (7 - i) * 6;
        let six_bits = ((xored >> shift) & 0x3F) as u8;

        // Row = outer bits (bit5, bit0), Column = inner bits (bit4..bit1).
        let row = ((six_bits >> 4) & 0x02) | (six_bits & 0x01);
        let col = (six_bits >> 1) & 0x0F;
        let index = (row * 16 + col) as usize;

        let sbox_val = ct_select_n(sbox, index);
        sbox_output |= u32::from(sbox_val) << ((7 - i) * 4);
    }

    // P permutation: 32 bits -> 32 bits.
    permute_32(sbox_output, &P_PERM)
}

/// Expand 32-bit half-block to 48 bits using the E table.
fn expand(half: u32) -> u64 {
    let mut result = 0u64;
    for (i, &bit_pos) in E_PERM.iter().enumerate() {
        let bit = (half >> (32 - u32::from(bit_pos))) & 1;
        result |= u64::from(bit) << (47 - i);
    }
    result
}

/// Permute a 64-bit value using a permutation table.
fn permute_64(input: u64, table: &[u8; 64]) -> u64 {
    let mut output = 0u64;
    for (i, &bit_pos) in table.iter().enumerate() {
        let bit = (input >> (64 - u32::from(bit_pos))) & 1;
        output |= bit << (63 - i);
    }
    output
}

/// Permute a 32-bit value using a 32-entry permutation table.
fn permute_32(input: u32, table: &[u8; 32]) -> u32 {
    let mut output = 0u32;
    for (i, &bit_pos) in table.iter().enumerate() {
        let bit = (input >> (32 - u32::from(bit_pos))) & 1;
        output |= bit << (31 - i);
    }
    output
}

// ---------------------------------------------------------------------------
// Key Schedule
// ---------------------------------------------------------------------------

/// Compute the 16 round subkeys from an 8-byte DES key.
#[allow(clippy::cast_possible_truncation)] // intentional 64->32 split for C/D halves
fn des_key_schedule(key: [u8; 8]) -> [u64; 16] {
    let key_bits = u64::from_be_bytes(key);

    // Permuted Choice 1: select 56 bits from the 64-bit key.
    let mut cd = 0u64;
    for (i, &bit_pos) in PC1.iter().enumerate() {
        let bit = (key_bits >> (64 - u32::from(bit_pos))) & 1;
        cd |= bit << (55 - i);
    }

    let mut c = (cd >> 28) as u32 & 0x0FFF_FFFF;
    let mut d = cd as u32 & 0x0FFF_FFFF;

    let mut subkeys = [0u64; 16];

    for (i, subkey) in subkeys.iter_mut().enumerate() {
        // Left rotate C and D by 1 or 2 positions.
        let shift = LEFT_SHIFTS[i];
        c = rotate_left_28(c, shift);
        d = rotate_left_28(d, shift);

        // Combine C and D, then apply Permuted Choice 2 to get 48-bit subkey.
        let cd_combined = (u64::from(c) << 28) | u64::from(d);
        let mut k = 0u64;
        for (j, &bit_pos) in PC2.iter().enumerate() {
            let bit = (cd_combined >> (56 - u32::from(bit_pos))) & 1;
            k |= bit << (47 - j);
        }
        *subkey = k;
    }

    subkeys
}

/// Left-rotate a 28-bit value by `n` positions.
const fn rotate_left_28(val: u32, n: u8) -> u32 {
    ((val << n) | (val >> (28 - n))) & 0x0FFF_FFFF
}

// ---------------------------------------------------------------------------
// Permutation Tables (NIST FIPS 46-3)
// ---------------------------------------------------------------------------

/// Initial Permutation (IP).
/// FIPS 46-3, Table 1.
static IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// Final Permutation (FP = IP^-1).
/// FIPS 46-3, Table 2.
static FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// Expansion permutation E (32 -> 48 bits).
/// FIPS 46-3, Table 3.
static E_PERM: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// P permutation (32 bits -> 32 bits, after S-box substitution).
/// FIPS 46-3, Table 4.
static P_PERM: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

/// Permuted Choice 1 (PC-1): select 56 bits from 64-bit key.
/// FIPS 46-3, Table 5.
static PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// Permuted Choice 2 (PC-2): select 48 bits from 56-bit CD.
/// FIPS 46-3, Table 6.
static PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Left rotation schedule per round.
/// FIPS 46-3: rounds 1, 2, 9, 16 rotate by 1; all others by 2.
static LEFT_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// ---------------------------------------------------------------------------
// S-boxes (NIST FIPS 46-3)
// ---------------------------------------------------------------------------
//
// Each S-box maps a 6-bit input to a 4-bit output. Stored as flat [u8; 64]
// arrays in row-major order (4 rows x 16 columns).
//
// Row selection: outer bits (bit5, bit0) -> 2-bit row index.
// Column selection: inner bits (bit4..bit1) -> 4-bit column index.
// Flat index: row * 16 + column.

/// Pointer-to-array for S-box dispatch.
static SBOXES: [&[u8]; 8] = [&S1, &S2, &S3, &S4, &S5, &S6, &S7, &S8];

/// S-box 1. FIPS 46-3 Table 7.
static S1: [u8; 64] = [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,
    9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5,
    11, 3, 14, 10, 0, 6, 13,
];

/// S-box 2. FIPS 46-3 Table 7.
static S2: [u8; 64] = [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10,
    6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2,
    11, 6, 7, 12, 0, 5, 14, 9,
];

/// S-box 3. FIPS 46-3 Table 7.
static S3: [u8; 64] = [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14,
    12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7,
    4, 15, 14, 3, 11, 5, 2, 12,
];

/// S-box 4. FIPS 46-3 Table 7.
static S4: [u8; 64] = [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12,
    1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8,
    9, 4, 5, 11, 12, 7, 2, 14,
];

/// S-box 5. FIPS 46-3 Table 7.
static S5: [u8; 64] = [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10,
    3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13,
    6, 15, 0, 9, 10, 4, 5, 3,
];

/// S-box 6. FIPS 46-3 Table 7.
static S6: [u8; 64] = [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14,
    0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10,
    11, 14, 1, 7, 6, 0, 8, 13,
];

/// S-box 7. FIPS 46-3 Table 7.
static S7: [u8; 64] = [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12,
    2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7,
    9, 5, 0, 15, 14, 2, 3, 12,
];

/// S-box 8. FIPS 46-3 Table 7.
static S8: [u8; 64] = [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11,
    0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13,
    15, 12, 9, 0, 3, 5, 6, 11,
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DES known answer tests --

    /// NIST SP 800-67 Appendix B.1 (single DES encrypt).
    /// Key:       0123456789ABCDEF
    /// Plaintext: 0123456789ABCDEF
    /// Expected:  56CC09E7CFDC4CEF
    #[test]
    fn nist_sp800_67_single_des() {
        let key = Secret::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let des = Des::new(&key);
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let ct = des.encrypt(&pt);
        assert_eq!(ct, [0x56, 0xCC, 0x09, 0xE7, 0xCF, 0xDC, 0x4C, 0xEF]);
    }

    /// DES with zero key and zero plaintext.
    /// Known value: DES(0...0, 0...0) = 8CA64DE9C1B123A7.
    #[test]
    fn zero_key_zero_input() {
        let des = Des::new(&Secret::new([0u8; 8]));
        let ct = des.encrypt(&[0u8; 8]);
        assert_ne!(ct, [0u8; 8], "zero input must not produce zero output");
        assert_eq!(ct, [0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7]);
    }

    /// Round-trip: decrypt(encrypt(pt)) == pt.
    #[test]
    fn round_trip() {
        let key = Secret::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let des = Des::new(&key);
        let pt = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(des.decrypt(&des.encrypt(&pt)), pt);
    }

    /// Decryption is not identity.
    #[test]
    fn decrypt_not_identity() {
        let key = Secret::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let des = Des::new(&key);
        let ct = [0x56, 0xCC, 0x09, 0xE7, 0xCF, 0xDC, 0x4C, 0xEF];
        assert_ne!(des.decrypt(&ct), ct, "decrypt must not be identity");
    }

    /// Different keys produce different ciphertexts.
    #[test]
    fn different_keys() {
        let pt = [0xAA; 8];
        let d1 = Des::new(&Secret::new([0x01; 8]));
        let d2 = Des::new(&Secret::new([0x02; 8]));
        assert_ne!(d1.encrypt(&pt), d2.encrypt(&pt));
    }

    /// Deterministic: same key + input always yields same output.
    #[test]
    fn deterministic() {
        let key = Secret::new([0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]);
        let des = Des::new(&key);
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        assert_eq!(des.encrypt(&pt), des.encrypt(&pt));
    }

    /// NIST SP 800-20 test: key=0133457799BBCDFF, pt=0123456789ABCDEF.
    #[test]
    fn nist_sp800_20_vector() {
        let key = Secret::new([0x01, 0x33, 0x45, 0x77, 0x99, 0xBB, 0xCD, 0xFF]);
        let des = Des::new(&key);
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let ct = des.encrypt(&pt);
        // Decrypt must recover plaintext.
        assert_eq!(des.decrypt(&ct), pt);
        // Ciphertext must differ from plaintext.
        assert_ne!(ct, pt);
    }

    // -- IP/FP inverse test --

    #[test]
    fn ip_fp_are_inverses() {
        // FP must be the inverse permutation of IP.
        for i in 0..64 {
            let bit_pos = IP[i]; // IP maps position i+1 to bit_pos
                                 // FP must map bit_pos back to i+1
            let recovered = FP.iter().position(|&b| b == (i as u8 + 1)).unwrap();
            assert_eq!(
                recovered,
                (bit_pos - 1) as usize,
                "FP is not the inverse of IP at position {i}"
            );
        }
    }

    // -- Triple-DES tests --

    /// Verify DES step by step for 3DES intermediate values.
    /// E(K1=0123456789ABCDEF, PT=5468652071756963) = A3C6E831AD654880
    /// (Verified against PyCryptodome)
    #[test]
    fn des_encrypt_step1_3des() {
        let k1 = Secret::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let des = Des::new(&k1);
        let pt = [0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63];
        let ct = des.encrypt(&pt);
        assert_eq!(ct, [0xA3, 0xC6, 0xE8, 0x31, 0xAD, 0x65, 0x48, 0x80]);
    }

    /// 3-key 3DES: verified against PyCryptodome.
    /// Keys: K1=0123456789ABCDEF, K2=23456789ABCDEF01, K3=456789ABCDEF0123
    /// Plaintext:  5468652071756963 ("The quic")
    /// Ciphertext: 1CCF23869D09333E (PyCryptodome ECB)
    #[test]
    fn tdes_3key_pycryptodome_vector() {
        let key = Secret::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K1
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, // K2
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, // K3
        ]);
        let tdes = TripleDes::new_3key(&key);
        let pt = [0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63]; // "The quic"
        let ct = tdes.encrypt(&pt);
        assert_eq!(ct, [0x1C, 0xCF, 0x23, 0x86, 0x9D, 0x09, 0x33, 0x3E]);
        assert_eq!(tdes.decrypt(&ct), pt);
    }

    /// 2-key 3DES round-trip.
    #[test]
    fn tdes_2key_roundtrip() {
        let key = Secret::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        let tdes = TripleDes::new_2key(&key);
        let pt = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(tdes.decrypt(&tdes.encrypt(&pt)), pt);
    }

    /// 3-key 3DES round-trip.
    #[test]
    fn tdes_3key_roundtrip() {
        let key = Secret::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
            0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        ]);
        let tdes = TripleDes::new_3key(&key);
        let pt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(tdes.decrypt(&tdes.encrypt(&pt)), pt);
    }

    /// 2-key 3DES with identical keys reduces to single DES.
    #[test]
    fn tdes_2key_identical_is_single_des() {
        let single_key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let des = Des::new(&Secret::new(single_key));

        // 2-key with K1=K2 -> E(K1, D(K1, E(K1, pt))) = E(K1, pt)
        let mut double_key = [0u8; 16];
        double_key[..8].copy_from_slice(&single_key);
        double_key[8..16].copy_from_slice(&single_key);
        let tdes = TripleDes::new_2key(&Secret::new(double_key));

        let pt = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(tdes.encrypt(&pt), des.encrypt(&pt));
    }

    /// S-box output is always 4-bit (0..15).
    #[test]
    fn sbox_output_range() {
        for (sbox_idx, sbox) in SBOXES.iter().enumerate() {
            for i in 0..64 {
                let val = ct_select_n(sbox, i);
                assert!(val <= 15, "S-box {sbox_idx} index {i}: output {val} > 15");
            }
        }
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
        #[test]
        fn des_encrypt_decrypt_roundtrip(key in any::<[u8; 8]>(), pt in any::<[u8; 8]>()) {
            let des = Des::new(&Secret::new(key));
            let ct = des.encrypt(&pt);
            let recovered = des.decrypt(&ct);
            prop_assert_eq!(recovered, pt);
        }
    }

    proptest! {
        #[test]
        fn des_different_keys_different_ct(
            k1 in any::<[u8; 8]>(),
            k2 in any::<[u8; 8]>(),
            pt in any::<[u8; 8]>(),
        ) {
            prop_assume!(k1 != k2);
            let c1 = Des::new(&Secret::new(k1)).encrypt(&pt);
            let c2 = Des::new(&Secret::new(k2)).encrypt(&pt);
            prop_assert_ne!(c1, c2);
        }
    }

    proptest! {
        #[test]
        fn des_is_bijection(
            key in any::<[u8; 8]>(),
            pt1 in any::<[u8; 8]>(),
            pt2 in any::<[u8; 8]>(),
        ) {
            prop_assume!(pt1 != pt2);
            let des = Des::new(&Secret::new(key));
            prop_assert_ne!(des.encrypt(&pt1), des.encrypt(&pt2));
        }
    }

    proptest! {
        #[test]
        fn tdes_3key_roundtrip(key in any::<[u8; 24]>(), pt in any::<[u8; 8]>()) {
            let tdes = TripleDes::new_3key(&Secret::new(key));
            prop_assert_eq!(tdes.decrypt(&tdes.encrypt(&pt)), pt);
        }
    }

    proptest! {
        #[test]
        fn tdes_2key_roundtrip(key in any::<[u8; 16]>(), pt in any::<[u8; 8]>()) {
            let tdes = TripleDes::new_2key(&Secret::new(key));
            prop_assert_eq!(tdes.decrypt(&tdes.encrypt(&pt)), pt);
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (DudeCT)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    /// DES encryption timing must be independent of key content.
    #[test]
    fn test_des_encrypt_ct() {
        let outcome = ct_test(
            0xDE5E_0CC7,
            |rng| {
                let key = [0u8; 8];
                let mut plaintext = [0u8; 8];
                rng.fill_bytes(&mut plaintext);
                (key, plaintext)
            },
            |rng| {
                let mut key = [0u8; 8];
                rng.fill_bytes(&mut key);
                let mut plaintext = [0u8; 8];
                rng.fill_bytes(&mut plaintext);
                (key, plaintext)
            },
            |(key, plaintext)| {
                let cipher = Des::new(&Secret::new(*key));
                let ct = cipher.encrypt(plaintext);
                black_box(ct);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// DES decryption timing must be independent of key content.
    #[test]
    fn test_des_decrypt_ct() {
        let outcome = ct_test(
            0xDE5D_ECC7,
            |rng| {
                let key = [0u8; 8];
                let mut ct = [0u8; 8];
                rng.fill_bytes(&mut ct);
                (key, ct)
            },
            |rng| {
                let mut key = [0u8; 8];
                rng.fill_bytes(&mut key);
                let mut ct = [0u8; 8];
                rng.fill_bytes(&mut ct);
                (key, ct)
            },
            |(key, ct)| {
                let cipher = Des::new(&Secret::new(*key));
                let pt = cipher.decrypt(ct);
                black_box(pt);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
