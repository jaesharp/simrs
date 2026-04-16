//! `COMP128v1` (A3/A8) GSM authentication algorithm.
//!
//! Implementation of the reversed COMP128 algorithm per Briceno, Goldberg, Wagner (1998).
//! Produces SRES (4 bytes) and Kc (8 bytes) from Ki (16 bytes) and RAND (16 bytes).
//!
//! # Algorithm Overview
//!
//! COMP128 uses 5 substitution tables (512, 256, 128, 64, 32 entries) applied over
//! 8 rounds of substitution + permutation on a 32-byte working state. The first 16
//! bytes are loaded from Ki at the start of each round; the second 16 bytes come from
//! RAND (round 1) or the permuted output of the previous round (rounds 2-8).
//!
//! After 8 rounds, the 32-byte state is converted to 128 bits, then packed into:
//! - **SRES** (4 bytes): bytes 0-7 of the working state, packed as nibbles
//! - **Kc** (8 bytes): bytes 18-31 of the working state, packed as 6-bit groups
//!   with the final byte zero-padded
//!
//! # Known Weakness
//!
//! `COMP128v1` has a well-known collision attack (Briceno/Goldberg/Wagner 1998) that
//! allows Ki extraction from ~150,000 chosen-challenge queries. It was deprecated by
//! GSM operators in favour of COMP128v2/v3 and later Milenage. simrs implements v1
//! for legacy GSM testing.
//!
//! # Standards
//! - [ETSI TS 151 011 V4.15.0 clause 11](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A327%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C689%5D) -- A3/A8 algorithm interface
//! - [ETSI TS 151 011 V4.15.0 clause 11](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A327%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C689%5D) -- RUN GSM ALGORITHM command
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All computation is done in-place on stack buffers.
//!
//! # Example
//!
//! ```
//! use simrs_comp128::{comp128, GsmAuthResult};
//! use simrs_secret::Secret;
//!
//! // Cross-validated against reference implementation
//! let ki   = Secret::new([0xABu8; 16]);
//! let rand = [0xCDu8; 16];
//!
//! let result: GsmAuthResult = comp128(&ki, &rand);
//!
//! assert_eq!(*result.signed_response.as_bytes(), [0x43, 0xFA, 0xD2, 0x08]);
//! assert_eq!(*result.cipher_key.declassify_ref(), [0x8F, 0x6E, 0x14, 0x88, 0x18, 0x39, 0xD4, 0x00]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::{ct_select, ct_select_n};
use simrs_redact::Redact;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// Newtype: SignedResponse (SRES)
// ---------------------------------------------------------------------------

/// GSM signed response (4 bytes, COMP128 output).
///
/// The authentication response sent from the SIM to the network during
/// GSM authentication (A3/A8 algorithm).
///
/// Per ETSI TS 131 102 / GSM 11.11.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedResponse([u8; 4]);
impl SignedResponse {
    /// Create a new `SignedResponse` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 4]) -> Self {
        Self(raw)
    }
    /// Access the raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}
impl From<[u8; 4]> for SignedResponse {
    fn from(raw: [u8; 4]) -> Self {
        Self(raw)
    }
}

/// GSM abbreviation for [`SignedResponse`].
///
/// The specs (GSM 11.11 / ETSI TS 131 102) use "SRES" (Signed Response).
/// We prefer `SignedResponse` for self-documenting code.
#[deprecated(note = "GSM SRES (TS 131 102) -- prefer SignedResponse")]
pub type Sres = SignedResponse;

/// Result of the `COMP128v1` GSM authentication algorithm.
///
/// Contains the signed response used for network authentication
/// and the cipher key used for A5 stream cipher encryption.
///
/// # Layout
///
/// Per [ETSI TS 151 011 V4.15.0 clause 11](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A327%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C689%5D):
/// - Signed response: 4 bytes (32 bits) -- sent to the network
/// - Cipher key: 8 bytes (64 bits) -- used as the A5 key
///
/// # Invariants
///
/// - `cipher_key[7]` is always `0x00` (COMP128v1 only produces 54 effective bits)
/// - `cipher_key[6] & 0x03 == 0` (bottom 2 bits of byte 6 are always zero)
///
/// ```
/// use simrs_comp128::{comp128, GsmAuthResult};
/// use simrs_secret::Secret;
///
/// let r = comp128(&Secret::new([0u8; 16]), &[0u8; 16]);
/// assert_eq!(r.cipher_key.declassify_ref()[7], 0x00);
/// assert_eq!(r.cipher_key.declassify_ref()[6] & 0x03, 0x00);
/// ```
#[derive(Clone, Copy)]
pub struct GsmAuthResult {
    /// Signed response (4 bytes).
    /// Sent to the base station to prove knowledge of Ki.
    pub signed_response: SignedResponse,

    /// Cipher key (8 bytes, effective 54 bits).
    /// Used as the session key for A5/1 or A5/3 encryption.
    /// Byte 7 is always 0x00; byte 6 bottom 2 bits are always 0.
    pub cipher_key: Secret<[u8; 8]>,
}

/// GSM abbreviation for [`GsmAuthResult`].
///
/// The algorithm literature uses "Comp128Result". We prefer `GsmAuthResult`
/// for consistency with the descriptive naming convention.
#[deprecated(note = "renamed to GsmAuthResult")]
pub type Comp128Result = GsmAuthResult;

/// COMP128 algorithm version selector.
///
/// GSM operators deployed different COMP128 versions over time:
/// - **V1**: Original (Briceno/Goldberg/Wagner 1998 reversal). Vulnerable to
///   Ki extraction via ~150,000 chosen-challenge queries.
/// - **V2**: Strengthened round function, but still zeroes the last 10 bits
///   of Kc (54-bit effective cipher key), matching V1's output weakness.
/// - **V3**: Same strengthened round function as V2, but with full 64-bit Kc.
///
/// V2 and V3 are structurally different from V1 (different substitution tables,
/// different internal computation). They are NOT merely V1 with a modified
/// output stage.
///
/// # Standards
///
/// - COMP128v1: ETSI TS 155 205
/// - COMP128v2/v3: proprietary (reverse-engineered by Tamas Jos / skelsec)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comp128Version {
    /// Version 1: original algorithm, vulnerable to Ki extraction.
    V1,
    /// Version 2: strengthened core, 54-bit effective Kc (last 10 bits zeroed).
    V2,
    /// Version 3: strengthened core, full 64-bit Kc.
    V3,
}

impl core::fmt::Debug for GsmAuthResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GsmAuthResult")
            .field("signed_response", &self.signed_response.as_bytes())
            .field("cipher_key", &Redact(self.cipher_key.declassify_ref()))
            .finish()
    }
}

/// Run the COMP128v1 A3/A8 GSM authentication algorithm.
///
/// Computes SRES and Kc from the subscriber's secret key (Ki) and a random
/// challenge (RAND) from the base station.
///
/// # Arguments
///
/// * `ki` -- 16-byte Individual Subscriber Authentication Key wrapped in [`Secret`]
/// * `rand` -- 16-byte random challenge from the network
///
/// # Returns
///
/// [`GsmAuthResult`] containing the 4-byte signed response and 8-byte cipher key.
///
/// # Algorithm
///
/// 1. Initialize 32-byte working state: `x[0..16] = Ki`, `x[16..32] = RAND`
/// 2. For each of 8 rounds:
///    a. Reload `x[0..16] = Ki`
///    b. Apply 5 substitution stages using tables of size 512, 256, 128, 64, 32
///    c. Extract 128 bits from the 32-byte state
///    d. Permute bits using `bit_next = (8*j + k) * 17 mod 128` (rounds 1-7 only)
/// 3. Pack output: SRES from x[0..8] as nibble pairs, Kc from x[18..32] as 6-bit groups
///
/// # Determinism
///
/// This function is pure: same Ki + RAND always produces the same SRES + Kc.
///
/// ```
/// use simrs_comp128::comp128;
/// use simrs_secret::Secret;
///
/// let ki   = Secret::new([0x11u8; 16]);
/// let rand = [0x22u8; 16];
/// let r1 = comp128(&ki, &rand);
/// let r2 = comp128(&ki, &rand);
/// assert_eq!(r1.signed_response.as_bytes(), r2.signed_response.as_bytes());
/// assert_eq!(r1.cipher_key.declassify_ref(), r2.cipher_key.declassify_ref());
/// ```
///
/// # Different inputs produce different outputs
///
/// ```
/// use simrs_comp128::comp128;
/// use simrs_secret::Secret;
///
/// let ki = Secret::new([0x11u8; 16]);
/// let r1 = comp128(&ki, &[0x00u8; 16]);
/// let r2 = comp128(&ki, &[0x01u8; 16]);
/// assert!(
///     r1.signed_response.as_bytes() != r2.signed_response.as_bytes() || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref(),
///     "different RAND must produce different results"
/// );
/// ```
///
/// # Cross-validation
///
/// Bit-identical output to reference implementation.
///
/// ```
/// use simrs_comp128::comp128;
/// use simrs_secret::Secret;
///
/// let ki = Secret::new([
///     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
///     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
/// ]);
/// let rand = [
///     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
///     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
/// ];
/// let result = comp128(&ki, &rand);
/// assert_eq!(*result.signed_response.as_bytes(), [0x46, 0xF0, 0x2D, 0xBA]);
/// assert_eq!(*result.cipher_key.declassify_ref(), [0xE9, 0xB7, 0xD0, 0x45, 0xEC, 0x87, 0x1C, 0x00]);
/// ```
#[allow(clippy::cast_possible_truncation)] // values bounded by table size / bit masks
#[allow(clippy::many_single_char_names)] // matches C reference variable names
pub fn comp128(ki: &Secret<[u8; 16]>, rand: &[u8; 16]) -> GsmAuthResult {
    let ki_bytes = ki.declassify_ref();
    let tables: [&[u8]; 5] = [&TABLE_0, &TABLE_1, &TABLE_2, &TABLE_3, &TABLE_4];

    let mut x = [0u8; 32];
    let mut bits = [0u8; 128];

    // Load RAND into upper half.
    x[16..32].copy_from_slice(rand);

    // 8 rounds (indexed 1..=8 in the C reference).
    for round in 1..=8u32 {
        // Reload Ki into lower half each round.
        x[0..16].copy_from_slice(ki_bytes);

        // 5 substitution stages.
        for j in 0..5u32 {
            let groups = 1u32 << j; // number of butterfly groups
            let half = 1u32 << (4 - j); // half-size of each group
            let modulus = 1u32 << (9 - j); // table modulus

            for k in 0..groups {
                for l in 0..half {
                    let m = (l + k * (half << 1)) as usize;
                    let n = m + half as usize;
                    let y = ((u32::from(x[m]) + 2 * u32::from(x[n])) & (modulus - 1)) as usize;
                    let z = ((2 * u32::from(x[m]) + u32::from(x[n])) & (modulus - 1)) as usize;
                    x[m] = ct_select_n(tables[j as usize], y);
                    x[n] = ct_select_n(tables[j as usize], z);
                }
            }
        }

        // Extract 128 bits from the 32-byte state (4 bits per byte).
        for j in 0..32usize {
            for k in 0..4u32 {
                bits[4 * j + k as usize] = (x[j] >> (3 - k)) & 1;
            }
        }

        // Bit permutation (skip on last round).
        if round < 8 {
            for j in 0..16usize {
                x[j + 16] = 0;
                for k in 0..8u32 {
                    let bit_next = ((8 * j as u32 + k) * 17) & 127;
                    x[j + 16] |= bits[bit_next as usize] << (7 - k);
                }
            }
        }
    }

    // Pack SRES: x[0..8] as nibble pairs -> 4 bytes.
    let mut sres = [0u8; 4];
    for i in 0..4usize {
        sres[i] = (x[2 * i] << 4) | x[2 * i + 1];
    }

    // Pack Kc: x[18..32] as 6-bit groups -> 8 bytes.
    // 14 nibbles (4 bits each) = 56 bits, packed into 6-bit groups:
    //   Kc[i] = x[2i+18] << 6 | x[2i+19] << 2 | x[2i+20] >> 2
    // Last byte (i=6) only has 2 nibbles, last byte (i=7) is 0x00.
    let mut kc = [0u8; 8];
    for i in 0..6usize {
        kc[i] = (x[2 * i + 18] << 6) | (x[2 * i + 19] << 2) | (x[2 * i + 20] >> 2);
    }
    kc[6] = (x[30] << 6) | (x[31] << 2);
    kc[7] = 0x00;

    GsmAuthResult {
        signed_response: SignedResponse::new(sres),
        cipher_key: Secret::new(kc),
    }
}

/// Run the COMP128v3 A3/A8 GSM authentication algorithm.
///
/// COMP128v3 uses a completely different internal structure from V1: two
/// 256-entry substitution tables, byte-reversed inputs, and a different
/// bit-extraction stage. The output includes a full 64-bit Kc (no bit zeroing).
///
/// # Reference
///
/// Ported from Osmocom libosmocore `comp128v23.c` (Tamas Jos / skelsec).
///
/// ```
/// use simrs_comp128::comp128v3;
/// use simrs_secret::Secret;
///
/// let ki   = Secret::new([0x00u8; 16]);
/// let rand = [0x00u8; 16];
/// let r = comp128v3(&ki, &rand);
/// assert_eq!(*r.signed_response.as_bytes(), [0xB2, 0x4C, 0x2D, 0xAC]);
/// assert_eq!(*r.cipher_key.declassify_ref(), [0x7C, 0x82, 0xC3, 0xEC, 0x44, 0x95, 0x35, 0x61]);
/// ```
#[allow(clippy::cast_possible_truncation)]
pub fn comp128v3(ki: &Secret<[u8; 16]>, rand: &[u8; 16]) -> GsmAuthResult {
    let ki_bytes = ki.declassify_ref();

    // Byte reversal of Ki and RAND.
    let mut k_mix = [0u8; 16];
    let mut rand_mix = [0u8; 16];
    for i in 0..8 {
        k_mix[i] = ki_bytes[15 - i];
        k_mix[15 - i] = ki_bytes[i];
    }
    for i in 0..8 {
        rand_mix[i] = rand[15 - i];
        rand_mix[15 - i] = rand[i];
    }

    // XOR key and rand.
    let mut katyvasz = [0u8; 16];
    for i in 0..16 {
        katyvasz[i] = k_mix[i] ^ rand_mix[i];
    }

    // 8 iterations of the internal function.
    for _ in 0..8 {
        rand_mix = comp128v23_internal(&rand_mix, &katyvasz);
    }

    // Byte reversal of output.
    let mut output = [0u8; 16];
    for i in 0..16 {
        output[i] = rand_mix[15 - i];
    }

    // Skip bytes 4..7 (memmove(output+4, output+8, 8) in the C reference).
    let mut sres = [0u8; 4];
    sres.copy_from_slice(&output[..4]);

    let mut kc = [0u8; 8];
    kc.copy_from_slice(&output[8..16]);

    GsmAuthResult {
        signed_response: SignedResponse::new(sres),
        cipher_key: Secret::new(kc),
    }
}

/// Run the COMP128v2 A3/A8 GSM authentication algorithm.
///
/// Identical to COMP128v3 but forces the last 10 bits of Kc to zero,
/// producing a 54-bit effective cipher key (same constraint as V1).
///
/// ```
/// use simrs_comp128::comp128v2;
/// use simrs_secret::Secret;
///
/// let ki   = Secret::new([0x00u8; 16]);
/// let rand = [0x00u8; 16];
/// let r = comp128v2(&ki, &rand);
/// assert_eq!(*r.signed_response.as_bytes(), [0xB2, 0x4C, 0x2D, 0xAC]);
/// // Kc last 10 bits zeroed vs V3:
/// assert_eq!(r.cipher_key.declassify_ref()[7], 0x00);
/// assert_eq!(r.cipher_key.declassify_ref()[6] & 0x03, 0x00);
/// ```
pub fn comp128v2(ki: &Secret<[u8; 16]>, rand: &[u8; 16]) -> GsmAuthResult {
    let result = comp128v3(ki, rand);
    let mut kc = *result.cipher_key.declassify_ref();
    kc[7] = 0x00;
    kc[6] &= 0xFC;
    GsmAuthResult {
        signed_response: result.signed_response,
        cipher_key: Secret::new(kc),
    }
}

/// Run the COMP128 A3/A8 algorithm for a specified version.
///
/// Dispatches to [`comp128`] (V1), [`comp128v2`], or [`comp128v3`].
///
/// ```
/// use simrs_comp128::{comp128, comp128_versioned, Comp128Version};
/// use simrs_secret::Secret;
///
/// let ki = Secret::new([0x11u8; 16]);
/// let rand = [0x22u8; 16];
/// let r_direct = comp128(&ki, &rand);
/// let r_versioned = comp128_versioned(&ki, &rand, Comp128Version::V1);
/// assert_eq!(r_direct.signed_response, r_versioned.signed_response);
/// ```
pub fn comp128_versioned(
    ki: &Secret<[u8; 16]>,
    rand: &[u8; 16],
    version: Comp128Version,
) -> GsmAuthResult {
    match version {
        Comp128Version::V1 => comp128(ki, rand),
        Comp128Version::V2 => comp128v2(ki, rand),
        Comp128Version::V3 => comp128v3(ki, rand),
    }
}

/// COMP128v2/v3 internal round function.
///
/// Applies two-table substitution and bit extraction to produce a 16-byte
/// output from the current state (`rand_in`) and key-XOR material (`kxor`).
#[allow(clippy::cast_possible_truncation)]
fn comp128v23_internal(rand_in: &[u8; 16], kxor: &[u8; 16]) -> [u8; 16] {
    let mut temp = [0u8; 16];
    let mut km_rm = [0u8; 32];

    km_rm[..16].copy_from_slice(rand_in);
    km_rm[16..32].copy_from_slice(kxor);

    for i in 0..5u32 {
        for z in 0..16usize {
            let t1 = ct_select(&TABLE_V23_1, km_rm[16 + z]);
            temp[z] = ct_select(&TABLE_V23_0, t1 ^ km_rm[z]);
        }

        let mut j = 0u32;
        while (1u32 << i) > j {
            let mut k = 0u32;
            while (1u32 << (4 - i)) > k {
                let src = ((k << i) + j) as usize;
                let src_k = ((k << i) + 16 + j) as usize;
                let dst1 = (((2 * k + 1) << i) + j) as usize;
                let dst2 = ((k << (i + 1)) + j) as usize;

                let t1 = ct_select(&TABLE_V23_1, temp[src]);
                km_rm[dst1] = ct_select(&TABLE_V23_0, t1 ^ km_rm[src_k]);
                km_rm[dst2] = temp[src];

                k += 1;
            }
            j += 1;
        }
    }

    let mut output = [0u8; 16];
    for i in 0..16u32 {
        for j in 0..8u32 {
            let idx = ((19 * (j + 8 * i) + 19) % 256 / 8) as usize;
            let shift = (3 * j + 3) % 8;
            output[i as usize] ^= ((km_rm[idx] >> shift) & 1) << j;
        }
    }

    output
}

// ---------------------------------------------------------------------------
// Substitution tables (Briceno/Goldberg/Wagner 1998 reversal)
// ---------------------------------------------------------------------------

/// Stage 0: 512 entries (9-bit input -> 8-bit output).
static TABLE_0: [u8; 512] = [
    0x66, 0xB1, 0xBA, 0xA2, 0x02, 0x9C, 0x70, 0x4B, 0x37, 0x19, 0x08, 0x0C, 0xFB, 0xC1, 0xF6, 0xBC,
    0x6D, 0xD5, 0x97, 0x35, 0x2A, 0x4F, 0xBF, 0x73, 0xE9, 0xF2, 0xA4, 0xDF, 0xD1, 0x94, 0x6C, 0xA1,
    0xFC, 0x25, 0xF4, 0x2F, 0x40, 0xD3, 0x06, 0xED, 0xB9, 0xA0, 0x8B, 0x71, 0x4C, 0x8A, 0x3B, 0x46,
    0x43, 0x1A, 0x0D, 0x9D, 0x3F, 0xB3, 0xDD, 0x1E, 0xD6, 0x24, 0xA6, 0x45, 0x98, 0x7C, 0xCF, 0x74,
    0xF7, 0xC2, 0x29, 0x54, 0x47, 0x01, 0x31, 0x0E, 0x5F, 0x23, 0xA9, 0x15, 0x60, 0x4E, 0xD7, 0xE1,
    0xB6, 0xF3, 0x1C, 0x5C, 0xC9, 0x76, 0x04, 0x4A, 0xF8, 0x80, 0x11, 0x0B, 0x92, 0x84, 0xF5, 0x30,
    0x95, 0x5A, 0x78, 0x27, 0x57, 0xE6, 0x6A, 0xE8, 0xAF, 0x13, 0x7E, 0xBE, 0xCA, 0x8D, 0x89, 0xB0,
    0xFA, 0x1B, 0x65, 0x28, 0xDB, 0xE3, 0x3A, 0x14, 0x33, 0xB2, 0x62, 0xD8, 0x8C, 0x16, 0x20, 0x79,
    0x3D, 0x67, 0xCB, 0x48, 0x1D, 0x6E, 0x55, 0xD4, 0xB4, 0xCC, 0x96, 0xB7, 0x0F, 0x42, 0xAC, 0xC4,
    0x38, 0xC5, 0x9E, 0x00, 0x64, 0x2D, 0x99, 0x07, 0x90, 0xDE, 0xA3, 0xA7, 0x3C, 0x87, 0xD2, 0xE7,
    0xAE, 0xA5, 0x26, 0xF9, 0xE0, 0x22, 0xDC, 0xE5, 0xD9, 0xD0, 0xF1, 0x44, 0xCE, 0xBD, 0x7D, 0xFF,
    0xEF, 0x36, 0xA8, 0x59, 0x7B, 0x7A, 0x49, 0x91, 0x75, 0xEA, 0x8F, 0x63, 0x81, 0xC8, 0xC0, 0x52,
    0x68, 0xAA, 0x88, 0xEB, 0x5D, 0x51, 0xCD, 0xAD, 0xEC, 0x5E, 0x69, 0x34, 0x2E, 0xE4, 0xC6, 0x05,
    0x39, 0xFE, 0x61, 0x9B, 0x8E, 0x85, 0xC7, 0xAB, 0xBB, 0x32, 0x41, 0xB5, 0x7F, 0x6B, 0x93, 0xE2,
    0xB8, 0xDA, 0x83, 0x21, 0x4D, 0x56, 0x1F, 0x2C, 0x58, 0x3E, 0xEE, 0x12, 0x18, 0x2B, 0x9A, 0x17,
    0x50, 0x9F, 0x86, 0x6F, 0x09, 0x72, 0x03, 0x5B, 0x10, 0x82, 0x53, 0x0A, 0xC3, 0xF0, 0xFD, 0x77,
    0xB1, 0x66, 0xA2, 0xBA, 0x9C, 0x02, 0x4B, 0x70, 0x19, 0x37, 0x0C, 0x08, 0xC1, 0xFB, 0xBC, 0xF6,
    0xD5, 0x6D, 0x35, 0x97, 0x4F, 0x2A, 0x73, 0xBF, 0xF2, 0xE9, 0xDF, 0xA4, 0x94, 0xD1, 0xA1, 0x6C,
    0x25, 0xFC, 0x2F, 0xF4, 0xD3, 0x40, 0xED, 0x06, 0xA0, 0xB9, 0x71, 0x8B, 0x8A, 0x4C, 0x46, 0x3B,
    0x1A, 0x43, 0x9D, 0x0D, 0xB3, 0x3F, 0x1E, 0xDD, 0x24, 0xD6, 0x45, 0xA6, 0x7C, 0x98, 0x74, 0xCF,
    0xC2, 0xF7, 0x54, 0x29, 0x01, 0x47, 0x0E, 0x31, 0x23, 0x5F, 0x15, 0xA9, 0x4E, 0x60, 0xE1, 0xD7,
    0xF3, 0xB6, 0x5C, 0x1C, 0x76, 0xC9, 0x4A, 0x04, 0x80, 0xF8, 0x0B, 0x11, 0x84, 0x92, 0x30, 0xF5,
    0x5A, 0x95, 0x27, 0x78, 0xE6, 0x57, 0xE8, 0x6A, 0x13, 0xAF, 0xBE, 0x7E, 0x8D, 0xCA, 0xB0, 0x89,
    0x1B, 0xFA, 0x28, 0x65, 0xE3, 0xDB, 0x14, 0x3A, 0xB2, 0x33, 0xD8, 0x62, 0x16, 0x8C, 0x79, 0x20,
    0x67, 0x3D, 0x48, 0xCB, 0x6E, 0x1D, 0xD4, 0x55, 0xCC, 0xB4, 0xB7, 0x96, 0x42, 0x0F, 0xC4, 0xAC,
    0xC5, 0x38, 0x00, 0x9E, 0x2D, 0x64, 0x07, 0x99, 0xDE, 0x90, 0xA7, 0xA3, 0x87, 0x3C, 0xE7, 0xD2,
    0xA5, 0xAE, 0xF9, 0x26, 0x22, 0xE0, 0xE5, 0xDC, 0xD0, 0xD9, 0x44, 0xF1, 0xBD, 0xCE, 0xFF, 0x7D,
    0x36, 0xEF, 0x59, 0xA8, 0x7A, 0x7B, 0x91, 0x49, 0xEA, 0x75, 0x63, 0x8F, 0xC8, 0x81, 0x52, 0xC0,
    0xAA, 0x68, 0xEB, 0x88, 0x51, 0x5D, 0xAD, 0xCD, 0x5E, 0xEC, 0x34, 0x69, 0xE4, 0x2E, 0x05, 0xC6,
    0xFE, 0x39, 0x9B, 0x61, 0x85, 0x8E, 0xAB, 0xC7, 0x32, 0xBB, 0xB5, 0x41, 0x6B, 0x7F, 0xE2, 0x93,
    0xDA, 0xB8, 0x21, 0x83, 0x56, 0x4D, 0x2C, 0x1F, 0x3E, 0x58, 0x12, 0xEE, 0x2B, 0x18, 0x17, 0x9A,
    0x9F, 0x50, 0x6F, 0x86, 0x72, 0x09, 0x5B, 0x03, 0x82, 0x10, 0x0A, 0x53, 0xF0, 0xC3, 0x77, 0xFD,
];

/// Stage 1: 256 entries (8-bit input -> 7-bit output).
static TABLE_1: [u8; 256] = [
    0x13, 0x0B, 0x50, 0x72, 0x2B, 0x01, 0x45, 0x5E, 0x27, 0x12, 0x7F, 0x75, 0x61, 0x03, 0x55, 0x2B,
    0x1B, 0x7C, 0x46, 0x53, 0x2F, 0x47, 0x3F, 0x0A, 0x2F, 0x59, 0x4F, 0x04, 0x0E, 0x3B, 0x0B, 0x05,
    0x23, 0x6B, 0x67, 0x44, 0x15, 0x56, 0x24, 0x5B, 0x55, 0x7E, 0x20, 0x32, 0x6D, 0x5E, 0x78, 0x06,
    0x35, 0x4F, 0x1C, 0x2D, 0x63, 0x5F, 0x29, 0x22, 0x58, 0x44, 0x5D, 0x37, 0x6E, 0x7D, 0x69, 0x14,
    0x5A, 0x50, 0x4C, 0x60, 0x17, 0x3C, 0x59, 0x40, 0x79, 0x38, 0x0E, 0x4A, 0x65, 0x08, 0x13, 0x4E,
    0x4C, 0x42, 0x68, 0x2E, 0x6F, 0x32, 0x20, 0x03, 0x27, 0x00, 0x3A, 0x19, 0x5C, 0x16, 0x12, 0x33,
    0x39, 0x41, 0x77, 0x74, 0x16, 0x6D, 0x07, 0x56, 0x3B, 0x5D, 0x3E, 0x6E, 0x4E, 0x63, 0x4D, 0x43,
    0x0C, 0x71, 0x57, 0x62, 0x66, 0x05, 0x58, 0x21, 0x26, 0x38, 0x17, 0x08, 0x4B, 0x2D, 0x0D, 0x4B,
    0x5F, 0x3F, 0x1C, 0x31, 0x7B, 0x78, 0x14, 0x70, 0x2C, 0x1E, 0x0F, 0x62, 0x6A, 0x02, 0x67, 0x1D,
    0x52, 0x6B, 0x2A, 0x7C, 0x18, 0x1E, 0x29, 0x10, 0x6C, 0x64, 0x75, 0x28, 0x49, 0x28, 0x07, 0x72,
    0x52, 0x73, 0x24, 0x70, 0x0C, 0x66, 0x64, 0x54, 0x5C, 0x30, 0x48, 0x61, 0x09, 0x36, 0x37, 0x4A,
    0x71, 0x7B, 0x11, 0x1A, 0x35, 0x3A, 0x04, 0x09, 0x45, 0x7A, 0x15, 0x76, 0x2A, 0x3C, 0x1B, 0x49,
    0x76, 0x7D, 0x22, 0x0F, 0x41, 0x73, 0x54, 0x40, 0x3E, 0x51, 0x46, 0x01, 0x18, 0x6F, 0x79, 0x53,
    0x68, 0x51, 0x31, 0x7F, 0x30, 0x69, 0x1F, 0x0A, 0x06, 0x5B, 0x57, 0x25, 0x10, 0x36, 0x74, 0x7E,
    0x1F, 0x26, 0x0D, 0x00, 0x48, 0x6A, 0x4D, 0x3D, 0x1A, 0x43, 0x2E, 0x1D, 0x60, 0x25, 0x3D, 0x34,
    0x65, 0x11, 0x2C, 0x6C, 0x47, 0x34, 0x42, 0x39, 0x21, 0x33, 0x19, 0x5A, 0x02, 0x77, 0x7A, 0x23,
];

/// Stage 2: 128 entries (7-bit input -> 6-bit output).
static TABLE_2: [u8; 128] = [
    0x34, 0x32, 0x2C, 0x06, 0x15, 0x31, 0x29, 0x3B, 0x27, 0x33, 0x19, 0x20, 0x33, 0x2F, 0x34, 0x2B,
    0x25, 0x04, 0x28, 0x22, 0x3D, 0x0C, 0x1C, 0x04, 0x3A, 0x17, 0x08, 0x0F, 0x0C, 0x16, 0x09, 0x12,
    0x37, 0x0A, 0x21, 0x23, 0x32, 0x01, 0x2B, 0x03, 0x39, 0x0D, 0x3E, 0x0E, 0x07, 0x2A, 0x2C, 0x3B,
    0x3E, 0x39, 0x1B, 0x06, 0x08, 0x1F, 0x1A, 0x36, 0x29, 0x16, 0x2D, 0x14, 0x27, 0x03, 0x10, 0x38,
    0x30, 0x02, 0x15, 0x1C, 0x24, 0x2A, 0x3C, 0x21, 0x22, 0x12, 0x00, 0x0B, 0x18, 0x0A, 0x11, 0x3D,
    0x1D, 0x0E, 0x2D, 0x1A, 0x37, 0x2E, 0x0B, 0x11, 0x36, 0x2E, 0x09, 0x18, 0x1E, 0x3C, 0x20, 0x00,
    0x14, 0x26, 0x02, 0x1E, 0x3A, 0x23, 0x01, 0x10, 0x38, 0x28, 0x17, 0x30, 0x0D, 0x13, 0x13, 0x1B,
    0x1F, 0x35, 0x2F, 0x26, 0x3F, 0x0F, 0x31, 0x05, 0x25, 0x35, 0x19, 0x24, 0x3F, 0x1D, 0x05, 0x07,
];

/// Stage 3: 64 entries (6-bit input -> 5-bit output).
static TABLE_3: [u8; 64] = [
    0x01, 0x05, 0x1D, 0x06, 0x19, 0x01, 0x12, 0x17, 0x11, 0x13, 0x00, 0x09, 0x18, 0x19, 0x06, 0x1F,
    0x1C, 0x14, 0x18, 0x1E, 0x04, 0x1B, 0x03, 0x0D, 0x0F, 0x10, 0x0E, 0x12, 0x04, 0x03, 0x08, 0x09,
    0x14, 0x00, 0x0C, 0x1A, 0x15, 0x08, 0x1C, 0x02, 0x1D, 0x02, 0x0F, 0x07, 0x0B, 0x16, 0x0E, 0x0A,
    0x11, 0x15, 0x0C, 0x1E, 0x1A, 0x1B, 0x10, 0x1F, 0x0B, 0x07, 0x0D, 0x17, 0x0A, 0x05, 0x16, 0x13,
];

/// Stage 4: 32 entries (5-bit input -> 4-bit output).
static TABLE_4: [u8; 32] = [
    0x0F, 0x0C, 0x0A, 0x04, 0x01, 0x0E, 0x0B, 0x07, 0x05, 0x00, 0x0E, 0x07, 0x01, 0x02, 0x0D, 0x08,
    0x0A, 0x03, 0x04, 0x09, 0x06, 0x00, 0x03, 0x02, 0x05, 0x06, 0x08, 0x09, 0x0B, 0x0D, 0x0F, 0x0C,
];

// ---------------------------------------------------------------------------
// COMP128v2/v3 substitution tables (Tamas Jos / skelsec / Osmocom)
// ---------------------------------------------------------------------------

/// V2/V3 table 0: 256 entries (8-bit input -> 8-bit output).
///
/// Values transcribed from Osmocom libosmocore `comp128v23.c`.
static TABLE_V23_0: [u8; 256] = [
    197, 235, 60, 151, 98, 96, 3, 100, 248, 118, 42, 117, 172, 211, 181, 203, 61, 126, 156, 87,
    149, 224, 55, 132, 186, 63, 238, 255, 85, 83, 152, 33, 160, 184, 210, 219, 159, 11, 180, 194,
    130, 212, 147, 5, 215, 92, 27, 46, 113, 187, 52, 25, 185, 79, 221, 48, 70, 31, 101, 15, 195,
    201, 50, 222, 137, 233, 229, 106, 122, 183, 178, 177, 144, 207, 234, 182, 37, 254, 227, 231,
    54, 209, 133, 65, 202, 69, 237, 220, 189, 146, 120, 68, 21, 125, 38, 30, 2, 155, 53, 196, 174,
    176, 51, 246, 167, 76, 110, 20, 82, 121, 103, 112, 56, 173, 49, 217, 252, 0, 114, 228, 123, 12,
    93, 161, 253, 232, 240, 175, 67, 128, 22, 158, 89, 18, 77, 109, 190, 17, 62, 4, 153, 163, 59,
    145, 138, 7, 74, 205, 10, 162, 80, 45, 104, 111, 150, 214, 154, 28, 191, 169, 213, 88, 193,
    198, 200, 245, 39, 164, 124, 84, 78, 1, 188, 170, 23, 86, 226, 141, 32, 6, 131, 127, 199, 40,
    135, 16, 57, 71, 91, 225, 168, 242, 206, 97, 166, 44, 14, 90, 236, 239, 230, 244, 223, 108,
    102, 119, 148, 251, 29, 216, 8, 9, 249, 208, 24, 105, 94, 34, 64, 95, 115, 72, 134, 204, 43,
    247, 243, 218, 47, 58, 73, 107, 241, 179, 116, 66, 36, 143, 81, 250, 139, 19, 13, 142, 140,
    129, 192, 99, 171, 157, 136, 41, 75, 35, 165, 26,
];

/// V2/V3 table 1: 256 entries (8-bit input -> 8-bit output).
///
/// Values transcribed from Osmocom libosmocore `comp128v23.c`.
static TABLE_V23_1: [u8; 256] = [
    170, 42, 95, 141, 109, 30, 71, 89, 26, 147, 231, 205, 239, 212, 124, 129, 216, 79, 15, 185,
    153, 14, 251, 162, 0, 241, 172, 197, 43, 10, 194, 235, 6, 20, 72, 45, 143, 104, 161, 119, 41,
    136, 38, 189, 135, 25, 93, 18, 224, 171, 252, 195, 63, 19, 58, 165, 23, 55, 133, 254, 214, 144,
    220, 178, 156, 52, 110, 225, 97, 183, 140, 39, 53, 88, 219, 167, 16, 198, 62, 222, 76, 139,
    175, 94, 51, 134, 115, 22, 67, 1, 249, 217, 3, 5, 232, 138, 31, 56, 116, 163, 70, 128, 234,
    132, 229, 184, 244, 13, 34, 73, 233, 154, 179, 131, 215, 236, 142, 223, 27, 57, 246, 108, 211,
    8, 253, 85, 66, 245, 193, 78, 190, 4, 17, 7, 150, 127, 152, 213, 37, 186, 2, 243, 46, 169, 68,
    101, 60, 174, 208, 158, 176, 69, 238, 191, 90, 83, 166, 125, 77, 59, 21, 92, 49, 151, 168, 99,
    9, 50, 146, 113, 117, 228, 65, 230, 40, 82, 54, 237, 227, 102, 28, 36, 107, 24, 44, 126, 206,
    201, 61, 114, 164, 207, 181, 29, 91, 64, 221, 255, 48, 155, 192, 111, 180, 210, 182, 247, 203,
    148, 209, 98, 173, 11, 75, 123, 250, 118, 32, 47, 240, 202, 74, 177, 100, 80, 196, 33, 248, 86,
    157, 137, 120, 130, 84, 204, 122, 81, 242, 188, 200, 149, 226, 218, 160, 187, 106, 35, 87, 105,
    96, 145, 199, 159, 12, 121, 103, 112,
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ki(bytes: [u8; 16]) -> Secret<[u8; 16]> {
        Secret::new(bytes)
    }

    // -- Cross-validation vectors (generated by compiling reference gsm_algo()) --

    #[test]
    fn swsim_vector_all_zero() {
        let r = comp128(&ki([0x00; 16]), &[0x00; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0x09, 0xE5, 0x5D, 0xA4]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x17, 0x47, 0x57, 0x78, 0x3D, 0xC4, 0x04, 0x00]
        );
    }

    #[test]
    fn swsim_vector_ab_cd() {
        let r = comp128(&ki([0xAB; 16]), &[0xCD; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0x43, 0xFA, 0xD2, 0x08]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x8F, 0x6E, 0x14, 0x88, 0x18, 0x39, 0xD4, 0x00]
        );
    }

    #[test]
    fn swsim_vector_doctest() {
        let k = ki([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x07,
        ]);
        let rand = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let r = comp128(&k, &rand);
        assert_eq!(*r.signed_response.as_bytes(), [0x46, 0xF0, 0x2D, 0xBA]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0xE9, 0xB7, 0xD0, 0x45, 0xEC, 0x87, 0x1C, 0x00]
        );
    }

    #[test]
    fn swsim_vector_11_22() {
        let r = comp128(&ki([0x11; 16]), &[0x22; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0x67, 0x5B, 0x74, 0xF6]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x7E, 0xFC, 0x50, 0xA3, 0xED, 0x03, 0x68, 0x00]
        );
    }

    #[test]
    fn swsim_vector_all_ff() {
        let r = comp128(&ki([0xFF; 16]), &[0xFF; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0xFE, 0x65, 0xFD, 0x52]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x8E, 0xD6, 0x68, 0x0A, 0x9B, 0x77, 0xC4, 0x00]
        );
    }

    #[test]
    fn swsim_vector_sequential() {
        #[allow(clippy::cast_possible_truncation)]
        let k = ki(core::array::from_fn(|i| i as u8));
        #[allow(clippy::cast_possible_truncation)]
        let rand: [u8; 16] = core::array::from_fn(|i| (i + 16) as u8);
        let r = comp128(&k, &rand);
        assert_eq!(*r.signed_response.as_bytes(), [0x37, 0x38, 0xF8, 0x82]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x39, 0xCD, 0xA2, 0xDB, 0xBA, 0x4A, 0x7C, 0x00]
        );
    }

    // -- Structural invariants --

    #[test]
    fn kc_byte7_always_zero() {
        let r = comp128(&ki([0xAB; 16]), &[0xCD; 16]);
        assert_eq!(r.cipher_key.declassify_ref()[7], 0x00);
    }

    #[test]
    fn kc_byte6_bottom_bits_zero() {
        let r = comp128(&ki([0xAB; 16]), &[0xCD; 16]);
        assert_eq!(r.cipher_key.declassify_ref()[6] & 0x03, 0x00);
    }

    #[test]
    fn deterministic() {
        let k = ki([0x11; 16]);
        let rand = [0x22; 16];
        let r1 = comp128(&k, &rand);
        let r2 = comp128(&k, &rand);
        assert_eq!(r1.signed_response, r2.signed_response);
        assert_eq!(
            r1.cipher_key.declassify_ref(),
            r2.cipher_key.declassify_ref()
        );
    }

    #[test]
    fn different_rand_different_output() {
        let k = ki([0x11; 16]);
        let r1 = comp128(&k, &[0x00; 16]);
        let r2 = comp128(&k, &[0x01; 16]);
        assert!(
            r1.signed_response != r2.signed_response
                || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref()
        );
    }

    #[test]
    fn different_ki_different_output() {
        let rand = [0x33; 16];
        let r1 = comp128(&ki([0x00; 16]), &rand);
        let r2 = comp128(&ki([0x01; 16]), &rand);
        assert!(
            r1.signed_response != r2.signed_response
                || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref()
        );
    }

    #[test]
    fn zero_input_not_zero_output() {
        let r = comp128(&ki([0u8; 16]), &[0u8; 16]);
        assert!(
            *r.signed_response.as_bytes() != [0u8; 4] || *r.cipher_key.declassify_ref() != [0u8; 8],
            "zero input must not produce all-zero output"
        );
    }

    #[test]
    fn output_not_all_ff() {
        let r = comp128(&ki([0xFF; 16]), &[0xFF; 16]);
        let all_ff = *r.signed_response.as_bytes() == [0xFF; 4]
            && *r.cipher_key.declassify_ref() == [0xFF; 8];
        assert!(!all_ff, "all-FF input must not produce all-FF output");
    }

    // -- COMP128v2/v3 cross-validation vectors (Osmocom comp128v23.c) --

    #[test]
    fn v3_vector_all_zero() {
        let r = comp128v3(&ki([0x00; 16]), &[0x00; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0xB2, 0x4C, 0x2D, 0xAC]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x7C, 0x82, 0xC3, 0xEC, 0x44, 0x95, 0x35, 0x61]
        );
    }

    #[test]
    fn v3_vector_ab_cd() {
        let r = comp128v3(&ki([0xAB; 16]), &[0xCD; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0xCC, 0xC1, 0xBD, 0x74]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x1E, 0x85, 0x1D, 0xE6, 0x76, 0xF4, 0xF7, 0xB3]
        );
    }

    #[test]
    fn v3_vector_doctest() {
        let k = ki([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x07,
        ]);
        let rand = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let r = comp128v3(&k, &rand);
        assert_eq!(*r.signed_response.as_bytes(), [0x54, 0xA0, 0xC1, 0x93]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x88, 0xF1, 0x3E, 0x4C, 0x97, 0xC0, 0x31, 0x49]
        );
    }

    #[test]
    fn v3_vector_11_22() {
        let r = comp128v3(&ki([0x11; 16]), &[0x22; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0x4C, 0x4E, 0x54, 0x32]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0xF0, 0x32, 0xA8, 0x6E, 0x4C, 0x45, 0xE6, 0x32]
        );
    }

    #[test]
    fn v3_vector_all_ff() {
        let r = comp128v3(&ki([0xFF; 16]), &[0xFF; 16]);
        assert_eq!(*r.signed_response.as_bytes(), [0xED, 0x20, 0x1E, 0x4B]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x82, 0x4B, 0x86, 0x0B, 0x02, 0x2B, 0x87, 0x55]
        );
    }

    #[test]
    fn v3_vector_sequential() {
        #[allow(clippy::cast_possible_truncation)]
        let k = ki(core::array::from_fn(|i| i as u8));
        #[allow(clippy::cast_possible_truncation)]
        let rand: [u8; 16] = core::array::from_fn(|i| (i + 16) as u8);
        let r = comp128v3(&k, &rand);
        assert_eq!(*r.signed_response.as_bytes(), [0x6F, 0x67, 0x6F, 0x06]);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x6D, 0x8A, 0xFA, 0x70, 0x72, 0x3F, 0xF3, 0x78]
        );
    }

    #[test]
    fn v2_zeroes_kc_bottom_10_bits() {
        let r = comp128v2(&ki([0xAB; 16]), &[0xCD; 16]);
        // SRES identical to V3
        assert_eq!(*r.signed_response.as_bytes(), [0xCC, 0xC1, 0xBD, 0x74]);
        // Kc: last 10 bits zeroed
        assert_eq!(r.cipher_key.declassify_ref()[7], 0x00);
        assert_eq!(r.cipher_key.declassify_ref()[6] & 0x03, 0x00);
        assert_eq!(
            *r.cipher_key.declassify_ref(),
            [0x1E, 0x85, 0x1D, 0xE6, 0x76, 0xF4, 0xF4, 0x00]
        );
    }

    #[test]
    fn v2_all_vectors_kc_bottom_10_zeroed() {
        // Verify the V2 constraint holds across all test vectors.
        let cases: [([u8; 16], [u8; 16]); 4] = [
            ([0x00; 16], [0x00; 16]),
            ([0xAB; 16], [0xCD; 16]),
            ([0x11; 16], [0x22; 16]),
            ([0xFF; 16], [0xFF; 16]),
        ];
        for (k, rand) in &cases {
            let r = comp128v2(&ki(*k), rand);
            assert_eq!(r.cipher_key.declassify_ref()[7], 0x00, "kc[7] must be 0x00");
            assert_eq!(
                r.cipher_key.declassify_ref()[6] & 0x03,
                0x00,
                "kc[6] bottom 2 bits must be 0"
            );
        }
    }

    #[test]
    fn v2_v3_sres_identical() {
        let k = ki([0x11; 16]);
        let rand = [0x22; 16];
        let r2 = comp128v2(&k, &rand);
        let r3 = comp128v3(&k, &rand);
        assert_eq!(
            r2.signed_response, r3.signed_response,
            "V2 and V3 SRES must be identical"
        );
    }

    #[test]
    fn versioned_dispatch_matches_direct() {
        let k = ki([0xAB; 16]);
        let rand = [0xCD; 16];
        let r1 = comp128(&k, &rand);
        let rv1 = comp128_versioned(&k, &rand, Comp128Version::V1);
        assert_eq!(r1.signed_response, rv1.signed_response);
        assert_eq!(
            r1.cipher_key.declassify_ref(),
            rv1.cipher_key.declassify_ref()
        );

        let r2 = comp128v2(&k, &rand);
        let rv2 = comp128_versioned(&k, &rand, Comp128Version::V2);
        assert_eq!(r2.signed_response, rv2.signed_response);
        assert_eq!(
            r2.cipher_key.declassify_ref(),
            rv2.cipher_key.declassify_ref()
        );

        let r3 = comp128v3(&k, &rand);
        let rv3 = comp128_versioned(&k, &rand, Comp128Version::V3);
        assert_eq!(r3.signed_response, rv3.signed_response);
        assert_eq!(
            r3.cipher_key.declassify_ref(),
            rv3.cipher_key.declassify_ref()
        );
    }

    #[test]
    fn v1_v3_produce_different_output() {
        let k = ki([0x11; 16]);
        let rand = [0x22; 16];
        let r1 = comp128(&k, &rand);
        let r3 = comp128v3(&k, &rand);
        assert_ne!(
            r1.signed_response, r3.signed_response,
            "V1 and V3 must differ"
        );
    }

    // -- ct_select_n correctness --

    #[test]
    fn ct_select_n_all_tables_all_indices() {
        // Verify ct_select_n returns the correct value for every valid index
        // in all 5 substitution tables.
        let tables: [&[u8]; 5] = [&TABLE_0, &TABLE_1, &TABLE_2, &TABLE_3, &TABLE_4];
        for (j, table) in tables.iter().enumerate() {
            for i in 0..table.len() {
                assert_eq!(
                    ct_select_n(table, i),
                    table[i],
                    "ct_select_n(TABLE_{j}, {i}) mismatch"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(not(miri))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Different RAND with same Ki must produce different output.
        // Collision probability is astronomically low for a good PRF.
        #[test]
        fn different_rand_different_output(
            ki_bytes in any::<[u8; 16]>(),
            rand1 in any::<[u8; 16]>(),
            rand2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(rand1 != rand2);
            let ki = Secret::new(ki_bytes);
            let r1 = comp128(&ki, &rand1);
            let r2 = comp128(&ki, &rand2);
            prop_assert!(
                r1.signed_response != r2.signed_response || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref(),
                "same Ki with different RAND must produce different outputs"
            );
        }
    }

    proptest! {
        // Kc byte 7 is always 0x00 for any input.
        #[test]
        fn kc_byte7_zero(ki_bytes in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let r = comp128(&Secret::new(ki_bytes), &rand);
            prop_assert_eq!(r.cipher_key.declassify_ref()[7], 0x00);
        }
    }

    proptest! {
        // Kc byte 6 bottom 2 bits are always zero for any input.
        #[test]
        fn kc_byte6_bottom_bits(ki_bytes in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let r = comp128(&Secret::new(ki_bytes), &rand);
            prop_assert_eq!(r.cipher_key.declassify_ref()[6] & 0x03, 0x00);
        }
    }

    proptest! {
        // Flipping any single bit in RAND changes the output.
        // (This is a weak non-linearity test, not guaranteed but empirically holds.)
        #[test]
        fn single_rand_bit_flip_changes_output(
            ki_bytes in any::<[u8; 16]>(),
            rand in any::<[u8; 16]>(),
            bit_idx in 0usize..128,
        ) {
            let ki = Secret::new(ki_bytes);
            let r1 = comp128(&ki, &rand);
            let mut rand2 = rand;
            rand2[bit_idx / 8] ^= 1 << (bit_idx % 8);
            let r2 = comp128(&ki, &rand2);
            prop_assert!(
                r1.signed_response != r2.signed_response || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref(),
                "flipping bit {} in RAND should change output", bit_idx
            );
        }
    }

    proptest! {
        // Different Ki with same RAND must produce different output.
        #[test]
        fn different_ki_different_output(
            ki1_bytes in any::<[u8; 16]>(),
            ki2_bytes in any::<[u8; 16]>(),
            rand in any::<[u8; 16]>(),
        ) {
            prop_assume!(ki1_bytes != ki2_bytes);
            let r1 = comp128(&Secret::new(ki1_bytes), &rand);
            let r2 = comp128(&Secret::new(ki2_bytes), &rand);
            prop_assert!(
                r1.signed_response != r2.signed_response || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref(),
                "different Ki must produce different outputs"
            );
        }
    }

    // -- COMP128v3 property tests --

    proptest! {
        #[test]
        fn v3_different_rand_different_output(
            ki_bytes in any::<[u8; 16]>(),
            rand1 in any::<[u8; 16]>(),
            rand2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(rand1 != rand2);
            let ki = Secret::new(ki_bytes);
            let r1 = comp128v3(&ki, &rand1);
            let r2 = comp128v3(&ki, &rand2);
            prop_assert!(
                r1.signed_response != r2.signed_response || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref(),
                "V3: same Ki with different RAND must produce different outputs"
            );
        }
    }

    proptest! {
        #[test]
        fn v2_kc_bottom_10_bits_zero(ki_bytes in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let r = comp128v2(&Secret::new(ki_bytes), &rand);
            prop_assert_eq!(r.cipher_key.declassify_ref()[7], 0x00, "V2 kc[7] must be 0x00");
            prop_assert_eq!(r.cipher_key.declassify_ref()[6] & 0x03, 0x00, "V2 kc[6] bottom 2 bits must be 0");
        }
    }

    proptest! {
        #[test]
        fn v2_v3_sres_always_identical(ki_bytes in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let ki = Secret::new(ki_bytes);
            let r2 = comp128v2(&ki, &rand);
            let r3 = comp128v3(&ki, &rand);
            prop_assert_eq!(r2.signed_response, r3.signed_response, "V2 and V3 SRES must always match");
        }
    }

    proptest! {
        #[test]
        fn v3_different_ki_different_output(
            ki1_bytes in any::<[u8; 16]>(),
            ki2_bytes in any::<[u8; 16]>(),
            rand in any::<[u8; 16]>(),
        ) {
            prop_assume!(ki1_bytes != ki2_bytes);
            let r1 = comp128v3(&Secret::new(ki1_bytes), &rand);
            let r2 = comp128v3(&Secret::new(ki2_bytes), &rand);
            prop_assert!(
                r1.signed_response != r2.signed_response || r1.cipher_key.declassify_ref() != r2.cipher_key.declassify_ref(),
                "V3: different Ki must produce different outputs"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    #[test]
    fn test_comp128_ct() {
        let fixed_ki = [0xABu8; 16];

        let outcome = ct_test(
            42,
            |rng| {
                // Class 0: fixed Ki, random RAND
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut rand);
                (fixed_ki, rand)
            },
            |rng| {
                // Class 1: random Ki, random RAND
                let mut ki = [0u8; 16];
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut ki);
                rng.fill_bytes(&mut rand);
                (ki, rand)
            },
            |(ki, rand)| {
                let r = comp128(&Secret::new(*ki), rand);
                core::hint::black_box(r);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// COMP128 timing must be independent of RAND content with fixed Ki.
    ///
    /// Class 0: fixed RAND (values near modulus boundaries: 0xFF bytes
    ///          that produce intermediates near 512, 256, etc.).
    /// Class 1: random RAND.
    ///
    /// Before the bitmask fix, `% modulus` on values near the boundary
    /// could exhibit variable-time division paths. The `& (modulus - 1)` fix
    /// makes this a single AND instruction regardless of value.
    #[test]
    fn test_comp128_rand_independence_ct() {
        let fixed_ki = [0xABu8; 16];

        // Fixed RAND with boundary-probing values: bytes near 0xFF produce
        // intermediates (x[m] + 2*x[n]) near the modulus boundary.
        let boundary_rand: [u8; 16] = [
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];

        let outcome = ct_test(
            0xC128_0002,
            |rng| {
                // Class 0: fixed boundary RAND, burn RNG for symmetry.
                let mut discard = [0u8; 16];
                rng.fill_bytes(&mut discard);
                (fixed_ki, boundary_rand)
            },
            |rng| {
                // Class 1: random RAND.
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut rand);
                (fixed_ki, rand)
            },
            |(ki, rand)| {
                let r = comp128(&Secret::new(*ki), rand);
                core::hint::black_box(r);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// COMP128v3 timing must be independent of Ki content.
    #[test]
    fn test_comp128v3_ct() {
        let fixed_ki = [0xABu8; 16];

        let outcome = ct_test(
            0xC128_0003,
            |rng| {
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut rand);
                (fixed_ki, rand)
            },
            |rng| {
                let mut ki = [0u8; 16];
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut ki);
                rng.fill_bytes(&mut rand);
                (ki, rand)
            },
            |(ki, rand)| {
                let r = comp128v3(&Secret::new(*ki), rand);
                core::hint::black_box(r);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// COMP128v3 timing must be independent of RAND content.
    #[test]
    fn test_comp128v3_rand_independence_ct() {
        let fixed_ki = [0xABu8; 16];
        let boundary_rand: [u8; 16] = [
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];

        let outcome = ct_test(
            0xC128_0004,
            |rng| {
                let mut discard = [0u8; 16];
                rng.fill_bytes(&mut discard);
                (fixed_ki, boundary_rand)
            },
            |rng| {
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut rand);
                (fixed_ki, rand)
            },
            |(ki, rand)| {
                let r = comp128v3(&Secret::new(*ki), rand);
                core::hint::black_box(r);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
