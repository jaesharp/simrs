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
//! use simrs_comp128::{comp128, Comp128Result};
//! use simrs_secret::Secret;
//!
//! // Cross-validated against reference implementation
//! let ki   = Secret::new([0xABu8; 16]);
//! let rand = [0xCDu8; 16];
//!
//! let result: Comp128Result = comp128(&ki, &rand);
//!
//! assert_eq!(*result.sres.as_bytes(), [0x43, 0xFA, 0xD2, 0x08]);
//! assert_eq!(*result.kc.declassify_ref(), [0x8F, 0x6E, 0x14, 0x88, 0x18, 0x39, 0xD4, 0x00]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::ct_select_n;
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
    #[inline] pub const fn new(raw: [u8; 4]) -> Self { Self(raw) }
    /// Access the raw bytes.
    #[inline] pub const fn as_bytes(&self) -> &[u8; 4] { &self.0 }
}
impl From<[u8; 4]> for SignedResponse { fn from(raw: [u8; 4]) -> Self { Self(raw) } }

/// GSM abbreviation for [`SignedResponse`].
///
/// The specs (GSM 11.11 / ETSI TS 131 102) use "SRES" (Signed Response).
/// We prefer `SignedResponse` for self-documenting code.
#[deprecated(note = "GSM SRES (TS 131 102) -- prefer SignedResponse")]
pub type Sres = SignedResponse;

/// Result of the `COMP128v1` algorithm.
///
/// Contains the Signed Response (SRES) used for network authentication
/// and the ciphering key (Kc) used for A5 stream cipher encryption.
///
/// # Layout
///
/// Per [ETSI TS 151 011 V4.15.0 clause 11](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A327%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C689%5D):
/// - SRES: 4 bytes (32 bits) -- sent to the network as the authentication response
/// - Kc: 8 bytes (64 bits) -- used as the A5 ciphering key
///
/// # Invariants
///
/// - `kc[7]` is always `0x00` (COMP128v1 only produces 54 effective bits of Kc)
/// - `kc[6] & 0x03 == 0` (bottom 2 bits of byte 6 are always zero)
///
/// ```
/// use simrs_comp128::{comp128, Comp128Result};
/// use simrs_secret::Secret;
///
/// let r = comp128(&Secret::new([0u8; 16]), &[0u8; 16]);
/// assert_eq!(r.kc.declassify_ref()[7], 0x00);
/// assert_eq!(r.kc.declassify_ref()[6] & 0x03, 0x00);
/// ```
#[derive(Clone, Copy)]
pub struct Comp128Result {
    /// Signed Response (4 bytes).
    /// Sent to the base station to prove knowledge of Ki.
    pub sres: SignedResponse,

    /// Ciphering key (8 bytes, effective 54 bits).
    /// Used as the session key for A5/1 or A5/3 encryption.
    /// Byte 7 is always 0x00; byte 6 bottom 2 bits are always 0.
    pub kc: Secret<[u8; 8]>,
}

impl core::fmt::Debug for Comp128Result {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Comp128Result")
            .field("sres", &self.sres.as_bytes())
            .field("kc", &Redact(self.kc.declassify_ref()))
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
/// [`Comp128Result`] containing the 4-byte SRES and 8-byte Kc.
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
/// assert_eq!(r1.sres.as_bytes(), r2.sres.as_bytes());
/// assert_eq!(r1.kc.declassify_ref(), r2.kc.declassify_ref());
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
///     r1.sres.as_bytes() != r2.sres.as_bytes() || r1.kc.declassify_ref() != r2.kc.declassify_ref(),
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
/// assert_eq!(*result.sres.as_bytes(), [0x46, 0xF0, 0x2D, 0xBA]);
/// assert_eq!(*result.kc.declassify_ref(), [0xE9, 0xB7, 0xD0, 0x45, 0xEC, 0x87, 0x1C, 0x00]);
/// ```
#[allow(clippy::cast_possible_truncation)] // values bounded by table size / bit masks
#[allow(clippy::many_single_char_names)]  // matches C reference variable names
pub fn comp128(ki: &Secret<[u8; 16]>, rand: &[u8; 16]) -> Comp128Result {
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
            let groups = 1u32 << j;       // number of butterfly groups
            let half = 1u32 << (4 - j);   // half-size of each group
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

    Comp128Result { sres: SignedResponse::new(sres), kc: Secret::new(kc) }
}

// ---------------------------------------------------------------------------
// Substitution tables (Briceno/Goldberg/Wagner 1998 reversal)
// ---------------------------------------------------------------------------

/// Stage 0: 512 entries (9-bit input -> 8-bit output).
static TABLE_0: [u8; 512] = [
    0x66, 0xB1, 0xBA, 0xA2, 0x02, 0x9C, 0x70, 0x4B, 0x37, 0x19, 0x08, 0x0C,
    0xFB, 0xC1, 0xF6, 0xBC, 0x6D, 0xD5, 0x97, 0x35, 0x2A, 0x4F, 0xBF, 0x73,
    0xE9, 0xF2, 0xA4, 0xDF, 0xD1, 0x94, 0x6C, 0xA1, 0xFC, 0x25, 0xF4, 0x2F,
    0x40, 0xD3, 0x06, 0xED, 0xB9, 0xA0, 0x8B, 0x71, 0x4C, 0x8A, 0x3B, 0x46,
    0x43, 0x1A, 0x0D, 0x9D, 0x3F, 0xB3, 0xDD, 0x1E, 0xD6, 0x24, 0xA6, 0x45,
    0x98, 0x7C, 0xCF, 0x74, 0xF7, 0xC2, 0x29, 0x54, 0x47, 0x01, 0x31, 0x0E,
    0x5F, 0x23, 0xA9, 0x15, 0x60, 0x4E, 0xD7, 0xE1, 0xB6, 0xF3, 0x1C, 0x5C,
    0xC9, 0x76, 0x04, 0x4A, 0xF8, 0x80, 0x11, 0x0B, 0x92, 0x84, 0xF5, 0x30,
    0x95, 0x5A, 0x78, 0x27, 0x57, 0xE6, 0x6A, 0xE8, 0xAF, 0x13, 0x7E, 0xBE,
    0xCA, 0x8D, 0x89, 0xB0, 0xFA, 0x1B, 0x65, 0x28, 0xDB, 0xE3, 0x3A, 0x14,
    0x33, 0xB2, 0x62, 0xD8, 0x8C, 0x16, 0x20, 0x79, 0x3D, 0x67, 0xCB, 0x48,
    0x1D, 0x6E, 0x55, 0xD4, 0xB4, 0xCC, 0x96, 0xB7, 0x0F, 0x42, 0xAC, 0xC4,
    0x38, 0xC5, 0x9E, 0x00, 0x64, 0x2D, 0x99, 0x07, 0x90, 0xDE, 0xA3, 0xA7,
    0x3C, 0x87, 0xD2, 0xE7, 0xAE, 0xA5, 0x26, 0xF9, 0xE0, 0x22, 0xDC, 0xE5,
    0xD9, 0xD0, 0xF1, 0x44, 0xCE, 0xBD, 0x7D, 0xFF, 0xEF, 0x36, 0xA8, 0x59,
    0x7B, 0x7A, 0x49, 0x91, 0x75, 0xEA, 0x8F, 0x63, 0x81, 0xC8, 0xC0, 0x52,
    0x68, 0xAA, 0x88, 0xEB, 0x5D, 0x51, 0xCD, 0xAD, 0xEC, 0x5E, 0x69, 0x34,
    0x2E, 0xE4, 0xC6, 0x05, 0x39, 0xFE, 0x61, 0x9B, 0x8E, 0x85, 0xC7, 0xAB,
    0xBB, 0x32, 0x41, 0xB5, 0x7F, 0x6B, 0x93, 0xE2, 0xB8, 0xDA, 0x83, 0x21,
    0x4D, 0x56, 0x1F, 0x2C, 0x58, 0x3E, 0xEE, 0x12, 0x18, 0x2B, 0x9A, 0x17,
    0x50, 0x9F, 0x86, 0x6F, 0x09, 0x72, 0x03, 0x5B, 0x10, 0x82, 0x53, 0x0A,
    0xC3, 0xF0, 0xFD, 0x77, 0xB1, 0x66, 0xA2, 0xBA, 0x9C, 0x02, 0x4B, 0x70,
    0x19, 0x37, 0x0C, 0x08, 0xC1, 0xFB, 0xBC, 0xF6, 0xD5, 0x6D, 0x35, 0x97,
    0x4F, 0x2A, 0x73, 0xBF, 0xF2, 0xE9, 0xDF, 0xA4, 0x94, 0xD1, 0xA1, 0x6C,
    0x25, 0xFC, 0x2F, 0xF4, 0xD3, 0x40, 0xED, 0x06, 0xA0, 0xB9, 0x71, 0x8B,
    0x8A, 0x4C, 0x46, 0x3B, 0x1A, 0x43, 0x9D, 0x0D, 0xB3, 0x3F, 0x1E, 0xDD,
    0x24, 0xD6, 0x45, 0xA6, 0x7C, 0x98, 0x74, 0xCF, 0xC2, 0xF7, 0x54, 0x29,
    0x01, 0x47, 0x0E, 0x31, 0x23, 0x5F, 0x15, 0xA9, 0x4E, 0x60, 0xE1, 0xD7,
    0xF3, 0xB6, 0x5C, 0x1C, 0x76, 0xC9, 0x4A, 0x04, 0x80, 0xF8, 0x0B, 0x11,
    0x84, 0x92, 0x30, 0xF5, 0x5A, 0x95, 0x27, 0x78, 0xE6, 0x57, 0xE8, 0x6A,
    0x13, 0xAF, 0xBE, 0x7E, 0x8D, 0xCA, 0xB0, 0x89, 0x1B, 0xFA, 0x28, 0x65,
    0xE3, 0xDB, 0x14, 0x3A, 0xB2, 0x33, 0xD8, 0x62, 0x16, 0x8C, 0x79, 0x20,
    0x67, 0x3D, 0x48, 0xCB, 0x6E, 0x1D, 0xD4, 0x55, 0xCC, 0xB4, 0xB7, 0x96,
    0x42, 0x0F, 0xC4, 0xAC, 0xC5, 0x38, 0x00, 0x9E, 0x2D, 0x64, 0x07, 0x99,
    0xDE, 0x90, 0xA7, 0xA3, 0x87, 0x3C, 0xE7, 0xD2, 0xA5, 0xAE, 0xF9, 0x26,
    0x22, 0xE0, 0xE5, 0xDC, 0xD0, 0xD9, 0x44, 0xF1, 0xBD, 0xCE, 0xFF, 0x7D,
    0x36, 0xEF, 0x59, 0xA8, 0x7A, 0x7B, 0x91, 0x49, 0xEA, 0x75, 0x63, 0x8F,
    0xC8, 0x81, 0x52, 0xC0, 0xAA, 0x68, 0xEB, 0x88, 0x51, 0x5D, 0xAD, 0xCD,
    0x5E, 0xEC, 0x34, 0x69, 0xE4, 0x2E, 0x05, 0xC6, 0xFE, 0x39, 0x9B, 0x61,
    0x85, 0x8E, 0xAB, 0xC7, 0x32, 0xBB, 0xB5, 0x41, 0x6B, 0x7F, 0xE2, 0x93,
    0xDA, 0xB8, 0x21, 0x83, 0x56, 0x4D, 0x2C, 0x1F, 0x3E, 0x58, 0x12, 0xEE,
    0x2B, 0x18, 0x17, 0x9A, 0x9F, 0x50, 0x6F, 0x86, 0x72, 0x09, 0x5B, 0x03,
    0x82, 0x10, 0x0A, 0x53, 0xF0, 0xC3, 0x77, 0xFD,
];

/// Stage 1: 256 entries (8-bit input -> 7-bit output).
static TABLE_1: [u8; 256] = [
    0x13, 0x0B, 0x50, 0x72, 0x2B, 0x01, 0x45, 0x5E, 0x27, 0x12, 0x7F, 0x75,
    0x61, 0x03, 0x55, 0x2B, 0x1B, 0x7C, 0x46, 0x53, 0x2F, 0x47, 0x3F, 0x0A,
    0x2F, 0x59, 0x4F, 0x04, 0x0E, 0x3B, 0x0B, 0x05, 0x23, 0x6B, 0x67, 0x44,
    0x15, 0x56, 0x24, 0x5B, 0x55, 0x7E, 0x20, 0x32, 0x6D, 0x5E, 0x78, 0x06,
    0x35, 0x4F, 0x1C, 0x2D, 0x63, 0x5F, 0x29, 0x22, 0x58, 0x44, 0x5D, 0x37,
    0x6E, 0x7D, 0x69, 0x14, 0x5A, 0x50, 0x4C, 0x60, 0x17, 0x3C, 0x59, 0x40,
    0x79, 0x38, 0x0E, 0x4A, 0x65, 0x08, 0x13, 0x4E, 0x4C, 0x42, 0x68, 0x2E,
    0x6F, 0x32, 0x20, 0x03, 0x27, 0x00, 0x3A, 0x19, 0x5C, 0x16, 0x12, 0x33,
    0x39, 0x41, 0x77, 0x74, 0x16, 0x6D, 0x07, 0x56, 0x3B, 0x5D, 0x3E, 0x6E,
    0x4E, 0x63, 0x4D, 0x43, 0x0C, 0x71, 0x57, 0x62, 0x66, 0x05, 0x58, 0x21,
    0x26, 0x38, 0x17, 0x08, 0x4B, 0x2D, 0x0D, 0x4B, 0x5F, 0x3F, 0x1C, 0x31,
    0x7B, 0x78, 0x14, 0x70, 0x2C, 0x1E, 0x0F, 0x62, 0x6A, 0x02, 0x67, 0x1D,
    0x52, 0x6B, 0x2A, 0x7C, 0x18, 0x1E, 0x29, 0x10, 0x6C, 0x64, 0x75, 0x28,
    0x49, 0x28, 0x07, 0x72, 0x52, 0x73, 0x24, 0x70, 0x0C, 0x66, 0x64, 0x54,
    0x5C, 0x30, 0x48, 0x61, 0x09, 0x36, 0x37, 0x4A, 0x71, 0x7B, 0x11, 0x1A,
    0x35, 0x3A, 0x04, 0x09, 0x45, 0x7A, 0x15, 0x76, 0x2A, 0x3C, 0x1B, 0x49,
    0x76, 0x7D, 0x22, 0x0F, 0x41, 0x73, 0x54, 0x40, 0x3E, 0x51, 0x46, 0x01,
    0x18, 0x6F, 0x79, 0x53, 0x68, 0x51, 0x31, 0x7F, 0x30, 0x69, 0x1F, 0x0A,
    0x06, 0x5B, 0x57, 0x25, 0x10, 0x36, 0x74, 0x7E, 0x1F, 0x26, 0x0D, 0x00,
    0x48, 0x6A, 0x4D, 0x3D, 0x1A, 0x43, 0x2E, 0x1D, 0x60, 0x25, 0x3D, 0x34,
    0x65, 0x11, 0x2C, 0x6C, 0x47, 0x34, 0x42, 0x39, 0x21, 0x33, 0x19, 0x5A,
    0x02, 0x77, 0x7A, 0x23,
];

/// Stage 2: 128 entries (7-bit input -> 6-bit output).
static TABLE_2: [u8; 128] = [
    0x34, 0x32, 0x2C, 0x06, 0x15, 0x31, 0x29, 0x3B, 0x27, 0x33, 0x19, 0x20,
    0x33, 0x2F, 0x34, 0x2B, 0x25, 0x04, 0x28, 0x22, 0x3D, 0x0C, 0x1C, 0x04,
    0x3A, 0x17, 0x08, 0x0F, 0x0C, 0x16, 0x09, 0x12, 0x37, 0x0A, 0x21, 0x23,
    0x32, 0x01, 0x2B, 0x03, 0x39, 0x0D, 0x3E, 0x0E, 0x07, 0x2A, 0x2C, 0x3B,
    0x3E, 0x39, 0x1B, 0x06, 0x08, 0x1F, 0x1A, 0x36, 0x29, 0x16, 0x2D, 0x14,
    0x27, 0x03, 0x10, 0x38, 0x30, 0x02, 0x15, 0x1C, 0x24, 0x2A, 0x3C, 0x21,
    0x22, 0x12, 0x00, 0x0B, 0x18, 0x0A, 0x11, 0x3D, 0x1D, 0x0E, 0x2D, 0x1A,
    0x37, 0x2E, 0x0B, 0x11, 0x36, 0x2E, 0x09, 0x18, 0x1E, 0x3C, 0x20, 0x00,
    0x14, 0x26, 0x02, 0x1E, 0x3A, 0x23, 0x01, 0x10, 0x38, 0x28, 0x17, 0x30,
    0x0D, 0x13, 0x13, 0x1B, 0x1F, 0x35, 0x2F, 0x26, 0x3F, 0x0F, 0x31, 0x05,
    0x25, 0x35, 0x19, 0x24, 0x3F, 0x1D, 0x05, 0x07,
];

/// Stage 3: 64 entries (6-bit input -> 5-bit output).
static TABLE_3: [u8; 64] = [
    0x01, 0x05, 0x1D, 0x06, 0x19, 0x01, 0x12, 0x17, 0x11, 0x13, 0x00,
    0x09, 0x18, 0x19, 0x06, 0x1F, 0x1C, 0x14, 0x18, 0x1E, 0x04, 0x1B,
    0x03, 0x0D, 0x0F, 0x10, 0x0E, 0x12, 0x04, 0x03, 0x08, 0x09, 0x14,
    0x00, 0x0C, 0x1A, 0x15, 0x08, 0x1C, 0x02, 0x1D, 0x02, 0x0F, 0x07,
    0x0B, 0x16, 0x0E, 0x0A, 0x11, 0x15, 0x0C, 0x1E, 0x1A, 0x1B, 0x10,
    0x1F, 0x0B, 0x07, 0x0D, 0x17, 0x0A, 0x05, 0x16, 0x13,
];

/// Stage 4: 32 entries (5-bit input -> 4-bit output).
static TABLE_4: [u8; 32] = [
    0x0F, 0x0C, 0x0A, 0x04, 0x01, 0x0E, 0x0B, 0x07, 0x05, 0x00, 0x0E,
    0x07, 0x01, 0x02, 0x0D, 0x08, 0x0A, 0x03, 0x04, 0x09, 0x06, 0x00,
    0x03, 0x02, 0x05, 0x06, 0x08, 0x09, 0x0B, 0x0D, 0x0F, 0x0C,
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
        assert_eq!(*r.sres.as_bytes(), [0x09, 0xE5, 0x5D, 0xA4]);
        assert_eq!(*r.kc.declassify_ref(), [0x17, 0x47, 0x57, 0x78, 0x3D, 0xC4, 0x04, 0x00]);
    }

    #[test]
    fn swsim_vector_ab_cd() {
        let r = comp128(&ki([0xAB; 16]), &[0xCD; 16]);
        assert_eq!(*r.sres.as_bytes(), [0x43, 0xFA, 0xD2, 0x08]);
        assert_eq!(*r.kc.declassify_ref(), [0x8F, 0x6E, 0x14, 0x88, 0x18, 0x39, 0xD4, 0x00]);
    }

    #[test]
    fn swsim_vector_doctest() {
        let k = ki([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
        ]);
        let rand = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ];
        let r = comp128(&k, &rand);
        assert_eq!(*r.sres.as_bytes(), [0x46, 0xF0, 0x2D, 0xBA]);
        assert_eq!(*r.kc.declassify_ref(), [0xE9, 0xB7, 0xD0, 0x45, 0xEC, 0x87, 0x1C, 0x00]);
    }

    #[test]
    fn swsim_vector_11_22() {
        let r = comp128(&ki([0x11; 16]), &[0x22; 16]);
        assert_eq!(*r.sres.as_bytes(), [0x67, 0x5B, 0x74, 0xF6]);
        assert_eq!(*r.kc.declassify_ref(), [0x7E, 0xFC, 0x50, 0xA3, 0xED, 0x03, 0x68, 0x00]);
    }

    #[test]
    fn swsim_vector_all_ff() {
        let r = comp128(&ki([0xFF; 16]), &[0xFF; 16]);
        assert_eq!(*r.sres.as_bytes(), [0xFE, 0x65, 0xFD, 0x52]);
        assert_eq!(*r.kc.declassify_ref(), [0x8E, 0xD6, 0x68, 0x0A, 0x9B, 0x77, 0xC4, 0x00]);
    }

    #[test]
    fn swsim_vector_sequential() {
        #[allow(clippy::cast_possible_truncation)]
        let k = ki(core::array::from_fn(|i| i as u8));
        #[allow(clippy::cast_possible_truncation)]
        let rand: [u8; 16] = core::array::from_fn(|i| (i + 16) as u8);
        let r = comp128(&k, &rand);
        assert_eq!(*r.sres.as_bytes(), [0x37, 0x38, 0xF8, 0x82]);
        assert_eq!(*r.kc.declassify_ref(), [0x39, 0xCD, 0xA2, 0xDB, 0xBA, 0x4A, 0x7C, 0x00]);
    }

    // -- Structural invariants --

    #[test]
    fn kc_byte7_always_zero() {
        let r = comp128(&ki([0xAB; 16]), &[0xCD; 16]);
        assert_eq!(r.kc.declassify_ref()[7], 0x00);
    }

    #[test]
    fn kc_byte6_bottom_bits_zero() {
        let r = comp128(&ki([0xAB; 16]), &[0xCD; 16]);
        assert_eq!(r.kc.declassify_ref()[6] & 0x03, 0x00);
    }

    #[test]
    fn deterministic() {
        let k = ki([0x11; 16]);
        let rand = [0x22; 16];
        let r1 = comp128(&k, &rand);
        let r2 = comp128(&k, &rand);
        assert_eq!(r1.sres, r2.sres);
        assert_eq!(r1.kc.declassify_ref(), r2.kc.declassify_ref());
    }

    #[test]
    fn different_rand_different_output() {
        let k = ki([0x11; 16]);
        let r1 = comp128(&k, &[0x00; 16]);
        let r2 = comp128(&k, &[0x01; 16]);
        assert!(r1.sres != r2.sres || r1.kc.declassify_ref() != r2.kc.declassify_ref());
    }

    #[test]
    fn different_ki_different_output() {
        let rand = [0x33; 16];
        let r1 = comp128(&ki([0x00; 16]), &rand);
        let r2 = comp128(&ki([0x01; 16]), &rand);
        assert!(r1.sres != r2.sres || r1.kc.declassify_ref() != r2.kc.declassify_ref());
    }

    #[test]
    fn zero_input_not_zero_output() {
        let r = comp128(&ki([0u8; 16]), &[0u8; 16]);
        assert!(
            *r.sres.as_bytes() != [0u8; 4] || *r.kc.declassify_ref() != [0u8; 8],
            "zero input must not produce all-zero output"
        );
    }

    #[test]
    fn output_not_all_ff() {
        let r = comp128(&ki([0xFF; 16]), &[0xFF; 16]);
        let all_ff = *r.sres.as_bytes() == [0xFF; 4] && *r.kc.declassify_ref() == [0xFF; 8];
        assert!(!all_ff, "all-FF input must not produce all-FF output");
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
                r1.sres != r2.sres || r1.kc.declassify_ref() != r2.kc.declassify_ref(),
                "same Ki with different RAND must produce different outputs"
            );
        }
    }

    proptest! {
        // Kc byte 7 is always 0x00 for any input.
        #[test]
        fn kc_byte7_zero(ki_bytes in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let r = comp128(&Secret::new(ki_bytes), &rand);
            prop_assert_eq!(r.kc.declassify_ref()[7], 0x00);
        }
    }

    proptest! {
        // Kc byte 6 bottom 2 bits are always zero for any input.
        #[test]
        fn kc_byte6_bottom_bits(ki_bytes in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let r = comp128(&Secret::new(ki_bytes), &rand);
            prop_assert_eq!(r.kc.declassify_ref()[6] & 0x03, 0x00);
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
                r1.sres != r2.sres || r1.kc.declassify_ref() != r2.kc.declassify_ref(),
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
                r1.sres != r2.sres || r1.kc.declassify_ref() != r2.kc.declassify_ref(),
                "different Ki must produce different outputs"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (DudeCT)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use simrs_consttime_validation::{ct_test, assert_no_timing_leak};

    #[test]
    fn test_comp128_ct() {
        let fixed_ki = Secret::new([0xABu8; 16]);

        let outcome = ct_test(42,
            |rng| {
                // Class 0: fixed Ki, random RAND
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut rand);
                (fixed_ki, rand)
            },
            |rng| {
                // Class 1: random Ki, random RAND
                let mut ki_bytes = [0u8; 16];
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut ki_bytes);
                rng.fill_bytes(&mut rand);
                (Secret::new(ki_bytes), rand)
            },
            |(ki, rand)| {
                let r = comp128(ki, rand);
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
        let fixed_ki = Secret::new([0xABu8; 16]);

        // Fixed RAND with boundary-probing values: bytes near 0xFF produce
        // intermediates (x[m] + 2*x[n]) near the modulus boundary.
        let boundary_rand: [u8; 16] = [
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        let outcome = ct_test(0xC128_0002,
            |rng| {
                // Class 0: fixed boundary RAND, burn RNG for symmetry.
                let mut _discard = [0u8; 16];
                rng.fill_bytes(&mut _discard);
                (fixed_ki, boundary_rand)
            },
            |rng| {
                // Class 1: random RAND.
                let mut rand = [0u8; 16];
                rng.fill_bytes(&mut rand);
                (fixed_ki, rand)
            },
            |(ki, rand)| {
                let r = comp128(ki, rand);
                core::hint::black_box(r);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
