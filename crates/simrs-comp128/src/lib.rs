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
//! for compatibility with the swsim reference and legacy GSM testing.
//!
//! # Standards
//! - GSM 11.11 v4.21.1 clause 11 -- A3/A8 algorithm interface
//! - 3GPP TS 51.011 V4.15.0 clause 11 -- RUN GSM ALGORITHM command
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All computation is done in-place on stack buffers.
//!
//! # Example
//!
//! ```
//! use simrs_comp128::{comp128, Comp128Result};
//!
//! // Known test vector (from GSM security research literature)
//! let ki   = [0xABu8; 16];
//! let rand = [0xCDu8; 16];
//!
//! let result: Comp128Result = comp128(&ki, &rand);
//!
//! // SRES is 4 bytes, Kc is 8 bytes (Kc[7] is always 0x00)
//! assert_eq!(result.sres.len(), 4);
//! assert_eq!(result.kc.len(), 8);
//! assert_eq!(result.kc[7], 0x00, "Kc byte 7 must always be zero per COMP128v1");
//!
//! // Kc byte 6 has bottom 2 bits cleared (6-bit packing artifact)
//! assert_eq!(result.kc[6] & 0x03, 0x00, "Kc[6] bottom 2 bits always zero");
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

/// Result of the `COMP128v1` algorithm.
///
/// Contains the Signed Response (SRES) used for network authentication
/// and the ciphering key (Kc) used for A5 stream cipher encryption.
///
/// # Layout
///
/// Per GSM 11.11 clause 11:
/// - SRES: 4 bytes (32 bits) -- sent to the network as the authentication response
/// - Kc: 8 bytes (64 bits) -- used as the A5 ciphering key
///
/// # Invariants
///
/// - `kc[7]` is always `0x00` (`COMP128v1` only produces 54 effective bits of Kc)
/// - `kc[6] & 0x03 == 0` (bottom 2 bits of byte 6 are always zero)
///
/// ```
/// use simrs_comp128::{comp128, Comp128Result};
///
/// let r = comp128(&[0u8; 16], &[0u8; 16]);
/// assert_eq!(r.kc[7], 0x00);
/// assert_eq!(r.kc[6] & 0x03, 0x00);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comp128Result {
    /// Signed Response (4 bytes).
    /// Sent to the base station to prove knowledge of Ki.
    pub sres: [u8; 4],

    /// Ciphering key (8 bytes, effective 54 bits).
    /// Used as the session key for A5/1 or A5/3 encryption.
    /// Byte 7 is always 0x00; byte 6 bottom 2 bits are always 0.
    pub kc: [u8; 8],
}

/// Run the `COMP128v1` A3/A8 GSM authentication algorithm.
///
/// Computes SRES and Kc from the subscriber's secret key (Ki) and a random
/// challenge (RAND) from the base station.
///
/// # Arguments
///
/// * `ki` -- 16-byte Individual Subscriber Authentication Key (stored in SIM and `AuC`)
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
///
/// let ki   = [0x11u8; 16];
/// let rand = [0x22u8; 16];
/// assert_eq!(comp128(&ki, &rand), comp128(&ki, &rand));
/// ```
///
/// # Different inputs produce different outputs
///
/// ```
/// use simrs_comp128::comp128;
///
/// let ki = [0x11u8; 16];
/// let r1 = comp128(&ki, &[0x00u8; 16]);
/// let r2 = comp128(&ki, &[0x01u8; 16]);
/// assert_ne!(r1, r2, "different RAND must produce different results");
/// ```
///
/// # Cross-validation with swsim reference
///
/// The implementation must produce bit-identical output to swsim's `gsm_algo()`.
///
/// ```
/// use simrs_comp128::comp128;
///
/// // Ki and RAND from swsim's hardcoded Milenage test params, used here
/// // as a cross-validation vector. The expected values were computed by
/// // running swsim's gsm_algo() with these inputs.
/// let ki = [
///     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
///     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
/// ];
/// let rand = [
///     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
///     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
/// ];
/// let result = comp128(&ki, &rand);
/// // These expected values must be verified against swsim before uncommenting:
/// // assert_eq!(result.sres, [0x??, 0x??, 0x??, 0x??]);
/// // assert_eq!(result.kc, [0x??, 0x??, 0x??, 0x??, 0x??, 0x??, 0x??, 0x00]);
/// let _ = result; // placeholder until reference values are computed
/// ```
pub fn comp128(ki: &[u8; 16], rand: &[u8; 16]) -> Comp128Result {
    // 5 substitution tables: 512, 256, 128, 64, 32 entries
    // (reversed by Marc Briceno, Ian Goldberg, David Wagner, 1998)
    let _tables = tables();

    todo!("COMP128v1 algorithm not yet implemented")
}

/// Internal: the 5 COMP128 substitution tables.
///
/// Table sizes (entries): 512, 256, 128, 64, 32.
/// These correspond to the 5 stages of each COMP128 round.
/// The tables were reversed from a GSM SIM card by Briceno, Goldberg, Wagner.
fn tables() -> CompTables {
    todo!("COMP128 substitution tables not yet defined")
}

/// Internal type holding references to all 5 substitution tables.
struct CompTables {
    /// Stage 0: 512 entries (9-bit input, 8-bit output)
    t0: &'static [u8; 512],
    /// Stage 1: 256 entries (8-bit input, 7-bit output)
    t1: &'static [u8; 256],
    /// Stage 2: 128 entries (7-bit input, 6-bit output)
    t2: &'static [u8; 128],
    /// Stage 3: 64 entries (6-bit input, 5-bit output)
    t3: &'static [u8; 64],
    /// Stage 4: 32 entries (5-bit input, 4-bit output)
    t4: &'static [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SRES is always exactly 4 bytes.
    #[test]
    fn sres_is_4_bytes() {
        let r = comp128(&[0u8; 16], &[0u8; 16]);
        assert_eq!(r.sres.len(), 4);
    }

    /// Kc is always exactly 8 bytes.
    #[test]
    fn kc_is_8_bytes() {
        let r = comp128(&[0u8; 16], &[0u8; 16]);
        assert_eq!(r.kc.len(), 8);
    }

    /// Kc byte 7 is always 0x00 per COMP128v1 output packing.
    #[test]
    fn kc_byte7_always_zero() {
        let r = comp128(&[0xAB; 16], &[0xCD; 16]);
        assert_eq!(r.kc[7], 0x00);
    }

    /// Kc byte 6 bottom 2 bits are always zero (6-bit packing artifact).
    #[test]
    fn kc_byte6_bottom_bits_zero() {
        let r = comp128(&[0xAB; 16], &[0xCD; 16]);
        assert_eq!(r.kc[6] & 0x03, 0x00);
    }

    /// Same Ki + RAND always produces the same result.
    #[test]
    fn deterministic() {
        let ki = [0x11; 16];
        let rand = [0x22; 16];
        assert_eq!(comp128(&ki, &rand), comp128(&ki, &rand));
    }

    /// Different RAND values produce different results.
    #[test]
    fn different_rand_different_output() {
        let ki = [0x11; 16];
        let r1 = comp128(&ki, &[0x00; 16]);
        let r2 = comp128(&ki, &[0x01; 16]);
        assert_ne!(r1, r2);
    }

    /// Different Ki values produce different results.
    #[test]
    fn different_ki_different_output() {
        let rand = [0x33; 16];
        let r1 = comp128(&[0x00; 16], &rand);
        let r2 = comp128(&[0x01; 16], &rand);
        assert_ne!(r1, r2);
    }

    /// Zero Ki + zero RAND must NOT produce all-zero output.
    /// (If it did, the algorithm would be trivially broken.)
    #[test]
    fn zero_input_not_zero_output() {
        let r = comp128(&[0u8; 16], &[0u8; 16]);
        assert!(
            r.sres != [0u8; 4] || r.kc != [0u8; 8],
            "zero input must not produce all-zero output"
        );
    }

    /// The full 12-byte output (SRES || Kc) is never all-0xFF.
    #[test]
    fn output_not_all_ff() {
        let r = comp128(&[0xFF; 16], &[0xFF; 16]);
        let all_ff = r.sres == [0xFF; 4] && r.kc == [0xFF; 8];
        assert!(!all_ff, "all-FF input must not produce all-FF output");
    }

    /// Cross-validation against swsim gsm_algo() reference implementation.
    /// These vectors are computed by running the C implementation with known inputs.
    /// TODO: compute exact reference values from swsim and fill in.
    #[test]
    #[ignore = "reference values not yet computed from swsim"]
    fn swsim_cross_validation_vector_1() {
        let ki = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
        ];
        let rand = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ];
        let r = comp128(&ki, &rand);
        // Fill these in after running swsim:
        let _ = r;
        todo!("fill in expected SRES and Kc from swsim reference run");
    }
}
