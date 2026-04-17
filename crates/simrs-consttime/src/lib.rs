//! Constant-time primitives for cryptographic operations.
//!
//! Provides building blocks that execute in data-independent time, preventing
//! cache-timing and branch-prediction side-channel attacks. All functions in
//! this crate are designed so that their execution time and memory access
//! patterns do not depend on the values of secret data.
//!
//! # Core Type
//!
//! [`CtBool`] is an opaque constant-time boolean that prevents accidental
//! branching. All comparison and zero-test operations return `CtBool` instead
//! of `bool`. Call [`.into_bool()`](CtBool::into_bool) explicitly when a
//! branch is intentional.
//!
//! # Traits
//!
//! | Trait | Purpose |
//! |-------|---------|
//! | [`CtEq`] | Constant-time equality (returns [`CtBool`]) |
//! | [`CtSelect`] | Conditional select / cmov |
//! | [`CtSwap`] | Conditional swap / cswap |
//! | [`CtZero`] | Zero test |
//!
//! Implementations are provided for `u8`, `u64`, `[u8; N]`, `[u64; N]`,
//! and tuples up to arity 5.
//!
//! # Free Functions
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`ct_select`] | Lookup in a 256-entry `[u8; 256]` table |
//! | [`ct_select_n`] | Lookup in a variable-size `&[u8]` table |
//! | [`ct_xtime`] | Branchless GF(2^8) multiplication by {02} |
//! | [`ct_eq`] | Constant-time byte-slice equality |
//! | [`ct_is_zero_u8`] | Constant-time zero test for `u8` |
//! | [`ct_is_zero_u64`] | Constant-time zero test for `u64` |
//! | [`ct_mux_u8`] | Constant-time conditional select for `u8` |
//! | [`ct_mux_u64`] | Constant-time conditional select for `u64` |
//! | [`ct_swap_u64`] | Constant-time conditional swap for `u64` |
//!
//! # Derive Macro
//!
//! The [`CtEq`] trait can be derived for structs with byte-array fields:
//!
//! ```
//! use simrs_consttime::CtEq;
//!
//! #[derive(CtEq)]
//! struct Mac([u8; 8]);
//!
//! let a = Mac([0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3]);
//! let b = Mac([0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3]);
//! assert!(a.ct_eq(&b).into_bool());
//! ```
//!
//! # Constant-Time Guarantees
//!
//! These functions prevent the following side-channel vectors:
//! - **Cache timing**: Table lookups read ALL entries regardless of index,
//!   so cache line access patterns are independent of secret values.
//! - **Branch prediction**: No data-dependent branches. All conditionals
//!   are replaced with branchless arithmetic (masks, wrapping ops).
//! - **Timing oracles**: Comparison functions examine all bytes regardless
//!   of where mismatches occur, preventing MAC verification timing leaks.
//!
//! Note: these are software-level defenses. Hardware-level attacks (power
//! analysis, EM emanation) require additional countermeasures.
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All operations are performed on stack values.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

// Allow the derive macro's generated code to reference `simrs_consttime::`
// paths when used within this crate's own tests.
#[cfg(test)]
extern crate self as simrs_consttime;

mod ctbool;
mod traits;

// Re-export derive macros so users only need `simrs-consttime` as a dep.
pub use simrs_consttime_macros::{CtEq, CtSelect, CtSwap};

// Re-export core types and traits.
pub use ctbool::CtBool;
pub use traits::{
    CtEq, CtSelect, CtSwap, CtZero, ct_is_zero_u8, ct_is_zero_u64, ct_mux_u8, ct_mux_u64,
    ct_swap_u64,
};

// ---------------------------------------------------------------------------
// Table Lookups
// ---------------------------------------------------------------------------

/// Constant-time lookup in a 256-entry byte table.
///
/// Reads ALL 256 entries and masks the result, so the memory access pattern
/// is independent of `index`. Prevents cache-timing side-channel attacks
/// on S-box substitution.
///
/// # How It Works
///
/// For each table index `i` in 0..256:
/// 1. Compute `d = i XOR index` (zero only when `i == index`)
/// 2. Compute a mask: `0xFF` if `d == 0`, `0x00` otherwise
/// 3. OR the masked table entry into the result
///
/// The mask computation uses wrapping arithmetic on `u8`:
/// - `d | d.wrapping_neg()` has bit 7 set for all nonzero `d`
/// - Right-shifting by 7 gives 1 (nonzero) or 0 (zero)
/// - Subtracting 1 inverts: `0xFF` for match, `0x00` for non-match
///
/// # Example
///
/// ```
/// use simrs_consttime::ct_select;
///
/// let table: [u8; 256] = core::array::from_fn(|i| i as u8);
/// assert_eq!(ct_select(&table, 0), 0);
/// assert_eq!(ct_select(&table, 42), 42);
/// assert_eq!(ct_select(&table, 255), 255);
/// ```
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub const fn ct_select(table: &[u8; 256], index: u8) -> u8 {
    let mut result = 0u8;
    let mut i = 0u32;
    while i < 256 {
        let d = (i as u8) ^ index;
        // d == 0 when i == index.
        // (d | d.wrapping_neg()) >> 7 is 1 if d != 0, 0 if d == 0.
        // Subtracting 1 gives 0xFF if d == 0 (match), 0x00 otherwise.
        let mask = ((d | d.wrapping_neg()) >> 7).wrapping_sub(1);
        result |= table[i as usize] & mask;
        i += 1;
    }
    result
}

/// Constant-time lookup in a variable-size byte table.
///
/// Reads ALL `table.len()` entries and masks the result, making the memory
/// access pattern independent of `index`. Suitable for tables of any size
/// (e.g., COMP128's 512/256/128/64/32-entry substitution tables).
///
/// Uses `usize` arithmetic for the mask computation to handle table sizes
/// larger than 256.
///
/// # Example
///
/// ```
/// use simrs_consttime::ct_select_n;
///
/// let table: [u8; 512] = core::array::from_fn(|i| (i & 0xFF) as u8);
/// assert_eq!(ct_select_n(&table, 0), 0);
/// assert_eq!(ct_select_n(&table, 511), 255);
/// ```
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub fn ct_select_n(table: &[u8], index: usize) -> u8 {
    let mut result = 0u8;
    for (i, &entry) in table.iter().enumerate() {
        let d = i ^ index;
        // For nonzero d, (d | d.wrapping_neg()) has the high bit set.
        // For d == 0, (d | d.wrapping_neg()) == 0.
        let nonzero = (d | d.wrapping_neg()) >> (usize::BITS - 1);
        // nonzero is 1 if d != 0, 0 if d == 0.
        // Subtracting 1 gives 0xFF if match (d == 0), 0x00 otherwise.
        let mask = (nonzero as u8).wrapping_sub(1);
        result |= entry & mask;
    }
    result
}

// ---------------------------------------------------------------------------
// GF(2^8) Arithmetic
// ---------------------------------------------------------------------------

/// Branchless multiplication by {02} in GF(2^8).
///
/// Uses the irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11B`),
/// which is the AES field polynomial ([NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 4.2.1).
///
/// Equivalent to a left-shift with conditional XOR of `0x1B`, but computed
/// without branches or table lookups.
///
/// # How It Works
///
/// - If the high bit of `b` is set: `result = (b << 1) XOR 0x1B`
/// - If the high bit is clear: `result = b << 1`
///
/// The conditional is replaced by: `mask = 0xFF` if bit 7 is set,
/// `0x00` otherwise, then `result = (b << 1) XOR (mask AND 0x1B)`.
///
/// # Example
///
/// ```
/// use simrs_consttime::ct_xtime;
///
/// // {02} * {57} = {AE} ([NIST FIPS 197](../../../docs/specs/nist/fips-197/NIST.FIPS.197.pdf) clause 4.2.1 example)
/// assert_eq!(ct_xtime(0x57), 0xAE);
/// // {02} * {AE} = {47} (high bit set, reduction applies)
/// assert_eq!(ct_xtime(0xAE), 0x47);
/// ```
#[inline]
pub const fn ct_xtime(b: u8) -> u8 {
    // mask = 0xFF if high bit set, 0x00 otherwise (branchless)
    let mask = ((b >> 7) & 1).wrapping_neg();
    (b << 1) ^ (mask & 0x1B)
}

// ---------------------------------------------------------------------------
// Byte-slice comparison (kept as free function for &[u8] slices)
// ---------------------------------------------------------------------------

/// Constant-time byte-slice equality comparison.
///
/// Returns [`CtBool::TRUE`] if `a` and `b` have the same length and
/// identical contents. Always examines every byte regardless of where
/// mismatches occur, preventing timing side-channel attacks on MAC
/// verification.
///
/// For fixed-size arrays, prefer the [`CtEq`] trait:
/// `a.ct_eq(&b)`.
///
/// # Example
///
/// ```
/// use simrs_consttime::ct_eq;
///
/// let a = [0x4A, 0x9F, 0xFA, 0xC3];
/// let b = [0x4A, 0x9F, 0xFA, 0xC3];
/// let c = [0x4A, 0x9F, 0xFA, 0xC4];
///
/// assert!(ct_eq(&a, &b).into_bool());
/// assert!(!ct_eq(&a, &c).into_bool());
/// assert!(!ct_eq(&a, &[0x4A, 0x9F]).into_bool()); // different lengths
/// ```
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> CtBool {
    if a.len() != b.len() {
        return CtBool::FALSE;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    ct_is_zero_u8(diff)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // -- ct_select --

    #[test]
    fn ct_select_identity_table() {
        let table: [u8; 256] = core::array::from_fn(|i| i as u8);
        for i in 0u16..256 {
            let b = i as u8;
            assert_eq!(ct_select(&table, b), b, "ct_select identity at {b}");
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn ct_select_inverted_table() {
        let table: [u8; 256] = core::array::from_fn(|i| 255 - i as u8);
        for i in 0u16..256 {
            let b = i as u8;
            assert_eq!(ct_select(&table, b), 255 - b, "ct_select inverted at {b}");
        }
    }

    #[test]
    fn ct_select_single_nonzero() {
        for pos in [0u8, 1, 127, 128, 254, 255] {
            let mut table = [0u8; 256];
            table[pos as usize] = 0xAB;

            for i in 0u16..256 {
                let b = i as u8;
                let expected = if b == pos { 0xAB } else { 0x00 };
                assert_eq!(ct_select(&table, b), expected, "pos={pos}, index={b}");
            }
        }
    }

    // -- ct_select_n --

    #[test]
    fn ct_select_n_size_512() {
        let table: [u8; 512] = core::array::from_fn(|i| (i & 0xFF) as u8);
        for i in 0..512 {
            assert_eq!(ct_select_n(&table, i), table[i], "ct_select_n(512) at {i}");
        }
    }

    #[test]
    fn ct_select_n_size_32() {
        let table: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        for i in 0..32 {
            assert_eq!(ct_select_n(&table, i), table[i], "ct_select_n(32) at {i}");
        }
    }

    #[test]
    fn ct_select_n_size_128() {
        let table: [u8; 128] = core::array::from_fn(|i| (i ^ 0x55) as u8);
        for i in 0..128 {
            assert_eq!(ct_select_n(&table, i), table[i], "ct_select_n(128) at {i}");
        }
    }

    #[test]
    fn ct_select_n_size_1() {
        let table = [0x42u8];
        assert_eq!(ct_select_n(&table, 0), 0x42);
    }

    // -- ct_xtime --

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn ct_xtime_exhaustive() {
        for i in 0u16..256 {
            let b = i as u8;
            let expected = (b << 1) ^ (if b & 0x80 != 0 { 0x1B } else { 0 });
            assert_eq!(ct_xtime(b), expected, "ct_xtime({b:#04X}) mismatch");
        }
    }

    #[test]
    fn ct_xtime_fips197_example() {
        assert_eq!(ct_xtime(0x57), 0xAE);
    }

    // -- ct_eq (free function) --

    #[test]
    fn ct_eq_equal() {
        let a = [0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
        assert!(ct_eq(&a, &a).into_bool());
    }

    #[test]
    fn ct_eq_single_bit_diff() {
        let a = [0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
        for i in 0..a.len() {
            for bit in 0..8u32 {
                let mut b = a;
                b[i] ^= 1 << bit;
                assert!(
                    !ct_eq(&a, &b).into_bool(),
                    "must detect bit {bit} diff at byte {i}"
                );
            }
        }
    }

    #[test]
    fn ct_eq_different_lengths() {
        assert!(!ct_eq(&[1, 2, 3], &[1, 2]).into_bool());
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]).into_bool());
    }

    #[test]
    fn ct_eq_empty() {
        let a: [u8; 0] = [];
        assert!(ct_eq(&a, &a).into_bool());
    }

    #[test]
    fn ct_eq_all_zero() {
        assert!(ct_eq(&[0u8; 16], &[0u8; 16]).into_bool());
    }

    #[test]
    fn ct_eq_all_ff() {
        assert!(ct_eq(&[0xFF; 16], &[0xFF; 16]).into_bool());
    }

    #[test]
    fn ct_eq_last_byte_differs() {
        let a = [0x00; 16];
        let mut b = [0x00; 16];
        b[15] = 0x01;
        assert!(!ct_eq(&a, &b).into_bool());
    }

    // -- CtEq trait (via [u8; N] impl) --

    #[test]
    fn ct_eq_trait_array_8() {
        let a: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let b: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let c: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 9];
        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
    }

    #[test]
    fn ct_eq_trait_array_16() {
        let a = [0xABu8; 16];
        let b = [0xABu8; 16];
        assert!(a.ct_eq(&b).into_bool());
    }

    // -- Derive CtEq integration --

    #[derive(CtEq)]
    struct TestMac([u8; 8]);

    #[test]
    fn derive_ct_eq_tuple_struct() {
        let a = TestMac([0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3]);
        let b = TestMac([0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3]);
        let c = TestMac([0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB4]);
        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
    }

    #[derive(CtEq)]
    struct TestAuth {
        mac: [u8; 8],
        res: [u8; 8],
    }

    #[test]
    fn derive_ct_eq_named_struct() {
        let a = TestAuth {
            mac: [1, 2, 3, 4, 5, 6, 7, 8],
            res: [9, 10, 11, 12, 13, 14, 15, 16],
        };
        let b = TestAuth {
            mac: [1, 2, 3, 4, 5, 6, 7, 8],
            res: [9, 10, 11, 12, 13, 14, 15, 16],
        };
        let c = TestAuth {
            mac: [1, 2, 3, 4, 5, 6, 7, 8],
            res: [9, 10, 11, 12, 13, 14, 15, 0],
        };
        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
    }

    #[derive(CtEq)]
    struct TestMixed {
        tag: u8,
        data: [u8; 4],
    }

    #[test]
    fn derive_ct_eq_mixed_fields() {
        let a = TestMixed {
            tag: 0xAB,
            data: [1, 2, 3, 4],
        };
        let b = TestMixed {
            tag: 0xAB,
            data: [1, 2, 3, 4],
        };
        let c = TestMixed {
            tag: 0xAC,
            data: [1, 2, 3, 4],
        };
        let d = TestMixed {
            tag: 0xAB,
            data: [1, 2, 3, 5],
        };
        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
        assert!(!a.ct_eq(&d).into_bool());
    }

    #[derive(CtEq)]
    struct TestUnit;

    #[test]
    fn derive_ct_eq_unit_struct() {
        let a = TestUnit;
        assert!(a.ct_eq(&TestUnit).into_bool());
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(not(miri))]
#[allow(clippy::cast_possible_truncation)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ct_select_matches_direct(index in 0u8..=255) {
            let table: [u8; 256] = core::array::from_fn(|i| i as u8);
            prop_assert_eq!(ct_select(&table, index), index);
        }
    }

    proptest! {
        #[test]
        fn ct_eq_reflexive(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert!(ct_eq(&data, &data).into_bool());
        }
    }

    proptest! {
        #[test]
        fn ct_eq_detects_single_flip(
            data in proptest::collection::vec(any::<u8>(), 1..64),
            flip_pos in 0usize..63,
            flip_bit in 0u32..8,
        ) {
            prop_assume!(flip_pos < data.len());
            let mut modified = data.clone();
            modified[flip_pos] ^= 1 << flip_bit;
            prop_assert!(!ct_eq(&data, &modified).into_bool());
        }
    }

    proptest! {
        #[test]
        fn ct_xtime_matches_formula(b in any::<u8>()) {
            let expected = (b << 1) ^ (if b & 0x80 != 0 { 0x1B } else { 0 });
            prop_assert_eq!(ct_xtime(b), expected);
        }
    }

    proptest! {
        #[test]
        fn ct_is_zero_correct(x in any::<u8>()) {
            prop_assert_eq!(ct_is_zero_u8(x).into_bool(), x == 0);
        }
    }

    proptest! {
        #[test]
        fn ct_mux_correct(a in any::<u8>(), b in any::<u8>()) {
            prop_assert_eq!(ct_mux_u8(CtBool::TRUE, a, b), a);
            prop_assert_eq!(ct_mux_u8(CtBool::FALSE, a, b), b);
        }
    }
}

// ---------------------------------------------------------------------------
// Timing validation tests (tacet-backed)
//
// These tests use statistical timing analysis to detect data-dependent
// timing behavior. They MUST be run in release mode (`--release` or
// opt-level >= 2) to avoid false positives from unoptimized code paths.
//
// Run with:
//   cargo test -p simrs-consttime --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
#[allow(clippy::cast_possible_truncation)]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{Rng, assert_no_timing_leak, ct_test};

    #[test]
    fn ct_select_timing() {
        let table: [u8; 256] = core::array::from_fn(|i| i as u8);
        let outcome = ct_test(
            1,
            |_rng| 0u8,
            Rng::next_u8,
            |&index| {
                black_box(ct_select(&table, index));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn ct_select_n_timing() {
        let table: [u8; 512] = core::array::from_fn(|i| (i & 0xFF) as u8);
        let outcome = ct_test(
            2,
            |_rng| 0usize,
            |rng| (rng.next_u64() as usize) % 512,
            |&index| {
                black_box(ct_select_n(&table, index));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn ct_xtime_timing() {
        let outcome = ct_test(
            3,
            |rng| rng.next_u8() & 0x7F,
            |rng| rng.next_u8() | 0x80,
            |&b| {
                black_box(ct_xtime(b));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn ct_eq_equal_vs_different_timing() {
        let outcome = ct_test(
            4,
            |rng| {
                let mut buf = [0u8; 32];
                rng.fill_bytes(&mut buf);
                (buf, buf)
            },
            |rng| {
                let mut a = [0u8; 32];
                rng.fill_bytes(&mut a);
                let mut b = a;
                let pos = (rng.next_u64() as usize) % 32;
                b[pos] ^= 0x01;
                (a, b)
            },
            |pair| {
                black_box(ct_eq(&pair.0, &pair.1));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn ct_eq_early_vs_late_diff_timing() {
        let outcome = ct_test(
            5,
            |rng| {
                let mut a = [0u8; 32];
                rng.fill_bytes(&mut a);
                let mut b = a;
                b[0] ^= 0x01;
                (a, b)
            },
            |rng| {
                let mut a = [0u8; 32];
                rng.fill_bytes(&mut a);
                let mut b = a;
                b[31] ^= 0x01;
                (a, b)
            },
            |pair| {
                black_box(ct_eq(&pair.0, &pair.1));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn ct_is_zero_u8_timing() {
        let outcome = ct_test(
            6,
            |_rng| 0u8,
            |rng| {
                let mut v = rng.next_u8();
                if v == 0 {
                    v = 1;
                }
                v
            },
            |&x| {
                black_box(ct_is_zero_u8(x));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn ct_mux_u8_timing() {
        let outcome = ct_test(
            7,
            |rng| (true, rng.next_u8(), rng.next_u8()),
            |rng| (false, rng.next_u8(), rng.next_u8()),
            |&(cond, a, b)| {
                let ct_cond = if cond { CtBool::TRUE } else { CtBool::FALSE };
                black_box(ct_mux_u8(ct_cond, a, b));
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
