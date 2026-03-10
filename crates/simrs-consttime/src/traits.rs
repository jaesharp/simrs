//! Constant-time traits for cryptographic operations.
//!
//! Provides [`CtEq`], [`CtSelect`], [`CtSwap`], and [`CtZero`] with
//! implementations for primitive types (`u8`, `u64`) and fixed-size arrays
//! (`[u8; N]`, `[u64; N]`).

use crate::CtBool;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Constant-time equality comparison.
///
/// Returns [`CtBool`] instead of `bool`, preventing accidental branching
/// on the result. Call [`.into_bool()`](CtBool::into_bool) explicitly
/// when a branch is intentional (e.g., in assertions or non-secret
/// control flow).
///
/// # Contract
///
/// - Returns `CtBool::TRUE` if and only if the two values are equal.
/// - Execution time is independent of which bytes differ.
/// - Memory access patterns are independent of which bytes differ.
pub trait CtEq {
    /// Compare `self` with `other` in constant time.
    fn ct_eq(&self, other: &Self) -> CtBool;
}

/// Constant-time conditional select (cmov).
///
/// `ct_select(cond, a, b)` returns `a` when `cond` is `TRUE`,
/// `b` when `cond` is `FALSE`. The operation always reads both `a` and `b`.
pub trait CtSelect: Sized {
    /// Returns `a` if `cond` is TRUE, `b` if FALSE.
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self;

    /// In-place conditional assign: `*self = other` when `cond` is TRUE.
    fn ct_assign(&mut self, other: &Self, cond: CtBool) {
        *self = Self::ct_select(cond, other, self);
    }
}

/// Constant-time conditional swap (cswap).
///
/// When `cond` is `TRUE`, swaps `a` and `b` in place.
/// When `cond` is `FALSE`, both values are unchanged.
/// Either way, the same instructions execute.
pub trait CtSwap {
    /// Swap `a` and `b` when `cond` is TRUE; no-op when FALSE.
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool);
}

/// Constant-time zero test.
///
/// Returns `CtBool::TRUE` if the value is zero, `FALSE` otherwise,
/// without data-dependent branches.
pub trait CtZero {
    /// Returns TRUE if `self` is zero.
    fn ct_is_zero(&self) -> CtBool;
}

// ---------------------------------------------------------------------------
// u8 implementations
// ---------------------------------------------------------------------------

impl CtEq for u8 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        (*self ^ *other).ct_is_zero()
    }
}

impl CtSelect for u8 {
    #[inline]
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self {
        b ^ (cond.as_u8_mask() & (a ^ b))
    }
}

impl CtSwap for u8 {
    #[inline]
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool) {
        let t = cond.as_u8_mask() & (*a ^ *b);
        *a ^= t;
        *b ^= t;
    }
}

impl CtZero for u8 {
    #[inline]
    fn ct_is_zero(&self) -> CtBool {
        // (x | x.wrapping_neg()) >> 7 is 1 for nonzero, 0 for zero.
        let x = *self;
        let nonzero = (x | x.wrapping_neg()) >> 7;
        CtBool::from_u8_bit(nonzero ^ 1)
    }
}

// ---------------------------------------------------------------------------
// u64 implementations
// ---------------------------------------------------------------------------

impl CtEq for u64 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        (*self ^ *other).ct_is_zero()
    }
}

impl CtSelect for u64 {
    #[inline]
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self {
        let mask = cond.as_u64_mask();
        b ^ (mask & (a ^ b))
    }
}

impl CtSwap for u64 {
    #[inline]
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool) {
        let mask = cond.as_u64_mask();
        let t = mask & (*a ^ *b);
        *a ^= t;
        *b ^= t;
    }
}

impl CtZero for u64 {
    #[inline]
    fn ct_is_zero(&self) -> CtBool {
        let x = *self;
        let nonzero = (x | x.wrapping_neg()) >> 63;
        // nonzero is 1 when x != 0, 0 when x == 0.
        // XOR 1 to invert, then take bit 0.
        #[allow(clippy::cast_possible_truncation)]
        CtBool::from_u8_bit((nonzero as u8) ^ 1)
    }
}

// ---------------------------------------------------------------------------
// [u8; N] implementations
// ---------------------------------------------------------------------------

impl<const N: usize> CtEq for [u8; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        let mut diff = 0u8;
        let mut i = 0;
        while i < N {
            diff |= self[i] ^ other[i];
            i += 1;
        }
        diff.ct_is_zero()
    }
}

impl<const N: usize> CtSelect for [u8; N] {
    #[inline]
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self {
        let mask = cond.as_u8_mask();
        let mut result = [0u8; N];
        let mut i = 0;
        while i < N {
            result[i] = b[i] ^ (mask & (a[i] ^ b[i]));
            i += 1;
        }
        result
    }
}

impl<const N: usize> CtSwap for [u8; N] {
    #[inline]
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool) {
        let mask = cond.as_u8_mask();
        let mut i = 0;
        while i < N {
            let t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
            i += 1;
        }
    }
}

impl<const N: usize> CtZero for [u8; N] {
    #[inline]
    fn ct_is_zero(&self) -> CtBool {
        let mut or = 0u8;
        let mut i = 0;
        while i < N {
            or |= self[i];
            i += 1;
        }
        or.ct_is_zero()
    }
}

// ---------------------------------------------------------------------------
// [u64; N] implementations
// ---------------------------------------------------------------------------

impl<const N: usize> CtEq for [u64; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        let mut diff = 0u64;
        let mut i = 0;
        while i < N {
            diff |= self[i] ^ other[i];
            i += 1;
        }
        diff.ct_is_zero()
    }
}

impl<const N: usize> CtSelect for [u64; N] {
    #[inline]
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self {
        let mask = cond.as_u64_mask();
        let mut result = [0u64; N];
        let mut i = 0;
        while i < N {
            result[i] = b[i] ^ (mask & (a[i] ^ b[i]));
            i += 1;
        }
        result
    }
}

impl<const N: usize> CtSwap for [u64; N] {
    #[inline]
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool) {
        let mask = cond.as_u64_mask();
        let mut i = 0;
        while i < N {
            let t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
            i += 1;
        }
    }
}

impl<const N: usize> CtZero for [u64; N] {
    #[inline]
    fn ct_is_zero(&self) -> CtBool {
        let mut or = 0u64;
        let mut i = 0;
        while i < N {
            or |= self[i];
            i += 1;
        }
        or.ct_is_zero()
    }
}

// ---------------------------------------------------------------------------
// Tuple implementations (for ct_test input types)
// ---------------------------------------------------------------------------

impl<A: CtEq, B: CtEq> CtEq for (A, B) {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0.ct_eq(&other.0).and(self.1.ct_eq(&other.1))
    }
}

impl<A: CtEq, B: CtEq, C: CtEq> CtEq for (A, B, C) {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0
            .ct_eq(&other.0)
            .and(self.1.ct_eq(&other.1))
            .and(self.2.ct_eq(&other.2))
    }
}

impl<A: CtEq, B: CtEq, C: CtEq, D: CtEq> CtEq for (A, B, C, D) {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0
            .ct_eq(&other.0)
            .and(self.1.ct_eq(&other.1))
            .and(self.2.ct_eq(&other.2))
            .and(self.3.ct_eq(&other.3))
    }
}

impl<A: CtEq, B: CtEq, C: CtEq, D: CtEq, E: CtEq> CtEq for (A, B, C, D, E) {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0
            .ct_eq(&other.0)
            .and(self.1.ct_eq(&other.1))
            .and(self.2.ct_eq(&other.2))
            .and(self.3.ct_eq(&other.3))
            .and(self.4.ct_eq(&other.4))
    }
}

// ---------------------------------------------------------------------------
// Free functions (const fn, for use in const contexts)
// ---------------------------------------------------------------------------

/// Constant-time zero test for `u8`. Returns [`CtBool`].
#[inline]
pub const fn ct_is_zero_u8(x: u8) -> CtBool {
    let nonzero = (x | x.wrapping_neg()) >> 7;
    CtBool::from_u8_bit(nonzero ^ 1)
}

/// Constant-time conditional select for `u8`.
///
/// Returns `a` when `cond` is TRUE, `b` when FALSE.
#[inline]
pub const fn ct_mux_u8(cond: CtBool, a: u8, b: u8) -> u8 {
    b ^ (cond.as_u8_mask() & (a ^ b))
}

/// Constant-time zero test for `u64`. Returns [`CtBool`].
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub const fn ct_is_zero_u64(x: u64) -> CtBool {
    let nonzero = (x | x.wrapping_neg()) >> 63;
    CtBool::from_u8_bit((nonzero as u8) ^ 1)
}

/// Constant-time conditional select for `u64`.
///
/// Returns `a` when `cond` is TRUE, `b` when FALSE.
#[inline]
pub const fn ct_mux_u64(cond: CtBool, a: u64, b: u64) -> u64 {
    let mask = cond.as_u64_mask();
    b ^ (mask & (a ^ b))
}

/// Constant-time conditional swap for `u64`.
#[inline]
pub fn ct_swap_u64(a: &mut u64, b: &mut u64, cond: CtBool) {
    let mask = cond.as_u64_mask();
    let t = mask & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // -- CtEq --

    #[test]
    fn ct_eq_u8() {
        assert!(0u8.ct_eq(&0u8).into_bool());
        assert!(!0u8.ct_eq(&1u8).into_bool());
        assert!(0xFFu8.ct_eq(&0xFFu8).into_bool());
    }

    #[test]
    fn ct_eq_u64() {
        assert!(0u64.ct_eq(&0u64).into_bool());
        assert!(!0u64.ct_eq(&1u64).into_bool());
        assert!(u64::MAX.ct_eq(&u64::MAX).into_bool());
        assert!(!u64::MAX.ct_eq(&(u64::MAX - 1)).into_bool());
    }

    #[test]
    fn ct_eq_u8_array() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
    }

    #[test]
    fn ct_eq_u64_array() {
        let a = [1u64, 2, 3, 4];
        let b = [1u64, 2, 3, 4];
        let c = [1u64, 2, 3, 5];
        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
    }

    #[test]
    fn ct_eq_empty_arrays() {
        let a: [u8; 0] = [];
        assert!(a.ct_eq(&a).into_bool());
        let b: [u64; 0] = [];
        assert!(b.ct_eq(&b).into_bool());
    }

    // -- CtSelect --

    #[test]
    fn ct_select_u8() {
        assert_eq!(u8::ct_select(CtBool::TRUE, &0x42, &0x99), 0x42);
        assert_eq!(u8::ct_select(CtBool::FALSE, &0x42, &0x99), 0x99);
    }

    #[test]
    fn ct_select_u64() {
        assert_eq!(
            u64::ct_select(CtBool::TRUE, &0xDEAD_BEEF, &0xCAFE_BABE),
            0xDEAD_BEEF
        );
        assert_eq!(
            u64::ct_select(CtBool::FALSE, &0xDEAD_BEEF, &0xCAFE_BABE),
            0xCAFE_BABE
        );
    }

    #[test]
    fn ct_select_u64_array() {
        let a = [1u64, 2, 3, 4];
        let b = [5u64, 6, 7, 8];
        assert_eq!(<[u64; 4]>::ct_select(CtBool::TRUE, &a, &b), a);
        assert_eq!(<[u64; 4]>::ct_select(CtBool::FALSE, &a, &b), b);
    }

    #[test]
    fn ct_assign_u64() {
        let mut x = 42u64;
        x.ct_assign(&99, CtBool::TRUE);
        assert_eq!(x, 99);

        x.ct_assign(&0, CtBool::FALSE);
        assert_eq!(x, 99);
    }

    // -- CtSwap --

    #[test]
    fn ct_swap_u8_true() {
        let (mut a, mut b) = (0x42u8, 0x99u8);
        u8::ct_swap(&mut a, &mut b, CtBool::TRUE);
        assert_eq!((a, b), (0x99, 0x42));
    }

    #[test]
    fn ct_swap_u8_false() {
        let (mut a, mut b) = (0x42u8, 0x99u8);
        u8::ct_swap(&mut a, &mut b, CtBool::FALSE);
        assert_eq!((a, b), (0x42, 0x99));
    }

    #[test]
    fn ct_swap_u64_roundtrip() {
        let (mut a, mut b) = (123u64, 456u64);
        u64::ct_swap(&mut a, &mut b, CtBool::TRUE);
        assert_eq!((a, b), (456, 123));
        u64::ct_swap(&mut a, &mut b, CtBool::TRUE);
        assert_eq!((a, b), (123, 456));
    }

    #[test]
    fn ct_swap_u64_array() {
        let mut a = [1u64, 2, 3, 4];
        let mut b = [5u64, 6, 7, 8];
        <[u64; 4]>::ct_swap(&mut a, &mut b, CtBool::TRUE);
        assert_eq!(a, [5, 6, 7, 8]);
        assert_eq!(b, [1, 2, 3, 4]);
    }

    // -- CtZero --

    #[test]
    fn ct_zero_u8_exhaustive() {
        for i in 0u16..256 {
            let x = i as u8;
            assert_eq!(x.ct_is_zero().into_bool(), x == 0, "ct_is_zero({x})");
        }
    }

    #[test]
    fn ct_zero_u64() {
        assert!(0u64.ct_is_zero().into_bool());
        assert!(!1u64.ct_is_zero().into_bool());
        assert!(!u64::MAX.ct_is_zero().into_bool());
        assert!(!(1u64 << 63).ct_is_zero().into_bool());
    }

    #[test]
    fn ct_zero_u8_array() {
        assert!([0u8; 4].ct_is_zero().into_bool());
        assert!(![1u8, 0, 0, 0].ct_is_zero().into_bool());
        assert!(![0u8, 0, 0, 1].ct_is_zero().into_bool());
    }

    #[test]
    fn ct_zero_u64_array() {
        assert!([0u64; 4].ct_is_zero().into_bool());
        assert!(![1u64, 0, 0, 0].ct_is_zero().into_bool());
        assert!(![0u64, 0, 0, 1].ct_is_zero().into_bool());
    }

    // -- Free functions --

    #[test]
    fn free_fn_ct_is_zero_u8() {
        assert!(ct_is_zero_u8(0).into_bool());
        assert!(!ct_is_zero_u8(1).into_bool());
        assert!(!ct_is_zero_u8(0xFF).into_bool());
    }

    #[test]
    fn free_fn_ct_mux_u8() {
        assert_eq!(ct_mux_u8(CtBool::TRUE, 0x42, 0x99), 0x42);
        assert_eq!(ct_mux_u8(CtBool::FALSE, 0x42, 0x99), 0x99);
    }

    #[test]
    fn free_fn_ct_is_zero_u64() {
        assert!(ct_is_zero_u64(0).into_bool());
        assert!(!ct_is_zero_u64(1).into_bool());
        assert!(!ct_is_zero_u64(u64::MAX).into_bool());
    }

    #[test]
    fn free_fn_ct_mux_u64() {
        assert_eq!(ct_mux_u64(CtBool::TRUE, 42, 99), 42);
        assert_eq!(ct_mux_u64(CtBool::FALSE, 42, 99), 99);
    }

    #[test]
    fn free_fn_ct_swap_u64() {
        let (mut a, mut b) = (42u64, 99u64);
        ct_swap_u64(&mut a, &mut b, CtBool::TRUE);
        assert_eq!((a, b), (99, 42));
        ct_swap_u64(&mut a, &mut b, CtBool::FALSE);
        assert_eq!((a, b), (99, 42));
    }

    // -- Tuple CtEq --

    #[test]
    fn ct_eq_tuple2() {
        let a = (1u8, 2u8);
        assert!(a.ct_eq(&(1u8, 2u8)).into_bool());
        assert!(!a.ct_eq(&(1u8, 3u8)).into_bool());
    }

    #[test]
    fn ct_eq_tuple3() {
        let a = ([1u8; 4], [2u8; 4], [3u8; 4]);
        assert!(a.ct_eq(&a).into_bool());
        let mut b = a;
        b.2[3] = 99;
        assert!(!a.ct_eq(&b).into_bool());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ct_select_u64_true_returns_a(a in any::<u64>(), b in any::<u64>()) {
            prop_assert_eq!(u64::ct_select(CtBool::TRUE, &a, &b), a);
        }
    }

    proptest! {
        #[test]
        fn ct_select_u64_false_returns_b(a in any::<u64>(), b in any::<u64>()) {
            prop_assert_eq!(u64::ct_select(CtBool::FALSE, &a, &b), b);
        }
    }

    proptest! {
        #[test]
        fn ct_swap_u64_involution(a in any::<u64>(), b in any::<u64>()) {
            let (mut x, mut y) = (a, b);
            u64::ct_swap(&mut x, &mut y, CtBool::TRUE);
            prop_assert_eq!((x, y), (b, a));
            u64::ct_swap(&mut x, &mut y, CtBool::TRUE);
            prop_assert_eq!((x, y), (a, b));
        }
    }

    proptest! {
        #[test]
        fn ct_swap_u64_false_is_noop(a in any::<u64>(), b in any::<u64>()) {
            let (mut x, mut y) = (a, b);
            u64::ct_swap(&mut x, &mut y, CtBool::FALSE);
            prop_assert_eq!((x, y), (a, b));
        }
    }

    proptest! {
        #[test]
        fn ct_zero_u64_correct(x in any::<u64>()) {
            prop_assert_eq!(x.ct_is_zero().into_bool(), x == 0);
        }
    }

    proptest! {
        #[test]
        fn ct_eq_u64_reflexive(x in any::<u64>()) {
            prop_assert!(x.ct_eq(&x).into_bool());
        }
    }

    proptest! {
        #[test]
        fn ct_eq_u64_array_reflexive(
            a in any::<u64>(), b in any::<u64>(),
            c in any::<u64>(), d in any::<u64>(),
        ) {
            let arr = [a, b, c, d];
            prop_assert!(arr.ct_eq(&arr).into_bool());
        }
    }
}
