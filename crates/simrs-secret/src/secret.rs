//! Zero-cost secret value wrapper.
//!
//! [`Secret<T>`] restricts a value to constant-time operations at compile
//! time. It deliberately omits `PartialEq`, `Display`, `Hash`, `Deref`,
//! and other traits that would allow non-CT operations on the inner value.
//!
//! ## Compile-time enforcement
//!
//! ```compile_fail
//! use simrs_secret::Secret;
//! let a = Secret::new([0u8; 16]);
//! let b = Secret::new([0u8; 16]);
//! let _ = a == b;  // ERROR: Secret<T> does not implement PartialEq
//! ```
//!
//! ## Correct usage via CT traits
//!
//! ```
//! use simrs_secret::Secret;
//! use simrs_consttime::CtEq;
//!
//! let a = Secret::new([0xABu8; 16]);
//! let b = Secret::new([0xABu8; 16]);
//! assert!(a.ct_eq(&b).into_bool());
//! ```

use simrs_consttime::{CtBool, CtEq, CtSelect, CtSwap, CtZero};
use simrs_redact::{AsBytes, Redact};

/// Zero-cost wrapper restricting a value to constant-time operations.
///
/// `Secret<T>` does NOT implement `PartialEq`, `Eq`, `PartialOrd`, `Ord`,
/// `Display`, `Hash`, `Deref`, `AsRef`, or `Borrow`. The only way to
/// compare is [`.ct_eq()`](CtEq::ct_eq) and the only way to extract the
/// value is [`.declassify()`](Secret::declassify).
#[derive(Clone, Copy)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Classify a value as secret.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Classify a value as secret (alias for [`new`](Self::new)).
    ///
    /// Reads better in API signatures:
    /// `Secret::classify(key_bytes)` vs `Secret::new(key_bytes)`.
    #[inline]
    pub const fn classify(value: T) -> Self {
        Self(value)
    }

    /// Extract the inner value, consuming the wrapper.
    ///
    /// Each call site is a visible acknowledgement that secret data is
    /// leaving the CT-protected domain. Use sparingly -- typically only
    /// at serialization boundaries (e.g., writing key bytes to a socket).
    #[inline]
    pub fn declassify(self) -> T {
        self.0
    }

    /// Borrow the inner value.
    ///
    /// Useful for passing to CT operations that take `&T`, or for
    /// serialization where you need to read bytes without consuming
    /// the wrapper. Each call site is a visible acknowledgement.
    #[inline]
    pub const fn declassify_ref(&self) -> &T {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// CT trait delegations
// ---------------------------------------------------------------------------

impl<T: CtEq> CtEq for Secret<T> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0.ct_eq(&other.0)
    }
}

impl<T: CtSelect> CtSelect for Secret<T> {
    #[inline]
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self {
        Self(T::ct_select(cond, &a.0, &b.0))
    }
}

impl<T: CtSwap> CtSwap for Secret<T> {
    #[inline]
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool) {
        T::ct_swap(&mut a.0, &mut b.0, cond);
    }
}

impl<T: CtZero> CtZero for Secret<T> {
    #[inline]
    fn ct_is_zero(&self) -> CtBool {
        self.0.ct_is_zero()
    }
}

// ---------------------------------------------------------------------------
// Debug / Display (redacted via simrs-redact)
// ---------------------------------------------------------------------------

impl<T: AsBytes + core::fmt::Debug> core::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Secret").field(&Redact(&self.0)).finish()
    }
}

impl<T: AsBytes + core::fmt::Debug> core::fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret({})", Redact(&self.0))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::format;

    use super::*;

    #[test]
    fn classify_declassify_roundtrip() {
        let raw = [0xABu8; 16];
        let s = Secret::new(raw);
        assert_eq!(s.declassify(), raw);
    }

    #[test]
    fn classify_alias() {
        let raw = [0x42u8; 32];
        let s = Secret::classify(raw);
        assert_eq!(s.declassify(), raw);
    }

    #[test]
    fn declassify_ref_borrows() {
        let raw = [1u8, 2, 3, 4];
        let s = Secret::new(raw);
        assert_eq!(*s.declassify_ref(), raw);
    }

    #[test]
    fn ct_eq_equal() {
        let a = Secret::new([0xABu8; 16]);
        let b = Secret::new([0xABu8; 16]);
        assert!(a.ct_eq(&b).into_bool());
    }

    #[test]
    fn ct_eq_different() {
        let a = Secret::new([0xABu8; 16]);
        let b = Secret::new([0xACu8; 16]);
        assert!(!a.ct_eq(&b).into_bool());
    }

    #[test]
    fn ct_eq_single_bit_flip() {
        let raw = [0x4Au8, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
        let a = Secret::new(raw);
        for i in 0..raw.len() {
            for bit in 0..8u32 {
                let mut modified = raw;
                modified[i] ^= 1 << bit;
                let b = Secret::new(modified);
                assert!(
                    !a.ct_eq(&b).into_bool(),
                    "must detect bit {bit} diff at byte {i}"
                );
            }
        }
    }

    #[test]
    fn ct_select_true_returns_a() {
        let a = Secret::new([1u8; 8]);
        let b = Secret::new([2u8; 8]);
        let result = Secret::ct_select(CtBool::TRUE, &a, &b);
        assert_eq!(result.declassify(), [1u8; 8]);
    }

    #[test]
    fn ct_select_false_returns_b() {
        let a = Secret::new([1u8; 8]);
        let b = Secret::new([2u8; 8]);
        let result = Secret::ct_select(CtBool::FALSE, &a, &b);
        assert_eq!(result.declassify(), [2u8; 8]);
    }

    #[test]
    fn ct_swap_true_swaps() {
        let mut a = Secret::new([1u8; 4]);
        let mut b = Secret::new([2u8; 4]);
        Secret::ct_swap(&mut a, &mut b, CtBool::TRUE);
        assert_eq!(a.declassify(), [2u8; 4]);
        assert_eq!(b.declassify(), [1u8; 4]);
    }

    #[test]
    fn ct_swap_false_noop() {
        let mut a = Secret::new([1u8; 4]);
        let mut b = Secret::new([2u8; 4]);
        Secret::ct_swap(&mut a, &mut b, CtBool::FALSE);
        assert_eq!(a.declassify(), [1u8; 4]);
        assert_eq!(b.declassify(), [2u8; 4]);
    }

    #[test]
    fn ct_is_zero_true() {
        let s = Secret::new([0u8; 16]);
        assert!(s.ct_is_zero().into_bool());
    }

    #[test]
    fn ct_is_zero_false() {
        let s = Secret::new([0u8, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!s.ct_is_zero().into_bool());
    }

    #[test]
    fn debug_redacted() {
        let s = Secret::new([0xDEu8, 0xAD, 0xBE, 0xEF]);
        let output = format!("{s:?}");
        assert!(output.contains("masked"), "Debug must redact: {output}");
        assert!(!output.contains("DEAD"), "Debug must not leak data: {output}");
        assert!(!output.contains("dead"), "Debug must not leak data: {output}");
    }

    #[test]
    fn ct_assign_updates_on_true() {
        let mut a = Secret::new([0u8; 8]);
        let b = Secret::new([0xFFu8; 8]);
        a.ct_assign(&b, CtBool::TRUE);
        assert_eq!(a.declassify(), [0xFFu8; 8]);
    }

    #[test]
    fn ct_assign_noop_on_false() {
        let mut a = Secret::new([0u8; 8]);
        let b = Secret::new([0xFFu8; 8]);
        a.ct_assign(&b, CtBool::FALSE);
        assert_eq!(a.declassify(), [0u8; 8]);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_u8_16(data in any::<[u8; 16]>()) {
            let s = Secret::new(data);
            prop_assert_eq!(s.declassify(), data);
        }
    }

    proptest! {
        #[test]
        fn roundtrip_u8_32(data in any::<[u8; 32]>()) {
            let s = Secret::classify(data);
            prop_assert_eq!(*s.declassify_ref(), data);
        }
    }

    proptest! {
        #[test]
        fn ct_eq_matches_inner(a in any::<[u8; 16]>(), b in any::<[u8; 16]>()) {
            let sa = Secret::new(a);
            let sb = Secret::new(b);
            prop_assert_eq!(
                sa.ct_eq(&sb).into_bool(),
                a.ct_eq(&b).into_bool(),
            );
        }
    }

    proptest! {
        #[test]
        fn ct_is_zero_matches_inner(data in any::<[u8; 8]>()) {
            let s = Secret::new(data);
            prop_assert_eq!(
                s.ct_is_zero().into_bool(),
                data.ct_is_zero().into_bool(),
            );
        }
    }

    proptest! {
        #[test]
        fn ct_select_matches_inner(a in any::<[u8; 8]>(), b in any::<[u8; 8]>()) {
            let sa = Secret::new(a);
            let sb = Secret::new(b);
            let selected_t = Secret::ct_select(CtBool::TRUE, &sa, &sb);
            let selected_f = Secret::ct_select(CtBool::FALSE, &sa, &sb);
            prop_assert_eq!(selected_t.declassify(), a);
            prop_assert_eq!(selected_f.declassify(), b);
        }
    }

    proptest! {
        #[test]
        fn ct_swap_involution(a in any::<[u8; 8]>(), b in any::<[u8; 8]>()) {
            let mut sa = Secret::new(a);
            let mut sb = Secret::new(b);
            Secret::ct_swap(&mut sa, &mut sb, CtBool::TRUE);
            prop_assert_eq!(sa.declassify(), b);
            prop_assert_eq!(sb.declassify(), a);
            Secret::ct_swap(&mut sa, &mut sb, CtBool::TRUE);
            prop_assert_eq!(sa.declassify(), a);
            prop_assert_eq!(sb.declassify(), b);
        }
    }
}
