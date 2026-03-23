//! Constant-time option type.
//!
//! [`CtOption<T>`] uses a [`CtBool`] discriminant instead of Rust's `bool`.
//! The value is always present in memory, avoiding cache-timing leaks from
//! allocation/deallocation patterns.

use simrs_consttime::{CtBool, CtEq, CtSelect};

/// Constant-time option type.
///
/// The discriminant is a [`CtBool`], not a Rust `bool`. The value is
/// always present in memory (avoids cache-timing leaks from
/// allocation/deallocation patterns).
///
/// # Construction
///
/// ```
/// use simrs_secret::CtOption;
///
/// let some_val = CtOption::some(42u8);
/// let none_val = CtOption::<u8>::none_with(0);
///
/// assert!(some_val.is_some().into_bool());
/// assert!(none_val.is_none().into_bool());
/// ```
#[derive(Clone, Copy)]
pub struct CtOption<T> {
    value: T,
    is_some: CtBool,
}

impl<T> CtOption<T> {
    /// Create a `CtOption` containing a value.
    #[inline]
    pub const fn some(value: T) -> Self {
        Self {
            value,
            is_some: CtBool::TRUE,
        }
    }

    /// Create a `CtOption` that is "none", backed by the given default.
    ///
    /// A default value is required because the value must always be present
    /// in memory (no alloc, no branch on the discriminant).
    #[inline]
    pub const fn none_with(default: T) -> Self {
        Self {
            value: default,
            is_some: CtBool::FALSE,
        }
    }

    /// Returns `CtBool::TRUE` if this option contains a value.
    #[inline]
    pub const fn is_some(&self) -> CtBool {
        self.is_some
    }

    /// Returns `CtBool::TRUE` if this option is "none".
    #[inline]
    pub const fn is_none(&self) -> CtBool {
        self.is_some.not()
    }

    /// Convert to a standard `Option<T>`.
    ///
    /// This is an explicit escape hatch from the CT domain. The branch
    /// on the discriminant leaks timing information, so use this only
    /// when exiting the constant-time context.
    #[inline]
    pub fn into_option(self) -> Option<T> {
        if self.is_some.into_bool() {
            Some(self.value)
        } else {
            None
        }
    }

    /// Apply a function to the contained value, preserving the discriminant.
    ///
    /// `f` is **always** called regardless of the discriminant, preventing
    /// timing leaks from conditional execution.
    #[inline]
    pub fn ct_map<U>(self, f: impl FnOnce(T) -> U) -> CtOption<U> {
        CtOption {
            value: f(self.value),
            is_some: self.is_some,
        }
    }
}

impl<T: CtSelect> CtOption<T> {
    /// Extract the value if "some", or return `default` if "none".
    ///
    /// Uses constant-time select -- both paths execute.
    #[inline]
    pub fn ct_unwrap_or(&self, default: &T) -> T {
        T::ct_select(self.is_some, &self.value, default)
    }

    /// Combine two `CtOption`s: returns `other` when `self` is "some",
    /// or "none" (backed by `other`'s value) when `self` is "none".
    ///
    /// Uses constant-time select on the value.
    #[inline]
    #[must_use]
    pub fn ct_and(&self, other: &Self) -> Self {
        Self {
            value: T::ct_select(self.is_some, &other.value, &self.value),
            is_some: self.is_some.and(other.is_some),
        }
    }
}

// ---------------------------------------------------------------------------
// CT trait implementations
// ---------------------------------------------------------------------------

impl<T: CtEq> CtEq for CtOption<T> {
    /// Compare two `CtOption`s in constant time.
    ///
    /// Both the discriminant **and** the stored value are compared,
    /// preventing timing leaks from short-circuit evaluation.
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        // Compare discriminants via XOR (same = 0 bit).
        let disc_eq = self.is_some.xor(other.is_some).not();
        // Always compare values, even if discriminants differ.
        let val_eq = self.value.ct_eq(&other.value);
        disc_eq.and(val_eq)
    }
}

impl<T> core::fmt::Debug for CtOption<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_some.into_bool() {
            f.write_str("CtOption(some)")
        } else {
            f.write_str("CtOption(none)")
        }
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
    fn some_is_some() {
        let opt = CtOption::some(42u8);
        assert!(opt.is_some().into_bool());
        assert!(!opt.is_none().into_bool());
    }

    #[test]
    fn none_is_none() {
        let opt = CtOption::<u8>::none_with(0);
        assert!(!opt.is_some().into_bool());
        assert!(opt.is_none().into_bool());
    }

    #[test]
    fn into_option_some() {
        let opt = CtOption::some([0xABu8; 4]);
        assert_eq!(opt.into_option(), Some([0xABu8; 4]));
    }

    #[test]
    fn into_option_none() {
        let opt = CtOption::<[u8; 4]>::none_with([0; 4]);
        assert_eq!(opt.into_option(), None);
    }

    #[test]
    fn ct_unwrap_or_some() {
        let opt = CtOption::some(42u8);
        assert_eq!(opt.ct_unwrap_or(&99), 42);
    }

    #[test]
    fn ct_unwrap_or_none() {
        let opt = CtOption::<u8>::none_with(0);
        assert_eq!(opt.ct_unwrap_or(&99), 99);
    }

    #[test]
    fn ct_map_preserves_discriminant() {
        let some_opt = CtOption::some(10u8);
        let mapped = some_opt.ct_map(|x| x.wrapping_mul(2));
        assert!(mapped.is_some().into_bool());
        assert_eq!(mapped.into_option(), Some(20u8));

        let none_opt = CtOption::<u8>::none_with(10);
        let mapped = none_opt.ct_map(|x| x.wrapping_mul(2));
        assert!(mapped.is_none().into_bool());
    }

    #[test]
    fn ct_and_both_some() {
        let a = CtOption::some([1u8; 4]);
        let b = CtOption::some([2u8; 4]);
        let result = a.ct_and(&b);
        assert!(result.is_some().into_bool());
        assert_eq!(result.into_option(), Some([2u8; 4]));
    }

    #[test]
    fn ct_and_first_none() {
        let a = CtOption::<[u8; 4]>::none_with([0; 4]);
        let b = CtOption::some([2u8; 4]);
        let result = a.ct_and(&b);
        assert!(!result.is_some().into_bool());
    }

    #[test]
    fn ct_and_second_none() {
        let a = CtOption::some([1u8; 4]);
        let b = CtOption::<[u8; 4]>::none_with([0; 4]);
        let result = a.ct_and(&b);
        assert!(!result.is_some().into_bool());
    }

    #[test]
    fn ct_and_both_none() {
        let a = CtOption::<[u8; 4]>::none_with([0; 4]);
        let b = CtOption::<[u8; 4]>::none_with([0; 4]);
        let result = a.ct_and(&b);
        assert!(!result.is_some().into_bool());
    }

    #[test]
    fn ct_eq_both_some_equal() {
        let a = CtOption::some([0xABu8; 8]);
        let b = CtOption::some([0xABu8; 8]);
        assert!(a.ct_eq(&b).into_bool());
    }

    #[test]
    fn ct_eq_both_some_different() {
        let a = CtOption::some([0xABu8; 8]);
        let b = CtOption::some([0xACu8; 8]);
        assert!(!a.ct_eq(&b).into_bool());
    }

    #[test]
    fn ct_eq_some_vs_none() {
        let a = CtOption::some([0xABu8; 8]);
        let b = CtOption::<[u8; 8]>::none_with([0xAB; 8]);
        // Same value but different discriminant -> not equal.
        assert!(!a.ct_eq(&b).into_bool());
    }

    #[test]
    fn ct_eq_both_none_same_default() {
        let a = CtOption::<[u8; 4]>::none_with([0; 4]);
        let b = CtOption::<[u8; 4]>::none_with([0; 4]);
        assert!(a.ct_eq(&b).into_bool());
    }

    #[test]
    fn ct_eq_both_none_different_default() {
        // Both "none" but with different backing values: not equal
        // because we compare the full storage in CT.
        let a = CtOption::<[u8; 4]>::none_with([0; 4]);
        let b = CtOption::<[u8; 4]>::none_with([1; 4]);
        assert!(!a.ct_eq(&b).into_bool());
    }

    #[test]
    fn debug_some() {
        let opt = CtOption::some([0xDEu8, 0xAD]);
        let output = format!("{opt:?}");
        assert_eq!(output, "CtOption(some)");
        assert!(!output.contains("DE"), "Debug must not leak data: {output}");
    }

    #[test]
    fn debug_none() {
        let opt = CtOption::<u8>::none_with(0);
        let output = format!("{opt:?}");
        assert_eq!(output, "CtOption(none)");
    }

    #[test]
    fn clone_preserves_value_and_discriminant() {
        let a = CtOption::some([1u8, 2, 3, 4]);
        let b = a;
        assert!(a.ct_eq(&b).into_bool());
        assert!(b.is_some().into_bool());
    }

    #[test]
    fn copy_semantics() {
        let a = CtOption::some(42u8);
        let b = a; // Copy
        assert!(a.is_some().into_bool()); // a still usable
        assert!(b.is_some().into_bool());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ct_unwrap_or_roundtrip(data in any::<[u8; 8]>(), default in any::<[u8; 8]>()) {
            let some_opt = CtOption::some(data);
            prop_assert_eq!(some_opt.ct_unwrap_or(&default), data);

            let none_opt = CtOption::<[u8; 8]>::none_with([0; 8]);
            prop_assert_eq!(none_opt.ct_unwrap_or(&default), default);
        }
    }

    proptest! {
        #[test]
        fn ct_eq_reflexive(data in any::<[u8; 8]>()) {
            let a = CtOption::some(data);
            prop_assert!(a.ct_eq(&a).into_bool());
        }
    }

    proptest! {
        #[test]
        fn ct_map_identity(data in any::<u8>()) {
            let opt = CtOption::some(data);
            let mapped = opt.ct_map(|x| x);
            prop_assert!(mapped.is_some().into_bool());
            prop_assert_eq!(mapped.into_option(), Some(data));
        }
    }

    proptest! {
        #[test]
        fn into_option_roundtrip(data in any::<[u8; 4]>()) {
            let some_opt = CtOption::some(data);
            prop_assert_eq!(some_opt.into_option(), Some(data));

            let none_opt = CtOption::<[u8; 4]>::none_with([0; 4]);
            prop_assert_eq!(none_opt.into_option(), None);
        }
    }
}
