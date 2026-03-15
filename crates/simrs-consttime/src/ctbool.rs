//! Opaque constant-time boolean.
//!
//! [`CtBool`] wraps a single canonical bit (0 or 1) and cannot be used in
//! `if` expressions without calling [`.into_bool()`](CtBool::into_bool),
//! making timing-unsafe branches a deliberate, visible choice.
//!
//! ```compile_fail
//! let b = simrs_consttime::CtBool::TRUE;
//! if b { }  // ERROR: CtBool doesn't implement the required traits
//! ```

/// Opaque constant-time boolean.
///
/// Stores a canonical bit: either `0` (false) or `1` (true).
/// The struct field is private, so the invariant is enforced by
/// construction -- all public constructors canonicalize their input.
///
/// `CtBool` deliberately does *not* implement `PartialEq`, `Eq`,
/// `PartialOrd`, `Ord`, `From<bool>`, or `Into<bool>`, forcing
/// all conversions to go through named methods.
#[derive(Clone, Copy)]
pub struct CtBool(u8);

impl CtBool {
    /// The constant-time `true` value.
    pub const TRUE: Self = Self(1);
    /// The constant-time `false` value.
    pub const FALSE: Self = Self(0);

    /// Construct from a `u8`, taking only bit 0.
    ///
    /// Values 0, 2, 4, ... map to `FALSE`; 1, 3, 5, ... map to `TRUE`.
    #[inline]
    pub const fn from_u8_bit(b: u8) -> Self {
        Self(b & 1)
    }

    /// Construct from a `u64`, taking only bit 0.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn from_u64_bit(b: u64) -> Self {
        Self((b & 1) as u8)
    }

    /// Construct from a `u8`: `FALSE` if zero, `TRUE` if nonzero.
    ///
    /// Uses branchless arithmetic: `(x | x.wrapping_neg()) >> 7` yields
    /// 1 for any nonzero `x`, 0 for zero.
    #[inline]
    pub const fn from_u8_nonzero(x: u8) -> Self {
        Self((x | x.wrapping_neg()) >> 7)
    }

    /// Construct from a `u64`: `FALSE` if zero, `TRUE` if nonzero.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn from_u64_nonzero(x: u64) -> Self {
        Self(((x | x.wrapping_neg()) >> 63) as u8)
    }

    /// Expand to a `u8` mask: `0x00` when false, `0xFF` when true.
    #[inline]
    pub const fn as_u8_mask(self) -> u8 {
        0u8.wrapping_sub(self.0)
    }

    /// Expand to a `u64` mask: `0` when false, `u64::MAX` when true.
    #[inline]
    pub const fn as_u64_mask(self) -> u64 {
        0u64.wrapping_sub(self.0 as u64)
    }

    /// Intentional conversion to `bool`.
    ///
    /// This is the **only** way to branch on a `CtBool`. Every call site
    /// is an explicit acknowledgement that timing information may leak
    /// through the branch.
    #[inline]
    pub const fn into_bool(self) -> bool {
        self.0 != 0
    }

    /// Constant-time NOT.
    #[inline]
    #[must_use]
    pub const fn not(self) -> Self {
        Self(self.0 ^ 1)
    }

    /// Constant-time AND.
    #[inline]
    #[must_use]
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Constant-time OR.
    #[inline]
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Constant-time XOR.
    #[inline]
    #[must_use]
    pub const fn xor(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
}

impl core::fmt::Debug for CtBool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 == 0 {
            f.write_str("CtBool(false)")
        } else {
            f.write_str("CtBool(true)")
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;

    #[test]
    fn constants() {
        assert!(CtBool::TRUE.into_bool());
        assert!(!CtBool::FALSE.into_bool());
    }

    #[test]
    fn masks() {
        assert_eq!(CtBool::TRUE.as_u8_mask(), 0xFF);
        assert_eq!(CtBool::FALSE.as_u8_mask(), 0x00);
        assert_eq!(CtBool::TRUE.as_u64_mask(), u64::MAX);
        assert_eq!(CtBool::FALSE.as_u64_mask(), 0);
    }

    #[test]
    fn from_u8_bit_canonicalization() {
        assert!(!CtBool::from_u8_bit(0).into_bool());
        assert!(CtBool::from_u8_bit(1).into_bool());
        // Even values -> FALSE (bit 0 = 0)
        assert!(!CtBool::from_u8_bit(2).into_bool());
        assert!(!CtBool::from_u8_bit(254).into_bool());
        // Odd values -> TRUE (bit 0 = 1)
        assert!(CtBool::from_u8_bit(3).into_bool());
        assert!(CtBool::from_u8_bit(255).into_bool());
    }

    #[test]
    fn from_u64_bit_canonicalization() {
        assert!(!CtBool::from_u64_bit(0).into_bool());
        assert!(CtBool::from_u64_bit(1).into_bool());
        assert!(!CtBool::from_u64_bit(u64::MAX - 1).into_bool());
        assert!(CtBool::from_u64_bit(u64::MAX).into_bool());
    }

    #[test]
    fn from_u8_nonzero() {
        assert!(!CtBool::from_u8_nonzero(0).into_bool());
        assert!(CtBool::from_u8_nonzero(1).into_bool());
        assert!(CtBool::from_u8_nonzero(0x80).into_bool());
        assert!(CtBool::from_u8_nonzero(0xFF).into_bool());
    }

    #[test]
    fn from_u64_nonzero() {
        assert!(!CtBool::from_u64_nonzero(0).into_bool());
        assert!(CtBool::from_u64_nonzero(1).into_bool());
        assert!(CtBool::from_u64_nonzero(u64::MAX).into_bool());
        assert!(CtBool::from_u64_nonzero(1 << 63).into_bool());
    }

    #[test]
    fn boolean_algebra() {
        let t = CtBool::TRUE;
        let f = CtBool::FALSE;

        // NOT
        assert!(!t.not().into_bool());
        assert!(f.not().into_bool());

        // AND
        assert!(!f.and(f).into_bool());
        assert!(!f.and(t).into_bool());
        assert!(!t.and(f).into_bool());
        assert!(t.and(t).into_bool());

        // OR
        assert!(!f.or(f).into_bool());
        assert!(f.or(t).into_bool());
        assert!(t.or(f).into_bool());
        assert!(t.or(t).into_bool());

        // XOR
        assert!(!f.xor(f).into_bool());
        assert!(f.xor(t).into_bool());
        assert!(t.xor(f).into_bool());
        assert!(!t.xor(t).into_bool());
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", CtBool::TRUE), "CtBool(true)");
        assert_eq!(format!("{:?}", CtBool::FALSE), "CtBool(false)");
    }
}
