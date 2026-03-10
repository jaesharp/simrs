//! Feature-gated Debug/Display redaction for secret byte arrays.
//!
//! `Redact` wraps a reference to a value and controls its `Debug` and
//! `Display` output via feature flags:
//!
//! | Feature                        | Debug / Display output            |
//! |--------------------------------|-----------------------------------|
//! | `redact-secrets-in-logs` (default) | `[REDACTED]`                  |
//! | `fingerprint-secrets-in-logs`  | `[masked:a7b3c2d1]` (salted FNV) |
//! | Neither                        | Pass-through to inner type        |
//!
//! When both features are enabled, `fingerprint-secrets-in-logs` takes
//! priority (the fingerprint is strictly more useful than a static string).
//!
//! The fingerprint is a salted FNV-1a hash truncated to 32 bits. It is
//! deterministic (same input produces the same fingerprint within a build)
//! but non-reversible for cryptographic key lengths (>= 128 bits).
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All operations are performed on stack values.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Debug/Display wrapper that redacts secret values.
///
/// # Example
///
/// ```
/// use simrs_redact::Redact;
///
/// let key = [0xABu8; 16];
/// let dbg = format!("{:?}", Redact(&key));
/// // With default features: "[REDACTED]"
/// // With fingerprint-secrets-in-logs: "[masked:...]"
/// // With no features: raw byte array
/// ```
pub struct Redact<'a, T: AsBytes + core::fmt::Debug + ?Sized>(pub &'a T);

/// Trait for types that can provide a byte-slice view for fingerprinting.
pub trait AsBytes {
    /// Return the raw bytes of this value.
    fn as_bytes_for_fingerprint(&self) -> &[u8];
}

impl<const N: usize> AsBytes for [u8; N] {
    fn as_bytes_for_fingerprint(&self) -> &[u8] {
        self
    }
}

impl AsBytes for [u8] {
    fn as_bytes_for_fingerprint(&self) -> &[u8] {
        self
    }
}

/// Compute a salted FNV-1a 32-bit fingerprint.
///
/// The salt differentiates this from standard FNV-1a to prevent
/// lookup against pre-computed tables.
#[cfg(any(feature = "fingerprint-secrets-in-logs", test))]
const fn fingerprint(data: &[u8]) -> u32 {
    // FNV-1a with a custom offset basis (salt).
    const SALT: u32 = 0x5EC8_E7A1; // arbitrary non-standard basis
    const PRIME: u32 = 0x0100_0193; // FNV-1a 32-bit prime

    let mut hash = SALT;
    let mut i = 0;
    while i < data.len() {
        hash ^= data[i] as u32;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}

// ---------------------------------------------------------------------------
// Debug impl -- three-way cfg
// ---------------------------------------------------------------------------

// Fingerprint mode takes priority when both features are enabled.
#[cfg(feature = "fingerprint-secrets-in-logs")]
impl<T: AsBytes + core::fmt::Debug + ?Sized> core::fmt::Debug for Redact<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fp = fingerprint(self.0.as_bytes_for_fingerprint());
        write!(f, "[masked:{fp:08x}]")
    }
}

// Plain redaction when fingerprint feature is not enabled.
#[cfg(all(
    feature = "redact-secrets-in-logs",
    not(feature = "fingerprint-secrets-in-logs")
))]
impl<T: AsBytes + core::fmt::Debug + ?Sized> core::fmt::Debug for Redact<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Raw pass-through when no redaction features are enabled.
#[cfg(not(any(
    feature = "redact-secrets-in-logs",
    feature = "fingerprint-secrets-in-logs"
)))]
impl<T: AsBytes + core::fmt::Debug + ?Sized> core::fmt::Debug for Redact<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// Display impl -- mirrors Debug behaviour
// ---------------------------------------------------------------------------

#[cfg(feature = "fingerprint-secrets-in-logs")]
impl<T: AsBytes + core::fmt::Debug + ?Sized> core::fmt::Display for Redact<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fp = fingerprint(self.0.as_bytes_for_fingerprint());
        write!(f, "[masked:{fp:08x}]")
    }
}

#[cfg(all(
    feature = "redact-secrets-in-logs",
    not(feature = "fingerprint-secrets-in-logs")
))]
impl<T: AsBytes + core::fmt::Debug + ?Sized> core::fmt::Display for Redact<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(not(any(
    feature = "redact-secrets-in-logs",
    feature = "fingerprint-secrets-in-logs"
)))]
impl<T: AsBytes + core::fmt::Debug + ?Sized> core::fmt::Display for Redact<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
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
    fn fingerprint_deterministic() {
        let a = [0xABu8; 16];
        assert_eq!(fingerprint(&a), fingerprint(&a));
    }

    #[test]
    fn fingerprint_different_inputs_differ() {
        let a = [0xABu8; 16];
        let b = [0xCDu8; 16];
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn debug_format_not_empty() {
        let key = [0xABu8; 16];
        let s = format!("{:?}", Redact(&key));
        assert!(!s.is_empty());
    }

    #[test]
    fn display_format_not_empty() {
        let key = [0xABu8; 16];
        let s = format!("{}", Redact(&key));
        assert!(!s.is_empty());
    }

    #[test]
    fn debug_and_display_agree() {
        let key = [0x42u8; 16];
        assert_eq!(format!("{:?}", Redact(&key)), format!("{}", Redact(&key)));
    }

    #[cfg(all(
        feature = "redact-secrets-in-logs",
        not(feature = "fingerprint-secrets-in-logs")
    ))]
    #[test]
    fn redact_shows_redacted() {
        let key = [0xABu8; 16];
        assert_eq!(format!("{:?}", Redact(&key)), "[REDACTED]");
        assert_eq!(format!("{}", Redact(&key)), "[REDACTED]");
    }

    #[cfg(feature = "fingerprint-secrets-in-logs")]
    #[test]
    fn fingerprint_shows_masked() {
        let key = [0xABu8; 16];
        let s = format!("{:?}", Redact(&key));
        assert!(s.starts_with("[masked:"), "expected masked output, got: {s}");
        assert_eq!(s.len(), 17); // "[masked:" (8) + 8 hex chars + "]" (1) = 17
    }

    #[cfg(feature = "fingerprint-secrets-in-logs")]
    #[test]
    fn same_key_same_fingerprint() {
        let key = [0x11u8; 16];
        let s1 = format!("{:?}", Redact(&key));
        let s2 = format!("{:?}", Redact(&key));
        assert_eq!(s1, s2);
    }

    #[cfg(feature = "fingerprint-secrets-in-logs")]
    #[test]
    fn different_keys_different_fingerprint() {
        let a = [0x11u8; 16];
        let b = [0x22u8; 16];
        assert_ne!(format!("{:?}", Redact(&a)), format!("{:?}", Redact(&b)));
    }

    #[test]
    fn works_with_slice() {
        let data: &[u8] = &[0x01, 0x02, 0x03];
        let s = format!("{:?}", Redact(data));
        assert!(!s.is_empty());
    }
}
