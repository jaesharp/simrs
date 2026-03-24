//! Context-based access control per [JC RE 2.1.1 Chapter 6](../../../../telecom-standards/javacard/2.1.1/JCRESpec.pdf).
//!
//! The `JavaCard` firewall prevents applets from accessing objects owned by
//! other applets. Every object carries an owner context (the package ID of
//! the applet that created it). Field and array accesses are checked against
//! the currently active applet context.
//!
//! # Security Model
//!
//! - Each applet package has a unique context ID (0..`MAX_PACKAGES`)
//! - Object creation tags the object with the creator's context
//! - Every field read/write and array access checks `current_context == owner_context`
//! - Cross-context access raises [`SecurityException`]
//! - The JCRE context (ID 0) has special privileges (not yet implemented)

/// Error raised when the firewall denies a cross-context access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityException;

/// Check whether the current execution context may access an object
/// owned by `owner_context`.
///
/// Per JCRE Chapter 6: access is permitted only when the current context
/// matches the owner context. Shareable interface objects (SIOs) and
/// JCRE-owned objects are future extensions.
///
/// # Errors
///
/// Returns [`SecurityException`] if `current_context != owner_context`.
pub const fn check_access(current_context: u8, owner_context: u8) -> Result<(), SecurityException> {
    if current_context == owner_context {
        Ok(())
    } else {
        Err(SecurityException)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_context_allows_access() {
        assert!(check_access(1, 1).is_ok());
        assert!(check_access(0, 0).is_ok());
        assert!(check_access(255, 255).is_ok());
    }

    #[test]
    fn different_context_denies_access() {
        assert_eq!(check_access(1, 2), Err(SecurityException));
        assert_eq!(check_access(0, 1), Err(SecurityException));
        assert_eq!(check_access(254, 255), Err(SecurityException));
    }
}
