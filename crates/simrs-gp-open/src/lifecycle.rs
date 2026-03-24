//! Card and applet lifecycle state machines per GP 2.1.1 Chapter 5.
//!
//! # Card Lifecycle (GP 2.1.1 clause 5.1, Figure 5-1)
//!
//! ```text
//! OP_READY -> INITIALIZED -> SECURED -> CARD_LOCKED
//!                                ^          |
//!                                +----------+ (unlock)
//!
//! any state -------> TERMINATED (irreversible)
//! ```
//!
//! # Applet Lifecycle (GP 2.1.1 clause 5.3, Figure 5-2)
//!
//! ```text
//! INSTALLED -> SELECTABLE -> PERSONALIZED
//!                   |
//!                   v
//!              LOCKED (from SELECTABLE only)
//! ```

/// Card lifecycle states per GP 2.1.1 clause 5.1, Table 5-1.
///
/// Each state value encodes as a bitmask where lower bits accumulate:
/// - `OP_READY`:    `0x01` (bit 0)
/// - `INITIALIZED`: `0x07` (bits 0-2)
/// - `SECURED`:     `0x0F` (bits 0-3)
/// - `CARD_LOCKED`: `0x7F` (bits 0-6)
/// - `TERMINATED`:  `0xFF` (all bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CardLifecycle {
    /// Card is ready for content management (pre-issuance).
    OpReady = 0x01,
    /// Card has been initialized with initial key set.
    Initialized = 0x07,
    /// Card is in secured (post-issuance) state. Normal operating mode.
    Secured = 0x0F,
    /// Card has been locked (reversible). Management commands only.
    CardLocked = 0x7F,
    /// Card is permanently terminated. No further operations possible.
    Terminated = 0xFF,
}

impl CardLifecycle {
    /// Attempt to transition to a new lifecycle state.
    ///
    /// Returns `Some(new_state)` if the transition is valid per GP 2.1.1
    /// Figure 5-1, or `None` if the transition is not allowed.
    ///
    /// Valid transitions:
    /// - `OpReady` -> `Initialized`
    /// - `Initialized` -> `Secured`
    /// - `Secured` -> `CardLocked`
    /// - `CardLocked` -> `Secured` (unlock)
    /// - Any -> `Terminated` (irreversible)
    pub const fn transition(self, target: Self) -> Option<Self> {
        match (self, target) {
            (Self::OpReady, Self::Initialized) => Some(Self::Initialized),
            (Self::Initialized | Self::CardLocked, Self::Secured) => Some(Self::Secured),
            (Self::Secured, Self::CardLocked) => Some(Self::CardLocked),
            (_, Self::Terminated) => Some(Self::Terminated),
            _ => None,
        }
    }

    /// Encode as the GP 2.1.1 byte value.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Decode from a GP 2.1.1 byte value.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::OpReady),
            0x07 => Some(Self::Initialized),
            0x0F => Some(Self::Secured),
            0x7F => Some(Self::CardLocked),
            0xFF => Some(Self::Terminated),
            _ => None,
        }
    }
}

/// Applet lifecycle states per GP 2.1.1 clause 5.3, Table 5-2.
///
/// Bit 7 (0x80) indicates the locked flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AppletLifecycle {
    /// Applet has been loaded and installed but is not yet selectable.
    Installed = 0x03,
    /// Applet is available for selection via SELECT [by AID].
    Selectable = 0x07,
    /// Applet has been personalized (application-specific data written).
    Personalized = 0x0F,
    /// Applet has been locked. Not available for selection.
    Locked = 0x83,
}

impl AppletLifecycle {
    /// Attempt to transition to a new lifecycle state.
    ///
    /// Returns `Some(new_state)` if the transition is valid, or `None` if not.
    ///
    /// Valid transitions:
    /// - `Installed` -> `Selectable`
    /// - `Selectable` -> `Personalized`
    /// - `Selectable` -> `Locked`
    /// - `Locked` -> `Selectable` (unlock)
    /// - `Personalized` -> `Locked`
    /// - `Locked` -> `Personalized` (unlock from personalized+locked)
    pub const fn transition(self, target: Self) -> Option<Self> {
        match (self, target) {
            (Self::Installed | Self::Locked, Self::Selectable) => Some(Self::Selectable),
            (Self::Selectable | Self::Locked, Self::Personalized) => Some(Self::Personalized),
            (Self::Selectable | Self::Personalized, Self::Locked) => Some(Self::Locked),
            _ => None,
        }
    }

    /// Whether this applet is selectable (SELECT [by AID] will succeed).
    pub const fn is_selectable(self) -> bool {
        matches!(self, Self::Selectable | Self::Personalized)
    }

    /// Encode as the GP 2.1.1 byte value.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Decode from a GP 2.1.1 byte value.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x03 => Some(Self::Installed),
            0x07 => Some(Self::Selectable),
            0x0F => Some(Self::Personalized),
            0x83 => Some(Self::Locked),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Card lifecycle tests --

    #[test]
    fn card_lifecycle_valid_forward_transitions() {
        assert_eq!(
            CardLifecycle::OpReady.transition(CardLifecycle::Initialized),
            Some(CardLifecycle::Initialized)
        );
        assert_eq!(
            CardLifecycle::Initialized.transition(CardLifecycle::Secured),
            Some(CardLifecycle::Secured)
        );
        assert_eq!(
            CardLifecycle::Secured.transition(CardLifecycle::CardLocked),
            Some(CardLifecycle::CardLocked)
        );
    }

    #[test]
    fn card_lifecycle_unlock() {
        assert_eq!(
            CardLifecycle::CardLocked.transition(CardLifecycle::Secured),
            Some(CardLifecycle::Secured)
        );
    }

    #[test]
    fn card_lifecycle_terminate_from_any() {
        for &state in &[
            CardLifecycle::OpReady,
            CardLifecycle::Initialized,
            CardLifecycle::Secured,
            CardLifecycle::CardLocked,
            CardLifecycle::Terminated,
        ] {
            assert_eq!(
                state.transition(CardLifecycle::Terminated),
                Some(CardLifecycle::Terminated),
                "should terminate from {state:?}",
            );
        }
    }

    #[test]
    fn card_lifecycle_invalid_transitions() {
        // Can't skip states.
        assert_eq!(
            CardLifecycle::OpReady.transition(CardLifecycle::Secured),
            None
        );
        assert_eq!(
            CardLifecycle::OpReady.transition(CardLifecycle::CardLocked),
            None
        );
        // Can't go backwards (except unlock).
        assert_eq!(
            CardLifecycle::Initialized.transition(CardLifecycle::OpReady),
            None
        );
        assert_eq!(
            CardLifecycle::Secured.transition(CardLifecycle::Initialized),
            None
        );
        // Terminated is absorbing (except to Terminated itself, which is idempotent).
        assert_eq!(
            CardLifecycle::Terminated.transition(CardLifecycle::OpReady),
            None
        );
        assert_eq!(
            CardLifecycle::Terminated.transition(CardLifecycle::Secured),
            None
        );
    }

    #[test]
    fn card_lifecycle_byte_roundtrip() {
        for &state in &[
            CardLifecycle::OpReady,
            CardLifecycle::Initialized,
            CardLifecycle::Secured,
            CardLifecycle::CardLocked,
            CardLifecycle::Terminated,
        ] {
            let b = state.to_byte();
            assert_eq!(CardLifecycle::from_byte(b), Some(state));
        }
    }

    #[test]
    fn card_lifecycle_from_byte_invalid() {
        assert_eq!(CardLifecycle::from_byte(0x00), None);
        assert_eq!(CardLifecycle::from_byte(0x03), None);
        assert_eq!(CardLifecycle::from_byte(0x42), None);
    }

    // -- Applet lifecycle tests --

    #[test]
    fn applet_lifecycle_valid_transitions() {
        assert_eq!(
            AppletLifecycle::Installed.transition(AppletLifecycle::Selectable),
            Some(AppletLifecycle::Selectable)
        );
        assert_eq!(
            AppletLifecycle::Selectable.transition(AppletLifecycle::Personalized),
            Some(AppletLifecycle::Personalized)
        );
        assert_eq!(
            AppletLifecycle::Selectable.transition(AppletLifecycle::Locked),
            Some(AppletLifecycle::Locked)
        );
        assert_eq!(
            AppletLifecycle::Personalized.transition(AppletLifecycle::Locked),
            Some(AppletLifecycle::Locked)
        );
    }

    #[test]
    fn applet_lifecycle_unlock() {
        assert_eq!(
            AppletLifecycle::Locked.transition(AppletLifecycle::Selectable),
            Some(AppletLifecycle::Selectable)
        );
        assert_eq!(
            AppletLifecycle::Locked.transition(AppletLifecycle::Personalized),
            Some(AppletLifecycle::Personalized)
        );
    }

    #[test]
    fn applet_lifecycle_invalid_transitions() {
        // Can't skip installed -> personalized.
        assert_eq!(
            AppletLifecycle::Installed.transition(AppletLifecycle::Personalized),
            None
        );
        // Can't go backwards from personalized to selectable.
        assert_eq!(
            AppletLifecycle::Personalized.transition(AppletLifecycle::Selectable),
            None
        );
        // Can't lock installed directly.
        assert_eq!(
            AppletLifecycle::Installed.transition(AppletLifecycle::Locked),
            None
        );
    }

    #[test]
    fn applet_lifecycle_is_selectable() {
        assert!(!AppletLifecycle::Installed.is_selectable());
        assert!(AppletLifecycle::Selectable.is_selectable());
        assert!(AppletLifecycle::Personalized.is_selectable());
        assert!(!AppletLifecycle::Locked.is_selectable());
    }

    #[test]
    fn applet_lifecycle_byte_roundtrip() {
        for &state in &[
            AppletLifecycle::Installed,
            AppletLifecycle::Selectable,
            AppletLifecycle::Personalized,
            AppletLifecycle::Locked,
        ] {
            let b = state.to_byte();
            assert_eq!(AppletLifecycle::from_byte(b), Some(state));
        }
    }

    #[test]
    fn applet_lifecycle_from_byte_invalid() {
        assert_eq!(AppletLifecycle::from_byte(0x00), None);
        assert_eq!(AppletLifecycle::from_byte(0x01), None);
        assert_eq!(AppletLifecycle::from_byte(0xFF), None);
    }
}
