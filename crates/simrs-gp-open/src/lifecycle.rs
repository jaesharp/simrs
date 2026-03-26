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
/// Supports standard states and application-specific states:
/// - 0x03: INSTALLED
/// - 0x07: SELECTABLE
/// - 0x0F: PERSONALIZED
/// - 0x07-0x7F (bits 0-2 set): application-specific states
/// - bit 7 (0x80): LOCKED flag (preserves lower bits for unlock)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppletLifecycle(u8);

#[allow(non_upper_case_globals)]
impl AppletLifecycle {
    /// Installed but not yet selectable (0x03).
    pub const Installed: Self = Self(0x03);
    /// Available for selection (0x07).
    pub const Selectable: Self = Self(0x07);
    /// Personalization complete (0x0F).
    pub const Personalized: Self = Self(0x0F);
    /// Locked (0x83). Not selectable.
    pub const Locked: Self = Self(0x83);

    /// Attempt to transition to a new lifecycle state.
    ///
    /// GP 2.1.1 clause 5.3 transitions:
    /// - INSTALLED -> SELECTABLE (or any app-specific state with bits 0-2 set)
    /// - SELECTABLE -> PERSONALIZED, app-specific, or LOCKED
    /// - PERSONALIZED -> LOCKED
    /// - Any -> LOCKED (sets bit 7)
    /// - LOCKED -> previous state (clears bit 7)
    pub const fn transition(self, target: Self) -> Option<Self> {
        let cur = self.0;
        let tgt = target.0;

        // Lock: any state can be locked.
        if tgt & 0x80 != 0 {
            // Locked target: combine lock bit with current state bits.
            return Some(Self(cur | 0x80));
        }

        // Unlock: LOCKED -> target (restore previous state).
        if cur & 0x80 != 0 {
            // Can unlock to any non-locked state that bits 0-6 allow.
            return Some(Self(tgt & 0x7F));
        }

        // Forward transitions (no lock involved).
        match (cur, tgt) {
            // INSTALLED -> SELECTABLE only (must go through SELECTABLE first).
            (0x03, 0x07) => Some(Self(tgt)),
            // From SELECTABLE or higher: can transition to any higher state
            // where bits 0-2 are set.
            (_, _) if cur >= 0x07 && cur < 0x80 && tgt > cur && tgt & 0x07 == 0x07 => {
                Some(Self(tgt))
            }
            _ => None,
        }
    }

    /// Whether this applet is selectable (SELECT [by AID] will succeed).
    ///
    /// Selectable if: value >= 0x07 AND not locked (bit 7 clear).
    pub const fn is_selectable(self) -> bool {
        self.0 >= 0x07 && self.0 & 0x80 == 0
    }

    /// Encode as the GP 2.1.1 byte value.
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    /// Decode from a GP 2.1.1 byte value.
    pub const fn from_byte(b: u8) -> Option<Self> {
        // GP 2.1.1 clause 5.3:
        // - 0x03: INSTALLED
        // - bits 0-2 set (& 0x07 == 0x07): SELECTABLE and above
        // - bit 7 set: LOCKED variant of any state
        let base = b & 0x7F;
        if base == 0x03 || (base & 0x07 == 0x07) {
            Some(Self(b))
        } else {
            None
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
        // Locking Selectable: 0x07 | 0x80 = 0x87
        let locked_sel = AppletLifecycle::Selectable.transition(AppletLifecycle::Locked);
        assert!(locked_sel.is_some());
        assert_eq!(locked_sel.unwrap().to_byte(), 0x87);
        // Locking Personalized: 0x0F | 0x80 = 0x8F
        let locked_pers = AppletLifecycle::Personalized.transition(AppletLifecycle::Locked);
        assert!(locked_pers.is_some());
        assert_eq!(locked_pers.unwrap().to_byte(), 0x8F);
    }

    #[test]
    fn applet_lifecycle_unlock() {
        // Unlock from locked+selectable (0x87) to selectable (0x07).
        let locked_sel = AppletLifecycle::from_byte(0x87).unwrap();
        assert_eq!(
            locked_sel.transition(AppletLifecycle::Selectable),
            Some(AppletLifecycle::Selectable)
        );
        // Unlock from locked+personalized (0x8F) to personalized (0x0F).
        let locked_pers = AppletLifecycle::from_byte(0x8F).unwrap();
        assert_eq!(
            locked_pers.transition(AppletLifecycle::Personalized),
            Some(AppletLifecycle::Personalized)
        );
    }

    #[test]
    fn applet_lifecycle_app_specific_state() {
        // Application-specific state 0x17 (bits 0-2 set).
        let specific = AppletLifecycle::from_byte(0x17);
        assert!(specific.is_some());
        assert!(specific.unwrap().is_selectable());
        // Transition from Selectable to app-specific.
        assert_eq!(
            AppletLifecycle::Selectable.transition(specific.unwrap()),
            specific
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
        ] {
            let b = state.to_byte();
            assert_eq!(AppletLifecycle::from_byte(b), Some(state));
        }
        // Locked variants preserve previous state bits.
        assert_eq!(AppletLifecycle::from_byte(0x83), Some(AppletLifecycle::from_byte(0x83).unwrap()));
        assert_eq!(AppletLifecycle::from_byte(0x87), Some(AppletLifecycle::from_byte(0x87).unwrap()));
    }

    #[test]
    fn applet_lifecycle_from_byte_invalid() {
        assert_eq!(AppletLifecycle::from_byte(0x00), None);
        assert_eq!(AppletLifecycle::from_byte(0x01), None);
        // 0xFF is valid: 0xFF & 0x07 == 0x07, so it's a locked app-specific state.
        assert!(AppletLifecycle::from_byte(0xFF).is_some());
    }
}
