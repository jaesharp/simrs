//! Shared card event/response types for SIM and `GlobalPlatform` cards.
//!
//! This tiny foundation crate defines the [`SimEvent`] / [`SimResponse`]
//! interface that both `simrs-sim` (standalone SIM/USIM) and `simrs-gp-card`
//! (`GlobalPlatform` card) implement. By sharing these types, both card
//! personalities work with the same infrastructure: HLE, QEMU bridge,
//! interposer, fuzzer, and snapshot.
//!
//! Also provides [`ResetKind`], [`ResetEffects`], and [`CardState`] for
//! lifecycle management.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation. No dependencies
//! except `simrs-iso7816` (for [`StatusWord`]).
#![no_std]

#[cfg(feature = "std")]
extern crate std;

use simrs_iso7816::StatusWord;

// ---------------------------------------------------------------------------
// Lifecycle policy
// ---------------------------------------------------------------------------

/// Distinguishes cold reset (power-on) from warm reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetKind {
    /// Cold reset -- card was powered on from the Off state, or the host
    /// issued a full power cycle.
    Cold,
    /// Warm reset -- RST line asserted while Vcc remains applied.
    Warm,
}

/// Per-subsystem flags controlling what session state is cleared on reset.
///
/// Each flag corresponds to a discrete piece of session state. A value of
/// `true` means the subsystem is cleared; `false` preserves it across the
/// reset boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ResetEffects {
    /// Clear PIN/PUK verified flags (re-verification required).
    pub clear_pin_verified: bool,
    /// Clear the GET RESPONSE queue (no stale data from prior session).
    pub clear_response_queue: bool,
    /// Reset file selection context (MF implicitly selected).
    pub clear_file_selection: bool,
    /// Close supplementary logical channels 1-3.
    ///
    /// USIM-specific; has no effect when only the `gsm` feature is enabled.
    pub clear_logical_channels: bool,
    /// Reset the proactive (STK) session and terminal capability.
    ///
    /// USIM-specific; has no effect when only the `gsm` feature is enabled.
    pub clear_proactive_session: bool,
    /// Clear the last AID match flag.
    ///
    /// USIM-specific; has no effect when only the `gsm` feature is enabled.
    pub clear_last_aid_match: bool,
}

impl ResetEffects {
    /// All subsystems cleared -- matches [ETSI TS 102 221 V18.3.0 clause 6.5](https://www.etsi.org/) reset procedures.
    pub const fn all() -> Self {
        Self {
            clear_pin_verified: true,
            clear_response_queue: true,
            clear_file_selection: true,
            clear_logical_channels: true,
            clear_proactive_session: true,
            clear_last_aid_match: true,
        }
    }

    /// No subsystems cleared -- everything preserved across reset.
    pub const fn none() -> Self {
        Self {
            clear_pin_verified: false,
            clear_response_queue: false,
            clear_file_selection: false,
            clear_logical_channels: false,
            clear_proactive_session: false,
            clear_last_aid_match: false,
        }
    }
}

/// Standard reset policy: clear all session state on both cold and warm
/// reset. This is the default and matches ETSI TS 102 221 V18.3.0
/// clause 6.5 (reset procedures).
pub const fn standard_reset_policy(_kind: ResetKind) -> ResetEffects {
    ResetEffects::all()
}

// ---------------------------------------------------------------------------
// Card state
// ---------------------------------------------------------------------------

/// Internal card power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardState {
    /// Card is not powered.
    Off,
    /// Card is powered and ready for APDU exchange.
    Ready,
}

// ---------------------------------------------------------------------------
// Events and responses
// ---------------------------------------------------------------------------

/// An event delivered to the card by the terminal or host.
///
/// Per ISO/IEC 7816-3, the card lifecycle is:
/// 1. `PowerOn` -- card activation, returns ATR
/// 2. `Apdu` -- command exchange (repeats)
/// 3. `Reset` -- warm reset, returns ATR
/// 4. `PowerOff` -- card deactivation, returns `Ignored`
///
/// The `Tick` variant is an extension for advancing UICC-side timers
/// (per ETSI TS 102 223 V18.2.0 clause 6.6.21). Since `no_std` has no clock,
/// the caller supplies elapsed seconds.
#[derive(Debug, Clone, Copy)]
pub enum SimEvent<'a> {
    /// Card power-on (cold reset). Returns ATR.
    PowerOn,
    /// Warm reset. Returns ATR.
    Reset,
    /// Card deactivation. Returns `Ignored`.
    ///
    /// After `PowerOff`, subsequent APDUs return `Ignored` until the
    /// next `PowerOn`.
    PowerOff,
    /// APDU command (raw bytes, at least 4 for CLA INS P1 P2).
    Apdu(&'a [u8]),
    /// Advance UICC-side proactive timers by `elapsed_secs`.
    ///
    /// Returns `Ignored` (timers are internal state).
    Tick(u32),
}

/// A response produced by the card.
#[derive(Debug)]
#[must_use]
pub enum SimResponse<'a> {
    /// Answer To Reset bytes.
    Atr(&'a [u8]),
    /// APDU response: data (may be empty) + status word.
    Apdu {
        /// Response data (empty for SW-only responses).
        data: &'a [u8],
        /// Status word (2 bytes).
        sw: StatusWord,
    },
    /// Event was ignored (malformed APDU, card not powered on, etc.).
    Ignored,
}
