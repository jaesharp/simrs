//! Top-level SIM/USIM simulator -- state machine orchestrator.
//!
//! Provides the [`Sim`] type: an event-driven state machine that accepts
//! [`SimEvent`] messages and produces [`SimResponse`] messages. Routes APDUs
//! to the appropriate application layer (GSM or USIM) based on the CLA byte.
//!
//! # Architecture
//!
//! ```text
//! SimEvent::Apdu(bytes)
//!     -> Command::parse(bytes)
//!     -> CLA dispatch -> GsmApp (0xA0) | UsimApp (0x00/0x80)
//!     -> SimResponse::Apdu { data, sw }
//! ```
//!
//! # Lifecycle Policy
//!
//! On `PowerOn` (cold reset) and `Reset` (warm reset), the card invokes
//! a configurable reset policy (`fn(ResetKind) -> ResetEffects`) to decide
//! which session state is cleared. The default [`standard_reset_policy`]
//! clears everything on both cold and warm resets, matching [ETSI TS 102 221
//! V18.3.0 clause 6.5](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A211%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C582%5D). Use [`Sim::with_reset_policy`] to customize this behavior
//! for card profiles that preserve state across warm resets.
//!
//! # Features
//!
//! - `gsm` -- enables [GSM 11.11 (TS 51.011 V4.15.0)](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf) application layer (CLA=`0xA0`)
//! - `usim` -- enables 3GPP USIM application layer (CLA=`0x00`/`0x80`)
//!
//! Enable one or both. With neither feature, all APDUs return `6E 00`.
//!
//! # `no_std`
//!
//! This crate is `no_std`. All buffers are stack-allocated with a const
//! generic `RSP_CAP` (default 256 bytes).
//!
//! # Example
//!
//! ```ignore
//! use simrs_sim::{Sim, SimEvent, SimResponse};
//! use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
//! use simrs_fs::{DfDef, Fid};
//!
//! static MF: DfDef = DfDef { fid: Fid::new(0x3F00), children: &[] };
//! static ATR: [u8; 2] = [0x3B, 0x00];
//!
//! let gsm = simrs_gsm::GsmApp::new(&MF, simrs_gsm::SubscriberKey::classify([0u8; 16]));
//! let mil = MilenageParams::with_defaults(
//!     SubscriberKey::classify([0u8; 16]),
//!     OperatorVariant::operator_cipher([0u8; 16]),
//! );
//! let usim = simrs_usim::UsimApp::new(&MF, &[], mil);
//! let mut sim = Sim::<MilenageParams, 256>::new(&ATR, gsm, usim);
//!
//! // Power on returns ATR
//! let rsp = sim.process(SimEvent::PowerOn);
//! assert!(matches!(rsp, SimResponse::Atr(&[0x3B, 0x00])));
//!
//! // Unsupported CLA (0xF0 is never routed)
//! let rsp = sim.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
//! match rsp {
//!     SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x6E, 0x00] => {} // class not supported
//!     _ => panic!("expected 6E 00"),
//! }
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// Many 3GPP terms used in docs (CLA, USIM, ATR, etc.)
#![allow(clippy::doc_markdown)]

#[cfg(not(any(feature = "gsm", feature = "usim")))]
use simrs_fs::DfDef;
#[cfg(feature = "gsm")]
use simrs_gsm::GsmApp;
use simrs_iso7816::{write_sw, Command, StatusWord};
use simrs_milenage::{AuthenticationAlgorithm, MilenageParams};
#[cfg(feature = "usim")]
use simrs_usim::UsimApp;

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
    /// All subsystems cleared -- matches [ETSI TS 102 221 V18.3.0 clause 6.5](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A211%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C582%5D) reset procedures.
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
/// reset. This is the default used by [`Sim::new`] and matches ETSI TS
/// 102 221 V18.3.0 clause 6.5 (reset procedures).
///
/// Both cold and warm resets clear all session state identically.
/// Custom policies may differentiate by matching on `kind` -- pass a
/// custom `fn(ResetKind) -> ResetEffects` to [`Sim::with_reset_policy`].
pub const fn standard_reset_policy(_kind: ResetKind) -> ResetEffects {
    ResetEffects::all()
}

// ---------------------------------------------------------------------------
// Snapshot format header
// ---------------------------------------------------------------------------

/// Magic bytes identifying a simrs snapshot blob.
const SNAPSHOT_MAGIC: [u8; 4] = *b"SRSS";

/// Snapshot format version. Increment when the layout changes.
const SNAPSHOT_VERSION: u8 = 1;

/// Size of the snapshot header: magic (4) + version (1) + feature flags (1).
pub const SNAPSHOT_HEADER_SIZE: usize = 6;

/// Feature flag: GSM application present.
const SNAP_FLAG_GSM: u8 = 1 << 0;
/// Feature flag: USIM application present.
const SNAP_FLAG_USIM: u8 = 1 << 1;

/// Build the feature flags byte for the current compilation.
const fn snapshot_feature_flags() -> u8 {
    let mut flags = 0u8;
    #[cfg(feature = "gsm")]
    {
        flags |= SNAP_FLAG_GSM;
    }
    #[cfg(feature = "usim")]
    {
        flags |= SNAP_FLAG_USIM;
    }
    flags
}

// ---------------------------------------------------------------------------
// State hash buffer upper bound
// ---------------------------------------------------------------------------

// Rust does not allow `Self::SNAPSHOT_SIZE` in array-length position for
// generic types.  We compute a fixed upper bound from the non-generic
// component sizes.  The `Sim::state_hash` method uses a `debug_assert_eq`
// to verify the bound at runtime.
#[cfg(all(feature = "gsm", feature = "usim"))]
const STATE_HASH_BUF: usize = SNAPSHOT_HEADER_SIZE + 1 + GsmApp::SNAPSHOT_SIZE + {
    // UsimApp<A>::SNAPSHOT_SIZE depends on A::SNAPSHOT_SIZE.
    // MilenageParams::SNAPSHOT_SIZE is the largest known auth algorithm.
    // TuakParams would be similar.  Add headroom for future algorithms.
    simrs_usim::UsimApp::<MilenageParams>::SNAPSHOT_SIZE + 256
};

#[cfg(all(feature = "gsm", not(feature = "usim")))]
const STATE_HASH_BUF: usize = SNAPSHOT_HEADER_SIZE + 1 + GsmApp::SNAPSHOT_SIZE + 256;

#[cfg(all(not(feature = "gsm"), feature = "usim"))]
const STATE_HASH_BUF: usize =
    SNAPSHOT_HEADER_SIZE + 1 + simrs_usim::UsimApp::<MilenageParams>::SNAPSHOT_SIZE + 256;

#[cfg(all(not(feature = "gsm"), not(feature = "usim")))]
const STATE_HASH_BUF: usize = SNAPSHOT_HEADER_SIZE + 256;

// ---------------------------------------------------------------------------
// CLA byte classification
// ---------------------------------------------------------------------------

/// CLA family classification per [ETSI TS 102 221 V18.3.0 clause 10.1.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A311%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C531%5D).
///
/// Strips logical channel bits from the CLA byte and classifies the
/// command into a routing family. The original CLA byte is passed to
/// the application handler unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaFamily {
    /// Interindustry: (CLA & 0xF0) in {0x00, 0x40, 0x60}.
    Interindustry,
    /// ETSI proprietary: (CLA & 0xF0) in {0x80, 0xC0, 0xE0}.
    EtsiProprietary,
    /// GSM legacy: CLA == 0xA0.
    Gsm,
    /// Unknown / unsupported CLA family.
    Unknown,
}

/// Classify a CLA byte into a routing family.
const fn classify_cla(cla: u8) -> ClaFamily {
    // GSM legacy is an exact match (0xA0).
    if cla == CLA_GSM_RAW {
        return ClaFamily::Gsm;
    }
    match cla & 0xF0 {
        // Interindustry families (ISO 7816-4):
        // 0x0X: first interindustry, channels 0-3
        // 0x4X: first interindustry, channels 4-19 (further coding)
        // 0x6X: second interindustry, channels 0-3 (unless RFU)
        0x00 | 0x40 | 0x60 => ClaFamily::Interindustry,
        // ETSI proprietary families:
        // 0x8X: proprietary, channels 0-3
        // 0xCX: proprietary, channels 4-19 (further coding)
        // 0xEX: proprietary, channels 0-3 (further coding)
        0x80 | 0xC0 | 0xE0 => ClaFamily::EtsiProprietary,
        _ => ClaFamily::Unknown,
    }
}

/// Raw GSM CLA value for classification (always needed, not feature-gated).
const CLA_GSM_RAW: u8 = 0xA0;

// ---------------------------------------------------------------------------
// SimEvent / SimResponse
// ---------------------------------------------------------------------------

/// An event delivered to the SIM card.
///
/// Per ISO/IEC 7816-3, the card lifecycle is:
/// 1. `PowerOn` -- card activation, returns ATR
/// 2. `Apdu` -- command exchange (repeats)
/// 3. `Reset` -- warm reset, returns ATR
/// 4. `PowerOff` -- card deactivation, returns `Ignored`
///
/// `PowerOn` and `Reset` invoke the configured reset policy to determine
/// which session state is cleared. See [`Sim::with_reset_policy`] and
/// [`ResetEffects`].
///
/// The `Tick` variant is an extension for advancing UICC-side timers
/// (per [ETSI TS 102 223 V18.2.0 clause 6.6.21](../../../docs/specs/etsi/ts-102-223/ts_102223v180200p.pdf#%5B%7B%22num%22%3A232%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C199%5D)). Since `no_std` has no clock,
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
    /// Returns `Ignored` (timers are internal state). Check for expired
    /// timers via `usim_app_mut().proactive_state().take_expired_timer()`.
    Tick(u32),
}

/// A response produced by the SIM card.
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

// ---------------------------------------------------------------------------
// Card state
// ---------------------------------------------------------------------------

/// Internal card power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardState {
    /// Card is not powered.
    Off,
    /// Card is powered and ready for APDU exchange.
    Ready,
}

// ---------------------------------------------------------------------------
// Sim
// ---------------------------------------------------------------------------

/// Top-level SIM card simulator.
///
/// `RSP_CAP` is the internal response buffer size (default 256).
/// This buffer is used to hold APDU responses from the application layers.
///
/// # RSP_CAP sizing
///
/// Minimum recommended values:
/// - No features: 2 (SW only)
/// - `gsm` only: 25 (STATUS = 23 bytes + SW)
/// - `usim` only: 47 (AUTHENTICATE success = 45 bytes + SW)
/// - Both features: 47
///
/// Smaller values cause the affected command to return `6F 00`.
///
/// Enable features `gsm` and/or `usim` to include the respective
/// application layers. With no features, all APDUs return `6E 00`.
///
/// # Reset policy
///
/// The reset policy is set at construction time via [`Sim::new`] (which
/// uses [`standard_reset_policy`]) or [`Sim::with_reset_policy`]. It
/// cannot be changed after construction.
pub struct Sim<A: AuthenticationAlgorithm = MilenageParams, const RSP_CAP: usize = 256> {
    atr: &'static [u8],
    state: CardState,
    reset_policy: fn(ResetKind) -> ResetEffects,
    rsp_buf: [u8; RSP_CAP],
    #[cfg(feature = "gsm")]
    gsm: GsmApp,
    #[cfg(feature = "usim")]
    usim: UsimApp<A>,
    #[cfg(not(any(feature = "gsm", feature = "usim")))]
    _mf: &'static DfDef,
    #[cfg(not(feature = "usim"))]
    _auth: core::marker::PhantomData<A>,
}

impl<A: AuthenticationAlgorithm, const RSP_CAP: usize> Sim<A, RSP_CAP> {
    // -- Constructors (one per feature combination) --
    //
    // `new()` uses [`standard_reset_policy`] (clear everything on both
    // cold and warm reset). `with_reset_policy()` accepts a custom
    // `fn(ResetKind) -> ResetEffects` for card-specific behavior.

    /// Create a new SIM card (no application features enabled).
    ///
    /// All APDUs will return `6E 00` (class not supported).
    #[cfg(not(any(feature = "gsm", feature = "usim")))]
    pub fn new(atr: &'static [u8], mf: &'static DfDef) -> Self {
        Self::with_reset_policy(atr, mf, standard_reset_policy)
    }

    /// Create a new SIM card (no application features enabled) with a
    /// custom reset policy.
    #[cfg(not(any(feature = "gsm", feature = "usim")))]
    pub fn with_reset_policy(
        atr: &'static [u8],
        mf: &'static DfDef,
        reset_policy: fn(ResetKind) -> ResetEffects,
    ) -> Self {
        Self {
            atr,
            state: CardState::Off,
            reset_policy,
            rsp_buf: [0u8; RSP_CAP],
            _mf: mf,
            _auth: core::marker::PhantomData,
        }
    }

    /// Create a new SIM card with GSM application layer.
    ///
    /// Configure PINs via `sim.gsm_app_mut().pin_manager().add_pin(...)`.
    #[cfg(all(feature = "gsm", not(feature = "usim")))]
    pub fn new(atr: &'static [u8], gsm: GsmApp) -> Self {
        Self::with_reset_policy(atr, gsm, standard_reset_policy)
    }

    /// Create a new SIM card with GSM application layer and a custom
    /// reset policy.
    #[cfg(all(feature = "gsm", not(feature = "usim")))]
    pub fn with_reset_policy(
        atr: &'static [u8],
        gsm: GsmApp,
        reset_policy: fn(ResetKind) -> ResetEffects,
    ) -> Self {
        Self {
            atr,
            state: CardState::Off,
            reset_policy,
            rsp_buf: [0u8; RSP_CAP],
            gsm,
            _auth: core::marker::PhantomData,
        }
    }

    /// Create a new SIM card with USIM application layer.
    ///
    /// Configure PINs via `sim.usim_app_mut().pin_manager().add_pin(...)`.
    #[cfg(all(feature = "usim", not(feature = "gsm")))]
    pub fn new(atr: &'static [u8], usim: UsimApp<A>) -> Self {
        Self::with_reset_policy(atr, usim, standard_reset_policy)
    }

    /// Create a new SIM card with USIM application layer and a custom
    /// reset policy.
    #[cfg(all(feature = "usim", not(feature = "gsm")))]
    pub fn with_reset_policy(
        atr: &'static [u8],
        usim: UsimApp<A>,
        reset_policy: fn(ResetKind) -> ResetEffects,
    ) -> Self {
        Self {
            atr,
            state: CardState::Off,
            reset_policy,
            rsp_buf: [0u8; RSP_CAP],
            usim,
        }
    }

    /// Create a new SIM card with both GSM and USIM application layers.
    ///
    /// ```ignore
    /// use simrs_usim::profile::{REFERENCE_MF, ADF_TABLE};
    ///
    /// let gsm = GsmApp::new(&REFERENCE_MF, ki);
    /// let usim = UsimApp::new(&REFERENCE_MF, &ADF_TABLE, auth);
    /// let sim = Sim::<MilenageParams, 256>::new(&ATR, gsm, usim);
    /// ```
    ///
    /// Configure PINs via `sim.usim_app_mut().pin_manager().add_pin(...)`.
    #[cfg(all(feature = "gsm", feature = "usim"))]
    pub fn new(atr: &'static [u8], gsm: GsmApp, usim: UsimApp<A>) -> Self {
        Self::with_reset_policy(atr, gsm, usim, standard_reset_policy)
    }

    /// Create a new SIM card with both GSM and USIM application layers
    /// and a custom reset policy.
    ///
    /// ```ignore
    /// // Warm reset preserves PIN verified status:
    /// fn warm_preserves_pin(kind: ResetKind) -> ResetEffects {
    ///     match kind {
    ///         ResetKind::Cold => ResetEffects::all(),
    ///         ResetKind::Warm => ResetEffects { clear_pin_verified: false, ..ResetEffects::all() },
    ///     }
    /// }
    /// let gsm = GsmApp::new(&MF, ki);
    /// let usim = UsimApp::new(&MF, &[], auth);
    /// let sim = Sim::<MilenageParams, 256>::with_reset_policy(&ATR, gsm, usim, warm_preserves_pin);
    /// ```
    #[cfg(all(feature = "gsm", feature = "usim"))]
    pub fn with_reset_policy(
        atr: &'static [u8],
        gsm: GsmApp,
        usim: UsimApp<A>,
        reset_policy: fn(ResetKind) -> ResetEffects,
    ) -> Self {
        Self {
            atr,
            state: CardState::Off,
            reset_policy,
            rsp_buf: [0u8; RSP_CAP],
            gsm,
            usim,
        }
    }

    // -- Accessors --

    /// Access the GSM application layer for configuration.
    ///
    /// Use this to replace the app with configured credentials:
    /// ```ignore
    /// *sim.gsm_app_mut() = GsmApp::new(mf, SubscriberKey::classify(ki));
    /// sim.gsm_app_mut().pin_manager().add_pin(...);
    /// ```
    #[cfg(feature = "gsm")]
    pub const fn gsm_app_mut(&mut self) -> &mut GsmApp {
        &mut self.gsm
    }

    /// Access the USIM application layer for configuration.
    ///
    /// Use this to replace the app with configured credentials:
    /// ```ignore
    /// *sim.usim_app_mut() = UsimApp::new(mf, adfs, auth);
    /// sim.usim_app_mut().pin_manager().add_pin(...);
    /// ```
    #[cfg(feature = "usim")]
    pub const fn usim_app_mut(&mut self) -> &mut UsimApp<A> {
        &mut self.usim
    }

    // -- Event processing --

    /// Process an event and produce a response.
    ///
    /// This is the single entry point for all card interactions.
    /// The built-in logic never panics. If a custom reset policy supplied
    /// to [`Sim::with_reset_policy`] panics, the panic propagates to the
    /// caller with the card state unchanged (the state transition occurs
    /// only after the policy returns successfully).
    ///
    /// - `PowerOn` / `Reset`: invokes the reset policy, applies the
    ///   returned [`ResetEffects`], and returns [`SimResponse::Atr`].
    ///   With [`standard_reset_policy`] both clear all session state.
    ///   Custom policies may preserve selected subsystems.
    /// - `PowerOff`: transitions to `Off` state, returns [`SimResponse::Ignored`].
    ///   Subsequent APDUs return `Ignored` until the next `PowerOn`.
    /// - `Apdu`: parses the command, routes by CLA byte, returns
    ///   [`SimResponse::Apdu`] or [`SimResponse::Ignored`] if malformed
    ///   or the card is not powered on.
    /// - `Tick`: advances UICC-side proactive timers, returns
    ///   [`SimResponse::Ignored`]. Check for expired timers via
    ///   `usim_app_mut().proactive_state().take_expired_timer()`.
    pub fn process(&mut self, event: SimEvent<'_>) -> SimResponse<'_> {
        match event {
            SimEvent::PowerOn => {
                let effects = (self.reset_policy)(ResetKind::Cold);
                self.apply_reset_effects(effects);
                self.state = CardState::Ready;
                SimResponse::Atr(self.atr)
            }
            SimEvent::Reset => {
                let effects = (self.reset_policy)(ResetKind::Warm);
                self.apply_reset_effects(effects);
                self.state = CardState::Ready;
                SimResponse::Atr(self.atr)
            }
            SimEvent::PowerOff => {
                self.state = CardState::Off;
                SimResponse::Ignored
            }
            SimEvent::Apdu(bytes) => {
                if self.state != CardState::Ready {
                    return SimResponse::Ignored;
                }
                self.handle_apdu(bytes)
            }
            #[allow(unused_variables)]
            SimEvent::Tick(elapsed) => {
                #[cfg(feature = "usim")]
                {
                    let _ = self.usim.tick(elapsed);
                }
                SimResponse::Ignored
            }
        }
    }

    /// Apply per-subsystem reset effects according to the reset policy.
    ///
    /// Each flag in [`ResetEffects`] independently controls whether its
    /// corresponding piece of session state is cleared. The subsystems are
    /// independent and the application order does not affect the outcome.
    // Allow: when no features are enabled, all cfg blocks compile away
    // leaving an empty body. The method is kept for structural correctness.
    #[allow(
        clippy::unused_self,
        clippy::needless_pass_by_ref_mut,
        clippy::missing_const_for_fn,
        unused_variables
    )]
    fn apply_reset_effects(&mut self, effects: ResetEffects) {
        #[cfg(feature = "gsm")]
        {
            if effects.clear_pin_verified {
                self.gsm.pin_manager().reset_verified();
            }
            if effects.clear_response_queue {
                self.gsm.clear_response_queue();
            }
            if effects.clear_file_selection {
                self.gsm.reset_file_selection();
            }
        }
        #[cfg(feature = "usim")]
        {
            if effects.clear_pin_verified {
                self.usim.pin_manager().reset_verified();
            }
            if effects.clear_response_queue {
                self.usim.clear_response_queue();
            }
            if effects.clear_file_selection {
                self.usim.reset_file_selection();
            }
            if effects.clear_logical_channels {
                self.usim.close_all_channels();
            }
            if effects.clear_proactive_session {
                self.usim.reset_proactive_session();
            }
            if effects.clear_last_aid_match {
                self.usim.clear_last_aid_match();
            }
        }
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes.
    ///
    /// Varies by enabled features and profile tiers:
    /// Header(6) + CardState(1) + GsmApp::SNAPSHOT\_SIZE + UsimApp::\<A\>::SNAPSHOT\_SIZE.
    pub const SNAPSHOT_SIZE: usize = SNAPSHOT_HEADER_SIZE
        + 1
        + {
            #[cfg(feature = "gsm")]
            {
                GsmApp::SNAPSHOT_SIZE
            }
            #[cfg(not(feature = "gsm"))]
            {
                0
            }
        }
        + {
            #[cfg(feature = "usim")]
            {
                UsimApp::<A>::SNAPSHOT_SIZE
            }
            #[cfg(not(feature = "usim"))]
            {
                0
            }
        };

    /// Serialize the SIM state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    /// Static references (ATR, MF tree) and transient buffers are not serialized.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        // Write header: magic + version + feature flags.
        let mut off = 0;
        buf[off..off + 4].copy_from_slice(&SNAPSHOT_MAGIC);
        off += 4;
        buf[off] = SNAPSHOT_VERSION;
        off += 1;
        buf[off] = snapshot_feature_flags();
        off += 1;
        // Card state.
        buf[off] = match self.state {
            CardState::Off => 0,
            CardState::Ready => 1,
        };
        off += 1;
        #[cfg(feature = "gsm")]
        {
            off += self.gsm.save_state(&mut buf[off..]);
        }
        #[cfg(feature = "usim")]
        {
            off += self.usim.save_state(&mut buf[off..]);
        }
        let _ = off;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the SIM state from `buf`.
    ///
    /// Returns `true` on success. Static references (ATR, MF tree, ADF table)
    /// remain as set during construction.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        // Validate header: magic + version + feature flags.
        let mut off = 0;
        if buf[off..off + 4] != SNAPSHOT_MAGIC {
            return false;
        }
        off += 4;
        if buf[off] != SNAPSHOT_VERSION {
            return false;
        }
        off += 1;
        if buf[off] != snapshot_feature_flags() {
            return false;
        }
        off += 1;
        // Card state.
        self.state = match buf[off] {
            0 => CardState::Off,
            1 => CardState::Ready,
            _ => return false,
        };
        off += 1;
        #[cfg(feature = "gsm")]
        {
            // GSM 11.11 has no Application DFs; pass empty ADF table.
            if !self.gsm.restore_state(&buf[off..], &[]) {
                return false;
            }
            off += GsmApp::SNAPSHOT_SIZE;
        }
        #[cfg(feature = "usim")]
        {
            if !self.usim.restore_state(&buf[off..]) {
                return false;
            }
            off += UsimApp::<A>::SNAPSHOT_SIZE;
        }
        let _ = off;
        true
    }

    /// Compute an FNV-1a hash of the serialized state for deduplication.
    #[allow(clippy::large_stack_arrays)]
    pub fn state_hash(&self) -> u64 {
        // Rust cannot use `Self::SNAPSHOT_SIZE` in array-length position for
        // generic types, so we compute a fixed upper bound from the known
        // component sizes.  The `debug_assert_eq` below will catch any
        // mismatch at runtime in debug builds.
        const HASH_BUF: usize = STATE_HASH_BUF;
        let mut buf = [0u8; HASH_BUF];
        let n = self.save_state(&mut buf);
        debug_assert_eq!(n, Self::SNAPSHOT_SIZE, "save_state wrote unexpected size");
        fnv1a(&buf[..n])
    }

    /// Route an APDU to the appropriate application layer.
    fn handle_apdu(&mut self, bytes: &[u8]) -> SimResponse<'_> {
        // Minimum APDU is 4 bytes: CLA INS P1 P2.
        if bytes.len() < 4 {
            return SimResponse::Ignored;
        }

        let Ok(cmd) = Command::parse(bytes) else {
            return SimResponse::Ignored;
        };

        let cla = cmd.cla_raw();
        let family = classify_cla(cla);

        // Route by CLA family. The original CLA (with channel bits) is
        // passed to the application handler unchanged.
        let rsp_slice = match family {
            #[cfg(feature = "gsm")]
            ClaFamily::Gsm => self.gsm.handle(&cmd, &mut self.rsp_buf),

            #[cfg(not(feature = "gsm"))]
            ClaFamily::Gsm => write_sw(&mut self.rsp_buf, StatusWord::ClassNotSupported),

            #[cfg(feature = "usim")]
            ClaFamily::Interindustry | ClaFamily::EtsiProprietary => {
                self.usim.handle(&cmd, &mut self.rsp_buf)
            }

            #[cfg(not(feature = "usim"))]
            ClaFamily::Interindustry | ClaFamily::EtsiProprietary => {
                write_sw(&mut self.rsp_buf, StatusWord::ClassNotSupported)
            }

            ClaFamily::Unknown => write_sw(&mut self.rsp_buf, StatusWord::ClassNotSupported),
        };

        // Application layers always return [data..., SW1, SW2].
        if rsp_slice.len() < 2 {
            return SimResponse::Ignored;
        }

        let sw_offset = rsp_slice.len() - 2;
        SimResponse::Apdu {
            data: &rsp_slice[..sw_offset],
            sw: StatusWord::from_bytes(rsp_slice[sw_offset], rsp_slice[sw_offset + 1]),
        }
    }
}

// ---------------------------------------------------------------------------
// FNV-1a hash
// ---------------------------------------------------------------------------

/// Compute FNV-1a 64-bit hash of a byte slice.
fn fnv1a(data: &[u8]) -> u64 {
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = BASIS;
    let mut i = 0;
    while i < data.len() {
        hash ^= u64::from(data[i]);
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::large_stack_arrays)]
mod tests {
    use super::*;
    use simrs_fs::{DfDef, EfDef, Fid, FileRef};

    #[cfg(feature = "usim")]
    use simrs_fs::AdfSlot;
    use simrs_milenage::MilenageParams;
    #[cfg(feature = "usim")]
    use simrs_milenage::{OperatorVariant, SubscriberKey};
    #[cfg(any(feature = "gsm", feature = "usim"))]
    use simrs_pin::{PinKey, PinValue};

    // -- Test filesystem (shared across features) --

    static ICCID_DATA: [u8; 10] = [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

    static EF_ICCID: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &ICCID_DATA);

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

    // -- USIM-only test statics --

    #[cfg(feature = "usim")]
    static IMSI_DATA: [u8; 9] = [0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01];

    #[cfg(feature = "usim")]
    static EF_IMSI: EfDef = EfDef::transparent(Fid::new(0x6F07), None, &IMSI_DATA);

    #[cfg(feature = "usim")]
    static ADF_USIM_DF: DfDef = DfDef {
        fid: Fid::new(0x7FFF),
        children: &[FileRef::Ef(&EF_IMSI)],
    };

    #[cfg(feature = "usim")]
    static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

    #[cfg(feature = "usim")]
    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_DF,
    }];

    // -- Test helper --

    fn make_sim() -> Sim<MilenageParams, 256> {
        make_sim_with_policy(standard_reset_policy)
    }

    fn make_sim_with_policy(policy: fn(ResetKind) -> ResetEffects) -> Sim<MilenageParams, 256> {
        #[cfg(feature = "gsm")]
        let gsm = {
            use simrs_gsm::GsmApp;
            let mut g = GsmApp::new(&MF, simrs_gsm::SubscriberKey::classify([0x11u8; 16]));
            let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
            let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
            let _ = g
                .pin_manager()
                .add_pin(PinKey::PIN1, &pin, 3, &puk, 10, true);
            g
        };

        #[cfg(feature = "usim")]
        let usim = {
            use simrs_usim::UsimApp;
            let mil = MilenageParams::with_defaults(
                SubscriberKey::classify([0u8; 16]),
                OperatorVariant::operator_cipher([0u8; 16]),
            );
            let mut u = UsimApp::new(&MF, &ADF_TABLE, mil);
            let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
            let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
            let _ = u
                .pin_manager()
                .add_pin(PinKey::PIN1, &pin, 3, &puk, 10, true);
            u
        };

        #[cfg(all(feature = "gsm", feature = "usim"))]
        {
            Sim::<MilenageParams, 256>::with_reset_policy(&ATR, gsm, usim, policy)
        }
        #[cfg(all(feature = "gsm", not(feature = "usim")))]
        {
            Sim::<MilenageParams, 256>::with_reset_policy(&ATR, gsm, policy)
        }
        #[cfg(all(feature = "usim", not(feature = "gsm")))]
        {
            Sim::<MilenageParams, 256>::with_reset_policy(&ATR, usim, policy)
        }
        #[cfg(not(any(feature = "gsm", feature = "usim")))]
        {
            Sim::<MilenageParams, 256>::with_reset_policy(&ATR, &MF, policy)
        }
    }

    /// Verify USIM PIN1 ("1234") on a powered-on SIM.
    #[cfg(feature = "usim")]
    fn verify_usim_pin(sim: &mut Sim<MilenageParams, 256>) {
        let cmd = [
            0x00, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let rsp = sim.process(SimEvent::Apdu(&cmd));
        assert!(
            matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]),
            "VERIFY PIN1 setup should succeed, got {rsp:?}"
        );
    }

    /// Verify GSM PIN1 ("1234") on a powered-on SIM.
    #[cfg(feature = "gsm")]
    fn verify_gsm_pin(sim: &mut Sim<MilenageParams, 256>) {
        let cmd = [
            0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let rsp = sim.process(SimEvent::Apdu(&cmd));
        assert!(
            matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]),
            "GSM VERIFY PIN1 setup should succeed, got {rsp:?}"
        );
    }

    // -----------------------------------------------------------------------
    // PowerOn / Reset
    // -----------------------------------------------------------------------

    #[test]
    fn power_on_returns_atr() {
        let mut sim = make_sim();
        let rsp = sim.process(SimEvent::PowerOn);
        match rsp {
            SimResponse::Atr(atr) => assert_eq!(atr, &ATR),
            _ => panic!("expected Atr"),
        }
    }

    #[test]
    fn reset_returns_atr() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Reset);
        match rsp {
            SimResponse::Atr(atr) => assert_eq!(atr, &ATR),
            _ => panic!("expected Atr"),
        }
    }

    #[test]
    fn multiple_power_on_is_idempotent() {
        let mut sim = make_sim();
        for _ in 0..3 {
            let rsp = sim.process(SimEvent::PowerOn);
            match rsp {
                SimResponse::Atr(atr) => assert_eq!(atr, &ATR),
                _ => panic!("expected Atr"),
            }
        }
    }

    #[test]
    fn apdu_before_power_on_returns_ignored() {
        let mut sim = make_sim();
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    #[test]
    fn power_off_transitions_to_off() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // PowerOff returns Ignored
        let rsp = sim.process(SimEvent::PowerOff);
        assert!(matches!(rsp, SimResponse::Ignored));

        // APDUs after PowerOff should be Ignored
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    // CLA=0x00 routes to UsimApp, so this test requires the `usim` feature.
    #[cfg(feature = "usim")]
    #[test]
    fn power_off_then_power_on_works() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let _ = sim.process(SimEvent::PowerOff);

        // PowerOn after PowerOff should work normally
        let rsp = sim.process(SimEvent::PowerOn);
        assert!(matches!(rsp, SimResponse::Atr(_)));

        // APDUs should work again (CLA=0x00 SELECT MF -> USIM returns 61 XX)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => assert_eq!(sw.to_bytes()[0], 0x61),
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Malformed APDU
    // -----------------------------------------------------------------------

    #[test]
    fn short_apdu_returns_ignored() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    #[test]
    fn empty_apdu_returns_ignored() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    // -----------------------------------------------------------------------
    // CLA routing -- GSM
    // -----------------------------------------------------------------------

    #[cfg(feature = "gsm")]
    #[test]
    fn cla_a0_routes_to_gsm() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(sw.to_bytes()[0], 0x9F, "expected GSM SELECT response 9F XX");
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[cfg(feature = "gsm")]
    #[test]
    fn gsm_select_get_response_round_trip() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT MF
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
        let SimResponse::Apdu { sw, .. } = rsp else {
            panic!("expected 9F XX from GSM SELECT")
        };
        let [sw1, le] = sw.to_bytes();
        assert_eq!(sw1, 0x9F);

        // GET RESPONSE
        let mut apdu = [0xA0, 0xC0, 0x00, 0x00, 0x00];
        apdu[4] = le;
        let rsp = sim.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x90, 0x00]);
                assert!(
                    data.len() >= 15,
                    "GSM SELECT response too short: {}",
                    data.len()
                );
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // CLA routing -- USIM
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn cla_00_routes_to_usim() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, _sw2] = sw.to_bytes();
                assert_eq!(sw1, 0x61, "expected USIM SELECT response 61 XX");
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn cla_80_routes_to_usim_for_cat() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[
            0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
        ]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x90, 0x00]);
            }
            _ => panic!("expected Apdu response"),
        }
    }

    /// Verify that the proactive 91 XX override passes through the Sim layer
    /// when a proactive command is pending in UsimApp.
    #[cfg(feature = "usim")]
    #[test]
    fn proactive_91_override_passes_through() {
        use simrs_proactive::{ProactiveCommand, TextCoding};

        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // Queue a proactive DISPLAY TEXT command.
        sim.usim_app_mut()
            .proactive_state()
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Hello",
                coding: TextCoding::Gsm7Bit,
                high_priority: false,
            })
            .unwrap();

        // TERMINAL PROFILE (CLA=0x80) normally returns 90 00, but with
        // a proactive command pending the UsimApp overrides to 91 XX.
        let rsp = sim.process(SimEvent::Apdu(&[0x80, 0x10, 0x00, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(sw1, 0x91, "expected proactive override 91 XX");
                assert!(sw2 > 0, "proactive command length should be > 0");
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn usim_select_get_response_round_trip() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT MF
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        let SimResponse::Apdu { sw, .. } = rsp else {
            panic!("expected 61 XX from USIM SELECT")
        };
        let [sw1, le] = sw.to_bytes();
        assert_eq!(sw1, 0x61, "expected 61 XX from USIM SELECT");

        // GET RESPONSE
        let mut apdu = [0x00, 0xC0, 0x00, 0x00, 0x00];
        apdu[4] = le;
        let rsp = sim.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x90, 0x00]);
                assert!(!data.is_empty(), "FCP should not be empty");
                assert_eq!(data[0], 0x62, "FCP should start with 0x62");
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // Unsupported CLA
    // -----------------------------------------------------------------------

    #[test]
    fn unsupported_cla_returns_6e_00() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x6E, 0x00]);
                assert!(data.is_empty());
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[test]
    fn unknown_ins_returns_6d_00() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        #[cfg(feature = "usim")]
        let apdu = [0x00u8, 0xFF, 0x00, 0x00];
        #[cfg(all(feature = "gsm", not(feature = "usim")))]
        let apdu = [0xA0u8, 0xFF, 0x00, 0x00];
        #[cfg(not(any(feature = "gsm", feature = "usim")))]
        let apdu = [0x00u8, 0xFF, 0x00, 0x00];

        let rsp = sim.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                #[cfg(any(feature = "gsm", feature = "usim"))]
                assert_eq!([sw1, sw2], [0x6D, 0x00], "expected INS not supported");
                #[cfg(not(any(feature = "gsm", feature = "usim")))]
                assert_eq!([sw1, sw2], [0x6E, 0x00], "expected CLA not supported");
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // SimResponse structure
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn apdu_response_contains_data_and_sw() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT MF + GET RESPONSE
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x40]));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert!(!data.is_empty(), "response should have data");
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x90, 0x00]);
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[test]
    fn error_response_has_empty_data() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00]));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert!(data.is_empty());
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x6E, 0x00]);
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // Reset clears PIN state (standard policy)
    // -----------------------------------------------------------------------

    #[cfg(feature = "gsm")]
    #[test]
    fn reset_clears_pin_verified_standard_policy() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // Verify GSM PIN1 and select EF.ICCID
        verify_gsm_pin(&mut sim);
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x9F));
        let _ = sim.process(SimEvent::Apdu(&[0xA0, 0xC0, 0x00, 0x00, 0x0F]));

        // Confirm READ BINARY works (PIN verified, EF selected)
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xB0, 0x00, 0x00, 0x0A]));
        assert!(
            matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]),
            "READ BINARY should succeed before reset"
        );

        // Standard reset clears everything including PIN verified
        let _ = sim.process(SimEvent::Reset);

        // Re-select EF.ICCID (file selection cleared by standard policy)
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x9F));
        let _ = sim.process(SimEvent::Apdu(&[0xA0, 0xC0, 0x00, 0x00, 0x0F]));

        // READ BINARY without re-verifying -- should fail (PIN cleared)
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x69, 0x82],
                    "READ BINARY must fail after reset: PIN cleared by standard policy"
                );
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // Feature gating: CLA rejection
    // -----------------------------------------------------------------------

    #[cfg(all(feature = "gsm", not(feature = "usim")))]
    #[test]
    fn gsm_only_rejects_usim_cla() {
        let mut sim = make_sim();
        sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => assert_eq!(sw.to_bytes(), [0x6E, 0x00]),
            _ => panic!("expected Apdu response"),
        }
    }

    #[cfg(all(feature = "usim", not(feature = "gsm")))]
    #[test]
    fn usim_only_rejects_gsm_cla() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => assert_eq!(sw.to_bytes(), [0x6E, 0x00]),
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_save_writes_exact_size() {
        let sim = make_sim();
        let mut buf = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let n = sim.save_state(&mut buf);
        assert_eq!(n, Sim::<MilenageParams, 256>::SNAPSHOT_SIZE);
    }

    #[test]
    fn snapshot_roundtrip_preserves_card_state() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        let mut snap = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let n = sim.save_state(&mut snap);
        assert_eq!(n, Sim::<MilenageParams, 256>::SNAPSHOT_SIZE);

        // Restore into a fresh sim.
        let mut restored = make_sim();
        assert!(restored.restore_state(&snap[..n]));

        // Card should be in Ready state (APDU works without PowerOn).
        let rsp = restored.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x6E, 0x00]);
            }
            _ => panic!("expected Apdu, card should be Ready after restore"),
        }
    }

    #[test]
    fn snapshot_restore_off_state() {
        let sim = make_sim(); // never powered on -> Off state
        let mut snap = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let n = sim.save_state(&mut snap);
        assert_eq!(n, Sim::<MilenageParams, 256>::SNAPSHOT_SIZE);

        let mut restored = make_sim();
        let _ = restored.process(SimEvent::PowerOn); // make it Ready
        assert!(restored.restore_state(&snap[..n]));

        // After restore, card should be Off -> APDU ignored.
        let rsp = restored.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let sim = make_sim();
        let mut small = [0u8; 0];
        assert_eq!(sim.save_state(&mut small), 0);

        let mut sim2 = make_sim();
        assert!(!sim2.restore_state(&small));
    }

    #[test]
    fn state_hash_deterministic() {
        let sim = make_sim();
        let h1 = sim.state_hash();
        let h2 = sim.state_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn state_hash_changes_on_state_change() {
        let mut sim = make_sim();
        let h1 = sim.state_hash();
        let _ = sim.process(SimEvent::PowerOn);
        let h2 = sim.state_hash();
        assert_ne!(h1, h2, "hash should differ after PowerOn");
    }

    #[test]
    fn snapshot_restore_invalid_card_state() {
        let sim = make_sim();
        let mut snap = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let n = sim.save_state(&mut snap);
        assert!(n > 0);
        // Corrupt the card state byte.
        snap[0] = 0xFF;
        let mut sim2 = make_sim();
        assert!(!sim2.restore_state(&snap[..n]));
    }

    // -----------------------------------------------------------------------
    // Tick
    // -----------------------------------------------------------------------

    #[test]
    fn tick_before_power_on_returns_ignored() {
        let mut sim = make_sim();
        let rsp = sim.process(SimEvent::Tick(10));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    #[cfg(feature = "usim")]
    #[test]
    fn tick_advances_proactive_timers() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // Start a 10-second timer on slot 1 via proactive state.
        let bcd_10s = [0x00, 0x00, 0x10]; // BCD: 00h 00m 10s
        assert!(sim.usim_app_mut().proactive_state().start_timer(1, bcd_10s));

        // Tick 5 seconds -- timer should still be active.
        let rsp = sim.process(SimEvent::Tick(5));
        assert!(matches!(rsp, SimResponse::Ignored));
        assert!(sim
            .usim_app_mut()
            .proactive_state()
            .get_timer_value(1)
            .is_some());

        // Tick 6 more seconds -- timer should expire (5+6 > 10).
        let _ = sim.process(SimEvent::Tick(6));
        let expired_id = sim.usim_app_mut().proactive_state().take_expired_timer();
        assert_eq!(expired_id, 1, "timer 1 should have expired");
    }

    // -----------------------------------------------------------------------
    // CLA family routing (3D)
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn cla_01_routes_to_usim() {
        // CLA=0x01 is interindustry channel 1 -- should route to USIM.
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        // SELECT MF with CLA=0x01. USIM now accepts all interindustry CLA
        // values. CLA=0x01 targets logical channel 1 which is not open,
        // so USIM returns 68 81 (logical channel not supported). This confirms the
        // Sim layer routed to USIM (not rejecting at the Sim level).
        let rsp = sim.process(SimEvent::Apdu(&[0x01, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                // Channel 1 not open -> 68 81 (logical channel not supported).
                assert_eq!([sw1, sw2], [0x68, 0x81]);
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn cla_40_routes_to_usim() {
        // CLA=0x40 is interindustry (further coding, channel 0) -- should route to USIM.
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        // CLA=0x40 is now accepted as interindustry channel 0, so SELECT MF
        // succeeds and returns 61 XX (data available via GET RESPONSE).
        let rsp = sim.process(SimEvent::Apdu(&[0x40, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, _sw2] = sw.to_bytes();
                // Routed to USIM, SELECT MF succeeds with data available.
                assert_eq!(sw1, 0x61);
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn cla_c0_routes_to_usim() {
        // CLA=0xC0 is ETSI proprietary (further coding) -- should route to USIM.
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0xC0, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                // Routed to USIM which rejects non-0x00/0x80 CLA values.
                assert_eq!([sw1, sw2], [0x6E, 0x00]);
            }
            _ => panic!("expected Apdu response"),
        }
    }

    #[test]
    fn cla_f0_rejected() {
        // CLA=0xF0 is unknown family -- should be rejected at Sim level.
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x6E, 0x00]);
                assert!(data.is_empty());
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // APDU boundary tests
    // -----------------------------------------------------------------------

    /// APDU with exactly 4 bytes (CLA INS P1 P2, no Lc, no data, no Le).
    /// This is the minimum valid APDU. With a known CLA, the application layer
    /// should process it (not Ignored).
    #[test]
    fn apdu_4_byte_header_only() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // STATUS command (INS=0xF2 for GSM, INS=0xF2 for USIM) with no data.
        #[cfg(feature = "usim")]
        let apdu = [0x00u8, 0xF2, 0x00, 0x0C]; // STATUS P2=0x0C (no FCI data)
        #[cfg(all(feature = "gsm", not(feature = "usim")))]
        let apdu = [0xA0u8, 0xF2, 0x00, 0x00];
        #[cfg(not(any(feature = "gsm", feature = "usim")))]
        let apdu = [0x00u8, 0xF2, 0x00, 0x00];

        let rsp = sim.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                // Must get a real response (not Ignored). Exact SW depends on features.
                #[cfg(any(feature = "gsm", feature = "usim"))]
                assert_eq!(
                    sw1, 0x90,
                    "4-byte APDU should be processed, got SW {sw1:02X} {sw2:02X}"
                );
                #[cfg(not(any(feature = "gsm", feature = "usim")))]
                assert_eq!([sw1, sw2], [0x6E, 0x00], "no features: CLA not supported");
            }
            _ => panic!("expected Apdu response for 4-byte APDU"),
        }
    }

    /// APDU with Lc=0 and explicit empty data field (5-byte case: CLA INS P1 P2 Le=0).
    /// Le=0x00 means Le=256 in short APDU encoding.
    #[cfg(feature = "usim")]
    #[test]
    fn apdu_le_zero_means_256() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT MF first to have a valid context.
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));

        // STATUS with Le=0x00 (= 256 bytes requested).
        // The card should return what it has (FCP or status data), not error.
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xF2, 0x00, 0x0C, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!([sw1, sw2], [0x90, 0x00], "STATUS with Le=0 should succeed");
            }
            _ => panic!("expected Apdu response"),
        }
    }

    /// Unknown INS code must return 6D 00 (instruction not supported).
    /// Uses INS=0xFE which is not assigned in any supported application.
    #[test]
    fn unknown_ins_returns_6d00_boundary() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // INS=0xFE is not a valid instruction in GSM or USIM.
        #[cfg(feature = "usim")]
        let apdu = [0x00u8, 0xFE, 0x00, 0x00];
        #[cfg(all(feature = "gsm", not(feature = "usim")))]
        let apdu = [0xA0u8, 0xFE, 0x00, 0x00];
        #[cfg(not(any(feature = "gsm", feature = "usim")))]
        let apdu = [0x00u8, 0xFE, 0x00, 0x00];

        let rsp = sim.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                #[cfg(any(feature = "gsm", feature = "usim"))]
                assert_eq!([sw1, sw2], [0x6D, 0x00], "unknown INS must return 6D 00");
                #[cfg(not(any(feature = "gsm", feature = "usim")))]
                assert_eq!([sw1, sw2], [0x6E, 0x00], "no features: CLA not supported");
            }
            _ => panic!("expected Apdu response"),
        }
    }

    /// Wrong CLA class returns 6E 00. Tests a range of CLA bytes that
    /// should never be routed to any application.
    #[test]
    fn wrong_cla_classes_return_6e00() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // CLA values in the 0xBX and 0xFX ranges are not assigned to any family.
        for cla in [0xB0, 0xB1, 0xBF, 0xF0, 0xF1, 0xFF] {
            let apdu = [cla, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
            let rsp = sim.process(SimEvent::Apdu(&apdu));
            match rsp {
                SimResponse::Apdu { sw, data } => {
                    let [sw1, sw2] = sw.to_bytes();
                    assert_eq!(
                        [sw1, sw2],
                        [0x6E, 0x00],
                        "CLA 0x{cla:02X} must return 6E 00, got {sw1:02X} {sw2:02X}"
                    );
                    assert!(
                        data.is_empty(),
                        "error response for CLA 0x{cla:02X} must have empty data"
                    );
                }
                _ => panic!("expected Apdu response for CLA 0x{cla:02X}"),
            }
        }
    }

    /// APDU with exactly 3 bytes (too short) returns Ignored.
    /// This boundary test ensures the 4-byte minimum is enforced.
    #[test]
    fn apdu_3_bytes_returns_ignored() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00]));
        assert!(
            matches!(rsp, SimResponse::Ignored),
            "3-byte APDU must return Ignored"
        );
    }

    // -----------------------------------------------------------------------
    // Reset policy
    // -----------------------------------------------------------------------

    #[test]
    fn reset_effects_all_sets_every_flag() {
        let e = ResetEffects::all();
        assert!(e.clear_pin_verified);
        assert!(e.clear_response_queue);
        assert!(e.clear_file_selection);
        assert!(e.clear_logical_channels);
        assert!(e.clear_proactive_session);
        assert!(e.clear_last_aid_match);
    }

    #[test]
    fn reset_effects_none_clears_every_flag() {
        let e = ResetEffects::none();
        assert!(!e.clear_pin_verified);
        assert!(!e.clear_response_queue);
        assert!(!e.clear_file_selection);
        assert!(!e.clear_logical_channels);
        assert!(!e.clear_proactive_session);
        assert!(!e.clear_last_aid_match);
    }

    #[test]
    fn standard_policy_returns_all_for_cold() {
        assert_eq!(standard_reset_policy(ResetKind::Cold), ResetEffects::all());
    }

    #[test]
    fn standard_policy_returns_all_for_warm() {
        assert_eq!(standard_reset_policy(ResetKind::Warm), ResetEffects::all());
    }

    #[test]
    fn power_on_passes_cold_to_policy() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static KIND: AtomicU8 = AtomicU8::new(0xFF);
        fn recording(kind: ResetKind) -> ResetEffects {
            KIND.store(kind as u8, Ordering::Relaxed);
            ResetEffects::all()
        }
        let mut sim = make_sim_with_policy(recording);
        let _ = sim.process(SimEvent::PowerOn);
        assert_eq!(KIND.load(Ordering::Relaxed), ResetKind::Cold as u8);
    }

    #[test]
    fn reset_passes_warm_to_policy() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static KIND: AtomicU8 = AtomicU8::new(0xFF);
        fn recording(kind: ResetKind) -> ResetEffects {
            KIND.store(kind as u8, Ordering::Relaxed);
            ResetEffects::all()
        }
        let mut sim = make_sim_with_policy(recording);
        let _ = sim.process(SimEvent::PowerOn);
        let _ = sim.process(SimEvent::Reset);
        assert_eq!(KIND.load(Ordering::Relaxed), ResetKind::Warm as u8);
    }

    #[cfg(feature = "usim")]
    #[test]
    fn with_reset_policy_preserves_state() {
        fn noop_policy(_kind: ResetKind) -> ResetEffects {
            ResetEffects::none()
        }

        let mut sim = make_sim_with_policy(noop_policy);
        let _ = sim.process(SimEvent::PowerOn);
        verify_usim_pin(&mut sim);

        // SELECT EF.ICCID to establish a verifiable file selection
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));
        // Drain queue
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x20]));

        let rsp = sim.process(SimEvent::Reset);
        assert!(matches!(rsp, SimResponse::Atr(_)));

        // File selection survived -- READ BINARY returns ICCID data
        // (PIN also preserved since noop_policy clears nothing)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "file selection should survive noop reset"
                );
                assert_eq!(data, &ICCID_DATA);
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn custom_policy_warm_preserves_pin() {
        fn warm_preserves_pin(kind: ResetKind) -> ResetEffects {
            match kind {
                ResetKind::Cold => ResetEffects::all(),
                ResetKind::Warm => ResetEffects {
                    clear_pin_verified: false,
                    ..ResetEffects::all()
                },
            }
        }

        let mut sim = make_sim_with_policy(warm_preserves_pin);

        let _ = sim.process(SimEvent::PowerOn);

        // VERIFY PIN1
        let verify_cmd = [
            0x00, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let rsp = sim.process(SimEvent::Apdu(&verify_cmd));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]));

        // Warm reset: clear_pin_verified=false (preserved), but
        // clear_file_selection=true (cleared). Re-select EF.ICCID.
        let _ = sim.process(SimEvent::Reset);

        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x20]));

        // READ BINARY without re-verifying PIN -- should succeed because
        // warm_preserves_pin keeps the verified flag on warm reset.
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "PIN should remain verified after warm reset"
                );
            }
            _ => panic!("expected Apdu response"),
        }

        // Cold reset (PowerOn): clear_pin_verified=true, all cleared.
        let _ = sim.process(SimEvent::PowerOn);

        // Re-select EF.ICCID (file selection cleared by cold reset)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x20]));

        // READ BINARY without re-verifying PIN -- should fail because
        // cold reset cleared the verified flag.
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x69, 0x82],
                    "PIN should be cleared after cold reset"
                );
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // Reset policy: per-flag behavioral tests
    // -----------------------------------------------------------------------
    //
    // Each test verifies that a single ResetEffects flag independently
    // controls its subsystem:
    //
    //   - `preserve_all`: all flags false -- nothing cleared
    //   - `clear_only_X`: exactly one flag true, rest false
    //
    // The test pattern is:
    //   1. Set up the target state (queue response, select file, etc.)
    //   2. Reset with the policy
    //   3. Assert the target was preserved or cleared
    //   4. ("cleared" tests) Assert an adjacent subsystem was NOT disturbed

    // -- Policy catalogue --

    #[cfg(any(feature = "gsm", feature = "usim"))]
    fn preserve_all(_: ResetKind) -> ResetEffects {
        ResetEffects::none()
    }

    #[cfg(any(feature = "gsm", feature = "usim"))]
    fn clear_only_pin_verified(_: ResetKind) -> ResetEffects {
        ResetEffects {
            clear_pin_verified: true,
            ..ResetEffects::none()
        }
    }

    #[cfg(any(feature = "gsm", feature = "usim"))]
    fn clear_only_response_queue(_: ResetKind) -> ResetEffects {
        ResetEffects {
            clear_response_queue: true,
            ..ResetEffects::none()
        }
    }

    #[cfg(any(feature = "gsm", feature = "usim"))]
    fn clear_only_file_selection(_: ResetKind) -> ResetEffects {
        ResetEffects {
            clear_file_selection: true,
            ..ResetEffects::none()
        }
    }

    #[cfg(feature = "usim")]
    fn clear_only_logical_channels(_: ResetKind) -> ResetEffects {
        ResetEffects {
            clear_logical_channels: true,
            ..ResetEffects::none()
        }
    }

    #[cfg(feature = "usim")]
    fn clear_only_proactive_session(_: ResetKind) -> ResetEffects {
        ResetEffects {
            clear_proactive_session: true,
            ..ResetEffects::none()
        }
    }

    #[cfg(feature = "usim")]
    fn clear_only_last_aid_match(_: ResetKind) -> ResetEffects {
        ResetEffects {
            clear_last_aid_match: true,
            ..ResetEffects::none()
        }
    }

    // -- pin verified (USIM) --
    //
    // PIN tests use a PIN-gated operation (READ BINARY on EF.ICCID) as the
    // observable rather than re-issuing VERIFY, because a correct-PIN VERIFY
    // always returns 90 00 regardless of whether the verified flag survived
    // the reset. Using READ BINARY directly exposes the flag state.

    #[cfg(feature = "usim")]
    #[test]
    fn pin_verified_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);
        verify_usim_pin(&mut sim);

        // SELECT EF.ICCID, drain queue
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x20]));

        let _ = sim.process(SimEvent::Reset);

        // READ BINARY without re-verifying PIN -- should succeed because
        // clear_pin_verified=false preserves the verified flag, and
        // clear_file_selection=false preserves the EF.ICCID selection.
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "READ BINARY should succeed: PIN preserved across reset"
                );
                assert_eq!(data, &ICCID_DATA);
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn pin_verified_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_pin_verified);
        let _ = sim.process(SimEvent::PowerOn);
        verify_usim_pin(&mut sim);

        // SELECT EF.ICCID, drain queue (file selection preserved by policy)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x20]));

        let _ = sim.process(SimEvent::Reset);

        // READ BINARY without re-verifying PIN -- should fail because
        // clear_pin_verified=true cleared the verified flag.
        // File selection is preserved, so the failure is specifically due to PIN.
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x69, 0x82],
                    "READ BINARY must fail: PIN cleared by reset"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }

        // Re-verify PIN, then READ BINARY should succeed (proving it was
        // only PIN that blocked access, not file selection or anything else).
        verify_usim_pin(&mut sim);
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "READ BINARY should succeed after re-verifying PIN"
                );
                assert_eq!(data, &ICCID_DATA);
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- pin verified (GSM) --

    #[cfg(feature = "gsm")]
    #[test]
    fn gsm_pin_verified_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);
        verify_gsm_pin(&mut sim);

        // SELECT EF.ICCID via GSM, drain queue
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x9F));
        let _ = sim.process(SimEvent::Apdu(&[0xA0, 0xC0, 0x00, 0x00, 0x0F]));

        let _ = sim.process(SimEvent::Reset);

        // READ BINARY without re-verifying PIN -- should succeed
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "GSM READ BINARY should succeed: PIN preserved across reset"
                );
                assert_eq!(data, &ICCID_DATA);
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "gsm")]
    #[test]
    fn gsm_pin_verified_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_pin_verified);
        let _ = sim.process(SimEvent::PowerOn);
        verify_gsm_pin(&mut sim);

        // SELECT EF.ICCID via GSM, drain queue
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x9F));
        let _ = sim.process(SimEvent::Apdu(&[0xA0, 0xC0, 0x00, 0x00, 0x0F]));

        let _ = sim.process(SimEvent::Reset);

        // READ BINARY without re-verifying PIN -- should fail
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x69, 0x82],
                    "GSM READ BINARY must fail: PIN cleared by reset"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- response queue (USIM) --

    #[cfg(feature = "usim")]
    #[test]
    fn response_queue_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT MF queues FCP in response queue -> 61 XX
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        let le = match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(sw1, 0x61);
                sw2
            }
            other => panic!("expected 61 XX, got {other:?}"),
        };

        let _ = sim.process(SimEvent::Reset);

        // GET RESPONSE should still return the queued FCP
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = le;
        let rsp = sim.process(SimEvent::Apdu(&gr));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "queued response should survive reset when clear_response_queue=false"
                );
                assert!(!data.is_empty(), "FCP data should be present");
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn response_queue_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_response_queue);
        let _ = sim.process(SimEvent::PowerOn);
        verify_usim_pin(&mut sim);

        // SELECT EF.ICCID first (establishes file selection for isolation check)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));

        let _ = sim.process(SimEvent::Reset);

        // Queue was cleared -- GET RESPONSE returns 6F 00 (no data pending)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x20]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x6F, 0x00],
                    "GET RESPONSE must return 6F 00 (no data) after queue cleared"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }

        // Isolation: file selection was NOT cleared
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "file selection should be preserved (isolation check)"
                );
                assert_eq!(data, &ICCID_DATA);
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- response queue (GSM) --

    #[cfg(feature = "gsm")]
    #[test]
    fn gsm_response_queue_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT MF via GSM CLA -> 9F XX
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
        let le = match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(sw1, 0x9F);
                sw2
            }
            other => panic!("expected 9F XX, got {other:?}"),
        };

        let _ = sim.process(SimEvent::Reset);

        let mut gr = [0xA0, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = le;
        let rsp = sim.process(SimEvent::Apdu(&gr));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "GSM queue should survive reset when clear_response_queue=false"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "gsm")]
    #[test]
    fn gsm_response_queue_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_response_queue);
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT MF via GSM CLA -> 9F XX
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x9F));

        let _ = sim.process(SimEvent::Reset);

        // Queue was cleared -- GET RESPONSE returns 6F 00 (no data pending)
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xC0, 0x00, 0x00, 0x17]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x6F, 0x00],
                    "GSM GET RESPONSE must return 6F 00 (no data) after queue cleared"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- file selection (USIM) --

    #[cfg(feature = "usim")]
    #[test]
    fn file_selection_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);
        verify_usim_pin(&mut sim);

        // SELECT EF.ICCID (2FE2)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(
            matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61),
            "SELECT EF.ICCID should succeed"
        );

        let _ = sim.process(SimEvent::Reset);

        // READ BINARY on preserved selection -- should return ICCID data
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "READ BINARY should succeed on preserved file selection"
                );
                assert_eq!(
                    data, &ICCID_DATA,
                    "should read ICCID data from preserved EF selection"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn file_selection_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_file_selection);
        let _ = sim.process(SimEvent::PowerOn);
        verify_usim_pin(&mut sim);

        // SELECT EF.ICCID, then queue a response so we can check isolation
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        let le = match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(sw1, 0x61);
                sw2
            }
            other => panic!("expected 61 XX, got {other:?}"),
        };

        let _ = sim.process(SimEvent::Reset);

        // Isolation first: response queue was NOT cleared.
        // Must check GET RESPONSE BEFORE any other command, because
        // non-GET-RESPONSE commands clear the response queue per
        // ETSI TS 102 221 V18.3.0 clause 11.1.3.
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = le;
        let rsp = sim.process(SimEvent::Apdu(&gr));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "response queue should be preserved (isolation check)"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }

        // READ BINARY should fail -- MF is selected (not an EF)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x69, 0x86],
                    "READ BINARY must return 69 86 (no current EF) after file selection reset"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- file selection (GSM) --

    #[cfg(feature = "gsm")]
    #[test]
    fn gsm_file_selection_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);
        verify_gsm_pin(&mut sim);

        // SELECT EF.ICCID via GSM CLA
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]));
        assert!(
            matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x9F),
            "GSM SELECT EF.ICCID should succeed"
        );
        // Drain queue so READ BINARY doesn't trigger queue-clearing behavior
        let _ = sim.process(SimEvent::Apdu(&[0xA0, 0xC0, 0x00, 0x00, 0x0F]));

        let _ = sim.process(SimEvent::Reset);

        // READ BINARY on preserved selection
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "GSM READ BINARY should succeed on preserved file selection"
                );
                assert_eq!(data, &ICCID_DATA);
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "gsm")]
    #[test]
    fn gsm_file_selection_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_file_selection);
        let _ = sim.process(SimEvent::PowerOn);
        verify_gsm_pin(&mut sim);

        // SELECT EF.ICCID via GSM CLA
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x9F));

        let _ = sim.process(SimEvent::Reset);

        // READ BINARY should fail with "no EF selected" (not PIN failure)
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x94, 0x00],
                    "GSM READ BINARY must return 94 00 (no EF selected) after file selection reset"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- logical channels (USIM only) --

    #[cfg(feature = "usim")]
    #[test]
    fn logical_channels_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);

        // MANAGE CHANNEL: open channel (P1=0x00, P2=0x00)
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0x70, 0x00, 0x00, 0x01]));
        let ch = match rsp {
            SimResponse::Apdu { sw, data } => {
                assert_eq!(sw.to_bytes(), [0x90, 0x00]);
                assert_eq!(data.len(), 1, "should return channel number");
                data[0]
            }
            other => panic!("expected channel open success, got {other:?}"),
        };
        assert!(
            (1..=3).contains(&ch),
            "channel number should be 1-3, got {ch}"
        );

        let _ = sim.process(SimEvent::Reset);

        // SELECT MF on the preserved channel -- should succeed with 61 XX
        let cla = ch;
        let rsp = sim.process(SimEvent::Apdu(&[cla, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    sw1, 0x61,
                    "channel {ch} should remain open, expected 61 XX got {sw1:02X} {sw2:02X}"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn logical_channels_closed_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_logical_channels);
        let _ = sim.process(SimEvent::PowerOn);
        verify_usim_pin(&mut sim);

        // MANAGE CHANNEL: open channel
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0x70, 0x00, 0x00, 0x01]));
        let ch = match rsp {
            SimResponse::Apdu { sw, data } => {
                assert_eq!(sw.to_bytes(), [0x90, 0x00]);
                data[0]
            }
            other => panic!("expected channel open success, got {other:?}"),
        };

        // SELECT EF.ICCID on basic channel for isolation check
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));
        // Drain queue
        let _ = sim.process(SimEvent::Apdu(&[0x00, 0xC0, 0x00, 0x00, 0x20]));

        let _ = sim.process(SimEvent::Reset);

        // SELECT on closed channel should fail with 68 81 (logical channel not supported)
        let cla = ch;
        let rsp = sim.process(SimEvent::Apdu(&[cla, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x68, 0x81],
                    "channel {ch} should be closed after reset with clear_logical_channels=true"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }

        // Isolation: file selection on basic channel was NOT cleared
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xB0, 0x00, 0x00, 0x0A]));
        match rsp {
            SimResponse::Apdu { sw, data } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x90, 0x00],
                    "basic channel file selection should be preserved (isolation check)"
                );
                assert_eq!(data, &ICCID_DATA);
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- proactive session (USIM only) --

    #[cfg(feature = "usim")]
    #[test]
    fn proactive_session_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);

        // TERMINAL PROFILE activates proactive session
        let rsp = sim.process(SimEvent::Apdu(&[
            0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
        ]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]));

        let _ = sim.process(SimEvent::Reset);

        // ENVELOPE (Menu Selection D3) should be accepted (session still active)
        let rsp = sim.process(SimEvent::Apdu(&[
            0x80, 0xC2, 0x00, 0x00, 0x05, 0xD3, 0x03, 0x90, 0x01, 0x02,
        ]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(sw1, 0x90,
                    "ENVELOPE should succeed when proactive session preserved, got {sw1:02X} {sw2:02X}");
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn proactive_session_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_proactive_session);
        let _ = sim.process(SimEvent::PowerOn);

        // TERMINAL PROFILE activates proactive session
        let rsp = sim.process(SimEvent::Apdu(&[
            0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
        ]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]));

        let _ = sim.process(SimEvent::Reset);

        // ENVELOPE (Menu Selection D3) should be rejected (session cleared)
        let rsp = sim.process(SimEvent::Apdu(&[
            0x80, 0xC2, 0x00, 0x00, 0x05, 0xD3, 0x03, 0x90, 0x01, 0x02,
        ]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x69, 0x85],
                    "ENVELOPE should be rejected after proactive session cleared"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -- last AID match (USIM only) --

    #[cfg(feature = "usim")]
    #[test]
    fn last_aid_match_preserved_when_flag_false() {
        let mut sim = make_sim_with_policy(preserve_all);
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT by AID (USIM AID: A0 00 00 00 87 10 02)
        // P1=04 (select by DF name), P2=04 (FCI)
        let rsp = sim.process(SimEvent::Apdu(&[
            0x00, 0xA4, 0x04, 0x04, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
        ]));
        assert!(
            matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61),
            "SELECT by AID should succeed"
        );

        let _ = sim.process(SimEvent::Reset);

        // "Next occurrence" SELECT by AID (P2=02) should fail
        // because last_aid_match is still true from the prior SELECT.
        let rsp = sim.process(SimEvent::Apdu(&[
            0x00, 0xA4, 0x04, 0x02, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
        ]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x6A, 0x82],
                    "next-occurrence SELECT should fail when last_aid_match preserved"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[cfg(feature = "usim")]
    #[test]
    fn last_aid_match_cleared_when_flag_true() {
        let mut sim = make_sim_with_policy(clear_only_last_aid_match);
        let _ = sim.process(SimEvent::PowerOn);

        // SELECT by AID -> sets last_aid_match=true
        let rsp = sim.process(SimEvent::Apdu(&[
            0x00, 0xA4, 0x04, 0x04, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
        ]));
        assert!(matches!(rsp, SimResponse::Apdu { sw, .. } if sw.to_bytes()[0] == 0x61));

        let _ = sim.process(SimEvent::Reset);

        // "Next occurrence" SELECT by AID should now succeed because
        // last_aid_match was cleared (treated as first occurrence).
        let rsp = sim.process(SimEvent::Apdu(&[
            0x00, 0xA4, 0x04, 0x02, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
        ]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(sw1, 0x61,
                    "next-occurrence SELECT should succeed after clearing last_aid_match, got {sw1:02X} {sw2:02X}");
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Reset policy: adversarial / boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn power_off_does_not_invoke_reset_policy() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static CALL_COUNT: AtomicU8 = AtomicU8::new(0);
        fn counting_policy(kind: ResetKind) -> ResetEffects {
            CALL_COUNT.fetch_add(1, Ordering::Relaxed);
            let _ = kind;
            ResetEffects::all()
        }

        let mut sim = make_sim_with_policy(counting_policy);
        CALL_COUNT.store(0, Ordering::Relaxed);

        // PowerOn invokes the policy once (Cold)
        let _ = sim.process(SimEvent::PowerOn);
        assert_eq!(
            CALL_COUNT.load(Ordering::Relaxed),
            1,
            "PowerOn should invoke policy"
        );

        // PowerOff must NOT invoke the policy
        let _ = sim.process(SimEvent::PowerOff);
        assert_eq!(
            CALL_COUNT.load(Ordering::Relaxed),
            1,
            "PowerOff must not invoke reset policy"
        );
    }

    #[test]
    fn multiple_resets_each_invoke_policy() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static CALL_COUNT: AtomicU8 = AtomicU8::new(0);
        fn counting_policy(kind: ResetKind) -> ResetEffects {
            let _ = kind;
            CALL_COUNT.fetch_add(1, Ordering::Relaxed);
            ResetEffects::all()
        }

        let mut sim = make_sim_with_policy(counting_policy);
        CALL_COUNT.store(0, Ordering::Relaxed);

        let _ = sim.process(SimEvent::PowerOn); // call 1
        let _ = sim.process(SimEvent::Reset); // call 2
        let _ = sim.process(SimEvent::Reset); // call 3
        let _ = sim.process(SimEvent::Reset); // call 4

        assert_eq!(
            CALL_COUNT.load(Ordering::Relaxed),
            4,
            "policy should be invoked on every PowerOn and Reset"
        );
    }

    #[test]
    fn power_cycle_always_passes_cold() {
        use core::sync::atomic::{AtomicU8, Ordering};
        static LAST_KIND: AtomicU8 = AtomicU8::new(0xFF);
        fn recording(kind: ResetKind) -> ResetEffects {
            LAST_KIND.store(kind as u8, Ordering::Relaxed);
            ResetEffects::all()
        }

        let mut sim = make_sim_with_policy(recording);

        // First PowerOn -> Cold
        let _ = sim.process(SimEvent::PowerOn);
        assert_eq!(LAST_KIND.load(Ordering::Relaxed), ResetKind::Cold as u8);

        // Warm reset -> Warm
        let _ = sim.process(SimEvent::Reset);
        assert_eq!(LAST_KIND.load(Ordering::Relaxed), ResetKind::Warm as u8);

        // PowerOff -> PowerOn should be Cold (not Warm)
        let _ = sim.process(SimEvent::PowerOff);
        let _ = sim.process(SimEvent::PowerOn);
        assert_eq!(
            LAST_KIND.load(Ordering::Relaxed),
            ResetKind::Cold as u8,
            "PowerOn after PowerOff must pass Cold, not Warm"
        );
    }

    #[test]
    fn reset_from_off_state_transitions_to_ready() {
        let mut sim = make_sim();
        // Card starts Off. Reset from Off -> should transition to Ready.
        let rsp = sim.process(SimEvent::Reset);
        assert!(
            matches!(rsp, SimResponse::Atr(_)),
            "Reset from Off should return ATR (transition to Ready)"
        );

        // Card should now accept APDUs
        let rsp = sim.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, sw2] = sw.to_bytes();
                assert_eq!(
                    [sw1, sw2],
                    [0x6E, 0x00],
                    "card should be Ready after Reset from Off"
                );
            }
            other => panic!("expected Apdu, got {other:?}"),
        }
    }

    #[test]
    fn struct_update_syntax_produces_single_false_flag() {
        let effects = ResetEffects {
            clear_pin_verified: false,
            ..ResetEffects::all()
        };
        assert!(!effects.clear_pin_verified);
        assert!(effects.clear_response_queue);
        assert!(effects.clear_file_selection);
        assert!(effects.clear_logical_channels);
        assert!(effects.clear_proactive_session);
        assert!(effects.clear_last_aid_match);
    }

    #[test]
    fn struct_update_syntax_produces_single_true_flag() {
        let effects = ResetEffects {
            clear_response_queue: true,
            ..ResetEffects::none()
        };
        assert!(!effects.clear_pin_verified);
        assert!(effects.clear_response_queue);
        assert!(!effects.clear_file_selection);
        assert!(!effects.clear_logical_channels);
        assert!(!effects.clear_proactive_session);
        assert!(!effects.clear_last_aid_match);
    }

    // -----------------------------------------------------------------------
    // Proptest
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn process_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let mut sim = make_sim();
            let _ = sim.process(SimEvent::PowerOn);
            let _ = sim.process(SimEvent::Apdu(&bytes));
        }

        #[test]
        fn short_apdu_always_ignored(len in 0usize..4) {
            let bytes = [0x00u8; 3];
            let mut sim = make_sim();
            let _ = sim.process(SimEvent::PowerOn);
            let rsp = sim.process(SimEvent::Apdu(&bytes[..len]));
            assert!(matches!(rsp, SimResponse::Ignored));
        }
    }
}
