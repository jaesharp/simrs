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
//!     -> SimResponse::Apdu { data, sw1, sw2 }
//! ```
//!
//! # Features
//!
//! - `gsm` -- enables GSM 11.11 application layer (CLA=`0xA0`)
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
//! ```
//! use simrs_sim::{Sim, SimEvent, SimResponse};
//! use simrs_milenage::MilenageParams;
//! use simrs_fs::{DfDef, Fid};
//!
//! static MF: DfDef = DfDef { fid: Fid::new(0x3F00), children: &[] };
//! static ATR: [u8; 2] = [0x3B, 0x00];
//!
//! let mut sim = Sim::<MilenageParams, 256>::new(&ATR, &MF);
//!
//! // Power on returns ATR
//! let rsp = sim.process(SimEvent::PowerOn);
//! assert!(matches!(rsp, SimResponse::Atr(&[0x3B, 0x00])));
//!
//! // Unsupported CLA (0xF0 is never routed)
//! let rsp = sim.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
//! match rsp {
//!     SimResponse::Apdu { sw1: 0x6E, sw2: 0x00, .. } => {} // class not supported
//!     _ => panic!("expected 6E 00"),
//! }
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// Many 3GPP terms used in docs (CLA, USIM, ATR, etc.)
#![allow(clippy::doc_markdown)]

use simrs_fs::DfDef;
#[cfg(feature = "gsm")]
use simrs_gsm::GsmApp;
use simrs_iso7816::{Command, StatusWord, write_sw};
use simrs_milenage::{AuthenticationAlgorithm, MilenageParams};
#[cfg(feature = "usim")]
use simrs_usim::UsimApp;

// ---------------------------------------------------------------------------
// State hash buffer upper bound
// ---------------------------------------------------------------------------

// Rust does not allow `Self::SNAPSHOT_SIZE` in array-length position for
// generic types.  We compute a fixed upper bound from the non-generic
// component sizes.  The `Sim::state_hash` method uses a `debug_assert_eq`
// to verify the bound at runtime.
#[cfg(all(feature = "gsm", feature = "usim"))]
const STATE_HASH_BUF: usize = 1 + GsmApp::SNAPSHOT_SIZE + {
    // UsimApp<A>::SNAPSHOT_SIZE depends on A::SNAPSHOT_SIZE.
    // MilenageParams::SNAPSHOT_SIZE is the largest known auth algorithm.
    // TuakParams would be similar.  Add headroom for future algorithms.
    simrs_usim::UsimApp::<MilenageParams>::SNAPSHOT_SIZE + 256
};

#[cfg(all(feature = "gsm", not(feature = "usim")))]
const STATE_HASH_BUF: usize = 1 + GsmApp::SNAPSHOT_SIZE + 256;

#[cfg(all(not(feature = "gsm"), feature = "usim"))]
const STATE_HASH_BUF: usize = 1 + simrs_usim::UsimApp::<MilenageParams>::SNAPSHOT_SIZE + 256;

#[cfg(all(not(feature = "gsm"), not(feature = "usim")))]
const STATE_HASH_BUF: usize = 256;

// ---------------------------------------------------------------------------
// CLA byte classification
// ---------------------------------------------------------------------------

/// CLA family classification per ETSI TS 102 221.
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
/// 3. `Reset` -- warm reset, returns ATR, clears session state
/// 4. `PowerOff` -- card deactivation, returns `Ignored`
///
/// The `Tick` variant is an extension for advancing UICC-side timers
/// (per ETSI TS 102 223 clause 6.6.21). Since `no_std` has no clock,
/// the caller supplies elapsed seconds.
#[derive(Debug, Clone, Copy)]
pub enum SimEvent<'a> {
    /// Card power-on (cold reset). Returns ATR.
    PowerOn,
    /// Warm reset. Returns ATR and clears session state.
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
        /// Status word byte 1.
        sw1: u8,
        /// Status word byte 2.
        sw2: u8,
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
pub struct Sim<A: AuthenticationAlgorithm = MilenageParams, const RSP_CAP: usize = 256> {
    atr: &'static [u8],
    state: CardState,
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

    /// Create a new SIM card (no application features enabled).
    ///
    /// All APDUs will return `6E 00` (class not supported).
    #[cfg(not(any(feature = "gsm", feature = "usim")))]
    pub const fn new(atr: &'static [u8], mf: &'static DfDef) -> Self {
        Self {
            atr,
            state: CardState::Off,
            rsp_buf: [0u8; RSP_CAP],
            _mf: mf,
            _auth: core::marker::PhantomData,
        }
    }

    /// Create a new SIM card with GSM application layer.
    ///
    /// The COMP128 Ki is zero-initialized. Use [`gsm_app_mut`](Self::gsm_app_mut)
    /// to replace the `GsmApp` with properly configured credentials
    /// (e.g. `*sim.gsm_app_mut() = GsmApp::new(mf, Ki(ki))`).
    ///
    /// Configure PINs via `sim.gsm_app_mut().pin_manager().add_pin(...)`.
    #[cfg(all(feature = "gsm", not(feature = "usim")))]
    pub fn new(atr: &'static [u8], mf: &'static DfDef) -> Self {
        Self {
            atr,
            state: CardState::Off,
            rsp_buf: [0u8; RSP_CAP],
            gsm: GsmApp::new(mf, simrs_gsm::Ki([0u8; 16])),
            _auth: core::marker::PhantomData,
        }
    }

    /// Create a new SIM card with USIM application layer.
    ///
    /// Authentication parameters are zero-initialized. Use
    /// [`usim_app_mut`](Self::usim_app_mut) to replace the `UsimApp` with
    /// properly configured credentials
    /// (e.g. `*sim.usim_app_mut() = UsimApp::new(mf, adfs, auth)`).
    ///
    /// Configure PINs via `sim.usim_app_mut().pin_manager().add_pin(...)`.
    #[cfg(all(feature = "usim", not(feature = "gsm")))]
    pub fn new(atr: &'static [u8], mf: &'static DfDef) -> Self
    where
        A: Default,
    {
        Self {
            atr,
            state: CardState::Off,
            rsp_buf: [0u8; RSP_CAP],
            usim: UsimApp::new(mf, &[], A::default()),
        }
    }

    /// Create a new SIM card with both GSM and USIM application layers.
    ///
    /// Both Ki and authentication parameters are zero-initialized.
    /// Use [`gsm_app_mut`](Self::gsm_app_mut) and
    /// [`usim_app_mut`](Self::usim_app_mut) to replace the app layers with
    /// properly configured credentials before activating the card.
    #[cfg(all(feature = "gsm", feature = "usim"))]
    pub fn new(atr: &'static [u8], mf: &'static DfDef) -> Self
    where
        A: Default,
    {
        Self {
            atr,
            state: CardState::Off,
            rsp_buf: [0u8; RSP_CAP],
            gsm: GsmApp::new(mf, simrs_gsm::Ki([0u8; 16])),
            usim: UsimApp::new(mf, &[], A::default()),
        }
    }

    // -- Accessors --

    /// Access the GSM application layer for configuration.
    ///
    /// Use this to replace the app with configured credentials:
    /// ```ignore
    /// *sim.gsm_app_mut() = GsmApp::new(mf, Ki(ki));
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
    /// Never panics.
    ///
    /// - `PowerOn` / `Reset`: returns [`SimResponse::Atr`].
    ///   Both clear PIN verified state.
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
            SimEvent::PowerOn | SimEvent::Reset => {
                self.state = CardState::Ready;
                self.reset_session_state();
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

    /// Clear session state on power-on or reset.
    ///
    /// Per ETSI TS 102 221, a cold reset clears:
    /// - PIN verified flags (re-verification required after reset)
    /// - Response queue (no stale GET RESPONSE data from prior session)
    /// - File selection context (MF implicitly selected)
    /// - Logical channels
    // Allow: when no features are enabled, all cfg blocks compile away
    // leaving an empty body. The method is kept for structural correctness.
    #[allow(clippy::unused_self, clippy::needless_pass_by_ref_mut, clippy::missing_const_for_fn)]
    fn reset_session_state(&mut self) {
        #[cfg(feature = "gsm")]
        {
            self.gsm.pin_manager().reset_verified();
            self.gsm.reset_session();
        }
        #[cfg(feature = "usim")]
        {
            self.usim.pin_manager().reset_verified();
            self.usim.reset_session();
        }
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes.
    ///
    /// Varies by enabled features and profile tiers:
    /// CardState(1) + GsmApp::SNAPSHOT\_SIZE + UsimApp::\<A\>::SNAPSHOT\_SIZE.
    pub const SNAPSHOT_SIZE: usize = 1
        + { #[cfg(feature = "gsm")] { GsmApp::SNAPSHOT_SIZE } #[cfg(not(feature = "gsm"))] { 0 } }
        + { #[cfg(feature = "usim")] { UsimApp::<A>::SNAPSHOT_SIZE } #[cfg(not(feature = "usim"))] { 0 } };

    /// Serialize the SIM state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    /// Static references (ATR, MF tree) and transient buffers are not serialized.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut off = 0;
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
        let mut off = 0;
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
            sw1: rsp_slice[sw_offset],
            sw2: rsp_slice[sw_offset + 1],
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
mod tests {
    use super::*;
    use simrs_fs::{DfDef, EfDef, Fid, FileRef};

    #[cfg(feature = "usim")]
    use simrs_fs::AdfSlot;
    use simrs_milenage::MilenageParams;
    #[cfg(feature = "usim")]
    use simrs_milenage::OperatorVariant;
    #[cfg(any(feature = "gsm", feature = "usim"))]
    use simrs_pin::{PinKey, PinValue};

    // -- Test filesystem (shared across features) --

    static ICCID_DATA: [u8; 10] =
        [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

    static EF_ICCID: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        None,
        &ICCID_DATA,
    );

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

    // -- USIM-only test statics --

    #[cfg(feature = "usim")]
    static IMSI_DATA: [u8; 9] = [0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01];

    #[cfg(feature = "usim")]
    static EF_IMSI: EfDef = EfDef::transparent(
        Fid::new(0x6F07),
        None,
        &IMSI_DATA,
    );

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
        #[allow(unused_mut)]
        let mut sim = Sim::<MilenageParams, 256>::new(&ATR, &MF);

        #[cfg(feature = "gsm")]
        {
            use simrs_gsm::GsmApp;
            let gsm = sim.gsm_app_mut();
            *gsm = GsmApp::new(&MF, simrs_gsm::Ki([0x11u8; 16]));
            let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
            let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
            let _ = gsm.pin_manager().add_pin(PinKey::PIN1, &pin, 3, &puk, 10, true);
        }

        #[cfg(feature = "usim")]
        {
            use simrs_usim::UsimApp;
            let mil = MilenageParams::with_defaults([0u8; 16], OperatorVariant::Opc([0u8; 16]));
            let usim = sim.usim_app_mut();
            *usim = UsimApp::new(&MF, &ADF_TABLE, mil);
            let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
            let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
            let _ = usim.pin_manager().add_pin(PinKey::PIN1, &pin, 3, &puk, 10, true);
        }

        sim
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

    #[test]
    fn power_off_then_power_on_works() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);
        let _ = sim.process(SimEvent::PowerOff);

        // PowerOn after PowerOff should work normally
        let rsp = sim.process(SimEvent::PowerOn);
        assert!(matches!(rsp, SimResponse::Atr(_)));

        // APDUs should work again
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw1, .. } => assert_eq!(sw1, 0x61),
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
            SimResponse::Apdu { sw1, .. } => {
                assert_eq!(sw1, 0x9F, "expected GSM SELECT response 9F XX");
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
        let SimResponse::Apdu { sw1: 0x9F, sw2: le, .. } = rsp else {
            panic!("expected 9F XX from GSM SELECT")
        };

        // GET RESPONSE
        let mut apdu = [0xA0, 0xC0, 0x00, 0x00, 0x00];
        apdu[4] = le;
        let rsp = sim.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw1, sw2 } => {
                assert_eq!((sw1, sw2), (0x90, 0x00));
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
            SimResponse::Apdu { sw1, .. } => {
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
        let rsp = sim.process(SimEvent::Apdu(
            &[0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF],
        ));
        match rsp {
            SimResponse::Apdu { sw1, sw2, .. } => {
                assert_eq!((sw1, sw2), (0x90, 0x00));
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
            SimResponse::Apdu { sw1, sw2, .. } => {
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
        let SimResponse::Apdu { sw1: 0x61, sw2: le, .. } = rsp else {
            panic!("expected 61 XX from USIM SELECT")
        };

        // GET RESPONSE
        let mut apdu = [0x00, 0xC0, 0x00, 0x00, 0x00];
        apdu[4] = le;
        let rsp = sim.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw1, sw2 } => {
                assert_eq!((sw1, sw2), (0x90, 0x00));
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
            SimResponse::Apdu { sw1, sw2, data } => {
                assert_eq!((sw1, sw2), (0x6E, 0x00));
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
            SimResponse::Apdu { sw1, sw2, .. } => {
                #[cfg(any(feature = "gsm", feature = "usim"))]
                assert_eq!((sw1, sw2), (0x6D, 0x00), "expected INS not supported");
                #[cfg(not(any(feature = "gsm", feature = "usim")))]
                assert_eq!((sw1, sw2), (0x6E, 0x00), "expected CLA not supported");
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
            SimResponse::Apdu { data, sw1, sw2 } => {
                assert!(!data.is_empty(), "response should have data");
                assert_eq!((sw1, sw2), (0x90, 0x00));
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
            SimResponse::Apdu { data, sw1, sw2 } => {
                assert!(data.is_empty());
                assert_eq!((sw1, sw2), (0x6E, 0x00));
            }
            _ => panic!("expected Apdu response"),
        }
    }

    // -----------------------------------------------------------------------
    // Reset clears PIN state
    // -----------------------------------------------------------------------

    // NOTE: This test verifies that reset_session_state() calls
    // reset_verified() without error, and that the VERIFY command path
    // works correctly through a reset boundary. However, currently no
    // command handler in GsmApp/UsimApp consults is_verified() for access
    // control (all operations are "always allowed"). The reset_verified()
    // call is structurally correct per ETSI TS 102 221 clause 11.1.9 and
    // will become behaviorally testable when access control enforcement is
    // added to the application layers.
    #[cfg(feature = "gsm")]
    #[test]
    fn reset_allows_pin_reverification() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        // Verify PIN via GSM (correct PIN -> 90 00)
        let rsp = sim.process(SimEvent::Apdu(
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        ));
        match rsp {
            SimResponse::Apdu { sw1, sw2, .. } => assert_eq!((sw1, sw2), (0x90, 0x00)),
            _ => panic!("expected successful VERIFY"),
        }

        // Reset
        let _ = sim.process(SimEvent::Reset);

        // After reset, re-verify with correct PIN succeeds (counter is intact).
        let rsp = sim.process(SimEvent::Apdu(
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        ));
        match rsp {
            SimResponse::Apdu { sw1, sw2, .. } => {
                assert_eq!(
                    (sw1, sw2),
                    (0x90, 0x00),
                    "correct PIN should succeed after reset"
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
            SimResponse::Apdu { sw1, sw2, .. } => assert_eq!((sw1, sw2), (0x6E, 0x00)),
            _ => panic!("expected Apdu response"),
        }
    }

    #[cfg(all(feature = "usim", not(feature = "gsm")))]
    #[test]
    fn usim_only_rejects_gsm_cla() {
        let mut sim = make_sim();
        sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw1, sw2, .. } => assert_eq!((sw1, sw2), (0x6E, 0x00)),
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
            SimResponse::Apdu { sw1, sw2, .. } => {
                assert_eq!((sw1, sw2), (0x6E, 0x00));
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
        assert!(sim
            .usim_app_mut()
            .proactive_state()
            .start_timer(1, bcd_10s));

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
        let expired_id = sim
            .usim_app_mut()
            .proactive_state()
            .take_expired_timer();
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
        // so USIM returns 69 86 (command not allowed). This confirms the
        // Sim layer routed to USIM (not rejecting at the Sim level).
        let rsp = sim.process(SimEvent::Apdu(&[0x01, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
        match rsp {
            SimResponse::Apdu { sw1, sw2, .. } => {
                // Channel 1 not open -> 69 86 (command not allowed).
                assert_eq!((sw1, sw2), (0x69, 0x86));
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
            SimResponse::Apdu { sw1, .. } => {
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
            SimResponse::Apdu { sw1, sw2, .. } => {
                // Routed to USIM which rejects non-0x00/0x80 CLA values.
                assert_eq!((sw1, sw2), (0x6E, 0x00));
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
            SimResponse::Apdu { sw1, sw2, data } => {
                assert_eq!((sw1, sw2), (0x6E, 0x00));
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
            SimResponse::Apdu { sw1, sw2, .. } => {
                // Must get a real response (not Ignored). Exact SW depends on features.
                #[cfg(any(feature = "gsm", feature = "usim"))]
                assert_eq!(sw1, 0x90, "4-byte APDU should be processed, got SW {sw1:02X} {sw2:02X}");
                #[cfg(not(any(feature = "gsm", feature = "usim")))]
                assert_eq!((sw1, sw2), (0x6E, 0x00), "no features: CLA not supported");
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
            SimResponse::Apdu { sw1, sw2, .. } => {
                assert_eq!((sw1, sw2), (0x90, 0x00),
                    "STATUS with Le=0 should succeed");
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
            SimResponse::Apdu { sw1, sw2, .. } => {
                #[cfg(any(feature = "gsm", feature = "usim"))]
                assert_eq!((sw1, sw2), (0x6D, 0x00),
                    "unknown INS must return 6D 00");
                #[cfg(not(any(feature = "gsm", feature = "usim")))]
                assert_eq!((sw1, sw2), (0x6E, 0x00),
                    "no features: CLA not supported");
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
                SimResponse::Apdu { sw1, sw2, data } => {
                    assert_eq!((sw1, sw2), (0x6E, 0x00),
                        "CLA 0x{cla:02X} must return 6E 00, got {sw1:02X} {sw2:02X}");
                    assert!(data.is_empty(),
                        "error response for CLA 0x{cla:02X} must have empty data");
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
        assert!(matches!(rsp, SimResponse::Ignored),
            "3-byte APDU must return Ignored");
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
