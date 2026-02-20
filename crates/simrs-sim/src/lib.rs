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
//! use simrs_fs::DfDef;
//!
//! static MF: DfDef = DfDef { fid: 0x3F00, children: &[] };
//! static ATR: [u8; 2] = [0x3B, 0x00];
//!
//! let mut sim = Sim::<256>::new(&ATR, &MF);
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
use simrs_iso7816::{Command, StatusWord};
#[cfg(feature = "usim")]
use simrs_usim::UsimApp;

// ---------------------------------------------------------------------------
// CLA byte classification
// ---------------------------------------------------------------------------

/// GSM 11.11 proprietary CLA byte.
#[cfg(feature = "gsm")]
const CLA_GSM: u8 = 0xA0;

/// Interindustry CLA byte (ETSI TS 102 221).
#[cfg(feature = "usim")]
const CLA_INTER: u8 = 0x00;

/// ETSI CAT proprietary CLA byte.
#[cfg(feature = "usim")]
const CLA_ETSI: u8 = 0x80;

// ---------------------------------------------------------------------------
// SimEvent / SimResponse
// ---------------------------------------------------------------------------

/// An event delivered to the SIM card.
///
/// Per ISO/IEC 7816-3, the card lifecycle is:
/// 1. `PowerOn` -- card activation, returns ATR
/// 2. `Apdu` -- command exchange (repeats)
/// 3. `Reset` -- warm reset, returns ATR, clears session state
#[derive(Debug, Clone, Copy)]
pub enum SimEvent<'a> {
    /// Card power-on (cold reset). Returns ATR.
    PowerOn,
    /// Warm reset. Returns ATR and clears session state.
    Reset,
    /// APDU command (raw bytes, at least 4 for CLA INS P1 P2).
    Apdu(&'a [u8]),
}

/// A response produced by the SIM card.
#[derive(Debug)]
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
pub struct Sim<const RSP_CAP: usize = 256> {
    atr: &'static [u8],
    state: CardState,
    rsp_buf: [u8; RSP_CAP],
    #[cfg(feature = "gsm")]
    gsm: GsmApp,
    #[cfg(feature = "usim")]
    usim: UsimApp,
    #[cfg(not(any(feature = "gsm", feature = "usim")))]
    _mf: &'static DfDef,
}

impl<const RSP_CAP: usize> Sim<RSP_CAP> {
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
        }
    }

    /// Create a new SIM card with GSM application layer.
    ///
    /// The COMP128 Ki is zero-initialized. Use [`gsm_app_mut`](Self::gsm_app_mut)
    /// to replace the `GsmApp` with properly configured credentials
    /// (e.g. `*sim.gsm_app_mut() = GsmApp::new(mf, ki)`).
    ///
    /// Configure PINs via `sim.gsm_app_mut().pin_manager().add_pin(...)`.
    #[cfg(all(feature = "gsm", not(feature = "usim")))]
    pub const fn new(atr: &'static [u8], mf: &'static DfDef) -> Self {
        Self {
            atr,
            state: CardState::Off,
            rsp_buf: [0u8; RSP_CAP],
            gsm: GsmApp::new(mf, [0u8; 16]),
        }
    }

    /// Create a new SIM card with USIM application layer.
    ///
    /// Milenage K/OPc are zero-initialized. Use [`usim_app_mut`](Self::usim_app_mut)
    /// to replace the `UsimApp` with properly configured credentials
    /// (e.g. `*sim.usim_app_mut() = UsimApp::new(mf, adfs, milenage)`).
    ///
    /// Configure PINs via `sim.usim_app_mut().pin_manager().add_pin(...)`.
    #[cfg(all(feature = "usim", not(feature = "gsm")))]
    pub fn new(atr: &'static [u8], mf: &'static DfDef) -> Self {
        Self {
            atr,
            state: CardState::Off,
            rsp_buf: [0u8; RSP_CAP],
            usim: UsimApp::new(
                mf,
                &[],
                simrs_milenage::MilenageParams::with_defaults(
                    [0u8; 16],
                    simrs_milenage::OpVariant::Opc([0u8; 16]),
                ),
            ),
        }
    }

    /// Create a new SIM card with both GSM and USIM application layers.
    ///
    /// Both Ki and Milenage K/OPc are zero-initialized.
    /// Use [`gsm_app_mut`](Self::gsm_app_mut) and
    /// [`usim_app_mut`](Self::usim_app_mut) to replace the app layers with
    /// properly configured credentials before activating the card.
    #[cfg(all(feature = "gsm", feature = "usim"))]
    pub fn new(atr: &'static [u8], mf: &'static DfDef) -> Self {
        Self {
            atr,
            state: CardState::Off,
            rsp_buf: [0u8; RSP_CAP],
            gsm: GsmApp::new(mf, [0u8; 16]),
            usim: UsimApp::new(
                mf,
                &[],
                simrs_milenage::MilenageParams::with_defaults(
                    [0u8; 16],
                    simrs_milenage::OpVariant::Opc([0u8; 16]),
                ),
            ),
        }
    }

    // -- Accessors --

    /// Access the GSM application layer for configuration.
    ///
    /// Use this to replace the app with configured credentials:
    /// ```ignore
    /// *sim.gsm_app_mut() = GsmApp::new(mf, ki);
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
    /// *sim.usim_app_mut() = UsimApp::new(mf, adfs, milenage);
    /// sim.usim_app_mut().pin_manager().add_pin(...);
    /// ```
    #[cfg(feature = "usim")]
    pub const fn usim_app_mut(&mut self) -> &mut UsimApp {
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
    /// - `Apdu`: parses the command, routes by CLA byte, returns
    ///   [`SimResponse::Apdu`] or [`SimResponse::Ignored`] if malformed
    ///   or the card is not powered on.
    pub fn process(&mut self, event: SimEvent<'_>) -> SimResponse<'_> {
        match event {
            SimEvent::PowerOn | SimEvent::Reset => {
                self.state = CardState::Ready;
                self.reset_session_state();
                SimResponse::Atr(self.atr)
            }
            SimEvent::Apdu(bytes) => {
                if self.state != CardState::Ready {
                    return SimResponse::Ignored;
                }
                self.handle_apdu(bytes)
            }
        }
    }

    /// Clear session state on power-on or reset.
    ///
    /// Clears the PIN verified flags so that access-controlled operations
    /// require re-verification after reset.
    ///
    /// NOTE: Currently no command handler in `GsmApp`/`UsimApp` consults
    /// `is_verified()` (access control is always-allowed). This call is
    /// structurally correct per ETSI TS 102 221 clause 11.1.9 and will
    /// become observable when access control enforcement is added.
    // Allow: when no features are enabled, all cfg blocks compile away
    // leaving an empty body. The method is kept for structural correctness.
    #[allow(clippy::unused_self, clippy::needless_pass_by_ref_mut, clippy::missing_const_for_fn)]
    fn reset_session_state(&mut self) {
        #[cfg(feature = "gsm")]
        {
            self.gsm.pin_manager().reset_verified();
        }
        #[cfg(feature = "usim")]
        {
            self.usim.pin_manager().reset_verified();
        }
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes.
    ///
    /// Varies by enabled features: CardState(1) + GsmApp(159) + UsimApp(560).
    pub const SNAPSHOT_SIZE: usize = 1
        + { #[cfg(feature = "gsm")] { GsmApp::SNAPSHOT_SIZE } #[cfg(not(feature = "gsm"))] { 0 } }
        + { #[cfg(feature = "usim")] { UsimApp::SNAPSHOT_SIZE } #[cfg(not(feature = "usim"))] { 0 } };

    /// Serialize the SIM state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    /// Static references (ATR, MF tree) and transient buffers are not serialized.
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
            off += UsimApp::SNAPSHOT_SIZE;
        }
        let _ = off;
        true
    }

    /// Compute an FNV-1a hash of the serialized state for deduplication.
    pub fn state_hash(&self) -> u64 {
        let mut buf = [0u8; 1024];
        let n = self.save_state(&mut buf);
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

        let rsp_slice = match cla {
            #[cfg(feature = "gsm")]
            CLA_GSM => self.gsm.handle(&cmd, &mut self.rsp_buf),

            #[cfg(feature = "usim")]
            CLA_INTER | CLA_ETSI => self.usim.handle(&cmd, &mut self.rsp_buf),

            _ => {
                let sw = StatusWord::ClassNotSupported.to_bytes();
                self.rsp_buf[0] = sw[0];
                self.rsp_buf[1] = sw[1];
                &self.rsp_buf[..2]
            }
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
    use simrs_fs::{DfDef, EfDef, EfStructure, FileRef};

    #[cfg(feature = "usim")]
    use simrs_fs::AdfSlot;
    #[cfg(feature = "usim")]
    use simrs_milenage::{MilenageParams, OpVariant};
    #[cfg(any(feature = "gsm", feature = "usim"))]
    use simrs_pin::{PinKey, PinValue};

    // -- Test filesystem (shared across features) --

    static ICCID_DATA: [u8; 10] =
        [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

    static EF_ICCID: EfDef = EfDef {
        fid: 0x2FE2,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &ICCID_DATA,
    };

    static MF: DfDef = DfDef {
        fid: 0x3F00,
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

    // -- USIM-only test statics --

    #[cfg(feature = "usim")]
    static IMSI_DATA: [u8; 9] = [0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01];

    #[cfg(feature = "usim")]
    static EF_IMSI: EfDef = EfDef {
        fid: 0x6F07,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &IMSI_DATA,
    };

    #[cfg(feature = "usim")]
    static ADF_USIM_DF: DfDef = DfDef {
        fid: 0x7FFF,
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

    fn make_sim() -> Sim<256> {
        #[allow(unused_mut)]
        let mut sim = Sim::<256>::new(&ATR, &MF);

        #[cfg(feature = "gsm")]
        {
            use simrs_gsm::GsmApp;
            let gsm = sim.gsm_app_mut();
            *gsm = GsmApp::new(&MF, [0x11u8; 16]);
            let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
            let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
            let _ = gsm.pin_manager().add_pin(PinKey(0x01), &pin, 3, &puk, 10, true);
        }

        #[cfg(feature = "usim")]
        {
            use simrs_usim::UsimApp;
            let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
            let usim = sim.usim_app_mut();
            *usim = UsimApp::new(&MF, &ADF_TABLE, mil);
            let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
            let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
            let _ = usim.pin_manager().add_pin(PinKey(0x01), &pin, 3, &puk, 10, true);
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
        sim.process(SimEvent::PowerOn);
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

    // -----------------------------------------------------------------------
    // Malformed APDU
    // -----------------------------------------------------------------------

    #[test]
    fn short_apdu_returns_ignored() {
        let mut sim = make_sim();
        sim.process(SimEvent::PowerOn);
        let rsp = sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    #[test]
    fn empty_apdu_returns_ignored() {
        let mut sim = make_sim();
        sim.process(SimEvent::PowerOn);
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
        sim.process(SimEvent::PowerOn);
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
        sim.process(SimEvent::PowerOn);

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
        sim.process(SimEvent::PowerOn);
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
        sim.process(SimEvent::PowerOn);
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
        sim.process(SimEvent::PowerOn);

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
        sim.process(SimEvent::PowerOn);

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
        sim.process(SimEvent::PowerOn);
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
        sim.process(SimEvent::PowerOn);

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
        sim.process(SimEvent::PowerOn);

        // SELECT MF + GET RESPONSE
        sim.process(SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]));
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
        sim.process(SimEvent::PowerOn);
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
        sim.process(SimEvent::PowerOn);

        // Verify PIN via GSM (correct PIN -> 90 00)
        let rsp = sim.process(SimEvent::Apdu(
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        ));
        match rsp {
            SimResponse::Apdu { sw1, sw2, .. } => assert_eq!((sw1, sw2), (0x90, 0x00)),
            _ => panic!("expected successful VERIFY"),
        }

        // Reset
        sim.process(SimEvent::Reset);

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
        let mut buf = [0u8; 1024];
        let n = sim.save_state(&mut buf);
        assert_eq!(n, Sim::<256>::SNAPSHOT_SIZE);
    }

    #[test]
    fn snapshot_roundtrip_preserves_card_state() {
        let mut sim = make_sim();
        sim.process(SimEvent::PowerOn);

        let mut snap = [0u8; 1024];
        let n = sim.save_state(&mut snap);
        assert_eq!(n, Sim::<256>::SNAPSHOT_SIZE);

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
        let mut snap = [0u8; 1024];
        let n = sim.save_state(&mut snap);
        assert_eq!(n, Sim::<256>::SNAPSHOT_SIZE);

        let mut restored = make_sim();
        restored.process(SimEvent::PowerOn); // make it Ready
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
        sim.process(SimEvent::PowerOn);
        let h2 = sim.state_hash();
        assert_ne!(h1, h2, "hash should differ after PowerOn");
    }

    #[test]
    fn snapshot_restore_invalid_card_state() {
        let sim = make_sim();
        let mut snap = [0u8; 1024];
        let n = sim.save_state(&mut snap);
        assert!(n > 0);
        // Corrupt the card state byte.
        snap[0] = 0xFF;
        let mut sim2 = make_sim();
        assert!(!sim2.restore_state(&snap[..n]));
    }

    // -----------------------------------------------------------------------
    // Proptest
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn process_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let mut sim = make_sim();
            sim.process(SimEvent::PowerOn);
            let _ = sim.process(SimEvent::Apdu(&bytes));
        }

        #[test]
        fn short_apdu_always_ignored(len in 0usize..4) {
            let bytes = [0x00u8; 3];
            let mut sim = make_sim();
            sim.process(SimEvent::PowerOn);
            let rsp = sim.process(SimEvent::Apdu(&bytes[..len]));
            assert!(matches!(rsp, SimResponse::Ignored));
        }
    }
}
