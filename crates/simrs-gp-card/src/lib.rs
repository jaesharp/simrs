//! `GlobalPlatform` card -- top-level event-driven card type.
//!
//! Parallel to [`simrs_sim::Sim`] for SIM/USIM cards, `GpCard` provides the
//! same `process(event) -> response` interface so it integrates with the
//! existing infrastructure (HLE, interposer, fuzzer, QEMU bridge).
//!
//! # Architecture
//!
//! ```text
//! SimEvent::Apdu(bytes)
//!     -> GpCard::handle_apdu(bytes)
//!         -> GpOpen::handle(cmd_bytes, buf)
//!             -> GP management commands / applet dispatch
//!     -> SimResponse::Apdu { data, sw }
//! ```
//!
//! # Event/Response types
//!
//! Uses [`SimEvent`] and [`SimResponse`] from `simrs-card-api`, shared with
//! `simrs-sim`. Both card types use the same event/response types so they
//! integrate with the same infrastructure (HLE, interposer, fuzzer, QEMU).
//!
//! # `no_std`
//! This crate is `no_std`. The embedded `JcVM` inside `GpOpen` is
//! `Box`-allocated to avoid stack overflow (so the `GpOpen` crate
//! pulls in `alloc`), but `GpCard` itself does no heap allocation in
//! production paths -- the on-card entropy source is a generic type
//! parameter.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]

// Tests need `alloc::vec::Vec` for APDU buffers; the production paths
// are heap-free.
#[cfg(test)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub use simrs_card_api::{CardState, SimEvent, SimResponse, fnv1a};

use simrs_gp_keys::KeySet;
use simrs_gp_open::{DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS, GpOpen, snapshot::snapshot_size};
use simrs_iso7816::StatusWord;

/// Default response-buffer capacity for [`GpCard`].
///
/// Sized for the worst case of a 256-byte response + R-ENC padding
/// (Method 2 adds up to 16 bytes for an already-aligned input) +
/// 8-byte R-MAC trailer + 2-byte SW = 282 bytes, with 8 bytes of slack.
pub const DEFAULT_RSP_CAP: usize = 290;

#[cfg(feature = "sim")]
use simrs_gp_open::AppletLifecycle;
#[cfg(feature = "sim")]
use simrs_gp_open::registry::{self, AppletEntry};
#[cfg(feature = "sim")]
use simrs_jcre::{Applet, AppletResult};
#[cfg(feature = "sim")]
use simrs_milenage::MilenageParams;
#[cfg(feature = "sim")]
use simrs_sim::gp_adapter::SimApplet;

// ---------------------------------------------------------------------------
// Default ATR
// ---------------------------------------------------------------------------

/// Default ATR for a GlobalPlatform card.
///
/// Encodes: TS=3B (direct convention), T0=90 (TD1 present, 0 historical),
/// TD1=95 (T=1, TD2 present), TD2=80 (no further interface bytes, T=0),
/// T1=1F, historical bytes C3 83 80, TCK=73 21.
/// This is representative of a typical Java Card with GP 2.1.1 support.
const DEFAULT_ATR: &[u8] = &[0x3B, 0x90, 0x95, 0x80, 0x1F, 0xC3, 0x83, 0x80, 0x73, 0x21];

/// USIM AID: A0 00 00 00 87 10 02 (3GPP USIM RID + PIX).
#[cfg(feature = "sim")]
const USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

// ---------------------------------------------------------------------------
// State hash buffer
// ---------------------------------------------------------------------------

/// Fixed upper bound for the state hash buffer.
///
/// Equal to `1 + GpOpen` snapshot size for the default applet/SD
/// capacities. Computed via the standalone `snapshot_size` const fn so
/// the value does not depend on the `E` or `RSP_CAP` const generics --
/// Rust cannot prove independence in array-length position on a generic
/// impl, hence this module-level constant.
const STATE_HASH_BUF: usize = 1 + snapshot_size(DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS);

// ---------------------------------------------------------------------------
// GpCard
// ---------------------------------------------------------------------------

/// Top-level `GlobalPlatform` card simulator.
///
/// Generic parameters:
/// - `E`: on-card entropy source ([`simrs_card_api::EntropySource`]).
///   Production callers inject a hardware-backed implementation; tests
///   inject [`simrs_card_api::DeterministicRng`] with an explicit seed.
/// - `RSP_CAP`: internal response buffer size (default 290 bytes,
///   sufficient for the worst case of a 256-byte response + R-ENC
///   padding (Method 2 adds up to 16 bytes for an already-aligned
///   input) + 8-byte R-MAC trailer + 2-byte SW = 282 bytes, with
///   8 bytes of slack). Smaller buffers are accepted as the
///   const-generic parameter; in those cases `maybe_wrap_rmac` skips
///   R-MAC wrapping rather than panicking when the response would
///   overflow.
///
/// # Usage
///
/// ```ignore
/// use simrs_card_api::DeterministicRng;
/// use simrs_gp_card::{GpCard, SimEvent, SimResponse};
/// use simrs_gp_keys::KeySet;
///
/// let keys = KeySet::des3_2key([0x40; 16], [0x40; 16], [0x40; 16]);
/// let mut card = GpCard::new(DEFAULT_ATR, &keys, DeterministicRng::new(0x42));
/// let rsp = card.process(SimEvent::PowerOn);
/// // rsp is SimResponse::Atr(...)
/// ```
pub struct GpCard<E: simrs_card_api::EntropySource, const RSP_CAP: usize = DEFAULT_RSP_CAP> {
    atr: &'static [u8],
    state: CardState,
    open: GpOpen<E, DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS>,
    rsp_buf: [u8; RSP_CAP],
    #[cfg(feature = "sim")]
    sim_applet: Option<SimApplet<MilenageParams>>,
    /// Registry index of the SIM applet in `GpOpen`'s applet registry.
    #[cfg(feature = "sim")]
    sim_registry_idx: u8,
}

impl<E: simrs_card_api::EntropySource, const RSP_CAP: usize> GpCard<E, RSP_CAP> {
    /// Create a new GP card with the given ATR, ISD key set, and entropy source.
    ///
    /// The card starts powered off. The ISD is initialized with the
    /// provided keys and the card lifecycle is set to `OpReady`. The
    /// entropy source drives SCP01/SCP02-explicit-mode card-challenge
    /// generation; see [`simrs_card_api::EntropySource`] for the trait
    /// contract.
    pub fn new(atr: &'static [u8], isd_keys: &KeySet, rng: E) -> Self {
        Self {
            atr,
            state: CardState::Off,
            open: GpOpen::new(isd_keys, rng),
            rsp_buf: [0u8; RSP_CAP],
            #[cfg(feature = "sim")]
            sim_applet: None,
            #[cfg(feature = "sim")]
            sim_registry_idx: 0,
        }
    }

    /// Create a new GP card with the default ATR and the given ISD
    /// key set + entropy source.
    pub fn with_default_atr(isd_keys: &KeySet, rng: E) -> Self {
        Self::new(DEFAULT_ATR, isd_keys, rng)
    }

    /// Create a GP card with a SIM/USIM applet deployed.
    ///
    /// The SIM applet is registered at AID `A0 00 00 00 87 10 02` (USIM).
    /// SELECT this AID to route APDUs to the SIM logic. SELECT the ISD
    /// AID to access GP card management.
    ///
    /// # Panics
    ///
    /// Panics if the applet registry is full (all 16 slots occupied).
    #[cfg(feature = "sim")]
    pub fn with_sim(
        atr: &'static [u8],
        isd_keys: &KeySet,
        sim_applet: SimApplet<MilenageParams>,
        rng: E,
    ) -> Self {
        let mut open = GpOpen::new(isd_keys, rng);

        // Register the USIM AID in the GP registry.
        let slot = registry::find_empty_slot(open.registry())
            .expect("applet registry full -- cannot register SIM applet");
        open.registry_mut()[slot] = Some(AppletEntry::new(
            &USIM_AID,
            AppletLifecycle::Selectable,
            0x00,
        ));

        #[allow(clippy::cast_possible_truncation)]
        let sim_registry_idx = slot as u8;

        Self {
            atr,
            state: CardState::Off,
            open,
            rsp_buf: [0u8; RSP_CAP],
            sim_applet: Some(sim_applet),
            sim_registry_idx,
        }
    }

    /// Process an event and return the card's response.
    ///
    /// This is the main entry point, matching the `Sim::process()` interface.
    pub fn process(&mut self, event: SimEvent<'_>) -> SimResponse<'_> {
        match event {
            SimEvent::PowerOn => {
                self.state = CardState::Ready;
                SimResponse::Atr(self.atr)
            }
            SimEvent::Reset => {
                self.state = CardState::Ready;
                // Reset SCP session state -- a warm reset invalidates any
                // in-progress secure channel authentication.
                self.open.reset_scp_state();
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
            SimEvent::Tick(_) => SimResponse::Ignored,
        }
    }

    /// Handle an APDU command, delegating to `GpOpen`.
    fn handle_apdu(&mut self, bytes: &[u8]) -> SimResponse<'_> {
        // Minimum APDU is 4 bytes: CLA INS P1 P2.
        if bytes.len() < 4 {
            return SimResponse::Ignored;
        }

        let rsp_slice;

        #[cfg(feature = "sim")]
        {
            if let Some(ref mut sim) = self.sim_applet {
                let sim_idx = self.sim_registry_idx;
                rsp_slice = self.open.handle_with_dispatch(
                    bytes,
                    &mut self.rsp_buf,
                    Some(&mut |idx, cmd, out| {
                        if idx != sim_idx {
                            // Unknown applet index -- return 6D 00.
                            out[0] = 0x6D;
                            out[1] = 0x00;
                            return 2;
                        }
                        match sim.process(cmd, out) {
                            AppletResult::Ok(n) => {
                                out[n] = 0x90;
                                out[n + 1] = 0x00;
                                n + 2
                            }
                            AppletResult::Sw(sw) => {
                                let [s1, s2] = sw.to_bytes();
                                out[0] = s1;
                                out[1] = s2;
                                2
                            }
                        }
                    }),
                );
            } else {
                rsp_slice = self.open.handle(bytes, &mut self.rsp_buf);
            }
        }

        #[cfg(not(feature = "sim"))]
        {
            rsp_slice = self.open.handle(bytes, &mut self.rsp_buf);
        }

        // GpOpen always returns [data..., SW1, SW2].
        if rsp_slice.len() < 2 {
            return SimResponse::Ignored;
        }

        let sw_offset = rsp_slice.len() - 2;
        SimResponse::Apdu {
            data: &rsp_slice[..sw_offset],
            sw: StatusWord::from_bytes(rsp_slice[sw_offset], rsp_slice[sw_offset + 1]),
        }
    }

    // -- Accessors --

    /// Reference to the underlying GP OPEN runtime.
    pub const fn open(&self) -> &GpOpen<E, DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS> {
        &self.open
    }

    /// Mutable reference to the underlying GP OPEN runtime.
    pub const fn open_mut(&mut self) -> &mut GpOpen<E, DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS> {
        &mut self.open
    }

    /// The card's ATR.
    pub const fn atr(&self) -> &'static [u8] {
        self.atr
    }

    /// Whether the card is currently powered and ready.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, CardState::Ready)
    }

    /// Reference to the SIM applet, if one is deployed.
    #[cfg(feature = "sim")]
    pub const fn sim_applet(&self) -> Option<&SimApplet<MilenageParams>> {
        self.sim_applet.as_ref()
    }

    /// Mutable reference to the SIM applet, if one is deployed.
    #[cfg(feature = "sim")]
    pub const fn sim_applet_mut(&mut self) -> Option<&mut SimApplet<MilenageParams>> {
        self.sim_applet.as_mut()
    }

    // -- State hash --

    /// Compute an FNV-1a hash of the serialized state for deduplication.
    ///
    /// Mirrors `Sim::state_hash()` so both card types expose the same
    /// interface for HLE deduplication.
    #[allow(clippy::large_stack_arrays)]
    pub fn state_hash(&self) -> u64 {
        // Use a module-level constant to avoid the
        // `const-evaluatable-unchecked` error when referencing
        // `Self::SNAPSHOT_SIZE` in array-length position on a generic impl.
        const HASH_BUF: usize = STATE_HASH_BUF;
        let mut buf = [0u8; HASH_BUF];
        let n = self.save_state(&mut buf);
        debug_assert_eq!(n, Self::SNAPSHOT_SIZE, "save_state wrote unexpected size");
        fnv1a(&buf[..n])
    }

    // -- Snapshot --

    /// Snapshot buffer size: 1 (card state) + GpOpen snapshot size.
    /// Computed via the standalone `snapshot_size` const fn so the
    /// value does not depend on the `E` type parameter.
    pub const SNAPSHOT_SIZE: usize = 1 + snapshot_size(DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS);

    /// Save the entire card state to `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    /// The ATR is a static reference and is not serialized.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut off = 0;

        // Card power state.
        buf[off] = match self.state {
            CardState::Off => 0,
            CardState::Ready => 1,
        };
        off += 1;

        // Delegate to GpOpen.
        let written = self.open.save_state(&mut buf[off..]);
        if written == 0 {
            return 0;
        }
        off + written
    }

    /// Restore state from `buf`.
    ///
    /// Returns `true` on success, `false` if `buf` is too small or invalid.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut off = 0;

        // Card power state.
        self.state = match buf[off] {
            0 => CardState::Off,
            1 => CardState::Ready,
            _ => return false,
        };
        off += 1;

        // Delegate to GpOpen.
        self.open.restore_state(&buf[off..])
    }
}

/// A GP card with the default response buffer capacity and SIM
/// applet support, parameterised by an `EntropySource` `E`.
///
/// This is the most common configuration for a combined GP+USIM card.
#[cfg(feature = "sim")]
pub type GpSimCard<E> = GpCard<E, DEFAULT_RSP_CAP>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_card_api::DeterministicRng;
    use simrs_gp_keys::KeySet;
    use simrs_gp_open::{CardLifecycle, INS_GET_DATA, INS_INITIALIZE_UPDATE};
    use simrs_iso7816::{apdu_header, apdu_with_data};

    /// Fixed seed for the test entropy source. Inlined so tests have a
    /// single, named anchor for reproducibility -- bare hex literals
    /// scattered through the suite would drift.
    pub const TEST_RNG_SEED: u64 = 0xCAFE_BABE_DEAD_BEEF;

    fn test_keys() -> KeySet {
        let k = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        KeySet::des3_2key(k, k, k)
    }

    fn make_card() -> GpCard<DeterministicRng, DEFAULT_RSP_CAP> {
        GpCard::new(
            DEFAULT_ATR,
            &test_keys(),
            DeterministicRng::new(TEST_RNG_SEED),
        )
    }

    // -- Test 1: PowerOn returns ATR --

    #[test]
    fn power_on_returns_atr() {
        let mut card = make_card();
        let rsp = card.process(SimEvent::PowerOn);
        match rsp {
            SimResponse::Atr(atr) => assert_eq!(atr, DEFAULT_ATR),
            _ => panic!("expected Atr response on PowerOn"),
        }
    }

    // -- Test 2: Apdu before PowerOn returns Ignored --

    #[test]
    fn apdu_before_power_on_returns_ignored() {
        let mut card = make_card();
        // Card is Off by default -- APDU should be ignored.
        let rsp = card.process(SimEvent::Apdu(&[0x00, 0xA4, 0x04, 0x00]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    // -- Test 3: PowerOff then Apdu returns Ignored --

    #[test]
    fn power_off_then_apdu_returns_ignored() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);
        let _ = card.process(SimEvent::PowerOff);
        let rsp = card.process(SimEvent::Apdu(&[0x00, 0xA4, 0x04, 0x00]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    // -- Test 4: SELECT ISD by AID returns success --

    #[test]
    fn select_isd_by_aid_returns_success() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);

        let isd_aid: [u8; 8] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
        let apdu = apdu_with_data(0x00, 0xA4, 0x04, 0x00, &isd_aid);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "SELECT ISD should succeed with 9000"
                );
            }
            _ => panic!("expected Apdu response for SELECT"),
        }
    }

    // -- Test 5: INITIALIZE UPDATE + EXTERNAL AUTHENTICATE round-trip --

    #[test]
    fn initialize_update_returns_28_data_bytes() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);

        // INITIALIZE UPDATE with key_version = 0 (any), 8-byte host challenge.
        let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let apdu = apdu_with_data(0x80, INS_INITIALIZE_UPDATE, 0x00, 0x00, &host_challenge);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "INITIALIZE UPDATE should succeed"
                );
                assert_eq!(
                    data.len(),
                    28,
                    "INITIALIZE UPDATE response should be 28 bytes"
                );
            }
            _ => panic!("expected Apdu response for INITIALIZE UPDATE"),
        }

        // Verify SCP state advanced to InitUpdateDone.
        assert!(matches!(
            card.open().scp_state(),
            simrs_gp_open::ScpState::InitUpdateDone { .. }
        ));
    }

    // -- Test 6: GET STATUS returns card lifecycle --

    #[test]
    fn get_status_returns_card_lifecycle() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);

        // GET DATA 0066 does not require auth and returns card lifecycle.
        // GP 2.3.1 § 11.3 (legacy 2.1.1 § 9.6): GET DATA is auth-exempt.
        let apdu = apdu_header(0x80, INS_GET_DATA, 0x00, 0x66);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert_eq!(sw.to_bytes(), [0x90, 0x00], "GET DATA 0066 should succeed");
                // Card recognition data starts with tag 66.
                assert!(data.len() >= 15, "should return card recognition data");
                assert_eq!(data[0], 0x66, "outer tag should be 66");
            }
            _ => panic!("expected Apdu response for GET DATA"),
        }

        // Verify card lifecycle from accessor.
        assert_eq!(card.open().card_lifecycle(), CardLifecycle::OpReady);
    }

    // -- Test 7: Snapshot save/restore round-trip --

    #[test]
    #[allow(clippy::large_stack_arrays)]
    fn snapshot_save_restore_roundtrip() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);

        // Issue INITIALIZE UPDATE to change SCP state.
        let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let apdu = apdu_with_data(0x80, INS_INITIALIZE_UPDATE, 0x00, 0x00, &host_challenge);
        let _ = card.process(SimEvent::Apdu(&apdu));

        // Save state.
        let mut snap_buf = [0u8; GpCard::<DeterministicRng, DEFAULT_RSP_CAP>::SNAPSHOT_SIZE];
        let written = card.save_state(&mut snap_buf);
        assert!(written > 0, "snapshot should write bytes");

        // Restore into a fresh card.
        let mut card2 = make_card();
        assert!(card2.restore_state(&snap_buf[..written]));

        // Verify restored card is Ready.
        assert!(card2.is_ready());

        // Verify restored card can process APDUs. Use GET DATA 0066 which
        // is auth-exempt (GP 2.3.1 § 11.3 / legacy 2.1.1 § 9.6).
        let get_data = apdu_header(0x80, INS_GET_DATA, 0x00, 0x66);
        let rsp = card2.process(SimEvent::Apdu(&get_data));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "restored card should handle GET DATA"
                );
            }
            _ => panic!("restored card should be functional"),
        }
    }

    // -- Test 8: Reset clears SCP state --

    #[test]
    fn reset_clears_scp_state() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);

        // Start SCP session with INITIALIZE UPDATE.
        let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let apdu = apdu_with_data(0x80, INS_INITIALIZE_UPDATE, 0x00, 0x00, &host_challenge);
        let _ = card.process(SimEvent::Apdu(&apdu));

        // Verify SCP state is InitUpdateDone.
        assert!(matches!(
            card.open().scp_state(),
            simrs_gp_open::ScpState::InitUpdateDone { .. }
        ));

        // Reset the card.
        let rsp = card.process(SimEvent::Reset);
        match rsp {
            SimResponse::Atr(atr) => assert_eq!(atr, DEFAULT_ATR),
            _ => panic!("expected Atr response on Reset"),
        }

        // After reset, SCP state should be NoSession.
        assert!(matches!(
            card.open().scp_state(),
            simrs_gp_open::ScpState::NoSession
        ));
    }

    // -- Tick returns Ignored --

    #[test]
    fn tick_returns_ignored() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);
        let rsp = card.process(SimEvent::Tick(100));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    // -- Short APDU returns Ignored --

    #[test]
    fn short_apdu_returns_ignored() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);
        let rsp = card.process(SimEvent::Apdu(&[0x00, 0xA4]));
        assert!(matches!(rsp, SimResponse::Ignored));
    }

    // -- Snapshot with small buffer returns 0 --

    #[test]
    fn snapshot_small_buffer_returns_zero() {
        let card = make_card();
        let mut small = [0u8; 2];
        assert_eq!(card.save_state(&mut small), 0);
    }

    // -- Snapshot restore with invalid data returns false --

    #[test]
    fn snapshot_invalid_data_returns_false() {
        let mut card = make_card();
        assert!(!card.restore_state(&[]));
    }

    // -- Snapshot restore with invalid card state byte returns false --

    #[test]
    fn snapshot_invalid_card_state_returns_false() {
        let mut card = make_card();
        let mut buf = [0u8; GpCard::<DeterministicRng, DEFAULT_RSP_CAP>::SNAPSHOT_SIZE];
        buf[0] = 0xFF; // invalid card state byte
        // Rest is zeros, which will also fail GpOpen restore, but we hit the
        // card state check first.
        assert!(!card.restore_state(&buf));
    }

    // -- PowerOn after PowerOff restores readiness --

    #[test]
    fn power_cycle_restores_readiness() {
        let mut card = make_card();
        let _ = card.process(SimEvent::PowerOn);
        assert!(card.is_ready());
        let _ = card.process(SimEvent::PowerOff);
        assert!(!card.is_ready());
        let _ = card.process(SimEvent::PowerOn);
        assert!(card.is_ready());
    }

    // -- Proptest: process never panics on arbitrary input --

    proptest::proptest! {
        #[test]
        fn process_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let mut card = make_card();
            let _ = card.process(SimEvent::PowerOn);
            let _ = card.process(SimEvent::Apdu(&bytes));
        }
    }
}

// ---------------------------------------------------------------------------
// SIM integration tests (feature = "sim")
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "sim")]
mod sim_tests {
    use super::tests::TEST_RNG_SEED;
    use super::*;
    use simrs_card_api::DeterministicRng;
    use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef};
    use simrs_gp_keys::KeySet;
    use simrs_gp_open::{INS_GET_STATUS, INS_INITIALIZE_UPDATE};
    use simrs_gp_scp::ScpVersion;
    use simrs_iso7816::{apdu_header, apdu_with_data};
    use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
    use simrs_sim::gp_adapter::SimApplet;

    // -- Test filesystem ---------------------------------------------------

    static ICCID_DATA: [u8; 10] = [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];
    static EF_ICCID: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &ICCID_DATA);

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static IMSI_DATA: [u8; 9] = [0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01];
    static EF_IMSI: EfDef = EfDef::transparent(Fid::new(0x6F07), None, &IMSI_DATA);

    static ADF_USIM_DF: DfDef = DfDef {
        fid: Fid::new(0x7FFF),
        children: &[FileRef::Ef(&EF_IMSI)],
    };

    static USIM_AID_BYTES: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];
    static ISD_AID_BYTES: [u8; 8] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &USIM_AID_BYTES,
        root: &ADF_USIM_DF,
    }];

    fn test_keys() -> KeySet {
        let k = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        KeySet::des3_2key(k, k, k)
    }

    fn make_sim_applet() -> SimApplet<MilenageParams> {
        let mil = MilenageParams::with_defaults(
            SubscriberKey::classify([0u8; 16]),
            OperatorVariant::operator_cipher([0u8; 16]),
        );
        SimApplet::new(&MF, &ADF_TABLE, mil)
    }

    fn make_gp_sim_card() -> GpCard<DeterministicRng, DEFAULT_RSP_CAP> {
        GpCard::with_sim(
            DEFAULT_ATR,
            &test_keys(),
            make_sim_applet(),
            DeterministicRng::new(TEST_RNG_SEED),
        )
    }

    /// Perform full SCP02 mutual authentication on a powered-on card.
    ///
    /// Sends SELECT ISD, INITIALIZE UPDATE, derives session keys,
    /// computes host cryptogram + C-MAC, and sends EXTERNAL AUTHENTICATE.
    fn scp02_authenticate(card: &mut GpCard<DeterministicRng, DEFAULT_RSP_CAP>) {
        let keys = test_keys();

        // 1. SELECT ISD.
        let select = select_aid_apdu(&ISD_AID_BYTES);
        let rsp = card.process(SimEvent::Apdu(&select));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(sw.to_bytes(), [0x90, 0x00], "SELECT ISD should succeed");
            }
            _ => panic!("expected Apdu response for SELECT ISD"),
        }

        // 2. INITIALIZE UPDATE with key_version = 0 (any), 8-byte host
        //    challenge.
        let hc: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let iu_apdu = apdu_with_data(0x80, INS_INITIALIZE_UPDATE, 0x00, 0x00, &hc);
        let rsp = card.process(SimEvent::Apdu(&iu_apdu));
        let iu_data = match rsp {
            SimResponse::Apdu { data, sw } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "INITIALIZE UPDATE should succeed"
                );
                assert!(data.len() >= 28, "INIT UPDATE response must be >= 28 bytes");
                let mut buf = [0u8; 28];
                buf.copy_from_slice(&data[..28]);
                buf
            }
            _ => panic!("expected Apdu response for INITIALIZE UPDATE"),
        };

        // 3. Parse response: [0..10] key_div, [10] key_ver, [11] scp_id,
        //    [12..14] sequence_counter, [14..20] card_challenge, [20..28] card_cryptogram.
        let seq = u16::from_be_bytes([iu_data[12], iu_data[13]]);
        let mut cc6 = [0u8; 6];
        cc6.copy_from_slice(&iu_data[14..20]);

        // 4. Derive SCP02 session keys.
        let (enc, mac, _rmac, _dek) = simrs_gp_scp::derive_scp02_session_keys(&keys, seq);

        // 5. Compute host cryptogram.
        let host_crypto = simrs_gp_scp::compute_scp02_host_cryptogram(&enc, &hc, seq, &cc6);

        // 6. Compute C-MAC for EXTERNAL AUTHENTICATE.
        let security_level: u8 = 0x00; // no secure messaging required
        let (cmac, _) = simrs_gp_scp::generate_cmac(
            &mac,
            &[0x84, 0x82, security_level, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp02,
        );

        // 7. EXTERNAL AUTHENTICATE with `host_cryptogram[8] || C-MAC[8]`.
        let mut body = [0u8; 16];
        body[..8].copy_from_slice(&host_crypto);
        body[8..].copy_from_slice(&cmac);
        let ea_apdu = apdu_with_data(0x84, 0x82, security_level, 0x00, &body);
        let rsp = card.process(SimEvent::Apdu(&ea_apdu));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "EXTERNAL AUTHENTICATE should succeed"
                );
            }
            _ => panic!("expected Apdu response for EXTERNAL AUTHENTICATE"),
        }
    }

    /// Build a SELECT-by-AID APDU for the given AID.
    fn select_aid_apdu(aid: &[u8]) -> alloc::vec::Vec<u8> {
        apdu_with_data(0x00, 0xA4, 0x04, 0x00, aid)
    }

    // -- Test 1: SELECT USIM AID routes to SIM applet ----------------------

    #[test]
    fn select_usim_aid_succeeds() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        let apdu = select_aid_apdu(&USIM_AID_BYTES);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "SELECT USIM AID should succeed with 9000"
                );
            }
            _ => panic!("expected Apdu response for SELECT USIM"),
        }
    }

    // -- Test 2: SELECT ISD AID routes to GP card manager ------------------

    #[test]
    fn select_isd_aid_succeeds() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        let apdu = select_aid_apdu(&ISD_AID_BYTES);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "SELECT ISD AID should succeed with 9000"
                );
            }
            _ => panic!("expected Apdu response for SELECT ISD"),
        }
    }

    // -- Test 3: SIM APDU (STATUS) after selecting USIM works ---------------

    #[test]
    fn sim_status_after_usim_select() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        // SELECT USIM AID.
        let select = select_aid_apdu(&USIM_AID_BYTES);
        let _ = card.process(SimEvent::Apdu(&select));

        // STATUS command (INS=0xF2, P1=0x00, P2=0x0C = no FCI).
        let status_cmd = [0x00, 0xF2, 0x00, 0x0C];
        let rsp = card.process(SimEvent::Apdu(&status_cmd));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, _sw2] = sw.to_bytes();
                // STATUS should return a success-family SW (90 XX or 61 XX).
                assert!(
                    sw1 == 0x90 || sw1 == 0x61,
                    "STATUS should succeed after USIM select, got SW {sw1:02X}"
                );
            }
            _ => panic!("expected Apdu response for STATUS"),
        }
    }

    // -- Test 4: GP APDU (GET STATUS) after selecting ISD works ------------

    #[test]
    fn gp_get_status_after_isd_select() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        // Authenticate via SCP02 (GET STATUS requires an authenticated session).
        scp02_authenticate(&mut card);

        let apdu = apdu_header(0x80, INS_GET_STATUS, 0x80, 0x00);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert_eq!(sw.to_bytes(), [0x90, 0x00], "GET STATUS should succeed");
                // Response is E3 TLV per GP 2.3.1 § 11.4.3:
                // E3 <len> { 4F <aid_len> <aid> 9F70 01 <lifecycle> C5 01 <privileges> }
                assert!(data.len() >= 18, "GET STATUS should return ISD TLV data");
                assert_eq!(data[0], 0xE3, "response should start with E3 tag");
                assert_eq!(data[2], 0x4F, "AID tag should be 4F");
                assert_eq!(data[3], 8, "ISD AID length should be 8 (GP 2.3.1)");
                assert_eq!(&data[4..12], &ISD_AID_BYTES, "ISD AID should match");
            }
            _ => panic!("expected Apdu response for GET STATUS"),
        }
    }

    // -- Test 5: Both on same card without interference --------------------

    #[test]
    fn switch_between_usim_and_isd() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        // Authenticate via SCP02 (GET STATUS requires an authenticated session).
        scp02_authenticate(&mut card);

        // 1. SELECT USIM and issue a SIM STATUS.
        let select_usim = select_aid_apdu(&USIM_AID_BYTES);
        let _ = card.process(SimEvent::Apdu(&select_usim));
        let status_cmd = apdu_header(0x00, 0xF2, 0x00, 0x0C);
        let rsp = card.process(SimEvent::Apdu(&status_cmd));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, _] = sw.to_bytes();
                assert!(sw1 == 0x90 || sw1 == 0x61, "SIM STATUS should succeed");
            }
            _ => panic!("expected Apdu response for SIM STATUS"),
        }

        // 2. SELECT ISD and issue a GP command.
        let select_isd = select_aid_apdu(&ISD_AID_BYTES);
        let _ = card.process(SimEvent::Apdu(&select_isd));
        let get_status = apdu_header(0x80, INS_GET_STATUS, 0x80, 0x00);
        let rsp = card.process(SimEvent::Apdu(&get_status));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(sw.to_bytes(), [0x90, 0x00], "GP GET STATUS should succeed");
            }
            _ => panic!("expected Apdu response for GP GET STATUS"),
        }

        // 3. Switch back to USIM -- should still work.
        let _ = card.process(SimEvent::Apdu(&select_usim));
        let rsp = card.process(SimEvent::Apdu(&status_cmd));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, _] = sw.to_bytes();
                assert!(
                    sw1 == 0x90 || sw1 == 0x61,
                    "SIM STATUS should still succeed after switching back"
                );
            }
            _ => panic!("expected Apdu response for SIM STATUS after switch"),
        }
    }

    // -- Test 6: USIM applet visible in GET STATUS apps listing -------------

    #[test]
    fn usim_applet_in_get_status_apps() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        // Authenticate via SCP02 (GET STATUS requires an authenticated session).
        scp02_authenticate(&mut card);

        let apdu = apdu_header(0x80, INS_GET_STATUS, 0x40, 0x00);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "GET STATUS apps should succeed"
                );
                // Data should contain the USIM AID entry in E3 TLV format
                // per GP 2.1.1 Table 9-7:
                // E3 <len> { 4F <aid_len> <aid> 9F70 01 <lifecycle> C5 01 <privileges> }
                assert!(data.len() >= 18, "should have at least one applet entry");
                assert_eq!(data[0], 0xE3, "response should start with E3 tag");
                assert_eq!(data[2], 0x4F, "AID tag should be 4F");
                assert_eq!(data[3], 7, "USIM AID length should be 7");
                assert_eq!(
                    &data[4..11],
                    &USIM_AID_BYTES,
                    "USIM AID should be in the registry"
                );
            }
            _ => panic!("expected Apdu response for GET STATUS apps"),
        }
    }

    // -- Test 7: SIM SELECT MF works through dispatch ----------------------

    #[test]
    fn sim_select_mf_via_dispatch() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        // SELECT USIM AID first.
        let select_usim = select_aid_apdu(&USIM_AID_BYTES);
        let _ = card.process(SimEvent::Apdu(&select_usim));

        // SELECT MF by FID 3F00 (case 3, 2-byte body).
        let select_mf = apdu_with_data(0x00, 0xA4, 0x00, 0x04, &[0x3F, 0x00]);
        let rsp = card.process(SimEvent::Apdu(&select_mf));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                let [sw1, _] = sw.to_bytes();
                // SELECT MF returns either 90 00 or 61 XX (more data available).
                assert!(
                    sw1 == 0x90 || sw1 == 0x61,
                    "SELECT MF through SIM dispatch should succeed, got SW1={sw1:02X}"
                );
            }
            _ => panic!("expected Apdu response for SELECT MF"),
        }
    }

    // -- Test 8: INITIALIZE UPDATE still works on combined card ------------

    #[test]
    fn scp_initialize_update_on_combined_card() {
        let mut card = make_gp_sim_card();
        let _ = card.process(SimEvent::PowerOn);

        // INITIALIZE UPDATE with key_version = 0 (any), 8-byte host
        // challenge.
        let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let apdu = apdu_with_data(0x80, INS_INITIALIZE_UPDATE, 0x00, 0x00, &host_challenge);
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "INITIALIZE UPDATE should succeed on combined card"
                );
                assert_eq!(
                    data.len(),
                    28,
                    "INITIALIZE UPDATE response should be 28 bytes"
                );
            }
            _ => panic!("expected Apdu response for INITIALIZE UPDATE"),
        }
    }

    // -- Test 9: GpSimCard alias works -------------------------------------

    #[test]
    fn gp_sim_card_alias_compiles() {
        let _card: GpSimCard<DeterministicRng> = GpCard::with_sim(
            DEFAULT_ATR,
            &test_keys(),
            make_sim_applet(),
            DeterministicRng::new(TEST_RNG_SEED),
        );
    }

    // -- Test 10: sim_applet accessor works ---------------------------------

    #[test]
    fn sim_applet_accessor() {
        let card = make_gp_sim_card();
        assert!(
            card.sim_applet().is_some(),
            "with_sim card should have SIM applet"
        );

        let card_no_sim: GpCard<DeterministicRng, DEFAULT_RSP_CAP> = GpCard::new(
            DEFAULT_ATR,
            &test_keys(),
            DeterministicRng::new(TEST_RNG_SEED),
        );
        assert!(
            card_no_sim.sim_applet().is_none(),
            "regular card should not have SIM applet"
        );
    }
}
