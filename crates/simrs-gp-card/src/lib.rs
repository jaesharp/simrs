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
//! This crate defines [`SimEvent`] and [`SimResponse`] locally with the same
//! layout as `simrs_sim::SimEvent` / `simrs_sim::SimResponse`. This avoids
//! pulling in the heavy SIM/USIM dependency chain (simrs-fs, simrs-pin,
//! simrs-milenage) that simrs-sim requires. A future unification pass can
//! extract these types into a shared `simrs-card-api` crate.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

use simrs_gp_keys::KeySet;
use simrs_gp_open::GpOpen;
use simrs_iso7816::StatusWord;

// ---------------------------------------------------------------------------
// SimEvent / SimResponse (compatible with simrs-sim)
// ---------------------------------------------------------------------------

/// An event delivered to the card.
///
/// This is layout-compatible with `simrs_sim::SimEvent`. Defined locally to
/// avoid a dependency on simrs-sim's SIM/USIM dependency chain.
#[derive(Debug, Clone, Copy)]
pub enum SimEvent<'a> {
    /// Card power-on (cold reset). Returns ATR.
    PowerOn,
    /// Warm reset. Returns ATR.
    Reset,
    /// Card deactivation. Returns `Ignored`.
    PowerOff,
    /// APDU command (raw bytes, at least 4 for CLA INS P1 P2).
    Apdu(&'a [u8]),
    /// Advance timers by `elapsed_secs`. Returns `Ignored`.
    Tick(u32),
}

/// A response produced by the card.
///
/// This is layout-compatible with `simrs_sim::SimResponse`. Defined locally to
/// avoid a dependency on simrs-sim's SIM/USIM dependency chain.
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
    /// Event was ignored (card not powered on, malformed APDU, etc.).
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
// Default ATR
// ---------------------------------------------------------------------------

/// Default ATR for a GlobalPlatform card.
///
/// Encodes: TS=3B (direct convention), T0=90 (TD1 present, 0 historical),
/// TD1=95 (T=1, TD2 present), TD2=80 (no further interface bytes, T=0),
/// T1=1F, historical bytes C3 83 80, TCK=73 21.
/// This is representative of a typical Java Card with GP 2.1.1 support.
const DEFAULT_ATR: &[u8] = &[0x3B, 0x90, 0x95, 0x80, 0x1F, 0xC3, 0x83, 0x80, 0x73, 0x21];

// ---------------------------------------------------------------------------
// GpCard
// ---------------------------------------------------------------------------

/// Top-level `GlobalPlatform` card simulator.
///
/// `RSP_CAP` is the internal response buffer size (default 261 bytes,
/// sufficient for a 256-byte response + 2-byte SW + 3-byte overhead).
///
/// # Usage
///
/// ```ignore
/// use simrs_gp_card::{GpCard, SimEvent, SimResponse};
/// use simrs_gp_keys::KeySet;
///
/// let keys = KeySet::des3_2key([0x40; 16], [0x40; 16], [0x40; 16]);
/// let mut card = GpCard::new(DEFAULT_ATR, keys);
/// let rsp = card.process(SimEvent::PowerOn);
/// // rsp is SimResponse::Atr(...)
/// ```
pub struct GpCard<const RSP_CAP: usize = 261> {
    atr: &'static [u8],
    state: CardState,
    open: GpOpen<16, 4>,
    rsp_buf: [u8; RSP_CAP],
}

impl<const RSP_CAP: usize> GpCard<RSP_CAP> {
    /// Create a new GP card with the given ATR and ISD key set.
    ///
    /// The card starts powered off. The ISD is initialized with the
    /// provided keys and the card lifecycle is set to `OpReady`.
    pub fn new(atr: &'static [u8], isd_keys: &KeySet) -> Self {
        Self {
            atr,
            state: CardState::Off,
            open: GpOpen::new(isd_keys),
            rsp_buf: [0u8; RSP_CAP],
        }
    }

    /// Create a new GP card with the default ATR and the given ISD key set.
    pub fn with_default_atr(isd_keys: &KeySet) -> Self {
        Self::new(DEFAULT_ATR, isd_keys)
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

        let rsp_slice = self.open.handle(bytes, &mut self.rsp_buf);

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
    pub const fn open(&self) -> &GpOpen<16, 4> {
        &self.open
    }

    /// Mutable reference to the underlying GP OPEN runtime.
    pub const fn open_mut(&mut self) -> &mut GpOpen<16, 4> {
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

    // -- Snapshot --

    /// Snapshot buffer size: 1 (card state) + GpOpen snapshot size.
    pub const SNAPSHOT_SIZE: usize = 1 + GpOpen::<16, 4>::SNAPSHOT_SIZE;

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_gp_keys::KeySet;
    use simrs_gp_open::{CardLifecycle, INS_GET_STATUS, INS_INITIALIZE_UPDATE};

    fn test_keys() -> KeySet {
        let k = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        KeySet::des3_2key(k, k, k)
    }

    fn make_card() -> GpCard<261> {
        GpCard::new(DEFAULT_ATR, &test_keys())
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

        // SELECT by AID: 00 A4 04 00 07 <ISD AID>
        let isd_aid: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];
        let mut apdu = [0u8; 12];
        apdu[0] = 0x00; // CLA interindustry
        apdu[1] = 0xA4; // INS SELECT
        apdu[2] = 0x04; // P1 = select by name
        apdu[3] = 0x00; // P2
        apdu[4] = 0x07; // Lc = 7
        apdu[5..12].copy_from_slice(&isd_aid);

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

        // INITIALIZE UPDATE: 80 50 00 00 08 <host_challenge[8]>
        let mut apdu = [0u8; 13];
        apdu[0] = 0x80;
        apdu[1] = INS_INITIALIZE_UPDATE;
        apdu[2] = 0x00; // P1 = key version 0 (any)
        apdu[3] = 0x00;
        apdu[4] = 0x08; // Lc
        apdu[5..13].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

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

        // GET STATUS P1=0x80 (ISD): 80 F2 80 00
        let apdu = [0x80, INS_GET_STATUS, 0x80, 0x00];
        let rsp = card.process(SimEvent::Apdu(&apdu));
        match rsp {
            SimResponse::Apdu { data, sw } => {
                assert_eq!(sw.to_bytes(), [0x90, 0x00], "GET STATUS should succeed");
                // Response: AID_len(1) + AID(7) + lifecycle(1) + privileges(1) = 10 bytes
                assert!(data.len() >= 10, "GET STATUS should return ISD data");
                assert_eq!(data[0], 7, "ISD AID length should be 7");
                assert_eq!(
                    &data[1..8],
                    &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00],
                    "ISD AID should be default GP AID"
                );
            }
            _ => panic!("expected Apdu response for GET STATUS"),
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
        let mut apdu = [0u8; 13];
        apdu[0] = 0x80;
        apdu[1] = INS_INITIALIZE_UPDATE;
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = 0x08;
        apdu[5..13].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let _ = card.process(SimEvent::Apdu(&apdu));

        // Save state.
        let mut snap_buf = [0u8; GpCard::<261>::SNAPSHOT_SIZE];
        let written = card.save_state(&mut snap_buf);
        assert!(written > 0, "snapshot should write bytes");

        // Restore into a fresh card.
        let mut card2 = make_card();
        assert!(card2.restore_state(&snap_buf[..written]));

        // Verify restored card is Ready.
        assert!(card2.is_ready());

        // Verify restored card can process APDUs (GET STATUS should work).
        let get_status = [0x80, INS_GET_STATUS, 0x80, 0x00];
        let rsp = card2.process(SimEvent::Apdu(&get_status));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(
                    sw.to_bytes(),
                    [0x90, 0x00],
                    "restored card should handle GET STATUS"
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
        let mut apdu = [0u8; 13];
        apdu[0] = 0x80;
        apdu[1] = INS_INITIALIZE_UPDATE;
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = 0x08;
        apdu[5..13].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
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
        let mut buf = [0u8; GpCard::<261>::SNAPSHOT_SIZE];
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
