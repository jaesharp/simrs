//! Controlplane differential tests.
//!
//! Wraps the simrs side with [`ControlplaneCard`] so control-plane
//! private APDUs land in the applet; the reference side has no
//! controlplane installed, so the same APDUs are rejected by the
//! reference's natural GP surface. Used to (a) prove the controlplane
//! reaches simrs correctly under the differential harness and (b)
//! document that reference backends reject the controlplane AID as
//! expected (cataloged divergence).
//!
//! This is the "as is" wiring — the simrs-side is a
//! `ControlplaneCard<GpCardTerminal>` constructed inline per test,
//! and the reference backend uses the same matrix-selector pattern
//! as [`apdu_test!`]. Tests run under both jcsl and jcardengine
//! matrix cells.
//!
//! Later phases (conformance engine) will replace this with a
//! scenario-bound formulation; until then this file demonstrates
//! the controlplane is differential-reachable on simrs.
//!
//! # Running
//!
//! ```bash
//! cargo test -p simrs-differential-crossvalidation --test controlplane_differential
//! SIMRS_DIFF_BACKEND=jcardengine \
//!   cargo test -p simrs-differential-crossvalidation --test controlplane_differential
//! ```

use simrs_card_api::SimEvent;
use simrs_controlplane::{
    CONTROLPLANE_AID, ControlplaneCard,
    probes::ping::{P2_PING, P2_VERSION, VERSION_STRING},
    protocol::{CLA as CP_CLA, Category, INS as CP_INS},
};
use simrs_differential_crossvalidation::{
    GpCardTerminal, KEY_BYTES, ReferenceBackend, panic_or_skip_on_missing_backend, select_aid,
    select_backend, try_start_and_power_on,
};
use simrs_gp_card::GpCard;
use simrs_gp_keys::KeySet;
use simrs_transport::Transport;

/// Build a simrs card wrapped by the controlplane interposer.
///
/// Shape: `GpCard → GpCardTerminal (Transport) → ControlplaneCard
/// <GpCardTerminal> (Transport + controlplane dispatch)`. Powers on
/// the inner `GpCard` so subsequent APDUs are immediately valid.
fn make_simrs_with_controlplane() -> ControlplaneCard<GpCardTerminal> {
    let keyset = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
    let mut card = GpCard::with_default_atr(&keyset);
    // Power on the raw card so the first ATR is available before the
    // controlplane wrapper sees APDUs.
    let _atr = card.process(SimEvent::PowerOn);
    let terminal = GpCardTerminal::new(card);
    ControlplaneCard::new(terminal)
}

/// Start + power-on the configured reference backend under the
/// shared panic-or-skip policy.
///
/// Policy (via [`panic_or_skip_on_missing_backend`] in the lib):
/// - `SIMRS_DIFF_BACKEND` explicitly set → the matrix cell requires
///   this backend; missing runtime panics.
/// - Unset → workspace-test cell without a backend installed; log
///   and skip by returning `None` to the macro.
fn try_reference_under_policy() -> Option<Box<dyn ReferenceBackend>> {
    let backend = select_backend();
    let r = try_start_and_power_on(backend);
    if r.is_none() {
        panic_or_skip_on_missing_backend("controlplane_differential", backend);
    }
    r
}

/// Short-circuit macro: invokes the shared policy and returns from
/// the calling `#[test]` when skipping.
macro_rules! reference_or_skip {
    () => {
        match try_reference_under_policy() {
            Some(r) => r,
            None => return,
        }
    };
}

/// Exchange a full APDU against the controlplane-wrapped simrs card.
/// Returns `(data_without_sw, sw)`.
fn simrs_exchange(card: &mut ControlplaneCard<GpCardTerminal>, apdu: &[u8]) -> (Vec<u8>, [u8; 2]) {
    let mut buf = vec![0u8; 512];
    let n = card
        .exchange(apdu, &mut buf)
        .expect("controlplane exchange");
    buf.truncate(n);
    let sw = [buf[n - 2], buf[n - 1]];
    let data = buf[..n - 2].to_vec();
    (data, sw)
}

fn reference_exchange(r: &mut dyn ReferenceBackend, apdu: &[u8]) -> (Vec<u8>, [u8; 2]) {
    let resp = r.transmit_apdu(apdu).expect("reference transmit");
    let n = resp.len();
    assert!(n >= 2, "reference response too short");
    let sw = [resp[n - 2], resp[n - 1]];
    let data = resp[..n - 2].to_vec();
    (data, sw)
}

// -----------------------------------------------------------------------
// SELECT controlplane AID — simrs accepts; reference rejects
// -----------------------------------------------------------------------

#[test]
fn select_controlplane_aid_simrs_accepts_reference_rejects() {
    let mut simrs = make_simrs_with_controlplane();
    let mut reference = reference_or_skip!();

    let apdu = select_aid(&CONTROLPLANE_AID);

    let (_simrs_data, simrs_sw) = simrs_exchange(&mut simrs, &apdu);
    let (_ref_data, ref_sw) = reference_exchange(reference.as_mut(), &apdu);

    eprintln!(
        "SELECT controlplane AID: simrs={:02X}{:02X}, reference={:02X}{:02X}",
        simrs_sw[0], simrs_sw[1], ref_sw[0], ref_sw[1]
    );

    // simrs must succeed — ControlplaneCard intercepts SELECT of its AID.
    assert_eq!(
        simrs_sw,
        [0x90, 0x00],
        "simrs SELECT controlplane AID failed: {simrs_sw:02X?}"
    );

    // reference does not know the controlplane AID; must reject with 6xxx.
    assert_eq!(
        ref_sw[0] & 0xF0,
        0x60,
        "reference should reject unknown controlplane AID, got {ref_sw:02X?}"
    );
}

// -----------------------------------------------------------------------
// Misc ping — simrs echoes, reference rejects
// -----------------------------------------------------------------------

#[test]
fn misc_ping_simrs_echoes_reference_rejects() {
    let mut simrs = make_simrs_with_controlplane();
    let mut reference = reference_or_skip!();

    // Select the controlplane on simrs (required for subsequent
    // controlplane APDUs to reach the applet).
    let sel = select_aid(&CONTROLPLANE_AID);
    let (_s, ssw) = simrs_exchange(&mut simrs, &sel);
    assert_eq!(ssw, [0x90, 0x00]);
    // reference: attempt SELECT too (will fail); proves no controlplane
    // state is accidentally carried over.
    let _ = reference_exchange(reference.as_mut(), &sel);

    // Build a ping APDU with a 4-byte payload.
    let payload = [0xDE, 0xAD, 0xBE, 0xEF];
    let lc = u8::try_from(payload.len()).expect("payload fits in one byte");
    let mut ping = vec![CP_CLA, CP_INS, Category::Misc as u8, P2_PING, lc];
    ping.extend_from_slice(&payload);

    let (simrs_data, simrs_sw) = simrs_exchange(&mut simrs, &ping);
    let (_r_data, r_sw) = reference_exchange(reference.as_mut(), &ping);

    eprintln!(
        "ping: simrs={:02X}{:02X} data={:02X?}, reference={:02X}{:02X}",
        simrs_sw[0], simrs_sw[1], simrs_data, r_sw[0], r_sw[1]
    );

    assert_eq!(simrs_sw, [0x90, 0x00], "simrs ping should succeed");
    assert_eq!(
        simrs_data, payload,
        "simrs ping should echo the request data field"
    );

    // reference rejects the proprietary CLA/INS combination. Any 6xxx
    // response is acceptable; jcsl and jcardengine may differ in
    // exact SW.
    assert_eq!(
        r_sw[0] & 0xF0,
        0x60,
        "reference should reject controlplane ping, got {r_sw:02X?}"
    );
}

// -----------------------------------------------------------------------
// Misc version — byte-stable version string on simrs
// -----------------------------------------------------------------------

#[test]
fn misc_version_simrs_returns_version_tag() {
    let mut simrs = make_simrs_with_controlplane();
    let mut reference = reference_or_skip!();

    let sel = select_aid(&CONTROLPLANE_AID);
    let (_s, ssw) = simrs_exchange(&mut simrs, &sel);
    assert_eq!(ssw, [0x90, 0x00]);
    let _ = reference_exchange(reference.as_mut(), &sel);

    let version = [CP_CLA, CP_INS, Category::Misc as u8, P2_VERSION];

    let (simrs_data, simrs_sw) = simrs_exchange(&mut simrs, &version);
    let (_r_data, r_sw) = reference_exchange(reference.as_mut(), &version);

    eprintln!(
        "version: simrs={:02X}{:02X} string={:?}, reference={:02X}{:02X}",
        simrs_sw[0],
        simrs_sw[1],
        std::str::from_utf8(&simrs_data).ok(),
        r_sw[0],
        r_sw[1]
    );

    assert_eq!(simrs_sw, [0x90, 0x00], "simrs version should succeed");
    assert_eq!(
        simrs_data, VERSION_STRING,
        "simrs version string drifted from VERSION_STRING constant"
    );
    assert_eq!(
        r_sw[0] & 0xF0,
        0x60,
        "reference should reject controlplane version, got {r_sw:02X?}"
    );
}
