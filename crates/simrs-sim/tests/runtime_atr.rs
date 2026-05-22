//! Regression test for WS-7: runtime-owned ATRs.
//!
//! Constructs two `Sim` instances with different ATRs in the same process
//! and verifies each returns its own ATR on `PowerOn`. Prior to WS-7,
//! `Sim::new` required `atr: &'static [u8]`, which forced callers to use
//! a single module-level static and made per-instance ATRs impossible
//! without leaking heap allocations.

#![cfg(all(feature = "gsm", feature = "usim"))]

use simrs_card_api::DEFAULT_ATR;
use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef};
use simrs_gsm::{GsmApp, SubscriberKey as GsmSubscriberKey};
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_sim::{AtrBytes, Sim, SimEvent, SimResponse};
use simrs_usim::UsimApp;

static ICCID_DATA: [u8; 10] = [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];
static EF_ICCID: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &ICCID_DATA);
static MF: DfDef = DfDef {
    fid: Fid::new(0x3F00),
    children: &[FileRef::Ef(&EF_ICCID)],
};
static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];
static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
    aid: &USIM_AID,
    root: &MF,
}];

/// Build a configured Sim with the given ATR. The ATR is whatever the
/// caller supplies -- no `'static` lifetime requirement.
fn build_sim(atr: impl Into<AtrBytes>) -> Sim<MilenageParams, 256> {
    let gsm = GsmApp::new(&MF, GsmSubscriberKey::classify([0u8; 16]));
    let mil = MilenageParams::with_defaults(
        SubscriberKey::classify([0u8; 16]),
        OperatorVariant::operator_cipher([0u8; 16]),
    );
    let usim = UsimApp::new(&MF, &ADF_TABLE, mil);
    Sim::<MilenageParams, 256>::new(atr, gsm, usim)
}

#[test]
fn distinct_atrs_in_same_process_return_their_own_bytes() {
    // First Sim: USIM-realistic 22-byte ATR.
    let mut sim_a = build_sim(&DEFAULT_ATR);
    // Second Sim: minimal T=0-only ATR. Constructed from a stack-local
    // array -- no `'static` lifetime, which the old API required.
    let local_atr: [u8; 2] = [0x3B, 0x00];
    let mut sim_b = build_sim(&local_atr);

    let atr_a = match sim_a.process(SimEvent::PowerOn) {
        SimResponse::Atr(atr) => atr.to_vec(),
        other => panic!("sim_a PowerOn returned {other:?}"),
    };
    let atr_b = match sim_b.process(SimEvent::PowerOn) {
        SimResponse::Atr(atr) => atr.to_vec(),
        other => panic!("sim_b PowerOn returned {other:?}"),
    };

    assert_eq!(atr_a, DEFAULT_ATR.to_vec(), "sim_a must return DEFAULT_ATR");
    assert_eq!(atr_b, local_atr.to_vec(), "sim_b must return its own ATR");
    assert_ne!(atr_a, atr_b, "the two ATRs must differ");
}

#[test]
fn warm_reset_returns_instance_specific_atr() {
    // Verify the ATR survives a warm reset (Sim::process(SimEvent::Reset)).
    let local_atr: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];
    let mut sim = build_sim(&local_atr);

    // PowerOn first.
    match sim.process(SimEvent::PowerOn) {
        SimResponse::Atr(atr) => assert_eq!(atr, &local_atr),
        other => panic!("PowerOn returned {other:?}"),
    }

    // Warm reset: same ATR comes back.
    match sim.process(SimEvent::Reset) {
        SimResponse::Atr(atr) => assert_eq!(atr, &local_atr),
        other => panic!("Reset returned {other:?}"),
    }
}

#[test]
fn atr_bytes_explicit_construction_works_via_from_slice() {
    // Caller already has the bytes as a `&[u8]` slice (the typical shape
    // when the ATR comes from a parsed profile, a CLI flag, or another
    // runtime source). `AtrBytes::from_slice` is the canonical path.
    let runtime_bytes: Vec<u8> = vec![0x3B, 0x00];
    let atr = AtrBytes::from_slice(&runtime_bytes).expect("ATR fits");
    let mut sim = build_sim(atr);

    match sim.process(SimEvent::PowerOn) {
        SimResponse::Atr(atr) => assert_eq!(atr, runtime_bytes.as_slice()),
        other => panic!("PowerOn returned {other:?}"),
    }
}
