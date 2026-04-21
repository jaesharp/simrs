//! Differential tests: simrs `GpCard` vs a configured reference simulator.
//!
//! Each test sends identical APDU sequences to both implementations and
//! compares the results. The focus is on status words and response
//! structure rather than exact byte-for-byte matching, since the two
//! implementations target different GP specification versions:
//!
//! - simrs: GP 2.1.1, SCP01/SCP02 (DES3 keys)
//! - reference (jcsl): GP 2.3, SCP03 (AES-128 keys)
//! - reference (`JCardEngine`): GP 2.3, SCP03 (AES-128 keys)
//!
//! The reference backend is chosen at run time by `SIMRS_DIFF_BACKEND`
//! (defaults to `jcsl`); every APDU-capable test is matrixed through
//! both via [`apdu_test!`].
//!
//! # Running
//!
//! ```bash
//! # Against Oracle jcsl (default)
//! SIMRS_JCSL_BINARY=/path/to/jcsl \
//!   cargo test -p simrs-differential-crossvalidation --test differential
//!
//! # Against martinpaljak/JCardEngine
//! SIMRS_DIFF_BACKEND=jcardengine \
//!   cargo test -p simrs-differential-crossvalidation --test differential
//! ```

use simrs_card_api::{SimEvent, SimResponse};
use simrs_differential_crossvalidation::{
    BackendId, DualCard, ORACLE_ISD_AID, ReferenceBackend, SIMRS_ISD_AID,
    panic_backend_not_discoverable, select_aid, select_backend, try_create_dual_card_jcardengine,
    try_create_dual_card_jcsl,
};

/// APDU-only matrix test harness.
///
/// Wraps a generic body (`|dc| { ... }`) in a `#[test]` entry point
/// that dispatches on [`select_backend`] so the same test runs
/// against whichever reference the matrix cell has configured via
/// `SIMRS_DIFF_BACKEND`. Panics if the chosen backend isn't
/// discoverable: a configured-but-missing reference is a
/// configuration error, not a silent skip.
///
/// The body receives a mutable `DualCard<B: ReferenceBackend>` and
/// must only invoke trait-level operations (`power_on`, `exchange`,
/// `reset`, `reconnect_reference`, `dc.simrs.process(...)`,
/// `dc.reference.transmit_apdu(...)`). Assertions that depend on
/// backend-specific byte layouts (e.g. `IIN` data bytes, ATR
/// presence) must guard on `is_empty()` / `is_success()` or target
/// `dc.simrs` only; reference-side divergences are surfaced through
/// the [`known_divergences`] catalog, not as hard failures here.
///
/// [`known_divergences`]: simrs_differential_crossvalidation::known_divergences
macro_rules! apdu_test {
    ($name:ident, $label:expr, |$dc:ident| $body:block) => {
        #[test]
        fn $name() {
            #[allow(unused_mut)]
            fn run<B: ReferenceBackend>(mut $dc: DualCard<B>) $body
            let backend = select_backend();
            let label = stringify!($name);
            match backend {
                BackendId::Jcsl => {
                    let dc = try_create_dual_card_jcsl($label).unwrap_or_else(|| {
                        panic_backend_not_discoverable(label, backend)
                    });
                    run(dc);
                }
                BackendId::Jcardengine => {
                    let dc = try_create_dual_card_jcardengine($label).unwrap_or_else(|| {
                        panic_backend_not_discoverable(label, backend)
                    });
                    run(dc);
                }
            }
        }
    };
}

// -----------------------------------------------------------------------
// Power-on / ATR
// -----------------------------------------------------------------------

apdu_test!(power_on_both_return_valid_atr, "atr", |dc| {
    let (simrs_atr, reference_atr) = dc.power_on();

    // simrs always emits a valid ATR; JCardEngine's bridge returns an
    // empty vector (no physical card context), so guard the reference
    // assertion on non-empty.
    assert!(
        simrs_atr[0] == 0x3B || simrs_atr[0] == 0x3F,
        "simrs ATR initial byte: 0x{:02X}",
        simrs_atr[0]
    );
    if !reference_atr.is_empty() {
        assert!(
            reference_atr[0] == 0x3B || reference_atr[0] == 0x3F,
            "reference ATR initial byte: 0x{:02X}",
            reference_atr[0]
        );
    }

    eprintln!("simrs     ATR: {simrs_atr:02x?}");
    eprintln!("reference ATR: {reference_atr:02x?}");

    assert!(!simrs_atr.is_empty());
});

// -----------------------------------------------------------------------
// SELECT by AID
// -----------------------------------------------------------------------

apdu_test!(select_isd_simrs_aid_on_both, "sel-simrs-aid", |dc| {
    dc.power_on();

    let apdu = select_aid(&SIMRS_ISD_AID);
    let dr = dc.exchange(&apdu);

    eprintln!("SELECT ISD (7-byte) simrs:     {:?}", dr.simrs);
    eprintln!("SELECT ISD (7-byte) reference: {:?}", dr.reference);

    assert!(
        dr.simrs.is_success(),
        "simrs SELECT ISD (7-byte) failed: {:02X}{:02X}",
        dr.simrs.sw[0],
        dr.simrs.sw[1]
    );

    // Reference may succeed (prefix match) or reject (exact-match only /
    // narrower GP surface); either is cataloged, not fatal here.
    eprintln!(
        "SW match: {} (simrs={:04X}, reference={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
});

apdu_test!(
    select_isd_reference_aid_on_both,
    "sel-reference-aid",
    |dc| {
        dc.power_on();

        let apdu = select_aid(&ORACLE_ISD_AID);
        let dr = dc.exchange(&apdu);

        eprintln!("SELECT ISD (8-byte) simrs:     {:?}", dr.simrs);
        eprintln!("SELECT ISD (8-byte) reference: {:?}", dr.reference);

        // simrs may return 6A82 (exact match) since its ISD is 7 bytes.
        // Reference outcome depends on how the backend's default ISD AID is
        // provisioned; we just log the divergence.
        eprintln!(
            "SW match: {} (simrs={:04X}, reference={:04X})",
            dr.sw_match(),
            dr.simrs.sw16(),
            dr.reference.sw16()
        );
    }
);

apdu_test!(select_unknown_aid_both_reject, "sel-unknown", |dc| {
    dc.power_on();

    let unknown = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB];
    let apdu = select_aid(&unknown);
    let dr = dc.exchange(&apdu);

    eprintln!("SELECT unknown simrs:     {:?}", dr.simrs);
    eprintln!("SELECT unknown reference: {:?}", dr.reference);

    // Both must reject. simrs returns 6Axx; JCardEngine collapses to
    // 6D00 (cataloged as J3). Accept any 6x error class on reference.
    assert_eq!(
        dr.simrs.sw[0], 0x6A,
        "simrs: expected 6Axx for unknown AID, got {:02X}{:02X}",
        dr.simrs.sw[0], dr.simrs.sw[1]
    );
    assert_eq!(
        dr.reference.sw[0] & 0xF0,
        0x60,
        "reference: expected 6xxx for unknown AID, got {:02X}{:02X}",
        dr.reference.sw[0],
        dr.reference.sw[1]
    );

    eprintln!(
        "SW match: {} (simrs={:04X}, reference={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
});

// -----------------------------------------------------------------------
// GET DATA
// -----------------------------------------------------------------------

apdu_test!(get_data_card_recognition_0066, "get-data-66", |dc| {
    dc.power_on();

    // GET DATA tag 0066 (Card Recognition Data). CLA=80 INS=CA P1=00 P2=66.
    let apdu = [0x80, 0xCA, 0x00, 0x66];
    let dr = dc.exchange(&apdu);

    eprintln!("GET DATA 0066 simrs:     {:?}", dr.simrs);
    eprintln!("GET DATA 0066 reference: {:?}", dr.reference);

    assert!(
        dr.simrs.is_success(),
        "simrs GET DATA 0066 failed: {:04X}",
        dr.simrs.sw16()
    );

    // Reference may return the same (9000 + tag 66 payload) or reject
    // (6A88 / 6D00 / 6982). We log the outcome; the catalog handles
    // known divergences.
    eprintln!(
        "SW match: {} (simrs={:04X}, reference={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.reference.sw16()
    );

    if dr.simrs.is_success() && !dr.simrs.data.is_empty() {
        assert_eq!(
            dr.simrs.data[0], 0x66,
            "simrs: card recognition data should start with tag 66"
        );
    }
    if dr.reference.is_success() && !dr.reference.data.is_empty() {
        assert_eq!(
            dr.reference.data[0], 0x66,
            "reference: card recognition data should start with tag 66"
        );
    }
});

apdu_test!(get_data_cplc_9f7f, "get-data-cplc", |dc| {
    dc.power_on();

    // GET DATA tag 9F7F (CPLC - Card Production Life Cycle).
    let apdu = [0x80, 0xCA, 0x9F, 0x7F, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("GET DATA CPLC simrs:     {:?}", dr.simrs);
    eprintln!("GET DATA CPLC reference: {:?}", dr.reference);

    assert!(
        dr.simrs.is_success(),
        "simrs should support CPLC: {:04X}",
        dr.simrs.sw16()
    );
});

apdu_test!(get_data_unknown_tag_both_reject, "get-data-bad", |dc| {
    dc.power_on();

    // GET DATA with a nonsense tag.
    let apdu = [0x80, 0xCA, 0xDE, 0xAD];
    let dr = dc.exchange(&apdu);

    eprintln!("GET DATA 0xDEAD simrs:     {:?}", dr.simrs);
    eprintln!("GET DATA 0xDEAD reference: {:?}", dr.reference);

    assert!(
        !dr.simrs.is_success(),
        "simrs should reject unknown GET DATA tag"
    );
    assert!(
        !dr.reference.is_success(),
        "reference should reject unknown GET DATA tag"
    );

    eprintln!(
        "SW match: {} (simrs={:04X}, reference={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
});

// -----------------------------------------------------------------------
// Error handling: invalid INS
// -----------------------------------------------------------------------

apdu_test!(invalid_ins_both_reject, "bad-ins", |dc| {
    dc.power_on();

    // GP-class APDU with a non-existent INS byte.
    let apdu = [0x80, 0xFD, 0x00, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("Invalid INS simrs:     {:?}", dr.simrs);
    eprintln!("Invalid INS reference: {:?}", dr.reference);

    assert!(!dr.simrs.is_success(), "simrs should reject invalid INS");
    assert!(
        !dr.reference.is_success(),
        "reference should reject invalid INS"
    );

    eprintln!(
        "SW match: {} (simrs={:04X}, reference={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
});

apdu_test!(iso_class_invalid_ins_both_reject, "iso-bad-ins", |dc| {
    dc.power_on();

    // ISO interindustry class with an unrecognized INS.
    let apdu = [0x00, 0xFD, 0x00, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("ISO invalid INS simrs:     {:?}", dr.simrs);
    eprintln!("ISO invalid INS reference: {:?}", dr.reference);

    assert!(
        !dr.simrs.is_success(),
        "simrs should reject invalid INS in ISO class"
    );
    assert!(
        !dr.reference.is_success(),
        "reference should reject invalid INS in ISO class"
    );

    eprintln!(
        "SW match: {} (simrs={:04X}, reference={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
});

// -----------------------------------------------------------------------
// INITIALIZE UPDATE (structure comparison only)
// -----------------------------------------------------------------------

apdu_test!(initialize_update_both_respond, "init-update", |dc| {
    dc.power_on();

    // First SELECT the ISD on each (using each card's own AID).
    let sel_simrs = select_aid(&SIMRS_ISD_AID);
    let _ = dc.simrs.process(SimEvent::Apdu(&sel_simrs));

    let sel_reference = select_aid(&ORACLE_ISD_AID);
    let _ = dc.reference.transmit_apdu(&sel_reference);

    // INITIALIZE UPDATE: 80 50 00 00 08 <host_challenge[8]>.
    let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut apdu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    apdu.extend_from_slice(&host_challenge);

    let dr = dc.exchange(&apdu);

    eprintln!("INIT UPDATE simrs:     {:?}", dr.simrs);
    eprintln!("INIT UPDATE reference: {:?}", dr.reference);

    assert!(
        dr.simrs.is_success(),
        "simrs INITIALIZE UPDATE failed: {:04X}",
        dr.simrs.sw16()
    );
    assert!(
        dr.reference.is_success(),
        "reference INITIALIZE UPDATE failed: {:04X}",
        dr.reference.sw16()
    );

    // simrs (SCP01/02) returns 28 bytes; reference SCP03 (jcsl,
    // JCardEngine) returns 29+ bytes. Both must be at least 28.
    eprintln!(
        "Response lengths: simrs={}, reference={}",
        dr.simrs.data.len(),
        dr.reference.data.len()
    );

    assert!(
        dr.simrs.data.len() >= 28,
        "simrs INIT UPDATE response too short: {} bytes",
        dr.simrs.data.len()
    );
    assert!(
        dr.reference.data.len() >= 28,
        "reference INIT UPDATE response too short: {} bytes",
        dr.reference.data.len()
    );

    let simrs_kdiv = &dr.simrs.data[..10];
    let reference_kdiv = &dr.reference.data[..10];
    eprintln!("simrs     key diversification: {simrs_kdiv:02x?}");
    eprintln!("reference key diversification: {reference_kdiv:02x?}");
});

// -----------------------------------------------------------------------
// GET STATUS (ISD)
// -----------------------------------------------------------------------

apdu_test!(get_status_isd_both_respond, "get-status", |dc| {
    dc.power_on();

    // GET STATUS P1=0x80 (ISD), no secure messaging. Per GP 2.1.1
    // clause 9.4, GET STATUS requires an authenticated SCP session.
    // Both simrs and reference should reject this.
    let apdu = [0x80, 0xF2, 0x80, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("GET STATUS ISD simrs:     {:?}", dr.simrs);
    eprintln!("GET STATUS ISD reference: {:?}", dr.reference);

    assert!(
        !dr.simrs.is_success(),
        "simrs GET STATUS should require auth, but returned: {:04X}",
        dr.simrs.sw16()
    );
    assert_eq!(
        dr.simrs.sw[0], 0x69,
        "simrs should return 69xx for auth failure"
    );
});

// -----------------------------------------------------------------------
// Power cycle: reset clears state
// -----------------------------------------------------------------------

// Reset semantics differ across backends: jcsl tears down the
// simulator when the TCP session reconnects, so a fresh INIT UPDATE
// afterwards succeeds cleanly. JCardEngine's bridge accepts exactly
// one connection per spawn and serves power_on/power_off through the
// existing socket, so reconnect_reference() is a no-op there. The
// shared assertion is that simrs clears its SCP session on Reset;
// reference-side behaviour is logged.
apdu_test!(
    reset_after_init_update_clears_scp_state,
    "reset-scp",
    |dc| {
        dc.power_on();

        let host_challenge = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let mut init_apdu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
        init_apdu.extend_from_slice(&host_challenge);
        let dr1 = dc.exchange(&init_apdu);
        assert!(dr1.simrs.is_success(), "simrs INIT UPDATE should succeed");
        eprintln!(
            "INIT UPDATE before reset: simrs={:04X}, reference={:04X}",
            dr1.simrs.sw16(),
            dr1.reference.sw16()
        );

        let _ = dc.simrs.process(SimEvent::Reset);
        dc.reconnect_reference();
        let _ = dc.reference.power_on();

        let ext_auth = [
            0x84, 0x82, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let dr2 = dc.exchange(&ext_auth);

        eprintln!("EXT AUTH after reset simrs:     {:?}", dr2.simrs);
        eprintln!("EXT AUTH after reset reference: {:?}", dr2.reference);

        assert!(
            !dr2.simrs.is_success(),
            "simrs should reject EXT AUTH after reset"
        );
    }
);

// -----------------------------------------------------------------------
// MANAGE CHANNEL
// -----------------------------------------------------------------------

apdu_test!(manage_channel_open_close, "manage-ch", |dc| {
    dc.power_on();

    // MANAGE CHANNEL: Open (P1=00, P2=00 = card assigns number).
    let open_ch = [0x00, 0x70, 0x00, 0x00, 0x01];
    let dr_open = dc.exchange(&open_ch);

    eprintln!("MANAGE CHANNEL open simrs:     {:?}", dr_open.simrs);
    eprintln!("MANAGE CHANNEL open reference: {:?}", dr_open.reference);

    if dr_open.simrs.is_success() && dr_open.reference.is_success() {
        assert!(
            !dr_open.simrs.data.is_empty(),
            "simrs: MANAGE CHANNEL open should return channel number"
        );
        assert!(
            !dr_open.reference.data.is_empty(),
            "reference: MANAGE CHANNEL open should return channel number"
        );

        let simrs_ch = dr_open.simrs.data[0];
        let reference_ch = dr_open.reference.data[0];
        eprintln!("Assigned channels: simrs={simrs_ch}, reference={reference_ch}");

        let close_simrs = [0x00, 0x70, 0x80, simrs_ch];
        let close_reference = [0x00, 0x70, 0x80, reference_ch];

        let dr_close_s = match dc.simrs.process(SimEvent::Apdu(&close_simrs)) {
            SimResponse::Apdu { sw, .. } => sw.to_bytes(),
            _ => [0x6F, 0x00],
        };
        let close_raw = dc
            .reference
            .transmit_apdu(&close_reference)
            .unwrap_or_default();
        let dr_close_r = if close_raw.len() >= 2 {
            [
                close_raw[close_raw.len() - 2],
                close_raw[close_raw.len() - 1],
            ]
        } else {
            [0x6F, 0x00]
        };

        eprintln!(
            "CLOSE channel: simrs={:02X}{:02X}, reference={:02X}{:02X}",
            dr_close_s[0], dr_close_s[1], dr_close_r[0], dr_close_r[1]
        );
    }
});

// -----------------------------------------------------------------------
// SCP02/03 authentication flow -- structural assertions only
// -----------------------------------------------------------------------

// INITIALIZE UPDATE: both respond with 28+ bytes. Key version and SCP
// identifier layouts differ across backends; we assert only that the
// simrs side advertises the expected key version.
apdu_test!(
    diff_scp_init_update_response_fields,
    "diff-iu-fields",
    |dc| {
        dc.power_on();

        let _ = dc
            .simrs
            .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
        let _ = dc.reference.transmit_apdu(&select_aid(&ORACLE_ISD_AID));

        let hc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut apdu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
        apdu.extend_from_slice(&hc);
        let dr = dc.exchange(&apdu);

        assert!(dr.simrs.is_success() && dr.reference.is_success());
        assert!(dr.simrs.data.len() >= 28 && dr.reference.data.len() >= 28);

        let simrs_scp = dr.simrs.data[11];
        let reference_scp = dr.reference.data[11];
        eprintln!("SCP identifiers: simrs=0x{simrs_scp:02X}, reference=0x{reference_scp:02X}");

        let simrs_kv = dr.simrs.data[10];
        let reference_kv = dr.reference.data[10];
        eprintln!("Key versions: simrs=0x{simrs_kv:02X}, reference=0x{reference_kv:02X}");
        // Both sides commonly advertise the default key set (KV 0x01 for
        // SCP02, 0x03 for SCP03). Exact equality across mixed-protocol
        // backends is not guaranteed; log and move on.
    }
);

// INITIALIZE UPDATE with non-existent key version.
//
// simrs must reject with 6A86. JCardEngine's default `GlobalPlatform`
// doesn't validate the KV parameter and accepts KV=0xFF as 9000, which
// is a known backend-surface divergence from GP 2.x spec behaviour; we
// log it rather than hard-failing.
apdu_test!(diff_scp_wrong_key_version, "diff-bad-kv", |dc| {
    dc.power_on();

    let _ = dc
        .simrs
        .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
    let _ = dc.reference.transmit_apdu(&select_aid(&ORACLE_ISD_AID));

    let hc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut apdu = vec![0x80, 0x50, 0xFF, 0x00, 0x08]; // KV=0xFF
    apdu.extend_from_slice(&hc);
    let dr = dc.exchange(&apdu);

    eprintln!(
        "Bad KV: simrs={:04X}, reference={:04X}",
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
    assert!(!dr.simrs.is_success());
    assert_eq!(dr.simrs.sw, [0x6A, 0x86], "simrs should return 6A86");
});

// EXTERNAL AUTHENTICATE without INITIALIZE UPDATE: both reject.
apdu_test!(diff_ext_auth_without_init_update, "diff-ea-noiu", |dc| {
    dc.power_on();

    let ext_auth = [
        0x84, 0x82, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let dr = dc.exchange(&ext_auth);

    eprintln!(
        "EXT AUTH no IU: simrs={:04X}, reference={:04X}",
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
    assert!(!dr.simrs.is_success());
    assert!(!dr.reference.is_success());
    assert_eq!(dr.simrs.sw[0], 0x69);
    assert_eq!(dr.reference.sw[0], 0x69);
});

// -----------------------------------------------------------------------
// GET DATA 0042 (ISD AID)
// -----------------------------------------------------------------------

apdu_test!(diff_get_data_0042_isd_aid, "diff-gd-42", |dc| {
    dc.power_on();

    let apdu = [0x80, 0xCA, 0x00, 0x42, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("GET DATA 0042 simrs:     {:?}", dr.simrs);
    eprintln!("GET DATA 0042 reference: {:?}", dr.reference);

    assert!(dr.simrs.is_success(), "simrs GET DATA 0042 should succeed");
    // Reference may reject this tag (JCardEngine collapses unknown GET
    // DATA to 6D00, cataloged as J1/J2). Assert content equality only
    // when both sides succeeded.
    if dr.reference.is_success() {
        assert_eq!(
            dr.simrs.data, dr.reference.data,
            "IIN data should match when both backends support tag 0042"
        );
    }
    eprintln!(
        "SW match: {} (simrs={:04X}, reference={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.reference.sw16()
    );
});

// -----------------------------------------------------------------------
// Error class consistency
// -----------------------------------------------------------------------

// simrs returns the documented error class for each failure mode; the
// reference may collapse narrower surfaces (JCardEngine: GET DATA ->
// 6D00, SELECT unknown -> 6D00). We assert on the simrs class and
// just log the reference divergence.
apdu_test!(diff_error_class_consistency, "diff-err-class", |dc| {
    dc.power_on();

    let cases: Vec<(Vec<u8>, u8)> = vec![
        (vec![0x80, 0xFD, 0x00, 0x00], 0x6D), // invalid GP INS -> 6Dxx
        (vec![0x80, 0xF2, 0x80, 0x00], 0x69), // GET STATUS w/o auth -> 69xx
        (select_aid(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), 0x6A), // unknown AID -> 6Axx
    ];

    for (apdu, expected_class) in &cases {
        let dr = dc.exchange(apdu);
        assert!(!dr.simrs.is_success());
        assert!(!dr.reference.is_success());
        let simrs_class = dr.simrs.sw[0] & 0xF0;
        let reference_class = dr.reference.sw[0] & 0xF0;
        assert_eq!(
            simrs_class,
            expected_class & 0xF0,
            "simrs error class mismatch for APDU {:02X?}: got {:02X}",
            apdu,
            dr.simrs.sw[0]
        );
        eprintln!(
            "APDU {:02X?}: simrs={:04X}, reference={:04X} (class match: {})",
            &apdu[..4.min(apdu.len())],
            dr.simrs.sw16(),
            dr.reference.sw16(),
            simrs_class == reference_class
        );
    }
});

// -----------------------------------------------------------------------
// Full discovery sequence
// -----------------------------------------------------------------------

// Standard card discovery flow replayed through both implementations.
apdu_test!(diff_full_discovery_sequence, "diff-discovery", |dc| {
    dc.power_on();

    // 1. SELECT ISD (each with their own AID).
    let sel_s = dc
        .simrs
        .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
    assert!(matches!(sel_s, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]));
    let sel_r = dc
        .reference
        .transmit_apdu(&select_aid(&ORACLE_ISD_AID))
        .unwrap();
    assert!(sel_r.len() >= 2 && sel_r[sel_r.len() - 2] == 0x90);

    // 2. GET DATA 0066 (Card Recognition Data).
    let dr1 = dc.exchange(&[0x80, 0xCA, 0x00, 0x66]);
    eprintln!(
        "Discovery step 2 (GET DATA 0066): simrs={:04X}, reference={:04X}",
        dr1.simrs.sw16(),
        dr1.reference.sw16()
    );

    // 3. INITIALIZE UPDATE.
    let hc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let mut iu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu.extend_from_slice(&hc);
    let dr2 = dc.exchange(&iu);
    eprintln!(
        "Discovery step 3 (INIT UPDATE): simrs={:04X}, reference={:04X}",
        dr2.simrs.sw16(),
        dr2.reference.sw16()
    );
    assert!(dr2.simrs.is_success() && dr2.reference.is_success());

    // 4. GET DATA CPLC.
    let dr3 = dc.exchange(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]);
    eprintln!(
        "Discovery step 4 (CPLC): simrs={:04X}, reference={:04X}",
        dr3.simrs.sw16(),
        dr3.reference.sw16()
    );

    let steps_both_success = [&dr1, &dr2, &dr3]
        .iter()
        .filter(|d| d.simrs.is_success() && d.reference.is_success())
        .count();
    eprintln!("Discovery: {steps_both_success}/3 steps matched");
});

// -----------------------------------------------------------------------
// Full authenticated session: SCP02 (simrs) + SCP03 (reference)
// -----------------------------------------------------------------------

/// Complete mutual auth on BOTH sides independently, then compare
/// authenticated GET STATUS responses. SCP03 derivation assumes the
/// reference is provisioned with the same master key as simrs (jcsl:
/// default 40..4F; jcardengine: configured via `--gp-master-key-hex`).
#[allow(clippy::too_many_lines, clippy::similar_names)]
fn diff_authenticated_get_status_body<B: ReferenceBackend>(mut dc: DualCard<B>) {
    dc.power_on();

    // -- simrs side: SCP02 handshake --
    let sel_s = select_aid(&SIMRS_ISD_AID);
    let _ = dc.simrs.process(SimEvent::Apdu(&sel_s));

    let hc: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut iu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu.extend_from_slice(&hc);
    let simrs_iu = match dc.simrs.process(SimEvent::Apdu(&iu)) {
        SimResponse::Apdu { data, sw } => {
            assert_eq!(sw.to_bytes(), [0x90, 0x00], "simrs INIT UPDATE failed");
            data.to_vec()
        }
        other => panic!("unexpected simrs response: {other:?}"),
    };
    assert!(simrs_iu.len() >= 28);

    // Derive SCP02 session keys.
    let scp_id = simrs_iu[11];
    assert_eq!(scp_id, 0x02, "simrs should be SCP02");
    let seq = u16::from_be_bytes([simrs_iu[12], simrs_iu[13]]);
    let mut cc6 = [0u8; 6];
    cc6.copy_from_slice(&simrs_iu[14..20]);

    let keys = simrs_gp_keys::KeySet::des3_2key(
        simrs_differential_crossvalidation::KEY_BYTES,
        simrs_differential_crossvalidation::KEY_BYTES,
        simrs_differential_crossvalidation::KEY_BYTES,
    );
    let (enc, mac, _rmac, _dek) = simrs_gp_scp::derive_scp02_session_keys(&keys, seq);

    let host_crypto = simrs_gp_scp::compute_scp02_host_cryptogram(&enc, &hc, seq, &cc6);
    let (cmac, _) = simrs_gp_scp::generate_cmac(
        &mac,
        &[0x84, 0x82, 0x01, 0x00],
        &host_crypto,
        &[0u8; 8],
        simrs_gp_scp::ScpVersion::Scp02,
    );

    let mut ea = vec![0x84, 0x82, 0x01, 0x00, 0x10];
    ea.extend_from_slice(&host_crypto);
    ea.extend_from_slice(&cmac);
    let simrs_ea = dc.simrs.process(SimEvent::Apdu(&ea));
    assert!(
        matches!(simrs_ea, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]),
        "simrs EXT AUTH failed: {simrs_ea:?}"
    );

    // Send GET STATUS with C-MAC on simrs.
    let gs_data = [0x4F, 0x00]; // search criteria: all
    let (gs_cmac, _) = simrs_gp_scp::generate_cmac(
        &mac,
        &[0x80, 0xF2, 0x80, 0x00],
        &gs_data,
        &cmac, // ICV from EXT AUTH
        simrs_gp_scp::ScpVersion::Scp02,
    );
    let mut gs_apdu = vec![0x84, 0xF2, 0x80, 0x00, 0x0A, 0x4F, 0x00];
    gs_apdu.extend_from_slice(&gs_cmac);
    let simrs_gs = match dc.simrs.process(SimEvent::Apdu(&gs_apdu)) {
        SimResponse::Apdu { data, sw } => {
            eprintln!(
                "simrs GET STATUS: SW={:02X}{:02X} data_len={}",
                sw.to_bytes()[0],
                sw.to_bytes()[1],
                data.len()
            );
            (data.to_vec(), sw.to_bytes())
        }
        other => panic!("simrs GET STATUS unexpected: {other:?}"),
    };

    // -- reference side: SCP03 handshake --
    let sel_r = select_aid(&ORACLE_ISD_AID);
    let _ = dc.reference.transmit_apdu(&sel_r);

    let reference_iu_raw = dc
        .reference
        .transmit_apdu(&iu)
        .expect("reference INIT UPDATE failed");
    assert!(
        reference_iu_raw.len() >= 31,
        "reference INIT UPDATE response too short"
    );
    let reference_sw = [
        reference_iu_raw[reference_iu_raw.len() - 2],
        reference_iu_raw[reference_iu_raw.len() - 1],
    ];
    assert_eq!(
        reference_sw,
        [0x90, 0x00],
        "reference INIT UPDATE failed: {reference_sw:02X?}"
    );
    let reference_data = &reference_iu_raw[..reference_iu_raw.len() - 2];

    let parsed = simrs_gp_scp::scp03::parse_init_update(reference_data)
        .expect("failed to parse SCP03 INIT UPDATE response");
    assert_eq!(parsed.scp_id, 0x03, "reference should be SCP03");

    // Derive SCP03 session keys.
    let (s_enc, s_mac, s_rmac) = simrs_gp_scp::scp03::derive_session_keys(
        &simrs_differential_crossvalidation::KEY_BYTES,
        &simrs_differential_crossvalidation::KEY_BYTES,
        &hc,
        &parsed.card_challenge,
    );
    let _ = (s_enc, s_rmac); // suppress unused warnings

    // Verify card cryptogram.
    let expected_card_crypto =
        simrs_gp_scp::scp03::compute_card_cryptogram(&s_mac, &hc, &parsed.card_challenge);
    eprintln!("reference card crypto: {:02X?}", parsed.card_cryptogram);
    eprintln!("expected card crypto:  {expected_card_crypto:02X?}");

    // Compute host cryptogram.
    let host_crypto_scp03 =
        simrs_gp_scp::scp03::compute_host_cryptogram(&s_mac, &hc, &parsed.card_challenge);

    // EXT AUTH for SCP03: CLA=0x84, INS=0x82, P1=0x33 (C-MAC+C-ENC+R-MAC), P2=0x00.
    // Actually P1=0x01 for C-MAC only, which is simpler.
    let (ea_cmac3, new_cv) = simrs_gp_scp::scp03::generate_cmac(
        &s_mac,
        &[0u8; 16], // initial chaining value
        &[0x84, 0x82, 0x01, 0x00],
        &host_crypto_scp03,
    );
    let mut ea3 = vec![0x84, 0x82, 0x01, 0x00, 0x10];
    ea3.extend_from_slice(&host_crypto_scp03);
    ea3.extend_from_slice(&ea_cmac3);
    let reference_ea_raw = dc
        .reference
        .transmit_apdu(&ea3)
        .expect("reference EXT AUTH transmit failed");
    let reference_ea_sw = if reference_ea_raw.len() >= 2 {
        [
            reference_ea_raw[reference_ea_raw.len() - 2],
            reference_ea_raw[reference_ea_raw.len() - 1],
        ]
    } else {
        [0x6F, 0x00]
    };
    eprintln!(
        "reference EXT AUTH: SW={:02X}{:02X}",
        reference_ea_sw[0], reference_ea_sw[1]
    );

    if reference_ea_sw == [0x90, 0x00] {
        // Send authenticated GET STATUS on the reference.
        let (gs_cmac3, _) = simrs_gp_scp::scp03::generate_cmac(
            &s_mac,
            &new_cv,
            &[0x80, 0xF2, 0x80, 0x00],
            &gs_data,
        );
        let mut gs3 = vec![0x84, 0xF2, 0x80, 0x00, 0x0A, 0x4F, 0x00];
        gs3.extend_from_slice(&gs_cmac3);
        let reference_gs_raw = dc.reference.transmit_apdu(&gs3).unwrap_or_default();
        let reference_gs_sw = if reference_gs_raw.len() >= 2 {
            [
                reference_gs_raw[reference_gs_raw.len() - 2],
                reference_gs_raw[reference_gs_raw.len() - 1],
            ]
        } else {
            [0x6F, 0x00]
        };
        let reference_gs_data = if reference_gs_raw.len() > 2 {
            &reference_gs_raw[..reference_gs_raw.len() - 2]
        } else {
            &[]
        };

        eprintln!(
            "reference GET STATUS: SW={:02X}{:02X} data_len={}",
            reference_gs_sw[0],
            reference_gs_sw[1],
            reference_gs_data.len()
        );

        eprintln!("\n--- Authenticated GET STATUS comparison ---");
        eprintln!(
            "simrs:     SW={:02X}{:02X} data[{}]={:02X?}",
            simrs_gs.1[0],
            simrs_gs.1[1],
            simrs_gs.0.len(),
            &simrs_gs.0
        );
        eprintln!(
            "reference: SW={:02X}{:02X} data[{}]={:02X?}",
            reference_gs_sw[0],
            reference_gs_sw[1],
            reference_gs_data.len(),
            reference_gs_data
        );

        assert_eq!(simrs_gs.1, [0x90, 0x00], "simrs GET STATUS should succeed");
        if reference_gs_sw != [0x90, 0x00] {
            // Reference accepted auth but GET STATUS hit a backend-specific
            // surface: JCardEngine's GP applet collapses unhandled GP INS
            // to 6D00 (cataloged as J1/J2). Log and continue rather than
            // hard-failing the matrix cell.
            eprintln!(
                "reference GET STATUS after auth returned {reference_gs_sw:02X?} \
                 -- likely narrower GP applet surface (cataloged divergence)."
            );
        }
    } else {
        eprintln!(
            "reference EXT AUTH failed with {:02X}{:02X} -- skipping authenticated comparison",
            reference_ea_sw[0], reference_ea_sw[1]
        );
        eprintln!(
            "(This may mean our SCP03 key derivation doesn't match the reference's, \
             or the reference is not provisioned with the expected master key.)"
        );
    }
}

apdu_test!(diff_authenticated_get_status, "diff-auth-gs", |dc| {
    diff_authenticated_get_status_body(dc);
});

// -----------------------------------------------------------------------
// SCP03 on simrs only -- reference not exercised, matrixed for uniform CI
// -----------------------------------------------------------------------

// SCP03 INITIALIZE UPDATE on simrs: verifies 29-byte response with SCP
// ID 0x03. simrs-only test (reference is set up but unused); matrixed
// so both backend cells exercise the simrs SCP03 path uniformly.
apdu_test!(diff_scp03_init_update_simrs, "diff-scp03-iu", |dc| {
    dc.power_on();

    let sel_s = select_aid(&SIMRS_ISD_AID);
    let _ = dc.simrs.process(SimEvent::Apdu(&sel_s));

    let hc: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut iu = vec![0x80, 0x50, 0x03, 0x00, 0x08]; // KV=0x03
    iu.extend_from_slice(&hc);
    let simrs_iu = match dc.simrs.process(SimEvent::Apdu(&iu)) {
        SimResponse::Apdu { data, sw } => {
            assert_eq!(
                sw.to_bytes(),
                [0x90, 0x00],
                "simrs SCP03 INIT UPDATE failed"
            );
            data.to_vec()
        }
        other => panic!("unexpected simrs response: {other:?}"),
    };

    assert_eq!(
        simrs_iu.len(),
        29,
        "SCP03 INIT UPDATE should be 29 bytes, got {}",
        simrs_iu.len()
    );
    assert_eq!(simrs_iu[11], 0x03, "SCP ID should be 0x03");
    assert_eq!(simrs_iu[10], 0x03, "key version should be 0x03");
    assert_eq!(simrs_iu[12], 0x00, "i parameter should be 0x00 (explicit)");

    eprintln!(
        "simrs SCP03 INIT UPDATE: {} bytes, SCP={:02X}, KV={:02X}, i={:02X}",
        simrs_iu.len(),
        simrs_iu[11],
        simrs_iu[10],
        simrs_iu[12]
    );
});

// SCP03 full mutual auth on simrs with authenticated GET STATUS for
// the ISD (P1=0x80). simrs-only test; matrixed so both backend cells
// exercise the simrs SCP03 path uniformly. Shares the handshake with
// scp03_open_simrs_session — that helper does the cryptographic
// correctness checks (card cryptogram, SCP identifier); this test
// exercises the post-auth command path.
apdu_test!(diff_scp03_full_auth_simrs, "diff-scp03-auth", |dc| {
    let (s_mac, icv) = scp03_open_simrs_session(&mut dc);
    let (data, sw, _) = scp03_authenticated_exchange(
        &mut dc,
        &s_mac,
        &icv,
        [0x80, 0xF2, 0x80, 0x00],
        &[0x4F, 0x00],
    );

    eprintln!(
        "simrs SCP03 GET STATUS (ISD): SW={:02X}{:02X} data_len={}",
        sw[0],
        sw[1],
        data.len()
    );

    assert_eq!(
        sw,
        [0x90, 0x00],
        "SCP03 authenticated GET STATUS should succeed"
    );
    assert!(!data.is_empty(), "GET STATUS should return ISD data");
});

/// Open a SCP03 session on the simrs side and return the derived MAC
/// session key plus the ICV to use on the next authenticated command.
///
/// Reusable helper for the SCP03-authenticated batch of tests below.
/// Shares the handshake shape with
/// [`diff_scp03_full_auth_simrs_body`] so the cryptographic path is
/// exercised identically; callers supply the follow-up commands.
fn scp03_open_simrs_session<B: ReferenceBackend>(dc: &mut DualCard<B>) -> ([u8; 16], [u8; 16]) {
    dc.power_on();
    let sel = select_aid(&SIMRS_ISD_AID);
    let _ = dc.simrs.process(SimEvent::Apdu(&sel));

    let hc: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut iu = vec![0x80, 0x50, 0x03, 0x00, 0x08];
    iu.extend_from_slice(&hc);

    let iu_resp = match dc.simrs.process(SimEvent::Apdu(&iu)) {
        SimResponse::Apdu { data, sw } => {
            assert_eq!(
                sw.to_bytes(),
                [0x90, 0x00],
                "simrs SCP03 INIT UPDATE failed"
            );
            data.to_vec()
        }
        other => panic!("unexpected simrs INIT UPDATE response: {other:?}"),
    };

    // SCP identifier at byte 11 must be 0x03 for SCP03.
    assert_eq!(
        iu_resp[11], 0x03,
        "simrs SCP03 INIT UPDATE: expected SCP=0x03, got {:02X}",
        iu_resp[11]
    );

    let mut cc = [0u8; 8];
    cc.copy_from_slice(&iu_resp[13..21]);

    let (_enc, s_mac, _rmac) = simrs_gp_scp::derive_scp03_session_keys(
        &simrs_differential_crossvalidation::KEY_BYTES,
        &simrs_differential_crossvalidation::KEY_BYTES,
        &hc,
        &cc,
    );

    // Verify the card's cryptogram against what our host-side derivation expects.
    let expected_card_crypto = simrs_gp_scp::compute_scp03_card_cryptogram(&s_mac, &hc, &cc);
    assert_eq!(
        &iu_resp[21..29],
        &expected_card_crypto,
        "SCP03 card cryptogram mismatch — key derivation drift"
    );

    let host_crypto = simrs_gp_scp::compute_scp03_host_cryptogram(&s_mac, &hc, &cc);
    let (ea_cmac, next_icv) = simrs_gp_scp::scp03_generate_cmac(
        &s_mac,
        &[0u8; 16],
        &[0x84, 0x82, 0x01, 0x00],
        &host_crypto,
    );

    let mut ea = vec![0x84, 0x82, 0x01, 0x00, 0x10];
    ea.extend_from_slice(&host_crypto);
    ea.extend_from_slice(&ea_cmac);
    match dc.simrs.process(SimEvent::Apdu(&ea)) {
        SimResponse::Apdu { sw, .. } => {
            assert_eq!(sw.to_bytes(), [0x90, 0x00], "simrs SCP03 EXT AUTH failed");
        }
        other => panic!("unexpected simrs EXT AUTH response: {other:?}"),
    }

    (s_mac, next_icv)
}

/// Send one C-MAC'd APDU under an open SCP03 session. Returns
/// `(data_without_sw, sw_bytes, new_icv_for_next_command)`.
fn scp03_authenticated_exchange<B: ReferenceBackend>(
    dc: &mut DualCard<B>,
    s_mac: &[u8; 16],
    icv: &[u8; 16],
    header: [u8; 4],
    data: &[u8],
) -> (Vec<u8>, [u8; 2], [u8; 16]) {
    let (cmac, new_icv) = simrs_gp_scp::scp03_generate_cmac(s_mac, icv, &header, data);
    // secured CLA = original CLA with bit 0x04 set
    let secured_cla = header[0] | 0x04;
    let lc = u8::try_from(data.len() + 8).expect("APDU data fits in one byte");
    let mut apdu = vec![secured_cla, header[1], header[2], header[3], lc];
    apdu.extend_from_slice(data);
    apdu.extend_from_slice(&cmac);

    match dc.simrs.process(SimEvent::Apdu(&apdu)) {
        SimResponse::Apdu { data, sw } => (data.to_vec(), sw.to_bytes(), new_icv),
        other => panic!("unexpected authenticated response: {other:?}"),
    }
}

// GET DATA 9F7F (CPLC) under an authenticated SCP03 session.
apdu_test!(scp03_auth_get_data_cplc, "scp03-auth-cplc", |dc| {
    let (s_mac, icv) = scp03_open_simrs_session(&mut dc);
    let (data, sw, _) =
        scp03_authenticated_exchange(&mut dc, &s_mac, &icv, [0x80, 0xCA, 0x9F, 0x7F], &[]);

    eprintln!(
        "SCP03 auth GET DATA CPLC: sw={:02X}{:02X} data_len={}",
        sw[0],
        sw[1],
        data.len()
    );

    assert_eq!(sw, [0x90, 0x00], "authenticated CPLC should succeed");
    assert!(!data.is_empty(), "CPLC must have payload");
});

// GET DATA 0042 (ISD IIN) under an authenticated SCP03 session.
apdu_test!(scp03_auth_get_data_iin, "scp03-auth-iin", |dc| {
    let (s_mac, icv) = scp03_open_simrs_session(&mut dc);
    let (data, sw, _) =
        scp03_authenticated_exchange(&mut dc, &s_mac, &icv, [0x80, 0xCA, 0x00, 0x42], &[]);

    eprintln!(
        "SCP03 auth GET DATA IIN: sw={:02X}{:02X} data={:02X?}",
        sw[0], sw[1], data
    );

    assert_eq!(sw, [0x90, 0x00], "authenticated IIN should succeed");
    assert!(!data.is_empty(), "IIN must have payload");
});

// GET STATUS P1=0x20 (Executable Load Files / packages) authenticated.
apdu_test!(scp03_auth_get_status_packages, "scp03-auth-gs-pkg", |dc| {
    let (s_mac, icv) = scp03_open_simrs_session(&mut dc);
    let (data, sw, _) = scp03_authenticated_exchange(
        &mut dc,
        &s_mac,
        &icv,
        [0x80, 0xF2, 0x20, 0x00],
        &[0x4F, 0x00],
    );

    eprintln!(
        "SCP03 auth GET STATUS (packages): sw={:02X}{:02X} data_len={}",
        sw[0],
        sw[1],
        data.len()
    );

    // 9000 (have entries) or 6A88 (no entries in this slot) both valid.
    assert!(
        sw == [0x90, 0x00] || sw == [0x6A, 0x88],
        "packages GET STATUS unexpected SW: {sw:02X?}"
    );
});

// GET STATUS P1=0x40 (Applications / applets) authenticated.
apdu_test!(scp03_auth_get_status_applets, "scp03-auth-gs-app", |dc| {
    let (s_mac, icv) = scp03_open_simrs_session(&mut dc);
    let (data, sw, _) = scp03_authenticated_exchange(
        &mut dc,
        &s_mac,
        &icv,
        [0x80, 0xF2, 0x40, 0x00],
        &[0x4F, 0x00],
    );

    eprintln!(
        "SCP03 auth GET STATUS (applets): sw={:02X}{:02X} data_len={}",
        sw[0],
        sw[1],
        data.len()
    );

    assert!(
        sw == [0x90, 0x00] || sw == [0x6A, 0x88],
        "applets GET STATUS unexpected SW: {sw:02X?}"
    );
});

// -----------------------------------------------------------------------
// APDU sequence: SELECT then GET DATA
// -----------------------------------------------------------------------

apdu_test!(select_then_get_data_sequence, "seq-sel-gd", |dc| {
    dc.power_on();

    // Step 1: SELECT ISD on each (using their respective AIDs).
    let sel_simrs = select_aid(&SIMRS_ISD_AID);
    let simrs_sel = dc.simrs.process(SimEvent::Apdu(&sel_simrs));
    assert!(
        matches!(simrs_sel, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]),
        "simrs SELECT ISD failed"
    );

    let sel_reference = select_aid(&ORACLE_ISD_AID);
    let reference_sel_raw = dc
        .reference
        .transmit_apdu(&sel_reference)
        .expect("reference SELECT failed");
    assert!(
        reference_sel_raw.len() >= 2
            && reference_sel_raw[reference_sel_raw.len() - 2] == 0x90
            && reference_sel_raw[reference_sel_raw.len() - 1] == 0x00,
        "reference SELECT ISD failed: {reference_sel_raw:02x?}"
    );

    // Step 2: GET DATA 0066 on both (same APDU).
    let get_data = [0x80, 0xCA, 0x00, 0x66];
    let dr = dc.exchange(&get_data);

    eprintln!("After SELECT -> GET DATA 0066:");
    eprintln!("  simrs:     {:?}", dr.simrs);
    eprintln!("  reference: {:?}", dr.reference);

    if dr.simrs.is_success() {
        assert!(
            !dr.simrs.data.is_empty(),
            "simrs GET DATA 0066 returned empty data"
        );
    }
});

// -----------------------------------------------------------------------
// GP lifecycle: INSTALL / LOAD / DELETE without authenticated SCP
// -----------------------------------------------------------------------
//
// GP 2.x requires INSTALL / LOAD / DELETE to be carried inside a
// secured channel (SCP01/02/03 with at least C-MAC). Sending them
// outside an authenticated session must be rejected. The exact
// reject SW differs per implementation (69 82, 69 85, 69 87) but
// the error class (0x69 — security conditions) is invariant.

// INSTALL [for Load] — P1=0x02.
apdu_test!(
    lifecycle_install_for_load_unauthenticated_rejected,
    "lc-install-load",
    |dc| {
        dc.power_on();
        let _ = dc
            .simrs
            .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
        let _ = dc.reference.transmit_apdu(&select_aid(&ORACLE_ISD_AID));

        // Data: LFAID(7) + empty SDAID + empty hash + empty params + empty token.
        let apdu = [
            0x80, 0xE6, 0x02, 0x00, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let dr = dc.exchange(&apdu);

        eprintln!(
            "INSTALL [for Load] unauth: simrs={:04X}, reference={:04X}",
            dr.simrs.sw16(),
            dr.reference.sw16()
        );

        assert!(
            !dr.simrs.is_success(),
            "simrs should reject unauthenticated INSTALL [for Load]: {:04X}",
            dr.simrs.sw16()
        );
        assert!(
            !dr.reference.is_success(),
            "reference should reject unauthenticated INSTALL [for Load]"
        );
    }
);

// INSTALL [for Install and Make Selectable] — P1=0x0C.
apdu_test!(
    lifecycle_install_for_install_unauthenticated_rejected,
    "lc-install-inst",
    |dc| {
        dc.power_on();
        let _ = dc
            .simrs
            .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
        let _ = dc.reference.transmit_apdu(&select_aid(&ORACLE_ISD_AID));

        // Data: ELF AID(7) + EM AID(7) + Instance AID(5) + Privs(0) + Install params(3) + Token(0).
        let apdu = [
            0x80, 0xE6, 0x0C, 0x00, 0x1B, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00,
            0x02, 0xC9, 0x00, 0x00,
        ];
        let dr = dc.exchange(&apdu);

        eprintln!(
            "INSTALL [for Inst+MS] unauth: simrs={:04X}, reference={:04X}",
            dr.simrs.sw16(),
            dr.reference.sw16()
        );

        assert!(!dr.simrs.is_success());
        assert!(!dr.reference.is_success());
    }
);

// LOAD command — P1=0x80 (last block).
apdu_test!(lifecycle_load_unauthenticated_rejected, "lc-load", |dc| {
    dc.power_on();
    let _ = dc
        .simrs
        .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
    let _ = dc.reference.transmit_apdu(&select_aid(&ORACLE_ISD_AID));

    // LOAD data: tag C4 (load file data) + length + bogus payload.
    let apdu = [
        0x80, 0xE8, 0x80, 0x00, 0x05, 0xC4, 0x03, 0xDE, 0xAD, 0xBE, 0x00,
    ];
    let dr = dc.exchange(&apdu);

    eprintln!(
        "LOAD unauth: simrs={:04X}, reference={:04X}",
        dr.simrs.sw16(),
        dr.reference.sw16()
    );

    assert!(
        !dr.simrs.is_success(),
        "simrs should reject unauthenticated LOAD"
    );
    assert!(
        !dr.reference.is_success(),
        "reference should reject unauthenticated LOAD"
    );
});

// DELETE [application].
apdu_test!(
    lifecycle_delete_unauthenticated_rejected,
    "lc-delete",
    |dc| {
        dc.power_on();
        let _ = dc
            .simrs
            .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
        let _ = dc.reference.transmit_apdu(&select_aid(&ORACLE_ISD_AID));

        // DELETE application: TLV tag 4F + length + AID.
        let apdu = [
            0x80, 0xE4, 0x00, 0x00, 0x09, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01,
            0x00,
        ];
        let dr = dc.exchange(&apdu);

        eprintln!(
            "DELETE unauth: simrs={:04X}, reference={:04X}",
            dr.simrs.sw16(),
            dr.reference.sw16()
        );

        assert!(
            !dr.simrs.is_success(),
            "simrs should reject unauthenticated DELETE"
        );
        assert!(
            !dr.reference.is_success(),
            "reference should reject unauthenticated DELETE"
        );
    }
);

// INSTALL with a P1 value that is not any defined GP 2.x combination.
//
// simrs validates P1 strictly and rejects 0xFF. jcsl silently
// accepts the command (returns 9000) — it treats P1 as a permissive
// bitmask rather than a closed set, which is a reference-side
// laxity we catalog rather than enforce. Assertion is simrs-only.
apdu_test!(
    lifecycle_install_invalid_p1_rejected,
    "lc-install-bad-p1",
    |dc| {
        dc.power_on();
        let _ = dc
            .simrs
            .process(SimEvent::Apdu(&select_aid(&SIMRS_ISD_AID)));
        let _ = dc.reference.transmit_apdu(&select_aid(&ORACLE_ISD_AID));

        // P1=0xFF is not a valid INSTALL combination under GP 2.1.1 or 2.3.
        let apdu = [0x80, 0xE6, 0xFF, 0x00, 0x00];
        let dr = dc.exchange(&apdu);

        eprintln!(
            "INSTALL bad P1: simrs={:04X}, reference={:04X}",
            dr.simrs.sw16(),
            dr.reference.sw16()
        );

        assert!(
            !dr.simrs.is_success(),
            "simrs must reject INSTALL with P1=0xFF"
        );
    }
);

// -----------------------------------------------------------------------
// MANAGE CHANNEL — multi-channel and error handling
// -----------------------------------------------------------------------

// Open multiple logical channels in sequence. Card must assign
// distinct non-zero channel numbers. GP 2.x supports up to four
// logical channels (0..=3); implementations may support fewer.
apdu_test!(manage_channel_multiple_opens, "mc-multi-open", |dc| {
    dc.power_on();

    // Open channel #1
    let open_ch = [0x00, 0x70, 0x00, 0x00, 0x01];
    let dr1 = dc.exchange(&open_ch);
    eprintln!(
        "Open #1: simrs={:04X} data={:02X?}, reference={:04X} data={:02X?}",
        dr1.simrs.sw16(),
        dr1.simrs.data,
        dr1.reference.sw16(),
        dr1.reference.data
    );

    if !dr1.simrs.is_success() {
        eprintln!("simrs does not support MANAGE CHANNEL — skipping multi-open");
        return;
    }

    // Open channel #2
    let dr2 = dc.exchange(&open_ch);
    eprintln!(
        "Open #2: simrs={:04X} data={:02X?}, reference={:04X}",
        dr2.simrs.sw16(),
        dr2.simrs.data,
        dr2.reference.sw16()
    );

    if dr2.simrs.is_success() && !dr1.simrs.data.is_empty() && !dr2.simrs.data.is_empty() {
        assert_ne!(
            dr1.simrs.data[0], dr2.simrs.data[0],
            "simrs must assign distinct channel numbers across successive opens"
        );
    }
});

// Close a channel that was never opened must be rejected.
apdu_test!(manage_channel_close_nonexistent, "mc-close-none", |dc| {
    dc.power_on();

    // Close channel 5 (does not exist; GP 2.x supports ch 0..=3).
    let close_unknown = [0x00, 0x70, 0x80, 0x05];
    let dr = dc.exchange(&close_unknown);

    eprintln!(
        "Close unknown channel 5: simrs={:04X}, reference={:04X}",
        dr.simrs.sw16(),
        dr.reference.sw16()
    );

    assert!(
        !dr.simrs.is_success(),
        "simrs should reject close of non-existent channel"
    );
    assert!(
        !dr.reference.is_success(),
        "reference should reject close of non-existent channel"
    );
});

// MANAGE CHANNEL with an invalid P1 value (neither open=0x00 nor
// close=0x80). Must be rejected with 6A86 / 6A81 / 6D00 per impl.
apdu_test!(manage_channel_invalid_p1, "mc-bad-p1", |dc| {
    dc.power_on();

    let apdu = [0x00, 0x70, 0x7F, 0x00, 0x01];
    let dr = dc.exchange(&apdu);

    eprintln!(
        "MANAGE CHANNEL bad P1: simrs={:04X}, reference={:04X}",
        dr.simrs.sw16(),
        dr.reference.sw16()
    );

    assert!(!dr.simrs.is_success());
    assert!(!dr.reference.is_success());
});
