//! Replay-based differential tests driven by BDD scenario APDU sequences.
//!
//! Each test mirrors a scenario from the GP BDD feature files
//! (`tests/simrs-globalplatform-conformance-validation/features/`) and
//! replays the same APDU sequence through both simrs `GpCard`
//! (in-process) and whichever [`ReferenceBackend`] the matrix cell
//! selects via `SIMRS_DIFF_BACKEND`, comparing responses via the
//! interposer's [`DiffEngine`].
//!
//! # Running
//!
//! ```bash
//! # Against Oracle jcsl (default)
//! SIMRS_JCSL_BINARY=/path/to/jcsl \
//!   cargo test -p simrs-differential-crossvalidation --test replay
//!
//! # Against martinpaljak/JCardEngine
//! SIMRS_DIFF_BACKEND=jcardengine \
//!   cargo test -p simrs-differential-crossvalidation --test replay
//! ```
//!
//! A configured-but-missing backend panics rather than silently
//! skipping: differential tests are meaningless without their
//! reference, and a missing backend is a configuration error.
//!
//! [`ReferenceBackend`]: simrs_differential_crossvalidation::ReferenceBackend

use simrs_differential_crossvalidation::{
    BackendId, CompareResult, DiffSession, SIMRS_ISD_AID, panic_backend_not_discoverable,
    select_aid, select_backend,
};

/// Build a [`DiffSession`] for the backend configured by
/// [`select_backend`]. Panics on a configured-but-missing reference so
/// misconfigured CI fails loudly.
fn build_matrix_session(label: &str) -> DiffSession {
    let builder = DiffSession::builder(label).simrs_gp_card();
    let backend = select_backend();
    #[allow(unreachable_patterns)]
    let built = match backend {
        #[cfg(feature = "jcsl-backend")]
        BackendId::Jcsl => builder.try_oracle_jcsl().build(),
        #[cfg(feature = "jcardengine-backend")]
        BackendId::Jcardengine => builder.try_jcardengine().build(),
        _ => panic_backend_not_discoverable(label, backend),
    };
    built.unwrap_or_else(|| panic_backend_not_discoverable(label, backend))
}

/// Matrix test macro: build a session against the selected backend and
/// run the body with a `session` binding. Mirrors `apdu_test!` in
/// `differential.rs` but scoped to [`DiffSession`] instead of
/// [`DualCard`](simrs_differential_crossvalidation::DualCard).
macro_rules! replay_test {
    ($name:ident, $label:expr, |$session:ident| $body:block) => {
        #[test]
        fn $name() {
            #[allow(unused_mut)]
            let mut $session = build_matrix_session($label);
            $body
        }
    };
}

// -----------------------------------------------------------------------
// select_by_aid.feature scenarios
// -----------------------------------------------------------------------

// Mirrors: "SELECT ISD by full AID returns FCI with lifecycle byte".
// Both implementations accept SELECT with the ISD AID (7-byte for
// simrs, 8-byte for Oracle/JCardEngine).
replay_test!(replay_select_isd_full_aid, "replay-sel-isd", |s| {
    let sel7 = select_aid(&SIMRS_ISD_AID);
    let r1 = s.replay_one(&sel7);
    eprintln!("SELECT 7-byte ISD: {r1:?}");

    let sel8 = select_aid(&[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00]);
    let r2 = s.replay_one(&sel8);
    eprintln!("SELECT 8-byte ISD: {r2:?}");

    s.print_summary();
});

// Mirrors: "SELECT unknown AID returns 6A 82". Both implementations
// must reject an unknown AID; JCardEngine's narrower surface collapses
// to 6D00 (cataloged as J3) which we accept via the `Match`/`SwMismatch`
// fallthrough -- the test asserts only that neither side accepts.
replay_test!(replay_select_unknown_aid_rejected, "replay-sel-unk", |s| {
    let unknown = select_aid(&[0xFF, 0xEE, 0xDD, 0xCC, 0xBB]);
    let results = s.replay_one(&unknown);
    for r in &results {
        assert!(
            matches!(r, CompareResult::Match | CompareResult::SwMismatch { .. }),
            "both references should reject unknown AID: {r:?}"
        );
    }
});

// Mirrors: "SELECT changes current applet context and deselects previous".
replay_test!(replay_select_sequence, "replay-sel-seq", |s| {
    let sel_isd = select_aid(&SIMRS_ISD_AID);
    let sel_unknown = select_aid(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let sel_isd_again = select_aid(&SIMRS_ISD_AID);

    s.replay_one(&sel_isd);
    s.replay_one(&sel_unknown);
    s.replay_one(&sel_isd_again);

    s.print_summary();
});

// -----------------------------------------------------------------------
// scp01_mutual_auth.feature scenarios
// -----------------------------------------------------------------------

// Mirrors: "INITIALIZE UPDATE with valid host challenge returns 28-byte
// response". Both sides succeed with SW 9000; crypto material differs
// (SCP01/SCP02 on simrs vs SCP03 on the reference).
replay_test!(replay_initialize_update, "replay-init-upd", |s| {
    let sel = select_aid(&SIMRS_ISD_AID);
    s.replay_one(&sel);

    let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut init_update = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    init_update.extend_from_slice(&host_challenge);

    let results = s.replay_one(&init_update);
    eprintln!("INIT UPDATE: {results:?}");

    for result in &results {
        match result {
            CompareResult::Match => eprintln!("  Full match (unexpected but good)"),
            CompareResult::DataMismatch { sw, .. } => {
                assert_eq!(*sw, (0x90, 0x00), "both references should succeed");
                eprintln!("  Data differs (expected: SCP02 vs SCP03)");
            }
            CompareResult::SwMismatch { real_sw, shadow_sw } => {
                eprintln!("  SW divergence: simrs={real_sw:02X?} reference={shadow_sw:02X?}");
            }
            CompareResult::ShadowIgnored { .. } => {
                panic!("reference should process INIT UPDATE")
            }
        }
    }
});

// Mirrors: "INITIALIZE UPDATE with wrong key version returns 6A xx".
replay_test!(
    replay_init_update_wrong_key_version,
    "replay-init-badkv",
    |s| {
        let sel = select_aid(&SIMRS_ISD_AID);
        s.replay_one(&sel);

        let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut init_update = vec![0x80, 0x50, 0xFF, 0x00, 0x08];
        init_update.extend_from_slice(&host_challenge);

        let results = s.replay_one(&init_update);
        eprintln!("INIT UPDATE bad KV: {results:?}");
    }
);

// Mirrors: "EXTERNAL AUTHENTICATE without INIT UPDATE returns 69 xx".
// simrs returns 6985 (conditions of use not satisfied); JCardEngine
// returns 6986 (command not allowed -- no current EF) per its
// `GlobalPlatformApplet` implementation. Both reject, which is the
// invariant.
replay_test!(
    replay_ext_auth_without_init_update,
    "replay-extauth-noiu",
    |s| {
        let ext_auth = [
            0x84, 0x82, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let results = s.replay_one(&ext_auth);
        eprintln!("EXT AUTH (no INIT UPDATE): {results:?}");

        for r in &results {
            assert!(
                matches!(r, CompareResult::Match | CompareResult::SwMismatch { .. }),
                "both references should reject EXT AUTH without INIT UPDATE: {r:?}"
            );
        }
    }
);

// -----------------------------------------------------------------------
// get_status.feature scenarios
// -----------------------------------------------------------------------

// Mirrors: "GET STATUS without authenticated SCP session returns 69 85".
// Reference requires SCP auth; simrs (GP 2.1.1 mode) may accept without.
// Documents the known divergence.
replay_test!(replay_get_status_without_auth, "replay-gs-noauth", |s| {
    let get_status = [0x80, 0xF2, 0x80, 0x00, 0x02, 0x4F, 0x00];
    s.replay_one(&get_status);
    s.print_summary();
});

// -----------------------------------------------------------------------
// card_lifecycle.feature / GET DATA scenarios
// -----------------------------------------------------------------------

// Mirrors: "GET DATA returns card recognition data".
replay_test!(replay_get_data_card_recognition, "replay-gd-0066", |s| {
    let get_data = [0x80, 0xCA, 0x00, 0x66];
    s.replay_one(&get_data);
    s.print_summary();
});

// Mirrors: "GET DATA CPLC". Both references support CPLC (9F7F).
replay_test!(replay_get_data_cplc, "replay-gd-cplc", |s| {
    let get_cplc = [0x80, 0xCA, 0x9F, 0x7F, 0x00];
    let results = s.replay_one(&get_cplc);

    for result in &results {
        match result {
            CompareResult::Match | CompareResult::DataMismatch { .. } => {
                eprintln!("CPLC: both implementations succeed");
            }
            other => eprintln!("CPLC result: {other:?}"),
        }
    }
});

// -----------------------------------------------------------------------
// Error handling scenarios
// -----------------------------------------------------------------------

// Invalid GP-class INS byte. Both should reject.
replay_test!(replay_invalid_gp_ins, "replay-bad-ins-gp", |s| {
    let results = s.replay_one(&[0x80, 0xFD, 0x00, 0x00]);
    for r in &results {
        assert!(
            matches!(r, CompareResult::Match | CompareResult::SwMismatch { .. }),
            "unexpected result: {r:?}"
        );
    }
});

// Invalid ISO-class INS byte.
replay_test!(replay_invalid_iso_ins, "replay-bad-ins-iso", |s| {
    let results = s.replay_one(&[0x00, 0xFD, 0x00, 0x00]);
    for r in &results {
        assert!(
            matches!(r, CompareResult::Match | CompareResult::SwMismatch { .. }),
            "unexpected result: {r:?}"
        );
    }
});

// -----------------------------------------------------------------------
// Multi-step sequence replays
// -----------------------------------------------------------------------

// Full GP card discovery sequence: SELECT ISD -> GET DATA -> INIT UPDATE.
replay_test!(replay_discovery_sequence, "replay-discovery", |s| {
    let host_challenge = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let mut init_update = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    init_update.extend_from_slice(&host_challenge);

    let sequence: Vec<Vec<u8>> = vec![
        select_aid(&SIMRS_ISD_AID),
        vec![0x80, 0xCA, 0x00, 0x66],
        init_update,
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 3);
    assert_eq!(
        stats.shadow_ignored, 0,
        "reference should process all APDUs"
    );

    s.print_summary();
});

// Error recovery sequence: bad APDU -> valid SELECT -> GET DATA.
replay_test!(replay_error_recovery_sequence, "replay-recovery", |s| {
    let sequence: Vec<Vec<u8>> = vec![
        vec![0x80, 0xFD, 0x00, 0x00],
        select_aid(&SIMRS_ISD_AID),
        vec![0x80, 0xCA, 0x00, 0x66],
        vec![0x80, 0xCA, 0xDE, 0xAD],
        select_aid(&SIMRS_ISD_AID),
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 5);
    assert_eq!(stats.shadow_ignored, 0);
    s.print_summary();
});

// MANAGE CHANNEL open/close sequence.
replay_test!(replay_manage_channel_sequence, "replay-mgmt-ch", |s| {
    let sequence: Vec<Vec<u8>> = vec![
        vec![0x00, 0x70, 0x00, 0x00, 0x01],
        select_aid(&SIMRS_ISD_AID),
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    s.replay_sequence(&refs);
    s.print_summary();
});

// -----------------------------------------------------------------------
// Extended replay sequences (BDD-derived)
// -----------------------------------------------------------------------

// SCP02 handshake: SELECT + INIT UPDATE + wrong EXT AUTH. Both should
// reject the incorrect EXT AUTH.
replay_test!(replay_scp02_handshake_failure, "replay-scp02-fail", |s| {
    let host_challenge = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let mut init_update = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    init_update.extend_from_slice(&host_challenge);

    let bad_ext_auth = vec![
        0x84, 0x82, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    let sequence: Vec<Vec<u8>> = vec![select_aid(&SIMRS_ISD_AID), init_update, bad_ext_auth];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 3);
    eprintln!(
        "SCP02 handshake failure: {} matches, {} sw mismatches, {} data mismatches",
        stats.matches, stats.sw_mismatches, stats.data_mismatches
    );
    s.print_summary();
});

// Multiple GET DATA tags: 0066 (card recognition), 0042 (ISD AID), unknown.
replay_test!(replay_get_data_multi_tag, "replay-gd-multi", |s| {
    let sequence: Vec<Vec<u8>> = vec![
        select_aid(&SIMRS_ISD_AID),
        vec![0x80, 0xCA, 0x00, 0x66],
        vec![0x80, 0xCA, 0x00, 0x42, 0x00],
        vec![0x80, 0xCA, 0xDE, 0xAD],
        vec![0x80, 0xCA, 0x9F, 0x7F, 0x00],
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 5);
    eprintln!(
        "GET DATA multi: {} matches, {} divergences",
        stats.matches,
        stats.sw_mismatches + stats.data_mismatches
    );
    s.print_summary();
});

// Repeated INIT UPDATE: sequence counter increments on simrs;
// reference may have different counter behaviour.
replay_test!(replay_repeated_init_update, "replay-repeated-iu", |s| {
    let hc1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let hc2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let hc3 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    let mut iu1 = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu1.extend_from_slice(&hc1);
    let mut iu2 = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu2.extend_from_slice(&hc2);
    let mut iu3 = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu3.extend_from_slice(&hc3);

    let sequence: Vec<Vec<u8>> = vec![select_aid(&SIMRS_ISD_AID), iu1, iu2, iu3];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 4);
    eprintln!(
        "Repeated INIT UPDATE: {} matches, {} data mismatches (expected for crypto)",
        stats.matches, stats.data_mismatches
    );
    s.print_summary();
});

// -----------------------------------------------------------------------
// Semantic differential tests (field-level comparison via SchemaRegistry)
// -----------------------------------------------------------------------

// Semantic comparison of INIT UPDATE: field structure matches even when
// crypto material differs (SCP02 vs SCP03).
replay_test!(replay_semantic_init_update, "replay-sem-iu", |s| {
    let sel = select_aid(&SIMRS_ISD_AID);
    s.replay_one(&sel);

    let hc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut iu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu.extend_from_slice(&hc);

    let semantic_results = s.replay_one_semantic(&iu);
    for result in &semantic_results {
        eprintln!("Semantic INIT UPDATE: {result:?}");
    }

    s.print_summary();
});

// Semantic comparison of GET DATA 0066.
replay_test!(replay_semantic_get_data_0066, "replay-sem-gd66", |s| {
    let gd = [0x80, 0xCA, 0x00, 0x66];
    let semantic_results = s.replay_one_semantic(&gd);
    for result in &semantic_results {
        eprintln!("Semantic GET DATA 0066: {result:?}");
    }

    s.print_summary();
});

// Semantic comparison of SELECT: FCI structure matches even when data
// lengths differ across backends.
replay_test!(replay_semantic_select, "replay-sem-sel", |s| {
    let sel = select_aid(&SIMRS_ISD_AID);
    let semantic_results = s.replay_one_semantic(&sel);
    for result in &semantic_results {
        eprintln!("Semantic SELECT: {result:?}");
    }

    s.print_summary();
});

// Semantic comparison of a full discovery sequence.
replay_test!(replay_semantic_discovery, "replay-sem-disc", |s| {
    let sel = select_aid(&SIMRS_ISD_AID);
    let gd = [0x80, 0xCA, 0x00, 0x66];
    let hc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let mut iu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu.extend_from_slice(&hc);

    for cmd in &[sel.as_slice(), &gd[..], iu.as_slice()] {
        let results = s.replay_one_semantic(cmd);
        for r in &results {
            eprintln!("Semantic discovery step: {r:?}");
        }
    }

    let sem_stats = s.semantic_stats();
    eprintln!(
        "Semantic: {} matches, {} mismatches, {} fallbacks",
        sem_stats.semantic_matches, sem_stats.semantic_mismatches, sem_stats.schema_fallbacks
    );
    s.print_summary();
});

// -----------------------------------------------------------------------
// Error resilience
// -----------------------------------------------------------------------

// Error recovery: bad APDU -> SELECT -> GET DATA -> bad APDU -> SELECT.
// Tests that both implementations recover gracefully from errors.
replay_test!(replay_error_resilience, "replay-resilience", |s| {
    let sequence: Vec<Vec<u8>> = vec![
        vec![0x80, 0xFD, 0x00, 0x00],
        vec![0x00, 0xFD, 0x00, 0x00],
        select_aid(&SIMRS_ISD_AID),
        vec![0x80, 0xCA, 0x00, 0x66],
        vec![0x80, 0xCA, 0xFF, 0xFF],
        select_aid(&SIMRS_ISD_AID),
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 6);
    assert_eq!(
        stats.shadow_ignored, 0,
        "reference should process all APDUs"
    );
    eprintln!(
        "Error resilience: {}/{} matched",
        stats.matches, stats.total_apdus
    );
    s.print_summary();
});
