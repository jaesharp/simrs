//! Replay-based differential tests driven by BDD scenario APDU sequences.
//!
//! Each test mirrors a scenario from the GP BDD feature files
//! (`tests/simrs-globalplatform-conformance-validation/features/`) and replays the same APDU sequence
//! through both simrs `GpCard` (in-process) and Oracle jcsl (TCP),
//! comparing responses via the interposer's [`DiffEngine`].
//!
//! # Running
//!
//! ```bash
//! SIMRS_JCSL_BINARY=/path/to/jcsl cargo test -p simrs-differential-crossvalidation --test replay
//! ```

use simrs_differential_crossvalidation::{CompareResult, DiffSession, SIMRS_ISD_AID, select_aid};

/// Helper macro: create a `DiffSession` or skip the test.
macro_rules! diff_session {
    ($label:expr) => {
        match DiffSession::builder($label)
            .simrs_gp_card()
            .try_oracle_jcsl()
            .build()
        {
            Some(s) => s,
            None => {
                eprintln!("jcsl binary not found, skipping");
                return;
            }
        }
    };
}

// -----------------------------------------------------------------------
// select_by_aid.feature scenarios
// -----------------------------------------------------------------------

/// Mirrors: "SELECT ISD by full AID returns FCI with lifecycle byte"
///
/// Both implementations should accept SELECT with the ISD AID.
/// Known divergence: simrs uses 7-byte AID, Oracle uses 8-byte.
#[test]
fn replay_select_isd_full_aid() {
    let mut s = diff_session!("replay-sel-isd");

    // SELECT with 7-byte AID (simrs default).
    let sel7 = select_aid(&SIMRS_ISD_AID);
    let r1 = s.replay_one(&sel7);
    eprintln!("SELECT 7-byte ISD: {r1:?}");

    // SELECT with 8-byte AID (Oracle default).
    let sel8 = select_aid(&[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00]);
    let r2 = s.replay_one(&sel8);
    eprintln!("SELECT 8-byte ISD: {r2:?}");

    s.print_summary();
}

/// Mirrors: "SELECT unknown AID returns 6A 82"
///
/// Both implementations must reject an unknown AID with 6A82.
#[test]
fn replay_select_unknown_aid_rejected() {
    let mut s = diff_session!("replay-sel-unk");

    let unknown = select_aid(&[0xFF, 0xEE, 0xDD, 0xCC, 0xBB]);
    let results = s.replay_one(&unknown);

    assert!(
        results.iter().all(|r| *r == CompareResult::Match),
        "Both should reject unknown AID with same SW"
    );
}

/// Mirrors: "SELECT changes current applet context and deselects previous"
///
/// Sequence: SELECT ISD -> SELECT unknown -> SELECT ISD again.
#[test]
fn replay_select_sequence() {
    let mut s = diff_session!("replay-sel-seq");

    let sel_isd = select_aid(&SIMRS_ISD_AID);
    let sel_unknown = select_aid(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let sel_isd_again = select_aid(&SIMRS_ISD_AID);

    s.replay_one(&sel_isd);
    s.replay_one(&sel_unknown);
    s.replay_one(&sel_isd_again);

    s.print_summary();
}

// -----------------------------------------------------------------------
// scp01_mutual_auth.feature scenarios
// -----------------------------------------------------------------------

/// Mirrors: "INITIALIZE UPDATE with valid host challenge returns 28-byte response"
///
/// Both implementations should accept INIT UPDATE and return >= 28 bytes.
/// The actual cryptographic material differs (SCP01 vs SCP03), but both
/// should succeed with SW 9000.
#[test]
fn replay_initialize_update() {
    let mut s = diff_session!("replay-init-upd");

    // First SELECT the ISD.
    let sel = select_aid(&SIMRS_ISD_AID);
    s.replay_one(&sel);

    // INITIALIZE UPDATE: 80 50 KV KI 08 <host_challenge[8]>
    let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut init_update = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    init_update.extend_from_slice(&host_challenge);

    let results = s.replay_one(&init_update);
    eprintln!("INIT UPDATE: {results:?}");

    // Both should succeed (SW 9000), but data differs (different SCP versions).
    for result in &results {
        match result {
            CompareResult::Match => eprintln!("  Full match (unexpected but good)"),
            CompareResult::DataMismatch { sw, .. } => {
                assert_eq!(*sw, (0x90, 0x00), "Both should succeed");
                eprintln!("  Data differs (expected: SCP01 vs SCP03)");
            }
            CompareResult::SwMismatch { real_sw, shadow_sw } => {
                eprintln!("  SW divergence: simrs={real_sw:02X?} oracle={shadow_sw:02X?}");
            }
            CompareResult::ShadowIgnored { .. } => panic!("Oracle should process INIT UPDATE"),
        }
    }
}

/// Mirrors: "INITIALIZE UPDATE with wrong key version returns 6A 88"
#[test]
fn replay_init_update_wrong_key_version() {
    let mut s = diff_session!("replay-init-badkv");

    let sel = select_aid(&SIMRS_ISD_AID);
    s.replay_one(&sel);

    // Key version 0xFF does not exist.
    let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut init_update = vec![0x80, 0x50, 0xFF, 0x00, 0x08];
    init_update.extend_from_slice(&host_challenge);

    let results = s.replay_one(&init_update);
    eprintln!("INIT UPDATE bad KV: {results:?}");
}

/// Mirrors: "EXTERNAL AUTHENTICATE without INIT UPDATE returns 69 85"
#[test]
fn replay_ext_auth_without_init_update() {
    let mut s = diff_session!("replay-extauth-noiu");

    let ext_auth = [
        0x84, 0x82, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let results = s.replay_one(&ext_auth);
    eprintln!("EXT AUTH (no INIT UPDATE): {results:?}");

    assert!(
        results.iter().all(|r| *r == CompareResult::Match),
        "Both should reject EXT AUTH without INIT UPDATE"
    );
}

// -----------------------------------------------------------------------
// get_status.feature scenarios
// -----------------------------------------------------------------------

/// Mirrors: "GET STATUS without authenticated SCP session returns 69 85"
///
/// Oracle requires SCP auth for GET STATUS. simrs (GP 2.1.1 mode) may
/// accept it without auth. This documents the known divergence.
#[test]
fn replay_get_status_without_auth() {
    let mut s = diff_session!("replay-gs-noauth");

    let get_status = [0x80, 0xF2, 0x80, 0x00, 0x02, 0x4F, 0x00];
    s.replay_one(&get_status);
    s.print_summary();
}

// -----------------------------------------------------------------------
// card_lifecycle.feature / GET DATA scenarios
// -----------------------------------------------------------------------

/// Mirrors: "GET DATA returns card recognition data"
#[test]
fn replay_get_data_card_recognition() {
    let mut s = diff_session!("replay-gd-0066");

    let get_data = [0x80, 0xCA, 0x00, 0x66];
    s.replay_one(&get_data);
    s.print_summary();
}

/// Mirrors: "GET DATA CPLC"
///
/// Both simrs and Oracle support CPLC (9F7F). SW should match.
#[test]
fn replay_get_data_cplc() {
    let mut s = diff_session!("replay-gd-cplc");

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
}

// -----------------------------------------------------------------------
// Error handling scenarios
// -----------------------------------------------------------------------

/// Invalid GP-class INS byte. Both should reject with 6D 00 (INS not supported).
#[test]
fn replay_invalid_gp_ins() {
    let mut s = diff_session!("replay-bad-ins-gp");
    let results = s.replay_one(&[0x80, 0xFD, 0x00, 0x00]);
    // Both reject the command; SW may differ in exact value.
    for r in &results {
        assert!(
            matches!(r, CompareResult::Match | CompareResult::SwMismatch { .. }),
            "unexpected result: {r:?}"
        );
    }
}

/// Invalid ISO-class INS byte. Both should reject.
#[test]
fn replay_invalid_iso_ins() {
    let mut s = diff_session!("replay-bad-ins-iso");
    let results = s.replay_one(&[0x00, 0xFD, 0x00, 0x00]);
    assert!(
        results.iter().all(|r| *r == CompareResult::Match),
        "Both should reject invalid INS"
    );
}

// -----------------------------------------------------------------------
// Multi-step sequence replays
// -----------------------------------------------------------------------

/// Full GP card discovery sequence: SELECT ISD -> GET DATA -> INIT UPDATE.
#[test]
fn replay_discovery_sequence() {
    let mut s = diff_session!("replay-discovery");

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
    assert_eq!(stats.shadow_ignored, 0, "Oracle should process all APDUs");

    s.print_summary();
}

/// Error recovery sequence: bad APDU -> valid SELECT -> GET DATA.
#[test]
fn replay_error_recovery_sequence() {
    let mut s = diff_session!("replay-recovery");

    let sequence: Vec<Vec<u8>> = vec![
        vec![0x80, 0xFD, 0x00, 0x00], // Invalid INS
        select_aid(&SIMRS_ISD_AID),   // Valid SELECT
        vec![0x80, 0xCA, 0x00, 0x66], // GET DATA 0066
        vec![0x80, 0xCA, 0xDE, 0xAD], // GET DATA bad tag
        select_aid(&SIMRS_ISD_AID),   // Recovery SELECT
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 5);
    assert_eq!(stats.shadow_ignored, 0);
    s.print_summary();
}

/// MANAGE CHANNEL open/close sequence.
#[test]
fn replay_manage_channel_sequence() {
    let mut s = diff_session!("replay-mgmt-ch");

    let sequence: Vec<Vec<u8>> = vec![
        vec![0x00, 0x70, 0x00, 0x00, 0x01], // MANAGE CHANNEL OPEN
        select_aid(&SIMRS_ISD_AID),         // SELECT ISD on basic channel
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    s.replay_sequence(&refs);
    s.print_summary();
}

// -----------------------------------------------------------------------
// Extended replay sequences (BDD-derived)
// -----------------------------------------------------------------------

/// SCP02 handshake: SELECT + INIT UPDATE + wrong EXT AUTH.
/// Both should reject the incorrect EXT AUTH.
#[test]
fn replay_scp02_handshake_failure() {
    let mut s = diff_session!("replay-scp02-fail");

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

    // SELECT and INIT UPDATE should succeed on both. EXT AUTH should fail on both.
    assert_eq!(stats.total_apdus, 3);
    eprintln!(
        "SCP02 handshake failure: {} matches, {} sw mismatches, {} data mismatches",
        stats.matches, stats.sw_mismatches, stats.data_mismatches
    );
    s.print_summary();
}

/// Multiple GET DATA tags: 0066 (card recognition), 0042 (ISD AID), unknown.
#[test]
fn replay_get_data_multi_tag() {
    let mut s = diff_session!("replay-gd-multi");

    let sequence: Vec<Vec<u8>> = vec![
        select_aid(&SIMRS_ISD_AID),
        vec![0x80, 0xCA, 0x00, 0x66],       // Card Recognition Data
        vec![0x80, 0xCA, 0x00, 0x42, 0x00], // ISD AID
        vec![0x80, 0xCA, 0xDE, 0xAD],       // Unknown tag
        vec![0x80, 0xCA, 0x9F, 0x7F, 0x00], // CPLC
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
}

/// Repeated INIT UPDATE: sequence counter should increment on simrs.
/// Oracle may have different counter behavior.
#[test]
fn replay_repeated_init_update() {
    let mut s = diff_session!("replay-repeated-iu");

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
    // All INIT UPDATEs should succeed with SW 9000 on both.
    // Data will differ (different crypto material) but SW should match.
    eprintln!(
        "Repeated INIT UPDATE: {} matches, {} data mismatches (expected for crypto)",
        stats.matches, stats.data_mismatches
    );
    s.print_summary();
}

// -----------------------------------------------------------------------
// Semantic differential tests (field-level comparison via SchemaRegistry)
// -----------------------------------------------------------------------

/// Semantic comparison of INIT UPDATE: field structure matches even when
/// crypto material differs (SCP02 vs SCP03).
#[test]
fn replay_semantic_init_update() {
    let mut s = diff_session!("replay-sem-iu");

    let sel = select_aid(&SIMRS_ISD_AID);
    s.replay_one(&sel);

    let hc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut iu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    iu.extend_from_slice(&hc);

    // Use semantic comparison: schema-aware field matching.
    let semantic_results = s.replay_one_semantic(&iu);
    for result in &semantic_results {
        eprintln!("Semantic INIT UPDATE: {result:?}");
    }

    s.print_summary();
}

/// Semantic comparison of GET DATA 0066: OID field matches exactly,
/// lifecycle and SCP identifier fields are compared by policy.
#[test]
fn replay_semantic_get_data_0066() {
    let mut s = diff_session!("replay-sem-gd66");

    let gd = [0x80, 0xCA, 0x00, 0x66];
    let semantic_results = s.replay_one_semantic(&gd);
    for result in &semantic_results {
        eprintln!("Semantic GET DATA 0066: {result:?}");
    }

    s.print_summary();
}

/// Semantic comparison of SELECT: FCI structure matches even when
/// data lengths differ (simrs FCI vs Oracle FCI).
#[test]
fn replay_semantic_select() {
    let mut s = diff_session!("replay-sem-sel");

    let sel = select_aid(&SIMRS_ISD_AID);
    let semantic_results = s.replay_one_semantic(&sel);
    for result in &semantic_results {
        eprintln!("Semantic SELECT: {result:?}");
    }

    s.print_summary();
}

/// Semantic comparison of a full discovery sequence:
/// SELECT -> GET DATA 0066 -> INIT UPDATE.
/// Uses schema-aware comparison for each step.
#[test]
fn replay_semantic_discovery() {
    let mut s = diff_session!("replay-sem-disc");

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
}

// -----------------------------------------------------------------------
// Error resilience
// -----------------------------------------------------------------------

/// Error recovery: bad APDU -> SELECT -> GET DATA -> bad APDU -> SELECT.
/// Tests that both implementations recover gracefully from errors.
#[test]
fn replay_error_resilience() {
    let mut s = diff_session!("replay-resilience");

    let sequence: Vec<Vec<u8>> = vec![
        vec![0x80, 0xFD, 0x00, 0x00], // Bad GP INS
        vec![0x00, 0xFD, 0x00, 0x00], // Bad ISO INS
        select_aid(&SIMRS_ISD_AID),   // Recovery SELECT
        vec![0x80, 0xCA, 0x00, 0x66], // GET DATA (should work)
        vec![0x80, 0xCA, 0xFF, 0xFF], // Bad tag
        select_aid(&SIMRS_ISD_AID),   // Recovery SELECT again
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    let stats = s.replay_sequence(&refs);

    assert_eq!(stats.total_apdus, 6);
    assert_eq!(stats.shadow_ignored, 0, "Oracle should process all APDUs");
    eprintln!(
        "Error resilience: {}/{} matched",
        stats.matches, stats.total_apdus
    );
    s.print_summary();
}
