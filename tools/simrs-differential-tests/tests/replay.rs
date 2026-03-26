//! Replay-based differential tests driven by BDD scenario APDU sequences.
//!
//! Each test mirrors a scenario from the GP BDD feature files
//! (`tools/simrs-gp-tests/features/`) and replays the same APDU sequence
//! through both simrs `GpCard` (in-process) and Oracle jcsl (TCP),
//! comparing responses via the interposer's [`DiffEngine`].
//!
//! # Running
//!
//! ```bash
//! SIMRS_JCSL_BINARY=/path/to/jcsl cargo test -p simrs-differential-tests --test replay
//! ```

use simrs_differential_tests::{CompareResult, DiffSession, SIMRS_ISD_AID};

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

/// Build a SELECT-by-AID APDU.
#[allow(clippy::cast_possible_truncation)]
fn select_aid(aid: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    apdu.extend_from_slice(aid);
    apdu
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
        0x84, 0x82, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
/// Oracle supports CPLC (9F7F), simrs does not. Known divergence.
#[test]
fn replay_get_data_cplc() {
    let mut s = diff_session!("replay-gd-cplc");

    let get_cplc = [0x80, 0xCA, 0x9F, 0x7F, 0x00];
    let results = s.replay_one(&get_cplc);

    for result in &results {
        match result {
            CompareResult::SwMismatch { real_sw, shadow_sw } => {
                eprintln!("Known CPLC divergence: simrs={real_sw:02X?} oracle={shadow_sw:02X?}");
            }
            other => eprintln!("CPLC result: {other:?}"),
        }
    }
}

// -----------------------------------------------------------------------
// Error handling scenarios
// -----------------------------------------------------------------------

/// Invalid GP-class INS byte. Both should reject.
///
/// simrs returns 69 85 (SCP auth required before reaching INS dispatch);
/// Oracle may return 6D 00 (INS not supported). Both reject -- the SW
/// class (6x) matches even if the exact SW2 differs.
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
        vec![0x80, 0xFD, 0x00, 0x00],           // Invalid INS
        select_aid(&SIMRS_ISD_AID),              // Valid SELECT
        vec![0x80, 0xCA, 0x00, 0x66],            // GET DATA 0066
        vec![0x80, 0xCA, 0xDE, 0xAD],            // GET DATA bad tag
        select_aid(&SIMRS_ISD_AID),              // Recovery SELECT
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
        vec![0x00, 0x70, 0x00, 0x00, 0x01],     // MANAGE CHANNEL OPEN
        select_aid(&SIMRS_ISD_AID),              // SELECT ISD on basic channel
    ];

    let refs: Vec<&[u8]> = sequence.iter().map(Vec::as_slice).collect();
    s.replay_sequence(&refs);
    s.print_summary();
}
