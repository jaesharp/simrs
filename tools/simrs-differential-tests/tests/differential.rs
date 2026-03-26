//! Differential tests: simrs `GpCard` vs Oracle jcsl reference simulator.
//!
//! Each test sends identical APDU sequences to both implementations and
//! compares the results. The focus is on status words and response
//! structure rather than exact byte-for-byte matching, since the two
//! implementations target different GP specification versions:
//!
//! - simrs: GP 2.1.1, SCP01/SCP02 (DES3 keys)
//! - Oracle jcsl: GP 2.3, SCP03 (AES-128 keys)
//!
//! # Running
//!
//! ```bash
//! SIMRS_JCSL_BINARY=/path/to/jcsl cargo test -p simrs-differential-tests
//! ```

use simrs_card_api::{SimEvent, SimResponse};
use simrs_differential_tests::{try_create_dual_card, ORACLE_ISD_AID, SIMRS_ISD_AID};

/// Helper macro: skip if `SIMRS_JCSL_BINARY` is not set.
macro_rules! dual_card {
    ($label:expr) => {
        match try_create_dual_card($label) {
            Some(dc) => dc,
            None => {
                eprintln!("jcsl binary not found, skipping");
                return;
            }
        }
    };
}

// -----------------------------------------------------------------------
// Power-on / ATR
// -----------------------------------------------------------------------

#[test]
fn power_on_both_return_valid_atr() {
    let mut dc = dual_card!("atr");
    let (simrs_atr, oracle_atr) = dc.power_on();

    // Both ATRs must start with 0x3B (direct convention) or 0x3F (inverse).
    assert!(
        simrs_atr[0] == 0x3B || simrs_atr[0] == 0x3F,
        "simrs ATR initial byte: 0x{:02X}",
        simrs_atr[0]
    );
    assert!(
        oracle_atr[0] == 0x3B || oracle_atr[0] == 0x3F,
        "Oracle ATR initial byte: 0x{:02X}",
        oracle_atr[0]
    );

    eprintln!("simrs  ATR: {simrs_atr:02x?}");
    eprintln!("Oracle ATR: {oracle_atr:02x?}");

    // ATRs will differ (different card profiles), but both must be non-empty.
    assert!(!simrs_atr.is_empty());
    assert!(!oracle_atr.is_empty());
}

// -----------------------------------------------------------------------
// SELECT by AID
// -----------------------------------------------------------------------

/// Build a SELECT-by-AID APDU: 00 A4 04 00 <Lc> <AID>.
#[allow(clippy::cast_possible_truncation)]
fn select_aid(aid: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    apdu.extend_from_slice(aid);
    apdu
}

#[test]
fn select_isd_simrs_aid_on_both() {
    let mut dc = dual_card!("sel-simrs-aid");
    dc.power_on();

    // SELECT with simrs's 7-byte ISD AID.
    let apdu = select_aid(&SIMRS_ISD_AID);
    let dr = dc.exchange(&apdu);

    eprintln!("SELECT ISD (7-byte) simrs:  {:?}", dr.simrs);
    eprintln!("SELECT ISD (7-byte) Oracle: {:?}", dr.oracle);

    // simrs must succeed.
    assert!(
        dr.simrs.is_success(),
        "simrs SELECT ISD (7-byte) failed: {:02X}{:02X}",
        dr.simrs.sw[0],
        dr.simrs.sw[1]
    );

    // Oracle may succeed (prefix match) or return 6A82 (exact match only).
    // Both are acceptable; we document the divergence.
    eprintln!(
        "SW match: {} (simrs={:04X}, oracle={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );
}

#[test]
fn select_isd_oracle_aid_on_both() {
    let mut dc = dual_card!("sel-oracle-aid");
    dc.power_on();

    // SELECT with Oracle's 8-byte ISD AID.
    let apdu = select_aid(&ORACLE_ISD_AID);
    let dr = dc.exchange(&apdu);

    eprintln!("SELECT ISD (8-byte) simrs:  {:?}", dr.simrs);
    eprintln!("SELECT ISD (8-byte) Oracle: {:?}", dr.oracle);

    // Oracle must succeed.
    assert!(
        dr.oracle.is_success(),
        "Oracle SELECT ISD (8-byte) failed: {:02X}{:02X}",
        dr.oracle.sw[0],
        dr.oracle.sw[1]
    );

    // simrs may return 6A82 (exact match) since its ISD is 7 bytes.
    eprintln!(
        "SW match: {} (simrs={:04X}, oracle={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );
}

#[test]
fn select_unknown_aid_both_reject() {
    let mut dc = dual_card!("sel-unknown");
    dc.power_on();

    let unknown = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB];
    let apdu = select_aid(&unknown);
    let dr = dc.exchange(&apdu);

    eprintln!("SELECT unknown simrs:  {:?}", dr.simrs);
    eprintln!("SELECT unknown Oracle: {:?}", dr.oracle);

    // Both should reject with 6A82 (file/app not found) or similar 6Axx.
    assert_eq!(
        dr.simrs.sw[0], 0x6A,
        "simrs: expected 6Axx for unknown AID, got {:02X}{:02X}",
        dr.simrs.sw[0], dr.simrs.sw[1]
    );
    assert_eq!(
        dr.oracle.sw[0], 0x6A,
        "Oracle: expected 6Axx for unknown AID, got {:02X}{:02X}",
        dr.oracle.sw[0], dr.oracle.sw[1]
    );

    // Ideally both return 6A82.
    eprintln!(
        "SW match: {} (simrs={:04X}, oracle={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );
}

// -----------------------------------------------------------------------
// GET DATA
// -----------------------------------------------------------------------

#[test]
fn get_data_card_recognition_0066() {
    let mut dc = dual_card!("get-data-66");
    dc.power_on();

    // GET DATA tag 0066 (Card Recognition Data).
    // CLA=80 INS=CA P1=00 P2=66
    let apdu = [0x80, 0xCA, 0x00, 0x66];
    let dr = dc.exchange(&apdu);

    eprintln!("GET DATA 0066 simrs:  {:?}", dr.simrs);
    eprintln!("GET DATA 0066 Oracle: {:?}", dr.oracle);

    // simrs should succeed (it implements tag 0066).
    assert!(
        dr.simrs.is_success(),
        "simrs GET DATA 0066 failed: {:04X}",
        dr.simrs.sw16()
    );

    // Oracle should also support card recognition data.
    // It may require authentication first (returning 6982 = security not satisfied)
    // or it may succeed.
    eprintln!(
        "SW match: {} (simrs={:04X}, oracle={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );

    // If both succeed, verify they both start with tag 0x66.
    if dr.simrs.is_success() && !dr.simrs.data.is_empty() {
        assert_eq!(
            dr.simrs.data[0], 0x66,
            "simrs: card recognition data should start with tag 66"
        );
    }
    if dr.oracle.is_success() && !dr.oracle.data.is_empty() {
        assert_eq!(
            dr.oracle.data[0], 0x66,
            "Oracle: card recognition data should start with tag 66"
        );
    }
}

#[test]
fn get_data_cplc_9f7f() {
    let mut dc = dual_card!("get-data-cplc");
    dc.power_on();

    // GET DATA tag 9F7F (CPLC - Card Production Life Cycle).
    let apdu = [0x80, 0xCA, 0x9F, 0x7F, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("GET DATA CPLC simrs:  {:?}", dr.simrs);
    eprintln!("GET DATA CPLC Oracle: {:?}", dr.oracle);

    // Oracle supports CPLC. simrs does not (returns 6A88 = referenced data not found).
    // This is a known divergence.
    eprintln!(
        "CPLC divergence: simrs={:04X}, oracle={:04X}",
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );
}

#[test]
fn get_data_unknown_tag_both_reject() {
    let mut dc = dual_card!("get-data-bad");
    dc.power_on();

    // GET DATA with a nonsense tag.
    let apdu = [0x80, 0xCA, 0xDE, 0xAD];
    let dr = dc.exchange(&apdu);

    eprintln!("GET DATA 0xDEAD simrs:  {:?}", dr.simrs);
    eprintln!("GET DATA 0xDEAD Oracle: {:?}", dr.oracle);

    // Neither should succeed.
    assert!(
        !dr.simrs.is_success(),
        "simrs should reject unknown GET DATA tag"
    );
    assert!(
        !dr.oracle.is_success(),
        "Oracle should reject unknown GET DATA tag"
    );

    // Both should return a 6Axx or 6Dxx error class.
    eprintln!(
        "SW match: {} (simrs={:04X}, oracle={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );
}

// -----------------------------------------------------------------------
// Error handling: invalid INS
// -----------------------------------------------------------------------

#[test]
fn invalid_ins_both_reject() {
    let mut dc = dual_card!("bad-ins");
    dc.power_on();

    // Send a GP-class APDU with a non-existent INS byte.
    let apdu = [0x80, 0xFD, 0x00, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("Invalid INS simrs:  {:?}", dr.simrs);
    eprintln!("Invalid INS Oracle: {:?}", dr.oracle);

    // Both should return 6D00 (INS not supported) or similar error.
    assert!(!dr.simrs.is_success(), "simrs should reject invalid INS");
    assert!(!dr.oracle.is_success(), "Oracle should reject invalid INS");

    eprintln!(
        "SW match: {} (simrs={:04X}, oracle={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );
}

#[test]
fn iso_class_invalid_ins_both_reject() {
    let mut dc = dual_card!("iso-bad-ins");
    dc.power_on();

    // ISO interindustry class with an unrecognized INS.
    let apdu = [0x00, 0xFD, 0x00, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("ISO invalid INS simrs:  {:?}", dr.simrs);
    eprintln!("ISO invalid INS Oracle: {:?}", dr.oracle);

    assert!(
        !dr.simrs.is_success(),
        "simrs should reject invalid INS in ISO class"
    );
    assert!(
        !dr.oracle.is_success(),
        "Oracle should reject invalid INS in ISO class"
    );

    eprintln!(
        "SW match: {} (simrs={:04X}, oracle={:04X})",
        dr.sw_match(),
        dr.simrs.sw16(),
        dr.oracle.sw16()
    );
}

// -----------------------------------------------------------------------
// INITIALIZE UPDATE (structure comparison only)
// -----------------------------------------------------------------------

#[test]
fn initialize_update_both_respond() {
    let mut dc = dual_card!("init-update");
    dc.power_on();

    // First SELECT the ISD on both (use each card's own AID).
    let sel_simrs = select_aid(&SIMRS_ISD_AID);
    let _ = dc.simrs.process(SimEvent::Apdu(&sel_simrs));

    let sel_oracle = select_aid(&ORACLE_ISD_AID);
    let _ = dc.oracle.transmit_apdu(&sel_oracle);

    // INITIALIZE UPDATE: 80 50 00 00 08 <host_challenge[8]>
    let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut apdu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    apdu.extend_from_slice(&host_challenge);

    let dr = dc.exchange(&apdu);

    eprintln!("INIT UPDATE simrs:  {:?}", dr.simrs);
    eprintln!("INIT UPDATE Oracle: {:?}", dr.oracle);

    // Both should succeed.
    assert!(
        dr.simrs.is_success(),
        "simrs INITIALIZE UPDATE failed: {:04X}",
        dr.simrs.sw16()
    );
    assert!(
        dr.oracle.is_success(),
        "Oracle INITIALIZE UPDATE failed: {:04X}",
        dr.oracle.sw16()
    );

    // simrs (SCP01/02) returns 28 bytes: key_div[10] + key_info[2] + seq_ctr[2] + card_chal[6] + card_crypto[8]
    // Oracle (SCP03) returns 28+ bytes with different structure.
    eprintln!(
        "Response lengths: simrs={}, oracle={}",
        dr.simrs.data.len(),
        dr.oracle.data.len()
    );

    // Both should return at least 28 bytes.
    assert!(
        dr.simrs.data.len() >= 28,
        "simrs INIT UPDATE response too short: {} bytes",
        dr.simrs.data.len()
    );
    assert!(
        dr.oracle.data.len() >= 28,
        "Oracle INIT UPDATE response too short: {} bytes",
        dr.oracle.data.len()
    );

    // Key diversification data should start at offset 0 (10 bytes).
    let simrs_kdiv = &dr.simrs.data[..10];
    let oracle_kdiv = &dr.oracle.data[..10];
    eprintln!("simrs  key diversification: {simrs_kdiv:02x?}");
    eprintln!("Oracle key diversification: {oracle_kdiv:02x?}");
}

// -----------------------------------------------------------------------
// GET STATUS (ISD)
// -----------------------------------------------------------------------

#[test]
fn get_status_isd_both_respond() {
    let mut dc = dual_card!("get-status");
    dc.power_on();

    // GET STATUS P1=0x80 (ISD), no secure messaging.
    // Per GP 2.1.1 clause 9.4, GET STATUS requires an authenticated SCP
    // session. Both simrs and Oracle should reject this.
    let apdu = [0x80, 0xF2, 0x80, 0x00];
    let dr = dc.exchange(&apdu);

    eprintln!("GET STATUS ISD simrs:  {:?}", dr.simrs);
    eprintln!("GET STATUS ISD Oracle: {:?}", dr.oracle);

    // Both should reject: simrs returns 69 85, Oracle may return 69 82/85.
    assert!(
        !dr.simrs.is_success(),
        "simrs GET STATUS should require auth, but returned: {:04X}",
        dr.simrs.sw16()
    );
    assert_eq!(
        dr.simrs.sw[0], 0x69,
        "simrs should return 69xx for auth failure"
    );
}

// -----------------------------------------------------------------------
// Power cycle: reset clears state
// -----------------------------------------------------------------------

#[test]
fn reset_after_init_update_clears_scp_state() {
    let mut dc = dual_card!("reset-scp");
    dc.power_on();

    // Start an INITIALIZE UPDATE on both.
    let host_challenge = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let mut init_apdu = vec![0x80, 0x50, 0x00, 0x00, 0x08];
    init_apdu.extend_from_slice(&host_challenge);
    let dr1 = dc.exchange(&init_apdu);
    assert!(dr1.simrs.is_success(), "simrs INIT UPDATE should succeed");
    assert!(dr1.oracle.is_success(), "Oracle INIT UPDATE should succeed");

    // Reset both cards.
    // simrs: warm reset via SimEvent::Reset.
    // Oracle: reconnect (jcsl does not support power-cycling on the same TCP session).
    let _ = dc.simrs.process(SimEvent::Reset);
    dc.reconnect_oracle();
    dc.oracle.power_on().expect("Oracle power_on after reconnect");

    // Now try EXTERNAL AUTHENTICATE without a valid INIT UPDATE session.
    // Both should reject because the SCP session was cleared by reset.
    let ext_auth = [
        0x84, 0x82, 0x00, 0x00, 0x10, // CLA INS P1 P2 Lc=16
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fake host cryptogram
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fake C-MAC
    ];
    let dr2 = dc.exchange(&ext_auth);

    eprintln!("EXT AUTH after reset simrs:  {:?}", dr2.simrs);
    eprintln!("EXT AUTH after reset Oracle: {:?}", dr2.oracle);

    // Both should reject.
    assert!(
        !dr2.simrs.is_success(),
        "simrs should reject EXT AUTH after reset"
    );
    assert!(
        !dr2.oracle.is_success(),
        "Oracle should reject EXT AUTH after reset"
    );
}

// -----------------------------------------------------------------------
// MANAGE CHANNEL
// -----------------------------------------------------------------------

#[test]
fn manage_channel_open_close() {
    let mut dc = dual_card!("manage-ch");
    dc.power_on();

    // MANAGE CHANNEL: Open (P1=00, P2=00 = card assigns number).
    let open_ch = [0x00, 0x70, 0x00, 0x00, 0x01];
    let dr_open = dc.exchange(&open_ch);

    eprintln!("MANAGE CHANNEL open simrs:  {:?}", dr_open.simrs);
    eprintln!("MANAGE CHANNEL open Oracle: {:?}", dr_open.oracle);

    // Both should succeed and return a channel number.
    if dr_open.simrs.is_success() && dr_open.oracle.is_success() {
        assert!(
            !dr_open.simrs.data.is_empty(),
            "simrs: MANAGE CHANNEL open should return channel number"
        );
        assert!(
            !dr_open.oracle.data.is_empty(),
            "Oracle: MANAGE CHANNEL open should return channel number"
        );

        let simrs_ch = dr_open.simrs.data[0];
        let oracle_ch = dr_open.oracle.data[0];
        eprintln!("Assigned channels: simrs={simrs_ch}, oracle={oracle_ch}");

        // Close the channels.
        let close_simrs = [0x00, 0x70, 0x80, simrs_ch];
        let close_oracle = [0x00, 0x70, 0x80, oracle_ch];

        let dr_close_s = match dc.simrs.process(SimEvent::Apdu(&close_simrs)) {
            SimResponse::Apdu { sw, .. } => sw.to_bytes(),
            _ => [0x6F, 0x00],
        };
        let close_raw = dc.oracle.transmit_apdu(&close_oracle).unwrap_or_default();
        let dr_close_o = if close_raw.len() >= 2 {
            [close_raw[close_raw.len() - 2], close_raw[close_raw.len() - 1]]
        } else {
            [0x6F, 0x00]
        };

        eprintln!(
            "CLOSE channel: simrs={:02X}{:02X}, oracle={:02X}{:02X}",
            dr_close_s[0], dr_close_s[1], dr_close_o[0], dr_close_o[1]
        );
    }
}

// -----------------------------------------------------------------------
// APDU sequence: SELECT then GET DATA
// -----------------------------------------------------------------------

#[test]
fn select_then_get_data_sequence() {
    let mut dc = dual_card!("seq-sel-gd");
    dc.power_on();

    // Step 1: SELECT ISD on each (using their respective AIDs).
    let sel_simrs = select_aid(&SIMRS_ISD_AID);
    let simrs_sel = dc.simrs.process(SimEvent::Apdu(&sel_simrs));
    assert!(
        matches!(simrs_sel, SimResponse::Apdu { sw, .. } if sw.to_bytes() == [0x90, 0x00]),
        "simrs SELECT ISD failed"
    );

    let sel_oracle = select_aid(&ORACLE_ISD_AID);
    let oracle_sel_raw = dc.oracle.transmit_apdu(&sel_oracle).expect("Oracle SELECT failed");
    assert!(
        oracle_sel_raw.len() >= 2
            && oracle_sel_raw[oracle_sel_raw.len() - 2] == 0x90
            && oracle_sel_raw[oracle_sel_raw.len() - 1] == 0x00,
        "Oracle SELECT ISD failed: {oracle_sel_raw:02x?}"
    );

    // Step 2: GET DATA 0066 on both (same APDU).
    let get_data = [0x80, 0xCA, 0x00, 0x66];
    let dr = dc.exchange(&get_data);

    eprintln!("After SELECT -> GET DATA 0066:");
    eprintln!("  simrs:  {:?}", dr.simrs);
    eprintln!("  Oracle: {:?}", dr.oracle);

    // Both should have consistent behavior after SELECT.
    if dr.simrs.is_success() {
        assert!(
            !dr.simrs.data.is_empty(),
            "simrs GET DATA 0066 returned empty data"
        );
    }
}
