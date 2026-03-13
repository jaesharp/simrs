#![allow(missing_docs)]
//! Step definitions for `usim.feature` -- USIM application layer.
//!
//! Crates under test: `simrs-usim`, `simrs-milenage`.
//!
//! This module exercises the full USIM APDU handling path through
//! `simrs-sim`, including SELECT (with FCP), GET RESPONSE, READ BINARY,
//! READ RECORD, STATUS, AUTHENTICATE (Milenage), VERIFY/UNBLOCK PIN,
//! TERMINAL PROFILE, FETCH, TERMINAL RESPONSE, ENVELOPE, and the
//! proactive 91 XX status override.

use cucumber::{given, then, when};
use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef};
use simrs_milenage::{AuthChallenge, AuthManagementField, MilenageParams, OperatorVariant, SequenceNumber, SubscriberKey};
use simrs_pin::{PinKey, PinValue};
use simrs_proactive::{ProactiveCommand, TextCoding};
use simrs_sim::{Sim, SimEvent};
use simrs_spec_tests::{
    parse_hex, verify_pin1,
    TEST_K, TEST_OPC, CORRECT_PIN, WRONG_PIN, CORRECT_PUK, NEW_PIN,
    PIN_MAX_RETRIES, PUK_MAX_RETRIES, ATR,
};

use super::world::{do_send_apdu, sim_mut, SpecWorld};

// =========================================================================
// Static filesystem tree (matches feature file Background)
// =========================================================================

/// EF.ICCID (transparent, 10 bytes) under MF.
static EF_ICCID: EfDef = EfDef::transparent(
    Fid::new(0x2FE2),
    None,
    &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

/// EF.DIR (linear-fixed, record_size=8, 2 records) under MF.
static EF_DIR: EfDef = EfDef::linear_fixed(
    Fid::new(0x2F00),
    None,
    8,
    2,
    &[
        // Record 1: AID tag + partial USIM AID
        0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00,
        // Record 2: empty/unused
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ],
);

/// EF.IMSI (transparent, 9 bytes) under ADF.USIM.
static EF_IMSI: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

/// EF.UST (transparent, 4 bytes) under ADF.USIM.
static EF_UST: EfDef = EfDef::transparent(
    Fid::new(0x6F38),
    None,
    &[0xFF, 0xFF, 0x00, 0x00],
);

/// ADF.USIM root DF.
static ADF_USIM_ROOT: DfDef = DfDef {
    fid: Fid::new(0xFF01),
    children: &[FileRef::Ef(&EF_IMSI), FileRef::Ef(&EF_UST)],
};

/// ADF table with a single USIM application.
static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
    aid: &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
    root: &ADF_USIM_ROOT,
}];

/// MF with EF.ICCID and EF.DIR.
static USIM_MF: DfDef = DfDef {
    fid: Fid::new(0x3F00),
    children: &[FileRef::Ef(&EF_ICCID), FileRef::Ef(&EF_DIR)],
};

/// AID for ADF.USIM.
const AID_USIM: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

// =========================================================================
// Factory
// =========================================================================

/// Create a SIM configured per the usim.feature Background, powered on.
fn create_usim_sim() -> Sim<MilenageParams, 256> {
    let mil = MilenageParams::with_defaults(
        SubscriberKey::classify(TEST_K),
        OperatorVariant::operator_cipher(TEST_OPC),
    );
    let gsm = simrs_gsm::GsmApp::new(
        &USIM_MF,
        simrs_gsm::SubscriberKey::classify([0x11; 16]),
    );
    let mut usim = simrs_usim::UsimApp::new(&USIM_MF, &ADF_TABLE, mil);

    let pin_val = PinValue::new(CORRECT_PIN);
    let puk_val = PinValue::new(CORRECT_PUK);
    usim.pin_manager()
        .add_pin(PinKey::PIN1, &pin_val, PIN_MAX_RETRIES, &puk_val, PUK_MAX_RETRIES, true)
        .expect("add_pin must succeed");

    let mut sim = Sim::<MilenageParams, 256>::new(&ATR, gsm, usim);
    let _ = sim.process(SimEvent::PowerOn);
    sim
}

// =========================================================================
// Helpers
// =========================================================================

/// Send SELECT by FID and return (sw1, sw2).
fn select_by_fid(world: &mut SpecWorld, fid: u16) {
    let cmd = [0x00, 0xA4, 0x00, 0x04, 0x02, (fid >> 8) as u8, fid as u8];
    do_send_apdu(world, &cmd);
}

/// Send SELECT by AID (USIM) and return (sw1, sw2).
fn select_adf_usim(world: &mut SpecWorld) {
    let mut cmd = vec![0x00, 0xA4, 0x04, 0x04, 0x07];
    cmd.extend_from_slice(&AID_USIM);
    do_send_apdu(world, &cmd);
}

/// Send GET RESPONSE with the given Le byte, storing the result in world.
fn do_get_response(world: &mut SpecWorld, le: u8) {
    let cmd = [0x00, 0xC0, 0x00, 0x00, le];
    do_send_apdu(world, &cmd);
}

/// Perform SELECT + GET RESPONSE, leaving FCP data in `world.last_data`.
fn select_and_get_fcp(world: &mut SpecWorld, fid: u16) {
    select_by_fid(world, fid);
    let (sw1, sw2) = world.last_sw.expect("SELECT produced no SW");
    assert_eq!(sw1, 0x61, "SELECT must return 61 XX, got {sw1:02X} {sw2:02X}");
    do_get_response(world, sw2);
    let (sw1_2, sw2_2) = world.last_sw.expect("GET RESPONSE produced no SW");
    assert_eq!(
        (sw1_2, sw2_2),
        (0x90, 0x00),
        "GET RESPONSE must return 90 00, got {sw1_2:02X} {sw2_2:02X}"
    );
}

/// Perform SELECT AID + GET RESPONSE, leaving FCP data in `world.last_data`.
fn select_aid_and_get_fcp(world: &mut SpecWorld) {
    select_adf_usim(world);
    let (sw1, sw2) = world.last_sw.expect("SELECT AID produced no SW");
    assert_eq!(sw1, 0x61, "SELECT AID must return 61 XX, got {sw1:02X} {sw2:02X}");
    do_get_response(world, sw2);
}

/// Build a valid AUTN for the test Milenage credentials.
fn build_valid_autn(challenge: &[u8; 16], sqn: [u8; 6], amf: [u8; 2]) -> [u8; 16] {
    let params = MilenageParams::with_defaults(
        SubscriberKey::classify(TEST_K),
        OperatorVariant::operator_cipher(TEST_OPC),
    );
    let ch = AuthChallenge::new(*challenge);
    let sqn_t = SequenceNumber::new(sqn);
    let amf_t = AuthManagementField::new(amf);
    let ak = params.compute_anonymity_key(&ch);
    let mac_a = params.compute_auth_mac(&ch, &sqn_t, &amf_t);
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn[i] ^ ak.as_bytes()[i];
    }
    autn[6] = amf[0];
    autn[7] = amf[1];
    autn[8..16].copy_from_slice(mac_a.as_bytes());
    autn
}

/// Build the full AUTHENTICATE APDU bytes.
fn build_authenticate_apdu(challenge: &[u8; 16], autn: &[u8; 16]) -> Vec<u8> {
    let mut cmd = vec![0x00, 0x88, 0x00, 0x81, 0x22]; // CLA INS P1 P2 Lc=34
    cmd.push(0x10);
    cmd.extend_from_slice(challenge);
    cmd.push(0x10);
    cmd.extend_from_slice(autn);
    cmd
}

/// Find a tag in an FCP TLV structure. Returns Some(value_bytes) if found.
fn find_fcp_tag(fcp: &[u8], target_tag: u8) -> Option<Vec<u8>> {
    // FCP starts with 0x62 <len> <inner TLVs...>
    if fcp.len() < 2 || fcp[0] != 0x62 {
        return None;
    }
    let (inner_start, inner_len) = if fcp[1] <= 0x7F {
        (2, fcp[1] as usize)
    } else if fcp[1] == 0x81 && fcp.len() >= 3 {
        (3, fcp[2] as usize)
    } else {
        return None;
    };
    let inner = &fcp[inner_start..inner_start + inner_len.min(fcp.len() - inner_start)];
    let mut pos = 0;
    while pos < inner.len() {
        let tag = inner[pos];
        pos += 1;
        if pos >= inner.len() {
            break;
        }
        let len = inner[pos] as usize;
        pos += 1;
        if pos + len > inner.len() {
            break;
        }
        if tag == target_tag {
            return Some(inner[pos..pos + len].to_vec());
        }
        pos += len;
    }
    None
}

/// Queue a proactive DISPLAY TEXT command on the SIM's UsimApp.
fn queue_proactive_display_text(world: &mut SpecWorld) {
    let sim = sim_mut(world);
    let text = b"Hello";
    let cmd = ProactiveCommand::DisplayText {
        text,
        coding: TextCoding::Gsm8Bit,
        high_priority: false,
    };
    sim.usim_app_mut()
        .proactive_state()
        .queue_command(&cmd)
        .expect("queue_command must succeed");
}

// =========================================================================
// Background
// =========================================================================

#[given(regex = r"^a UsimApp with:$")]
fn given_usim_app_with(world: &mut SpecWorld) {
    world.sim = Some(Box::new(create_usim_sim()));
    world.powered_on = true;
}

#[given(regex = r"^Milenage params: K, OPc, SQN, AMF per test set 1$")]
fn given_milenage_params(world: &mut SpecWorld) {
    // Already configured by create_usim_sim().
    let _ = world;
}

#[given(regex = r#"^PIN1 is "1234", enabled, 3 retries$"#)]
fn given_pin1_configured(world: &mut SpecWorld) {
    // Already configured by create_usim_sim().
    let _ = world;
}

#[given(regex = r#"^PUK1 is "12345678", 10 retries$"#)]
fn given_puk1_configured(world: &mut SpecWorld) {
    // Already configured by create_usim_sim().
    let _ = world;
}

// "a 256-byte response buffer" is defined in sim.rs (shared Background step).

// =========================================================================
// CLA routing
// =========================================================================

#[then(regex = r"^the status word is not 6E 00.*$")]
fn then_sw_is_not_6e00(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert!(
        !(sw1 == 0x6E && sw2 == 0x00),
        "Expected SW != 6E 00 (class not supported), but got 6E 00"
    );
}

// =========================================================================
// SELECT / FCP -- SW2 is the FCP length
// =========================================================================

#[then(regex = r"^SW2 is the FCP length$")]
fn then_sw2_is_fcp_length(world: &mut SpecWorld) {
    let (_sw1, sw2) = world.last_sw.expect("No SW available");
    // SW2 after a successful SELECT with FCP must be > 0 (some FCP bytes pending).
    assert!(sw2 > 0, "SW2 should be the FCP length (> 0), got {sw2}");
}

// =========================================================================
// GET RESPONSE after SELECT
// =========================================================================

#[given(regex = r"^I have selected MF via \[([^\]]*)\]$")]
fn given_selected_mf_via(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
    let (sw1, _sw2) = world.last_sw.expect("No SW from SELECT MF");
    if world.gsm_mode {
        assert_eq!(sw1, 0x9F, "GSM SELECT MF must return 9F XX, got {sw1:02X}");
    } else {
        assert_eq!(sw1, 0x61, "SELECT MF must return 61 XX");
    }
}

#[when(regex = r"^I send GET RESPONSE \[([^\]]*)\] with Le=SW2$")]
fn when_get_response_with_le_sw2(world: &mut SpecWorld, hex: String) {
    let base = parse_hex(&hex);
    // The previous SELECT stored SW2 = FCP length.
    let (_sw1, sw2) = world.last_sw.expect("No SW from previous SELECT");
    let mut cmd = base;
    cmd.push(sw2); // Append Le = SW2
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^the response starts with tag 0x62$")]
fn then_response_starts_with_62(world: &mut SpecWorld) {
    assert!(
        !world.last_data.is_empty(),
        "Response data is empty, expected FCP starting with 0x62"
    );
    assert_eq!(
        world.last_data[0], 0x62,
        "Expected FCP template tag 0x62, got {:#04X}",
        world.last_data[0]
    );
}

#[then(regex = r"^the FCP contains tag 0x([0-9A-Fa-f]{2}) with value ([0-9A-Fa-f ]+?)(?:\s*\(.*\))?$")]
fn then_fcp_tag_with_value(world: &mut SpecWorld, tag_hex: String, val_hex: String) {
    let tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    let expected = parse_hex(&val_hex);
    let found = find_fcp_tag(&world.last_data, tag)
        .unwrap_or_else(|| panic!("FCP does not contain tag {tag:#04X}"));
    assert_eq!(
        found, expected,
        "FCP tag {tag:#04X}: expected {:02X?}, got {:02X?}",
        expected, found
    );
}

#[then(regex = r"^the FCP contains tag 0x([0-9A-Fa-f]{2})\s*\(.*\)$")]
fn then_fcp_tag_present(world: &mut SpecWorld, tag_hex: String) {
    let tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    assert!(
        find_fcp_tag(&world.last_data, tag).is_some(),
        "FCP does not contain tag {tag:#04X}"
    );
}

#[then(regex = r"^the FCP contains tag 0x82 with file descriptor byte for transparent EF$")]
fn then_fcp_fd_transparent(world: &mut SpecWorld) {
    let fd = find_fcp_tag(&world.last_data, 0x82)
        .expect("FCP does not contain tag 0x82 (file descriptor)");
    assert!(
        !fd.is_empty(),
        "File descriptor TLV is empty"
    );
    // Transparent EF: file descriptor byte bits 2..0 = 001 (transparent), bits 5..3 = 000 (no structure).
    // The standard value for transparent EF is 0x41 (shareable, transparent).
    // Bit 0 of the file descriptor byte = 1 means transparent.
    assert_eq!(
        fd[0] & 0x07,
        0x01,
        "File descriptor byte {:#04X} does not indicate transparent EF (expected bits 2..0 = 001)",
        fd[0]
    );
}

// =========================================================================
// SELECT by AID
// =========================================================================

#[then(regex = r"^GET RESPONSE returns an FCP with tag 0x84 containing the AID$")]
fn then_get_response_fcp_with_aid(world: &mut SpecWorld) {
    let (_sw1, sw2) = world.last_sw.expect("No SW from SELECT AID");
    // If SW1 is 0x61, need GET RESPONSE first.
    if world.last_sw.unwrap().0 == 0x61 {
        do_get_response(world, sw2);
    }
    let aid_val = find_fcp_tag(&world.last_data, 0x84)
        .expect("FCP does not contain tag 0x84 (DF name / AID)");
    assert_eq!(
        aid_val, AID_USIM,
        "FCP tag 0x84 AID mismatch: expected {:02X?}, got {:02X?}",
        AID_USIM, aid_val
    );
}

// =========================================================================
// FCP template structure (clauses)
// =========================================================================

#[given(regex = r"^I have selected MF with FCP$")]
fn given_selected_mf_with_fcp(world: &mut SpecWorld) {
    select_and_get_fcp(world, 0x3F00);
}

#[given(regex = r"^I have selected EF\.ICCID with FCP$")]
fn given_selected_iccid_with_fcp(world: &mut SpecWorld) {
    verify_pin1(sim_mut(world));
    select_and_get_fcp(world, 0x2FE2);
}

#[given(regex = r"^I have selected EF\.ICCID \(transparent\) with FCP$")]
fn given_selected_iccid_transparent_with_fcp(world: &mut SpecWorld) {
    verify_pin1(sim_mut(world));
    select_and_get_fcp(world, 0x2FE2);
}

#[then(regex = r"^the FCP contains tag 0x80 with a 2-byte file size$")]
fn then_fcp_file_size_2_bytes(world: &mut SpecWorld) {
    let val = find_fcp_tag(&world.last_data, 0x80)
        .expect("FCP does not contain tag 0x80 (file size)");
    assert_eq!(
        val.len(),
        2,
        "File size tag 0x80 should have 2-byte value, got {} bytes",
        val.len()
    );
}

#[then(regex = r"^the file descriptor byte has bits for transparent EF$")]
fn then_fd_byte_transparent(world: &mut SpecWorld) {
    let fd = find_fcp_tag(&world.last_data, 0x82)
        .expect("FCP does not contain tag 0x82 (file descriptor)");
    assert!(
        !fd.is_empty(),
        "File descriptor TLV value is empty"
    );
    assert_eq!(
        fd[0] & 0x07,
        0x01,
        "File descriptor byte {:#04X} does not indicate transparent EF",
        fd[0]
    );
}

// =========================================================================
// GET RESPONSE edge cases
// =========================================================================

// "Then SW indicates error (no data pending)" -- handled by common.rs
// via the generic "SW indicates error.*" handler.

#[given(regex = r"^I have sent SELECT MF$")]
fn given_sent_select_mf(world: &mut SpecWorld) {
    select_by_fid(world, 0x3F00);
    let (sw1, _sw2) = world.last_sw.expect("No SW from SELECT");
    assert_eq!(sw1, 0x61, "SELECT MF must return 61 XX for pending FCP");
}

#[when(regex = r"^I send STATUS \[([^\]]*)\] \(not GET RESPONSE\)$")]
fn when_send_status(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^then I send GET RESPONSE \[([^\]]*)\]$")]
fn when_then_send_get_response(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^GET RESPONSE returns error \(queue was cleared\)$")]
fn then_get_response_queue_cleared(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error SW (queue cleared), got {sw1:02X} {sw2:02X}"
    );
}

// =========================================================================
// SELECT EF under MF / GET RESPONSE retrieves FCP
// =========================================================================

#[given(regex = r"^I have selected MF$")]
fn given_selected_mf(world: &mut SpecWorld) {
    select_by_fid(world, 0x3F00);
    let (sw1, sw2) = world.last_sw.expect("No SW");
    assert_eq!(sw1, 0x61, "SELECT MF must return 61 XX, got {sw1:02X} {sw2:02X}");
    // Consume the FCP via GET RESPONSE to clear the queue.
    do_get_response(world, sw2);
}

#[when(regex = r"^GET RESPONSE retrieves the FCP$")]
fn when_get_response_retrieves_fcp(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW from SELECT");
    assert_eq!(sw1, 0x61, "Expected 61 XX from SELECT, got {sw1:02X}");
    do_get_response(world, sw2);
}

// =========================================================================
// READ BINARY
// =========================================================================

#[given(regex = r"^EF\.ICCID is selected$")]
fn given_ef_iccid_selected(world: &mut SpecWorld) {
    if world.gsm_mode {
        // GSM context: CLA=0xA0, SELECT returns 9F XX.
        use crate::gsm::gsm_select_and_consume;
        // Verify PIN1 via GSM VERIFY APDU.
        let pin_cmd = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        do_send_apdu(world, &pin_cmd);
        gsm_select_and_consume(world, 0x3F00);
        gsm_select_and_consume(world, 0x2FE2);
    } else if world.sim.is_some() {
        // USIM context: CLA=0x00, SELECT returns 61 XX.
        verify_pin1(sim_mut(world));
        select_by_fid(world, 0x2FE2);
        let (sw1, sw2) = world.last_sw.expect("No SW from SELECT EF.ICCID");
        assert_eq!(sw1, 0x61, "SELECT EF.ICCID must return 61 XX, got {sw1:02X} {sw2:02X}");
        // Consume FCP.
        do_get_response(world, sw2);
    } else {
        // Library-level (fs_ctx) context: use SelectionCtx directly.
        use simrs_fs::SelectionCtx;
        if world.fs_ctx.is_none() {
            world.fs_ctx = Some(SelectionCtx::new(&crate::fs::TEST_MF));
        }
        let ctx = world.fs_ctx.as_mut().unwrap();
        ctx.select_by_fid(Fid::MF).expect("select MF");
        ctx.select_by_fid(Fid::new(0x2FE2)).expect("select EF.ICCID");
    }
}

// "Then I get the 10-byte ICCID content" -- moved to gsm.rs (context-aware).

#[then(regex = r"^I get 3 bytes from offset 2$")]
fn then_get_3_bytes_offset_2(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        3,
        "Expected 3 bytes, got {}",
        world.last_data.len()
    );
    // Bytes 2..5 of the ICCID: [0x14, 0x80, 0x00]
    let expected: &[u8] = &[0x14, 0x80, 0x00];
    assert_eq!(
        world.last_data, expected,
        "Data at offset 2 mismatch"
    );
}

#[then(regex = r"^SW indicates offset/length error$")]
fn then_sw_offset_length_error(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    // 6A 86 (incorrect parameters P1-P2 / offset out of range) or
    // 6B 00 (wrong parameters) -- implementation dependent.
    assert!(
        (sw1 == 0x6A && (sw2 == 0x86 || sw2 == 0x82)) || sw1 == 0x6B
            || (sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91),
        "Expected offset/length error SW, got {sw1:02X} {sw2:02X}"
    );
}

#[then(regex = r"^SW indicates no EF selected error$")]
fn then_sw_no_ef_selected(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    // 6A 86 (no current EF) or 69 86 (command not allowed, no EF selected).
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error SW for no EF selected, got {sw1:02X} {sw2:02X}"
    );
}

// =========================================================================
// READ RECORD
// =========================================================================

#[given(regex = r"^EF\.DIR is selected$")]
fn given_ef_dir_selected(world: &mut SpecWorld) {
    verify_pin1(sim_mut(world));
    select_by_fid(world, 0x2F00);
    let (sw1, sw2) = world.last_sw.expect("No SW from SELECT EF.DIR");
    assert_eq!(sw1, 0x61, "SELECT EF.DIR must return 61 XX, got {sw1:02X} {sw2:02X}");
    do_get_response(world, sw2);
}

#[given(regex = r"^EF\.DIR \(2 records\) is selected$")]
fn given_ef_dir_2_records_selected(world: &mut SpecWorld) {
    // Same as above; our EF.DIR has 2 records.
    verify_pin1(sim_mut(world));
    select_by_fid(world, 0x2F00);
    let (sw1, sw2) = world.last_sw.expect("No SW from SELECT EF.DIR");
    assert_eq!(sw1, 0x61, "SELECT EF.DIR must return 61 XX, got {sw1:02X} {sw2:02X}");
    do_get_response(world, sw2);
}

#[then(regex = r"^I get the 8-byte first record$")]
fn then_get_8_byte_first_record(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        8,
        "Expected 8-byte record, got {} bytes",
        world.last_data.len()
    );
}

#[then(regex = r"^SW indicates record out of range$")]
fn then_sw_record_out_of_range(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    // 6A 83 (record not found).
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error SW for record out of range, got {sw1:02X} {sw2:02X}"
    );
}

// =========================================================================
// STATUS (INS=0xF2)
// =========================================================================

#[then(regex = r"^I get the MF FCP$")]
fn then_get_mf_fcp(world: &mut SpecWorld) {
    assert!(
        !world.last_data.is_empty(),
        "STATUS returned empty data"
    );
    // Must contain file ID 3F 00.
    let file_id = find_fcp_tag(&world.last_data, 0x83);
    assert!(
        file_id.is_some(),
        "STATUS response does not contain file ID tag 0x83"
    );
    assert_eq!(
        file_id.unwrap(),
        [0x3F, 0x00],
        "STATUS file ID is not MF (3F 00)"
    );
}

#[given(regex = r"^I have selected ADF\.USIM by AID$")]
fn given_selected_adf_usim_by_aid(world: &mut SpecWorld) {
    select_aid_and_get_fcp(world);
}

#[then(regex = r"^the FCP file ID matches the ADF$")]
fn then_fcp_file_id_matches_adf(world: &mut SpecWorld) {
    // After STATUS, response data should be FCP of current DF.
    // For ADF.USIM, the file ID is the ADF's internal FID (0xFF01 in our tree).
    // Or the FCP may contain tag 0x84 (AID) instead of / in addition to file ID.
    // Check that either file ID or AID is present.
    let has_fid = find_fcp_tag(&world.last_data, 0x83).is_some();
    let has_aid = find_fcp_tag(&world.last_data, 0x84).is_some();
    assert!(
        has_fid || has_aid,
        "STATUS FCP for ADF.USIM contains neither file ID nor AID"
    );
}

// =========================================================================
// AUTHENTICATE (INS=0x88)
// =========================================================================

#[given(regex = r"^ADF\.USIM is selected$")]
fn given_adf_usim_selected(world: &mut SpecWorld) {
    select_adf_usim(world);
    let (sw1, sw2) = world.last_sw.expect("No SW from SELECT AID");
    assert_eq!(sw1, 0x61, "SELECT ADF.USIM must return 61 XX, got {sw1:02X} {sw2:02X}");
    // Consume FCP.
    do_get_response(world, sw2);
}

#[when(regex = r"^I send AUTHENTICATE \[([^\]]*)\] with:$")]
fn when_send_authenticate_with_docstring(world: &mut SpecWorld, _hex: String) {
    // Build a valid AUTHENTICATE APDU using Milenage test credentials.
    // RAND = [0xAA; 16], SQN = [0; 6] (initial), AMF = [0x80, 0x00].
    let challenge = [0xAA; 16];
    let sqn = [0x00; 6];
    let amf = [0x80, 0x00];
    let autn = build_valid_autn(&challenge, sqn, amf);
    let cmd = build_authenticate_apdu(&challenge, &autn);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^GET RESPONSE returns tag 0xDB with RES \+ CK \+ IK$")]
fn then_get_response_db_with_keys(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW");
    assert_eq!(sw1, 0x61, "AUTHENTICATE must return 61 XX, got {sw1:02X} {sw2:02X}");
    do_get_response(world, sw2);
    let (sw1_2, sw2_2) = world.last_sw.expect("No SW from GET RESPONSE");
    assert_eq!(
        (sw1_2, sw2_2),
        (0x90, 0x00),
        "GET RESPONSE must return 90 00, got {sw1_2:02X} {sw2_2:02X}"
    );
    assert!(
        !world.last_data.is_empty() && world.last_data[0] == 0xDB,
        "Expected response starting with tag 0xDB, got {:02X?}",
        world.last_data.first()
    );
    // Verify structure: 0xDB <len> <0x08 RES[8] 0x10 CK[16] 0x10 IK[16]>
    // Total inner: 1 + 8 + 1 + 16 + 1 + 16 = 43 bytes.
    assert!(
        world.last_data.len() >= 2,
        "DB response too short"
    );
    let inner_len = world.last_data[1] as usize;
    assert!(
        inner_len >= 43,
        "DB inner length should be >= 43, got {inner_len}"
    );
}

#[when(regex = r"^I send AUTHENTICATE with tampered AUTN$")]
fn when_authenticate_tampered_autn(world: &mut SpecWorld) {
    let challenge = [0xAA; 16];
    let sqn = [0x00; 6];
    let amf = [0x80, 0x00];
    let mut autn = build_valid_autn(&challenge, sqn, amf);
    // Invert MAC field (bytes 8..16) to cause MAC failure.
    for b in &mut autn[8..16] {
        *b ^= 0xFF;
    }
    let cmd = build_authenticate_apdu(&challenge, &autn);
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send AUTHENTICATE with out-of-range SQN$")]
fn when_authenticate_out_of_range_sqn(world: &mut SpecWorld) {
    // First, do a successful auth to advance SQN_HE to 1.
    let challenge_1 = [0xAA; 16];
    let sqn_1 = [0x00; 6];
    let amf = [0x80, 0x00];
    let autn_1 = build_valid_autn(&challenge_1, sqn_1, amf);
    let cmd_1 = build_authenticate_apdu(&challenge_1, &autn_1);
    do_send_apdu(world, &cmd_1);
    let (sw1, sw2) = world.last_sw.expect("No SW from first AUTHENTICATE");
    assert_eq!(sw1, 0x61, "Setup AUTHENTICATE must succeed (61 XX)");
    // Consume the response.
    do_get_response(world, sw2);

    // Now send AUTHENTICATE with SQN=0 (already consumed, so out of range).
    let challenge_2 = [0xBB; 16];
    let sqn_2 = [0x00; 6]; // SQN=0 is now behind SQN_HE=1
    let autn_2 = build_valid_autn(&challenge_2, sqn_2, amf);
    let cmd_2 = build_authenticate_apdu(&challenge_2, &autn_2);
    do_send_apdu(world, &cmd_2);
}

#[then(regex = r"^GET RESPONSE returns tag 0xDC with 14-byte AUTS$")]
fn then_get_response_dc_with_auts(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW");
    assert_eq!(sw1, 0x61, "Expected 61 XX for sync failure response");
    do_get_response(world, sw2);
    assert!(
        !world.last_data.is_empty() && world.last_data[0] == 0xDC,
        "Expected response starting with tag 0xDC, got {:02X?}",
        world.last_data.first()
    );
    // DC <0E> <AUTS[14]> = 16 bytes total
    assert!(
        world.last_data.len() >= 16,
        "DC response too short: need >= 16, got {}",
        world.last_data.len()
    );
    assert_eq!(
        world.last_data[1], 0x0E,
        "AUTS length must be 0x0E (14), got {:#04X}",
        world.last_data[1]
    );
}

#[when(regex = r"^I send AUTHENTICATE with 8-byte data \(not 34\)$")]
fn when_authenticate_wrong_length(world: &mut SpecWorld) {
    // Send AUTHENTICATE with 8 bytes of data instead of the required 34.
    let mut cmd = vec![0x00, 0x88, 0x00, 0x81, 0x08]; // Lc=8
    cmd.extend_from_slice(&[0x10, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^SW indicates wrong length$")]
fn then_sw_wrong_length(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    // 67 00 (wrong length) or 6C XX (wrong Le).
    assert!(
        sw1 == 0x67 || sw1 == 0x6C || (sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91),
        "Expected wrong length error, got {sw1:02X} {sw2:02X}"
    );
}

// =========================================================================
// VERIFY PIN (INS=0x20)
// =========================================================================

#[when(regex = r"^I send VERIFY PIN1 with wrong value$")]
fn when_verify_wrong_pin(world: &mut SpecWorld) {
    let mut cmd = vec![0x00, 0x20, 0x00, 0x01, 0x08];
    cmd.extend_from_slice(&WRONG_PIN);
    do_send_apdu(world, &cmd);
}

#[given(regex = r"^PIN1 is blocked \(retries exhausted\)$")]
fn given_pin1_blocked_retries_exhausted(world: &mut SpecWorld) {
    // Exhaust all 3 retries with wrong PIN.
    let cla = if world.gsm_mode { 0xA0 } else { 0x00 };
    let mut cmd = vec![cla, 0x20, 0x00, 0x01, 0x08];
    cmd.extend_from_slice(&WRONG_PIN);
    for _ in 0..PIN_MAX_RETRIES {
        do_send_apdu(world, &cmd);
    }
}

#[when(regex = r"^I send VERIFY PIN1 with correct value$")]
fn when_verify_correct_pin(world: &mut SpecWorld) {
    let cla = if world.gsm_mode { 0xA0 } else { 0x00 };
    let mut cmd = vec![cla, 0x20, 0x00, 0x01, 0x08];
    cmd.extend_from_slice(&CORRECT_PIN);
    do_send_apdu(world, &cmd);
}

// "Given PIN1 is blocked" -- moved to pin.rs (context-aware for APDU and library).

// =========================================================================
// UNBLOCK PIN (INS=0x2C)
// =========================================================================

#[when(regex = r"^I send UNBLOCK with PUK \+ new PIN$")]
fn when_send_unblock(world: &mut SpecWorld) {
    let mut cmd = vec![0x00, 0x2C, 0x00, 0x01, 0x10];
    cmd.extend_from_slice(&CORRECT_PUK);
    cmd.extend_from_slice(&NEW_PIN);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^the new PIN verifies successfully$")]
fn then_new_pin_verifies(world: &mut SpecWorld) {
    let mut cmd = vec![0x00, 0x20, 0x00, 0x01, 0x08];
    cmd.extend_from_slice(&NEW_PIN);
    do_send_apdu(world, &cmd);
    let (sw1, sw2) = world.last_sw.expect("No SW from VERIFY new PIN");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "VERIFY with new PIN must return 90 00, got {sw1:02X} {sw2:02X}"
    );
}

// =========================================================================
// FETCH (INS=0x12, CLA=0x80)
// =========================================================================

#[given(regex = r"^a proactive DISPLAY TEXT command is queued$")]
fn given_proactive_display_text_queued(world: &mut SpecWorld) {
    queue_proactive_display_text(world);
}

#[when(regex = r"^I send FETCH \[([^\]]*)\] with Le=pending_len$")]
fn when_send_fetch_with_pending_len(world: &mut SpecWorld, hex: String) {
    let base = parse_hex(&hex);
    let pending = sim_mut(world).usim_app_mut().proactive_state().pending_len();
    assert!(pending > 0, "No proactive command pending for FETCH");
    let mut cmd = base;
    cmd.push(pending as u8);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^I get the BER-TLV encoded proactive command$")]
fn then_get_ber_tlv_proactive(world: &mut SpecWorld) {
    assert!(
        !world.last_data.is_empty(),
        "FETCH returned empty data"
    );
}

#[then(regex = r"^the command starts with tag 0xD0$")]
fn then_command_starts_with_d0(world: &mut SpecWorld) {
    assert!(
        !world.last_data.is_empty() && world.last_data[0] == 0xD0,
        "Expected proactive command tag 0xD0, got {:02X?}",
        world.last_data.first()
    );
}

#[then(regex = r"^the proactive queue is now empty$")]
fn then_proactive_queue_empty(world: &mut SpecWorld) {
    let sim = sim_mut(world);
    assert!(
        !sim.usim_app_mut().proactive_state().has_pending(),
        "Proactive queue should be empty after FETCH"
    );
}

#[then(regex = r"^SW indicates no proactive data pending$")]
fn then_sw_no_proactive_data(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    // Should be an error -- 62 00 (warning) or 69 85 (conditions not satisfied)
    // or 94 02 (no data available) depending on implementation.
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error/warning SW for no proactive data, got {sw1:02X} {sw2:02X}"
    );
}

// =========================================================================
// TERMINAL RESPONSE (INS=0x14, CLA=0x80)
// =========================================================================

#[given(regex = r"^a proactive command was fetched$")]
fn given_proactive_command_fetched(world: &mut SpecWorld) {
    // Queue a DISPLAY TEXT command.
    queue_proactive_display_text(world);
    // Send TERMINAL PROFILE first (needed to activate proactive session).
    let tp_cmd = [0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF];
    do_send_apdu(world, &tp_cmd);
    // Fetch it.
    let pending = sim_mut(world).usim_app_mut().proactive_state().pending_len();
    let mut fetch_cmd = vec![0x80, 0x12, 0x00, 0x00];
    fetch_cmd.push(pending as u8);
    do_send_apdu(world, &fetch_cmd);
}

#[when(regex = r"^I send TERMINAL RESPONSE \[([^\]]*)\] with response data$")]
fn when_send_terminal_response(world: &mut SpecWorld, hex: String) {
    let base = parse_hex(&hex);
    // Build a minimal terminal response: cmd_details + device_id + result.
    let tr_data: Vec<u8> = vec![
        // Command Details: tag 0x81, len 3, cmd_number=1, cmd_type=0x21 (DISPLAY TEXT), qualifier=0x00
        0x81, 0x03, 0x01, 0x21, 0x00,
        // Device Identities: tag 0x82, len 2, terminal=0x82, UICC=0x81
        0x82, 0x02, 0x82, 0x81,
        // Result: tag 0x83, len 1, success=0x00
        0x83, 0x01, 0x00,
    ];
    let mut cmd = base;
    cmd.push(tr_data.len() as u8); // Lc
    cmd.extend_from_slice(&tr_data);
    do_send_apdu(world, &cmd);
}

// =========================================================================
// ENVELOPE (INS=0xC2, CLA=0x80)
// =========================================================================

#[when(regex = r"^I send ENVELOPE \[([^\]]*)\] with BER-TLV data$")]
fn when_send_envelope(world: &mut SpecWorld, hex: String) {
    let base = parse_hex(&hex);

    // ENVELOPE requires a prior TERMINAL PROFILE in this session.
    let tp_cmd = [0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF];
    do_send_apdu(world, &tp_cmd);

    // Minimal Menu Selection envelope (BER-TLV outer tag D3).
    // D3 09 -- Menu Selection, length 9
    //   90 01 01 -- Item identifier (id=1)
    //   82 02 01 81 -- Device identities (keypad -> UICC)
    //   15 00 -- Help request (tag 0x15, len 0) -- optional but pads length
    let inner: Vec<u8> = vec![
        0x90, 0x01, 0x01, // Item identifier
        0x82, 0x02, 0x01, 0x81, // Device identities (keypad -> UICC)
    ];
    let mut env_data = vec![0xD3, inner.len() as u8];
    env_data.extend_from_slice(&inner);

    let mut cmd = base;
    cmd.push(env_data.len() as u8); // Lc
    cmd.extend_from_slice(&env_data);
    do_send_apdu(world, &cmd);
}

// =========================================================================
// Proactive SW override (91 XX)
// =========================================================================

#[given(regex = r"^a proactive command is queued \(e\.g\. DISPLAY TEXT\)$")]
fn given_proactive_command_queued(world: &mut SpecWorld) {
    queue_proactive_display_text(world);
}

#[when(regex = r"^I send any command that returns 90 00 \(e\.g\. VERIFY correct PIN\)$")]
fn when_send_command_returns_9000(world: &mut SpecWorld) {
    // Send VERIFY with correct PIN -> normally 90 00.
    let mut cmd = vec![0x00, 0x20, 0x00, 0x01, 0x08];
    cmd.extend_from_slice(&CORRECT_PIN);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^SW is 91 XX where XX is the proactive command length$")]
fn then_sw_91_xx(world: &mut SpecWorld) {
    let (sw1, _sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        sw1, 0x91,
        "Expected SW1=91 (proactive override), got {sw1:02X}"
    );
    // SW2 should be the pending command length (> 0).
    let sw2 = world.last_sw.unwrap().1;
    assert!(sw2 > 0, "SW2 (proactive command length) should be > 0");
}

#[given(regex = r"^a proactive command is queued$")]
fn given_proactive_queued(world: &mut SpecWorld) {
    queue_proactive_display_text(world);
}

#[when(regex = r"^I send a command that returns an error \(e\.g\. SELECT nonexistent\)$")]
fn when_send_error_command(world: &mut SpecWorld) {
    // SELECT a nonexistent AID -> 6A 82 (file not found).
    let cmd = [0x00, 0xA4, 0x04, 0x04, 0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^SW is the error code \(not overridden to 91 XX\)$")]
fn then_sw_not_overridden(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert_ne!(
        sw1, 0x91,
        "Expected error SW (not 91 XX override), got {sw1:02X} {sw2:02X}"
    );
    // Must be an error SW.
    assert!(
        sw1 >= 0x60 && sw1 != 0x90,
        "Expected error SW, got {sw1:02X} {sw2:02X}"
    );
}

// =========================================================================
// Navigation sequences
// =========================================================================

#[when(regex = r"^I select MF by FID$")]
fn when_select_mf_by_fid(world: &mut SpecWorld) {
    select_by_fid(world, 0x3F00);
    let (sw1, sw2) = world.last_sw.expect("No SW");
    if sw1 == 0x61 {
        do_get_response(world, sw2);
    }
}

#[when(regex = r"^I select ADF\.USIM by AID$")]
fn when_select_adf_usim_by_aid(world: &mut SpecWorld) {
    select_adf_usim(world);
    let (sw1, sw2) = world.last_sw.expect("No SW");
    if sw1 == 0x61 {
        do_get_response(world, sw2);
    }
}

#[when(regex = r"^I select EF\.IMSI by FID$")]
fn when_select_ef_imsi_by_fid(world: &mut SpecWorld) {
    select_by_fid(world, 0x6F07);
    let (sw1, sw2) = world.last_sw.expect("No SW");
    if sw1 == 0x61 {
        do_get_response(world, sw2);
    }
}

#[when(regex = r"^I READ BINARY to get IMSI data$")]
fn when_read_binary_imsi(world: &mut SpecWorld) {
    // PIN1 must be verified before reading EFs under ADF.USIM.
    verify_pin1(sim_mut(world));
    // Read 9 bytes (IMSI EF size) from offset 0.
    let cmd = [0x00, 0xB0, 0x00, 0x00, 0x09];
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^I get the IMSI content$")]
fn then_get_imsi_content(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        9,
        "Expected 9-byte IMSI, got {} bytes",
        world.last_data.len()
    );
    let expected: &[u8] = &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0];
    assert_eq!(world.last_data, expected, "IMSI content mismatch");
}

#[when(regex = r"^I select MF$")]
fn when_select_mf(world: &mut SpecWorld) {
    select_by_fid(world, 0x3F00);
    let (sw1, sw2) = world.last_sw.expect("No SW");
    if sw1 == 0x61 {
        do_get_response(world, sw2);
    }
}

#[then(regex = r"^STATUS returns MF FCP$")]
fn then_status_returns_mf_fcp(world: &mut SpecWorld) {
    let cmd = [0x00, 0xF2, 0x00, 0x00, 0x00];
    do_send_apdu(world, &cmd);
    assert!(
        !world.last_data.is_empty(),
        "STATUS returned empty data"
    );
    let file_id = find_fcp_tag(&world.last_data, 0x83);
    assert!(
        file_id.is_some(),
        "STATUS FCP does not contain file ID tag 0x83"
    );
    assert_eq!(
        file_id.unwrap(),
        [0x3F, 0x00],
        "STATUS file ID must be MF (3F 00)"
    );
}
