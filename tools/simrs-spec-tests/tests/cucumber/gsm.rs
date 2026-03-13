#![allow(missing_docs)]
//! Step definitions for `gsm.feature` -- GSM 11.11 SIM application layer.
//!
//! Crates under test: `simrs-gsm`, `simrs-comp128`.
//!
//! The GSM feature exercises the full APDU-level flow through `Sim`, which
//! routes CLA=0xA0 APDUs to `GsmApp`.  The Background creates a custom SIM
//! with a specified filesystem, Ki, PIN1 and PUK1, then each scenario sends
//! raw APDUs and asserts on status words and response data.
//!
//! **Shared steps**: Several step patterns are shared with `usim.rs` and
//! `fs.rs`.  To avoid regex collisions, shared steps live in usim.rs (which
//! uses `world.gsm_mode` to decide CLA byte) or fs.rs (which uses context
//! detection for library-level vs APDU-level).  This module defines only
//! steps that are **unique to gsm.feature**.

use cucumber::{given, then, when};
use simrs_comp128::comp128;
use simrs_fs::{DfDef, EfDef, Fid, FileRef};
use simrs_gsm::Ki;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_pin::{PinKey, PinValue};
use simrs_secret::Secret;
use simrs_sim::{Sim, SimEvent};
use simrs_spec_tests::{
    parse_hex, TEST_K, TEST_OPC, CORRECT_PIN, CORRECT_PUK,
    PIN_MAX_RETRIES, PUK_MAX_RETRIES, ATR,
};

use super::world::{do_send_apdu, SpecWorld};

// =========================================================================
// Static filesystem tree (matches gsm.feature Background docstring)
// =========================================================================

static GSM_EF_ICCID: EfDef = EfDef::transparent(
    Fid::new(0x2FE2),
    None,
    &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

static GSM_EF_DIR: EfDef = EfDef::linear_fixed(
    Fid::new(0x2F00),
    None,
    8,  // record_size
    2,  // num_records
    &[0xFF; 16], // 8 * 2 = 16 bytes
);

static GSM_EF_ADN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3A),
    None,
    14, // record_size
    3,  // num_records
    // 14 * 3 = 42 bytes -- distinct per-record content.
    &[
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    ],
);

static GSM_DF_TELECOM: DfDef = DfDef {
    fid: Fid::new(0x7F10),
    children: &[FileRef::Ef(&GSM_EF_ADN)],
};

static GSM_EF_IMSI: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

static GSM_EF_KC: EfDef = EfDef::transparent(
    Fid::new(0x6F20),
    None,
    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07],
);

static GSM_DF_GSM: DfDef = DfDef {
    fid: Fid::new(0x7F20),
    children: &[FileRef::Ef(&GSM_EF_IMSI), FileRef::Ef(&GSM_EF_KC)],
};

pub(crate) static GSM_TEST_MF: DfDef = DfDef {
    fid: Fid::MF,
    children: &[
        FileRef::Ef(&GSM_EF_ICCID),
        FileRef::Ef(&GSM_EF_DIR),
        FileRef::Df(&GSM_DF_TELECOM),
        FileRef::Df(&GSM_DF_GSM),
    ],
};

/// The Ki specified in the feature's Background.
const FEATURE_KI: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];

// =========================================================================
// Helpers (pub(crate) for use by other step modules)
// =========================================================================

/// Create a SIM configured per the gsm.feature Background.
///
/// - Custom MF with EF.ICCID, EF.DIR, DF.TELECOM/EF.ADN, DF.GSM/{EF.IMSI, EF.Kc}
/// - Ki from the feature Background
/// - PIN1 = "1234", enabled, 3 retries
/// - PUK1 = "12345678", 10 retries
/// - Both GSM and USIM apps (USIM required by Sim<MilenageParams, 256>)
fn create_gsm_test_sim() -> Sim<MilenageParams, 256> {
    let ki = Ki::classify(FEATURE_KI);
    let mut gsm = simrs_gsm::GsmApp::new(&GSM_TEST_MF, ki);

    // Configure PIN1 on the GSM app.
    let pin_val = PinValue::new(CORRECT_PIN);
    let puk_val = PinValue::new(CORRECT_PUK);
    gsm.pin_manager()
        .add_pin(
            PinKey::PIN1,
            &pin_val,
            PIN_MAX_RETRIES,
            &puk_val,
            PUK_MAX_RETRIES,
            true,
        )
        .expect("GSM add_pin must succeed");

    // USIM app is required by the Sim type but won't be used for CLA=0xA0.
    let mil = MilenageParams::with_defaults(
        SubscriberKey::classify(TEST_K),
        OperatorVariant::opc(TEST_OPC),
    );
    let mut usim = simrs_usim::UsimApp::new(&GSM_TEST_MF, &[], mil);
    let pin_val2 = PinValue::new(CORRECT_PIN);
    let puk_val2 = PinValue::new(CORRECT_PUK);
    usim.pin_manager()
        .add_pin(
            PinKey::PIN1,
            &pin_val2,
            PIN_MAX_RETRIES,
            &puk_val2,
            PUK_MAX_RETRIES,
            true,
        )
        .expect("USIM add_pin must succeed");

    let mut sim = Sim::<MilenageParams, 256>::new(&ATR, gsm, usim);
    let _ = sim.process(SimEvent::PowerOn);
    sim
}

/// Send an APDU via the SIM, storing results in world state.
fn gsm_send(world: &mut SpecWorld, cmd: &[u8]) {
    do_send_apdu(world, cmd);
}

/// Context-aware data accessor: returns `last_data` (APDU context) or
/// `fs_read_data` (library context).
///
/// Several Then steps are shared between gsm.feature (APDU-level) and
/// fs.feature (library-level).  APDU results go to `world.last_data`;
/// library-level read results go to `world.fs_read_data`.
pub(crate) fn response_data(world: &SpecWorld) -> &[u8] {
    if world.sim.is_some() {
        &world.last_data
    } else {
        &world.fs_read_data
    }
}

/// Send a GSM SELECT command for a file ID.
pub(crate) fn gsm_select(world: &mut SpecWorld, fid: u16) {
    let cmd = [0xA0, 0xA4, 0x00, 0x00, 0x02, (fid >> 8) as u8, (fid & 0xFF) as u8];
    gsm_send(world, &cmd);
}

/// Send SELECT + GET RESPONSE (consuming the response queue) via GSM APDUs.
pub(crate) fn gsm_select_and_consume(world: &mut SpecWorld, fid: u16) {
    gsm_select(world, fid);
    let (sw1, sw2) = world.last_sw.expect("SELECT must produce SW");
    assert_eq!(sw1, 0x9F, "Expected SW1=9F after SELECT, got {sw1:02X}");
    let get_rsp = [0xA0, 0xC0, 0x00, 0x00, sw2];
    gsm_send(world, &get_rsp);
}

/// Verify PIN1 via a GSM VERIFY APDU (CLA=0xA0).
fn gsm_verify_pin1(world: &mut SpecWorld) {
    let cmd = [
        0xA0, 0x20, 0x00, 0x01, 0x08,
        0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    gsm_send(world, &cmd);
    let (sw1, sw2) = world.last_sw.expect("VERIFY PIN1 must produce SW");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "VERIFY PIN1 failed: SW={sw1:02X} {sw2:02X}",
    );
}

// =========================================================================
// GIVEN steps -- Background (GSM-only)
// =========================================================================

/// Background: "Given a GsmApp with:" -- creates a SIM with the specified
/// filesystem, powers it on, and verifies PIN1 so subsequent commands work.
#[given(regex = r"^a GsmApp with:$")]
fn given_gsm_app_with(world: &mut SpecWorld) {
    world.sim = Some(Box::new(create_gsm_test_sim()));
    world.powered_on = true;
    world.gsm_mode = true;
    // Verify PIN1 so READ BINARY / RUN GSM ALGO commands succeed.
    gsm_verify_pin1(world);
}

/// Background: "And Ki = [01 23 45 67 ...]" -- already baked into
/// `create_gsm_test_sim()`.
#[given(regex = r"^Ki = \[.*\]$")]
fn given_ki(_world: &mut SpecWorld) {
    // Ki is configured in create_gsm_test_sim().
}

// Background "PIN1 is ..." and "PUK1 is ..." are handled by usim.rs (shared no-ops).

/// Background: "And a 256-byte response buffer" -- the Sim<_, 256> type
/// parameter already provides this.
#[given(regex = r"^a 256-byte response buffer$")]
fn given_response_buffer(_world: &mut SpecWorld) {
    // Buffer size is the const generic parameter of Sim.
}

// =========================================================================
// GIVEN steps -- Navigation / selection preconditions (GSM-only)
// =========================================================================

/// "Given I have selected EF.ICCID under MF"
#[given(regex = r"^I have selected EF\.ICCID under MF$")]
fn given_selected_ef_iccid_under_mf(world: &mut SpecWorld) {
    gsm_select_and_consume(world, 0x3F00);
    gsm_select(world, 0x2FE2);
}

/// "Given I have navigated to DF.GSM"
#[given(regex = r"^I have navigated to DF\.GSM$")]
fn given_navigated_to_df_gsm(world: &mut SpecWorld) {
    gsm_select_and_consume(world, 0x3F00);
    gsm_select_and_consume(world, 0x7F20);
}

/// "Given I have sent SELECT MF [A0 A4 00 00 02 3F 00]"
#[given(regex = r"^I have sent SELECT MF \[([^\]]+)\]$")]
fn given_sent_select_mf(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    gsm_send(world, &cmd);
}

/// "Given I have selected DF.GSM (0x7F20)" -- context-aware for fs.feature
/// and gsm.feature.
#[given(regex = r"^I have selected DF\.GSM \(0x7F20\)$")]
fn given_selected_df_gsm(world: &mut SpecWorld) {
    if world.sim.is_some() {
        gsm_select_and_consume(world, 0x3F00);
        gsm_select(world, 0x7F20);
    } else if let Some(ref mut ctx) = world.fs_ctx {
        ctx.select_by_fid(Fid::new(0x7F20)).expect("select DF.GSM");
    } else {
        panic!("Neither sim nor fs_ctx available");
    }
}

/// "Given EF.DIR (linear-fixed) is selected" (note: hyphen in gsm.feature
/// vs no hyphen in fs.feature)
#[given(regex = r"^EF\.DIR \(linear-fixed\) is selected$")]
fn given_ef_dir_linear_fixed_selected(world: &mut SpecWorld) {
    gsm_select_and_consume(world, 0x3F00);
    gsm_select_and_consume(world, 0x2F00);
}

/// "Given EF.ADN is selected under DF.TELECOM"
#[given(regex = r"^EF\.ADN is selected under DF\.TELECOM$")]
fn given_ef_adn_under_telecom(world: &mut SpecWorld) {
    gsm_select_and_consume(world, 0x3F00);
    gsm_select_and_consume(world, 0x7F10);
    gsm_select_and_consume(world, 0x6F3A);
}

/// "Given EF.ADN (3 records) is selected" -- context-aware for fs.feature
/// and gsm.feature.
#[given(regex = r"^EF\.ADN \(3 records\) is selected$")]
fn given_ef_adn_3_records_selected(world: &mut SpecWorld) {
    if world.sim.is_some() {
        gsm_select_and_consume(world, 0x3F00);
        gsm_select_and_consume(world, 0x7F10);
        gsm_select_and_consume(world, 0x6F3A);
    } else {
        let ctx = world.fs_ctx.get_or_insert_with(|| {
            simrs_fs::SelectionCtx::new(&GSM_TEST_MF)
        });
        ctx.select_by_fid(Fid::MF).expect("select MF");
        ctx.select_by_fid(Fid::new(0x7F10)).expect("select DF.TELECOM");
        ctx.select_by_fid(Fid::new(0x6F3A)).expect("select EF.ADN");
    }
}

/// "Given EF.ICCID (transparent) is selected" -- context-aware.
#[given(regex = r"^EF\.ICCID \(transparent\) is selected$")]
fn given_ef_iccid_transparent_selected(world: &mut SpecWorld) {
    if world.sim.is_some() {
        gsm_select_and_consume(world, 0x3F00);
        gsm_select_and_consume(world, 0x2FE2);
    } else {
        let ctx = world.fs_ctx.get_or_insert_with(|| {
            simrs_fs::SelectionCtx::new(&GSM_TEST_MF)
        });
        ctx.select_by_fid(Fid::MF).expect("select MF");
        ctx.select_by_fid(Fid::new(0x2FE2)).expect("select EF.ICCID");
    }
}

// =========================================================================
// WHEN steps -- GSM-specific APDU sends not in common.rs or usim.rs
// =========================================================================

/// "When I send GET RESPONSE to clear the queue" /
/// "When I send GET RESPONSE to consume it"
///
/// GSM-specific: sends GET RESPONSE with CLA=0xA0 and Le=SW2.
#[when(regex = r"^I send GET RESPONSE to (?:clear the queue|consume it)$")]
fn when_send_get_response_consume(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW from previous command");
    assert_eq!(sw1, 0x9F, "Expected SW1=9F before consuming GET RESPONSE, got {sw1:02X}");
    let cmd = [0xA0, 0xC0, 0x00, 0x00, sw2];
    gsm_send(world, &cmd);
}

/// "When I send GET RESPONSE" (bare, no brackets -- GSM context)
#[when(regex = r"^I send GET RESPONSE$")]
fn when_send_get_response_bare(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW from previous command");
    assert_eq!(sw1, 0x9F, "Expected SW1=9F before GET RESPONSE, got {sw1:02X}");
    let cmd = [0xA0, 0xC0, 0x00, 0x00, sw2];
    gsm_send(world, &cmd);
}

/// "When I send RUN GSM ALGO [A0 88 00 00 10] with 16-byte RAND"
#[when(regex = r"^I send RUN GSM ALGO \[([^\]]+)\] with 16-byte RAND$")]
fn when_send_run_gsm_algo(world: &mut SpecWorld, hex: String) {
    let mut cmd = parse_hex(&hex);
    let rand: [u8; 16] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF,
    ];
    cmd.extend_from_slice(&rand);
    world.rand_val = Some(rand);
    gsm_send(world, &cmd);
}

/// "When I send RUN GSM ALGO with 8-byte data (not 16)"
#[when(regex = r"^I send RUN GSM ALGO with 8-byte data \(not 16\)$")]
fn when_send_run_gsm_algo_wrong_len(world: &mut SpecWorld) {
    let cmd = [
        0xA0, 0x88, 0x00, 0x00, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    gsm_send(world, &cmd);
}

/// "When I send VERIFY PIN1 [A0 20 ...]"
#[when(regex = r"^I send VERIFY PIN1 \[([^\]]+)\]$")]
fn when_send_verify_pin1(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    gsm_send(world, &cmd);
}

/// "When I send VERIFY PIN1 with wrong value [A0 20 ...]"
#[when(regex = r"^I send VERIFY PIN1 with wrong value \[([^\]]+)\]$")]
fn when_send_verify_pin1_wrong(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    gsm_send(world, &cmd);
}

/// "When I send UNBLOCK [A0 2C 00 01 10] with PUK [...] + new PIN [...]"
#[when(regex = r"^I send UNBLOCK \[([^\]]+)\] with PUK \[.*\] \+ new PIN \[.*\]$")]
fn when_send_unblock(world: &mut SpecWorld, hex: String) {
    let mut cmd = parse_hex(&hex);
    // PUK: ASCII "12345678"
    cmd.extend_from_slice(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    // New PIN: ASCII "5678" + FF padding
    cmd.extend_from_slice(&[0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
    gsm_send(world, &cmd);
}

// =========================================================================
// THEN steps -- Status word assertions unique to GSM
// =========================================================================

/// "Then the status word is XX XX (...)".
/// Distinct from common.rs "SW is XX XX" (which uses bare "SW").
#[then(regex = r"^the status word is ([0-9A-Fa-f]{2}) ([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_the_status_word_is(world: &mut SpecWorld, sw1_hex: String, sw2_hex: String) {
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        (sw1, sw2),
        (expected_sw1, expected_sw2),
        "Expected SW {expected_sw1:02X} {expected_sw2:02X}, got {sw1:02X} {sw2:02X}",
    );
}

/// "Then SW1 is 0x9F (response data available)" / "Then SW1 is 0x9F"
/// common.rs handles `SW1 is XX` but the "0x" prefix doesn't match.
#[then(regex = r"^SW1 is 0x([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_sw1_is_hex(world: &mut SpecWorld, sw1_hex: String) {
    let expected = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let (sw1, _) = world.last_sw.expect("No SW available");
    assert_eq!(sw1, expected, "Expected SW1 0x{expected:02X}, got 0x{sw1:02X}");
}

/// "And SW2 is the response length (23 for DF/MF)"
#[then(regex = r"^SW2 is the response length \(23 for DF/MF\)$")]
fn then_sw2_is_23(world: &mut SpecWorld) {
    let (_, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(sw2, 23, "Expected SW2=23 (0x17), got {sw2} (0x{sw2:02X})");
}

/// "And SW2 is 15 (EF response length)"
#[then(regex = r"^SW2 is 15 \(EF response length\)$")]
fn then_sw2_is_15(world: &mut SpecWorld) {
    let (_, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(sw2, 15, "Expected SW2=15 (0x0F), got {sw2} (0x{sw2:02X})");
}

/// "Then SW1 is 0x9F and SW2 is 0x0C (12 bytes available)"
#[then(regex = r"^SW1 is 0x([0-9A-Fa-f]{2}) and SW2 is 0x([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_sw1_and_sw2(world: &mut SpecWorld, sw1_hex: String, sw2_hex: String) {
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        (sw1, sw2),
        (expected_sw1, expected_sw2),
        "Expected SW 0x{expected_sw1:02X} 0x{expected_sw2:02X}, got 0x{sw1:02X} 0x{sw2:02X}",
    );
}

/// "Then SW indicates file type mismatch error" / "Then SW indicates file type mismatch"
///
/// GSM-only: no usim.feature equivalent.
#[then(regex = r"^SW indicates file type mismatch(?:\s+error)?$")]
fn then_sw_file_type_mismatch(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    // GSM 11.11 uses 94 08 for file type inconsistency.
    assert_eq!(
        (sw1, sw2),
        (0x94, 0x08),
        "Expected SW 94 08 (file type mismatch), got {sw1:02X} {sw2:02X}",
    );
}

// =========================================================================
// THEN steps -- Response data assertions
// =========================================================================

/// "Then I get a 23-byte response"
#[then(regex = r"^I get a 23-byte response$")]
fn then_23_byte_response(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        23,
        "Expected 23-byte response, got {} bytes",
        world.last_data.len(),
    );
}

/// "Then I get a 15-byte response"
#[then(regex = r"^I get a 15-byte response$")]
fn then_15_byte_response(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        15,
        "Expected 15-byte response, got {} bytes",
        world.last_data.len(),
    );
}

/// "And bytes 4-5 are 0xXXXX (...)" / "And bytes 4-5 are 0xXXXX"
#[then(regex = r"^bytes 4-5 are 0x([0-9A-Fa-f]{4})(?:\s*\(.*\))?$")]
fn then_bytes_4_5(world: &mut SpecWorld, hex: String) {
    let expected = u16::from_str_radix(&hex, 16).unwrap();
    assert!(
        world.last_data.len() >= 6,
        "Response too short ({} bytes) to check bytes 4-5",
        world.last_data.len(),
    );
    let actual = u16::from_be_bytes([world.last_data[4], world.last_data[5]]);
    assert_eq!(
        actual, expected,
        "bytes 4-5: expected 0x{expected:04X}, got 0x{actual:04X}",
    );
}

/// "And bytes 4-5 in the response are 0xXXXX"
#[then(regex = r"^bytes 4-5 in the response are 0x([0-9A-Fa-f]{4})$")]
fn then_bytes_4_5_in_response(world: &mut SpecWorld, hex: String) {
    let expected = u16::from_str_radix(&hex, 16).unwrap();
    assert!(
        world.last_data.len() >= 6,
        "Response too short ({} bytes) to check bytes 4-5",
        world.last_data.len(),
    );
    let actual = u16::from_be_bytes([world.last_data[4], world.last_data[5]]);
    assert_eq!(
        actual, expected,
        "bytes 4-5: expected 0x{expected:04X}, got 0x{actual:04X}",
    );
}

/// "And byte 6 is 0xXX (...)" / "And byte 6 is 0xXX"
#[then(regex = r"^byte 6 is 0x([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_byte_6(world: &mut SpecWorld, hex: String) {
    let expected = u8::from_str_radix(&hex, 16).unwrap();
    assert!(
        world.last_data.len() > 6,
        "Response too short ({} bytes) to check byte 6",
        world.last_data.len(),
    );
    assert_eq!(
        world.last_data[6], expected,
        "byte 6: expected 0x{expected:02X}, got 0x{:02X}",
        world.last_data[6],
    );
}

/// "And byte 13 is 0xXX (...)" / "And byte 13 is 0xXX"
#[then(regex = r"^byte 13 is 0x([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_byte_13(world: &mut SpecWorld, hex: String) {
    let expected = u8::from_str_radix(&hex, 16).unwrap();
    assert!(
        world.last_data.len() > 13,
        "Response too short ({} bytes) to check byte 13",
        world.last_data.len(),
    );
    assert_eq!(
        world.last_data[13], expected,
        "byte 13: expected 0x{expected:02X}, got 0x{:02X}",
        world.last_data[13],
    );
}

/// "Then I get the 14-byte first record" (gsm.feature word order)
#[then(regex = r"^I get the 14-byte first record$")]
fn then_14_byte_first_record(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        14,
        "Expected 14-byte record, got {} bytes",
        world.last_data.len(),
    );
    let expected = [0x01u8; 14];
    assert_eq!(
        world.last_data,
        &expected[..],
        "First record mismatch: expected {:02X?}, got {:02X?}",
        expected, world.last_data,
    );
}

/// "Then I get the 23-byte MF status response"
#[then(regex = r"^I get the 23-byte MF status response$")]
fn then_23_byte_mf_status(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        23,
        "Expected 23-byte STATUS response, got {} bytes",
        world.last_data.len(),
    );
    let fid = u16::from_be_bytes([world.last_data[4], world.last_data[5]]);
    assert_eq!(fid, 0x3F00, "STATUS file ID: expected 0x3F00, got 0x{fid:04X}");
}

/// "Then I get the 9-byte IMSI data"
#[then(regex = r"^I get the 9-byte IMSI data$")]
fn then_9_byte_imsi(world: &mut SpecWorld) {
    assert_eq!(
        world.last_data.len(),
        9,
        "Expected 9-byte IMSI, got {} bytes",
        world.last_data.len(),
    );
}

// =========================================================================
// THEN steps -- RUN GSM ALGORITHM verification
// =========================================================================

/// "And GET RESPONSE returns 12 bytes: 4-byte SRES + 8-byte Kc"
#[then(regex = r"^GET RESPONSE returns 12 bytes: 4-byte SRES \+ 8-byte Kc$")]
fn then_get_response_12_bytes(world: &mut SpecWorld) {
    let cmd = [0xA0, 0xC0, 0x00, 0x00, 0x0C];
    gsm_send(world, &cmd);
    assert_eq!(
        world.last_data.len(),
        12,
        "Expected 12-byte COMP128 result, got {} bytes",
        world.last_data.len(),
    );
    let (sw1, sw2) = world.last_sw.expect("No SW after GET RESPONSE");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "Expected SW 90 00 after GET RESPONSE, got {sw1:02X} {sw2:02X}",
    );
}

/// "And the values match COMP128(Ki, RAND)"
#[then(regex = r"^the values match COMP128\(Ki, RAND\)$")]
fn then_values_match_comp128(world: &mut SpecWorld) {
    let rand = world
        .rand_val
        .expect("No RAND stashed from RUN GSM ALGO step");
    let ki = Secret::new(FEATURE_KI);
    let result = comp128(&ki, &rand);

    assert!(
        world.last_data.len() >= 12,
        "Need 12-byte result to verify COMP128, got {} bytes",
        world.last_data.len(),
    );

    let sres = &world.last_data[..4];
    let kc = &world.last_data[4..12];

    assert_eq!(
        sres,
        &result.sres[..],
        "SRES mismatch: expected {:02X?}, got {:02X?}",
        result.sres, sres,
    );
    assert_eq!(
        kc,
        result.kc.declassify_ref().as_slice(),
        "Kc mismatch: expected {:02X?}, got {:02X?}",
        result.kc.declassify_ref(), kc,
    );
}

// =========================================================================
// THEN steps -- PIN / UNBLOCK assertions (GSM-only)
// =========================================================================

/// "And PIN1 is unblocked with 3 retries"
#[then(regex = r"^PIN1 is unblocked with 3 retries$")]
fn then_pin1_unblocked_3_retries(world: &mut SpecWorld) {
    let cmd = [0xA0, 0x20, 0x00, 0x01, 0x00];
    gsm_send(world, &cmd);
    let (sw1, sw2) = world.last_sw.expect("No SW after VERIFY query");
    assert_eq!(sw1, 0x63, "Expected SW1=63 (retries), got 0x{sw1:02X}");
    let retries = sw2 & 0x0F;
    assert_eq!(retries, 3, "Expected 3 retries remaining, got {retries}");
}

/// "And the new PIN "5678" verifies successfully"
#[then(regex = r#"^the new PIN "(\d+)" verifies successfully$"#)]
fn then_new_pin_verifies(world: &mut SpecWorld, pin_digits: String) {
    let mut pin_bytes = [0xFFu8; 8];
    for (i, ch) in pin_digits.chars().enumerate() {
        assert!(i < 8, "PIN too long");
        pin_bytes[i] = 0x30 + ch.to_digit(10).expect("PIN must be digits") as u8;
    }
    let mut cmd = vec![0xA0, 0x20, 0x00, 0x01, 0x08];
    cmd.extend_from_slice(&pin_bytes);
    gsm_send(world, &cmd);
    let (sw1, sw2) = world.last_sw.expect("No SW after VERIFY");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "New PIN verification failed: SW={sw1:02X} {sw2:02X}",
    );
}

// =========================================================================
// THEN steps -- Navigation scenario assertions (GSM-only)
// =========================================================================

/// "And STATUS returns MF info"
#[then(regex = r"^STATUS returns MF info$")]
fn then_status_returns_mf(world: &mut SpecWorld) {
    let cmd = [0xA0, 0xF2, 0x00, 0x00, 0x17];
    gsm_send(world, &cmd);
    let (sw1, sw2) = world.last_sw.expect("No SW after STATUS");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "STATUS failed: SW={sw1:02X} {sw2:02X}",
    );
    assert!(
        world.last_data.len() >= 6,
        "STATUS response too short: {} bytes",
        world.last_data.len(),
    );
    let fid = u16::from_be_bytes([world.last_data[4], world.last_data[5]]);
    assert_eq!(fid, 0x3F00, "STATUS file ID: expected MF (0x3F00), got 0x{fid:04X}");
}

// =========================================================================
// Shared Then steps -- context-aware data assertions used by multiple features
// =========================================================================

/// "Then I get the 10-byte ICCID content"
///
/// Context-aware: checks `last_data` (APDU) or `fs_read_data` (library).
/// Shared by gsm.feature, fs.feature, and usim.feature.
#[then(regex = r"^I get the 10-byte ICCID content$")]
fn then_10_byte_iccid(world: &mut SpecWorld) {
    let expected: &[u8] = &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];
    let actual = response_data(world);
    assert_eq!(
        actual, expected,
        "ICCID mismatch: expected {:02X?}, got {:02X?}",
        expected, actual,
    );
}

/// "Then I get bytes [14 80 00]"
///
/// Context-aware: checks `last_data` (APDU) or `fs_read_data` (library).
/// Shared by gsm.feature and fs.feature.
#[then(regex = r"^I get bytes \[([0-9A-Fa-f ]+)\]$")]
fn then_get_bytes(world: &mut SpecWorld, hex: String) {
    let expected = parse_hex(&hex);
    let actual = response_data(world);
    assert_eq!(
        actual, expected,
        "Data mismatch: expected {:02X?}, got {:02X?}",
        expected, actual,
    );
}

/// "Then I get the second 14-byte record"
///
/// Context-aware: shared by gsm.feature and fs.feature.
#[then(regex = r"^I get the second 14-byte record$")]
fn then_second_14_byte_record(world: &mut SpecWorld) {
    let actual = response_data(world);
    assert_eq!(
        actual.len(),
        14,
        "Expected 14-byte record, got {} bytes",
        actual.len(),
    );
    let expected = [0x02u8; 14];
    assert_eq!(
        actual,
        &expected[..],
        "Second record mismatch: expected {:02X?}, got {:02X?}",
        expected, actual,
    );
}
