#![allow(missing_docs)]
//! Step definitions shared across multiple feature files.
//!
//! Contains SIM initialization Given steps, generic APDU When steps,
//! and generic SW/data Then steps used by two or more vulnerability categories.

use cucumber::{given, then, when};
use simrs_adversarial_countervalidation::{apdu, create_sim, create_sim_powered_on, parse_hex};

use super::snapshot::{
    reserve_proactive, reserve_rsp_queue, reserve_selection_ctx, reserve_terminal_capability,
};
use super::world::{
    do_send_apdu, ensure_pin1_verified, reset_state_snapshots, select_mf_and_consume, Phase,
    SimWorld,
};

// =========================================================================
// GIVEN steps -- SIM initialisation (used by all features)
// =========================================================================

// Group A: SIM initialization -- all variants create a powered-on SIM with test credentials.
#[given(
    regex = r"^the SIM is initiali[sz]ed (?:with test credentials.*|with:$|with Milenage credentials:$)"
)]
fn given_sim_initialized(world: &mut SimWorld) {
    world.activate(Box::new(create_sim_powered_on()));
}

#[given("PIN1 (P2=0x01) is configured:")]
fn given_pin1_configured(world: &mut SimWorld) {
    // Already done by create_sim() / create_sim_powered_on().
    let _ = world;
}

// Group B: Power-on guard -- ensure the SIM is powered on.
#[given(regex = r"^the SIM (?:is|has been) powered on.*$")]
fn given_sim_powered_on(world: &mut SimWorld) {
    if !world.is_powered() {
        world.power_on();
    }
}

#[given(regex = r"^the SIM is initiali[sz]ed but NOT yet powered on$")]
fn given_sim_not_powered_on(world: &mut SimWorld) {
    world.create_unpowered(Box::new(create_sim()));
}

#[given(regex = r"^the SIM is initiali[sz]ed with an ADF table.*$")]
fn given_adf_table(world: &mut SimWorld) {
    // ADF table is configured in create_sim() via profile::ADF_TABLE.
    // SELECT by AID A0000000871002 routes to ADF.USIM.
    let _ = world;
}

// Group C: Freshly-powered guard -- init only if not already done by Background.
#[given(
    regex = r"^the SIM (?:is freshly powered on with no commands sent|has just been powered on and no other APDU has been sent)$"
)]
fn given_freshly_powered(world: &mut SimWorld) {
    if matches!(world.phase, Phase::Uninit) {
        world.activate(Box::new(create_sim_powered_on()));
    }
}

#[given("no SELECT command has been sent since power-on")]
fn given_no_select(world: &mut SimWorld) {
    // Power on already happened in Background; nothing extra needed.
    let _ = world;
}

#[given(regex = r"^MF is (?:implicitly selected|the current DF).*$")]
fn given_mf_selected(world: &mut SimWorld) {
    // MF is implicitly selected after power-on; no-op.
    let _ = world;
}

#[given("the MF filesystem contains:")]
fn given_mf_filesystem(world: &mut SimWorld) {
    // Already configured by create_sim_powered_on().
    // Verify PIN1 so that READ BINARY and other FS commands can succeed
    // in scenarios that require file data access.
    ensure_pin1_verified(world);
}

// Group D: MF selection -- select MF and consume FCP.
// Covers "I have selected MF", "I have selected MF (SW 61 XX returned)",
// and "I have selected MF and consumed its FCP".
// Note: "I have selected MF and received SW 61 XX" is a DIFFERENT step
// (does NOT consume FCP) and lives in fs_access_control.rs.
#[given(regex = r"^I have selected MF(?:\s*\(SW 61 XX returned\))?(?:\s+and consumed its FCP)?$")]
fn given_selected_mf(world: &mut SimWorld) {
    select_mf_and_consume(world);
    reset_state_snapshots(world);
}

// =========================================================================
// WHEN steps -- generic APDU send (used by all features)
// =========================================================================

// Matches hex-bracketed APDUs: I send APDU [...], I send SELECT [...], etc.
// Used by apdu_boundary.feature where the raw bytes ARE the test.
//
// Does NOT match AUTHENTICATE or ENVELOPE -- those have dedicated handlers.
// Semantic steps ("I send SELECT MF", "I send READ BINARY at offset N length M")
// are defined below and match step text without trailing [...] brackets.
#[when(
    regex = r"^I send (?:APDU|SELECT|READ BINARY|UPDATE BINARY|READ RECORD|TERMINAL PROFILE)\b.* \[([^\]]*)\]$"
)]
fn when_send_apdu_bracketed(world: &mut SimWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

// Hex-based GET RESPONSE with optional "again" suffix (boundary tests).
#[when(regex = r"^I send (?:a (?:second|third) )?GET RESPONSE \[([^\]]+)\](?:\s+again)?$")]
fn when_get_response_bracketed(world: &mut SimWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^the SIM receives a power cycle.*$")]
fn when_power_cycle(world: &mut SimWorld) {
    world.power_on();
}

// =========================================================================
// WHEN steps -- semantic command names (shared across features)
// =========================================================================

#[when("I send SELECT MF")]
fn when_select_mf(world: &mut SimWorld) {
    let cmd = apdu::select_fid(apdu::FID_MF).build();
    do_send_apdu(world, &cmd);
    reserve_selection_ctx(&mut world.reservations);
    reserve_rsp_queue(&mut world.reservations);
}

#[when("I send SELECT EF.ICCID")]
fn when_select_ef_iccid(world: &mut SimWorld) {
    let cmd = apdu::select_fid(apdu::FID_ICCID).build();
    do_send_apdu(world, &cmd);
    reserve_selection_ctx(&mut world.reservations);
    reserve_rsp_queue(&mut world.reservations);
}

#[when("I send SELECT non-existent FID")]
fn when_select_nonexistent_fid(world: &mut SimWorld) {
    let cmd = apdu::select_fid(apdu::FID_NONEXISTENT).build();
    do_send_apdu(world, &cmd);
}

#[when("I send SELECT by unknown AID")]
fn when_select_unknown_aid(world: &mut SimWorld) {
    let cmd = apdu::select_aid(&[0xFF; 7]).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send (?:a (?:second|third) )?GET RESPONSE with Le=(\d+)$")]
fn when_get_response_le(world: &mut SimWorld, le: u8) {
    let cmd = apdu::get_response(le).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send (?:a (?:second|third) )?GET RESPONSE with Le matching SW2$")]
fn when_get_response_matching_sw2(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(sw1, 0x61, "Expected SW1=61, got {sw1:02X} {sw2:02X}");
    let cmd = apdu::get_response(sw2).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send READ BINARY at offset (\d+) length (\d+)$")]
fn when_read_binary(world: &mut SimWorld, offset: u16, le: u8) {
    let cmd = apdu::read_binary(offset, le).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send UPDATE BINARY at offset (\d+) with (\d+) bytes?$")]
fn when_update_binary(world: &mut SimWorld, offset: u16, n_bytes: usize) {
    let data = vec![0xAA; n_bytes];
    let cmd = apdu::update_binary(offset, &data).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send READ RECORD record (\d+) in absolute mode$")]
fn when_read_record(world: &mut SimWorld, record: u8) {
    let cmd = apdu::read_record(record, 0x04, 1).build();
    do_send_apdu(world, &cmd);
}

#[when("I send TERMINAL PROFILE")]
fn when_terminal_profile(world: &mut SimWorld) {
    let cmd = apdu::terminal_profile(&[0xFF; 4]).build();
    do_send_apdu(world, &cmd);
    reserve_terminal_capability(&mut world.reservations);
    reserve_proactive(&mut world.reservations);
}

// =========================================================================
// THEN steps -- generic SW and response data checks
// =========================================================================

#[then(regex = r#"^SW is "([0-9A-Fa-f]{2}) ([0-9A-Fa-f]{2})"$"#)]
fn then_sw_is_quoted(world: &mut SimWorld, sw1_hex: String, sw2_hex: String) {
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (expected_sw1, expected_sw2),
        "Expected SW {expected_sw1:02X} {expected_sw2:02X}, got {sw1:02X} {sw2:02X}",
    );
}

#[then(regex = r"^SW is ([0-9A-Fa-f]{2}) ([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_sw_is(world: &mut SimWorld, sw1_hex: String, sw2_hex: String) {
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (expected_sw1, expected_sw2),
        "Expected SW {expected_sw1:02X} {expected_sw2:02X}, got {sw1:02X} {sw2:02X}",
    );
}

// Matches "SW1 is XX" and "SW1 is XX (description)" but NOT "SW1 is XX and SW2..."
#[then(regex = r"^SW1 is ([0-9A-Fa-f]{2})(?: \(.*\))?$")]
fn then_sw1_is(world: &mut SimWorld, sw1_hex: String) {
    let expected = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let (sw1, _) = world.last_sw();
    assert_eq!(sw1, expected, "Expected SW1 {expected:02X}, got {sw1:02X}");
}

// GET RESPONSE with no queued data: 69 86 (conditions not satisfied) or
// 6F 00 (technical problem).
#[then("SW indicates no data pending")]
fn then_sw_no_data_pending(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        (sw1, sw2) == (0x69, 0x86) || (sw1, sw2) == (0x6F, 0x00),
        "Expected 69 86 or 6F 00 (no data pending), got {sw1:02X} {sw2:02X}",
    );
}

// Command rejected outright (e.g. ENVELOPE before TERMINAL PROFILE):
// 69 85 (conditions not satisfied), 69 86 (no current EF),
// 6D 00 (INS not supported), 6F 00 (technical).
#[then("SW indicates command rejected")]
fn then_sw_command_rejected(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        (sw1, sw2) == (0x69, 0x85)
            || (sw1, sw2) == (0x69, 0x86)
            || (sw1, sw2) == (0x6D, 0x00)
            || (sw1, sw2) == (0x6F, 0x00),
        "Expected 69 85, 69 86, 6D 00, or 6F 00 (command rejected), got {sw1:02X} {sw2:02X}",
    );
}

// READ BINARY / READ RECORD applied to a DF (not an EF): 69 86 (no current EF)
// or 69 81 (command incompatible with file structure).
#[then("SW indicates command not allowed on DF")]
fn then_sw_not_allowed_on_df(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        (sw1, sw2) == (0x69, 0x86) || (sw1, sw2) == (0x69, 0x81),
        "Expected 69 86 or 69 81 (command not allowed on DF), got {sw1:02X} {sw2:02X}",
    );
}

// Malformed data field or Lc mismatch: 67 00 (wrong length), 6A 80 (incorrect
// parameters in data field), or 69 86 (some implementations reject at the
// "is data valid" gate before parsing).
#[then("SW indicates wrong length or incorrect parameters")]
fn then_sw_wrong_length_or_params(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        (sw1, sw2) == (0x67, 0x00) || (sw1, sw2) == (0x6A, 0x80) || (sw1, sw2) == (0x69, 0x86),
        "Expected 67 00, 6A 80, or 69 86 (wrong length / incorrect data), got {sw1:02X} {sw2:02X}",
    );
}

// Generic: any error SW.  Used in boundary/robustness tests where the point is
// "didn't crash and returned SOME error," not a specific error category.
#[then(regex = r"^SW (?:indicates (?:an )?error|is an error code)$")]
fn then_sw_error(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error SW, got {sw1:02X} {sw2:02X}",
    );
}

// ---- Specific SW semantic steps (each maps to exactly one SW) ----

// ISO 7816-4 clause 5.4.1: CLA byte not supported -> 6E 00.
#[then("SW indicates class not supported")]
fn then_sw_class_not_supported(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x6E, 0x00),
        "Expected 6E 00 (class not supported), got {sw1:02X} {sw2:02X}"
    );
}

// ISO 7816-4 clause 5.4.2: INS byte not supported -> 6D 00.
#[then("SW indicates instruction not supported")]
fn then_sw_ins_not_supported(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x6D, 0x00),
        "Expected 6D 00 (instruction not supported), got {sw1:02X} {sw2:02X}"
    );
}

// ISO 7816-4: wrong length of command data -> 67 00.
#[then("SW indicates wrong length")]
fn then_sw_wrong_length(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x67, 0x00),
        "Expected 67 00 (wrong length), got {sw1:02X} {sw2:02X}"
    );
}

// ETSI TS 102 221 Table 10.3: file or application not found -> 6A 82.
#[then("SW indicates file not found")]
fn then_sw_file_not_found(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x6A, 0x82),
        "Expected 6A 82 (file not found), got {sw1:02X} {sw2:02X}"
    );
}

// ETSI TS 102 221: incorrect parameters P1-P2 -> 6A 86.
#[then("SW indicates incorrect P1-P2")]
fn then_sw_incorrect_p1p2(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x6A, 0x86),
        "Expected 6A 86 (incorrect P1-P2), got {sw1:02X} {sw2:02X}"
    );
}

// ETSI TS 102 221: referenced data (PIN/key) not found -> 6A 88.
#[then("SW indicates reference data not found")]
fn then_sw_ref_data_not_found(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x6A, 0x88),
        "Expected 6A 88 (reference data not found), got {sw1:02X} {sw2:02X}"
    );
}

// ETSI TS 102 221: no current EF in the selection context -> 69 86.
#[then("SW indicates no current EF")]
fn then_sw_no_current_ef(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x86),
        "Expected 69 86 (no current EF), got {sw1:02X} {sw2:02X}"
    );
}

// ETSI TS 102 221: authentication method blocked -> 69 83.
#[then("the PIN is blocked")]
fn then_pin_blocked(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x83),
        "Expected 69 83 (authentication method blocked), got {sw1:02X} {sw2:02X}"
    );
}

// ETSI TS 102 221: referenced data not usable (PIN disabled) -> 69 84.
#[then("the PIN is disabled")]
fn then_pin_disabled(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x84),
        "Expected 69 84 (referenced data not usable / PIN disabled), got {sw1:02X} {sw2:02X}"
    );
}

// 3GPP TS 31.102: authentication error / incorrect MAC -> 98 62.
#[then("SW indicates authentication error")]
fn then_sw_auth_error(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x98, 0x62),
        "Expected 98 62 (authentication error), got {sw1:02X} {sw2:02X}"
    );
}

// ---- Parameterized retry counter steps ----

// 63 CX: verification failed / retry counter query, X retries remaining.
#[then(regex = r"^SW indicates (\d+) retr(?:y|ies) remaining$")]
fn then_sw_retries_remaining(world: &mut SimWorld, remaining: u8) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        sw1, 0x63,
        "Expected SW1=63 (verification failed), got {sw1:02X} {sw2:02X}"
    );
    let expected_sw2 = 0xC0 | (remaining & 0x0F);
    assert_eq!(
        sw2, expected_sw2,
        "Expected {remaining} retries remaining (63 C{remaining:X}), got 63 {sw2:02X}"
    );
}

// ---- Compound SW steps (logical connectives) ----

// 67 00 or 6A 80: wrong length or incorrect data field.
// Used for AUTHENTICATE with malformed RAND/AUTN where the rejection reason
// depends on which check fires first.
#[then("SW indicates wrong length or incorrect data")]
fn then_sw_wrong_length_or_data(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        (sw1, sw2) == (0x67, 0x00) || (sw1, sw2) == (0x6A, 0x80),
        "Expected 67 00 or 6A 80 (wrong length / incorrect data), got {sw1:02X} {sw2:02X}",
    );
}

// 90 00 or 61 XX: command succeeded, possibly with response data pending.
#[then("the command succeeds or response data is available")]
fn then_sw_success_or_61(world: &mut SimWorld) {
    let (sw1, _) = world.last_sw();
    assert!(
        sw1 == 0x90 || sw1 == 0x61,
        "Expected 90 00 or 61 XX, got SW1={sw1:02X}",
    );
}

// 98 62 or 61 XX: authentication error (MAC failure) or valid response.
// Used for AUTHENTICATE with arbitrary test data where the MAC may or may
// not validate, but the command was routed correctly (not rejected as 6A 86).
#[then("SW indicates authentication error or response data is available")]
fn then_sw_auth_error_or_61(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        (sw1, sw2) == (0x98, 0x62) || sw1 == 0x61,
        "Expected 98 62 or 61 XX, got {sw1:02X} {sw2:02X}",
    );
}

#[then(regex = r"^the response data is empty.*$")]
fn then_data_empty(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        data.is_empty(),
        "Expected empty response data, got {} bytes: {:02X?}",
        data.len(),
        data,
    );
}

#[then(regex = r"^the response data is non-empty$")]
fn then_data_non_empty(world: &mut SimWorld) {
    assert!(
        !world.last_data().is_empty(),
        "Expected non-empty response data"
    );
}

#[then(regex = r"^the response data is \[([^\]]+)\].*$")]
fn then_data_is(world: &mut SimWorld, hex: String) {
    let expected = parse_hex(&hex);
    let data = world.last_data();
    assert_eq!(
        data,
        &expected[..],
        "Expected data {expected:02X?}, got {data:02X?}",
    );
}

#[then("the response data matches the provisioned EF.ICCID content")]
fn then_data_matches_iccid(world: &mut SimWorld) {
    let expected = simrs_usim::profile::EF_ICCID.data();
    let data = world.last_data();
    assert_eq!(
        data, expected,
        "Expected EF.ICCID content {expected:02X?}, got {data:02X?}",
    );
}

#[then("the response data matches the last byte of provisioned EF.ICCID")]
fn then_data_matches_iccid_last_byte(world: &mut SimWorld) {
    let iccid = simrs_usim::profile::EF_ICCID.data();
    let expected = iccid[iccid.len() - 1];
    let data = world.last_data();
    assert_eq!(
        data.len(),
        1,
        "Expected 1 byte, got {} bytes: {data:02X?}",
        data.len(),
    );
    assert_eq!(
        data[0], expected,
        "Expected last ICCID byte {expected:02X}, got {:02X}",
        data[0],
    );
}

#[then(regex = r"^the response data starts with tag ([0-9A-Fa-f]{2}).*$")]
fn then_data_starts_with_tag(world: &mut SimWorld, tag_hex: String) {
    let expected = u8::from_str_radix(&tag_hex, 16).unwrap();
    let data = world.last_data();
    assert!(
        !data.is_empty(),
        "Response data is empty, expected tag {expected:02X}",
    );
    assert_eq!(
        data[0], expected,
        "Expected first byte (tag) {expected:02X}, got {:02X}",
        data[0]
    );
}

#[then(regex = r"^SW1 is ([0-9A-Fa-f]{2}) and SW2 is the FCP byte count.*$")]
fn then_sw1_sw2_fcp(world: &mut SimWorld, sw1_hex: String) {
    let expected = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw();
    assert_eq!(sw1, expected, "Expected SW1 {expected:02X}, got {sw1:02X}");
    assert!(sw2 > 0, "Expected non-zero SW2 (FCP byte count)");
}

#[then(regex = r"^the command succeeds and FCP data is returned.*$")]
fn then_sw_9000_fcp(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "Expected 90 00, got {sw1:02X} {sw2:02X}",
    );
    assert!(!world.last_data().is_empty(), "Expected FCP data");
}

#[then("the command succeeds")]
fn then_command_succeeds(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "Expected 90 00, got {sw1:02X} {sw2:02X}",
    );
}

#[then("the command is rejected")]
fn then_command_rejected(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error SW, got {sw1:02X} {sw2:02X}",
    );
}
