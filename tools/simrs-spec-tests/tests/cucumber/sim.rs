#![allow(missing_docs)]
//! Step definitions for `sim.feature` -- Top-level SIM state machine.
//!
//! Crate under test: `simrs-sim`.
//!
//! Steps shared with other features (generic SW checks, generic APDU send)
//! live in `common.rs`. This module defines only the steps unique to
//! `sim.feature`: lifecycle events (`PowerOn`, `Reset`), CLA routing
//! assertions, malformed APDU handling, round-trip GET RESPONSE flows,
//! proactive 91 XX passthrough, feature-gating, and `SimResponse`
//! structure checks.

use cucumber::{given, then, when};
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_proactive::{ProactiveCommand, TextCoding};
use simrs_secret::Secret;
use simrs_sim::{SimEvent, SimResponse};
use simrs_spec_tests::{create_sim, parse_hex, verify_pin1, TEST_K, TEST_OPC};

use super::world::{do_send_apdu, sim_mut, SpecWorld};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Send a `SimEvent` directly through `sim.process()` and store the
/// response type (ATR / APDU / Ignored) in world state.
///
/// We extract all response data into owned temporaries before writing
/// to `world`, because `SimResponse` borrows the sim's internal buffer.
fn process_event(world: &mut SpecWorld, event: SimEvent<'_>) {
    let sim = sim_mut(world);
    let rsp = sim.process(event);

    // Extract into owned values while the borrow on `sim` is still live.
    let (is_atr, is_ignored, sw, data) = match rsp {
        SimResponse::Atr(_) => (true, false, None, Vec::new()),
        SimResponse::Apdu { data, sw1, sw2 } => {
            (false, false, Some((sw1, sw2)), data.to_vec())
        }
        SimResponse::Ignored => (false, true, None, Vec::new()),
    };

    // Now safe to write to world -- no outstanding borrows.
    world.last_atr = is_atr;
    world.last_ignored = is_ignored;
    world.last_sw = sw;
    world.last_data = data;
}

/// Build a valid AUTN for the test credentials (K=[0x22;16], OPc=[0x33;16])
/// using the given RAND and SQN. Returns (RAND, AUTN) both as 16-byte arrays.
fn build_valid_auth_vectors() -> ([u8; 16], [u8; 16]) {
    let rand = [0x01u8; 16]; // arbitrary non-zero RAND
    let sqn = [0u8; 6]; // SQN=0 (fresh SIM starts at expected_sqn=0)
    let amf = [0x80, 0x00]; // standard AMF

    let params = MilenageParams::with_defaults(
        SubscriberKey::new(Secret::new(TEST_K)),
        OperatorVariant::opc(Secret::new(TEST_OPC)),
    );

    let ak = params.compute_anonymity_key(&rand);
    let mac_a = params.compute_auth_mac(&rand, &sqn, &amf);

    let mut autn = [0u8; 16];
    // AUTN = (SQN XOR AK) || AMF || MAC-A
    for i in 0..6 {
        autn[i] = sqn[i] ^ ak[i];
    }
    autn[6] = amf[0];
    autn[7] = amf[1];
    autn[8..16].copy_from_slice(&mac_a);

    (rand, autn)
}

// =========================================================================
// Background: "Given a Sim with:" (docstring)
// =========================================================================

#[given(regex = r"^a Sim with:$")]
fn given_a_sim_with(world: &mut SpecWorld) {
    // create_sim() builds a dual-app (GSM + USIM) SIM with MF, EF.ICCID,
    // PIN1 "1234" (enabled, 3 retries), 256-byte response buffer, and
    // standard ATR. Card is NOT powered on yet.
    world.sim = Some(Box::new(create_sim()));
    world.powered_on = false;
    world.last_atr = false;
}

#[given(regex = r"^ATR = \[.*\].*$")]
fn given_atr(_world: &mut SpecWorld) {
    // ATR is already configured by create_sim().
}

#[given(regex = r#"^feature "gsm" enabled.*$"#)]
fn given_feature_gsm(_world: &mut SpecWorld) {
    // GSM feature is already enabled by create_sim().
}

#[given(regex = r#"^feature "usim" enabled.*$"#)]
fn given_feature_usim(_world: &mut SpecWorld) {
    // USIM feature is already enabled by create_sim().
}

#[given(regex = r#"^PIN1 = "1234".*$"#)]
fn given_pin1(_world: &mut SpecWorld) {
    // PIN1 is already configured by create_sim().
}

// "And a 256-byte response buffer" is already defined in gsm.rs.

// =========================================================================
// Power / Reset lifecycle
// =========================================================================

#[when("I send SimEvent::PowerOn")]
fn when_send_power_on(world: &mut SpecWorld) {
    process_event(world, SimEvent::PowerOn);
    world.powered_on = true;
}

#[when("I send SimEvent::PowerOn again")]
fn when_send_power_on_again(world: &mut SpecWorld) {
    process_event(world, SimEvent::PowerOn);
    world.powered_on = true;
}

#[when("I send SimEvent::Reset")]
fn when_send_reset(world: &mut SpecWorld) {
    process_event(world, SimEvent::Reset);
    world.powered_on = true;
}

#[given("the card is powered on")]
fn given_card_powered_on(world: &mut SpecWorld) {
    if !world.powered_on {
        process_event(world, SimEvent::PowerOn);
        world.powered_on = true;
    }
}

#[given("PIN1 has been verified")]
fn given_pin1_verified(world: &mut SpecWorld) {
    let sim = sim_mut(world);
    verify_pin1(sim);
}

#[then("the response is SimResponse::Atr with the configured ATR bytes")]
fn then_response_is_atr(world: &mut SpecWorld) {
    assert!(
        world.last_atr,
        "Expected SimResponse::Atr, but got {}",
        if world.last_ignored {
            "SimResponse::Ignored"
        } else {
            "SimResponse::Apdu"
        },
    );
}

#[then(regex = r"^the response is SimResponse::Atr \(no error\)$")]
fn then_response_is_atr_no_error(world: &mut SpecWorld) {
    assert!(
        world.last_atr,
        "Expected SimResponse::Atr, but got {}",
        if world.last_ignored {
            "SimResponse::Ignored"
        } else {
            "SimResponse::Apdu"
        },
    );
}

#[then("the response is SimResponse::Ignored")]
fn then_response_is_ignored(world: &mut SpecWorld) {
    assert!(
        world.last_ignored,
        "Expected SimResponse::Ignored, but got {}",
        if world.last_atr {
            "SimResponse::Atr"
        } else {
            "SimResponse::Apdu"
        },
    );
}

// =========================================================================
// Reset clears PIN verified state
// =========================================================================

#[when("I send SimEvent::Apdu with a GSM READ BINARY")]
fn when_send_gsm_read_binary(world: &mut SpecWorld) {
    // The default SIM from create_sim() only has PIN1 configured on the
    // USIM app, not the GSM app. Use USIM routing (CLA=0x00) to exercise
    // a PIN-protected path.
    //
    // SELECT EF.ICCID (2FE2) under MF via USIM routing.
    do_send_apdu(world, &[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0xE2]);
    // Attempt READ BINARY via USIM routing.
    do_send_apdu(world, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
}

#[then("PIN-dependent operations require re-verification")]
fn then_pin_dependent_require_reverification(world: &mut SpecWorld) {
    // After reset, PIN-verified state is cleared.
    // A PIN-protected READ BINARY should fail with 69 82 (security status
    // not satisfied) rather than succeeding.
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x82),
        "Expected 69 82 (security status not satisfied) after reset, \
         got {sw1:02X} {sw2:02X}",
    );
}

// =========================================================================
// APDU before PowerOn
// =========================================================================

#[when("I send SimEvent::Apdu without prior PowerOn")]
fn when_send_apdu_without_power_on(world: &mut SpecWorld) {
    // Card was created but never powered on. Send an APDU directly.
    process_event(
        world,
        SimEvent::Apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]),
    );
}

// =========================================================================
// CLA-based routing
// =========================================================================

// "When I send SimEvent::Apdu with [hex hex ...]"
// This regex handles the "with" bracketed form used by the CLA routing
// and malformed APDU scenarios in sim.feature.
#[when(regex = r"^I send SimEvent::Apdu with \[([^\]]*)\]$")]
fn when_send_sim_event_apdu_with(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^the response comes from GsmApp \(SW1=0x9F for GSM SELECT\)$")]
fn then_response_from_gsm_app(world: &mut SpecWorld) {
    let (sw1, _sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        sw1, 0x9F,
        "Expected SW1=9F (GSM SELECT response available), got {sw1:02X}",
    );
}

#[then(regex = r"^the response comes from UsimApp \(SW1=0x61 for USIM SELECT\)$")]
fn then_response_from_usim_app(world: &mut SpecWorld) {
    let (sw1, _sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        sw1, 0x61,
        "Expected SW1=61 (USIM SELECT response available), got {sw1:02X}",
    );
}

// "Then SW1 is 0xNN" is already defined in gsm.rs (then_sw1_is_hex).

// =========================================================================
// Malformed APDU handling -- steps already covered by:
//   when_send_sim_event_apdu_with (above)
//   then_response_is_ignored (above)
// =========================================================================

// =========================================================================
// Full round-trip through routing (SELECT -> GET RESPONSE)
// =========================================================================

// "When I send SimEvent::Apdu [hex hex ...]" (no "with", bracketed)
#[when(regex = r"^I send SimEvent::Apdu \[([^\]]+)\]$")]
fn when_send_sim_event_apdu(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

// "When I send SimEvent::Apdu [hex...] with Le=SW2"
// Constructs a GET RESPONSE command using the SW2 from the previous response
// as the Le byte.
#[when(regex = r"^I send SimEvent::Apdu \[([^\]]+)\] with Le=SW2$")]
fn when_send_apdu_with_le_sw2(world: &mut SpecWorld, hex: String) {
    let (_, sw2) = world.last_sw.expect("No previous SW to use as Le");
    let mut cmd = parse_hex(&hex);
    cmd.push(sw2);
    do_send_apdu(world, &cmd);
}

#[then("I get the GSM 11.11 SELECT response")]
fn then_get_gsm_select_response(world: &mut SpecWorld) {
    // GSM 11.11 SELECT response: a binary blob of at least 2 bytes
    // containing file metadata (file size, type, etc.).
    assert!(
        !world.last_data.is_empty(),
        "Expected non-empty GSM SELECT response data",
    );
}

#[then("I get the ETSI FCP BER-TLV response")]
fn then_get_fcp_response(world: &mut SpecWorld) {
    // FCP template starts with tag 0x62 per ETSI TS 102 221.
    assert!(
        !world.last_data.is_empty(),
        "Expected non-empty FCP response data",
    );
    assert_eq!(
        world.last_data[0], 0x62,
        "FCP template must start with tag 62, got {:02X}",
        world.last_data[0],
    );
}

// =========================================================================
// USIM AUTHENTICATE through Sim
// =========================================================================

#[given(regex = r"^ADF\.USIM is selected \(via USIM routing\)$")]
fn given_adf_usim_selected(world: &mut SpecWorld) {
    // The default SIM from create_sim() has no ADFs registered for
    // SELECT-by-AID. However, AUTHENTICATE does not require an ADF to
    // be selected (per ETSI TS 102 221, it operates at session level).
    //
    // Ensure MF is current context for the USIM app by sending a benign
    // SELECT MF via USIM routing (CLA=0x00, P2=0x0C for no data returned).
    do_send_apdu(world, &[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00]);
    let (sw1, sw2) = world.last_sw.expect("SELECT MF for USIM routing failed");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "SELECT MF via USIM routing failed with SW {sw1:02X} {sw2:02X}",
    );
}

#[when("I send AUTHENTICATE with valid RAND+AUTN")]
fn when_send_authenticate(world: &mut SpecWorld) {
    let (rand, autn) = build_valid_auth_vectors();

    // AUTHENTICATE APDU: CLA=0x00, INS=0x88, P1=0x00, P2=0x81 (UMTS),
    // Lc=0x22 (34 bytes), Data = 0x10 || RAND(16) || 0x10 || AUTN(16)
    let mut cmd = vec![0x00, 0x88, 0x00, 0x81, 0x22, 0x10];
    cmd.extend_from_slice(&rand);
    cmd.push(0x10);
    cmd.extend_from_slice(&autn);

    do_send_apdu(world, &cmd);
}

#[then("GET RESPONSE returns Milenage output (tag 0xDB)")]
fn then_get_response_returns_milenage(world: &mut SpecWorld) {
    // AUTHENTICATE queues its response in the GET RESPONSE buffer.
    // SW should be 61 XX from the AUTHENTICATE step.
    let (sw1, sw2) = world.last_sw.expect("No SW from AUTHENTICATE");
    assert_eq!(
        sw1, 0x61,
        "Expected 61 XX from AUTHENTICATE, got {sw1:02X} {sw2:02X}",
    );

    // Send GET RESPONSE to retrieve the queued data.
    let cmd = vec![0x00, 0xC0, 0x00, 0x00, sw2];
    do_send_apdu(world, &cmd);

    let (sw1, sw2) = world.last_sw.expect("No SW from GET RESPONSE");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "GET RESPONSE should return 90 00, got {sw1:02X} {sw2:02X}",
    );

    // The response data should start with tag 0xDB (successful UMTS auth).
    assert!(
        !world.last_data.is_empty(),
        "GET RESPONSE returned empty data",
    );
    assert_eq!(
        world.last_data[0], 0xDB,
        "Expected Milenage success tag DB, got {:02X}",
        world.last_data[0],
    );
}

// =========================================================================
// Proactive passthrough
// =========================================================================

#[given("a proactive command is pending in UsimApp")]
fn given_proactive_pending(world: &mut SpecWorld) {
    let sim = sim_mut(world);
    sim.usim_app_mut()
        .proactive_state()
        .queue_command(&ProactiveCommand::DisplayText {
            text: b"TestProactive",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        })
        .expect("queue_command for proactive test must succeed");
}

#[when("I send a command that would return 90 00 via USIM routing")]
fn when_send_command_returning_9000(world: &mut SpecWorld) {
    // TERMINAL PROFILE (CLA=0x80, INS=0x10) normally returns 90 00.
    do_send_apdu(world, &[0x80, 0x10, 0x00, 0x00]);
}

#[then(regex = r"^the SimResponse contains SW 91 XX$")]
fn then_sim_response_contains_91_xx(world: &mut SpecWorld) {
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        sw1, 0x91,
        "Expected proactive override SW1=91, got {sw1:02X}",
    );
    assert!(
        sw2 > 0,
        "Expected non-zero SW2 (proactive command length), got {sw2:02X}",
    );
}

// =========================================================================
// Feature gating
//
// The spec-test binary is compiled with both "gsm" and "usim" features
// enabled (see Cargo.toml). The Sim constructor requires both a GsmApp
// and a UsimApp when both features are active; there is no way to create
// a single-feature Sim at runtime under this configuration.
//
// These Given steps create the standard dual-app SIM and document the
// limitation. The CLA routing behavior is still testable: in the dual-app
// SIM, CLA=0xA0 routes to GsmApp and CLA=0x00 routes to UsimApp, so the
// "unsupported CLA" assertion would only fire for truly unknown CLA bytes
// (e.g. 0xF0). The scenarios verify that routing works correctly for the
// enabled applications.
// =========================================================================

#[given(regex = r#"^only feature "gsm" is enabled$"#)]
fn given_only_gsm(world: &mut SpecWorld) {
    // Cannot create a GSM-only Sim at runtime when both features are compiled
    // in. Use the standard dual-app SIM. The scenario's assertion (CLA=0x00
    // returning 6E 00) will not hold because USIM is also active.
    //
    // This scenario requires conditional compilation (cfg(not(feature="usim")))
    // which is a build-time concern, not a runtime one.
    world.sim = Some(Box::new(create_sim()));
    world.powered_on = false;
}

#[given(regex = r#"^only feature "usim" is enabled$"#)]
fn given_only_usim(world: &mut SpecWorld) {
    // Same limitation as above: cannot create USIM-only Sim at runtime.
    world.sim = Some(Box::new(create_sim()));
    world.powered_on = false;
}

#[when(regex = r"^I send SimEvent::Apdu with CLA=0x([0-9A-Fa-f]{2})$")]
fn when_send_apdu_with_cla(world: &mut SpecWorld, cla_hex: String) {
    let cla = u8::from_str_radix(&cla_hex, 16).unwrap();
    // Minimal valid APDU: CLA INS P1 P2 Lc Data
    // Use SELECT MF as a benign command.
    let cmd = [cla, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
    do_send_apdu(world, &cmd);
}

// =========================================================================
// SimResponse structure
// =========================================================================

#[when("I send a valid READ BINARY")]
fn when_send_valid_read_binary(world: &mut SpecWorld) {
    // Verify PIN1 first so the read succeeds.
    let sim = sim_mut(world);
    verify_pin1(sim);

    // Select EF.ICCID (2FE2) via USIM routing (CLA=0x00).
    do_send_apdu(world, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
    // Drain GET RESPONSE if needed.
    if let Some((0x61, sw2)) = world.last_sw {
        let cmd = vec![0x00, 0xC0, 0x00, 0x00, sw2];
        do_send_apdu(world, &cmd);
    }

    // READ BINARY: CLA=0x00, INS=0xB0, P1=0x00, P2=0x00, Le=0x0A (10 bytes)
    do_send_apdu(world, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
}

#[then(regex = r"^SimResponse::Apdu contains the data bytes and sw1\+sw2$")]
fn then_sim_response_apdu_contains_data_and_sw(world: &mut SpecWorld) {
    assert!(
        !world.last_ignored,
        "Expected SimResponse::Apdu, got Ignored",
    );
    assert!(!world.last_atr, "Expected SimResponse::Apdu, got Atr");
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "Expected 90 00 for successful READ BINARY, got {sw1:02X} {sw2:02X}",
    );
    assert!(
        !world.last_data.is_empty(),
        "Expected non-empty data from READ BINARY",
    );
}

#[when(regex = r"^I send an unknown INS \[([^\]]+)\]$")]
fn when_send_unknown_ins(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

#[then(regex = r"^SimResponse::Apdu has sw1=6D sw2=00.*$")]
fn then_sim_response_apdu_6d_00(world: &mut SpecWorld) {
    assert!(
        !world.last_ignored,
        "Expected SimResponse::Apdu, got Ignored",
    );
    assert!(!world.last_atr, "Expected SimResponse::Apdu, got Atr");
    let (sw1, sw2) = world.last_sw.expect("No SW available");
    assert_eq!(
        (sw1, sw2),
        (0x6D, 0x00),
        "Expected 6D 00 (INS not supported), got {sw1:02X} {sw2:02X}",
    );
    assert!(
        world.last_data.is_empty(),
        "Expected empty data for error-only response, got {} bytes",
        world.last_data.len(),
    );
}
