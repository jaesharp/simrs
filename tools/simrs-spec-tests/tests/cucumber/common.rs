#![allow(missing_docs)]
//! Step definitions shared across multiple feature files.
//!
//! Contains SIM initialization Given steps, generic APDU When steps,
//! and generic SW/data Then steps used by two or more spec domains.

use cucumber::{given, then, when};
use simrs_spec_tests::{create_sim, create_sim_powered_on, parse_hex, power_cycle};

use super::world::{do_send_apdu, ensure_pin1_verified, sim_mut, SpecWorld};

// =========================================================================
// GIVEN steps -- SIM initialisation (used by many features)
// =========================================================================

#[given(regex = r"^the SIM is initiali[sz]ed with test credentials.*$")]
fn given_sim_initialized_with_test_credentials(world: &mut SpecWorld) {
    world.sim = Some(Box::new(create_sim_powered_on()));
    world.powered_on = true;
}

#[given(regex = r"^the SIM is powered on.*$")]
fn given_sim_powered_on(world: &mut SpecWorld) {
    if !world.powered_on {
        let sim = sim_mut(world);
        power_cycle(sim);
        world.powered_on = true;
    }
}

#[given(regex = r"^the SIM is initiali[sz]ed but NOT yet powered on$")]
fn given_sim_not_powered_on(world: &mut SpecWorld) {
    world.sim = Some(Box::new(create_sim()));
    world.powered_on = false;
}

#[given(regex = r"^the SIM is initiali[sz]ed with:$")]
fn given_sim_initialized_with(world: &mut SpecWorld) {
    world.sim = Some(Box::new(create_sim_powered_on()));
    world.powered_on = true;
}

#[given(regex = r"^the SIM is initiali[sz]ed with Milenage credentials:$")]
fn given_sim_initialized_milenage(world: &mut SpecWorld) {
    world.sim = Some(Box::new(create_sim_powered_on()));
    world.powered_on = true;
}

#[given(regex = r"^MF is (?:implicitly selected|the current DF).*$")]
fn given_mf_selected(world: &mut SpecWorld) {
    // MF is implicitly selected after power-on; no-op.
    let _ = world;
}

#[given(regex = r"^PIN1 \(P2=0x01\) is configured:$")]
fn given_pin1_configured(world: &mut SpecWorld) {
    // Already done by create_sim() / create_sim_powered_on().
    let _ = world;
}

#[given(regex = r"^the MF filesystem contains:$")]
fn given_mf_filesystem(world: &mut SpecWorld) {
    // Already configured by create_sim_powered_on().
    ensure_pin1_verified(world);
}

// =========================================================================
// WHEN steps -- generic APDU send (used by many features)
// =========================================================================

#[when(regex = r#"^I send .+ "([^"]+)"$"#)]
fn when_send_apdu_quoted(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r"^I send (?:APDU|SELECT|READ BINARY|UPDATE BINARY|READ RECORD|TERMINAL PROFILE|GET RESPONSE|STATUS|FETCH|TERMINAL RESPONSE|ENVELOPE)\b.* \[([^\]]*)\]$"
)]
fn when_send_apdu_bracketed(world: &mut SpecWorld, hex: String) {
    let cmd = parse_hex(&hex);
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^the SIM receives a power cycle.*$")]
fn when_power_cycle(world: &mut SpecWorld) {
    let sim = sim_mut(world);
    power_cycle(sim);
    world.powered_on = true;
    world.last_sw = None;
    world.last_data.clear();
    world.last_ignored = false;
}

// =========================================================================
// THEN steps -- generic SW and response data checks
// =========================================================================

#[then(regex = r#"^SW is "([0-9A-Fa-f]{2}) ([0-9A-Fa-f]{2})"$"#)]
fn then_sw_is_quoted(world: &mut SpecWorld, sw1_hex: String, sw2_hex: String) {
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw.expect("No SW available (APDU was ignored?)");
    assert_eq!(
        (sw1, sw2),
        (expected_sw1, expected_sw2),
        "Expected SW {expected_sw1:02X} {expected_sw2:02X}, got {sw1:02X} {sw2:02X}",
    );
}

#[then(regex = r"^SW is ([0-9A-Fa-f]{2}) ([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_sw_is(world: &mut SpecWorld, sw1_hex: String, sw2_hex: String) {
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw.expect("No SW available (APDU was ignored?)");
    assert_eq!(
        (sw1, sw2),
        (expected_sw1, expected_sw2),
        "Expected SW {expected_sw1:02X} {expected_sw2:02X}, got {sw1:02X} {sw2:02X}",
    );
}

#[then(regex = r"^SW1 is ([0-9A-Fa-f]{2})(?: \(.*\))?$")]
fn then_sw1_is(world: &mut SpecWorld, sw1_hex: String) {
    let expected = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let (sw1, _) = world.last_sw.expect("No SW available");
    assert_eq!(sw1, expected, "Expected SW1 {expected:02X}, got {sw1:02X}");
}

#[then(regex = r"^SW indicates (?:an )?error.*$")]
fn then_sw_error(world: &mut SpecWorld) {
    if world.last_ignored {
        return;
    }
    let (sw1, _sw2) = world.last_sw.expect("No SW available");
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error SW"
    );
}

#[then(regex = r"^the response data is empty.*$")]
fn then_data_empty(world: &mut SpecWorld) {
    assert!(
        world.last_data.is_empty(),
        "Expected empty response data, got {} bytes",
        world.last_data.len(),
    );
}

#[then(regex = r"^the response data is non-empty$")]
fn then_data_non_empty(world: &mut SpecWorld) {
    assert!(
        !world.last_data.is_empty(),
        "Expected non-empty response data"
    );
}

#[then(regex = r"^SW is 90 00 or 61 XX.*$")]
fn then_sw_9000_or_61(world: &mut SpecWorld) {
    let (sw1, _) = world.last_sw.expect("No SW");
    assert!(
        sw1 == 0x90 || sw1 == 0x61,
        "Expected SW1 90 or 61, got {sw1:02X}",
    );
}
