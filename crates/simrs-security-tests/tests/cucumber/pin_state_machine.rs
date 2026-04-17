#![allow(missing_docs)]
//! PIN/PUK state machine step definitions.
//!
//! Covers VERIFY, CHANGE, DISABLE, ENABLE, UNBLOCK lifecycle,
//! power cycle persistence, and attack scenarios per:
//!   - ETSI TS 102 221 V18.0.0 clauses 11.1.9 -- 11.1.13
//!   - `SIMuraI` (USENIX 2024)

use cucumber::{given, then, when};
use simrs_pin::PinKey;
use simrs_security_tests::{
    apdu, block_pin1, disable_pin1, enable_pin1, send_apdu_sw, submit_wrong_pin1, submit_wrong_puk,
    verify_pin1,
};

use super::snapshot::{
    reserve_pin_change, reserve_pin_toggle, reserve_pin_unblock, reserve_pin_verify,
};
use super::world::{do_send_apdu, query_pin1_retries, query_puk1_retries, SimWorld};

/// Map a PIN name string to a `PinKey`.
fn parse_pin_name(name: &str) -> PinKey {
    match name {
        "PIN1" => PinKey::PIN1,
        "PIN2" => PinKey::PIN2,
        _ => panic!("Unknown PIN reference: {name:?}"),
    }
}

// =========================================================================
// GIVEN steps -- PIN state preconditions
// =========================================================================

#[given(regex = r"^PIN1 is blocked.*$")]
fn given_pin1_blocked(world: &mut SimWorld) {
    let sim = world.sim_mut();
    block_pin1(sim);
}

#[given("PIN1 has been disabled with correct PIN")]
fn given_pin1_disabled(world: &mut SimWorld) {
    let sim = world.sim_mut();
    disable_pin1(sim);
}

#[given("PIN1 has been re-enabled with correct PIN")]
fn given_pin1_reenabled(world: &mut SimWorld) {
    let sim = world.sim_mut();
    enable_pin1(sim);
}

#[given("PIN1 has been verified with correct PIN")]
fn given_pin1_verified(world: &mut SimWorld) {
    let sim = world.sim_mut();
    verify_pin1(sim);
}

#[given(regex = r"^PIN1 has been submitted wrong (\d+) times?$")]
fn given_pin1_wrong_n(world: &mut SimWorld, n: usize) {
    let sim = world.sim_mut();
    submit_wrong_pin1(sim, n);
}

#[given(regex = r"^(\d+) wrong PUK attempts? (?:have|has) been made.*$")]
fn given_puk_wrong_n(world: &mut SimWorld, n: usize) {
    let sim = world.sim_mut();
    submit_wrong_puk(sim, n);
}

// =========================================================================
// WHEN steps -- semantic PIN operations
// =========================================================================

#[when(regex = r#"^I verify (PIN1|PIN2) with "(\d+)"$"#)]
fn when_verify_pin(world: &mut SimWorld, pin_name: String, digits: String) {
    let key = parse_pin_name(&pin_name);
    let cmd = apdu::verify(key, &digits).build();
    do_send_apdu(world, &cmd);
    reserve_pin_verify(&mut world.reservations, key);
}

#[when(regex = r"^I query (PIN1|PIN2) retry counter$")]
fn when_query_pin_retries(world: &mut SimWorld, pin_name: String) {
    let cmd = apdu::verify_query(parse_pin_name(&pin_name)).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r#"^I change (PIN1|PIN2) from "(\d+)" to "(\d+)"$"#)]
fn when_change_pin(world: &mut SimWorld, pin_name: String, old_pin: String, new_pin: String) {
    let key = parse_pin_name(&pin_name);
    let cmd = apdu::change_pin(key, &old_pin, &new_pin).build();
    do_send_apdu(world, &cmd);
    reserve_pin_change(&mut world.reservations, key);
}

#[when(regex = r#"^I disable (PIN1|PIN2) with "(\d+)"$"#)]
fn when_disable_pin(world: &mut SimWorld, pin_name: String, digits: String) {
    let key = parse_pin_name(&pin_name);
    let cmd = apdu::disable_pin(key, &digits).build();
    do_send_apdu(world, &cmd);
    reserve_pin_toggle(&mut world.reservations, key);
}

#[when(regex = r#"^I enable (PIN1|PIN2) with "(\d+)"$"#)]
fn when_enable_pin(world: &mut SimWorld, pin_name: String, digits: String) {
    let key = parse_pin_name(&pin_name);
    let cmd = apdu::enable_pin(key, &digits).build();
    do_send_apdu(world, &cmd);
    reserve_pin_toggle(&mut world.reservations, key);
}

#[when(regex = r#"^I unblock (PIN1|PIN2) with PUK "(\d+)" new PIN "(\d+)"$"#)]
fn when_unblock_pin(world: &mut SimWorld, pin_name: String, puk: String, new_pin: String) {
    let key = parse_pin_name(&pin_name);
    let cmd = apdu::unblock(key, &puk, &new_pin).build();
    do_send_apdu(world, &cmd);
    reserve_pin_unblock(&mut world.reservations, key);
}

#[when(regex = r"^I query (PUK1|PUK2) retry counter$")]
fn when_query_puk_retries(world: &mut SimWorld, puk_name: String) {
    // ETSI TS 102 221 V18.0.0 clause 11.1.13: RESET RETRY COUNTER uses the same
    // P2 reference key as the PIN it unblocks (PUK1 -> P2=0x01 = PIN1).
    let key = match puk_name.as_str() {
        "PUK1" => PinKey::PIN1,
        "PUK2" => PinKey::PIN2,
        _ => panic!("Unknown PUK reference: {puk_name:?}"),
    };
    let cmd = apdu::unblock_query(key).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r#"^I verify (PIN1|PIN2) with "(\d+)" (\d+) times$"#)]
fn when_verify_pin_n_times(world: &mut SimWorld, pin_name: String, digits: String, count: usize) {
    let key = parse_pin_name(&pin_name);
    let cmd = apdu::verify(key, &digits).build();
    for _ in 0..count {
        do_send_apdu(world, &cmd);
    }
    reserve_pin_verify(&mut world.reservations, key);
}

#[when(regex = r#"^I unblock (PIN1|PIN2) with PUK "(\d+)" new PIN "(\d+)" (\d+) times$"#)]
fn when_unblock_pin_n_times(
    world: &mut SimWorld,
    pin_name: String,
    puk: String,
    new_pin: String,
    count: usize,
) {
    let key = parse_pin_name(&pin_name);
    let cmd = apdu::unblock(key, &puk, &new_pin).build();
    for _ in 0..count {
        do_send_apdu(world, &cmd);
    }
    reserve_pin_unblock(&mut world.reservations, key);
}

// =========================================================================
// WHEN steps -- malformed APDU mutations (interposer-style)
// =========================================================================

/// Build a single-PIN command (VERIFY, DISABLE, or ENABLE) for PIN1.
///
/// Centralises the VERIFY|DISABLE|ENABLE dispatch so that the 3-way match
/// lives in one place. If you add a new command to the regex alternations
/// below, add it here too.
fn build_single_pin_cmd(cmd_name: &str, digits: &str) -> apdu::ApduCmd {
    match cmd_name {
        "VERIFY" => apdu::verify(PinKey::PIN1, digits),
        "DISABLE" => apdu::disable_pin(PinKey::PIN1, digits),
        "ENABLE" => apdu::enable_pin(PinKey::PIN1, digits),
        other => panic!(
            "build_single_pin_cmd: unhandled {other:?}; \
             add it to both the regex and this match arm",
        ),
    }
}

/// Truncate an APDU's data field to `n` bytes, with a bounds check.
fn truncate_data(base: apdu::ApduCmd, n: usize, label: &str) -> Vec<u8> {
    assert!(
        n < base.data.len(),
        "Truncation target {n} must be less than data field length {} for {label}",
        base.data.len(),
    );
    let truncated = base.data[..n].to_vec();
    base.with_data(&truncated).build()
}

#[when(
    regex = r#"^I send (VERIFY|DISABLE|ENABLE) PIN1 with "(\d+)" with data truncated to (\d+) bytes$"#
)]
fn when_pin_cmd_truncated(world: &mut SimWorld, cmd_name: String, digits: String, n: usize) {
    let base = build_single_pin_cmd(&cmd_name, &digits);
    let cmd = truncate_data(base, n, &cmd_name);
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r#"^I send CHANGE PIN1 from "(\d+)" to "(\d+)" with data truncated to (\d+) bytes$"#
)]
fn when_change_truncated(world: &mut SimWorld, old: String, new_pin: String, n: usize) {
    let base = apdu::change_pin(PinKey::PIN1, &old, &new_pin);
    let cmd = truncate_data(base, n, "CHANGE");
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r#"^I send UNBLOCK PIN1 with PUK "(\d+)" new PIN "(\d+)" with data truncated to (\d+) bytes$"#
)]
fn when_unblock_truncated(world: &mut SimWorld, puk: String, new_pin: String, n: usize) {
    let base = apdu::unblock(PinKey::PIN1, &puk, &new_pin);
    let cmd = truncate_data(base, n, "UNBLOCK");
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r#"^I send (VERIFY|DISABLE|ENABLE) for unregistered P2=0x([0-9A-Fa-f]{2}) with "(\d+)"$"#
)]
fn when_pin_cmd_bad_p2(world: &mut SimWorld, cmd_name: String, p2_hex: String, digits: String) {
    let p2 = u8::from_str_radix(&p2_hex, 16).unwrap();
    let cmd = build_single_pin_cmd(&cmd_name, &digits).with_p2(p2).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r#"^I send CHANGE for unregistered P2=0x([0-9A-Fa-f]{2}) from "(\d+)" to "(\d+)"$"#)]
fn when_change_bad_p2(world: &mut SimWorld, p2_hex: String, old: String, new_pin: String) {
    let p2 = u8::from_str_radix(&p2_hex, 16).unwrap();
    let cmd = apdu::change_pin(PinKey::PIN1, &old, &new_pin)
        .with_p2(p2)
        .build();
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r#"^I send UNBLOCK for unregistered P2=0x([0-9A-Fa-f]{2}) with PUK "(\d+)" new PIN "(\d+)"$"#
)]
fn when_unblock_bad_p2(world: &mut SimWorld, p2_hex: String, puk: String, new_pin: String) {
    let p2 = u8::from_str_radix(&p2_hex, 16).unwrap();
    let cmd = apdu::unblock(PinKey::PIN1, &puk, &new_pin)
        .with_p2(p2)
        .build();
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r#"^I send (VERIFY|DISABLE|ENABLE) PIN1 with "(\d+)" with P1 set to 0x([0-9A-Fa-f]{2})$"#
)]
fn when_pin_cmd_bad_p1(world: &mut SimWorld, cmd_name: String, digits: String, p1_hex: String) {
    let p1 = u8::from_str_radix(&p1_hex, 16).unwrap();
    let cmd = build_single_pin_cmd(&cmd_name, &digits).with_p1(p1).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r#"^I send CHANGE PIN1 from "(\d+)" to "(\d+)" with P1 set to 0x([0-9A-Fa-f]{2})$"#)]
fn when_change_bad_p1(world: &mut SimWorld, old: String, new_pin: String, p1_hex: String) {
    let p1 = u8::from_str_radix(&p1_hex, 16).unwrap();
    let cmd = apdu::change_pin(PinKey::PIN1, &old, &new_pin)
        .with_p1(p1)
        .build();
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r#"^I send UNBLOCK PIN1 with PUK "(\d+)" new PIN "(\d+)" with P1 set to 0x([0-9A-Fa-f]{2})$"#
)]
fn when_unblock_bad_p1(world: &mut SimWorld, puk: String, new_pin: String, p1_hex: String) {
    let p1 = u8::from_str_radix(&p1_hex, 16).unwrap();
    let cmd = apdu::unblock(PinKey::PIN1, &puk, &new_pin)
        .with_p1(p1)
        .build();
    do_send_apdu(world, &cmd);
}

// =========================================================================
// THEN steps -- PIN/PUK state assertions
// =========================================================================

#[then(regex = r"^PIN1 retry counter is (?:still |reset to )?(\d+)$")]
fn then_pin1_retries(world: &mut SimWorld, expected: u8) {
    let retries = query_pin1_retries(world);
    assert_eq!(
        retries, expected,
        "Expected PIN1 retries = {expected}, got {retries}"
    );
}

#[then("PIN1 retry counter is not decremented")]
fn then_pin1_not_decremented(world: &mut SimWorld) {
    // When PIN is disabled, the counter should still be at max (3).
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    let retries = pm.retries(PinKey::PIN1).unwrap_or(0);
    assert_eq!(
        retries, 3,
        "Expected PIN1 retries = 3 (not decremented), got {retries}"
    );
}

#[then("PIN1 verification flag is set for this session")]
fn then_pin1_verified_flag(world: &mut SimWorld) {
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    if pm.is_enabled(PinKey::PIN1) {
        // PIN1 is enabled: the verified flag must be explicitly set.
        assert!(
            pm.is_verified(PinKey::PIN1),
            "Expected PIN1 verified flag to be set after correct VERIFY",
        );
    }
    // If PIN1 is disabled, the security condition is unconditionally satisfied
    // (ETSI TS 102 221 V18.0.0 clause 11.1.9). That case is tested separately by
    // "the PIN1 security condition is satisfied without explicit VERIFY".
}

#[then("PIN1 verification flag is not set")]
fn then_pin1_not_verified(world: &mut SimWorld) {
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    let enabled = pm.is_enabled(PinKey::PIN1);
    if enabled {
        assert!(
            !pm.is_verified(PinKey::PIN1),
            "Expected PIN1 verification flag NOT set"
        );
    }
}

#[then("PIN1 is blocked")]
fn then_pin1_is_blocked(world: &mut SimWorld) {
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    assert!(pm.is_blocked(PinKey::PIN1), "Expected PIN1 to be blocked");
}

#[then("PIN1 remains blocked")]
fn then_pin1_remains_blocked(world: &mut SimWorld) {
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    assert!(
        pm.is_blocked(PinKey::PIN1),
        "Expected PIN1 to remain blocked"
    );
}

#[then(regex = r"^PIN1 is (?:still )?enabled$")]
fn then_pin1_enabled(world: &mut SimWorld) {
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    assert!(pm.is_enabled(PinKey::PIN1), "Expected PIN1 to be enabled");
}

#[then(regex = r"^PIN1 is (?:still )?disabled$")]
fn then_pin1_disabled(world: &mut SimWorld) {
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    assert!(!pm.is_enabled(PinKey::PIN1), "Expected PIN1 to be disabled");
}

#[then(regex = r"^PUK1 retry counter is (?:still )?(\d+)$")]
fn then_puk1_retries(world: &mut SimWorld, expected: u8) {
    let retries = query_puk1_retries(world);
    assert_eq!(
        retries, expected,
        "Expected PUK1 retries = {expected}, got {retries}"
    );
}

#[then("the PIN1 security condition is satisfied without explicit VERIFY")]
fn then_pin1_security_satisfied(world: &mut SimWorld) {
    let pm = world.sim_mut().usim_app_mut().pin_manager();
    assert!(
        pm.is_verified(PinKey::PIN1),
        "Expected PIN1 security condition satisfied"
    );
}

#[then(regex = r#"^verifying (PIN1|PIN2) with "(\d+)" succeeds$"#)]
fn then_verify_succeeds(world: &mut SimWorld, pin_name: String, digits: String) {
    let cmd = apdu::verify(parse_pin_name(&pin_name), &digits).build();
    let sim = world.sim_mut();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "Expected 90 00, got {sw1:02X} {sw2:02X}",
    );
}

// Direct probe: intentionally bypasses do_send_apdu to avoid
// clobbering the world response that preceding Then steps may check.

#[then(regex = r#"^verifying (PIN1|PIN2) with "(\d+)" fails with (\d+) retries? remaining$"#)]
fn then_verify_fails_retries(
    world: &mut SimWorld,
    pin_name: String,
    digits: String,
    remaining: u8,
) {
    let cmd = apdu::verify(parse_pin_name(&pin_name), &digits).build();
    let sim = world.sim_mut();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    let expected_sw2 = 0xC0 | (remaining & 0x0F);
    assert_eq!(
        (sw1, sw2),
        (0x63, expected_sw2),
        "Expected 63 C{remaining:X} ({remaining} retries remaining), got {sw1:02X} {sw2:02X}",
    );
}

#[then(regex = r#"^the next VERIFY (PIN1|PIN2) with "(\d+)" is blocked$"#)]
fn then_next_verify_blocked(world: &mut SimWorld, pin_name: String, digits: String) {
    let cmd = apdu::verify(parse_pin_name(&pin_name), &digits).build();
    let sim = world.sim_mut();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x83),
        "Expected 69 83 (blocked), got {sw1:02X} {sw2:02X}",
    );
}

#[then(regex = r#"^the next UNBLOCK (PIN1|PIN2) with PUK "(\d+)" new PIN "(\d+)" is blocked$"#)]
fn then_next_unblock_blocked(world: &mut SimWorld, pin_name: String, puk: String, new_pin: String) {
    let cmd = apdu::unblock(parse_pin_name(&pin_name), &puk, &new_pin).build();
    let sim = world.sim_mut();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x83),
        "Expected 69 83 (blocked), got {sw1:02X} {sw2:02X}",
    );
}

#[then("PIN1 is permanently unrecoverable")]
fn then_pin1_unrecoverable(world: &mut SimWorld) {
    let cmd = apdu::unblock(PinKey::PIN1, apdu::PUK1_CORRECT, apdu::PIN1_NEW).build();
    let sim = world.sim_mut();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x83),
        "Expected 69 83 (permanently blocked), got {sw1:02X} {sw2:02X}",
    );
}
