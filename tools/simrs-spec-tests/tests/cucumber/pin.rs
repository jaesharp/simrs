#![allow(missing_docs)]
//! Step definitions for `pin.feature` -- PIN/PUK management.
//!
//! Crate under test: `simrs-pin`.

use cucumber::{given, then, when};
use simrs_pin::{PinError, PinKey, PinManager, PinResult, PinValue};

use crate::world::SpecWorld;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an ASCII PIN string (e.g. "1234") into a `PinValue`.
fn pin_to_value(pin_str: &str) -> PinValue {
    let mut bytes = [0xFF; 8];
    for (i, b) in pin_str.bytes().enumerate() {
        bytes[i] = b;
    }
    PinValue::new(bytes)
}

/// Borrow the PinManager from world state, panicking if absent.
fn mgr(world: &mut SpecWorld) -> &mut PinManager<5> {
    world.pin_manager.as_mut().expect("PinManager not initialised")
}

// =========================================================================
// BACKGROUND steps
// =========================================================================

#[given(regex = r"^a PinManager with capacity for 5 slots$")]
fn given_pin_manager(world: &mut SpecWorld) {
    world.pin_manager = Some(Box::new(PinManager::<5>::new()));
    world.pin_result = None;
    world.pin_error = None;
    world.pin_results.clear();
}

#[given(regex = r#"^PIN1 \(key 0x01\) configured with value "([^"]*)", max (\d+) retries$"#)]
fn given_pin1_configured(world: &mut SpecWorld, pin_str: String, max_retries: u8) {
    // PUK is provided in the next Background step. Stash PIN params in generic
    // world slots so the PUK step can call add_pin with all values.
    world.hex_input = pin_str.bytes().collect();
    world.hex_output = vec![max_retries];
}

#[given(regex = r#"^PUK1 configured with value "([^"]*)", max (\d+) retries$"#)]
fn given_puk1_configured(world: &mut SpecWorld, puk_str: String, puk_max: u8) {
    // Retrieve stashed PIN values from the previous step.
    let pin_str: String = world.hex_input.iter().map(|&b| b as char).collect();
    let pin_max = world.hex_output[0];
    let pin = pin_to_value(&pin_str);
    let puk = pin_to_value(&puk_str);

    // add_pin with enabled=false; the next step will handle the enabled flag.
    // Actually, we'll add with enabled=false and let the "PIN1 is enabled" step
    // just assert or set. But we need add_pin now since we have all params.
    mgr(world)
        .add_pin(PinKey::PIN1, &pin, pin_max, &puk, puk_max, false)
        .expect("Background: add_pin failed");

    // Clear temporary stash.
    world.hex_input.clear();
    world.hex_output.clear();
}

#[given(regex = r"^PIN1 is enabled$")]
fn given_pin1_is_enabled(world: &mut SpecWorld) {
    // The PIN was added as disabled in the PUK step; re-add is not possible.
    // Instead, enable it via the enable API with the correct PIN.
    // But enable requires the correct PIN value and the PIN is currently disabled,
    // so enable() will work.
    let pin = pin_to_value("1234");
    let result = mgr(world).enable(PinKey::PIN1, &pin);
    assert_eq!(result, PinResult::Success, "Background: enable PIN1 failed: {result:?}");
}

// =========================================================================
// GIVEN steps -- scenario preconditions
// =========================================================================

#[given(regex = r"^PIN1 is blocked \(retry counter is 0\)$")]
fn given_pin1_blocked_explicit(world: &mut SpecWorld) {
    // Exhaust retries with wrong PIN.
    let wrong = pin_to_value("9999");
    loop {
        let r = mgr(world).verify(PinKey::PIN1, &wrong);
        if r == PinResult::Blocked {
            break;
        }
    }
    assert!(mgr(world).is_blocked(PinKey::PIN1));
}

#[given(regex = r"^PIN1 is blocked$")]
fn given_pin1_blocked(world: &mut SpecWorld) {
    if world.sim.is_some() {
        // APDU-level: exhaust retries by sending VERIFY with wrong PIN.
        let cla = if world.gsm_mode { 0xA0 } else { 0x00 };
        let wrong_pin: [u8; 8] = [0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut cmd = vec![cla, 0x20, 0x00, 0x01, 0x08];
        cmd.extend_from_slice(&wrong_pin);
        for _ in 0..3 {
            crate::world::do_send_apdu(world, &cmd);
        }
    } else {
        // Library-level: use PinManager directly.
        let wrong = pin_to_value("9999");
        loop {
            let r = mgr(world).verify(PinKey::PIN1, &wrong);
            if r == PinResult::Blocked {
                break;
            }
        }
        assert!(mgr(world).is_blocked(PinKey::PIN1));
    }
}

#[given(regex = r"^PIN1 is disabled$")]
fn given_pin1_disabled(world: &mut SpecWorld) {
    let pin = pin_to_value("1234");
    let result = mgr(world).disable(PinKey::PIN1, &pin);
    assert_eq!(result, PinResult::Success, "Given disable failed: {result:?}");
    assert!(!mgr(world).is_enabled(PinKey::PIN1));
}

#[given(regex = r"^PIN1 has 1 retry remaining after two wrong attempts$")]
fn given_pin1_one_retry(world: &mut SpecWorld) {
    let wrong = pin_to_value("9999");
    // Two wrong attempts: 3 -> 2 -> 1
    let _ = mgr(world).verify(PinKey::PIN1, &wrong);
    let _ = mgr(world).verify(PinKey::PIN1, &wrong);
    assert_eq!(mgr(world).retries(PinKey::PIN1), Some(1));
}

#[given(regex = r"^PIN1 is verified$")]
fn given_pin1_verified(world: &mut SpecWorld) {
    let pin = pin_to_value("1234");
    let result = mgr(world).verify(PinKey::PIN1, &pin);
    assert_eq!(result, PinResult::Success);
    assert!(mgr(world).is_verified(PinKey::PIN1));
}

#[given(regex = r"^PUK1 retry counter is exhausted \(0\)$")]
fn given_puk1_exhausted(world: &mut SpecWorld) {
    let wrong_puk = pin_to_value("00000000");
    let dummy_pin = pin_to_value("0000");
    loop {
        let r = mgr(world).unblock(PinKey::PIN1, &wrong_puk, &dummy_pin);
        if r == PinResult::Blocked {
            break;
        }
    }
    assert_eq!(mgr(world).puk_retries(PinKey::PIN1), Some(0));
}

#[given(regex = r"^PUK1 has been used once \(9 retries remaining\)$")]
fn given_puk1_used_once(world: &mut SpecWorld) {
    // One wrong PUK attempt: 10 -> 9
    let wrong_puk = pin_to_value("00000000");
    let dummy_pin = pin_to_value("0000");
    let r = mgr(world).unblock(PinKey::PIN1, &wrong_puk, &dummy_pin);
    assert!(
        matches!(r, PinResult::WrongPin { retries_remaining: 9 }),
        "Expected WrongPin(9), got {r:?}"
    );
    assert_eq!(mgr(world).puk_retries(PinKey::PIN1), Some(9));
}

#[given(regex = r"^the manager is full \(5 slots used\)$")]
fn given_manager_full(world: &mut SpecWorld) {
    // PIN1 is already in slot 0; fill slots 1..4 with unique keys.
    let dummy_pin = pin_to_value("0000");
    let dummy_puk = pin_to_value("00000000");
    let keys = [PinKey::PIN2, PinKey::ADM1, PinKey::ADM2, PinKey::UNIVERSAL];
    for key in keys {
        mgr(world)
            .add_pin(key, &dummy_pin, 3, &dummy_puk, 10, true)
            .expect("failed to fill manager slot");
    }
}

#[given(regex = r#"^PIN2 \(key 0x81\) is also configured with value "([^"]*)"$"#)]
fn given_pin2_configured(world: &mut SpecWorld, pin_str: String) {
    let pin = pin_to_value(&pin_str);
    let puk = pin_to_value("00000000");
    mgr(world)
        .add_pin(PinKey::PIN2, &pin, 3, &puk, 10, true)
        .expect("add_pin PIN2 failed");
}

// =========================================================================
// WHEN steps -- PIN operations
// =========================================================================

#[when(regex = r#"^I verify PIN1 with "([^"]*)"$"#)]
fn when_verify_pin1(world: &mut SpecWorld, pin_str: String) {
    let val = pin_to_value(&pin_str);
    let result = mgr(world).verify(PinKey::PIN1, &val);
    world.pin_result = Some(result);
}

#[when(regex = r#"^I verify PIN1 with "([^"]*)" three times$"#)]
fn when_verify_pin1_three_times(world: &mut SpecWorld, pin_str: String) {
    let val = pin_to_value(&pin_str);
    world.pin_results.clear();
    for _ in 0..3 {
        let r = mgr(world).verify(PinKey::PIN1, &val);
        world.pin_results.push(r);
    }
    // Also set pin_result to the last one for any "the result is" assertions.
    world.pin_result = world.pin_results.last().copied();
}

#[when(regex = r"^I verify PinKey\(0xFF\) with any value$")]
fn when_verify_unknown_key(world: &mut SpecWorld) {
    let val = pin_to_value("0000");
    let result = mgr(world).verify(PinKey(0xFF), &val);
    world.pin_result = Some(result);
}

#[when(regex = r#"^I change PIN1 from "([^"]*)" to "([^"]*)"$"#)]
fn when_change_pin1(world: &mut SpecWorld, old_str: String, new_str: String) {
    let old = pin_to_value(&old_str);
    let new_pin = pin_to_value(&new_str);
    let result = mgr(world).change(PinKey::PIN1, &old, &new_pin);
    world.pin_result = Some(result);
}

#[when(regex = r#"^I disable PIN1 with "([^"]*)"$"#)]
fn when_disable_pin1(world: &mut SpecWorld, pin_str: String) {
    let val = pin_to_value(&pin_str);
    let result = mgr(world).disable(PinKey::PIN1, &val);
    world.pin_result = Some(result);
}

#[when(regex = r#"^I enable PIN1 with "([^"]*)"$"#)]
fn when_enable_pin1(world: &mut SpecWorld, pin_str: String) {
    let val = pin_to_value(&pin_str);
    let result = mgr(world).enable(PinKey::PIN1, &val);
    world.pin_result = Some(result);
}

#[when(regex = r#"^I unblock PIN1 with PUK "([^"]*)" and new PIN "([^"]*)"$"#)]
fn when_unblock_pin1(world: &mut SpecWorld, puk_str: String, new_pin_str: String) {
    let puk = pin_to_value(&puk_str);
    let new_pin = pin_to_value(&new_pin_str);
    let result = mgr(world).unblock(PinKey::PIN1, &puk, &new_pin);
    world.pin_result = Some(result);
}

#[when(regex = r"^I add another PIN with key 0x01$")]
fn when_add_duplicate_key(world: &mut SpecWorld) {
    let pin = pin_to_value("0000");
    let puk = pin_to_value("00000000");
    match mgr(world).add_pin(PinKey::PIN1, &pin, 3, &puk, 10, true) {
        Ok(()) => {
            world.pin_error = None;
        }
        Err(e) => {
            world.pin_error = Some(e);
        }
    }
}

#[when(regex = r"^I add a 6th PIN$")]
fn when_add_beyond_capacity(world: &mut SpecWorld) {
    let pin = pin_to_value("0000");
    let puk = pin_to_value("00000000");
    match mgr(world).add_pin(PinKey(0xFE), &pin, 3, &puk, 10, true) {
        Ok(()) => {
            world.pin_error = None;
        }
        Err(e) => {
            world.pin_error = Some(e);
        }
    }
}

#[when(regex = r"^I verify PIN1 with wrong value$")]
fn when_verify_pin1_wrong(world: &mut SpecWorld) {
    let wrong = pin_to_value("9999");
    let result = mgr(world).verify(PinKey::PIN1, &wrong);
    world.pin_result = Some(result);
}

#[when(regex = r"^the session is reset$")]
fn when_session_reset(world: &mut SpecWorld) {
    mgr(world).reset_verified();
}

// =========================================================================
// THEN steps -- result assertions
// =========================================================================

#[then(regex = r"^the result is Success$")]
fn then_result_success(world: &mut SpecWorld) {
    let result = world.pin_result.expect("No PinResult available");
    assert_eq!(result, PinResult::Success, "Expected Success, got {result:?}");
}

#[then(regex = r"^the result is WrongPin with (\d+) retries remaining$")]
fn then_result_wrong_pin(world: &mut SpecWorld, expected_retries: u8) {
    let result = world.pin_result.expect("No PinResult available");
    assert_eq!(
        result,
        PinResult::WrongPin { retries_remaining: expected_retries },
        "Expected WrongPin({expected_retries}), got {result:?}"
    );
}

#[then(regex = r"^the result is Blocked$")]
fn then_result_blocked(world: &mut SpecWorld) {
    let result = world.pin_result.expect("No PinResult available");
    assert_eq!(result, PinResult::Blocked, "Expected Blocked, got {result:?}");
}

#[then(regex = r"^the result is Disabled$")]
fn then_result_disabled(world: &mut SpecWorld) {
    let result = world.pin_result.expect("No PinResult available");
    assert_eq!(result, PinResult::Disabled, "Expected Disabled, got {result:?}");
}

#[then(regex = r"^the result is NotFound$")]
fn then_result_not_found(world: &mut SpecWorld) {
    let result = world.pin_result.expect("No PinResult available");
    assert_eq!(result, PinResult::NotFound, "Expected NotFound, got {result:?}");
}

#[then(regex = r"^the result is DuplicateKey error$")]
fn then_result_duplicate_key(world: &mut SpecWorld) {
    let err = world.pin_error.expect("Expected PinError, but none occurred");
    assert_eq!(err, PinError::DuplicateKey, "Expected DuplicateKey, got {err:?}");
}

#[then(regex = r"^the result is SlotsFull error$")]
fn then_result_slots_full(world: &mut SpecWorld) {
    let err = world.pin_error.expect("Expected PinError, but none occurred");
    assert_eq!(err, PinError::SlotsFull, "Expected SlotsFull, got {err:?}");
}

// =========================================================================
// THEN steps -- state assertions
// =========================================================================

#[then(regex = r"^PIN1 is marked as verified$")]
fn then_pin1_verified(world: &mut SpecWorld) {
    assert!(mgr(world).is_verified(PinKey::PIN1), "Expected PIN1 to be verified");
}

#[then(regex = r"^PIN1 is not verified$")]
fn then_pin1_not_verified(world: &mut SpecWorld) {
    assert!(!mgr(world).is_verified(PinKey::PIN1), "Expected PIN1 to NOT be verified");
}

#[then(regex = r"^PIN1 is not marked as verified$")]
fn then_pin1_not_marked_verified(world: &mut SpecWorld) {
    assert!(!mgr(world).is_verified(PinKey::PIN1), "Expected PIN1 to NOT be marked verified");
}

#[then(regex = r"^PIN1 retry counter is (\d+)$")]
fn then_pin1_retries(world: &mut SpecWorld, expected: u8) {
    let actual = mgr(world).retries(PinKey::PIN1).expect("PIN1 not found");
    assert_eq!(actual, expected, "Expected PIN1 retries={expected}, got {actual}");
}

#[then(regex = r"^PIN1 retry counter is reset to (\d+)$")]
fn then_pin1_retries_reset(world: &mut SpecWorld, expected: u8) {
    let actual = mgr(world).retries(PinKey::PIN1).expect("PIN1 not found");
    assert_eq!(actual, expected, "Expected PIN1 retries reset to {expected}, got {actual}");
}

#[then(regex = r"^the retry counter remains 0$")]
fn then_retry_counter_remains_zero(world: &mut SpecWorld) {
    let actual = mgr(world).retries(PinKey::PIN1).expect("PIN1 not found");
    assert_eq!(actual, 0, "Expected retry counter to remain 0, got {actual}");
}

#[then(regex = r"^the retry counter is not decremented$")]
fn then_retry_counter_not_decremented(world: &mut SpecWorld) {
    let actual = mgr(world).retries(PinKey::PIN1).expect("PIN1 not found");
    assert_eq!(actual, 3, "Expected retries=3 (not decremented), got {actual}");
}

#[then(regex = r"^PIN1 is disabled$")]
fn then_pin1_disabled(world: &mut SpecWorld) {
    assert!(!mgr(world).is_enabled(PinKey::PIN1), "Expected PIN1 to be disabled");
}

#[then(regex = r"^PIN1 is enabled$")]
fn then_pin1_enabled(world: &mut SpecWorld) {
    assert!(mgr(world).is_enabled(PinKey::PIN1), "Expected PIN1 to be enabled");
}

#[then(regex = r"^PIN1 is still enabled$")]
fn then_pin1_still_enabled(world: &mut SpecWorld) {
    assert!(mgr(world).is_enabled(PinKey::PIN1), "Expected PIN1 to still be enabled");
}

#[then(regex = r"^PIN1 is still disabled$")]
fn then_pin1_still_disabled(world: &mut SpecWorld) {
    assert!(!mgr(world).is_enabled(PinKey::PIN1), "Expected PIN1 to still be disabled");
}

#[then(regex = r"^is_verified for PIN1 returns true$")]
fn then_is_verified_true(world: &mut SpecWorld) {
    assert!(
        mgr(world).is_verified(PinKey::PIN1),
        "Expected is_verified(PIN1) = true"
    );
}

// =========================================================================
// THEN steps -- multi-attempt assertions
// =========================================================================

#[then(regex = r"^the first two results are WrongPin with 2 and 1 retries$")]
fn then_first_two_wrong(world: &mut SpecWorld) {
    assert!(
        world.pin_results.len() >= 2,
        "Expected at least 2 results, got {}",
        world.pin_results.len()
    );
    assert_eq!(
        world.pin_results[0],
        PinResult::WrongPin { retries_remaining: 2 },
        "First result: expected WrongPin(2), got {:?}",
        world.pin_results[0]
    );
    assert_eq!(
        world.pin_results[1],
        PinResult::WrongPin { retries_remaining: 1 },
        "Second result: expected WrongPin(1), got {:?}",
        world.pin_results[1]
    );
}

#[then(regex = r"^the third result is WrongPin with 0 retries remaining$")]
fn then_third_wrong_zero(world: &mut SpecWorld) {
    assert!(
        world.pin_results.len() >= 3,
        "Expected at least 3 results, got {}",
        world.pin_results.len()
    );
    assert_eq!(
        world.pin_results[2],
        PinResult::WrongPin { retries_remaining: 0 },
        "Third result: expected WrongPin(0), got {:?}",
        world.pin_results[2]
    );
}

// =========================================================================
// THEN steps -- verify after change
// =========================================================================

#[then(regex = r#"^verifying PIN1 with "([^"]*)" succeeds$"#)]
fn then_verify_succeeds(world: &mut SpecWorld, pin_str: String) {
    let val = pin_to_value(&pin_str);
    let result = mgr(world).verify(PinKey::PIN1, &val);
    assert_eq!(result, PinResult::Success, "Expected verify({pin_str}) = Success, got {result:?}");
}

#[then(regex = r#"^verifying PIN1 with "([^"]*)" fails$"#)]
fn then_verify_fails(world: &mut SpecWorld, pin_str: String) {
    // This is a declarative assertion ("the old PIN no longer works"), not
    // a stateful action. Save and restore the PinManager state around the
    // probe so verify's side-effects (retry decrement, verified flag clear)
    // do not leak into subsequent assertions.
    let mut snapshot = [0u8; PinManager::<5>::SNAPSHOT_SIZE];
    let written = mgr(world).save_state(&mut snapshot);
    assert_ne!(written, 0, "save_state failed");

    let val = pin_to_value(&pin_str);
    let result = mgr(world).verify(PinKey::PIN1, &val);
    assert!(
        !matches!(result, PinResult::Success),
        "Expected verify({pin_str}) to fail, got {result:?}"
    );

    // Restore state to undo side-effects of the probe.
    assert!(mgr(world).restore_state(&snapshot), "restore_state failed");
}

#[then(regex = r#"^verifying PIN1 with "([^"]*)" still succeeds$"#)]
fn then_verify_still_succeeds(world: &mut SpecWorld, pin_str: String) {
    let val = pin_to_value(&pin_str);
    let result = mgr(world).verify(PinKey::PIN1, &val);
    assert_eq!(
        result,
        PinResult::Success,
        "Expected verify({pin_str}) to still succeed, got {result:?}"
    );
}

// =========================================================================
// THEN steps -- PUK counter assertions
// =========================================================================

#[then(regex = r"^PUK1 retry counter is (\d+)$")]
fn then_puk1_retries(world: &mut SpecWorld, expected: u8) {
    let actual = mgr(world).puk_retries(PinKey::PIN1).expect("PIN1 not found");
    assert_eq!(actual, expected, "Expected PUK1 retries={expected}, got {actual}");
}

#[then(regex = r"^PUK1 retry counter is still (\d+)$")]
fn then_puk1_retries_still(world: &mut SpecWorld, expected: u8) {
    let actual = mgr(world).puk_retries(PinKey::PIN1).expect("PIN1 not found");
    assert_eq!(actual, expected, "Expected PUK1 retries still={expected}, got {actual}");
}

#[then(regex = r"^PIN1 is permanently unrecoverable$")]
fn then_pin1_permanently_unrecoverable(world: &mut SpecWorld) {
    // Both PIN and PUK are exhausted.
    assert!(mgr(world).is_blocked(PinKey::PIN1), "Expected PIN1 to be blocked");
    assert_eq!(
        mgr(world).puk_retries(PinKey::PIN1),
        Some(0),
        "Expected PUK retries=0 for permanent block"
    );
}

// =========================================================================
// THEN steps -- unblock verification order
// =========================================================================

#[then(regex = r"^PIN1 is not verified before the verify call$")]
fn then_pin1_not_verified_before_verify(world: &mut SpecWorld) {
    // The previous step ("verifying PIN1 with 5678 succeeds") already called
    // verify, so is_verified is now true. To validate the spec property that
    // unblock alone does NOT set verified, re-block and re-unblock, then check
    // is_verified before any verify call.
    let wrong = pin_to_value("0000");
    loop {
        let r = mgr(world).verify(PinKey::PIN1, &wrong);
        if r == PinResult::Blocked {
            break;
        }
    }
    let puk = pin_to_value("12345678");
    let new_pin = pin_to_value("5678");
    let r = mgr(world).unblock(PinKey::PIN1, &puk, &new_pin);
    assert_eq!(r, PinResult::Success, "Re-unblock failed: {r:?}");
    assert!(
        !mgr(world).is_verified(PinKey::PIN1),
        "Expected PIN1 NOT verified immediately after unblock (before any verify call)"
    );
}

// =========================================================================
// THEN steps -- independent PIN assertions
// =========================================================================

#[then(regex = r"^PIN2 retry counter is unaffected$")]
fn then_pin2_retries_unaffected(world: &mut SpecWorld) {
    let actual = mgr(world).retries(PinKey::PIN2).expect("PIN2 not found");
    assert_eq!(actual, 3, "Expected PIN2 retries=3 (unaffected), got {actual}");
}

#[then(regex = r"^PIN2 is not blocked$")]
fn then_pin2_not_blocked(world: &mut SpecWorld) {
    assert!(!mgr(world).is_blocked(PinKey::PIN2), "Expected PIN2 to NOT be blocked");
}

// =========================================================================
// THEN steps -- session reset
// =========================================================================

#[then(regex = r"^PIN1 retry counter is unchanged$")]
fn then_pin1_retries_unchanged(world: &mut SpecWorld) {
    let actual = mgr(world).retries(PinKey::PIN1).expect("PIN1 not found");
    assert_eq!(actual, 3, "Expected PIN1 retries=3 (unchanged after reset), got {actual}");
}
