#![allow(missing_docs)]
//! Step definitions for snapshot integrity validation.
//!
//! Tests that `save_state()` / `restore_state()` round-trip correctly and
//! that `restore_state()` rejects corrupted snapshot headers (wrong magic,
//! wrong version, mismatched feature flags, truncation).

use cucumber::{given, then, when};
use simrs_adversarial_countervalidation::{apdu, create_sim_powered_on, send_apdu_sw};

use super::world::{capture_snapshot, SimWorld};

// =========================================================================
// GIVEN steps
// =========================================================================

#[given("the SIM state has been snapshotted")]
fn given_snapshot_taken(world: &mut SimWorld) {
    let snap = capture_snapshot(world.sim_ref());
    world.state_before = Some(snap);
}

// =========================================================================
// WHEN steps -- corruption
// =========================================================================

#[when(r#"the magic bytes are corrupted to "BAAD""#)]
fn when_corrupt_magic(world: &mut SimWorld) {
    let snap = world.state_before.as_mut().expect("no snapshot captured");
    snap[0..4].copy_from_slice(b"BAAD");
}

#[when("the version byte is changed to 0xFF")]
fn when_corrupt_version(world: &mut SimWorld) {
    let snap = world.state_before.as_mut().expect("no snapshot captured");
    snap[4] = 0xFF;
}

#[when("the feature flags byte is changed to 0xFF")]
fn when_corrupt_flags(world: &mut SimWorld) {
    let snap = world.state_before.as_mut().expect("no snapshot captured");
    snap[5] = 0xFF;
}

#[when("the snapshot is truncated to 5 bytes")]
fn when_truncate(world: &mut SimWorld) {
    let snap = world.state_before.as_mut().expect("no snapshot captured");
    snap.truncate(5);
}

// =========================================================================
// WHEN steps -- restore
// =========================================================================

#[when("the snapshot is restored into a fresh SIM")]
fn when_restore_valid(world: &mut SimWorld) {
    let snap = world.state_before.as_ref().expect("no snapshot captured");
    let mut target = create_sim_powered_on();
    let ok = target.restore_state(snap);
    world.restore_result = Some(ok);
    if ok {
        world.activate(Box::new(target));
    }
}

#[when("the corrupted snapshot is restored into a fresh SIM")]
fn when_restore_corrupted(world: &mut SimWorld) {
    let snap = world.state_before.as_ref().expect("no snapshot captured");
    let mut target = create_sim_powered_on();
    let ok = target.restore_state(snap);
    world.restore_result = Some(ok);
}

#[when("the truncated snapshot is restored into a fresh SIM")]
fn when_restore_truncated(world: &mut SimWorld) {
    let snap = world.state_before.as_ref().expect("no snapshot captured");
    let mut target = create_sim_powered_on();
    let ok = target.restore_state(snap);
    world.restore_result = Some(ok);
}

// =========================================================================
// THEN steps
// =========================================================================

#[then("the restore succeeds")]
fn then_restore_ok(world: &mut SimWorld) {
    let result = world.restore_result.expect("no restore attempted");
    assert!(result, "Expected restore_state() to return true");
}

#[then("the restore fails")]
fn then_restore_fails(world: &mut SimWorld) {
    let result = world.restore_result.expect("no restore attempted");
    assert!(!result, "Expected restore_state() to return false");
}

#[then("the restored SIM processes APDUs normally")]
fn then_restored_sim_works(world: &mut SimWorld) {
    // Verify the restored SIM can process a SELECT MF.
    let cmd = apdu::select_fid(apdu::FID_MF).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &cmd);
    assert!(
        sw1 == 0x90 || sw1 == 0x61,
        "Expected 90 00 or 61 XX from restored SIM, got {sw1:02X} {sw2:02X}",
    );
}
