#![allow(missing_docs)]
//! Declarative interposer step definitions.
//!
//! The interposer sits between the UE (terminal) and the SIM under test.
//! It is configured in Given steps and silently mutates or drops APDUs
//! matching its rules before they reach the SIM.
//!
//! Architecture mirrors `simrs-interposer`: the SIM only processes valid
//! commands; the interposer corrupts them on the wire for security testing.

use cucumber::{given, then};

use super::snapshot::{format_diff_report, is_reserved};
use super::world::{
    capture_snapshot, ensure_state_before, ins_from_name, CommandMatcher, InterposerRule, Mutation,
    SimWorld,
};

// =========================================================================
// GIVEN steps -- interposer configuration
// =========================================================================

#[given("a mutating interposer between UE and SIM")]
fn given_interposer_present(world: &mut SimWorld) {
    world.interposer_rules.clear();
    // Capture byte-level state snapshot for "no state changed" assertions.
    ensure_state_before(world);
}

#[given(regex = r"^the interposer sets P1 to (0x[0-9A-Fa-f]+) on (\w[\w ]*) commands$")]
fn given_interposer_set_p1(world: &mut SimWorld, hex_val: String, command: String) {
    let value = u8::from_str_radix(hex_val.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex {hex_val:?}: {e}"));
    let ins = ins_from_name(command.trim());
    world.interposer_rules.push(InterposerRule {
        matcher: CommandMatcher::ByIns(ins),
        mutation: Mutation::SetP1(value),
    });
}

#[given(regex = r"^the interposer sets P2 to (0x[0-9A-Fa-f]+) on (\w[\w ]*) commands$")]
fn given_interposer_set_p2(world: &mut SimWorld, hex_val: String, command: String) {
    let value = u8::from_str_radix(hex_val.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex {hex_val:?}: {e}"));
    let ins = ins_from_name(command.trim());
    world.interposer_rules.push(InterposerRule {
        matcher: CommandMatcher::ByIns(ins),
        mutation: Mutation::SetP2(value),
    });
}

#[given(regex = r"^the interposer sets CLA to (0x[0-9A-Fa-f]+) on all commands$")]
fn given_interposer_set_cla_all(world: &mut SimWorld, hex_val: String) {
    let value = u8::from_str_radix(hex_val.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex {hex_val:?}: {e}"));
    world.interposer_rules.push(InterposerRule {
        matcher: CommandMatcher::All,
        mutation: Mutation::SetCla(value),
    });
}

#[given(regex = r"^the interposer sets CLA to (0x[0-9A-Fa-f]+) on (\w[\w ]*) commands$")]
fn given_interposer_set_cla(world: &mut SimWorld, hex_val: String, command: String) {
    let value = u8::from_str_radix(hex_val.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex {hex_val:?}: {e}"));
    let ins = ins_from_name(command.trim());
    world.interposer_rules.push(InterposerRule {
        matcher: CommandMatcher::ByIns(ins),
        mutation: Mutation::SetCla(value),
    });
}

#[given(regex = r"^the interposer drops (\w[\w ]*) commands$")]
fn given_interposer_drop(world: &mut SimWorld, command: String) {
    let ins = ins_from_name(command.trim());
    world.interposer_rules.push(InterposerRule {
        matcher: CommandMatcher::ByIns(ins),
        mutation: Mutation::Drop,
    });
}

#[given(regex = r"^the interposer truncates (\w[\w ]*) data to (\d+) bytes?$")]
fn given_interposer_truncate(world: &mut SimWorld, command: String, len: usize) {
    let ins = ins_from_name(command.trim());
    world.interposer_rules.push(InterposerRule {
        matcher: CommandMatcher::ByIns(ins),
        mutation: Mutation::TruncateData(len),
    });
}

// =========================================================================
// THEN steps -- state integrity assertions
// =========================================================================

#[then("no SIM state has changed")]
fn then_no_state_changed(world: &mut SimWorld) {
    // Capture "after" now if not already done (e.g. dropped commands).
    if world.state_after.is_none() {
        world.state_after = Some(capture_snapshot(world.sim_ref()));
    }

    let before = world
        .state_before
        .as_ref()
        .expect("No state snapshot -- was the SIM initialised?");
    let after = world.state_after.as_ref().unwrap();
    let registry = world
        .registry
        .as_ref()
        .expect("No snapshot registry -- was the SIM initialised?");

    let diffs = registry.diff(before, after);
    if !diffs.is_empty() {
        let report = format_diff_report(&diffs, &world.reservations);
        panic!("SIM state changed unexpectedly after rejected command:\n{report}");
    }
}

#[then("no other SIM state has changed")]
fn then_no_other_state_changed(world: &mut SimWorld) {
    // Capture "after" now if not already done.
    if world.state_after.is_none() {
        world.state_after = Some(capture_snapshot(world.sim_ref()));
    }

    let before = world
        .state_before
        .as_ref()
        .expect("No state snapshot -- was the SIM initialised?");
    let after = world.state_after.as_ref().unwrap();
    let registry = world
        .registry
        .as_ref()
        .expect("No snapshot registry -- was the SIM initialised?");

    let diffs = registry.diff(before, after);
    let has_unreserved = diffs
        .iter()
        .any(|(path, _)| !is_reserved(path, &world.reservations));

    if has_unreserved {
        let report = format_diff_report(&diffs, &world.reservations);
        panic!("SIM state changed in unreserved fields:\n{report}");
    }
}
