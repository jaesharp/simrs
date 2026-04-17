#![allow(missing_docs)]
//! Step definitions for BIP (Bearer Independent Protocol) channel security testing.
//!
//! Tests that BIP channel state management (IDs 1-7) correctly validates
//! channel boundaries, rejects double-open / close-without-open, maintains
//! channel isolation, and respects TERMINAL RESPONSE failure codes.
//!
//! BIP channels are managed via the proactive UICC command cycle:
//! queue OPEN/CLOSE CHANNEL -> FETCH -> TERMINAL RESPONSE.
//!
//! Standards:
//!   ETSI TS 102 223 V18.2.0  clauses 6.4.27, 6.4.28, 8.56

use cucumber::{given, then, when};
use simrs_adversarial_countervalidation::{apdu, create_sim_powered_on, send_apdu_sw};
use simrs_proactive::ProactiveCommand;

use super::world::{SimWorld, capture_snapshot, reset_state_snapshots};

// =========================================================================
// Helpers
// =========================================================================

/// Send TERMINAL PROFILE to enable proactive command support.
fn send_terminal_profile_for_bip(world: &mut SimWorld) {
    let cmd = apdu::terminal_profile(&[0xFF; 4]).build();
    send_apdu_sw(world.sim_mut(), &cmd);
}

/// Queue an OPEN CHANNEL proactive command, FETCH it, and send a
/// TERMINAL RESPONSE with the given result and channel ID.
///
/// `general_result`: 0x00 = success, 0x20 = ME unable to process (failure).
fn proactive_open_channel_cycle(
    world: &mut SimWorld,
    bearer: u8,
    channel_id: u8,
    general_result: u8,
) {
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    ps.queue_command(&ProactiveCommand::OpenChannel {
        bearer: core::slice::from_ref(&bearer),
        buffer_size: 1024,
        alpha_id: &[],
        transport_level: &[],
        destination_address: &[],
        qualifier: 0x00,
    })
    .expect("queue OPEN CHANNEL failed");

    // FETCH the proactive command.
    let fetch_cmd = apdu::fetch(0x00).build();
    let (sw1, _sw2) = send_apdu_sw(world.sim_mut(), &fetch_cmd);
    assert!(sw1 == 0x90 || sw1 == 0x91, "FETCH failed: SW1={sw1:02X}");

    // Build TERMINAL RESPONSE TLV payload.
    let tr_data = [
        0x81,
        0x03,
        0x01,
        0x40,
        0x00, // Command Details: OPEN CHANNEL
        0x82,
        0x02,
        0x82,
        0x81, // Device Identities: ME -> UICC
        0x83,
        0x01,
        general_result, // Result
        0xB8,
        0x02,
        channel_id,
        0x00, // Channel Status: channel_id
        0xB5,
        0x01,
        bearer, // Bearer Description
        0xB9,
        0x02,
        0x04,
        0x00, // Buffer Size: 1024
    ];
    let tr_cmd = apdu::terminal_response(&tr_data).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &tr_cmd);
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "TERMINAL RESPONSE failed: {sw1:02X} {sw2:02X}",
    );
}

// =========================================================================
// GIVEN steps
// =========================================================================

#[given("TERMINAL PROFILE has been sent for BIP testing")]
fn given_terminal_profile_for_bip(world: &mut SimWorld) {
    send_terminal_profile_for_bip(world);
    reset_state_snapshots(world);
}

#[given(regex = r"^a proactive OPEN CHANNEL is queued for bearer 0x([0-9A-Fa-f]{2})$")]
fn given_open_channel_queued(world: &mut SimWorld, bearer_hex: String) {
    let bearer = u8::from_str_radix(&bearer_hex, 16).unwrap();
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    ps.queue_command(&ProactiveCommand::OpenChannel {
        bearer: core::slice::from_ref(&bearer),
        buffer_size: 1024,
        alpha_id: &[],
        transport_level: &[],
        destination_address: &[],
        qualifier: 0x00,
    })
    .expect("queue OPEN CHANNEL failed");
}

#[given(regex = r"^BIP channel (\d+) has been opened via proactive cycle$")]
fn given_bip_channel_opened(world: &mut SimWorld, channel: u8) {
    proactive_open_channel_cycle(world, 0x01, channel, 0x00);
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    assert!(
        ps.is_channel_open(channel),
        "Expected BIP channel {channel} to be open after proactive cycle",
    );
    reset_state_snapshots(world);
}

// =========================================================================
// WHEN steps
// =========================================================================

#[when("I FETCH the proactive command")]
fn when_fetch(world: &mut SimWorld) {
    let fetch_cmd = apdu::fetch(0x00).build();
    let (sw1, _sw2) = send_apdu_sw(world.sim_mut(), &fetch_cmd);
    assert!(sw1 == 0x90 || sw1 == 0x91, "FETCH failed: SW1={sw1:02X}");
}

#[when(regex = r"^I send TERMINAL RESPONSE with success for OPEN CHANNEL on channel (\d+)$")]
fn when_tr_success_open(world: &mut SimWorld, channel: u8) {
    let tr_data = [
        0x81, 0x03, 0x01, 0x40, 0x00, 0x82, 0x02, 0x82, 0x81, 0x83, 0x01,
        0x00, // Result: success
        0xB8, 0x02, channel, 0x00, // Channel Status
        0xB5, 0x01, 0x01, // Bearer Description
        0xB9, 0x02, 0x04, 0x00, // Buffer Size: 1024
    ];
    let tr_cmd = apdu::terminal_response(&tr_data).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &tr_cmd);
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "TERMINAL RESPONSE failed: {sw1:02X} {sw2:02X}",
    );
}

#[when(regex = r"^I send TERMINAL RESPONSE with failure for OPEN CHANNEL on channel (\d+)$")]
fn when_tr_failure_open(world: &mut SimWorld, channel: u8) {
    let tr_data = [
        0x81, 0x03, 0x01, 0x40, 0x00, 0x82, 0x02, 0x82, 0x81, 0x83, 0x01,
        0x20, // Result: ME unable to process
        0xB8, 0x02, channel, 0x00, // Channel Status (present but failure)
        0xB5, 0x01, 0x01, 0xB9, 0x02, 0x04, 0x00,
    ];
    let tr_cmd = apdu::terminal_response(&tr_data).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &tr_cmd);
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "TERMINAL RESPONSE failed: {sw1:02X} {sw2:02X}",
    );
}

#[when(regex = r"^a direct OPEN CHANNEL is attempted for channel (\d+)$")]
fn when_direct_open(world: &mut SimWorld, channel: u8) {
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    let result = ps.open_channel(channel, 0x01, 1024);
    world.restore_result = Some(result);
}

#[when(regex = r"^a direct CLOSE CHANNEL is attempted for channel (\d+)$")]
fn when_direct_close(world: &mut SimWorld, channel: u8) {
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    let result = ps.close_channel(channel);
    world.restore_result = Some(result);
}

#[when(regex = r"^BIP channel (\d+) is opened via proactive cycle$")]
fn when_bip_channel_opened(world: &mut SimWorld, channel: u8) {
    proactive_open_channel_cycle(world, 0x01, channel, 0x00);
}

#[when("a snapshot is saved and restored")]
fn when_snapshot_roundtrip(world: &mut SimWorld) {
    let snap = capture_snapshot(world.sim_ref());
    let mut target = create_sim_powered_on();
    let ok = target.restore_state(&snap);
    assert!(ok, "restore_state() failed during snapshot round-trip");
    world.activate(Box::new(target));
}

// =========================================================================
// THEN steps
// =========================================================================

#[then(regex = r"^BIP channel (\d+) is open$")]
fn then_bip_channel_open(world: &mut SimWorld, channel: u8) {
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    assert!(
        ps.is_channel_open(channel),
        "Expected BIP channel {channel} to be open",
    );
}

#[then(regex = r"^BIP channel (\d+) is not open$")]
fn then_bip_channel_not_open(world: &mut SimWorld, channel: u8) {
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    assert!(
        !ps.is_channel_open(channel),
        "Expected BIP channel {channel} to be NOT open",
    );
}

#[then(regex = r"^BIP channel (\d+) is still open$")]
fn then_bip_channel_still_open(world: &mut SimWorld, channel: u8) {
    let ps = world.sim_mut().usim_app_mut().proactive_state();
    assert!(
        ps.is_channel_open(channel),
        "Expected BIP channel {channel} to still be open after rejected operation",
    );
}

#[then("the channel open is rejected")]
fn then_channel_open_rejected(world: &mut SimWorld) {
    let result = world
        .restore_result
        .expect("No channel open result recorded");
    assert!(
        !result,
        "Expected open_channel() to return false (rejected)"
    );
}

#[then("the channel close is rejected")]
fn then_channel_close_rejected(world: &mut SimWorld) {
    let result = world
        .restore_result
        .expect("No channel close result recorded");
    assert!(
        !result,
        "Expected close_channel() to return false (rejected)",
    );
}
