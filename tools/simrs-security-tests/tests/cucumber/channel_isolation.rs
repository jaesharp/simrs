#![allow(missing_docs)]
//! Step definitions for logical channel isolation testing.
//!
//! Tests that MANAGE CHANNEL (INS=0x70) correctly manages supplementary
//! logical channels and that each channel maintains an independent
//! selection context (`SelectionCtx`).

use cucumber::{given, then, when};
use simrs_security_tests::{apdu, verify_pin1};

use super::world::{do_send_apdu, reset_state_snapshots, SimWorld};

// =========================================================================
// GIVEN steps
// =========================================================================

#[given("I have opened logical channel 1")]
fn given_open_channel_1(world: &mut SimWorld) {
    let cmd = apdu::manage_channel_open().build();
    do_send_apdu(world, &cmd);
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "MANAGE CHANNEL OPEN failed: {sw1:02X} {sw2:02X}",
    );
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 1,
        "Expected channel 1 allocated, got {data:02X?}",
    );
    reset_state_snapshots(world);
}

#[given("EF.ICCID is selected on channel 0 with PIN1 verified")]
fn given_select_iccid_ch0(world: &mut SimWorld) {
    verify_pin1(world.sim_mut());
    let cmd = apdu::select_fid(apdu::FID_ICCID).build();
    do_send_apdu(world, &cmd);
    let (sw1, sw2) = world.last_sw();
    assert!(
        sw1 == 0x90 || sw1 == 0x61,
        "SELECT EF.ICCID on ch0 failed: {sw1:02X} {sw2:02X}",
    );
    // Consume FCP if available.
    if sw1 == 0x61 {
        let get_rsp = apdu::get_response(sw2).build();
        do_send_apdu(world, &get_rsp);
    }
    reset_state_snapshots(world);
}

// =========================================================================
// WHEN steps
// =========================================================================

#[when("I send MANAGE CHANNEL OPEN")]
fn when_manage_channel_open(world: &mut SimWorld) {
    let cmd = apdu::manage_channel_open().build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send MANAGE CHANNEL CLOSE for channel (\d+)$")]
fn when_manage_channel_close(world: &mut SimWorld, channel: u8) {
    let cmd = apdu::manage_channel_close(channel).build();
    do_send_apdu(world, &cmd);
}

#[when("I send SELECT MF on channel 1")]
fn when_select_mf_ch1(world: &mut SimWorld) {
    // CLA bits 0-1 = 0x01 for channel 1.
    let cmd = apdu::select_fid(apdu::FID_MF).with_cla(0x01).build();
    do_send_apdu(world, &cmd);
}

#[when("I send READ BINARY on channel 0 at offset 0 length 10")]
fn when_read_binary_ch0(world: &mut SimWorld) {
    let cmd = apdu::read_binary(0, 10).build();
    do_send_apdu(world, &cmd);
}

// =========================================================================
// THEN steps
// =========================================================================

#[then("the response data contains an allocated channel number")]
fn then_data_contains_channel(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty(),
        "Expected response data with channel number",
    );
    let ch = data[0];
    assert!(
        (1..=3).contains(&ch),
        "Expected channel number 1-3, got {ch}",
    );
}
