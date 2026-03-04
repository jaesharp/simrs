#![allow(missing_docs)]
//! Filesystem access control bypass step definitions.
//!
//! Covers READ/UPDATE without SELECT, non-existent FIDs, offset boundary,
//! GET RESPONSE queue behaviour per:
//!   - ETSI TS 102 221 clause 8 (security architecture)
//!   - ISO/IEC 7816-4 clause 7

use cucumber::given;
use simrs_security_tests::apdu;

use super::world::{do_send_apdu, ensure_pin1_verified, reset_state_snapshots, SimWorld};

// =========================================================================
// GIVEN steps -- filesystem preconditions
// =========================================================================

// "I have selected MF [...] and received SW 61 XX" -- selects MF but does NOT
// consume the FCP; the scenario will do GET RESPONSE explicitly.
#[given("I have selected MF and received SW 61 XX")]
fn given_selected_mf_61xx(world: &mut SimWorld) {
    let cmd = apdu::select_fid(apdu::FID_MF).build();
    do_send_apdu(world, &cmd);
    // Don't consume FCP here -- the scenario will GET RESPONSE explicitly.
    reset_state_snapshots(world);
}

#[given(regex = r"^I have consumed the FCP.*$")]
fn given_consumed_fcp(world: &mut SimWorld) {
    if let Some((0x61, le)) = world.last_sw_opt() {
        let get_resp = apdu::get_response(le).build();
        do_send_apdu(world, &get_resp);
    }
    reset_state_snapshots(world);
}

#[given(regex = r"^I have selected EF\.ICCID.*$")]
fn given_selected_ef_iccid(world: &mut SimWorld) {
    // Verify PIN1 first so subsequent READ BINARY works.
    ensure_pin1_verified(world);
    let cmd = apdu::select_fid(apdu::FID_ICCID).build();
    do_send_apdu(world, &cmd);
    // Consume FCP if returned.
    if let Some((0x61, le)) = world.last_sw_opt() {
        let get_resp = apdu::get_response(le).build();
        do_send_apdu(world, &get_resp);
    }
    reset_state_snapshots(world);
}

// (Then steps for FS access control are in common.rs: parameterised handler.)
