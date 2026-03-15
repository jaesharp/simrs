#![allow(missing_docs)]
//! ECIES/SUCI step definitions for GET IDENTITY (INS=0x78) testing.
//!
//! Covers null scheme, Profile A (X25519), error handling, and ephemeral
//! key uniqueness per:
//!   - 3GPP TS 31.102 V19.4.0 clauses 4.4.11.8, 7.5
//!   - 3GPP TS 33.501 Annex C.3/C.4

use cucumber::{given, then, when};
use simrs_security_tests::{
    apdu, create_sim_powered_on, create_sim_with_suci_powered_on, send_apdu_sw, verify_pin1,
};

use super::world::{do_send_apdu, reset_state_snapshots, select_adf_usim, Response, SimWorld};

// =========================================================================
// Test constants
// =========================================================================

/// Test HN private key for Profile A (X25519).
const TEST_HN_SK_A: [u8; 32] = [
    0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];

/// Build `EF_SUCI_CALC_INFO` TLV data for Profile A with the test HN public key.
///
/// Layout:
/// ```text
/// A0 02 01 01          -- Protection Scheme: Profile A, key_index=1
/// A1 25                -- HN Public Key List (37 bytes)
///   80 01 01           -- Key Identifier = 1
///   81 20 <key:32>     -- Key = 32-byte X25519 public key
/// ```
fn build_suci_calc_info_profile_a() -> Vec<u8> {
    let hn_pk = simrs_ecies::x25519::x25519_base(&simrs_secret::Secret::new(TEST_HN_SK_A));
    let mut data = Vec::with_capacity(41);
    // Protection Scheme Identifier List (tag 0xA0)
    data.extend_from_slice(&[0xA0, 0x02, 0x01, 0x01]);
    // HN Public Key List (tag 0xA1)
    // Inner: [80 01 01] (3 bytes) + [81 20 <key32>] (34 bytes) = 37 = 0x25
    data.extend_from_slice(&[0xA1, 0x25]);
    // Key Identifier (tag 0x80)
    data.extend_from_slice(&[0x80, 0x01, 0x01]);
    // Key value (tag 0x81)
    data.push(0x81);
    data.push(0x20);
    data.extend_from_slice(hn_pk.as_bytes());
    data
}

// =========================================================================
// GIVEN steps
// =========================================================================

#[given("the SIM is initialised with SUCI service enabled")]
fn given_sim_with_suci(world: &mut SimWorld) {
    world.activate(Box::new(create_sim_with_suci_powered_on()));
}

#[given("the SIM is initialised without SUCI service")]
fn given_sim_without_suci(world: &mut SimWorld) {
    world.activate(Box::new(create_sim_powered_on()));
}

#[given("ADF.USIM is selected for SUCI testing")]
fn given_adf_usim_selected(world: &mut SimWorld) {
    select_adf_usim(world);
    reset_state_snapshots(world);
}

#[given("EF_SUCI_CALC_INFO is provisioned with Profile A")]
fn given_profile_a_provisioned(world: &mut SimWorld) {
    verify_pin1(world.sim_mut());

    // SELECT DF_5GS (0x5FC0) under ADF.USIM.
    let select_5gs = apdu::select_fid(simrs_fs::Fid::new(0x5FC0)).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &select_5gs);
    assert!(
        sw1 == 0x90 || sw1 == 0x61,
        "SELECT DF_5GS failed: {sw1:02X} {sw2:02X}",
    );
    if sw1 == 0x61 {
        let get_rsp = apdu::get_response(sw2).build();
        send_apdu_sw(world.sim_mut(), &get_rsp);
    }

    // SELECT EF_SUCI_CALC_INFO (0x4F07).
    let select_ef = apdu::select_fid(simrs_fs::Fid::new(0x4F07)).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &select_ef);
    assert!(
        sw1 == 0x90 || sw1 == 0x61,
        "SELECT EF_SUCI_CALC_INFO failed: {sw1:02X} {sw2:02X}",
    );
    if sw1 == 0x61 {
        let get_rsp = apdu::get_response(sw2).build();
        send_apdu_sw(world.sim_mut(), &get_rsp);
    }

    // UPDATE BINARY with Profile A TLV data.
    let profile_a_data = build_suci_calc_info_profile_a();
    let update = apdu::update_binary(0, &profile_a_data).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &update);
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "UPDATE BINARY EF_SUCI_CALC_INFO failed: {sw1:02X} {sw2:02X}",
    );

    reset_state_snapshots(world);
}

// =========================================================================
// GIVEN steps (IMPI/DOMAIN)
// =========================================================================

#[given("PIN1 is verified for SUCI testing")]
fn given_pin1_verified(world: &mut SimWorld) {
    verify_pin1(world.sim_mut());
    reset_state_snapshots(world);
}

// =========================================================================
// WHEN steps
// =========================================================================

#[when("I send GET IDENTITY with SUCI context")]
fn when_get_identity_suci(world: &mut SimWorld) {
    let cmd = apdu::get_identity_suci().build();
    do_send_apdu(world, &cmd);
}

#[when("I send GET IDENTITY with IMPI context")]
fn when_get_identity_impi(world: &mut SimWorld) {
    let cmd = apdu::get_identity_impi().build();
    do_send_apdu(world, &cmd);
}

#[when("I send GET IDENTITY with domain context")]
fn when_get_identity_domain(world: &mut SimWorld) {
    let cmd = apdu::get_identity_domain().build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send GET IDENTITY with P2=0x([0-9A-Fa-f]{2})$")]
fn when_get_identity_p2(world: &mut SimWorld, p2_hex: String) {
    let p2 = u8::from_str_radix(&p2_hex, 16).unwrap();
    let cmd = apdu::get_identity_suci().with_p2(p2).build();
    do_send_apdu(world, &cmd);
}

#[when(regex = r"^I send GET IDENTITY with P1=0x([0-9A-Fa-f]{2})$")]
fn when_get_identity_p1(world: &mut SimWorld, p1_hex: String) {
    let p1 = u8::from_str_radix(&p1_hex, 16).unwrap();
    let cmd = apdu::get_identity_suci().with_p1(p1).build();
    do_send_apdu(world, &cmd);
}

#[when("I send GET IDENTITY with SUCI context and stash the response")]
fn when_get_identity_stash(world: &mut SimWorld) {
    let cmd = apdu::get_identity_suci().build();
    do_send_apdu(world, &cmd);
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        sw1, 0x61,
        "GET IDENTITY must return 61 XX, got {sw1:02X} {sw2:02X}"
    );
    let get_rsp = apdu::get_response(sw2).build();
    do_send_apdu(world, &get_rsp);
    world.first_auth_response = Some(world.response().clone());
}

// =========================================================================
// THEN steps
// =========================================================================

// ETSI TS 102 221: SW1=61 means response data bytes available.
#[then("SW indicates response data available")]
fn then_sw_response_data_available(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        sw1, 0x61,
        "Expected SW1=61 (response data available), got {sw1:02X} {sw2:02X}",
    );
}

// ETSI TS 102 221: 69 85 = conditions of use not satisfied.
#[then("SW indicates conditions not satisfied")]
fn then_sw_conditions_not_satisfied(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x85),
        "Expected 69 85 (conditions not satisfied), got {sw1:02X} {sw2:02X}",
    );
}

#[then("the SUCI response starts with tag A1")]
fn then_suci_tag_a1(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 0xA1,
        "Expected SUCI TLV tag 0xA1, got {:02X?}",
        data.first()
    );
}

#[then("the SUCI response uses null scheme")]
fn then_suci_null_scheme(world: &mut SimWorld) {
    let data = world.last_data();
    // SUCI TLV: A1 <len> <SUPI_type:1> <MCC_MNC:3> <routing:2> <scheme:1> <key_idx:1> <output>
    // scheme_id at byte offset 8: tag(1) + len(1) + SUPI(1) + MCC_MNC(3) + routing(2)
    assert!(data.len() >= 10, "SUCI TLV too short: {} bytes", data.len());
    assert_eq!(data[0], 0xA1, "Expected tag A1");
    let scheme_id = data[8];
    assert_eq!(
        scheme_id, 0x00,
        "Expected null scheme (0x00), got {scheme_id:02X}"
    );
}

#[then("the SUCI response uses Profile A")]
fn then_suci_profile_a(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(data.len() >= 10, "SUCI TLV too short: {} bytes", data.len());
    assert_eq!(data[0], 0xA1, "Expected tag A1");
    let scheme_id = data[8];
    assert_eq!(
        scheme_id, 0x01,
        "Expected Profile A (0x01), got {scheme_id:02X}"
    );
}

#[then("the SUCI Profile A scheme output is 45 bytes")]
fn then_suci_profile_a_output_len(world: &mut SimWorld) {
    let data = world.last_data();
    assert_eq!(data[0], 0xA1, "Expected tag A1");
    let inner_len = data[1] as usize;
    // Scheme output = inner_len - (SUPI(1) + MCC_MNC(3) + routing(2) + scheme(1) + key_idx(1))
    let scheme_output_len = inner_len - 8;
    // Profile A: ephemeral_pk(32) + ciphertext(5 for 10-digit MSIN) + mac(8) = 45
    assert_eq!(
        scheme_output_len, 45,
        "Profile A scheme output should be 45 bytes (32+5+8), got {scheme_output_len}"
    );
}

// ETSI TS 102 221: 69 82 = security status not satisfied.
#[then("SW indicates security not satisfied")]
fn then_sw_security_not_satisfied(world: &mut SimWorld) {
    let (sw1, sw2) = world.last_sw();
    assert_eq!(
        (sw1, sw2),
        (0x69, 0x82),
        "Expected 69 82 (security not satisfied), got {sw1:02X} {sw2:02X}",
    );
}

// -- IMPI assertions --

#[then("the IMPI response starts with tag A2")]
fn then_impi_tag_a2(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 0xA2,
        "Expected IMPI TLV tag 0xA2, got {:02X?}",
        data.first()
    );
}

#[then("the IMPI contains the IMSI digits")]
fn then_impi_contains_imsi(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(data.len() >= 3, "IMPI TLV too short");
    let inner = &data[2..];
    let impi_str = core::str::from_utf8(inner).expect("IMPI must be valid UTF-8");
    // Default IMSI: 001010000000000.
    assert!(
        impi_str.starts_with("001010000000000"),
        "IMPI must start with IMSI digits: {impi_str}",
    );
}

#[then("the IMPI contains the IMS domain suffix")]
fn then_impi_domain_suffix(world: &mut SimWorld) {
    let data = world.last_data();
    let inner = &data[2..];
    let impi_str = core::str::from_utf8(inner).expect("IMPI must be valid UTF-8");
    assert!(
        impi_str.contains("@ims.mnc"),
        "IMPI must contain @ims.mnc: {impi_str}",
    );
    assert!(
        impi_str.ends_with("3gppnetwork.org"),
        "IMPI must end with 3gppnetwork.org: {impi_str}",
    );
}

// -- Domain assertions --

#[then("the domain response starts with tag A3")]
fn then_domain_tag_a3(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 0xA3,
        "Expected Domain TLV tag 0xA3, got {:02X?}",
        data.first()
    );
}

#[then("the domain starts with ims.mnc")]
fn then_domain_starts_ims(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(data.len() >= 3, "Domain TLV too short");
    let inner = &data[2..];
    let domain_str = core::str::from_utf8(inner).expect("Domain must be valid UTF-8");
    assert!(
        domain_str.starts_with("ims.mnc"),
        "Domain must start with ims.mnc: {domain_str}",
    );
}

#[then("the domain ends with 3gppnetwork.org")]
fn then_domain_ends_3gpp(world: &mut SimWorld) {
    let data = world.last_data();
    let inner = &data[2..];
    let domain_str = core::str::from_utf8(inner).expect("Domain must be valid UTF-8");
    assert!(
        domain_str.ends_with("3gppnetwork.org"),
        "Domain must end with 3gppnetwork.org: {domain_str}",
    );
}

#[then("the SUCI ephemeral key differs from the stashed response")]
fn then_suci_eph_key_differs(world: &mut SimWorld) {
    let current_data = world.last_data().to_vec();
    let first = world
        .first_auth_response
        .as_ref()
        .expect("No stashed SUCI response");

    let Response::Received {
        data: first_data, ..
    } = first
    else {
        panic!("Stashed response is not Received")
    };

    assert_eq!(first_data[0], 0xA1, "Stashed response missing A1 tag");
    assert_eq!(current_data[0], 0xA1, "Current response missing A1 tag");

    // Ephemeral PK starts at offset 10: tag(1) + len(1) + SUPI(1) + MCC_MNC(3) + routing(2) + scheme(1) + key_idx(1)
    // For Profile A: 32 bytes of X25519 ephemeral public key.
    assert!(first_data.len() >= 42, "Stashed SUCI too short for eph_pk");
    assert!(
        current_data.len() >= 42,
        "Current SUCI too short for eph_pk"
    );

    let first_eph_pk = &first_data[10..42];
    let current_eph_pk = &current_data[10..42];

    assert_ne!(
        first_eph_pk, current_eph_pk,
        "Consecutive GET IDENTITY calls must produce different ephemeral keys"
    );
}
