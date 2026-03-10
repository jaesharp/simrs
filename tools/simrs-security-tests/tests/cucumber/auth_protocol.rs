#![allow(missing_docs)]
//! AUTHENTICATE protocol attack step definitions.
//!
//! Covers AUTHENTICATE without ADF.USIM, wrong RAND length, MAC verification,
//! SQN sync failure, P2 validation per:
//!   - 3GPP TS 31.102 clause 7.1.2
//!   - 3GPP TS 33.102 clause 6.3
//!   - ETSI TS 102 221 V18.0.0 clause 11.1.10

use cucumber::{given, then, when};
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_security_tests::{apdu, build_authenticate_apdu, build_valid_autn, parse_hex, TEST_K, TEST_KI, TEST_OPC};

use super::snapshot::{reserve_auth, reserve_rsp_queue};
use super::world::{do_send_apdu, parse_db_response, reset_state_snapshots, select_adf_usim, Response, SimWorld};

// =========================================================================
// GIVEN steps
// =========================================================================

#[given("ADF.USIM is selected")]
fn given_adf_usim_selected(world: &mut SimWorld) {
    select_adf_usim(world);
    reset_state_snapshots(world);
}

// =========================================================================
// WHEN steps
// =========================================================================

// AUTHENTICATE with arbitrary RAND=[0xAA;16] and AUTN=[0xBB;16] (P2=0x81 UMTS).
#[when("I send AUTHENTICATE with arbitrary RAND and AUTN")]
fn when_authenticate_arbitrary(world: &mut SimWorld) {
    let challenge = [0xAA; 16];
    let auth_token = [0xBB; 16];
    let cmd = apdu::authenticate_umts(&challenge, &auth_token).build();
    do_send_apdu(world, &cmd);
}

// AUTHENTICATE with short RAND (fewer than 16 bytes).
#[when(regex = r"^I send AUTHENTICATE with short RAND of (\d+) bytes$")]
fn when_authenticate_short_rand(world: &mut SimWorld, n: usize) {
    let mut data = Vec::with_capacity(1 + n);
    data.push(u8::try_from(n).expect("RAND length must fit in u8"));
    data.extend(std::iter::repeat_n(0xAA, n));
    let cmd = apdu::authenticate_umts(&[0; 16], &[0; 16])
        .with_data(&data)
        .build();
    do_send_apdu(world, &cmd);
}

// AUTHENTICATE with zero-length RAND prefix.
#[when("I send AUTHENTICATE with zero-length RAND")]
fn when_authenticate_zero_rand(world: &mut SimWorld) {
    let cmd = apdu::authenticate_umts(&[0; 16], &[0; 16])
        .with_data(&[0x00])
        .build();
    do_send_apdu(world, &cmd);
}

#[when(
    regex = r"^I send AUTHENTICATE with a RAND and AUTN that pass Milenage MAC verification$"
)]
fn when_authenticate_valid(world: &mut SimWorld) {
    let challenge = [0xAA; 16];
    let sequence_number = [0x00; 6]; // SQN = 0: within the initial window
    let management_field = [0x80, 0x00];
    let auth_token = build_valid_autn(&challenge, sequence_number, management_field);
    let apdu = build_authenticate_apdu(&challenge, &auth_token);
    do_send_apdu(world, &apdu);
    // Auth (MilenageParams) is mutated: SQN_HE advances on successful AUTHENTICATE.
    // RspQueue changes: RES/CK/IK response data queued.
    reserve_auth(&mut world.reservations);
    reserve_rsp_queue(&mut world.reservations);
}

#[when(
    regex = r"^I send AUTHENTICATE with a valid RAND but with AUTN MAC field fully inverted.*$"
)]
fn when_authenticate_bad_mac(world: &mut SimWorld) {
    let challenge = [0xAA; 16];
    let sequence_number = [0x00; 6];
    let management_field = [0x80, 0x00];
    let mut auth_token = build_valid_autn(&challenge, sequence_number, management_field);
    // Invert the MAC field (bytes 8..16).
    for b in &mut auth_token[8..16] {
        *b ^= 0xFF;
    }
    let apdu = build_authenticate_apdu(&challenge, &auth_token);
    do_send_apdu(world, &apdu);
}

// Perform a successful AUTHENTICATE to advance SQN_HE, then reset snapshots.
#[given("a successful AUTHENTICATE has been performed")]
fn given_auth_done(world: &mut SimWorld) {
    let challenge = [0xAA; 16];
    let sequence_number = [0x00; 6]; // SQN = 0: accepted on first auth
    let management_field = [0x80, 0x00];
    let auth_token = build_valid_autn(&challenge, sequence_number, management_field);
    let apdu = build_authenticate_apdu(&challenge, &auth_token);
    do_send_apdu(world, &apdu);
    // Consume the response via GET RESPONSE.
    let (sw1, sw2) = world.last_sw();
    assert_eq!(sw1, 0x61, "Setup AUTHENTICATE must succeed (61 XX)");
    let get_rsp = apdu::get_response(sw2).build();
    do_send_apdu(world, &get_rsp);
    // Reset snapshots: captures the post-setup state (sqn_he=1, empty rsp_queue)
    // as the new baseline.  No reservations needed -- setup mutations are absorbed
    // into the baseline and won't trigger "no SIM state has changed" assertions.
    reset_state_snapshots(world);
}

// AUTHENTICATE with a replayed SQN (valid MAC but already consumed).
#[when(
    regex = r"^I send AUTHENTICATE with a replayed SQN.*$"
)]
fn when_authenticate_replayed_sqn(world: &mut SimWorld) {
    let challenge = [0xBB; 16]; // Different RAND for freshness
    let sequence_number = [0x00; 6]; // SQN = 0: already consumed by prior auth
    let management_field = [0x80, 0x00];
    let auth_token = build_valid_autn(&challenge, sequence_number, management_field);
    let apdu = build_authenticate_apdu(&challenge, &auth_token);
    do_send_apdu(world, &apdu);
}

// AUTHENTICATE GSM context (P2=0x00): RAND only, no AUTN.
#[when("I send AUTHENTICATE P2=0x00 GSM context with arbitrary RAND")]
fn when_authenticate_gsm_context(world: &mut SimWorld) {
    let challenge = [0xAA; 16];
    let cmd = apdu::authenticate_gsm(&challenge).build();
    do_send_apdu(world, &cmd);
}

// AUTHENTICATE with unsupported P2 context byte.
#[when(regex = r"^I send AUTHENTICATE with unsupported P2=0x([0-9A-Fa-f]{2})$")]
fn when_authenticate_unsupported_p2(world: &mut SimWorld, p2_hex: String) {
    let p2 = u8::from_str_radix(&p2_hex, 16).unwrap();
    let challenge = [0xAA; 16];
    let auth_token = [0xBB; 16];
    let cmd = apdu::authenticate_umts(&challenge, &auth_token).with_p2(p2).build();
    do_send_apdu(world, &cmd);
}

// AUTHENTICATE first call (stash response for comparison).
#[when("I send AUTHENTICATE with arbitrary RAND and AUTN (first call)")]
fn when_authenticate_first(world: &mut SimWorld) {
    let challenge = [0xAA; 16];
    let auth_token = [0xBB; 16];
    let cmd = apdu::authenticate_umts(&challenge, &auth_token).build();
    do_send_apdu(world, &cmd);
    world.first_auth_response = Some(world.response().clone());
}

// AUTHENTICATE second call (different bytes).
#[when("I send AUTHENTICATE with different arbitrary RAND and AUTN (second call)")]
fn when_authenticate_second(world: &mut SimWorld) {
    let challenge = [0xCC; 16];
    let auth_token = [0xDD; 16];
    let cmd = apdu::authenticate_umts(&challenge, &auth_token).build();
    do_send_apdu(world, &cmd);
}

// =========================================================================
// THEN steps
// =========================================================================

#[then(regex = r"^the response starts with tag DB.*$")]
fn then_response_db(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 0xDB,
        "Expected response starting with tag 0xDB, got {:02X?}",
        data.first()
    );
}

#[then(regex = r"^the DB response contains a RES sub-field.*$")]
fn then_db_has_res(world: &mut SimWorld) {
    let parsed = parse_db_response(world.last_data())
        .expect("Failed to parse DB response structure");
    assert!(
        (4..=16).contains(&parsed.res.len()),
        "RES length {} outside valid range 4..=16",
        parsed.res.len(),
    );
    assert!(
        parsed.res.iter().any(|&b| b != 0),
        "RES is all zeros (suspicious)",
    );
}

#[then(regex = r"^the DB response contains a CK sub-field.*$")]
fn then_db_has_ck(world: &mut SimWorld) {
    let parsed = parse_db_response(world.last_data())
        .expect("Failed to parse DB response structure");
    assert_eq!(
        parsed.ck.len(),
        16,
        "CK length {} != 16",
        parsed.ck.len(),
    );
}

#[then(regex = r"^the DB response contains an IK sub-field.*$")]
fn then_db_has_ik(world: &mut SimWorld) {
    let parsed = parse_db_response(world.last_data())
        .expect("Failed to parse DB response structure");
    assert_eq!(
        parsed.ik.len(),
        16,
        "IK length {} != 16",
        parsed.ik.len(),
    );
}

#[then(regex = r"^the response starts with tag DC.*$")]
fn then_response_dc(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 0xDC,
        "Expected response starting with tag 0xDC (sync failure), got {:02X?}",
        data.first()
    );
}

#[then("the DC response contains an AUTS sub-field of exactly 14 bytes")]
fn then_dc_has_auts(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 0xDC,
        "Expected DC tag, got {:02X?}",
        data.first()
    );
    assert!(
        data.len() >= 16,
        "DC response too short to contain AUTS: need 16 bytes (tag + len + 14), got {}",
        data.len()
    );
    assert_eq!(
        data[1], 0x0E,
        "AUTS length byte must be 0x0E (14), got {:02X}",
        data[1]
    );
}

// Verify AUTS content independently: decode SQN_MS from AUTS[0..6] XOR f5*(RAND)
// and verify MAC-S = f1*(RAND, SQN_MS, AMF=0000) per TS 33.102 clause 6.3.5.
#[then("the AUTS encodes the expected SQN_MS and MAC-S for the replayed RAND")]
fn then_auts_content_valid(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(data.len() >= 16 && data[0] == 0xDC, "Expected DC response");
    let auts = &data[2..16];

    // The replay step uses RAND=[0xBB;16] and sqn_he should be 1 after
    // one successful auth with SQN=0.
    let challenge = [0xBB_u8; 16];
    let p = MilenageParams::with_defaults(SubscriberKey::new(TEST_K), OperatorVariant::Opc(TEST_OPC));

    // Recover SQN_MS: AUTS[0..6] = SQN_MS XOR AK*
    let resync_anonymity_key = p.compute_resync_anonymity_key(&challenge);
    let mut reported_sequence_number = [0u8; 6];
    for i in 0..6 {
        reported_sequence_number[i] = auts[i] ^ resync_anonymity_key[i];
    }
    // SQN_MS must be 1 (the card's sqn_he after accepting SQN=0).
    let expected_sqn_ms = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(
        reported_sequence_number, expected_sqn_ms,
        "AUTS SQN_MS must equal sqn_he=1, got {reported_sequence_number:02X?}",
    );

    // MAC-S must equal f1*(RAND, SQN_MS, AMF=0000).
    let resync_mac = p.compute_resync_mac(&challenge, &reported_sequence_number, &[0x00, 0x00]);
    assert_eq!(
        &auts[6..14],
        &resync_mac,
        "AUTS MAC-S must equal f1*(RAND, SQN_MS, AMF=0000)",
    );
}

#[then(regex = r"^the response does not contain tag DB or DC.*$")]
fn then_no_db_dc(world: &mut SimWorld) {
    let data = world.last_data();
    if !data.is_empty() {
        assert!(
            data[0] != 0xDB && data[0] != 0xDC,
            "Expected no DB/DC tag in GSM context response"
        );
    }
}

#[then(
    regex = r"^the response of the second call is not a copy of the first call's response$"
)]
fn then_second_not_copy(world: &mut SimWorld) {
    let first = world.first_auth_response.as_ref().expect("No first auth response stashed");
    let current = world.response();
    // If both are MAC failures (98 62), that's independent processing.
    if let (
        Response::Received { sw: (0x98, 0x62), .. },
        Response::Received { sw: (0x98, 0x62), .. },
    ) = (first, current) {
        return;
    }
    // If both have data, they must differ.
    if let (
        Response::Received { data: first_data, .. },
        Response::Received { data: current_data, .. },
    ) = (first, current) {
        assert!(
            first_data.is_empty() || current_data.is_empty() || first_data != current_data,
            "Second AUTHENTICATE response is a copy of the first",
        );
    }
}

// =========================================================================
// COMP128v1 Kc weakness steps
// =========================================================================

#[when(regex = r"^I compute COMP128 with RAND \[([^\]]+)\]$")]
fn when_compute_comp128(world: &mut SimWorld, hex: String) {
    let rand_bytes = parse_hex(&hex);
    assert_eq!(rand_bytes.len(), 16, "RAND must be 16 bytes");
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&rand_bytes);
    let result = simrs_comp128::comp128(&TEST_KI.0, &rand);
    // Store Kc in response for Then assertions.
    world.record_response((0x90, 0x00), result.kc.to_vec());
}

#[then(regex = r"^the Kc byte (\d+) is (0x[0-9A-Fa-f]+)$")]
fn then_kc_byte_is(world: &mut SimWorld, index: usize, hex_val: String) {
    let expected = u8::from_str_radix(hex_val.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("bad hex {hex_val:?}: {e}"));
    let data = world.last_data();
    assert!(
        index < data.len(),
        "Kc index {index} out of bounds (Kc has {} bytes)",
        data.len(),
    );
    assert_eq!(
        data[index], expected,
        "Kc[{index}] = {:02X}, expected {expected:02X}",
        data[index],
    );
}

#[then(regex = r"^the Kc byte (\d+) has bottom (\d+) bits zero$")]
fn then_kc_byte_bottom_bits_zero(world: &mut SimWorld, index: usize, n_bits: u8) {
    let data = world.last_data();
    assert!(
        index < data.len(),
        "Kc index {index} out of bounds (Kc has {} bytes)",
        data.len(),
    );
    let mask = (1u8 << n_bits) - 1;
    assert_eq!(
        data[index] & mask,
        0,
        "Kc[{index}] = {:02X}, expected bottom {n_bits} bits to be zero (mask {:02X})",
        data[index],
        mask,
    );
}
