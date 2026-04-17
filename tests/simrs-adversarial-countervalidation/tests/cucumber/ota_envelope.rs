#![allow(missing_docs)]
//! OTA/ENVELOPE injection step definitions.
//!
//! Covers ENVELOPE before TERMINAL PROFILE, `SIMjacker`-style injection,
//! malformed BER-TLV payloads per:
//!   - CVE-2019-16256 (`SIMjacker`)
//!   - 3GPP TS 23.048 (OTA security)
//!   - ETSI TS 102 221 V18.0.0 clause 11.2

use cucumber::{given, then, when};
use simrs_adversarial_countervalidation::apdu;
use simrs_ota::{CommandPacketHeader, KeyIdentifier, OtaCryptoKey, OtaError, SecurityParameters};
use simrs_secret::Secret;

use super::world::{SimWorld, do_send_apdu, reset_state_snapshots, send_terminal_profile};

// =========================================================================
// GIVEN steps
// =========================================================================

#[given(regex = r"^TERMINAL PROFILE has (?:NOT yet been sent|not been sent)$")]
fn given_no_terminal_profile(world: &mut SimWorld) {
    // No-op: we haven't sent one yet.
    let _ = world;
}

#[given(regex = r"^I have sent TERMINAL PROFILE.*$")]
fn given_terminal_profile_sent(world: &mut SimWorld) {
    send_terminal_profile(world);
    reset_state_snapshots(world);
}

// =========================================================================
// WHEN steps
// =========================================================================

// ENVELOPE with empty SMS-PP download (D1 00) or zero-length TLV value.
#[when(regex = r"^I send ENVELOPE with (?:empty SMS-PP download|zero-length TLV value)$")]
fn when_envelope_empty_smspp(world: &mut SimWorld) {
    let cmd = apdu::envelope(&[0xD1, 0x00]).build();
    do_send_apdu(world, &cmd);
}

// ENVELOPE with empty data (Lc=0 byte explicitly present).
// Uses the envelope builder's header then appends an explicit Lc=0x00 byte.
// Normal build() omits Lc when data is empty (Case 1 APDU); this interposer
// mutation forces the Lc byte present to test the card's handling of a
// zero-length data field with an explicit length prefix.
#[when("I send ENVELOPE with empty data")]
fn when_envelope_empty_data(world: &mut SimWorld) {
    let base = apdu::envelope(&[]);
    let cmd = vec![base.cla, base.ins, base.p1, base.p2, 0x00];
    do_send_apdu(world, &cmd);
}

// ENVELOPE with truncated BER-TLV (tag D1, no length field).
#[when("I send ENVELOPE with truncated BER-TLV")]
fn when_envelope_truncated_tlv(world: &mut SimWorld) {
    let cmd = apdu::envelope(&[0xD1]).build();
    do_send_apdu(world, &cmd);
}

// ENVELOPE with 255-byte payload (Lc=0xFF boundary test).
#[when("I send ENVELOPE with 255-byte BER-TLV payload")]
fn when_envelope_255(world: &mut SimWorld) {
    let cmd = apdu::envelope(&[0x00; 255]).build();
    do_send_apdu(world, &cmd);
}

// ENVELOPE with valid SMS-PP download structure.
#[when("I send ENVELOPE with valid SMS-PP download")]
fn when_envelope_valid_smspp(world: &mut SimWorld) {
    // D1 07 82 02 83 81 06 01 81: Device Identities + Address TLV
    let cmd = apdu::envelope(&[0xD1, 0x07, 0x82, 0x02, 0x83, 0x81, 0x06, 0x01, 0x81]).build();
    do_send_apdu(world, &cmd);
}

// SIMjacker-style ENVELOPE: PROVIDE LOCAL INFO (type 0x26) without OTA security.
#[when("I send SIMjacker-style ENVELOPE with PROVIDE LOCAL INFO")]
fn when_envelope_simjacker(world: &mut SimWorld) {
    // D6 09 82 02 82 81 99 03 26 00 00: CAT envelope with PROVIDE LOCAL INFO
    let cmd = apdu::envelope(&[
        0xD6, 0x09, 0x82, 0x02, 0x82, 0x81, 0x99, 0x03, 0x26, 0x00, 0x00,
    ])
    .build();
    do_send_apdu(world, &cmd);
}

// =========================================================================
// THEN steps
// =========================================================================

#[then("no STK command is executed")]
fn then_no_stk(world: &mut SimWorld) {
    // SW1=91 indicates a proactive command is pending (STK was triggered).
    if let Some((sw1, sw2)) = world.last_sw_opt() {
        assert_ne!(
            sw1, 0x91,
            "SW 91 {sw2:02X} indicates a proactive command was triggered",
        );
    }
}

#[then("the ENVELOPE is rejected or the STK action is not executed")]
fn then_envelope_rejected(world: &mut SimWorld) {
    // SW1=91 would indicate a proactive command is pending.
    if let Some((sw1, sw2)) = world.last_sw_opt() {
        assert_ne!(
            sw1, 0x91,
            "SW 91 {sw2:02X} indicates a proactive command was triggered",
        );
    }
}

#[then(regex = r"^the response SW does not indicate that PROVIDE LOCAL INFO ran.*$")]
fn then_no_provide_local_info(world: &mut SimWorld) {
    // SW1=91 would indicate a proactive command is pending.
    if let Some((sw1, sw2)) = world.last_sw_opt() {
        assert_ne!(
            sw1, 0x91,
            "SW 91 {sw2:02X} indicates PROVIDE LOCAL INFO or other proactive command ran",
        );
    }
}

#[then(regex = r"^the SIM remains operational.*$")]
fn then_sim_operational(world: &mut SimWorld) {
    // Direct probe: intentionally bypasses do_send_apdu to avoid
    // clobbering the world response that preceding Then steps may check.
    let cmd = simrs_adversarial_countervalidation::apdu::select_fid(
        simrs_adversarial_countervalidation::apdu::FID_MF,
    )
    .build();
    let sim = world.sim_mut();
    let result = simrs_adversarial_countervalidation::send_apdu(sim, &cmd);
    assert!(
        result.is_some(),
        "SIM stopped responding after ENVELOPE (health-check SELECT MF returned None)",
    );
}

// =========================================================================
// OTA command packet MAC verification steps
// =========================================================================

/// OTA test key for MAC operations.
const OTA_MAC_KEY: [u8; 16] = [0xAA; 16];

/// Build a test OTA command packet with AES-CBC-MAC.
fn build_test_ota_packet() -> (Vec<u8>, Vec<u8>) {
    let mut hdr = CommandPacketHeader::new();
    // command_header = 0x02: CC (cryptographic checksum), no ciphering
    // response_header = 0x01: PoR required
    hdr.security_parameters = SecurityParameters {
        command_header: 0x02,
        response_header: 0x01,
    };
    hdr.ciphering_key_id = KeyIdentifier::new(0x01); // AES CBC
    hdr.integrity_key_id = KeyIdentifier::new(0x01); // AES CBC MAC
    hdr.target_app = [0xB0, 0x00, 0x10].into();
    hdr.counter = [0x00, 0x00, 0x00, 0x00, 0x01].into();

    let payload = b"Hello SIM";
    let mut buf = [0u8; 512];
    let len = simrs_ota::encode_command_packet(
        &hdr,
        payload,
        None,
        Some(&OtaCryptoKey::Aes(Secret::new(OTA_MAC_KEY))),
        &mut buf,
    )
    .expect("encode_command_packet must succeed");

    (buf[..len].to_vec(), payload.to_vec())
}

#[given("an OTA command packet encoded with AES-CBC-MAC")]
fn given_ota_packet(world: &mut SimWorld) {
    let (packet, _payload) = build_test_ota_packet();
    world.ota_packet = packet;
}

#[when("the packet is decoded with the correct key")]
fn when_decode_correct_key(world: &mut SimWorld) {
    let packet = world.ota_packet.clone();
    let mut hdr = CommandPacketHeader::new();
    let mut data = [0u8; 256];
    let mac_key = OtaCryptoKey::Aes(Secret::new(OTA_MAC_KEY));
    let result =
        simrs_ota::decode_command_packet(&packet, None, Some(&mac_key), &mut hdr, &mut data);
    match result {
        Ok(len) => {
            world.record_response((0x90, 0x00), data[..len].to_vec());
        }
        Err(e) => {
            panic!("Decode with correct key should succeed, got: {e}");
        }
    }
}

#[when("the MAC bytes in the packet are inverted and it is decoded")]
fn when_decode_tampered_mac(world: &mut SimWorld) {
    let mut packet = world.ota_packet.clone();
    // The CC (MAC) sits at offset 16 for 8 bytes (CC_SIZE=8 in simrs-ota).
    // Invert all 8 MAC bytes.
    for b in &mut packet[16..24] {
        *b ^= 0xFF;
    }
    let mut hdr = CommandPacketHeader::new();
    let mut data = [0u8; 256];
    let mac_key = OtaCryptoKey::Aes(Secret::new(OTA_MAC_KEY));
    let result =
        simrs_ota::decode_command_packet(&packet, None, Some(&mac_key), &mut hdr, &mut data);
    // Store result for Then assertion.
    match result {
        Ok(_) => {
            world.record_response((0x90, 0x00), vec![]);
        }
        Err(OtaError::MacVerifyFailed) => {
            world.record_response((0x98, 0x50), vec![]);
        }
        Err(e) => {
            panic!("Expected MacVerifyFailed, got: {e}");
        }
    }
}

#[when("the packet is decoded with a different key")]
fn when_decode_wrong_key(world: &mut SimWorld) {
    let packet = world.ota_packet.clone();
    let wrong_key = OtaCryptoKey::Aes(Secret::new([0xBB; 16])); // different from OTA_MAC_KEY
    let mut hdr = CommandPacketHeader::new();
    let mut data = [0u8; 256];
    let result =
        simrs_ota::decode_command_packet(&packet, None, Some(&wrong_key), &mut hdr, &mut data);
    match result {
        Ok(_) => {
            world.record_response((0x90, 0x00), vec![]);
        }
        Err(OtaError::MacVerifyFailed) => {
            world.record_response((0x98, 0x50), vec![]);
        }
        Err(e) => {
            panic!("Expected MacVerifyFailed, got: {e}");
        }
    }
}

// =========================================================================
// UST service gating / Call Control TLV validation steps
// =========================================================================

#[when("I send Call Control ENVELOPE without Device Identities")]
fn when_cc_no_device_ids(world: &mut SimWorld) {
    // Call Control (D4) with Address tag (0x06) but no Device Identities (0x82).
    let cmd = apdu::envelope(&[0xD4, 0x04, 0x06, 0x02, 0xAA, 0xBB]).build();
    do_send_apdu(world, &cmd);
}

#[when("I send Call Control ENVELOPE with Device Identities")]
fn when_cc_with_device_ids(world: &mut SimWorld) {
    // Call Control (D4) with Device Identities (0x82 0x02 0x83 0x81).
    let cmd = apdu::envelope(&[0xD4, 0x04, 0x82, 0x02, 0x83, 0x81]).build();
    do_send_apdu(world, &cmd);
}

#[then("decoding succeeds with the original data")]
fn then_decode_succeeds(world: &mut SimWorld) {
    assert_eq!(world.last_sw(), (0x90, 0x00), "Expected successful decode");
    assert_eq!(
        world.last_data(),
        b"Hello SIM",
        "Decoded data does not match original payload",
    );
}

#[then("decoding fails with MacVerifyFailed")]
fn then_decode_mac_failed(world: &mut SimWorld) {
    assert_eq!(
        world.last_sw(),
        (0x98, 0x50),
        "Expected MAC verification failure",
    );
}
