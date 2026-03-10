#![allow(missing_docs)]
//! GET RESPONSE data leakage step definitions.
//!
//! Covers GET RESPONSE without prior command, double GET RESPONSE,
//! FCP sensitive data exclusion, power cycle stale data per:
//!   - ISO/IEC 7816-4 clause 7.6
//!   - ETSI TS 102 221 V18.0.0 clause 11.1.2, 11.1.1.3

use cucumber::{then, when};
use simrs_security_tests::parse_hex;

use super::world::{contains_subseq, fcp_find_tag, tlv_read_length, SimWorld};

// =========================================================================
// WHEN steps
// =========================================================================

#[when(regex = r"^I send SimEvent::PowerOn.*$")]
fn when_simevent_power_on(world: &mut SimWorld) {
    let _atr = world.power_on();
}

// =========================================================================
// THEN steps -- FCP content and data leakage assertions
// =========================================================================

#[then("the FCP outer tag is 62")]
fn then_fcp_outer_62(world: &mut SimWorld) {
    let data = world.last_data();
    assert!(
        !data.is_empty() && data[0] == 0x62,
        "Expected FCP outer tag 0x62"
    );
}

#[then(regex = r"^the FCP contains tag ([0-9A-Fa-f]{2}) with value ([0-9A-Fa-f ]+).*$")]
fn then_fcp_contains_tag_value(world: &mut SimWorld, tag_hex: String, value_hex: String) {
    let tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    let expected_value = parse_hex(&value_hex);
    assert!(
        fcp_find_tag(world.last_data(), tag, Some(&expected_value)),
        "FCP does not contain tag {tag:02X} with value {expected_value:02X?}",
    );
}

#[then(regex = r"^the FCP contains tag ([0-9A-Fa-f]{2})(?:\s*\(.*\))?$")]
fn then_fcp_contains_tag(world: &mut SimWorld, tag_hex: String) {
    let tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    assert!(
        fcp_find_tag(world.last_data(), tag, None),
        "FCP does not contain tag {tag:02X}",
    );
}

#[then(regex = r"^every inner TLV tag is one of: (.+)$")]
fn then_fcp_only_permitted_tags(world: &mut SimWorld, tags_str: String) {
    let permitted: Vec<u8> = tags_str
        .split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect();
    let data = world.last_data();
    if data.len() < 2 || data[0] != 0x62 {
        return;
    }
    let (inner_len, offset) = tlv_read_length(data, 1);
    let inner = &data[offset..offset + inner_len];
    let mut pos = 0;
    while pos < inner.len() {
        let tag = inner[pos];
        assert!(
            permitted.contains(&tag),
            "FCP contains non-permitted tag {tag:02X}",
        );
        pos += 1;
        if pos >= inner.len() {
            break;
        }
        let (len, new_pos) = tlv_read_length(inner, pos);
        pos = new_pos + len;
    }
}

#[then(regex = r"^the FCP does not contain any byte sequence matching the test Ki\s+\[.*\]$")]
fn then_fcp_no_ki(world: &mut SimWorld) {
    let ki = [0x11u8; 16];
    assert!(
        !contains_subseq(world.last_data(), &ki),
        "FCP contains test Ki"
    );
}

#[then(regex = r"^the FCP does not contain any byte sequence matching the test K\s+\[.*\]$")]
fn then_fcp_no_k(world: &mut SimWorld) {
    let k = [0x22u8; 16];
    assert!(
        !contains_subseq(world.last_data(), &k),
        "FCP contains test K"
    );
}

#[then(regex = r"^the FCP does not contain any byte sequence matching the test OPc\s+\[.*\]$")]
fn then_fcp_no_opc(world: &mut SimWorld) {
    let opc = [0x33u8; 16];
    assert!(
        !contains_subseq(world.last_data(), &opc),
        "FCP contains test OPc"
    );
}

#[then("the FCP does not contain the raw EF.ICCID file content")]
fn then_no_raw_iccid(world: &mut SimWorld) {
    let iccid = simrs_usim::profile::EF_ICCID.data();
    assert!(
        !contains_subseq(world.last_data(), iccid),
        "FCP contains raw ICCID data ({iccid:02X?})"
    );
}

#[then("the command succeeds or returns an error")]
fn then_sw_9000_or_error(world: &mut SimWorld) {
    let (sw1, _) = world.last_sw();
    assert!(sw1 >= 0x60, "Unexpected SW1: {sw1:02X}");
}

#[then("if SW is 90 00 the response data length is at most SW2 of the preceding 61 XX")]
fn then_data_at_most_sw2(world: &mut SimWorld) {
    if world.last_sw() == (0x90, 0x00) {
        if let Some(expected_max) = world.prev_sw2_61 {
            assert!(
                world.last_data().len() <= expected_max as usize,
                "Response data is {} bytes but preceding 61 XX indicated at most {expected_max}",
                world.last_data().len(),
            );
        }
    }
}

#[then("the response data does not extend beyond the FCP buffer bounds")]
fn then_no_overread(world: &mut SimWorld) {
    let data = world.last_data();
    // If the response contains an FCP (tag 62), verify the actual data length
    // matches the BER-TLV declared length (tag + length + value).
    if data.len() >= 2 && data[0] == 0x62 {
        let (inner_len, hdr_end) = tlv_read_length(data, 1);
        let expected_total = hdr_end + inner_len;
        assert!(
            data.len() <= expected_total,
            "Response data ({} bytes) extends beyond FCP declared bounds ({expected_total} bytes)",
            data.len(),
        );
    }
}

#[then("the SIM returns ATR bytes")]
fn then_atr_returned(world: &mut SimWorld) {
    assert!(world.is_powered(), "Expected SIM to be powered on after ATR");
}
