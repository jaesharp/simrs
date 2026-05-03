#![allow(missing_docs)]
//! Step definitions for `iso7816.feature` -- ISO 7816 APDU framing.
//!
//! Crate under test: `simrs-iso7816`.

use cucumber::{then, when};
use simrs_iso7816::{ApduError, ClassByte, Command, StatusWord};
use simrs_standards_integration_validation::parse_hex;

use crate::world::SpecWorld;

// =========================================================================
// WHEN steps -- command parsing
// =========================================================================

#[when(regex = r#"^bytes "([^"]*)" are parsed as a command$"#)]
fn when_bytes_parsed_as_command(world: &mut SpecWorld, hex: String) {
    let bytes = parse_hex(&hex);
    match Command::parse(&bytes) {
        Ok(cmd) => {
            world.parsed_ins = Some(cmd.ins());
            world.parsed_data = cmd.data().to_vec();
            world.parsed_le = Some(cmd.response_len());
            world.parse_error = None;
        }
        Err(ApduError::TooShort) => {
            world.parse_error = Some("TooShort".to_string());
        }
        Err(ApduError::DataTruncated) => {
            world.parse_error = Some("DataTruncated".to_string());
        }
    }
}

// =========================================================================
// THEN steps -- command field assertions
// =========================================================================

#[then(regex = r#"^INS is "([0-9A-Fa-f]{2})"$"#)]
fn then_ins_is(world: &mut SpecWorld, hex: String) {
    let expected = u8::from_str_radix(&hex, 16).unwrap();
    let actual = world.parsed_ins.expect("No parsed INS available");
    assert_eq!(
        actual, expected,
        "Expected INS {expected:02X}, got {actual:02X}"
    );
}

#[then(regex = r"^data is empty$")]
fn then_data_is_empty(world: &mut SpecWorld) {
    assert!(
        world.parsed_data.is_empty(),
        "Expected empty data, got {} bytes: {:02X?}",
        world.parsed_data.len(),
        world.parsed_data,
    );
}

#[then(regex = r"^Le is absent$")]
fn then_le_is_absent(world: &mut SpecWorld) {
    let le = world.parsed_le.expect("No parse result available");
    assert_eq!(le, None, "Expected Le absent, got Le={le:?}");
}

#[then(regex = r#"^Le is "([0-9A-Fa-f]{2})"$"#)]
fn then_le_is(world: &mut SpecWorld, hex: String) {
    let expected = u8::from_str_radix(&hex, 16).unwrap();
    let le = world.parsed_le.expect("No parse result available");
    assert_eq!(
        le,
        Some(expected),
        "Expected Le={expected:02X}, got Le={le:?}",
    );
}

#[then(regex = r#"^data is "([^"]*)"$"#)]
fn then_data_is(world: &mut SpecWorld, hex: String) {
    let expected = parse_hex(&hex);
    assert_eq!(
        world.parsed_data, expected,
        "Expected data {:02X?}, got {:02X?}",
        expected, world.parsed_data,
    );
}

#[then(regex = r"^parsing fails with TooShort$")]
fn then_parsing_fails_too_short(world: &mut SpecWorld) {
    let err = world
        .parse_error
        .as_deref()
        .expect("Expected parse error, but parsing succeeded");
    assert_eq!(err, "TooShort", "Expected TooShort, got {err}");
}

#[then(regex = r"^parsing fails with DataTruncated$")]
fn then_parsing_fails_data_truncated(world: &mut SpecWorld) {
    let err = world
        .parse_error
        .as_deref()
        .expect("Expected parse error, but parsing succeeded");
    assert_eq!(err, "DataTruncated", "Expected DataTruncated, got {err}");
}

// =========================================================================
// WHEN/THEN steps -- CLA byte classification
// =========================================================================

#[when(regex = r#"^CLA byte "([0-9A-Fa-f]{2})" is parsed$"#)]
fn when_cla_byte_parsed(world: &mut SpecWorld, hex: String) {
    let byte = u8::from_str_radix(&hex, 16).unwrap();
    let cla = ClassByte::parse(byte);
    let class_name = if cla.is_interindustry() {
        "Interindustry"
    } else {
        "Proprietary"
    };
    world.parsed_cla_class = Some(class_name.to_string());
}

#[then(regex = r#"^class is "([^"]*)"$"#)]
fn then_class_is(world: &mut SpecWorld, expected: String) {
    let actual = world
        .parsed_cla_class
        .as_deref()
        .expect("No CLA class parsed");
    assert_eq!(actual, expected, "Expected class {expected}, got {actual}");
}

// =========================================================================
// WHEN/THEN steps -- status word roundtrip
// =========================================================================

#[when(regex = r#"^status word SW1="([0-9A-Fa-f]{2})" SW2="([0-9A-Fa-f]{2})" is decoded$"#)]
fn when_status_word_decoded(world: &mut SpecWorld, sw1_hex: String, sw2_hex: String) {
    let sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let _sw = StatusWord::from_bytes(sw1, sw2);
    world.parsed_sw = Some((sw1, sw2));
}

#[then(regex = r#"^it re-encodes to SW1="([0-9A-Fa-f]{2})" SW2="([0-9A-Fa-f]{2})"$"#)]
fn then_it_re_encodes_to(world: &mut SpecWorld, sw1_hex: String, sw2_hex: String) {
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.parsed_sw.expect("No status word decoded");
    let sw = StatusWord::from_bytes(sw1, sw2);
    let [actual_sw1, actual_sw2] = sw.to_bytes();
    assert_eq!(
        (actual_sw1, actual_sw2),
        (expected_sw1, expected_sw2),
        "Re-encode mismatch: from_bytes({sw1:02X},{sw2:02X}).to_bytes() = \
         [{actual_sw1:02X},{actual_sw2:02X}], expected [{expected_sw1:02X},{expected_sw2:02X}]",
    );
}
