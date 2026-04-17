#![allow(missing_docs)]
//! Step definitions for `bertlv.feature` -- BER-TLV encoding/decoding.
//!
//! Crate under test: `simrs-bertlv`.

use cucumber::{given, then, when};
use simrs_bertlv::{length_of_length, Decoder, Encoder};
use simrs_standards_integration_validation::parse_hex;

use crate::world::SpecWorld;

// =========================================================================
// GIVEN steps -- encoder setup
// =========================================================================

#[given(regex = r"^an encoder with a (\d+)-byte buffer$")]
fn given_encoder_with_buffer(world: &mut SpecWorld, size: usize) {
    world.tlv_encoder_output = vec![0u8; size];
    world.tlv_encoder_pos = 0;
    world.last_error = None;
    world.tlv_input_pairs.clear();
}

#[given(regex = r"^a dry-run encoder$")]
fn given_dry_run_encoder(world: &mut SpecWorld) {
    // Signal dry-run mode by leaving encoder_output empty.
    world.tlv_encoder_output.clear();
    world.tlv_encoder_pos = 0;
    world.last_error = None;
    world.tlv_dry_run_count = None;
    world.tlv_input_pairs.clear();
}

// =========================================================================
// GIVEN steps -- decoder setup
// =========================================================================

#[given(regex = r#"^input bytes "([^"]*)"$"#)]
fn given_input_bytes(world: &mut SpecWorld, hex: String) {
    world.hex_input = if hex.is_empty() {
        Vec::new()
    } else {
        parse_hex(&hex)
    };
    world.tlv_decoded.clear();
    world.last_error = None;
}

// =========================================================================
// GIVEN steps -- roundtrip input
// =========================================================================

#[given(
    regex = r#"^TLVs: tag=0x([0-9A-Fa-f]+) value="([^"]*)", tag=0x([0-9A-Fa-f]+) value="([^"]*)"$"#
)]
fn given_tlv_pairs(
    world: &mut SpecWorld,
    tag1_hex: String,
    val1_hex: String,
    tag2_hex: String,
    val2_hex: String,
) {
    let tag1 = u8::from_str_radix(&tag1_hex, 16).unwrap();
    let val1 = parse_hex(&val1_hex);
    let tag2 = u8::from_str_radix(&tag2_hex, 16).unwrap();
    let val2 = parse_hex(&val2_hex);
    world.tlv_input_pairs = vec![(tag1, val1), (tag2, val2)];
    world.last_error = None;
}

// =========================================================================
// WHEN steps -- encoding
// =========================================================================

#[when(regex = r#"^TLV tag=0x([0-9A-Fa-f]+) value="([^"]*)" is encoded$"#)]
fn when_tlv_encoded(world: &mut SpecWorld, tag_hex: String, val_hex: String) {
    let tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    let value = if val_hex.is_empty() {
        Vec::new()
    } else {
        parse_hex(&val_hex)
    };

    // Track input pairs for dry-run comparison.
    world.tlv_input_pairs.push((tag, value.clone()));

    if world.tlv_encoder_output.is_empty() {
        // Dry-run mode: count bytes only.
        let current = world.tlv_encoder_pos;
        let mut dry = Encoder::dry_run();
        // Replay all previously-encoded TLVs to reach current position.
        // (dry run encoder is stateless across calls, so we track pos manually)
        // Actually, we just need the incremental count. Simulate by calling once.
        match dry.tag_length_value(tag, &value) {
            Ok(()) => {
                world.tlv_encoder_pos = current + dry.len();
            }
            Err(_e) => {
                // Dry-run never returns BufferFull, but handle it.
                world.last_error = Some("BufferFull".to_string());
            }
        }
    } else {
        // Real write mode.
        // We need to encode into the buffer at the current position.
        let pos = world.tlv_encoder_pos;
        let buf_len = world.tlv_encoder_output.len();
        if pos >= buf_len {
            world.last_error = Some("BufferFull".to_string());
            return;
        }
        let mut enc = Encoder::new(&mut world.tlv_encoder_output[pos..]);
        match enc.tag_length_value(tag, &value) {
            Ok(()) => {
                world.tlv_encoder_pos = pos + enc.len();
                world.last_error = None;
            }
            Err(simrs_bertlv::BerError::BufferFull) => {
                world.last_error = Some("BufferFull".to_string());
            }
            Err(e) => {
                world.last_error = Some(format!("{e:?}"));
            }
        }
    }
}

// =========================================================================
// WHEN steps -- BER length encoding (Scenario Outline)
// =========================================================================

#[when(regex = r"^a value of (\d+) bytes is encoded$")]
fn when_value_of_n_bytes_encoded(world: &mut SpecWorld, length: usize) {
    // Store the length so the Then step can check length_of_length().
    world.tlv_length = Some(length);
}

// =========================================================================
// WHEN steps -- decoding
// =========================================================================

#[when(regex = r"^the input is decoded$")]
fn when_input_decoded(world: &mut SpecWorld) {
    let mut dec = Decoder::new(&world.hex_input);
    world.tlv_decoded.clear();
    world.last_error = None;

    for item in &mut dec {
        match item {
            Ok(obj) => {
                world.tlv_decoded.push((obj.tag, obj.value.to_vec()));
            }
            Err(simrs_bertlv::BerError::Truncated) => {
                world.last_error = Some("Truncated".to_string());
                return;
            }
            Err(e) => {
                world.last_error = Some(format!("{e:?}"));
                return;
            }
        }
    }
}

// =========================================================================
// WHEN steps -- roundtrip
// =========================================================================

#[when(regex = r"^encoded then decoded$")]
fn when_encoded_then_decoded(world: &mut SpecWorld) {
    // Encode all input pairs.
    let mut buf = [0u8; 256];
    let mut enc = Encoder::new(&mut buf);
    for (tag, ref value) in &world.tlv_input_pairs {
        enc.tag_length_value(*tag, value)
            .expect("encoding should succeed in roundtrip");
    }
    let written = enc.len();

    // Decode them back.
    let mut dec = Decoder::new(&buf[..written]);
    world.tlv_decoded.clear();
    for item in &mut dec {
        let obj = item.expect("decoding should succeed in roundtrip");
        world.tlv_decoded.push((obj.tag, obj.value.to_vec()));
    }
}

// =========================================================================
// THEN steps -- encoder assertions
// =========================================================================

#[then(regex = r#"^the output is "([^"]*)"$"#)]
fn then_output_is(world: &mut SpecWorld, hex: String) {
    let expected = parse_hex(&hex);
    let actual = &world.tlv_encoder_output[..world.tlv_encoder_pos];
    assert_eq!(
        actual,
        &expected[..],
        "Expected output {:02X?}, got {:02X?}",
        expected,
        actual,
    );
}

#[then(regex = r"^the encoder position is (\d+)$")]
fn then_encoder_position_is(world: &mut SpecWorld, expected: usize) {
    assert_eq!(
        world.tlv_encoder_pos, expected,
        "Expected encoder position {expected}, got {}",
        world.tlv_encoder_pos,
    );
}

#[then(regex = r"^encoding fails with BufferFull$")]
fn then_encoding_fails_buffer_full(world: &mut SpecWorld) {
    let err = world
        .last_error
        .as_deref()
        .expect("Expected encoding error, but encoding succeeded");
    assert_eq!(err, "BufferFull", "Expected BufferFull, got {err}");
}

// =========================================================================
// THEN steps -- dry-run comparison
// =========================================================================

#[then(regex = r"^the dry-run byte count equals a real write of the same TLVs$")]
fn then_dry_run_equals_real_write(world: &mut SpecWorld) {
    let dry_count = world.tlv_encoder_pos;
    let pairs = world.tlv_input_pairs.clone();

    // Now do a real write of the same TLVs.
    let mut buf = [0u8; 256];
    let mut enc = Encoder::new(&mut buf);
    for (tag, ref value) in &pairs {
        enc.tag_length_value(*tag, value)
            .expect("real write should succeed");
    }
    let real_count = enc.len();

    assert_eq!(
        dry_count, real_count,
        "Dry-run count ({dry_count}) differs from real write count ({real_count})",
    );
}

// =========================================================================
// THEN steps -- BER length encoding
// =========================================================================

#[then(regex = r"^the length field occupies (\d+) bytes?$")]
fn then_length_field_occupies(world: &mut SpecWorld, expected_bytes: usize) {
    let length = world.tlv_length.expect("No length value stored");
    let actual = length_of_length(length);
    assert_eq!(
        actual, expected_bytes,
        "length_of_length({length}) = {actual}, expected {expected_bytes}",
    );
}

// =========================================================================
// THEN steps -- decoder assertions
// =========================================================================

#[then(regex = r#"^one TLV object is returned with tag=0x([0-9A-Fa-f]+) value="([^"]*)"$"#)]
fn then_one_tlv_object_returned(world: &mut SpecWorld, tag_hex: String, val_hex: String) {
    let expected_tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    let expected_value = parse_hex(&val_hex);
    assert_eq!(
        world.tlv_decoded.len(),
        1,
        "Expected 1 TLV, got {}",
        world.tlv_decoded.len(),
    );
    let (tag, ref value) = world.tlv_decoded[0];
    assert_eq!(
        tag, expected_tag,
        "Expected tag {expected_tag:02X}, got {tag:02X}"
    );
    assert_eq!(
        value, &expected_value,
        "Expected value {:02X?}, got {:02X?}",
        expected_value, value,
    );
}

#[then(regex = r"^one TLV is returned with tag=0x([0-9A-Fa-f]+)$")]
fn then_one_tlv_returned_with_tag(world: &mut SpecWorld, tag_hex: String) {
    let expected_tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    assert_eq!(
        world.tlv_decoded.len(),
        1,
        "Expected 1 TLV, got {}",
        world.tlv_decoded.len(),
    );
    let (tag, _) = world.tlv_decoded[0];
    assert_eq!(
        tag, expected_tag,
        "Expected tag {expected_tag:02X}, got {tag:02X}"
    );
}

#[then(regex = r#"^decoding the value yields tag=0x([0-9A-Fa-f]+) value="([^"]*)"$"#)]
fn then_decoding_value_yields(world: &mut SpecWorld, tag_hex: String, val_hex: String) {
    let expected_tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    let expected_value = parse_hex(&val_hex);

    // Decode the value of the first (outer) TLV as nested BER-TLV.
    let (_, ref outer_value) = world.tlv_decoded[0];
    let mut inner_dec = Decoder::new(outer_value);
    let inner = inner_dec
        .next()
        .expect("Expected inner TLV")
        .expect("Inner TLV decode error");

    assert_eq!(
        inner.tag, expected_tag,
        "Expected inner tag {expected_tag:02X}, got {:02X}",
        inner.tag,
    );
    assert_eq!(
        inner.value,
        &expected_value[..],
        "Expected inner value {:02X?}, got {:02X?}",
        expected_value,
        inner.value,
    );
}

#[then(regex = r"^decoding fails with Truncated$")]
fn then_decoding_fails_truncated(world: &mut SpecWorld) {
    let err = world
        .last_error
        .as_deref()
        .expect("Expected decoding error, but decoding succeeded");
    assert_eq!(err, "Truncated", "Expected Truncated, got {err}");
}

#[then(regex = r"^no TLV objects are returned$")]
fn then_no_tlv_objects(world: &mut SpecWorld) {
    assert!(
        world.tlv_decoded.is_empty(),
        "Expected no TLV objects, got {}",
        world.tlv_decoded.len(),
    );
}

#[then(regex = r"^one TLV is returned with tag=0x([0-9A-Fa-f]+) and empty value$")]
fn then_one_tlv_empty_value(world: &mut SpecWorld, tag_hex: String) {
    let expected_tag = u8::from_str_radix(&tag_hex, 16).unwrap();
    assert_eq!(
        world.tlv_decoded.len(),
        1,
        "Expected 1 TLV, got {}",
        world.tlv_decoded.len(),
    );
    let (tag, ref value) = world.tlv_decoded[0];
    assert_eq!(
        tag, expected_tag,
        "Expected tag {expected_tag:02X}, got {tag:02X}"
    );
    assert!(
        value.is_empty(),
        "Expected empty value, got {} bytes: {:02X?}",
        value.len(),
        value,
    );
}

// =========================================================================
// THEN steps -- roundtrip
// =========================================================================

#[then(regex = r"^the decoded tags and values match the originals$")]
fn then_decoded_match_originals(world: &mut SpecWorld) {
    let pairs = &world.tlv_input_pairs;
    let decoded = &world.tlv_decoded;
    assert_eq!(
        pairs.len(),
        decoded.len(),
        "Expected {} TLVs, got {}",
        pairs.len(),
        decoded.len(),
    );
    for (i, ((exp_tag, exp_val), (act_tag, act_val))) in
        pairs.iter().zip(decoded.iter()).enumerate()
    {
        assert_eq!(
            act_tag, exp_tag,
            "TLV {i}: expected tag {exp_tag:02X}, got {act_tag:02X}",
        );
        assert_eq!(
            act_val, exp_val,
            "TLV {i}: expected value {:02X?}, got {:02X?}",
            exp_val, act_val,
        );
    }
}
