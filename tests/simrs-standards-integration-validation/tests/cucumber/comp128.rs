#![allow(missing_docs)]
//! Step definitions for `comp128.feature` -- COMP128v1 authentication.
//!
//! Crate under test: `simrs-comp128`.

use cucumber::{given, then, when};
use simrs_comp128::comp128;
use simrs_gsm::SubscriberKey as GsmSubscriberKey;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_secret::Secret;
use simrs_sim::{Sim, SimEvent};
use simrs_standards_integration_validation::{parse_hex, ATR, MF, TEST_K, TEST_OPC};

use super::world::{do_send_apdu, SpecWorld};

// =========================================================================
// GIVEN steps
// =========================================================================

#[given(regex = r"^the COMP128v1 algorithm is available$")]
fn given_comp128_available(_world: &mut SpecWorld) {
    // The algorithm is statically linked; nothing to initialise.
}

#[given(regex = r#"^Ki is "([0-9A-Fa-f]{32})"$"#)]
fn given_ki_is(world: &mut SpecWorld, hex: String) {
    let bytes = parse_hex(&hex);
    let mut ki = [0u8; 16];
    ki.copy_from_slice(&bytes);
    world.ki = Some(ki);
}

#[given(regex = r#"^a SIM with Ki "([0-9A-Fa-f]{32})"$"#)]
fn given_sim_with_ki(world: &mut SpecWorld, hex: String) {
    let bytes = parse_hex(&hex);
    let mut ki_bytes = [0u8; 16];
    ki_bytes.copy_from_slice(&bytes);

    // Store the Ki for later verification steps.
    world.ki = Some(ki_bytes);

    // Build a SIM with the specified Ki.
    let ki = GsmSubscriberKey::classify(ki_bytes);
    let gsm = simrs_gsm::GsmApp::new(&MF, ki);
    let mil = MilenageParams::with_defaults(
        SubscriberKey::classify(TEST_K),
        OperatorVariant::operator_cipher(TEST_OPC),
    );
    let usim = simrs_usim::UsimApp::new(&MF, &[], mil);
    let mut sim = Sim::<MilenageParams, 256>::new(&ATR, gsm, usim);
    let _ = sim.process(SimEvent::PowerOn);
    world.sim = Some(Box::new(sim));
    world.powered_on = true;
}

// =========================================================================
// WHEN steps
// =========================================================================

#[when(regex = r"^COMP128v1 is computed$")]
fn when_comp128_computed(world: &mut SpecWorld) {
    let ki = world.ki.expect("Ki not set");
    let rand = world.rand_val.expect("RAND not set");
    let result = comp128(&Secret::new(ki), &rand);
    world.sres = Some(*result.signed_response.as_bytes());
    world.kc = Some(*result.cipher_key.declassify_ref());
}

#[when(regex = r"^COMP128v1 is computed twice$")]
fn when_comp128_computed_twice(world: &mut SpecWorld) {
    let ki = world.ki.expect("Ki not set");
    let rand = world.rand_val.expect("RAND not set");
    let r1 = comp128(&Secret::new(ki), &rand);
    let r2 = comp128(&Secret::new(ki), &rand);
    world.sres = Some(*r1.signed_response.as_bytes());
    world.kc = Some(*r1.cipher_key.declassify_ref());
    world.sres_alt = Some(*r2.signed_response.as_bytes());
    world.kc_alt = Some(*r2.cipher_key.declassify_ref());
}

#[when(regex = r#"^COMP128v1 is computed with RAND "([0-9A-Fa-f]{32})"$"#)]
fn when_comp128_with_rand(world: &mut SpecWorld, hex: String) {
    let bytes = parse_hex(&hex);
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&bytes);
    let ki = world.ki.expect("Ki not set");
    let result = comp128(&Secret::new(ki), &rand);

    // Shift current result into alt slot, then store new result.
    if world.sres.is_some() {
        world.sres_alt = world.sres;
        world.kc_alt = world.kc;
    }
    world.sres = Some(*result.signed_response.as_bytes());
    world.kc = Some(*result.cipher_key.declassify_ref());
}

#[when(regex = r#"^COMP128v1 is computed with Ki "([0-9A-Fa-f]{32})"$"#)]
fn when_comp128_with_ki(world: &mut SpecWorld, hex: String) {
    let bytes = parse_hex(&hex);
    let mut ki = [0u8; 16];
    ki.copy_from_slice(&bytes);
    let rand = world.rand_val.expect("RAND not set");
    let result = comp128(&Secret::new(ki), &rand);

    // Shift current result into alt slot, then store new result.
    if world.sres.is_some() {
        world.sres_alt = world.sres;
        world.kc_alt = world.kc;
    }
    world.sres = Some(*result.signed_response.as_bytes());
    world.kc = Some(*result.cipher_key.declassify_ref());
}

#[when(regex = r#"^the terminal sends RUN GSM ALGORITHM with RAND "([0-9A-Fa-f]{32})"$"#)]
fn when_run_gsm_algorithm(world: &mut SpecWorld, hex: String) {
    let rand_bytes = parse_hex(&hex);
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&rand_bytes);
    world.rand_val = Some(rand);

    // RUN GSM ALGORITHM: CLA=A0, INS=88, P1=00, P2=00, Lc=10, <RAND>
    let mut cmd = vec![0xA0, 0x88, 0x00, 0x00, 0x10];
    cmd.extend_from_slice(&rand);
    do_send_apdu(world, &cmd);
}

// =========================================================================
// THEN steps
// =========================================================================

#[then(regex = r"^SRES has length (\d+)$")]
fn then_sres_has_length(world: &mut SpecWorld, len: usize) {
    let sres = world.sres.expect("SRES not computed");
    assert_eq!(
        sres.len(),
        len,
        "Expected SRES length {len}, got {}",
        sres.len(),
    );
}

#[then(regex = r"^Kc has length (\d+)$")]
fn then_kc_has_length(world: &mut SpecWorld, len: usize) {
    let kc = world.kc.expect("Kc not computed");
    assert_eq!(kc.len(), len, "Expected Kc length {len}, got {}", kc.len());
}

#[then(regex = r#"^Kc byte 7 equals "([0-9A-Fa-f]{2})"$"#)]
fn then_kc_byte_7_equals(world: &mut SpecWorld, hex: String) {
    let expected = u8::from_str_radix(&hex, 16).unwrap();
    let kc = world.kc.expect("Kc not computed");
    assert_eq!(
        kc[7], expected,
        "Expected Kc[7] = {expected:#04X}, got {:#04X}",
        kc[7],
    );
}

#[then(regex = r"^Kc byte 6 has bottom 2 bits clear$")]
fn then_kc_byte_6_bottom_bits_clear(world: &mut SpecWorld) {
    let kc = world.kc.expect("Kc not computed");
    assert_eq!(
        kc[6] & 0x03,
        0x00,
        "Expected Kc[6] bottom 2 bits clear, got Kc[6] = {:#04X} (bottom 2 bits = {:#04X})",
        kc[6],
        kc[6] & 0x03,
    );
}

#[then(regex = r"^the two SRES values differ$")]
fn then_two_sres_differ(world: &mut SpecWorld) {
    let sres1 = world.sres_alt.expect("First SRES not computed");
    let sres2 = world.sres.expect("Second SRES not computed");
    assert_ne!(
        sres1, sres2,
        "Expected different SRES values, but both are {sres1:02X?}",
    );
}

#[then(regex = r#"^SRES is not "([0-9A-Fa-f]+)"$"#)]
fn then_sres_is_not(world: &mut SpecWorld, hex: String) {
    let forbidden = parse_hex(&hex);
    let sres = world.sres.expect("SRES not computed");
    assert_ne!(
        sres.as_slice(),
        forbidden.as_slice(),
        "SRES must not be {forbidden:02X?}",
    );
}

#[then(regex = r#"^Kc is not "([0-9A-Fa-f]+)"$"#)]
fn then_kc_is_not(world: &mut SpecWorld, hex: String) {
    let forbidden = parse_hex(&hex);
    let kc = world.kc.expect("Kc not computed");
    assert_ne!(
        kc.as_slice(),
        forbidden.as_slice(),
        "Kc must not be {forbidden:02X?}",
    );
}

#[then(regex = r#"^SRES equals "([0-9A-Fa-f]{8})"$"#)]
fn then_sres_equals(world: &mut SpecWorld, hex: String) {
    let expected = parse_hex(&hex);
    let sres = world.sres.expect("SRES not computed");
    assert_eq!(
        sres.as_slice(),
        expected.as_slice(),
        "Expected SRES {expected:02X?}, got {sres:02X?}",
    );
}

#[then(regex = r#"^Kc equals "([0-9A-Fa-f]{16})"$"#)]
fn then_kc_equals(world: &mut SpecWorld, hex: String) {
    let expected = parse_hex(&hex);
    let kc = world.kc.expect("Kc not computed");
    assert_eq!(
        kc.as_slice(),
        expected.as_slice(),
        "Expected Kc {expected:02X?}, got {kc:02X?}",
    );
}

// =========================================================================
// THEN steps -- APDU-level (RUN GSM ALGORITHM scenario)
// =========================================================================

#[then(regex = r#"^the SIM responds with status "([0-9A-Fa-f]{4})"$"#)]
fn then_sim_responds_with_status(world: &mut SpecWorld, hex: String) {
    let expected_sw1 = u8::from_str_radix(&hex[0..2], 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&hex[2..4], 16).unwrap();
    let (sw1, sw2) = world.last_sw.expect("No SW available (APDU was ignored?)");
    assert_eq!(
        (sw1, sw2),
        (expected_sw1, expected_sw2),
        "Expected SW {expected_sw1:02X}{expected_sw2:02X}, got {sw1:02X}{sw2:02X}",
    );
}

#[then(regex = r"^GET RESPONSE returns (\d+) bytes$")]
fn then_get_response_returns_n_bytes(world: &mut SpecWorld, expected_len: usize) {
    // GET RESPONSE: CLA=A0, INS=C0, P1=00, P2=00, Le=0C
    #[allow(clippy::cast_possible_truncation)] // expected_len is 12, fits in u8
    let cmd = [0xA0, 0xC0, 0x00, 0x00, expected_len as u8];
    do_send_apdu(world, &cmd);

    let (sw1, sw2) = world.last_sw.expect("No SW from GET RESPONSE");
    assert_eq!(
        (sw1, sw2),
        (0x90, 0x00),
        "GET RESPONSE failed: SW {sw1:02X}{sw2:02X}",
    );
    assert_eq!(
        world.last_data.len(),
        expected_len,
        "Expected {expected_len} bytes, got {}",
        world.last_data.len(),
    );
}

#[then(regex = r"^the first 4 bytes are the SRES$")]
fn then_first_4_bytes_are_sres(world: &mut SpecWorld) {
    assert!(
        world.last_data.len() >= 4,
        "Response too short for SRES extraction: {} bytes",
        world.last_data.len(),
    );
    let ki = world.ki.expect("Ki not set");
    let rand = world.rand_val.expect("RAND not set");
    let expected = comp128(&Secret::new(ki), &rand);
    let actual_sres = &world.last_data[..4];
    assert_eq!(
        actual_sres,
        expected.signed_response.as_bytes().as_slice(),
        "SRES mismatch: got {actual_sres:02X?}, expected {:02X?}",
        expected.signed_response.as_bytes(),
    );
}

#[then(regex = r"^the last 8 bytes are the Kc$")]
fn then_last_8_bytes_are_kc(world: &mut SpecWorld) {
    assert!(
        world.last_data.len() >= 12,
        "Response too short for Kc extraction: {} bytes",
        world.last_data.len(),
    );
    let ki = world.ki.expect("Ki not set");
    let rand = world.rand_val.expect("RAND not set");
    let expected = comp128(&Secret::new(ki), &rand);
    let actual_kc = &world.last_data[4..12];
    assert_eq!(
        actual_kc,
        expected.cipher_key.declassify_ref().as_slice(),
        "Kc mismatch: got {actual_kc:02X?}, expected {:02X?}",
        expected.cipher_key.declassify_ref(),
    );
}
