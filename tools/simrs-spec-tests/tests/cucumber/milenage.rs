#![allow(missing_docs)]
//! Step definitions for `milenage.feature` -- Milenage authentication.
//!
//! Crate under test: `simrs-milenage`.

use cucumber::{given, then, when};
use simrs_milenage::{AuthenticationAlgorithm, AuthenticationError, MilenageParams, OperatorVariant, SubscriberKey};
use simrs_secret::Secret;
use simrs_spec_tests::parse_hex;

use crate::world::SpecWorld;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex string into a fixed-size array, panicking on length mismatch.
fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
    let v = parse_hex(hex);
    let mut arr = [0u8; N];
    assert_eq!(
        v.len(),
        N,
        "expected {N} hex bytes, got {} from \"{hex}\"",
        v.len()
    );
    arr.copy_from_slice(&v);
    arr
}

/// Build `MilenageParams` from the current world state (K + OPc/OP + defaults).
fn build_params(world: &SpecWorld) -> MilenageParams {
    let k = world.milenage_k.expect("K not set");
    let op_variant = if let Some(opc) = world.milenage_opc {
        OperatorVariant::opc(Secret::new(opc))
    } else if let Some(op) = world.milenage_op {
        OperatorVariant::op(Secret::new(op))
    } else {
        panic!("neither OPc nor OP is set");
    };
    MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), op_variant)
}

// =========================================================================
// Background
// =========================================================================

#[given(regex = r"^the Milenage algorithm with default ETSI TS 135 206 constants$")]
fn given_milenage_defaults(world: &mut SpecWorld) {
    // Background step -- just ensure a clean state.
    world.milenage_k = None;
    world.milenage_opc = None;
    world.milenage_op = None;
    world.milenage_challenge = None;
    world.milenage_sequence_number = None;
    world.milenage_management_field = None;
    world.milenage_auth_mac = None;
    world.milenage_resync_mac = None;
    world.milenage_response = None;
    world.milenage_cipher_key = None;
    world.milenage_integrity_key = None;
    world.milenage_anonymity_key = None;
    world.milenage_resync_anonymity_key = None;
    world.milenage_gsm_cipher_key = None;
    world.milenage_auth_token = None;
    world.milenage_auth_result = None;
    world.milenage_f2_alt = None;
    world.milenage_param_result = None;
}

// =========================================================================
// GIVEN steps -- parameter setup
// =========================================================================

#[given(regex = r#"^K is "([0-9A-Fa-f]+)"$"#)]
fn given_k(world: &mut SpecWorld, hex: String) {
    world.milenage_k = Some(hex_to_array::<16>(&hex));
}

#[given(regex = r#"^OPc is "([0-9A-Fa-f]+)"$"#)]
fn given_opc(world: &mut SpecWorld, hex: String) {
    world.milenage_opc = Some(hex_to_array::<16>(&hex));
}

#[given(regex = r#"^RAND is "([0-9A-Fa-f]+)"$"#)]
fn given_rand(world: &mut SpecWorld, hex: String) {
    world.milenage_challenge = Some(hex_to_array::<16>(&hex));
}

#[given(regex = r#"^SQN is "([0-9A-Fa-f]+)"$"#)]
fn given_sqn(world: &mut SpecWorld, hex: String) {
    world.milenage_sequence_number = Some(hex_to_array::<6>(&hex));
}

#[given(regex = r#"^AMF is "([0-9A-Fa-f]+)"$"#)]
fn given_amf(world: &mut SpecWorld, hex: String) {
    world.milenage_management_field = Some(hex_to_array::<2>(&hex));
}

#[given(regex = r#"^a valid AUTN constructed from SQN "([0-9A-Fa-f]+)" and AMF "([0-9A-Fa-f]+)"$"#)]
fn given_valid_autn(world: &mut SpecWorld, sqn_hex: String, amf_hex: String) {
    let sequence_number = hex_to_array::<6>(&sqn_hex);
    let management_field = hex_to_array::<2>(&amf_hex);

    // Build AUTN = (SQN XOR AK) || AMF || MAC-A
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    let anonymity_key = params.compute_anonymity_key(&challenge);
    let auth_mac = params.compute_auth_mac(&challenge, &sequence_number, &management_field);

    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sequence_number[i] ^ anonymity_key[i];
    }
    autn[6..8].copy_from_slice(&management_field);
    autn[8..16].copy_from_slice(&auth_mac);

    world.milenage_auth_token = Some(autn);
}

#[given(regex = r#"^AUTN is "([0-9A-Fa-f]+)"$"#)]
fn given_autn(world: &mut SpecWorld, hex: String) {
    world.milenage_auth_token = Some(hex_to_array::<16>(&hex));
}

#[given(regex = r#"^custom constants with c1=c2="([0-9A-Fa-f]+)" and r1=r2=(\d+)$"#)]
fn given_custom_constants(world: &mut SpecWorld, c_hex: String, r_val: String) {
    let c_val = hex_to_array::<16>(&c_hex);
    let r: u8 = r_val.parse().expect("invalid r value");

    let k = world.milenage_k.expect("K not set");
    let opc = world.milenage_opc.expect("OPc not set");

    // Build ci array with c1==c2 and remaining as defaults
    let ci = [c_val, c_val, [0u8; 16], [0u8; 16], [0u8; 16]];
    let ri = [r, r, 32, 64, 96];

    let result = MilenageParams::new(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new(opc)), ci, ri);
    world.milenage_param_result = Some(result);
}

// =========================================================================
// WHEN steps -- algorithm invocations
// =========================================================================

#[when(regex = r"^f1 is computed$")]
fn when_f1(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    let sequence_number = world.milenage_sequence_number.expect("SQN not set");
    let management_field = world.milenage_management_field.expect("AMF not set");
    world.milenage_auth_mac = Some(params.compute_auth_mac(&challenge, &sequence_number, &management_field));
}

#[when(regex = r"^f1\* is computed$")]
fn when_f1_star(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    let sequence_number = world.milenage_sequence_number.expect("SQN not set");
    let management_field = world.milenage_management_field.expect("AMF not set");
    world.milenage_resync_mac = Some(params.compute_resync_mac(&challenge, &sequence_number, &management_field));
}

#[when(regex = r"^f2 is computed$")]
fn when_f2(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    world.milenage_response = Some(params.compute_response(&challenge));
}

#[when(regex = r"^f3 is computed$")]
fn when_f3(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    world.milenage_cipher_key = Some(*params.compute_cipher_key(&challenge).declassify());
}

#[when(regex = r"^f4 is computed$")]
fn when_f4(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    world.milenage_integrity_key = Some(*params.compute_integrity_key(&challenge).declassify());
}

#[when(regex = r"^f5 is computed$")]
fn when_f5(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    world.milenage_anonymity_key = Some(params.compute_anonymity_key(&challenge));
}

#[when(regex = r"^f5\* is computed$")]
fn when_f5_star(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    world.milenage_resync_anonymity_key = Some(params.compute_resync_anonymity_key(&challenge));
}

#[when(regex = r#"^f2 is computed with OPc "([0-9A-Fa-f]+)"$"#)]
fn when_f2_with_opc(world: &mut SpecWorld, opc_hex: String) {
    let k = world.milenage_k.expect("K not set");
    let opc = hex_to_array::<16>(&opc_hex);
    let challenge = world.milenage_challenge.expect("RAND not set");
    let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new(opc)));
    world.milenage_response = Some(params.compute_response(&challenge));
}

#[when(regex = r#"^f2 is computed with OP "([0-9A-Fa-f]+)"$"#)]
fn when_f2_with_op(world: &mut SpecWorld, op_hex: String) {
    let k = world.milenage_k.expect("K not set");
    let op = hex_to_array::<16>(&op_hex);
    let challenge = world.milenage_challenge.expect("RAND not set");
    let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::op(Secret::new(op)));
    world.milenage_f2_alt = Some(params.compute_response(&challenge));
}

#[when(regex = r"^authenticate is called$")]
fn when_authenticate(world: &mut SpecWorld) {
    let mut params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    let auth_token = world.milenage_auth_token.expect("AUTN not set");
    let result = params.authenticate(&challenge, &auth_token);
    // Store individual fields on success for Then steps.
    if let Ok(ref out) = result {
        world.milenage_response = Some(out.response);
        world.milenage_cipher_key = Some(*out.cipher_key.declassify());
        world.milenage_integrity_key = Some(*out.integrity_key.declassify());
        world.milenage_gsm_cipher_key = Some(*out.gsm_cipher_key.declassify());
    }
    world.milenage_auth_result = Some(result);
}

#[when(regex = r"^MilenageParams is constructed$")]
fn when_params_constructed(world: &mut SpecWorld) {
    // The custom constants step already set milenage_param_result.
    // If not set, build with current state.
    if world.milenage_param_result.is_none() {
        let k = world.milenage_k.expect("K not set");
        let opc = world.milenage_opc.expect("OPc not set");
        // Use default constants via `new` -- this should succeed.
        let ci = [[0u8; 16]; 5];
        let ri = [0u8; 5];
        let result = MilenageParams::new(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new(opc)), ci, ri);
        world.milenage_param_result = Some(result);
    }
}

#[when(regex = r"^MilenageParams is constructed with defaults$")]
fn when_params_defaults(world: &mut SpecWorld) {
    let k = world.milenage_k.expect("K not set");
    let opc = world.milenage_opc.expect("OPc not set");
    // with_defaults never fails -- wrap in Ok for the Then step.
    let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new(opc)));
    world.milenage_param_result = Some(Ok(params));
}

#[when(regex = r"^f2 is computed twice$")]
fn when_f2_twice(world: &mut SpecWorld) {
    let params = build_params(world);
    let challenge = world.milenage_challenge.expect("RAND not set");
    world.milenage_response = Some(params.compute_response(&challenge));
    world.milenage_f2_alt = Some(params.compute_response(&challenge));
}

// =========================================================================
// THEN steps -- result verification
// =========================================================================

#[then(regex = r#"^MAC-A equals "([0-9A-Fa-f]+)"$"#)]
fn then_mac_a(world: &mut SpecWorld, expected_hex: String) {
    let expected = hex_to_array::<8>(&expected_hex);
    let actual = world.milenage_auth_mac.expect("MAC-A not computed");
    assert_eq!(
        actual, expected,
        "MAC-A mismatch: got {}, expected {}",
        hex_string(&actual),
        expected_hex
    );
}

#[then(regex = r#"^MAC-S equals "([0-9A-Fa-f]+)"$"#)]
fn then_mac_s(world: &mut SpecWorld, expected_hex: String) {
    let expected = hex_to_array::<8>(&expected_hex);
    let actual = world.milenage_resync_mac.expect("MAC-S not computed");
    assert_eq!(
        actual, expected,
        "MAC-S mismatch: got {}, expected {}",
        hex_string(&actual),
        expected_hex
    );
}

#[then(regex = r#"^RES equals "([0-9A-Fa-f]+)"$"#)]
fn then_res(world: &mut SpecWorld, expected_hex: String) {
    let expected = hex_to_array::<8>(&expected_hex);
    let actual = world.milenage_response.expect("RES not computed");
    assert_eq!(
        actual, expected,
        "RES mismatch: got {}, expected {}",
        hex_string(&actual),
        expected_hex
    );
}

#[then(regex = r#"^CK equals "([0-9A-Fa-f]+)"$"#)]
fn then_ck(world: &mut SpecWorld, expected_hex: String) {
    let expected = hex_to_array::<16>(&expected_hex);
    let actual = world.milenage_cipher_key.expect("CK not computed");
    assert_eq!(
        actual, expected,
        "CK mismatch: got {}, expected {}",
        hex_string(&actual),
        expected_hex
    );
}

#[then(regex = r#"^IK equals "([0-9A-Fa-f]+)"$"#)]
fn then_ik(world: &mut SpecWorld, expected_hex: String) {
    let expected = hex_to_array::<16>(&expected_hex);
    let actual = world.milenage_integrity_key.expect("IK not computed");
    assert_eq!(
        actual, expected,
        "IK mismatch: got {}, expected {}",
        hex_string(&actual),
        expected_hex
    );
}

#[then(regex = r#"^AK equals "([0-9A-Fa-f]+)"$"#)]
fn then_ak(world: &mut SpecWorld, expected_hex: String) {
    let expected = hex_to_array::<6>(&expected_hex);
    let actual = world.milenage_anonymity_key.expect("AK not computed");
    assert_eq!(
        actual, expected,
        "AK mismatch: got {}, expected {}",
        hex_string(&actual),
        expected_hex
    );
}

#[then(regex = r#"^AK\* equals "([0-9A-Fa-f]+)"$"#)]
fn then_ak_star(world: &mut SpecWorld, expected_hex: String) {
    let expected = hex_to_array::<6>(&expected_hex);
    let actual = world.milenage_resync_anonymity_key.expect("AK* not computed");
    assert_eq!(
        actual, expected,
        "AK* mismatch: got {}, expected {}",
        hex_string(&actual),
        expected_hex
    );
}

#[then(regex = r"^both f2 results are identical$")]
fn then_f2_identical(world: &mut SpecWorld) {
    let a = world.milenage_response.expect("first f2 result not set");
    let b = world.milenage_f2_alt.expect("second f2 result not set");
    assert_eq!(a, b, "f2 results differ: {} vs {}", hex_string(&a), hex_string(&b));
}

#[then(regex = r"^both results are identical$")]
fn then_results_identical(world: &mut SpecWorld) {
    let a = world.milenage_response.expect("first result not set");
    let b = world.milenage_f2_alt.expect("second result not set");
    assert_eq!(a, b, "results differ: {} vs {}", hex_string(&a), hex_string(&b));
}

#[then(regex = r"^authentication succeeds$")]
fn then_auth_succeeds(world: &mut SpecWorld) {
    let result = world.milenage_auth_result.as_ref().expect("authenticate not called");
    assert!(result.is_ok(), "expected authentication success, got: {result:?}");
}

#[then(regex = r"^authentication fails with MAC failure$")]
fn then_auth_mac_failure(world: &mut SpecWorld) {
    let result = world.milenage_auth_result.as_ref().expect("authenticate not called");
    assert!(
        matches!(result, Err(AuthenticationError::MacFailure)),
        "expected MacFailure, got: {result:?}"
    );
}

#[then(regex = r"^Kc equals CK XOR CK\[8:\] XOR IK XOR IK\[8:\]$")]
fn then_kc_c3_conversion(world: &mut SpecWorld) {
    let auth = world
        .milenage_auth_result
        .as_ref()
        .expect("authenticate not called")
        .as_ref()
        .expect("authentication failed");

    // Compute expected Kc via C3 conversion.
    let ck = auth.cipher_key.declassify();
    let ik = auth.integrity_key.declassify();
    let mut expected = [0u8; 8];
    for i in 0..8 {
        expected[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
    }
    assert_eq!(
        auth.gsm_cipher_key.declassify(), &expected,
        "Kc mismatch: got {}, expected {}",
        hex_string(auth.gsm_cipher_key.declassify()),
        hex_string(&expected)
    );
}

#[then(regex = r"^construction fails with DuplicateCiRi error$")]
fn then_duplicate_ci_ri(world: &mut SpecWorld) {
    let result = world.milenage_param_result.as_ref().expect("params not constructed");
    assert!(
        matches!(result, Err(simrs_milenage::ParamError::DuplicateCiRi { .. })),
        "expected DuplicateCiRi error, got: {result:?}"
    );
}

#[then(regex = r"^construction succeeds$")]
fn then_construction_succeeds(world: &mut SpecWorld) {
    let result = world.milenage_param_result.as_ref().expect("params not constructed");
    assert!(result.is_ok(), "expected construction success, got: {result:?}");
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
}
