//! Security regression test harness for simrs.
//!
//! Provides helpers for APDU-level testing of SIM security properties.
//! Each integration test module (Gherkin feature file) exercises a specific
//! vulnerability class documented in the research reports.
//!
//! # Vulnerability Categories
//!
//! | Feature file | Category | Key References |
//! |--------------|----------|---------------|
//! | `pin_state_machine` | PIN/PUK state machine attacks | ETSI TS 102 221, `SIMuraI` USENIX 2024 |
//! | `apdu_boundary` | APDU boundary conditions | ISO 7816-4, APDU fuzzing research |
//! | `fs_access_control` | Filesystem access control bypass | ETSI TS 102 221 V18.0.0 clause 8 |
//! | `ota_envelope` | OTA/ENVELOPE injection | CVE-2019-16256, GSM 03.48 |
//! | `auth_protocol` | AUTHENTICATE protocol attacks | 3GPP TS 31.102, TS 33.102 |
//! | `data_leakage` | GET RESPONSE data leakage | ISO 7816-4 clause 7.6 |
//! | `ecies_suci` | ECIES/SUCI on-card computation | 3GPP TS 31.102 clause 7.5, TS 33.501 |
//!
//! # Restricted Distribution
//!
//! This crate contains proof-of-concept test sequences for known SIM vulnerabilities.
//! Handle according to your organization's security testing policy.
//!
//! # Multi-Version Testing
//!
//! To test against a different version of any simrs crate, change the path
//! dependencies in `Cargo.toml` or use Cargo's `[patch]` mechanism.

pub mod apdu;

use simrs_gsm::SubscriberKey as GsmSubscriberKey;
use simrs_milenage::{AuthChallenge, AuthManagementField, MilenageParams, OperatorVariant, SequenceNumber, SubscriberKey};
use simrs_pin::{PinKey, PinValue};
use simrs_sim::{Sim, SimEvent, SimResponse};
use simrs_usim::profile::{ADF_TABLE, REFERENCE_MF};
use simrs_usim::SuciSeed;

/// Type alias for the SIM instance used across all security tests.
pub type TestSim = Sim<MilenageParams, 256>;

/// Minimal ATR.
pub static ATR: [u8; 2] = [0x3B, 0x00];

// ---- Test credentials ----

/// Test Ki (all 0x11).
pub const TEST_KI: GsmSubscriberKey = GsmSubscriberKey::classify([0x11; 16]);
/// Test K (all 0x22).
pub const TEST_K: SubscriberKey = SubscriberKey::classify([0x22; 16]);
/// Test `OPc` (all 0x33).
pub const TEST_OPC: OperatorVariant = OperatorVariant::operator_cipher([0x33; 16]);
/// Test SUCI DRBG seed (all 0x44).
pub const TEST_SUCI_SEED: SuciSeed = SuciSeed::new([0x44; 32]);

// PIN/PUK digit-string constants live in apdu::PIN1_CORRECT etc.
// Encoding to 8-byte ISO format is done by apdu::encode_pin().

/// PIN1 max retries.
pub const PIN_MAX_RETRIES: u8 = 3;
/// PUK max retries.
pub const PUK_MAX_RETRIES: u8 = 10;

// ---- Helper: create a configured SIM ----

/// Create a new SIM instance with test credentials and PIN1 configured.
///
/// The SIM is in `Off` state; call `sim.process(SimEvent::PowerOn)` to
/// bring it to `Ready`.
///
/// # Panics
///
/// Panics if `add_pin` fails (should not happen with valid test data).
pub fn create_sim() -> TestSim {
    let mil = MilenageParams::with_defaults(TEST_K, TEST_OPC);
    let gsm = simrs_gsm::GsmApp::new(&REFERENCE_MF, TEST_KI);
    let usim = simrs_usim::UsimApp::new(&REFERENCE_MF, &ADF_TABLE, mil);
    let mut sim = TestSim::new(&ATR, gsm, usim);

    // Configure PIN1 with test values.
    let pin1 = PinValue::new(apdu::encode_pin(apdu::PIN1_CORRECT));
    let puk1 = PinValue::new(apdu::encode_pin(apdu::PUK1_CORRECT));
    sim.usim_app_mut()
        .pin_manager()
        .add_pin(PinKey::PIN1, &pin1, PIN_MAX_RETRIES, &puk1, PUK_MAX_RETRIES, true)
        .expect("add_pin1 must succeed");

    // Configure PIN2 with test values.
    let pin2 = PinValue::new(apdu::encode_pin(apdu::PIN2_CORRECT));
    let puk2 = PinValue::new(apdu::encode_pin(apdu::PUK2_CORRECT));
    sim.usim_app_mut()
        .pin_manager()
        .add_pin(PinKey::PIN2, &pin2, PIN_MAX_RETRIES, &puk2, PUK_MAX_RETRIES, true)
        .expect("add_pin2 must succeed");

    sim
}

/// Create a configured SIM and power it on.
pub fn create_sim_powered_on() -> TestSim {
    let mut sim = create_sim();
    let _ = sim.process(SimEvent::PowerOn);
    sim
}

/// Create a new SIM with SUCI service enabled.
///
/// Uses [`TEST_SUCI_SEED`] for the HMAC-DRBG ephemeral key derivation.
/// The SIM is in `Off` state; call `sim.process(SimEvent::PowerOn)` to start.
pub fn create_sim_with_suci() -> TestSim {
    let mut sim = create_sim();
    *sim.usim_app_mut().suci_mut() = Some(simrs_usim::SuciState::new(TEST_SUCI_SEED));
    sim
}

/// Create a configured SIM with SUCI service enabled and power it on.
pub fn create_sim_with_suci_powered_on() -> TestSim {
    let mut sim = create_sim_with_suci();
    let _ = sim.process(SimEvent::PowerOn);
    sim
}

// ---- APDU helpers ----

/// Parse a hex string like "00 A4 00 04 02 3F 00" into bytes.
///
/// Handles both space-separated and bracket-wrapped formats:
/// - `"00 A4 00 04"` (quoted, spaces)
/// - `[00 A4 00 04]` (bracketed, spaces)
///
/// # Panics
///
/// Panics if any token is not valid hexadecimal.
pub fn parse_hex(s: &str) -> Vec<u8> {
    let s = s.trim().trim_matches(|c| c == '[' || c == ']' || c == '"');
    s.split_whitespace()
        .filter(|tok| !tok.is_empty())
        .map(|tok| u8::from_str_radix(tok, 16).unwrap_or_else(|e| panic!("bad hex '{tok}': {e}")))
        .collect()
}

/// Send an APDU to the SIM and return the result.
///
/// Returns `Some((data, sw1, sw2))` if processed, `None` if ignored.
pub fn send_apdu(sim: &mut TestSim, cmd: &[u8]) -> Option<(Vec<u8>, u8, u8)> {
    match sim.process(SimEvent::Apdu(cmd)) {
        SimResponse::Apdu { data, sw } => {
            let [sw1, sw2] = sw.to_bytes();
            Some((data.to_vec(), sw1, sw2))
        }
        SimResponse::Ignored | SimResponse::Atr(_) => None,
    }
}

/// Send an APDU, panicking if it was ignored.
///
/// # Panics
///
/// Panics if the APDU is ignored by the SIM.
pub fn send_apdu_expect(sim: &mut TestSim, cmd: &[u8]) -> (Vec<u8>, u8, u8) {
    send_apdu(sim, cmd)
        .unwrap_or_else(|| panic!("APDU was ignored: {cmd:02X?}"))
}

/// Send an APDU and return just `(sw1, sw2)`, panicking if ignored.
pub fn send_apdu_sw(sim: &mut TestSim, cmd: &[u8]) -> (u8, u8) {
    let (_, sw1, sw2) = send_apdu_expect(sim, cmd);
    (sw1, sw2)
}

/// Block PIN1 by exhausting all retries with wrong PIN.
pub fn block_pin1(sim: &mut TestSim) {
    let cmd = apdu::verify(PinKey::PIN1, apdu::PIN1_WRONG).build();
    for _ in 0..PIN_MAX_RETRIES {
        send_apdu(sim, &cmd);
    }
}

/// Disable PIN1 with correct PIN.
///
/// # Panics
///
/// Panics if the DISABLE command does not return 90 00.
pub fn disable_pin1(sim: &mut TestSim) {
    let cmd = apdu::disable_pin(PinKey::PIN1, apdu::PIN1_CORRECT).build();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!((sw1, sw2), (0x90, 0x00), "DISABLE PIN1 setup failed");
}

/// Enable PIN1 with correct PIN (after disabling).
///
/// # Panics
///
/// Panics if the ENABLE command does not return 90 00.
pub fn enable_pin1(sim: &mut TestSim) {
    let cmd = apdu::enable_pin(PinKey::PIN1, apdu::PIN1_CORRECT).build();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!((sw1, sw2), (0x90, 0x00), "ENABLE PIN1 setup failed");
}

/// Verify PIN1 with correct PIN.
///
/// # Panics
///
/// Panics if the VERIFY command does not return 90 00.
pub fn verify_pin1(sim: &mut TestSim) {
    let cmd = apdu::verify(PinKey::PIN1, apdu::PIN1_CORRECT).build();
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!((sw1, sw2), (0x90, 0x00), "VERIFY PIN1 setup failed");
}

/// Submit N wrong PIN1 attempts.
pub fn submit_wrong_pin1(sim: &mut TestSim, count: usize) {
    let cmd = apdu::verify(PinKey::PIN1, apdu::PIN1_WRONG).build();
    for _ in 0..count {
        send_apdu(sim, &cmd);
    }
}

/// Submit N wrong PUK attempts.
pub fn submit_wrong_puk(sim: &mut TestSim, count: usize) {
    let cmd = apdu::unblock(PinKey::PIN1, "00000000", apdu::PIN1_NEW).build();
    for _ in 0..count {
        send_apdu(sim, &cmd);
    }
}

/// Select EF.ICCID (2FE2) under MF.
pub fn select_ef_iccid(sim: &mut TestSim) -> (u8, u8) {
    send_apdu_sw(sim, &apdu::select_fid(apdu::FID_ICCID).build())
}

// ---- AUTHENTICATE helpers ----

/// Construct a valid AUTN for the test Milenage credentials with a given
/// SQN and AMF, so AUTHENTICATE will accept the MAC.
pub fn build_valid_autn(challenge: &[u8; 16], sequence_number: [u8; 6], management_field: [u8; 2]) -> [u8; 16] {
    let params = MilenageParams::with_defaults(TEST_K, TEST_OPC);
    let ch = AuthChallenge::new(*challenge);
    let sqn = SequenceNumber::new(sequence_number);
    let amf = AuthManagementField::new(management_field);
    let anonymity_key = params.compute_anonymity_key(&ch);
    let auth_mac = params.compute_auth_mac(&ch, &sqn, &amf);
    let mut auth_token = [0u8; 16];
    for i in 0..6 {
        auth_token[i] = sequence_number[i] ^ anonymity_key.as_bytes()[i];
    }
    auth_token[6] = management_field[0];
    auth_token[7] = management_field[1];
    auth_token[8..16].copy_from_slice(auth_mac.as_bytes());
    auth_token
}

/// Build the full AUTHENTICATE APDU (CLA=00 INS=88 P1=00 P2=81)
/// with 0x10 RAND[16] 0x10 AUTN[16].
pub fn build_authenticate_apdu(challenge: &[u8; 16], auth_token: &[u8; 16]) -> Vec<u8> {
    apdu::authenticate_umts(challenge, auth_token).build()
}
