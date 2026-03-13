//! Shared test helpers for the simrs spec-test suite.
//!
//! Provides hex parsing, SIM factory functions, and APDU helper routines
//! used by the Cucumber step definitions in `tests/cucumber/`.
//!
//! # Feature coverage
//!
//! | Feature file   | Crate(s) under test |
//! |----------------|---------------------|
//! | `bertlv`       | `simrs-bertlv` |
//! | `comp128`      | `simrs-comp128` |
//! | `fs`           | `simrs-fs` |
//! | `gsm`          | `simrs-gsm`, `simrs-comp128` |
//! | `iso7816`      | `simrs-iso7816` |
//! | `milenage`     | `simrs-milenage` |
//! | `pin`          | `simrs-pin` |
//! | `proactive`    | `simrs-proactive`, `simrs-bertlv` |
//! | `sim`          | `simrs-sim` |
//! | `transport`    | `simrs-transport` |
//! | `transport-tcp`| `simrs-transport-tcp` |
//! | `usim`         | `simrs-usim`, `simrs-milenage` |

use simrs_fs::{DfDef, EfDef, Fid, FileRef};
use simrs_gsm::Ki;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_pin::{PinKey, PinValue};
use simrs_sim::{Sim, SimEvent, SimResponse};

// ---- Static filesystem for tests ------------------------------------------------

/// EF.ICCID (transparent, 10 bytes) under MF.
static EF_ICCID: EfDef = EfDef::transparent(
    Fid::new(0x2FE2),
    None,
    &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

/// EF.DIR (linear-fixed, 1 record of 32 bytes) under MF.
static EF_DIR: EfDef = EfDef::linear_fixed(Fid::new(0x2F00), None, 32, 1, &[0xFF; 32]);

/// Minimal MF for spec tests.
pub static MF: DfDef = DfDef {
    fid: Fid::new(0x3F00),
    children: &[FileRef::Ef(&EF_ICCID), FileRef::Ef(&EF_DIR)],
};

/// Minimal ATR.
pub static ATR: [u8; 2] = [0x3B, 0x00];

// ---- Test credentials -----------------------------------------------------------

/// Test Ki (all 0x11).
pub const TEST_KI: Ki = Ki::classify([0x11; 16]);
/// Test K (all 0x22).
pub const TEST_K: [u8; 16] = [0x22; 16];
/// Test OPc (all 0x33).
pub const TEST_OPC: [u8; 16] = [0x33; 16];

/// Correct PIN1 value: ASCII "1234" + 0xFF padding.
pub const CORRECT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF];
/// Wrong PIN value.
pub const WRONG_PIN: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
/// Correct PUK value: ASCII "12345678".
pub const CORRECT_PUK: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
/// New PIN value for CHANGE/UNBLOCK: ASCII "5678" + 0xFF padding.
pub const NEW_PIN: [u8; 8] = [0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF];

/// PIN1 max retries.
pub const PIN_MAX_RETRIES: u8 = 3;
/// PUK max retries.
pub const PUK_MAX_RETRIES: u8 = 10;

// ---- Hex parsing ----------------------------------------------------------------

/// Parse a hex string like `"00 A4 00 04 02 3F 00"` into bytes.
///
/// Handles both space-separated and bracket-wrapped formats:
/// - `"00 A4 00 04"` (quoted, spaces)
/// - `[00 A4 00 04]` (bracketed, spaces)
/// - `00A40004` (compact, no spaces)
///
/// # Panics
///
/// Panics if any token is not valid hexadecimal.
pub fn parse_hex(s: &str) -> Vec<u8> {
    let s = s.trim().trim_matches(|c| c == '[' || c == ']' || c == '"');
    // If the string contains spaces, split on whitespace.
    if s.contains(' ') {
        s.split_whitespace()
            .filter(|tok| !tok.is_empty())
            .map(|tok| {
                u8::from_str_radix(tok, 16)
                    .unwrap_or_else(|e| panic!("bad hex '{tok}': {e}"))
            })
            .collect()
    } else {
        // Compact hex: parse pairs of characters.
        assert!(s.len() % 2 == 0, "compact hex must have even length: '{s}'");
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .unwrap_or_else(|e| panic!("bad hex '{}': {e}", &s[i..i + 2]))
            })
            .collect()
    }
}

// ---- SIM factory functions ------------------------------------------------------

/// Create a new SIM instance with test credentials and PIN1 configured.
///
/// The SIM is in `Off` state; call `sim.process(SimEvent::PowerOn)` to
/// bring it to `Ready`.
///
/// # Panics
///
/// Panics if `add_pin` fails (should not happen with valid test data).
pub fn create_sim() -> Sim<MilenageParams, 256> {
    let mil = MilenageParams::with_defaults(SubscriberKey::classify(TEST_K), OperatorVariant::opc(TEST_OPC));
    let gsm = simrs_gsm::GsmApp::new(&MF, TEST_KI);
    let mut usim = simrs_usim::UsimApp::new(&MF, &[], mil);

    // Configure PIN1 with test values.
    let pin_val = PinValue::new(CORRECT_PIN);
    let puk_val = PinValue::new(CORRECT_PUK);
    usim.pin_manager()
        .add_pin(
            PinKey::PIN1,
            &pin_val,
            PIN_MAX_RETRIES,
            &puk_val,
            PUK_MAX_RETRIES,
            true,
        )
        .expect("add_pin must succeed");

    Sim::<MilenageParams, 256>::new(&ATR, gsm, usim)
}

/// Create a configured SIM and power it on.
pub fn create_sim_powered_on() -> Sim<MilenageParams, 256> {
    let mut sim = create_sim();
    let _ = sim.process(SimEvent::PowerOn);
    sim
}

// ---- APDU helpers ---------------------------------------------------------------

/// Send an APDU to the SIM and return the result.
///
/// Returns `Some((data, sw1, sw2))` if processed, `None` if ignored.
pub fn send_apdu(sim: &mut Sim<MilenageParams, 256>, cmd: &[u8]) -> Option<(Vec<u8>, u8, u8)> {
    match sim.process(SimEvent::Apdu(cmd)) {
        SimResponse::Apdu { data, sw1, sw2 } => Some((data.to_vec(), sw1, sw2)),
        SimResponse::Ignored | SimResponse::Atr(_) => None,
    }
}

/// Send an APDU, panicking if it was ignored.
///
/// # Panics
///
/// Panics if the APDU is ignored by the SIM.
pub fn send_apdu_expect(
    sim: &mut Sim<MilenageParams, 256>,
    cmd: &[u8],
) -> (Vec<u8>, u8, u8) {
    send_apdu(sim, cmd)
        .unwrap_or_else(|| panic!("APDU was ignored: {cmd:02X?}"))
}

/// Send an APDU and return just `(sw1, sw2)`, panicking if ignored.
pub fn send_apdu_sw(sim: &mut Sim<MilenageParams, 256>, cmd: &[u8]) -> (u8, u8) {
    let (_, sw1, sw2) = send_apdu_expect(sim, cmd);
    (sw1, sw2)
}

/// Power cycle (reset) the SIM.
pub fn power_cycle(sim: &mut Sim<MilenageParams, 256>) {
    let _ = sim.process(SimEvent::PowerOn);
}

/// Verify PIN1 with correct PIN.
///
/// # Panics
///
/// Panics if the VERIFY command does not return 90 00.
pub fn verify_pin1(sim: &mut Sim<MilenageParams, 256>) {
    let cmd = [
        0x00, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    let (sw1, sw2) = send_apdu_sw(sim, &cmd);
    assert_eq!((sw1, sw2), (0x90, 0x00), "VERIFY PIN1 setup failed");
}

/// Select EF.ICCID (2FE2) under MF.
pub fn select_ef_iccid(sim: &mut Sim<MilenageParams, 256>) -> (u8, u8) {
    send_apdu_sw(sim, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2])
}
