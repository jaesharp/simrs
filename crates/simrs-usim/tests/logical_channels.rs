//! Logical-channel tests for the USIM application.
//!
//! Exercises MANAGE CHANNEL (INS=0x70) OPEN/CLOSE semantics, CLA-routed
//! per-channel selection context, and reset clearing of supplementary
//! channels.  Specs:
//!
//! - ETSI TS 102 221 V18.3.0 clause 11.1.17 (MANAGE CHANNEL)
//! - ETSI TS 102 221 V18.3.0 clause 8.4.1 (per-channel selection context)
//! - ISO/IEC 7816-4:2020 clause 5.1.1 (CLA byte / logical channel encoding)
//!
//! Phones (Android RIL) routinely open supplementary channels to talk to
//! the USIM, ISIM, and carrier-config applets concurrently, so this
//! coverage is a hard prerequisite for the simtrace2 cardem
//! integration (WS-8).

use simrs_iso7816::Command;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_usim::UsimApp;
use simrs_usim::profile::{ADF_TABLE, REFERENCE_MF, USIM_AID};

// ETSI TS 135 208 Test Set 1 (Milenage) -- mirrors the in-crate unit
// tests so this file boots the same USIM under test.
const K_BYTES: [u8; 16] = [
    0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC,
];
const OPC_BYTES: [u8; 16] = [
    0xCD, 0x63, 0xCB, 0x71, 0x95, 0x4A, 0x9F, 0x4E, 0x48, 0xA5, 0x99, 0x4E, 0x37, 0xA0, 0x2B, 0xAF,
];

/// Build a fresh USIM with the reference MF + `ADF_USIM` mounted.
///
/// PIN1 is not configured; logical-channel commands and SELECT do not
/// require PIN1 access (per ETSI TS 102 221 V18.3.0 access conditions),
/// so the tests can run without VERIFY PIN.
fn make_app() -> UsimApp {
    let key = SubscriberKey::classify(K_BYTES);
    let opc = OperatorVariant::operator_cipher(OPC_BYTES);
    let mil = MilenageParams::with_defaults(key, opc);
    UsimApp::new(&REFERENCE_MF, &ADF_TABLE, mil)
}

/// Execute an APDU against `app`, returning the trimmed response.
fn exec(app: &mut UsimApp, apdu: &[u8]) -> ([u8; 256], usize) {
    let cmd = Command::parse(apdu).expect("APDU must parse");
    let mut buf = [0u8; 256];
    let rsp = app.handle(&cmd, &mut buf);
    let len = rsp.len();
    (buf, len)
}

/// Extract the trailing (SW1, SW2) status word.
fn sw(buf: &[u8], len: usize) -> (u8, u8) {
    assert!(len >= 2, "response must contain SW1 SW2");
    (buf[len - 2], buf[len - 1])
}

/// Apply a standard warm/cold reset to the USIM in-place, mirroring
/// `simrs_sim::Sim::apply_reset_effects` with `ResetEffects::all()`.
///
/// The simrs-usim crate is `no_std` and does not depend on simrs-sim, so
/// integration tests at this level synthesize the reset by invoking the
/// public reset entry points directly.
const fn warm_reset(app: &mut UsimApp) {
    app.clear_response_queue();
    app.reset_file_selection();
    app.close_all_channels();
    app.reset_proactive_session();
    app.clear_last_aid_match();
    app.pin_manager().reset_verified();
}

// ---------------------------------------------------------------------
// Test 1: MANAGE CHANNEL OPEN allocates free channels.
// ---------------------------------------------------------------------

/// `00 70 00 00 01` (P1=OPEN, P2=any, Le=1) must allocate one of the
/// three supplementary channels and return the assigned channel number.
/// Four allocations are required to exhaust the pool; a fifth must fail
/// with `68 81` (Logical channel not supported) per
/// [ETSI TS 102 221 V18.3.0 clause 11.1.17].
#[test]
fn manage_channel_open_allocates_free_channel() {
    let mut app = make_app();

    // First open: assigned channel must be in {1, 2, 3}.
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x01]);
    assert_eq!(sw(&buf, len), (0x90, 0x00), "first OPEN should succeed");
    assert!(
        len >= 3,
        "first OPEN must return one data byte (assigned channel), got len={len}"
    );
    let ch1 = buf[0];
    assert!(
        (1..=3).contains(&ch1),
        "assigned channel must be 1..=3, got {ch1}"
    );

    // Second and third opens: must return distinct channels.
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x01]);
    assert_eq!(sw(&buf, len), (0x90, 0x00), "second OPEN should succeed");
    let ch2 = buf[0];
    assert!((1..=3).contains(&ch2));

    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x01]);
    assert_eq!(sw(&buf, len), (0x90, 0x00), "third OPEN should succeed");
    let ch3 = buf[0];
    assert!((1..=3).contains(&ch3));

    // The three opens must yield three distinct channel numbers.
    assert_ne!(ch1, ch2, "channels 1 and 2 must differ ({ch1} vs {ch2})");
    assert_ne!(ch1, ch3, "channels 1 and 3 must differ ({ch1} vs {ch3})");
    assert_ne!(ch2, ch3, "channels 2 and 3 must differ ({ch2} vs {ch3})");

    // Fourth open: no free supplementary channel -- must fail.
    // ETSI TS 102 221 V18.3.0 clause 11.1.17 lists both 6A 81 and 68 81
    // for "logical channel not supported"; either is acceptable.  simrs
    // returns 68 81 (StatusWord::FunctionNotSupported(0x81)).
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x01]);
    let (sw1, sw2) = sw(&buf, len);
    assert!(
        (sw1 == 0x68 || sw1 == 0x6A) && sw2 == 0x81,
        "fourth OPEN must fail with 68 81 or 6A 81, got {sw1:02X} {sw2:02X}"
    );
}

// ---------------------------------------------------------------------
// Test 2: MANAGE CHANNEL OPEN with explicit channel.
// ---------------------------------------------------------------------

/// Per ETSI TS 102 221 V18.3.0 clause 11.1.17, OPEN with P2=ch
/// (1..=3) asks the UICC to open *that specific* channel and must
/// return no response data on success; a subsequent attempt to open
/// the same channel must fail.
#[test]
fn manage_channel_open_explicit_channel_two() {
    let mut app = make_app();

    // OPEN channel 2 explicitly.  Lc/Le omitted (case 1).
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x02]);
    assert_eq!(
        sw(&buf, len),
        (0x90, 0x00),
        "explicit OPEN of channel 2 should succeed"
    );
    assert_eq!(
        len, 2,
        "explicit OPEN must return SW only (no data), got len={len}"
    );

    // Verify channel 2 is now usable.
    let (buf, _len) = exec(&mut app, &[0x02, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    assert_eq!(
        buf[0], 0x61,
        "SELECT MF on opened channel 2 should return 61 XX (data available)"
    );

    // Second attempt to open channel 2: must fail (already open).
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x02]);
    let (sw1, _) = sw(&buf, len);
    assert_ne!(
        (sw1, buf[len - 1]),
        (0x90, 0x00),
        "second OPEN of channel 2 must fail (already open)"
    );
}

// ---------------------------------------------------------------------
// Test 3: SELECT on a non-zero channel isolates context.
// ---------------------------------------------------------------------

/// Each supplementary channel must carry its own selection context per
/// ETSI TS 102 221 V18.3.0 clause 8.4.1.  Selecting MF on channel 0 and
/// `ADF_USIM` on channel 1 must leave each channel reporting its own
/// current DF via STATUS.
#[test]
fn select_on_non_zero_channel_isolates_context() {
    let mut app = make_app();

    // Open channel 1.
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x01]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    let ch = buf[0];
    assert!((1..=3).contains(&ch));

    // On channel 0 (CLA=0x00): SELECT MF, drain FCP via GET RESPONSE.
    let (buf, _) = exec(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    assert_eq!(buf[0], 0x61, "SELECT MF on channel 0 should return 61 XX");
    let avail = buf[1];
    let (_, len) = exec(&mut app, &[0x00, 0xC0, 0x00, 0x00, avail]);
    // We only care that GET RESPONSE succeeds; FCP shape is covered elsewhere.
    assert!(len >= 2, "GET RESPONSE after SELECT MF must produce data");

    // On the opened supplementary channel (CLA=ch): SELECT ADF_USIM by AID,
    // drain FCP via GET RESPONSE on the same channel.
    let aid_len = u8::try_from(USIM_AID.len()).expect("USIM_AID fits in a byte");
    let mut select_adf = vec![ch, 0xA4, 0x04, 0x04, aid_len];
    select_adf.extend_from_slice(&USIM_AID);
    let (buf, _) = exec(&mut app, &select_adf);
    assert_eq!(
        buf[0], 0x61,
        "SELECT ADF_USIM by AID on channel {ch} should return 61 XX"
    );
    let avail = buf[1];
    let (_, len) = exec(&mut app, &[ch, 0xC0, 0x00, 0x00, avail]);
    assert!(
        len >= 2,
        "GET RESPONSE on channel {ch} after SELECT must produce data"
    );

    // STATUS P1=0x00 P2=0x01 returns DF name (AID) TLV when an ADF is
    // selected, otherwise FCP.  On channel 0 we expect *no* AID tag
    // (MF is selected); on channel `ch` we expect the USIM AID.
    //
    // Encoding: tag 0x84, length n, AID bytes.

    // Channel 0 status: MF is not an ADF, response should be FCP (tag 0x62).
    let (buf, len) = exec(&mut app, &[0x00, 0xF2, 0x00, 0x01, 0x00]);
    assert_eq!(
        sw(&buf, len),
        (0x90, 0x00),
        "STATUS on channel 0 should succeed"
    );
    assert_ne!(
        buf[0], 0x84,
        "channel 0 (MF selected) must NOT return AID tag 0x84"
    );

    // Channel `ch` status: ADF_USIM is selected -> AID tag 0x84.
    let (buf, len) = exec(&mut app, &[ch, 0xF2, 0x00, 0x01, 0x00]);
    assert_eq!(
        sw(&buf, len),
        (0x90, 0x00),
        "STATUS on channel {ch} should succeed"
    );
    assert_eq!(
        buf[0], 0x84,
        "channel {ch} (ADF_USIM selected) must return AID tag 0x84"
    );
    let aid_len = buf[1] as usize;
    assert_eq!(aid_len, USIM_AID.len());
    assert_eq!(
        &buf[2..2 + aid_len],
        &USIM_AID,
        "AID payload must equal USIM_AID"
    );
}

// ---------------------------------------------------------------------
// Test 4: MANAGE CHANNEL CLOSE.
// ---------------------------------------------------------------------

/// CLOSE with P1=0x80, P2=ch must close the channel and any subsequent
/// APDU on that CLA must fail with "logical channel not supported".
#[test]
fn manage_channel_close_makes_channel_unusable() {
    let mut app = make_app();

    // Open channel 2 explicitly so the close target is deterministic.
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x02]);
    assert_eq!(sw(&buf, len), (0x90, 0x00), "explicit OPEN should succeed");

    // Pre-flight: APDU on channel 2 should currently succeed.
    let (buf, _) = exec(&mut app, &[0x02, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    assert_eq!(
        buf[0], 0x61,
        "SELECT MF on open channel 2 should return 61 XX"
    );

    // CLOSE channel 2 (case 1: 4-byte APDU).
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x80, 0x02]);
    assert_eq!(
        sw(&buf, len),
        (0x90, 0x00),
        "CLOSE channel 2 should succeed"
    );

    // Subsequent APDU on CLA=0x02: channel is closed -> 68 81 or 6A 81.
    let (buf, len) = exec(&mut app, &[0x02, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    let (sw1, sw2) = sw(&buf, len);
    assert!(
        (sw1 == 0x68 || sw1 == 0x6A) && sw2 == 0x81,
        "APDU on closed channel 2 must fail with 68 81 or 6A 81, got {sw1:02X} {sw2:02X}"
    );
}

// ---------------------------------------------------------------------
// Test 5: APDU on never-opened channel.
// ---------------------------------------------------------------------

/// After cold reset, supplementary channels 1..=3 are closed by
/// default.  Any APDU on a closed channel must be rejected with `68 81`
/// per ETSI TS 102 221 V18.3.0 clause 11.1.18.
#[test]
fn apdu_on_never_opened_channel_rejected() {
    let mut app = make_app();

    // SELECT MF with CLA=0x01 (channel 1, never opened).
    let (buf, len) = exec(&mut app, &[0x01, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    let (sw1, sw2) = sw(&buf, len);
    assert!(
        (sw1 == 0x68 || sw1 == 0x6A) && sw2 == 0x81,
        "APDU on never-opened channel must fail with 68 81 or 6A 81, got {sw1:02X} {sw2:02X}"
    );

    // Same for channels 2 and 3.
    for ch in [0x02u8, 0x03u8] {
        let (buf, len) = exec(&mut app, &[ch, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let (sw1, sw2) = sw(&buf, len);
        assert!(
            (sw1 == 0x68 || sw1 == 0x6A) && sw2 == 0x81,
            "APDU on never-opened channel {ch} must fail with 68 81 or 6A 81, got {sw1:02X} {sw2:02X}"
        );
    }
}

// ---------------------------------------------------------------------
// Test 6: Reset clears all supplementary channels.
// ---------------------------------------------------------------------

/// Per ETSI TS 102 221 V18.3.0 clause 8.7, a card reset (cold or warm)
/// closes every supplementary logical channel.  After reset, APDUs
/// addressed to the previously-open channels must fail with
/// "logical channel not supported".
#[test]
fn reset_closes_all_supplementary_channels() {
    let mut app = make_app();

    // Open channels 1 and 2 explicitly so we know which CLAs to test
    // afterwards (the implementation may also pick these implicitly).
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x01]);
    assert_eq!(sw(&buf, len), (0x90, 0x00), "explicit OPEN of channel 1");
    let (buf, len) = exec(&mut app, &[0x00, 0x70, 0x00, 0x02]);
    assert_eq!(sw(&buf, len), (0x90, 0x00), "explicit OPEN of channel 2");

    // Pre-flight: both channels are usable.
    let (buf, _) = exec(&mut app, &[0x01, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    assert_eq!(buf[0], 0x61, "channel 1 should be open before reset");
    let (buf, _) = exec(&mut app, &[0x02, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    assert_eq!(buf[0], 0x61, "channel 2 should be open before reset");

    // Warm reset (mirrors simrs_sim::Sim with ResetEffects::all()).
    warm_reset(&mut app);

    // Both supplementary channels must now be closed.
    for ch in [0x01u8, 0x02u8] {
        let (buf, len) = exec(&mut app, &[ch, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let (sw1, sw2) = sw(&buf, len);
        assert!(
            (sw1 == 0x68 || sw1 == 0x6A) && sw2 == 0x81,
            "channel {ch} must be closed after reset, got {sw1:02X} {sw2:02X}"
        );
    }

    // Basic channel (CLA=0x00) must still work after reset.
    let (buf, _) = exec(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    assert_eq!(
        buf[0], 0x61,
        "basic channel 0 must remain usable after reset"
    );
}
