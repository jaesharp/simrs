//! Mandatory EF coverage audit for the reference GSM profile.
//!
//! Verifies that every EF listed in 3GPP TS 51.011 §10.2 as mandatory for
//! GSM Phase 2+ is present and selectable. The DF.GSM tree is selected via
//! `MF -> DF.GSM` before each EF SELECT.

use simrs_gsm::{GsmApp, SubscriberKey, profile};
use simrs_iso7816::Command;
use simrs_pin::{PinKey, PinValue};

fn app() -> GsmApp {
    let ki = SubscriberKey::classify([
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6,
        0xBC,
    ]);
    let mut a = GsmApp::new(&profile::REFERENCE_MF_GSM, ki);
    let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
    let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    a.pin_manager()
        .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
        .unwrap();
    let _ = a.pin_manager().verify(PinKey::PIN1, &pin_val);
    a
}

fn send(app: &mut GsmApp, apdu: &[u8]) -> ([u8; 256], usize) {
    let cmd = Command::parse(apdu).unwrap();
    let mut buf = [0u8; 256];
    let rsp = app.handle(&cmd, &mut buf);
    let len = rsp.len();
    (buf, len)
}

fn sw(buf: &[u8], len: usize) -> (u8, u8) {
    (buf[len - 2], buf[len - 1])
}

fn select_df_gsm(app: &mut GsmApp) {
    let (buf, _len) = send(app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
    assert_eq!(buf[0], 0x9F, "SELECT DF.GSM must return 9F XX, got {:02X}", buf[0]);
    let resp_len = buf[1];
    let (buf, len) = send(app, &[0xA0, 0xC0, 0x00, 0x00, resp_len]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
}

fn assert_selectable(app: &mut GsmApp, fid_hi: u8, fid_lo: u8, label: &str) {
    let (buf, _) = send(app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, fid_hi, fid_lo]);
    assert_eq!(
        buf[0], 0x9F,
        "SELECT {label} ({fid_hi:02X}{fid_lo:02X}) must return 9F XX, got {:02X}",
        buf[0]
    );
    let resp_len = buf[1];
    let (buf, len) = send(app, &[0xA0, 0xC0, 0x00, 0x00, resp_len]);
    assert_eq!(
        sw(&buf, len),
        (0x90, 0x00),
        "GET RESPONSE for {label} must return 9000"
    );
    // FID is at bytes 4-5 of GSM SELECT response (TS 51.011 §9.2.1).
    assert_eq!(
        (buf[4], buf[5]),
        (fid_hi, fid_lo),
        "{label}: response FID mismatch"
    );
}

/// GSM Phase 2+ mandatory EFs per TS 51.011 §10.2 are selectable.
#[test]
fn mandatory_df_gsm_efs_selectable() {
    let mut a = app();
    select_df_gsm(&mut a);

    // Mandatory at minimal tier.
    assert_selectable(&mut a, 0x6F, 0x05, "EF.LP");
    assert_selectable(&mut a, 0x6F, 0x07, "EF.IMSI");
    assert_selectable(&mut a, 0x6F, 0x20, "EF.Kc");
    assert_selectable(&mut a, 0x6F, 0x31, "EF.HPPLMN");
    assert_selectable(&mut a, 0x6F, 0x38, "EF.SST");
    assert_selectable(&mut a, 0x6F, 0x78, "EF.ACC");
    assert_selectable(&mut a, 0x6F, 0x7B, "EF.FPLMN");
    assert_selectable(&mut a, 0x6F, 0x7E, "EF.LOCI");
    assert_selectable(&mut a, 0x6F, 0xAD, "EF.AD");

    // Mandatory at standard tier.
    assert_selectable(&mut a, 0x6F, 0x30, "EF.PLMNsel");
    assert_selectable(&mut a, 0x6F, 0x37, "EF.ACMmax");
    assert_selectable(&mut a, 0x6F, 0x39, "EF.ACM");
    assert_selectable(&mut a, 0x6F, 0xAE, "EF.Phase");
}

/// EF.ICCID is selectable under MF.
#[test]
fn mandatory_mf_ef_iccid_selectable() {
    let mut a = app();
    let (buf, _) = send(&mut a, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
    assert_eq!(buf[0], 0x9F, "SELECT EF.ICCID must return 9F XX");
    let resp_len = buf[1];
    let (buf, len) = send(&mut a, &[0xA0, 0xC0, 0x00, 0x00, resp_len]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
}

/// EF.IMSI byte 0 must be 0x08 (length indicator). Non-degenerate.
#[test]
fn ef_imsi_non_degenerate() {
    let mut a = app();
    select_df_gsm(&mut a);
    send(&mut a, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07]);
    let (buf, len) = send(&mut a, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    assert_eq!(buf[0], 0x08, "IMSI length byte must be 0x08");
}

/// EF.Phase must indicate Phase 2+ (0x03).
#[test]
fn ef_phase_is_phase2_plus() {
    let mut a = app();
    select_df_gsm(&mut a);
    send(&mut a, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0xAE]);
    let (buf, len) = send(&mut a, &[0xA0, 0xB0, 0x00, 0x00, 0x01]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    assert_eq!(buf[0], 0x03, "EF.Phase must be 0x03 (Phase 2+)");
}

/// EF.AD byte 0 must equal a recognized MS operation mode value (0x00 normal,
/// 0x80 type approval, etc.). The reference profile uses 0x00.
#[test]
fn ef_ad_operation_mode() {
    let mut a = app();
    select_df_gsm(&mut a);
    send(&mut a, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0xAD]);
    let (buf, len) = send(&mut a, &[0xA0, 0xB0, 0x00, 0x00, 0x03]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    assert_eq!(buf[0], 0x00, "EF.AD operation mode must be 0x00 (normal)");
}

/// EF.Kc CKSN byte (byte 8) must be 0x07 (no key) for an unprovisioned card.
#[test]
fn ef_kc_cksn_no_key() {
    let mut a = app();
    select_df_gsm(&mut a);
    send(&mut a, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x20]);
    let (buf, len) = send(&mut a, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    assert_eq!(buf[8], 0x07, "EF.Kc CKSN must be 0x07");
}
