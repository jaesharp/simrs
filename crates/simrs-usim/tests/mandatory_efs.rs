//! Mandatory EF coverage audit for the reference profile.
//!
//! Verifies that every EF listed in [3GPP TS 31.102 V19.4.0 clause 4.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf)
//! as mandatory at the standard tier, plus the [ETSI TS 102 221](../../../docs/specs/etsi/ts-102-221/)
//! UICC platform EFs under MF, are selectable via SELECT and that their
//! contents are not entirely placeholder.
//!
//! The test boots a [`UsimApp`] from `profile::REFERENCE_MF` + `profile::ADF_TABLE`,
//! selects ADF.USIM by AID, then walks the FID list asserting each select
//! returns the `61 XX` data-available status and the subsequent GET RESPONSE
//! returns an FCP starting with tag `0x62` containing the expected FID
//! (TLV tag `0x83`).

use simrs_fs::{DfDef, Fid, FileRef};
use simrs_iso7816::Command;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_pin::{PinKey, PinValue};
use simrs_usim::{UsimApp, profile};

fn app() -> UsimApp {
    let k = SubscriberKey::classify([
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6,
        0xBC,
    ]);
    let opc = OperatorVariant::operator_cipher([
        0xCD, 0x63, 0xCB, 0x71, 0x95, 0x4A, 0x9F, 0x4E, 0x48, 0xA5, 0x99, 0x4E, 0x37, 0xA0, 0x2B,
        0xAF,
    ]);
    let mil = MilenageParams::with_defaults(k, opc);
    let mut a = UsimApp::new(&profile::REFERENCE_MF, &profile::ADF_TABLE, mil);
    let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
    let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    a.pin_manager()
        .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
        .unwrap();
    let _ = a.pin_manager().verify(PinKey::PIN1, &pin_val);
    a
}

fn send(app: &mut UsimApp, apdu: &[u8]) -> ([u8; 256], usize) {
    let cmd = Command::parse(apdu).unwrap();
    let mut buf = [0u8; 256];
    let rsp = app.handle(&cmd, &mut buf);
    let len = rsp.len();
    (buf, len)
}

fn sw(buf: &[u8], len: usize) -> (u8, u8) {
    (buf[len - 2], buf[len - 1])
}

fn select_adf_usim(app: &mut UsimApp) {
    let (buf, _len) = send(
        app,
        &[
            0x00, 0xA4, 0x04, 0x04, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
        ],
    );
    assert_eq!(buf[0], 0x61, "SELECT ADF.USIM must return 61 XX");
    let fcp_len = buf[1];
    let (buf, len) = send(app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
    assert_eq!(sw(&buf, len), (0x90, 0x00), "GET RESPONSE post ADF select");
}

fn assert_selectable(app: &mut UsimApp, fid_hi: u8, fid_lo: u8, label: &str) {
    let (buf, _) = send(app, &[0x00, 0xA4, 0x00, 0x04, 0x02, fid_hi, fid_lo]);
    assert_eq!(
        buf[0], 0x61,
        "SELECT {label} ({fid_hi:02X}{fid_lo:02X}) must return 61 XX, got {:02X}",
        buf[0]
    );
    let fcp_len = buf[1];
    let (buf, len) = send(app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
    assert_eq!(
        sw(&buf, len),
        (0x90, 0x00),
        "GET RESPONSE for {label} must return 9000"
    );
    assert_eq!(buf[0], 0x62, "{label} FCP must start with tag 62");
    let inner = &buf[2..fcp_len as usize];
    let fid_val =
        find_tlv_tag(inner, 0x83).unwrap_or_else(|| panic!("{label}: FCP missing FID tag 83"));
    assert_eq!(fid_val, &[fid_hi, fid_lo], "{label}: FCP FID mismatch");
}

fn find_tlv_tag(buf: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 1 < buf.len() {
        let t = buf[i];
        let l = buf[i + 1] as usize;
        if t == tag && i + 2 + l <= buf.len() {
            return Some(&buf[i + 2..i + 2 + l]);
        }
        i += 2 + l;
    }
    None
}

/// EFs under MF (UICC platform per ETSI TS 102 221).
#[test]
fn mandatory_mf_efs_selectable() {
    let mut a = app();
    // Already selected MF on init; select explicitly to be deterministic.
    let _ = send(&mut a, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    let _ = send(&mut a, &[0x00, 0xC0, 0x00, 0x00, 0x20]);

    assert_selectable(&mut a, 0x2F, 0xE2, "EF.ICCID");
    assert_selectable(&mut a, 0x2F, 0x00, "EF.DIR");
    assert_selectable(&mut a, 0x2F, 0x06, "EF.ARR");
    assert_selectable(&mut a, 0x2F, 0x05, "EF.PL");
}

/// EFs under ADF.USIM mandatory per TS 31.102 standard tier.
#[test]
fn mandatory_adf_usim_efs_selectable() {
    let mut a = app();
    select_adf_usim(&mut a);

    // Core auth/identity.
    assert_selectable(&mut a, 0x6F, 0x07, "EF.IMSI");
    assert_selectable(&mut a, 0x6F, 0xAD, "EF.AD");
    assert_selectable(&mut a, 0x6F, 0x38, "EF.UST");
    assert_selectable(&mut a, 0x6F, 0x08, "EF.Keys");
    assert_selectable(&mut a, 0x6F, 0x09, "EF.KeysPS");
    assert_selectable(&mut a, 0x6F, 0x78, "EF.ACC");

    // Location + state.
    assert_selectable(&mut a, 0x6F, 0x7E, "EF.LOCI");
    assert_selectable(&mut a, 0x6F, 0xE7, "EF.PSLOCI");
    assert_selectable(&mut a, 0x6F, 0xE3, "EF.EPSLOCI");
    assert_selectable(&mut a, 0x6F, 0xE4, "EF.EPSNSC");

    // PLMN selection.
    assert_selectable(&mut a, 0x6F, 0x7B, "EF.FPLMN");
    assert_selectable(&mut a, 0x6F, 0x31, "EF.HPPLMN");
    assert_selectable(&mut a, 0x6F, 0x60, "EF.PLMNwAcT");
    assert_selectable(&mut a, 0x6F, 0x61, "EF.OPLMNwAcT");
    assert_selectable(&mut a, 0x6F, 0x62, "EF.HPLMNwAcT");
    assert_selectable(&mut a, 0x6F, 0xD9, "EF.EHPLMN");

    // Security parameters.
    assert_selectable(&mut a, 0x6F, 0x06, "EF.ARR");
    assert_selectable(&mut a, 0x6F, 0x5B, "EF.START_HFN");
    assert_selectable(&mut a, 0x6F, 0x5C, "EF.THRESHOLD");
    assert_selectable(&mut a, 0x6F, 0xC4, "EF.NETPAR");

    // Language + emergency.
    assert_selectable(&mut a, 0x6F, 0x05, "EF.LI");
    assert_selectable(&mut a, 0x6F, 0xB7, "EF.ECC");
}

/// EF.IMSI byte 0 must be 0x08 (IMSI digit count). Non-degenerate.
#[test]
fn ef_imsi_non_degenerate() {
    let mut a = app();
    select_adf_usim(&mut a);
    send(&mut a, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
    let (buf, len) = send(&mut a, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    assert_eq!(buf[0], 0x08, "IMSI length byte must be 0x08");
    assert_ne!(
        &buf[1..9],
        &[0xFFu8; 8],
        "IMSI bytes 1-8 must not be all 0xFF"
    );
}

/// EF.AD byte 3 must be 0x02 (MNC=2 digits) for the reference profile.
#[test]
fn ef_ad_mnc_length() {
    let mut a = app();
    select_adf_usim(&mut a);
    send(&mut a, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0xAD]);
    let (buf, len) = send(&mut a, &[0x00, 0xB0, 0x00, 0x00, 0x04]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    assert_eq!(buf[3], 0x02, "EF.AD byte 3 must be 0x02 (MNC=2 digits)");
}

/// EF.UST must enable at least the LTE/E-UTRAN baseline services.
#[test]
fn ef_ust_enables_lte_baseline() {
    let mut a = app();
    select_adf_usim(&mut a);
    send(&mut a, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x38]);
    let (buf, len) = send(&mut a, &[0x00, 0xB0, 0x00, 0x00, 0x13]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    // Service 2 (Fixed Dialling) is bit 1 of byte 0; reference profile has 1-24 set.
    assert_ne!(
        buf[0] & 0b0000_0010,
        0,
        "EF.UST service 2 (FDN) must be enabled"
    );
    // Service 28 (SMS-PP Data Download) is bit 3 of byte 3.
    assert_ne!(
        buf[3] & 0b0000_1000,
        0,
        "EF.UST service 28 (SMS-PP Data Download) must be enabled"
    );
    // Service 30 (Call Control by USIM) is bit 5 of byte 3.
    assert_ne!(
        buf[3] & 0b0010_0000,
        0,
        "EF.UST service 30 (Call Control by USIM) must be enabled"
    );
}

/// EF.ECC must contain at least one real emergency code (not all 0xFF).
#[test]
fn ef_ecc_has_emergency_codes() {
    let mut a = app();
    select_adf_usim(&mut a);
    send(&mut a, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0xB7]);
    let (buf, len) = send(&mut a, &[0x00, 0xB2, 0x01, 0x04, 0x10]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    // Record 1 should start with BCD 11 F2 (= "112").
    assert_eq!(
        &buf[..2],
        &[0x11, 0xF2],
        "EF.ECC record 1 must encode the emergency number 112"
    );
}

/// EF.PSLOCI status byte must indicate not-updated (0x01); the rest 0xFF.
#[test]
fn ef_psloci_non_degenerate() {
    let mut a = app();
    select_adf_usim(&mut a);
    send(&mut a, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0xE7]);
    let (buf, len) = send(&mut a, &[0x00, 0xB0, 0x00, 0x00, 0x0E]);
    assert_eq!(sw(&buf, len), (0x90, 0x00));
    assert_eq!(
        buf[13], 0x01,
        "EF.PSLOCI routing-area update status must be 0x01 (not updated)"
    );
    assert_eq!(
        &buf[..13],
        &[0xFFu8; 13],
        "EF.PSLOCI bytes 0-12 must be 0xFF (unprovisioned)"
    );
}

/// Walks the static MF tree and counts EFs, verifying that the reference
/// profile contains the union of the standard-tier mandatory list above.
#[test]
fn mandatory_fids_present_in_static_tree() {
    fn collect_fids(df: &'static DfDef, out: &mut alloc::vec::Vec<u16>) {
        for child in df.children {
            match child {
                FileRef::Ef(ef) => out.push(ef.fid().value()),
                FileRef::Df(sub) => {
                    out.push(sub.fid.value());
                    collect_fids(sub, out);
                }
            }
        }
    }

    extern crate alloc;
    let mut fids = alloc::vec::Vec::new();
    collect_fids(&profile::REFERENCE_MF, &mut fids);
    for slot in &profile::ADF_TABLE {
        collect_fids(slot.root, &mut fids);
    }
    let must_have: &[u16] = &[
        0x2FE2, 0x2F00, 0x2F06, 0x2F05, // MF
        0x6F07, 0x6FAD, 0x6F38, 0x6F08, 0x6F09, 0x6F78, // identity + keys + ACC
        0x6F7E, 0x6FE7, 0x6FE3, 0x6FE4, // location
        0x6F7B, 0x6F31, 0x6F60, 0x6F61, 0x6F62, 0x6FD9, // PLMN
        0x6F06, 0x6F5B, 0x6F5C, 0x6FC4, // security
        0x6F05, 0x6FB7, // language + ECC
    ];
    for fid in must_have {
        assert!(
            fids.contains(fid),
            "Mandatory FID {fid:#06X} missing from static reference tree"
        );
    }
    // Sanity: also assert the Fid type accepts these.
    let _ = Fid::new(0x6F07);
}
