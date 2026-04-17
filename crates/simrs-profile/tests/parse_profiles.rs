//! Integration tests: parse real GSMA TS.48 Generic Test Profiles.
//!
//! These test against the actual DER-encoded profiles from the GSMA
//! TS.48 test suite (via pySim). Each profile is ~12KB of real-world
//! TCA eUICC Profile Package data.

use simrs_profile::{AuthConfig, ProfileError, load_profile};

/// Load a fixture DER profile by name.
fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/profiles/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

// ---------------------------------------------------------------------------
// Basic parsing: every fixture must parse without error
// ---------------------------------------------------------------------------

#[test]
fn parse_ts48v1_a() {
    let der = fixture("TS48v1_A.der");
    let config = load_profile(&der).expect("TS48v1_A should parse");
    assert!(!config.iccid.is_empty(), "ICCID must be present");
    assert!(!config.pins.is_empty(), "PINs must be present");
    assert!(!config.puks.is_empty(), "PUKs must be present");
}

#[test]
fn parse_ts48v2() {
    let der = fixture("TS48v2_SAIP2.3_BERTLV.der");
    let config = load_profile(&der).expect("TS48v2 should parse");
    assert!(!config.iccid.is_empty());
}

#[test]
fn parse_ts48v3() {
    let der = fixture("TS48v3_SAIP2.1_NoBERTLV.der");
    let config = load_profile(&der).expect("TS48v3 should parse");
    assert!(!config.iccid.is_empty());
}

#[test]
fn parse_ts48v4() {
    let der = fixture("TS48v4_SAIP2.3_BERTLV.der");
    let config = load_profile(&der).expect("TS48v4 should parse");
    assert!(!config.iccid.is_empty());
}

#[test]
fn parse_ts48v5() {
    let der = fixture("TS48v5_SAIP2.3_BERTLV_SUCI.der");
    let config = load_profile(&der).expect("TS48v5 should parse");
    assert!(!config.iccid.is_empty());
}

// ---------------------------------------------------------------------------
// ICCID verification
// ---------------------------------------------------------------------------

#[test]
fn ts48v1_iccid_correct() {
    let der = fixture("TS48v1_A.der");
    let config = load_profile(&der).unwrap();
    // GSMA TS.48 v1 test profile ICCID: 89 00 01 23 45 67 89 01 23 41
    // (BCD: 9800103254769810 3214)
    assert_eq!(config.iccid.len(), 10, "ICCID must be 10 bytes");
    assert_eq!(
        config.iccid,
        [0x89, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x41],
        "ICCID bytes must match TS.48 test profile"
    );
}

// ---------------------------------------------------------------------------
// Authentication parameter extraction
// ---------------------------------------------------------------------------

#[test]
fn ts48v1_auth_extracted() {
    let der = fixture("TS48v1_A.der");
    let config = load_profile(&der).unwrap();
    match &config.auth {
        AuthConfig::Milenage { k, opc } => {
            // TS.48 test profile uses XOR-3G (algorithm_id=3) with
            // K=[00..0F] and no OPc. extract_auth maps XOR-3G to
            // Milenage with zeroed OPc.
            assert_eq!(k.len(), 16);
            assert_eq!(opc.len(), 16);
            // K should be the well-known test key 00 01 02 ... 0F.
            assert_eq!(
                k,
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                "K must be the XOR-3G test key"
            );
        }
        other => panic!("expected Milenage auth, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// PIN/PUK configuration
// ---------------------------------------------------------------------------

#[test]
fn ts48v1_has_pin1_and_puk1() {
    let der = fixture("TS48v1_A.der");
    let config = load_profile(&der).unwrap();

    // Should have at least one PIN.
    assert!(
        !config.pins.is_empty(),
        "profile must have PIN configurations"
    );

    // Find PIN1 (key reference 0x01).
    let pin1 = config.pins.iter().find(|p| p.key_reference == 0x01);
    assert!(pin1.is_some(), "PIN1 (key_ref 0x01) must be present");

    // Should have at least one PUK.
    assert!(
        !config.puks.is_empty(),
        "profile must have PUK configurations"
    );
}

// ---------------------------------------------------------------------------
// Filesystem tree structure
// ---------------------------------------------------------------------------

#[test]
fn ts48v1_mf_has_children() {
    let der = fixture("TS48v1_A.der");
    let config = load_profile(&der).unwrap();

    // MF should have at least EF.ICCID, EF.DIR, EF.ARR.
    assert!(
        config.mf.children.len() >= 3,
        "MF should have at least 3 children, got {}",
        config.mf.children.len()
    );
}

#[test]
fn ts48v1_has_adf_usim() {
    let der = fixture("TS48v1_A.der");
    let config = load_profile(&der).unwrap();

    // Should have at least one ADF (USIM).
    assert!(!config.adf_table.is_empty(), "ADF table must not be empty");

    // First ADF should have the USIM AID prefix.
    let usim_aid_prefix = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];
    let has_usim = config
        .adf_table
        .iter()
        .any(|slot| slot.aid.len() >= 7 && slot.aid[..7] == usim_aid_prefix);
    assert!(has_usim, "ADF table must contain USIM AID");
}

#[test]
fn ts48v1_adf_usim_has_efs() {
    let der = fixture("TS48v1_A.der");
    let config = load_profile(&der).unwrap();

    // Find ADF.USIM.
    let usim_aid_prefix = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];
    let usim = config
        .adf_table
        .iter()
        .find(|slot| slot.aid.len() >= 7 && slot.aid[..7] == usim_aid_prefix)
        .expect("USIM ADF must exist");

    // ADF.USIM should have many children (EF.IMSI, EF.ARR, etc.).
    assert!(
        usim.root.children.len() >= 5,
        "ADF.USIM should have at least 5 EFs, got {}",
        usim.root.children.len()
    );
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn empty_input_is_error() {
    let result = load_profile(&[]);
    assert!(result.is_err());
}

#[test]
fn truncated_input_is_error() {
    let der = fixture("TS48v1_A.der");
    // Truncate to just 50 bytes -- should fail.
    let result = load_profile(&der[..50]);
    assert!(result.is_err());
}

#[test]
fn garbage_input_is_error() {
    let result = load_profile(&[0xFF; 100]);
    assert!(result.is_err());
}

#[test]
fn missing_header_is_error() {
    // Construct a SEQUENCE with just an End marker (tag 10), no header.
    // tag 0xAA = context [10] constructed, length 0
    let der = [0x30, 0x02, 0xAA, 0x00];
    let result = load_profile(&der);
    match result {
        Err(ProfileError::MissingHeader | ProfileError::MissingMf) => {}
        Err(e) => panic!("expected MissingHeader or MissingMf, got {e}"),
        Ok(_) => panic!("should have failed"),
    }
}

// ---------------------------------------------------------------------------
// All fixtures parse: parametric sweep
// ---------------------------------------------------------------------------

#[test]
fn all_fixtures_parse_successfully() {
    let fixture_dir = format!("{}/tests/fixtures/profiles", env!("CARGO_MANIFEST_DIR"));
    let entries: Vec<_> = std::fs::read_dir(&fixture_dir)
        .unwrap_or_else(|e| panic!("cannot read {fixture_dir}: {e}"))
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "der"))
        .collect();

    assert!(
        !entries.is_empty(),
        "no .der fixtures found in {fixture_dir}"
    );

    for entry in &entries {
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy();
        let der = std::fs::read(&path).unwrap();
        let result = load_profile(&der);
        match result {
            Ok(_) => {}
            Err(e) => panic!("failed to parse {name}: {e}"),
        }
    }
}
