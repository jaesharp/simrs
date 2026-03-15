#![allow(missing_docs)]
//! Step definitions for `fs.feature` -- ICC filesystem model.
//!
//! Crate under test: `simrs-fs`.
//!
//! These tests exercise the `SelectionCtx` API directly (library-level),
//! not through APDU processing.  The static filesystem tree defined below
//! mirrors the Background section of the feature file.

use cucumber::{given, then, when};
use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef, SelectedFile, SelectionCtx};
use simrs_spec_tests::parse_hex;

use crate::world::SpecWorld;

// =========================================================================
// Static filesystem tree (matches feature file Background)
// =========================================================================

// -- MF children --

static EF_ICCID: EfDef = EfDef::transparent(
    Fid::new(0x2FE2),
    None,
    &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

static EF_DIR: EfDef = EfDef::linear_fixed(
    Fid::new(0x2F00),
    None,
    8,           // record_size
    2,           // num_records
    &[0xFF; 16], // 8 * 2 = 16 bytes
);

// -- DF.TELECOM children --

static EF_ADN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3A),
    None,
    14, // record_size
    3,  // num_records
    // 14 * 3 = 42 bytes -- distinct per-record content so tests are meaningful.
    // Record 1: 0x01-repeated, Record 2: 0x02-repeated, Record 3: 0x03-repeated.
    &[
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    ],
);

static DF_TELECOM: DfDef = DfDef {
    fid: Fid::new(0x7F10),
    children: &[FileRef::Ef(&EF_ADN)],
};

// -- DF.GSM children --

static GSM_EF_IMSI: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

static GSM_EF_KC: EfDef = EfDef::transparent(
    Fid::new(0x6F20),
    None,
    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07],
);

static DF_GSM: DfDef = DfDef {
    fid: Fid::new(0x7F20),
    children: &[FileRef::Ef(&GSM_EF_IMSI), FileRef::Ef(&GSM_EF_KC)],
};

// -- MF --

pub(crate) static TEST_MF: DfDef = DfDef {
    fid: Fid::MF,
    children: &[
        FileRef::Ef(&EF_ICCID),
        FileRef::Ef(&EF_DIR),
        FileRef::Df(&DF_TELECOM),
        FileRef::Df(&DF_GSM),
    ],
};

// -- ADF.USIM --

static USIM_EF_IMSI: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    // Distinct from GSM EF.IMSI to verify ADF isolation.
    &[0x08, 0x29, 0x43, 0x05, 0x00, 0x10, 0x00, 0x00, 0xF0],
);

static ADF_USIM_ROOT: DfDef = DfDef {
    fid: Fid::new(0xFF01), // Internal FID for the ADF root
    children: &[FileRef::Ef(&USIM_EF_IMSI)],
};

static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
    aid: &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
    root: &ADF_USIM_ROOT,
}];

// =========================================================================
// Helpers
// =========================================================================

/// Obtain a mutable reference to the filesystem `SelectionCtx`, initializing
/// it from the test tree if it has not been created yet.
fn fs_ctx(world: &mut SpecWorld) -> &mut SelectionCtx {
    if world.fs_ctx.is_none() {
        world.fs_ctx = Some(SelectionCtx::new(&TEST_MF));
    }
    world.fs_ctx.as_mut().unwrap()
}

// =========================================================================
// GIVEN steps -- Background
// =========================================================================

/// Background: "Given a filesystem tree:" -- the tree is defined as statics
/// above, so this step just ensures a fresh SelectionCtx for each scenario.
#[given(regex = r"^a filesystem tree:$")]
fn given_filesystem_tree(world: &mut SpecWorld) {
    world.fs_ctx = Some(SelectionCtx::new(&TEST_MF));
    world.fs_result = None;
    world.fs_read_data.clear();
    world.last_error = None;
}

/// Background: "And an ADF table:" -- acknowledged; the static ADF_TABLE
/// is always available.
#[given(regex = r"^an ADF table:$")]
fn given_adf_table(_world: &mut SpecWorld) {
    // ADF_TABLE is a module-level static; nothing to initialize.
}

// =========================================================================
// GIVEN steps -- precondition setup
// =========================================================================

#[given(regex = r"^I am in DF\.GSM with an EF selected$")]
fn given_in_df_gsm_with_ef(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    ctx.select_by_fid(Fid::new(0x7F20)).expect("select DF.GSM");
    ctx.select_by_fid(Fid::new(0x6F07))
        .expect("select EF.IMSI under DF.GSM");
}

// "Given I have selected DF.GSM (0x7F20)" -- moved to gsm.rs (context-aware).

#[given(regex = r"^I am in MF$")]
fn given_in_mf(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    ctx.select_by_fid(Fid::MF).expect("select MF");
}

#[given(regex = r"^ADF\.USIM is the current ADF$")]
fn given_adf_usim_active(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    ctx.select_by_aid(&[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02], &ADF_TABLE)
        .expect("select ADF.USIM by AID");
}

#[given(regex = r"^no ADF is active$")]
fn given_no_adf_active(world: &mut SpecWorld) {
    // Reset to MF which clears ADF.
    let ctx = fs_ctx(world);
    ctx.select_by_fid(Fid::MF).expect("select MF to clear ADF");
    assert!(
        ctx.current_adf().is_none(),
        "Expected no ADF after selecting MF",
    );
}

// "Given EF.ICCID is selected" -- moved to gsm.rs (context-aware).

#[given(regex = r"^no EF is selected$")]
fn given_no_ef_selected(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    // Selecting MF clears the EF.
    ctx.select_by_fid(Fid::MF).expect("select MF to clear EF");
    assert!(
        ctx.current_ef().is_none(),
        "Expected no EF after selecting MF",
    );
}

#[given(regex = r"^EF\.DIR \(linear fixed\) is selected$")]
fn given_ef_dir_selected(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    ctx.select_by_fid(Fid::MF).expect("select MF");
    ctx.select_by_fid(Fid::new(0x2F00)).expect("select EF.DIR");
}

#[given(regex = r"^EF\.ICCID \(10 bytes\) is selected$")]
fn given_ef_iccid_10_bytes_selected(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    ctx.select_by_fid(Fid::MF).expect("select MF");
    ctx.select_by_fid(Fid::new(0x2FE2))
        .expect("select EF.ICCID");
}

#[given(regex = r"^EF\.ADN \(record_size=14, 3 records\) is selected$")]
fn given_ef_adn_full_selected(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    ctx.select_by_fid(Fid::MF).expect("select MF");
    ctx.select_by_fid(Fid::new(0x7F10))
        .expect("select DF.TELECOM");
    ctx.select_by_fid(Fid::new(0x6F3A)).expect("select EF.ADN");
}

#[given(regex = r"^EF\.ADN is selected$")]
fn given_ef_adn_selected(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    ctx.select_by_fid(Fid::MF).expect("select MF");
    ctx.select_by_fid(Fid::new(0x7F10))
        .expect("select DF.TELECOM");
    ctx.select_by_fid(Fid::new(0x6F3A)).expect("select EF.ADN");
}

// "Given EF.ADN (3 records) is selected" -- moved to gsm.rs (context-aware).
// "Given EF.ICCID (transparent) is selected" -- moved to gsm.rs (context-aware).

// =========================================================================
// WHEN steps -- SELECT by FID
// =========================================================================

/// Matches:
///   "I select FID 0x3F00"
///   "I select FID 0x7F20 (DF.GSM)"
///   "I select FID 0x6F07 (which is under DF.GSM, not MF)"
#[when(regex = r"^I select FID 0x([0-9A-Fa-f]{4})")]
fn when_select_fid(world: &mut SpecWorld, fid_hex: String) {
    let fid_val = u16::from_str_radix(&fid_hex, 16).unwrap();
    let fid = Fid::from_raw(fid_val);
    let ctx = fs_ctx(world);
    let result = ctx.select_by_fid(fid);
    world.fs_result = Some(result);
    world.last_error = result.err().map(|e| format!("{e:?}"));
}

// =========================================================================
// WHEN steps -- SELECT by AID
// =========================================================================

#[when(regex = r"^I select by AID \[([0-9A-Fa-f ]+)\]$")]
fn when_select_by_aid(world: &mut SpecWorld, aid_hex: String) {
    let aid = parse_hex(&aid_hex);
    let ctx = fs_ctx(world);
    let result = ctx.select_by_aid(&aid, &ADF_TABLE);
    world.fs_result = Some(result);
    world.last_error = result.err().map(|e| format!("{e:?}"));
}

// =========================================================================
// WHEN steps -- READ BINARY
// =========================================================================

#[when(regex = r"^I read binary at offset (\d+), length (\d+)$")]
fn when_read_binary(world: &mut SpecWorld, offset: u16, len: u16) {
    let ctx = fs_ctx(world);
    match ctx.read_binary(offset, len) {
        Ok(data) => {
            world.fs_read_data = data.to_vec();
            world.last_error = None;
        }
        Err(e) => {
            world.fs_read_data.clear();
            world.last_error = Some(format!("{e:?}"));
        }
    }
}

// =========================================================================
// WHEN steps -- READ RECORD
// =========================================================================

#[when(regex = r"^I read record (\d+)$")]
fn when_read_record(world: &mut SpecWorld, num: u8) {
    let ctx = fs_ctx(world);
    match ctx.read_record(num) {
        Ok(data) => {
            world.fs_read_data = data.to_vec();
            world.last_error = None;
        }
        Err(e) => {
            world.fs_read_data.clear();
            world.last_error = Some(format!("{e:?}"));
        }
    }
}

// =========================================================================
// THEN steps -- DF assertions
// =========================================================================

#[then(regex = r"^the current DF is MF$")]
fn then_current_df_is_mf(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    assert_eq!(
        ctx.current_df().fid,
        Fid::MF,
        "Expected current DF = MF (3F00), got {:04X}",
        ctx.current_df().fid,
    );
}

#[then(regex = r"^the current DF remains MF$")]
fn then_current_df_remains_mf(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    assert_eq!(
        ctx.current_df().fid,
        Fid::MF,
        "Expected current DF to remain MF (3F00), got {:04X}",
        ctx.current_df().fid,
    );
}

#[then(regex = r"^the current DF is DF\.GSM$")]
fn then_current_df_is_df_gsm(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    assert_eq!(
        ctx.current_df().fid,
        Fid::new(0x7F20),
        "Expected current DF = DF.GSM (7F20), got {:04X}",
        ctx.current_df().fid,
    );
}

#[then(regex = r"^the current DF remains DF\.GSM$")]
fn then_current_df_remains_df_gsm(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    assert_eq!(
        ctx.current_df().fid,
        Fid::new(0x7F20),
        "Expected current DF to remain DF.GSM (7F20), got {:04X}",
        ctx.current_df().fid,
    );
}

#[then(regex = r"^the current DF is the ADF root$")]
fn then_current_df_is_adf_root(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    let adf = ctx
        .current_adf()
        .expect("Expected an active ADF, but none is set");
    assert!(
        core::ptr::eq(ctx.current_df(), adf),
        "Expected current DF to be the ADF root (FID {:04X}), got {:04X}",
        adf.fid,
        ctx.current_df().fid,
    );
}

// =========================================================================
// THEN steps -- EF assertions
// =========================================================================

#[then(regex = r"^no EF is selected$")]
fn then_no_ef_selected(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    assert!(
        ctx.current_ef().is_none(),
        "Expected no EF selected, but {:04X} is selected",
        ctx.current_ef().unwrap().fid(),
    );
}

// =========================================================================
// THEN steps -- ADF assertions
// =========================================================================

#[then(regex = r"^no ADF is active$")]
fn then_no_adf_active(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    assert!(
        ctx.current_adf().is_none(),
        "Expected no ADF active, but one is set",
    );
}

#[then(regex = r"^the current ADF is ADF\.USIM$")]
fn then_current_adf_is_usim(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    let adf = ctx
        .current_adf()
        .expect("Expected an active ADF, but none is set");
    assert!(
        core::ptr::eq(adf, &ADF_USIM_ROOT),
        "Expected ADF.USIM root, got DF with FID {:04X}",
        adf.fid,
    );
}

// =========================================================================
// THEN steps -- SELECT result assertions
// =========================================================================

#[then(regex = r"^the result is Ef with FID 0x([0-9A-Fa-f]{4})$")]
fn then_result_is_ef_with_fid(world: &mut SpecWorld, fid_hex: String) {
    let expected_fid = Fid::new(u16::from_str_radix(&fid_hex, 16).unwrap());
    let result = world.fs_result.as_ref().expect("No fs_result stored");
    match result {
        Ok(SelectedFile::Ef(ef)) => {
            assert_eq!(
                ef.fid(),
                expected_fid,
                "Expected Ef with FID {expected_fid:04X}, got {:04X}",
                ef.fid(),
            );
        }
        Ok(SelectedFile::Df(df)) => {
            panic!(
                "Expected Ef with FID {expected_fid:04X}, got Df with FID {:04X}",
                df.fid,
            );
        }
        Err(e) => {
            panic!("Expected Ef with FID {expected_fid:04X}, got error: {e:?}");
        }
    }
}

#[then(regex = r"^the result is Df with FID 0x([0-9A-Fa-f]{4})$")]
fn then_result_is_df_with_fid(world: &mut SpecWorld, fid_hex: String) {
    let expected_fid = Fid::new(u16::from_str_radix(&fid_hex, 16).unwrap());
    let result = world.fs_result.as_ref().expect("No fs_result stored");
    match result {
        Ok(SelectedFile::Df(df)) => {
            assert_eq!(
                df.fid, expected_fid,
                "Expected Df with FID {expected_fid:04X}, got {:04X}",
                df.fid,
            );
        }
        Ok(SelectedFile::Ef(ef)) => {
            panic!(
                "Expected Df with FID {expected_fid:04X}, got Ef with FID {:04X}",
                ef.fid(),
            );
        }
        Err(e) => {
            panic!("Expected Df with FID {expected_fid:04X}, got error: {e:?}");
        }
    }
}

#[then(regex = r"^the result is Df for the ADF root$")]
fn then_result_is_df_for_adf_root(world: &mut SpecWorld) {
    let result = world.fs_result.as_ref().expect("No fs_result stored");
    match result {
        Ok(SelectedFile::Df(df)) => {
            assert!(
                core::ptr::eq(*df, &ADF_USIM_ROOT),
                "Expected Df for ADF.USIM root, got Df with FID {:04X}",
                df.fid,
            );
        }
        Ok(SelectedFile::Ef(ef)) => {
            panic!("Expected Df for ADF root, got Ef with FID {:04X}", ef.fid());
        }
        Err(e) => {
            panic!("Expected Df for ADF root, got error: {e:?}");
        }
    }
}

// =========================================================================
// THEN steps -- error assertions
// =========================================================================

#[then(regex = r"^the result is FileNotFound error$")]
fn then_result_is_file_not_found(world: &mut SpecWorld) {
    assert_fs_error(world, "FileNotFound");
}

#[then(regex = r"^the result is NoEfSelected error$")]
fn then_result_is_no_ef_selected(world: &mut SpecWorld) {
    assert_fs_error(world, "NoEfSelected");
}

#[then(regex = r"^the result is NotTransparent error$")]
fn then_result_is_not_transparent(world: &mut SpecWorld) {
    assert_fs_error(world, "NotTransparent");
}

#[then(regex = r"^the result is OffsetOutOfRange error$")]
fn then_result_is_offset_out_of_range(world: &mut SpecWorld) {
    assert_fs_error(world, "OffsetOutOfRange");
}

#[then(regex = r"^the result is RecordOutOfRange error$")]
fn then_result_is_record_out_of_range(world: &mut SpecWorld) {
    assert_fs_error(world, "RecordOutOfRange");
}

#[then(regex = r"^the result is NotRecordBased error$")]
fn then_result_is_not_record_based(world: &mut SpecWorld) {
    assert_fs_error(world, "NotRecordBased");
}

/// Check that `last_error` matches the expected `FsError` variant name.
fn assert_fs_error(world: &SpecWorld, expected: &str) {
    let err = world
        .last_error
        .as_deref()
        .unwrap_or_else(|| panic!("Expected {expected} error, but operation succeeded"));
    assert_eq!(err, expected, "Expected {expected} error, got {err}",);
}

// =========================================================================
// THEN steps -- READ BINARY data assertions
// =========================================================================

// "Then I get the 10-byte ICCID content" -- moved to gsm.rs (context-aware).
// "Then I get bytes [...]" -- moved to gsm.rs (context-aware).

// =========================================================================
// THEN steps -- READ RECORD data assertions
// =========================================================================

#[then(regex = r"^I get the first 14-byte record$")]
fn then_get_first_record(world: &mut SpecWorld) {
    assert_eq!(
        world.fs_read_data.len(),
        14,
        "Expected 14-byte record, got {} bytes",
        world.fs_read_data.len(),
    );
    let expected = [0x01u8; 14];
    assert_eq!(
        world.fs_read_data,
        &expected[..],
        "First record content mismatch: expected {:02X?}, got {:02X?}",
        expected,
        world.fs_read_data,
    );
}

// "Then I get the second 14-byte record" -- moved to gsm.rs (context-aware).

// =========================================================================
// THEN steps -- ADF navigation assertions
// =========================================================================

#[then(regex = r"^the current EF is the USIM EF\.IMSI$")]
fn then_current_ef_is_usim_imsi(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    let ef = ctx
        .current_ef()
        .expect("Expected an EF selected, but none is");
    assert!(
        core::ptr::eq(ef, &USIM_EF_IMSI),
        "Expected USIM EF.IMSI (pointer identity), got EF with FID {:04X}",
        ef.fid(),
    );
}

#[then(regex = r"^it has different data from the GSM EF\.IMSI$")]
fn then_different_data_from_gsm(world: &mut SpecWorld) {
    let ctx = fs_ctx(world);
    let usim_ef = ctx.current_ef().expect("Expected an EF selected");
    assert_ne!(
        usim_ef.data(),
        GSM_EF_IMSI.data(),
        "USIM EF.IMSI data should differ from GSM EF.IMSI data, \
         but both are {:02X?}",
        usim_ef.data(),
    );
}
