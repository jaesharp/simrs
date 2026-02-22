//! Default reference USIM profile filesystem per 3GPP TS 31.102.
//!
//! Provides a standard USIM filesystem tree as `static` definitions,
//! suitable for test and development use. The file data is zero-filled
//! or populated with sensible defaults.
//!
//! # Structure
//!
//! ```text
//! MF (3F00)
//! +-- EF.ICCID (2FE2) transparent, 10 bytes
//! +-- EF.DIR (2F00) linear-fixed, 1 record x 16 bytes
//! +-- EF.ARR (2F06) linear-fixed, 1 record x 8 bytes
//! +-- ADF.USIM (7FFF)
//! |   +-- EF.IMSI (6F07) transparent, 9 bytes
//! |   +-- EF.AD (6FAD) transparent, 4 bytes
//! |   +-- EF.UST (6F38) transparent, 4 bytes
//! |   +-- EF.ACC (6F78) transparent, 2 bytes
//! |   +-- EF.LOCI (6F7E) transparent, 11 bytes
//! |   +-- EF.PSLOCI (6FE7) transparent, 14 bytes
//! |   +-- EF.FPLMN (6F7B) transparent, 12 bytes
//! |   +-- EF.HPPLMN (6F31) transparent, 1 byte
//! |   +-- EF.MSISDN (6F40) linear-fixed, 1 record x 28 bytes
//! |   +-- EF.SMSP (6F42) linear-fixed, 1 record x 28 bytes
//! |   +-- EF.FDN (6F3B) linear-fixed, 5 records x 14 bytes
//! +-- DF.TELECOM (7F10)
//! ```
//!
//! # Standards
//! - 3GPP TS 31.102 V17.5.0 clause 4.2 -- USIM EF definitions
//! - 3GPP TS 31.102 V17.5.0 clause 4.4 -- File identifiers
//! - ETSI TS 102 221 V16.4.0 clause 13 -- UICC files under MF

use simrs_fs::{AdfSlot, DfDef, EfDef, EfStructure, Fid, FileRef, Sfi};

// ---------------------------------------------------------------------------
// EFs under MF
// ---------------------------------------------------------------------------

/// EF.ICCID (2FE2) -- ICC Identification.
///
/// 10-byte transparent EF. Default: test ICCID `8901260000000000000`.
/// Encoding: BCD-nibble-swapped per ETSI TS 102 221 clause 13.2.
pub static EF_ICCID: EfDef = EfDef {
    fid: Fid(0x2FE2),
    sfi: Some(Sfi(2)),
    structure: EfStructure::Transparent,
    data: &[0x98, 0x10, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
};

/// EF.DIR data: one record with a minimal AID TLV for USIM.
///
/// Format: `61 09 4F 07 A0000000871002 ...padding`
static EF_DIR_DATA: [u8; 16] = [
    0x61, 0x09, 0x4F, 0x07,
    0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// EF.DIR (2F00) -- Application Directory.
///
/// Linear-fixed, 1 record of 16 bytes. Contains a single USIM AID entry.
pub static EF_DIR: EfDef = EfDef {
    fid: Fid(0x2F00),
    sfi: Some(Sfi(30)),
    structure: EfStructure::LinearFixed {
        record_size: 16,
        num_records: 1,
    },
    data: &EF_DIR_DATA,
};

/// EF.ARR data: one empty record.
static EF_ARR_DATA: [u8; 8] = [0xFF; 8];

/// EF.ARR (2F06) -- Access Rule Reference.
///
/// Linear-fixed, 1 record of 8 bytes. Default: empty (all 0xFF).
pub static EF_ARR: EfDef = EfDef {
    fid: Fid(0x2F06),
    sfi: None,
    structure: EfStructure::LinearFixed {
        record_size: 8,
        num_records: 1,
    },
    data: &EF_ARR_DATA,
};

// ---------------------------------------------------------------------------
// EFs under ADF.USIM
// ---------------------------------------------------------------------------

/// EF.IMSI (6F07) -- International Mobile Subscriber Identity.
///
/// 9-byte transparent EF. Default: test IMSI `001010000000000`.
/// Byte 0: length of IMSI data (0x08 = 8 bytes of BCD digits).
/// Remaining: BCD-encoded with nibble swap.
pub static EF_IMSI: EfDef = EfDef {
    fid: Fid(0x6F07),
    sfi: Some(Sfi(7)),
    structure: EfStructure::Transparent,
    data: &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0],
};

/// EF.AD (6FAD) -- Administrative Data.
///
/// 4-byte transparent EF. Byte 0: MS operation mode (0x00 = normal).
/// Bytes 1-2: reserved. Byte 3: MNC length (2 digits).
pub static EF_AD: EfDef = EfDef {
    fid: Fid(0x6FAD),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x00, 0x00, 0x00, 0x02],
};

/// EF.UST (6F38) -- USIM Service Table.
///
/// 4-byte transparent EF. Each bit enables a service per TS 31.102 clause 4.2.8.
/// Default: services 1-25 enabled (local phone book, FDN, SMS, etc.).
pub static EF_UST: EfDef = EfDef {
    fid: Fid(0x6F38),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF, 0xFF, 0xFF, 0x01],
};

/// EF.ACC (6F78) -- Access Control Class.
///
/// 2-byte transparent EF. Default: class 0 (bit 0 set).
pub static EF_ACC: EfDef = EfDef {
    fid: Fid(0x6F78),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x00, 0x01],
};

/// EF.LOCI (6F7E) -- Location Information.
///
/// 11-byte transparent EF. Default: zero-filled (no location).
pub static EF_LOCI: EfDef = EfDef {
    fid: Fid(0x6F7E),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x00; 11],
};

/// EF.PSLOCI (6FE7) -- Packet Switched Location Information.
///
/// 14-byte transparent EF. Default: zero-filled.
pub static EF_PSLOCI: EfDef = EfDef {
    fid: Fid(0x6FE7),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x00; 14],
};

/// EF.FPLMN (6F7B) -- Forbidden PLMNs.
///
/// 12-byte transparent EF (4 PLMN entries x 3 bytes each).
/// Default: all 0xFF (no forbidden PLMNs).
pub static EF_FPLMN: EfDef = EfDef {
    fid: Fid(0x6F7B),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF; 12],
};

/// EF.HPPLMN (6F31) -- Higher Priority PLMN Search Period.
///
/// 1-byte transparent EF. Value in units of N * 6 minutes. Default: 0x3C (60 = 6 hours).
pub static EF_HPPLMN: EfDef = EfDef {
    fid: Fid(0x6F31),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x3C],
};

/// EF.MSISDN data: one empty record.
static EF_MSISDN_DATA: [u8; 28] = [0xFF; 28];

/// EF.MSISDN (6F40) -- MSISDN (own phone number).
///
/// Linear-fixed, 1 record of 28 bytes. Default: empty.
pub static EF_MSISDN: EfDef = EfDef {
    fid: Fid(0x6F40),
    sfi: None,
    structure: EfStructure::LinearFixed {
        record_size: 28,
        num_records: 1,
    },
    data: &EF_MSISDN_DATA,
};

/// EF.SMSP data: one empty record.
static EF_SMSP_DATA: [u8; 28] = [0xFF; 28];

/// EF.SMSP (6F42) -- Short Message Service Parameters.
///
/// Linear-fixed, 1 record of 28 bytes. Default: empty.
pub static EF_SMSP: EfDef = EfDef {
    fid: Fid(0x6F42),
    sfi: None,
    structure: EfStructure::LinearFixed {
        record_size: 28,
        num_records: 1,
    },
    data: &EF_SMSP_DATA,
};

/// EF.FDN data: 5 empty records of 14 bytes each.
static EF_FDN_DATA: [u8; 70] = [0xFF; 70];

/// EF.FDN (6F3B) -- Fixed Dialling Numbers.
///
/// Linear-fixed, 5 records of 14 bytes. Default: empty.
pub static EF_FDN: EfDef = EfDef {
    fid: Fid(0x6F3B),
    sfi: None,
    structure: EfStructure::LinearFixed {
        record_size: 14,
        num_records: 5,
    },
    data: &EF_FDN_DATA,
};

// ---------------------------------------------------------------------------
// DF / ADF definitions
// ---------------------------------------------------------------------------

/// ADF.USIM root DF.
///
/// Contains the standard USIM EFs listed above.
pub static ADF_USIM_ROOT: DfDef = DfDef {
    fid: Fid(0xFF01),
    children: &[
        FileRef::Ef(&EF_IMSI),
        FileRef::Ef(&EF_AD),
        FileRef::Ef(&EF_UST),
        FileRef::Ef(&EF_ACC),
        FileRef::Ef(&EF_LOCI),
        FileRef::Ef(&EF_PSLOCI),
        FileRef::Ef(&EF_FPLMN),
        FileRef::Ef(&EF_HPPLMN),
        FileRef::Ef(&EF_MSISDN),
        FileRef::Ef(&EF_SMSP),
        FileRef::Ef(&EF_FDN),
    ],
};

/// Standard USIM AID: A0000000871002 (per 3GPP TS 31.102).
pub static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

/// ADF table with a single USIM entry.
pub static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
    aid: &USIM_AID,
    root: &ADF_USIM_ROOT,
}];

/// DF.TELECOM (7F10) -- Telecom DF.
///
/// Empty in this minimal profile.
pub static DF_TELECOM: DfDef = DfDef {
    fid: Fid(0x7F10),
    children: &[],
};

/// Reference Master File (MF).
///
/// Contains EF.ICCID, EF.DIR, EF.ARR, and DF.TELECOM.
pub static REFERENCE_MF: DfDef = DfDef {
    fid: Fid::MF,
    children: &[
        FileRef::Ef(&EF_ICCID),
        FileRef::Ef(&EF_DIR),
        FileRef::Ef(&EF_ARR),
        FileRef::Df(&DF_TELECOM),
    ],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_mf_has_iccid() {
        let has_iccid = REFERENCE_MF.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid == Fid(0x2FE2)
            } else {
                false
            }
        });
        assert!(has_iccid, "MF must contain EF.ICCID (2FE2)");
    }

    #[test]
    fn profile_adf_usim_has_imsi() {
        let has_imsi = ADF_USIM_ROOT.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid == Fid(0x6F07)
            } else {
                false
            }
        });
        assert!(has_imsi, "ADF.USIM must contain EF.IMSI (6F07)");
    }

    #[test]
    fn profile_ef_dir_is_linear_fixed() {
        assert!(
            matches!(EF_DIR.structure, EfStructure::LinearFixed { .. }),
            "EF.DIR must be linear-fixed"
        );
    }

    #[test]
    fn profile_fids_unique() {
        // Collect all FIDs from MF children and ADF.USIM children.
        let mut fids: [u16; 32] = [0xFFFF; 32];

        for (idx, child) in REFERENCE_MF.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid.value(),
                FileRef::Df(df) => df.fid.value(),
            };
            // Check for duplicates within MF.
            for f in &fids[..idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under MF");
            }
            fids[idx] = fid;
        }

        // Reset for ADF.USIM scope.
        let mut adf_fids: [u16; 32] = [0xFFFF; 32];

        for (adf_idx, child) in ADF_USIM_ROOT.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid.value(),
                FileRef::Df(df) => df.fid.value(),
            };
            for f in &adf_fids[..adf_idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under ADF.USIM");
            }
            adf_fids[adf_idx] = fid;
        }
    }
}
