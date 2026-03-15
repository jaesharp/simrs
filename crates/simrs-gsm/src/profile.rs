//! Default reference GSM profile filesystem per GSM 11.11 / 3GPP TS 51.011.
//!
//! Provides a standard GSM SIM filesystem tree as `static` definitions,
//! suitable for test and development use. Default data values are taken
//! with sensible default values.
//!
//! # Profile tiers
//!
//! EFs are gated by feature flags:
//! - **`profile-minimal`** -- IMSI, Kc, LOCI, ACC, SST (~8 EFs)
//! - **`profile-standard`** (default) -- full GSM 11.11 EF set (~22 EFs)
//!
//! # Structure
//!
//! ```text
//! MF (3F00)
//! +-- EF.ICCID (2FE2) transparent, 10 bytes
//! +-- DF.TELECOM (7F10)  (empty)
//! +-- DF.GSM (7F20)
//!     +-- EF.LP (6F05) transparent, 4 bytes
//!     +-- EF.IMSI (6F07) transparent, 9 bytes
//!     +-- EF.Kc (6F20) transparent, 9 bytes
//!     +-- EF.PLMNsel (6F30) transparent, 3 bytes
//!     +-- EF.HPPLMN (6F31) transparent, 1 byte
//!     +-- EF.ACMmax (6F37) transparent, 3 bytes
//!     +-- EF.SST (6F38) transparent, 14 bytes
//!     +-- EF.ACM (6F39) cyclic, 3 rec x 3 bytes
//!     +-- EF.GID1 (6F3E) transparent, 4 bytes
//!     +-- EF.GID2 (6F3F) transparent, 4 bytes
//!     +-- EF.PUCT (6F41) transparent, 5 bytes
//!     +-- EF.CBMI (6F45) transparent, 10 bytes
//!     +-- EF.SPN (6F46) transparent, 17 bytes
//!     +-- EF.BCCH (6F74) transparent, 16 bytes
//!     +-- EF.ACC (6F78) transparent, 2 bytes
//!     +-- EF.FPLMN (6F7B) transparent, 12 bytes
//!     +-- EF.LOCI (6F7E) transparent, 11 bytes
//!     +-- EF.AD (6FAD) transparent, 3 bytes
//!     +-- EF.Phase (6FAE) transparent, 1 byte
//! ```
//!
//! # Standards
//! - [3GPP TS 51.011 V4.15.0](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf) (GSM 11.11)

#[cfg(test)]
use simrs_fs::EfStructure;
use simrs_fs::{DfDef, EfDef, Fid, FileRef};

// ---------------------------------------------------------------------------
// MF-level EFs
// ---------------------------------------------------------------------------

/// EF.ICCID (2FE2) -- ICC Identification.
///
/// 10-byte transparent EF. Default: test ICCID.
/// Encoding: BCD-nibble-swapped per [ETSI TS 151 011 V4.15.0 clause 10.1.1](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A105%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C436%5D).
pub static EF_ICCID: EfDef = EfDef::transparent(
    Fid::new(0x2FE2),
    None,
    &[0x98, 0x99, 0x99, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF1],
);

// ---------------------------------------------------------------------------
// EFs under DF.GSM (7F20) -- minimal tier
// ---------------------------------------------------------------------------

/// EF.LP (6F05) -- Language Preference.
///
/// 4-byte transparent EF. Default: `[0x0E, 0x01, 0xFF, 0xFF]`.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.6](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A117%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C128%5D).
pub static EF_LP: EfDef = EfDef::transparent(Fid::new(0x6F05), None, &[0x0E, 0x01, 0xFF, 0xFF]);

/// EF.IMSI (6F07) -- International Mobile Subscriber Identity.
///
/// 9-byte transparent EF. Default: test IMSI.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.2](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A111%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C772%5D).
pub static EF_IMSI: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0x08, 0x99, 0x99, 0x99, 0x00, 0x00, 0x00, 0x00, 0x10],
);

/// EF.Kc (6F20) -- Ciphering Key Kc.
///
/// 9-byte transparent EF. Bytes 0-7: Kc. Byte 8: CKSN.
/// Default: Kc=FF..FF, CKSN=7 (no key).
/// [ETSI TS 151 011 V4.15.0 clause 10.3.3](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A114%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C772%5D).
pub static EF_KC: EfDef = EfDef::transparent(
    Fid::new(0x6F20),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07],
);

/// EF.HPPLMN (6F31) -- Higher Priority PLMN Search Period.
///
/// 1-byte transparent EF. Default: 0x05.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.8](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A129%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C363%5D).
pub static EF_HPPLMN: EfDef = EfDef::transparent(Fid::new(0x6F31), None, &[0x05]);

/// EF.SST (6F38) -- SIM Service Table.
///
/// 14-byte transparent EF. Default: standard service table.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.7](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A123%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C772%5D).
pub static EF_SST: EfDef = EfDef::transparent(
    Fid::new(0x6F38),
    None,
    &[
        0xFF, 0x3F, 0xFF, 0xFF, 0x3F, 0x00, 0x3F, 0x0F, 0x30, 0x0C, 0x00, 0x00, 0x00, 0xC0,
    ],
);

/// EF.ACC (6F78) -- Access Control Class.
///
/// 2-byte transparent EF. Default: `[0x00, 0x80]`.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.15](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A141%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C415%5D).
pub static EF_ACC: EfDef = EfDef::transparent(Fid::new(0x6F78), None, &[0x00, 0x80]);

/// EF.LOCI (6F7E) -- Location Information.
///
/// 11-byte transparent EF. Default: empty LOCI.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.18](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A150%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C699%5D).
pub static EF_LOCI: EfDef = EfDef::transparent(
    Fid::new(0x6F7E),
    None,
    &[
        0xFF, 0xFF, 0xFF, 0xFF, // TMSI
        0x99, 0x99, 0x99, // LAI: MCC/MNC
        0x99, 0xF9, // LAI: LAC
        0xFF, // TMSI TIME
        0x03, // location update status
    ],
);

/// EF.FPLMN (6F7B) -- Forbidden PLMNs.
///
/// 12-byte transparent EF (4 PLMN entries x 3 bytes).
/// Default: all 0xFF (no forbidden PLMNs).
/// [ETSI TS 151 011 V4.15.0 clause 10.3.16](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A144%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C690%5D).
pub static EF_FPLMN: EfDef = EfDef::transparent(Fid::new(0x6F7B), None, &[0xFF; 12]);

/// EF.AD (6FAD) -- Administrative Data.
///
/// 3-byte transparent EF. Default: `[0x00, 0xFF, 0xFF]`.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.18](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A150%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C699%5D).
pub static EF_AD: EfDef = EfDef::transparent(Fid::new(0x6FAD), None, &[0x00, 0xFF, 0xFF]);

// ---------------------------------------------------------------------------
// EFs under DF.GSM (7F20) -- standard tier
// ---------------------------------------------------------------------------

/// EF.PLMNsel (6F30) -- PLMN Selector.
///
/// 3-byte transparent EF. Default: test PLMN.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.4](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A114%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C364%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_PLMNSEL: EfDef = EfDef::transparent(Fid::new(0x6F30), None, &[0x99, 0x99, 0x99]);

/// EF.ACMmax (6F37) -- ACM Maximum Value.
///
/// 3-byte transparent EF. Default: 0x000000 (no maximum).
/// [ETSI TS 151 011 V4.15.0 clause 10.3.14](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A141%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C724%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_ACMMAX: EfDef = EfDef::transparent(Fid::new(0x6F37), None, &[0x00, 0x00, 0x00]);

/// EF.ACM (6F39) -- Accumulated Call Meter.
///
/// Cyclic, 3 records of 3 bytes. Default: zero.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.13](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A138%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C385%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_ACM: EfDef = EfDef::cyclic(Fid::new(0x6F39), None, 3, 3, &[0x00; 9]);

/// EF.GID1 (6F3E) -- Group Identifier Level 1.
///
/// 4-byte transparent EF. Default: empty.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.9](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A132%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C772%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_GID1: EfDef = EfDef::transparent(Fid::new(0x6F3E), None, &[0xFF; 4]);

/// EF.GID2 (6F3F) -- Group Identifier Level 2.
///
/// 4-byte transparent EF. Default: empty.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.10](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A132%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C567%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_GID2: EfDef = EfDef::transparent(Fid::new(0x6F3F), None, &[0xFF; 4]);

/// EF.PUCT (6F41) -- Price per Unit and Currency Table.
///
/// 5-byte transparent EF. Default: empty price table.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.12](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A135%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C457%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_PUCT: EfDef =
    EfDef::transparent(Fid::new(0x6F41), None, &[0xFF, 0xFF, 0xFF, 0x00, 0x00]);

/// EF.CBMI (6F45) -- Cell Broadcast Message Identifier Selection.
///
/// 10-byte transparent EF. Default: empty.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.11](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A132%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C331%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_CBMI: EfDef = EfDef::transparent(Fid::new(0x6F45), None, &[0xFF; 10]);

/// EF.SPN (6F46) -- Service Provider Name.
///
/// 17-byte transparent EF. Default: test service provider name.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.11](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A132%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C331%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_SPN: EfDef = EfDef::transparent(
    Fid::new(0x6F46),
    None,
    &[
        0x00, 0x73, 0x77, 0x53, 0x49, 0x4D, 0x20, 0x62, 0x79, 0x20, 0x54, 0x6F, 0x6D, 0x61, 0x73,
        0x7A, 0xFF,
    ],
);

/// EF.BCCH (6F74) -- Broadcast Control Channel.
///
/// 16-byte transparent EF. Default: all zeros.
/// [ETSI TS 151 011 V4.15.0 clause 10.3.17](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A144%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C121%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_BCCH: EfDef = EfDef::transparent(Fid::new(0x6F74), None, &[0x00; 16]);

/// EF.Phase (6FAE) -- Phase Identification.
///
/// 1-byte transparent EF. Default: 0x03 (phase 2+).
/// [ETSI TS 151 011 V4.15.0 clause 10.3.19](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A153%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C415%5D).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
pub static EF_PHASE: EfDef = EfDef::transparent(Fid::new(0x6FAE), None, &[0x03]);

// ---------------------------------------------------------------------------
// DF / MF definitions
// ---------------------------------------------------------------------------

/// DF.GSM (7F20) children for profile-standard (default).
#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
static DF_GSM_CHILDREN: [FileRef; 19] = [
    FileRef::Ef(&EF_LP),
    FileRef::Ef(&EF_IMSI),
    FileRef::Ef(&EF_KC),
    FileRef::Ef(&EF_PLMNSEL),
    FileRef::Ef(&EF_HPPLMN),
    FileRef::Ef(&EF_ACMMAX),
    FileRef::Ef(&EF_SST),
    FileRef::Ef(&EF_ACM),
    FileRef::Ef(&EF_GID1),
    FileRef::Ef(&EF_GID2),
    FileRef::Ef(&EF_PUCT),
    FileRef::Ef(&EF_CBMI),
    FileRef::Ef(&EF_SPN),
    FileRef::Ef(&EF_BCCH),
    FileRef::Ef(&EF_ACC),
    FileRef::Ef(&EF_FPLMN),
    FileRef::Ef(&EF_LOCI),
    FileRef::Ef(&EF_AD),
    FileRef::Ef(&EF_PHASE),
];

#[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
const _: () = simrs_fs::assert_fids_unique(&[
    0x6F05, // EF_LP
    0x6F07, // EF_IMSI
    0x6F20, // EF_KC
    0x6F30, // EF_PLMNSEL
    0x6F31, // EF_HPPLMN
    0x6F37, // EF_ACMMAX
    0x6F38, // EF_SST
    0x6F39, // EF_ACM
    0x6F3E, // EF_GID1
    0x6F3F, // EF_GID2
    0x6F41, // EF_PUCT
    0x6F45, // EF_CBMI
    0x6F46, // EF_SPN
    0x6F74, // EF_BCCH
    0x6F78, // EF_ACC
    0x6F7B, // EF_FPLMN
    0x6F7E, // EF_LOCI
    0x6FAD, // EF_AD
    0x6FAE, // EF_PHASE
]);

/// DF.GSM (7F20) children for profile-minimal.
#[cfg(all(feature = "profile-minimal", not(feature = "profile-standard")))]
static DF_GSM_CHILDREN: [FileRef; 9] = [
    FileRef::Ef(&EF_LP),
    FileRef::Ef(&EF_IMSI),
    FileRef::Ef(&EF_KC),
    FileRef::Ef(&EF_HPPLMN),
    FileRef::Ef(&EF_SST),
    FileRef::Ef(&EF_ACC),
    FileRef::Ef(&EF_FPLMN),
    FileRef::Ef(&EF_LOCI),
    FileRef::Ef(&EF_AD),
];

#[cfg(all(feature = "profile-minimal", not(feature = "profile-standard")))]
const _: () = simrs_fs::assert_fids_unique(&[
    0x6F05, // EF_LP
    0x6F07, // EF_IMSI
    0x6F20, // EF_KC
    0x6F31, // EF_HPPLMN
    0x6F38, // EF_SST
    0x6F78, // EF_ACC
    0x6F7B, // EF_FPLMN
    0x6F7E, // EF_LOCI
    0x6FAD, // EF_AD
]);

/// DF.GSM (7F20) -- GSM application DF.
///
/// Contains the GSM EF catalog under the MF.
pub static DF_GSM: DfDef = DfDef {
    fid: Fid::new(0x7F20),
    children: &DF_GSM_CHILDREN,
};

/// DF.TELECOM (7F10) -- Telecom DF (empty in GSM profile).
pub static DF_TELECOM: DfDef = DfDef {
    fid: Fid::new(0x7F10),
    children: &[],
};

/// Reference Master File (MF) for GSM.
///
/// Contains EF.ICCID, DF.TELECOM (empty), and DF.GSM.
pub static REFERENCE_MF_GSM: DfDef = DfDef {
    fid: Fid::MF,
    children: &[
        FileRef::Ef(&EF_ICCID),
        FileRef::Df(&DF_TELECOM),
        FileRef::Df(&DF_GSM),
    ],
};

const _: () = simrs_fs::assert_fids_unique(&[
    0x2FE2, // EF_ICCID
    0x7F10, // DF_TELECOM
    0x7F20, // DF_GSM
]);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gsm_mf_has_iccid() {
        let has_iccid = REFERENCE_MF_GSM.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid() == Fid::new(0x2FE2)
            } else {
                false
            }
        });
        assert!(has_iccid, "GSM MF must contain EF.ICCID (2FE2)");
    }

    #[test]
    fn gsm_mf_has_df_gsm() {
        let has_gsm = REFERENCE_MF_GSM.children.iter().any(|c| {
            if let FileRef::Df(df) = c {
                df.fid == Fid::new(0x7F20)
            } else {
                false
            }
        });
        assert!(has_gsm, "GSM MF must contain DF.GSM (7F20)");
    }

    #[test]
    fn df_gsm_has_imsi() {
        let has_imsi = DF_GSM.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid() == Fid::new(0x6F07)
            } else {
                false
            }
        });
        assert!(has_imsi, "DF.GSM must contain EF.IMSI (6F07)");
    }

    #[test]
    fn df_gsm_fids_unique() {
        let mut fids: [u16; 32] = [0xFFFF; 32];
        for (idx, child) in DF_GSM.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid().value(),
                FileRef::Df(df) => df.fid.value(),
            };
            for f in &fids[..idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under DF.GSM");
            }
            fids[idx] = fid;
        }
    }

    #[test]
    fn ef_iccid_is_10_bytes() {
        assert_eq!(EF_ICCID.data().len(), 10);
    }

    #[test]
    fn ef_imsi_is_9_bytes() {
        assert_eq!(EF_IMSI.data().len(), 9);
    }

    #[test]
    fn ef_kc_is_9_bytes() {
        assert_eq!(EF_KC.data().len(), 9);
        assert_eq!(EF_KC.data()[8], 0x07, "CKSN must be 7 (no key)");
    }

    #[test]
    fn ef_sst_is_14_bytes() {
        assert_eq!(EF_SST.data().len(), 14);
    }

    #[test]
    fn ef_loci_is_11_bytes() {
        assert_eq!(EF_LOCI.data().len(), 11);
    }

    /// Verify data length matches `record_size * num_records` for all record-based EFs.
    #[test]
    fn all_record_ef_data_sizes_consistent() {
        for child in DF_GSM.children {
            if let FileRef::Ef(ef) = child {
                let expected = match ef.structure() {
                    EfStructure::LinearFixed {
                        record_size,
                        num_records,
                    }
                    | EfStructure::Cyclic {
                        record_size,
                        num_records,
                    } => Some(record_size as usize * num_records as usize),
                    _ => None,
                };
                if let Some(exp) = expected {
                    assert_eq!(
                        ef.data().len(),
                        exp,
                        "EF {:#06X}: data.len()={} != record_size*num_records={}",
                        ef.fid().value(),
                        ef.data().len(),
                        exp,
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Phase 7: Structural (BDD-style) tests
    // -----------------------------------------------------------------------

    /// MF children FIDs are unique.
    #[test]
    fn gsm_mf_fids_unique() {
        let mut fids: [u16; 8] = [0xFFFF; 8];
        for (idx, child) in REFERENCE_MF_GSM.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid().value(),
                FileRef::Df(df) => df.fid.value(),
            };
            for f in &fids[..idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under GSM MF");
            }
            fids[idx] = fid;
        }
    }

    /// MF has exactly 3 children (EF.ICCID, DF.TELECOM, DF.GSM).
    #[test]
    fn gsm_mf_has_3_children() {
        assert_eq!(
            REFERENCE_MF_GSM.children.len(),
            3,
            "GSM MF must have exactly 3 children"
        );
    }

    /// MF FID is 3F00.
    #[test]
    fn gsm_mf_fid_is_3f00() {
        assert_eq!(REFERENCE_MF_GSM.fid, Fid::MF, "GSM MF FID must be 3F00");
    }

    /// DF.TELECOM FID is 7F10 and is empty in the GSM profile.
    #[test]
    fn gsm_df_telecom_is_empty() {
        assert_eq!(DF_TELECOM.fid, Fid::new(0x7F10));
        assert!(
            DF_TELECOM.children.is_empty(),
            "DF.TELECOM must be empty in GSM profile"
        );
    }

    /// DF.GSM FID is 7F20.
    #[test]
    fn df_gsm_fid_is_7f20() {
        assert_eq!(DF_GSM.fid, Fid::new(0x7F20), "DF.GSM FID must be 7F20");
    }

    /// DF.GSM standard profile has 19 children.
    #[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
    #[test]
    fn df_gsm_standard_has_19_children() {
        assert_eq!(
            DF_GSM.children.len(),
            19,
            "DF.GSM standard profile must have 19 children"
        );
    }

    /// `FsData::init` succeeds for the reference GSM profile.
    #[test]
    fn gsm_fsdata_init_succeeds() {
        use simrs_fs::FsData;
        let mut data = FsData::<1024, 32>::new();
        let result = data.init(&REFERENCE_MF_GSM);
        assert!(
            result.is_ok(),
            "FsData::init failed for GSM profile: {:?}",
            result.err()
        );
    }

    /// Each EF under DF.GSM is found at its expected FID.
    #[test]
    fn df_gsm_ef_at_correct_fid() {
        // (FID, expected data length)
        let expected: [(u16, usize); 8] = [
            (0x6F07, 9),  // EF.IMSI
            (0x6F20, 9),  // EF.Kc
            (0x6F31, 1),  // EF.HPPLMN
            (0x6F38, 14), // EF.SST
            (0x6F78, 2),  // EF.ACC
            (0x6F7B, 12), // EF.FPLMN
            (0x6F7E, 11), // EF.LOCI
            (0x6FAD, 3),  // EF.AD
        ];
        for (fid, exp_len) in &expected {
            let found = DF_GSM.children.iter().find_map(|c| {
                if let FileRef::Ef(ef) = c {
                    if ef.fid().value() == *fid {
                        Some(*ef)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });
            assert!(found.is_some(), "EF {fid:#06X} not found in DF.GSM");
            assert_eq!(
                found.unwrap().data().len(),
                *exp_len,
                "EF {fid:#06X} data length mismatch"
            );
        }
    }

    /// Standard profile EFs at correct FIDs.
    #[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
    #[test]
    fn df_gsm_standard_efs_at_correct_fid() {
        let expected: [(u16, usize); 10] = [
            (0x6F05, 4),  // EF.LP
            (0x6F30, 3),  // EF.PLMNsel
            (0x6F37, 3),  // EF.ACMmax
            (0x6F3E, 4),  // EF.GID1
            (0x6F3F, 4),  // EF.GID2
            (0x6F41, 5),  // EF.PUCT
            (0x6F45, 10), // EF.CBMI
            (0x6F46, 17), // EF.SPN
            (0x6F74, 16), // EF.BCCH
            (0x6FAE, 1),  // EF.Phase
        ];
        for (fid, exp_len) in &expected {
            let found = DF_GSM.children.iter().find_map(|c| {
                if let FileRef::Ef(ef) = c {
                    if ef.fid().value() == *fid {
                        Some(*ef)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });
            assert!(
                found.is_some(),
                "EF {fid:#06X} not found in DF.GSM (standard)"
            );
            assert_eq!(
                found.unwrap().data().len(),
                *exp_len,
                "EF {fid:#06X} data length mismatch"
            );
        }
    }

    /// EF.ACM is cyclic with 3 records of 3 bytes.
    #[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
    #[test]
    fn ef_acm_is_cyclic() {
        match EF_ACM.structure() {
            EfStructure::Cyclic {
                record_size,
                num_records,
            } => {
                assert_eq!(record_size, 3, "EF.ACM record size must be 3");
                assert_eq!(num_records, 3, "EF.ACM must have 3 records");
            }
            _ => panic!("EF.ACM must be Cyclic"),
        }
        assert_eq!(EF_ACM.data().len(), 9, "EF.ACM data must be 9 bytes (3*3)");
    }

    /// EF.IMSI first byte is length indicator (must be 0x08).
    #[test]
    fn ef_imsi_has_valid_length_byte() {
        assert_eq!(
            EF_IMSI.data()[0],
            0x08,
            "EF.IMSI first byte must be 0x08 (length of IMSI content)"
        );
    }

    /// EF.Phase value is valid (phase 2+ = 0x03).
    #[cfg(any(feature = "profile-standard", not(feature = "profile-minimal")))]
    #[test]
    fn ef_phase_is_phase2_plus() {
        assert_eq!(
            EF_PHASE.data()[0],
            0x03,
            "EF.Phase must indicate phase 2+ (0x03)"
        );
    }

    /// EF.LOCI last byte is location update status (must be 0x03 = not updated).
    #[test]
    fn ef_loci_update_status() {
        assert_eq!(
            EF_LOCI.data()[10],
            0x03,
            "EF.LOCI location update status must be 0x03 (not updated)"
        );
    }

    /// EF.Kc CKSN field (byte 8) is 0x07 (no valid key).
    #[test]
    fn ef_kc_cksn_is_no_key() {
        assert_eq!(
            EF_KC.data()[8],
            0x07,
            "EF.Kc CKSN (byte 8) must be 0x07 (no valid key)"
        );
    }

    /// All transparent EFs in the GSM tree have non-empty data.
    #[test]
    fn all_transparent_efs_have_data() {
        fn check(df: &DfDef) {
            for child in df.children {
                match child {
                    FileRef::Ef(ef) => {
                        if matches!(ef.structure(), EfStructure::Transparent) {
                            assert!(
                                !ef.data().is_empty(),
                                "Transparent EF {:#06X} has empty data",
                                ef.fid().value()
                            );
                        }
                    }
                    FileRef::Df(sub) => check(sub),
                }
            }
        }
        check(&REFERENCE_MF_GSM);
    }

    /// MF has DF.TELECOM as a child.
    #[test]
    fn gsm_mf_has_df_telecom() {
        let has_telecom = REFERENCE_MF_GSM.children.iter().any(|c| {
            if let FileRef::Df(df) = c {
                df.fid == Fid::new(0x7F10)
            } else {
                false
            }
        });
        assert!(has_telecom, "GSM MF must contain DF.TELECOM (7F10)");
    }
}
