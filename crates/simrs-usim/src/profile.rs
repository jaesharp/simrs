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
//! |   +-- EF.UST (6F38) transparent, 16 bytes
//! |   +-- EF.ACC (6F78) transparent, 2 bytes
//! |   +-- EF.LOCI (6F7E) transparent, 11 bytes
//! |   +-- EF.PSLOCI (6FE7) transparent, 14 bytes
//! |   +-- EF.FPLMN (6F7B) transparent, 12 bytes
//! |   +-- EF.HPPLMN (6F31) transparent, 1 byte
//! |   +-- EF.MSISDN (6F40) linear-fixed, 1 record x 28 bytes
//! |   +-- EF.SMSP (6F42) linear-fixed, 1 record x 28 bytes
//! |   +-- EF.FDN (6F3B) linear-fixed, 5 records x 14 bytes
//! |   +-- DF.5GS (5FC0)
//! |       +-- EF.5GS3GPPLOCI (4F01) transparent, 20 bytes
//! |       +-- EF.5GSN3GPPLOCI (4F02) transparent, 20 bytes
//! |       +-- EF.5GS3GPPNSC (4F03) linear-fixed, 1 rec x 57 bytes
//! |       +-- EF.5GSN3GPPNSC (4F04) linear-fixed, 1 rec x 57 bytes
//! |       +-- EF.5GAUTHKEYS (4F05) transparent, 68 bytes
//! |       +-- EF.UAC_AIC (4F06) transparent, 4 bytes
//! |       +-- EF.SUCI_Calc_Info (4F07) transparent, 34 bytes
//! |       +-- EF.OPL5G (4F08) linear-fixed, 1 rec x 5 bytes
//! |       +-- EF.SUPI_NAI (4F09) transparent, 32 bytes
//! |       +-- EF.Routing_Indicator (4F0A) transparent, 4 bytes
//! |       +-- EF.URSP (4F0B) transparent, 64 bytes
//! |       +-- EF.TN3GPPSNN (4F0C) transparent, 32 bytes
//! |       +-- EF.CAG (4F0D) transparent, 32 bytes
//! |       +-- EF.SOR_CMCI (4F0E) transparent, 32 bytes
//! |       +-- EF.DRI (4F0F) transparent, 16 bytes
//! |       +-- EF.5GSEDRX (4F10) transparent, 3 bytes
//! |       +-- EF.5GNSWO_CONF (4F11) transparent, 2 bytes
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
/// 16-byte transparent EF. Each bit enables a service per TS 31.102 clause 4.2.8.
/// Default: services 1-25 enabled (local phone book, FDN, SMS, etc.),
/// plus 5GS services: 122-124, 126, 129-130, 132, 135, 137-138, 140-142.
///
/// Service N is encoded as bit ((N-1) % 8) of byte ((N-1) / 8).
/// Byte indices are zero-based.
///
/// Byte 15 (services 121-128): bits 1,2,3,5 set = 0x2E (svc 122,123,124,126)
/// Byte 16 (services 129-136): bits 0,1,3,6 set = 0x4B (svc 129,130,132,135)
/// Byte 17 (services 137-144): bits 0,1,3,4,5 set = 0x3B (svc 137,138,140,141,142)
static EF_UST_DATA: [u8; 18] = [
    0xFF, 0xFF, 0xFF, 0x01, // bytes 0-3: services 1-32 (1-25 enabled)
    0x00, 0x00, 0x00, 0x00, // bytes 4-7: services 33-64
    0x00, 0x00, 0x00, 0x00, // bytes 8-11: services 65-96
    0x00, 0x00, 0x00, 0x2E, // bytes 12-15: services 97-128 (122,123,124,126)
    0x4B, 0x3B,             // bytes 16-17: services 129-144 (129,130,132,135,137,138,140,141,142)
];

/// EF.UST (6F38) -- USIM Service Table.
///
/// 18-byte transparent EF. Each bit enables a service per TS 31.102 clause 4.2.8.
/// See `EF_UST_DATA` for which services are enabled.
pub static EF_UST: EfDef = EfDef {
    fid: Fid(0x6F38),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &EF_UST_DATA,
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
// EFs under DF_5GS (5FC0)
// ---------------------------------------------------------------------------

/// EF.5GS3GPPLOCI (4F01) -- 5GS 3GPP Location Information.
///
/// 20-byte transparent EF. Contains 5G-GUTI, last visited TAI, and
/// 5GS update status. Default: zero-filled (no location).
static EF_5GS_3GPP_LOCI_DATA: [u8; 20] = [0x00; 20];

/// EF.5GS3GPPLOCI (4F01) -- 5GS 3GPP access location info.
///
/// Transparent, 20 bytes. Service 122, Rel-15.
pub static EF_5GS3GPPLOCI: EfDef = EfDef {
    fid: Fid(0x4F01),
    sfi: Some(Sfi(1)),
    structure: EfStructure::Transparent,
    data: &EF_5GS_3GPP_LOCI_DATA,
};

/// EF.5GSN3GPPLOCI (4F02) -- 5GS non-3GPP Location Information.
///
/// 20-byte transparent EF. Contains non-3GPP access 5G-GUTI, TAI, and
/// update status. Default: zero-filled (no location).
static EF_5GS_N3GPP_LOCI_DATA: [u8; 20] = [0x00; 20];

/// EF.5GSN3GPPLOCI (4F02) -- 5GS non-3GPP access location info.
///
/// Transparent, 20 bytes. Service 122, Rel-15.
pub static EF_5GSN3GPPLOCI: EfDef = EfDef {
    fid: Fid(0x4F02),
    sfi: Some(Sfi(2)),
    structure: EfStructure::Transparent,
    data: &EF_5GS_N3GPP_LOCI_DATA,
};

/// EF.5GS3GPPNSC (4F03) -- 5G NAS Security Context (3GPP access).
///
/// Linear-fixed, 1 record of 57 bytes. Default: 0xFF (empty).
static EF_5GS_3GPP_NSC_DATA: [u8; 57] = [0xFF; 57];

/// EF.5GS3GPPNSC (4F03) -- 5G NAS security context for 3GPP access.
///
/// Linear-fixed, 1 record x 57 bytes. Service 122, Rel-15.
pub static EF_5GS3GPPNSC: EfDef = EfDef {
    fid: Fid(0x4F03),
    sfi: Some(Sfi(3)),
    structure: EfStructure::LinearFixed {
        record_size: 57,
        num_records: 1,
    },
    data: &EF_5GS_3GPP_NSC_DATA,
};

/// EF.5GSN3GPPNSC (4F04) -- 5G NAS Security Context (non-3GPP access).
///
/// Linear-fixed, 1 record of 57 bytes. Default: 0xFF (empty).
static EF_5GS_N3GPP_NSC_DATA: [u8; 57] = [0xFF; 57];

/// EF.5GSN3GPPNSC (4F04) -- 5G NAS security context for non-3GPP access.
///
/// Linear-fixed, 1 record x 57 bytes. Service 122, Rel-15.
pub static EF_5GSN3GPPNSC: EfDef = EfDef {
    fid: Fid(0x4F04),
    sfi: Some(Sfi(4)),
    structure: EfStructure::LinearFixed {
        record_size: 57,
        num_records: 1,
    },
    data: &EF_5GS_N3GPP_NSC_DATA,
};

/// EF.5GAUTHKEYS (4F05) -- 5G Authentication Keys.
///
/// 68-byte transparent EF. Contains KAUSF (32 bytes), KSEAF (32 bytes),
/// and key identifiers (4 bytes). Default: zero-filled (no keys stored).
static EF_5G_AUTH_KEYS_DATA: [u8; 68] = [0x00; 68];

/// EF.5GAUTHKEYS (4F05) -- 5G authentication keys.
///
/// Transparent, 68 bytes. Service 123, Rel-15.
pub static EF_5GAUTHKEYS: EfDef = EfDef {
    fid: Fid(0x4F05),
    sfi: Some(Sfi(5)),
    structure: EfStructure::Transparent,
    data: &EF_5G_AUTH_KEYS_DATA,
};

/// EF.UAC_AIC (4F06) -- UAC Access Identity Configuration.
///
/// 4-byte transparent EF. Default: 0x00 (no access identities configured).
pub static EF_UAC_AIC: EfDef = EfDef {
    fid: Fid(0x4F06),
    sfi: Some(Sfi(6)),
    structure: EfStructure::Transparent,
    data: &[0x00, 0x00, 0x00, 0x00],
};

/// EF.SUCI_Calc_Info (4F07) -- SUCI Calculation Info.
///
/// 34-byte transparent EF. Contains protection scheme identifier, home
/// network public key identifier, and home network public key.
/// Default: protection scheme 0x00 (null scheme), key ID 0x00,
/// remaining bytes 0xFF (unprovisioned).
static EF_SUCI_CALC_INFO_DATA: [u8; 34] = {
    let mut d = [0xFF; 34];
    d[0] = 0x00; // protection scheme identifier (null scheme)
    d[1] = 0x00; // home network public key identifier
    d
};

/// EF.SUCI_Calc_Info (4F07) -- SUCI calculation info.
///
/// Transparent, 34 bytes. Service 124, Rel-15.
pub static EF_SUCI_CALC_INFO: EfDef = EfDef {
    fid: Fid(0x4F07),
    sfi: Some(Sfi(7)),
    structure: EfStructure::Transparent,
    data: &EF_SUCI_CALC_INFO_DATA,
};

/// EF.OPL5G (4F08) -- 5G Operator PLMN List.
///
/// Linear-fixed, 1 record of 5 bytes. Default: 0xFF (empty).
static EF_OPL5G_DATA: [u8; 5] = [0xFF; 5];

/// EF.OPL5G (4F08) -- 5G operator PLMN list.
///
/// Linear-fixed, 1 record x 5 bytes. Service 129, Rel-15.
pub static EF_OPL5G: EfDef = EfDef {
    fid: Fid(0x4F08),
    sfi: None,
    structure: EfStructure::LinearFixed {
        record_size: 5,
        num_records: 1,
    },
    data: &EF_OPL5G_DATA,
};

/// EF.SUPI_NAI (4F09) -- Non-IMSI SUPI as NAI.
///
/// 32-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_SUPI_NAI: EfDef = EfDef {
    fid: Fid(0x4F09),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF; 32],
};

/// EF.Routing_Indicator (4F0A) -- SUCI Routing Indicator.
///
/// 4-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_ROUTING_INDICATOR: EfDef = EfDef {
    fid: Fid(0x4F0A),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF, 0xFF, 0xFF, 0xFF],
};

/// EF.URSP (4F0B) -- UE Route Selection Policies.
///
/// 64-byte transparent EF. Default: 0xFF (no policies configured).
static EF_URSP_DATA: [u8; 64] = [0xFF; 64];

/// EF.URSP (4F0B) -- UE route selection policies.
///
/// Transparent, 64 bytes. Service 132, Rel-16.
pub static EF_URSP: EfDef = EfDef {
    fid: Fid(0x4F0B),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &EF_URSP_DATA,
};

/// EF.TN3GPPSNN (4F0C) -- Trusted Non-3GPP Serving Network Name.
///
/// 32-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_TN3GPPSNN: EfDef = EfDef {
    fid: Fid(0x4F0C),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF; 32],
};

/// EF.CAG (4F0D) -- CAG Information List.
///
/// 32-byte transparent EF. Default: 0xFF (no CAG info).
pub static EF_CAG: EfDef = EfDef {
    fid: Fid(0x4F0D),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF; 32],
};

/// EF.SOR_CMCI (4F0E) -- Steering of Roaming Connected Mode Control Info.
///
/// 32-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_SOR_CMCI: EfDef = EfDef {
    fid: Fid(0x4F0E),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF; 32],
};

/// EF.DRI (4F0F) -- Disaster Roaming Information.
///
/// 16-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_DRI: EfDef = EfDef {
    fid: Fid(0x4F0F),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0xFF; 16],
};

/// EF.5GSEDRX (4F10) -- 5GS eDRX Parameters.
///
/// 3-byte transparent EF. Default: 0x00 (eDRX not configured).
pub static EF_5GSEDRX: EfDef = EfDef {
    fid: Fid(0x4F10),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x00, 0x00, 0x00],
};

/// EF.5GNSWO_CONF (4F11) -- 5G Non-Seamless WLAN Offload Configuration.
///
/// 2-byte transparent EF. Default: 0x00 (NSWO not configured).
pub static EF_5GNSWO_CONF: EfDef = EfDef {
    fid: Fid(0x4F11),
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x00, 0x00],
};

/// DF.5GS (5FC0) -- 5G System dedicated file.
///
/// Contains all Rel-15/16/17 5G SA Elementary Files per TS 31.102.
pub static DF_5GS: DfDef = DfDef {
    fid: Fid(0x5FC0),
    children: &[
        FileRef::Ef(&EF_5GS3GPPLOCI),
        FileRef::Ef(&EF_5GSN3GPPLOCI),
        FileRef::Ef(&EF_5GS3GPPNSC),
        FileRef::Ef(&EF_5GSN3GPPNSC),
        FileRef::Ef(&EF_5GAUTHKEYS),
        FileRef::Ef(&EF_UAC_AIC),
        FileRef::Ef(&EF_SUCI_CALC_INFO),
        FileRef::Ef(&EF_OPL5G),
        FileRef::Ef(&EF_SUPI_NAI),
        FileRef::Ef(&EF_ROUTING_INDICATOR),
        FileRef::Ef(&EF_URSP),
        FileRef::Ef(&EF_TN3GPPSNN),
        FileRef::Ef(&EF_CAG),
        FileRef::Ef(&EF_SOR_CMCI),
        FileRef::Ef(&EF_DRI),
        FileRef::Ef(&EF_5GSEDRX),
        FileRef::Ef(&EF_5GNSWO_CONF),
    ],
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
        FileRef::Df(&DF_5GS),
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

    // -----------------------------------------------------------------------
    // DF_5GS tests
    // -----------------------------------------------------------------------

    #[test]
    fn df_5gs_has_17_children() {
        assert_eq!(
            DF_5GS.children.len(),
            17,
            "DF_5GS must contain exactly 17 EFs"
        );
    }

    #[test]
    fn df_5gs_fid_is_5fc0() {
        assert_eq!(
            DF_5GS.fid,
            Fid(0x5FC0),
            "DF_5GS must have FID 0x5FC0"
        );
    }

    #[test]
    fn df_5gs_fids_unique() {
        let mut fids: [u16; 17] = [0xFFFF; 17];
        for (idx, child) in DF_5GS.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid.value(),
                FileRef::Df(df) => df.fid.value(),
            };
            for f in &fids[..idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under DF_5GS");
            }
            fids[idx] = fid;
        }
    }

    #[test]
    fn adf_usim_contains_df_5gs() {
        let has_5gs = ADF_USIM_ROOT.children.iter().any(|c| {
            if let FileRef::Df(df) = c {
                df.fid == Fid(0x5FC0)
            } else {
                false
            }
        });
        assert!(has_5gs, "ADF.USIM must contain DF_5GS (5FC0)");
    }

    #[test]
    fn df_5gs_ef_data_sizes() {
        // (FID, expected data length)
        let expected: [(u16, usize); 17] = [
            (0x4F01, 20),  // EF5GS3GPPLOCI
            (0x4F02, 20),  // EF5GSN3GPPLOCI
            (0x4F03, 57),  // EF5GS3GPPNSC
            (0x4F04, 57),  // EF5GSN3GPPNSC
            (0x4F05, 68),  // EF5GAUTHKEYS
            (0x4F06, 4),   // EFUAC_AIC
            (0x4F07, 34),  // EFSUCI_Calc_Info
            (0x4F08, 5),   // EFOPL5G
            (0x4F09, 32),  // EFSUPI_NAI
            (0x4F0A, 4),   // EFRouting_Indicator
            (0x4F0B, 64),  // EFURSP
            (0x4F0C, 32),  // EFTN3GPPSNN
            (0x4F0D, 32),  // EFCAG
            (0x4F0E, 32),  // EFSOR_CMCI
            (0x4F0F, 16),  // EFDRI
            (0x4F10, 3),   // EF5GSEDRX
            (0x4F11, 2),   // EF5GNSWO_CONF
        ];

        for (fid, exp_len) in &expected {
            let child = DF_5GS.children.iter().find(|c| {
                if let FileRef::Ef(ef) = c {
                    ef.fid.value() == *fid
                } else {
                    false
                }
            });
            let Some(FileRef::Ef(ef)) = child else {
                panic!("EF {fid:#06X} not found in DF_5GS")
            };
            assert_eq!(
                ef.data.len(),
                *exp_len,
                "EF {fid:#06X} data length mismatch: got {}, expected {exp_len}",
                ef.data.len()
            );
        }
    }

    #[test]
    fn df_5gs_linear_fixed_record_sizes() {
        // (FID, expected record_size, expected num_records)
        let lf_efs: [(u16, u8, u8); 3] = [
            (0x4F03, 57, 1), // EF5GS3GPPNSC
            (0x4F04, 57, 1), // EF5GSN3GPPNSC
            (0x4F08, 5, 1),  // EFOPL5G
        ];

        for (fid, exp_rec_size, exp_num_recs) in &lf_efs {
            let child = DF_5GS.children.iter().find(|c| {
                if let FileRef::Ef(ef) = c {
                    ef.fid.value() == *fid
                } else {
                    false
                }
            });
            let Some(FileRef::Ef(ef)) = child else {
                panic!("EF {fid:#06X} not found in DF_5GS")
            };
            match ef.structure {
                EfStructure::LinearFixed {
                    record_size,
                    num_records,
                } => {
                    assert_eq!(
                        record_size, *exp_rec_size,
                        "EF {fid:#06X} record_size mismatch"
                    );
                    assert_eq!(
                        num_records, *exp_num_recs,
                        "EF {fid:#06X} num_records mismatch"
                    );
                }
                _ => panic!("EF {fid:#06X} must be LinearFixed"),
            }
        }
    }

    #[test]
    fn ef_ust_has_5gs_services_enabled() {
        // Service 122 is bit 1 of byte 15 (zero-indexed).
        // Service N: byte = (N-1)/8, bit = (N-1)%8.
        let ust = EF_UST.data;
        assert!(
            ust.len() >= 18,
            "UST must be at least 18 bytes to cover 5GS services"
        );

        // Check service 122: byte 15, bit 1
        assert_ne!(
            ust[15] & (1 << 1),
            0,
            "UST service 122 (5GS mobility management) must be enabled"
        );
        // Check service 123: byte 15, bit 2
        assert_ne!(
            ust[15] & (1 << 2),
            0,
            "UST service 123 (5G authentication management) must be enabled"
        );
        // Check service 124: byte 15, bit 3
        assert_ne!(
            ust[15] & (1 << 3),
            0,
            "UST service 124 (SUCI calculation) must be enabled"
        );
        // Check service 126: byte 15, bit 5
        assert_ne!(
            ust[15] & (1 << 5),
            0,
            "UST service 126 (UAC access identity) must be enabled"
        );
    }
}
