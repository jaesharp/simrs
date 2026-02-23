//! Default reference USIM profile filesystem per 3GPP TS 31.102.
//!
//! Provides a standard USIM filesystem tree as `static` definitions,
//! suitable for test and development use. The file data is zero-filled
//! or populated with sensible defaults from the swsim reference profile.
//!
//! # Profile tiers
//!
//! EFs are gated by feature flags:
//! - **`profile-minimal`** -- LTE attach minimum (~15 EFs)
//! - **`profile-standard`** (default) -- baseline + auth + SMS + phonebook (~35 EFs)
//! - **`profile-full`** -- full TS 31.102 catalog (~100 EFs)
//!
//! # Structure (profile-full)
//!
//! ```text
//! MF (3F00)
//! +-- EF.ICCID (2FE2) transparent, 10 bytes
//! +-- EF.DIR (2F00) linear-fixed, 1 record x 16 bytes
//! +-- EF.ARR (2F06) linear-fixed, 1 record x 8 bytes
//! +-- ADF.USIM (FF01)
//! |   +-- [minimal] EF.IMSI (6F07) transparent, 9 bytes
//! |   +-- [minimal] EF.AD (6FAD) transparent, 4 bytes
//! |   +-- [minimal] EF.UST (6F38) transparent, 18 bytes
//! |   +-- [minimal] EF.ACC (6F78) transparent, 2 bytes
//! |   +-- [minimal] EF.LOCI (6F7E) transparent, 11 bytes
//! |   +-- [minimal] EF.PSLOCI (6FE7) transparent, 14 bytes
//! |   +-- [minimal] EF.FPLMN (6F7B) transparent, 12 bytes
//! |   +-- [minimal] EF.HPPLMN (6F31) transparent, 1 byte
//! |   +-- [minimal] EF.Keys (6F08) transparent, 33 bytes
//! |   +-- [minimal] EF.KeysPS (6F09) transparent, 33 bytes
//! |   +-- [standard] EF.LI (6F05) transparent, 10 bytes
//! |   +-- [standard] EF.MSISDN (6F40) linear-fixed, 2 rec x 30 bytes
//! |   +-- [standard] EF.SMSP (6F42) linear-fixed, 2 rec x 52 bytes
//! |   +-- [standard] EF.FDN (6F3B) linear-fixed, 2 rec x 30 bytes
//! |   +-- [standard] EF.SPN (6F46) transparent, 17 bytes
//! |   +-- [standard] EF.CBMI (6F45) transparent, 20 bytes
//! |   +-- [standard] EF.CBMID (6F48) transparent, 20 bytes
//! |   +-- [standard] EF.CBMIR (6F50) transparent, 20 bytes
//! |   +-- [standard] EF.SMS (6F3C) linear-fixed, 2 rec x 176 bytes
//! |   +-- [standard] EF.SMSS (6F43) transparent, 2 bytes
//! |   +-- [standard] EF.SMSR (6F47) linear-fixed, 2 rec x 30 bytes
//! |   +-- [standard] EF.ECC (6FB7) linear-fixed, 5 rec x 16 bytes
//! |   +-- [standard] EF.PLMNwAcT (6F60) transparent, 60 bytes
//! |   +-- [standard] EF.OPLMNwACT (6F61) transparent, 60 bytes
//! |   +-- [standard] EF.HPLMNwAcT (6F62) transparent, 60 bytes
//! |   +-- [standard] EF.EHPLMN (6FD9) transparent, 12 bytes
//! |   +-- [standard] EF.PNN (6FC5) linear-fixed, 4 rec x 24 bytes
//! |   +-- [standard] EF.OPL (6FC6) linear-fixed, 1 rec x 8 bytes
//! |   +-- [standard] EF.GID1 (6F3E) transparent, 10 bytes
//! |   +-- [standard] EF.GID2 (6F3F) transparent, 10 bytes
//! |   +-- [standard] EF.SPDI (6FCD) transparent, 33 bytes
//! |   +-- [standard] EF.ACL (6F57) transparent, 4 bytes
//! |   +-- [standard] EF.EST (6F56) transparent, 9 bytes
//! |   +-- [standard] EF.EPSLOCI (6FE3) transparent, 18 bytes
//! |   +-- [standard] EF.EPSNSC (6FE4) linear-fixed, 1 rec x 54 bytes
//! |   +-- [full] EF.DCK (6F2C) transparent, 16 bytes
//! |   +-- [full] EF.CNL (6F32) transparent, 24 bytes
//! |   +-- [full] EF.ACMmax (6F37) transparent, 3 bytes
//! |   +-- [full] EF.ACM (6F39) cyclic, 3 rec x 3 bytes
//! |   +-- [full] EF.PUCT (6F41) transparent, 5 bytes
//! |   +-- [full] EF.SDN (6F49) linear-fixed, 2 rec x 30 bytes
//! |   +-- [full] EF.EXT2 (6F4B) linear-fixed, 2 rec x 13 bytes
//! |   +-- [full] EF.EXT3 (6F4C) linear-fixed, 2 rec x 13 bytes
//! |   +-- [full] EF.BDN (6F4D) linear-fixed, 4 rec x 29 bytes
//! |   +-- [full] EF.EXT5 (6F4E) linear-fixed, 4 rec x 13 bytes
//! |   +-- [full] EF.CCP2 (6F4F) linear-fixed, 4 rec x 15 bytes
//! |   +-- [full] EF.CMI (6F58) linear-fixed, 4 rec x 11 bytes
//! |   +-- [full] EF.START_HFN (6F5B) transparent, 6 bytes
//! |   +-- [full] EF.THRESHOLD (6F5C) transparent, 3 bytes
//! |   +-- [full] EF.ICI (6F80) cyclic, 1 rec x 30 bytes
//! |   +-- [full] EF.OCI (6F81) cyclic, 1 rec x 30 bytes
//! |   +-- [full] EF.ICT (6F82) cyclic, 1 rec x 3 bytes
//! |   +-- [full] EF.OCT (6F83) cyclic, 1 rec x 3 bytes
//! |   +-- [full] EF.VGCS (6FB1) transparent, 40 bytes
//! |   +-- [full] EF.VGCSS (6FB2) transparent, 7 bytes
//! |   +-- [full] EF.VBS (6FB3) transparent, 40 bytes
//! |   +-- [full] EF.VBSS (6FB4) transparent, 7 bytes
//! |   +-- [full] EF.eMLPP (6FB5) transparent, 2 bytes
//! |   +-- [full] EF.AaeM (6FB6) transparent, 1 byte
//! |   +-- [full] EF.NETPAR (6FC4) transparent, 62 bytes
//! |   +-- [full] EF.MBDN (6FC7) linear-fixed, 4 rec x 24 bytes
//! |   +-- [full] EF.EXT6 (6FC8) linear-fixed, 4 rec x 13 bytes
//! |   +-- [full] EF.MBI (6FC9) linear-fixed, 4 rec x 4 bytes
//! |   +-- [full] EF.MWIS (6FCA) linear-fixed, 4 rec x 5 bytes
//! |   +-- [full] EF.CFIS (6FCB) linear-fixed, 4 rec x 16 bytes
//! |   +-- [full] EF.EXT7 (6FCC) linear-fixed, 4 rec x 13 bytes
//! |   +-- [full] EF.MMSN (6FCE) linear-fixed, 4 rec x 24 bytes
//! |   +-- [full] EF.EXT8 (6FCF) linear-fixed, 4 rec x 64 bytes
//! |   +-- [full] EF.MMSICP (6FD0) transparent, 32 bytes
//! |   +-- [full] EF.MMSUP (6FD1) linear-fixed, 1 rec x 64 bytes
//! |   +-- [full] EF.MMSUCP (6FD2) transparent, 4 bytes
//! |   +-- [full] EF.NIA (6FD3) linear-fixed, 1 rec x 21 bytes
//! |   +-- [full] EF.VGCSCA (6FD4) transparent, 20 bytes
//! |   +-- [full] EF.GBABP (6FD6) transparent, 64 bytes
//! |   +-- [full] EF.MSK (6FD7) linear-fixed, 4 rec x 20 bytes
//! |   +-- [full] EF.MUK (6FD8) linear-fixed, 1 rec x 40 bytes
//! |   +-- [full] EF.GBANL (6FDA) linear-fixed, 1 rec x 4 bytes
//! |   +-- [full] EF.EHPLMNPI (6FDB) transparent, 1 byte
//! |   +-- [full] EF.NAFKCA (6FDD) linear-fixed, 2 rec x 32 bytes
//! |   +-- [full] EF.SPNI (6FDE) transparent, 30 bytes
//! |   +-- [full] EF.PNNI (6FDF) linear-fixed, 3 rec x 30 bytes
//! |   +-- [full] EF.NCP_IP (6FE2) linear-fixed, 1 rec x 54 bytes
//! |   +-- [full] EF.UFC (6FE6) transparent, 64 bytes
//! |   +-- [full] EF.NASCONFIG (6FE8) transparent, 4 bytes
//! |   +-- [full] EF.PWS (6FEC) transparent, 3 bytes
//! |   +-- [full] EF.FDNURI (6FED) linear-fixed, 1 rec x 4 bytes
//! |   +-- [full] EF.BDNURI (6FEE) linear-fixed, 4 rec x 128 bytes
//! |   +-- [full] EF.SDNURI (6FEF) linear-fixed, 1 rec x 4 bytes
//! |   +-- [full] EF.IPS (6FF1) cyclic, 5 rec x 4 bytes
//! |   +-- [full] EF.FromPreferred (6FF7) transparent, 1 byte
//! |   +-- DF.5GS (5FC0)
//! |   |   +-- EF.5GS3GPPLOCI (4F01) transparent, 20 bytes
//! |   |   +-- ... (17 EFs total)
//! |   +-- [full] DF.GSM-ACCESS (5F3B)
//! |       +-- EF.Kc (4F20) transparent, 9 bytes
//! |       +-- EF.KcGPRS (4F52) transparent, 9 bytes
//! +-- DF.TELECOM (7F10)
//! ```
//!
//! # Standards
//! - 3GPP TS 31.102 V17.5.0 clause 4.2 -- USIM EF definitions
//! - 3GPP TS 31.102 V17.5.0 clause 4.4 -- File identifiers
//! - ETSI TS 102 221 V16.4.0 clause 13 -- UICC files under MF

use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef, Sfi};
#[cfg(test)]
use simrs_fs::EfStructure;

// ---------------------------------------------------------------------------
// EFs under MF
// ---------------------------------------------------------------------------

/// EF.ICCID (2FE2) -- ICC Identification.
///
/// 10-byte transparent EF. Default: test ICCID `8901260000000000000`.
/// Encoding: BCD-nibble-swapped per ETSI TS 102 221 clause 13.2.
pub static EF_ICCID: EfDef = EfDef::transparent(
    Fid::new(0x2FE2),
    Some(Sfi::new(2)),
    &[0x98, 0x10, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

/// Single DIR record for USIM AID.
///
/// Format: `61 09 4F 07 A0000000871002 ...padding`
static EF_DIR_RECORD_USIM: [u8; 16] = [
    0x61, 0x09, 0x4F, 0x07,
    0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Single DIR record for ISIM AID.
///
/// Format: `61 09 4F 07 A0000000871004 ...padding`
#[cfg(feature = "isim")]
static EF_DIR_RECORD_ISIM: [u8; 16] = [
    0x61, 0x09, 0x4F, 0x07,
    0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Single DIR record for HPSIM AID.
///
/// Format: `61 09 4F 07 A000000087100A ...padding`
#[cfg(feature = "hpsim")]
static EF_DIR_RECORD_HPSIM: [u8; 16] = [
    0x61, 0x09, 0x4F, 0x07,
    0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x0A,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Helper: concatenate two 16-byte records into a 32-byte array.
#[cfg(any(
    all(feature = "isim", not(feature = "hpsim")),
    all(not(feature = "isim"), feature = "hpsim"),
))]
const fn concat_2(a: &[u8; 16], b: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 16 {
        out[i] = a[i];
        out[16 + i] = b[i];
        i += 1;
    }
    out
}

/// Helper: concatenate three 16-byte records into a 48-byte array.
#[cfg(all(feature = "isim", feature = "hpsim"))]
const fn concat_3(a: &[u8; 16], b: &[u8; 16], c: &[u8; 16]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut i = 0;
    while i < 16 {
        out[i] = a[i];
        out[16 + i] = b[i];
        out[32 + i] = c[i];
        i += 1;
    }
    out
}

/// EF.DIR data: USIM only (1 record x 16 bytes).
#[cfg(all(not(feature = "isim"), not(feature = "hpsim")))]
static EF_DIR_DATA: [u8; 16] = EF_DIR_RECORD_USIM;

/// EF.DIR data: USIM + ISIM (2 records x 16 bytes).
#[cfg(all(feature = "isim", not(feature = "hpsim")))]
static EF_DIR_DATA: [u8; 32] = concat_2(&EF_DIR_RECORD_USIM, &EF_DIR_RECORD_ISIM);

/// EF.DIR data: USIM + HPSIM (2 records x 16 bytes).
#[cfg(all(not(feature = "isim"), feature = "hpsim"))]
static EF_DIR_DATA: [u8; 32] = concat_2(&EF_DIR_RECORD_USIM, &EF_DIR_RECORD_HPSIM);

/// EF.DIR data: USIM + ISIM + HPSIM (3 records x 16 bytes).
#[cfg(all(feature = "isim", feature = "hpsim"))]
static EF_DIR_DATA: [u8; 48] = concat_3(
    &EF_DIR_RECORD_USIM,
    &EF_DIR_RECORD_ISIM,
    &EF_DIR_RECORD_HPSIM,
);

/// EF.DIR (2F00) -- Application Directory.
///
/// Linear-fixed, N records of 16 bytes. Number of records depends on
/// which ADF features are enabled (USIM always present; ISIM and HPSIM
/// are optional).
#[cfg(all(not(feature = "isim"), not(feature = "hpsim")))]
pub static EF_DIR: EfDef = EfDef::linear_fixed(
    Fid::new(0x2F00),
    Some(Sfi::new(30)),
    16, 1,
    &EF_DIR_DATA,
);

/// EF.DIR (2F00) -- Application Directory (USIM + one ADF).
#[cfg(any(
    all(feature = "isim", not(feature = "hpsim")),
    all(not(feature = "isim"), feature = "hpsim"),
))]
pub static EF_DIR: EfDef = EfDef::linear_fixed(
    Fid::new(0x2F00),
    Some(Sfi::new(30)),
    16, 2,
    &EF_DIR_DATA,
);

/// EF.DIR (2F00) -- Application Directory (USIM + ISIM + HPSIM).
#[cfg(all(feature = "isim", feature = "hpsim"))]
pub static EF_DIR: EfDef = EfDef::linear_fixed(
    Fid::new(0x2F00),
    Some(Sfi::new(30)),
    16, 3,
    &EF_DIR_DATA,
);

/// EF.ARR data: one empty record.
static EF_ARR_DATA: [u8; 8] = [0xFF; 8];

/// EF.ARR (2F06) -- Access Rule Reference.
///
/// Linear-fixed, 1 record of 8 bytes. Default: empty (all 0xFF).
pub static EF_ARR: EfDef = EfDef::linear_fixed(
    Fid::new(0x2F06),
    None,
    8, 1,
    &EF_ARR_DATA,
);

// ---------------------------------------------------------------------------
// EFs under ADF.USIM
// ---------------------------------------------------------------------------

/// EF.IMSI (6F07) -- International Mobile Subscriber Identity.
///
/// 9-byte transparent EF. Default: test IMSI `001010000000000`.
/// Byte 0: length of IMSI data (0x08 = 8 bytes of BCD digits).
/// Remaining: BCD-encoded with nibble swap.
pub static EF_IMSI: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    Some(Sfi::new(7)),
    &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0],
);

/// EF.AD (6FAD) -- Administrative Data.
///
/// 4-byte transparent EF. Byte 0: MS operation mode (0x00 = normal).
/// Bytes 1-2: reserved. Byte 3: MNC length (2 digits).
pub static EF_AD: EfDef = EfDef::transparent(
    Fid::new(0x6FAD),
    None,
    &[0x00, 0x00, 0x00, 0x02],
);

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
pub static EF_UST: EfDef = EfDef::transparent(
    Fid::new(0x6F38),
    None,
    &EF_UST_DATA,
);

/// EF.ACC (6F78) -- Access Control Class.
///
/// 2-byte transparent EF. Default: class 0 (bit 0 set).
pub static EF_ACC: EfDef = EfDef::transparent(
    Fid::new(0x6F78),
    None,
    &[0x00, 0x01],
);

/// EF.LOCI (6F7E) -- Location Information.
///
/// 11-byte transparent EF. Bytes 0-3: TMSI (0xFF = unprovisioned),
/// bytes 4-8: LAI (MCC/MNC/LAC), byte 9: TMSI TIME, byte 10: update status.
/// Default: unprovisioned (0xFF fill, status 0x02 = not updated).
/// TS 31.102 clause 4.2.17.
pub static EF_LOCI: EfDef = EfDef::transparent(
    Fid::new(0x6F7E),
    None,
    &[
        0xFF, 0xFF, 0xFF, 0xFF, // TMSI: unprovisioned
        0xFF, 0xFF, 0xFF,       // LAI: MCC/MNC
        0xFF, 0xFF,             // LAI: LAC
        0xFF,                   // TMSI TIME
        0x02,                   // location update status: not updated
    ],
);

/// EF.PSLOCI (6FE7) -- Packet Switched Location Information.
///
/// 14-byte transparent EF. Default: zero-filled.
pub static EF_PSLOCI: EfDef = EfDef::transparent(
    Fid::new(0x6FE7),
    None,
    &[0x00; 14],
);

/// EF.FPLMN (6F7B) -- Forbidden PLMNs.
///
/// 12-byte transparent EF (4 PLMN entries x 3 bytes each).
/// Default: all 0xFF (no forbidden PLMNs).
pub static EF_FPLMN: EfDef = EfDef::transparent(
    Fid::new(0x6F7B),
    None,
    &[0xFF; 12],
);

/// EF.HPPLMN (6F31) -- Higher Priority PLMN Search Period.
///
/// 1-byte transparent EF. Value in units of N * 6 minutes. Default: 0x3C (60 = 6 hours).
pub static EF_HPPLMN: EfDef = EfDef::transparent(
    Fid::new(0x6F31),
    None,
    &[0x3C],
);

/// EF.Keys (6F08) -- Ciphering and Integrity Keys.
///
/// 33-byte transparent EF. Byte 0: KSI (key set identifier).
/// Bytes 1-16: CK (ciphering key). Bytes 17-32: IK (integrity key).
/// TS 31.102 clause 4.2.6.
pub static EF_KEYS: EfDef = EfDef::transparent(
    Fid::new(0x6F08),
    Some(Sfi::new(8)),
    &[
        0x07, // KSI = 7 (no key available)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // CK
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // IK
    ],
);

/// EF.KeysPS (6F09) -- Ciphering and Integrity Keys for Packet Switched domain.
///
/// 33-byte transparent EF. Same layout as EF.Keys.
/// TS 31.102 clause 4.2.7.
pub static EF_KEYS_PS: EfDef = EfDef::transparent(
    Fid::new(0x6F09),
    Some(Sfi::new(9)),
    &[
        0x07, // KSI = 7 (no key available)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // CK
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // IK
    ],
);

// ---------------------------------------------------------------------------
// EFs under ADF.USIM -- standard tier
// ---------------------------------------------------------------------------

/// EF.LI (6F05) -- Language Indication.
///
/// Transparent EF, 10 bytes. Contains language preferences.
/// TS 31.102 clause 4.2.9. SFI 0x02.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_LI: EfDef = EfDef::transparent(
    Fid::new(0x6F05),
    Some(Sfi::new(2)),
    &[0xFF; 10],
);

/// EF.MSISDN data: two empty records of 30 bytes each.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_MSISDN_DATA: [u8; 60] = [0xFF; 60];

/// EF.MSISDN (6F40) -- MSISDN (own phone number).
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// TS 31.102 clause 4.2.26.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_MSISDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F40),
    None,
    30, 2,
    &EF_MSISDN_DATA,
);

/// EF.SMSP data: two records of 52 bytes each.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_SMSP_DATA: [u8; 104] = [0xFF; 104];

/// EF.SMSP (6F42) -- Short Message Service Parameters.
///
/// Linear-fixed, 2 records of 52 bytes. Default: empty.
/// TS 31.102 clause 4.2.27.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_SMSP: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F42),
    None,
    52, 2,
    &EF_SMSP_DATA,
);

/// EF.FDN data: 2 empty records of 30 bytes each.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_FDN_DATA: [u8; 60] = [0xFF; 60];

/// EF.FDN (6F3B) -- Fixed Dialling Numbers.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// TS 31.102 clause 4.2.24.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_FDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3B),
    None,
    30, 2,
    &EF_FDN_DATA,
);

/// EF.SPN (6F46) -- Service Provider Name.
///
/// 17-byte transparent EF. Byte 0: display condition.
/// Bytes 1-16: SPN in UCS2 or GSM 7-bit. Default: empty.
/// TS 31.102 clause 4.2.12.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_SPN: EfDef = EfDef::transparent(
    Fid::new(0x6F46),
    None,
    &[
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ],
);

/// EF.CBMI (6F45) -- Cell Broadcast Message Identifier selection.
///
/// 20-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.14.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_CBMI: EfDef = EfDef::transparent(
    Fid::new(0x6F45),
    None,
    &[0xFF; 20],
);

/// EF.CBMID (6F48) -- Cell Broadcast Message Identifier for Data Download.
///
/// 20-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.20. SFI 0x0E.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_CBMID: EfDef = EfDef::transparent(
    Fid::new(0x6F48),
    Some(Sfi::new(0x0E)),
    &[0xFF; 20],
);

/// EF.CBMIR (6F50) -- Cell Broadcast Message Identifier Range selection.
///
/// 20-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.22.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_CBMIR: EfDef = EfDef::transparent(
    Fid::new(0x6F50),
    None,
    &[0xFF; 20],
);

/// EF.SMS data: 2 records of 176 bytes each.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_SMS_DATA: [u8; 352] = {
    let mut d = [0xFF; 352];
    d[0] = 0x00; // record 1 status: free
    d[176] = 0x00; // record 2 status: free
    d
};

/// EF.SMS (6F3C) -- Short Messages.
///
/// Linear-fixed, 2 records of 176 bytes. Default: free (status byte 0x00).
/// TS 31.102 clause 4.2.25.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_SMS: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3C),
    None,
    176, 2,
    &EF_SMS_DATA,
);

/// EF.SMSS (6F43) -- SMS Status.
///
/// 2-byte transparent EF. Byte 0: last TP-MR. Byte 1: memory cap exceeded flag.
/// TS 31.102 clause 4.2.28.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_SMSS: EfDef = EfDef::transparent(
    Fid::new(0x6F43),
    None,
    &[0x0B, 0xFF],
);

/// EF.SMSR data: 2 records of 30 bytes each.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_SMSR_DATA: [u8; 60] = [0xFF; 60];

/// EF.SMSR (6F47) -- Short Message Status Reports.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// TS 31.102 clause 4.2.29.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_SMSR: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F47),
    None,
    30, 2,
    &EF_SMSR_DATA,
);

/// EF.ECC data: 5 records of 16 bytes each.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_ECC_DATA: [u8; 80] = {
    let mut d = [0xFF; 80];
    // Last byte of each record is service category (0x00)
    d[15] = 0x00;
    d[31] = 0x00;
    d[47] = 0x00;
    d[63] = 0x00;
    d[79] = 0x00;
    d
};

/// EF.ECC (6FB7) -- Emergency Call Codes.
///
/// Linear-fixed, 5 records of 16 bytes. Default: empty.
/// TS 31.102 clause 4.2.21. SFI 0x01.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_ECC: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FB7),
    Some(Sfi::new(1)),
    16, 5,
    &EF_ECC_DATA,
);

/// EF.PLMNwAcT data: 60 bytes (12 PLMN entries x 5 bytes).
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_PLMNWACT_DATA: [u8; 60] = {
    let mut d = [0xFF; 60];
    // Last two bytes are AcT (0x0000) for the trailing entry
    d[58] = 0x00;
    d[59] = 0x00;
    d
};

/// EF.PLMNwAcT (6F60) -- User Controlled PLMN Selector with Access Technology.
///
/// Transparent, 60 bytes. 12 entries of 5 bytes (3 PLMN + 2 AcT).
/// TS 31.102 clause 4.2.5. SFI 0x0A.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_PLMNWACT: EfDef = EfDef::transparent(
    Fid::new(0x6F60),
    Some(Sfi::new(0x0A)),
    &EF_PLMNWACT_DATA,
);

/// EF.OPLMNwACT data: 60 bytes.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_OPLMNWACT_DATA: [u8; 60] = {
    let mut d = [0xFF; 60];
    d[58] = 0x00;
    d[59] = 0x00;
    d
};

/// EF.OPLMNwACT (6F61) -- Operator Controlled PLMN Selector with Access Technology.
///
/// Transparent, 60 bytes.
/// TS 31.102 clause 4.2.59. SFI 0x11.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_OPLMNWACT: EfDef = EfDef::transparent(
    Fid::new(0x6F61),
    Some(Sfi::new(0x11)),
    &EF_OPLMNWACT_DATA,
);

/// EF.HPLMNwAcT data: 60 bytes.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_HPLMNWACT_DATA: [u8; 60] = {
    let mut d = [0xFF; 60];
    d[58] = 0x00;
    d[59] = 0x00;
    d
};

/// EF.HPLMNwAcT (6F62) -- HPLMN Selector with Access Technology.
///
/// Transparent, 60 bytes.
/// TS 31.102 clause 4.2.60. SFI 0x13.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_HPLMNWACT: EfDef = EfDef::transparent(
    Fid::new(0x6F62),
    Some(Sfi::new(0x13)),
    &EF_HPLMNWACT_DATA,
);

/// EF.EHPLMN (6FD9) -- Equivalent HPLMN.
///
/// 12-byte transparent EF. 4 PLMN entries of 3 bytes each.
/// TS 31.102 clause 4.2.84. SFI 0x1D.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_EHPLMN: EfDef = EfDef::transparent(
    Fid::new(0x6FD9),
    Some(Sfi::new(0x1D)),
    &[
        0x09, 0xF1, 0x07, // PLMN 901-70 (test network)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ],
);

/// EF.PNN data: 4 records of 24 bytes each.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_PNN_DATA: [u8; 96] = [0xFF; 96];

/// EF.PNN (6FC5) -- PLMN Network Name.
///
/// Linear-fixed, 4 records of 24 bytes. Default: empty.
/// TS 31.102 clause 4.2.58. SFI 0x19.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_PNN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FC5),
    Some(Sfi::new(0x19)),
    24, 4,
    &EF_PNN_DATA,
);

/// EF.OPL data: 1 record of 8 bytes.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_OPL_DATA: [u8; 8] = [0xFF; 8];

/// EF.OPL (6FC6) -- Operator PLMN List.
///
/// Linear-fixed, 1 record of 8 bytes. Default: empty.
/// TS 31.102 clause 4.2.59.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_OPL: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FC6),
    None,
    8, 1,
    &EF_OPL_DATA,
);

/// EF.GID1 (6F3E) -- Group Identifier Level 1.
///
/// 10-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.10.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_GID1: EfDef = EfDef::transparent(
    Fid::new(0x6F3E),
    None,
    &[0xFF; 10],
);

/// EF.GID2 (6F3F) -- Group Identifier Level 2.
///
/// 10-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.11.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_GID2: EfDef = EfDef::transparent(
    Fid::new(0x6F3F),
    None,
    &[0xFF; 10],
);

/// EF.SPDI (6FCD) -- Service Provider Display Information.
///
/// 33-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.66. SFI 0x1B.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_SPDI: EfDef = EfDef::transparent(
    Fid::new(0x6FCD),
    Some(Sfi::new(0x1B)),
    &[0xFF; 33],
);

/// EF.ACL (6F57) -- Access Point Name Control List.
///
/// 4-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.48.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_ACL: EfDef = EfDef::transparent(
    Fid::new(0x6F57),
    None,
    &[0xFF; 4],
);

/// EF.EST (6F56) -- Enabled Services Table.
///
/// 9-byte transparent EF. Default: all services disabled.
/// TS 31.102 clause 4.2.47. SFI 0x05.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_EST: EfDef = EfDef::transparent(
    Fid::new(0x6F56),
    Some(Sfi::new(5)),
    &[0x00; 9],
);

/// EF.EPSLOCI (6FE3) -- EPS Location Information.
///
/// 18-byte transparent EF. Contains GUTI, last visited TAI, EPS update status.
/// TS 31.102 clause 4.2.91. SFI 0x1E.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_EPSLOCI: EfDef = EfDef::transparent(
    Fid::new(0x6FE3),
    Some(Sfi::new(0x1E)),
    &[
        0x0B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0x02,
    ],
);

/// EF.EPSNSC data: 1 record of 54 bytes.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
static EF_EPSNSC_DATA: [u8; 54] = [
    0xA0, 0x34, 0x80, 0x01, 0x07, 0x81, 0x20,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x82, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x83, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x84, 0x01, 0xFF,
];

/// EF.EPSNSC (6FE4) -- EPS NAS Security Context.
///
/// Linear-fixed, 1 record of 54 bytes.
/// TS 31.102 clause 4.2.92. SFI 0x18.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_EPSNSC: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FE4),
    Some(Sfi::new(0x18)),
    54, 1,
    &EF_EPSNSC_DATA,
);

// ---------------------------------------------------------------------------
// EFs under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

/// EF.DCK (6F2C) -- Depersonalisation Control Keys.
///
/// 16-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.42.
#[cfg(feature = "profile-full")]
pub static EF_DCK: EfDef = EfDef::transparent(
    Fid::new(0x6F2C),
    None,
    &[0xFF; 16],
);

/// EF.CNL (6F32) -- Co-operative Network List.
///
/// 24-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.43.
#[cfg(feature = "profile-full")]
pub static EF_CNL: EfDef = EfDef::transparent(
    Fid::new(0x6F32),
    None,
    &[0xFF; 24],
);

/// EF.ACMmax (6F37) -- ACM Maximum Value.
///
/// 3-byte transparent EF. Default: 0x000000 (no maximum).
/// TS 31.102 clause 4.2.44.
#[cfg(feature = "profile-full")]
pub static EF_ACMMAX: EfDef = EfDef::transparent(
    Fid::new(0x6F37),
    None,
    &[0x00, 0x00, 0x00],
);

/// EF.ACM data: 3 records of 3 bytes each.
#[cfg(feature = "profile-full")]
static EF_ACM_DATA: [u8; 9] = [0x00; 9];

/// EF.ACM (6F39) -- Accumulated Call Meter.
///
/// Cyclic, 3 records of 3 bytes. Default: zero.
/// TS 31.102 clause 4.2.45. SFI 0x1C.
#[cfg(feature = "profile-full")]
pub static EF_ACM: EfDef = EfDef::cyclic(
    Fid::new(0x6F39),
    Some(Sfi::new(0x1C)),
    3, 3,
    &EF_ACM_DATA,
);

/// EF.PUCT (6F41) -- Price per Unit and Currency Table.
///
/// 5-byte transparent EF. Default: empty currency, zero price.
/// TS 31.102 clause 4.2.46.
#[cfg(feature = "profile-full")]
pub static EF_PUCT: EfDef = EfDef::transparent(
    Fid::new(0x6F41),
    None,
    &[0xFF, 0xFF, 0xFF, 0x00, 0x00],
);

/// EF.SDN data: 2 records of 30 bytes each.
#[cfg(feature = "profile-full")]
static EF_SDN_DATA: [u8; 60] = [0xFF; 60];

/// EF.SDN (6F49) -- Service Dialling Numbers.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// TS 31.102 clause 4.2.31.
#[cfg(feature = "profile-full")]
pub static EF_SDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F49),
    None,
    30, 2,
    &EF_SDN_DATA,
);

/// EF.EXT2 data: 2 records of 13 bytes each.
#[cfg(feature = "profile-full")]
static EF_EXT2_DATA: [u8; 26] = {
    let mut d = [0xFF; 26];
    d[0] = 0x00; // record 1: type = not used
    d[13] = 0x00; // record 2: type = not used
    d
};

/// EF.EXT2 (6F4B) -- Extension 2 (FDN).
///
/// Linear-fixed, 2 records of 13 bytes. Default: empty.
/// TS 31.102 clause 4.2.32.
#[cfg(feature = "profile-full")]
pub static EF_EXT2: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4B),
    None,
    13, 2,
    &EF_EXT2_DATA,
);

/// EF.EXT3 data: 2 records of 13 bytes each.
#[cfg(feature = "profile-full")]
static EF_EXT3_DATA: [u8; 26] = [0xFF; 26];

/// EF.EXT3 (6F4C) -- Extension 3 (SDN).
///
/// Linear-fixed, 2 records of 13 bytes. Default: empty.
/// TS 31.102 clause 4.2.33.
#[cfg(feature = "profile-full")]
pub static EF_EXT3: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4C),
    None,
    13, 2,
    &EF_EXT3_DATA,
);

/// EF.BDN data: 4 records of 29 bytes each.
#[cfg(feature = "profile-full")]
static EF_BDN_DATA: [u8; 116] = [0xFF; 116];

/// EF.BDN (6F4D) -- Barred Dialling Numbers.
///
/// Linear-fixed, 4 records of 29 bytes. Default: empty.
/// TS 31.102 clause 4.2.34.
#[cfg(feature = "profile-full")]
pub static EF_BDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4D),
    None,
    29, 4,
    &EF_BDN_DATA,
);

/// EF.EXT5 data: 4 records of 13 bytes each.
#[cfg(feature = "profile-full")]
static EF_EXT5_DATA: [u8; 52] = [0xFF; 52];

/// EF.EXT5 (6F4E) -- Extension 5 (ICI/OCI/MSISDN).
///
/// Linear-fixed, 4 records of 13 bytes. Default: empty.
/// TS 31.102 clause 4.2.35.
#[cfg(feature = "profile-full")]
pub static EF_EXT5: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4E),
    None,
    13, 4,
    &EF_EXT5_DATA,
);

/// EF.CCP2 data: 4 records of 15 bytes each.
#[cfg(feature = "profile-full")]
static EF_CCP2_DATA: [u8; 60] = [0xFF; 60];

/// EF.CCP2 (6F4F) -- Capability Configuration Parameters 2.
///
/// Linear-fixed, 4 records of 15 bytes. Default: empty.
/// TS 31.102 clause 4.2.36. SFI 0x16.
#[cfg(feature = "profile-full")]
pub static EF_CCP2: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4F),
    Some(Sfi::new(0x16)),
    15, 4,
    &EF_CCP2_DATA,
);

/// EF.CMI data: 4 records of 11 bytes each.
#[cfg(feature = "profile-full")]
static EF_CMI_DATA: [u8; 44] = [0xFF; 44];

/// EF.CMI (6F58) -- Comparison Method Information.
///
/// Linear-fixed, 4 records of 11 bytes. Default: empty.
/// TS 31.102 clause 4.2.49.
#[cfg(feature = "profile-full")]
pub static EF_CMI: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F58),
    None,
    11, 4,
    &EF_CMI_DATA,
);

/// EF.START_HFN (6F5B) -- Initialisation values for Hyperframe number.
///
/// 6-byte transparent EF. Default: per swsim reference.
/// TS 31.102 clause 4.2.50. SFI 0x0F.
#[cfg(feature = "profile-full")]
pub static EF_START_HFN: EfDef = EfDef::transparent(
    Fid::new(0x6F5B),
    Some(Sfi::new(0x0F)),
    &[0xF0, 0x00, 0x00, 0xF0, 0x00, 0x00],
);

/// EF.THRESHOLD (6F5C) -- Maximum value of START.
///
/// 3-byte transparent EF. Default: 0xFFFFFF.
/// TS 31.102 clause 4.2.51. SFI 0x10.
#[cfg(feature = "profile-full")]
pub static EF_THRESHOLD: EfDef = EfDef::transparent(
    Fid::new(0x6F5C),
    Some(Sfi::new(0x10)),
    &[0xFF, 0xFF, 0xFF],
);

/// EF.ICI data: 1 record of 30 bytes.
#[cfg(feature = "profile-full")]
static EF_ICI_DATA: [u8; 30] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF,
];

/// EF.ICI (6F80) -- Incoming Call Information.
///
/// Cyclic, 1 record of 30 bytes.
/// TS 31.102 clause 4.2.52. SFI 0x14.
#[cfg(feature = "profile-full")]
pub static EF_ICI: EfDef = EfDef::cyclic(
    Fid::new(0x6F80),
    Some(Sfi::new(0x14)),
    30, 1,
    &EF_ICI_DATA,
);

/// EF.OCI data: 1 record of 30 bytes.
#[cfg(feature = "profile-full")]
static EF_OCI_DATA: [u8; 30] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF,
];

/// EF.OCI (6F81) -- Outgoing Call Information.
///
/// Cyclic, 1 record of 30 bytes.
/// TS 31.102 clause 4.2.53. SFI 0x15.
#[cfg(feature = "profile-full")]
pub static EF_OCI: EfDef = EfDef::cyclic(
    Fid::new(0x6F81),
    Some(Sfi::new(0x15)),
    30, 1,
    &EF_OCI_DATA,
);

/// EF.ICT data: 1 record of 3 bytes.
#[cfg(feature = "profile-full")]
static EF_ICT_DATA: [u8; 3] = [0x00; 3];

/// EF.ICT (6F82) -- Incoming Call Timer.
///
/// Cyclic, 1 record of 3 bytes.
/// TS 31.102 clause 4.2.54.
#[cfg(feature = "profile-full")]
pub static EF_ICT: EfDef = EfDef::cyclic(
    Fid::new(0x6F82),
    None,
    3, 1,
    &EF_ICT_DATA,
);

/// EF.OCT data: 1 record of 3 bytes.
#[cfg(feature = "profile-full")]
static EF_OCT_DATA: [u8; 3] = [0x00; 3];

/// EF.OCT (6F83) -- Outgoing Call Timer.
///
/// Cyclic, 1 record of 3 bytes.
/// TS 31.102 clause 4.2.55.
#[cfg(feature = "profile-full")]
pub static EF_OCT: EfDef = EfDef::cyclic(
    Fid::new(0x6F83),
    None,
    3, 1,
    &EF_OCT_DATA,
);

/// EF.VGCS (6FB1) -- Voice Group Call Service.
///
/// 40-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.15.
#[cfg(feature = "profile-full")]
pub static EF_VGCS: EfDef = EfDef::transparent(
    Fid::new(0x6FB1),
    None,
    &[0xFF; 40],
);

/// EF.VGCSS (6FB2) -- Voice Group Call Service Status.
///
/// 7-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.16.
#[cfg(feature = "profile-full")]
pub static EF_VGCSS: EfDef = EfDef::transparent(
    Fid::new(0x6FB2),
    None,
    &[0xFF; 7],
);

/// EF.VBS (6FB3) -- Voice Broadcast Service.
///
/// 40-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.17.
#[cfg(feature = "profile-full")]
pub static EF_VBS: EfDef = EfDef::transparent(
    Fid::new(0x6FB3),
    None,
    &[0xFF; 40],
);

/// EF.VBSS (6FB4) -- Voice Broadcast Service Status.
///
/// 7-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.18.
#[cfg(feature = "profile-full")]
pub static EF_VBSS: EfDef = EfDef::transparent(
    Fid::new(0x6FB4),
    None,
    &[0xFF; 7],
);

/// EF.eMLPP (6FB5) -- enhanced Multi-Level Pre-emption and Priority.
///
/// 2-byte transparent EF. Default: 0x0000.
/// TS 31.102 clause 4.2.19.
#[cfg(feature = "profile-full")]
pub static EF_EMLPP: EfDef = EfDef::transparent(
    Fid::new(0x6FB5),
    None,
    &[0x00, 0x00],
);

/// EF.AaeM (6FB6) -- Automatic Answer for eMLPP.
///
/// 1-byte transparent EF. Default: 0x00.
/// TS 31.102 clause 4.2.20.
#[cfg(feature = "profile-full")]
pub static EF_AAEM: EfDef = EfDef::transparent(
    Fid::new(0x6FB6),
    None,
    &[0x00],
);

/// EF.NETPAR data: 62 bytes.
#[cfg(feature = "profile-full")]
static EF_NETPAR_DATA: [u8; 62] = [
    0xA0, 0x08, 0x80, 0x02, 0x24, 0x9F, 0x81, 0x02,
    0x24, 0x9F, 0xA1, 0x04, 0x80, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// EF.NETPAR (6FC4) -- Network Parameters.
///
/// 62-byte transparent EF.
/// TS 31.102 clause 4.2.57.
#[cfg(feature = "profile-full")]
pub static EF_NETPAR: EfDef = EfDef::transparent(
    Fid::new(0x6FC4),
    None,
    &EF_NETPAR_DATA,
);

/// EF.MBDN data: 4 records of 24 bytes each.
#[cfg(feature = "profile-full")]
static EF_MBDN_DATA: [u8; 96] = [0xFF; 96];

/// EF.MBDN (6FC7) -- Mailbox Dialling Numbers.
///
/// Linear-fixed, 4 records of 24 bytes. Default: empty.
/// TS 31.102 clause 4.2.60.
#[cfg(feature = "profile-full")]
pub static EF_MBDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FC7),
    None,
    24, 4,
    &EF_MBDN_DATA,
);

/// EF.EXT6 data: 4 records of 13 bytes each.
#[cfg(feature = "profile-full")]
static EF_EXT6_DATA: [u8; 52] = [0xFF; 52];

/// EF.EXT6 (6FC8) -- Extension 6 (MBDN).
///
/// Linear-fixed, 4 records of 13 bytes. Default: empty.
/// TS 31.102 clause 4.2.61.
#[cfg(feature = "profile-full")]
pub static EF_EXT6: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FC8),
    None,
    13, 4,
    &EF_EXT6_DATA,
);

/// EF.MBI data: 4 records of 4 bytes each.
#[cfg(feature = "profile-full")]
static EF_MBI_DATA: [u8; 16] = [0xFF; 16];

/// EF.MBI (6FC9) -- Mailbox Identifier.
///
/// Linear-fixed, 4 records of 4 bytes. Default: empty.
/// TS 31.102 clause 4.2.62.
#[cfg(feature = "profile-full")]
pub static EF_MBI: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FC9),
    None,
    4, 4,
    &EF_MBI_DATA,
);

/// EF.MWIS data: 4 records of 5 bytes each.
#[cfg(feature = "profile-full")]
static EF_MWIS_DATA: [u8; 20] = [0xFF; 20];

/// EF.MWIS (6FCA) -- Message Waiting Indication Status.
///
/// Linear-fixed, 4 records of 5 bytes. Default: empty.
/// TS 31.102 clause 4.2.63.
#[cfg(feature = "profile-full")]
pub static EF_MWIS: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FCA),
    None,
    5, 4,
    &EF_MWIS_DATA,
);

/// EF.CFIS data: 4 records of 16 bytes each.
#[cfg(feature = "profile-full")]
static EF_CFIS_DATA: [u8; 64] = [0xFF; 64];

/// EF.CFIS (6FCB) -- Call Forwarding Indication Status.
///
/// Linear-fixed, 4 records of 16 bytes. Default: empty.
/// TS 31.102 clause 4.2.64.
#[cfg(feature = "profile-full")]
pub static EF_CFIS: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FCB),
    None,
    16, 4,
    &EF_CFIS_DATA,
);

/// EF.EXT7 data: 4 records of 13 bytes each.
#[cfg(feature = "profile-full")]
static EF_EXT7_DATA: [u8; 52] = [0xFF; 52];

/// EF.EXT7 (6FCC) -- Extension 7 (CFIS).
///
/// Linear-fixed, 4 records of 13 bytes. Default: empty.
/// TS 31.102 clause 4.2.65.
#[cfg(feature = "profile-full")]
pub static EF_EXT7: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FCC),
    None,
    13, 4,
    &EF_EXT7_DATA,
);

/// EF.MMSN data: 4 records of 24 bytes each.
#[cfg(feature = "profile-full")]
static EF_MMSN_DATA: [u8; 96] = [0xFF; 96];

/// EF.MMSN (6FCE) -- MMS Notification.
///
/// Linear-fixed, 4 records of 24 bytes. Default: empty.
/// TS 31.102 clause 4.2.67.
#[cfg(feature = "profile-full")]
pub static EF_MMSN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FCE),
    None,
    24, 4,
    &EF_MMSN_DATA,
);

/// EF.EXT8 data: 4 records of 64 bytes each.
#[cfg(feature = "profile-full")]
static EF_EXT8_DATA: [u8; 256] = [0xFF; 256];

/// EF.EXT8 (6FCF) -- Extension 8 (MMS).
///
/// Linear-fixed, 4 records of 64 bytes. Default: empty.
/// TS 31.102 clause 4.2.68.
#[cfg(feature = "profile-full")]
pub static EF_EXT8: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FCF),
    None,
    64, 4,
    &EF_EXT8_DATA,
);

/// EF.MMSICP (6FD0) -- MMS Issuer Connectivity Parameters.
///
/// 32-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.69.
#[cfg(feature = "profile-full")]
pub static EF_MMSICP: EfDef = EfDef::transparent(
    Fid::new(0x6FD0),
    None,
    &[0xFF; 32],
);

/// EF.MMSUP data: 1 record of 64 bytes.
#[cfg(feature = "profile-full")]
static EF_MMSUP_DATA: [u8; 64] = [0xFF; 64];

/// EF.MMSUP (6FD1) -- MMS User Preferences.
///
/// Linear-fixed, 1 record of 64 bytes. Default: empty.
/// TS 31.102 clause 4.2.70.
#[cfg(feature = "profile-full")]
pub static EF_MMSUP: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FD1),
    None,
    64, 1,
    &EF_MMSUP_DATA,
);

/// EF.MMSUCP (6FD2) -- MMS User Connectivity Parameters.
///
/// 4-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.71.
#[cfg(feature = "profile-full")]
pub static EF_MMSUCP: EfDef = EfDef::transparent(
    Fid::new(0x6FD2),
    None,
    &[0xFF; 4],
);

/// EF.NIA data: 1 record of 21 bytes.
#[cfg(feature = "profile-full")]
static EF_NIA_DATA: [u8; 21] = [0xFF; 21];

/// EF.NIA (6FD3) -- Network's Indication of Alerting.
///
/// Linear-fixed, 1 record of 21 bytes. Default: empty.
/// TS 31.102 clause 4.2.72.
#[cfg(feature = "profile-full")]
pub static EF_NIA: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FD3),
    None,
    21, 1,
    &EF_NIA_DATA,
);

/// EF.VGCSCA (6FD4) -- Voice Group Call Service Ciphering Algorithm.
///
/// 20-byte transparent EF. Default: all zeroes.
/// TS 31.102 clause 4.2.73.
#[cfg(feature = "profile-full")]
pub static EF_VGCSCA: EfDef = EfDef::transparent(
    Fid::new(0x6FD4),
    None,
    &[0x00; 20],
);

/// EF.GBABP (6FD6) -- GBA Bootstrapping Parameters.
///
/// 64-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.76.
#[cfg(feature = "profile-full")]
pub static EF_GBABP: EfDef = EfDef::transparent(
    Fid::new(0x6FD6),
    None,
    &[0xFF; 64],
);

/// EF.MSK data: 4 records of 20 bytes each.
#[cfg(feature = "profile-full")]
static EF_MSK_DATA: [u8; 80] = [0xFF; 80];

/// EF.MSK (6FD7) -- MBMS Service Key List.
///
/// Linear-fixed, 4 records of 20 bytes. Default: empty.
/// TS 31.102 clause 4.2.77.
#[cfg(feature = "profile-full")]
pub static EF_MSK: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FD7),
    None,
    20, 4,
    &EF_MSK_DATA,
);

/// EF.MUK data: 1 record of 40 bytes.
#[cfg(feature = "profile-full")]
static EF_MUK_DATA: [u8; 40] = [0xFF; 40];

/// EF.MUK (6FD8) -- MBMS User Key.
///
/// Linear-fixed, 1 record of 40 bytes. Default: empty.
/// TS 31.102 clause 4.2.78.
#[cfg(feature = "profile-full")]
pub static EF_MUK: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FD8),
    None,
    40, 1,
    &EF_MUK_DATA,
);

/// EF.GBANL data: 1 record of 4 bytes.
#[cfg(feature = "profile-full")]
static EF_GBANL_DATA: [u8; 4] = [0xFF; 4];

/// EF.GBANL (6FDA) -- GBA NAF List.
///
/// Linear-fixed, 1 record of 4 bytes. Default: empty.
/// TS 31.102 clause 4.2.82.
#[cfg(feature = "profile-full")]
pub static EF_GBANL: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FDA),
    None,
    4, 1,
    &EF_GBANL_DATA,
);

/// EF.EHPLMNPI (6FDB) -- EHPLMN Presentation Indication.
///
/// 1-byte transparent EF. 0x02 = display highest priority EHPLMN only.
/// TS 31.102 clause 4.2.85.
#[cfg(feature = "profile-full")]
pub static EF_EHPLMNPI: EfDef = EfDef::transparent(
    Fid::new(0x6FDB),
    None,
    &[0x02],
);

/// EF.NAFKCA data: 2 records of 32 bytes each.
#[cfg(feature = "profile-full")]
static EF_NAFKCA_DATA: [u8; 64] = [0xFF; 64];

/// EF.NAFKCA (6FDD) -- NAF Key Centre Address.
///
/// Linear-fixed, 2 records of 32 bytes. Default: empty.
/// TS 31.102 clause 4.2.83.
#[cfg(feature = "profile-full")]
pub static EF_NAFKCA: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FDD),
    None,
    32, 2,
    &EF_NAFKCA_DATA,
);

/// EF.SPNI (6FDE) -- Service Provider Name Icon.
///
/// 30-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.86.
#[cfg(feature = "profile-full")]
pub static EF_SPNI: EfDef = EfDef::transparent(
    Fid::new(0x6FDE),
    None,
    &[0xFF; 30],
);

/// EF.PNNI data: 3 records of 30 bytes each.
#[cfg(feature = "profile-full")]
static EF_PNNI_DATA: [u8; 90] = [0xFF; 90];

/// EF.PNNI (6FDF) -- PLMN Network Name Icon.
///
/// Linear-fixed, 3 records of 30 bytes. Default: empty.
/// TS 31.102 clause 4.2.87.
#[cfg(feature = "profile-full")]
pub static EF_PNNI: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FDF),
    None,
    30, 3,
    &EF_PNNI_DATA,
);

/// EF.NCP_IP data: 1 record of 54 bytes.
#[cfg(feature = "profile-full")]
static EF_NCP_IP_DATA: [u8; 54] = [
    0xA0, 0x34, 0x80, 0x01, 0x07, 0x81, 0x20,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x82, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x83, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x84, 0x01, 0xFF,
];

/// EF.NCP-IP (6FE2) -- Network Connectivity Parameters for USIM IP connections.
///
/// Linear-fixed, 1 record of 54 bytes.
/// TS 31.102 clause 4.2.89.
#[cfg(feature = "profile-full")]
pub static EF_NCP_IP: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FE2),
    None,
    54, 1,
    &EF_NCP_IP_DATA,
);

/// EF.UFC (6FE6) -- UICC IARI Feature Codes.
///
/// 64-byte transparent EF. Default: all zeroes.
/// TS 31.102 clause 4.2.93.
#[cfg(feature = "profile-full")]
pub static EF_UFC: EfDef = EfDef::transparent(
    Fid::new(0x6FE6),
    None,
    &[0x00; 64],
);

/// EF.NASCONFIG (6FE8) -- Non Access Stratum Configuration.
///
/// 4-byte transparent EF. Default: empty.
/// TS 31.102 clause 4.2.94.
#[cfg(feature = "profile-full")]
pub static EF_NASCONFIG: EfDef = EfDef::transparent(
    Fid::new(0x6FE8),
    None,
    &[0xFF; 4],
);

/// EF.PWS (6FEC) -- Public Warning System.
///
/// 3-byte transparent EF. Default: all zeroes.
/// TS 31.102 clause 4.2.96.
#[cfg(feature = "profile-full")]
pub static EF_PWS: EfDef = EfDef::transparent(
    Fid::new(0x6FEC),
    None,
    &[0x00, 0x00, 0x00],
);

/// EF.FDNURI data: 1 record of 4 bytes.
#[cfg(feature = "profile-full")]
static EF_FDNURI_DATA: [u8; 4] = [0xFF; 4];

/// EF.FDNURI (6FED) -- FDN URI.
///
/// Linear-fixed, 1 record of 4 bytes. Default: empty.
/// TS 31.102 clause 4.2.97.
#[cfg(feature = "profile-full")]
pub static EF_FDNURI: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FED),
    None,
    4, 1,
    &EF_FDNURI_DATA,
);

/// EF.BDNURI data: 4 records of 128 bytes each.
#[cfg(feature = "profile-full")]
static EF_BDNURI_DATA: [u8; 512] = [0xFF; 512];

/// EF.BDNURI (6FEE) -- BDN URI.
///
/// Linear-fixed, 4 records of 128 bytes. Default: empty.
/// TS 31.102 clause 4.2.98.
#[cfg(feature = "profile-full")]
pub static EF_BDNURI: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FEE),
    None,
    128, 4,
    &EF_BDNURI_DATA,
);

/// EF.SDNURI data: 1 record of 4 bytes.
#[cfg(feature = "profile-full")]
static EF_SDNURI_DATA: [u8; 4] = [0xFF; 4];

/// EF.SDNURI (6FEF) -- SDN URI.
///
/// Linear-fixed, 1 record of 4 bytes. Default: empty.
/// TS 31.102 clause 4.2.99.
#[cfg(feature = "profile-full")]
pub static EF_SDNURI: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FEF),
    None,
    4, 1,
    &EF_SDNURI_DATA,
);

/// EF.IPS data: 5 records of 4 bytes each.
#[cfg(feature = "profile-full")]
static EF_IPS_DATA: [u8; 20] = [0xFF; 20];

/// EF.IPS (6FF1) -- IMEI(SV) Pairing Status.
///
/// Cyclic, 5 records of 4 bytes. Default: empty.
/// TS 31.102 clause 4.2.101.
#[cfg(feature = "profile-full")]
pub static EF_IPS: EfDef = EfDef::cyclic(
    Fid::new(0x6FF1),
    None,
    4, 5,
    &EF_IPS_DATA,
);

/// EF.FromPreferred (6FF7) -- From Preferred.
///
/// 1-byte transparent EF. Default: 0xFF.
/// TS 31.102 clause 4.2.105.
#[cfg(feature = "profile-full")]
pub static EF_FROM_PREFERRED: EfDef = EfDef::transparent(
    Fid::new(0x6FF7),
    None,
    &[0xFF],
);

// ---------------------------------------------------------------------------
// DF.GSM-ACCESS (5F3B) under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

/// EF.Kc (4F20) -- GSM Ciphering Key Kc.
///
/// 9-byte transparent EF. Bytes 0-7: Kc. Byte 8: CKSN.
/// Default: empty key, CKSN = 7 (no key).
/// TS 31.102 clause 4.4.3.
#[cfg(feature = "profile-full")]
pub static EF_KC: EfDef = EfDef::transparent(
    Fid::new(0x4F20),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07],
);

/// EF.KcGPRS (4F52) -- GPRS Ciphering Key KcGPRS.
///
/// 9-byte transparent EF. Same layout as EF.Kc.
/// Default: empty key, CKSN = 7 (no key).
/// TS 31.102 clause 4.4.4.
#[cfg(feature = "profile-full")]
pub static EF_KC_GPRS: EfDef = EfDef::transparent(
    Fid::new(0x4F52),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07],
);

/// DF.GSM-ACCESS (5F3B) -- GSM Access sub-DF under ADF.USIM.
///
/// Contains EF.Kc and EF.KcGPRS for GSM/GPRS access.
/// TS 31.102 clause 4.4.
#[cfg(feature = "profile-full")]
pub static DF_GSM_ACCESS: DfDef = DfDef {
    fid: Fid::new(0x5F3B),
    children: &[
        FileRef::Ef(&EF_KC),
        FileRef::Ef(&EF_KC_GPRS),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F20, // EF_KC
    0x4F52, // EF_KC_GPRS
]);

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
pub static EF_5GS3GPPLOCI: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    Some(Sfi::new(1)),
    &EF_5GS_3GPP_LOCI_DATA,
);

/// EF.5GSN3GPPLOCI (4F02) -- 5GS non-3GPP Location Information.
///
/// 20-byte transparent EF. Contains non-3GPP access 5G-GUTI, TAI, and
/// update status. Default: zero-filled (no location).
static EF_5GS_N3GPP_LOCI_DATA: [u8; 20] = [0x00; 20];

/// EF.5GSN3GPPLOCI (4F02) -- 5GS non-3GPP access location info.
///
/// Transparent, 20 bytes. Service 122, Rel-15.
pub static EF_5GSN3GPPLOCI: EfDef = EfDef::transparent(
    Fid::new(0x4F02),
    Some(Sfi::new(2)),
    &EF_5GS_N3GPP_LOCI_DATA,
);

/// EF.5GS3GPPNSC (4F03) -- 5G NAS Security Context (3GPP access).
///
/// Linear-fixed, 1 record of 57 bytes. Default: 0xFF (empty).
static EF_5GS_3GPP_NSC_DATA: [u8; 57] = [0xFF; 57];

/// EF.5GS3GPPNSC (4F03) -- 5G NAS security context for 3GPP access.
///
/// Linear-fixed, 1 record x 57 bytes. Service 122, Rel-15.
pub static EF_5GS3GPPNSC: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F03),
    Some(Sfi::new(3)),
    57, 1,
    &EF_5GS_3GPP_NSC_DATA,
);

/// EF.5GSN3GPPNSC (4F04) -- 5G NAS Security Context (non-3GPP access).
///
/// Linear-fixed, 1 record of 57 bytes. Default: 0xFF (empty).
static EF_5GS_N3GPP_NSC_DATA: [u8; 57] = [0xFF; 57];

/// EF.5GSN3GPPNSC (4F04) -- 5G NAS security context for non-3GPP access.
///
/// Linear-fixed, 1 record x 57 bytes. Service 122, Rel-15.
pub static EF_5GSN3GPPNSC: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F04),
    Some(Sfi::new(4)),
    57, 1,
    &EF_5GS_N3GPP_NSC_DATA,
);

/// EF.5GAUTHKEYS (4F05) -- 5G Authentication Keys.
///
/// 68-byte transparent EF. Contains KAUSF (32 bytes), KSEAF (32 bytes),
/// and key identifiers (4 bytes). Default: zero-filled (no keys stored).
static EF_5G_AUTH_KEYS_DATA: [u8; 68] = [0x00; 68];

/// EF.5GAUTHKEYS (4F05) -- 5G authentication keys.
///
/// Transparent, 68 bytes. Service 123, Rel-15.
pub static EF_5GAUTHKEYS: EfDef = EfDef::transparent(
    Fid::new(0x4F05),
    Some(Sfi::new(5)),
    &EF_5G_AUTH_KEYS_DATA,
);

/// EF.UAC_AIC (4F06) -- UAC Access Identity Configuration.
///
/// 4-byte transparent EF. Default: 0x00 (no access identities configured).
pub static EF_UAC_AIC: EfDef = EfDef::transparent(
    Fid::new(0x4F06),
    Some(Sfi::new(6)),
    &[0x00, 0x00, 0x00, 0x00],
);

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
pub static EF_SUCI_CALC_INFO: EfDef = EfDef::transparent(
    Fid::new(0x4F07),
    Some(Sfi::new(7)),
    &EF_SUCI_CALC_INFO_DATA,
);

/// EF.OPL5G (4F08) -- 5G Operator PLMN List.
///
/// Linear-fixed, 1 record of 5 bytes. Default: 0xFF (empty).
static EF_OPL5G_DATA: [u8; 5] = [0xFF; 5];

/// EF.OPL5G (4F08) -- 5G operator PLMN list.
///
/// Linear-fixed, 1 record x 5 bytes. Service 129, Rel-15.
pub static EF_OPL5G: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F08),
    None,
    5, 1,
    &EF_OPL5G_DATA,
);

/// EF.SUPI_NAI (4F09) -- Non-IMSI SUPI as NAI.
///
/// 32-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_SUPI_NAI: EfDef = EfDef::transparent(
    Fid::new(0x4F09),
    None,
    &[0xFF; 32],
);

/// EF.Routing_Indicator (4F0A) -- SUCI Routing Indicator.
///
/// 4-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_ROUTING_INDICATOR: EfDef = EfDef::transparent(
    Fid::new(0x4F0A),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.URSP (4F0B) -- UE Route Selection Policies.
///
/// 64-byte transparent EF. Default: 0xFF (no policies configured).
static EF_URSP_DATA: [u8; 64] = [0xFF; 64];

/// EF.URSP (4F0B) -- UE route selection policies.
///
/// Transparent, 64 bytes. Service 132, Rel-16.
pub static EF_URSP: EfDef = EfDef::transparent(
    Fid::new(0x4F0B),
    None,
    &EF_URSP_DATA,
);

/// EF.TN3GPPSNN (4F0C) -- Trusted Non-3GPP Serving Network Name.
///
/// 32-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_TN3GPPSNN: EfDef = EfDef::transparent(
    Fid::new(0x4F0C),
    None,
    &[0xFF; 32],
);

/// EF.CAG (4F0D) -- CAG Information List.
///
/// 32-byte transparent EF. Default: 0xFF (no CAG info).
pub static EF_CAG: EfDef = EfDef::transparent(
    Fid::new(0x4F0D),
    None,
    &[0xFF; 32],
);

/// EF.SOR_CMCI (4F0E) -- Steering of Roaming Connected Mode Control Info.
///
/// 32-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_SOR_CMCI: EfDef = EfDef::transparent(
    Fid::new(0x4F0E),
    None,
    &[0xFF; 32],
);

/// EF.DRI (4F0F) -- Disaster Roaming Information.
///
/// 16-byte transparent EF. Default: 0xFF (not provisioned).
pub static EF_DRI: EfDef = EfDef::transparent(
    Fid::new(0x4F0F),
    None,
    &[0xFF; 16],
);

/// EF.5GSEDRX (4F10) -- 5GS eDRX Parameters.
///
/// 3-byte transparent EF. Default: 0x00 (eDRX not configured).
pub static EF_5GSEDRX: EfDef = EfDef::transparent(
    Fid::new(0x4F10),
    None,
    &[0x00, 0x00, 0x00],
);

/// EF.5GNSWO_CONF (4F11) -- 5G Non-Seamless WLAN Offload Configuration.
///
/// 2-byte transparent EF. Default: 0x00 (NSWO not configured).
pub static EF_5GNSWO_CONF: EfDef = EfDef::transparent(
    Fid::new(0x4F11),
    None,
    &[0x00, 0x00],
);

/// DF.5GS (5FC0) -- 5G System dedicated file.
///
/// Contains all Rel-15/16/17 5G SA Elementary Files per TS 31.102.
pub static DF_5GS: DfDef = DfDef {
    fid: Fid::new(0x5FC0),
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

const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // EF_5GS3GPPLOCI
    0x4F02, // EF_5GSN3GPPLOCI
    0x4F03, // EF_5GS3GPPNSC
    0x4F04, // EF_5GSN3GPPNSC
    0x4F05, // EF_5GAUTHKEYS
    0x4F06, // EF_UAC_AIC
    0x4F07, // EF_SUCI_CALC_INFO
    0x4F08, // EF_OPL5G
    0x4F09, // EF_SUPI_NAI
    0x4F0A, // EF_ROUTING_INDICATOR
    0x4F0B, // EF_URSP
    0x4F0C, // EF_TN3GPPSNN
    0x4F0D, // EF_CAG
    0x4F0E, // EF_SOR_CMCI
    0x4F0F, // EF_DRI
    0x4F10, // EF_5GSEDRX
    0x4F11, // EF_5GNSWO_CONF
]);

// ---------------------------------------------------------------------------
// DF / ADF definitions
// ---------------------------------------------------------------------------

/// ADF.USIM root DF.
///
/// Children are conditionally compiled based on the profile tier feature flags.
pub static ADF_USIM_ROOT: DfDef = DfDef {
    fid: Fid::new(0xFF01),
    children: &ADF_USIM_CHILDREN,
};

// -- profile-full children: minimal + standard + full EFs -----------------
#[cfg(feature = "profile-full")]
static ADF_USIM_CHILDREN: [FileRef; 92] = [
    // -- minimal --
    FileRef::Ef(&EF_IMSI),
    FileRef::Ef(&EF_AD),
    FileRef::Ef(&EF_UST),
    FileRef::Ef(&EF_ACC),
    FileRef::Ef(&EF_LOCI),
    FileRef::Ef(&EF_PSLOCI),
    FileRef::Ef(&EF_FPLMN),
    FileRef::Ef(&EF_HPPLMN),
    FileRef::Ef(&EF_KEYS),
    FileRef::Ef(&EF_KEYS_PS),
    // -- standard --
    FileRef::Ef(&EF_LI),
    FileRef::Ef(&EF_MSISDN),
    FileRef::Ef(&EF_SMSP),
    FileRef::Ef(&EF_FDN),
    FileRef::Ef(&EF_SPN),
    FileRef::Ef(&EF_CBMI),
    FileRef::Ef(&EF_CBMID),
    FileRef::Ef(&EF_CBMIR),
    FileRef::Ef(&EF_SMS),
    FileRef::Ef(&EF_SMSS),
    FileRef::Ef(&EF_SMSR),
    FileRef::Ef(&EF_ECC),
    FileRef::Ef(&EF_PLMNWACT),
    FileRef::Ef(&EF_OPLMNWACT),
    FileRef::Ef(&EF_HPLMNWACT),
    FileRef::Ef(&EF_EHPLMN),
    FileRef::Ef(&EF_PNN),
    FileRef::Ef(&EF_OPL),
    FileRef::Ef(&EF_GID1),
    FileRef::Ef(&EF_GID2),
    FileRef::Ef(&EF_SPDI),
    FileRef::Ef(&EF_ACL),
    FileRef::Ef(&EF_EST),
    FileRef::Ef(&EF_EPSLOCI),
    FileRef::Ef(&EF_EPSNSC),
    // -- full --
    FileRef::Ef(&EF_DCK),
    FileRef::Ef(&EF_CNL),
    FileRef::Ef(&EF_ACMMAX),
    FileRef::Ef(&EF_ACM),
    FileRef::Ef(&EF_PUCT),
    FileRef::Ef(&EF_SDN),
    FileRef::Ef(&EF_EXT2),
    FileRef::Ef(&EF_EXT3),
    FileRef::Ef(&EF_BDN),
    FileRef::Ef(&EF_EXT5),
    FileRef::Ef(&EF_CCP2),
    FileRef::Ef(&EF_CMI),
    FileRef::Ef(&EF_START_HFN),
    FileRef::Ef(&EF_THRESHOLD),
    FileRef::Ef(&EF_ICI),
    FileRef::Ef(&EF_OCI),
    FileRef::Ef(&EF_ICT),
    FileRef::Ef(&EF_OCT),
    FileRef::Ef(&EF_VGCS),
    FileRef::Ef(&EF_VGCSS),
    FileRef::Ef(&EF_VBS),
    FileRef::Ef(&EF_VBSS),
    FileRef::Ef(&EF_EMLPP),
    FileRef::Ef(&EF_AAEM),
    FileRef::Ef(&EF_NETPAR),
    FileRef::Ef(&EF_MBDN),
    FileRef::Ef(&EF_EXT6),
    FileRef::Ef(&EF_MBI),
    FileRef::Ef(&EF_MWIS),
    FileRef::Ef(&EF_CFIS),
    FileRef::Ef(&EF_EXT7),
    FileRef::Ef(&EF_MMSN),
    FileRef::Ef(&EF_EXT8),
    FileRef::Ef(&EF_MMSICP),
    FileRef::Ef(&EF_MMSUP),
    FileRef::Ef(&EF_MMSUCP),
    FileRef::Ef(&EF_NIA),
    FileRef::Ef(&EF_VGCSCA),
    FileRef::Ef(&EF_GBABP),
    FileRef::Ef(&EF_MSK),
    FileRef::Ef(&EF_MUK),
    FileRef::Ef(&EF_GBANL),
    FileRef::Ef(&EF_EHPLMNPI),
    FileRef::Ef(&EF_NAFKCA),
    FileRef::Ef(&EF_SPNI),
    FileRef::Ef(&EF_PNNI),
    FileRef::Ef(&EF_NCP_IP),
    FileRef::Ef(&EF_UFC),
    FileRef::Ef(&EF_NASCONFIG),
    FileRef::Ef(&EF_PWS),
    FileRef::Ef(&EF_FDNURI),
    FileRef::Ef(&EF_BDNURI),
    FileRef::Ef(&EF_SDNURI),
    FileRef::Ef(&EF_IPS),
    FileRef::Ef(&EF_FROM_PREFERRED),
    // -- sub-DFs --
    FileRef::Df(&DF_5GS),
    FileRef::Df(&DF_GSM_ACCESS),
];

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    // -- minimal --
    0x6F07, // EF_IMSI
    0x6FAD, // EF_AD
    0x6F38, // EF_UST
    0x6F78, // EF_ACC
    0x6F7E, // EF_LOCI
    0x6FE7, // EF_PSLOCI
    0x6F7B, // EF_FPLMN
    0x6F31, // EF_HPPLMN
    0x6F08, // EF_KEYS
    0x6F09, // EF_KEYS_PS
    // -- standard --
    0x6F05, // EF_LI
    0x6F40, // EF_MSISDN
    0x6F42, // EF_SMSP
    0x6F3B, // EF_FDN
    0x6F46, // EF_SPN
    0x6F45, // EF_CBMI
    0x6F48, // EF_CBMID
    0x6F50, // EF_CBMIR
    0x6F3C, // EF_SMS
    0x6F43, // EF_SMSS
    0x6F47, // EF_SMSR
    0x6FB7, // EF_ECC
    0x6F60, // EF_PLMNWACT
    0x6F61, // EF_OPLMNWACT
    0x6F62, // EF_HPLMNWACT
    0x6FD9, // EF_EHPLMN
    0x6FC5, // EF_PNN
    0x6FC6, // EF_OPL
    0x6F3E, // EF_GID1
    0x6F3F, // EF_GID2
    0x6FCD, // EF_SPDI
    0x6F57, // EF_ACL
    0x6F56, // EF_EST
    0x6FE3, // EF_EPSLOCI
    0x6FE4, // EF_EPSNSC
    // -- full --
    0x6F2C, // EF_DCK
    0x6F32, // EF_CNL
    0x6F37, // EF_ACMMAX
    0x6F39, // EF_ACM
    0x6F41, // EF_PUCT
    0x6F49, // EF_SDN
    0x6F4B, // EF_EXT2
    0x6F4C, // EF_EXT3
    0x6F4D, // EF_BDN
    0x6F4E, // EF_EXT5
    0x6F4F, // EF_CCP2
    0x6F58, // EF_CMI
    0x6F5B, // EF_START_HFN
    0x6F5C, // EF_THRESHOLD
    0x6F80, // EF_ICI
    0x6F81, // EF_OCI
    0x6F82, // EF_ICT
    0x6F83, // EF_OCT
    0x6FB1, // EF_VGCS
    0x6FB2, // EF_VGCSS
    0x6FB3, // EF_VBS
    0x6FB4, // EF_VBSS
    0x6FB5, // EF_EMLPP
    0x6FB6, // EF_AAEM
    0x6FC4, // EF_NETPAR
    0x6FC7, // EF_MBDN
    0x6FC8, // EF_EXT6
    0x6FC9, // EF_MBI
    0x6FCA, // EF_MWIS
    0x6FCB, // EF_CFIS
    0x6FCC, // EF_EXT7
    0x6FCE, // EF_MMSN
    0x6FCF, // EF_EXT8
    0x6FD0, // EF_MMSICP
    0x6FD1, // EF_MMSUP
    0x6FD2, // EF_MMSUCP
    0x6FD3, // EF_NIA
    0x6FD4, // EF_VGCSCA
    0x6FD6, // EF_GBABP
    0x6FD7, // EF_MSK
    0x6FD8, // EF_MUK
    0x6FDA, // EF_GBANL
    0x6FDB, // EF_EHPLMNPI
    0x6FDD, // EF_NAFKCA
    0x6FDE, // EF_SPNI
    0x6FDF, // EF_PNNI
    0x6FE2, // EF_NCP_IP
    0x6FE6, // EF_UFC
    0x6FE8, // EF_NASCONFIG
    0x6FEC, // EF_PWS
    0x6FED, // EF_FDNURI
    0x6FEE, // EF_BDNURI
    0x6FEF, // EF_SDNURI
    0x6FF1, // EF_IPS
    0x6FF7, // EF_FROM_PREFERRED
    // -- sub-DFs --
    0x5FC0, // DF_5GS
    0x5F3B, // DF_GSM_ACCESS
]);

// -- profile-standard children (no profile-full): minimal + standard EFs --
#[cfg(all(feature = "profile-standard", not(feature = "profile-full")))]
static ADF_USIM_CHILDREN: [FileRef; 36] = [
    // -- minimal --
    FileRef::Ef(&EF_IMSI),
    FileRef::Ef(&EF_AD),
    FileRef::Ef(&EF_UST),
    FileRef::Ef(&EF_ACC),
    FileRef::Ef(&EF_LOCI),
    FileRef::Ef(&EF_PSLOCI),
    FileRef::Ef(&EF_FPLMN),
    FileRef::Ef(&EF_HPPLMN),
    FileRef::Ef(&EF_KEYS),
    FileRef::Ef(&EF_KEYS_PS),
    // -- standard --
    FileRef::Ef(&EF_LI),
    FileRef::Ef(&EF_MSISDN),
    FileRef::Ef(&EF_SMSP),
    FileRef::Ef(&EF_FDN),
    FileRef::Ef(&EF_SPN),
    FileRef::Ef(&EF_CBMI),
    FileRef::Ef(&EF_CBMID),
    FileRef::Ef(&EF_CBMIR),
    FileRef::Ef(&EF_SMS),
    FileRef::Ef(&EF_SMSS),
    FileRef::Ef(&EF_SMSR),
    FileRef::Ef(&EF_ECC),
    FileRef::Ef(&EF_PLMNWACT),
    FileRef::Ef(&EF_OPLMNWACT),
    FileRef::Ef(&EF_HPLMNWACT),
    FileRef::Ef(&EF_EHPLMN),
    FileRef::Ef(&EF_PNN),
    FileRef::Ef(&EF_OPL),
    FileRef::Ef(&EF_GID1),
    FileRef::Ef(&EF_GID2),
    FileRef::Ef(&EF_SPDI),
    FileRef::Ef(&EF_ACL),
    FileRef::Ef(&EF_EST),
    FileRef::Ef(&EF_EPSLOCI),
    FileRef::Ef(&EF_EPSNSC),
    // -- sub-DFs --
    FileRef::Df(&DF_5GS),
];

#[cfg(all(feature = "profile-standard", not(feature = "profile-full")))]
const _: () = simrs_fs::assert_fids_unique(&[
    // -- minimal --
    0x6F07, // EF_IMSI
    0x6FAD, // EF_AD
    0x6F38, // EF_UST
    0x6F78, // EF_ACC
    0x6F7E, // EF_LOCI
    0x6FE7, // EF_PSLOCI
    0x6F7B, // EF_FPLMN
    0x6F31, // EF_HPPLMN
    0x6F08, // EF_KEYS
    0x6F09, // EF_KEYS_PS
    // -- standard --
    0x6F05, // EF_LI
    0x6F40, // EF_MSISDN
    0x6F42, // EF_SMSP
    0x6F3B, // EF_FDN
    0x6F46, // EF_SPN
    0x6F45, // EF_CBMI
    0x6F48, // EF_CBMID
    0x6F50, // EF_CBMIR
    0x6F3C, // EF_SMS
    0x6F43, // EF_SMSS
    0x6F47, // EF_SMSR
    0x6FB7, // EF_ECC
    0x6F60, // EF_PLMNWACT
    0x6F61, // EF_OPLMNWACT
    0x6F62, // EF_HPLMNWACT
    0x6FD9, // EF_EHPLMN
    0x6FC5, // EF_PNN
    0x6FC6, // EF_OPL
    0x6F3E, // EF_GID1
    0x6F3F, // EF_GID2
    0x6FCD, // EF_SPDI
    0x6F57, // EF_ACL
    0x6F56, // EF_EST
    0x6FE3, // EF_EPSLOCI
    0x6FE4, // EF_EPSNSC
    // -- sub-DFs --
    0x5FC0, // DF_5GS
]);

// -- profile-minimal children (no standard/full): minimal EFs only --------
// Also the fallback when no profile feature is enabled (default-features = false).
#[cfg(not(any(feature = "profile-standard", feature = "profile-full")))]
static ADF_USIM_CHILDREN: [FileRef; 11] = [
    FileRef::Ef(&EF_IMSI),
    FileRef::Ef(&EF_AD),
    FileRef::Ef(&EF_UST),
    FileRef::Ef(&EF_ACC),
    FileRef::Ef(&EF_LOCI),
    FileRef::Ef(&EF_PSLOCI),
    FileRef::Ef(&EF_FPLMN),
    FileRef::Ef(&EF_HPPLMN),
    FileRef::Ef(&EF_KEYS),
    FileRef::Ef(&EF_KEYS_PS),
    FileRef::Df(&DF_5GS),
];

#[cfg(not(any(feature = "profile-standard", feature = "profile-full")))]
const _: () = simrs_fs::assert_fids_unique(&[
    0x6F07, // EF_IMSI
    0x6FAD, // EF_AD
    0x6F38, // EF_UST
    0x6F78, // EF_ACC
    0x6F7E, // EF_LOCI
    0x6FE7, // EF_PSLOCI
    0x6F7B, // EF_FPLMN
    0x6F31, // EF_HPPLMN
    0x6F08, // EF_KEYS
    0x6F09, // EF_KEYS_PS
    0x5FC0, // DF_5GS
]);

/// Standard USIM AID: A0000000871002 (per 3GPP TS 31.102).
pub static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

// ---------------------------------------------------------------------------
// ISIM ADF -- TS 31.103
// ---------------------------------------------------------------------------

/// Standard ISIM AID: A0000000871004 (per 3GPP TS 31.103).
#[cfg(feature = "isim")]
pub static ISIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04];

/// EF.IMPI (6F02) under ADF.ISIM -- IMS Private User Identity.
///
/// 64-byte transparent EF. Default: empty.
/// TS 31.103 clause 4.2.2.
#[cfg(feature = "isim")]
pub static ISIM_EF_IMPI: EfDef = EfDef::transparent(
    Fid::new(0x6F02),
    None,
    &[0xFF; 64],
);

/// EF.DOMAIN (6F03) under ADF.ISIM -- Home Network Domain Name.
///
/// 64-byte transparent EF. Default: empty.
/// TS 31.103 clause 4.2.3.
#[cfg(feature = "isim")]
pub static ISIM_EF_DOMAIN: EfDef = EfDef::transparent(
    Fid::new(0x6F03),
    None,
    &[0xFF; 64],
);

/// EF.IMPU (6F04) under ADF.ISIM -- IMS Public User Identity.
///
/// Linear-fixed, 2 records of 64 bytes. Default: empty.
/// TS 31.103 clause 4.2.4.
#[cfg(feature = "isim")]
pub static ISIM_EF_IMPU: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F04),
    None,
    64, 2,
    &[0xFF; 128],
);

/// EF.ARR (6F06) under ADF.ISIM -- Access Rule Reference.
///
/// Linear-fixed, 2 records of 32 bytes. Default: empty.
/// ETSI TS 102 221.
#[cfg(feature = "isim")]
pub static ISIM_EF_ARR: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F06),
    None,
    32, 2,
    &[0xFF; 64],
);

/// EF.IST (6F07) under ADF.ISIM -- ISIM Service Table.
///
/// 4-byte transparent EF. Default: empty.
/// TS 31.103 clause 4.2.7.
#[cfg(feature = "isim")]
pub static ISIM_EF_IST: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0xFF; 4],
);

/// EF.P-CSCF (6F09) under ADF.ISIM -- P-CSCF Address.
///
/// 64-byte transparent EF. Default: empty.
/// TS 31.103 clause 4.2.8.
#[cfg(feature = "isim")]
pub static ISIM_EF_PCSCF: EfDef = EfDef::transparent(
    Fid::new(0x6F09),
    None,
    &[0xFF; 64],
);

/// EF.GBABP (6F3A) under ADF.ISIM -- GBA Bootstrapping Parameters.
///
/// 64-byte transparent EF. Default: empty.
/// TS 31.103 clause 4.2.9.
#[cfg(feature = "isim")]
pub static ISIM_EF_GBABP: EfDef = EfDef::transparent(
    Fid::new(0x6F3A),
    None,
    &[0xFF; 64],
);

/// EF.GBANL (6F3B) under ADF.ISIM -- GBA NAF List.
///
/// Linear-fixed, 1 record of 4 bytes. Default: empty.
/// TS 31.103 clause 4.2.10.
#[cfg(feature = "isim")]
pub static ISIM_EF_GBANL: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3B),
    None,
    4, 1,
    &[0xFF; 4],
);

/// EF.NAFKCA (6F3C) under ADF.ISIM -- NAF Key Centre Address.
///
/// Linear-fixed, 1 record of 32 bytes. Default: empty.
/// TS 31.103 clause 4.2.11.
#[cfg(feature = "isim")]
pub static ISIM_EF_NAFKCA: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3C),
    None,
    32, 1,
    &[0xFF; 32],
);

/// EF.AD (6FAD) under ADF.ISIM -- Administrative Data.
///
/// 4-byte transparent EF. Default: normal operation.
/// TS 31.103 clause 4.2.6.
#[cfg(feature = "isim")]
pub static ISIM_EF_AD: EfDef = EfDef::transparent(
    Fid::new(0x6FAD),
    None,
    &[0xFF; 4],
);

/// ADF.ISIM root DF.
///
/// Contains 10 EFs per 3GPP TS 31.103.
#[cfg(feature = "isim")]
pub static ADF_ISIM_ROOT: DfDef = DfDef {
    fid: Fid::new(0xFF02),
    children: &[
        FileRef::Ef(&ISIM_EF_IMPI),
        FileRef::Ef(&ISIM_EF_DOMAIN),
        FileRef::Ef(&ISIM_EF_IMPU),
        FileRef::Ef(&ISIM_EF_ARR),
        FileRef::Ef(&ISIM_EF_IST),
        FileRef::Ef(&ISIM_EF_PCSCF),
        FileRef::Ef(&ISIM_EF_GBABP),
        FileRef::Ef(&ISIM_EF_GBANL),
        FileRef::Ef(&ISIM_EF_NAFKCA),
        FileRef::Ef(&ISIM_EF_AD),
    ],
};

#[cfg(feature = "isim")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x6F02, // ISIM_EF_IMPI
    0x6F03, // ISIM_EF_DOMAIN
    0x6F04, // ISIM_EF_IMPU
    0x6F06, // ISIM_EF_ARR
    0x6F07, // ISIM_EF_IST
    0x6F09, // ISIM_EF_PCSCF
    0x6F3A, // ISIM_EF_GBABP
    0x6F3B, // ISIM_EF_GBANL
    0x6F3C, // ISIM_EF_NAFKCA
    0x6FAD, // ISIM_EF_AD
]);

// ---------------------------------------------------------------------------
// HPSIM ADF -- TS 31.104
// ---------------------------------------------------------------------------

/// Standard HPSIM AID: A000000087100A (per 3GPP TS 31.104).
#[cfg(feature = "hpsim")]
pub static HPSIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x0A];

/// EF.ARR (6F06) under ADF.HPSIM -- Access Rule Reference.
///
/// Linear-fixed, 1 record of 8 bytes. Default: empty.
/// ETSI TS 102 221.
#[cfg(feature = "hpsim")]
pub static HPSIM_EF_ARR: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F06),
    None,
    8, 1,
    &[0xFF; 8],
);

/// EF.HPST (6F07) under ADF.HPSIM -- HPSIM Service Table.
///
/// 2-byte transparent EF. Default: empty.
/// TS 31.104 clause 4.2.2.
#[cfg(feature = "hpsim")]
pub static HPSIM_EF_HPST: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0xFF; 2],
);

/// EF.AD (6FAD) under ADF.HPSIM -- Administrative Data.
///
/// 4-byte transparent EF. Default: empty.
/// TS 31.104 clause 4.2.3.
#[cfg(feature = "hpsim")]
pub static HPSIM_EF_AD: EfDef = EfDef::transparent(
    Fid::new(0x6FAD),
    None,
    &[0xFF; 4],
);

/// ADF.HPSIM root DF.
///
/// Contains 3 EFs per 3GPP TS 31.104.
#[cfg(feature = "hpsim")]
pub static ADF_HPSIM_ROOT: DfDef = DfDef {
    fid: Fid::new(0xFF03),
    children: &[
        FileRef::Ef(&HPSIM_EF_ARR),
        FileRef::Ef(&HPSIM_EF_HPST),
        FileRef::Ef(&HPSIM_EF_AD),
    ],
};

#[cfg(feature = "hpsim")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x6F06, // HPSIM_EF_ARR
    0x6F07, // HPSIM_EF_HPST
    0x6FAD, // HPSIM_EF_AD
]);

// ---------------------------------------------------------------------------
// ADF table -- conditional on isim/hpsim features
// ---------------------------------------------------------------------------

/// ADF table: USIM only (no ISIM, no HPSIM).
#[cfg(all(not(feature = "isim"), not(feature = "hpsim")))]
pub static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
    aid: &USIM_AID,
    root: &ADF_USIM_ROOT,
}];

/// ADF table: USIM + ISIM (no HPSIM).
#[cfg(all(feature = "isim", not(feature = "hpsim")))]
pub static ADF_TABLE: [AdfSlot; 2] = [
    AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_ROOT,
    },
    AdfSlot {
        aid: &ISIM_AID,
        root: &ADF_ISIM_ROOT,
    },
];

/// ADF table: USIM + HPSIM (no ISIM).
#[cfg(all(not(feature = "isim"), feature = "hpsim"))]
pub static ADF_TABLE: [AdfSlot; 2] = [
    AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_ROOT,
    },
    AdfSlot {
        aid: &HPSIM_AID,
        root: &ADF_HPSIM_ROOT,
    },
];

/// ADF table: USIM + ISIM + HPSIM.
#[cfg(all(feature = "isim", feature = "hpsim"))]
pub static ADF_TABLE: [AdfSlot; 3] = [
    AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_ROOT,
    },
    AdfSlot {
        aid: &ISIM_AID,
        root: &ADF_ISIM_ROOT,
    },
    AdfSlot {
        aid: &HPSIM_AID,
        root: &ADF_HPSIM_ROOT,
    },
];

// ---------------------------------------------------------------------------
// EFs under DF.TELECOM (7F10) -- ETSI TS 102 221 clause 13
// ---------------------------------------------------------------------------

/// EF.ADN (6F3A) under DF.TELECOM -- Abbreviated Dialling Numbers.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.1.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_ADN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3A),
    None,
    30, 2,
    &[0xFF; 60],
);

/// EF.FDN (6F3B) under DF.TELECOM -- Fixed Dialling Numbers.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.2.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_FDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3B),
    None,
    30, 2,
    &[0xFF; 60],
);

/// EF.SMS (6F3C) under DF.TELECOM -- Short Messages.
///
/// Linear-fixed, 2 records of 176 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.3.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_SMS: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3C),
    None,
    176, 2,
    &[0xFF; 352],
);

/// EF.CCP (6F3D) under DF.TELECOM -- Capability Configuration Parameters.
///
/// Linear-fixed, 3 records of 14 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.4.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_CCP: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3D),
    None,
    14, 3,
    &[0xFF; 42],
);

/// EF.MSISDN (6F40) under DF.TELECOM -- MSISDN.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.5.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_MSISDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F40),
    None,
    30, 2,
    &[0xFF; 60],
);

/// EF.SMSP (6F42) under DF.TELECOM -- Short Message Service Parameters.
///
/// Linear-fixed, 2 records of 44 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.6.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_SMSP: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F42),
    None,
    44, 2,
    &[0xFF; 88],
);

/// EF.SMSS (6F43) under DF.TELECOM -- SMS Status.
///
/// 2-byte transparent EF. Default: empty.
/// ETSI TS 102 221 clause 13.4.7.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_SMSS: EfDef = EfDef::transparent(
    Fid::new(0x6F43),
    None,
    &[0xFF; 2],
);

/// EF.LND (6F44) under DF.TELECOM -- Last Number Dialled.
///
/// Cyclic, 3 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.8.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_LND: EfDef = EfDef::cyclic(
    Fid::new(0x6F44),
    None,
    30, 3,
    &[0xFF; 90],
);

/// EF.SMSR (6F47) under DF.TELECOM -- Short Message Status Reports.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.9.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_SMSR: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F47),
    None,
    30, 2,
    &[0xFF; 60],
);

/// EF.SDN (6F49) under DF.TELECOM -- Service Dialling Numbers.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.10.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_SDN: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F49),
    None,
    30, 2,
    &[0xFF; 60],
);

/// EF.EXT1 (6F4A) under DF.TELECOM -- Extension 1.
///
/// Linear-fixed, 2 records of 13 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.11.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_EXT1: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4A),
    None,
    13, 2,
    &[0xFF; 26],
);

/// EF.EXT2 (6F4B) under DF.TELECOM -- Extension 2.
///
/// Linear-fixed, 2 records of 13 bytes. Default: empty.
/// ETSI TS 102 221 clause 13.4.12.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_EXT2: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4B),
    None,
    13, 2,
    &[0xFF; 26],
);

/// DF.TELECOM (7F10) -- Telecom DF.
///
/// When the `telecom` feature is enabled, populated with 12 EFs per
/// ETSI TS 102 221 clause 13.
#[cfg(feature = "telecom")]
pub static DF_TELECOM: DfDef = DfDef {
    fid: Fid::new(0x7F10),
    children: &[
        FileRef::Ef(&TELECOM_EF_ADN),
        FileRef::Ef(&TELECOM_EF_FDN),
        FileRef::Ef(&TELECOM_EF_SMS),
        FileRef::Ef(&TELECOM_EF_CCP),
        FileRef::Ef(&TELECOM_EF_MSISDN),
        FileRef::Ef(&TELECOM_EF_SMSP),
        FileRef::Ef(&TELECOM_EF_SMSS),
        FileRef::Ef(&TELECOM_EF_LND),
        FileRef::Ef(&TELECOM_EF_SMSR),
        FileRef::Ef(&TELECOM_EF_SDN),
        FileRef::Ef(&TELECOM_EF_EXT1),
        FileRef::Ef(&TELECOM_EF_EXT2),
    ],
};

#[cfg(feature = "telecom")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x6F3A, // TELECOM_EF_ADN
    0x6F3B, // TELECOM_EF_FDN
    0x6F3C, // TELECOM_EF_SMS
    0x6F3D, // TELECOM_EF_CCP
    0x6F40, // TELECOM_EF_MSISDN
    0x6F42, // TELECOM_EF_SMSP
    0x6F43, // TELECOM_EF_SMSS
    0x6F44, // TELECOM_EF_LND
    0x6F47, // TELECOM_EF_SMSR
    0x6F49, // TELECOM_EF_SDN
    0x6F4A, // TELECOM_EF_EXT1
    0x6F4B, // TELECOM_EF_EXT2
]);

/// DF.TELECOM (7F10) -- Telecom DF.
///
/// Empty when the `telecom` feature is not enabled.
#[cfg(not(feature = "telecom"))]
pub static DF_TELECOM: DfDef = DfDef {
    fid: Fid::new(0x7F10),
    children: &[],
};

/// EF.PL (2F05) -- Preferred Languages.
///
/// 10-byte transparent EF under MF. Default: empty.
/// ETSI TS 102 221 clause 13.3.
pub static EF_PL: EfDef = EfDef::transparent(
    Fid::new(0x2F05),
    None,
    &[0xFF; 10],
);

/// Reference Master File (MF).
///
/// Contains EF.ICCID, EF.DIR, EF.ARR, EF.PL, and DF.TELECOM.
pub static REFERENCE_MF: DfDef = DfDef {
    fid: Fid::MF,
    children: &[
        FileRef::Ef(&EF_ICCID),
        FileRef::Ef(&EF_DIR),
        FileRef::Ef(&EF_ARR),
        FileRef::Ef(&EF_PL),
        FileRef::Df(&DF_TELECOM),
    ],
};

const _: () = simrs_fs::assert_fids_unique(&[
    0x2FE2, // EF_ICCID
    0x2F00, // EF_DIR
    0x2F06, // EF_ARR
    0x2F05, // EF_PL
    0x7F10, // DF_TELECOM
]);

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
                ef.fid() == Fid::new(0x2FE2)
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
                ef.fid() == Fid::new(0x6F07)
            } else {
                false
            }
        });
        assert!(has_imsi, "ADF.USIM must contain EF.IMSI (6F07)");
    }

    #[test]
    fn profile_ef_dir_is_linear_fixed() {
        assert!(
            matches!(EF_DIR.structure(), EfStructure::LinearFixed { .. }),
            "EF.DIR must be linear-fixed"
        );
    }

    #[test]
    fn profile_fids_unique() {
        // Collect all FIDs from MF children and ADF.USIM children.
        let mut fids: [u16; 16] = [0xFFFF; 16];

        for (idx, child) in REFERENCE_MF.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid().value(),
                FileRef::Df(df) => df.fid.value(),
            };
            // Check for duplicates within MF.
            for f in &fids[..idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under MF");
            }
            fids[idx] = fid;
        }

        // Reset for ADF.USIM scope.
        let mut adf_fids: [u16; 128] = [0xFFFF; 128];

        for (adf_idx, child) in ADF_USIM_ROOT.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid().value(),
                FileRef::Df(df) => df.fid.value(),
            };
            for f in &adf_fids[..adf_idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under ADF.USIM");
            }
            adf_fids[adf_idx] = fid;
        }
    }

    #[test]
    fn profile_adf_usim_has_keys() {
        let has_keys = ADF_USIM_ROOT.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid() == Fid::new(0x6F08)
            } else {
                false
            }
        });
        assert!(has_keys, "ADF.USIM must contain EF.Keys (6F08)");

        let has_keys_ps = ADF_USIM_ROOT.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid() == Fid::new(0x6F09)
            } else {
                false
            }
        });
        assert!(has_keys_ps, "ADF.USIM must contain EF.KeysPS (6F09)");
    }

    #[test]
    fn ef_keys_data_valid() {
        assert_eq!(EF_KEYS.data().len(), 33, "EF.Keys must be 33 bytes");
        assert_eq!(EF_KEYS.data()[0], 0x07, "KSI must be 7 (no key)");
        assert_eq!(EF_KEYS_PS.data().len(), 33, "EF.KeysPS must be 33 bytes");
        assert_eq!(EF_KEYS_PS.data()[0], 0x07, "KSI must be 7 (no key)");
    }

    /// Verify data length matches record_size * num_records for all record-based EFs
    /// in the ADF.USIM tree (including sub-DFs).
    #[test]
    fn all_record_ef_data_sizes_consistent() {
        fn check_children(children: &[FileRef]) {
            for child in children {
                match child {
                    FileRef::Ef(ef) => {
                        let expected = match ef.structure() {
                            EfStructure::LinearFixed { record_size, num_records }
                            | EfStructure::Cyclic { record_size, num_records } => {
                                Some(record_size as usize * num_records as usize)
                            }
                            _ => None,
                        };
                        if let Some(exp) = expected {
                            assert_eq!(
                                ef.data().len(), exp,
                                "EF {:#06X}: data.len()={} != record_size*num_records={}",
                                ef.fid().value(), ef.data().len(), exp,
                            );
                        }
                    }
                    FileRef::Df(df) => {
                        check_children(df.children);
                    }
                }
            }
        }
        check_children(ADF_USIM_ROOT.children);
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
            Fid::new(0x5FC0),
            "DF_5GS must have FID 0x5FC0"
        );
    }

    #[test]
    fn df_5gs_fids_unique() {
        let mut fids: [u16; 17] = [0xFFFF; 17];
        for (idx, child) in DF_5GS.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid().value(),
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
                df.fid == Fid::new(0x5FC0)
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
                    ef.fid().value() == *fid
                } else {
                    false
                }
            });
            let Some(FileRef::Ef(ef)) = child else {
                panic!("EF {fid:#06X} not found in DF_5GS")
            };
            assert_eq!(
                ef.data().len(),
                *exp_len,
                "EF {fid:#06X} data length mismatch: got {}, expected {exp_len}",
                ef.data().len()
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
                    ef.fid().value() == *fid
                } else {
                    false
                }
            });
            let Some(FileRef::Ef(ef)) = child else {
                panic!("EF {fid:#06X} not found in DF_5GS")
            };
            match ef.structure() {
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
        let ust = EF_UST.data();
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

    // -----------------------------------------------------------------------
    // Structural (BDD-style) tests -- Phase 7
    // -----------------------------------------------------------------------

    /// Helper: check FID uniqueness among direct children of a DF.
    fn assert_fids_unique(df: &DfDef, label: &str) {
        let mut seen: [u16; 128] = [0xFFFF; 128];
        for (idx, child) in df.children.iter().enumerate() {
            let fid = match child {
                FileRef::Ef(ef) => ef.fid().value(),
                FileRef::Df(sub) => sub.fid.value(),
            };
            for f in &seen[..idx] {
                assert_ne!(*f, fid, "duplicate FID {fid:#06X} under {label}");
            }
            seen[idx] = fid;
        }
    }

    /// Helper: check record EF data size consistency for all children of a DF.
    #[allow(dead_code)] // used only by feature-gated tests (telecom, isim, hpsim, profile-full)
    fn assert_record_sizes_consistent(df: &DfDef, label: &str) {
        for child in df.children {
            if let FileRef::Ef(ef) = child {
                let expected = match ef.structure() {
                    EfStructure::LinearFixed { record_size, num_records }
                    | EfStructure::Cyclic { record_size, num_records } => {
                        Some(record_size as usize * num_records as usize)
                    }
                    _ => None,
                };
                if let Some(exp) = expected {
                    assert_eq!(
                        ef.data().len(), exp,
                        "{label} EF {:#06X}: data.len()={} != record_size*num_records={}",
                        ef.fid().value(), ef.data().len(), exp,
                    );
                }
            }
        }
    }

    /// MF children have unique FIDs (expanded: checks all MF children including
    /// DF_TELECOM and EF.PL that were added in later phases).
    #[test]
    fn mf_children_fids_unique_exhaustive() {
        assert!(REFERENCE_MF.children.len() >= 4,
            "MF must have at least 4 children, got {}", REFERENCE_MF.children.len());
        assert_fids_unique(&REFERENCE_MF, "MF");
    }

    /// DF_TELECOM FIDs are unique among its children.
    #[cfg(feature = "telecom")]
    #[test]
    fn df_telecom_fids_unique() {
        assert_eq!(DF_TELECOM.children.len(), 12,
            "DF_TELECOM must have 12 children when telecom enabled");
        assert_fids_unique(&DF_TELECOM, "DF_TELECOM");
    }

    /// All record EF data sizes consistent in DF_TELECOM.
    #[cfg(feature = "telecom")]
    #[test]
    fn telecom_record_ef_data_sizes_consistent() {
        assert_record_sizes_consistent(&DF_TELECOM, "DF_TELECOM");
    }

    /// ADF.ISIM FIDs unique among its children.
    #[cfg(feature = "isim")]
    #[test]
    fn adf_isim_fids_unique() {
        assert_eq!(ADF_ISIM_ROOT.children.len(), 10, "ADF.ISIM must have 10 children");
        assert_fids_unique(&ADF_ISIM_ROOT, "ADF.ISIM");
    }

    /// All record EF data sizes consistent in ADF.ISIM.
    #[cfg(feature = "isim")]
    #[test]
    fn isim_record_ef_data_sizes_consistent() {
        assert_record_sizes_consistent(&ADF_ISIM_ROOT, "ADF.ISIM");
    }

    /// ADF.HPSIM FIDs unique among its children.
    #[cfg(feature = "hpsim")]
    #[test]
    fn adf_hpsim_fids_unique() {
        assert_eq!(ADF_HPSIM_ROOT.children.len(), 3, "ADF.HPSIM must have 3 children");
        assert_fids_unique(&ADF_HPSIM_ROOT, "ADF.HPSIM");
    }

    /// All record EF data sizes consistent in ADF.HPSIM.
    #[cfg(feature = "hpsim")]
    #[test]
    fn hpsim_record_ef_data_sizes_consistent() {
        assert_record_sizes_consistent(&ADF_HPSIM_ROOT, "ADF.HPSIM");
    }

    /// DF.GSM-ACCESS FIDs unique.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_gsm_access_fids_unique() {
        assert_eq!(DF_GSM_ACCESS.children.len(), 2, "DF.GSM-ACCESS must have 2 children");
        assert_fids_unique(&DF_GSM_ACCESS, "DF.GSM-ACCESS");
    }

    /// DF.GSM-ACCESS record EF sizes consistent.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_gsm_access_record_sizes_consistent() {
        assert_record_sizes_consistent(&DF_GSM_ACCESS, "DF.GSM-ACCESS");
    }

    /// SFI values are unique within ADF.USIM direct children and in range 1-30.
    #[test]
    fn sfi_values_unique_and_in_range() {
        let mut sfis: [u8; 32] = [0xFF; 32];
        let mut count = 0;
        for child in ADF_USIM_ROOT.children {
            if let FileRef::Ef(ef) = child {
                if let Some(sfi) = ef.sfi() {
                    let val = sfi.value();
                    assert!((1..=30).contains(&val),
                        "EF {:#06X} SFI {} is outside range 1..=30",
                        ef.fid().value(), val);
                    for s in &sfis[..count] {
                        assert_ne!(*s, val,
                            "EF {:#06X} has duplicate SFI {} already used by another EF",
                            ef.fid().value(), val);
                    }
                    sfis[count] = val;
                    count += 1;
                }
            }
        }
        // At minimum, IMSI(7), Keys(8), KeysPS(9) should have SFIs
        assert!(count >= 3, "Expected at least 3 SFIs, got {count}");
    }

    /// SFI values are unique within MF direct children.
    #[test]
    fn mf_sfi_values_unique_and_in_range() {
        let mut sfis: [u8; 16] = [0xFF; 16];
        let mut count = 0;
        for child in REFERENCE_MF.children {
            if let FileRef::Ef(ef) = child {
                if let Some(sfi) = ef.sfi() {
                    let val = sfi.value();
                    assert!((1..=30).contains(&val),
                        "MF EF {:#06X} SFI {} is outside range 1..=30",
                        ef.fid().value(), val);
                    for s in &sfis[..count] {
                        assert_ne!(*s, val,
                            "MF EF {:#06X} has duplicate SFI {}", ef.fid().value(), val);
                    }
                    sfis[count] = val;
                    count += 1;
                }
            }
        }
    }

    /// AID bytes have correct length (7 bytes for 3GPP AIDs) and match standards.
    #[test]
    fn aid_bytes_correct() {
        assert_eq!(USIM_AID.len(), 7, "USIM AID must be 7 bytes");
        assert_eq!(&USIM_AID[..5], &[0xA0, 0x00, 0x00, 0x00, 0x87],
            "USIM AID must start with 3GPP RID A0000000 87");
        assert_eq!(&USIM_AID[5..], &[0x10, 0x02],
            "USIM AID PIX must be 1002");
    }

    /// ISIM AID is correct per TS 31.103.
    #[cfg(feature = "isim")]
    #[test]
    fn isim_aid_bytes_correct() {
        assert_eq!(ISIM_AID.len(), 7, "ISIM AID must be 7 bytes");
        assert_eq!(&ISIM_AID[..5], &[0xA0, 0x00, 0x00, 0x00, 0x87],
            "ISIM AID must start with 3GPP RID A0000000 87");
        assert_eq!(&ISIM_AID[5..], &[0x10, 0x04],
            "ISIM AID PIX must be 1004");
    }

    /// HPSIM AID is correct per TS 31.104.
    #[cfg(feature = "hpsim")]
    #[test]
    fn hpsim_aid_bytes_correct() {
        assert_eq!(HPSIM_AID.len(), 7, "HPSIM AID must be 7 bytes");
        assert_eq!(&HPSIM_AID[..5], &[0xA0, 0x00, 0x00, 0x00, 0x87],
            "HPSIM AID must start with 3GPP RID A0000000 87");
        assert_eq!(&HPSIM_AID[5..], &[0x10, 0x0A],
            "HPSIM AID PIX must be 100A");
    }

    /// FsData::init succeeds for the full tree -- no TooManyFiles or StoreFull.
    #[test]
    fn fsdata_init_succeeds() {
        use simrs_fs::FsData;
        let mut data = FsData::<8192, 160>::new();
        let result = data.init_with_adfs(&REFERENCE_MF, &ADF_TABLE);
        assert!(result.is_ok(),
            "FsData::init_with_adfs failed: {:?}", result.err());
    }

    /// FsData::init succeeds with the active profile's FS_CAP and FS_MAX_EFS.
    ///
    /// This catches capacity regressions: if the EF tree grows beyond the
    /// profile-tier constants, this test panics immediately.
    #[test]
    fn fsdata_init_with_profile_constants_succeeds() {
        use simrs_fs::FsData;
        let mut data = FsData::<{ crate::FS_CAP }, { crate::FS_MAX_EFS }>::new();
        let result = data.init_with_adfs(&REFERENCE_MF, &ADF_TABLE);
        assert!(result.is_ok(),
            "FsData::<{}, {}>::init_with_adfs failed for active profile tier: {:?}",
            crate::FS_CAP, crate::FS_MAX_EFS, result.err());
    }

    /// All record EFs in the entire tree (MF + ADF.USIM + sub-DFs) have consistent
    /// data sizes. This covers the full tree including DF_5GS, DF.GSM-ACCESS, etc.
    #[test]
    fn full_tree_record_ef_data_sizes_consistent() {
        fn check(df: &DfDef) {
            for child in df.children {
                match child {
                    FileRef::Ef(ef) => {
                        let expected = match ef.structure() {
                            EfStructure::LinearFixed { record_size, num_records }
                            | EfStructure::Cyclic { record_size, num_records } => {
                                Some(record_size as usize * num_records as usize)
                            }
                            _ => None,
                        };
                        if let Some(exp) = expected {
                            assert_eq!(
                                ef.data().len(), exp,
                                "EF {:#06X}: data.len()={} != record_size*num_records={}",
                                ef.fid().value(), ef.data().len(), exp,
                            );
                        }
                    }
                    FileRef::Df(sub) => check(sub),
                }
            }
        }
        check(&REFERENCE_MF);
        for slot in &ADF_TABLE {
            check(slot.root);
        }
    }

    /// Every transparent EF has non-zero data length.
    #[test]
    fn all_transparent_efs_have_data() {
        fn check_efs(df: &DfDef) {
            for child in df.children {
                match child {
                    FileRef::Ef(ef) => {
                        if matches!(ef.structure(), EfStructure::Transparent) {
                            assert!(
                                !ef.data().is_empty(),
                                "Transparent EF {:#06X} has empty data", ef.fid().value(),
                            );
                        }
                    }
                    FileRef::Df(sub) => check_efs(sub),
                }
            }
        }
        check_efs(&REFERENCE_MF);
        for slot in &ADF_TABLE {
            check_efs(slot.root);
        }
    }

    /// No two ADFs share the same FID in the ADF table.
    #[test]
    fn adf_fids_unique() {
        let mut fids: [u16; 4] = [0xFFFF; 4];
        for (idx, slot) in ADF_TABLE.iter().enumerate() {
            let fid = slot.root.fid.value();
            for f in &fids[..idx] {
                assert_ne!(*f, fid, "duplicate ADF FID {fid:#06X} in ADF_TABLE");
            }
            fids[idx] = fid;
        }
    }

    /// No two ADFs share the same AID in the ADF table.
    #[test]
    fn adf_aids_unique() {
        for (i, a) in ADF_TABLE.iter().enumerate() {
            for b in ADF_TABLE.iter().skip(i + 1) {
                assert_ne!(a.aid, b.aid, "duplicate AID in ADF_TABLE");
            }
        }
    }

    /// Cross-DF FID collision: EF.FDN exists in both ADF.USIM and DF_TELECOM
    /// with the same FID (6F3B) but at different pointer addresses.
    #[cfg(all(feature = "profile-full", feature = "telecom"))]
    #[test]
    fn cross_df_fdn_different_data_pointers() {
        // Find EF.FDN (6F3B) in ADF.USIM
        let usim_fdn = ADF_USIM_ROOT.children.iter().find_map(|c| {
            if let FileRef::Ef(ef) = c {
                if ef.fid() == Fid::new(0x6F3B) { Some(*ef) } else { None }
            } else {
                None
            }
        });
        assert!(usim_fdn.is_some(), "EF.FDN (6F3B) not found in ADF.USIM");

        // Find EF.FDN (6F3B) in DF_TELECOM
        let telecom_fdn = DF_TELECOM.children.iter().find_map(|c| {
            if let FileRef::Ef(ef) = c {
                if ef.fid() == Fid::new(0x6F3B) { Some(*ef) } else { None }
            } else {
                None
            }
        });
        assert!(telecom_fdn.is_some(), "EF.FDN (6F3B) not found in DF_TELECOM");

        // They must be different static definitions (different addresses).
        let usim_ptr: *const EfDef = usim_fdn.unwrap();
        let telecom_ptr: *const EfDef = telecom_fdn.unwrap();
        assert_ne!(usim_ptr, telecom_ptr,
            "EF.FDN in ADF.USIM and DF_TELECOM must be different static definitions");
    }

    /// EF.PL exists under MF with FID 2F05.
    #[test]
    fn mf_has_ef_pl() {
        let has_pl = REFERENCE_MF.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid() == Fid::new(0x2F05)
            } else {
                false
            }
        });
        assert!(has_pl, "MF must contain EF.PL (2F05)");
    }

    /// EF.ARR exists under MF with FID 2F06.
    #[test]
    fn mf_has_ef_arr() {
        let has_arr = REFERENCE_MF.children.iter().any(|c| {
            if let FileRef::Ef(ef) = c {
                ef.fid() == Fid::new(0x2F06)
            } else {
                false
            }
        });
        assert!(has_arr, "MF must contain EF.ARR (2F06)");
    }

    /// DF_TELECOM exists under MF with FID 7F10.
    #[test]
    fn mf_has_df_telecom() {
        let has_telecom = REFERENCE_MF.children.iter().any(|c| {
            if let FileRef::Df(df) = c {
                df.fid == Fid::new(0x7F10)
            } else {
                false
            }
        });
        assert!(has_telecom, "MF must contain DF_TELECOM (7F10)");
    }

    /// Profile-full tier has expected number of EFs in ADF.USIM (92 direct children).
    #[cfg(feature = "profile-full")]
    #[test]
    fn adf_usim_full_child_count() {
        assert_eq!(
            ADF_USIM_ROOT.children.len(), 92,
            "profile-full ADF.USIM must have 92 children (90 EFs + 2 sub-DFs)"
        );
    }

    /// EF.DIR record count matches number of ADFs (1 USIM + optional ISIM + optional HPSIM).
    #[test]
    fn ef_dir_record_count_matches_adfs() {
        let expected_records = ADF_TABLE.len();
        match EF_DIR.structure() {
            EfStructure::LinearFixed { num_records, .. } => {
                assert_eq!(num_records as usize, expected_records,
                    "EF.DIR num_records ({num_records}) must match ADF_TABLE length ({expected_records})");
            }
            _ => panic!("EF.DIR must be LinearFixed"),
        }
    }

    /// EF.ICCID data length is exactly 10 bytes.
    #[test]
    fn ef_iccid_data_is_10_bytes() {
        assert_eq!(EF_ICCID.data().len(), 10, "EF.ICCID must be 10 bytes");
    }

    /// EF.IMSI data length is exactly 9 bytes with valid length byte.
    #[test]
    fn ef_imsi_data_is_valid() {
        assert_eq!(EF_IMSI.data().len(), 9, "EF.IMSI must be 9 bytes");
        assert_eq!(EF_IMSI.data()[0], 0x08, "EF.IMSI length byte must be 8");
    }

    /// Profile-full includes DF.GSM-ACCESS under ADF.USIM.
    #[cfg(feature = "profile-full")]
    #[test]
    fn adf_usim_contains_df_gsm_access() {
        let has = ADF_USIM_ROOT.children.iter().any(|c| {
            if let FileRef::Df(df) = c {
                df.fid == Fid::new(0x5F3B)
            } else {
                false
            }
        });
        assert!(has, "ADF.USIM must contain DF.GSM-ACCESS (5F3B) in profile-full");
    }

    /// EF.Kc and EF.KcGPRS under DF.GSM-ACCESS are each 9 bytes.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_gsm_access_ef_sizes() {
        for child in DF_GSM_ACCESS.children {
            if let FileRef::Ef(ef) = child {
                assert_eq!(ef.data().len(), 9,
                    "EF {:#06X} in DF.GSM-ACCESS must be 9 bytes", ef.fid().value());
            }
        }
    }

    /// ISIM EF.IMPI exists and has correct properties.
    #[cfg(feature = "isim")]
    #[test]
    fn isim_ef_impi_properties() {
        assert_eq!(ISIM_EF_IMPI.fid(), Fid::new(0x6F02));
        assert!(matches!(ISIM_EF_IMPI.structure(), EfStructure::Transparent));
        assert_eq!(ISIM_EF_IMPI.data().len(), 64, "ISIM EF.IMPI must be 64 bytes");
    }

    /// ISIM EF.IMPU exists and is linear-fixed.
    #[cfg(feature = "isim")]
    #[test]
    fn isim_ef_impu_is_linear_fixed() {
        match ISIM_EF_IMPU.structure() {
            EfStructure::LinearFixed { record_size, num_records } => {
                assert_eq!(record_size, 64, "ISIM EF.IMPU record size must be 64");
                assert_eq!(num_records, 2, "ISIM EF.IMPU must have 2 records");
            }
            _ => panic!("ISIM EF.IMPU must be LinearFixed"),
        }
    }

    /// HPSIM EF.HPST has expected size.
    #[cfg(feature = "hpsim")]
    #[test]
    fn hpsim_ef_hpst_size() {
        assert_eq!(HPSIM_EF_HPST.data().len(), 2, "HPSIM EF.HPST must be 2 bytes");
        assert_eq!(HPSIM_EF_HPST.fid(), Fid::new(0x6F07));
    }
}

// ---------------------------------------------------------------------------
// Property-based tests for profile
// ---------------------------------------------------------------------------

#[cfg(test)]
mod profile_proptests {
    extern crate alloc;
    use alloc::vec::Vec;
    use super::*;
    use proptest::prelude::*;

    /// Collect all EfDefs from a DF recursively.
    fn collect_efs(df: &DfDef) -> Vec<&'static EfDef> {
        let mut efs = Vec::new();
        for child in df.children {
            match child {
                FileRef::Ef(ef) => efs.push(*ef),
                FileRef::Df(sub) => efs.extend(collect_efs(sub)),
            }
        }
        efs
    }

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// For any randomly chosen EF in the ADF.USIM tree, if it is a
        /// record-based EF, data.len() == record_size * num_records.
        #[test]
        fn random_ef_record_size_consistency(idx in any::<usize>()) {
            let efs = collect_efs(&ADF_USIM_ROOT);
            prop_assume!(!efs.is_empty());
            let ef = efs[idx % efs.len()];

            match ef.structure() {
                EfStructure::LinearFixed { record_size, num_records }
                | EfStructure::Cyclic { record_size, num_records } => {
                    let expected = record_size as usize * num_records as usize;
                    prop_assert_eq!(ef.data().len(), expected,
                        "EF {:#06X}: data.len()={} != record_size*num_records={}",
                        ef.fid().value(), ef.data().len(), expected);
                }
                EfStructure::Transparent => {
                    prop_assert!(!ef.data().is_empty(),
                        "EF {:#06X}: transparent EF should have non-empty data",
                        ef.fid().value());
                }
                EfStructure::BerTlv => {}
            }
        }

        /// For any randomly chosen pair of EFs at the same level in
        /// ADF.USIM, their FIDs must differ.
        #[test]
        fn random_pair_fids_differ(i in any::<usize>(), j in any::<usize>()) {
            let children = ADF_USIM_ROOT.children;
            prop_assume!(children.len() >= 2);
            let i = i % children.len();
            let j = j % children.len();
            prop_assume!(i != j);

            let fid_i = match &children[i] {
                FileRef::Ef(ef) => ef.fid().value(),
                FileRef::Df(df) => df.fid.value(),
            };
            let fid_j = match &children[j] {
                FileRef::Ef(ef) => ef.fid().value(),
                FileRef::Df(df) => df.fid.value(),
            };
            prop_assert_ne!(fid_i, fid_j,
                "children at indices {} and {} have same FID {:#06X}",
                i, j, fid_i);
        }

        /// For any randomly chosen EF in the full tree (MF + all ADFs),
        /// if it has an SFI, the SFI is in the valid range 1..=30.
        #[test]
        fn random_ef_sfi_in_range(idx in any::<usize>()) {
            let mut all_efs = collect_efs(&REFERENCE_MF);
            for slot in &ADF_TABLE {
                all_efs.extend(collect_efs(slot.root));
            }
            prop_assume!(!all_efs.is_empty());
            let ef = all_efs[idx % all_efs.len()];

            if let Some(sfi) = ef.sfi() {
                prop_assert!((1..=30).contains(&sfi.value()),
                    "EF {:#06X} has invalid SFI {} (must be 1..=30)",
                    ef.fid().value(), sfi.value());
            }
        }

        /// FsData::init_with_adfs succeeds with any subset of the ADF table.
        /// We test with 0..=N ADFs selected from the table.
        #[test]
        fn fsdata_init_subset(count in 0usize..=ADF_TABLE.len()) {
            use simrs_fs::FsData;
            let mut data = FsData::<8192, 160>::new();
            // Cannot slice a static array by runtime index in proptest,
            // so we use a match on the known small counts.
            let result = match count {
                0 => data.init_with_adfs(&REFERENCE_MF, &[]),
                _ => data.init_with_adfs(&REFERENCE_MF, &ADF_TABLE[..count]),
            };
            prop_assert!(result.is_ok(),
                "FsData::init_with_adfs failed with {} ADFs: {:?}",
                count, result.err());
        }
    }
}
