//! Default reference USIM profile filesystem per 3GPP TS 31.102.
//!
//! Provides a standard USIM filesystem tree as `static` definitions,
//! suitable for test and development use. The file data is zero-filled
//! or populated with sensible defaults.
//!
//! # Profile tiers
//!
//! EFs are gated by feature flags:
//! - **`profile-minimal`** -- LTE attach minimum (33 EFs)
//! - **`profile-standard`** (default) -- baseline + auth + SMS + phonebook (58 EFs)
//! - **`profile-full`** -- full TS 31.102 catalog (207 EFs)
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
//! |   +-- [minimal] EF.UST (6F38) transparent, 19 bytes
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
//! |   +-- [full] EF.EXT4 (6F55) linear-fixed, 2 rec x 13 bytes
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
//! |   +-- [full] EF.Hiddenkey (6FC3) transparent, 4 bytes
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
//! |   +-- [full] EF.VBSCA (6FD5) transparent, 20 bytes
//! |   +-- [full] EF.GBABP (6FD6) transparent, 64 bytes
//! |   +-- [full] EF.MSK (6FD7) linear-fixed, 4 rec x 20 bytes
//! |   +-- [full] EF.MUK (6FD8) linear-fixed, 1 rec x 40 bytes
//! |   +-- [full] EF.GBANL (6FDA) linear-fixed, 1 rec x 4 bytes
//! |   +-- [full] EF.EHPLMNPI (6FDB) transparent, 1 byte
//! |   +-- [full] EF.LRPLMNSI (6FDC) transparent, 1 byte
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
//! |   +-- [full] EF.ARR (6F06) linear-fixed, 1 rec x 32 bytes
//! |   +-- [full] EF.UICCIARI (6FE9) transparent, 4 bytes
//! |   +-- [full] EF.ePDGId (6FF3) transparent, 4 bytes
//! |   +-- [full] EF.ePDGSelection (6FF4) transparent, 4 bytes
//! |   +-- [full] EF.3GPPPSDATAOFF (6FF9) transparent, 4 bytes
//! |   +-- [full] EF.3GPPPSDATAOFFsvclist (6FFA) linear-fixed, 1 rec x 32 bytes
//! |   +-- [full] EF.EARFCNList (6FFD) transparent, 4 bytes
//! |   +-- [full] EF.eAKA (6F01) transparent, 1 byte
//! |   +-- [full] EF.OPLMNwACT_LSP (6F0C) transparent, 7 bytes
//! |   +-- [full] EF.LSPPLMN (6F0D) transparent, 1 byte
//! |   +-- [full] EF.ePDGIdEm (6FF5) transparent, 4 bytes
//! |   +-- [full] EF.ePDGSelEm (6FF6) transparent, 4 bytes
//! |   +-- [full] EF.IAL (6FF0) linear-fixed, 1 rec x 18 bytes
//! |   +-- [full] EF.IPD (6FF2) linear-fixed, 1 rec x 10 bytes
//! |   +-- [full] EF.OCST (6F02) transparent, 1 byte
//! |   +-- [full] EF.IMSConfigData (6FF8) transparent, 4 bytes
//! |   +-- [full] EF.TVCONFIG (6FFB) linear-fixed, 1 rec x 16 bytes
//! |   +-- [full] EF.XCAPConfigData (6FFC) transparent, 4 bytes
//! |   +-- [full] EF.MuDMiDConfigData (6FFE) transparent, 4 bytes
//! |   +-- [full] EF.AC_GBAUAPI (6F0A) transparent, 4 bytes
//! |   +-- [full] EF.IMSDCI (6F0B) transparent, 1 byte
//! |   +-- DF.5GS (5FC0)
//! |   |   +-- EF.5GS3GPPLOCI (4F01) transparent, 20 bytes
//! |   |   +-- ... (17 EFs total)
//! |   +-- [full] DF.GSM-ACCESS (5F3B)
//! |   |   +-- EF.Kc (4F20) transparent, 9 bytes
//! |   |   +-- EF.KcGPRS (4F52) transparent, 9 bytes
//! |   +-- [full] DF.SNPN (5FE0)
//! |   |   +-- EF.PWS_SNPN (4F01) transparent, 1 byte
//! |   |   +-- EF.NID (4F02) linear-fixed, 1 rec x 6 bytes
//! |   +-- [full] DF.5G_ProSe (5FF0)
//! |   |   +-- EF.5G_PROSE_ST (4F01) transparent, 2 bytes
//! |   |   +-- ... (13 EFs total)
//! |   +-- [full] DF.5MBSUECONFIG (5FF1)
//! |       +-- EF.5MBSUECONFIG (4F01) transparent, 4 bytes
//! |       +-- EF.5MBSUSD (4F08) transparent, 4 bytes
//! +-- DF.TELECOM (7F10)
//! ```
//!
//! # Standards
//! - 3GPP TS 31.102 V19.4.0 clause 4.2 -- USIM EF definitions
//! - 3GPP TS 31.102 V19.4.0 clause 4.4 -- File identifiers
//! - [ETSI TS 102 221 V18.3.0 clause 13](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A485%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D) -- UICC files under MF

use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef, Sfi};
#[cfg(test)]
use simrs_fs::EfStructure;

// ---------------------------------------------------------------------------
// EFs under MF
// ---------------------------------------------------------------------------

/// EF.ICCID (2FE2) -- ICC Identification.
///
/// 10-byte transparent EF. Default: test ICCID `8901260000000000000`.
/// Encoding: BCD-nibble-swapped per [ETSI TS 102 221 V18.3.0 clause 13.2](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A488%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C787%5D).
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
    // IMSI 001010000000000 (15 digits, odd parity, MCC=001, MNC=01).
    // Nibble-swapped BCD per TS 24.008 clause 10.5.1.4:
    //   byte 0 = 0x08 (8 data bytes), byte 1 = 0x09 (odd parity, digit1=0),
    //   bytes 2-8 = remaining 14 digits in lo/hi nibble pairs.
    &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00],
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
/// 19-byte transparent EF. Each bit enables a service per [3GPP TS 31.102 V19.4.0 clause 4.2.8](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
/// Default: services 1-25 enabled (local phone book, FDN, SMS, etc.),
/// plus GBA (68), LRPLMNSI (74), ePDG (106,107), emergency ePDG (110,111),
/// IMS Config (115), TV Config (116), PS Data Off (117,118), XCAP (120),
/// EARFCN (121), 5GS services (122-124, 126, 129-130, 132, 134, 135, 137-143),
/// SNPN (143,146), 5MBS (147), SENSE (148), IMS DCI (150),
/// and Rel-19 LSP (151,152).
///
/// Service N is encoded as bit ((N-1) % 8) of byte ((N-1) / 8).
/// Byte indices are zero-based.
///
/// Byte 8 (services 65-72): bit 3 set = 0x08 (svc 68)
/// Byte 9 (services 73-80): bit 1 set = 0x02 (svc 74)
/// Byte 13 (services 105-112): bits 1,2,5,6 set = 0x66 (svc 106,107,110,111)
/// Byte 14 (services 113-120): bits 2,3,4,5,7 set = 0xBC (svc 115,116,117,118,120)
/// Byte 15 (services 121-128): bits 0,1,2,3,5 set = 0x2F (svc 121,122,123,124,126)
/// Byte 16 (services 129-136): bits 0,1,3,5,6 set = 0x6B (svc 129,130,132,134,135)
/// Byte 17 (services 137-144): bits 0,1,2,3,4,5,6 set = 0x7F (svc 137-143)
/// Byte 18 (services 145-152): bits 1,2,3,5,6,7 set = 0xEE (svc 146,147,148,150,151,152)
static EF_UST_DATA: [u8; 19] = [
    0xFF, 0xFF, 0xFF, 0x01, // bytes 0-3: services 1-32 (1-25 enabled)
    0x00, 0x00, 0x00, 0x00, // bytes 4-7: services 33-64
    0x08, 0x02, 0x00, 0x00, // bytes 8-11: services 65-96 (68,74)
    0x00, 0x66, 0xBC, 0x2F, // bytes 12-15: services 97-128 (106,107,110,111,115,116,117,118,120,121-124,126)
    0x6B, 0x7F, 0xEE,       // bytes 16-18: services 129-152 (129,130,132,134,135,137-143,146-148,150,151,152)
];

/// EF.UST (6F38) -- USIM Service Table.
///
/// 19-byte transparent EF. Each bit enables a service per [3GPP TS 31.102 V19.4.0 clause 4.2.8](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.17](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A90%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C481%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.3](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A62%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.4](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A62%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C383%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C493%5D). SFI 0x02.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.26](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A108%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.27](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A108%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C409%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.24](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A104%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C666%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.12](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A82%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C403%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.14](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A86%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C470%5D).
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_CBMI: EfDef = EfDef::transparent(
    Fid::new(0x6F45),
    None,
    &[0xFF; 20],
);

/// EF.CBMID (6F48) -- Cell Broadcast Message Identifier for Data Download.
///
/// 20-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.20](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A96%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C431%5D). SFI 0x0E.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_CBMID: EfDef = EfDef::transparent(
    Fid::new(0x6F48),
    Some(Sfi::new(0x0E)),
    &[0xFF; 20],
);

/// EF.CBMIR (6F50) -- Cell Broadcast Message Identifier Range selection.
///
/// 20-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.22](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A100%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C591%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.25](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A104%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C257%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.28](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A112%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C703%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.32](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A116%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C586%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.21](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A98%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D). SFI 0x01.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.5](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A64%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C687%5D). SFI 0x0A.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.53](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A144%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C235%5D). SFI 0x11.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.54](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A146%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C419%5D). SFI 0x13.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_HPLMNWACT: EfDef = EfDef::transparent(
    Fid::new(0x6F62),
    Some(Sfi::new(0x13)),
    &EF_HPLMNWACT_DATA,
);

/// EF.EHPLMN (6FD9) -- Equivalent HPLMN.
///
/// 12-byte transparent EF. 4 PLMN entries of 3 bytes each.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.84](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A202%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C632%5D). SFI 0x1D.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.58](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A154%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C546%5D). SFI 0x19.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.59](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A156%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C509%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.10](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A80%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C252%5D).
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_GID1: EfDef = EfDef::transparent(
    Fid::new(0x6F3E),
    None,
    &[0xFF; 10],
);

/// EF.GID2 (6F3F) -- Group Identifier Level 2.
///
/// 10-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.11](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A82%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C649%5D).
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_GID2: EfDef = EfDef::transparent(
    Fid::new(0x6F3F),
    None,
    &[0xFF; 10],
);

/// EF.SPDI (6FCD) -- Service Provider Display Information.
///
/// 33-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.66](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A168%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D). SFI 0x1B.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_SPDI: EfDef = EfDef::transparent(
    Fid::new(0x6FCD),
    Some(Sfi::new(0x1B)),
    &[0xFF; 33],
);

/// EF.ACL (6F57) -- Access Point Name Control List.
///
/// 4-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.48](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A138%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C157%5D).
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_ACL: EfDef = EfDef::transparent(
    Fid::new(0x6F57),
    None,
    &[0xFF; 4],
);

/// EF.EST (6F56) -- Enabled Services Table.
///
/// 9-byte transparent EF. Default: all services disabled.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.47](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A138%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D). SFI 0x05.
#[cfg(any(feature = "profile-standard", feature = "profile-full"))]
pub static EF_EST: EfDef = EfDef::transparent(
    Fid::new(0x6F56),
    Some(Sfi::new(5)),
    &[0x00; 9],
);

/// EF.EPSLOCI (6FE3) -- EPS Location Information.
///
/// 18-byte transparent EF. Contains GUTI, last visited TAI, EPS update status.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.91](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A215%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C260%5D). SFI 0x1E.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.92](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A221%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D). SFI 0x18.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.49](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A140%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C605%5D).
#[cfg(feature = "profile-full")]
pub static EF_DCK: EfDef = EfDef::transparent(
    Fid::new(0x6F2C),
    None,
    &[0xFF; 16],
);

/// EF.CNL (6F32) -- Co-operative Network List.
///
/// 24-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.50](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A140%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C307%5D).
#[cfg(feature = "profile-full")]
pub static EF_CNL: EfDef = EfDef::transparent(
    Fid::new(0x6F32),
    None,
    &[0xFF; 24],
);

/// EF.ACMmax (6F37) -- ACM Maximum Value.
///
/// 3-byte transparent EF. Default: 0x000000 (no maximum).
/// [3GPP TS 31.102 V19.4.0 clause 4.2.7](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A68%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C495%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.9](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A80%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C648%5D). SFI 0x1C.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.13](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A84%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C506%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.29](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A112%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C282%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.30](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A114%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C532%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.31](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A114%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C287%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.44](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A134%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C422%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.37](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A128%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C612%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.38](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A128%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C367%5D). SFI 0x16.
#[cfg(feature = "profile-full")]
pub static EF_CCP2: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F4F),
    Some(Sfi::new(0x16)),
    15, 4,
    &EF_CCP2_DATA,
);

// EF_EXT4 data: 2 records of 13 bytes.
#[cfg(feature = "profile-full")]
static EF_EXT4_DATA: [u8; 26] = [0xFF; 26];

/// EF.EXT4 (6F55) -- Extension4 (BDN/SSC).
///
/// Linear-fixed, 2 records of 13 bytes. Contains extension data for BDN.
/// Record: type (1B) + extension data (11B) + identifier (1B).
/// Service 7.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.45](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A136%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C744%5D).
#[cfg(feature = "profile-full")]
pub static EF_EXT4: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F55),
    None,
    13, 2,
    &EF_EXT4_DATA,
);

/// EF.CMI data: 4 records of 11 bytes each.
#[cfg(feature = "profile-full")]
static EF_CMI_DATA: [u8; 44] = [0xFF; 44];

/// EF.CMI (6F58) -- Comparison Method Information.
///
/// Linear-fixed, 4 records of 11 bytes. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.46](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A136%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C499%5D).
#[cfg(feature = "profile-full")]
pub static EF_CMI: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F58),
    None,
    11, 4,
    &EF_CMI_DATA,
);

/// EF.START_HFN (6F5B) -- Initialisation values for Hyperframe number.
///
/// 6-byte transparent EF. Default: all zeros.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.51](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A144%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D). SFI 0x0F.
#[cfg(feature = "profile-full")]
pub static EF_START_HFN: EfDef = EfDef::transparent(
    Fid::new(0x6F5B),
    Some(Sfi::new(0x0F)),
    &[0xF0, 0x00, 0x00, 0xF0, 0x00, 0x00],
);

/// EF.THRESHOLD (6F5C) -- Maximum value of START.
///
/// 3-byte transparent EF. Default: 0xFFFFFF.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.52](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A144%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C471%5D). SFI 0x10.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.33](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A116%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C143%5D). SFI 0x14.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.34](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A124%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C634%5D). SFI 0x15.
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.35](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A126%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.36](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A126%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C219%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.73](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A182%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C415%5D).
#[cfg(feature = "profile-full")]
pub static EF_VGCS: EfDef = EfDef::transparent(
    Fid::new(0x6FB1),
    None,
    &[0xFF; 40],
);

/// EF.VGCSS (6FB2) -- Voice Group Call Service Status.
///
/// 7-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.74](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A186%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C743%5D).
#[cfg(feature = "profile-full")]
pub static EF_VGCSS: EfDef = EfDef::transparent(
    Fid::new(0x6FB2),
    None,
    &[0xFF; 7],
);

/// EF.VBS (6FB3) -- Voice Broadcast Service.
///
/// 40-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.75](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A186%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C166%5D).
#[cfg(feature = "profile-full")]
pub static EF_VBS: EfDef = EfDef::transparent(
    Fid::new(0x6FB3),
    None,
    &[0xFF; 40],
);

/// EF.VBSS (6FB4) -- Voice Broadcast Service Status.
///
/// 7-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.76](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A190%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C461%5D).
#[cfg(feature = "profile-full")]
pub static EF_VBSS: EfDef = EfDef::transparent(
    Fid::new(0x6FB4),
    None,
    &[0xFF; 7],
);

/// EF.eMLPP (6FB5) -- enhanced Multi-Level Pre-emption and Priority.
///
/// 2-byte transparent EF. Default: 0x0000.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.39](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A130%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C747%5D).
#[cfg(feature = "profile-full")]
pub static EF_EMLPP: EfDef = EfDef::transparent(
    Fid::new(0x6FB5),
    None,
    &[0x00, 0x00],
);

/// EF.AaeM (6FB6) -- Automatic Answer for eMLPP.
///
/// 1-byte transparent EF. Default: 0x00.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.40](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A132%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C648%5D).
#[cfg(feature = "profile-full")]
pub static EF_AAEM: EfDef = EfDef::transparent(
    Fid::new(0x6FB6),
    None,
    &[0x00],
);

/// EF.Hiddenkey (6FC3) -- Hidden Key.
///
/// 4-byte transparent EF. Verification data for hidden phonebook entries.
/// UST service 23.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.42](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf).
#[cfg(feature = "profile-full")]
pub static EF_HIDDENKEY: EfDef = EfDef::transparent(
    Fid::new(0x6FC3),
    None,
    &[0xFF; 4],
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.57](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A150%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C754%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.60](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A158%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C518%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.61](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A158%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C143%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.62](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A160%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C596%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.63](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A160%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C143%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.64](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A164%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C533%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.65](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A166%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C499%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.67](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A168%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C237%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.68](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A172%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C586%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.69](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A174%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.70](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A178%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C623%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.71](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A180%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C609%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.72](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A180%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C232%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.77](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A192%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C781%5D).
#[cfg(feature = "profile-full")]
pub static EF_VGCSCA: EfDef = EfDef::transparent(
    Fid::new(0x6FD4),
    None,
    &[0x00; 20],
);

/// EF.VBSCA (6FD5) -- Voice Broadcast Service Ciphering Algorithm.
///
/// 20-byte transparent EF. Default: all zeroes (no ciphering).
/// Contains ciphering algorithm identifiers for VBS group V_Ki values.
/// Coding same as EF_VGCSCA. Service 65.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.78](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A194%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C781%5D).
#[cfg(feature = "profile-full")]
pub static EF_VBSCA: EfDef = EfDef::transparent(
    Fid::new(0x6FD5),
    None,
    &[0x00; 20],
);

/// EF.GBABP (6FD6) -- GBA Bootstrapping Parameters.
///
/// 64-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.79](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A194%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C383%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.80](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A196%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C539%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.81](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A198%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C573%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.83](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A200%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C520%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.85](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A202%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C286%5D).
#[cfg(feature = "profile-full")]
pub static EF_EHPLMNPI: EfDef = EfDef::transparent(
    Fid::new(0x6FDB),
    None,
    &[0x02],
);

/// EF.LRPLMNSI (6FDC) -- Last RPLMN Selection Indication.
///
/// 1-byte transparent EF. Default: 0x00 (attempt registration on last RPLMN).
/// 0x01 = attempt HPLMN or last RPLMN per TS 23.122. Service 74.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.86](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A204%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C687%5D).
#[cfg(feature = "profile-full")]
pub static EF_LRPLMNSI: EfDef = EfDef::transparent(
    Fid::new(0x6FDC),
    None,
    &[0x00],
);

/// EF.NAFKCA data: 2 records of 32 bytes each.
#[cfg(feature = "profile-full")]
static EF_NAFKCA_DATA: [u8; 64] = [0xFF; 64];

/// EF.NAFKCA (6FDD) -- NAF Key Centre Address.
///
/// Linear-fixed, 2 records of 32 bytes. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.87](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A204%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C359%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.88](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A206%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C535%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.89](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A208%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C427%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.90](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A208%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C172%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.93](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A223%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C109%5D).
#[cfg(feature = "profile-full")]
pub static EF_UFC: EfDef = EfDef::transparent(
    Fid::new(0x6FE6),
    None,
    &[0x00; 64],
);

/// EF.NASCONFIG (6FE8) -- Non Access Stratum Configuration.
///
/// 4-byte transparent EF. Default: empty.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.94](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A225%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C555%5D).
#[cfg(feature = "profile-full")]
pub static EF_NASCONFIG: EfDef = EfDef::transparent(
    Fid::new(0x6FE8),
    None,
    &[0xFF; 4],
);

/// EF.PWS (6FEC) -- Public Warning System.
///
/// 3-byte transparent EF. Default: all zeroes.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.96](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A241%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C427%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.97](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A243%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C744%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.98](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A243%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C167%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.99](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A245%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C277%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.101](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A249%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C318%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.2.106](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A259%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C235%5D).
#[cfg(feature = "profile-full")]
pub static EF_FROM_PREFERRED: EfDef = EfDef::transparent(
    Fid::new(0x6FF7),
    None,
    &[0xFF],
);

// ---------------------------------------------------------------------------
// New ADF_USIM root EFs -- P0 (mandatory + Shannon-critical)
// ---------------------------------------------------------------------------

// EF_ARR_USIM data: 1 record of 32 bytes.
#[cfg(feature = "profile-full")]
static EF_ARR_USIM_DATA: [u8; 32] = [0xFF; 32];

/// EF.ARR (6F06) -- Access Rule Reference (ADF_USIM level).
///
/// Linear-fixed, 1 record of 32 bytes. Default: 0xFF (empty rule).
/// Contains access rules referenced by file FCPs via security attribute
/// tag '8B'. Mandatory per TS 31.102.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.55](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A148%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C642%5D).
#[cfg(feature = "profile-full")]
pub static EF_ARR_USIM: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F06),
    Some(Sfi::new(0x17)),
    32, 1,
    &EF_ARR_USIM_DATA,
);

/// EF.UICCIARI (6FE9) -- UICC IARI.
///
/// Transparent, 4 bytes. Default: 0xFF (unprovisioned).
/// Contains IMS Integrated Resource Identifiers for UICC applications.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.95](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A239%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C263%5D).
#[cfg(feature = "profile-full")]
pub static EF_UICCIARI: EfDef = EfDef::transparent(
    Fid::new(0x6FE9),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.ePDGId (6FF3) -- Home ePDG Identifier.
///
/// Transparent, 4 bytes. Default: 0xFF (unprovisioned).
/// Contains home ePDG FQDN or IP address for WiFi calling.
/// Services 106+107.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.103](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A253%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C527%5D).
#[cfg(feature = "profile-full")]
pub static EF_EPDG_ID: EfDef = EfDef::transparent(
    Fid::new(0x6FF3),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.ePDGSelection (6FF4) -- ePDG Selection Information.
///
/// Transparent, 4 bytes. Default: 0xFF (unprovisioned).
/// Contains ePDG selection parameters per PLMN for WiFi calling.
/// Services 106+107.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.104](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A255%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
#[cfg(feature = "profile-full")]
pub static EF_EPDG_SELECTION: EfDef = EfDef::transparent(
    Fid::new(0x6FF4),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.3GPPPSDATAOFF (6FF9) -- 3GPP PS Data Off.
///
/// Transparent, 4 bytes. Default: 0x00 (all services active).
/// Bitmap indicating which services are exempt from PS Data Off.
/// Service 117.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.109](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A265%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C670%5D).
#[cfg(feature = "profile-full")]
pub static EF_3GPP_PS_DATA_OFF: EfDef = EfDef::transparent(
    Fid::new(0x6FF9),
    None,
    &[0x00, 0x00, 0x00, 0x00],
);

// EF_3GPPPSDATAOFFservicelist data: 1 record of 32 bytes.
#[cfg(feature = "profile-full")]
static EF_3GPP_PS_DATA_OFF_SVC_DATA: [u8; 32] = [0xFF; 32];

/// EF.3GPPPSDATAOFFservicelist (6FFA) -- 3GPP PS Data Off Service List.
///
/// Linear-fixed, 1 record of 32 bytes. Default: 0xFF (empty).
/// Contains ICSI TLV objects identifying exempt IMS services.
/// Service 118.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.110](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A267%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C539%5D).
#[cfg(feature = "profile-full")]
pub static EF_3GPP_PS_DATA_OFF_SVC: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FFA),
    None,
    32, 1,
    &EF_3GPP_PS_DATA_OFF_SVC_DATA,
);

/// EF.EARFCNList (6FFD) -- EARFCN List.
///
/// Transparent, 4 bytes. Default: 0xFF (empty list).
/// Contains E-UTRA Absolute Radio Frequency Channel Number entries.
/// Service 121.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.112](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A269%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C683%5D).
#[cfg(feature = "profile-full")]
pub static EF_EARFCN_LIST: EfDef = EfDef::transparent(
    Fid::new(0x6FFD),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.eAKA (6F01) -- Enhanced AKA Configuration.
///
/// Transparent, 1 byte. Default: 0x00 (enhanced SQN not supported).
/// Bit 1 of byte 1: 0 = enhanced SQN management not supported,
/// 1 = supported. Rel-18.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.114](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A271%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C611%5D).
#[cfg(feature = "profile-full")]
pub static EF_EAKA: EfDef = EfDef::transparent(
    Fid::new(0x6F01),
    None,
    &[0x00],
);

/// EF.OPLMNwACT_LSP (6F0C) -- Operator PLMN with ACT and LSP.
///
/// Transparent, 7 bytes (1 priority + 1 entry of 6 bytes).
/// Default: 0xFF (unprovisioned).
/// Contains operator-controlled PLMN selection with Local Service
/// Provider priority for network selection. Rel-19.
/// Service 151.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.118](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A275%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C146%5D).
#[cfg(feature = "profile-full")]
pub static EF_OPLMNWACT_LSP: EfDef = EfDef::transparent(
    Fid::new(0x6F0C),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.LSPPLMN (6F0D) -- LSP PLMN Search Timer.
///
/// Transparent, 1 byte. Default: 0x00 (timer disabled).
/// Contains PeriodicSearchTimerNonLSP value controlling how often
/// the UE searches for non-LSP PLMNs. Rel-19.
/// Service 152.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.119](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A279%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C696%5D).
#[cfg(feature = "profile-full")]
pub static EF_LSPPLMN: EfDef = EfDef::transparent(
    Fid::new(0x6F0D),
    None,
    &[0x00],
);

// ---------------------------------------------------------------------------
// New ADF_USIM root EFs -- P1 (remaining high-value)
// ---------------------------------------------------------------------------

/// EF.ePDGIdEm (6FF5) -- Emergency ePDG Identifier.
///
/// Transparent, 4 bytes. Default: 0xFF (unprovisioned).
/// Contains emergency ePDG FQDN or IP address for emergency WiFi calling.
/// Services 110+111.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.104a](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A259%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
#[cfg(feature = "profile-full")]
pub static EF_EPDG_ID_EM: EfDef = EfDef::transparent(
    Fid::new(0x6FF5),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.ePDGSelectionEm (6FF6) -- Emergency ePDG Selection Information.
///
/// Transparent, 4 bytes. Default: 0xFF (unprovisioned).
/// Contains emergency ePDG selection parameters per PLMN.
/// Services 110+111.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.105](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A259%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C489%5D).
#[cfg(feature = "profile-full")]
pub static EF_EPDG_SELECTION_EM: EfDef = EfDef::transparent(
    Fid::new(0x6FF6),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

// EF_IAL data: 1 record of 18 bytes.
#[cfg(feature = "profile-full")]
static EF_IAL_DATA: [u8; 18] = [0xFF; 18];

/// EF.IAL (6FF0) -- IMEI(SV) Allowed List.
///
/// Linear-fixed, 1 record of 18 bytes (X+2, X>=16). Default: 0xFF (empty).
/// Contains TAC and optional SVN allowed list for device pairing.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.100](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A247%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C338%5D).
#[cfg(feature = "profile-full")]
pub static EF_IAL: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FF0),
    None,
    18, 1,
    &EF_IAL_DATA,
);

// EF_IPD data: 1 record of 10 bytes.
#[cfg(feature = "profile-full")]
static EF_IPD_DATA: [u8; 10] = [0xFF; 10];

/// EF.IPD (6FF2) -- IMEI(SV) of Pairing Device.
///
/// Linear-fixed, 1 record of 10 bytes (X+2, X>=8). Default: 0xFF (empty).
/// Contains IMEI(SV) of the paired device.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.102](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A251%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C332%5D).
#[cfg(feature = "profile-full")]
pub static EF_IPD: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FF2),
    None,
    10, 1,
    &EF_IPD_DATA,
);

/// EF.OCST (6F02) -- Operator Controlled SENSE Threshold.
///
/// Transparent, 1 byte. Default: 0x00 (no threshold configured).
/// Contains operator signal threshold for SENSE feature. Rel-18.
/// Service 148.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.115](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A273%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
#[cfg(feature = "profile-full")]
pub static EF_OCST: EfDef = EfDef::transparent(
    Fid::new(0x6F02),
    None,
    &[0x00],
);

// ---------------------------------------------------------------------------
// New ADF_USIM root EFs -- P2 (TS 31.103 cross-refs + niche)
// ---------------------------------------------------------------------------

/// EF.IMSConfigData (6FF8) -- IMS Configuration Data.
///
/// Transparent, variable length. Default: 4 bytes 0xFF (unprovisioned).
/// Contains IMS configuration data object per 3GPP TS 24.167.
/// Structure, content and coding defined in EF_IMSConfigData of TS 31.103.
/// Service 115.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.107](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A261%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C525%5D).
#[cfg(feature = "profile-full")]
pub static EF_IMS_CONFIG_DATA: EfDef = EfDef::transparent(
    Fid::new(0x6FF8),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

// EF_TVCONFIG data: 1 record of 16 bytes.
#[cfg(feature = "profile-full")]
static EF_TVCONFIG_DATA: [u8; 16] = [0xFF; 16];

/// EF.TVCONFIG (6FFB) -- TV Configuration.
///
/// Linear-fixed, 1 record of 16 bytes. Default: 0xFF (unprovisioned).
/// Each record: PLMN identity (3B) + optional TMGI List TLV + EARFCN List TLV.
/// Service 116.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.108](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A261%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C389%5D).
#[cfg(feature = "profile-full")]
pub static EF_TVCONFIG: EfDef = EfDef::linear_fixed(
    Fid::new(0x6FFB),
    None,
    16, 1,
    &EF_TVCONFIG_DATA,
);

/// EF.XCAPConfigData (6FFC) -- XCAP Configuration Data.
///
/// Transparent, variable length. Default: 4 bytes 0xFF (unprovisioned).
/// Contains XCAP configuration data object per 3GPP TS 24.424.
/// Structure, content and coding defined in EF_XCAPConfigData of TS 31.103.
/// Service 120.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.111](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A267%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C138%5D).
#[cfg(feature = "profile-full")]
pub static EF_XCAP_CONFIG_DATA: EfDef = EfDef::transparent(
    Fid::new(0x6FFC),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.MuDMiDConfigData (6FFE) -- MuD and MiD Configuration Data.
///
/// Transparent, variable length. Default: 4 bytes 0xFF (unprovisioned).
/// Contains MuD/MiD configuration data object per 3GPP TS 24.175.
/// Structure, content and coding defined in EF_MuDMiDConfigData of TS 31.103.
/// Service 134.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.113](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A271%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C747%5D).
#[cfg(feature = "profile-full")]
pub static EF_MUDMID_CONFIG_DATA: EfDef = EfDef::transparent(
    Fid::new(0x6FFE),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.AC_GBAUAPI (6F0A) -- Access Control to GBA_U_API.
///
/// Transparent, variable length. Default: 4 bytes 0xFF (unprovisioned).
/// Contains AC_GBAUAPI TLV with NAF_ID data objects per 3GPP TS 33.220.
/// Structure, content and coding defined in EF_AC_GBAUAPI of TS 31.103.
/// Service 68.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.116](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A275%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C429%5D).
#[cfg(feature = "profile-full")]
pub static EF_AC_GBAUAPI: EfDef = EfDef::transparent(
    Fid::new(0x6F0A),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.IMSDCI (6F0B) -- IMS Data Channel Indication.
///
/// Transparent, 1 byte. Default: 0x00 (IMS data channel not required).
/// Bit 1: use of IMS data channel required (1) or not (0). Bits 2-8: RFU.
/// Structure, content and coding defined in EF_IMSDCI of TS 31.103.
/// Service 150.
/// [3GPP TS 31.102 V19.4.0 clause 4.2.117](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A275%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C281%5D).
#[cfg(feature = "profile-full")]
pub static EF_IMSDCI: EfDef = EfDef::transparent(
    Fid::new(0x6F0B),
    None,
    &[0x00],
);

// ---------------------------------------------------------------------------
// DF.PHONEBOOK (5F3A) under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

// EF_PBR data: 1 record of 64 bytes.
// Contains PBR TLV structure referencing phonebook EFs by FID.
// Type 1 (A8): ADN, PBC, ANR, SNE, EMAIL, GRP, UID, PURI
// Type 3 (AA): EXT1, AAS, GAS, CCP1
#[cfg(feature = "profile-full")]
static PB_EF_PBR_DATA: [u8; 64] = [
    // Type 1 files (A8) -- paired 1:1 with ADN records
    0xA8, 0x20,
    0xC0, 0x02, 0x4F, 0x31, // EF_ADN (4F31)
    0xC5, 0x02, 0x4F, 0x34, // EF_PBC (4F34)
    0xC4, 0x02, 0x4F, 0x35, // EF_ANR (4F35)
    0xC3, 0x02, 0x4F, 0x36, // EF_SNE (4F36)
    0xCA, 0x02, 0x4F, 0x3C, // EF_EMAIL (4F3C)
    0xC6, 0x02, 0x4F, 0x37, // EF_GRP (4F37)
    0xC9, 0x02, 0x4F, 0x3B, // EF_UID (4F3B)
    0xCC, 0x02, 0x4F, 0x3D, // EF_PURI (4F3D)
    // Type 3 files (AA) -- shared, linked by record identifier
    0xAA, 0x10,
    0xC2, 0x02, 0x4F, 0x32, // EF_EXT1 (4F32)
    0xC7, 0x02, 0x4F, 0x38, // EF_AAS (4F38)
    0xC8, 0x02, 0x4F, 0x39, // EF_GAS (4F39)
    0xCB, 0x02, 0x4F, 0x3A, // EF_CCP1 (4F3A)
    // padding
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// EF.PBR (4F30) -- Phone Book Reference file.
///
/// Linear-fixed, 1 record of 64 bytes. Contains TLV-structured references
/// to phonebook EFs per Table 4.2: C0=ADN, C1=IAP, C2=EXT1, C3=SNE,
/// C4=ANR, C5=PBC, C6=GRP, C7=AAS, C8=GAS, C9=UID, CA=EMAIL, CB=CCP1,
/// CC=PURI. Tags grouped under A8 (Type 1), A9 (Type 2), AA (Type 3).
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A291%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C783%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_PBR: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F30),
    None,
    64, 1,
    &PB_EF_PBR_DATA,
);

// EF_ADN data: 5 records of 28 bytes (14B alpha + 14B dialling number data).
#[cfg(feature = "profile-full")]
static PB_EF_ADN_DATA: [u8; 140] = [0xFF; 140];

/// EF.ADN (4F31) -- Abbreviated Dialling Numbers.
///
/// Linear-fixed, 5 records of 28 bytes. Record: X bytes alpha identifier +
/// 1B BCD number length + 1B TON/NPI + 10B dialling number + 1B CCP1 ID +
/// 1B EXT1 ID. X=14, total=28.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.3](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A295%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C332%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_ADN: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F31),
    None,
    28, 5,
    &PB_EF_ADN_DATA,
);

// EF_EXT1 data: 5 records of 13 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_EXT1_DATA: [u8; 65] = [0xFF; 65];

/// EF.EXT1 (4F32) -- Extension 1.
///
/// Linear-fixed, 5 records of 13 bytes. Record: 1B record type (02=BCD,
/// 01=additional data, FF=free) + 11B extension data + 1B next record ID.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.4](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A301%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C346%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_EXT1: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F32),
    None,
    13, 5,
    &PB_EF_EXT1_DATA,
);

// EF_IAP data: 5 records of 1 byte.
#[cfg(feature = "profile-full")]
static PB_EF_IAP_DATA: [u8; 5] = [0xFF; 5];

/// EF.IAP (4F33) -- Index Administration Phone book.
///
/// Linear-fixed, 5 records of 1 byte. Each byte is a record pointer to a
/// Type 2 file. Record length = number of Type 2 files per PBR record.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A295%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C756%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_IAP: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F33),
    None,
    1, 5,
    &PB_EF_IAP_DATA,
);

// EF_PBC data: 5 records of 2 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_PBC_DATA: [u8; 10] = [0x00; 10];

/// EF.PBC (4F34) -- Phone Book Control.
///
/// Linear-fixed, 5 records of 2 bytes. Byte 1 bit 1: hidden entry flag;
/// byte 2: change counter/modification flag.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.5](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A305%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C465%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_PBC: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F34),
    None,
    2, 5,
    &PB_EF_PBC_DATA,
);

// EF_ANR data: 5 records of 15 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_ANR_DATA: [u8; 75] = [0xFF; 75];

/// EF.ANR (4F35) -- Additional Number.
///
/// Linear-fixed, 5 records of 15 bytes. Record: 1B AAS record ID +
/// 1B BCD number length + 1B TON/NPI + 10B additional number +
/// 1B CCP2 ID + 1B EXT1 ID.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.9](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A309%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C216%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_ANR: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F35),
    None,
    15, 5,
    &PB_EF_ANR_DATA,
);

// EF_SNE data: 5 records of 18 bytes (16B alpha + 2B extension ref).
#[cfg(feature = "profile-full")]
static PB_EF_SNE_DATA: [u8; 90] = [0xFF; 90];

/// EF.SNE (4F36) -- Second Name Entry.
///
/// Linear-fixed, 5 records of 18 bytes. Record: X bytes alpha identifier +
/// optional 2 bytes extension reference. X=16.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.10](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A313%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C402%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_SNE: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F36),
    None,
    18, 5,
    &PB_EF_SNE_DATA,
);

/// EF.GRP (4F37) -- Grouping file.
///
/// Linear-fixed, 5 records of 1 byte. Each byte is a record number in
/// EF_GAS identifying a group association.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.6](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A307%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C627%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_GRP: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F37),
    None,
    1, 5,
    &[0xFF; 5],
);

// EF_AAS data: 2 records of 16 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_AAS_DATA: [u8; 32] = [0xFF; 32];

/// EF.AAS (4F38) -- Additional number Alpha String.
///
/// Linear-fixed, 2 records of 16 bytes. Contains alpha identifiers for
/// additional numbers (ANR). Referenced by ANR AAS record identifier.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.7](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A307%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C222%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_AAS: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F38),
    None,
    16, 2,
    &PB_EF_AAS_DATA,
);

// EF_GAS data: 2 records of 16 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_GAS_DATA: [u8; 32] = [0xFF; 32];

/// EF.GAS (4F39) -- Grouping information Alpha String.
///
/// Linear-fixed, 2 records of 16 bytes. Contains alpha identifiers for
/// groups. Referenced by GRP group association record number.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.8](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A309%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C535%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_GAS: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F39),
    None,
    16, 2,
    &PB_EF_GAS_DATA,
);

// EF_CCP1 data: 2 records of 15 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_CCP1_DATA: [u8; 30] = [0xFF; 30];

/// EF.CCP1 (4F3A) -- Capability Configuration Parameters 1.
///
/// Linear-fixed, 2 records of 15 bytes. Contains bearer capability
/// information element per TS 24.008.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.11](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A315%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C576%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_CCP1: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F3A),
    None,
    15, 2,
    &PB_EF_CCP1_DATA,
);

// EF_UID data: 5 records of 2 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_UID_DATA: [u8; 10] = [0xFF; 10];

/// EF.UID (4F3B) -- Unique Identifier.
///
/// Linear-fixed, 5 records of 2 bytes. Each record contains a 16-bit
/// unique identifier for phonebook synchronization.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.12.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A315%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C176%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_UID: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F3B),
    None,
    2, 5,
    &PB_EF_UID_DATA,
);

// EF_EMAIL data: 5 records of 32 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_EMAIL_DATA: [u8; 160] = [0xFF; 160];

/// EF.EMAIL (4F3C) -- e-mail address.
///
/// Linear-fixed, 5 records of 32 bytes. Contains email address associated
/// with a phonebook entry.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.13](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A321%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C400%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_EMAIL: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F3C),
    None,
    32, 5,
    &PB_EF_EMAIL_DATA,
);

// EF_PURI data: 2 records of 32 bytes.
#[cfg(feature = "profile-full")]
static PB_EF_PURI_DATA: [u8; 64] = [0xFF; 64];

/// EF.PURI (4F3D) -- Phonebook URIs.
///
/// Linear-fixed, 2 records of 32 bytes. Contains URI associated with
/// a phonebook entry.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.15](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A323%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C320%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_PURI: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F3D),
    None,
    32, 2,
    &PB_EF_PURI_DATA,
);

/// EF.PSC (4F22) -- Phone book Synchronisation Counter.
///
/// Transparent, 4 bytes. 32-bit counter incremented on each phonebook
/// modification. Fixed FID per spec.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.12.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A317%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C455%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_PSC: EfDef = EfDef::transparent(
    Fid::new(0x4F22),
    None,
    &[0x00, 0x00, 0x00, 0x00],
);

/// EF.CC (4F23) -- Change Counter.
///
/// Transparent, 2 bytes. 16-bit counter incremented on each phonebook
/// change (add/delete/modify). Fixed FID per spec.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.12.3](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A319%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C413%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_CC: EfDef = EfDef::transparent(
    Fid::new(0x4F23),
    None,
    &[0x00, 0x00],
);

/// EF.PUID (4F24) -- Previous Unique Identifier.
///
/// Transparent, 2 bytes. Contains the highest UID value that has been
/// used. Fixed FID per spec.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2.12.4](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A321%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C744%5D).
#[cfg(feature = "profile-full")]
pub static PB_EF_PUID: EfDef = EfDef::transparent(
    Fid::new(0x4F24),
    None,
    &[0x00, 0x00],
);

/// DF.PHONEBOOK (5F3A) -- Phonebook sub-DF under ADF.USIM.
///
/// Contains the USIM phonebook file set: EF_PBR (reference file),
/// EF_ADN, EF_EXT1, EF_IAP, EF_PBC, EF_ANR, EF_SNE, EF_GRP, EF_AAS,
/// EF_GAS, EF_CCP1, EF_UID, EF_EMAIL, EF_PURI, and synchronization
/// files EF_PSC, EF_CC, EF_PUID. FIDs for ADN-linked EFs are card-assigned
/// and referenced through EF_PBR TLV entries; PSC/CC/PUID have fixed FIDs.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A289%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C644%5D).
#[cfg(feature = "profile-full")]
pub static DF_PHONEBOOK: DfDef = DfDef {
    fid: Fid::new(0x5F3A),
    children: &[
        FileRef::Ef(&PB_EF_PBR),
        FileRef::Ef(&PB_EF_ADN),
        FileRef::Ef(&PB_EF_EXT1),
        FileRef::Ef(&PB_EF_IAP),
        FileRef::Ef(&PB_EF_PBC),
        FileRef::Ef(&PB_EF_ANR),
        FileRef::Ef(&PB_EF_SNE),
        FileRef::Ef(&PB_EF_GRP),
        FileRef::Ef(&PB_EF_AAS),
        FileRef::Ef(&PB_EF_GAS),
        FileRef::Ef(&PB_EF_CCP1),
        FileRef::Ef(&PB_EF_UID),
        FileRef::Ef(&PB_EF_EMAIL),
        FileRef::Ef(&PB_EF_PURI),
        FileRef::Ef(&PB_EF_PSC),
        FileRef::Ef(&PB_EF_CC),
        FileRef::Ef(&PB_EF_PUID),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F22, // PB_EF_PSC
    0x4F23, // PB_EF_CC
    0x4F24, // PB_EF_PUID
    0x4F30, // PB_EF_PBR
    0x4F31, // PB_EF_ADN
    0x4F32, // PB_EF_EXT1
    0x4F33, // PB_EF_IAP
    0x4F34, // PB_EF_PBC
    0x4F35, // PB_EF_ANR
    0x4F36, // PB_EF_SNE
    0x4F37, // PB_EF_GRP
    0x4F38, // PB_EF_AAS
    0x4F39, // PB_EF_GAS
    0x4F3A, // PB_EF_CCP1
    0x4F3B, // PB_EF_UID
    0x4F3C, // PB_EF_EMAIL
    0x4F3D, // PB_EF_PURI
]);

// ---------------------------------------------------------------------------
// DF.GSM-ACCESS (5F3B) under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

/// EF.Kc (4F20) -- GSM Ciphering Key Kc.
///
/// 9-byte transparent EF. Bytes 0-7: Kc. Byte 8: CKSN.
/// Default: empty key, CKSN = 7 (no key).
/// [3GPP TS 31.102 V19.4.0 clause 4.4.3](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A325%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C334%5D).
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
/// [3GPP TS 31.102 V19.4.0 clause 4.4.4](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A331%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C358%5D).
#[cfg(feature = "profile-full")]
pub static EF_KC_GPRS: EfDef = EfDef::transparent(
    Fid::new(0x4F52),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07],
);

/// DF.GSM-ACCESS (5F3B) -- GSM Access sub-DF under ADF.USIM.
///
/// Contains EF.Kc and EF.KcGPRS for GSM/GPRS access.
/// [3GPP TS 31.102 V19.4.0 clause 4.4](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A281%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C705%5D).
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
/// TLV-structured transparent EF per TS 31.102 V19.4.0 clause 4.4.11.8.
///
/// Contains two data objects:
/// - Protection Scheme Identifier List (tag 0xA0): list of (scheme_id, key_index) pairs
/// - Home Network Public Key List (tag 0xA1, conditional): list of (key_id, key) entries
///
/// Default: null scheme only (scheme=0x00, key_index=0x00, no HN public key list).
static EF_SUCI_CALC_INFO_DATA: [u8; 80] = {
    let mut d = [0xFF; 80];
    d[0] = 0xA0; // Protection Scheme Identifier List tag
    d[1] = 0x02; // length
    d[2] = 0x00; // protection scheme identifier (0x00 = null scheme)
    d[3] = 0x00; // home network public key index (0x00 = none)
    // Bytes 4..80 are 0xFF padding, available for Profile A/B key provisioning
    // via UPDATE BINARY. See TS 31.102 V19.4.0 clause 4.4.11.8.
    d
};

/// EF.SUCI_Calc_Info (4F07) -- SUCI calculation info.
///
/// Transparent, TLV-structured. Service 124, Rel-15.
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

/// EF.MCHPPLMN (4F15) -- Multiplier Coefficient for Higher Priority PLMN search.
///
/// Transparent, 1 byte. Default: 0x0A (multiplier = 10).
/// Multiplier N used to extend HPPLMN search period: T_search = N * T_HPPLMN.
/// UST service 144, Rel-18.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.11.20].
pub static EF_MCHPPLMN: EfDef = EfDef::transparent(
    Fid::new(0x4F15),
    Some(Sfi::new(0x15)),
    &[0x0A],
);

/// EF.KAUSF_DERIVATION (4F16) -- KAUSF Derivation Configuration.
///
/// Transparent, 1 byte. Default: 0x00 (default derivation).
/// Contains configuration for KAUSF key derivation method.
/// UST service 145, Rel-18.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.11.21].
pub static EF_KAUSF_DERIVATION: EfDef = EfDef::transparent(
    Fid::new(0x4F16),
    Some(Sfi::new(0x16)),
    &[0x00],
);

/// DF.5GS (5FC0) -- 5G System dedicated file.
///
/// Contains all Rel-15 through Rel-18 5G SA Elementary Files per TS 31.102.
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
        FileRef::Ef(&EF_MCHPPLMN),
        FileRef::Ef(&EF_KAUSF_DERIVATION),
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
    0x4F15, // EF_MCHPPLMN
    0x4F16, // EF_KAUSF_DERIVATION
]);

// ---------------------------------------------------------------------------
// EFs under DF_SNPN (5FE0)
// ---------------------------------------------------------------------------

/// EF.PWS_SNPN (4F01) -- Public Warning System for SNPN.
///
/// Transparent, 1 byte. Default: 0x00 (no PWS configured).
/// Contains PWS configuration for standalone non-public networks.
/// UST service 143.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.12.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A471%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C629%5D).
#[cfg(feature = "profile-full")]
pub static EF_PWS_SNPN: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    Some(Sfi::new(1)),
    &[0x00],
);

// EF_NID data: 1 record of 6 bytes.
#[cfg(feature = "profile-full")]
static EF_NID_DATA: [u8; 6] = [0xFF; 6];

/// EF.NID (4F02) -- Network Identifier.
///
/// Linear-fixed, 1 record of 6 bytes. Default: 0xFF (empty).
/// Contains SNPN network identifiers (NID values).
/// UST service 146.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.12.3](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A471%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C244%5D).
#[cfg(feature = "profile-full")]
pub static EF_NID: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F02),
    Some(Sfi::new(2)),
    6, 1,
    &EF_NID_DATA,
);

/// DF.SNPN (5FE0) -- Standalone Non-Public Network dedicated file.
///
/// Contains SNPN-related EFs per TS 31.102. UST service 143.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.12](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A471%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
#[cfg(feature = "profile-full")]
pub static DF_SNPN: DfDef = DfDef {
    fid: Fid::new(0x5FE0),
    children: &[
        FileRef::Ef(&EF_PWS_SNPN),
        FileRef::Ef(&EF_NID),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // EF_PWS_SNPN
    0x4F02, // EF_NID
]);

// ---------------------------------------------------------------------------
// EFs under DF_5G_ProSe (5FF0)
// ---------------------------------------------------------------------------

/// EF.5G_PROSE_ST (4F01) -- 5G ProSe Service Table.
///
/// Transparent, 2 bytes. Default: 0x00 (all ProSe services disabled).
/// Contains service bitmap for 5G ProSe features.
/// UST service 139.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A475%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C608%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_ST: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    Some(Sfi::new(1)),
    &[0x00, 0x00],
);

/// EF.5G_PROSE_DD (4F02) -- 5G ProSe Direct Discovery.
///
/// Transparent, 26 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded 5G ProSe direct discovery configuration.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.3](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A477%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C690%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_DD: EfDef = EfDef::transparent(
    Fid::new(0x4F02),
    Some(Sfi::new(2)),
    &[0xFF; 26],
);

/// EF.5G_PROSE_DC (4F03) -- 5G ProSe Direct Communication.
///
/// Transparent, 12 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded 5G ProSe direct communication configuration.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.4](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A483%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C783%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_DC: EfDef = EfDef::transparent(
    Fid::new(0x4F03),
    Some(Sfi::new(3)),
    &[0xFF; 12],
);

/// EF.5G_PROSE_U2NRU (4F04) -- 5G ProSe UE-to-Network Relay UE.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for UE-to-network relay UE role.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.5](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A487%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C290%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_U2NRU: EfDef = EfDef::transparent(
    Fid::new(0x4F04),
    Some(Sfi::new(4)),
    &[0xFF; 32],
);

/// EF.5G_PROSE_RU (4F05) -- 5G ProSe Remote UE.
///
/// Transparent, 29 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for remote UE role.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.6](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A495%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C290%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_RU: EfDef = EfDef::transparent(
    Fid::new(0x4F05),
    Some(Sfi::new(5)),
    &[0xFF; 29],
);

/// EF.5G_PROSE_UIR (4F06) -- 5G ProSe Usage Information Reporting.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for ProSe usage information reporting.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.7](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A503%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C471%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_UIR: EfDef = EfDef::transparent(
    Fid::new(0x4F06),
    Some(Sfi::new(6)),
    &[0xFF; 32],
);

/// EF.5G_PROSE_U2URU (4F07) -- 5G ProSe UE-to-UE Relay UE.
///
/// Transparent, 46 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for UE-to-UE relay UE role.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.8](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A507%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C315%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_U2URU: EfDef = EfDef::transparent(
    Fid::new(0x4F07),
    Some(Sfi::new(7)),
    &[0xFF; 46],
);

/// EF.5G_PROSE_EU (4F08) -- 5G ProSe End UE.
///
/// Transparent, 46 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for ProSe end UE role.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.9](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A513%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C532%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_EU: EfDef = EfDef::transparent(
    Fid::new(0x4F08),
    Some(Sfi::new(8)),
    &[0xFF; 46],
);

/// EF.5G_PROSE_MU2NRU (4F09) -- 5G ProSe Multi-hop UE-to-Network Relay UE.
///
/// Transparent, 46 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for multi-hop UE-to-network relay UE.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.10](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A519%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C783%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_MU2NRU: EfDef = EfDef::transparent(
    Fid::new(0x4F09),
    Some(Sfi::new(9)),
    &[0xFF; 46],
);

/// EF.5G_PROSE_IMU2NRU (4F0A) -- 5G ProSe Intermediate UE-to-Network Relay UE.
///
/// Transparent, 46 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for intermediate multi-hop relay UE.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.11](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A525%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C270%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_IMU2NRU: EfDef = EfDef::transparent(
    Fid::new(0x4F0A),
    Some(Sfi::new(0x0A)),
    &[0xFF; 46],
);

/// EF.5G_PROSE_MRU (4F0B) -- 5G ProSe Multi-hop Remote UE.
///
/// Transparent, 29 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for multi-hop remote UE role.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.12](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A533%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C270%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_MRU: EfDef = EfDef::transparent(
    Fid::new(0x4F0B),
    Some(Sfi::new(0x0B)),
    &[0xFF; 29],
);

/// EF.5G_PROSE_MU2URU (4F0C) -- 5G ProSe Multi-hop UE-to-UE Relay UE.
///
/// Transparent, 46 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for multi-hop UE-to-UE relay UE.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.13](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A541%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C407%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_MU2URU: EfDef = EfDef::transparent(
    Fid::new(0x4F0C),
    Some(Sfi::new(0x0C)),
    &[0xFF; 46],
);

/// EF.5G_PROSE_MEU (4F0D) -- 5G ProSe Multi-hop End UE.
///
/// Transparent, 46 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded configuration for multi-hop end UE role.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13.14](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A547%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C783%5D).
#[cfg(feature = "profile-full")]
pub static EF_5G_PROSE_MEU: EfDef = EfDef::transparent(
    Fid::new(0x4F0D),
    Some(Sfi::new(0x0D)),
    &[0xFF; 46],
);

/// DF.5G_ProSe (5FF0) -- 5G Proximity Services dedicated file.
///
/// Contains 13 EFs for 5G ProSe configuration per TS 31.102.
/// UST service 139. Rel-17.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.13](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A475%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C641%5D).
#[cfg(feature = "profile-full")]
pub static DF_5G_PROSE: DfDef = DfDef {
    fid: Fid::new(0x5FF0),
    children: &[
        FileRef::Ef(&EF_5G_PROSE_ST),
        FileRef::Ef(&EF_5G_PROSE_DD),
        FileRef::Ef(&EF_5G_PROSE_DC),
        FileRef::Ef(&EF_5G_PROSE_U2NRU),
        FileRef::Ef(&EF_5G_PROSE_RU),
        FileRef::Ef(&EF_5G_PROSE_UIR),
        FileRef::Ef(&EF_5G_PROSE_U2URU),
        FileRef::Ef(&EF_5G_PROSE_EU),
        FileRef::Ef(&EF_5G_PROSE_MU2NRU),
        FileRef::Ef(&EF_5G_PROSE_IMU2NRU),
        FileRef::Ef(&EF_5G_PROSE_MRU),
        FileRef::Ef(&EF_5G_PROSE_MU2URU),
        FileRef::Ef(&EF_5G_PROSE_MEU),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // EF_5G_PROSE_ST
    0x4F02, // EF_5G_PROSE_DD
    0x4F03, // EF_5G_PROSE_DC
    0x4F04, // EF_5G_PROSE_U2NRU
    0x4F05, // EF_5G_PROSE_RU
    0x4F06, // EF_5G_PROSE_UIR
    0x4F07, // EF_5G_PROSE_U2URU
    0x4F08, // EF_5G_PROSE_EU
    0x4F09, // EF_5G_PROSE_MU2NRU
    0x4F0A, // EF_5G_PROSE_IMU2NRU
    0x4F0B, // EF_5G_PROSE_MRU
    0x4F0C, // EF_5G_PROSE_MU2URU
    0x4F0D, // EF_5G_PROSE_MEU
]);

// ---------------------------------------------------------------------------
// EFs under DF_5MBSUECONFIG (5FF1)
// ---------------------------------------------------------------------------

/// EF.5MBSUECONFIG (4F01) -- 5MBS UE Pre-configuration.
///
/// Transparent, 4 bytes. Default: 0xFF (unprovisioned).
/// Contains TLV-coded PLMN 5MBS pre-configuration data objects.
/// UST service 147.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.14.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A551%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C283%5D).
#[cfg(feature = "profile-full")]
pub static EF_5MBS_CONFIG: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// EF.5MBSUSD (4F08) -- 5MBS User Service Description.
///
/// Transparent, 4 bytes. Default: 0xFF (unprovisioned).
/// Contains USD TLV data object for one 5MBS user service. FID range
/// 4FXX where XX>7; 4F08 is the first valid instance.
/// UST service 147.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.14.3](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A557%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C159%5D).
#[cfg(feature = "profile-full")]
pub static EF_5MBS_USD: EfDef = EfDef::transparent(
    Fid::new(0x4F08),
    None,
    &[0xFF, 0xFF, 0xFF, 0xFF],
);

/// DF.5MBSUECONFIG (5FF1) -- 5G Multicast/Broadcast UE configuration.
///
/// Contains 5MBS pre-configuration and user service description EFs.
/// UST service 147.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.14](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A551%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C386%5D).
#[cfg(feature = "profile-full")]
pub static DF_5MBSUECONFIG: DfDef = DfDef {
    fid: Fid::new(0x5FF1),
    children: &[
        FileRef::Ef(&EF_5MBS_CONFIG),
        FileRef::Ef(&EF_5MBS_USD),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // EF_5MBS_CONFIG
    0x4F08, // EF_5MBS_USD
]);

// ---------------------------------------------------------------------------
// DF.WLAN (5F40) under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

/// EF.Pseudo (4F01) -- WLAN Pseudonym.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains pseudonym identity for WLAN access authentication.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.2].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_PSEUDO: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    Some(Sfi::new(1)),
    &[0xFF; 32],
);

/// EF.UPLMNWLAN (4F02) -- User controlled PLMN selector for I-WLAN.
///
/// Transparent, 12 bytes. Default: 0xFF (empty list).
/// Contains user-preferred PLMN list for WLAN interworking.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.3].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_UPLMNWLAN: EfDef = EfDef::transparent(
    Fid::new(0x4F02),
    Some(Sfi::new(2)),
    &[0xFF; 12],
);

/// EF.OPLMNWLAN (4F03) -- Operator controlled PLMN selector for I-WLAN.
///
/// Transparent, 12 bytes. Default: 0xFF (empty list).
/// Contains operator-preferred PLMN list for WLAN interworking.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.4].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_OPLMNWLAN: EfDef = EfDef::transparent(
    Fid::new(0x4F03),
    Some(Sfi::new(3)),
    &[0xFF; 12],
);

/// EF.UWSIDL (4F04) -- User controlled WLAN Specific Identifier List.
///
/// Transparent, 32 bytes. Default: 0xFF (empty list).
/// Contains user-preferred WLAN specific identifiers (SSIDs).
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.5].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_UWSIDL: EfDef = EfDef::transparent(
    Fid::new(0x4F04),
    Some(Sfi::new(4)),
    &[0xFF; 32],
);

/// EF.OWSIDL (4F05) -- Operator controlled WLAN Specific Identifier List.
///
/// Transparent, 32 bytes. Default: 0xFF (empty list).
/// Contains operator-preferred WLAN specific identifiers (SSIDs).
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.6].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_OWSIDL: EfDef = EfDef::transparent(
    Fid::new(0x4F05),
    Some(Sfi::new(5)),
    &[0xFF; 32],
);

/// EF.WRI (4F06) -- WLAN Reauthentication Identity.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains reauthentication identity for fast re-auth in EAP-SIM/AKA.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.7].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_WRI: EfDef = EfDef::transparent(
    Fid::new(0x4F06),
    Some(Sfi::new(6)),
    &[0xFF; 32],
);

/// EF.HWSIDL (4F07) -- Home I-WLAN Specific Identifier List.
///
/// Transparent, 32 bytes. Default: 0xFF (empty list).
/// Contains home PLMN WLAN specific identifiers.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.8].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_HWSIDL: EfDef = EfDef::transparent(
    Fid::new(0x4F07),
    Some(Sfi::new(7)),
    &[0xFF; 32],
);

/// EF.WEHPLMNPI (4F08) -- I-WLAN EHPLMN Presentation Indication.
///
/// Transparent, 1 byte. Default: 0x00 (EHPLMN not presented).
/// Bit 1: display EHPLMN in WLAN network selection (0=no, 1=yes).
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.9].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_WEHPLMNPI: EfDef = EfDef::transparent(
    Fid::new(0x4F08),
    Some(Sfi::new(8)),
    &[0x00],
);

/// EF.WHPI (4F09) -- I-WLAN HPLMN Priority Indication.
///
/// Transparent, 1 byte. Default: 0x00 (no HPLMN priority).
/// Bit 1: HPLMN priority in WLAN (0=no priority, 1=priority).
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.10].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_WHPI: EfDef = EfDef::transparent(
    Fid::new(0x4F09),
    Some(Sfi::new(9)),
    &[0x00],
);

/// EF.WLRPLMN (4F0A) -- I-WLAN Last Registered PLMN.
///
/// Transparent, 3 bytes. Default: 0xFF (no RPLMN).
/// Contains the last registered PLMN for WLAN access (3-byte PLMN ID).
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.11].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_WLRPLMN: EfDef = EfDef::transparent(
    Fid::new(0x4F0A),
    Some(Sfi::new(0x0A)),
    &[0xFF, 0xFF, 0xFF],
);

/// EF.HPLMNDAI (4F0B) -- HPLMN Direct Access Indicator.
///
/// Transparent, 1 byte. Default: 0x00 (no direct access).
/// Bit 1: direct access to HPLMN I-WLAN indicator.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5.12].
#[cfg(feature = "profile-full")]
pub static WLAN_EF_HPLMNDAI: EfDef = EfDef::transparent(
    Fid::new(0x4F0B),
    Some(Sfi::new(0x0B)),
    &[0x00],
);

/// DF.WLAN (5F40) -- I-WLAN sub-DF under ADF.USIM.
///
/// Contains 11 EFs for WLAN interworking configuration.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.5].
#[cfg(feature = "profile-full")]
pub static DF_WLAN: DfDef = DfDef {
    fid: Fid::new(0x5F40),
    children: &[
        FileRef::Ef(&WLAN_EF_PSEUDO),
        FileRef::Ef(&WLAN_EF_UPLMNWLAN),
        FileRef::Ef(&WLAN_EF_OPLMNWLAN),
        FileRef::Ef(&WLAN_EF_UWSIDL),
        FileRef::Ef(&WLAN_EF_OWSIDL),
        FileRef::Ef(&WLAN_EF_WRI),
        FileRef::Ef(&WLAN_EF_HWSIDL),
        FileRef::Ef(&WLAN_EF_WEHPLMNPI),
        FileRef::Ef(&WLAN_EF_WHPI),
        FileRef::Ef(&WLAN_EF_WLRPLMN),
        FileRef::Ef(&WLAN_EF_HPLMNDAI),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // WLAN_EF_PSEUDO
    0x4F02, // WLAN_EF_UPLMNWLAN
    0x4F03, // WLAN_EF_OPLMNWLAN
    0x4F04, // WLAN_EF_UWSIDL
    0x4F05, // WLAN_EF_OWSIDL
    0x4F06, // WLAN_EF_WRI
    0x4F07, // WLAN_EF_HWSIDL
    0x4F08, // WLAN_EF_WEHPLMNPI
    0x4F09, // WLAN_EF_WHPI
    0x4F0A, // WLAN_EF_WLRPLMN
    0x4F0B, // WLAN_EF_HPLMNDAI
]);

// ---------------------------------------------------------------------------
// DF.HNB (5F50) under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

/// EF.ACSGL (4F01) -- Allowed CSG Lists.
///
/// Transparent, 32 bytes. Default: 0xFF (empty list).
/// Contains allowed Closed Subscriber Group lists with associated PLMNs.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.6.2].
#[cfg(feature = "profile-full")]
pub static HNB_EF_ACSGL: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    Some(Sfi::new(1)),
    &[0xFF; 32],
);

// EF_CSGT data: 2 records of 32 bytes.
#[cfg(feature = "profile-full")]
static HNB_EF_CSGT_DATA: [u8; 64] = [0xFF; 64];

/// EF.CSGT (4F02) -- CSG Type.
///
/// Linear-fixed, 2 records of 32 bytes. Default: 0xFF (empty).
/// Contains CSG Type identifiers for display purposes.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.6.3].
#[cfg(feature = "profile-full")]
pub static HNB_EF_CSGT: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F02),
    Some(Sfi::new(2)),
    32, 2,
    &HNB_EF_CSGT_DATA,
);

// EF_HNBN data: 2 records of 32 bytes.
#[cfg(feature = "profile-full")]
static HNB_EF_HNBN_DATA: [u8; 64] = [0xFF; 64];

/// EF.HNBN (4F03) -- Home NodeB Name.
///
/// Linear-fixed, 2 records of 32 bytes. Default: 0xFF (empty).
/// Contains Home NodeB/eNodeB names for display.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.6.4].
#[cfg(feature = "profile-full")]
pub static HNB_EF_HNBN: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F03),
    Some(Sfi::new(3)),
    32, 2,
    &HNB_EF_HNBN_DATA,
);

/// EF.OCSGL (4F04) -- Operator CSG Lists.
///
/// Transparent, 32 bytes. Default: 0xFF (empty list).
/// Contains operator-controlled Closed Subscriber Group lists.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.6.5].
#[cfg(feature = "profile-full")]
pub static HNB_EF_OCSGL: EfDef = EfDef::transparent(
    Fid::new(0x4F04),
    Some(Sfi::new(4)),
    &[0xFF; 32],
);

// EF_OCSGT data: 2 records of 32 bytes.
#[cfg(feature = "profile-full")]
static HNB_EF_OCSGT_DATA: [u8; 64] = [0xFF; 64];

/// EF.OCSGT (4F05) -- Operator CSG Type.
///
/// Linear-fixed, 2 records of 32 bytes. Default: 0xFF (empty).
/// Contains operator CSG Type identifiers for display.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.6.6].
#[cfg(feature = "profile-full")]
pub static HNB_EF_OCSGT: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F05),
    Some(Sfi::new(5)),
    32, 2,
    &HNB_EF_OCSGT_DATA,
);

// EF_OHNBN data: 2 records of 32 bytes.
#[cfg(feature = "profile-full")]
static HNB_EF_OHNBN_DATA: [u8; 64] = [0xFF; 64];

/// EF.OHNBN (4F06) -- Operator Home NodeB Name.
///
/// Linear-fixed, 2 records of 32 bytes. Default: 0xFF (empty).
/// Contains operator Home NodeB names for display.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.6.7].
#[cfg(feature = "profile-full")]
pub static HNB_EF_OHNBN: EfDef = EfDef::linear_fixed(
    Fid::new(0x4F06),
    Some(Sfi::new(6)),
    32, 2,
    &HNB_EF_OHNBN_DATA,
);

/// DF.HNB (5F50) -- Home NodeB sub-DF under ADF.USIM.
///
/// Contains 6 EFs for CSG and Home NodeB/eNodeB configuration.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.6].
#[cfg(feature = "profile-full")]
pub static DF_HNB: DfDef = DfDef {
    fid: Fid::new(0x5F50),
    children: &[
        FileRef::Ef(&HNB_EF_ACSGL),
        FileRef::Ef(&HNB_EF_CSGT),
        FileRef::Ef(&HNB_EF_HNBN),
        FileRef::Ef(&HNB_EF_OCSGL),
        FileRef::Ef(&HNB_EF_OCSGT),
        FileRef::Ef(&HNB_EF_OHNBN),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // HNB_EF_ACSGL
    0x4F02, // HNB_EF_CSGT
    0x4F03, // HNB_EF_HNBN
    0x4F04, // HNB_EF_OCSGL
    0x4F05, // HNB_EF_OCSGT
    0x4F06, // HNB_EF_OHNBN
]);

// ---------------------------------------------------------------------------
// DF.ProSe (5F90) under ADF.USIM -- full tier (legacy Rel-12)
// ---------------------------------------------------------------------------

/// EF.PROSE_MON (4F01) -- ProSe Monitoring Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains parameters for ProSe direct discovery monitoring.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.2].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_MON: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    Some(Sfi::new(1)),
    &[0xFF; 32],
);

/// EF.PROSE_ANN (4F02) -- ProSe Announcing Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains parameters for ProSe direct discovery announcing.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.3].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_ANN: EfDef = EfDef::transparent(
    Fid::new(0x4F02),
    Some(Sfi::new(2)),
    &[0xFF; 32],
);

/// EF.PROSEFUNC (4F03) -- HPLMN ProSe Function.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains address of HPLMN ProSe Function for D2D services.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.4].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_FUNC: EfDef = EfDef::transparent(
    Fid::new(0x4F03),
    Some(Sfi::new(3)),
    &[0xFF; 32],
);

/// EF.PROSE_RADIO_COM (4F04) -- ProSe Direct Communication Radio Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains radio parameters for ProSe direct communication.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.5].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_RADIO_COM: EfDef = EfDef::transparent(
    Fid::new(0x4F04),
    Some(Sfi::new(4)),
    &[0xFF; 32],
);

/// EF.PROSE_RADIO_MON (4F05) -- ProSe Direct Discovery Monitoring Radio Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains radio parameters for ProSe discovery monitoring.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.6].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_RADIO_MON: EfDef = EfDef::transparent(
    Fid::new(0x4F05),
    Some(Sfi::new(5)),
    &[0xFF; 32],
);

/// EF.PROSE_RADIO_ANN (4F06) -- ProSe Direct Discovery Announcing Radio Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains radio parameters for ProSe discovery announcing.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.7].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_RADIO_ANN: EfDef = EfDef::transparent(
    Fid::new(0x4F06),
    Some(Sfi::new(6)),
    &[0xFF; 32],
);

/// EF.PROSE_POLICY (4F07) -- ProSe Policy Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains ProSe policy parameters for D2D operation.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.8].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_POLICY: EfDef = EfDef::transparent(
    Fid::new(0x4F07),
    Some(Sfi::new(7)),
    &[0xFF; 32],
);

/// EF.PROSE_PLMN (4F08) -- ProSe PLMN Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains per-PLMN ProSe configuration parameters.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.9].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_PLMN: EfDef = EfDef::transparent(
    Fid::new(0x4F08),
    Some(Sfi::new(8)),
    &[0xFF; 32],
);

/// EF.PROSE_GC (4F09) -- ProSe Group Counter.
///
/// Transparent, 4 bytes. Default: 0x00000000 (counter = 0).
/// Contains 32-bit group counter for ProSe group management.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.10].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_GC: EfDef = EfDef::transparent(
    Fid::new(0x4F09),
    Some(Sfi::new(9)),
    &[0x00, 0x00, 0x00, 0x00],
);

/// EF.PST (4F0A) -- ProSe Service Table.
///
/// Transparent, 1 byte. Default: 0x00 (all services disabled).
/// Contains bitmap of available ProSe services.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.11].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_PST: EfDef = EfDef::transparent(
    Fid::new(0x4F0A),
    Some(Sfi::new(0x0A)),
    &[0x00],
);

/// EF.PROSE_GM_DISCOVERY (4F0B) -- ProSe Group Member Discovery Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains parameters for ProSe group member discovery.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.12].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_GM_DISCOVERY: EfDef = EfDef::transparent(
    Fid::new(0x4F0B),
    Some(Sfi::new(0x0B)),
    &[0xFF; 32],
);

/// EF.PROSE_RELAY (4F0C) -- ProSe Relay Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains ProSe UE-to-network relay parameters.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.13].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_RELAY: EfDef = EfDef::transparent(
    Fid::new(0x4F0C),
    Some(Sfi::new(0x0C)),
    &[0xFF; 32],
);

/// EF.PROSE_RELAY_DISCOVERY (4F0D) -- ProSe Relay Discovery Parameters.
///
/// Transparent, 32 bytes. Default: 0xFF (unprovisioned).
/// Contains ProSe relay discovery parameters.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8.14].
#[cfg(feature = "profile-full")]
pub static PROSE_EF_RELAY_DISCOVERY: EfDef = EfDef::transparent(
    Fid::new(0x4F0D),
    Some(Sfi::new(0x0D)),
    &[0xFF; 32],
);

/// DF.ProSe (5F90) -- Proximity Services sub-DF under ADF.USIM.
///
/// Contains 13 EFs for legacy ProSe D2D configuration (Rel-12).
/// UST service 108.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.8].
#[cfg(feature = "profile-full")]
pub static DF_PROSE: DfDef = DfDef {
    fid: Fid::new(0x5F90),
    children: &[
        FileRef::Ef(&PROSE_EF_MON),
        FileRef::Ef(&PROSE_EF_ANN),
        FileRef::Ef(&PROSE_EF_FUNC),
        FileRef::Ef(&PROSE_EF_RADIO_COM),
        FileRef::Ef(&PROSE_EF_RADIO_MON),
        FileRef::Ef(&PROSE_EF_RADIO_ANN),
        FileRef::Ef(&PROSE_EF_POLICY),
        FileRef::Ef(&PROSE_EF_PLMN),
        FileRef::Ef(&PROSE_EF_GC),
        FileRef::Ef(&PROSE_EF_PST),
        FileRef::Ef(&PROSE_EF_GM_DISCOVERY),
        FileRef::Ef(&PROSE_EF_RELAY),
        FileRef::Ef(&PROSE_EF_RELAY_DISCOVERY),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // PROSE_EF_MON
    0x4F02, // PROSE_EF_ANN
    0x4F03, // PROSE_EF_FUNC
    0x4F04, // PROSE_EF_RADIO_COM
    0x4F05, // PROSE_EF_RADIO_MON
    0x4F06, // PROSE_EF_RADIO_ANN
    0x4F07, // PROSE_EF_POLICY
    0x4F08, // PROSE_EF_PLMN
    0x4F09, // PROSE_EF_GC
    0x4F0A, // PROSE_EF_PST
    0x4F0B, // PROSE_EF_GM_DISCOVERY
    0x4F0C, // PROSE_EF_RELAY
    0x4F0D, // PROSE_EF_RELAY_DISCOVERY
]);

// ---------------------------------------------------------------------------
// DF.ACDC (5FA0) under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

/// EF.ACDC_LIST (4F01) -- ACDC Category List.
///
/// Transparent, 32 bytes. Default: 0xFF (empty).
/// Contains TLV-coded ACDC OS configuration data objects identifying
/// application categories for Application specific Congestion control.
/// UST service 112.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.9.2].
#[cfg(feature = "profile-full")]
pub static ACDC_EF_LIST: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    Some(Sfi::new(1)),
    &[0xFF; 32],
);

/// EF.ACDC_OS_CONFIG (4F02) -- ACDC OS-specific Application Configuration.
///
/// Transparent, 32 bytes. Default: 0xFF (empty).
/// Contains TLV-coded ACDC application identifier data objects for
/// OS-specific application identification.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.9.3].
#[cfg(feature = "profile-full")]
pub static ACDC_EF_OS_CONFIG: EfDef = EfDef::transparent(
    Fid::new(0x4F02),
    Some(Sfi::new(2)),
    &[0xFF; 32],
);

/// DF.ACDC (5FA0) -- Application specific Congestion control for Data Communication.
///
/// Contains 2 EFs for ACDC configuration.
/// UST service 112.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.9].
#[cfg(feature = "profile-full")]
pub static DF_ACDC: DfDef = DfDef {
    fid: Fid::new(0x5FA0),
    children: &[
        FileRef::Ef(&ACDC_EF_LIST),
        FileRef::Ef(&ACDC_EF_OS_CONFIG),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // ACDC_EF_LIST
    0x4F02, // ACDC_EF_OS_CONFIG
]);

// ---------------------------------------------------------------------------
// DF.TV (5FB0) under ADF.USIM -- full tier
// ---------------------------------------------------------------------------

/// EF.TVUSD (4F01) -- TV User Service Description.
///
/// Transparent, 32 bytes. Default: 0xFF (empty).
/// Contains TV user service description TLV data objects.
/// UST service 116.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.10.2].
#[cfg(feature = "profile-full")]
pub static TV_EF_TVUSD: EfDef = EfDef::transparent(
    Fid::new(0x4F01),
    None,
    &[0xFF; 32],
);

/// DF.TV (5FB0) -- TV Service Configuration sub-DF under ADF.USIM.
///
/// Contains 1 EF for TV user service description.
/// UST service 116.
/// [3GPP TS 31.102 V19.4.0 clause 4.4.10].
#[cfg(feature = "profile-full")]
pub static DF_TV: DfDef = DfDef {
    fid: Fid::new(0x5FB0),
    children: &[
        FileRef::Ef(&TV_EF_TVUSD),
    ],
};

#[cfg(feature = "profile-full")]
const _: () = simrs_fs::assert_fids_unique(&[
    0x4F01, // TV_EF_TVUSD
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
static ADF_USIM_CHILDREN: [FileRef; 126] = [
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
    FileRef::Ef(&EF_EXT4),
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
    FileRef::Ef(&EF_HIDDENKEY),
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
    FileRef::Ef(&EF_VBSCA),
    FileRef::Ef(&EF_GBABP),
    FileRef::Ef(&EF_MSK),
    FileRef::Ef(&EF_MUK),
    FileRef::Ef(&EF_GBANL),
    FileRef::Ef(&EF_EHPLMNPI),
    FileRef::Ef(&EF_LRPLMNSI),
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
    // -- P0 additions (Rel-12 through Rel-19) --
    FileRef::Ef(&EF_ARR_USIM),
    FileRef::Ef(&EF_UICCIARI),
    FileRef::Ef(&EF_EPDG_ID),
    FileRef::Ef(&EF_EPDG_SELECTION),
    FileRef::Ef(&EF_3GPP_PS_DATA_OFF),
    FileRef::Ef(&EF_3GPP_PS_DATA_OFF_SVC),
    FileRef::Ef(&EF_EARFCN_LIST),
    FileRef::Ef(&EF_EAKA),
    FileRef::Ef(&EF_OPLMNWACT_LSP),
    FileRef::Ef(&EF_LSPPLMN),
    // -- P1 additions (remaining high-value) --
    FileRef::Ef(&EF_EPDG_ID_EM),
    FileRef::Ef(&EF_EPDG_SELECTION_EM),
    FileRef::Ef(&EF_IAL),
    FileRef::Ef(&EF_IPD),
    FileRef::Ef(&EF_OCST),
    // -- P2 additions (TS 31.103 cross-refs + niche) --
    FileRef::Ef(&EF_IMS_CONFIG_DATA),
    FileRef::Ef(&EF_TVCONFIG),
    FileRef::Ef(&EF_XCAP_CONFIG_DATA),
    FileRef::Ef(&EF_MUDMID_CONFIG_DATA),
    FileRef::Ef(&EF_AC_GBAUAPI),
    FileRef::Ef(&EF_IMSDCI),
    // -- sub-DFs --
    FileRef::Df(&DF_PHONEBOOK),
    FileRef::Df(&DF_5GS),
    FileRef::Df(&DF_GSM_ACCESS),
    FileRef::Df(&DF_SNPN),
    FileRef::Df(&DF_5G_PROSE),
    FileRef::Df(&DF_5MBSUECONFIG),
    FileRef::Df(&DF_WLAN),
    FileRef::Df(&DF_HNB),
    FileRef::Df(&DF_PROSE),
    FileRef::Df(&DF_ACDC),
    FileRef::Df(&DF_TV),
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
    0x6F55, // EF_EXT4
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
    0x6FC3, // EF_HIDDENKEY
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
    0x6FD5, // EF_VBSCA
    0x6FD6, // EF_GBABP
    0x6FD7, // EF_MSK
    0x6FD8, // EF_MUK
    0x6FDA, // EF_GBANL
    0x6FDB, // EF_EHPLMNPI
    0x6FDC, // EF_LRPLMNSI
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
    // -- P0 additions --
    0x6F01, // EF_EAKA
    0x6F06, // EF_ARR_USIM
    0x6F0C, // EF_OPLMNWACT_LSP
    0x6F0D, // EF_LSPPLMN
    0x6FE9, // EF_UICCIARI
    0x6FF3, // EF_EPDG_ID
    0x6FF4, // EF_EPDG_SELECTION
    0x6FF9, // EF_3GPP_PS_DATA_OFF
    0x6FFA, // EF_3GPP_PS_DATA_OFF_SVC
    0x6FFD, // EF_EARFCN_LIST
    // -- P1 additions --
    0x6F02, // EF_OCST
    0x6FF0, // EF_IAL
    0x6FF2, // EF_IPD
    0x6FF5, // EF_EPDG_ID_EM
    0x6FF6, // EF_EPDG_SELECTION_EM
    // -- P2 additions --
    0x6F0A, // EF_AC_GBAUAPI
    0x6F0B, // EF_IMSDCI
    0x6FF8, // EF_IMS_CONFIG_DATA
    0x6FFB, // EF_TVCONFIG
    0x6FFC, // EF_XCAP_CONFIG_DATA
    0x6FFE, // EF_MUDMID_CONFIG_DATA
    // -- sub-DFs --
    0x5F3A, // DF_PHONEBOOK
    0x5FC0, // DF_5GS
    0x5F3B, // DF_GSM_ACCESS
    0x5FE0, // DF_SNPN
    0x5FF0, // DF_5G_PROSE
    0x5FF1, // DF_5MBSUECONFIG
    0x5F40, // DF_WLAN
    0x5F50, // DF_HNB
    0x5F90, // DF_PROSE
    0x5FA0, // DF_ACDC
    0x5FB0, // DF_TV
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
// ISIM ADF -- 3GPP TS 31.103 V19.0.0
// ---------------------------------------------------------------------------

/// Build EF.IMPU data: 2 records of 64 bytes.
/// Record 1: TLV (tag 0x80) containing `sip:0123456789@ims.mnc001.mcc001.3gppnetwork.org` (48 chars).
/// Record 2: empty (0xFF-filled).
#[cfg(feature = "isim")]
const fn concat_impu_records() -> [u8; 128] {
    // "sip:0123456789@ims.mnc001.mcc001.3gppnetwork.org" = 48 bytes
    // Record 1: 0x80, 0x30, <48 bytes>, <14 bytes 0xFF pad>  = 64 bytes
    // Record 2: <64 bytes 0xFF>
    let rec1: [u8; 64] = [
        0x80, 0x30,
        b's', b'i', b'p', b':',
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
        b'@',
        b'i', b'm', b's', b'.',
        b'm', b'n', b'c', b'0', b'0', b'1', b'.',
        b'm', b'c', b'c', b'0', b'0', b'1', b'.',
        b'3', b'g', b'p', b'p', b'n', b'e', b't', b'w', b'o', b'r', b'k', b'.', b'o', b'r', b'g',
        // pad: 64 - 2 - 48 = 14 bytes
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    let mut out = [0xFF; 128];
    let mut i = 0;
    while i < 64 {
        out[i] = rec1[i];
        i += 1;
    }
    out
}

/// Standard ISIM AID: A0000000871004 (per [3GPP TS 31.103 V19.0.0](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf)).
#[cfg(feature = "isim")]
pub static ISIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04];

/// EF.IMPI (6F02) under ADF.ISIM -- IMS Private User Identity.
///
/// 64-byte transparent EF. TLV-encoded NAI per TS 31.103 clause 4.2.2.
/// Default: `0123456789@ims.mnc001.mcc001.3gppnetwork.org` (tag 0x80).
/// [3GPP TS 31.103 V19.0.0 clause 4.2.2](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A32%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C407%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_IMPI: EfDef = EfDef::transparent(
    Fid::new(0x6F02),
    None,
    // 0x80 || len(44) || "0123456789@ims.mnc001.mcc001.3gppnetwork.org" || FF-pad
    &[
        0x80, 0x2C,
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
        b'@',
        b'i', b'm', b's', b'.',
        b'm', b'n', b'c', b'0', b'0', b'1', b'.',
        b'm', b'c', b'c', b'0', b'0', b'1', b'.',
        b'3', b'g', b'p', b'p', b'n', b'e', b't', b'w', b'o', b'r', b'k', b'.', b'o', b'r', b'g',
        // pad to 64 bytes: 64 - 2 (tag+len) - 44 (value) = 18 bytes
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ],
);

/// EF.DOMAIN (6F03) under ADF.ISIM -- Home Network Domain Name.
///
/// 64-byte transparent EF. TLV-encoded domain per TS 31.103 clause 4.2.3.
/// Default: `ims.mnc001.mcc001.3gppnetwork.org` (tag 0x80).
/// [3GPP TS 31.103 V19.0.0 clause 4.2.3](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A34%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_DOMAIN: EfDef = EfDef::transparent(
    Fid::new(0x6F03),
    None,
    // 0x80 || len(33) || "ims.mnc001.mcc001.3gppnetwork.org" || FF-pad
    &[
        0x80, 0x21,
        b'i', b'm', b's', b'.',
        b'm', b'n', b'c', b'0', b'0', b'1', b'.',
        b'm', b'c', b'c', b'0', b'0', b'1', b'.',
        b'3', b'g', b'p', b'p', b'n', b'e', b't', b'w', b'o', b'r', b'k', b'.', b'o', b'r', b'g',
        // pad to 64 bytes: 64 - 2 (tag+len) - 33 (value) = 29 bytes
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ],
);

/// EF.IMPU (6F04) under ADF.ISIM -- IMS Public User Identity.
///
/// Linear-fixed, 2 records of 64 bytes. TLV-encoded SIP URI per TS 31.103 clause 4.2.4.
/// Record 1: `sip:0123456789@ims.mnc001.mcc001.3gppnetwork.org` (tag 0x80).
/// Record 2: empty.
/// [3GPP TS 31.103 V19.0.0 clause 4.2.4](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A34%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C438%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_IMPU: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F04),
    None,
    64, 2,
    &concat_impu_records(),
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
/// 4-byte transparent EF. Bit mask of available ISIM services.
/// Byte 1 bit 1: P-CSCF discovery, bit 2: GBA, bit 3: HTTP digest,
/// bit 4: GBA-based P-CSCF discovery.
/// Default: services 1-4 enabled (0x0F).
/// [3GPP TS 31.103 V19.0.0 clause 4.2.7](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A38%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C489%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_IST: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0x0F, 0x00, 0x00, 0x00],
);

/// EF.P-CSCF (6F09) under ADF.ISIM -- P-CSCF Address.
///
/// 64-byte transparent EF. Default: empty.
/// [3GPP TS 31.103 V19.0.0 clause 4.2.8](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A42%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C648%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_PCSCF: EfDef = EfDef::transparent(
    Fid::new(0x6F09),
    None,
    &[0xFF; 64],
);

/// EF.GBABP (6F3A) under ADF.ISIM -- GBA Bootstrapping Parameters.
///
/// 64-byte transparent EF. Default: empty.
/// [3GPP TS 31.103 V19.0.0 clause 4.2.9](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A44%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C605%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_GBABP: EfDef = EfDef::transparent(
    Fid::new(0x6F3A),
    None,
    &[0xFF; 64],
);

/// EF.GBANL (6F3B) under ADF.ISIM -- GBA NAF List.
///
/// Linear-fixed, 1 record of 4 bytes. Default: empty.
/// [3GPP TS 31.103 V19.0.0 clause 4.2.10](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A46%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C767%5D).
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
/// [3GPP TS 31.103 V19.0.0 clause 4.2.11](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A46%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C125%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_NAFKCA: EfDef = EfDef::linear_fixed(
    Fid::new(0x6F3C),
    None,
    32, 1,
    &[0xFF; 32],
);

/// EF.AD (6FAD) under ADF.ISIM -- Administrative Data.
///
/// 4-byte transparent EF. Byte 1: MS operation mode (0x00 = normal),
/// byte 4: MNC length (0x02 = 2-digit MNC).
/// [3GPP TS 31.103 V19.0.0 clause 4.2.5](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A36%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
#[cfg(feature = "isim")]
pub static ISIM_EF_AD: EfDef = EfDef::transparent(
    Fid::new(0x6FAD),
    None,
    &[0x00, 0x00, 0x00, 0x02],
);

/// ADF.ISIM root DF.
///
/// Contains 10 EFs per [3GPP TS 31.103 V19.0.0 clause 4.2](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf#%5B%7B%22num%22%3A32%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C537%5D).
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
// HPSIM ADF -- 3GPP TS 31.104 V19.0.0
// ---------------------------------------------------------------------------

/// Standard HPSIM AID: A000000087100A (per [3GPP TS 31.104 V19.0.0](../../../docs/specs/3gpp/ts-31.104/ts_131104v190000p.pdf)).
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
/// [3GPP TS 31.104 V19.0.0 clause 4.2.2](../../../docs/specs/3gpp/ts-31.104/ts_131104v190000p.pdf#%5B%7B%22num%22%3A25%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C498%5D).
#[cfg(feature = "hpsim")]
pub static HPSIM_EF_HPST: EfDef = EfDef::transparent(
    Fid::new(0x6F07),
    None,
    &[0xFF; 2],
);

/// EF.AD (6FAD) under ADF.HPSIM -- Administrative Data.
///
/// 4-byte transparent EF. Default: empty.
/// [3GPP TS 31.104 V19.0.0 clause 4.2.3](../../../docs/specs/3gpp/ts-31.104/ts_131104v190000p.pdf#%5B%7B%22num%22%3A25%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C253%5D).
#[cfg(feature = "hpsim")]
pub static HPSIM_EF_AD: EfDef = EfDef::transparent(
    Fid::new(0x6FAD),
    None,
    &[0xFF; 4],
);

/// ADF.HPSIM root DF.
///
/// Contains 3 EFs per [3GPP TS 31.104 V19.0.0 clause 4.2](../../../docs/specs/3gpp/ts-31.104/ts_131104v190000p.pdf#%5B%7B%22num%22%3A23%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C384%5D).
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
// EFs under DF.TELECOM (7F10) -- ETSI TS 102 221 V16.4.0 clause 13.4
// (DF.TELECOM EFs removed from TS 102 221 V18.3.0)
// ---------------------------------------------------------------------------

/// EF.ADN (6F3A) under DF.TELECOM -- Abbreviated Dialling Numbers.
///
/// Linear-fixed, 2 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 V16.4.0 clause 13.4.1.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.2.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.3.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.4.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.5.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.6.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.7.
#[cfg(feature = "telecom")]
pub static TELECOM_EF_SMSS: EfDef = EfDef::transparent(
    Fid::new(0x6F43),
    None,
    &[0xFF; 2],
);

/// EF.LND (6F44) under DF.TELECOM -- Last Number Dialled.
///
/// Cyclic, 3 records of 30 bytes. Default: empty.
/// ETSI TS 102 221 V16.4.0 clause 13.4.8.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.9.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.10.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.11.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.12.
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
/// ETSI TS 102 221 V16.4.0 clause 13.4.
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
/// [ETSI TS 102 221 V18.3.0 clause 13.3](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A491%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C787%5D).
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
    fn df_5gs_has_19_children() {
        assert_eq!(
            DF_5GS.children.len(),
            19,
            "DF_5GS must contain exactly 19 EFs (17 base + 2 Rel-18)"
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
        let mut fids: [u16; 19] = [0xFFFF; 19];
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
        let expected: [(u16, usize); 19] = [
            (0x4F01, 20),  // EF5GS3GPPLOCI
            (0x4F02, 20),  // EF5GSN3GPPLOCI
            (0x4F03, 57),  // EF5GS3GPPNSC
            (0x4F04, 57),  // EF5GSN3GPPNSC
            (0x4F05, 68),  // EF5GAUTHKEYS
            (0x4F06, 4),   // EFUAC_AIC
            (0x4F07, 80),  // EFSUCI_Calc_Info (TLV: A0 02 00 00 + 0xFF padding)
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
            (0x4F15, 1),   // EFMCHPPLMN
            (0x4F16, 1),   // EFKAUSF_DERIVATION
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

    /// DF.WLAN child count and FID uniqueness.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_wlan_children() {
        assert_eq!(DF_WLAN.children.len(), 11, "DF.WLAN must have 11 children");
        assert_fids_unique(&DF_WLAN, "DF.WLAN");
    }

    /// DF.HNB child count, FID uniqueness, and record sizes.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_hnb_children() {
        assert_eq!(DF_HNB.children.len(), 6, "DF.HNB must have 6 children");
        assert_fids_unique(&DF_HNB, "DF.HNB");
        assert_record_sizes_consistent(&DF_HNB, "DF.HNB");
    }

    /// DF.ProSe child count and FID uniqueness.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_prose_children() {
        assert_eq!(DF_PROSE.children.len(), 13, "DF.ProSe must have 13 children");
        assert_fids_unique(&DF_PROSE, "DF.ProSe");
    }

    /// DF.ACDC child count and FID uniqueness.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_acdc_children() {
        assert_eq!(DF_ACDC.children.len(), 2, "DF.ACDC must have 2 children");
        assert_fids_unique(&DF_ACDC, "DF.ACDC");
    }

    /// DF.TV child count and FID uniqueness.
    #[cfg(feature = "profile-full")]
    #[test]
    fn df_tv_children() {
        assert_eq!(DF_TV.children.len(), 1, "DF.TV must have 1 child");
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

    /// ISIM AID is correct per [3GPP TS 31.103 V19.0.0](../../../docs/specs/3gpp/ts-31.103/ts_131103v190000p.pdf).
    #[cfg(feature = "isim")]
    #[test]
    fn isim_aid_bytes_correct() {
        assert_eq!(ISIM_AID.len(), 7, "ISIM AID must be 7 bytes");
        assert_eq!(&ISIM_AID[..5], &[0xA0, 0x00, 0x00, 0x00, 0x87],
            "ISIM AID must start with 3GPP RID A0000000 87");
        assert_eq!(&ISIM_AID[5..], &[0x10, 0x04],
            "ISIM AID PIX must be 1004");
    }

    /// HPSIM AID is correct per [3GPP TS 31.104 V19.0.0](../../../docs/specs/3gpp/ts-31.104/ts_131104v190000p.pdf).
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
        let mut data = FsData::<16384, 290>::new();
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

    /// Profile-full tier has expected number of EFs in ADF.USIM (110 direct children).
    #[cfg(feature = "profile-full")]
    #[test]
    fn adf_usim_full_child_count() {
        assert_eq!(
            ADF_USIM_ROOT.children.len(), 126,
            "profile-full ADF.USIM must have 126 children (115 EFs + 11 sub-DFs)"
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
            let mut data = FsData::<16384, 290>::new();
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
