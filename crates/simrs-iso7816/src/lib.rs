//! ISO/IEC 7816 APDU types, CLA parsing, and status words.
//!
//! Provides the foundational types for SIM/USIM APDU processing:
//! command parsing, response construction, status word semantics, and
//! instruction code constants. Used by every other simrs crate that
//! handles APDUs.
//!
//! # APDU Structure (ISO/IEC 7816-4:2020 clause 5)
//!
//! ```text
//! Command:  [CLA] [INS] [P1] [P2] [Lc] [Data...] [Le]
//!            1B    1B    1B   1B  0-3B  0-65535B  0-3B
//!
//! Response: [Data...] [SW1] [SW2]
//!           0-65536B   1B    1B
//! ```
//!
//! Short APDUs use 1-byte Lc/Le (data 0-255 bytes). Extended APDUs use
//! 3-byte Lc/Le (data 0-65535 bytes) per ISO 7816-4 clause 5.1.
//!
//! # CLA Byte Routing
//!
//! The CLA byte determines the command class and routing:
//!
//! | CLA | Class | Standard |
//! |-----|-------|----------|
//! | `0x0X`, `0x4X`, `0x6X` | Interindustry | ISO/IEC 7816-4 / ETSI TS 102 221 |
//! | `0x8X` | ETSI proprietary (CAT) | ETSI TS 102 221 V18.3.0 clause 10.1.1 |
//! | `0xA0` | GSM proprietary | GSM 11.11 / 3GPP TS 51.011 |
//!
//! # Standards
//! - ISO/IEC 7816-4:2020 -- Organization, security, and commands
//! - [ETSI TS 102 221 V18.3.0 clause 10.1.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A311%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C531%5D) -- UICC-terminal CLA byte
//! - GSM 11.11 v4.21.1 clause 9 -- ME-SIM interface
//! - 3GPP TS 51.011 V4.15.0 clause 9 -- CLA class A0
//!
//! # `no_std`
//! This crate is fully `no_std`. Enable the `std` feature for `std::error::Error` impls.
//!
//! # Example
//!
//! ```
//! use simrs_iso7816::{Command, StatusWord};
//!
//! // Parse a SELECT MF command: 00 A4 00 00 02 3F00
//! let bytes = [0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
//! let cmd = Command::parse(&bytes).unwrap();
//!
//! assert_eq!(cmd.ins(), 0xA4);          // SELECT
//! assert_eq!(cmd.p1(), 0x00);
//! assert_eq!(cmd.p2(), 0x00);
//! assert_eq!(cmd.data(), &[0x3F, 0x00]); // MF FID
//!
//! // Status words
//! let sw = StatusWord::Success;
//! assert_eq!(sw.to_bytes(), [0x90, 0x00]);
//!
//! let sw = StatusWord::bytes_available(0x1A);
//! assert_eq!(sw.to_bytes(), [0x61, 0x1A]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)] // 3GPP terms: APDU, MF, DF, EF, FID, AID, etc.

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

// ---------------------------------------------------------------------------
// Response schemas (for semantic comparison)
// ---------------------------------------------------------------------------

/// Response schema for SELECT: SW-only comparison, data payload ignored.
///
/// simrs returns bare SW; some implementations return FCI data. The
/// semantic comparison checks only that the SWs agree.
pub static SELECT_SCHEMA: simrs_apdu_schema::ResponseSchema = simrs_apdu_schema::ResponseSchema {
    name: "SELECT",
    expected_len: None,
    fields: &[],
};

/// Response schema for error responses: no data expected, SW comparison only.
pub static ERROR_SCHEMA: simrs_apdu_schema::ResponseSchema = simrs_apdu_schema::ResponseSchema {
    name: "ERROR",
    expected_len: Some(0),
    fields: &[],
};

// ---------------------------------------------------------------------------
// Instruction codes
// ---------------------------------------------------------------------------

/// Well-known INS (instruction) byte values.
///
/// Per ISO/IEC 7816-4:2020 clause 5.1.2 and [ETSI TS 102 221 V18.3.0 clause 11.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A331%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C481%5D).
///
/// ```
/// use simrs_iso7816::ins;
///
/// assert_eq!(ins::SELECT, 0xA4);
/// assert_eq!(ins::READ_BINARY, 0xB0);
/// assert_eq!(ins::VERIFY, 0x20);
/// ```
pub mod ins {
    /// SELECT (file, DF, AID). ISO 7816-4, [ETSI TS 102 221 V18.3.0 clause 11.1.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A331%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C371%5D).
    pub const SELECT: u8 = 0xA4;
    /// STATUS. [ETSI TS 102 221 V18.3.0 clause 11.1.2](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A358%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C299%5D).
    pub const STATUS: u8 = 0xF2;
    /// READ BINARY. [ETSI TS 102 221 V18.3.0 clause 11.1.3](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A361%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C413%5D).
    pub const READ_BINARY: u8 = 0xB0;
    /// UPDATE BINARY. [ETSI TS 102 221 V18.3.0 clause 11.1.4](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A363%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C620%5D).
    pub const UPDATE_BINARY: u8 = 0xD6;
    /// READ RECORD. [ETSI TS 102 221 V18.3.0 clause 11.1.5](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A363%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C255%5D).
    pub const READ_RECORD: u8 = 0xB2;
    /// UPDATE RECORD. [ETSI TS 102 221 V18.3.0 clause 11.1.6](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A367%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
    pub const UPDATE_RECORD: u8 = 0xDC;
    /// GET RESPONSE. [ETSI TS 102 221 V18.3.0 clause 12.1.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A483%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C655%5D).
    ///
    /// (Moved from clause 11 to supplemental chapter 12 in V18.0.0.)
    pub const GET_RESPONSE: u8 = 0xC0;
    /// VERIFY (PIN). [ETSI TS 102 221 V18.3.0 clause 11.1.9](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A375%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C454%5D).
    pub const VERIFY: u8 = 0x20;
    /// CHANGE REFERENCE DATA (change PIN). [ETSI TS 102 221 V18.3.0 clause 11.1.10](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A379%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
    pub const CHANGE_REF_DATA: u8 = 0x24;
    /// DISABLE PIN. [ETSI TS 102 221 V18.3.0 clause 11.1.11](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A379%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C217%5D).
    pub const DISABLE_PIN: u8 = 0x26;
    /// ENABLE PIN. [ETSI TS 102 221 V18.3.0 clause 11.1.12](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A385%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
    pub const ENABLE_PIN: u8 = 0x28;
    /// RESET RETRY COUNTER (unblock PIN). [ETSI TS 102 221 V18.3.0 clause 11.1.13](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A387%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
    pub const RESET_RETRY_CTR: u8 = 0x2C;
    /// AUTHENTICATE (INTERNAL AUTHENTICATE / GENERAL AUTHENTICATE).
    ///
    /// [ETSI TS 102 221 V18.3.0 clause 11.1.16](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A392%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C276%5D) / [3GPP TS 31.102 V19.4.0 clause 7.1.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A717%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C738%5D).
    pub const AUTHENTICATE: u8 = 0x88;
    /// TERMINAL PROFILE. [ETSI TS 102 221 V18.3.0 clause 11.2.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A467%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C751%5D).
    pub const TERMINAL_PROFILE: u8 = 0x10;
    // V18.0.0 reordered clause 11.2: ENVELOPE (11.2.2), FETCH (11.2.3),
    // TERMINAL RESPONSE (11.2.4). V16.4.0 was: FETCH, TR, ENVELOPE.
    /// FETCH (proactive command retrieval). [ETSI TS 102 221 V18.3.0 clause 11.2.3](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A470%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
    pub const FETCH: u8 = 0x12;
    /// TERMINAL RESPONSE. [ETSI TS 102 221 V18.3.0 clause 11.2.4](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A470%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C442%5D).
    pub const TERMINAL_RESPONSE: u8 = 0x14;
    /// ENVELOPE. [ETSI TS 102 221 V18.3.0 clause 11.2.2](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A467%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C451%5D).
    pub const ENVELOPE: u8 = 0xC2;
    /// INCREASE. [ETSI TS 102 221 V18.3.0 clause 11.1.8](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A372%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C478%5D).
    pub const INCREASE: u8 = 0x32;
    /// SEARCH RECORD. [ETSI TS 102 221 V18.3.0 clause 11.1.7](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A369%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
    pub const SEARCH_RECORD: u8 = 0xA2;
    /// MANAGE CHANNEL. [ETSI TS 102 221 V18.3.0 clause 11.1.17](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A398%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C327%5D).
    pub const MANAGE_CHANNEL: u8 = 0x70;
    /// DEACTIVATE FILE. [ETSI TS 102 221 V18.3.0 clause 11.1.14](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A389%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C574%5D).
    pub const DEACTIVATE_FILE: u8 = 0x04;
    /// ACTIVATE FILE. [ETSI TS 102 221 V18.3.0 clause 11.1.15](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A392%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C661%5D).
    pub const ACTIVATE_FILE: u8 = 0x44;
    /// TERMINAL CAPABILITY. [ETSI TS 102 221 V18.3.0 clause 11.1.19](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A402%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C538%5D).
    pub const TERMINAL_CAPABILITY: u8 = 0xAA;
    /// GET IDENTITY.
    ///
    /// [ETSI TS 102 221 V18.3.0 clause 11.1.20](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf) /
    /// [3GPP TS 31.102 V19.4.0 clause 7.5](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf).
    pub const GET_IDENTITY: u8 = 0x78;
}

/// `GlobalPlatform` card management instruction codes per
/// [GP Card Specification v2.1.1](../../../telecom-standards/globalplatform/GPC_CardSpecification_v2.1.1.pdf)
/// Chapter 9.
pub mod gp_ins {
    /// INITIALIZE UPDATE (SCP establishment). GP 2.1.1 Appendix D/E.
    pub const INITIALIZE_UPDATE: u8 = 0x50;
    /// EXTERNAL AUTHENTICATE (SCP establishment). GP 2.1.1 Appendix D/E.
    pub const EXTERNAL_AUTHENTICATE: u8 = 0x82;
    /// GET DATA. GP 2.1.1 clause 9.3.
    pub const GET_DATA: u8 = 0xCA;
    /// PUT KEY. GP 2.1.1 clause 9.8.
    pub const PUT_KEY: u8 = 0xD8;
    /// STORE DATA. GP 2.1.1 clause 9.11.
    pub const STORE_DATA: u8 = 0xE2;
    /// DELETE. GP 2.1.1 clause 9.2.
    pub const DELETE: u8 = 0xE4;
    /// INSTALL. GP 2.1.1 clause 9.5.
    pub const INSTALL: u8 = 0xE6;
    /// LOAD. GP 2.1.1 clause 9.6.
    pub const LOAD: u8 = 0xE8;
    /// SET STATUS. GP 2.1.1 clause 9.10.
    pub const SET_STATUS: u8 = 0xF0;
    /// GET STATUS. GP 2.1.1 clause 9.4.
    pub const GET_STATUS: u8 = 0xF2;
    /// BEGIN R-MAC SESSION (SCP02). GP 2.1.1 Appendix E clause E.5.3.
    pub const BEGIN_RMAC_SESSION: u8 = 0x70;
    /// END R-MAC SESSION (SCP02). GP 2.1.1 Appendix E clause E.5.4.
    pub const END_RMAC_SESSION: u8 = 0x78;
}

// ---------------------------------------------------------------------------
// FCP (File Control Parameters) tags
// ---------------------------------------------------------------------------

/// FCP (File Control Parameters) BER-TLV tag values.
///
/// Per ISO/IEC 7816-4:2020 Table 12 and [ETSI TS 102 221 V18.3.0 clause 11.1.1.3](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A335%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C783%5D).
///
/// ```
/// use simrs_iso7816::fcp;
///
/// assert_eq!(fcp::TEMPLATE, 0x62);
/// assert_eq!(fcp::FILE_ID, 0x83);
/// assert_eq!(fcp::LIFECYCLE_STATUS, 0x8A);
/// ```
pub mod fcp {
    /// FCP template tag. ISO 7816-4 Table 12.
    pub const TEMPLATE: u8 = 0x62;
    /// File descriptor. ISO 7816-4 / [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.3](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A337%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C365%5D).
    pub const FILE_DESCRIPTOR: u8 = 0x82;
    /// File identifier. ISO 7816-4 / [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.4](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A339%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C262%5D).
    pub const FILE_ID: u8 = 0x83;
    /// DF name (AID). ISO 7816-4 / [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.5](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A339%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C169%5D).
    pub const DF_NAME: u8 = 0x84;
    /// Proprietary information. ISO 7816-4.
    pub const PROPRIETARY_INFO: u8 = 0xA5;
    /// Life cycle status integer. ISO 7816-4 / [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.9](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A355%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C241%5D).
    pub const LIFECYCLE_STATUS: u8 = 0x8A;
    /// Security attributes (compact format). [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.7](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A352%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C518%5D).
    pub const SECURITY_ATTRS_COMPACT: u8 = 0x8C;
    /// PIN status template DO. [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.10](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A358%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C636%5D).
    pub const PIN_STATUS_TEMPLATE: u8 = 0xC6;
    /// File size (data bytes). ISO 7816-4 / [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A337%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C753%5D).
    pub const FILE_SIZE: u8 = 0x80;
    /// Short File Identifier. [ETSI TS 102 221 V18.3.0 clause 11.1.1.4.8](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A355%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C439%5D).
    pub const SHORT_FILE_ID: u8 = 0x88;
}

// ---------------------------------------------------------------------------
// SW2 semantic values
// ---------------------------------------------------------------------------

/// SW2 semantic values for parametric status words.
///
/// Named constants for the second byte of `StatusWord::WrongParams(sw2)`
/// and `StatusWord::CommandNotAllowed(sw2)`.
///
/// Per [ETSI TS 102 221 V18.3.0 clause 10.2.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A320%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C673%5D) and ISO/IEC 7816-4:2020 clause 5.6.
///
/// ```
/// use simrs_iso7816::{sw2, StatusWord};
///
/// let sw = StatusWord::wrong_params(sw2::FILE_NOT_FOUND);
/// assert_eq!(sw.to_bytes(), [0x6A, 0x82]);
///
/// let sw = StatusWord::command_not_allowed(sw2::NO_CURRENT_EF);
/// assert_eq!(sw.to_bytes(), [0x69, 0x86]);
/// ```
pub mod sw2 {
    /// File or application not found. Used with `WrongParams` (6A 82).
    pub const FILE_NOT_FOUND: u8 = 0x82;
    /// Record not found. Used with `WrongParams` (6A 83).
    pub const RECORD_NOT_FOUND: u8 = 0x83;
    /// Incorrect parameters P1-P2. Used with `WrongParams` (6A 86).
    pub const WRONG_P1_P2: u8 = 0x86;
    /// No current EF. Used with `CommandNotAllowed` (69 86).
    pub const NO_CURRENT_EF: u8 = 0x86;
    /// Command incompatible with file structure. Used with `CommandNotAllowed` (69 81).
    pub const INCOMPATIBLE_FILE_STRUCTURE: u8 = 0x81;
    /// Authentication method blocked (PIN blocked). Used with `CommandNotAllowed` (69 83).
    /// ISO/IEC 7816-4:2020 Table 6.
    pub const AUTH_METHOD_BLOCKED: u8 = 0x83;
    /// Referenced data not usable (PIN disabled). Used with `CommandNotAllowed` (69 84).
    /// ISO/IEC 7816-4:2020 Table 6.
    pub const REF_DATA_NOT_USABLE: u8 = 0x84;
    /// Referenced data or reference data not found. Used with `WrongParams` (6A 88).
    /// ISO/IEC 7816-4:2020 Table 6.
    pub const REFERENCE_NOT_FOUND: u8 = 0x88;
    /// Security status not satisfied. Used with `CommandNotAllowed` (69 82).
    /// ISO/IEC 7816-4:2020 Table 6.
    pub const SECURITY_NOT_SATISFIED: u8 = 0x82;
    /// Conditions of use not satisfied. Used with `CommandNotAllowed` (69 85).
    /// ISO/IEC 7816-4:2020 Table 6.
    pub const CONDITIONS_NOT_SATISFIED: u8 = 0x85;
    /// Incorrect parameters in the command data field. Used with `WrongParams` (6A 80).
    /// ISO/IEC 7816-4:2020 Table 6.
    pub const INCORRECT_DATA: u8 = 0x80;
    /// Referenced data or reference data not found. Used with `WrongParams` (6A 88).
    /// Alias for cases where data (not a file) is missing.
    pub const DATA_NOT_FOUND: u8 = 0x88;
}

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

/// APDU status word (SW1-SW2).
///
/// Per ISO/IEC 7816-4:2020 clause 5.6 and [ETSI TS 102 221 V18.3.0 clause 10.2.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A320%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C673%5D).
///
/// ```
/// use simrs_iso7816::StatusWord;
///
/// // Normal processing
/// assert_eq!(StatusWord::Success.to_bytes(), [0x90, 0x00]);
/// assert_eq!(StatusWord::bytes_available(0x20).to_bytes(), [0x61, 0x20]);
///
/// // Warning: PIN retries
/// assert_eq!(StatusWord::pin_retries(3).to_bytes(), [0x63, 0xC3]);
///
/// // Error conditions
/// assert_eq!(StatusWord::WrongLength.to_bytes(), [0x67, 0x00]);
/// assert_eq!(StatusWord::ClassNotSupported.to_bytes(), [0x6E, 0x00]);
/// assert_eq!(StatusWord::InsNotSupported.to_bytes(), [0x6D, 0x00]);
///
/// // Roundtrip
/// let sw = StatusWord::from_bytes(0x6A, 0x82);
/// assert_eq!(sw, StatusWord::wrong_params(0x82));
/// assert_eq!(sw.to_bytes(), [0x6A, 0x82]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusWord {
    /// `90 00` -- Normal ending of command.
    Success,
    /// `61 XX` -- SW2 indicates the number of response bytes available.
    BytesAvailable(u8),
    /// `63 CX` -- Verification failed; X = retries remaining.
    PinRetries(u8),
    /// `63 XX` -- Warning, non-volatile memory unchanged (other than PIN).
    WarningUnchanged(u8),
    /// `67 00` -- Wrong length (Lc/Le incorrect).
    WrongLength,
    /// `6C XX` -- Wrong Le; SW2 = exact length available.
    ExactLength(u8),
    /// `68 XX` -- Functions in CLA not supported.
    FunctionNotSupported(u8),
    /// `69 XX` -- Command not allowed.
    CommandNotAllowed(u8),
    /// `6A XX` -- Wrong parameters P1-P2 or referenced data not found.
    WrongParams(u8),
    /// `6B 00` -- Wrong parameters P1-P2.
    WrongP1P2,
    /// `6D 00` -- Instruction code not supported or invalid.
    InsNotSupported,
    /// `6E 00` -- Class not supported.
    ClassNotSupported,
    /// `6F 00` -- No precise diagnosis (technical problem, no info given).
    NoPreciseDiagnosis,
    /// `91 XX` -- Proactive command pending; SW2 = FETCH length.
    /// Per [ETSI TS 102 223 V18.2.0 clause 6.1](../../../docs/specs/etsi/ts-102-223/ts_102223v180200p.pdf#%5B%7B%22num%22%3A115%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C590%5D).
    ProactivePending(u8),
    /// `98 62` -- Authentication error (MAC failure).
    /// Per [3GPP TS 31.102 V19.4.0 clause 7.1.2.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A754%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C330%5D).
    AuthenticationError,
    /// Any other SW1/SW2 pair not specifically modeled.
    Other(u8, u8),
}

impl StatusWord {
    /// `61 XX` -- response bytes available.
    pub const fn bytes_available(len: u8) -> Self {
        Self::BytesAvailable(len)
    }
    /// `63 CX` -- PIN retries remaining.
    pub const fn pin_retries(n: u8) -> Self {
        Self::PinRetries(n & 0x0F)
    }
    /// `6A XX` -- wrong parameters.
    pub const fn wrong_params(sw2: u8) -> Self {
        Self::WrongParams(sw2)
    }
    /// `69 XX` -- command not allowed.
    pub const fn command_not_allowed(sw2: u8) -> Self {
        Self::CommandNotAllowed(sw2)
    }
    /// `6C XX` -- exact length.
    pub const fn exact_length(len: u8) -> Self {
        Self::ExactLength(len)
    }
    /// `91 XX` -- proactive pending.
    pub const fn proactive_pending(len: u8) -> Self {
        Self::ProactivePending(len)
    }

    /// Encode as `[SW1, SW2]`.
    ///
    /// ```
    /// use simrs_iso7816::StatusWord;
    /// assert_eq!(StatusWord::Success.to_bytes(), [0x90, 0x00]);
    /// ```
    pub const fn to_bytes(self) -> [u8; 2] {
        match self {
            Self::Success => [0x90, 0x00],
            Self::BytesAvailable(n) => [0x61, n],
            Self::PinRetries(n) => [0x63, 0xC0 | (n & 0x0F)],
            Self::WarningUnchanged(n) => [0x63, n],
            Self::WrongLength => [0x67, 0x00],
            Self::ExactLength(n) => [0x6C, n],
            Self::FunctionNotSupported(n) => [0x68, n],
            Self::CommandNotAllowed(n) => [0x69, n],
            Self::WrongParams(n) => [0x6A, n],
            Self::WrongP1P2 => [0x6B, 0x00],
            Self::InsNotSupported => [0x6D, 0x00],
            Self::ClassNotSupported => [0x6E, 0x00],
            Self::NoPreciseDiagnosis => [0x6F, 0x00],
            Self::ProactivePending(n) => [0x91, n],
            Self::AuthenticationError => [0x98, 0x62],
            Self::Other(sw1, sw2) => [sw1, sw2],
        }
    }

    /// Decode from `SW1, SW2` bytes.
    ///
    /// ```
    /// use simrs_iso7816::StatusWord;
    /// assert_eq!(StatusWord::from_bytes(0x90, 0x00), StatusWord::Success);
    /// assert_eq!(StatusWord::from_bytes(0x63, 0xC3), StatusWord::PinRetries(3));
    /// assert_eq!(StatusWord::from_bytes(0x98, 0x62), StatusWord::AuthenticationError);
    /// ```
    pub const fn from_bytes(sw1: u8, sw2: u8) -> Self {
        match (sw1, sw2) {
            (0x90, 0x00) => Self::Success,
            (0x61, n) => Self::BytesAvailable(n),
            (0x63, n) if n & 0xF0 == 0xC0 => Self::PinRetries(n & 0x0F),
            (0x63, n) => Self::WarningUnchanged(n),
            (0x67, 0x00) => Self::WrongLength,
            (0x6C, n) => Self::ExactLength(n),
            (0x68, n) => Self::FunctionNotSupported(n),
            (0x69, n) => Self::CommandNotAllowed(n),
            (0x6A, n) => Self::WrongParams(n),
            (0x6B, 0x00) => Self::WrongP1P2,
            (0x6D, 0x00) => Self::InsNotSupported,
            (0x6E, 0x00) => Self::ClassNotSupported,
            (0x6F, 0x00) => Self::NoPreciseDiagnosis,
            (0x91, n) => Self::ProactivePending(n),
            (0x98, 0x62) => Self::AuthenticationError,
            (s1, s2) => Self::Other(s1, s2),
        }
    }

    /// Is this a success status (SW1 = 0x90 or 0x91)?
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success | Self::ProactivePending(_))
    }
}

impl core::fmt::Display for StatusWord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [sw1, sw2] = self.to_bytes();
        match self {
            Self::Success => write!(f, "{sw1:02X}{sw2:02X} ok"),
            Self::BytesAvailable(n) => write!(f, "{sw1:02X}{sw2:02X} {n} bytes available"),
            Self::PinRetries(n) => write!(f, "{sw1:02X}{sw2:02X} {n} PIN retries remaining"),
            Self::WarningUnchanged(_) => write!(
                f,
                "{sw1:02X}{sw2:02X} warning, non-volatile memory unchanged"
            ),
            Self::WrongLength => write!(f, "{sw1:02X}{sw2:02X} wrong length"),
            Self::ExactLength(n) => write!(f, "{sw1:02X}{sw2:02X} exact length {n}"),
            Self::FunctionNotSupported(_) => write!(f, "{sw1:02X}{sw2:02X} function not supported"),
            Self::CommandNotAllowed(_) => write!(f, "{sw1:02X}{sw2:02X} command not allowed"),
            Self::WrongParams(_) => write!(f, "{sw1:02X}{sw2:02X} wrong parameters"),
            Self::WrongP1P2 => write!(f, "{sw1:02X}{sw2:02X} wrong P1-P2"),
            Self::InsNotSupported => write!(f, "{sw1:02X}{sw2:02X} instruction not supported"),
            Self::ClassNotSupported => write!(f, "{sw1:02X}{sw2:02X} class not supported"),
            Self::NoPreciseDiagnosis => write!(f, "{sw1:02X}{sw2:02X} no precise diagnosis"),
            Self::ProactivePending(n) => {
                write!(f, "{sw1:02X}{sw2:02X} proactive command pending, fetch {n}")
            }
            Self::AuthenticationError => write!(f, "{sw1:02X}{sw2:02X} authentication error"),
            Self::Other(_, _) => write!(f, "{sw1:02X}{sw2:02X}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CLA byte
// ---------------------------------------------------------------------------

/// Parsed CLA (class) byte.
///
/// Per ISO/IEC 7816-4:2020 clause 5.1.1 and [ETSI TS 102 221 V18.3.0 clause 10.1.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A311%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C531%5D).
///
/// ```
/// use simrs_iso7816::ClassByte;
///
/// let cla = ClassByte::parse(0x00);
/// assert!(cla.is_interindustry());
/// assert_eq!(cla.channel(), 0);
///
/// let cla = ClassByte::parse(0xA0);
/// assert!(cla.is_proprietary());
/// assert_eq!(cla.raw(), 0xA0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassByte {
    /// Interindustry class (first byte 0x0X, 0x4X, 0x6X).
    /// Bits 1-0: logical channel (0-3). Bits 3-2: secure messaging.
    Interindustry {
        /// Secure messaging indication (bits 3-2).
        sm: u8,
        /// Logical channel number (bits 1-0, range 0-3).
        channel: u8,
        /// Raw CLA byte.
        raw: u8,
    },
    /// Proprietary class (0xA0 = GSM, 0x80 = ETSI CAT, etc.).
    Proprietary {
        /// Raw CLA byte.
        raw: u8,
    },
}

impl ClassByte {
    /// Parse a CLA byte.
    ///
    /// ```
    /// use simrs_iso7816::ClassByte;
    ///
    /// // Interindustry: 00, 40, 60 series
    /// assert!(ClassByte::parse(0x00).is_interindustry());
    /// assert!(ClassByte::parse(0x40).is_interindustry());
    ///
    /// // Proprietary: A0 (GSM), 80 (ETSI CAT)
    /// assert!(ClassByte::parse(0xA0).is_proprietary());
    /// assert!(ClassByte::parse(0x80).is_proprietary());
    /// ```
    pub const fn parse(cla: u8) -> Self {
        match cla & 0xF0 {
            0x00 | 0x40 | 0x60 => Self::Interindustry {
                sm: (cla >> 2) & 0x03,
                channel: cla & 0x03,
                raw: cla,
            },
            _ => Self::Proprietary { raw: cla },
        }
    }

    /// Is this an interindustry class?
    pub const fn is_interindustry(&self) -> bool {
        matches!(self, Self::Interindustry { .. })
    }

    /// Is this a proprietary class?
    pub const fn is_proprietary(&self) -> bool {
        matches!(self, Self::Proprietary { .. })
    }

    /// Logical channel number (0-3 for interindustry, 0 for proprietary).
    pub const fn channel(&self) -> u8 {
        match self {
            Self::Interindustry { channel, .. } => *channel,
            Self::Proprietary { .. } => 0,
        }
    }

    /// Raw CLA byte value.
    pub const fn raw(&self) -> u8 {
        match self {
            Self::Interindustry { raw, .. } | Self::Proprietary { raw } => *raw,
        }
    }
}

// ---------------------------------------------------------------------------
// APDU Command
// ---------------------------------------------------------------------------

/// APDU parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduError {
    /// Fewer than 4 bytes (minimum CLA+INS+P1+P2).
    TooShort,
    /// Lc indicates more data bytes than present.
    DataTruncated,
}

impl core::fmt::Display for ApduError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => f.write_str("APDU too short"),
            Self::DataTruncated => f.write_str("Lc/data length mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ApduError {}

/// Parsed APDU command (borrowed from input buffer).
///
/// Borrows the data field from the input byte slice -- no copying.
///
/// # Parsing Rules (short APDU, T=0 compatible)
///
/// | Case | Bytes | Structure |
/// |------|-------|-----------|
/// | 1 | 4 | CLA INS P1 P2 |
/// | 2 | 5 | CLA INS P1 P2 Le |
/// | 3 | 5+Lc | CLA INS P1 P2 Lc Data\[Lc\] |
/// | 4 | 5+Lc+1 | CLA INS P1 P2 Lc Data\[Lc\] Le |
///
/// ```
/// use simrs_iso7816::Command;
///
/// // Case 1: header only
/// let cmd = Command::parse(&[0x00, 0xA4, 0x00, 0x00]).unwrap();
/// assert_eq!(cmd.data(), &[]);
/// assert_eq!(cmd.response_len(), None);
///
/// // Case 3: header + Lc + data
/// let cmd = Command::parse(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]).unwrap();
/// assert_eq!(cmd.data(), &[0x3F, 0x00]);
///
/// // Too short
/// assert!(Command::parse(&[0x00, 0xA4]).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command<'a> {
    cla: ClassByte,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &'a [u8],
    le: Option<u8>,
    /// Extended Le for extended-length APDUs (ISO 7816-4 clause 5.1).
    /// `Some(n)` when the APDU uses extended Lc/Le encoding.
    /// 0 represents 65536.
    le_ext: Option<u16>,
    /// Whether this APDU was parsed as extended-length format.
    extended: bool,
}

impl<'a> Command<'a> {
    /// Parse an APDU command from raw bytes.
    ///
    /// Supports both short (1-byte Lc/Le, max 255) and extended (3-byte
    /// Lc/Le, max 65535) formats per ISO/IEC 7816-4:2020 clause 5.1 and
    /// ETSI TS 102 221 V18.3.0 clause 10.1.1.
    ///
    /// Extended format is detected when `bytes[4] == 0x00` and
    /// `bytes.len() >= 7`. In extended mode, [`le()`](Self::le) returns
    /// `None`; use [`le_extended()`](Self::le_extended) instead.
    ///
    /// # Errors
    ///
    /// - [`ApduError::TooShort`] if `bytes.len() < 4`
    /// - [`ApduError::DataTruncated`] if Lc indicates more data than available
    pub const fn parse(bytes: &'a [u8]) -> Result<Self, ApduError> {
        if bytes.len() < 4 {
            return Err(ApduError::TooShort);
        }

        let cla = ClassByte::parse(bytes[0]);
        let ins = bytes[1];
        let p1 = bytes[2];
        let p2 = bytes[3];

        if bytes.len() == 4 {
            // Case 1: header only
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: None,
                le_ext: None,
                extended: false,
            });
        }

        let p3 = bytes[4];

        if bytes.len() == 5 {
            // Case 2S: Le only (short)
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: Some(p3),
                le_ext: None,
                extended: false,
            });
        }

        // Extended format detection: byte[4] == 0x00 and at least 7 bytes.
        // Per ISO 7816-4, when the first Lc/Le byte is 0x00 and there are
        // additional bytes, the APDU uses 3-byte extended length encoding.
        if p3 == 0x00 && bytes.len() >= 7 {
            return Self::parse_extended(cla, ins, p1, p2, bytes);
        }

        // Case 3S or 4S: short format -- Lc = P3, followed by data, optionally Le
        let lc = p3 as usize;
        if bytes.len() < 5 + lc {
            return Err(ApduError::DataTruncated);
        }

        // data = bytes[5 .. 5+lc]
        // We can't use range indexing in const fn, so use split_at
        let (_, after_header) = bytes.split_at(5);
        let (data, remainder) = after_header.split_at(lc);

        let le = if remainder.is_empty() {
            None // Case 3S
        } else {
            Some(remainder[0]) // Case 4S
        };

        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
            le_ext: None,
            extended: false,
        })
    }

    /// Parse an extended-length APDU (ISO 7816-4 clause 5.1).
    ///
    /// Called when byte[4] == 0x00 and len >= 7. Layout variants:
    ///
    /// ```text
    /// Case 2E: [CLA INS P1 P2] [00 Le1 Le2]           -- Le only
    /// Case 3E: [CLA INS P1 P2] [00 Lc1 Lc2] [Data]    -- Lc + data
    /// Case 4E: [CLA INS P1 P2] [00 Lc1 Lc2] [Data] [Le1 Le2] -- Lc + data + Le
    /// ```
    const fn parse_extended(
        cla: ClassByte,
        ins: u8,
        p1: u8,
        p2: u8,
        bytes: &'a [u8],
    ) -> Result<Self, ApduError> {
        let b1 = bytes[5];
        let b2 = bytes[6];
        let field = ((b1 as u16) << 8) | (b2 as u16);

        if bytes.len() == 7 {
            // Case 2E: extended Le only, Lc=0
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: None,
                le_ext: Some(field),
                extended: true,
            });
        }

        // Case 3E or 4E: Lc = field, then data, optionally Le
        let lc = field as usize;
        if lc == 0 {
            // Lc=0 with extra bytes: treat the remaining 2 bytes as Le
            // (disambiguate Case 2E with trailing bytes from Case 3E with Lc=0)
            if bytes.len() >= 9 {
                let le_val = ((bytes[7] as u16) << 8) | (bytes[8] as u16);
                return Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: &[],
                    le: None,
                    le_ext: Some(le_val),
                    extended: true,
                });
            }
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: None,
                le_ext: Some(field),
                extended: true,
            });
        }

        if bytes.len() < 7 + lc {
            return Err(ApduError::DataTruncated);
        }

        let (_, after_ext_header) = bytes.split_at(7);
        let (data, remainder) = after_ext_header.split_at(lc);

        let le_ext = if remainder.len() >= 2 {
            // Case 4E: 2-byte Le follows data
            Some(((remainder[0] as u16) << 8) | (remainder[1] as u16))
        } else {
            None // Case 3E
        };

        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le: None,
            le_ext,
            extended: true,
        })
    }

    /// Parsed CLA byte.
    pub const fn cla(&self) -> ClassByte {
        self.cla
    }
    /// Raw CLA byte value.
    pub const fn cla_raw(&self) -> u8 {
        self.cla.raw()
    }
    /// INS (instruction) byte.
    pub const fn ins(&self) -> u8 {
        self.ins
    }
    /// P1 parameter byte.
    pub const fn p1(&self) -> u8 {
        self.p1
    }
    /// P2 parameter byte.
    pub const fn p2(&self) -> u8 {
        self.p2
    }
    /// Command data field (may be empty).
    pub const fn data(&self) -> &[u8] {
        self.data
    }
    /// Expected response length (the `Le` field of ISO 7816-4) for
    /// short APDUs, if present.
    ///
    /// Returns `None` for extended-length APDUs; use
    /// [`response_len_extended()`](Self::response_len_extended) instead.
    pub const fn response_len(&self) -> Option<u8> {
        self.le
    }

    /// Deprecated alias for [`response_len`](Self::response_len).
    #[deprecated(
        since = "0.2.0",
        note = "use `response_len` -- `le` is ISO 7816-4 jargon"
    )]
    pub const fn le(&self) -> Option<u8> {
        self.le
    }

    /// Expected response length (the `Le` field of ISO 7816-4) as `u16`.
    ///
    /// Works for both short and extended APDUs:
    /// - Short APDU: returns the short Le widened to `u16`
    /// - Extended APDU: returns the 2-byte extended Le
    /// - No Le present: returns `None`
    ///
    /// A value of 0 means "maximum available" (256 for short, 65536 for
    /// extended).
    pub const fn response_len_extended(&self) -> Option<u16> {
        match (self.le, self.le_ext) {
            (_, Some(le)) => Some(le),
            (Some(le), None) => Some(le as u16),
            (None, None) => None,
        }
    }

    /// Deprecated alias for [`response_len_extended`](Self::response_len_extended).
    #[deprecated(
        since = "0.2.0",
        note = "use `response_len_extended` -- `le_extended` is ISO 7816-4 jargon"
    )]
    pub const fn le_extended(&self) -> Option<u16> {
        self.response_len_extended()
    }

    /// Whether this command used extended-length encoding.
    pub const fn is_extended(&self) -> bool {
        self.extended
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Write a [`StatusWord`] into `buf` and return a 2-byte slice.
///
/// Convenience for APDU response building: encodes `sw` at `buf[0..2]`
/// and returns `&buf[..2]`.
///
/// # Panics
///
/// Panics if `buf.len() < 2`.
///
/// ```
/// use simrs_iso7816::{write_sw, StatusWord};
///
/// let mut buf = [0u8; 2];
/// let rsp = write_sw(&mut buf, StatusWord::Success);
/// assert_eq!(rsp, &[0x90, 0x00]);
/// ```
pub fn write_sw(buf: &mut [u8], sw: StatusWord) -> &[u8] {
    let [sw1, sw2] = sw.to_bytes();
    write_sw_raw(buf, sw1, sw2)
}

/// Write raw SW1/SW2 bytes into `buf` and return a 2-byte slice.
///
/// # Panics
///
/// Panics if `buf.len() < 2`.
///
/// ```
/// use simrs_iso7816::write_sw_raw;
///
/// let mut buf = [0u8; 2];
/// let rsp = write_sw_raw(&mut buf, 0x6A, 0x82);
/// assert_eq!(rsp, &[0x6A, 0x82]);
/// ```
pub fn write_sw_raw(buf: &mut [u8], sw1: u8, sw2: u8) -> &[u8] {
    buf[0] = sw1;
    buf[1] = sw2;
    &buf[..2]
}

/// Copy `data` into `buf`, append a [`StatusWord`], and return the slice.
///
/// Returns `&buf[..data.len() + 2]`.
///
/// # Panics
///
/// Panics if `buf.len() < data.len() + 2`.
///
/// ```
/// use simrs_iso7816::{write_data_sw, StatusWord};
///
/// let mut buf = [0u8; 16];
/// let rsp = write_data_sw(&mut buf, &[0x01, 0x02], StatusWord::Success);
/// assert_eq!(rsp, &[0x01, 0x02, 0x90, 0x00]);
/// ```
pub fn write_data_sw<'buf>(buf: &'buf mut [u8], data: &[u8], sw: StatusWord) -> &'buf [u8] {
    let [sw1, sw2] = sw.to_bytes();
    write_data_sw_raw(buf, data, sw1, sw2)
}

/// Copy `data` into `buf`, append raw SW1/SW2, and return the slice.
///
/// Returns `&buf[..data.len() + 2]`.
///
/// # Panics
///
/// Panics if `buf.len() < data.len() + 2`.
///
/// ```
/// use simrs_iso7816::write_data_sw_raw;
///
/// let mut buf = [0u8; 16];
/// let rsp = write_data_sw_raw(&mut buf, &[0xAA, 0xBB], 0x90, 0x00);
/// assert_eq!(rsp, &[0xAA, 0xBB, 0x90, 0x00]);
/// ```
pub fn write_data_sw_raw<'buf>(buf: &'buf mut [u8], data: &[u8], sw1: u8, sw2: u8) -> &'buf [u8] {
    let n = data.len();
    buf[..n].copy_from_slice(data);
    buf[n] = sw1;
    buf[n + 1] = sw2;
    &buf[..n + 2]
}

// ---------------------------------------------------------------------------
// APDU command builders (named by APDU shape; corresponds to
// ISO/IEC 7816-4 § 5.1 Cases 1..4)
// ---------------------------------------------------------------------------

/// Build an APDU with header only (`CLA INS P1 P2`).
///
/// No body, no expected response length. Corresponds to ISO 7816-4 Case 1.
/// Used for commands like SET STATUS without data, MANAGE CHANNEL OPEN.
///
/// ```
/// use simrs_iso7816::apdu_header;
/// assert_eq!(apdu_header(0x80, 0xF2, 0x80, 0x00), [0x80, 0xF2, 0x80, 0x00]);
/// ```
#[must_use]
pub const fn apdu_header(cla: u8, ins: u8, p1: u8, p2: u8) -> [u8; 4] {
    [cla, ins, p1, p2]
}

/// Build an APDU with header and expected response length
/// (`CLA INS P1 P2 Le`).
///
/// Corresponds to ISO 7816-4 Case 2S. `response_len` is the `Le` field --
/// the number of bytes the host expects the card to return. `0` means
/// "max" (256 bytes for short, 65536 for extended).
///
/// ```
/// use simrs_iso7816::apdu_with_response_len;
/// assert_eq!(
///     apdu_with_response_len(0x00, 0xB0, 0x00, 0x00, 0x10),
///     [0x00, 0xB0, 0x00, 0x00, 0x10],
/// );
/// ```
#[must_use]
pub const fn apdu_with_response_len(cla: u8, ins: u8, p1: u8, p2: u8, response_len: u8) -> [u8; 5] {
    [cla, ins, p1, p2, response_len]
}

/// Write an APDU with a body into a caller-supplied buffer
/// (`CLA INS P1 P2 Lc Data`).
///
/// Corresponds to ISO 7816-4 Case 3S. Returns `&buf[..total]`, matching
/// [`write_sw_raw`] and [`write_data_sw_raw`] for symmetry across this
/// crate's request/response helpers. Allocator-free counterpart to
/// [`apdu_with_data`].
///
/// # Panics
///
/// Panics if `data.len() > 255` or `buf.len() < 5 + data.len()`.
///
/// ```
/// use simrs_iso7816::write_apdu_with_data;
///
/// let mut buf = [0u8; 16];
/// let apdu = write_apdu_with_data(&mut buf, 0x80, 0xE6, 0x04, 0x00, &[0x01, 0x02, 0x03]);
/// assert_eq!(apdu, &[0x80, 0xE6, 0x04, 0x00, 0x03, 0x01, 0x02, 0x03]);
/// ```
pub fn write_apdu_with_data<'buf>(
    buf: &'buf mut [u8],
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> &'buf [u8] {
    assert!(
        data.len() <= 255,
        "Case 3 APDU body must fit in a single short Lc"
    );
    let total = 5 + data.len();
    assert!(buf.len() >= total, "buffer too small for Case 3 APDU");
    buf[0] = cla;
    buf[1] = ins;
    buf[2] = p1;
    buf[3] = p2;
    #[allow(clippy::cast_possible_truncation)]
    {
        buf[4] = data.len() as u8;
    }
    buf[5..total].copy_from_slice(data);
    &buf[..total]
}

/// Write an APDU with both body and expected response length into a
/// caller-supplied buffer (`CLA INS P1 P2 Lc Data Le`).
///
/// Corresponds to ISO 7816-4 Case 4S. `response_len` is the `Le` field.
///
/// # Panics
///
/// Panics if `data.len() > 255` or `buf.len() < 6 + data.len()`.
///
/// ```
/// use simrs_iso7816::write_apdu_with_data_and_response_len;
///
/// let mut buf = [0u8; 16];
/// let apdu = write_apdu_with_data_and_response_len(
///     &mut buf, 0x00, 0xC0, 0x00, 0x00, &[0x01, 0x02], 0xFF,
/// );
/// assert_eq!(apdu, &[0x00, 0xC0, 0x00, 0x00, 0x02, 0x01, 0x02, 0xFF]);
/// ```
pub fn write_apdu_with_data_and_response_len<'buf>(
    buf: &'buf mut [u8],
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    response_len: u8,
) -> &'buf [u8] {
    assert!(
        data.len() <= 255,
        "Case 4 APDU body must fit in a single short Lc"
    );
    let total = 6 + data.len();
    assert!(buf.len() >= total, "buffer too small for Case 4 APDU");
    write_apdu_with_data(buf, cla, ins, p1, p2, data);
    buf[total - 1] = response_len;
    &buf[..total]
}

// ---------------------------------------------------------------------------
// Deprecated aliases (case1/2/3/4 etc.) -- retained for external callers.
// Internal simrs code should use the descriptive names above.
// ---------------------------------------------------------------------------

/// Deprecated alias for [`apdu_header`].
#[deprecated(
    since = "0.2.0",
    note = "use `apdu_header` -- `case1` is ISO 7816-4 § 5.1 jargon"
)]
#[must_use]
pub const fn case1(cla: u8, ins: u8, p1: u8, p2: u8) -> [u8; 4] {
    apdu_header(cla, ins, p1, p2)
}

/// Deprecated alias for [`apdu_with_response_len`].
#[deprecated(
    since = "0.2.0",
    note = "use `apdu_with_response_len` -- `case2` is ISO 7816-4 § 5.1 jargon"
)]
#[must_use]
pub const fn case2(cla: u8, ins: u8, p1: u8, p2: u8, le: u8) -> [u8; 5] {
    apdu_with_response_len(cla, ins, p1, p2, le)
}

/// Deprecated alias for [`write_apdu_with_data`].
#[deprecated(
    since = "0.2.0",
    note = "use `write_apdu_with_data` -- `write_case3` is ISO 7816-4 § 5.1 jargon"
)]
pub fn write_case3<'buf>(
    buf: &'buf mut [u8],
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> &'buf [u8] {
    write_apdu_with_data(buf, cla, ins, p1, p2, data)
}

/// Deprecated alias for [`write_apdu_with_data_and_response_len`].
#[deprecated(
    since = "0.2.0",
    note = "use `write_apdu_with_data_and_response_len` -- `write_case4` is ISO 7816-4 § 5.1 jargon"
)]
pub fn write_case4<'buf>(
    buf: &'buf mut [u8],
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: u8,
) -> &'buf [u8] {
    write_apdu_with_data_and_response_len(buf, cla, ins, p1, p2, data, le)
}

/// Build an APDU with body (`CLA INS P1 P2 Lc Data`) and return an owned
/// [`alloc::vec::Vec`].
///
/// Corresponds to ISO 7816-4 Case 3S. Used for commands that send data
/// without expecting a data response (PUT KEY, STORE DATA, INSTALL,
/// DELETE, EXTERNAL AUTHENTICATE, ...). For hot paths or `no_alloc`
/// contexts, prefer [`write_apdu_with_data`].
///
/// Available with the `alloc` feature.
///
/// # Panics
///
/// Panics if `data.len() > 255`. Use extended-length encoding for larger
/// payloads.
///
/// ```
/// # #[cfg(feature = "alloc")]
/// # {
/// use simrs_iso7816::apdu_with_data;
///
/// let apdu = apdu_with_data(0x80, 0xE6, 0x04, 0x00, &[0x01, 0x02, 0x03]);
/// assert_eq!(&*apdu, &[0x80, 0xE6, 0x04, 0x00, 0x03, 0x01, 0x02, 0x03]);
/// # }
/// ```
#[cfg(feature = "alloc")]
#[must_use]
pub fn apdu_with_data(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> alloc::vec::Vec<u8> {
    assert!(
        data.len() <= 255,
        "Case 3 APDU body must fit in a single short Lc (<= 255 bytes)"
    );
    let mut v = alloc::vec::Vec::with_capacity(5 + data.len());
    v.extend_from_slice(&[cla, ins, p1, p2]);
    #[allow(clippy::cast_possible_truncation)]
    v.push(data.len() as u8);
    v.extend_from_slice(data);
    v
}

/// Build an APDU with body and expected response length
/// (`CLA INS P1 P2 Lc Data Le`) and return an owned [`alloc::vec::Vec`].
///
/// Corresponds to ISO 7816-4 Case 4S. For commands that both send body
/// and request data back. `response_len` is the `Le` field.
///
/// Available with the `alloc` feature.
///
/// # Panics
///
/// Panics if `data.len() > 255`.
///
/// ```
/// # #[cfg(feature = "alloc")]
/// # {
/// use simrs_iso7816::apdu_with_data_and_response_len;
///
/// let apdu = apdu_with_data_and_response_len(0x00, 0xC0, 0x00, 0x00, &[0x01, 0x02], 0xFF);
/// assert_eq!(&*apdu, &[0x00, 0xC0, 0x00, 0x00, 0x02, 0x01, 0x02, 0xFF]);
/// # }
/// ```
#[cfg(feature = "alloc")]
#[must_use]
pub fn apdu_with_data_and_response_len(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    response_len: u8,
) -> alloc::vec::Vec<u8> {
    assert!(
        data.len() <= 255,
        "Case 4 APDU body must fit in a single short Lc"
    );
    let mut v = alloc::vec::Vec::with_capacity(6 + data.len());
    v.extend_from_slice(&[cla, ins, p1, p2]);
    #[allow(clippy::cast_possible_truncation)]
    v.push(data.len() as u8);
    v.extend_from_slice(data);
    v.push(response_len);
    v
}

/// Deprecated alias for [`apdu_with_data`].
#[cfg(feature = "alloc")]
#[deprecated(
    since = "0.2.0",
    note = "use `apdu_with_data` -- `case3` is ISO 7816-4 § 5.1 jargon"
)]
#[must_use]
pub fn case3(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> alloc::vec::Vec<u8> {
    apdu_with_data(cla, ins, p1, p2, data)
}

/// Deprecated alias for [`apdu_with_data_and_response_len`].
#[cfg(feature = "alloc")]
#[deprecated(
    since = "0.2.0",
    note = "use `apdu_with_data_and_response_len` -- `case4` is ISO 7816-4 § 5.1 jargon"
)]
#[must_use]
pub fn case4(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u8) -> alloc::vec::Vec<u8> {
    apdu_with_data_and_response_len(cla, ins, p1, p2, data, le)
}

// ---------------------------------------------------------------------------
// Response queue
// ---------------------------------------------------------------------------

/// Fixed-capacity response queue for GET RESPONSE buffering.
///
/// Both GSM and USIM application layers queue response data (SELECT FCP,
/// AUTHENTICATE output, etc.) and deliver it via GET RESPONSE. This type
/// captures that shared pattern.
///
/// `CAP` is the maximum response size in bytes (e.g. 23 for GSM, 64 for USIM).
///
/// # Example
///
/// ```
/// use simrs_iso7816::ResponseQueue;
///
/// let mut q = ResponseQueue::<32>::new();
/// assert!(q.is_empty());
///
/// q.queue(&[0x01, 0x02, 0x03]);
/// assert!(!q.is_empty());
/// assert_eq!(q.len(), 3);
///
/// let mut buf = [0u8; 64];
/// let rsp = q.get_response(None, &mut buf);
/// assert_eq!(rsp, &[0x01, 0x02, 0x03, 0x90, 0x00]);
/// assert!(q.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct ResponseQueue<const CAP: usize> {
    buf: [u8; CAP],
    len: u8,
}

impl<const CAP: usize> Default for ResponseQueue<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> ResponseQueue<CAP> {
    /// Create an empty response queue.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; CAP],
            len: 0,
        }
    }

    /// Queue response data. All bytes from `data` are stored (up to `CAP`).
    #[allow(clippy::cast_possible_truncation)] // n is clamped to CAP which fits in u8
    pub fn queue(&mut self, data: &[u8]) {
        let n = data.len().min(CAP);
        self.buf[..n].copy_from_slice(&data[..n]);
        self.len = n as u8;
    }

    /// Queue response data from a mutable buffer reference.
    ///
    /// Sets the queue length to `n` (clamped to CAP). The caller must have
    /// already written the data into [`buf_mut()`](Self::buf_mut).
    #[allow(clippy::cast_possible_truncation)]
    pub fn set_len(&mut self, n: usize) {
        self.len = n.min(CAP) as u8;
    }

    /// Direct access to the internal buffer for in-place response building.
    pub const fn buf_mut(&mut self) -> &mut [u8; CAP] {
        &mut self.buf
    }

    /// Clear the queued response.
    pub const fn clear(&mut self) {
        self.len = 0;
    }

    /// Returns `true` if no response is queued.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of queued response bytes.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Handle GET RESPONSE: copy queued data into `out`, append SW 90 00.
    ///
    /// Returns `&out[..n+2]` where `n` is the number of data bytes copied.
    /// The `le` parameter controls how many bytes the terminal expects;
    /// `None` or `Some(0)` means "all available". Clears the queue after
    /// retrieval.
    ///
    /// If the queue is empty, returns `6F 00` (no precise diagnosis).
    /// If P1/P2 validation is needed, the caller should check before calling.
    pub fn get_response<'buf>(&mut self, le: Option<u8>, out: &'buf mut [u8]) -> &'buf [u8] {
        let len = self.len as usize;
        if len == 0 {
            return write_sw(out, StatusWord::NoPreciseDiagnosis);
        }
        let le = le.unwrap_or(0) as usize;
        let n = if le == 0 { len } else { le.min(len) };
        if out.len() < n + 2 {
            return write_sw(out, StatusWord::NoPreciseDiagnosis);
        }
        out[..n].copy_from_slice(&self.buf[..n]);
        let [sw1, sw2] = StatusWord::Success.to_bytes();
        out[n] = sw1;
        out[n + 1] = sw2;
        self.len = 0;
        &out[..n + 2]
    }

    // -- snapshot --

    /// Snapshot buffer size: `CAP` bytes for data + 1 byte for length.
    pub const SNAPSHOT_SIZE: usize = CAP + 1;

    /// Serialize the queue state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        buf[..CAP].copy_from_slice(&self.buf);
        buf[CAP] = self.len;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the queue state from `buf`.
    ///
    /// Returns `false` if `buf` is too small or contains an invalid length.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        self.buf.copy_from_slice(&buf[..CAP]);
        let queue_len = buf[CAP];
        if queue_len as usize > CAP {
            return false;
        }
        self.len = queue_len;
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    // -- StatusWord --

    #[test]
    fn sw_success_roundtrip() {
        assert_eq!(StatusWord::from_bytes(0x90, 0x00), StatusWord::Success);
        assert_eq!(StatusWord::Success.to_bytes(), [0x90, 0x00]);
    }

    #[test]
    fn sw_bytes_available_roundtrip() {
        let sw = StatusWord::bytes_available(0x1A);
        assert_eq!(sw.to_bytes(), [0x61, 0x1A]);
        assert_eq!(StatusWord::from_bytes(0x61, 0x1A), sw);
    }

    #[test]
    fn sw_pin_retries_roundtrip() {
        let sw = StatusWord::pin_retries(3);
        assert_eq!(sw.to_bytes(), [0x63, 0xC3]);
        assert_eq!(StatusWord::from_bytes(0x63, 0xC3), sw);
    }

    #[test]
    fn sw_error_codes() {
        assert_eq!(StatusWord::WrongLength.to_bytes(), [0x67, 0x00]);
        assert_eq!(StatusWord::ClassNotSupported.to_bytes(), [0x6E, 0x00]);
        assert_eq!(StatusWord::InsNotSupported.to_bytes(), [0x6D, 0x00]);
        assert_eq!(StatusWord::AuthenticationError.to_bytes(), [0x98, 0x62]);
    }

    #[test]
    fn sw_file_not_found() {
        // 6A 82 = file or application not found
        let sw = StatusWord::wrong_params(0x82);
        assert_eq!(sw.to_bytes(), [0x6A, 0x82]);
        assert_eq!(StatusWord::from_bytes(0x6A, 0x82), sw);
    }

    #[test]
    fn sw_proactive_pending() {
        let sw = StatusWord::proactive_pending(0x15);
        assert_eq!(sw.to_bytes(), [0x91, 0x15]);
        assert!(sw.is_success());
    }

    // -- ClassByte --

    #[test]
    fn cla_interindustry() {
        let cla = ClassByte::parse(0x00);
        assert!(cla.is_interindustry());
        assert_eq!(cla.channel(), 0);

        let cla = ClassByte::parse(0x01);
        assert!(cla.is_interindustry());
        assert_eq!(cla.channel(), 1);
    }

    #[test]
    fn cla_proprietary_gsm() {
        let cla = ClassByte::parse(0xA0);
        assert!(cla.is_proprietary());
        assert_eq!(cla.raw(), 0xA0);
    }

    #[test]
    fn cla_proprietary_etsi_cat() {
        let cla = ClassByte::parse(0x80);
        assert!(cla.is_proprietary());
        assert_eq!(cla.raw(), 0x80);
    }

    // -- Command parsing --

    #[test]
    fn parse_case1_header_only() {
        let cmd = Command::parse(&[0x00, 0xA4, 0x00, 0x00]).unwrap();
        assert_eq!(cmd.ins(), ins::SELECT);
        assert_eq!(cmd.data(), &[]);
        assert_eq!(cmd.response_len(), None);
    }

    #[test]
    fn parse_case2_le_only() {
        // GET RESPONSE: 00 C0 00 00 1A
        let cmd = Command::parse(&[0x00, 0xC0, 0x00, 0x00, 0x1A]).unwrap();
        assert_eq!(cmd.ins(), ins::GET_RESPONSE);
        assert_eq!(cmd.data(), &[]);
        assert_eq!(cmd.response_len(), Some(0x1A));
    }

    #[test]
    fn parse_case3_data() {
        // SELECT MF: 00 A4 00 00 02 3F00
        let cmd = Command::parse(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]).unwrap();
        assert_eq!(cmd.ins(), ins::SELECT);
        assert_eq!(cmd.data(), &[0x3F, 0x00]);
        assert_eq!(cmd.response_len(), None);
    }

    #[test]
    fn parse_case4_data_and_le() {
        // SELECT by AID: 00 A4 04 00 07 [AID] 00
        let bytes = [0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x00];
        let cmd = Command::parse(&bytes).unwrap();
        assert_eq!(cmd.data(), &[0xAA, 0xBB]);
        assert_eq!(cmd.response_len(), Some(0x00));
    }

    #[test]
    fn parse_too_short() {
        assert_eq!(Command::parse(&[0x00, 0xA4]), Err(ApduError::TooShort));
        assert_eq!(Command::parse(&[]), Err(ApduError::TooShort));
    }

    #[test]
    fn parse_data_truncated() {
        // Lc=05 but only 2 data bytes present
        let bytes = [0x00, 0xA4, 0x00, 0x00, 0x05, 0x3F, 0x00];
        assert_eq!(Command::parse(&bytes), Err(ApduError::DataTruncated));
    }

    #[test]
    fn parse_gsm_class() {
        // GSM SELECT: A0 A4 00 00 02 3F00
        let cmd = Command::parse(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]).unwrap();
        assert!(cmd.cla().is_proprietary());
        assert_eq!(cmd.cla_raw(), 0xA0);
    }

    #[test]
    fn parse_authenticate() {
        // AUTHENTICATE: 00 88 00 81 22 [RAND:16] [AUTN:16]
        let mut bytes = [0u8; 4 + 1 + 32];
        bytes[0] = 0x00; // CLA
        bytes[1] = 0x88; // INS
        bytes[2] = 0x00; // P1
        bytes[3] = 0x81; // P2 (UMTS/EPS/5GS context)
        bytes[4] = 0x20; // Lc = 32
        // RAND + AUTN = 32 bytes of dummy data
        let cmd = Command::parse(&bytes).unwrap();
        assert_eq!(cmd.ins(), ins::AUTHENTICATE);
        assert_eq!(cmd.p2(), 0x81);
        assert_eq!(cmd.data().len(), 32);
    }

    // -- Extended APDU parsing --

    #[test]
    fn parse_extended_case2e_le_only() {
        // Case 2E: 00 B0 00 00 00 01 00  -- READ BINARY, Le=256
        let bytes = [0x00, 0xB0, 0x00, 0x00, 0x00, 0x01, 0x00];
        let cmd = Command::parse(&bytes).unwrap();
        assert_eq!(cmd.ins(), ins::READ_BINARY);
        assert!(cmd.is_extended());
        assert_eq!(cmd.data(), &[]);
        assert_eq!(cmd.response_len(), None); // short le not available for extended
        assert_eq!(cmd.response_len_extended(), Some(0x0100)); // 256
    }

    #[test]
    fn parse_extended_case2e_le_max() {
        // Case 2E: 00 B0 00 00 00 00 00  -- Le=0 means 65536
        let bytes = [0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00];
        let cmd = Command::parse(&bytes).unwrap();
        assert!(cmd.is_extended());
        assert_eq!(cmd.response_len_extended(), Some(0x0000)); // 0 = 65536
    }

    #[test]
    fn parse_extended_case3e_data() {
        // Case 3E: 00 A4 04 00 00 00 07 [7 bytes AID]
        let mut bytes = [0u8; 7 + 7]; // header(4) + 00(1) + Lc(2) + data(7)
        bytes[0] = 0x00;
        bytes[1] = 0xA4; // SELECT
        bytes[2] = 0x04;
        bytes[3] = 0x00;
        bytes[4] = 0x00; // extended marker
        bytes[5] = 0x00; // Lc high
        bytes[6] = 0x07; // Lc low = 7
        bytes[7..14].copy_from_slice(&[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        let cmd = Command::parse(&bytes).unwrap();
        assert!(cmd.is_extended());
        assert_eq!(cmd.data(), &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        assert_eq!(cmd.response_len(), None);
        assert_eq!(cmd.response_len_extended(), None); // no Le
    }

    #[test]
    fn parse_extended_case4e_data_and_le() {
        // Case 4E: 00 A4 04 00 00 00 02 [2 bytes] 01 00  -- Lc=2, Le=256
        let bytes = [
            0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x01, 0x00,
        ];
        let cmd = Command::parse(&bytes).unwrap();
        assert!(cmd.is_extended());
        assert_eq!(cmd.data(), &[0x3F, 0x00]);
        assert_eq!(cmd.response_len_extended(), Some(0x0100)); // 256
    }

    #[test]
    fn parse_extended_large_data() {
        // Case 3E with 300 bytes of data (exceeds short APDU limit of 255)
        let mut bytes = [0u8; 7 + 300]; // header(4) + 00(1) + Lc(2) + data(300)
        bytes[0] = 0x00;
        bytes[1] = 0xD6; // UPDATE BINARY
        bytes[4] = 0x00; // extended marker
        bytes[5] = 0x01; // Lc high
        bytes[6] = 0x2C; // Lc low = 0x012C = 300
        bytes[7..307].fill(0xAA);
        let cmd = Command::parse(&bytes).unwrap();
        assert!(cmd.is_extended());
        assert_eq!(cmd.data().len(), 300);
        assert!(cmd.data().iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn parse_extended_data_truncated() {
        // Extended Lc=10 but only 3 data bytes
        let bytes = [0x00, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03];
        assert_eq!(Command::parse(&bytes), Err(ApduError::DataTruncated));
    }

    #[test]
    fn parse_short_le_zero_not_extended() {
        // Short Case 2 with Le=0 (5 bytes total) must NOT be parsed as extended
        let bytes = [0x00, 0xC0, 0x00, 0x00, 0x00];
        let cmd = Command::parse(&bytes).unwrap();
        assert!(!cmd.is_extended());
        assert_eq!(cmd.response_len(), Some(0x00)); // short le=0 means 256
        assert_eq!(cmd.response_len_extended(), Some(0x0000)); // upconverted
    }

    #[test]
    fn parse_short_lc_not_extended() {
        // Short Case 3 with Lc=2 (non-zero byte[4]) is always short
        let bytes = [0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
        let cmd = Command::parse(&bytes).unwrap();
        assert!(!cmd.is_extended());
        assert_eq!(cmd.data(), &[0x3F, 0x00]);
    }

    #[test]
    fn le_extended_upconverts_short() {
        // Short Case 4 with Le=0x1A: le_extended() returns Some(0x001A)
        let bytes = [0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x1A];
        let cmd = Command::parse(&bytes).unwrap();
        assert!(!cmd.is_extended());
        assert_eq!(cmd.response_len(), Some(0x1A));
        assert_eq!(cmd.response_len_extended(), Some(0x001A));
    }

    // -- INS constants --

    #[test]
    fn ins_constants_correct() {
        assert_eq!(ins::SELECT, 0xA4);
        assert_eq!(ins::READ_BINARY, 0xB0);
        assert_eq!(ins::READ_RECORD, 0xB2);
        assert_eq!(ins::UPDATE_BINARY, 0xD6);
        assert_eq!(ins::UPDATE_RECORD, 0xDC);
        assert_eq!(ins::VERIFY, 0x20);
        assert_eq!(ins::AUTHENTICATE, 0x88);
        assert_eq!(ins::TERMINAL_PROFILE, 0x10);
        assert_eq!(ins::FETCH, 0x12);
        assert_eq!(ins::ENVELOPE, 0xC2);
    }

    // -- write_sw helpers --

    #[test]
    fn write_sw_success() {
        let mut buf = [0u8; 4];
        let rsp = write_sw(&mut buf, StatusWord::Success);
        assert_eq!(rsp, &[0x90, 0x00]);
    }

    #[test]
    fn write_sw_raw_custom() {
        let mut buf = [0u8; 4];
        let rsp = write_sw_raw(&mut buf, 0x6A, 0x82);
        assert_eq!(rsp, &[0x6A, 0x82]);
    }

    // -- ResponseQueue --

    #[test]
    fn rsp_queue_new_is_empty() {
        let q = ResponseQueue::<32>::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn rsp_queue_queue_and_len() {
        let mut q = ResponseQueue::<32>::new();
        q.queue(&[0x01, 0x02, 0x03]);
        assert!(!q.is_empty());
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn rsp_queue_clear() {
        let mut q = ResponseQueue::<32>::new();
        q.queue(&[0x01, 0x02]);
        q.clear();
        assert!(q.is_empty());
    }

    #[test]
    fn rsp_queue_get_response_all() {
        let mut q = ResponseQueue::<32>::new();
        q.queue(&[0xAA, 0xBB, 0xCC]);
        let mut buf = [0u8; 64];
        let rsp = q.get_response(None, &mut buf);
        assert_eq!(rsp, &[0xAA, 0xBB, 0xCC, 0x90, 0x00]);
        assert!(q.is_empty());
    }

    #[test]
    fn rsp_queue_get_response_le_zero() {
        let mut q = ResponseQueue::<32>::new();
        q.queue(&[0x01, 0x02, 0x03, 0x04]);
        let mut buf = [0u8; 64];
        // Le=0 means "all available"
        let rsp = q.get_response(Some(0), &mut buf);
        assert_eq!(rsp, &[0x01, 0x02, 0x03, 0x04, 0x90, 0x00]);
    }

    #[test]
    fn rsp_queue_get_response_le_truncates() {
        let mut q = ResponseQueue::<32>::new();
        q.queue(&[0x01, 0x02, 0x03, 0x04]);
        let mut buf = [0u8; 64];
        let rsp = q.get_response(Some(2), &mut buf);
        assert_eq!(rsp, &[0x01, 0x02, 0x90, 0x00]);
    }

    #[test]
    fn rsp_queue_get_response_empty_returns_error() {
        let mut q = ResponseQueue::<32>::new();
        let mut buf = [0u8; 64];
        let rsp = q.get_response(None, &mut buf);
        assert_eq!(rsp, &[0x6F, 0x00]); // NoPreciseDiagnosis
    }

    #[test]
    fn rsp_queue_buf_mut_and_set_len() {
        let mut q = ResponseQueue::<32>::new();
        q.buf_mut()[0] = 0xDE;
        q.buf_mut()[1] = 0xAD;
        q.set_len(2);
        assert_eq!(q.len(), 2);
        let mut buf = [0u8; 64];
        let rsp = q.get_response(None, &mut buf);
        assert_eq!(rsp, &[0xDE, 0xAD, 0x90, 0x00]);
    }

    #[test]
    fn rsp_queue_snapshot_roundtrip() {
        let mut q = ResponseQueue::<32>::new();
        q.queue(&[0x01, 0x02, 0x03]);
        let mut snap = [0u8; ResponseQueue::<32>::SNAPSHOT_SIZE];
        let n = q.save_state(&mut snap);
        assert_eq!(n, ResponseQueue::<32>::SNAPSHOT_SIZE);

        let mut restored = ResponseQueue::<32>::new();
        assert!(restored.restore_state(&snap));
        assert_eq!(restored.len(), 3);

        let mut buf = [0u8; 64];
        let rsp = restored.get_response(None, &mut buf);
        assert_eq!(rsp, &[0x01, 0x02, 0x03, 0x90, 0x00]);
    }

    #[test]
    fn rsp_queue_snapshot_small_buf_returns_zero() {
        let q = ResponseQueue::<32>::new();
        let mut small = [0u8; 2];
        assert_eq!(q.save_state(&mut small), 0);
    }

    #[test]
    fn rsp_queue_restore_invalid_len() {
        let mut q = ResponseQueue::<4>::new();
        // len byte = 5, but CAP = 4
        let snap = [0u8, 0u8, 0u8, 0u8, 5];
        assert!(!q.restore_state(&snap));
    }

    #[test]
    fn rsp_queue_queue_clamps_to_cap() {
        let mut q = ResponseQueue::<4>::new();
        q.queue(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(q.len(), 4);
    }

    #[test]
    fn apdu_error_display_non_empty() {
        let variants: &[ApduError] = &[ApduError::TooShort, ApduError::DataTruncated];
        for v in variants {
            let s = alloc::format!("{v}");
            assert!(
                !s.is_empty(),
                "Display for {v:?} must produce non-empty string"
            );
        }
    }

    // ----------------------------------------------------------------------
    // APDU command builders -- round-trip with Command::parse
    // ----------------------------------------------------------------------

    #[test]
    fn apdu_header_builds_4_bytes() {
        let apdu = apdu_header(0x80, 0xF2, 0x80, 0x00);
        assert_eq!(apdu, [0x80, 0xF2, 0x80, 0x00]);

        // Parses back to a Case 1 Command.
        let cmd = Command::parse(&apdu).expect("apdu_header parses");
        assert_eq!(cmd.cla().raw(), 0x80);
        assert_eq!(cmd.ins(), 0xF2);
        assert_eq!(cmd.p1(), 0x80);
        assert_eq!(cmd.p2(), 0x00);
        assert!(cmd.data().is_empty());
        assert_eq!(cmd.response_len(), None);
    }

    #[test]
    fn apdu_with_response_len_builds_5_bytes() {
        let apdu = apdu_with_response_len(0x00, 0xB0, 0x00, 0x00, 0x10);
        assert_eq!(apdu, [0x00, 0xB0, 0x00, 0x00, 0x10]);

        let cmd = Command::parse(&apdu).expect("apdu_with_response_len parses");
        assert!(cmd.data().is_empty());
        assert_eq!(cmd.response_len(), Some(0x10));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn apdu_with_data_builds_header_lc_data() {
        let body = [0x01, 0x02, 0x03];
        let apdu = apdu_with_data(0x80, 0xE6, 0x04, 0x00, &body);
        assert_eq!(&*apdu, &[0x80, 0xE6, 0x04, 0x00, 0x03, 0x01, 0x02, 0x03]);

        let cmd = Command::parse(&apdu).expect("apdu_with_data parses");
        assert_eq!(cmd.cla().raw(), 0x80);
        assert_eq!(cmd.ins(), 0xE6);
        assert_eq!(cmd.data(), &body);
        assert_eq!(cmd.response_len(), None);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn apdu_with_data_empty_body_emits_lc_zero() {
        // Lc = 0 with no following data is a valid Case 3S form.
        let apdu = apdu_with_data(0x80, 0xCA, 0x00, 0x66, &[]);
        assert_eq!(&*apdu, &[0x80, 0xCA, 0x00, 0x66, 0x00]);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn apdu_with_data_and_response_len_builds_full() {
        let body = [0x11, 0x22, 0x33, 0x44];
        let apdu = apdu_with_data_and_response_len(0x80, 0x50, 0x00, 0x00, &body, 0x1C);
        assert_eq!(
            &*apdu,
            &[0x80, 0x50, 0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x1C]
        );

        let cmd = Command::parse(&apdu).expect("apdu_with_data_and_response_len parses");
        assert_eq!(cmd.data(), &body);
        assert_eq!(cmd.response_len(), Some(0x1C));
    }

    #[test]
    fn write_apdu_with_data_returns_written_slice() {
        let mut buf = [0u8; 16];
        let apdu = write_apdu_with_data(&mut buf, 0x80, 0xE6, 0x04, 0x00, &[0xAA, 0xBB]);
        assert_eq!(apdu, &[0x80, 0xE6, 0x04, 0x00, 0x02, 0xAA, 0xBB]);
        // Bytes past the slice must be untouched.
        assert_eq!(buf[7..], [0u8; 9]);
    }

    #[test]
    fn write_apdu_with_data_and_response_len_le_at_end() {
        let mut buf = [0u8; 16];
        let apdu = write_apdu_with_data_and_response_len(
            &mut buf,
            0x00,
            0xC0,
            0x00,
            0x00,
            &[0xAA, 0xBB],
            0xFF,
        );
        assert_eq!(apdu, &[0x00, 0xC0, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xFF]);
        // Le must be the last byte; off-by-one regression guard.
        assert_eq!(apdu[apdu.len() - 1], 0xFF);
    }

    #[test]
    #[should_panic(expected = "buffer too small")]
    fn write_apdu_with_data_panics_on_undersized_buffer() {
        let mut buf = [0u8; 4]; // need 5 + 2 = 7
        let _ = write_apdu_with_data(&mut buf, 0x80, 0xE6, 0x04, 0x00, &[0xAA, 0xBB]);
    }

    #[test]
    #[should_panic(expected = "must fit in a single short Lc")]
    fn write_apdu_with_data_panics_on_oversized_body() {
        let big = [0u8; 256];
        let mut buf = [0u8; 512];
        let _ = write_apdu_with_data(&mut buf, 0x80, 0xE6, 0x04, 0x00, &big);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[should_panic(expected = "must fit in a single short Lc")]
    fn apdu_with_data_panics_on_oversized_body() {
        let big = alloc::vec![0u8; 256];
        let _ = apdu_with_data(0x80, 0xE6, 0x04, 0x00, &big);
    }
}
