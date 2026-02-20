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
//! For short APDUs (which simrs targets): Lc and Le are each 0 or 1 byte,
//! data is 0-255 bytes.
//!
//! # CLA Byte Routing
//!
//! The CLA byte determines the command class and routing:
//!
//! | CLA | Class | Standard |
//! |-----|-------|----------|
//! | `0x0X`, `0x4X`, `0x6X` | Interindustry | ISO/IEC 7816-4 / ETSI TS 102 221 |
//! | `0x8X` | ETSI proprietary (CAT) | ETSI TS 102 221 clause 10.1.1 |
//! | `0xA0` | GSM proprietary | GSM 11.11 / 3GPP TS 51.011 |
//!
//! # Standards
//! - ISO/IEC 7816-4:2020 -- Organization, security, and commands
//! - ETSI TS 102 221 V16.4.0 clause 10.1.1 -- UICC-terminal CLA byte
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
// Instruction codes
// ---------------------------------------------------------------------------

/// Well-known INS (instruction) byte values.
///
/// Per ISO/IEC 7816-4:2020 clause 5.1.2 and ETSI TS 102 221 clause 11.1.
///
/// ```
/// use simrs_iso7816::ins;
///
/// assert_eq!(ins::SELECT, 0xA4);
/// assert_eq!(ins::READ_BINARY, 0xB0);
/// assert_eq!(ins::VERIFY, 0x20);
/// ```
pub mod ins {
    /// SELECT (file, DF, AID). ISO 7816-4, ETSI TS 102 221 clause 11.1.1.
    pub const SELECT: u8 = 0xA4;
    /// STATUS. ETSI TS 102 221 clause 11.1.2.
    pub const STATUS: u8 = 0xF2;
    /// READ BINARY. ETSI TS 102 221 clause 11.1.3.
    pub const READ_BINARY: u8 = 0xB0;
    /// UPDATE BINARY. ETSI TS 102 221 clause 11.1.4.
    pub const UPDATE_BINARY: u8 = 0xD6;
    /// READ RECORD. ETSI TS 102 221 clause 11.1.5.
    pub const READ_RECORD: u8 = 0xB2;
    /// UPDATE RECORD. ETSI TS 102 221 clause 11.1.6.
    pub const UPDATE_RECORD: u8 = 0xDC;
    /// GET RESPONSE. ISO 7816-4.
    pub const GET_RESPONSE: u8 = 0xC0;
    /// VERIFY (PIN). ETSI TS 102 221 clause 11.1.9.
    pub const VERIFY: u8 = 0x20;
    /// CHANGE REFERENCE DATA (change PIN). ETSI TS 102 221 clause 11.1.10.
    pub const CHANGE_REF_DATA: u8 = 0x24;
    /// DISABLE PIN. ETSI TS 102 221 clause 11.1.11.
    pub const DISABLE_PIN: u8 = 0x26;
    /// ENABLE PIN. ETSI TS 102 221 clause 11.1.11.
    pub const ENABLE_PIN: u8 = 0x28;
    /// RESET RETRY COUNTER (unblock PIN). ETSI TS 102 221 clause 11.1.12.
    pub const RESET_RETRY_CTR: u8 = 0x2C;
    /// AUTHENTICATE (INTERNAL AUTHENTICATE / GENERAL AUTHENTICATE).
    /// ETSI TS 102 221 clause 11.1.16 / 3GPP TS 31.102 clause 7.1.2.
    pub const AUTHENTICATE: u8 = 0x88;
    /// TERMINAL PROFILE. ETSI TS 102 221 clause 11.2.1.
    pub const TERMINAL_PROFILE: u8 = 0x10;
    /// FETCH (proactive command retrieval). ETSI TS 102 221 clause 11.2.2.
    pub const FETCH: u8 = 0x12;
    /// TERMINAL RESPONSE. ETSI TS 102 221 clause 11.2.3.
    pub const TERMINAL_RESPONSE: u8 = 0x14;
    /// ENVELOPE. ETSI TS 102 221 clause 11.2.4.
    pub const ENVELOPE: u8 = 0xC2;
    /// INCREASE. ETSI TS 102 221 clause 11.1.7.
    pub const INCREASE: u8 = 0x32;
    /// MANAGE CHANNEL. ETSI TS 102 221 clause 11.1.17.
    pub const MANAGE_CHANNEL: u8 = 0x70;
}

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

/// APDU status word (SW1-SW2).
///
/// Per ISO/IEC 7816-4:2020 clause 5.6 and ETSI TS 102 221 clause 10.2.1.
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
    /// Per ETSI TS 102 223 clause 6.1.
    ProactivePending(u8),
    /// `98 62` -- Authentication error (MAC failure).
    /// Per 3GPP TS 31.102 clause 7.1.2.1.
    AuthenticationError,
    /// Any other SW1/SW2 pair not specifically modeled.
    Other(u8, u8),
}

impl StatusWord {
    /// `61 XX` -- response bytes available.
    pub const fn bytes_available(len: u8) -> Self { Self::BytesAvailable(len) }
    /// `63 CX` -- PIN retries remaining.
    pub const fn pin_retries(n: u8) -> Self { Self::PinRetries(n & 0x0F) }
    /// `6A XX` -- wrong parameters.
    pub const fn wrong_params(sw2: u8) -> Self { Self::WrongParams(sw2) }
    /// `69 XX` -- command not allowed.
    pub const fn command_not_allowed(sw2: u8) -> Self { Self::CommandNotAllowed(sw2) }
    /// `6C XX` -- exact length.
    pub const fn exact_length(len: u8) -> Self { Self::ExactLength(len) }
    /// `91 XX` -- proactive pending.
    pub const fn proactive_pending(len: u8) -> Self { Self::ProactivePending(len) }

    /// Encode as `[SW1, SW2]`.
    ///
    /// ```
    /// use simrs_iso7816::StatusWord;
    /// assert_eq!(StatusWord::Success.to_bytes(), [0x90, 0x00]);
    /// ```
    pub const fn to_bytes(self) -> [u8; 2] {
        match self {
            Self::Success              => [0x90, 0x00],
            Self::BytesAvailable(n)    => [0x61, n],
            Self::PinRetries(n)        => [0x63, 0xC0 | (n & 0x0F)],
            Self::WarningUnchanged(n)  => [0x63, n],
            Self::WrongLength          => [0x67, 0x00],
            Self::ExactLength(n)       => [0x6C, n],
            Self::FunctionNotSupported(n) => [0x68, n],
            Self::CommandNotAllowed(n) => [0x69, n],
            Self::WrongParams(n)       => [0x6A, n],
            Self::WrongP1P2            => [0x6B, 0x00],
            Self::InsNotSupported      => [0x6D, 0x00],
            Self::ClassNotSupported    => [0x6E, 0x00],
            Self::NoPreciseDiagnosis   => [0x6F, 0x00],
            Self::ProactivePending(n)  => [0x91, n],
            Self::AuthenticationError  => [0x98, 0x62],
            Self::Other(sw1, sw2)      => [sw1, sw2],
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
            (0x61, n)    => Self::BytesAvailable(n),
            (0x63, n) if n & 0xF0 == 0xC0 => Self::PinRetries(n & 0x0F),
            (0x63, n)    => Self::WarningUnchanged(n),
            (0x67, 0x00) => Self::WrongLength,
            (0x6C, n)    => Self::ExactLength(n),
            (0x68, n)    => Self::FunctionNotSupported(n),
            (0x69, n)    => Self::CommandNotAllowed(n),
            (0x6A, n)    => Self::WrongParams(n),
            (0x6B, 0x00) => Self::WrongP1P2,
            (0x6D, 0x00) => Self::InsNotSupported,
            (0x6E, 0x00) => Self::ClassNotSupported,
            (0x6F, 0x00) => Self::NoPreciseDiagnosis,
            (0x91, n)    => Self::ProactivePending(n),
            (0x98, 0x62) => Self::AuthenticationError,
            (s1, s2)     => Self::Other(s1, s2),
        }
    }

    /// Is this a success status (SW1 = 0x90 or 0x91)?
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success | Self::ProactivePending(_))
    }
}

// ---------------------------------------------------------------------------
// CLA byte
// ---------------------------------------------------------------------------

/// Parsed CLA (class) byte.
///
/// Per ISO/IEC 7816-4:2020 clause 5.1.1 and ETSI TS 102 221 clause 10.1.1.
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
/// assert_eq!(cmd.le(), None);
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
}

impl<'a> Command<'a> {
    /// Parse a short APDU command from raw bytes.
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
            return Ok(Self { cla, ins, p1, p2, data: &[], le: None });
        }

        let p3 = bytes[4];

        if bytes.len() == 5 {
            // Case 2: Le only (Lc=0, Le=P3)
            return Ok(Self { cla, ins, p1, p2, data: &[], le: Some(p3) });
        }

        // Case 3 or 4: Lc = P3, followed by data, optionally Le
        let lc = p3 as usize;
        if bytes.len() < 5 + lc {
            return Err(ApduError::DataTruncated);
        }

        // data = bytes[5 .. 5+lc]
        // We can't use range indexing in const fn, so use split_at
        let (_, after_header) = bytes.split_at(5);
        let (data, remainder) = after_header.split_at(lc);

        let le = if remainder.is_empty() {
            None // Case 3
        } else {
            Some(remainder[0]) // Case 4
        };

        Ok(Self { cla, ins, p1, p2, data, le })
    }

    /// Parsed CLA byte.
    pub const fn cla(&self) -> ClassByte { self.cla }
    /// Raw CLA byte value.
    pub const fn cla_raw(&self) -> u8 { self.cla.raw() }
    /// INS (instruction) byte.
    pub const fn ins(&self) -> u8 { self.ins }
    /// P1 parameter byte.
    pub const fn p1(&self) -> u8 { self.p1 }
    /// P2 parameter byte.
    pub const fn p2(&self) -> u8 { self.p2 }
    /// Command data field (may be empty).
    pub const fn data(&self) -> &[u8] { self.data }
    /// Le (expected response length), if present.
    pub const fn le(&self) -> Option<u8> { self.le }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
        assert_eq!(cmd.le(), None);
    }

    #[test]
    fn parse_case2_le_only() {
        // GET RESPONSE: 00 C0 00 00 1A
        let cmd = Command::parse(&[0x00, 0xC0, 0x00, 0x00, 0x1A]).unwrap();
        assert_eq!(cmd.ins(), ins::GET_RESPONSE);
        assert_eq!(cmd.data(), &[]);
        assert_eq!(cmd.le(), Some(0x1A));
    }

    #[test]
    fn parse_case3_data() {
        // SELECT MF: 00 A4 00 00 02 3F00
        let cmd = Command::parse(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]).unwrap();
        assert_eq!(cmd.ins(), ins::SELECT);
        assert_eq!(cmd.data(), &[0x3F, 0x00]);
        assert_eq!(cmd.le(), None);
    }

    #[test]
    fn parse_case4_data_and_le() {
        // SELECT by AID: 00 A4 04 00 07 [AID] 00
        let bytes = [0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x00];
        let cmd = Command::parse(&bytes).unwrap();
        assert_eq!(cmd.data(), &[0xAA, 0xBB]);
        assert_eq!(cmd.le(), Some(0x00));
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
}
