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

impl core::fmt::Display for StatusWord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [sw1, sw2] = self.to_bytes();
        match self {
            Self::Success => write!(f, "{sw1:02X}{sw2:02X} ok"),
            Self::BytesAvailable(n) => write!(f, "{sw1:02X}{sw2:02X} {n} bytes available"),
            Self::PinRetries(n) => write!(f, "{sw1:02X}{sw2:02X} {n} PIN retries remaining"),
            Self::WarningUnchanged(_) => write!(f, "{sw1:02X}{sw2:02X} warning, non-volatile memory unchanged"),
            Self::WrongLength => write!(f, "{sw1:02X}{sw2:02X} wrong length"),
            Self::ExactLength(n) => write!(f, "{sw1:02X}{sw2:02X} exact length {n}"),
            Self::FunctionNotSupported(_) => write!(f, "{sw1:02X}{sw2:02X} function not supported"),
            Self::CommandNotAllowed(_) => write!(f, "{sw1:02X}{sw2:02X} command not allowed"),
            Self::WrongParams(_) => write!(f, "{sw1:02X}{sw2:02X} wrong parameters"),
            Self::WrongP1P2 => write!(f, "{sw1:02X}{sw2:02X} wrong P1-P2"),
            Self::InsNotSupported => write!(f, "{sw1:02X}{sw2:02X} instruction not supported"),
            Self::ClassNotSupported => write!(f, "{sw1:02X}{sw2:02X} class not supported"),
            Self::NoPreciseDiagnosis => write!(f, "{sw1:02X}{sw2:02X} no precise diagnosis"),
            Self::ProactivePending(n) => write!(f, "{sw1:02X}{sw2:02X} proactive command pending, fetch {n}"),
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

impl core::fmt::Display for ApduError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => f.write_str("APDU too short"),
            Self::DataTruncated => f.write_str("Lc/data length mismatch"),
        }
    }
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
        out[n] = 0x90;
        out[n + 1] = 0x00;
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
}
