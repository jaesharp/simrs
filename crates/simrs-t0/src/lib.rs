//! ISO 7816-3 T=0 character protocol and ATR handling.
//!
//! Implements the character-level transport layer between a terminal and a
//! smart card.  The T=0 state machine converts between byte-at-a-time I/O
//! (as seen on the I/O line) and complete APDU commands/responses.
//!
//! # Architecture
//!
//! ```text
//! Terminal                        T0Protocol                        Card
//!   |  --- CLA INS P1 P2 [P3] ----->  |                              |
//!   |                                  |  (assembles 5-byte header)   |
//!   |                                  |  --- full APDU header -----> |
//!   |  <--- procedure byte (INS) ---  |  <--- procedure byte ------  |
//!   |  --- data byte(s) ----------->  |  --- data byte(s) --------> |
//!   |  <--- SW1 SW2 ---------------  |  <--- SW1 SW2 ------------- |
//! ```
//!
//! # ATR (Answer To Reset)
//!
//! The [`Atr`] type parses and represents the Answer To Reset per ISO 7816-3
//! clause 8.  It extracts protocol parameters (Fi, Di, guard time, waiting
//! time) and historical bytes.
//!
//! # PPS (Protocol and Parameters Selection)
//!
//! The [`Pps`] type handles PPS exchange per ISO 7816-3 clause 9. After ATR
//! reception, the terminal may negotiate alternative Fi/Di values.
//!
//! # `no_std`, `no_alloc`
//!
//! This crate is `no_std` with zero heap allocations.  All buffers are
//! stack-allocated with compile-time sizes.
//!
//! # Example
//!
//! ```
//! use simrs_t0::{Atr, Convention};
//!
//! // Minimal ATR: direct convention, no interface bytes.
//! let atr = Atr::parse(&[0x3B, 0x00]).unwrap();
//! assert_eq!(atr.convention(), Convention::Direct);
//! assert_eq!(atr.historical_bytes(), &[]);
//! assert_eq!(atr.fi(), 372);
//! assert_eq!(atr.di(), 1);
//! ```

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from ATR parsing, PPS exchange, or T=0 protocol operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T0Error {
    /// ATR is too short (need at least TS + T0).
    AtrTooShort,
    /// ATR initial byte (TS) is neither `0x3B` (direct) nor `0x3F` (inverse).
    AtrBadTs,
    /// ATR is truncated (declared interface/historical bytes missing).
    AtrTruncated,
    /// ATR check byte (TCK) is incorrect.
    AtrBadTck,
    /// ATR exceeds the 33-byte maximum (TS + up to 32 bytes).
    AtrTooLong,
    /// PPS request is malformed.
    PpsMalformed,
    /// PPS check byte (PCK) does not match.
    PpsBadPck,
    /// T=0 header is incomplete (need 5 bytes: CLA INS P1 P2 P3).
    HeaderIncomplete,
    /// Unexpected state transition in the T=0 state machine.
    InvalidState,
    /// Response buffer overflow.
    BufferOverflow,
}

impl core::fmt::Display for T0Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AtrTooShort => f.write_str("ATR too short"),
            Self::AtrBadTs => f.write_str("bad TS byte in ATR"),
            Self::AtrTruncated => f.write_str("ATR truncated"),
            Self::AtrBadTck => f.write_str("ATR check byte mismatch"),
            Self::AtrTooLong => f.write_str("ATR exceeds 33-byte limit"),
            Self::PpsMalformed => f.write_str("PPS request malformed"),
            Self::PpsBadPck => f.write_str("PPS check byte mismatch"),
            Self::HeaderIncomplete => f.write_str("T=0 header incomplete"),
            Self::InvalidState => f.write_str("invalid T=0 state"),
            Self::BufferOverflow => f.write_str("buffer overflow"),
        }
    }
}

// ---------------------------------------------------------------------------
// Convention (direct / inverse)
// ---------------------------------------------------------------------------

/// Bit-ordering convention indicated by the TS byte of the ATR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Convention {
    /// Direct convention (TS = `0x3B`): logical 1 is high.
    Direct,
    /// Inverse convention (TS = `0x3F`): logical 1 is low, bit order reversed.
    Inverse,
}

impl Convention {
    /// Decode a byte received on the I/O line into its logical value.
    ///
    /// For direct convention this is the identity.  For inverse convention
    /// the byte is bit-reversed and complemented per ISO 7816-3 clause 7.
    #[inline]
    pub const fn decode(self, byte: u8) -> u8 {
        match self {
            Self::Direct => byte,
            Self::Inverse => {
                // Bit-reverse + complement.  ISO 7816-3: inverse convention
                // reverses the bit order (b1<->b8, b2<->b7, etc.) and
                // complements each bit.
                let mut b = byte;
                b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
                b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
                b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
                b ^ 0xFF
            }
        }
    }

    /// Encode a logical byte for transmission on the I/O line.
    ///
    /// For direct convention this is the identity.  For inverse convention
    /// the byte is complemented and bit-reversed.
    #[inline]
    pub const fn encode(self, byte: u8) -> u8 {
        // Encoding is the same operation as decoding (self-inverse).
        self.decode(byte)
    }
}

// ---------------------------------------------------------------------------
// Fi / Di tables (ISO 7816-3 Table 7 & 8)
// ---------------------------------------------------------------------------

/// Clock rate conversion factor (Fi) table indexed by the high nibble of TA1.
///
/// Index 0 and entries marked "RFU" in the standard use the default Fi=372.
const FI_TABLE: [u16; 16] = [
    372,  // 0: default
    372,  // 1
    558,  // 2
    744,  // 3
    1116, // 4
    1488, // 5
    1860, // 6
    372,  // 7: RFU
    372,  // 8: RFU
    512,  // 9
    768,  // A
    1024, // B
    1536, // C
    2048, // D
    372,  // E: RFU
    372,  // F: RFU
];

/// Baud rate adjustment factor (Di) table indexed by the low nibble of TA1.
///
/// Index 0 and entries marked "RFU" use the default Di=1.
const DI_TABLE: [u8; 16] = [
    1,  // 0: default
    1,  // 1
    2,  // 2
    4,  // 3
    8,  // 4
    16, // 5
    32, // 6
    64, // 7
    12, // 8
    20, // 9
    1,  // A: RFU
    1,  // B: RFU
    1,  // C: RFU
    1,  // D: RFU
    1,  // E: RFU
    1,  // F: RFU
];

// ---------------------------------------------------------------------------
// ATR
// ---------------------------------------------------------------------------

/// Maximum ATR length per ISO 7816-3: TS + up to 32 following bytes.
pub const ATR_MAX_LEN: usize = 33;

/// Parsed Answer To Reset (ATR) per ISO 7816-3 clause 8.
///
/// Stores the raw ATR bytes and decoded protocol parameters.
///
/// # Example
///
/// ```
/// use simrs_t0::Atr;
///
/// // ATR with TA1 indicating Fi=512, Di=8.
/// let atr = Atr::parse(&[0x3B, 0x10, 0x94]).unwrap();
/// assert_eq!(atr.fi(), 512);
/// assert_eq!(atr.di(), 8);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Atr {
    /// Raw ATR bytes.
    raw: [u8; ATR_MAX_LEN],
    /// Length of valid bytes in `raw`.
    len: u8,
    /// Convention (direct or inverse).
    convention: Convention,
    /// Fi (clock rate conversion factor).
    fi: u16,
    /// Di (baud rate adjustment factor).
    di: u8,
    /// Extra guard time N (from TC1, default 0).
    guard_time_n: u8,
    /// Waiting time index WI (from TC2, default 10).
    wi: u8,
    /// Start of historical bytes in `raw`.
    hist_start: u8,
    /// Number of historical bytes.
    hist_len: u8,
    /// Whether T=0 protocol is supported.
    t0_supported: bool,
}

/// Intermediate result from parsing ATR interface bytes.
struct AtrInterfaceParams {
    fi: u16,
    di: u8,
    guard_time_n: u8,
    wi: u8,
    t0_supported: bool,
    tck_required: bool,
    pos: usize,
}

/// Walk ATR interface bytes starting from T0.
fn parse_interface_bytes(bytes: &[u8], t0: u8) -> Result<AtrInterfaceParams, T0Error> {
    let mut fi: u16 = 372;
    let mut di: u8 = 1;
    let mut guard_time_n: u8 = 0;
    let mut wi: u8 = 10;
    let mut t0_supported = true;
    let mut tck_required = false;

    let mut pos: usize = 2;
    let mut td_byte = t0;
    let mut layer: u8 = 0;

    loop {
        let y = td_byte >> 4;

        if y & 0x01 != 0 {
            if pos >= bytes.len() {
                return Err(T0Error::AtrTruncated);
            }
            let ta = bytes[pos];
            pos += 1;
            if layer == 0 {
                fi = FI_TABLE[(ta >> 4) as usize];
                di = DI_TABLE[(ta & 0x0F) as usize];
            }
        }

        if y & 0x02 != 0 {
            if pos >= bytes.len() {
                return Err(T0Error::AtrTruncated);
            }
            pos += 1;
        }

        if y & 0x04 != 0 {
            if pos >= bytes.len() {
                return Err(T0Error::AtrTruncated);
            }
            let tc = bytes[pos];
            pos += 1;
            if layer == 0 {
                guard_time_n = tc;
            } else if layer == 1 {
                wi = tc;
            }
        }

        if y & 0x08 != 0 {
            if pos >= bytes.len() {
                return Err(T0Error::AtrTruncated);
            }
            td_byte = bytes[pos];
            pos += 1;
            layer += 1;
            let protocol = td_byte & 0x0F;
            if protocol != 0 {
                tck_required = true;
            }
            if protocol == 0 {
                t0_supported = true;
            }
        } else {
            break;
        }
    }

    Ok(AtrInterfaceParams {
        fi,
        di,
        guard_time_n,
        wi,
        t0_supported,
        tck_required,
        pos,
    })
}

impl Atr {
    /// Parse an ATR from raw bytes.
    ///
    /// Validates structure, extracts Fi/Di/guard-time/waiting-time parameters,
    /// and verifies TCK when required (i.e. when any protocol other than T=0
    /// is indicated).
    ///
    /// # Errors
    ///
    /// Returns [`T0Error::AtrTooShort`] if fewer than 2 bytes, [`T0Error::AtrBadTs`]
    /// if TS is invalid, [`T0Error::AtrTruncated`] if declared bytes are missing,
    /// [`T0Error::AtrBadTck`] if the check byte is wrong, or [`T0Error::AtrTooLong`]
    /// if the ATR exceeds 33 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, T0Error> {
        if bytes.len() < 2 {
            return Err(T0Error::AtrTooShort);
        }
        if bytes.len() > ATR_MAX_LEN {
            return Err(T0Error::AtrTooLong);
        }

        let convention = match bytes[0] {
            0x3B => Convention::Direct,
            0x3F => Convention::Inverse,
            _ => return Err(T0Error::AtrBadTs),
        };

        let t0 = bytes[1];
        let num_historical = (t0 & 0x0F) as usize;

        let params = parse_interface_bytes(bytes, t0)?;

        // Historical bytes.
        let hist_start = params.pos;
        if hist_start + num_historical > bytes.len() {
            return Err(T0Error::AtrTruncated);
        }
        let mut final_pos = hist_start + num_historical;

        // TCK (check byte) -- required when any TD byte indicates T != 0.
        if params.tck_required {
            if final_pos >= bytes.len() {
                return Err(T0Error::AtrTruncated);
            }
            let mut xor: u8 = 0;
            for &b in &bytes[1..=final_pos] {
                xor ^= b;
            }
            if xor != 0 {
                return Err(T0Error::AtrBadTck);
            }
            final_pos += 1;
        }

        if final_pos != bytes.len() {
            return Err(T0Error::AtrTruncated);
        }

        let mut raw = [0u8; ATR_MAX_LEN];
        raw[..bytes.len()].copy_from_slice(bytes);

        #[allow(clippy::cast_possible_truncation)]
        Ok(Self {
            raw,
            len: bytes.len() as u8,
            convention,
            fi: params.fi,
            di: params.di,
            guard_time_n: params.guard_time_n,
            wi: params.wi,
            hist_start: hist_start as u8,
            hist_len: num_historical as u8,
            t0_supported: params.t0_supported,
        })
    }

    /// Build a minimal ATR for a T=0-only card.
    ///
    /// Returns an ATR with direct convention, default Fi/Di (372/1), and
    /// the given historical bytes (up to 15).
    ///
    /// # Errors
    ///
    /// Returns [`T0Error::AtrTooLong`] if more than 15 historical bytes.
    pub fn build_minimal(historical: &[u8]) -> Result<Self, T0Error> {
        let num_hist = historical.len();
        if num_hist > 15 {
            return Err(T0Error::AtrTooLong);
        }
        let total_len = 2 + num_hist;
        if total_len > ATR_MAX_LEN {
            return Err(T0Error::AtrTooLong);
        }

        let mut raw = [0u8; ATR_MAX_LEN];
        raw[0] = 0x3B;
        #[allow(clippy::cast_possible_truncation)]
        {
            raw[1] = num_hist as u8;
        }
        raw[2..2 + num_hist].copy_from_slice(historical);

        #[allow(clippy::cast_possible_truncation)]
        Ok(Self {
            raw,
            len: total_len as u8,
            convention: Convention::Direct,
            fi: 372,
            di: 1,
            guard_time_n: 0,
            wi: 10,
            hist_start: 2,
            hist_len: num_hist as u8,
            t0_supported: true,
        })
    }

    /// Build an ATR with custom Fi/Di values.
    ///
    /// Emits TA1 with the given Fi/Di indices, producing a 3-byte ATR
    /// (TS + T0 + TA1) plus any historical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`T0Error::AtrTooLong`] if more than 15 historical bytes.
    pub fn build_with_fi_di(
        fi_index: u8,
        di_index: u8,
        historical: &[u8],
    ) -> Result<Self, T0Error> {
        let num_hist = historical.len();
        if num_hist > 15 {
            return Err(T0Error::AtrTooLong);
        }
        let total_len = 3 + num_hist;
        if total_len > ATR_MAX_LEN {
            return Err(T0Error::AtrTooLong);
        }

        let fi_idx = (fi_index & 0x0F) as usize;
        let di_idx = (di_index & 0x0F) as usize;

        let mut raw = [0u8; ATR_MAX_LEN];
        raw[0] = 0x3B;
        #[allow(clippy::cast_possible_truncation)]
        {
            raw[1] = 0x10 | (num_hist as u8);
        }
        raw[2] = (fi_index << 4) | di_index;
        raw[3..3 + num_hist].copy_from_slice(historical);

        #[allow(clippy::cast_possible_truncation)]
        Ok(Self {
            raw,
            len: total_len as u8,
            convention: Convention::Direct,
            fi: FI_TABLE[fi_idx],
            di: DI_TABLE[di_idx],
            guard_time_n: 0,
            wi: 10,
            hist_start: 3,
            hist_len: num_hist as u8,
            t0_supported: true,
        })
    }

    /// Raw ATR bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw[..self.len as usize]
    }

    /// Bit-ordering convention.
    pub const fn convention(&self) -> Convention {
        self.convention
    }

    /// Clock rate conversion factor Fi (default 372).
    pub const fn fi(&self) -> u16 {
        self.fi
    }

    /// Baud rate adjustment factor Di (default 1).
    pub const fn di(&self) -> u8 {
        self.di
    }

    /// Extra guard time N from TC1 (default 0).
    pub const fn guard_time_n(&self) -> u8 {
        self.guard_time_n
    }

    /// Waiting time index WI from TC2 (default 10).
    pub const fn wi(&self) -> u8 {
        self.wi
    }

    /// Work Waiting Time in ETU: 960 * Di * WI.
    pub const fn work_waiting_time_etu(&self) -> u32 {
        960 * self.di as u32 * self.wi as u32
    }

    /// Elementary Time Unit duration in clock cycles: Fi / Di.
    pub const fn etu_clocks(&self) -> u16 {
        if self.di == 0 {
            return self.fi;
        }
        self.fi / self.di as u16
    }

    /// Character Guard Time in ETU (minimum 12 for T=0, plus N from TC1).
    pub const fn character_guard_time_etu(&self) -> u16 {
        12 + self.guard_time_n as u16
    }

    /// Historical bytes from the ATR.
    pub fn historical_bytes(&self) -> &[u8] {
        let start = self.hist_start as usize;
        let end = start + self.hist_len as usize;
        &self.raw[start..end]
    }

    /// Whether T=0 protocol is supported (should always be true for
    /// ISO 7816-3 compliant cards, but may be false if only T=1 is declared).
    pub const fn t0_supported(&self) -> bool {
        self.t0_supported
    }
}

// ---------------------------------------------------------------------------
// PPS (Protocol and Parameters Selection)
// ---------------------------------------------------------------------------

/// PPS (Protocol and Parameters Selection) per ISO 7816-3 clause 9.
///
/// After ATR reception, the terminal may send a PPS request to negotiate
/// alternative protocol parameters.  The card responds with a PPS response
/// confirming or rejecting the negotiation.
///
/// # Example
///
/// ```
/// use simrs_t0::Pps;
///
/// // PPS request: select T=0 with Fi/Di from TA1=0x94 (Fi=512, Di=8).
/// let req = Pps::new_request(0, Some(0x94), None);
/// let bytes = req.to_bytes();
/// assert_eq!(bytes[0], 0xFF); // PPSS
///
/// // Parse the bytes back.
/// let parsed = Pps::parse(&bytes).unwrap();
/// assert_eq!(parsed.protocol(), 0);
/// assert_eq!(parsed.pps1(), Some(0x94));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pps {
    /// Raw PPS bytes (max 6: PPSS + PPS0 + PPS1 + PPS2 + PPS3 + PCK).
    raw: [u8; 6],
    /// Length of valid bytes.
    len: u8,
    /// Protocol (T value from PPS0 low nibble).
    protocol: u8,
    /// PPS1 (Fi/Di selection), if present.
    pps1: Option<u8>,
    /// PPS2 (SPU usage), if present.
    pps2: Option<u8>,
}

impl Pps {
    /// Create a new PPS request.
    ///
    /// - `protocol`: protocol number (0 for T=0, 1 for T=1)
    /// - `pps1`: optional Fi/Di byte (same encoding as TA1)
    /// - `pps2`: optional SPU byte
    pub fn new_request(protocol: u8, pps1: Option<u8>, pps2: Option<u8>) -> Self {
        let mut raw = [0u8; 6];
        let mut pos: usize = 0;

        raw[pos] = 0xFF;
        pos += 1;

        let mut pps0 = protocol & 0x0F;
        if pps1.is_some() {
            pps0 |= 0x10;
        }
        if pps2.is_some() {
            pps0 |= 0x20;
        }
        raw[pos] = pps0;
        pos += 1;

        if let Some(p1) = pps1 {
            raw[pos] = p1;
            pos += 1;
        }
        if let Some(p2) = pps2 {
            raw[pos] = p2;
            pos += 1;
        }

        let mut pck: u8 = 0;
        for &b in &raw[..pos] {
            pck ^= b;
        }
        raw[pos] = pck;
        pos += 1;

        #[allow(clippy::cast_possible_truncation)]
        Self {
            raw,
            len: pos as u8,
            protocol: protocol & 0x0F,
            pps1,
            pps2,
        }
    }

    /// Parse a PPS request or response from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`T0Error::PpsMalformed`] if too short or PPSS is not `0xFF`,
    /// or [`T0Error::PpsBadPck`] if the check byte does not match.
    pub fn parse(bytes: &[u8]) -> Result<Self, T0Error> {
        if bytes.len() < 3 {
            return Err(T0Error::PpsMalformed);
        }
        if bytes[0] != 0xFF {
            return Err(T0Error::PpsMalformed);
        }

        let pps0 = bytes[1];
        let protocol = pps0 & 0x0F;
        let has_pps1 = pps0 & 0x10 != 0;
        let has_pps2 = pps0 & 0x20 != 0;
        let has_pps3 = pps0 & 0x40 != 0;

        let expected_len =
            2 + usize::from(has_pps1) + usize::from(has_pps2) + usize::from(has_pps3) + 1;
        if bytes.len() < expected_len {
            return Err(T0Error::PpsMalformed);
        }

        let mut xor: u8 = 0;
        for &b in &bytes[..expected_len] {
            xor ^= b;
        }
        if xor != 0 {
            return Err(T0Error::PpsBadPck);
        }

        let mut pos: usize = 2;
        let pps1 = if has_pps1 {
            let v = bytes[pos];
            pos += 1;
            Some(v)
        } else {
            None
        };
        let pps2 = if has_pps2 {
            let v = bytes[pos];
            pos += 1;
            Some(v)
        } else {
            None
        };
        if has_pps3 {
            pos += 1;
        }
        let _ = pos;

        let mut raw = [0u8; 6];
        let copy_len = expected_len.min(6);
        raw[..copy_len].copy_from_slice(&bytes[..copy_len]);

        #[allow(clippy::cast_possible_truncation)]
        Ok(Self {
            raw,
            len: expected_len as u8,
            protocol,
            pps1,
            pps2,
        })
    }

    /// Negotiated protocol (0 = T=0, 1 = T=1).
    pub const fn protocol(&self) -> u8 {
        self.protocol
    }

    /// PPS1 byte (Fi/Di selection), if present.
    pub const fn pps1(&self) -> Option<u8> {
        self.pps1
    }

    /// PPS2 byte (SPU usage), if present.
    pub const fn pps2(&self) -> Option<u8> {
        self.pps2
    }

    /// Serialize the PPS to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.raw[..self.len as usize]
    }

    /// Fi value implied by PPS1, or 372 if PPS1 is absent.
    pub const fn fi(&self) -> u16 {
        match self.pps1 {
            Some(p1) => FI_TABLE[(p1 >> 4) as usize],
            None => 372,
        }
    }

    /// Di value implied by PPS1, or 1 if PPS1 is absent.
    pub const fn di(&self) -> u8 {
        match self.pps1 {
            Some(p1) => DI_TABLE[(p1 & 0x0F) as usize],
            None => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// T=0 Protocol State Machine
// ---------------------------------------------------------------------------

/// Maximum APDU data length for T=0 (short APDU: 256 bytes).
const T0_DATA_MAX: usize = 256;

/// T=0 protocol state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T0State {
    /// Idle, waiting for a command header.
    Idle,
    /// Receiving the 5-byte command header (CLA INS P1 P2 P3).
    ReceivingHeader,
    /// Header received, waiting for procedure byte from card.
    WaitProcedure,
    /// Transferring data bytes (terminal -> card, case 3/4).
    SendingData,
    /// Receiving data bytes (card -> terminal, case 2).
    ReceivingData,
    /// Command complete, SW1 SW2 available.
    Complete,
}

/// Action the host should take after feeding a byte to the T=0 state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T0Action {
    /// No action needed, continue feeding bytes.
    Continue,
    /// The complete 5-byte header is available. The host should forward it
    /// to the card and await a procedure byte.
    HeaderReady,
    /// A procedure byte was received. If it's the INS echo, the terminal
    /// should send all remaining data bytes.  If it's ~INS, send one byte.
    /// If it's NULL (`0x60`), wait for the next procedure byte.
    ProcedureByte {
        /// The procedure byte value.
        byte: u8,
    },
    /// The command is complete. SW1 SW2 are available via [`T0Protocol::sw`].
    Done,
    /// Invalid procedure byte received (not NULL, INS, ~INS, or SW1).
    ///
    /// Per ISO 7816-3 clause 10.3.3, procedure bytes must be one of: `0x60`
    /// (NULL), INS echo, complement of INS, or a status byte (`0x6X`/`0x9X`).
    /// The state machine resets to [`T0State::Idle`] on this error.
    ProtocolError,
}

/// Data direction for the T=0 command in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T0Direction {
    /// No data transfer (case 1, or Le-only case 2 where card sends data).
    CardToTerminal,
    /// Terminal sends data to card (case 3/4).
    TerminalToCard,
}

/// ISO 7816-3 T=0 character-level protocol state machine.
///
/// Converts between byte-at-a-time I/O and complete APDU exchanges.
///
/// # Data flow
///
/// 1. Terminal sends 5-byte header via [`feed_terminal_byte`](Self::feed_terminal_byte).
/// 2. State machine returns [`T0Action::HeaderReady`].
/// 3. Caller sets data direction via [`set_direction`](Self::set_direction):
///    - [`T0Direction::TerminalToCard`] for case 3/4 (P3 = Lc).
///    - [`T0Direction::CardToTerminal`] for case 2 (P3 = Le).
/// 4. Card sends procedure byte via [`feed_card_byte`](Self::feed_card_byte).
/// 5. State machine returns [`T0Action::ProcedureByte`] indicating what
///    to do next:
///    - INS echo: transfer all remaining data bytes.
///    - ~INS complement: transfer exactly one data byte.
///    - `0x60` NULL: wait, card is still processing.
///    - `0x6x`/`0x9x`: early termination with status word.
/// 6. Data transfer completes, card sends SW1 SW2.
/// 7. State machine returns [`T0Action::Done`].
pub struct T0Protocol {
    state: T0State,
    /// Active Fi value.
    fi: u16,
    /// Active Di value.
    di: u8,
    /// Bit-ordering convention.
    convention: Convention,
    /// Command header (CLA INS P1 P2 P3).
    header: [u8; 5],
    /// Bytes received into header so far.
    header_pos: u8,
    /// Data buffer (for outgoing or incoming data).
    data: [u8; T0_DATA_MAX],
    /// Number of valid bytes in data buffer.
    data_len: usize,
    /// Current position in data buffer.
    data_pos: usize,
    /// Expected data length (P3 byte).
    p3: u8,
    /// Status word (valid when state == Complete).
    sw: [u8; 2],
    /// Whether we got SW1 and are waiting for SW2.
    have_sw1: bool,
    /// Data direction for current command.
    direction: T0Direction,
    /// When true, transfer exactly one byte then return to `WaitProcedure`
    /// (complement-INS procedure byte per ISO 7816-3 clause 10.3.3).
    single_byte: bool,
}

impl Default for T0Protocol {
    fn default() -> Self {
        Self::new()
    }
}

impl T0Protocol {
    /// Create a new T=0 protocol handler with default parameters.
    pub const fn new() -> Self {
        Self {
            state: T0State::Idle,
            fi: 372,
            di: 1,
            convention: Convention::Direct,
            header: [0; 5],
            header_pos: 0,
            data: [0; T0_DATA_MAX],
            data_len: 0,
            data_pos: 0,
            p3: 0,
            sw: [0; 2],
            have_sw1: false,
            direction: T0Direction::CardToTerminal,
            single_byte: false,
        }
    }

    /// Create from ATR parameters.
    pub const fn from_atr(atr: &Atr) -> Self {
        Self {
            state: T0State::Idle,
            fi: atr.fi,
            di: atr.di,
            convention: atr.convention,
            header: [0; 5],
            header_pos: 0,
            data: [0; T0_DATA_MAX],
            data_len: 0,
            data_pos: 0,
            p3: 0,
            sw: [0; 2],
            have_sw1: false,
            direction: T0Direction::CardToTerminal,
            single_byte: false,
        }
    }

    /// Update Fi/Di after a successful PPS exchange.
    pub const fn apply_pps(&mut self, pps: &Pps) {
        if let Some(p1) = pps.pps1() {
            self.fi = FI_TABLE[(p1 >> 4) as usize];
            self.di = DI_TABLE[(p1 & 0x0F) as usize];
        }
    }

    /// Current state.
    pub const fn state(&self) -> T0State {
        self.state
    }

    /// Active Fi value.
    pub const fn fi(&self) -> u16 {
        self.fi
    }

    /// Active Di value.
    pub const fn di(&self) -> u8 {
        self.di
    }

    /// Convention in use.
    pub const fn convention(&self) -> Convention {
        self.convention
    }

    /// Reset the state machine for a new command.
    pub const fn reset(&mut self) {
        self.state = T0State::Idle;
        self.header_pos = 0;
        self.data_len = 0;
        self.data_pos = 0;
        self.p3 = 0;
        self.sw = [0; 2];
        self.have_sw1 = false;
        self.direction = T0Direction::CardToTerminal;
        self.single_byte = false;
    }

    /// Set the data direction for the current command.
    ///
    /// Must be called after [`T0Action::HeaderReady`] and before the
    /// procedure byte exchange.  The caller determines the direction
    /// from the INS byte semantics:
    /// - [`T0Direction::TerminalToCard`] when P3 is Lc (case 3/4).
    /// - [`T0Direction::CardToTerminal`] when P3 is Le (case 2) or
    ///   the command has no data (case 1).
    pub const fn set_direction(&mut self, dir: T0Direction) {
        self.direction = dir;
    }

    /// Feed a byte from the terminal (command direction).
    ///
    /// Returns the action the host should take.
    pub const fn feed_terminal_byte(&mut self, byte: u8) -> T0Action {
        let decoded = self.convention.decode(byte);

        match self.state {
            T0State::Idle | T0State::ReceivingHeader => {
                self.state = T0State::ReceivingHeader;
                self.header[self.header_pos as usize] = decoded;
                self.header_pos += 1;

                if self.header_pos >= 5 {
                    self.p3 = self.header[4];
                    self.data_pos = 0;
                    self.data_len = 0;
                    self.state = T0State::WaitProcedure;
                    T0Action::HeaderReady
                } else {
                    T0Action::Continue
                }
            }
            T0State::SendingData => {
                if self.data_pos < self.p3 as usize && self.data_pos < T0_DATA_MAX {
                    self.data[self.data_pos] = decoded;
                    self.data_pos += 1;
                    self.data_len = self.data_pos;
                }

                if self.data_pos >= self.p3 as usize || self.single_byte {
                    // Return to WaitProcedure: either all data sent, or
                    // complement-INS single-byte transfer complete.
                    self.state = T0State::WaitProcedure;
                    self.single_byte = false;
                }
                T0Action::Continue
            }
            _ => T0Action::Continue,
        }
    }

    /// Feed a byte from the card (response direction).
    ///
    /// Returns the action the host should take.
    pub const fn feed_card_byte(&mut self, byte: u8) -> T0Action {
        let decoded = self.convention.decode(byte);

        match self.state {
            T0State::WaitProcedure => {
                if self.have_sw1 {
                    self.sw[1] = decoded;
                    self.have_sw1 = false;
                    self.state = T0State::Complete;
                    return T0Action::Done;
                }

                let ins = self.header[1];

                if decoded == 0x60 {
                    return T0Action::ProcedureByte { byte: 0x60 };
                }

                if (decoded & 0xF0 == 0x60) || (decoded & 0xF0 == 0x90) {
                    self.sw[0] = decoded;
                    self.have_sw1 = true;
                    return T0Action::Continue;
                }

                if decoded == ins || decoded == !ins {
                    // INS echo = transfer all remaining bytes.
                    // ~INS (complement) = transfer exactly one byte, then
                    // return to WaitProcedure (ISO 7816-3 clause 10.3.3).
                    self.single_byte = decoded == !ins;
                    match self.direction {
                        T0Direction::TerminalToCard => {
                            self.state = T0State::SendingData;
                        }
                        T0Direction::CardToTerminal => {
                            self.state = T0State::ReceivingData;
                            self.data_pos = 0;
                            self.data_len = 0;
                        }
                    }
                    return T0Action::ProcedureByte { byte: decoded };
                }

                // Any byte that is not NULL (0x60), INS, ~INS, or a
                // status byte (0x6X/0x9X) is a protocol violation per
                // ISO 7816-3 clause 10.3.3.
                self.state = T0State::Idle;
                T0Action::ProtocolError
            }
            T0State::ReceivingData => {
                if self.data_pos < T0_DATA_MAX {
                    self.data[self.data_pos] = decoded;
                    self.data_pos += 1;
                    self.data_len = self.data_pos;
                }

                if self.data_pos >= self.p3 as usize || self.single_byte {
                    // Return to WaitProcedure: either all data received, or
                    // complement-INS single-byte transfer complete.
                    self.state = T0State::WaitProcedure;
                    self.single_byte = false;
                }
                T0Action::Continue
            }
            _ => T0Action::Continue,
        }
    }

    /// The 5-byte command header (CLA INS P1 P2 P3).
    ///
    /// Valid after [`T0Action::HeaderReady`] is returned.
    pub const fn header(&self) -> &[u8; 5] {
        &self.header
    }

    /// INS byte from the command header.
    pub const fn ins(&self) -> u8 {
        self.header[1]
    }

    /// P3 byte (data length / Le).
    pub const fn p3(&self) -> u8 {
        self.p3
    }

    /// The data buffer contents.
    ///
    /// For case 3/4 commands, this contains data sent by the terminal.
    /// For case 2 commands, this contains data received from the card.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Status word (SW1 SW2), valid when state is [`T0State::Complete`].
    pub const fn sw(&self) -> [u8; 2] {
        self.sw
    }

    /// Assemble the complete APDU command from header + data.
    ///
    /// For case 1 commands (P3=0, no data), returns just the 4-byte header.
    /// For case 3/4 commands, returns CLA INS P1 P2 Lc data.
    ///
    /// Writes into `buf` and returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`T0Error::BufferOverflow`] if the buffer is too small.
    pub fn assemble_command(&self, buf: &mut [u8]) -> Result<usize, T0Error> {
        if self.data_len > 0 {
            let total = 5 + self.data_len;
            if buf.len() < total {
                return Err(T0Error::BufferOverflow);
            }
            buf[..5].copy_from_slice(&self.header);
            buf[5..total].copy_from_slice(&self.data[..self.data_len]);
            Ok(total)
        } else if self.p3 == 0 {
            if buf.len() < 4 {
                return Err(T0Error::BufferOverflow);
            }
            buf[..4].copy_from_slice(&self.header[..4]);
            Ok(4)
        } else {
            if buf.len() < 5 {
                return Err(T0Error::BufferOverflow);
            }
            buf[..5].copy_from_slice(&self.header);
            Ok(5)
        }
    }

    /// Deliver a complete APDU response (data + SW1 SW2) and split it into
    /// the byte sequence the card would send on the I/O line.
    ///
    /// Returns the T=0 response frame: procedure byte (INS) + data + SW1 SW2.
    ///
    /// Writes into `buf` and returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`T0Error::BufferOverflow`] if the buffer is too small.
    pub fn frame_response(
        &self,
        resp_data: &[u8],
        sw: [u8; 2],
        buf: &mut [u8],
    ) -> Result<usize, T0Error> {
        let total = 1 + resp_data.len() + 2;
        if buf.len() < total {
            return Err(T0Error::BufferOverflow);
        }

        let ins = self.header[1];
        buf[0] = self.convention.encode(ins);
        for (i, &b) in resp_data.iter().enumerate() {
            buf[1 + i] = self.convention.encode(b);
        }
        buf[1 + resp_data.len()] = self.convention.encode(sw[0]);
        buf[2 + resp_data.len()] = self.convention.encode(sw[1]);

        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // -- Convention tests --

    #[test]
    fn direct_convention_is_identity() {
        for b in 0..=255u8 {
            assert_eq!(Convention::Direct.decode(b), b);
            assert_eq!(Convention::Direct.encode(b), b);
        }
    }

    #[test]
    fn inverse_convention_roundtrip() {
        for b in 0..=255u8 {
            let encoded = Convention::Inverse.encode(b);
            let decoded = Convention::Inverse.decode(encoded);
            assert_eq!(decoded, b, "roundtrip failed for {b:#04x}");
        }
    }

    #[test]
    fn inverse_convention_known_values() {
        assert_eq!(Convention::Inverse.decode(0xFF), 0x00);
        assert_eq!(Convention::Inverse.decode(0x00), 0xFF);
    }

    // -- ATR parsing tests --

    #[test]
    fn parse_minimal_atr() {
        let atr = Atr::parse(&[0x3B, 0x00]).unwrap();
        assert_eq!(atr.convention(), Convention::Direct);
        assert_eq!(atr.fi(), 372);
        assert_eq!(atr.di(), 1);
        assert_eq!(atr.historical_bytes(), &[]);
        assert!(atr.t0_supported());
    }

    #[test]
    fn parse_atr_with_historical_bytes() {
        let atr = Atr::parse(&[0x3B, 0x03, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(atr.historical_bytes(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn parse_atr_with_ta1() {
        let atr = Atr::parse(&[0x3B, 0x10, 0x94]).unwrap();
        assert_eq!(atr.fi(), 512);
        assert_eq!(atr.di(), 8);
    }

    #[test]
    fn parse_atr_with_ta1_and_tc1() {
        let atr = Atr::parse(&[0x3B, 0x50, 0x11, 0x05]).unwrap();
        assert_eq!(atr.fi(), 372);
        assert_eq!(atr.di(), 1);
        assert_eq!(atr.guard_time_n(), 5);
    }

    #[test]
    fn parse_atr_inverse_convention() {
        let atr = Atr::parse(&[0x3F, 0x00]).unwrap();
        assert_eq!(atr.convention(), Convention::Inverse);
    }

    #[test]
    fn parse_atr_too_short() {
        assert_eq!(Atr::parse(&[0x3B]), Err(T0Error::AtrTooShort));
        assert_eq!(Atr::parse(&[]), Err(T0Error::AtrTooShort));
    }

    #[test]
    fn parse_atr_bad_ts() {
        assert_eq!(Atr::parse(&[0x00, 0x00]), Err(T0Error::AtrBadTs));
    }

    #[test]
    fn parse_atr_truncated_interface_bytes() {
        assert_eq!(Atr::parse(&[0x3B, 0x10]), Err(T0Error::AtrTruncated));
    }

    #[test]
    fn parse_atr_truncated_historical() {
        assert_eq!(Atr::parse(&[0x3B, 0x02, 0xAA]), Err(T0Error::AtrTruncated));
    }

    #[test]
    fn parse_atr_with_tck() {
        // ATR with TD1 declaring T=1, requiring TCK.
        // TS=0x3B, T0=0x80 (TD1 present, 0 historical), TD1=0x01 (T=1).
        // TCK = T0 ^ TD1 = 0x80 ^ 0x01 = 0x81.
        let atr = Atr::parse(&[0x3B, 0x80, 0x01, 0x81]).unwrap();
        assert!(atr.t0_supported());
    }

    #[test]
    fn parse_atr_bad_tck() {
        assert_eq!(
            Atr::parse(&[0x3B, 0x80, 0x01, 0x00]),
            Err(T0Error::AtrBadTck)
        );
    }

    #[test]
    fn parse_atr_too_long() {
        let mut buf = [0u8; 34];
        buf[0] = 0x3B;
        buf[1] = 0x0F;
        assert_eq!(Atr::parse(&buf), Err(T0Error::AtrTooLong));
    }

    #[test]
    fn atr_timing_calculations() {
        let atr = Atr::parse(&[0x3B, 0x00]).unwrap();
        assert_eq!(atr.etu_clocks(), 372);
        assert_eq!(atr.work_waiting_time_etu(), 9600);
        assert_eq!(atr.character_guard_time_etu(), 12);
    }

    #[test]
    fn atr_build_minimal() {
        let atr = Atr::build_minimal(&[0x48, 0x65]).unwrap();
        assert_eq!(atr.as_bytes(), &[0x3B, 0x02, 0x48, 0x65]);
        assert_eq!(atr.historical_bytes(), &[0x48, 0x65]);
        assert_eq!(atr.fi(), 372);
        assert_eq!(atr.di(), 1);
    }

    #[test]
    fn atr_build_with_fi_di() {
        let atr = Atr::build_with_fi_di(9, 4, &[]).unwrap();
        assert_eq!(atr.as_bytes(), &[0x3B, 0x10, 0x94]);
        assert_eq!(atr.fi(), 512);
        assert_eq!(atr.di(), 8);
    }

    #[test]
    fn build_minimal_too_many_historical() {
        let hist = [0u8; 16];
        assert_eq!(Atr::build_minimal(&hist), Err(T0Error::AtrTooLong));
    }

    // -- PPS tests --

    #[test]
    fn pps_roundtrip() {
        let pps = Pps::new_request(0, Some(0x94), None);
        let bytes = pps.to_bytes();
        let parsed = Pps::parse(bytes).unwrap();
        assert_eq!(parsed.protocol(), 0);
        assert_eq!(parsed.pps1(), Some(0x94));
        assert_eq!(parsed.pps2(), None);
    }

    #[test]
    fn pps_minimal() {
        let pps = Pps::new_request(0, None, None);
        let bytes = pps.to_bytes();
        assert_eq!(bytes.len(), 3);
        assert_eq!(bytes[0], 0xFF);
    }

    #[test]
    fn pps_fi_di_extraction() {
        let pps = Pps::new_request(0, Some(0x94), None);
        assert_eq!(pps.fi(), 512);
        assert_eq!(pps.di(), 8);
    }

    #[test]
    fn pps_parse_bad_ppss() {
        assert_eq!(Pps::parse(&[0x00, 0x00, 0x00]), Err(T0Error::PpsMalformed));
    }

    #[test]
    fn pps_parse_bad_pck() {
        assert_eq!(Pps::parse(&[0xFF, 0x00, 0x00]), Err(T0Error::PpsBadPck));
    }

    #[test]
    fn pps_parse_too_short() {
        assert_eq!(Pps::parse(&[0xFF, 0x00]), Err(T0Error::PpsMalformed));
    }

    // -- T=0 protocol tests --

    #[test]
    fn t0_header_assembly() {
        let mut proto = T0Protocol::new();
        let header = [0x00, 0xA4, 0x00, 0x04, 0x02];

        for (i, &b) in header.iter().enumerate() {
            let action = proto.feed_terminal_byte(b);
            if i < 4 {
                assert_eq!(action, T0Action::Continue);
            } else {
                assert_eq!(action, T0Action::HeaderReady);
            }
        }

        assert_eq!(proto.header(), &header);
        assert_eq!(proto.state(), T0State::WaitProcedure);
    }

    #[test]
    fn t0_case1_sw_only() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xC0, 0x00, 0x00, 0x00] {
            proto.feed_terminal_byte(b);
        }

        let action = proto.feed_card_byte(0x90);
        assert_eq!(action, T0Action::Continue);
        let action = proto.feed_card_byte(0x00);
        assert_eq!(action, T0Action::Done);
        assert_eq!(proto.sw(), [0x90, 0x00]);
    }

    #[test]
    fn t0_case2_card_sends_data() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xC0, 0x00, 0x00, 0x02] {
            proto.feed_terminal_byte(b);
        }

        let action = proto.feed_card_byte(0xC0);
        assert_eq!(action, T0Action::ProcedureByte { byte: 0xC0 });
        assert_eq!(proto.state(), T0State::ReceivingData);

        proto.feed_card_byte(0xAA);
        proto.feed_card_byte(0xBB);

        assert_eq!(proto.state(), T0State::WaitProcedure);
        proto.feed_card_byte(0x90);
        let action = proto.feed_card_byte(0x00);
        assert_eq!(action, T0Action::Done);
        assert_eq!(proto.data(), &[0xAA, 0xBB]);
        assert_eq!(proto.sw(), [0x90, 0x00]);
    }

    #[test]
    fn t0_case3_terminal_sends_data() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xA4, 0x00, 0x04, 0x02] {
            proto.feed_terminal_byte(b);
        }
        proto.set_direction(T0Direction::TerminalToCard);

        let action = proto.feed_card_byte(0xA4);
        assert_eq!(action, T0Action::ProcedureByte { byte: 0xA4 });
        assert_eq!(proto.state(), T0State::SendingData);

        proto.feed_terminal_byte(0x3F);
        proto.feed_terminal_byte(0x00);

        assert_eq!(proto.state(), T0State::WaitProcedure);
        assert_eq!(proto.data(), &[0x3F, 0x00]);

        proto.feed_card_byte(0x90);
        let action = proto.feed_card_byte(0x00);
        assert_eq!(action, T0Action::Done);
    }

    #[test]
    fn t0_null_procedure_byte() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xC0, 0x00, 0x00, 0x02] {
            proto.feed_terminal_byte(b);
        }

        let action = proto.feed_card_byte(0x60);
        assert_eq!(action, T0Action::ProcedureByte { byte: 0x60 });
        assert_eq!(proto.state(), T0State::WaitProcedure);

        let action = proto.feed_card_byte(0xC0);
        assert_eq!(action, T0Action::ProcedureByte { byte: 0xC0 });
    }

    #[test]
    fn t0_early_sw() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xA4, 0x00, 0x04, 0x02] {
            proto.feed_terminal_byte(b);
        }
        proto.set_direction(T0Direction::TerminalToCard);

        proto.feed_card_byte(0x6A);
        let action = proto.feed_card_byte(0x82);
        assert_eq!(action, T0Action::Done);
        assert_eq!(proto.sw(), [0x6A, 0x82]);
    }

    #[test]
    fn t0_assemble_command_case3() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xA4, 0x00, 0x04, 0x02] {
            proto.feed_terminal_byte(b);
        }
        proto.set_direction(T0Direction::TerminalToCard);

        proto.feed_card_byte(0xA4);

        proto.feed_terminal_byte(0x3F);
        proto.feed_terminal_byte(0x00);

        let mut buf = [0u8; 16];
        let len = proto.assemble_command(&mut buf).unwrap();
        assert_eq!(&buf[..len], &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    }

    #[test]
    fn t0_frame_response() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xC0, 0x00, 0x00, 0x02] {
            proto.feed_terminal_byte(b);
        }

        let mut buf = [0u8; 16];
        let len = proto
            .frame_response(&[0xAA, 0xBB], [0x90, 0x00], &mut buf)
            .unwrap();
        assert_eq!(&buf[..len], &[0xC0, 0xAA, 0xBB, 0x90, 0x00]);
    }

    #[test]
    fn t0_reset_clears_state() {
        let mut proto = T0Protocol::new();

        for &b in &[0x00, 0xA4, 0x00, 0x04, 0x02] {
            proto.feed_terminal_byte(b);
        }
        assert_eq!(proto.state(), T0State::WaitProcedure);

        proto.reset();
        assert_eq!(proto.state(), T0State::Idle);
        assert_eq!(proto.data(), &[]);
    }

    #[test]
    fn t0_from_atr_inherits_params() {
        let atr = Atr::parse(&[0x3B, 0x10, 0x94]).unwrap();
        let proto = T0Protocol::from_atr(&atr);
        assert_eq!(proto.fi(), 512);
        assert_eq!(proto.di(), 8);
    }

    #[test]
    fn t0_apply_pps() {
        let mut proto = T0Protocol::new();
        assert_eq!(proto.fi(), 372);

        let pps = Pps::new_request(0, Some(0x94), None);
        proto.apply_pps(&pps);
        assert_eq!(proto.fi(), 512);
        assert_eq!(proto.di(), 8);
    }

    #[test]
    fn assemble_command_buffer_too_small() {
        let mut proto = T0Protocol::new();
        for &b in &[0x00, 0xA4, 0x00, 0x04, 0x00] {
            proto.feed_terminal_byte(b);
        }
        let mut buf = [0u8; 2];
        assert_eq!(
            proto.assemble_command(&mut buf),
            Err(T0Error::BufferOverflow)
        );
    }

    #[test]
    fn frame_response_buffer_too_small() {
        let mut proto = T0Protocol::new();
        for &b in &[0x00, 0xC0, 0x00, 0x00, 0x02] {
            proto.feed_terminal_byte(b);
        }
        let mut buf = [0u8; 2];
        assert_eq!(
            proto.frame_response(&[0xAA, 0xBB], [0x90, 0x00], &mut buf),
            Err(T0Error::BufferOverflow)
        );
    }

    #[test]
    fn error_display_non_empty() {
        let errors = [
            T0Error::AtrTooShort,
            T0Error::AtrBadTs,
            T0Error::AtrTruncated,
            T0Error::AtrBadTck,
            T0Error::AtrTooLong,
            T0Error::PpsMalformed,
            T0Error::PpsBadPck,
            T0Error::HeaderIncomplete,
            T0Error::InvalidState,
            T0Error::BufferOverflow,
        ];
        for e in &errors {
            let s = format!("{e}");
            assert!(!s.is_empty(), "Display for {e:?} is empty");
        }
    }

    // -- Real-world ATR --

    #[test]
    fn parse_real_world_sim_atr() {
        // ATR structure: TS=3B, T0=9F (TA1+TD1, K=15), TA1=96,
        // TD1=80 (TD2, T=0), TD2=1F (TA3, T=15), TA3=C7,
        // 15 historical bytes, TCK=F4.
        let atr_bytes: [u8; 22] = [
            0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x13, 0x67,
            0x4D, 0x45, 0x20, 0x4F, 0x53, 0x20, 0x38, 0xF4,
        ];
        let atr = Atr::parse(&atr_bytes).unwrap();
        assert_eq!(atr.convention(), Convention::Direct);
        assert_eq!(atr.historical_bytes().len(), 15);
        assert_eq!(atr.fi(), 512);
        assert_eq!(atr.di(), 32);
    }

    // -- Proptests --

    mod proptests {
        use super::*;
        use alloc::vec::Vec;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn inverse_convention_is_self_inverse(b in 0u8..=255) {
                let enc = Convention::Inverse.encode(b);
                let dec = Convention::Inverse.decode(enc);
                prop_assert_eq!(dec, b);
            }

            #[test]
            fn pps_roundtrip(protocol in 0u8..2, p1 in proptest::option::of(any::<u8>())) {
                let pps = Pps::new_request(protocol, p1, None);
                let bytes = pps.to_bytes();
                let parsed = Pps::parse(bytes).unwrap();
                prop_assert_eq!(parsed.protocol(), protocol);
                prop_assert_eq!(parsed.pps1(), p1);
            }

            #[test]
            fn atr_build_minimal_roundtrip(hist_len in 0usize..=15) {
                let hist: Vec<u8> = (0..hist_len).map(|i| i as u8).collect();
                let atr = Atr::build_minimal(&hist).unwrap();
                let parsed = Atr::parse(atr.as_bytes()).unwrap();
                prop_assert_eq!(parsed.historical_bytes(), hist.as_slice());
                prop_assert_eq!(parsed.fi(), 372);
                prop_assert_eq!(parsed.di(), 1);
            }

            #[test]
            fn t0_header_always_captured(
                cla in any::<u8>(),
                ins in any::<u8>(),
                p1 in any::<u8>(),
                p2 in any::<u8>(),
                p3 in any::<u8>(),
            ) {
                let mut proto = T0Protocol::new();
                proto.feed_terminal_byte(cla);
                proto.feed_terminal_byte(ins);
                proto.feed_terminal_byte(p1);
                proto.feed_terminal_byte(p2);
                let action = proto.feed_terminal_byte(p3);
                prop_assert_eq!(action, T0Action::HeaderReady);
                prop_assert_eq!(proto.header(), &[cla, ins, p1, p2, p3]);
            }
        }
    }
}
