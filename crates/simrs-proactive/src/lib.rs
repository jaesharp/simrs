//! Proactive UICC command encoding and state machine.
//!
//! Encodes proactive commands as BER-TLV envelopes (outer tag `0xD0`) for
//! retrieval via FETCH. Manages the pending command buffer and the
//! `91 XX` status word override mechanism.
//!
//! Supported commands (P0 -- matching swsim):
//! - DISPLAY TEXT (type `0x21`)
//! - SET UP MENU (type `0x25`)
//! - LAUNCH BROWSER (type `0x15`)
//! - PLAY TONE (type `0x20`)
//! - SEND SHORT MESSAGE (type `0x13`)
//!
//! # Architecture
//!
//! This crate is a pure **encoding + state** library. It does NOT handle
//! APDUs directly. The APDU-level FETCH / TERMINAL RESPONSE / ENVELOPE
//! handlers live in `simrs-usim`.
//!
//! # Encoding Structure
//!
//! Every proactive command is a BER-TLV with outer tag `0xD0`:
//!
//! ```text
//! D0 [len]
//!   81 03 [cmd_number] [cmd_type] [cmd_qualifier]   -- Command Details
//!   82 02 [source] [destination]                     -- Device Identities
//!   ... command-specific TLVs ...
//! ```
//!
//! # Standards
//! - ETSI TS 102 223 V17.2.0 -- Card Application Toolkit (CAT)
//! - 3GPP TS 31.111 V17.0.0 -- USIM Application Toolkit (USAT)
//!
//! # `no_std`
//! This crate is `no_std`. All buffers are caller-supplied.
//!
//! # Example
//!
//! ```
//! use simrs_proactive::{ProactiveState, ProactiveCommand, TextCoding};
//!
//! let mut state = ProactiveState::new();
//!
//! let cmd = ProactiveCommand::DisplayText {
//!     text: b"Hello from SIM",
//!     coding: TextCoding::Gsm8Bit,
//!     high_priority: false,
//! };
//! state.queue_command(&cmd).unwrap();
//!
//! // After processing any APDU that would return 90 00:
//! let (sw1, sw2) = state.override_status(0x90, 0x00);
//! assert_eq!(sw1, 0x91);
//! assert!(sw2 > 0);
//!
//! // Terminal issues FETCH to retrieve the command:
//! let mut buf = [0u8; 256];
//! let len = state.fetch(&mut buf);
//! assert_eq!(buf[0], 0xD0); // proactive command tag
//! assert!(!state.has_pending());
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

use simrs_bertlv::Encoder;

// ---------------------------------------------------------------------------
// Constants per ETSI TS 102 223
// ---------------------------------------------------------------------------

/// BER-TLV tag for proactive command envelope.
const TAG_PROACTIVE_CMD: u8 = 0xD0;
/// Command Details (ETSI TS 102 223 clause 8.6).
const TAG_CMD_DETAILS: u8 = 0x81;
/// Device Identities (ETSI TS 102 223 clause 8.7).
const TAG_DEVICE_ID: u8 = 0x82;
/// Alpha Identifier (ETSI TS 102 223 clause 8.2).
const TAG_ALPHA_ID: u8 = 0x85;
/// Duration (ETSI TS 102 223 clause 8.8).
const TAG_DURATION: u8 = 0x84;
/// Text String (ETSI TS 102 223 clause 8.15).
const TAG_TEXT_STRING: u8 = 0x8D;
/// Tone (ETSI TS 102 223 clause 8.16).
const TAG_TONE: u8 = 0x8E;
/// Item (ETSI TS 102 223 clause 8.9).
const TAG_ITEM: u8 = 0x8F;
/// SMS TPDU (ETSI TS 102 223 clause 8.13).
const TAG_SMS_TPDU: u8 = 0x8B;
/// Browser Identity (ETSI TS 102 223 clause 8.61).
const TAG_BROWSER_ID: u8 = 0xB0;
/// URL (ETSI TS 102 223 clause 8.48).
const TAG_URL: u8 = 0xB1;

// -- Command type values (ETSI TS 102 223 clause 9.4) --

/// SEND SHORT MESSAGE (type `0x13`).
const CMD_TYPE_SEND_SMS: u8 = 0x13;
/// LAUNCH BROWSER (type `0x15`).
const CMD_TYPE_LAUNCH_BROWSER: u8 = 0x15;
/// PLAY TONE (type `0x20`).
const CMD_TYPE_PLAY_TONE: u8 = 0x20;
/// DISPLAY TEXT (type `0x21`).
const CMD_TYPE_DISPLAY_TEXT: u8 = 0x21;
/// SET UP MENU (type `0x25`).
const CMD_TYPE_SET_UP_MENU: u8 = 0x25;

// -- Device identity values (ETSI TS 102 223 clause 8.7) --

/// Keypad device identity.
pub const DEV_KEYPAD: u8 = 0x01;
/// Display device identity.
pub const DEV_DISPLAY: u8 = 0x02;
/// Earpiece device identity.
pub const DEV_EARPIECE: u8 = 0x03;
/// UICC device identity.
pub const DEV_UICC: u8 = 0x81;
/// Terminal device identity.
pub const DEV_TERMINAL: u8 = 0x82;
/// Network device identity.
pub const DEV_NETWORK: u8 = 0x83;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Text encoding scheme for text strings.
///
/// Per ETSI TS 102 223 clause 8.15, the first byte of a text string
/// TLV value is the Data Coding Scheme (DCS).
///
/// # Example
///
/// ```
/// use simrs_proactive::TextCoding;
/// assert_eq!(TextCoding::Gsm8Bit.dcs_byte(), 0x04);
/// assert_eq!(TextCoding::Ucs2.dcs_byte(), 0x08);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextCoding {
    /// GSM 7-bit default alphabet, packed.
    Gsm7Bit,
    /// GSM 8-bit data.
    Gsm8Bit,
    /// UCS-2 (16-bit Unicode).
    Ucs2,
}

impl TextCoding {
    /// Data Coding Scheme byte per 3GPP TS 23.038.
    pub const fn dcs_byte(self) -> u8 {
        match self {
            Self::Gsm7Bit => 0x00,
            Self::Gsm8Bit => 0x04,
            Self::Ucs2 => 0x08,
        }
    }
}

/// A menu item for SET UP MENU.
///
/// # Example
///
/// ```
/// use simrs_proactive::MenuItem;
/// let item = MenuItem { id: 1, text: b"Option A" };
/// assert_eq!(item.id, 1);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct MenuItem<'a> {
    /// Item identifier (1--255, unique within the menu).
    pub id: u8,
    /// Item text (unencoded bytes, GSM 8-bit assumed).
    pub text: &'a [u8],
}

/// Duration time unit per ETSI TS 102 223 clause 8.8.
///
/// # Example
///
/// ```
/// use simrs_proactive::TimeUnit;
/// assert_eq!(TimeUnit::Tenths.to_byte(), 0x02);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeUnit {
    /// Minutes.
    Minutes,
    /// Seconds.
    Seconds,
    /// Tenths of a second.
    Tenths,
}

impl TimeUnit {
    /// Encode as the time unit byte.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Minutes => 0x00,
            Self::Seconds => 0x01,
            Self::Tenths => 0x02,
        }
    }
}

/// A proactive command to be encoded and delivered via FETCH.
///
/// Each variant corresponds to one command type from ETSI TS 102 223.
///
/// # Example
///
/// ```
/// use simrs_proactive::{ProactiveCommand, TextCoding};
/// let cmd = ProactiveCommand::DisplayText {
///     text: b"Hello",
///     coding: TextCoding::Gsm8Bit,
///     high_priority: false,
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub enum ProactiveCommand<'a> {
    /// DISPLAY TEXT (type `0x21`): show text on the terminal display.
    ///
    /// Per ETSI TS 102 223 clause 6.4.1.
    DisplayText {
        /// Text content.
        text: &'a [u8],
        /// Text encoding.
        coding: TextCoding,
        /// If true, high priority (displayed immediately).
        high_priority: bool,
    },

    /// SET UP MENU (type `0x25`): install a persistent menu.
    ///
    /// Per ETSI TS 102 223 clause 6.6.7.
    SetUpMenu {
        /// Menu title (alpha identifier).
        title: &'a [u8],
        /// Menu items (1--255).
        items: &'a [MenuItem<'a>],
    },

    /// LAUNCH BROWSER (type `0x15`): open a URL.
    ///
    /// Per ETSI TS 102 223 clause 6.4.26.
    LaunchBrowser {
        /// URL to open.
        url: &'a [u8],
        /// Browser identity (0x00 = default).
        browser_id: u8,
    },

    /// PLAY TONE (type `0x20`): audio feedback.
    ///
    /// Per ETSI TS 102 223 clause 6.4.5.
    PlayTone {
        /// Tone type (per ETSI TS 102 223 clause 8.16).
        tone: u8,
        /// Duration time unit.
        unit: TimeUnit,
        /// Duration value (1--255).
        interval: u8,
    },

    /// SEND SHORT MESSAGE (type `0x13`): send an SMS.
    ///
    /// Per ETSI TS 102 223 clause 6.4.10.
    SendSms {
        /// Raw SMS TPDU.
        tpdu: &'a [u8],
    },
}

/// Proactive encoding error.
///
/// # Example
///
/// ```
/// use simrs_proactive::ProactiveError;
/// let e = ProactiveError::BufferTooSmall;
/// assert_eq!(e, ProactiveError::BufferTooSmall);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProactiveError {
    /// Output buffer is too small to hold the encoded command.
    BufferTooSmall,
}

impl core::fmt::Display for ProactiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("buffer too small"),
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Compute the encoded length of a proactive command without writing.
///
/// Uses `simrs-bertlv` dry-run mode.
///
/// # Example
///
/// ```
/// use simrs_proactive::{encoded_len, ProactiveCommand, TextCoding};
/// let cmd = ProactiveCommand::DisplayText {
///     text: b"Hi",
///     coding: TextCoding::Gsm8Bit,
///     high_priority: false,
/// };
/// let len = encoded_len(&cmd, 1);
/// assert!(len > 0);
/// ```
pub fn encoded_len(cmd: &ProactiveCommand<'_>, cmd_number: u8) -> usize {
    let mut enc = Encoder::dry_run();
    // Errors impossible in dry-run mode (no buffer to overflow).
    let _ = encode_inner(&mut enc, cmd, cmd_number);
    enc.len()
}

/// Encode a proactive command into a caller-supplied buffer.
///
/// Returns the number of bytes written.
///
/// # Errors
///
/// Returns [`ProactiveError::BufferTooSmall`] if `buf` is too small.
///
/// # Example
///
/// ```
/// use simrs_proactive::{encode, ProactiveCommand, TextCoding};
/// let cmd = ProactiveCommand::DisplayText {
///     text: b"Hi",
///     coding: TextCoding::Gsm8Bit,
///     high_priority: false,
/// };
/// let mut buf = [0u8; 64];
/// let len = encode(&cmd, 1, &mut buf).unwrap();
/// assert_eq!(buf[0], 0xD0);
/// ```
pub fn encode(
    cmd: &ProactiveCommand<'_>,
    cmd_number: u8,
    buf: &mut [u8],
) -> Result<usize, ProactiveError> {
    let mut enc = Encoder::new(buf);
    encode_inner(&mut enc, cmd, cmd_number)?;
    Ok(enc.len())
}

/// Internal: encode a proactive command using the given encoder.
fn encode_inner(
    enc: &mut Encoder<'_>,
    cmd: &ProactiveCommand<'_>,
    cmd_number: u8,
) -> Result<(), ProactiveError> {
    // First, compute the inner content length via dry-run.
    let inner_len = {
        let mut dry = Encoder::dry_run();
        encode_common(&mut dry, cmd, cmd_number)?;
        encode_payload(&mut dry, cmd)?;
        dry.len()
    };

    // Outer envelope: D0 [inner_len] [inner...]
    enc.tag_length_value_split(TAG_PROACTIVE_CMD, inner_len, |enc_inner| {
        encode_common(enc_inner, cmd, cmd_number)?;
        encode_payload(enc_inner, cmd)
    })
    .map_err(|_| ProactiveError::BufferTooSmall)?;

    Ok(())
}

/// Encode the common header TLVs (command details + device identities).
fn encode_common(
    enc: &mut Encoder<'_>,
    cmd: &ProactiveCommand<'_>,
    cmd_number: u8,
) -> Result<(), ProactiveError> {
    let (cmd_type, cmd_qualifier, dest_device) = cmd.header_fields();

    // Command Details: 81 03 [number] [type] [qualifier]
    enc.tag_length_value(TAG_CMD_DETAILS, &[cmd_number, cmd_type, cmd_qualifier])
        .map_err(|_| ProactiveError::BufferTooSmall)?;

    // Device Identities: 82 02 [source=UICC] [destination]
    enc.tag_length_value(TAG_DEVICE_ID, &[DEV_UICC, dest_device])
        .map_err(|_| ProactiveError::BufferTooSmall)?;

    Ok(())
}

/// Encode command-specific payload TLVs.
fn encode_payload(
    enc: &mut Encoder<'_>,
    cmd: &ProactiveCommand<'_>,
) -> Result<(), ProactiveError> {
    match cmd {
        ProactiveCommand::DisplayText { text, coding, .. } => {
            // Text String: 8D [len] [DCS] [text...]
            let mut text_buf = [0u8; 256];
            let tlen = 1 + text.len();
            if tlen > text_buf.len() {
                return Err(ProactiveError::BufferTooSmall);
            }
            text_buf[0] = coding.dcs_byte();
            text_buf[1..=text.len()].copy_from_slice(text);
            enc.tag_length_value(TAG_TEXT_STRING, &text_buf[..tlen])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::SetUpMenu { title, items } => {
            // Alpha Identifier: 85 [len] [title...]
            enc.tag_length_value(TAG_ALPHA_ID, title)
                .map_err(|_| ProactiveError::BufferTooSmall)?;

            // Items: 8F [len] [id] [text...] (repeated)
            for item in *items {
                let mut item_buf = [0u8; 256];
                let ilen = 1 + item.text.len();
                if ilen > item_buf.len() {
                    return Err(ProactiveError::BufferTooSmall);
                }
                item_buf[0] = item.id;
                item_buf[1..=item.text.len()].copy_from_slice(item.text);
                enc.tag_length_value(TAG_ITEM, &item_buf[..ilen])
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
        }

        ProactiveCommand::LaunchBrowser { url, browser_id } => {
            // Browser Identity: B0 01 [id]
            enc.tag_length_value(TAG_BROWSER_ID, &[*browser_id])
                .map_err(|_| ProactiveError::BufferTooSmall)?;

            // URL: B1 [len] [url...]
            enc.tag_length_value(TAG_URL, url)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::PlayTone {
            tone,
            unit,
            interval,
        } => {
            // Tone: 8E 01 [tone]
            enc.tag_length_value(TAG_TONE, &[*tone])
                .map_err(|_| ProactiveError::BufferTooSmall)?;

            // Duration: 84 02 [unit] [interval]
            enc.tag_length_value(TAG_DURATION, &[unit.to_byte(), *interval])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::SendSms { tpdu } => {
            // SMS TPDU: 8B [len] [tpdu...]
            enc.tag_length_value(TAG_SMS_TPDU, tpdu)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }
    }

    Ok(())
}

impl ProactiveCommand<'_> {
    /// Command type byte, qualifier, and destination device.
    const fn header_fields(&self) -> (u8, u8, u8) {
        match self {
            Self::DisplayText {
                high_priority: _,
                ..
            } => {
                // Qualifier: bit 0 = high priority, bit 7 = clear after delay
                // For simplicity: 0x01 = normal priority + clear after delay
                // 0x01 for both normal and high priority per swsim convention
                (CMD_TYPE_DISPLAY_TEXT, 0x01, DEV_DISPLAY)
            }
            Self::SetUpMenu { .. } => (CMD_TYPE_SET_UP_MENU, 0x00, DEV_TERMINAL),
            Self::LaunchBrowser { .. } => (CMD_TYPE_LAUNCH_BROWSER, 0x00, DEV_TERMINAL),
            Self::PlayTone { .. } => (CMD_TYPE_PLAY_TONE, 0x00, DEV_EARPIECE),
            Self::SendSms { .. } => (CMD_TYPE_SEND_SMS, 0x00, DEV_NETWORK),
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot cursor helpers
// ---------------------------------------------------------------------------

pub(crate) struct SnapWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SnapWriter<'a> {
    pub(crate) const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn put_u8(&mut self, v: u8) {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    pub(crate) fn put_bytes(&mut self, src: &[u8]) {
        self.buf[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
    }
    pub(crate) fn put_u16_le(&mut self, v: u16) {
        self.put_bytes(&v.to_le_bytes());
    }
    pub(crate) const fn finish(self) -> usize {
        self.pos
    }
}

pub(crate) struct SnapReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SnapReader<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn get_u8(&mut self) -> u8 {
        let v = self.buf[self.pos];
        self.pos += 1;
        v
    }
    pub(crate) fn get_bytes(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.buf[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
    }
    pub(crate) fn get_u16_le(&mut self) -> u16 {
        let b = [self.buf[self.pos], self.buf[self.pos + 1]];
        self.pos += 2;
        u16::from_le_bytes(b)
    }
}

// ---------------------------------------------------------------------------
// ProactiveState
// ---------------------------------------------------------------------------

/// Proactive command state machine.
///
/// Tracks the pending command buffer, command sequencing, and the
/// `91 XX` status word override. This struct is owned by the USIM
/// application layer (`simrs-usim`).
///
/// # Example
///
/// ```
/// use simrs_proactive::{ProactiveState, ProactiveCommand, TextCoding};
///
/// let mut state = ProactiveState::new();
/// let cmd = ProactiveCommand::DisplayText {
///     text: b"Test",
///     coding: TextCoding::Gsm8Bit,
///     high_priority: false,
/// };
/// state.queue_command(&cmd).unwrap();
/// assert!(state.has_pending());
///
/// let (sw1, sw2) = state.override_status(0x90, 0x00);
/// assert_eq!(sw1, 0x91);
/// ```
pub struct ProactiveState {
    buf: [u8; 256],
    len: usize,
    seq: u8,
}

impl Default for ProactiveState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProactiveState {
    /// Create a new proactive state with no pending command.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_proactive::ProactiveState;
    /// let state = ProactiveState::new();
    /// assert!(!state.has_pending());
    /// ```
    pub const fn new() -> Self {
        Self {
            buf: [0u8; 256],
            len: 0,
            seq: 1,
        }
    }

    /// Queue a proactive command for delivery via FETCH.
    ///
    /// Encodes the command into the internal buffer. The command number
    /// is assigned automatically from the internal sequence counter.
    ///
    /// # Errors
    ///
    /// Returns [`ProactiveError::BufferTooSmall`] if the encoded command
    /// exceeds 256 bytes.
    pub fn queue_command(&mut self, cmd: &ProactiveCommand<'_>) -> Result<(), ProactiveError> {
        let len = encode(cmd, self.seq, &mut self.buf)?;
        self.len = len;
        Ok(())
    }

    /// Whether a proactive command is pending (awaiting FETCH).
    pub const fn has_pending(&self) -> bool {
        self.len > 0
    }

    /// Length of the pending encoded command, or 0 if none.
    pub const fn pending_len(&self) -> usize {
        self.len
    }

    /// Retrieve the pending command into `out`.
    ///
    /// Returns the number of bytes written. Clears the pending buffer
    /// and advances the sequence counter.
    ///
    /// Returns 0 if no command is pending.
    pub fn fetch(&mut self, out: &mut [u8]) -> usize {
        if self.len == 0 {
            return 0;
        }
        let n = self.len.min(out.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.len = 0;
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1; // skip 0, per convention
        }
        n
    }

    /// Process a TERMINAL RESPONSE from the terminal.
    ///
    /// Currently a no-op beyond allowing the next command to be queued.
    /// The response data could be parsed for result codes in a future
    /// enhancement.
    pub const fn terminal_response(&mut self, _data: &[u8]) {
        // Ready for next command.
    }

    /// Override the status word if a proactive command is pending.
    ///
    /// Per ETSI TS 102 223 clause 6.1: if a proactive command is pending
    /// and the original status would be `90 00`, replace it with `91 XX`
    /// where XX is the pending command length.
    ///
    /// Non-`90 00` status words are returned unchanged. If no command is
    /// pending, the original status is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_proactive::{ProactiveState, ProactiveCommand, TextCoding};
    ///
    /// let mut state = ProactiveState::new();
    /// // No command pending: no override
    /// assert_eq!(state.override_status(0x90, 0x00), (0x90, 0x00));
    ///
    /// state.queue_command(&ProactiveCommand::DisplayText {
    ///     text: b"Hi",
    ///     coding: TextCoding::Gsm8Bit,
    ///     high_priority: false,
    /// }).unwrap();
    ///
    /// // Command pending: override 90 00 -> 91 XX
    /// let (sw1, sw2) = state.override_status(0x90, 0x00);
    /// assert_eq!(sw1, 0x91);
    ///
    /// // Non-9000 is never overridden
    /// assert_eq!(state.override_status(0x6A, 0x82), (0x6A, 0x82));
    /// ```
    #[allow(clippy::cast_possible_truncation)]
    pub const fn override_status(&self, sw1: u8, sw2: u8) -> (u8, u8) {
        if self.len > 0 && sw1 == 0x90 && sw2 == 0x00 {
            (0x91, self.len as u8)
        } else {
            (sw1, sw2)
        }
    }

    /// Current command sequence number (for testing/debugging).
    pub const fn sequence(&self) -> u8 {
        self.seq
    }

    // -- snapshot --

    /// Snapshot buffer size: 259 bytes (`buf`(256) + `len`(2 LE) + `seq`(1)).
    pub const SNAPSHOT_SIZE: usize = 256 + 2 + 1;

    /// Serialize the proactive state into `buf` as flat bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // self.len capped at 256
    pub fn save_state(&self, out: &mut [u8]) -> usize {
        if out.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut w = SnapWriter::new(out);
        w.put_bytes(&self.buf);
        w.put_u16_le(self.len as u16);
        w.put_u8(self.seq);
        w.finish()
    }

    /// Restore the proactive state from `data`.
    ///
    /// Returns `true` on success.
    #[must_use]
    pub fn restore_state(&mut self, data: &[u8]) -> bool {
        if data.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut r = SnapReader::new(data);
        r.get_bytes(&mut self.buf);
        self.len = r.get_u16_le() as usize;
        self.seq = r.get_u8();
        if self.len > 256 {
            self.len = 0;
            return false;
        }
        true
    }
}

// We need a way to encode the D0 envelope with computed inner length.
// The bertlv Encoder doesn't have a "nested" API, so we use the
// dry-run-then-real pattern inline.

/// Extension trait for split encoding (write tag+length, then inner content).
trait EncoderSplitExt {
    /// Write a TLV where the value is produced by a callback.
    ///
    /// # Errors
    ///
    /// Propagates any error from the callback or from buffer overflow.
    fn tag_length_value_split<F>(
        &mut self,
        tag: u8,
        inner_len: usize,
        f: F,
    ) -> Result<(), simrs_bertlv::BerError>
    where
        F: FnOnce(&mut Encoder<'_>) -> Result<(), ProactiveError>;
}

impl EncoderSplitExt for Encoder<'_> {
    fn tag_length_value_split<F>(
        &mut self,
        tag: u8,
        inner_len: usize,
        f: F,
    ) -> Result<(), simrs_bertlv::BerError>
    where
        F: FnOnce(&mut Encoder<'_>) -> Result<(), ProactiveError>,
    {
        // Write tag.
        self.raw(&[tag])?;
        // Write BER length.
        if inner_len <= 0x7F {
            #[allow(clippy::cast_possible_truncation)]
            self.raw(&[inner_len as u8])?;
        } else if inner_len <= 0xFF {
            #[allow(clippy::cast_possible_truncation)]
            self.raw(&[0x81, inner_len as u8])?;
        } else {
            #[allow(clippy::cast_possible_truncation)]
            self.raw(&[0x82, (inner_len >> 8) as u8, inner_len as u8])?;
        }
        // Write inner content.
        f(self).map_err(|_| simrs_bertlv::BerError::BufferFull)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_bertlv::Decoder;

    // -- Encoding structure tests --

    #[test]
    fn display_text_outer_tag_is_d0() {
        let cmd = ProactiveCommand::DisplayText {
            text: b"Hello",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();
        assert!(len > 2);
        assert_eq!(buf[0], 0xD0);
    }

    #[test]
    fn display_text_first_inner_is_cmd_details() {
        let cmd = ProactiveCommand::DisplayText {
            text: b"Hi",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        // Parse outer D0 envelope.
        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        assert_eq!(envelope.tag, 0xD0);

        // Parse inner TLVs.
        let mut inner = Decoder::new(envelope.value);
        let cmd_details = inner.next().unwrap().unwrap();
        assert_eq!(cmd_details.tag, TAG_CMD_DETAILS);
        assert_eq!(cmd_details.value.len(), 3);
        assert_eq!(cmd_details.value[0], 1); // cmd_number
        assert_eq!(cmd_details.value[1], CMD_TYPE_DISPLAY_TEXT); // type
        assert_eq!(cmd_details.value[2], 0x01); // qualifier
    }

    #[test]
    fn display_text_second_inner_is_device_id() {
        let cmd = ProactiveCommand::DisplayText {
            text: b"Hi",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);
        inner.next().unwrap().unwrap(); // skip cmd details
        let dev_id = inner.next().unwrap().unwrap();
        assert_eq!(dev_id.tag, TAG_DEVICE_ID);
        assert_eq!(dev_id.value, &[DEV_UICC, DEV_DISPLAY]);
    }

    #[test]
    fn display_text_has_text_string_tlv() {
        let cmd = ProactiveCommand::DisplayText {
            text: b"Hello",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);
        inner.next().unwrap().unwrap(); // cmd details
        inner.next().unwrap().unwrap(); // device id
        let text = inner.next().unwrap().unwrap();
        assert_eq!(text.tag, TAG_TEXT_STRING);
        assert_eq!(text.value[0], 0x04); // GSM 8-bit DCS
        assert_eq!(&text.value[1..], b"Hello");
    }

    #[test]
    fn display_text_ucs2_encoding() {
        let ucs2_data = [0x00, 0x48, 0x00, 0x69]; // "Hi" in UCS-2
        let cmd = ProactiveCommand::DisplayText {
            text: &ucs2_data,
            coding: TextCoding::Ucs2,
            high_priority: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);
        inner.next().unwrap().unwrap(); // cmd details
        inner.next().unwrap().unwrap(); // device id
        let text = inner.next().unwrap().unwrap();
        assert_eq!(text.value[0], 0x08); // UCS-2 DCS
        assert_eq!(&text.value[1..], &ucs2_data);
    }

    #[test]
    fn display_text_dry_run_matches_real() {
        let cmd = ProactiveCommand::DisplayText {
            text: b"Test message",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        };
        let dry_len = encoded_len(&cmd, 1);
        let mut buf = [0u8; 128];
        let real_len = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(dry_len, real_len);
    }

    // -- SET UP MENU tests --

    #[test]
    fn set_up_menu_encoding() {
        let items = [
            MenuItem {
                id: 1,
                text: b"Item One",
            },
            MenuItem {
                id: 2,
                text: b"Item Two",
            },
            MenuItem {
                id: 3,
                text: b"Item Three",
            },
        ];
        let cmd = ProactiveCommand::SetUpMenu {
            title: b"Main",
            items: &items,
        };
        let mut buf = [0u8; 128];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        assert_eq!(envelope.tag, 0xD0);

        let mut inner = Decoder::new(envelope.value);

        // Command details
        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SET_UP_MENU);

        // Device identities
        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_TERMINAL);

        // Alpha identifier (title)
        let alpha = inner.next().unwrap().unwrap();
        assert_eq!(alpha.tag, TAG_ALPHA_ID);
        assert_eq!(alpha.value, b"Main");

        // Three menu items
        let item1 = inner.next().unwrap().unwrap();
        assert_eq!(item1.tag, TAG_ITEM);
        assert_eq!(item1.value[0], 1);
        assert_eq!(&item1.value[1..], b"Item One");

        let item2 = inner.next().unwrap().unwrap();
        assert_eq!(item2.tag, TAG_ITEM);
        assert_eq!(item2.value[0], 2);
        assert_eq!(&item2.value[1..], b"Item Two");

        let item3 = inner.next().unwrap().unwrap();
        assert_eq!(item3.tag, TAG_ITEM);
        assert_eq!(item3.value[0], 3);
        assert_eq!(&item3.value[1..], b"Item Three");

        // No more TLVs
        assert!(inner.next().is_none());
    }

    // -- LAUNCH BROWSER tests --

    #[test]
    fn launch_browser_encoding() {
        let cmd = ProactiveCommand::LaunchBrowser {
            url: b"http://example.com",
            browser_id: 0x00,
        };
        let mut buf = [0u8; 128];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_LAUNCH_BROWSER);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_TERMINAL);

        let browser = inner.next().unwrap().unwrap();
        assert_eq!(browser.tag, TAG_BROWSER_ID);
        assert_eq!(browser.value, &[0x00]);

        let url = inner.next().unwrap().unwrap();
        assert_eq!(url.tag, TAG_URL);
        assert_eq!(url.value, b"http://example.com");
    }

    // -- PLAY TONE tests --

    #[test]
    fn play_tone_encoding() {
        let cmd = ProactiveCommand::PlayTone {
            tone: 0x01,
            unit: TimeUnit::Tenths,
            interval: 5,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_PLAY_TONE);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_EARPIECE);

        let tone = inner.next().unwrap().unwrap();
        assert_eq!(tone.tag, TAG_TONE);
        assert_eq!(tone.value, &[0x01]);

        let dur = inner.next().unwrap().unwrap();
        assert_eq!(dur.tag, TAG_DURATION);
        assert_eq!(dur.value, &[0x02, 0x05]); // tenths, 5
    }

    // -- SEND SMS tests --

    #[test]
    fn send_sms_encoding() {
        let tpdu = [0x01, 0x00, 0x0B, 0x91];
        let cmd = ProactiveCommand::SendSms { tpdu: &tpdu };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SEND_SMS);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_NETWORK);

        let sms = inner.next().unwrap().unwrap();
        assert_eq!(sms.tag, TAG_SMS_TPDU);
        assert_eq!(sms.value, &tpdu);
    }

    // -- ProactiveState tests --

    #[test]
    fn new_state_has_no_pending() {
        let state = ProactiveState::new();
        assert!(!state.has_pending());
        assert_eq!(state.pending_len(), 0);
    }

    #[test]
    fn queue_makes_pending() {
        let mut state = ProactiveState::new();
        let cmd = ProactiveCommand::DisplayText {
            text: b"Hello",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        };
        state.queue_command(&cmd).unwrap();
        assert!(state.has_pending());
        assert!(state.pending_len() > 0);
    }

    #[test]
    fn override_status_when_pending() {
        let mut state = ProactiveState::new();
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Hi",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();

        let (sw1, sw2) = state.override_status(0x90, 0x00);
        assert_eq!(sw1, 0x91);
        #[allow(clippy::cast_possible_truncation)]
        let expected_len = state.pending_len() as u8;
        assert_eq!(sw2, expected_len);
    }

    #[test]
    fn override_status_no_change_for_non_9000() {
        let mut state = ProactiveState::new();
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Hi",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();
        assert_eq!(state.override_status(0x6A, 0x82), (0x6A, 0x82));
    }

    #[test]
    fn override_status_no_change_when_no_pending() {
        let state = ProactiveState::new();
        assert_eq!(state.override_status(0x90, 0x00), (0x90, 0x00));
    }

    #[test]
    fn fetch_retrieves_and_clears() {
        let mut state = ProactiveState::new();
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Hello",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();
        let plen = state.pending_len();

        let mut buf = [0u8; 256];
        let n = state.fetch(&mut buf);
        assert_eq!(n, plen);
        assert_eq!(buf[0], 0xD0);
        assert!(!state.has_pending());
        assert_eq!(state.pending_len(), 0);
    }

    #[test]
    fn fetch_with_no_pending_returns_zero() {
        let mut state = ProactiveState::new();
        let mut buf = [0u8; 256];
        assert_eq!(state.fetch(&mut buf), 0);
    }

    #[test]
    fn terminal_response_allows_next_command() {
        let mut state = ProactiveState::new();
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"First",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();

        let mut buf = [0u8; 256];
        state.fetch(&mut buf);
        state.terminal_response(&[0x81, 0x03, 0x01, 0x21, 0x00]);

        // Can queue another command.
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Second",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();
        assert!(state.has_pending());
    }

    #[test]
    fn sequential_commands_increment_number() {
        let mut state = ProactiveState::new();
        assert_eq!(state.sequence(), 1);

        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"First",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();

        // Verify cmd_number in encoding is 1.
        let mut buf = [0u8; 256];
        let n = state.fetch(&mut buf);
        let mut outer = Decoder::new(&buf[..n]);
        let env = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(env.value);
        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[0], 1); // command number = 1

        state.terminal_response(&[]);
        assert_eq!(state.sequence(), 2);

        // Second command should have number 2.
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Second",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();
        let n = state.fetch(&mut buf);
        let mut outer = Decoder::new(&buf[..n]);
        let env = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(env.value);
        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[0], 2); // command number = 2
    }

    // -- Buffer overflow tests --

    #[test]
    fn encode_into_tiny_buffer_returns_error() {
        let cmd = ProactiveCommand::DisplayText {
            text: b"Hello",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        };
        let mut buf = [0u8; 4];
        assert_eq!(
            encode(&cmd, 1, &mut buf),
            Err(ProactiveError::BufferTooSmall)
        );
    }

    // -- Device identity constants --

    #[test]
    fn device_identity_values() {
        assert_eq!(DEV_KEYPAD, 0x01);
        assert_eq!(DEV_DISPLAY, 0x02);
        assert_eq!(DEV_EARPIECE, 0x03);
        assert_eq!(DEV_UICC, 0x81);
        assert_eq!(DEV_TERMINAL, 0x82);
        assert_eq!(DEV_NETWORK, 0x83);
    }

    // -- TextCoding DCS bytes --

    #[test]
    fn text_coding_dcs_bytes() {
        assert_eq!(TextCoding::Gsm7Bit.dcs_byte(), 0x00);
        assert_eq!(TextCoding::Gsm8Bit.dcs_byte(), 0x04);
        assert_eq!(TextCoding::Ucs2.dcs_byte(), 0x08);
    }

    // -- TimeUnit bytes --

    #[test]
    fn time_unit_bytes() {
        assert_eq!(TimeUnit::Minutes.to_byte(), 0x00);
        assert_eq!(TimeUnit::Seconds.to_byte(), 0x01);
        assert_eq!(TimeUnit::Tenths.to_byte(), 0x02);
    }

    // -- All command types encode without error --

    #[test]
    fn all_command_types_encode_successfully() {
        let items = [MenuItem {
            id: 1,
            text: b"A",
        }];
        let commands: &[ProactiveCommand<'_>] = &[
            ProactiveCommand::DisplayText {
                text: b"X",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            },
            ProactiveCommand::SetUpMenu {
                title: b"T",
                items: &items,
            },
            ProactiveCommand::LaunchBrowser {
                url: b"http://x",
                browser_id: 0,
            },
            ProactiveCommand::PlayTone {
                tone: 1,
                unit: TimeUnit::Seconds,
                interval: 3,
            },
            ProactiveCommand::SendSms {
                tpdu: &[0x01, 0x02],
            },
        ];
        for cmd in commands {
            let mut buf = [0u8; 128];
            let len = encode(cmd, 1, &mut buf).unwrap();
            assert!(len > 0);
            assert_eq!(buf[0], 0xD0);
        }
    }

    // -- SNAPSHOT tests --

    #[test]
    fn snapshot_size_correct() {
        assert_eq!(ProactiveState::SNAPSHOT_SIZE, 259);
    }

    #[test]
    fn snapshot_roundtrip_with_pending_command() {
        let mut state = ProactiveState::new();
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Snapshot test",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();
        let orig_len = state.pending_len();
        let orig_seq = state.sequence();

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        assert_eq!(state.save_state(&mut snap), 259);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));
        assert!(restored.has_pending());
        assert_eq!(restored.pending_len(), orig_len);
        assert_eq!(restored.sequence(), orig_seq);

        // Fetch should produce the same data.
        let mut orig_buf = [0u8; 256];
        let mut rest_buf = [0u8; 256];
        let orig_n = state.fetch(&mut orig_buf);
        let rest_n = restored.fetch(&mut rest_buf);
        assert_eq!(orig_n, rest_n);
        assert_eq!(&orig_buf[..orig_n], &rest_buf[..rest_n]);
    }

    #[test]
    fn snapshot_roundtrip_empty_state() {
        let state = ProactiveState::new();
        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let _ = state.save_state(&mut snap);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));
        assert!(!restored.has_pending());
        assert_eq!(restored.sequence(), 1);
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let state = ProactiveState::new();
        let mut small = [0u8; 10];
        assert_eq!(state.save_state(&mut small), 0);

        let mut s2 = ProactiveState::new();
        assert!(!s2.restore_state(&small));
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Dry-run always matches real encoding for DISPLAY TEXT.
        #[test]
        fn dry_run_matches_real_display_text(
            text in proptest::collection::vec(0x20u8..=0x7E, 1..200),
            cmd_num in 1u8..=255,
        ) {
            let cmd = ProactiveCommand::DisplayText {
                text: &text,
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            };
            let dry = encoded_len(&cmd, cmd_num);
            let mut buf = [0u8; 256];
            let real = encode(&cmd, cmd_num, &mut buf).unwrap();
            prop_assert_eq!(dry, real);
        }

        // Every encoded command starts with D0 and round-trips through
        // BER-TLV decoder.
        #[test]
        fn encoded_starts_with_d0_and_decodes(
            text in proptest::collection::vec(0x20u8..=0x7E, 1..100),
        ) {
            let cmd = ProactiveCommand::DisplayText {
                text: &text,
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            };
            let mut buf = [0u8; 256];
            let len = encode(&cmd, 1, &mut buf).unwrap();
            prop_assert_eq!(buf[0], 0xD0);

            let mut dec = simrs_bertlv::Decoder::new(&buf[..len]);
            let obj = dec.next().unwrap().unwrap();
            prop_assert_eq!(obj.tag, 0xD0);
            prop_assert!(obj.value.len() > 7); // at least cmd_details + device_id
        }

        // Queue + fetch round-trip preserves encoding.
        #[test]
        fn queue_fetch_roundtrip(
            text in proptest::collection::vec(0x20u8..=0x7E, 1..100),
        ) {
            let cmd = ProactiveCommand::DisplayText {
                text: &text,
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            };

            // Encode directly.
            let mut direct = [0u8; 256];
            let direct_len = encode(&cmd, 1, &mut direct).unwrap();

            // Queue then fetch.
            let mut state = ProactiveState::new();
            state.queue_command(&cmd).unwrap();
            let mut fetched = [0u8; 256];
            let fetched_len = state.fetch(&mut fetched);

            prop_assert_eq!(direct_len, fetched_len);
            prop_assert_eq!(&direct[..direct_len], &fetched[..fetched_len]);
        }
    }
}
