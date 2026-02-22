//! Proactive UICC command encoding and state machine.
//!
//! Encodes proactive commands as BER-TLV envelopes (outer tag `0xD0`) for
//! retrieval via FETCH. Manages the pending command buffer, the
//! `91 XX` status word override mechanism, ENVELOPE event processing,
//! and terminal profile storage.
//!
//! Supported commands (P0 -- matching swsim):
//! - DISPLAY TEXT (type `0x21`)
//! - SET UP MENU (type `0x25`)
//! - LAUNCH BROWSER (type `0x15`)
//! - PLAY TONE (type `0x20`)
//! - SEND SHORT MESSAGE (type `0x13`)
//! - GET INKEY (type `0x22`)
//! - GET INPUT (type `0x23`)
//! - SELECT ITEM (type `0x24`)
//! - SET UP IDLE MODE TEXT (type `0x28`)
//! - REFRESH (type `0x01`)
//! - MORE TIME (type `0x02`)
//! - POLL INTERVAL (type `0x03`)
//! - POLLING OFF (type `0x04`)
//! - SET UP EVENT LIST (type `0x05`)
//! - SET UP CALL (type `0x10`)
//! - SEND USSD (type `0x12`)
//! - SEND DTMF (type `0x14`)
//! - PROVIDE LOCAL INFORMATION (type `0x26`)
//! - TIMER MANAGEMENT (type `0x27`)
//! - LANGUAGE NOTIFICATION (type `0x35`)
//! - SEND SS (type `0x11`)
//! - GEOGRAPHICAL LOCATION REQUEST (type `0x16`)
//! - PERFORM CARD APDU (type `0x30`)
//! - POWER ON CARD (type `0x31`)
//! - POWER OFF CARD (type `0x32`)
//! - GET READER STATUS (type `0x33`)
//! - RUN AT COMMAND (type `0x34`)
//! - OPEN CHANNEL (type `0x40`)
//! - CLOSE CHANNEL (type `0x41`)
//! - RECEIVE DATA (type `0x42`)
//! - SEND DATA (type `0x43`)
//! - GET CHANNEL STATUS (type `0x44`)
//! - SERVICE SEARCH (type `0x45`)
//! - GET SERVICE INFORMATION (type `0x46`)
//! - DECLARE SERVICE (type `0x47`)
//! - SET FRAMES (type `0x50`)
//! - GET FRAMES STATUS (type `0x51`)
//! - RETRIEVE MULTIMEDIA MESSAGE (type `0x60`)
//! - SUBMIT MULTIMEDIA MESSAGE (type `0x61`)
//! - DISPLAY MULTIMEDIA MESSAGE (type `0x62`)
//! - ACTIVATE (type `0x70`)
//! - CONTACTLESS STATE CHANGED (type `0x71`)
//! - COMMAND CONTAINER (type `0x72`)
//! - ENCAPSULATED SESSION CONTROL (type `0x73`)
//! - LSI COMMAND (type `0x79`)
//! - END OF PROACTIVE UICC SESSION (type `0x81`)
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

pub mod gsm7;

use simrs_bertlv::{BER_LONG_FORM_1, BER_LONG_FORM_2, BER_SHORT_FORM_MAX, Decoder, Encoder};

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
/// Response Length (ETSI TS 102 223 clause 8.11).
const TAG_RESPONSE_LENGTH: u8 = 0x91;
/// Result (ETSI TS 102 223 clause 8.12).
const TAG_RESULT: u8 = 0x83;

/// BER-TLV tag for Menu Selection envelope (ETSI TS 102 223 clause 7.1).
const TAG_MENU_SELECTION: u8 = 0xD3;
/// BER-TLV tag for Event Download envelope (ETSI TS 102 223 clause 7.5).
const TAG_EVENT_DOWNLOAD: u8 = 0xD6;
/// Item Identifier tag (ETSI TS 102 223 clause 8.10).
const TAG_ITEM_ID: u8 = 0x90;

/// File List (TS 102 223 clause 8.18).
const TAG_FILE_LIST: u8 = 0x92;
/// Event List (TS 102 223 clause 8.25).
const TAG_EVENT_LIST: u8 = 0x99;
/// Address (TS 102 223 clause 8.1).
const TAG_ADDRESS: u8 = 0x86;
/// USSD String (TS 102 223 clause 8.17).
const TAG_USSD_STRING: u8 = 0x8A;
/// DTMF String (TS 102 223 clause 8.44).
const TAG_DTMF_STRING: u8 = 0xAC;
/// Timer Identifier (TS 102 223 clause 8.38).
const TAG_TIMER_ID: u8 = 0xA4;
/// Timer Value (TS 102 223 clause 8.39).
const TAG_TIMER_VALUE: u8 = 0xA5;
/// Language (TS 102 223 clause 8.45).
const TAG_LANGUAGE: u8 = 0xAD;
/// Bearer Description (TS 102 223 clause 8.52).
const TAG_BEARER_DESCRIPTION: u8 = 0xB5;
/// Buffer Size (TS 102 223 clause 8.55).
const TAG_BUFFER_SIZE: u8 = 0xB9;
/// Transport Level (TS 102 223 clause 8.59).
const TAG_TRANSPORT_LEVEL: u8 = 0xBC;
/// Other Address (TS 102 223 clause 8.58).
const TAG_OTHER_ADDRESS: u8 = 0xBE;

// -- Command type values (ETSI TS 102 223 clause 9.4) --

/// SEND SHORT MESSAGE (type `0x13`).
const CMD_TYPE_SEND_SMS: u8 = 0x13;
/// LAUNCH BROWSER (type `0x15`).
const CMD_TYPE_LAUNCH_BROWSER: u8 = 0x15;
/// PLAY TONE (type `0x20`).
const CMD_TYPE_PLAY_TONE: u8 = 0x20;
/// DISPLAY TEXT (type `0x21`).
const CMD_TYPE_DISPLAY_TEXT: u8 = 0x21;
/// GET INKEY (type `0x22`).
const CMD_TYPE_GET_INKEY: u8 = 0x22;
/// GET INPUT (type `0x23`).
const CMD_TYPE_GET_INPUT: u8 = 0x23;
/// SELECT ITEM (type `0x24`).
const CMD_TYPE_SELECT_ITEM: u8 = 0x24;
/// SET UP MENU (type `0x25`).
const CMD_TYPE_SET_UP_MENU: u8 = 0x25;
/// SET UP IDLE MODE TEXT (type `0x28`).
const CMD_TYPE_SETUP_IDLE_TEXT: u8 = 0x28;

/// REFRESH (type `0x01`).
const CMD_TYPE_REFRESH: u8 = 0x01;
/// MORE TIME (type `0x02`).
const CMD_TYPE_MORE_TIME: u8 = 0x02;
/// POLL INTERVAL (type `0x03`).
const CMD_TYPE_POLL_INTERVAL: u8 = 0x03;
/// POLLING OFF (type `0x04`).
const CMD_TYPE_POLLING_OFF: u8 = 0x04;
/// SET UP EVENT LIST (type `0x05`).
const CMD_TYPE_SET_UP_EVENT_LIST: u8 = 0x05;
/// SET UP CALL (type `0x10`).
const CMD_TYPE_SET_UP_CALL: u8 = 0x10;
/// SEND USSD (type `0x12`).
const CMD_TYPE_SEND_USSD: u8 = 0x12;
/// SEND DTMF (type `0x14`).
const CMD_TYPE_SEND_DTMF: u8 = 0x14;
/// PROVIDE LOCAL INFORMATION (type `0x26`).
const CMD_TYPE_PROVIDE_LOCAL_INFO: u8 = 0x26;
/// TIMER MANAGEMENT (type `0x27`).
const CMD_TYPE_TIMER_MANAGEMENT: u8 = 0x27;
/// LANGUAGE NOTIFICATION (type `0x35`).
const CMD_TYPE_LANGUAGE_NOTIFICATION: u8 = 0x35;
/// SEND SS (type `0x11`).
const CMD_TYPE_SEND_SS: u8 = 0x11;
/// GEOGRAPHICAL LOCATION REQUEST (type `0x16`).
const CMD_TYPE_GEO_LOCATION_REQUEST: u8 = 0x16;
/// PERFORM CARD APDU (type `0x30`).
const CMD_TYPE_PERFORM_CARD_APDU: u8 = 0x30;
/// POWER ON CARD (type `0x31`).
const CMD_TYPE_POWER_ON_CARD: u8 = 0x31;
/// POWER OFF CARD (type `0x32`).
const CMD_TYPE_POWER_OFF_CARD: u8 = 0x32;
/// GET READER STATUS (type `0x33`).
const CMD_TYPE_GET_READER_STATUS: u8 = 0x33;
/// RUN AT COMMAND (type `0x34`).
const CMD_TYPE_RUN_AT_COMMAND: u8 = 0x34;
/// OPEN CHANNEL (type `0x40`).
const CMD_TYPE_OPEN_CHANNEL: u8 = 0x40;
/// CLOSE CHANNEL (type `0x41`).
const CMD_TYPE_CLOSE_CHANNEL: u8 = 0x41;
/// RECEIVE DATA (type `0x42`).
const CMD_TYPE_RECEIVE_DATA: u8 = 0x42;
/// SEND DATA (type `0x43`).
const CMD_TYPE_SEND_DATA: u8 = 0x43;
/// GET CHANNEL STATUS (type `0x44`).
const CMD_TYPE_GET_CHANNEL_STATUS: u8 = 0x44;
/// SERVICE SEARCH (type `0x45`).
const CMD_TYPE_SERVICE_SEARCH: u8 = 0x45;
/// GET SERVICE INFORMATION (type `0x46`).
const CMD_TYPE_GET_SERVICE_INFO: u8 = 0x46;
/// DECLARE SERVICE (type `0x47`).
const CMD_TYPE_DECLARE_SERVICE: u8 = 0x47;
/// SET FRAMES (type `0x50`).
const CMD_TYPE_SET_FRAMES: u8 = 0x50;
/// GET FRAMES STATUS (type `0x51`).
const CMD_TYPE_GET_FRAMES_STATUS: u8 = 0x51;
/// RETRIEVE MULTIMEDIA MESSAGE (type `0x60`).
const CMD_TYPE_RETRIEVE_MMS: u8 = 0x60;
/// SUBMIT MULTIMEDIA MESSAGE (type `0x61`).
const CMD_TYPE_SUBMIT_MMS: u8 = 0x61;
/// DISPLAY MULTIMEDIA MESSAGE (type `0x62`).
const CMD_TYPE_DISPLAY_MMS: u8 = 0x62;
/// ACTIVATE (type `0x70`).
const CMD_TYPE_ACTIVATE: u8 = 0x70;
/// CONTACTLESS STATE CHANGED (type `0x71`).
const CMD_TYPE_CONTACTLESS_STATE_CHANGED: u8 = 0x71;
/// COMMAND CONTAINER (type `0x72`).
const CMD_TYPE_COMMAND_CONTAINER: u8 = 0x72;
/// ENCAPSULATED SESSION CONTROL (type `0x73`).
const CMD_TYPE_ENCAP_SESSION_CTRL: u8 = 0x73;
/// LSI COMMAND (type `0x79`).
const CMD_TYPE_LSI_COMMAND: u8 = 0x79;
/// END OF PROACTIVE UICC SESSION (type `0x81`).
const CMD_TYPE_END_PROACTIVE_SESSION: u8 = 0x81;

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
// Event ID constants (ETSI TS 102 223 clause 8.25)
// ---------------------------------------------------------------------------

/// Event type identifiers for SET UP EVENT LIST and Event Download.
///
/// Per ETSI TS 102 223 clause 8.25. These are the event ID bytes
/// carried in the Event List TLV (tag 0x99).
pub mod event_id {
    /// MT call event.
    pub const MT_CALL: u8 = 0x00;
    /// Call connected event.
    pub const CALL_CONNECTED: u8 = 0x01;
    /// Call disconnected event.
    pub const CALL_DISCONNECTED: u8 = 0x02;
    /// Location status event.
    pub const LOCATION_STATUS: u8 = 0x03;
    /// User activity event.
    pub const USER_ACTIVITY: u8 = 0x04;
    /// Idle screen available event.
    pub const IDLE_SCREEN_AVAILABLE: u8 = 0x05;
    /// Timer expiry event.
    pub const TIMER_EXPIRY: u8 = 0x07;
    /// Language selection event.
    pub const LANGUAGE_SELECTION: u8 = 0x09;
    /// Browser termination event.
    pub const BROWSER_TERMINATION: u8 = 0x0B;
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// ENVELOPE event parsed from terminal.
///
/// Per ETSI TS 102 223 clause 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeEvent {
    /// Terminal user selected a menu item (tag D3).
    MenuSelection {
        /// The selected item identifier.
        item_id: u8,
    },
    /// Terminal reports an event (tag D6).
    ///
    /// Per ETSI TS 102 223 clause 7.5.
    EventDownload {
        /// Event type byte (see [`event_id`] constants).
        event_type: u8,
        /// Timer ID (1-8) for Timer Expiry events, 0 otherwise.
        timer_id: u8,
        /// BCD timer value [hours, minutes, seconds] for Timer Expiry.
        timer_value: [u8; 3],
    },
}

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

    /// GET INKEY (type `0x22`): prompt for single character.
    ///
    /// Per ETSI TS 102 223 clause 6.4.2.
    GetInkey {
        /// Prompt text.
        text: &'a [u8],
        /// Text encoding.
        coding: TextCoding,
        /// If true, only digits (0-9, *, #, +) accepted.
        digits_only: bool,
    },

    /// GET INPUT (type `0x23`): prompt for text string.
    ///
    /// Per ETSI TS 102 223 clause 6.4.3.
    GetInput {
        /// Prompt text.
        text: &'a [u8],
        /// Text encoding.
        coding: TextCoding,
        /// Minimum response length.
        min_len: u8,
        /// Maximum response length.
        max_len: u8,
        /// If true, only digits (0-9, *, #, +) accepted.
        digits_only: bool,
    },

    /// SELECT ITEM (type `0x24`): present list of items.
    ///
    /// Per ETSI TS 102 223 clause 6.4.9.
    SelectItem {
        /// Menu title (alpha identifier).
        title: &'a [u8],
        /// Selection items (1--255).
        items: &'a [MenuItem<'a>],
    },

    /// SET UP IDLE MODE TEXT (type `0x28`): persistent idle screen text.
    ///
    /// Per ETSI TS 102 223 clause 6.4.22.
    SetUpIdleModeText {
        /// Text to display on idle screen.
        text: &'a [u8],
        /// Text encoding.
        coding: TextCoding,
    },

    /// REFRESH (type `0x01`): card lifecycle management.
    /// Per ETSI TS 102 223 clause 6.4.7.
    Refresh {
        /// Refresh qualifier (0x00-0x07 per TS 102 223 clause 8.6).
        qualifier: u8,
        /// File list (raw bytes for File List TLV value).
        file_list: &'a [u8],
    },

    /// MORE TIME (type `0x02`): request additional processing time.
    /// Per ETSI TS 102 223 clause 6.6.4.
    MoreTime,

    /// POLL INTERVAL (type `0x03`): set polling interval.
    /// Per ETSI TS 102 223 clause 6.6.5.
    PollInterval {
        /// Duration time unit.
        unit: TimeUnit,
        /// Duration value (1-255).
        interval: u8,
    },

    /// POLLING OFF (type `0x04`): disable polling.
    /// Per ETSI TS 102 223 clause 6.6.6.
    PollingOff,

    /// SET UP EVENT LIST (type `0x05`): subscribe to terminal events.
    /// Per ETSI TS 102 223 clause 6.4.16.
    SetUpEventList {
        /// Event ID bytes per TS 102 223 clause 8.25.
        events: &'a [u8],
    },

    /// SET UP CALL (type `0x10`): initiate a voice call.
    /// Per ETSI TS 102 223 clause 6.6.12.
    SetUpCall {
        /// Address (TON/NPI prefix byte + dialing number).
        address: &'a [u8],
        /// Call qualifier per TS 102 223 clause 8.6.
        qualifier: u8,
        /// Alpha identifier for user confirmation.
        alpha_id: &'a [u8],
    },

    /// SEND USSD (type `0x12`): send a USSD string.
    /// Per ETSI TS 102 223 clause 6.6.8.
    SendUssd {
        /// USSD string (DCS byte + string data).
        ussd_string: &'a [u8],
    },

    /// SEND DTMF (type `0x14`): send DTMF tones during a call.
    /// Per ETSI TS 102 223 clause 6.6.24.
    SendDtmf {
        /// DTMF string (BCD encoded digits).
        dtmf: &'a [u8],
    },

    /// PROVIDE LOCAL INFORMATION (type `0x26`): request terminal info.
    /// Per ETSI TS 102 223 clause 6.4.15.
    ProvideLocalInformation {
        /// Information subtype (qualifier byte).
        qualifier: u8,
    },

    /// TIMER MANAGEMENT (type `0x27`): start/stop/query timers.
    /// Per ETSI TS 102 223 clause 6.6.21.
    TimerManagement {
        /// Timer identifier (1-8).
        timer_id: u8,
        /// Qualifier: 0x00=start, 0x01=deactivate, 0x02=get value.
        qualifier: u8,
        /// Timer value in BCD [hours, minutes, seconds].
        /// Required for start. None for deactivate/get.
        timer_value: Option<[u8; 3]>,
    },

    /// LANGUAGE NOTIFICATION (type `0x35`): language change.
    /// Per ETSI TS 102 223 clause 6.4.25.
    LanguageNotification {
        /// If true, specific language notification.
        specific: bool,
        /// Language code (2 bytes, ISO 639). Required if specific.
        language: Option<[u8; 2]>,
    },

    /// SEND SS (type `0x11`): send supplementary service request.
    /// Per ETSI TS 102 223 clause 6.4.10.
    SendSs {
        /// SS qualifier.
        qualifier: u8,
    },

    /// GEOGRAPHICAL LOCATION REQUEST (type `0x16`).
    /// Per ETSI TS 102 223 clause 6.4.28.
    GeographicalLocationRequest,

    /// PERFORM CARD APDU (type `0x30`): proxy APDU to another card.
    /// Per ETSI TS 102 223 clause 6.4.17.
    PerformCardApdu {
        /// Card reader qualifier.
        qualifier: u8,
    },

    /// POWER ON CARD (type `0x31`): power on additional card.
    /// Per ETSI TS 102 223 clause 6.4.18.
    PowerOnCard {
        /// Card reader qualifier.
        qualifier: u8,
    },

    /// POWER OFF CARD (type `0x32`): power off additional card.
    /// Per ETSI TS 102 223 clause 6.4.19.
    PowerOffCard {
        /// Card reader qualifier.
        qualifier: u8,
    },

    /// GET READER STATUS (type `0x33`): query card reader state.
    /// Per ETSI TS 102 223 clause 6.4.20.
    GetReaderStatus {
        /// Card reader qualifier.
        qualifier: u8,
    },

    /// RUN AT COMMAND (type `0x34`): execute modem AT command.
    /// Per ETSI TS 102 223 clause 6.6.28.
    RunAtCommand,

    /// OPEN CHANNEL (type `0x40`): establish BIP connection.
    /// Per ETSI TS 102 223 clause 6.4.27.
    OpenChannel {
        /// Bearer description bytes (type + parameters).
        bearer: &'a [u8],
        /// Buffer size (big-endian u16).
        buffer_size: u16,
        /// Alpha identifier (empty = not present).
        alpha_id: &'a [u8],
        /// Transport level (`protocol_type`, `port_hi`, `port_lo`). Empty = not present.
        transport_level: &'a [u8],
        /// Data destination address. Empty = not present.
        destination_address: &'a [u8],
        /// Command qualifier per TS 102 223.
        qualifier: u8,
    },

    /// CLOSE CHANNEL (type `0x41`): terminate BIP channel.
    /// Per ETSI TS 102 223 clause 6.4.28.
    CloseChannel {
        /// Channel qualifier.
        qualifier: u8,
    },

    /// RECEIVE DATA (type `0x42`): receive data from BIP channel.
    /// Per ETSI TS 102 223 clause 6.4.29.
    ReceiveData {
        /// Channel qualifier.
        qualifier: u8,
    },

    /// SEND DATA (type `0x43`): send data on BIP channel.
    /// Per ETSI TS 102 223 clause 6.4.30.
    SendDataCmd {
        /// Channel qualifier.
        qualifier: u8,
    },

    /// GET CHANNEL STATUS (type `0x44`): query BIP channel state.
    /// Per ETSI TS 102 223 clause 6.4.31.
    GetChannelStatus,

    /// SERVICE SEARCH (type `0x45`): search for local services.
    /// Per ETSI TS 102 223 clause 6.4.32.
    ServiceSearch,

    /// GET SERVICE INFORMATION (type `0x46`): get service details.
    /// Per ETSI TS 102 223 clause 6.4.33.
    GetServiceInformation,

    /// DECLARE SERVICE (type `0x47`): declare a local service.
    /// Per ETSI TS 102 223 clause 6.4.34.
    DeclareService {
        /// Service qualifier.
        qualifier: u8,
    },

    /// SET FRAMES (type `0x50`): configure display frames.
    /// Per ETSI TS 102 223 clause 6.4.35.
    SetFrames,

    /// GET FRAMES STATUS (type `0x51`): query frame layout.
    /// Per ETSI TS 102 223 clause 6.4.36.
    GetFramesStatus,

    /// RETRIEVE MULTIMEDIA MESSAGE (type `0x60`).
    /// Per ETSI TS 102 223 clause 6.4.37.
    RetrieveMultimediaMessage,

    /// SUBMIT MULTIMEDIA MESSAGE (type `0x61`).
    /// Per ETSI TS 102 223 clause 6.4.38.
    SubmitMultimediaMessage,

    /// DISPLAY MULTIMEDIA MESSAGE (type `0x62`).
    /// Per ETSI TS 102 223 clause 6.4.39.
    DisplayMultimediaMessage,

    /// ACTIVATE (type `0x70`): profile activation.
    /// Per ETSI TS 102 223 clause 6.4.40.
    Activate {
        /// Activation qualifier.
        qualifier: u8,
    },

    /// CONTACTLESS STATE CHANGED (type `0x71`): NFC state notification.
    /// Per ETSI TS 102 223 clause 6.4.41.
    ContactlessStateChanged,

    /// COMMAND CONTAINER (type `0x72`): grouped commands.
    /// Per ETSI TS 102 223 clause 6.4.42.
    CommandContainer,

    /// ENCAPSULATED SESSION CONTROL (type `0x73`): secure session.
    /// Per ETSI TS 102 223 clause 6.4.43.
    EncapsulatedSessionControl,

    /// LSI COMMAND (type `0x79`): Locally Supplied Information.
    /// Per ETSI TS 102 223 clause 6.4.44.
    LsiCommand,

    /// END OF PROACTIVE UICC SESSION (type `0x81`): session termination.
    /// Per ETSI TS 102 223 clause 6.6.14.
    EndOfProactiveUiccSession,
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

/// Parsed result from a TERMINAL RESPONSE APDU.
///
/// Per ETSI TS 102 223 clause 6.8, the terminal sends this in response
/// to a proactive command. Contains the command details and general result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalResult {
    /// Command number echoed from the original proactive command.
    pub cmd_number: u8,
    /// Command type echoed from the original proactive command.
    pub cmd_type: u8,
    /// General result byte (ETSI TS 102 223 clause 8.12).
    ///
    /// Common values:
    /// - `0x00`: command performed successfully
    /// - `0x10`: proactive UICC session terminated by the user
    /// - `0x12`: no response from user
    /// - `0x20`: terminal currently unable to process command
    /// - `0x30`: beyond terminal's capabilities
    pub general_result: u8,
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

/// Encode a TLV whose value is `[prefix]` followed by `data`.
fn encode_prefixed_tlv(
    enc: &mut Encoder<'_>,
    tag: u8,
    prefix: u8,
    data: &[u8],
) -> Result<(), ProactiveError> {
    let mut buf = [0u8; 256];
    let total = 1 + data.len();
    if total > buf.len() {
        return Err(ProactiveError::BufferTooSmall);
    }
    buf[0] = prefix;
    buf[1..total].copy_from_slice(data);
    enc.tag_length_value(tag, &buf[..total])
        .map_err(|_| ProactiveError::BufferTooSmall)
}

/// Encode a Text String TLV: tag `0x8D`, value = [DCS byte] [text bytes].
fn encode_text_string(
    enc: &mut Encoder<'_>,
    text: &[u8],
    coding: TextCoding,
) -> Result<(), ProactiveError> {
    encode_prefixed_tlv(enc, TAG_TEXT_STRING, coding.dcs_byte(), text)
}

/// Encode a sequence of Item TLVs: tag `0x8F`, value = [id] [text bytes].
fn encode_items(
    enc: &mut Encoder<'_>,
    items: &[MenuItem<'_>],
) -> Result<(), ProactiveError> {
    for item in items {
        encode_prefixed_tlv(enc, TAG_ITEM, item.id, item.text)?;
    }
    Ok(())
}

/// Encode command-specific payload TLVs.
#[allow(clippy::too_many_lines)]
fn encode_payload(
    enc: &mut Encoder<'_>,
    cmd: &ProactiveCommand<'_>,
) -> Result<(), ProactiveError> {
    match cmd {
        ProactiveCommand::DisplayText { text, coding, .. }
        | ProactiveCommand::GetInkey { text, coding, .. }
        | ProactiveCommand::SetUpIdleModeText { text, coding } => {
            encode_text_string(enc, text, *coding)?;
        }

        ProactiveCommand::SetUpMenu { title, items }
        | ProactiveCommand::SelectItem { title, items } => {
            enc.tag_length_value(TAG_ALPHA_ID, title)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
            encode_items(enc, items)?;
        }

        ProactiveCommand::LaunchBrowser { url, browser_id } => {
            enc.tag_length_value(TAG_BROWSER_ID, &[*browser_id])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
            enc.tag_length_value(TAG_URL, url)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::PlayTone {
            tone,
            unit,
            interval,
        } => {
            enc.tag_length_value(TAG_TONE, &[*tone])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
            enc.tag_length_value(TAG_DURATION, &[unit.to_byte(), *interval])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::SendSms { tpdu } => {
            enc.tag_length_value(TAG_SMS_TPDU, tpdu)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::GetInput { text, coding, min_len, max_len, .. } => {
            encode_text_string(enc, text, *coding)?;
            enc.tag_length_value(TAG_RESPONSE_LENGTH, &[*min_len, *max_len])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::MoreTime
        | ProactiveCommand::PollingOff
        | ProactiveCommand::ProvideLocalInformation { .. }
        | ProactiveCommand::SendSs { .. }
        | ProactiveCommand::GeographicalLocationRequest
        | ProactiveCommand::PerformCardApdu { .. }
        | ProactiveCommand::PowerOnCard { .. }
        | ProactiveCommand::PowerOffCard { .. }
        | ProactiveCommand::GetReaderStatus { .. }
        | ProactiveCommand::RunAtCommand
        | ProactiveCommand::CloseChannel { .. }
        | ProactiveCommand::ReceiveData { .. }
        | ProactiveCommand::SendDataCmd { .. }
        | ProactiveCommand::GetChannelStatus
        | ProactiveCommand::ServiceSearch
        | ProactiveCommand::GetServiceInformation
        | ProactiveCommand::DeclareService { .. }
        | ProactiveCommand::SetFrames
        | ProactiveCommand::GetFramesStatus
        | ProactiveCommand::RetrieveMultimediaMessage
        | ProactiveCommand::SubmitMultimediaMessage
        | ProactiveCommand::DisplayMultimediaMessage
        | ProactiveCommand::Activate { .. }
        | ProactiveCommand::ContactlessStateChanged
        | ProactiveCommand::CommandContainer
        | ProactiveCommand::EncapsulatedSessionControl
        | ProactiveCommand::LsiCommand
        | ProactiveCommand::EndOfProactiveUiccSession => {
            // Header-only commands: no payload TLVs.
        }

        ProactiveCommand::PollInterval { unit, interval } => {
            // Duration TLV: 84 02 [unit] [interval]
            enc.tag_length_value(TAG_DURATION, &[unit.to_byte(), *interval])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::Refresh { file_list, .. } => {
            if !file_list.is_empty() {
                enc.tag_length_value(TAG_FILE_LIST, file_list)
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
        }

        ProactiveCommand::SetUpEventList { events } => {
            enc.tag_length_value(TAG_EVENT_LIST, events)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::SetUpCall { alpha_id, address, .. } => {
            if !alpha_id.is_empty() {
                enc.tag_length_value(TAG_ALPHA_ID, alpha_id)
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
            enc.tag_length_value(TAG_ADDRESS, address)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::SendUssd { ussd_string } => {
            enc.tag_length_value(TAG_USSD_STRING, ussd_string)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::SendDtmf { dtmf } => {
            enc.tag_length_value(TAG_DTMF_STRING, dtmf)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
        }

        ProactiveCommand::TimerManagement { timer_id, timer_value, .. } => {
            enc.tag_length_value(TAG_TIMER_ID, &[*timer_id])
                .map_err(|_| ProactiveError::BufferTooSmall)?;
            if let Some(tv) = timer_value {
                enc.tag_length_value(TAG_TIMER_VALUE, tv)
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
        }

        ProactiveCommand::LanguageNotification { language, .. } => {
            if let Some(lang) = language {
                enc.tag_length_value(TAG_LANGUAGE, lang)
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
        }

        ProactiveCommand::OpenChannel {
            bearer,
            buffer_size,
            alpha_id,
            transport_level,
            destination_address,
            ..
        } => {
            // Mandatory: Bearer Description (tag 0xB5).
            enc.tag_length_value(TAG_BEARER_DESCRIPTION, bearer)
                .map_err(|_| ProactiveError::BufferTooSmall)?;
            // Mandatory: Buffer Size (tag 0xB9, 2 bytes big-endian).
            enc.tag_length_value(TAG_BUFFER_SIZE, &buffer_size.to_be_bytes())
                .map_err(|_| ProactiveError::BufferTooSmall)?;
            // Optional: Alpha Identifier.
            if !alpha_id.is_empty() {
                enc.tag_length_value(TAG_ALPHA_ID, alpha_id)
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
            // Optional: Transport Level.
            if !transport_level.is_empty() {
                enc.tag_length_value(TAG_TRANSPORT_LEVEL, transport_level)
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
            // Optional: Data Destination Address.
            if !destination_address.is_empty() {
                enc.tag_length_value(TAG_OTHER_ADDRESS, destination_address)
                    .map_err(|_| ProactiveError::BufferTooSmall)?;
            }
        }
    }

    Ok(())
}

impl ProactiveCommand<'_> {
    /// Command type byte, qualifier, and destination device.
    const fn header_fields(&self) -> (u8, u8, u8) {
        match self {
            Self::DisplayText { high_priority, .. } => {
                // Per TS 102 223 clause 8.6 (DISPLAY TEXT qualifier):
                // bit 0: 1 = high priority (display immediately)
                // bit 7: 1 = wait for user to clear, 0 = clear after delay
                let qual = if *high_priority { 0x01 } else { 0x00 };
                (CMD_TYPE_DISPLAY_TEXT, qual, DEV_DISPLAY)
            }
            Self::SetUpMenu { .. } => (CMD_TYPE_SET_UP_MENU, 0x00, DEV_TERMINAL),
            Self::LaunchBrowser { .. } => (CMD_TYPE_LAUNCH_BROWSER, 0x00, DEV_TERMINAL),
            Self::PlayTone { .. } => (CMD_TYPE_PLAY_TONE, 0x00, DEV_EARPIECE),
            Self::SendSms { .. } => (CMD_TYPE_SEND_SMS, 0x00, DEV_NETWORK),
            Self::GetInkey { digits_only, .. } => {
                // Per TS 102 223 clause 8.6 (GET INKEY qualifier):
                // bit 0: 0 = digits (0-9, *, #, +) only
                //         1 = SMS default alphabet set
                let qual = if *digits_only { 0x00 } else { 0x01 };
                (CMD_TYPE_GET_INKEY, qual, DEV_TERMINAL)
            }
            Self::GetInput { digits_only, .. } => {
                // Per TS 102 223 clause 8.6 (GET INPUT qualifier):
                // bit 0: 0 = digits (0-9, *, #, +) only
                //         1 = SMS default alphabet set
                let qual = if *digits_only { 0x00 } else { 0x01 };
                (CMD_TYPE_GET_INPUT, qual, DEV_TERMINAL)
            }
            Self::SelectItem { .. } => (CMD_TYPE_SELECT_ITEM, 0x00, DEV_TERMINAL),
            Self::SetUpIdleModeText { .. } => (CMD_TYPE_SETUP_IDLE_TEXT, 0x00, DEV_TERMINAL),
            Self::Refresh { qualifier, .. } => (CMD_TYPE_REFRESH, *qualifier, DEV_UICC),
            Self::MoreTime => (CMD_TYPE_MORE_TIME, 0x00, DEV_TERMINAL),
            Self::PollInterval { .. } => (CMD_TYPE_POLL_INTERVAL, 0x00, DEV_TERMINAL),
            Self::PollingOff => (CMD_TYPE_POLLING_OFF, 0x00, DEV_TERMINAL),
            Self::SetUpEventList { .. } => (CMD_TYPE_SET_UP_EVENT_LIST, 0x00, DEV_TERMINAL),
            Self::SetUpCall { qualifier, .. } => (CMD_TYPE_SET_UP_CALL, *qualifier, DEV_NETWORK),
            Self::SendUssd { .. } => (CMD_TYPE_SEND_USSD, 0x00, DEV_NETWORK),
            Self::SendDtmf { .. } => (CMD_TYPE_SEND_DTMF, 0x00, DEV_NETWORK),
            Self::ProvideLocalInformation { qualifier } => (CMD_TYPE_PROVIDE_LOCAL_INFO, *qualifier, DEV_TERMINAL),
            Self::TimerManagement { qualifier, .. } => (CMD_TYPE_TIMER_MANAGEMENT, *qualifier, DEV_TERMINAL),
            Self::LanguageNotification { specific, .. } => {
                let qual = if *specific { 0x01 } else { 0x00 };
                (CMD_TYPE_LANGUAGE_NOTIFICATION, qual, DEV_TERMINAL)
            }
            Self::SendSs { qualifier } => (CMD_TYPE_SEND_SS, *qualifier, DEV_NETWORK),
            Self::GeographicalLocationRequest => (CMD_TYPE_GEO_LOCATION_REQUEST, 0x00, DEV_TERMINAL),
            Self::PerformCardApdu { qualifier } => (CMD_TYPE_PERFORM_CARD_APDU, *qualifier, DEV_TERMINAL),
            Self::PowerOnCard { qualifier } => (CMD_TYPE_POWER_ON_CARD, *qualifier, DEV_TERMINAL),
            Self::PowerOffCard { qualifier } => (CMD_TYPE_POWER_OFF_CARD, *qualifier, DEV_TERMINAL),
            Self::GetReaderStatus { qualifier } => (CMD_TYPE_GET_READER_STATUS, *qualifier, DEV_TERMINAL),
            Self::RunAtCommand => (CMD_TYPE_RUN_AT_COMMAND, 0x00, DEV_TERMINAL),
            Self::OpenChannel { qualifier, .. } => (CMD_TYPE_OPEN_CHANNEL, *qualifier, DEV_TERMINAL),
            Self::CloseChannel { qualifier } => (CMD_TYPE_CLOSE_CHANNEL, *qualifier, DEV_TERMINAL),
            Self::ReceiveData { qualifier } => (CMD_TYPE_RECEIVE_DATA, *qualifier, DEV_TERMINAL),
            Self::SendDataCmd { qualifier } => (CMD_TYPE_SEND_DATA, *qualifier, DEV_TERMINAL),
            Self::GetChannelStatus => (CMD_TYPE_GET_CHANNEL_STATUS, 0x00, DEV_TERMINAL),
            Self::ServiceSearch => (CMD_TYPE_SERVICE_SEARCH, 0x00, DEV_TERMINAL),
            Self::GetServiceInformation => (CMD_TYPE_GET_SERVICE_INFO, 0x00, DEV_TERMINAL),
            Self::DeclareService { qualifier } => (CMD_TYPE_DECLARE_SERVICE, *qualifier, DEV_TERMINAL),
            Self::SetFrames => (CMD_TYPE_SET_FRAMES, 0x00, DEV_TERMINAL),
            Self::GetFramesStatus => (CMD_TYPE_GET_FRAMES_STATUS, 0x00, DEV_TERMINAL),
            Self::RetrieveMultimediaMessage => (CMD_TYPE_RETRIEVE_MMS, 0x00, DEV_TERMINAL),
            Self::SubmitMultimediaMessage => (CMD_TYPE_SUBMIT_MMS, 0x00, DEV_TERMINAL),
            Self::DisplayMultimediaMessage => (CMD_TYPE_DISPLAY_MMS, 0x00, DEV_TERMINAL),
            Self::Activate { qualifier } => (CMD_TYPE_ACTIVATE, *qualifier, DEV_TERMINAL),
            Self::ContactlessStateChanged => (CMD_TYPE_CONTACTLESS_STATE_CHANGED, 0x00, DEV_TERMINAL),
            Self::CommandContainer => (CMD_TYPE_COMMAND_CONTAINER, 0x00, DEV_TERMINAL),
            Self::EncapsulatedSessionControl => (CMD_TYPE_ENCAP_SESSION_CTRL, 0x00, DEV_TERMINAL),
            Self::LsiCommand => (CMD_TYPE_LSI_COMMAND, 0x00, DEV_TERMINAL),
            Self::EndOfProactiveUiccSession => (CMD_TYPE_END_PROACTIVE_SESSION, 0x00, DEV_TERMINAL),
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
    pub(crate) fn put_u32_le(&mut self, v: u32) {
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
    pub(crate) fn get_u32_le(&mut self) -> u32 {
        let b = [
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ];
        self.pos += 4;
        u32::from_le_bytes(b)
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
    /// Envelope event tag (0 = none, 0xD3 = menu selection, 0xD6 = event download).
    event_tag: u8,
    /// Envelope event item identifier (for Menu Selection).
    event_item_id: u8,
    /// Terminal profile data (up to 32 bytes).
    profile: [u8; 32],
    /// Actual length of stored terminal profile.
    profile_len: u8,
    /// Event type byte from Event Download envelope.
    event_type: u8,
    /// Timer ID from Timer Expiry event download (1-8, 0 = none).
    event_timer_id: u8,
    /// BCD timer value from Timer Expiry event download [HH, MM, SS].
    event_timer_value: [u8; 3],
    /// Bitmask of subscribed event IDs (bits 0..31).
    /// Set via SET UP EVENT LIST proactive command.
    subscribed_events: u32,
    /// 8 concurrent timers (IDs 1-8, indexed 0-7).
    /// Per ETSI TS 102 223 clause 6.6.21.
    timers: [TimerSlot; 8],
    /// Bitmask of expired timer IDs (bits 0-7 for timers 1-8).
    expired_timers: u8,
    /// 7 BIP channel slots (IDs 1-7, indexed 0-6).
    /// Per ETSI TS 102 223 clause 6.6.27.
    channels: [ChannelSlot; 7],
    /// General result byte from the most recent TERMINAL RESPONSE.
    /// 0xFF means no response received yet.
    last_result: u8,
}

// ---------------------------------------------------------------------------
// Timer slot
// ---------------------------------------------------------------------------

/// A single timer slot (1 of 8).
///
/// Per ETSI TS 102 223 clause 6.6.21, the UICC can manage up to 8
/// concurrent timers. Each timer counts down in seconds.
#[derive(Clone, Copy)]
struct TimerSlot {
    /// Whether this timer is actively counting down.
    active: bool,
    /// Remaining time in seconds.
    remaining_secs: u32,
}

impl TimerSlot {
    const fn new() -> Self {
        Self {
            active: false,
            remaining_secs: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BIP channel slot
// ---------------------------------------------------------------------------

/// A single BIP channel slot.
///
/// Per ETSI TS 102 223 clause 6.6.27, the terminal can manage up to 7
/// Bearer Independent Protocol channels (IDs 1-7).
#[derive(Clone, Copy)]
struct ChannelSlot {
    /// Whether this channel is open.
    open: bool,
    /// Bearer type byte (0 = not set).
    bearer_type: u8,
    /// Buffer size negotiated at OPEN CHANNEL.
    buffer_size: u16,
}

impl ChannelSlot {
    const fn new() -> Self {
        Self {
            open: false,
            bearer_type: 0,
            buffer_size: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BCD time helpers
// ---------------------------------------------------------------------------

/// Decode a single BCD byte to its decimal value.
///
/// BCD format: high nibble is tens, low nibble is units.
const fn bcd_byte_to_dec(b: u8) -> u8 {
    (b >> 4) * 10 + (b & 0x0F)
}

/// Encode a decimal value (0-99) as BCD.
const fn dec_to_bcd_byte(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

/// Convert BCD timer value [HH, MM, SS] to total seconds.
///
/// Per ETSI TS 102 223 clause 8.39.
const fn bcd_to_seconds(bcd: [u8; 3]) -> u32 {
    let hours = bcd_byte_to_dec(bcd[0]) as u32;
    let minutes = bcd_byte_to_dec(bcd[1]) as u32;
    let seconds = bcd_byte_to_dec(bcd[2]) as u32;
    hours * 3600 + minutes * 60 + seconds
}

/// Convert total seconds to BCD timer value [HH, MM, SS].
///
/// Clamps to 23:59:59 (86399 seconds).
#[allow(clippy::cast_possible_truncation)]
const fn seconds_to_bcd(total: u32) -> [u8; 3] {
    let clamped = if total > 86399 { 86399 } else { total };
    let hours = (clamped / 3600) as u8;
    let minutes = ((clamped % 3600) / 60) as u8;
    let seconds = (clamped % 60) as u8;
    [dec_to_bcd_byte(hours), dec_to_bcd_byte(minutes), dec_to_bcd_byte(seconds)]
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
            event_tag: 0,
            event_item_id: 0,
            profile: [0u8; 32],
            profile_len: 0,
            event_type: 0,
            event_timer_id: 0,
            event_timer_value: [0; 3],
            subscribed_events: 0,
            timers: [TimerSlot::new(); 8],
            expired_timers: 0,
            channels: [ChannelSlot::new(); 7],
            last_result: 0xFF,
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
        // Keep subscription state consistent with SET UP EVENT LIST.
        if let ProactiveCommand::SetUpEventList { events } = cmd {
            self.subscribe_events(events);
        }
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
    /// Parses the BER-TLV data to extract Command Details (tag `0x81`)
    /// and Result (tag `0x83`). Stores the general result byte for
    /// later retrieval via [`last_terminal_result`](Self::last_terminal_result).
    ///
    /// Returns `Some(TerminalResult)` on successful parse, `None` if
    /// the data is malformed or missing required TLVs.
    pub fn terminal_response(&mut self, data: &[u8]) -> Option<TerminalResult> {
        let mut cmd_number: u8 = 0;
        let mut cmd_type: u8 = 0;
        let mut general_result: Option<u8> = None;
        let mut found_cmd_details = false;

        let mut dec = Decoder::new(data);
        while let Some(Ok(tlv)) = dec.next() {
            match tlv.tag {
                TAG_CMD_DETAILS if tlv.value.len() >= 3 => {
                    cmd_number = tlv.value[0];
                    cmd_type = tlv.value[1];
                    // tlv.value[2] is cmd_qualifier (not stored)
                    found_cmd_details = true;
                }
                TAG_RESULT if !tlv.value.is_empty() => {
                    general_result = Some(tlv.value[0]);
                }
                _ => {} // skip unknown TLVs
            }
        }

        if let Some(result) = general_result {
            self.last_result = result;
            if found_cmd_details {
                return Some(TerminalResult {
                    cmd_number,
                    cmd_type,
                    general_result: result,
                });
            }
        }
        None
    }

    /// Return the general result byte from the most recent TERMINAL RESPONSE.
    ///
    /// Returns `0xFF` if no TERMINAL RESPONSE has been received yet.
    #[must_use]
    pub const fn last_terminal_result(&self) -> u8 {
        self.last_result
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

    // -- ENVELOPE processing --

    /// Process an ENVELOPE command's BER-TLV data.
    ///
    /// Parses the outer tag to identify the envelope type, then extracts
    /// relevant inner TLVs. Supports:
    /// - Menu Selection (tag D3, TS 102 223 clause 7.1)
    /// - Event Download (tag D6, TS 102 223 clause 7.5)
    ///
    /// For Event Download, the event must be in the subscribed set
    /// (see [`subscribe_events`](Self::subscribe_events)).
    ///
    /// Returns `true` if the envelope was recognized and accepted.
    pub fn process_envelope(&mut self, data: &[u8]) -> bool {
        let mut outer = Decoder::new(data);
        let Some(Ok(tlv)) = outer.next() else {
            return false;
        };

        if tlv.tag == TAG_MENU_SELECTION {
            // Parse inner TLVs to find Item Identifier (tag 0x90).
            let mut inner = Decoder::new(tlv.value);
            while let Some(Ok(inner_tlv)) = inner.next() {
                if inner_tlv.tag == TAG_ITEM_ID && !inner_tlv.value.is_empty() {
                    self.event_tag = TAG_MENU_SELECTION;
                    self.event_item_id = inner_tlv.value[0];
                    return true;
                }
            }
            // Menu Selection without Item Identifier -- still recognized.
            self.event_tag = TAG_MENU_SELECTION;
            self.event_item_id = 0;
            return true;
        }

        if tlv.tag == TAG_EVENT_DOWNLOAD {
            return self.process_event_download(tlv.value);
        }

        false
    }

    /// Parse Event Download (D6) inner TLVs.
    ///
    /// Per TS 102 223 clause 7.5, the inner TLVs include:
    /// - Event List (tag 0x99): single event type byte
    /// - Timer Identifier (tag 0xA4): for Timer Expiry events
    /// - Timer Value (tag 0xA5): for Timer Expiry events
    fn process_event_download(&mut self, value: &[u8]) -> bool {
        let mut inner = Decoder::new(value);
        let mut found_event = false;
        let mut evt_type: u8 = 0;
        let mut tmr_id: u8 = 0;
        let mut tmr_val: [u8; 3] = [0; 3];

        while let Some(Ok(inner_tlv)) = inner.next() {
            match inner_tlv.tag {
                TAG_EVENT_LIST if !inner_tlv.value.is_empty() => {
                    evt_type = inner_tlv.value[0];
                    found_event = true;
                }
                TAG_TIMER_ID if !inner_tlv.value.is_empty() => {
                    tmr_id = inner_tlv.value[0];
                }
                TAG_TIMER_VALUE if inner_tlv.value.len() >= 3 => {
                    tmr_val[0] = inner_tlv.value[0];
                    tmr_val[1] = inner_tlv.value[1];
                    tmr_val[2] = inner_tlv.value[2];
                }
                _ => {}
            }
        }

        if !found_event {
            return false;
        }

        // Reject if event is not in the subscribed set.
        if !self.is_event_subscribed(evt_type) {
            return false;
        }

        self.event_tag = TAG_EVENT_DOWNLOAD;
        self.event_type = evt_type;
        self.event_timer_id = tmr_id;
        self.event_timer_value = tmr_val;
        true
    }

    /// Retrieve the last envelope event, clearing it.
    pub const fn take_event(&mut self) -> Option<EnvelopeEvent> {
        if self.event_tag == TAG_MENU_SELECTION {
            let item_id = self.event_item_id;
            self.event_tag = 0;
            self.event_item_id = 0;
            Some(EnvelopeEvent::MenuSelection { item_id })
        } else if self.event_tag == TAG_EVENT_DOWNLOAD {
            let event = EnvelopeEvent::EventDownload {
                event_type: self.event_type,
                timer_id: self.event_timer_id,
                timer_value: self.event_timer_value,
            };
            self.event_tag = 0;
            self.event_type = 0;
            self.event_timer_id = 0;
            self.event_timer_value = [0; 3];
            Some(event)
        } else {
            None
        }
    }

    // -- Event subscription --

    /// Subscribe to a set of event IDs.
    ///
    /// Per ETSI TS 102 223 clause 8.25. Replaces any existing subscriptions.
    /// Each byte in `events` is an event ID (0-31). IDs >= 32 are ignored.
    pub fn subscribe_events(&mut self, events: &[u8]) {
        self.subscribed_events = 0;
        for &ev in events {
            if ev < 32 {
                self.subscribed_events |= 1 << ev;
            }
        }
    }

    /// Check if a specific event type is in the subscribed set.
    pub const fn is_event_subscribed(&self, event_type: u8) -> bool {
        if event_type >= 32 {
            return false;
        }
        self.subscribed_events & (1 << event_type) != 0
    }

    /// Clear all event subscriptions.
    pub const fn clear_event_subscriptions(&mut self) {
        self.subscribed_events = 0;
    }

    // -- Timer management --

    /// Start a timer.
    ///
    /// `timer_id` must be 1-8 (per TS 102 223 clause 6.6.21).
    /// `timer_value` is BCD-encoded [hours, minutes, seconds].
    ///
    /// Returns `true` on success, `false` for invalid `timer_id`.
    pub const fn start_timer(&mut self, timer_id: u8, timer_value: [u8; 3]) -> bool {
        if timer_id == 0 || timer_id > 8 {
            return false;
        }
        let idx = (timer_id - 1) as usize;
        self.timers[idx].active = true;
        self.timers[idx].remaining_secs = bcd_to_seconds(timer_value);
        true
    }

    /// Deactivate a timer and return its remaining value as BCD.
    ///
    /// Returns `None` for invalid `timer_id` or inactive timer.
    pub const fn deactivate_timer(&mut self, timer_id: u8) -> Option<[u8; 3]> {
        if timer_id == 0 || timer_id > 8 {
            return None;
        }
        let idx = (timer_id - 1) as usize;
        if !self.timers[idx].active {
            return None;
        }
        let remaining = self.timers[idx].remaining_secs;
        self.timers[idx].active = false;
        self.timers[idx].remaining_secs = 0;
        Some(seconds_to_bcd(remaining))
    }

    /// Get current timer value without stopping it.
    ///
    /// Returns BCD [hours, minutes, seconds], or `None` for invalid/inactive.
    pub const fn get_timer_value(&self, timer_id: u8) -> Option<[u8; 3]> {
        if timer_id == 0 || timer_id > 8 {
            return None;
        }
        let idx = (timer_id - 1) as usize;
        if !self.timers[idx].active {
            return None;
        }
        Some(seconds_to_bcd(self.timers[idx].remaining_secs))
    }

    /// Advance all active timers by `elapsed_secs`.
    ///
    /// Returns the number of timers that expired during this tick.
    /// Expired timers are deactivated and their IDs stored for retrieval
    /// via [`take_expired_timer`](Self::take_expired_timer).
    pub const fn tick(&mut self, elapsed_secs: u32) -> u8 {
        let mut count = 0u8;
        let mut i = 0;
        while i < 8 {
            if self.timers[i].active {
                if self.timers[i].remaining_secs <= elapsed_secs {
                    self.timers[i].active = false;
                    self.timers[i].remaining_secs = 0;
                    self.expired_timers |= 1 << i;
                    count += 1;
                } else {
                    self.timers[i].remaining_secs -= elapsed_secs;
                }
            }
            i += 1;
        }
        count
    }

    /// Take the next expired timer ID (1-8), or 0 if none.
    ///
    /// The caller should generate a Timer Expiry Event Download envelope
    /// for each expired timer returned.
    pub const fn take_expired_timer(&mut self) -> u8 {
        if self.expired_timers == 0 {
            return 0;
        }
        // Find lowest set bit.
        let bit = self.expired_timers.trailing_zeros();
        self.expired_timers &= !(1 << bit);
        #[allow(clippy::cast_possible_truncation)]
        { (bit as u8) + 1 }
    }

    // -- Terminal profile --

    /// Store terminal profile data.
    ///
    /// Per ETSI TS 102 221 clause 11.2.1, the terminal sends its capability
    /// profile at power-up. Up to 32 bytes are stored; excess is truncated.
    #[allow(clippy::cast_possible_truncation)] // len capped at 32
    pub fn set_terminal_profile(&mut self, data: &[u8]) {
        let len = data.len().min(32);
        self.profile[..len].copy_from_slice(&data[..len]);
        // Zero out any previously stored bytes beyond the new length.
        self.profile[len..].fill(0);
        self.profile_len = len as u8;
    }

    /// Check if a specific terminal capability is supported.
    ///
    /// Byte and bit positions are per ETSI TS 102 223 Annex A.
    /// Returns `false` if the byte index is beyond the stored profile.
    pub const fn terminal_supports(&self, byte: usize, bit: u8) -> bool {
        if byte >= self.profile_len as usize || bit > 7 {
            return false;
        }
        self.profile[byte] & (1 << bit) != 0
    }

    // -- BIP channel management -----------------------------------------------

    /// Open a BIP channel.
    ///
    /// `id` is the channel identifier (1-7). Returns `true` if the channel was
    /// successfully opened (valid ID and not already open).
    pub const fn open_channel(&mut self, id: u8, bearer_type: u8, buffer_size: u16) -> bool {
        if id == 0 || id > 7 {
            return false;
        }
        let slot = &mut self.channels[(id - 1) as usize];
        if slot.open {
            return false;
        }
        slot.open = true;
        slot.bearer_type = bearer_type;
        slot.buffer_size = buffer_size;
        true
    }

    /// Close a BIP channel.
    ///
    /// `id` is the channel identifier (1-7). Returns `true` if the channel was
    /// successfully closed (valid ID and currently open).
    pub const fn close_channel(&mut self, id: u8) -> bool {
        if id == 0 || id > 7 {
            return false;
        }
        let slot = &mut self.channels[(id - 1) as usize];
        if !slot.open {
            return false;
        }
        slot.open = false;
        slot.bearer_type = 0;
        slot.buffer_size = 0;
        true
    }

    /// Check whether a BIP channel is open.
    ///
    /// Returns `false` for out-of-range IDs.
    #[must_use]
    pub const fn is_channel_open(&self, id: u8) -> bool {
        if id == 0 || id > 7 {
            return false;
        }
        self.channels[(id - 1) as usize].open
    }

    /// Return a bitmask of open channel IDs (bit 0 = channel 1, ..., bit 6 = channel 7).
    #[must_use]
    pub const fn channel_status_bitmask(&self) -> u8 {
        let mut mask: u8 = 0;
        let mut i: usize = 0;
        while i < 7 {
            if self.channels[i].open {
                mask |= 1 << i;
            }
            i += 1;
        }
        mask
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes.
    ///
    /// Layout: `buf`(256) + `len`(2 LE) + `seq`(1) + `event_tag`(1)
    /// + `event_item_id`(1) + `profile`(32) + `profile_len`(1)
    /// + `event_type`(1) + `event_timer_id`(1) + `event_timer_value`(3)
    /// + `subscribed_events`(4) + `timers`(8 x 5 = 40)
    /// + `expired_timers`(1) + `channels`(7 x 4 = 28) + `last_result`(1) = 373.
    pub const SNAPSHOT_SIZE: usize = 256 + 2 + 1 + 1 + 1 + 32 + 1 + 1 + 1 + 3 + 4 + 40 + 1 + 28 + 1;

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
        w.put_u8(self.event_tag);
        w.put_u8(self.event_item_id);
        w.put_bytes(&self.profile);
        w.put_u8(self.profile_len);
        w.put_u8(self.event_type);
        w.put_u8(self.event_timer_id);
        w.put_bytes(&self.event_timer_value);
        w.put_u32_le(self.subscribed_events);
        // Timers: 8 slots x (1 byte active + 4 bytes remaining_secs LE) = 40 bytes.
        let mut i = 0;
        while i < 8 {
            w.put_u8(u8::from(self.timers[i].active));
            w.put_u32_le(self.timers[i].remaining_secs);
            i += 1;
        }
        w.put_u8(self.expired_timers);
        // BIP channels: 7 slots x (1 byte open + 1 byte bearer_type + 2 bytes buffer_size LE) = 28 bytes.
        let mut j = 0;
        while j < 7 {
            w.put_u8(u8::from(self.channels[j].open));
            w.put_u8(self.channels[j].bearer_type);
            w.put_u16_le(self.channels[j].buffer_size);
            j += 1;
        }
        w.put_u8(self.last_result);
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
        self.event_tag = r.get_u8();
        self.event_item_id = r.get_u8();
        r.get_bytes(&mut self.profile);
        self.profile_len = r.get_u8();
        self.event_type = r.get_u8();
        self.event_timer_id = r.get_u8();
        r.get_bytes(&mut self.event_timer_value);
        self.subscribed_events = r.get_u32_le();
        // Timers: 8 slots.
        let mut i = 0;
        while i < 8 {
            self.timers[i].active = r.get_u8() != 0;
            self.timers[i].remaining_secs = r.get_u32_le();
            i += 1;
        }
        self.expired_timers = r.get_u8();
        // BIP channels: 7 slots.
        let mut j = 0;
        while j < 7 {
            self.channels[j].open = r.get_u8() != 0;
            self.channels[j].bearer_type = r.get_u8();
            self.channels[j].buffer_size = r.get_u16_le();
            j += 1;
        }
        self.last_result = r.get_u8();
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
        if inner_len <= BER_SHORT_FORM_MAX {
            #[allow(clippy::cast_possible_truncation)]
            self.raw(&[inner_len as u8])?;
        } else if inner_len <= 0xFF {
            #[allow(clippy::cast_possible_truncation)]
            self.raw(&[BER_LONG_FORM_1, inner_len as u8])?;
        } else {
            #[allow(clippy::cast_possible_truncation)]
            self.raw(&[BER_LONG_FORM_2, (inner_len >> 8) as u8, inner_len as u8])?;
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
    extern crate alloc;
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
        assert_eq!(cmd_details.value[2], 0x00); // qualifier: normal priority
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
    fn display_text_high_priority_qualifier() {
        let cmd = ProactiveCommand::DisplayText {
            text: b"Urgent",
            coding: TextCoding::Gsm8Bit,
            high_priority: true,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);
        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_DISPLAY_TEXT);
        assert_eq!(cd.value[2], 0x01); // qualifier: high priority
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

    // -- GET INKEY tests --

    #[test]
    fn get_inkey_encoding() {
        let cmd = ProactiveCommand::GetInkey {
            text: b"Press a key",
            coding: TextCoding::Gsm8Bit,
            digits_only: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_GET_INKEY);
        assert_eq!(cd.value[2], 0x01); // alphabet set (not digits only)

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_TERMINAL);

        let text = inner.next().unwrap().unwrap();
        assert_eq!(text.tag, TAG_TEXT_STRING);
        assert_eq!(text.value[0], 0x04); // GSM 8-bit
        assert_eq!(&text.value[1..], b"Press a key");
    }

    #[test]
    fn get_inkey_digits_only() {
        let cmd = ProactiveCommand::GetInkey {
            text: b"Enter digit",
            coding: TextCoding::Gsm8Bit,
            digits_only: true,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);
        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[2], 0x00); // digits only
    }

    // -- GET INPUT tests --

    #[test]
    fn get_input_encoding() {
        let cmd = ProactiveCommand::GetInput {
            text: b"Enter name",
            coding: TextCoding::Gsm8Bit,
            min_len: 1,
            max_len: 20,
            digits_only: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_GET_INPUT);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_TERMINAL);

        let text = inner.next().unwrap().unwrap();
        assert_eq!(text.tag, TAG_TEXT_STRING);
        assert_eq!(&text.value[1..], b"Enter name");

        let resp_len = inner.next().unwrap().unwrap();
        assert_eq!(resp_len.tag, TAG_RESPONSE_LENGTH);
        assert_eq!(resp_len.value, &[1, 20]); // min=1, max=20
    }

    // -- SELECT ITEM tests --

    #[test]
    fn select_item_encoding() {
        let items = [
            MenuItem { id: 1, text: b"First" },
            MenuItem { id: 2, text: b"Second" },
        ];
        let cmd = ProactiveCommand::SelectItem {
            title: b"Choose",
            items: &items,
        };
        let mut buf = [0u8; 128];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SELECT_ITEM);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_TERMINAL);

        let alpha = inner.next().unwrap().unwrap();
        assert_eq!(alpha.tag, TAG_ALPHA_ID);
        assert_eq!(alpha.value, b"Choose");

        let item1 = inner.next().unwrap().unwrap();
        assert_eq!(item1.tag, TAG_ITEM);
        assert_eq!(item1.value[0], 1);
        assert_eq!(&item1.value[1..], b"First");

        let item2 = inner.next().unwrap().unwrap();
        assert_eq!(item2.tag, TAG_ITEM);
        assert_eq!(item2.value[0], 2);
        assert_eq!(&item2.value[1..], b"Second");
    }

    // -- SET UP IDLE MODE TEXT tests --

    #[test]
    fn setup_idle_text_encoding() {
        let cmd = ProactiveCommand::SetUpIdleModeText {
            text: b"Welcome",
            coding: TextCoding::Gsm8Bit,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SETUP_IDLE_TEXT);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value[1], DEV_TERMINAL);

        let text = inner.next().unwrap().unwrap();
        assert_eq!(text.tag, TAG_TEXT_STRING);
        assert_eq!(&text.value[1..], b"Welcome");
    }

    // -- REFRESH tests --

    #[test]
    fn refresh_encoding() {
        let file_list = [0x3F, 0x00, 0x7F, 0xFF, 0x6F, 0x07];
        let cmd = ProactiveCommand::Refresh {
            qualifier: 0x03,
            file_list: &file_list,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        assert_eq!(envelope.tag, 0xD0);
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.tag, TAG_CMD_DETAILS);
        assert_eq!(cd.value[1], CMD_TYPE_REFRESH);
        assert_eq!(cd.value[2], 0x03); // qualifier passthrough

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.tag, TAG_DEVICE_ID);
        assert_eq!(di.value, &[DEV_UICC, DEV_UICC]); // source=UICC, dest=UICC

        let fl = inner.next().unwrap().unwrap();
        assert_eq!(fl.tag, TAG_FILE_LIST);
        assert_eq!(fl.value, &file_list);

        assert!(inner.next().is_none());
    }

    #[test]
    fn refresh_empty_file_list() {
        let cmd = ProactiveCommand::Refresh {
            qualifier: 0x00,
            file_list: &[],
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_REFRESH);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.tag, TAG_DEVICE_ID);

        // No file list TLV when empty.
        assert!(inner.next().is_none());
    }

    // -- MORE TIME tests --

    #[test]
    fn more_time_encoding() {
        let cmd = ProactiveCommand::MoreTime;
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        assert_eq!(envelope.tag, 0xD0);
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.tag, TAG_CMD_DETAILS);
        assert_eq!(cd.value[1], CMD_TYPE_MORE_TIME);
        assert_eq!(cd.value[2], 0x00);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.tag, TAG_DEVICE_ID);
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        // Header-only: no more TLVs.
        assert!(inner.next().is_none());
    }

    // -- POLL INTERVAL tests --

    #[test]
    fn poll_interval_encoding() {
        let cmd = ProactiveCommand::PollInterval {
            unit: TimeUnit::Seconds,
            interval: 30,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_POLL_INTERVAL);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        let dur = inner.next().unwrap().unwrap();
        assert_eq!(dur.tag, TAG_DURATION);
        assert_eq!(dur.value, &[0x01, 30]); // seconds, 30

        assert!(inner.next().is_none());
    }

    // -- POLLING OFF tests --

    #[test]
    fn polling_off_encoding() {
        let cmd = ProactiveCommand::PollingOff;
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        assert_eq!(envelope.tag, 0xD0);
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_POLLING_OFF);
        assert_eq!(cd.value[2], 0x00);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        // Header-only: no more TLVs.
        assert!(inner.next().is_none());
    }

    // -- SET UP EVENT LIST tests --

    #[test]
    fn set_up_event_list_encoding() {
        let events = [0x05, 0x07]; // MT call + Data available
        let cmd = ProactiveCommand::SetUpEventList { events: &events };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SET_UP_EVENT_LIST);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        let ev = inner.next().unwrap().unwrap();
        assert_eq!(ev.tag, TAG_EVENT_LIST);
        assert_eq!(ev.value, &events);

        assert!(inner.next().is_none());
    }

    // -- SET UP CALL tests --

    #[test]
    fn set_up_call_encoding() {
        let address = [0x91, 0x21, 0x43, 0x65, 0x87]; // TON/NPI + BCD digits
        let alpha = b"Call John?";
        let cmd = ProactiveCommand::SetUpCall {
            address: &address,
            qualifier: 0x00,
            alpha_id: alpha,
        };
        let mut buf = [0u8; 128];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SET_UP_CALL);
        assert_eq!(cd.value[2], 0x00);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_NETWORK]);

        let ai = inner.next().unwrap().unwrap();
        assert_eq!(ai.tag, TAG_ALPHA_ID);
        assert_eq!(ai.value, b"Call John?");

        let addr = inner.next().unwrap().unwrap();
        assert_eq!(addr.tag, TAG_ADDRESS);
        assert_eq!(addr.value, &address);

        assert!(inner.next().is_none());
    }

    // -- SEND USSD tests --

    #[test]
    fn send_ussd_encoding() {
        let ussd = [0x0F, 0x2A, 0x31, 0x30, 0x30, 0x23]; // DCS + *100#
        let cmd = ProactiveCommand::SendUssd { ussd_string: &ussd };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SEND_USSD);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_NETWORK]);

        let us = inner.next().unwrap().unwrap();
        assert_eq!(us.tag, TAG_USSD_STRING);
        assert_eq!(us.value, &ussd);

        assert!(inner.next().is_none());
    }

    // -- SEND DTMF tests --

    #[test]
    fn send_dtmf_encoding() {
        let dtmf = [0x21, 0x43]; // BCD digits 1234
        let cmd = ProactiveCommand::SendDtmf { dtmf: &dtmf };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_SEND_DTMF);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_NETWORK]);

        let df = inner.next().unwrap().unwrap();
        assert_eq!(df.tag, TAG_DTMF_STRING);
        assert_eq!(df.value, &dtmf);

        assert!(inner.next().is_none());
    }

    // -- PROVIDE LOCAL INFORMATION tests --

    #[test]
    fn provide_local_info_encoding() {
        let cmd = ProactiveCommand::ProvideLocalInformation { qualifier: 0x04 };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        assert_eq!(envelope.tag, 0xD0);
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.tag, TAG_CMD_DETAILS);
        assert_eq!(cd.value[1], CMD_TYPE_PROVIDE_LOCAL_INFO);
        assert_eq!(cd.value[2], 0x04); // qualifier passthrough

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        // Header-only: no more TLVs.
        assert!(inner.next().is_none());
    }

    // -- TIMER MANAGEMENT tests --

    #[test]
    fn timer_management_start_encoding() {
        let cmd = ProactiveCommand::TimerManagement {
            timer_id: 0x01,
            qualifier: 0x00,
            timer_value: Some([0x00, 0x30, 0x00]), // 00h 30m 00s BCD
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_TIMER_MANAGEMENT);
        assert_eq!(cd.value[2], 0x00); // start

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        let tid = inner.next().unwrap().unwrap();
        assert_eq!(tid.tag, TAG_TIMER_ID);
        assert_eq!(tid.value, &[0x01]);

        let tv = inner.next().unwrap().unwrap();
        assert_eq!(tv.tag, TAG_TIMER_VALUE);
        assert_eq!(tv.value, &[0x00, 0x30, 0x00]);

        assert!(inner.next().is_none());
    }

    #[test]
    fn timer_management_deactivate_encoding() {
        let cmd = ProactiveCommand::TimerManagement {
            timer_id: 0x03,
            qualifier: 0x01,
            timer_value: None,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_TIMER_MANAGEMENT);
        assert_eq!(cd.value[2], 0x01); // deactivate

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.tag, TAG_DEVICE_ID);

        let tid = inner.next().unwrap().unwrap();
        assert_eq!(tid.tag, TAG_TIMER_ID);
        assert_eq!(tid.value, &[0x03]);

        // No timer value TLV for deactivate.
        assert!(inner.next().is_none());
    }

    // -- LANGUAGE NOTIFICATION tests --

    #[test]
    fn language_notification_specific() {
        let cmd = ProactiveCommand::LanguageNotification {
            specific: true,
            language: Some([b'e', b'n']),
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_LANGUAGE_NOTIFICATION);
        assert_eq!(cd.value[2], 0x01); // specific

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        let lang = inner.next().unwrap().unwrap();
        assert_eq!(lang.tag, TAG_LANGUAGE);
        assert_eq!(lang.value, b"en");

        assert!(inner.next().is_none());
    }

    #[test]
    fn language_notification_nonspecific() {
        let cmd = ProactiveCommand::LanguageNotification {
            specific: false,
            language: None,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_LANGUAGE_NOTIFICATION);
        assert_eq!(cd.value[2], 0x00); // non-specific

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        // No language TLV when non-specific.
        assert!(inner.next().is_none());
    }

    // -- All command types encode without error --

    #[test]
    #[allow(clippy::too_many_lines)]
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
            ProactiveCommand::GetInkey {
                text: b"Key",
                coding: TextCoding::Gsm8Bit,
                digits_only: false,
            },
            ProactiveCommand::GetInput {
                text: b"Input",
                coding: TextCoding::Gsm8Bit,
                min_len: 1,
                max_len: 10,
                digits_only: false,
            },
            ProactiveCommand::SelectItem {
                title: b"Pick",
                items: &items,
            },
            ProactiveCommand::SetUpIdleModeText {
                text: b"Idle",
                coding: TextCoding::Gsm8Bit,
            },
            ProactiveCommand::Refresh {
                qualifier: 0x01,
                file_list: &[0x3F, 0x00],
            },
            ProactiveCommand::MoreTime,
            ProactiveCommand::PollInterval {
                unit: TimeUnit::Seconds,
                interval: 10,
            },
            ProactiveCommand::PollingOff,
            ProactiveCommand::SetUpEventList {
                events: &[0x05],
            },
            ProactiveCommand::SetUpCall {
                address: &[0x91, 0x11],
                qualifier: 0x00,
                alpha_id: b"Call",
            },
            ProactiveCommand::SendUssd {
                ussd_string: &[0x0F, 0x2A],
            },
            ProactiveCommand::SendDtmf {
                dtmf: &[0x12],
            },
            ProactiveCommand::ProvideLocalInformation {
                qualifier: 0x00,
            },
            ProactiveCommand::TimerManagement {
                timer_id: 1,
                qualifier: 0x00,
                timer_value: Some([0x01, 0x00, 0x00]),
            },
            ProactiveCommand::LanguageNotification {
                specific: true,
                language: Some([b'f', b'r']),
            },
            ProactiveCommand::SendSs { qualifier: 0x00 },
            ProactiveCommand::GeographicalLocationRequest,
            ProactiveCommand::PerformCardApdu { qualifier: 0x00 },
            ProactiveCommand::PowerOnCard { qualifier: 0x00 },
            ProactiveCommand::PowerOffCard { qualifier: 0x00 },
            ProactiveCommand::GetReaderStatus { qualifier: 0x00 },
            ProactiveCommand::RunAtCommand,
            ProactiveCommand::OpenChannel {
                bearer: &[0x01],
                buffer_size: 1024,
                alpha_id: &[],
                transport_level: &[],
                destination_address: &[],
                qualifier: 0x00,
            },
            ProactiveCommand::CloseChannel { qualifier: 0x00 },
            ProactiveCommand::ReceiveData { qualifier: 0x00 },
            ProactiveCommand::SendDataCmd { qualifier: 0x00 },
            ProactiveCommand::GetChannelStatus,
            ProactiveCommand::ServiceSearch,
            ProactiveCommand::GetServiceInformation,
            ProactiveCommand::DeclareService { qualifier: 0x00 },
            ProactiveCommand::SetFrames,
            ProactiveCommand::GetFramesStatus,
            ProactiveCommand::RetrieveMultimediaMessage,
            ProactiveCommand::SubmitMultimediaMessage,
            ProactiveCommand::DisplayMultimediaMessage,
            ProactiveCommand::Activate { qualifier: 0x00 },
            ProactiveCommand::ContactlessStateChanged,
            ProactiveCommand::CommandContainer,
            ProactiveCommand::EncapsulatedSessionControl,
            ProactiveCommand::LsiCommand,
            ProactiveCommand::EndOfProactiveUiccSession,
        ];
        for cmd in commands {
            let mut buf = [0u8; 256];
            let len = encode(cmd, 1, &mut buf).unwrap();
            assert!(len > 0);
            assert_eq!(buf[0], 0xD0);
        }
    }

    // -- SNAPSHOT tests --

    #[test]
    fn snapshot_size_correct() {
        assert_eq!(ProactiveState::SNAPSHOT_SIZE, 373);
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
        assert_eq!(state.save_state(&mut snap), ProactiveState::SNAPSHOT_SIZE);

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

    // -- ENVELOPE processing tests --

    /// Build a BER-TLV envelope: outer tag D3 containing item ID (tag 0x90).
    fn build_menu_selection_envelope(item_id: u8) -> ([u8; 32], usize) {
        let mut buf = [0u8; 32];
        let mut enc = Encoder::new(&mut buf);
        // Inner: Item Identifier TLV: tag 0x90, length 1, value = item_id
        let inner = [TAG_ITEM_ID, 0x01, item_id];
        // Outer: Menu Selection envelope: tag D3, length = inner.len()
        enc.tag_length_value(TAG_MENU_SELECTION, &inner).unwrap();
        let len = enc.len();
        (buf, len)
    }

    #[test]
    fn envelope_menu_selection() {
        let mut state = ProactiveState::new();
        let (buf, len) = build_menu_selection_envelope(0x03);
        assert!(state.process_envelope(&buf[..len]));
        let event = state.take_event();
        assert_eq!(
            event,
            Some(EnvelopeEvent::MenuSelection { item_id: 0x03 })
        );
    }

    #[test]
    fn envelope_unknown_tag() {
        let mut state = ProactiveState::new();
        // Construct a TLV with tag 0xE0 (not D3).
        let data = [0xE0, 0x01, 0x00];
        assert!(!state.process_envelope(&data));
        assert_eq!(state.take_event(), None);
    }

    #[test]
    fn envelope_malformed_data() {
        let mut state = ProactiveState::new();
        assert!(!state.process_envelope(&[]));
        assert_eq!(state.take_event(), None);
    }

    #[test]
    fn envelope_take_clears() {
        let mut state = ProactiveState::new();
        let (buf, len) = build_menu_selection_envelope(0x05);
        assert!(state.process_envelope(&buf[..len]));

        // First take returns the event.
        assert!(state.take_event().is_some());
        // Second take returns None.
        assert_eq!(state.take_event(), None);
    }

    // -- Event Download (D6) tests --

    /// Build a BER-TLV Event Download envelope (outer tag D6).
    fn build_event_download_envelope(event_type: u8) -> ([u8; 32], usize) {
        let mut buf = [0u8; 32];
        let mut enc = Encoder::new(&mut buf);
        // Inner: Event List TLV (tag 0x99, length 1, event_type)
        //      + Device Identities TLV (tag 0x82, length 2, terminal->UICC)
        let inner = [
            TAG_EVENT_LIST, 0x01, event_type,
            TAG_DEVICE_ID, 0x02, DEV_TERMINAL, DEV_UICC,
        ];
        enc.tag_length_value(TAG_EVENT_DOWNLOAD, &inner).unwrap();
        let len = enc.len();
        (buf, len)
    }

    /// Build a Timer Expiry Event Download envelope.
    fn build_timer_expiry_envelope(
        timer_id: u8,
        timer_value: [u8; 3],
    ) -> ([u8; 32], usize) {
        let mut buf = [0u8; 32];
        let mut enc = Encoder::new(&mut buf);
        let inner = [
            TAG_EVENT_LIST, 0x01, event_id::TIMER_EXPIRY,
            TAG_DEVICE_ID, 0x02, DEV_TERMINAL, DEV_UICC,
            TAG_TIMER_ID, 0x01, timer_id,
            TAG_TIMER_VALUE, 0x03, timer_value[0], timer_value[1], timer_value[2],
        ];
        enc.tag_length_value(TAG_EVENT_DOWNLOAD, &inner).unwrap();
        let len = enc.len();
        (buf, len)
    }

    #[test]
    fn event_download_location_status() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[event_id::LOCATION_STATUS]);

        let (buf, len) = build_event_download_envelope(event_id::LOCATION_STATUS);
        assert!(state.process_envelope(&buf[..len]));

        let event = state.take_event();
        assert_eq!(
            event,
            Some(EnvelopeEvent::EventDownload {
                event_type: event_id::LOCATION_STATUS,
                timer_id: 0,
                timer_value: [0, 0, 0],
            })
        );
    }

    #[test]
    fn event_download_timer_expiry() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[event_id::TIMER_EXPIRY]);

        let timer_val = [0x01, 0x30, 0x00]; // 01h 30m 00s BCD
        let (buf, len) = build_timer_expiry_envelope(0x03, timer_val);
        assert!(state.process_envelope(&buf[..len]));

        let event = state.take_event();
        assert_eq!(
            event,
            Some(EnvelopeEvent::EventDownload {
                event_type: event_id::TIMER_EXPIRY,
                timer_id: 0x03,
                timer_value: timer_val,
            })
        );
    }

    #[test]
    fn event_download_unsubscribed_rejected() {
        let mut state = ProactiveState::new();
        // Do not subscribe to LOCATION_STATUS.
        let (buf, len) = build_event_download_envelope(event_id::LOCATION_STATUS);
        assert!(!state.process_envelope(&buf[..len]));
        assert_eq!(state.take_event(), None);
    }

    #[test]
    fn event_download_malformed_no_event_list() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[0x03]);
        // D6 envelope with no Event List TLV inside.
        let data = [TAG_EVENT_DOWNLOAD, 0x04, TAG_DEVICE_ID, 0x02, DEV_TERMINAL, DEV_UICC];
        assert!(!state.process_envelope(&data));
    }

    #[test]
    fn event_download_take_clears() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[event_id::USER_ACTIVITY]);
        let (buf, len) = build_event_download_envelope(event_id::USER_ACTIVITY);
        state.process_envelope(&buf[..len]);
        assert!(state.take_event().is_some());
        assert_eq!(state.take_event(), None);
    }

    // -- Event subscription tests --

    #[test]
    fn subscribe_events_bitmask() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[
            event_id::LOCATION_STATUS,
            event_id::IDLE_SCREEN_AVAILABLE,
            event_id::TIMER_EXPIRY,
        ]);
        assert!(state.is_event_subscribed(event_id::LOCATION_STATUS));
        assert!(state.is_event_subscribed(event_id::IDLE_SCREEN_AVAILABLE));
        assert!(state.is_event_subscribed(event_id::TIMER_EXPIRY));
        assert!(!state.is_event_subscribed(event_id::MT_CALL));
        assert!(!state.is_event_subscribed(event_id::USER_ACTIVITY));
    }

    #[test]
    fn subscribe_replaces_previous() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[event_id::MT_CALL, event_id::LOCATION_STATUS]);
        assert!(state.is_event_subscribed(event_id::MT_CALL));

        // Subscribe to different events -- replaces.
        state.subscribe_events(&[event_id::TIMER_EXPIRY]);
        assert!(!state.is_event_subscribed(event_id::MT_CALL));
        assert!(state.is_event_subscribed(event_id::TIMER_EXPIRY));
    }

    #[test]
    fn clear_subscriptions() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[event_id::MT_CALL, event_id::TIMER_EXPIRY]);
        assert!(state.is_event_subscribed(event_id::MT_CALL));

        state.clear_event_subscriptions();
        assert!(!state.is_event_subscribed(event_id::MT_CALL));
        assert!(!state.is_event_subscribed(event_id::TIMER_EXPIRY));
    }

    #[test]
    fn subscribe_ignores_out_of_range() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[32, 33, 255]);
        assert!(!state.is_event_subscribed(32));
        assert!(!state.is_event_subscribed(255));
    }

    #[test]
    fn set_up_event_list_activates_subscription() {
        let mut state = ProactiveState::new();
        // Queue SET UP EVENT LIST: subscribe to LOCATION_STATUS and USER_ACTIVITY.
        state
            .queue_command(&ProactiveCommand::SetUpEventList {
                events: &[event_id::LOCATION_STATUS, event_id::USER_ACTIVITY],
            })
            .unwrap();
        // Subscriptions should be activated by the queue call.
        assert!(state.is_event_subscribed(event_id::LOCATION_STATUS));
        assert!(state.is_event_subscribed(event_id::USER_ACTIVITY));
        assert!(!state.is_event_subscribed(event_id::TIMER_EXPIRY));

        // Simulate the terminal sending a matching event.
        let (buf, len) = build_event_download_envelope(event_id::LOCATION_STATUS);
        assert!(state.process_envelope(&buf[..len]));
        assert!(state.take_event().is_some());
    }

    // -- Timer management tests --

    #[test]
    fn start_timer_and_get_value() {
        let mut state = ProactiveState::new();
        let bcd = [0x01, 0x30, 0x00]; // 01:30:00
        assert!(state.start_timer(1, bcd));
        let val = state.get_timer_value(1).unwrap();
        assert_eq!(val, bcd);
    }

    #[test]
    fn tick_half_duration() {
        let mut state = ProactiveState::new();
        let bcd = [0x00, 0x10, 0x00]; // 00:10:00 = 600 seconds
        state.start_timer(1, bcd);

        let expired = state.tick(300); // advance 5 minutes
        assert_eq!(expired, 0);

        let val = state.get_timer_value(1).unwrap();
        assert_eq!(val, [0x00, 0x05, 0x00]); // 00:05:00
    }

    #[test]
    fn tick_past_expiry() {
        let mut state = ProactiveState::new();
        let bcd = [0x00, 0x00, 0x10]; // 10 seconds
        state.start_timer(3, bcd);

        let expired = state.tick(15);
        assert_eq!(expired, 1);

        // Timer should be inactive now.
        assert!(state.get_timer_value(3).is_none());

        // Should be retrievable via take_expired_timer.
        assert_eq!(state.take_expired_timer(), 3);
        assert_eq!(state.take_expired_timer(), 0); // no more
    }

    #[test]
    fn deactivate_timer_returns_remaining() {
        let mut state = ProactiveState::new();
        let bcd = [0x00, 0x20, 0x00]; // 20 minutes = 1200 seconds
        state.start_timer(2, bcd);
        state.tick(600); // advance 10 minutes

        let remaining = state.deactivate_timer(2).unwrap();
        assert_eq!(remaining, [0x00, 0x10, 0x00]); // 10 minutes left
        assert!(state.get_timer_value(2).is_none()); // now inactive
    }

    #[test]
    fn invalid_timer_id_rejected() {
        let mut state = ProactiveState::new();
        assert!(!state.start_timer(0, [0x00, 0x01, 0x00]));
        assert!(!state.start_timer(9, [0x00, 0x01, 0x00]));
        assert!(state.deactivate_timer(0).is_none());
        assert!(state.deactivate_timer(9).is_none());
        assert!(state.get_timer_value(0).is_none());
        assert!(state.get_timer_value(9).is_none());
    }

    #[test]
    fn all_eight_timers() {
        let mut state = ProactiveState::new();
        // Start all 8 with different durations: 10, 20, 30, 40, 50, 60, 70, 80 secs.
        for id in 1..=8u8 {
            let secs = u32::from(id) * 10;
            state.start_timer(id, seconds_to_bcd(secs));
        }

        // Tick 15 seconds: timer 1 (10s) expires.
        // Remaining: T2=5, T3=15, T4=25, T5=35, T6=45, T7=55, T8=65.
        let expired = state.tick(15);
        assert_eq!(expired, 1);
        assert_eq!(state.take_expired_timer(), 1);

        // Tick 10 more: timer 2 (5s left) also expires.
        // Remaining: T3=5, T4=15, T5=25, T6=35, T7=45, T8=55.
        let expired = state.tick(10);
        assert_eq!(expired, 1);
        assert_eq!(state.take_expired_timer(), 2);

        // Tick 10 more: timer 3 (5s left) expires.
        let expired = state.tick(10);
        assert_eq!(expired, 1);
        assert_eq!(state.take_expired_timer(), 3);
        assert_eq!(state.take_expired_timer(), 0);

        // Remaining 5 timers still active (T4=5, T5=15, T6=25, T7=35, T8=45).
        assert!(state.get_timer_value(4).is_some());
        assert!(state.get_timer_value(8).is_some());
    }

    #[test]
    fn bcd_roundtrip_boundary_values() {
        // 23:59:59
        let max = [0x23, 0x59, 0x59];
        let secs = bcd_to_seconds(max);
        assert_eq!(secs, 86399);
        assert_eq!(seconds_to_bcd(secs), max);

        // 00:00:01
        let min = [0x00, 0x00, 0x01];
        assert_eq!(bcd_to_seconds(min), 1);
        assert_eq!(seconds_to_bcd(1), min);

        // 00:00:00
        let zero = [0x00, 0x00, 0x00];
        assert_eq!(bcd_to_seconds(zero), 0);
        assert_eq!(seconds_to_bcd(0), zero);

        // 01:00:00
        let one_hour = [0x01, 0x00, 0x00];
        assert_eq!(bcd_to_seconds(one_hour), 3600);
        assert_eq!(seconds_to_bcd(3600), one_hour);
    }

    #[test]
    fn bcd_seconds_clamp() {
        // seconds_to_bcd clamps above 86399.
        let over = seconds_to_bcd(100_000);
        assert_eq!(over, [0x23, 0x59, 0x59]);
    }

    #[test]
    fn deactivate_inactive_returns_none() {
        let state = ProactiveState::new();
        // Timer 1 was never started.
        assert!(state.get_timer_value(1).is_none());
    }

    #[test]
    fn deactivate_expired_timer_returns_none() {
        let mut state = ProactiveState::new();
        state.start_timer(4, [0x00, 0x00, 0x05]); // 5 seconds
        state.tick(10); // expire it
        let _id = state.take_expired_timer(); // consume from expired queue
        // Attempting to deactivate an already-expired timer must return None.
        assert!(state.deactivate_timer(4).is_none());
    }

    #[test]
    fn tick_zero_does_not_expire() {
        let mut state = ProactiveState::new();
        state.start_timer(1, [0x00, 0x00, 0x30]); // 30 seconds
        let expired = state.tick(0);
        assert_eq!(expired, 0);
        assert_eq!(state.get_timer_value(1).unwrap(), [0x00, 0x00, 0x30]);
    }

    // -- Terminal profile tests --

    #[test]
    fn terminal_profile_store_and_check() {
        let mut state = ProactiveState::new();
        // Set bits: byte 0 = 0b0000_0101 (bits 0 and 2), byte 1 = 0x80 (bit 7).
        let profile = [0x05, 0x80];
        state.set_terminal_profile(&profile);

        assert!(state.terminal_supports(0, 0));  // bit 0 of byte 0
        assert!(!state.terminal_supports(0, 1)); // bit 1 of byte 0
        assert!(state.terminal_supports(0, 2));  // bit 2 of byte 0
        assert!(state.terminal_supports(1, 7));  // bit 7 of byte 1
        assert!(!state.terminal_supports(1, 0)); // bit 0 of byte 1
        assert!(!state.terminal_supports(2, 0)); // beyond stored profile
    }

    #[test]
    fn terminal_profile_truncation() {
        let mut state = ProactiveState::new();
        let big_profile = [0xFF; 40];
        state.set_terminal_profile(&big_profile);

        // Only first 32 bytes stored.
        assert!(state.terminal_supports(31, 0));
        assert!(!state.terminal_supports(32, 0)); // beyond 32
    }

    #[test]
    fn terminal_profile_empty() {
        let state = ProactiveState::new();
        assert!(!state.terminal_supports(0, 0));
        assert!(!state.terminal_supports(0, 7));
        assert!(!state.terminal_supports(31, 0));
    }

    #[test]
    fn terminal_profile_bit_boundary() {
        let mut state = ProactiveState::new();
        // Byte 0: bit 7 set (0x80), byte 3: bit 0 set (0x01).
        let mut profile = [0u8; 4];
        profile[0] = 0x80;
        profile[3] = 0x01;
        state.set_terminal_profile(&profile);

        assert!(state.terminal_supports(0, 7));
        assert!(!state.terminal_supports(0, 0));
        assert!(state.terminal_supports(3, 0));
        assert!(!state.terminal_supports(3, 7));
        // bit > 7 returns false
        assert!(!state.terminal_supports(0, 8));
    }

    // -- BIP channel tests --

    #[test]
    fn open_close_channel() {
        let mut state = ProactiveState::new();
        assert!(!state.is_channel_open(1));
        assert!(state.open_channel(1, 0x01, 1024));
        assert!(state.is_channel_open(1));
        assert!(state.close_channel(1));
        assert!(!state.is_channel_open(1));
    }

    #[test]
    fn open_channel_rejects_already_open() {
        let mut state = ProactiveState::new();
        assert!(state.open_channel(3, 0x02, 512));
        assert!(!state.open_channel(3, 0x02, 512));
    }

    #[test]
    fn close_channel_rejects_not_open() {
        let mut state = ProactiveState::new();
        assert!(!state.close_channel(5));
    }

    #[test]
    fn channel_out_of_range() {
        let mut state = ProactiveState::new();
        assert!(!state.open_channel(0, 0x01, 256));
        assert!(!state.open_channel(8, 0x01, 256));
        assert!(!state.is_channel_open(0));
        assert!(!state.is_channel_open(8));
        assert!(!state.close_channel(0));
        assert!(!state.close_channel(8));
    }

    #[test]
    fn channel_status_bitmask_tracks_open() {
        let mut state = ProactiveState::new();
        assert_eq!(state.channel_status_bitmask(), 0);
        state.open_channel(1, 0x01, 128);
        assert_eq!(state.channel_status_bitmask(), 0b0000_0001);
        state.open_channel(4, 0x03, 256);
        assert_eq!(state.channel_status_bitmask(), 0b0000_1001);
        state.open_channel(7, 0x02, 512);
        assert_eq!(state.channel_status_bitmask(), 0b0100_1001);
        state.close_channel(4);
        assert_eq!(state.channel_status_bitmask(), 0b0100_0001);
    }

    #[test]
    fn all_channels_open_close() {
        let mut state = ProactiveState::new();
        for id in 1..=7u8 {
            assert!(state.open_channel(id, id, u16::from(id) * 100));
        }
        assert_eq!(state.channel_status_bitmask(), 0b0111_1111);
        for id in 1..=7u8 {
            assert!(state.close_channel(id));
        }
        assert_eq!(state.channel_status_bitmask(), 0);
    }

    #[test]
    fn snapshot_roundtrip_with_channels() {
        let mut state = ProactiveState::new();
        state.open_channel(2, 0x03, 1500);
        state.open_channel(5, 0x01, 256);

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));
        assert!(restored.is_channel_open(2));
        assert!(restored.is_channel_open(5));
        assert!(!restored.is_channel_open(1));
        assert_eq!(
            restored.channel_status_bitmask(),
            state.channel_status_bitmask()
        );
    }

    #[test]
    fn channel_close_clears_metadata() {
        let mut state = ProactiveState::new();
        state.open_channel(3, 0x05, 2048);
        state.close_channel(3);

        // Snapshot and restore - channel should remain closed with zeroed metadata.
        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);
        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));
        assert!(!restored.is_channel_open(3));
    }

    // -- Terminal response parsing tests --

    #[test]
    fn terminal_response_parse_success() {
        let mut state = ProactiveState::new();
        // CMD_DETAILS: tag=0x81, len=3, cmd_number=1, cmd_type=0x21 (DISPLAY TEXT), qualifier=0x00
        // DEVICE_ID:   tag=0x82, len=2, terminal, UICC
        // RESULT:      tag=0x83, len=1, general_result=0x00 (success)
        let data = [
            0x81, 0x03, 0x01, 0x21, 0x00,
            0x82, 0x02, 0x82, 0x81,
            0x83, 0x01, 0x00,
        ];
        let result = state.terminal_response(&data);
        assert_eq!(
            result,
            Some(TerminalResult {
                cmd_number: 1,
                cmd_type: 0x21,
                general_result: 0x00,
            })
        );
        assert_eq!(state.last_terminal_result(), 0x00);
    }

    #[test]
    fn terminal_response_parse_user_cancelled() {
        let mut state = ProactiveState::new();
        // RESULT: 0x10 = proactive session terminated by user
        let data = [
            0x81, 0x03, 0x02, 0x21, 0x80,
            0x82, 0x02, 0x82, 0x81,
            0x83, 0x01, 0x10,
        ];
        let result = state.terminal_response(&data);
        assert_eq!(
            result,
            Some(TerminalResult {
                cmd_number: 2,
                cmd_type: 0x21,
                general_result: 0x10,
            })
        );
        assert_eq!(state.last_terminal_result(), 0x10);
    }

    #[test]
    fn terminal_response_parse_unable() {
        let mut state = ProactiveState::new();
        // RESULT: 0x20 = terminal currently unable to process
        let data = [
            0x81, 0x03, 0x05, 0x25, 0x00,
            0x83, 0x01, 0x20,
        ];
        let result = state.terminal_response(&data);
        assert_eq!(
            result,
            Some(TerminalResult {
                cmd_number: 5,
                cmd_type: 0x25,
                general_result: 0x20,
            })
        );
    }

    #[test]
    fn terminal_response_missing_result_tag() {
        let mut state = ProactiveState::new();
        // Only CMD_DETAILS, no RESULT tag
        let data = [0x81, 0x03, 0x01, 0x21, 0x00];
        let result = state.terminal_response(&data);
        assert_eq!(result, None);
        // last_result should stay at initial value
        assert_eq!(state.last_terminal_result(), 0xFF);
    }

    #[test]
    fn terminal_response_empty_data() {
        let mut state = ProactiveState::new();
        let result = state.terminal_response(&[]);
        assert_eq!(result, None);
        assert_eq!(state.last_terminal_result(), 0xFF);
    }

    #[test]
    fn terminal_response_result_without_cmd_details() {
        let mut state = ProactiveState::new();
        // Only RESULT, no CMD_DETAILS
        let data = [0x83, 0x01, 0x00];
        let result = state.terminal_response(&data);
        // RESULT present but CMD_DETAILS missing => None (but last_result still updated)
        assert_eq!(result, None);
        assert_eq!(state.last_terminal_result(), 0x00);
    }

    #[test]
    fn terminal_response_cmd_number_preserved() {
        let mut state = ProactiveState::new();
        // cmd_number = 0xFE
        let data = [
            0x81, 0x03, 0xFE, 0x13, 0x01,
            0x83, 0x01, 0x00,
        ];
        let result = state.terminal_response(&data).unwrap();
        assert_eq!(result.cmd_number, 0xFE);
        assert_eq!(result.cmd_type, 0x13);
    }

    #[test]
    fn terminal_response_full_stk_cycle() {
        let mut state = ProactiveState::new();
        state
            .queue_command(&ProactiveCommand::DisplayText {
                text: b"Hello",
                coding: TextCoding::Gsm8Bit,
                high_priority: false,
            })
            .unwrap();
        assert!(state.has_pending());

        let mut fetch_buf = [0u8; 256];
        let fetched = state.fetch(&mut fetch_buf);
        assert!(fetched > 0);
        assert!(!state.has_pending());

        // Terminal responds with success
        let tr_data = [
            0x81, 0x03, 0x01, 0x21, 0x00,
            0x82, 0x02, 0x82, 0x81,
            0x83, 0x01, 0x00,
        ];
        let result = state.terminal_response(&tr_data).unwrap();
        assert_eq!(result.general_result, 0x00);
        assert_eq!(state.last_terminal_result(), 0x00);

        // Can queue next command
        state
            .queue_command(&ProactiveCommand::MoreTime)
            .unwrap();
        assert!(state.has_pending());
    }

    #[test]
    fn snapshot_roundtrip_with_last_result() {
        let mut state = ProactiveState::new();
        let data = [
            0x81, 0x03, 0x01, 0x21, 0x00,
            0x83, 0x01, 0x30,
        ];
        state.terminal_response(&data);
        assert_eq!(state.last_terminal_result(), 0x30);

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));
        assert_eq!(restored.last_terminal_result(), 0x30);
    }

    // -- Snapshot roundtrip with new fields --

    #[test]
    fn snapshot_roundtrip_with_event() {
        let mut state = ProactiveState::new();
        let (buf, len) = build_menu_selection_envelope(0x07);
        state.process_envelope(&buf[..len]);

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));
        let event = restored.take_event();
        assert_eq!(
            event,
            Some(EnvelopeEvent::MenuSelection { item_id: 0x07 })
        );
    }

    #[test]
    fn snapshot_roundtrip_with_profile() {
        let mut state = ProactiveState::new();
        let profile = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
        state.set_terminal_profile(&profile);

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));

        // Verify each byte/bit combination.
        for (byte_idx, &byte_val) in profile.iter().enumerate() {
            for bit in 0u8..8 {
                let expected = byte_val & (1 << bit) != 0;
                assert_eq!(
                    restored.terminal_supports(byte_idx, bit),
                    expected,
                    "mismatch at byte {byte_idx} bit {bit}"
                );
            }
        }
        // Beyond stored profile returns false.
        assert!(!restored.terminal_supports(8, 0));
    }

    #[test]
    fn snapshot_roundtrip_with_event_download() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[event_id::TIMER_EXPIRY, event_id::LOCATION_STATUS]);

        let timer_val = [0x02, 0x15, 0x30]; // 02h 15m 30s
        let (buf, len) = build_timer_expiry_envelope(0x05, timer_val);
        state.process_envelope(&buf[..len]);

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));

        // Event should be preserved.
        let event = restored.take_event();
        assert_eq!(
            event,
            Some(EnvelopeEvent::EventDownload {
                event_type: event_id::TIMER_EXPIRY,
                timer_id: 0x05,
                timer_value: timer_val,
            })
        );

        // Subscriptions should be preserved.
        assert!(restored.is_event_subscribed(event_id::TIMER_EXPIRY));
        assert!(restored.is_event_subscribed(event_id::LOCATION_STATUS));
        assert!(!restored.is_event_subscribed(event_id::MT_CALL));
    }

    #[test]
    fn snapshot_roundtrip_subscriptions_only() {
        let mut state = ProactiveState::new();
        state.subscribe_events(&[
            event_id::MT_CALL,
            event_id::CALL_CONNECTED,
            event_id::USER_ACTIVITY,
            event_id::BROWSER_TERMINATION,
        ]);

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));
        assert!(restored.is_event_subscribed(event_id::MT_CALL));
        assert!(restored.is_event_subscribed(event_id::CALL_CONNECTED));
        assert!(restored.is_event_subscribed(event_id::USER_ACTIVITY));
        assert!(restored.is_event_subscribed(event_id::BROWSER_TERMINATION));
        assert!(!restored.is_event_subscribed(event_id::TIMER_EXPIRY));
    }

    #[test]
    fn snapshot_roundtrip_with_active_timers() {
        let mut state = ProactiveState::new();
        state.start_timer(1, [0x01, 0x00, 0x00]); // 1 hour
        state.start_timer(5, [0x00, 0x30, 0x00]); // 30 minutes
        state.tick(600); // advance 10 minutes

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));

        // Timer 1: 1h - 10m = 50m
        let v1 = restored.get_timer_value(1).unwrap();
        assert_eq!(v1, [0x00, 0x50, 0x00]);
        // Timer 5: 30m - 10m = 20m
        let v5 = restored.get_timer_value(5).unwrap();
        assert_eq!(v5, [0x00, 0x20, 0x00]);
        // Others inactive
        assert!(restored.get_timer_value(2).is_none());
    }

    #[test]
    fn snapshot_roundtrip_with_expired_queue() {
        let mut state = ProactiveState::new();
        state.start_timer(2, [0x00, 0x00, 0x05]); // 5 seconds
        state.start_timer(7, [0x00, 0x00, 0x03]); // 3 seconds
        state.tick(10); // both expire

        let mut snap = [0u8; ProactiveState::SNAPSHOT_SIZE];
        let written = state.save_state(&mut snap);
        assert_eq!(written, ProactiveState::SNAPSHOT_SIZE);

        let mut restored = ProactiveState::new();
        assert!(restored.restore_state(&snap));

        // Expired timers should be preserved.
        let a = restored.take_expired_timer();
        let b = restored.take_expired_timer();
        assert!(a == 2 || a == 7);
        assert!(b == 2 || b == 7);
        assert_ne!(a, b);
        assert_eq!(restored.take_expired_timer(), 0);
    }

    #[test]
    fn encode_prefixed_tlv_consistency() {
        // Encode a DisplayText and verify the Text String TLV is present
        // with DCS byte 0x00 (GSM 7-bit) followed by text bytes.
        let cmd = ProactiveCommand::DisplayText {
            text: b"Test",
            coding: TextCoding::Gsm7Bit,
            high_priority: false,
        };
        let mut buf = [0u8; 64];
        let len = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..len]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);
        inner.next().unwrap().unwrap(); // cmd details
        inner.next().unwrap().unwrap(); // device id
        let text_tlv = inner.next().unwrap().unwrap();
        assert_eq!(text_tlv.tag, TAG_TEXT_STRING);
        assert_eq!(text_tlv.value[0], 0x00); // GSM 7-bit DCS
        assert_eq!(&text_tlv.value[1..], b"Test");
    }

    // -- New command encoding tests --

    #[test]
    fn send_ss_encoding() {
        let cmd = ProactiveCommand::SendSs { qualifier: 0x00 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_SEND_SS);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_NETWORK]);
    }

    #[test]
    fn geographical_location_request_encoding() {
        let cmd = ProactiveCommand::GeographicalLocationRequest;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_GEO_LOCATION_REQUEST);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn perform_card_apdu_encoding() {
        let cmd = ProactiveCommand::PerformCardApdu { qualifier: 0x01 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_PERFORM_CARD_APDU);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn power_on_card_encoding() {
        let cmd = ProactiveCommand::PowerOnCard { qualifier: 0x00 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_POWER_ON_CARD);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn power_off_card_encoding() {
        let cmd = ProactiveCommand::PowerOffCard { qualifier: 0x00 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_POWER_OFF_CARD);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn get_reader_status_encoding() {
        let cmd = ProactiveCommand::GetReaderStatus { qualifier: 0x01 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_GET_READER_STATUS);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn run_at_command_encoding() {
        let cmd = ProactiveCommand::RunAtCommand;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_RUN_AT_COMMAND);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn close_channel_encoding() {
        let cmd = ProactiveCommand::CloseChannel { qualifier: 0x00 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_CLOSE_CHANNEL);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn receive_data_encoding() {
        let cmd = ProactiveCommand::ReceiveData { qualifier: 0x00 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_RECEIVE_DATA);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn send_data_cmd_encoding() {
        let cmd = ProactiveCommand::SendDataCmd { qualifier: 0x01 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_SEND_DATA);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn get_channel_status_encoding() {
        let cmd = ProactiveCommand::GetChannelStatus;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_GET_CHANNEL_STATUS);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn service_search_encoding() {
        let cmd = ProactiveCommand::ServiceSearch;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_SERVICE_SEARCH);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn get_service_information_encoding() {
        let cmd = ProactiveCommand::GetServiceInformation;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_GET_SERVICE_INFO);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn declare_service_encoding() {
        let cmd = ProactiveCommand::DeclareService { qualifier: 0x01 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_DECLARE_SERVICE);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn set_frames_encoding() {
        let cmd = ProactiveCommand::SetFrames;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_SET_FRAMES);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn get_frames_status_encoding() {
        let cmd = ProactiveCommand::GetFramesStatus;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_GET_FRAMES_STATUS);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn retrieve_mms_encoding() {
        let cmd = ProactiveCommand::RetrieveMultimediaMessage;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_RETRIEVE_MMS);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn submit_mms_encoding() {
        let cmd = ProactiveCommand::SubmitMultimediaMessage;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_SUBMIT_MMS);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn display_mms_encoding() {
        let cmd = ProactiveCommand::DisplayMultimediaMessage;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_DISPLAY_MMS);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn activate_encoding() {
        let cmd = ProactiveCommand::Activate { qualifier: 0x01 };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_ACTIVATE);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn contactless_state_changed_encoding() {
        let cmd = ProactiveCommand::ContactlessStateChanged;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_CONTACTLESS_STATE_CHANGED);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn command_container_encoding() {
        let cmd = ProactiveCommand::CommandContainer;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_COMMAND_CONTAINER);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn encapsulated_session_control_encoding() {
        let cmd = ProactiveCommand::EncapsulatedSessionControl;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_ENCAP_SESSION_CTRL);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn lsi_command_encoding() {
        let cmd = ProactiveCommand::LsiCommand;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_LSI_COMMAND);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    #[test]
    fn end_of_proactive_session_encoding() {
        let cmd = ProactiveCommand::EndOfProactiveUiccSession;
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);
        let mut dec = Decoder::new(&buf[2..n]);
        let details = dec.next().unwrap().unwrap();
        assert_eq!(details.tag, 0x81);
        assert_eq!(details.value[1], CMD_TYPE_END_PROACTIVE_SESSION);
        let devid = dec.next().unwrap().unwrap();
        assert_eq!(devid.tag, 0x82);
        assert_eq!(devid.value, &[DEV_UICC, DEV_TERMINAL]);
    }

    // -- OPEN CHANNEL tests --

    #[test]
    fn open_channel_mandatory_only() {
        let cmd = ProactiveCommand::OpenChannel {
            bearer: &[0x01],
            buffer_size: 1024,
            alpha_id: &[],
            transport_level: &[],
            destination_address: &[],
            qualifier: 0x00,
        };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);

        let mut outer = Decoder::new(&buf[..n]);
        let envelope = outer.next().unwrap().unwrap();
        assert_eq!(envelope.tag, 0xD0);
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.tag, TAG_CMD_DETAILS);
        assert_eq!(cd.value[1], CMD_TYPE_OPEN_CHANNEL);
        assert_eq!(cd.value[2], 0x00);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.tag, TAG_DEVICE_ID);
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        let bearer = inner.next().unwrap().unwrap();
        assert_eq!(bearer.tag, TAG_BEARER_DESCRIPTION);
        assert_eq!(bearer.value, &[0x01]);

        let bufsz = inner.next().unwrap().unwrap();
        assert_eq!(bufsz.tag, TAG_BUFFER_SIZE);
        assert_eq!(bufsz.value, &[0x04, 0x00]); // 1024 big-endian

        // No more TLVs (optionals empty).
        assert!(inner.next().is_none());
    }

    #[test]
    fn open_channel_all_optionals() {
        let cmd = ProactiveCommand::OpenChannel {
            bearer: &[0x02, 0x03],
            buffer_size: 512,
            alpha_id: b"Connect",
            transport_level: &[0x01, 0x00, 0x50], // TCP, port 80
            destination_address: &[0x21, 0x01, 0x02, 0x03, 0x04],
            qualifier: 0x01,
        };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 0xD0);

        let mut outer = Decoder::new(&buf[..n]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);

        let cd = inner.next().unwrap().unwrap();
        assert_eq!(cd.value[1], CMD_TYPE_OPEN_CHANNEL);
        assert_eq!(cd.value[2], 0x01);

        let di = inner.next().unwrap().unwrap();
        assert_eq!(di.value, &[DEV_UICC, DEV_TERMINAL]);

        let bearer = inner.next().unwrap().unwrap();
        assert_eq!(bearer.tag, TAG_BEARER_DESCRIPTION);
        assert_eq!(bearer.value, &[0x02, 0x03]);

        let bufsz = inner.next().unwrap().unwrap();
        assert_eq!(bufsz.tag, TAG_BUFFER_SIZE);
        assert_eq!(bufsz.value, &[0x02, 0x00]); // 512 big-endian

        let alpha = inner.next().unwrap().unwrap();
        assert_eq!(alpha.tag, TAG_ALPHA_ID);
        assert_eq!(alpha.value, b"Connect");

        let tl = inner.next().unwrap().unwrap();
        assert_eq!(tl.tag, TAG_TRANSPORT_LEVEL);
        assert_eq!(tl.value, &[0x01, 0x00, 0x50]);

        let addr = inner.next().unwrap().unwrap();
        assert_eq!(addr.tag, TAG_OTHER_ADDRESS);
        assert_eq!(addr.value, &[0x21, 0x01, 0x02, 0x03, 0x04]);

        assert!(inner.next().is_none());
    }

    #[test]
    fn open_channel_dry_run_matches() {
        let cmd = ProactiveCommand::OpenChannel {
            bearer: &[0x01, 0x02, 0x03],
            buffer_size: 2048,
            alpha_id: b"Test",
            transport_level: &[0x02, 0x13, 0x88],
            destination_address: &[0x57, 0xC0, 0xA8, 0x01, 0x01],
            qualifier: 0x00,
        };
        let dry = encoded_len(&cmd, 1);
        let mut buf = [0u8; 256];
        let real = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(dry, real);
    }

    #[test]
    fn open_channel_buffer_size_big_endian() {
        let cmd = ProactiveCommand::OpenChannel {
            bearer: &[0x01],
            buffer_size: 0x0102,
            alpha_id: &[],
            transport_level: &[],
            destination_address: &[],
            qualifier: 0x00,
        };
        let mut buf = [0u8; 256];
        let n = encode(&cmd, 1, &mut buf).unwrap();

        let mut outer = Decoder::new(&buf[..n]);
        let envelope = outer.next().unwrap().unwrap();
        let mut inner = Decoder::new(envelope.value);
        inner.next().unwrap().unwrap(); // cmd details
        inner.next().unwrap().unwrap(); // device id
        inner.next().unwrap().unwrap(); // bearer
        let bufsz = inner.next().unwrap().unwrap();
        assert_eq!(bufsz.tag, TAG_BUFFER_SIZE);
        assert_eq!(bufsz.value, &[0x01, 0x02]);
    }

    // -- Dry-run batch test for all 26 new commands --

    #[test]
    fn dry_run_matches_new_commands() {
        let commands: &[ProactiveCommand<'_>] = &[
            ProactiveCommand::SendSs { qualifier: 0x00 },
            ProactiveCommand::GeographicalLocationRequest,
            ProactiveCommand::PerformCardApdu { qualifier: 0x00 },
            ProactiveCommand::PowerOnCard { qualifier: 0x00 },
            ProactiveCommand::PowerOffCard { qualifier: 0x00 },
            ProactiveCommand::GetReaderStatus { qualifier: 0x00 },
            ProactiveCommand::RunAtCommand,
            ProactiveCommand::OpenChannel {
                bearer: &[0x01],
                buffer_size: 1024,
                alpha_id: b"Test",
                transport_level: &[0x01, 0x00, 0x50],
                destination_address: &[0x21, 0x01, 0x02, 0x03, 0x04],
                qualifier: 0x00,
            },
            ProactiveCommand::CloseChannel { qualifier: 0x00 },
            ProactiveCommand::ReceiveData { qualifier: 0x00 },
            ProactiveCommand::SendDataCmd { qualifier: 0x00 },
            ProactiveCommand::GetChannelStatus,
            ProactiveCommand::ServiceSearch,
            ProactiveCommand::GetServiceInformation,
            ProactiveCommand::DeclareService { qualifier: 0x00 },
            ProactiveCommand::SetFrames,
            ProactiveCommand::GetFramesStatus,
            ProactiveCommand::RetrieveMultimediaMessage,
            ProactiveCommand::SubmitMultimediaMessage,
            ProactiveCommand::DisplayMultimediaMessage,
            ProactiveCommand::Activate { qualifier: 0x00 },
            ProactiveCommand::ContactlessStateChanged,
            ProactiveCommand::CommandContainer,
            ProactiveCommand::EncapsulatedSessionControl,
            ProactiveCommand::LsiCommand,
            ProactiveCommand::EndOfProactiveUiccSession,
        ];
        for cmd in commands {
            let dry = encoded_len(cmd, 1);
            let mut buf = [0u8; 256];
            let real = encode(cmd, 1, &mut buf).unwrap();
            assert_eq!(dry, real, "dry-run mismatch for {cmd:?}");
        }
    }


    #[test]
    fn proactive_error_display_non_empty() {
        let e = ProactiveError::BufferTooSmall;
        let s = alloc::format!("{e}");
        assert!(!s.is_empty(), "Display for ProactiveError must produce non-empty string");
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

    }

    #[test]
    fn dry_run_matches_real_get_input() {
        let cmd = ProactiveCommand::GetInput {
            text: b"Test prompt",
            coding: TextCoding::Gsm8Bit,
            min_len: 0,
            max_len: 50,
            digits_only: true,
        };
        let dry = encoded_len(&cmd, 1);
        let mut buf = [0u8; 128];
        let real = encode(&cmd, 1, &mut buf).unwrap();
        assert_eq!(dry, real);
    }

    #[test]
    fn dry_run_matches_real_timer_management() {
        // With timer value (start).
        let cmd_start = ProactiveCommand::TimerManagement {
            timer_id: 0x02,
            qualifier: 0x00,
            timer_value: Some([0x01, 0x30, 0x00]),
        };
        let dry = encoded_len(&cmd_start, 1);
        let mut buf = [0u8; 128];
        let real = encode(&cmd_start, 1, &mut buf).unwrap();
        assert_eq!(dry, real);

        // Without timer value (deactivate).
        let cmd_deactivate = ProactiveCommand::TimerManagement {
            timer_id: 0x05,
            qualifier: 0x01,
            timer_value: None,
        };
        let dry2 = encoded_len(&cmd_deactivate, 1);
        let mut buf2 = [0u8; 128];
        let real2 = encode(&cmd_deactivate, 1, &mut buf2).unwrap();
        assert_eq!(dry2, real2);
    }

    proptest! {
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
