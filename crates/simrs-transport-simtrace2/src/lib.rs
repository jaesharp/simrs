//! `CardTransport` over USB to an Osmocom SIMtrace2 board running cardem
//! firmware.
//!
//! This crate is the device-side bridge between simrs's APDU-granular
//! [`simrs_transport::CardTransport`] trait and the Osmocom SIMtrace2 USB
//! protocol (cardem class, message class 0x02).
//!
//! # Quickstart
//!
//! ```no_run
//! use simrs_transport::CardTransport;
//! use simrs_transport_simtrace2::{DeviceFilter, Simtrace2Transport};
//!
//! let mut transport = Simtrace2Transport::open(&DeviceFilter::default())?;
//!
//! // Pre-stage the ATR so the firmware has one ready when the phone
//! // releases RST. Per ISO 7816-3 §6.3 the window between RST release and
//! // the first ATR byte is 400-40 000 cycles (~123 us-12.3 ms). If we
//! // miss it, the phone latches whatever the firmware advertised as
//! // default and treats subsequent ATRs as a mismatch.
//! transport.send_atr(&simrs_card_api::DEFAULT_ATR)?;
//!
//! let mut buf = [0u8; 261];
//! loop {
//!     match transport.recv(&mut buf)? {
//!         // ... drive simrs Sim here
//!         _ => {}
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Hardware requirements
//!
//! - Osmocom SIMtrace2 (`1d50:60e3`) running cardem firmware. Boards ship
//!   with the `trace` (passive sniffer) firmware -- you need to reflash
//!   with the cardem image. See [`docs/runbooks/simtrace2-cardem-path-a.md`]
//!   in this repository for the DFU procedure.
//! - udev permissions so the running user can claim the USB interface
//!   without root. The Path A runbook covers the rule set.
//!
//! # Design notes
//!
//! - I/O is synchronous via `nusb`'s `transfer_blocking` API. The rest of
//!   the simrs binaries (vpcd, swicc) are sync, and there is no benefit to
//!   bringing tokio into the dependency tree for a single-card-side
//!   server loop.
//! - The cardem firmware handles all character-level T=0 mechanics
//!   autonomously, including emitting NULL (0x60) procedure bytes while
//!   waiting for host data. Host code therefore operates at APDU
//!   granularity and can tolerate 100-300 ms of latency per APDU comfortably.
//! - The transport derives lifecycle events ([`simrs_transport::CardEvent`])
//!   from `BD_CEMU_STATUS` flag transitions, exactly mirroring
//!   `update_status_flags` in upstream
//!   [`host/src/simtrace2-cardem-pcsc.c`](https://github.com/osmocom/simtrace2/blob/master/host/src/simtrace2-cardem-pcsc.c).
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)] // 3GPP/USB acronyms

pub mod cardem;
pub mod device;
pub mod protocol;

pub use cardem::Simtrace2Transport;
pub use device::DeviceFilter;
pub use protocol::{
    CardemMsgType, CardemStatus, ProtocolError, RxDataView, SimtraceMsgHdr, CONFIG_FEAT_STATUS_IRQ,
    DATA_F_FINAL, DATA_F_PB_AND_RX, DATA_F_PB_AND_TX, DATA_F_TPDU_HDR, EP_BULK_IN, EP_BULK_OUT,
    EP_INT_IN, MSGC_CARDEM, PID_NGFF_CARDEM, PID_OCTSIMTEST, PID_SIMTRACE2, PID_SIMTRACE2_DFU,
    STATUS_F_CARD_INSERT, STATUS_F_CLK_ACTIVE, STATUS_F_RCEMU_ACTIVE, STATUS_F_RESET_ACTIVE,
    STATUS_F_VCC_PRESENT, VID_OPENMOKO,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors raised by [`Simtrace2Transport`].
#[derive(Debug)]
pub enum Error {
    /// No matching SIMtrace2 board found on the USB bus.
    DeviceNotFound,
    /// A SIMtrace2 board is present, but currently in DFU bootloader mode
    /// (`1d50:60e2`). Reflash and exit DFU before retrying.
    DfuModeDetected,
    /// Protocol-level encode / decode failure.
    Protocol(ProtocolError),
    /// Caller-supplied buffer is too small for an inbound APDU.
    BufferTooSmall,
    /// Underlying USB / I/O failure surfaced by `nusb`.
    Usb(String),
    /// A USB transfer completed with a non-success status.
    Transfer(String),
}

impl Error {
    /// Wrap an `nusb` error into [`Error::Usb`]. Keeps the variant explicit
    /// so log output stays helpful.
    pub(crate) fn from_io<E: core::fmt::Display>(err: E) -> Self {
        Self::Usb(err.to_string())
    }

    /// Wrap a USB transfer-status error into [`Error::Transfer`].
    pub(crate) fn from_transfer<E: core::fmt::Display>(err: E) -> Self {
        Self::Transfer(err.to_string())
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeviceNotFound => f.write_str("no matching SIMtrace2 board on USB bus"),
            Self::DfuModeDetected => f.write_str(
                "SIMtrace2 board present but in DFU mode; reflash cardem firmware first",
            ),
            Self::Protocol(e) => write!(f, "SIMtrace2 protocol error: {e}"),
            Self::BufferTooSmall => f.write_str("APDU buffer too small for incoming data"),
            Self::Usb(s) => write!(f, "USB error: {s}"),
            Self::Transfer(s) => write!(f, "USB transfer failed: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}
