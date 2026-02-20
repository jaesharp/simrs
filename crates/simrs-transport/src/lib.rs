//! SIM transport abstraction traits.
//!
//! Defines the [`Transport`] and [`CardTransport`] traits that decouple the
//! SIM simulator from any specific physical or virtual channel (TCP, shared
//! memory, `VirtIO`, etc.).
//!
//! Two trait flavours are provided:
//!
//! | Trait | Perspective | Use case |
//! |-------|------------|----------|
//! | [`Transport`] | **Terminal / test harness** | Send command, receive response |
//! | [`CardTransport`] | **Card / SIM daemon** | Receive event, send response |
//!
//! # Wire model
//!
//! Both traits operate on raw byte slices. The caller is responsible for
//! constructing valid APDU command bytes (CLA INS P1 P2 \[Lc data\] \[Le\])
//! and interpreting the response (data + SW1 SW2).
//!
//! # `no_std`, `no_alloc`
//!
//! This crate contains only trait definitions, enums, and a small error type.
//! It is fully `no_std` with zero dependencies beyond `core`.
//!
//! # Example (terminal side)
//!
//! ```
//! use simrs_transport::{Transport, TransportError};
//!
//! /// A loopback transport that always returns 90 00.
//! struct Loopback;
//!
//! impl Transport for Loopback {
//!     type Error = TransportError;
//!     fn exchange(&mut self, _cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
//!         if rsp.len() < 2 {
//!             return Err(TransportError::BufferTooSmall);
//!         }
//!         rsp[0] = 0x90;
//!         rsp[1] = 0x00;
//!         Ok(2)
//!     }
//! }
//!
//! let mut t = Loopback;
//! let mut rsp = [0u8; 258];
//! let n = t.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
//! assert_eq!(&rsp[..n], &[0x90, 0x00]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Transport error
// ---------------------------------------------------------------------------

/// Errors that can occur during transport operations.
///
/// This is intentionally coarse-grained; concrete transports may carry
/// additional detail in their own error types and convert to this via `From`.
///
/// # Example
///
/// ```
/// use simrs_transport::TransportError;
/// let e = TransportError::Disconnected;
/// assert_eq!(e, TransportError::Disconnected);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The response buffer is too small for the incoming data.
    BufferTooSmall,
    /// The remote peer disconnected.
    Disconnected,
    /// An I/O or framing error occurred on the channel.
    IoError,
    /// The received message has an invalid or unsupported format.
    InvalidMessage,
    /// A timeout expired before the operation completed.
    Timeout,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("response buffer too small"),
            Self::Disconnected => f.write_str("peer disconnected"),
            Self::IoError => f.write_str("I/O error on transport channel"),
            Self::InvalidMessage => f.write_str("invalid message format"),
            Self::Timeout => f.write_str("transport operation timed out"),
        }
    }
}

// ---------------------------------------------------------------------------
// CardEvent (card-side)
// ---------------------------------------------------------------------------

/// An event received by the card from the interface device.
///
/// Used by [`CardTransport::recv`] to convey what the reader/terminal
/// is requesting.
///
/// # Example
///
/// ```
/// use simrs_transport::CardEvent;
/// let ev = CardEvent::PowerOn;
/// assert!(matches!(ev, CardEvent::PowerOn));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardEvent {
    /// Cold reset -- the card should return its ATR.
    PowerOn,
    /// Warm reset -- the card should return its ATR and clear session state.
    WarmReset,
    /// An APDU command was received.
    ///
    /// The `usize` is the number of command bytes written into the buffer
    /// passed to [`CardTransport::recv`].
    Apdu(usize),
    /// The interface device has disconnected or signalled shutdown.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Transport trait (terminal / test-harness side)
// ---------------------------------------------------------------------------

/// Bidirectional APDU channel from the **terminal** perspective.
///
/// A `Transport` sends command APDUs and receives response APDUs.
/// The response includes both data bytes and the two status-word bytes
/// (SW1 SW2) appended at the end.
///
/// # Contract
///
/// - `cmd` must be a valid APDU command (at least 4 bytes: CLA INS P1 P2).
///   Implementors are not required to validate APDU structure.
/// - On success, `exchange` writes the response into `rsp` and returns the
///   number of bytes written. The last two bytes are always SW1 SW2.
/// - If `rsp` is too small, returns an appropriate error.
///
/// # Example
///
/// ```
/// use simrs_transport::{Transport, TransportError};
///
/// struct Echo;
/// impl Transport for Echo {
///     type Error = TransportError;
///     fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
///         let sw = [0x6D, 0x00]; // INS not supported
///         if rsp.len() < 2 { return Err(TransportError::BufferTooSmall); }
///         rsp[..2].copy_from_slice(&sw);
///         Ok(2)
///     }
/// }
/// ```
pub trait Transport {
    /// Error type for this transport implementation.
    type Error: core::fmt::Debug;

    /// Send a command APDU and receive the response.
    ///
    /// Returns the number of response bytes written into `rsp`
    /// (data + SW1 + SW2).
    ///
    /// # Errors
    ///
    /// Returns an error if `rsp` is shorter than the incoming response
    /// or the channel has failed.
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error>;
}

// ---------------------------------------------------------------------------
// CardTransport trait (card / SIM-daemon side)
// ---------------------------------------------------------------------------

/// Bidirectional channel from the **card** perspective.
///
/// A `CardTransport` receives events (reset, APDU commands) from the
/// interface device and sends responses (ATR, APDU data + SW) back.
///
/// # Typical event loop
///
/// ```rust,ignore
/// fn serve(sim: &mut Sim, ct: &mut impl CardTransport) {
///     let mut cmd = [0u8; 261];
///     loop {
///         match ct.recv(&mut cmd) {
///             Ok(CardEvent::PowerOn) => {
///                 let rsp = sim.process(SimEvent::PowerOn);
///                 // send ATR
///             }
///             Ok(CardEvent::Apdu(len)) => {
///                 let rsp = sim.process(SimEvent::Apdu(&cmd[..len]));
///                 // send response
///             }
///             Ok(CardEvent::Shutdown) => break,
///             Err(_) => break,
///             _ => {}
///         }
///     }
/// }
/// ```
pub trait CardTransport {
    /// Error type for this transport implementation.
    type Error: core::fmt::Debug;

    /// Wait for the next event from the interface device.
    ///
    /// For [`CardEvent::Apdu`], the command bytes are written into `buf`
    /// and the variant carries the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer has disconnected, the command does
    /// not fit in `buf`, or the channel has otherwise failed.
    fn recv(&mut self, buf: &mut [u8]) -> Result<CardEvent, Self::Error>;

    /// Send an APDU response (data + SW1 SW2) to the interface device.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel write fails.
    fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Send the ATR (Answer To Reset) to the interface device.
    ///
    /// Called after receiving [`CardEvent::PowerOn`] or [`CardEvent::WarmReset`].
    ///
    /// # Errors
    ///
    /// Returns an error if the channel write fails.
    fn send_atr(&mut self, atr: &[u8]) -> Result<(), Self::Error>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Loopback Transport (terminal side) --

    struct LoopbackTransport;

    impl Transport for LoopbackTransport {
        type Error = TransportError;
        fn exchange(&mut self, _cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
            if rsp.len() < 2 {
                return Err(TransportError::BufferTooSmall);
            }
            rsp[0] = 0x90;
            rsp[1] = 0x00;
            Ok(2)
        }
    }

    #[test]
    fn loopback_exchange_returns_success_sw() {
        let mut t = LoopbackTransport;
        let mut rsp = [0u8; 258];
        let n = t.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        assert_eq!(n, 2);
        assert_eq!(rsp[0], 0x90);
        assert_eq!(rsp[1], 0x00);
    }

    #[test]
    fn loopback_exchange_buffer_too_small() {
        let mut t = LoopbackTransport;
        let mut rsp = [0u8; 1]; // too small for 2-byte SW
        let err = t.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap_err();
        assert_eq!(err, TransportError::BufferTooSmall);
    }

    // -- Mock CardTransport --

    struct MockCardTransport {
        events: &'static [CardEvent],
        idx: usize,
    }

    impl CardTransport for MockCardTransport {
        type Error = TransportError;
        fn recv(&mut self, buf: &mut [u8]) -> Result<CardEvent, Self::Error> {
            if self.idx >= self.events.len() {
                return Err(TransportError::Disconnected);
            }
            let ev = self.events[self.idx];
            self.idx += 1;
            // For Apdu events, write dummy command bytes.
            if let CardEvent::Apdu(len) = ev {
                if buf.len() < len {
                    return Err(TransportError::BufferTooSmall);
                }
                // Fill with SELECT MF pattern for testing.
                let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
                let copy_len = len.min(select_mf.len());
                buf[..copy_len].copy_from_slice(&select_mf[..copy_len]);
            }
            Ok(ev)
        }

        fn send(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn send_atr(&mut self, _atr: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn card_transport_recv_power_on() {
        let mut ct = MockCardTransport {
            events: &[CardEvent::PowerOn],
            idx: 0,
        };
        let mut buf = [0u8; 261];
        let ev = ct.recv(&mut buf).unwrap();
        assert_eq!(ev, CardEvent::PowerOn);
    }

    #[test]
    fn card_transport_recv_apdu() {
        let mut ct = MockCardTransport {
            events: &[CardEvent::Apdu(7)],
            idx: 0,
        };
        let mut buf = [0u8; 261];
        let ev = ct.recv(&mut buf).unwrap();
        assert_eq!(ev, CardEvent::Apdu(7));
        assert_eq!(&buf[..4], &[0x00, 0xA4, 0x00, 0x04]);
    }

    #[test]
    fn card_transport_recv_warm_reset() {
        let mut ct = MockCardTransport {
            events: &[CardEvent::WarmReset],
            idx: 0,
        };
        let mut buf = [0u8; 261];
        let ev = ct.recv(&mut buf).unwrap();
        assert_eq!(ev, CardEvent::WarmReset);
    }

    #[test]
    fn card_transport_recv_shutdown() {
        let mut ct = MockCardTransport {
            events: &[CardEvent::Shutdown],
            idx: 0,
        };
        let mut buf = [0u8; 261];
        let ev = ct.recv(&mut buf).unwrap();
        assert_eq!(ev, CardEvent::Shutdown);
    }

    #[test]
    fn card_transport_recv_after_exhausted() {
        let mut ct = MockCardTransport {
            events: &[],
            idx: 0,
        };
        let mut buf = [0u8; 261];
        let err = ct.recv(&mut buf).unwrap_err();
        assert_eq!(err, TransportError::Disconnected);
    }

    #[test]
    fn card_transport_send_succeeds() {
        let mut ct = MockCardTransport {
            events: &[],
            idx: 0,
        };
        ct.send(&[0x90, 0x00]).unwrap();
    }

    #[test]
    fn card_transport_send_atr_succeeds() {
        let mut ct = MockCardTransport {
            events: &[],
            idx: 0,
        };
        ct.send_atr(&[0x3B, 0x9F, 0x96, 0x80]).unwrap();
    }

    #[test]
    fn card_event_equality() {
        assert_eq!(CardEvent::PowerOn, CardEvent::PowerOn);
        assert_eq!(CardEvent::WarmReset, CardEvent::WarmReset);
        assert_eq!(CardEvent::Apdu(5), CardEvent::Apdu(5));
        assert_ne!(CardEvent::Apdu(5), CardEvent::Apdu(6));
        assert_ne!(CardEvent::PowerOn, CardEvent::WarmReset);
        assert_ne!(CardEvent::PowerOn, CardEvent::Shutdown);
    }

    /// Format a `Display` impl into a fixed buffer for `no_std` testing.
    fn display(e: TransportError) -> &'static str {
        match e {
            TransportError::BufferTooSmall => "response buffer too small",
            TransportError::Disconnected => "peer disconnected",
            TransportError::IoError => "I/O error on transport channel",
            TransportError::InvalidMessage => "invalid message format",
            TransportError::Timeout => "transport operation timed out",
        }
    }

    #[test]
    fn transport_error_display() {
        // Verify Display impl matches expected strings by writing into a
        // stack buffer via core::fmt::Write.
        use core::fmt::Write;
        let mut buf = [0u8; 64];

        for variant in &[
            TransportError::BufferTooSmall,
            TransportError::Disconnected,
            TransportError::IoError,
            TransportError::InvalidMessage,
            TransportError::Timeout,
        ] {
            struct StackWriter<'a> {
                buf: &'a mut [u8],
                pos: usize,
            }
            impl Write for StackWriter<'_> {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    let bytes = s.as_bytes();
                    if self.pos + bytes.len() > self.buf.len() {
                        return Err(core::fmt::Error);
                    }
                    self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
                    self.pos += bytes.len();
                    Ok(())
                }
            }

            let pos = {
                let mut w = StackWriter { buf: &mut buf, pos: 0 };
                write!(w, "{variant}").unwrap();
                w.pos
            };
            let written = core::str::from_utf8(&buf[..pos]).unwrap();
            assert_eq!(written, display(*variant));
        }
    }

    // -- Sequence test: full event loop pattern --

    #[test]
    fn full_event_loop_pattern() {
        let mut ct = MockCardTransport {
            events: &[
                CardEvent::PowerOn,
                CardEvent::Apdu(7),
                CardEvent::WarmReset,
                CardEvent::Apdu(4),
                CardEvent::Shutdown,
            ],
            idx: 0,
        };
        let mut buf = [0u8; 261];
        let mut event_count = 0;

        loop {
            match ct.recv(&mut buf) {
                Ok(CardEvent::PowerOn | CardEvent::WarmReset) => {
                    ct.send_atr(&[0x3B, 0x00]).unwrap();
                    event_count += 1;
                }
                Ok(CardEvent::Apdu(len)) => {
                    assert!(len >= 4);
                    ct.send(&[0x90, 0x00]).unwrap();
                    event_count += 1;
                }
                Ok(CardEvent::Shutdown) => {
                    event_count += 1;
                    break;
                }
                Err(_) => break,
            }
        }

        assert_eq!(event_count, 5);
    }
}
