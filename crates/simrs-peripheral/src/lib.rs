//! SIM hardware slot abstraction trait.
//!
//! Defines the [`SimPeripheral`] trait representing a physical or virtual SIM
//! card slot. Implementations may be: a Shannon baseband MMIO controller,
//! a Linux ioctl interface, a `VirtIO` smart card device, or a test stub.
//!
//! # Design
//!
//! | Trait | Perspective | Use case |
//! |-------|------------|----------|
//! | [`SimPeripheral`] | **Host / driver** | Power on/off, reset, exchange APDUs |
//!
//! The trait models the lifecycle of a SIM card slot: power on (returns ATR),
//! exchange APDUs, reset, and power off. Implementations are responsible for
//! the underlying transport (MMIO, ioctl, virtqueue, etc.).
//!
//! # `no_std`
//!
//! This crate contains only trait definitions, an error enum, and is fully
//! `no_std` with zero dependencies beyond `core`.
//!
//! # Example
//!
//! ```
//! use simrs_peripheral::{SimPeripheral, PeripheralError};
//!
//! struct StubSlot { powered: bool }
//!
//! impl SimPeripheral for StubSlot {
//!     type Error = PeripheralError;
//!     fn power_on(&mut self) -> Result<&'static [u8], Self::Error> {
//!         self.powered = true;
//!         Ok(&[0x3B, 0x00]) // minimal ATR
//!     }
//!     fn power_off(&mut self) -> Result<(), Self::Error> {
//!         self.powered = false;
//!         Ok(())
//!     }
//!     fn reset(&mut self) -> Result<(), Self::Error> {
//!         if !self.powered { return Err(PeripheralError::NotPowered); }
//!         Ok(())
//!     }
//!     fn exchange(&mut self, _cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
//!         if !self.powered { return Err(PeripheralError::NotPowered); }
//!         if rsp.len() < 2 { return Err(PeripheralError::BufferTooSmall); }
//!         rsp[0] = 0x90;
//!         rsp[1] = 0x00;
//!         Ok(2)
//!     }
//!     fn is_powered(&self) -> bool { self.powered }
//! }
//!
//! let mut slot = StubSlot { powered: false };
//! let atr = slot.power_on().unwrap();
//! assert_eq!(atr, &[0x3B, 0x00]);
//! assert!(slot.is_powered());
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// PeripheralError
// ---------------------------------------------------------------------------

/// Errors that can occur during SIM peripheral operations.
///
/// Intentionally coarse-grained; concrete implementations may carry
/// additional detail in their own error types and convert via `From`.
///
/// # Example
///
/// ```
/// use simrs_peripheral::PeripheralError;
/// let e = PeripheralError::NotPowered;
/// assert_eq!(e, PeripheralError::NotPowered);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeripheralError {
    /// The SIM slot is not powered on.
    NotPowered,
    /// The response buffer is too small for the incoming data.
    BufferTooSmall,
    /// An I/O or driver-level error occurred.
    IoError,
    /// The command is invalid or unsupported.
    InvalidCommand,
    /// The SIM card was removed from the slot.
    CardRemoved,
    /// A timeout expired before the operation completed.
    Timeout,
}

impl core::fmt::Display for PeripheralError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotPowered => f.write_str("SIM slot not powered"),
            Self::BufferTooSmall => f.write_str("response buffer too small"),
            Self::IoError => f.write_str("I/O error on SIM peripheral"),
            Self::InvalidCommand => f.write_str("invalid command"),
            Self::CardRemoved => f.write_str("SIM card removed"),
            Self::Timeout => f.write_str("peripheral operation timed out"),
        }
    }
}

// ---------------------------------------------------------------------------
// SimPeripheral trait
// ---------------------------------------------------------------------------

/// Abstraction over a physical or virtual SIM card slot.
///
/// Models the lifecycle of a SIM slot: power on (returns ATR), exchange
/// APDUs, reset, and power off.
///
/// # Contract
///
/// - [`power_on`](Self::power_on) powers the card and returns the ATR.
///   Calling it when already powered is implementation-defined (may return
///   the cached ATR or re-power).
/// - [`exchange`](Self::exchange) sends a command APDU and receives the
///   response (data + SW1 SW2). The card must be powered.
/// - [`reset`](Self::reset) performs a warm reset. The card must be powered.
/// - [`power_off`](Self::power_off) powers down the card. Subsequent
///   [`exchange`](Self::exchange) calls should return an error.
/// - [`is_powered`](Self::is_powered) returns whether the slot is currently
///   powered.
///
/// # Example
///
/// ```rust,ignore
/// fn run(slot: &mut impl SimPeripheral) {
///     let atr = slot.power_on().unwrap();
///     // ... exchange APDUs ...
///     slot.power_off().unwrap();
/// }
/// ```
pub trait SimPeripheral {
    /// Error type for this peripheral implementation.
    type Error: core::fmt::Debug;

    /// Power on the SIM card and return the ATR (Answer To Reset).
    ///
    /// The ATR is returned as a `&'static` slice; implementations must
    /// store the ATR in a static or compile-time constant.
    ///
    /// # Errors
    ///
    /// Returns an error if power-on fails (card removed, I/O error, etc.).
    fn power_on(&mut self) -> Result<&'static [u8], Self::Error>;

    /// Power off the SIM card.
    ///
    /// # Errors
    ///
    /// Returns an error if power-off fails.
    fn power_off(&mut self) -> Result<(), Self::Error>;

    /// Perform a warm reset of the SIM card.
    ///
    /// The card must be powered. After reset, the card returns to its
    /// initial state but remains powered.
    ///
    /// # Errors
    ///
    /// Returns an error if the card is not powered or the reset fails.
    fn reset(&mut self) -> Result<(), Self::Error>;

    /// Send a command APDU and receive the response.
    ///
    /// Returns the number of response bytes written into `rsp`
    /// (data + SW1 + SW2).
    ///
    /// # Errors
    ///
    /// Returns an error if the card is not powered, `rsp` is too small,
    /// or the exchange fails.
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error>;

    /// Whether the SIM slot is currently powered.
    fn is_powered(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- MockPeripheral --

    /// ATR for testing: TS=3B, T0=00 (no historical bytes, no TA/TB/TC/TD).
    const MOCK_ATR: &[u8] = &[0x3B, 0x00];

    /// A mock peripheral with a fixed response queue.
    struct MockPeripheral {
        powered: bool,
        responses: &'static [&'static [u8]],
        rsp_idx: usize,
    }

    impl MockPeripheral {
        fn new(responses: &'static [&'static [u8]]) -> Self {
            Self {
                powered: false,
                responses,
                rsp_idx: 0,
            }
        }
    }

    impl SimPeripheral for MockPeripheral {
        type Error = PeripheralError;

        fn power_on(&mut self) -> Result<&'static [u8], Self::Error> {
            self.powered = true;
            self.rsp_idx = 0;
            Ok(MOCK_ATR)
        }

        fn power_off(&mut self) -> Result<(), Self::Error> {
            self.powered = false;
            Ok(())
        }

        fn reset(&mut self) -> Result<(), Self::Error> {
            if !self.powered {
                return Err(PeripheralError::NotPowered);
            }
            self.rsp_idx = 0;
            Ok(())
        }

        fn exchange(&mut self, _cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
            if !self.powered {
                return Err(PeripheralError::NotPowered);
            }
            if self.rsp_idx >= self.responses.len() {
                return Err(PeripheralError::IoError);
            }
            let data = self.responses[self.rsp_idx];
            if rsp.len() < data.len() {
                return Err(PeripheralError::BufferTooSmall);
            }
            rsp[..data.len()].copy_from_slice(data);
            self.rsp_idx += 1;
            Ok(data.len())
        }

        fn is_powered(&self) -> bool {
            self.powered
        }
    }

    // -- Power lifecycle tests --

    #[test]
    fn power_on_returns_atr() {
        let mut p = MockPeripheral::new(&[]);
        let atr = p.power_on().unwrap();
        assert_eq!(atr, MOCK_ATR);
        assert!(p.is_powered());
    }

    #[test]
    fn power_off_clears_powered() {
        let mut p = MockPeripheral::new(&[]);
        p.power_on().unwrap();
        assert!(p.is_powered());
        p.power_off().unwrap();
        assert!(!p.is_powered());
    }

    #[test]
    fn not_powered_initially() {
        let p = MockPeripheral::new(&[]);
        assert!(!p.is_powered());
    }

    #[test]
    fn exchange_when_not_powered_returns_error() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00]]);
        let mut rsp = [0u8; 258];
        let err = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap_err();
        assert_eq!(err, PeripheralError::NotPowered);
    }

    #[test]
    fn reset_when_not_powered_returns_error() {
        let mut p = MockPeripheral::new(&[]);
        let err = p.reset().unwrap_err();
        assert_eq!(err, PeripheralError::NotPowered);
    }

    // -- Exchange tests --

    #[test]
    fn exchange_returns_queued_response() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00]]);
        p.power_on().unwrap();
        let mut rsp = [0u8; 258];
        let n = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&rsp[..n], &[0x90, 0x00]);
    }

    #[test]
    fn exchange_returns_data_plus_sw() {
        let mut p = MockPeripheral::new(&[&[0x6F, 0x10, 0x90, 0x00]]);
        p.power_on().unwrap();
        let mut rsp = [0u8; 258];
        let n = p
            .exchange(&[0x00, 0xA4, 0x04, 0x04, 0x02, 0x3F, 0x00], &mut rsp)
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(&rsp[..n], &[0x6F, 0x10, 0x90, 0x00]);
    }

    #[test]
    fn exchange_multiple_commands() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00], &[0x6A, 0x82], &[0x61, 0x10]]);
        p.power_on().unwrap();
        let mut rsp = [0u8; 258];

        let n = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        assert_eq!(&rsp[..n], &[0x90, 0x00]);

        let n = p.exchange(&[0x00, 0xB0, 0x00, 0x00], &mut rsp).unwrap();
        assert_eq!(&rsp[..n], &[0x6A, 0x82]);

        let n = p
            .exchange(&[0x00, 0xC0, 0x00, 0x00, 0x10], &mut rsp)
            .unwrap();
        assert_eq!(&rsp[..n], &[0x61, 0x10]);
    }

    #[test]
    fn exchange_buffer_too_small() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00]]);
        p.power_on().unwrap();
        let mut rsp = [0u8; 1]; // too small for 2-byte response
        let err = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap_err();
        assert_eq!(err, PeripheralError::BufferTooSmall);
    }

    #[test]
    fn exchange_exhausted_returns_io_error() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00]]);
        p.power_on().unwrap();
        let mut rsp = [0u8; 258];
        p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        // Second exchange: no more queued responses.
        let err = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap_err();
        assert_eq!(err, PeripheralError::IoError);
    }

    // -- Reset tests --

    #[test]
    fn reset_resets_response_index() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00]]);
        p.power_on().unwrap();
        let mut rsp = [0u8; 258];
        p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        // Exhausted -- reset should let us exchange again.
        p.reset().unwrap();
        let n = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        assert_eq!(&rsp[..n], &[0x90, 0x00]);
    }

    #[test]
    fn reset_preserves_power_state() {
        let mut p = MockPeripheral::new(&[]);
        p.power_on().unwrap();
        p.reset().unwrap();
        assert!(p.is_powered());
    }

    // -- Power cycle tests --

    #[test]
    fn power_cycle_resets_state() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00]]);
        p.power_on().unwrap();
        let mut rsp = [0u8; 258];
        p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        p.power_off().unwrap();
        assert!(!p.is_powered());
        // Re-power: response index should be reset.
        p.power_on().unwrap();
        let n = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap();
        assert_eq!(&rsp[..n], &[0x90, 0x00]);
    }

    #[test]
    fn exchange_after_power_off_returns_error() {
        let mut p = MockPeripheral::new(&[&[0x90, 0x00]]);
        p.power_on().unwrap();
        p.power_off().unwrap();
        let mut rsp = [0u8; 258];
        let err = p.exchange(&[0x00, 0xA4, 0x00, 0x00], &mut rsp).unwrap_err();
        assert_eq!(err, PeripheralError::NotPowered);
    }

    // -- PeripheralError Display --

    #[test]
    fn error_display() {
        use core::fmt::Write;

        let cases: &[(PeripheralError, &str)] = &[
            (PeripheralError::NotPowered, "SIM slot not powered"),
            (PeripheralError::BufferTooSmall, "response buffer too small"),
            (PeripheralError::IoError, "I/O error on SIM peripheral"),
            (PeripheralError::InvalidCommand, "invalid command"),
            (PeripheralError::CardRemoved, "SIM card removed"),
            (PeripheralError::Timeout, "peripheral operation timed out"),
        ];

        for (variant, expected) in cases {
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

            let mut buf = [0u8; 64];
            let pos = {
                let mut w = StackWriter {
                    buf: &mut buf,
                    pos: 0,
                };
                write!(w, "{variant}").unwrap();
                w.pos
            };
            let written = core::str::from_utf8(&buf[..pos]).unwrap();
            assert_eq!(written, *expected);
        }
    }

    // -- Error equality --

    #[test]
    fn error_equality() {
        assert_eq!(PeripheralError::NotPowered, PeripheralError::NotPowered);
        assert_eq!(
            PeripheralError::BufferTooSmall,
            PeripheralError::BufferTooSmall
        );
        assert_ne!(PeripheralError::NotPowered, PeripheralError::IoError);
        assert_ne!(PeripheralError::Timeout, PeripheralError::CardRemoved);
    }
}
