//! Terminal-side TCP client for the jcardsim bridge.
//!
//! Mirrors [`simrs_jcsl::client`](../../simrs-jcsl/src/client.rs):
//! `connect` -> `power_on` -> `exchange` ... -> `power_off`, with the
//! whole path also exposed via [`simrs_transport::Transport`] for the
//! differential framework.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

use simrs_transport::{Transport, TransportError};

use crate::protocol::{CMD_APDU, CMD_POWER_OFF, CMD_POWER_ON, Frame};

/// Default read timeout on the TCP socket.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Terminal-side connection to a running [`JcardsimProcess`](crate::process::JcardsimProcess).
pub struct JcardsimClient {
    stream: TcpStream,
    /// ATR from the most recent `power_on`, empty before that.
    atr: Vec<u8>,
    /// Whether the card is currently powered on.
    powered: bool,
}

impl JcardsimClient {
    /// Connect to a jcardsim bridge at `addr` (e.g. `"127.0.0.1:9125"`).
    ///
    /// Does NOT power on the card -- call [`power_on`](Self::power_on)
    /// to do that.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] on TCP connect or
    /// `set_*_timeout` failure.
    pub fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(DEFAULT_TIMEOUT))?;
        stream.set_write_timeout(Some(DEFAULT_TIMEOUT))?;
        Ok(Self {
            stream,
            atr: Vec::new(),
            powered: false,
        })
    }

    /// Send a cold reset and receive the ATR.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if framing fails or the bridge responds
    /// with a non-`CMD_POWER_ON` frame.
    pub fn power_on(&mut self) -> Result<&[u8], TransportError> {
        let req = Frame::new(CMD_POWER_ON, Vec::new());
        req.write_to(&mut self.stream).map_err(|e| map_io_err(&e))?;
        let rsp = Frame::read_from(&mut self.stream).map_err(|e| map_io_err(&e))?;
        if rsp.cmd_type != CMD_POWER_ON {
            return Err(TransportError::InvalidMessage);
        }
        self.atr = rsp.payload;
        self.powered = true;
        Ok(&self.atr)
    }

    /// Send a power-off notification. Subsequent APDUs will fail until
    /// [`power_on`](Self::power_on) is called again.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] on framing / I/O failure.
    pub fn power_off(&mut self) -> Result<(), TransportError> {
        let req = Frame::new(CMD_POWER_OFF, Vec::new());
        req.write_to(&mut self.stream).map_err(|e| map_io_err(&e))?;
        let rsp = Frame::read_from(&mut self.stream).map_err(|e| map_io_err(&e))?;
        if rsp.cmd_type != CMD_POWER_OFF {
            return Err(TransportError::InvalidMessage);
        }
        self.powered = false;
        Ok(())
    }

    /// Whether `power_on` has been called and `power_off` has not.
    #[must_use]
    pub const fn is_powered(&self) -> bool {
        self.powered
    }

    /// ATR from the most recent `power_on`. Empty before then.
    #[must_use]
    pub fn atr(&self) -> &[u8] {
        &self.atr
    }
}

impl Transport for JcardsimClient {
    type Error = TransportError;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.powered {
            return Err(TransportError::IoError);
        }
        let req = Frame::new(CMD_APDU, cmd.to_vec());
        req.write_to(&mut self.stream).map_err(|e| map_io_err(&e))?;
        let frame = Frame::read_from(&mut self.stream).map_err(|e| map_io_err(&e))?;
        if frame.cmd_type != CMD_APDU {
            return Err(TransportError::InvalidMessage);
        }
        if frame.payload.len() > rsp.len() {
            return Err(TransportError::BufferTooSmall);
        }
        rsp[..frame.payload.len()].copy_from_slice(&frame.payload);
        Ok(frame.payload.len())
    }
}

/// Map low-level I/O errors to transport-level errors.
///
/// Same classification as `simrs-transport-tcp`: peer-closed signals
/// collapse to `Disconnected`; the rest are `IoError`.
fn map_io_err(e: &io::Error) -> TransportError {
    use io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    match e.kind() {
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => {
            TransportError::Disconnected
        }
        _ => TransportError::IoError,
    }
}
