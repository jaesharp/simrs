//! Terminal-side TCP client for the `JCardEngine` bridge.
//!
//! Same shape as [`simrs_jcsl::client`](../../simrs-jcsl/src/client.rs):
//! `connect` -> `power_on` -> `exchange` ... -> `power_off`, plus a
//! [`simrs_transport::Transport`] implementation for the differential
//! harness.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

use simrs_transport::{Transport, TransportError};

use crate::protocol::{CMD_APDU, CMD_POWER_OFF, CMD_POWER_ON, Frame};

/// Default read/write timeout on the TCP socket.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Terminal-side connection to a running [`JcardengineProcess`].
///
/// [`JcardengineProcess`]: crate::process::JcardengineProcess
pub struct JcardengineClient {
    stream: TcpStream,
    atr: Vec<u8>,
    powered: bool,
}

impl JcardengineClient {
    /// Connect to a bridge at `addr` (e.g. `"127.0.0.1:9225"`).
    ///
    /// Does not power the card on -- call [`power_on`](Self::power_on).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] on TCP connect or timeout
    /// configuration failure.
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

    /// Send cold reset, receive ATR.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidMessage`] if the bridge
    /// response tag isn't `CMD_POWER_ON`, or [`TransportError::Disconnected`]/
    /// [`TransportError::IoError`] on transport failure.
    pub fn power_on(&mut self) -> Result<&[u8], TransportError> {
        Frame::new(CMD_POWER_ON, Vec::new())
            .write_to(&mut self.stream)
            .map_err(|e| map_io_err(&e))?;
        let rsp = Frame::read_from(&mut self.stream).map_err(|e| map_io_err(&e))?;
        if rsp.cmd_type != CMD_POWER_ON {
            return Err(TransportError::InvalidMessage);
        }
        self.atr = rsp.payload;
        self.powered = true;
        Ok(&self.atr)
    }

    /// Send power-off. Subsequent APDUs fail until the next
    /// [`power_on`](Self::power_on).
    ///
    /// # Errors
    ///
    /// As for [`power_on`](Self::power_on).
    pub fn power_off(&mut self) -> Result<(), TransportError> {
        Frame::new(CMD_POWER_OFF, Vec::new())
            .write_to(&mut self.stream)
            .map_err(|e| map_io_err(&e))?;
        let rsp = Frame::read_from(&mut self.stream).map_err(|e| map_io_err(&e))?;
        if rsp.cmd_type != CMD_POWER_OFF {
            return Err(TransportError::InvalidMessage);
        }
        self.powered = false;
        Ok(())
    }

    /// Whether the card is currently powered on.
    #[must_use]
    pub const fn is_powered(&self) -> bool {
        self.powered
    }

    /// ATR captured from the most recent `power_on`.
    #[must_use]
    pub fn atr(&self) -> &[u8] {
        &self.atr
    }
}

impl Transport for JcardengineClient {
    type Error = TransportError;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.powered {
            return Err(TransportError::IoError);
        }
        Frame::new(CMD_APDU, cmd.to_vec())
            .write_to(&mut self.stream)
            .map_err(|e| map_io_err(&e))?;
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

/// Peer-closed TCP errors collapse to `Disconnected`; others to `IoError`.
/// Mirrors the classification used by `simrs-transport-tcp` so callers
/// don't care which endpoint closed first.
fn map_io_err(e: &io::Error) -> TransportError {
    use io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    match e.kind() {
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => {
            TransportError::Disconnected
        }
        _ => TransportError::IoError,
    }
}
