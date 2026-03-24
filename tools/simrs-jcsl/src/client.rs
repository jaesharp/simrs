//! TCP client for the Oracle jcsl simulator.
//!
//! Implements [`simrs_transport::Transport`] over the Oracle RAW
//! wire protocol, enabling the jcsl simulator to be used as a
//! reference card for differential testing.

use crate::protocol::{self, Frame};
use simrs_transport::{Transport, TransportError};
use std::io;
use std::net::TcpStream;
use std::time::Duration;

/// Default read timeout for the TCP connection.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Client connection to a running jcsl simulator.
///
/// # Example
///
/// ```rust,no_run
/// use simrs_jcsl::JcslClient;
/// use simrs_transport::Transport;
///
/// let mut client = JcslClient::connect("127.0.0.1:9025").unwrap();
/// let atr = client.power_on().unwrap();
/// println!("ATR: {:02x?}", atr);
///
/// let mut rsp = [0u8; 258];
/// let n = client.exchange(
///     &[0x00, 0xA4, 0x04, 0x00, 0x00],
///     &mut rsp,
/// ).unwrap();
/// println!("Response: {:02x?}", &rsp[..n]);
///
/// client.power_off().unwrap();
/// ```
pub struct JcslClient {
    stream: TcpStream,
    /// ATR received from the last power-on.
    atr: Vec<u8>,
    /// Whether the card is currently powered on.
    powered: bool,
}

impl JcslClient {
    /// Connect to a jcsl simulator at the given address.
    ///
    /// Does NOT send Power ON -- call [`power_on`](Self::power_on) to
    /// initialize the card.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the TCP connection cannot be established.
    pub fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(DEFAULT_TIMEOUT))?;
        stream.set_write_timeout(Some(DEFAULT_TIMEOUT))?;
        stream.set_nodelay(true)?;

        Ok(Self {
            stream,
            atr: Vec::new(),
            powered: false,
        })
    }

    /// Connect with a custom timeout.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the address is invalid or the connection
    /// cannot be established within the given timeout.
    pub fn connect_with_timeout(addr: &str, timeout: Duration) -> io::Result<Self> {
        let sock_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let stream = TcpStream::connect_timeout(&sock_addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;

        Ok(Self {
            stream,
            atr: Vec::new(),
            powered: false,
        })
    }

    /// Send Power ON and receive the ATR.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the frame cannot be sent or the simulator
    /// does not respond.
    pub fn power_on(&mut self) -> io::Result<Vec<u8>> {
        let frame = protocol::power_on_frame();
        protocol::write_frame(&mut self.stream, &frame)?;

        let response = protocol::read_frame(&mut self.stream)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "no response to power on"))?;

        self.atr.clone_from(&response.payload);
        self.powered = true;
        Ok(response.payload)
    }

    /// Send Power OFF.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the frame cannot be sent.
    pub fn power_off(&mut self) -> io::Result<()> {
        let frame = protocol::power_off_frame();
        protocol::write_frame(&mut self.stream, &frame)?;
        self.powered = false;
        // Some implementations send a response, some don't.
        // Try to read but don't fail if the stream is closed.
        let _ = protocol::read_frame(&mut self.stream);
        Ok(())
    }

    /// Send a raw APDU and receive the response (data + SW1 SW2).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the card is not powered on, the frame
    /// cannot be sent, or the simulator does not respond.
    pub fn transmit_apdu(&mut self, apdu: &[u8]) -> io::Result<Vec<u8>> {
        if !self.powered {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "card is not powered on",
            ));
        }

        let frame = protocol::apdu_frame(apdu);
        protocol::write_frame(&mut self.stream, &frame)?;

        let response = protocol::read_frame(&mut self.stream)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionReset, "no response to APDU")
            })?;

        Ok(response.payload)
    }

    /// Get the ATR from the last power-on.
    pub fn atr(&self) -> &[u8] {
        &self.atr
    }

    /// Whether the card is currently powered on.
    pub const fn is_powered(&self) -> bool {
        self.powered
    }

    /// Send a raw frame and receive the response.
    ///
    /// Low-level method for protocol exploration.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the frame cannot be sent or the
    /// response cannot be read.
    pub fn raw_exchange(&mut self, frame: &Frame) -> io::Result<Option<Frame>> {
        protocol::write_frame(&mut self.stream, frame)?;
        protocol::read_frame(&mut self.stream)
    }
}

/// [`Transport`] implementation for the jcsl client.
///
/// Assumes the card has already been powered on via [`JcslClient::power_on`].
/// Each `exchange` call sends an APDU and returns the response.
impl Transport for JcslClient {
    type Error = TransportError;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, TransportError> {
        let response = self.transmit_apdu(cmd).map_err(|_| TransportError::IoError)?;

        if response.len() > rsp.len() {
            return Err(TransportError::BufferTooSmall);
        }

        let n = response.len();
        rsp[..n].copy_from_slice(&response);
        Ok(n)
    }
}
