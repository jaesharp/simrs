//! TCP transport for the swICC PC/SC server protocol.
//!
//! Implements [`CardTransport`] over a TCP socket, connecting to a swICC
//! network server (or any compatible PC/SC server) as the **card** side.
//!
//! # Protocol
//!
//! The swICC wire protocol uses a packed binary message format:
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//!   0      4    hdr.size     -- payload byte count (LE u32)
//!   4      4    cont_state   -- contact state bitmask (LE u32)
//!   8      4    buf_len_exp  -- expected buffer length (LE u32)
//!  12      1    ctrl         -- control / status byte
//!  13    0-258  buf          -- APDU data (max `SWICC_DATA_MAX` + 2)
//! ```
//!
//! Total maximum message size: 4 + 4 + 4 + 1 + 258 = 271 bytes.
//!
//! # Standards
//!
//! Interoperates with the swICC network protocol (not formally standardized;
//! based on the [swICC open-source PC/SC bridge](https://github.com/tomasz-lisowski/swicc)).
//!
//! # `std` required
//!
//! This crate uses [`std::net::TcpStream`] and is **not** `no_std`.
//! For `no_std` alternatives see `simrs-transport-shmem` or
//! `simrs-transport-virtio`.
//!
//! # Usage
//!
//! ```rust,no_run
//! use simrs_transport_tcp::SwIccClient;
//! use simrs_transport::CardTransport;
//!
//! let mut client = SwIccClient::connect("127.0.0.1:37324").unwrap();
//! // Now use client.recv() / client.send() / client.send_atr()
//! // in an event loop with a Sim instance.
//! ```
#![deny(unsafe_code)]
#![warn(missing_docs)]

use simrs_transport::{CardEvent, CardTransport, Transport, TransportError};
use std::io::{Read, Write};
use std::net::TcpStream;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default swICC server address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:37324";

/// Maximum APDU data size (short APDUs only: 256 data + 2 SW).
const SWICC_DATA_MAX: usize = 256;

/// Maximum buf field size in a swICC message.
const BUF_MAX: usize = SWICC_DATA_MAX + 2; // 258

/// Header size: the 4-byte `hdr.size` field.
const HDR_SIZE: usize = 4;

/// Data section overhead: `cont_state` (4) + `buf_len_exp` (4) + `ctrl` (1) = 9.
const DATA_OVERHEAD: usize = 9;

/// Maximum data section size: overhead + buf.
const DATA_MAX: usize = DATA_OVERHEAD + BUF_MAX; // 267

/// Total maximum message size on the wire.
pub const MSG_MAX: usize = HDR_SIZE + DATA_MAX; // 271

// ---------------------------------------------------------------------------
// Control byte values
// ---------------------------------------------------------------------------

/// Control byte values for the swICC network protocol.
///
/// Request values are sent by the server to the card.
/// Response values are sent by the card back to the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctrl {
    /// Normal data/APDU message (no special control).
    None = 0,
    /// Keep-alive ping from server.
    Keepalive = 1,
    /// Cold reset with PPS negotiation.
    MockResetColdPpsY = 2,
    /// Warm reset with PPS negotiation.
    MockResetWarmPpsY = 3,
    /// Cold reset without PPS negotiation.
    MockResetColdPpsN = 4,
    /// Warm reset without PPS negotiation.
    MockResetWarmPpsN = 5,
    /// Card response: success.
    Success = 0xF0,
    /// Card response: failure.
    Failure = 0x0F,
}

impl Ctrl {
    /// Parse a control byte value.
    ///
    /// # Errors
    ///
    /// Returns `None` for unrecognised values.
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Keepalive),
            2 => Some(Self::MockResetColdPpsY),
            3 => Some(Self::MockResetWarmPpsY),
            4 => Some(Self::MockResetColdPpsN),
            5 => Some(Self::MockResetWarmPpsN),
            0xF0 => Some(Self::Success),
            0x0F => Some(Self::Failure),
            _ => None,
        }
    }

    /// Whether this control value represents a reset request.
    pub const fn is_reset(self) -> bool {
        matches!(
            self,
            Self::MockResetColdPpsY
                | Self::MockResetColdPpsN
                | Self::MockResetWarmPpsY
                | Self::MockResetWarmPpsN
        )
    }

    /// Whether this control value represents a cold reset.
    pub const fn is_cold_reset(self) -> bool {
        matches!(self, Self::MockResetColdPpsY | Self::MockResetColdPpsN)
    }
}

// ---------------------------------------------------------------------------
// SwIccMessage
// ---------------------------------------------------------------------------

/// A decoded swICC network protocol message.
///
/// This struct represents the parsed content of a single swICC message,
/// separated from wire encoding for testability.
///
/// # Example
///
/// ```
/// use simrs_transport_tcp::SwIccMessage;
/// use simrs_transport_tcp::Ctrl;
///
/// let msg = SwIccMessage::new_response(Ctrl::Success, &[0x90, 0x00], 0);
/// assert_eq!(msg.ctrl, Ctrl::Success);
/// assert_eq!(msg.buf_len(), 2);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwIccMessage {
    /// Contact state bitmask.
    pub cont_state: u32,
    /// Expected buffer length (used by server to tell card how much to read).
    pub buf_len_exp: u32,
    /// Control / status byte.
    pub ctrl: Ctrl,
    buf: [u8; BUF_MAX],
    buf_len: usize,
}

impl SwIccMessage {
    /// Create a new empty message with the given control byte.
    pub const fn new(ctrl: Ctrl) -> Self {
        Self {
            cont_state: 0,
            buf_len_exp: 0,
            ctrl,
            buf: [0u8; BUF_MAX],
            buf_len: 0,
        }
    }

    /// Create a response message with data.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` exceeds `BUF_MAX` (258).
    pub fn new_response(ctrl: Ctrl, data: &[u8], cont_state: u32) -> Self {
        assert!(
            data.len() <= BUF_MAX,
            "data length {} exceeds BUF_MAX ({})",
            data.len(),
            BUF_MAX,
        );
        let mut msg = Self::new(ctrl);
        msg.cont_state = cont_state;
        msg.buf[..data.len()].copy_from_slice(data);
        msg.buf_len = data.len();
        msg
    }

    /// The APDU / data buffer contents.
    pub fn buf(&self) -> &[u8] {
        &self.buf[..self.buf_len]
    }

    /// Length of data in the buffer.
    pub const fn buf_len(&self) -> usize {
        self.buf_len
    }

    /// Encode this message into the wire format.
    ///
    /// Returns the number of bytes written into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::BufferTooSmall`] if `out` is too small.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, TransportError> {
        let payload_size = DATA_OVERHEAD + self.buf_len;
        let total = HDR_SIZE + payload_size;
        if out.len() < total {
            return Err(TransportError::BufferTooSmall);
        }

        // Header: payload size as little-endian u32 (matches C swICC server).
        // payload_size is bounded by DATA_MAX (267), always fits in u32.
        #[allow(clippy::cast_possible_truncation)]
        let size_le = (payload_size as u32).to_le_bytes();
        out[..4].copy_from_slice(&size_le);

        // cont_state
        out[4..8].copy_from_slice(&self.cont_state.to_le_bytes());

        // buf_len_exp
        out[8..12].copy_from_slice(&self.buf_len_exp.to_le_bytes());

        // ctrl
        out[12] = self.ctrl as u8;

        // buf
        out[13..13 + self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);

        Ok(total)
    }

    /// Decode a message from wire bytes.
    ///
    /// `data` must contain the complete message (header + payload).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidMessage`] if the data is malformed.
    pub fn decode(data: &[u8]) -> Result<Self, TransportError> {
        if data.len() < HDR_SIZE + DATA_OVERHEAD {
            return Err(TransportError::InvalidMessage);
        }

        let payload_size =
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

        if payload_size < DATA_OVERHEAD {
            return Err(TransportError::InvalidMessage);
        }
        if payload_size > DATA_MAX {
            return Err(TransportError::InvalidMessage);
        }
        if data.len() < HDR_SIZE + payload_size {
            return Err(TransportError::InvalidMessage);
        }

        let cont_state = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let buf_len_exp = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let ctrl_byte = data[12];
        let ctrl = Ctrl::from_u8(ctrl_byte).ok_or(TransportError::InvalidMessage)?;

        let buf_len = payload_size - DATA_OVERHEAD;
        let mut msg = Self::new(ctrl);
        msg.cont_state = cont_state;
        msg.buf_len_exp = buf_len_exp;
        msg.buf[..buf_len].copy_from_slice(&data[13..13 + buf_len]);
        msg.buf_len = buf_len;

        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// SwIccClient
// ---------------------------------------------------------------------------

/// A swICC network protocol client (card side).
///
/// Connects to a swICC PC/SC server over TCP and implements
/// [`CardTransport`] to bridge APDUs between the server and a SIM state
/// machine.
///
/// # Wire endianness
///
/// All multi-byte integers are transmitted in **little-endian** byte
/// order, matching the C swICC server which uses native (x86) byte order
/// without any `htonl`/`ntohl` conversion.
pub struct SwIccClient {
    stream: TcpStream,
    /// Wire buffer for sending/receiving complete messages.
    wire_buf: [u8; MSG_MAX],
}

impl SwIccClient {
    /// Connect to a swICC PC/SC server at the given address.
    ///
    /// The address should be in `"host:port"` format (e.g. `"127.0.0.1:37324"`).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoError`] if the TCP connection fails.
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(addr).map_err(|_| TransportError::IoError)?;
        Ok(Self {
            stream,
            wire_buf: [0u8; MSG_MAX],
        })
    }

    /// Create a client from an already-connected `TcpStream`.
    ///
    /// Useful for testing or when the connection is established externally.
    pub const fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream,
            wire_buf: [0u8; MSG_MAX],
        }
    }

    /// Send a [`SwIccMessage`] over the wire.
    fn send_msg(&mut self, msg: &SwIccMessage) -> Result<(), TransportError> {
        let n = msg.encode(&mut self.wire_buf)?;
        self.stream
            .write_all(&self.wire_buf[..n])
            .map_err(|_| TransportError::IoError)
    }

    /// Receive a [`SwIccMessage`] from the wire.
    fn recv_msg(&mut self) -> Result<SwIccMessage, TransportError> {
        // Read header (4 bytes).
        read_exact(&mut self.stream, &mut self.wire_buf[..HDR_SIZE])?;

        let payload_size = u32::from_le_bytes([
            self.wire_buf[0],
            self.wire_buf[1],
            self.wire_buf[2],
            self.wire_buf[3],
        ]) as usize;

        if !(DATA_OVERHEAD..=DATA_MAX).contains(&payload_size) {
            return Err(TransportError::InvalidMessage);
        }

        // Read payload.
        read_exact(
            &mut self.stream,
            &mut self.wire_buf[HDR_SIZE..HDR_SIZE + payload_size],
        )?;

        SwIccMessage::decode(&self.wire_buf[..HDR_SIZE + payload_size])
    }

    /// Handle a keepalive by responding immediately.
    fn handle_keepalive(&mut self) -> Result<(), TransportError> {
        let rsp = SwIccMessage::new(Ctrl::Success);
        self.send_msg(&rsp)
    }
}

/// Read exactly `buf.len()` bytes from the stream.
fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), TransportError> {
    stream.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            TransportError::Disconnected
        } else {
            TransportError::IoError
        }
    })
}

impl CardTransport for SwIccClient {
    type Error = TransportError;

    fn recv(&mut self, buf: &mut [u8]) -> Result<CardEvent, Self::Error> {
        loop {
            let msg = self.recv_msg()?;

            match msg.ctrl {
                Ctrl::Keepalive => {
                    // Auto-respond to keepalive, then continue waiting.
                    self.handle_keepalive()?;
                }
                Ctrl::MockResetColdPpsY | Ctrl::MockResetColdPpsN => {
                    return Ok(CardEvent::PowerOn);
                }
                Ctrl::MockResetWarmPpsY | Ctrl::MockResetWarmPpsN => {
                    return Ok(CardEvent::WarmReset);
                }
                Ctrl::None => {
                    // APDU data message.
                    let data = msg.buf();
                    if data.len() > buf.len() {
                        return Err(TransportError::BufferTooSmall);
                    }
                    buf[..data.len()].copy_from_slice(data);
                    return Ok(CardEvent::Apdu(data.len()));
                }
                Ctrl::Success | Ctrl::Failure => {
                    // These are response codes, not valid as server requests.
                    return Err(TransportError::InvalidMessage);
                }
            }
        }
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if data.len() > BUF_MAX {
            return Err(TransportError::BufferTooSmall);
        }
        let msg = SwIccMessage::new_response(Ctrl::Success, data, 0);
        self.send_msg(&msg)
    }

    fn send_atr(&mut self, atr: &[u8]) -> Result<(), Self::Error> {
        if atr.len() > BUF_MAX {
            return Err(TransportError::BufferTooSmall);
        }
        let msg = SwIccMessage::new_response(Ctrl::Success, atr, 0);
        self.send_msg(&msg)
    }
}

// ---------------------------------------------------------------------------
// SwIccTerminal
// ---------------------------------------------------------------------------

/// A swICC terminal-side client.
///
/// Connects to a swICC PC/SC server and sends APDU commands to the
/// virtual card connected to that server. Implements [`Transport`] for
/// the terminal (command-sending) perspective.
///
/// Use [`SwIccClient`] for the card (command-receiving) perspective.
pub struct SwIccTerminal {
    stream: TcpStream,
    /// Wire buffer for sending/receiving complete messages.
    wire_buf: [u8; MSG_MAX],
}

impl SwIccTerminal {
    /// Connect to a swICC PC/SC server at the given address.
    ///
    /// The address should be in `"host:port"` format (e.g. `"127.0.0.1:37324"`).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoError`] if the TCP connection fails.
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(addr).map_err(|_| TransportError::IoError)?;
        Ok(Self {
            stream,
            wire_buf: [0u8; MSG_MAX],
        })
    }

    /// Create a terminal from an already-connected `TcpStream`.
    ///
    /// Useful for testing or when the connection is established externally.
    pub const fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream,
            wire_buf: [0u8; MSG_MAX],
        }
    }

    /// Send a cold reset and return the ATR response.
    ///
    /// Sends [`Ctrl::MockResetColdPpsY`] and reads the response message
    /// (expected to be [`Ctrl::Success`] with ATR data).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoError`] on I/O failure, or
    /// [`TransportError::InvalidMessage`] if the response has an unexpected
    /// control byte.
    pub fn reset_cold(&mut self) -> Result<SwIccMessage, TransportError> {
        let msg = SwIccMessage::new(Ctrl::MockResetColdPpsY);
        self.send_msg(&msg)?;
        self.recv_msg()
    }

    /// Send a warm reset and return the ATR response.
    ///
    /// Sends [`Ctrl::MockResetWarmPpsY`] and reads the response message
    /// (expected to be [`Ctrl::Success`] with ATR data).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoError`] on I/O failure, or
    /// [`TransportError::InvalidMessage`] if the response has an unexpected
    /// control byte.
    pub fn reset_warm(&mut self) -> Result<SwIccMessage, TransportError> {
        let msg = SwIccMessage::new(Ctrl::MockResetWarmPpsY);
        self.send_msg(&msg)?;
        self.recv_msg()
    }

    /// Send a [`SwIccMessage`] over the wire.
    fn send_msg(&mut self, msg: &SwIccMessage) -> Result<(), TransportError> {
        let n = msg.encode(&mut self.wire_buf)?;
        self.stream
            .write_all(&self.wire_buf[..n])
            .map_err(|_| TransportError::IoError)
    }

    /// Receive a [`SwIccMessage`] from the wire.
    fn recv_msg(&mut self) -> Result<SwIccMessage, TransportError> {
        // Read header (4 bytes).
        read_exact(&mut self.stream, &mut self.wire_buf[..HDR_SIZE])?;

        let payload_size = u32::from_le_bytes([
            self.wire_buf[0],
            self.wire_buf[1],
            self.wire_buf[2],
            self.wire_buf[3],
        ]) as usize;

        if !(DATA_OVERHEAD..=DATA_MAX).contains(&payload_size) {
            return Err(TransportError::InvalidMessage);
        }

        // Read payload.
        read_exact(
            &mut self.stream,
            &mut self.wire_buf[HDR_SIZE..HDR_SIZE + payload_size],
        )?;

        SwIccMessage::decode(&self.wire_buf[..HDR_SIZE + payload_size])
    }
}

impl Transport for SwIccTerminal {
    type Error = TransportError;

    /// Send an APDU command and receive the response.
    ///
    /// Sends the command as a [`Ctrl::None`] message, reads the response
    /// (expecting [`Ctrl::Success`]), and copies response data to `rsp`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::BufferTooSmall`] if `cmd` exceeds `BUF_MAX`
    /// or `rsp` is too small for the response data.
    /// Returns [`TransportError::IoError`] if the peer sent [`Ctrl::Failure`].
    /// Returns [`TransportError::InvalidMessage`] for any other control byte.
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        if cmd.len() > BUF_MAX {
            return Err(TransportError::BufferTooSmall);
        }
        let request = SwIccMessage::new_response(Ctrl::None, cmd, 0);
        self.send_msg(&request)?;

        let msg = self.recv_msg()?;
        match msg.ctrl {
            Ctrl::Success => {
                let data = msg.buf();
                if data.len() > rsp.len() {
                    return Err(TransportError::BufferTooSmall);
                }
                rsp[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            Ctrl::Failure => Err(TransportError::IoError),
            _ => Err(TransportError::InvalidMessage),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // -- Ctrl parsing --

    #[test]
    fn ctrl_from_u8_valid() {
        assert_eq!(Ctrl::from_u8(0), Some(Ctrl::None));
        assert_eq!(Ctrl::from_u8(1), Some(Ctrl::Keepalive));
        assert_eq!(Ctrl::from_u8(2), Some(Ctrl::MockResetColdPpsY));
        assert_eq!(Ctrl::from_u8(3), Some(Ctrl::MockResetWarmPpsY));
        assert_eq!(Ctrl::from_u8(4), Some(Ctrl::MockResetColdPpsN));
        assert_eq!(Ctrl::from_u8(5), Some(Ctrl::MockResetWarmPpsN));
        assert_eq!(Ctrl::from_u8(0xF0), Some(Ctrl::Success));
        assert_eq!(Ctrl::from_u8(0x0F), Some(Ctrl::Failure));
    }

    #[test]
    fn ctrl_from_u8_invalid() {
        assert_eq!(Ctrl::from_u8(6), None);
        assert_eq!(Ctrl::from_u8(0xFF), None);
        assert_eq!(Ctrl::from_u8(0x80), None);
    }

    #[test]
    fn ctrl_is_reset() {
        assert!(Ctrl::MockResetColdPpsY.is_reset());
        assert!(Ctrl::MockResetColdPpsN.is_reset());
        assert!(Ctrl::MockResetWarmPpsY.is_reset());
        assert!(Ctrl::MockResetWarmPpsN.is_reset());
        assert!(!Ctrl::None.is_reset());
        assert!(!Ctrl::Keepalive.is_reset());
        assert!(!Ctrl::Success.is_reset());
    }

    #[test]
    fn ctrl_is_cold_reset() {
        assert!(Ctrl::MockResetColdPpsY.is_cold_reset());
        assert!(Ctrl::MockResetColdPpsN.is_cold_reset());
        assert!(!Ctrl::MockResetWarmPpsY.is_cold_reset());
        assert!(!Ctrl::MockResetWarmPpsN.is_cold_reset());
    }

    // -- Message encoding --

    #[test]
    fn encode_success_with_sw() {
        let msg = SwIccMessage::new_response(Ctrl::Success, &[0x90, 0x00], 0);
        let mut buf = [0u8; MSG_MAX];
        let n = msg.encode(&mut buf).unwrap();

        // Payload: 9 (overhead) + 2 (buf) = 11
        assert_eq!(n, HDR_SIZE + 11);
        // Header: little-endian 11
        assert_eq!(&buf[..4], &[0x0B, 0x00, 0x00, 0x00]);
        // cont_state = 0
        assert_eq!(&buf[4..8], &[0x00; 4]);
        // buf_len_exp = 0
        assert_eq!(&buf[8..12], &[0x00; 4]);
        // ctrl = SUCCESS
        assert_eq!(buf[12], 0xF0);
        // buf = [90 00]
        assert_eq!(&buf[13..15], &[0x90, 0x00]);
    }

    #[test]
    fn encode_keepalive_response() {
        let msg = SwIccMessage::new(Ctrl::Success);
        let mut buf = [0u8; MSG_MAX];
        let n = msg.encode(&mut buf).unwrap();

        // Payload: 9 (overhead) + 0 (no buf) = 9
        assert_eq!(n, HDR_SIZE + 9);
        assert_eq!(&buf[..4], &[0x09, 0x00, 0x00, 0x00]);
        assert_eq!(buf[12], 0xF0);
    }

    #[test]
    fn encode_with_cont_state() {
        let msg = SwIccMessage::new_response(Ctrl::Success, &[0x61, 0x0F], 0x0000_0001);
        let mut buf = [0u8; MSG_MAX];
        msg.encode(&mut buf).unwrap();
        assert_eq!(&buf[4..8], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_buffer_too_small() {
        let msg = SwIccMessage::new_response(Ctrl::Success, &[0x90, 0x00], 0);
        let mut buf = [0u8; 10]; // too small
        assert_eq!(msg.encode(&mut buf), Err(TransportError::BufferTooSmall));
    }

    #[test]
    fn encode_maximum_data() {
        let data = [0xAA; BUF_MAX]; // 258 bytes
        let msg = SwIccMessage::new_response(Ctrl::Success, &data, 0);
        let mut buf = [0u8; MSG_MAX];
        let n = msg.encode(&mut buf).unwrap();
        assert_eq!(n, MSG_MAX); // 271
        assert_eq!(&buf[13..MSG_MAX], &data[..]);
    }

    // -- Message decoding --

    #[test]
    fn decode_apdu_command() {
        let apdu = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let payload_size: u32 = (DATA_OVERHEAD + apdu.len()) as u32;
        let mut wire = [0u8; MSG_MAX];
        wire[..4].copy_from_slice(&payload_size.to_le_bytes());
        // cont_state = 0
        // buf_len_exp = 7
        wire[8..12].copy_from_slice(&7u32.to_le_bytes());
        // ctrl = NONE
        wire[12] = 0;
        // buf = APDU
        wire[13..13 + apdu.len()].copy_from_slice(&apdu);

        let msg =
            SwIccMessage::decode(&wire[..HDR_SIZE + payload_size as usize]).unwrap();
        assert_eq!(msg.ctrl, Ctrl::None);
        assert_eq!(msg.buf_len_exp, 7);
        assert_eq!(msg.buf(), &apdu);
    }

    #[test]
    fn decode_keepalive() {
        let payload_size: u32 = DATA_OVERHEAD as u32; // 9 bytes, no buf
        let mut wire = [0u8; HDR_SIZE + DATA_OVERHEAD];
        wire[..4].copy_from_slice(&payload_size.to_le_bytes());
        wire[12] = 1; // KEEPALIVE

        let msg = SwIccMessage::decode(&wire).unwrap();
        assert_eq!(msg.ctrl, Ctrl::Keepalive);
        assert_eq!(msg.buf_len(), 0);
    }

    #[test]
    fn decode_cold_reset() {
        let payload_size: u32 = DATA_OVERHEAD as u32;
        let mut wire = [0u8; HDR_SIZE + DATA_OVERHEAD];
        wire[..4].copy_from_slice(&payload_size.to_le_bytes());
        wire[12] = 2; // MOCK_RESET_COLD_PPS_Y

        let msg = SwIccMessage::decode(&wire).unwrap();
        assert_eq!(msg.ctrl, Ctrl::MockResetColdPpsY);
    }

    #[test]
    fn decode_too_short() {
        let wire = [0u8; 10]; // less than HDR_SIZE + DATA_OVERHEAD (13)
        assert_eq!(
            SwIccMessage::decode(&wire),
            Err(TransportError::InvalidMessage)
        );
    }

    #[test]
    fn decode_payload_size_too_small() {
        let mut wire = [0u8; HDR_SIZE + DATA_OVERHEAD];
        // Claim payload is only 5 bytes (< DATA_OVERHEAD = 9).
        wire[..4].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            SwIccMessage::decode(&wire),
            Err(TransportError::InvalidMessage)
        );
    }

    #[test]
    fn decode_payload_size_too_large() {
        let mut wire = [0u8; HDR_SIZE + DATA_OVERHEAD];
        // Claim payload is 300 bytes (> DATA_MAX = 267).
        wire[..4].copy_from_slice(&300u32.to_le_bytes());
        assert_eq!(
            SwIccMessage::decode(&wire),
            Err(TransportError::InvalidMessage)
        );
    }

    #[test]
    fn decode_unknown_ctrl() {
        let payload_size: u32 = DATA_OVERHEAD as u32;
        let mut wire = [0u8; HDR_SIZE + DATA_OVERHEAD];
        wire[..4].copy_from_slice(&payload_size.to_le_bytes());
        wire[12] = 0x77; // unknown ctrl value
        assert_eq!(
            SwIccMessage::decode(&wire),
            Err(TransportError::InvalidMessage)
        );
    }

    #[test]
    fn decode_truncated_payload() {
        let mut wire = [0u8; HDR_SIZE + DATA_OVERHEAD];
        // Claim 20 bytes of payload but only provide 9.
        wire[..4].copy_from_slice(&20u32.to_le_bytes());
        wire[12] = 0; // Ctrl::None
        assert_eq!(
            SwIccMessage::decode(&wire),
            Err(TransportError::InvalidMessage)
        );
    }

    // -- Encode/decode round-trip --

    #[test]
    fn encode_decode_roundtrip_empty() {
        let orig = SwIccMessage::new(Ctrl::Success);
        let mut wire = [0u8; MSG_MAX];
        let n = orig.encode(&mut wire).unwrap();
        let decoded = SwIccMessage::decode(&wire[..n]).unwrap();
        assert_eq!(decoded.ctrl, orig.ctrl);
        assert_eq!(decoded.cont_state, orig.cont_state);
        assert_eq!(decoded.buf_len_exp, orig.buf_len_exp);
        assert_eq!(decoded.buf(), orig.buf());
    }

    #[test]
    fn encode_decode_roundtrip_with_data() {
        let data = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
        let mut orig = SwIccMessage::new_response(Ctrl::None, &data, 42);
        orig.buf_len_exp = 100;
        let mut wire = [0u8; MSG_MAX];
        let n = orig.encode(&mut wire).unwrap();
        let decoded = SwIccMessage::decode(&wire[..n]).unwrap();
        assert_eq!(decoded.ctrl, Ctrl::None);
        assert_eq!(decoded.cont_state, 42);
        assert_eq!(decoded.buf_len_exp, 100);
        assert_eq!(decoded.buf(), &data);
    }

    #[test]
    fn encode_decode_roundtrip_max_buf() {
        let data = [0xFF; BUF_MAX];
        let orig = SwIccMessage::new_response(Ctrl::Success, &data, 0xDEAD_BEEF);
        let mut wire = [0u8; MSG_MAX];
        let n = orig.encode(&mut wire).unwrap();
        assert_eq!(n, MSG_MAX);
        let decoded = SwIccMessage::decode(&wire[..n]).unwrap();
        assert_eq!(decoded.buf(), &data[..]);
        assert_eq!(decoded.cont_state, 0xDEAD_BEEF);
    }

    // -- CardTransport over TCP (using loopback) --

    /// Create a connected pair of `SwIccClient` instances using a loopback.
    fn loopback_pair() -> (SwIccClient, SwIccClient) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client_stream = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        (
            SwIccClient::from_stream(client_stream),
            SwIccClient::from_stream(server_stream),
        )
    }

    #[test]
    fn tcp_apdu_exchange() {
        let (mut card, mut server) = loopback_pair();

        // Server sends APDU command.
        let apdu = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let request = SwIccMessage::new_response(Ctrl::None, &apdu, 0);
        server.send_msg(&request).unwrap();

        // Card receives APDU.
        let mut cmd_buf = [0u8; 261];
        let event = card.recv(&mut cmd_buf).unwrap();
        assert_eq!(event, CardEvent::Apdu(7));
        assert_eq!(&cmd_buf[..7], &apdu);

        // Card sends response.
        card.send(&[0x61, 0x0F]).unwrap();

        // Server receives response.
        let rsp = server.recv_msg().unwrap();
        assert_eq!(rsp.ctrl, Ctrl::Success);
        assert_eq!(rsp.buf(), &[0x61, 0x0F]);
    }

    #[test]
    fn tcp_cold_reset() {
        let (mut card, mut server) = loopback_pair();

        // Server sends cold reset.
        let request = SwIccMessage::new(Ctrl::MockResetColdPpsY);
        server.send_msg(&request).unwrap();

        // Card receives power-on event.
        let mut buf = [0u8; 261];
        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::PowerOn);

        // Card sends ATR.
        let atr = [0x3B, 0x9F, 0x96, 0x80];
        card.send_atr(&atr).unwrap();

        // Server receives ATR response.
        let rsp = server.recv_msg().unwrap();
        assert_eq!(rsp.ctrl, Ctrl::Success);
        assert_eq!(rsp.buf(), &atr);
    }

    #[test]
    fn tcp_warm_reset() {
        let (mut card, mut server) = loopback_pair();

        let request = SwIccMessage::new(Ctrl::MockResetWarmPpsN);
        server.send_msg(&request).unwrap();

        let mut buf = [0u8; 261];
        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::WarmReset);
    }

    #[test]
    fn tcp_keepalive_auto_responded() {
        let (mut card, mut server) = loopback_pair();

        // Server sends keepalive then an APDU.
        let keepalive = SwIccMessage::new(Ctrl::Keepalive);
        server.send_msg(&keepalive).unwrap();

        let apdu_msg =
            SwIccMessage::new_response(Ctrl::None, &[0x00, 0xB0, 0x00, 0x00], 0);
        server.send_msg(&apdu_msg).unwrap();

        // Card's recv() should auto-respond to keepalive and return the APDU.
        let mut buf = [0u8; 261];
        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::Apdu(4));
        assert_eq!(&buf[..4], &[0x00, 0xB0, 0x00, 0x00]);

        // Verify server received the keepalive SUCCESS response.
        let ka_rsp = server.recv_msg().unwrap();
        assert_eq!(ka_rsp.ctrl, Ctrl::Success);
        assert_eq!(ka_rsp.buf_len(), 0);
    }

    #[test]
    fn tcp_disconnect_returns_error() {
        let (mut card, server) = loopback_pair();

        // Drop server to simulate disconnect.
        drop(server);

        let mut buf = [0u8; 261];
        let err = card.recv(&mut buf).unwrap_err();
        assert_eq!(err, TransportError::Disconnected);
    }

    #[test]
    fn tcp_success_ctrl_as_request_rejected() {
        let (mut card, mut server) = loopback_pair();

        // Server (improperly) sends Success as a request.
        let bad = SwIccMessage::new(Ctrl::Success);
        server.send_msg(&bad).unwrap();

        let mut buf = [0u8; 261];
        let err = card.recv(&mut buf).unwrap_err();
        assert_eq!(err, TransportError::InvalidMessage);
    }

    #[test]
    fn tcp_failure_ctrl_as_request_rejected() {
        let (mut card, mut server) = loopback_pair();

        let bad = SwIccMessage::new(Ctrl::Failure);
        server.send_msg(&bad).unwrap();

        let mut buf = [0u8; 261];
        let err = card.recv(&mut buf).unwrap_err();
        assert_eq!(err, TransportError::InvalidMessage);
    }

    #[test]
    fn tcp_send_oversized_data_returns_error() {
        let (mut card, _server) = loopback_pair();
        let oversized = [0u8; BUF_MAX + 1];
        let err = card.send(&oversized).unwrap_err();
        assert_eq!(err, TransportError::BufferTooSmall);
    }

    #[test]
    fn tcp_send_atr_oversized_returns_error() {
        let (mut card, _server) = loopback_pair();
        let oversized = [0u8; BUF_MAX + 1];
        let err = card.send_atr(&oversized).unwrap_err();
        assert_eq!(err, TransportError::BufferTooSmall);
    }

    // -- SwIccTerminal tests --

    /// Create a connected `SwIccTerminal` + `SwIccClient` pair.
    ///
    /// The terminal sends commands; the client receives them (acts as card).
    fn terminal_card_pair() -> (SwIccTerminal, SwIccClient) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let terminal_stream = TcpStream::connect(addr).unwrap();
        let (card_stream, _) = listener.accept().unwrap();
        (
            SwIccTerminal::from_stream(terminal_stream),
            SwIccClient::from_stream(card_stream),
        )
    }

    #[test]
    fn terminal_exchange_apdu() {
        let (mut terminal, mut card) = terminal_card_pair();

        // Terminal sends SELECT MF in a background-ish manner:
        // we need to do this from a thread because exchange() blocks
        // waiting for the card response.
        let handle = std::thread::spawn(move || {
            let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
            let mut rsp = [0u8; 258];
            let n = terminal.exchange(&select_mf, &mut rsp).unwrap();
            (terminal, rsp, n)
        });

        // Card receives APDU.
        let mut cmd_buf = [0u8; 261];
        let event = card.recv(&mut cmd_buf).unwrap();
        assert_eq!(event, CardEvent::Apdu(7));
        assert_eq!(
            &cmd_buf[..7],
            &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]
        );

        // Card sends response (SW 90 00).
        card.send(&[0x90, 0x00]).unwrap();

        // Terminal gets the response.
        let (_terminal, rsp, n) = handle.join().unwrap();
        assert_eq!(n, 2);
        assert_eq!(&rsp[..n], &[0x90, 0x00]);
    }

    #[test]
    fn terminal_exchange_response_data() {
        let (mut terminal, mut card) = terminal_card_pair();

        let handle = std::thread::spawn(move || {
            // READ BINARY P1=0x00 P2=0x00 Le=0x08
            let read_bin = [0x00, 0xB0, 0x00, 0x00, 0x08];
            let mut rsp = [0u8; 258];
            let n = terminal.exchange(&read_bin, &mut rsp).unwrap();
            (rsp, n)
        });

        let mut cmd_buf = [0u8; 261];
        let event = card.recv(&mut cmd_buf).unwrap();
        assert_eq!(event, CardEvent::Apdu(5));

        // Card responds with 8 data bytes + SW.
        let response_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x90, 0x00];
        card.send(&response_data).unwrap();

        let (rsp, n) = handle.join().unwrap();
        assert_eq!(n, 10);
        assert_eq!(&rsp[..n], &response_data);
    }

    #[test]
    fn terminal_reset_cold() {
        let (mut terminal, mut card) = terminal_card_pair();

        let handle = std::thread::spawn(move || terminal.reset_cold());

        // Card receives power-on.
        let mut buf = [0u8; 261];
        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::PowerOn);

        // Card sends ATR.
        let atr = [0x3B, 0x9F, 0x96, 0x80];
        card.send_atr(&atr).unwrap();

        let rsp = handle.join().unwrap().unwrap();
        assert_eq!(rsp.ctrl, Ctrl::Success);
        assert_eq!(rsp.buf(), &atr);
    }

    #[test]
    fn terminal_reset_warm() {
        let (mut terminal, mut card) = terminal_card_pair();

        let handle = std::thread::spawn(move || terminal.reset_warm());

        // Card receives warm reset.
        let mut buf = [0u8; 261];
        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::WarmReset);

        // Card sends ATR.
        let atr = [0x3B, 0x00];
        card.send_atr(&atr).unwrap();

        let rsp = handle.join().unwrap().unwrap();
        assert_eq!(rsp.ctrl, Ctrl::Success);
        assert_eq!(rsp.buf(), &atr);
    }

    #[test]
    fn terminal_exchange_failure_response() {
        let (mut terminal, mut card) = terminal_card_pair();

        let handle = std::thread::spawn(move || {
            let cmd = [0x00, 0xA4, 0x00, 0x00];
            let mut rsp = [0u8; 258];
            terminal.exchange(&cmd, &mut rsp)
        });

        // Card receives the command.
        let mut cmd_buf = [0u8; 261];
        card.recv(&mut cmd_buf).unwrap();

        // Card sends Failure response (using raw send_msg via a SwIccClient
        // acting as the wire -- we need to send Ctrl::Failure).
        // SwIccClient::send always uses Ctrl::Success, so we construct the
        // message manually and use the underlying stream.
        let fail_msg = SwIccMessage::new(Ctrl::Failure);
        let mut wire = [0u8; MSG_MAX];
        let n = fail_msg.encode(&mut wire).unwrap();
        std::io::Write::write_all(&mut card.stream, &wire[..n]).unwrap();

        let result = handle.join().unwrap();
        assert_eq!(result, Err(TransportError::IoError));
    }

    #[test]
    fn terminal_disconnect() {
        let (mut terminal, card) = terminal_card_pair();

        // Drop card side to simulate disconnect.
        drop(card);

        let cmd = [0x00, 0xA4, 0x00, 0x00];
        let mut rsp = [0u8; 258];
        let err = terminal.exchange(&cmd, &mut rsp).unwrap_err();
        assert_eq!(err, TransportError::Disconnected);
    }

    #[test]
    fn terminal_rsp_buffer_too_small() {
        let (mut terminal, mut card) = terminal_card_pair();

        let handle = std::thread::spawn(move || {
            let cmd = [0x00, 0xB0, 0x00, 0x00];
            let mut rsp = [0u8; 2]; // too small for 10-byte response
            terminal.exchange(&cmd, &mut rsp)
        });

        let mut cmd_buf = [0u8; 261];
        card.recv(&mut cmd_buf).unwrap();

        // Card responds with more data than the terminal buffer can hold.
        let big_response = [0xAA; 10];
        card.send(&big_response).unwrap();

        let result = handle.join().unwrap();
        assert_eq!(result, Err(TransportError::BufferTooSmall));
    }

    #[test]
    fn terminal_exchange_oversized_cmd() {
        let (mut terminal, _card) = terminal_card_pair();

        let oversized = [0u8; BUF_MAX + 1];
        let mut rsp = [0u8; 258];
        let err = terminal.exchange(&oversized, &mut rsp).unwrap_err();
        assert_eq!(err, TransportError::BufferTooSmall);
    }

    #[test]
    fn terminal_full_roundtrip() {
        let (mut terminal, mut card) = terminal_card_pair();

        // Step 1: Cold reset.
        let handle = std::thread::spawn(move || {
            let reset_rsp = terminal.reset_cold().unwrap();
            (terminal, reset_rsp)
        });

        let mut buf = [0u8; 261];
        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::PowerOn);
        let atr = [0x3B, 0x9F, 0x96, 0x80];
        card.send_atr(&atr).unwrap();

        let (mut terminal, reset_rsp) = handle.join().unwrap();
        assert_eq!(reset_rsp.ctrl, Ctrl::Success);
        assert_eq!(reset_rsp.buf(), &atr);

        // Step 2: SELECT MF.
        let handle = std::thread::spawn(move || {
            let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
            let mut rsp = [0u8; 258];
            let n = terminal.exchange(&select_mf, &mut rsp).unwrap();
            (terminal, rsp, n)
        });

        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::Apdu(7));
        card.send(&[0x90, 0x00]).unwrap();

        let (mut terminal, rsp, n) = handle.join().unwrap();
        assert_eq!(n, 2);
        assert_eq!(&rsp[..n], &[0x90, 0x00]);

        // Step 3: READ BINARY.
        let handle = std::thread::spawn(move || {
            let read_bin = [0x00, 0xB0, 0x00, 0x00, 0x04];
            let mut rsp = [0u8; 258];
            let n = terminal.exchange(&read_bin, &mut rsp).unwrap();
            (rsp, n)
        });

        let event = card.recv(&mut buf).unwrap();
        assert_eq!(event, CardEvent::Apdu(5));
        card.send(&[0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00]).unwrap();

        let (rsp, n) = handle.join().unwrap();
        assert_eq!(n, 6);
        assert_eq!(&rsp[..n], &[0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00]);
    }

    #[test]
    fn terminal_multiple_exchanges() {
        let (mut terminal, mut card) = terminal_card_pair();

        // Perform 5 back-to-back exchanges.
        for i in 0u8..5 {
            let handle = std::thread::spawn(move || {
                let cmd = [0x80, 0x10 + i, 0x00, 0x00];
                let mut rsp = [0u8; 258];
                let n = terminal.exchange(&cmd, &mut rsp).unwrap();
                (terminal, rsp, n)
            });

            let mut cmd_buf = [0u8; 261];
            let event = card.recv(&mut cmd_buf).unwrap();
            assert_eq!(event, CardEvent::Apdu(4));
            assert_eq!(cmd_buf[1], 0x10 + i);

            // Card responds with the command INS byte echoed + SW.
            card.send(&[cmd_buf[1], 0x90, 0x00]).unwrap();

            let (t, rsp, n) = handle.join().unwrap();
            terminal = t;
            assert_eq!(n, 3);
            assert_eq!(rsp[0], 0x10 + i);
            assert_eq!(&rsp[1..3], &[0x90, 0x00]);
        }
    }
}
