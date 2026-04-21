//! Framing protocol between [`JcardsimClient`](crate::client::JcardsimClient)
//! and the Java bridge (`tools/jcardsim-bridge`).
//!
//! Chosen to mirror the jcsl RAW protocol (see
//! [`simrs_jcsl::protocol`](../../simrs-jcsl/src/protocol.rs)) at a wire
//! level: one command byte, a reserved byte, a 16-bit big-endian payload
//! length, then the payload. Keeping the framing identical means the
//! differential infrastructure can swap backends without wire-level
//! surprises.
//!
//! # Frame format
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//!   0     1     Command type (echoed in responses)
//!   1     1     Reserved (0x00)
//!   2     2     Payload length (big-endian u16)
//!  [4]    N     Payload bytes
//! ```
//!
//! # Command types
//!
//! | Byte | Direction | Meaning                       |
//! |------|-----------|-------------------------------|
//! | 0x00 | C -> S    | APDU transmit                 |
//! | 0xF0 | C -> S    | Power ON (cold reset, returns ATR) |
//! | 0xFE | C -> S    | Power OFF                     |
//!
//! Responses echo the command byte in offset 0.

use std::io::{self, Read, Write};

/// APDU transmit command.
pub const CMD_APDU: u8 = 0x00;

/// Power ON command (cold reset). The response payload is the ATR.
pub const CMD_POWER_ON: u8 = 0xF0;

/// Power OFF command. The response payload is empty.
pub const CMD_POWER_OFF: u8 = 0xFE;

/// Fixed frame header size (cmd + reserved + u16 length).
pub const HEADER_SIZE: usize = 4;

/// Upper bound on any one payload (APDU: 5 + 255 + 1 + 1 = 262 to be safe).
pub const MAX_PAYLOAD: usize = 512;

/// A framed message, either a request or a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Command type byte (or echoed command byte for responses).
    pub cmd_type: u8,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Build a new frame from a command type and payload.
    #[must_use]
    pub const fn new(cmd_type: u8, payload: Vec<u8>) -> Self {
        Self { cmd_type, payload }
    }

    /// Write this frame to `w`.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the writer fails or the
    /// payload exceeds [`MAX_PAYLOAD`].
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame payload exceeds MAX_PAYLOAD",
            ));
        }
        #[allow(clippy::cast_possible_truncation)] // bounds-checked above
        let len = self.payload.len() as u16;
        let header = [self.cmd_type, 0x00, (len >> 8) as u8, (len & 0xFF) as u8];
        w.write_all(&header)?;
        w.write_all(&self.payload)?;
        Ok(())
    }

    /// Read one frame from `r`.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] on I/O failure or truncation,
    /// or `InvalidData` if the declared payload length exceeds
    /// [`MAX_PAYLOAD`].
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut header = [0u8; HEADER_SIZE];
        r.read_exact(&mut header)?;
        let cmd_type = header[0];
        let len = (u16::from(header[2]) << 8) | u16::from(header[3]);
        let len = len as usize;
        if len > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("declared payload {len} exceeds MAX_PAYLOAD {MAX_PAYLOAD}"),
            ));
        }
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload)?;
        Ok(Self { cmd_type, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_apdu_frame() {
        let original = Frame::new(CMD_APDU, vec![0x00, 0xA4, 0x04, 0x00, 0x00]);
        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();
        let mut cursor = buf.as_slice();
        let round = Frame::read_from(&mut cursor).unwrap();
        assert_eq!(original, round);
    }

    #[test]
    fn empty_payload_power_off() {
        let f = Frame::new(CMD_POWER_OFF, vec![]);
        let mut buf = Vec::new();
        f.write_to(&mut buf).unwrap();
        assert_eq!(buf, vec![CMD_POWER_OFF, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn oversize_payload_rejected_on_write() {
        let f = Frame::new(CMD_APDU, vec![0u8; MAX_PAYLOAD + 1]);
        let mut buf = Vec::new();
        assert!(f.write_to(&mut buf).is_err());
    }

    #[test]
    fn oversize_payload_rejected_on_read() {
        // Declared length > MAX_PAYLOAD, short-read the payload bytes.
        let mut malformed = vec![CMD_APDU, 0x00];
        #[allow(clippy::cast_possible_truncation)]
        let len = (MAX_PAYLOAD + 1) as u16;
        malformed.extend_from_slice(&[(len >> 8) as u8, (len & 0xFF) as u8]);
        let mut cursor = malformed.as_slice();
        assert!(Frame::read_from(&mut cursor).is_err());
    }
}
