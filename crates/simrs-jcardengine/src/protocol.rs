//! Framing protocol between [`JcardengineClient`](crate::client::JcardengineClient)
//! and the Java bridge (`tools/jcardengine-bridge`).
//!
//! Wire format chosen to match the Oracle RAW framing of
//! [`simrs_jcsl::protocol`](../../simrs-jcsl/src/protocol.rs) byte-for-byte
//! so packet captures parse with the same decoders. The Java bridge
//! speaks exactly this protocol on both sides.
//!
//! # Frame format
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//!   0     1     Command type (echoed back in responses)
//!   1     1     Reserved (0x00)
//!   2     2     Payload length (big-endian u16)
//!  [4]    N     Payload bytes
//! ```
//!
//! # Command types
//!
//! | Byte | Direction | Meaning                             |
//! |------|-----------|-------------------------------------|
//! | 0x00 | C -> S    | APDU transmit                       |
//! | 0xF0 | C -> S    | Power ON (cold reset, returns ATR)  |
//! | 0xFE | C -> S    | Power OFF                           |

use std::io::{self, Read, Write};

/// APDU transmit command.
pub const CMD_APDU: u8 = 0x00;

/// Power ON command (cold reset). Response payload is the ATR.
pub const CMD_POWER_ON: u8 = 0xF0;

/// Power OFF command. Response payload is empty.
pub const CMD_POWER_OFF: u8 = 0xFE;

/// Header size (cmd + reserved + u16 length).
pub const HEADER_SIZE: usize = 4;

/// Upper bound on any single payload. APDU: 5-byte header + 255-byte
/// data + 1-byte Le. Plus slack for extended-APDU responses.
pub const MAX_PAYLOAD: usize = 512;

/// A framed message (request or response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Command type byte (echoed in responses).
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
    /// Returns [`io::Error`] of kind `InvalidInput` if the payload
    /// exceeds [`MAX_PAYLOAD`], or the underlying writer error.
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
    /// Returns [`io::Error`] of kind `InvalidData` if the declared
    /// payload length exceeds [`MAX_PAYLOAD`], or the underlying
    /// reader error on truncation or I/O failure.
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut header = [0u8; HEADER_SIZE];
        r.read_exact(&mut header)?;
        let cmd_type = header[0];
        let len = ((u16::from(header[2]) << 8) | u16::from(header[3])) as usize;
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
        let round = Frame::read_from(&mut buf.as_slice()).unwrap();
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
        let mut malformed = vec![CMD_APDU, 0x00];
        #[allow(clippy::cast_possible_truncation)]
        let len = (MAX_PAYLOAD + 1) as u16;
        malformed.extend_from_slice(&[(len >> 8) as u8, (len & 0xFF) as u8]);
        assert!(Frame::read_from(&mut malformed.as_slice()).is_err());
    }
}
