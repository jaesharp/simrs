//! Oracle jcsl RAW wire protocol framing.
//!
//! The Oracle Java Card Simulator uses a simple 4-byte header protocol
//! over TCP (reverse-engineered from `SocketRAWProtocol.class` in
//! `socketprovider.jar`).
//!
//! # Frame format
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//!   0     1     Command type
//!   1     1     Reserved (0x00)
//!   2     2     Payload length (big-endian u16)
//!  [4]    N     Payload data
//! ```
//!
//! # Command types
//!
//! | Byte | Direction | Meaning |
//! |------|-----------|---------|
//! | 0x00 | C -> S    | APDU transmit |
//! | 0xF0 | C -> S    | Power ON (cold reset) |
//! | 0xFE | C -> S    | Power OFF |
//!
//! Responses use the same frame format, with byte 0 echoing
//! the command type.

use std::io::{self, Read, Write};

/// Command type: APDU transmit.
pub const CMD_APDU: u8 = 0x00;

/// Command type: Power ON (cold reset).
pub const CMD_POWER_ON: u8 = 0xF0;

/// Command type: Power OFF.
pub const CMD_POWER_OFF: u8 = 0xFE;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 4;

/// Maximum APDU payload size (261 = 5-byte header + 256-byte data).
pub const MAX_PAYLOAD: usize = 261;

/// A framed message (sent or received).
#[derive(Debug, Clone)]
pub struct Frame {
    /// Command/response type byte.
    pub cmd_type: u8,
    /// Payload data.
    pub payload: Vec<u8>,
}

/// Write a frame to a stream.
///
/// # Errors
///
/// Returns an I/O error if the write fails or the payload exceeds 64 KB.
pub fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let len = frame.payload.len();
    if len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload too large for 16-bit length field",
        ));
    }
    #[allow(clippy::cast_possible_truncation)]
    let len16 = len as u16;
    let header = [
        frame.cmd_type,
        0x00,
        (len16 >> 8) as u8,
        (len16 & 0xFF) as u8,
    ];
    w.write_all(&header)?;
    if !frame.payload.is_empty() {
        w.write_all(&frame.payload)?;
    }
    w.flush()
}

/// Read a frame from a stream.
///
/// Returns `None` if the stream is closed (0 bytes read on header).
///
/// # Errors
///
/// Returns an I/O error if the read fails or the stream is truncated
/// mid-frame.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut header = [0u8; HEADER_SIZE];
    match r.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let cmd_type = header[0];
    let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        r.read_exact(&mut payload)?;
    }

    Ok(Some(Frame { cmd_type, payload }))
}

/// Build a Power ON frame.
pub const fn power_on_frame() -> Frame {
    Frame {
        cmd_type: CMD_POWER_ON,
        payload: Vec::new(),
    }
}

/// Build a Power OFF frame.
pub const fn power_off_frame() -> Frame {
    Frame {
        cmd_type: CMD_POWER_OFF,
        payload: Vec::new(),
    }
}

/// Build an APDU transmit frame.
pub fn apdu_frame(apdu: &[u8]) -> Frame {
    Frame {
        cmd_type: CMD_APDU,
        payload: apdu.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Format bytes as a hex dump for snapshot readability.
    fn hex_dump(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn power_on_frame_encoding() {
        let frame = power_on_frame();
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        assert_eq!(buf, [0xF0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn power_off_frame_encoding() {
        let frame = power_off_frame();
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        assert_eq!(buf, [0xFE, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn apdu_frame_encoding() {
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x00];
        let frame = apdu_frame(&apdu);
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        assert_eq!(&buf[..4], &[0x00, 0x00, 0x00, 0x05]);
        assert_eq!(&buf[4..], &apdu);
    }

    #[test]
    fn round_trip_power_on() {
        let frame = power_on_frame();
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(decoded.cmd_type, CMD_POWER_ON);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn round_trip_apdu() {
        let apdu = [0x80, 0x50, 0x00, 0x00, 0x08];
        let frame = apdu_frame(&apdu);
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(decoded.cmd_type, CMD_APDU);
        assert_eq!(decoded.payload, apdu);
    }

    #[test]
    fn read_frame_empty_stream() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result = read_frame(&mut cursor).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn round_trip_large_apdu() {
        let mut apdu = vec![0x00, 0xB0, 0x00, 0x00, 0x00];
        apdu.extend_from_slice(&[0xAA; 256]);
        let frame = apdu_frame(&apdu);
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();

        // Check length encoding: 261 = 0x0105
        assert_eq!(buf[2], 0x01);
        assert_eq!(buf[3], 0x05);

        let mut cursor = Cursor::new(&buf);
        let decoded = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(decoded.payload.len(), 261);
        assert_eq!(decoded.payload, apdu);
    }

    #[test]
    fn frame_header_big_endian() {
        // Verify the length field uses big-endian encoding.
        let payload = vec![0x42; 0x0102]; // 258 bytes
        let frame = Frame {
            cmd_type: CMD_APDU,
            payload,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        assert_eq!(buf[2], 0x01); // high byte
        assert_eq!(buf[3], 0x02); // low byte
    }

    // -------------------------------------------------------------------
    // Insta snapshots
    // -------------------------------------------------------------------

    #[test]
    fn snap_power_on_wire() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &power_on_frame()).unwrap();
        insta::assert_snapshot!("power_on_wire", hex_dump(&buf));
    }

    #[test]
    fn snap_power_off_wire() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &power_off_frame()).unwrap();
        insta::assert_snapshot!("power_off_wire", hex_dump(&buf));
    }

    #[test]
    fn snap_select_apdu_wire() {
        // SELECT by DF name (no data)
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x00];
        let mut buf = Vec::new();
        write_frame(&mut buf, &apdu_frame(&apdu)).unwrap();
        insta::assert_snapshot!("select_apdu_wire", hex_dump(&buf));
    }

    #[test]
    fn snap_init_update_apdu_wire() {
        // INITIALIZE UPDATE with 8-byte host challenge
        let apdu = [
            0x80, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let mut buf = Vec::new();
        write_frame(&mut buf, &apdu_frame(&apdu)).unwrap();
        insta::assert_snapshot!("init_update_apdu_wire", hex_dump(&buf));
    }

    #[test]
    fn snap_frame_debug() {
        let frame = apdu_frame(&[
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00,
        ]);
        insta::assert_snapshot!("frame_debug", format!("{frame:?}"));
    }
}
