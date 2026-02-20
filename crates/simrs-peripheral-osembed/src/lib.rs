//! Linux/Android OS-embedded SIM peripheral protocol types.
//!
//! Provides protocol-level types for Linux kernel ioctl and Android RIL
//! (Radio Interface Layer) SIM card interfaces. This crate does **not**
//! perform actual ioctl syscalls or socket I/O -- it provides the wire-level
//! building blocks that a concrete driver crate assembles.
//!
//! # Linux ioctl interface
//!
//! Constants for SIM slot character device ioctls (`/dev/simX`).
//! The [`IoctlXferCmd`] and [`IoctlXferRsp`] types encode/decode the
//! ioctl transfer structure used by `SIM_IOC_XFER`.
//!
//! # Android RIL interface
//!
//! The [`RilHeader`] and [`RilSimIoRequest`] types encode/decode the
//! Android Radio Interface Layer parcel format for SIM I/O operations.
//!
//! # `std` required
//!
//! This crate requires `std` (consumers will use POSIX file descriptors
//! and ioctl syscalls).
//!
//! # Example
//!
//! ```
//! use simrs_peripheral_osembed::{IoctlXferCmd, SIM_IOC_XFER};
//!
//! let cmd = IoctlXferCmd::new(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
//! assert_eq!(cmd.len, 7);
//!
//! let mut buf = [0u8; 268]; // 4 + 2 + 261 + 1 spare
//! let n = cmd.encode(&mut buf).unwrap();
//! let decoded = IoctlXferCmd::decode(&buf[..n]).unwrap();
//! assert_eq!(decoded.len, 7);
//! assert_eq!(&decoded.data[..7], &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
//! ```
#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Linux ioctl constants
// ---------------------------------------------------------------------------

/// ioctl number: Power on the SIM slot.
pub const SIM_IOC_POWER_ON: u32 = 0xAE01;

/// ioctl number: Power off the SIM slot.
pub const SIM_IOC_POWER_OFF: u32 = 0xAE02;

/// ioctl number: Reset the SIM card.
pub const SIM_IOC_RESET: u32 = 0xAE03;

/// ioctl number: Get the ATR (Answer To Reset).
pub const SIM_IOC_GET_ATR: u32 = 0xAE04;

/// ioctl number: Transfer (exchange) an APDU.
pub const SIM_IOC_XFER: u32 = 0xAE05;

/// Maximum APDU data length for ioctl transfer (short APDUs).
const IOCTL_DATA_MAX: usize = 261;

// ---------------------------------------------------------------------------
// IoctlXferCmd -- ioctl transfer command
// ---------------------------------------------------------------------------

/// Ioctl transfer command structure.
///
/// Wire format (little-endian):
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
///   0      4    len    (u32 LE -- APDU command byte count)
///   4      2    sw     (u16 LE -- reserved, set to 0 on command)
///   6      N    data   (APDU command bytes, N = len)
/// ```
///
/// # Example
///
/// ```
/// use simrs_peripheral_osembed::IoctlXferCmd;
///
/// let cmd = IoctlXferCmd::new(&[0x00, 0xA4, 0x00, 0x00]);
/// assert_eq!(cmd.len, 4);
/// assert_eq!(&cmd.data[..4], &[0x00, 0xA4, 0x00, 0x00]);
/// ```
#[derive(Clone, Debug)]
pub struct IoctlXferCmd {
    /// Number of APDU command bytes.
    pub len: u32,
    /// Reserved status word (set to 0 on command).
    pub sw: u16,
    /// APDU command data.
    pub data: [u8; IOCTL_DATA_MAX],
}

impl IoctlXferCmd {
    /// Create a new transfer command from APDU bytes.
    ///
    /// # Panics
    ///
    /// Panics if `apdu` exceeds 261 bytes.
    pub fn new(apdu: &[u8]) -> Self {
        assert!(apdu.len() <= IOCTL_DATA_MAX);
        let mut data = [0u8; IOCTL_DATA_MAX];
        data[..apdu.len()].copy_from_slice(apdu);
        #[allow(clippy::cast_possible_truncation)]
        let len = apdu.len() as u32; // bounded by assert above
        Self { len, sw: 0, data }
    }

    /// Encode into a byte buffer (little-endian).
    ///
    /// Returns the number of bytes written, or `None` if `buf` is too small.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        let total = 6 + self.len as usize;
        if buf.len() < total {
            return None;
        }
        buf[0..4].copy_from_slice(&self.len.to_le_bytes());
        buf[4..6].copy_from_slice(&self.sw.to_le_bytes());
        buf[6..total].copy_from_slice(&self.data[..self.len as usize]);
        Some(total)
    }

    /// Decode from a byte buffer (little-endian).
    ///
    /// Returns `None` if `buf` is too short or `len` exceeds maximum.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            return None;
        }
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let sw = u16::from_le_bytes([buf[4], buf[5]]);
        if len as usize > IOCTL_DATA_MAX {
            return None;
        }
        let total = 6 + len as usize;
        if buf.len() < total {
            return None;
        }
        let mut data = [0u8; IOCTL_DATA_MAX];
        data[..len as usize].copy_from_slice(&buf[6..total]);
        Some(Self { len, sw, data })
    }
}

// ---------------------------------------------------------------------------
// IoctlXferRsp -- ioctl transfer response
// ---------------------------------------------------------------------------

/// Ioctl transfer response structure.
///
/// Wire format (little-endian):
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
///   0      4    len    (u32 LE -- response data byte count, including SW)
///   4      2    sw     (u16 LE -- status word SW1||SW2)
///   6      N    data   (response data bytes, N = len)
/// ```
///
/// # Example
///
/// ```
/// use simrs_peripheral_osembed::IoctlXferRsp;
///
/// let rsp = IoctlXferRsp::new(0x9000, &[0x6F, 0x10]);
/// assert_eq!(rsp.sw, 0x9000);
/// assert_eq!(rsp.len, 2);
/// ```
#[derive(Clone, Debug)]
pub struct IoctlXferRsp {
    /// Number of response data bytes (excluding the SW in `sw` field).
    pub len: u32,
    /// Status word (SW1 in high byte, SW2 in low byte).
    pub sw: u16,
    /// Response data bytes.
    pub data: [u8; IOCTL_DATA_MAX],
}

impl IoctlXferRsp {
    /// Create a new transfer response.
    ///
    /// # Panics
    ///
    /// Panics if `data` exceeds 261 bytes.
    pub fn new(sw: u16, data: &[u8]) -> Self {
        assert!(data.len() <= IOCTL_DATA_MAX);
        let mut buf = [0u8; IOCTL_DATA_MAX];
        buf[..data.len()].copy_from_slice(data);
        #[allow(clippy::cast_possible_truncation)]
        let len = data.len() as u32; // bounded by assert above
        Self { len, sw, data: buf }
    }

    /// Encode into a byte buffer (little-endian).
    ///
    /// Returns the number of bytes written, or `None` if `buf` is too small.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        let total = 6 + self.len as usize;
        if buf.len() < total {
            return None;
        }
        buf[0..4].copy_from_slice(&self.len.to_le_bytes());
        buf[4..6].copy_from_slice(&self.sw.to_le_bytes());
        buf[6..total].copy_from_slice(&self.data[..self.len as usize]);
        Some(total)
    }

    /// Decode from a byte buffer (little-endian).
    ///
    /// Returns `None` if `buf` is too short or `len` exceeds maximum.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            return None;
        }
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let sw = u16::from_le_bytes([buf[4], buf[5]]);
        if len as usize > IOCTL_DATA_MAX {
            return None;
        }
        let total = 6 + len as usize;
        if buf.len() < total {
            return None;
        }
        let mut data = [0u8; IOCTL_DATA_MAX];
        data[..len as usize].copy_from_slice(&buf[6..total]);
        Some(Self { len, sw, data })
    }
}

// ---------------------------------------------------------------------------
// Android RIL constants
// ---------------------------------------------------------------------------

/// RIL request ID: SIM I/O (ETSI TS 102 221 based access).
pub const RIL_REQUEST_SIM_IO: u32 = 28;

/// RIL request ID: Get SIM status.
pub const RIL_REQUEST_GET_SIM_STATUS: u32 = 51;

/// RIL request ID: Enter SIM PIN.
pub const RIL_REQUEST_ENTER_SIM_PIN: u32 = 2;

/// RIL request ID: Enter SIM PUK.
pub const RIL_REQUEST_ENTER_SIM_PUK: u32 = 3;

// ---------------------------------------------------------------------------
// RilHeader
// ---------------------------------------------------------------------------

/// Android RIL parcel header.
///
/// Wire format (little-endian):
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
///   0      4    length     (u32 LE -- total parcel length after this field)
///   4      4    request_id (u32 LE -- RIL request type)
///   8      4    serial     (u32 LE -- transaction serial number)
/// ```
///
/// # Example
///
/// ```
/// use simrs_peripheral_osembed::{RilHeader, RIL_REQUEST_SIM_IO};
///
/// let hdr = RilHeader::new(RIL_REQUEST_SIM_IO, 1);
/// assert_eq!(hdr.request_id, RIL_REQUEST_SIM_IO);
/// assert_eq!(hdr.serial, 1);
/// ```
pub const RIL_HEADER_SIZE: usize = 12;

/// Android RIL parcel header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RilHeader {
    /// Total parcel length after this field.
    pub length: u32,
    /// RIL request type.
    pub request_id: u32,
    /// Transaction serial number.
    pub serial: u32,
}

impl RilHeader {
    /// Create a new RIL header. `length` is set to 8 (`request_id` + `serial`)
    /// by default; callers should update it after appending payload.
    pub const fn new(request_id: u32, serial: u32) -> Self {
        Self {
            length: 8,
            request_id,
            serial,
        }
    }

    /// Encode into a byte buffer (little-endian).
    ///
    /// Returns `None` if `buf` is shorter than [`RIL_HEADER_SIZE`].
    pub fn encode(&self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < RIL_HEADER_SIZE {
            return None;
        }
        buf[0..4].copy_from_slice(&self.length.to_le_bytes());
        buf[4..8].copy_from_slice(&self.request_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.serial.to_le_bytes());
        Some(())
    }

    /// Decode from a byte buffer (little-endian).
    ///
    /// Returns `None` if `buf` is shorter than [`RIL_HEADER_SIZE`].
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < RIL_HEADER_SIZE {
            return None;
        }
        Some(Self {
            length: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            request_id: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            serial: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}

// ---------------------------------------------------------------------------
// RilSimIoRequest
// ---------------------------------------------------------------------------

/// Maximum RIL SIM I/O data payload.
const RIL_SIM_IO_DATA_MAX: usize = 256;

/// RIL SIM I/O request payload (follows [`RilHeader`]).
///
/// Wire format (little-endian):
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
///   0      4    command    (u32 LE -- SIM I/O command: READ_BINARY=176, etc.)
///   4      4    file_id    (u32 LE -- EF identifier)
///   8      4    p1         (u32 LE)
///  12      4    p2         (u32 LE)
///  16      4    p3         (u32 LE -- data length or Le)
///  20      4    data_len   (u32 LE -- number of data bytes following)
///  24      N    data       (command data, N = data_len)
/// ```
///
/// # Example
///
/// ```
/// use simrs_peripheral_osembed::RilSimIoRequest;
///
/// let req = RilSimIoRequest::new(176, 0x6F07, 0, 0, 10, &[]);
/// assert_eq!(req.command, 176);
/// assert_eq!(req.file_id, 0x6F07);
/// ```
pub const RIL_SIM_IO_HEADER_SIZE: usize = 24;

/// RIL SIM I/O request fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RilSimIoRequest {
    /// SIM I/O command (`READ_BINARY`=176, `READ_RECORD`=178, `UPDATE_BINARY`=214, etc.).
    pub command: u32,
    /// Elementary File identifier.
    pub file_id: u32,
    /// Parameter 1.
    pub p1: u32,
    /// Parameter 2.
    pub p2: u32,
    /// Parameter 3 (data length or Le).
    pub p3: u32,
    /// Data length.
    pub data_len: u32,
    /// Command data payload.
    pub data: [u8; RIL_SIM_IO_DATA_MAX],
}

impl RilSimIoRequest {
    /// Create a new SIM I/O request.
    ///
    /// # Panics
    ///
    /// Panics if `data` exceeds 256 bytes.
    pub fn new(command: u32, file_id: u32, p1: u32, p2: u32, p3: u32, data: &[u8]) -> Self {
        assert!(data.len() <= RIL_SIM_IO_DATA_MAX);
        let mut buf = [0u8; RIL_SIM_IO_DATA_MAX];
        buf[..data.len()].copy_from_slice(data);
        #[allow(clippy::cast_possible_truncation)]
        let data_len = data.len() as u32; // bounded by assert above
        Self {
            command,
            file_id,
            p1,
            p2,
            p3,
            data_len,
            data: buf,
        }
    }

    /// Encode into a byte buffer (little-endian).
    ///
    /// Returns the number of bytes written, or `None` if `buf` is too small.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        let total = RIL_SIM_IO_HEADER_SIZE + self.data_len as usize;
        if buf.len() < total {
            return None;
        }
        buf[0..4].copy_from_slice(&self.command.to_le_bytes());
        buf[4..8].copy_from_slice(&self.file_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.p1.to_le_bytes());
        buf[12..16].copy_from_slice(&self.p2.to_le_bytes());
        buf[16..20].copy_from_slice(&self.p3.to_le_bytes());
        buf[20..24].copy_from_slice(&self.data_len.to_le_bytes());
        buf[24..total].copy_from_slice(&self.data[..self.data_len as usize]);
        Some(total)
    }

    /// Decode from a byte buffer (little-endian).
    ///
    /// Returns `None` if `buf` is too short or `data_len` exceeds maximum.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < RIL_SIM_IO_HEADER_SIZE {
            return None;
        }
        let command = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let file_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let p1 = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let p2 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let p3 = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let data_len = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        if data_len as usize > RIL_SIM_IO_DATA_MAX {
            return None;
        }
        let total = RIL_SIM_IO_HEADER_SIZE + data_len as usize;
        if buf.len() < total {
            return None;
        }
        let mut data = [0u8; RIL_SIM_IO_DATA_MAX];
        data[..data_len as usize].copy_from_slice(&buf[24..total]);
        Some(Self {
            command,
            file_id,
            p1,
            p2,
            p3,
            data_len,
            data,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Ioctl constants --

    #[test]
    fn ioctl_constants_are_distinct() {
        let all = [
            SIM_IOC_POWER_ON,
            SIM_IOC_POWER_OFF,
            SIM_IOC_RESET,
            SIM_IOC_GET_ATR,
            SIM_IOC_XFER,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // -- IoctlXferCmd --

    #[test]
    fn xfer_cmd_new() {
        let cmd = IoctlXferCmd::new(&[0x00, 0xA4, 0x00, 0x00]);
        assert_eq!(cmd.len, 4);
        assert_eq!(cmd.sw, 0);
        assert_eq!(&cmd.data[..4], &[0x00, 0xA4, 0x00, 0x00]);
    }

    #[test]
    fn xfer_cmd_encode_decode_roundtrip() {
        let cmd = IoctlXferCmd::new(&[0x00, 0xA4, 0x04, 0x04, 0x02, 0x3F, 0x00]);
        let mut buf = [0u8; 280];
        let n = cmd.encode(&mut buf).unwrap();
        assert_eq!(n, 6 + 7);
        let decoded = IoctlXferCmd::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.len, 7);
        assert_eq!(&decoded.data[..7], &[0x00, 0xA4, 0x04, 0x04, 0x02, 0x3F, 0x00]);
    }

    #[test]
    fn xfer_cmd_encode_too_small() {
        let cmd = IoctlXferCmd::new(&[0x00, 0xA4, 0x00, 0x00]);
        let mut buf = [0u8; 4]; // too small for 6+4=10
        assert!(cmd.encode(&mut buf).is_none());
    }

    #[test]
    fn xfer_cmd_decode_too_short() {
        assert!(IoctlXferCmd::decode(&[0u8; 4]).is_none());
    }

    #[test]
    fn xfer_cmd_decode_len_exceeds_buf() {
        let mut buf = [0u8; 10];
        // Encode len=100 but only provide 10 bytes total.
        buf[0..4].copy_from_slice(&100u32.to_le_bytes());
        assert!(IoctlXferCmd::decode(&buf).is_none());
    }

    #[test]
    fn xfer_cmd_empty_apdu() {
        let cmd = IoctlXferCmd::new(&[]);
        assert_eq!(cmd.len, 0);
        let mut buf = [0u8; 10];
        let n = cmd.encode(&mut buf).unwrap();
        assert_eq!(n, 6);
        let decoded = IoctlXferCmd::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.len, 0);
    }

    // -- IoctlXferRsp --

    #[test]
    fn xfer_rsp_new() {
        let rsp = IoctlXferRsp::new(0x9000, &[0x6F, 0x10]);
        assert_eq!(rsp.len, 2);
        assert_eq!(rsp.sw, 0x9000);
        assert_eq!(&rsp.data[..2], &[0x6F, 0x10]);
    }

    #[test]
    fn xfer_rsp_encode_decode_roundtrip() {
        let rsp = IoctlXferRsp::new(0x6A82, &[0x01, 0x02, 0x03]);
        let mut buf = [0u8; 280];
        let n = rsp.encode(&mut buf).unwrap();
        assert_eq!(n, 6 + 3);
        let decoded = IoctlXferRsp::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.len, 3);
        assert_eq!(decoded.sw, 0x6A82);
        assert_eq!(&decoded.data[..3], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn xfer_rsp_sw_only() {
        let rsp = IoctlXferRsp::new(0x9000, &[]);
        assert_eq!(rsp.len, 0);
        let mut buf = [0u8; 10];
        let n = rsp.encode(&mut buf).unwrap();
        assert_eq!(n, 6);
        let decoded = IoctlXferRsp::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.sw, 0x9000);
        assert_eq!(decoded.len, 0);
    }

    #[test]
    fn xfer_rsp_decode_too_short() {
        assert!(IoctlXferRsp::decode(&[0u8; 4]).is_none());
    }

    // -- RilHeader --

    #[test]
    fn ril_header_new() {
        let hdr = RilHeader::new(RIL_REQUEST_SIM_IO, 42);
        assert_eq!(hdr.request_id, RIL_REQUEST_SIM_IO);
        assert_eq!(hdr.serial, 42);
        assert_eq!(hdr.length, 8);
    }

    #[test]
    fn ril_header_encode_decode_roundtrip() {
        let hdr = RilHeader::new(RIL_REQUEST_GET_SIM_STATUS, 7);
        let mut buf = [0u8; RIL_HEADER_SIZE];
        hdr.encode(&mut buf).unwrap();
        let decoded = RilHeader::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn ril_header_encode_too_small() {
        let hdr = RilHeader::new(0, 0);
        let mut buf = [0u8; 8];
        assert!(hdr.encode(&mut buf).is_none());
    }

    #[test]
    fn ril_header_decode_too_short() {
        assert!(RilHeader::decode(&[0u8; 8]).is_none());
    }

    #[test]
    fn ril_header_endianness() {
        let hdr = RilHeader::new(0x0102_0304, 0x0506_0708);
        let mut buf = [0u8; RIL_HEADER_SIZE];
        hdr.encode(&mut buf).unwrap();
        // LE: request_id low byte first at offset 4.
        assert_eq!(buf[4], 0x04);
        assert_eq!(buf[7], 0x01);
        // serial at offset 8.
        assert_eq!(buf[8], 0x08);
        assert_eq!(buf[11], 0x05);
    }

    // -- RilSimIoRequest --

    #[test]
    fn ril_sim_io_new() {
        let req = RilSimIoRequest::new(176, 0x6F07, 0, 0, 10, &[]);
        assert_eq!(req.command, 176);
        assert_eq!(req.file_id, 0x6F07);
        assert_eq!(req.p1, 0);
        assert_eq!(req.p2, 0);
        assert_eq!(req.p3, 10);
        assert_eq!(req.data_len, 0);
    }

    #[test]
    fn ril_sim_io_encode_decode_roundtrip() {
        let req = RilSimIoRequest::new(214, 0x6F07, 0, 0, 5, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut buf = [0u8; 300];
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(n, RIL_SIM_IO_HEADER_SIZE + 5);
        let decoded = RilSimIoRequest::decode(&buf[..n]).unwrap();
        assert_eq!(req.command, decoded.command);
        assert_eq!(req.file_id, decoded.file_id);
        assert_eq!(req.p3, decoded.p3);
        assert_eq!(req.data_len, decoded.data_len);
        assert_eq!(&decoded.data[..5], &[0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn ril_sim_io_no_data() {
        let req = RilSimIoRequest::new(176, 0x2FE2, 0, 0, 10, &[]);
        let mut buf = [0u8; 300];
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(n, RIL_SIM_IO_HEADER_SIZE);
        let decoded = RilSimIoRequest::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.data_len, 0);
    }

    #[test]
    fn ril_sim_io_decode_too_short() {
        assert!(RilSimIoRequest::decode(&[0u8; 20]).is_none());
    }

    #[test]
    fn ril_sim_io_decode_data_exceeds_buf() {
        let mut buf = [0u8; 28];
        // data_len = 100 at offset 20, but buf only has 4 bytes after header.
        buf[20..24].copy_from_slice(&100u32.to_le_bytes());
        assert!(RilSimIoRequest::decode(&buf).is_none());
    }

    // -- RIL constant values --

    #[test]
    fn ril_constants_match_spec() {
        assert_eq!(RIL_REQUEST_SIM_IO, 28);
        assert_eq!(RIL_REQUEST_GET_SIM_STATUS, 51);
        assert_eq!(RIL_REQUEST_ENTER_SIM_PIN, 2);
        assert_eq!(RIL_REQUEST_ENTER_SIM_PUK, 3);
    }
}
