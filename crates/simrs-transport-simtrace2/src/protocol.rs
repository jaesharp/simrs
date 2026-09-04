//! SIMtrace2 USB protocol -- pure encoders / decoders.
//!
//! Mirrors the upstream protocol headers from
//! [`firmware/libcommon/include/simtrace_prot.h`](https://github.com/osmocom/simtrace2/blob/master/firmware/libcommon/include/simtrace_prot.h)
//! and the host-side reference at
//! [`host/lib/simtrace2_api.c`](https://github.com/osmocom/simtrace2/blob/master/host/lib/simtrace2_api.c).
//!
//! All multi-byte fields on the wire are little-endian. The 8-byte common
//! header `simtrace_msg_hdr` prefixes every message in both directions.
//!
//! This module is intentionally I/O-free: every encoder produces bytes into a
//! caller-supplied buffer (or returns `Vec<u8>` for variable-length payloads),
//! and every decoder takes a byte slice. The USB layer in [`crate::cardem`]
//! provides the actual transport.
//!
//! Constants verified against upstream commit history as of 2026-05-22.

use core::convert::TryFrom;

// ---------------------------------------------------------------------------
// Vendor / Product IDs
// ---------------------------------------------------------------------------

/// OpenMoko vendor ID, shared by all Osmocom SIMtrace2 hardware variants.
pub const VID_OPENMOKO: u16 = 0x1d50;

/// SIMtrace2 application firmware product ID.
pub const PID_SIMTRACE2: u16 = 0x60e3;

/// SIMtrace2 DFU bootloader product ID.
///
/// Boards present this PID while held in DFU mode; reflashing happens at this
/// address, not the application PID.
pub const PID_SIMTRACE2_DFU: u16 = 0x60e2;

/// ngff-cardem variant product ID.
pub const PID_NGFF_CARDEM: u16 = 0x616e;

/// octsimtest variant product ID (eight-slot dev kit).
pub const PID_OCTSIMTEST: u16 = 0x616d;

// ---------------------------------------------------------------------------
// USB interface / endpoint layout
// ---------------------------------------------------------------------------

/// USIM1 bulk OUT endpoint address (host -> device).
///
/// Per `firmware/libcommon/include/simtrace_usb.h`:
/// `SIMTRACE_CARDEM_USB_EP_USIM1_DATAOUT = 4`. The high bit (0x80) is
/// cleared for OUT endpoints, so the address is `0x04`.
pub const EP_BULK_OUT: u8 = 0x04;

/// USIM1 bulk IN endpoint address (device -> host).
///
/// `SIMTRACE_CARDEM_USB_EP_USIM1_DATAIN = 5`, with the IN-direction bit set
/// gives endpoint address `0x85`.
pub const EP_BULK_IN: u8 = 0x85;

/// USIM1 interrupt IN endpoint address.
///
/// `SIMTRACE_CARDEM_USB_EP_USIM1_INT = 6`, IN-direction bit set: `0x86`.
pub const EP_INT_IN: u8 = 0x86;

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// On-wire length of [`SimtraceMsgHdr`] in bytes.
pub const HDR_LEN: usize = 8;

/// `SIMTRACE_MSGC_CARDEM` -- cardem message class.
pub const MSGC_CARDEM: u8 = 0x02;

/// Common 8-byte header prefixing every SIMtrace2 message.
///
/// Wire layout (little-endian):
///
/// | Offset | Size | Field       |
/// |-------:|-----:|-------------|
/// | 0      | 1    | `msg_class` |
/// | 1      | 1    | `msg_type`  |
/// | 2      | 1    | `seq_nr`    |
/// | 3      | 1    | `slot_nr`   |
/// | 4      | 2    | `_reserved` |
/// | 6      | 2    | `msg_len` (total bytes incl. header) |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimtraceMsgHdr {
    /// Message class (`SIMTRACE_MSGC_*`).
    pub msg_class: u8,
    /// Message type within the class.
    pub msg_type: u8,
    /// Host-incremented sequence number; firmware echoes it back where useful.
    pub seq_nr: u8,
    /// SIM slot number. Always 0 for single-slot boards.
    pub slot_nr: u8,
    /// Total message length on the wire, including the header.
    pub msg_len: u16,
}

impl SimtraceMsgHdr {
    /// Encode the header into the first 8 bytes of `out`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooSmall`] if `out` is shorter than
    /// [`HDR_LEN`].
    pub fn encode(&self, out: &mut [u8]) -> Result<(), ProtocolError> {
        if out.len() < HDR_LEN {
            return Err(ProtocolError::BufferTooSmall);
        }
        out[0] = self.msg_class;
        out[1] = self.msg_type;
        out[2] = self.seq_nr;
        out[3] = self.slot_nr;
        out[4] = 0;
        out[5] = 0;
        out[6..8].copy_from_slice(&self.msg_len.to_le_bytes());
        Ok(())
    }

    /// Decode an 8-byte header from the front of `data`.
    ///
    /// `data` must be at least [`HDR_LEN`] bytes; surplus bytes are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Truncated`] if `data.len() < HDR_LEN`.
    pub const fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < HDR_LEN {
            return Err(ProtocolError::Truncated);
        }
        Ok(Self {
            msg_class: data[0],
            msg_type: data[1],
            seq_nr: data[2],
            slot_nr: data[3],
            // bytes 4..6 are reserved; we don't surface them
            msg_len: u16::from_le_bytes([data[6], data[7]]),
        })
    }
}

// ---------------------------------------------------------------------------
// Cardem message types
// ---------------------------------------------------------------------------

/// Cardem message types under [`MSGC_CARDEM`].
///
/// Numeric values come from `enum simtrace_msg_type_cardem` in the upstream
/// header: TX_DATA = 1, SET_ATR = 2, STATS = 3, STATUS = 4, CARDINSERT = 5,
/// RX_DATA = 6, PTS = 7, CONFIG = 8.
///
/// Direction-prefix legend in the upstream naming:
/// - `DT` = direction-to-device (host -> device)
/// - `DO` = direction-from-device (device -> host)
/// - `BD` = bi-directional
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CardemMsgType {
    /// Host -> device: TPDU payload to clock out to the phone.
    TxData = 1,
    /// Host -> device: ATR to present at the next reset.
    SetAtr = 2,
    /// Bi-directional: cardem statistics.
    Stats = 3,
    /// Bi-directional: VCC/CLK/RST/INSERT status flags + timing parameters.
    Status = 4,
    /// Host -> device: assert / de-assert simulated card-insert switch.
    CardInsert = 5,
    /// Device -> host: phone sent us C-APDU bytes.
    RxData = 6,
    /// Device -> host: phone issued a PTS / PPS request.
    Pts = 7,
    /// Bi-directional: get/set firmware configuration.
    Config = 8,
}

impl TryFrom<u8> for CardemMsgType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TxData),
            2 => Ok(Self::SetAtr),
            3 => Ok(Self::Stats),
            4 => Ok(Self::Status),
            5 => Ok(Self::CardInsert),
            6 => Ok(Self::RxData),
            7 => Ok(Self::Pts),
            8 => Ok(Self::Config),
            _ => Err(ProtocolError::UnknownMsgType),
        }
    }
}

// ---------------------------------------------------------------------------
// Cardem data flags
// ---------------------------------------------------------------------------

/// TPDU header present in this message.
pub const DATA_F_TPDU_HDR: u32 = 0x0000_0001;

/// Final fragment of this direction's transmission.
pub const DATA_F_FINAL: u32 = 0x0000_0002;

/// Procedure byte present + we want the firmware to keep TX-ing data.
pub const DATA_F_PB_AND_TX: u32 = 0x0000_0004;

/// Procedure byte present + we want the firmware to switch to RX.
pub const DATA_F_PB_AND_RX: u32 = 0x0000_0008;

// ---------------------------------------------------------------------------
// Cardem status flags
// ---------------------------------------------------------------------------

/// Phone is supplying Vcc to the card slot.
pub const STATUS_F_VCC_PRESENT: u32 = 0x0000_0001;

/// Phone is providing a clock signal.
pub const STATUS_F_CLK_ACTIVE: u32 = 0x0000_0002;

/// Internal "rcemu" state machine is active. Surfaced by firmware; the host
/// generally ignores it.
pub const STATUS_F_RCEMU_ACTIVE: u32 = 0x0000_0004;

/// Simulated card-insert pin is asserted toward the phone.
pub const STATUS_F_CARD_INSERT: u32 = 0x0000_0008;

/// Phone is driving RST low (card is in reset).
pub const STATUS_F_RESET_ACTIVE: u32 = 0x0000_0010;

// ---------------------------------------------------------------------------
// Config feature flags
// ---------------------------------------------------------------------------

/// Request firmware to push `Status` updates on the interrupt endpoint as
/// soon as flags change, rather than only on poll.
pub const CONFIG_FEAT_STATUS_IRQ: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// Decoded payload types
// ---------------------------------------------------------------------------

/// Decoded `BD_CEMU_STATUS` payload.
///
/// Wire layout: `flags: u32 LE, voltage_mv: u16 LE, fi: u8, di: u8, wi: u8,
/// waiting_time: u32 LE` -- 13 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardemStatus {
    /// Bit-mask of `STATUS_F_*` flags.
    pub flags: u32,
    /// Last-measured Vcc level in millivolts.
    pub voltage_mv: u16,
    /// Index into ISO 7816-3 Table 7 (F / f_max).
    pub fi: u8,
    /// Index into ISO 7816-3 Table 8 (D).
    pub di: u8,
    /// Waiting Integer (WI) per ISO 7816-3 §10.2.
    pub wi: u8,
    /// Waiting Time in ETU per ISO 7816-3 §8.1.
    pub waiting_time: u32,
}

/// On-wire size of [`CardemStatus`].
pub const STATUS_LEN: usize = 4 + 2 + 1 + 1 + 1 + 4;

impl CardemStatus {
    /// Decode from the payload bytes that follow the [`SimtraceMsgHdr`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Truncated`] if `payload.len() < STATUS_LEN`.
    pub const fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < STATUS_LEN {
            return Err(ProtocolError::Truncated);
        }
        Ok(Self {
            flags: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
            voltage_mv: u16::from_le_bytes([payload[4], payload[5]]),
            fi: payload[6],
            di: payload[7],
            wi: payload[8],
            waiting_time: u32::from_le_bytes([payload[9], payload[10], payload[11], payload[12]]),
        })
    }

    /// True iff Vcc is present and a clock is running.
    pub const fn is_powered(self) -> bool {
        const POWER_MASK: u32 = STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE;
        self.flags & POWER_MASK == POWER_MASK
    }

    /// True iff RST is held low (card is being reset).
    pub const fn is_in_reset(self) -> bool {
        self.flags & STATUS_F_RESET_ACTIVE != 0
    }

    /// True iff Vcc is present (regardless of clock).
    pub const fn has_vcc(self) -> bool {
        self.flags & STATUS_F_VCC_PRESENT != 0
    }
}

/// Decoded `DO_CEMU_RX_DATA` payload (variable-length APDU bytes).
///
/// Wire layout: `flags: u32 LE, data_len: u16 LE, data: [u8; data_len]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxDataView<'a> {
    /// `DATA_F_*` flag bitmask.
    pub flags: u32,
    /// Slice borrowed from the input payload.
    pub data: &'a [u8],
}

impl<'a> RxDataView<'a> {
    /// Decode an `RxData` payload.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Truncated`] if the header is short or the
    /// declared `data_len` exceeds what was provided.
    /// Returns [`ProtocolError::InvalidLength`] if `data_len` exceeds the
    /// caller's allotment.
    pub fn decode(payload: &'a [u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 6 {
            return Err(ProtocolError::Truncated);
        }
        let flags = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let data_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
        if payload.len() < 6 + data_len {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(Self {
            flags,
            data: &payload[6..6 + data_len],
        })
    }
}

// ---------------------------------------------------------------------------
// Encoders -- host -> device messages
// ---------------------------------------------------------------------------

/// Header + payload sizes for `SET_ATR`: header + `atr_len` (1) + max 33 ATR bytes.
const MAX_ATR_BYTES: usize = 33;

/// Encode an `HO_CEMU_SET_ATR` (`SetAtr`) message into a freshly allocated buffer.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidLength`] if `atr` is empty or longer than
/// 33 bytes (ATR upper bound per ISO 7816-3).
pub fn encode_set_atr(seq_nr: u8, slot_nr: u8, atr: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if atr.is_empty() || atr.len() > MAX_ATR_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    let payload_len = 1 + atr.len();
    let total = HDR_LEN + payload_len;
    let mut out = vec![0u8; total];

    let hdr = SimtraceMsgHdr {
        msg_class: MSGC_CARDEM,
        msg_type: CardemMsgType::SetAtr as u8,
        seq_nr,
        slot_nr,
        // total message length on the wire; firmware uses this to know how
        // much data follows the header.
        msg_len: u16::try_from(total).map_err(|_| ProtocolError::InvalidLength)?,
    };
    hdr.encode(&mut out)?;

    // payload: atr_len (u8) + atr bytes
    out[HDR_LEN] = u8::try_from(atr.len()).map_err(|_| ProtocolError::InvalidLength)?;
    out[HDR_LEN + 1..].copy_from_slice(atr);

    Ok(out)
}

/// Encode an `HO_CEMU_TX_DATA` (`TxData`) message into a freshly allocated buffer.
///
/// The `flags` argument is typically `DATA_F_PB_AND_TX | DATA_F_FINAL` when
/// sending a complete R-APDU. See the data-flag constants.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidLength`] if `data.len()` exceeds
/// `u16::MAX` or the total message size exceeds `u16::MAX`.
pub fn encode_tx_data(
    seq_nr: u8,
    slot_nr: u8,
    flags: u32,
    data: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let data_len_u16 = u16::try_from(data.len()).map_err(|_| ProtocolError::InvalidLength)?;
    let payload_len = 4 + 2 + data.len();
    let total = HDR_LEN + payload_len;
    let total_u16 = u16::try_from(total).map_err(|_| ProtocolError::InvalidLength)?;
    let mut out = vec![0u8; total];

    let hdr = SimtraceMsgHdr {
        msg_class: MSGC_CARDEM,
        msg_type: CardemMsgType::TxData as u8,
        seq_nr,
        slot_nr,
        msg_len: total_u16,
    };
    hdr.encode(&mut out)?;

    out[HDR_LEN..HDR_LEN + 4].copy_from_slice(&flags.to_le_bytes());
    out[HDR_LEN + 4..HDR_LEN + 6].copy_from_slice(&data_len_u16.to_le_bytes());
    out[HDR_LEN + 6..].copy_from_slice(data);

    Ok(out)
}

/// Encode a `DT_CEMU_CARDINSERT` message asking the firmware to assert (or
/// release) the card-insert switch toward the phone.
///
/// # Errors
///
/// This encoder cannot fail at runtime; it returns `Result` for API symmetry
/// with the other encoders.
pub fn encode_card_insert(
    seq_nr: u8,
    slot_nr: u8,
    inserted: bool,
) -> Result<Vec<u8>, ProtocolError> {
    let payload_len = 1;
    let total = HDR_LEN + payload_len;
    let mut out = vec![0u8; total];

    let hdr = SimtraceMsgHdr {
        msg_class: MSGC_CARDEM,
        msg_type: CardemMsgType::CardInsert as u8,
        seq_nr,
        slot_nr,
        // total fits in u16 (9), unwrap is safe and documented by the API.
        msg_len: u16::try_from(total).map_err(|_| ProtocolError::InvalidLength)?,
    };
    hdr.encode(&mut out)?;

    out[HDR_LEN] = u8::from(inserted);
    Ok(out)
}

/// Encode a `BD_CEMU_CONFIG` message setting the firmware feature mask.
///
/// `pres_pol` mirrors the C struct field: bit 0 is the GPIO level when the
/// SIM is present; bit 1 is a validity flag for that bit. Pass `0` to leave
/// the firmware default.
///
/// # Errors
///
/// Cannot fail at runtime; returns `Result` for API symmetry.
pub fn encode_config(
    seq_nr: u8,
    slot_nr: u8,
    features: u32,
    slot_mux_nr: u8,
    pres_pol: u8,
) -> Result<Vec<u8>, ProtocolError> {
    let payload_len = 4 + 1 + 1;
    let total = HDR_LEN + payload_len;
    let mut out = vec![0u8; total];

    let hdr = SimtraceMsgHdr {
        msg_class: MSGC_CARDEM,
        msg_type: CardemMsgType::Config as u8,
        seq_nr,
        slot_nr,
        msg_len: u16::try_from(total).map_err(|_| ProtocolError::InvalidLength)?,
    };
    hdr.encode(&mut out)?;

    out[HDR_LEN..HDR_LEN + 4].copy_from_slice(&features.to_le_bytes());
    out[HDR_LEN + 4] = slot_mux_nr;
    out[HDR_LEN + 5] = pres_pol;

    Ok(out)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by the protocol layer (encoding / decoding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// Output buffer too small for the requested encoding.
    BufferTooSmall,
    /// Input ends before the expected field boundary.
    Truncated,
    /// A declared length field is inconsistent with the available bytes
    /// or exceeds a documented protocol limit.
    InvalidLength,
    /// `msg_type` value outside the known cardem set.
    UnknownMsgType,
    /// `msg_class` byte did not match [`MSGC_CARDEM`].
    WrongMsgClass,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("output buffer too small"),
            Self::Truncated => f.write_str("input truncated before field boundary"),
            Self::InvalidLength => f.write_str("declared length inconsistent with buffer"),
            Self::UnknownMsgType => f.write_str("unknown cardem message type"),
            Self::WrongMsgClass => f.write_str("message class is not SIMTRACE_MSGC_CARDEM"),
        }
    }
}

impl std::error::Error for ProtocolError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -- Header encode / decode -------------------------------------------

    #[test]
    fn encode_header_writes_eight_bytes_le() {
        let hdr = SimtraceMsgHdr {
            msg_class: MSGC_CARDEM,
            msg_type: CardemMsgType::SetAtr as u8,
            seq_nr: 0x42,
            slot_nr: 0,
            msg_len: 0x0123,
        };
        let mut out = [0u8; HDR_LEN];
        hdr.encode(&mut out).unwrap();
        assert_eq!(out, [0x02, 0x02, 0x42, 0x00, 0x00, 0x00, 0x23, 0x01]);
    }

    #[test]
    fn decode_header_parses_le_length() {
        let wire = [0x02, 0x06, 0x07, 0x00, 0x00, 0x00, 0xAB, 0xCD];
        let hdr = SimtraceMsgHdr::decode(&wire).unwrap();
        assert_eq!(hdr.msg_class, MSGC_CARDEM);
        assert_eq!(hdr.msg_type, CardemMsgType::RxData as u8);
        assert_eq!(hdr.seq_nr, 0x07);
        assert_eq!(hdr.slot_nr, 0x00);
        assert_eq!(hdr.msg_len, 0xCDAB);
    }

    #[test]
    fn decode_header_rejects_truncated_input() {
        let wire = [0u8; 7];
        let err = SimtraceMsgHdr::decode(&wire).unwrap_err();
        assert_eq!(err, ProtocolError::Truncated);
    }

    #[test]
    fn encode_header_rejects_undersized_buffer() {
        let hdr = SimtraceMsgHdr {
            msg_class: 0,
            msg_type: 0,
            seq_nr: 0,
            slot_nr: 0,
            msg_len: 0,
        };
        let mut out = [0u8; 7];
        let err = hdr.encode(&mut out).unwrap_err();
        assert_eq!(err, ProtocolError::BufferTooSmall);
    }

    #[test]
    fn header_round_trip() {
        let original = SimtraceMsgHdr {
            msg_class: 0x02,
            msg_type: 0x06,
            seq_nr: 0xAB,
            slot_nr: 0x01,
            msg_len: 1234,
        };
        let mut out = [0u8; HDR_LEN];
        original.encode(&mut out).unwrap();
        let decoded = SimtraceMsgHdr::decode(&out).unwrap();
        assert_eq!(decoded, original);
    }

    // -- CardemMsgType conversion -----------------------------------------

    #[test]
    fn msg_type_from_u8_known_values() {
        assert_eq!(CardemMsgType::try_from(1).unwrap(), CardemMsgType::TxData);
        assert_eq!(CardemMsgType::try_from(2).unwrap(), CardemMsgType::SetAtr);
        assert_eq!(CardemMsgType::try_from(3).unwrap(), CardemMsgType::Stats);
        assert_eq!(CardemMsgType::try_from(4).unwrap(), CardemMsgType::Status);
        assert_eq!(
            CardemMsgType::try_from(5).unwrap(),
            CardemMsgType::CardInsert
        );
        assert_eq!(CardemMsgType::try_from(6).unwrap(), CardemMsgType::RxData);
        assert_eq!(CardemMsgType::try_from(7).unwrap(), CardemMsgType::Pts);
        assert_eq!(CardemMsgType::try_from(8).unwrap(), CardemMsgType::Config);
    }

    #[test]
    fn msg_type_from_u8_rejects_zero_and_oob() {
        assert_eq!(
            CardemMsgType::try_from(0).unwrap_err(),
            ProtocolError::UnknownMsgType
        );
        assert_eq!(
            CardemMsgType::try_from(9).unwrap_err(),
            ProtocolError::UnknownMsgType
        );
        assert_eq!(
            CardemMsgType::try_from(0xFF).unwrap_err(),
            ProtocolError::UnknownMsgType
        );
    }

    // -- encode_set_atr ----------------------------------------------------

    #[test]
    fn encode_set_atr_minimal_atr() {
        let atr = [0x3B, 0x00];
        let wire = encode_set_atr(0, 0, &atr).unwrap();
        // header (8) + atr_len (1) + atr (2) = 11
        assert_eq!(wire.len(), 11);
        // header
        assert_eq!(wire[0], MSGC_CARDEM);
        assert_eq!(wire[1], CardemMsgType::SetAtr as u8);
        assert_eq!(wire[2], 0); // seq
        assert_eq!(wire[3], 0); // slot
        // reserved
        assert_eq!(&wire[4..6], &[0, 0]);
        // msg_len (LE)
        assert_eq!(&wire[6..8], &[11, 0]);
        // atr_len
        assert_eq!(wire[8], 2);
        // atr
        assert_eq!(&wire[9..11], &atr);
    }

    #[test]
    fn encode_set_atr_full_usim_atr() {
        // 22-byte USIM-realistic ATR (matches DEFAULT_ATR in simrs-card-api).
        let atr = [
            0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x1B, 0x67,
            0x4A, 0x4C, 0x75, 0x30, 0x34, 0x05, 0x4B, 0xE9,
        ];
        let wire = encode_set_atr(0x55, 1, &atr).unwrap();
        assert_eq!(wire.len(), HDR_LEN + 1 + atr.len());
        assert_eq!(wire[1], CardemMsgType::SetAtr as u8);
        assert_eq!(wire[2], 0x55);
        assert_eq!(wire[3], 1);
        assert_eq!(wire[8], u8::try_from(atr.len()).unwrap());
        assert_eq!(&wire[9..], &atr);
    }

    #[test]
    fn encode_set_atr_rejects_empty() {
        let err = encode_set_atr(0, 0, &[]).unwrap_err();
        assert_eq!(err, ProtocolError::InvalidLength);
    }

    #[test]
    fn encode_set_atr_rejects_oversized() {
        let big = [0u8; MAX_ATR_BYTES + 1];
        let err = encode_set_atr(0, 0, &big).unwrap_err();
        assert_eq!(err, ProtocolError::InvalidLength);
    }

    #[test]
    fn encode_set_atr_accepts_max_size() {
        let big = [0xAA; MAX_ATR_BYTES];
        let wire = encode_set_atr(0, 0, &big).unwrap();
        assert_eq!(wire[8], u8::try_from(MAX_ATR_BYTES).unwrap());
        assert_eq!(wire.len(), HDR_LEN + 1 + MAX_ATR_BYTES);
    }

    // -- encode_tx_data ----------------------------------------------------

    #[test]
    fn encode_tx_data_sw_only() {
        // Typical "send status word" pattern: flags = PB_AND_TX | FINAL, data = [SW1, SW2].
        let wire = encode_tx_data(1, 0, DATA_F_PB_AND_TX | DATA_F_FINAL, &[0x90, 0x00]).unwrap();
        assert_eq!(wire[0], MSGC_CARDEM);
        assert_eq!(wire[1], CardemMsgType::TxData as u8);
        // flags = 0x06
        assert_eq!(&wire[8..12], &[0x06, 0, 0, 0]);
        // data_len = 2
        assert_eq!(&wire[12..14], &[2, 0]);
        assert_eq!(&wire[14..], &[0x90, 0x00]);
    }

    #[test]
    fn encode_tx_data_zero_length_payload() {
        let wire = encode_tx_data(0, 0, 0, &[]).unwrap();
        assert_eq!(wire.len(), HDR_LEN + 6);
        // data_len field = 0
        assert_eq!(&wire[12..14], &[0, 0]);
    }

    #[test]
    fn encode_tx_data_max_size_under_u16() {
        // Pick a size that comfortably fits but exercises real payloads.
        let data = vec![0x55u8; 256];
        let wire = encode_tx_data(0, 0, DATA_F_PB_AND_TX, &data).unwrap();
        assert_eq!(wire.len(), HDR_LEN + 6 + 256);
        let len_field = u16::from_le_bytes([wire[12], wire[13]]);
        assert_eq!(len_field, 256);
    }

    // -- encode_card_insert ------------------------------------------------

    #[test]
    fn encode_card_insert_true_sets_byte_one() {
        let wire = encode_card_insert(0, 0, true).unwrap();
        assert_eq!(wire.len(), HDR_LEN + 1);
        assert_eq!(wire[1], CardemMsgType::CardInsert as u8);
        assert_eq!(wire[HDR_LEN], 1);
    }

    #[test]
    fn encode_card_insert_false_sets_byte_zero() {
        let wire = encode_card_insert(0, 0, false).unwrap();
        assert_eq!(wire[HDR_LEN], 0);
    }

    // -- encode_config -----------------------------------------------------

    #[test]
    fn encode_config_status_irq_feature() {
        let wire = encode_config(0, 0, CONFIG_FEAT_STATUS_IRQ, 0, 0).unwrap();
        assert_eq!(wire.len(), HDR_LEN + 6);
        assert_eq!(&wire[8..12], &[0x01, 0, 0, 0]);
        assert_eq!(wire[12], 0); // slot_mux_nr
        assert_eq!(wire[13], 0); // pres_pol
    }

    #[test]
    fn encode_config_carries_pres_pol() {
        let wire = encode_config(0, 0, 0, 0, 0x03).unwrap();
        assert_eq!(wire[13], 0x03);
    }

    // -- CardemStatus decoding --------------------------------------------

    #[test]
    fn decode_status_full_payload() {
        // flags = VCC|CLK|CARD_INSERT (= 0x0B), voltage = 1800 mV,
        // fi = 1, di = 1, wi = 10, waiting_time = 9600.
        let payload = [
            0x0B, 0x00, 0x00, 0x00, // flags LE
            0x08, 0x07, // 0x0708 = 1800 LE
            0x01, 0x01, 0x0A, // fi, di, wi
            0x80, 0x25, 0x00, 0x00, // 0x2580 = 9600 LE
        ];
        let s = CardemStatus::decode(&payload).unwrap();
        assert_eq!(
            s.flags,
            STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE | STATUS_F_CARD_INSERT
        );
        assert_eq!(s.voltage_mv, 1800);
        assert_eq!(s.fi, 1);
        assert_eq!(s.di, 1);
        assert_eq!(s.wi, 10);
        assert_eq!(s.waiting_time, 9600);
        assert!(s.is_powered());
        assert!(!s.is_in_reset());
        assert!(s.has_vcc());
    }

    #[test]
    fn decode_status_reset_active_makes_unpowered() {
        let payload = [
            0x13, 0x00, 0x00, 0x00, // VCC|CLK|RESET
            0x00, 0x00, 0, 0, 0, 0, 0, 0, 0,
        ];
        let s = CardemStatus::decode(&payload).unwrap();
        assert!(s.has_vcc());
        assert!(s.is_powered());
        assert!(s.is_in_reset());
    }

    #[test]
    fn decode_status_rejects_short() {
        let err = CardemStatus::decode(&[0u8; STATUS_LEN - 1]).unwrap_err();
        assert_eq!(err, ProtocolError::Truncated);
    }

    #[test]
    fn decode_status_powered_only_when_vcc_and_clk() {
        // Only VCC -- not powered (clock missing).
        let mut payload = [0u8; STATUS_LEN];
        payload[0] = u8::try_from(STATUS_F_VCC_PRESENT).unwrap();
        let s = CardemStatus::decode(&payload).unwrap();
        assert!(s.has_vcc());
        assert!(!s.is_powered());
    }

    // -- RxDataView decoding ----------------------------------------------

    #[test]
    fn decode_rx_data_minimal_apdu() {
        // flags=0, data_len=5, data = SELECT MF header
        let payload = [
            0x00, 0x00, 0x00, 0x00, // flags
            0x05, 0x00, // data_len LE
            0x00, 0xA4, 0x00, 0x04, 0x02,
        ];
        let rx = RxDataView::decode(&payload).unwrap();
        assert_eq!(rx.flags, 0);
        assert_eq!(rx.data, &[0x00, 0xA4, 0x00, 0x04, 0x02]);
    }

    #[test]
    fn decode_rx_data_with_zero_length_payload() {
        let payload = [
            0x01, 0x00, 0x00, 0x00, // flags = TPDU_HDR
            0x00, 0x00, // data_len = 0
        ];
        let rx = RxDataView::decode(&payload).unwrap();
        assert_eq!(rx.flags, DATA_F_TPDU_HDR);
        assert_eq!(rx.data, &[]);
    }

    #[test]
    fn decode_rx_data_rejects_truncated_header() {
        let err = RxDataView::decode(&[0, 0, 0]).unwrap_err();
        assert_eq!(err, ProtocolError::Truncated);
    }

    #[test]
    fn decode_rx_data_rejects_length_mismatch() {
        // Claims 10 bytes but only carries 4.
        let payload = [0, 0, 0, 0, 10, 0, 1, 2, 3, 4];
        let err = RxDataView::decode(&payload).unwrap_err();
        assert_eq!(err, ProtocolError::InvalidLength);
    }

    #[test]
    fn decode_rx_data_data_flags_combined() {
        let payload = [
            u8::try_from(DATA_F_TPDU_HDR | DATA_F_FINAL).unwrap(),
            0,
            0,
            0,
            0,
            0,
        ];
        let rx = RxDataView::decode(&payload).unwrap();
        assert_eq!(rx.flags & DATA_F_TPDU_HDR, DATA_F_TPDU_HDR);
        assert_eq!(rx.flags & DATA_F_FINAL, DATA_F_FINAL);
    }

    // -- proptest round-trips ---------------------------------------------

    proptest! {
        #[test]
        fn header_encode_decode_round_trip(
            msg_type in 1u8..=8,
            seq_nr in any::<u8>(),
            slot_nr in any::<u8>(),
            msg_len in 8u16..=4096,
        ) {
            let original = SimtraceMsgHdr {
                msg_class: MSGC_CARDEM,
                msg_type,
                seq_nr,
                slot_nr,
                msg_len,
            };
            let mut buf = [0u8; HDR_LEN];
            original.encode(&mut buf).unwrap();
            let decoded = SimtraceMsgHdr::decode(&buf).unwrap();
            prop_assert_eq!(decoded, original);
        }

        #[test]
        fn set_atr_round_trips_via_decoded_header(
            atr in proptest::collection::vec(any::<u8>(), 2..=33),
            seq_nr in any::<u8>(),
            slot_nr in any::<u8>(),
        ) {
            let wire = encode_set_atr(seq_nr, slot_nr, &atr).unwrap();
            let hdr = SimtraceMsgHdr::decode(&wire).unwrap();
            prop_assert_eq!(hdr.msg_class, MSGC_CARDEM);
            prop_assert_eq!(hdr.msg_type, CardemMsgType::SetAtr as u8);
            prop_assert_eq!(hdr.seq_nr, seq_nr);
            prop_assert_eq!(hdr.slot_nr, slot_nr);
            prop_assert_eq!(hdr.msg_len as usize, wire.len());
            // payload: 1 + atr.len()
            prop_assert_eq!(wire[HDR_LEN] as usize, atr.len());
            prop_assert_eq!(&wire[HDR_LEN + 1..], &atr[..]);
        }

        #[test]
        fn tx_data_round_trips(
            data in proptest::collection::vec(any::<u8>(), 0..=512),
            flags in any::<u32>(),
            seq_nr in any::<u8>(),
            slot_nr in any::<u8>(),
        ) {
            let wire = encode_tx_data(seq_nr, slot_nr, flags, &data).unwrap();
            let hdr = SimtraceMsgHdr::decode(&wire).unwrap();
            prop_assert_eq!(hdr.msg_class, MSGC_CARDEM);
            prop_assert_eq!(hdr.msg_type, CardemMsgType::TxData as u8);
            prop_assert_eq!(hdr.msg_len as usize, wire.len());

            // flags
            let got_flags = u32::from_le_bytes([
                wire[HDR_LEN],
                wire[HDR_LEN + 1],
                wire[HDR_LEN + 2],
                wire[HDR_LEN + 3],
            ]);
            prop_assert_eq!(got_flags, flags);

            // data_len matches what we wrote
            let data_len = u16::from_le_bytes([wire[HDR_LEN + 4], wire[HDR_LEN + 5]]) as usize;
            prop_assert_eq!(data_len, data.len());

            // data round-trips
            prop_assert_eq!(&wire[HDR_LEN + 6..], &data[..]);
        }

        #[test]
        fn status_round_trips_through_decode(
            flags in any::<u32>(),
            voltage_mv in any::<u16>(),
            fi in any::<u8>(),
            di in any::<u8>(),
            wi in any::<u8>(),
            waiting_time in any::<u32>(),
        ) {
            let mut payload = [0u8; STATUS_LEN];
            payload[0..4].copy_from_slice(&flags.to_le_bytes());
            payload[4..6].copy_from_slice(&voltage_mv.to_le_bytes());
            payload[6] = fi;
            payload[7] = di;
            payload[8] = wi;
            payload[9..13].copy_from_slice(&waiting_time.to_le_bytes());

            let s = CardemStatus::decode(&payload).unwrap();
            prop_assert_eq!(s.flags, flags);
            prop_assert_eq!(s.voltage_mv, voltage_mv);
            prop_assert_eq!(s.fi, fi);
            prop_assert_eq!(s.di, di);
            prop_assert_eq!(s.wi, wi);
            prop_assert_eq!(s.waiting_time, waiting_time);
        }

        #[test]
        fn rx_data_round_trips_when_we_assemble_payload(
            data in proptest::collection::vec(any::<u8>(), 0..=512),
            flags in any::<u32>(),
        ) {
            let mut payload = vec![0u8; 6 + data.len()];
            payload[0..4].copy_from_slice(&flags.to_le_bytes());
            let len_u16 = u16::try_from(data.len()).unwrap();
            payload[4..6].copy_from_slice(&len_u16.to_le_bytes());
            payload[6..].copy_from_slice(&data);

            let rx = RxDataView::decode(&payload).unwrap();
            prop_assert_eq!(rx.flags, flags);
            prop_assert_eq!(rx.data, &data[..]);
        }
    }
}
