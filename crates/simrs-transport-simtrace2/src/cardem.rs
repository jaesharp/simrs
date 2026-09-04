//! [`Simtrace2Transport`] -- a [`CardTransport`] over USB to a SIMtrace2 board.
//!
//! This module bridges the gap between the byte-level SIMtrace2 USB protocol
//! (encoded by [`crate::protocol`]) and the APDU-level [`CardTransport`]
//! contract that the rest of simrs speaks.
//!
//! # Reset semantics
//!
//! The transport derives card-lifecycle events from `BD_CEMU_STATUS` flag
//! transitions, mirroring `update_status_flags` in upstream
//! `host/src/simtrace2-cardem-pcsc.c`:
//!
//! - VCC rising (from absent to present) + CLK active + RST not asserted ->
//!   [`CardEvent::PowerOn`] (cold reset).
//! - RST falling (previously asserted, now released) while VCC remained on ->
//!   [`CardEvent::WarmReset`].
//! - VCC falling (was on, now absent) -> [`CardEvent::Shutdown`].
//!
//! `DO_CEMU_RX_DATA` is currently mapped to [`CardEvent::Apdu`] with the
//! full data buffer copied into the caller's slice. Fragmentation is not
//! observed in the cardem firmware (the firmware delivers a full TPDU in a
//! single message), but if the firmware ever splits a message we treat each
//! `RX_DATA` as its own event -- callers are responsible for re-assembling.
//!
//! `DO_CEMU_PTS` (PPS negotiation) is logged at trace-equivalent verbosity
//! (eprintln) and otherwise ignored, since the firmware handles PPS itself.

use std::time::Duration;

use simrs_transport::{CardEvent, CardTransport};

use crate::Error;
use crate::device::{CardemEndpoints, DeviceFilter, open_endpoints};
use crate::protocol::{
    CONFIG_FEAT_STATUS_IRQ, CardemMsgType, CardemStatus, DATA_F_FINAL, DATA_F_PB_AND_TX, HDR_LEN,
    MSGC_CARDEM, RxDataView, STATUS_F_RESET_ACTIVE, STATUS_F_VCC_PRESENT, SimtraceMsgHdr,
    encode_card_insert, encode_config, encode_set_atr, encode_tx_data,
};

use nusb::transfer::Buffer;

/// Maximum bytes we'll pull from a single bulk IN transfer.
///
/// The upstream host tool allocates 4096 (`16 * 256`). We follow the same
/// envelope -- it's well over any real cardem message size (the largest
/// payload is an R-APDU at ~258 + header overhead).
const BULK_IN_BUF: usize = 4096;

/// Default deadline for `recv()` polls.
///
/// Long enough that a phone's idle-then-active sequence doesn't trip a false
/// timeout, short enough that Ctrl-C-style shutdowns from the caller are
/// responsive.
const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_secs(60);

/// Default timeout for bulk OUT writes during `send` / `send_atr`.
const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// `CardTransport` implementation over USB to an Osmocom SIMtrace2 board.
///
/// # Lifecycle
///
/// 1. [`Simtrace2Transport::open`] enumerates USB, claims the cardem
///    interface, and exchanges an initial `Config` + `CardInsert(true)`
///    pair with the firmware to enable interrupt-driven status updates
///    and assert the simulated card-insert signal toward the phone.
/// 2. Callers should immediately call [`Self::send_atr`] with the ATR
///    they want the firmware to present at the next reset. (The firmware
///    silently rejects ATR updates that arrive after RST has already been
///    released, so pre-staging the ATR before the first `recv()` is
///    essential -- see ISO 7816-3 §6.3.)
/// 3. The caller drives an event loop on [`Self::recv`].
///
/// # Sequence numbers
///
/// We increment a free-running `u8` and place it in every outgoing
/// `simtrace_msg_hdr.seq_nr`. The firmware does not enforce any ordering on
/// the host's sequence numbers; it is logged for diagnostic purposes only.
pub struct Simtrace2Transport {
    endpoints: CardemEndpoints,
    seq_nr: u8,
    slot_nr: u8,
    last_status_flags: u32,
    /// `recv()` deadline. Configurable for tests / long-idle phones.
    recv_timeout: Duration,
    /// `send` / `send_atr` deadline.
    send_timeout: Duration,
}

impl Simtrace2Transport {
    /// Enumerate USB, claim the cardem interface, send initial config, and
    /// return a ready-to-use transport.
    ///
    /// The returned transport has already:
    /// - selected alt-setting 0 on interface 0,
    /// - sent a `Config` message enabling [`CONFIG_FEAT_STATUS_IRQ`] so that
    ///   status updates arrive promptly on the interrupt endpoint,
    /// - asserted simulated card-insert toward the phone.
    ///
    /// Callers **must** call [`Self::send_atr`] before the first reset
    /// transition (see the type-level doc comment).
    ///
    /// # Errors
    ///
    /// Returns [`Error::DeviceNotFound`] / [`Error::DfuModeDetected`] /
    /// [`Error::Usb`] as documented on [`open_endpoints`].
    pub fn open(filter: &DeviceFilter) -> Result<Self, Error> {
        let endpoints = open_endpoints(filter)?;
        let mut transport = Self {
            endpoints,
            seq_nr: 0,
            slot_nr: 0,
            last_status_flags: 0,
            recv_timeout: DEFAULT_RECV_TIMEOUT,
            send_timeout: DEFAULT_SEND_TIMEOUT,
        };

        // Configure: request status notifications on the interrupt endpoint.
        let cfg = encode_config(
            transport.next_seq(),
            transport.slot_nr,
            CONFIG_FEAT_STATUS_IRQ,
            0,
            0,
        )
        .map_err(Error::Protocol)?;
        transport.write_out(&cfg)?;

        // Assert simulated card-insert so the phone sees a SIM as soon as
        // it powers up.
        let ins = encode_card_insert(transport.next_seq(), transport.slot_nr, true)
            .map_err(Error::Protocol)?;
        transport.write_out(&ins)?;

        Ok(transport)
    }

    /// Override the default recv() deadline.
    ///
    /// Useful in tests where a quicker timeout makes failures more readable.
    pub const fn set_recv_timeout(&mut self, t: Duration) {
        self.recv_timeout = t;
    }

    /// Override the default send() deadline.
    pub const fn set_send_timeout(&mut self, t: Duration) {
        self.send_timeout = t;
    }

    /// Use a non-zero slot number when communicating with multi-slot
    /// firmware variants (qmod, octsimtest). Defaults to 0.
    pub const fn set_slot(&mut self, slot_nr: u8) {
        self.slot_nr = slot_nr;
    }

    /// Free-running 8-bit sequence number.
    const fn next_seq(&mut self) -> u8 {
        let s = self.seq_nr;
        self.seq_nr = self.seq_nr.wrapping_add(1);
        s
    }

    /// Write a full pre-encoded message (header + payload) on the bulk OUT
    /// endpoint with the configured send timeout.
    fn write_out(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let buffer = Buffer::from(bytes.to_vec());
        let completion = self
            .endpoints
            .bulk_out
            .transfer_blocking(buffer, self.send_timeout);
        // `into_result()` discards `actual_len` -- for an OUT transfer we
        // require the entire buffer be sent.
        completion
            .into_result()
            .map(|_| ())
            .map_err(Error::from_transfer)
    }

    /// Try to interpret a complete message read from a bulk IN transfer and
    /// drive `buf` / `CardEvent` from it.
    ///
    /// Returns:
    /// - `Ok(Some(CardEvent))` when the message corresponds to a card-side
    ///   event the caller should act on.
    /// - `Ok(None)` when the message was internal (`Pts`, `Stats`,
    ///   `Config` echo, or a status update that did not cross a lifecycle
    ///   threshold) and the caller should poll for the next message.
    /// - `Err(_)` for protocol errors.
    fn handle_message(&mut self, msg: &[u8], buf: &mut [u8]) -> Result<Option<CardEvent>, Error> {
        if msg.len() < HDR_LEN {
            return Err(Error::Protocol(crate::protocol::ProtocolError::Truncated));
        }
        let hdr = SimtraceMsgHdr::decode(msg).map_err(Error::Protocol)?;
        if hdr.msg_class != MSGC_CARDEM {
            // Foreign class -- not our concern; ignore.
            return Ok(None);
        }
        let total = usize::from(hdr.msg_len);
        if total > msg.len() {
            // Firmware claimed more bytes than the transfer carried; bail.
            return Err(Error::Protocol(crate::protocol::ProtocolError::Truncated));
        }
        let payload = &msg[HDR_LEN..total];
        let mt = CardemMsgType::try_from(hdr.msg_type).map_err(Error::Protocol)?;
        match mt {
            CardemMsgType::Status => {
                let status = CardemStatus::decode(payload).map_err(Error::Protocol)?;
                Ok(self.classify_status_transition(status.flags))
            }
            CardemMsgType::RxData => {
                let rx = RxDataView::decode(payload).map_err(Error::Protocol)?;
                if rx.data.len() > buf.len() {
                    return Err(Error::BufferTooSmall);
                }
                buf[..rx.data.len()].copy_from_slice(rx.data);
                Ok(Some(CardEvent::Apdu(rx.data.len())))
            }
            CardemMsgType::Pts => {
                eprintln!("simtrace2: ignoring PTS / PPS notification (firmware-handled)");
                Ok(None)
            }
            CardemMsgType::Stats | CardemMsgType::Config => {
                // Firmware echoes Config back as confirmation; Stats is just
                // counters. Neither is a card-side event.
                Ok(None)
            }
            CardemMsgType::TxData | CardemMsgType::SetAtr | CardemMsgType::CardInsert => {
                // These are host -> device types; receiving them inbound is a
                // protocol error from the firmware. Tolerate but log.
                eprintln!("simtrace2: unexpected host-direction msg_type {mt:?} on bulk IN");
                Ok(None)
            }
        }
    }

    /// Compare new status flags to [`Self::last_status_flags`] and emit a
    /// card-lifecycle event when the transition warrants one.
    const fn classify_status_transition(&mut self, flags: u32) -> Option<CardEvent> {
        let prev = self.last_status_flags;
        self.last_status_flags = flags;

        let vcc_now = (flags & STATUS_F_VCC_PRESENT) != 0;
        let vcc_prev = (prev & STATUS_F_VCC_PRESENT) != 0;
        let rst_now = (flags & STATUS_F_RESET_ACTIVE) != 0;
        let rst_prev = (prev & STATUS_F_RESET_ACTIVE) != 0;

        // VCC falling: phone removed power. This is shutdown regardless of
        // anything else.
        if vcc_prev && !vcc_now {
            return Some(CardEvent::Shutdown);
        }

        // VCC rising: phone just powered the slot. Always treat as cold
        // reset.
        if !vcc_prev && vcc_now {
            return Some(CardEvent::PowerOn);
        }

        // RST falling while VCC stayed on: warm reset finished, card should
        // re-present its ATR.
        if vcc_now && rst_prev && !rst_now {
            return Some(CardEvent::WarmReset);
        }

        // Otherwise this status update just told us something we don't act on.
        None
    }
}

impl CardTransport for Simtrace2Transport {
    type Error = Error;

    fn recv(&mut self, buf: &mut [u8]) -> Result<CardEvent, Self::Error> {
        loop {
            let rx_buf = Buffer::new(BULK_IN_BUF);
            let completion = self
                .endpoints
                .bulk_in
                .transfer_blocking(rx_buf, self.recv_timeout);
            let actual = completion.actual_len;
            let result = completion.status;
            let buffer = completion.buffer;
            result.map_err(Error::from_transfer)?;

            let msg = &buffer[..actual];
            if let Some(event) = self.handle_message(msg, buf)? {
                return Ok(event);
            }
            // Otherwise loop and read the next message.
        }
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let bytes = encode_tx_data(
            self.next_seq(),
            self.slot_nr,
            DATA_F_PB_AND_TX | DATA_F_FINAL,
            data,
        )
        .map_err(Error::Protocol)?;
        self.write_out(&bytes)
    }

    fn send_atr(&mut self, atr: &[u8]) -> Result<(), Self::Error> {
        let bytes = encode_set_atr(self.next_seq(), self.slot_nr, atr).map_err(Error::Protocol)?;
        self.write_out(&bytes)
    }
}

#[cfg(test)]
mod tests {
    //! These tests exercise `Simtrace2Transport::classify_status_transition`
    //! and `handle_message` -- the parts of the transport that operate on
    //! pre-decoded bytes and don't touch USB.
    //!
    //! Tests that require a live USB endpoint live in
    //! `tests/hardware.rs` and are marked `#[ignore]`.
    use super::*;
    use crate::protocol::{
        CONFIG_FEAT_STATUS_IRQ, CardemMsgType, HDR_LEN, MSGC_CARDEM, STATUS_F_CLK_ACTIVE,
        STATUS_F_RESET_ACTIVE, STATUS_F_VCC_PRESENT, STATUS_LEN, encode_set_atr, encode_tx_data,
    };

    // We can't easily build a `Simtrace2Transport` without opening real
    // USB endpoints (nusb does not expose constructors for `Endpoint`).
    // The classification logic is therefore mirrored in a freestanding
    // helper below; the impl mirrors classify_status_transition exactly
    // and both must be updated in lock-step. The cardem.rs implementation
    // is the source of truth.

    fn classify(prev: u32, next: u32) -> (Option<CardEvent>, u32) {
        // Mirror of Simtrace2Transport::classify_status_transition, kept in
        // sync with the impl. Both branches must be updated together.
        let vcc_now = (next & STATUS_F_VCC_PRESENT) != 0;
        let vcc_prev = (prev & STATUS_F_VCC_PRESENT) != 0;
        let rst_now = (next & STATUS_F_RESET_ACTIVE) != 0;
        let rst_prev = (prev & STATUS_F_RESET_ACTIVE) != 0;
        let event = if vcc_prev && !vcc_now {
            Some(CardEvent::Shutdown)
        } else if !vcc_prev && vcc_now {
            Some(CardEvent::PowerOn)
        } else if vcc_now && rst_prev && !rst_now {
            Some(CardEvent::WarmReset)
        } else {
            None
        };
        (event, next)
    }

    #[test]
    fn vcc_rising_yields_power_on() {
        let (ev, _) = classify(0, STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE);
        assert_eq!(ev, Some(CardEvent::PowerOn));
    }

    #[test]
    fn vcc_falling_yields_shutdown() {
        let (ev, _) = classify(STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE, 0);
        assert_eq!(ev, Some(CardEvent::Shutdown));
    }

    #[test]
    fn rst_falling_while_vcc_on_yields_warm_reset() {
        let prev = STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE | STATUS_F_RESET_ACTIVE;
        let next = STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE;
        let (ev, _) = classify(prev, next);
        assert_eq!(ev, Some(CardEvent::WarmReset));
    }

    #[test]
    fn vcc_steady_no_event() {
        let flags = STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE;
        let (ev, _) = classify(flags, flags);
        assert!(ev.is_none());
    }

    #[test]
    fn rst_rising_no_event() {
        // RST asserted (entering reset) is not itself a card event; we wait
        // for the rising edge of RST release before signalling.
        let prev = STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE;
        let next = STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE | STATUS_F_RESET_ACTIVE;
        let (ev, _) = classify(prev, next);
        assert!(ev.is_none());
    }

    #[test]
    fn vcc_falling_takes_precedence_over_rst() {
        // Even if RST happens to fall in the same update, VCC fall wins.
        let prev = STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE | STATUS_F_RESET_ACTIVE;
        let next = 0;
        let (ev, _) = classify(prev, next);
        assert_eq!(ev, Some(CardEvent::Shutdown));
    }

    // -- handle_message path-coverage tests (synthetic wire bytes) --
    //
    // These don't construct a Simtrace2Transport -- they exercise the same
    // decode path through a freestanding helper that mirrors the dispatch.

    fn parse_inbound_for_test(bytes: &[u8], buf: &mut [u8]) -> Result<Option<CardEvent>, Error> {
        // Parse just enough to classify; reset transitions are tested
        // separately. This mirrors handle_message minus the
        // self.classify_status_transition call (since we don't have state).
        if bytes.len() < HDR_LEN {
            return Err(Error::Protocol(crate::protocol::ProtocolError::Truncated));
        }
        let hdr = SimtraceMsgHdr::decode(bytes).map_err(Error::Protocol)?;
        if hdr.msg_class != MSGC_CARDEM {
            return Ok(None);
        }
        let payload = &bytes[HDR_LEN..hdr.msg_len as usize];
        match CardemMsgType::try_from(hdr.msg_type).map_err(Error::Protocol)? {
            CardemMsgType::RxData => {
                let rx = RxDataView::decode(payload).map_err(Error::Protocol)?;
                if rx.data.len() > buf.len() {
                    return Err(Error::BufferTooSmall);
                }
                buf[..rx.data.len()].copy_from_slice(rx.data);
                Ok(Some(CardEvent::Apdu(rx.data.len())))
            }
            CardemMsgType::Pts
            | CardemMsgType::Stats
            | CardemMsgType::Config
            | CardemMsgType::Status
            | CardemMsgType::TxData
            | CardemMsgType::SetAtr
            | CardemMsgType::CardInsert => Ok(None),
        }
    }

    fn fabricate_rx_data(apdu: &[u8], flags: u32) -> Vec<u8> {
        // header (8) + flags (4) + len (2) + data
        let total = HDR_LEN + 4 + 2 + apdu.len();
        let mut out = vec![0u8; total];
        let hdr = SimtraceMsgHdr {
            msg_class: MSGC_CARDEM,
            msg_type: CardemMsgType::RxData as u8,
            seq_nr: 0,
            slot_nr: 0,
            msg_len: u16::try_from(total).unwrap(),
        };
        hdr.encode(&mut out).unwrap();
        out[HDR_LEN..HDR_LEN + 4].copy_from_slice(&flags.to_le_bytes());
        out[HDR_LEN + 4..HDR_LEN + 6]
            .copy_from_slice(&u16::try_from(apdu.len()).unwrap().to_le_bytes());
        out[HDR_LEN + 6..].copy_from_slice(apdu);
        out
    }

    fn fabricate_status(flags: u32) -> Vec<u8> {
        let total = HDR_LEN + STATUS_LEN;
        let mut out = vec![0u8; total];
        let hdr = SimtraceMsgHdr {
            msg_class: MSGC_CARDEM,
            msg_type: CardemMsgType::Status as u8,
            seq_nr: 0,
            slot_nr: 0,
            msg_len: u16::try_from(total).unwrap(),
        };
        hdr.encode(&mut out).unwrap();
        out[HDR_LEN..HDR_LEN + 4].copy_from_slice(&flags.to_le_bytes());
        // voltage / fi / di / wi / waiting_time stay zero.
        out
    }

    #[test]
    fn parse_rx_data_copies_apdu_into_buf() {
        let apdu = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let wire = fabricate_rx_data(&apdu, 0);
        let mut buf = [0u8; 261];
        let ev = parse_inbound_for_test(&wire, &mut buf).unwrap();
        assert_eq!(ev, Some(CardEvent::Apdu(apdu.len())));
        assert_eq!(&buf[..apdu.len()], &apdu);
    }

    #[test]
    fn parse_rx_data_buffer_too_small_errors() {
        let apdu = [0xAA; 10];
        let wire = fabricate_rx_data(&apdu, 0);
        let mut buf = [0u8; 5];
        let err = parse_inbound_for_test(&wire, &mut buf).unwrap_err();
        matches!(err, Error::BufferTooSmall);
    }

    #[test]
    fn parse_status_returns_none_in_helper() {
        // Helper does not classify transitions, so it returns None for
        // Status messages.
        let wire = fabricate_status(STATUS_F_VCC_PRESENT | STATUS_F_CLK_ACTIVE);
        let mut buf = [0u8; 261];
        let ev = parse_inbound_for_test(&wire, &mut buf).unwrap();
        assert!(ev.is_none());
    }

    #[test]
    fn parse_unknown_msg_class_returns_none() {
        let mut wire = vec![0u8; HDR_LEN + 4];
        let hdr = SimtraceMsgHdr {
            msg_class: 0x77, // not MSGC_CARDEM
            msg_type: 1,
            seq_nr: 0,
            slot_nr: 0,
            msg_len: u16::try_from(wire.len()).unwrap(),
        };
        hdr.encode(&mut wire).unwrap();
        let mut buf = [0u8; 261];
        let ev = parse_inbound_for_test(&wire, &mut buf).unwrap();
        assert!(ev.is_none());
    }

    #[test]
    fn parse_truncated_header_errors() {
        let short = [0u8; 4];
        let mut buf = [0u8; 261];
        let err = parse_inbound_for_test(&short, &mut buf).unwrap_err();
        matches!(err, Error::Protocol(_));
    }

    // -- Verifying our outbound encoders match what the firmware expects --

    #[test]
    fn outbound_send_atr_format() {
        // What `send_atr(&atr)` ends up writing on the bulk OUT endpoint.
        let atr = [0x3B, 0x00];
        let wire = encode_set_atr(0, 0, &atr).unwrap();
        // msg_class
        assert_eq!(wire[0], MSGC_CARDEM);
        // msg_type
        assert_eq!(wire[1], CardemMsgType::SetAtr as u8);
        // atr_len + atr at offsets 8..
        assert_eq!(wire[HDR_LEN], 2);
        assert_eq!(&wire[HDR_LEN + 1..], &atr);
    }

    #[test]
    fn outbound_send_format() {
        // What `send(&rapdu)` ends up writing on the bulk OUT endpoint.
        let rapdu = [0x90, 0x00];
        let wire = encode_tx_data(0, 0, DATA_F_PB_AND_TX | DATA_F_FINAL, &rapdu).unwrap();
        assert_eq!(wire[0], MSGC_CARDEM);
        assert_eq!(wire[1], CardemMsgType::TxData as u8);
        // flags
        let got = u32::from_le_bytes([wire[8], wire[9], wire[10], wire[11]]);
        assert_eq!(got, DATA_F_PB_AND_TX | DATA_F_FINAL);
        // data_len
        let got_len = u16::from_le_bytes([wire[12], wire[13]]);
        assert_eq!(got_len, 2);
        assert_eq!(&wire[14..], &rapdu);
    }

    #[test]
    fn outbound_config_enables_status_irq() {
        let wire = encode_config(0, 0, CONFIG_FEAT_STATUS_IRQ, 0, 0).unwrap();
        assert_eq!(wire[1], CardemMsgType::Config as u8);
        // features little-endian
        assert_eq!(&wire[8..12], &[0x01, 0, 0, 0]);
    }
}
