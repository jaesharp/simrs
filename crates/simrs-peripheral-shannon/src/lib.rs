//! Samsung Shannon baseband SIM peripheral interface.
//!
//! Models the Shannon SIM MMIO register file as a pure state machine.
//! Each [`ShannonSim::write_reg`] call returns a [`ShannonAction`] that
//! the host (QEMU HLE layer) dispatches to the simrs SIM engine.
//! Responses are fed back via [`ShannonSim::deliver_response`].
//!
//! # Architecture
//!
//! ```text
//! Shannon firmware (ARM guest in QEMU)
//!   -> MMIO write to SIM_TX register
//!   -> QEMU MMIO trap
//!   -> ShannonSim::write_reg (pure state machine)
//!   -> ShannonAction::EmitApdu { len }
//!   -> Host dispatches to Sim::process()
//!   -> ShannonSim::deliver_response(msg_type, payload)
//!   -> Guest reads SIM_RX register
//! ```
//!
//! This crate does **not** perform actual MMIO -- it provides the
//! safe state machine that a QEMU plugin or HLE layer drives.
//!
//! # `no_std`
//!
//! This crate is `no_std`. All buffer sizes are compile-time constants.
//!
//! # Example
//!
//! ```
//! use simrs_peripheral_shannon::{ShannonSim, ShannonAction, ShannonSimState};
//! use simrs_peripheral_shannon::{REG_SIM_CON, CON_SIM_EN, CON_VCC_EN, CON_CLOCK_EN};
//!
//! let mut sim = ShannonSim::new();
//! assert_eq!(sim.state(), ShannonSimState::Idle);
//!
//! // Enable the SIM controller.
//! let action = sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
//! assert_eq!(action, ShannonAction::EmitPowerOn);
//! assert_eq!(sim.state(), ShannonSimState::WaitAtr);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

use simrs_transport_virtio::APDU_MAX;

// ---------------------------------------------------------------------------
// MMIO register offsets
// ---------------------------------------------------------------------------

/// SIM controller control register offset.
pub const REG_SIM_CON: u32 = 0x00;
/// SIM controller status register offset.
pub const REG_SIM_STAT: u32 = 0x04;
/// SIM TX data register offset (guest writes APDU command bytes here).
pub const REG_SIM_TX: u32 = 0x08;
/// SIM RX data register offset (guest reads APDU response bytes here).
pub const REG_SIM_RX: u32 = 0x0C;
/// SIM interrupt enable register offset.
pub const REG_SIM_INT_EN: u32 = 0x10;
/// SIM interrupt status register offset.
pub const REG_SIM_INT_ST: u32 = 0x14;
/// SIM baud rate register offset.
pub const REG_SIM_BAUD: u32 = 0x18;
/// SIM command register offset (triggers APDU send).
pub const REG_SIM_CMD: u32 = 0x1C;

// ---------------------------------------------------------------------------
// Control register bit fields
// ---------------------------------------------------------------------------

/// CON: SIM controller enable.
pub const CON_SIM_EN: u32 = 1 << 0;
/// CON: SIM reset line (active low, 1 = deassert reset).
pub const CON_SIM_RST: u32 = 1 << 1;
/// CON: Clock enable.
pub const CON_CLOCK_EN: u32 = 1 << 2;
/// CON: VCC power enable.
pub const CON_VCC_EN: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Status register bit fields
// ---------------------------------------------------------------------------

/// STAT: TX FIFO ready (can accept data).
pub const STAT_TX_READY: u32 = 1 << 0;
/// STAT: RX data available.
pub const STAT_RX_AVAIL: u32 = 1 << 1;
/// STAT: Card presence detected.
pub const STAT_CARD_DET: u32 = 1 << 2;
/// STAT: ATR reception complete.
pub const STAT_ATR_DONE: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Command register values
// ---------------------------------------------------------------------------

/// CMD: Send the APDU currently in the TX buffer.
pub const CMD_SEND_APDU: u32 = 0x01;
/// CMD: Request warm reset.
pub const CMD_WARM_RESET: u32 = 0x02;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// State of the Shannon SIM controller.
///
/// # Example
///
/// ```
/// use simrs_peripheral_shannon::ShannonSimState;
/// let s = ShannonSimState::Idle;
/// assert_eq!(s, ShannonSimState::Idle);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShannonSimState {
    /// Controller is idle / powered down.
    Idle,
    /// Waiting for ATR after power-on or warm reset.
    WaitAtr,
    /// Ready to exchange APDUs.
    Ready,
    /// Waiting for an APDU response from the host SIM.
    WaitResponse,
}

/// Action emitted by [`ShannonSim::write_reg`].
///
/// The host (QEMU plugin) inspects the returned action and dispatches
/// accordingly (e.g., calling `Sim::process(SimEvent::PowerOn)`).
///
/// # Example
///
/// ```
/// use simrs_peripheral_shannon::ShannonAction;
/// let a = ShannonAction::None;
/// assert_eq!(a, ShannonAction::None);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShannonAction {
    /// No host action required.
    None,
    /// Guest requested card power-on. Host should return ATR via
    /// [`ShannonSim::deliver_response`].
    EmitPowerOn,
    /// Guest requested card power-off.
    EmitPowerOff,
    /// Guest requested warm reset. Host should return ATR via
    /// [`ShannonSim::deliver_response`].
    EmitWarmReset,
    /// Guest submitted an APDU command. `len` bytes are available via
    /// [`ShannonSim::pending_tx`].
    EmitApdu {
        /// Number of APDU command bytes in the TX buffer.
        len: usize,
    },
}

// ---------------------------------------------------------------------------
// ShannonSim
// ---------------------------------------------------------------------------

/// Shannon SIM controller state machine.
///
/// Models the register file and TX/RX buffers. All operations are pure
/// (no I/O, no unsafe). The host dispatches [`ShannonAction`]s returned
/// by [`write_reg`](Self::write_reg) and feeds responses back via
/// [`deliver_response`](Self::deliver_response).
pub struct ShannonSim {
    state: ShannonSimState,
    // Register file
    con: u32,
    stat: u32,
    int_en: u32,
    int_st: u32,
    baud: u32,
    // TX buffer (guest -> host APDU command)
    tx_buf: [u8; APDU_MAX],
    tx_len: usize,
    // RX buffer (host -> guest APDU response / ATR)
    rx_buf: [u8; APDU_MAX],
    rx_len: usize,
    rx_pos: usize,
}

impl Default for ShannonSim {
    fn default() -> Self {
        Self::new()
    }
}

impl ShannonSim {
    /// Create a new controller in [`ShannonSimState::Idle`].
    pub const fn new() -> Self {
        Self {
            state: ShannonSimState::Idle,
            con: 0,
            stat: STAT_TX_READY | STAT_CARD_DET,
            int_en: 0,
            int_st: 0,
            baud: 0,
            tx_buf: [0; APDU_MAX],
            tx_len: 0,
            rx_buf: [0; APDU_MAX],
            rx_len: 0,
            rx_pos: 0,
        }
    }

    /// Current controller state.
    pub const fn state(&self) -> ShannonSimState {
        self.state
    }

    /// Read an MMIO register.
    ///
    /// Returns the register value. For `REG_SIM_RX`, returns the next
    /// byte from the RX buffer (auto-advancing the read position) packed
    /// into the low byte of a `u32`. Returns 0 when the buffer is empty.
    pub fn read_reg(&mut self, offset: u32) -> u32 {
        match offset {
            REG_SIM_CON => self.con,
            REG_SIM_STAT => self.stat,
            REG_SIM_RX if self.rx_pos < self.rx_len => {
                let b = self.rx_buf[self.rx_pos];
                self.rx_pos += 1;
                if self.rx_pos >= self.rx_len {
                    // All bytes consumed -- clear RX_AVAIL.
                    self.stat &= !STAT_RX_AVAIL;
                }
                u32::from(b)
            }
            REG_SIM_INT_EN => self.int_en,
            REG_SIM_INT_ST => self.int_st,
            REG_SIM_BAUD => self.baud,
            _ => 0,
        }
    }

    /// Write an MMIO register.
    ///
    /// Returns a [`ShannonAction`] indicating what the host should do
    /// in response.
    pub fn write_reg(&mut self, offset: u32, value: u32) -> ShannonAction {
        match offset {
            REG_SIM_CON => self.write_con(value),
            REG_SIM_TX => {
                // Append byte to TX buffer.
                if self.tx_len < APDU_MAX {
                    #[allow(clippy::cast_possible_truncation)]
                    let byte = value as u8; // intentional: MMIO register is 32-bit, only low byte used
                    self.tx_buf[self.tx_len] = byte;
                    self.tx_len += 1;
                }
                ShannonAction::None
            }
            REG_SIM_INT_EN => {
                self.int_en = value;
                ShannonAction::None
            }
            REG_SIM_INT_ST => {
                // Write-1-to-clear semantics.
                self.int_st &= !value;
                ShannonAction::None
            }
            REG_SIM_BAUD => {
                self.baud = value;
                ShannonAction::None
            }
            REG_SIM_CMD => self.write_cmd(value),
            _ => ShannonAction::None,
        }
    }

    /// Deliver a response (ATR or APDU response) from the host SIM.
    ///
    /// Returns `true` if the response was accepted (controller was
    /// expecting it), `false` otherwise.
    pub fn deliver_response(
        &mut self,
        msg_type: simrs_transport_virtio::MessageType,
        payload: &[u8],
    ) -> bool {
        use simrs_transport_virtio::MessageType;

        match (self.state, msg_type) {
            (ShannonSimState::WaitAtr, MessageType::PowerOn | MessageType::WarmReset) => {
                let n = payload.len().min(APDU_MAX);
                self.rx_buf[..n].copy_from_slice(&payload[..n]);
                self.rx_len = n;
                self.rx_pos = 0;
                self.stat |= STAT_RX_AVAIL | STAT_ATR_DONE;
                self.state = ShannonSimState::Ready;
                true
            }
            (ShannonSimState::WaitResponse, MessageType::Apdu) => {
                let n = payload.len().min(APDU_MAX);
                self.rx_buf[..n].copy_from_slice(&payload[..n]);
                self.rx_len = n;
                self.rx_pos = 0;
                self.stat |= STAT_RX_AVAIL;
                self.state = ShannonSimState::Ready;
                true
            }
            _ => false,
        }
    }

    /// Access the pending TX buffer (APDU command bytes written by the guest).
    ///
    /// Returns `Some(bytes)` if there is pending TX data, `None` otherwise.
    pub fn pending_tx(&self) -> Option<&[u8]> {
        if self.tx_len > 0 {
            Some(&self.tx_buf[..self.tx_len])
        } else {
            None
        }
    }

    /// Access the RX buffer contents (response / ATR data).
    pub fn rx_data(&self) -> &[u8] {
        &self.rx_buf[..self.rx_len]
    }

    // -- internal helpers --

    const fn write_con(&mut self, value: u32) -> ShannonAction {
        let prev = self.con;
        self.con = value;

        let powering_on = (value & (CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN))
            == (CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        let was_powered = (prev & (CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN))
            == (CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);

        if powering_on && !was_powered {
            // Power-on transition.
            self.tx_len = 0;
            self.rx_len = 0;
            self.rx_pos = 0;
            self.stat &= !(STAT_RX_AVAIL | STAT_ATR_DONE);
            self.state = ShannonSimState::WaitAtr;
            return ShannonAction::EmitPowerOn;
        }

        if !powering_on && was_powered {
            // Power-off transition.
            self.tx_len = 0;
            self.rx_len = 0;
            self.rx_pos = 0;
            self.stat &= !(STAT_RX_AVAIL | STAT_ATR_DONE);
            self.state = ShannonSimState::Idle;
            return ShannonAction::EmitPowerOff;
        }

        ShannonAction::None
    }

    fn write_cmd(&mut self, value: u32) -> ShannonAction {
        match value {
            CMD_SEND_APDU => {
                if self.state != ShannonSimState::Ready {
                    return ShannonAction::None;
                }
                if self.tx_len == 0 {
                    return ShannonAction::None;
                }
                let len = self.tx_len;
                self.tx_len = 0;
                self.stat &= !STAT_RX_AVAIL;
                self.state = ShannonSimState::WaitResponse;
                ShannonAction::EmitApdu { len }
            }
            CMD_WARM_RESET => {
                if self.state == ShannonSimState::Idle {
                    return ShannonAction::None;
                }
                self.tx_len = 0;
                self.rx_len = 0;
                self.rx_pos = 0;
                self.stat &= !(STAT_RX_AVAIL | STAT_ATR_DONE);
                self.state = ShannonSimState::WaitAtr;
                ShannonAction::EmitWarmReset
            }
            _ => ShannonAction::None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_transport_virtio::MessageType;

    // -- Initial state --

    #[test]
    fn new_starts_idle() {
        let sim = ShannonSim::new();
        assert_eq!(sim.state(), ShannonSimState::Idle);
    }

    #[test]
    fn initial_stat_has_tx_ready_and_card_det() {
        let mut sim = ShannonSim::new();
        let stat = sim.read_reg(REG_SIM_STAT);
        assert_ne!(stat & STAT_TX_READY, 0);
        assert_ne!(stat & STAT_CARD_DET, 0);
        assert_eq!(stat & STAT_RX_AVAIL, 0);
        assert_eq!(stat & STAT_ATR_DONE, 0);
    }

    // -- Power on/off transitions --

    #[test]
    fn power_on_transitions_to_wait_atr() {
        let mut sim = ShannonSim::new();
        let action = sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        assert_eq!(action, ShannonAction::EmitPowerOn);
        assert_eq!(sim.state(), ShannonSimState::WaitAtr);
    }

    #[test]
    fn power_off_transitions_to_idle() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        let action = sim.write_reg(REG_SIM_CON, 0);
        assert_eq!(action, ShannonAction::EmitPowerOff);
        assert_eq!(sim.state(), ShannonSimState::Idle);
    }

    #[test]
    fn partial_con_does_not_power_on() {
        let mut sim = ShannonSim::new();
        // Only SIM_EN + VCC_EN, missing CLOCK_EN.
        let action = sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN);
        assert_eq!(action, ShannonAction::None);
        assert_eq!(sim.state(), ShannonSimState::Idle);
    }

    #[test]
    fn redundant_power_on_is_no_op() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        // Write same value again.
        let action = sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        assert_eq!(action, ShannonAction::None);
    }

    // -- ATR delivery --

    #[test]
    fn deliver_atr_transitions_to_ready() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        assert_eq!(sim.state(), ShannonSimState::WaitAtr);

        let atr = [0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7];
        let ok = sim.deliver_response(MessageType::PowerOn, &atr);
        assert!(ok);
        assert_eq!(sim.state(), ShannonSimState::Ready);
        assert_eq!(sim.rx_data(), &atr);
    }

    #[test]
    fn deliver_atr_sets_stat_flags() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);

        let stat = sim.read_reg(REG_SIM_STAT);
        assert_ne!(stat & STAT_RX_AVAIL, 0);
        assert_ne!(stat & STAT_ATR_DONE, 0);
    }

    #[test]
    fn deliver_response_wrong_state_rejected() {
        let mut sim = ShannonSim::new();
        // Idle state -- can't deliver ATR.
        let ok = sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);
        assert!(!ok);
    }

    #[test]
    fn deliver_apdu_in_wait_atr_rejected() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        // Trying to deliver APDU response when expecting ATR.
        let ok = sim.deliver_response(MessageType::Apdu, &[0x90, 0x00]);
        assert!(!ok);
    }

    // -- RX register read (byte-by-byte) --

    #[test]
    fn read_rx_returns_bytes_sequentially() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x9F, 0x96]);

        assert_eq!(sim.read_reg(REG_SIM_RX), 0x3B);
        assert_eq!(sim.read_reg(REG_SIM_RX), 0x9F);
        assert_eq!(sim.read_reg(REG_SIM_RX), 0x96);
        // Exhausted.
        assert_eq!(sim.read_reg(REG_SIM_RX), 0);
    }

    #[test]
    fn rx_avail_clears_when_all_read() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);

        // Still available.
        assert_ne!(sim.read_reg(REG_SIM_STAT) & STAT_RX_AVAIL, 0);
        sim.read_reg(REG_SIM_RX); // 0x3B
        assert_ne!(sim.read_reg(REG_SIM_STAT) & STAT_RX_AVAIL, 0);
        sim.read_reg(REG_SIM_RX); // 0x00
                                  // Now cleared.
        assert_eq!(sim.read_reg(REG_SIM_STAT) & STAT_RX_AVAIL, 0);
    }

    // -- TX buffer + APDU send --

    #[test]
    fn tx_writes_accumulate() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);

        // Write a 4-byte APDU header.
        sim.write_reg(REG_SIM_TX, 0x00);
        sim.write_reg(REG_SIM_TX, 0xA4);
        sim.write_reg(REG_SIM_TX, 0x00);
        sim.write_reg(REG_SIM_TX, 0x04);

        let tx = sim.pending_tx().unwrap();
        assert_eq!(tx, &[0x00, 0xA4, 0x00, 0x04]);
    }

    #[test]
    fn cmd_send_apdu_emits_action() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);

        // Write APDU command.
        for &b in &[0x00u8, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00] {
            sim.write_reg(REG_SIM_TX, u32::from(b));
        }

        let action = sim.write_reg(REG_SIM_CMD, CMD_SEND_APDU);
        assert_eq!(action, ShannonAction::EmitApdu { len: 7 });
        assert_eq!(sim.state(), ShannonSimState::WaitResponse);
    }

    #[test]
    fn cmd_send_apdu_in_idle_is_no_op() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_TX, 0x00);
        let action = sim.write_reg(REG_SIM_CMD, CMD_SEND_APDU);
        assert_eq!(action, ShannonAction::None);
        assert_eq!(sim.state(), ShannonSimState::Idle);
    }

    #[test]
    fn cmd_send_empty_tx_is_no_op() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);

        // No TX data written.
        let action = sim.write_reg(REG_SIM_CMD, CMD_SEND_APDU);
        assert_eq!(action, ShannonAction::None);
        assert_eq!(sim.state(), ShannonSimState::Ready);
    }

    // -- APDU exchange round-trip --

    #[test]
    fn full_apdu_round_trip() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);
        // Consume ATR.
        sim.read_reg(REG_SIM_RX);
        sim.read_reg(REG_SIM_RX);

        // Write SELECT MF command.
        for &b in &[0x00u8, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00] {
            sim.write_reg(REG_SIM_TX, u32::from(b));
        }
        let action = sim.write_reg(REG_SIM_CMD, CMD_SEND_APDU);
        assert_eq!(action, ShannonAction::EmitApdu { len: 7 });

        // Deliver APDU response.
        let ok = sim.deliver_response(MessageType::Apdu, &[0x90, 0x00]);
        assert!(ok);
        assert_eq!(sim.state(), ShannonSimState::Ready);

        // Read response.
        assert_eq!(sim.read_reg(REG_SIM_RX), 0x90);
        assert_eq!(sim.read_reg(REG_SIM_RX), 0x00);
    }

    // -- Warm reset --

    #[test]
    fn warm_reset_transitions_to_wait_atr() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);
        assert_eq!(sim.state(), ShannonSimState::Ready);

        let action = sim.write_reg(REG_SIM_CMD, CMD_WARM_RESET);
        assert_eq!(action, ShannonAction::EmitWarmReset);
        assert_eq!(sim.state(), ShannonSimState::WaitAtr);
    }

    #[test]
    fn warm_reset_clears_buffers() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);

        // Write some TX data.
        sim.write_reg(REG_SIM_TX, 0x00);
        sim.write_reg(REG_SIM_TX, 0xA4);

        sim.write_reg(REG_SIM_CMD, CMD_WARM_RESET);
        assert!(sim.pending_tx().is_none());
        assert!(sim.rx_data().is_empty());
    }

    #[test]
    fn warm_reset_from_idle_is_no_op() {
        let mut sim = ShannonSim::new();
        let action = sim.write_reg(REG_SIM_CMD, CMD_WARM_RESET);
        assert_eq!(action, ShannonAction::None);
        assert_eq!(sim.state(), ShannonSimState::Idle);
    }

    #[test]
    fn deliver_warm_reset_atr() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);
        sim.write_reg(REG_SIM_CMD, CMD_WARM_RESET);

        let atr = [0x3B, 0x9F];
        let ok = sim.deliver_response(MessageType::WarmReset, &atr);
        assert!(ok);
        assert_eq!(sim.state(), ShannonSimState::Ready);
        assert_eq!(sim.rx_data(), &atr);
    }

    // -- Interrupt registers --

    #[test]
    fn int_enable_read_write() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_INT_EN, 0x0F);
        assert_eq!(sim.read_reg(REG_SIM_INT_EN), 0x0F);
    }

    #[test]
    fn int_status_write_one_to_clear() {
        let mut sim = ShannonSim::new();
        // Manually set int_st for testing (via internal state).
        sim.int_st = 0x07;
        assert_eq!(sim.read_reg(REG_SIM_INT_ST), 0x07);
        sim.write_reg(REG_SIM_INT_ST, 0x02);
        assert_eq!(sim.read_reg(REG_SIM_INT_ST), 0x05);
    }

    // -- Baud register --

    #[test]
    fn baud_read_write() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_BAUD, 372);
        assert_eq!(sim.read_reg(REG_SIM_BAUD), 372);
    }

    // -- Unknown register --

    #[test]
    fn unknown_register_read_returns_zero() {
        let mut sim = ShannonSim::new();
        assert_eq!(sim.read_reg(0xFF), 0);
    }

    #[test]
    fn unknown_register_write_is_no_op() {
        let mut sim = ShannonSim::new();
        let action = sim.write_reg(0xFF, 0x1234);
        assert_eq!(action, ShannonAction::None);
    }

    // -- Unknown command --

    #[test]
    fn unknown_cmd_is_no_op() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);

        let action = sim.write_reg(REG_SIM_CMD, 0xFF);
        assert_eq!(action, ShannonAction::None);
    }

    // -- CON register readback --

    #[test]
    fn con_register_readback() {
        let mut sim = ShannonSim::new();
        let val = CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN | CON_SIM_RST;
        sim.write_reg(REG_SIM_CON, val);
        assert_eq!(sim.read_reg(REG_SIM_CON), val);
    }

    // -- Power off clears ATR_DONE --

    #[test]
    fn power_off_clears_atr_done() {
        let mut sim = ShannonSim::new();
        sim.write_reg(REG_SIM_CON, CON_SIM_EN | CON_VCC_EN | CON_CLOCK_EN);
        sim.deliver_response(MessageType::PowerOn, &[0x3B, 0x00]);
        assert_ne!(sim.read_reg(REG_SIM_STAT) & STAT_ATR_DONE, 0);

        sim.write_reg(REG_SIM_CON, 0); // power off
        assert_eq!(sim.read_reg(REG_SIM_STAT) & STAT_ATR_DONE, 0);
    }
}
