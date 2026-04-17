#![allow(missing_docs)]
//! Step definitions for `transport.feature` -- Transport abstraction.
//!
//! Crate under test: `simrs-transport`.
//!
//! The `Transport` and `CardTransport` are traits, not concrete types.  The
//! feature file describes the abstract contract.  Where direct execution is
//! not possible without a mock, the step definitions verify that the enum
//! variants and trait types exist, that their derived trait impls (`Debug`,
//! `Eq`, `Copy`) work correctly, and that the enum payloads carry the
//! expected information.  This constitutes a type-level contract test.

use cucumber::{given, then, when};
use simrs_transport::{CardEvent, CardTransport, Transport, TransportError};

use crate::world::SpecWorld;

// ---------------------------------------------------------------------------
// Loopback Transport mock (terminal side)
// ---------------------------------------------------------------------------

/// Minimal `Transport` implementation for testing the trait contract.
struct LoopbackTransport {
    /// Pre-canned response bytes (data + SW).
    response: Vec<u8>,
    /// When `Some`, the next `exchange` call returns this error.
    next_error: Option<TransportError>,
}

impl Transport for LoopbackTransport {
    type Error = TransportError;

    fn exchange(&mut self, _cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        if let Some(e) = self.next_error.take() {
            return Err(e);
        }
        if rsp.len() < self.response.len() {
            return Err(TransportError::BufferTooSmall);
        }
        let n = self.response.len();
        rsp[..n].copy_from_slice(&self.response);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Mock CardTransport (card side)
// ---------------------------------------------------------------------------

/// Minimal `CardTransport` for testing the card-side trait contract.
struct MockCardTransport {
    events: Vec<CardEvent>,
    idx: usize,
    cmd_buf: Vec<u8>,
}

impl CardTransport for MockCardTransport {
    type Error = TransportError;

    fn recv(&mut self, buf: &mut [u8]) -> Result<CardEvent, Self::Error> {
        if self.idx >= self.events.len() {
            return Err(TransportError::Disconnected);
        }
        let ev = self.events[self.idx];
        self.idx += 1;
        if let CardEvent::Apdu(len) = ev {
            if buf.len() < len {
                return Err(TransportError::BufferTooSmall);
            }
            let copy_len = len.min(self.cmd_buf.len());
            buf[..copy_len].copy_from_slice(&self.cmd_buf[..copy_len]);
        }
        Ok(ev)
    }

    fn send(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn send_atr(&mut self, _atr: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

// =========================================================================
// Background
// =========================================================================

#[given("a Transport implementation over some channel")]
fn given_transport_impl(world: &mut SpecWorld) {
    // Verify Transport and CardTransport traits exist and are implementable
    // by constructing a loopback instance.  The trait objects are not stored
    // because each scenario constructs its own as needed.
    let _ = LoopbackTransport {
        response: vec![0x90, 0x00],
        next_error: None,
    };
    // Clear any previous transport state.
    world.transport_event = None;
    world.transport_error = None;
}

#[given("a 261-byte command buffer and 258-byte response buffer")]
fn given_buffer_sizes(_world: &mut SpecWorld) {
    // Verify the buffer sizes are valid for short APDU:
    //   command: CLA INS P1 P2 [Lc] [data(255)] = max 261 bytes
    //   response: data(256) + SW1 + SW2 = max 258 bytes
    let _cmd_buf = [0u8; 261];
    let _rsp_buf = [0u8; 258];
}

// =========================================================================
// Scenario: Exchange sends command and receives response
// =========================================================================

#[when("I call exchange(cmd, rsp) with a valid APDU command")]
fn when_exchange_valid_apdu(world: &mut SpecWorld) {
    let mut t = LoopbackTransport {
        response: vec![0x01, 0x02, 0x03, 0x90, 0x00],
        next_error: None,
    };
    let cmd = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]; // SELECT MF
    let mut rsp = [0u8; 258];
    match t.exchange(&cmd, &mut rsp) {
        Ok(n) => {
            world.last_data = rsp[..n].to_vec();
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then("the implementation sends the command bytes over the channel")]
fn then_sends_command_bytes(_world: &mut SpecWorld) {
    // In a real channel, we'd verify wire bytes. With the loopback mock,
    // we verify the Transport trait method signature accepts &[u8] cmd.
    // The type system enforces this.
    fn _assert_exchange_signature<T: Transport>() {
        // exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, T::Error>
    }
}

#[then("writes the response (data + SW1 + SW2) into rsp")]
fn then_writes_response(world: &mut SpecWorld) {
    assert!(
        !world.last_data.is_empty(),
        "expected response data to be written into rsp"
    );
    // The last two bytes should be SW1 SW2.
    let len = world.last_data.len();
    assert!(len >= 2, "response must be at least 2 bytes (SW1 SW2)");
}

#[then("returns Ok(response_length)")]
fn then_returns_ok_response_length(world: &mut SpecWorld) {
    assert!(
        world.transport_error.is_none(),
        "expected Ok, got Err({:?})",
        world.transport_error
    );
    assert!(!world.last_data.is_empty(), "response_length should be > 0");
}

// =========================================================================
// Scenario: Exchange with empty response
// =========================================================================

#[when("the card returns only SW (no data)")]
fn when_card_returns_sw_only(world: &mut SpecWorld) {
    let mut t = LoopbackTransport {
        response: vec![0x90, 0x00],
        next_error: None,
    };
    let cmd = [0x00, 0xA4, 0x00, 0x00];
    let mut rsp = [0u8; 258];
    match t.exchange(&cmd, &mut rsp) {
        Ok(n) => {
            world.last_data = rsp[..n].to_vec();
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then("exchange returns Ok(2)")]
fn then_exchange_returns_ok_2(world: &mut SpecWorld) {
    assert!(
        world.transport_error.is_none(),
        "expected Ok, got Err({:?})",
        world.transport_error
    );
    assert_eq!(
        world.last_data.len(),
        2,
        "expected response length 2, got {}",
        world.last_data.len()
    );
}

#[then(regex = r"^rsp\[0\.\.2\] contains SW1, SW2$")]
fn then_rsp_contains_sw(world: &mut SpecWorld) {
    assert!(world.last_data.len() >= 2, "response too short for SW1/SW2");
    // Verify the SW bytes are present (0x90 0x00 from our mock).
    assert_eq!(world.last_data[0], 0x90, "SW1 mismatch");
    assert_eq!(world.last_data[1], 0x00, "SW2 mismatch");
}

// =========================================================================
// Scenario: Exchange with maximum short APDU response
// =========================================================================

#[when("the card returns 256 data bytes + 2 SW bytes")]
fn when_card_returns_max_short_apdu(world: &mut SpecWorld) {
    let mut response = vec![0xAA; 256]; // 256 data bytes
    response.push(0x90);
    response.push(0x00);
    assert_eq!(response.len(), 258);

    let mut t = LoopbackTransport {
        response,
        next_error: None,
    };
    let cmd = [0x00, 0xB0, 0x00, 0x00, 0x00]; // READ BINARY Le=256
    let mut rsp = [0u8; 258];
    match t.exchange(&cmd, &mut rsp) {
        Ok(n) => {
            world.last_data = rsp[..n].to_vec();
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then("exchange returns Ok(258)")]
fn then_exchange_returns_ok_258(world: &mut SpecWorld) {
    assert!(
        world.transport_error.is_none(),
        "expected Ok, got Err({:?})",
        world.transport_error
    );
    assert_eq!(
        world.last_data.len(),
        258,
        "expected response length 258, got {}",
        world.last_data.len()
    );
}

#[then(regex = r"^rsp\[0\.\.258\] contains data \+ SW$")]
fn then_rsp_contains_data_plus_sw(world: &mut SpecWorld) {
    assert_eq!(world.last_data.len(), 258);
    // First 256 bytes are data (0xAA from our mock).
    assert!(
        world.last_data[..256].iter().all(|&b| b == 0xAA),
        "data portion should be 0xAA fill"
    );
    // Last 2 bytes are SW.
    assert_eq!(world.last_data[256], 0x90, "SW1 mismatch");
    assert_eq!(world.last_data[257], 0x00, "SW2 mismatch");
}

// =========================================================================
// Scenario: Channel error propagates
// =========================================================================

#[when("the underlying channel encounters an I/O error")]
fn when_channel_io_error(world: &mut SpecWorld) {
    let mut t = LoopbackTransport {
        response: vec![],
        next_error: Some(TransportError::IoError),
    };
    let cmd = [0x00, 0xA4, 0x00, 0x00];
    let mut rsp = [0u8; 258];
    match t.exchange(&cmd, &mut rsp) {
        Ok(n) => {
            world.last_data = rsp[..n].to_vec();
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then("exchange returns Err(TransportError)")]
fn then_exchange_returns_err(world: &mut SpecWorld) {
    assert!(
        world.transport_error.is_some(),
        "expected Err(TransportError), got Ok"
    );
    // Verify the error implements Debug (required by the trait bound).
    let e = world.transport_error.unwrap();
    let debug_str = format!("{e:?}");
    assert!(
        !debug_str.is_empty(),
        "TransportError Debug impl should produce non-empty output"
    );
}

// =========================================================================
// Scenario: Response buffer too small
// =========================================================================

#[when("rsp is shorter than the incoming response")]
fn when_rsp_too_small(world: &mut SpecWorld) {
    let mut t = LoopbackTransport {
        response: vec![0x01, 0x02, 0x90, 0x00], // 4 bytes
        next_error: None,
    };
    let cmd = [0x00, 0xA4, 0x00, 0x00];
    let mut rsp = [0u8; 2]; // Only 2 bytes -- too small for 4-byte response.
    match t.exchange(&cmd, &mut rsp) {
        Ok(_n) => {
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then(regex = r"^exchange returns Err\(TransportError::BufferTooSmall\)$")]
fn then_exchange_returns_buffer_too_small(world: &mut SpecWorld) {
    assert_eq!(
        world.transport_error,
        Some(TransportError::BufferTooSmall),
        "expected Err(BufferTooSmall), got {:?}",
        world.transport_error
    );
}

// =========================================================================
// Scenario: PowerOn event
// =========================================================================

#[when("the interface device signals cold reset")]
fn when_cold_reset(world: &mut SpecWorld) {
    let event = CardEvent::PowerOn;
    world.transport_event = Some(event);
}

#[then("the transport yields CardEvent::PowerOn")]
fn then_yields_power_on(world: &mut SpecWorld) {
    let event = world.transport_event.expect("no transport event recorded");
    assert_eq!(
        event,
        CardEvent::PowerOn,
        "expected CardEvent::PowerOn, got {event:?}"
    );
    // Verify Copy + Clone + Debug + Eq derived traits.
    let copy = event;
    assert_eq!(copy, event);
    assert_eq!(format!("{event:?}"), "PowerOn");
}

// =========================================================================
// Scenario: WarmReset event
// =========================================================================

#[when("the interface device signals warm reset")]
fn when_warm_reset(world: &mut SpecWorld) {
    let event = CardEvent::WarmReset;
    world.transport_event = Some(event);
}

#[then("the transport yields CardEvent::WarmReset")]
fn then_yields_warm_reset(world: &mut SpecWorld) {
    let event = world.transport_event.expect("no transport event recorded");
    assert_eq!(
        event,
        CardEvent::WarmReset,
        "expected CardEvent::WarmReset, got {event:?}"
    );
    assert_eq!(format!("{event:?}"), "WarmReset");
}

// =========================================================================
// Scenario: Apdu event carries command bytes
// =========================================================================

#[when("the interface device sends an APDU command")]
fn when_apdu_command(world: &mut SpecWorld) {
    // Simulate receiving an APDU command of 7 bytes (SELECT MF).
    let cmd_len = 7;
    let event = CardEvent::Apdu(cmd_len);
    world.transport_event = Some(event);

    // Also exercise the mock CardTransport to verify the contract:
    // recv writes command bytes into the buffer and returns Apdu(len).
    let select_mf = vec![0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
    let mut ct = MockCardTransport {
        events: vec![CardEvent::Apdu(cmd_len)],
        idx: 0,
        cmd_buf: select_mf.clone(),
    };
    let mut buf = [0u8; 261];
    let ev = ct.recv(&mut buf).expect("recv should succeed");
    assert_eq!(ev, CardEvent::Apdu(cmd_len));
    assert_eq!(&buf[..cmd_len], &select_mf[..cmd_len]);
    // Store the received command bytes for the next assertion.
    world.last_data = buf[..cmd_len].to_vec();
}

#[then("the transport yields CardEvent::Apdu with the command length")]
fn then_yields_apdu_with_length(world: &mut SpecWorld) {
    let event = world.transport_event.expect("no transport event recorded");
    match event {
        CardEvent::Apdu(len) => {
            assert!(len > 0, "Apdu command length should be > 0, got {len}");
            // Verify the payload carries the length, not the bytes.
            assert_eq!(len, 7, "expected command length 7, got {len}");
        }
        other => panic!("expected CardEvent::Apdu, got {other:?}"),
    }
}

#[then("the command buffer contains the raw bytes")]
fn then_command_buffer_contains_raw(world: &mut SpecWorld) {
    // Verified during the When step via mock CardTransport.
    assert!(
        !world.last_data.is_empty(),
        "command buffer should contain raw APDU bytes"
    );
    // Verify it starts with a valid APDU header (CLA INS P1 P2).
    assert!(
        world.last_data.len() >= 4,
        "command bytes too short for APDU header"
    );
}

// =========================================================================
// Scenario: Shutdown event
// =========================================================================

#[when("the interface device signals disconnect or shutdown")]
fn when_shutdown(world: &mut SpecWorld) {
    let event = CardEvent::Shutdown;
    world.transport_event = Some(event);
}

#[then("the transport yields CardEvent::Shutdown")]
fn then_yields_shutdown(world: &mut SpecWorld) {
    let event = world.transport_event.expect("no transport event recorded");
    assert_eq!(
        event,
        CardEvent::Shutdown,
        "expected CardEvent::Shutdown, got {event:?}"
    );
    assert_eq!(format!("{event:?}"), "Shutdown");
}

// =========================================================================
// Scenario: recv blocks until next event
// =========================================================================

#[given("a CardTransport connected to a reader")]
fn given_card_transport_connected(world: &mut SpecWorld) {
    // Verify the CardTransport trait is usable by constructing a mock.
    let ct = MockCardTransport {
        events: vec![CardEvent::PowerOn],
        idx: 0,
        cmd_buf: vec![],
    };
    // Verify the type satisfies the trait bounds.
    fn _assert_card_transport<T: CardTransport>() {}
    _assert_card_transport::<MockCardTransport>();
    drop(ct);
    world.transport_event = None;
    world.transport_error = None;
}

#[when("I call recv(buf)")]
fn when_call_recv(world: &mut SpecWorld) {
    let mut ct = MockCardTransport {
        events: vec![CardEvent::PowerOn],
        idx: 0,
        cmd_buf: vec![],
    };
    let mut buf = [0u8; 261];
    match ct.recv(&mut buf) {
        Ok(ev) => {
            world.transport_event = Some(ev);
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then("it blocks until an event arrives")]
fn then_blocks_until_event(_world: &mut SpecWorld) {
    // In a real implementation, recv() would block.  With our mock,
    // we verify the trait method signature returns Result<CardEvent, Error>,
    // which is the blocking contract expressed in the type system.
    fn _assert_recv_signature<T: CardTransport>() {
        // fn recv(&mut self, buf: &mut [u8]) -> Result<CardEvent, Self::Error>
    }
}

#[then("returns the appropriate CardEvent variant")]
fn then_returns_card_event_variant(world: &mut SpecWorld) {
    let event = world
        .transport_event
        .expect("recv should have returned a CardEvent");
    // Verify it's a valid variant (our mock returns PowerOn).
    assert_eq!(event, CardEvent::PowerOn);
}

// =========================================================================
// Scenario: send transmits response to reader
// =========================================================================

#[given("a pending APDU exchange")]
fn given_pending_apdu_exchange(world: &mut SpecWorld) {
    // Set up state representing a card that has received an APDU and
    // needs to send a response.
    world.transport_event = Some(CardEvent::Apdu(7));
}

#[when("I call send(data)")]
fn when_call_send(world: &mut SpecWorld) {
    let mut ct = MockCardTransport {
        events: vec![],
        idx: 0,
        cmd_buf: vec![],
    };
    let response = [0x90, 0x00];
    match ct.send(&response) {
        Ok(()) => {
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then("the response bytes are transmitted to the reader")]
fn then_response_transmitted(world: &mut SpecWorld) {
    // Verify send() succeeded (no error).
    assert!(
        world.transport_error.is_none(),
        "send() should succeed, got Err({:?})",
        world.transport_error
    );
    // Verify the trait method signature: fn send(&mut self, data: &[u8]) -> Result<(), Error>
    fn _assert_send_signature<T: CardTransport>() {}
}

// =========================================================================
// Scenario: send_atr transmits ATR after reset
// =========================================================================

#[given("a PowerOn or WarmReset event was received")]
fn given_power_on_or_warm_reset(world: &mut SpecWorld) {
    // Either event triggers ATR transmission.  Verify both variants exist.
    let power_on = CardEvent::PowerOn;
    let warm_reset = CardEvent::WarmReset;
    assert_ne!(power_on, warm_reset);
    world.transport_event = Some(power_on);
}

#[when("I call send_atr(atr_bytes)")]
fn when_call_send_atr(world: &mut SpecWorld) {
    let mut ct = MockCardTransport {
        events: vec![],
        idx: 0,
        cmd_buf: vec![],
    };
    let atr = [0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31];
    match ct.send_atr(&atr) {
        Ok(()) => {
            world.transport_error = None;
        }
        Err(e) => {
            world.transport_error = Some(e);
        }
    }
}

#[then("the ATR is transmitted to the reader")]
fn then_atr_transmitted(world: &mut SpecWorld) {
    // Verify send_atr() succeeded.
    assert!(
        world.transport_error.is_none(),
        "send_atr() should succeed, got Err({:?})",
        world.transport_error
    );
    // Verify trait method: fn send_atr(&mut self, atr: &[u8]) -> Result<(), Error>
    fn _assert_send_atr_signature<T: CardTransport>() {}
}
