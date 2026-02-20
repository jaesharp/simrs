Feature: Transport Trait (simrs-transport)
  As a SIM transport layer
  I need a trait abstraction that decouples the SIM from any specific channel
  so that TCP, shmem, VirtIO, and test harnesses all share one interface

  Background:
    Given a Transport implementation over some channel
    And a 261-byte command buffer and 258-byte response buffer

  # -- Trait contract --

  Scenario: Exchange sends command and receives response
    When I call exchange(cmd, rsp) with a valid APDU command
    Then the implementation sends the command bytes over the channel
    And writes the response (data + SW1 + SW2) into rsp
    And returns Ok(response_length)

  Scenario: Exchange with empty response
    When the card returns only SW (no data)
    Then exchange returns Ok(2)
    And rsp[0..2] contains SW1, SW2

  Scenario: Exchange with maximum short APDU response
    When the card returns 256 data bytes + 2 SW bytes
    Then exchange returns Ok(258)
    And rsp[0..258] contains data + SW

  Scenario: Channel error propagates
    When the underlying channel encounters an I/O error
    Then exchange returns Err(TransportError)

  Scenario: Response buffer too small
    When rsp is shorter than the incoming response
    Then exchange returns Err(TransportError::BufferTooSmall)

  # -- CardEvent enumeration --

  Scenario: PowerOn event
    When the interface device signals cold reset
    Then the transport yields CardEvent::PowerOn

  Scenario: WarmReset event
    When the interface device signals warm reset
    Then the transport yields CardEvent::WarmReset

  Scenario: Apdu event carries command bytes
    When the interface device sends an APDU command
    Then the transport yields CardEvent::Apdu with the command length
    And the command buffer contains the raw bytes

  Scenario: Shutdown event
    When the interface device signals disconnect or shutdown
    Then the transport yields CardEvent::Shutdown

  # -- CardTransport trait (card-side) --

  Scenario: recv blocks until next event
    Given a CardTransport connected to a reader
    When I call recv(buf)
    Then it blocks until an event arrives
    And returns the appropriate CardEvent variant

  Scenario: send transmits response to reader
    Given a pending APDU exchange
    When I call send(data)
    Then the response bytes are transmitted to the reader

  Scenario: send_atr transmits ATR after reset
    Given a PowerOn or WarmReset event was received
    When I call send_atr(atr_bytes)
    Then the ATR is transmitted to the reader
