Feature: TCP Transport -- swICC PC/SC Protocol (simrs-transport-tcp)
  As a SIM card simulator
  I need a TCP client that speaks the swICC network protocol
  so that I can connect to a swICC PC/SC server and bridge APDUs

  Background:
    Given the swICC wire format:
      | Field        | Type    | Offset | Size  | Description              |
      | hdr.size     | u32    |   0    |   4   | Payload size (bytes)     |
      | cont_state   | u32    |   4    |   4   | Contact state bitmask    |
      | buf_len_exp  | u32    |   8    |   4   | Expected buffer length   |
      | ctrl         | u8     |  12    |   1   | Control / status byte    |
      | buf          | [u8]   |  13    | 0-258 | APDU data (max 256+2)   |
    And total max message size = 271 bytes
    And default server address = 127.0.0.1:37324

  # -- Wire protocol framing --

  Scenario: Encode message with APDU data
    Given cont_state = 0, ctrl = SUCCESS (0xF0), buf = [90 00]
    When I encode to wire format
    Then the first 4 bytes are the size: 11 (4+4+1+2) in big-endian
    And bytes 4-7 are cont_state = 0
    And bytes 8-11 are buf_len_exp = 0
    And byte 12 is ctrl = 0xF0
    And bytes 13-14 are [90 00]

  Scenario: Decode message with APDU command
    Given wire bytes: [00 00 00 10  00 00 00 00  00 00 00 07  00  00 A4 00 04 02 3F 00]
    When I decode from wire format
    Then hdr.size = 16, cont_state = 0, buf_len_exp = 7, ctrl = NONE
    And buf contains [00 A4 00 04 02 3F 00]

  Scenario: Decode message with empty payload (control-only)
    Given wire bytes: [00 00 00 09  00 00 00 00  00 00 00 00  01]
    When I decode from wire format
    Then ctrl = KEEPALIVE (1), buf is empty

  Scenario: Message too short rejects
    Given fewer than 4 header bytes
    When I attempt decode
    Then error is InvalidMessage

  Scenario: Payload size exceeds maximum rejects
    Given hdr.size > 267 (max data section)
    When I attempt decode
    Then error is InvalidMessage

  # -- Control message types --

  Scenario: NONE (0) indicates data/APDU message
    Given ctrl = 0
    Then the message carries APDU data in buf

  Scenario: KEEPALIVE (1) is a server ping
    Given ctrl = 1
    Then the card should respond with ctrl = SUCCESS (0xF0)

  Scenario: MOCK_RESET_COLD_PPS_Y (2) triggers cold reset
    Given ctrl = 2
    Then the card should reset and return ATR with ctrl = SUCCESS

  Scenario: MOCK_RESET_WARM_PPS_Y (3) triggers warm reset
    Given ctrl = 3
    Then the card should reset and return ATR with ctrl = SUCCESS

  Scenario: MOCK_RESET_COLD_PPS_N (4) triggers cold reset without PPS
    Given ctrl = 4
    Then the card should reset and return ATR with ctrl = SUCCESS

  Scenario: MOCK_RESET_WARM_PPS_N (5) triggers warm reset without PPS
    Given ctrl = 5
    Then the card should reset and return ATR with ctrl = SUCCESS

  Scenario: SUCCESS (0xF0) is a card response status
    Given ctrl = 0xF0 in a response message
    Then it indicates the card processed the request successfully

  Scenario: FAILURE (0x0F) is a card error status
    Given ctrl = 0x0F in a response message
    Then it indicates the card could not process the request

  # -- CardTransport mapping --

  Scenario: Data message maps to CardEvent::Apdu
    Given a received message with ctrl = NONE and buf = [A0 A4 00 00 02 3F 00]
    When mapped to CardEvent
    Then the result is CardEvent::Apdu(7)

  Scenario: Cold reset maps to CardEvent::PowerOn
    Given a received message with ctrl = MOCK_RESET_COLD_PPS_Y or _N
    When mapped to CardEvent
    Then the result is CardEvent::PowerOn

  Scenario: Warm reset maps to CardEvent::WarmReset
    Given a received message with ctrl = MOCK_RESET_WARM_PPS_Y or _N
    When mapped to CardEvent
    Then the result is CardEvent::WarmReset

  Scenario: Keepalive is handled internally
    Given a received message with ctrl = KEEPALIVE
    When the CardTransport processes it
    Then a SUCCESS response is sent automatically
    And recv continues waiting for the next real event

  # -- Round-trip scenarios --

  Scenario: APDU exchange round-trip
    Given a connected SwIccClient
    When the server sends a data message with [00 A4 00 04 02 3F 00]
    And the card processes it through Sim::process()
    Then the card sends back a response with ctrl=SUCCESS and buf=[data + SW]

  Scenario: Reset round-trip
    When the server sends ctrl = MOCK_RESET_COLD_PPS_Y
    Then the card responds with ctrl = SUCCESS, buf = ATR bytes
