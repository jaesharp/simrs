# specs/sim.feature
#
# BDD specification for SIM/USIM orchestrator.
#
# Standards:
#   - ETSI TS 102 221 V18.3.0 (UICC-terminal interface)

Feature: SIM/USIM Orchestrator (simrs-sim)
  As a SIM card simulator
  I need a single entry-point state machine that accepts power/reset/APDU events
  and routes them to the correct application layer (GSM or USIM) based on CLA byte

  Background:
    Given a Sim with:
      MF (3F00)
      +-- EF.ICCID (2FE2) transparent, 10 bytes
      +-- ADF.USIM (AID=A0000000871002)
          +-- EF.IMSI (6F07) transparent, 9 bytes
    And ATR = [3B 9F 96 80 ...] (standard UICC ATR)
    And feature "gsm" enabled with Ki = [00; 16]
    And feature "usim" enabled with Milenage K/OPc params
    And PIN1 = "1234", enabled, 3 retries
    And a 256-byte response buffer

  # -- Power / Reset lifecycle --

  Scenario: PowerOn returns ATR
    When I send SimEvent::PowerOn
    Then the response is SimResponse::Atr with the configured ATR bytes

  Scenario: Reset returns ATR
    Given the card is powered on
    When I send SimEvent::Reset
    Then the response is SimResponse::Atr with the configured ATR bytes

  Scenario: Reset clears PIN verified state
    Given the card is powered on
    And PIN1 has been verified
    When I send SimEvent::Reset
    And I send SimEvent::Apdu with a GSM READ BINARY
    Then PIN-dependent operations require re-verification

  Scenario: APDU before PowerOn returns Ignored
    When I send SimEvent::Apdu without prior PowerOn
    Then the response is SimResponse::Ignored

  Scenario: Multiple PowerOn is idempotent
    When I send SimEvent::PowerOn
    And I send SimEvent::PowerOn again
    Then the response is SimResponse::Atr (no error)

  # -- CLA-based routing --

  Scenario: CLA=0xA0 routes to GsmApp (feature "gsm")
    Given the card is powered on
    When I send SimEvent::Apdu with [A0 A4 00 00 02 3F 00]
    Then the response comes from GsmApp (SW1=0x9F for GSM SELECT)

  Scenario: CLA=0x00 routes to UsimApp (feature "usim")
    Given the card is powered on
    When I send SimEvent::Apdu with [00 A4 00 04 02 3F 00]
    Then the response comes from UsimApp (SW1=0x61 for USIM SELECT)

  Scenario: CLA=0x80 routes to UsimApp for ETSI CAT commands
    Given the card is powered on
    When I send SimEvent::Apdu with [80 10 00 00 04 FF FF FF FF]
    Then SW is 90 00 (TERMINAL PROFILE accepted by UsimApp)

  Scenario: Unsupported CLA returns 6E 00
    Given the card is powered on
    When I send SimEvent::Apdu with [F0 A4 00 00 02 3F 00]
    Then SW is 6E 00 (class not supported)

  # -- Malformed APDU handling --

  Scenario: APDU shorter than 4 bytes returns Ignored
    Given the card is powered on
    When I send SimEvent::Apdu with [00 A4 00]
    Then the response is SimResponse::Ignored

  Scenario: Empty APDU returns Ignored
    Given the card is powered on
    When I send SimEvent::Apdu with []
    Then the response is SimResponse::Ignored

  # -- Full round-trip through routing --

  Scenario: GSM SELECT MF -> GET RESPONSE round-trip
    Given the card is powered on
    When I send SimEvent::Apdu [A0 A4 00 00 02 3F 00]
    Then SW1 is 0x9F
    When I send SimEvent::Apdu [A0 C0 00 00] with Le=SW2
    Then I get the GSM 11.11 SELECT response
    And SW is 90 00

  Scenario: USIM SELECT MF -> GET RESPONSE round-trip
    Given the card is powered on
    When I send SimEvent::Apdu [00 A4 00 04 02 3F 00]
    Then SW1 is 0x61
    When I send SimEvent::Apdu [00 C0 00 00] with Le=SW2
    Then I get the ETSI FCP BER-TLV response
    And SW is 90 00

  Scenario: USIM AUTHENTICATE through Sim
    Given the card is powered on
    And ADF.USIM is selected (via USIM routing)
    When I send AUTHENTICATE with valid RAND+AUTN
    Then SW1 is 0x61 (response available)
    And GET RESPONSE returns Milenage output (tag 0xDB)

  # -- Proactive passthrough --

  Scenario: Proactive 91 XX passes through Sim layer
    Given the card is powered on
    And a proactive command is pending in UsimApp
    When I send a command that would return 90 00 via USIM routing
    Then the SimResponse contains SW 91 XX

  # -- Feature gating --

  Scenario: GSM-only build rejects USIM CLA
    Given only feature "gsm" is enabled
    And the card is powered on
    When I send SimEvent::Apdu with CLA=0x00
    Then SW is 6E 00 (class not supported)

  Scenario: USIM-only build rejects GSM CLA
    Given only feature "usim" is enabled
    And the card is powered on
    When I send SimEvent::Apdu with CLA=0xA0
    Then SW is 6E 00 (class not supported)

  # -- SimResponse structure --

  Scenario: Successful APDU response includes data and SW
    Given the card is powered on
    When I send a valid READ BINARY
    Then SimResponse::Apdu contains the data bytes and sw1+sw2

  Scenario: Error-only APDU response has empty data and error SW
    Given the card is powered on
    When I send an unknown INS [00 FF 00 00]
    Then SimResponse::Apdu has sw1=6D sw2=00 (INS not supported)
