# specs/gsm.feature
#
# BDD specification for GSM 11.11 SIM application layer.
#
# Standards:
#   - 3GPP TS 51.011 V4.15.0 (GSM 11.11)
#   - ETSI TS 102 221 V18.3.0 (UICC-terminal interface)

Feature: GSM 11.11 SIM Application Layer
  As a UICC simulator
  I need to handle GSM-class (CLA=0xA0) APDUs per GSM 11.11 / 3GPP TS 51.011
  including SELECT, READ BINARY, READ RECORD, GET RESPONSE, STATUS,
  RUN GSM ALGORITHM, and PIN operations

  Background:
    Given a GsmApp with:
      MF (3F00)
      +-- EF.ICCID (2FE2) transparent, 10 bytes [98 10 14 80 00 00 00 00 00 F0]
      +-- EF.DIR (2F00) linear-fixed, record_size=8, num_records=2
      +-- DF.TELECOM (7F10)
      |   +-- EF.ADN (6F3A) linear-fixed, record_size=14, num_records=3
      +-- DF.GSM (7F20)
          +-- EF.IMSI (6F07) transparent, 9 bytes
          +-- EF.Kc (6F20) transparent, 9 bytes
    And Ki = [01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF]
    And PIN1 is "1234", enabled, 3 retries
    And PUK1 is "12345678", 10 retries
    And a 256-byte response buffer

  # -- CLA routing --

  Scenario: CLA=0xA0 is accepted
    When I send APDU [A0 A4 00 00 02 3F 00]
    Then the status word is not 6E 00 (class supported)

  Scenario: CLA=0x00 is rejected
    When I send APDU [00 A4 00 00 02 3F 00]
    Then the status word is 6E 00 (class not supported)

  # -- SELECT (INS=0xA4) per GSM 11.11 clause 9.2.1 --

  Scenario: SELECT MF returns 9F with response length
    When I send SELECT [A0 A4 00 00 02 3F 00]
    Then SW1 is 0x9F (response data available)
    And SW2 is the response length (23 for DF/MF)

  Scenario: GET RESPONSE after SELECT MF returns 23-byte DF response
    Given I have selected MF via [A0 A4 00 00 02 3F 00]
    When I send GET RESPONSE [A0 C0 00 00 17]
    Then I get a 23-byte response
    And SW is 90 00
    And bytes 4-5 are 0x3F00 (file ID, big-endian)
    And byte 6 is 0x01 (file type = MF)

  Scenario: SELECT EF under MF returns 9F with EF response length
    When I send SELECT MF [A0 A4 00 00 02 3F 00]
    And I send GET RESPONSE to clear the queue
    And I send SELECT [A0 A4 00 00 02 2F E2]
    Then SW1 is 0x9F
    And SW2 is 15 (EF response length)

  Scenario: GET RESPONSE after SELECT EF returns 15-byte EF response
    Given I have selected EF.ICCID under MF
    When I send GET RESPONSE [A0 C0 00 00 0F]
    Then I get a 15-byte response
    And bytes 4-5 are 0x2FE2 (file ID)
    And byte 6 is 0x04 (file type = EF)
    And byte 13 is 0x00 (EF structure = transparent)

  Scenario: SELECT DF returns 23-byte DF response via GET RESPONSE
    Given I have selected DF.GSM (0x7F20)
    When I send GET RESPONSE
    Then byte 6 is 0x02 (file type = DF)
    And bytes 4-5 are 0x7F20

  Scenario: SELECT nonexistent FID returns 94 04
    When I send SELECT [A0 A4 00 00 02 FF FF]
    Then SW is 94 04 (file not found)

  # -- GET RESPONSE (INS=0xC0) --

  Scenario: GET RESPONSE with no pending data returns error
    When I send GET RESPONSE [A0 C0 00 00 17]
    Then SW indicates error (no data pending)

  Scenario: Non-GET-RESPONSE command clears pending data
    Given I have sent SELECT MF [A0 A4 00 00 02 3F 00]
    When I send STATUS [A0 F2 00 00 17] (not GET RESPONSE)
    And then I send GET RESPONSE [A0 C0 00 00 17]
    Then GET RESPONSE returns error (queue was cleared)

  # -- READ BINARY (INS=0xB0) per GSM 11.11 clause 9.2.3 --

  Scenario: READ BINARY from transparent EF
    Given EF.ICCID is selected
    When I send READ BINARY [A0 B0 00 00 0A]
    Then I get the 10-byte ICCID content
    And SW is 90 00

  Scenario: READ BINARY with offset
    Given EF.ICCID is selected
    When I send READ BINARY offset=2 length=3 [A0 B0 00 02 03]
    Then I get bytes [14 80 00]

  Scenario: READ BINARY past end of file
    Given EF.ICCID is selected
    When I send READ BINARY offset=8 length=5 [A0 B0 00 08 05]
    Then SW indicates offset/length error

  Scenario: READ BINARY with no EF selected
    When I send READ BINARY [A0 B0 00 00 01]
    Then SW indicates no EF selected error

  Scenario: READ BINARY on non-transparent EF
    Given EF.DIR (linear-fixed) is selected
    When I send READ BINARY [A0 B0 00 00 01]
    Then SW indicates file type mismatch error

  # -- READ RECORD (INS=0xB2) per GSM 11.11 clause 9.2.5 --

  Scenario: READ RECORD from linear-fixed EF
    Given EF.ADN is selected under DF.TELECOM
    When I send READ RECORD record=1 [A0 B2 01 04 0E]
    Then I get the 14-byte first record
    And SW is 90 00

  Scenario: READ RECORD record 2
    Given EF.ADN is selected under DF.TELECOM
    When I send READ RECORD record=2 [A0 B2 02 04 0E]
    Then I get the second 14-byte record

  Scenario: READ RECORD with invalid record number 0
    Given EF.ADN is selected under DF.TELECOM
    When I send READ RECORD record=0 [A0 B2 00 04 0E]
    Then SW indicates record out of range

  Scenario: READ RECORD beyond last record
    Given EF.ADN (3 records) is selected
    When I send READ RECORD record=4 [A0 B2 04 04 0E]
    Then SW indicates record out of range

  Scenario: READ RECORD on transparent EF
    Given EF.ICCID (transparent) is selected
    When I send READ RECORD record=1 [A0 B2 01 04 0A]
    Then SW indicates file type mismatch

  # -- STATUS (INS=0xF2) per GSM 11.11 clause 9.2.2 --

  Scenario: STATUS returns current DF info
    When I send STATUS [A0 F2 00 00 17]
    Then I get the 23-byte MF status response
    And bytes 4-5 are 0x3F00
    And SW is 90 00

  Scenario: STATUS after navigating to DF.GSM
    Given I have navigated to DF.GSM
    When I send STATUS [A0 F2 00 00 17]
    Then bytes 4-5 in the response are 0x7F20

  # -- RUN GSM ALGORITHM (INS=0x88) per GSM 11.11 clause 9.2.16 --

  Scenario: RUN GSM ALGORITHM returns SRES + Kc
    When I send RUN GSM ALGO [A0 88 00 00 10] with 16-byte RAND
    Then SW1 is 0x9F and SW2 is 0x0C (12 bytes available)
    And GET RESPONSE returns 12 bytes: 4-byte SRES + 8-byte Kc
    And the values match COMP128(Ki, RAND)

  Scenario: RUN GSM ALGORITHM with wrong data length
    When I send RUN GSM ALGO with 8-byte data (not 16)
    Then SW indicates wrong length

  # -- VERIFY PIN (INS=0x20) --

  Scenario: VERIFY correct PIN
    When I send VERIFY PIN1 [A0 20 00 01 08 31 32 33 34 FF FF FF FF]
    Then SW is 90 00

  Scenario: VERIFY wrong PIN decrements counter
    When I send VERIFY PIN1 with wrong value [A0 20 00 01 08 39 39 39 39 FF FF FF FF]
    Then SW is 63 C2 (2 retries remaining)

  Scenario: VERIFY on blocked PIN returns 69 83
    Given PIN1 is blocked (retries exhausted)
    When I send VERIFY PIN1 with correct value
    Then SW is 69 83 (authentication method blocked)

  # -- UNBLOCK PIN (INS=0x2C) --

  Scenario: UNBLOCK with correct PUK sets new PIN
    Given PIN1 is blocked
    When I send UNBLOCK [A0 2C 00 01 10] with PUK [31..38] + new PIN [35 36 37 38 FF FF FF FF]
    Then SW is 90 00
    And PIN1 is unblocked with 3 retries
    And the new PIN "5678" verifies successfully

  # -- INS not supported --

  Scenario: Unknown instruction returns 6D 00
    When I send APDU [A0 FF 00 00]
    Then SW is 6D 00 (instruction not supported)

  # -- Navigation sequences --

  Scenario: Navigate MF -> DF -> EF -> read -> MF round-trip
    When I send SELECT MF [A0 A4 00 00 02 3F 00]
    And I send GET RESPONSE to consume it
    And I send SELECT DF.GSM [A0 A4 00 00 02 7F 20]
    And I send GET RESPONSE to consume it
    And I send SELECT EF.IMSI [A0 A4 00 00 02 6F 07]
    And I send GET RESPONSE to consume it
    And I send READ BINARY [A0 B0 00 00 09]
    Then I get the 9-byte IMSI data
    And I send SELECT MF [A0 A4 00 00 02 3F 00]
    And STATUS returns MF info
