# specs/usim.feature
#
# BDD specification for 3GPP USIM application layer.
#
# Standards:
#   - ETSI TS 102 221 V18.3.0 (UICC-terminal interface)
#   - 3GPP TS 31.102 V19.4.0 (USIM application)

Feature: 3GPP USIM Application Layer
  As a UICC simulator
  I need to handle interindustry and ETSI-class APDUs per ETSI TS 102 221
  and 3GPP TS 31.102 including SELECT (FCP), READ BINARY, READ RECORD,
  STATUS, AUTHENTICATE (Milenage), VERIFY PIN, UNBLOCK PIN,
  TERMINAL PROFILE, FETCH, TERMINAL RESPONSE, and ENVELOPE

  Background:
    Given a UsimApp with:
      """
      MF (3F00)
      +-- EF.ICCID (2FE2) transparent, 10 bytes
      +-- EF.DIR (2F00) linear-fixed, record_size=8, num_records=2
      +-- ADF.USIM (AID=A0000000871002)
          +-- EF.IMSI (6F07) transparent, 9 bytes
          +-- EF.UST (6F38) transparent, 4 bytes
      """
    And Milenage params: K, OPc, SQN, AMF per test set 1
    And PIN1 is "1234", enabled, 3 retries
    And PUK1 is "12345678", 10 retries
    And a 256-byte response buffer

  # -- CLA routing --

  Scenario: CLA=0x00 (interindustry) is accepted
    When I send APDU [00 A4 00 00 02 3F 00]
    Then the status word is not 6E 00 (class supported)

  Scenario: CLA=0xA0 (GSM proprietary) routes to GSM app in dual-app build
    When I send APDU [A0 A4 00 00 02 3F 00]
    Then the status word is not 6E 00 (dual-app build routes CLA=0xA0 to GSM)

  Scenario: CLA=0x80 (ETSI CAT) is accepted for TERMINAL PROFILE
    When I send APDU [80 10 00 00]
    Then the status word is not 6E 00

  # -- SELECT by FID (INS=0xA4, P1=0x00) with FCP response --

  Scenario: SELECT MF by FID returns FCP template
    When I send SELECT [00 A4 00 04 02 3F 00]
    Then SW1 is 0x61 (data available via GET RESPONSE)
    And SW2 is the FCP length

  Scenario: GET RESPONSE after SELECT MF returns FCP with tag 0x62
    Given I have selected MF via [00 A4 00 04 02 3F 00]
    When I send GET RESPONSE [00 C0 00 00] with Le=SW2
    Then the response starts with tag 0x62
    And the FCP contains tag 0x83 with value 3F 00 (file ID)
    And the FCP contains tag 0x82 (file descriptor)
    And the FCP contains tag 0x8A (life cycle status)
    And SW is 90 00

  Scenario: SELECT EF under MF returns FCP
    Given I have selected MF
    When I send SELECT [00 A4 00 04 02 2F E2]
    And GET RESPONSE retrieves the FCP
    Then the FCP contains tag 0x83 with value 2F E2
    And the FCP contains tag 0x82 with file descriptor byte for transparent EF
    And the FCP contains tag 0x80 (file size)

  # -- SELECT by AID (INS=0xA4, P1=0x04) --

  Scenario: SELECT ADF.USIM by AID
    When I send SELECT [00 A4 04 04 07 A0 00 00 00 87 10 02]
    Then SW1 is 0x61 (FCP available)
    And GET RESPONSE returns an FCP with tag 0x84 containing the AID

  Scenario: SELECT unknown AID returns 6A 82
    When I send SELECT [00 A4 04 04 07 FF FF FF FF FF FF FF]
    Then SW is 6A 82 (file not found)

  # -- FCP template structure per ETSI TS 102 221 clause 11.1.1.3 --

  Scenario: FCP for DF contains PIN status template (tag 0xC6)
    Given I have selected MF with FCP
    Then the FCP contains tag 0xC6 (PIN status template DO)
    And the FCP contains tag 0x8C (security attributes compact)

  Scenario: FCP for EF contains file size (tag 0x80)
    Given I have selected EF.ICCID with FCP
    Then the FCP contains tag 0x80 with a 2-byte file size

  Scenario: FCP file descriptor (tag 0x82) encodes structure
    Given I have selected EF.ICCID (transparent) with FCP
    Then the file descriptor byte has bits for transparent EF

  # -- GET RESPONSE (INS=0xC0) --

  Scenario: GET RESPONSE with no pending data returns error
    When I send GET RESPONSE [00 C0 00 00 10]
    Then SW indicates error (no data pending)

  Scenario: Non-GET-RESPONSE command clears pending data
    Given I have sent SELECT MF
    When I send STATUS [00 F2 00 00 00] (not GET RESPONSE)
    And then I send GET RESPONSE [00 C0 00 00 10]
    Then GET RESPONSE returns error (queue was cleared)

  # -- READ BINARY (INS=0xB0) per ETSI TS 102 221 clause 11.1.3 --

  Scenario: READ BINARY from transparent EF
    Given EF.ICCID is selected
    When I send READ BINARY [00 B0 00 00 0A]
    Then I get the 10-byte ICCID content
    And SW is 90 00

  Scenario: READ BINARY with offset
    Given EF.ICCID is selected
    When I send READ BINARY offset=2 length=3 [00 B0 00 02 03]
    Then I get 3 bytes from offset 2

  Scenario: READ BINARY past end of file
    Given EF.ICCID is selected
    When I send READ BINARY offset=8 length=5 [00 B0 00 08 05]
    Then SW indicates offset/length error

  Scenario: READ BINARY with no EF selected
    When I send READ BINARY [00 B0 00 00 01]
    Then SW indicates no EF selected error

  # -- READ RECORD (INS=0xB2) per ETSI TS 102 221 clause 11.1.5 --

  Scenario: READ RECORD from linear-fixed EF
    Given EF.DIR is selected
    When I send READ RECORD record=1 [00 B2 01 04 08]
    Then I get the 8-byte first record
    And SW is 90 00

  Scenario: READ RECORD beyond last record
    Given EF.DIR (2 records) is selected
    When I send READ RECORD record=3 [00 B2 03 04 08]
    Then SW indicates record out of range

  # -- STATUS (INS=0xF2) per ETSI TS 102 221 clause 11.1.2 --

  Scenario: STATUS returns current DF FCP
    When I send STATUS [00 F2 00 00 00]
    Then I get the MF FCP
    And the FCP contains tag 0x83 with value 3F 00
    And SW is 90 00

  Scenario: STATUS after selecting ADF.USIM
    Given I have selected ADF.USIM by AID
    When I send STATUS [00 F2 00 00 00]
    Then the FCP file ID matches the ADF

  # -- AUTHENTICATE (INS=0x88) per 3GPP TS 31.102 clause 7.1.2.1 --

  Scenario: AUTHENTICATE UMTS context with valid AUTN
    Given ADF.USIM is selected
    When I send AUTHENTICATE [00 88 00 81 22] with:
      """
      0x10 [RAND:16 bytes] 0x10 [AUTN:16 bytes]
      """
    Then SW1 is 0x61 (response available)
    And GET RESPONSE returns tag 0xDB with RES + CK + IK

  Scenario: AUTHENTICATE with MAC failure returns 98 62
    Given ADF.USIM is selected
    When I send AUTHENTICATE with tampered AUTN
    Then SW is 98 62 (authentication error, incorrect MAC)

  Scenario: AUTHENTICATE with SQN out of range returns DC tag with AUTS
    Given ADF.USIM is selected
    When I send AUTHENTICATE with out-of-range SQN
    Then SW1 is 0x61
    And GET RESPONSE returns tag 0xDC with 14-byte AUTS

  Scenario: AUTHENTICATE with wrong data length
    Given ADF.USIM is selected
    When I send AUTHENTICATE with 8-byte data (not 34)
    Then SW indicates wrong length

  # -- VERIFY PIN (INS=0x20) --

  Scenario: VERIFY correct PIN
    When I send VERIFY PIN1 [00 20 00 01 08 31 32 33 34 FF FF FF FF]
    Then SW is 90 00

  Scenario: VERIFY wrong PIN decrements counter
    When I send VERIFY PIN1 with wrong value
    Then SW is 63 C2 (2 retries remaining)

  Scenario: VERIFY on blocked PIN returns 69 83
    Given PIN1 is blocked (retries exhausted)
    When I send VERIFY PIN1 with correct value
    Then SW is 69 83 (authentication method blocked)

  # -- UNBLOCK PIN (INS=0x2C) --

  Scenario: UNBLOCK with correct PUK sets new PIN
    Given PIN1 is blocked
    When I send UNBLOCK with PUK + new PIN
    Then SW is 90 00
    And the new PIN verifies successfully

  # -- TERMINAL PROFILE (INS=0x10, CLA=0x80) --

  Scenario: TERMINAL PROFILE accepted
    When I send TERMINAL PROFILE [80 10 00 00 04 FF FF FF FF]
    Then SW is 90 00

  # -- FETCH (INS=0x12, CLA=0x80) --

  Scenario: FETCH retrieves queued proactive command
    Given a proactive DISPLAY TEXT command is queued
    When I send FETCH [80 12 00 00] with Le=pending_len
    Then I get the BER-TLV encoded proactive command
    And the command starts with tag 0xD0
    And SW is 90 00
    And the proactive queue is now empty

  Scenario: FETCH with no pending command
    When I send FETCH [80 12 00 00 00]
    Then SW indicates no proactive data pending

  # -- TERMINAL RESPONSE (INS=0x14, CLA=0x80) --

  Scenario: TERMINAL RESPONSE accepted
    Given a proactive command was fetched
    When I send TERMINAL RESPONSE [80 14 00 00] with response data
    Then SW is 90 00

  # -- ENVELOPE (INS=0xC2, CLA=0x80) --

  Scenario: ENVELOPE accepted
    When I send ENVELOPE [80 C2 00 00] with BER-TLV data
    Then SW is 90 00

  # -- Proactive SW override (91 XX) --

  Scenario: Normal command overridden to 91 XX when proactive pending
    Given a proactive command is queued (e.g. DISPLAY TEXT)
    When I send any command that returns 90 00 (e.g. VERIFY correct PIN)
    Then SW is 91 XX where XX is the proactive command length

  Scenario: 91 XX override only applies to 90 00 status
    Given a proactive command is queued
    When I send a command that returns an error (e.g. SELECT nonexistent)
    Then SW is the error code (not overridden to 91 XX)

  # -- INS not supported --

  Scenario: Unknown instruction returns 6D 00
    When I send APDU [00 FF 00 00]
    Then SW is 6D 00 (instruction not supported)

  # -- Navigation sequences --

  Scenario: MF -> ADF.USIM -> EF -> read -> MF round-trip
    When I select MF by FID
    And I select ADF.USIM by AID
    And I select EF.IMSI by FID
    And I READ BINARY to get IMSI data
    Then I get the IMSI content
    When I select MF
    Then STATUS returns MF FCP
