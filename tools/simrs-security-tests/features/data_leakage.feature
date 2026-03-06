# features/data_leakage.feature
#
# Security regression: GET RESPONSE data leakage and response buffer hygiene.
#
# Standards:
#   ISO/IEC 7816-4:2020      clause 7.6  (GET RESPONSE command)
#   ETSI TS 102 221 V18.0.0  clause 11.1.2  (GET RESPONSE)
#   ETSI TS 102 221 V18.0.0  clause 11.1.1.3 (FCP template structure)
#   3GPP TS 31.102 V16.9.0   clause 11.2.1  (SELECT response for USIM)
#
# Vulnerability model:
#   The GET RESPONSE command (INS=0xC0) retrieves data that was queued by a
#   previous command whose SW1 was 0x61 (data available).  If the response
#   queue is not correctly cleared, a second GET RESPONSE, a GET RESPONSE
#   after a different command, or a GET RESPONSE after power-cycle could
#   return stale data from a prior successful operation, leaking sensitive
#   file content or authentication outputs to an attacker who can send
#   subsequent APDUs.
#
# Status words:
#   90 00  normal ending
#   61 XX  response data available (XX = byte count)
#   69 86  command not allowed (no data pending)
#   6F 00  unknown / technical problem
#
# FCP template (ETSI TS 102 221 clause 11.1.1.3):
#   Tag 0x62  FCP template
#   Tag 0x80  file size
#   Tag 0x82  file descriptor
#   Tag 0x83  file identifier
#   Tag 0x84  AID (for ADF)
#   Tag 0x8A  life cycle status
#   Tag 0x8C  security attributes compact
#   Tag 0xC6  PIN status template DO
#
# NOTE: the FCP must NOT contain raw key material, subscriber credentials
# (Ki, K, OPc), PIN values, or any data beyond the administrative metadata
# described in ETSI TS 102 221 clause 11.1.1.3.

Feature: GET RESPONSE Data Leakage Prevention
  As a SIM card simulator
  I must ensure that the GET RESPONSE command (INS=0xC0) only returns data
  that was explicitly queued by the immediately preceding command, that the
  queue is cleared after each retrieval, that power-cycle clears any pending
  state, and that FCP response data does not contain sensitive information
  beyond what ETSI TS 102 221 clause 11.1.1.3 permits.

  Background:
    Given the SIM is initialized with test credentials (Ki=0x11*16, K=0x22*16, OPc=0x33*16)
    And the SIM is powered on (SimEvent::PowerOn sent, ATR received)
    And the MF filesystem contains:
      """
      MF (3F00)
      +-- EF.ICCID (2FE2) transparent, 10 bytes [98 10 14 80 00 00 00 00 00 F0]
      +-- EF.DIR  (2F00) linear-fixed, record_size=32, num_records=1
      """

  # ---------------------------------------------------------------------------
  # GET RESPONSE without any prior command
  # Attack vector: attacker sends GET RESPONSE (INS=0xC0) cold, immediately
  # after power-on before any other APDU, hoping to receive stale data from
  # a previous card session or an uninitialised response buffer.
  # ISO 7816-4 clause 7.6: GET RESPONSE is only valid following a command
  # that returned SW1=0x61.  With nothing queued the card must return an
  # error, not arbitrary memory contents.
  # Reference: ISO/IEC 7816-4:2020 clause 7.6.
  # ---------------------------------------------------------------------------

  Scenario: GET RESPONSE without any prior command returns error with no data
    # APDU: CLA=00 INS=C0 P1=00 P2=00 Le=10
    Given the SIM has just been powered on and no other APDU has been sent
    When I send GET RESPONSE with Le=16
    Then SW indicates no data pending
    And the response data is empty (zero bytes returned)
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # GET RESPONSE after SELECT (61 XX) returns FCP data
  # Positive control: SELECT MF returns SW 61 XX, and the subsequent
  # GET RESPONSE must return the FCP template (tag 0x62) with correct SW 90 00.
  # Reference: ETSI TS 102 221 clause 11.1.1.3.
  # ---------------------------------------------------------------------------

  Scenario: GET RESPONSE after SELECT returns FCP template with tag 0x62
    # Step 1: SELECT MF (returns 61 XX)
    When I send SELECT MF
    Then SW1 is 61 and SW2 is the FCP byte count (61 XX)
    # Step 2: GET RESPONSE retrieves FCP
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the response data starts with tag 62 (FCP template)
    And the FCP contains tag 83 with value 3F 00 (MF file identifier)
    And the FCP contains tag 82 (file descriptor)
    And the response data is non-empty

  # ---------------------------------------------------------------------------
  # Second GET RESPONSE after data consumed returns error
  # Attack vector: attacker sends two consecutive GET RESPONSE commands after
  # a single SELECT.  The first drains the response queue; the second must
  # find nothing pending and must return an error without leaking any data.
  # A vulnerable implementation might return the FCP again from a stale buffer.
  # Reference: ETSI TS 102 221 clause 11.1.2.
  # ---------------------------------------------------------------------------

  Scenario: Second GET RESPONSE after data already consumed returns error
    # First GET RESPONSE drains the SELECT-MF FCP queue.
    Given I have selected MF and received SW 61 XX
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds and FCP data is returned
    # Second GET RESPONSE must find no data.
    When I send a second GET RESPONSE with Le=16
    Then SW indicates no data pending
    And the response data is empty

  # ---------------------------------------------------------------------------
  # GET RESPONSE with Le=0
  # ISO 7816-4 clause 7.1.2: Le=0x00 in a short APDU means "return all
  # available data" (up to 256 bytes).  This must not cause the card to return
  # more than the queued FCP length, and must not trigger a buffer overflow.
  # The card may either return all queued data (SW 90 00) or return an error
  # if Le=0 is not supported for GET RESPONSE (implementation-defined).
  # Reference: ISO/IEC 7816-4:2020 clause 5.3.3, 7.6.
  # ---------------------------------------------------------------------------

  Scenario: GET RESPONSE with Le=0 returns available data or error without overflow
    # Le=0x00 means "return all" in ISO 7816-4 short APDU case 2.
    Given I have selected MF and received SW 61 XX
    When I send GET RESPONSE with Le=0
    Then the command succeeds or returns an error
    And if SW is 90 00 the response data length is at most SW2 of the preceding 61 XX
    And the response data does not extend beyond the FCP buffer bounds

  # ---------------------------------------------------------------------------
  # GET RESPONSE after an error command does not leak data from a prior success
  # Attack vector: attacker sequences:
  #   1. SELECT MF (queues FCP, returns 61 XX)
  #   2. GET RESPONSE (drains FCP, SW 90 00)  <-- queue now empty
  #   3. SELECT non-existent FID (returns 6A 82, no queue entry created)
  #   4. GET RESPONSE again (must NOT return the previously queued FCP)
  # A vulnerable implementation with a "sticky" buffer could return the MF FCP
  # on step 4, leaking file information to an observer of step 4's output.
  # Reference: ETSI TS 102 221 clause 11.1.2; ISO 7816-4 clause 7.6.
  # ---------------------------------------------------------------------------

  Scenario: GET RESPONSE after error command does not leak data from prior SELECT
    # Sequence: SELECT MF -> drain FCP -> SELECT bad FID -> GET RESPONSE.
    Given I have selected MF and received SW 61 XX
    And I have consumed the FCP (SW 90 00, queue empty)
    When I send SELECT non-existent FID
    Then SW indicates file not found
    When I send GET RESPONSE with Le=16
    Then SW indicates no data pending
    And the response data is empty (MF FCP is not re-leaked)

  # ---------------------------------------------------------------------------
  # FCP response does not contain sensitive information
  # The FCP returned by SELECT (ETSI TS 102 221 clause 11.1.1.3) must contain
  # only administrative metadata: file size (0x80), file descriptor (0x82),
  # file ID (0x83), AID (0x84 for ADF), life cycle (0x8A), security attributes
  # (0x8C), and PIN status template (0xC6).
  # It must NOT contain:
  #   - Ki, K, OPc, or any cryptographic key material
  #   - PIN or PUK values
  #   - EF content (raw file data)
  #   - Any tag outside those listed in ETSI TS 102 221 Table 11.4
  # ---------------------------------------------------------------------------

  Scenario: SELECT MF FCP contains only permitted administrative tags
    When I send SELECT MF
    Then SW1 is 61
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the FCP outer tag is 62
    And every inner TLV tag is one of: 80 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8F A0 A5 C6
    And the FCP does not contain any byte sequence matching the test Ki  [11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11]
    And the FCP does not contain any byte sequence matching the test K   [22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22]
    And the FCP does not contain any byte sequence matching the test OPc [33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33]

  Scenario: SELECT EF.ICCID FCP does not contain EF raw data
    # SELECT EF.ICCID should return an FCP describing the file, not its content.
    # The EF.ICCID content is [98 10 14 80 00 00 00 00 00 F0]; this must not
    # appear in the FCP response.
    Given I have selected MF and consumed its FCP
    When I send SELECT EF.ICCID
    Then SW1 is 61
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the response data starts with tag 62 (FCP)
    And the FCP contains tag 80 (file size = 0x000A for 10-byte EF)
    And the FCP contains tag 83 with value 2F E2 (EF.ICCID file ID)
    And the response data does not contain the raw ICCID bytes [98 10 14 80 00 00 00 00 00 F0]

  # ---------------------------------------------------------------------------
  # GET RESPONSE after power cycle does not return stale data
  # Attack vector: attacker performs:
  #   1. SELECT MF (queues FCP, returns 61 XX)
  #   2. Power-cycle the card (SimEvent::PowerOn or SimEvent::Reset)
  #   3. GET RESPONSE immediately after power-on
  # A vulnerable implementation that does not reset the response queue on
  # power-on could return the FCP queued in step 1 to the attacker in step 3,
  # even across a card reset boundary.
  # Reference: ETSI TS 102 221 clause 8.1 (card state on power-on/reset);
  #   ISO 7816-3 clause 8.2 (ATR returned on power-on, no data pending).
  # ---------------------------------------------------------------------------

  Scenario: GET RESPONSE after power cycle does not return stale data
    # Step 1: queue some data via SELECT MF.
    Given I have selected MF and received SW 61 XX
    # Step 2: power-cycle (reset) WITHOUT sending GET RESPONSE.
    When I send SimEvent::PowerOn (power-cycle / cold reset)
    Then the SIM returns ATR bytes
    # Step 3: GET RESPONSE must find no pending data.
    When I send GET RESPONSE with Le=16
    Then SW indicates no data pending
    And the response data is empty (no MF FCP leaked across reset boundary)
