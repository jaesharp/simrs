# features/fs_access_control.feature
#
# Security regression: filesystem access control bypass.
#
# Standards:
#   ETSI TS 102 221 V16.4.0  clause 8  (security architecture)
#   ETSI TS 102 221 V16.4.0  clause 11 (command descriptions)
#   ETSI TS 102 222 V16.0.0  clause 6  (administrative commands)
#   ISO/IEC 7816-4:2020      clause 7  (interindustry commands)
#
# Status words used (ETSI TS 102 221 Table 10.3):
#   69 86  command not allowed -- no current EF
#   69 81  command incompatible with file structure
#   6A 82  file or application not found
#   6A 81  function not supported
#   6B 00  wrong parameters P1-P2 (offset outside EF)
#   69 86  (also: command not allowed -- conditions of use not satisfied)
#   6F 00  unknown / technical problem
#   90 00  normal ending of the command

Feature: Filesystem Access Control Bypass
  As a SIM card simulator
  I must enforce ETSI TS 102 221 clause 8 access conditions at the APDU level
  so that file-read commands without a prior correct SELECT are rejected,
  out-of-bounds accesses are caught, and directory nodes cannot be read as data.

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
  # READ BINARY without prior SELECT
  # Attack vector: caller sends READ BINARY (CLA=0x00 INS=0xB0) immediately after
  # power-on, bypassing the mandatory SELECT step.  The card must not return any
  # file data.  ETSI TS 102 221 clause 11.1.3 states the command is rejected with
  # SW 69 86 when there is no current EF in the selection state.
  # ---------------------------------------------------------------------------

  Scenario: READ BINARY without prior SELECT returns 69 86
    # Attack: attempt to read a transparent EF with no EF in selection context.
    # Reference: ETSI TS 102 221 clause 11.1.3 condition check.
    Given no SELECT command has been sent since power-on
    When I send READ BINARY at offset 0 length 1
    Then SW indicates no current EF
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # UPDATE BINARY without prior SELECT
  # Attack vector: caller sends UPDATE BINARY (INS=0xD6) with attacker-controlled
  # data to overwrite an EF without first SELECTing it.
  # Reference: ETSI TS 102 221 clause 11.1.4.
  # ---------------------------------------------------------------------------

  Scenario: UPDATE BINARY without prior SELECT returns 69 86
    # Attack: attempt to write 1 byte at offset 0 to whatever the "current EF"
    # would be, when in fact no EF is selected.
    # APDU: CLA=00 INS=D6 P1=00 P2=00 Lc=01 Data=AA
    Given no SELECT command has been sent since power-on
    When I send UPDATE BINARY at offset 0 with 1 byte
    Then SW indicates no current EF
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # READ RECORD without prior SELECT
  # Attack vector: caller sends READ RECORD (INS=0xB2) for record 1 with no
  # current EF, attempting to read record data from an unspecified file.
  # Reference: ETSI TS 102 221 clause 11.1.5.
  # ---------------------------------------------------------------------------

  Scenario: READ RECORD without prior SELECT returns 69 86
    # APDU: CLA=00 INS=B2 P1=01 (record 1) P2=04 (absolute mode) Le=01
    Given no SELECT command has been sent since power-on
    When I send READ RECORD record 1 in absolute mode
    Then SW indicates no current EF
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # SELECT non-existent FID
  # Attack vector: caller probes for files by trying non-existent FIDs.
  # The card must return 6A 82 without leaking timing information about
  # which FIDs exist.
  # Reference: ETSI TS 102 221 clause 11.1.1.
  # ---------------------------------------------------------------------------

  Scenario: SELECT non-existent FID returns 6A 82
    # APDU: CLA=00 INS=A4 P1=00 (by FID) P2=04 (return FCP) Lc=02 FID=FF FF
    When I send SELECT non-existent FID
    Then SW indicates file not found
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # SELECT non-existent AID
  # Probing for applications via AID (P1=0x04) should also return 6A 82.
  # Reference: ETSI TS 102 221 clause 11.1.1.
  # ---------------------------------------------------------------------------

  Scenario: SELECT by unknown AID returns 6A 82
    # APDU: CLA=00 INS=A4 P1=04 (by AID) P2=04 Lc=07 AID=FF FF FF FF FF FF FF
    When I send SELECT by unknown AID
    Then SW indicates file not found
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # READ BINARY on a DF (directory) node
  # Attack vector: attacker SELECTs a DF (e.g. MF=3F00 which is always selectable)
  # then sends READ BINARY, hoping to read internal DF metadata as raw bytes.
  # ETSI TS 102 221 clause 11.1.3: READ BINARY is only valid on transparent EFs;
  # the command applied to a DF must be rejected.
  # The expected SW is 69 86 (no current EF -- DF is not an EF) or
  # 69 81 (command incompatible with file structure).
  # ---------------------------------------------------------------------------

  Scenario: READ BINARY after selecting MF (a DF, not an EF) is rejected
    # Step 1 selects the MF successfully. Step 2 attempts a binary read.
    Given I have selected MF (SW 61 XX returned)
    And I have consumed the FCP via GET RESPONSE
    When I send READ BINARY at offset 0 length 1
    Then SW indicates command not allowed on DF
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # READ BINARY with offset beyond end of file
  # Attack vector: caller presents an offset that, combined with the requested
  # length, extends past the last byte of the EF to read memory beyond the file.
  # EF.ICCID is 10 bytes (indices 0x00..0x09); offset 0x08 + length 5 overruns.
  # Reference: ETSI TS 102 221 clause 11.1.3; ISO 7816-4 clause 7.2.3.
  # Expected: SW 6B 00 (wrong parameters -- offset outside EF).
  # ---------------------------------------------------------------------------

  Scenario: READ BINARY with offset + length beyond EF size returns 6B 00
    # EF.ICCID is 10 bytes.  Offset 8, length 5 requires bytes 8..12 -- overrun.
    # APDU: CLA=00 INS=B0 P1=00 P2=08 (offset=8) Le=05
    Given I have selected EF.ICCID (SW 61 XX returned)
    And I have consumed the FCP via GET RESPONSE
    When I send READ BINARY at offset 8 length 5
    Then the command is rejected
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # READ BINARY at exact end of file (boundary -- must succeed)
  # Verify the off-by-one boundary: reading the last byte of a 10-byte EF
  # at offset 9 with length 1 is valid and must return 90 00.
  # ---------------------------------------------------------------------------

  Scenario: READ BINARY of last byte of EF succeeds
    # APDU: CLA=00 INS=B0 P1=00 P2=09 (offset=9) Le=01
    Given I have selected EF.ICCID
    And I have consumed the FCP via GET RESPONSE
    When I send READ BINARY at offset 9 length 1
    Then the command succeeds
    And the response data is [F0] (last byte of ICCID)

  # ---------------------------------------------------------------------------
  # GET RESPONSE without any prior data-returning command
  # Attack vector: send GET RESPONSE cold (no prior SELECT or other 61-XX
  # command) to see if the card leaks stale data from a previous session or
  # exposes an uninitialised response buffer.
  # Reference: ISO 7816-4 clause 7.6; ETSI TS 102 221 clause 11.1.2.
  # Expected: SW 69 86 or 6F 00 (nothing pending).
  # ---------------------------------------------------------------------------

  Scenario: GET RESPONSE without prior data-returning command returns error
    # APDU: CLA=00 INS=C0 P1=00 P2=00 Le=10
    Given the SIM is freshly powered on with no commands sent
    When I send GET RESPONSE with Le=16
    Then SW indicates no data pending
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # Double GET RESPONSE -- second call after data consumed must fail
  # Attack vector: attacker sends two consecutive GET RESPONSE commands after
  # a single SELECT, hoping the second call returns leftover or stale data.
  # The response queue must be emptied after the first GET RESPONSE.
  # Reference: ETSI TS 102 221 clause 11.1.2.
  # ---------------------------------------------------------------------------

  Scenario: Second GET RESPONSE after data already consumed returns error
    # After SELECT MF returns 61 XX, one GET RESPONSE drains the queue.
    # The second GET RESPONSE must find nothing pending.
    Given I have selected MF and received SW 61 XX
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds and FCP data is returned
    When I send a second GET RESPONSE with Le=16
    Then SW indicates no data pending
    And the response data is empty

  # ---------------------------------------------------------------------------
  # SELECT MF then READ BINARY without selecting an EF
  # Attack vector: attacker correctly navigates to MF but then skips the EF
  # SELECT step and sends READ BINARY directly, hoping that the current-DF
  # context implicitly grants access to child EFs.
  # Reference: ETSI TS 102 221 clause 8 -- access to EF requires EF selection.
  # ---------------------------------------------------------------------------

  Scenario: SELECT MF then READ BINARY without EF selection returns 69 86
    # MF is selected (current DF = MF, no current EF).
    # READ BINARY without subsequent EF SELECT must be rejected.
    Given I have selected MF
    And I have consumed the FCP via GET RESPONSE
    When I send READ BINARY at offset 0 length 1
    Then SW indicates no current EF
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # SELECT EF.ICCID (FID 2FE2) under MF then READ BINARY (positive control)
  # Verifies that the correct access sequence -- SELECT MF, SELECT EF.ICCID,
  # READ BINARY -- succeeds, confirming the security controls are applied only
  # at the right boundaries.
  # Reference: ETSI TS 102 221 clause 11.1.1 and 11.1.3.
  # ---------------------------------------------------------------------------

  Scenario: Full SELECT MF -> SELECT EF.ICCID -> READ BINARY round-trip succeeds
    # Step 1: SELECT MF
    When I send SELECT MF
    Then SW1 is 61
    # Step 2: consume FCP
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    # Step 3: SELECT EF.ICCID under MF (FID 2F E2)
    When I send SELECT EF.ICCID
    Then SW1 is 61
    # Step 4: consume FCP
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    # Step 5: READ BINARY -- all 10 bytes
    When I send READ BINARY at offset 0 length 10
    Then the command succeeds
    And the response data is [98 10 14 80 00 00 00 00 00 F0] (EF.ICCID content)
