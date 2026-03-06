# features/auth_protocol.feature
#
# Security regression: AUTHENTICATE protocol attack scenarios.
#
# Standards:
#   3GPP TS 31.102 V16.9.0  clause 7.1.2   (AUTHENTICATE command)
#   3GPP TS 33.102 V16.2.0  clause 6.3     (AKA authentication and key agreement)
#   3GPP TS 35.205 V16.0.0                 (Milenage algorithm spec)
#   ETSI TS 102 221 V18.0.0 clause 11.1.10 (AUTHENTICATE)
#   GSM 11.11 / 3GPP TS 51.011 clause 9   (RUN GSM ALGORITHM, INS=0x88, P2=0x00)
#
# AUTHENTICATE APDU structure (3GPP USIM context, 3GPP TS 31.102 clause 7.1.2):
#   CLA = 0x00
#   INS = 0x88
#   P1  = 0x00
#   P2  = 0x81  (UMTS context -- 3G AKA)
#   Lc  = total data length
#   Data= 0x10 <RAND[16]> 0x10 <AUTN[16]>   (standard 34 bytes + 2 length bytes)
#
# GSM context (P2=0x00, used by GsmApp CLA=0xA0):
#   CLA = 0xA0
#   INS = 0x88  (RUN GSM ALGORITHM in GSM 11.11)
#   P1  = 0x00
#   P2  = 0x00
#   Lc  = 0x10 (16 bytes)
#   Data= RAND[16]
#
# Status words:
#   90 00  command successful
#   61 XX  response data available (XX bytes via GET RESPONSE)
#   69 86  command not allowed (conditions of use not satisfied -- no ADF selected)
#   67 00  wrong length (wrong Lc)
#   6A 80  incorrect parameters in data field (malformed RAND/AUTN)
#   6A 86  incorrect parameters P1-P2 (unsupported P2 context byte)
#   98 62  authentication error -- incorrect MAC (AUTN MAC mismatch)
#   98 64  authentication error -- security context not supported
#   6E 00  class not supported
#
# Successful AUTHENTICATE response (UMTS context, GET RESPONSE after 61 XX):
#   Tag 0xDB: successful AKA
#     0x04 <RES[4..16]>  -- response
#     0x10 <CK[16]>      -- cipher key
#     0x10 <IK[16]>      -- integrity key
#   Tag 0xDC: sync failure
#     0x0E <AUTS[14]>    -- resynchronisation token

Feature: AUTHENTICATE Protocol Attack Scenarios
  As a SIM card simulator
  I must enforce the preconditions and input validation of the AUTHENTICATE
  command (INS=0x88) to prevent authentication oracle abuse and protocol
  downgrade attacks as specified in 3GPP TS 31.102 clause 7.1.2 and
  3GPP TS 33.102 clause 6.3.

  Background:
    Given the SIM is initialized with Milenage credentials:
      """
      Ki  = [11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11]
      K   = [22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22]
      OPc = [33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33]
      """
    And the SIM is initialized with an ADF table mapping AID A0000000871002 to ADF.USIM
    And the SIM is powered on (SimEvent::PowerOn sent, ATR received)
    And MF is implicitly selected

  # ---------------------------------------------------------------------------
  # AUTHENTICATE without ADF.USIM selection
  # Attack vector: attacker sends AUTHENTICATE (CLA=0x00 INS=0x88, P2=0x81)
  # while MF is current -- no ADF.USIM context is active.
  # 3GPP TS 31.102 clause 7.1.2 mandates that AUTHENTICATE is only valid
  # within the ADF.USIM application context; the card must reject it with
  # 69 86 (conditions of use not satisfied) when no ADF is selected.
  # This prevents using the AUTHENTICATE channel without proper application
  # selection, which could otherwise bypass AID-level access control.
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE without ADF.USIM selection returns 69 86
    # APDU: CLA=00 INS=88 P1=00 P2=81 Lc=22
    #       Data = 10 [RAND:16 bytes] 10 [AUTN:16 bytes]
    # Total data field = 0x10 + 16 + 0x10 + 16 = 34 bytes; Lc=0x22
    Given MF is the current DF (no ADF selected)
    When I send AUTHENTICATE with arbitrary RAND and AUTN
    Then the command is rejected
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # AUTHENTICATE with wrong RAND length (not 16 bytes)
  # Attack vector: supply a RAND that is 8 bytes instead of the mandatory
  # 16 bytes, e.g. to probe input validation or trigger a buffer underread.
  # 3GPP TS 31.102 clause 7.1.2: RAND must be exactly 16 bytes (0x10).
  # Expected: SW 67 00 (wrong length) or 6A 80 (incorrect data field).
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with RAND shorter than 16 bytes returns wrong-length error
    # Data: length byte 0x08 indicating 8-byte RAND, then 8 bytes of RAND.
    # No AUTN follows, so Lc=0x09.
    # APDU: CLA=00 INS=88 P1=00 P2=81 Lc=09 Data=[08 AA AA AA AA AA AA AA AA]
    Given ADF.USIM is selected
    When I send AUTHENTICATE with short RAND of 8 bytes
    Then SW indicates wrong length or incorrect data
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # AUTHENTICATE with RAND length byte = 0
  # Edge case: length prefix for RAND is 0x00, meaning zero-byte RAND.
  # This violates the 3GPP TS 31.102 data format and must be rejected.
  # A vulnerable implementation might treat a zero-length RAND as all-zeros,
  # providing an authentication oracle for the zero RAND.
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with zero-length RAND is rejected
    # APDU: CLA=00 INS=88 P1=00 P2=81 Lc=01 Data=[00]
    Given ADF.USIM is selected
    When I send AUTHENTICATE with zero-length RAND
    Then SW indicates wrong length or incorrect data
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # AUTHENTICATE with valid 16-byte RAND and correct AUTN returns RES/CK/IK
  # Positive control: confirms the authentication path works end-to-end.
  # With Milenage K=[22]*16, OPc=[33]*16, and Milenage test RAND/AUTN that
  # produces a valid MAC, the card must return SW 61 XX and GET RESPONSE
  # must yield tag 0xDB containing RES, CK, IK.
  # Reference: 3GPP TS 31.102 clause 7.1.2.1; TS 35.207 test vectors.
  #
  # Note: because the test credentials are not from a published TS 35.207
  # test set, the actual RES/CK/IK values are not hardcoded here; the test
  # verifies structural properties only (tag, sub-field lengths).
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with valid RAND and correct AUTN returns 61 XX then DB tag
    # For test purpose use a RAND that produces no SQN failure with the
    # test Milenage parameters.  The exact bytes are implementation-dependent
    # for the test credential set; the step supplies a plausible (RAND, AUTN)
    # pair accepted by the Milenage engine.
    # APDU: CLA=00 INS=88 P1=00 P2=81 Lc=22
    #       10 [RAND:16] 10 [AUTN:16]
    Given ADF.USIM is selected
    When I send AUTHENTICATE with a RAND and AUTN that pass Milenage MAC verification
    Then SW1 is 61
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the response starts with tag DB (successful authentication)
    And the DB response contains a RES sub-field (tag 04, 4..16 bytes)
    And the DB response contains a CK sub-field (tag 10, 16 bytes)
    And the DB response contains an IK sub-field (tag 10, 16 bytes)

  # ---------------------------------------------------------------------------
  # AUTHENTICATE with AUTN containing a wrong MAC (tampered MAC)
  # Attack vector: the attacker replays or forges an AUTN whose MAC field
  # is incorrect.  The card must detect the MAC failure and return SW 98 62
  # (authentication error -- incorrect MAC) without leaking key material.
  # Reference: 3GPP TS 33.102 clause 6.3.3; TS 31.102 clause 7.1.2.
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with tampered AUTN MAC returns 98 62
    # Tamper the last 8 bytes of AUTN (the MAC field) by XORing all bits.
    # APDU: CLA=00 INS=88 P1=00 P2=81 Lc=22
    #       10 [RAND:16]  10 [AUTN with corrupted MAC:16]
    Given ADF.USIM is selected
    When I send AUTHENTICATE with a valid RAND but with AUTN MAC field fully inverted (all FF XOR original)
    Then SW indicates authentication error
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # AUTHENTICATE with replayed SQN (replay attack detection)
  # When the SQN in AUTN has already been accepted, the USIM's SQN_HE counter
  # rejects it as stale and returns a sync failure response (tag 0xDC
  # containing AUTS) rather than 98 62.
  # Reference: 3GPP TS 33.102 clause 6.3.3 (SQN freshness);
  #            3GPP TS 33.102 clause 6.3.5 (AUTS resynchronization);
  #            3GPP TS 31.102 clause 7.1.2.
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with replayed SQN returns 61 XX then DC tag with AUTS
    # A valid MAC but a stale SQN (one that has already been accepted)
    # triggers synchronisation failure.  The USIM returns tag 0xDC
    # containing a 14-byte AUTS token for network resynchronization.
    Given ADF.USIM is selected
    And a successful AUTHENTICATE has been performed
    When I send AUTHENTICATE with a replayed SQN (valid MAC but consumed sequence number)
    Then SW1 is 61
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the response starts with tag DC (synchronisation failure)
    And the DC response contains an AUTS sub-field of exactly 14 bytes
    And the AUTS encodes the expected SQN_MS and MAC-S for the replayed RAND

  # ---------------------------------------------------------------------------
  # AUTHENTICATE P2 byte validation: P2=0x00 is the GSM context
  # 3GPP TS 31.102 clause 7.1.2: P2=0x00 selects the GSM security context
  # (used by the USIM for 2G authentication).  When accessed via the USIM
  # application (CLA=0x00) with P2=0x00, the card must process it as a GSM
  # context authenticate (returning SRES+Kc) rather than UMTS AKA.
  # This scenario verifies correct routing -- not a security attack per se,
  # but ensures P2=0x00 is not silently ignored or mis-routed to 3G AKA.
  # Reference: 3GPP TS 31.102 clause 7.1.2.1 table.
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with P2=0x00 (GSM context) is handled correctly
    # GSM context AUTHENTICATE: RAND only (16 bytes), no AUTN.
    # APDU: CLA=00 INS=88 P1=00 P2=00 Lc=11 Data=[10 <RAND:16>]
    Given ADF.USIM is selected
    When I send AUTHENTICATE P2=0x00 GSM context with arbitrary RAND
    Then the command succeeds or response data is available
    And the response does not contain tag DB or DC (not UMTS AKA format)

  # ---------------------------------------------------------------------------
  # AUTHENTICATE with P2=0x81 (UMTS context) is handled correctly
  # Positive control confirming UMTS AKA routing.
  # Reference: 3GPP TS 31.102 clause 7.1.2.
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with P2=0x81 (UMTS context) routes to Milenage AKA
    # APDU: CLA=00 INS=88 P1=00 P2=81 Lc=22 Data=[10 <RAND:16> 10 <AUTN:16>]
    Given ADF.USIM is selected
    When I send AUTHENTICATE with arbitrary RAND and AUTN
    Then SW indicates authentication error or response data is available
    # If the RAND/AUTN are arbitrary test bytes the MAC will fail (98 62);
    # the important check is that 6A 86 is NOT returned (P2 was accepted).

  # ---------------------------------------------------------------------------
  # AUTHENTICATE with invalid P2 value returns 6A 86
  # Attack vector: supply an unsupported P2 context byte (e.g. 0x42) to probe
  # whether the card falls back to a default context or rejects the command.
  # A silent fallback could allow context confusion attacks.
  # Reference: ETSI TS 102 221 clause 11.1.10; 3GPP TS 31.102 clause 7.1.2.
  # ---------------------------------------------------------------------------

  Scenario: AUTHENTICATE with unsupported P2 context byte returns 6A 86
    # APDU: CLA=00 INS=88 P1=00 P2=42 (undefined context) Lc=22
    Given ADF.USIM is selected
    When I send AUTHENTICATE with unsupported P2=0x42
    Then SW indicates incorrect P1-P2
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # Multiple AUTHENTICATE commands in sequence are independent
  # Verifies that authentication state does not bleed between calls:
  # each AUTHENTICATE operates on fresh inputs and the response of one call
  # does not influence the next.  This guards against state machine bugs where
  # a pending response from call N is returned by call N+1.
  # Reference: 3GPP TS 31.102 clause 7.1.2 -- no session state between calls.
  # ---------------------------------------------------------------------------

  Scenario: Multiple AUTHENTICATE commands in sequence work independently
    # First AUTHENTICATE: arbitrary bytes -> expect MAC failure (98 62) or sync
    # failure (61 XX with DC), but NOT a crash or stale state carry-over.
    Given ADF.USIM is selected
    When I send AUTHENTICATE with arbitrary RAND and AUTN (first call)
    Then SW indicates authentication error or response data is available
    When I send AUTHENTICATE with different arbitrary RAND and AUTN (second call)
    Then SW indicates authentication error or response data is available
    And the response of the second call is not a copy of the first call's response

  # ---------------------------------------------------------------------------
  # COMP128v1 Kc weakness: bits 54-63 are always zero
  # The COMP128v1 algorithm only produces 54 effective bits of Kc. Per the
  # algorithm specification (Briceno/Goldberg/Wagner 1998):
  #   kc[7] == 0x00 (all 8 bits zero)
  #   kc[6] & 0x03 == 0x00 (bottom 2 bits zero)
  # This is a structural weakness that reduces the A5 keyspace.
  # Reference: GSM 11.11 clause 11; simrs-comp128 crate.
  # ---------------------------------------------------------------------------

  Scenario: COMP128v1 Kc has last 10 bits always zero
    Given the SIM is initialized with test credentials
    When I compute COMP128 with RAND [AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99]
    Then the Kc byte 7 is 0x00
    And the Kc byte 6 has bottom 2 bits zero

  Scenario: COMP128v1 Kc weakness holds across different RAND values
    Given the SIM is initialized with test credentials
    When I compute COMP128 with RAND [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
    Then the Kc byte 7 is 0x00
    And the Kc byte 6 has bottom 2 bits zero
    When I compute COMP128 with RAND [FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF]
    Then the Kc byte 7 is 0x00
    And the Kc byte 6 has bottom 2 bits zero
