# features/ota_envelope.feature
#
# Security regression: OTA / ENVELOPE injection attacks.
#
# Standards:
#   ETSI TS 102 225 V19.0.0  (secured packet structure for UICC)
#   ETSI TS 102 226 V19.0.0  (remote APDU structure for UICC)
#   3GPP TS 23.048 V5.9.0    (security mechanisms for SIM application toolkit)
#   ETSI TS 102 221 V18.3.0  clause 11.2 (ENVELOPE, TERMINAL PROFILE)
#   ETSI TS 102 223 V18.2.0  clause 6   (Card Application Toolkit -- CAT)
#   GSM 03.48 / 3GPP TS 23.048 (OTA security, MSL -- minimum security level)
#
# CVE / research references:
#   CVE-2019-16256 -- SIMjacker: STK PROVIDE LOCAL INFO via malicious ENVELOPE
#   WIBattack (2019) -- similar OTA-based STK injection via Wireless Internet Browser
#
# Status words used:
#   90 00  normal ending
#   67 00  wrong length (Lc/Le inconsistency)
#   6D 00  INS not supported
#   6E 00  CLA not supported
#   6A 80  incorrect parameters in data field (malformed BER-TLV)
#   6F 00  unknown / technical problem
#   69 86  command not allowed (conditions of use not satisfied)
#   98 50  MSL check failed (proprietary -- OTA security failure)
#
# ENVELOPE command structure (ETSI TS 102 221 clause 11.2.1):
#   CLA = 0x80
#   INS = 0xC2
#   P1  = 0x00
#   P2  = 0x00
#   Lc  = length of BER-TLV envelope data
#   Data= BER-TLV encoded envelope (tag, length, value)
#
# TERMINAL PROFILE command (ETSI TS 102 221 clause 11.2.2):
#   CLA = 0x80
#   INS = 0x10
#   P1  = 0x00
#   P2  = 0x00
#   Lc  = profile data length
#   Data= terminal profile bitmap

Feature: OTA / ENVELOPE Injection Security
  As a SIM card simulator
  I must enforce the correct sequencing and structural constraints on ENVELOPE
  and TERMINAL PROFILE commands so that malformed, unsolicited, or improperly
  secured OTA envelopes are rejected before any STK action takes place.

  Background:
    Given the SIM is initialized with test credentials (Ki=0x11*16, K=0x22*16, OPc=0x33*16)
    And the SIM is powered on (SimEvent::PowerOn sent, ATR received)
    And MF is implicitly selected at power-on
    And TERMINAL PROFILE has NOT yet been sent

  # ---------------------------------------------------------------------------
  # ENVELOPE before TERMINAL PROFILE
  # Attack vector (SIMjacker-class): the attacker sends a crafted ENVELOPE
  # (CLA=0x80, INS=0xC2) over-the-air before the handset has sent a
  # TERMINAL PROFILE, bypassing the CAT initialisation sequence.
  # Reference: CVE-2019-16256; ETSI TS 102 221 clause 11.2.1 precondition.
  # The TERMINAL PROFILE exchange establishes the terminal's CAT capability
  # bitmap; without it the UICC has no basis for processing CAT envelopes.
  # Expected: error SW (69 86 -- conditions not satisfied, or 6D 00, or 6F 00).
  # ---------------------------------------------------------------------------

  Scenario: ENVELOPE before TERMINAL PROFILE is rejected
    # Attack APDU: ENVELOPE with a minimal BER-TLV (tag=D1 len=00 -- empty
    # SMS-PP download container).
    # CLA=80 INS=C2 P1=00 P2=00 Lc=02 Data=[D1 00]
    Given TERMINAL PROFILE has not been sent
    When I send ENVELOPE with empty SMS-PP download
    Then SW indicates command rejected
    And no STK command is executed
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # ENVELOPE with empty data field
  # Attack vector: zero-length ENVELOPE body; no BER-TLV at all.
  # A well-formed ENVELOPE requires at least a tag and a length byte.
  # An empty data field cannot constitute a valid CAT envelope.
  # Reference: ETSI TS 102 221 clause 11.2.1; ETSI TS 102 223 clause 6.
  # Expected: error SW (6A 80 or 67 00 or 69 86).
  # ---------------------------------------------------------------------------

  Scenario: ENVELOPE with empty data field is rejected
    # Precondition: TERMINAL PROFILE sent first to pass the sequencing check.
    # ENVELOPE APDU: CLA=80 INS=C2 P1=00 P2=00 Lc=00 (no data)
    Given I have sent TERMINAL PROFILE (SW 90 00)
    When I send ENVELOPE with empty data
    Then SW indicates wrong length or incorrect parameters
    And no STK command is executed
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # ENVELOPE with malformed BER-TLV (tag present, length byte absent)
  # Attack vector: truncated BER-TLV -- the tag byte D1 is present but the
  # stream ends before the length field.  Parsers that assume a minimum of
  # two bytes may access out-of-bounds memory or misinterpret the value.
  # Reference: ETSI TS 102 221 clause 11.2.1; X.690 BER encoding rules.
  # Expected: error SW (6A 80 -- incorrect data field, or 67 00).
  # ---------------------------------------------------------------------------

  Scenario: ENVELOPE with BER-TLV tag but no length field is rejected
    # APDU: CLA=80 INS=C2 P1=00 P2=00 Lc=01 Data=[D1]
    # The BER-TLV has tag 0xD1 but zero further bytes -- incomplete TLV.
    Given I have sent TERMINAL PROFILE (SW 90 00)
    When I send ENVELOPE with truncated BER-TLV
    Then SW indicates wrong length or incorrect parameters
    And no STK command is executed
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # ENVELOPE with oversized data (> 255 bytes payload)
  # Attack vector: APDU with Lc claiming more than 255 bytes, probing whether
  # the T=0 framing or the ENVELOPE handler overflows an internal buffer.
  # ISO 7816-3 T=0: a single TPDU data field is limited to 255 bytes; an Lc
  # of 0x00 in extended-length context is not available in T=0.
  # At the HLE layer the raw APDU slice is bounded by the caller, so we test
  # a synthetic 256-byte data slice passed to the APDU dispatcher.
  # Reference: ISO 7816-4 clause 5.1; ETSI TS 102 221 clause 10.
  # Expected: SW 67 00 (wrong length) or 6A 80.
  # ---------------------------------------------------------------------------

  Scenario: ENVELOPE with data length exceeding 255 bytes returns wrong length
    # Construct an APDU slice whose Lc byte = 0xFF (255) but the actual
    # content is padded with zeros to match.  The total APDU is 4+1+255=260
    # bytes; some implementations reject Lc=FF for ENVELOPE as oversized.
    # Alternatively supply Lc=0xFF with a 256-byte payload to trigger the
    # length mismatch path.
    Given I have sent TERMINAL PROFILE (SW 90 00)
    When I send ENVELOPE with 255-byte BER-TLV payload
    Then SW indicates wrong length or incorrect parameters
    And no STK command is executed
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # TERMINAL PROFILE with valid profile bitmap (positive control)
  # Confirms that a well-formed TERMINAL PROFILE is accepted by the card.
  # This establishes the precondition required by all subsequent ENVELOPE tests.
  # Reference: ETSI TS 102 221 clause 11.2.2; ETSI TS 102 223 clause 5.2.
  # ---------------------------------------------------------------------------

  Scenario: TERMINAL PROFILE with valid profile data returns 90 00
    # 4-byte all-ones bitmap: terminal claims full STK feature support.
    # APDU: CLA=80 INS=10 P1=00 P2=00 Lc=04 Data=[FF FF FF FF]
    When I send TERMINAL PROFILE
    Then the command succeeds

  # ---------------------------------------------------------------------------
  # ENVELOPE after TERMINAL PROFILE with valid SMS-PP download structure
  # Positive control: after the correct TERMINAL PROFILE exchange an ENVELOPE
  # carrying a syntactically valid SMS-PP download container must be accepted.
  # SMS-PP download outer tag = 0xD1; Device Identities TLV (82 02 83 81) and
  # Address TLV (06 01 81) are the minimum non-empty inner TLVs.
  # Reference: ETSI TS 102 223 clause 6.7 (SMS-PP download); 3GPP TS 23.048.
  # ---------------------------------------------------------------------------

  Scenario: ENVELOPE after TERMINAL PROFILE with valid SMS-PP download is accepted
    # SMS-PP Download envelope (tag D1):
    #   82 02 83 81  -- Device Identities: source=Network(83), dest=UICC(81)
    #   06 01 81     -- Address TLV (minimal)
    # Full BER-TLV body = D1 07 82 02 83 81 06 01 81 (9 bytes)
    # APDU: CLA=80 INS=C2 P1=00 P2=00 Lc=09 Data=[D1 07 82 02 83 81 06 01 81]
    Given I have sent TERMINAL PROFILE (SW 90 00)
    When I send ENVELOPE with valid SMS-PP download
    Then the command succeeds or response data is available

  # ---------------------------------------------------------------------------
  # SIMjacker-style ENVELOPE: STK PROVIDE LOCAL INFO without OTA security
  # CVE-2019-16256 attack path:
  #   An attacker sends an over-the-air binary SMS whose payload is a raw
  #   ENVELOPE APDU containing a PROVIDE LOCAL INFO STK command (type 0x26).
  #   On vulnerable cards the ENVELOPE was processed without verifying the
  #   OTA security header (MSL = minimum security level check).
  #
  # The simrs implementation must enforce the MSL check defined in
  # 3GPP TS 23.048 clause 5 before forwarding any OTA command to the STK
  # engine.  Without valid RC/CC/DS authentication the ENVELOPE must be
  # rejected even if the BER-TLV is syntactically correct.
  #
  # Attack APDU structure (simplified -- no OTA security header):
  #   CLA=80 INS=C2 P1=00 P2=00 Lc=0B
  #   Data = D6 09              -- CAT envelope tag D6 (Event Download),
  #          82 02 82 81        -- Device Identities: ME -> UICC
  #          99 03 26 00 00     -- PROVIDE LOCAL INFO (type 26h)
  #   Note: legitimate SIMjacker used SMS-PP tag D1 + STK commands embedded
  #         inside; here we use a direct CAT envelope without OTA wrapper.
  #
  # Reference: CVE-2019-16256; 3GPP TS 23.048 clause 5 (MSL); Citizen Lab
  #   SIMjacker report (2019).
  # ---------------------------------------------------------------------------

  Scenario: SIMjacker-style ENVELOPE with PROVIDE LOCAL INFO is rejected without OTA security
    # Attack: send an ENVELOPE containing a PROVIDE LOCAL INFO STK command
    # (command type 0x26) without any OTA security wrapper (no RC/CC/DS).
    # The card must reject this because the minimum security level (MSL) is
    # not satisfied.
    # APDU: CLA=80 INS=C2 P1=00 P2=00 Lc=0B
    #       Data = [D6 09 82 02 82 81 99 03 26 00 00]
    Given I have sent TERMINAL PROFILE (SW 90 00)
    When I send SIMjacker-style ENVELOPE with PROVIDE LOCAL INFO
    Then the ENVELOPE is rejected or the STK action is not executed
    And the response SW does not indicate that PROVIDE LOCAL INFO ran (not 90 00 with location data)
    And no SIM state has changed
    # Rationale: the simrs OTA layer (simrs-ota) must check MSL before
    # dispatching; absent a cryptographically verified OTA header the card
    # treats the payload as unauthenticated and rejects it.

  # ---------------------------------------------------------------------------
  # ENVELOPE with zero-length TLV value
  # Attack vector: BER-TLV with valid tag (D1 -- SMS-PP download) and
  # explicit zero length (L=00, V absent).  This is syntactically legal BER
  # but semantically invalid for SMS-PP which requires at least Device
  # Identities.  The card must handle this gracefully without crashing,
  # looping, or leaking data.
  # Reference: ETSI TS 102 223 clause 6.7; X.690 BER.
  # ---------------------------------------------------------------------------

  Scenario: ENVELOPE with zero-length TLV value is handled gracefully
    # BER-TLV: tag=D1 length=00 (empty SMS-PP download)
    # APDU: CLA=80 INS=C2 P1=00 P2=00 Lc=02 Data=[D1 00]
    Given I have sent TERMINAL PROFILE (SW 90 00)
    When I send ENVELOPE with zero-length TLV value
    Then SW is an error code
    And the SIM remains operational (subsequent commands are processed normally)
    And the response data is empty
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # OTA command packet MAC verification (crypto layer)
  # Tests simrs-ota encode/decode_command_packet directly. These verify that
  # the OTA security layer correctly enforces AES-CBC-MAC integrity checks,
  # which is the mechanism that prevents SIMjacker-class attacks at the
  # protocol level.
  # Reference: ETSI TS 102 225 clause 5; 3GPP TS 23.048 clause 5.
  # ---------------------------------------------------------------------------

  Scenario: OTA command packet with valid MAC roundtrips successfully
    Given an OTA command packet encoded with AES-CBC-MAC
    When the packet is decoded with the correct key
    Then decoding succeeds with the original data

  Scenario: OTA command packet with tampered MAC is rejected
    Given an OTA command packet encoded with AES-CBC-MAC
    When the MAC bytes in the packet are inverted and it is decoded
    Then decoding fails with MacVerifyFailed

  Scenario: OTA command packet decoded with wrong key is rejected
    Given an OTA command packet encoded with AES-CBC-MAC
    When the packet is decoded with a different key
    Then decoding fails with MacVerifyFailed

  # ---------------------------------------------------------------------------
  # UST service gating for ENVELOPE
  # ENVELOPE acceptance must be gated by the USIM Service Table (EF.UST).
  # SMS-PP Data Download requires UST service 28; Call Control requires
  # service 30. If the service is disabled, the ENVELOPE must be rejected.
  # Reference: 3GPP TS 31.102 V19.4.0 clause 4.2.8 Table 4.2.8.
  # ---------------------------------------------------------------------------

  Scenario: Call Control ENVELOPE without Device Identities is rejected
    Given the SIM is initialised with test credentials
    And the SIM is powered on
    And I have sent TERMINAL PROFILE (SW 90 00)
    When I send Call Control ENVELOPE without Device Identities
    Then SW is 6A 80 (incorrect parameters in data field)

  Scenario: Call Control ENVELOPE with valid Device Identities is accepted
    Given the SIM is initialised with test credentials
    And the SIM is powered on
    And I have sent TERMINAL PROFILE (SW 90 00)
    When I send Call Control ENVELOPE with Device Identities
    Then SW is 90 00 (success)

  # ---------------------------------------------------------------------------
  # ENVELOPE response chaining (3GPP TS 31.101 / ETSI TS 102 221 clause 11.2.1)
  #
  # When a short APDU cannot carry the full response, the card returns
  # SW 61 XX and the terminal issues GET RESPONSE [00 C0 00 00 XX] to
  # retrieve the remaining bytes. OTA ENVELOPE responses that include a
  # proactive command payload routinely exceed 255 bytes.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: ENVELOPE with response exceeding 255 bytes returns 61 XX and chains via GET RESPONSE
    Given the SIM is initialised with test credentials
    And the SIM is powered on
    And I have sent TERMINAL PROFILE (SW 90 00)
    When I send an ENVELOPE whose response is 300 bytes long
    Then SW is 61 XX where XX is the remaining byte count
    When I send GET RESPONSE [00 C0 00 00 XX]
    Then SW is 90 00
    And the concatenated response equals the original 300-byte ENVELOPE response

  @wip
  Scenario: ENVELOPE response chaining preserves proactive-command state across GET RESPONSE
    # A proactive command queued by ENVELOPE must remain FETCH-retrievable
    # after the full response has been chained back to the terminal.
    Given the SIM is initialised with test credentials
    And the SIM is powered on
    And I have sent TERMINAL PROFILE (SW 90 00)
    When I send an ENVELOPE that queues a DISPLAY TEXT proactive command
    And the ENVELOPE response is 300 bytes requiring chained GET RESPONSE
    And I chain the response via GET RESPONSE
    When I send FETCH [80 12 00 00 00]
    Then SW is 90 00
    And the response data is the DISPLAY TEXT proactive command TLV
