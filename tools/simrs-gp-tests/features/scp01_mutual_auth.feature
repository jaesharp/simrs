# features/scp01_mutual_auth.feature
#
# SCP01 Secure Channel Protocol mutual authentication tests.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  Appendix D (SCP01)
#   GlobalPlatform Card Specification v2.1.1  clause 8 (Secure Channel)
#
# INITIALIZE UPDATE APDU (GP 2.1.1 clause 8.1):
#   CLA = 0x80
#   INS = 0x50
#   P1  = key version number (0x00 = any)
#   P2  = key identifier (0x00 = any)
#   Lc  = 0x08
#   Data= host_challenge[8]
#   Le  = 0x00 (expect 28 bytes)
#
# EXTERNAL AUTHENTICATE APDU (GP 2.1.1 clause 8.2):
#   CLA = 0x84
#   INS = 0x82
#   P1  = security level (0x00, 0x01, or 0x03)
#   P2  = 0x00
#   Lc  = 0x08
#   Data= host_cryptogram[8]
#
# INITIALIZE UPDATE response (28 bytes):
#   key_diversification_data[10] + key_information[2] + card_challenge[8] + card_cryptogram[8]
#
# Session key derivation (Appendix D, Figures D-3/4/5):
#   derivation_data = host_challenge[4..8] || card_challenge[0..4] || host_challenge[0..4] || card_challenge[4..8]
#   session_S-ENC = 3DES_ECB(static_S-ENC, derivation_data)
#   session_C-MAC = 3DES_ECB(static_C-MAC, derivation_data)
#   session_DEK   = 3DES_ECB(static_DEK, derivation_data)
#
# Card cryptogram (Appendix D, Figure D-2):
#   card_cryptogram = MAC_3DES_CBC(session_S-ENC, host_challenge || card_challenge)
#   (full 3DES CBC MAC with Method 2 padding, final 8 bytes)
#
# Host cryptogram:
#   host_cryptogram = MAC_3DES_CBC(session_S-ENC, card_challenge || host_challenge)
#
# Status words:
#   90 00  mutual authentication successful
#   6A 88  referenced data not found (wrong key version/identifier)
#   69 85  conditions of use not satisfied (command not allowed in current state)

@wip
Feature: SCP01 Mutual Authentication (GP 2.1.1 Appendix D)
  As a GlobalPlatform card simulator
  I must implement the SCP01 secure channel protocol for mutual authentication
  between the host and card, deriving session keys from the static keys and
  the host/card challenges per Appendix D of GP Card Specification v2.1.1.

  Background:
    Given a GP card in SECURED state
    And the ISD is configured with static SCP01 keys:
      """
      key_version = 0x01
      S-ENC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      C-MAC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      DEK   = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      """
    And the ISD is selected

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix D clause D.1.1: INITIALIZE UPDATE command/response
  # The card returns a 28-byte response containing key diversification data,
  # key information, the card challenge, and the card cryptogram.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: INITIALIZE UPDATE with valid host challenge returns 28-byte response
    # APDU: 80 50 00 00 08 [host_challenge:8] 00
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the response data is exactly 28 bytes
    And bytes 0..9 are the key diversification data (10 bytes)
    And bytes 10..11 are the key information (2 bytes)
    And bytes 12..19 are the card challenge (8 bytes)
    And bytes 20..27 are the card cryptogram (8 bytes)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix D clause D.1.1: key information field
  # Byte 10 is the key version number, byte 11 is the SCP identifier (0x01).
  # ---------------------------------------------------------------------------

  @wip
  Scenario: INITIALIZE UPDATE response identifies SCP01
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the key information byte 11 is 0x01 (SCP01 identifier)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix D, Figure D-2: card cryptogram verification
  # The card cryptogram is the last 8 bytes of a full 3DES CBC MAC over
  # (host_challenge || card_challenge) using the session S-ENC key, with
  # an IV of all zeros and Method 2 padding (0x80 00 00 00 00 00 00 00).
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Card cryptogram matches MAC(session_S-ENC, host_challenge || card_challenge)
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And I derive session keys from static keys and the challenges per Figure D-3/4/5
    And the card cryptogram equals MAC(session_S-ENC, host_challenge || card_challenge) per Figure D-2

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.2: EXTERNAL AUTHENTICATE with correct host cryptogram
  # The host proves knowledge of the session S-ENC key by computing a MAC
  # over (card_challenge || host_challenge) and sending it as the host
  # cryptogram. The card verifies it and establishes the secure channel.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: EXTERNAL AUTHENTICATE with correct host cryptogram returns 90 00
    Given I have completed INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    And I have derived the session keys per Appendix D
    When I compute the host cryptogram as MAC(session_S-ENC, card_challenge || host_challenge)
    And I send EXTERNAL AUTHENTICATE with security level 0x00 and the host cryptogram
    Then SW is 90 00
    And an SCP01 secure channel session is established

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.2: EXTERNAL AUTHENTICATE with wrong host cryptogram
  # If the host cryptogram does not verify, the card rejects authentication.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: EXTERNAL AUTHENTICATE with wrong host cryptogram returns 6A 88
    Given I have completed INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    When I send EXTERNAL AUTHENTICATE with security level 0x00 and cryptogram [FF FF FF FF FF FF FF FF]
    Then SW is 6A 88
    And no SCP session is established

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.2, Table 8-4: Security level byte P1
  # P1=0x00: no secure messaging on subsequent commands (auth only)
  # P1=0x01: C-MAC on subsequent commands
  # P1=0x03: C-MAC and C-ENC on subsequent commands
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Security level 0x00 establishes authentication-only session
    Given I have completed INITIALIZE UPDATE successfully
    And I have computed the correct host cryptogram
    When I send EXTERNAL AUTHENTICATE with security level 0x00 and the host cryptogram
    Then SW is 90 00
    And the session security level is NO_SECURE_MESSAGING

  @wip
  Scenario: Security level 0x01 establishes C-MAC session
    Given I have completed INITIALIZE UPDATE successfully
    And I have computed the correct host cryptogram
    When I send EXTERNAL AUTHENTICATE with security level 0x01 and the host cryptogram
    Then SW is 90 00
    And the session security level is C_MAC

  @wip
  Scenario: Security level 0x03 establishes C-MAC and C-ENC session
    Given I have completed INITIALIZE UPDATE successfully
    And I have computed the correct host cryptogram
    When I send EXTERNAL AUTHENTICATE with security level 0x03 and the host cryptogram
    Then SW is 90 00
    And the session security level is C_MAC_AND_C_ENC

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.1: INITIALIZE UPDATE with wrong key version
  # If P1 specifies a key version that does not exist on the card, the card
  # must reject the command.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: INITIALIZE UPDATE with wrong key version returns 6A 88
    When I send INITIALIZE UPDATE with key version 0xFF and host challenge [01 02 03 04 05 06 07 08]
    Then SW is 6A 88
    And no SCP session is established

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8: re-authentication after an existing session
  # A new INITIALIZE UPDATE terminates the current SCP session and begins
  # a fresh authentication sequence.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Re-authentication starts a new SCP session
    Given I have established an SCP01 session with security level 0x01
    When I send INITIALIZE UPDATE with a new host challenge [AA BB CC DD EE FF 00 11]
    Then SW is 90 00
    And the previous SCP session is invalidated
    And a new card challenge and cryptogram are returned

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8: GP commands before authentication
  # Commands that require an authenticated SCP session (INSTALL, DELETE,
  # SET STATUS, etc.) must be rejected when no session is active.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: GP command before authentication returns 69 85
    When I send INSTALL [for load] without an authenticated SCP session
    Then SW is 69 85

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix D, Figures D-3/4/5: session key derivation
  # derivation_data = host_challenge[4..8] || card_challenge[0..4]
  #                   || host_challenge[0..4] || card_challenge[4..8]
  # session_key = 3DES_ECB(static_key, derivation_data)
  # Applied independently for S-ENC, C-MAC, and DEK.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Session keys derived from host_challenge XOR card_challenge per Figures D-3/4/5
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And I extract the card challenge from the response
    And the derivation data is host_challenge[4..8] || card_challenge[0..4] || host_challenge[0..4] || card_challenge[4..8]
    And session_S-ENC equals 3DES_ECB(static_S-ENC, derivation_data)
    And session_C-MAC equals 3DES_ECB(static_C-MAC, derivation_data)
    And session_DEK equals 3DES_ECB(static_DEK, derivation_data)
