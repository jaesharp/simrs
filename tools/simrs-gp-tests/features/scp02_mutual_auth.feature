# features/scp02_mutual_auth.feature
#
# SCP02 Secure Channel Protocol mutual authentication tests.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  Appendix E (SCP02)
#   GlobalPlatform Card Specification v2.1.1  clause 8 (Secure Channel)
#
# SCP02 extends SCP01 with:
#   - A 2-byte sequence counter that increments on each INITIALIZE UPDATE
#   - Session key derivation uses the sequence counter as input
#   - Derivation constants identify which session key is being derived
#   - ICV chaining for C-MAC (ICV from previous command, not reset to zero)
#   - ICV encryption (ICV encrypted with session S-MAC before use as CBC IV)
#   - R-MAC session support via BEGIN/END R-MAC SESSION commands
#
# Session key derivation (Appendix E, Figure E-2):
#   derivation_data = derivation_constant[2] || sequence_counter[2] || 0x00[12]
#   session_key = 3DES_CBC(static_key, derivation_data) with IV = 0x00[8]
#
# Derivation constants:
#   0x0182 = S-ENC (data encryption)
#   0x0101 = C-MAC (command MAC)
#   0x0102 = R-MAC (response MAC)
#   0x0181 = DEK   (key encryption key for PUT KEY)
#
# INITIALIZE UPDATE response (28 bytes):
#   key_diversification_data[10] + key_information[2] + sequence_counter[2]
#   + card_challenge[6] + card_cryptogram[8]
#
# Status words:
#   90 00  mutual authentication successful
#   6A 88  referenced data not found (wrong key version/identifier)
#   69 85  conditions of use not satisfied

Feature: SCP02 Mutual Authentication (GP 2.1.1 Appendix E)
  As a GlobalPlatform card simulator
  I must implement the SCP02 secure channel protocol with sequence-counter-based
  session key derivation, ICV chaining, and R-MAC session support per
  Appendix E of GP Card Specification v2.1.1.

  Background:
    Given a GP card in SECURED state
    And the ISD is configured with static SCP02 keys:
      """
      key_version = 0x01
      S-ENC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      C-MAC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      DEK   = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      """
    And the card sequence counter is at initial value 0x0000
    And the ISD is selected

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E clause E.1.1: INITIALIZE UPDATE response structure
  # SCP02 response is 28 bytes but the fields differ from SCP01:
  # key_diversification[10] + key_info[2] + sequence_counter[2]
  # + card_challenge[6] + card_cryptogram[8]
  # ---------------------------------------------------------------------------

  Scenario: INITIALIZE UPDATE returns 28-byte response with sequence counter
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the response data is exactly 28 bytes
    And bytes 10..11 identify SCP02 (key info byte 11 is 0x02)
    And bytes 12..13 are the sequence counter (2 bytes)
    And bytes 14..19 are the card challenge (6 bytes)
    And bytes 20..27 are the card cryptogram (8 bytes)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E: sequence counter starts at 0x0000
  # The sequence counter is a 16-bit unsigned integer stored in non-volatile
  # memory and initialized to 0x0000 on card personalization.
  # ---------------------------------------------------------------------------

  Scenario: Sequence counter starts at 0x0000 on a fresh card
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the sequence counter in the response is 0x0000

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E: sequence counter increments on each INITIALIZE UPDATE
  # ---------------------------------------------------------------------------

  Scenario: Sequence counter increments on each INITIALIZE UPDATE
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the sequence counter in the response is 0x0000
    When I send INITIALIZE UPDATE with host challenge [AA BB CC DD EE FF 00 11]
    Then SW is 90 00
    And the sequence counter in the response is 0x0001

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E, Figure E-2: session key derivation
  # derivation_data = constant[2] || sequence_counter[2] || 0x00[12]
  # session_key = 3DES_CBC(static_key, derivation_data, IV=0x00[8])
  # ---------------------------------------------------------------------------

  Scenario: Session S-ENC derived with constant 0x0182 and sequence counter
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the session S-ENC key equals 3DES_CBC(static_S-ENC, [01 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=0x00[8])

  Scenario: Session C-MAC derived with constant 0x0101 and sequence counter
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the session C-MAC key equals 3DES_CBC(static_C-MAC, [01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=0x00[8])

  Scenario: Session R-MAC derived with constant 0x0102 and sequence counter
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the session R-MAC key equals 3DES_CBC(static_C-MAC, [01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=0x00[8])

  Scenario: Session DEK derived with constant 0x0181 and sequence counter
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the session DEK key equals 3DES_CBC(static_DEK, [01 81 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=0x00[8])

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E: card cryptogram in SCP02
  # card_cryptogram = MAC_3DES_CBC(session_S-ENC,
  #   host_challenge || sequence_counter || card_challenge)
  # ---------------------------------------------------------------------------

  Scenario: Card cryptogram computed over host_challenge || sequence_counter || card_challenge
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And I derive session S-ENC with constant 0x0182 and the sequence counter
    And the card cryptogram equals MAC(session_S-ENC, host_challenge || sequence_counter || card_challenge)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.2: EXTERNAL AUTHENTICATE completes mutual auth
  # Host cryptogram = MAC(session_S-ENC, sequence_counter || card_challenge || host_challenge)
  # ---------------------------------------------------------------------------

  Scenario: EXTERNAL AUTHENTICATE with correct SCP02 host cryptogram returns 90 00
    Given I have completed SCP02 INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    And I have derived the SCP02 session keys
    When I compute the host cryptogram as MAC(session_S-ENC, sequence_counter || card_challenge || host_challenge)
    And I send EXTERNAL AUTHENTICATE with security level 0x01 and the host cryptogram with C-MAC
    Then SW is 90 00

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E: ICV chaining
  # After EXTERNAL AUTHENTICATE, the ICV (initial chaining value) for the
  # next C-MAC is the C-MAC from the EXTERNAL AUTHENTICATE command itself.
  # Subsequent commands chain: each command's C-MAC becomes the ICV for
  # the next command. The ICV is NOT reset to zero between commands.
  # ---------------------------------------------------------------------------

  Scenario: ICV chains from EXTERNAL AUTHENTICATE C-MAC to subsequent command
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send GET STATUS (P1=0x80) with C-MAC computed using the EXTERNAL AUTHENTICATE C-MAC as ICV
    Then SW is 90 00
    And the C-MAC on GET STATUS was computed with the chained ICV

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E clause E.4.4: ICV encryption
  # Before using the chained ICV as the CBC IV, it is encrypted with the
  # single-DES ECB using the session C-MAC key (left half only).
  # This prevents a known-plaintext attack on the ICV chain.
  # ---------------------------------------------------------------------------

  Scenario: ICV is encrypted with session C-MAC before use as CBC IV
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send a GP command with C-MAC
    Then the ICV used for CBC was DES_ECB(session_C-MAC_left_half, previous_C-MAC)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E: R-MAC session
  # BEGIN R-MAC SESSION (CLA=0x84, INS=0x70) and END R-MAC SESSION
  # (CLA=0x84, INS=0x78) control response MAC generation.
  # ---------------------------------------------------------------------------

  Scenario: BEGIN R-MAC SESSION enables response MAC generation
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send BEGIN R-MAC SESSION [84 70 00 01] with C-MAC
    Then SW is 90 00
    And subsequent responses include an 8-byte R-MAC appended to the data

  Scenario: END R-MAC SESSION disables response MAC generation
    Given I have established an SCP02 session with R-MAC active
    When I send END R-MAC SESSION [84 78 00 03] with C-MAC
    Then SW is 90 00
    And subsequent responses do not include R-MAC

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E: sequence counter persists across card reset
  # The counter is stored in non-volatile memory and survives ATR/reset.
  # ---------------------------------------------------------------------------

  Scenario: Sequence counter persists across card reset
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then the sequence counter in the response is 0x0000
    When the card is reset (ATR)
    And I send INITIALIZE UPDATE with host challenge [AA BB CC DD EE FF 00 11]
    Then the sequence counter in the response is 0x0001

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E: sequence counter wraps at 0xFFFF
  # When the counter reaches 0xFFFF, the next increment wraps to 0x0000.
  # The card must continue to function after wrap-around.
  # ---------------------------------------------------------------------------

  Scenario: Sequence counter wraps from 0xFFFF to 0x0000
    Given the card sequence counter has been advanced to 0xFFFF
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then the sequence counter in the response is 0xFFFF
    When I send INITIALIZE UPDATE with host challenge [AA BB CC DD EE FF 00 11]
    Then the sequence counter in the response is 0x0000
