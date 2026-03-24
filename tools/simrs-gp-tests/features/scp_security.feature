# features/scp_security.feature
#
# Security regression tests for SCP protocols based on known attacks.
#
# These tests defend against published cryptanalytic and protocol-level attacks
# on GlobalPlatform Secure Channel Protocols. Each scenario references the
# specific paper or specification clause that describes the vulnerability.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  Appendix D (SCP01)
#   GlobalPlatform Card Specification v2.1.1  Appendix E (SCP02)
#   GlobalPlatform Card Specification v2.1.1  clause 8 (Secure Channel)
#
# Attack references:
#   Avoine & Ferreira, "Attacking GlobalPlatform SCP02-compliant Smart Cards
#     Using a Padding Oracle Attack," TCHES 2018.
#   Avoine & Ferreira, "Decrypting Without Keys," J. Cryptol. 38(9), 2025.
#   Sabt & Traore, "Cryptanalysis of GlobalPlatform Secure Channel Protocols,"
#     SSR 2016 / IACR ePrint 2017/032.
#
# Defense principle: MAC-then-decrypt ordering, uniform error responses,
#   no information leakage via status words or timing.
#
# Status words:
#   90 00  mutual authentication successful
#   69 85  conditions of use not satisfied
#   69 88  incorrect secure messaging data object
#   6A 88  referenced data not found

@wip
Feature: SCP Protocol Security Regressions (Avoine/Ferreira TCHES 2018, Sabt/Traore SSR 2016)
  As a GlobalPlatform card simulator
  I must defend against known protocol-level attacks on SCP02 and SCP01
  by ensuring uniform error responses, correct MAC-before-decrypt ordering,
  correct truncation of C-MAC values, and proper session isolation. These
  tests are regression guards against the specific attack vectors published
  in the academic literature.

  Background:
    Given a GP card in SECURED state
    And the ISD is configured with static SCP02 keys:
      """
      key_version = 0x01
      S-ENC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      C-MAC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      DEK   = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      """
    And the ISD is configured with static SCP01 keys:
      """
      key_version = 0x02
      S-ENC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      C-MAC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      DEK   = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      """
    And the card sequence counter is at initial value 0x0000
    And the ISD is selected

  # ---------------------------------------------------------------------------
  # Defense: SCP02 Padding Oracle (Avoine & Ferreira, TCHES 2018)
  #
  # SCP02 uses 3DES-CBC with null IV. If the card checks padding BEFORE
  # verifying the MAC, a distinguishable error response (different SW or
  # different timing) between "bad padding" and "bad MAC" enables adaptive
  # chosen-ciphertext plaintext recovery in 128 queries per byte.
  #
  # Mitigation: the card MUST verify MAC first. Regardless of padding
  # correctness, a bad MAC produces the same SW. All three failure modes
  # below must return identical status words.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SCP02 padding oracle defense -- uniform SW for all failure modes
    # Avoine & Ferreira, TCHES 2018, Section 4.2
    # Attack: send EXTERNAL AUTHENTICATE with crafted ciphertext and observe
    # whether "bad padding + bad MAC" vs "good padding + bad MAC" returns
    # a different SW. If it does, a padding oracle exists.
    Given I have completed SCP02 INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    And I have derived the SCP02 session keys
    When I send EXTERNAL AUTHENTICATE with valid ciphertext structure but incorrect MAC [FF FF FF FF FF FF FF FF]
    Then SW is 69 88
    When I send EXTERNAL AUTHENTICATE with invalid padding bytes and incorrect MAC [FF FF FF FF FF FF FF FF]
    Then SW is 69 88
    When I send EXTERNAL AUTHENTICATE with 8 bytes of random garbage [A3 7B 02 D9 14 E8 6C F0]
    Then SW is 69 88
    And all three EXTERNAL AUTHENTICATE responses used the same status word

  # ---------------------------------------------------------------------------
  # Defense: Uniform error responses across authentication failures
  #
  # GP Card Manager APDU oracle (Finding 4 in research): different failure
  # modes return different SWs, enabling enumeration and differential analysis.
  # Within each error CLASS, all failures must be indistinguishable.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Uniform error responses for INITIALIZE UPDATE failures
    # GP 2.1.1 clause 8.1; GP Card Manager APDU oracle analysis
    # All "key not found" failures must return the same SW regardless of which
    # key version was tried, preventing key version enumeration timing.
    When I send INITIALIZE UPDATE with key version 0x7F and host challenge [01 02 03 04 05 06 07 08]
    Then SW is 6A 88
    When I send INITIALIZE UPDATE with key version 0x30 and host challenge [01 02 03 04 05 06 07 08]
    Then SW is 6A 88
    When I send INITIALIZE UPDATE with key version 0xFF and host challenge [01 02 03 04 05 06 07 08]
    Then SW is 6A 88

  @wip
  Scenario: Uniform error responses for EXTERNAL AUTHENTICATE cryptogram failures
    # GP 2.1.1 clause 8.2; Avoine & Ferreira, J. Cryptol. 38(9), 2025
    # All cryptogram verification failures must return the same SW.
    # No differentiation between all-zeros, single-bit-flip, and random data.
    Given I have completed SCP02 INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    When I send EXTERNAL AUTHENTICATE with security level 0x01 and cryptogram [00 00 00 00 00 00 00 00]
    Then SW is 69 88
    When I have completed SCP02 INITIALIZE UPDATE with host challenge [02 03 04 05 06 07 08 09]
    And I compute the correct host cryptogram and flip bit 0 of byte 3
    And I send EXTERNAL AUTHENTICATE with security level 0x01 and the modified cryptogram
    Then SW is 69 88
    When I have completed SCP02 INITIALIZE UPDATE with host challenge [03 04 05 06 07 08 09 0A]
    And I send EXTERNAL AUTHENTICATE with security level 0x01 and cryptogram [C7 3A F1 08 5D B2 E6 49]
    Then SW is 69 88

  @wip
  Scenario: GP command before authentication returns uniform rejection
    # GP 2.1.1 clause 8; defense against state probing
    # Commands requiring authentication must all fail with the same SW,
    # regardless of which command is attempted.
    When I send INSTALL [for load] without an authenticated SCP session
    Then SW is 69 85
    When I send DELETE without an authenticated SCP session
    Then SW is 69 85
    When I send SET STATUS without an authenticated SCP session
    Then SW is 69 85
    When I send PUT KEY without an authenticated SCP session
    Then SW is 69 85

  # ---------------------------------------------------------------------------
  # Defense: C-MAC truncation correctness (Sabt & Traore, SSR 2016)
  #
  # SCP02 C-MAC is the LEFT 8 bytes of the full 16-byte 3DES CBC-MAC.
  # SCP03 C-MAC is the FIRST 8 bytes of the full 16-byte AES-CMAC.
  # Taking the wrong half passes interop tests but halves forgery resistance
  # and breaks the MAC chaining invariant.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SCP02 C-MAC is the left 8 bytes of the full 3DES CBC-MAC
    # Sabt & Traore, SSR 2016, Section 4; GP 2.1.1 Appendix E clause E.4.2
    # Known-vector test: given session C-MAC key and a known command, verify
    # that the transmitted 8-byte C-MAC equals bytes [0..7] of the full
    # 16-byte 3DES CBC-MAC, not bytes [8..15].
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    And the session C-MAC key is known from the derivation
    When I compute the full 16-byte 3DES CBC-MAC of GET STATUS (P1=0x80, P2=0x00) header
    Then the transmitted C-MAC equals bytes [0..7] of the full MAC
    And the transmitted C-MAC does NOT equal bytes [8..15] of the full MAC

  # ---------------------------------------------------------------------------
  # Defense: SCP02 session key derivation known-vector test
  #
  # GP 2.1.1 Appendix E, Figure E-2 defines the derivation:
  #   derivation_data = constant[2] || sequence_counter[2] || 0x00[12]
  #   session_key = 3DES_CBC(static_key, derivation_data, IV=0x00[8])
  #
  # With all-0x40 static keys and counter=0x0000, we can hand-compute and
  # verify the exact session key bytes.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SCP02 session key derivation with known static keys and counter 0x0000
    # GP 2.1.1 Appendix E, Figure E-2; Sabt & Traore SSR 2016 Section 3
    # Static keys = [40]*16, sequence counter = 0x0000
    # S-ENC derivation_data = [01 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
    # C-MAC derivation_data = [01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
    # R-MAC derivation_data = [01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
    # DEK   derivation_data = [01 81 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the sequence counter in the response is 0x0000
    And the session S-ENC equals 3DES_CBC([40]*16, [01 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=[00]*8)
    And the session C-MAC equals 3DES_CBC([40]*16, [01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=[00]*8)
    And the session R-MAC equals 3DES_CBC([40]*16, [01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=[00]*8)
    And the session DEK equals 3DES_CBC([40]*16, [01 81 00 00 00 00 00 00 00 00 00 00 00 00 00 00], IV=[00]*8)
    And S-ENC != C-MAC != R-MAC != DEK (all four session keys are distinct)

  # ---------------------------------------------------------------------------
  # Defense: Re-authentication invalidates previous session keys
  #
  # After a new INITIALIZE UPDATE, the old session keys must be discarded.
  # If old session keys remain valid, a MITM who captured a previous session's
  # C-MAC key can forge commands in the new session.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Re-authentication clears previous SCP01 session keys
    # GP 2.1.1 clause 8; defense against session key reuse
    Given I have established an SCP01 session with security level 0x01 (C-MAC) using key version 0x02
    And I record the current session C-MAC key as old_session_cmac
    When I send INITIALIZE UPDATE with a new host challenge [AA BB CC DD EE FF 00 11]
    Then SW is 90 00
    And the previous SCP01 session is invalidated
    When I compute a C-MAC using old_session_cmac for GET STATUS (P1=0x80)
    And I send GET STATUS with the old-session C-MAC
    Then SW is 69 88
    And the command is rejected because the old session keys are no longer valid

  # ---------------------------------------------------------------------------
  # Defense: SCP session vs snapshot and card reset behavior
  #
  # A snapshot captures the card's full state including active SCP sessions.
  # Restoring a snapshot should restore the SCP session. But a card reset
  # (ATR) must invalidate the SCP session -- the terminal must re-authenticate.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SCP session survives snapshot restore but not card reset
    # GP 2.1.1 clause 8; simrs snapshot semantics
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I save a snapshot of the card state
    And I restore the snapshot
    And I send GET STATUS (P1=0x80) with correct C-MAC using the session keys
    Then SW is 90 00
    And the SCP session is still active after snapshot restore
    When the card is reset (ATR)
    And I send GET STATUS (P1=0x80) with C-MAC computed from the old session keys
    Then SW is 69 85
    And the SCP session was invalidated by card reset

  # ---------------------------------------------------------------------------
  # Defense: Card challenge must contribute entropy (IND-CPA defense)
  #
  # Sabt & Traore (SSR 2016) showed that SCP02 with deterministic encryption
  # (null IV) fails IND-CPA. If the card also uses a static/predictable
  # challenge, session keys become deterministic and all sessions are breakable
  # from a single key recovery.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Card challenge differs between consecutive INITIALIZE UPDATE commands
    # Sabt & Traore, SSR 2016, Section 3.2; IND-CPA failure mitigation
    # Two INITIALIZE UPDATE commands with the same host challenge must return
    # different card challenges. If they return the same card challenge, the
    # session keys are identical and the protocol is trivially broken.
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And I record the card challenge from the response as challenge_1
    When I send INITIALIZE UPDATE with host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And I record the card challenge from the response as challenge_2
    And challenge_1 != challenge_2

  # ---------------------------------------------------------------------------
  # Defense: SCP02 ICV must advance between commands (replay defense)
  #
  # Sabt & Traore, SSR 2016: within a session, if the ICV does not chain,
  # an attacker can replay a previous command's C-MAC on a different command.
  # The card must reject a replayed C-MAC from a previous command.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Replayed C-MAC from a previous command is rejected
    # Sabt & Traore, SSR 2016, Section 4.1; GP 2.1.1 Appendix E clause E.4.3
    # After sending command_1 with correct C-MAC, re-sending command_1 with
    # the SAME C-MAC value must fail because the ICV has advanced.
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send GET STATUS (P1=0x80) with correct C-MAC and record the C-MAC value
    Then SW is 90 00
    When I re-send GET STATUS (P1=0x80) with the same recorded C-MAC value
    Then SW is 69 88
    And the replayed command is rejected because the ICV has advanced
