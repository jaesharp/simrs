# features/scp_secure_messaging.feature
#
# Secure messaging tests for SCP01/SCP02 after channel establishment.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  clause 8.3 (Secure Messaging)
#   GlobalPlatform Card Specification v2.1.1  Appendix D.4 (SCP01 C-MAC/C-ENC)
#   GlobalPlatform Card Specification v2.1.1  Appendix E.4 (SCP02 C-MAC/C-ENC)
#
# C-MAC generation (clause 8.3.1):
#   1. Modify CLA byte: set bit 3 (CLA |= 0x04) to indicate secure messaging
#   2. Adjust Lc: add 8 to account for the MAC appended to the data field
#   3. MAC input: modified_CLA || INS || P1 || P2 || adjusted_Lc || original_data
#   4. Apply ISO 9797-1 Method 2 padding (0x80 then 0x00 to block boundary)
#   5. Compute full 3DES CBC MAC using session C-MAC key
#   6. Append 8-byte MAC to original data field
#
# C-ENC (clause 8.3.2):
#   1. Pad data with ISO 9797-1 Method 2 (0x80 00...)
#   2. Encrypt padded data with 3DES CBC using session S-ENC key
#   3. IV for SCP01: zero vector; IV for SCP02: derived from C-MAC ICV
#   4. Replace original data with ciphertext
#   5. Then compute C-MAC over (modified header || encrypted data)
#
# PUT KEY DEK encryption (clause 8.3.3):
#   Key data in PUT KEY is encrypted with the session DEK key (3DES ECB).
#   The key check value (KCV) is the first 3 bytes of 3DES_ECB(new_key, 0x00[8]).
#
# Status words:
#   90 00  command processed successfully
#   69 88  incorrect secure messaging data object (wrong C-MAC)
#   69 87  expected secure messaging data object missing (no C-MAC when required)

Feature: SCP Secure Messaging (GP 2.1.1 clause 8.3)
  As a GlobalPlatform card simulator
  I must correctly process C-MAC, C-ENC, and R-MAC secure messaging after
  an SCP session has been established, rejecting commands with incorrect
  or missing MACs and properly encrypting/decrypting data fields.

  Background:
    Given a GP card in SECURED state
    And the ISD is configured with static SCP02 keys:
      """
      key_version = 0x01
      S-ENC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      C-MAC = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      DEK   = [40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F]
      """
    And the ISD is selected

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.1: C-MAC generation and verification
  # The card must verify the C-MAC on every command when a C-MAC session
  # is active. The MAC is computed over the modified header and data using
  # the session C-MAC key.
  # ---------------------------------------------------------------------------

  Scenario: C-MAC on GET STATUS is verified and command succeeds
    # GP 2.1.1 clause 8.3.1
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send GET STATUS (P1=0x80, P2=0x00) with correct C-MAC
    Then SW is 90 00
    And the response contains ISD registry data

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.1: C-MAC verification failure
  # If the C-MAC does not verify, the card must reject the command with
  # SW 69 88 (incorrect secure messaging data object).
  # ---------------------------------------------------------------------------

  Scenario: Wrong C-MAC on command is rejected with 69 88
    # GP 2.1.1 clause 8.3.1
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send GET STATUS (P1=0x80) with C-MAC [FF FF FF FF FF FF FF FF]
    Then SW is 69 88
    And no card state has changed

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.1: missing C-MAC when session requires it
  # When the SCP session was established with security level 0x01 or 0x03,
  # every subsequent GP command must include a C-MAC. A command sent without
  # C-MAC must be rejected with SW 69 87.
  # ---------------------------------------------------------------------------

  Scenario: Command without required C-MAC after auth returns 69 87
    # GP 2.1.1 clause 8.3.1
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send GET STATUS (P1=0x80) without C-MAC (CLA=0x80 instead of 0x84)
    Then SW is 69 87

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.1: C-MAC CLA byte modification
  # The CLA byte in the MAC input must have bit 3 set (CLA |= 0x04 -> 0x84).
  # The Lc in the MAC input must include the 8-byte MAC length.
  # ---------------------------------------------------------------------------

  Scenario: C-MAC is computed over modified CLA with secure messaging bit set
    # GP 2.1.1 clause 8.3.1
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I compute C-MAC for GET STATUS with CLA modified to 0x84 and Lc increased by 8
    And I send GET STATUS with the computed C-MAC
    Then SW is 90 00

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.2: C-ENC data field encryption
  # When security level 0x03 is active, the command data is encrypted with
  # the session S-ENC key using 3DES CBC before C-MAC is computed.
  # The IV depends on the SCP variant.
  # ---------------------------------------------------------------------------

  Scenario: C-ENC encrypts command data with session S-ENC before C-MAC
    # GP 2.1.1 clause 8.3.2
    Given I have established an SCP02 session with security level 0x03 (C-MAC + C-ENC)
    When I send STORE DATA with plaintext [01 02 03 04 05 06 07 08] encrypted with session S-ENC and C-MAC appended
    Then SW is 90 00
    And the card decrypted the data correctly

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.3 / clause 9.8: PUT KEY with DEK-encrypted key data
  # Key material in PUT KEY commands is encrypted with the session DEK key
  # using 3DES ECB. The key check value (KCV) is sent alongside for
  # verification: KCV = first 3 bytes of 3DES_ECB(new_key, 0x00[8]).
  # ---------------------------------------------------------------------------

  Scenario: PUT KEY with DEK-encrypted key data is accepted
    # GP 2.1.1 clause 9.8
    Given I have established an SCP02 session with security level 0x03 (C-MAC + C-ENC)
    When I send PUT KEY with new key [50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F] encrypted with session DEK
    And the key check value matches 3DES_ECB(new_key, 0x00[8])[0..3]
    Then SW is 90 00
    And the new key is stored in the key store

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.1 / Appendix E.4.3: multiple commands with ICV chaining
  # Each command's C-MAC becomes the ICV for the next command's C-MAC
  # computation. The ICV is not reset between commands.
  # ---------------------------------------------------------------------------

  Scenario: Multiple commands chain ICV correctly
    # GP 2.1.1 Appendix E clause E.4.3
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send GET STATUS (P1=0x80) with correct C-MAC using initial ICV
    Then SW is 90 00
    When I send GET STATUS (P1=0x40) with correct C-MAC using the previous C-MAC as ICV
    Then SW is 90 00
    When I send GET STATUS (P1=0x20) with correct C-MAC using the previous C-MAC as ICV
    Then SW is 90 00

  # ---------------------------------------------------------------------------
  # GP 2.1.1 Appendix E clause E.4.4: R-MAC in response
  # When an R-MAC session is active, the response data has an 8-byte R-MAC
  # appended. The R-MAC is computed over (response_data || SW1 || SW2) using
  # the session R-MAC key.
  # ---------------------------------------------------------------------------

  Scenario: Response with R-MAC when R-MAC session is active
    # GP 2.1.1 Appendix E clause E.4.4
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    And I have started an R-MAC session via BEGIN R-MAC SESSION
    When I send GET STATUS (P1=0x80) with correct C-MAC
    Then SW is 90 00
    And the response data ends with an 8-byte R-MAC
    And the R-MAC verifies against MAC(session_R-MAC, response_data || SW1 || SW2)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3.2: C-ENC IV derivation
  # For SCP02, the IV for C-ENC is NOT the zero vector (unlike SCP01).
  # The IV is derived from the ICV that was used for the C-MAC computation
  # on the same command, encrypted with single-DES ECB using the session
  # S-ENC key (left half).
  # ---------------------------------------------------------------------------

  Scenario: C-ENC IV is derived from C-MAC ICV for SCP02
    # GP 2.1.1 clause 8.3.2 / Appendix E
    Given I have established an SCP02 session with security level 0x03 (C-MAC + C-ENC)
    When I send a command with encrypted data field
    Then the encryption IV used was derived from the C-MAC ICV, not the zero vector

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 8.3: Method 2 padding applied before MAC
  # ISO 9797-1 Method 2: append 0x80, then 0x00 bytes to reach a multiple
  # of the block size (8 bytes for 3DES). The padding must be applied to
  # the MAC input, not the transmitted data.
  # ---------------------------------------------------------------------------

  Scenario: C-MAC uses ISO 9797-1 Method 2 padding
    # GP 2.1.1 clause 8.3.1
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send a command whose header+data is not a multiple of 8 bytes
    Then the C-MAC is computed over the padded input (0x80 00... to block boundary)
    And the padding bytes are not included in the transmitted APDU data field

  # ---------------------------------------------------------------------------
  # PUT KEY algorithm coverage (GP 2.1.1 clause 9.8, GP 2.3 Amd D for AES)
  #
  # simrs-gp-keys::KeySet supports DES3-2key, DES3-3key, and AES-128/192/256.
  # Each variant carries a distinct Algorithm ID in the PUT KEY payload
  # (Table 11-13) and a distinct key-data length; these scenarios pin the
  # Algorithm ID + Lc per variant.
  # ---------------------------------------------------------------------------

  @wip
  Scenario Outline: PUT KEY installs a key of algorithm "<algo>" under KVN <kvn>
    # GP 2.1.1 clause 9.8, Amd D 7.6 (AES), Table 11-13 (algorithm IDs)
    Given I have established an SCP02 session with security level 0x03 (C-MAC + C-ENC)
    When I send PUT KEY with algorithm ID <algo_id> and key length <key_len_bytes> bytes under KVN <kvn>
    And the key check value matches <kcv_algo>(new_key, 0x00[<kcv_block>])[0..3]
    Then SW is 90 00
    And the new key is stored at version <kvn> with algorithm "<algo>"
    And a subsequent INITIALIZE UPDATE with KVN <kvn> succeeds

    Examples:
      | algo      | algo_id | kvn | key_len_bytes | kcv_algo | kcv_block |
      | DES3-2key | 80      | 02  | 16            | 3DES_ECB | 8         |
      | DES3-3key | 81      | 03  | 24            | 3DES_ECB | 8         |
      | AES-128   | 88      | 04  | 16            | AES_ECB  | 16        |
      | AES-192   | 88      | 05  | 24            | AES_ECB  | 16        |
      | AES-256   | 88      | 06  | 32            | AES_ECB  | 16        |

  @wip
  Scenario: PUT KEY with mismatched KCV is rejected
    # GP 2.1.1 clause 9.8.3: KCV is the first 3 bytes of encrypting the
    # zero block with the new key. A mismatched KCV must be rejected
    # without installing the key, to prevent silent key-install corruption.
    Given I have established an SCP02 session with security level 0x03 (C-MAC + C-ENC)
    When I send PUT KEY with algorithm ID 88 and a KCV that does NOT match AES_ECB(new_key, 0x00[16])[0..3]
    Then SW is 69 85 or 6A 80
    And the key store is unchanged

  # ---------------------------------------------------------------------------
  # SCP02 R-MAC session lifecycle (GP 2.1.1 Appendix E.4.4)
  #
  # BEGIN R-MAC SESSION (INS 0x7A) activates R-MAC appendage on responses;
  # END R-MAC SESSION (INS 0x78) stops it. Both must be rejected outside
  # an active SCP session.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: BEGIN R-MAC SESSION activates R-MAC appendage on responses
    # GP 2.1.1 Appendix E.4.4
    Given I have established an SCP02 session with security level 0x01 (C-MAC)
    When I send BEGIN R-MAC SESSION [80 7A 00 00 00]
    Then SW is 90 00
    When I send GET STATUS (P1=0x80) with correct C-MAC
    Then SW is 90 00
    And the response data ends with an 8-byte R-MAC
    And the R-MAC verifies against MAC(session_R-MAC, response_data || SW1 || SW2)

  @wip
  Scenario: END R-MAC SESSION stops appending R-MAC to responses
    # GP 2.1.1 Appendix E.4.4
    Given I have established an SCP02 session with R-MAC active
    When I send END R-MAC SESSION [80 78 00 00 00]
    Then SW is 90 00
    When I send GET STATUS (P1=0x80) with correct C-MAC
    Then SW is 90 00
    And the response data does NOT end with an R-MAC

  @wip
  Scenario: BEGIN R-MAC SESSION outside an SCP session is rejected
    Given no SCP session is active
    When I send BEGIN R-MAC SESSION [80 7A 00 00 00]
    Then SW is 69 85
