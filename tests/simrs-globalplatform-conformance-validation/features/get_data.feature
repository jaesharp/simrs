# features/get_data.feature
#
# GET DATA command coverage across the full GP/ISO tag surface.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  clause 9.3 (GET DATA)
#   GlobalPlatform Card Specification v2.1.1  Table 9-37 (card data TLV)
#   GlobalPlatform Card Specification v2.3    Amd C, Table C-2 (Card Recognition)
#   ISO 7816-4 clause 5.3.7 / 5.4.3 (GET DATA / tag namespace)
#
# Command shape (CLA=80, INS=CA):
#   80 CA <P1> <P2> <Le>
#   where the 2-byte tag is P1||P2.
#
# All scenarios in this file require an authenticated SCP session,
# per GP 2.1.1 Table 9-36 (GET DATA uses the current security domain's
# selection and is authorised after the ISD is SELECTed).
#
# Tags probed here (beyond the three already covered):
#   0x0042  Issuer Identification Number (IIN)
#   0x0045  Card Image Number (CIN)
#   0x00C1  Sequence counter of the default Key Version Number
#   0x00C2  Confirmation counter
#   0x00E0  Key information template (list of installed keys)
#   0x00FF  Card data
#   0x2F00  List of applications (default selected listing)
#   0x9F70  Card production life cycle (alias of 9F7F on some cards)
#
# Status words:
#   90 00  success
#   6A 82  referenced data not found / application not found
#   6A 88  referenced data not found (ISO 7816 precise)
#   69 85  conditions of use not satisfied (no SCP session)

Feature: GET DATA tag coverage beyond the differential baseline
  As a GlobalPlatform card simulator
  I must respond to every GET DATA tag declared in the card recognition
  template with structurally-valid BER-TLV, and return a conforming
  error (6A88 or 6A82) for tags I do not implement.

  Background:
    Given a GP card in SECURED state
    And the ISD is selected
    And an authenticated SCP session

  @wip
  Scenario: GET DATA for card data (0x0066) returns non-empty TLV
    When I send GET DATA [80 CA 00 66 00]
    Then SW is 90 00
    And the response is a non-empty BER-TLV

  @wip
  Scenario: GET DATA for CPLC (0x9F7F) returns a life-cycle template
    When I send GET DATA [80 CA 9F 7F 00]
    Then SW is 90 00
    And the response begins with BER-TLV tag 9F7F

  # ---------------------------------------------------------------------------
  # Extended tag coverage. @wip until step defs land.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: GET DATA for IIN (0x0042) returns the Issuer Identification Number
    # GP 2.1.1 Table 9-37: tag 42 / length 8
    When I send GET DATA [80 CA 00 42 00]
    Then SW is 90 00
    And the response BER-TLV tag is 42
    And the response value length is 8

  @wip
  Scenario: GET DATA for CIN (0x0045) returns the Card Image Number
    # GP 2.1.1 Table 9-37: tag 45 / length 10
    When I send GET DATA [80 CA 00 45 00]
    Then SW is 90 00
    And the response BER-TLV tag is 45
    And the response value length is 10

  @wip
  Scenario: GET DATA for key information template (0x00E0) lists keys
    # GP 2.1.1 clause 9.3.3 / Table 11-16: key information template
    When I send GET DATA [80 CA 00 E0 00]
    Then SW is 90 00
    And the response BER-TLV tag is E0
    And the response enumerates each installed key (KVN, key type, length)

  @wip
  Scenario: GET DATA for sequence counter (0x00C1) returns card sequence counter
    # GP 2.1.1 clause 9.3.4: card sequence counter used in INITIALIZE UPDATE
    When I send GET DATA [80 CA 00 C1 00]
    Then SW is 90 00
    And the response is exactly 2 bytes

  @wip
  Scenario: GET DATA for confirmation counter (0x00C2) returns current value
    When I send GET DATA [80 CA 00 C2 00]
    Then SW is 90 00
    And the response is exactly 2 bytes

  @wip
  Scenario: GET DATA for card data (0x00FF) returns the full card data TLV
    # GP 2.1.1 Table 9-37: tag FF is the encapsulating card data template
    When I send GET DATA [80 CA 00 FF 00]
    Then SW is 90 00
    And the response BER-TLV starts with tag FF
    And the response contains nested TLVs: 42, 45, 66, 9F7F

  @wip
  Scenario: GET DATA with unimplemented tag returns 6A 88
    # ISO 7816-4: 6A88 = referenced data or reference data not found
    When I send GET DATA [80 CA DE AD 00]
    Then SW is 6A 88

  # ---------------------------------------------------------------------------
  # Error paths
  # ---------------------------------------------------------------------------

  @wip
  Scenario: GET DATA without an authenticated SCP session is rejected
    # GP 2.1.1 Table 9-36: authorization "Security Domain"
    Given no SCP session is active
    When I send GET DATA [80 CA 00 66 00]
    Then SW is 69 85
