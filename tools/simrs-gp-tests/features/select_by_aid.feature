# features/select_by_aid.feature
#
# SELECT by AID tests for GlobalPlatform card management.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  clause 9.9 (SELECT command)
#   GlobalPlatform Card Specification v2.1.1  clause 6.3 (Application Selection)
#   GlobalPlatform Card Specification v2.1.1  clause 9.6.2.4 (Partial AID matching)
#   ISO/IEC 7816-4:2020  clause 12.2.3 (SELECT command)
#
# SELECT APDU (clause 9.9):
#   CLA = 0x00
#   INS = 0xA4
#   P1  = 0x04 (select by DF name / AID)
#   P2  = 0x00 (first or only occurrence)
#         0x02 (next occurrence)
#   Lc  = length of AID (5-16 bytes)
#   Data= AID
#   Le  = 0x00 (request FCI in response)
#
# FCI (File Control Information) response structure:
#   Tag 6F: FCI template
#     Tag 84: DF name (AID)
#     Tag A5: FCI proprietary template
#       Tag 9F65: lifecycle state (1 byte)
#       Tag 73: Security Domain management data
#
# Default ISD AID: A0 00 00 01 51 00 00
#
# Status words:
#   90 00  command processed successfully (FCI returned)
#   61 XX  response data available (XX bytes via GET RESPONSE)
#   6A 82  file not found (unknown AID)
#   69 85  conditions of use not satisfied

@wip
Feature: SELECT by AID (GP 2.1.1 clause 9.9 / 6.3)
  As a GlobalPlatform card simulator
  I must correctly handle application selection by AID, supporting full AID
  matching, partial AID (prefix) matching, occurrence iteration, and
  returning proper FCI with lifecycle information per GP 2.1.1 clause 9.9.

  Background:
    Given a GP card in SECURED state
    And the ISD has AID [A0 00 00 01 51 00 00]
    And a test applet with AID [A0 00 00 00 62 01 01 02] is installed and selectable
    And a second test applet with AID [A0 00 00 00 62 01 01 03] is installed and selectable

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.9: SELECT ISD by full AID
  # Selecting the ISD returns FCI containing the AID and lifecycle state.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SELECT ISD by full AID returns FCI with lifecycle byte
    # GP 2.1.1 clause 9.9
    When I send SELECT [00 A4 04 00 07 A0 00 00 01 51 00 00 00]
    Then SW is 90 00
    And the response contains FCI template (tag 6F)
    And the FCI contains DF name (tag 84) matching [A0 00 00 01 51 00 00]
    And the FCI contains lifecycle state reflecting the ISD's current state

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.9: SELECT installed applet by full AID
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SELECT installed applet by full AID returns FCI
    # GP 2.1.1 clause 9.9
    When I send SELECT with AID [A0 00 00 00 62 01 01 02]
    Then SW is 90 00
    And the response contains FCI template (tag 6F)
    And the FCI contains DF name (tag 84) matching [A0 00 00 00 62 01 01 02]

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.6.2.4: SELECT by partial AID (prefix match)
  # When a partial AID is provided (shorter than the full AID), the card
  # must match it as a prefix against all installed applications.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SELECT by partial AID matches first application with that prefix
    # GP 2.1.1 clause 9.6.2.4
    When I send SELECT with partial AID [A0 00 00 00 62] (P1=0x04, P2=0x00)
    Then SW is 90 00
    And the response contains FCI for the first matching application

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.6.2.4: SELECT next occurrence
  # P2=0x02 selects the next application matching the AID after the
  # currently selected one.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SELECT first then next occurrence iterates matching applications
    # GP 2.1.1 clause 9.6.2.4
    When I send SELECT with partial AID [A0 00 00 00 62] (P1=0x04, P2=0x00)
    Then SW is 90 00
    And I note the AID in the FCI response
    When I send SELECT with partial AID [A0 00 00 00 62] (P1=0x04, P2=0x02)
    Then SW is 90 00
    And the AID in the FCI response differs from the first selection

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.9: SELECT unknown AID
  # If no application matches the provided AID, the card returns 6A 82.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SELECT unknown AID returns 6A 82
    # GP 2.1.1 clause 9.9
    When I send SELECT with AID [FF FF FF FF FF FF FF]
    Then SW is 6A 82
    And no application context has changed

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 6.3: SELECT on supplementary logical channel
  # Applications can be selected on supplementary logical channels opened
  # via MANAGE CHANNEL. Each channel maintains independent selection state.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SELECT on supplementary logical channel after MANAGE CHANNEL open
    # GP 2.1.1 clause 6.3
    When I send MANAGE CHANNEL OPEN [00 70 00 00 01]
    Then SW is 90 00
    And the response contains the assigned channel number
    When I send SELECT with AID [A0 00 00 00 62 01 01 02] on the opened logical channel
    Then SW is 90 00
    And the applet is selected on the supplementary channel
    And the basic channel selection is unchanged

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 6.3: implicit selection after ATR
  # After ATR (card reset), the default selectable application is implicitly
  # selected on the basic logical channel. This is typically the ISD unless
  # a default selected application has been configured.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: Implicit selection of default selectable app after ATR
    # GP 2.1.1 clause 6.3
    When the card is reset (ATR)
    And I send GET DATA [80 CA 00 42 00] for card data on the basic channel
    Then SW is 90 00
    And the ISD is the implicitly selected application

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.9 / clause 6.3: SELECT changes current applet context
  # Selecting a new application deselects the previously selected application
  # on the same logical channel.
  # ---------------------------------------------------------------------------

  @wip
  Scenario: SELECT changes current applet context and deselects previous
    # GP 2.1.1 clause 6.3
    When I send SELECT with AID [A0 00 00 00 62 01 01 02]
    Then SW is 90 00
    When I send SELECT with AID [A0 00 00 00 62 01 01 03]
    Then SW is 90 00
    And the currently selected application is [A0 00 00 00 62 01 01 03]
    And application [A0 00 00 00 62 01 01 02] has been deselected
