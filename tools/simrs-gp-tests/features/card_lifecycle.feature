@wip
Feature: Card Lifecycle State Machine (GP 2.1.1 clause 5.1)

  The GlobalPlatform card has five lifecycle states with defined
  transitions. The card starts in OP_READY after manufacturing.
  State bytes: OP_READY=0x01, INITIALIZED=0x07, SECURED=0x0F,
  CARD_LOCKED=0x7F, TERMINATED=0xFF.

  Reference: GP Card Specification v2.1.1, Figure 5-1

  @wip
  Scenario: Card starts in OP_READY state
    Given a GP card in OP_READY state
    When I query the card lifecycle via GET STATUS
    Then the card lifecycle byte is 0x01

  @wip
  Scenario: First INSTALL transitions card to INITIALIZED
    Given a GP card in OP_READY state
    And an authenticated SCP session
    When I send INSTALL [for install] for a test applet
    Then the card lifecycle byte is 0x07

  @wip
  Scenario: SET STATUS transitions INITIALIZED to SECURED
    Given a GP card in INITIALIZED state
    And an authenticated SCP session
    When I send SET STATUS with new state 0x0F
    Then the card lifecycle byte is 0x0F

  @wip
  Scenario: SET STATUS with Card Lock privilege locks the card
    Given a GP card in SECURED state
    And an authenticated SCP session
    When I send SET STATUS with new state 0x7F
    Then the card lifecycle byte is 0x7F
    And only the ISD is selectable

  @wip
  Scenario: Unlock from CARD_LOCKED back to SECURED
    Given a GP card in CARD_LOCKED state
    And an authenticated SCP session as ISD
    When I send SET STATUS with new state 0x0F
    Then the card lifecycle byte is 0x0F

  @wip
  Scenario: SET STATUS with Card Terminate privilege terminates
    Given a GP card in SECURED state
    And an authenticated SCP session
    When I send SET STATUS with new state 0xFF
    Then the card lifecycle byte is 0xFF

  @wip
  Scenario: TERMINATED state is irreversible
    Given a GP card in TERMINATED state
    When I attempt SET STATUS with new state 0x0F
    Then the command is rejected with SW 69 85

  @wip
  Scenario: GET DATA returns card lifecycle in TERMINATED state
    Given a GP card in TERMINATED state
    When I send GET DATA for card recognition data on basic channel
    Then the response contains the lifecycle byte 0xFF
