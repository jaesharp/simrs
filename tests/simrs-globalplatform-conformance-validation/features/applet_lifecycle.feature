# features/applet_lifecycle.feature
#
# Application lifecycle state machine tests.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  clause 5.3 (Application Lifecycle)
#   GlobalPlatform Card Specification v2.1.1  Figure 5-2 (Application Life Cycle State Diagram)
#   GlobalPlatform Card Specification v2.1.1  clause 9.5 (INSTALL command)
#   GlobalPlatform Card Specification v2.1.1  clause 9.7 (SET STATUS command)
#   GlobalPlatform Card Specification v2.1.1  clause 9.3 (STORE DATA command)
#   GlobalPlatform Card Specification v2.1.1  clause 9.2 (DELETE command)
#
# Application lifecycle state bytes (clause 5.3, Figure 5-2):
#   INSTALLED         = 0x03  (installed but not yet selectable)
#   SELECTABLE        = 0x07  (installed and selectable)
#   PERSONALIZED      = 0x0F  (application-specific personalization complete)
#   Application-specific states: 0x07-0x7F with bits 0-2 set (b1=1, b2=1, b3=1)
#   LOCKED            = 0x83  (locked; previous state preserved for unlock)
#
# SET STATUS APDU (clause 9.7):
#   CLA = 0x80
#   INS = 0xF0
#   P1  = 0x40 (application/SD) or 0x60 (application and associated SDs)
#   P2  = new lifecycle state
#   Data= AID of the target application
#
# Status words:
#   90 00  command processed successfully
#   69 85  conditions of use not satisfied (invalid transition)
#   6A 88  referenced data not found (unknown AID)

Feature: Applet Lifecycle State Machine (GP 2.1.1 clause 5.3, Figure 5-2)
  As a GlobalPlatform card simulator
  I must enforce the application lifecycle state transitions defined in
  GP Card Specification v2.1.1 Figure 5-2, ensuring that applications move
  through INSTALLED -> SELECTABLE -> PERSONALIZED states correctly, support
  locking/unlocking, and enforce access control for state transitions.

  Background:
    Given a GP card in SECURED state
    And an authenticated SCP session with C-MAC
    And a test load file with AID [A0 00 00 00 62 01 01] has been loaded
    And a test module with AID [A0 00 00 00 62 01 01 01] exists in the load file

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5 / clause 5.3: INSTALL [for load] creates registry entry
  # After INSTALL [for load], the load file AID appears in the GP Registry
  # in the Loaded state.
  # ---------------------------------------------------------------------------

  Scenario: INSTALL for load creates a Loaded entry in the registry
    # GP 2.1.1 clause 9.5
    Given a load file with AID [A0 00 00 00 62 02 01] is prepared
    When I send INSTALL [for load] (P1=0x02) with Load File AID [A0 00 00 00 62 02 01] and SD AID of the ISD
    Then SW is 90 00
    And GET STATUS for load files (P1=0x20) includes AID [A0 00 00 00 62 02 01]

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5 / clause 5.3: INSTALL [for install] -> INSTALLED (0x03)
  # The instance AID is created with lifecycle state INSTALLED.
  # ---------------------------------------------------------------------------

  Scenario: INSTALL for install transitions entry to INSTALLED state
    # GP 2.1.1 clause 5.3, Figure 5-2
    When I send INSTALL [for install] (P1=0x04) with Module AID [A0 00 00 00 62 01 01 01] and Instance AID [A0 00 00 00 62 01 01 02]
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] lifecycle state is 0x03 (INSTALLED)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5 / clause 5.3: INSTALL [for make selectable] -> SELECTABLE (0x07)
  # ---------------------------------------------------------------------------

  Scenario: INSTALL for make selectable transitions to SELECTABLE state
    # GP 2.1.1 clause 5.3, Figure 5-2
    Given an application [A0 00 00 00 62 01 01 02] is in INSTALLED state (0x03)
    When I send INSTALL [for make selectable] (P1=0x08) with Instance AID [A0 00 00 00 62 01 01 02]
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] lifecycle state is 0x07 (SELECTABLE)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.3 / clause 5.3: STORE DATA -> PERSONALIZED (0x0F)
  # Application personalization via STORE DATA transitions the app to
  # PERSONALIZED once personalization is complete.
  # ---------------------------------------------------------------------------

  Scenario: Application personalization via STORE DATA transitions to PERSONALIZED
    # GP 2.1.1 clause 5.3, clause 9.3
    Given an application [A0 00 00 00 62 01 01 02] is in SELECTABLE state (0x07)
    And the application [A0 00 00 00 62 01 01 02] is selected
    When I send STORE DATA with personalization data [C9 03 01 02 03] (last block, P1 bit 8 set)
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] lifecycle state is 0x0F (PERSONALIZED)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 5.3: application-specific states
  # Applications may define states in the range 0x07-0x7F where the low 3
  # bits must be set (i.e., value & 0x07 == 0x07). These are valid states
  # that the application can transition to via SET STATUS.
  # ---------------------------------------------------------------------------

  Scenario: Application-specific state in valid range is accepted
    # GP 2.1.1 clause 5.3
    Given an application [A0 00 00 00 62 01 01 02] is in SELECTABLE state (0x07)
    When I send SET STATUS (P1=0x40) for application [A0 00 00 00 62 01 01 02] with new state 0x17
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] lifecycle state is 0x17

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.7 / clause 5.3: SET STATUS -> LOCKED (0x83)
  # Locking sets bit 7 (0x80) and preserves bit 0-1 of the previous state
  # so that unlock can restore the original state.
  # ---------------------------------------------------------------------------

  Scenario: SET STATUS LOCKED preserves previous state for unlock
    # GP 2.1.1 clause 5.3, clause 9.7
    Given an application [A0 00 00 00 62 01 01 02] is in SELECTABLE state (0x07)
    When I send SET STATUS (P1=0x40) for application [A0 00 00 00 62 01 01 02] with new state 0x83
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] lifecycle state is 0x87 (LOCKED with SELECTABLE preserved)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.7: unlock restores previous state
  # ---------------------------------------------------------------------------

  Scenario: SET STATUS unlock restores previous state
    # GP 2.1.1 clause 5.3, clause 9.7
    Given an application [A0 00 00 00 62 01 01 02] is in LOCKED state (0x87, previously SELECTABLE)
    When I send SET STATUS (P1=0x40) for application [A0 00 00 00 62 01 01 02] with new state 0x07
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] lifecycle state is 0x07 (SELECTABLE)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.2: DELETE removes application from registry
  # ---------------------------------------------------------------------------

  Scenario: DELETE removes application from registry
    # GP 2.1.1 clause 9.2
    Given an application [A0 00 00 00 62 01 01 02] is installed and selectable
    When I send DELETE for AID [A0 00 00 00 62 01 01 02]
    Then SW is 90 00
    And GET STATUS for applications (P1=0x40) does not include AID [A0 00 00 00 62 01 01 02]

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.2: DELETE with related objects
  # P2 bit 0 set means cascade delete: delete the load file and all
  # application instances associated with it.
  # ---------------------------------------------------------------------------

  Scenario: DELETE with cascade removes load file and all instances
    # GP 2.1.1 clause 9.2
    Given an application [A0 00 00 00 62 01 01 02] is installed from load file [A0 00 00 00 62 01 01]
    When I send DELETE for AID [A0 00 00 00 62 01 01] with P2=0x80 (cascade)
    Then SW is 90 00
    And GET STATUS for load files (P1=0x20) does not include AID [A0 00 00 00 62 01 01]
    And GET STATUS for applications (P1=0x40) does not include AID [A0 00 00 00 62 01 01 02]

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.2: DELETE of Security Domain with associated apps
  # An SD that has associated applications must not be deleted.
  # ---------------------------------------------------------------------------

  Scenario: DELETE of Security Domain with associated applications is rejected
    # GP 2.1.1 clause 9.2
    Given a supplementary SD [A0 00 00 00 62 03 01] exists with associated application [A0 00 00 00 62 03 02]
    When I send DELETE for AID [A0 00 00 00 62 03 01]
    Then SW is 69 85
    And the SD [A0 00 00 00 62 03 01] is still present in the registry
