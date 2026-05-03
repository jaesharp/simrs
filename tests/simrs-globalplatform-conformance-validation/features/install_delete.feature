# features/install_delete.feature
#
# INSTALL and DELETE command tests for application management.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  clause 9.5 (INSTALL command)
#   GlobalPlatform Card Specification v2.1.1  clause 9.2 (DELETE command)
#   GlobalPlatform Card Specification v2.1.1  clause 9.6 (LOAD command)
#   GlobalPlatform Card Specification v2.1.1  clause 5.3 (Application Lifecycle)
#
# INSTALL APDU (clause 9.5):
#   CLA = 0x80
#   INS = 0xE6
#   P1  = install type:
#         0x02 = for load
#         0x04 = for install
#         0x08 = for make selectable
#         0x0C = for install and make selectable (combined)
#   P2  = 0x00
#   Lc  = length of install data
#   Data= TLV-encoded install parameters (see clause 9.5.2)
#
# INSTALL [for load] data (clause 9.5.2.1):
#   Load File AID length || Load File AID ||
#   Security Domain AID length || Security Domain AID ||
#   Load File Data Block Hash length || Load File Data Block Hash ||
#   Load Parameters length || Load Parameters
#
# INSTALL [for install] data (clause 9.5.2.3):
#   Executable Load File AID length || Executable Load File AID ||
#   Executable Module AID length || Executable Module AID ||
#   Application AID length || Application AID ||
#   Privileges length || Privileges ||
#   Install Parameters length || Install Parameters (tag C9)
#   Install Token length || Install Token
#
# LOAD APDU (clause 9.6):
#   CLA = 0x80
#   INS = 0xE8
#   P1  = block number (0x00 for first block)
#   P2  = 0x00 (last block) or 0x01 (more blocks follow)
#   Data= DAP Block (optional) || Load File Data Block
#
# DELETE APDU (clause 9.2):
#   CLA = 0x80
#   INS = 0xE4
#   P1  = 0x00
#   P2  = 0x00 (application/load file only)
#         0x80 (cascade: load file and all related instances)
#   Data= Tag 4F || length || AID
#
# Status words:
#   90 00  command processed successfully
#   69 85  conditions of use not satisfied (no SCP session)
#   6A 80  incorrect parameters in command data (duplicate AID, etc.)
#   6A 82  referenced data not found (unknown AID)
#   6A 88  referenced data not found

Feature: INSTALL and DELETE Application Management (GP 2.1.1 clauses 9.5, 9.2)
  As a GlobalPlatform card simulator
  I must correctly process INSTALL and DELETE commands for loading executable
  load files, installing application instances, making them selectable, and
  removing them from the GP Registry per GP Card Specification v2.1.1.

  Background:
    Given a GP card in SECURED state
    And the ISD has AID [A0 00 00 01 51 00 00 00]
    And an authenticated SCP session with C-MAC is established

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5.2.1: INSTALL [for load] (P1=0x02)
  # Registers the load file AID with the GP Registry, associated with the
  # specified Security Domain. Returns 90 00 on success.
  # ---------------------------------------------------------------------------

  Scenario: INSTALL for load registers load file in registry
    # GP 2.1.1 clause 9.5
    When I send INSTALL [for load] (P1=0x02) with:
      | field             | value                         |
      | Load File AID     | A0 00 00 00 62 01 01          |
      | Security Domain   | A0 00 00 01 51 00 00 00 (ISD) |
      | Data Block Hash   | (empty)                       |
      | Load Parameters   | (empty)                       |
    Then SW is 90 00

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.6: LOAD command sequence
  # After INSTALL [for load], the LOAD command (INS=0xE8) delivers the
  # executable content in one or more blocks. P1 is the block number,
  # P2 bit 0 indicates whether more blocks follow.
  # ---------------------------------------------------------------------------

  Scenario: LOAD sequence delivers executable content in blocks
    # GP 2.1.1 clause 9.6
    Given INSTALL [for load] has been sent for load file [A0 00 00 00 62 01 01]
    When I send LOAD block 0 (P1=0x00, P2=0x01) with first data block and C-MAC
    Then SW is 90 00
    When I send LOAD block 1 (P1=0x01, P2=0x00) with final data block and C-MAC
    Then SW is 90 00
    And the load file [A0 00 00 00 62 01 01] is fully loaded

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5.2.3: INSTALL [for install] (P1=0x04)
  # Creates an application instance from a loaded module. The instance AID
  # may differ from the module AID. Privileges and install parameters are
  # provided in the command data.
  # ---------------------------------------------------------------------------

  Scenario: INSTALL for install creates application instance
    # GP 2.1.1 clause 9.5
    Given load file [A0 00 00 00 62 01 01] is loaded with module [A0 00 00 00 62 01 01 01]
    When I send INSTALL [for install] (P1=0x04) with:
      | field                  | value                         |
      | Executable Load File   | A0 00 00 00 62 01 01          |
      | Executable Module      | A0 00 00 00 62 01 01 01       |
      | Application Instance   | A0 00 00 00 62 01 01 02       |
      | Privileges             | 00                            |
      | Install Parameters     | C9 00                         |
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] is in INSTALLED state (0x03)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5.2.4: INSTALL [for make selectable] (P1=0x08)
  # Transitions an INSTALLED application to SELECTABLE state.
  # ---------------------------------------------------------------------------

  Scenario: INSTALL for make selectable transitions app to SELECTABLE
    # GP 2.1.1 clause 9.5
    Given application [A0 00 00 00 62 01 01 02] is in INSTALLED state
    When I send INSTALL [for make selectable] (P1=0x08) with Instance AID [A0 00 00 00 62 01 01 02]
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 02] is in SELECTABLE state (0x07)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5: INSTALL [for install and make selectable] (P1=0x0C)
  # Combined operation: install and make selectable in a single command.
  # The application goes directly to SELECTABLE (0x07).
  # ---------------------------------------------------------------------------

  Scenario: INSTALL for install and make selectable combined
    # GP 2.1.1 clause 9.5
    Given load file [A0 00 00 00 62 01 01] is loaded with module [A0 00 00 00 62 01 01 01]
    When I send INSTALL [for install and make selectable] (P1=0x0C) with:
      | field                  | value                         |
      | Executable Load File   | A0 00 00 00 62 01 01          |
      | Executable Module      | A0 00 00 00 62 01 01 01       |
      | Application Instance   | A0 00 00 00 62 01 01 05       |
      | Privileges             | 00                            |
      | Install Parameters     | C9 00                         |
    Then SW is 90 00
    And the application [A0 00 00 00 62 01 01 05] is in SELECTABLE state (0x07)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.2: DELETE application by AID
  # Removes a single application instance from the GP Registry.
  # ---------------------------------------------------------------------------

  Scenario: DELETE application by AID removes it from registry
    # GP 2.1.1 clause 9.2
    Given application [A0 00 00 00 62 01 01 02] is installed and selectable
    When I send DELETE [80 E4 00 00] with data [4F 08 A0 00 00 00 62 01 01 02] and C-MAC
    Then SW is 90 00
    And GET STATUS for applications does not include [A0 00 00 00 62 01 01 02]

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.2: DELETE with cascade (P2=0x80)
  # Deletes the load file and all application instances created from it.
  # ---------------------------------------------------------------------------

  Scenario: DELETE with cascade removes load file and all related instances
    # GP 2.1.1 clause 9.2
    Given load file [A0 00 00 00 62 01 01] has instances [A0 00 00 00 62 01 01 02] and [A0 00 00 00 62 01 01 03]
    When I send DELETE [80 E4 00 80] with data [4F 07 A0 00 00 00 62 01 01] and C-MAC
    Then SW is 90 00
    And GET STATUS for load files does not include [A0 00 00 00 62 01 01]
    And GET STATUS for applications does not include [A0 00 00 00 62 01 01 02]
    And GET STATUS for applications does not include [A0 00 00 00 62 01 01 03]

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.5: duplicate instance AID on INSTALL [for install]
  # If an application with the same instance AID already exists, the card
  # must reject the INSTALL command.
  # ---------------------------------------------------------------------------

  Scenario: Duplicate instance AID on INSTALL for install returns 6A 80
    # GP 2.1.1 clause 9.5
    Given application [A0 00 00 00 62 01 01 02] is already installed
    When I send INSTALL [for install] (P1=0x04) with Instance AID [A0 00 00 00 62 01 01 02]
    Then SW is 6A 80

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clauses 9.5, 9.2: commands require authenticated SCP session
  # INSTALL and DELETE are card management commands that require an
  # authenticated SCP session. Without one, they must be rejected.
  # ---------------------------------------------------------------------------

  Scenario: INSTALL without authenticated SCP session returns 69 85
    # GP 2.1.1 clause 9.5
    Given no SCP session is active
    When I send INSTALL [for load] (P1=0x02) with Load File AID [A0 00 00 00 62 01 01]
    Then SW is 69 85

  Scenario: DELETE without authenticated SCP session returns 69 85
    # GP 2.1.1 clause 9.2
    Given no SCP session is active
    When I send DELETE for AID [A0 00 00 00 62 01 01 02]
    Then SW is 69 85
