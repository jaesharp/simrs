# features/get_status.feature
#
# GET STATUS command tests for querying the GP Registry.
#
# Standards:
#   GlobalPlatform Card Specification v2.1.1  clause 9.4 (GET STATUS)
#   GlobalPlatform Card Specification v2.1.1  clause 5.4 (GP Registry)
#
# GET STATUS APDU (clause 9.4):
#   CLA = 0x80
#   INS = 0xF2
#   P1  = scope:
#         0x80 = Issuer Security Domain only
#         0x40 = Applications and Supplementary Security Domains
#         0x20 = Executable Load Files
#         0x10 = Executable Load Files and their Executable Modules
#   P2  = 0x00 (first/only occurrence) or 0x01 (next occurrence)
#   Lc  = length of search criteria
#   Data= TLV search criteria:
#         Tag 4F: AID filter (empty = match all, or AID prefix to filter)
#   Le  = 0x00
#
# Response TLV structure:
#   Tag E3: GP Registry entry
#     Tag 4F: AID (5-16 bytes)
#     Tag 9F70: Lifecycle state (1 byte)
#     Tag C5: Privileges (1 byte for basic, 3 bytes for extended)
#
# Status words:
#   90 00  command processed successfully
#   69 85  conditions of use not satisfied (no authenticated SCP session)
#   6A 88  referenced data not found (no matching entries)
#   6A 86  incorrect parameters P1-P2

Feature: GET STATUS Registry Query (GP 2.1.1 clause 9.4)
  As a GlobalPlatform card simulator
  I must correctly implement the GET STATUS command to query the GP Registry,
  returning entries for the ISD, installed applications, Security Domains,
  and executable load files with proper TLV-encoded lifecycle and privilege
  information per GP Card Specification v2.1.1 clause 9.4.

  Background:
    Given a GP card in SECURED state
    And the ISD has AID [A0 00 00 01 51 00 00 00]
    And a test applet with AID [A0 00 00 00 62 01 01 02] is installed and selectable
    And a test load file with AID [A0 00 00 00 62 01 01] is loaded
    And an authenticated SCP session with C-MAC is established

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.4: GET STATUS for ISD (P1=0x80)
  # Returns the Issuer Security Domain entry with its AID, lifecycle state,
  # and privileges.
  # ---------------------------------------------------------------------------

  Scenario: GET STATUS for ISD returns ISD entry with lifecycle and privileges
    # GP 2.1.1 clause 9.4
    When I send GET STATUS [80 F2 80 00 02 4F 00 00] with C-MAC
    Then SW is 90 00
    And the response contains a GP Registry entry (tag E3)
    And the entry contains AID (tag 4F) matching [A0 00 00 01 51 00 00 00]
    And the entry contains lifecycle state (tag 9F70) reflecting SECURED
    And the entry contains privileges (tag C5) with Security Domain privilege set

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.4: GET STATUS for applications and SDs (P1=0x40)
  # Returns all installed applications and supplementary Security Domains.
  # ---------------------------------------------------------------------------

  Scenario: GET STATUS for applications returns all installed entries
    # GP 2.1.1 clause 9.4
    When I send GET STATUS [80 F2 40 00 02 4F 00 00] with C-MAC
    Then SW is 90 00
    And the response contains one or more GP Registry entries (tag E3)
    And an entry with AID [A0 00 00 00 62 01 01 02] is present with lifecycle state (tag 9F70)

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.4: GET STATUS for executable load files (P1=0x20)
  # Returns all loaded executable load files.
  # ---------------------------------------------------------------------------

  Scenario: GET STATUS for executable load files lists loaded packages
    # GP 2.1.1 clause 9.4
    When I send GET STATUS [80 F2 20 00 02 4F 00 00] with C-MAC
    Then SW is 90 00
    And the response contains a GP Registry entry (tag E3) for load file [A0 00 00 00 62 01 01]

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.4: filter by AID prefix
  # The command data TLV with tag 4F containing an AID prefix filters the
  # results to entries whose AID starts with the given prefix.
  # ---------------------------------------------------------------------------

  Scenario: GET STATUS filtered by AID prefix returns only matching entries
    # GP 2.1.1 clause 9.4
    When I send GET STATUS (P1=0x40) with AID filter [A0 00 00 00 62] with C-MAC
    Then SW is 90 00
    And every returned entry has an AID starting with [A0 00 00 00 62]
    And no entry with AID [A0 00 00 01 51 00 00 00] is returned

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.4: response TLV structure validation
  # Each entry must be wrapped in tag E3 and contain at minimum AID (4F),
  # lifecycle (9F70), and privileges (C5).
  # ---------------------------------------------------------------------------

  Scenario: GET STATUS response TLV contains required tags
    # GP 2.1.1 clause 9.4
    When I send GET STATUS [80 F2 40 00 02 4F 00 00] with C-MAC
    Then SW is 90 00
    And each GP Registry entry (tag E3) contains:
      | tag  | description          | min_length |
      | 4F   | AID                  | 5          |
      | 9F70 | Lifecycle state      | 1          |
      | C5   | Privileges           | 1          |

  # ---------------------------------------------------------------------------
  # GP 2.1.1 clause 9.4: GET STATUS requires authenticated SCP session
  # Without an active SCP session, GET STATUS must be rejected.
  # ---------------------------------------------------------------------------

  Scenario: GET STATUS without authenticated SCP session returns 69 85
    # GP 2.1.1 clause 9.4
    Given no SCP session is active
    When I send GET STATUS [80 F2 80 00 02 4F 00]
    Then SW is 69 85
