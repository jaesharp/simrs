# tools/simrs-spec-tests/features/proactive.feature
#
# BDD specification for proactive UICC command encoding and state machine.
#
# Standards:
#   - ETSI TS 102 223 V18.2.0 (Card Application Toolkit)
#   - 3GPP TS 31.111 V19.3.0 (USIM Application Toolkit)

Feature: Proactive UICC Command Encoding & State Machine
  As a UICC simulator
  I need to encode proactive commands as BER-TLV and manage the FETCH cycle
  per ETSI TS 102 223 and 3GPP TS 31.111

  Background:
    Given a ProactiveState with no pending command
    And command sequence number starts at 1

  # -- BER-TLV Envelope Structure per ETSI TS 102 223 clause 6.6 --

  Scenario: Proactive command uses D0 outer tag
    When I encode a DISPLAY TEXT command with text "Hello"
    Then the first byte is 0xD0 (proactive command tag)
    And the second byte is the BER length of the inner TLVs

  Scenario: Command details TLV is always first child
    When I encode any proactive command
    Then the first inner TLV has tag 0x81 (command details)
    And it is 3 bytes: command_number, command_type, command_qualifier

  Scenario: Device identities TLV is always second child
    When I encode any proactive command
    Then the second inner TLV has tag 0x82 (device identities)
    And it is 2 bytes: source_device, destination_device
    And source_device is 0x81 (UICC)

  # -- DISPLAY TEXT (type 0x21) per ETSI TS 102 223 clause 6.4.1 --

  Scenario: Encode DISPLAY TEXT with normal priority
    When I encode DISPLAY TEXT with text "Hello" and normal priority
    Then command_type is 0x21
    And command_qualifier is 0x00 (normal priority, clear after delay)
    And destination_device is 0x02 (display)
    And the third TLV has tag 0x8D (text string)
    And text string starts with DCS byte 0x04 (GSM 8-bit) followed by "Hello"

  Scenario: Encode DISPLAY TEXT with high priority
    When I encode DISPLAY TEXT with text "Urgent" and high priority
    Then command_qualifier is 0x01 (high priority, clear after delay)
    And destination_device is 0x02 (display)

  Scenario: Encode DISPLAY TEXT with UCS2 text
    When I encode DISPLAY TEXT with UCS2 text [0x00, 0x48, 0x00, 0x69]
    Then the text string DCS byte is 0x08 (UCS2)
    And the text string data is [0x00, 0x48, 0x00, 0x69]

  Scenario: DISPLAY TEXT dry-run length matches real encoding
    When I compute encoded_len for DISPLAY TEXT "Test"
    And I encode the same command into a buffer
    Then the dry-run length equals the actual bytes written

  # -- SET UP MENU (type 0x25) per ETSI TS 102 223 clause 6.6.7 --

  Scenario: Encode SET UP MENU with title and items
    When I encode SET UP MENU with title "Main" and items:
      | id | text       |
      |  1 | Item One   |
      |  2 | Item Two   |
      |  3 | Item Three |
    Then command_type is 0x25
    And command_qualifier is 0x00
    And destination_device is 0x82 (terminal)
    And the third TLV has tag 0x85 (alpha identifier) with "Main"
    And there are 3 TLVs with tag 0x8F (item)
    And item 1 starts with byte 0x01 followed by "Item One"
    And item 2 starts with byte 0x02 followed by "Item Two"
    And item 3 starts with byte 0x03 followed by "Item Three"

  Scenario: SET UP MENU with no items returns error
    When I try to encode SET UP MENU with title "Empty" and 0 items
    Then the result is a BufferTooSmall or encoding error

  # -- LAUNCH BROWSER (type 0x15) per ETSI TS 102 223 clause 6.4.26 --

  Scenario: Encode LAUNCH BROWSER
    When I encode LAUNCH BROWSER with URL "http://example.com" and browser_id 0x00
    Then command_type is 0x15
    And command_qualifier is 0x00 (launch if not already launched)
    And destination_device is 0x82 (terminal)
    And there is a TLV with tag 0xB0 (browser identity) containing [0x00]
    And there is a TLV with tag 0xB1 (URL) containing "http://example.com"

  # -- PLAY TONE (type 0x20) per ETSI TS 102 223 clause 6.4.5 --

  Scenario: Encode PLAY TONE
    When I encode PLAY TONE with tone 0x01 and duration 5 tenths of seconds
    Then command_type is 0x20
    And command_qualifier is 0x00
    And destination_device is 0x03 (earpiece)
    And there is a TLV with tag 0x8E (tone) containing [0x01]
    And there is a TLV with tag 0x84 (duration) containing [0x02, 0x05]

  # -- SEND SHORT MESSAGE (type 0x13) per ETSI TS 102 223 clause 6.4.10 --

  Scenario: Encode SEND SHORT MESSAGE
    When I encode SEND SMS with TPDU [0x01, 0x00, 0x0B, 0x91]
    Then command_type is 0x13
    And command_qualifier is 0x00
    And destination_device is 0x83 (network)
    And there is a TLV with tag 0x8B (SMS TPDU)

  # -- ProactiveState: Queue and Status Override --

  Scenario: Queue command makes it pending
    When I queue a DISPLAY TEXT "Hello"
    Then pending_len returns the encoded command length (> 0)
    And has_pending returns true

  Scenario: Override status when command pending
    Given I have queued a DISPLAY TEXT "Hello"
    When I call override_status(0x90, 0x00)
    Then the result is (0x91, pending_len as u8)

  Scenario: Override does not affect non-9000 status
    Given I have queued a DISPLAY TEXT "Hello"
    When I call override_status(0x6A, 0x82)
    Then the result is (0x6A, 0x82) unchanged

  Scenario: Override does not affect 9000 when no command pending
    When I call override_status(0x90, 0x00)
    Then the result is (0x90, 0x00) unchanged

  # -- ProactiveState: FETCH --

  Scenario: Fetch retrieves pending command and clears it
    Given I have queued a DISPLAY TEXT "Hello"
    When I call fetch with a sufficiently sized buffer
    Then the returned bytes equal the encoded DISPLAY TEXT
    And has_pending returns false
    And pending_len returns 0

  Scenario: Fetch with no pending command returns 0 bytes
    When I call fetch with a buffer
    Then the returned length is 0

  # -- ProactiveState: Terminal Response --

  Scenario: Terminal response clears response-wait state
    Given I have queued a DISPLAY TEXT "Hello"
    And the command has been fetched
    When I call terminal_response with response data
    Then the state is ready for the next command

  # -- ProactiveState: Command Sequencing --

  Scenario: Sequential commands increment command number
    When I queue and fetch DISPLAY TEXT "First"
    And I call terminal_response
    And I queue DISPLAY TEXT "Second"
    Then the second command's command_number in the encoding is 2

  # -- Encoding Size Guarantees --

  Scenario: Encoded command fits in 256-byte buffer
    When I encode DISPLAY TEXT with a 200-byte text string
    Then encoding succeeds (proactive commands max out at ~256 bytes)

  Scenario: Encoding into too-small buffer returns error
    When I try to encode SET UP MENU with 10 items into a 32-byte buffer
    Then the result is BufferTooSmall error

  # -- Device Identity Constants --

  Scenario: Device identity values per ETSI TS 102 223 clause 8.7
    Then KEYPAD is 0x01
    And DISPLAY is 0x02
    And EARPIECE is 0x03
    And UICC is 0x81
    And TERMINAL is 0x82
    And NETWORK is 0x83
