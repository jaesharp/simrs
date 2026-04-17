Feature: BIP Channel Security

  Tests that BIP (Bearer Independent Protocol) channel state management
  correctly validates channel IDs, rejects double-open and
  close-without-open, maintains channel isolation, and respects
  TERMINAL RESPONSE failure codes.

  BIP channels (IDs 1-7) are managed via proactive UICC commands:
  the UICC queues OPEN CHANNEL / CLOSE CHANNEL, the terminal FETCHes
  the command, and responds via TERMINAL RESPONSE.

  Standards:
    ETSI TS 102 223 V18.2.0  clause 6.4.27 (OPEN CHANNEL)
    ETSI TS 102 223 V18.2.0  clause 6.4.28 (CLOSE CHANNEL)
    ETSI TS 102 223 V18.2.0  clause 8.56 (Channel Status)

  Background:
    Given the SIM is initialised with test credentials
    And the SIM is powered on
    And TERMINAL PROFILE has been sent for BIP testing

  Scenario: OPEN CHANNEL via proactive cycle opens a valid channel
    Given a proactive OPEN CHANNEL is queued for bearer 0x01
    When I FETCH the proactive command
    And I send TERMINAL RESPONSE with success for OPEN CHANNEL on channel 3
    Then BIP channel 3 is open
    And BIP channel 1 is not open

  Scenario: Channel ID 0 is rejected by direct open
    When a direct OPEN CHANNEL is attempted for channel 0
    Then the channel open is rejected

  Scenario: Channel ID 8 is rejected by direct open
    When a direct OPEN CHANNEL is attempted for channel 8
    Then the channel open is rejected

  Scenario: Double-open of the same channel is rejected
    Given BIP channel 3 has been opened via proactive cycle
    When a direct OPEN CHANNEL is attempted for channel 3
    Then the channel open is rejected
    And BIP channel 3 is still open

  Scenario: CLOSE CHANNEL on unopened channel is rejected
    When a direct CLOSE CHANNEL is attempted for channel 5
    Then the channel close is rejected

  Scenario: Channel isolation -- opening one does not affect another
    Given BIP channel 2 has been opened via proactive cycle
    When BIP channel 5 is opened via proactive cycle
    Then BIP channel 2 is open
    And BIP channel 5 is open
    And BIP channel 1 is not open
    And BIP channel 7 is not open

  Scenario: TERMINAL RESPONSE with failure does not open channel
    Given a proactive OPEN CHANNEL is queued for bearer 0x01
    When I FETCH the proactive command
    And I send TERMINAL RESPONSE with failure for OPEN CHANNEL on channel 4
    Then BIP channel 4 is not open

  Scenario: BIP channel state survives snapshot round-trip
    Given BIP channel 2 has been opened via proactive cycle
    And BIP channel 5 has been opened via proactive cycle
    When a snapshot is saved and restored
    Then BIP channel 2 is open
    And BIP channel 5 is open
    And BIP channel 1 is not open
