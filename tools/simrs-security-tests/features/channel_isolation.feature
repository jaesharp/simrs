Feature: Logical Channel Isolation

  Tests that MANAGE CHANNEL (INS=0x70) and per-channel selection contexts
  correctly isolate file selections across logical channels 0-3.

  CLA byte bits 0-1 encode the logical channel for interindustry commands:
    0x00 = channel 0, 0x01 = channel 1, 0x02 = channel 2, 0x03 = channel 3.

  Standards:
    ETSI TS 102 221 V18.3.0  clause 8.4 (logical channels)
    ETSI TS 102 221 V18.3.0  clause 11.1.17 (MANAGE CHANNEL)
    ISO/IEC 7816-4:2020      clause 5.1.1 (CLA byte logical channel encoding)

  Background:
    Given the SIM is initialised with test credentials
    And the SIM is powered on

  Scenario: MANAGE CHANNEL opens a supplementary channel
    When I send MANAGE CHANNEL OPEN
    Then the command succeeds
    And the response data contains an allocated channel number

  Scenario: Selecting a file on channel 1 does not change channel 0 selection
    Given I have opened logical channel 1
    And EF.ICCID is selected on channel 0 with PIN1 verified
    When I send SELECT MF on channel 1
    And I send READ BINARY on channel 0 at offset 0 length 10
    Then the command succeeds
    And the response data matches the provisioned EF.ICCID content

  Scenario: Command on unopened channel is rejected
    When I send SELECT MF on channel 1
    Then the command is rejected

  Scenario: Cannot close the basic channel
    When I send MANAGE CHANNEL CLOSE for channel 0
    Then SW is 69 85 (conditions not satisfied)

  Scenario: Closing an already-closed channel is rejected
    When I send MANAGE CHANNEL CLOSE for channel 3
    Then SW indicates incorrect P1-P2
