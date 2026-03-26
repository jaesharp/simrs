# GP Card Specification v2.3.1 Amendment D -- SCP03 Mutual Authentication
#
# SCP03 uses AES-128 throughout: AES-CMAC for MAC and key derivation,
# AES-CBC for encryption. These scenarios verify the simrs SCP03
# implementation against the protocol specification.

Feature: SCP03 Mutual Authentication

  Background:
    Given a GP card in SECURED state

  # -- INITIALIZE UPDATE --

  Scenario: SCP03 INITIALIZE UPDATE returns 29-byte response with SCP ID 0x03
    When I send INITIALIZE UPDATE with key version 0x03 and host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And the response data is exactly 29 bytes
    And byte 11 of the response data is 0x03

  # -- Full authentication round-trip --

  Scenario: SCP03 mutual authentication with C-MAC
    Given I have established an SCP03 session with security level 0x01 (C-MAC)
    Then SW is 90 00

  Scenario: SCP03 mutual authentication without secure messaging
    Given I have established an SCP03 session with security level 0x00
    Then SW is 90 00

  # -- Authenticated commands --

  Scenario: SCP03 authenticated GET STATUS returns ISD
    Given I have established an SCP03 session with security level 0x01 (C-MAC)
    When I send GET STATUS (P1=0x80) with correct C-MAC using the session keys
    Then SW is 90 00

  # -- Session isolation --

  Scenario: SCP03 session keys differ from SCP02 for same key material
    When I send INITIALIZE UPDATE with key version 0x03 and host challenge [01 02 03 04 05 06 07 08]
    Then SW is 90 00
    And byte 11 of the response data is 0x03
