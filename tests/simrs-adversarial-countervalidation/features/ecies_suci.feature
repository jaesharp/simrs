Feature: ECIES/SUCI Security Regression

  Tests for GET IDENTITY (INS=0x78) command and SUCI on-card computation.

  Per 3GPP TS 31.102 V19.4.0 clause 7.5, the USIM computes SUCI on-card
  using ECIES encryption of the MSIN. The ME sends GET IDENTITY with
  P2=0x01 (SUCI context) and the USIM returns a SUCI TLV (tag 0xA1).

  References:
    - 3GPP TS 31.102 V19.4.0 clauses 4.4.11.8, 7.5
    - 3GPP TS 33.501 Annex C.3/C.4
    - ETSI TS 102 221 V18.3.0 clause 11.1.20

  # ------------------------------------------------------------------
  # Null scheme (protection_scheme_id = 0x00)
  # ------------------------------------------------------------------

  Scenario: GET IDENTITY with null scheme returns cleartext MSIN
    Given the SIM is initialised with SUCI service enabled
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    When I send GET IDENTITY with SUCI context
    Then SW indicates response data available
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the SUCI response starts with tag A1
    And the SUCI response uses null scheme

  # ------------------------------------------------------------------
  # Error handling
  # ------------------------------------------------------------------

  Scenario: GET IDENTITY with invalid P2 is rejected as incorrect parameters
    Given the SIM is initialised with SUCI service enabled
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    When I send GET IDENTITY with P2=0x04
    Then SW indicates incorrect P1-P2

  Scenario: GET IDENTITY with wrong P1 is rejected as incorrect parameters
    Given the SIM is initialised with SUCI service enabled
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    When I send GET IDENTITY with P1=0x01
    Then SW indicates incorrect P1-P2

  Scenario: GET IDENTITY without SUCI service is rejected as conditions not satisfied
    Given the SIM is initialised without SUCI service
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    When I send GET IDENTITY with SUCI context
    Then SW indicates conditions not satisfied

  # ------------------------------------------------------------------
  # Profile A (X25519 ECIES)
  # ------------------------------------------------------------------

  Scenario: GET IDENTITY with Profile A returns valid SUCI TLV
    Given the SIM is initialised with SUCI service enabled
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    And EF_SUCI_CALC_INFO is provisioned with Profile A
    When I send GET IDENTITY with SUCI context
    Then SW indicates response data available
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the SUCI response starts with tag A1
    And the SUCI response uses Profile A
    And the SUCI Profile A scheme output is 45 bytes

  Scenario: Consecutive GET IDENTITY calls produce different ephemeral keys
    Given the SIM is initialised with SUCI service enabled
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    And EF_SUCI_CALC_INFO is provisioned with Profile A
    When I send GET IDENTITY with SUCI context and stash the response
    And I send GET IDENTITY with SUCI context
    Then SW indicates response data available
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the SUCI ephemeral key differs from the stashed response

  # ------------------------------------------------------------------
  # IMPI context (P2=0x02, TS 31.102 clause 7.5, TS 23.003 clause 13.2)
  # ------------------------------------------------------------------

  Scenario: GET IDENTITY P2=0x02 returns valid IMPI TLV
    Given the SIM is initialised without SUCI service
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    And PIN1 is verified for SUCI testing
    When I send GET IDENTITY with IMPI context
    Then SW indicates response data available
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the IMPI response starts with tag A2
    And the IMPI contains the IMSI digits
    And the IMPI contains the IMS domain suffix

  Scenario: GET IDENTITY P2=0x02 without PIN1 is rejected
    Given the SIM is initialised without SUCI service
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    When I send GET IDENTITY with IMPI context
    Then SW indicates security not satisfied

  # ------------------------------------------------------------------
  # Home Network Domain Name context (P2=0x03, TS 31.102 clause 7.5)
  # ------------------------------------------------------------------

  Scenario: GET IDENTITY P2=0x03 returns valid domain TLV
    Given the SIM is initialised without SUCI service
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    And PIN1 is verified for SUCI testing
    When I send GET IDENTITY with domain context
    Then SW indicates response data available
    When I send GET RESPONSE with Le matching SW2
    Then the command succeeds
    And the domain response starts with tag A3
    And the domain starts with ims.mnc
    And the domain ends with 3gppnetwork.org

  Scenario: GET IDENTITY P2=0x03 without PIN1 is rejected
    Given the SIM is initialised without SUCI service
    And the SIM is powered on
    And ADF.USIM is selected for SUCI testing
    When I send GET IDENTITY with domain context
    Then SW indicates security not satisfied
