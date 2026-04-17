# tests/simrs-standards-integration-validation/features/milenage.feature
#
# BDD specification for Milenage UMTS authentication algorithm set (f1-f5, f1*, f5*).
#
# Standards:
#   - ETSI TS 135 206 V19.0.0 -- Algorithm specification
#   - ETSI TS 135 208 V19.0.0 -- Test data (6 test sets)
#   - ETSI TS 133 102 V19.1.0 clause 6 -- 3GPP security architecture
#   - 3GPP TS 31.102 V19.4.0 clause 7.1.2.1 -- AUTHENTICATE response

Feature: Milenage UMTS Authentication
  The Milenage algorithm set produces MAC-A, RES, CK, IK, and AK from a
  subscriber key K, random challenge RAND, sequence number SQN, and
  authentication management field AMF, using AES-128 as the block cipher.

  Background:
    Given the Milenage algorithm with default ETSI TS 135 206 constants

  # --- ETSI TS 135 208 Test Set 1 ---

  @reference @etsi_ts_135_208
  Scenario: Test Set 1 -- f1 produces correct MAC-A
    Per ETSI TS 135 208 V19.0.0 clause 5.1.

    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    And SQN is "FF9BB4D0B607"
    And AMF is "B9B9"
    When f1 is computed
    Then MAC-A equals "4A9FFAC354DFAFB3"

  @reference @etsi_ts_135_208
  Scenario: Test Set 1 -- f1* produces correct MAC-S
    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    And SQN is "FF9BB4D0B607"
    And AMF is "B9B9"
    When f1* is computed
    Then MAC-S equals "01CFAF9EC4E871E9"

  @reference @etsi_ts_135_208
  Scenario: Test Set 1 -- f2 produces correct RES
    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    When f2 is computed
    Then RES equals "A54211D5E3BA50BF"

  @reference @etsi_ts_135_208
  Scenario: Test Set 1 -- f3 produces correct CK
    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    When f3 is computed
    Then CK equals "B40BA9A3C58B2A05BBF0D987B21BF8CB"

  @reference @etsi_ts_135_208
  Scenario: Test Set 1 -- f4 produces correct IK
    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    When f4 is computed
    Then IK equals "F769BCD751044604127672711C6D3441"

  @reference @etsi_ts_135_208
  Scenario: Test Set 1 -- f5 produces correct AK
    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    When f5 is computed
    Then AK equals "AA689C648370"

  @reference @etsi_ts_135_208
  Scenario: Test Set 1 -- f5* produces correct AK*
    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    When f5* is computed
    Then AK* equals "451E8BECA43B"

  # --- OPc derivation equivalence ---

  @opc
  Scenario: OP and pre-computed OPc produce identical results
    Per ETSI TS 135 206 V19.0.0 Annex 1: OPc = E_K[OP] XOR OP.
    Using OP with runtime OPc derivation must produce the same f2 output
    as using pre-computed OPc directly.

    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    When f2 is computed with OPc "CD63CB71954A9F4E48A5994E37A02BAF"
    And f2 is computed with OP "CDC202D5123E20F62B6D676AC72CB318"
    Then both f2 results are identical

  # --- Full authentication flow ---

  @authenticate
  Scenario: Valid AUTN authenticates successfully
    Per TS 33.102 clause 6.3.3, the USIM verifies AUTN by checking
    that XMAC-A == MAC-A and SQN is in range, then returns RES, CK, IK, Kc.

    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    And a valid AUTN constructed from SQN "FF9BB4D0B607" and AMF "B9B9"
    When authenticate is called
    Then authentication succeeds
    And RES equals "A54211D5E3BA50BF"
    And CK equals "B40BA9A3C58B2A05BBF0D987B21BF8CB"
    And IK equals "F769BCD751044604127672711C6D3441"

  @authenticate
  Scenario: Invalid MAC-A causes authentication failure
    Per TS 33.102 clause 6.3.3: if XMAC-A != MAC-A, the USIM rejects
    authentication and returns status 98 62.

    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    And AUTN is "00000000000000000000000000000000"
    When authenticate is called
    Then authentication fails with MAC failure

  # --- C3 conversion ---

  @c3
  Scenario: Kc is the C3 conversion of CK and IK
    Per TS 33.102 clause 6.8.1.2:
      Kc[i] = CK[i] XOR CK[i+8] XOR IK[i] XOR IK[i+8]  for i in 0..8

    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    And a valid AUTN constructed from SQN "FF9BB4D0B607" and AMF "B9B9"
    When authenticate is called
    Then authentication succeeds
    And Kc equals CK XOR CK[8:] XOR IK XOR IK[8:]

  # --- Parameter validation ---

  @params
  Scenario: Duplicate (ci, ri) pairs are rejected
    Per ETSI TS 135 206 V19.0.0 clause 5.3: all (ci, ri) pairs must be distinct.

    Given K is "00000000000000000000000000000000"
    And OPc is "00000000000000000000000000000000"
    And custom constants with c1=c2="00000000000000000000000000000000" and r1=r2=0
    When MilenageParams is constructed
    Then construction fails with DuplicateCiRi error

  @params
  Scenario: Default constants are always valid
    The ETSI TS 135 206 default constants have distinct (ci, ri) pairs
    by construction and must always pass validation.

    Given K is "00000000000000000000000000000000"
    And OPc is "00000000000000000000000000000000"
    When MilenageParams is constructed with defaults
    Then construction succeeds

  # --- Determinism ---

  Scenario: Same inputs always produce the same output
    Given K is "465B5CE8B199B49FAA5F0A2EE238A6BC"
    And OPc is "CD63CB71954A9F4E48A5994E37A02BAF"
    And RAND is "23553CBE9637A89D218AE64DAE47BF35"
    When f2 is computed twice
    Then both results are identical
