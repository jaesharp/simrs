# specs/comp128.feature
#
# BDD specification for COMP128v1 (A3/A8) GSM authentication algorithm.
#
# Standards:
#   - GSM 11.11 v4.21.1 clause 11
#   - 3GPP TS 51.011 V4.15.0 clause 11
#
# Algorithm reversed by Marc Briceno, Ian Goldberg, David Wagner (1998).

Feature: COMP128v1 GSM Authentication
  The COMP128v1 algorithm takes a 16-byte subscriber key (Ki) and a 16-byte
  random challenge (RAND) and produces a 4-byte Signed Response (SRES) and
  an 8-byte ciphering key (Kc).

  Background:
    Given the COMP128v1 algorithm is available

  # --- Output structure invariants ---

  Scenario: SRES is exactly 4 bytes
    Given Ki is "00000000000000000000000000000000"
    And RAND is "00000000000000000000000000000000"
    When COMP128v1 is computed
    Then SRES has length 4

  Scenario: Kc is exactly 8 bytes
    Given Ki is "00000000000000000000000000000000"
    And RAND is "00000000000000000000000000000000"
    When COMP128v1 is computed
    Then Kc has length 8

  Scenario: Kc byte 7 is always zero
    Per COMP128v1 output packing, the 8th byte of Kc is always 0x00.
    This means Kc has only 54 effective bits of entropy.

    Given Ki is "ABABABABABABABABABABABABABABABAB"
    And RAND is "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
    When COMP128v1 is computed
    Then Kc byte 7 equals "00"

  Scenario: Kc byte 6 bottom 2 bits are always zero
    The 6-bit packing scheme used in COMP128v1 leaves the bottom 2 bits
    of Kc byte 6 as zero.

    Given Ki is "ABABABABABABABABABABABABABABABAB"
    And RAND is "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
    When COMP128v1 is computed
    Then Kc byte 6 has bottom 2 bits clear

  # --- Determinism ---

  Scenario: Same inputs produce same outputs
    Per GSM 11.11 clause 11, the A3/A8 algorithm must be deterministic.

    Given Ki is "11111111111111111111111111111111"
    And RAND is "22222222222222222222222222222222"
    When COMP128v1 is computed twice
    Then both results are identical

  # --- Sensitivity to inputs ---

  Scenario: Different RAND produces different SRES
    A single-bit change in RAND must change the output.
    Per GSM security requirements, the algorithm must be sensitive to
    all bits of the random challenge.

    Given Ki is "11111111111111111111111111111111"
    When COMP128v1 is computed with RAND "00000000000000000000000000000000"
    And COMP128v1 is computed with RAND "00000000000000000000000000000001"
    Then the two SRES values differ

  Scenario: Different Ki produces different SRES
    Given RAND is "33333333333333333333333333333333"
    When COMP128v1 is computed with Ki "00000000000000000000000000000000"
    And COMP128v1 is computed with Ki "00000000000000000000000000000001"
    Then the two SRES values differ

  # --- Edge cases ---

  Scenario: Zero inputs do not produce zero output
    An algorithm that returns zero for zero inputs would be trivially broken.

    Given Ki is "00000000000000000000000000000000"
    And RAND is "00000000000000000000000000000000"
    When COMP128v1 is computed
    Then SRES is not "00000000"
    # Kc[7]=0x00 is expected, so we check the full Kc isn't all-zero
    And Kc is not "0000000000000000"

  Scenario: All-FF inputs do not produce all-FF output
    Given Ki is "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    And RAND is "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    When COMP128v1 is computed
    Then SRES is not "FFFFFFFF"

  # --- Cross-validation with reference ---

  @reference
  Scenario Outline: Cross-validation against reference implementation
    These vectors are produced by running the reference C implementation
    (gsm.c:gsm_algo) with the given inputs. They serve as bit-exact
    regression tests to ensure our Rust implementation matches the reference.

    Given Ki is "<Ki>"
    And RAND is "<Rand>"
    When COMP128v1 is computed
    Then SRES equals "<SRES>"
    And Kc equals "<Kc>"

    Examples: reference vectors
      | Ki                               | Rand                             | SRES     | Kc               |
      # Vector 1: reference default Ki with sequential RAND
      # | FFFFFFFFFFFFFFFFFFFFFFFFFFFF07   | 0123456789ABCDEF0123456789ABCDEF | ???????? | ???????????????? |
      # Vector 2: all-zero
      # | 00000000000000000000000000000000 | 00000000000000000000000000000000 | ???????? | ???????????????? |
      # Vector 3: all-ones
      # | FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF | FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF | ???????? | ???????????????? |

  # --- GSM RUN GSM ALGORITHM context ---

  @apdu
  Scenario: RUN GSM ALGORITHM APDU produces correct 12-byte response
    Per GSM 11.11 clause 9.2.16, the RUN GSM ALGORITHM command (INS=0x88)
    takes a 16-byte RAND and produces a 12-byte response: SRES (4) || Kc (8).

    Given a SIM with Ki "ABABABABABABABABABABABABABABABAB"
    When the terminal sends RUN GSM ALGORITHM with RAND "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
    Then the SIM responds with status "9F0C"
    And GET RESPONSE returns 12 bytes
    And the first 4 bytes are the SRES
    And the last 8 bytes are the Kc
