# tools/simrs-spec-tests/features/iso7816.feature
#
# BDD specification for ISO/IEC 7816 APDU types and parsing.
#
# Standards:
#   - ISO/IEC 7816-4:2020 clause 5
#   - ETSI TS 102 221 V18.3.0 clause 10
#   - GSM 11.11 v4.21.1 clause 9

Feature: ISO 7816 APDU Parsing
  The APDU parser accepts raw byte sequences and produces structured
  command objects with CLA classification, INS, P1, P2, data, and Le.

  # --- Command parsing cases (ISO 7816-4 clause 5.3.2) ---

  Scenario: Case 1 -- header only (4 bytes)
    When bytes "00 A4 00 00" are parsed as a command
    Then INS is "A4"
    And data is empty
    And Le is absent

  Scenario: Case 2 -- header + Le (5 bytes)
    When bytes "00 C0 00 00 1A" are parsed as a command
    Then INS is "C0"
    And data is empty
    And Le is "1A"

  Scenario: Case 3 -- header + Lc + data
    When bytes "00 A4 00 00 02 3F 00" are parsed as a command
    Then INS is "A4"
    And data is "3F 00"
    And Le is absent

  Scenario: Case 4 -- header + Lc + data + Le
    When bytes "00 A4 04 00 02 AA BB 00" are parsed as a command
    Then data is "AA BB"
    And Le is "00"

  Scenario: Too-short input is rejected
    When bytes "00 A4" are parsed as a command
    Then parsing fails with TooShort

  Scenario: Truncated data is rejected
    Per ISO 7816-4: if Lc indicates more data than present, reject.
    When bytes "00 A4 00 00 05 3F 00" are parsed as a command
    Then parsing fails with DataTruncated

  # --- CLA byte classification ---

  Scenario Outline: CLA byte routing
    When CLA byte "<CLA>" is parsed
    Then class is "<Class>"

    Examples:
      | CLA | Class          |
      | 00  | Interindustry  |
      | 01  | Interindustry  |
      | 40  | Interindustry  |
      | 60  | Interindustry  |
      | 80  | Proprietary    |
      | A0  | Proprietary    |
      | FF  | Proprietary    |

  # --- Status word encoding ---

  Scenario Outline: Status word roundtrip
    When status word SW1="<SW1>" SW2="<SW2>" is decoded
    Then it re-encodes to SW1="<SW1>" SW2="<SW2>"

    Examples:
      | SW1 | SW2 | Meaning                    |
      | 90  | 00  | Success                    |
      | 61  | 1A  | 26 bytes available         |
      | 63  | C3  | 3 PIN retries remaining    |
      | 67  | 00  | Wrong length               |
      | 6E  | 00  | Class not supported        |
      | 6D  | 00  | INS not supported          |
      | 6A  | 82  | File not found             |
      | 91  | 15  | Proactive pending (21B)    |
      | 98  | 62  | Authentication error       |
