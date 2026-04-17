# tests/simrs-standards-integration-validation/features/bertlv.feature
#
# BDD specification for BER-TLV encoding and decoding.
#
# Standards:
#   - ETSI TS 101 220 V19.0.0 -- BER-TLV tag assignments
#   - ISO/IEC 8825-1 -- Basic Encoding Rules
#   - ETSI TS 102 221 V18.3.0 clause 11.1 -- FCP BER-TLV structures

Feature: BER-TLV Encoding and Decoding
  The BER-TLV codec encodes Tag-Length-Value objects into byte buffers
  and decodes them back, supporting both real writes and dry-run mode
  for size-first allocation patterns.

  # --- Encoder ---

  Scenario: Encode a single TLV with short length
    Given an encoder with a 16-byte buffer
    When TLV tag=0x80 value="00 10" is encoded
    Then the output is "80 02 00 10"
    And the encoder position is 4

  Scenario: Encode TLV with empty value
    Given an encoder with a 16-byte buffer
    When TLV tag=0x8A value="" is encoded
    Then the output is "8A 00"
    And the encoder position is 2

  Scenario: Encode overflows buffer
    Given an encoder with a 3-byte buffer
    When TLV tag=0x80 value="01 02 03" is encoded
    Then encoding fails with BufferFull

  Scenario: Dry-run counts match real write
    Given a dry-run encoder
    When TLV tag=0x62 value="01 02 03 04" is encoded
    And TLV tag=0x80 value="00 10" is encoded
    Then the dry-run byte count equals a real write of the same TLVs

  # --- BER Length Encoding ---

  Scenario Outline: BER length encoding
    Per ISO/IEC 8825-1 definite length encoding.

    When a value of <length> bytes is encoded
    Then the length field occupies <bytes> bytes

    Examples:
      | length | bytes |
      | 0      | 1     |
      | 127    | 1     |
      | 128    | 2     |
      | 255    | 2     |
      | 256    | 3     |

  # --- Decoder ---

  Scenario: Decode a single TLV
    Given input bytes "80 02 00 10"
    When the input is decoded
    Then one TLV object is returned with tag=0x80 value="00 10"

  Scenario: Decode nested FCP template
    Per ETSI TS 102 221 clause 11.1.1.3: FCP is tag 0x62 containing inner TLVs.

    Given input bytes "62 04 80 02 00 10"
    When the input is decoded
    Then one TLV is returned with tag=0x62
    And decoding the value yields tag=0x80 value="00 10"

  Scenario: Decode truncated input
    Given input bytes "80 05 01 02"
    When the input is decoded
    Then decoding fails with Truncated

  Scenario: Decode empty input
    Given input bytes ""
    When the input is decoded
    Then no TLV objects are returned

  Scenario: Decode TLV with empty value
    Given input bytes "8A 00"
    When the input is decoded
    Then one TLV is returned with tag=0x8A and empty value

  # --- Roundtrip ---

  Scenario: Encode then decode produces original data
    Given TLVs: tag=0x80 value="DE AD", tag=0x83 value="BE EF"
    When encoded then decoded
    Then the decoded tags and values match the originals
