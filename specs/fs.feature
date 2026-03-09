# specs/fs.feature
#
# BDD specification for ICC filesystem model.
#
# Standards:
#   - ETSI TS 102 221 V18.3.0 clause 8 (file system)

Feature: ICC Filesystem Model
  As a UICC simulator
  I need a hierarchical read-only filesystem with EF/DF/ADF nodes
  and selection context per ETSI TS 102 221 clause 8

  Background:
    Given a filesystem tree:
      MF (3F00)
      +-- EF.ICCID (2FE2) transparent, 10 bytes [98 10 14 80 00 00 00 00 00 F0]
      +-- EF.DIR (2F00) linear fixed, record_size=8, num_records=2
      +-- DF.TELECOM (7F10)
      |   +-- EF.ADN (6F3A) linear fixed, record_size=14, num_records=3
      +-- DF.GSM (7F20)
          +-- EF.IMSI (6F07) transparent, 9 bytes
          +-- EF.Kc (6F20) transparent, 9 bytes

    And an ADF table:
      ADF.USIM (AID=A0000000871002) root:
      +-- EF.IMSI (6F07) transparent, 9 bytes [USIM-specific content]

  # -- SELECT by FID (P1=0x00) per clause 11.1.1 --

  Scenario: Select MF resets context
    Given I am in DF.GSM with an EF selected
    When I select FID 0x3F00
    Then the current DF is MF
    And no EF is selected
    And no ADF is active

  Scenario: Select EF under MF
    When I select FID 0x2FE2
    Then the result is Ef with FID 0x2FE2
    And the current DF remains MF

  Scenario: Select DF under MF
    When I select FID 0x7F20
    Then the result is Df with FID 0x7F20
    And the current DF is DF.GSM
    And no EF is selected

  Scenario: Select EF under DF
    Given I have selected DF.GSM (0x7F20)
    When I select FID 0x6F07
    Then the result is Ef with FID 0x6F07
    And the current DF remains DF.GSM

  Scenario: Select non-existent FID returns FileNotFound
    When I select FID 0xFFFF
    Then the result is FileNotFound error

  Scenario: Select child not in current DF returns FileNotFound
    Given I am in MF
    When I select FID 0x6F07 (which is under DF.GSM, not MF)
    Then the result is FileNotFound error

  Scenario: Select 0x7FFF reselects current ADF
    Given ADF.USIM is the current ADF
    When I select FID 0x7FFF
    Then the result is Df for the ADF root

  Scenario: Select 0x7FFF with no ADF returns FileNotFound
    Given no ADF is active
    When I select FID 0x7FFF
    Then the result is FileNotFound error

  # -- SELECT by AID (P1=0x04) --

  Scenario: Select ADF by full AID
    When I select by AID [A0 00 00 00 87 10 02]
    Then the current ADF is ADF.USIM
    And the current DF is the ADF root
    And no EF is selected

  Scenario: Select ADF by partial AID prefix
    When I select by AID [A0 00 00 00 87]
    Then the current ADF is ADF.USIM

  Scenario: Select by unknown AID returns FileNotFound
    When I select by AID [FF FF FF FF]
    Then the result is FileNotFound error

  # -- READ BINARY per clause 11.1.3 --

  Scenario: Read binary from transparent EF
    Given EF.ICCID is selected
    When I read binary at offset 0, length 10
    Then I get the 10-byte ICCID content

  Scenario: Read binary partial
    Given EF.ICCID is selected
    When I read binary at offset 2, length 3
    Then I get bytes [14 80 00]

  Scenario: Read binary with no EF selected
    Given no EF is selected
    When I read binary at offset 0, length 1
    Then the result is NoEfSelected error

  Scenario: Read binary on non-transparent EF
    Given EF.DIR (linear fixed) is selected
    When I read binary at offset 0, length 1
    Then the result is NotTransparent error

  Scenario: Read binary past end of file
    Given EF.ICCID (10 bytes) is selected
    When I read binary at offset 8, length 5
    Then the result is OffsetOutOfRange error

  # -- READ RECORD per clause 11.1.5 --

  Scenario: Read record from linear fixed EF
    Given EF.ADN (record_size=14, 3 records) is selected
    When I read record 1
    Then I get the first 14-byte record

  Scenario: Read record 2
    Given EF.ADN is selected
    When I read record 2
    Then I get the second 14-byte record

  Scenario: Read record 0 (invalid) returns error
    Given EF.ADN is selected
    When I read record 0
    Then the result is RecordOutOfRange error

  Scenario: Read record beyond last returns error
    Given EF.ADN (3 records) is selected
    When I read record 4
    Then the result is RecordOutOfRange error

  Scenario: Read record on transparent EF returns error
    Given EF.ICCID (transparent) is selected
    When I read record 1
    Then the result is NotRecordBased error

  Scenario: Read record with no EF selected
    Given no EF is selected
    When I read record 1
    Then the result is NoEfSelected error

  # -- DF navigation sequences --

  Scenario: Navigate MF -> DF -> EF -> MF round-trip
    When I select FID 0x7F20 (DF.GSM)
    And I select FID 0x6F07 (EF.IMSI)
    And I select FID 0x3F00 (MF)
    Then the current DF is MF
    And no EF is selected

  Scenario: Select EF in ADF after AID selection
    When I select by AID [A0 00 00 00 87 10 02]
    And I select FID 0x6F07
    Then the current EF is the USIM EF.IMSI
    And it has different data from the GSM EF.IMSI
