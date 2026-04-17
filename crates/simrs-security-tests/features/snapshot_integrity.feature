Feature: Snapshot Integrity Validation

  Tests that restore_state() correctly rejects snapshots with corrupted
  headers (wrong magic, wrong version, mismatched feature flags) and that
  valid snapshots round-trip correctly.

  Snapshot format header (6 bytes):
    bytes 0-3: magic "SRSS"
    byte  4:   version (currently 1)
    byte  5:   feature flags (bit 0 = GSM present, bit 1 = USIM present)

  Reference: simrs-sim internal snapshot format

  Background:
    Given the SIM is initialised with test credentials
    And the SIM is powered on

  Scenario: Valid snapshot round-trips correctly
    Given the SIM state has been snapshotted
    When the snapshot is restored into a fresh SIM
    Then the restore succeeds
    And the restored SIM processes APDUs normally

  Scenario: Snapshot with wrong magic is rejected
    Given the SIM state has been snapshotted
    When the magic bytes are corrupted to "BAAD"
    And the corrupted snapshot is restored into a fresh SIM
    Then the restore fails

  Scenario: Snapshot with wrong version is rejected
    Given the SIM state has been snapshotted
    When the version byte is changed to 0xFF
    And the corrupted snapshot is restored into a fresh SIM
    Then the restore fails

  Scenario: Snapshot with mismatched feature flags is rejected
    Given the SIM state has been snapshotted
    When the feature flags byte is changed to 0xFF
    And the corrupted snapshot is restored into a fresh SIM
    Then the restore fails

  Scenario: Truncated snapshot is rejected
    Given the SIM state has been snapshotted
    When the snapshot is truncated to 5 bytes
    And the truncated snapshot is restored into a fresh SIM
    Then the restore fails
