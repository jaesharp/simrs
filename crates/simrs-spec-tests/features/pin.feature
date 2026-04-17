Feature: PIN/PUK Management State Machine
  As a UICC simulator
  I need to manage PIN verification, change, enable/disable, and PUK unblock
  Per ETSI TS 102 221 V18.3.0 clauses 11.1.9 through 11.1.12

  Background:
    Given a PinManager with capacity for 5 slots
    And PIN1 (key 0x01) configured with value "1234", max 3 retries
    And PUK1 configured with value "12345678", max 10 retries
    And PIN1 is enabled

  # ── VERIFY (INS=0x20) per clause 11.1.9 ──────────────────────

  Scenario: Verify with correct PIN succeeds
    When I verify PIN1 with "1234"
    Then the result is Success
    And PIN1 is marked as verified
    And PIN1 retry counter is 3

  Scenario: Verify with wrong PIN decrements retry counter
    When I verify PIN1 with "9999"
    Then the result is WrongPin with 2 retries remaining
    And PIN1 is not verified

  Scenario: Verify wrong PIN three times blocks the PIN
    When I verify PIN1 with "9999" three times
    Then the first two results are WrongPin with 2 and 1 retries
    And the third result is WrongPin with 0 retries remaining
    And PIN1 retry counter is 0

  Scenario: Verify on already-blocked PIN returns Blocked without decrementing
    Given PIN1 is blocked (retry counter is 0)
    When I verify PIN1 with "1234"
    Then the result is Blocked
    And the retry counter remains 0

  Scenario: Verify on disabled PIN returns Disabled
    Given PIN1 is disabled
    When I verify PIN1 with "1234"
    Then the result is Disabled
    And the retry counter is not decremented

  Scenario: Successful verify resets retry counter to max
    Given PIN1 has 1 retry remaining after two wrong attempts
    When I verify PIN1 with "1234"
    Then the result is Success
    And PIN1 retry counter is reset to 3

  Scenario: Verify on unknown PIN key returns NotFound
    When I verify PinKey(0xFF) with any value
    Then the result is NotFound

  Scenario: Disabled PIN satisfies security condition automatically
    Given PIN1 is disabled
    Then is_verified for PIN1 returns true

  # ── CHANGE REFERENCE DATA (INS=0x24) per clause 11.1.10 ─────

  Scenario: Change PIN with correct old PIN succeeds
    When I change PIN1 from "1234" to "5678"
    Then the result is Success
    And verifying PIN1 with "5678" succeeds
    And verifying PIN1 with "1234" fails
    And PIN1 retry counter is 3

  Scenario: Change PIN with wrong old PIN fails
    When I change PIN1 from "0000" to "5678"
    Then the result is WrongPin with 2 retries remaining
    And verifying PIN1 with "1234" still succeeds

  Scenario: Change on blocked PIN returns Blocked
    Given PIN1 is blocked
    When I change PIN1 from "1234" to "5678"
    Then the result is Blocked

  Scenario: Change does not set verified flag
    When I change PIN1 from "1234" to "5678"
    Then PIN1 is not marked as verified

  # ── DISABLE VERIFICATION (INS=0x26) per clause 11.1.11 ──────

  Scenario: Disable PIN with correct PIN succeeds
    When I disable PIN1 with "1234"
    Then the result is Success
    And PIN1 is disabled
    And is_verified for PIN1 returns true

  Scenario: Disable with wrong PIN fails
    When I disable PIN1 with "0000"
    Then the result is WrongPin with 2 retries remaining
    And PIN1 is still enabled

  Scenario: Disable on already-disabled PIN returns Disabled
    Given PIN1 is disabled
    When I disable PIN1 with "1234"
    Then the result is Disabled

  Scenario: Disable on blocked PIN returns Blocked
    Given PIN1 is blocked
    When I disable PIN1 with "1234"
    Then the result is Blocked

  # ── ENABLE VERIFICATION (INS=0x28) per clause 11.1.12 ───────

  Scenario: Enable disabled PIN with correct PIN succeeds
    Given PIN1 is disabled
    When I enable PIN1 with "1234"
    Then the result is Success
    And PIN1 is enabled
    And PIN1 is not verified

  Scenario: Enable with wrong PIN fails
    Given PIN1 is disabled
    When I enable PIN1 with "0000"
    Then the result is WrongPin with 2 retries remaining
    And PIN1 is still disabled

  Scenario: Enable on blocked PIN returns Blocked
    Given PIN1 is blocked
    When I enable PIN1 with "1234"
    Then the result is Blocked

  # ── RESET RETRY COUNTER / UNBLOCK (INS=0x2C) ────────────────

  Scenario: Unblock PIN with correct PUK and new PIN succeeds
    Given PIN1 is blocked
    When I unblock PIN1 with PUK "12345678" and new PIN "5678"
    Then the result is Success
    And PIN1 is enabled
    And PIN1 retry counter is reset to 3
    And verifying PIN1 with "5678" succeeds
    And PIN1 is not verified before the verify call

  Scenario: Unblock with wrong PUK decrements PUK retry counter
    Given PIN1 is blocked
    When I unblock PIN1 with PUK "00000000" and new PIN "5678"
    Then the result is WrongPin with 9 retries remaining
    And PUK1 retry counter is 9

  Scenario: Unblock with exhausted PUK returns Blocked (permanent)
    Given PIN1 is blocked
    And PUK1 retry counter is exhausted (0)
    When I unblock PIN1 with PUK "12345678" and new PIN "5678"
    Then the result is Blocked
    And PIN1 is permanently unrecoverable

  Scenario: Successful unblock does not reset PUK retry counter
    Given PIN1 is blocked
    And PUK1 has been used once (9 retries remaining)
    When I unblock PIN1 with PUK "12345678" and new PIN "5678"
    Then the result is Success
    And PUK1 retry counter is still 9

  # ── CONFIGURATION ────────────────────────────────────────────

  Scenario: Adding duplicate PIN key is rejected
    When I add another PIN with key 0x01
    Then the result is DuplicateKey error

  Scenario: Adding PIN beyond capacity is rejected
    Given the manager is full (5 slots used)
    When I add a 6th PIN
    Then the result is SlotsFull error

  Scenario: Multiple independent PINs do not interfere
    Given PIN2 (key 0x81) is also configured with value "4321"
    When I verify PIN1 with wrong value
    Then PIN2 retry counter is unaffected
    And PIN2 is not blocked

  # ── SESSION RESET ────────────────────────────────────────────

  Scenario: Reset clears all verified flags
    Given PIN1 is verified
    When the session is reset
    Then PIN1 is not verified
    And PIN1 retry counter is unchanged
