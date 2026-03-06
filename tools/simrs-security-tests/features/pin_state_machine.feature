# features/pin_state_machine.feature
#
# Security regression tests for the PIN/PUK state machine.
#
# Exercises vulnerability classes documented in:
#   - ETSI TS 102 221 V18.0.0 clauses 11.1.9 -- 11.1.13
#   - 3GPP TS 31.102 V17.5.0 clause 6.2
#   - SIMuraI: Exploiting SIM Card Vulnerabilities (USENIX 2024)
#   - Security Explorations research (PIN bypass techniques)
#
# Test credentials (fixed for all scenarios):
#   PIN1 reference : P2 = 0x01
#   Correct PIN    : 31 32 33 34 FF FF FF FF  (ASCII "1234" + padding)
#   Wrong PIN      : 00 00 00 00 FF FF FF FF  (invalid digits)
#   Correct PUK    : 31 32 33 34 35 36 37 38  (ASCII "12345678")
#
# APDU structure quick reference (ETSI TS 102 221 clause 10.1):
#   CLA INS P1 P2 [Lc data] [Le]
#
#   VERIFY  (INS=20): 00 20 00 <P2> 08 <8-byte-PIN>
#   CHANGE  (INS=24): 00 24 00 <P2> 10 <8-byte-old-PIN> <8-byte-new-PIN>
#   DISABLE (INS=26): 00 26 00 <P2> 08 <8-byte-PIN>
#   ENABLE  (INS=28): 00 28 00 <P2> 08 <8-byte-PIN>
#   UNBLOCK (INS=2C): 00 2C 00 <P2> 10 <8-byte-PUK> <8-byte-new-PIN>
#
# Status words used throughout:
#   90 00 : Success
#   63 CX : Wrong PIN, X retries remaining
#   67 00 : Wrong length (Lc unexpected)
#   69 83 : Authentication method blocked (PIN blocked)
#   69 84 : Referenced data not usable (PIN disabled)
#   6A 86 : Incorrect parameters P1-P2 (unknown reference)
#   6A 88 : Referenced data not found (unregistered key)

Feature: PIN/PUK State Machine Security Regression
  As a security regression test suite
  I test that the simrs UICC simulator correctly enforces all PIN/PUK
  lifecycle rules per ETSI TS 102 221 and rejects attacks documented
  in SIMuraI (USENIX 2024) and related research.

  Background:
    Given the SIM is initialised with test credentials
      """
      Ki  = 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
      K   = 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22
      OPc = 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33
      """
    And PIN1 (P2=0x01) is configured:
      """
      PIN value : 31 32 33 34 FF FF FF FF
      PUK value : 31 32 33 34 35 36 37 38
      PIN max retries : 3
      PUK max retries : 10
      PIN enabled : true
      """
    And the SIM is powered on (ATR received)


  # =========================================================================
  # 1. VERIFY PIN (INS=0x20, ETSI TS 102 221 clause 11.1.9)
  # =========================================================================

  Scenario: VERIFY with correct PIN returns 90 00 and sets verified flag
    When I verify PIN1 with "1234"
    Then the command succeeds
    And PIN1 verification flag is set for this session

  Scenario: VERIFY with wrong PIN returns 63 CX and decrements retry counter
    # First wrong attempt: 3 -> 2 retries remaining
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    And PIN1 retry counter is 2
    And PIN1 verification flag is not set
    And no other SIM state has changed

  Scenario: VERIFY with empty data (Lc=0x00) returns retry count without decrementing
    # ETSI TS 102 221 clause 11.1.9: P3=0 / no data = query retry counter.
    # Expected SW: 63 C3 (3 retries, counter unchanged).
    When I query PIN1 retry counter
    Then SW indicates 3 retries remaining
    And PIN1 retry counter is still 3
    And no SIM state has changed

  Scenario: VERIFY with wrong data length (not 8 bytes) returns 67 00
    # APDU (5-byte PIN, Lc=05): 00 20 00 01 05 31 32 33 34 FF
    When I send VERIFY PIN1 with "1234" with data truncated to 5 bytes
    Then SW indicates wrong length
    And PIN1 retry counter is still 3
    And no SIM state has changed

  Scenario: VERIFY with unregistered P2 reference returns 6A 88
    # P2=0xFF is not a registered PIN reference.
    When I send VERIFY for unregistered P2=0xFF with "1234"
    Then SW indicates reference data not found
    And no SIM state has changed

  Scenario: PIN blocks after 3 consecutive wrong VERIFY attempts
    # SIMuraI section 3.1: retry exhaustion is the gateway to PUK attack surface.
    # After three wrong attempts the retry counter reaches 0.
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    When I verify PIN1 with "0000"
    Then SW indicates 1 retry remaining
    When I verify PIN1 with "0000"
    Then SW indicates 0 retries remaining
    And PIN1 retry counter is 0
    And PIN1 is blocked

  Scenario: VERIFY on already-blocked PIN returns 69 83 without decrementing
    # Counter must not be decremented further when already 0.
    # ETSI TS 102 221 clause 11.1.9: return 69 83 if blocked.
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I verify PIN1 with "1234"
    Then the PIN is blocked
    And PIN1 retry counter is still 0
    And no SIM state has changed

  Scenario: Correct VERIFY after wrong attempts resets retry counter to maximum
    # Counter reset is critical: failure to reset creates a gradual lockout vector.
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    When I verify PIN1 with "1234"
    Then the command succeeds
    And PIN1 retry counter is 3

  Scenario Outline: VERIFY retry counter decrements correctly per attempt
    # Parameterised to confirm the 63 CX encoding at each step.
    Given PIN1 has been submitted wrong <prior_wrong> times
    When I verify PIN1 with "0000"
    Then SW is "<expected_sw>"
    And PIN1 retry counter is <remaining>

    Examples:
      | prior_wrong | expected_sw | remaining |
      | 0           | 63 C2       | 2         |
      | 1           | 63 C1       | 1         |
      | 2           | 63 C0       | 0         |


  # =========================================================================
  # 2. CHANGE REFERENCE DATA (INS=0x24, ETSI TS 102 221 clause 11.1.10)
  # =========================================================================

  Scenario: CHANGE with correct old PIN and new PIN succeeds
    When I change PIN1 from "1234" to "5678"
    Then the command succeeds
    And PIN1 retry counter is reset to 3
    And verifying PIN1 with "5678" succeeds
    And verifying PIN1 with "1234" fails with 2 retries remaining

  Scenario: CHANGE with wrong old PIN fails and decrements retry counter
    When I change PIN1 from "0000" to "5678"
    Then SW indicates 2 retries remaining
    And PIN1 retry counter is 2
    And no other SIM state has changed
    And verifying PIN1 with "1234" succeeds

  Scenario: CHANGE with wrong data length (not 16 bytes) returns 67 00
    # Lc must be exactly 0x10 (16 bytes = old PIN + new PIN).
    # APDU (Lc=08, only old PIN supplied): 00 24 00 01 08 31 32 33 34 FF FF FF FF
    When I send CHANGE PIN1 from "1234" to "5678" with data truncated to 8 bytes
    Then SW indicates wrong length
    And PIN1 retry counter is still 3
    And no SIM state has changed

  Scenario: CHANGE on blocked PIN returns 69 83
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I change PIN1 from "1234" to "5678"
    Then the PIN is blocked
    And no SIM state has changed

  Scenario: CHANGE on unregistered P2 returns 6A 88
    When I send CHANGE for unregistered P2=0xFF from "1234" to "5678"
    Then SW indicates reference data not found
    And no SIM state has changed

  Scenario: CHANGE without prior VERIFY succeeds when old PIN is correct (by spec)
    # ETSI TS 102 221 clause 11.1.10 does not require prior VERIFY.
    # Providing the correct old PIN is the authentication step.
    # This distinguishes CHANGE from commands that check the session verified flag.
    When I change PIN1 from "1234" to "5678"
    Then the command succeeds

  Scenario: CHANGE does not set the PIN verified session flag
    # Security Explorations: commands that succeed without setting verified flag
    # must not inadvertently open access to PIN-gated files.
    When I change PIN1 from "1234" to "5678"
    Then the command succeeds
    And PIN1 verification flag is not set


  # =========================================================================
  # 3. DISABLE VERIFICATION REQUIREMENT (INS=0x26, ETSI TS 102 221 clause 11.1.11)
  # =========================================================================

  Scenario: DISABLE with correct PIN succeeds and satisfies security condition
    # After DISABLE the security condition is automatically satisfied per spec.
    When I disable PIN1 with "1234"
    Then the command succeeds
    And PIN1 is disabled
    And the PIN1 security condition is satisfied without explicit VERIFY

  Scenario: DISABLE with wrong PIN fails and decrements retry counter
    When I disable PIN1 with "0000"
    Then SW indicates 2 retries remaining
    And PIN1 is still enabled
    And PIN1 retry counter is 2
    And no other SIM state has changed

  Scenario: DISABLE on already-disabled PIN returns 69 84
    Given PIN1 has been disabled with correct PIN
    When I disable PIN1 with "1234"
    Then the PIN is disabled
    And no SIM state has changed

  Scenario: DISABLE on blocked PIN returns 69 83
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I disable PIN1 with "1234"
    Then the PIN is blocked
    And no SIM state has changed

  Scenario: DISABLE with wrong data length returns 67 00
    When I send DISABLE PIN1 with "1234" with data truncated to 4 bytes
    Then SW indicates wrong length
    And no SIM state has changed

  Scenario: DISABLE on unregistered P2 returns 6A 88
    When I send DISABLE for unregistered P2=0xFF with "1234"
    Then SW indicates reference data not found
    And no SIM state has changed

  Scenario: VERIFY on a disabled PIN returns 69 84
    # ETSI TS 102 221 clause 11.1.9: if PIN is disabled, VERIFY returns 69 84.
    # SIMuraI: this confirms the disabled state is observable to the attacker.
    Given PIN1 has been disabled with correct PIN
    When I verify PIN1 with "1234"
    Then the PIN is disabled
    And PIN1 retry counter is not decremented
    And no SIM state has changed


  # =========================================================================
  # 4. ENABLE VERIFICATION REQUIREMENT (INS=0x28, ETSI TS 102 221 clause 11.1.12)
  # =========================================================================

  Scenario: ENABLE on disabled PIN with correct PIN re-enables and clears verified flag
    # After ENABLE the PIN is active but unverified; caller must VERIFY separately.
    Given PIN1 has been disabled with correct PIN
    When I enable PIN1 with "1234"
    Then the command succeeds
    And PIN1 is enabled
    And PIN1 verification flag is not set

  Scenario: ENABLE on disabled PIN with wrong PIN fails and decrements retry counter
    Given PIN1 has been disabled with correct PIN
    When I enable PIN1 with "0000"
    Then SW indicates 2 retries remaining
    And PIN1 is still disabled
    And PIN1 retry counter is 2
    And no other SIM state has changed

  Scenario: ENABLE on already-enabled PIN is a no-op and returns 90 00
    # ETSI TS 102 221 does not prohibit ENABLE when already enabled.
    # The implementation treats it as a successful no-op (90 00), not 69 84.
    # This matches the simrs implementation: PinResult::Success returned
    # when enabled == true (see simrs-pin/src/lib.rs enable()).
    When I enable PIN1 with "1234"
    Then the command succeeds
    And no SIM state has changed

  Scenario: ENABLE on blocked PIN returns 69 83
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I enable PIN1 with "1234"
    Then the PIN is blocked
    And no SIM state has changed

  Scenario: ENABLE with wrong data length returns 67 00
    Given PIN1 has been disabled with correct PIN
    When I send ENABLE PIN1 with "1234" with data truncated to 4 bytes
    Then SW indicates wrong length
    And no SIM state has changed

  Scenario: ENABLE on unregistered P2 returns 6A 88
    When I send ENABLE for unregistered P2=0xFF with "1234"
    Then SW indicates reference data not found
    And no SIM state has changed

  Scenario: VERIFY after ENABLE requires explicit re-verification
    # Confirm the re-enable -> unverified -> verify flow is complete.
    Given PIN1 has been disabled with correct PIN
    And PIN1 has been re-enabled with correct PIN
    When I verify PIN1 with "1234"
    Then the command succeeds
    And PIN1 verification flag is set for this session


  # =========================================================================
  # 5. RESET RETRY COUNTER / UNBLOCK (INS=0x2C, ETSI TS 102 221 clause 11.1.13)
  # =========================================================================

  Scenario: UNBLOCK with correct PUK and new PIN restores access
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I unblock PIN1 with PUK "12345678" new PIN "5678"
    Then the command succeeds
    And PIN1 retry counter is reset to 3
    And PIN1 is enabled
    And PIN1 verification flag is not set
    And verifying PIN1 with "5678" succeeds

  Scenario: UNBLOCK with wrong PUK decrements PUK retry counter
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I unblock PIN1 with PUK "00000000" new PIN "5678"
    Then SW indicates 9 retries remaining
    And PUK1 retry counter is 9
    And PIN1 remains blocked
    And no other SIM state has changed

  Scenario: PUK blocks after 10 wrong UNBLOCK attempts -- permanent block
    # SIMuraI section 3.2: PUK exhaustion creates an irrecoverable device.
    # After 10 wrong PUK attempts the PUK counter reaches 0 and returns 69 83.
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I unblock PIN1 with PUK "00000000" new PIN "5678" 10 times
    Then PUK1 retry counter is 0
    And the next UNBLOCK PIN1 with PUK "12345678" new PIN "5678" is blocked
    And PIN1 is permanently unrecoverable

  Scenario: UNBLOCK on non-blocked PIN resets the PIN retry counter
    # ETSI TS 102 221 does not restrict RESET RETRY COUNTER to blocked PINs only.
    # It is valid to unblock a non-blocked PIN; the counter is reset and a new
    # PIN value is installed. PUK counter is NOT reset on success.
    When I unblock PIN1 with PUK "12345678" new PIN "5678"
    Then the command succeeds
    And PIN1 retry counter is 3

  Scenario: Successful UNBLOCK does not reset the PUK retry counter
    # ETSI TS 102 221 clause 11.1.13: PUK counter is not restored on success.
    # This prevents an attacker from "healing" a partially used PUK counter.
    Given PIN1 is blocked (retry counter exhausted to 0)
    And 1 wrong PUK attempt has been made (PUK counter is 9)
    When I unblock PIN1 with PUK "12345678" new PIN "5678"
    Then the command succeeds
    And PUK1 retry counter is still 9

  Scenario: UNBLOCK with empty data (Lc=0x00) queries PUK retry count
    # Mirror of VERIFY empty-data behaviour: Lc=0 returns PUK retry count.
    When I query PUK1 retry counter
    Then SW indicates 10 retries remaining
    And PUK1 retry counter is still 10
    And no SIM state has changed

  Scenario: UNBLOCK with wrong data length (not 16 bytes) returns 67 00
    # Lc must be exactly 0x10 (PUK + new PIN).
    When I send UNBLOCK PIN1 with PUK "12345678" new PIN "5678" with data truncated to 8 bytes
    Then SW indicates wrong length
    And no SIM state has changed

  Scenario: UNBLOCK on unregistered P2 returns 6A 88
    When I send UNBLOCK for unregistered P2=0xFF with PUK "12345678" new PIN "5678"
    Then SW indicates reference data not found
    And no SIM state has changed

  Scenario Outline: UNBLOCK PUK retry counter decrements correctly per wrong attempt
    Given PIN1 is blocked (retry counter exhausted to 0)
    And <prior_wrong> wrong PUK attempts have been made
    When I unblock PIN1 with PUK "00000000" new PIN "5678"
    Then SW is "<expected_sw>"
    And PUK1 retry counter is <remaining>

    Examples:
      | prior_wrong | expected_sw | remaining |
      | 0           | 63 C9       | 9         |
      | 1           | 63 C8       | 8         |
      | 5           | 63 C4       | 4         |
      | 9           | 63 C0       | 0         |


  # =========================================================================
  # 6. POWER CYCLE / STATE PERSISTENCE
  # =========================================================================

  Scenario: PIN verification flag resets after power cycle
    # ETSI TS 102 221 clause 9.3: session state is cleared on reset.
    # SIMuraI: persisted verification flag would allow PIN bypass after power cycle.
    Given PIN1 has been verified with correct PIN
    When the SIM receives a power cycle (reset)
    Then PIN1 verification flag is not set
    And PIN1 retry counter is still 3

  Scenario: PIN retry counter persists across power cycles
    # Retry counter is non-volatile: it must survive reset or power-off.
    # An attacker cannot recover retries by power-cycling.
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    When the SIM receives a power cycle (reset)
    And I query PIN1 retry counter
    Then SW indicates 2 retries remaining
    And PIN1 retry counter is still 2

  Scenario: Blocked state persists across power cycles
    # Once blocked the PIN must remain blocked after a reset.
    # SIMuraI: power-cycle-induced counter reset was exploited in real SIMs.
    Given PIN1 is blocked (retry counter exhausted to 0)
    When the SIM receives a power cycle (reset)
    Then PIN1 retry counter is 0
    And the next VERIFY PIN1 with "1234" is blocked

  Scenario: PUK counter persists across power cycles
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I unblock PIN1 with PUK "00000000" new PIN "5678"
    Then SW indicates 9 retries remaining
    When the SIM receives a power cycle (reset)
    And I query PUK1 retry counter
    Then SW indicates 9 retries remaining
    And PUK1 retry counter is still 9


  # =========================================================================
  # 7. ATTACK SCENARIOS
  # =========================================================================

  Scenario: Rapid retry exhaustion -- drain three retries in minimal round-trips
    # SIMuraI section 3.1 / CVE-class: attacker submits wrong PINs as fast as
    # possible hoping to catch a window where state is not committed.
    # Each wrong attempt must atomically decrement the counter before responding.
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    When I verify PIN1 with "0000"
    Then SW indicates 1 retry remaining
    When I verify PIN1 with "0000"
    Then SW indicates 0 retries remaining
    And PIN1 is blocked
    And the next VERIFY PIN1 with "1234" is blocked

  Scenario: Retry counter is not reset between independent sessions without correct VERIFY
    # Verify that partial retry-counter depletion carries forward into a new
    # session (power cycle). An attacker cannot spread wrong attempts across
    # resets to avoid the lockout.
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    When the SIM receives a power cycle (reset)
    When I verify PIN1 with "0000"
    Then SW indicates 1 retry remaining
    When the SIM receives a power cycle (reset)
    When I verify PIN1 with "0000"
    Then SW indicates 0 retries remaining
    And PIN1 is blocked

  Scenario: CHANGE without prior VERIFY is accepted when old PIN is correct -- by spec
    # ETSI TS 102 221 clause 11.1.10: CHANGE REFERENCE DATA authenticates via
    # the supplied old PIN value, not via the session verification flag.
    # This is intentional: an operator may rotate PIN values without interactive
    # verification. The test confirms the simulator follows the standard.
    When I change PIN1 from "1234" to "5678"
    Then the command succeeds
    And verifying PIN1 with "5678" succeeds

  Scenario: DISABLE accepted without prior VERIFY when correct PIN is supplied
    # Like CHANGE, DISABLE authenticates via the supplied PIN value.
    # An attacker who knows the PIN can disable the verification requirement
    # without a separate VERIFY step; this is spec-compliant, not a bypass.
    When I disable PIN1 with "1234"
    Then the command succeeds
    And PIN1 is disabled

  Scenario: Wrong-PIN CHANGE attempt followed by correct VERIFY still works
    # Confirm that a failed CHANGE does not put the PIN into a broken state.
    When I change PIN1 from "0000" to "5678"
    Then SW indicates 2 retries remaining
    When I verify PIN1 with "1234"
    Then the command succeeds
    And PIN1 verification flag is set for this session
    And PIN1 retry counter is 3

  Scenario: Interleaved correct and wrong attempts do not lead to unexpected block
    # Regression: correct VERIFY must reset counter; wrong attempt after that
    # must restart from the maximum, not from a previously depleted value.
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    When I verify PIN1 with "1234"
    Then the command succeeds
    When I verify PIN1 with "0000"
    Then SW indicates 2 retries remaining
    And PIN1 retry counter is 2

  Scenario: UNBLOCK with wrong PUK followed by correct PUK still recovers the PIN
    # An attacker who makes one wrong PUK attempt cannot prevent recovery.
    # The PUK counter decrements but the correct PUK must still succeed.
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I unblock PIN1 with PUK "00000000" new PIN "5678"
    Then SW indicates 9 retries remaining
    When I unblock PIN1 with PUK "12345678" new PIN "5678"
    Then the command succeeds
    And PIN1 is enabled
    And PIN1 retry counter is 3

  Scenario: P1 != 0x00 on VERIFY is rejected with 6A 86
    # ETSI TS 102 221 clause 11.1.9: P1 must be 0x00.
    # APDU: 00 20 01 01 08 31 32 33 34 FF FF FF FF  (P1=0x01)
    When I send VERIFY PIN1 with "1234" with P1 set to 0x01
    Then SW indicates incorrect P1-P2
    And PIN1 retry counter is still 3
    And no SIM state has changed

  Scenario: P1 != 0x00 on CHANGE is rejected with 6A 86
    When I send CHANGE PIN1 from "1234" to "5678" with P1 set to 0x01
    Then SW indicates incorrect P1-P2
    And no SIM state has changed

  Scenario: P1 != 0x00 on DISABLE is rejected with 6A 86
    When I send DISABLE PIN1 with "1234" with P1 set to 0x01
    Then SW indicates incorrect P1-P2
    And PIN1 is still enabled
    And no SIM state has changed

  Scenario: P1 != 0x00 on ENABLE is rejected with 6A 86
    Given PIN1 has been disabled with correct PIN
    When I send ENABLE PIN1 with "1234" with P1 set to 0x01
    Then SW indicates incorrect P1-P2
    And PIN1 is still disabled
    And no SIM state has changed

  Scenario: P1 != 0x00 on UNBLOCK is rejected with 6A 86
    Given PIN1 is blocked (retry counter exhausted to 0)
    When I send UNBLOCK PIN1 with PUK "12345678" new PIN "5678" with P1 set to 0x01
    Then SW indicates incorrect P1-P2
    And PIN1 remains blocked
    And no SIM state has changed

  # ---------------------------------------------------------------------------
  # PIN2 independence
  # PIN2 (P2=0x81) is an independent reference data object from PIN1 (P2=0x01).
  # Blocking or verifying one must not affect the other.
  # Reference: ETSI TS 102 221 clause 9.3; 3GPP TS 31.102 clause 6.2.
  # Test credentials:
  #   PIN2 reference : P2 = 0x81
  #   Correct PIN2   : 35 36 37 38 FF FF FF FF  (ASCII "5678" + padding)
  #   Correct PUK2   : 38 37 36 35 34 33 32 31  (ASCII "87654321")
  # ---------------------------------------------------------------------------

  Scenario: PIN2 VERIFY with correct PIN returns 90 00
    When I verify PIN2 with "5678"
    Then the command succeeds

  Scenario: PIN2 VERIFY with wrong PIN decrements PIN2 retry counter
    When I verify PIN2 with "0000"
    Then SW indicates 2 retries remaining
    And PIN1 retry counter is 3

  Scenario: Blocking PIN2 does not affect PIN1
    # Exhaust PIN2 retries
    When I verify PIN2 with "0000"
    And I verify PIN2 with "0000"
    And I verify PIN2 with "0000"
    # PIN2 should now be blocked
    When I verify PIN2 with "5678"
    Then the PIN is blocked
    # PIN1 remains unaffected
    And PIN1 retry counter is 3
