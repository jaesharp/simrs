# features/confinement.feature
#
# Security regression: command side-effect confinement.
#
# Tests that successful commands confine their state mutations to the minimum
# necessary set of state paths.  This is a fundamental security property: a
# command must not corrupt, leak into, or modify state outside its designated
# domain.
#
# Standards:
#   ETSI TS 102 221 V16.4.0  clause 8 (security architecture: access control)
#   ISO/IEC 7816-4:2020      clause 5 (basic organisations and operations)
#   3GPP TS 31.102 V16.8.0   clause 7.1.2 (AUTHENTICATE)
#
# Methodology:
#   Each scenario sends a single command that is designed to succeed, then
#   asserts "no other SIM state has changed" -- which verifies that every byte
#   in the full SIM state snapshot is either unchanged or belongs to a
#   reserved (expected) state path.  The reservation set is registered by the
#   When step and reflects the command's legitimate side effects.
#
# Confinement boundaries:
#
#   | Command          | Legitimate side effects                          |
#   |------------------|--------------------------------------------------|
#   | SELECT           | SelectionCtx, RspQueue (FCP queued)               |
#   | AUTHENTICATE     | Auth (SQN_HE advances), RspQueue (RES/CK/IK)     |
#   | TERMINAL PROFILE | TerminalCapability, Proactive (profile init)      |
#   | VERIFY PIN       | Pin retries, Pin verified flag                    |
#
#   Any mutation outside the designated paths indicates a confinement violation.

Feature: Command Side-Effect Confinement
  As a SIM card simulator
  I must confine the side effects of each command to its designated state paths
  so that a legitimate operation in one domain cannot corrupt or leak into another.

  Background:
    Given the SIM is initialized with test credentials
    And the SIM is powered on

  # ---------------------------------------------------------------------------
  # SELECT confinement
  # Verify that SELECT MF only mutates the selection context (current DF/EF)
  # and the response queue (FCP data pending for GET RESPONSE).
  # Auth state, PIN state, filesystem data, and proactive state must remain
  # invariant.
  # ---------------------------------------------------------------------------

  Scenario: SELECT MF confines side effects to selection context and response queue
    When I send SELECT MF
    Then the command succeeds or response data is available
    And no other SIM state has changed

  # ---------------------------------------------------------------------------
  # AUTHENTICATE confinement
  # Verify that a successful UMTS AUTHENTICATE only mutates the auth state
  # (SQN_HE advances) and the response queue (RES/CK/IK response data
  # pending for GET RESPONSE).
  # PIN state, filesystem data, selection context, and proactive state must
  # remain invariant.
  # ---------------------------------------------------------------------------

  Scenario: Successful AUTHENTICATE confines side effects to auth state and response queue
    Given ADF.USIM is selected
    When I send AUTHENTICATE with a RAND and AUTN that pass Milenage MAC verification
    Then the command succeeds or response data is available
    And no other SIM state has changed

  # ---------------------------------------------------------------------------
  # TERMINAL PROFILE confinement
  # Verify that TERMINAL PROFILE only mutates the terminal capability bitmap
  # and the proactive engine state (the profile bitmap is copied into the
  # ProactiveState to enable STK command processing).
  # Auth state, PIN state, filesystem data, and selection context must remain
  # invariant.
  # ---------------------------------------------------------------------------

  Scenario: TERMINAL PROFILE confines side effects to terminal capability and proactive state
    When I send TERMINAL PROFILE
    Then the command succeeds
    And no other SIM state has changed
