# tools/simrs-security-tests/features/apdu_boundary.feature
#
# Security regression tests: APDU boundary conditions and malformed input.
#
# The central invariant under test is that the simulator NEVER panics or
# crashes on any byte sequence presented as an APDU.  The acceptable
# outcomes are:
#   - Returns None (ignored) -- below the minimum 4-byte header length
#   - Returns a well-formed error SW (6E 00, 6D 00, 67 00, etc.)
#   - Returns a normal success SW (90 00, 61 XX, 9F XX)
#
# Standards:
#   ISO/IEC 7816-4:2020 clause 5 (APDU structure)
#   ETSI TS 102 221 V18.3.0 clauses 10, 11
#   GSM 11.11 v4.21.1 clause 9
#
# Research background:
#   SIMTester (SRLabs, 2013) -- automated APDU fuzzing for production SIMs
#   pyAPDUFuzzer (Meadows et al.) -- coverage-guided APDU mutation fuzzer
#   "SIMurai" USENIX Security 2024 -- SIM card attack surface analysis

Feature: APDU Boundary Conditions and Malformed Input Handling
  As a SIM card simulator
  I must handle every possible byte sequence presented as an APDU without
  panicking, crashing, or exposing undefined behaviour.
  Malformed input must be silently ignored or answered with a protocol-
  compliant error status word.

  Background:
    Given the SIM is initialised with:
      """
      Ki  = [11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11]
      K   = [22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22]
      OPc = [33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33]
      MF (3F00)
      +-- EF.ICCID (2FE2) transparent, 10 bytes
      +-- EF.DIR   (2F00) linear-fixed, record_size=32, num_records=1
      """
    And the SIM has been powered on (hle_reset called)
    And a 258-byte response buffer is allocated

  # =========================================================================
  # 1. Truncated APDUs
  #
  # ISO 7816-4 clause 5.1: the minimum valid command APDU is 4 bytes
  # (CLA INS P1 P2).  Shorter sequences are not parseable and MUST be
  # silently ignored -- the simulator returns None, not an error SW.
  # This matches the behaviour documented in the sim.feature APDU-before-
  # minimum-header scenarios.
  # =========================================================================

  Scenario: Zero-length APDU is ignored
    # An empty byte slice cannot be a command.  The simulator must return
    # None rather than panicking on an empty slice dereference.
    When I send APDU []
    Then the APDU is ignored (simulator returns None)
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: 1-byte APDU is ignored
    # Only CLA present; INS, P1, P2 are absent.
    When I send APDU [00]
    Then the APDU is ignored (simulator returns None)
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: 2-byte APDU is ignored
    # CLA + INS present; P1, P2 are absent.
    When I send APDU [00 A4]
    Then the APDU is ignored (simulator returns None)
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: 3-byte APDU is ignored
    # CLA + INS + P1 present; P2 is absent.
    # Minimum parseable header requires all four bytes.
    When I send APDU [00 A4 00]
    Then the APDU is ignored (simulator returns None)
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: 4-byte APDU (header only, Case 1) is processed
    # Exactly CLA + INS + P1 + P2 -- ISO 7816-4 Case 1 command.
    # No Lc, no Le, no data.  This is a well-formed APDU and must be
    # dispatched to the application layer, not silently ignored.
    When I send APDU [00 A4 00 00]
    Then the APDU is processed (simulator returns a status word)
    And the simulator has not panicked

  Scenario: 4-byte header-only APDU with valid GSM CLA is processed
    When I send APDU [A0 A4 00 00]
    Then the APDU is processed (simulator returns a status word)
    And the simulator has not panicked

  # =========================================================================
  # 2. Invalid CLA Byte
  #
  # ISO 7816-4 clause 5.4.1 / ETSI TS 102 221 clause 10.1.1:
  # If the CLA byte is not supported by the application, the card SHALL
  # return SW 6E 00 (class not supported).
  #
  # CLA=0x00 is the USIM/interindustry class.
  # CLA=0xA0 is the GSM class.
  # All other values outside the set the simulator knows about must be
  # rejected with 6E 00 rather than causing undefined behaviour.
  # =========================================================================

  Scenario: CLA 0xF0 is rejected with class-not-supported
    When I send APDU [F0 A4 00 00 02 3F 00]
    Then SW indicates class not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: CLA 0xFF is rejected with class-not-supported
    # 0xFF is reserved by ISO 7816-3 for PTS and must not be accepted.
    When I send APDU [FF A4 00 00 02 3F 00]
    Then SW indicates class not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: CLA 0xC0 is rejected with class-not-supported
    When I send APDU [C0 A4 00 00 02 3F 00]
    Then SW indicates class not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: CLA 0x10 is rejected with class-not-supported
    When I send APDU [10 A4 00 00 02 3F 00]
    Then SW indicates class not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: CLA 0x01 (logical channel 1) is answered without panic
    # ISO 7816-4 clause 5.4.1 permits CLA values 0x01-0x03 for logical
    # channels.  A simulator that does not support logical channels MUST
    # return 6E 00; one that does support them may process the command.
    # Either outcome is acceptable; panic is not.
    When I send APDU [01 A4 00 00 02 3F 00]
    Then the simulator has not panicked
    And the response is either SW 6E 00 or a processed result

  Scenario: CLA 0x02 (logical channel 2) is answered without panic
    When I send APDU [02 A4 00 00 02 3F 00]
    Then the simulator has not panicked
    And the response is either SW 6E 00 or a processed result

  Scenario Outline: Arbitrary CLA bytes in the reserved range do not crash
    When I send APDU [<CLA> A4 00 00 02 3F 00]
    Then the simulator has not panicked
    And the response is either SW 6E 00 or a processed result

    Examples:
      | CLA | Notes                                 |
      | 20  | Not a valid USIM or GSM class         |
      | 50  | Not a valid USIM or GSM class         |
      | 70  | Not a valid USIM or GSM class         |
      | 90  | Not a valid USIM or GSM class         |
      | B0  | Not a valid USIM or GSM class         |
      | D0  | Not a valid USIM or GSM class         |
      | E0  | Not a valid USIM or GSM class         |

  # =========================================================================
  # 3. Invalid INS Byte
  #
  # ISO 7816-4 clause 5.4.2: if the INS byte names a function not
  # supported by the application, the card SHALL return SW 6D 00
  # (instruction not supported).
  #
  # Additionally, ISO 7816-4 clause 5.4.2 note: even-numbered INS bytes
  # with no counterpart odd companion that exists are still valid to
  # attempt; the card returns 6D 00.  The simulator must never panic
  # regardless of INS value.
  # =========================================================================

  Scenario: INS 0xFF is rejected with instruction-not-supported
    When I send APDU [00 FF 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: INS 0x00 is rejected with instruction-not-supported
    # 0x00 is not assigned a function in ISO 7816-4 or ETSI TS 102 221.
    When I send APDU [00 00 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: INS 0x01 is rejected with instruction-not-supported
    When I send APDU [00 01 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: INS 0x02 is rejected with instruction-not-supported
    When I send APDU [00 02 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: INS 0x6E is rejected with instruction-not-supported
    # 0x6E would be confused with an SW1 byte; ensure no aliasing panic.
    When I send APDU [00 6E 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: INS 0x90 is rejected with instruction-not-supported
    # 0x90 would be confused with SW1=90 (success); ensure no aliasing.
    When I send APDU [00 90 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

  Scenario Outline: Unassigned INS bytes with valid USIM CLA return 6D 00
    When I send APDU [00 <INS> 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

    Examples:
      | INS | Notes                                          |
      | 03  | Not assigned in ISO 7816-4 or ETSI TS 102 221  |
      | 05  | Not assigned                                   |
      | 07  | Not assigned                                   |
      | 09  | Not assigned                                   |
      | 11  | Not assigned (adjacent to TERMINAL PROFILE 10) |
      | 13  | Not assigned (adjacent to FETCH 12)            |
      | 50  | Not assigned                                   |
      | 60  | Not assigned                                   |
      | 7F  | Not assigned                                   |
      | A0  | Not assigned in USIM context                   |
      | FE  | Not assigned                                   |

  Scenario Outline: Unassigned INS bytes with GSM CLA return 6D 00
    When I send APDU [A0 <INS> 00 00]
    Then SW indicates instruction not supported
    And the simulator has not panicked
    And no SIM state has changed

    Examples:
      | INS | Notes                                             |
      | 00  | Not a GSM 11.11 instruction                       |
      | 03  | Not a GSM 11.11 instruction                       |
      | 50  | Not a GSM 11.11 instruction                       |
      | FF  | Not a GSM 11.11 instruction                       |

  # =========================================================================
  # 4. Length Field Mismatches (Lc / Le errors)
  #
  # ISO 7816-4 clause 5.3.2: Lc specifies the exact number of data bytes
  # that follow in the command.  If the actual byte count is less than Lc
  # the APDU parser should detect a truncated data field and reject the
  # command without crashing (returns DataTruncated / SW 67 00 or is
  # ignored at the HLE layer depending on where detection happens).
  #
  # pyAPDUFuzzer documents length mismatch as a common crash vector on
  # production SIMs.  The simulator must handle all cases without panic.
  # =========================================================================

  Scenario: Lc=5 but only 2 data bytes present -- no crash
    # APDU claims 5 bytes of data (Lc=0x05) but only 2 bytes follow.
    # The parser must detect the truncation and return an error or ignore
    # the APDU; it must not read past the end of the buffer.
    When I send APDU [00 A4 00 00 05 3F 00]
    Then the simulator has not panicked
    And the response is either ignored or SW 67 00
    And no SIM state has changed

  Scenario: Lc=10 but zero data bytes present -- no crash
    When I send APDU [00 D6 00 00 0A]
    Then the simulator has not panicked
    And the response is either ignored or SW 67 00
    And no SIM state has changed

  Scenario: Lc=255 but only 4 bytes total -- no crash
    # Maximum Lc with nothing following the header.
    When I send APDU [00 D6 00 00 FF]
    Then the simulator has not panicked
    And the response is either ignored or SW 67 00
    And no SIM state has changed

  Scenario: Lc=0 with extra data bytes present -- extra bytes tolerated or rejected cleanly
    # ISO 7816-4 Case 2: Lc absent, Le=1 byte.  If the implementation
    # treats the 5th byte as Le=0x02 (a data byte when Lc=0 is implied)
    # the extra byte should be ignored, not cause a panic.
    # Sending [00 B0 00 00 00 AA] -- Le=0x00 then an unexpected 0xAA.
    When I send APDU [00 B0 00 00 00 AA]
    Then the simulator has not panicked

  Scenario: Le requesting 255 bytes when EF contains only 10 bytes -- capped at available
    # READ BINARY asking for 255 bytes from a 10-byte transparent EF.
    # The simulator must return at most the available bytes with SW 90 00
    # or return SW 6C XX (wrong Le, correct value is XX) per ISO 7816-4.
    # It must not read beyond the EF boundary.
    Given EF.ICCID (2FE2) is selected
    When I send READ BINARY [00 B0 00 00 FF]
    Then the simulator has not panicked
    And the response is either at most 10 bytes with SW 90 00 or SW 6C 0A

  Scenario: Le=0 (meaning 256) on a 10-byte EF -- handled without panic
    # Le=0x00 in Case 2/4 short-form encoding means "256 bytes expected".
    # The simulator must cap the response at the available data and must
    # not attempt to write 256 bytes into a short buffer.
    Given EF.ICCID (2FE2) is selected
    When I send READ BINARY [00 B0 00 00 00]
    Then the simulator has not panicked

  Scenario: Lc present and Le present, data shorter than Lc -- no crash
    # Case 4: CLA INS P1 P2 Lc data Le.  Data field shorter than Lc.
    # [00 D6 00 00 08 AA BB 00] -- Lc=8, only 2 data bytes + Le byte.
    When I send APDU [00 D6 00 00 08 AA BB 00]
    Then the simulator has not panicked
    And the response is either ignored or SW 67 00
    And no SIM state has changed

  # =========================================================================
  # 5. APDU Before Power On
  #
  # The HLE state machine must reject any APDU received before hle_reset()
  # has been called.  This matches the sim.feature scenario:
  # "APDU before PowerOn returns Ignored".
  # =========================================================================

  Scenario: APDU sent before power-on is ignored
    # A fresh SIM instance that has had hle_init called but NOT hle_reset
    # must return None for any APDU attempt.
    Given the SIM is initialised but NOT yet powered on
    When I send APDU [00 A4 00 04 02 3F 00]
    Then the APDU is ignored (simulator returns None)
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: GSM SELECT before power-on is ignored
    Given the SIM is initialised but NOT yet powered on
    When I send APDU [A0 A4 00 00 02 3F 00]
    Then the APDU is ignored (simulator returns None)
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: Malformed APDU before power-on is ignored
    Given the SIM is initialised but NOT yet powered on
    When I send APDU [FF FF]
    Then the APDU is ignored (simulator returns None)
    And the simulator has not panicked
    And no SIM state has changed

  # =========================================================================
  # 6. Rapid Command Sequences and Stress
  #
  # SIMTester and pyAPDUFuzzer both rely on sending large volumes of
  # varied APDUs in rapid succession.  Any stateful assumptions in the
  # simulator that are violated by out-of-order or repeated commands must
  # not cause a panic.
  # =========================================================================

  Scenario: GET RESPONSE without any prior data-returning command returns error
    # The response queue is empty immediately after power-on.
    # GET RESPONSE must return an error SW, not panic on an empty queue.
    When I send GET RESPONSE [00 C0 00 00 10]
    Then SW indicates an error
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: GET RESPONSE without prior data-returning command (GSM CLA)
    When I send GET RESPONSE [A0 C0 00 00 17]
    Then SW indicates an error
    And the simulator has not panicked
    And no SIM state has changed

  Scenario: Three consecutive SELECT MF commands do not crash
    # Repeated SELECT of the same file must be idempotent and not cause
    # state corruption or panic.
    When I send APDU [00 A4 00 04 02 3F 00]
    And I send APDU [00 A4 00 04 02 3F 00]
    And I send APDU [00 A4 00 04 02 3F 00]
    Then the simulator has not panicked
    And the last response is either SW 61 XX or SW 90 00

  Scenario: SELECT then immediate GET RESPONSE then second GET RESPONSE
    # Second GET RESPONSE after queue has been consumed must return error.
    When I send SELECT MF [00 A4 00 04 02 3F 00]
    And I send GET RESPONSE with Le matching SW2
    And I send GET RESPONSE [00 C0 00 00 10] again
    Then the third command returns an error SW
    And the simulator has not panicked

  Scenario: Interleaved USIM and invalid-CLA commands do not corrupt state
    When I send APDU [00 A4 00 04 02 3F 00]
    And I send APDU [F0 A4 00 00 02 3F 00]
    And I send APDU [00 A4 00 04 02 3F 00]
    Then the simulator has not panicked
    And the last SELECT returns a valid response

  Scenario: 1000 pseudo-random APDUs do not panic
    # Proptest-style chaos: any stream of bytes presented as APDUs must
    # not panic the simulator.  The step implementation generates 1000
    # APDUs from a deterministic seed (to keep tests reproducible) using
    # the byte sequence described below, covering lengths 0-9 and all
    # 256 possible CLA and INS values.
    #
    # Acceptable outcomes for each APDU:
    #   - None (ignored -- APDU too short)
    #   - Any well-formed SW (any 2-byte status word)
    # Unacceptable outcome: panic / process abort.
    When I send 1000 pseudo-random APDUs with seed 0xDEADBEEF
    Then none of them cause the simulator to panic

  Scenario: Rapid fire of all 256 INS values with USIM CLA does not panic
    # Exhaustive INS sweep: every possible INS byte sent with CLA=0x00.
    When I send APDU [00 <INS> 00 00] for every INS byte from 0x00 to 0xFF
    Then none of them cause the simulator to panic

  Scenario: Rapid fire of all 256 INS values with GSM CLA does not panic
    When I send APDU [A0 <INS> 00 00] for every INS byte from 0x00 to 0xFF
    Then none of them cause the simulator to panic

  Scenario: Alternating valid and truncated APDUs maintain consistent state
    # Confirms that processing a truncated (ignored) APDU does not corrupt
    # the internal state machine so that subsequent valid APDUs fail.
    When I send APDU [00 A4 00 04 02 3F 00]
    And I send APDU [00]
    And I send APDU [00 A4 00 04 02 3F 00]
    And I send APDU [00 A4]
    And I send APDU [00 A4 00 04 02 3F 00]
    Then the simulator has not panicked
    And every 4-byte-or-longer APDU returned a status word
    And every APDU shorter than 4 bytes was ignored

  Scenario: Maximum-length APDU (255-byte data field) is handled without panic
    # Lc=0xFF with 255 bytes of data following -- largest short-form Case 3.
    # The content is irrelevant; the point is that a 260-byte APDU does
    # not overflow the internal buffer.
    When I send APDU [00 D6 00 00 FF] followed by 255 bytes of 0xAA
    Then the simulator has not panicked

  Scenario: APDU with all-zero bytes does not crash
    When I send APDU [00 00 00 00 00]
    Then the simulator has not panicked
    And no SIM state has changed

  Scenario: APDU with all-0xFF bytes does not crash
    When I send APDU [FF FF FF FF FF]
    Then the simulator has not panicked
    And no SIM state has changed

  Scenario: APDU with alternating 0x55/0xAA bytes does not crash
    When I send APDU [55 AA 55 AA 55]
    Then the simulator has not panicked
    And no SIM state has changed
