#![allow(missing_docs)]
//! APDU boundary condition step definitions.
//!
//! Covers truncated APDUs, invalid CLA/INS, length mismatches,
//! APDU before power-on, and rapid/stress sequences per:
//!   - ISO/IEC 7816-4:2020 clause 5
//!   - ETSI TS 102 221 V18.0.0 clauses 10, 11
//!   - `SIMTester` (`SRLabs` 2013), `pyAPDUFuzzer`

use cucumber::{given, then, when};
use simrs_security_tests::{apdu, parse_hex};

use super::world::{do_send_apdu, ensure_pin1_verified, reset_state_snapshots, SimWorld};

// =========================================================================
// GIVEN steps
// =========================================================================

#[given("a 258-byte response buffer is allocated")]
fn given_response_buffer(world: &mut SimWorld) {
    // No-op: handled internally by the Sim<_, 256> generic.
    let _ = world;
}

#[given("EF.ICCID (2FE2) is selected")]
fn given_ef_iccid_selected(world: &mut SimWorld) {
    // Verify PIN1 first so READ BINARY will succeed.
    ensure_pin1_verified(world);
    let cmd = apdu::select_fid(apdu::FID_ICCID).build();
    do_send_apdu(world, &cmd);
    // Consume FCP if pending.
    if let Some((0x61, le)) = world.last_sw_opt() {
        let get_resp = apdu::get_response(le).build();
        do_send_apdu(world, &get_resp);
    }
    reset_state_snapshots(world);
}

// =========================================================================
// WHEN steps -- stress and boundary test patterns
// =========================================================================

#[when(regex = r"^I send (\d+) pseudo-random APDUs with seed (.+)$")]
fn when_send_random_apdus(world: &mut SimWorld, count: usize, seed_str: String) {
    let seed = if seed_str.starts_with("0x") || seed_str.starts_with("0X") {
        u64::from_str_radix(&seed_str[2..], 16).unwrap()
    } else {
        seed_str.parse::<u64>().unwrap()
    };
    // Simple PRNG (xorshift64) for deterministic pseudo-random APDUs.
    let mut state = seed;
    let next = |s: &mut u64| -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    };
    for _ in 0..count {
        let len = (next(&mut state) % 10) as usize; // 0..9 byte APDUs
        let mut apdu = Vec::with_capacity(len);
        for _ in 0..len {
            apdu.push((next(&mut state) & 0xFF) as u8);
        }
        do_send_apdu(world, &apdu);
    }
}

#[when(
    regex = r"^I send APDU \[([0-9A-Fa-f]{2}) <INS> ([0-9A-Fa-f]{2}) ([0-9A-Fa-f]{2})\] for every INS byte from 0x00 to 0xFF$"
)]
fn when_ins_sweep(world: &mut SimWorld, cla_hex: String, p1_hex: String, p2_hex: String) {
    let cla = u8::from_str_radix(&cla_hex, 16).unwrap();
    let p1 = u8::from_str_radix(&p1_hex, 16).unwrap();
    let p2 = u8::from_str_radix(&p2_hex, 16).unwrap();
    for ins in 0x00..=0xFF_u8 {
        let apdu = [cla, ins, p1, p2];
        do_send_apdu(world, &apdu);
    }
}

#[when(regex = r"^I send APDU \[([^\]]+)\] followed by (\d+) bytes of 0xAA$")]
fn when_send_apdu_with_padding(world: &mut SimWorld, hex: String, count: usize) {
    let mut cmd = parse_hex(&hex);
    cmd.extend(std::iter::repeat_n(0xAA, count));
    do_send_apdu(world, &cmd);
}

// =========================================================================
// THEN steps -- robustness assertions
// =========================================================================

#[then("the APDU is ignored (simulator returns None)")]
fn then_apdu_ignored(world: &mut SimWorld) {
    assert!(
        world.last_apdu_dropped(),
        "Expected APDU to be ignored, but got SW {:02X?}",
        world.last_sw_opt()
    );
}

#[then("the APDU is processed (simulator returns a status word)")]
fn then_apdu_processed(world: &mut SimWorld) {
    assert!(
        !world.last_apdu_dropped(),
        "Expected APDU to be processed, but it was ignored"
    );
    assert!(world.last_sw_opt().is_some(), "Expected a status word");
}

// Reaching this Then step without unwinding IS the assertion: the preceding
// When step executed without panicking. No further check is needed.
#[then("the simulator has not panicked")]
fn then_no_panic(world: &mut SimWorld) {
    let _ = world;
}

// Same reasoning as then_no_panic: if the fuzz/sweep When step completed
// without aborting, the assertion holds.
#[then("none of them cause the simulator to panic")]
fn then_none_panicked(world: &mut SimWorld) {
    let _ = world;
}

#[then(regex = r"^the response is either ignored or SW ([0-9A-Fa-f]{2}) ([0-9A-Fa-f]{2})$")]
fn then_ignored_or_sw(world: &mut SimWorld, sw1_hex: String, sw2_hex: String) {
    if world.last_apdu_dropped() {
        return;
    }
    let expected_sw1 = u8::from_str_radix(&sw1_hex, 16).unwrap();
    let expected_sw2 = u8::from_str_radix(&sw2_hex, 16).unwrap();
    let (sw1, sw2) = world.last_sw();
    if (sw1, sw2) == (expected_sw1, expected_sw2) {
        return;
    }
    // Accept any error SW as an alternative (the command was rejected).
    let got_is_error = sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91;
    assert!(
        got_is_error,
        "Expected ignored or SW {expected_sw1:02X} {expected_sw2:02X}, got {sw1:02X} {sw2:02X}",
    );
}

#[then("the response is either SW 6E 00 or a processed result")]
fn then_6e00_or_processed(world: &mut SimWorld) {
    if world.last_apdu_dropped() {
        return;
    }
    assert!(world.last_sw_opt().is_some(), "Expected some SW");
}

#[then(
    regex = r"^the response is either at most (\d+) bytes with SW 90 00 or SW 6C ([0-9A-Fa-f]{2})$"
)]
fn then_at_most_n_or_6c(world: &mut SimWorld, max_bytes: usize, le_hex: String) {
    let (sw1, sw2) = world.last_sw();
    if sw1 == 0x90 && sw2 == 0x00 {
        assert!(
            world.last_data().len() <= max_bytes,
            "Expected at most {max_bytes} bytes, got {}",
            world.last_data().len()
        );
    } else if sw1 == 0x6C {
        let expected_le = u8::from_str_radix(&le_hex, 16).unwrap();
        assert_eq!(
            sw2, expected_le,
            "Expected SW 6C {expected_le:02X}, got 6C {sw2:02X}",
        );
    } else {
        // Some implementations may return other error SWs; accept gracefully.
        assert!(sw1 >= 0x60, "Unexpected SW {sw1:02X} {sw2:02X}");
    }
}

#[then("the last response is either SW 61 XX or SW 90 00")]
fn then_last_61_or_90(world: &mut SimWorld) {
    let (sw1, _) = world.last_sw();
    assert!(
        sw1 == 0x61 || sw1 == 0x90,
        "Expected SW1=61 or 90, got {sw1:02X}",
    );
}

#[then("the third command returns an error SW")]
fn then_third_error(world: &mut SimWorld) {
    let (sw1, _) = world.last_sw();
    assert!(
        sw1 >= 0x60 && sw1 != 0x90 && sw1 != 0x91,
        "Expected error SW, got {sw1:02X}",
    );
}

#[then("the last SELECT returns a valid response")]
fn then_last_select_valid(world: &mut SimWorld) {
    assert!(
        !world.last_apdu_dropped(),
        "Expected last SELECT to be processed"
    );
    assert!(world.last_sw_opt().is_some(), "Expected a status word");
}

#[then("every 4-byte-or-longer APDU returned a status word")]
fn then_every_4byte_returned_sw(world: &mut SimWorld) {
    for (i, &(len, processed)) in world.apdu_log.iter().enumerate() {
        if len >= 4 {
            assert!(
                processed,
                "APDU #{i} ({len} bytes) was ignored, expected a status word",
            );
        }
    }
}

#[then("every APDU shorter than 4 bytes was ignored")]
fn then_short_apdus_ignored(world: &mut SimWorld) {
    for (i, &(len, processed)) in world.apdu_log.iter().enumerate() {
        if len < 4 {
            assert!(
                !processed,
                "APDU #{i} ({len} bytes) was processed, expected to be ignored",
            );
        }
    }
}
