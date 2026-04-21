//! `P1 = 0x04` PRNG probe: a seedable deterministic pseudo-random
//! byte stream so tests can pin the PRNG state to a fixture value.
//!
//! - `P2 = 0x00` SEED: accept exactly 8 bytes in the data field,
//!   interpret as a big-endian `u64` seed.
//! - `P2 = 0x01` READ: accept a single data byte `N`, return the
//!   next `N` pseudo-random bytes produced by the current seed.
//!
//! # Scope
//!
//! This probe does not (yet) override randomness consumers inside
//! other simrs crates. It exposes an applet-local PRNG so callers
//! can verify end-to-end plumbing of a seed/read cycle; the broader
//! "thread-local seed override for every simrs crate's RNG" refactor
//! is a later design-doc phase. Until then, treat this as a sanity
//! probe that ensures seed + read round-trip deterministically.
//!
//! # Algorithm
//!
//! Xorshift64 (Marsaglia 2003). Single-word state, period `2^64 - 1`
//! when seeded non-zero. A zero seed produces an all-zero stream
//! (`xorshift64(0) == 0` by construction); this is documented
//! rather than guarded so `seed = 0x00...00` remains a valid test
//! fixture for code paths that must handle all-zero randomness.

use crate::applet::AppletState;
use crate::protocol::{SW_INCORRECT_DATA, SW_INCORRECT_P1P2, SW_OK};

/// Sub-operation: install a new seed.
pub const P2_SEED: u8 = 0x00;

/// Sub-operation: read the next N bytes from the stream.
pub const P2_READ: u8 = 0x01;

/// Length of the seed data field in bytes.
pub const SEED_LEN: usize = 8;

/// Maximum byte count a single READ can request. The upper bound is
/// chosen to stay well within a short-APDU response; larger streams
/// can be obtained with repeated READ commands.
pub const MAX_READ_BYTES: usize = 255;

/// Handle a PRNG APDU.
#[must_use]
pub fn handle(state: &mut AppletState, p2: u8, data: &[u8], rsp: &mut Vec<u8>) -> [u8; 2] {
    match p2 {
        P2_SEED => handle_seed(state, data),
        P2_READ => handle_read(state, data, rsp),
        _ => SW_INCORRECT_P1P2,
    }
}

const fn handle_seed(state: &mut AppletState, data: &[u8]) -> [u8; 2] {
    if data.len() != SEED_LEN {
        return SW_INCORRECT_DATA;
    }
    let mut buf = [0u8; SEED_LEN];
    buf.copy_from_slice(data);
    state.prng_state = u64::from_be_bytes(buf);
    SW_OK
}

fn handle_read(state: &mut AppletState, data: &[u8], rsp: &mut Vec<u8>) -> [u8; 2] {
    if data.len() != 1 {
        return SW_INCORRECT_DATA;
    }
    let n = data[0] as usize;
    if n > MAX_READ_BYTES {
        return SW_INCORRECT_DATA;
    }
    // Advance the state once per 8 bytes requested, consuming the
    // full 64-bit output each step. Earlier drafts used only the low
    // byte per advance, wasting 56 bits of entropy per iteration.
    let mut remaining = n;
    while remaining > 0 {
        state.prng_state = xorshift64(state.prng_state);
        let block = state.prng_state.to_be_bytes();
        let take = remaining.min(block.len());
        rsp.extend_from_slice(&block[..take]);
        remaining -= take;
    }
    SW_OK
}

/// Marsaglia's 64-bit xorshift. `xorshift64(0) == 0`; callers who
/// want a non-degenerate stream must seed non-zero.
const fn xorshift64(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_stores_big_endian_u64() {
        let mut state = AppletState::default();
        let seed_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut rsp = Vec::new();
        let sw = handle(&mut state, P2_SEED, &seed_bytes, &mut rsp);
        assert_eq!(sw, SW_OK);
        assert!(rsp.is_empty());
        assert_eq!(state.prng_state, 0x0102_0304_0506_0708);
    }

    #[test]
    fn seed_rejects_wrong_length() {
        let mut state = AppletState::default();
        let mut rsp = Vec::new();
        let sw = handle(&mut state, P2_SEED, &[0u8; 4], &mut rsp);
        assert_eq!(sw, SW_INCORRECT_DATA);
        // Original state untouched.
        assert_eq!(state.prng_state, 0);
    }

    #[test]
    fn zero_seed_yields_zero_stream() {
        let mut state = AppletState {
            prng_state: 0,
            ..AppletState::default()
        };
        let mut rsp = Vec::new();
        let sw = handle(&mut state, P2_READ, &[16], &mut rsp);
        assert_eq!(sw, SW_OK);
        assert_eq!(rsp, vec![0u8; 16]);
    }

    #[test]
    fn nonzero_seed_stream_is_deterministic() {
        let seed: u64 = 0xdead_beef_cafe_babe;
        let mut s1 = AppletState {
            prng_state: seed,
            ..AppletState::default()
        };
        let mut s2 = AppletState {
            prng_state: seed,
            ..AppletState::default()
        };
        let mut r1 = Vec::new();
        let mut r2 = Vec::new();
        assert_eq!(handle(&mut s1, P2_READ, &[32], &mut r1), SW_OK);
        assert_eq!(handle(&mut s2, P2_READ, &[32], &mut r2), SW_OK);
        assert_eq!(r1, r2);
        assert_ne!(r1, vec![0u8; 32]);
    }

    #[test]
    fn stream_consumes_state() {
        let mut state = AppletState {
            prng_state: 1,
            ..AppletState::default()
        };
        // Two 16-byte reads from the same state should not overlap in
        // output -- the PRNG advances with each byte.
        let mut r1 = Vec::new();
        let mut r2 = Vec::new();
        assert_eq!(handle(&mut state, P2_READ, &[16], &mut r1), SW_OK);
        assert_eq!(handle(&mut state, P2_READ, &[16], &mut r2), SW_OK);
        assert_ne!(r1, r2);
    }

    #[test]
    fn read_with_zero_length_is_empty_ok() {
        let mut state = AppletState {
            prng_state: 1,
            ..AppletState::default()
        };
        let mut rsp = Vec::new();
        let sw = handle(&mut state, P2_READ, &[0], &mut rsp);
        assert_eq!(sw, SW_OK);
        assert!(rsp.is_empty());
        // State is unchanged.
        assert_eq!(state.prng_state, 1);
    }

    #[test]
    fn read_requires_exactly_one_data_byte() {
        let mut state = AppletState {
            prng_state: 1,
            ..AppletState::default()
        };
        let mut rsp = Vec::new();
        assert_eq!(
            handle(&mut state, P2_READ, &[], &mut rsp),
            SW_INCORRECT_DATA
        );
        assert_eq!(
            handle(&mut state, P2_READ, &[1, 2], &mut rsp),
            SW_INCORRECT_DATA
        );
    }

    #[test]
    fn unknown_p2_returns_6a86() {
        let mut state = AppletState::default();
        let mut rsp = Vec::new();
        let sw = handle(&mut state, 0xFF, &[], &mut rsp);
        assert_eq!(sw, SW_INCORRECT_P1P2);
    }
}
