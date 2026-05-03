//! Shared card event/response types for SIM and `GlobalPlatform` cards.
//!
//! This tiny foundation crate defines the [`SimEvent`] / [`SimResponse`]
//! interface that both `simrs-sim` (standalone SIM/USIM) and `simrs-gp-card`
//! (`GlobalPlatform` card) implement. By sharing these types, both card
//! personalities work with the same infrastructure: HLE, QEMU bridge,
//! interposer, fuzzer, and snapshot.
//!
//! Also provides [`ResetKind`], [`ResetEffects`], and [`CardState`] for
//! lifecycle management.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation. No dependencies
//! except `simrs-iso7816` (for [`StatusWord`]). The optional `os-rng`
//! feature pulls in `getrandom` to expose [`OsRng`] for hosted callers.
#![no_std]

use simrs_iso7816::StatusWord;

// ---------------------------------------------------------------------------
// Lifecycle policy
// ---------------------------------------------------------------------------

/// Distinguishes cold reset (power-on) from warm reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetKind {
    /// Cold reset -- card was powered on from the Off state, or the host
    /// issued a full power cycle.
    Cold,
    /// Warm reset -- RST line asserted while Vcc remains applied.
    Warm,
}

/// Per-subsystem flags controlling what session state is cleared on reset.
///
/// Each flag corresponds to a discrete piece of session state. A value of
/// `true` means the subsystem is cleared; `false` preserves it across the
/// reset boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ResetEffects {
    /// Clear PIN/PUK verified flags (re-verification required).
    pub clear_pin_verified: bool,
    /// Clear the GET RESPONSE queue (no stale data from prior session).
    pub clear_response_queue: bool,
    /// Reset file selection context (MF implicitly selected).
    pub clear_file_selection: bool,
    /// Close supplementary logical channels 1-3.
    ///
    /// USIM-specific; has no effect when only the `gsm` feature is enabled.
    pub clear_logical_channels: bool,
    /// Reset the proactive (STK) session and terminal capability.
    ///
    /// USIM-specific; has no effect when only the `gsm` feature is enabled.
    pub clear_proactive_session: bool,
    /// Clear the last AID match flag.
    ///
    /// USIM-specific; has no effect when only the `gsm` feature is enabled.
    pub clear_last_aid_match: bool,
}

impl ResetEffects {
    /// All subsystems cleared -- matches [ETSI TS 102 221 V18.3.0 clause 6.5](https://www.etsi.org/) reset procedures.
    pub const fn all() -> Self {
        Self {
            clear_pin_verified: true,
            clear_response_queue: true,
            clear_file_selection: true,
            clear_logical_channels: true,
            clear_proactive_session: true,
            clear_last_aid_match: true,
        }
    }

    /// No subsystems cleared -- everything preserved across reset.
    pub const fn none() -> Self {
        Self {
            clear_pin_verified: false,
            clear_response_queue: false,
            clear_file_selection: false,
            clear_logical_channels: false,
            clear_proactive_session: false,
            clear_last_aid_match: false,
        }
    }
}

/// Standard reset policy: clear all session state on both cold and warm
/// reset. This is the default and matches ETSI TS 102 221 V18.3.0
/// clause 6.5 (reset procedures).
pub const fn standard_reset_policy(_kind: ResetKind) -> ResetEffects {
    ResetEffects::all()
}

// ---------------------------------------------------------------------------
// Card state
// ---------------------------------------------------------------------------

/// Internal card power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardState {
    /// Card is not powered.
    Off,
    /// Card is powered and ready for APDU exchange.
    Ready,
}

// ---------------------------------------------------------------------------
// Events and responses
// ---------------------------------------------------------------------------

/// An event delivered to the card by the terminal or host.
///
/// Per ISO/IEC 7816-3, the card lifecycle is:
/// 1. `PowerOn` -- card activation, returns ATR
/// 2. `Apdu` -- command exchange (repeats)
/// 3. `Reset` -- warm reset, returns ATR
/// 4. `PowerOff` -- card deactivation, returns `Ignored`
///
/// The `Tick` variant is an extension for advancing UICC-side timers
/// (per ETSI TS 102 223 V18.2.0 clause 6.6.21). Since `no_std` has no clock,
/// the caller supplies elapsed seconds.
#[derive(Debug, Clone, Copy)]
pub enum SimEvent<'a> {
    /// Card power-on (cold reset). Returns ATR.
    PowerOn,
    /// Warm reset. Returns ATR.
    Reset,
    /// Card deactivation. Returns `Ignored`.
    ///
    /// After `PowerOff`, subsequent APDUs return `Ignored` until the
    /// next `PowerOn`.
    PowerOff,
    /// APDU command (raw bytes, at least 4 for CLA INS P1 P2).
    Apdu(&'a [u8]),
    /// Advance UICC-side proactive timers by `elapsed_secs`.
    ///
    /// Returns `Ignored` (timers are internal state).
    Tick(u32),
}

/// A response produced by the card.
#[derive(Debug)]
#[must_use]
pub enum SimResponse<'a> {
    /// Answer To Reset bytes.
    Atr(&'a [u8]),
    /// APDU response: data (may be empty) + status word.
    Apdu {
        /// Response data (empty for SW-only responses).
        data: &'a [u8],
        /// Status word (2 bytes).
        sw: StatusWord,
    },
    /// Event was ignored (malformed APDU, card not powered on, etc.).
    Ignored,
}

// ---------------------------------------------------------------------------
// FNV-1a hash
// ---------------------------------------------------------------------------

/// FNV-1a 64-bit hash for state deduplication.
///
/// Not cryptographic. Used by snapshot and fuzzing infrastructure
/// for fast state fingerprinting.
pub const fn fnv1a(data: &[u8]) -> u64 {
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = BASIS;
    let mut i = 0;
    while i < data.len() {
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}

// ---------------------------------------------------------------------------
// Card-level entropy source
// ---------------------------------------------------------------------------

/// On-card source of entropy.
///
/// Real cards use a hardware TRNG; the simulator can plug in any
/// implementation -- a host `OsRng` for production use, or a
/// deterministic seeded RNG ([`DeterministicRng`]) for reproducible
/// tests and replay.
///
/// Used by GP secure-channel session establishment for card-challenge
/// generation in the SCP01/SCP02-explicit and SCP03-random modes.
/// Plumbed through `GpOpen` / `GpCard` as a generic type parameter so
/// no heap allocation is required for trait-object dispatch.
pub trait EntropySource {
    /// Fill `dest` with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// Deterministic xorshift64 RNG, seeded once per construction.
///
/// Useful for test reproducibility and replay vectors. **Not** suitable
/// for production card challenges -- xorshift64 is statistically weak
/// and the seed is observable.
#[derive(Debug, Clone, Copy)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Construct a deterministic RNG with the given seed. Zero seed is
    /// remapped to a fixed non-zero constant (xorshift64 is
    /// stationary at zero).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xDEAD_BEEF_CAFE_BABE
            } else {
                seed
            },
        }
    }

    /// Pull the next 64-bit word from the stream.
    const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

impl EntropySource for DeterministicRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }
}

/// Host-OS-backed entropy source (gated behind the `std` feature).
///
/// Wraps `getrandom::getrandom` so hosted callers (HLE, fuzzer,
/// conformance tests) can plug a real CSPRNG into `GpOpen` / `GpCard`
/// without re-implementing the wrapper at every call site.
///
/// # Panics
///
/// `fill_bytes` panics if the underlying `getrandom` call fails. This
/// matches the realistic failure mode for a card RNG: hardware-level
/// entropy starvation is a non-recoverable condition; tests that need
/// to exercise that path should use [`DeterministicRng`] instead.
#[cfg(feature = "os-rng")]
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

#[cfg(feature = "os-rng")]
impl EntropySource for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OsRng: getrandom failed");
    }
}

#[cfg(test)]
mod card_rng_tests {
    use super::{DeterministicRng, EntropySource};

    #[test]
    fn deterministic_same_seed_same_stream() {
        let mut a = DeterministicRng::new(42);
        let mut b = DeterministicRng::new(42);
        let mut ba = [0u8; 32];
        let mut bb = [0u8; 32];
        a.fill_bytes(&mut ba);
        b.fill_bytes(&mut bb);
        assert_eq!(ba, bb);
    }

    #[test]
    fn deterministic_different_seeds_diverge() {
        let mut a = DeterministicRng::new(1);
        let mut b = DeterministicRng::new(2);
        let mut ba = [0u8; 16];
        let mut bb = [0u8; 16];
        a.fill_bytes(&mut ba);
        b.fill_bytes(&mut bb);
        assert_ne!(ba, bb);
    }

    #[test]
    fn deterministic_zero_seed_remapped_to_nonzero() {
        let mut a = DeterministicRng::new(0);
        let mut buf = [0u8; 8];
        a.fill_bytes(&mut buf);
        assert_ne!(buf, [0u8; 8]);
    }

    #[test]
    fn deterministic_fill_advances_stream() {
        let mut rng = DeterministicRng::new(99);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        // Two consecutive draws from a single RNG must differ.
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_short_buffers_dont_panic() {
        let mut rng = DeterministicRng::new(7);
        for n in 0..32 {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf[..n]);
        }
    }
}
