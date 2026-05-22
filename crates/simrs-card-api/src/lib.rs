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
// Default ATR
// ---------------------------------------------------------------------------

/// Shared default Answer To Reset for simrs SIM binaries.
///
/// TS + T0 + TA1 + TD1 + TD2 + TA3 + 15 historical bytes + TCK; T=0 only.
/// Parses cleanly under ISO 7816-3 clause 8 and is the single source of truth
/// for `simrs-vpcd`, `simrs-swicc`, `simrs-interposer`, `simrs-hle`, and the
/// `simrs-sim` test fixtures.
pub static DEFAULT_ATR: [u8; 22] = [
    0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x1B, 0x67, 0x4A, 0x4C,
    0x75, 0x30, 0x34, 0x05, 0x4B, 0xE9,
];

// ---------------------------------------------------------------------------
// Owned ATR bytes
// ---------------------------------------------------------------------------

/// Maximum ATR length per ISO 7816-3 clause 8: TS + up to 32 following bytes.
///
/// Mirrors `simrs_t0::ATR_MAX_LEN` but is duplicated here to avoid a
/// dependency from this foundation crate on the higher-level T=0 protocol
/// crate.
pub const ATR_MAX_LEN: usize = 33;

/// Owned, inline-stored ATR byte sequence.
///
/// Backed by a fixed-size buffer ([`ATR_MAX_LEN`] = 33) plus a length, so it
/// works in `no_std`/`no_alloc` contexts. Constructed from a slice, a
/// fixed-size array reference, or built up incrementally. Implements
/// [`AsRef<[u8]>`] so consumers expecting `&[u8]` get one cheaply.
///
/// Used as the storage type for the ATR carried by a `Sim` instance,
/// enabling per-instance ATRs that don't require a `'static` reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtrBytes {
    buf: [u8; ATR_MAX_LEN],
    len: u8,
}

/// Error type for [`AtrBytes`] construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtrError {
    /// Input exceeds [`ATR_MAX_LEN`] bytes.
    TooLong,
}

impl core::fmt::Display for AtrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong => f.write_str("ATR exceeds 33-byte limit"),
        }
    }
}

impl AtrBytes {
    /// Construct from a byte slice, copying the contents.
    ///
    /// # Errors
    ///
    /// Returns [`AtrError::TooLong`] if `bytes.len() > ATR_MAX_LEN`.
    pub const fn from_slice(bytes: &[u8]) -> Result<Self, AtrError> {
        if bytes.len() > ATR_MAX_LEN {
            return Err(AtrError::TooLong);
        }
        let mut buf = [0u8; ATR_MAX_LEN];
        let mut i = 0;
        while i < bytes.len() {
            buf[i] = bytes[i];
            i += 1;
        }
        #[allow(clippy::cast_possible_truncation)]
        Ok(Self {
            buf,
            len: bytes.len() as u8,
        })
    }

    /// Return the valid ATR bytes as a slice.
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        let (head, _) = self.buf.split_at(self.len as usize);
        head
    }

    /// Return the number of valid bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Return whether the ATR is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for AtrBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Default for AtrBytes {
    /// Returns an empty (zero-length) [`AtrBytes`].
    fn default() -> Self {
        Self {
            buf: [0u8; ATR_MAX_LEN],
            len: 0,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for AtrBytes {
    type Error = AtrError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes)
    }
}

// Const-generic blanket: any fixed-size array reference up to ATR_MAX_LEN
// converts infallibly. Oversize arrays fail to compile because the const
// assertion in the body triggers.
impl<const N: usize> From<&[u8; N]> for AtrBytes {
    fn from(bytes: &[u8; N]) -> Self {
        const {
            assert!(N <= ATR_MAX_LEN, "ATR array exceeds 33-byte limit");
        }
        let mut buf = [0u8; ATR_MAX_LEN];
        let mut i = 0;
        while i < N {
            buf[i] = bytes[i];
            i += 1;
        }
        #[allow(clippy::cast_possible_truncation)]
        Self {
            buf,
            len: N as u8,
        }
    }
}

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
mod atr_bytes_tests {
    use super::{ATR_MAX_LEN, AtrBytes, AtrError, DEFAULT_ATR};

    #[test]
    fn from_slice_round_trip() {
        let bytes: &[u8] = &[0x3B, 0x00];
        let atr = AtrBytes::from_slice(bytes).unwrap();
        assert_eq!(atr.as_slice(), bytes);
        assert_eq!(atr.len(), 2);
        assert!(!atr.is_empty());
    }

    #[test]
    fn from_array_conversion() {
        let atr: AtrBytes = (&DEFAULT_ATR).into();
        assert_eq!(atr.as_slice(), &DEFAULT_ATR);
        assert_eq!(atr.len(), DEFAULT_ATR.len());
    }

    #[test]
    fn from_max_length_slice_works() {
        let bytes = [0xAA; ATR_MAX_LEN];
        let atr = AtrBytes::from_slice(&bytes).unwrap();
        assert_eq!(atr.len(), ATR_MAX_LEN);
        assert_eq!(atr.as_slice(), &bytes[..]);
    }

    #[test]
    fn from_slice_too_long_errors() {
        let bytes = [0xAA; ATR_MAX_LEN + 1];
        assert_eq!(AtrBytes::from_slice(&bytes), Err(AtrError::TooLong));
    }

    #[test]
    fn try_from_slice_works() {
        let bytes: &[u8] = &[0x3B, 0x9F];
        let atr: AtrBytes = bytes.try_into().unwrap();
        assert_eq!(atr.as_slice(), bytes);
    }

    #[test]
    fn try_from_slice_too_long_errors() {
        let bytes = [0xAA; ATR_MAX_LEN + 1];
        let result: Result<AtrBytes, _> = (&bytes[..]).try_into();
        assert_eq!(result, Err(AtrError::TooLong));
    }

    #[test]
    fn as_ref_returns_slice() {
        let atr = AtrBytes::from_slice(&[0x3B, 0x00, 0xFF]).unwrap();
        let s: &[u8] = atr.as_ref();
        assert_eq!(s, &[0x3B, 0x00, 0xFF]);
    }

    #[test]
    fn default_is_empty() {
        let atr = AtrBytes::default();
        assert!(atr.is_empty());
        assert_eq!(atr.len(), 0);
        assert_eq!(atr.as_slice(), &[] as &[u8]);
    }

    #[test]
    fn equality_compares_full_buffer() {
        // Two AtrBytes with the same valid contents must compare equal.
        // Equality is derived over the full [u8; 33] buffer, which is
        // sound only because all constructors zero-init the buffer
        // before copying the payload bytes.
        let a = AtrBytes::from_slice(&[0x3B, 0x00]).unwrap();
        let b = AtrBytes::from_slice(&[0x3B, 0x00]).unwrap();
        assert_eq!(a, b);
        let c = AtrBytes::from_slice(&[0x3B, 0x9F]).unwrap();
        assert_ne!(a, c);
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
