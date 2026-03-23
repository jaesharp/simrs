//! Constant-time validation facade backed by [tacet](https://github.com/agucova/tacet).
//!
//! Provides a two-class test pattern with a deterministic PRNG, powered by
//! tacet's adaptive Bayesian methodology and platform-specific high-resolution
//! timers (rdtsc on `x86_64`, ~0.3ns resolution).
//!
//! # Usage
//!
//! ```rust,no_run
//! use simrs_consttime_validation::{ct_test, assert_no_timing_leak, Rng};
//!
//! let outcome = ct_test(42,
//!     |rng| rng.next_u8() & 0x7F,   // class 0: fixed pattern
//!     |rng| rng.next_u8() | 0x80,   // class 1: different pattern
//!     |&input| {
//!         core::hint::black_box(input.wrapping_mul(3));
//!     },
//! );
//! assert_no_timing_leak!(outcome);
//! ```
//!
//! # Methodology
//!
//! tacet uses an adaptive Bayesian approach (rather than the frequentist
//! Welch's t-test from `DudeCT`) to determine whether two input classes produce
//! statistically different execution times. The test runs adaptively up to a
//! time budget, reporting:
//!
//! - **Pass**: P(leak) < 5% -- no timing difference detected
//! - **Fail**: P(leak) > 95% -- with exploitability classification
//! - **Inconclusive**: insufficient evidence in the time budget
//! - **Unmeasurable**: operation too fast for the platform timer
//!
//! IMPORTANT: Always compile with optimizations (`--release` or `opt-level >= 2`).
//! Debug builds produce false positives due to unoptimized code paths.

// Re-export tacet essentials.
pub use tacet::{
    assert_constant_time, assert_no_timing_leak, AttackerModel, InputPair, Outcome, TimingOracle,
};

// ---------------------------------------------------------------------------
// Minimal PRNG (xorshift64) -- avoids pulling in rand
// ---------------------------------------------------------------------------

/// Minimal xorshift64 PRNG for generating test inputs.
///
/// Avoids pulling in `rand` as a dependency. Seeded from OS entropy via
/// `getrandom`. Not cryptographically secure -- suitable only for test
/// input generation.
pub struct Rng(u64);

impl Rng {
    /// Create a new PRNG seeded from OS entropy.
    ///
    /// # Panics
    ///
    /// Panics if the OS entropy source is unavailable.
    pub fn from_entropy() -> Self {
        let mut seed = [0u8; 8];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        let s = u64::from_le_bytes(seed);
        Self(if s == 0 { 0xDEAD_BEEF_CAFE_BABE } else { s })
    }

    /// Create a PRNG with a fixed seed (for reproducible tests).
    pub const fn from_seed(seed: u64) -> Self {
        Self(if seed == 0 {
            0xDEAD_BEEF_CAFE_BABE
        } else {
            seed
        })
    }

    /// Generate the next `u64` value.
    pub const fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Generate a random byte.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// Fill a byte slice with random data.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_u8();
        }
    }

    /// Generate a random boolean.
    pub const fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }
}

// ---------------------------------------------------------------------------
// Convenience wrapper
// ---------------------------------------------------------------------------

/// Run a constant-time validation test using tacet's Bayesian methodology.
///
/// Each input class receives its own [`Rng`] for deterministic input
/// generation. Class 0 is seeded with `seed`, class 1 with `seed + 1`,
/// producing independent sequences. The oracle uses `AdjacentNetwork`
/// attacker model (100ns exploitability threshold) and a 10-second time
/// budget (tacet default is 60s; 10s is sufficient for `AdjacentNetwork`
/// because the model's coarse threshold converges quickly).
///
/// tacet pre-generates all inputs before measurement begins, so the RNG
/// and closure overhead never enters the timed region.
///
/// Returns the full [`Outcome`] for use with assertion macros:
///
/// ```rust,no_run
/// # use simrs_consttime_validation::{ct_test, assert_no_timing_leak};
/// let outcome = ct_test(42, |rng| 0u8, |rng| rng.next_u8(), |&x| {});
/// assert_no_timing_leak!(outcome);
/// ```
pub fn ct_test<T, F0, F1, R>(
    seed: u64,
    mut prepare_class0: F0,
    mut prepare_class1: F1,
    run: R,
) -> Outcome
where
    T: Clone + core::hash::Hash,
    F0: FnMut(&mut Rng) -> T,
    F1: FnMut(&mut Rng) -> T,
    R: FnMut(&T),
{
    let mut rng0 = Rng::from_seed(seed);
    let mut rng1 = Rng::from_seed(seed.wrapping_add(1));

    TimingOracle::for_attacker(AttackerModel::AdjacentNetwork)
        .seed(seed)
        .time_budget_secs(10)
        .test(
            InputPair::new_untracked(
                move || prepare_class0(&mut rng0),
                move || prepare_class1(&mut rng1),
            ),
            run,
        )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_from_seed_deterministic() {
        let mut a = Rng::from_seed(12345);
        let mut b = Rng::from_seed(12345);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn rng_zero_seed_replaced() {
        let mut rng = Rng::from_seed(0);
        assert_ne!(rng.next_u64(), 0);
    }

    #[test]
    fn rng_fill_bytes_coverage() {
        let mut rng = Rng::from_seed(42);
        let mut buf = [0u8; 256];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn ct_test_constant_operation_passes() {
        let outcome = ct_test(99, super::Rng::next_u8, super::Rng::next_u8, |&x| {
            core::hint::black_box(x.wrapping_add(1));
        });
        assert_no_timing_leak!(outcome);
    }
}
