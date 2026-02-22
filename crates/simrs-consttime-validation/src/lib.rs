//! DudeCT-style constant-time validation utilities for cryptographic code.
//!
//! Provides a reusable test harness based on the online Welch's t-test from:
//!   Reparaz, Balasch, Verbauwhede -- "Dude, is my code constant time?"
//!   (DATE 2017, ePrint 2016/1123)
//!
//! # Usage
//!
//! Other crates can depend on `simrs-consttime-validation` as a dev-dependency
//! to write constant-time integration tests:
//!
//! ```rust,no_run
//! use simrs_consttime_validation::{dudect_test, Rng, TestResult};
//!
//! let mut rng = Rng::from_entropy();
//! let result = dudect_test(
//!     "my_ct_op (class A vs class B)",
//!     10_000,
//!     &mut rng,
//!     |rng| rng.next_u8() & 0x7F,   // class 0: fixed pattern
//!     |rng| rng.next_u8() | 0x80,   // class 1: different pattern
//!     |&input| {
//!         core::hint::black_box(input.wrapping_mul(3));
//!     },
//! );
//! assert!(result.pass, "|t| = {:.3}, expected < 4.5", result.t_value.abs());
//! ```
//!
//! # Methodology
//!
//! For each sample, the harness randomly assigns the measurement to one of
//! two input classes, times the operation, and feeds the result into an online
//! Welch's t-test. After all samples, if |t| > 4.5 there is strong evidence
//! that the two classes have different timing distributions, indicating a
//! constant-time violation.
//!
//! A passing result does NOT prove constant-time behavior -- it means no
//! leakage was detected at the given sample count. Increase `--samples` for
//! higher confidence.
//!
//! IMPORTANT: Always compile with optimizations (`--release` or `opt-level >= 2`).
//! Debug builds produce false positives due to unoptimized code paths.

// ---------------------------------------------------------------------------
// Online Welch's t-test accumulator
// ---------------------------------------------------------------------------

/// Online accumulator for Welch's t-test across two input classes.
///
/// Maintains running sums in O(1) space per class, computing the t-statistic
/// on demand without storing individual measurements.
pub struct TTest {
    n: [u64; 2],
    sum: [f64; 2],
    sum_sq: [f64; 2],
}

impl TTest {
    /// Create a new empty accumulator.
    pub const fn new() -> Self {
        Self {
            n: [0; 2],
            sum: [0.0; 2],
            sum_sq: [0.0; 2],
        }
    }

    /// Record a timing measurement for the given class (0 or 1).
    pub fn push(&mut self, class: usize, value: f64) {
        self.n[class] += 1;
        self.sum[class] += value;
        self.sum_sq[class] += value * value;
    }

    /// Compute Welch's t-statistic. Returns 0.0 if insufficient samples.
    #[allow(clippy::cast_precision_loss)]
    pub fn t_value(&self) -> f64 {
        if self.n[0] < 2 || self.n[1] < 2 {
            return 0.0;
        }
        let n0 = self.n[0] as f64;
        let n1 = self.n[1] as f64;
        let mean0 = self.sum[0] / n0;
        let mean1 = self.sum[1] / n1;
        // Clamp to zero: floating-point cancellation can produce tiny negative
        // values when timing samples cluster at large magnitudes (nanoseconds).
        let var0 = ((self.sum_sq[0] - self.sum[0] * self.sum[0] / n0) / (n0 - 1.0)).max(0.0);
        let var1 = ((self.sum_sq[1] - self.sum[1] * self.sum[1] / n1) / (n1 - 1.0)).max(0.0);
        let se = (var0 / n0 + var1 / n1).sqrt();
        if se < 1e-15 {
            return 0.0;
        }
        (mean0 - mean1) / se
    }

    /// Total number of samples across both classes.
    pub const fn total_samples(&self) -> u64 {
        self.n[0] + self.n[1]
    }
}

impl Default for TTest {
    fn default() -> Self {
        Self::new()
    }
}

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
        Self(if seed == 0 { 0xDEAD_BEEF_CAFE_BABE } else { seed })
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
// Test result
// ---------------------------------------------------------------------------

/// Result of a single `DudeCT` timing test.
pub struct TestResult {
    /// Descriptive name of the test.
    pub name: &'static str,
    /// Total number of timing samples collected.
    pub samples: u64,
    /// Welch's t-statistic (signed).
    pub t_value: f64,
    /// Whether |t| < threshold (default 4.5).
    pub pass: bool,
}

impl TestResult {
    /// Print a one-line summary to stdout.
    pub fn report(&self) {
        let status = if self.pass { "PASS" } else { "FAIL" };
        println!(
            "  [{status}] {name:<40} n={samples:>8}  |t|={t:.3}",
            status = status,
            name = self.name,
            samples = self.samples,
            t = self.t_value.abs(),
        );
    }
}

// ---------------------------------------------------------------------------
// DudeCT test runner
// ---------------------------------------------------------------------------

/// The default threshold for |t| above which we declare timing leakage.
pub const DEFAULT_THRESHOLD: f64 = 4.5;

/// Run a `DudeCT` timing test.
///
/// Randomly assigns each of `samples` measurements to class 0 or class 1,
/// prepares the input using the corresponding closure, measures the
/// execution time of `run`, and accumulates into a Welch's t-test.
///
/// # Arguments
///
/// * `name` -- descriptive label for the test
/// * `samples` -- number of timing measurements to collect
/// * `rng` -- PRNG for input generation and class assignment
/// * `prepare_class0` -- generates an input for class 0 ("fixed" pattern)
/// * `prepare_class1` -- generates an input for class 1 ("random" pattern)
/// * `run` -- the operation under test
///
/// # Returns
///
/// A [`TestResult`] with the t-statistic and pass/fail determination.
pub fn dudect_test<T, F0, F1, R>(
    name: &'static str,
    samples: u64,
    rng: &mut Rng,
    prepare_class0: F0,
    prepare_class1: F1,
    run: R,
) -> TestResult
where
    F0: FnMut(&mut Rng) -> T,
    F1: FnMut(&mut Rng) -> T,
    R: FnMut(&T),
{
    dudect_test_with_threshold(
        name,
        samples,
        rng,
        prepare_class0,
        prepare_class1,
        run,
        DEFAULT_THRESHOLD,
    )
}

/// Like [`dudect_test`] but with a custom threshold.
pub fn dudect_test_with_threshold<T, F0, F1, R>(
    name: &'static str,
    samples: u64,
    rng: &mut Rng,
    mut prepare_class0: F0,
    mut prepare_class1: F1,
    mut run: R,
    threshold: f64,
) -> TestResult
where
    F0: FnMut(&mut Rng) -> T,
    F1: FnMut(&mut Rng) -> T,
    R: FnMut(&T),
{
    let mut ttest = TTest::new();

    for _ in 0..samples {
        let class = usize::from(!rng.next_bool());
        let input = if class == 0 {
            prepare_class0(rng)
        } else {
            prepare_class1(rng)
        };

        let start = std::time::Instant::now();
        run(&input);
        #[allow(clippy::cast_precision_loss)]
        let elapsed = start.elapsed().as_nanos() as f64;

        ttest.push(class, elapsed);
    }

    let t = ttest.t_value();
    TestResult {
        name,
        samples: ttest.total_samples(),
        t_value: t,
        pass: t.abs() < threshold,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_precision_loss, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn ttest_identical_distributions() {
        let mut tt = TTest::new();
        let mut rng = Rng::from_seed(42);
        for _ in 0..10_000 {
            let v = (rng.next_u64() % 1000) as f64;
            let class = usize::from(!rng.next_bool());
            tt.push(class, v);
        }
        assert!(
            tt.t_value().abs() < 4.5,
            "identical distributions: |t| = {:.3}",
            tt.t_value().abs()
        );
    }

    #[test]
    fn ttest_different_distributions() {
        let mut tt = TTest::new();
        for i in 0..5_000u64 {
            tt.push(0, 100.0 + (i % 10) as f64);
            tt.push(1, 200.0 + (i % 10) as f64);
        }
        assert!(
            tt.t_value().abs() > 100.0,
            "different distributions: |t| = {:.3}",
            tt.t_value().abs()
        );
    }

    #[test]
    fn ttest_empty() {
        let tt = TTest::new();
        assert_eq!(tt.t_value(), 0.0);
        assert_eq!(tt.total_samples(), 0);
    }

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
    fn dudect_constant_operation_passes() {
        let mut rng = Rng::from_seed(99);
        let result = dudect_test(
            "trivial add (constant-time)",
            10_000,
            &mut rng,
            Rng::next_u8,
            Rng::next_u8,
            |&x| {
                core::hint::black_box(x.wrapping_add(1));
            },
        );
        assert!(result.pass, "|t| = {:.3}", result.t_value.abs());
    }

    #[test]
    fn test_result_fields() {
        let r = TestResult {
            name: "test",
            samples: 1000,
            t_value: 1.5,
            pass: true,
        };
        assert_eq!(r.name, "test");
        assert_eq!(r.samples, 1000);
        assert!(r.pass);
    }
}
