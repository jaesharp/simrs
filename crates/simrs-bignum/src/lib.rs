//! Const-generic big integer arithmetic for RSA.
//!
//! Provides [`BigUint`], a fixed-size unsigned integer stored as `[u64; LIMBS]`
//! in little-endian limb order (limb 0 = least significant 64 bits), with
//! constant-time arithmetic suitable for cryptographic applications.
//!
//! The primary use case is RSA modular exponentiation via Montgomery
//! multiplication. All arithmetic operations are constant-time: execution
//! time and memory access patterns do not depend on operand values.
//!
//! # Montgomery multiplication
//!
//! [`MontParams`] precomputes the Montgomery parameters for a given odd
//! modulus, and [`mod_exp`] performs constant-time modular exponentiation
//! using the square-and-always-multiply method with [`CtSelect`] to prevent
//! timing side channels.
//!
//! # References
//!
//! - P. L. Montgomery, "Modular multiplication without trial division",
//!   Mathematics of Computation 44(170):519--521, April 1985.
//! - C. K. Koc, T. Acar, B. S. Kaliski Jr., "Analyzing and Comparing
//!   Montgomery Multiplication Algorithms", IEEE Micro 16(3):26--33, June 1996.
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All operations are performed on stack values.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::{CtBool, CtSelect, CtZero};

// ---------------------------------------------------------------------------
// BigUint<LIMBS>
// ---------------------------------------------------------------------------

/// A fixed-size unsigned integer stored as `[u64; LIMBS]` in little-endian
/// limb order.
///
/// `limbs[0]` holds the least significant 64 bits. This representation
/// simplifies carry propagation in addition and multiplication.
#[derive(Clone, Copy, Debug)]
pub struct BigUint<const LIMBS: usize> {
    /// Little-endian limbs.
    pub limbs: [u64; LIMBS],
}

impl<const LIMBS: usize> BigUint<LIMBS> {
    /// The zero value.
    pub const ZERO: Self = Self { limbs: [0; LIMBS] };

    /// Construct from a single `u64` value, placed in the least significant
    /// limb.
    pub const fn from_u64(val: u64) -> Self {
        let mut limbs = [0u64; LIMBS];
        if LIMBS > 0 {
            limbs[0] = val;
        }
        Self { limbs }
    }

    /// Decode from a big-endian byte slice.
    ///
    /// If the slice is shorter than `LIMBS * 8` bytes, the value is
    /// right-justified (padded with leading zeros). If the slice is longer,
    /// only the last `LIMBS * 8` bytes are used (higher bytes are silently
    /// truncated).
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; LIMBS];
        let capacity = LIMBS * 8;

        // Work from the least significant byte (end of input) toward MSB.
        let len = bytes.len();
        let mut byte_idx = 0usize;
        while byte_idx < len && byte_idx < capacity {
            let byte_val = bytes[len - 1 - byte_idx];
            let limb_idx = byte_idx / 8;
            let shift = (byte_idx % 8) * 8;
            limbs[limb_idx] |= u64::from(byte_val) << shift;
            byte_idx += 1;
        }

        Self { limbs }
    }

    /// Encode to a big-endian byte buffer.
    ///
    /// The buffer must have length `>= LIMBS * 8`. If the buffer is
    /// exactly `LIMBS * 8` bytes, the full value is written. If the buffer
    /// is larger, the value is right-justified (leading bytes are zeroed).
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < LIMBS * 8`.
    pub fn to_be_bytes(&self, buf: &mut [u8]) {
        let needed = LIMBS * 8;
        assert!(
            buf.len() >= needed,
            "buffer too small: need {needed}, got {}",
            buf.len()
        );

        // Zero the leading portion if buffer is oversized.
        let offset = buf.len() - needed;
        let mut idx = 0;
        while idx < offset {
            buf[idx] = 0;
            idx += 1;
        }

        // Write limbs in big-endian order (most significant limb first).
        let mut limb_idx = LIMBS;
        while limb_idx > 0 {
            limb_idx -= 1;
            let be = self.limbs[limb_idx].to_be_bytes();
            let dst_start = offset + (LIMBS - 1 - limb_idx) * 8;
            let mut byte_pos = 0;
            while byte_pos < 8 {
                buf[dst_start + byte_pos] = be[byte_pos];
                byte_pos += 1;
            }
        }
    }

    // -- Arithmetic ----------------------------------------------------------

    /// Addition with carry out. Returns `(sum, carry)`.
    ///
    /// Constant-time: the carry chain always processes all limbs.
    pub const fn add(&self, rhs: &Self) -> (Self, bool) {
        let mut result = [0u64; LIMBS];
        let mut carry = false;
        let mut idx = 0;
        while idx < LIMBS {
            let (s1, c1) = self.limbs[idx].overflowing_add(rhs.limbs[idx]);
            let (s2, c2) = s1.overflowing_add(if carry { 1 } else { 0 });
            result[idx] = s2;
            carry = c1 | c2;
            idx += 1;
        }
        (Self { limbs: result }, carry)
    }

    /// Subtraction with borrow out. Returns `(difference, borrow)`.
    ///
    /// Constant-time: the borrow chain always processes all limbs.
    pub const fn sub(&self, rhs: &Self) -> (Self, bool) {
        let mut result = [0u64; LIMBS];
        let mut borrow = false;
        let mut idx = 0;
        while idx < LIMBS {
            let (d1, b1) = self.limbs[idx].overflowing_sub(rhs.limbs[idx]);
            let (d2, b2) = d1.overflowing_sub(if borrow { 1 } else { 0 });
            result[idx] = d2;
            borrow = b1 | b2;
            idx += 1;
        }
        (Self { limbs: result }, borrow)
    }

    /// Constant-time comparison. Returns -1, 0, or 1.
    ///
    /// Uses [`CtBool`] internally to avoid data-dependent branches.
    /// Returns -1 if `self < rhs`, 0 if equal, 1 if `self > rhs`.
    pub fn ct_cmp(&self, rhs: &Self) -> i8 {
        // Walk from most significant limb to least significant.
        // Track the result using constant-time flags.
        let mut gt = CtBool::FALSE; // self > rhs established
        let mut lt = CtBool::FALSE; // self < rhs established
        let mut idx = LIMBS;
        while idx > 0 {
            idx -= 1;
            let lhs_limb = self.limbs[idx];
            let rhs_limb = rhs.limbs[idx];
            // "not yet decided" = neither gt nor lt is set
            let undecided = gt.or(lt).not();
            // This limb decides only if we haven't decided yet.
            let lhs_gt = ct_gt_u64(lhs_limb, rhs_limb);
            let rhs_gt = ct_gt_u64(rhs_limb, lhs_limb);
            gt = gt.or(undecided.and(lhs_gt));
            lt = lt.or(undecided.and(rhs_gt));
        }
        // gt => 1, lt => -1, else 0
        let gt_val = i8::from(gt.into_bool());
        let lt_val = i8::from(lt.into_bool());
        gt_val - lt_val
    }

    /// Constant-time zero check.
    pub fn ct_is_zero(&self) -> bool {
        self.limbs.ct_is_zero().into_bool()
    }

    /// Shift left by 1 bit. Returns `(result, carry_out)`.
    ///
    /// The carry out is the former most significant bit.
    pub const fn shl1(&self) -> (Self, bool) {
        let mut result = [0u64; LIMBS];
        let mut carry = 0u64;
        let mut idx = 0;
        while idx < LIMBS {
            let new_carry = self.limbs[idx] >> 63;
            result[idx] = (self.limbs[idx] << 1) | carry;
            carry = new_carry;
            idx += 1;
        }
        (Self { limbs: result }, carry != 0)
    }

    /// Shift right by 1 bit.
    ///
    /// The most significant bit of the result is always zero.
    #[must_use]
    pub const fn shr1(&self) -> Self {
        let mut result = [0u64; LIMBS];
        let mut idx = LIMBS;
        let mut carry = 0u64;
        while idx > 0 {
            idx -= 1;
            let new_carry = self.limbs[idx] << 63;
            result[idx] = (self.limbs[idx] >> 1) | carry;
            carry = new_carry;
        }
        Self { limbs: result }
    }
}

// ---------------------------------------------------------------------------
// Helper: constant-time u64 greater-than
// ---------------------------------------------------------------------------

/// Returns `CtBool::TRUE` if `lhs > rhs`, `FALSE` otherwise.
///
/// Uses the borrow from `rhs - lhs`: if `rhs < lhs`, the subtraction borrows.
#[inline]
const fn ct_gt_u64(lhs: u64, rhs: u64) -> CtBool {
    let (_, borrow) = rhs.overflowing_sub(lhs);
    CtBool::from_u8_bit(if borrow { 1 } else { 0 })
}

// ---------------------------------------------------------------------------
// Wide multiplication
// ---------------------------------------------------------------------------

/// Schoolbook multiplication of `lhs[0..LIMBS] * rhs[0..LIMBS]` into `out`.
///
/// `out` must have length `>= 2 * LIMBS` and is zeroed before use.
/// Uses `u128` intermediates for carry-free inner products.
///
/// # Panics
///
/// Panics if `out.len() < 2 * LIMBS`.
#[allow(clippy::cast_possible_truncation)]
pub fn mul_wide_into<const LIMBS: usize>(
    lhs: &[u64; LIMBS],
    rhs: &[u64; LIMBS],
    out: &mut [u64],
) {
    assert!(
        out.len() >= 2 * LIMBS,
        "output buffer too small: need {}, got {}",
        2 * LIMBS,
        out.len()
    );

    // Zero the output.
    let mut idx = 0;
    while idx < out.len() {
        out[idx] = 0;
        idx += 1;
    }

    let mut row = 0;
    while row < LIMBS {
        let mut carry: u128 = 0;
        let mut col = 0;
        while col < LIMBS {
            let prod = u128::from(lhs[row]) * u128::from(rhs[col])
                + u128::from(out[row + col])
                + carry;
            out[row + col] = prod as u64;
            carry = prod >> 64;
            col += 1;
        }
        out[row + LIMBS] = carry as u64;
        row += 1;
    }
}

// ---------------------------------------------------------------------------
// Montgomery parameters
// ---------------------------------------------------------------------------

/// Precomputed Montgomery parameters for an odd modulus `n`.
///
/// Montgomery multiplication computes `a * b * R^{-1} mod n` where
/// `R = 2^{64*LIMBS}`. This is efficient because division by `R` is
/// just a right shift when working modulo `R`.
///
/// # Fields
///
/// - `n`: the modulus (must be odd)
/// - `n_prime`: `-n^{-1} mod 2^{64}`, used in the CIOS reduction step
/// - `r_squared`: `R^2 mod n`, used to convert values into Montgomery form
#[derive(Clone, Debug)]
pub struct MontParams<const LIMBS: usize> {
    /// The modulus.
    pub n: [u64; LIMBS],
    /// `-n^{-1} mod 2^{64}`.
    pub n_prime: u64,
    /// `R^2 mod n`.
    pub r_squared: [u64; LIMBS],
}

impl<const LIMBS: usize> MontParams<LIMBS> {
    /// Precompute Montgomery parameters for the given odd modulus.
    ///
    /// # Panics
    ///
    /// Panics if `n` is even (bit 0 of `n.limbs[0]` must be 1).
    pub fn new(modulus: &BigUint<LIMBS>) -> Self {
        assert!(
            LIMBS > 0 && modulus.limbs[0] & 1 == 1,
            "Montgomery modulus must be odd and non-empty"
        );

        let n_prime = compute_n_prime(modulus.limbs[0]);
        let r_squared = compute_r_squared(&modulus.limbs);

        Self {
            n: modulus.limbs,
            n_prime,
            r_squared,
        }
    }
}

/// Compute `-n^{-1} mod 2^{64}` using the Newton-Hensel lifting method.
///
/// Starting from the trivial inverse `x = 1` (since `n` is odd, `n * 1 = 1 mod 2`),
/// we repeatedly double the precision: `x = x * (2 - n * x) mod 2^k`.
/// After 6 iterations we have 64 bits of precision.
const fn compute_n_prime(n0: u64) -> u64 {
    // n0 is odd, so n0^{-1} mod 2 = 1.
    let mut inv = 1u64;
    // Each iteration doubles precision: 1 -> 2 -> 4 -> 8 -> 16 -> 32 -> 64 bits.
    let mut step = 0;
    while step < 6 {
        // inv = inv * (2 - n0 * inv) mod 2^64
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
        step += 1;
    }
    // We want -n^{-1} mod 2^64.
    inv.wrapping_neg()
}

/// Compute `R^2 mod n` where `R = 2^{64*LIMBS}`.
///
/// Uses the shift-and-subtract method: start with 1 and left-shift
/// `2 * 64 * LIMBS` times, reducing mod n after each shift.
fn compute_r_squared<const LIMBS: usize>(modulus: &[u64; LIMBS]) -> [u64; LIMBS] {
    // Start with value = 1.
    let mut val = [0u64; LIMBS];
    val[0] = 1;

    // Shift left 1 bit at a time, reducing mod n after each shift.
    // We need 2 * 64 * LIMBS shifts total to get R^2 mod n.
    let total_shifts = 2 * 64 * LIMBS;
    let mut step = 0;
    while step < total_shifts {
        // Shift left by 1.
        let mut carry = 0u64;
        let mut idx = 0;
        while idx < LIMBS {
            let new_carry = val[idx] >> 63;
            val[idx] = (val[idx] << 1) | carry;
            carry = new_carry;
            idx += 1;
        }

        // If carry or val >= n, subtract n.
        let (sub_result, borrow) = sub_limbs::<LIMBS>(&val, modulus);

        // Use subtracted result if no borrow (val >= n) or if carry was set.
        let use_sub = carry != 0 || !borrow;
        ct_assign_limbs(&mut val, &sub_result, use_sub);

        step += 1;
    }

    val
}

/// Constant-time conditional assignment: `dst = src` if `cond` is true.
#[inline]
fn ct_assign_limbs<const LIMBS: usize>(
    dst: &mut [u64; LIMBS],
    src: &[u64; LIMBS],
    cond: bool,
) {
    let cond_ct = if cond {
        CtBool::TRUE
    } else {
        CtBool::FALSE
    };
    let mask = cond_ct.as_u64_mask();
    let mut idx = 0;
    while idx < LIMBS {
        dst[idx] ^= mask & (dst[idx] ^ src[idx]);
        idx += 1;
    }
}

/// Subtract two limb arrays: `lhs - rhs`. Returns `(result, borrow)`.
fn sub_limbs<const LIMBS: usize>(
    lhs: &[u64; LIMBS],
    rhs: &[u64; LIMBS],
) -> ([u64; LIMBS], bool) {
    let mut result = [0u64; LIMBS];
    let mut borrow = false;
    let mut idx = 0;
    while idx < LIMBS {
        let (d1, b1) = lhs[idx].overflowing_sub(rhs[idx]);
        let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
        result[idx] = d2;
        borrow = b1 | b2;
        idx += 1;
    }
    (result, borrow)
}

// ---------------------------------------------------------------------------
// Montgomery multiplication (CIOS)
// ---------------------------------------------------------------------------

/// Montgomery multiplication: computes `a * b * R^{-1} mod n`.
///
/// Uses the Coarsely Integrated Operand Scanning (CIOS) method, which
/// interleaves multiplication and reduction to avoid storing the full
/// double-width product.
///
/// The algorithm processes one limb of `a` per outer iteration, accumulating
/// partial products into a working register `t[0..LIMBS+2]` and immediately
/// reducing by one word of `R` via the Montgomery quotient `m`.
///
/// # Panics
///
/// Panics if `LIMBS + 2 > 66` (i.e., LIMBS > 64, exceeding 4096-bit keys).
#[allow(clippy::cast_possible_truncation)]
pub fn mont_mul<const LIMBS: usize>(
    lhs: &BigUint<LIMBS>,
    rhs: &BigUint<LIMBS>,
    params: &MontParams<LIMBS>,
) -> BigUint<LIMBS> {
    // Working register: LIMBS + 2 words to absorb intermediate carries.
    let mut work = [0u64; MAX_MONT_LIMBS];
    assert!(
        LIMBS + 2 <= MAX_MONT_LIMBS,
        "LIMBS too large for mont_mul (max {})",
        MAX_MONT_LIMBS - 2
    );

    let mut outer = 0;
    while outer < LIMBS {
        // Step 1: work += lhs[outer] * rhs
        let mut carry: u128 = 0;
        let mut inner = 0;
        while inner < LIMBS {
            let prod = u128::from(lhs.limbs[outer]) * u128::from(rhs.limbs[inner])
                + u128::from(work[inner])
                + carry;
            work[inner] = prod as u64;
            carry = prod >> 64;
            inner += 1;
        }
        let sum = u128::from(work[LIMBS]) + carry;
        work[LIMBS] = sum as u64;
        work[LIMBS + 1] = (sum >> 64) as u64;

        // Step 2: Montgomery reduction for this row.
        // Compute m such that (work[0] + m*n[0]) = 0 mod 2^64.
        let mont_quot = work[0].wrapping_mul(params.n_prime);

        // First limb: (work[0] + m*n[0]) has low word = 0 by construction.
        // We only need the carry.
        let prod0 =
            u128::from(mont_quot) * u128::from(params.n[0]) + u128::from(work[0]);
        carry = prod0 >> 64;

        // Remaining limbs: compute work[j] + m*n[j] + carry, shift down by 1.
        inner = 1;
        while inner < LIMBS {
            let prod = u128::from(mont_quot) * u128::from(params.n[inner])
                + u128::from(work[inner])
                + carry;
            work[inner - 1] = prod as u64;
            carry = prod >> 64;
            inner += 1;
        }
        // Absorb carry into work[LIMBS-1] from work[LIMBS].
        let sum2 = u128::from(work[LIMBS]) + carry;
        work[LIMBS - 1] = sum2 as u64;
        work[LIMBS] = work[LIMBS + 1] + (sum2 >> 64) as u64;
        work[LIMBS + 1] = 0;

        outer += 1;
    }

    // Final conditional subtraction: if work >= n, subtract n.
    let mut result = [0u64; LIMBS];
    let mut idx = 0;
    while idx < LIMBS {
        result[idx] = work[idx];
        idx += 1;
    }

    let (sub_result, borrow) = sub_limbs::<LIMBS>(&result, &params.n);
    // If work[LIMBS] != 0 or no borrow from subtraction, use the subtracted result.
    let overflow = work[LIMBS] != 0;
    let use_sub = overflow || !borrow;
    ct_assign_limbs::<LIMBS>(&mut result, &sub_result, use_sub);

    BigUint { limbs: result }
}

/// Maximum number of limbs supported in Montgomery multiplication.
///
/// Supports up to 4096-bit RSA keys (64 limbs) with 2 overflow words.
const MAX_MONT_LIMBS: usize = 66;

/// Convert a value to Montgomery form: `a * R mod n`.
///
/// Computed as `mont_mul(a, R^2, params)`, since
/// `a * R^2 * R^{-1} = a * R mod n`.
pub fn to_mont<const LIMBS: usize>(
    val: &BigUint<LIMBS>,
    params: &MontParams<LIMBS>,
) -> BigUint<LIMBS> {
    let r_sq = BigUint {
        limbs: params.r_squared,
    };
    mont_mul(val, &r_sq, params)
}

/// Convert from Montgomery form back to standard representation.
///
/// Computed as `mont_mul(a, 1, params)`, since
/// `a * 1 * R^{-1} = a * R^{-1} mod n`.
pub fn from_mont<const LIMBS: usize>(
    val: &BigUint<LIMBS>,
    params: &MontParams<LIMBS>,
) -> BigUint<LIMBS> {
    let one = BigUint::from_u64(1);
    mont_mul(val, &one, params)
}

// ---------------------------------------------------------------------------
// Modular exponentiation
// ---------------------------------------------------------------------------

/// Constant-time modular exponentiation: `base^exp mod n`.
///
/// Uses the left-to-right binary (square-and-always-multiply) method
/// with constant-time selection via [`CtSelect`], ensuring the operation
/// sequence is identical regardless of the exponent value.
///
/// # Algorithm
///
/// ```text
/// r0 = to_mont(1)     // Montgomery form of 1
/// r1 = to_mont(base)  // Montgomery form of base
/// for each bit of exp from MSB to LSB:
///     r0 = mont_mul(r0, r0)  // always square
///     t  = mont_mul(r0, r1)  // always multiply
///     r0 = ct_select(bit, t, r0)  // constant-time select
/// return from_mont(r0)
/// ```
pub fn mod_exp<const LIMBS: usize>(
    base: &BigUint<LIMBS>,
    exp: &BigUint<LIMBS>,
    params: &MontParams<LIMBS>,
) -> BigUint<LIMBS> {
    let mut accumulator = to_mont(&BigUint::from_u64(1), params);
    let base_mont = to_mont(base, params);

    // Process all bits from MSB to LSB.
    // Total bits = LIMBS * 64.
    let total_bits = LIMBS * 64;
    let mut bit_pos = total_bits;
    while bit_pos > 0 {
        bit_pos -= 1;
        let limb_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;
        let bit = (exp.limbs[limb_idx] >> bit_idx) & 1;
        let bit_ct = CtBool::from_u64_bit(bit);

        // Always square.
        accumulator = mont_mul(&accumulator, &accumulator, params);

        // Always multiply.
        let candidate = mont_mul(&accumulator, &base_mont, params);

        // Constant-time select: accumulator = bit ? candidate : accumulator.
        accumulator.limbs =
            <[u64; LIMBS]>::ct_select(bit_ct, &candidate.limbs, &accumulator.limbs);
    }

    from_mont(&accumulator, params)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // -- BigUint basic construction ------------------------------------------

    #[test]
    fn zero_is_zero() {
        let z = BigUint::<4>::ZERO;
        assert!(z.ct_is_zero());
        assert_eq!(z.limbs, [0, 0, 0, 0]);
    }

    #[test]
    fn from_u64_small() {
        let val = BigUint::<4>::from_u64(42);
        assert_eq!(val.limbs[0], 42);
        assert_eq!(val.limbs[1], 0);
        assert_eq!(val.limbs[2], 0);
        assert_eq!(val.limbs[3], 0);
    }

    #[test]
    fn from_u64_max() {
        let val = BigUint::<2>::from_u64(u64::MAX);
        assert_eq!(val.limbs[0], u64::MAX);
        assert_eq!(val.limbs[1], 0);
    }

    // -- from_be_bytes / to_be_bytes roundtrip --------------------------------

    #[test]
    fn be_bytes_roundtrip_full() {
        // 2 limbs = 16 bytes
        let bytes: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
            0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let val = BigUint::<2>::from_be_bytes(&bytes);
        let mut out = [0u8; 16];
        val.to_be_bytes(&mut out);
        assert_eq!(out, bytes);
    }

    #[test]
    fn be_bytes_roundtrip_short_input() {
        // Only 3 bytes -> value = 0x01_02_03 in 2 limbs (16 byte capacity)
        let bytes = [0x01, 0x02, 0x03];
        let val = BigUint::<2>::from_be_bytes(&bytes);
        let mut out = [0u8; 16];
        val.to_be_bytes(&mut out);
        // Should be zero-padded on the left.
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3];
        assert_eq!(out, expected);
    }

    #[test]
    fn be_bytes_single_byte() {
        let val = BigUint::<1>::from_be_bytes(&[0xFF]);
        assert_eq!(val.limbs[0], 0xFF);
    }

    #[test]
    fn be_bytes_empty() {
        let val = BigUint::<2>::from_be_bytes(&[]);
        assert!(val.ct_is_zero());
    }

    // -- Addition -------------------------------------------------------------

    #[test]
    fn add_zero_plus_zero() {
        let z = BigUint::<2>::ZERO;
        let (sum, carry) = z.add(&z);
        assert!(sum.ct_is_zero());
        assert!(!carry);
    }

    #[test]
    fn add_known_sum() {
        let lhs = BigUint::<2>::from_u64(100);
        let rhs = BigUint::<2>::from_u64(200);
        let (sum, carry) = lhs.add(&rhs);
        assert_eq!(sum.limbs[0], 300);
        assert_eq!(sum.limbs[1], 0);
        assert!(!carry);
    }

    #[test]
    fn add_carry_propagation() {
        let lhs = BigUint::<2> {
            limbs: [u64::MAX, 0],
        };
        let rhs = BigUint::<2>::from_u64(1);
        let (sum, carry) = lhs.add(&rhs);
        assert_eq!(sum.limbs[0], 0);
        assert_eq!(sum.limbs[1], 1);
        assert!(!carry);
    }

    #[test]
    fn add_max_plus_one_wraps() {
        let max = BigUint::<2> {
            limbs: [u64::MAX, u64::MAX],
        };
        let one = BigUint::<2>::from_u64(1);
        let (sum, carry) = max.add(&one);
        assert_eq!(sum.limbs[0], 0);
        assert_eq!(sum.limbs[1], 0);
        assert!(carry);
    }

    // -- Subtraction ----------------------------------------------------------

    #[test]
    fn sub_known_difference() {
        let lhs = BigUint::<2>::from_u64(300);
        let rhs = BigUint::<2>::from_u64(100);
        let (diff, borrow) = lhs.sub(&rhs);
        assert_eq!(diff.limbs[0], 200);
        assert!(!borrow);
    }

    #[test]
    fn sub_with_borrow_propagation() {
        let lhs = BigUint::<2> {
            limbs: [0, 1], // = 2^64
        };
        let rhs = BigUint::<2>::from_u64(1);
        let (diff, borrow) = lhs.sub(&rhs);
        assert_eq!(diff.limbs[0], u64::MAX);
        assert_eq!(diff.limbs[1], 0);
        assert!(!borrow);
    }

    #[test]
    fn sub_underflow_borrows() {
        let lhs = BigUint::<2>::from_u64(0);
        let rhs = BigUint::<2>::from_u64(1);
        let (_, borrow) = lhs.sub(&rhs);
        assert!(borrow);
    }

    // -- ct_cmp ---------------------------------------------------------------

    #[test]
    fn ct_cmp_equal() {
        let val = BigUint::<2>::from_u64(42);
        assert_eq!(val.ct_cmp(&val), 0);
    }

    #[test]
    fn ct_cmp_less() {
        let lhs = BigUint::<2>::from_u64(10);
        let rhs = BigUint::<2>::from_u64(20);
        assert_eq!(lhs.ct_cmp(&rhs), -1);
    }

    #[test]
    fn ct_cmp_greater() {
        let lhs = BigUint::<2>::from_u64(20);
        let rhs = BigUint::<2>::from_u64(10);
        assert_eq!(lhs.ct_cmp(&rhs), 1);
    }

    #[test]
    fn ct_cmp_high_limb() {
        let lhs = BigUint::<2> { limbs: [0, 1] };
        let rhs = BigUint::<2> { limbs: [u64::MAX, 0] };
        assert_eq!(lhs.ct_cmp(&rhs), 1); // 2^64 > 2^64 - 1
    }

    #[test]
    fn ct_cmp_zeros() {
        let z = BigUint::<4>::ZERO;
        assert_eq!(z.ct_cmp(&z), 0);
    }

    // -- ct_is_zero -----------------------------------------------------------

    #[test]
    fn ct_is_zero_yes() {
        assert!(BigUint::<4>::ZERO.ct_is_zero());
    }

    #[test]
    fn ct_is_zero_no() {
        assert!(!BigUint::<4>::from_u64(1).ct_is_zero());
    }

    #[test]
    fn ct_is_zero_high_limb() {
        let val = BigUint::<4> {
            limbs: [0, 0, 0, 1],
        };
        assert!(!val.ct_is_zero());
    }

    // -- shl1 / shr1 ---------------------------------------------------------

    #[test]
    fn shl1_basic() {
        let val = BigUint::<2>::from_u64(0x4000_0000_0000_0000);
        let (shifted, carry) = val.shl1();
        assert_eq!(shifted.limbs[0], 0x8000_0000_0000_0000);
        assert_eq!(shifted.limbs[1], 0);
        assert!(!carry);
    }

    #[test]
    fn shl1_carry_across_limbs() {
        let val = BigUint::<2>::from_u64(0x8000_0000_0000_0000);
        let (shifted, carry) = val.shl1();
        assert_eq!(shifted.limbs[0], 0);
        assert_eq!(shifted.limbs[1], 1);
        assert!(!carry);
    }

    #[test]
    fn shl1_carry_out() {
        let val = BigUint::<2> {
            limbs: [0, 0x8000_0000_0000_0000],
        };
        let (_, carry) = val.shl1();
        assert!(carry);
    }

    #[test]
    fn shr1_basic() {
        let val = BigUint::<2>::from_u64(4);
        let shifted = val.shr1();
        assert_eq!(shifted.limbs[0], 2);
    }

    #[test]
    fn shr1_carry_across_limbs() {
        let val = BigUint::<2> { limbs: [0, 1] };
        let shifted = val.shr1();
        assert_eq!(shifted.limbs[0], 0x8000_0000_0000_0000);
        assert_eq!(shifted.limbs[1], 0);
    }

    #[test]
    fn shr1_drops_lsb() {
        let val = BigUint::<2>::from_u64(3);
        let shifted = val.shr1();
        assert_eq!(shifted.limbs[0], 1);
    }

    // -- Montgomery: n_prime computation -------------------------------------

    #[test]
    fn n_prime_small_odd() {
        // n0 = 3: verify n_prime * n0 = -1 mod 2^64.
        let n0: u64 = 3;
        let np = compute_n_prime(n0);
        assert_eq!(np.wrapping_mul(n0), u64::MAX); // -1 mod 2^64
    }

    #[test]
    fn n_prime_large_odd() {
        let n0: u64 = 0xFFFF_FFFF_FFFF_FFFD; // a large odd number
        let np = compute_n_prime(n0);
        assert_eq!(np.wrapping_mul(n0), u64::MAX);
    }

    // -- Montgomery multiplication -------------------------------------------

    #[test]
    fn mont_roundtrip_identity() {
        // Use a small 1-limb modulus: n = 7.
        let modulus = BigUint::<1>::from_u64(7);
        let params = MontParams::new(&modulus);
        let val = BigUint::<1>::from_u64(3);

        let val_mont = to_mont(&val, &params);
        let val_back = from_mont(&val_mont, &params);
        assert_eq!(val_back.limbs[0], 3);
    }

    #[test]
    fn mont_roundtrip_identity_2limb() {
        // n = 2^64 + 1 = 0x1_0000_0000_0000_0001 (odd, 2 limbs)
        let modulus = BigUint::<2> {
            limbs: [1, 1],
        };
        let params = MontParams::new(&modulus);

        let val = BigUint::<2>::from_u64(42);
        let val_mont = to_mont(&val, &params);
        let val_back = from_mont(&val_mont, &params);
        assert_eq!(val_back.limbs, [42, 0]);
    }

    #[test]
    fn mont_mul_product() {
        // n = 17, a = 3, b = 5. 3 * 5 = 15 mod 17.
        let modulus = BigUint::<1>::from_u64(17);
        let params = MontParams::new(&modulus);

        let lhs = BigUint::<1>::from_u64(3);
        let rhs = BigUint::<1>::from_u64(5);

        let lhs_m = to_mont(&lhs, &params);
        let rhs_m = to_mont(&rhs, &params);
        let prod_m = mont_mul(&lhs_m, &rhs_m, &params);
        let prod = from_mont(&prod_m, &params);

        assert_eq!(prod.limbs[0], 15);
    }

    #[test]
    fn mont_mul_with_reduction() {
        // n = 13, a = 7, b = 8. 7 * 8 = 56 = 4 * 13 + 4. So 56 mod 13 = 4.
        let modulus = BigUint::<1>::from_u64(13);
        let params = MontParams::new(&modulus);

        let lhs = BigUint::<1>::from_u64(7);
        let rhs = BigUint::<1>::from_u64(8);

        let lhs_m = to_mont(&lhs, &params);
        let rhs_m = to_mont(&rhs, &params);
        let prod_m = mont_mul(&lhs_m, &rhs_m, &params);
        let prod = from_mont(&prod_m, &params);

        assert_eq!(prod.limbs[0], 4); // 56 mod 13 = 4
    }

    #[test]
    fn mont_mul_commutativity() {
        let modulus = BigUint::<1>::from_u64(97);
        let params = MontParams::new(&modulus);

        let lhs = BigUint::<1>::from_u64(33);
        let rhs = BigUint::<1>::from_u64(71);

        let lhs_m = to_mont(&lhs, &params);
        let rhs_m = to_mont(&rhs, &params);

        let ab = from_mont(&mont_mul(&lhs_m, &rhs_m, &params), &params);
        let ba = from_mont(&mont_mul(&rhs_m, &lhs_m, &params), &params);
        assert_eq!(ab.limbs[0], ba.limbs[0]);
        assert_eq!(ab.limbs[0], (33u64 * 71) % 97);
    }

    #[test]
    fn mont_mul_consistency_with_to_mont() {
        // Verify: mont_mul(to_mont(a), to_mont(b)) = to_mont(a*b mod n)
        let modulus = BigUint::<1>::from_u64(251); // prime
        let params = MontParams::new(&modulus);

        let a_val = 100u64;
        let b_val = 200u64;
        let product_mod_n = (a_val * b_val) % 251;

        let lhs = BigUint::<1>::from_u64(a_val);
        let rhs = BigUint::<1>::from_u64(b_val);
        let expected = BigUint::<1>::from_u64(product_mod_n);

        let lhs_m = to_mont(&lhs, &params);
        let rhs_m = to_mont(&rhs, &params);
        let product_m = mont_mul(&lhs_m, &rhs_m, &params);
        let expected_m = to_mont(&expected, &params);

        assert_eq!(product_m.limbs[0], expected_m.limbs[0]);
    }

    // -- Modular exponentiation -----------------------------------------------

    #[test]
    fn mod_exp_two_pow_ten_mod_1009() {
        // 2^10 = 1024, 1024 mod 1009 = 15. (1009 is odd prime.)
        let base = BigUint::<1>::from_u64(2);
        let exp = BigUint::<1>::from_u64(10);
        let modulus = BigUint::<1>::from_u64(1009);
        let params = MontParams::new(&modulus);

        let result = mod_exp(&base, &exp, &params);
        assert_eq!(result.limbs[0], 15);
    }

    #[test]
    fn mod_exp_small_fermat() {
        // Fermat's little theorem: a^(p-1) = 1 mod p for prime p.
        // p = 97, a = 42. 42^96 mod 97 = 1.
        let base = BigUint::<1>::from_u64(42);
        let exp = BigUint::<1>::from_u64(96);
        let modulus = BigUint::<1>::from_u64(97);
        let params = MontParams::new(&modulus);

        let result = mod_exp(&base, &exp, &params);
        assert_eq!(result.limbs[0], 1);
    }

    #[test]
    fn mod_exp_base_one() {
        // 1^anything = 1 mod n.
        let base = BigUint::<1>::from_u64(1);
        let exp = BigUint::<1>::from_u64(12345);
        let modulus = BigUint::<1>::from_u64(97);
        let params = MontParams::new(&modulus);

        let result = mod_exp(&base, &exp, &params);
        assert_eq!(result.limbs[0], 1);
    }

    #[test]
    fn mod_exp_exponent_zero() {
        // a^0 = 1 mod n for any a != 0.
        let base = BigUint::<1>::from_u64(42);
        let exp = BigUint::<1>::ZERO;
        let modulus = BigUint::<1>::from_u64(97);
        let params = MontParams::new(&modulus);

        let result = mod_exp(&base, &exp, &params);
        assert_eq!(result.limbs[0], 1);
    }

    #[test]
    fn mod_exp_exponent_one() {
        // a^1 = a mod n.
        let base = BigUint::<1>::from_u64(42);
        let exp = BigUint::<1>::from_u64(1);
        let modulus = BigUint::<1>::from_u64(97);
        let params = MontParams::new(&modulus);

        let result = mod_exp(&base, &exp, &params);
        assert_eq!(result.limbs[0], 42);
    }

    #[test]
    fn mod_exp_known_value_2limb() {
        // n = 65537 (Fermat prime F4, fits in 1 limb but use 2 limbs).
        let modulus = BigUint::<2>::from_u64(65537);
        let params = MontParams::new(&modulus);

        // 2^16 mod 65537 = 65536 mod 65537 = 65536
        let base = BigUint::<2>::from_u64(2);
        let exp = BigUint::<2>::from_u64(16);
        let result = mod_exp(&base, &exp, &params);
        assert_eq!(result.limbs[0], 65536);
        assert_eq!(result.limbs[1], 0);

        // 2^17 mod 65537 = 131072 mod 65537 = 131072 - 65537 = 65535
        let exp17 = BigUint::<2>::from_u64(17);
        let result17 = mod_exp(&base, &exp17, &params);
        assert_eq!(result17.limbs[0], 65535);

        // Fermat: 2^65536 mod 65537 = 1 (65537 is prime)
        let exp_fermat = BigUint::<2>::from_u64(65536);
        let result_fermat = mod_exp(&base, &exp_fermat, &params);
        assert_eq!(result_fermat.limbs[0], 1);
        assert_eq!(result_fermat.limbs[1], 0);
    }

    #[test]
    fn mod_exp_larger_modulus() {
        // n = 2^127 - 1 = Mersenne prime M127 (2 limbs).
        let modulus = BigUint::<2> {
            limbs: [u64::MAX, 0x7FFF_FFFF_FFFF_FFFF],
        };
        let params = MontParams::new(&modulus);

        // 2^1 mod n = 2
        let base = BigUint::<2>::from_u64(2);
        let exp = BigUint::<2>::from_u64(1);
        let result = mod_exp(&base, &exp, &params);
        assert_eq!(result.limbs[0], 2);
        assert_eq!(result.limbs[1], 0);

        // 3^1 = 3 mod n
        let base3 = BigUint::<2>::from_u64(3);
        let result3 = mod_exp(&base3, &exp, &params);
        assert_eq!(result3.limbs[0], 3);
        assert_eq!(result3.limbs[1], 0);

        // a^0 = 1 mod n
        let exp0 = BigUint::<2>::ZERO;
        let result0 = mod_exp(&base3, &exp0, &params);
        assert_eq!(result0.limbs[0], 1);
        assert_eq!(result0.limbs[1], 0);
    }

    // -- Wide multiplication -------------------------------------------------

    #[test]
    fn mul_wide_small() {
        let lhs = [3u64; 1];
        let rhs = [7u64; 1];
        let mut out = [0u64; 2];
        mul_wide_into::<1>(&lhs, &rhs, &mut out);
        assert_eq!(out[0], 21);
        assert_eq!(out[1], 0);
    }

    #[test]
    fn mul_wide_overflow() {
        let lhs = [u64::MAX; 1];
        let rhs = [u64::MAX; 1];
        let mut out = [0u64; 2];
        mul_wide_into::<1>(&lhs, &rhs, &mut out);
        // (2^64-1)^2 = 2^128 - 2^65 + 1
        assert_eq!(out[0], 1);
        assert_eq!(out[1], 0xFFFF_FFFF_FFFF_FFFE);
    }

    #[test]
    fn mul_wide_2limb() {
        // (2^64 + 1) * (2^64 + 1) = 2^128 + 2^65 + 1
        let lhs = [1u64, 1u64];
        let rhs = [1u64, 1u64];
        let mut out = [0u64; 4];
        mul_wide_into::<2>(&lhs, &rhs, &mut out);
        assert_eq!(out[0], 1); // 1
        assert_eq!(out[1], 2); // 2 * 2^64
        assert_eq!(out[2], 1); // 2^128
        assert_eq!(out[3], 0);
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn add_sub_roundtrip(
            a_limbs in any::<[u64; 2]>(),
            b_limbs in any::<[u64; 2]>(),
        ) {
            let lhs = BigUint::<2> { limbs: a_limbs };
            let rhs = BigUint::<2> { limbs: b_limbs };
            let (sum, carry) = lhs.add(&rhs);
            if !carry {
                let (recovered, borrow) = sum.sub(&rhs);
                prop_assert!(!borrow);
                prop_assert_eq!(recovered.limbs, lhs.limbs);
            }
        }
    }

    proptest! {
        #[test]
        fn be_bytes_roundtrip(limbs in any::<[u64; 2]>()) {
            let val = BigUint::<2> { limbs };
            let mut buf = [0u8; 16];
            val.to_be_bytes(&mut buf);
            let recovered = BigUint::<2>::from_be_bytes(&buf);
            prop_assert_eq!(recovered.limbs, val.limbs);
        }
    }

    proptest! {
        #[test]
        fn ct_cmp_consistent_with_sub(
            a_limbs in any::<[u64; 2]>(),
            b_limbs in any::<[u64; 2]>(),
        ) {
            let lhs = BigUint::<2> { limbs: a_limbs };
            let rhs = BigUint::<2> { limbs: b_limbs };
            let cmp = lhs.ct_cmp(&rhs);
            let (_, lhs_borrows) = lhs.sub(&rhs);
            let (_, rhs_borrows) = rhs.sub(&lhs);
            let eq = !lhs_borrows && !rhs_borrows;
            if eq {
                prop_assert_eq!(cmp, 0);
            } else if lhs_borrows {
                prop_assert_eq!(cmp, -1);
            } else {
                prop_assert_eq!(cmp, 1);
            }
        }
    }

    proptest! {
        #[test]
        fn shl1_shr1_roundtrip(limbs in any::<[u64; 2]>()) {
            let val = BigUint::<2> { limbs };
            // If the MSB is 0, shl1 then shr1 recovers the value.
            if limbs[1] >> 63 == 0 {
                let (shifted, carry) = val.shl1();
                prop_assert!(!carry);
                let recovered = shifted.shr1();
                prop_assert_eq!(recovered.limbs, val.limbs);
            }
        }
    }

    // We need odd moduli > 1 for Montgomery arithmetic.
    fn arb_odd_modulus_1limb() -> impl Strategy<Value = u64> {
        (1u64..=u64::MAX / 2).prop_map(|v| v | 1).prop_filter(
            "modulus must be > 1",
            |&v| v > 1,
        )
    }

    proptest! {
        #[test]
        fn mont_mul_commutative(
            n_val in arb_odd_modulus_1limb(),
            a_raw in any::<u64>(),
            b_raw in any::<u64>(),
        ) {
            let modulus = BigUint::<1>::from_u64(n_val);
            let params = MontParams::new(&modulus);
            let lhs = BigUint::<1>::from_u64(a_raw % n_val);
            let rhs = BigUint::<1>::from_u64(b_raw % n_val);
            let lhs_m = to_mont(&lhs, &params);
            let rhs_m = to_mont(&rhs, &params);
            let ab = from_mont(&mont_mul(&lhs_m, &rhs_m, &params), &params);
            let ba = from_mont(&mont_mul(&rhs_m, &lhs_m, &params), &params);
            prop_assert_eq!(ab.limbs[0], ba.limbs[0]);
        }
    }

    proptest! {
        #[test]
        fn mont_roundtrip(
            n_val in arb_odd_modulus_1limb(),
            a_raw in any::<u64>(),
        ) {
            let modulus = BigUint::<1>::from_u64(n_val);
            let params = MontParams::new(&modulus);
            let a_val = a_raw % n_val;
            let val = BigUint::<1>::from_u64(a_val);
            let val_m = to_mont(&val, &params);
            let val_back = from_mont(&val_m, &params);
            prop_assert_eq!(val_back.limbs[0], a_val);
        }
    }

    proptest! {
        #[test]
        fn mont_mul_correct(
            n_val in arb_odd_modulus_1limb(),
            a_raw in any::<u64>(),
            b_raw in any::<u64>(),
        ) {
            let modulus = BigUint::<1>::from_u64(n_val);
            let params = MontParams::new(&modulus);
            let a_val = a_raw % n_val;
            let b_val = b_raw % n_val;
            let lhs = BigUint::<1>::from_u64(a_val);
            let rhs = BigUint::<1>::from_u64(b_val);
            let lhs_m = to_mont(&lhs, &params);
            let rhs_m = to_mont(&rhs, &params);
            let product = from_mont(&mont_mul(&lhs_m, &rhs_m, &params), &params);
            let expected = (u128::from(a_val) * u128::from(b_val)) % u128::from(n_val);
            prop_assert_eq!(product.limbs[0], expected as u64);
        }
    }

    proptest! {
        #[test]
        fn be_bytes_roundtrip_random_length(
            data in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let val = BigUint::<4>::from_be_bytes(&data);
            let mut buf = [0u8; 32];
            val.to_be_bytes(&mut buf);
            let recovered = BigUint::<4>::from_be_bytes(&buf);
            prop_assert_eq!(recovered.limbs, val.limbs);
        }
    }

    proptest! {
        #[test]
        fn ct_cmp_reflexive(limbs in any::<[u64; 2]>()) {
            let val = BigUint::<2> { limbs };
            prop_assert_eq!(val.ct_cmp(&val), 0);
        }
    }

    proptest! {
        #[test]
        fn ct_cmp_antisymmetric(
            a_limbs in any::<[u64; 2]>(),
            b_limbs in any::<[u64; 2]>(),
        ) {
            let lhs = BigUint::<2> { limbs: a_limbs };
            let rhs = BigUint::<2> { limbs: b_limbs };
            let ab = lhs.ct_cmp(&rhs);
            let ba = rhs.ct_cmp(&lhs);
            prop_assert_eq!(ab, -ba);
        }
    }

    proptest! {
        #[test]
        #[allow(clippy::similar_names)]
        fn mont_mul_associative(
            n_val in arb_odd_modulus_1limb(),
            a_raw in any::<u32>(),
            b_raw in any::<u32>(),
            c_raw in any::<u32>(),
        ) {
            let modulus = BigUint::<1>::from_u64(n_val);
            let params = MontParams::new(&modulus);
            let val_a = BigUint::<1>::from_u64(u64::from(a_raw) % n_val);
            let val_b = BigUint::<1>::from_u64(u64::from(b_raw) % n_val);
            let val_c = BigUint::<1>::from_u64(u64::from(c_raw) % n_val);
            let am = to_mont(&val_a, &params);
            let bm = to_mont(&val_b, &params);
            let cm = to_mont(&val_c, &params);

            // (a * b) * c
            let ab_m = mont_mul(&am, &bm, &params);
            let abc = from_mont(&mont_mul(&ab_m, &cm, &params), &params);

            // a * (b * c)
            let bc_m = mont_mul(&bm, &cm, &params);
            let abc2 = from_mont(&mont_mul(&am, &bc_m, &params), &params);

            prop_assert_eq!(abc.limbs[0], abc2.limbs[0]);
        }
    }

    proptest! {
        #[test]
        fn add_commutative(
            a_limbs in any::<[u64; 2]>(),
            b_limbs in any::<[u64; 2]>(),
        ) {
            let lhs = BigUint::<2> { limbs: a_limbs };
            let rhs = BigUint::<2> { limbs: b_limbs };
            let (sum_ab, carry_ab) = lhs.add(&rhs);
            let (sum_ba, carry_ba) = rhs.add(&lhs);
            prop_assert_eq!(sum_ab.limbs, sum_ba.limbs);
            prop_assert_eq!(carry_ab, carry_ba);
        }
    }
}
