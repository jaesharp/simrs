//! NIST P-256 (secp256r1) elliptic curve arithmetic per
//! [FIPS 186-4](../../../docs/specs/nist/fips-186-4/) and
//! [SEC 1 v2.0](../../../docs/specs/secg/).
//!
//! Implements field arithmetic over GF(p) where
//! p = 2^256 - 2^224 + 2^192 + 2^96 - 1,
//! Jacobian projective point operations, and constant-time scalar
//! multiplication for ECDH.
//!
//! # Design
//!
//! Field elements use 4x64-bit limbs (little-endian). The multiplication
//! path uses u128 intermediates and NIST fast reduction. Point operations
//! use Jacobian projective coordinates (X, Y, Z) where the affine point
//! is (X/Z^2, Y/Z^3).
//!
//! Scalar multiplication uses the double-and-always-add method with
//! conditional swap, making the operation sequence independent of the
//! scalar value. Point addition and doubling use constant-time
//! conditional moves to handle all exceptional cases (identity inputs,
//! point doubling, inverse points) without data-dependent branches.
//!
//! # Side-channel hardening
//!
//! To defend against Zero-Value Register Attacks (ZRA / Goubin 2003) and
//! Refined Power Analysis (RPA), scalar multiplication applies two
//! countermeasures before the Montgomery ladder:
//!
//! 1. **Projective coordinate randomization**: the input point (X:Y:Z) is
//!    replaced with (lambda^2 X : lambda^3 Y : lambda Z) for a non-zero
//!    lambda derived from the scalar via HMAC-SHA-256. This ensures no
//!    intermediate Z coordinate is algebraically zero.
//!
//! 2. **Scalar blinding**: the scalar k is replaced with k' = k + r*n
//!    (128-bit r, also HMAC-derived) so the ladder processes 384 bits with
//!    a near-uniform Hamming weight distribution.
//!
//! Both values are deterministically derived from the scalar itself using
//! domain-separated HMAC. In the SUCI/ECIES use case, each ephemeral key
//! is used exactly once, so deterministic derivation is equivalent to
//! fresh randomness for power-analysis purposes.
//!
//! # Abstraction
//!
//! The implementation is structured so that field operations are isolated
//! from point-level logic. This allows future replacement of the software
//! field backend with hardware accelerators (e.g. ARM `CryptoCell`, hardware
//! PKA) without changing the point or ECDH layer.

use simrs_consttime::{CtBool, CtEq, CtSelect, CtSwap, CtZero};
use simrs_kdf::hmac_sha256;
use simrs_secret::Secret;

use crate::{P256CompressedPublicKey, P256UncompressedPublicKey};

// ---------------------------------------------------------------------------
// Field element: GF(p) where p = 2^256 - 2^224 + 2^192 + 2^96 - 1
// ---------------------------------------------------------------------------

/// The NIST P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
///
/// Limbs are little-endian: `P[0]` is the least significant 64-bit word.
const P: [u64; 4] = [
    0xFFFFFFFF_FFFFFFFF,
    0x00000000_FFFFFFFF,
    0x00000000_00000000,
    0xFFFFFFFF_00000001,
];

/// Curve coefficient a = -3 mod p.
const A: Fe = Fe([
    0xFFFFFFFF_FFFFFFFC,
    0x00000000_FFFFFFFF,
    0x00000000_00000000,
    0xFFFFFFFF_00000001,
]);

/// Curve coefficient b.
const B: Fe = Fe([
    0x3BCE3C3E_27D2604B,
    0x651D06B0_CC53B0F6,
    0xB3EBBD55_769886BC,
    0x5AC635D8_AA3A93E7,
]);

/// Group order n.
const N: [u64; 4] = [
    0xF3B9CAC2_FC632551,
    0xBCE6FAAD_A7179E84,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_00000000,
];

/// Generator point G (affine coordinates).
const GX: Fe = Fe([
    0xF4A13945_D898C296,
    0x77037D81_2DEB33A0,
    0xF8BCE6E5_63A440F2,
    0x6B17D1F2_E12C4247,
]);

const GY: Fe = Fe([
    0xCBB64068_37BF51F5,
    0x2BCE3357_6B315ECE,
    0x8EE7EB4A_7C0F9E16,
    0x4FE342E2_FE1A7F9B,
]);

/// A field element in GF(p), stored as four u64 limbs, little-endian.
///
/// Invariant: a fully reduced element satisfies `Fe < P` when interpreted
/// as a 256-bit unsigned integer.
#[derive(Clone, Copy)]
pub(crate) struct Fe([u64; 4]);

impl Fe {
    const ZERO: Self = Self([0; 4]);
    const ONE: Self = Self([1, 0, 0, 0]);

    // -- Serialization -------------------------------------------------------

    /// Decode from 32-byte big-endian encoding (SEC 1 / X.690 convention).
    const fn from_bytes(b: &[u8; 32]) -> Self {
        Self([
            u64::from_be_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
            u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        ])
    }

    /// Encode to 32-byte big-endian representation.
    fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let w3 = self.0[3].to_be_bytes();
        let w2 = self.0[2].to_be_bytes();
        let w1 = self.0[1].to_be_bytes();
        let w0 = self.0[0].to_be_bytes();
        out[0..8].copy_from_slice(&w3);
        out[8..16].copy_from_slice(&w2);
        out[16..24].copy_from_slice(&w1);
        out[24..32].copy_from_slice(&w0);
        out
    }

    /// Return true if this element is zero (not constant-time; only for
    /// validation paths, never on secret data).
    const fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    // -- Arithmetic ----------------------------------------------------------

    /// Addition mod p.
    fn add(self, rhs: Self) -> Self {
        let (r0, c0) = self.0[0].overflowing_add(rhs.0[0]);
        let (r1, c1) = self.0[1].carrying_add(rhs.0[1], c0);
        let (r2, c2) = self.0[2].carrying_add(rhs.0[2], c1);
        let (r3, c3) = self.0[3].carrying_add(rhs.0[3], c2);

        // If carry out or result >= p, subtract p.
        let sum = Self([r0, r1, r2, r3]);
        let (d, borrow) = sub_inner(sum.0, P);

        // Use sum if borrow (sum < p), else use d (sum >= p).
        // c3 means the addition overflowed 256 bits, so sum >= p for sure.
        let use_d = CtBool::from_u64_bit(u64::from(c3) | (1 - u64::from(borrow)));
        Self(<[u64; 4]>::ct_select(use_d, &d, &sum.0))
    }

    /// Subtraction mod p.
    fn sub(self, rhs: Self) -> Self {
        let (d, borrow) = sub_inner(self.0, rhs.0);
        // If borrow, add p back.
        let (r0, c0) = d[0].overflowing_add(P[0] & 0u64.wrapping_sub(u64::from(borrow)));
        let (r1, c1) = d[1].carrying_add(P[1] & 0u64.wrapping_sub(u64::from(borrow)), c0);
        let (r2, c2) = d[2].carrying_add(P[2] & 0u64.wrapping_sub(u64::from(borrow)), c1);
        let (r3, _) = d[3].carrying_add(P[3] & 0u64.wrapping_sub(u64::from(borrow)), c2);
        Self([r0, r1, r2, r3])
    }

    /// Negation mod p.
    fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Multiplication mod p using u128 intermediates and NIST fast reduction.
    #[allow(clippy::cast_possible_truncation)]
    fn mul(self, rhs: Self) -> Self {
        let t = mul_wide(self.0, rhs.0);
        reduce(t)
    }

    /// Squaring mod p using dedicated Comba squaring (10 multiplications
    /// vs 16 for generic mul).
    fn square(self) -> Self {
        let t = sqr_wide(self.0);
        reduce(t)
    }

    /// Repeated squaring: compute self^(2^n).
    fn square_n(self, n: u32) -> Self {
        let mut r = self;
        let mut i = 0;
        while i < n {
            r = r.square();
            i += 1;
        }
        r
    }

    /// Multiplicative inverse via Fermat's little theorem: a^(p-2).
    ///
    /// Uses an addition chain optimized for P-256's prime.
    /// Cost: 277 squarings + 13 multiplications = 290 field ops.
    fn invert(self) -> Self {
        // p-2 = 0xFFFFFFFF_00000001_00000000_00000000
        //       _00000000_FFFFFFFF_FFFFFFFF_FFFFFFFD
        let a = self;

        // Building blocks: a^(2^k - 1)
        let x2 = a.square().mul(a);                   // a^(2^2 - 1)
        let x4 = x2.square_n(2).mul(x2);              // a^(2^4 - 1)
        let x6 = x4.square_n(2).mul(x2);              // a^(2^6 - 1)
        let x8 = x4.square_n(4).mul(x4);              // a^(2^8 - 1)
        let x14 = x8.square_n(6).mul(x6);             // a^(2^14 - 1)
        let x16 = x8.square_n(8).mul(x8);             // a^(2^16 - 1)
        let x30 = x16.square_n(14).mul(x14);          // a^(2^30 - 1)
        let x32 = x16.square_n(16).mul(x16);          // a^(2^32 - 1)

        // Process p-2 word by word (32-bit words, MSB to LSB):
        //   FFFFFFFF 00000001 [96 zero bits] FFFFFFFF FFFFFFFF FFFFFFFD
        let e = x32;                                   // word: FFFFFFFF
        let e = e.square_n(32).mul(a);                 // word: 00000001
        let e = e.square_n(96);                        // 3 zero words
        let e = e.square_n(32).mul(x32);               // word: FFFFFFFF
        let e = e.square_n(32).mul(x32);               // word: FFFFFFFF
        // FFFFFFFD = (2^30-1)*4 + 1
        let e = e.square_n(30).mul(x30);
        e.square().square().mul(a)
    }

    /// Square root mod p: a^((p+1)/4).
    ///
    /// Returns `Some(sqrt)` if a is a quadratic residue, `None` otherwise.
    /// Since p = 3 mod 4, the square root (if it exists) is a^((p+1)/4).
    fn sqrt(self) -> Option<Self> {
        // Since p = 3 mod 4, sqrt(a) = a^((p+1)/4) if a is a QR.
        //
        // (p+1)/4 = 2^254 - 2^222 + 2^190 + 2^94
        //
        // Bit structure (254 bits): [32 ones][31 zeros][1][95 zeros][1][94 zeros]
        // Cost: 253 squarings + 7 multiplications = 260 field ops.
        let a = self;

        // Building blocks: a^(2^k - 1)
        let x2 = a.square().mul(a);                   // a^(2^2 - 1)
        let x4 = x2.square_n(2).mul(x2);              // a^(2^4 - 1)
        let x8 = x4.square_n(4).mul(x4);              // a^(2^8 - 1)
        let x16 = x8.square_n(8).mul(x8);             // a^(2^16 - 1)
        let x32 = x16.square_n(16).mul(x16);          // a^(2^32 - 1)

        // Main chain
        let e = x32;                                   // 32 ones
        let e = e.square_n(31);                        // 31 zeros
        let e = e.square().mul(a);                     // bit 190 = 1
        let e = e.square_n(95);                        // 95 zeros
        let e = e.square().mul(a);                     // bit 94 = 1
        let candidate = e.square_n(94);                // 94 trailing zeros

        // Verify: candidate^2 == self
        if candidate.square().ct_eq(&self).into_bool() {
            Some(candidate)
        } else {
            None
        }
    }

}

// Constant-time trait implementations for Fe.

impl CtZero for Fe {
    #[inline]
    fn ct_is_zero(&self) -> CtBool {
        self.0.ct_is_zero()
    }
}

impl CtEq for Fe {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0.ct_eq(&other.0)
    }
}

impl CtSelect for Fe {
    #[inline]
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self {
        Self(<[u64; 4]>::ct_select(cond, &a.0, &b.0))
    }
}

impl CtSwap for Fe {
    #[inline]
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool) {
        <[u64; 4]>::ct_swap(&mut a.0, &mut b.0, cond);
    }
}

// -- Wide multiplication and NIST reduction --------------------------------

/// 4x4 schoolbook multiplication producing an 8-limb (512-bit) result.
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
const fn mul_wide(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];

    // Process one row at a time: for each a[i], multiply by all b[j]
    // and add into r[i+j..i+j+1] with carry propagation.
    let mut i = 0;
    while i < 4 {
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < 4 {
            let prod = (a[i] as u128) * (b[j] as u128) + (r[i + j] as u128) + carry;
            r[i + j] = prod as u64;
            carry = prod >> 64;
            j += 1;
        }
        r[i + 4] = carry as u64;
        i += 1;
    }

    r
}

/// Comba squaring: compute a^2 as an 8-limb (512-bit) result.
///
/// Exploits the symmetry a[i]*a[j] == a[j]*a[i] to use only 10
/// u64*u64 multiplications (4 diagonal + 6 cross) instead of 16.
///
/// Uses a 192-bit triple-register accumulator (c0, c1, c2) because
/// column sums can exceed 128 bits (column k=3 reaches ~2^130).
/// Cross-products are added to the accumulator twice (not pre-doubled
/// in u128, as 2*(2^64-1)^2 > 2^128).
///
/// Column sums (before carries):
///   w0 = a0*a0
///   w1 = 2*a0*a1
///   w2 = 2*a0*a2 + a1*a1
///   w3 = 2*a0*a3 + 2*a1*a2
///   w4 = 2*a1*a3 + a2*a2
///   w5 = 2*a2*a3
///   w6 = a3*a3
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
const fn sqr_wide(a: [u64; 4]) -> [u64; 8] {
    // Compute the 10 distinct products.
    let a0a0 = (a[0] as u128) * (a[0] as u128);
    let a0a1 = (a[0] as u128) * (a[1] as u128);
    let a0a2 = (a[0] as u128) * (a[2] as u128);
    let a0a3 = (a[0] as u128) * (a[3] as u128);
    let a1a1 = (a[1] as u128) * (a[1] as u128);
    let a1a2 = (a[1] as u128) * (a[2] as u128);
    let a1a3 = (a[1] as u128) * (a[3] as u128);
    let a2a2 = (a[2] as u128) * (a[2] as u128);
    let a2a3 = (a[2] as u128) * (a[3] as u128);
    let a3a3 = (a[3] as u128) * (a[3] as u128);

    // 192-bit triple-register Comba accumulator.
    // True value = c0 + c1*2^64 + c2*2^128.
    let mut c0: u64 = 0;
    let mut c1: u64 = 0;
    let mut c2: u64 = 0;

    // Helper: add a u128 product (lo, hi) to the accumulator.
    macro_rules! acc_add {
        ($prod:expr) => {
            let lo = $prod as u64;
            let hi = ($prod >> 64) as u64;
            let (new_c0, carry0) = c0.overflowing_add(lo);
            c0 = new_c0;
            let (new_c1, carry1) = c1.overflowing_add(hi);
            c1 = new_c1;
            let (new_c1, carry2) = c1.overflowing_add(carry0 as u64);
            c1 = new_c1;
            c2 += carry1 as u64 + carry2 as u64;
        };
    }

    let mut r = [0u64; 8];

    // Column 0: a0*a0
    acc_add!(a0a0);
    r[0] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 1: 2*a0*a1
    acc_add!(a0a1);
    acc_add!(a0a1);
    r[1] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 2: 2*a0*a2 + a1*a1
    acc_add!(a0a2);
    acc_add!(a0a2);
    acc_add!(a1a1);
    r[2] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 3: 2*a0*a3 + 2*a1*a2
    acc_add!(a0a3);
    acc_add!(a0a3);
    acc_add!(a1a2);
    acc_add!(a1a2);
    r[3] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 4: 2*a1*a3 + a2*a2
    acc_add!(a1a3);
    acc_add!(a1a3);
    acc_add!(a2a2);
    r[4] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 5: 2*a2*a3
    acc_add!(a2a3);
    acc_add!(a2a3);
    r[5] = c0; c0 = c1; c1 = c2;

    // Column 6: a3*a3 (last column -- inline to avoid unused c2 warning).
    {
        let lo = a3a3 as u64;
        let hi = (a3a3 >> 64) as u64;
        let (new_c0, carry0) = c0.overflowing_add(lo);
        c0 = new_c0;
        let (new_c1, _) = c1.overflowing_add(hi);
        c1 = new_c1;
        let (new_c1, _) = c1.overflowing_add(carry0 as u64);
        c1 = new_c1;
        // c2 carry is always 0 for the last column of a 4-limb square.
    }
    r[6] = c0;
    r[7] = c1;

    r
}

/// NIST fast reduction for P-256.
///
/// Given a 512-bit product t[0..8], compute t mod p using the
/// special form of the P-256 prime. Based on FIPS 186-4 D.2.3 with
/// the reduction identity for p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
///
/// The algorithm decomposes the 512-bit value into overlapping 256-bit
/// values (s1..s9) and computes:
///   result = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9  (mod p)
#[allow(clippy::cast_possible_truncation)]
fn reduce(t: [u64; 8]) -> Fe {
    // Extract 32-bit words from the 512-bit product.
    // t is in 64-bit limbs; we need 32-bit pieces c0..c15.
    let c = |idx: usize| -> u64 {
        let limb = t[idx / 2];
        if idx.is_multiple_of(2) {
            limb & 0xFFFFFFFF
        } else {
            limb >> 32
        }
    };

    // FIPS 186-4, D.2.3: define s1..s9 as 256-bit values from c0..c15.
    // s1 = (c7, c6, c5, c4, c3, c2, c1, c0) -- the low 256 bits
    // s2 = (c15, c14, c13, c12, c11, 0, 0, 0)
    // s3 = (0, c15, c14, c13, c12, 0, 0, 0)
    // s4 = (c15, c14, 0, 0, 0, c10, c9, c8)
    // s5 = (c8, c13, c15, c14, c13, c11, c10, c9)
    // s6 = (c10, c8, 0, 0, 0, c13, c12, c11)
    // s7 = (c11, c9, 0, 0, c15, c14, c13, c12)
    // s8 = (c12, 0, c10, c9, c8, c15, c14, c13)
    // s9 = (c13, 0, c11, c10, c9, 0, c15, c14)
    //
    // Each s is 8 x 32-bit words packed into 4 x 64-bit limbs (little-endian).

    // Pack eight 32-bit words (MSB first) into four 64-bit limbs (LE).
    // s_val = w7*2^224 + w6*2^192 + ... + w1*2^32 + w0
    // limb0 = w1*2^32 + w0, limb1 = w3*2^32 + w2, etc.
    let pack = |w7: u64, w6: u64, w5: u64, w4: u64, w3: u64, w2: u64, w1: u64, w0: u64| -> [u64; 4] {
        [
            (w1 << 32) | w0,
            (w3 << 32) | w2,
            (w5 << 32) | w4,
            (w7 << 32) | w6,
        ]
    };

    let c8 = c(8); let c9 = c(9); let c10 = c(10); let c11 = c(11);
    let c12 = c(12); let c13 = c(13); let c14 = c(14); let c15 = c(15);

    // s1 = low 256 bits of the product.
    let s1 = [t[0], t[1], t[2], t[3]];
    let s2 = pack(c15, c14, c13, c12, c11,  0,   0,   0);
    let s3 = pack(  0, c15, c14, c13, c12,  0,   0,   0);
    let s4 = pack(c15, c14,   0,   0,   0, c10,  c9,  c8);
    let s5 = pack( c8, c13, c15, c14, c13, c11, c10,  c9);
    let s6 = pack(c10,  c8,   0,   0,   0, c13, c12, c11);
    let s7 = pack(c11,  c9,   0,   0, c15, c14, c13, c12);
    let s8 = pack(c12,   0, c10,  c9,  c8, c15, c14, c13);
    let s9 = pack(c13,   0, c11, c10,  c9,   0, c15, c14);

    // Compute: s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9
    // We do this with wide (320-bit) signed arithmetic to avoid underflow,
    // then reduce mod p at the end.

    // Accumulate additions in a 320-bit accumulator (5 limbs).
    let mut acc = [0i128; 5];

    // Add s1
    add_to_acc(&mut acc, s1);
    // Add 2*s2
    add_to_acc(&mut acc, s2);
    add_to_acc(&mut acc, s2);
    // Add 2*s3
    add_to_acc(&mut acc, s3);
    add_to_acc(&mut acc, s3);
    // Add s4
    add_to_acc(&mut acc, s4);
    // Add s5
    add_to_acc(&mut acc, s5);
    // Subtract s6
    sub_from_acc(&mut acc, s6);
    // Subtract s7
    sub_from_acc(&mut acc, s7);
    // Subtract s8
    sub_from_acc(&mut acc, s8);
    // Subtract s9
    sub_from_acc(&mut acc, s9);

    // Now normalize: propagate carries through the signed accumulator,
    // then reduce mod p.
    normalize_acc(acc)
}

/// Add a 256-bit value (4 limbs) into a 5-limb signed accumulator.
fn add_to_acc(acc: &mut [i128; 5], val: [u64; 4]) {
    acc[0] += i128::from(val[0]);
    acc[1] += i128::from(val[1]);
    acc[2] += i128::from(val[2]);
    acc[3] += i128::from(val[3]);
}

/// Subtract a 256-bit value from a 5-limb signed accumulator.
fn sub_from_acc(acc: &mut [i128; 5], val: [u64; 4]) {
    acc[0] -= i128::from(val[0]);
    acc[1] -= i128::from(val[1]);
    acc[2] -= i128::from(val[2]);
    acc[3] -= i128::from(val[3]);
}

/// Normalize a signed accumulator to a field element mod p.
///
/// Constant-time: no branches, memory accesses, or instruction timing depend
/// on accumulator values. Uses exactly 2 unconditional fold-backs followed
/// by 1 conditional subtraction.
///
/// Bounds (proven for products of field elements in [0, p)):
/// - After initial carry propagation: acc[4] in [-4, +4]
/// - After 1st fold-back + carry: acc[4] in {-1, 0, +1}
/// - After 2nd fold-back + carry: acc[4] = 0, result in [0, 2^256)
/// - One conditional subtraction of p canonicalizes to [0, p)
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn normalize_acc(mut acc: [i128; 5]) -> Fe {
    // Round 1: propagate carries, then fold acc[4] back into lower limbs.
    // 2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p)
    propagate_carries(&mut acc);
    fold_top(&mut acc);

    // Round 2: unconditional (if acc[4] == 0, the fold is arithmetic no-op).
    propagate_carries(&mut acc);
    fold_top(&mut acc);

    // Final carry propagation. acc[4] is now 0 for all valid reduction inputs.
    propagate_carries(&mut acc);
    debug_assert!(acc[4] == 0, "acc[4] must be 0 after 2 fold-backs");

    // Convert to unsigned 256-bit result (guaranteed non-negative).
    let r = [acc[0] as u64, acc[1] as u64, acc[2] as u64, acc[3] as u64];

    // One constant-time conditional subtraction: if r >= p, return r - p.
    let (d, borrow) = sub_inner(r, P);
    let use_d = CtBool::from_u64_bit(1 - u64::from(borrow)); // TRUE if r >= p
    Fe(<[u64; 4]>::ct_select(use_d, &d, &r))
}

/// Propagate signed carries through a 5-limb accumulator.
/// After this, acc[0..4] are in [0, 2^64) and acc[4] holds the overflow.
const fn propagate_carries(acc: &mut [i128; 5]) {
    let mut i = 0;
    while i < 4 {
        let carry = acc[i] >> 64;
        acc[i] -= carry << 64;
        acc[i + 1] += carry;
        i += 1;
    }
}

/// Fold acc[4] * 2^256 into the lower limbs using the NIST identity:
///   2^256 = 2^224 - 2^192 - 2^96 + 1  (mod p)
///
/// Each 64-bit limb i covers bits [64*i, 64*(i+1)).
/// So `top * 2^256 = top * (2^224 - 2^192 - 2^96 + 1)` distributes as:
///   limb 0: +top          (top * 2^0  in bits [0,64))
///   limb 1: -top << 32    (top * 2^32 in limb 1 = top * 2^(64+32) = top * 2^96)
///   limb 3: -top          (top * 2^0  in limb 3 = top * 2^192)
///   limb 3: +top << 32    (top * 2^32 in limb 3 = top * 2^(192+32) = top * 2^224)
const fn fold_top(acc: &mut [i128; 5]) {
    let top = acc[4];
    acc[4] = 0;
    acc[0] += top;              // +top * 1
    acc[1] -= top << 32;        // -top * 2^96
    acc[3] -= top;              // -top * 2^192
    acc[3] += top << 32;        // +top * 2^224
}

/// Subtraction of two 256-bit values, returns (result, borrow).
fn sub_inner(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let (r0, b0) = a[0].overflowing_sub(b[0]);
    let (r1, b1) = a[1].borrowing_sub(b[1], b0);
    let (r2, b2) = a[2].borrowing_sub(b[2], b1);
    let (r3, b3) = a[3].borrowing_sub(b[3], b2);
    ([r0, r1, r2, r3], b3)
}


// ---------------------------------------------------------------------------
// Point operations: Jacobian projective coordinates
// ---------------------------------------------------------------------------

/// A point on P-256 in Jacobian projective coordinates.
///
/// The affine point (x, y) is represented as (X, Y, Z) where
/// x = X/Z^2 and y = Y/Z^3. The point at infinity has Z = 0.
#[derive(Clone, Copy)]
pub(crate) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    /// The point at infinity (identity element).
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ZERO,
    };

    /// The generator point G.
    const fn generator() -> Self {
        Self {
            x: GX,
            y: GY,
            z: Fe::ONE,
        }
    }

    /// Check if this is the point at infinity.
    const fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    /// Point doubling in Jacobian coordinates (branchless).
    ///
    /// Uses the "dbl-2001-b" formula from
    /// <https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html>
    /// (optimized for a = -3). Handles identity input without branching:
    /// when Z=0 the formula naturally produces Z3=0.
    ///
    /// Cost: 4M + 4S + 1*half (+ adds)
    fn double(self) -> Self {
        let x = self.x;
        let y = self.y;
        let z = self.z;

        // delta = Z^2
        let delta = z.square();
        // gamma = Y^2
        let gamma = y.square();
        // beta = X * gamma
        let beta = x.mul(gamma);

        // alpha = 3*(X - delta)*(X + delta)
        // Since a = -3, this simplifies to 3*(X^2 - Z^4) = 3*(X-Z^2)*(X+Z^2)
        let xmd = x.sub(delta);
        let xpd = x.add(delta);
        let alpha = xmd.mul(xpd);
        let alpha = alpha.add(alpha).add(alpha); // 3 * alpha

        // X3 = alpha^2 - 8*beta
        let beta4 = beta.add(beta).add(beta.add(beta)); // 4*beta
        let beta8 = beta4.add(beta4);
        let x3 = alpha.square().sub(beta8);

        // Z3 = (Y + Z)^2 - gamma - delta
        let z3 = y.add(z).square().sub(gamma).sub(delta);

        // Y3 = alpha * (4*beta - X3) - 8*gamma^2
        let gamma_sq = gamma.square();
        let gamma_sq8 = gamma_sq.add(gamma_sq);
        let gamma_sq8 = gamma_sq8.add(gamma_sq8);
        let gamma_sq8 = gamma_sq8.add(gamma_sq8);
        let y3 = alpha.mul(beta4.sub(x3)).sub(gamma_sq8);

        Self { x: x3, y: y3, z: z3 }
    }

    /// Point addition (full Jacobian + Jacobian, branchless).
    ///
    /// Uses the "add-2007-bl" formula for the generic case, with
    /// constant-time conditional moves to handle all exceptional cases
    /// (identity inputs, point doubling, inverse points) without
    /// data-dependent branches.
    ///
    /// Cost: ~16M + ~5S + 1 doubling (always computed) + 4 cmov.
    fn add(self, rhs: Self) -> Self {
        let z1sq = self.z.square();
        let z2sq = rhs.z.square();

        let u1 = self.x.mul(z2sq);
        let u2 = rhs.x.mul(z1sq);

        let s1 = self.y.mul(z2sq.mul(rhs.z));
        let s2 = rhs.y.mul(z1sq.mul(self.z));

        let h = u2.sub(u1);
        let i = h.add(h).square(); // i = (2*h)^2
        let j = h.mul(i);
        let r = s2.sub(s1).add(s2.sub(s1)); // r = 2*(s2-s1)
        let v = u1.mul(i);

        let x3 = r.square().sub(j).sub(v.add(v));
        let y3 = r.mul(v.sub(x3)).sub(s1.mul(j).add(s1.mul(j)));
        let z3 = self.z.add(rhs.z).square().sub(z1sq).sub(z2sq).mul(h);

        let mut result = Self { x: x3, y: y3, z: z3 };

        // Handle exceptional cases with constant-time conditional moves.
        let self_is_id = self.z.ct_is_zero();
        let rhs_is_id = rhs.z.ct_is_zero();
        let u_eq = u1.ct_eq(&u2);
        let s_eq = s1.ct_eq(&s2);

        // When u1 == u2 and s1 == s2: points are equal, use doubling.
        let doubled = self.double();
        result.ct_assign(&doubled, u_eq.and(s_eq));

        // When u1 == u2 and s1 != s2: points are inverses, result is identity.
        result.ct_assign(&Self::IDENTITY, u_eq.and(s_eq.not()));

        // When rhs is identity, result is self.
        result.ct_assign(&self, rhs_is_id);

        // When self is identity, result is rhs (highest priority).
        result.ct_assign(&rhs, self_is_id);

        result
    }

    /// Convert from Jacobian to affine coordinates.
    ///
    /// Returns (x, y) as field elements. Panics if this is the identity.
    fn to_affine(self) -> (Fe, Fe) {
        assert!(!self.is_identity(), "cannot convert identity to affine");
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(z_inv);
        let x = self.x.mul(z_inv2);
        let y = self.y.mul(z_inv3);
        (x, y)
    }

    /// Check if an affine point (x, y) satisfies y^2 = x^3 + a*x + b.
    fn is_on_curve_affine(x: Fe, y: Fe) -> bool {
        let lhs = y.square();
        let rhs = x.square().mul(x).add(A.mul(x)).add(B);
        lhs.ct_eq(&rhs).into_bool()
    }

}

impl CtSelect for Point {
    #[inline]
    fn ct_select(cond: CtBool, a: &Self, b: &Self) -> Self {
        Self {
            x: Fe::ct_select(cond, &a.x, &b.x),
            y: Fe::ct_select(cond, &a.y, &b.y),
            z: Fe::ct_select(cond, &a.z, &b.z),
        }
    }
}

impl CtSwap for Point {
    #[inline]
    fn ct_swap(a: &mut Self, b: &mut Self, cond: CtBool) {
        Fe::ct_swap(&mut a.x, &mut b.x, cond);
        Fe::ct_swap(&mut a.y, &mut b.y, cond);
        Fe::ct_swap(&mut a.z, &mut b.z, cond);
    }
}

// ---------------------------------------------------------------------------
// Scalar blinding and coordinate randomization (ZRA countermeasures)
// ---------------------------------------------------------------------------

/// Reduce a 256-bit value mod p (constant-time).
///
/// Tries subtracting p; keeps the result if no borrow. Since the input
/// is at most 2^256 - 1 and p > 2^255, at most one subtraction is needed.
fn fe_reduce(raw: [u64; 4]) -> Fe {
    let (d, borrow) = sub_inner(raw, P);
    // borrow == true means raw < p, so keep raw; else keep d.
    Fe(<[u64; 4]>::ct_select(CtBool::from_u64_bit(u64::from(borrow)), &raw, &d))
}

/// Derive a non-zero field element from a 32-byte HMAC output.
///
/// Reduces mod p, then replaces zero with 1 (constant-time).
fn fe_from_hmac(h: &[u8; 32]) -> Fe {
    let raw = [
        u64::from_be_bytes([h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]]),
        u64::from_be_bytes([h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23]]),
        u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]),
        u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]),
    ];
    let fe = fe_reduce(raw);
    // If zero (probability ~2^-256), use 1 instead.
    let is_zero = fe.ct_is_zero().as_u64_mask();
    Fe([
        fe.0[0] | (is_zero & 1),
        fe.0[1],
        fe.0[2],
        fe.0[3],
    ])
}

/// Randomize projective coordinates: (X:Y:Z) -> (lam^2*X : lam^3*Y : lam*Z).
///
/// The resulting point represents the same affine point but with a
/// non-trivial Z coordinate, defeating Zero-Value Register Attacks.
/// Cost: 1S + 4M.
fn randomize_projective(p: Point, lam: Fe) -> Point {
    let lam2 = lam.square();
    let lam3 = lam2.mul(lam);
    Point {
        x: p.x.mul(lam2),
        y: p.y.mul(lam3),
        z: p.z.mul(lam),
    }
}

/// Compute k' = k + r*n as a 384-bit (48-byte) big-endian scalar.
///
/// k: 32-byte big-endian scalar in [1, n-1].
/// r: 16-byte blinding factor (used as 128-bit little-endian integer).
///
/// The result fits in exactly 384 bits (proven: max = n*2^128 - 1 < 2^384).
#[allow(clippy::cast_possible_truncation)]
fn blind_scalar(k: &[u8; 32], r: &[u8; 16]) -> [u8; 48] {
    // Decode r as 2 little-endian u64 limbs.
    let r0 = u64::from_le_bytes([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]);
    let r1 = u64::from_le_bytes([r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]]);
    let r_limbs = [r0, r1];

    // Phase A: multiply r (2 limbs) * N (4 limbs) -> temp (6 limbs, LE).
    let mut temp = [0u64; 6];
    let mut i = 0;
    while i < 2 {
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < 4 {
            let wide = u128::from(r_limbs[i]) * u128::from(N[j])
                + u128::from(temp[i + j])
                + carry;
            temp[i + j] = wide as u64;
            carry = wide >> 64;
            j += 1;
        }
        temp[i + 4] = carry as u64;
        i += 1;
    }

    // Decode k as 4 little-endian u64 limbs (from big-endian bytes).
    let k_limbs: [u64; 4] = [
        u64::from_be_bytes([k[24], k[25], k[26], k[27], k[28], k[29], k[30], k[31]]),
        u64::from_be_bytes([k[16], k[17], k[18], k[19], k[20], k[21], k[22], k[23]]),
        u64::from_be_bytes([k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]]),
        u64::from_be_bytes([k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]]),
    ];

    // Phase B: add k to temp.
    let mut carry: u128 = 0;
    i = 0;
    while i < 6 {
        let kv = if i < 4 { k_limbs[i] } else { 0 };
        let sum = u128::from(temp[i]) + u128::from(kv) + carry;
        temp[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }
    debug_assert!(carry as u64 == 0, "k + r*n must fit in 384 bits");

    // Phase C: serialize to 48-byte big-endian.
    let mut out = [0u8; 48];
    out[0..8].copy_from_slice(&temp[5].to_be_bytes());
    out[8..16].copy_from_slice(&temp[4].to_be_bytes());
    out[16..24].copy_from_slice(&temp[3].to_be_bytes());
    out[24..32].copy_from_slice(&temp[2].to_be_bytes());
    out[32..40].copy_from_slice(&temp[1].to_be_bytes());
    out[40..48].copy_from_slice(&temp[0].to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Scalar operations
// ---------------------------------------------------------------------------

/// Montgomery ladder over a 384-bit scalar (48-byte big-endian).
fn scalar_mul_wide(k: &[u8; 48], p: Point) -> Point {
    let mut r0 = Point::IDENTITY;
    let mut r1 = p;

    let mut byte_idx: usize = 0;
    while byte_idx < 48 {
        let mut bit: u32 = 8;
        while bit > 0 {
            bit -= 1;
            let ki = u64::from((k[byte_idx] >> bit) & 1);

            Point::ct_swap(&mut r0, &mut r1, CtBool::from_u64_bit(ki));
            r1 = r0.add(r1);
            r0 = r0.double();
            Point::ct_swap(&mut r0, &mut r1, CtBool::from_u64_bit(ki));
        }
        byte_idx += 1;
    }

    r0
}

/// Constant-time scalar multiplication with ZRA countermeasures: k * P.
///
/// Applies projective coordinate randomization and scalar blinding before
/// the Montgomery ladder. The blinding values are derived deterministically
/// from k via domain-separated HMAC-SHA-256.
fn scalar_mul(k: &[u8; 32], p: Point) -> Point {
    // Derive blinding material from the scalar.
    let lam_bytes = hmac_sha256(&simrs_secret::Secret::new(*b"p256-coord-blind"), k);
    let r_bytes = hmac_sha256(&simrs_secret::Secret::new(*b"p256-scalar-blind"), k);

    // Projective coordinate randomization: (X:Y:Z) -> (lam^2*X:lam^3*Y:lam*Z).
    let lam = fe_from_hmac(&lam_bytes);
    let p_rand = randomize_projective(p, lam);

    // Scalar blinding: k' = k + r*n (384 bits).
    let k_blind = blind_scalar(k, &{
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&r_bytes[..16]);
        buf
    });

    scalar_mul_wide(&k_blind, p_rand)
}

/// Scalar multiplication with the generator: k * G.
fn scalar_mul_base(k: &[u8; 32]) -> Point {
    scalar_mul(k, Point::generator())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// P-256 ECDH: compute the shared secret (x-coordinate of k * Q).
///
/// `scalar` is the private key (32 bytes, big-endian).
/// `peer_pubkey` is the peer's public key in uncompressed SEC 1 format (65 bytes: 0x04 || x || y).
///
/// Returns the x-coordinate of the shared point as 32 bytes (big-endian),
/// or `None` if the public key is invalid.
pub fn p256_ecdh(scalar: &Secret<[u8; 32]>, peer_pubkey: &P256UncompressedPublicKey) -> Option<Secret<[u8; 32]>> {
    let q = decode_point_uncompressed(peer_pubkey.as_bytes())?;
    let shared = scalar_mul(scalar.declassify_ref(), q);
    // Use constant-time zero check on Z coordinate to detect identity.
    // For valid inputs (scalar in [1,n-1], Q on curve), this never triggers.
    let is_id = shared.z.ct_is_zero();
    if is_id.into_bool() {
        return None;
    }
    let (x, _) = shared.to_affine();
    Some(Secret::new(x.to_bytes()))
}

/// Compute the P-256 public key from a private key.
///
/// `scalar` is the private key (32 bytes, big-endian).
/// Returns the public key in uncompressed SEC 1 format (65 bytes: 0x04 || x || y).
pub fn p256_pubkey(scalar: &Secret<[u8; 32]>) -> P256UncompressedPublicKey {
    let q = scalar_mul_base(scalar.declassify_ref());
    P256UncompressedPublicKey::new(encode_point_uncompressed(q))
}

/// Compute the compressed P-256 public key.
///
/// Returns 33 bytes: 0x02 (even y) or 0x03 (odd y) followed by x-coordinate.
pub fn p256_pubkey_compressed(scalar: &Secret<[u8; 32]>) -> P256CompressedPublicKey {
    let q = scalar_mul_base(scalar.declassify_ref());
    P256CompressedPublicKey::new(encode_point_compressed(q))
}

/// Decompress a P-256 public key from compressed SEC 1 format (33 bytes)
/// to uncompressed SEC 1 format (65 bytes).
///
/// Returns `None` if the compressed key is invalid.
pub fn p256_decompress_pubkey(compressed: &P256CompressedPublicKey) -> Option<P256UncompressedPublicKey> {
    let point = decode_point_compressed(compressed.as_bytes())?;
    Some(P256UncompressedPublicKey::new(encode_point_uncompressed(point)))
}

// ---------------------------------------------------------------------------
// Point encoding/decoding (SEC 1 v2.0 clause 2.3)
// ---------------------------------------------------------------------------

/// Encode a point in uncompressed SEC 1 format: 0x04 || x || y.
fn encode_point_uncompressed(p: Point) -> [u8; 65] {
    let (x, y) = p.to_affine();
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&x.to_bytes());
    out[33..65].copy_from_slice(&y.to_bytes());
    out
}

/// Encode a point in compressed SEC 1 format: 0x02/0x03 || x.
fn encode_point_compressed(p: Point) -> [u8; 33] {
    let (x, y) = p.to_affine();
    let y_bytes = y.to_bytes();
    let mut out = [0u8; 33];
    out[0] = if y_bytes[31] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..33].copy_from_slice(&x.to_bytes());
    out
}

/// Decode an uncompressed SEC 1 point (65 bytes: 0x04 || x || y).
///
/// Validates that the point is on the curve. Returns `None` if invalid.
fn decode_point_uncompressed(bytes: &[u8; 65]) -> Option<Point> {
    if bytes[0] != 0x04 {
        return None;
    }
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&bytes[1..33]);
    yb.copy_from_slice(&bytes[33..65]);

    let x = Fe::from_bytes(&xb);
    let y = Fe::from_bytes(&yb);

    if !Point::is_on_curve_affine(x, y) {
        return None;
    }

    Some(Point { x, y, z: Fe::ONE })
}

/// Decode a compressed SEC 1 point (33 bytes: 0x02/0x03 || x).
///
/// Recovers y from x using the curve equation, choosing the parity
/// indicated by the prefix byte. Returns `None` if x yields no valid point.
pub(crate) fn decode_point_compressed(bytes: &[u8; 33]) -> Option<Point> {
    let prefix = bytes[0];
    if prefix != 0x02 && prefix != 0x03 {
        return None;
    }
    let y_is_odd = prefix == 0x03;

    let mut xb = [0u8; 32];
    xb.copy_from_slice(&bytes[1..33]);
    let x = Fe::from_bytes(&xb);

    // y^2 = x^3 + a*x + b
    let y_sq = x.square().mul(x).add(A.mul(x)).add(B);
    let y = y_sq.sqrt()?;

    let y_bytes = y.to_bytes();
    let got_odd = y_bytes[31] & 1 == 1;

    let y = if got_odd == y_is_odd { y } else { y.neg() };

    Some(Point { x, y, z: Fe::ONE })
}

// ---------------------------------------------------------------------------
// Scalar mod n helpers
// ---------------------------------------------------------------------------

/// Check if a scalar is zero.
const fn scalar_is_zero(k: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    let mut i = 0;
    while i < 32 {
        acc |= k[i];
        i += 1;
    }
    acc == 0
}

/// Constant-time check whether scalar >= n (group order).
/// Returns true if k >= N, false otherwise. No branching on byte values.
fn scalar_gte_n(k: &[u8; 32]) -> bool {
    // N in big-endian bytes.
    let n_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        let w3 = N[3].to_be_bytes();
        let w2 = N[2].to_be_bytes();
        let w1 = N[1].to_be_bytes();
        let w0 = N[0].to_be_bytes();
        b[0..8].copy_from_slice(&w3);
        b[8..16].copy_from_slice(&w2);
        b[16..24].copy_from_slice(&w1);
        b[24..32].copy_from_slice(&w0);
        b
    };

    // Compute k - n as a 256-bit subtraction; if no borrow, then k >= n.
    let mut borrow: u16 = 0;
    let mut i: usize = 31;
    loop {
        let diff = u16::from(k[i]).wrapping_sub(u16::from(n_bytes[i])).wrapping_sub(borrow);
        borrow = (diff >> 8) & 1;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    // borrow == 0 means k >= n; borrow == 1 means k < n.
    borrow == 0
}

/// Validate a scalar for use as a P-256 private key: must be in [1, n-1].
///
/// Returns `true` if the 32-byte big-endian scalar is a valid ECDH
/// private key, `false` otherwise. Both checks are constant-time.
pub fn validate_scalar(k: &[u8; 32]) -> bool {
    !scalar_is_zero(k) && !scalar_gte_n(k)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_byte(hi: u8, lo: u8) -> u8 {
        let h = match hi {
            b'0'..=b'9' => hi - b'0',
            b'a'..=b'f' => hi - b'a' + 10,
            b'A'..=b'F' => hi - b'A' + 10,
            _ => panic!("bad hex"),
        };
        let l = match lo {
            b'0'..=b'9' => lo - b'0',
            b'a'..=b'f' => lo - b'a' + 10,
            b'A'..=b'F' => lo - b'A' + 10,
            _ => panic!("bad hex"),
        };
        (h << 4) | l
    }

    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = hex_byte(s.as_bytes()[i * 2], s.as_bytes()[i * 2 + 1]);
            i += 1;
        }
        out
    }

    fn hex65(s: &str) -> [u8; 65] {
        assert_eq!(s.len(), 130);
        let mut out = [0u8; 65];
        let mut i = 0;
        while i < 65 {
            out[i] = hex_byte(s.as_bytes()[i * 2], s.as_bytes()[i * 2 + 1]);
            i += 1;
        }
        out
    }

    fn hex33(s: &str) -> [u8; 33] {
        assert_eq!(s.len(), 66);
        let mut out = [0u8; 33];
        let mut i = 0;
        while i < 33 {
            out[i] = hex_byte(s.as_bytes()[i * 2], s.as_bytes()[i * 2 + 1]);
            i += 1;
        }
        out
    }

    // -- Field element tests -------------------------------------------------

    #[test]
    fn fe_encode_decode_roundtrip() {
        let bytes = hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        let fe = Fe::from_bytes(&bytes);
        assert_eq!(fe.to_bytes(), bytes);
    }

    #[test]
    fn fe_one_roundtrip() {
        let bytes = Fe::ONE.to_bytes();
        assert_eq!(bytes[31], 1);
        assert!(bytes[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn fe_add_mod_p() {
        // p - 1 + 1 = p = 0 mod p
        let p_minus_1 = Fe([
            0xFFFFFFFF_FFFFFFFE,
            0x00000000_FFFFFFFF,
            0x00000000_00000000,
            0xFFFFFFFF_00000001,
        ]);
        let result = p_minus_1.add(Fe::ONE);
        assert!(result.is_zero());
    }

    #[test]
    fn fe_sub_zero() {
        let a = Fe::from_bytes(&hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
        let result = a.sub(a);
        assert!(result.is_zero());
    }

    #[test]
    fn fe_mul_one_identity() {
        let a = Fe::from_bytes(&hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
        let result = a.mul(Fe::ONE);
        assert_eq!(result.to_bytes(), a.to_bytes());
    }

    #[test]
    fn fe_mul_commutative() {
        let a = Fe::from_bytes(&hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
        let b = Fe::from_bytes(&hex32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
        assert_eq!(a.mul(b).to_bytes(), b.mul(a).to_bytes());
    }

    #[test]
    fn fe_invert_self_mul_is_one() {
        let a = Fe::from_bytes(&hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
        let a_inv = a.invert();
        let product = a.mul(a_inv);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(product.to_bytes(), expected);
    }

    #[test]
    fn fe_invert_of_b() {
        // Invert b, then multiply by b, should get 1.
        let b_inv = B.invert();
        let product = B.mul(b_inv);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(product.to_bytes(), expected);
    }

    #[test]
    fn fe_square_vs_mul() {
        let a = Fe::from_bytes(&hex32("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"));
        assert_eq!(a.square().to_bytes(), a.mul(a).to_bytes());
    }

    /// Verify sqr_wide produces identical output to mul_wide(a, a) at the
    /// 512-bit level, using adversarial inputs that maximize carry pressure.
    #[test]
    fn sqr_wide_vs_mul_wide() {
        // Max-limb input: all limbs = u64::MAX.
        let max = [u64::MAX; 4];
        assert_eq!(sqr_wide(max), mul_wide(max, max));

        // Alternating zero/max limbs (tests cross-term carry propagation).
        let alt1 = [u64::MAX, 0, u64::MAX, 0];
        assert_eq!(sqr_wide(alt1), mul_wide(alt1, alt1));
        let alt2 = [0, u64::MAX, 0, u64::MAX];
        assert_eq!(sqr_wide(alt2), mul_wide(alt2, alt2));

        // Half-word boundary: all limbs = 2^63 (maximizes doubling carry).
        let half = [1u64 << 63; 4];
        assert_eq!(sqr_wide(half), mul_wide(half, half));

        // Single limb set (exercises each diagonal independently).
        let mut i = 0;
        while i < 4 {
            let mut a = [0u64; 4];
            a[i] = u64::MAX;
            assert_eq!(sqr_wide(a), mul_wide(a, a));
            i += 1;
        }

        // P-256 prime limbs (realistic field element values).
        assert_eq!(sqr_wide(P), mul_wide(P, P));

        // Group order limbs.
        assert_eq!(sqr_wide(N), mul_wide(N, N));
    }

    #[test]
    fn fe_sub_add_roundtrip() {
        let a = Fe::from_bytes(&hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
        let b = Fe::from_bytes(&hex32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
        let c = a.sub(b);
        let d = c.add(b);
        assert_eq!(d.to_bytes(), a.to_bytes());
    }

    // -- Point tests ---------------------------------------------------------

    #[test]
    fn generator_on_curve() {
        assert!(Point::is_on_curve_affine(GX, GY));
    }

    #[test]
    fn double_generator() {
        let g = Point::generator();
        let g2 = g.double();
        let (x, y) = g2.to_affine();
        assert!(Point::is_on_curve_affine(x, y));
    }

    #[test]
    fn add_generator_to_itself() {
        let g = Point::generator();
        let g2_add = g.add(g);
        let g2_dbl = g.double();
        let (ax, ay) = g2_add.to_affine();
        let (dx, dy) = g2_dbl.to_affine();
        assert_eq!(ax.to_bytes(), dx.to_bytes());
        assert_eq!(ay.to_bytes(), dy.to_bytes());
    }

    #[test]
    fn scalar_mul_identity() {
        // 1 * G = G
        let mut one = [0u8; 32];
        one[31] = 1;
        let result = scalar_mul_base(&one);
        let (x, y) = result.to_affine();
        assert_eq!(x.to_bytes(), GX.to_bytes());
        assert_eq!(y.to_bytes(), GY.to_bytes());
    }

    #[test]
    fn scalar_mul_two() {
        // 2 * G = double(G)
        let mut two = [0u8; 32];
        two[31] = 2;
        let result = scalar_mul_base(&two);
        let doubled = Point::generator().double();
        let (rx, ry) = result.to_affine();
        let (dx, dy) = doubled.to_affine();
        assert_eq!(rx.to_bytes(), dx.to_bytes());
        assert_eq!(ry.to_bytes(), dy.to_bytes());
    }

    // -- NIST CAVP ECDH test vectors -----------------------------------------

    #[test]
    fn nist_cavp_ecdh_count0() {
        // NIST CAVP KAS_ECC_CDH_PrimitiveTest, COUNT=0
        let qcavs = hex65("04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");
        let diut = hex32("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let expected_z = hex32("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");

        let z = p256_ecdh(&Secret::new(diut), &P256UncompressedPublicKey::new(qcavs)).unwrap();
        assert_eq!(*z.declassify_ref(), expected_z);
    }

    #[test]
    fn nist_cavp_ecdh_count1() {
        // NIST CAVP KAS_ECC_CDH_PrimitiveTest, COUNT=1
        let qcavs = hex65("04809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7aeb29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3");
        let diut = hex32("38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5");
        let expected_z = hex32("057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67");

        let z = p256_ecdh(&Secret::new(diut), &P256UncompressedPublicKey::new(qcavs)).unwrap();
        assert_eq!(*z.declassify_ref(), expected_z);
    }

    // -- Public key generation -----------------------------------------------

    #[test]
    fn nist_cavp_pubkey_count0() {
        // Verify public key from COUNT=0 private key.
        let diut = hex32("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let expected = hex65("04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141");

        let pk = p256_pubkey(&Secret::new(diut));
        assert_eq!(*pk.as_bytes(), expected);
    }

    // -- Point encoding roundtrip --------------------------------------------

    #[test]
    fn encode_decode_uncompressed_roundtrip() {
        let sk = hex32("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let pk = p256_pubkey(&Secret::new(sk));
        let decoded = decode_point_uncompressed(pk.as_bytes()).unwrap();
        let re_encoded = encode_point_uncompressed(decoded);
        assert_eq!(*pk.as_bytes(), re_encoded);
    }

    #[test]
    fn encode_decode_compressed_roundtrip() {
        let sk = hex32("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let pk_full = p256_pubkey(&Secret::new(sk));
        let pk_compressed = p256_pubkey_compressed(&Secret::new(sk));

        // Decode compressed and re-encode as uncompressed.
        let decoded = decode_point_compressed(pk_compressed.as_bytes()).unwrap();
        let re_encoded = encode_point_uncompressed(decoded);
        assert_eq!(*pk_full.as_bytes(), re_encoded);
    }

    #[test]
    fn invalid_point_rejected() {
        // A point not on the curve should be rejected.
        let mut bad = [0u8; 65];
        bad[0] = 0x04;
        bad[1] = 0x42; // arbitrary x
        bad[33] = 0x42; // arbitrary y
        assert!(decode_point_uncompressed(&bad).is_none());
    }

    // -- Scalar validation ---------------------------------------------------

    #[test]
    fn scalar_zero_invalid() {
        assert!(!validate_scalar(&[0u8; 32]));
    }

    #[test]
    fn scalar_one_valid() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(validate_scalar(&one));
    }

    #[test]
    fn scalar_n_invalid() {
        // n itself is invalid (must be < n).
        let n_bytes = Fe(N).to_bytes(); // Reuse Fe serialization for N
        assert!(!validate_scalar(&n_bytes));
    }

    // -- ECDH commutativity --------------------------------------------------

    #[test]
    fn ecdh_commutativity() {
        let sk_a = hex32("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let sk_b = hex32("38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5");

        let pk_a = p256_pubkey(&Secret::new(sk_a));
        let pk_b = p256_pubkey(&Secret::new(sk_b));

        let z_ab = p256_ecdh(&Secret::new(sk_a), &pk_b).unwrap();
        let z_ba = p256_ecdh(&Secret::new(sk_b), &pk_a).unwrap();

        assert_eq!(*z_ab.declassify_ref(), *z_ba.declassify_ref());
    }

    // -- TS 33.501 C.4.4 vectors (ECIES Profile B keys) ----------------------

    #[test]
    fn ts33501_c44_hn_pubkey() {
        // Verify HN public key from HN private key.
        let hn_sk = hex32("f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda");
        let pk = p256_pubkey(&Secret::new(hn_sk));
        let expected_x = hex32("72da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1");
        let expected_y = hex32("5a7ded52fcbb097a4ed250e036c7b9c8c7004c4eedc4f068cd7bf8d3f900e3b4");
        assert_eq!(&pk.as_bytes()[1..33], &expected_x);
        assert_eq!(&pk.as_bytes()[33..65], &expected_y);
    }

    #[test]
    fn ts33501_c44_eph_pubkey() {
        // Verify ephemeral public key.
        let eph_sk = hex32("99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529");
        let pk = p256_pubkey(&Secret::new(eph_sk));
        let expected_x = hex32("9aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d1");
        let expected_y = hex32("d1f44ea1c87aa7478b954537bde79951e748a43294a4f4cf86eaff1789c9c81f");
        assert_eq!(&pk.as_bytes()[1..33], &expected_x);
        assert_eq!(&pk.as_bytes()[33..65], &expected_y);
    }

    #[test]
    fn ts33501_c44_shared_secret() {
        // Verify ECDH shared secret between ephemeral and HN keys.
        let eph_sk = hex32("99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529");
        let hn_pk = hex65("0472da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd15a7ded52fcbb097a4ed250e036c7b9c8c7004c4eedc4f068cd7bf8d3f900e3b4");
        let expected_z = hex32("6c7e6518980025b982fbb2ff746e3c2e85a196d252099a7ad23ea7b4c0959cae");

        let z = p256_ecdh(&Secret::new(eph_sk), &P256UncompressedPublicKey::new(hn_pk)).unwrap();
        assert_eq!(*z.declassify_ref(), expected_z);
    }

    #[test]
    fn ts33501_c44_compressed_decode() {
        // Verify compressed point decoding for the HN public key.
        let compressed = hex33("0272da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1");
        let point = decode_point_compressed(&compressed).unwrap();
        let (x, y) = point.to_affine();
        assert_eq!(x.to_bytes(), hex32("72da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1"));
        assert_eq!(y.to_bytes(), hex32("5a7ded52fcbb097a4ed250e036c7b9c8c7004c4eedc4f068cd7bf8d3f900e3b4"));
    }

    #[test]
    fn ts33501_c44_eph_compressed() {
        // Verify ephemeral compressed key.
        let eph_sk = hex32("99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529");
        let compressed = p256_pubkey_compressed(&Secret::new(eph_sk));
        let expected = hex33("039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d1");
        assert_eq!(*compressed.as_bytes(), expected);
    }

    // -- fe_reduce tests ----------------------------------------------------

    #[test]
    fn fe_reduce_below_p_is_identity() {
        let val = [1u64, 0, 0, 0];
        let fe = fe_reduce(val);
        assert_eq!(fe.0, val);
    }

    #[test]
    fn fe_reduce_p_gives_zero() {
        let fe = fe_reduce(P);
        assert_eq!(fe.0, [0u64; 4]);
    }

    #[test]
    fn fe_reduce_p_plus_one() {
        // p + 1 via multi-precision addition.
        let mut val = P;
        let mut carry = 1u64;
        let mut i = 0;
        while i < 4 {
            let (s, c) = val[i].overflowing_add(carry);
            val[i] = s;
            carry = c as u64;
            i += 1;
        }
        let fe = fe_reduce(val);
        assert_eq!(fe.0, [1, 0, 0, 0]);
    }

    #[test]
    fn fe_reduce_max_u256() {
        let val = [u64::MAX; 4];
        let fe = fe_reduce(val);
        let (expected, _) = sub_inner(val, P);
        assert_eq!(fe.0, expected);
    }

    // -- fe_from_hmac tests -------------------------------------------------

    #[test]
    fn fe_from_hmac_zero_input_gives_one() {
        let fe = fe_from_hmac(&[0u8; 32]);
        assert_eq!(fe.0, [1, 0, 0, 0]);
    }

    #[test]
    fn fe_from_hmac_p_in_be_gives_one() {
        // p encoded as big-endian bytes reduces to zero; must return 1.
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&P[3].to_be_bytes());
        b[8..16].copy_from_slice(&P[2].to_be_bytes());
        b[16..24].copy_from_slice(&P[1].to_be_bytes());
        b[24..32].copy_from_slice(&P[0].to_be_bytes());
        let fe = fe_from_hmac(&b);
        assert_eq!(fe.0, [1, 0, 0, 0], "zero mod p must map to 1");
    }

    #[test]
    fn fe_from_hmac_one() {
        let mut h = [0u8; 32];
        h[31] = 1;
        let fe = fe_from_hmac(&h);
        assert_eq!(fe.0, [1, 0, 0, 0]);
    }

    #[test]
    fn fe_from_hmac_above_p_reduces() {
        let fe = fe_from_hmac(&[0xFF; 32]);
        let raw = [u64::MAX; 4];
        let expected = fe_reduce(raw);
        assert_eq!(fe.0, expected.0);
        assert_ne!(fe.0, [0u64; 4]);
    }

    // -- randomize_projective tests -----------------------------------------

    #[test]
    fn randomize_projective_preserves_affine() {
        // (lam^2*X : lam^3*Y : lam*Z) represents the same affine point.
        // Verify: rp.x == g.x * rp.z^2 and rp.y == g.y * rp.z^3
        // (since g.z = 1).
        let g = Point { x: GX, y: GY, z: Fe::ONE };
        let lam = Fe([7, 0, 0, 0]);
        let rp = randomize_projective(g, lam);
        let rz2 = rp.z.mul(rp.z);
        let rz3 = rz2.mul(rp.z);
        assert_eq!(rp.x.to_bytes(), g.x.mul(rz2).to_bytes());
        assert_eq!(rp.y.to_bytes(), g.y.mul(rz3).to_bytes());
    }

    #[test]
    fn randomize_projective_with_one_is_identity() {
        let g = Point { x: GX, y: GY, z: Fe::ONE };
        let rp = randomize_projective(g, Fe::ONE);
        assert_eq!(rp.x.to_bytes(), g.x.to_bytes());
        assert_eq!(rp.y.to_bytes(), g.y.to_bytes());
        assert_eq!(rp.z.to_bytes(), g.z.to_bytes());
    }

    // -- blind_scalar tests -------------------------------------------------

    #[test]
    fn blind_scalar_zero_r_returns_k_padded() {
        let mut k = [0u8; 32];
        k[0] = 0x42;
        let r = [0u8; 16];
        let result = blind_scalar(&k, &r);
        assert_eq!(&result[..16], &[0u8; 16]);
        assert_eq!(&result[16..], &k[..]);
    }

    #[test]
    fn blind_scalar_r_one_adds_n() {
        // k=1, r=1 (LE) => k' = 1 + n.
        let mut k = [0u8; 32];
        k[31] = 1;
        let mut r = [0u8; 16];
        r[0] = 1;
        let result = blind_scalar(&k, &r);
        // n+1 ends with 0x52 (since n ends with 0x51).
        assert_eq!(result[47], 0x52);
        // First 16 bytes are zero (n+1 fits in 256 bits).
        assert_eq!(&result[..16], &[0u8; 16]);
    }

    #[test]
    fn blind_scalar_max_r_no_panic() {
        // r = 2^128 - 1, k = max 32-byte value. Must not panic.
        let k = [0xFFu8; 32];
        let r = [0xFFu8; 16];
        let result = blind_scalar(&k, &r);
        assert_eq!(result.len(), 48);
        assert!(result.iter().any(|&b| b != 0));
    }

    #[test]
    fn blind_scalar_algebraic_identity() {
        // For any k and r: (k + r*n) mod n == k mod n.
        // Since k < 2^256 and n ~ 2^256, k mod n is just k (for small k).
        // Verify via scalar_mul_wide: scalar_mul_wide(blind(k, r), G) == k*G.
        let mut k = [0u8; 32];
        k[31] = 7; // k = 7
        let mut r = [0u8; 16];
        r[0] = 42; // r = 42 (LE)
        let blinded = blind_scalar(&k, &r);
        let result = scalar_mul_wide(&blinded, Point::generator());
        let direct = scalar_mul_base(&k);
        let (rx, ry) = result.to_affine();
        let (dx, dy) = direct.to_affine();
        assert_eq!(rx.to_bytes(), dx.to_bytes());
        assert_eq!(ry.to_bytes(), dy.to_bytes());
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Strategy that generates a valid P-256 scalar in [1, n-1].
    // We use 32 random bytes and skip if they fall outside the valid range.
    fn valid_scalar() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>().prop_filter("scalar must be in [1, n-1]", |k| validate_scalar(k))
    }

    proptest! {
        // k * G is on the curve for any valid scalar k.
        #[test]
        fn scalar_mul_base_on_curve(k in valid_scalar()) {
            let q = scalar_mul_base(&k);
            let (x, y) = q.to_affine();
            prop_assert!(
                Point::is_on_curve_affine(x, y),
                "k*G must be on the curve"
            );
        }
    }

    proptest! {
        // ECDH commutativity: a*(b*G) == b*(a*G).
        #[test]
        fn ecdh_commutative(a in valid_scalar(), b in valid_scalar()) {
            let pk_a = p256_pubkey(&Secret::new(a));
            let pk_b = p256_pubkey(&Secret::new(b));

            let z_ab = p256_ecdh(&Secret::new(a), &pk_b).unwrap();
            let z_ba = p256_ecdh(&Secret::new(b), &pk_a).unwrap();
            prop_assert_eq!(z_ab.declassify_ref(), z_ba.declassify_ref(), "ECDH must be commutative");
        }
    }

    proptest! {
        // Compressed/uncompressed roundtrip: decompress(compress(k*G)) == k*G.
        #[test]
        fn compress_decompress_roundtrip(k in valid_scalar()) {
            let pk_uncompressed = p256_pubkey(&Secret::new(k));
            let pk_compressed = p256_pubkey_compressed(&Secret::new(k));
            let decompressed = p256_decompress_pubkey(&pk_compressed).unwrap();
            prop_assert_eq!(pk_uncompressed, decompressed);
        }
    }

    proptest! {
        // Different scalars produce different public keys.
        #[test]
        fn different_scalars_different_pubkeys(a in valid_scalar(), b in valid_scalar()) {
            prop_assume!(a != b);
            let pk_a = p256_pubkey(&Secret::new(a));
            let pk_b = p256_pubkey(&Secret::new(b));
            prop_assert_ne!(pk_a, pk_b, "different scalars must give different public keys");
        }
    }

    proptest! {
        // sqr_wide(a) == mul_wide(a, a) for random 4-limb inputs.
        // Tests the Comba squaring against the known-good schoolbook multiply
        // at the 512-bit level before NIST reduction.
        #[test]
        fn sqr_wide_matches_mul_wide(a in any::<[u64; 4]>()) {
            prop_assert_eq!(sqr_wide(a), mul_wide(a, a));
        }
    }

    proptest! {
        // Fe::square(a) == Fe::mul(a, a) for random field elements.
        // Exercises both the Comba squaring and the NIST reduction together.
        #[test]
        fn fe_square_matches_mul(bytes in any::<[u8; 32]>()) {
            let a = Fe::from_bytes(&bytes);
            prop_assert_eq!(a.square().to_bytes(), a.mul(a).to_bytes());
        }
    }
}
