//! X25519 Diffie-Hellman function per [RFC 7748](../../../docs/specs/ietf/rfc7748.txt).
//!
//! Implements scalar multiplication on Curve25519 using the Montgomery ladder.
//! Field elements in GF(2^255 - 19) are represented as five 51-bit limbs in
//! radix 2^51.

// ---------------------------------------------------------------------------
// Field element: GF(2^255 - 19)
// ---------------------------------------------------------------------------

/// A field element in GF(2^255 - 19), stored as five u64 limbs in
/// radix 2^51. Each limb holds at most ~52 bits during computation;
/// a fully reduced element has each limb < 2^51.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

/// 2^51
const MASK51: u64 = (1u64 << 51) - 1;

impl Fe {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Construct from a 32-byte little-endian encoding.
    fn from_bytes(b: &[u8; 32]) -> Self {
        let mut out = [0u64; 5];
        // Load 32 bytes into a u256 via 4 u64s, then extract 51-bit limbs.
        let load64 = |offset: usize| -> u64 {
            let mut v = [0u8; 8];
            let end = if offset + 8 <= 32 { offset + 8 } else { 32 };
            let len = end - offset;
            v[..len].copy_from_slice(&b[offset..end]);
            u64::from_le_bytes(v)
        };

        // Limb 0: bits [0..51)
        out[0] = load64(0) & MASK51;
        // Limb 1: bits [51..102) -- starts at byte 6 bit 3
        out[1] = (load64(6) >> 3) & MASK51;
        // Limb 2: bits [102..153) -- starts at byte 12 bit 6
        out[2] = (load64(12) >> 6) & MASK51;
        // Limb 3: bits [153..204) -- starts at byte 19 bit 1
        out[3] = (load64(19) >> 1) & MASK51;
        // Limb 4: bits [204..255) -- starts at byte 25 bit 4
        out[4] = (load64(25) >> 4) & MASK51;

        Self(out)
    }

    /// Encode to 32-byte little-endian representation.
    fn to_bytes(self) -> [u8; 32] {
        let f = self.reduce();
        let mut out = [0u8; 32];

        // Reconstruct 256 bits from five 51-bit limbs.
        // Limb boundaries: 0, 51, 102, 153, 204
        let combine = |a: u64, a_shift: u32, b: u64, b_shift: u32| -> u64 {
            (a >> a_shift) | (b << b_shift)
        };

        let h0 = f.0[0];
        let h1 = f.0[1];
        let h2 = f.0[2];
        let h3 = f.0[3];
        let h4 = f.0[4];

        // Bytes 0..8: bits [0..64) = h0[0..51) | h1[0..13)
        let w0 = h0 | (h1 << 51);
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        // Bytes 8..16: bits [64..128) = h1[13..51) | h2[0..26)
        let w1 = combine(h1, 13, h2, 38);
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        // Bytes 16..24: bits [128..192) = h2[26..51) | h3[0..39)
        let w2 = combine(h2, 26, h3, 25);
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        // Bytes 24..32: bits [192..256) = h3[39..51) | h4[0..51)
        let w3 = combine(h3, 39, h4, 12);
        out[24..32].copy_from_slice(&w3.to_le_bytes());

        out
    }

    /// Carry-propagate: ensure each limb < 2^52.
    fn carry(self) -> Self {
        let mut h = self.0;
        let mut i = 0;
        while i < 4 {
            let carry = h[i] >> 51;
            h[i] &= MASK51;
            h[i + 1] += carry;
            i += 1;
        }
        // Top limb: carry wraps around with factor 19 (since 2^255 = 19 mod p).
        let carry = h[4] >> 51;
        h[4] &= MASK51;
        h[0] += carry * 19;
        Self(h)
    }

    /// Fully reduce modulo p = 2^255 - 19.
    fn reduce(self) -> Self {
        // First carry to normalize.
        let mut f = self.carry().carry();

        // Check if f >= p. If so, subtract p.
        // p = 2^255 - 19, so in limbs: [2^51 - 19, 2^51 - 1, 2^51 - 1, 2^51 - 1, 2^51 - 1]
        // We compute f - p and check if it's non-negative.
        let mut g = [0u64; 5];
        g[0] = f.0[0].wrapping_sub(MASK51 - 18);
        g[1] = f.0[1].wrapping_sub(MASK51);
        g[2] = f.0[2].wrapping_sub(MASK51);
        g[3] = f.0[3].wrapping_sub(MASK51);
        g[4] = f.0[4].wrapping_sub(MASK51);

        // Propagate borrows.
        let mut i = 0;
        while i < 4 {
            let borrow = (g[i] >> 63) & 1;
            g[i] &= MASK51;
            g[i + 1] = g[i + 1].wrapping_sub(borrow);
            i += 1;
        }

        // If g[4] bit 63 is set, subtraction underflowed: f < p, keep f.
        // Otherwise f >= p, use g (= f - p).
        let mask = 0u64.wrapping_sub((g[4] >> 63) & 1); // all-1s if f < p
        f.0[0] = (f.0[0] & mask) | (g[0] & !mask);
        f.0[1] = (f.0[1] & mask) | (g[1] & !mask);
        f.0[2] = (f.0[2] & mask) | (g[2] & !mask);
        f.0[3] = (f.0[3] & mask) | (g[3] & !mask);
        f.0[4] = (f.0[4] & mask) | ((g[4] & MASK51) & !mask);

        f
    }

    /// Addition.
    fn add(self, rhs: Self) -> Self {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    /// Subtraction (add 2p to avoid underflow before subtracting).
    fn sub(self, rhs: Self) -> Self {
        // Add 2*p to each limb to ensure non-negative results.
        // 2*p limbs: [2*(2^51-19), 2*(2^51-1), 2*(2^51-1), 2*(2^51-1), 2*(2^51-1)]
        Self([
            self.0[0] + 2 * (MASK51 - 18) - rhs.0[0],
            self.0[1] + 2 * MASK51 - rhs.0[1],
            self.0[2] + 2 * MASK51 - rhs.0[2],
            self.0[3] + 2 * MASK51 - rhs.0[3],
            self.0[4] + 2 * MASK51 - rhs.0[4],
        ]).carry()
    }

    /// Multiplication using u128 intermediates.
    #[allow(clippy::cast_possible_truncation)]
    fn mul(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;

        // Precompute 19*b[i] for reduction of cross terms.
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        // Schoolbook multiplication with reduction.
        // Result limb i = sum of a[j]*b[k] where (j+k) mod 5 == i,
        // with a factor of 19 for wrap-around terms.
        let t0 = (a[0] as u128) * (b[0] as u128)
            + (a[1] as u128) * (b4_19 as u128)
            + (a[2] as u128) * (b3_19 as u128)
            + (a[3] as u128) * (b2_19 as u128)
            + (a[4] as u128) * (b1_19 as u128);

        let t1 = (a[0] as u128) * (b[1] as u128)
            + (a[1] as u128) * (b[0] as u128)
            + (a[2] as u128) * (b4_19 as u128)
            + (a[3] as u128) * (b3_19 as u128)
            + (a[4] as u128) * (b2_19 as u128);

        let t2 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128)
            + (a[3] as u128) * (b4_19 as u128)
            + (a[4] as u128) * (b3_19 as u128);

        let t3 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128)
            + (a[4] as u128) * (b4_19 as u128);

        let t4 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);

        // Carry chain.
        let mut r = [0u64; 5];
        let mut carry: u128;

        r[0] = (t0 as u64) & MASK51;
        carry = t0 >> 51;

        let t1 = t1 + carry;
        r[1] = (t1 as u64) & MASK51;
        carry = t1 >> 51;

        let t2 = t2 + carry;
        r[2] = (t2 as u64) & MASK51;
        carry = t2 >> 51;

        let t3 = t3 + carry;
        r[3] = (t3 as u64) & MASK51;
        carry = t3 >> 51;

        let t4 = t4 + carry;
        r[4] = (t4 as u64) & MASK51;
        carry = t4 >> 51;

        // Wrap carry with factor 19.
        r[0] += (carry as u64) * 19;
        // One more carry from r[0].
        let c = r[0] >> 51;
        r[0] &= MASK51;
        r[1] += c;

        Self(r)
    }

    /// Squaring mod p (alias for `mul(self, self)`).
    fn square(self) -> Self {
        self.mul(self)
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

    /// Compute the multiplicative inverse via Fermat's little theorem:
    /// a^(-1) = a^(p-2) where p = 2^255 - 19.
    /// p-2 = 2^255 - 21.
    fn invert(self) -> Self {
        // Addition chain for p-2 = 2^255 - 21.
        // Following the standard decomposition.
        let a = self;

        // a^2
        let a2 = a.square();
        // a^(2^2 - 1) = a^3
        let a_2_1 = a2.mul(a);
        // a^(2^3 - 1) = a^7 -- wait, we actually need a^(2^2) * a^(2^2-1)
        // Let's use the standard chain from curve25519-donna.

        // t = a^(2^2 - 1) = a^3
        let t = a_2_1;

        // a^(2^4 - 1) = (a^(2^2-1))^(2^2) * a^(2^2-1) = a^15
        let t2 = t.square_n(2).mul(t);

        // a^(2^5 - 1) = (a^(2^4-1))^2 * a = a^31
        let t5 = t2.square().mul(a);

        // a^(2^10 - 1) = (a^(2^5-1))^(2^5) * a^(2^5-1)
        let t10 = t5.square_n(5).mul(t5);

        // a^(2^20 - 1)
        let t20 = t10.square_n(10).mul(t10);

        // a^(2^40 - 1)
        let t40 = t20.square_n(20).mul(t20);

        // a^(2^50 - 1)
        let t50 = t40.square_n(10).mul(t10);

        // a^(2^100 - 1)
        let t100 = t50.square_n(50).mul(t50);

        // a^(2^200 - 1)
        let t200 = t100.square_n(100).mul(t100);

        // a^(2^250 - 1)
        let t250 = t200.square_n(50).mul(t50);

        // a^(2^255 - 2^5) = (a^(2^250-1))^(2^5)
        let t255_5 = t250.square_n(5);

        // a^(2^255 - 21) = a^(2^255 - 2^5) * a^(2^5 - 2^2 - 1)
        // 2^5 - 21 = 32 - 21 = 11 = 1011b
        // a^11 = a^8 * a^2 * a = (a^(2^2-1))^(2^1) * a^(2^2) * a ... hmm.
        // Actually: 2^255 - 21 = (2^255 - 32) + 11 = 2^255 - 2^5 + 11
        // a^(p-2) = a^(2^255-21) = t255_5 * a^11
        // a^11: a^8 * a^2 * a = a2.square().square().mul(a2).mul(a)
        let a11 = a2.square().square().mul(a2).mul(a);

        t255_5.mul(a11)
    }

    /// Constant-time conditional swap.
    /// If swap == 1, swap self and other. If swap == 0, no-op.
    fn cswap(&mut self, other: &mut Self, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        let mut i = 0;
        while i < 5 {
            let t = mask & (self.0[i] ^ other.0[i]);
            self.0[i] ^= t;
            other.0[i] ^= t;
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// X25519 scalar multiplication per [RFC 7748](../../../docs/specs/ietf/rfc7748.txt) clause 5.
///
/// Computes the shared secret `scalar * point` on Curve25519 using the
/// Montgomery ladder. Both scalar and point are 32-byte little-endian encodings.
///
/// The scalar is clamped per RFC 7748:
/// - Clear bits 0, 1, 2 of the first byte
/// - Clear bit 7 of the last byte
/// - Set bit 6 of the last byte
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    // Clamp scalar per RFC 7748 clause 5.
    let mut k = *scalar;
    k[0] &= 248;  // clear bits 0, 1, 2
    k[31] &= 127; // clear bit 255
    k[31] |= 64;  // set bit 254

    let u = Fe::from_bytes(point);
    ladder(&k, &u).to_bytes()
}

/// Curve25519 base point (u=9).
const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// X25519 base point multiplication: compute the public key from a secret key.
///
/// Equivalent to `x25519(scalar, &[9, 0, 0, ..., 0])`.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    x25519(scalar, &BASEPOINT)
}

// ---------------------------------------------------------------------------
// Montgomery ladder (RFC 7748 clause 5)
// ---------------------------------------------------------------------------

/// Montgomery ladder for scalar multiplication on Curve25519.
///
/// `k` is the clamped scalar (32 bytes), `u` is the u-coordinate of the point.
fn ladder(k: &[u8; 32], u: &Fe) -> Fe {
    let x_1 = *u;
    let mut x_2 = Fe::ONE;
    let mut z_2 = Fe::ZERO;
    let mut x_3 = *u;
    let mut z_3 = Fe::ONE;
    let mut swap: u64 = 0;

    // Constant a24 = (A - 2) / 4 = (486662 - 2) / 4 = 121665.
    let a24 = Fe([121_665, 0, 0, 0, 0]);

    // Process bits from 254 down to 0.
    let mut t: i32 = 254;
    while t >= 0 {
        let k_t = ((k[(t >> 3) as usize] >> (t & 7)) & 1) as u64;
        swap ^= k_t;
        Fe::cswap(&mut x_2, &mut x_3, swap);
        Fe::cswap(&mut z_2, &mut z_3, swap);
        swap = k_t;

        let a = x_2.add(z_2);
        let aa = a.square();
        let b = x_2.sub(z_2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x_3.add(z_3);
        let d = x_3.sub(z_3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x_3 = da.add(cb).square();
        z_3 = da.sub(cb).square().mul(x_1);
        x_2 = aa.mul(bb);
        z_2 = e.mul(aa.add(a24.mul(e)));

        t -= 1;
    }

    Fe::cswap(&mut x_2, &mut x_3, swap);
    Fe::cswap(&mut z_2, &mut z_3, swap);

    // Return x_2 * z_2^(-1).
    x_2.mul(z_2.invert())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            let hi = match s.as_bytes()[i * 2] {
                b'0'..=b'9' => s.as_bytes()[i * 2] - b'0',
                b'a'..=b'f' => s.as_bytes()[i * 2] - b'a' + 10,
                _ => panic!("bad hex"),
            };
            let lo = match s.as_bytes()[i * 2 + 1] {
                b'0'..=b'9' => s.as_bytes()[i * 2 + 1] - b'0',
                b'a'..=b'f' => s.as_bytes()[i * 2 + 1] - b'a' + 10,
                _ => panic!("bad hex"),
            };
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    // -- RFC 7748 Section 5.2 scalar multiplication vectors --
    // (docs/specs/ietf/rfc7748.txt)

    #[test]
    fn rfc7748_scalar_mul_1() {
        let scalar = hex_to_32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let point  = hex_to_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expect = hex_to_32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&scalar, &point), expect);
    }

    #[test]
    fn rfc7748_scalar_mul_2() {
        let scalar = hex_to_32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let point  = hex_to_32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expect = hex_to_32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&scalar, &point), expect);
    }

    // -- RFC 7748 Section 5.2 iterated test --

    #[test]
    fn rfc7748_iterated_1() {
        // After 1 iteration starting from k=u=9.
        let nine = {
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        };
        let result = x25519(&nine, &nine);
        let expect = hex_to_32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        assert_eq!(result, expect);
    }

    #[test]
    fn rfc7748_iterated_1000() {
        // After 1000 iterations starting from k=u=9.
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = [0u8; 32];
        u[0] = 9;

        for _ in 0..1000 {
            let new_k = x25519(&k, &u);
            u = k;
            k = new_k;
        }
        let expect = hex_to_32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
        assert_eq!(k, expect);
    }

    // Note: the 1,000,000 iteration test from RFC 7748 is omitted due to
    // execution time (~minutes without optimizations). The 1000-iteration
    // test exercises the same code path.

    // -- RFC 7748 Section 6.1 Diffie-Hellman --

    #[test]
    fn rfc7748_dh_alice_pubkey() {
        let alice_sk = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk = hex_to_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(x25519_base(&alice_sk), alice_pk);
    }

    #[test]
    fn rfc7748_dh_bob_pubkey() {
        let bob_sk = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pk = hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(x25519_base(&bob_sk), bob_pk);
    }

    #[test]
    fn rfc7748_dh_shared_secret() {
        let alice_sk = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_pk   = hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared   = hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&alice_sk, &bob_pk), shared);
    }

    #[test]
    fn rfc7748_dh_shared_secret_bob_side() {
        let bob_sk   = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_pk = hex_to_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let shared   = hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        // Both sides must compute the same shared secret.
        assert_eq!(x25519(&bob_sk, &alice_pk), shared);
    }

    // -- Anti-theater tests --

    #[test]
    fn x25519_not_zero() {
        // Non-trivial scalar * basepoint should not be all-zero.
        let sk = [42u8; 32];
        let pk = x25519_base(&sk);
        assert_ne!(pk, [0u8; 32]);
    }

    #[test]
    fn x25519_different_keys_different_outputs() {
        // Use values that differ in bits that survive clamping (bits 3+).
        let sk1 = {
            let mut b = [0u8; 32];
            b[0] = 8; // bit 3 set, survives k[0] &= 248
            b
        };
        let sk2 = {
            let mut b = [0u8; 32];
            b[0] = 16; // bit 4 set
            b
        };
        assert_ne!(x25519_base(&sk1), x25519_base(&sk2));
    }

    // -- Field element round-trip tests --

    #[test]
    fn fe_encode_decode_roundtrip() {
        let bytes = hex_to_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let fe = Fe::from_bytes(&bytes);
        let out = fe.to_bytes();
        assert_eq!(out, bytes);
    }

    #[test]
    fn fe_one_roundtrip() {
        let one = Fe::ONE;
        let bytes = one.to_bytes();
        assert_eq!(bytes[0], 1);
        assert!(bytes[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn fe_mul_one_identity() {
        // Use a non-trivial value, not zero or one.
        let bytes = hex_to_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let a = Fe::from_bytes(&bytes);
        let result = a.mul(Fe::ONE);
        assert_eq!(result.to_bytes(), bytes);
    }

    #[test]
    fn fe_invert_self_mul_is_one() {
        let bytes = hex_to_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let a = Fe::from_bytes(&bytes);
        let a_inv = a.invert();
        let product = a.mul(a_inv);
        let result = product.to_bytes();

        let mut expected_one = [0u8; 32];
        expected_one[0] = 1;
        assert_eq!(result, expected_one);
    }
}
