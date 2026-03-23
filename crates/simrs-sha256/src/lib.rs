//! SHA-256 cryptographic hash function per [NIST FIPS 180-4](../../../docs/specs/nist/fips-180-4/NIST.FIPS.180-4.pdf).
//!
//! Provides both a streaming [`Sha256`] hasher and a one-shot [`sha256`] function.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
//!
//! # Example
//!
//! ```
//! use simrs_sha256::sha256;
//!
//! let digest = sha256(b"abc");
//! assert_eq!(
//!     digest,
//!     [
//!         0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
//!         0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
//!         0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
//!         0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
//!     ]
//! );
//! ```
#![no_std]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::unreadable_literal)]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Constants (FIPS 180-4 clauses 4.2.2 and 5.3.3)
// ---------------------------------------------------------------------------

/// Round constants: first 32 bits of the fractional parts of the cube roots
/// of the first 64 primes (FIPS 180-4 clause 4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash values: first 32 bits of the fractional parts of the square
/// roots of the first 8 primes (FIPS 180-4 clause 5.3.3).
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Block size in bytes (512 bits).
const BLOCK_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// SHA-256 logical functions (FIPS 180-4 clause 4.1.2)
// ---------------------------------------------------------------------------

const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

const fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

const fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

const fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

const fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// SHA-256 streaming hasher.
///
/// Processes data incrementally via [`update`](Sha256::update) and produces
/// a 256-bit digest via [`finalize`](Sha256::finalize).
///
/// ```
/// use simrs_sha256::Sha256;
///
/// let mut h = Sha256::new();
/// h.update(b"abc");
/// let digest = h.finalize();
/// assert_eq!(digest[0], 0xba);
/// ```
pub struct Sha256 {
    /// Working hash state (H0..H7).
    state: [u32; 8],
    /// Partial block buffer.
    buf: [u8; BLOCK_SIZE],
    /// Number of bytes buffered in `buf` (always < `BLOCK_SIZE`).
    buf_len: usize,
    /// Total message length in bytes.
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher with initial state.
    pub const fn new() -> Self {
        Self {
            state: H_INIT,
            buf: [0u8; BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        // If we have buffered data, try to fill the block.
        if self.buf_len > 0 {
            let space = BLOCK_SIZE - self.buf_len;
            let n = if data.len() < space {
                data.len()
            } else {
                space
            };
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            offset = n;

            if self.buf_len == BLOCK_SIZE {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly from input.
        while offset + BLOCK_SIZE <= data.len() {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
            compress(&mut self.state, &block);
            offset += BLOCK_SIZE;
        }

        // Buffer remaining bytes.
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize the hash and return the 256-bit digest.
    ///
    /// Consumes the hasher. Applies FIPS 180-4 clause 5.1.1 padding.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

        // Append 0x80 byte.
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If not enough room for the 8-byte length, pad this block and compress.
        if self.buf_len > 56 {
            // Zero-fill rest of current block.
            let mut i = self.buf_len;
            while i < BLOCK_SIZE {
                self.buf[i] = 0;
                i += 1;
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }

        // Zero-fill up to byte 56.
        let mut i = self.buf_len;
        while i < 56 {
            self.buf[i] = 0;
            i += 1;
        }

        // Append 64-bit big-endian bit length.
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());

        let block = self.buf;
        compress(&mut self.state, &block);

        // Produce output as big-endian bytes.
        let mut out = [0u8; 32];
        let mut j = 0;
        while j < 8 {
            let bytes = self.state[j].to_be_bytes();
            out[j * 4] = bytes[0];
            out[j * 4 + 1] = bytes[1];
            out[j * 4 + 2] = bytes[2];
            out[j * 4 + 3] = bytes[3];
            j += 1;
        }
        out
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-256: hash `data` and return the 256-bit digest.
///
/// ```
/// use simrs_sha256::sha256;
///
/// let empty = sha256(b"");
/// assert_eq!(empty[0], 0xe3); // e3b0c442...
/// ```
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Compression function (FIPS 180-4 clause 6.2.2)
// ---------------------------------------------------------------------------

/// Process one 512-bit (64-byte) block.
#[allow(clippy::cast_lossless)]
const fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    // 1. Prepare the message schedule W.
    let mut w = [0u32; 64];

    // W[0..16] = block words (big-endian).
    let mut t = 0;
    while t < 16 {
        let base = t * 4;
        // Note: `as u32` is used instead of `u32::from()` because
        // `From::from()` is not available in const fn on stable Rust.
        w[t] = (block[base] as u32) << 24
            | (block[base + 1] as u32) << 16
            | (block[base + 2] as u32) << 8
            | (block[base + 3] as u32);
        t += 1;
    }

    // W[16..64] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16].
    while t < 64 {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
        t += 1;
    }

    // 2. Initialize working variables.
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // 3. Compression rounds.
    t = 0;
    while t < 64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);

        t += 1;
    }

    // 4. Update state.
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: decode a hex string to bytes.
    fn hex(s: &str) -> [u8; 32] {
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

    // -- NIST FIPS 180-4 test vectors --

    #[test]
    fn empty_string() {
        let digest = sha256(b"");
        assert_eq!(
            digest,
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn abc() {
        let digest = sha256(b"abc");
        assert_eq!(
            digest,
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn msg_448_bits() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes = 448 bits)
        let digest = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    #[test]
    fn msg_896_bits() {
        // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno
        //  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" (112 bytes = 896 bits)
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let digest = sha256(msg);
        assert_eq!(
            digest,
            hex("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
        );
    }

    #[test]
    #[allow(clippy::large_stack_arrays)]
    fn one_million_a() {
        // 1,000,000 repetitions of 'a' (0x61).
        let digest = sha256(&[0x61; 1_000_000]);
        assert_eq!(
            digest,
            hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    // -- Streaming (multi-update) tests --

    #[test]
    fn streaming_equivalence() {
        // update("ab") + update("c") == sha256("abc")
        let mut h = Sha256::new();
        h.update(b"ab");
        h.update(b"c");
        let digest = h.finalize();
        assert_eq!(digest, sha256(b"abc"));
    }

    #[test]
    fn streaming_byte_at_a_time() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let mut h = Sha256::new();
        for &byte in msg {
            h.update(&[byte]);
        }
        let digest = h.finalize();
        assert_eq!(digest, sha256(msg));
    }

    #[test]
    fn streaming_one_million_a_chunked() {
        // Process 1M 'a' chars in 1000-byte chunks.
        let mut h = Sha256::new();
        let chunk = [0x61u8; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        let digest = h.finalize();
        assert_eq!(
            digest,
            hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    // -- Anti-theater tests --

    #[test]
    fn not_all_zero() {
        let digest = sha256(b"");
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn not_identity() {
        // SHA-256(x) != x for any plausible input.
        let data = [0x42u8; 32];
        let digest = sha256(&data);
        assert_ne!(digest, data);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let d1 = sha256(b"hello");
        let d2 = sha256(b"hellp");
        assert_ne!(d1, d2);
    }

    #[test]
    fn deterministic() {
        let d1 = sha256(b"test");
        let d2 = sha256(b"test");
        assert_eq!(d1, d2);
    }

    // -- Block boundary tests --

    #[test]
    fn exactly_one_block() {
        // 64 bytes = exactly one block.
        let data = [0xAB; 64];
        let _ = sha256(&data);
    }

    #[test]
    fn exactly_two_blocks() {
        // 128 bytes = exactly two blocks.
        let data = [0xCD; 128];
        let _ = sha256(&data);
    }

    #[test]
    fn padding_boundary_55_bytes() {
        // 55 bytes: padding fits in the same block (55 + 1 + 8 = 64).
        let data = [0xEF; 55];
        let _ = sha256(&data);
    }

    #[test]
    fn padding_boundary_56_bytes() {
        // 56 bytes: padding requires an extra block (56 + 1 + 8 = 65 > 64).
        let data = [0xEF; 56];
        let _ = sha256(&data);
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Streaming equivalence: sha256(a||b) must equal update(a)+update(b)+finalize.
        // Uses fixed-size arrays to stay no_std compatible.
        #[test]
        fn streaming_equivalence(
            a in any::<[u8; 64]>(),
            a_len in 0usize..=64,
            b in any::<[u8; 64]>(),
            b_len in 0usize..=64,
        ) {
            let a = &a[..a_len];
            let b = &b[..b_len];

            // One-shot: hash the concatenation.
            let mut combined = [0u8; 128];
            combined[..a.len()].copy_from_slice(a);
            combined[a.len()..a.len() + b.len()].copy_from_slice(b);
            let one_shot = sha256(&combined[..a.len() + b.len()]);

            // Streaming: update(a) then update(b).
            let mut hasher = Sha256::new();
            hasher.update(a);
            hasher.update(b);
            let streamed = hasher.finalize();

            prop_assert_eq!(one_shot, streamed);
        }
    }

    proptest! {
        // Non-zero output: SHA-256 of any input must not be all-zeros.
        #[test]
        fn non_zero_output(data in any::<[u8; 64]>(), len in 0usize..=64) {
            let digest = sha256(&data[..len]);
            prop_assert_ne!(digest, [0u8; 32]);
        }
    }

    proptest! {
        // Collision resistance (probabilistic): different inputs should produce
        // different digests. Not guaranteed but practically certain for random data.
        #[test]
        fn different_inputs_different_digests(
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
        ) {
            prop_assume!(a != b);
            let da = sha256(&a);
            let db = sha256(&b);
            prop_assert_ne!(da, db, "distinct inputs should produce distinct digests");
        }
    }

    proptest! {
        // Single-bit flip changes the digest.
        #[test]
        fn bit_flip_changes_digest(
            data in any::<[u8; 32]>(),
            bit_idx in 0usize..256,
        ) {
            let d1 = sha256(&data);
            let mut flipped = data;
            flipped[bit_idx / 8] ^= 1 << (bit_idx % 8);
            let d2 = sha256(&flipped);
            prop_assert_ne!(d1, d2, "flipping bit {} should change digest", bit_idx);
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet via ct_test wrapper)
//
//   cargo test -p simrs-sha256 --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    /// SHA-256 timing must be independent of input content for fixed-length
    /// inputs. Class 0: all-zero block. Class 1: random block.
    #[test]
    fn test_sha256_ct() {
        let outcome = ct_test(
            0x5A25_6C17,
            |rng| {
                let _ = rng;
                [0u8; 64]
            },
            |rng| {
                let mut buf = [0u8; 64];
                rng.fill_bytes(&mut buf);
                buf
            },
            |input| {
                black_box(sha256(input));
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
