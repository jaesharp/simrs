//! SHA-1 cryptographic hash function per [NIST FIPS 180-1](https://csrc.nist.gov/pubs/fips/180-1/final).
//!
//! Required by `GlobalPlatform` SCP01/SCP02 key derivation (GP 2.1.1
//! Appendix B.2.1; GP 2.3.1 retains SHA-1 in its cryptographic
//! algorithm appendix) and the `JavaCard` `MessageDigest.ALG_SHA` API.
//!
//! Provides both a streaming [`Sha1`] hasher and a one-shot [`sha1`] function.
//!
//! # Security Note
//!
//! SHA-1 is cryptographically broken for collision resistance (`SHAttered`, 2017).
//! It remains in use for legacy smart card protocols where the spec mandates it.
//! New designs should use SHA-256 ([`simrs_sha256`]).
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
//!
//! # Example
//!
//! ```
//! use simrs_sha1::sha1;
//!
//! let digest = sha1(b"abc");
//! assert_eq!(
//!     digest,
//!     [
//!         0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
//!         0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
//!     ]
//! );
//! ```
#![no_std]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::unreadable_literal)]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Constants (FIPS 180-1 clause 5)
// ---------------------------------------------------------------------------

/// Round constants `K_t` (FIPS 180-1 clause 5).
const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

/// Initial hash values H0-H4 (FIPS 180-1 clause 7).
const H_INIT: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Block size in bytes (512 bits).
const BLOCK_SIZE: usize = 64;

/// Digest size in bytes (160 bits).
pub const DIGEST_SIZE: usize = 20;

// ---------------------------------------------------------------------------
// SHA-1 logical functions (FIPS 180-1 clause 5)
// ---------------------------------------------------------------------------

const fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => (b & c) | ((!b) & d),
        40..=59 => (b & c) | (b & d) | (c & d),
        // Rounds 20..=39 and 60..=79 use the same function (FIPS 180-1 clause 5).
        _ => b ^ c ^ d,
    }
}

const fn k(t: usize) -> u32 {
    match t {
        0..=19 => K[0],
        20..=39 => K[1],
        40..=59 => K[2],
        _ => K[3],
    }
}

// ---------------------------------------------------------------------------
// Block processing (FIPS 180-1 clause 7)
// ---------------------------------------------------------------------------

/// Process a single 512-bit block, updating the hash state.
fn compress(state: &mut [u32; 5], block: &[u8; BLOCK_SIZE]) {
    // Step a: Prepare message schedule W[0..79]
    let mut w = [0u32; 80];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[t * 4],
            block[t * 4 + 1],
            block[t * 4 + 2],
            block[t * 4 + 3],
        ]);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }

    // Step b: Initialize working variables
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    // Step c: 80 rounds (FIPS 180-1 clause 8, step d)
    for (t, &w_t) in w.iter().enumerate() {
        let temp = a
            .rotate_left(5)
            .wrapping_add(f(t, b, c, d))
            .wrapping_add(e)
            .wrapping_add(w_t)
            .wrapping_add(k(t));
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    // Step d: Update hash state
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Streaming SHA-1 hasher.
///
/// Accumulates data via [`update`](Sha1::update) and produces the final
/// 20-byte digest via [`finalize`](Sha1::finalize).
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Create a new SHA-1 hasher.
    pub const fn new() -> Self {
        Self {
            state: H_INIT,
            buffer: [0u8; BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    ///
    /// # Panics
    ///
    /// Cannot panic. The internal `expect` is guarded by the slice length check.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // If we have buffered data, try to fill the block.
        if self.buf_len > 0 {
            let fill = BLOCK_SIZE - self.buf_len;
            if data.len() < fill {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..BLOCK_SIZE].copy_from_slice(&data[..fill]);
            let block: [u8; BLOCK_SIZE] = self.buffer;
            compress(&mut self.state, &block);
            self.buf_len = 0;
            offset = fill;
        }

        // Process full blocks directly.
        while offset + BLOCK_SIZE <= data.len() {
            let block: &[u8; BLOCK_SIZE] = data[offset..offset + BLOCK_SIZE]
                .try_into()
                .expect("slice is exactly BLOCK_SIZE");
            compress(&mut self.state, block);
            offset += BLOCK_SIZE;
        }

        // Buffer remaining bytes.
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize the hash and return the 20-byte digest.
    ///
    /// Consumes the hasher. For reuse, create a new [`Sha1`].
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        // Padding: append 0x80, then zeros, then 64-bit big-endian bit count.
        let bit_len = self.total_len * 8;

        // Append 0x80.
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If not enough room for the 8-byte length, pad this block and compress.
        if self.buf_len > 56 {
            self.buffer[self.buf_len..BLOCK_SIZE].fill(0);
            let block: [u8; BLOCK_SIZE] = self.buffer;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }

        // Zero-pad to 56 bytes, then append 64-bit big-endian bit count.
        self.buffer[self.buf_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block: [u8; BLOCK_SIZE] = self.buffer;
        compress(&mut self.state, &block);

        // Produce output.
        let mut digest = [0u8; DIGEST_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// Compute SHA-1 hash of `data` in one shot.
///
/// ```
/// use simrs_sha1::sha1;
///
/// assert_eq!(
///     sha1(b""),
///     [
///         0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
///         0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
///     ]
/// );
/// ```
pub fn sha1(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // NIST FIPS 180-1 Appendix A: SHA-1 test vectors.

    #[test]
    fn nist_abc() {
        // "abc"
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
    }

    #[test]
    fn nist_empty() {
        // Empty string
        assert_eq!(
            sha1(b""),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ]
        );
    }

    #[test]
    fn nist_448bit() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (448 bits)
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            [
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
                0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
            ]
        );
    }

    #[test]
    fn nist_million_a() {
        // 1,000,000 repetitions of 'a'
        let mut h = Sha1::new();
        // Feed in chunks to test streaming.
        for _ in 0..10000 {
            h.update(&[0x61; 100]);
        }
        assert_eq!(
            h.finalize(),
            [
                0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
                0x27, 0x31, 0x65, 0x34, 0x01, 0x6f,
            ]
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = sha1(data);

        // Feed byte-by-byte.
        let mut h = Sha1::new();
        for &byte in data {
            h.update(&[byte]);
        }
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn streaming_across_block_boundary() {
        // 63 bytes (just under one block), then 65 bytes (crosses into second block).
        let mut h = Sha1::new();
        h.update(&[0xAA; 63]);
        h.update(&[0xBB; 65]);
        let streamed = h.finalize();

        let mut full = [0u8; 128];
        full[..63].fill(0xAA);
        full[63..128].fill(0xBB);
        assert_eq!(sha1(&full), streamed);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn streaming_equals_oneshot(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let oneshot = sha1(&data);

            let mut h = Sha1::new();
            // Split at arbitrary point.
            if data.len() > 1 {
                let mid = data.len() / 2;
                h.update(&data[..mid]);
                h.update(&data[mid..]);
            } else {
                h.update(&data);
            }
            prop_assert_eq!(h.finalize(), oneshot);
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet via ct_test wrapper)
//
//   cargo test -p simrs-sha1 --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    /// SHA-1 timing must be independent of input content for fixed-length
    /// inputs. Class 0: all-zero block. Class 1: random block.
    #[test]
    fn test_sha1_ct() {
        let outcome = ct_test(
            0x5A01_0C17,
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
                black_box(sha1(input));
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
