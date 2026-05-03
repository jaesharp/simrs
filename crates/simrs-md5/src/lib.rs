//! MD5 message-digest algorithm per [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321).
//!
//! Required by the `JavaCard` `MessageDigest.ALG_MD5` API on JCOP20+ cards.
//!
//! Provides both a streaming [`Md5`] hasher and a one-shot [`md5`] function.
//!
//! # Security Note
//!
//! MD5 is cryptographically broken (collision attacks practical since 2004).
//! It is included solely because the `JavaCard` 2.1.1 API mandates it for
//! legacy smart card applications. New designs must not use MD5.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
//!
//! # Example
//!
//! ```
//! use simrs_md5::md5;
//!
//! let digest = md5(b"");
//! assert_eq!(
//!     digest,
//!     [
//!         0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
//!         0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
//!     ]
//! );
//! ```
#![no_std]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::unreadable_literal)]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Constants (RFC 1321 clause 3.4)
// ---------------------------------------------------------------------------

/// Per-round shift amounts s[i] (RFC 1321 clause 3.4).
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// Per-round constants T[i] = floor(2^32 * abs(sin(i+1))) (RFC 1321 clause 3.4).
const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Initial hash values (RFC 1321 clause 3.3): A, B, C, D.
const INIT: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// Block size in bytes (512 bits).
const BLOCK_SIZE: usize = 64;

/// Digest size in bytes (128 bits).
pub const DIGEST_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Block processing (RFC 1321 clause 3.4)
// ---------------------------------------------------------------------------

/// Process a single 512-bit block, updating the hash state.
fn compress(state: &mut [u32; 4], block: &[u8; BLOCK_SIZE]) {
    // Decode block into 16 little-endian 32-bit words.
    let mut m = [0u32; 16];
    for (i, m_i) in m.iter_mut().enumerate() {
        *m_i = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | ((!b) & d), i),
            16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | (!d)), (7 * i) % 16),
        };

        let temp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(T[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]),
        );
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Streaming MD5 hasher.
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// Create a new MD5 hasher.
    pub const fn new() -> Self {
        Self {
            state: INIT,
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

        while offset + BLOCK_SIZE <= data.len() {
            let block: &[u8; BLOCK_SIZE] = data[offset..offset + BLOCK_SIZE]
                .try_into()
                .expect("slice is exactly BLOCK_SIZE");
            compress(&mut self.state, block);
            offset += BLOCK_SIZE;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize the hash and return the 16-byte digest.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        let bit_len = self.total_len * 8;

        // Append 0x80.
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buffer[self.buf_len..BLOCK_SIZE].fill(0);
            let block: [u8; BLOCK_SIZE] = self.buffer;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }

        // Zero-pad to 56 bytes, then append 64-bit LITTLE-endian bit count.
        self.buffer[self.buf_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_len.to_le_bytes());
        let block: [u8; BLOCK_SIZE] = self.buffer;
        compress(&mut self.state, &block);

        // Produce output in LITTLE-endian (RFC 1321 clause 3.5).
        let mut digest = [0u8; DIGEST_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        digest
    }
}

/// Compute MD5 hash of `data` in one shot.
///
/// ```
/// use simrs_md5::md5;
///
/// assert_eq!(
///     md5(b"abc"),
///     [
///         0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
///         0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
///     ]
/// );
/// ```
pub fn md5(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Tests (RFC 1321 Appendix A.5)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1321_empty() {
        assert_eq!(
            md5(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e,
            ]
        );
    }

    #[test]
    fn rfc1321_a() {
        assert_eq!(
            md5(b"a"),
            [
                0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77,
                0x26, 0x61,
            ]
        );
    }

    #[test]
    fn rfc1321_abc() {
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72,
            ]
        );
    }

    #[test]
    fn rfc1321_message_digest() {
        assert_eq!(
            md5(b"message digest"),
            [
                0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1,
                0x61, 0xd0,
            ]
        );
    }

    #[test]
    fn rfc1321_alphabet() {
        assert_eq!(
            md5(b"abcdefghijklmnopqrstuvwxyz"),
            [
                0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67,
                0xe1, 0x3b,
            ]
        );
    }

    #[test]
    fn rfc1321_alphanumeric() {
        assert_eq!(
            md5(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            [
                0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41,
                0x9d, 0x9f,
            ]
        );
    }

    #[test]
    fn rfc1321_numeric_repeat() {
        assert_eq!(
            md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            [
                0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07,
                0xb6, 0x7a,
            ]
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = md5(data);

        let mut h = Md5::new();
        for &byte in data {
            h.update(&[byte]);
        }
        assert_eq!(h.finalize(), oneshot);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn streaming_equals_oneshot(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let oneshot = md5(&data);

            let mut h = Md5::new();
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
// Constant-time validation (tacet Bayesian timing analysis)
//
// MD5 itself processes public data in most uses, but it appears in JC API
// `javacard.security.MessageDigest` where applet-supplied input may be
// secret. These tests assert that the hash compression function shows no
// statistically-detectable timing dependence on the input bytes.
//
// Run via: cargo test -p simrs-md5 --features ct-validation ct_validation
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    #[test]
    fn md5_oneshot_is_constant_time_in_input() {
        let outcome = ct_test(
            0x00D5_C9A0,
            |_rng| [0u8; 64],
            |rng| {
                let mut data = [0u8; 64];
                rng.fill_bytes(&mut data);
                data
            },
            |data| {
                let h = md5(data);
                black_box(h);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn md5_streaming_is_constant_time_in_input() {
        let outcome = ct_test(
            0x00D5_C9A1,
            |_rng| [0u8; 128],
            |rng| {
                let mut data = [0u8; 128];
                rng.fill_bytes(&mut data);
                data
            },
            |data| {
                let mut h = Md5::new();
                h.update(data);
                let out = h.finalize();
                black_box(out);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
