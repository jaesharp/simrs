//! ISO 9797-1 CBC-MAC and CBC encrypt/decrypt for DES, 3DES, and AES-128.
//!
//! Provides the MAC and block-cipher-mode primitives used by:
//! - `GlobalPlatform` SCP01/SCP02 secure messaging (GP 2.1.1 Appendices D/E)
//! - `GlobalPlatform` token and receipt generation (GP 2.1.1 Appendix C)
//! - ETSI TS 102 225 OTA secured packets (via `simrs-ota`)
//!
//! # Padding Methods
//!
//! - **Method 1**: Zero-pad to block boundary. Used when data length is
//!   implicitly known (e.g., fixed-size fields).
//! - **Method 2**: Append `0x80`, then zero-pad to block boundary. Used by
//!   GP SCP C-MAC generation (GP 2.1.1 Appendix D clause D.3.3).
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
//!
//! # Example
//!
//! ```
//! use simrs_iso9797::{aes128_cbc_mac, pad_method2};
//! use simrs_secret::Secret;
//!
//! let key = Secret::new([0x40u8; 16]);
//! let mut buf = [0u8; 32];
//! let padded_len = pad_method2(b"Hello, GP!", 16, &mut buf);
//! let mac = aes128_cbc_mac(&key, &buf[..padded_len]);
//! assert_eq!(mac.len(), 16); // full AES block; truncate to 8 for GP C-MAC
//! ```
#![no_std]

#[cfg(feature = "std")]
extern crate std;

use simrs_des::{Des, TripleDes};
use simrs_rijndael::Rijndael;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// Padding (ISO 9797-1 clause 6)
// ---------------------------------------------------------------------------

/// ISO 9797-1 Method 1 padding: zero-pad `data` to a multiple of `block_size`.
///
/// Copies `data` into `buf`, then zero-pads to the next block boundary.
/// If `data` is already a multiple of `block_size`, no padding is added.
///
/// Returns the padded length (always a multiple of `block_size`, at least `block_size`).
///
/// # Panics
///
/// Panics if `buf` is too small to hold the padded result.
pub fn pad_method1(data: &[u8], block_size: usize, buf: &mut [u8]) -> usize {
    let padded_len = if data.is_empty() {
        block_size
    } else {
        data.len().div_ceil(block_size) * block_size
    };
    assert!(
        buf.len() >= padded_len,
        "buffer too small for Method 1 padding"
    );
    buf[..data.len()].copy_from_slice(data);
    buf[data.len()..padded_len].fill(0);
    padded_len
}

/// ISO 9797-1 Method 2 padding: append `0x80` then zero-pad to block boundary.
///
/// Used by GP SCP01/SCP02 C-MAC generation (GP 2.1.1 Appendix D clause D.3.3).
///
/// Returns the padded length (always a multiple of `block_size`).
///
/// # Panics
///
/// Panics if `buf` is too small to hold the padded result.
pub fn pad_method2(data: &[u8], block_size: usize, buf: &mut [u8]) -> usize {
    let padded_len = (data.len() + 1).div_ceil(block_size) * block_size;
    assert!(
        buf.len() >= padded_len,
        "buffer too small for Method 2 padding"
    );
    buf[..data.len()].copy_from_slice(data);
    buf[data.len()] = 0x80;
    buf[data.len() + 1..padded_len].fill(0);
    padded_len
}

// ---------------------------------------------------------------------------
// XOR helper
// ---------------------------------------------------------------------------

fn xor_block(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

// ---------------------------------------------------------------------------
// AES-128 CBC-MAC
// ---------------------------------------------------------------------------

/// Compute AES-128 CBC-MAC (ISO 9797-1 Algorithm 1) over `data`.
///
/// `data` must be a multiple of 16 bytes (caller pads first).
/// IV is all-zeros. Returns the full 16-byte final ciphertext block.
///
/// For GP SCP C-MAC, truncate the result to 8 bytes (left half).
pub fn aes128_cbc_mac(key: &Secret<[u8; 16]>, data: &[u8]) -> [u8; 16] {
    debug_assert!(
        data.len().is_multiple_of(16) && !data.is_empty(),
        "data must be padded to 16-byte blocks"
    );
    let rij = Rijndael::new(key);
    let mut cv = [0u8; 16];

    let mut off = 0;
    while off + 16 <= data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        xor_block(&mut block, &cv);
        cv = rij.encrypt(&block);
        off += 16;
    }
    cv
}

/// AES-128 CBC encrypt `data` in-place.
///
/// `data` must be a multiple of 16 bytes. `iv` is the initialization vector.
pub fn aes128_cbc_encrypt(key: &Secret<[u8; 16]>, iv: &[u8; 16], data: &mut [u8]) {
    debug_assert!(
        data.len().is_multiple_of(16),
        "data must be padded to 16-byte blocks"
    );
    let rij = Rijndael::new(key);
    let mut cv = *iv;

    let mut off = 0;
    while off + 16 <= data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        xor_block(&mut block, &cv);
        cv = rij.encrypt(&block);
        data[off..off + 16].copy_from_slice(&cv);
        off += 16;
    }
}

/// AES-128 CBC decrypt `data` in-place.
///
/// `data` must be a multiple of 16 bytes. `iv` is the initialization vector.
pub fn aes128_cbc_decrypt(key: &Secret<[u8; 16]>, iv: &[u8; 16], data: &mut [u8]) {
    debug_assert!(
        data.len().is_multiple_of(16),
        "data must be padded to 16-byte blocks"
    );
    let rij = Rijndael::new(key);
    let mut prev_ct = *iv;

    let mut off = 0;
    while off + 16 <= data.len() {
        let mut ct_block = [0u8; 16];
        ct_block.copy_from_slice(&data[off..off + 16]);
        let mut pt_block = rij.decrypt(&ct_block);
        xor_block(&mut pt_block, &prev_ct);
        data[off..off + 16].copy_from_slice(&pt_block);
        prev_ct = ct_block;
        off += 16;
    }
}

// ---------------------------------------------------------------------------
// DES CBC-MAC
// ---------------------------------------------------------------------------

/// Compute single-DES CBC-MAC (ISO 9797-1 Algorithm 1) over `data`.
///
/// `data` must be a multiple of 8 bytes (caller pads first).
/// IV is all-zeros. Returns the full 8-byte final ciphertext block.
pub fn des_cbc_mac(key: &Secret<[u8; 8]>, data: &[u8]) -> [u8; 8] {
    debug_assert!(
        data.len().is_multiple_of(8) && !data.is_empty(),
        "data must be padded to 8-byte blocks"
    );
    let des = Des::new(key);
    let mut cv = [0u8; 8];

    let mut off = 0;
    while off + 8 <= data.len() {
        let mut block = [0u8; 8];
        block.copy_from_slice(&data[off..off + 8]);
        xor_block(&mut block, &cv);
        cv = des.encrypt(&block);
        off += 8;
    }
    cv
}

/// Compute 2-key 3DES CBC-MAC (ISO 9797-1 Algorithm 1) over `data`.
///
/// `data` must be a multiple of 8 bytes. IV is all-zeros.
/// Returns the full 8-byte final ciphertext block.
///
/// Used by GP SCP01/SCP02 for C-MAC generation (GP 2.1.1 Appendix D clause D.3.3).
pub fn des3_2key_cbc_mac(key: &Secret<[u8; 16]>, data: &[u8]) -> [u8; 8] {
    debug_assert!(
        data.len().is_multiple_of(8) && !data.is_empty(),
        "data must be padded to 8-byte blocks"
    );
    let tdes = TripleDes::new_2key(key);
    let mut cv = [0u8; 8];

    let mut off = 0;
    while off + 8 <= data.len() {
        let mut block = [0u8; 8];
        block.copy_from_slice(&data[off..off + 8]);
        xor_block(&mut block, &cv);
        cv = tdes.encrypt(&block);
        off += 8;
    }
    cv
}

/// 2-key 3DES CBC encrypt `data` in-place.
///
/// `data` must be a multiple of 8 bytes. `iv` is the initialization vector.
pub fn des3_2key_cbc_encrypt(key: &Secret<[u8; 16]>, iv: &[u8; 8], data: &mut [u8]) {
    debug_assert!(
        data.len().is_multiple_of(8),
        "data must be padded to 8-byte blocks"
    );
    let tdes = TripleDes::new_2key(key);
    let mut cv = *iv;

    let mut off = 0;
    while off + 8 <= data.len() {
        let mut block = [0u8; 8];
        block.copy_from_slice(&data[off..off + 8]);
        xor_block(&mut block, &cv);
        cv = tdes.encrypt(&block);
        data[off..off + 8].copy_from_slice(&cv);
        off += 8;
    }
}

/// 2-key 3DES CBC decrypt `data` in-place.
///
/// `data` must be a multiple of 8 bytes. `iv` is the initialization vector.
pub fn des3_2key_cbc_decrypt(key: &Secret<[u8; 16]>, iv: &[u8; 8], data: &mut [u8]) {
    debug_assert!(
        data.len().is_multiple_of(8),
        "data must be padded to 8-byte blocks"
    );
    let tdes = TripleDes::new_2key(key);
    let mut prev_ct = *iv;

    let mut off = 0;
    while off + 8 <= data.len() {
        let mut ct_block = [0u8; 8];
        ct_block.copy_from_slice(&data[off..off + 8]);
        let mut pt_block = tdes.decrypt(&ct_block);
        xor_block(&mut pt_block, &prev_ct);
        data[off..off + 8].copy_from_slice(&pt_block);
        prev_ct = ct_block;
        off += 8;
    }
}

/// Compute 3-key 3DES CBC-MAC over `data`.
///
/// `data` must be a multiple of 8 bytes. IV is all-zeros.
/// Returns the full 8-byte final ciphertext block.
pub fn des3_3key_cbc_mac(key: &Secret<[u8; 24]>, data: &[u8]) -> [u8; 8] {
    debug_assert!(
        data.len().is_multiple_of(8) && !data.is_empty(),
        "data must be padded to 8-byte blocks"
    );
    let tdes = TripleDes::new_3key(key);
    let mut cv = [0u8; 8];

    let mut off = 0;
    while off + 8 <= data.len() {
        let mut block = [0u8; 8];
        block.copy_from_slice(&data[off..off + 8]);
        xor_block(&mut block, &cv);
        cv = tdes.encrypt(&block);
        off += 8;
    }
    cv
}

// ---------------------------------------------------------------------------
// AES-CMAC (RFC 4493) -- used by SCP03 (GP 2.3.1 Amendment D)
// ---------------------------------------------------------------------------

/// Left-shift a 16-byte block by 1 bit.
const fn cmac_left_shift_1(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    let mut i = 15;
    loop {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    out
}

/// Generate AES-CMAC subkeys K1 and K2 from the AES cipher instance.
const fn cmac_subkeys(cipher: &Rijndael) -> ([u8; 16], [u8; 16]) {
    let l = cipher.encrypt(&[0u8; 16]);

    let mut k1 = cmac_left_shift_1(&l);
    if l[0] & 0x80 != 0 {
        k1[15] ^= 0x87; // Rb for 128-bit blocks
    }

    let mut k2 = cmac_left_shift_1(&k1);
    if k1[0] & 0x80 != 0 {
        k2[15] ^= 0x87;
    }

    (k1, k2)
}

/// XOR two 16-byte blocks, returning the result.
const fn xor_block_16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = a[i] ^ b[i];
        i += 1;
    }
    out
}

/// Compute AES-CMAC (RFC 4493) over `data` using a 16-byte AES key.
///
/// Returns the full 16-byte MAC. For GP SCP03 wire format, the caller
/// truncates to 8 bytes (left half).
///
/// This is the only MAC primitive needed for SCP03: key derivation,
/// cryptogram computation, C-MAC, and R-MAC all use AES-CMAC.
///
/// Maximum input length: 288 bytes (16-byte chaining value + 5-byte
/// APDU header + 255 data bytes + padding). Inputs larger than 288
/// bytes will cause a panic.
#[allow(clippy::missing_panics_doc)]
pub fn aes_cmac(key: &Secret<[u8; 16]>, data: &[u8]) -> [u8; 16] {
    assert!(data.len() <= 288, "aes_cmac: input exceeds 288 bytes");

    let cipher = Rijndael::new(key);
    let (k1, k2) = cmac_subkeys(&cipher);

    let n_blocks = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(16)
    };

    let complete = !data.is_empty() && data.len().is_multiple_of(16);

    // Prepare the last block with appropriate subkey masking.
    let mut last_block = [0u8; 16];
    let start = (n_blocks - 1) * 16;
    if complete {
        last_block.copy_from_slice(&data[start..start + 16]);
        last_block = xor_block_16(&last_block, &k1);
    } else {
        // Pad with 0x80 || 0x00...
        let remaining = data.len() - start;
        last_block[..remaining].copy_from_slice(&data[start..]);
        last_block[remaining] = 0x80;
        // Rest is already zero.
        last_block = xor_block_16(&last_block, &k2);
    }

    // CBC-MAC over all blocks.
    let mut x = [0u8; 16];
    for i in 0..n_blocks - 1 {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[i * 16..(i + 1) * 16]);
        x = xor_block_16(&x, &block);
        x = cipher.encrypt(&x);
    }
    x = xor_block_16(&x, &last_block);
    cipher.encrypt(&x)
}

// ---------------------------------------------------------------------------
// DES ECB
// ---------------------------------------------------------------------------

/// DES ECB encrypt a single 8-byte block. Used for SCP session key derivation.
pub fn des3_2key_ecb_encrypt(key: &Secret<[u8; 16]>, block: &[u8; 8]) -> [u8; 8] {
    TripleDes::new_2key(key).encrypt(block)
}

/// DES ECB decrypt a single 8-byte block.
pub fn des3_2key_ecb_decrypt(key: &Secret<[u8; 16]>, block: &[u8; 8]) -> [u8; 8] {
    TripleDes::new_2key(key).decrypt(block)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Padding tests
    // -----------------------------------------------------------------------

    #[test]
    fn method1_exact_block() {
        let mut buf = [0xFFu8; 16];
        let len = pad_method1(&[0x01; 8], 8, &mut buf);
        assert_eq!(len, 8);
        assert_eq!(&buf[..8], &[0x01; 8]);
    }

    #[test]
    fn method1_needs_padding() {
        let mut buf = [0xFFu8; 16];
        let len = pad_method1(&[0x01; 5], 8, &mut buf);
        assert_eq!(len, 8);
        assert_eq!(&buf[..8], &[0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn method1_empty() {
        let mut buf = [0xFFu8; 16];
        let len = pad_method1(&[], 8, &mut buf);
        assert_eq!(len, 8);
        assert_eq!(&buf[..8], &[0x00; 8]);
    }

    #[test]
    fn method2_exact_block() {
        // Method 2 always adds at least 0x80, so exact block -> new block
        let mut buf = [0xFFu8; 24];
        let len = pad_method2(&[0x01; 8], 8, &mut buf);
        assert_eq!(len, 16);
        assert_eq!(
            &buf[..16],
            &[
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ]
        );
    }

    #[test]
    fn method2_needs_padding() {
        let mut buf = [0xFFu8; 16];
        let len = pad_method2(&[0x01; 5], 8, &mut buf);
        assert_eq!(len, 8);
        assert_eq!(&buf[..8], &[0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00]);
    }

    #[test]
    fn method2_empty() {
        let mut buf = [0xFFu8; 16];
        let len = pad_method2(&[], 8, &mut buf);
        assert_eq!(len, 8);
        assert_eq!(&buf[..8], &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    // -----------------------------------------------------------------------
    // AES CBC round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn aes_cbc_roundtrip() {
        let key = Secret::new([0x2Bu8; 16]);
        let iv = [0u8; 16];
        let original = [0x41u8; 32]; // 2 blocks of 'A'
        let mut data = original;
        aes128_cbc_encrypt(&key, &iv, &mut data);
        assert_ne!(data, original); // must differ
        aes128_cbc_decrypt(&key, &iv, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn aes_cbc_mac_known_vector() {
        // Known: AES-128 CBC-MAC of 16 zero bytes with zero key
        let key = Secret::new([0u8; 16]);
        let data = [0u8; 16];
        let mac = aes128_cbc_mac(&key, &data);
        // AES-128 encrypts 16 zero bytes with zero key XOR zero IV:
        // This is simply AES_ECB(0...0, 0...0)
        let expected = Rijndael::new(&key).encrypt(&[0u8; 16]);
        assert_eq!(mac, expected);
    }

    // -----------------------------------------------------------------------
    // DES/3DES CBC round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn des3_cbc_roundtrip() {
        let key = Secret::new([0x2Bu8; 16]);
        let iv = [0u8; 8];
        let original = [0x41u8; 16]; // 2 blocks of 'A'
        let mut data = original;
        des3_2key_cbc_encrypt(&key, &iv, &mut data);
        assert_ne!(data, original);
        des3_2key_cbc_decrypt(&key, &iv, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn des3_ecb_roundtrip() {
        let key = Secret::new([0x2Bu8; 16]);
        let block = [0x41u8; 8];
        let enc = des3_2key_ecb_encrypt(&key, &block);
        let dec = des3_2key_ecb_decrypt(&key, &enc);
        assert_eq!(dec, block);
    }

    // -----------------------------------------------------------------------
    // AES-CMAC (RFC 4493) test vectors
    // -----------------------------------------------------------------------

    /// RFC 4493 test key: 2b7e1516 28aed2a6 abf71588 09cf4f3c
    fn rfc4493_key() -> Secret<[u8; 16]> {
        Secret::new([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ])
    }

    #[test]
    fn aes_cmac_rfc4493_empty() {
        // Example 1: Mlen = 0
        let mac = aes_cmac(&rfc4493_key(), &[]);
        assert_eq!(
            mac,
            [0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
             0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46]
        );
    }

    #[test]
    fn aes_cmac_rfc4493_16_bytes() {
        // Example 2: Mlen = 16
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let mac = aes_cmac(&rfc4493_key(), &msg);
        assert_eq!(
            mac,
            [0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
             0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c]
        );
    }

    #[test]
    fn aes_cmac_rfc4493_40_bytes() {
        // Example 3: Mlen = 40
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let mac = aes_cmac(&rfc4493_key(), &msg);
        assert_eq!(
            mac,
            [0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
             0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27]
        );
    }

    #[test]
    fn aes_cmac_rfc4493_64_bytes() {
        // Example 4: Mlen = 64
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let mac = aes_cmac(&rfc4493_key(), &msg);
        assert_eq!(
            mac,
            [0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
             0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe]
        );
    }

    // -----------------------------------------------------------------------
    // DES CBC-MAC known vector
    // -----------------------------------------------------------------------

    #[test]
    fn des_cbc_mac_known() {
        // DES CBC-MAC of 8 zero bytes with zero key and zero IV
        let key = Secret::new([0u8; 8]);
        let data = [0u8; 8];
        let mac = des_cbc_mac(&key, &data);
        // = DES_ECB(0...0, 0...0 XOR 0...0) = DES_ECB(0, 0)
        let expected = Des::new(&key).encrypt(&[0u8; 8]);
        assert_eq!(mac, expected);
    }
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // (i & 0xFF) as u8 is always safe
mod proptests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn aes_cbc_encrypt_decrypt_roundtrip(
            key_bytes in any::<[u8; 16]>(),
            iv in any::<[u8; 16]>(),
            block_count in 1usize..8,
        ) {
            let key = Secret::new(key_bytes);
            let mut data = vec![0u8; block_count * 16];
            for (i, b) in data.iter_mut().enumerate() {
                *b = (i & 0xFF) as u8;
            }
            let original = data.clone();
            aes128_cbc_encrypt(&key, &iv, &mut data);
            aes128_cbc_decrypt(&key, &iv, &mut data);
            prop_assert_eq!(data, original);
        }

        #[test]
        fn des3_cbc_encrypt_decrypt_roundtrip(
            key_bytes in any::<[u8; 16]>(),
            iv in any::<[u8; 8]>(),
            block_count in 1usize..8,
        ) {
            let key = Secret::new(key_bytes);
            let mut data = vec![0u8; block_count * 8];
            for (i, b) in data.iter_mut().enumerate() {
                *b = (i & 0xFF) as u8;
            }
            let original = data.clone();
            des3_2key_cbc_encrypt(&key, &iv, &mut data);
            des3_2key_cbc_decrypt(&key, &iv, &mut data);
            prop_assert_eq!(data, original);
        }
    }
}
