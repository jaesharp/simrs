//! ECIES Profiles A and B for SUCI computation per
//! [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex C.3/C.4.
//!
//! Encrypts the MSIN portion of the SUPI to produce a SUCI
//! (Subscription Concealed Identifier) in 5G-SA.
//!
//! # Profiles
//!
//! - **Profile A** ([`ecies_profile_a_encrypt`]): X25519 ECDH + ANSI X9.63 KDF +
//!   AES-128-CTR + HMAC-SHA-256 (Annex C.3.4)
//! - **Profile B** ([`ecies_profile_b_encrypt`]): P-256 ECDH + ANSI X9.63 KDF +
//!   AES-128-CTR + HMAC-SHA-256 (Annex C.4.4)
//!
//! # Components
//!
//! - [`x25519`]: Curve25519 Diffie-Hellman per [RFC 7748](../../../docs/specs/ietf/rfc7748.txt)
//! - [`p256`]: P-256 (secp256r1) ECDH per [FIPS 186-4](../../../docs/specs/nist/fips-186-4/)
//! - [`aes128_ctr`]: AES-128 counter mode per [NIST SP 800-38A](../../../docs/specs/nist/sp-800-38a/NIST.SP.800-38A.pdf)
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
//!
//! # Example
//!
//! ```
//! use simrs_ecies::{ecies_profile_a_encrypt, x25519};
//! use simrs_secret::Secret;
//!
//! // Home Network key pair (use CSPRNG in production).
//! let hn_sk = [0x42u8; 32];
//! let hn_pk = x25519::x25519_base(&hn_sk);
//!
//! // Encrypt the MSIN with a fresh ephemeral key.
//! let eph_sk = Secret::new([0x99u8; 32]);
//! let msin = [0x00, 0x01, 0x20, 0x80, 0xf6];
//! let result = ecies_profile_a_encrypt(&hn_pk, &msin, &eph_sk);
//!
//! assert_eq!(result.ct_len, msin.len());
//! assert_ne!(result.mac, [0u8; 8]);
//! ```
#![no_std]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::unreadable_literal)]

#[cfg(feature = "std")]
extern crate std;

pub mod p256;
pub mod x25519;

use simrs_kdf::{kdf_x963, HmacSha256};
use simrs_rijndael::Rijndael;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// AES-128-CTR (NIST SP 800-38A clause 6.5)
// ---------------------------------------------------------------------------

/// AES-128 counter mode encryption/decryption per
/// [NIST SP 800-38A](../../../docs/specs/nist/sp-800-38a/NIST.SP.800-38A.pdf) clause 6.5.
///
/// Encrypts or decrypts `input` into `output` using AES-128-CTR with the
/// given 16-byte key and 16-byte initial counter block (IV).
///
/// # Panics
///
/// Panics if `output.len() < input.len()`.
pub fn aes128_ctr(key: &[u8; 16], iv: &[u8; 16], input: &[u8], output: &mut [u8]) {
    assert!(output.len() >= input.len(), "output buffer too small");

    let cipher = Rijndael::new(key);
    let mut counter = *iv;
    let mut offset = 0;

    while offset < input.len() {
        // Encrypt the counter block to get the keystream block.
        let keystream = cipher.encrypt(&counter);

        // XOR keystream with input.
        let remaining = input.len() - offset;
        let block_len = if remaining < 16 { remaining } else { 16 };
        let mut i = 0;
        while i < block_len {
            output[offset + i] = input[offset + i] ^ keystream[i];
            i += 1;
        }
        offset += block_len;

        // Increment counter (big-endian, rightmost bytes).
        increment_counter(&mut counter);
    }
}

/// Increment a 128-bit counter in big-endian byte order (branchless).
///
/// Always processes all 16 bytes using a carry mask to avoid
/// data-dependent branches on the counter value.
fn increment_counter(ctr: &mut [u8; 16]) {
    // Process from LSB to MSB. carry starts at 1 (the increment).
    let mut carry: u16 = 1;
    let mut i: usize = 16;
    while i > 0 {
        i -= 1;
        let sum = ctr[i] as u16 + carry;
        ctr[i] = sum as u8;
        carry = sum >> 8;
    }
}

// ---------------------------------------------------------------------------
// Shared encrypt-and-MAC logic (used by both Profile A and Profile B)
// ---------------------------------------------------------------------------

/// Maximum plaintext length for ECIES.
///
/// The MSIN is at most 10 BCD digits = 5 bytes. We allow up to 16 bytes
/// for flexibility.
pub const MAX_PLAINTEXT_LEN: usize = 16;

/// AES-128-CTR encrypt `plaintext` with `enc_key`/`iv`, then compute
/// HMAC-SHA-256(`mac_key`, ciphertext) truncated to 8 bytes.
///
/// Returns (ciphertext_buf, plaintext_len, mac_tag).
fn encrypt_and_mac(
    enc_key: &[u8; 16],
    iv: &[u8; 16],
    mac_key: &[u8; 32],
    plaintext: &[u8],
) -> ([u8; MAX_PLAINTEXT_LEN], usize, [u8; 8]) {
    let mut ciphertext = [0u8; MAX_PLAINTEXT_LEN];
    aes128_ctr(enc_key, iv, plaintext, &mut ciphertext);

    let mut mac_hasher = HmacSha256::new(mac_key);
    mac_hasher.update(&ciphertext[..plaintext.len()]);
    let full_mac = mac_hasher.finalize();
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&full_mac[..8]);

    (ciphertext, plaintext.len(), mac)
}

// ---------------------------------------------------------------------------
// ECIES Profile A (TS 33.501 Annex C.3.4)
// ---------------------------------------------------------------------------

/// Result of ECIES Profile A encryption.
///
/// Contains the ephemeral public key, ciphertext, and MAC tag, all as
/// fixed-size arrays suitable for embedding in a SUCI TLV.
pub struct EciesProfileAResult {
    /// Ephemeral public key (32 bytes, Curve25519 u-coordinate).
    pub ephemeral_pk: [u8; 32],
    /// Ciphertext (up to 16 bytes, same length as plaintext).
    pub ciphertext: [u8; MAX_PLAINTEXT_LEN],
    /// Number of valid bytes in `ciphertext`.
    pub ct_len: usize,
    /// HMAC-SHA-256 tag truncated to 8 bytes per TS 33.501 Annex C.3.4.
    pub mac: [u8; 8],
}

/// ECIES Profile A encryption per
/// [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex C.3.4.
///
/// Encrypts `plaintext` (the MSIN portion of the SUPI) using:
/// 1. ECDH: X25519(`ephemeral_sk`, `hn_pubkey`) to derive a shared secret
/// 2. KDF: ANSI X9.63 KDF (SHA-256), SharedInfo = ephemeral public key (32 bytes, no prefix)
/// 3. KDF output 64 bytes: enc_key(16) || ICB(16) || mac_key(32)
/// 4. AES-128-CTR encryption with derived enc_key and ICB
/// 5. HMAC-SHA-256 MAC over the ciphertext (truncated to 64 bits)
///
/// The `ephemeral_sk` must be a fresh random 32-byte secret key.
/// The `hn_pubkey` is the Home Network's Curve25519 public key.
///
/// # Panics
///
/// Panics if `plaintext.len() > 16`.
pub fn ecies_profile_a_encrypt(
    hn_pubkey: &[u8; 32],
    plaintext: &[u8],
    ephemeral_sk: &Secret<[u8; 32]>,
) -> EciesProfileAResult {
    assert!(plaintext.len() <= MAX_PLAINTEXT_LEN, "plaintext too long");

    // Step 1: Compute ephemeral public key.
    let ephemeral_pk = x25519::x25519_base(ephemeral_sk.declassify_ref());

    // Step 2: ECDH shared secret.
    let shared_secret = x25519::x25519(ephemeral_sk.declassify_ref(), hn_pubkey);

    // Step 3: Key derivation via ANSI X9.63 KDF.
    // Per TS 33.501 C.3.4:
    //   KDF(Z, SharedInfo1) where SharedInfo1 = ephemeral public key (raw 32 bytes, no prefix)
    //   Output: 64 bytes = enc_key(16) || ICB(16) || mac_key(32)
    let mut kdf_out = [0u8; 64];
    kdf_x963(&shared_secret, &ephemeral_pk, 64, &mut kdf_out);

    let mut enc_key = [0u8; 16];
    enc_key.copy_from_slice(&kdf_out[..16]);
    let mut icb = [0u8; 16];
    icb.copy_from_slice(&kdf_out[16..32]);
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&kdf_out[32..64]);

    // Steps 4+5: AES-128-CTR encryption + HMAC-SHA-256 MAC.
    let (ciphertext, ct_len, mac) = encrypt_and_mac(&enc_key, &icb, &mac_key, plaintext);

    EciesProfileAResult {
        ephemeral_pk,
        ciphertext,
        ct_len,
        mac,
    }
}

// ---------------------------------------------------------------------------
// ECIES Profile B (TS 33.501 Annex C.4.4)
// ---------------------------------------------------------------------------

/// Result of ECIES Profile B encryption.
///
/// Contains the compressed ephemeral public key (33 bytes), ciphertext,
/// and MAC tag, all as fixed-size arrays suitable for embedding in a SUCI TLV.
pub struct EciesProfileBResult {
    /// Ephemeral public key in compressed SEC 1 format (33 bytes: 0x02/0x03 || x).
    pub ephemeral_pk: [u8; 33],
    /// Ciphertext (up to 16 bytes, same length as plaintext).
    pub ciphertext: [u8; MAX_PLAINTEXT_LEN],
    /// Number of valid bytes in `ciphertext`.
    pub ct_len: usize,
    /// HMAC-SHA-256 tag truncated to 8 bytes per TS 33.501 Annex C.4.4.
    pub mac: [u8; 8],
}

/// ECIES Profile B encryption per
/// [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex C.4.4.
///
/// Encrypts `plaintext` (the MSIN portion of the SUPI) using:
/// 1. ECDH: P-256(`ephemeral_sk`, `hn_pubkey`) to derive a shared secret
/// 2. KDF: ANSI X9.63 KDF with SHA-256, SharedInfo = compressed ephemeral pubkey
/// 3. AES-128-CTR encryption with derived enc_key and ICB
/// 4. HMAC-SHA-256 MAC over the ciphertext (truncated to 64 bits)
///
/// The `ephemeral_sk` must be a valid P-256 private key (32 bytes, big-endian,
/// in the range [1, n-1]). Use [`p256::validate_scalar`] to check before calling.
/// The `hn_pubkey` is the Home Network's P-256 public key in uncompressed
/// SEC 1 format (65 bytes: 0x04 || x || y).
///
/// # Panics
///
/// Panics if `plaintext.len() > 16`, if the ECDH shared secret computation
/// fails (invalid HN public key or degenerate shared point), or if the
/// ephemeral private key is invalid.
pub fn ecies_profile_b_encrypt(
    hn_pubkey: &[u8; 65],
    plaintext: &[u8],
    ephemeral_sk: &Secret<[u8; 32]>,
) -> EciesProfileBResult {
    assert!(plaintext.len() <= MAX_PLAINTEXT_LEN, "plaintext too long");
    assert!(
        p256::validate_scalar(ephemeral_sk.declassify_ref()),
        "ephemeral_sk must be in [1, n-1]"
    );

    // Step 1: Compute compressed ephemeral public key.
    let ephemeral_pk = p256::p256_pubkey_compressed(ephemeral_sk.declassify_ref());

    // Step 2: ECDH shared secret (x-coordinate).
    let shared_secret = p256::p256_ecdh(ephemeral_sk.declassify_ref(), hn_pubkey)
        .expect("ECDH failed: invalid HN public key or degenerate point");

    // Step 3: Key derivation via ANSI X9.63 KDF.
    // Per TS 33.501 C.4.4:
    //   KDF(Z, SharedInfo1) where SharedInfo1 = compressed ephemeral pubkey
    //   Output: 64 bytes = enc_key(16) || ICB(16) || mac_key(32)
    let mut kdf_out = [0u8; 64];
    kdf_x963(&shared_secret, &ephemeral_pk, 64, &mut kdf_out);

    let mut enc_key = [0u8; 16];
    enc_key.copy_from_slice(&kdf_out[..16]);
    let mut icb = [0u8; 16];
    icb.copy_from_slice(&kdf_out[16..32]);
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&kdf_out[32..64]);

    // Steps 4+5: AES-128-CTR encryption + HMAC-SHA-256 MAC.
    let (ciphertext, ct_len, mac) = encrypt_and_mac(&enc_key, &icb, &mac_key, plaintext);

    EciesProfileBResult {
        ephemeral_pk,
        ciphertext,
        ct_len,
        mac,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Hex parsing helpers --

    fn hex_to_n(s: &str, out: &mut [u8]) {
        assert_eq!(s.len(), out.len() * 2);
        let mut i = 0;
        while i < out.len() {
            let hi = match s.as_bytes()[i * 2] {
                b'0'..=b'9' => s.as_bytes()[i * 2] - b'0',
                b'a'..=b'f' => s.as_bytes()[i * 2] - b'a' + 10,
                b'A'..=b'F' => s.as_bytes()[i * 2] - b'A' + 10,
                _ => panic!("bad hex"),
            };
            let lo = match s.as_bytes()[i * 2 + 1] {
                b'0'..=b'9' => s.as_bytes()[i * 2 + 1] - b'0',
                b'a'..=b'f' => s.as_bytes()[i * 2 + 1] - b'a' + 10,
                b'A'..=b'F' => s.as_bytes()[i * 2 + 1] - b'A' + 10,
                _ => panic!("bad hex"),
            };
            out[i] = (hi << 4) | lo;
            i += 1;
        }
    }

    fn hex_to_16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        hex_to_n(s, &mut out);
        out
    }

    #[test]
    fn nist_aes128_ctr_block1() {
        // NIST SP 800-38A F.5.1: CTR-AES128.Encrypt, Block #1
        let key = hex_to_16("2b7e151628aed2a6abf7158809cf4f3c");
        let iv  = hex_to_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt  = hex_to_16("6bc1bee22e409f96e93d7e117393172a");
        let expected_ct = hex_to_16("874d6191b620e3261bef6864990db6ce");

        let mut ct = [0u8; 16];
        aes128_ctr(&key, &iv, &pt, &mut ct);
        assert_eq!(ct, expected_ct);
    }

    #[test]
    fn nist_aes128_ctr_4_blocks() {
        // NIST SP 800-38A F.5.1: CTR-AES128.Encrypt, all 4 blocks
        let key = hex_to_16("2b7e151628aed2a6abf7158809cf4f3c");
        let iv  = hex_to_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        let pt = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];

        let expected_ct = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
            0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
            0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
            0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
        ];

        let mut ct = [0u8; 64];
        aes128_ctr(&key, &iv, &pt, &mut ct);
        assert_eq!(ct, expected_ct);
    }

    #[test]
    fn aes128_ctr_decrypt_roundtrip() {
        // CTR mode is symmetric: encrypt then decrypt should recover plaintext.
        let key = hex_to_16("2b7e151628aed2a6abf7158809cf4f3c");
        let iv  = hex_to_16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = b"Hello, Curve25519 world!";

        let mut ct = [0u8; 24];
        aes128_ctr(&key, &iv, pt, &mut ct);

        let mut recovered = [0u8; 24];
        aes128_ctr(&key, &iv, &ct, &mut recovered);
        assert_eq!(&recovered[..], &pt[..]);
    }

    #[test]
    fn aes128_ctr_partial_block() {
        // Less than 16 bytes should still work.
        let key = hex_to_16("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = [0u8; 16];
        let pt = [0x42; 5];
        let mut ct = [0u8; 5];
        aes128_ctr(&key, &iv, &pt, &mut ct);

        // Decrypt.
        let mut recovered = [0u8; 5];
        aes128_ctr(&key, &iv, &ct, &mut recovered);
        assert_eq!(recovered, pt);
    }

    // -- ECIES Profile A tests (TS 33.501 Annex C.3.4 / C.4.3) --

    #[test]
    fn ts33501_c43_profile_a_full_vector() {
        // TS 33.501 Annex C.4.3 complete test vector.
        let hn_pk = hex_to_32(
            "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650",
        );
        let eph_sk = hex_to_32(
            "c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256",
        );
        let plaintext = [0x00, 0x01, 0x20, 0x80, 0xf6]; // packed BCD MSIN

        let result = ecies_profile_a_encrypt(&hn_pk, &plaintext, &Secret::new(eph_sk));

        // Verify ephemeral pubkey.
        assert_eq!(
            result.ephemeral_pk,
            hex_to_32("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d"),
        );

        // Verify ciphertext.
        let mut expected_ct = [0u8; 5];
        hex_to_n("cb02352410", &mut expected_ct);
        assert_eq!(&result.ciphertext[..result.ct_len], &expected_ct);

        // Verify MAC tag.
        let mut expected_mac = [0u8; 8];
        hex_to_n("cddd9e730ef3fa87", &mut expected_mac);
        assert_eq!(result.mac, expected_mac);
    }

    #[test]
    fn ts33501_c43_profile_a_kdf_intermediate() {
        // Verify intermediate KDF values from TS 33.501 C.4.3.
        let hn_pk = hex_to_32(
            "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650",
        );
        let eph_sk = hex_to_32(
            "c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256",
        );

        // Shared secret (X25519 ECDH).
        let z = x25519::x25519(&eph_sk, &hn_pk);
        assert_eq!(
            z,
            hex_to_32("028ddf890ec83cdf163947ce45f6ec1a0e3070ea5fe57e2b1f05139f3e82422a"),
        );

        // Ephemeral pubkey (= SharedInfo for KDF, raw 32 bytes).
        let eph_pk = x25519::x25519_base(&eph_sk);
        assert_eq!(
            eph_pk,
            hex_to_32("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d"),
        );

        // KDF output: enc_key(16) || ICB(16) || mac_key(32).
        let mut kdf_out = [0u8; 64];
        simrs_kdf::kdf_x963(&z, &eph_pk, 64, &mut kdf_out);

        let expected_enc_key = hex_to_16("2ba342cabd2b3b1e5e4e890da11b65f6");
        let expected_icb = hex_to_16("e2622cb0cdd08204e721c8ea9b95a7c6");
        assert_eq!(&kdf_out[..16], &expected_enc_key);
        assert_eq!(&kdf_out[16..32], &expected_icb);
        let mut expected_mac_key = [0u8; 32];
        hex_to_n(
            "d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52bd2",
            &mut expected_mac_key,
        );
        assert_eq!(&kdf_out[32..64], &expected_mac_key);
    }

    #[test]
    fn ecies_profile_a_encrypt_decrypt_roundtrip() {
        // HN key pair.
        let hn_sk = hex_to_32(
            "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d",
        );
        let hn_pk = x25519::x25519_base(&hn_sk);

        let eph_sk = hex_to_32(
            "c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256",
        );
        let msin = [0x00, 0x01, 0x20, 0x80, 0xf6];

        let result = ecies_profile_a_encrypt(&hn_pk, &msin, &Secret::new(eph_sk));

        // HN side: compute shared secret and re-derive keys.
        let shared_secret = x25519::x25519(&hn_sk, &result.ephemeral_pk);
        let mut kdf_out = [0u8; 64];
        simrs_kdf::kdf_x963(&shared_secret, &result.ephemeral_pk, 64, &mut kdf_out);

        let mut enc_key = [0u8; 16];
        enc_key.copy_from_slice(&kdf_out[..16]);
        let mut icb = [0u8; 16];
        icb.copy_from_slice(&kdf_out[16..32]);
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&kdf_out[32..64]);

        // Verify MAC.
        let mut mac_hasher = HmacSha256::new(&mac_key);
        mac_hasher.update(&result.ciphertext[..result.ct_len]);
        let full_mac = mac_hasher.finalize();
        assert_eq!(&full_mac[..8], &result.mac);

        // Decrypt.
        let mut decrypted = [0u8; 16];
        aes128_ctr(&enc_key, &icb, &result.ciphertext[..result.ct_len], &mut decrypted);
        assert_eq!(&decrypted[..msin.len()], &msin);
    }

    #[test]
    fn ecies_profile_a_deterministic() {
        // Same inputs should produce same outputs.
        let hn_pk = x25519::x25519_base(&[42u8; 32]);
        let eph_sk = [99u8; 32];
        let msin = [0xAB, 0xCD, 0xEF];

        let eph_sk = Secret::new(eph_sk);
        let r1 = ecies_profile_a_encrypt(&hn_pk, &msin, &eph_sk);
        let r2 = ecies_profile_a_encrypt(&hn_pk, &msin, &eph_sk);

        assert_eq!(r1.ephemeral_pk, r2.ephemeral_pk);
        assert_eq!(r1.ciphertext[..r1.ct_len], r2.ciphertext[..r2.ct_len]);
        assert_eq!(r1.mac, r2.mac);
    }

    #[test]
    fn ecies_profile_a_different_eph_keys() {
        // Different ephemeral keys should produce different ciphertext.
        let hn_pk = x25519::x25519_base(&[42u8; 32]);
        let msin = [0xAB, 0xCD, 0xEF];

        let r1 = ecies_profile_a_encrypt(&hn_pk, &msin, &Secret::new([1u8; 32]));
        let r2 = ecies_profile_a_encrypt(&hn_pk, &msin, &Secret::new([2u8; 32]));

        assert_ne!(r1.ephemeral_pk, r2.ephemeral_pk);
        assert_ne!(r1.ciphertext[..r1.ct_len], r2.ciphertext[..r2.ct_len]);
    }

    #[test]
    fn ecies_profile_a_mac_changes_with_data() {
        let hn_pk = x25519::x25519_base(&[42u8; 32]);
        let eph_sk = [99u8; 32];

        let eph_sk = Secret::new(eph_sk);
        let r1 = ecies_profile_a_encrypt(&hn_pk, &[0x01, 0x02], &eph_sk);
        let r2 = ecies_profile_a_encrypt(&hn_pk, &[0x01, 0x03], &eph_sk);

        assert_ne!(r1.mac, r2.mac);
    }

    // -- Counter increment tests --

    #[test]
    fn counter_increment_simple() {
        let mut ctr = [0u8; 16];
        ctr[15] = 0;
        increment_counter(&mut ctr);
        assert_eq!(ctr[15], 1);
    }

    #[test]
    fn counter_increment_carry() {
        let mut ctr = [0u8; 16];
        ctr[15] = 0xFF;
        increment_counter(&mut ctr);
        assert_eq!(ctr[15], 0);
        assert_eq!(ctr[14], 1);
    }

    #[test]
    fn counter_increment_multi_carry() {
        let mut ctr = [0u8; 16];
        ctr[13] = 0;
        ctr[14] = 0xFF;
        ctr[15] = 0xFF;
        increment_counter(&mut ctr);
        assert_eq!(ctr[15], 0);
        assert_eq!(ctr[14], 0);
        assert_eq!(ctr[13], 1);
    }

    // -- ECIES Profile B tests (TS 33.501 Annex C.4.4) --

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex_to_n(s, &mut out);
        out
    }

    fn hex_to_65(s: &str) -> [u8; 65] {
        let mut out = [0u8; 65];
        hex_to_n(s, &mut out);
        out
    }

    #[test]
    fn ts33501_c44_profile_b_full_vector() {
        // TS 33.501 Annex C.4.4 complete test vector.
        let hn_pk = hex_to_65(
            "0472da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1\
             5a7ded52fcbb097a4ed250e036c7b9c8c7004c4eedc4f068cd7bf8d3f900e3b4",
        );
        let eph_sk = hex_to_32(
            "99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529",
        );
        let plaintext = [0x00, 0x01, 0x20, 0x80, 0xf6]; // packed BCD MSIN

        let result = ecies_profile_b_encrypt(&hn_pk, &plaintext, &Secret::new(eph_sk));

        // Verify ephemeral compressed pubkey.
        let mut expected_eph = [0u8; 33];
        hex_to_n(
            "039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d1",
            &mut expected_eph,
        );
        assert_eq!(result.ephemeral_pk, expected_eph);

        // Verify ciphertext.
        let mut expected_ct = [0u8; 5];
        hex_to_n("46a33fc271", &mut expected_ct);
        assert_eq!(&result.ciphertext[..result.ct_len], &expected_ct);

        // Verify MAC tag.
        let mut expected_mac = [0u8; 8];
        hex_to_n("6ac7dae96aa30a4d", &mut expected_mac);
        assert_eq!(result.mac, expected_mac);
    }

    #[test]
    fn ts33501_c44_profile_b_kdf_intermediate() {
        // Verify intermediate KDF values from TS 33.501 C.4.4.
        let eph_sk = hex_to_32(
            "99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529",
        );
        let hn_pk = hex_to_65(
            "0472da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1\
             5a7ded52fcbb097a4ed250e036c7b9c8c7004c4eedc4f068cd7bf8d3f900e3b4",
        );

        // Shared secret (ECDH x-coordinate).
        let z = p256::p256_ecdh(&eph_sk, &hn_pk).unwrap();
        assert_eq!(
            z,
            hex_to_32("6c7e6518980025b982fbb2ff746e3c2e85a196d252099a7ad23ea7b4c0959cae"),
        );

        // Compressed ephemeral pubkey (= SharedInfo for KDF).
        let eph_pk = p256::p256_pubkey_compressed(&eph_sk);
        let mut expected_eph = [0u8; 33];
        hex_to_n(
            "039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d1",
            &mut expected_eph,
        );
        assert_eq!(eph_pk, expected_eph);

        // KDF output: enc_key(16) || ICB(16) || mac_key(32).
        let mut kdf_out = [0u8; 64];
        simrs_kdf::kdf_x963(&z, &eph_pk, 64, &mut kdf_out);

        let expected_enc_key = hex_to_16("8a65c3aed80295c12bd55087e965702a");
        let expected_icb = hex_to_16("ef285b4061c3baee858ab6ec68487dae");
        assert_eq!(&kdf_out[..16], &expected_enc_key);
        assert_eq!(&kdf_out[16..32], &expected_icb);
        // mac_key = kdf_out[32..64]
        let mut expected_mac_key = [0u8; 32];
        hex_to_n(
            "a5ebac0bc48d9cf7ae5ce39cd840ac6c761aec04078fab954d634f923e901c64",
            &mut expected_mac_key,
        );
        assert_eq!(&kdf_out[32..64], &expected_mac_key);
    }

    #[test]
    fn ecies_profile_b_encrypt_decrypt_roundtrip() {
        // Verify that the HN side can decrypt what Profile B encrypts.
        let hn_sk = hex_to_32(
            "f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda",
        );
        let hn_pk = p256::p256_pubkey(&hn_sk);

        let eph_sk = hex_to_32(
            "99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529",
        );
        let msin = [0x00, 0x01, 0x20, 0x80, 0xf6];

        let result = ecies_profile_b_encrypt(&hn_pk, &msin, &Secret::new(eph_sk));

        // HN side: recover shared secret from compressed ephemeral pubkey.
        let eph_pk_uncompressed = p256::p256_decompress_pubkey(&result.ephemeral_pk)
            .expect("compressed decompress failed");
        let z = p256::p256_ecdh(&hn_sk, &eph_pk_uncompressed).unwrap();

        // Re-derive keys.
        let mut kdf_out = [0u8; 64];
        simrs_kdf::kdf_x963(&z, &result.ephemeral_pk, 64, &mut kdf_out);

        let mut enc_key = [0u8; 16];
        enc_key.copy_from_slice(&kdf_out[..16]);
        let mut icb = [0u8; 16];
        icb.copy_from_slice(&kdf_out[16..32]);
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&kdf_out[32..64]);

        // Verify MAC.
        let mut mac_hasher = HmacSha256::new(&mac_key);
        mac_hasher.update(&result.ciphertext[..result.ct_len]);
        let full_mac = mac_hasher.finalize();
        assert_eq!(&full_mac[..8], &result.mac);

        // Decrypt.
        let mut decrypted = [0u8; 16];
        aes128_ctr(&enc_key, &icb, &result.ciphertext[..result.ct_len], &mut decrypted);
        assert_eq!(&decrypted[..msin.len()], &msin);
    }

    #[test]
    fn ecies_profile_b_deterministic() {
        let hn_sk = hex_to_32(
            "f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda",
        );
        let hn_pk = p256::p256_pubkey(&hn_sk);
        let eph_sk = hex_to_32(
            "99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529",
        );
        let msin = [0x00, 0x01, 0x20, 0x80, 0xf6];

        let eph_sk = Secret::new(eph_sk);
        let r1 = ecies_profile_b_encrypt(&hn_pk, &msin, &eph_sk);
        let r2 = ecies_profile_b_encrypt(&hn_pk, &msin, &eph_sk);

        assert_eq!(r1.ephemeral_pk, r2.ephemeral_pk);
        assert_eq!(r1.ciphertext[..r1.ct_len], r2.ciphertext[..r2.ct_len]);
        assert_eq!(r1.mac, r2.mac);
    }

    #[test]
    fn ecies_profile_b_different_eph_keys() {
        let hn_sk = hex_to_32(
            "f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda",
        );
        let hn_pk = p256::p256_pubkey(&hn_sk);

        let eph_sk1 = hex_to_32(
            "99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529",
        );
        let eph_sk2 = hex_to_32(
            "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
        );
        let msin = [0x00, 0x01, 0x20, 0x80, 0xf6];

        let r1 = ecies_profile_b_encrypt(&hn_pk, &msin, &Secret::new(eph_sk1));
        let r2 = ecies_profile_b_encrypt(&hn_pk, &msin, &Secret::new(eph_sk2));

        assert_ne!(r1.ephemeral_pk, r2.ephemeral_pk);
        assert_ne!(r1.ciphertext[..r1.ct_len], r2.ciphertext[..r2.ct_len]);
    }

    #[test]
    fn ecies_profile_b_mac_changes_with_data() {
        let hn_sk = hex_to_32(
            "f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda",
        );
        let hn_pk = p256::p256_pubkey(&hn_sk);
        let eph_sk = hex_to_32(
            "99798858a1dc6a2c68637149a4b1dbfd1fdff5addd62a2142f06699ed7602529",
        );

        let eph_sk = Secret::new(eph_sk);
        let r1 = ecies_profile_b_encrypt(&hn_pk, &[0x01, 0x02], &eph_sk);
        let r2 = ecies_profile_b_encrypt(&hn_pk, &[0x01, 0x03], &eph_sk);

        assert_ne!(r1.mac, r2.mac);
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
        // AES-128-CTR: encrypt then decrypt recovers plaintext.
        #[test]
        fn aes_ctr_roundtrip(
            key in any::<[u8; 16]>(),
            iv in any::<[u8; 16]>(),
            pt in any::<[u8; 48]>(),
            pt_len in 1usize..=48,
        ) {
            let pt = &pt[..pt_len];
            let mut ct = [0u8; 48];
            aes128_ctr(&key, &iv, pt, &mut ct);
            let mut recovered = [0u8; 48];
            aes128_ctr(&key, &iv, &ct[..pt_len], &mut recovered);
            prop_assert_eq!(&recovered[..pt_len], pt);
        }
    }

    proptest! {
        // X25519 ECDH commutativity:
        // scalar_mul(a, scalar_mul(b, G)) == scalar_mul(b, scalar_mul(a, G))
        #[test]
        fn x25519_ecdh_commutative(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
            let pk_a = x25519::x25519_base(&a);
            let pk_b = x25519::x25519_base(&b);
            let shared_ab = x25519::x25519(&a, &pk_b);
            let shared_ba = x25519::x25519(&b, &pk_a);
            prop_assert_eq!(shared_ab, shared_ba, "ECDH must be commutative");
        }
    }

    proptest! {
        // X25519 public key is never all-zero for random scalars.
        #[test]
        fn x25519_pubkey_nonzero(sk in any::<[u8; 32]>()) {
            let pk = x25519::x25519_base(&sk);
            prop_assert_ne!(pk, [0u8; 32], "public key must not be all-zero");
        }
    }

    proptest! {
        // ECIES Profile A: encrypt/decrypt roundtrip with random keys.
        #[test]
        fn ecies_a_roundtrip(
            hn_sk in any::<[u8; 32]>(),
            eph_sk in any::<[u8; 32]>(),
            msin in any::<[u8; 5]>(),
        ) {
            let hn_pk = x25519::x25519_base(&hn_sk);
            let result = ecies_profile_a_encrypt(&hn_pk, &msin, &Secret::new(eph_sk));

            // HN-side decrypt: ECDH + X9.63 KDF + verify MAC + AES-128-CTR.
            let shared_secret = x25519::x25519(&hn_sk, &result.ephemeral_pk);
            let mut kdf_out = [0u8; 64];
            simrs_kdf::kdf_x963(&shared_secret, &result.ephemeral_pk, 64, &mut kdf_out);

            let mut enc_key = [0u8; 16];
            enc_key.copy_from_slice(&kdf_out[..16]);
            let mut icb = [0u8; 16];
            icb.copy_from_slice(&kdf_out[16..32]);
            let mut mac_key = [0u8; 32];
            mac_key.copy_from_slice(&kdf_out[32..64]);

            // Verify MAC.
            let mut mac_hasher = simrs_kdf::HmacSha256::new(&mac_key);
            mac_hasher.update(&result.ciphertext[..result.ct_len]);
            let full_mac = mac_hasher.finalize();
            prop_assert_eq!(&full_mac[..8], &result.mac[..], "MAC must verify");

            // Decrypt.
            let mut decrypted = [0u8; 16];
            aes128_ctr(&enc_key, &icb, &result.ciphertext[..result.ct_len], &mut decrypted);
            prop_assert_eq!(&decrypted[..msin.len()], &msin[..]);
        }
    }

    // Strategy that generates a valid P-256 scalar in [1, n-1].
    fn valid_p256_scalar() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>().prop_filter("scalar must be in [1, n-1]", |k| {
            p256::validate_scalar(k)
        })
    }

    proptest! {
        // ECIES Profile B: encrypt/decrypt roundtrip with random valid keys.
        #[test]
        fn ecies_b_roundtrip(
            hn_sk in valid_p256_scalar(),
            eph_sk in valid_p256_scalar(),
            msin in any::<[u8; 5]>(),
        ) {
            let hn_pk = p256::p256_pubkey(&hn_sk);
            let result = ecies_profile_b_encrypt(&hn_pk, &msin, &Secret::new(eph_sk));

            // HN-side decrypt: decompress ephemeral pk, ECDH, re-derive keys.
            let eph_pk_uncompressed = p256::p256_decompress_pubkey(&result.ephemeral_pk)
                .expect("decompress must succeed for valid key");
            let z = p256::p256_ecdh(&hn_sk, &eph_pk_uncompressed)
                .expect("ECDH must succeed");

            let mut kdf_out = [0u8; 64];
            simrs_kdf::kdf_x963(&z, &result.ephemeral_pk, 64, &mut kdf_out);

            let mut enc_key = [0u8; 16];
            enc_key.copy_from_slice(&kdf_out[..16]);
            let mut icb = [0u8; 16];
            icb.copy_from_slice(&kdf_out[16..32]);
            let mut mac_key = [0u8; 32];
            mac_key.copy_from_slice(&kdf_out[32..64]);

            // Verify MAC.
            let mut mac_hasher = simrs_kdf::HmacSha256::new(&mac_key);
            mac_hasher.update(&result.ciphertext[..result.ct_len]);
            let full_mac = mac_hasher.finalize();
            prop_assert_eq!(&full_mac[..8], &result.mac[..], "MAC must verify");

            // Decrypt.
            let mut decrypted = [0u8; 16];
            aes128_ctr(&enc_key, &icb, &result.ciphertext[..result.ct_len], &mut decrypted);
            prop_assert_eq!(&decrypted[..msin.len()], &msin[..]);
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (DudeCT)
//
//   cargo test -p simrs-ecies --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{ct_test, assert_no_timing_leak, Rng};

    /// X25519 scalar multiplication timing must be independent of scalar value.
    /// Class 0: fixed scalar, random base point.
    /// Class 1: random scalar, random base point.
    #[test]
    fn test_x25519_scalar_mul_ct() {
        let outcome = ct_test(0xC25519_01,
            |rng| {
                let scalar = [0x42u8; 32];
                let mut base = [0u8; 32];
                rng.fill_bytes(&mut base);
                (scalar, base)
            },
            |rng| {
                let mut scalar = [0u8; 32];
                rng.fill_bytes(&mut scalar);
                let mut base = [0u8; 32];
                rng.fill_bytes(&mut base);
                (scalar, base)
            },
            |(scalar, base)| {
                black_box(x25519::x25519(scalar, base));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// ECIES Profile A encryption timing must be independent of plaintext content.
    /// Class 0: fixed plaintext with random ephemeral key.
    /// Class 1: random plaintext with random ephemeral key.
    #[test]
    fn test_ecies_profile_a_ct() {
        let hn_pk = x25519::x25519_base(&[0x77u8; 32]);
        let outcome = ct_test(0xEC1E5_A01,
            |rng| {
                let pt = [0x12, 0x34, 0x56, 0x78, 0x9A];
                let mut eph = [0u8; 32];
                rng.fill_bytes(&mut eph);
                (pt, eph)
            },
            |rng| {
                let mut pt = [0u8; 5];
                rng.fill_bytes(&mut pt);
                let mut eph = [0u8; 32];
                rng.fill_bytes(&mut eph);
                (pt, eph)
            },
            |(pt, eph)| {
                black_box(ecies_profile_a_encrypt(&hn_pk, pt, &Secret::new(*eph)));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// P-256 scalar multiplication timing must be independent of scalar value.
    /// Class 0: fixed scalar, same peer pubkey.
    /// Class 1: random valid scalar, same peer pubkey.
    ///
    /// Both classes consume the RNG identically (fill 32 bytes, validate,
    /// retry if needed) to avoid setup-time asymmetry.
    #[test]
    fn test_p256_scalar_mul_ct() {
        let hn_sk = [
            0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7,
            0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68, 0xb1,
            0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac,
            0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f, 0xec, 0xda,
        ];
        let hn_pk = p256::p256_pubkey(&hn_sk);
        let fixed_scalar: [u8; 32] = [
            0x99, 0x79, 0x88, 0x58, 0xa1, 0xdc, 0x6a, 0x2c,
            0x68, 0x63, 0x71, 0x49, 0xa4, 0xb1, 0xdb, 0xfd,
            0x1f, 0xdf, 0xf5, 0xad, 0xdd, 0x62, 0xa2, 0x14,
            0x2f, 0x06, 0x69, 0x9e, 0xd7, 0x60, 0x25, 0x29,
        ];

        // Helper: generate a valid scalar from RNG (both classes use this
        // so setup cost is symmetric).
        fn gen_valid_scalar(rng: &mut Rng) -> [u8; 32] {
            let mut s = [0u8; 32];
            loop {
                rng.fill_bytes(&mut s);
                if p256::validate_scalar(&s) {
                    return s;
                }
            }
        }

        let outcome = ct_test(0x9256_0001,
            |rng| {
                // Class 0: generate a random scalar (burn rng), but use the fixed one.
                let _ = gen_valid_scalar(rng);
                (fixed_scalar, hn_pk)
            },
            |rng| {
                // Class 1: use the random scalar.
                let scalar = gen_valid_scalar(rng);
                (scalar, hn_pk)
            },
            |(scalar, pk)| {
                black_box(p256::p256_ecdh(scalar, pk));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// ECIES Profile B encryption timing must be independent of plaintext content.
    /// Class 0: fixed plaintext with valid random ephemeral key.
    /// Class 1: random plaintext with valid random ephemeral key.
    #[test]
    fn test_ecies_profile_b_ct() {
        let hn_sk = [
            0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7,
            0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68, 0xb1,
            0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac,
            0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f, 0xec, 0xda,
        ];
        let hn_pk = p256::p256_pubkey(&hn_sk);
        let outcome = ct_test(0xEC1E5_B01,
            |rng| {
                let pt = [0x12, 0x34, 0x56, 0x78, 0x9A];
                let mut eph = [0u8; 32];
                loop {
                    rng.fill_bytes(&mut eph);
                    if p256::validate_scalar(&eph) {
                        break;
                    }
                }
                (pt, eph)
            },
            |rng| {
                let mut pt = [0u8; 5];
                rng.fill_bytes(&mut pt);
                let mut eph = [0u8; 32];
                loop {
                    rng.fill_bytes(&mut eph);
                    if p256::validate_scalar(&eph) {
                        break;
                    }
                }
                (pt, eph)
            },
            |(pt, eph)| {
                black_box(ecies_profile_b_encrypt(&hn_pk, pt, &Secret::new(*eph)));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// P-256 scalar multiplication with scalar = n-1 (maximum valid) vs
    /// mid-range scalars. This exercises the edge of the scalar domain where
    /// the ladder repeatedly hits the doubling case in Point::add.
    ///
    /// Class 0: scalar = n-1 (fixed, near group order).
    /// Class 1: random valid scalar.
    #[test]
    fn test_p256_scalar_near_order_ct() {
        let hn_sk = [
            0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7,
            0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68, 0xb1,
            0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac,
            0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f, 0xec, 0xda,
        ];
        let hn_pk = p256::p256_pubkey(&hn_sk);

        // n-1 for P-256: FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
        //                 BCE6FAAD A7179E84 F3B9CAC2 FC632550
        let n_minus_1: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
        ];

        let outcome = ct_test(0x9256_0003,
            |rng| {
                let mut _discard = [0u8; 32];
                rng.fill_bytes(&mut _discard);
                (n_minus_1, hn_pk)
            },
            |rng| {
                let mut s = [0u8; 32];
                loop {
                    rng.fill_bytes(&mut s);
                    if p256::validate_scalar(&s) {
                        break;
                    }
                }
                (s, hn_pk)
            },
            |(scalar, pk)| {
                black_box(p256::p256_ecdh(scalar, pk));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// P-256 scalar multiplication must be constant-time for sparse scalars.
    ///
    /// Scalar=3 has Hamming weight 2, meaning 254 of 256 ladder steps
    /// operate on the identity point (Z=0). Without projective coordinate
    /// randomization and scalar blinding, this causes a Zero-Value Register
    /// Attack (ZRA / Goubin 2003) where field multiplications with all-zero
    /// operands execute faster on some CPUs.
    ///
    /// Class 0: scalar = 3 (sparse, Hamming weight 2).
    /// Class 1: random valid scalar (dense, ~128 set bits on average).
    #[test]
    fn test_p256_scalar_sparse_vs_dense_ct() {
        let hn_sk = [
            0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7,
            0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68, 0xb1,
            0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac,
            0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f, 0xec, 0xda,
        ];
        let hn_pk = p256::p256_pubkey(&hn_sk);

        // Scalar = 3 (big-endian): 31 zero bytes followed by 0x03.
        let mut sparse_scalar = [0u8; 32];
        sparse_scalar[31] = 0x03;

        let outcome = ct_test(0x9256_0004,
            |rng| {
                // Class 0: burn RNG to keep symmetric, use sparse scalar.
                let mut _discard = [0u8; 32];
                rng.fill_bytes(&mut _discard);
                (sparse_scalar, hn_pk)
            },
            |rng| {
                // Class 1: random valid scalar.
                let mut s = [0u8; 32];
                loop {
                    rng.fill_bytes(&mut s);
                    if p256::validate_scalar(&s) {
                        break;
                    }
                }
                (s, hn_pk)
            },
            |(scalar, pk)| {
                black_box(p256::p256_ecdh(scalar, pk));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// AES-CTR counter increment timing must be independent of carry depth.
    ///
    /// Class 0: counter = 0xFF..FF (maximum carry: all 16 bytes carry).
    /// Class 1: counter = 0x00..01 (zero carry: only LSB increments).
    ///
    /// Before the branchless fix, the old implementation had an early exit
    /// on no carry, making class 1 significantly faster.
    #[test]
    fn test_increment_counter_ct() {
        let outcome = ct_test(0x1AAEC_0001,
            |_rng| {
                // Class 0: all-FF counter (every byte carries).
                [0xFFu8; 16]
            },
            |_rng| {
                // Class 1: counter at 1 (no carry at all).
                let mut c = [0u8; 16];
                c[15] = 0x01;
                c
            },
            |ctr| {
                let mut c = *ctr;
                black_box(increment_counter(&mut c));
                black_box(c);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// AES-CTR counter increment with random carry depth.
    ///
    /// Class 0: counter ending in 8 bytes of 0xFF (8-byte carry chain).
    /// Class 1: random counter value (variable carry depth).
    #[test]
    fn test_increment_counter_variable_carry_ct() {
        let outcome = ct_test(0x1AAEC_0002,
            |rng| {
                // Class 0: high bytes random, low 8 bytes = 0xFF.
                let mut c = [0xFFu8; 16];
                let mut hi = [0u8; 8];
                rng.fill_bytes(&mut hi);
                c[..8].copy_from_slice(&hi);
                // Burn 8 more bytes to keep RNG symmetric.
                let mut _discard = [0u8; 8];
                rng.fill_bytes(&mut _discard);
                c
            },
            |rng| {
                // Class 1: fully random counter.
                let mut c = [0u8; 16];
                rng.fill_bytes(&mut c);
                c
            },
            |ctr| {
                let mut c = *ctr;
                black_box(increment_counter(&mut c));
                black_box(c);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
