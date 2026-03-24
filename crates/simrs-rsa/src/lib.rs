//! RSA encryption/decryption and PKCS#1 v1.5 signing/verification.
//!
//! Implements RSA raw operations and PKCS#1 v1.5 padding per
//! [RFC 2437](https://www.rfc-editor.org/rfc/rfc2437) /
//! [RFC 8017 Sections 7.2 and 9.2](https://www.rfc-editor.org/rfc/rfc8017).
//!
//! Built on top of [`simrs_bignum`] for all big-integer arithmetic
//! (Montgomery modular exponentiation).
//!
//! # Key sizes
//!
//! Type aliases are provided for common RSA key sizes:
//! - [`Rsa512Public`] / [`Rsa512Private`] -- 512-bit (legacy, insecure)
//! - [`Rsa768Public`] / [`Rsa768Private`] -- 768-bit (legacy, insecure)
//! - [`Rsa1024Public`] / [`Rsa1024Private`] -- 1024-bit
//! - [`Rsa2048Public`] / [`Rsa2048Private`] -- 2048-bit
//!
//! # Security note
//!
//! This implementation is intended for embedded smart-card contexts where
//! key sizes and algorithms are constrained by the platform specification.
//! SHA-1 is used for signing because many SIM/smart-card standards mandate it.
//!
//! # `no_std`, `no_alloc`
//!
//! This crate uses no heap. All operations are performed on stack values.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

use simrs_bignum::{BigUint, MontParams, mod_exp};
use simrs_sha1::sha1;

// ---------------------------------------------------------------------------
// SHA-1 DigestInfo prefix (PKCS#1 v1.5 / RFC 8017 Section 9.2 Note 1)
// ---------------------------------------------------------------------------

/// ASN.1 `DigestInfo` prefix for SHA-1 per RFC 8017 Section 9.2, Note 1.
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///   digestAlgorithm  AlgorithmIdentifier(id-sha1, NULL),
///   digest           OCTET STRING (SIZE(20))
/// }
/// ```
///
/// Encoded as: `30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14`
const SHA1_DIGEST_INFO_PREFIX: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

/// Total `DigestInfo` length: 15 bytes prefix + 20 bytes SHA-1 hash.
const DIGEST_INFO_LEN: usize = SHA1_DIGEST_INFO_PREFIX.len() + 20;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// RSA public key parameterised by limb count.
///
/// `LIMBS` determines the key size: `LIMBS * 64` bits.
/// For example, `LIMBS = 16` gives a 1024-bit RSA key.
#[derive(Clone, Debug)]
pub struct RsaPublicKey<const LIMBS: usize> {
    /// The RSA modulus `n = p * q`.
    n: BigUint<LIMBS>,
    /// The public exponent (typically 65537 = 0x10001).
    e: u32,
    /// Precomputed Montgomery parameters for `n`.
    mont: MontParams<LIMBS>,
}

/// RSA private key parameterised by limb count.
///
/// `LIMBS` determines the key size: `LIMBS * 64` bits.
#[derive(Clone, Debug)]
pub struct RsaPrivateKey<const LIMBS: usize> {
    /// The RSA modulus `n = p * q`.
    n: BigUint<LIMBS>,
    /// The private exponent `d = e^{-1} mod phi(n)`.
    d: BigUint<LIMBS>,
    /// The public exponent.
    e: u32,
    /// Precomputed Montgomery parameters for `n`.
    mont: MontParams<LIMBS>,
}

// -- Type aliases for common key sizes --------------------------------------

/// 512-bit RSA public key (8 limbs of 64 bits each).
pub type Rsa512Public = RsaPublicKey<8>;
/// 512-bit RSA private key.
pub type Rsa512Private = RsaPrivateKey<8>;
/// 768-bit RSA public key (12 limbs).
pub type Rsa768Public = RsaPublicKey<12>;
/// 768-bit RSA private key.
pub type Rsa768Private = RsaPrivateKey<12>;
/// 1024-bit RSA public key (16 limbs).
pub type Rsa1024Public = RsaPublicKey<16>;
/// 1024-bit RSA private key.
pub type Rsa1024Private = RsaPrivateKey<16>;
/// 2048-bit RSA public key (32 limbs).
pub type Rsa2048Public = RsaPublicKey<32>;
/// 2048-bit RSA private key.
pub type Rsa2048Private = RsaPrivateKey<32>;

// -- Key construction -------------------------------------------------------

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Create a new RSA public key from modulus bytes and public exponent.
    ///
    /// `n_bytes` is the modulus in big-endian byte order.
    /// `e` is the public exponent (typically 65537).
    ///
    /// # Panics
    ///
    /// Panics if the modulus is even (Montgomery arithmetic requires odd modulus).
    pub fn new(n_bytes: &[u8], e: u32) -> Self {
        let n = BigUint::<LIMBS>::from_be_bytes(n_bytes);
        let mont = MontParams::new(&n);
        Self { n, e, mont }
    }

    /// Return the key size in bytes (modulus byte length).
    pub const fn key_len(&self) -> usize {
        LIMBS * 8
    }

    /// Return a reference to the modulus.
    pub const fn modulus(&self) -> &BigUint<LIMBS> {
        &self.n
    }

    /// Return the public exponent.
    pub const fn exponent(&self) -> u32 {
        self.e
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Create a new RSA private key from modulus bytes, private exponent
    /// bytes, and public exponent.
    ///
    /// Both `n_bytes` and `d_bytes` are in big-endian byte order.
    ///
    /// # Panics
    ///
    /// Panics if the modulus is even.
    pub fn new(n_bytes: &[u8], d_bytes: &[u8], e: u32) -> Self {
        let n = BigUint::<LIMBS>::from_be_bytes(n_bytes);
        let d = BigUint::<LIMBS>::from_be_bytes(d_bytes);
        let mont = MontParams::new(&n);
        Self { n, d, e, mont }
    }

    /// Return the key size in bytes.
    pub const fn key_len(&self) -> usize {
        LIMBS * 8
    }

    /// Extract the corresponding public key.
    pub fn public_key(&self) -> RsaPublicKey<LIMBS> {
        RsaPublicKey {
            n: self.n,
            e: self.e,
            mont: self.mont.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Raw RSA operations
// ---------------------------------------------------------------------------

/// Raw RSA encryption: `c = m^e mod n`.
///
/// No padding is applied. The caller is responsible for ensuring that
/// `msg < n`.
pub fn rsa_encrypt_raw<const LIMBS: usize>(
    key: &RsaPublicKey<LIMBS>,
    msg: &BigUint<LIMBS>,
) -> BigUint<LIMBS> {
    let e_big = BigUint::<LIMBS>::from_u64(u64::from(key.e));
    mod_exp(msg, &e_big, &key.mont)
}

/// Raw RSA decryption: `m = c^d mod n`.
///
/// No padding is removed. The caller is responsible for interpreting
/// the result.
pub fn rsa_decrypt_raw<const LIMBS: usize>(
    key: &RsaPrivateKey<LIMBS>,
    cipher: &BigUint<LIMBS>,
) -> BigUint<LIMBS> {
    mod_exp(cipher, &key.d, &key.mont)
}

// ---------------------------------------------------------------------------
// PKCS#1 v1.5 padding helpers
// ---------------------------------------------------------------------------

/// Build EMSA-PKCS1-v1_5 encoded message for signing (RFC 8017 Section 9.2).
///
/// ```text
/// EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
/// ```
///
/// where `PS` is `0xFF` bytes of length `em_len - 3 - DIGEST_INFO_LEN`,
/// and `DigestInfo = SHA1_DIGEST_INFO_PREFIX || hash`.
///
/// Returns the number of bytes written to `em`, or 0 if the key is too
/// short to hold the padded message.
fn pkcs1_sign_pad(hash: &[u8; 20], em: &mut [u8]) -> usize {
    let em_len = em.len();

    // Minimum: 0x00 0x01 [>=8 bytes PS] 0x00 [35 bytes DigestInfo]
    // = 3 + 8 + 35 = 46 bytes minimum
    if em_len < DIGEST_INFO_LEN + 11 {
        return 0;
    }

    let ps_len = em_len - 3 - DIGEST_INFO_LEN;
    let mut pos = 0;

    // 0x00 || 0x01
    em[pos] = 0x00;
    pos += 1;
    em[pos] = 0x01;
    pos += 1;

    // PS: 0xFF bytes
    let mut i = 0;
    while i < ps_len {
        em[pos] = 0xFF;
        pos += 1;
        i += 1;
    }

    // 0x00 separator
    em[pos] = 0x00;
    pos += 1;

    // DigestInfo prefix
    let mut j = 0;
    while j < SHA1_DIGEST_INFO_PREFIX.len() {
        em[pos] = SHA1_DIGEST_INFO_PREFIX[j];
        pos += 1;
        j += 1;
    }

    // SHA-1 hash
    let mut k = 0;
    while k < 20 {
        em[pos] = hash[k];
        pos += 1;
        k += 1;
    }

    pos
}

/// Build RSAES-PKCS1-V1_5 encoded message for encryption (RFC 8017 Section 7.2.1).
///
/// ```text
/// EM = 0x00 || 0x02 || PS || 0x00 || M
/// ```
///
/// where `PS` is random non-zero bytes of length `em_len - 3 - msg_len`,
/// with `len(PS) >= 8`.
///
/// The `rand_fill` closure fills a buffer with random non-zero bytes.
/// Returns the number of bytes written to `em`, or 0 on error.
fn pkcs1_encrypt_pad(
    msg: &[u8],
    em: &mut [u8],
    rand_fill: &mut dyn FnMut(&mut [u8]),
) -> usize {
    let em_len = em.len();

    // Minimum: 0x00 0x02 [>=8 bytes PS] 0x00 msg
    // = 3 + 8 + msg_len minimum
    if msg.len() + 11 > em_len {
        return 0;
    }

    let ps_len = em_len - 3 - msg.len();
    let mut pos = 0;

    // 0x00 || 0x02
    em[pos] = 0x00;
    pos += 1;
    em[pos] = 0x02;
    pos += 1;

    // PS: random non-zero bytes
    rand_fill(&mut em[pos..pos + ps_len]);
    // Ensure no zero bytes in PS (replace any zeros with 0x01)
    let mut i = 0;
    while i < ps_len {
        if em[pos + i] == 0x00 {
            em[pos + i] = 0x01;
        }
        i += 1;
    }
    pos += ps_len;

    // 0x00 separator
    em[pos] = 0x00;
    pos += 1;

    // Message
    let mut j = 0;
    while j < msg.len() {
        em[pos] = msg[j];
        pos += 1;
        j += 1;
    }

    pos
}

/// Verify EMSA-PKCS1-v1_5 padding and extract the hash from a decrypted
/// signature block.
///
/// Returns `true` if the padding is valid and the extracted hash matches
/// `expected_hash`.
fn pkcs1_verify_pad(em: &[u8], expected_hash: &[u8; 20]) -> bool {
    let em_len = em.len();
    if em_len < DIGEST_INFO_LEN + 11 {
        return false;
    }

    // Check: 0x00 0x01
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }

    // Find the 0x00 separator after PS. PS must be all 0xFF and >= 8 bytes.
    let mut sep_pos = 2;
    while sep_pos < em_len && em[sep_pos] == 0xFF {
        sep_pos += 1;
    }

    // PS length check
    let ps_len = sep_pos - 2;
    if ps_len < 8 {
        return false;
    }

    // Check separator
    if sep_pos >= em_len || em[sep_pos] != 0x00 {
        return false;
    }
    sep_pos += 1;

    // Remaining bytes must be DigestInfo
    let remaining = em_len - sep_pos;
    if remaining != DIGEST_INFO_LEN {
        return false;
    }

    // Check DigestInfo prefix
    let mut i = 0;
    while i < SHA1_DIGEST_INFO_PREFIX.len() {
        if em[sep_pos + i] != SHA1_DIGEST_INFO_PREFIX[i] {
            return false;
        }
        i += 1;
    }

    // Compare hash
    let hash_start = sep_pos + SHA1_DIGEST_INFO_PREFIX.len();
    let mut j = 0;
    while j < 20 {
        if em[hash_start + j] != expected_hash[j] {
            return false;
        }
        j += 1;
    }

    true
}

/// Unpad an RSAES-PKCS1-V1_5 encrypted message (RFC 8017 Section 7.2.2).
///
/// Returns the number of plaintext bytes written to `output`, or 0 on error.
fn pkcs1_decrypt_unpad(em: &[u8], output: &mut [u8]) -> usize {
    let em_len = em.len();
    if em_len < 11 {
        return 0;
    }

    // Check: 0x00 0x02
    if em[0] != 0x00 || em[1] != 0x02 {
        return 0;
    }

    // Find the 0x00 separator. PS must be non-zero bytes, >= 8 bytes long.
    let mut sep_pos = 2;
    while sep_pos < em_len && em[sep_pos] != 0x00 {
        sep_pos += 1;
    }

    let ps_len = sep_pos - 2;
    if ps_len < 8 {
        return 0;
    }

    if sep_pos >= em_len {
        return 0;
    }

    // Skip separator
    sep_pos += 1;

    let msg_len = em_len - sep_pos;
    if msg_len > output.len() {
        return 0;
    }

    let mut i = 0;
    while i < msg_len {
        output[i] = em[sep_pos + i];
        i += 1;
    }

    msg_len
}

// ---------------------------------------------------------------------------
// Public API: PKCS#1 v1.5 sign / verify
// ---------------------------------------------------------------------------

/// PKCS#1 v1.5 sign with SHA-1.
///
/// 1. Hash `message` with SHA-1.
/// 2. Apply EMSA-PKCS1-v1_5 padding (type 1).
/// 3. Compute signature = padded^d mod n (raw RSA "decryption" with private key).
///
/// The signature is written to `sig` in big-endian byte order.
/// Returns the number of bytes written (always `LIMBS * 8` on success, 0 on error).
///
/// # Panics
///
/// Panics if `sig.len() < LIMBS * 8`.
pub fn sign_pkcs1_sha1<const LIMBS: usize>(
    key: &RsaPrivateKey<LIMBS>,
    message: &[u8],
    sig: &mut [u8],
) -> usize {
    let key_bytes = LIMBS * 8;
    assert!(
        sig.len() >= key_bytes,
        "signature buffer too small: need {key_bytes}, got {}",
        sig.len()
    );

    let hash = sha1(message);

    // Build EMSA-PKCS1-v1_5 padded message
    let mut em = [0u8; 512]; // max 4096-bit key
    if key_bytes > em.len() {
        return 0;
    }
    let padded_len = pkcs1_sign_pad(&hash, &mut em[..key_bytes]);
    if padded_len == 0 {
        return 0;
    }

    // Convert padded message to BigUint and compute signature
    let em_int = BigUint::<LIMBS>::from_be_bytes(&em[..key_bytes]);
    let sig_int = rsa_decrypt_raw(key, &em_int);

    // Write signature to output
    sig_int.to_be_bytes(&mut sig[..key_bytes]);
    key_bytes
}

/// PKCS#1 v1.5 verify with SHA-1.
///
/// 1. Compute padded = signature^e mod n (raw RSA "encryption" with public key).
/// 2. Check EMSA-PKCS1-v1_5 padding structure.
/// 3. Compare embedded hash with SHA-1 hash of `message`.
///
/// Returns `true` if the signature is valid.
pub fn verify_pkcs1_sha1<const LIMBS: usize>(
    key: &RsaPublicKey<LIMBS>,
    message: &[u8],
    sig: &[u8],
) -> bool {
    let key_bytes = LIMBS * 8;
    if sig.len() != key_bytes {
        return false;
    }

    let hash = sha1(message);

    // Recover padded message from signature
    let sig_int = BigUint::<LIMBS>::from_be_bytes(sig);
    let em_int = rsa_encrypt_raw(key, &sig_int);

    // Convert back to bytes
    let mut em = [0u8; 512]; // max 4096-bit key
    if key_bytes > em.len() {
        return false;
    }
    em_int.to_be_bytes(&mut em[..key_bytes]);

    // Verify padding and hash
    pkcs1_verify_pad(&em[..key_bytes], &hash)
}

// ---------------------------------------------------------------------------
// Public API: PKCS#1 v1.5 encrypt / decrypt
// ---------------------------------------------------------------------------

/// PKCS#1 v1.5 encrypt (RSAES-PKCS1-V1_5, RFC 8017 Section 7.2.1).
///
/// Encrypts `plaintext` using the public key with type-2 padding.
/// The `rand_fill` closure provides random non-zero bytes for padding.
///
/// The ciphertext is written to `output` in big-endian byte order.
/// Returns the number of bytes written (always `LIMBS * 8` on success, 0 on error).
///
/// # Panics
///
/// Panics if `output.len() < LIMBS * 8`.
pub fn encrypt_pkcs1<const LIMBS: usize>(
    key: &RsaPublicKey<LIMBS>,
    plaintext: &[u8],
    output: &mut [u8],
    rand_fill: &mut dyn FnMut(&mut [u8]),
) -> usize {
    let key_bytes = LIMBS * 8;
    assert!(
        output.len() >= key_bytes,
        "output buffer too small: need {key_bytes}, got {}",
        output.len()
    );

    let mut em = [0u8; 512];
    if key_bytes > em.len() {
        return 0;
    }

    let padded_len = pkcs1_encrypt_pad(plaintext, &mut em[..key_bytes], rand_fill);
    if padded_len == 0 {
        return 0;
    }

    let em_int = BigUint::<LIMBS>::from_be_bytes(&em[..key_bytes]);
    let ct_int = rsa_encrypt_raw(key, &em_int);

    ct_int.to_be_bytes(&mut output[..key_bytes]);
    key_bytes
}

/// PKCS#1 v1.5 decrypt (RSAES-PKCS1-V1_5, RFC 8017 Section 7.2.2).
///
/// Decrypts `ciphertext` using the private key and removes type-2 padding.
///
/// Returns the number of plaintext bytes written to `output`, or 0 on error.
pub fn decrypt_pkcs1<const LIMBS: usize>(
    key: &RsaPrivateKey<LIMBS>,
    ciphertext: &[u8],
    output: &mut [u8],
) -> usize {
    let key_bytes = LIMBS * 8;
    if ciphertext.len() != key_bytes {
        return 0;
    }

    let ct_int = BigUint::<LIMBS>::from_be_bytes(ciphertext);
    let em_int = rsa_decrypt_raw(key, &ct_int);

    let mut em = [0u8; 512];
    if key_bytes > em.len() {
        return 0;
    }
    em_int.to_be_bytes(&mut em[..key_bytes]);

    pkcs1_decrypt_unpad(&em[..key_bytes], output)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test key material (512-bit for fast tests) --------------------------
    //
    // Generated with:
    //   p = 0xD4BCD52406F2C926_B1B34B340F893075_DE2F093B0739BE63_47C5C86A00F2C735
    //   q = 0xD15ECF0C2E43E2B8_05BEED04F74B7E35_D6ED7C3DA185E32A_5B3C5AF8DF04A9FF
    //   n = p * q
    //   e = 65537
    //   d = e^{-1} mod lcm(p-1, q-1)
    //
    // These are NOT cryptographically secure -- they're test vectors only.

    // n (64 bytes, big-endian) -- product of two 256-bit primes
    const TEST_N_512: [u8; 64] = [
        0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47, 0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25,
        0xA5, 0x8B, 0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76, 0x30, 0xBB, 0x58, 0xBD,
        0xC3, 0x4D, 0xB1, 0xF0, 0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36, 0x79, 0x0D,
        0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3, 0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C,
        0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
    ];

    // d (64 bytes, big-endian) -- e^{-1} mod phi(n)
    const TEST_D_512: [u8; 64] = [
        0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC, 0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA,
        0xEF, 0xE8, 0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E, 0xEF, 0xAA, 0x69, 0x14,
        0xF7, 0x21, 0x0E, 0x08, 0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA, 0x12, 0xB4,
        0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78, 0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63,
        0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
    ];

    const TEST_E: u32 = 65537;

    fn test_private_key() -> RsaPrivateKey<8> {
        RsaPrivateKey::new(&TEST_N_512, &TEST_D_512, TEST_E)
    }

    fn test_public_key() -> RsaPublicKey<8> {
        RsaPublicKey::new(&TEST_N_512, TEST_E)
    }

    // -- Raw RSA round-trip --------------------------------------------------

    #[test]
    fn raw_encrypt_decrypt_roundtrip() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        // Use a small plaintext value
        let plaintext = BigUint::<8>::from_u64(0x4865_6C6C_6F21); // "Hello!"

        let ciphertext = rsa_encrypt_raw(&pub_key, &plaintext);
        let recovered = rsa_decrypt_raw(&priv_key, &ciphertext);

        // Compare limb by limb
        assert_eq!(recovered.limbs, plaintext.limbs, "raw RSA round-trip failed");
    }

    #[test]
    fn raw_encrypt_decrypt_larger_value() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        // A larger value (still < n)
        let msg_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23,
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let plaintext = BigUint::<8>::from_be_bytes(&msg_bytes);

        let ciphertext = rsa_encrypt_raw(&pub_key, &plaintext);
        // Ciphertext should differ from plaintext
        assert_ne!(
            ciphertext.limbs, plaintext.limbs,
            "ciphertext should differ from plaintext"
        );

        let recovered = rsa_decrypt_raw(&priv_key, &ciphertext);
        assert_eq!(recovered.limbs, plaintext.limbs, "raw RSA round-trip failed");
    }

    // -- PKCS#1 v1.5 sign padding structure ----------------------------------

    #[test]
    fn sign_padding_structure() {
        let hash = sha1(b"test message");
        let mut em = [0u8; 64]; // 512-bit key
        let len = pkcs1_sign_pad(&hash, &mut em);
        assert_eq!(len, 64);

        // Check structure: 0x00 0x01 FF...FF 0x00 DigestInfo Hash
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);

        // PS: bytes 2..(2 + ps_len), all 0xFF
        // ps_len = 64 - 3 - 35 = 26
        let ps_len = 64 - 3 - DIGEST_INFO_LEN;
        assert_eq!(ps_len, 26);
        for i in 0..ps_len {
            assert_eq!(em[2 + i], 0xFF, "PS byte {i} should be 0xFF");
        }

        // 0x00 separator
        assert_eq!(em[2 + ps_len], 0x00);

        // DigestInfo prefix
        let di_start = 3 + ps_len;
        assert_eq!(
            &em[di_start..di_start + 15],
            &SHA1_DIGEST_INFO_PREFIX,
            "DigestInfo prefix mismatch"
        );

        // Hash
        assert_eq!(
            &em[di_start + 15..di_start + 35],
            &hash,
            "hash mismatch in padded message"
        );
    }

    // -- PKCS#1 v1.5 sign/verify round-trip ----------------------------------

    #[test]
    fn sign_verify_roundtrip() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        let message = b"Hello, RSA PKCS#1 v1.5!";
        let mut sig = [0u8; 64];
        let sig_len = sign_pkcs1_sha1(&priv_key, message, &mut sig);
        assert_eq!(sig_len, 64);

        // Signature should not be all zeros
        assert!(sig.iter().any(|&b| b != 0), "signature should not be zero");

        // Verify should succeed
        assert!(
            verify_pkcs1_sha1(&pub_key, message, &sig),
            "signature verification failed"
        );
    }

    #[test]
    fn verify_wrong_message_fails() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        let message = b"original message";
        let mut sig = [0u8; 64];
        sign_pkcs1_sha1(&priv_key, message, &mut sig);

        // Different message should fail verification
        assert!(
            !verify_pkcs1_sha1(&pub_key, b"tampered message", &sig),
            "verification should fail for wrong message"
        );
    }

    #[test]
    fn verify_corrupted_signature_fails() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        let message = b"test message";
        let mut sig = [0u8; 64];
        sign_pkcs1_sha1(&priv_key, message, &mut sig);

        // Flip a bit in the signature
        sig[32] ^= 0x01;

        assert!(
            !verify_pkcs1_sha1(&pub_key, message, &sig),
            "verification should fail for corrupted signature"
        );
    }

    #[test]
    fn verify_wrong_length_signature_fails() {
        let pub_key = test_public_key();
        let message = b"test";

        // Signature that's too short
        let short_sig = [0u8; 32];
        assert!(
            !verify_pkcs1_sha1(&pub_key, message, &short_sig),
            "verification should fail for wrong-length signature"
        );
    }

    // -- PKCS#1 v1.5 encrypt/decrypt round-trip ------------------------------

    /// Deterministic "random" fill for testing. Fills with a repeating
    /// pattern of non-zero bytes.
    #[allow(clippy::cast_possible_truncation)]
    fn test_rand_fill(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            // Non-zero pattern: cycle through 0x01..0xFF
            // Truncation is intentional: i % 255 + 1 is always in [1, 255].
            *byte = (i % 255 + 1) as u8;
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        let plaintext = b"secret data";
        let mut ciphertext = [0u8; 64];
        let ct_len =
            encrypt_pkcs1(&pub_key, plaintext, &mut ciphertext, &mut test_rand_fill);
        assert_eq!(ct_len, 64);

        let mut recovered = [0u8; 64];
        let pt_len = decrypt_pkcs1(&priv_key, &ciphertext, &mut recovered);
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(
            &recovered[..pt_len],
            plaintext,
            "encrypt/decrypt round-trip failed"
        );
    }

    #[test]
    fn encrypt_decrypt_empty_message() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        let plaintext = b"";
        let mut ciphertext = [0u8; 64];
        let ct_len =
            encrypt_pkcs1(&pub_key, plaintext, &mut ciphertext, &mut test_rand_fill);
        assert_eq!(ct_len, 64);

        let mut recovered = [0u8; 64];
        let pt_len = decrypt_pkcs1(&priv_key, &ciphertext, &mut recovered);
        assert_eq!(pt_len, 0);
    }

    #[test]
    fn encrypt_max_length_message() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        // Max plaintext for 512-bit key: 64 - 11 = 53 bytes
        let plaintext = [0x42u8; 53];
        let mut ciphertext = [0u8; 64];
        let ct_len =
            encrypt_pkcs1(&pub_key, &plaintext, &mut ciphertext, &mut test_rand_fill);
        assert_eq!(ct_len, 64);

        let mut recovered = [0u8; 64];
        let pt_len = decrypt_pkcs1(&priv_key, &ciphertext, &mut recovered);
        assert_eq!(pt_len, 53);
        assert_eq!(&recovered[..pt_len], &plaintext[..]);
    }

    #[test]
    fn encrypt_message_too_long() {
        let pub_key = test_public_key();

        // 54 bytes is too long for 512-bit key (max is 53)
        let plaintext = [0x42u8; 54];
        let mut ciphertext = [0u8; 64];
        let ct_len =
            encrypt_pkcs1(&pub_key, &plaintext, &mut ciphertext, &mut test_rand_fill);
        assert_eq!(ct_len, 0, "should fail for message too long");
    }

    #[test]
    fn decrypt_corrupted_ciphertext_fails() {
        let priv_key = test_private_key();
        let pub_key = test_public_key();

        let plaintext = b"test data";
        let mut ciphertext = [0u8; 64];
        encrypt_pkcs1(&pub_key, plaintext, &mut ciphertext, &mut test_rand_fill);

        // Corrupt ciphertext
        ciphertext[10] ^= 0xFF;

        let mut recovered = [0u8; 64];
        let pt_len = decrypt_pkcs1(&priv_key, &ciphertext, &mut recovered);
        // Decryption should fail (bad padding) or produce garbage
        // Either way, it should not produce the original plaintext
        if pt_len == plaintext.len() {
            assert_ne!(
                &recovered[..pt_len],
                plaintext.as_slice(),
                "corrupted ciphertext should not decrypt to original"
            );
        }
    }

    #[test]
    fn decrypt_wrong_length_ciphertext() {
        let priv_key = test_private_key();

        let bad_ct = [0u8; 32]; // wrong length
        let mut output = [0u8; 64];
        let pt_len = decrypt_pkcs1(&priv_key, &bad_ct, &mut output);
        assert_eq!(pt_len, 0, "should fail for wrong-length ciphertext");
    }

    // -- Key accessor tests --------------------------------------------------

    #[test]
    fn public_key_accessors() {
        let pub_key = test_public_key();
        assert_eq!(pub_key.key_len(), 64);
        assert_eq!(pub_key.exponent(), 65537);
    }

    #[test]
    fn private_key_extracts_public() {
        let priv_key = test_private_key();
        let pub_key = priv_key.public_key();
        assert_eq!(pub_key.key_len(), 64);
        assert_eq!(pub_key.exponent(), TEST_E);
        assert_eq!(pub_key.modulus().limbs, priv_key.n.limbs);
    }

    // -- Padding edge cases --------------------------------------------------

    #[test]
    fn sign_pad_too_small_key() {
        let hash = [0u8; 20];
        // 45 bytes is less than minimum (46)
        let mut em = [0u8; 45];
        let len = pkcs1_sign_pad(&hash, &mut em);
        assert_eq!(len, 0, "padding should fail for key too small");
    }

    #[test]
    fn sign_pad_minimum_key() {
        let hash = [0xAB; 20];
        // 46 bytes is the absolute minimum: 0x00 0x01 [8xFF] 0x00 [35 DigestInfo]
        let mut em = [0u8; 46];
        let len = pkcs1_sign_pad(&hash, &mut em);
        assert_eq!(len, 46);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        // PS is exactly 8 bytes of 0xFF
        for i in 0..8 {
            assert_eq!(em[2 + i], 0xFF);
        }
        assert_eq!(em[10], 0x00);
    }

    #[test]
    fn verify_pad_rejects_short_ps() {
        // Build an EM with only 7 bytes of FF (below minimum of 8)
        // 0x00 0x01 [7 x FF] 0x00 [35 DigestInfo]
        let total = 2 + 7 + 1 + DIGEST_INFO_LEN; // = 45
        let mut em = [0u8; 45];
        em[0] = 0x00;
        em[1] = 0x01;
        for i in 0..7 {
            em[2 + i] = 0xFF;
        }
        em[9] = 0x00;
        em[10..10 + 15].copy_from_slice(&SHA1_DIGEST_INFO_PREFIX);
        let hash = [0u8; 20];
        em[25..45].copy_from_slice(&hash);

        assert!(
            !pkcs1_verify_pad(&em[..total], &hash),
            "should reject PS shorter than 8 bytes"
        );
    }

    #[test]
    fn verify_pad_rejects_wrong_block_type() {
        let hash = [0u8; 20];
        let mut em = [0u8; 64];
        pkcs1_sign_pad(&hash, &mut em);
        // Change block type from 0x01 to 0x02
        em[1] = 0x02;
        assert!(
            !pkcs1_verify_pad(&em, &hash),
            "should reject wrong block type"
        );
    }

    // -- Multiple messages produce different signatures -----------------------

    #[test]
    fn different_messages_different_signatures() {
        let priv_key = test_private_key();

        let mut sig1 = [0u8; 64];
        let mut sig2 = [0u8; 64];
        sign_pkcs1_sha1(&priv_key, b"message one", &mut sig1);
        sign_pkcs1_sha1(&priv_key, b"message two", &mut sig2);

        assert_ne!(sig1, sig2, "different messages should produce different signatures");
    }

    // -- Sign then verify with extracted public key --------------------------

    #[test]
    fn sign_with_private_verify_with_extracted_public() {
        let priv_key = test_private_key();
        let pub_key = priv_key.public_key();

        let message = b"cross-key verification test";
        let mut sig = [0u8; 64];
        sign_pkcs1_sha1(&priv_key, message, &mut sig);

        assert!(
            verify_pkcs1_sha1(&pub_key, message, &sig),
            "verification with extracted public key should succeed"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Duplicate test key material (same as tests module) -- these are test-only
    // constants that can't be shared across sibling test modules.
    const TEST_N_512: [u8; 64] = [
        0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47, 0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25,
        0xA5, 0x8B, 0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76, 0x30, 0xBB, 0x58, 0xBD,
        0xC3, 0x4D, 0xB1, 0xF0, 0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36, 0x79, 0x0D,
        0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3, 0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C,
        0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
    ];
    const TEST_D_512: [u8; 64] = [
        0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC, 0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA,
        0xEF, 0xE8, 0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E, 0xEF, 0xAA, 0x69, 0x14,
        0xF7, 0x21, 0x0E, 0x08, 0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA, 0x12, 0xB4,
        0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78, 0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63,
        0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
    ];
    const TEST_E: u32 = 65537;

    fn test_private_key() -> RsaPrivateKey<8> {
        RsaPrivateKey::new(&TEST_N_512, &TEST_D_512, TEST_E)
    }

    fn test_public_key() -> RsaPublicKey<8> {
        RsaPublicKey::new(&TEST_N_512, TEST_E)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn proptest_rand_fill(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            // Truncation is intentional: i % 255 + 1 is always in [1, 255].
            *byte = (i % 255 + 1) as u8;
        }
    }

    proptest! {
        #[test]
        fn sign_verify_arbitrary_message(msg in proptest::collection::vec(any::<u8>(), 0..256)) {
            let priv_key = test_private_key();
            let pub_key = test_public_key();

            let mut sig = [0u8; 64];
            let sig_len = sign_pkcs1_sha1(&priv_key, &msg, &mut sig);
            prop_assert_eq!(sig_len, 64);

            prop_assert!(verify_pkcs1_sha1(&pub_key, &msg, &sig));
        }

        #[test]
        fn encrypt_decrypt_arbitrary_plaintext(pt in proptest::collection::vec(any::<u8>(), 0..53)) {
            let priv_key = test_private_key();
            let pub_key = test_public_key();

            let mut ciphertext = [0u8; 64];
            let ct_len = encrypt_pkcs1(&pub_key, &pt, &mut ciphertext, &mut proptest_rand_fill);
            prop_assert_eq!(ct_len, 64);

            let mut recovered = [0u8; 64];
            let pt_len = decrypt_pkcs1(&priv_key, &ciphertext, &mut recovered);
            prop_assert_eq!(pt_len, pt.len());
            prop_assert_eq!(&recovered[..pt_len], pt.as_slice());
        }

        #[test]
        fn tampered_signature_fails(
            msg in proptest::collection::vec(any::<u8>(), 1..128),
            flip_pos in 0..64usize,
            flip_bit in 0..8u8,
        ) {
            let priv_key = test_private_key();
            let pub_key = test_public_key();

            let mut sig = [0u8; 64];
            sign_pkcs1_sha1(&priv_key, &msg, &mut sig);

            // Flip one bit
            sig[flip_pos] ^= 1 << flip_bit;

            prop_assert!(!verify_pkcs1_sha1(&pub_key, &msg, &sig));
        }
    }
}
