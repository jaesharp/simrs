//! PUT KEY component wrapping/unwrapping primitives per
//! GP 2.3.1 § 11.8.2.3.1 (SCP01/SCP02) and Amendment D § 4.2.4.1.1 (SCP03).
//!
//! GP defines two distinct wrap modes for PUT KEY data, selected by the
//! active SCP version:
//!
//! - **SCP01 / SCP02:** each 16-byte key component is wrapped with the
//!   *session* DEK using **3DES-ECB**. Decryption splits the block into
//!   two independent 8-byte halves.
//! - **SCP03 (Amendment D):** each 16-byte key component is wrapped with
//!   the *static* DEK using **AES-CBC, IV = all-zeros**.
//!
//! Key Check Values (KCVs) are always computed in ECB mode, regardless of
//! the wrap mode used. The block plaintext differs by algorithm:
//!
//! - **3DES KCV** (GP 2.3.1 Appendix B.4): first 3 bytes of
//!   `3DES_ECB(key, [0u8; 8])`.
//! - **AES KCV** (Amendment D § B.2): first 3 bytes of
//!   `AES_ECB(key, [0x01u8; 16])`.
//!
//! Callers (currently `simrs-gp-open` PUT KEY) dispatch by inspecting the
//! `ScpVersion` of the active session and the Key Type Indicator of each
//! key block. This matches the static-dispatch convention used throughout
//! [`scp01`](crate::scp01), [`scp02`](crate::scp02), [`scp03`](crate::scp03),
//! and [`cmac`](crate::cmac).

use simrs_iso9797::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, des3_2key_ecb_decrypt, des3_2key_ecb_encrypt,
};
use simrs_rijndael::Rijndael;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// Key unwrap (SCP session -> raw key component)
// ---------------------------------------------------------------------------

/// Unwrap a 16-byte 3DES key component using 3DES-ECB and the session DEK.
///
/// Used for PUT KEY under SCP01 or SCP02 sessions per
/// GP 2.3.1 § 11.8.2.3.1. The 16-byte ciphertext is split into two
/// independent 8-byte ECB blocks; chaining is *not* applied.
#[must_use]
pub fn unwrap_3des_ecb(session_dek: &[u8; 16], wrapped: [u8; 16]) -> [u8; 16] {
    let dek = Secret::new(*session_dek);
    let mut hi = [0u8; 8];
    let mut lo = [0u8; 8];
    hi.copy_from_slice(&wrapped[0..8]);
    lo.copy_from_slice(&wrapped[8..16]);
    let pt_hi = des3_2key_ecb_decrypt(&dek, &hi);
    let pt_lo = des3_2key_ecb_decrypt(&dek, &lo);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&pt_hi);
    out[8..16].copy_from_slice(&pt_lo);
    out
}

/// Unwrap a 16-byte AES key component using AES-CBC with zero IV and
/// the static DEK.
///
/// Used for PUT KEY under SCP03 per GP 2.3.1 Amendment D § 4.2.4.1.1.
/// AES-CBC with a zero IV degenerates to AES-ECB for a single 16-byte
/// block, but the spec calls out CBC, so we stay faithful.
#[must_use]
pub fn unwrap_aes_cbc(static_dek: &[u8; 16], wrapped: [u8; 16]) -> [u8; 16] {
    let dek = Secret::new(*static_dek);
    // GP 2.3.1 Amendment D § 4.2.4.1.1: PUT KEY component unwrap under
    // SCP03 uses AES-CBC with `IV = [0u8; 16]`. The all-zero IV is
    // spec-mandated, not a secret -- CodeQL false positive on
    // `rust/hard-coded-cryptographic-value`.
    let iv = [0u8; 16];
    let mut buf = wrapped;
    aes128_cbc_decrypt(&dek, &iv, &mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Key Check Values (KCVs)
// ---------------------------------------------------------------------------

/// Compute the 3-byte Key Check Value for a 3DES key per
/// GP 2.3.1 Appendix B.4: `first 3 bytes of 3DES_ECB(key, [0u8; 8])`.
#[must_use]
pub fn kcv_3des(key: &[u8; 16]) -> [u8; 3] {
    let secret = Secret::new(*key);
    let block = des3_2key_ecb_encrypt(&secret, &[0u8; 8]);
    [block[0], block[1], block[2]]
}

/// Compute the 3-byte Key Check Value for an AES-128 key per
/// GP 2.3.1 Amendment D § B.2: `first 3 bytes of AES_ECB(key, [0x01u8; 16])`.
#[must_use]
pub const fn kcv_aes_128(key: &[u8; 16]) -> [u8; 3] {
    let secret = Secret::new(*key);
    let cipher = Rijndael::new(&secret);
    let block = cipher.encrypt(&[0x01u8; 16]);
    [block[0], block[1], block[2]]
}

// ---------------------------------------------------------------------------
// Wrap helpers (the inverse operation; primarily for tests and tools that
// pre-encrypt PUT KEY payloads. Production cards only unwrap.)
// ---------------------------------------------------------------------------

/// Inverse of [`unwrap_3des_ecb`] -- wrap a 16-byte plaintext key under
/// 3DES-ECB using the session DEK.
#[must_use]
pub fn wrap_3des_ecb(session_dek: &[u8; 16], plaintext: [u8; 16]) -> [u8; 16] {
    let dek = Secret::new(*session_dek);
    let mut hi = [0u8; 8];
    let mut lo = [0u8; 8];
    hi.copy_from_slice(&plaintext[0..8]);
    lo.copy_from_slice(&plaintext[8..16]);
    let ct_hi = des3_2key_ecb_encrypt(&dek, &hi);
    let ct_lo = des3_2key_ecb_encrypt(&dek, &lo);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&ct_hi);
    out[8..16].copy_from_slice(&ct_lo);
    out
}

/// Inverse of [`unwrap_aes_cbc`] -- wrap a 16-byte plaintext key under
/// AES-CBC (zero IV) using the static DEK.
///
/// Symmetric with [`unwrap_aes_cbc`]: both use `aes128_cbc_*` primitives
/// with the same zero IV. For a single 16-byte block this reduces to
/// AES-ECB, but using the named CBC primitive keeps the wrap/unwrap pair
/// trivially obvious.
#[must_use]
pub fn wrap_aes_cbc(static_dek: &[u8; 16], plaintext: [u8; 16]) -> [u8; 16] {
    let dek = Secret::new(*static_dek);
    // GP 2.3.1 Amendment D § 4.2.4.1.1: PUT KEY component wrap under
    // SCP03 uses AES-CBC with `IV = [0u8; 16]`. Symmetric with
    // [`unwrap_aes_cbc`]; the all-zero IV is spec-mandated, not a
    // secret -- CodeQL false positive on
    // `rust/hard-coded-cryptographic-value`.
    let iv = [0u8; 16];
    let mut buf = plaintext;
    aes128_cbc_encrypt(&dek, &iv, &mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_3des_ecb_inverts_wrap_3des_ecb() {
        let dek = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        let plaintext = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];

        let wrapped = wrap_3des_ecb(&dek, plaintext);
        assert_ne!(
            wrapped, plaintext,
            "wrapped output must differ from plaintext (sanity)"
        );
        let unwrapped = unwrap_3des_ecb(&dek, wrapped);
        assert_eq!(unwrapped, plaintext, "unwrap(wrap(x)) must equal x");
    }

    #[test]
    fn unwrap_3des_ecb_treats_halves_independently() {
        // Each 8-byte half is decrypted independently. Construct a
        // wrapped value where the top half decrypts to one pattern and the
        // bottom half to another, distinct pattern.
        let dek = [0x40u8; 16];
        let half_a = [0xAAu8; 8];
        let half_b = [0xBBu8; 8];
        let mut plaintext = [0u8; 16];
        plaintext[0..8].copy_from_slice(&half_a);
        plaintext[8..16].copy_from_slice(&half_b);
        let wrapped = wrap_3des_ecb(&dek, plaintext);
        let unwrapped = unwrap_3des_ecb(&dek, wrapped);
        assert_eq!(&unwrapped[0..8], &half_a);
        assert_eq!(&unwrapped[8..16], &half_b);
    }

    #[test]
    fn unwrap_aes_cbc_inverts_wrap_aes_cbc() {
        let dek = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        let plaintext = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];
        let wrapped = wrap_aes_cbc(&dek, plaintext);
        assert_ne!(wrapped, plaintext);
        assert_eq!(unwrap_aes_cbc(&dek, wrapped), plaintext);
    }

    #[test]
    fn kcv_3des_is_deterministic_and_nontrivial() {
        let key = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        let kcv1 = kcv_3des(&key);
        let kcv2 = kcv_3des(&key);
        assert_eq!(kcv1, kcv2, "KCV must be deterministic");
        assert_ne!(kcv1, [0u8; 3], "KCV of non-trivial key must be non-zero");

        // KCV must equal the first 3 bytes of 3DES_ECB(key, [0u8; 8]).
        let secret = Secret::new(key);
        let block = des3_2key_ecb_encrypt(&secret, &[0u8; 8]);
        assert_eq!(kcv1, [block[0], block[1], block[2]]);
    }

    #[test]
    fn kcv_aes_128_is_deterministic_and_nontrivial() {
        let key = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        let kcv1 = kcv_aes_128(&key);
        let kcv2 = kcv_aes_128(&key);
        assert_eq!(kcv1, kcv2);
        assert_ne!(kcv1, [0u8; 3]);

        // KCV must equal the first 3 bytes of AES_ECB(key, [0x01u8; 16]).
        let secret = Secret::new(key);
        let cipher = Rijndael::new(&secret);
        let block = cipher.encrypt(&[0x01u8; 16]);
        assert_eq!(kcv1, [block[0], block[1], block[2]]);
    }

    #[test]
    fn kcv_3des_distinguishes_different_keys() {
        // DES treats bit 0 of each key byte as a parity bit and ignores it,
        // so 0x40/0x41 and 0x42/0x43 etc. are pairwise-equivalent. Pick
        // keys that differ in bits 7..1 to exercise true key distinction.
        let k1 = [0x40u8; 16];
        let k2 = [0x42u8; 16];
        assert_ne!(kcv_3des(&k1), kcv_3des(&k2));
    }

    #[test]
    fn kcv_3des_collapses_keys_that_differ_only_in_parity_bits() {
        // Documented quirk of DES: the LSB of each key byte is a parity
        // bit. Verify the KCV reflects this so callers know not to rely
        // on the parity bit for distinction.
        let k1 = [0x40u8; 16];
        let k2 = [0x41u8; 16]; // differs only in LSB of every byte
        assert_eq!(
            kcv_3des(&k1),
            kcv_3des(&k2),
            "DES ignores parity bits; keys differing only in LSB collide"
        );
    }

    #[test]
    fn kcv_aes_128_distinguishes_different_keys() {
        // AES has no parity-bit semantics so any byte difference works.
        let k1 = [0x40u8; 16];
        let k2 = [0x41u8; 16];
        assert_ne!(kcv_aes_128(&k1), kcv_aes_128(&k2));
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet Bayesian timing analysis)
//
// Run via: cargo test -p simrs-gp-scp --features ct-validation ct_validation
//
// Each test compares two execution-time distributions:
//   * class 0: all-zero (or fixed) secret input
//   * class 1: random secret input
//
// A constant-time implementation must show no statistically-detectable
// timing difference between the classes; `assert_no_timing_leak!` fails
// the test otherwise. Validates the wrappers are CT in addition to the
// underlying ciphers (which are individually validated in
// simrs-des / simrs-rijndael).
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    #[test]
    fn unwrap_3des_ecb_is_constant_time_in_dek_and_wrapped() {
        let outcome = ct_test(
            0x3DE5_EC81,
            |rng| {
                let dek = [0u8; 16];
                let mut wrapped = [0u8; 16];
                rng.fill_bytes(&mut wrapped);
                (dek, wrapped)
            },
            |rng| {
                let mut dek = [0u8; 16];
                rng.fill_bytes(&mut dek);
                let mut wrapped = [0u8; 16];
                rng.fill_bytes(&mut wrapped);
                (dek, wrapped)
            },
            |(dek, wrapped)| {
                let pt = unwrap_3des_ecb(dek, *wrapped);
                black_box(pt);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn unwrap_aes_cbc_is_constant_time_in_dek_and_wrapped() {
        let outcome = ct_test(
            0xAE5C_BC81,
            |rng| {
                let dek = [0u8; 16];
                let mut wrapped = [0u8; 16];
                rng.fill_bytes(&mut wrapped);
                (dek, wrapped)
            },
            |rng| {
                let mut dek = [0u8; 16];
                rng.fill_bytes(&mut dek);
                let mut wrapped = [0u8; 16];
                rng.fill_bytes(&mut wrapped);
                (dek, wrapped)
            },
            |(dek, wrapped)| {
                let pt = unwrap_aes_cbc(dek, *wrapped);
                black_box(pt);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn kcv_3des_is_constant_time_in_key() {
        let outcome = ct_test(
            0x3DE5_C081,
            |_rng| [0u8; 16],
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                key
            },
            |key| {
                let kcv = kcv_3des(key);
                black_box(kcv);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn kcv_aes_128_is_constant_time_in_key() {
        let outcome = ct_test(
            0xAE5C_C081,
            |_rng| [0u8; 16],
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                key
            },
            |key| {
                let kcv = kcv_aes_128(key);
                black_box(kcv);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
