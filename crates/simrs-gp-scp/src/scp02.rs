//! SCP02-specific key derivation and cryptogram computation.
//!
//! GP Card Specification v2.1.1 Appendix E.

use simrs_gp_keys::KeySet;
use simrs_iso9797::{des3_2key_cbc_encrypt, des3_2key_ecb_encrypt};
use simrs_secret::Secret;

use crate::cmac::compute_cryptogram;

// ---------------------------------------------------------------------------
// Key derivation -- SCP02 (GP 2.1.1 Appendix E, Figure E-2)
// ---------------------------------------------------------------------------

/// Derive an SCP02 session key.
///
/// `derivation_data = constant[2] || sequence_counter[2] || 0x00[12]`
/// `session_key = 3DES_CBC(static_key, derivation_data, IV=0x00[8])`
///
/// The output is the full 16-byte ciphertext (two CBC-encrypted blocks).
pub fn scp02_derive_session_key(
    static_key: &[u8],
    constant: [u8; 2],
    sequence_counter: u16,
) -> [u8; 16] {
    let mut key16 = [0u8; 16];
    key16.copy_from_slice(&static_key[..16]);
    let secret_key = Secret::new(key16);

    let mut data = [0u8; 16];
    data[0] = constant[0];
    data[1] = constant[1];
    #[allow(clippy::cast_possible_truncation)]
    {
        data[2] = (sequence_counter >> 8) as u8;
        data[3] = sequence_counter as u8;
    }
    // bytes 4..16 are already zero.

    let iv = [0u8; 8];
    des3_2key_cbc_encrypt(&secret_key, &iv, &mut data);
    data
}

// ---------------------------------------------------------------------------
// Public helpers for testing / external use
// ---------------------------------------------------------------------------

/// Derive a single SCP02 session key with the given constant and counter.
///
/// Returns the 16-byte derived key.
pub fn derive_scp02_session_key(
    static_key: &[u8],
    constant: [u8; 2],
    sequence_counter: u16,
) -> [u8; 16] {
    scp02_derive_session_key(static_key, constant, sequence_counter)
}

/// Derive all SCP02 session keys.
///
/// Returns `(session_enc, command_mac, response_mac, session_dek)`.
pub fn derive_scp02_session_keys(
    keys: &KeySet,
    sequence_counter: u16,
) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
    let enc = scp02_derive_session_key(keys.enc(), [0x01, 0x82], sequence_counter);
    let mac = scp02_derive_session_key(keys.mac(), [0x01, 0x01], sequence_counter);
    let rmac = scp02_derive_session_key(keys.mac(), [0x01, 0x02], sequence_counter);
    let dek = scp02_derive_session_key(keys.dek(), [0x01, 0x81], sequence_counter);
    (enc, mac, rmac, dek)
}

/// Derive the 6-byte SCP02 `card_challenge` in pseudo-random mode.
///
/// Per GP 2.3.1 Appendix E.4.2.1.5: when the SCP02 `i` parameter has bit 4
/// cleared (e.g., `i = 0x05` instead of `i = 0x15`), the card does **not**
/// generate a fresh random challenge; instead it derives the challenge
/// deterministically from the persistent sequence counter using the static
/// S-ENC key:
///
/// ```text
/// input = seq_counter[2] || 0x00[6]            (8 bytes)
/// output = 3DES_ECB(static_S-ENC, input)       (8 bytes)
/// card_challenge[6] = output[2..8]             (right-most 6 bytes)
/// ```
///
/// This guarantees uniqueness (a fresh sequence counter produces a fresh
/// challenge) without requiring an on-card RNG. Real-card use cases include
/// OTA scenarios where the card must produce a deterministic challenge that
/// the OTA host has independently predicted.
///
/// The 6-byte result is returned right-aligned in an 8-byte buffer
/// (i.e., `result[0..2] == 0` and `result[2..8]` holds the challenge),
/// matching the in-state representation used elsewhere in this crate.
#[must_use]
pub fn scp02_pseudo_random_card_challenge(
    static_s_enc: &[u8; 16],
    sequence_counter: u16,
) -> [u8; 8] {
    let secret = Secret::new(*static_s_enc);
    let mut input = [0u8; 8];
    #[allow(clippy::cast_possible_truncation)]
    {
        input[0] = (sequence_counter >> 8) as u8;
        input[1] = sequence_counter as u8;
    }
    // input[2..8] = zeros (already initialised).
    let block = des3_2key_ecb_encrypt(&secret, &input);
    // Right-aligned: leading 2 bytes zero, trailing 6 bytes hold the
    // truncated challenge. Use the last 6 bytes of the cipher output.
    let mut out = [0u8; 8];
    out[2..8].copy_from_slice(&block[2..8]);
    out
}

/// Compute a card cryptogram for SCP02.
///
/// `card_cryptogram = MAC(session_ENC, host_challenge || seq_counter || card_challenge_6)`
#[allow(clippy::cast_possible_truncation)]
pub fn compute_scp02_card_cryptogram(
    session_enc: &[u8; 16],
    host_challenge: &[u8; 8],
    sequence_counter: u16,
    card_challenge_6: &[u8; 6],
) -> [u8; 8] {
    let mut input = [0u8; 16];
    input[0..8].copy_from_slice(host_challenge);
    input[8] = (sequence_counter >> 8) as u8;
    input[9] = sequence_counter as u8;
    input[10..16].copy_from_slice(card_challenge_6);
    compute_cryptogram(session_enc, &input)
}

/// Compute a host cryptogram for SCP02.
///
/// `host_cryptogram = MAC(session_ENC, seq_counter || card_challenge_6 || host_challenge)`
#[allow(clippy::cast_possible_truncation)]
pub fn compute_scp02_host_cryptogram(
    session_enc: &[u8; 16],
    host_challenge: &[u8; 8],
    sequence_counter: u16,
    card_challenge_6: &[u8; 6],
) -> [u8; 8] {
    let mut input = [0u8; 16];
    input[0] = (sequence_counter >> 8) as u8;
    input[1] = sequence_counter as u8;
    input[2..8].copy_from_slice(card_challenge_6);
    input[8..16].copy_from_slice(host_challenge);
    compute_cryptogram(session_enc, &input)
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet Bayesian timing analysis)
//
// Run via: cargo test -p simrs-gp-scp --features ct-validation ct_validation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod scp02_pseudo_random_tests {
    use super::*;

    #[test]
    fn pseudo_random_card_challenge_is_deterministic() {
        let key = [0x40u8; 16];
        let cc1 = scp02_pseudo_random_card_challenge(&key, 0x0042);
        let cc2 = scp02_pseudo_random_card_challenge(&key, 0x0042);
        assert_eq!(cc1, cc2, "same (key, seq) must produce same card_challenge");
    }

    #[test]
    fn pseudo_random_card_challenge_changes_with_sequence_counter() {
        let key = [0x40u8; 16];
        let cc1 = scp02_pseudo_random_card_challenge(&key, 0x0001);
        let cc2 = scp02_pseudo_random_card_challenge(&key, 0x0002);
        assert_ne!(
            cc1, cc2,
            "different sequence counters must produce different card_challenges"
        );
    }

    #[test]
    fn pseudo_random_card_challenge_is_right_aligned() {
        // Per the spec: leading 2 bytes are zero, trailing 6 bytes hold
        // the truncated cipher output.
        let key = [0x40u8; 16];
        let cc = scp02_pseudo_random_card_challenge(&key, 0x1234);
        assert_eq!(&cc[0..2], &[0u8; 2]);
        // The 6-byte challenge in cc[2..8] should be non-trivial.
        assert_ne!(&cc[2..8], &[0u8; 6]);
    }

    #[test]
    fn pseudo_random_card_challenge_changes_with_static_enc_key() {
        let cc1 = scp02_pseudo_random_card_challenge(&[0x40u8; 16], 0x0042);
        let cc2 = scp02_pseudo_random_card_challenge(&[0x42u8; 16], 0x0042);
        assert_ne!(
            cc1, cc2,
            "different static_S-ENC keys must produce different card_challenges"
        );
    }
}

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    #[test]
    fn scp02_pseudo_random_card_challenge_ct() {
        let outcome = ct_test(
            0x5C_02C9A,
            |_rng| ([0u8; 16], 0x4242u16),
            |rng| {
                let mut static_enc = [0u8; 16];
                rng.fill_bytes(&mut static_enc);
                let mut seq_bytes = [0u8; 2];
                rng.fill_bytes(&mut seq_bytes);
                (static_enc, u16::from_be_bytes(seq_bytes))
            },
            |(static_enc, seq)| {
                let cc = scp02_pseudo_random_card_challenge(static_enc, *seq);
                black_box(cc);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn scp02_derive_session_key_ct() {
        let outcome = ct_test(
            0x5C_02D90,
            |_rng| {
                let static_key = [0u8; 16];
                (static_key, 0x4242u16)
            },
            |rng| {
                let mut static_key = [0u8; 16];
                rng.fill_bytes(&mut static_key);
                let mut seq_bytes = [0u8; 2];
                rng.fill_bytes(&mut seq_bytes);
                let seq = u16::from_be_bytes(seq_bytes);
                (static_key, seq)
            },
            |(static_key, seq)| {
                let derived = scp02_derive_session_key(static_key, [0x01, 0x82], *seq);
                black_box(derived);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn scp02_compute_card_cryptogram_ct() {
        let outcome = ct_test(
            0x5C_02C90,
            |rng| {
                let session_enc = [0u8; 16];
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc6 = [0u8; 6];
                rng.fill_bytes(&mut cc6);
                (session_enc, hc, cc6)
            },
            |rng| {
                let mut session_enc = [0u8; 16];
                rng.fill_bytes(&mut session_enc);
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc6 = [0u8; 6];
                rng.fill_bytes(&mut cc6);
                (session_enc, hc, cc6)
            },
            |(session_enc, hc, cc6)| {
                let crypto = compute_scp02_card_cryptogram(session_enc, hc, 0x0042, cc6);
                black_box(crypto);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
