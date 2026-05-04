//! SCP01-specific key derivation and cryptogram computation.
//!
//! Spec source: GP Card Specification v2.1.1 Appendix D (figure
//! numbering verified there; GP 2.3.1 retains SCP01 in Appendix D
//! unchanged but is not independently verified here -- see crate
//! lib.rs intro).

use simrs_gp_keys::KeySet;
use simrs_iso9797::des3_2key_ecb_encrypt;
use simrs_secret::Secret;

use crate::cmac::compute_cryptogram;

// ---------------------------------------------------------------------------
// Key derivation -- SCP01 (GP 2.1.1 Appendix D, Figures D-3/D-4/D-5)
// ---------------------------------------------------------------------------

/// Build SCP01 derivation data from host and card challenges.
///
/// `derivation_data = host_challenge[4..8] || card_challenge[0..4]
///                     || host_challenge[0..4] || card_challenge[4..8]`
pub fn scp01_derivation_data(host_challenge: [u8; 8], card_challenge: [u8; 8]) -> [u8; 16] {
    let mut dd = [0u8; 16];
    dd[0..4].copy_from_slice(&host_challenge[4..8]);
    dd[4..8].copy_from_slice(&card_challenge[0..4]);
    dd[8..12].copy_from_slice(&host_challenge[0..4]);
    dd[12..16].copy_from_slice(&card_challenge[4..8]);
    dd
}

/// Derive an SCP01 session key by encrypting the derivation data with the
/// static key using 3DES ECB. The 16-byte derivation data is treated as two
/// independent 8-byte ECB blocks.
pub fn scp01_derive_session_key(static_key: &[u8], derivation_data: &[u8; 16]) -> [u8; 16] {
    let mut key16 = [0u8; 16];
    key16.copy_from_slice(&static_key[..16]);
    let secret_key = Secret::new(key16);

    let mut block_lo = [0u8; 8];
    let mut block_hi = [0u8; 8];
    block_lo.copy_from_slice(&derivation_data[0..8]);
    block_hi.copy_from_slice(&derivation_data[8..16]);

    let enc_lo = des3_2key_ecb_encrypt(&secret_key, &block_lo);
    let enc_hi = des3_2key_ecb_encrypt(&secret_key, &block_hi);

    let mut result = [0u8; 16];
    result[0..8].copy_from_slice(&enc_lo);
    result[8..16].copy_from_slice(&enc_hi);
    result
}

// ---------------------------------------------------------------------------
// Public helpers for testing / external use
// ---------------------------------------------------------------------------

/// Derive SCP01 session keys from static keys and challenges.
///
/// Returns `(session_enc, command_mac, session_dek)`.
pub fn derive_scp01_session_keys(
    keys: &KeySet,
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> ([u8; 16], [u8; 16], [u8; 16]) {
    let dd = scp01_derivation_data(*host_challenge, *card_challenge);
    let enc = scp01_derive_session_key(keys.enc(), &dd);
    let mac = scp01_derive_session_key(keys.mac(), &dd);
    let dek = scp01_derive_session_key(keys.dek(), &dd);
    (enc, mac, dek)
}

/// Compute a card cryptogram for SCP01.
///
/// `card_cryptogram = MAC(session_ENC, host_challenge || card_challenge)`
pub fn compute_scp01_card_cryptogram(
    session_enc: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    let mut input = [0u8; 16];
    input[0..8].copy_from_slice(host_challenge);
    input[8..16].copy_from_slice(card_challenge);
    compute_cryptogram(session_enc, &input)
}

/// Compute a host cryptogram for SCP01.
///
/// `host_cryptogram = MAC(session_ENC, card_challenge || host_challenge)`
pub fn compute_scp01_host_cryptogram(
    session_enc: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    let mut input = [0u8; 16];
    input[0..8].copy_from_slice(card_challenge);
    input[8..16].copy_from_slice(host_challenge);
    compute_cryptogram(session_enc, &input)
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet Bayesian timing analysis)
//
// Run via: cargo test -p simrs-gp-scp --features ct-validation ct_validation
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    #[test]
    fn scp01_derive_session_key_ct() {
        let outcome = ct_test(
            0x5C_01D90,
            |rng| {
                let static_key = [0u8; 16];
                let mut dd = [0u8; 16];
                rng.fill_bytes(&mut dd);
                (static_key, dd)
            },
            |rng| {
                let mut static_key = [0u8; 16];
                rng.fill_bytes(&mut static_key);
                let mut dd = [0u8; 16];
                rng.fill_bytes(&mut dd);
                (static_key, dd)
            },
            |(static_key, dd)| {
                let derived = scp01_derive_session_key(static_key, dd);
                black_box(derived);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn scp01_compute_card_cryptogram_ct() {
        let outcome = ct_test(
            0x5C_01C90,
            |rng| {
                let session_enc = [0u8; 16];
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (session_enc, hc, cc)
            },
            |rng| {
                let mut session_enc = [0u8; 16];
                rng.fill_bytes(&mut session_enc);
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (session_enc, hc, cc)
            },
            |(session_enc, hc, cc)| {
                let crypto = compute_scp01_card_cryptogram(session_enc, hc, cc);
                black_box(crypto);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
