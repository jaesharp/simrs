//! SCP01-specific key derivation and cryptogram computation.
//!
//! GP Card Specification v2.1.1 Appendix D.

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
/// Returns `(session_enc, session_mac, session_dek)`.
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
