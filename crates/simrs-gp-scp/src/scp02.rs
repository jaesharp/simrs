//! SCP02-specific key derivation and cryptogram computation.
//!
//! GP Card Specification v2.1.1 Appendix E.

use simrs_gp_keys::KeySet;
use simrs_iso9797::des3_2key_cbc_encrypt;
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
/// Returns `(session_enc, session_mac, session_rmac, session_dek)`.
#[allow(clippy::similar_names)]
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
