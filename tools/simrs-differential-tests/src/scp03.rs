//! SCP03 host-side implementation for differential testing.
//!
//! Provides session key derivation, cryptogram computation, and C-MAC
//! generation per GP Card Specification Amendment D (SCP03).
//!
//! Uses AES-128 via `simrs-rijndael`. This module is NOT no_std -- it's
//! test infrastructure only.

use simrs_rijndael::Rijndael;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// AES-CMAC (RFC 4493)
// ---------------------------------------------------------------------------

/// Left-shift a 16-byte block by 1 bit.
fn left_shift_1(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    out
}

/// Generate AES-CMAC subkeys K1 and K2 from the AES key.
fn cmac_subkeys(cipher: &Rijndael) -> ([u8; 16], [u8; 16]) {
    let zero = [0u8; 16];
    let l = cipher.encrypt(&zero);

    let mut k1 = left_shift_1(&l);
    if l[0] & 0x80 != 0 {
        k1[15] ^= 0x87; // Rb for 128-bit blocks
    }

    let mut k2 = left_shift_1(&k1);
    if k1[0] & 0x80 != 0 {
        k2[15] ^= 0x87;
    }

    (k1, k2)
}

/// XOR two 16-byte blocks.
fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Compute AES-CMAC over `data` using the given 16-byte key.
///
/// Returns the 16-byte MAC (full, not truncated).
pub fn aes_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let secret = Secret::new(*key);
    let cipher = Rijndael::new(&secret);
    let (k1, k2) = cmac_subkeys(&cipher);

    let n_blocks = if data.is_empty() {
        1
    } else {
        (data.len() + 15) / 16
    };

    let complete = !data.is_empty() && data.len() % 16 == 0;

    // Prepare the last block.
    let mut last_block = [0u8; 16];
    if complete {
        let start = (n_blocks - 1) * 16;
        last_block[..16].copy_from_slice(&data[start..start + 16]);
        last_block = xor_block(&last_block, &k1);
    } else {
        // Pad with 10...0
        let start = (n_blocks - 1) * 16;
        let remaining = data.len() - start;
        last_block[..remaining].copy_from_slice(&data[start..]);
        last_block[remaining] = 0x80;
        // Rest is already zero.
        last_block = xor_block(&last_block, &k2);
    }

    // CBC-MAC over all blocks.
    let mut x = [0u8; 16];
    for i in 0..n_blocks - 1 {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[i * 16..(i + 1) * 16]);
        x = xor_block(&x, &block);
        x = cipher.encrypt(&x);
    }
    x = xor_block(&x, &last_block);
    cipher.encrypt(&x)
}

// ---------------------------------------------------------------------------
// SCP03 Key Derivation Function (GP Amendment D, Section 6.2.2)
// ---------------------------------------------------------------------------

/// SCP03 derivation constants.
const DERIV_CARD_CRYPTO: u8 = 0x00;
const DERIV_HOST_CRYPTO: u8 = 0x01;
const DERIV_S_ENC: u8 = 0x04;
const DERIV_S_MAC: u8 = 0x06;
const DERIV_S_RMAC: u8 = 0x07;

/// KDF for SCP03: derives a 16-byte key using AES-CMAC.
///
/// derivation_data (32 bytes):
/// ```text
/// [0x00]*11 || label(1) || separation_indicator(1) || L(2) || counter(1) || context(16)
/// ```
///
/// where context = card_challenge(8) || host_challenge(8) for session keys,
/// or host_challenge(8) || card_challenge(8) for cryptograms.
fn kdf_scp03(
    static_key: &[u8; 16],
    label: u8,
    separation: u8,
    key_length_bits: u16,
    context: &[u8],
) -> [u8; 16] {
    // Build derivation data.
    let mut dd = [0u8; 32];
    // Bytes 0-10: zero (11 bytes)
    dd[11] = label;
    dd[12] = separation;
    dd[13] = (key_length_bits >> 8) as u8;
    dd[14] = key_length_bits as u8;
    dd[15] = 0x01; // counter = 1 (we only need 128 bits)
    let ctx_len = context.len().min(16);
    dd[16..16 + ctx_len].copy_from_slice(&context[..ctx_len]);

    aes_cmac(static_key, &dd[..16 + ctx_len])
}

/// SCP03 session keys derived from static keys and challenges.
pub struct Scp03SessionKeys {
    /// Session encryption key.
    pub s_enc: [u8; 16],
    /// Session MAC key.
    pub s_mac: [u8; 16],
    /// Session response MAC key.
    pub s_rmac: [u8; 16],
}

/// Derive SCP03 session keys from static key material and challenges.
///
/// Per GP Amendment D, Section 6.2.2.
pub fn derive_scp03_session_keys(
    static_enc: &[u8; 16],
    static_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> Scp03SessionKeys {
    // Context for session keys: host_challenge || card_challenge (GP Amendment D 6.2.1).
    let mut context = [0u8; 16];
    context[..8].copy_from_slice(host_challenge);
    context[8..16].copy_from_slice(card_challenge);

    let s_enc = kdf_scp03(static_enc, DERIV_S_ENC, 0x00, 128, &context);
    let s_mac = kdf_scp03(static_mac, DERIV_S_MAC, 0x00, 128, &context);
    let s_rmac = kdf_scp03(static_mac, DERIV_S_RMAC, 0x00, 128, &context);

    Scp03SessionKeys {
        s_enc,
        s_mac,
        s_rmac,
    }
}

/// Compute the SCP03 card cryptogram for verification.
///
/// card_cryptogram = first 8 bytes of AES-CMAC(S-MAC, host_challenge || card_challenge)
pub fn compute_scp03_card_cryptogram(
    s_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    let mut context = [0u8; 16];
    context[..8].copy_from_slice(host_challenge);
    context[8..16].copy_from_slice(card_challenge);

    let dd = build_cryptogram_dd(DERIV_CARD_CRYPTO, &context);
    let mac = aes_cmac(s_mac, &dd);
    let mut result = [0u8; 8];
    result.copy_from_slice(&mac[..8]);
    result
}

/// Compute the SCP03 host cryptogram.
///
/// host_cryptogram = first 8 bytes of AES-CMAC(S-MAC, card_challenge || host_challenge)
pub fn compute_scp03_host_cryptogram(
    s_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    let mut context = [0u8; 16];
    context[..8].copy_from_slice(host_challenge);
    context[8..16].copy_from_slice(card_challenge);

    let dd = build_cryptogram_dd(DERIV_HOST_CRYPTO, &context);
    let mac = aes_cmac(s_mac, &dd);
    let mut result = [0u8; 8];
    result.copy_from_slice(&mac[..8]);
    result
}

/// Build derivation data for cryptogram computation.
fn build_cryptogram_dd(label: u8, context: &[u8; 16]) -> [u8; 32] {
    let mut dd = [0u8; 32];
    // [0x00]*11 || label || 0x00 || L=0x0040 (64 bits) || counter=0x01 || context
    dd[11] = label;
    dd[12] = 0x00;
    dd[13] = 0x00;
    dd[14] = 0x40; // 64 bits
    dd[15] = 0x01;
    dd[16..32].copy_from_slice(context);
    dd
}

/// Compute SCP03 C-MAC for an APDU command.
///
/// mac_chaining_value is the previous MAC (or zeros for first command after EXT AUTH).
/// Returns (8-byte MAC, 16-byte new chaining value).
pub fn scp03_cmac(
    s_mac: &[u8; 16],
    mac_chaining_value: &[u8; 16],
    apdu_header: &[u8; 4],
    data: &[u8],
) -> ([u8; 8], [u8; 16]) {
    // MAC input: chaining_value || CLA(with SM bit) || INS || P1 || P2 || Lc(adjusted) || data
    let new_lc = data.len() + 8; // original data + 8-byte MAC
    let mut input = Vec::with_capacity(16 + 5 + data.len());
    input.extend_from_slice(mac_chaining_value);
    input.push(apdu_header[0] | 0x04); // set SM bit
    input.push(apdu_header[1]);
    input.push(apdu_header[2]);
    input.push(apdu_header[3]);
    #[allow(clippy::cast_possible_truncation)]
    input.push(new_lc as u8);
    input.extend_from_slice(data);

    let full_mac = aes_cmac(s_mac, &input);
    let mut mac8 = [0u8; 8];
    mac8.copy_from_slice(&full_mac[..8]);
    (mac8, full_mac)
}

// ---------------------------------------------------------------------------
// SCP03 INIT UPDATE Response Parser
// ---------------------------------------------------------------------------

/// Parsed SCP03 INITIALIZE UPDATE response.
pub struct Scp03InitUpdateResponse {
    /// Key diversification data (10 bytes).
    pub key_div: [u8; 10],
    /// Key version number.
    pub key_version: u8,
    /// SCP identifier (should be 0x03).
    pub scp_id: u8,
    /// SCP03 "i" parameter.
    pub i_param: u8,
    /// Card challenge (8 bytes).
    pub card_challenge: [u8; 8],
    /// Card cryptogram (8 bytes).
    pub card_cryptogram: [u8; 8],
    /// Sequence counter (3 bytes, present when i indicates pseudo-random challenge).
    pub sequence_counter: [u8; 3],
}

/// Parse an SCP03 INIT UPDATE response (29 or 32 bytes).
pub fn parse_scp03_init_update(data: &[u8]) -> Option<Scp03InitUpdateResponse> {
    if data.len() < 29 {
        return None;
    }

    let mut key_div = [0u8; 10];
    key_div.copy_from_slice(&data[0..10]);

    let key_version = data[10];
    let scp_id = data[11];
    let i_param = data[12];

    let mut card_challenge = [0u8; 8];
    card_challenge.copy_from_slice(&data[13..21]);

    let mut card_cryptogram = [0u8; 8];
    card_cryptogram.copy_from_slice(&data[21..29]);

    let mut sequence_counter = [0u8; 3];
    if data.len() >= 32 {
        sequence_counter.copy_from_slice(&data[29..32]);
    }

    Some(Scp03InitUpdateResponse {
        key_div,
        key_version,
        scp_id,
        i_param,
        card_challenge,
        card_cryptogram,
        sequence_counter,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_cmac_16_bytes() {
        // RFC 4493 test vector 2: key = 2b7e1516..., message = 6bc1bee2...
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let mac = aes_cmac(&key, &msg);
        // Expected: 070a16b46b4d4144f79bdd9dd04a287c
        assert_eq!(
            mac,
            [
                0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
                0x28, 0x7c
            ]
        );
    }

    #[test]
    fn session_key_derivation_produces_distinct_keys() {
        let static_enc = [0x40u8; 16];
        let static_mac = [0x40u8; 16];
        let hc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        let keys = derive_scp03_session_keys(&static_enc, &static_mac, &hc, &cc);

        assert_ne!(keys.s_enc, keys.s_mac, "S-ENC and S-MAC should differ");
        assert_ne!(keys.s_mac, keys.s_rmac, "S-MAC and S-RMAC should differ");
        assert_ne!(keys.s_enc, [0u8; 16], "S-ENC should be non-zero");
    }

    #[test]
    fn host_and_card_cryptograms_differ() {
        let s_mac = [0x40u8; 16];
        let hc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        let card_crypto = compute_scp03_card_cryptogram(&s_mac, &hc, &cc);
        let host_crypto = compute_scp03_host_cryptogram(&s_mac, &hc, &cc);

        assert_ne!(
            card_crypto, host_crypto,
            "card and host cryptograms should differ"
        );
    }
}
