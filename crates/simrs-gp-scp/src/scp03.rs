//! SCP03-specific key derivation, cryptogram computation, and secure messaging.
//!
//! GP Card Specification v2.3.1 Amendment D (SCP03).
//!
//! All functions are `no_std`/`no_alloc`. The only new crypto primitive is
//! `aes_cmac` from `simrs-iso9797` (RFC 4493).

use simrs_consttime::ct_eq;
use simrs_iso9797::{aes_cmac, aes128_cbc_decrypt, aes128_cbc_encrypt, pad_method2};
use simrs_rijndael::Rijndael;
use simrs_secret::Secret;

use crate::ScpError;

// ---------------------------------------------------------------------------
// Constants (Amendment D Section 6.2.2)
// ---------------------------------------------------------------------------

/// KDF label: card cryptogram derivation.
const DERIV_CARD_CRYPTO: u8 = 0x00;
/// KDF label: host cryptogram derivation.
const DERIV_HOST_CRYPTO: u8 = 0x01;
/// KDF label: session encryption key.
const DERIV_S_ENC: u8 = 0x04;
/// KDF label: session MAC key.
const DERIV_S_MAC: u8 = 0x06;
/// KDF label: session response MAC key.
const DERIV_S_RMAC: u8 = 0x07;

// ---------------------------------------------------------------------------
// KDF (Amendment D Section 6.2.2)
// ---------------------------------------------------------------------------

/// SCP03 Key Derivation Function using AES-CMAC.
///
/// Derivation data (32 bytes):
/// ```text
/// [0x00]*11 || label(1) || separation(1) || L(2) || counter(1) || context(16)
/// ```
#[allow(clippy::cast_possible_truncation)]
fn kdf(
    static_key: &[u8; 16],
    label: u8,
    separation: u8,
    key_length_bits: u16,
    context: &[u8; 16],
) -> [u8; 16] {
    let mut dd = [0u8; 32];
    // Bytes 0..11: zero
    dd[11] = label;
    dd[12] = separation;
    dd[13] = (key_length_bits >> 8) as u8;
    dd[14] = key_length_bits as u8;
    dd[15] = 0x01; // counter = 1 (we only derive 128 bits)
    dd[16..32].copy_from_slice(context);

    let key = Secret::new(*static_key);
    aes_cmac(&key, &dd)
}

/// Build the derivation data context block for cryptogram computation.
///
/// For cryptograms, context = `host_challenge(8) || card_challenge(8)`.
fn cryptogram_dd(label: u8, context: &[u8; 16]) -> [u8; 32] {
    let mut dd = [0u8; 32];
    dd[11] = label;
    dd[12] = 0x00; // separation = 0
    dd[13] = 0x00;
    dd[14] = 0x40; // L = 64 bits (8-byte truncated output)
    dd[15] = 0x01; // counter = 1
    dd[16..32].copy_from_slice(context);
    dd
}

// ---------------------------------------------------------------------------
// Session key derivation
// ---------------------------------------------------------------------------

/// Derive SCP03 session keys from static key material and challenges.
///
/// Returns `(s_enc, command_mac, response_mac)`.
///
/// Per Amendment D Section 6.2.2:
/// - S-ENC derived from `static_enc` with label 0x04
/// - S-MAC derived from `static_mac` with label 0x06
/// - S-RMAC derived from `static_mac` with label 0x07
///
/// Context = `host_challenge(8) || card_challenge(8)`.
pub fn derive_session_keys(
    static_enc: &[u8; 16],
    static_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> ([u8; 16], [u8; 16], [u8; 16]) {
    let mut context = [0u8; 16];
    context[..8].copy_from_slice(host_challenge);
    context[8..16].copy_from_slice(card_challenge);

    let s_enc = kdf(static_enc, DERIV_S_ENC, 0x00, 128, &context);
    let command_mac = kdf(static_mac, DERIV_S_MAC, 0x00, 128, &context);
    let response_mac = kdf(static_mac, DERIV_S_RMAC, 0x00, 128, &context);

    (s_enc, command_mac, response_mac)
}

// ---------------------------------------------------------------------------
// Cryptogram computation
// ---------------------------------------------------------------------------

/// Compute the SCP03 card cryptogram (8 bytes, truncated from 16).
///
/// `card_cryptogram = first_8(AES-CMAC(S-MAC, derivation_data))`
///
/// Where `derivation_data` uses label `DERIV_CARD_CRYPTO` (0x00) and L=64 bits.
/// Context = `host_challenge(8) || card_challenge(8)`.
pub fn compute_card_cryptogram(
    command_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    let mut context = [0u8; 16];
    context[..8].copy_from_slice(host_challenge);
    context[8..16].copy_from_slice(card_challenge);

    let dd = cryptogram_dd(DERIV_CARD_CRYPTO, &context);
    let key = Secret::new(*command_mac);
    let mac = aes_cmac(&key, &dd);
    let mut result = [0u8; 8];
    result.copy_from_slice(&mac[..8]);
    result
}

/// Compute the SCP03 host cryptogram (8 bytes, truncated from 16).
///
/// Same as card cryptogram but with label `DERIV_HOST_CRYPTO` (0x01).
pub fn compute_host_cryptogram(
    command_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    let mut context = [0u8; 16];
    context[..8].copy_from_slice(host_challenge);
    context[8..16].copy_from_slice(card_challenge);

    let dd = cryptogram_dd(DERIV_HOST_CRYPTO, &context);
    let key = Secret::new(*command_mac);
    let mac = aes_cmac(&key, &dd);
    let mut result = [0u8; 8];
    result.copy_from_slice(&mac[..8]);
    result
}

// ---------------------------------------------------------------------------
// C-MAC generation (host side / testing)
// ---------------------------------------------------------------------------

/// Compute SCP03 C-MAC for a command APDU.
///
/// MAC input: `chaining_value(16) || CLA(with SM bit) || INS || P1 || P2
///             || Lc(adjusted) || data`.
///
/// Returns `(8-byte wire MAC, 16-byte new chaining value)`.
/// The full 16-byte AES-CMAC output becomes the chaining value for the next command.
#[allow(clippy::cast_possible_truncation)]
pub fn generate_cmac(
    command_mac: &[u8; 16],
    mac_chaining_value: &[u8; 16],
    apdu_header: &[u8; 4],
    data: &[u8],
) -> ([u8; 8], [u8; 16]) {
    // MAC input: chaining_value || CLA(|0x04) || INS || P1 || P2 || Lc || data
    let new_lc = data.len() + 8; // data + 8-byte MAC
    let input_len = 16 + 5 + data.len();
    let mut input = [0u8; 288];
    input[..16].copy_from_slice(mac_chaining_value);
    input[16] = apdu_header[0] | 0x04; // set SM bit
    input[17] = apdu_header[1];
    input[18] = apdu_header[2];
    input[19] = apdu_header[3];
    input[20] = new_lc as u8;
    input[21..21 + data.len()].copy_from_slice(data);

    let key = Secret::new(*command_mac);
    let full_mac = aes_cmac(&key, &input[..input_len]);
    let mut mac8 = [0u8; 8];
    mac8.copy_from_slice(&full_mac[..8]);
    (mac8, full_mac)
}

// ---------------------------------------------------------------------------
// C-ENC IV derivation
// ---------------------------------------------------------------------------

/// Compute the SCP03 C-ENC initialization vector for a given counter.
///
/// `IV = AES_ECB(S-ENC, counter_block)`
///
/// Where `counter_block` is a 16-byte big-endian representation of `counter`
/// with the high bit of byte 0 set to 1 (to distinguish from MAC chaining).
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn cenc_iv(s_enc: &[u8; 16], enc_counter: u16) -> [u8; 16] {
    let mut counter_block = [0u8; 16];
    // Per Amendment D: counter in big-endian, top bit set for C-ENC.
    // The counter occupies the rightmost bytes; bit 128 is set.
    counter_block[0] = 0x80; // distinguish from MAC
    counter_block[14] = (enc_counter >> 8) as u8;
    counter_block[15] = enc_counter as u8;

    let key = Secret::new(*s_enc);
    let rij = Rijndael::new(&key);
    rij.encrypt(&counter_block)
}

// ---------------------------------------------------------------------------
// C-MAC verification + C-ENC decryption (card side)
// ---------------------------------------------------------------------------

/// Verify SCP03 C-MAC on an incoming command and optionally decrypt C-ENC.
///
/// Returns the unwrapped data length on success.
#[allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]
pub fn unwrap_command(
    session_enc: &[u8; 16],
    command_mac: &[u8; 16],
    security_level: u8,
    mac_chaining_value: &mut [u8; 16],
    enc_counter: &mut u16,
    apdu: &[u8],
    output: &mut [u8],
) -> Result<usize, ScpError> {
    let cmac_required = security_level & 0x01 != 0;

    if apdu.len() < 5 {
        return Err(ScpError::InvalidApdu);
    }

    let cla = apdu[0];

    if cmac_required && (cla & 0x04) == 0 {
        return Err(ScpError::SecureMessagingMissing);
    }

    if !cmac_required {
        let data_len = if apdu.len() > 5 { apdu.len() - 5 } else { 0 };
        if output.len() < data_len {
            return Err(ScpError::BufferTooSmall);
        }
        if data_len > 0 {
            output[..data_len].copy_from_slice(&apdu[5..5 + data_len]);
        }
        return Ok(data_len);
    }

    // C-MAC is last 8 bytes of data field.
    let lc = apdu[4] as usize;
    if apdu.len() < 5 + lc || lc < 8 {
        return Err(ScpError::InvalidApdu);
    }

    let data_end = 5 + lc - 8;
    let received_mac = &apdu[data_end..data_end + 8];

    // Compute expected C-MAC.
    // Input: chaining_value(16) || CLA(|0x04) || INS || P1 || P2 || Lc || data(without MAC)
    let input_len = 16 + 5 + (lc - 8);
    let mut mac_input = [0u8; 288];
    mac_input[..16].copy_from_slice(mac_chaining_value);
    mac_input[16] = cla | 0x04;
    mac_input[17] = apdu[1];
    mac_input[18] = apdu[2];
    mac_input[19] = apdu[3];
    mac_input[20] = apdu[4]; // Lc includes MAC
    if data_end > 5 {
        mac_input[21..21 + (data_end - 5)].copy_from_slice(&apdu[5..data_end]);
    }

    let key = Secret::new(*command_mac);
    let expected_full = aes_cmac(&key, &mac_input[..input_len]);

    if !ct_eq(received_mac, &expected_full[..8]).into_bool() {
        return Err(ScpError::CmacMismatch);
    }

    // Update chaining value (full 16-byte MAC).
    *mac_chaining_value = expected_full;

    let original_data_len = lc - 8;

    if output.len() < original_data_len {
        return Err(ScpError::BufferTooSmall);
    }
    output[..original_data_len].copy_from_slice(&apdu[5..5 + original_data_len]);

    // C-ENC decryption if security level bit 1 set.
    let cenc_active = security_level & 0x02 != 0;

    if cenc_active && original_data_len > 0 {
        *enc_counter = enc_counter.wrapping_add(1);
        let iv = cenc_iv(session_enc, *enc_counter);
        let enc_key = Secret::new(*session_enc);
        aes128_cbc_decrypt(&enc_key, &iv, &mut output[..original_data_len]);

        // Remove Method 2 padding.
        let unpadded = unpad_method2(&output[..original_data_len]);
        Ok(unpadded)
    } else {
        Ok(original_data_len)
    }
}

// ---------------------------------------------------------------------------
// R-MAC (and optional R-ENC) for responses
// ---------------------------------------------------------------------------

/// Apply SCP03 R-MAC (and optionally R-ENC) to a response per
/// GP 2.3.1 Amendment D § 6.2.7.
///
/// Returns the number of bytes written to `output`.
#[allow(clippy::cast_possible_truncation, clippy::too_many_arguments)]
pub fn wrap_response(
    response_mac: &[u8; 16],
    session_enc: &[u8; 16],
    security_level: u8,
    mac_chaining_value: &[u8; 16],
    response_data: &[u8],
    sw1: u8,
    sw2: u8,
    output: &mut [u8],
) -> usize {
    let rmac_active = security_level & 0x10 != 0;
    let renc_active = security_level & 0x20 != 0;

    if !rmac_active {
        let total = response_data.len() + 2;
        output[..response_data.len()].copy_from_slice(response_data);
        output[response_data.len()] = sw1;
        output[response_data.len() + 1] = sw2;
        return total;
    }

    // Optional R-ENC: encrypt response data with AES-CBC.
    let enc_data_len = if renc_active && !response_data.is_empty() {
        // Pad to 16-byte boundary, encrypt.
        let mut padded = [0u8; 272];
        let padded_len = pad_method2(response_data, 16, &mut padded);
        let iv = [0u8; 16]; // R-ENC IV is zero for SCP03
        let enc_key = Secret::new(*session_enc);
        aes128_cbc_encrypt(&enc_key, &iv, &mut padded[..padded_len]);
        output[..padded_len].copy_from_slice(&padded[..padded_len]);
        padded_len
    } else {
        output[..response_data.len()].copy_from_slice(response_data);
        response_data.len()
    };

    // R-MAC = AES-CMAC(S-RMAC, chaining_value || response_data || SW1 || SW2)
    let rmac_input_len = 16 + enc_data_len + 2;
    let mut rmac_input = [0u8; 288];
    rmac_input[..16].copy_from_slice(mac_chaining_value);
    rmac_input[16..16 + enc_data_len].copy_from_slice(&output[..enc_data_len]);
    rmac_input[16 + enc_data_len] = sw1;
    rmac_input[16 + enc_data_len + 1] = sw2;

    let rmac_key = Secret::new(*response_mac);
    let full_rmac = aes_cmac(&rmac_key, &rmac_input[..rmac_input_len]);

    // Output: response_data || R-MAC(8) || SW1 || SW2
    let rmac_start = enc_data_len;
    output[rmac_start..rmac_start + 8].copy_from_slice(&full_rmac[..8]);
    output[rmac_start + 8] = sw1;
    output[rmac_start + 9] = sw2;
    enc_data_len + 10
}

// ---------------------------------------------------------------------------
// INIT UPDATE Response Parser
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
pub fn parse_init_update(data: &[u8]) -> Option<Scp03InitUpdateResponse> {
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
// Utility
// ---------------------------------------------------------------------------

/// Remove ISO 9797-1 Method 2 padding from decrypted data.
const fn unpad_method2(data: &[u8]) -> usize {
    let mut i = data.len();
    while i > 0 {
        i -= 1;
        if data[i] == 0x80 {
            return i;
        }
        if data[i] != 0x00 {
            return data.len();
        }
    }
    0
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
    fn scp03_derive_session_keys_ct() {
        let outcome = ct_test(
            0x5C_03D90,
            |rng| {
                let static_enc = [0u8; 16];
                let static_mac = [0u8; 16];
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (static_enc, static_mac, hc, cc)
            },
            |rng| {
                let mut static_enc = [0u8; 16];
                rng.fill_bytes(&mut static_enc);
                let mut static_mac = [0u8; 16];
                rng.fill_bytes(&mut static_mac);
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (static_enc, static_mac, hc, cc)
            },
            |(static_enc, static_mac, hc, cc)| {
                let keys = derive_session_keys(static_enc, static_mac, hc, cc);
                black_box(keys);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn scp03_compute_host_cryptogram_ct() {
        let outcome = ct_test(
            0x5C03_C9A1,
            |rng| {
                let command_mac = [0u8; 16];
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (command_mac, hc, cc)
            },
            |rng| {
                let mut command_mac = [0u8; 16];
                rng.fill_bytes(&mut command_mac);
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (command_mac, hc, cc)
            },
            |(command_mac, hc, cc)| {
                let crypto = compute_host_cryptogram(command_mac, hc, cc);
                black_box(crypto);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn scp03_compute_card_cryptogram_ct() {
        let outcome = ct_test(
            0x5C_03C90,
            |rng| {
                let command_mac = [0u8; 16];
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (command_mac, hc, cc)
            },
            |rng| {
                let mut command_mac = [0u8; 16];
                rng.fill_bytes(&mut command_mac);
                let mut hc = [0u8; 8];
                rng.fill_bytes(&mut hc);
                let mut cc = [0u8; 8];
                rng.fill_bytes(&mut cc);
                (command_mac, hc, cc)
            },
            |(command_mac, hc, cc)| {
                let crypto = compute_card_cryptogram(command_mac, hc, cc);
                black_box(crypto);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Build a properly-AES-CMAC'd SCP03 command APDU for the given session
    /// keys, chaining value, header, and payload. Returns `(apdu, total_len)`.
    fn build_authenticated_scp03_apdu(
        command_mac: &[u8; 16],
        chaining_value: &[u8; 16],
        header: [u8; 4],
        data: &[u8],
    ) -> ([u8; 32], usize) {
        let mut mac_input = [0u8; 32];
        mac_input[..16].copy_from_slice(chaining_value);
        mac_input[16] = header[0] | 0x04;
        mac_input[17] = header[1];
        mac_input[18] = header[2];
        mac_input[19] = header[3];
        #[allow(clippy::cast_possible_truncation)]
        {
            mac_input[20] = (data.len() + 8) as u8;
        }
        mac_input[21..21 + data.len()].copy_from_slice(data);
        let input_len = 21 + data.len();
        let key = Secret::new(*command_mac);
        let full_mac = aes_cmac(&key, &mac_input[..input_len]);
        let mut apdu = [0u8; 32];
        apdu[0] = header[0] | 0x04;
        apdu[1] = header[1];
        apdu[2] = header[2];
        apdu[3] = header[3];
        #[allow(clippy::cast_possible_truncation)]
        {
            apdu[4] = (data.len() + 8) as u8;
        }
        apdu[5..5 + data.len()].copy_from_slice(data);
        apdu[5 + data.len()..5 + data.len() + 8].copy_from_slice(&full_mac[..8]);
        (apdu, 5 + data.len() + 8)
    }

    #[test]
    fn scp03_unwrap_command_ct() {
        // Tests the SCP03 successful-MAC path. Both classes produce a
        // valid AES-CMAC'd APDU; only the session key class varies.
        let outcome = ct_test(
            0x5C03_C9A2,
            |rng| {
                let session_enc = [0u8; 16];
                let command_mac = [0u8; 16];
                let mut data = [0u8; 8];
                rng.fill_bytes(&mut data);
                (session_enc, command_mac, data)
            },
            |rng| {
                let mut session_enc = [0u8; 16];
                rng.fill_bytes(&mut session_enc);
                let mut command_mac = [0u8; 16];
                rng.fill_bytes(&mut command_mac);
                let mut data = [0u8; 8];
                rng.fill_bytes(&mut data);
                (session_enc, command_mac, data)
            },
            |(session_enc, command_mac, data)| {
                let chaining = [0u8; 16];
                let (apdu, total_len) = build_authenticated_scp03_apdu(
                    command_mac,
                    &chaining,
                    [0x80, 0xF2, 0x80, 0x00],
                    data,
                );
                let mut chain = chaining;
                let mut counter = 0u16;
                let mut output = [0u8; 32];
                let result = unwrap_command(
                    session_enc,
                    command_mac,
                    0x01, // C-MAC required
                    &mut chain,
                    &mut counter,
                    &apdu[..total_len],
                    &mut output,
                );
                let _ = black_box(result);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn scp03_generate_cmac_ct() {
        let outcome = ct_test(
            0x5C03_C9A0,
            |rng| {
                let command_mac = [0u8; 16];
                let mut data = [0u8; 8];
                rng.fill_bytes(&mut data);
                (command_mac, data)
            },
            |rng| {
                let mut command_mac = [0u8; 16];
                rng.fill_bytes(&mut command_mac);
                let mut data = [0u8; 8];
                rng.fill_bytes(&mut data);
                (command_mac, data)
            },
            |(command_mac, data)| {
                let (mac, cv) =
                    generate_cmac(command_mac, &[0u8; 16], &[0x84, 0x82, 0x01, 0x00], data);
                black_box((mac, cv));
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
