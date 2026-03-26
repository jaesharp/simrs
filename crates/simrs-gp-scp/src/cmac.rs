//! Secure messaging: C-MAC generation/verification, C-ENC decryption, R-MAC.
//!
//! Implements the MAC and encryption primitives needed for `GlobalPlatform`
//! secure channel command/response protection.

use simrs_consttime::ct_eq;
use simrs_des::Des;
use simrs_iso9797::{des3_2key_cbc_encrypt, des3_2key_cbc_mac, pad_method2};
use simrs_secret::Secret;

use crate::{ScpError, ScpState, ScpVersion};

// ---------------------------------------------------------------------------
// Cryptogram computation (GP 2.1.1 Appendix D clause D.3.2 / Appendix E)
// ---------------------------------------------------------------------------

/// Compute a cryptogram using full 3DES CBC-MAC with Method 2 padding.
///
/// For SCP01:
/// - Card cryptogram input: `host_challenge || card_challenge`
/// - Host cryptogram input: `card_challenge || host_challenge`
///
/// For SCP02:
/// - Card cryptogram input: `host_challenge || seq_counter[2] || card_challenge[6]`
/// - Host cryptogram input: `seq_counter[2] || card_challenge[6] || host_challenge`
///
/// The cryptogram is the last 8 bytes of the CBC-MAC (which for 3DES CBC-MAC
/// is the single 8-byte output).
pub fn compute_cryptogram(session_enc: &[u8; 16], data: &[u8]) -> [u8; 8] {
    let secret_key = Secret::new(*session_enc);
    let mut padded = [0u8; 48]; // max possible: 24 bytes data + 8 bytes padding
    let padded_len = pad_method2(data, 8, &mut padded);
    des3_2key_cbc_mac(&secret_key, &padded[..padded_len])
}

// ---------------------------------------------------------------------------
// Full 3DES CBC-MAC with custom IV (for C-MAC chaining)
// ---------------------------------------------------------------------------

/// Compute full 3DES CBC-MAC with a custom IV.
///
/// This is equivalent to 3DES-CBC-encrypting the data and taking the last
/// 8-byte block. Used for C-MAC generation with ICV chaining.
pub fn des3_2key_cbc_mac_with_iv(key: &Secret<[u8; 16]>, iv: [u8; 8], data: &[u8]) -> [u8; 8] {
    // CBC encrypt the data and return the final block.
    let mut buf = [0u8; 272]; // max APDU + padding
    let len = data.len();
    buf[..len].copy_from_slice(data);
    des3_2key_cbc_encrypt(key, &iv, &mut buf[..len]);
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&buf[len - 8..len]);
    mac
}

// ---------------------------------------------------------------------------
// Single-DES ECB encrypt (for SCP02 ICV encryption)
// ---------------------------------------------------------------------------

/// Encrypt an 8-byte block with single DES ECB using the left half of a
/// 16-byte key. Used for SCP02 ICV encryption per Appendix E clause E.4.4.
pub fn des_ecb_encrypt_left_half(key16: &[u8; 16], block: [u8; 8]) -> [u8; 8] {
    let mut key8 = [0u8; 8];
    key8.copy_from_slice(&key16[..8]);
    let secret_key = Secret::new(key8);
    let des = Des::new(&secret_key);
    des.encrypt(&block)
}

// ---------------------------------------------------------------------------
// Public API -- C-MAC generation (host side / testing)
// ---------------------------------------------------------------------------

/// Generate a C-MAC for a command APDU.
///
/// This function is used by the host side (or tests) to compute the C-MAC
/// that the card will verify. It modifies the CLA byte (sets bit 3) and
/// adjusts Lc to include the MAC, then returns the 8-byte MAC.
///
/// # Arguments
///
/// - `session_mac` -- session C-MAC key
/// - `apdu_header` -- 4 bytes: CLA, INS, P1, P2
/// - `data` -- command data (without MAC)
/// - `icv` -- initial chaining value (zeros for first command in SCP01;
///   previous MAC for SCP02 chaining)
/// - `scp_version` -- SCP01 or SCP02 (affects ICV handling)
///
/// Returns `(mac, new_icv)` -- the 8-byte MAC and the new ICV for chaining.
#[allow(clippy::missing_panics_doc)]
pub fn generate_cmac(
    session_mac: &[u8; 16],
    apdu_header: &[u8; 4],
    data: &[u8],
    icv: &[u8; 8],
    scp_version: ScpVersion,
) -> ([u8; 8], [u8; 8]) {
    let cmac_key = Secret::new(*session_mac);

    // Build MAC input: modified CLA || INS || P1 || P2 || new_Lc || data
    let new_lc = data.len() + 8; // original data + 8-byte MAC
    let mut cmac_input = [0u8; 272];
    cmac_input[0] = apdu_header[0] | 0x04; // set secure messaging bit
    cmac_input[1] = apdu_header[1];
    cmac_input[2] = apdu_header[2];
    cmac_input[3] = apdu_header[3];
    #[allow(clippy::cast_possible_truncation)]
    {
        cmac_input[4] = new_lc as u8;
    }
    cmac_input[5..5 + data.len()].copy_from_slice(data);
    let input_len = 5 + data.len();

    let mut padded = [0u8; 280];
    let padded_len = pad_method2(&cmac_input[..input_len], 8, &mut padded);

    let effective_icv = match scp_version {
        ScpVersion::Scp01 => *icv, // SCP01: use ICV as-is (always zeros)
        ScpVersion::Scp02 => {
            // SCP02: encrypt ICV with single-DES ECB (left half of session MAC key)
            des_ecb_encrypt_left_half(session_mac, *icv)
        }
        ScpVersion::Scp03 => {
            // SCP03 uses AES-CMAC; use scp03_generate_cmac() instead.
            panic!("generate_cmac called with SCP03; use scp03_generate_cmac");
        }
    };

    let mac = des3_2key_cbc_mac_with_iv(&cmac_key, effective_icv, &padded[..padded_len]);
    (mac, mac)
}

// ---------------------------------------------------------------------------
// Public API -- unwrap_command (C-MAC verification / C-ENC decryption)
// ---------------------------------------------------------------------------

/// Verify C-MAC on an incoming command and optionally decrypt the data field.
///
/// Returns the unwrapped command data length (MAC stripped, data decrypted if
/// C-ENC is active). The unwrapped data is written to `output`.
///
/// # Errors
///
/// - [`ScpError::InvalidState`] if not in `Authenticated` state
/// - [`ScpError::InvalidApdu`] if APDU is too short
/// - [`ScpError::SecureMessagingMissing`] if C-MAC required but CLA bit 3 not set
/// - [`ScpError::CmacMismatch`] if MAC verification fails
/// - [`ScpError::BufferTooSmall`] if output buffer is too small
pub fn unwrap_command(
    state: &mut ScpState,
    apdu: &[u8],
    output: &mut [u8],
) -> Result<usize, ScpError> {
    let (session_enc, session_mac, security_level, current_icv8, scp_version) = match state {
        ScpState::Authenticated {
            session_enc,
            session_mac,
            security_level,
            icv,
            scp_version,
            ..
        } => {
            let mut icv8 = [0u8; 8];
            icv8.copy_from_slice(&icv[0..8]);
            (
                *session_enc,
                *session_mac,
                *security_level,
                icv8,
                *scp_version,
            )
        }
        _ => return Err(ScpError::InvalidState),
    };

    // Need C-MAC?
    let cmac_required = security_level & 0x01 != 0;

    if apdu.len() < 5 {
        return Err(ScpError::InvalidApdu);
    }

    let cla = apdu[0];

    // Check if secure messaging bit is set in CLA.
    if cmac_required && (cla & 0x04) == 0 {
        return Err(ScpError::SecureMessagingMissing);
    }

    // If no C-MAC required, pass through.
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

    // C-MAC is in the last 8 bytes of the data field.
    let lc = apdu[4] as usize;
    if apdu.len() < 5 + lc || lc < 8 {
        return Err(ScpError::InvalidApdu);
    }

    let data_end = 5 + lc - 8;
    let received_cmac = &apdu[data_end..data_end + 8];

    // Compute expected C-MAC.
    // MAC input: modified header (CLA with bit 3 set, original Lc) || data (without MAC).
    let mut cmac_input = [0u8; 272];
    cmac_input[0] = cla | 0x04; // ensure bit 3 set
    cmac_input[1] = apdu[1]; // INS
    cmac_input[2] = apdu[2]; // P1
    cmac_input[3] = apdu[3]; // P2
    cmac_input[4] = apdu[4]; // Lc (includes MAC length)
    let header_plus_data_len = 5 + lc - 8;
    if header_plus_data_len > 5 {
        cmac_input[5..header_plus_data_len].copy_from_slice(&apdu[5..data_end]);
    }

    let mut padded = [0u8; 280];
    let padded_len = pad_method2(&cmac_input[..header_plus_data_len], 8, &mut padded);

    let cmac_key = Secret::new(session_mac);

    // ICV handling depends on SCP version.
    // SCP03 is handled separately in scp03::scp03_unwrap_command.
    let effective_icv = match scp_version {
        ScpVersion::Scp01 => [0u8; 8], // SCP01: ICV is always zeros
        ScpVersion::Scp02 => {
            // SCP02: ICV is encrypted with single-DES ECB (left half of session MAC key)
            des_ecb_encrypt_left_half(&session_mac, current_icv8)
        }
        ScpVersion::Scp03 => {
            // SCP03 should not reach this code path; handled by scp03_unwrap_command.
            return Err(ScpError::InvalidState);
        }
    };

    let expected_cmac = des3_2key_cbc_mac_with_iv(&cmac_key, effective_icv, &padded[..padded_len]);

    if !ct_eq(received_cmac, &expected_cmac).into_bool() {
        return Err(ScpError::CmacMismatch);
    }

    // Update ICV for next command (SCP01/02: store 8-byte MAC in first 8 bytes).
    if let ScpState::Authenticated { icv, .. } = state {
        icv[0..8].copy_from_slice(&expected_cmac);
        icv[8..16].fill(0);
    }

    // Extract data (strip MAC).
    let original_data_len = lc - 8;

    // Common: copy data to output.
    if output.len() < original_data_len {
        return Err(ScpError::BufferTooSmall);
    }
    output[..original_data_len].copy_from_slice(&apdu[5..5 + original_data_len]);

    // C-ENC decryption if security level has bit 1 set.
    let cenc_active = security_level & 0x02 != 0;

    if cenc_active && original_data_len > 0 {
        let enc_key = Secret::new(session_enc);
        let enc_iv = match scp_version {
            ScpVersion::Scp01 => [0u8; 8],
            ScpVersion::Scp02 => {
                // IV for C-ENC = DES_ECB(`session_ENC` left half, ICV used for this cmd)
                des_ecb_encrypt_left_half(&session_enc, effective_icv)
            }
            ScpVersion::Scp03 => {
                // SCP03 C-ENC handled in scp03 module.
                return Err(ScpError::InvalidState);
            }
        };

        simrs_iso9797::des3_2key_cbc_decrypt(&enc_key, &enc_iv, &mut output[..original_data_len]);

        // Remove Method 2 padding from decrypted data.
        let unpadded_len = unpad_method2(&output[..original_data_len]);
        Ok(unpadded_len)
    } else {
        Ok(original_data_len)
    }
}

// ---------------------------------------------------------------------------
// Public API -- wrap_response (R-MAC)
// ---------------------------------------------------------------------------

/// Apply R-MAC to a response (SCP02 only, when R-MAC session is active).
///
/// If R-MAC is not active, copies response data and status words to output
/// unchanged. Otherwise, appends an 8-byte R-MAC.
///
/// Returns the number of bytes written to `output`.
pub fn wrap_response(
    state: &mut ScpState,
    response_data: &[u8],
    sw1: u8,
    sw2: u8,
    output: &mut [u8],
) -> usize {
    let (sess_rmac, is_rmac_active, current_icv8) = if let ScpState::Authenticated {
        session_rmac,
        rmac_active,
        icv,
        ..
    } = state
    {
        let mut icv8 = [0u8; 8];
        icv8.copy_from_slice(&icv[0..8]);
        (*session_rmac, *rmac_active, icv8)
    } else {
        // Not authenticated: pass through.
        let total = response_data.len() + 2;
        output[..response_data.len()].copy_from_slice(response_data);
        output[response_data.len()] = sw1;
        output[response_data.len() + 1] = sw2;
        return total;
    };

    if !is_rmac_active {
        let total = response_data.len() + 2;
        output[..response_data.len()].copy_from_slice(response_data);
        output[response_data.len()] = sw1;
        output[response_data.len() + 1] = sw2;
        return total;
    }

    // R-MAC = MAC(`session_R-MAC`, response_data || SW1 || SW2)
    // with Method 2 padding and ICV chaining.
    let mut rmac_data = [0u8; 272];
    let data_len = response_data.len() + 2;
    rmac_data[..response_data.len()].copy_from_slice(response_data);
    rmac_data[response_data.len()] = sw1;
    rmac_data[response_data.len() + 1] = sw2;

    let mut padded = [0u8; 280];
    let padded_len = pad_method2(&rmac_data[..data_len], 8, &mut padded);

    let rmac_key = Secret::new(sess_rmac);
    let rmac = des3_2key_cbc_mac_with_iv(&rmac_key, current_icv8, &padded[..padded_len]);

    // Output: response_data || R-MAC || SW1 || SW2
    let total = response_data.len() + 8 + 2;
    output[..response_data.len()].copy_from_slice(response_data);
    output[response_data.len()..response_data.len() + 8].copy_from_slice(&rmac);
    output[response_data.len() + 8] = sw1;
    output[response_data.len() + 9] = sw2;
    total
}

// ---------------------------------------------------------------------------
// Utility -- unpad Method 2
// ---------------------------------------------------------------------------

/// Remove ISO 9797-1 Method 2 padding. Returns the unpadded data length.
pub fn unpad_method2(data: &[u8]) -> usize {
    // Search backwards for 0x80.
    let mut i = data.len();
    while i > 0 {
        i -= 1;
        if data[i] == 0x80 {
            return i;
        }
        if data[i] != 0x00 {
            // Invalid padding -- return full length.
            return data.len();
        }
    }
    0
}
