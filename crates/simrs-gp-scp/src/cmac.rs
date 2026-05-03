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
///
/// **Note for static analysers:** the actual cryptographic IV is the
/// `iv` parameter, supplied by callers. The `[0u8; 8]` literal on the
/// `mac` line below is the OUTPUT buffer being stack-zeroed before
/// `copy_from_slice` fills it -- not an IV.
pub fn des3_2key_cbc_mac_with_iv(key: &Secret<[u8; 16]>, iv: [u8; 8], data: &[u8]) -> [u8; 8] {
    // CBC encrypt the data and return the final block.
    let mut buf = [0u8; 272]; // max APDU + padding
    let len = data.len();
    buf[..len].copy_from_slice(data);
    des3_2key_cbc_encrypt(key, &iv, &mut buf[..len]);
    // Output buffer (not an IV): stack-allocated, zero-initialised, then
    // overwritten by `copy_from_slice`. CodeQL `rust/hard-coded-cryptographic-value`
    // mis-tags this as a hard-coded IV via taint flow from the `iv` parameter.
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&buf[len - 8..len]);
    mac
}

/// Seed the SCP01/02 R-MAC running chain from BEGIN R-MAC SESSION's
/// optional data field per GP 2.3.1 Appendix E.6.
///
/// Returns `[0; 8]` when `data` is empty (no seeding needed).
/// Otherwise pads `data` with ISO 9797-1 Method 2 to an 8-byte boundary
/// and runs `des3_2key_cbc_mac_with_iv(response_mac, [0; 8], padded)`.
///
/// # Panics
///
/// Panics if `data.len() > 24` -- the GP-spec upper bound for the
/// BEGIN R-MAC SESSION data field. Callers ([`begin_rmac_session`] in
/// `simrs-gp-open`) enforce this before invoking; the runtime check
/// here guards against direct external misuse in release builds.
#[must_use]
pub fn seed_rmac_chain_scp02(response_mac: &[u8; 16], data: &[u8]) -> [u8; 8] {
    if data.is_empty() {
        return [0u8; 8];
    }
    assert!(
        data.len() <= 24,
        "BEGIN R-MAC SESSION data exceeds 24-byte spec limit"
    );
    let mut padded = [0u8; 32];
    let padded_len = pad_method2(data, 8, &mut padded);
    let key = Secret::new(*response_mac);
    // GP 2.3.1 Appendix E.6: the R-MAC running ICV is initialised to zero
    // and `BEGIN R-MAC SESSION` data is hashed via
    // `CBC-MAC(S-RMAC, IV = 0, Method-2-pad(data))`. The all-zero IV is
    // spec-mandated, not a secret -- CodeQL false positive on
    // `rust/hard-coded-cryptographic-value`.
    des3_2key_cbc_mac_with_iv(&key, [0u8; 8], &padded[..padded_len])
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
/// - `command_mac` -- session C-MAC key
/// - `apdu_header` -- 4 bytes: CLA, INS, P1, P2
/// - `data` -- command data (without MAC)
/// - `icv` -- initial chaining value (zeros for first command in SCP01;
///   previous MAC for SCP02 chaining)
/// - `scp_version` -- SCP01 or SCP02 (affects ICV handling)
///
/// Returns `(mac, new_icv)` -- the 8-byte MAC and the new ICV for chaining.
#[allow(clippy::missing_panics_doc)]
pub fn generate_cmac(
    command_mac: &[u8; 16],
    apdu_header: &[u8; 4],
    data: &[u8],
    icv: &[u8; 8],
    scp_version: ScpVersion,
) -> ([u8; 8], [u8; 8]) {
    let cmac_key = Secret::new(*command_mac);

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
            des_ecb_encrypt_left_half(command_mac, *icv)
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
    let (session_enc, command_mac, security_level, current_icv8, scp_version) = match state {
        ScpState::Authenticated {
            session_enc,
            command_mac,
            security_level,
            icv,
            scp_version,
            ..
        } => {
            let mut icv8 = [0u8; 8];
            icv8.copy_from_slice(&icv[0..8]);
            (
                *session_enc,
                *command_mac,
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

    let cmac_key = Secret::new(command_mac);

    // ICV handling depends on SCP version.
    // SCP03 is handled separately in scp03::scp03_unwrap_command.
    let effective_icv = match scp_version {
        ScpVersion::Scp01 => [0u8; 8], // SCP01: ICV is always zeros
        ScpVersion::Scp02 => {
            // SCP02: ICV is encrypted with single-DES ECB (left half of session MAC key)
            des_ecb_encrypt_left_half(&command_mac, current_icv8)
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

/// Apply R-MAC to a response (SCP01/02 only, when R-MAC session is active).
///
/// If R-MAC is not active, copies response data and status words to output
/// unchanged. Otherwise computes per GP 2.3.1 Appendix E.4.6.3:
///
/// ```text
/// R-MAC_n = MAC(session_R-MAC, R-MAC_ICV_n,
///               command_data || response_data || SW1 || SW2)
/// R-MAC_ICV_{n+1} = R-MAC_n
/// ```
///
/// `command_data` is the data field of the command APDU corresponding to
/// this response (post-unwrap, no C-MAC trailer); empty for case 1/2
/// commands. The R-MAC running chain is initialised to all zeros at
/// BEGIN R-MAC SESSION and updated in `state.rmac_icv` after each call.
///
/// Layout written to `output`: `response_data || R-MAC || SW1 || SW2`.
/// Returns the number of bytes written.
pub fn wrap_response(
    state: &mut ScpState,
    command_data: &[u8],
    response_data: &[u8],
    sw1: u8,
    sw2: u8,
    output: &mut [u8],
) -> usize {
    let ScpState::Authenticated {
        response_mac,
        rmac_active,
        rmac_icv,
        ..
    } = state
    else {
        // Not authenticated: pass through.
        let total = response_data.len() + 2;
        output[..response_data.len()].copy_from_slice(response_data);
        output[response_data.len()] = sw1;
        output[response_data.len() + 1] = sw2;
        return total;
    };

    if !*rmac_active {
        let total = response_data.len() + 2;
        output[..response_data.len()].copy_from_slice(response_data);
        output[response_data.len()] = sw1;
        output[response_data.len() + 1] = sw2;
        return total;
    }

    // R-MAC input = command_data || response_data || SW1 || SW2 with
    // ISO 9797-1 Method 2 padding.
    let mut rmac_data = [0u8; 528]; // up to 256 cmd + 256 rsp + 2 SW + slack
    let mut input_len = 0;
    rmac_data[input_len..input_len + command_data.len()].copy_from_slice(command_data);
    input_len += command_data.len();
    rmac_data[input_len..input_len + response_data.len()].copy_from_slice(response_data);
    input_len += response_data.len();
    rmac_data[input_len] = sw1;
    rmac_data[input_len + 1] = sw2;
    input_len += 2;

    let mut padded = [0u8; 536];
    let padded_len = pad_method2(&rmac_data[..input_len], 8, &mut padded);

    let rmac_key = Secret::new(*response_mac);
    let rmac = des3_2key_cbc_mac_with_iv(&rmac_key, *rmac_icv, &padded[..padded_len]);

    // Update the running R-MAC chain.
    *rmac_icv = rmac;

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

// ---------------------------------------------------------------------------
// Constant-time validation (tacet Bayesian timing analysis)
//
// Run via: cargo test -p simrs-gp-scp --features ct-validation ct_validation
//
// These wrappers thread session keys (SCP01/02 secret material) through
// the underlying iso9797 primitives. Each test confirms no observable
// timing dependence on the secret-key class.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
#[allow(clippy::cast_possible_truncation)]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    #[test]
    fn compute_cryptogram_ct() {
        let outcome = ct_test(
            0xC0_C09A0,
            |rng| {
                let session_enc = [0u8; 16];
                let mut data = [0u8; 16];
                rng.fill_bytes(&mut data);
                (session_enc, data)
            },
            |rng| {
                let mut session_enc = [0u8; 16];
                rng.fill_bytes(&mut session_enc);
                let mut data = [0u8; 16];
                rng.fill_bytes(&mut data);
                (session_enc, data)
            },
            |(session_enc, data)| {
                let mac = compute_cryptogram(session_enc, data);
                black_box(mac);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn des3_2key_cbc_mac_with_iv_ct() {
        let outcome = ct_test(
            0xC0_C09A1,
            |rng| {
                let key = [0u8; 16];
                let mut data = [0u8; 16];
                rng.fill_bytes(&mut data);
                (key, data)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut data = [0u8; 16];
                rng.fill_bytes(&mut data);
                (key, data)
            },
            |(key, data)| {
                let secret = Secret::new(*key);
                let mac = des3_2key_cbc_mac_with_iv(&secret, [0u8; 8], data);
                black_box(mac);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn des_ecb_encrypt_left_half_ct() {
        let outcome = ct_test(
            0xC0_C09A2,
            |rng| {
                let key16 = [0u8; 16];
                let mut block = [0u8; 8];
                rng.fill_bytes(&mut block);
                (key16, block)
            },
            |rng| {
                let mut key16 = [0u8; 16];
                rng.fill_bytes(&mut key16);
                let mut block = [0u8; 8];
                rng.fill_bytes(&mut block);
                (key16, block)
            },
            |(key16, block)| {
                let ct = des_ecb_encrypt_left_half(key16, *block);
                black_box(ct);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Helper: build a properly-authenticated SCP02 APDU using the same
    /// keys the unwrap path will check. Returns `(apdu_buf, total_len)`.
    fn build_authenticated_scp02_apdu(
        command_mac: &[u8; 16],
        header: [u8; 4],
        data: &[u8],
    ) -> ([u8; 32], usize) {
        let mut mac_input = [0u8; 32];
        mac_input[0] = header[0] | 0x04; // SM bit set
        mac_input[1] = header[1];
        mac_input[2] = header[2];
        mac_input[3] = header[3];
        #[allow(clippy::cast_possible_truncation)]
        {
            mac_input[4] = (data.len() + 8) as u8;
        }
        mac_input[5..5 + data.len()].copy_from_slice(data);
        let input_len = 5 + data.len();
        let mut padded = [0u8; 40];
        let padded_len = pad_method2(&mac_input[..input_len], 8, &mut padded);
        let effective_icv = des_ecb_encrypt_left_half(command_mac, [0u8; 8]);
        let cmac_key = Secret::new(*command_mac);
        let mac = des3_2key_cbc_mac_with_iv(&cmac_key, effective_icv, &padded[..padded_len]);
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
        apdu[5 + data.len()..5 + data.len() + 8].copy_from_slice(&mac);
        (apdu, 5 + data.len() + 8)
    }

    #[test]
    fn unwrap_command_ct() {
        // Tests the SCP02 successful-MAC path. Both classes produce a
        // properly-MAC'd APDU so the function takes the same control-flow
        // path; the only timing variable is whether the session keys are
        // fixed-zero or random.
        let outcome = ct_test(
            0xC0_C09A4,
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
                let (apdu, total_len) =
                    build_authenticated_scp02_apdu(command_mac, [0x80, 0xF2, 0x80, 0x00], data);
                let mut state = ScpState::Authenticated {
                    session_enc: *session_enc,
                    command_mac: *command_mac,
                    response_mac: [0u8; 16],
                    session_dek: [0u8; 16],
                    security_level: 0x01, // C-MAC required, no C-ENC
                    icv: [0u8; 16],
                    rmac_icv: [0u8; 8],
                    rmac_active: false,
                    scp_version: ScpVersion::Scp02,
                    enc_counter: 0,
                };
                let mut output = [0u8; 32];
                let result = unwrap_command(&mut state, &apdu[..total_len], &mut output);
                let _ = black_box(result);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn wrap_response_ct() {
        // wrap_response with R-MAC active: timed path is the R-MAC
        // computation over the response bytes plus SW. Secret = response_mac.
        let outcome = ct_test(
            0xC0_C09A5,
            |rng| {
                let response_mac = [0u8; 16];
                let mut response = [0u8; 8];
                rng.fill_bytes(&mut response);
                (response_mac, response)
            },
            |rng| {
                let mut response_mac = [0u8; 16];
                rng.fill_bytes(&mut response_mac);
                let mut response = [0u8; 8];
                rng.fill_bytes(&mut response);
                (response_mac, response)
            },
            |(response_mac, response)| {
                let mut state = ScpState::Authenticated {
                    session_enc: [0u8; 16],
                    command_mac: [0u8; 16],
                    response_mac: *response_mac,
                    session_dek: [0u8; 16],
                    security_level: 0x10, // R-MAC active
                    icv: [0u8; 16],
                    rmac_icv: [0u8; 8],
                    rmac_active: true,
                    scp_version: ScpVersion::Scp02,
                    enc_counter: 0,
                };
                let mut output = [0u8; 64];
                let n = wrap_response(&mut state, &[], response, 0x90, 0x00, &mut output);
                black_box(n);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    #[test]
    fn generate_cmac_ct() {
        // generate_cmac wraps a header + data with C-MAC. Treat the
        // command_mac as the secret class variable.
        let outcome = ct_test(
            0xC0_C09A3,
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
                let (mac, _icv) = generate_cmac(
                    command_mac,
                    &[0x84, 0xF2, 0x80, 0x00],
                    data,
                    &[0u8; 8],
                    ScpVersion::Scp02,
                );
                black_box(mac);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
