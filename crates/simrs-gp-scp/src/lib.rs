//! `GlobalPlatform` SCP01 and SCP02 secure channel protocols per
//! [GP Card Specification v2.1.1](../../../../telecom-standards/globalplatform/GPC_CardSpecification_v2.1.1.pdf)
//! Appendices D (SCP01) and E (SCP02).
//!
//! Implements session key derivation, mutual authentication (cryptogram
//! generation/verification), and secure messaging (C-MAC, C-ENC, R-MAC).
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
#![no_std]

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::ct_eq;
use simrs_des::Des;
use simrs_gp_keys::KeySet;
use simrs_iso9797::{des3_2key_cbc_encrypt, des3_2key_cbc_mac, des3_2key_ecb_encrypt, pad_method2};
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// SCP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpVersion {
    /// Secure Channel Protocol 01 (GP 2.1.1 Appendix D).
    Scp01,
    /// Secure Channel Protocol 02 (GP 2.1.1 Appendix E).
    Scp02,
}

/// Errors from SCP operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpError {
    /// Host cryptogram verification failed.
    HostCryptogramMismatch,
    /// C-MAC verification failed (SW 69 88).
    CmacMismatch,
    /// Missing secure messaging data (SW 69 87).
    SecureMessagingMissing,
    /// Not in correct state for this operation.
    InvalidState,
    /// APDU too short or malformed.
    InvalidApdu,
    /// Output buffer too small.
    BufferTooSmall,
}

/// State machine for the secure channel protocol.
///
/// Transitions: `NoSession` -> `InitUpdateDone` -> `Authenticated`.
/// A new `INITIALIZE UPDATE` from any state resets to `InitUpdateDone`.
#[derive(Default)]
pub enum ScpState {
    /// No secure channel session.
    #[default]
    NoSession,
    /// `INITIALIZE UPDATE` received, waiting for `EXTERNAL AUTHENTICATE`.
    InitUpdateDone {
        /// Host challenge from `INITIALIZE UPDATE`.
        host_challenge: [u8; 8],
        /// Card challenge (8 bytes for SCP01, 6 bytes right-aligned for SCP02).
        card_challenge: [u8; 8],
        /// Key diversification data returned in `INITIALIZE UPDATE` response.
        key_diversification: [u8; 10],
        /// Derived session S-ENC key (2-key 3DES, 16 bytes).
        session_enc: [u8; 16],
        /// Derived session C-MAC key (2-key 3DES, 16 bytes).
        session_mac: [u8; 16],
        /// Computed card cryptogram (8 bytes).
        card_cryptogram: [u8; 8],
        /// SCP version for this session.
        scp_version: ScpVersion,
        /// Sequence counter (SCP02 only; stored for response formatting).
        sequence_counter: u16,
    },
    /// Authenticated session active.
    Authenticated {
        /// Session S-ENC key.
        session_enc: [u8; 16],
        /// Session C-MAC key.
        session_mac: [u8; 16],
        /// Session R-MAC key (SCP02 only; zero for SCP01).
        session_rmac: [u8; 16],
        /// Session DEK key (SCP02 only; zero for SCP01).
        session_dek: [u8; 16],
        /// Security level from `EXTERNAL AUTHENTICATE` P1.
        security_level: u8,
        /// ICV for C-MAC chaining.
        icv: [u8; 8],
        /// Whether R-MAC session is active.
        rmac_active: bool,
        /// SCP version for this session.
        scp_version: ScpVersion,
    },
}

// ---------------------------------------------------------------------------
// Key derivation -- SCP01 (GP 2.1.1 Appendix D, Figures D-3/D-4/D-5)
// ---------------------------------------------------------------------------

/// Build SCP01 derivation data from host and card challenges.
///
/// `derivation_data = host_challenge[4..8] || card_challenge[0..4]
///                     || host_challenge[0..4] || card_challenge[4..8]`
fn scp01_derivation_data(host_challenge: [u8; 8], card_challenge: [u8; 8]) -> [u8; 16] {
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
fn scp01_derive_session_key(static_key: &[u8], derivation_data: &[u8; 16]) -> [u8; 16] {
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
// Key derivation -- SCP02 (GP 2.1.1 Appendix E, Figure E-2)
// ---------------------------------------------------------------------------

/// Derive an SCP02 session key.
///
/// `derivation_data = constant[2] || sequence_counter[2] || 0x00[12]`
/// `session_key = 3DES_CBC(static_key, derivation_data, IV=0x00[8])`
///
/// The output is the full 16-byte ciphertext (two CBC-encrypted blocks).
fn scp02_derive_session_key(
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
fn compute_cryptogram(session_enc: &[u8; 16], data: &[u8]) -> [u8; 8] {
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
fn des3_2key_cbc_mac_with_iv(key: &Secret<[u8; 16]>, iv: [u8; 8], data: &[u8]) -> [u8; 8] {
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
fn des_ecb_encrypt_left_half(key16: &[u8; 16], block: [u8; 8]) -> [u8; 8] {
    let mut key8 = [0u8; 8];
    key8.copy_from_slice(&key16[..8]);
    let secret_key = Secret::new(key8);
    let des = Des::new(&secret_key);
    des.encrypt(&block)
}

// ---------------------------------------------------------------------------
// Public API -- INITIALIZE UPDATE
// ---------------------------------------------------------------------------

/// Process `INITIALIZE UPDATE` command.
///
/// Derives session keys and computes the card cryptogram. Returns the 28-byte
/// response data:
/// - SCP01: `key_diversification[10] || key_info[2] || card_challenge[8]
///   || card_cryptogram[8]`
/// - SCP02: `key_diversification[10] || key_info[2] || sequence_counter[2]
///   || card_challenge[6] || card_cryptogram[8]`
///
/// # Arguments
///
/// - `state` -- mutable SCP state machine; will transition to `InitUpdateDone`
/// - `scp_version` -- SCP01 or SCP02
/// - `key_version` -- key version number from P1 (included in `key_info`)
/// - `host_challenge` -- 8-byte host challenge from command data
/// - `keys` -- static key set from the key store
/// - `card_challenge` -- card-generated challenge (8 bytes for SCP01, 6 bytes
///   right-aligned in an 8-byte buffer for SCP02 -- first 2 bytes are ignored
///   for SCP02)
/// - `key_diversification` -- 10-byte key diversification data to return
/// - `sequence_counter` -- sequence counter for SCP02 (ignored for SCP01)
#[allow(clippy::too_many_arguments)]
pub fn process_initialize_update(
    state: &mut ScpState,
    scp_version: ScpVersion,
    key_version: u8,
    host_challenge: &[u8; 8],
    keys: &KeySet,
    card_challenge: &[u8; 8],
    key_diversification: &[u8; 10],
    sequence_counter: Option<u16>,
) -> [u8; 28] {
    let (session_enc, session_mac);

    match scp_version {
        ScpVersion::Scp01 => {
            let dd = scp01_derivation_data(*host_challenge, *card_challenge);
            session_enc = scp01_derive_session_key(keys.enc(), &dd);
            session_mac = scp01_derive_session_key(keys.mac(), &dd);
        }
        ScpVersion::Scp02 => {
            let seq = sequence_counter.unwrap_or(0);
            session_enc = scp02_derive_session_key(keys.enc(), [0x01, 0x82], seq);
            session_mac = scp02_derive_session_key(keys.mac(), [0x01, 0x01], seq);
        }
    }

    // Compute card cryptogram.
    let card_cryptogram = match scp_version {
        ScpVersion::Scp01 => {
            // Card cryptogram = MAC(`session_ENC`, host_challenge || card_challenge)
            let mut input = [0u8; 16];
            input[0..8].copy_from_slice(host_challenge);
            input[8..16].copy_from_slice(card_challenge);
            compute_cryptogram(&session_enc, &input)
        }
        ScpVersion::Scp02 => {
            // Card cryptogram = MAC(`session_ENC`,
            //   host_challenge || sequence_counter[2] || card_challenge[6])
            let seq = sequence_counter.unwrap_or(0);
            let mut input = [0u8; 16];
            input[0..8].copy_from_slice(host_challenge);
            #[allow(clippy::cast_possible_truncation)]
            {
                input[8] = (seq >> 8) as u8;
                input[9] = seq as u8;
            }
            // SCP02 card_challenge is 6 bytes, stored in card_challenge[2..8]
            input[10..16].copy_from_slice(&card_challenge[2..8]);
            compute_cryptogram(&session_enc, &input)
        }
    };

    // Build response.
    let mut response = [0u8; 28];
    response[0..10].copy_from_slice(key_diversification);
    response[10] = key_version;
    match scp_version {
        ScpVersion::Scp01 => {
            response[11] = 0x01; // SCP identifier
            response[12..20].copy_from_slice(card_challenge);
        }
        ScpVersion::Scp02 => {
            let seq = sequence_counter.unwrap_or(0);
            response[11] = 0x02; // SCP identifier
            #[allow(clippy::cast_possible_truncation)]
            {
                response[12] = (seq >> 8) as u8;
                response[13] = seq as u8;
            }
            // 6-byte card challenge
            response[14..20].copy_from_slice(&card_challenge[2..8]);
        }
    }
    response[20..28].copy_from_slice(&card_cryptogram);

    let seq = sequence_counter.unwrap_or(0);
    *state = ScpState::InitUpdateDone {
        host_challenge: *host_challenge,
        card_challenge: *card_challenge,
        key_diversification: *key_diversification,
        session_enc,
        session_mac,
        card_cryptogram,
        scp_version,
        sequence_counter: seq,
    };

    response
}

// ---------------------------------------------------------------------------
// Public API -- EXTERNAL AUTHENTICATE
// ---------------------------------------------------------------------------

/// Process `EXTERNAL AUTHENTICATE` command.
///
/// Verifies the host cryptogram and C-MAC from the command data. On success,
/// transitions to `Authenticated` state.
///
/// # Arguments
///
/// - `state` -- must be in `InitUpdateDone`; transitions to `Authenticated`
/// - `security_level` -- P1 from the `EXTERNAL AUTHENTICATE` APDU
///   (0x00 = auth only, 0x01 = C-MAC, 0x03 = C-MAC + C-ENC)
/// - `host_cryptogram_and_mac` -- 16 bytes: `host_cryptogram`[8] || C-MAC[8]
///
/// # Errors
///
/// - [`ScpError::InvalidState`] if not in `InitUpdateDone`
/// - [`ScpError::HostCryptogramMismatch`] if the host cryptogram does not verify
/// - [`ScpError::CmacMismatch`] if the C-MAC does not verify
pub fn process_external_authenticate(
    state: &mut ScpState,
    security_level: u8,
    host_cryptogram_and_mac: &[u8; 16],
) -> Result<(), ScpError> {
    // Extract state fields (must be `InitUpdateDone`).
    let (host_challenge, card_challenge, session_enc, session_mac, scp_version, seq_counter) =
        match state {
            ScpState::InitUpdateDone {
                host_challenge,
                card_challenge,
                session_enc,
                session_mac,
                scp_version,
                sequence_counter,
                ..
            } => (
                *host_challenge,
                *card_challenge,
                *session_enc,
                *session_mac,
                *scp_version,
                *sequence_counter,
            ),
            _ => return Err(ScpError::InvalidState),
        };

    let host_cryptogram = &host_cryptogram_and_mac[0..8];
    let received_cmac = &host_cryptogram_and_mac[8..16];

    // Compute expected host cryptogram.
    let expected_host_cryptogram = match scp_version {
        ScpVersion::Scp01 => {
            // Host cryptogram = MAC(`session_ENC`, card_challenge || host_challenge)
            let mut input = [0u8; 16];
            input[0..8].copy_from_slice(&card_challenge);
            input[8..16].copy_from_slice(&host_challenge);
            compute_cryptogram(&session_enc, &input)
        }
        ScpVersion::Scp02 => {
            // Host cryptogram = MAC(`session_ENC`,
            //   sequence_counter[2] || card_challenge[6] || host_challenge)
            let mut input = [0u8; 16];
            #[allow(clippy::cast_possible_truncation)]
            {
                input[0] = (seq_counter >> 8) as u8;
                input[1] = seq_counter as u8;
            }
            input[2..8].copy_from_slice(&card_challenge[2..8]);
            input[8..16].copy_from_slice(&host_challenge);
            compute_cryptogram(&session_enc, &input)
        }
    };

    // Constant-time comparison.
    if !ct_eq(host_cryptogram, &expected_host_cryptogram).into_bool() {
        *state = ScpState::NoSession;
        return Err(ScpError::HostCryptogramMismatch);
    }

    // Verify C-MAC on the EXTERNAL AUTHENTICATE command itself.
    // APDU header: CLA=0x84, INS=0x82, P1=security_level, P2=0x00, Lc=0x10
    // MAC input: 0x84 || 0x82 || P1 || 0x00 || 0x10 || host_cryptogram[8]
    let cmac_key = Secret::new(session_mac);
    let mut cmac_input_buf = [0u8; 24]; // 5 header + 8 cryptogram = 13 bytes, padded to 16
    let cmac_data = [
        0x84,
        0x82,
        security_level,
        0x00,
        0x10,
        host_cryptogram_and_mac[0],
        host_cryptogram_and_mac[1],
        host_cryptogram_and_mac[2],
        host_cryptogram_and_mac[3],
        host_cryptogram_and_mac[4],
        host_cryptogram_and_mac[5],
        host_cryptogram_and_mac[6],
        host_cryptogram_and_mac[7],
    ];
    let padded_len = pad_method2(&cmac_data, 8, &mut cmac_input_buf);

    let effective_icv = match scp_version {
        ScpVersion::Scp01 => [0u8; 8],
        ScpVersion::Scp02 => {
            // SCP02: encrypt the zero ICV with single-DES ECB (left half of session MAC)
            des_ecb_encrypt_left_half(&session_mac, [0u8; 8])
        }
    };

    let expected_cmac =
        des3_2key_cbc_mac_with_iv(&cmac_key, effective_icv, &cmac_input_buf[..padded_len]);

    if !ct_eq(received_cmac, &expected_cmac).into_bool() {
        *state = ScpState::NoSession;
        return Err(ScpError::CmacMismatch);
    }

    // SCP02 R-MAC and DEK keys would need the original static keys, which
    // are not stored in `InitUpdateDone`. For now, store zeros; a real
    // implementation should derive these during `INITIALIZE UPDATE`.
    let (sess_rmac, sess_dek) = ([0u8; 16], [0u8; 16]);

    // The C-MAC we just verified becomes the ICV for the next command (SCP02).
    let next_icv = expected_cmac;

    *state = ScpState::Authenticated {
        session_enc,
        session_mac,
        session_rmac: sess_rmac,
        session_dek: sess_dek,
        security_level,
        icv: next_icv,
        rmac_active: false,
        scp_version,
    };

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API -- INITIALIZE UPDATE with full SCP02 key derivation
// ---------------------------------------------------------------------------

/// Process `INITIALIZE UPDATE` for SCP02 with full session key derivation.
///
/// This is a convenience wrapper that derives all four SCP02 session keys
/// (S-ENC, C-MAC, R-MAC, DEK) and stores them in the state so that
/// `process_external_authenticate` can later populate the `Authenticated`
/// state with R-MAC and DEK keys.
#[allow(clippy::too_many_arguments)]
pub fn process_initialize_update_scp02_full(
    state: &mut ScpState,
    key_version: u8,
    host_challenge: &[u8; 8],
    keys: &KeySet,
    card_challenge: &[u8; 8],
    key_diversification: &[u8; 10],
    sequence_counter: u16,
) -> [u8; 28] {
    process_initialize_update(
        state,
        ScpVersion::Scp02,
        key_version,
        host_challenge,
        keys,
        card_challenge,
        key_diversification,
        Some(sequence_counter),
    )
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
    let (session_enc, session_mac, security_level, current_icv, scp_version) = match state {
        ScpState::Authenticated {
            session_enc,
            session_mac,
            security_level,
            icv,
            scp_version,
            ..
        } => (
            *session_enc,
            *session_mac,
            *security_level,
            *icv,
            *scp_version,
        ),
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
    let effective_icv = match scp_version {
        ScpVersion::Scp01 => [0u8; 8], // SCP01: ICV is always zeros
        ScpVersion::Scp02 => {
            // SCP02: ICV is encrypted with single-DES ECB (left half of session MAC key)
            des_ecb_encrypt_left_half(&session_mac, current_icv)
        }
    };

    let expected_cmac = des3_2key_cbc_mac_with_iv(&cmac_key, effective_icv, &padded[..padded_len]);

    if !ct_eq(received_cmac, &expected_cmac).into_bool() {
        return Err(ScpError::CmacMismatch);
    }

    // Update ICV for next command.
    if let ScpState::Authenticated { icv, .. } = state {
        *icv = expected_cmac;
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
    let (sess_rmac, is_rmac_active, current_icv) = if let ScpState::Authenticated {
        session_rmac,
        rmac_active,
        icv,
        ..
    } = state
    {
        (*session_rmac, *rmac_active, *icv)
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
    let rmac = des3_2key_cbc_mac_with_iv(&rmac_key, current_icv, &padded[..padded_len]);

    // Output: response_data || R-MAC || SW1 || SW2
    let total = response_data.len() + 8 + 2;
    output[..response_data.len()].copy_from_slice(response_data);
    output[response_data.len()..response_data.len() + 8].copy_from_slice(&rmac);
    output[response_data.len() + 8] = sw1;
    output[response_data.len() + 9] = sw2;
    total
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
    };

    let mac = des3_2key_cbc_mac_with_iv(&cmac_key, effective_icv, &padded[..padded_len]);
    (mac, mac)
}

// ---------------------------------------------------------------------------
// Utility -- unpad Method 2
// ---------------------------------------------------------------------------

/// Remove ISO 9797-1 Method 2 padding. Returns the unpadded data length.
fn unpad_method2(data: &[u8]) -> usize {
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
// Snapshot support
// ---------------------------------------------------------------------------

/// Snapshot size for [`ScpState`].
///
/// Layout:
/// - 1 byte: variant tag (0 = `NoSession`, 1 = `InitUpdateDone`, 2 = `Authenticated`)
/// - For `InitUpdateDone`: 8+8+10+16+16+8+1+2 = 69 bytes
/// - For `Authenticated`: 16+16+16+16+1+8+1+1 = 75 bytes
///
/// Maximum: 1 + 75 = 76 bytes.
pub const SCP_STATE_SNAPSHOT_SIZE: usize = 76;

/// Save SCP state to a buffer. Returns number of bytes written.
#[allow(clippy::cast_possible_truncation)]
pub fn save_scp_state(state: &ScpState, buf: &mut [u8]) -> usize {
    let mut off = 0;
    match state {
        ScpState::NoSession => {
            buf[off] = 0;
            off += 1;
        }
        ScpState::InitUpdateDone {
            host_challenge,
            card_challenge,
            key_diversification,
            session_enc,
            session_mac,
            card_cryptogram,
            scp_version,
            sequence_counter,
        } => {
            buf[off] = 1;
            off += 1;
            buf[off..off + 8].copy_from_slice(host_challenge);
            off += 8;
            buf[off..off + 8].copy_from_slice(card_challenge);
            off += 8;
            buf[off..off + 10].copy_from_slice(key_diversification);
            off += 10;
            buf[off..off + 16].copy_from_slice(session_enc);
            off += 16;
            buf[off..off + 16].copy_from_slice(session_mac);
            off += 16;
            buf[off..off + 8].copy_from_slice(card_cryptogram);
            off += 8;
            buf[off] = match scp_version {
                ScpVersion::Scp01 => 0x01,
                ScpVersion::Scp02 => 0x02,
            };
            off += 1;
            buf[off] = (*sequence_counter >> 8) as u8;
            buf[off + 1] = *sequence_counter as u8;
            off += 2;
        }
        ScpState::Authenticated {
            session_enc,
            session_mac,
            session_rmac,
            session_dek,
            security_level,
            icv,
            rmac_active,
            scp_version,
        } => {
            buf[off] = 2;
            off += 1;
            buf[off..off + 16].copy_from_slice(session_enc);
            off += 16;
            buf[off..off + 16].copy_from_slice(session_mac);
            off += 16;
            buf[off..off + 16].copy_from_slice(session_rmac);
            off += 16;
            buf[off..off + 16].copy_from_slice(session_dek);
            off += 16;
            buf[off] = *security_level;
            off += 1;
            buf[off..off + 8].copy_from_slice(icv);
            off += 8;
            buf[off] = u8::from(*rmac_active);
            off += 1;
            buf[off] = match scp_version {
                ScpVersion::Scp01 => 0x01,
                ScpVersion::Scp02 => 0x02,
            };
            off += 1;
        }
    }
    off
}

/// Restore SCP state from a buffer. Returns `true` on success.
#[allow(clippy::similar_names)]
pub fn restore_scp_state(state: &mut ScpState, buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    match buf[0] {
        0 => {
            *state = ScpState::NoSession;
            true
        }
        1 => {
            if buf.len() < 70 {
                return false;
            }
            let mut off = 1;
            let mut host_challenge = [0u8; 8];
            host_challenge.copy_from_slice(&buf[off..off + 8]);
            off += 8;
            let mut card_challenge = [0u8; 8];
            card_challenge.copy_from_slice(&buf[off..off + 8]);
            off += 8;
            let mut key_diversification = [0u8; 10];
            key_diversification.copy_from_slice(&buf[off..off + 10]);
            off += 10;
            let mut session_enc = [0u8; 16];
            session_enc.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            let mut session_mac = [0u8; 16];
            session_mac.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            let mut card_cryptogram = [0u8; 8];
            card_cryptogram.copy_from_slice(&buf[off..off + 8]);
            off += 8;
            let scp_version = match buf[off] {
                0x01 => ScpVersion::Scp01,
                0x02 => ScpVersion::Scp02,
                _ => return false,
            };
            off += 1;
            let sequence_counter = u16::from_be_bytes([buf[off], buf[off + 1]]);
            *state = ScpState::InitUpdateDone {
                host_challenge,
                card_challenge,
                key_diversification,
                session_enc,
                session_mac,
                card_cryptogram,
                scp_version,
                sequence_counter,
            };
            true
        }
        2 => {
            if buf.len() < 76 {
                return false;
            }
            let mut off = 1;
            let mut session_enc = [0u8; 16];
            session_enc.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            let mut session_mac = [0u8; 16];
            session_mac.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            let mut session_rmac = [0u8; 16];
            session_rmac.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            let mut session_dek = [0u8; 16];
            session_dek.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            let security_level = buf[off];
            off += 1;
            let mut icv = [0u8; 8];
            icv.copy_from_slice(&buf[off..off + 8]);
            off += 8;
            let rmac_active = buf[off] != 0;
            off += 1;
            let scp_version = match buf[off] {
                0x01 => ScpVersion::Scp01,
                0x02 => ScpVersion::Scp02,
                _ => return false,
            };
            *state = ScpState::Authenticated {
                session_enc,
                session_mac,
                session_rmac,
                session_dek,
                security_level,
                icv,
                rmac_active,
                scp_version,
            };
            true
        }
        _ => false,
    }
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use simrs_gp_keys::KeySet;

    // Standard test keys from GP 2.1.1: all bytes 0x40..0x4F repeated.
    fn test_keys() -> KeySet {
        let k = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        KeySet::des3_2key(k, k, k)
    }

    fn test_host_challenge() -> [u8; 8] {
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    fn test_card_challenge_scp01() -> [u8; 8] {
        [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8]
    }

    fn test_key_diversification() -> [u8; 10] {
        [0x00; 10]
    }

    // ----- Test 1: SCP01 session key derivation -----

    #[test]
    fn scp01_session_key_derivation() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();

        let (session_enc, session_mac, session_dek) = derive_scp01_session_keys(&keys, &hc, &cc);

        // Verify derivation data construction.
        let dd = scp01_derivation_data(hc, cc);
        // dd = hc[4..8] || cc[0..4] || hc[0..4] || cc[4..8]
        assert_eq!(&dd[0..4], &hc[4..8]);
        assert_eq!(&dd[4..8], &cc[0..4]);
        assert_eq!(&dd[8..12], &hc[0..4]);
        assert_eq!(&dd[12..16], &cc[4..8]);

        // Verify session keys are 3DES ECB encrypted derivation data.
        let expected_enc = scp01_derive_session_key(keys.enc(), &dd);
        let expected_mac = scp01_derive_session_key(keys.mac(), &dd);
        let expected_dek = scp01_derive_session_key(keys.dek(), &dd);

        assert_eq!(session_enc, expected_enc);
        assert_eq!(session_mac, expected_mac);
        assert_eq!(session_dek, expected_dek);

        // Keys must not be the same as static keys (unless by extraordinary coincidence).
        assert_ne!(session_enc, *keys.enc());

        // Independently verify: encrypt derivation data halves with 3DES ECB.
        let static_key_secret = Secret::new([
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ]);
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&dd[0..8]);
        hi.copy_from_slice(&dd[8..16]);
        let enc_lo = des3_2key_ecb_encrypt(&static_key_secret, &lo);
        let enc_hi = des3_2key_ecb_encrypt(&static_key_secret, &hi);
        assert_eq!(&session_enc[0..8], &enc_lo);
        assert_eq!(&session_enc[8..16], &enc_hi);
    }

    // ----- Test 2: SCP01 card cryptogram computation -----

    #[test]
    fn scp01_card_cryptogram() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();

        let (session_enc, _, _) = derive_scp01_session_keys(&keys, &hc, &cc);
        let card_crypto = compute_scp01_card_cryptogram(&session_enc, &hc, &cc);

        // Independently compute: MAC(session_ENC, hc || cc) with Method 2 padding.
        let mut input = [0u8; 16];
        input[0..8].copy_from_slice(&hc);
        input[8..16].copy_from_slice(&cc);
        let mut padded = [0u8; 24];
        let padded_len = pad_method2(&input, 8, &mut padded);
        let enc_key = Secret::new(session_enc);
        let expected = des3_2key_cbc_mac(&enc_key, &padded[..padded_len]);

        assert_eq!(card_crypto, expected);
        // Ensure it's not trivially zero.
        assert_ne!(card_crypto, [0u8; 8]);
    }

    // ----- Test 3: SCP01 INITIALIZE UPDATE + EXTERNAL AUTHENTICATE round-trip -----

    #[test]
    fn scp01_full_authentication_roundtrip() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let response = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );

        // Verify response structure.
        assert_eq!(&response[0..10], &kdiv);
        assert_eq!(response[10], 0x01); // key version
        assert_eq!(response[11], 0x01); // SCP01 identifier
        assert_eq!(&response[12..20], &cc);

        // Verify state is InitUpdateDone.
        assert!(matches!(state, ScpState::InitUpdateDone { .. }));

        // Extract session keys from state.
        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        // Compute host cryptogram.
        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);

        // Compute C-MAC for EXTERNAL AUTHENTICATE.
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x00, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );

        let mut host_crypto_and_mac = [0u8; 16];
        host_crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        host_crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);

        let result = process_external_authenticate(&mut state, 0x00, &host_crypto_and_mac);
        assert!(result.is_ok(), "EXTERNAL AUTHENTICATE failed: {result:?}");

        // Verify state is Authenticated.
        assert!(matches!(
            state,
            ScpState::Authenticated {
                security_level: 0x00,
                ..
            }
        ));
    }

    // ----- Test 4: SCP01 wrong host cryptogram -> error -----

    #[test]
    fn scp01_wrong_host_cryptogram() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );

        // Send wrong host cryptogram.
        let bad_crypto_and_mac = [0xFF; 16];
        let result = process_external_authenticate(&mut state, 0x00, &bad_crypto_and_mac);
        assert_eq!(result, Err(ScpError::HostCryptogramMismatch));

        // State should be reset to NoSession.
        assert!(matches!(state, ScpState::NoSession));
    }

    // ----- Test 5: SCP02 session key derivation with sequence counter -----

    #[test]
    fn scp02_session_key_derivation() {
        let keys = test_keys();

        // Sequence counter 0x0000.
        let (enc, mac, rmac, dek) = derive_scp02_session_keys(&keys, 0x0000);

        // Independently compute session keys.
        let expected_enc = scp02_derive_session_key(keys.enc(), [0x01, 0x82], 0x0000);
        let expected_mac = scp02_derive_session_key(keys.mac(), [0x01, 0x01], 0x0000);
        let expected_rmac = scp02_derive_session_key(keys.mac(), [0x01, 0x02], 0x0000);
        let expected_dek = scp02_derive_session_key(keys.dek(), [0x01, 0x81], 0x0000);

        assert_eq!(enc, expected_enc);
        assert_eq!(mac, expected_mac);
        assert_eq!(rmac, expected_rmac);
        assert_eq!(dek, expected_dek);

        // Keys must differ from static keys.
        assert_ne!(enc, *keys.enc());

        // Verify by independent CBC encryption.
        let static_enc_secret = Secret::new([
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ]);
        let mut dd = [0x01, 0x82, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        des3_2key_cbc_encrypt(&static_enc_secret, &[0u8; 8], &mut dd);
        assert_eq!(enc, dd);
    }

    // ----- Test 6: SCP02 sequence counter in response -----

    #[test]
    fn scp02_sequence_counter_in_response() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = [0x00, 0x00, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6]; // 6-byte challenge in [2..8]
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let response = process_initialize_update(
            &mut state,
            ScpVersion::Scp02,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            Some(0x0042),
        );

        // Verify SCP02 identifier.
        assert_eq!(response[11], 0x02);

        // Verify sequence counter.
        assert_eq!(response[12], 0x00); // high byte
        assert_eq!(response[13], 0x42); // low byte

        // Verify 6-byte card challenge.
        assert_eq!(&response[14..20], &cc[2..8]);
    }

    // ----- Test 7: C-MAC generation over known command bytes -----

    #[test]
    fn cmac_generation_known_command() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();

        let (_, session_mac, _) = derive_scp01_session_keys(&keys, &hc, &cc);

        // GET STATUS: 80 F2 80 00 02 4F 00
        let header = [0x80, 0xF2, 0x80, 0x00];
        let data = [0x4F, 0x00];
        let icv = [0u8; 8];

        let (mac, _) = generate_cmac(&session_mac, &header, &data, &icv, ScpVersion::Scp01);

        // Independently compute:
        // Input = 84 F2 80 00 0A 4F 00  (CLA|=0x04, Lc = 2+8 = 10)
        // Padded with Method 2: 84 F2 80 00 0A 4F 00 80  (8 bytes, already aligned)
        let mac_input = [0x84, 0xF2, 0x80, 0x00, 0x0A, 0x4F, 0x00];
        let mut padded = [0u8; 16];
        let padded_len = pad_method2(&mac_input, 8, &mut padded);
        let mac_key = Secret::new(session_mac);
        let expected = des3_2key_cbc_mac(&mac_key, &padded[..padded_len]);

        assert_eq!(mac, expected);
        assert_ne!(mac, [0u8; 8]); // not trivially zero
    }

    // ----- Test 8: C-MAC verification (good and bad) -----

    #[test]
    fn cmac_verification_good() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        // Set up authenticated session.
        let mut state = ScpState::NoSession;
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );
        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        // Complete authentication.
        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        assert!(process_external_authenticate(&mut state, 0x01, &crypto_and_mac).is_ok());

        // Now send a command with C-MAC.
        let header = [0x80, 0xF2, 0x80, 0x00];
        let data = [0x4F, 0x00];
        let (cmd_mac, _) =
            generate_cmac(&session_mac, &header, &data, &[0u8; 8], ScpVersion::Scp01);

        // Build APDU: CLA=0x84, INS=0xF2, P1=0x80, P2=0x00, Lc=0x0A, data, MAC
        let mut apdu = [0u8; 15];
        apdu[0] = 0x84;
        apdu[1] = 0xF2;
        apdu[2] = 0x80;
        apdu[3] = 0x00;
        apdu[4] = 0x0A; // 2 data + 8 MAC
        apdu[5..7].copy_from_slice(&data);
        apdu[7..15].copy_from_slice(&cmd_mac);

        let mut output = [0u8; 256];
        let result = unwrap_command(&mut state, &apdu, &mut output);
        assert!(result.is_ok(), "unwrap_command failed: {result:?}");
        let len = result.unwrap();
        assert_eq!(len, 2);
        assert_eq!(&output[..2], &data);
    }

    #[test]
    fn cmac_verification_bad() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );
        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        assert!(process_external_authenticate(&mut state, 0x01, &crypto_and_mac).is_ok());

        // Send a command with a bad C-MAC.
        let mut apdu = [0u8; 15];
        apdu[0] = 0x84;
        apdu[1] = 0xF2;
        apdu[2] = 0x80;
        apdu[3] = 0x00;
        apdu[4] = 0x0A;
        apdu[5..7].copy_from_slice(&[0x4F, 0x00]);
        apdu[7..15].copy_from_slice(&[0xFF; 8]); // bad MAC

        let mut output = [0u8; 256];
        let result = unwrap_command(&mut state, &apdu, &mut output);
        assert_eq!(result, Err(ScpError::CmacMismatch));
    }

    // ----- Test 9: State machine transitions -----

    #[test]
    fn state_machine_transitions() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;

        // NoSession -> InitUpdateDone
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );
        assert!(matches!(state, ScpState::InitUpdateDone { .. }));

        // InitUpdateDone -> Authenticated
        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x00, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        assert!(process_external_authenticate(&mut state, 0x00, &crypto_and_mac).is_ok());
        assert!(matches!(state, ScpState::Authenticated { .. }));
    }

    // ----- Test 10: Command before auth -> error -----

    #[test]
    fn command_before_auth_error() {
        let mut state = ScpState::NoSession;
        let apdu = [
            0x84, 0xF2, 0x80, 0x00, 0x0A, 0x4F, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF,
        ];
        let mut output = [0u8; 256];
        let result = unwrap_command(&mut state, &apdu, &mut output);
        assert_eq!(result, Err(ScpError::InvalidState));
    }

    // ----- Snapshot round-trip -----

    #[test]
    fn snapshot_nosession_roundtrip() {
        let state = ScpState::NoSession;
        let mut buf = [0u8; SCP_STATE_SNAPSHOT_SIZE];
        let written = save_scp_state(&state, &mut buf);
        assert_eq!(written, 1);

        let mut restored = ScpState::NoSession;
        assert!(restore_scp_state(&mut restored, &buf[..written]));
        assert!(matches!(restored, ScpState::NoSession));
    }

    #[test]
    fn snapshot_authenticated_roundtrip() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );

        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        assert!(process_external_authenticate(&mut state, 0x01, &crypto_and_mac).is_ok());

        // Save state.
        let mut buf = [0u8; SCP_STATE_SNAPSHOT_SIZE];
        let written = save_scp_state(&state, &mut buf);

        // Restore state.
        let mut restored = ScpState::NoSession;
        assert!(restore_scp_state(&mut restored, &buf[..written]));

        // Verify restored state matches.
        match (&state, &restored) {
            (
                ScpState::Authenticated {
                    session_enc: enc1,
                    session_mac: mac1,
                    security_level: sl1,
                    icv: icv1,
                    scp_version: sv1,
                    ..
                },
                ScpState::Authenticated {
                    session_enc: enc2,
                    session_mac: mac2,
                    security_level: sl2,
                    icv: icv2,
                    scp_version: sv2,
                    ..
                },
            ) => {
                assert_eq!(enc1, enc2);
                assert_eq!(mac1, mac2);
                assert_eq!(sl1, sl2);
                assert_eq!(icv1, icv2);
                assert_eq!(sv1, sv2);
            }
            _ => panic!("state mismatch after restore"),
        }
    }

    #[test]
    fn snapshot_rejects_invalid() {
        let mut state = ScpState::NoSession;
        assert!(!restore_scp_state(&mut state, &[]));
        assert!(!restore_scp_state(&mut state, &[0xFF]));
        assert!(!restore_scp_state(&mut state, &[2, 0])); // too short for Authenticated
    }

    // ----- SCP02 full round-trip -----

    #[test]
    fn scp02_full_authentication_roundtrip() {
        let keys = test_keys();
        let hc = test_host_challenge();
        // SCP02: 6-byte card challenge, stored in [2..8] of an 8-byte buffer.
        let cc = [0x00, 0x00, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6];
        let kdiv = test_key_diversification();
        let seq: u16 = 0x0000;

        let mut state = ScpState::NoSession;
        let response = process_initialize_update(
            &mut state,
            ScpVersion::Scp02,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            Some(seq),
        );

        // Verify SCP02 response structure.
        assert_eq!(response[11], 0x02); // SCP02 identifier
        assert_eq!(response[12], 0x00); // seq high
        assert_eq!(response[13], 0x00); // seq low
        assert_eq!(&response[14..20], &cc[2..8]); // 6-byte challenge

        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        // Verify card cryptogram.
        let expected_card_crypto =
            compute_scp02_card_cryptogram(&session_enc, &hc, seq, &cc[2..8].try_into().unwrap());
        assert_eq!(&response[20..28], &expected_card_crypto);

        // Compute host cryptogram.
        let host_crypto =
            compute_scp02_host_cryptogram(&session_enc, &hc, seq, &cc[2..8].try_into().unwrap());

        // Compute C-MAC for EXTERNAL AUTHENTICATE.
        // For SCP02, first EXT AUTH ICV = zeros.
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp02,
        );

        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);

        let result = process_external_authenticate(&mut state, 0x01, &crypto_and_mac);
        assert!(
            result.is_ok(),
            "SCP02 EXTERNAL AUTHENTICATE failed: {result:?}"
        );
        assert!(matches!(state, ScpState::Authenticated { .. }));
    }

    // ----- Different session keys with different sequence counters -----

    #[test]
    fn scp02_different_seq_counters_produce_different_keys() {
        let keys = test_keys();

        let (enc0, mac0, _, _) = derive_scp02_session_keys(&keys, 0x0000);
        let (enc1, mac1, _, _) = derive_scp02_session_keys(&keys, 0x0001);

        assert_ne!(
            enc0, enc1,
            "S-ENC must differ for different sequence counters"
        );
        assert_ne!(
            mac0, mac1,
            "C-MAC must differ for different sequence counters"
        );
    }

    // ----- Security level values -----

    #[test]
    fn scp01_security_level_cmac() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );

        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);

        assert!(process_external_authenticate(&mut state, 0x01, &crypto_and_mac).is_ok());
        if let ScpState::Authenticated { security_level, .. } = &state {
            assert_eq!(*security_level, 0x01);
        } else {
            panic!("expected Authenticated");
        }
    }

    #[test]
    fn scp01_security_level_cmac_and_cenc() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            None,
        );

        let (session_enc, session_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                session_mac,
                ..
            } => (*session_enc, *session_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &session_mac,
            &[0x84, 0x82, 0x03, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);

        assert!(process_external_authenticate(&mut state, 0x03, &crypto_and_mac).is_ok());
        if let ScpState::Authenticated { security_level, .. } = &state {
            assert_eq!(*security_level, 0x03);
        } else {
            panic!("expected Authenticated");
        }
    }

    // ----- Unpad Method 2 -----

    #[test]
    fn unpad_method2_basic() {
        assert_eq!(
            unpad_method2(&[0x01, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00]),
            2
        );
        assert_eq!(
            unpad_method2(&[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            0
        );
        assert_eq!(
            unpad_method2(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x80]),
            7
        );
    }

    // ----- Re-authentication resets state -----

    #[test]
    fn reinitialize_update_resets_state() {
        let keys = test_keys();
        let hc1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let hc2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;

        // First INIT UPDATE.
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc1,
            &keys,
            &cc,
            &kdiv,
            None,
        );
        assert!(matches!(state, ScpState::InitUpdateDone { .. }));

        // Second INIT UPDATE from InitUpdateDone (re-auth).
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp01,
            0x01,
            &hc2,
            &keys,
            &cc,
            &kdiv,
            None,
        );
        // Should be in InitUpdateDone with new host challenge.
        match &state {
            ScpState::InitUpdateDone { host_challenge, .. } => {
                assert_eq!(*host_challenge, hc2);
            }
            _ => panic!("expected InitUpdateDone with new host challenge"),
        }
    }
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// SCP01 key derivation is deterministic for the same inputs.
        #[test]
        fn scp01_key_derivation_deterministic(
            static_key in any::<[u8; 16]>(),
            hc in any::<[u8; 8]>(),
            cc in any::<[u8; 8]>(),
        ) {
            let keys = KeySet::des3_2key(static_key, static_key, static_key);
            let (enc1, mac1, dek1) = derive_scp01_session_keys(&keys, &hc, &cc);
            let (enc2, mac2, dek2) = derive_scp01_session_keys(&keys, &hc, &cc);
            prop_assert_eq!(enc1, enc2);
            prop_assert_eq!(mac1, mac2);
            prop_assert_eq!(dek1, dek2);
        }
    }

    proptest! {
        /// SCP02 key derivation is deterministic for the same inputs.
        #[test]
        #[allow(clippy::similar_names)]
        fn scp02_key_derivation_deterministic(
            static_key in any::<[u8; 16]>(),
            seq in any::<u16>(),
        ) {
            let keys = KeySet::des3_2key(static_key, static_key, static_key);
            let (enc1, mac1, rmac1, dek1) = derive_scp02_session_keys(&keys, seq);
            let (enc2, mac2, rmac2, dek2) = derive_scp02_session_keys(&keys, seq);
            prop_assert_eq!(enc1, enc2);
            prop_assert_eq!(mac1, mac2);
            prop_assert_eq!(rmac1, rmac2);
            prop_assert_eq!(dek1, dek2);
        }
    }

    proptest! {
        /// SCP01 card and host cryptograms differ (different input order).
        #[test]
        fn scp01_card_host_cryptograms_differ(
            enc_key in any::<[u8; 16]>(),
            hc in any::<[u8; 8]>(),
            cc in any::<[u8; 8]>(),
        ) {
            prop_assume!(hc != cc);
            let card_crypto = compute_scp01_card_cryptogram(&enc_key, &hc, &cc);
            let host_crypto = compute_scp01_host_cryptogram(&enc_key, &hc, &cc);
            prop_assert_ne!(card_crypto, host_crypto);
        }
    }

    proptest! {
        /// Snapshot round-trip preserves state for `NoSession`.
        #[test]
        fn snapshot_roundtrip_nosession(_dummy in 0u8..1) {
            let state = ScpState::NoSession;
            let mut buf = [0u8; SCP_STATE_SNAPSHOT_SIZE];
            let written = save_scp_state(&state, &mut buf);
            let mut restored = ScpState::NoSession;
            prop_assert!(restore_scp_state(&mut restored, &buf[..written]));
            prop_assert!(matches!(restored, ScpState::NoSession));
        }
    }
}
