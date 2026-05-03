//! `GlobalPlatform` SCP01, SCP02, and SCP03 secure channel protocols per
//! [GP Card Specification v2.1.1](../../../../docs/specs/globalplatform/GPC_CardSpecification_v2.1.1.pdf)
//! Appendices D (SCP01) and E (SCP02), and
//! [GP Amendment D v1.1.2](../../../../docs/specs/globalplatform/GPC_2.3_D_SCP03_v1.1.2.pdf)
//! (SCP03).
//!
//! Implements session key derivation, mutual authentication (cryptogram
//! generation/verification), and secure messaging (C-MAC, C-ENC, R-MAC).
//!
//! # SCP01 (GP 2.1.1 Appendix D, p199-212)
//!
//! 3 static 3DES keys per key set (Table D-1):
//! - S-ENC (key ID 1): encryption key
//! - S-MAC (key ID 2): MAC key
//! - DEK (key ID 3): data encryption key (PUT KEY wrapping)
//!
//! Session key derivation (Fig D-3/D-4/D-5):
//! ```text
//! derivation = card_challenge[4..8] || host_challenge[0..4]
//!           || card_challenge[0..4] || host_challenge[4..8]
//! session_enc = 3DES_ECB(static_enc, derivation)
//! command_mac = 3DES_ECB(static_mac, derivation)
//! ```
//!
//! INITIALIZE UPDATE (Table D-4): `80 50 <kv> <kid> 08 <host_challenge[8]>`
//! - Response (Table D-5): 28 bytes = `key_div[10] || key_info[2] || card_challenge[8] || card_cryptogram[8]`
//! - Card cryptogram = `MAC(session_enc, host_challenge || card_challenge)`
//!
//! EXTERNAL AUTHENTICATE (Table D-7): `84 82 <sec_level> 00 10 <host_crypto[8]> <cmac[8]>`
//! - Host cryptogram = `MAC(session_enc, card_challenge || host_challenge)`
//! - Security levels: `0x00` no security, `0x01` C-MAC, `0x03` C-MAC+C-ENC
//!
//! # SCP02 (GP 2.1.1 Appendix E, p213-234)
//!
//! Key differences from SCP01:
//! - Session keys derived from static keys AND a 2-byte sequence counter
//! - Sequence counter is persistent, increments on each INITIALIZE UPDATE
//! - ICV chaining: MAC ICV from previous command (not always zero)
//! - R-MAC support (response message authentication)
//!
//! Session key derivation (Fig E-2):
//! ```text
//! constants: 0x0182 (S-ENC), 0x0101 (C-MAC), 0x0102 (R-MAC), 0x0181 (DEK)
//! session_key = 3DES_CBC(static_key, [constant || seq_counter || pad_to_16])
//! IV = 0x0000000000000000
//! ```
//!
//! C-MAC ICV chaining (Fig E-3/E-4): ICV starts at zero for explicit SC;
//! subsequent commands chain from previous MAC. Each ICV is encrypted with
//! session S-MAC before use as CBC IV.
//!
//! # SCP03 (GP Amendment D v1.1.2)
//!
//! AES-128 based (not DES). Key derivation uses AES-CMAC (RFC 4493) with
//! derivation data encoding the key type and challenge material.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
#![no_std]

#[cfg(feature = "std")]
extern crate std;

mod cmac;
pub mod keywrap;
mod scp01;
mod scp02;
pub mod scp03;
mod snapshot;

// Re-export all public items so the crate API is unchanged.
pub use cmac::{
    des_ecb_encrypt_left_half, des3_2key_cbc_mac_with_iv, generate_cmac, seed_rmac_chain_scp02,
    unwrap_command, wrap_response,
};
pub use scp01::{
    compute_scp01_card_cryptogram, compute_scp01_host_cryptogram, derive_scp01_session_keys,
};
pub use scp02::{
    compute_scp02_card_cryptogram, compute_scp02_host_cryptogram, derive_scp02_session_key,
    derive_scp02_session_keys, scp02_pseudo_random_card_challenge,
};
pub use scp03::{
    Scp03InitUpdateResponse, compute_card_cryptogram as compute_scp03_card_cryptogram,
    compute_host_cryptogram as compute_scp03_host_cryptogram,
    derive_session_keys as derive_scp03_session_keys, generate_cmac as scp03_generate_cmac,
    parse_init_update as parse_scp03_init_update, wrap_response as scp03_wrap_response,
};
pub use snapshot::{SCP_STATE_SNAPSHOT_SIZE, restore_scp_state, save_scp_state};

use simrs_consttime::ct_eq;
use simrs_gp_keys::KeySet;
use simrs_iso9797::pad_method2;
use simrs_secret::Secret;

// Internal imports used by process_initialize_update / process_external_authenticate.
use cmac::compute_cryptogram;
use scp01::{scp01_derivation_data, scp01_derive_session_key};
use scp02::scp02_derive_session_key;

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
    /// Secure Channel Protocol 03 (GP 2.3.1 Amendment D).
    Scp03,
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
        /// Derived session S-ENC key (16 bytes).
        session_enc: [u8; 16],
        /// Derived session C-MAC key (16 bytes).
        command_mac: [u8; 16],
        /// Derived session R-MAC key (16 bytes; SCP03 only, zeros for SCP01/02).
        response_mac: [u8; 16],
        /// Derived session DEK key (16 bytes).
        ///
        /// SCP01: `3DES_ECB(static_DEK, derivation_data)` per Appendix D.
        /// SCP02: `3DES_CBC(static_DEK, [0x01, 0x81] || seq || zeros)` per Appendix E.
        /// SCP03: copy of the static DEK from the keystore -- Amendment D § 4.2.4.1
        /// uses the static DEK directly (not session-derived) for PUT KEY unwrapping.
        session_dek: [u8; 16],
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
        command_mac: [u8; 16],
        /// Session R-MAC key.
        response_mac: [u8; 16],
        /// Session DEK key (SCP01/02 only; zero for SCP03).
        session_dek: [u8; 16],
        /// Security level from `EXTERNAL AUTHENTICATE` P1.
        security_level: u8,
        /// ICV / MAC chaining value.
        ///
        /// SCP01/02: only `[0..8]` used (8-byte 3DES MAC).
        /// SCP03: full 16 bytes (AES-CMAC chaining value).
        icv: [u8; 16],
        /// R-MAC running chaining value for SCP01/02 (GP 2.3.1
        /// Appendix E.4.6.2). Initialised to all zeros at BEGIN R-MAC
        /// SESSION; updated to the most recent R-MAC after each
        /// response is wrapped. SCP03 uses its own counter-based
        /// derivation and ignores this field.
        rmac_icv: [u8; 8],
        /// Whether R-MAC session is active.
        rmac_active: bool,
        /// SCP version for this session.
        scp_version: ScpVersion,
        /// SCP03 C-ENC encryption counter (incremented per command).
        /// Unused for SCP01/SCP02.
        enc_counter: u16,
    },
}

// ---------------------------------------------------------------------------
// Response schemas (for semantic comparison)
// ---------------------------------------------------------------------------

/// Response schema for INITIALIZE UPDATE (28-byte fixed layout).
///
/// Field layout:
/// ```text
/// [0..10]   key_diversification   -- Ignore (implementation-specific)
/// [10]      key_version           -- Exact
/// [11]      scp_identifier        -- Exact
/// [12..20]  challenge_region      -- LengthOnly (random/derived)
/// [20..28]  card_cryptogram       -- LengthOnly (derived from session keys)
/// ```
pub static INIT_UPDATE_SCHEMA: simrs_apdu_schema::ResponseSchema =
    simrs_apdu_schema::ResponseSchema {
        name: "INIT_UPDATE",
        expected_len: Some(28),
        fields: &[
            simrs_apdu_schema::FieldSpec {
                name: "key_diversification",
                span: simrs_apdu_schema::FieldSpan::Bytes { offset: 0, len: 10 },
                policy: simrs_apdu_schema::FieldPolicy::Ignore,
            },
            simrs_apdu_schema::FieldSpec {
                name: "key_version",
                span: simrs_apdu_schema::FieldSpan::Bytes { offset: 10, len: 1 },
                policy: simrs_apdu_schema::FieldPolicy::Exact,
            },
            simrs_apdu_schema::FieldSpec {
                name: "scp_identifier",
                span: simrs_apdu_schema::FieldSpan::Bytes { offset: 11, len: 1 },
                policy: simrs_apdu_schema::FieldPolicy::Exact,
            },
            simrs_apdu_schema::FieldSpec {
                name: "challenge_region",
                span: simrs_apdu_schema::FieldSpan::Bytes { offset: 12, len: 8 },
                policy: simrs_apdu_schema::FieldPolicy::LengthOnly,
            },
            simrs_apdu_schema::FieldSpec {
                name: "card_cryptogram",
                span: simrs_apdu_schema::FieldSpan::Bytes { offset: 20, len: 8 },
                policy: simrs_apdu_schema::FieldPolicy::LengthOnly,
            },
        ],
    };

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
    let (session_enc, command_mac, response_mac, session_dek);

    match scp_version {
        ScpVersion::Scp01 => {
            let dd = scp01_derivation_data(*host_challenge, *card_challenge);
            session_enc = scp01_derive_session_key(keys.enc(), &dd);
            command_mac = scp01_derive_session_key(keys.mac(), &dd);
            session_dek = scp01_derive_session_key(keys.dek(), &dd);
            // SCP01 has no separate R-MAC key; PUT KEY / response auth uses
            // the same MAC scheme as commands.
            response_mac = [0u8; 16];
        }
        ScpVersion::Scp02 => {
            let seq = sequence_counter.unwrap_or(0);
            session_enc = scp02_derive_session_key(keys.enc(), [0x01, 0x82], seq);
            command_mac = scp02_derive_session_key(keys.mac(), [0x01, 0x01], seq);
            response_mac = scp02_derive_session_key(keys.mac(), [0x01, 0x02], seq);
            session_dek = scp02_derive_session_key(keys.dek(), [0x01, 0x81], seq);
        }
        ScpVersion::Scp03 => unreachable!("use process_*_scp03"),
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
        ScpVersion::Scp03 => unreachable!("use process_*_scp03"),
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
        ScpVersion::Scp03 => unreachable!("use process_*_scp03"),
    }
    response[20..28].copy_from_slice(&card_cryptogram);

    let seq = sequence_counter.unwrap_or(0);
    *state = ScpState::InitUpdateDone {
        host_challenge: *host_challenge,
        card_challenge: *card_challenge,
        key_diversification: *key_diversification,
        session_enc,
        command_mac,
        response_mac,
        session_dek,
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
    let extracted = extract_init_update_done_for_scp01_02(state)?;
    let host_cryptogram = &host_cryptogram_and_mac[0..8];
    let received_cmac = &host_cryptogram_and_mac[8..16];

    let expected_host_cryptogram = compute_expected_host_cryptogram_scp01_02(
        extracted.scp_version,
        &extracted.session_enc,
        extracted.host_challenge,
        extracted.card_challenge,
        extracted.seq_counter,
    );

    // Constant-time comparison. Keep InitUpdateDone on failure: GP 2.1.1
    // does not mandate session abandonment before the session is
    // established. Keeping the state allows terminal retry and ensures
    // uniform error responses for the padding oracle defence
    // (Avoine & Ferreira, TCHES 2018).
    if !ct_eq(host_cryptogram, &expected_host_cryptogram).into_bool() {
        return Err(ScpError::HostCryptogramMismatch);
    }

    let expected_cmac = compute_external_authenticate_cmac_scp01_02(
        extracted.scp_version,
        &extracted.command_mac,
        security_level,
        host_cryptogram,
    );

    if !ct_eq(received_cmac, &expected_cmac).into_bool() {
        return Err(ScpError::CmacMismatch);
    }

    // The C-MAC we just verified becomes the ICV for the next command (SCP02).
    // Store in the first 8 bytes of the 16-byte ICV field.
    // The C-MAC we just verified becomes the ICV for the next command (SCP02).
    let mut next_icv = [0u8; 16];
    next_icv[0..8].copy_from_slice(&expected_cmac);

    *state = ScpState::Authenticated {
        session_enc: extracted.session_enc,
        command_mac: extracted.command_mac,
        response_mac: extracted.response_mac,
        session_dek: extracted.session_dek,
        security_level,
        icv: next_icv,
        rmac_icv: [0u8; 8],
        rmac_active: false,
        scp_version: extracted.scp_version,
        enc_counter: 0,
    };

    Ok(())
}

/// State extracted from `InitUpdateDone` for SCP01/SCP02 EXTERNAL AUTHENTICATE.
struct InitUpdateDoneScp01Or02 {
    host_challenge: [u8; 8],
    card_challenge: [u8; 8],
    session_enc: [u8; 16],
    command_mac: [u8; 16],
    response_mac: [u8; 16],
    session_dek: [u8; 16],
    scp_version: ScpVersion,
    seq_counter: u16,
}

/// Pull the relevant fields out of `InitUpdateDone`. Returns
/// `InvalidState` if the SCP state isn't in the expected variant.
const fn extract_init_update_done_for_scp01_02(
    state: &ScpState,
) -> Result<InitUpdateDoneScp01Or02, ScpError> {
    match state {
        ScpState::InitUpdateDone {
            host_challenge,
            card_challenge,
            session_enc,
            command_mac,
            response_mac,
            session_dek,
            scp_version,
            sequence_counter,
            ..
        } => Ok(InitUpdateDoneScp01Or02 {
            host_challenge: *host_challenge,
            card_challenge: *card_challenge,
            session_enc: *session_enc,
            command_mac: *command_mac,
            response_mac: *response_mac,
            session_dek: *session_dek,
            scp_version: *scp_version,
            seq_counter: *sequence_counter,
        }),
        _ => Err(ScpError::InvalidState),
    }
}

/// Compute the expected host cryptogram per SCP01/SCP02 spec.
///
/// - **SCP01:** `MAC(session_ENC, card_challenge || host_challenge)` per Appendix D.
/// - **SCP02:** `MAC(session_ENC, seq[2] || card_challenge[2..8] || host_challenge)`
///   per Appendix E.
fn compute_expected_host_cryptogram_scp01_02(
    scp_version: ScpVersion,
    session_enc: &[u8; 16],
    host_challenge: [u8; 8],
    card_challenge: [u8; 8],
    seq_counter: u16,
) -> [u8; 8] {
    let mut input = [0u8; 16];
    match scp_version {
        ScpVersion::Scp01 => {
            input[0..8].copy_from_slice(&card_challenge);
            input[8..16].copy_from_slice(&host_challenge);
        }
        ScpVersion::Scp02 => {
            #[allow(clippy::cast_possible_truncation)]
            {
                input[0] = (seq_counter >> 8) as u8;
                input[1] = seq_counter as u8;
            }
            input[2..8].copy_from_slice(&card_challenge[2..8]);
            input[8..16].copy_from_slice(&host_challenge);
        }
        ScpVersion::Scp03 => unreachable!("use process_*_scp03"),
    }
    compute_cryptogram(session_enc, &input)
}

/// Compute the expected C-MAC over the EXTERNAL AUTHENTICATE APDU header
/// per SCP01/SCP02 spec.
///
/// MAC input: `0x84 || 0x82 || P1 || 0x00 || 0x10 || host_cryptogram[8]`,
/// padded with ISO 9797-1 method 2 to a multiple of 8 bytes. The effective
/// ICV differs by SCP version (SCP01: zero; SCP02: single-DES ECB on zero
/// using the left half of `command_mac`).
fn compute_external_authenticate_cmac_scp01_02(
    scp_version: ScpVersion,
    command_mac: &[u8; 16],
    security_level: u8,
    host_cryptogram: &[u8],
) -> [u8; 8] {
    let cmac_key = Secret::new(*command_mac);
    let mut cmac_input_buf = [0u8; 24];
    let cmac_data = [
        0x84,
        0x82,
        security_level,
        0x00,
        0x10,
        host_cryptogram[0],
        host_cryptogram[1],
        host_cryptogram[2],
        host_cryptogram[3],
        host_cryptogram[4],
        host_cryptogram[5],
        host_cryptogram[6],
        host_cryptogram[7],
    ];
    let padded_len = pad_method2(&cmac_data, 8, &mut cmac_input_buf);

    let effective_icv = match scp_version {
        // GP 2.3.1 Appendix D.4.1.4 (SCP01): the C-MAC ICV for the first
        // command in a session is 8 zero bytes; subsequent C-MACs chain
        // from the prior C-MAC. Zero ICV is spec-mandated -- CodeQL
        // false positive on `rust/hard-coded-cryptographic-value`.
        ScpVersion::Scp01 => [0u8; 8],
        // GP 2.3.1 Appendix E.4.4 (SCP02): the C-MAC ICV is
        // single-DES_ECB(C-MAC_key, [0u8; 8]) for the first command.
        // The starting all-zero block here is the spec-defined seed,
        // not a secret -- CodeQL false positive.
        ScpVersion::Scp02 => des_ecb_encrypt_left_half(command_mac, [0u8; 8]),
        ScpVersion::Scp03 => unreachable!("use process_*_scp03"),
    };

    des3_2key_cbc_mac_with_iv(&cmac_key, effective_icv, &cmac_input_buf[..padded_len])
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
// Public API -- INITIALIZE UPDATE for SCP03
// ---------------------------------------------------------------------------

/// Process `INITIALIZE UPDATE` for SCP03.
///
/// Derives session keys (S-ENC, S-MAC, S-RMAC) using AES-CMAC KDF and
/// computes the card cryptogram. The response layout depends on the
/// configured `i_param` (GP 2.3.1 Amendment D § 6.2):
///
/// **Random card challenge** (`i & 0x40 == 0`, 29 bytes):
/// ```text
/// key_diversification[10] || key_version[1] || 0x03[1] || i_param[1]
///   || card_challenge[8] || card_cryptogram[8]
/// ```
///
/// **Pseudo-random card challenge** (`i & 0x40 != 0`, 32 bytes):
/// ```text
/// key_diversification[10] || key_version[1] || 0x03[1] || i_param[1]
///   || card_challenge[8] || card_cryptogram[8] || sequence_counter[3]
/// ```
///
/// Recognised `i_param` bits (Amd D Table 6-1):
/// - `0x10`: card supports R-MAC on response messages.
/// - `0x20`: card supports R-ENC on response messages.
/// - `0x40`: pseudo-random card challenge mode (otherwise random).
///
/// Bits not honoured today are accepted-but-ignored: the function still
/// emits the correct response size and stores the configured `i_param`
/// in `state` for follow-up processing. To preserve current behaviour for
/// callers that don't care about `i`, pass `0x00`.
///
/// Returns `(buffer, len)` where `len` is 29 or 32. The buffer is fixed
/// at 32 bytes; bytes past `len` are zero.
#[allow(clippy::too_many_arguments)]
pub fn process_initialize_update_scp03(
    state: &mut ScpState,
    key_version: u8,
    host_challenge: &[u8; 8],
    keys: &KeySet,
    card_challenge: &[u8; 8],
    key_diversification: &[u8; 10],
    i_param: u8,
    sequence_counter: u32,
) -> ([u8; 32], usize) {
    // Derive session keys via AES-CMAC KDF.
    let mut static_enc = [0u8; 16];
    static_enc.copy_from_slice(&keys.enc()[..16]);
    let mut static_mac = [0u8; 16];
    static_mac.copy_from_slice(&keys.mac()[..16]);

    let (s_enc, command_mac, response_mac) =
        scp03::derive_session_keys(&static_enc, &static_mac, host_challenge, card_challenge);

    // Compute card cryptogram.
    let card_cryptogram =
        scp03::compute_card_cryptogram(&command_mac, host_challenge, card_challenge);

    // Build response. Header is identical across modes.
    let mut response = [0u8; 32];
    response[0..10].copy_from_slice(key_diversification);
    response[10] = key_version;
    response[11] = 0x03; // SCP03 identifier
    response[12] = i_param;
    response[13..21].copy_from_slice(card_challenge);
    response[21..29].copy_from_slice(&card_cryptogram);

    let pseudo_random = i_param & 0x40 != 0;
    let len = if pseudo_random {
        // Sequence counter (3 bytes, big-endian) appended after the
        // cryptogram. Per Amd D § 6.2.2 the counter is the running
        // pseudo-random challenge counter; callers track it.
        #[allow(clippy::cast_possible_truncation)]
        {
            response[29] = (sequence_counter >> 16) as u8;
            response[30] = (sequence_counter >> 8) as u8;
            response[31] = sequence_counter as u8;
        }
        32
    } else {
        29
    };

    // SCP03 PUT KEY (Amendment D § 4.2.4.1) wraps key components with the
    // *static* DEK directly, not a session-derived one. Stash it here so
    // EXTERNAL AUTHENTICATE can copy it through to Authenticated.
    let mut static_dek = [0u8; 16];
    static_dek.copy_from_slice(&keys.dek()[..16]);

    // Store intermediate state for EXTERNAL AUTHENTICATE. SCP03 doesn't
    // use the persistent SCP02 16-bit counter, so `sequence_counter` in the
    // state stays at zero; the 24-bit pseudo-random counter is encoded into
    // `card_challenge` derivation by callers (Phase 1.5).
    *state = ScpState::InitUpdateDone {
        host_challenge: *host_challenge,
        card_challenge: *card_challenge,
        key_diversification: *key_diversification,
        session_enc: s_enc,
        command_mac,
        response_mac,
        session_dek: static_dek,
        card_cryptogram,
        scp_version: ScpVersion::Scp03,
        sequence_counter: 0,
    };

    (response, len)
}

// ---------------------------------------------------------------------------
// Public API -- EXTERNAL AUTHENTICATE for SCP03
// ---------------------------------------------------------------------------

/// Process `EXTERNAL AUTHENTICATE` for SCP03.
///
/// Verifies the host cryptogram and C-MAC using AES-CMAC (not 3DES).
/// On success, transitions to `Authenticated` state.
#[allow(clippy::missing_errors_doc)]
pub fn process_external_authenticate_scp03(
    state: &mut ScpState,
    security_level: u8,
    host_cryptogram_and_mac: &[u8; 16],
) -> Result<(), ScpError> {
    let (host_challenge, card_challenge, s_enc, command_mac, response_mac, s_dek) = match state {
        ScpState::InitUpdateDone {
            host_challenge,
            card_challenge,
            session_enc,
            command_mac,
            response_mac,
            session_dek,
            scp_version: ScpVersion::Scp03,
            ..
        } => (
            *host_challenge,
            *card_challenge,
            *session_enc,
            *command_mac,
            *response_mac,
            *session_dek,
        ),
        _ => return Err(ScpError::InvalidState),
    };

    let host_cryptogram = &host_cryptogram_and_mac[0..8];
    let received_mac = &host_cryptogram_and_mac[8..16];

    // Verify host cryptogram.
    let expected_host_crypto =
        scp03::compute_host_cryptogram(&command_mac, &host_challenge, &card_challenge);

    if !ct_eq(host_cryptogram, &expected_host_crypto).into_bool() {
        return Err(ScpError::HostCryptogramMismatch);
    }

    // Verify C-MAC on the EXTERNAL AUTHENTICATE command.
    // APDU: CLA=0x84, INS=0x82, P1=security_level, P2=0x00
    let (expected_mac, new_chaining) = scp03::generate_cmac(
        &command_mac,
        &[0u8; 16], // initial chaining value (zeros for first command)
        &[0x84, 0x82, security_level, 0x00],
        host_cryptogram,
    );

    if !ct_eq(received_mac, &expected_mac).into_bool() {
        return Err(ScpError::CmacMismatch);
    }

    *state = ScpState::Authenticated {
        session_enc: s_enc,
        command_mac,
        response_mac,
        // SCP03 stores the static DEK from the keystore (per Amd D § 4.2.4.1
        // PUT KEY uses the static DEK directly, not a session-derived one).
        session_dek: s_dek,
        security_level,
        icv: new_chaining,
        // SCP03 derives R-MAC chaining from its own counter; this field is
        // unused for SCP03 but kept zeroed for snapshot symmetry.
        rmac_icv: [0u8; 8],
        rmac_active: security_level & 0x10 != 0,
        scp_version: ScpVersion::Scp03,
        enc_counter: 0,
    };

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CodeQL note for test fixtures below
// ---------------------------------------------------------------------------
//
// Several tests in this module pass `[0u8; 8]` as the initial ICV /
// IV to `generate_cmac` or `des3_2key_cbc_mac_with_iv`. CodeQL flags
// these as `rust/hard-coded-cryptographic-value`. They are NOT
// vulnerabilities -- the zero value is the spec-mandated initial
// chaining value:
//
//   - GP 2.3.1 Appendix D.4.1.4 (SCP01): the first C-MAC of a session
//     is computed with ICV = 8 zero bytes; subsequent C-MACs chain
//     from the previous C-MAC.
//   - GP 2.3.1 Appendix E.4.4 (SCP02): the first C-MAC is computed
//     with ICV derived from the all-zero block under the C-MAC key;
//     the starting block is spec-defined to be all zeros.
//   - GP 2.3.1 Appendix E.6 (R-MAC seed): `BEGIN R-MAC SESSION` data
//     is hashed via `CBC-MAC(S-RMAC, IV = 0, Method-2-pad(data))`.
//
// Tests use the same zero seed to compute reference values that the
// production code is asserted equal to. The differential
// cross-validation suite (`tests/simrs-differential-crossvalidation`)
// then confirms the production output matches Oracle JCDK and
// martinpaljak's JCardEngine independently.

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_gp_keys::KeySet;
    use simrs_iso7816::write_apdu_with_data;
    use simrs_iso9797::{
        des3_2key_cbc_encrypt, des3_2key_cbc_mac, des3_2key_ecb_encrypt, pad_method2,
    };
    use simrs_secret::Secret;

    #[test]
    fn seed_rmac_chain_empty_data_returns_zero() {
        let key = [0xAAu8; 16];
        assert_eq!(seed_rmac_chain_scp02(&key, &[]), [0u8; 8]);
    }

    #[test]
    fn seed_rmac_chain_matches_padded_cbc_mac_reference() {
        // Compute the helper's output and an independent CBC-MAC over
        // Method-2-padded(data) and assert byte equality.
        let key_bytes = [0x40u8; 16];
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let observed = seed_rmac_chain_scp02(&key_bytes, &data);

        let mut padded = [0u8; 32];
        let padded_len = pad_method2(&data, 8, &mut padded);
        let key = Secret::new(key_bytes);
        let expected = des3_2key_cbc_mac_with_iv(&key, [0u8; 8], &padded[..padded_len]);
        assert_eq!(observed, expected);
    }

    #[test]
    #[should_panic(expected = "exceeds 24-byte spec limit")]
    fn seed_rmac_chain_panics_on_data_over_24_bytes() {
        let key = [0u8; 16];
        let too_long = [0u8; 25];
        let _ = seed_rmac_chain_scp02(&key, &too_long);
    }

    // Re-import pub(crate) items for tests.
    use crate::cmac::unpad_method2;
    use crate::scp01::{scp01_derivation_data, scp01_derive_session_key};
    use crate::scp02::scp02_derive_session_key;

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

        let (session_enc, command_mac, session_dek) = derive_scp01_session_keys(&keys, &hc, &cc);

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
        assert_eq!(command_mac, expected_mac);
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
        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        // Compute host cryptogram.
        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);

        // Compute C-MAC for EXTERNAL AUTHENTICATE.
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
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

        // State stays in InitUpdateDone (allows retry, uniform error response).
        assert!(matches!(state, ScpState::InitUpdateDone { .. }));
    }

    // ----- Test 5: SCP02 session key derivation with sequence counter -----

    #[test]
    fn scp02_session_key_derivation() {
        let keys = test_keys();

        // Sequence counter 0x0000.
        let (enc, mac, rmac, dek) = derive_scp02_session_keys(&keys, 0x0000);

        // Independently compute session keys.
        let expected_enc = scp02_derive_session_key(keys.enc(), [0x01, 0x82], 0x0000);
        let expected_command_mac = scp02_derive_session_key(keys.mac(), [0x01, 0x01], 0x0000);
        let expected_response_mac = scp02_derive_session_key(keys.mac(), [0x01, 0x02], 0x0000);
        let expected_dek = scp02_derive_session_key(keys.dek(), [0x01, 0x81], 0x0000);

        assert_eq!(enc, expected_enc);
        assert_eq!(mac, expected_command_mac);
        assert_eq!(rmac, expected_response_mac);
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

        let (_, command_mac, _) = derive_scp01_session_keys(&keys, &hc, &cc);

        // GET STATUS: 80 F2 80 00 02 4F 00
        let header = [0x80, 0xF2, 0x80, 0x00];
        let data = [0x4F, 0x00];
        let icv = [0u8; 8];

        let (mac, _) = generate_cmac(&command_mac, &header, &data, &icv, ScpVersion::Scp01);

        // Independently compute:
        // Input = 84 F2 80 00 0A 4F 00  (CLA|=0x04, Lc = 2+8 = 10)
        // Padded with Method 2: 84 F2 80 00 0A 4F 00 80  (8 bytes, already aligned)
        let mac_input = [0x84, 0xF2, 0x80, 0x00, 0x0A, 0x4F, 0x00];
        let mut padded = [0u8; 16];
        let padded_len = pad_method2(&mac_input, 8, &mut padded);
        let mac_key = Secret::new(command_mac);
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
        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        // Complete authentication.
        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
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
            generate_cmac(&command_mac, &header, &data, &[0u8; 8], ScpVersion::Scp01);

        // Build APDU with CLA = 0x84 (with-C-MAC variant of GET STATUS).
        // Body = `data || MAC`.
        let mut body = [0u8; 10];
        body[..2].copy_from_slice(&data);
        body[2..].copy_from_slice(&cmd_mac);
        let mut buf = [0u8; 15];
        let apdu = write_apdu_with_data(&mut buf, 0x84, 0xF2, 0x80, 0x00, &body);

        let mut output = [0u8; 256];
        let result = unwrap_command(&mut state, apdu, &mut output);
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
        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        assert!(process_external_authenticate(&mut state, 0x01, &crypto_and_mac).is_ok());

        // Send a command with a bad C-MAC. Body = `4F 00 || FF*8`.
        let mut body = [0u8; 10];
        body[..2].copy_from_slice(&[0x4F, 0x00]);
        body[2..].copy_from_slice(&[0xFF; 8]);
        let mut buf = [0u8; 15];
        let apdu = write_apdu_with_data(&mut buf, 0x84, 0xF2, 0x80, 0x00, &body);

        let mut output = [0u8; 256];
        let result = unwrap_command(&mut state, apdu, &mut output);
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
        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
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

        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
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
                    command_mac: mac1,
                    security_level: sl1,
                    icv: icv1,
                    scp_version: sv1,
                    ..
                },
                ScpState::Authenticated {
                    session_enc: enc2,
                    command_mac: mac2,
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

        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
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
            &command_mac,
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

        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
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

        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
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

    // ----- SCP03 tests -----

    fn test_aes_keys() -> KeySet {
        let k = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        KeySet::aes128(k, k, k)
    }

    #[test]
    fn scp03_session_key_derivation() {
        let static_key = [0x40u8; 16];
        let hc = test_host_challenge();
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        let (s_enc, command_mac, response_mac) =
            derive_scp03_session_keys(&static_key, &static_key, &hc, &cc);

        assert_ne!(s_enc, command_mac, "S-ENC and S-MAC should differ");
        assert_ne!(command_mac, response_mac, "S-MAC and S-RMAC should differ");
        assert_ne!(s_enc, response_mac, "S-ENC and S-RMAC should differ");
        assert_ne!(s_enc, [0u8; 16]);
        assert_ne!(command_mac, [0u8; 16]);
        assert_ne!(response_mac, [0u8; 16]);
    }

    #[test]
    fn scp03_cryptograms_differ() {
        let command_mac = [0x40u8; 16];
        let hc = test_host_challenge();
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        let card_crypto = compute_scp03_card_cryptogram(&command_mac, &hc, &cc);
        let host_crypto = compute_scp03_host_cryptogram(&command_mac, &hc, &cc);

        assert_ne!(
            card_crypto, host_crypto,
            "card and host cryptograms should differ"
        );
        assert_ne!(card_crypto, [0u8; 8]);
        assert_ne!(host_crypto, [0u8; 8]);
    }

    #[test]
    fn scp03_cross_validate_determinism() {
        let static_enc = [0x40u8; 16];
        let static_mac = [0x40u8; 16];
        let hc = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        let (s_enc, command_mac, response_mac) =
            derive_scp03_session_keys(&static_enc, &static_mac, &hc, &cc);

        // Same inputs -> same outputs.
        let (s_enc_again, command_mac_again, response_mac_again) =
            derive_scp03_session_keys(&static_enc, &static_mac, &hc, &cc);
        assert_eq!(s_enc, s_enc_again);
        assert_eq!(command_mac, command_mac_again);
        assert_eq!(response_mac, response_mac_again);

        // Changing one byte of host challenge changes all keys.
        let mut hc2 = hc;
        hc2[0] ^= 0x01;
        let (s_enc_other, command_mac_other, response_mac_other) =
            derive_scp03_session_keys(&static_enc, &static_mac, &hc2, &cc);
        assert_ne!(s_enc, s_enc_other);
        assert_ne!(command_mac, command_mac_other);
        assert_ne!(response_mac, response_mac_other);
    }

    /// Phase 1.5 #1 plumbing check: `session_dek` must be the spec-correct
    /// derived value in `InitUpdateDone`, and the same value must transit
    /// to `Authenticated` after EXTERNAL AUTHENTICATE. Before this plumbing
    /// landed, `session_dek` in `Authenticated` was always `[0u8; 16]`.
    #[test]
    fn scp01_session_dek_is_derived_and_propagates_to_authenticated() {
        let keys = test_keys();
        let hc = test_host_challenge();
        let cc = test_card_challenge_scp01();
        let kdiv = test_key_diversification();

        // SCP01 derives session_dek with the same derivation_data as ENC/MAC.
        let dd = scp01_derivation_data(hc, cc);
        let expected_dek = scp01_derive_session_key(keys.dek(), &dd);
        assert_ne!(expected_dek, [0u8; 16], "expected_dek must be non-trivial");

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

        match &state {
            ScpState::InitUpdateDone { session_dek, .. } => {
                assert_eq!(
                    *session_dek, expected_dek,
                    "session_dek in InitUpdateDone must equal scp01_derive_session_key(static_DEK, dd)"
                );
            }
            _ => panic!("expected InitUpdateDone"),
        }

        // Drive EXTERNAL AUTHENTICATE through to Authenticated.
        let session_enc = match &state {
            ScpState::InitUpdateDone { session_enc, .. } => *session_enc,
            _ => unreachable!(),
        };
        let command_mac = match &state {
            ScpState::InitUpdateDone { command_mac, .. } => *command_mac,
            _ => unreachable!(),
        };
        let host_crypto = compute_scp01_host_cryptogram(&session_enc, &hc, &cc);
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp01,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        process_external_authenticate(&mut state, 0x01, &crypto_and_mac).unwrap();

        match &state {
            ScpState::Authenticated { session_dek, .. } => {
                assert_eq!(
                    *session_dek, expected_dek,
                    "session_dek must propagate unchanged from InitUpdateDone to Authenticated"
                );
            }
            _ => panic!("expected Authenticated"),
        }
    }

    /// SCP02 `session_dek` = `3DES_CBC(static_DEK, [0x01, 0x81] || seq || zeros)`.
    #[test]
    fn scp02_session_dek_is_derived_and_propagates_to_authenticated() {
        let keys = test_keys();
        let hc = test_host_challenge();
        // SCP02: 6-byte card challenge stored in cc[2..8].
        let cc = [0x00, 0x00, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6];
        let kdiv = test_key_diversification();
        let seq: u16 = 0x0042;

        // Compute the expected SCP02 session DEK independently.
        let expected_dek = derive_scp02_session_key(keys.dek(), [0x01, 0x81], seq);
        assert_ne!(expected_dek, [0u8; 16], "expected_dek must be non-trivial");

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update(
            &mut state,
            ScpVersion::Scp02,
            0x01,
            &hc,
            &keys,
            &cc,
            &kdiv,
            Some(seq),
        );

        match &state {
            ScpState::InitUpdateDone { session_dek, .. } => {
                assert_eq!(
                    *session_dek, expected_dek,
                    "SCP02 session_dek must equal derive_scp02_session_key(static_DEK, [0x01,0x81], seq)"
                );
            }
            _ => panic!("expected InitUpdateDone"),
        }

        // Drive EXT AUTH and check the value transits to Authenticated.
        let (session_enc, command_mac) = match &state {
            ScpState::InitUpdateDone {
                session_enc,
                command_mac,
                ..
            } => (*session_enc, *command_mac),
            _ => unreachable!(),
        };
        let host_crypto =
            compute_scp02_host_cryptogram(&session_enc, &hc, seq, &cc[2..8].try_into().unwrap());
        let (ext_auth_mac, _) = generate_cmac(
            &command_mac,
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
            &[0u8; 8],
            ScpVersion::Scp02,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        process_external_authenticate(&mut state, 0x01, &crypto_and_mac).unwrap();

        match &state {
            ScpState::Authenticated { session_dek, .. } => {
                assert_eq!(*session_dek, expected_dek);
            }
            _ => panic!("expected Authenticated"),
        }
    }

    /// SCP03 stores the static DEK directly (Amd D § 4.2.4.1 wraps with
    /// the static DEK, not a session-derived one).
    #[test]
    fn scp03_session_dek_is_static_dek_and_propagates_to_authenticated() {
        let keys = test_aes_keys();
        let hc = test_host_challenge();
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let kdiv = test_key_diversification();

        let mut expected_dek = [0u8; 16];
        expected_dek.copy_from_slice(&keys.dek()[..16]);

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update_scp03(&mut state, 0x01, &hc, &keys, &cc, &kdiv, 0x00, 0);

        match &state {
            ScpState::InitUpdateDone { session_dek, .. } => {
                assert_eq!(
                    *session_dek, expected_dek,
                    "SCP03 'session_dek' must be the static DEK (Amd D § 4.2.4.1)"
                );
            }
            _ => panic!("expected InitUpdateDone"),
        }

        // Drive EXT AUTH and confirm the static DEK transits to Authenticated.
        let command_mac = match &state {
            ScpState::InitUpdateDone { command_mac, .. } => *command_mac,
            _ => unreachable!(),
        };
        let host_crypto = compute_scp03_host_cryptogram(&command_mac, &hc, &cc);
        let (ext_auth_mac, _) = scp03_generate_cmac(
            &command_mac,
            &[0u8; 16],
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
        );
        let mut crypto_and_mac = [0u8; 16];
        crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);
        process_external_authenticate_scp03(&mut state, 0x01, &crypto_and_mac).unwrap();

        match &state {
            ScpState::Authenticated { session_dek, .. } => {
                assert_eq!(*session_dek, expected_dek);
            }
            _ => panic!("expected Authenticated"),
        }
    }

    #[test]
    fn scp03_full_authentication_roundtrip() {
        let keys = test_aes_keys();
        let hc = test_host_challenge();
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let (response, len) =
            process_initialize_update_scp03(&mut state, 0x01, &hc, &keys, &cc, &kdiv, 0x00, 0);

        assert_eq!(len, 29);
        assert_eq!(&response[0..10], &kdiv);
        assert_eq!(response[10], 0x01); // key version
        assert_eq!(response[11], 0x03); // SCP03 identifier
        assert_eq!(response[12], 0x00); // i parameter
        assert_eq!(&response[13..21], &cc);

        assert!(matches!(
            state,
            ScpState::InitUpdateDone {
                scp_version: ScpVersion::Scp03,
                ..
            }
        ));

        let command_mac = match &state {
            ScpState::InitUpdateDone { command_mac, .. } => *command_mac,
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp03_host_cryptogram(&command_mac, &hc, &cc);

        let (ext_auth_mac, _) = scp03_generate_cmac(
            &command_mac,
            &[0u8; 16],
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
        );

        let mut host_crypto_and_mac = [0u8; 16];
        host_crypto_and_mac[0..8].copy_from_slice(&host_crypto);
        host_crypto_and_mac[8..16].copy_from_slice(&ext_auth_mac);

        let result = process_external_authenticate_scp03(&mut state, 0x01, &host_crypto_and_mac);
        assert!(result.is_ok(), "SCP03 EXT AUTH failed: {result:?}");

        assert!(matches!(
            state,
            ScpState::Authenticated {
                scp_version: ScpVersion::Scp03,
                security_level: 0x01,
                ..
            }
        ));
    }

    #[test]
    fn scp03_wrong_host_cryptogram() {
        let keys = test_aes_keys();
        let hc = test_host_challenge();
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update_scp03(&mut state, 0x01, &hc, &keys, &cc, &kdiv, 0x00, 0);

        let bad_crypto_and_mac = [0xFF; 16];
        let result = process_external_authenticate_scp03(&mut state, 0x00, &bad_crypto_and_mac);
        assert_eq!(result, Err(ScpError::HostCryptogramMismatch));
        assert!(matches!(state, ScpState::InitUpdateDone { .. }));
    }

    #[test]
    fn scp03_cmac_chaining() {
        let command_mac = [0x40u8; 16];
        let initial_cv = [0u8; 16];

        let (mac1, cv1) = scp03_generate_cmac(
            &command_mac,
            &initial_cv,
            &[0x84, 0xF2, 0x80, 0x00],
            &[0x4F, 0x00],
        );

        let (mac2, cv2) =
            scp03_generate_cmac(&command_mac, &cv1, &[0x84, 0xF2, 0x40, 0x00], &[0x4F, 0x00]);

        assert_ne!(mac1, mac2, "chained MACs should differ");
        assert_ne!(cv1, cv2);
        assert_ne!(cv1, initial_cv);
    }

    #[test]
    fn scp03_snapshot_authenticated_roundtrip() {
        let keys = test_aes_keys();
        let hc = test_host_challenge();
        let cc = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let kdiv = test_key_diversification();

        let mut state = ScpState::NoSession;
        let _ = process_initialize_update_scp03(&mut state, 0x01, &hc, &keys, &cc, &kdiv, 0x00, 0);

        let command_mac = match &state {
            ScpState::InitUpdateDone { command_mac, .. } => *command_mac,
            _ => panic!("expected InitUpdateDone"),
        };

        let host_crypto = compute_scp03_host_cryptogram(&command_mac, &hc, &cc);
        let (ext_auth_mac, _) = scp03_generate_cmac(
            &command_mac,
            &[0u8; 16],
            &[0x84, 0x82, 0x01, 0x00],
            &host_crypto,
        );

        let mut hcm = [0u8; 16];
        hcm[0..8].copy_from_slice(&host_crypto);
        hcm[8..16].copy_from_slice(&ext_auth_mac);
        assert!(process_external_authenticate_scp03(&mut state, 0x01, &hcm).is_ok());

        let mut buf = [0u8; SCP_STATE_SNAPSHOT_SIZE];
        let written = save_scp_state(&state, &mut buf);
        assert!(written > 0);

        let mut restored = ScpState::NoSession;
        assert!(restore_scp_state(&mut restored, &buf[..written]));
        assert!(matches!(
            restored,
            ScpState::Authenticated {
                scp_version: ScpVersion::Scp03,
                security_level: 0x01,
                ..
            }
        ));
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
