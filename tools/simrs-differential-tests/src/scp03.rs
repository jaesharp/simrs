//! SCP03 re-exports from `simrs-gp-scp` for differential testing.
//!
//! This module provides thin wrappers around the real SCP03 implementation
//! in `simrs-gp-scp::scp03` with function names and types that match the
//! differential test call sites.

pub use simrs_gp_scp::scp03::{
    parse_init_update as parse_scp03_init_update, Scp03InitUpdateResponse,
};

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
/// Wraps [`simrs_gp_scp::scp03::derive_session_keys`] into a
/// [`Scp03SessionKeys`] struct for ergonomic field access.
#[allow(clippy::similar_names)]
pub fn derive_scp03_session_keys(
    static_enc: &[u8; 16],
    static_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> Scp03SessionKeys {
    let (s_enc, s_mac, s_rmac) = simrs_gp_scp::scp03::derive_session_keys(
        static_enc,
        static_mac,
        host_challenge,
        card_challenge,
    );
    Scp03SessionKeys {
        s_enc,
        s_mac,
        s_rmac,
    }
}

/// Compute the SCP03 card cryptogram for verification.
pub fn compute_scp03_card_cryptogram(
    s_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    simrs_gp_scp::scp03::compute_card_cryptogram(s_mac, host_challenge, card_challenge)
}

/// Compute the SCP03 host cryptogram.
pub fn compute_scp03_host_cryptogram(
    s_mac: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 8] {
    simrs_gp_scp::scp03::compute_host_cryptogram(s_mac, host_challenge, card_challenge)
}

/// Compute SCP03 C-MAC for an APDU command.
///
/// Returns (8-byte MAC, 16-byte new chaining value).
pub fn scp03_cmac(
    s_mac: &[u8; 16],
    mac_chaining_value: &[u8; 16],
    apdu_header: &[u8; 4],
    data: &[u8],
) -> ([u8; 8], [u8; 16]) {
    simrs_gp_scp::scp03::generate_cmac(s_mac, mac_chaining_value, apdu_header, data)
}
