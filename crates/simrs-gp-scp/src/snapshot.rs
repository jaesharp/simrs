//! Snapshot (save/restore) support for [`ScpState`].

use crate::{ScpState, ScpVersion};

/// Snapshot size for [`ScpState`].
///
/// Layout:
/// - 1 byte: variant tag (0 = `NoSession`, 1 = `InitUpdateDone`, 2/4 = `Authenticated`)
/// - For `InitUpdateDone` (tag 1): 8+8+10+16+16+8+1+2 = 69 bytes
/// - For `Authenticated` SCP01/02 (tag 2): 16+16+16+16+1+8+1+1 = 75 bytes
/// - For `Authenticated` SCP03 (tag 4): 16+16+16+16+1+16+1+1+2 = 85 bytes
///
/// Maximum: 1 + 85 = 86 bytes.
pub const SCP_STATE_SNAPSHOT_SIZE: usize = 86;

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
            session_rmac: _, // not saved in legacy format; re-derived if needed
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
                ScpVersion::Scp03 => 0x03,
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
            enc_counter,
        } => {
            let is_scp03 = matches!(scp_version, ScpVersion::Scp03);
            buf[off] = if is_scp03 { 4 } else { 2 };
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
            if is_scp03 {
                // SCP03: full 16-byte ICV + 2-byte enc_counter
                buf[off..off + 16].copy_from_slice(icv);
                off += 16;
                buf[off] = u8::from(*rmac_active);
                off += 1;
                buf[off] = 0x03;
                off += 1;
                buf[off] = (*enc_counter >> 8) as u8;
                buf[off + 1] = *enc_counter as u8;
                off += 2;
            } else {
                // SCP01/02: 8-byte ICV, no enc_counter
                buf[off..off + 8].copy_from_slice(&icv[0..8]);
                off += 8;
                buf[off] = u8::from(*rmac_active);
                off += 1;
                buf[off] = match scp_version {
                    ScpVersion::Scp01 => 0x01,
                    ScpVersion::Scp02 => 0x02,
                    ScpVersion::Scp03 => unreachable!(),
                };
                off += 1;
            }
        }
    }
    off
}

/// Restore SCP state from a buffer. Returns `true` on success.
#[allow(clippy::similar_names, clippy::too_many_lines)]
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
                0x03 => ScpVersion::Scp03,
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
                session_rmac: [0u8; 16], // not persisted in legacy format
                card_cryptogram,
                scp_version,
                sequence_counter,
            };
            true
        }
        2 => {
            // SCP01/02 Authenticated (legacy format: 8-byte ICV)
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
            let mut icv = [0u8; 16];
            icv[0..8].copy_from_slice(&buf[off..off + 8]);
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
                enc_counter: 0,
            };
            true
        }
        4 => {
            // SCP03 Authenticated (extended: 16-byte ICV + enc_counter)
            if buf.len() < 86 {
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
            let mut icv = [0u8; 16];
            icv.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            let rmac_active = buf[off] != 0;
            off += 1;
            // scp_version byte (must be 0x03)
            if buf[off] != 0x03 {
                return false;
            }
            off += 1;
            let enc_counter = u16::from_be_bytes([buf[off], buf[off + 1]]);
            *state = ScpState::Authenticated {
                session_enc,
                session_mac,
                session_rmac,
                session_dek,
                security_level,
                icv,
                rmac_active,
                scp_version: ScpVersion::Scp03,
                enc_counter,
            };
            true
        }
        _ => false,
    }
}
