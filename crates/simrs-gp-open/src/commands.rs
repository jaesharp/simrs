//! Individual GP command handlers per GP 2.1.1 Chapter 9.
//!
//! Each function processes a specific GP management command and writes the
//! response into the provided buffer. Functions return a slice of the buffer
//! containing `[response_data..., SW1, SW2]`.

use simrs_iso7816::{write_data_sw, write_sw, Command, StatusWord};

use crate::lifecycle::{AppletLifecycle, CardLifecycle};
use crate::registry::{self, AppletEntry, SecurityDomain, MAX_AID_LEN};

// ---------------------------------------------------------------------------
// GP INS codes (CLA 0x80/0x84)
// ---------------------------------------------------------------------------

/// INITIALIZE UPDATE (GP 2.1.1 clause 9.7).
pub const INS_INITIALIZE_UPDATE: u8 = 0x50;
/// EXTERNAL AUTHENTICATE (GP 2.1.1 clause 9.8).
pub const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
/// GET STATUS (GP 2.1.1 clause 9.12).
pub const INS_GET_STATUS: u8 = 0xF2;
/// SET STATUS (GP 2.1.1 clause 9.13).
pub const INS_SET_STATUS: u8 = 0xF0;
/// GET DATA (GP 2.1.1 clause 9.6).
pub const INS_GET_DATA: u8 = 0xCA;
/// INSTALL (GP 2.1.1 clause 9.9).
pub const INS_INSTALL: u8 = 0xE6;
/// DELETE (GP 2.1.1 clause 9.10).
pub const INS_DELETE: u8 = 0xE4;
/// LOAD (GP 2.1.1 clause 9.11).
pub const INS_LOAD: u8 = 0xE8;
/// PUT KEY (GP 2.1.1 clause 9.14).
pub const INS_PUT_KEY: u8 = 0xD8;
/// STORE DATA (GP 2.1.1 clause 9.15).
pub const INS_STORE_DATA: u8 = 0xE2;
/// MANAGE CHANNEL (ETSI TS 102 221 clause 11.1.17).
pub const INS_MANAGE_CHANNEL: u8 = 0x70;

// ---------------------------------------------------------------------------
// GET STATUS (GP 2.1.1 clause 9.12)
// ---------------------------------------------------------------------------

/// P1 values for GET STATUS.
const P1_ISD: u8 = 0x80;
const P1_APPS: u8 = 0x40;
const P1_ELF: u8 = 0x20;

/// Build a GET STATUS response per GP 2.1.1 clause 9.12.
///
/// P1 selects what to list:
/// - 0x80: Issuer Security Domain only
/// - 0x40: Applications and Security Domains
/// - 0x20: Executable Load Files (stub: empty)
///
/// Response format per entry: AID length (1) || AID || lifecycle (1) || privileges (1).
#[allow(clippy::cast_possible_truncation)]
pub fn get_status<'buf, const N: usize, const M: usize>(
    isd: &SecurityDomain,
    registry: &[Option<AppletEntry>; N],
    sds: &[Option<SecurityDomain>; M],
    cmd: &Command<'_>,
    buf: &'buf mut [u8],
) -> &'buf [u8] {
    let p1 = cmd.p1();

    // We only support P2=0x00 (get first or all) for simplicity.
    let mut off = 0;

    match p1 {
        P1_ISD => {
            // Return the ISD entry.
            let aid = isd.aid();
            if off + 1 + aid.len() + 2 > buf.len().saturating_sub(2) {
                return write_sw(buf, StatusWord::WrongLength);
            }
            buf[off] = aid.len() as u8;
            off += 1;
            buf[off..off + aid.len()].copy_from_slice(aid);
            off += aid.len();
            buf[off] = isd.lifecycle().to_byte();
            off += 1;
            buf[off] = isd.privileges();
            off += 1;
        }
        P1_APPS => {
            // List all applications and SDs.
            for entry in registry.iter().flatten() {
                let aid = entry.aid();
                let needed = 1 + aid.len() + 2;
                if off + needed > buf.len().saturating_sub(2) {
                    break;
                }
                buf[off] = aid.len() as u8;
                off += 1;
                buf[off..off + aid.len()].copy_from_slice(aid);
                off += aid.len();
                buf[off] = entry.lifecycle().to_byte();
                off += 1;
                buf[off] = entry.privileges();
                off += 1;
            }
            // Also list supplementary SDs.
            for sd in sds.iter().flatten() {
                let aid = sd.aid();
                let needed = 1 + aid.len() + 2;
                if off + needed > buf.len().saturating_sub(2) {
                    break;
                }
                buf[off] = aid.len() as u8;
                off += 1;
                buf[off..off + aid.len()].copy_from_slice(aid);
                off += aid.len();
                buf[off] = sd.lifecycle().to_byte();
                off += 1;
                buf[off] = sd.privileges();
                off += 1;
            }
        }
        P1_ELF => {
            // Executable Load Files -- stub: return empty list.
        }
        _ => {
            return write_sw(buf, StatusWord::wrong_params(0x86));
        }
    }

    // Append SW 90 00.
    if off + 2 > buf.len() {
        return write_sw(buf, StatusWord::WrongLength);
    }
    let sw = StatusWord::Success.to_bytes();
    buf[off] = sw[0];
    buf[off + 1] = sw[1];
    &buf[..off + 2]
}

// ---------------------------------------------------------------------------
// SET STATUS (GP 2.1.1 clause 9.13)
// ---------------------------------------------------------------------------

/// Process SET STATUS command.
///
/// P1 determines target scope:
/// - 0x80: Card lifecycle (ISD scope)
/// - 0x40: Application lifecycle
///
/// P2 contains the target lifecycle value.
///
/// Command data contains the AID of the target (for P1=0x40).
pub fn set_status<const N: usize, const M: usize>(
    card_lifecycle: &mut CardLifecycle,
    isd: &mut SecurityDomain,
    registry: &mut [Option<AppletEntry>; N],
    sds: &mut [Option<SecurityDomain>; M],
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1 = cmd.p1();
    let p2 = cmd.p2();

    match p1 {
        0x80 => {
            // Card lifecycle transition.
            let Some(target) = CardLifecycle::from_byte(p2) else {
                let sw = StatusWord::wrong_params(0x86).to_bytes();
                buf[0] = sw[0];
                buf[1] = sw[1];
                return 2;
            };
            let Some(new_state) = card_lifecycle.transition(target) else {
                let sw = StatusWord::command_not_allowed(0x85).to_bytes();
                buf[0] = sw[0];
                buf[1] = sw[1];
                return 2;
            };
            *card_lifecycle = new_state;
            let sw = StatusWord::Success.to_bytes();
            buf[0] = sw[0];
            buf[1] = sw[1];
            2
        }
        0x40 => {
            // Application lifecycle transition.
            let Some(target_lc) = AppletLifecycle::from_byte(p2) else {
                let sw = StatusWord::wrong_params(0x86).to_bytes();
                buf[0] = sw[0];
                buf[1] = sw[1];
                return 2;
            };

            let aid = cmd.data();
            if aid.is_empty() || aid.len() > MAX_AID_LEN {
                let sw = StatusWord::WrongLength.to_bytes();
                buf[0] = sw[0];
                buf[1] = sw[1];
                return 2;
            }

            // Search in registry.
            for entry in registry.iter_mut().flatten() {
                if entry.aid() == aid {
                    if let Some(new_lc) = entry.lifecycle().transition(target_lc) {
                        entry.set_lifecycle(new_lc);
                        let sw = StatusWord::Success.to_bytes();
                        buf[0] = sw[0];
                        buf[1] = sw[1];
                        return 2;
                    }
                    let sw = StatusWord::command_not_allowed(0x85).to_bytes();
                    buf[0] = sw[0];
                    buf[1] = sw[1];
                    return 2;
                }
            }
            // Search in SDs.
            for sd in sds.iter_mut().flatten() {
                if sd.aid() == aid {
                    if let Some(new_lc) = sd.lifecycle().transition(target_lc) {
                        sd.set_lifecycle(new_lc);
                        let sw = StatusWord::Success.to_bytes();
                        buf[0] = sw[0];
                        buf[1] = sw[1];
                        return 2;
                    }
                    let sw = StatusWord::command_not_allowed(0x85).to_bytes();
                    buf[0] = sw[0];
                    buf[1] = sw[1];
                    return 2;
                }
            }
            // Also check ISD.
            if isd.aid() == aid {
                if let Some(new_lc) = isd.lifecycle().transition(target_lc) {
                    isd.set_lifecycle(new_lc);
                    let sw = StatusWord::Success.to_bytes();
                    buf[0] = sw[0];
                    buf[1] = sw[1];
                    return 2;
                }
                let sw = StatusWord::command_not_allowed(0x85).to_bytes();
                buf[0] = sw[0];
                buf[1] = sw[1];
                return 2;
            }
            // Not found.
            let sw = StatusWord::wrong_params(0x82).to_bytes();
            buf[0] = sw[0];
            buf[1] = sw[1];
            2
        }
        _ => {
            let sw = StatusWord::wrong_params(0x86).to_bytes();
            buf[0] = sw[0];
            buf[1] = sw[1];
            2
        }
    }
}

// ---------------------------------------------------------------------------
// INSTALL (GP 2.1.1 clause 9.9) -- simplified stub
// ---------------------------------------------------------------------------

/// Process INSTALL command (simplified: just registers the AID).
///
/// For P1 = 0x0C (install for install and make selectable), extracts
/// the AID from the command data and adds it to the registry.
///
/// Returns `(sw, response_len)` written into `buf`.
#[allow(clippy::cast_possible_truncation)]
pub fn install<const N: usize>(
    registry: &mut [Option<AppletEntry>; N],
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let data = cmd.data();
    // Minimal parsing: first byte of data = executable load file AID length,
    // then load file AID, then executable module AID length, then module AID,
    // then application AID length, then application AID.
    // For our simplified stub, we treat the entire data as:
    //   [load_aid_len, load_aid..., module_aid_len, module_aid..., app_aid_len, app_aid...]
    let mut off = 0;
    // Skip load file AID.
    if off >= data.len() {
        let sw = StatusWord::WrongLength.to_bytes();
        buf[0] = sw[0];
        buf[1] = sw[1];
        return 2;
    }
    let load_len = data[off] as usize;
    off += 1 + load_len;
    // Skip module AID.
    if off >= data.len() {
        let sw = StatusWord::WrongLength.to_bytes();
        buf[0] = sw[0];
        buf[1] = sw[1];
        return 2;
    }
    let module_len = data[off] as usize;
    off += 1 + module_len;
    // Application AID.
    if off >= data.len() {
        let sw = StatusWord::WrongLength.to_bytes();
        buf[0] = sw[0];
        buf[1] = sw[1];
        return 2;
    }
    let app_len = data[off] as usize;
    off += 1;
    if app_len == 0 || app_len > MAX_AID_LEN || off + app_len > data.len() {
        let sw = StatusWord::WrongLength.to_bytes();
        buf[0] = sw[0];
        buf[1] = sw[1];
        return 2;
    }
    let app_aid = &data[off..off + app_len];

    // Check for duplicate.
    for entry in registry.iter().flatten() {
        if entry.aid() == app_aid {
            let sw = StatusWord::command_not_allowed(0x85).to_bytes();
            buf[0] = sw[0];
            buf[1] = sw[1];
            return 2;
        }
    }

    // Find empty slot.
    let Some(slot) = registry::find_empty_slot(registry) else {
        let sw = StatusWord::command_not_allowed(0x85).to_bytes();
        buf[0] = sw[0];
        buf[1] = sw[1];
        return 2;
    };

    registry[slot] = Some(AppletEntry::new(app_aid, AppletLifecycle::Selectable, 0x00));

    let sw = StatusWord::Success.to_bytes();
    buf[0] = sw[0];
    buf[1] = sw[1];
    2
}

// ---------------------------------------------------------------------------
// DELETE (GP 2.1.1 clause 9.10)
// ---------------------------------------------------------------------------

/// Process DELETE command. Removes the applet with the specified AID.
///
/// Command data: TLV with tag 0x4F containing the AID.
#[allow(clippy::cast_possible_truncation)]
pub fn delete<const N: usize>(
    registry: &mut [Option<AppletEntry>; N],
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let data = cmd.data();
    // Expect TLV: 4F <len> <AID>.
    if data.len() < 3 || data[0] != 0x4F {
        let sw = StatusWord::WrongLength.to_bytes();
        buf[0] = sw[0];
        buf[1] = sw[1];
        return 2;
    }
    let aid_len = data[1] as usize;
    if data.len() < 2 + aid_len || aid_len == 0 || aid_len > MAX_AID_LEN {
        let sw = StatusWord::WrongLength.to_bytes();
        buf[0] = sw[0];
        buf[1] = sw[1];
        return 2;
    }
    let aid = &data[2..2 + aid_len];

    for entry in &mut *registry {
        if let Some(e) = entry {
            if e.aid() == aid {
                *entry = None;
                let sw = StatusWord::Success.to_bytes();
                buf[0] = sw[0];
                buf[1] = sw[1];
                return 2;
            }
        }
    }
    // Not found.
    let sw = StatusWord::wrong_params(0x82).to_bytes();
    buf[0] = sw[0];
    buf[1] = sw[1];
    2
}

// ---------------------------------------------------------------------------
// GET DATA (GP 2.1.1 clause 9.6)
// ---------------------------------------------------------------------------

/// Tag 0x0066: Card Data / Card Recognition Data.
const TAG_CARD_DATA: u16 = 0x0066;

/// Process GET DATA command.
///
/// P1P2 encodes the tag being requested. For this initial implementation,
/// only Card Recognition Data (tag 0066) is supported.
pub fn get_data<'buf>(
    card_lifecycle: CardLifecycle,
    cmd: &Command<'_>,
    buf: &'buf mut [u8],
) -> &'buf [u8] {
    let tag = u16::from_be_bytes([cmd.p1(), cmd.p2()]);

    match tag {
        TAG_CARD_DATA => {
            // Return Card Recognition Data per GP 2.1.1 Table 9-3.
            // Minimal: tag 66 + length + OID for GP 2.1.1.
            // GP 2.1.1 card recognition data OID: 1.2.840.114283.1
            // Encoded: 06 07 2A 86 48 86 FC 6B 01
            // Wrapped in tag 73 (card data):
            //   73 0B 06 07 2A 86 48 86 FC 6B 01 <lifecycle> <scp>
            let data: [u8; 15] = [
                0x66,
                0x0D, // tag 66, length 13
                0x73,
                0x0B, // tag 73 (card recognition data), length 11
                0x06,
                0x07, // OID tag, length 7
                0x2A,
                0x86,
                0x48,
                0x86,
                0xFC,
                0x6B,
                0x01,                     // GP 2.1.1 OID
                card_lifecycle.to_byte(), // card lifecycle
                0x02,                     // SCP02 identifier
            ];
            write_data_sw(buf, &data, StatusWord::Success)
        }
        _ => write_sw(buf, StatusWord::wrong_params(0x88)),
    }
}

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

/// LOAD command stub -- accepts and returns 90 00.
pub fn load_stub(buf: &mut [u8]) -> usize {
    let sw = StatusWord::Success.to_bytes();
    buf[0] = sw[0];
    buf[1] = sw[1];
    2
}

/// PUT KEY command stub -- accepts and returns 90 00.
pub fn put_key_stub(buf: &mut [u8]) -> usize {
    let sw = StatusWord::Success.to_bytes();
    buf[0] = sw[0];
    buf[1] = sw[1];
    2
}

/// STORE DATA command stub -- accepts and returns 90 00.
pub fn store_data_stub(buf: &mut [u8]) -> usize {
    let sw = StatusWord::Success.to_bytes();
    buf[0] = sw[0];
    buf[1] = sw[1];
    2
}
