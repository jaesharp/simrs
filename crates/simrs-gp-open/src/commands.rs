//! Individual GP command handlers per GP 2.1.1 Chapter 9.
//!
//! Each function processes a specific GP management command and writes the
//! response into the provided buffer. Functions return a slice of the buffer
//! containing `[response_data..., SW1, SW2]`.

use simrs_iso7816::{write_data_sw, write_sw, Command, StatusWord};

use crate::lifecycle::{AppletLifecycle, CardLifecycle};
use crate::registry::{self, AppletEntry, LoadFileEntry, SecurityDomain, MAX_AID_LEN};

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
pub fn get_status<'buf, const N: usize, const M: usize, const L: usize>(
    isd: &SecurityDomain,
    registry: &[Option<AppletEntry>; N],
    sds: &[Option<SecurityDomain>; M],
    load_files: &[Option<LoadFileEntry>; L],
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
            // Executable Load Files.
            for lf in load_files.iter().flatten() {
                let aid = lf.aid();
                let needed = 1 + aid.len() + 2;
                if off + needed > buf.len().saturating_sub(2) {
                    break;
                }
                buf[off] = aid.len() as u8;
                off += 1;
                buf[off..off + aid.len()].copy_from_slice(aid);
                off += aid.len();
                buf[off] = 0x01; // "Loaded" lifecycle
                off += 1;
                buf[off] = 0x00; // no privileges
                off += 1;
            }
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

/// Process INSTALL command per GP 2.1.1 clause 9.5.
///
/// Handles P1 variants:
/// - 0x02: INSTALL [for load] -- registers load file AID (stub: accepts).
/// - 0x04: INSTALL [for install] -- creates app in INSTALLED state.
/// - 0x08: INSTALL [for make selectable] -- stub: accepts.
/// - 0x0C: INSTALL [for install and make selectable] -- creates app in SELECTABLE state.
///
/// Returns response length written into `buf`.
#[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
pub fn install<const N: usize, const L: usize>(
    card_lifecycle: &mut CardLifecycle,
    registry: &mut [Option<AppletEntry>; N],
    load_files: &mut [Option<LoadFileEntry>; L],
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1 = cmd.p1();
    let data = cmd.data();

    // P1=0x02: INSTALL [for load] -- register load file AID.
    if p1 == 0x02 {
        if data.is_empty() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let lf_aid_len = data[0] as usize;
        if lf_aid_len == 0 || lf_aid_len > MAX_AID_LEN || 1 + lf_aid_len > data.len() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let lf_aid = &data[1..=lf_aid_len];

        // Check for duplicate.
        if registry::find_load_file(load_files, lf_aid).is_some() {
            return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
        }

        let Some(slot) = registry::find_empty_lf_slot(load_files) else {
            return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
        };
        load_files[slot] = Some(LoadFileEntry::new(lf_aid));
        return write_sw_raw(buf, StatusWord::Success);
    }

    // P1=0x08: INSTALL [for make selectable] -- transition INSTALLED -> SELECTABLE.
    if p1 == 0x08 {
        // Parse the app AID (same format: skip load_aid, module_aid, then app_aid).
        let mut off = 0;
        if off >= data.len() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let load_len = data[off] as usize;
        off += 1 + load_len;
        if off >= data.len() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let module_len = data[off] as usize;
        off += 1 + module_len;
        if off >= data.len() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let app_len = data[off] as usize;
        off += 1;
        if app_len == 0 || off + app_len > data.len() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let app_aid = &data[off..off + app_len];

        // Find the app in registry and transition to Selectable.
        for entry in registry.iter_mut().flatten() {
            if entry.aid() == app_aid {
                if let Some(new_lc) = entry.lifecycle().transition(AppletLifecycle::Selectable) {
                    entry.set_lifecycle(new_lc);
                    return write_sw_raw(buf, StatusWord::Success);
                }
                return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
            }
        }
        return write_sw_raw(buf, StatusWord::wrong_params(0x82));
    }

    // P1=0x04 or P1=0x0C: install (and optionally make selectable).
    // Data: load_aid_len | load_aid | module_aid_len | module_aid | app_aid_len | app_aid | ...
    if p1 != 0x04 && p1 != 0x0C {
        return write_sw_raw(buf, StatusWord::wrong_params(0x86));
    }

    let mut off = 0;
    // Skip load file AID.
    if off >= data.len() {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }
    let load_len = data[off] as usize;
    off += 1 + load_len;
    // Skip module AID.
    if off >= data.len() {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }
    let module_len = data[off] as usize;
    off += 1 + module_len;
    // Application AID.
    if off >= data.len() {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }
    let app_len = data[off] as usize;
    off += 1;
    if app_len == 0 || app_len > MAX_AID_LEN || off + app_len > data.len() {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }
    let app_aid = &data[off..off + app_len];

    // Check for duplicate.
    for entry in registry.iter().flatten() {
        if entry.aid() == app_aid {
            // GP 2.1.1 clause 9.5: 6A 80 for duplicate instance AID.
            return write_sw_raw(buf, StatusWord::wrong_params(0x80));
        }
    }

    // Find empty slot.
    let Some(slot) = registry::find_empty_slot(registry) else {
        return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
    };

    // P1=0x04: INSTALLED state (0x03). P1=0x0C: SELECTABLE state (0x07).
    let lifecycle = if p1 == 0x04 {
        AppletLifecycle::Installed
    } else {
        AppletLifecycle::Selectable
    };

    registry[slot] = Some(AppletEntry::new(app_aid, lifecycle, 0x00));

    // Link instance to its load file, if the load file AID matches.
    if load_len > 0 {
        let lf_aid = &data[1..=load_len];
        if let Some(lf_idx) = registry::find_load_file(load_files, lf_aid) {
            if let Some(ref mut lf) = load_files[lf_idx] {
                let _ = lf.add_instance(slot as u8);
            }
        }
    }

    // GP 2.1.1 clause 5.1: first INSTALL transitions OP_READY -> INITIALIZED.
    if *card_lifecycle == CardLifecycle::OpReady {
        if let Some(new_state) = card_lifecycle.transition(CardLifecycle::Initialized) {
            *card_lifecycle = new_state;
        }
    }

    write_sw_raw(buf, StatusWord::Success)
}

/// Helper: write a StatusWord into buf, return 2.
fn write_sw_raw(buf: &mut [u8], sw: StatusWord) -> usize {
    let bytes = sw.to_bytes();
    buf[0] = bytes[0];
    buf[1] = bytes[1];
    2
}

// ---------------------------------------------------------------------------
// DELETE (GP 2.1.1 clause 9.10)
// ---------------------------------------------------------------------------

/// Process DELETE command per GP 2.1.1 clause 9.2.
///
/// P2=0x00: delete single application or SD.
/// P2=0x80: cascade delete (load file + all instances).
///
/// SD guard: an SD with associated applications cannot be deleted.
#[allow(clippy::cast_possible_truncation)]
pub fn delete<const N: usize, const M: usize, const L: usize>(
    registry: &mut [Option<AppletEntry>; N],
    sds: &mut [Option<SecurityDomain>; M],
    load_files: &mut [Option<LoadFileEntry>; L],
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let data = cmd.data();
    let p2 = cmd.p2();

    // Expect TLV: 4F <len> <AID>.
    if data.len() < 3 || data[0] != 0x4F {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }
    let aid_len = data[1] as usize;
    if data.len() < 2 + aid_len || aid_len == 0 || aid_len > MAX_AID_LEN {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }
    let aid = &data[2..2 + aid_len];

    // Cascade delete (P2 bit 7): delete load file + all instances.
    if p2 & 0x80 != 0 {
        if let Some(lf_idx) = registry::find_load_file(load_files, aid) {
            // Remove all instances tracked by this load file.
            if let Some(ref lf) = load_files[lf_idx] {
                for s in lf.instance_slots().iter().flatten() {
                    let idx = *s as usize;
                    if idx < registry.len() {
                        registry[idx] = None;
                    }
                }
            }
            load_files[lf_idx] = None;
            return write_sw_raw(buf, StatusWord::Success);
        }
        return write_sw_raw(buf, StatusWord::wrong_params(0x82));
    }

    // Check if AID is an SD.
    for (sd_idx, sd_opt) in sds.iter().enumerate() {
        if let Some(sd) = sd_opt {
            if sd.aid() == aid {
                // SD guard: check for associated applications.
                let has_apps = registry
                    .iter()
                    .flatten()
                    .any(|e| e.owner_sd_index() == Some(sd_idx as u8));
                if has_apps {
                    return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
                }
                // No associated apps -- delete the SD.
                sds[sd_idx] = None;
                return write_sw_raw(buf, StatusWord::Success);
            }
        }
    }

    // Standard delete: search registry.
    for entry in &mut *registry {
        if let Some(e) = entry {
            if e.aid() == aid {
                *entry = None;
                return write_sw_raw(buf, StatusWord::Success);
            }
        }
    }

    // Not found.
    write_sw_raw(buf, StatusWord::wrong_params(0x82))
}

// ---------------------------------------------------------------------------
// GET DATA (GP 2.1.1 clause 9.6)
// ---------------------------------------------------------------------------

/// Tag 0x0042: ISD AID / Card Data.
const TAG_ISD_AID: u16 = 0x0042;
/// Tag 0x0066: Card Data / Card Recognition Data.
const TAG_CARD_DATA: u16 = 0x0066;

/// Response schema for GET DATA tag 0066 (Card Recognition Data).
///
/// TLV structure: `66 { 73 { 06 <OID>, <lifecycle>, <scp_id> } }`
///
/// The OID must match exactly; lifecycle and SCP identifier are trailing
/// bytes inside tag 73 and are not checked (they vary by card state and
/// implementation).
pub static GET_DATA_0066_SCHEMA: simrs_apdu_schema::ResponseSchema =
    simrs_apdu_schema::ResponseSchema {
        name: "GET_DATA_0066",
        expected_len: None,
        fields: &[
            simrs_apdu_schema::FieldSpec {
                name: "outer_tag_66",
                span: simrs_apdu_schema::FieldSpan::Tag(0x66),
                policy: simrs_apdu_schema::FieldPolicy::PresenceOnly,
            },
            simrs_apdu_schema::FieldSpec {
                name: "inner_tag_73",
                span: simrs_apdu_schema::FieldSpan::TagPath(&[0x66, 0x73]),
                policy: simrs_apdu_schema::FieldPolicy::PresenceOnly,
            },
            simrs_apdu_schema::FieldSpec {
                name: "gp_oid",
                span: simrs_apdu_schema::FieldSpan::TagPath(&[0x66, 0x73, 0x06]),
                policy: simrs_apdu_schema::FieldPolicy::Exact,
            },
        ],
    };

/// Process GET DATA command.
///
/// P1P2 encodes the tag being requested. Supported tags:
/// - 0x0042: ISD AID
/// - 0x0066: Card Recognition Data
pub fn get_data<'buf>(
    card_lifecycle: CardLifecycle,
    isd_aid: &[u8],
    cmd: &Command<'_>,
    buf: &'buf mut [u8],
) -> &'buf [u8] {
    let tag = u16::from_be_bytes([cmd.p1(), cmd.p2()]);

    match tag {
        TAG_ISD_AID => {
            // Return ISD AID per GP 2.1.1 Table 9-2.
            write_data_sw(buf, isd_aid, StatusWord::Success)
        }
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
