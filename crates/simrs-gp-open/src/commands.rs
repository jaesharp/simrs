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
/// Response format per entry (GP 2.1.1 Table 9-7):
/// `E3 { 4F { AID } 9F70 01 { lifecycle } C5 01 { privileges } }`.
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
            if !write_e3_entry(
                buf,
                &mut off,
                isd.aid(),
                isd.lifecycle().to_byte(),
                isd.privileges(),
            ) {
                return write_sw(buf, StatusWord::WrongLength);
            }
        }
        P1_APPS => {
            for entry in registry.iter().flatten() {
                if !write_e3_entry(
                    buf,
                    &mut off,
                    entry.aid(),
                    entry.lifecycle().to_byte(),
                    entry.privileges(),
                ) {
                    break;
                }
            }
            for sd in sds.iter().flatten() {
                if !write_e3_entry(
                    buf,
                    &mut off,
                    sd.aid(),
                    sd.lifecycle().to_byte(),
                    sd.privileges(),
                ) {
                    break;
                }
            }
        }
        P1_ELF => {
            for lf in load_files.iter().flatten() {
                if !write_e3_entry(buf, &mut off, lf.aid(), 0x01, 0x00) {
                    break;
                }
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
    let [sw1, sw2] = StatusWord::Success.to_bytes();
    buf[off] = sw1;
    buf[off + 1] = sw2;
    &buf[..off + 2]
}

/// Write one E3 TLV entry into `buf` at `off`. Returns false if buffer too small.
#[allow(clippy::cast_possible_truncation)]
fn write_e3_entry(
    buf: &mut [u8],
    off: &mut usize,
    aid: &[u8],
    lifecycle: u8,
    privileges: u8,
) -> bool {
    // E3 { 4F { AID } 9F70 01 { lifecycle } C5 01 { privileges } }
    let aid_tlv_len = 2 + aid.len(); // tag 4F (1) + len (1) + AID
    let lifecycle_tlv_len = 4; // tag 9F70 (2) + len (1) + value (1)
    let privileges_tlv_len = 3; // tag C5 (1) + len (1) + value (1)
    let inner_len = aid_tlv_len + lifecycle_tlv_len + privileges_tlv_len;
    let total = 2 + inner_len; // tag E3 (1) + len (1) + inner
    if *off + total + 2 > buf.len() {
        return false;
    }
    buf[*off] = 0xE3;
    buf[*off + 1] = inner_len as u8;
    *off += 2;
    buf[*off] = 0x4F;
    buf[*off + 1] = aid.len() as u8;
    *off += 2;
    buf[*off..*off + aid.len()].copy_from_slice(aid);
    *off += aid.len();
    buf[*off] = 0x9F;
    buf[*off + 1] = 0x70;
    buf[*off + 2] = 0x01;
    buf[*off + 3] = lifecycle;
    *off += 4;
    buf[*off] = 0xC5;
    buf[*off + 1] = 0x01;
    buf[*off + 2] = privileges;
    *off += 3;
    true
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
        P1_ISD => {
            // Card lifecycle transition.
            let Some(target) = CardLifecycle::from_byte(p2) else {
                return write_sw_raw(buf, StatusWord::wrong_params(0x86));
            };
            let Some(new_state) = card_lifecycle.transition(target) else {
                return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
            };
            *card_lifecycle = new_state;
            write_sw_raw(buf, StatusWord::Success)
        }
        P1_APPS => {
            // Application lifecycle transition.
            let Some(target_lc) = AppletLifecycle::from_byte(p2) else {
                return write_sw_raw(buf, StatusWord::wrong_params(0x86));
            };

            let aid = cmd.data();
            if aid.is_empty() || aid.len() > MAX_AID_LEN {
                return write_sw_raw(buf, StatusWord::WrongLength);
            }

            // Search in registry.
            for entry in registry.iter_mut().flatten() {
                if entry.aid() == aid {
                    return try_lifecycle_transition(
                        entry.lifecycle(),
                        target_lc,
                        |lc| entry.set_lifecycle(lc),
                        buf,
                    );
                }
            }
            // Search in SDs.
            for sd in sds.iter_mut().flatten() {
                if sd.aid() == aid {
                    return try_lifecycle_transition(
                        sd.lifecycle(),
                        target_lc,
                        |lc| sd.set_lifecycle(lc),
                        buf,
                    );
                }
            }
            // Also check ISD.
            if isd.aid() == aid {
                return try_lifecycle_transition(
                    isd.lifecycle(),
                    target_lc,
                    |lc| isd.set_lifecycle(lc),
                    buf,
                );
            }
            // Not found.
            write_sw_raw(buf, StatusWord::wrong_params(0x82))
        }
        _ => write_sw_raw(buf, StatusWord::wrong_params(0x86)),
    }
}

/// Try a lifecycle transition and write the result SW into `buf`.
fn try_lifecycle_transition(
    current: AppletLifecycle,
    target: AppletLifecycle,
    set_fn: impl FnOnce(AppletLifecycle),
    buf: &mut [u8],
) -> usize {
    if let Some(new_lc) = current.transition(target) {
        set_fn(new_lc);
        write_sw_raw(buf, StatusWord::Success)
    } else {
        write_sw_raw(buf, StatusWord::command_not_allowed(0x85))
    }
}

// ---------------------------------------------------------------------------
// INSTALL (GP 2.1.1 clause 9.5)
// ---------------------------------------------------------------------------

/// INSTALL P1 values per GP 2.1.1 Table 9-5.
const INSTALL_P1_FOR_LOAD: u8 = 0x02;
const INSTALL_P1_FOR_INSTALL: u8 = 0x04;
const INSTALL_P1_FOR_MAKE_SELECTABLE: u8 = 0x08;
const INSTALL_P1_FOR_INSTALL_AND_MAKE_SELECTABLE: u8 = 0x0C;

/// Process INSTALL command per GP 2.1.1 clause 9.5.
///
/// Returns response length written into `buf`.
#[allow(clippy::cast_possible_truncation)]
pub fn install<const N: usize, const L: usize>(
    card_lifecycle: &mut CardLifecycle,
    registry: &mut [Option<AppletEntry>; N],
    load_files: &mut [Option<LoadFileEntry>; L],
    jcvm: &simrs_jcvm::JcVM<4096, 4>,
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1 = cmd.p1();
    let data = cmd.data();

    // P1=0x02: INSTALL [for load] -- register load file AID.
    if p1 == INSTALL_P1_FOR_LOAD {
        if data.is_empty() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let lf_aid_len = data[0] as usize;
        if lf_aid_len == 0 || lf_aid_len > MAX_AID_LEN || 1 + lf_aid_len > data.len() {
            return write_sw_raw(buf, StatusWord::WrongLength);
        }
        let lf_aid = &data[1..=lf_aid_len];

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
    if p1 == INSTALL_P1_FOR_MAKE_SELECTABLE {
        let Ok((app_aid, _)) = parse_install_aids(data) else {
            return write_sw_raw(buf, StatusWord::WrongLength);
        };
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
    if p1 != INSTALL_P1_FOR_INSTALL && p1 != INSTALL_P1_FOR_INSTALL_AND_MAKE_SELECTABLE {
        return write_sw_raw(buf, StatusWord::wrong_params(0x86));
    }

    let Ok((app_aid, load_len)) = parse_install_aids(data) else {
        return write_sw_raw(buf, StatusWord::WrongLength);
    };

    // Check for duplicate.
    for entry in registry.iter().flatten() {
        if entry.aid() == app_aid {
            // GP 2.1.1 clause 9.5: 6A 80 for duplicate instance AID.
            return write_sw_raw(buf, StatusWord::wrong_params(0x80));
        }
    }

    let Some(slot) = registry::find_empty_slot(registry) else {
        return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
    };

    let lifecycle = if p1 == INSTALL_P1_FOR_INSTALL {
        AppletLifecycle::Installed
    } else {
        AppletLifecycle::Selectable
    };

    registry[slot] = Some(AppletEntry::new(app_aid, lifecycle, 0x00));

    // Link to JCVM package if one with matching load file AID is loaded.
    if load_len > 0 {
        let lf_aid = &data[1..=load_len];
        if let Some(pkg_idx) = jcvm.find_package_by_aid(lf_aid) {
            if let Some(entry) = &mut registry[slot] {
                entry.set_jcvm(pkg_idx, 0);
            }
        }
    }

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

/// Parse INSTALL command data: `load_aid_len | load_aid | module_aid_len | module_aid | app_aid_len | app_aid`.
///
/// Returns `(app_aid, load_aid_len)` on success.
fn parse_install_aids(data: &[u8]) -> Result<(&[u8], usize), ()> {
    let mut off = 0;
    if off >= data.len() {
        return Err(());
    }
    let load_len = data[off] as usize;
    off += 1 + load_len;
    if off >= data.len() {
        return Err(());
    }
    let module_len = data[off] as usize;
    off += 1 + module_len;
    if off >= data.len() {
        return Err(());
    }
    let app_len = data[off] as usize;
    off += 1;
    if app_len == 0 || app_len > MAX_AID_LEN || off + app_len > data.len() {
        return Err(());
    }
    Ok((&data[off..off + app_len], load_len))
}

/// Helper: write a `StatusWord` into buf, return 2.
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

/// Tag 0x0042: Issuer Identification Number (IIN).
const TAG_IIN: u16 = 0x0042;
/// Tag 0x0066: Card Data / Card Recognition Data.
const TAG_CARD_DATA: u16 = 0x0066;
/// Tag 0x9F7F: Card Production Life Cycle (CPLC) data.
const TAG_CPLC: u16 = 0x9F7F;

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
/// - 0x0042: IIN (returns TLV-encoded IIN when configured, else 6A 88)
/// - 0x0066: Card Recognition Data
/// - 0x9F7F: CPLC (Card Production Life Cycle)
pub fn get_data<'buf>(
    card_lifecycle: CardLifecycle,
    _isd_aid: &[u8],
    iin: Option<&[u8]>,
    cmd: &Command<'_>,
    buf: &'buf mut [u8],
) -> &'buf [u8] {
    let tag = u16::from_be_bytes([cmd.p1(), cmd.p2()]);

    match tag {
        TAG_IIN => get_data_iin(iin, buf),
        TAG_CARD_DATA => get_data_card_recognition(card_lifecycle, buf),
        TAG_CPLC => get_data_cplc(buf),
        _ => write_sw(buf, StatusWord::wrong_params(0x88)),
    }
}

/// IIN data per GP 2.1.1 Table 9-2.
///
/// Returns TLV `42 <len> <iin_data>` when an IIN is configured, or 6A 88
/// (referenced data not found) when no IIN is available.
#[allow(clippy::cast_possible_truncation)]
fn get_data_iin<'buf>(iin: Option<&[u8]>, buf: &'buf mut [u8]) -> &'buf [u8] {
    let Some(iin_bytes) = iin else {
        return write_sw(buf, StatusWord::wrong_params(0x88));
    };
    // Build TLV: tag 42, length, IIN data.
    let mut data = [0u8; 18]; // tag(1) + len(1) + max 16 bytes
    data[0] = 0x42;
    data[1] = iin_bytes.len() as u8;
    data[2..2 + iin_bytes.len()].copy_from_slice(iin_bytes);
    write_data_sw(buf, &data[..2 + iin_bytes.len()], StatusWord::Success)
}

/// Build the card recognition OIDs (inner content of tag 73), 49 bytes.
///
/// Used in both GET DATA 0066 response and SELECT FCI (A5 template).
/// The lifecycle byte at offset 9 is the only dynamic element.
pub const fn build_card_recognition_oids(card_lifecycle: CardLifecycle) -> [u8; 49] {
    #[rustfmt::skip]
    let mut oids: [u8; 49] = [
        0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, // GP OID
        0x00, 0x02,                                               // lifecycle placeholder + SCP02
        // Tag 60: Card Management Type OID (SSD support)
        0x60, 0x0C,
        0x06, 0x0A,
        0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x01, 0x01,
        // Tag 63: Card Identification Scheme OID
        0x63, 0x09,
        0x06, 0x07,
        0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03,
        // Tag 64: Secure Channel Protocol OID (SCP02, i=0x15)
        0x64, 0x0B,
        0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x02, 0x15,
    ];
    oids[9] = card_lifecycle.to_byte();
    oids
}

/// Card Recognition Data per GP 2.1.1 Table 9-3 with extended OIDs.
fn get_data_card_recognition(card_lifecycle: CardLifecycle, buf: &mut [u8]) -> &[u8] {
    let oids = build_card_recognition_oids(card_lifecycle);
    let mut data = [0u8; 53];
    data[0] = 0x66; // outer tag
    data[1] = 0x33; // outer length (51)
    data[2] = 0x73; // tag 73
    data[3] = 0x31; // length 49
    data[4..53].copy_from_slice(&oids);
    write_data_sw(buf, &data, StatusWord::Success)
}

/// CPLC data length per GP 2.1.1 clause 9.6 Table 9-4.
const CPLC_DATA_LEN: usize = 42;

/// CPLC (Card Production Life Cycle) data per GP 2.1.1 clause 9.6.
/// Returns tag 9F7F with 42 bytes of manufacturing data (all zeros for simulator).
#[allow(clippy::cast_possible_truncation)]
fn get_data_cplc(buf: &mut [u8]) -> &[u8] {
    let mut data = [0u8; 3 + CPLC_DATA_LEN];
    data[0] = (TAG_CPLC >> 8) as u8;
    data[1] = TAG_CPLC as u8;
    data[2] = CPLC_DATA_LEN as u8;
    write_data_sw(buf, &data, StatusWord::Success)
}

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

/// LOAD command: accumulate CAP data blocks and parse on last block.
///
/// P1 bit 7 (0x80) signals the last (or only) block. Data is accumulated
/// in the load buffer until the final block, then parsed as a CAP blob
/// and loaded into the JCVM.
pub fn load(
    jcvm: &mut simrs_jcvm::JcVM<4096, 4>,
    load_buf: &mut [u8; 4096],
    load_buf_len: &mut usize,
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1 = cmd.p1();
    let data = cmd.data();
    let is_last = p1 & 0x80 != 0;

    let end = *load_buf_len + data.len();
    if end > load_buf.len() {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }
    load_buf[*load_buf_len..end].copy_from_slice(data);
    *load_buf_len = end;

    if is_last {
        let result = simrs_jcvm::cap::parse_cap(&load_buf[..*load_buf_len]);
        *load_buf_len = 0;
        match result {
            Ok(pkg) => {
                if jcvm.load_package(pkg).is_some() {
                    write_sw_raw(buf, StatusWord::Success)
                } else {
                    write_sw_raw(buf, StatusWord::command_not_allowed(0x84))
                }
            }
            Err(_) => write_sw_raw(buf, StatusWord::wrong_params(0x80)),
        }
    } else {
        write_sw_raw(buf, StatusWord::Success)
    }
}

/// PUT KEY command stub -- accepts and returns 90 00.
pub fn put_key_stub(buf: &mut [u8]) -> usize {
    write_sw_raw(buf, StatusWord::Success)
}

/// STORE DATA command stub -- accepts and returns 90 00.
pub fn store_data_stub(buf: &mut [u8]) -> usize {
    write_sw_raw(buf, StatusWord::Success)
}
