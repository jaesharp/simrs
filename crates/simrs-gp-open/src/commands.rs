//! Individual GP command handlers per GP 2.3.1 Chapter 11 (legacy GP 2.1.1
//! Chapter 9).
//!
//! Each function processes a specific GP management command and writes the
//! response into the provided buffer. Functions return a slice of the buffer
//! containing `[response_data..., SW1, SW2]`.

use simrs_consttime::ct_eq;
use simrs_iso7816::{Command, StatusWord, write_data_sw, write_sw};

use crate::lifecycle::{AppletLifecycle, CardLifecycle};
use crate::registry::{self, AppletEntry, LoadFileEntry, MAX_AID_LEN, SecurityDomain};

// ---------------------------------------------------------------------------
// GP INS codes (CLA 0x80/0x84)
// ---------------------------------------------------------------------------

/// INITIALIZE UPDATE (GP 2.3.1 clause 11.5; legacy 2.1.1 clause 9.7).
pub const INS_INITIALIZE_UPDATE: u8 = 0x50;
/// EXTERNAL AUTHENTICATE (GP 2.3.1 clause 11.4; legacy 2.1.1 clause 9.8).
pub const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
/// GET STATUS (GP 2.3.1 clause 11.4; legacy 2.1.1 clause 9.12).
pub const INS_GET_STATUS: u8 = 0xF2;
/// SET STATUS (GP 2.3.1 clause 11.10; legacy 2.1.1 clause 9.13).
pub const INS_SET_STATUS: u8 = 0xF0;
/// GET DATA (GP 2.3.1 clause 11.3; legacy 2.1.1 clause 9.6).
pub const INS_GET_DATA: u8 = 0xCA;
/// INSTALL (GP 2.3.1 clause 11.5; legacy 2.1.1 clause 9.9).
pub const INS_INSTALL: u8 = 0xE6;
/// DELETE (GP 2.3.1 clause 11.2; legacy 2.1.1 clause 9.10).
pub const INS_DELETE: u8 = 0xE4;
/// LOAD (GP 2.3.1 clause 11.6; legacy 2.1.1 clause 9.11).
pub const INS_LOAD: u8 = 0xE8;
/// PUT KEY (GP 2.3.1 clause 11.8; legacy 2.1.1 clause 9.14).
pub const INS_PUT_KEY: u8 = 0xD8;
/// STORE DATA (GP 2.3.1 clause 11.11; legacy 2.1.1 clause 9.15).
pub const INS_STORE_DATA: u8 = 0xE2;
/// MANAGE CHANNEL (ETSI TS 102 221 clause 11.1.17; GP 2.3.1 clause 11.7).
pub const INS_MANAGE_CHANNEL: u8 = 0x70;
/// BEGIN R-MAC SESSION (GP 2.3.1 clause 11.1).
pub const INS_BEGIN_RMAC_SESSION: u8 = 0x7A;
/// END R-MAC SESSION (GP 2.3.1 clause 11.1).
pub const INS_END_RMAC_SESSION: u8 = 0x78;

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

/// INSTALL P1 values per GP 2.3.1 Table 11-44 (legacy 2.1.1 Table 9-5).
const INSTALL_P1_FOR_LOAD: u8 = 0x02;
const INSTALL_P1_FOR_INSTALL: u8 = 0x04;
const INSTALL_P1_FOR_MAKE_SELECTABLE: u8 = 0x08;
const INSTALL_P1_FOR_INSTALL_AND_MAKE_SELECTABLE: u8 = 0x0C;
/// INSTALL [for personalization] -- subsequent STORE DATA chains target
/// the named applet's `processData()` method (GP 2.3.1 § 11.5.2.3.6).
const INSTALL_P1_FOR_PERSONALIZATION: u8 = 0x20;

/// Process INSTALL command per GP 2.3.1 clause 11.5 (legacy 2.1.1 clause 9.5).
///
/// `personalization_target` is updated when the command is INSTALL
/// [for personalization]: on success it carries the registry index of
/// the applet to which subsequent STORE DATA payloads should be
/// dispatched. The caller (the GP OPEN) consults this value when
/// processing STORE DATA on the last block of a chain.
///
/// Returns response length written into `buf`.
#[allow(clippy::cast_possible_truncation)]
pub fn install<const N: usize, const L: usize>(
    card_lifecycle: &mut CardLifecycle,
    registry: &mut [Option<AppletEntry>; N],
    load_files: &mut [Option<LoadFileEntry>; L],
    jcvm: &simrs_jcvm::JcVM<4096, 4>,
    personalization_target: &mut Option<u8>,
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1 = cmd.p1();
    let data = cmd.data();

    // P1=0x20: INSTALL [for personalization] -- record the registry index
    // of the target applet for subsequent STORE DATA dispatch.
    if p1 == INSTALL_P1_FOR_PERSONALIZATION {
        let Ok((app_aid, _)) = parse_install_aids(data) else {
            return write_sw_raw(buf, StatusWord::WrongLength);
        };
        for (idx, entry) in registry.iter().enumerate() {
            if let Some(e) = entry
                && e.aid() == app_aid
            {
                *personalization_target = Some(idx as u8);
                return write_sw_raw(buf, StatusWord::Success);
            }
        }
        return write_sw_raw(buf, StatusWord::wrong_params(0x82));
    }

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
        if let Some(pkg_idx) = jcvm.find_package_by_aid(lf_aid)
            && let Some(entry) = &mut registry[slot]
        {
            entry.set_jcvm(pkg_idx, 0);
        }
    }

    // Link instance to its load file, if the load file AID matches.
    if load_len > 0 {
        let lf_aid = &data[1..=load_len];
        if let Some(lf_idx) = registry::find_load_file(load_files, lf_aid)
            && let Some(ref mut lf) = load_files[lf_idx]
        {
            let _ = lf.add_instance(slot as u8);
        }
    }

    // GP 2.1.1 clause 5.1: first INSTALL transitions OP_READY -> INITIALIZED.
    if *card_lifecycle == CardLifecycle::OpReady
        && let Some(new_state) = card_lifecycle.transition(CardLifecycle::Initialized)
    {
        *card_lifecycle = new_state;
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
        if let Some(sd) = sd_opt
            && sd.aid() == aid
        {
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

    // Standard delete: search registry.
    for entry in &mut *registry {
        if let Some(e) = entry
            && e.aid() == aid
        {
            *entry = None;
            return write_sw_raw(buf, StatusWord::Success);
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
///
/// `scp02_i_param` is reflected into the SCP02 OID inside the Card
/// Recognition Data response.
pub fn get_data<'buf>(
    card_lifecycle: CardLifecycle,
    _isd_aid: &[u8],
    iin: Option<&[u8]>,
    scp02_i_param: u8,
    cmd: &Command<'_>,
    buf: &'buf mut [u8],
) -> &'buf [u8] {
    let tag = u16::from_be_bytes([cmd.p1(), cmd.p2()]);

    match tag {
        TAG_IIN => get_data_iin(iin, buf),
        TAG_CARD_DATA => get_data_card_recognition(card_lifecycle, scp02_i_param, buf),
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
/// The lifecycle byte at offset 9 and the SCP02 `i` parameter byte at
/// offset 47 are the dynamic elements.
///
/// `scp02_i_param` defaults to `0x15` (3 keys, ICV encryption, explicit
/// challenge) per Table E-1 of GP 2.3.1 Appendix E, matching the JCOP
/// family. Pseudo-random card challenges (`i & 0x10 == 0`, e.g. `0x05`)
/// require a derived `card_challenge` from a persistent counter; current
/// implementation always uses an explicit challenge, so configuring a
/// pseudo-random `i` value is advertised but not yet enforced (Phase 1.5).
pub const fn build_card_recognition_oids(
    card_lifecycle: CardLifecycle,
    scp02_i_param: u8,
) -> [u8; 49] {
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
        // Tag 64: Secure Channel Protocol OID (SCP02, i=<configurable>)
        0x64, 0x0B,
        0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x02, 0x15,
    ];
    oids[9] = card_lifecycle.to_byte();
    oids[48] = scp02_i_param;
    oids
}

/// Card Recognition Data per GP 2.3.1 § 11.3.4 (legacy 2.1.1 Table 9-3) with
/// extended OIDs.
fn get_data_card_recognition(
    card_lifecycle: CardLifecycle,
    scp02_i_param: u8,
    buf: &mut [u8],
) -> &[u8] {
    let oids = build_card_recognition_oids(card_lifecycle, scp02_i_param);
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
// LOAD (GP 2.3.1 clause 11.6)
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

// ---------------------------------------------------------------------------
// PUT KEY (GP 2.3.1 clause 11.8)
// ---------------------------------------------------------------------------

/// Key Type Indicator -- 3DES (GP 2.3.1 Table 11-77; legacy GPC 2.1.1 Table 9-49).
const KTI_DES3: u8 = 0x80;
/// Key Type Indicator -- AES (GP 2.3.1 Table 11-77).
const KTI_AES: u8 = 0x88;

/// Maximum KCV length we'll echo back (typically 3 bytes per key).
const MAX_KCV_LEN: usize = 3;
/// Maximum keys carried in a single PUT KEY data field (ENC, MAC, DEK).
const MAX_PUT_KEY_KEYS: usize = 3;

/// Process PUT KEY command per GP 2.3.1 clause 11.8.
///
/// # APDU layout
///
/// - P1 = Key Version Number (KVN) being installed/replaced.
///   - `0x00`: install at the next available KVN; the in-data KVN byte is
///     authoritative.
///   - `0x01..=0x7F`: target KVN.
/// - P2 bit 7 (`0x80`): more PUT KEY commands follow (chaining; not yet
///   handled -- caller should send all keys in one APDU).
/// - P2 bits 6..0: starting Key Identifier (typically `0x01` for ENC).
/// - Data:
///   ```text
///   KVN (1 byte)
///   for each key in {ENC, MAC, DEK}:
///       Key Type Indicator (1 byte)         -- 0x80 (3DES) or 0x88 (AES)
///       Key Component Length (1 byte)       -- length of following block
///       Key Component Data (KCL bytes)      -- encrypted with session DEK
///       KCV Length (1 byte)                 -- typically 3, 0 if absent
///       KCV (KCV Length bytes)              -- check value over the cleartext
///   ```
///
/// # Cryptographic processing
///
/// Each key component is unwrapped using the session DEK obtained from
/// the active SCP session (`ScpState::Authenticated::session_dek`). The
/// wrap mode follows the active SCP version per GP 2.3.1:
///
/// - **SCP01 / SCP02:** 3DES-ECB (§ 11.8.2.3.1)
/// - **SCP03:** AES-CBC with zero IV (Amendment D § 4.2.4.1.1)
///
/// After unwrapping, the Key Check Value is recomputed from the *cleartext*
/// key (per Appendix B.4 for 3DES, Amd D § B.2 for AES) and compared
/// constant-time against the provided KCV. Mismatch returns `6A 80`.
/// Wrap and KCV primitives live in [`simrs_gp_scp::keywrap`].
///
/// # Response
///
/// Returns `KVN || KCV1 || KCV2 || KCV3 || 90 00` on success, where each
/// `KCVn` is the raw KCV bytes (no length prefix) for the n-th installed
/// key. Length prefixes are not echoed; that matches widely-deployed card
/// behaviour and the GP 2.3.1 § 11.8.3 description ("KCVs of all the keys
/// received").
///
/// # Remaining limitations
///
/// - Multi-APDU PUT KEY chaining (P2 bit 7) is accepted but not enforced;
///   all three keys must arrive in a single APDU.
/// - Only 16-byte 3DES and 16-byte AES keys are supported. Other key
///   types (24-byte 3-key 3DES, AES-192/256, RSA components) are rejected
///   with `6A 80`.
pub fn put_key<const MAX_VERSIONS: usize>(
    key_store: &mut simrs_gp_keys::KeyStore<MAX_VERSIONS>,
    scp_state: &simrs_gp_scp::ScpState,
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1_kvn = cmd.p1();
    // P2 bit 7: chaining marker. We accept it without honoring chained-PUT-KEY
    // semantics; multi-APDU PUT KEY is a follow-up enhancement.
    let _chained = cmd.p2() & 0x80 != 0;
    let data = cmd.data();

    if data.is_empty() {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }

    // First data byte = KVN. Must equal P1 unless P1 == 0x00.
    let kvn_in_data = data[0];
    if kvn_in_data == 0x00 || kvn_in_data > 0x7F {
        return write_sw_raw(buf, StatusWord::wrong_params(0x80));
    }
    if p1_kvn != 0x00 && p1_kvn != kvn_in_data {
        return write_sw_raw(buf, StatusWord::wrong_params(0x80));
    }

    // PUT KEY is gated on an authenticated SCP session by the dispatcher;
    // extract the session DEK and SCP version so we know how to unwrap.
    let (session_dek, scp_version) = match scp_state {
        simrs_gp_scp::ScpState::Authenticated {
            session_dek,
            scp_version,
            ..
        } => (*session_dek, *scp_version),
        _ => {
            // Defence in depth -- the dispatcher should have rejected this
            // already with 6985.
            return write_sw_raw(buf, StatusWord::command_not_allowed(0x85));
        }
    };

    // Parse the (up to MAX_PUT_KEY_KEYS) key blocks.
    let parse = match parse_put_key_blocks(&data[1..]) {
        Ok(parsed) => parsed,
        Err(sw) => return write_sw_raw(buf, sw),
    };

    // For now we require exactly 3 keys (ENC, MAC, DEK). Multi-APDU PUT KEY
    // chaining is a follow-up enhancement.
    if parse.keys_seen != MAX_PUT_KEY_KEYS {
        return write_sw_raw(buf, StatusWord::wrong_params(0x80));
    }

    // Unwrap each key component using the session DEK and verify the KCV.
    // GP 2.3.1 § 11.8.2.3.1: SCP01/SCP02 use 3DES-ECB. Amendment D § 4.2.4.1.1:
    // SCP03 uses AES-CBC with zero IV.
    let unwrapped = match unwrap_and_verify_kcv(&session_dek, scp_version, &parse) {
        Ok(u) => u,
        Err(sw) => return write_sw_raw(buf, sw),
    };

    // Build the KeySet from the *decrypted* key material.
    let Some(new_keys) = build_keyset_from_unwrapped(&unwrapped) else {
        return write_sw_raw(buf, StatusWord::wrong_params(0x80));
    };

    if key_store.put(kvn_in_data, &new_keys).is_err() {
        // GP 2.3.1 § 11.8.3 -- 6A 84 "not enough memory space".
        return write_sw_raw(buf, StatusWord::wrong_params(0x84));
    }

    write_put_key_response(buf, kvn_in_data, &parse.kcvs, parse.kcv_lens)
}

/// Decrypted (unwrapped) key material, paired with its Key Type Indicator
/// so the caller can build a `KeySet` of the right algorithm.
struct UnwrappedKey {
    kti: u8,
    key: [u8; 16],
}

/// Unwrap each parsed key component using the session DEK and verify the
/// KCV against the decrypted bytes.
///
/// The wrap mode is selected by the active SCP version (SCP01/02 use
/// 3DES-ECB; SCP03 uses AES-CBC). The KCV algorithm is selected per-block
/// by the Key Type Indicator (3DES vs AES), independent of wrap mode.
fn unwrap_and_verify_kcv(
    session_dek: &[u8; 16],
    scp_version: simrs_gp_scp::ScpVersion,
    parse: &PutKeyParse,
) -> Result<[UnwrappedKey; MAX_PUT_KEY_KEYS], StatusWord> {
    let mut out: [UnwrappedKey; MAX_PUT_KEY_KEYS] = core::array::from_fn(|_| UnwrappedKey {
        kti: 0,
        key: [0u8; 16],
    });
    for ((slot, material), (kcv_buf, kcv_len)) in out
        .iter_mut()
        .zip(parse.materials.iter())
        .zip(parse.kcvs.iter().zip(parse.kcv_lens.iter()))
    {
        let (kti, wrapped) = match material.as_ref() {
            Some(KeyMaterial::Des3TwoKey(w)) => (KTI_DES3, *w),
            Some(KeyMaterial::Aes128(w)) => (KTI_AES, *w),
            None => return Err(StatusWord::wrong_params(0x80)),
        };

        let unwrapped = match scp_version {
            simrs_gp_scp::ScpVersion::Scp01 | simrs_gp_scp::ScpVersion::Scp02 => {
                simrs_gp_scp::keywrap::unwrap_3des_ecb(session_dek, wrapped)
            }
            simrs_gp_scp::ScpVersion::Scp03 => {
                simrs_gp_scp::keywrap::unwrap_aes_cbc(session_dek, wrapped)
            }
        };

        // Verify KCV (selected by the algorithm of the *decrypted* key,
        // not by the wrap mode). Skip verification only when KCV length is
        // 0 (caller opted out -- GP 2.3.1 § 11.8.2.3 permits this).
        let n = *kcv_len as usize;
        if n > 0 {
            let computed = match kti {
                KTI_DES3 => simrs_gp_scp::keywrap::kcv_3des(&unwrapped),
                KTI_AES => simrs_gp_scp::keywrap::kcv_aes_128(&unwrapped),
                _ => return Err(StatusWord::wrong_params(0x80)),
            };
            // The provided KCV may be 1..=3 bytes. Compare equal-length
            // slices via the project's established `ct_eq` primitive (which
            // is itself the Bayesian-timing-validated comparison routine).
            if !ct_eq(&computed[..n], &kcv_buf[..n]).into_bool() {
                // GP 2.3.1 § 11.8.3 -- 6A 80 "wrong data" covers KCV mismatch.
                return Err(StatusWord::wrong_params(0x80));
            }
        }

        *slot = UnwrappedKey {
            kti,
            key: unwrapped,
        };
    }
    Ok(out)
}

/// Build a `KeySet` from three already-unwrapped key components.
fn build_keyset_from_unwrapped(
    keys: &[UnwrappedKey; MAX_PUT_KEY_KEYS],
) -> Option<simrs_gp_keys::KeySet> {
    // All three KTIs must agree.
    if keys[0].kti != keys[1].kti || keys[0].kti != keys[2].kti {
        return None;
    }
    match keys[0].kti {
        KTI_DES3 => Some(simrs_gp_keys::KeySet::des3_2key(
            keys[0].key,
            keys[1].key,
            keys[2].key,
        )),
        KTI_AES => Some(simrs_gp_keys::KeySet::aes128(
            keys[0].key,
            keys[1].key,
            keys[2].key,
        )),
        _ => None,
    }
}

/// Parsed key blocks staged from the PUT KEY command body.
struct PutKeyParse {
    materials: [Option<KeyMaterial>; MAX_PUT_KEY_KEYS],
    kcvs: [[u8; MAX_KCV_LEN]; MAX_PUT_KEY_KEYS],
    kcv_lens: [u8; MAX_PUT_KEY_KEYS],
    keys_seen: usize,
}

/// Parse the key blocks following the leading KVN byte. Returns the bag of
/// material plus collected KCVs, or a status word on malformed input.
fn parse_put_key_blocks(data: &[u8]) -> Result<PutKeyParse, StatusWord> {
    let mut parse = PutKeyParse {
        materials: [const { None }; MAX_PUT_KEY_KEYS],
        kcvs: [[0u8; MAX_KCV_LEN]; MAX_PUT_KEY_KEYS],
        kcv_lens: [0u8; MAX_PUT_KEY_KEYS],
        keys_seen: 0,
    };
    let mut off = 0usize;

    while off < data.len() && parse.keys_seen < MAX_PUT_KEY_KEYS {
        let kti = *data.get(off).ok_or(StatusWord::WrongLength)?;
        off += 1;

        let kcl = *data.get(off).ok_or(StatusWord::WrongLength)? as usize;
        off += 1;

        let key_bytes = data.get(off..off + kcl).ok_or(StatusWord::WrongLength)?;
        off += kcl;

        let kcv_len_byte = *data.get(off).ok_or(StatusWord::WrongLength)?;
        off += 1;
        let kcv_len = kcv_len_byte as usize;
        if kcv_len > MAX_KCV_LEN {
            return Err(StatusWord::wrong_params(0x80));
        }

        let kcv_bytes = data
            .get(off..off + kcv_len)
            .ok_or(StatusWord::WrongLength)?;
        off += kcv_len;

        let mat = match (kti, kcl) {
            (KTI_DES3, 16) => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key_bytes);
                KeyMaterial::Des3TwoKey(k)
            }
            (KTI_AES, 16) => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key_bytes);
                KeyMaterial::Aes128(k)
            }
            _ => return Err(StatusWord::wrong_params(0x80)),
        };

        parse.materials[parse.keys_seen] = Some(mat);
        parse.kcvs[parse.keys_seen][..kcv_len].copy_from_slice(kcv_bytes);
        parse.kcv_lens[parse.keys_seen] = kcv_len_byte;
        parse.keys_seen += 1;
    }

    Ok(parse)
}

/// Write `KVN || concatenated KCVs || 90 00` into `buf`.
fn write_put_key_response(
    buf: &mut [u8],
    kvn: u8,
    kcvs: &[[u8; MAX_KCV_LEN]; MAX_PUT_KEY_KEYS],
    kcv_lens: [u8; MAX_PUT_KEY_KEYS],
) -> usize {
    let mut total_kcv_len = 0usize;
    for &n in &kcv_lens {
        total_kcv_len += n as usize;
    }
    let response_len = 1 + total_kcv_len;
    if response_len + 2 > buf.len() {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }

    buf[0] = kvn;
    let mut wpos = 1usize;
    for (kcv, &n) in kcvs.iter().zip(&kcv_lens) {
        let n = n as usize;
        buf[wpos..wpos + n].copy_from_slice(&kcv[..n]);
        wpos += n;
    }
    let [sw1, sw2] = StatusWord::Success.to_bytes();
    buf[response_len] = sw1;
    buf[response_len + 1] = sw2;
    response_len + 2
}

/// Internal staging type for PUT KEY parsing.
enum KeyMaterial {
    Des3TwoKey([u8; 16]),
    Aes128([u8; 16]),
}

// ---------------------------------------------------------------------------
// STORE DATA (GP 2.3.1 clause 11.11)
// ---------------------------------------------------------------------------

/// Maximum cumulative payload accepted across a STORE DATA chain.
///
/// Sized to the issuer's typical personalization data window; larger payloads
/// should be split across multiple INSTALL [for personalization] sessions.
pub const STORE_DATA_BUFFER_LEN: usize = 1024;

/// Persistent state for an in-flight STORE DATA chain.
///
/// STORE DATA is inherently multi-APDU: P1 carries a 1-byte block index and
/// a "last block" flag. The card must accumulate blocks until the last
/// arrives, then process the complete payload.
pub struct StoreDataState {
    /// Accumulated payload (cleared after the last block is received or on
    /// any error).
    buf: [u8; STORE_DATA_BUFFER_LEN],
    /// Current fill level.
    len: usize,
    /// Expected next block index. P1 bits 6..0 must match this value, with
    /// `0x00` for the first block of a chain and increment-by-1 thereafter.
    next_block: u8,
    /// Whether we've ever started a chain. Resets after the last block.
    in_progress: bool,
}

impl Default for StoreDataState {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreDataState {
    /// Create an empty STORE DATA accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; STORE_DATA_BUFFER_LEN],
            len: 0,
            next_block: 0,
            in_progress: false,
        }
    }

    /// Snapshot length helper.
    #[must_use]
    pub const fn fill_len(&self) -> usize {
        self.len
    }

    /// View of the accumulated payload.
    #[must_use]
    pub fn assembled(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Reset the accumulator (used by the SD on session loss, or by the
    /// caller after dispatching a completed payload).
    pub const fn clear(&mut self) {
        self.len = 0;
        self.next_block = 0;
        self.in_progress = false;
    }
}

/// Outcome of a STORE DATA block per GP 2.3.1 § 11.11.
///
/// The caller is responsible for translating the outcome into an APDU
/// response. The dispatch path is split out so that the `Complete` case
/// can forward the assembled payload to the personalization recipient.
pub enum StoreDataOutcome {
    /// Block accepted, more blocks expected. Caller writes `9000`.
    Accepted,
    /// Last block received. The assembled payload is in
    /// [`StoreDataState::assembled`]; caller dispatches it to the
    /// personalization recipient, then calls [`StoreDataState::clear`].
    Complete,
    /// Error with the specified status word. State already cleared.
    Error(StatusWord),
}

/// Process a STORE DATA block per GP 2.3.1 § 11.11.
///
/// # APDU layout
///
/// - P1 bit 7 (`0x80`): last block of the chain.
/// - P1 bit 6 (`0x40`): encrypted data flag (not yet decrypted -- Phase 1.5).
/// - P1 bit 5 (`0x20`): BER-TLV formatted data flag (not yet validated).
/// - P1 bits 4..0: reserved (`0`).
/// - P2: block sequence number, starting at `0x00` for the first block.
/// - Data: payload to accumulate.
///
/// # Returns
///
/// A [`StoreDataOutcome`] describing how the block was processed. The
/// caller writes the response APDU based on the outcome and -- on
/// `Complete` -- forwards `state.assembled()` to the personalization
/// recipient before calling `state.clear()`.
pub fn store_data_block(state: &mut StoreDataState, cmd: &Command<'_>) -> StoreDataOutcome {
    let p1 = cmd.p1();
    let p2 = cmd.p2();
    let data = cmd.data();

    let is_last = p1 & 0x80 != 0;
    // P1 bits 4..0 are reserved; require zero per GP 2.3.1 § 11.11.2.1.
    if p1 & 0x1F != 0 {
        return StoreDataOutcome::Error(StatusWord::wrong_params(0x86));
    }

    // P2 must match the next expected block index.
    if state.in_progress {
        if p2 != state.next_block {
            state.clear();
            return StoreDataOutcome::Error(StatusWord::wrong_params(0x86));
        }
    } else if p2 != 0x00 {
        // First block of a chain must have P2 == 0.
        return StoreDataOutcome::Error(StatusWord::wrong_params(0x86));
    }

    state.in_progress = true;

    // Append payload.
    let new_len = state.len + data.len();
    if new_len > state.buf.len() {
        state.clear();
        // GP 2.3.1 § 11.11 -- 6A 84 "not enough memory space".
        return StoreDataOutcome::Error(StatusWord::wrong_params(0x84));
    }
    state.buf[state.len..new_len].copy_from_slice(data);
    state.len = new_len;

    if is_last {
        // Mark the chain as no-longer-in-progress but retain `len` so the
        // caller can read `state.assembled()` and dispatch.
        state.in_progress = false;
        state.next_block = 0;
        StoreDataOutcome::Complete
    } else {
        state.next_block = state.next_block.wrapping_add(1);
        StoreDataOutcome::Accepted
    }
}

// ---------------------------------------------------------------------------
// BEGIN/END R-MAC SESSION (GP 2.3.1 clause 11.1)
// ---------------------------------------------------------------------------

/// Process BEGIN R-MAC SESSION command per GP 2.3.1 clause 11.1.
///
/// # APDU layout
///
/// - P1 = `0x00`: R-MAC only on responses (security level bit 0x10).
/// - P1 = `0x10`: R-MAC + R-ENC on responses.
/// - P1 other: invalid.
/// - P2 = `0x01`: begin the session (the only currently-defined value).
/// - Data: optional 1..24 bytes of session-scope data; if present, seeds
///   the R-MAC running chaining value per GP 2.3.1 Appendix E.6.
///
/// Requires an authenticated SCP session. Sets the `rmac_active` flag in
/// the SCP state so that subsequent `wrap_response` calls add an R-MAC
/// trailer, and seeds the R-MAC chaining value:
///
/// - With **no** data field, `rmac_icv = [0; 8]`.
/// - With a non-empty data field, `rmac_icv = CBC-MAC(session_R-MAC,
///   IV=0, Method-2-padded(data))` per Appendix E.6.
///
/// The BEGIN R-MAC SESSION response itself is **not** R-MAC-wrapped:
/// it is the seeding act, and the spec consumes the chain only for
/// subsequent responses.
pub fn begin_rmac_session(
    scp_state: &mut simrs_gp_scp::ScpState,
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1 = cmd.p1();
    let p2 = cmd.p2();

    if p2 != 0x01 {
        return write_sw_raw(buf, StatusWord::wrong_params(0x86));
    }
    // P1 selects whether R-ENC is also activated. Currently we don't honour
    // P1 = 0x10 (R-MAC + R-ENC); reject it explicitly so callers know.
    if p1 != 0x00 && p1 != 0x10 {
        return write_sw_raw(buf, StatusWord::wrong_params(0x86));
    }
    let data = cmd.data();
    if data.len() > 24 {
        return write_sw_raw(buf, StatusWord::WrongLength);
    }

    match scp_state {
        simrs_gp_scp::ScpState::Authenticated {
            rmac_active,
            rmac_icv,
            response_mac,
            security_level,
            ..
        } => {
            *rmac_active = true;
            *rmac_icv = simrs_gp_scp::seed_rmac_chain_scp02(response_mac, data);
            // Reflect the new R-MAC bit (0x10) into the session security
            // level so wrap_response knows to attach a trailer.
            *security_level |= 0x10;
            write_sw_raw(buf, StatusWord::Success)
        }
        _ => write_sw_raw(buf, StatusWord::command_not_allowed(0x85)),
    }
}

/// Process END R-MAC SESSION command per GP 2.3.1 clause 11.1.
///
/// # APDU layout
///
/// - P1 = `0x00`: end without returning the final R-MAC.
/// - P1 = `0x03`: end and return the current R-MAC value (8 bytes for
///   SCP01/02; SCP03 is not yet supported on this path and returns
///   the running 8-byte value zero-extended).
/// - P2 = `0x00`.
///
/// Clears the `rmac_active` flag and returns the current running R-MAC
/// chaining value when requested. The chaining value is also cleared
/// to all zeros so a subsequent BEGIN R-MAC SESSION starts fresh.
pub fn end_rmac_session(
    scp_state: &mut simrs_gp_scp::ScpState,
    cmd: &Command<'_>,
    buf: &mut [u8],
) -> usize {
    let p1 = cmd.p1();
    let p2 = cmd.p2();

    if p2 != 0x00 || (p1 != 0x00 && p1 != 0x03) {
        return write_sw_raw(buf, StatusWord::wrong_params(0x86));
    }

    match scp_state {
        simrs_gp_scp::ScpState::Authenticated {
            rmac_active,
            rmac_icv,
            security_level,
            ..
        } => {
            *rmac_active = false;
            *security_level &= !0x10;
            let snapshot = *rmac_icv;
            *rmac_icv = [0u8; 8];
            if p1 == 0x03 {
                // Return the 8-byte running R-MAC followed by SW.
                buf[..8].copy_from_slice(&snapshot);
                let sw = StatusWord::Success.to_bytes();
                buf[8] = sw[0];
                buf[9] = sw[1];
                10
            } else {
                write_sw_raw(buf, StatusWord::Success)
            }
        }
        _ => write_sw_raw(buf, StatusWord::command_not_allowed(0x85)),
    }
}
