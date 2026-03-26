//! Snapshot (save/restore) support for `GpOpen`.
//!
//! Serialization layout (all multi-byte values big-endian):
//!
//! | Field | Size | Description |
//! |-------|------|-------------|
//! | card_lifecycle | 1 | `CardLifecycle` byte |
//! | isd | 1+16+1+1 = 19 | aid_len + aid + lifecycle + privileges |
//! | sd_count | 1 | number of active SDs |
//! | sds[..] | sd_count * 19 | same layout as isd |
//! | app_count | 1 | number of registered applets |
//! | apps[..] | app_count * 19 | same layout |
//! | channels[0..3] | 4 * 2 = 8 | state + selected_applet per channel |
//! | scp_state | 76 | delegated to `simrs_gp_scp::save_scp_state` |
//! | sequence_counter | 2 | SCP02 persistent counter |
//! | default_selected | 1 | 0xFF = none, else registry index |

// TODO: JCVM snapshot integration is deferred -- the JCVM itself (packages,
// heap, static fields) is not yet persisted in the GpOpen snapshot. Only the
// per-AppletEntry JCVM linkage (pkg_idx, process_method) is saved here.
// The load_buffer is transient and never snapshotted.

use crate::channel::ChannelState;
use crate::lifecycle::{AppletLifecycle, CardLifecycle};
use crate::registry::{AppletEntry, LoadFileEntry, SecurityDomain, MAX_AID_LEN};
use crate::MAX_LOAD_FILES;
use simrs_gp_scp::{restore_scp_state, save_scp_state, ScpState, SCP_STATE_SNAPSHOT_SIZE};

/// Save a Security Domain / applet entry into `buf` at `off`. Returns new offset.
#[allow(clippy::cast_possible_truncation)]
fn save_aid_entry(buf: &mut [u8], off: usize, aid: &[u8], lifecycle: u8, privileges: u8) -> usize {
    let mut o = off;
    buf[o] = aid.len() as u8;
    o += 1;
    buf[o..o + MAX_AID_LEN].copy_from_slice(&{
        let mut tmp = [0u8; MAX_AID_LEN];
        tmp[..aid.len()].copy_from_slice(aid);
        tmp
    });
    o += MAX_AID_LEN;
    buf[o] = lifecycle;
    o += 1;
    buf[o] = privileges;
    o + 1
}

/// Restore an AID entry from `buf` at `off`. Returns (aid_len, aid, lifecycle_byte, privileges, new_offset).
fn restore_aid_entry(buf: &[u8], off: usize) -> Option<(u8, [u8; MAX_AID_LEN], u8, u8, usize)> {
    if off + 1 + MAX_AID_LEN + 2 > buf.len() {
        return None;
    }
    let mut o = off;
    let aid_len = buf[o];
    o += 1;
    if aid_len == 0 || aid_len as usize > MAX_AID_LEN {
        return None;
    }
    let mut aid = [0u8; MAX_AID_LEN];
    aid.copy_from_slice(&buf[o..o + MAX_AID_LEN]);
    o += MAX_AID_LEN;
    let lifecycle = buf[o];
    o += 1;
    let privileges = buf[o];
    o += 1;
    Some((aid_len, aid, lifecycle, privileges, o))
}

/// Per SD/ISD entry: 1 (aid_len) + 16 (aid) + 1 (lifecycle) + 1 (privileges).
const ENTRY_SIZE: usize = 1 + MAX_AID_LEN + 1 + 1;

/// Per applet entry: ENTRY_SIZE + 1 (owner_sd_index) + 1 (has_jcvm) + 1 (pkg_idx) + 1 (process_method).
const APP_ENTRY_SIZE: usize = ENTRY_SIZE + 1 + 3;

/// Per load file entry: 1 (aid_len) + 16 (aid) + 1 (instance_count) + 4 (slots).
const LF_ENTRY_SIZE: usize = 1 + MAX_AID_LEN + 1 + 4;

/// Compute the snapshot size for `GpOpen<MAX_APPLETS, MAX_SDS>`.
pub const fn snapshot_size(max_applets: usize, max_sds: usize) -> usize {
    1 // card_lifecycle
    + ENTRY_SIZE // isd
    + 1 // sd_count
    + max_sds * ENTRY_SIZE
    + 1 // app_count
    + max_applets * APP_ENTRY_SIZE
    + 1 // lf_count
    + MAX_LOAD_FILES * LF_ENTRY_SIZE
    + 4 * 2 // channels
    + SCP_STATE_SNAPSHOT_SIZE // scp_state
    + 2 // sequence_counter
    + 1 // default_selected
}

/// Save the entire `GpOpen` state into `buf`. Returns bytes written.
#[allow(clippy::cast_possible_truncation, clippy::too_many_arguments, clippy::too_many_lines)]
pub fn save_state<const MAX_APPLETS: usize, const MAX_SDS: usize>(
    card_lifecycle: CardLifecycle,
    isd: &SecurityDomain,
    sds: &[Option<SecurityDomain>; MAX_SDS],
    registry: &[Option<AppletEntry>; MAX_APPLETS],
    load_files: &[Option<LoadFileEntry>; MAX_LOAD_FILES],
    channels: &[ChannelState; 4],
    scp_state: &ScpState,
    sequence_counter: u16,
    default_selected: Option<u8>,
    buf: &mut [u8],
) -> usize {
    let needed = snapshot_size(MAX_APPLETS, MAX_SDS);
    if buf.len() < needed {
        return 0;
    }

    let mut off = 0;

    // Card lifecycle.
    buf[off] = card_lifecycle.to_byte();
    off += 1;

    // ISD.
    off = save_aid_entry(
        buf,
        off,
        isd.aid(),
        isd.lifecycle().to_byte(),
        isd.privileges(),
    );

    // Supplementary SDs.
    let sd_count = sds.iter().filter(|s| s.is_some()).count();
    buf[off] = sd_count as u8;
    off += 1;
    for sd in sds.iter().flatten() {
        off = save_aid_entry(
            buf,
            off,
            sd.aid(),
            sd.lifecycle().to_byte(),
            sd.privileges(),
        );
    }
    // Pad unused SD slots so offset is deterministic.
    let used_sds = sd_count;
    for _ in used_sds..MAX_SDS {
        buf[off..off + ENTRY_SIZE].fill(0);
        off += ENTRY_SIZE;
    }

    // Registry (applets with owner_sd_index).
    let app_count = registry.iter().filter(|e| e.is_some()).count();
    buf[off] = app_count as u8;
    off += 1;
    for entry in registry.iter().flatten() {
        off = save_aid_entry(
            buf,
            off,
            entry.aid(),
            entry.lifecycle().to_byte(),
            entry.privileges(),
        );
        buf[off] = entry.owner_sd_index().unwrap_or(0xFF);
        off += 1;
        // JCVM fields: has_jcvm(1) + pkg_idx(1) + process_method(1).
        if let Some(pkg_idx) = entry.jcvm_pkg_idx() {
            buf[off] = 1;
            buf[off + 1] = pkg_idx;
            buf[off + 2] = entry.jcvm_process_method();
        } else {
            buf[off] = 0;
            buf[off + 1] = 0;
            buf[off + 2] = 0;
        }
        off += 3;
    }
    for _ in app_count..MAX_APPLETS {
        buf[off..off + APP_ENTRY_SIZE].fill(0);
        off += APP_ENTRY_SIZE;
    }

    // Load files.
    let lf_count = load_files.iter().filter(|l| l.is_some()).count();
    buf[off] = lf_count as u8;
    off += 1;
    for lf in load_files.iter().flatten() {
        let aid = lf.aid();
        buf[off] = aid.len() as u8;
        off += 1;
        let mut aid_buf = [0u8; MAX_AID_LEN];
        aid_buf[..aid.len()].copy_from_slice(aid);
        buf[off..off + MAX_AID_LEN].copy_from_slice(&aid_buf);
        off += MAX_AID_LEN;
        // Instance count and slots.
        let slots = lf.instance_slots();
        let inst_count = slots.iter().filter(|s| s.is_some()).count();
        buf[off] = inst_count as u8;
        off += 1;
        for slot in slots {
            buf[off] = slot.unwrap_or(0xFF);
            off += 1;
        }
    }
    for _ in lf_count..MAX_LOAD_FILES {
        buf[off..off + LF_ENTRY_SIZE].fill(0);
        off += LF_ENTRY_SIZE;
    }

    // Channels.
    for ch in channels {
        match ch {
            ChannelState::Closed => {
                buf[off] = 0x00;
                buf[off + 1] = 0xFF;
            }
            ChannelState::Open { selected_applet } => {
                buf[off] = 0x01;
                buf[off + 1] = selected_applet.unwrap_or(0xFF);
            }
        }
        off += 2;
    }

    // SCP state.
    let scp_written = save_scp_state(scp_state, &mut buf[off..]);
    off += scp_written;
    // Pad to fixed size.
    if scp_written < SCP_STATE_SNAPSHOT_SIZE {
        buf[off..off + (SCP_STATE_SNAPSHOT_SIZE - scp_written)].fill(0);
        off += SCP_STATE_SNAPSHOT_SIZE - scp_written;
    }

    // Sequence counter.
    buf[off] = (sequence_counter >> 8) as u8;
    buf[off + 1] = sequence_counter as u8;
    off += 2;

    // Default selected.
    buf[off] = default_selected.unwrap_or(0xFF);
    off += 1;

    off
}

/// Restore the `GpOpen` state from `buf`. Returns `true` on success.
#[allow(clippy::too_many_arguments, clippy::needless_range_loop, clippy::too_many_lines)]
pub fn restore_state<const MAX_APPLETS: usize, const MAX_SDS: usize>(
    card_lifecycle: &mut CardLifecycle,
    isd: &mut SecurityDomain,
    sds: &mut [Option<SecurityDomain>; MAX_SDS],
    registry: &mut [Option<AppletEntry>; MAX_APPLETS],
    load_files: &mut [Option<LoadFileEntry>; MAX_LOAD_FILES],
    channels: &mut [ChannelState; 4],
    scp_state: &mut ScpState,
    sequence_counter: &mut u16,
    default_selected: &mut Option<u8>,
    buf: &[u8],
) -> bool {
    let needed = snapshot_size(MAX_APPLETS, MAX_SDS);
    if buf.len() < needed {
        return false;
    }

    let mut off = 0;

    // Card lifecycle.
    let Some(cl) = CardLifecycle::from_byte(buf[off]) else {
        return false;
    };
    *card_lifecycle = cl;
    off += 1;

    // ISD.
    let Some((aid_len, aid, lc_byte, privs, new_off)) = restore_aid_entry(buf, off) else {
        return false;
    };
    let Some(lc) = AppletLifecycle::from_byte(lc_byte) else {
        return false;
    };
    *isd = SecurityDomain::new(&aid[..aid_len as usize], lc, privs);
    off = new_off;

    // Supplementary SDs.
    let sd_count = buf[off] as usize;
    off += 1;
    if sd_count > MAX_SDS {
        return false;
    }
    for slot in &mut *sds {
        *slot = None;
    }
    for i in 0..sd_count {
        let Some((aid_len, aid, lc_byte, privs, new_off)) = restore_aid_entry(buf, off) else {
            return false;
        };
        let Some(lc) = AppletLifecycle::from_byte(lc_byte) else {
            return false;
        };
        sds[i] = Some(SecurityDomain::new(&aid[..aid_len as usize], lc, privs));
        off = new_off;
    }
    // Skip padding for unused SD slots.
    off += (MAX_SDS - sd_count) * ENTRY_SIZE;

    // Registry (applets with owner_sd_index).
    let app_count = buf[off] as usize;
    off += 1;
    if app_count > MAX_APPLETS {
        return false;
    }
    for slot in &mut *registry {
        *slot = None;
    }
    for i in 0..app_count {
        let Some((aid_len, aid, lc_byte, privs, new_off)) = restore_aid_entry(buf, off) else {
            return false;
        };
        let Some(lc) = AppletLifecycle::from_byte(lc_byte) else {
            return false;
        };
        let sd_byte = buf[new_off];
        let sd_idx = if sd_byte == 0xFF { None } else { Some(sd_byte) };
        let mut entry = AppletEntry::new_with_sd(
            &aid[..aid_len as usize],
            lc,
            privs,
            sd_idx,
        );
        // Restore JCVM fields: has_jcvm(1) + pkg_idx(1) + process_method(1).
        let jcvm_off = new_off + 1;
        if jcvm_off + 3 > buf.len() {
            return false;
        }
        if buf[jcvm_off] == 1 {
            entry.set_jcvm(buf[jcvm_off + 1], buf[jcvm_off + 2]);
        }
        registry[i] = Some(entry);
        off = jcvm_off + 3;
    }
    off += (MAX_APPLETS - app_count) * APP_ENTRY_SIZE;

    // Load files.
    let lf_count = buf[off] as usize;
    off += 1;
    if lf_count > MAX_LOAD_FILES {
        return false;
    }
    for slot in &mut *load_files {
        *slot = None;
    }
    for i in 0..lf_count {
        if off + LF_ENTRY_SIZE > buf.len() {
            return false;
        }
        let aid_len = buf[off] as usize;
        off += 1;
        if aid_len == 0 || aid_len > MAX_AID_LEN {
            return false;
        }
        let aid = &buf[off..off + aid_len];
        off += MAX_AID_LEN;
        let inst_count = buf[off] as usize;
        off += 1;
        let mut lf = LoadFileEntry::new(aid);
        for _ in 0..inst_count.min(4) {
            let slot_byte = buf[off];
            if slot_byte != 0xFF {
                let _ = lf.add_instance(slot_byte);
            }
            off += 1;
        }
        // Skip remaining slot bytes if inst_count < 4.
        off += 4usize.saturating_sub(inst_count.min(4));
        load_files[i] = Some(lf);
    }
    off += (MAX_LOAD_FILES - lf_count) * LF_ENTRY_SIZE;

    // Channels.
    for ch in channels.iter_mut() {
        let state_byte = buf[off];
        let applet_byte = buf[off + 1];
        off += 2;
        *ch = match state_byte {
            0x00 => ChannelState::Closed,
            0x01 => {
                let sel = if applet_byte == 0xFF {
                    None
                } else {
                    Some(applet_byte)
                };
                ChannelState::Open {
                    selected_applet: sel,
                }
            }
            _ => return false,
        };
    }

    // SCP state.
    if !restore_scp_state(scp_state, &buf[off..off + SCP_STATE_SNAPSHOT_SIZE]) {
        return false;
    }
    off += SCP_STATE_SNAPSHOT_SIZE;

    // Sequence counter.
    *sequence_counter = u16::from_be_bytes([buf[off], buf[off + 1]]);
    off += 2;

    // Default selected.
    let ds = buf[off];
    *default_selected = if ds == 0xFF { None } else { Some(ds) };

    true
}
