#![allow(missing_docs)]
//! Provenance-aware snapshot registry for SIM state diffing.
//!
//! Maps every byte in a flat SIM state snapshot to its semantic provenance
//! via typed enums. Test steps register expected changes by semantic path;
//! the diff step resolves byte-level changes through the registry and checks
//! them against reservations.
//!
//! The path hierarchy mirrors DNS delegation: each level resolves to the next,
//! enforced at compile time.
//!
//! # Dead code policy
//!
//! Variants of `UsimField`/`GsmField` that are not yet reservation targets are
//! still needed for `identify()` completeness (every byte in the snapshot must
//! be covered). Per-item `#[allow(dead_code)]` is applied to items that exist
//! solely for registry completeness; items without it are expected to gain
//! reservation helpers eventually.

use std::collections::HashSet;
use std::fmt::{self, Write as _};
use std::ops::Range;

use simrs_pin::PinKey;

// =========================================================================
// Typed semantic paths (DNS-style delegation)
// =========================================================================

/// Top-level path into the Sim snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatePath {
    /// `CardState` byte (offset 0).
    CardState,
    /// GSM application field.
    Gsm(GsmField),
    /// USIM application field.
    Usim(UsimField),
}

/// Fields within the GSM application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GsmField {
    SelectionCtx,
    FsData,
    Pin(PinId, PinField),
    Ki,
    Version,
    RspQueue,
}

/// Fields within the USIM application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsimField {
    SelectionCtx,
    FsData,
    Pin(PinId, PinField),
    Auth,
    Proactive,
    RspQueue,
    TerminalCapability,
    Deactivation,
    Channel(u8),
    LastAidMatch,
    Suci,
}

/// Individual fields within a PIN slot, or the manager's count byte.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PinField {
    /// The `PinManager` slot count byte (not associated with any particular slot).
    Count,
    Key,
    Pin,
    PinRetries,
    PinMax,
    Puk,
    PukRetries,
    Enabled,
    Verified,
}

/// PIN identity wrapper that supports Hash (unlike `PinKey`).
///
/// Wraps the raw u8 key value from `PinKey` so it can be used in `HashSet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PinId(pub u8);

impl PinId {
    /// Sentinel for the `PinManager` count byte and empty/unoccupied slots.
    /// `key=0` is not a valid `PinKey` value in the simrs-pin crate.
    pub const EMPTY: Self = Self(0);

    #[allow(dead_code)]
    pub const PIN1: Self = Self(PinKey::PIN1.0);
    #[allow(dead_code)]
    pub const PIN2: Self = Self(PinKey::PIN2.0);
    #[allow(dead_code)]
    pub const ADM1: Self = Self(PinKey::ADM1.0);
    #[allow(dead_code)]
    pub const ADM2: Self = Self(PinKey::ADM2.0);
    #[allow(dead_code)]
    pub const UNIVERSAL: Self = Self(PinKey::UNIVERSAL.0);

    /// Convert from `PinKey`.
    pub const fn from_key(key: PinKey) -> Self {
        Self(key.0)
    }

    /// Convert to `PinKey`.
    #[allow(dead_code)]
    pub const fn to_key(self) -> PinKey {
        PinKey(self.0)
    }
}

// Manual Hash for StatePath, GsmField, UsimField since PinId is Hashable.
impl std::hash::Hash for StatePath {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::CardState => {}
            Self::Gsm(f) => f.hash(state),
            Self::Usim(f) => f.hash(state),
        }
    }
}

impl std::hash::Hash for GsmField {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::SelectionCtx | Self::FsData | Self::Ki | Self::Version | Self::RspQueue => {}
            Self::Pin(id, f) => {
                id.hash(state);
                f.hash(state);
            }
        }
    }
}

impl std::hash::Hash for UsimField {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::SelectionCtx | Self::FsData | Self::Auth | Self::Proactive
            | Self::RspQueue | Self::TerminalCapability | Self::Deactivation
            | Self::LastAidMatch | Self::Suci => {}
            Self::Pin(id, f) => {
                id.hash(state);
                f.hash(state);
            }
            Self::Channel(n) => n.hash(state),
        }
    }
}

// =========================================================================
// Display -- human-readable dotted paths for error messages
// =========================================================================

impl fmt::Display for PinId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0x01 => write!(f, "PIN1"),
            0x81 => write!(f, "PIN2"),
            0x0A => write!(f, "ADM1"),
            0x0B => write!(f, "ADM2"),
            0x11 => write!(f, "UNIVERSAL"),
            other => write!(f, "0x{other:02X}"),
        }
    }
}

impl fmt::Display for PinField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count => write!(f, "count"),
            Self::Key => write!(f, "key"),
            Self::Pin => write!(f, "pin"),
            Self::PinRetries => write!(f, "pin_retries"),
            Self::PinMax => write!(f, "pin_max"),
            Self::Puk => write!(f, "puk"),
            Self::PukRetries => write!(f, "puk_retries"),
            Self::Enabled => write!(f, "enabled"),
            Self::Verified => write!(f, "verified"),
        }
    }
}

impl fmt::Display for GsmField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionCtx => write!(f, "selection_ctx"),
            Self::FsData => write!(f, "fs_data"),
            Self::Pin(id, field) => write!(f, "pin.{id}.{field}"),
            Self::Ki => write!(f, "ki"),
            Self::Version => write!(f, "version"),
            Self::RspQueue => write!(f, "rsp_queue"),
        }
    }
}

impl fmt::Display for UsimField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionCtx => write!(f, "selection_ctx"),
            Self::FsData => write!(f, "fs_data"),
            Self::Pin(id, field) => write!(f, "pin.{id}.{field}"),
            Self::Auth => write!(f, "auth"),
            Self::Proactive => write!(f, "proactive"),
            Self::RspQueue => write!(f, "rsp_queue"),
            Self::TerminalCapability => write!(f, "terminal_capability"),
            Self::Deactivation => write!(f, "deactivation"),
            Self::Channel(n) => write!(f, "channel[{n}]"),
            Self::LastAidMatch => write!(f, "last_aid_match"),
            Self::Suci => write!(f, "suci"),
        }
    }
}

impl fmt::Display for StatePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CardState => write!(f, "card_state"),
            Self::Gsm(field) => write!(f, "gsm.{field}"),
            Self::Usim(field) => write!(f, "usim.{field}"),
        }
    }
}

// =========================================================================
// Snapshot layout constants
// =========================================================================

/// Number of PIN slots in both `GsmApp` and `UsimApp`.
const PIN_SLOT_COUNT: usize = 5;

/// Size of a single serialized PIN slot (22 bytes).
const PIN_SLOT_SIZE: usize = 22;

/// Size of the `PinManager<5>` snapshot (1 count + 5 x 22).
const PIN_MANAGER_SIZE: usize = 1 + PIN_SLOT_COUNT * PIN_SLOT_SIZE;

/// Fields within a single PIN slot, with byte offsets relative to slot start.
const PIN_SLOT_FIELDS: [(usize, usize, PinField); 8] = [
    (0, 1, PinField::Key),         // key: 1 byte
    (1, 9, PinField::Pin),         // pin: 8 bytes
    (9, 10, PinField::PinRetries), // pin_retries: 1 byte
    (10, 11, PinField::PinMax),    // pin_max: 1 byte
    (11, 19, PinField::Puk),       // puk: 8 bytes
    (19, 20, PinField::PukRetries),// puk_retries: 1 byte
    (20, 21, PinField::Enabled),   // enabled: 1 byte
    (21, 22, PinField::Verified),  // verified: 1 byte
];

// =========================================================================
// SnapshotRegistry
// =========================================================================

/// A single diff group: a semantic path and the byte-level changes within it.
/// Each tuple in the vec is `(offset, old_byte, new_byte)`.
pub type DiffGroup<'a> = (&'a StatePath, Vec<(usize, u8, u8)>);

/// A registry entry: a byte range mapped to a semantic path.
#[derive(Clone, Debug)]
struct Entry {
    range: Range<usize>,
    path: StatePath,
}

/// Maps every byte in a flat SIM state snapshot to its semantic provenance.
///
/// Built once from a concrete snapshot. Test steps use `identify()` to resolve
/// byte offsets to typed paths, and `resolve()` to find byte ranges from paths.
pub struct SnapshotRegistry {
    /// Sorted by range.start, most-specific (smallest) ranges last for
    /// overlapping regions (PIN fields within PIN manager).
    entries: Vec<Entry>,
    /// Total snapshot size (for validation).
    snapshot_size: usize,
}

impl SnapshotRegistry {
    /// Build a registry from a concrete snapshot buffer.
    ///
    /// Uses `SNAPSHOT_SIZE` constants and `PIN_SNAPSHOT_OFFSET` from the core
    /// crates to compute byte ranges. Scans PIN slot key bytes to identify
    /// which slots are occupied and map them to `PinId` values.
    pub fn from_snapshot(bytes: &[u8]) -> Self {
        use simrs_gsm::GsmApp;
        use simrs_milenage::MilenageParams;
        use simrs_usim::UsimApp;

        type TestUsim = UsimApp<MilenageParams>;

        let total = 1 + GsmApp::SNAPSHOT_SIZE + TestUsim::SNAPSHOT_SIZE;
        assert_eq!(
            bytes.len(), total,
            "Snapshot size mismatch: expected {total}, got {}",
            bytes.len()
        );

        let mut entries = Vec::new();

        // -- CardState (1 byte at offset 0) --
        entries.push(Entry {
            range: 0..1,
            path: StatePath::CardState,
        });

        // -- GsmApp --
        let gsm_base = 1;
        Self::register_gsm(&mut entries, bytes, gsm_base);

        // -- UsimApp --
        let usim_base = 1 + GsmApp::SNAPSHOT_SIZE;
        Self::register_usim(&mut entries, bytes, usim_base);

        // Sort by range start, then by range length descending (broadest first).
        entries.sort_by(|a, b| {
            a.range.start.cmp(&b.range.start)
                .then_with(|| b.range.len().cmp(&a.range.len()))
        });

        Self {
            entries,
            snapshot_size: total,
        }
    }

    /// Register `GsmApp` entries.
    fn register_gsm(entries: &mut Vec<Entry>, bytes: &[u8], base: usize) {
        use simrs_fs::SelectionCtx;
        use simrs_gsm::GsmApp;
        use simrs_iso7816::ResponseQueue;

        let mut off = base;

        // SelectionCtx
        let sel_end = off + SelectionCtx::SNAPSHOT_SIZE;
        entries.push(Entry {
            range: off..sel_end,
            path: StatePath::Gsm(GsmField::SelectionCtx),
        });
        off = sel_end;

        // FsData
        let fs_size = GsmApp::PIN_SNAPSHOT_OFFSET - SelectionCtx::SNAPSHOT_SIZE;
        let fs_end = off + fs_size;
        entries.push(Entry {
            range: off..fs_end,
            path: StatePath::Gsm(GsmField::FsData),
        });
        off = fs_end;

        // PinManager<5>
        let pin_base = off;
        Self::register_pin_slots(
            entries,
            bytes,
            pin_base,
            |id, field| StatePath::Gsm(GsmField::Pin(id, field)),
        );
        off = pin_base + PIN_MANAGER_SIZE;

        // Ki (16 bytes)
        entries.push(Entry {
            range: off..off + 16,
            path: StatePath::Gsm(GsmField::Ki),
        });
        off += 16;

        // Comp128Version (1 byte)
        entries.push(Entry {
            range: off..off + 1,
            path: StatePath::Gsm(GsmField::Version),
        });
        off += 1;

        // ResponseQueue<23> (24 bytes)
        entries.push(Entry {
            range: off..off + ResponseQueue::<23>::SNAPSHOT_SIZE,
            path: StatePath::Gsm(GsmField::RspQueue),
        });

        // Sanity check
        let expected_end = base + GsmApp::SNAPSHOT_SIZE;
        let actual_end = off + ResponseQueue::<23>::SNAPSHOT_SIZE;
        assert_eq!(
            actual_end, expected_end,
            "GsmApp layout mismatch: entries end at {actual_end}, expected {expected_end}"
        );
    }

    /// Register `UsimApp` entries.
    fn register_usim(entries: &mut Vec<Entry>, bytes: &[u8], base: usize) {
        use simrs_fs::{DeactivationTracker, SelectionCtx};
        use simrs_iso7816::ResponseQueue;
        use simrs_milenage::MilenageParams;
        use simrs_proactive::ProactiveState;
        use simrs_usim::UsimApp;

        type TestUsim = UsimApp<MilenageParams>;

        let mut off = base;

        // SelectionCtx
        let sel_end = off + SelectionCtx::SNAPSHOT_SIZE;
        entries.push(Entry {
            range: off..sel_end,
            path: StatePath::Usim(UsimField::SelectionCtx),
        });
        off = sel_end;

        // FsData
        let fs_size = TestUsim::PIN_SNAPSHOT_OFFSET - SelectionCtx::SNAPSHOT_SIZE;
        let fs_end = off + fs_size;
        entries.push(Entry {
            range: off..fs_end,
            path: StatePath::Usim(UsimField::FsData),
        });
        off = fs_end;

        // PinManager<5>
        let pin_base = off;
        Self::register_pin_slots(
            entries,
            bytes,
            pin_base,
            |id, field| StatePath::Usim(UsimField::Pin(id, field)),
        );
        off = pin_base + PIN_MANAGER_SIZE;

        // Auth (MilenageParams)
        let auth_end = off + MilenageParams::SNAPSHOT_SIZE;
        entries.push(Entry {
            range: off..auth_end,
            path: StatePath::Usim(UsimField::Auth),
        });
        off = auth_end;

        // ProactiveState
        let pro_end = off + ProactiveState::SNAPSHOT_SIZE;
        entries.push(Entry {
            range: off..pro_end,
            path: StatePath::Usim(UsimField::Proactive),
        });
        off = pro_end;

        // ResponseQueue<64>
        let rsp_end = off + ResponseQueue::<64>::SNAPSHOT_SIZE;
        entries.push(Entry {
            range: off..rsp_end,
            path: StatePath::Usim(UsimField::RspQueue),
        });
        off = rsp_end;

        // terminal_capability (16 bytes) + terminal_capability_len (1 byte) = 17
        let tc_end = off + 17;
        entries.push(Entry {
            range: off..tc_end,
            path: StatePath::Usim(UsimField::TerminalCapability),
        });
        off = tc_end;

        // DeactivationTracker
        let deact_end = off + DeactivationTracker::SNAPSHOT_SIZE;
        entries.push(Entry {
            range: off..deact_end,
            path: StatePath::Usim(UsimField::Deactivation),
        });
        off = deact_end;

        // Channels: 4 x (1 is_open + SelectionCtx::SNAPSHOT_SIZE)
        let ch_entry_size = 1 + SelectionCtx::SNAPSHOT_SIZE;
        for i in 0..4u8 {
            let ch_end = off + ch_entry_size;
            entries.push(Entry {
                range: off..ch_end,
                path: StatePath::Usim(UsimField::Channel(i)),
            });
            off = ch_end;
        }

        // last_aid_match (1 byte)
        entries.push(Entry {
            range: off..off + 1,
            path: StatePath::Usim(UsimField::LastAidMatch),
        });
        off += 1;

        // SUCI state (41 bytes: 1 flag + 32 seed + 8 counter)
        let suci_size = TestUsim::SUCI_SNAPSHOT_SIZE;
        entries.push(Entry {
            range: off..off + suci_size,
            path: StatePath::Usim(UsimField::Suci),
        });
        off += suci_size;

        // Sanity check
        let expected_end = base + TestUsim::SNAPSHOT_SIZE;
        assert_eq!(
            off, expected_end,
            "UsimApp layout mismatch: entries end at {off}, expected {expected_end}"
        );
    }

    /// Register per-field entries for a `PinManager<5>` region.
    ///
    /// Scans the snapshot bytes to find slot key values, mapping occupied
    /// slots to `PinId`. Empty slots (key=0) get a `PinId(0)` placeholder.
    fn register_pin_slots(
        entries: &mut Vec<Entry>,
        bytes: &[u8],
        pin_base: usize,
        make_path: impl Fn(PinId, PinField) -> StatePath,
    ) {
        // Register the count byte. PinId::EMPTY is a sentinel -- the count byte
        // is not associated with any particular slot.
        entries.push(Entry {
            range: pin_base..pin_base + 1,
            path: make_path(PinId::EMPTY, PinField::Count),
        });

        // Walk each of the N slots.
        let slot_base = pin_base + 1; // after count byte
        for slot_idx in 0..PIN_SLOT_COUNT {
            let s_off = slot_base + slot_idx * PIN_SLOT_SIZE;
            let key_byte = bytes[s_off]; // first byte of slot is the PinKey value
            let pin_id = PinId(key_byte);

            for &(field_start, field_end, ref field) in &PIN_SLOT_FIELDS {
                let abs_start = s_off + field_start;
                let abs_end = s_off + field_end;
                entries.push(Entry {
                    range: abs_start..abs_end,
                    path: make_path(pin_id, field.clone()),
                });
            }
        }
    }

    /// Total expected snapshot size.
    #[allow(dead_code)]
    pub fn snapshot_size(&self) -> usize {
        self.snapshot_size
    }

    /// Identify the semantic path for a byte offset.
    ///
    /// Returns the most specific (smallest range) entry that covers the offset.
    /// Panics if the offset is out of range.
    pub fn identify(&self, offset: usize) -> &StatePath {
        assert!(
            offset < self.snapshot_size,
            "offset {offset} out of range (snapshot size {})",
            self.snapshot_size
        );

        // Linear scan for the most specific match (smallest range covering offset).
        // With ~80 entries this is fast enough.
        let mut best: Option<&Entry> = None;
        for entry in &self.entries {
            if entry.range.contains(&offset) {
                match best {
                    None => best = Some(entry),
                    Some(prev) if entry.range.len() < prev.range.len() => best = Some(entry),
                    _ => {}
                }
            }
        }
        &best
            .unwrap_or_else(|| panic!("no registry entry covers offset {offset}"))
            .path
    }

    /// Resolve a `StatePath` to its byte range.
    ///
    /// Returns `None` if the path isn't in the registry (e.g. unused PIN slot).
    #[allow(dead_code)]
    pub fn resolve(&self, path: &StatePath) -> Option<Range<usize>> {
        self.entries
            .iter()
            .find(|e| &e.path == path)
            .map(|e| e.range.clone())
    }

    /// Compare two snapshot buffers and return all differing byte positions
    /// grouped by semantic path.
    pub fn diff<'a>(
        &'a self,
        before: &[u8],
        after: &[u8],
    ) -> Vec<DiffGroup<'a>> {
        assert_eq!(before.len(), self.snapshot_size);
        assert_eq!(after.len(), self.snapshot_size);

        let mut groups: Vec<DiffGroup<'_>> = Vec::new();

        for i in 0..self.snapshot_size {
            if before[i] != after[i] {
                let path = self.identify(i);
                if let Some(group) = groups.iter_mut().find(|(p, _)| *p == path) {
                    group.1.push((i, before[i], after[i]));
                } else {
                    groups.push((path, vec![(i, before[i], after[i])]));
                }
            }
        }

        groups
    }
}

// =========================================================================
// Reservation matching
// =========================================================================

/// Check whether a `StatePath` is covered by any reservation in the set.
///
/// Exact match: the path must be in the set. No prefix/wildcard matching --
/// each field must be individually reserved.
pub fn is_reserved(path: &StatePath, reservations: &HashSet<StatePath>) -> bool {
    reservations.contains(path)
}

/// Format a diff report suitable for assertion failure messages.
pub fn format_diff_report(
    diffs: &[DiffGroup<'_>],
    reservations: &HashSet<StatePath>,
) -> String {
    let mut out = String::new();
    for (path, changes) in diffs {
        let reserved = is_reserved(path, reservations);
        let marker = if reserved { " [reserved]" } else { " [UNEXPECTED]" };
        for &(offset, old, new) in changes {
            let _ = writeln!(
                out,
                "  byte {offset} [{path}]: 0x{old:02X} -> 0x{new:02X}{marker}"
            );
        }
    }
    out
}

// =========================================================================
// Reservation helpers for When steps
// =========================================================================

/// Reserve PIN verification side effects (retries + verified flag).
///
/// Covers both USIM and GSM PIN managers since the simulator may
/// mutate either or both during a VERIFY command.
pub fn reserve_pin_verify(reservations: &mut HashSet<StatePath>, key: PinKey) {
    let id = PinId::from_key(key);
    reservations.insert(StatePath::Usim(UsimField::Pin(id, PinField::PinRetries)));
    reservations.insert(StatePath::Usim(UsimField::Pin(id, PinField::Verified)));
    reservations.insert(StatePath::Gsm(GsmField::Pin(id, PinField::PinRetries)));
    reservations.insert(StatePath::Gsm(GsmField::Pin(id, PinField::Verified)));
}

/// Reserve PIN change side effects (retries + verified + pin value).
pub fn reserve_pin_change(reservations: &mut HashSet<StatePath>, key: PinKey) {
    reserve_pin_verify(reservations, key);
    let id = PinId::from_key(key);
    reservations.insert(StatePath::Usim(UsimField::Pin(id, PinField::Pin)));
    reservations.insert(StatePath::Gsm(GsmField::Pin(id, PinField::Pin)));
}

/// Reserve PIN enable/disable side effects (retries + verified + enabled).
pub fn reserve_pin_toggle(reservations: &mut HashSet<StatePath>, key: PinKey) {
    reserve_pin_verify(reservations, key);
    let id = PinId::from_key(key);
    reservations.insert(StatePath::Usim(UsimField::Pin(id, PinField::Enabled)));
    reservations.insert(StatePath::Gsm(GsmField::Pin(id, PinField::Enabled)));
}

/// Reserve PIN unblock side effects (retries + verified + pin value + puk retries).
pub fn reserve_pin_unblock(reservations: &mut HashSet<StatePath>, key: PinKey) {
    reserve_pin_change(reservations, key);
    let id = PinId::from_key(key);
    reservations.insert(StatePath::Usim(UsimField::Pin(id, PinField::PukRetries)));
    reservations.insert(StatePath::Gsm(GsmField::Pin(id, PinField::PukRetries)));
}

/// Reserve response queue changes (both USIM and GSM).
///
/// Call from When steps that send commands expected to queue responses
/// (SELECT, AUTHENTICATE success) when followed by "no other SIM state
/// has changed" assertions.
pub fn reserve_rsp_queue(reservations: &mut HashSet<StatePath>) {
    reservations.insert(StatePath::Usim(UsimField::RspQueue));
    reservations.insert(StatePath::Gsm(GsmField::RspQueue));
}

/// Reserve selection context changes (both USIM and GSM).
///
/// Call from When steps that change the current DF/EF selection when
/// followed by "no other SIM state has changed" assertions.
pub fn reserve_selection_ctx(reservations: &mut HashSet<StatePath>) {
    reservations.insert(StatePath::Usim(UsimField::SelectionCtx));
    reservations.insert(StatePath::Gsm(GsmField::SelectionCtx));
}

/// Reserve authentication state changes (USIM only; no GSM equivalent).
///
/// `MilenageParams::save_state` serializes key material (K, `OPc`, constants)
/// and the `SQN_HE` counter. A successful AUTHENTICATE advances `SQN_HE`, so
/// the auth snapshot region changes. Call from When steps that send
/// AUTHENTICATE commands expected to succeed.
pub fn reserve_auth(reservations: &mut HashSet<StatePath>) {
    reservations.insert(StatePath::Usim(UsimField::Auth));
}

/// Reserve proactive engine state changes (USIM only; no GSM equivalent).
///
/// Call from When steps that send commands expected to trigger or
/// advance the proactive (STK) engine state (e.g., TERMINAL PROFILE).
pub fn reserve_proactive(reservations: &mut HashSet<StatePath>) {
    reservations.insert(StatePath::Usim(UsimField::Proactive));
}

/// Reserve terminal capability changes (USIM only).
///
/// Call from When steps that send TERMINAL PROFILE commands.
pub fn reserve_terminal_capability(reservations: &mut HashSet<StatePath>) {
    reservations.insert(StatePath::Usim(UsimField::TerminalCapability));
}

// Unit tests for SnapshotRegistry are validated through the cucumber integration
// tests: any layout mismatch will panic in `from_snapshot`'s assert_eq checks
// or in `identify`'s no-entry-covers-offset panic.
