//! Applet registry: AID-based lookup and management per GP 2.1.1 Chapter 9.
//!
//! The registry stores applet entries, each identified by an AID (Application
//! Identifier, 5-16 bytes per ISO 7816-4). The ISD (Issuer Security Domain)
//! is always present at index 0 and is never removed.
//!
//! AID matching supports both exact match and partial (prefix) match per
//! GP 2.1.1 clause 9.3.2: if no exact match is found, the first entry
//! whose AID is a prefix of the requested AID is returned.

use crate::lifecycle::AppletLifecycle;

/// Maximum AID length per ISO/IEC 7816-4 (16 bytes).
pub const MAX_AID_LEN: usize = 16;

/// Maximum instances tracked per load file.
const MAX_INSTANCES_PER_LF: usize = 4;

/// A registered applet entry in the GP registry.
#[derive(Clone)]
pub struct AppletEntry {
    /// Application Identifier (5-16 bytes).
    aid: [u8; MAX_AID_LEN],
    /// Effective AID length.
    aid_len: u8,
    /// Applet lifecycle state.
    lifecycle: AppletLifecycle,
    /// Privilege byte (GP 2.1.1 Table 9-3). Bit 7 = security domain.
    privileges: u8,
    /// Index of the owning Security Domain in `GpOpen.sds[]`, if any.
    /// `None` means ISD-managed (the default).
    owner_sd_index: Option<u8>,
    /// JCVM package index (if this applet runs on the bytecode interpreter).
    jcvm_pkg_idx: Option<u8>,
    /// JCVM process method index within the package.
    jcvm_process_method: u8,
}

impl AppletEntry {
    /// Create a new applet entry (ISD-managed).
    ///
    /// # Panics
    ///
    /// Panics if `aid` is empty or longer than 16 bytes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(aid: &[u8], lifecycle: AppletLifecycle, privileges: u8) -> Self {
        Self::new_with_sd(aid, lifecycle, privileges, None)
    }

    /// Create a new applet entry with explicit SD ownership.
    ///
    /// # Panics
    ///
    /// Panics if `aid` is empty or longer than 16 bytes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_with_sd(
        aid: &[u8],
        lifecycle: AppletLifecycle,
        privileges: u8,
        owner_sd_index: Option<u8>,
    ) -> Self {
        assert!(
            !aid.is_empty() && aid.len() <= MAX_AID_LEN,
            "AID must be 1-16 bytes"
        );
        let mut buf = [0u8; MAX_AID_LEN];
        buf[..aid.len()].copy_from_slice(aid);
        Self {
            aid: buf,
            aid_len: aid.len() as u8,
            lifecycle,
            privileges,
            owner_sd_index,
            jcvm_pkg_idx: None,
            jcvm_process_method: 0,
        }
    }

    /// AID bytes.
    pub fn aid(&self) -> &[u8] {
        &self.aid[..self.aid_len as usize]
    }

    /// Current lifecycle state.
    pub const fn lifecycle(&self) -> AppletLifecycle {
        self.lifecycle
    }

    /// Set the lifecycle state.
    pub const fn set_lifecycle(&mut self, lc: AppletLifecycle) {
        self.lifecycle = lc;
    }

    /// Privilege byte.
    pub const fn privileges(&self) -> u8 {
        self.privileges
    }

    /// Whether this entry is a Security Domain (privilege bit 7).
    pub const fn is_security_domain(&self) -> bool {
        self.privileges & 0x80 != 0
    }

    /// Index of the owning SD, if any.
    pub const fn owner_sd_index(&self) -> Option<u8> {
        self.owner_sd_index
    }

    /// JCVM package index, if this applet is a bytecode applet.
    pub const fn jcvm_pkg_idx(&self) -> Option<u8> {
        self.jcvm_pkg_idx
    }

    /// JCVM process method index within the package.
    pub const fn jcvm_process_method(&self) -> u8 {
        self.jcvm_process_method
    }

    /// Link this applet entry to a JCVM package for bytecode dispatch.
    pub const fn set_jcvm(&mut self, pkg_idx: u8, process_method: u8) {
        self.jcvm_pkg_idx = Some(pkg_idx);
        self.jcvm_process_method = process_method;
    }
}

/// Security Domain entry (ISD or supplementary SD).
#[derive(Clone)]
pub struct SecurityDomain {
    /// The SD's own AID.
    aid: [u8; MAX_AID_LEN],
    /// Effective AID length.
    aid_len: u8,
    /// SD lifecycle (uses `AppletLifecycle` encoding).
    lifecycle: AppletLifecycle,
    /// SD privileges.
    privileges: u8,
}

impl SecurityDomain {
    /// Create a new Security Domain entry.
    ///
    /// # Panics
    ///
    /// Panics if `aid` is empty or longer than 16 bytes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(aid: &[u8], lifecycle: AppletLifecycle, privileges: u8) -> Self {
        assert!(
            !aid.is_empty() && aid.len() <= MAX_AID_LEN,
            "AID must be 1-16 bytes"
        );
        let mut buf = [0u8; MAX_AID_LEN];
        buf[..aid.len()].copy_from_slice(aid);
        Self {
            aid: buf,
            aid_len: aid.len() as u8,
            lifecycle,
            privileges: privileges | 0x80, // bit 7 always set for SDs
        }
    }

    /// AID bytes.
    pub fn aid(&self) -> &[u8] {
        &self.aid[..self.aid_len as usize]
    }

    /// Current lifecycle state.
    pub const fn lifecycle(&self) -> AppletLifecycle {
        self.lifecycle
    }

    /// Set the lifecycle state.
    pub const fn set_lifecycle(&mut self, lc: AppletLifecycle) {
        self.lifecycle = lc;
    }

    /// Privilege byte.
    pub const fn privileges(&self) -> u8 {
        self.privileges
    }
}

/// A load file entry in the GP registry.
///
/// Tracks the load file AID and the registry slot indices of instances
/// created from it (for cascade DELETE per GP 2.1.1 clause 9.2).
#[derive(Clone)]
pub struct LoadFileEntry {
    /// Load File AID.
    aid: [u8; MAX_AID_LEN],
    /// Effective AID length.
    aid_len: u8,
    /// Registry slot indices of instances created from this load file.
    instance_slots: [Option<u8>; MAX_INSTANCES_PER_LF],
}

impl LoadFileEntry {
    /// Create a new load file entry.
    ///
    /// # Panics
    ///
    /// Panics if `aid` is empty or longer than 16 bytes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(aid: &[u8]) -> Self {
        assert!(
            !aid.is_empty() && aid.len() <= MAX_AID_LEN,
            "AID must be 1-16 bytes"
        );
        let mut buf = [0u8; MAX_AID_LEN];
        buf[..aid.len()].copy_from_slice(aid);
        Self {
            aid: buf,
            aid_len: aid.len() as u8,
            instance_slots: [None; MAX_INSTANCES_PER_LF],
        }
    }

    /// Load file AID bytes.
    pub fn aid(&self) -> &[u8] {
        &self.aid[..self.aid_len as usize]
    }

    /// Instance slot references.
    pub const fn instance_slots(&self) -> &[Option<u8>; MAX_INSTANCES_PER_LF] {
        &self.instance_slots
    }

    /// Track a new instance slot. Returns `false` if full.
    pub fn add_instance(&mut self, slot: u8) -> bool {
        for s in &mut self.instance_slots {
            if s.is_none() {
                *s = Some(slot);
                return true;
            }
        }
        false
    }
}

/// Find a load file by exact AID match. Returns index.
pub fn find_load_file<const L: usize>(
    load_files: &[Option<LoadFileEntry>; L],
    aid: &[u8],
) -> Option<usize> {
    for (i, lf) in load_files.iter().enumerate() {
        if let Some(lf) = lf
            && lf.aid() == aid
        {
            return Some(i);
        }
    }
    None
}

/// Find an empty slot in the load file array.
pub fn find_empty_lf_slot<const L: usize>(
    load_files: &[Option<LoadFileEntry>; L],
) -> Option<usize> {
    load_files.iter().position(core::option::Option::is_none)
}

/// Check if `candidate` AID matches `requested` AID.
///
/// Returns `true` for exact match or if `candidate` is a prefix of `requested`
/// (partial AID selection per GP 2.1.1 clause 9.3.2).
pub fn aid_matches(candidate: &[u8], requested: &[u8]) -> bool {
    if candidate.len() > requested.len() {
        return false;
    }
    candidate == &requested[..candidate.len()]
}

/// Check if `candidate` AID exactly matches `requested` AID.
pub fn aid_exact_match(candidate: &[u8], requested: &[u8]) -> bool {
    candidate == requested
}

/// Check if `partial` AID is a prefix of `registered` AID.
///
/// Used for partial AID selection per GP 2.1.1 clause 9.6.2.4:
/// "the card shall search for the application whose AID starts with
/// the partial DF name."
pub fn partial_aid_matches(registered: &[u8], partial: &[u8]) -> bool {
    if partial.len() > registered.len() {
        return false;
    }
    &registered[..partial.len()] == partial
}

/// Search the registry for a matching AID. Returns the index.
///
/// Strategy per GP 2.1.1 clause 9.3.2:
/// 1. Exact match first.
/// 2. If no exact match, prefix match (candidate is prefix of requested).
/// 3. If no prefix match, partial AID match (requested is prefix of candidate,
///    per GP 2.1.1 clause 9.6.2.4).
///
/// Only selectable applets are considered.
pub fn find_by_aid<const N: usize>(
    registry: &[Option<AppletEntry>; N],
    requested_aid: &[u8],
) -> Option<usize> {
    // First pass: exact match among selectable entries.
    for (i, entry) in registry.iter().enumerate() {
        if let Some(e) = entry
            && e.lifecycle().is_selectable()
            && aid_exact_match(e.aid(), requested_aid)
        {
            return Some(i);
        }
    }
    // Second pass: prefix match (registered is prefix of requested).
    for (i, entry) in registry.iter().enumerate() {
        if let Some(e) = entry
            && e.lifecycle().is_selectable()
            && aid_matches(e.aid(), requested_aid)
        {
            return Some(i);
        }
    }
    // Third pass: partial AID match (requested is prefix of registered).
    for (i, entry) in registry.iter().enumerate() {
        if let Some(e) = entry
            && e.lifecycle().is_selectable()
            && partial_aid_matches(e.aid(), requested_aid)
        {
            return Some(i);
        }
    }
    None
}

/// Search for the next matching AID after `start_after` index.
///
/// Used for P2=0x02 (next occurrence) in SELECT by partial AID.
/// Searches only by partial AID match (requested is prefix of registered).
pub fn find_by_aid_after<const N: usize>(
    registry: &[Option<AppletEntry>; N],
    requested_aid: &[u8],
    start_after: usize,
) -> Option<usize> {
    for (i, entry) in registry.iter().enumerate() {
        if i <= start_after {
            continue;
        }
        if let Some(e) = entry
            && e.lifecycle().is_selectable()
            && (aid_exact_match(e.aid(), requested_aid)
                || partial_aid_matches(e.aid(), requested_aid))
        {
            return Some(i);
        }
    }
    None
}

/// Find an empty slot in the registry. Returns the index.
pub fn find_empty_slot<const N: usize>(registry: &[Option<AppletEntry>; N]) -> Option<usize> {
    registry.iter().position(core::option::Option::is_none)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(aid: &[u8], lifecycle: AppletLifecycle) -> AppletEntry {
        AppletEntry::new(aid, lifecycle, 0x00)
    }

    #[test]
    fn aid_exact_match_found() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x03];
        assert!(aid_exact_match(&aid, &aid));
    }

    #[test]
    fn aid_exact_match_not_found() {
        let a = [0xA0, 0x00, 0x00, 0x00, 0x03];
        let b = [0xA0, 0x00, 0x00, 0x00, 0x04];
        assert!(!aid_exact_match(&a, &b));
    }

    #[test]
    fn aid_prefix_match() {
        let prefix = [0xA0, 0x00, 0x00];
        let full = [0xA0, 0x00, 0x00, 0x01, 0x02];
        assert!(aid_matches(&prefix, &full));
    }

    #[test]
    fn aid_prefix_no_match_when_longer() {
        let long = [0xA0, 0x00, 0x00, 0x01, 0x02];
        let short = [0xA0, 0x00, 0x00];
        assert!(!aid_matches(&long, &short));
    }

    #[test]
    fn registry_find_exact_match() {
        let mut reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        reg[0] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x00, 0x01],
            AppletLifecycle::Selectable,
        ));
        reg[1] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x00, 0x02],
            AppletLifecycle::Selectable,
        ));

        assert_eq!(find_by_aid(&reg, &[0xA0, 0x00, 0x00, 0x00, 0x02]), Some(1));
    }

    #[test]
    fn registry_find_prefix_match() {
        let mut reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        reg[0] = Some(make_entry(&[0xA0, 0x00, 0x00], AppletLifecycle::Selectable));

        // Requested AID is longer but has the same prefix.
        assert_eq!(find_by_aid(&reg, &[0xA0, 0x00, 0x00, 0x01, 0x02]), Some(0));
    }

    #[test]
    fn registry_exact_preferred_over_prefix() {
        let mut reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        // Index 0: prefix match only.
        reg[0] = Some(make_entry(&[0xA0, 0x00, 0x00], AppletLifecycle::Selectable));
        // Index 1: exact match.
        reg[1] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x01, 0x02],
            AppletLifecycle::Selectable,
        ));

        assert_eq!(find_by_aid(&reg, &[0xA0, 0x00, 0x00, 0x01, 0x02]), Some(1));
    }

    #[test]
    fn registry_ignores_non_selectable() {
        let mut reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        reg[0] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x00, 0x01],
            AppletLifecycle::Installed, // not selectable
        ));
        reg[1] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x00, 0x01],
            AppletLifecycle::Selectable,
        ));

        assert_eq!(find_by_aid(&reg, &[0xA0, 0x00, 0x00, 0x00, 0x01]), Some(1));
    }

    #[test]
    fn registry_find_not_found() {
        let reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        assert_eq!(find_by_aid(&reg, &[0xA0, 0x00, 0x00, 0x00, 0x01]), None);
    }

    #[test]
    fn find_empty_slot_works() {
        let mut reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        reg[0] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x00, 0x01],
            AppletLifecycle::Selectable,
        ));
        assert_eq!(find_empty_slot(&reg), Some(1));
    }

    #[test]
    fn find_empty_slot_full() {
        let mut reg: [Option<AppletEntry>; 2] = [const { None }; 2];
        reg[0] = Some(make_entry(&[0x01], AppletLifecycle::Selectable));
        reg[1] = Some(make_entry(&[0x02], AppletLifecycle::Selectable));
        assert_eq!(find_empty_slot(&reg), None);
    }

    #[test]
    fn security_domain_always_has_sd_bit() {
        let sd = SecurityDomain::new(&[0xA0, 0x00, 0x00], AppletLifecycle::Selectable, 0x00);
        assert_eq!(sd.privileges() & 0x80, 0x80);
    }

    #[test]
    fn applet_entry_is_security_domain() {
        let app = AppletEntry::new(&[0x01], AppletLifecycle::Selectable, 0x00);
        assert!(!app.is_security_domain());
        let sd = AppletEntry::new(&[0x01], AppletLifecycle::Selectable, 0x80);
        assert!(sd.is_security_domain());
    }

    #[test]
    fn personalized_applet_is_selectable() {
        let mut reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        reg[0] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x00, 0x01],
            AppletLifecycle::Personalized,
        ));
        assert_eq!(find_by_aid(&reg, &[0xA0, 0x00, 0x00, 0x00, 0x01]), Some(0));
    }

    #[test]
    fn locked_applet_not_found() {
        let mut reg: [Option<AppletEntry>; 4] = [const { None }; 4];
        reg[0] = Some(make_entry(
            &[0xA0, 0x00, 0x00, 0x00, 0x01],
            AppletLifecycle::Locked,
        ));
        assert_eq!(find_by_aid(&reg, &[0xA0, 0x00, 0x00, 0x00, 0x01]), None);
    }
}
