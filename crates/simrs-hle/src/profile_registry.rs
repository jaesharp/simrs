//! Profile registry for snapshot self-sufficiency.
//!
//! Snapshots embed a profile ID so [`crate::hle_init_from_snapshot`] can
//! reattach the correct static `&'static DfDef` and `&'static [AdfSlot]`
//! references without the caller needing to know which profile was used.

use simrs_fs::{AdfSlot, DfDef};

/// A statically-registered profile: ATR, MF filesystem, and ADF table.
pub struct StaticProfile {
    /// Numeric identifier embedded in snapshots.
    pub id: u16,
    /// Human-readable name for diagnostics.
    pub name: &'static str,
    /// ATR bytes.
    pub atr: &'static [u8],
    /// Master filesystem.
    pub mf: &'static DfDef,
    /// ADF table (AID -> DF).
    pub adf_table: &'static [AdfSlot],
}

/// The default reference USIM profile, always available.
pub const REFERENCE_USIM_ID: u16 = 0x0001;

/// All registered static profiles.
pub const PROFILES: &[StaticProfile] = &[StaticProfile {
    id: REFERENCE_USIM_ID,
    name: "reference-usim",
    atr: &crate::DEFAULT_ATR,
    mf: &simrs_usim::profile::REFERENCE_MF,
    adf_table: &simrs_usim::profile::ADF_TABLE,
}];

/// Look up a profile by ID.
#[must_use]
pub fn lookup(id: u16) -> Option<&'static StaticProfile> {
    PROFILES.iter().find(|p| p.id == id)
}
