//! `Snapshotable` impl for `PinManager` -- ADR 0001 Phase 3.
//!
//! Wraps the existing `save_state` / `restore_state` raw byte API
//! in the opaque `simrs_snapshot::Snapshot` type. Gated behind the
//! `snapshot` feature flag so production builds get no
//! `Snapshotable` surface.

use simrs_snapshot::{
    Snapshot, SnapshotError, Snapshotable, producer::PIN_MANAGER, restore_via_raw_bytes,
    snapshot_via_raw_bytes,
};

use crate::PinManager;

impl<const N: usize> Snapshotable for PinManager<N> {
    const PRODUCER_TAG: u16 = PIN_MANAGER;
    const VERSION: (u8, u8) = (1, 0);

    fn snapshot(&self) -> Snapshot {
        snapshot_via_raw_bytes(
            Self::VERSION,
            Self::PRODUCER_TAG,
            Self::SNAPSHOT_SIZE,
            |buf| self.save_state(buf),
        )
    }

    fn restore(&mut self, snap: &Snapshot) -> Result<(), SnapshotError> {
        restore_via_raw_bytes(snap, Self::PRODUCER_TAG, Self::VERSION, |buf| {
            self.restore_state(buf)
        })
    }
}
