//! `Snapshotable` impl for `ProactiveState` -- ADR 0001 Phase 3.

use simrs_snapshot::{
    Snapshot, SnapshotError, Snapshotable, producer::PROACTIVE, restore_via_raw_bytes,
    snapshot_via_raw_bytes,
};

use crate::ProactiveState;

impl Snapshotable for ProactiveState {
    const PRODUCER_TAG: u16 = PROACTIVE;
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

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_snapshot::producer::SIM;

    #[test]
    fn snapshot_round_trips() {
        let state = ProactiveState::new();
        let snap = state.snapshot();
        assert_eq!(snap.producer_tag(), PROACTIVE);
        assert_eq!(snap.version(), (1, 0));
        let mut s2 = ProactiveState::new();
        s2.restore(&snap).expect("restore succeeds");
    }

    #[test]
    fn restore_rejects_wrong_producer_tag() {
        let snap = Snapshot::from_header_and_payload((1, 0), SIM, &[]);
        let mut state = ProactiveState::new();
        assert_eq!(
            state.restore(&snap).unwrap_err(),
            SnapshotError::ProducerMismatch {
                expected: PROACTIVE,
                found: SIM,
            }
        );
    }

    #[test]
    fn restore_rejects_wrong_major_version() {
        let snap = Snapshot::from_header_and_payload((2, 0), PROACTIVE, &[]);
        let mut state = ProactiveState::new();
        assert_eq!(
            state.restore(&snap).unwrap_err(),
            SnapshotError::VersionMismatch {
                expected: (1, 0),
                found: (2, 0),
            }
        );
    }

    #[test]
    fn restore_rejects_truncated_payload() {
        let snap = Snapshot::from_header_and_payload((1, 0), PROACTIVE, &[]);
        let mut state = ProactiveState::new();
        assert_eq!(state.restore(&snap).unwrap_err(), SnapshotError::Malformed,);
    }
}
