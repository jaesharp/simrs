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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PinKey, PinValue};
    use simrs_snapshot::producer::SIM;

    fn make_manager() -> PinManager<5> {
        let mut m = PinManager::<5>::new();
        let pin = PinValue::new(*b"12345678");
        let puk = PinValue::new(*b"87654321");
        m.add_pin(PinKey::PIN1, &pin, 3, &puk, 10, true).unwrap();
        m
    }

    #[test]
    fn snapshot_round_trips() {
        let mut m = make_manager();
        let _ = m.verify(PinKey::PIN1, &PinValue::new(*b"12345678"));
        let snap = m.snapshot();
        assert_eq!(snap.producer_tag(), PIN_MANAGER);
        assert_eq!(snap.version(), (1, 0));

        let mut m2 = PinManager::<5>::new();
        m2.restore(&snap).expect("restore succeeds");

        // Verified state survived the round-trip.
        assert!(m2.is_verified(PinKey::PIN1));
    }

    #[test]
    fn restore_rejects_wrong_producer_tag() {
        let snap = Snapshot::from_header_and_payload((1, 0), SIM, &[]);
        let mut m = PinManager::<5>::new();
        assert_eq!(
            m.restore(&snap).unwrap_err(),
            SnapshotError::ProducerMismatch {
                expected: PIN_MANAGER,
                found: SIM,
            },
        );
    }

    #[test]
    fn restore_rejects_wrong_major_version() {
        let snap = Snapshot::from_header_and_payload((2, 0), PIN_MANAGER, &[]);
        let mut m = PinManager::<5>::new();
        assert_eq!(
            m.restore(&snap).unwrap_err(),
            SnapshotError::VersionMismatch {
                expected: (1, 0),
                found: (2, 0),
            },
        );
    }

    #[test]
    fn restore_rejects_truncated_payload() {
        let snap = Snapshot::from_header_and_payload((1, 0), PIN_MANAGER, &[]);
        let mut m = PinManager::<5>::new();
        assert_eq!(m.restore(&snap).unwrap_err(), SnapshotError::Malformed);
    }
}
