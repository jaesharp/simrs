//! `Snapshotable` impl for `ResponseQueue` -- ADR 0001 Phase 3.

use simrs_snapshot::{
    Snapshot, SnapshotError, Snapshotable, producer::RESPONSE_QUEUE, restore_via_raw_bytes,
    snapshot_via_raw_bytes,
};

use crate::ResponseQueue;

impl<const CAP: usize> Snapshotable for ResponseQueue<CAP> {
    const PRODUCER_TAG: u16 = RESPONSE_QUEUE;
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
        let mut q: ResponseQueue<64> = ResponseQueue::new();
        q.queue(b"hello");
        let snap = q.snapshot();
        assert_eq!(snap.producer_tag(), RESPONSE_QUEUE);
        assert_eq!(snap.version(), (1, 0));

        let mut q2: ResponseQueue<64> = ResponseQueue::new();
        q2.restore(&snap).expect("restore succeeds");
        assert_eq!(q2.len(), 5);
    }

    #[test]
    fn restore_rejects_wrong_producer_tag() {
        let snap = Snapshot::from_header_and_payload((1, 0), SIM, &[]);
        let mut q: ResponseQueue<64> = ResponseQueue::new();
        assert_eq!(
            q.restore(&snap).unwrap_err(),
            SnapshotError::ProducerMismatch {
                expected: RESPONSE_QUEUE,
                found: SIM,
            }
        );
    }

    #[test]
    fn restore_rejects_wrong_major_version() {
        let snap = Snapshot::from_header_and_payload((2, 0), RESPONSE_QUEUE, &[]);
        let mut q: ResponseQueue<64> = ResponseQueue::new();
        assert_eq!(
            q.restore(&snap).unwrap_err(),
            SnapshotError::VersionMismatch {
                expected: (1, 0),
                found: (2, 0),
            }
        );
    }

    #[test]
    fn restore_rejects_truncated_payload() {
        let snap = Snapshot::from_header_and_payload((1, 0), RESPONSE_QUEUE, &[]);
        let mut q: ResponseQueue<64> = ResponseQueue::new();
        assert_eq!(q.restore(&snap).unwrap_err(), SnapshotError::Malformed);
    }
}
