//! `Snapshotable` impl for `JcVM` -- ADR 0001 Phase 2.
//!
//! Wraps the crate-private byte serialization
//! (`save_state_internal` / `restore_state_internal`) in the opaque
//! `simrs_snapshot::Snapshot` type. Gated behind the `snapshot`
//! feature flag so production builds get no snapshot surface.

extern crate alloc;

use alloc::vec;

use simrs_snapshot::{Snapshot, SnapshotError, Snapshotable, producer::JCVM, validate_header};

use crate::JcVM;

impl<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> Snapshotable
    for JcVM<HEAP_SIZE, MAX_PACKAGES>
{
    const PRODUCER_TAG: u16 = JCVM;
    const VERSION: (u8, u8) = (1, 0);

    fn snapshot(&self) -> Snapshot {
        // Allocate exactly enough -- the trait `Snapshot` impl on
        // `JcVMApplet` already computes the upper bound; we replicate
        // it here rather than depending on simrs-jcre. Bumping `MAX`
        // is harmless (Snapshot will trim to the actual length).
        let max_size = upper_bound_snapshot_size::<HEAP_SIZE, MAX_PACKAGES>();
        let mut buf = vec![0u8; max_size];
        let n = self.save_state_internal(&mut buf);
        // n=0 means the buffer was too small. With max_size sized as
        // an upper bound, this should never fire in practice; if it
        // does, the empty payload below makes the snapshot
        // structurally valid but `restore` will reject it as
        // `Malformed`, which is the correct behaviour.
        let payload = if n == 0 { &[][..] } else { &buf[..n] };
        Snapshot::from_header_and_payload(Self::VERSION, Self::PRODUCER_TAG, payload)
    }

    fn restore(&mut self, snap: &Snapshot) -> Result<(), SnapshotError> {
        validate_header(snap, Self::PRODUCER_TAG, Self::VERSION)?;
        if !self.restore_state_internal(snap.payload()) {
            return Err(SnapshotError::Malformed);
        }
        Ok(())
    }
}

/// Upper bound on the byte length of a `JcVM` snapshot payload.
///
/// Mirrors the calculation in `JcVMApplet::snapshot_size` but lives
/// here so the `Snapshotable` impl doesn't need a dependency on
/// `simrs-jcre`'s `Applet` trait. The two formulas must stay in
/// lockstep -- a regression test below asserts equality.
const fn upper_bound_snapshot_size<const HEAP_SIZE: usize, const MAX_PACKAGES: usize>() -> usize {
    use crate::cap::Package;
    use crate::frame::{MAX_FRAMES, MAX_LOCALS, MAX_STACK};
    use crate::heap::ObjectHeap;
    use crate::transaction::TransactionJournal;

    // JOURNAL_CAP is private to crate::lib; replicate the constant
    // here to avoid making it pub. The compile-time test below
    // guards against drift.
    const JOURNAL_CAP: usize = 256;

    ObjectHeap::<HEAP_SIZE>::MAX_SNAPSHOT_SIZE
        + 1
        + MAX_PACKAGES * (1 + Package::MAX_SNAPSHOT_SIZE)
        + 1024
        + 1
        + TransactionJournal::<JOURNAL_CAP>::MAX_SNAPSHOT_SIZE
        + 5
        + 2
        + MAX_FRAMES * 6
        + MAX_STACK * 2
        + MAX_LOCALS * 2
}

#[cfg(test)]
#[allow(clippy::large_stack_arrays)]
mod tests {
    use super::*;
    use crate::cap::{build_cap_blob, parse_cap};
    use crate::opcodes::*;

    fn make_vm() -> JcVM<4096, 4> {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x01];
        let bc: &[u8] = &[SCONST_3, SRETURN];
        let mut blob = [0u8; 512];
        let len = build_cap_blob(&aid, &[bc], &mut blob);
        let pkg = parse_cap(&blob[..len]).unwrap();
        let mut vm = JcVM::<4096, 4>::new();
        vm.load_package(pkg).unwrap();
        vm
    }

    #[test]
    fn snapshot_round_trips_through_opaque_api() {
        let mut vm = make_vm();
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));

        let snap = vm.snapshot();
        assert_eq!(snap.producer_tag(), JCVM);
        assert_eq!(snap.version(), (1, 0));

        let mut vm2 = JcVM::<4096, 4>::new();
        vm2.restore(&snap).expect("restore succeeds");

        // Restored VM executes the same bytecode and gets the same result.
        assert_eq!(vm2.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn snapshot_persists_via_as_bytes_and_from_bytes() {
        let mut vm = make_vm();
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));

        let snap1 = vm.snapshot();
        let bytes = snap1.as_bytes().to_vec();
        let snap2 = Snapshot::from_bytes(&bytes).expect("from_bytes succeeds");
        assert_eq!(snap1, snap2);

        let mut vm2 = JcVM::<4096, 4>::new();
        vm2.restore(&snap2).expect("restore succeeds");
        assert_eq!(vm2.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn restore_rejects_wrong_producer_tag() {
        let payload: &[u8] = &[];
        let snap =
            Snapshot::from_header_and_payload((1, 0), simrs_snapshot::producer::SIM, payload);
        let mut vm = JcVM::<4096, 4>::new();
        let err = vm.restore(&snap).unwrap_err();
        assert_eq!(
            err,
            SnapshotError::ProducerMismatch {
                expected: JCVM,
                found: simrs_snapshot::producer::SIM,
            },
        );
    }

    #[test]
    fn restore_rejects_wrong_major_version() {
        let payload: &[u8] = &[];
        let snap = Snapshot::from_header_and_payload((2, 0), JCVM, payload);
        let mut vm = JcVM::<4096, 4>::new();
        let err = vm.restore(&snap).unwrap_err();
        assert_eq!(
            err,
            SnapshotError::VersionMismatch {
                expected: (1, 0),
                found: (2, 0),
            },
        );
    }

    #[test]
    fn restore_rejects_malformed_payload() {
        // Header is valid (correct tag and version), but the payload
        // is too short for the heap snapshot inside.
        let snap = Snapshot::from_header_and_payload((1, 0), JCVM, &[0xFF]);
        let mut vm = JcVM::<4096, 4>::new();
        let err = vm.restore(&snap).unwrap_err();
        assert_eq!(err, SnapshotError::Malformed);
    }

    #[test]
    fn upper_bound_matches_applet_snapshot_size() {
        // The bound formula in this module must stay in lockstep
        // with `JcVMApplet::snapshot_size`. If JOURNAL_CAP or any of
        // the per-component sizes change, both must update.
        use simrs_jcre::Applet;
        let vm = make_vm();
        let applet = crate::JcVMApplet::<4096, 4>::new(vm, 0);
        assert_eq!(
            upper_bound_snapshot_size::<4096, 4>(),
            applet.snapshot_size(),
        );
    }
}
