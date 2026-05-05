//! `Snapshotable` impl for `JcVM` -- ADR 0001 Phase 2.
//!
//! Wraps the crate-private byte serialization
//! (`save_state_internal` / `restore_state_internal`) in the opaque
//! `simrs_snapshot::Snapshot` type. Gated behind the `snapshot`
//! feature flag so production builds get no snapshot surface.

use simrs_snapshot::{
    Snapshot, SnapshotError, Snapshotable, producer::JCVM, restore_via_raw_bytes,
    snapshot_via_raw_bytes,
};

use crate::JcVM;

impl<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> Snapshotable
    for JcVM<HEAP_SIZE, MAX_PACKAGES>
{
    const PRODUCER_TAG: u16 = JCVM;
    const VERSION: (u8, u8) = (1, 0);

    fn snapshot(&self) -> Snapshot {
        snapshot_via_raw_bytes(
            Self::VERSION,
            Self::PRODUCER_TAG,
            Self::snapshot_max_size(),
            |buf| self.save_state_internal(buf),
        )
    }

    fn restore(&mut self, snap: &Snapshot) -> Result<(), SnapshotError> {
        restore_via_raw_bytes(snap, Self::PRODUCER_TAG, Self::VERSION, |buf| {
            self.restore_state_internal(buf)
        })
    }
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
    fn snapshot_max_size_matches_applet_snapshot_size() {
        // Sanity check: `JcVM::snapshot_max_size()` and
        // `JcVMApplet::snapshot_size` (Applet trait method) both
        // ultimately read the same const fn. If something refactors
        // one without the other, this fires.
        use simrs_jcre::Applet;
        let vm = make_vm();
        let applet = crate::JcVMApplet::<4096, 4>::new(vm, 0);
        assert_eq!(JcVM::<4096, 4>::snapshot_max_size(), applet.snapshot_size(),);
    }
}
