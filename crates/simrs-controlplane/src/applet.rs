//! Control-plane applet state and top-level APDU dispatcher.
//!
//! [`ControlplaneApplet`] owns the per-session state that every probe
//! can share (snapshot counter, PRNG seed, interposer recording
//! toggle, etc.) and routes incoming APDUs to the appropriate
//! handler based on `P1`/`P2`.

pub use crate::probes::jcvm_state::JcvmSnapshot;
pub use crate::probes::nested_card::NestedCardHandle;
use crate::probes::{fault, jcvm_state, nested_card, ping, prng, snapshot_marker};
use crate::protocol::{
    CLA, Category, HEADER_LEN, INS, SW_CLA_NOT_SUPPORTED, SW_INCORRECT_P1P2, SW_INS_NOT_SUPPORTED,
    SW_WRONG_LENGTH,
};

/// Shared state across probes. Every field except the PRNG seed is
/// initialised to a deterministic default so test runs are
/// reproducible.
///
/// The applet itself is stateless-per-command today (Misc/ping); the
/// struct exists so later probes (`SnapshotMarker`, PRNG, etc.) can
/// accumulate per-applet state without reshaping the dispatcher.
#[derive(Debug, Clone, Default)]
pub struct AppletState {
    /// Persistent snapshot-marker counter. Incremented via the
    /// `SnapshotMarker` probe; surfaced to differential tests to verify
    /// snapshot-restore fidelity.
    pub snapshot_counter: u32,
    /// Xorshift64 state used by the PRNG probe. `0` produces an
    /// all-zero stream (documented fixture); non-zero seeds produce
    /// a 2^64-1 period stream.
    pub prng_state: u64,
    /// If `Some`, the dispatcher short-circuits the next incoming
    /// APDU and returns this SW without running the probe handler.
    /// Armed by the `FaultInjection` probe; cleared automatically on
    /// the next command (single-shot semantics).
    pub armed_fault: Option<[u8; 2]>,
    /// Snapshot of JCVM introspection counters (opcode histogram,
    /// total instructions, max method-call depth). Refreshed by the
    /// harness from the live VM before the `JcvmState` probe runs;
    /// stays at zero when the inner guest is a reference backend
    /// without an introspectable VM.
    pub jcvm_snapshot: JcvmSnapshot,
}

/// Control-plane applet.
///
/// Holds the dispatcher and the shared [`AppletState`]. Callers are
/// normally the [`crate::card::ControlplaneCard`] wrapper; direct use
/// is also supported for unit tests.
#[derive(Debug, Default)]
pub struct ControlplaneApplet {
    state: AppletState,
    /// Optional nested card, managed via the `NestedCard` probe. The
    /// outer applet can spawn an inner card, forward APDUs to it,
    /// and verify state isolation. Lives outside [`AppletState`]
    /// because its `Box<dyn Transport>` is neither `Clone` nor
    /// directly `Debug`; the [`NestedCardHandle`] wrapper provides a
    /// skipped-field `Debug` impl.
    nested: Option<NestedCardHandle>,
}

impl ControlplaneApplet {
    /// Create a fresh applet instance with default state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the shared state read-only (tests use this).
    #[must_use]
    pub const fn state(&self) -> &AppletState {
        &self.state
    }

    /// Mutable state access for tests that need to preload a counter
    /// value or prime the PRNG seed before sending APDUs.
    pub const fn state_mut(&mut self) -> &mut AppletState {
        &mut self.state
    }

    /// Install (or remove) the nested card managed by this applet.
    /// Passing `None` is equivalent to a `NestedCard`-DESTROY.
    pub fn set_nested(&mut self, card: Option<NestedCardHandle>) {
        self.nested = card;
    }

    /// Borrow the nested card mutably, if any.
    pub const fn nested_mut(&mut self) -> Option<&mut NestedCardHandle> {
        self.nested.as_mut()
    }

    /// `true` iff a nested card is currently installed.
    #[must_use]
    pub const fn has_nested(&self) -> bool {
        self.nested.is_some()
    }

    /// Top-level APDU dispatch.
    ///
    /// Writes the response payload (data bytes only -- SW is returned
    /// separately by the caller to append) into `rsp`. Returns the
    /// two-byte status word.
    pub fn process(&mut self, apdu: &[u8], rsp: &mut Vec<u8>) -> [u8; 2] {
        if apdu.len() < HEADER_LEN {
            return SW_WRONG_LENGTH;
        }

        let cla = apdu[0];
        let ins = apdu[1];
        let p1 = apdu[2];
        let p2 = apdu[3];

        // Incoming data: `[CLA INS P1 P2 (Lc=N) data(N) (Le)]`. Short
        // APDU only. If there's no Lc byte, the data field is empty.
        let data: &[u8] = if apdu.len() > HEADER_LEN {
            let lc = apdu[HEADER_LEN] as usize;
            let data_start = HEADER_LEN + 1;
            if apdu.len() >= data_start + lc {
                &apdu[data_start..data_start + lc]
            } else {
                return SW_WRONG_LENGTH;
            }
        } else {
            &[]
        };

        if cla != CLA {
            return SW_CLA_NOT_SUPPORTED;
        }
        if ins != INS {
            return SW_INS_NOT_SUPPORTED;
        }
        let Some(category) = Category::from_p1(p1) else {
            return SW_INCORRECT_P1P2;
        };

        // Fault-injection shortcut. Any armed fault fires on the
        // next *guest* command and clears itself (single-shot). The
        // FaultInjection category itself is the control channel --
        // it bypasses the arm so dom0 can always reach DISARM and
        // re-arm with a different SW.
        if !matches!(category, Category::FaultInjection)
            && let Some(sw) = self.state.armed_fault.take()
        {
            return sw;
        }

        match category {
            Category::Misc => ping::handle(&mut self.state, p2, data, rsp),
            Category::Prng => prng::handle(&mut self.state, p2, data, rsp),
            Category::SnapshotMarker => snapshot_marker::handle(&mut self.state, p2, data, rsp),
            Category::FaultInjection => fault::handle(&mut self.state, p2, data, rsp),
            Category::JcvmState => jcvm_state::handle(&mut self.state, p2, data, rsp),
            // NestedCard takes the whole applet because it mutates
            // the non-state `nested` field; the other probes only
            // touch `AppletState`.
            Category::NestedCard => nested_card::handle(self, p2, data, rsp),
            // Remaining categories are scaffolded in the design doc
            // but unimplemented this iteration. Dispatcher returns
            // `6A 86` so tests can distinguish "category not wired"
            // from "bad sub-operation".
            Category::JcreHeap | Category::FirewallProbe | Category::InterposerControl => {
                SW_INCORRECT_P1P2
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{SW_INCORRECT_P1P2, SW_OK};

    /// Build a short APDU: `[CLA INS P1 P2 Lc data...]`. No Le.
    fn short_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![cla, ins, p1, p2];
        #[allow(clippy::cast_possible_truncation)]
        let lc = data.len() as u8;
        out.push(lc);
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn ping_echoes_data() {
        let mut applet = ControlplaneApplet::new();
        let apdu = short_apdu(CLA, INS, 0x08, 0x00, b"hello");
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_OK);
        assert_eq!(rsp, b"hello");
    }

    #[test]
    fn ping_with_empty_data_returns_empty_ok() {
        let mut applet = ControlplaneApplet::new();
        let apdu = [CLA, INS, 0x08, 0x00];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_OK);
        assert!(rsp.is_empty());
    }

    #[test]
    fn version_returns_expected_string() {
        let mut applet = ControlplaneApplet::new();
        let apdu = [CLA, INS, 0x08, 0x01];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_OK);
        assert_eq!(rsp, ping::VERSION_STRING);
    }

    #[test]
    fn unknown_misc_p2_returns_6a86() {
        let mut applet = ControlplaneApplet::new();
        let apdu = [CLA, INS, 0x08, 0xFF];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn unknown_category_returns_6a86() {
        let mut applet = ControlplaneApplet::new();
        let apdu = [CLA, INS, 0x42, 0x00];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn unimplemented_category_returns_6a86() {
        // JcreHeap (0x02) is defined but not yet implemented; it
        // must return 6A86 so the test harness can distinguish "not
        // yet wired" from "CLA/INS wrong".
        let mut applet = ControlplaneApplet::new();
        let apdu = [CLA, INS, 0x02, 0x00];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn jcvm_state_depth_roundtrips_through_dispatch() {
        let mut applet = ControlplaneApplet::new();
        applet.state_mut().jcvm_snapshot.total_instructions = 7;
        applet.state_mut().jcvm_snapshot.max_frame_depth = 2;
        // P1=0x01 P2=0x01 (GET_DEPTH).
        let apdu = [CLA, INS, 0x01, 0x01];
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&apdu, &mut rsp), SW_OK);
        // u64 BE (7) + u32 BE (2).
        assert_eq!(rsp, vec![0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 2]);
    }

    #[test]
    fn jcvm_state_reset_zeroes_snapshot() {
        let mut applet = ControlplaneApplet::new();
        applet.state_mut().jcvm_snapshot.total_instructions = 7;
        applet.state_mut().jcvm_snapshot.max_frame_depth = 2;
        let apdu = [CLA, INS, 0x01, 0x02]; // RESET
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&apdu, &mut rsp), SW_OK);
        assert_eq!(applet.state().jcvm_snapshot.total_instructions, 0);
        assert_eq!(applet.state().jcvm_snapshot.max_frame_depth, 0);
    }

    #[test]
    fn snapshot_marker_get_then_increment_roundtrips_through_dispatch() {
        let mut applet = ControlplaneApplet::new();
        // GET (P1=0x05, P2=0x00): initial counter is 0.
        let get = [CLA, INS, 0x05, 0x00];
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&get, &mut rsp), SW_OK);
        assert_eq!(rsp, vec![0, 0, 0, 0]);

        // INCREMENT (P1=0x05, P2=0x01): counter becomes 1.
        rsp.clear();
        let inc = [CLA, INS, 0x05, 0x01];
        assert_eq!(applet.process(&inc, &mut rsp), SW_OK);
        assert_eq!(rsp, vec![0, 0, 0, 1]);
        assert_eq!(applet.state().snapshot_counter, 1);
    }

    #[test]
    fn prng_seed_then_read_roundtrips_through_dispatch() {
        let mut applet = ControlplaneApplet::new();
        // Seed (P1=0x04, P2=0x00) with an 8-byte big-endian value.
        let seed = short_apdu(
            CLA,
            INS,
            0x04,
            0x00,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42],
        );
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&seed, &mut rsp), SW_OK);
        assert_eq!(applet.state().prng_state, 0x42);

        // Read (P2=0x01) 8 bytes. Must not be all-zero for this seed.
        rsp.clear();
        let read = short_apdu(CLA, INS, 0x04, 0x01, &[8]);
        assert_eq!(applet.process(&read, &mut rsp), SW_OK);
        assert_eq!(rsp.len(), 8);
        assert!(rsp.iter().any(|b| *b != 0));
    }

    #[test]
    fn fault_arm_default_fires_on_next_command_and_clears() {
        let mut applet = ControlplaneApplet::new();
        // Arm (P1=0x03, P2=0x00) -- itself succeeds with 9000.
        let arm = [CLA, INS, 0x03, 0x00];
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&arm, &mut rsp), SW_OK);
        assert_eq!(applet.state().armed_fault, Some([0x6F, 0x00]));

        // Next command: any P1/P2. It must return 6F00 regardless,
        // and the arm must be cleared (single-shot semantics).
        rsp.clear();
        let ping = [CLA, INS, 0x08, 0x00];
        assert_eq!(applet.process(&ping, &mut rsp), [0x6F, 0x00]);
        assert!(rsp.is_empty());
        assert_eq!(applet.state().armed_fault, None);

        // Third command lands normally.
        rsp.clear();
        assert_eq!(applet.process(&ping, &mut rsp), SW_OK);
    }

    #[test]
    fn fault_arm_custom_delivers_caller_supplied_sw() {
        let mut applet = ControlplaneApplet::new();
        let arm = short_apdu(CLA, INS, 0x03, 0x01, &[0x69, 0x85]);
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&arm, &mut rsp), SW_OK);

        rsp.clear();
        let trigger = [CLA, INS, 0x08, 0x00];
        assert_eq!(applet.process(&trigger, &mut rsp), [0x69, 0x85]);
    }

    #[test]
    fn fault_disarm_reverts_arming() {
        let mut applet = ControlplaneApplet::new();
        let arm = [CLA, INS, 0x03, 0x00];
        let disarm = [CLA, INS, 0x03, 0x02];
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&arm, &mut rsp), SW_OK);
        assert!(applet.state().armed_fault.is_some());
        rsp.clear();
        assert_eq!(applet.process(&disarm, &mut rsp), SW_OK);
        assert!(applet.state().armed_fault.is_none());

        // Subsequent command runs normally.
        rsp.clear();
        let ping = [CLA, INS, 0x08, 0x00];
        assert_eq!(applet.process(&ping, &mut rsp), SW_OK);
    }

    #[test]
    fn fault_arm_custom_rejects_wrong_data_length() {
        let mut applet = ControlplaneApplet::new();
        let arm_bad = short_apdu(CLA, INS, 0x03, 0x01, &[0x69]);
        let mut rsp = Vec::new();
        assert_ne!(applet.process(&arm_bad, &mut rsp), SW_OK);
        assert!(applet.state().armed_fault.is_none());
    }

    #[test]
    fn wrong_cla_returns_6e00() {
        let mut applet = ControlplaneApplet::new();
        let apdu = [0x00, INS, 0x08, 0x00];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_CLA_NOT_SUPPORTED);
    }

    #[test]
    fn wrong_ins_returns_6d00() {
        let mut applet = ControlplaneApplet::new();
        let apdu = [CLA, 0xA4, 0x08, 0x00];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_INS_NOT_SUPPORTED);
    }

    #[test]
    fn truncated_header_returns_6700() {
        let mut applet = ControlplaneApplet::new();
        let apdu = [CLA, INS, 0x08]; // missing P2
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_WRONG_LENGTH);
    }

    #[test]
    fn truncated_data_returns_6700() {
        let mut applet = ControlplaneApplet::new();
        // Lc says 5 but only 2 bytes of data follow.
        let apdu = [CLA, INS, 0x08, 0x00, 0x05, 0x41, 0x42];
        let mut rsp = Vec::new();
        let sw = applet.process(&apdu, &mut rsp);
        assert_eq!(sw, SW_WRONG_LENGTH);
    }
}
