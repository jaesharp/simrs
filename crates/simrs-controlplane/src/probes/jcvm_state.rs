//! `P1 = 0x01` `JcvmState` probe: expose dom0's view of the JCVM
//! interpreter counters.
//!
//! - `P2 = 0x00` `GET_OPCODE_COUNTS`: BER-TLV block listing every
//!   non-zero opcode count. Outer tag `E1`, inner entries
//!   `C1 05 <opcode:u8> <count:u32-be>`. Zero-count opcodes are
//!   omitted to keep the short-APDU response well under 256 bytes
//!   when the program hit only a handful of instructions.
//! - `P2 = 0x01` `GET_DEPTH`: 8-byte payload
//!   `<total_instructions:u64-be>` then 4 bytes `<max_depth:u32-be>`.
//!   No TLV framing -- fixed layout.
//! - `P2 = 0x02` `RESET`: zero all JCVM counters and return SW OK.
//!   Dom0 uses this to bracket a measurement window.
//!
//! The handler reads and mutates a [`JcvmSnapshot`] stored on
//! [`AppletState`]. Harness code that owns both the JCVM instance
//! and the applet is responsible for refreshing the snapshot from
//! the live VM (or calling the VM's reset alongside this probe's
//! RESET sub-op) -- the probe itself is storage-agnostic so the
//! same dispatcher serves both simrs-backed tests and
//! reference-backend tests where no live JCVM exists (the snapshot
//! just stays at zero).

use crate::applet::AppletState;
use crate::protocol::{SW_INCORRECT_P1P2, SW_OK};

/// Snapshot of JCVM introspection counters.
///
/// Mirrors the fields exposed by `simrs_jcvm::Hypervisor`
/// (`opcode_counts` / `total_instructions` / `max_frame_depth`)
/// when the JCVM crate is built with the `controlplane-hooks`
/// feature. Kept storage-independent so this probe does not need
/// a direct dependency on `simrs-jcvm`.
///
/// # Pending wiring
///
/// The trait-level connection between `simrs_jcvm::Hypervisor` and
/// this snapshot is not yet in place: callers currently populate
/// `AppletState::jcvm_snapshot` by hand. A follow-up should add an
/// adapter (optional dep on `simrs-jcvm` under a feature flag, or a
/// harness-level glue function) so the snapshot is refreshed from
/// the live VM atomically before each `JcvmState` probe dispatch.
#[derive(Debug, Clone)]
pub struct JcvmSnapshot {
    /// Per-opcode execution counts. Indexed by the raw opcode byte.
    pub opcode_counts: [u64; 256],
    /// Total instructions executed since the counter last reset.
    pub total_instructions: u64,
    /// High-water mark of method-call depth.
    pub max_frame_depth: u32,
}

impl Default for JcvmSnapshot {
    fn default() -> Self {
        Self {
            opcode_counts: [0; 256],
            total_instructions: 0,
            max_frame_depth: 0,
        }
    }
}

impl JcvmSnapshot {
    /// Zero every counter. Same semantics as
    /// `simrs_jcvm::JcVM::reset_controlplane_counters`.
    pub const fn reset(&mut self) {
        self.opcode_counts = [0; 256];
        self.total_instructions = 0;
        self.max_frame_depth = 0;
    }
}

/// Sub-operation: return per-opcode execution counts (BER-TLV).
pub const P2_OPCODE_COUNTS: u8 = 0x00;

/// Sub-operation: return depth + total instructions (fixed layout).
pub const P2_DEPTH: u8 = 0x01;

/// Sub-operation: reset all JCVM counters to zero.
pub const P2_RESET: u8 = 0x02;

/// Outer BER-TLV tag for the opcode-count vector.
pub const TAG_OPCODE_COUNTS: u8 = 0xE1;

/// Inner BER-TLV tag for a single `(opcode, count)` entry.
pub const TAG_OPCODE_ENTRY: u8 = 0xC1;

/// Handle a `JcvmState` APDU.
#[must_use]
pub fn handle(state: &mut AppletState, p2: u8, _data: &[u8], rsp: &mut Vec<u8>) -> [u8; 2] {
    match p2 {
        P2_OPCODE_COUNTS => {
            emit_opcode_counts_tlv(&state.jcvm_snapshot, rsp);
            SW_OK
        }
        P2_DEPTH => {
            rsp.extend_from_slice(&state.jcvm_snapshot.total_instructions.to_be_bytes());
            rsp.extend_from_slice(&state.jcvm_snapshot.max_frame_depth.to_be_bytes());
            SW_OK
        }
        P2_RESET => {
            state.jcvm_snapshot.reset();
            SW_OK
        }
        _ => SW_INCORRECT_P1P2,
    }
}

/// Serialise the non-zero entries of `snapshot.opcode_counts` into
/// `rsp` as `E1 <len> (C1 05 <op> <count-be>)*`.
fn emit_opcode_counts_tlv(snapshot: &JcvmSnapshot, rsp: &mut Vec<u8>) {
    // Entry size: tag(1) + len(1) + op(1) + count(4) = 7 bytes.
    const ENTRY_LEN: usize = 7;

    let nonzero: Vec<(u8, u64)> = snapshot
        .opcode_counts
        .iter()
        .enumerate()
        .filter_map(|(op, &count)| {
            if count == 0 {
                None
            } else {
                #[allow(clippy::cast_possible_truncation)]
                Some((op as u8, count))
            }
        })
        .collect();

    let body_len = nonzero.len() * ENTRY_LEN;
    rsp.push(TAG_OPCODE_COUNTS);
    // BER-TLV short-form length. We cap at 255 entries (1785 bytes,
    // far beyond a short APDU anyway -- callers querying a long run
    // should use the RESET sub-op to bracket measurements).
    #[allow(clippy::cast_possible_truncation)]
    let body_len_byte = body_len.min(u8::MAX as usize) as u8;
    rsp.push(body_len_byte);

    for (op, count) in nonzero.into_iter().take(u8::MAX as usize / ENTRY_LEN) {
        rsp.push(TAG_OPCODE_ENTRY);
        // Each inner value is 5 bytes (opcode + u32 count).
        rsp.push(5);
        rsp.push(op);
        // count is u64 internally but the entry carries u32-be. That
        // is enough range for realistic differential-test windows.
        #[allow(clippy::cast_possible_truncation)]
        let count_u32 = count.min(u64::from(u32::MAX)) as u32;
        rsp.extend_from_slice(&count_u32.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_zeroes_every_counter() {
        let mut state = AppletState {
            jcvm_snapshot: JcvmSnapshot {
                opcode_counts: [1; 256],
                total_instructions: 42,
                max_frame_depth: 9,
            },
            ..AppletState::default()
        };
        let mut rsp = Vec::new();
        assert_eq!(handle(&mut state, P2_RESET, &[], &mut rsp), SW_OK);
        assert!(rsp.is_empty());
        assert_eq!(state.jcvm_snapshot.max_frame_depth, 0);
        assert_eq!(state.jcvm_snapshot.total_instructions, 0);
        assert!(state.jcvm_snapshot.opcode_counts.iter().all(|&c| c == 0));
    }

    #[test]
    fn depth_subop_returns_fixed_12_byte_payload() {
        let mut state = AppletState {
            jcvm_snapshot: JcvmSnapshot {
                total_instructions: 0x0123_4567_89AB_CDEF,
                max_frame_depth: 0xDEAD_BEEF,
                ..JcvmSnapshot::default()
            },
            ..AppletState::default()
        };
        let mut rsp = Vec::new();
        assert_eq!(handle(&mut state, P2_DEPTH, &[], &mut rsp), SW_OK);
        // u64 BE + u32 BE.
        assert_eq!(
            rsp,
            vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
            ]
        );
    }

    #[test]
    fn opcode_counts_empty_when_all_zero() {
        let mut state = AppletState::default();
        let mut rsp = Vec::new();
        assert_eq!(handle(&mut state, P2_OPCODE_COUNTS, &[], &mut rsp), SW_OK);
        // Outer TLV header with body length 0.
        assert_eq!(rsp, vec![TAG_OPCODE_COUNTS, 0x00]);
    }

    #[test]
    fn opcode_counts_skips_zero_entries() {
        let mut snapshot = JcvmSnapshot::default();
        snapshot.opcode_counts[0x2A] = 3;
        snapshot.opcode_counts[0xFE] = 0xDEAD_BEEF;
        let mut state = AppletState {
            jcvm_snapshot: snapshot,
            ..AppletState::default()
        };
        let mut rsp = Vec::new();
        assert_eq!(handle(&mut state, P2_OPCODE_COUNTS, &[], &mut rsp), SW_OK);
        // Expected: E1 0E  (C1 05 2A 00 00 00 03)  (C1 05 FE DE AD BE EF)
        let expected = [
            TAG_OPCODE_COUNTS,
            0x0E, // 14 bytes of body (2 entries * 7 bytes)
            TAG_OPCODE_ENTRY,
            0x05,
            0x2A,
            0x00,
            0x00,
            0x00,
            0x03,
            TAG_OPCODE_ENTRY,
            0x05,
            0xFE,
            0xDE,
            0xAD,
            0xBE,
            0xEF,
        ];
        assert_eq!(rsp, expected);
    }

    #[test]
    fn unknown_p2_returns_6a86() {
        let mut state = AppletState::default();
        let mut rsp = Vec::new();
        assert_eq!(handle(&mut state, 0xFF, &[], &mut rsp), SW_INCORRECT_P1P2);
    }
}
