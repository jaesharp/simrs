//! Dom0-facing "hypervisor" trait over a `JavaCard` VM.
//!
//! The JCVM always tracks a small set of observation counters as
//! part of its default execution state (the "null hypervisor"). This
//! module exposes those counters through a [`Hypervisor`] trait so
//! the simrs-controlplane dom0 applet can read them without taking a
//! direct dependency on the concrete [`crate::JcVM`] type.
//!
//! Gated by the `controlplane-hooks` feature on `simrs-jcvm`. When
//! the feature is off the trait is absent and downstream crates
//! cannot reach the counters; the compiler can then DCE the
//! increments themselves.
//!
//! # Constant-time discipline
//!
//! - The JCVM's null-hypervisor counter updates are
//!   unconditionally executed and pinned against DCE, so a build
//!   without the `controlplane-hooks` feature performs the same
//!   stores as a build with it. Timing between the two configs is
//!   therefore structurally indistinguishable -- no
//!   `pause_counters`/`resume_counters` API is required because
//!   there is no "paused" execution mode to distinguish from
//!   "running".
//! - Guest VMs run on windowed stacks; the hypervisor owns a
//!   separate "hyperstack" that hosts hypercalls (dom0 → hypervisor
//!   queries) and hypertraps (hypervisor → guest injection, e.g.
//!   fault delivery). Events produced by guest execution reach
//!   dom0 via a static ring buffer that the guest writes into and
//!   dom0 drains from its own stack -- no guest context switch
//!   needed, no paravirt-mode toggle.
//! - Downstream trait implementors that handle secret or redacted
//!   values must not materialise those bytes through a public
//!   accessor without passing them through `simrs-redact` (follow-
//!   up): exposing bytes to a dom0 applet would bypass the
//!   redaction boundary.

use crate::JcVM;

/// Read-only introspection into a `JavaCard` virtual machine.
///
/// A null-hypervisor implementation is anything that can answer
/// "how much has the guest executed so far?" without perturbing it.
/// Implementors must be cheap to call repeatedly: the dom0 applet
/// will typically invoke the accessors per APDU.
pub trait Hypervisor {
    /// Per-opcode execution count, indexed by raw opcode byte.
    fn opcode_counts(&self) -> [u64; 256];

    /// Total instructions executed since the last reset.
    fn total_instructions(&self) -> u64;

    /// High-water mark of method-call depth observed.
    fn max_frame_depth(&self) -> u32;

    /// Zero every counter. Dom0 uses this to bracket a measurement
    /// window around a specific guest operation.
    fn reset_counters(&mut self);
}

impl<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> Hypervisor
    for JcVM<HEAP_SIZE, MAX_PACKAGES>
{
    fn opcode_counts(&self) -> [u64; 256] {
        Self::opcode_counts(self)
    }

    fn total_instructions(&self) -> u64 {
        Self::total_instructions(self)
    }

    fn max_frame_depth(&self) -> u32 {
        Self::max_frame_depth(self)
    }

    fn reset_counters(&mut self) {
        Self::reset_controlplane_counters(self);
    }
}

/// Stand-in [`Hypervisor`] that always returns zeros.
///
/// Dom0 tests driving a non-simrs backend (jcsl, `JCardEngine`) wire
/// this in so the probe dispatcher can still run; the `JcvmState`
/// probe's responses just report "no instructions executed".
#[derive(Debug, Clone, Copy, Default)]
pub struct NullHypervisor;

impl Hypervisor for NullHypervisor {
    fn opcode_counts(&self) -> [u64; 256] {
        [0; 256]
    }
    fn total_instructions(&self) -> u64 {
        0
    }
    fn max_frame_depth(&self) -> u32 {
        0
    }
    fn reset_counters(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JcVM;

    #[test]
    fn null_hypervisor_always_zero() {
        let mut h = NullHypervisor;
        assert_eq!(h.total_instructions(), 0);
        assert_eq!(h.max_frame_depth(), 0);
        assert_eq!(h.opcode_counts(), [0u64; 256]);
        h.reset_counters(); // no-op
        assert_eq!(h.total_instructions(), 0);
    }

    #[test]
    fn jcvm_exposes_initial_zero_state() {
        let vm: JcVM<1024, 4> = JcVM::new();
        let h: &dyn Hypervisor = &vm;
        assert_eq!(h.total_instructions(), 0);
        assert_eq!(h.max_frame_depth(), 0);
        assert_eq!(h.opcode_counts(), [0u64; 256]);
    }

    #[test]
    fn reset_counters_is_idempotent_on_fresh_vm() {
        let mut vm: JcVM<1024, 4> = JcVM::new();
        {
            let h: &mut dyn Hypervisor = &mut vm;
            h.reset_counters();
        }
        assert_eq!(vm.total_instructions(), 0);
    }
}
