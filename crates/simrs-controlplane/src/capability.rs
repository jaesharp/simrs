//! Capability model for the control-plane applet.
//!
//! Each `NestedCardHandle` carries a [`CapabilitySet`] describing the
//! operations that may be invoked through *that handle*. Capabilities
//! are strictly monotonically dropped: once removed from a handle they
//! cannot be re-granted through that handle, and no operation on one
//! handle can restore capabilities on another. This is the primitive
//! the host application uses to build information-flow security
//! policies: hand out a privileged handle and a reduced handle for the
//! same underlying card, drop the risky capabilities on the reduced
//! handle, route untrusted traffic through it.
//!
//! # Scope: handle-boundary operations only
//!
//! Capabilities gate operations that *cross a handle* -- i.e. the
//! `FORWARD` sub-op on [`NestedCard`](crate::probes::nested_card),
//! which lets caller A manipulate card B via a handle A holds. They
//! do **not** gate self-inspection probes (`Misc`, `Prng`,
//! `SnapshotMarker`, `JcvmState`, `FaultInjection`), because those
//! operate on the applet's own state with no handle involved: the
//! caller of the probe is the same party whose state is being read
//! or modified. When a probe *does* become handle-mediated in the
//! future (multi-handle shared applet state, or explicit session
//! handles on the outer applet), its dispatcher arm gains the
//! `contains(Capability::for_category(cat))` check and joins the
//! enforcement surface.
//!
//! The model is intentionally coarse -- one capability per probe
//! category -- because that is the smallest unit the APDU surface can
//! address. Finer-grained rights would require carving up individual
//! categories, which is possible but not required today.

use crate::protocol::Category;

/// A right that a handle may or may not hold.
///
/// Each variant corresponds 1:1 to a [`Category`]; it is the
/// "permission to issue a command in that category" through a
/// specific handle. Dropping a capability on a handle prevents every
/// sub-operation in that category from reaching the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Capability {
    /// Read JCVM introspection counters.
    InspectJcvmState = 0x01,
    /// Read JCRE heap accounting.
    InspectJcreHeap = 0x02,
    /// Inject faults into the applet dispatcher.
    InjectFault = 0x03,
    /// Seed or read the control-plane PRNG.
    UsePrng = 0x04,
    /// Read or increment the snapshot marker.
    UseSnapshotMarker = 0x05,
    /// Exercise the applet firewall probe.
    ProbeFirewall = 0x06,
    /// Toggle interposer recording.
    ControlInterposer = 0x07,
    /// Misc / ping / version (liveness).
    Liveness = 0x08,
    /// Spawn, forward to, and destroy nested cards.
    NestCards = 0x09,
}

impl Capability {
    /// Convert a [`Category`] into the capability that gates it.
    #[must_use]
    pub const fn for_category(cat: Category) -> Self {
        match cat {
            Category::JcvmState => Self::InspectJcvmState,
            Category::JcreHeap => Self::InspectJcreHeap,
            Category::FaultInjection => Self::InjectFault,
            Category::Prng => Self::UsePrng,
            Category::SnapshotMarker => Self::UseSnapshotMarker,
            Category::FirewallProbe => Self::ProbeFirewall,
            Category::InterposerControl => Self::ControlInterposer,
            Category::Misc => Self::Liveness,
            Category::NestedCard => Self::NestCards,
        }
    }

    /// Wire-format byte carried in the DROP sub-op data field.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parse a wire-format byte. Returns `None` on unknown values.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::InspectJcvmState),
            0x02 => Some(Self::InspectJcreHeap),
            0x03 => Some(Self::InjectFault),
            0x04 => Some(Self::UsePrng),
            0x05 => Some(Self::UseSnapshotMarker),
            0x06 => Some(Self::ProbeFirewall),
            0x07 => Some(Self::ControlInterposer),
            0x08 => Some(Self::Liveness),
            0x09 => Some(Self::NestCards),
            _ => None,
        }
    }

    /// Internal bitmask representation (one bit per variant, never
    /// exposed as a raw integer in the public API).
    const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

/// An unordered set of [`Capability`] values. Newtype around a u32
/// bitmask; the raw integer is intentionally not exposed so callers
/// cannot confuse it with an arbitrary number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet(u32);

impl CapabilitySet {
    /// The fully-privileged set: every capability enabled.
    ///
    /// Used at handle creation time; callers drop to the minimum
    /// they need before handing the handle to less-trusted code.
    #[must_use]
    pub const fn full() -> Self {
        let mut acc = 0u32;
        acc |= Capability::InspectJcvmState.bit();
        acc |= Capability::InspectJcreHeap.bit();
        acc |= Capability::InjectFault.bit();
        acc |= Capability::UsePrng.bit();
        acc |= Capability::UseSnapshotMarker.bit();
        acc |= Capability::ProbeFirewall.bit();
        acc |= Capability::ControlInterposer.bit();
        acc |= Capability::Liveness.bit();
        acc |= Capability::NestCards.bit();
        Self(acc)
    }

    /// The empty set: no capabilities held.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// `true` iff `cap` is currently in the set.
    #[must_use]
    pub const fn contains(self, cap: Capability) -> bool {
        (self.0 & cap.bit()) != 0
    }

    /// Remove `cap` from the set. Idempotent. Returns the new set so
    /// the call site reads as a transformation rather than a mutation.
    #[must_use]
    pub const fn drop(self, cap: Capability) -> Self {
        Self(self.0 & !cap.bit())
    }

    /// Drop every capability in `other` from `self`.
    #[must_use]
    pub const fn drop_all(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Singleton set containing exactly one capability.
    #[must_use]
    pub const fn single(cap: Capability) -> Self {
        Self(cap.bit())
    }

    /// Union of `self` and `other`. Used by tests that assemble a
    /// specific capability set directly (production code reaches
    /// these sets only by dropping from [`full`](Self::full)).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_roundtrips_through_capability() {
        for p1 in 0x01..=0x09u8 {
            let cat = Category::from_p1(p1).expect("known category");
            let cap = Capability::for_category(cat);
            let byte = cap.as_byte();
            assert_eq!(byte, p1);
            let back = Capability::from_byte(byte).expect("round-trip");
            assert_eq!(back, cap);
        }
    }

    #[test]
    fn full_set_contains_every_capability() {
        let full = CapabilitySet::full();
        for p1 in 0x01..=0x09u8 {
            let cap = Capability::from_byte(p1).unwrap();
            assert!(full.contains(cap), "full should contain {cap:?}");
        }
    }

    #[test]
    fn empty_set_contains_nothing() {
        let empty = CapabilitySet::empty();
        for p1 in 0x01..=0x09u8 {
            let cap = Capability::from_byte(p1).unwrap();
            assert!(!empty.contains(cap));
        }
    }

    #[test]
    fn drop_is_monotonic() {
        let s0 = CapabilitySet::full();
        let s1 = s0.drop(Capability::InjectFault);
        let s2 = s1.drop(Capability::InjectFault); // idempotent
        assert_eq!(s1, s2);
        assert!(!s1.contains(Capability::InjectFault));
        assert!(s1.contains(Capability::Liveness));
    }

    #[test]
    fn drop_on_one_handle_does_not_affect_another() {
        // Simulate "host has two handles, one privileged, one not."
        let privileged = CapabilitySet::full();
        let reduced = privileged.drop(Capability::NestCards);
        assert!(privileged.contains(Capability::NestCards));
        assert!(!reduced.contains(Capability::NestCards));
        // The privileged set is unchanged by operations on the
        // reduced copy; CapabilitySet is Copy, so `drop` cannot
        // mutate a sibling.
    }

    #[test]
    fn drop_all_composes() {
        let full = CapabilitySet::full();
        let to_drop = CapabilitySet::single(Capability::InjectFault)
            .union(CapabilitySet::single(Capability::NestCards));
        let reduced = full.drop_all(to_drop);
        assert!(!reduced.contains(Capability::InjectFault));
        assert!(!reduced.contains(Capability::NestCards));
        assert!(reduced.contains(Capability::Liveness));
    }
}
