//! Timing domains and timing-domain connectivity.
//!
//! # Why
//!
//! Constant-time operations are only meaningful relative to an
//! *observer*. A nested VM that shares timing-sensitive secrets with
//! another VM must execute secret-dependent code constant-time
//! relative to that peer; a VM in a distinct timing domain need
//! not. Modelling this explicitly lets the hypervisor verify the
//! data-flow rule "secrets only leave their timing domain through
//! channels the domain connectivity graph sanctions."
//!
//! # Model
//!
//! - Every [`NestedCardHandle`](crate::probes::nested_card::NestedCardHandle)
//!   belongs to exactly one [`TimingDomain`].
//! - A [`DomainEdge`] names an allowed information-flow direction
//!   between two domains: `source -> sink`.
//! - A [`DomainGraph`] is the (future) acyclic set of edges the
//!   hypervisor enforces. Nested-card operations that would cause a
//!   non-sanctioned flow must be refused.
//!
//! # Status
//!
//! Scaffolding only today: the types exist, they are carried on
//! handles, but the dispatcher does not yet consult the graph. The
//! next slice will:
//!
//! 1. Attach a `TimingDomain` to every handle (default = new fresh
//!    domain per handle).
//! 2. Reject cross-domain `FORWARD`s whose edge is absent from the
//!    graph with a `SECURITY_NOT_SATISFIED` SW.
//! 3. Prove via a CT-measurement test that operations within a
//!    domain holding a secret do not leak timing across the edge to
//!    an unsanctioned domain.

use core::num::NonZeroU32;

/// Identifier for a timing domain.
///
/// Newtype around [`NonZeroU32`]: `0` is reserved as "no domain
/// assigned" so a default-constructed handle must explicitly join a
/// domain before it can share secrets with anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimingDomain(NonZeroU32);

impl TimingDomain {
    /// Construct from a raw identifier. Typically only the
    /// hypervisor's domain allocator calls this.
    #[must_use]
    pub const fn new(id: NonZeroU32) -> Self {
        Self(id)
    }

    /// The raw id (for debugging / wire encoding).
    #[must_use]
    pub const fn get(self) -> NonZeroU32 {
        self.0
    }
}

/// A directed edge in the timing-domain data-flow graph.
///
/// `source` may share timing-sensitive data with `sink`. The reverse
/// direction is a separate edge; the graph is not implicitly
/// symmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainEdge {
    /// Domain producing the timing-sensitive information.
    pub source: TimingDomain,
    /// Domain allowed to observe it.
    pub sink: TimingDomain,
}

impl DomainEdge {
    /// Construct an edge. Self-edges (`source == sink`) are allowed
    /// and always trivially satisfied (a domain can always observe
    /// itself).
    #[must_use]
    pub const fn new(source: TimingDomain, sink: TimingDomain) -> Self {
        Self { source, sink }
    }

    /// `true` iff this edge is a self-loop.
    #[must_use]
    pub const fn is_self_loop(&self) -> bool {
        self.source.get().get() == self.sink.get().get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dom(n: u32) -> TimingDomain {
        TimingDomain::new(NonZeroU32::new(n).expect("non-zero"))
    }

    #[test]
    fn distinct_ids_are_distinct_domains() {
        assert_ne!(dom(1), dom(2));
    }

    #[test]
    fn edge_records_direction() {
        let a = dom(1);
        let b = dom(2);
        let ab = DomainEdge::new(a, b);
        let ba = DomainEdge::new(b, a);
        assert_ne!(ab, ba);
        assert_eq!(ab.source, a);
        assert_eq!(ab.sink, b);
    }

    #[test]
    fn self_loop_detected() {
        let a = dom(1);
        assert!(DomainEdge::new(a, a).is_self_loop());
        assert!(!DomainEdge::new(a, dom(2)).is_self_loop());
    }
}
