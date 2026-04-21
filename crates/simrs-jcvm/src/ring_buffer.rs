//! Static single-producer / single-consumer ring buffer carrying
//! guest-execution events from the JCVM to the dom0 hypervisor.
//!
//! # Design
//!
//! - Fixed compile-time capacity (const generic `N`). No heap.
//! - Power-of-two capacity required; enforced at `new()`. Wrap uses
//!   a bitmask instead of modulo.
//! - Plain `[Event; N]` storage initialised with [`Event::EMPTY`]
//!   sentinels. `Event` is [`Copy`] and its inline storage cost is
//!   8 bytes; 1 Ki-slot ring = 8 KiB, a reasonable ceiling for a
//!   `no_std` profile.
//! - Single-threaded within a `JcVM`: both the dispatch loop
//!   (writer) and the hypervisor reader run on the simulator
//!   thread. No atomics needed; the non-atomic head/tail are safe
//!   so long as writer and reader do not interleave on the same
//!   slot.
//! - Overwrite-on-full semantics: the producer never blocks; the
//!   oldest unread slot is overwritten and the reader's `tail`
//!   advances to follow. Lossy but deterministic -- callers who
//!   need loss-freedom size the ring for their workload.
//!
//! # Guest/hypervisor separation
//!
//! The ring buffer is invisible to the guest applet. The guest
//! (JCVM dispatch loop) unconditionally pushes every event through
//! [`RingBuffer::push`]; it has no knowledge of hypervisor filters,
//! ring capacity, or drain policy. All configuration -- including
//! event-type filtering -- happens on the hypervisor side at
//! *drain* time (see [`crate::hypervisor`]). This keeps the guest's
//! push path trivially data-oblivious: every event does the same
//! work.
//!
//! # Constant-time contract
//!
//! Every write follows the same code path (`push` has no
//! data-dependent branches beyond the tag byte; the store itself
//! is a plain assignment into pre-allocated storage). Pinned via
//! `pin_observation` like the counters so the feature-off build
//! still executes the store.

use crate::pin_observation;

/// A single record carried over the hypervisor ring buffer.
///
/// `#[repr(u8)]`-tagged so the wire size is predictable (at most
/// 8 bytes including tag + alignment). Kept small so the ring
/// buffer's memory footprint stays bounded in `no_std` profiles.
// The `Uninitialised` variant is a sentinel used by [`RingBuffer`]
// for slots that have never been written. It is not an "in-future
// more variants may be added" marker, so the non-exhaustive lint
// does not apply here.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    /// A bytecode opcode was dispatched. Payload: opcode byte.
    OpcodeExecuted(u8) = 0x01,
    /// A method was entered. Payload: package id + method id.
    MethodEntered {
        /// Package identifier of the entered method.
        pkg: u8,
        /// Method index within the package.
        method: u8,
    } = 0x02,
    /// A method returned. Payload: package id + method id that
    /// returned (i.e. the callee, not the caller). Depth delta is
    /// implicit (depth decreases by one).
    MethodReturned {
        /// Package identifier of the returning method.
        pkg: u8,
        /// Method index within the package.
        method: u8,
    } = 0x03,
    /// Counter snapshot marker. Used by dom0 to bracket a window
    /// across event drains -- the reader sees these in stream order
    /// and can correlate counter deltas to event sequences.
    CounterSnapshot {
        /// Running total-instructions value at the marker point.
        total_instructions: u64,
    } = 0x04,
    /// Placeholder for slots never written to. Never produced by
    /// the dispatch loop; only visible through unsafe raw access.
    #[doc(hidden)]
    Uninitialised = 0x00,
}

impl Event {
    /// Default value used to initialise freshly-reset ring slots.
    /// Never surfaces through the safe reader API.
    pub const EMPTY: Self = Self::Uninitialised;
}

/// Static single-producer / single-consumer event ring buffer.
///
/// `N` is the capacity in slots. Must be a power of two so the
/// wrap mask is `N - 1`.
#[derive(Debug, Clone)]
pub struct RingBuffer<const N: usize> {
    slots: [Event; N],
    /// Next slot the producer will write to (monotonically
    /// increasing; wraps only virtually via the `N - 1` mask).
    head: usize,
    /// Next slot the consumer will read from.
    tail: usize,
}

impl<const N: usize> RingBuffer<N> {
    /// Create a fresh, empty ring.
    ///
    /// # Panics
    ///
    /// Panics at compile time if `N` is not a power of two or is
    /// zero. The `const` assertion ensures the wrap mask is well
    /// defined.
    #[must_use]
    pub const fn new() -> Self {
        assert!(
            N.is_power_of_two(),
            "RingBuffer capacity must be a power of two"
        );
        assert!(N > 0, "RingBuffer capacity must be non-zero");
        Self {
            slots: [Event::EMPTY; N],
            head: 0,
            tail: 0,
        }
    }

    /// Capacity in slots.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Number of events currently unread (may be up to `capacity`;
    /// saturates on overwrite).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.head.wrapping_sub(self.tail)
    }

    /// `true` iff no events are waiting to be drained.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Push an event into the ring. If the ring is full, the oldest
    /// unread slot is overwritten and the reader's `tail` advances.
    /// Lossy but deterministic.
    pub const fn push(&mut self, ev: Event) {
        let mask = N - 1;
        let idx = self.head & mask;
        self.slots[idx] = ev;
        self.head = self.head.wrapping_add(1);
        // If we have wrapped past `tail`, drag `tail` along so
        // `len()` never exceeds `capacity`.
        if self.head.wrapping_sub(self.tail) > N {
            self.tail = self.head.wrapping_sub(N);
        }
        let _ = pin_observation(&self.slots);
        let _ = pin_observation(&self.head);
    }

    /// Pop the oldest event, if any.
    pub const fn pop(&mut self) -> Option<Event> {
        if self.is_empty() {
            return None;
        }
        let mask = N - 1;
        let idx = self.tail & mask;
        let ev = self.slots[idx];
        self.tail = self.tail.wrapping_add(1);
        Some(ev)
    }

    /// Drain up to `limit` events into `out`. Returns the number
    /// actually drained. Caller-supplied buffer avoids allocation.
    pub fn drain_into(&mut self, out: &mut [Event], limit: usize) -> usize {
        let n = core::cmp::min(limit, core::cmp::min(out.len(), self.len()));
        for slot in out.iter_mut().take(n) {
            // `pop()` returns Some here because we capped `n` at
            // `len()`.
            if let Some(ev) = self.pop() {
                *slot = ev;
            }
        }
        n
    }
}

impl<const N: usize> Default for RingBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let rb: RingBuffer<4> = RingBuffer::new();
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
        assert_eq!(rb.capacity(), 4);
    }

    #[test]
    fn push_pop_roundtrip() {
        let mut rb: RingBuffer<4> = RingBuffer::new();
        rb.push(Event::OpcodeExecuted(0x2A));
        rb.push(Event::OpcodeExecuted(0x2B));
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.pop(), Some(Event::OpcodeExecuted(0x2A)));
        assert_eq!(rb.pop(), Some(Event::OpcodeExecuted(0x2B)));
        assert_eq!(rb.pop(), None);
        assert!(rb.is_empty());
    }

    #[test]
    fn overwrite_when_full_drops_oldest() {
        let mut rb: RingBuffer<4> = RingBuffer::new();
        for i in 0..6 {
            rb.push(Event::OpcodeExecuted(i));
        }
        // Capacity 4: we pushed 6, so the two oldest (0, 1) are
        // gone. The next pop should return 2.
        assert_eq!(rb.len(), 4);
        let mut drained = [Event::EMPTY; 4];
        let n = rb.drain_into(&mut drained, 4);
        assert_eq!(n, 4);
        assert_eq!(
            drained,
            [
                Event::OpcodeExecuted(2),
                Event::OpcodeExecuted(3),
                Event::OpcodeExecuted(4),
                Event::OpcodeExecuted(5),
            ]
        );
        assert!(rb.is_empty());
    }

    #[test]
    fn drain_respects_caller_limit_and_buffer_length() {
        let mut rb: RingBuffer<8> = RingBuffer::new();
        for i in 0..5 {
            rb.push(Event::OpcodeExecuted(i));
        }
        let mut out = [Event::EMPTY; 3];
        let n = rb.drain_into(&mut out, 10);
        // Capped by out.len() = 3, not by our requested limit = 10.
        assert_eq!(n, 3);
        assert_eq!(rb.len(), 2);
    }

    #[test]
    fn distinct_variants_have_distinct_discriminants() {
        use core::mem::discriminant;
        let variants = [
            discriminant(&Event::OpcodeExecuted(0)),
            discriminant(&Event::MethodEntered { pkg: 0, method: 0 }),
            discriminant(&Event::MethodReturned { pkg: 0, method: 0 }),
            discriminant(&Event::CounterSnapshot {
                total_instructions: 0,
            }),
            discriminant(&Event::Uninitialised),
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
        assert_eq!(Event::EMPTY, Event::Uninitialised);
    }
}
