//! Deterministic state serialization for `simrs` simulator components.
//!
//! Two layered APIs:
//!
//! 1. [`Snapshot`] -- opaque newtype wrapping the serialized bytes. Holders
//!    cannot introspect or modify the contents; the only operations are
//!    `len`, `as_bytes` (for storage), `from_bytes` (for restoration), and
//!    pass-through to [`Snapshotable::restore`]. The byte format is private
//!    to each implementor, validated at restore time via a 4-byte
//!    version-and-producer-tag header.
//!
//! 2. [`Snapshotable`] -- trait that snapshotable types implement to
//!    produce/consume [`Snapshot`] values. Each impl declares a
//!    [`Snapshotable::PRODUCER_TAG`] (which type produced this snapshot)
//!    and [`Snapshotable::VERSION`] (which byte layout). Restoring a
//!    snapshot into the wrong type or wrong version returns
//!    [`SnapshotError::ProducerMismatch`] / [`SnapshotError::VersionMismatch`]
//!    rather than corrupting state.
//!
//! See [ADR 0001](../../../docs/adrs/0001-snapshot-architecture.md) for the
//! design rationale.
//!
//! # Hardware/software split
//!
//! Snapshots are produced and consumed by privileged host-side code (Rust
//! tests, fuzzers, control-plane probes). Application-level code (JCVM
//! bytecode, JCRE applet code, GP commands) cannot trigger save/restore --
//! the API surface is Rust-only and gated behind a `snapshot` feature on
//! each consumer crate.
//!
//! # Determinism guarantees
//! - No timestamps, RNG output, or platform-specific data included
//! - Identical blob across platforms for the same logical state
//! - Round-trip is byte-exact within a single `(PRODUCER_TAG, VERSION)` pair
//!
//! # `no_std` + `alloc`
//! Core trait and serialization logic are `no_std`. The `Snapshot` newtype
//! owns its bytes via [`alloc::boxed::Box`], requiring `alloc`.

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Producer tag registry
// ---------------------------------------------------------------------------

/// Stable producer-tag constants used in snapshot headers.
///
/// Each `Snapshotable` impl declares one of these as its
/// `PRODUCER_TAG`. Tags disambiguate snapshots at restore time --
/// feeding a `Sim` snapshot to `JcVM::restore` returns
/// [`SnapshotError::ProducerMismatch`] rather than corrupting state.
///
/// New tags must be appended; existing tag values must not change
/// (or stored snapshots become unrecoverable).
pub mod producer {
    /// `simrs-fs::FsData`.
    pub const FS_DATA: u16 = 0x0001;
    /// `simrs-pin::PinManager`.
    pub const PIN_MANAGER: u16 = 0x0002;
    /// `simrs-iso7816::ResponseQueue`.
    pub const RESPONSE_QUEUE: u16 = 0x0003;
    /// `simrs-proactive::ProactiveState`.
    pub const PROACTIVE: u16 = 0x0004;
    /// `simrs-jcre::TransactionJournal`.
    pub const JCRE_TRANSACTION_JOURNAL: u16 = 0x0005;
    /// `simrs-jcvm::heap::ObjectHeap`.
    pub const OBJECT_HEAP: u16 = 0x0006;
    /// `simrs-jcvm::cap::Package`.
    pub const PACKAGE: u16 = 0x0007;
    /// `simrs-gp-keys::KeyStore`.
    pub const KEYSTORE: u16 = 0x0008;
    /// `simrs-gp-open::Registry`.
    pub const REGISTRY: u16 = 0x0009;
    /// `simrs-gsm::GsmApp`.
    pub const GSM_APP: u16 = 0x000A;
    /// `simrs-usim::UsimApp`.
    pub const USIM_APP: u16 = 0x000B;
    /// `simrs-sim::Sim`.
    pub const SIM: u16 = 0x000C;
    /// `simrs-milenage::MilenageParams`.
    pub const MILENAGE: u16 = 0x000D;
    /// `simrs-tuak::TuakParams`.
    pub const TUAK: u16 = 0x000E;
    /// `simrs-jcvm::JcVM`.
    pub const JCVM: u16 = 0x000F;
    /// `simrs-jcvm::JcVMApplet`.
    pub const JCVM_APPLET: u16 = 0x0010;
    /// `simrs-gp-card::GpCard`.
    pub const GP_CARD: u16 = 0x0011;
    /// `simrs-gp-open::GpOpen`.
    pub const GP_OPEN: u16 = 0x0012;
    /// `simrs-jcvm::transaction::TransactionJournal`.
    pub const JCVM_TRANSACTION_JOURNAL: u16 = 0x0013;
}

// ---------------------------------------------------------------------------
// Snapshot opaque type
// ---------------------------------------------------------------------------

/// Length of the snapshot header (`[major, minor, producer_hi, producer_lo]`).
pub const HEADER_LEN: usize = 4;

/// Opaque snapshot of a snapshotable component's state.
///
/// Holders cannot inspect, decode, or modify the contents. The only
/// supported operations are:
///   - [`Snapshot::len`] -- byte length, for storage planning.
///   - [`Snapshot::as_bytes`] -- raw bytes for on-disk persistence.
///     Documented as "for storage; do not parse" -- the format is
///     private to each `Snapshotable` impl.
///   - [`Snapshot::from_bytes`] -- recover a `Snapshot` from on-disk
///     bytes. Validates the header but does not unpack the payload.
///   - Pass to a `Snapshotable::restore` for the matching producer tag.
///   - [`Snapshot::producer_tag`] / [`Snapshot::version`] -- header fields,
///     for diagnostics.
///   - Compare for equality (fast structural check).
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Snapshot {
    /// Header (4 bytes) + raw payload from the underlying type's
    /// `save_state_internal`.
    inner: Box<[u8]>,
}

impl Snapshot {
    /// Construct from a header + payload.
    ///
    /// Internal helper for `Snapshotable::snapshot` impls; not part
    /// of the public API.
    #[doc(hidden)]
    #[must_use]
    pub fn from_header_and_payload(version: (u8, u8), producer_tag: u16, payload: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
        buf.push(version.0);
        buf.push(version.1);
        buf.extend_from_slice(&producer_tag.to_be_bytes());
        buf.extend_from_slice(payload);
        Self {
            inner: buf.into_boxed_slice(),
        }
    }

    /// Total byte length of this snapshot (header + payload).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if this snapshot is empty. Always false for a well-formed
    /// snapshot (header alone is `HEADER_LEN` bytes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Raw bytes for storage. The format is opaque -- callers should
    /// only round-trip via [`Snapshot::from_bytes`], not parse.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Reconstitute a snapshot from on-disk bytes. Validates the
    /// header is the correct length but does not unpack the payload.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Truncated`] if `bytes.len() < HEADER_LEN`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() < HEADER_LEN {
            return Err(SnapshotError::Truncated);
        }
        Ok(Self {
            inner: bytes.into(),
        })
    }

    /// Producer tag from the header.
    #[must_use]
    pub fn producer_tag(&self) -> u16 {
        u16::from_be_bytes([self.inner[2], self.inner[3]])
    }

    /// Version `(major, minor)` from the header.
    #[must_use]
    pub fn version(&self) -> (u8, u8) {
        (self.inner[0], self.inner[1])
    }

    /// Payload bytes (header excluded). Used by `Snapshotable::restore`
    /// implementations to feed the underlying `restore_state_internal`.
    #[doc(hidden)]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.inner[HEADER_LEN..]
    }
}

// ---------------------------------------------------------------------------
// Snapshotable trait
// ---------------------------------------------------------------------------

/// Trait for types that can be snapshotted into / restored from an
/// opaque [`Snapshot`].
///
/// Each impl declares its [`Self::PRODUCER_TAG`] (a value from the
/// [`producer`] module) and [`Self::VERSION`]. The trait methods wrap
/// the type's internal raw byte serialization in a [`Snapshot`] with
/// the correct header.
pub trait Snapshotable {
    /// Stable identifier for this type. Used in the snapshot header
    /// to disambiguate snapshots of different types at restore time.
    const PRODUCER_TAG: u16;

    /// Snapshot version `(major, minor)`. Bumped on any byte-layout
    /// change. Restoring a mismatched-major snapshot returns
    /// [`SnapshotError::VersionMismatch`].
    const VERSION: (u8, u8);

    /// Capture current state into an opaque [`Snapshot`].
    fn snapshot(&self) -> Snapshot;

    /// Restore from a previously-captured snapshot.
    ///
    /// # Errors
    ///
    /// - [`SnapshotError::ProducerMismatch`] if the snapshot was
    ///   produced by a different type.
    /// - [`SnapshotError::VersionMismatch`] if the major version
    ///   doesn't match (breaking layout change).
    /// - [`SnapshotError::Truncated`] / [`SnapshotError::Malformed`] if
    ///   the payload doesn't decode correctly.
    fn restore(&mut self, snap: &Snapshot) -> Result<(), SnapshotError>;
}

/// Errors that can occur during snapshot restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// Snapshot is too short to contain even the header, or the
    /// payload is shorter than expected.
    Truncated,
    /// Header parses but payload doesn't match the expected layout.
    /// Distinct from `Truncated` -- the bytes were enough, they just
    /// aren't valid.
    Malformed,
    /// Snapshot was produced by a different type than the caller is
    /// attempting to restore into.
    ProducerMismatch {
        /// Producer tag the caller expected (its `PRODUCER_TAG`).
        expected: u16,
        /// Producer tag found in the snapshot header.
        found: u16,
    },
    /// Snapshot's major version doesn't match the caller's
    /// `VERSION.0`. Indicates a breaking layout change.
    VersionMismatch {
        /// Version the caller expects.
        expected: (u8, u8),
        /// Version found in the snapshot header.
        found: (u8, u8),
    },
}

/// Validate a snapshot's header against an expected
/// `(producer_tag, version)`. Used by `Snapshotable::restore` impls
/// before they hand the payload to `restore_state_internal`.
///
/// # Errors
///
/// Returns [`SnapshotError::ProducerMismatch`] or
/// [`SnapshotError::VersionMismatch`] as appropriate.
pub fn validate_header(
    snap: &Snapshot,
    expected_producer: u16,
    expected_version: (u8, u8),
) -> Result<(), SnapshotError> {
    if snap.len() < HEADER_LEN {
        return Err(SnapshotError::Truncated);
    }
    let found_producer = snap.producer_tag();
    if found_producer != expected_producer {
        return Err(SnapshotError::ProducerMismatch {
            expected: expected_producer,
            found: found_producer,
        });
    }
    let found_version = snap.version();
    // Major version must match exactly; minor version differences
    // are allowed (additive layout changes).
    if found_version.0 != expected_version.0 {
        return Err(SnapshotError::VersionMismatch {
            expected: expected_version,
            found: found_version,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers for `Snapshotable` impls that wrap a raw-byte API
// ---------------------------------------------------------------------------

/// Build a `Snapshot` by allocating an upper-bound buffer, calling
/// the type's raw `save_state(buf)`, and wrapping the result in the
/// opaque header.
///
/// The canonical implementation pattern for `Snapshotable::snapshot`
/// on types that already have a raw byte serialization API. Reduces
/// the per-consumer boilerplate from ~10 lines to a single call.
///
/// `save_fn` is `impl FnOnce(&mut [u8]) -> usize` -- the same shape
/// as the existing `save_state` methods. Returning `0` from `save_fn`
/// means "buffer too small"; the resulting snapshot has an empty
/// payload, and a subsequent `restore_via_raw_bytes` will return
/// [`SnapshotError::Malformed`].
#[must_use]
pub fn snapshot_via_raw_bytes(
    version: (u8, u8),
    producer_tag: u16,
    max_size: usize,
    save_fn: impl FnOnce(&mut [u8]) -> usize,
) -> Snapshot {
    let mut buf = alloc::vec![0u8; max_size];
    let n = save_fn(&mut buf);
    let payload = if n == 0 { &[][..] } else { &buf[..n] };
    Snapshot::from_header_and_payload(version, producer_tag, payload)
}

/// Restore a `Snapshot` by validating the header and feeding the
/// payload to the type's raw `restore_state(buf) -> bool`.
///
/// The canonical implementation pattern for `Snapshotable::restore`.
/// Reduces the per-consumer boilerplate from ~6 lines to a single
/// call.
///
/// `restore_fn` is `impl FnOnce(&[u8]) -> bool` -- the same shape as
/// the existing `restore_state` methods. `false` is mapped to
/// [`SnapshotError::Malformed`].
///
/// # Errors
///
/// Returns whatever [`validate_header`] returns, or
/// [`SnapshotError::Malformed`] if `restore_fn` returns `false`.
pub fn restore_via_raw_bytes(
    snap: &Snapshot,
    expected_producer: u16,
    expected_version: (u8, u8),
    restore_fn: impl FnOnce(&[u8]) -> bool,
) -> Result<(), SnapshotError> {
    validate_header(snap, expected_producer, expected_version)?;
    if !restore_fn(snap.payload()) {
        return Err(SnapshotError::Malformed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy trait (deprecated, kept for the migration window)
// ---------------------------------------------------------------------------

/// Legacy snapshot trait, deprecated in favour of [`Snapshotable`].
///
/// Kept during the workspace-wide migration from raw byte API to
/// opaque [`Snapshot`] type (see ADR 0001). Each consumer crate
/// implements this for its top-level type during Phase 3; the
/// trait is removed in Phase 5.
#[deprecated(
    since = "0.2.0",
    note = "use the `Snapshotable` trait instead; \
            see docs/adrs/0001-snapshot-architecture.md"
)]
pub trait LegacySnapshot {
    /// Fixed snapshot buffer size in bytes.
    const SIZE: usize;

    /// Serialize the current state into `buf`.
    fn save(&self, buf: &mut [u8]) -> usize;

    /// Restore state from `buf`.
    fn restore(&mut self, buf: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::large_stack_arrays)]
mod tests {
    use super::*;

    // -- New Snapshot type tests --

    #[test]
    fn snapshot_header_round_trips() {
        let payload = [1u8, 2, 3, 4, 5];
        let snap = Snapshot::from_header_and_payload((1, 0), 0x000F, &payload);
        assert_eq!(snap.len(), HEADER_LEN + payload.len());
        assert_eq!(snap.version(), (1, 0));
        assert_eq!(snap.producer_tag(), 0x000F);
        assert_eq!(snap.payload(), &payload);
    }

    #[test]
    fn snapshot_from_bytes_validates_header_length() {
        // 3 bytes is too short for the 4-byte header.
        let result = Snapshot::from_bytes(&[1, 2, 3]);
        assert_eq!(result.unwrap_err(), SnapshotError::Truncated);
    }

    #[test]
    fn snapshot_from_bytes_accepts_header_only() {
        // Exactly 4 bytes (header, no payload) is valid.
        let snap = Snapshot::from_bytes(&[1, 0, 0xAB, 0xCD]).unwrap();
        assert_eq!(snap.version(), (1, 0));
        assert_eq!(snap.producer_tag(), 0xABCD);
        assert!(snap.payload().is_empty());
    }

    #[test]
    fn snapshot_as_bytes_round_trips_through_from_bytes() {
        let snap1 = Snapshot::from_header_and_payload((2, 5), producer::JCVM, &[10, 20, 30]);
        let bytes = snap1.as_bytes().to_vec();
        let snap2 = Snapshot::from_bytes(&bytes).unwrap();
        assert_eq!(snap1, snap2);
    }

    #[test]
    fn snapshot_equality_is_structural() {
        let a = Snapshot::from_header_and_payload((1, 0), 0xAAAA, &[1, 2, 3]);
        let b = Snapshot::from_header_and_payload((1, 0), 0xAAAA, &[1, 2, 3]);
        let c = Snapshot::from_header_and_payload((1, 0), 0xAAAA, &[1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -- validate_header tests --

    #[test]
    fn validate_header_accepts_matching() {
        let snap = Snapshot::from_header_and_payload((1, 0), producer::JCVM, &[]);
        assert!(validate_header(&snap, producer::JCVM, (1, 0)).is_ok());
    }

    #[test]
    fn validate_header_minor_version_difference_is_allowed() {
        // Implementation expects (1, 0); snapshot is (1, 5). Same
        // major version, additive layout changes -> allowed.
        let snap = Snapshot::from_header_and_payload((1, 5), producer::JCVM, &[]);
        assert!(validate_header(&snap, producer::JCVM, (1, 0)).is_ok());
    }

    #[test]
    fn validate_header_rejects_producer_mismatch() {
        let snap = Snapshot::from_header_and_payload((1, 0), producer::SIM, &[]);
        let err = validate_header(&snap, producer::JCVM, (1, 0)).unwrap_err();
        assert_eq!(
            err,
            SnapshotError::ProducerMismatch {
                expected: producer::JCVM,
                found: producer::SIM,
            },
        );
    }

    #[test]
    fn validate_header_rejects_major_version_mismatch() {
        let snap = Snapshot::from_header_and_payload((2, 0), producer::JCVM, &[]);
        let err = validate_header(&snap, producer::JCVM, (1, 0)).unwrap_err();
        assert_eq!(
            err,
            SnapshotError::VersionMismatch {
                expected: (1, 0),
                found: (2, 0),
            },
        );
    }

    #[test]
    fn producer_tags_are_unique() {
        // Sanity check the producer-tag registry: every tag declared
        // in the `producer` module is distinct.
        let tags = [
            producer::FS_DATA,
            producer::PIN_MANAGER,
            producer::RESPONSE_QUEUE,
            producer::PROACTIVE,
            producer::JCRE_TRANSACTION_JOURNAL,
            producer::OBJECT_HEAP,
            producer::PACKAGE,
            producer::KEYSTORE,
            producer::REGISTRY,
            producer::GSM_APP,
            producer::USIM_APP,
            producer::SIM,
            producer::MILENAGE,
            producer::TUAK,
            producer::JCVM,
            producer::JCVM_APPLET,
            producer::GP_CARD,
            producer::GP_OPEN,
            producer::JCVM_TRANSACTION_JOURNAL,
        ];
        let mut seen = [false; 0x10000];
        for tag in tags {
            let idx = tag as usize;
            assert!(!seen[idx], "duplicate producer tag 0x{tag:04X}");
            seen[idx] = true;
        }
    }

    // -- LegacySnapshot trait shape (the trait is empty -- impls
    // live in their respective consumer crates) --

    #[allow(deprecated)]
    #[test]
    fn legacy_trait_is_object_safe_for_dyn_dispatch() {
        // Sanity: the LegacySnapshot trait can be defined without
        // a concrete impl in this crate. Consumer crates supply
        // impls; simrs-snapshot only owns the trait.
        struct Stub;
        impl LegacySnapshot for Stub {
            const SIZE: usize = 0;
            fn save(&self, _buf: &mut [u8]) -> usize {
                0
            }
            fn restore(&mut self, _buf: &[u8]) -> bool {
                false
            }
        }
        let mut s = Stub;
        let mut buf = [0u8; 8];
        assert_eq!(LegacySnapshot::save(&s, &mut buf), 0);
        assert!(!LegacySnapshot::restore(&mut s, &buf));
    }
}
