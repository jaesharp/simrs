//! Deterministic SIM state serialization for snapshot-based fuzzing.
//!
//! Provides the `Snapshot` trait with `save()` and `restore()` methods for
//! complete, byte-exact SIM state capture. All stateful simrs crates implement
//! `Snapshot`. The serialized blob is stored alongside QEMU VM snapshots to
//! ensure the SIM state and guest CPU/memory state are always synchronized.
//!
//! # Determinism guarantees
//! - No timestamps, RNG output, or platform-specific data included
//! - Fixed-size serialization format (no dynamic allocation in save/restore)
//! - Identical blob across platforms for the same logical state
//!
//! # `no_std`
//! Core trait and serialization logic are `no_std`.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;
