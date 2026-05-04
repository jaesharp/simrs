# ADR 0001: Snapshot architecture -- opaque, test-only, hardware/software-split

**Status:** Proposed
**Date:** 2026-05-05

---

## Context

`simrs` currently exposes snapshot capability as `pub fn save_state(buf: &mut [u8]) -> usize` and `pub fn restore_state(buf: &[u8]) -> bool` on **17 source files across 14 crates** (`simrs-fs`, `simrs-pin`, `simrs-gsm`, `simrs-usim`, `simrs-sim`, `simrs-jcvm`, `simrs-gp-keys`, `simrs-gp-open`, `simrs-gp-card`, `simrs-jcre`, `simrs-tuak`, `simrs-milenage`, `simrs-proactive`, `simrs-iso7816`).

Two design defects in the current architecture:

1. **Test infrastructure mixed into production surface.** Snapshots are a debugger / fuzzer / simulator-checkpoint capability. The methods that produce them are part of every consumer crate's public API, even in production builds where snapshot/restore should be inaccessible. A consumer that links `simrs-jcvm` for runtime use ends up with snapshot access whether it wants it or not.

2. **Snapshot blobs are not opaque.** Callers receive a raw `&[u8]`/`&mut [u8]` -- they can introspect, modify, or splice the bytes. The byte format is leaked across the API boundary. Round-trip correctness depends on caller discipline rather than type-level enforcement.

A user-flagged third concern that's adjacent: the "hardware/software split". Application code (JCVM bytecode, JCRE applet code) cannot trigger a snapshot because the `save_state` methods are Rust-side, not exposed via opcodes / APDU. That part is fine. The defect is at the **Rust API surface**, not at the bytecode/APDU surface.

This ADR proposes a workspace-wide cleanup that:
- Moves the raw byte API to `pub(crate)` visibility.
- Introduces a single opaque `Snapshot` newtype workspace-wide.
- Routes all snapshot/restore through a feature-gated test-manager surface.
- Preserves byte-for-byte compatibility with existing snapshots.

---

## Goals

1. **Production-build separation.** Default builds of consumer crates expose **zero** snapshot API. Code that links `simrs-jcvm` for production use cannot save/restore VM state. Failure mode: compile-time (the methods don't exist), not runtime gating.

2. **Opaque `Snapshot` type.** External holders of snapshots see only `Snapshot::len()` and round-trip APIs (`take_snapshot`, `restore_snapshot`). The byte representation is private; callers can store, transmit, or compare-by-equality, but cannot decode.

3. **Composability.** A `Snapshot` of a top-level type (e.g. `Sim`, `JcVM`, `GpCard`) transparently includes child component snapshots (`FsData`, `ObjectHeap`, `Package`, etc.). The opaque wrapper exists at the top level only; children produce/consume raw bytes within the same crate.

4. **Backwards compatibility (byte format).** Snapshots taken before this ADR must be restorable after this ADR (within a transition window). Versioning header on the opaque blob handles this. After the transition, old format is rejected with a clear error.

5. **One canonical pattern.** All 14 crates use the same trait, the same opaque type, the same feature flag name. New snapshotable types follow the pattern by default.

## Non-goals

- **Introducing snapshot stepping / mid-instruction checkpoints.** That's a separate, larger feature that depends on a `step()` API. The execution-state preservation we just landed (commit `e0b8faf`) makes mid-execution snapshots *correct* if a future stepping API is added; this ADR is purely about API hygiene, not about adding new capabilities.

- **Cross-version snapshot compatibility beyond the transition.** Opaque blobs from `simrs-jcvm` v0.1 are not required to restore into `simrs-jcvm` v0.2; the version tag lets us reject mismatches loudly.

- **Encrypted / signed snapshots.** Out of scope; layer that on top if needed.

---

## Architecture

### Three layers

```
                       (external consumers)
                              ▼
┌─────────────────────────────────────────────────────────┐
│ simrs-snapshot                                          │
│   pub struct Snapshot { ... }                           │
│   pub trait Snapshotable {                              │
│       fn snapshot(&self) -> Snapshot;                   │
│       fn restore(&mut self, snap: &Snapshot)            │
│           -> Result<(), SnapshotError>;                 │
│   }                                                     │
│   pub enum SnapshotError { ... }                        │
└─────────────────────────────────────────────────────────┘
                              ▼  (only via the trait)
┌─────────────────────────────────────────────────────────┐
│ simrs-{jcvm,sim,gp-card,...}                            │
│   #[cfg(feature = "snapshot")]                          │
│   impl Snapshotable for JcVM<...> { ... }               │
│                                                         │
│   pub(crate) fn save_state_internal(buf: &mut [u8])     │
│       -> usize;                                         │
│   pub(crate) fn restore_state_internal(buf: &[u8])      │
│       -> bool;                                          │
└─────────────────────────────────────────────────────────┘
                              ▼  (visibility-restricted)
                   (raw byte serialization, internal)
```

**Layer 1 -- `simrs-snapshot`** owns:
- The `Snapshot` opaque newtype.
- The `Snapshotable` trait that consumers implement.
- The `SnapshotError` enum.
- The version header convention.
- No concrete impls beyond `Sim` (which already exists).

**Layer 2 -- consumer crates** own their `impl Snapshotable for T`, gated behind a `snapshot` feature flag. Without the feature, the trait impl is absent and `T` cannot be snapshotted from outside the crate. Internal raw byte methods are `pub(crate)` so siblings within the crate (and tests) can compose them.

**Layer 3 -- raw serialization** stays inside each module, visibility `pub(crate)`. This is where `save_state(buf: &mut [u8]) -> usize` lives. Same byte format as today; only the visibility changes.

### Opaque `Snapshot` type

```rust
/// Opaque snapshot of a snapshotable component's state.
///
/// Holders cannot inspect, decode, or modify the contents. The only
/// supported operations are:
///   - Read `len()` for storage planning
///   - Pass to `T::restore()` for the original component type `T`
///   - Compare for equality (fast structural check)
///   - Serialize/deserialize as bytes via `as_bytes()`/`from_bytes()`
///     (for snapshot-on-disk; round-trips are guaranteed by version tag)
#[derive(Clone, Eq, PartialEq)]
pub struct Snapshot {
    /// Two-byte version + producer-tag header, then the raw bytes
    /// from the underlying type's `save_state_internal`.
    inner: Box<[u8]>,
}

impl Snapshot {
    pub fn len(&self) -> usize { self.inner.len() }

    /// Serialize for on-disk storage. Round-trip with `from_bytes`.
    pub fn as_bytes(&self) -> &[u8] { &self.inner }

    /// Deserialize from on-disk storage. Validates the version
    /// header but does not unpack the payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> { ... }
}

/// Snapshot version + producer-tag header.
///
/// Layout: [version_major: u8][version_minor: u8][producer_tag: u16 BE]
/// Producer tags are crate-defined constants in simrs-snapshot.
const SNAPSHOT_HEADER_LEN: usize = 4;
```

### `Snapshotable` trait

```rust
pub trait Snapshotable {
    /// Stable identifier for this type, used in the version header.
    /// Disambiguates a `JcVM` snapshot from a `Sim` snapshot at
    /// restore time.
    const PRODUCER_TAG: u16;

    /// Snapshot version this implementation produces. Bumped on
    /// any byte-layout change.
    const VERSION: (u8, u8);

    /// Capture state.
    fn snapshot(&self) -> Snapshot;

    /// Restore from a snapshot. Validates header, returns
    /// SnapshotError::ProducerMismatch / VersionMismatch /
    /// Truncated / Malformed as appropriate.
    fn restore(&mut self, snap: &Snapshot) -> Result<(), SnapshotError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// Snapshot too short to even contain the version header.
    Truncated,
    /// Header parses but payload doesn't match the expected layout.
    Malformed,
    /// PRODUCER_TAG doesn't match the type the caller is restoring
    /// into (e.g. trying to restore a `Sim` snapshot into a `JcVM`).
    ProducerMismatch { expected: u16, found: u16 },
    /// VERSION's major doesn't match -- breaking layout change.
    VersionMismatch { expected: (u8, u8), found: (u8, u8) },
}
```

### Feature flag

Each consumer crate gains a `snapshot` feature. Default off. When off, the `Snapshotable` impl and the `pub(crate)` raw byte methods are `#[cfg]`'d out entirely (no dead-code warning, no compiled bytes in production).

`simrs-fuzz`, `simrs-snapshot`'s test code, and any test-only consumer enables the feature explicitly.

### What about TestManager?

The user's original suggestion was "a test manager component for the OS". The `Snapshotable` trait IS the test manager API -- consumers call it, it produces opaque `Snapshot` values. We don't need a separate `TestManager` struct because:
- `Snapshotable` is generic over the component being snapshotted.
- The trait method namespace (`vm.snapshot()`, `vm.restore(&snap)`) is already at the right abstraction level.
- A standalone `TestManager` that wraps `&JcVM` would just be a forwarder.

If, in the future, snapshot operations need orchestration across multiple components (e.g. snapshot `Sim` and `Interposer` together), introduce a `TestManager` then. For now, the trait suffices.

---

## Migration plan -- 5 phases

### Phase 1: Foundation in `simrs-snapshot` (small, additive)

- Define `Snapshot`, `SnapshotError`, `Snapshotable` per the architecture above.
- Reserve producer tag constants for every existing snapshotable type:
  ```rust
  pub mod producer {
      pub const FS_DATA: u16             = 0x0001;
      pub const PIN_MANAGER: u16         = 0x0002;
      pub const RESPONSE_QUEUE: u16      = 0x0003;
      pub const PROACTIVE: u16           = 0x0004;
      pub const TRANSACTION_JOURNAL: u16 = 0x0005;
      pub const OBJECT_HEAP: u16         = 0x0006;
      pub const PACKAGE: u16             = 0x0007;
      pub const KEYSTORE: u16            = 0x0008;
      pub const REGISTRY: u16            = 0x0009;
      pub const GSM_APP: u16             = 0x000A;
      pub const USIM_APP: u16            = 0x000B;
      pub const SIM: u16                 = 0x000C;
      pub const MILENAGE: u16            = 0x000D;
      pub const TUAK: u16                = 0x000E;
      pub const JCVM: u16                = 0x000F;
      pub const JCVM_APPLET: u16         = 0x0010;
      pub const GP_CARD: u16             = 0x0011;
      pub const GP_OPEN: u16             = 0x0012;
  }
  ```
- Add the existing `Snapshot` (the trait already in `simrs-snapshot`) as a deprecated alias for backwards compatibility during the migration.
- **Tests**: `Snapshot::from_bytes`/`as_bytes` round-trip; `SnapshotError` variants emit on the right inputs.

**Risk:** Low. Pure addition, no existing code touched.

### Phase 2: Migrate one anchor consumer (`simrs-jcvm`)

- Add `snapshot` feature to `simrs-jcvm/Cargo.toml`.
- Rename the existing `pub fn save_state` / `pub fn restore_state` to `pub(crate) fn save_state_internal` / `pub(crate) fn restore_state_internal`. Internal callers (the `Snapshot` trait impl on `JcVMApplet`) follow.
- Add `#[cfg(feature = "snapshot")] impl Snapshotable for JcVM<...>` that wraps the raw byte API in the opaque `Snapshot` type with the right producer tag and version.
- `simrs-jcvm`'s own snapshot tests gain `#[cfg(feature = "snapshot")]` and run with `--features snapshot`.
- Workspace `Cargo.toml` adds `snapshot` to the default test feature set if needed.

**Risk:** Medium. Existing tests pass without re-implementation work because the raw byte format is unchanged; only the visibility moves. Verify by running the full suite.

**Acceptance:** All existing tests pass with `--features snapshot`; running without the feature, snapshot methods are gone and the crate still builds (no orphaned references).

### Phase 3: Migrate the rest of the consumers (one PR per crate)

For each crate in `simrs-fs`, `simrs-pin`, `simrs-gsm`, `simrs-usim`, `simrs-sim`, `simrs-gp-keys`, `simrs-gp-open`, `simrs-gp-card`, `simrs-jcre`, `simrs-tuak`, `simrs-milenage`, `simrs-proactive`, `simrs-iso7816`:

- Add `snapshot` feature.
- Convert `pub fn save_state`/`pub fn restore_state` to `pub(crate) fn ..._internal`.
- Add `Snapshotable` impl behind the feature.
- Update test calls from `vm.save_state(buf)` to `vm.snapshot()` / `Snapshotable::snapshot(&vm)`.

**Risk:** Per-crate. Mostly mechanical. Each PR is small and self-contained.

**Acceptance:** Every crate's tests pass with and without the `snapshot` feature. No `pub fn save_state` remains anywhere outside `simrs-snapshot`.

### Phase 4: Update top-level consumers (`simrs-fuzz`, `simrs-hle`)

- `simrs-fuzz`'s `Cargo.toml` enables `snapshot` on its consumer crates.
- Fuzz harness migrates from `vm.save_state(&mut buf)` / `vm.restore_state(&buf[..n])` to `let snap = vm.snapshot(); vm.restore(&snap)?;`.
- `simrs-hle`'s C ABI surface (which currently exposes `simrs_hle_snapshot_save` / `simrs_hle_snapshot_restore`) updates to wrap `Snapshot::as_bytes` / `Snapshot::from_bytes` -- the C side still gets a byte buffer, but the Rust side handles the opacity.

**Risk:** Low. These are the leaf consumers; once Phases 1-3 land, this is just rewiring.

### Phase 5: Cleanup

- Remove the deprecated `Snapshot` trait alias from Phase 1.
- Update `docs/architecture/README.md` and `docs/standards/06-globalplatform.md` to describe the new architecture.
- Add a "Snapshot architecture" section to crate-level docs.
- This ADR transitions to **Status: Accepted**.

---

## Per-crate impact summary

| Crate | Types affected | Public-API break? | Migration |
|-------|---------------|--------------------|-----------|
| `simrs-snapshot` | `Snapshot` trait | New stable API | New module |
| `simrs-fs` | `FsData` | Yes (visibility) | Add `Snapshotable` impl |
| `simrs-pin` | `PinManager` | Yes | Same |
| `simrs-iso7816` | `ResponseQueue` | Yes | Same |
| `simrs-proactive` | `ProactiveState` | Yes | Same |
| `simrs-jcre` | `TransactionJournal` | Yes | Same |
| `simrs-jcvm` | `JcVM`, `ObjectHeap`, `Package`, `TransactionJournal`, `JcVMApplet` | Yes | Already-extended save/restore (commit e0b8faf) wraps in opaque type |
| `simrs-gp-keys` | `KeyStore` | Yes | Same |
| `simrs-gp-open` | `GpOpen`, `Registry` | Yes | Same |
| `simrs-gp-card` | `GpCard` | Yes | Same |
| `simrs-gsm` | `GsmApp` | Yes | Same |
| `simrs-usim` | `UsimApp` | Yes | Same |
| `simrs-sim` | `Sim` | Yes (Snapshotable trait already there) | Replace existing trait with new one |
| `simrs-milenage` | `MilenageParams` | Yes | Same |
| `simrs-tuak` | `TuakParams` | Yes | Same |
| `simrs-fuzz` | n/a (consumer) | Internal change | Rewire to opaque API |
| `simrs-hle` | C ABI | No (transparent) | Wrap Snapshot in C-side byte buffer |

---

## Test strategy

1. **Byte-format compatibility test.** A precomputed snapshot from before this ADR (a fixture `tests/fixtures/jcvm_snapshot_v1.bin`) restores cleanly into a post-ADR `JcVM` with `--features snapshot`. The version header lets us make this strict: snapshot version (1, 0) resolves; (2, 0) future-format would fail with `VersionMismatch`.

2. **Without-feature build test.** Each consumer crate has `#[cfg(not(feature = "snapshot"))]` test that asserts `Snapshotable` is not implemented for the type (or that `snapshot()` doesn't compile). Runs in CI with the bare feature set.

3. **Cross-type rejection test.** Producer-tag mismatch -- a `Sim` snapshot fed to `JcVM::restore` returns `SnapshotError::ProducerMismatch` rather than corrupting state.

4. **End-to-end fuzz round-trip.** `simrs-fuzz` runs a snapshot-mutate-restore-execute loop over the new opaque API, verifying that mutations applied to the same logical state produce the same coverage.

5. **Mid-execution snapshot test.** With the full-state save/restore landed in commit `e0b8faf`, a test can: execute partway via a (future) `step()` API, snapshot, restore in fresh VM, continue, verify identical to no-snapshot run. This is **post-stepping-API** work; calling out here so we don't accidentally regress `e0b8faf` while doing the relocation.

---

## Open questions

1. **Should `Snapshot` be `Box<[u8]>` or `Vec<u8>`?** `Box<[u8]>` is smaller (no capacity field) and reflects the immutable nature of a snapshot. `Vec<u8>` is more flexible. Lean `Box<[u8]>`.

2. **Should `as_bytes()` exist publicly?** It enables on-disk persistence (which `simrs-fuzz` and the snapshot-on-disk story need) but technically leaks the byte representation. Mitigation: documented as "for storage; do not parse"; the version header makes parsing pointless to consumers since the format is opaque.

3. **Versioning granularity.** Per-type versioning (each implementor manages its own version) vs. workspace-global version. Per-type is more flexible; workspace-global simplifies migration. Lean per-type.

4. **Should Phase 1 land first as a no-op?** Pro: lets us iterate on the trait API before committing to migration. Con: an ADR'd-but-unused trait sits in the codebase for a window. Lean yes -- land it, write tests, get the shape right before touching consumer crates.

5. **Should we use `Result<usize, SnapshotError>` for the raw `pub(crate) fn save_state_internal`?** Currently it's `usize` with 0-on-failure. Sticking with the current shape preserves byte-level compatibility and keeps Phase 2-3 mechanical.

---

## Decision record

[Open] -- awaiting user review of the plan before Phase 1 lands.

When accepted, this ADR transitions to **Status: Accepted** and the migration sequence above governs the implementation order.
