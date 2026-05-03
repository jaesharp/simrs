# simrs-controlplane: Hypervisor-style Introspection Surface

A test-only JavaCard applet + Rust counterpart that gives a simrs card
a dom0-style management interface. Production builds compile without
it; test builds wrap any `Transport` in a `ControlplaneCard` to get a
proprietary APDU surface (`CLA=80 INS=F0`) for observing and
perturbing the card under test.

This document is the architectural overview. Source of truth is the
code in `crates/simrs-controlplane/`, `crates/simrs-jcvm/src/hypervisor.rs`,
and `crates/simrs-jcvm/src/ring_buffer.rs`.

## Mental Model

simrs is already doing hypervisor-shaped work: the JCVM schedules
between applets, enforces JavaCard firewall isolation, mediates
persistent and transient memory, captures snapshots. The control-
plane applet names the asymmetry of privilege explicitly.

| Virtualization term | simrs analogue                                                      |
|---------------------|---------------------------------------------------------------------|
| Hypervisor          | `simrs-jcvm` + `simrs-jcre` + `simrs-gp-card` (the simulator core)  |
| Guest VM            | An installed applet (GP ISD, USIM, OpenPGP, ...)                    |
| Dom0                | The control-plane applet -- privileged, test-only                   |
| Hypercall           | A proprietary APDU (`80 F0 ...`) from dom0 into the hypervisor      |
| Hypertrap           | Hypervisor-originated injection (e.g. fault-arm into the next APDU) |
| Hyperstack          | Stack frames used by dom0 while servicing hypercalls                |
| DomU / guest stack  | The JCVM's own operand/frame/local stacks for an applet             |

VM stacks are *windowed*: the JCVM already keeps per-applet stacks
isolated. Dom0 reaches into the hypervisor through APDUs rather than
through shared stack frames, so there is no "context switch" between
running a guest command and answering a hypercall. This is why no
pause/resume primitive is needed -- the hyperstack is already
separate by construction.

### Null hypervisor

The default shape is the *null hypervisor*: a hypervisor whose hooks
add no observable side effects to the guest. simrs is always a null
hypervisor -- it tracks counters and events unconditionally and holds
them in fixed-size storage. The only thing gated by a feature flag is
whether downstream crates can *read* them. Feature-on and feature-off
builds execute the exact same stores on the dispatch hot path, so a
test cannot fingerprint the configuration by timing.

This follows from a simple rule: the guest must not be able to
distinguish between a null hypervisor and a control-plane-instrumented
hypervisor. Paravirtualization -- "guest knows it's virtualised" --
is explicitly rejected.

## Identifiers

| Field                     | Value                                 |
|---------------------------|---------------------------------------|
| Applet AID                | `A0 00 00 00 62 FF 00 01`             |
| Package AID               | `A0 00 00 00 62 FF 00`                |
| Class AID                 | same as applet AID                    |
| Selection CLA             | `00`                                  |
| Command CLA (post-select) | `80` (proprietary)                    |
| Command INS               | `F0`                                  |

AID breakdown: `A0 00 00 00 62` is the RID for "Java Card for Open
Platform" (ISO/IEC 7816-5 registered). Trailing `FF` marks the PIX as
reserved-for-test-use; `00 01` is the control-plane applet's instance
discriminator. Coexists with production applets without collision.

## APDU Surface

Commands share the shape `80 F0 <P1> <P2> <Lc> <data> <Le>`. `P1`
selects a probe category; `P2` sub-selects the operation. Status
words conform to ISO 7816-4 Table 6 / GP Table 9-9 -- no proprietary
SWs.

| P1   | Category          | Capability gating       | Status             |
|------|-------------------|-------------------------|--------------------|
| 0x01 | `JcvmState`       | `InspectJcvmState`      | landed (snapshot)  |
| 0x02 | `JcreHeap`        | `InspectJcreHeap`       | stub (`6A 86`)     |
| 0x03 | `FaultInjection`  | `InjectFault`           | landed             |
| 0x04 | `Prng`            | `UsePrng`               | landed             |
| 0x05 | `SnapshotMarker`  | `UseSnapshotMarker`     | landed             |
| 0x06 | `FirewallProbe`   | `ProbeFirewall`         | stub               |
| 0x07 | `InterposerCtrl`  | `ControlInterposer`     | stub               |
| 0x08 | `Misc`            | `Liveness`              | landed             |
| 0x09 | `NestedCard`      | `NestCards` on FORWARD  | landed (1 slot)    |

Each category has its own submodule in
`crates/simrs-controlplane/src/probes/`; dispatch is a flat match in
`ControlplaneApplet::process`. Stubs return `6A 86` so tests can
distinguish "not yet wired" from "CLA/INS wrong".

Status words emitted by the dispatcher:

| SW      | Meaning                                                 |
|---------|---------------------------------------------------------|
| `90 00` | Success                                                 |
| `67 00` | Wrong length (header truncated, Lc overruns buffer)     |
| `69 82` | Security status not satisfied (capability dropped)      |
| `69 85` | Conditions of use not satisfied (e.g. no nested card)   |
| `6A 80` | Incorrect parameters in data field                      |
| `6A 86` | Incorrect P1/P2 (unknown category or sub-op)            |
| `6D 00` | INS not supported (CLA matches but INS differs)         |
| `6E 00` | CLA not supported                                       |

## Architectural Components

The crate is organised around five concerns:

1. **Null hypervisor observation** -- counters + event ring buffer
   in `simrs-jcvm`, always-on, feature-gated public access.
2. **Capabilities** -- per-handle rights that gate handle-crossing
   operations; monotonic drops; primitive for IFS policies.
3. **Timing domains** -- the scaffolding for cross-domain data-flow
   enforcement (types live today, enforcement is v2).
4. **Nested cards** -- dom0 can host an inner card, forward APDUs to
   it, drop capabilities on the handle; recursive composition.
5. **Probes** -- one module per P1 category, dispatched by
   `ControlplaneApplet`.

Each gets a section below.

## Null-hypervisor Observation

### Counters

`simrs-jcvm::JcVM` carries three unconditionally-maintained fields:

- `opcode_counts: [u64; 256]` -- per-opcode execution histogram.
- `total_instructions: u64` -- lifetime monotonic counter.
- `max_frame_depth: u32` -- high-water mark of `frame_ptr` observed
  across the VM's lifetime, updated via branchless `u32::max`
  (lowers to a `cmov`).

These are written in the dispatch loop (`run`) and invoke path
(`push_call_frame`), then pinned via `pin_observation(&field)` --
a `#[inline(always)] const fn` wrapper around `core::hint::black_box`
-- so the stores are preserved even when the `controlplane-hooks`
feature is off and no public accessor reads them.

### Hypervisor trait

`simrs-jcvm::hypervisor::Hypervisor` (gated on `controlplane-hooks`)
exposes the counters through a trait:

```rust
pub trait Hypervisor {
    fn opcode_counts(&self) -> [u64; 256];
    fn total_instructions(&self) -> u64;
    fn max_frame_depth(&self) -> u32;
    fn reset_counters(&mut self);
}
```

`JcVM` implements it. `NullHypervisor` is a zero-returning stub used
by harness code that drives a reference backend (jcsl, `JCardEngine`)
where no live JCVM exists to introspect.

Downstream consumers (`simrs-controlplane::probes::jcvm_state`) read
through the trait, not the concrete type, so the probe works against
any hypervisor impl including fake/null ones.

### Event ring buffer

`simrs-jcvm::ring_buffer::RingBuffer<const N: usize>` is a static,
no-alloc, single-producer/single-consumer ring. `N` must be a power
of two; wrap via bitmask. Storage is plain `[Event; N]` with
`Event::EMPTY` sentinels -- no `unsafe` (the crate forbids it).

```rust
pub enum Event {
    OpcodeExecuted(u8) = 0x01,
    MethodEntered { pkg, method } = 0x02,
    MethodReturned { pkg, method } = 0x03,
    CounterSnapshot { total_instructions: u64 } = 0x04,
    Uninitialised = 0x00,
}
```

Overwrite-on-full semantics: the producer never blocks; the reader's
`tail` auto-advances so `len()` never exceeds `N`. Single-threaded
within a JcVM, so atomics are avoided.

**Guest invisibility**: the guest never sees the ring buffer. Push
is unconditional and data-oblivious; filtering and drain policy are
hypervisor concerns applied on the *reader* side. This preserves the
null-hypervisor contract -- the guest can't distinguish runs where
dom0 is consuming events from runs where nothing is.

## Capabilities

Each `NestedCardHandle` carries a `CapabilitySet`: a typed bitmask of
which probe categories are reachable through *that handle*. The types
live in `crates/simrs-controlplane/src/capability.rs`:

```rust
pub enum Capability {
    InspectJcvmState, InspectJcreHeap, InjectFault, UsePrng,
    UseSnapshotMarker, ProbeFirewall, ControlInterposer, Liveness,
    NestCards,
}
pub struct CapabilitySet(/* private u32 */);
```

`CapabilitySet` exposes `full()`, `empty()`, `contains`, `drop`,
`drop_all`, `single`, `union` -- all `const fn` where possible, and
the raw `u32` is never exposed. Every operation returns a new value
(the set is `Copy`), so "drop on one copy doesn't affect the other"
is a type-system property, not a runtime invariant.

Capabilities apply to **handle-crossing operations** -- today this
means `NestedCard::FORWARD`. Self-inspection probes (ping, PRNG,
snapshot marker, fault injection on the same applet) are not
handle-mediated and therefore not gated: the caller of the probe is
the same party whose state is being read or modified, so there is
no privilege boundary to enforce. When a probe grows a handle-
mediated variant (e.g. shared-applet-state multi-handle mode), its
dispatcher arm gains the corresponding `contains` check.

### Monotonic drop

Drops are one-way. `CapabilitySet::drop(self, cap) -> Self` is
defined as `self & !cap.bit()`; no operation grants. This lets a
host application hand out a fully-privileged handle, fork off a
reduced handle for untrusted code, and be sure the reduced handle
cannot regain rights (not even with the cooperation of the
hypervisor it's talking to -- the drop is a value-level operation).

### Information flow security

Two handles to the same card can carry different capability sets.
The host keeps the privileged handle for bootstrap and audit; hands
out the reduced handle to the subsystem that processes untrusted
data. Any compromise of the reduced subsystem cannot climb back up
to the privileged handle -- the capability bits are simply absent.

Today the simrs implementation uses independent handles (each
`NestedCardHandle` owns its own inner card). "Two handles, one
card" via `Rc<RefCell<...>>` is planned but not implemented. The
value-level IFS guarantee is identical either way; the
implementation choice is about storage sharing, not about the rule.

## Timing Domains

Scaffolding in `crates/simrs-controlplane/src/timing_domain.rs`.
Types exist, dispatcher enforcement is future work.

```rust
pub struct TimingDomain(NonZeroU32);
pub struct DomainEdge { source: TimingDomain, sink: TimingDomain }
```

Motivating rule: constant-time guarantees are only meaningful
relative to an observer. A nested VM that shares timing-sensitive
secrets with another VM must execute secret-dependent code CT
relative to that peer; a VM in a distinct timing domain need not.
The graph of allowed flows is the `DomainEdge` set the hypervisor
sanctions.

### Planned v2 enforcement

1. Every handle is assigned a `TimingDomain` on creation.
2. `FORWARD` (and any future cross-domain operation) checks that the
   source/sink edge exists in the graph before forwarding.
3. Operations that would cause a non-sanctioned flow return
   `69 82` (`SECURITY_NOT_SATISFIED`).
4. A CT measurement test verifies operations in one domain don't
   leak timing to any domain that isn't transitively a sink.

### Why this can stay scaffolded

The capability model already enforces a coarse-grained flow rule:
no `FORWARD` without `NestCards`. Timing domains refine that into a
graph where `FORWARD` may be allowed structurally but must verify
its target is connected. We have the capability gate now; the
domain-graph overlay is additive.

## Nested Cards

The `NestedCard` probe (P1=0x09) lets dom0 host an inner card and
forward APDUs to it. Sub-ops:

| P2   | Name       | Data              | Effect                                    |
|------|------------|-------------------|-------------------------------------------|
| 0x00 | `SPAWN`    | empty             | Create an inner `ControlplaneCard`        |
| 0x01 | `DESTROY`  | empty             | Drop the inner card                       |
| 0x02 | `FORWARD`  | APDU bytes        | Route to inner, returns inner's response  |
| 0x03 | `DROP_CAP` | `Capability` byte | Monotonically drop a cap on the handle    |

`FORWARD` wraps the inner response as the outer's response *data*
and returns `90 00` as the outer SW. This keeps the nesting
boundary observable: the terminal always knows whether the reply
came from the outer or the inner, and inner failures don't
masquerade as outer failures.

Today the inner card is hard-coded to
`ControlplaneCard<NullTransport>` (a second-level control-plane
wrapping an always-`9000` stub). Enough for a composition test;
swapping in a real `GpCardTerminal` is a type-level change.

### Recursive composition

`ControlplaneCard<Inner>` implements `Transport` iff `Inner` does,
so `ControlplaneCard<ControlplaneCard<X>>` is a valid type. The
SELECT-interception logic lets the outer capture APDUs for its own
applet while forwarding everything else to the inner. Deep stacks
(root -> A/B -> A1/A2/B1/B2 -> GP SIM) work in principle; the
current implementation supports one slot per applet, so the 4-leaf
tree requires multi-slot storage (queued as follow-up).

### Snapshot / rewind

Planned but not implemented. Each `NestedCardHandle` would carry an
optional snapshot (a clone of the inner card); `SNAPSHOT` captures
the current state; `REWIND` restores it. Requires the inner card
type to be `Clone`. Since `Box<dyn Transport>` isn't `Clone`, a
`NestedCardTrait: Transport + BoxClone` marker would be added.

## Constant-time Discipline

### Feature-on / feature-off equivalence

`simrs-jcvm` counter updates are unconditional -- the
`controlplane-hooks` feature only gates the public trait and
accessors. `pin_observation` prevents DCE so both feature
configurations execute the same stores on the dispatch hot path.
Tests therefore cannot fingerprint the configuration from timing;
a future CT measurement test will make this an empirical guarantee
(a fixed workload timed under both configs, asserted equal within
tolerance).

### Branchless primitives where possible

- `max_frame_depth` update uses `u32::max` (branchless `cmov`).
- `CapabilitySet::drop` is pure bitwise; no branch.
- `CapabilitySet::contains` is a bit-extract; the boolean return
  currently lowers to a branch at the call site. Upgrading to a
  CT-typed `Choice` return (à la `subtle`) is planned before the
  probe surface starts consuming handle-scoped secrets.

### Secret / redact interaction

Probes that can materialise bytes from secret-tagged storage must
route through `simrs-redact` before handing them to dom0. Not yet
needed (the landed probes expose only public state), but gated in
the design so `JcreHeap` and `FirewallProbe` land with the
redaction boundary intact.

## Implementation Layout

### `crates/simrs-controlplane`

```
crates/simrs-controlplane/
├── Cargo.toml              # deps: simrs-transport, simrs-iso7816
├── src/
│   ├── lib.rs              # re-exports
│   ├── aid.rs              # CONTROLPLANE_AID + matcher
│   ├── applet.rs           # AppletState + ControlplaneApplet
│   ├── capability.rs       # Capability / CapabilitySet
│   ├── card.rs             # ControlplaneCard<Inner: Transport>
│   ├── protocol.rs         # CLA/INS/Category enum + SW constants
│   ├── timing_domain.rs    # TimingDomain / DomainEdge scaffolding
│   └── probes/
│       ├── mod.rs
│       ├── fault.rs
│       ├── jcvm_state.rs
│       ├── nested_card.rs  # probe + NestedCardHandle + NullTransport
│       ├── ping.rs
│       ├── prng.rs
│       └── snapshot_marker.rs
```

### `crates/simrs-jcvm` additions

- `hypervisor.rs` (feature `controlplane-hooks`) -- `Hypervisor`
  trait + `NullHypervisor` + `impl Hypervisor for JcVM`.
- `ring_buffer.rs` -- always compiled; the ring is the transport
  for whichever events the hypervisor chooses to emit.
- `pin_observation` helper at crate root.
- `JcVM` gains counter fields (unconditional) and feature-gated
  public accessors (`opcode_counts`, `total_instructions`,
  `max_frame_depth`, `reset_controlplane_counters`).

### `tools/controlplane-applet/` (planned)

Gradle project producing a `.cap` file that, once LOADED+INSTALLED
into a reference backend bridge, answers the same APDU surface.
Not yet started; the Rust side runs standalone today because
`ControlplaneCard<Inner>` composes with any `Transport`.

## Testing Strategy

1. **Rust unit tests** in `simrs-controlplane` --
   matrix of P1/P2 across every landed probe, plus capability
   semantics, AID matching, protocol constants, ring buffer
   behaviour.
2. **Feature-on / feature-off parity** in `simrs-jcvm` (361 vs 364
   lib tests) -- the three new hypervisor-trait tests appear only
   when `controlplane-hooks` is on; the rest of the test suite
   runs identically under both configs.
3. **Differential parity** -- the `report_gen.rs` matrix will
   eventually grow a row that SELECTs the control-plane AID and
   runs the ping probe, comparing simrs vs `JCardEngine` responses.
   jcsl cell will skip (cataloged as J-entry) until a jcsl-side
   `.cap` installer is available.
4. **BDD** -- a `features/controlplane.feature` file will exercise
   the probe surface from the terminal side. `@wip` until step
   defs catch up with implementation.
5. **CT measurement** -- release-mode microbenchmark comparing
   dispatch-loop timing with and without the `controlplane-hooks`
   feature, asserting equivalence within noise-floor tolerance.

## Phased Rollout

| Phase | Scope                                                                    | Status |
|-------|--------------------------------------------------------------------------|--------|
| A     | Scaffolding: crate, AID, dispatch, `ControlplaneCard<Inner>` wrapper     | done   |
| B.1   | `Misc` ping + version                                                    | done   |
| B.2   | `SnapshotMarker` + `Prng`                                                | done   |
| B.3   | `FaultInjection` (arm/disarm + fault-bypass for DISARM)                  | done   |
| B.4   | `JcvmState` snapshot-based + JCVM-side counter hooks + `Hypervisor` trait | done   |
| B.5   | `NestedCard` single-slot spawn/forward/destroy + `DROP_CAP`              | done   |
| C.1   | Ring buffer transport + `Event` enum + unconditional push points         | transport only |
| C.2   | Multi-slot nesting + snapshot/rewind + leaf `Transport` with state       | pending |
| C.3   | `JcreHeap`, `FirewallProbe`, `InterposerCtrl` probes                     | pending |
| C.4   | Timing-domain enforcement (graph + cross-domain FORWARD check)           | pending |
| C.5   | CT measurement test landing                                              | pending |
| D     | Java `.cap` produced by `tools/controlplane-applet/`                     | pending |
| E     | Differential parity row + BDD scenario promotion                         | pending |

## Security Considerations

- **Production exclusion**: `simrs-controlplane` is a workspace
  member with `publish = false`. The `controlplane-hooks` feature
  on `simrs-jcvm` gates the public hypervisor surface. A
  `no-controlplane` CI profile should grep the built artifact for
  the AID to catch accidental inclusion; not yet wired.
- **Capability drop as IFS primitive**: the "two handles, one
  privileged, one reduced" pattern documented above. Capability
  bits are `Copy` values, so a compromised reduced-handle cannot
  request a re-grant -- the hypervisor has no capability-raise API.
- **Fault injection single-shot**: the arm fires on the next
  *guest* command and clears itself. The `FaultInjection` category
  itself bypasses the arm so dom0 can always reach `DISARM` to
  recover from a wedged arm (`qemu-monitor inject-nmi` semantics).
- **Snapshot marker**: persistent-style counter exposed for
  snapshot-restore testing. Writes are idempotent and
  append-implicit; can't be used to smuggle state.
- **Firewall probe**: will deliberately attempt cross-context
  access. Landing that probe requires a production-build guard
  that refuses to compile if `firewall_probe.rs` is on the
  reachable module tree of a non-test profile.

## Open Questions

1. **jcsl `.cap` loading**: jcsl's binary-patch configurator does
   not support runtime applet install. Options: (a) jcsl patch
   preloads the control-plane `.cap` at configuration time
   (significant reverse-engineering), (b) jcsl skips the control-
   plane matrix row (catalog as a J-entry), (c) drop jcsl from
   control-plane-aware rows entirely. Leaning (b) for v1.
2. **PRNG seed scope**: thread-local vs process-wide. Thread-local
   survives parallel tests but needs every rng consumer in simrs
   to thread the seed through. Process-wide is one line per call
   site but serialises tests. Lean thread-local, accept the
   refactor cost.
3. **`.cap` reproducibility**: the JavaCard toolchain injects
   timestamps. `SOURCE_DATE_EPOCH` + custom Manifest stripping
   needed for byte-identical `.cap` across machines.
4. **Shared ownership**: "two handles to one card" currently
   needs `Rc<RefCell<_>>` in the handle. Whether that lives in the
   `NestedCardHandle` type or gets pushed into a separate
   `SharedNestedCardHandle` variant is TBD.
5. **`CapabilitySet::contains` CT return type**: swap `bool` for a
   `subtle::Choice`-style mask before probes start gating handle-
   bound secrets.
