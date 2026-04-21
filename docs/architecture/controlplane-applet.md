# simrs-controlplane: Test-only Introspection Applet

## Purpose

A JavaCard-compatible applet and Rust counterpart that expose simrs
internals (JCVM state, JCRE heap accounting, PRNG seed, fault
injection hooks) via proprietary APDUs so they become reachable from
the differential harness. The applet runs on simrs and on each
reference backend (Oracle `jcsl`, martinpaljak `JCardEngine`), which
lets differential tests compare their semantics at the same APDU
surface instead of at internal Rust/Java boundaries.

The applet ships only in test/dev profiles. It is not present in the
`release` workspace profile and is excluded from production `.cap`
and packaging artifacts.

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

All commands share the shape `80 F0 <P1> <P2> <Lc> <data> <Le>`.
Responses are BER-TLV with category-specific nested tags, or a bare
SW where no payload is meaningful.

| P1   | Category          | Operations (P2)                                             |
|------|-------------------|-------------------------------------------------------------|
| 0x01 | JCVM state        | 0x00 get opcode-count vector; 0x01 get method-depth history |
| 0x02 | JCRE heap         | 0x00 get persistent bytes used; 0x01 get transient bytes    |
| 0x03 | Fault injection   | 0x00 throw `NullPointerException`; 0x01 force SW `6F 00`    |
| 0x04 | PRNG control      | 0x00 seed PRNG (Lc=8); 0x01 read next N bytes (Le=N)        |
| 0x05 | Snapshot marker   | 0x00 get counter; 0x01 increment counter (persistent)       |
| 0x06 | Firewall probe    | 0x00 access sibling applet's field, return success flag     |
| 0x07 | Interposer ctrl   | 0x00 start APDU recording; 0x01 stop; 0x02 get record count |
| 0x08 | Misc              | 0x00 ping (echo Lc bytes); 0x01 applet version              |

Status words: `90 00` on success, `6A 86` for unimplemented P1/P2,
`6A 80` for malformed data, `6D 00` for unsupported INS. No
proprietary SWs; all values conform to ISO 7816-4 Table 6 or GP
Table 9-9.

### Response TLV examples

JCVM opcode-count vector (P1=0x01, P2=0x00):

```
C0 <len>
  C1 02 <aload count: u16 BE>
  C2 02 <areturn count>
  C3 02 <invoke count>
  ...
```

PRNG seed ack (P1=0x04, P2=0x00, Lc=8):

```
90 00      # no payload; the seed has been installed
```

Firewall probe result (P1=0x06, P2=0x00):

```
C0 <len>
  C1 01 <success: 0x01 access permitted / 0x00 SecurityException>
  C2 04 <thrown exception class hash: u32 BE if blocked>
```

## Implementation Layout

Two co-ordinated deliverables, same AID and command semantics:

### `crates/simrs-controlplane` (Rust)

Actual Phase-A layout that landed:

```
crates/simrs-controlplane/
├── Cargo.toml              # deps: simrs-transport, simrs-iso7816
├── src/
│   ├── lib.rs              # public re-exports
│   ├── aid.rs              # CONTROLPLANE_AID constant + matcher
│   ├── protocol.rs         # CLA/INS/Category enum + status words
│   ├── applet.rs           # AppletState + ControlplaneApplet (dispatch)
│   ├── card.rs             # ControlplaneCard<Inner: Transport> wrapper
│   └── probes/
│       ├── mod.rs
│       └── ping.rs         # P1=0x08 ping + version (Phase B.1)
└── tests/                  # integration tests go here as probes land
```

Integration is via composition, not a feature flag. Tests wrap any
existing [`Transport`] in a `ControlplaneCard`; the wrapper
intercepts SELECT for `CONTROLPLANE_AID` and routes subsequent APDUs
to the applet while it is selected. SELECTs to any other AID
deselect the applet and forward unchanged to the inner transport.
This keeps production crates (`simrs-gp-card`, reference clients)
unmodified -- the control plane adds zero production surface and no
feature-flag maintenance burden.

Future probe modules (one file per `P1` category) will extend
`probes/`: `jcvm_state.rs`, `heap_probe.rs`, `fault.rs`, `prng.rs`,
`snapshot_marker.rs`, `firewall_probe.rs`, `interposer_hook.rs`.
Deeper probes that need introspection hooks (JCVM opcode counting,
JCRE heap accounting) require adding test-only APIs to
`simrs-jcvm` / `simrs-jcre`; the wrapper itself never touches
production code.

### `tools/controlplane-applet/` (JavaCard `.cap`)

```
tools/controlplane-applet/
├── build.gradle            # ant-javacard or JavaCard toolchain
├── settings.gradle
└── src/main/java/com/simrs/controlplane/
    └── ControlplaneApplet.java
```

`.cap` is produced by Gradle, output copied to
`target/controlplane-applet/controlplane-applet.cap`. Reference
bridges (`tools/jcardengine-bridge`, `tools/simrs-jcsl`) grow a
`--controlplane-cap <path>` CLI flag that LOAD+INSTALLs it before
accepting connections. The `.cap` is deterministic (reproducible
build) so differential tests can hash-verify both sides are running
the same bytecode.

## Integration Points

### simrs crate hooks

| Probe             | Crate                 | Hook                                                      |
|-------------------|-----------------------|-----------------------------------------------------------|
| Opcode counters   | `simrs-jcvm`          | Increment per-opcode counter in dispatch loop (cfg-gated) |
| Method-depth      | `simrs-jcvm`          | Record call-stack depth on `invokestatic`/`return`        |
| Persistent bytes  | `simrs-jcre`          | Track `Applet.register` allocations                       |
| Transient bytes   | `simrs-jcre`          | Track `JCSystem.makeTransient*Array` allocations          |
| Fault injection   | `simrs-jcvm`          | Raise `ISOException` / set SW on next dispatch boundary   |
| PRNG seed         | `simrs-*` (every rng) | Thread-local seed-override hook                           |
| Snapshot marker   | `simrs-gp-card`       | Persistent EF at application-owned path                   |
| Firewall probe    | `simrs-jcre`          | Invoke cross-context field access, catch exception        |
| Interposer toggle | `simrs-interposer`    | Expose start/stop via test-only API                       |

### Reference backend hooks

JCardEngine exposes JCVM + JCRE APIs through standard JavaCard SPIs
(`javacard.framework.JCSystem`, `JavacardEngine` interface). The Java
applet uses those to implement the same commands. jcsl does not
expose most internals -- the applet will respond `6A 86` for
introspection commands it cannot service against jcsl, which is
cataloged as a known divergence (jcsl has narrower observability
than simrs/jcardengine by design).

## Testing Strategy

1. **Rust unit tests in `simrs-controlplane`** -- matrix of P1/P2
   combinations against the native impl. No JVM, no external process.

2. **Differential parity test** -- new row in
   `tests/simrs-differential-crossvalidation/tests/report_gen.rs`:
   SELECT control-plane AID, ping (P1=0x08 P2=0x00), assert equal
   responses across simrs and JCardEngine. jcsl skips (cataloged).

3. **BDD scenarios** -- new feature file
   `tests/simrs-globalplatform-conformance-validation/features/controlplane.feature`
   exercising each P1 category at the protocol level. @wip until
   step defs catch up with implementation.

4. **Reproducibility check** -- CI job hashes the generated `.cap`
   and fails if it diverges from the committed hash. Prevents silent
   drift between reference runs.

## Phased Rollout

| Phase | Scope                                                                    | Effort |
|-------|--------------------------------------------------------------------------|--------|
| A     | Scaffolding: crate skeleton, AID const, dispatch stubs, feature flag     | ~day   |
| B.1   | P1=0x08 (ping/version) end-to-end on simrs + jcardengine                 | ~day   |
| B.2   | P1=0x05 (snapshot marker) + P1=0x04 (PRNG seed)                          | ~day   |
| B.3   | P1=0x02 (heap probe) + P1=0x01 (JCVM state) -- needs deeper JCVM hooks   | ~2-3 days |
| B.4   | P1=0x03 (fault injection) + P1=0x06 (firewall probe)                     | ~2 days  |
| B.5   | P1=0x07 (interposer control) + differential parity row                   | ~day   |
| C     | Promote BDD scenarios from @wip to running; add reproducibility hash job | ~day   |

Phase A gates everything else; phases B.x are independent and can
ship in any order.

## Security Considerations

- The applet IS an attack surface. If accidentally shipped to a
  production-profile build, it would let any terminal read PRNG
  state, trigger faults, and inspect applet memory. Enforce
  exclusion at three layers: (1) `simrs-controlplane` has no entry
  in the `release` profile member list, (2) CI gating on a
  `no-controlplane` workspace profile that greps the built artifact
  for the AID, (3) the Gradle `.cap` build is only run from a
  feature-flagged test task.

- Snapshot marker uses a persistent EF but writes are idempotent and
  audit-logged via the interposer probe so snapshot-restore tests
  cannot use it to smuggle state into production captures.

- Firewall probe deliberately attempts cross-context access. Any
  test using it must be quarantined to the dev/test profile; a
  production-build CI guard refuses to compile if
  `firewall_probe.rs` is on the reachable module tree.

## Open Questions

1. **jcsl coverage**: jcsl's binary-patch configurator does not let
   us install new applets at runtime. The options are (a) a jcsl
   patch that preloads the control-plane `.cap` (significant
   reverse-engineering work), (b) running differential tests with
   jcsl only on commands the control-plane applet doesn't require,
   or (c) dropping jcsl from control-plane-aware rows. Pick (b) for
   v1; revisit if jcsl-side observability becomes urgent.

2. **PRNG seed scope**: Thread-local vs process-wide. Thread-local
   avoids breaking parallel tests but requires every rng consumer in
   simrs to thread the seed through. Process-wide is one line per
   call site but serialises tests. Lean thread-local, accept the
   refactor cost.

3. **`.cap` reproducibility**: the JavaCard toolchain injects
   timestamps. Need `SOURCE_DATE_EPOCH` + custom Manifest stripping
   to get a byte-identical `.cap` across machines.
