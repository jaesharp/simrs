# 10 — Report Model

A `Report` is the execution artefact for one `CaseQuery` run against
one frontend. It is serialisable, human-readable, machine-diff-able,
and the single input to the Diff Engine.

## Shape

Reports are flat at the step level but layered within each step.
Each step is a synchronisation anchor: all frontends that ran the same
case produce a step with the same `StepId`, with per-frontend
`World` views, per-frontend `Transform` (what APDUs the frontend
actually executed to realise the step's intent), and per-frontend
`Observation` traces (the raw evidence).

```rust
pub struct Report {
    pub case: CaseQuery,
    pub frontend: FrontendId,
    pub claims: Vec<ClaimedStandard>,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub steps: Vec<Step>,
    pub provenance: RunProvenance,
}

pub struct Step {
    pub id: StepId,
    pub world_before: World,
    pub transform: Transform,
    pub world_after: World,
    pub observations: Vec<Observation>,
    pub duration: Duration,
    pub outcome: StepOutcome,
}

pub enum StepOutcome {
    Completed,
    Skipped { reason: SkipReason },
    Errored { error: StepError },
}
```

## World as semantic state

`World` is the abstract state of the card at a step boundary. It is
not a byte blob of the card's internal memory; it is a typed
projection capturing the observable semantics that matter for diffing
at a semantic level.

```rust
pub struct World {
    views: Vec<Box<dyn WorldView>>,
}

pub trait WorldView: Any + Debug + Send + Sync {
    fn fields(&self) -> &[WorldField];
    fn get(&self, field: &WorldField) -> Option<WorldValue>;
    fn merge(&mut self, other: &dyn WorldView);  // for multi-source composition
}
```

Spec crates contribute implementations:

- `GpWorldView` — selected app, ISD lifecycle, SCP session state, key-set state
- `IsoWorldView` — logical channels, FCI state, shareable interface state
- `SimWorldView` — USIM AKA state, PIN retry counters, file tree
- `HarnessWorldView` — probe counters, rng state, snapshot markers

At runtime, each scenario's step returns a `World` assembled from
the frontend-driver's view contributions. Diff compares field-by-field
across frontends' `World`s at each step.

## Transform: what the frontend actually did

```rust
pub struct Transform {
    pub actions: Vec<Action>,
}

pub enum Action {
    PowerOn,
    PowerOff,
    Reconnect,
    Apdu(Vec<u8>),
    ScpInitUpdate { host_challenge: [u8; 8] },
    ScpExternalAuth { host_cryptogram: Vec<u8>, cmac: Vec<u8> },
    MacCommand { cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8> },
    ProbeRead(ProbeId),
    Wait(Duration),
    Custom(Arc<dyn ActionImpl>),
}
```

Transforms differ across frontends for the same step. At step
"OPEN_SCP_SESSION", simrs may produce `[InitUpdate, ExternalAuth(SCP02
crypto)]`; jcsl produces `[InitUpdate, ExternalAuth(SCP03 crypto)]`.
The transform is not diffed directly — it is *evidence* for the world
transition. The classifier can reach into it when a rule requires
fine-grained assertion.

## Observations

```rust
pub struct Observation {
    pub at: Timestamp,
    pub kind: ObservationKind,
    pub payload: ObservationPayload,
}

pub enum ObservationKind {
    ApduExchange,
    AtrReceived,
    FaultInjected,
    ProbeRead,
    SideChannel,
    Timing,
    LogLine,
}

pub enum ObservationPayload {
    Apdu { command: Vec<u8>, response: Vec<u8>, sw: Sw },
    Atr(Vec<u8>),
    Probe { id: ProbeId, response: Vec<u8> },
    Timing { start: Timestamp, end: Timestamp },
    Log { level: LogLevel, message: String },
    Bytes(Vec<u8>),
}
```

Observations are the raw evidence of what happened. Rules can match
on observation content directly when needed:

```rust
.guard(predicate::function(|d: &Divergence| {
    d.any_observation(|obs| match &obs.payload {
        ObservationPayload::Apdu { sw, .. } => *sw == Sw(0x6A, 0x82),
        _ => false,
    })
}))
```

## Serialisation

Reports serialise to JSON or CBOR. The schema is stable — downstream
tooling (book generator, external dashboards, CI aggregators) depends
on it. The schema is versioned independently from the kernel (a
report from Phase A's engine can be read by Phase C's engine via
migrations).

```
reports/
├── run-2026-04-21T14-02-11Z/
│   ├── manifest.json                # run metadata, participating frontends
│   ├── simrs/
│   │   ├── select_unknown_aid/
│   │   │   ├── case-00.json         # (scenario, case, frontend) → Report
│   │   │   └── case-01.json
│   │   └── …
│   ├── jcsl/…
│   └── jcardengine/…
```

Per-case reports are file-per-case to keep diffs reviewable in git
when committed as CI artefacts.

## Provenance

```rust
pub struct RunProvenance {
    pub engine_version: &'static str,
    pub spec_crate_versions: BTreeMap<SpecId, Version>,
    pub frontend_versions: BTreeMap<FrontendId, String>,
    pub host_env: HostEnvironment,
    pub cfg_assignment: CfgAssignment,
    pub rng_seed: Option<u64>,
}
```

Everything needed to reproduce the run, subject to determinism of the
frontends themselves.

## Report equivalence and normalisation

For diffing, reports are normalised:

- Timestamps are monotonically re-sequenced (relative to run start).
- Byte-order within a field is canonicalised where the spec allows
  multiple encodings.
- Non-determinism sources (random challenges, session IDs) are either
  zeroed or replaced with their `axis`-derived canonical values.

Normalisation rules are themselves ADR-governed — they are normative
decisions about what counts as "equivalent behaviour."
