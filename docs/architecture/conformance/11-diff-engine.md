# 11 — Diff Engine

The diff engine is a pure function `Vec<Report> → Vec<Divergence>`. It
has no knowledge of reference / shadow roles, no classification logic,
no I/O. Given the same normalised reports it produces the same
divergences in the same order.

## Entry point

```rust
pub struct DiffEngine;

impl DiffEngine {
    pub fn compare(reports: &[Report]) -> Vec<Divergence>;
    pub fn compare_cases(reports: &[Report]) -> BTreeMap<CaseQuery, Vec<Divergence>>;
}
```

`compare` is the total-ordering flat output. `compare_cases` groups by
`CaseQuery` for per-case diff rendering.

## Alignment

Reports are aligned by `(CaseQuery, StepId)`. Reports with mismatched
case keys are considered unrelated and produce no divergences between
them. Reports with aligned cases but differing step sequences produce
`StepMissing` divergences at the mismatching positions.

## Divergence kinds

```rust
pub enum Divergence {
    WorldField {
        case: CaseQuery,
        step: StepId,
        field: WorldField,
        per_report: BTreeMap<FrontendId, WorldValue>,
        agreement: AgreementGroups,
    },
    Observation {
        case: CaseQuery,
        step: StepId,
        kind: ObservationKind,
        per_report: BTreeMap<FrontendId, Vec<Observation>>,
    },
    StepMissing {
        case: CaseQuery,
        step: StepId,
        present_in: Vec<FrontendId>,
        missing_in: Vec<FrontendId>,
    },
    StepExtra {
        case: CaseQuery,
        step: StepId,
        extra_in: Vec<FrontendId>,
    },
    ConstraintUnsatisfied {
        case: CaseQuery,
        step: StepId,
        clause: DocumentRef,
        per_report: BTreeMap<FrontendId, SatisfactionResult>,
    },
    TransformDiverge {
        case: CaseQuery,
        step: StepId,
        per_report: BTreeMap<FrontendId, TransformSummary>,
    },
}

pub struct AgreementGroups {
    /// Groups of frontends whose values are equal to each other at
    /// this divergence point. [ {a,b}, {c} ] means a and b agree,
    /// c is the outlier.
    pub groups: Vec<BTreeSet<FrontendId>>,
}
```

`AgreementGroups` is the kernel's symmetric answer to "who agrees with
whom" — critical for multi-frontend (≥3) diffs where the "majority"
may not be the "correct" answer.

## Symmetry

No frontend is privileged. Given `reports = [simrs, jcsl, jcardengine]`,
diffing produces divergences whose `per_report` entries enumerate all
three. A rule (later) may declare "simrs is the reference" for some
contexts — but the diff itself is symmetric.

This resolves today's awkward `CompareResult::ShadowIgnored` asymmetry.

## World-field diff semantics

Two `WorldValue`s diverge when their typed content differs. Comparison
is semantic, not byte-level:

- `WorldValue::SelectedApp(Aid)` values compare by AID equality, not by
  byte-slice equality.
- `WorldValue::ScpState { version, session_keys_present, .. }` values
  compare field-by-field; a report that says `Scp02` and another that
  says `Scp03` diverges on the `version` sub-field, not on the whole
  struct.
- `WorldValue::Counter(u64)` values compare numerically.
- `WorldValue::Bytes(Vec<u8>)` values compare byte-exact.

The `WorldValue` enum is exhaustive per the spec crates contributing
`WorldView`s. New world fields require extending the enum (which is a
semver-governed change).

## Observation diff semantics

Observations are rarely compared directly — they are evidence, not
invariants. A `Divergence::Observation` is produced when a rule
explicitly requests observation-level comparison for a step. The
default diff does not emit observation divergences for steps where
world-field diff already classifies the disagreement.

## Constraint-unsatisfied divergences

When a step's clause binding is active and a frontend's observations
fail to satisfy the clause's `Constraint`, the diff emits a
`ConstraintUnsatisfied` divergence — even if all frontends agree on
the unsatisfied behaviour. "All frontends are wrong per GP 2.3" is
still a divergence from the spec, and the classifier handles it
(usually as `SpecDeviation`).

## Ordering and determinism

Divergences are emitted in lexicographic order by `(case.scenario,
axis-sorted-key, step.order, field-name)`. Same inputs → same output.
Tests assert this with snapshot fixtures.

## Memory model

The diff engine does not clone reports. It walks references and
constructs divergence structures that borrow or re-package data via
`Arc` where owned data is needed. Large reports (hundreds of steps,
MB of observations) diff in O(steps × frontends × fields) without
copying the observation payloads.

## Testing

- **Unit**: fixtures of 2-, 3-, 4-way reports with known divergences.
- **Property**: `proptest` over synthesised reports; diff is
  symmetric (`compare([a,b]) = compare([b,a])` modulo ordering),
  idempotent at the report level (duplicating a report adds no new
  divergences), stable under permutation.
- **Snapshot**: `insta` for canonical per-case divergence outputs.

## What the diff engine does NOT do

- It does not decide whether a divergence is "bad." That's the
  classifier's job.
- It does not consult rules. It emits divergences; rules match after.
- It does not consult frontend claims. Claims affect classification,
  not diffing.
- It does not filter. Filtering is a consumer's responsibility (the
  book generator renders per-frontend views; the CLI selector narrows
  the run).
