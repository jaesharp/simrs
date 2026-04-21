# 07 — Delta Graph

The delta graph is the kernel's model of how a single standard evolves
across versions. It is the mechanism by which a rule written once
automatically applies to every non-breaking version of a spec, and
the mechanism by which the system detects that an implementation
claims version V but behaves as if it implemented version W.

## Structure

For each `SpecId`, a `StandardGraph` is a directed acyclic graph over
`Version`s. Edges are `Delta` values pinned to specific clauses. There
may be many edges between two adjacent versions — one per affected
clause.

```
GP 2.1.1 ──────── Clarified @ 11.4.3 ────────▶ GP 2.3
         ────── Modified @ 11.1 ──────────▶
         ────── Added @ 11.11.2 (SCP03) ──▶

GP 2.3   ──── ErrataFix @ 11.7.2 ──────────▶ GP 2.3.1
```

Versions are totally ordered per spec — the DAG is effectively a path
graph for normal spec evolution; branches can exist (profile-specific
forks) and are encoded as parallel edges with disjoint clause coverage.

## Delta kinds

```rust
pub enum DeltaKind {
    Added,                                    // clause new in `to`, absent in `from`
    Removed,                                  // clause removed in `to`, present in `from`
    Modified { before: ConstraintRef, after: ConstraintRef },
    Clarified,                                // semantics unchanged; wording updated
    ErrataFix,                                // corrective change; older version was buggy
}
```

A rule pinned at version V_from projects through a delta to version
V_to if and only if the delta kind at the rule's clause is **not**
`Modified`, **not** `Removed`. `Added` edges do not propagate backward.
`Clarified` and `ErrataFix` propagate in both directions without
changing the rule.

## Multi-hop projection

Given a rule cited at clause C, version V_a, and a frontend's declared
version V_z, the classifier walks the version graph from V_a to V_z.
If every delta along the path that touches clause C is `Clarified` or
`ErrataFix`, the rule applies at V_z. If any delta on that path is
`Modified` or `Removed`, the rule does not apply at V_z — a new rule
for the V_z shape is required, or the rule must be rescoped to
`versions_from(V_a, V_pre_modified)`.

Walks are cached per `(rule_id, declared_version)` pair at
classification time.

## Implementation-claim falsification

`BehavesLike` is the outcome when:

1. A divergence at clause C is observed on a frontend claiming version
   V_z.
2. A rule scoped to V_z at clause C says "expected shape S_z".
3. The divergence matches an *earlier* shape S_w where V_w is a
   predecessor of V_z, and the delta V_w → V_z at clause C is
   `Modified { before: S_w, after: S_z }`.

In other words: the frontend is producing output consistent with the
pre-delta shape despite claiming the post-delta version. The classifier
emits:

```rust
Outcome::BehavesLike {
    claimed: V_z,
    effective: V_w,
    gap_clauses: vec![DocumentRef::Gp(V_z, C)],
}
```

This is valuable for cross-vendor reality checks. A backend vendor can
claim the latest spec; `BehavesLike` surfaces every clause where the
implementation is actually on an older version.

## Authoring deltas

Deltas are authored in the spec crate's `deltas/<from>_to_<to>.toml`:

```toml
from = "V2_1_1"
to   = "V2_3"

[[delta]]
clause    = "11.4.3"
kind      = "Clarified"
rationale = "GP 2.3 Foreword: editorial clarification; no behaviour change."
citations = [{ gp = { version = "V2_3", locator = "Foreword" } }]

[[delta]]
clause    = "11.1"
kind      = "Modified"
before    = "ResponseLayout(iu_layout_v2_1_1)"
after     = "ResponseLayout(iu_layout_v2_3)"
rationale = "INITIALIZE UPDATE response grows SCP identifier byte."
citations = [{ gp = { version = "V2_3", locator = "Change log item 4" } }]

[[delta]]
clause    = "11.11.2"
kind      = "Added"
rationale = "SCP03 protocol family introduced in GP 2.2; encoded here."
citations = [{ gp = { version = "V2_3", locator = "§11.11" } }]
```

`build.rs` validates:

- Every `clause` in `Modified`/`Removed`/`Clarified` exists in the
  `from` version's slice set.
- Every `clause` in `Added`/`Modified`/`Clarified` exists in the `to`
  version's slice set.
- Every `Removed` clause's id is absent from the `to` version's slice
  set.
- Every `Modified`'s `before` references a `Constraint` reachable from
  the `from` version's slice set.
- Every `Modified`'s `after` references a `Constraint` reachable from
  the `to` version's slice set.

Inconsistencies are build errors.

## Graph walk algorithms

Two primitives suffice:

```rust
impl StandardGraph {
    /// Does a rule pinned at `anchor` project to `target`?
    pub fn projects(&self, anchor: Version, target: Version, clause: &Locator) -> bool;

    /// What is the effective version of a frontend that observed
    /// behaviour `obs` at `clause`, given they claim `declared`?
    /// Returns the latest version whose constraint matches `obs`,
    /// subject to the delta graph.
    pub fn effective_version(
        &self,
        declared: Version,
        clause: &Locator,
        obs: &Observation,
    ) -> Option<Version>;
}
```

Both are O(|path|) per call in the common linear-version case, bounded
by O(|edges|) in the worst case. The DAG is small (standards have
dozens of versions, not thousands), so the unoptimised walk is fine
for Phase A; memoisation is additive.

## Interaction with profiles

A profile (e.g. `Scp03`) marks a clause as present only under certain
conditions. Profiles are a second dimension on top of version:

```rust
pub struct ClauseCoordinate {
    pub version: Version,
    pub profile: Option<ProfileId>,
}
```

Deltas can be profile-scoped (`Added under profile=Scp03 at V2.2`).
Claim falsification considers both — a frontend claiming `Gp(V2_3)
with Scp03` that produces Scp02-shaped output at the relevant clause
is `BehavesLike(V2_3 without Scp03)`, not a version regression but a
profile regression.

## Limitations

The delta graph captures what our authoring layer captures: clause-level
decisions with typed before/after shapes. Semantic changes that don't
fit the `Constraint` model (e.g. performance requirements, packaging
changes, non-normative reorganisations) do not produce deltas. They
are noted in the version node's prose metadata but do not participate
in rule projection or claim falsification.
