# 06 — Rule Engine

The rule engine takes a `Divergence`, walks a `RuleSet`, and emits an
`Outcome`. It is a ten-line core wrapped by type-level rigour on the
edges.

## Design choices

Per the research survey, no existing Rust rule engine fits the
combination of (a) typed citations on every rule, (b) first-match-wins
with a declared priority order, (c) no runtime cost beyond
`Iterator::find_map`. Heavyweight engines (Cedar, Biscuit, Oso,
zen-engine) bring evaluation models we don't want (Datalog fixpoint,
ABAC policy graphs, DMN decision tables). Data-driven rule definitions
are a deferral — we start code-first and can add a YAML loader later if
needed.

The kernel uses `predicates-rs` as the guard-composition primitive.
`Predicate<Divergence>` already supports `.and()`, `.or()`, `.not()`
combinators for free, and `predicates-rs` is the de-facto standard
predicate crate in the Rust ecosystem (3.6M downloads/month).

## The ten-line core

```rust
impl RuleSet {
    pub fn classify(&self, d: &Divergence, claim: &FrontendClaim) -> Outcome {
        for rule in &self.rules {
            if rule.when.applies(d, claim) && rule.guard.eval(d) {
                return rule.outcome.materialise(d, &rule.citations);
            }
        }
        Outcome::Regression(CitationChain::unattributed(d))
    }
}
```

Everything else is types around this loop.

## Priority ordering

`RuleSet` is constructed as an ordered composition:

```rust
let rs = RuleSet::empty()
    .then(simrs_conformance::standards::iso_7816_4::RULES)
    .then(simrs_conformance::standards::gp_2_3::RULES)
    .then(simrs_backends::jcsl::KNOWN_DIVERGENCES)
    .then(simrs_backends::jcardengine::KNOWN_DIVERGENCES)
    .then(current_test_tolerances());
```

Reading left-to-right: standards first, then vendor-specific known
divergences (which override when they match), then test tolerances
(which override when they match). In practice the ordering matters less
than most systems fear because most rule guards are disjoint — a
`KnownDivergence(J3)` rule guards on `(frontend = jcardengine &&
divergence.step = SELECT_unknown_aid && divergence.field = sw)` and no
other rule matches the same shape.

When two rules match the same divergence shape, the earlier rule wins.
The CLI `adr conflicts` surfaces these collisions during development so
authors can decide which rule should shadow which.

## Rule construction

```rust
pub fn rule<P>(id: RuleId) -> RuleBuilder<P>
where P: Predicate<Divergence> + Send + Sync + 'static { ... }

// Typical use:
rule("sw_6a82_for_unknown_select")
    .scope(
        RuleScope::new()
            .specs(&[SpecId::Gp])
            .versions_from(Version::Gp(V2_1_1), Version::Gp(V2_3_1))
    )
    .guard(
        step_is(StepId::SELECT_UNKNOWN_AID)
            .and(field_is(WorldField::Sw))
    )
    .outcome(OutcomeTemplate::KnownDivergence)
    .cite(gp(V2_3, "11.4.3"))
    .cite(adr(42))
    .build()
```

The `scope` narrows applicability *before* the guard runs — rules
scoped to GP never fire on ISO divergences. `versions_from` uses the
delta graph to include all versions in the DAG range; a rule written
for V2_1_1 projects forward through non-breaking deltas automatically.

## Predicate composition

All standard predicates are provided as constructors:

```rust
pub mod predicate {
    pub fn step_is(id: StepId) -> impl Predicate<Divergence>;
    pub fn field_is(f: WorldField) -> impl Predicate<Divergence>;
    pub fn frontend_is(f: FrontendId) -> impl Predicate<Divergence>;
    pub fn axis_is(name: AxisName, value: AxisValue) -> impl Predicate<Divergence>;
    pub fn any_of<P: Predicate<Divergence>>(ps: Vec<P>) -> impl Predicate<Divergence>;
    pub fn constraint_unsatisfied(by: SatisfactionKind) -> impl Predicate<Divergence>;
    // …
}
```

Custom predicates compose normally via `predicates-rs`. A rule author
who needs arbitrary logic can write a closure:

```rust
.guard(predicate::function(|d: &Divergence| {
    d.affects_any_of(&[WorldField::ScpVersion, WorldField::KeySession])
}))
```

## Outcome templating

`OutcomeTemplate` records the *shape* of the outcome; at classification
time, `materialise` fills in the divergence-specific details:

```rust
pub enum OutcomeTemplate {
    KnownDivergence,
    DesignDecision,
    SpecDeviation,
    UnderReview,
    BehavesLike { effective: Version },
    Match,
}

impl OutcomeTemplate {
    fn materialise(&self, d: &Divergence, cc: &CitationChain) -> Outcome {
        match self {
            KnownDivergence => Outcome::KnownDivergence(cc.clone_with_div(d)),
            BehavesLike { effective } => Outcome::BehavesLike {
                claimed: d.frontend_claim(),
                effective: *effective,
                gap_clauses: cc.clauses_only(),
            },
            // …
        }
    }
}
```

## Validation

Rule sets are validated at build time:

1. **No two rules with identical guards** — if guards are provably
   equivalent, one shadows the other silently. The validator surfaces
   this and requires explicit priority annotation or guard refinement.
2. **Citations resolve** — every `DocumentRef` in every rule's
   `CitationChain` is checked against the loaded spec crates.
3. **Scope consistency** — a rule scoped to `versions_from(V2_1_1,
   V2_3)` that cites `gp(V2_2, …)` is inconsistent; the scope must
   contain every version the citations pin.
4. **Outcome attribution** — `Regression` rules are allowed but
   discouraged; `DesignDecision` rules must cite ≥1 ADR;
   `SpecDeviation` must cite the specific spec clause being deviated
   from.

## Hot-reload (deferred)

A YAML-based rule loader is easy to layer on top:

```yaml
- id: sw_6a82_for_unknown_select
  scope: { specs: [gp], versions_from: v2_1_1, versions_to: v2_3_1 }
  guard: { all: [ { step_is: SELECT_UNKNOWN_AID }, { field_is: sw } ] }
  outcome: known_divergence
  citations:
    - { gp: { v2_3: "11.4.3" } }
    - { adr: 42 }
```

Phase A does not include this. Adding it later is a parsing exercise;
the kernel data model does not change.

## Composition with the delta graph

Rule scope interacts with the delta graph through `versions_from`.
Given `rule.scope.versions = [V2_1_1, V2_2, V2_3]` and a divergence
produced under frontend claim `ClaimedStandard::Gp(V2_3)`, the rule
fires on V2_3 if and only if the delta path V2_1_1 → V2_2 → V2_3 does
not contain a `Modified { before, after }` at the rule's cited clauses.
This is resolved lazily at classification time via a cached DAG walk.
Details in [07 — Delta Graph](07-delta-graph.md).

## Rule sources

Rules can be contributed by:

- **Spec crates**: standard-level rules asserting the spec's own
  invariants ("GP 2.3 § 11.4.3 requires SW 6A82"). Lowest priority
  by convention.
- **Backend adapters**: known-divergence entries for a specific
  reference backend at a specific version. Citations pin the
  backend version.
- **ADR rule bundles**: an ADR can own a small `&'static [Rule]`
  when its decision is expressed as a classifier behaviour rather
  than an implementation choice.
- **Test modules**: a `#[conformance_test]` function can attach a
  local `Vec<Rule>` as tolerances for its scenarios. These have
  highest priority and the narrowest scope.

All sources funnel into the same `RuleSet::then()` composition; there
is one classifier per test run.
