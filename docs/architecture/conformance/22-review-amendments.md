# 22 — Review Amendments

After the initial suite draft, four reviews (two documentation-consistency
passes, one adversarial design pass, one external-prior-art pass) surfaced
a set of corrections and clarifications that apply across multiple
chapters. This chapter is the authoritative record of those amendments.
When a statement here contradicts an earlier chapter, the amendment
wins until the earlier chapter is rewritten to match.

The amendments are grouped by category.

## A — Kernel type reconciliation

Chapter 03 ("Kernel Types") was the single biggest source of drift:
it was written first, and later refinements in Appendix B were not
back-ported. Chapter 03 has been updated to match Appendix B for:

- `Divergence` variant set: adds `StepExtra`, `TransformDiverge`,
  `case: CaseQuery` field on every variant, `agreement: AgreementGroups`
  on `WorldField`, and corrects `Observation.per_report` to
  `BTreeMap<FrontendId, Vec<Observation>>`.
- `RuleScope`: replaces `versions: Option<&[Version]>` with the pair
  `versions_from: Option<Version>` / `versions_to: Option<Version>`.
- `ClaimedStandard`: adds `range: VersionRange`, drops
  `effective_under_cfg`; `FrontendClaim` gains `profile_bundles` and
  `cfg_scope`.
- `ConstraintShape`: adds `Table` explicitly; closes the enum with a
  `#[non_exhaustive]`-governed extension policy rather than an open
  ellipsis.
- `Report`: replaces `ran_at: Timestamp` with `started_at` +
  `finished_at` plus `provenance: RunProvenance`.

Appendix B remains authoritative; chapter 03 is now a type-accurate
introduction rather than a drifted copy.

## B — Per-frontend classification

The reviews surfaced that a three-way divergence (three reports, three
different values) cannot be represented as a single `Outcome` — one
frontend may be `KnownDivergence`, another `Regression`, another
`Match` against the spec.

**Amendment**: `ClassifiedOutcome` is keyed per `(divergence,
frontend)`:

```rust
pub struct ClassifiedOutcome {
    pub divergence_id: DivergenceId,
    pub frontend: FrontendId,
    pub outcome: Outcome,
    pub matched_rule: Option<RuleId>,
    pub citation_chain: CitationChain,
}
```

The classifier emits N outcomes per divergence where N is the number
of frontends participating in the divergence. Chapter 12's loop
expands to:

```rust
for div in divs {
    for frontend in div.frontends() {
        let claim = self.claim_for(frontend);
        let outcome = self.rules.classify_for(div, frontend, claim);
        out.push(ClassifiedOutcome { ... });
    }
}
```

The `RuleSet::classify` contract gains a companion `classify_for`
method that scopes to one frontend.

## C — `RuleSet::classify` unmatched-signal

Chapter 06's ten-line core returns `Outcome::Regression(unattributed)`
as the default for unmatched divergences. Chapter 12's
auto-`BehavesLike` synthesis requires distinguishing "no rule
matched" from "a rule classified this as Regression." Amendment:

```rust
pub enum ClassifyResult {
    Matched(Outcome, RuleId),
    Unmatched,
}

impl RuleSet {
    pub fn classify(&self, d: &Divergence, claim: &FrontendClaim) -> ClassifyResult;
}
```

The outer classifier now explicitly handles `Unmatched` by (a)
attempting `BehavesLike` synthesis against the delta graph, then (b)
falling through to `Outcome::Regression(unattributed)` if no
falsification fires.

## D — Proc-macro cross-crate resolution

Chapter 14 promises `#[cite(gp(V2_3, "11.4.3"))]` fails at compile
time when the clause is missing. A proc-macro sees tokens, not the
`simrs-spec-gp-2-3` crate's registry, and does not have reflective
access to downstream-crate constants.

**Amendment**: the compile-time promise is *monomorphisation-time*
via `const` assertions, not proc-macro-time:

1. The `#[cite(gp(V2_3, "11.4.3"))]` attribute expands to an item
   referencing `simrs_spec_gp_2_3::__CLAUSES::must_exist!("11.4.3")`.
2. `__CLAUSES::must_exist!` is a `const fn`-driven `const` lookup
   that evaluates to a unit value if the clause is present and a
   `panic!()` at const-eval time otherwise.
3. Result: citation validity is a compile-time error at the citing
   crate's compilation, not at the spec crate's compilation.

The build-script fallback — running an `xtask` that scans the
workspace for citations and resolves them against the spec
registry — is also available and runs during CI. The two mechanisms
are complementary: const-eval catches immediate errors, xtask
catches cross-workspace consistency.

## E — Cross-crate site collection

Chapter 14 proposes `inventory`-crate collection for `__ADR_SITE_*`
consts. The reviews flagged:

1. `inventory` uses linker-section tricks not portable to WASM / some
   embedded targets.
2. `inventory` registrations are lost across non-whole-program linking.
3. The AdrGraph must be complete across the entire workspace, not
   just crates linked into one binary.

**Amendment**: the authoritative collector is a workspace-scan via
`cargo doc --output-format=json` (or a direct rustdoc-JSON walker).
The `inventory` path is an optional fast-local development option
for single-binary test runs; it is never the authoritative source
for the validator.

## F — Confluence and compatibility scoping

Chapter 16 promises confluence checking over the full cfg power set.
The reviews noted:

1. Confluence over arbitrary `Constraint` trait impls is semantically
   undecidable.
2. The cfg power set for n ≥ 20 features is infeasible.

**Amendment**: the confluence check is *structural*, not semantic.
Two `Constraint` contributions at a clause under the same cfg are
considered confluent iff they are the same `Constraint` value (pointer
equality via `ConstraintRef`) or one is marked as `implements` the
other via an `AdrEdge`. Semantic equivalence is out of scope. Rule
authors who believe two distinct constraints are semantically
equivalent must add an explicit `implements` edge declaring the
relationship.

For the cfg power set: the validator enumerates cfg assignments via a
SAT solver (chapter 17), and evaluates confluence only on reachable
assignments (those satisfying `VariantPolicy`). For workspaces with
feature counts exceeding the SAT tractability envelope, the validator
emits a coverage report ("checked N of M feasible assignments; M-N
assignments below the cut-off").

## G — Build-time vs xtask-time

Chapters 16 and 17 use "build-time" loosely. Clarification:

- `cargo build` per-crate time: per-crate invariants only (citation
  validity for in-scope citations, shape-check for local scenario
  bindings, ADR frontmatter schema).
- Workspace xtask time (typically `cargo xtask conformance`): AdrGraph
  collection, confluence, compatibility, product variant enumeration,
  drift detection.
- CI time: runs the xtask, uploads the book artefact, posts the
  status.

The xtask is the canonical binding authority for cross-crate
invariants. `cargo build` catches the subset it can see.

## H — Generated-at timestamp determinism

Chapter 15 specified `generated_at: Timestamp` in ADR frontmatter.
Chapter 18 asserts byte-identical book output for identical inputs.
The two contradict.

**Amendment**: ADR frontmatter's `generated_at` is pinned to
`SOURCE_DATE_EPOCH` (or the committer-date of the `HEAD` commit when
`SOURCE_DATE_EPOCH` is unset), not to wall-clock time. The book's
"build timestamp" footer is the only wall-clock value, and it is
rendered outside the `data-provenance` graph so does not affect
reproducibility.

## I — ProseOnly clause binding

Chapter 13 promised the `@binds` shape-check would fail at build time
when the scenario's observations don't match the clause's constraint
shape. Chapter 03 includes `ConstraintShape::ProseOnly`. The reviews
asked: what does `@binds` do for a ProseOnly clause?

**Amendment**: `@binds` on a ProseOnly clause is *declaratively*
valid but the shape-check is trivially satisfied. The scenario is
recorded as a "coverage witness" for the prose clause but does not
assert machine-checkable properties; the classifier cannot emit
`ConstraintUnsatisfied` for a ProseOnly clause. The book renders
ProseOnly bindings with a "coverage-only" badge to distinguish them
from executable bindings.

## J — Contradictory frontend claims invariant

Chapter 08 permitted `Vec<ClaimedStandard>` without specifying
uniqueness. Amendment: *per `(spec, cfg_assignment)` pair, a frontend
MUST have at most one `ClaimedStandard`.* Two claims for the same
spec that are both active under the same cfg is a build error on the
frontend's TOML. Distinct claims for disjoint cfg sets are fine.

## K — `WorldView::merge` commutativity

Chapter 10's `WorldView` trait provides `merge`. Amendment: merging
requires **disjoint field namespaces**. Each `WorldView`
implementation declares its `WorldField` set at registration; the
kernel asserts no two registered views share a field. Commutativity
of merge is thereby vacuous (no overlap implies no conflict).

## L — Delta graph acyclicity

Chapter 07 said "acyclic" without asserting. Amendment: `StandardGraph`
construction (via the `deltas!` macro + `build.rs` validation) must
produce a DAG. A cycle is a build error. Profile-fork re-merges are
expressed as a converging pair of edges at a common version; they
remain acyclic because the underlying version DAG is acyclic.

## M — Scenario expansion scale

Chapter 09 returned `Vec<CaseQuery>` eagerly. Amendment: `Scenario::expand`
returns `impl Iterator<Item = CaseQuery>`; Cartesian expansion is lazy.
Large parameter spaces use t-wise / pairwise sampling selectors to cap
the actual run size; the full Cartesian product is only materialised
when the selector admits all points.

## N — Informative clauses exempt from witness coverage

Chapter 16's witness coverage invariant was unqualified. Amendment:
witness coverage applies only to clauses with
`normative ∈ {Must, MustNot}`. `Should`/`ShouldNot` clauses are
recommended witness targets (warning if missing, not error).
`May` and `Informative` clauses have no witness requirement.

## O — ProvenanceJSON symmetric-edge invariant

Chapter 18's bidirectional traceability was described structurally but
not asserted. Amendment: every forward `uses` edge has a corresponding
backward `sources`/`cited_by` edge; the book generator asserts this
invariant at emit time and fails the build on missing reverse edges.

## P — Kernel bootstrap

The reviews noted a circular dependency: the kernel crate has its own
ADR-governed types, but the validator that enforces ADR invariants
depends on the kernel. Amendment: the kernel crate is exempt from
AdrGraph validation for *its own* `#[adr]` sites during Phase A. A
dedicated "kernel self-validation" xtask runs against the kernel's
ADR graph in isolation, using a bootstrap-only ruleset. Once Phase B
onboards the full validator, kernel ADRs participate normally.

## Q — Claim qualifications

Chapter 00 made several strong novelty claims. Amendments based on
the external prior-art review:

1. "No prior art for delta graphs with multi-hop projection" →
   qualify: "no prior art for delta graphs with typed
   *normative-change kinds* across *spec-clause version DAGs*." Cargo's
   resolver, POSIX feature-test macros, rustc stability attributes,
   and OCI layer DAGs are adjacent multi-hop systems with different
   typing disciplines.
2. "Implementation-claim falsification as a first-class outcome has no
   prior art" → qualify: "the *typed, versioned, delta-traced*
   falsification outcome is novel." The underlying concept of
   claim-vs-behavior matrix reporting exists in W3C
   ImplementationReport, QUIC interop, OSCAL implementation-status,
   and compiler conformance matrices.
3. "Bidirectionally-traceable document collections have no prior art" →
   qualify: "*cross-artefact-kind, build-time-enforced, typed*
   bidirectionality is novel." Literate programming and
   `rustdoc --json` are partial precedents within their narrower
   scopes.
4. `predicates-rs` recommendation is unchanged; no 2025 alternative
   supersedes it for this use case.

## R — Miscellaneous

- Rule id typo: `rule::sw_6a82_for_unknown_aid` → `rule::sw_6a82_for_unknown_select` (chapter 01).
- `cfg_gate` / `cfg:` / `cfg_scope` canonical form: struct field is
  `cfg_scope`; macro surface is `cfg:`; TOML key is `cfg_scope`.
- `FrontendId` / `StepId` construction uses the newtype form
  (`FrontendId("jcardengine")`, `StepId("SELECT_UNKNOWN_AID")`)
  everywhere; the variant-style (`FrontendId::Jcardengine`) examples in
  chapters 06/14 are corrected.
- `ForwardCompat` surface: TOML and macro both use
  `range: { forward_compat_from: <version> }`; grammar A.5 is
  authoritative.
- ADR state diagram (chapter 15): `InForce → Deprecated` and `* → Retracted`
  edges are added to the ASCII rendering.

## Policy

Subsequent reviews should produce amendments in the same structural
form — category letters, terse heading, authoritative statement. When
an amendment supersedes a previous amendment, it is recorded here
with a supersession note. This chapter is a first-class artefact; it
is generated into the book alongside the design suite and carries the
same provenance guarantees.
