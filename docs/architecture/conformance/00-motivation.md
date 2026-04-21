# 00 — Motivation

## The problem in one paragraph

We have a Rust smartcard / SIM simulator (`simrs`) whose correctness is
measured against multiple normative standards (GlobalPlatform 2.x, ISO/IEC
7816-*, ETSI TS 102.221, 3GPP TS 31.10x, etc.) and against independent
reference implementations (Oracle `jcsl`, martinpaljak `JCardEngine`,
physical cards). We have BDD feature files, unit tests, differential tests,
adversarial tests, and ADR markdown files. None of these artefacts currently
know about each other in a machine-checkable way: a feature file cites a
clause in prose, a test asserts a status word, an ADR explains a decision,
and the linkage lives in human memory. When a standard version advances,
when a reference backend releases a new build, when a feature flag flips,
we have no way to surface the consequences except by reading everything
again.

The conformance engine makes the linkage first-class. The standards are
typed Rust values with executable constraints. The tests bind to the
clauses they exercise by type-checked reference, not by tag convention.
The ADRs are generated reports on decisions that already live in the code,
with build-time confluence and compatibility checks. The output is a
standalone, offline book where every line traces back to source provenance
and forward to every use.

## What prior art solves, and what it leaves on the floor

The research survey (launched before this design committed) examined:

- **eADR and ADR tooling in Rust**: `adrs`, `adr-tools`, `ADRust`, `e-adr`
  (Java-only reference). None embed ADRs in source code with typed
  citations. None do bidirectional indexing. None integrate with cucumber
  tags as structured metadata.
- **Multi-implementation conformance frameworks**: `web-platform-tests`
  with `wpt-metadata`, WebGPU CTS, WebAssembly Core testsuite, JSON Schema
  Test Suite, Sonobuoy, OCI conformance. These give us proven patterns
  (out-of-tree classification catalogs, severity lattices over boolean
  pass/fail, proposal-gating by directory) but none solve per-clause
  typed versioning or "frontend claims X but behaves like Y" as a typed
  outcome.
- **Rule / policy engines in Rust**: Cedar, Biscuit, Oso, zen-engine,
  json-rules-engine, `predicates-rs`. The evaluation models on the heavy
  engines (Datalog fixpoint, ABAC policy graphs) fight first-match-wins
  with citations; the recommended kernel is a thin wrapper over
  `predicates-rs`.
- **Typed versioned spec modelling**: `rust-semverver`, rustc stability
  attributes, oasdiff, buf breaking, graphql-inspector, refinery, Diesel
  migrations, IETF Datatracker, W3C test-assertions methodology. All do
  pairwise diff. None model a delta *graph* with multi-hop projection.
  None express implementation-claim falsification ("you claim V2.3 but
  behave like V2.1.1 at these clauses").

Three design decisions fall out of the survey directly:

1. **Build on `predicates-rs`** for rule composition; do not embed Cedar
   or Biscuit. The kernel evaluator is ~10 lines of `Iterator::find_map`
   with typed citation carry-through.
2. **Adopt the out-of-tree classification pattern** (wpt-metadata model)
   but fix WPT's regret: per-rule version predicate pins classifications
   to spec versions, not just to product versions.
3. **Adopt the severity-lattice-over-boolean pattern** (WebGPU CTS),
   extended with `BehavesLike(version)` and explicit
   `DesignDecision(citation)` / `UnderReview(citation)` states so we
   never fall into JSON Schema's `optional/` conflation trap.

## What is novel

The research confirmed three things have no close prior art:

1. **Delta graphs with multi-hop rule projection**. A rule pinned to GP
   V2.1.1 at clause 11.4.3 auto-projects to V2.3 along the version DAG
   unless a typed `Modified{ before, after }` delta intervenes. No existing
   tool represents multi-hop delta traversal of typed spec changes.
2. **Implementation-claim falsification as a first-class outcome**. An
   implementation claiming GP 2.3 compliance that behaves according to
   the V2.1.1 constraint at a clause is classified `BehavesLike(V2_1_1)`
   at that clause, with a citation chain back to the delta that
   demonstrates the gap.
3. **Standards-as-typed-crates with type-checked Gherkin bindings**. The
   normative content of a spec is Rust: `clause!("11.4.3", …,
   constraint: Constraint::ExpectSw(0x6A82))`. A scenario's
   `@binds:gp_2_3::clause("11.4.3")` tag is resolved at test-build time
   against the spec crate, and the scenario's `Then` observations are
   shape-checked against the clause's `Constraint`. A scenario that
   binds to a clause but fails to observe the required shape is a
   compile-time error, not a runtime bug.

Beyond these, the system is the *composition* of several independently-
unremarkable parts into a machine-verifiable pipeline. The emergent
property is that every artefact — a function in the code, an ADR in the
docs, a scenario in the feature file, a rule in the classifier, an
executable constraint in a spec crate — is bidirectionally traceable to
every other artefact that touches it. Compliance documentation stops being
a human-authored after-the-fact narrative and becomes a derived artefact
that is true by construction.

## The problems this eliminates

- **Prose-only citations**. Today a test comment says "per GP 2.3 § 11.4".
  The comment can lie, drift, or be forgotten. Typed `DocumentRef`
  citations cannot: they resolve at compile time or fail the build.
- **Hidden dependencies between feature flags**. Today if you enable
  `feature = "scp02"` alongside `feature = "no_mac"` you may get a
  silently-incorrect build. With the product validator, active ADRs are
  enumerated per cfg tuple, confluence and compatibility are asserted,
  and contradictions are compile-time errors.
- **Stale known-divergence catalogs**. Today a rule in
  `known_divergences.rs` says "JCardEngine 26.04.06 returns 6D00 at X";
  when JCardEngine 27 drops, the catalog entry silently continues to
  apply. With versioned `DocumentRef` pins and a build-time drift check,
  every rule whose pinned version is no longer current surfaces in one
  report.
- **Ambiguous classification buckets**. Today a divergence may be
  recorded as a KnownDivergence with a prose reason; it may be a spec
  deviation, a test tolerance, an intentional design decision, or a
  pending-review finding. The severity lattice with explicit
  `DesignDecision` and `UnderReview` states distinguishes all four.
- **Unprovable cross-vendor conformance claims**. Today "all three of
  simrs, jcsl, JCardEngine pass our GP 2.3 tests" is a narrative
  statement. With per-clause typed rules, per-implementation claim
  declarations, and a classifier that walks the delta graph, the claim
  becomes a derived matrix that can be rendered per clause, per version,
  per product variant.

## The problems this introduces

A system with this much structural enforcement trades up-front flexibility
for long-term invariance. New contributors must learn an authoring
protocol (tag conventions, macro attributes, ADR frontmatter). A test that
does not bind to any clause is either legitimately implementation-specific
(and marked so) or an error. A feature flag that activates an ADR with no
current implementation fails the build.

We accept these costs because the alternative — a hundred loosely-coupled
artefacts with a maintainer who must hold the linkage in memory — is the
state we are in today, and it is already at the limit of its scaling.
When the `simrs` codebase triples in size or the reference-backend set
triples in count, the loosely-coupled approach breaks. The conformance
engine is the forcing function that makes the next tripling possible.

## What this suite is

The chapters that follow pin every type, every stage, every tag, every
macro, every artefact, every guarantee, every non-goal. They are written
to be read by implementers, reviewed by spec authors, cited by auditors,
and eventually rendered — by the very system they describe — into the
book output they make possible.
