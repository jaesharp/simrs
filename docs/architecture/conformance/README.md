# Conformance Engine — Design Specification Suite

This directory is the authoritative design spec for the `simrs` conformance
engine: the system that turns normative standards documents, implementation
code, test scenarios, and runtime observations into a single
bidirectionally-traceable document collection that *is* both the test suite
and the compliance evidence.

## Scope of this suite

The conformance engine spans:

- **Ingestion**: transcribe, slice, and transform authoritative normative
  documents (PDF, HTML, media) into typed Rust `Clause` values with
  executable `Constraint`s.
- **Kernel types**: `Version`, `DocumentRef`, `Delta`, `Clause`, `Rule`,
  `Outcome`, `CitationChain`, `FrontendClaim`, `Scenario`, `CaseQuery`,
  `Report`, `Step`, `World`, `Transform`, `Observation`, `Divergence`.
- **Pipeline stages**: Source → Transcribe → Slice → Transform → Execute
  → Report → Diff → Classify → Book.
- **Authoring surfaces**: Rust attribute macros (`#[adr]`, `#[cite]`,
  `#[governs]`, `#[implements_spec]`), spec DSL macros (`spec!`, `clause!`,
  `deltas!`), Gherkin citation tags (`@cite`, `@binds`, `@governs`,
  `@pinned`), and ADR markdown files with typed frontmatter.
- **Build-time guarantees**: confluence checking, compatibility checking,
  product-variant enumeration, spec-drift detection, citation-graph
  well-formedness.
- **Output**: a standalone, offline-browsable book where every line
  traces backward to source provenance and forward to every use.

## Reading order

New readers should read in this order:

1. [00 — Motivation](00-motivation.md) — what problem this solves and why existing tools fall short
2. [01 — Overview](01-overview.md) — thirty-thousand-foot picture in one page
3. [02 — Pipeline](02-pipeline.md) — the stages and their interfaces
4. [20 — Phases](20-phases.md) — what ships when
5. [21 — Non-Goals](21-non-goals.md) — what we deliberately do not build

After the foundational chapters, proceed topically. All specs cross-reference
each other; the glossary (appendix D) pins every term.

## Topical index

### Ingestion and sources

- [04 — Standards Ingestion](04-standards-ingestion.md): Transcriber, Slicer, Transformer traits; "any means" extensibility
- [05 — Spec Crates](05-spec-crates.md): `simrs-spec-*` crate layout; `sources/`, `slices/`, `transforms/`, `build.rs`

### Kernel

- [03 — Kernel Types](03-kernel-types.md): the type system backbone
- [06 — Rule Engine](06-rule-engine.md): `predicates-rs`-based, first-match-wins, priority composition
- [07 — Delta Graph](07-delta-graph.md): version DAG, `DeltaKind`, multi-hop projection
- [08 — Frontend Claims](08-frontend-claims.md): declarative versioning and falsification

### Scenarios and reports

- [09 — Scenarios and Cases](09-scenarios-and-cases.md): Cartesian-product cases, typed axes
- [10 — Report Model](10-report-model.md): flat steps, parallel worlds, transforms, observations
- [11 — Diff Engine](11-diff-engine.md): pure function over reports, symmetric diffs
- [12 — Classifier](12-classifier.md): rule application to divergences; `Outcome` emission

### Authoring

- [13 — Gherkin Binding](13-gherkin-binding.md): `@binds`/`@cite`/`@governs` tag grammar; type-checked bindings
- [14 — Proc Macros](14-proc-macros.md): `#[adr]`, `#[cite]`, `#[governs]`, `#[implements_spec]`; `spec!`, `clause!`, `deltas!`
- [15 — ADR Model](15-adr-model.md): opinionated frontmatter, state machine, generated vs author-maintained sections

### Build-time guarantees

- [16 — Confluence and Compatibility](16-confluence-and-compat.md): rewriting-sense confluence + constraint-satisfaction compatibility
- [17 — Product Validator](17-product-validator.md): cfg enumeration, variant reports, feature-flag handling

### Output

- [18 — Book Output](18-book-output.md): standalone, offline, bidirectionally-traceable site

### Meta

- [19 — Crate Layout](19-crate-layout.md): all new crates, naming, dependency direction
- [20 — Phases](20-phases.md): Phase A/B/C/D scope and sequencing
- [21 — Non-Goals](21-non-goals.md): explicit out-of-scope
- [22 — Review Amendments](22-review-amendments.md): authoritative corrections to earlier chapters from design-review passes

### Appendices

- [A — Grammars](A-grammar.md): BNF for every DSL
- [B — API Signatures](B-api-signatures.md): complete Rust public API
- [C — End-to-End Walkthrough](C-end-to-end-walkthrough.md): one clause flowing through the entire pipeline
- [D — Glossary](D-glossary.md): every term, pinned

## Status

This suite is the design spec for Phase A of the conformance engine. Each
chapter is versioned as part of the repository; substantive changes are
discussed in ADRs linked from the chapter itself. The chapters themselves
are authoritative — when they disagree with an implementation, the
implementation is the bug unless an ADR supersedes the chapter.

The conformance engine is, deliberately, a system designed to document and
validate itself. Once Phase A is in place, the chapters in this suite will
also be rendered into the book output alongside the generated artefacts;
at that point the suite becomes part of the very object it describes.
