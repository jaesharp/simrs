# 19 — Crate Layout

This chapter enumerates every new crate the conformance engine
introduces, its responsibility, and its dependency direction.
Existing crates are unchanged during Phase A; migrations happen in
later phases.

## New crates

### `simrs-conformance` — kernel

**Responsibility**: pure data types and pure-function pipelines.
`Version`, `DocumentRef`, `Delta`, `StandardGraph`, `Clause`,
`Constraint` trait, `Rule`, `RuleSet`, `Outcome`, `CitationChain`,
`FrontendClaim`, `Scenario`, `Axis`, `CaseQuery`, `Report`, `Step`,
`World`, `Transform`, `Observation`, `Divergence`, `DiffEngine`,
`Classifier`.

**Dependencies**:
- `predicates` (for `Predicate<Divergence>` guard composition)
- `serde` (for serialisation)
- `smallvec` / `arrayvec` where appropriate
- No I/O; `no_std` + `alloc` by default, `std` behind a feature flag

**Consumers**: every other conformance crate.

### `simrs-conformance-macros` — proc macros

**Responsibility**: attribute and function-like macros:
`#[adr]`, `#[cite]`, `#[governs]`, `#[implements_spec]`,
`#[conformance_step]`, `#[conformance_test]`, `spec!`, `clause!`,
`deltas!`, `rule!`, `frontend!`. See chapter 14.

**Dependencies**:
- `syn`, `quote`, `proc-macro2`
- `simrs-conformance` (for the types the macros emit)

**Consumers**: spec crates, ADR-annotated code, scenario authoring.

### `simrs-conformance-ingest` — ingestion traits

**Responsibility**: traits and types for the transcribe/slice/transform
pipeline. `Transcriber`, `Slicer`, `Transformer`, `TranscriptionResult`,
`Slice`, `TransformResult`, `Provenance` types.

**Dependencies**:
- `simrs-conformance` (for the Constraint types transforms emit)
- `serde`, `sha2`

**Consumers**: per-format transcriber crates; spec crate `build.rs`.

### `simrs-conformance-transcribe-pdf` — PDF transcriber

**Responsibility**: PDF → `TranscriptionResult`.

**Dependencies**:
- `pdfium-render` or `lopdf` (choice deferred)
- `simrs-conformance-ingest`

**Consumer**: `simrs-spec-*` crate `build.rs` when source is PDF.

### Additional transcribers (as needed)

- `simrs-conformance-transcribe-html`
- `simrs-conformance-transcribe-markdown`
- `simrs-conformance-transcribe-ocr` (tesseract wrapper)
- `simrs-conformance-transcribe-audio` (whisper; stretch)

Each is a separate crate so a spec's `build.rs` depends only on the
transcribers it needs.

### `simrs-conformance-slice` — slicer library

**Responsibility**: generic and configurable slicers (heading-
boundary, paragraph-boundary, manual-override).

**Dependencies**:
- `simrs-conformance-ingest`

### `simrs-conformance-transform-patterns` — pattern transformers

**Responsibility**: catalogue of pattern-based slice → Constraint
transformers (`shall return SW {hex}`, `shall contain {structure}`,
etc.). Each pattern is ADR-governed.

**Dependencies**:
- `simrs-conformance-ingest`
- `simrs-conformance` (for Constraint types)

### `simrs-conformance-transform-tables` — table lifter

**Responsibility**: parse extracted tables and emit
`Constraint::Table(...)` values for tabular clauses.

### `simrs-spec-gp-2-3` — seed spec crate

**Responsibility**: the first real spec encoding. GP 2.3 clauses
matching our current differential-test scope (SELECT, INITIALIZE
UPDATE, GET DATA basic tags, GET STATUS auth, INS error classes).
Phase A target: 3–5 clauses proving the pipeline; grows in Phase B.

**Dependencies**:
- `simrs-conformance`
- `simrs-conformance-macros`
- Build-dependency: `simrs-conformance-ingest`,
  `simrs-conformance-transcribe-pdf`, `simrs-conformance-slice`,
  `simrs-conformance-transform-patterns`

**Consumers**: rules, ADRs, scenarios, the book generator.

### `simrs-spec-iso-7816-4` — companion spec crate

**Responsibility**: ISO 7816-4 clauses cross-referenced by GP. Phase A
target: only the clauses GP's seed-set cites.

### `simrs-conformance-gherkin` — Gherkin integration

**Responsibility**: Gherkin tag parser + `@binds` type-check + step
registry. See chapter 13.

**Dependencies**:
- `cucumber` (existing cucumber-rs)
- `simrs-conformance`
- `simrs-conformance-macros`

### `simrs-conformance-book` — book generator

**Responsibility**: consume kernel data + reports + variants matrix
and emit `target/conformance-book/`. See chapter 18.

**Dependencies**:
- `simrs-conformance`
- `maud`, `tera`, `serde_json`
- `simrs-adr` (for the AdrGraph)

### `simrs-adr` — opinionated ADR tooling

**Responsibility**: CLI + build-time AdrGraph collector + state-machine
enforcer + product validator. See chapters 15, 16, 17.

**Dependencies**:
- `simrs-conformance`
- `simrs-conformance-macros` (to read emitted `__ADR_SITE_*` consts)
- `inventory` (for collection) or `walkdir` + file parsing
- `clap` (CLI)

**Binary**: ships an `adr` CLI binary.

### `simrs-conformance-frontend-simrs` — simrs frontend adapter

**Responsibility**: wrap `GpCardTerminal` as a conformance-engine
frontend — implements the per-step `World` projection, the
`Transform` emitter, and the claim declaration for simrs.

**Dependencies**:
- `simrs-conformance`
- `simrs-gp-card`

### `simrs-conformance-frontend-jcsl` — jcsl frontend adapter

**Responsibility**: wrap the jcsl backend as a conformance frontend.

**Dependencies**:
- `simrs-conformance`
- `simrs-jcsl`

### `simrs-conformance-frontend-jcardengine` — JCardEngine adapter

Same pattern.

## Dependency direction

```
simrs-conformance (kernel)
  ▲
  ├── simrs-conformance-macros
  ├── simrs-conformance-ingest
  │     ▲
  │     ├── simrs-conformance-transcribe-*
  │     ├── simrs-conformance-slice
  │     └── simrs-conformance-transform-*
  │
  ├── simrs-spec-* (spec crates)
  │     └── build-dep on ingest + transcribers
  │
  ├── simrs-conformance-gherkin
  ├── simrs-conformance-frontend-* (per-impl adapters)
  ├── simrs-adr
  └── simrs-conformance-book
        └── depends on most of the above for aggregation
```

Dependencies are strictly acyclic. No downstream crate depends on a
frontend adapter other than its own consumer (e.g. test harnesses
depend on adapters; the kernel does not).

## Crate naming convention

- `simrs-conformance*` for the engine itself (traits, types,
  tooling).
- `simrs-spec-<std>[-<version>]` for spec crates.
- `simrs-conformance-frontend-<id>` for frontend adapters.
- `simrs-conformance-transcribe-<format>` for transcribers.

Hyphens throughout; all under the `simrs-` umbrella.

## Versioning policy

- Kernel types (`simrs-conformance`): strict semver. Breaking changes
  require a major-version bump and a migration path documented in a
  seed ADR.
- Macros: track kernel version.
- Spec crates: independent semver per standard version (the crate
  encodes one spec-version; the crate's own version reflects encoding
  iterations, not the spec's version).
- Book generator: independent semver; output format is stable across
  minor versions within a major.

## Why this many crates

The fine-grained split is deliberate. Each crate has a single
responsibility; downstream consumers pull in exactly what they need.
A spec crate compiling a JSON-specified standard pulls in the JSON
transcriber and no PDF dependencies; a harness building only the book
doesn't pull in the PDF transcriber at all.

`simrs-conformance-ingest` is split from `simrs-conformance` so the
kernel stays `no_std`-clean; ingestion requires `std` (file I/O) but
the kernel should be embeddable in `no_std` contexts (e.g. on-card
bytecode validators).

## Workspace placement

```
crates/
  simrs-conformance/
  simrs-conformance-macros/
  simrs-conformance-ingest/
  simrs-conformance-transcribe-pdf/
  simrs-conformance-transcribe-html/
  simrs-conformance-slice/
  simrs-conformance-transform-patterns/
  simrs-conformance-transform-tables/
  simrs-conformance-gherkin/
  simrs-conformance-book/
  simrs-conformance-frontend-simrs/
  simrs-conformance-frontend-jcsl/
  simrs-conformance-frontend-jcardengine/
  simrs-adr/
  simrs-spec-gp-2-3/
  simrs-spec-iso-7816-4/
```

All added to `Cargo.toml`'s `[workspace.members]` as they come online.
Phase A lands the kernel + macros + ingest + one transcriber + one
spec crate + Gherkin + ADR tool + one frontend adapter + book
generator. Other transcribers and spec crates come as needed.
