# 02 — Pipeline

## Stages

The conformance engine is a staged pipeline. Each stage has a single
input type, a single output type, and no side-effects except at
clearly-marked boundaries (file I/O at ingestion; report emission at
execution). Stages can be replaced individually.

### 1. Transcribe

Turn any normative source into a structured `TranscriptionResult`.

| Source kind       | Transcriber crate                          |
|-------------------|--------------------------------------------|
| PDF (text layer)  | `simrs-conformance-transcribe-pdf`         |
| PDF (scanned)     | same + OCR fallback (tesseract)            |
| HTML / XHTML      | `simrs-conformance-transcribe-html`        |
| Markdown          | `simrs-conformance-transcribe-markdown`    |
| Image (figure)    | `simrs-conformance-transcribe-ocr`         |
| Audio (stretch)   | `simrs-conformance-transcribe-audio`       |

Outputs carry `SourceProvenance { file_hash, transcriber_id,
transcriber_version, pages_processed, warnings }`.

### 2. Slice

Turn a transcription into addressable clauses. A slicer identifies
heading boundaries, extracts the clause identifier (e.g. `"11.4.3"`),
captures the normative text verbatim, classifies the RFC 2119
keyword, records which transcription blocks and tables/figures the
clause consumes.

Slicers can be generic (heading-boundary, paragraph-boundary) or
hand-authored (TOML overrides when the auto-slicer mis-groups).

Output: `Vec<Slice>`, each carrying `SliceProvenance { transcription,
blocks_consumed, tables_consumed, figures_consumed, authored_overrides }`.

### 3. Transform

Turn a slice into a typed `Constraint`. Transformers are either:

- **Pattern-based**: regex/structured matchers over the slice's text
  that produce a `Constraint` directly ("shall return SW {hex}" →
  `Constraint::ExpectSw`). These have their own ids and ADRs.
- **Table-lifters**: extract tabular data into structured constraints
  (SW behavior tables, command structure tables).
- **Hand-authored**: Rust functions in `transforms/manual/<id>.rs`
  that emit constraints directly for slices whose prose is too
  idiosyncratic for pattern matching.

Output: `TransformResult<Constraint>` — `Ok(Constraint)`,
`ProseOnly { reason }`, `Ambiguous(Vec<Constraint>)`, or
`Failed { reason }`. A `ProseOnly` slice is rendered in the book
without an executable constraint; it informs humans but the
classifier cannot assert against it.

### 4. Spec emit (build-time)

The `simrs-spec-*` crate's `build.rs` walks `sources/`, `slices/`,
`transforms/` directories, runs transcribe + slice + transform, and
emits Rust code invoking the `spec!` / `clause!` macros. The macros
produce `&'static Clause` values, `&'static [Clause]` slices per
spec version, and a registry keyed on `(SpecId, Version, ClauseId)`.

The emit step is reproducible: given the same inputs (sources,
slices, transforms), it emits bit-identical Rust. Source hashes are
committed alongside slices to detect transcription drift.

### 5. Scenario expand

A `Scenario` declares axes (typed parameter dimensions); expansion
produces one `CaseQuery` per point in the Cartesian product of axis
values, minus any cases ruled out by axis constraints.

### 6. Execute

Each `CaseQuery` runs against each `Frontend` (a `CardFrontend`-trait
adapter over simrs, jcsl, JCardEngine, or any Transport). The
execution produces one `Report` per `(CaseQuery, Frontend)` pair,
recording the per-step `World` transitions, the `Transform`
(frontend-specific APDU actions), and the raw `Observation`s.

### 7. Diff

`DiffEngine::compare(&[Report]) -> Vec<Divergence>` is a pure
function. Reports are aligned by `(CaseQuery, StepId)`; diffs are
computed over world projections keyed by step. No report is
privileged — "reference" is a classification role, not a
pipeline role.

### 8. Classify

The classifier applies an ordered `RuleSet` to each `Divergence`.
Rules carry typed citations; the first rule whose predicate matches
emits the `Outcome`. Unmatched divergences default to `Regression`.

### 9. Validate (build-time)

Independent of execution, the build runs validators over the static
graph:

- **Citation resolution**: every `DocumentRef` in every ADR, rule,
  `#[cite]` attribute, and Gherkin tag must resolve to a known
  `(document, version, locator)` triple.
- **Confluence**: for every valid cfg assignment, the ADR subgraph
  active under that assignment must converge to a single normal form.
- **Compatibility**: the active ADR / rule / trait / impl graph under
  each cfg must be acyclic and contradiction-free.
- **Product variants**: enumerate satisfying cfg assignments; report
  each as a valid or invalid variant.
- **Drift**: compare pinned doc versions to currently-available
  versions; flag rules and ADRs whose pins are behind.
- **Orphans**: every clause has ≥1 binding scenario; every rule has
  ≥1 owning ADR; every ADR has ≥1 governed artefact.

### 10. Render (book)

`simrs-conformance-book` consumes everything above and renders a
static site. Every rendered element carries `data-provenance`
attribute keyed to the provenance graph. `provenance.json` ships
as the machine-readable index.

## Stage contract summary

No stage mutates the output of another stage. Every stage accepts
inputs by reference (or as typed values), returns a result, and is
independently unit-testable. The pipeline is pure except for:

- Transcription: reads source files from disk
- Execution: runs APDU exchanges against frontends
- Render: writes files

All other stages are total functions over typed data.

## Error handling

Errors at each stage are typed and surface at build time wherever
possible. Runtime errors (execution, diff) emit a typed `Outcome`
variant; they do not panic. A missing binding, an unresolvable
citation, or a confluence failure is a build error — you cannot
commit a state where the graph is inconsistent.

## What this pipeline does not try to do

- It does not prescribe the *scenario authoring language* beyond
  Gherkin + typed binding tags; authors can write scenarios in any
  BDD dialect cucumber-rs supports.
- It does not dictate the shape of the `World` type across all
  domains. Spec crates contribute the world fields they care about
  via a trait-object composition; domains outside smartcards can
  grow their own world schemas without touching the kernel.
- It does not rewrite the `simrs-interposer::DiffEngine`. The new
  `DiffEngine` is a different type in `simrs-conformance`, built
  alongside; migration of existing differential + replay tests to
  the new pipeline happens in Phase B.
