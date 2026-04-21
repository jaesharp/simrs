# 20 — Phases

The conformance engine is delivered in four phases. Each phase ships
a complete, usable increment; later phases extend without reshaping
earlier work.

## Phase A — Kernel and seed pipeline

**Goal**: the complete type shape and a minimum-viable end-to-end
pipeline, proven by three GP 2.3 clauses flowing through every stage.

**Deliverables**:

- `simrs-conformance` kernel crate: full type system.
- `simrs-conformance-macros`: `#[adr]`, `#[cite]`, `#[governs]`,
  `#[implements_spec]`, `#[conformance_step]`, `#[conformance_test]`,
  `spec!`, `clause!`, `deltas!`, `rule!`, `frontend!`.
- `simrs-conformance-ingest`: `Transcriber` / `Slicer` / `Transformer`
  traits + provenance types.
- `simrs-conformance-transcribe-pdf`: minimal PDF transcriber (text
  layer only; OCR deferred).
- `simrs-conformance-slice`: heading-boundary slicer + manual-override
  loader.
- `simrs-conformance-transform-patterns`: 5–10 starter patterns
  ("shall return SW {hex}", "shall contain {bytes}", etc.).
- `simrs-spec-gp-2-3`: 3–5 seed clauses (SELECT unknown AID,
  INITIALIZE UPDATE response layout, GET DATA card-recognition-data,
  GET STATUS auth requirement, invalid-INS error class) with their
  `sources/`, `slices/`, `transforms/`, `build.rs`.
- `simrs-conformance-gherkin`: tag parser + `@binds` type-check + step
  registry.
- `simrs-conformance-frontend-simrs`: simrs adapter with World
  projections for GP-relevant fields.
- `simrs-adr`: CLI + AdrGraph collector + state-machine enforcer +
  validators (confluence, compatibility, drift, orphan).
- `simrs-conformance-book`: minimal book generator producing clause
  pages, ADR pages, frontend compliance matrix, provenance.json.
- `docs/architecture/conformance/`: this suite (complete).
- `docs/adrs/*.md`: generated from `#[adr]` sites on seed code;
  author-maintained rationale sections populated for the seed decisions.
- CI wiring: run `adr validate` on every PR; regenerate the book on
  merges to `dev`; publish the book artefact.

**Success criteria**:

1. The three seed clauses flow from GP 2.3 PDF → `simrs-spec-gp-2-3`
   → Rust `clause!()` call sites → Gherkin `@binds` resolution →
   scenario execution → report → classifier outcome → book render.
2. Every element in the rendered book carries `data-provenance` and
   resolves in `provenance.json`.
3. The product validator enumerates all current Cargo-feature
   combinations and reports each as valid or invalid with concrete
   reasons.
4. An audit-trail query ("show me every use of GP 2.3 § 11.4.3")
   returns a complete list from `provenance.json`.
5. `cargo test --workspace` passes; `cargo clippy --workspace
   --all-targets -- -D warnings` is clean.

**Out of scope for Phase A**:

- Migrating existing differential / replay tests to the new pipeline
  (Phase B).
- Retargeting BDD suites onto the Frontend abstraction (Phase B).
- Additional spec crates beyond GP 2.3 + ISO 7816-4 (Phase C).
- Advanced transcribers (OCR, audio) (Phase D).

## Phase B — Migration and coverage

**Goal**: retarget existing suites onto the conformance engine and
widen spec-crate coverage.

**Deliverables**:

- `simrs-conformance-frontend-jcsl` and
  `simrs-conformance-frontend-jcardengine` adapters.
- `simrs-conformance-frontend-simrs` grows `World` fields to cover
  every current differential-test assertion.
- `simrs-differential-crossvalidation` tests migrated onto the new
  pipeline: tests become `#[conformance_test]` or Gherkin scenarios
  bound to clauses.
- `simrs-standards-integration-validation`,
  `simrs-globalplatform-conformance-validation`,
  `simrs-adversarial-countervalidation` BDD suites retargeted to use
  the Gherkin binding parser and run against any frontend.
- `simrs-spec-iso-7816-4` expanded; `simrs-spec-etsi-ts-102-221` added
  (for SIM coverage).
- Known-divergence catalog (`known_divergences.rs`) ported fully to
  `Rule`s owned by backend-adapter crates.
- Book output gains the multi-frontend compliance matrix + variant
  pages + ADR subgraph visualisations.

**Success criteria**:

1. Every existing APDU-only test is expressible as a scenario bound
   to a spec clause.
2. Running the test suite against each frontend produces reports
   whose classified outcomes match the current known-divergence
   catalog.
3. The book output is the authoritative compliance record — the
   existing hand-maintained `differential-report-*.md` artefacts are
   superseded.
4. No test in any crate fails to bind to a clause or to a frontend.

## Phase C — Coverage expansion and standards bookkeeping

**Goal**: widen standards coverage to every spec `simrs` claims to
implement, and operationalise spec-drift detection.

**Deliverables**:

- `simrs-spec-gp-2-1-1` (for legacy backward compat).
- `simrs-spec-emv-*` (EMV books 1–4) as needed by payment scenarios.
- `simrs-spec-3gpp-ts-31-10x` (USIM AKA).
- Delta graphs populated for GP 2.1.1 → 2.3 (and intermediates), ISO
  editions, ETSI releases.
- CAP-file transcriber (for JC applets whose source is the .cap
  bytecode itself).
- Spec-drift CI job that warns on pinned versions behind current.
- Multi-implementation "cross-vendor conformance" report pages.

**Success criteria**:

1. Every `simrs-*` crate's source code has an owning ADR; orphan
   impls are zero under every variant.
2. Every active rule in the classifier has typed version pins; no
   unpinned rules.
3. Delta graphs support multi-hop projection for at least GP, ISO
   7816, ETSI 102.221.

## Phase D — Automation and stretch

**Goal**: automate the parts of ingestion that are currently manual,
and expand the authoring surfaces that benefit from it.

**Deliverables**:

- OCR transcriber for scanned PDFs.
- Audio / video transcriber for standards-body recordings (stretch).
- Table extraction and layout-preserving transcription improvements.
- Auto-suggestion for pattern-transformers (propose Constraint types
  for novel slice prose based on similarity to catalogued patterns).
- Editable review surface on the rendered book — reviewers annotate
  clauses with notes that commit back to ADRs via Git.
- Interactive version-compare view in the book.
- Machine-learning-assisted slice boundary detection (stretch).

**Success criteria**: driven by needs that surface during Phase B/C,
not scheduled up-front. Phase D is the "stretch" bucket; its contents
are the follow-ups that make the preceding phases more powerful but
that are not in the critical path.

## Sequencing

| Phase | Approximate scope          | Roughly       | Gated by                          |
|-------|----------------------------|---------------|-----------------------------------|
| A     | Kernel + seed              | weeks         | architectural alignment (this doc)|
| B     | Migration                  | weeks         | Phase A complete + book published |
| C     | Coverage                   | ongoing       | Phase B reveals gaps              |
| D     | Automation                 | opportunistic | needs surface during B/C          |

The phases are partially overlappable once Phase A's kernel is
stable — e.g. additional spec crates (Phase C work) can land while
the differential-test migration (Phase B) is in flight.

## What this means for existing work

During Phase A, existing tests continue to run on the existing
pipeline. The new pipeline is built alongside. No existing artefact
is moved or renamed until Phase B. The only commitment up-front is
the new crate tree; it does not displace anything.

In-flight tasks (e.g. task #26 "Wire controlplane into differential
matrix") continue on the current pipeline; they are not gated on the
conformance engine.
