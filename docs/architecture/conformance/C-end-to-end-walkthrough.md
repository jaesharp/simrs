# C — End-to-End Walkthrough

A single clause flowing through every stage of the pipeline. This
chapter is concrete: filenames, line numbers, APDU bytes, rendered
output.

## The clause we trace

GlobalPlatform 2.3, § 11.4.3: "SELECT with unknown AID".

Normative text: *"Upon receipt of a SELECT command specifying an AID
not present on the card, the card shall return SW 6A82 (File not
found)."*

## Stage 1 — Source

The authoritative document is
`crates/simrs-spec-gp-2-3/sources/GPC_2.3_2019_PublicRelease.pdf`.
`sources.lock`:

```toml
[[source]]
path       = "sources/GPC_2.3_2019_PublicRelease.pdf"
sha256     = "8f1a..."
transcriber = "pdf-v1"
transcriber_version = "0.1.0"
pages      = "1..=320"
added_in   = "gp/2.3"
```

## Stage 2 — Transcription

`build.rs` invokes `simrs-conformance-transcribe-pdf`. The transcriber
reads the text layer of page 241, identifies two paragraphs (heading
"§11.4.3 SELECT with unknown AID" and body), and emits:

```json
{
  "provenance": {
    "file_hash": "sha256:8f1a...",
    "transcriber": "pdf-v1",
    "transcriber_version": "0.1.0",
    "pages": [241]
  },
  "blocks": [
    {
      "id": "page241-hdr",
      "kind": { "Heading": { "level": 4 } },
      "text": "11.4.3 SELECT with unknown AID",
      "page": 241,
      "bbox": [120, 360, 420, 378]
    },
    {
      "id": "page241-para2",
      "kind": "Paragraph",
      "text": "Upon receipt of a SELECT command specifying an AID not present on the card, the card shall return SW 6A82 (File not found).",
      "page": 241,
      "bbox": [120, 380, 420, 410]
    }
  ]
}
```

This JSON lands in
`crates/simrs-spec-gp-2-3/transcription/cache/8f1a....json` — cached,
committed, deterministic.

## Stage 3 — Slice

`crates/simrs-spec-gp-2-3/slices/11.4.3.toml`:

```toml
clause_id   = "11.4.3"
title       = "SELECT with unknown AID"
normative   = "Must"
prose       = """
Upon receipt of a SELECT command specifying an AID not present on the
card, the card shall return SW 6A82 (File not found).
"""
blocks      = ["page241-para2"]
cross_refs  = [
    { iso_7816_4 = { year = 2005, locator = "5.1.1" } },
    { etsi_ts_102221 = { release = 18, locator = "6.4.2" } },
]
```

The slicer (`simrs-conformance-slice::heading_boundary`) produces a
`Slice` value keyed on `clause_id = "11.4.3"` whose text references
transcription block `page241-para2`.

## Stage 4 — Transform

`crates/simrs-spec-gp-2-3/transforms/11.4.3.toml`:

```toml
transformer = "patterns/expect_sw_v1"
args        = { sw_hex = "6A82" }
rationale   = "Clause is a plain 'shall return SW X' form."
citations   = [{ adr = 42 }]
```

The pattern transformer `patterns/expect_sw_v1`, defined in
`simrs-conformance-transform-patterns`, matches the regex
`shall return SW\s+([0-9A-Fa-f]{4})` against the slice's prose. The
slice text matches; the transformer emits
`Constraint::ExpectSw(0x6A82)`. Output:

```rust
// Generated into OUT_DIR/generated.rs by build.rs
pub static CLAUSE_11_4_3_CONSTRAINT: ConstraintExpectSw = ConstraintExpectSw(0x6A82);
pub static CLAUSE_11_4_3: Clause = Clause {
    id: &ClauseId("11.4.3"),
    spec: SpecId::Gp,
    version: Version::Gp(GpVersion::V2_3),
    normative: NormativeType::Must,
    prose: "Upon receipt of a SELECT command specifying an AID not present on the card, the card shall return SW 6A82 (File not found).",
    constraint: &CLAUSE_11_4_3_CONSTRAINT,
    cross_refs: &[
        DocumentRef::Iso7816(IsoPart::Part4, IsoYear(2005), Locator("5.1.1")),
        DocumentRef::Etsi(EtsiSpec::Ts102221, EtsiRelease(18), Locator("6.4.2")),
    ],
    profile: None,
    provenance: &CLAUSE_11_4_3_PROVENANCE,
};
```

## Stage 5 — Rust citation site

In `crates/simrs-gp-card/src/select.rs`:

```rust
#[adr(42, cite = gp(V2_3, "11.4.3"), governs = rule::sw_6a82_for_unknown_select)]
impl GpCard for SimrsCard {
    fn select(&mut self, aid: &Aid) -> Result<Fci, Sw> {
        match self.applet_registry.resolve(aid) {
            Some(app) => Ok(self.do_select(app)),
            None => Err(Sw(0x6A, 0x82)),
        }
    }
}
```

The `#[adr(42, cite = gp(V2_3, "11.4.3"))]` attribute emits an
`__ADR_SITE_42` constant into a hidden submodule, carrying the cfg
predicate (default `Any`), the cited clause, the governed rule id,
and the source file + line.

## Stage 6 — Gherkin scenario

`tests/features/select_by_aid.feature`:

```gherkin
@spec:gp_2_3  @binds:gp-2.3:11.4.3  @governs:rule:sw_6a82_for_unknown_select
Feature: SELECT Command

  Scenario Outline: SELECT unknown AID returns 6A82
    Given a powered-on <frontend>
    When I send SELECT with AID "FF EE DD CC BB"
    Then SW equals 6A82

  Examples:
    | frontend    |
    | simrs       |
    | jcsl        |
    | jcardengine |
```

At test build-time, `simrs-conformance-gherkin` resolves
`@binds:gp-2.3:11.4.3` → `&CLAUSE_11_4_3`. The binding shape-check
reads `CLAUSE_11_4_3.constraint.shape()` → `ConstraintShape::ExpectSw`.
The `Then SW equals 6A82` step is registered as producing
`ObservationKind::ApduExchange` with SW payload; shape check passes.

## Stage 7 — Scenario expansion

The scenario has one axis (`frontend`) with three values.
`Scenario::expand()` produces three `CaseQuery` values:

```rust
[
  CaseQuery { scenario: "select_unknown_aid", axes: { frontend: Simrs } },
  CaseQuery { scenario: "select_unknown_aid", axes: { frontend: Jcsl } },
  CaseQuery { scenario: "select_unknown_aid", axes: { frontend: Jcardengine } },
]
```

## Stage 8 — Execution

Each case runs against its frontend. For `Simrs`:

```rust
// pseudo-execution
frontend.power_on();
let apdu = select_aid(&[0xFF, 0xEE, 0xDD, 0xCC, 0xBB]);
let response = frontend.transmit(&apdu);  // expects [0x6A, 0x82]
// World transition: selected_app = None (unchanged), last_sw = 6A82
// Observations: ApduExchange { command: apdu, response: [], sw: 6A82 }
```

Similar for `Jcsl` and `Jcardengine`. Each produces a `Report`
instance landed in `target/conformance/reports/run-<ts>/<frontend>/
select_unknown_aid/case-00.json`.

## Stage 9 — Diff

`DiffEngine::compare(&[simrs_report, jcsl_report, jcardengine_report])`
aligns by `(case, step)`. At step "SELECT_UNKNOWN_AID":

- simrs world-after: `last_sw = 0x6A82`
- jcsl world-after: `last_sw = 0x6A82`
- jcardengine world-after: `last_sw = 0x6D00`  (known divergence J3)

Emits:

```rust
Divergence::WorldField {
    case,
    step: StepId("SELECT_UNKNOWN_AID"),
    field: WorldField("last_sw"),
    per_report: {
        Simrs       => WorldValue::Sw(Sw(0x6A, 0x82)),
        Jcsl        => WorldValue::Sw(Sw(0x6A, 0x82)),
        Jcardengine => WorldValue::Sw(Sw(0x6D, 0x00)),
    },
    agreement: AgreementGroups { groups: [{Simrs, Jcsl}, {Jcardengine}] },
}
```

## Stage 10 — Classify

The classifier walks the `RuleSet`. The earliest matching rule:

```rust
pub const RULE_J3: Rule = rule! {
    id: "jcardengine_select_unknown_6d00",
    scope: { frontends: [FrontendId("jcardengine")] },
    guard: step_is(StepId("SELECT_UNKNOWN_AID")).and(field_is(WorldField("last_sw"))),
    outcome: KnownDivergence,
    cites: [
        gp(V2_3, "11.4.3"),
        jcardengine(v("26.04.06"), known_div("J3")),
        adr(42),
    ],
};
```

Fires on the `Jcardengine` entry. Outcome:

```rust
Outcome::KnownDivergence(CitationChain {
    refs: [Gp(V2_3, "11.4.3"), Jcardengine(V26_04_06, "J3"), Adr(42)],
    rationale: "JCardEngine GlobalPlatformApplet collapses unknown SELECT to 6D00.",
})
```

`Simrs` and `Jcsl` have no divergence at this step (they agree with
the spec); their outcomes for the case are `Match`.

## Stage 11 — Variant validation

The product validator enumerates `features = {}`, `{scp03}`,
`{scp02}`, `{scp02, scp03}` (four variants). All four have ADR-0042
active; none have a confluence conflict at clause 11.4.3. All four
are valid. The variant report carries ADR-0042 in each variant's
"active ADRs" list.

## Stage 12 — Book render

The book generator renders:

### Clause page (`specs/gp/2.3/clauses/11.4.3/index.html`)

Contains:
- Title, prose, constraint summary ("Expect SW 6A82").
- Source excerpt section with page-241 image + highlighted bbox.
- Provenance block (file hash, transcriber version).
- Cross-refs to `iso-7816-4:5.1.1` and `etsi-ts-102221:6.4.2` (linked).
- Forward-use sections:
  - **Implemented by**: `crates/simrs-gp-card/src/select.rs:42`
  - **Governed by ADR**: ADR-0042 (linked)
  - **Rules**: `sw_6a82_for_unknown_select`, `jcardengine_select_unknown_6d00`
  - **Scenarios**: "SELECT unknown AID returns 6A82" (linked)

### ADR page (`adrs/0042/index.html`)

Contains:
- Frontmatter panel (cites, governs, implements, cited_by).
- Author-maintained rationale & consequences.
- Subgraph visualisation (ADR-0042 governs rule `sw_6a82_for_unknown_select`;
  implemented by `impl GpCard for SimrsCard`; cited by scenario and rule J3).

### Frontend compliance (`frontends/jcardengine/compliance.html`)

Contains a row:

| Clause | Outcome | Matched rule | Citations |
|--------|---------|--------------|-----------|
| gp/2.3/11.4.3 | KnownDivergence | jcardengine_select_unknown_6d00 | ADR-0042, JCE-26.04.06-J3 |

### `provenance.json`

```json
"clause:gp-2.3:11.4.3/prose": {
  "type": "Clause.Prose",
  "sources": [{ "pdf": "GPC_2.3_2019_PublicRelease.pdf:241:[120,380,420,410]" }],
  "uses": [
    { "Adr": 42 },
    { "Rule": "sw_6a82_for_unknown_select" },
    { "Rule": "jcardengine_select_unknown_6d00" },
    { "Scenario": "select_unknown_aid" },
    { "Impl": "crates/simrs-gp-card/src/select.rs:42" },
    { "CrossRef": "iso-7816-4:2005:5.1.1" },
    { "CrossRef": "etsi-ts-102221:r18:6.4.2" }
  ]
}
```

## What every artefact knows

From any rendered line on any page in the book, the reader can:

- Walk backward: this line originated from PDF page X, bbox Y, via
  transcriber Z version W, slice A, transform B.
- Walk forward: this clause is implemented by F impls, governed by G
  ADRs, tested by H scenarios, bound by I rules, active in J variants.
- Walk sideways: this clause's cross-references resolve to K other
  clauses in L other specs.

The forward and backward walks are constant-time lookups in
`provenance.json`; rendering is deterministic; auditing is direct.

## Why this one example is the whole pipeline

Every other clause flows through the same eleven stages. New clauses
add slice + transform TOML; new ADRs add `#[adr]` sites; new
scenarios add Gherkin tags. The kernel remains unchanged. This is
the property Phase A must preserve and later phases exploit.
