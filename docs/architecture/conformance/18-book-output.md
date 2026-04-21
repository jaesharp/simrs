# 18 — Book Output

The book is the build's terminal artefact: a standalone, offline-
browsable static site in which every rendered line traces backward to
its source and forward to every use. It is the deliverable that
auditors, maintainers, spec-body participants, and new contributors
all consume.

## Core invariants

- **Standalone**: the `target/conformance-book/` directory renders from
  `file://` with no external fetches. Source documents ship with the
  book (subject to license) or are hash-pinned with local excerpts.
- **Bidirectionally traceable**: every element carries
  `data-provenance="<artifact-id>"`; `provenance.json` indexes every
  artefact → ancestors + descendants.
- **Semantic-web-ish**: `provenance.json` is JSON-LD; external tools
  can consume it without re-parsing the HTML.
- **Deterministic**: same inputs → same output, byte-identical except
  for the build timestamp.
- **Incremental**: regenerate only affected pages on partial source
  changes, keyed by provenance hashes.

## Directory layout

```
target/conformance-book/
├── index.html                              # top-level nav + compliance summary
├── assets/                                 # CSS, JS, search index, theme
│
├── provenance.json                         # JSON-LD graph, all edges
├── variants.json                           # product variant matrix
├── search-index.json                       # offline search
│
├── specs/
│   └── gp/
│       └── 2.3/
│           ├── index.html                  # spec overview
│           ├── versions.html               # version DAG view
│           ├── deltas.html                 # delta list per version pair
│           └── clauses/
│               └── 11.4.3/
│                   ├── index.html          # clause page: prose + constraint + provenance
│                   ├── source.html         # transcribed source excerpt + PDF page overlay
│                   ├── implementations.html # forward-use: impls citing this clause
│                   ├── scenarios.html      # forward-use: binding scenarios
│                   ├── rules.html          # forward-use: rules at this clause
│                   └── adrs.html           # forward-use: governing ADRs
│
├── adrs/
│   └── 0042/
│       ├── index.html                      # ADR page: frontmatter + prose + graph
│       └── graph.html                      # visual: subgraph
│
├── rules/
│   └── <id>/
│       ├── index.html                      # rule page: predicate, scope, citations
│       └── matches.html                    # recent match reports
│
├── scenarios/
│   └── <scenario-id>/
│       ├── index.html                      # scenario source + bindings
│       └── cases/                          # per-case reports
│           └── case-00.html
│
├── variants/
│   └── variant-01/
│       └── index.html                      # product-variant validation + active ADRs
│
├── frontends/
│   └── simrs/
│       ├── index.html                      # frontend summary
│       ├── claims.html                     # declared standards/versions/profiles
│       └── compliance.html                 # per-clause outcome matrix
│
└── conformance/                            # this very design spec suite
    ├── README.html
    ├── 00-motivation.html
    ├── 01-overview.html
    └── …
```

Every page includes: a header with the site nav, a footer with build
metadata, a sidebar with contextual navigation (up/down the graph),
and a main panel with the page content.

## Provenance embedding

Each rendered element with a semantic identity carries
`data-provenance`:

```html
<p data-provenance="clause:gp-2.3:11.4.3/prose">
  Upon receipt of a SELECT command specifying an AID not present on
  the card, the card shall return SW 6A82 (File not found).
</p>
```

The `data-provenance` value is a key into `provenance.json`, which
records:

```json
"clause:gp-2.3:11.4.3/prose": {
  "type": "Clause.Prose",
  "spec": "gp/2.3",
  "clause": "11.4.3",
  "sources": [
    {
      "kind": "pdf-transcribe",
      "file": "sources/GPC_2.3_2019_PublicRelease.pdf",
      "file_hash": "sha256:…",
      "pages": [241],
      "bbox": [120, 380, 420, 410],
      "transcriber": "pdf-v1",
      "transcriber_version": "0.1.0"
    }
  ],
  "uses": [
    { "type": "Rule", "id": "sw_6a82_for_unknown_select" },
    { "type": "Adr", "id": 42 },
    { "type": "Scenario", "id": "select_unknown_aid" },
    { "type": "Impl", "file": "crates/simrs-gp-card/src/select.rs", "line": 42 }
  ]
}
```

Hovering an element with `data-provenance` surfaces the backward
source + forward uses as a popover. Keyboard navigation (arrow keys +
a shortcut) walks the graph.

## Source excerpt embedding

Every clause page shows the transcribed source excerpt:

```html
<section class="source-excerpt" data-provenance="clause:gp-2.3:11.4.3/source">
  <h3>Source: GlobalPlatform 2.3 § 11.4.3</h3>
  <figure>
    <img src="/specs/gp/2.3/source/page-241.png" alt="page 241"
         usemap="#page-241-clauses">
    <!-- bbox map highlights this clause on the page -->
    <map name="page-241-clauses">
      <area shape="rect" coords="120,380,420,410"
            href="#clause-11.4.3"
            title="§11.4.3">
    </map>
    <figcaption>Page 241, § 11.4.3 — SELECT with unknown AID</figcaption>
  </figure>
  <blockquote class="verbatim">
    Upon receipt of a SELECT command specifying an AID not present on
    the card, the card shall return SW 6A82 (File not found).
  </blockquote>
  <dl class="provenance">
    <dt>File</dt> <dd>GPC_2.3_2019_PublicRelease.pdf (sha256:…)</dd>
    <dt>Transcriber</dt> <dd>pdf-v1 @ 0.1.0</dd>
    <dt>Extracted</dt> <dd>2026-04-21T14:02:11Z</dd>
  </dl>
</section>
```

The rendered page links include the source PDF (if license permits
bundling) or a hash-pinned external reference.

## Forward-use sections

Every clause / ADR / rule page has forward-use sections derived from
`provenance.json`:

- "Implemented by" (impls citing this clause)
- "Tested by" (scenarios binding to this clause)
- "Governed by" (ADRs that govern the clause's rule(s))
- "Varied across" (product variants where this clause is in force)

Click-through from a forward-use entry navigates to the using
artefact; the outgoing page includes a back-link (`provenance.json`
edges are bidirectional).

## Compliance matrix rendering

Per-frontend compliance pages (`frontends/<id>/compliance.html`) are
rendered as a sortable table:

| Clause         | Outcome                 | Matched rule            | Case(s)       | Citations         |
|----------------|-------------------------|-------------------------|---------------|-------------------|
| gp/2.3/11.4.3  | Match                   | sw_6a82_for_unknown_select | case-00, case-01 | ADR-0042, ISO-5.1.1 |
| gp/2.3/11.1    | BehavesLike(V2.1.1)     | (auto, delta-falsified) | case-03       | ADR-0064, GP-V2.3-changelog-item-4 |
| gp/2.3/11.7.2  | KnownDivergence(J3)     | jcardengine_get_status_6d00 | case-05   | ADR-0099, JCE-26.04.06-J3 |

Sortable by outcome severity, clause id, match rule, frontend.

## Generator crate

`crates/simrs-conformance-book` consumes:

- The kernel AdrGraph (from the build-time collector).
- The `Spec` registries loaded from each `simrs-spec-*` crate.
- Classified outcome reports (from the test runs).
- The variants matrix (from the product validator).

And produces the `target/conformance-book/` directory. The generator
is a separate process from `cargo test`; it is driven by an xtask
(`cargo xtask book`) that reruns the test suite (or consumes cached
reports), collects the AdrGraph, and renders.

## Rendering stack

Rather than adopt `mdbook` directly (template limits, weak support
for typed data-attributes throughout), Phase A uses a custom static
generator built on `maud` (type-safe HTML DSL in Rust) and `tera` for
prose templating. mdbook-style left-nav + search come via a small
JS bundle (`elasticlunr` or similar for offline search).

## Deferred: interactive features

- A "spec diff" view that renders two version's clauses side-by-side
  with deltas highlighted.
- A "variant compare" view that toggles which ADRs activate under
  selected cfg tuples.
- An editable view that lets reviewers annotate clauses with review
  notes (committed back as ADR updates via Git).

These are valuable but not Phase A.

## Testing the book

- Unit: renderer produces expected HTML for fixture inputs.
- Golden-file: `insta` snapshots of canonical pages.
- Link integrity: no internal link dangles; every `data-provenance`
  resolves.
- Accessibility: headings in order, alt text present, keyboard
  navigation works.
