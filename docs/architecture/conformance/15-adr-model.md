# 15 — ADR Model

ADRs in this system are *generated artefacts* — rendered views of
decisions that live in the code via the `#[adr(N)]` attribute
macros and `rule!`/`spec!`/`clause!` expansions. Author input is
restricted to rationale prose; everything else (citations, governed
rules, affected impls, compatibility edges, state machine progression)
is derived.

This is the central inversion called out in chapter 00: *the code is
the decision; the ADR file is a report on the code.*

## ADR file layout

```
docs/adrs/
├── 0001-pipeline-architecture.md
├── 0042-select-unknown-aid-returns-6a82.md
├── 0051-ins-0xfd-rejected-by-design.md
└── …
```

Each file has two sections separated by a sentinel comment:

```markdown
---
id: 42
title: "SELECT unknown AID returns 6A82"
status: InForce
generated_at: 2026-04-21T14:02:11Z
active_under:
  - any
cites:
  - gp: { version: V2_3, locator: "11.4.3" }
  - iso_7816_4: { year: 2005, locator: "5.1.1" }
governs:
  - rule: "sw_6a82_for_unknown_select"
implements: null
supersedes: []
superseded_by: null
cited_by:
  - src: "crates/simrs-gp-card/src/select.rs:42"
  - src: "crates/simrs-gp-card/src/select.rs:57"
  - feature: "features/select_by_aid.feature:10-18"
    scenario: "SELECT unknown AID"
---

# ADR-0042 — SELECT unknown AID returns 6A82

## Status

**In force** as of 2026-04-21. Active under all configurations.

## Citations

- GP 2.3 § 11.4.3 — SELECT unknown AID shall return SW 6A82
- ISO/IEC 7816-4:2005 § 5.1.1 — File/application not found

## Governs Rules

- `rule::sw_6a82_for_unknown_select`

## Cited By

### Implementations (2)

- `crates/simrs-gp-card/src/select.rs:42` — `impl GpCard for SimrsCard`
- `crates/simrs-gp-card/src/select.rs:57` — `fn validate_select`

### Scenarios (1)

- `features/select_by_aid.feature:10-18` — "SELECT unknown AID"

## Compatibility

No active incompatibility under current cfg assignments.

<!-- === AUTHOR NOTES === -->

## Rationale

The 6A82 ("File/application not found") SW is chosen over 6999 (applet
selection failed) because SELECT-by-AID is an ISO 7816-4 operation
first and a GlobalPlatform operation second. The ISO semantic is the
authoritative one: 6A82 signals absence, not failure.

## Consequences

Terminals conditional on 6A82 will behave correctly. Legacy code
expecting 6999 for unknown AIDs needs adjustment. The divergence
catalog records JCardEngine's return of 6D00 as a known deviation (J3)
rather than treating it as a regression.
```

The `<!-- === AUTHOR NOTES === -->` sentinel separates generated from
author-maintained content. Generator runs preserve everything below
the sentinel verbatim; everything above is regenerated on each build.

## Frontmatter schema

Every ADR frontmatter is a typed struct:

```rust
pub struct AdrFrontmatter {
    pub id: AdrId,
    pub title: String,
    pub status: AdrStatus,
    pub generated_at: Timestamp,
    pub active_under: ActiveUnder,
    pub cites: Vec<DocumentRef>,
    pub governs: Vec<RuleId>,
    pub implements: Option<AdrId>,
    pub supersedes: Vec<AdrId>,
    pub superseded_by: Option<AdrId>,
    pub cited_by: Vec<CitedBy>,
}

pub enum AdrStatus {
    Proposed { since: Date },
    Accepted { since: Date, reviewers: Vec<String> },
    InForce { since: Date },
    Superseded { by: AdrId, at: Date },
    Retracted { reason: String, at: Date },
    Deprecated { since: Date, sunset: Option<Date> },
}

pub enum ActiveUnder {
    Any,
    Cfg(CfgExpr),
}
```

The `adrs/` CLI enforces frontmatter conformance: authoring an ADR
with a missing field, unresolvable citation, or dangling reference
is a build error.

## State machine

```
          ┌────────────┐    accept    ┌────────────┐   push-live   ┌──────────┐
          │  Proposed  │ ───────────▶ │  Accepted  │ ────────────▶ │ InForce  │
          └────────────┘              └────────────┘               └─────┬────┘
                                                                         │
                                           retract ◀─────────────────────┤
                                                                         │
                                                                 supersede │
                                                                         │
                                                                         ▼
                                                                   ┌───────────┐
                                                                   │Superseded │
                                                                   └───────────┘
```

Transitions require evidence:

- `Proposed → Accepted` needs ≥1 reviewer signature (author commit
  trailer or explicit `adr accept --reviewer jane`).
- `Accepted → InForce` needs the governed implementations to exist
  under the ADR's `active_under` cfg and ≥1 test referencing the
  governed rules.
- `InForce → Superseded` requires a target ADR; both transition
  simultaneously (atomic file edit).
- `* → Retracted` requires a rationale string.

The CLI refuses transitions that would violate these invariants.

## Opinionated refusals

The ADR authoring path enforces:

1. **No uncited InForce ADRs** — every in-force ADR has ≥1 typed
   citation.
2. **No orphan ADRs** — every in-force ADR governs ≥1 rule or
   implements ≥1 trait/spec-clause.
3. **No dangling successors** — an ADR in `Superseded` status must
   name a `superseded_by` that exists and is in a non-terminal status.
4. **No citation cycles** — the `supersedes`/`implements`/`governs`
   graph is acyclic.
5. **No partial-active contradictions** — two in-force ADRs whose
   `active_under` cfg intersects must be confluent + compatible on
   every clause they both cite (details: chapter 16).
6. **No stale pinned citations without rationale** — an ADR citing
   a document version older than the current version must carry
   either `@pinned:reason="..."` or a scheduled `sunset` date.

The CLI catches all of these on `adr validate`; CI fails on violation.

## Lifecycle tooling

```
adr new                        # create an ADR skeleton; opens $EDITOR
adr accept <id> --reviewer …   # Proposed → Accepted
adr push-live <id>             # Accepted → InForce (validates invariants)
adr supersede <id> --by <M>    # InForce → Superseded (updates M too)
adr retract <id> --reason "…"  # * → Retracted
adr validate                   # run all invariant checks
adr generate                   # regenerate frontmatter + upper sections
adr drift                      # list ADRs with stale version pins
adr variants                   # enumerate product variants (chapter 17)
adr graph [--filter …]         # visualise the ADR graph
adr cited-by <id>              # show forward references
adr cites <id>                 # show backward references
```

## Book integration

Each ADR renders to a book page with:

- Frontmatter displayed as a structured panel.
- Prose sections as the main content.
- "Cited by" list with hyperlinks to source locations.
- "Citations" list with hyperlinks to spec clause pages.
- A visual subgraph showing this ADR's neighbourhood (supersedes /
  superseded-by / governs / implements / active-under-cfg).
- Forward-use summary: "this ADR is active in N product variants;
  governs M rules; cited by K implementations and J scenarios."

## Why generated-not-authored

Generated ADR frontmatter makes "maintainers only look in one spot"
real: when a governed rule is renamed, the ADR file updates without
hand-editing. When a new implementation cites the ADR, the "Cited by"
list updates on the next build. When a cited document version
advances, the ADR shows drift without anyone remembering to audit.

Author input is restricted to the sections where human judgment is
irreducible: why a decision was made, what the downstream consequences
are. Those don't change on their own, and they're the parts humans
want to read.
