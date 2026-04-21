# 01 — Overview

## The picture on one page

```
                               ┌──────────────────────────────────────┐
                               │   NORMATIVE SOURCES                  │
                               │   PDFs, HTML, media, erratum packs,  │
                               │   standards-body recordings          │
                               └────────────────┬─────────────────────┘
                                                │
                                                ▼
        ┌──────────────────────────────────────────────────────────┐
        │  INGESTION PIPELINE                                      │
        │                                                          │
        │    Transcribe ──▶ Slice ──▶ Transform                    │
        │    (pdf2text,  (clause    (prose + tables                │
        │     OCR,        bounds,     → typed Constraint)          │
        │     HTML DOM,   provenance,                              │
        │     …)          RFC 2119)                                │
        └────────────────────────────┬─────────────────────────────┘
                                     │  typed Slices +
                                     │  Constraint mappings
                                     ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  SPEC CRATES            (simrs-spec-gp-2-3, -iso-7816-4, …)  │
     │                                                              │
     │  spec! { clause "11.4.3" {                                   │
     │    normative: Must,                                          │
     │    constraint: Constraint::ExpectSw(0x6A82),                 │
     │    prose: "…", cross_refs: [iso_7816_4::clause("5.1.1")]     │
     │  }}                                                          │
     │                                                              │
     │  deltas! { V2_1_1 → V2_3 at "11.4.3": Clarified }            │
     └────────┬─────────────────────────────────────────────┬───────┘
              │ &'static Clause                             │ Delta edges
              ▼                                             ▼
    ┌──────────────────────────┐                  ┌────────────────────┐
    │ KERNEL                   │                  │ DELTA GRAPH        │
    │ Clause, Constraint,      │◀─────────────────▶ version DAG per    │
    │ Rule, RuleSet, Outcome,  │                  │ standard; rules    │
    │ Version, DocumentRef,    │                  │ project through    │
    │ CitationChain,           │                  │ non-breaking edges │
    │ FrontendClaim            │                  └────────────────────┘
    └──────────┬───────────────┘
               │
               ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  AUTHORING SURFACES                                          │
     │                                                              │
     │  #[adr(42, cite = gp(V2_3, "11.4.3"),                        │
     │         governs = rule::sw_6a82_for_unknown_select)]         │
     │  impl GpCard for SimrsCard { … }                             │
     │                                                              │
     │  @spec:gp_2_3  @binds:11.4.3                                 │
     │  Scenario: SELECT unknown AID returns 6A82                   │
     │    …                                                         │
     └────────────────────────────┬─────────────────────────────────┘
                                  │
                                  ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  EXECUTION                                                   │
     │                                                              │
     │    Scenario ─expand─▶ Cartesian cases                        │
     │    each case ─run─▶ against each Frontend                    │
     │    produces Report { case, frontend, steps:                  │
     │                      [Step { world_before, transform,        │
     │                             world_after, observations }] }   │
     └────────────────────────────┬─────────────────────────────────┘
                                  │ Vec<Report>
                                  ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  DIFF ENGINE                  (pure function, no I/O)        │
     │    Vec<Report>  →  Vec<Divergence>                           │
     │  symmetric: no "reference" role, classification does that    │
     └────────────────────────────┬─────────────────────────────────┘
                                  │ Vec<Divergence>
                                  ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  CLASSIFIER                                                  │
     │    apply RuleSet  (ordered: test tolerances > backend-known  │
     │                    > standard) to each Divergence            │
     │    emit Outcome ∈ { Match, Regression, KnownDivergence,      │
     │                     DesignDecision, UnderReview,             │
     │                     BehavesLike(version), SpecDeviation }    │
     └────────────────────────────┬─────────────────────────────────┘
                                  │ classified outcomes
                                  ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  BUILD-TIME VALIDATORS                                       │
     │    • Confluence (rewriting sense): all applicable rules      │
     │      converge on one outcome per cfg                         │
     │    • Compatibility: active-ADR set forms consistent graph    │
     │      under each cfg assignment                               │
     │    • Product Variants: enumerate valid (cfg, claim, frontend)│
     │      tuples; flag incompatible combinations                  │
     │    • Citation drift: pinned versions vs. current             │
     │    • Orphans: clauses with no binding scenario, rules with   │
     │      no owning ADR, ADRs with no governed rules              │
     └────────────────────────────┬─────────────────────────────────┘
                                  │
                                  ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  BOOK OUTPUT                                                 │
     │    target/conformance-book/                                  │
     │    • standalone static site (mdbook-style + custom pages)    │
     │    • data-provenance embedded on every rendered element      │
     │    • provenance.json: machine-readable graph, all edges      │
     │    • forward-use index per clause / ADR / rule               │
     │    • backward-source trace per rendered line → PDF page +    │
     │      bbox, transcriber version, slicer patch set             │
     └──────────────────────────────────────────────────────────────┘
```

## The central claim in one line

The only writeable artefacts are: **normative sources** (third-party), the
**prose rationale sections of ADRs** (human), **slice/transform metadata**
(human + generated), and the **scenario bodies** (human). Everything else
— ADR frontmatter, citation indexes, compliance matrices, the book output,
the product-variant enumeration — is derived. The entire derivation chain
is typed; drift surfaces at build time; the output is self-proving.

## Stage boundaries

The pipeline is staged so each boundary has a typed artefact on either
side, and each stage is independently testable:

| Stage            | Input                                                    | Output                                   |
|------------------|----------------------------------------------------------|------------------------------------------|
| Transcribe       | `&Path` to source media                                  | `TranscriptionResult`                    |
| Slice            | `&TranscriptionResult`                                   | `Vec<Slice>`                             |
| Transform        | `&Slice`                                                 | `TransformResult<Constraint>`            |
| Spec emit        | `Vec<Slice> + Vec<Constraint>`                           | `&'static Spec` / `&'static [Clause]`    |
| Scenario expand  | `&Scenario`                                              | `impl Iterator<Item = CaseQuery>`        |
| Execute          | `CaseQuery + Frontend + &FrontendClaim + RunContext`     | `Report`                                 |
| Diff             | `&[Report] + &ClauseRegistry`                            | `Vec<Divergence>`                        |
| Classify         | `&[Divergence] + &RuleSet + &[FrontendClaim]`            | `Vec<ClassifiedOutcome>`                 |
| Validate (xtask) | `AdrGraph + CfgSpace + Claims`                           | `Vec<ValidationReport>`                  |
| Render (book)    | everything above                                         | static site + `provenance.json`          |

Workspace-scoped validation (confluence, compatibility, product
variants) runs as an `xtask` / CI step, not `cargo build`, because
`cargo` builds one crate at a time and the AdrGraph requires all
crates' contributions to be collected together. See chapter 17.

No stage depends on a stage below it. Any stage can be replaced or
tested in isolation.

## What this document is and is not

This chapter is the big picture. The diagrams and tables here are the
"30k-foot view" — enough to orient a reader before they read the rest of
the suite. The **type signatures** are in [03 — Kernel Types](03-kernel-types.md)
and [Appendix B](B-api-signatures.md). The **DSL grammars** are in
[Appendix A](A-grammar.md). The **end-to-end walkthrough** — one clause
flowing through every stage — is in [Appendix C](C-end-to-end-walkthrough.md).

If you want to understand **what changes for existing code**, read
[19 — Crate Layout](19-crate-layout.md) and [20 — Phases](20-phases.md).

If you want to understand **why this shape rather than another**, read
[00 — Motivation](00-motivation.md) and the ADRs linked from each chapter.

If you want to understand **what we deliberately do not build**, read
[21 — Non-Goals](21-non-goals.md).
