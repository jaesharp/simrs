# 21 — Non-Goals

This chapter pins what the conformance engine deliberately does not do.
Explicit non-goals prevent scope creep and give reviewers a clean way
to route related-but-different requests to other systems.

## The engine is not

### A general-purpose rules engine

No Datalog evaluation, no fixpoint computation, no pattern-matching
DSL richer than `predicates-rs` combinators. When a rule requires
arbitrary computation, it is written in Rust; the engine is a loop.
If a use case demands richer evaluation semantics, the answer is to
pre-compute the rule's guard in Rust rather than embed an engine.

### A general-purpose ADR tool

The opinionated ADR tooling (`simrs-adr`) is tailored to this engine's
state machine and citation invariants. It is not a drop-in replacement
for `adrs`, `adr-tools`, `ADRust`, or e-adr. Projects without the
citation graph, the product validator, and the book output will find
the refusals annoying; those projects should use the generic tools.

### A production build system

`simrs-adr`'s product validator enumerates cfg variants but does not
*build* them. It reports whether each variant would cohere. Actually
compiling and testing every variant is a separate CI concern; the
validator's job is to prove the configuration space is well-formed
before any build starts.

### A runtime policy engine

The classifier runs at test time, not at production runtime. We do
not ship rule evaluation into the card or the SIM daemon. A failing
rule classification means "this test revealed a divergence worth
reviewing"; it does not mean "the card should reject this command."

### A theorem prover

Confluence checking in the rewriting sense is shallow — it asserts
that the ADR contributions at each clause agree, not that the
contributions are *correct* with respect to the spec prose. The engine
catches inconsistencies among decisions; it does not replace
specification review.

### A documentation generator for arbitrary content

The book output is specific to the conformance engine's artefacts:
specs, clauses, ADRs, rules, scenarios, frontends, variants,
reports. It is not a replacement for rustdoc, mdbook, or a wiki.
Generic project documentation continues to live in `docs/` outside
the conformance suite.

## Standards coverage we do not claim

### All of GlobalPlatform

We encode the GP clauses that `simrs` exercises. Composition services,
card-manager privileges we don't implement, supplementary security
domains, confidential cardholder verification — these will come as
`simrs` grows coverage, not as an up-front spec ingestion effort.

### All of ISO 7816

Part 4 (APDU commands, file system) is in scope. Parts 1–3
(physical / electrical), Part 8 (crypto commands), Part 11
(biometric) — encoded opportunistically, not systematically, until
there is a `simrs` feature that needs them.

### All of EMV

EMV is not in Phase A. When payment scenarios become relevant, Phase
C adds the EMV spec crates; they compose into the engine without
shape changes.

### All of 3GPP / ETSI

USIM AKA and related ETSI-TS-102.221 / 3GPP TS 31.10x clauses are in
scope because we implement them. Everything beyond the SIM surface
(network protocols, core network) is out of scope.

## Implementation surfaces we do not instrument

### simrs internal CPU / VM state (beyond current hooks)

`simrs-jcvm`'s hypervisor hooks (opcode counters, frame depth) are
exposed via the controlplane probes for simrs-only tests. The
conformance engine consumes them as observations but does not require
them for reference backends. We will not port controlplane probes to
a GP-loadable CAP file (as discussed before the design re-frame;
the right answer turned out to be the Frontend abstraction).

### Hardware side channels

Timing-channel validation and constant-time assertions live in
`simrs-consttime-validation` and stay there. The conformance engine
can read their reports as Observations but does not own the
measurement apparatus.

### Performance / throughput

The engine does not measure or compare APDU-per-second throughput,
command latency distributions, memory footprint, or any performance
property. Those belong in separate benchmarks (criterion, iai) that
consume conformance-engine reports only for correctness co-validation.

## Authoring affordances we do not provide

### A WYSIWYG ADR editor

ADR authoring is text-file editing with `adr new` providing scaffolds.
No GUI, no editor plugin beyond whatever the contributor's `$EDITOR`
offers.

### Rich scenario authoring UIs

Scenarios are Gherkin or Rust. No visual scenario builder, no record-
and-playback harness. The APDU trace format is authoritative.

### Live spec editing

Spec crates are code; editing a clause means editing the slice TOML
and/or the manual transform and re-running the build. No runtime
editing of clauses; no hot-reload of the rule set.

## Classification we do not do

### Severity scoring beyond the outcome enum

The outcome enum is a lattice (`Match < KnownDivergence <
DesignDecision < BehavesLike < SpecDeviation < Regression`); we do
not attach numeric scores, risk rankings, or customer-severity fields.
Downstream tooling that wants a quantitative conformance score derives
it from the outcome distribution.

### Automatic remediation suggestions (beyond confluence/compat fixes)

The confluence and compatibility checkers emit structural fix
suggestions (narrow scope, supersede, split clause). Beyond that, the
engine does not propose code changes or rule edits. Maintainers remain
the decision-makers.

### Risk modelling

We do not model vulnerability likelihood, exploit complexity, or
impact severity. A `Regression` is a divergence from spec, not a
security finding.

## Output we do not emit

### PDF / paper-formatted compliance reports (directly)

The book is HTML + JSON. PDF generation is a downstream concern:
consumers who need it run a headless browser print pipeline or a
markdown-to-PDF converter over the book content. The engine does not
ship a PDF renderer.

### Regulatory-certification-body report formats

Certain certification bodies (FIPS 140-3 modules, Common Criteria EAL
evaluations) require report templates in proprietary formats. The
engine does not target any specific body's format; `provenance.json`
is the machine-readable canonical, and downstream adapters produce
body-specific reports from it.

## Revision policy

Adding items to this list is a normal change (it narrows scope and
never breaks downstream). Removing items — i.e., deciding the engine
now does something we said we would not — is a significant change
that merits an ADR and a migration plan.
