# D — Glossary

Pinned definitions for every term used in this suite. Terms are
ordered alphabetically within each category.

## Pipeline terms

**AdrGraph** — the directed graph assembled at build time from every
`#[adr(N)]` site, its cfg predicate, its cited clauses, and its
governed rules. Used by confluence and compatibility checkers and by
the product validator.

**Axis** — a declared parameter dimension on a `Scenario`. Examples:
`frontend`, `scp_version`, `key_version`. Each axis has a typed set of
values; cases are points in the Cartesian product of axes.

**Axis constraint** — a rule that excludes, requires, or mirrors axis
values during Cartesian expansion. Enforced at expansion time; does
not reach runtime.

**BehavesLike(V)** — an `Outcome` emitted when a frontend's observed
behaviour at a clause matches the constraint of an earlier version V
despite the frontend claiming a later version. Derived by walking the
delta graph from the claimed version backward.

**Binding** — a typed association between a Gherkin scenario (or
`#[conformance_test]` function) and a `Clause`, declared via `@binds`
or the macro's `binds` parameter. The scenario's observations must
satisfy the clause's `Constraint`; failing to do so is a build error.

**Book** — the final rendered output of a build: a standalone,
offline-browsable static site in `target/conformance-book/` whose
every line carries `data-provenance` backward to source and
`forward-use` metadata forward to every use.

**CardFrontend** — synonym for `Frontend`. The term was used earlier
in design discussion; the suite uses `Frontend` throughout.

**CaseQuery** — one concrete point in a scenario's parameter space.
Produced by `Scenario::expand()`. Each case runs against each
frontend and produces one `Report`.

**Citation** — a typed reference (`DocumentRef`) from an artefact
(rule, ADR, impl, scenario) to a normative source. All citations are
typed; no string forms exist in the kernel.

**CitationChain** — an ordered list of `DocumentRef`s accompanying a
classified outcome, traced from the specific rule back to the
governing spec clauses.

**Clause** — a typed, addressable unit of a normative standard.
Carries prose, a `Constraint`, cross-references, provenance back to
source, and a `Version` pinning.

**Confluence** — the rewriting-sense property that applying all
applicable ADR contributions at a clause yields a single normal form.
Required under every cfg assignment.

**Compatibility** — the constraint-satisfaction property that active
ADRs under a cfg assignment form a consistent, acyclic graph.

**Constraint** — a trait-object that encodes an executable predicate
over observations. Produced by the `Transform` stage from slice
prose; satisfied or violated by observations at runtime.

**Delta** — a typed edge in a `StandardGraph` between two versions at
a specific clause, with `DeltaKind` (Added/Removed/Modified/Clarified/
ErrataFix).

**DiffEngine** — the pure function `Vec<Report> → Vec<Divergence>`.
No state, no I/O, symmetric over its input reports.

**Divergence** — a typed value produced by the `DiffEngine` describing
a disagreement among reports at a specific case, step, and field
(or step-presence, or constraint-satisfaction result).

**DocumentRef** — a typed citation to a specific clause / section /
location in a specific version of a specific document (standard, ADR,
internal commit, etc.).

**Effective version** — the version of a standard that a frontend's
observed behaviour actually matches at a given clause, as determined
by walking the delta graph. May differ from the frontend's declared
version.

**Frontend** — an implementation under test: our simrs card, an
external reference simulator, a physical card. Implemented as a
`CardFrontend` trait-adapter crate per implementation.

**FrontendClaim** — a declarative statement from a frontend of which
standards/versions/profiles it implements, possibly scoped by cfg.
Used by the classifier to decide rule applicability.

**Generated sections** — the parts of an ADR markdown file that are
re-emitted on each build from `#[adr]` site metadata. Includes the
frontmatter, citation lists, "Cited by" index, and compatibility
summary. Author-maintained sections (rationale, consequences) are
preserved verbatim between regenerations.

**Outcome** — the classifier's verdict for a divergence. Values:
`Match`, `Regression`, `KnownDivergence`, `DesignDecision`,
`SpecDeviation`, `BehavesLike`, `UnderReview`.

**Predicate** — a `predicates::Predicate<Divergence>` value used as a
rule's guard. Composable via `.and()`, `.or()`, `.not()`,
`.function(|d| ...)`.

**Product variant** — one satisfying cfg assignment paired with its
active ADR set and the frontends it enables. Each variant is valid
(passes confluence + compatibility) or invalid (fails). The product
validator enumerates all satisfying assignments.

**Provenance** — the typed ancestry of an artefact. Every clause,
every rule, every outcome carries a provenance chain from its
concrete identity back to the source document and forward to every
use.

**Report** — the execution artefact for one (CaseQuery, Frontend)
pair: metadata plus an ordered list of Steps with per-step World
transitions, Transforms, and Observations.

**Rule** — a `(guard, scope, outcome_template, citations)` tuple.
Applied to divergences in RuleSet order; first match wins.

**RuleSet** — an ordered composition of rules. Built from standards
modules, backend-adapter contributions, ADR-owned rules, and test
tolerances.

**Scenario** — a parameterised test template with typed axes, citations,
clause bindings, and step templates. Expands to a set of CaseQuery
values.

**Slice** — a structured, addressable fragment of a transcription
associated with a clause id, prose, and normative keyword. Authored
as TOML with references into the transcription cache.

**Spec** — an encoded standard: an `&'static Spec` value exposing
the spec's id, version, title, and clause list. Produced by the
`spec!` macro in a `simrs-spec-*` crate.

**StandardGraph** — the per-spec DAG of versions connected by
`Delta` edges. Used to project rules across versions and to detect
`BehavesLike` situations.

**Step** — one semantic operation within a scenario, identified by
`StepId`. Steps synchronise across frontends — all reports that ran
the same case produce the same steps by id, even though the
per-frontend transforms differ.

**Transcriber** — the trait for stage-1 ingestion. Takes source media,
produces a `TranscriptionResult`. Pluggable per format.

**Transcription** — the cached, structured result of running a
Transcriber over a source file. Committed to the spec crate's
`transcription/cache/` directory.

**Transform** (noun, stage 3) — the `TransformResult<Constraint>`
produced by a `Transformer` from a `Slice`. Encodes the human-to-
machine semantic bridge.

**Transform** (noun, in Report) — the per-frontend action sequence
executed to realise a step. Differs across frontends for the same
step; included in the report as evidence of what the frontend did.

**Transformer** — the trait for stage-3 ingestion. Takes a `Slice`,
produces a `Constraint`.

**Variant policy** — workspace-level declarations that constrain the
valid cfg space (`disjoint_exclusive`, `forbidden`, `required_pairs`).

**Version** — a typed, per-document variant of the `Version` enum.
`Version::Gp(GpVersion::V2_3)`. Not comparable across spec IDs.

**Witness** — an implementation impl block that satisfies an
ADR-governed trait. Every governed trait must have ≥1 witness active
under each cfg assignment that exercises the trait.

**World** — the semantic state of a card at a step boundary. Composed
from multiple `WorldView` contributions from spec crates.

**WorldField** — a typed field name within a World view.

**WorldValue** — a typed value for a WorldField.

**WorldView** — a trait-object contribution to the composite `World`,
providing a set of fields and a getter. Spec crates contribute
views; domains stack orthogonally.

## ADR terminology

**Accepted** — ADR status after reviewer signatures. Not yet in force;
an implementation may be pending.

**ActiveUnder** — the cfg predicate under which an ADR applies. `Any`
means the ADR is always active.

**Author-maintained section** — the prose portion of an ADR below the
`<!-- === AUTHOR NOTES === -->` sentinel. Preserved between
regenerations.

**Deprecated** — ADR status indicating a decision is no longer
recommended but has not yet been superseded or retracted.

**InForce** — ADR status indicating the decision is active and
implementations must conform. Only InForce ADRs contribute to
confluence/compatibility checks.

**Orphan ADR** — an in-force ADR that governs no rules and implements
no traits. Build error.

**Proposed** — ADR status immediately after `adr new`. Not yet
reviewed.

**Retracted** — ADR status indicating the decision has been withdrawn
without a successor; carries a `retraction_reason`.

**Superseded** — ADR status indicating the decision has been replaced
by a later ADR named in `superseded_by`.

**Sunset** — optional date on a Deprecated ADR after which the
warning escalates to an error.

## Spec-body abbreviations used throughout

- **ADR** — Architecture Decision Record.
- **AID** — Application Identifier (ISO 7816-4 / GP).
- **APDU** — Application Protocol Data Unit.
- **CVM** — Cardholder Verification Method (EMV / GP).
- **ETSI** — European Telecommunications Standards Institute.
- **FCI** — File Control Information (ISO 7816-4).
- **GP** — GlobalPlatform.
- **ISD** — Issuer Security Domain (GP).
- **ISO** — International Organization for Standardization.
- **SCP** — Secure Channel Protocol (GP): SCP01, SCP02, SCP03.
- **SW** — Status Word (2-byte APDU response suffix).
- **TS** — Technical Specification (ETSI / 3GPP).
- **UICC** — Universal Integrated Circuit Card (SIM hardware substrate).
- **USIM** — Universal Subscriber Identity Module.

## Cross-reference conventions

Within this suite, chapter references use the form `[N — Title](N-title.md)`.
Terms defined here link back to this glossary where ambiguity would
otherwise arise. The book renders the glossary as an alphabetically-
navigable page with cross-links to every chapter where each term is
used.
