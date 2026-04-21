# 03 — Kernel Types

The kernel lives in `crates/simrs-conformance`. Every type here is
`#![no_std]` + `alloc` where possible, with `std` available behind a
feature flag for the parts that need file I/O and threading.

## Identity and versioning

```rust
pub enum SpecId {
    Gp,                        // GlobalPlatform
    Iso7816(IsoPart),          // ISO/IEC 7816 parts 3, 4, 8, 11
    EtsiTs102221,              // ETSI TS 102.221 (UICC)
    Gsm1111,                   // 3GPP / legacy GSM 11.11
    Emv(EmvBook),              // EMV Books 1..4
    Simrs,                     // our own normative docs (ADRs, design)
    Custom(&'static str),      // for domain-specific standards
}

/// Per-frontend classification surface.
///
/// Three-way divergences (three reports, three different values) need
/// per-frontend outcomes, not one outcome per divergence. The
/// classifier emits one `ClassifiedOutcome` per `(divergence, frontend)`
/// pair.
pub struct ClassifiedOutcome {
    pub divergence_id: DivergenceId,
    pub frontend: FrontendId,
    pub outcome: Outcome,
    pub matched_rule: Option<RuleId>,
    pub citation_chain: CitationChain,
}

pub struct DivergenceId(pub u64);

pub enum Version {
    Gp(GpVersion),             // V2_1_1, V2_2, V2_3, V2_3_1
    Iso7816(IsoYear, IsoPart), // IsoYear(2005), IsoPart(4)
    Etsi(EtsiRelease),         // Rel18 = 18, etc.
    Semver(SemverVersion),     // vendor backends
    Git(GitPin),                // internal pins (commit SHA or tag)
    Adr(AdrId),                // internal ADR references
}

pub struct Locator(&'static str);    // "11.4.3", "§5.1.1", "Figure 6-2"
pub struct ClauseId(&'static str);
pub struct AdrId(u32);
pub struct RuleId(&'static str);
pub struct ScenarioId(&'static str);
pub struct FrontendId(&'static str); // "simrs", "jcsl", "jcardengine"
```

Each `Version` variant is its own enum; versions from different
documents are not comparable. A build-time macro (`version!("GP", "2.3")`)
produces the typed variant.

## DocumentRef and citations

```rust
pub enum DocumentRef {
    Gp(GpVersion, Locator),
    Iso7816(IsoPart, IsoYear, Locator),
    Etsi(EtsiSpec, EtsiRelease, Locator),
    Emv(EmvBook, EmvVersion, Locator),
    Jcardengine(SemverPin, SourceLoc),
    Jcsl(OracleReleaseTag, SourceLoc),
    Simrs(GitPin, Locator),
    Adr(AdrId),
    Rule(RuleId),
}

pub struct CitationChain {
    pub refs: Vec<DocumentRef>,
    pub rationale: &'static str,
}
```

`DocumentRef` is always typed — there is no `String` spelling anywhere
in the citation graph. Construction funnels through macros that
validate at compile time: `gp(V2_3, "11.4.3")` expands to
`DocumentRef::Gp(GpVersion::V2_3, Locator::from_static("11.4.3"))`.

## Clause and Constraint

```rust
pub struct Clause {
    pub id: &'static ClauseId,
    pub spec: SpecId,
    pub version: Version,
    pub normative: NormativeType,
    pub prose: &'static str,
    pub constraint: &'static dyn Constraint,
    pub cross_refs: &'static [DocumentRef],
    pub profile: Option<ProfileId>,      // SCP03 profile, contactless-only, etc.
    pub provenance: &'static ClauseProvenance,
}

pub enum NormativeType {
    Must, MustNot,
    Should, ShouldNot,
    May,
    Informative,
}

pub trait Constraint: Sync {
    fn shape(&self) -> ConstraintShape;
    fn satisfied_by(&self, observations: &[Observation]) -> SatisfactionResult;
    fn describe(&self) -> &'static str;  // one-line summary for reports
}

pub enum ConstraintShape {
    ExpectSw,
    ResponseLayout,
    TransitionTo,
    InvariantOver,
    Table,
    ProseOnly,
    // Additional variants require a kernel minor version bump; each
    // spec crate that needs a new shape contributes the enum variant
    // via a `#[non_exhaustive]`-governed PR.
}

pub struct ClauseProvenance {
    pub source: SourceProvenance,
    pub slice: SliceProvenance,
    pub transform: TransformProvenance,
}
```

`Constraint` is a trait so spec crates can contribute novel constraint
kinds (GP has different shapes than ETSI). The `ConstraintShape`
enum is the binding key used by the Gherkin parser for type-checked
scenario ↔ clause binding.

## Delta graph

```rust
pub struct StandardGraph {
    pub spec: SpecId,
    pub versions: &'static [Version],
    pub deltas: &'static [Delta],
}

pub struct Delta {
    pub from: Version,
    pub to: Version,
    pub clause: Locator,
    pub kind: DeltaKind,
    pub rationale: &'static str,
    pub citations: &'static [DocumentRef],  // errata, change-request refs
}

pub enum DeltaKind {
    Added,
    Removed,
    Modified {
        before: ConstraintRef,
        after: ConstraintRef,
    },
    Clarified,
    ErrataFix,
}
```

`StandardGraph` is consumed by the classifier to project rules
forward/backward through non-breaking edges.

## Rules and outcomes

```rust
pub struct Rule {
    pub id: RuleId,
    pub guard: Box<dyn Predicate<Divergence> + Send + Sync>, // predicates-rs
    pub when: RuleScope,
    pub outcome: OutcomeTemplate,
    pub citations: CitationChain,
}

pub struct RuleScope {
    pub specs: Option<&'static [SpecId]>,         // restrict by standard
    pub versions_from: Option<Version>,            // inclusive lower bound in DAG
    pub versions_to: Option<Version>,              // inclusive upper bound in DAG
    pub frontends: Option<&'static [FrontendId]>,  // restrict by frontend
    pub axes: Option<AxisGuard>,                   // restrict by axis values
}

pub enum Outcome {
    Match,
    Regression(CitationChain),
    KnownDivergence(CitationChain),
    DesignDecision(CitationChain),
    SpecDeviation {
        claimed: Version,
        deviates_from: CitationChain,
    },
    BehavesLike {
        claimed: Version,
        effective: Version,
        gap_clauses: Vec<DocumentRef>,
    },
    UnderReview(CitationChain),
}

pub struct RuleSet {
    rules: Vec<Rule>,  // ordered; first match wins
}

impl RuleSet {
    pub fn classify(&self, d: &Divergence, claim: &FrontendClaim) -> Outcome;
}
```

The guard is a `predicates-rs` `Predicate<Divergence>`. First-match
wins; unmatched divergences default to `Regression` with an
auto-generated citation pointing at the standard clause the divergence
violates (if inferrable) or `Regression { unattributed: true }`.

## Frontend and claims

```rust
pub struct FrontendId(&'static str);

pub struct FrontendClaim {
    pub frontend: FrontendId,
    pub standards: Vec<ClaimedStandard>,
    pub profile_bundles: Vec<ProfileBundle>,
    pub cfg_scope: Option<CfgAssignment>,
}

pub struct ClaimedStandard {
    pub spec: SpecId,
    pub version: Version,
    pub range: VersionRange,
    pub profiles: Vec<ProfileId>,
}

pub enum VersionRange {
    Exact(Version),
    Inclusive { low: Version, high: Version },
    ForwardCompat { from: Version },
}

pub struct ProfileBundle {
    pub name: ProfileId,
    pub requires: Vec<ClaimedStandard>,
}
```

Claims are data. A frontend says "I implement GP 2.3 with the SCP03
profile under `cfg(feature = "scp03")`." The classifier uses this to
decide which rules apply and whether a divergence constitutes a
claim falsification.

## Scenarios, axes, cases

```rust
pub struct Scenario {
    pub id: ScenarioId,
    pub axes: Vec<Axis>,
    pub steps: Vec<StepTemplate>,
    pub citations: CitationChain,
    pub binds: Vec<&'static Clause>,
}

pub struct Axis {
    pub name: AxisName,
    pub values: Vec<AxisValue>,
    pub constraints: Vec<AxisConstraint>, // e.g. "scp_version = SCP02 requires feature = scp02"
}

pub enum AxisValue {
    Frontend(FrontendId),
    ScpVersion(ScpVersion),
    KeyVersion(KeyVersionNumber),
    Channel(ChannelId),
    Cvm(CvmPolicy),
    DeclaredStandard(ClaimedStandard),
    Custom(Arc<dyn AxisAtom>),
}

pub struct CaseQuery {
    pub scenario: ScenarioId,
    pub axes: BTreeMap<AxisName, AxisValue>,
}
```

`Scenario::expand(&self) -> Vec<CaseQuery>` does the Cartesian
product minus constraint-violating points.

## Reports

```rust
pub struct Report {
    pub case: CaseQuery,
    pub frontend: FrontendId,
    pub claims: Vec<ClaimedStandard>,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub steps: Vec<Step>,
    pub provenance: RunProvenance,
}

pub struct Step {
    pub id: StepId,
    pub world_before: World,
    pub transform: Transform,
    pub world_after: World,
    pub observations: Vec<Observation>,
}

pub struct Transform {
    pub actions: Vec<Action>,
}

pub enum Action {
    Apdu(Vec<u8>),
    PowerOn,
    PowerOff,
    Reconnect,
    ScpInitUpdate { host_challenge: [u8; 8] },
    ScpExternalAuth,
    ProbeRead(ProbeId),
    Wait(Duration),
    // … extensible
}

pub struct Observation {
    pub at: Timestamp,
    pub kind: ObservationKind,
    pub payload: ObservationPayload,
}

pub enum ObservationKind {
    ApduExchange,
    AtrReceived,
    FaultInjected,
    ProbeRead,
    SideChannel,
}
```

`World` is a trait object composed from contributions per domain:

```rust
pub trait WorldView: 'static {
    fn fields(&self) -> &[WorldField];
    fn get(&self, field: &WorldField) -> Option<WorldValue>;
}

pub struct World {
    views: Vec<Box<dyn WorldView>>,
}
```

Spec crates contribute `WorldView` implementations: `GpWorldView`
exposes ISD selection, SCP session state; `IsoWorldView` exposes
channel state and lifecycle; a test-harness domain can add probe
counters without touching the kernel.

## Diffs and divergences

```rust
pub enum Divergence {
    WorldField {
        case: CaseQuery,
        step: StepId,
        field: WorldField,
        per_report: BTreeMap<FrontendId, WorldValue>,
        agreement: AgreementGroups,
    },
    Observation {
        case: CaseQuery,
        step: StepId,
        kind: ObservationKind,
        per_report: BTreeMap<FrontendId, Vec<Observation>>,
    },
    StepMissing {
        case: CaseQuery,
        step: StepId,
        present_in: Vec<FrontendId>,
        missing_in: Vec<FrontendId>,
    },
    StepExtra {
        case: CaseQuery,
        step: StepId,
        extra_in: Vec<FrontendId>,
    },
    ConstraintUnsatisfied {
        case: CaseQuery,
        step: StepId,
        clause: DocumentRef,
        per_report: BTreeMap<FrontendId, SatisfactionResult>,
    },
    TransformDiverge {
        case: CaseQuery,
        step: StepId,
        per_report: BTreeMap<FrontendId, TransformSummary>,
    },
}

pub struct AgreementGroups {
    pub groups: Vec<BTreeSet<FrontendId>>,
}

pub struct DiffEngine;

impl DiffEngine {
    pub fn compare(reports: &[Report], clauses: &ClauseRegistry) -> Vec<Divergence>;
}
```

`DiffEngine` is a pure function. It owns no state. Given the same
reports it produces the same divergences, in the same order.

## Summary

These are the types. Everything else in the kernel is a function over
these types. The public API is enumerated in [Appendix B](B-api-signatures.md).
The full grammars for the `spec!` / `clause!` / `deltas!` / Gherkin
tags are in [Appendix A](A-grammar.md). Each type's invariants are
documented in the rustdoc that ships with the crate; the chapters
that follow explain how they compose.
