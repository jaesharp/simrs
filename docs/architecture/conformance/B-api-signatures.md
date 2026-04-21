# B — Public API Signatures

Authoritative public surface of the conformance engine's runtime
crates. Internal items, helpers, and `pub(crate)` APIs are not listed.

## `simrs-conformance`

```rust
// ===== Identity and versioning =====

pub enum SpecId { Gp, Iso7816(IsoPart), EtsiTs102221, Gsm1111, Emv(EmvBook), Simrs, Custom(&'static str) }
pub enum IsoPart { Part3, Part4, Part8, Part11 }
pub enum EmvBook { Book1, Book2, Book3, Book4 }

pub enum Version {
    Gp(GpVersion),
    Iso7816(IsoYear, IsoPart),
    Etsi(EtsiRelease),
    Semver(SemverVersion),
    Git(GitPin),
    Adr(AdrId),
}
pub enum GpVersion { V2_1_1, V2_2, V2_3, V2_3_1 }
pub struct IsoYear(pub u16);
pub struct EtsiRelease(pub u16);
pub struct SemverVersion(pub semver::Version);
pub struct GitPin(pub &'static str);

pub struct ClauseId(pub &'static str);
pub struct Locator(pub &'static str);
pub struct AdrId(pub u32);
pub struct RuleId(pub &'static str);
pub struct ScenarioId(pub &'static str);
pub struct FrontendId(pub &'static str);
pub struct ProfileId(pub &'static str);
pub struct StepId(pub &'static str);

// ===== Citations =====

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

impl CitationChain {
    pub fn new(refs: Vec<DocumentRef>) -> Self;
    pub fn with_rationale(self, r: &'static str) -> Self;
    pub fn clauses_only(&self) -> Vec<DocumentRef>;
    pub fn unattributed(d: &Divergence) -> Self;
    pub fn clone_with_div(&self, d: &Divergence) -> Self;
}

// ===== Clauses and constraints =====

pub trait Constraint: Sync + Send + 'static {
    fn shape(&self) -> ConstraintShape;
    fn satisfied_by(&self, observations: &[Observation]) -> SatisfactionResult;
    fn describe(&self) -> &'static str;
}

pub enum ConstraintShape {
    ExpectSw,
    ResponseLayout,
    TransitionTo,
    InvariantOver,
    Table,
    ProseOnly,
}

pub struct Clause {
    pub id: &'static ClauseId,
    pub spec: SpecId,
    pub version: Version,
    pub normative: NormativeType,
    pub prose: &'static str,
    pub constraint: &'static dyn Constraint,
    pub cross_refs: &'static [DocumentRef],
    pub profile: Option<ProfileId>,
    pub provenance: &'static ClauseProvenance,
}

pub enum NormativeType {
    Must, MustNot, Should, ShouldNot, May, Informative,
}

pub enum SatisfactionResult {
    Satisfied,
    Violated { reason: String },
    NotApplicable,
}

pub struct ClauseProvenance {
    pub source: SourceProvenance,
    pub slice: SliceProvenance,
    pub transform: TransformProvenance,
}

pub struct Spec {
    pub id: SpecId,
    pub version: Version,
    pub title: &'static str,
    pub clauses: &'static [&'static Clause],
}

// ===== Delta graph =====

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
    pub citations: &'static [DocumentRef],
}

pub enum DeltaKind {
    Added,
    Removed,
    Modified { before: ConstraintRef, after: ConstraintRef },
    Clarified,
    ErrataFix,
}

pub struct ConstraintRef(pub &'static str);  // path to a const in the spec crate

pub struct StandardGraphRegistry;
impl StandardGraphRegistry {
    pub fn register(graph: &'static StandardGraph);
    pub fn get(spec: SpecId) -> Option<&'static StandardGraph>;
    pub fn projects(&self, spec: SpecId, anchor: Version, target: Version, clause: &Locator) -> bool;
    pub fn effective_version(&self, spec: SpecId, declared: Version, clause: &Locator, obs: &Observation) -> Option<Version>;
}

// ===== Rules and outcomes =====

pub struct Rule {
    pub id: RuleId,
    pub guard: Box<dyn predicates::Predicate<Divergence> + Send + Sync>,
    pub when: RuleScope,
    pub outcome: OutcomeTemplate,
    pub citations: CitationChain,
}

pub struct RuleScope {
    pub specs: Option<&'static [SpecId]>,
    pub versions_from: Option<Version>,
    pub versions_to: Option<Version>,
    pub frontends: Option<&'static [FrontendId]>,
    pub axes: Option<AxisGuard>,
}

pub enum OutcomeTemplate {
    Match,
    Regression,
    KnownDivergence,
    DesignDecision,
    SpecDeviation,
    UnderReview,
    BehavesLike { effective: Version },
}

pub enum Outcome {
    Match,
    Regression(CitationChain),
    KnownDivergence(CitationChain),
    DesignDecision(CitationChain),
    SpecDeviation { claimed: Version, deviates_from: CitationChain },
    BehavesLike { claimed: Version, effective: Version, gap_clauses: Vec<DocumentRef> },
    UnderReview(CitationChain),
}

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn empty() -> Self;
    pub fn then(self, rules: &[Rule]) -> Self;
    pub fn classify(&self, d: &Divergence, claim: &FrontendClaim) -> Outcome;
    pub fn rule_for(&self, d: &Divergence, claim: &FrontendClaim) -> Option<RuleId>;
}

// ===== Frontend claims =====

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

// ===== Scenarios, axes, cases =====

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
    pub constraints: Vec<AxisConstraint>,
}

pub struct AxisName(pub &'static str);

pub enum AxisValue {
    Frontend(FrontendId),
    ScpVersion(ScpVersion),
    KeyVersion(KeyVersionNumber),
    Channel(ChannelId),
    Cvm(CvmPolicy),
    DeclaredStandard(ClaimedStandard),
    Custom(Arc<dyn AxisAtom>),
}

pub trait AxisAtom: Debug + Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn as_string(&self) -> String;
    fn as_any(&self) -> &dyn Any;
}

pub struct CaseQuery {
    pub scenario: ScenarioId,
    pub axes: BTreeMap<AxisName, AxisValue>,
}

pub enum StepTemplate {
    PowerOn,
    PowerOff,
    Reconnect,
    Select { aid: AxisRef<Aid> },
    OpenScp { version: AxisRef<ScpVersion>, kv: AxisRef<KeyVersionNumber> },
    GetStatus { p1: u8, p2: u8 },
    GetData { tag: u16 },
    ProbeRead(ProbeId),
    Wait(Duration),
    Custom(Arc<dyn StepImpl>),
}

pub enum AxisRef<T> {
    Literal(T),
    FromAxis(AxisName),
}

impl Scenario {
    pub fn expand(&self) -> Vec<CaseQuery>;
}

// ===== Reports =====

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
    pub duration: Duration,
    pub outcome: StepOutcome,
}

pub enum StepOutcome {
    Completed,
    Skipped { reason: SkipReason },
    Errored { error: StepError },
}

pub struct World { views: Vec<Box<dyn WorldView>> }

pub trait WorldView: Any + Debug + Send + Sync + 'static {
    fn fields(&self) -> &[WorldField];
    fn get(&self, field: &WorldField) -> Option<WorldValue>;
    fn merge(&mut self, other: &dyn WorldView);
}

pub struct WorldField(pub &'static str);
pub enum WorldValue { /* spec-contributed variants */ }

pub struct Transform { pub actions: Vec<Action> }

pub enum Action {
    PowerOn, PowerOff, Reconnect,
    Apdu(Vec<u8>),
    ScpInitUpdate { host_challenge: [u8; 8] },
    ScpExternalAuth { host_cryptogram: Vec<u8>, cmac: Vec<u8> },
    MacCommand { cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8> },
    ProbeRead(ProbeId),
    Wait(Duration),
    Custom(Arc<dyn ActionImpl>),
}

pub struct Observation {
    pub at: Timestamp,
    pub kind: ObservationKind,
    pub payload: ObservationPayload,
}

pub enum ObservationKind {
    ApduExchange, AtrReceived, FaultInjected, ProbeRead, SideChannel, Timing, LogLine,
}

pub enum ObservationPayload {
    Apdu { command: Vec<u8>, response: Vec<u8>, sw: Sw },
    Atr(Vec<u8>),
    Probe { id: ProbeId, response: Vec<u8> },
    Timing { start: Timestamp, end: Timestamp },
    Log { level: LogLevel, message: String },
    Bytes(Vec<u8>),
}

pub struct Sw(pub u8, pub u8);

// ===== Diff engine =====

pub enum Divergence {
    WorldField { case: CaseQuery, step: StepId, field: WorldField, per_report: BTreeMap<FrontendId, WorldValue>, agreement: AgreementGroups },
    Observation { case: CaseQuery, step: StepId, kind: ObservationKind, per_report: BTreeMap<FrontendId, Vec<Observation>> },
    StepMissing { case: CaseQuery, step: StepId, present_in: Vec<FrontendId>, missing_in: Vec<FrontendId> },
    StepExtra { case: CaseQuery, step: StepId, extra_in: Vec<FrontendId> },
    ConstraintUnsatisfied { case: CaseQuery, step: StepId, clause: DocumentRef, per_report: BTreeMap<FrontendId, SatisfactionResult> },
    TransformDiverge { case: CaseQuery, step: StepId, per_report: BTreeMap<FrontendId, TransformSummary> },
}

pub struct AgreementGroups {
    pub groups: Vec<BTreeSet<FrontendId>>,
}

pub struct DiffEngine;

impl DiffEngine {
    pub fn compare(reports: &[Report]) -> Vec<Divergence>;
    pub fn compare_cases(reports: &[Report]) -> BTreeMap<CaseQuery, Vec<Divergence>>;
}

// ===== Classifier =====

pub struct Classifier<'a> {
    pub rules: &'a RuleSet,
    pub claims: &'a [FrontendClaim],
    pub graph: &'a StandardGraphRegistry,
}

impl<'a> Classifier<'a> {
    pub fn classify(&self, divs: &[Divergence]) -> Vec<ClassifiedOutcome>;
}

pub struct ClassifiedOutcome {
    pub divergence: Divergence,
    pub outcome: Outcome,
    pub matched_rule: Option<RuleId>,
    pub citation_chain: CitationChain,
}

pub enum Severity {
    Match, KnownDivergence, BehavesLike, SpecDeviation, UnderReview, Regression,
}

impl ClassifiedOutcome {
    pub fn severity(&self) -> Severity;
}

pub fn worst_per_case(outcomes: &[ClassifiedOutcome]) -> BTreeMap<CaseQuery, Severity>;
pub fn compliance_matrix(outcomes: &[ClassifiedOutcome]) -> ComplianceMatrix;

// ===== Predicates (re-exports from predicates-rs) =====

pub mod predicate {
    pub fn step_is(id: StepId) -> impl Predicate<Divergence>;
    pub fn field_is(f: WorldField) -> impl Predicate<Divergence>;
    pub fn frontend_is(f: FrontendId) -> impl Predicate<Divergence>;
    pub fn axis_is(name: AxisName, value: AxisValue) -> impl Predicate<Divergence>;
    pub fn constraint_unsatisfied(by: SatisfactionKind) -> impl Predicate<Divergence>;
    pub fn any_of<P: Predicate<Divergence>>(ps: Vec<P>) -> impl Predicate<Divergence>;
    pub fn function<F: Fn(&Divergence) -> bool>(f: F) -> impl Predicate<Divergence>;
}
```

## `simrs-conformance-ingest`

```rust
pub trait Transcriber {
    type Source;
    fn id(&self) -> TranscriberId;
    fn version(&self) -> &'static str;
    fn transcribe(&self, src: Self::Source) -> TranscriptionResult;
}

pub struct TranscriptionResult {
    pub canonical_text: String,
    pub blocks: Vec<TextBlock>,
    pub tables: Vec<Table>,
    pub figures: Vec<Figure>,
    pub provenance: SourceProvenance,
    pub warnings: Vec<TranscriberWarning>,
}

pub struct TextBlock {
    pub id: BlockId,
    pub text: String,
    pub page: Option<u32>,
    pub bbox: Option<Bbox>,
    pub kind: BlockKind,
}

pub enum BlockKind { Paragraph, Heading { level: u8 }, ListItem, Caption, TableCell, Footnote }

pub trait Slicer {
    fn id(&self) -> SlicerId;
    fn slice(&self, t: &TranscriptionResult) -> Vec<Slice>;
}

pub struct Slice {
    pub clause_id: ClauseId,
    pub normative: Option<NormativeType>,
    pub text: CowStr,
    pub tables: Vec<TableRef>,
    pub figures: Vec<FigureRef>,
    pub provenance: SliceProvenance,
}

pub trait Transformer {
    fn id(&self) -> TransformerId;
    fn transform(&self, slice: &Slice) -> TransformResult<Constraint>;
}

pub enum TransformResult<T> {
    Ok(T),
    ProseOnly { reason: &'static str },
    Ambiguous(Vec<T>),
    Failed { reason: &'static str },
}

pub struct SourceProvenance { ... }
pub struct SliceProvenance { ... }
pub struct TransformProvenance { ... }
```

## `simrs-adr`

```rust
pub struct AdrGraph {
    sites: Vec<AdrSite>,
    nodes: BTreeMap<AdrId, AdrNode>,
    edges: Vec<AdrEdge>,
}

impl AdrGraph {
    pub fn collect() -> Self;  // walks inventory registrations
    pub fn confluence(&self, cfg: &CfgAssignment) -> Result<Vec<AdrId>, Vec<ConfluenceFail>>;
    pub fn compatibility(&self, cfg: &CfgAssignment) -> Result<(), Vec<CompatFail>>;
    pub fn product_variants(&self, policy: &VariantPolicy) -> Vec<VariantValidation>;
    pub fn render_md(&self, out: &Path) -> io::Result<()>;
    pub fn drift(&self) -> Vec<DriftWarning>;
}

pub struct AdrSite {
    pub adr: AdrId,
    pub cfg: CfgExpr,
    pub cites: Vec<DocumentRef>,
    pub governs: Vec<RuleId>,
    pub implements: Option<AdrId>,
    pub location: SourceLocation,
}

pub struct VariantPolicy {
    pub allow_empty: bool,
    pub required: Vec<FeatureSet>,
    pub disjoint_exclusive: Vec<Vec<FeatureId>>,
    pub forbidden: Vec<CfgExpr>,
    pub required_pairs: Vec<(CfgExpr, CfgExpr)>,
}
```

## `simrs-conformance-book`

```rust
pub struct BookGenerator {
    pub adr_graph: AdrGraph,
    pub spec_registry: SpecRegistry,
    pub reports: Vec<Report>,
    pub outcomes: Vec<ClassifiedOutcome>,
    pub variants: Vec<VariantValidation>,
}

impl BookGenerator {
    pub fn render(&self, out_dir: &Path) -> io::Result<BookStats>;
}

pub struct BookStats {
    pub pages_emitted: usize,
    pub provenance_edges: usize,
    pub warnings: Vec<String>,
}
```

## `simrs-conformance-gherkin`

```rust
pub struct GherkinParser;

impl GherkinParser {
    pub fn parse(feature_path: &Path) -> Result<Vec<Scenario>, GherkinError>;
    pub fn parse_dir(dir: &Path) -> Result<Vec<Scenario>, GherkinError>;
    pub fn validate_bindings(scenarios: &[Scenario]) -> Vec<BindingError>;
}

pub struct StepRegistry;

impl StepRegistry {
    pub fn register(def: StepDef);
    pub fn match_phrase(phrase: &str) -> Option<&StepDef>;
    pub fn all() -> &'static [StepDef];
}
```

## Forward compatibility

All public types are `#[non_exhaustive]` by default; new variants can
be added in minor releases. Adding fields to public structs requires
the `#[non_exhaustive]` attribute on the struct or a major version
bump.
