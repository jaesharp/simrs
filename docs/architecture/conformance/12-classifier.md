# 12 — Classifier

The classifier takes `Vec<Divergence>`, a composed `RuleSet`, and the
active `Vec<FrontendClaim>`, and emits `Vec<Outcome>`. It is the
second half of the pure-function pipeline: given the same inputs it
always produces the same outputs, in the same order.

## Entry point

```rust
pub struct Classifier<'a> {
    rules: &'a RuleSet,
    claims: &'a [FrontendClaim],
    graph: &'a StandardGraphRegistry,
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
```

The `matched_rule` field records which rule fired (or `None` for
unattributed `Regression`s). The `citation_chain` consolidates all
citations that went into the classification decision.

## The loop

```rust
for div in divs {
    let claim = self.claim_for(div.frontend());
    let outcome = self.rules.classify(div, claim);
    let matched = self.rules.rule_for(div, claim);    // for reporting
    out.push(ClassifiedOutcome { divergence: div.clone(), outcome, matched_rule: matched, citation_chain: ... });
}
```

Every divergence produces exactly one classified outcome. The order
matches the input divergence order; no re-sorting.

## Rule scope evaluation

For each divergence, the classifier's `rules.classify(d, claim)`
evaluates rules in order. For each rule:

1. Check `rule.when.specs`: if set, the divergence's cited spec(s)
   must overlap.
2. Check `rule.when.versions`: if set, the frontend's claim must
   have a version within the rule's scoped range (accounting for
   delta-graph projection).
3. Check `rule.when.frontends`: if set, the divergence's frontend
   must be in the list.
4. Check `rule.when.axes`: if set, the divergence's case axes must
   satisfy the axis guard.
5. If all `when` checks pass, evaluate `rule.guard`.
6. On match, materialise the outcome; stop searching.

## BehavesLike synthesis

When a divergence touches a clause C under frontend claim V_declared,
and no explicit `BehavesLike` rule matches, the classifier
*automatically* evaluates claim falsification:

1. Walk the delta graph for C's spec from V_declared backward.
2. For each predecessor version V_w, look up the `before` constraint
   of any `Modified` delta on the path.
3. If the frontend's observed behaviour satisfies `before` but not
   `after`, emit `BehavesLike { claimed: V_declared, effective: V_w, gap_clauses: [C] }`.
4. Stop at the earliest matching V_w.

This is an automatic secondary pass — it runs only for divergences
that would otherwise be classified `Regression` or
`ConstraintUnsatisfied`. Explicit rules can preempt it by matching
first.

## Citation-chain assembly

Each classified outcome carries a citation chain assembled from:

- The matched rule's own citations.
- The cited clause(s) of the divergence.
- The frontend's claim (version + profile).
- The delta(s) traversed for `BehavesLike` decisions.

The chain is ordered from most specific (the rule) to most general
(the spec version). The book renders the chain as a breadcrumb trail
under each outcome.

## Aggregation

Per-case aggregation is a consumer's job, but the classifier provides
convenient reducers:

```rust
impl ClassifiedOutcome {
    pub fn severity(&self) -> Severity;  // Match < KnownDivergence < BehavesLike < SpecDeviation < Regression
}

pub fn worst_per_case(outcomes: &[ClassifiedOutcome]) -> BTreeMap<CaseQuery, Severity>;
pub fn compliance_matrix(outcomes: &[ClassifiedOutcome]) -> ComplianceMatrix;
```

`ComplianceMatrix` is the per-clause × per-frontend grid rendered in
the book.

## Testing

Classifier behaviour is pinned by fixtures:

- Given `(divergence_fixture, ruleset_fixture, claim_fixture)`,
  assert `(outcome, matched_rule, citation_chain)`.
- `insta` snapshots for canonical ruleset compositions.

## Side-effect policy

The classifier does not log, does not write files, does not mutate
shared state. Diagnostic output (the book's citation pages, the
compliance matrix) is emitted from consumers of the classifier's
output; the classifier itself is pure.
