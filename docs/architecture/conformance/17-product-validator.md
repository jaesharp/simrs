# 17 — Product Validator

The product validator is the build-time component that enumerates
every valid product variant the codebase can emit, validates each one
for confluence + compatibility, and reports the result as a structured
matrix. It is the forcing function that turns "configurability" from
a latent liability into an auditable property.

## What counts as a "product variant"

A product variant is a tuple of choices that together produce one
buildable binary / test target:

- **Feature-flag assignment**: a subset of the workspace's declared
  Cargo features, subject to any `disjoint_exclusive` or `required`
  policies.
- **Platform target**: Linux / macOS / Windows / embedded targets, when
  they meaningfully affect the active ADR set.
- **Build profile**: dev / release / custom profiles that gate
  optimisations or feature flags.
- **Frontend identity**: the variant's "claimed frontend" for
  conformance purposes (a given cfg may produce multiple frontends
  that test separately, e.g. simrs-standard and simrs-embedded).

A product variant is *valid* iff:

1. The cfg assignment is internally consistent per policy
   (`disjoint_exclusive`, `required`, `forbidden_pairs`).
2. The AdrGraph under the cfg passes confluence (chapter 16).
3. The AdrGraph under the cfg passes compatibility.
4. The frontend claims under the cfg form a consistent set.

Every invalid variant is a build error — you cannot commit a
repository that contains an invalid (and non-impossible) variant.

## Enumeration

For small feature counts (n ≤ 20), the validator enumerates the full
power set directly, pruning assignments that violate cfg policies
early. For larger spaces, a SAT solver is driven by the cfg predicate
expressions to enumerate satisfying assignments.

```rust
pub fn enumerate_variants(
    features: &[FeatureDecl],
    policies: &VariantPolicy,
) -> Vec<CfgAssignment>;

pub fn validate_variant(
    graph: &AdrGraph,
    claims: &[FrontendClaim],
    cfg: &CfgAssignment,
) -> VariantValidation;

pub struct VariantValidation {
    pub cfg: CfgAssignment,
    pub confluence: Result<(), Vec<ConfluenceFail>>,
    pub compatibility: Result<(), Vec<CompatFail>>,
    pub claims: ResolvedClaims,
    pub verdict: VariantVerdict,
}

pub enum VariantVerdict {
    Valid,
    Invalid { reasons: Vec<VariantFail> },
    Impossible { reason: PolicyViolation },
}
```

`Impossible` is returned when the cfg itself violates policy (and is
therefore not even a candidate); `Invalid` is returned when the cfg
passes policy but the AdrGraph doesn't cohere under it.

## Variant policies

Declared in `workspace.toml` or equivalent:

```toml
[conformance.variants]
allow_empty = false                     # every cfg must be a declared variant
required = ["default"]                  # default must be valid
disjoint_exclusive = [["scp02", "scp03"]]  # at most one of these per variant
forbidden = [
  { features = ["no_mac", "scp02"] },   # these together are forbidden
]
required_pairs = [
  { if_feature = "usim", then_feature = "iso7816-4" },
]
```

Policies are themselves ADR-governed — a change to `disjoint_exclusive`
is a decision that merits a rationale, and so the policy doc is
versioned alongside the ADR state.

## Validator output

### Textual

```
=== Product Variants (4 total; 3 valid, 1 invalid) ===

Variant 01: features = {default}                         VALID
  Frontends: simrs
  Active ADRs: [0001, 0017, 0042]
  Confluence: ✓
  Compatibility: ✓

Variant 02: features = {default, scp02}                  VALID
  Frontends: simrs (scp02 profile)
  Active ADRs: [0001, 0017, 0042, 0084]
  Confluence: ✓
  Compatibility: ✓

Variant 03: features = {default, scp03}                  VALID
  Frontends: simrs (scp03 profile)
  Active ADRs: [0001, 0017, 0042, 0085]
  Confluence: ✓
  Compatibility: ✓

Variant 04: features = {default, scp02, scp03}           INVALID (CONFLUENCE)
  Failing clause: gp::V2_3::"11.1"
  Contributors:
    - ADR-0084: Constraint::KeyVersion(0x01)
    - ADR-0085: Constraint::KeyVersion(0x03)
  Cfg puts both active; declared variants expect disjoint activation.
  Fix: add `disjoint_exclusive = [["scp02", "scp03"]]` to variant policy,
       OR supersede ADR-0084 with ADR-0085 (or vice versa),
       OR split the clause into two (one per cfg branch).
```

### Machine-readable

`variants.json` emitted alongside the book:

```json
{
  "variants": [
    {
      "id": "variant-01",
      "cfg": { "features": ["default"] },
      "active_adrs": [1, 17, 42],
      "frontends": [{ "id": "simrs", "profiles": [] }],
      "confluence": { "status": "ok" },
      "compatibility": { "status": "ok" },
      "verdict": "valid"
    },
    …
  ]
}
```

Consumed by the book generator to render one variant page per valid
combination and an "invalid variants" page with remediation guidance.

## Matrix queries

Once enumerated, the variant set supports queries:

- "Which variants support claim Gp(V2.3) with profile Scp03?"
- "Which ADRs are active in every valid variant?"
- "Which features are redundant (never appear in any valid variant)?"
- "Which features are forbidden (appear in zero valid variants)?"

These queries drive CI optimisation (we only need to run tests per
equivalence class of variants) and audit reports ("evidence that every
declared feature is exercised by at least one variant").

## Interaction with CI

CI runs the validator per PR. Output:

1. Diff in variants: which variants existed before vs. after the PR?
2. Any new invalid variants block merge.
3. Any newly-valid variants (a PR that makes a previously-invalid cfg
   valid) surface as information.
4. Coverage delta: did the PR increase / decrease the number of ADRs
   active in the default variant?

The PR check is a single status line with a link to the full variant
report — the book's `variants/` pages are the auditable artefact.

## Relationship to the rest of the system

The product validator is the capstone of the build-time guarantees:

```
spec crates (clauses + deltas)
       │
       ▼
AdrGraph collector
       │
       ▼
per-cfg confluence + compat checkers
       │
       ▼
product variant enumerator
       │
       ▼
variant matrix renderer + CI verdict
```

Every upstream piece contributes; the validator is the single place
where their composition is verified. When the validator passes, the
system guarantees that every buildable configuration coheres.
