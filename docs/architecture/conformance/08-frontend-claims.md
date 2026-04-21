# 08 — Frontend Claims

A *frontend* is any implementation under test: our own simrs card, an
external reference simulator (jcsl, JCardEngine), a physical card, a
subset of simrs compiled under different feature flags. A *claim* is
the frontend's declaration of which standards (and which versions of
those standards, and under which profiles) it purports to implement.
Claims are data, authored per frontend; the classifier reads them.

## The claim type

```rust
pub struct FrontendClaim {
    pub frontend: FrontendId,
    pub standards: Vec<ClaimedStandard>,
    pub profile_bundles: Vec<ProfileBundle>,
    pub cfg_scope: Option<CfgAssignment>,
}

pub struct ClaimedStandard {
    pub spec: SpecId,
    pub version: Version,
    pub range: VersionRange,        // exact | from..=to | forward-compat
    pub profiles: Vec<ProfileId>,
}

pub enum VersionRange {
    Exact(Version),
    Inclusive { low: Version, high: Version },
    ForwardCompat { from: Version },   // claim V_from or any later non-breaking version
}

pub struct ProfileBundle {
    pub name: ProfileId,
    pub requires: Vec<ClaimedStandard>,  // "Scp03 bundle requires GP 2.2+"
}
```

## Where claims are declared

A claim for simrs itself lives in `crates/simrs-card/frontend.toml`
(authored):

```toml
[frontend]
id = "simrs"

[[claims]]
spec = "gp"
version = "V2_1_1"
profiles = ["Scp02"]

[[claims]]
spec = "gp"
version = "V2_3"
profiles = ["Scp03"]
cfg_gate = { feature = "scp03" }

[[claims]]
spec = "iso-7816-4"
version = { year = 2005 }
```

For external backends, claims are declared in the backend adapter
crate (`crates/simrs-jcsl/frontend.toml`, etc.). Physical cards can
carry claims in an ATR-derived or hand-authored sidecar file.

## How claims are consumed

The classifier loads the frontend's claims at test-run time. When
classifying a divergence, it uses the claim to:

1. Decide which rules apply (rules scoped to specs/versions the
   frontend doesn't claim are skipped).
2. Evaluate claim falsification (`BehavesLike`).
3. Emit compliance matrix rows keyed on `(frontend, claim)`.

Unclaimed behaviour is not evaluated against rules that belong to
unclaimed specs. A frontend that doesn't claim ETSI TS 102.221
doesn't fail ETSI rules; it simply has no ETSI compliance row.

## cfg-scoped claims

Some simrs claims are feature-gated. The `cfg_gate` field ties a claim
to a specific cfg predicate. When the product validator enumerates
configurations, each cfg assignment produces a per-cfg claim set; the
classifier evaluates against that set for that variant.

Example: simrs in `feature = "scp02"` claims GP 2.1.1; in
`feature = "scp03"` it additionally claims GP 2.3. A single run of
the test suite with both features active claims both; with only one
feature, the other claim is inactive and its rules do not apply.

## Forward-compatibility claims

```toml
[[claims]]
spec = "gp"
version = "ForwardCompat { from = V2_3 }"
```

A `ForwardCompat` claim means: "we claim V2_3, and we also claim
compatibility with any later version whose delta path from V2_3 is
non-breaking at the clauses we implement." The classifier evaluates
this by walking the delta graph from V2_3 forward; if every reachable
version has only `Clarified` and `ErrataFix` deltas at the implemented
clauses, the claim extends. A breaking delta restricts the claim's
effective range.

This makes vendor claims falsifiable in the forward direction too:
if a frontend claims `ForwardCompat from V2_3` and V2_3.1 adds an
`ErrataFix` at a clause where the frontend behaves as V2_3 did
*before* the errata, the claim is falsified at that clause.

## Claim validation

At build time:

1. Every claim's `spec` resolves to a loaded spec crate.
2. Every claim's `version` resolves to a node in that spec's graph.
3. Every profile in `profiles` is declared by the spec crate.
4. A profile bundle's `requires` entries are themselves claimable
   (the frontend must claim the bundle's prerequisites).
5. `cfg_gate` references only declared features of the frontend crate.

## Interaction with product variants

A frontend with multiple cfg-scoped claims produces multiple product
variants — one per satisfying cfg assignment. Each variant is an
independent test target: the classifier runs against that variant's
claim set, and the compliance matrix renders one column per variant.

`[frontend.variants]` in the TOML declares the policy:

```toml
[variants.policy]
allow_empty = false                    # every buildable cfg must be a declared variant
disjoint_exclusive = ["scp02", "scp03"] # these features are mutually exclusive
required = ["default"]                 # default build must also be a valid variant
```

The product validator checks these at build time (chapter 17).

## When a claim fails

A `BehavesLike(effective)` outcome against a claim does not
automatically fail the build. Instead it is a typed record. CI can
be configured to fail on `BehavesLike` outcomes (a strict vendor
posture) or to tolerate them (a compatibility-testing posture). The
distinction is an operations policy, not a kernel behaviour.

## Anti-patterns

Avoid:

- Making unsupported claims. Claiming GP 2.3 "aspirationally" while
  only implementing GP 2.1.1 produces a wall of `BehavesLike`
  divergences; the right move is to claim GP 2.1.1 and treat GP 2.3
  adoption as a multi-commit journey.
- Claiming by copy-paste. Each claim should be authored alongside
  evidence (scenarios that pass, implementations that exist). The
  validator flags claimed-but-unimplemented profiles.
- Conflating profiles with features. A profile is a spec-defined
  bundle; a feature is a build-configuration choice. When a spec
  profile maps cleanly to a feature, the mapping is explicit via
  `cfg_gate`.
