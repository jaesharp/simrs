# 16 — Confluence and Compatibility

Two complementary build-time checks guard the ADR + rule graph from
self-contradiction.

- **Confluence** (rewriting sense): for any configuration, applying the
  applicable decisions in any order yields the same normal form.
- **Compatibility** (constraint-satisfaction sense): the active
  decisions form an internally consistent graph under each
  configuration.

Both are evaluated over every satisfying cfg assignment in the product
space (chapter 17). Violations are build errors.

## Confluence

### Definition

Given the set of in-force ADRs active under a cfg assignment, compute
each ADR's constraint contribution at each cited clause. For each
clause, the set of contributing ADRs must produce a single well-defined
constraint value.

Formally: for clause C and cfg σ, let `contrib(C, σ) = { (adr, c) :
adr active under σ, adr cites C, c is adr's constraint contribution at
C }`. Then:

```
confluent(C, σ)  ⟺  ∀ (adr_i, c_i), (adr_j, c_j) ∈ contrib(C, σ). c_i ≡ c_j
```

where `≡` is semantic equivalence of constraints (not identity).
`ExpectSw(0x6A82)` and `ExpectSw(0x6A82)` are equivalent. `ExpectSw(0x6A82)`
and `ExpectSw(0x6999)` are not — a confluence failure.

### What counts as "contribution"

An ADR contributes a constraint at a clause when:

- Its `cites` list includes the clause, AND
- It governs a rule scoped to the clause, OR
- It implements a trait/impl whose `#[implements_spec]` covers the clause.

ADRs that merely cite a clause in their rationale without governing or
implementing at that clause do not contribute — they are informative,
not normative.

### Common violations

- Two ADRs governing rules that produce different outcomes at the same
  clause without disjoint cfg. Fix: narrow one ADR's cfg scope or
  supersede one with the other.
- An ADR contributes `ExpectSw(X)` and another contributes
  `ResponseLayout(...)` at the same clause. Fix: the layout ADR likely
  subsumes the SW ADR; mark the relationship explicitly via
  `implements` edge.
- ADR-A's governed rule produces `KnownDivergence` for a divergence
  shape; ADR-B's rule produces `Regression` for the same shape. Fix:
  add explicit rule priority, or narrow scopes.

### Checker

```rust
pub fn check_confluence(graph: &AdrGraph, cfg: &CfgAssignment) -> Result<(), Vec<ConfluenceFail>>;

pub struct ConfluenceFail {
    pub clause: DocumentRef,
    pub cfg: CfgAssignment,
    pub contributors: Vec<(AdrId, ConstraintRef)>,
    pub suggested_fixes: Vec<FixSuggestion>,
}
```

## Compatibility

### Definition

Compatibility is graph-theoretic. The AdrGraph under a cfg assignment
σ is the subgraph whose nodes are ADRs active under σ and whose edges
are `supersedes`, `implements`, `governs`, `cites`. Compatibility
requires:

1. **Acyclicity** of the combined graph (no `supersedes` cycles, no
   `implements` cycles).
2. **Witness coverage**: every governed trait that is reachable at
   runtime has ≥1 impl witness active under σ.
3. **No mutual-exclusion contradictions**: two ADRs marked
   `conflicts_with` each other cannot both be active under σ.
4. **No forbidden combinations**: cfg predicates in `disjoint_exclusive`
   pairs cannot both hold.

### What witness coverage means

If ADR-17 governs `trait ScpSession` and cfg σ includes `feature =
"scp02"`, there must be an impl of `ScpSession` active under `feature =
"scp02"`. The implementing ADR (typically "ADR-84 implements = adr::0017")
satisfies the coverage requirement.

A trait with no active witness under σ is only allowed if no production
code path exercises the trait under σ (i.e., the trait is feature-gated
out entirely). The compat checker catches orphan traits via a graph
walk from the cfg-active impl set backward.

### Checker

```rust
pub fn check_compatibility(graph: &AdrGraph, cfg: &CfgAssignment) -> Result<(), Vec<CompatFail>>;

pub enum CompatFail {
    CycleFound { in: EdgeKind, participants: Vec<AdrId> },
    MissingWitness { trait_adr: AdrId, cfg: CfgAssignment },
    MutualExclusionViolated { a: AdrId, b: AdrId, cfg: CfgAssignment },
    ForbiddenCombination { rules: Vec<CfgPredicate>, cfg: CfgAssignment },
}
```

## How they compose with the delta graph

Confluence + compat are evaluated per cfg assignment; the delta graph
is a per-spec concept. They compose:

- Under cfg σ, for each frontend claim active under σ, the effective
  clause set includes all clauses reachable from the claim's declared
  version along the delta graph.
- Confluence is then evaluated for each clause in that effective set.
- Compat is evaluated over the cfg-active ADR subgraph.

An ADR authored for `Gp(V2_1_1)` is in-force under a cfg that claims
only `Gp(V2_3)` if the delta graph path V2_1_1 → V2_3 contains no
breaking edges at the ADR's cited clauses — same rule as rule
projection (chapter 7).

## Diagnostic output

When confluence or compat fails, the checker emits a diagnostic
pointing at:

- The specific cfg assignment under which failure occurs.
- The specific clause (for confluence) or graph edge (for compat).
- The participating ADRs with their source locations.
- A suggested fix where the structure of the failure admits one.

CI surfaces each diagnostic as a line in the PR-check output.

## Relationship to product variants

A cfg assignment that fails confluence or compat is *not* a valid
product variant. The product validator (chapter 17) takes the set of
assignments that pass both checks as the "valid variant set" and
reports the rest as invalid configurations.

This is the payoff: by evaluating confluence + compat across the cfg
power set, the system derives the valid product variants as a by-
product. Two mutually-exclusive feature flags that accidentally produce
a violating overlap surface as an invalid variant, not as a
configuration that compiles-but-misbehaves.

## Incremental evaluation

The full cfg power set can be large (n features → 2^n assignments).
The checkers prune early: a cfg that contains `all(feature = "foo",
feature = "bar")` where `foo` and `bar` are in `disjoint_exclusive` is
rejected before any ADR reachability computation. The remaining
assignments are processed, typically in the low hundreds for Phase A's
feature count. For larger spaces, a SAT-based enumeration (chapter 17)
kicks in.
