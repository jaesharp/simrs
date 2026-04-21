# 14 — Proc Macros

Rust-side authoring surfaces for the conformance engine are
attribute macros (on types/traits/impls/functions) and function-like
macros (for spec authoring). They emit structured metadata that the
build-time collector reads to assemble the AdrGraph, the clause
registry, and the rule set.

## Attribute macros

### `#[adr(N)]`

Marks any item as governed by ADR N.

```rust
#[adr(42)]
impl GpCard for SimrsCard { ... }

#[adr(17)]
pub trait ScpSession: Transport { ... }

#[adr(99, implements = adr::0017)]
impl ScpSession for Scp02 { ... }
```

Emits a `__ADR_SITE_N__<item-id>` const in a hidden submodule. The
const records: ADR id, cfg predicate the site is active under, source
file + line, and any nested `cite`/`governs`/`implements` parameters.

### `#[cite(...)]`

Attaches a typed citation to an item.

```rust
#[cite(gp(V2_3, "11.4.3"))]
fn validate_select(...) -> Sw { ... }

#[cite(iso_7816_4(part = 4, year = 2005, clause = "5.1.1"))]
#[cite(adr(42))]
impl CardSelector for SimrsCard { ... }
```

Multiple citations stack. The argument grammar mirrors the Rust-path
form used by `DocumentRef`'s variant constructors; the macro expands
to `DocumentRef::Gp(GpVersion::V2_3, Locator::from_static("11.4.3"))`.

### `#[governs(rule_id)]`

Declares that the item governs (is the implementation of) a named rule.

```rust
#[governs(rule::sw_6a82_for_unknown_select)]
fn classify_unknown_select(...) -> Outcome { ... }
```

The rule id must exist in some loaded `RuleSet` by build time.

### `#[implements_spec(...)]`

Declares that an impl is the implementation-witness for a spec clause.

```rust
#[implements_spec(gp(V2_3, "11.4.3"))]
impl GpCard for SimrsCard { ... }
```

Satisfies the "every clause has ≥1 implementation" invariant for the
scope of this item's cfg.

### `#[conformance_step(phrase = "...")]`

Registers a Gherkin step-definition function for type-checked
scenario binding.

```rust
#[conformance_step(phrase = "SW equals {hex}")]
fn sw_equals(ctx: &mut StepContext, hex: &str) -> StepOutcome { ... }
```

Emits a `__STEP_DEF_<id>` record with phrase pattern, observation
productions, and source location.

### `#[conformance_test]`

Marks a Rust-native test function as a conformance scenario (as
opposed to Gherkin feature files).

```rust
#[conformance_test(scenario = "select_unknown_aid", binds = gp_2_3::clause!("11.4.3"))]
fn test_select_unknown(ctx: &mut TestContext) { ... }
```

## Function-like macros

### `spec!`

Declares an entire spec in one expression:

```rust
spec! {
    id: Gp,
    version: V2_3,
    title: "GlobalPlatform Card Specification v2.3",

    clause "11.4.3" {
        title:     "SELECT with unknown AID",
        normative: Must,
        prose:     "Upon receipt...",
        constraint: Constraint::ExpectSw(0x6A82),
        cross_refs: [iso_7816_4::clause("5.1.1")],
    }

    clause "11.1" {
        title:     "INITIALIZE UPDATE response",
        normative: Must,
        prose:     "...",
        constraint: Constraint::ResponseLayout(iu_layout()),
    }
}
```

Expansion produces a `pub const SPEC: Spec` and `pub const CLAUSES:
&[&Clause]` plus module-level consts for each clause. Grammar in
[Appendix A](A-grammar.md).

### `clause!`

Retrieve a clause by id at call-site. Used throughout downstream crates:

```rust
let c: &'static Clause = gp_2_3::clause!("11.4.3");
```

Expands to `<spec registry>::lookup(ClauseId::from_static("11.4.3")).unwrap()`.
Missing clauses are compile errors.

### `deltas!`

Author a set of deltas between two versions:

```rust
deltas! {
    spec: Gp,
    from: V2_1_1,
    to:   V2_3,

    clause "11.4.3" { Clarified, rationale: "..." }
    clause "11.1"   { Modified { before: iu_layout_v2_1_1, after: iu_layout_v2_3 }, rationale: "..." }
    clause "11.11.2" { Added, rationale: "SCP03 introduced" }
}
```

### `rule!`

Declare a rule with guard + scope + outcome + citations:

```rust
pub const RULE_J3: Rule = rule! {
    id: "jcardengine_select_unknown_6d00",
    scope: { frontends: [FrontendId::Jcardengine] },
    guard: step_is(StepId::SELECT_UNKNOWN_AID).and(field_is(WorldField::Sw)),
    outcome: KnownDivergence,
    cites: [
        gp(V2_3, "11.4.3"),
        jcardengine(v("26.04.06"), known_div("J3")),
        adr(42),
    ],
};
```

### `frontend!`

Declare a frontend claim set (alternative to `frontend.toml`):

```rust
pub const SIMRS_CLAIMS: FrontendClaim = frontend! {
    id: "simrs",
    claims: [
        { spec: Gp, version: V2_1_1, profiles: [Scp02] },
        { spec: Gp, version: V2_3, profiles: [Scp03], cfg: feature("scp03") },
        { spec: Iso7816 { part: 4 }, version: Year(2005) },
    ],
};
```

## Build-time collection

Proc-macro output produces `__ADR_SITE_*`, `__STEP_DEF_*`, etc. consts.
A build-time collector (`simrs-adr` xtask or build.rs integration)
scans all compiled crates for these consts — via `cargo doc --output-format=json`
or via linker-level `inventory`-crate collection — and produces the
global `AdrGraph` used by validators.

The `inventory`-crate approach avoids `cargo doc` dependency but
requires ctor-style registration; the `cargo doc --json` approach is
slower but cleaner. Phase A uses `inventory`; Phase B can revisit.

## Error ergonomics

Macro-reported errors point at the call site, not at macro internals.
A malformed `cite(gp(V3, "11.4.3"))` — `V3` is not a variant —
produces a clear "no variant `V3`" error at the `cite` attribute's
line, with span information pointing at the problematic token.

## What the macros do not do

- No runtime codegen. All expansion is compile-time.
- No type erasure. Every `cite`/`governs`/`binds` preserves typed
  identity — a downstream user can `match` on a `DocumentRef` and
  handle each variant concretely.
- No implicit registration. Every registered entity has an explicit
  site (attribute or macro expansion); nothing "magically" joins the
  AdrGraph.
