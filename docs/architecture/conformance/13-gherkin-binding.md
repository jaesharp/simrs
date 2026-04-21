# 13 — Gherkin Binding

Gherkin feature files are a primary authoring surface. Scenarios bind
to clauses in spec crates by typed tag, with compile-time verification
that the scenario's observations match the clause's constraint shape.

## Tag grammar

```
tag         ::= '@' scheme ':' payload
scheme      ::= 'cite' | 'binds' | 'governs' | 'pinned' | 'axes' | 'adr' | ...
payload     ::= ... scheme-specific ...
```

### `@cite`

Declarative citation, no constraint-binding obligation:

```
@cite:gp-2.3:11.4.3
@cite:iso-7816-4:2005:5.1.1
@cite:adr:0042
@cite:jcardengine:26.04.06:J3
@cite:simrs:feat:bfee8a3
```

Syntax: `<scheme>:<version-or-id>:<locator>`. The scheme tells the
parser which `DocumentRef` variant to construct; the rest is variant-
specific. Version tokens use the spec crate's canonical spelling.

### `@binds`

Strong binding — the scenario's observations must satisfy the
clause's `Constraint`:

```
@binds:gp-2.3:11.4.3
@binds:gp_2_3::clause("11.4.3")    # rust-path form
```

Both forms resolve to the same `&'static Clause`. The tag-parser
loads the spec crates' registries at test-build time and fails
compilation if the clause is unknown.

### `@governs`

Declarative: this scenario is the primary test for a specific rule.
Used by the book generator to link rule pages to their covering
scenarios.

```
@governs:rule:sw_6a82_for_unknown_select
```

### `@pinned`

Suppresses drift warnings with an explicit reason:

```
@pinned:gp-2.3  reason="Awaiting vendor erratum"
```

### `@axes`

Declares the axes for scenario outlines (see chapter 9). The
`Examples` table is one authoring surface; `@axes` is an alternative
for non-tabular parameterisation.

```
@axes:frontend,scp_version,key_version
```

### `@adr`

Shorthand for `@cite:adr:NNNN` — the scenario references an ADR that
is authoritative for its intent.

```
@adr:0042
```

## Binding type-check

When a scenario has `@binds:C`, the parser retrieves the clause `C`,
reads `C.constraint.shape()`, and scans the scenario's `Then` steps
for observation productions matching that shape.

Example:

```gherkin
@binds:gp-2.3:11.4.3
Scenario: SELECT unknown AID
  …
  Then SW equals 6A82                # produces Observation::Sw(0x6A82)
```

`Constraint::ExpectSw(0x6A82)` has shape `ConstraintShape::ExpectSw`.
The `Then SW equals <hex>` step is known to produce an
`ObservationKind::ApduExchange` with SW payload. The parser's
shape-check passes.

A scenario that binds to a `Constraint::ExpectSw` but produces no SW
observation (because its `Then` steps only assert data-field shape)
fails the build with a diagnostic pointing at both the clause and the
scenario.

## Step registry

Standard step phrases are registered as typed observation producers:

```rust
#[conformance_step(phrase = "SW equals {hex}")]
fn sw_equals(ctx: &mut StepContext, hex: &str) -> StepOutcome {
    let expected = parse_hex_sw(hex);
    let obs = ctx.last_apdu_observation();
    ctx.assert_sw(obs.sw, expected);
    ctx.emit_observation(obs);
    StepOutcome::Completed
}
```

The `#[conformance_step]` macro registers (a) the step's phrase
pattern, (b) the observation kinds the step produces, (c) the
step's compile-time documentation. The registry is consumed by the
Gherkin parser's shape-check.

Custom steps outside the registry can be used, but they cannot
participate in `@binds` shape-checking — the parser emits a warning
(or error, configurable) on binding tags for unregistered steps.

## Scenarios to CaseQuery

Each scenario resolves to one or more `CaseQuery` values:

- `Scenario` without `Examples` and without `@axes` → one case with
  axes defaulted from the scenario's context.
- `Scenario Outline` with `Examples` → one case per examples row;
  axis names are the example column headers.
- Scenario with `@axes:...` → one case per Cartesian product point
  of declared axes; axis values come from registered per-axis atom
  lists in the spec crates.

The scenario's `citations` come from its tags; `binds` from
`@binds`; `steps` from the step body.

## Scenario body to StepTemplate

Each Gherkin step maps to an `Action` or set of actions:

| Gherkin phrase                       | Action                             |
|--------------------------------------|------------------------------------|
| `Given a powered-on card`            | `PowerOn`                          |
| `When I send SELECT with AID "..."`  | `Apdu(select_aid(aid))`            |
| `When I INITIALIZE UPDATE with ...`  | `ScpInitUpdate { challenge }`      |
| `Then SW equals <hex>`               | post-condition observation         |

The mapping is implemented as step-definition modules in the
scenario's step-def crate. The conformance kernel exposes a set of
common step definitions; domain-specific crates extend.

## Tooling

- `simrs-conformance-gherkin` — Gherkin parser + tag resolver + step
  registry + binding shape-checker. Runs as part of `cargo test` in
  any crate that contains `.feature` files; errors surface as build
  errors.
- `adr check-bindings` — standalone CLI that walks all feature files
  and validates tag resolution independent of the test harness.
- Book-generator ingestion: scenarios (with their parsed tags) are
  rendered into the book alongside their bound clauses.

## Backward-compat with existing cucumber-rs tests

Our existing BDD suites (simrs-standards-integration-validation,
simrs-globalplatform-conformance-validation, etc.) currently use
cucumber-rs tags as filter strings. The migration to typed tags is
incremental: the parser ignores unrecognised tags, so adding
`@cite:...` and `@binds:...` alongside existing `@wip` / `@unit` /
`@slow` tags breaks nothing. Enforcement of binding shape-checks is
opt-in per crate via a feature flag during the transition.
