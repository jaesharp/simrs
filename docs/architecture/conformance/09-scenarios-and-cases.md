# 09 — Scenarios and Cases

A `Scenario` is a parameterised test template — a semantic operation
with declared axes. `Scenario::expand()` produces one `CaseQuery` per
point in the Cartesian product of axis values, modulo axis
constraints. Each `CaseQuery` is run independently against each
frontend and produces one `Report`.

## Why Cartesian product from day one

The research survey confirmed WebGPU CTS's case-parameterisation as the
right shape: tests are *generators* of concrete cases, not single
cases. Building it into the kernel from the start avoids the WPT
problem where per-case metadata was retrofitted. Our axes are typed
from day one — no stringly-typed parameter tables.

## Types

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
    pub constraints: Vec<AxisConstraint>,
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

pub enum AxisConstraint {
    /// Exclude cases where this axis has this value.
    Exclude { axis: AxisName, value: AxisValue },
    /// Include cases only when some other axis equals a value.
    RequireIf {
        axis: AxisName,
        value: AxisValue,
        when: AxisPredicate,
    },
    /// Symbolic link: "this axis's value must match that axis's value".
    Mirror { from: AxisName, to: AxisName },
}

pub struct CaseQuery {
    pub scenario: ScenarioId,
    pub axes: BTreeMap<AxisName, AxisValue>,
}
```

## Expansion

```rust
impl Scenario {
    pub fn expand(&self) -> Vec<CaseQuery> {
        cartesian(&self.axes)
            .into_iter()
            .filter(|c| self.axes_satisfy_constraints(c))
            .map(|axes| CaseQuery {
                scenario: self.id,
                axes,
            })
            .collect()
    }
}
```

`cartesian` is the obvious product over per-axis value lists.
`axes_satisfy_constraints` evaluates every `AxisConstraint` against the
candidate axis assignment.

## Axis atoms and typed values

`AxisValue` is an enum with a few built-in variants plus a
`Custom(Arc<dyn AxisAtom>)` escape hatch. Spec crates contribute
their own axis atoms via a prelude export:

```rust
// in simrs-spec-gp-2-3
pub mod axes {
    pub enum ScpVersion { Scp02, Scp03 }
    impl AxisAtom for ScpVersion { /* … */ }

    pub enum KeyVersionNumber { Kv01, Kv03, Kv11 }
    impl AxisAtom for KeyVersionNumber { /* … */ }
}
```

Custom axis atoms can provide richer filtering semantics than the
built-in variants expose.

## Selectors / queries

A `CaseQuery` filter grammar lets authors and CI narrow the run:

```
--select "scenario:select_unknown_aid,frontend:jcardengine,scp_version:SCP03"
--select "frontend:simrs,scp_version:SCP02"
--select "axis:scp_version:* except Scp02"
```

Selectors are parsed to typed `CaseQuery` predicates; nothing is
stringly-matched beyond axis name resolution.

## Interaction with frontend claims

The built-in `Frontend` axis is always present, and its values default
to every frontend that declares any claim. A scenario's clause
bindings narrow the set: if the scenario `@binds` GP 2.3 clause 11.4.3,
the default frontend axis is `{frontends that claim GP 2.3}`. The
author can widen or narrow manually.

## Interaction with cfg

Cfg-scoped claims affect which axis values are legal in each variant.
For each product variant (cfg assignment), the scenario expansion
uses that variant's valid axis set. A case that requires
`feature = "scp03"` on simrs is simply absent from the `no-scp03`
variant's expansion — not skipped, not failed, not present.

## Per-case provenance

Every case knows its scenario, its axes, its expansion rationale. When
the report renders in the book, the per-case page links back to:

- The scenario source file (Gherkin or Rust-declared).
- The scenario's cited clauses.
- The axis assignment that produced this case.
- The variant / claim context under which the case ran.

## Parameterised steps

`StepTemplate` references axis values by name:

```rust
pub enum StepTemplate {
    PowerOn,
    Select { aid: AxisRef<Aid> },
    OpenScp { version: AxisRef<ScpVersion>, kv: AxisRef<KeyVersionNumber> },
    GetStatus { p1: u8, p2: u8 },
    Custom(Arc<dyn StepImpl>),
}

pub enum AxisRef<T> {
    Literal(T),
    FromAxis(AxisName),
}
```

At expansion, axis refs are resolved against the `CaseQuery`'s axes.
A `StepImpl` custom step gets access to the full `CaseQuery` to
derive its own behaviour.

## Authoring surfaces

### Rust-native scenarios

```rust
pub const SELECT_UNKNOWN_AID: Scenario = scenario! {
    id: "select_unknown_aid",
    axes: [
        frontend_axis(),
        axis(scp_version = [SCP02, SCP03]),
    ],
    binds: [gp_2_3::clause!("11.4.3")],
    steps: [
        StepTemplate::PowerOn,
        StepTemplate::Select { aid: AxisRef::Literal(Aid::unknown()) },
    ],
};
```

### Gherkin scenarios

```gherkin
@spec:gp_2_3  @binds:11.4.3
@axes:frontend,scp_version
Feature: SELECT unknown AID

  Scenario Outline: SELECT unknown AID returns 6A82
    Given a powered-on <frontend> with <scp_version>
    When I send SELECT with AID "FF EE DD CC BB"
    Then SW equals 6A82

  Examples:
    | frontend    | scp_version |
    | simrs       | SCP02       |
    | simrs       | SCP03       |
    | jcsl        | SCP03       |
    | jcardengine | SCP03       |
```

The Gherkin tag parser converts `@axes` to the axis list; `Examples`
tables are folded into the Cartesian product or replace it entirely
(scenario authors choose). Details in [13 — Gherkin Binding](13-gherkin-binding.md).
