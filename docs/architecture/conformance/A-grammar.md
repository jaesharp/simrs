# A — Grammars

Complete grammars for the DSLs the conformance engine exposes. Each
grammar is authoritative; changes require an ADR and a version bump
on `simrs-conformance-macros`.

## A.1 `spec!` macro

```
spec_decl    ::= 'spec!' '{' spec_header spec_body '}'

spec_header  ::= 'id:' spec_id ','
                 'version:' version_tok ','
                 'title:' string_lit ','

spec_body    ::= (clause_decl | delta_ref | cross_ref_group)*

clause_decl  ::= 'clause' string_lit '{' clause_field (',' clause_field)* ','? '}'

clause_field ::= 'title:'      string_lit
               | 'normative:'  normative_tok
               | 'prose:'      string_lit
               | 'constraint:' constraint_expr
               | 'cross_refs:' '[' cross_ref_expr (',' cross_ref_expr)* ']'
               | 'profile:'    profile_tok
               | 'deprecated_in:' version_tok

normative_tok ::= 'Must' | 'MustNot' | 'Should' | 'ShouldNot' | 'May' | 'Informative'

spec_id      ::= 'Gp' | 'Iso7816' '(' iso_part ')' | 'EtsiTs102221' | 'Emv' '(' emv_book ')' | 'Simrs' | 'Custom' '(' string_lit ')'

version_tok  ::= ident               (* variant of the spec's Version enum *)
iso_part     ::= 'Part' '(' int_lit ')'
emv_book     ::= 'Book' '(' int_lit ')'

constraint_expr ::= rust_expression  (* any Rust expression of Constraint type *)
cross_ref_expr  ::= ident '::' ident '!' '(' string_lit ')'

profile_tok  ::= 'None' | 'Some' '(' ident ')'
```

## A.2 `clause!` macro

```
clause_ref ::= 'clause!' '(' string_lit ')'
```

Resolves to `&'static Clause` via the enclosing spec crate's static
registry.

## A.3 `deltas!` macro

```
deltas_decl  ::= 'deltas!' '{' delta_header delta_body '}'

delta_header ::= 'spec:' spec_id ','
                 'from:' version_tok ','
                 'to:'   version_tok ','

delta_body   ::= (delta_clause_decl)*

delta_clause_decl ::= 'clause' string_lit '{' delta_kind_expr (',' delta_field)* ','? '}'

delta_kind_expr ::= 'Added'
                  | 'Removed'
                  | 'Modified' '{' 'before:' constraint_expr ',' 'after:' constraint_expr '}'
                  | 'Clarified'
                  | 'ErrataFix'

delta_field ::= 'rationale:' string_lit
              | 'citations:' '[' cite_expr (',' cite_expr)* ']'
```

## A.4 `rule!` macro

```
rule_decl    ::= 'rule!' '{' rule_field (',' rule_field)* ','? '}'

rule_field   ::= 'id:' string_lit
               | 'scope:' '{' scope_field (',' scope_field)* ','? '}'
               | 'guard:' predicate_expr
               | 'outcome:' outcome_template
               | 'cites:' '[' cite_expr (',' cite_expr)* ']'

scope_field  ::= 'specs:'     '[' spec_id (',' spec_id)* ']'
               | 'versions_from:' version_tok
               | 'versions_to:'   version_tok
               | 'frontends:' '[' frontend_id (',' frontend_id)* ']'
               | 'axes:' '{' axis_guard_expr '}'

outcome_template ::= 'Match'
                   | 'Regression'
                   | 'KnownDivergence'
                   | 'DesignDecision'
                   | 'SpecDeviation'
                   | 'UnderReview'
                   | 'BehavesLike' '{' 'effective:' version_tok '}'

predicate_expr ::= rust_expression  (* any Rust expression yielding predicates::Predicate<Divergence> *)
```

## A.5 `frontend!` macro

```
frontend_decl ::= 'frontend!' '{' frontend_field (',' frontend_field)* ','? '}'

frontend_field ::= 'id:' string_lit
                 | 'claims:' '[' claim_expr (',' claim_expr)* ']'
                 | 'profile_bundles:' '[' bundle_expr (',' bundle_expr)* ']'

claim_expr    ::= '{' 'spec:' spec_id ',' 'version:' version_tok (',' claim_extra)* '}'

claim_extra   ::= 'profiles:' '[' ident (',' ident)* ']'
                | 'cfg:' cfg_expr_rust
                | 'range:' '{' 'low:' version_tok ',' 'high:' version_tok '}'
                | 'forward_compat_from:' version_tok
```

## A.6 Attribute macros

### `#[adr(n, ...)]`

```
adr_attr     ::= '#[adr' '(' adr_id (',' adr_param)* ')' ']'

adr_id       ::= int_lit

adr_param    ::= 'cite' '=' cite_expr
               | 'governs' '=' rule_path
               | 'implements' '=' 'adr::' int_lit
               | 'cfg' '=' cfg_expr_rust

cite_expr    ::= ident '(' cite_args ')'
               (* Examples:
                   gp(V2_3, "11.4.3")
                   iso_7816_4(part = 4, year = 2005, clause = "5.1.1")
                   adr(42)
                   jcardengine(v("26.04.06"), known_div("J3"))
                *)
```

### `#[cite(...)]`

```
cite_attr    ::= '#[cite' '(' cite_expr ')' ']'
```

May appear multiple times; citations stack.

### `#[governs(rule_path)]`

```
governs_attr ::= '#[governs' '(' rule_path ')' ']'

rule_path    ::= ident ('::' ident)* ('::' string_lit)?
```

### `#[implements_spec(cite_expr)]`

```
impl_spec_attr ::= '#[implements_spec' '(' cite_expr ')' ']'
```

### `#[conformance_step(...)]`

```
step_attr    ::= '#[conformance_step' '(' step_params ')' ']'

step_params  ::= 'phrase' '=' string_lit
                 (',' 'produces' '=' '[' observation_kind (',' observation_kind)* ']')?
```

### `#[conformance_test(...)]`

```
conf_test_attr ::= '#[conformance_test' '(' test_params ')' ']'

test_params    ::= 'scenario' '=' string_lit
                   (',' 'binds' '=' clause_ref)*
                   (',' 'cites' '=' cite_expr)*
```

## A.7 Gherkin tags

```
tag          ::= '@' scheme ':' payload

scheme       ::= 'cite' | 'binds' | 'governs' | 'pinned' | 'axes' | 'adr' | 'spec' | 'frontend-claims'

payload      ::= cite_payload | binds_payload | governs_payload | pinned_payload
               | axes_payload | adr_payload | spec_payload | claims_payload

cite_payload ::= cite_doc ':' locator
               (* cite_doc ∈ { 'gp-<VERSION>', 'iso-7816-<PART>:<YEAR>',
                               'etsi-<SPEC>:<REL>', 'adr', 'jcardengine:<SEMVER>',
                               'jcsl:<TAG>', 'simrs:<GITPIN>' } *)

binds_payload ::= cite_payload          (* one of the cite forms above *)

governs_payload ::= 'rule' ':' rule_id

pinned_payload  ::= cite_payload ('  reason' '=' string_lit)?

axes_payload   ::= axis_name (',' axis_name)*

adr_payload    ::= int_lit

spec_payload   ::= spec_crate_ident

claims_payload ::= cite_payload (',' cite_payload)*

rule_id        ::= ident
axis_name      ::= ident
locator        ::= <non-empty string, may contain dots / hyphens / digits>
```

## A.8 ADR frontmatter YAML

```yaml
# required
id: <int>
title: <string>
status: Proposed | Accepted | InForce | Superseded | Retracted | Deprecated

# conditional (required when status ∈ { Accepted, InForce, Superseded, Retracted, Deprecated })
status_since: <ISO8601-date>
status_reviewers: [<string>]      # required for Accepted+
superseded_by: <int>              # required for Superseded
retraction_reason: <string>       # required for Retracted
sunset: <ISO8601-date>             # optional for Deprecated

# required for InForce (generated)
generated_at: <ISO8601-datetime>

# required (generated; authors must not hand-edit)
cites: [<DocumentRef>]
governs: [<RuleId>]
implements: <int> | null
supersedes: [<int>]
cited_by:
  - src: <path:line> | <feature>:<line-range>
    scenario: <string>            # for feature refs

# optional
active_under: any | CfgExpr
tags: [<string>]                   # free-form, not typed

# DocumentRef form
# One of:
#   { gp: { version: <GpVersion>, locator: <string> } }
#   { iso_7816_4: { year: <YYYY>, locator: <string> } }
#   { etsi_ts_102221: { release: <int>, locator: <string> } }
#   { adr: <int> }
#   { jcardengine: { version: <semver>, locator: <string> } }
#   { jcsl: { tag: <string>, locator: <string> } }
#   { simrs: { git: <sha-or-tag>, locator: <string> } }
```

## A.9 sources.lock TOML

```toml
[[source]]
path       = <relative-path>      # required
sha256     = <hex>                 # required
transcriber = <transcriber_id>     # required
transcriber_version = <semver>     # required
pages      = <range-expr>          # optional; defaults to all
added_in   = <version_tok>         # the spec version this source first contributes
supersedes_clauses = [<locator>]   # optional; erratum packs
```

## A.10 Slice TOML

```toml
clause_id   = <string>             # required
title       = <string>             # required
normative   = "Must" | "MustNot" | "Should" | "ShouldNot" | "May" | "Informative"
prose       = <string>             # required (verbatim)
blocks      = [<block_ref>]        # required (references into transcription cache)
tables      = [<table_ref>]        # optional
figures     = [<figure_ref>]       # optional
cross_refs  = [<cross_ref_inline>]  # optional
profile     = <profile_id> | null  # optional
deprecated_in = <version_tok> | null
```

## A.11 Delta TOML

```toml
from = <version_tok>               # required
to   = <version_tok>                # required

[[delta]]
clause    = <locator>              # required
kind      = "Added" | "Removed" | "Modified" | "Clarified" | "ErrataFix"
before    = <constraint_ref>       # required when kind = "Modified"
after     = <constraint_ref>       # required when kind = "Modified"
rationale = <string>                # required
citations = [<cite_inline>]        # optional
```

## A.12 Transform TOML

```toml
transformer = <transformer_id>     # required
args        = <arbitrary toml>      # transformer-specific
rationale   = <string>              # required
citations   = [<cite_inline>]      # optional
```

## Diagnostic errors

Every grammar surfaces parse errors with:

- The file + line + column of the offending token.
- The expected production(s).
- The actual token.
- A pointer to this grammar chapter (`cf. A.N`).

Macro-reported errors include span information and render under
`cargo` as normal compiler diagnostics.
