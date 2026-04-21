# 05 — Spec Crates

Each normative standard is encoded as a Rust crate named
`simrs-spec-<id>-<version>` (or `simrs-spec-<id>` when the version is
part of the crate's internal graph rather than its identity). The crate
is the authoritative, executable encoding of that standard for the
`simrs` ecosystem. All downstream references — rules, ADRs, Gherkin
bindings, implementation citations — resolve through typed paths into
the crate.

## Directory layout

```
crates/simrs-spec-gp-2-3/
├── Cargo.toml
├── build.rs                         # drives transcribe → slice → transform → emit
├── sources/
│   ├── sources.lock                 # source hash + transcriber id + version per file
│   └── <the authoritative source files>
├── transcription/
│   ├── cache/<source_hash>.json     # transcriber output, deterministic, committed
│   └── patches/<patch_id>.diff      # hand corrections layered over cache
├── slices/
│   ├── 11.4.3.toml                  # clause slice metadata
│   ├── 11.1.toml
│   └── …
├── transforms/
│   ├── patterns/                    # shared pattern transformers (symlink/import)
│   ├── tables/                      # table-lifter configs for tabular clauses
│   └── manual/
│       └── 11.4.3.rs                # hand-authored Rust Constraint for specific clauses
├── deltas/
│   └── v2_1_1_to_v2_3.toml          # typed delta entries between versions
└── src/
    └── lib.rs                       # hand-authored; re-exports + ergonomic accessors
```

The `build.rs` is the only code that runs the ingestion pipeline; everything in `src/` is either hand-written or emitted by `include!` of a generated file in `OUT_DIR`. This keeps the repository auditable: the `src/` is human-readable; the generated artefacts are reproducible from committed inputs.

## sources.lock

```toml
[[source]]
path       = "sources/GPC_2.3_2019_PublicRelease.pdf"
sha256     = "…"
transcriber = "pdf-v1"
transcriber_version = "0.1.0"
pages      = "1..=320"
added_in   = "gp/2.3"

[[source]]
path       = "sources/GPC_2.3.1_2023_Erratum.pdf"
sha256     = "…"
transcriber = "pdf-v1"
transcriber_version = "0.1.0"
supersedes_clauses = ["11.4.3", "11.7.2"]    # by the ingestor's policy
added_in   = "gp/2.3.1"
```

The lock file is committed; `cargo test` on the spec crate verifies the
live files' hashes against it. A mismatch is a build error — "source
drift" forces a regeneration of the transcription cache and a human
review of the new output.

## Slice TOML

```toml
# slices/11.4.3.toml
clause_id   = "11.4.3"
title       = "SELECT with unknown AID"
normative   = "Must"
prose       = """
Upon receipt of a SELECT command specifying an AID not present on the
card, the card shall return SW 6A82 (File not found).
"""
blocks      = ["page241-para2"]          # references into transcription cache
tables      = []
figures     = []
cross_refs  = [
    { spec = "iso-7816-4", version = "2005", locator = "5.1.1" },
    { spec = "etsi-102-221", version = "r18", locator = "6.4.2" },
]
profile     = null                        # applies generally
deprecated_in = null
```

## Transform TOML

```toml
# transforms/11.4.3.toml
transformer = "patterns/expect_sw_v1"
args        = { sw_hex = "6A82" }
rationale   = "Clause is a plain 'shall return SW X' form."
citations   = [{ adr = 42 }]
```

When a pattern fits, no Rust code is needed. When a clause is
idiosyncratic, `transforms/manual/<id>.rs` contains the Rust function
that emits the `Constraint`. Both kinds produce a single
`Constraint` reachable via the same `clause!()` expansion.

## Delta TOML

```toml
# deltas/v2_1_1_to_v2_3.toml
from = "V2_1_1"
to   = "V2_3"

[[delta]]
clause    = "11.4.3"
kind      = "Clarified"
rationale = "Wording clarified; observable behaviour unchanged."
citations = [{ gp = { version = "V2_3", locator = "Foreword" } }]

[[delta]]
clause    = "11.1"
kind      = "Modified"
before    = "ResponseLayout(iu_layout_v2_1_1)"
after     = "ResponseLayout(iu_layout_v2_3)"
rationale = "INITIALIZE UPDATE response adds SCP identifier byte."
citations = [{ gp = { version = "V2_3", locator = "Change log" } }]
```

## src/lib.rs shape

```rust
#![no_std]
extern crate alloc;

pub use simrs_conformance::prelude::*;

// Emitted by build.rs
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Ergonomic accessor for a single clause in the current version.
#[macro_export]
macro_rules! clause {
    ($id:expr) => {
        $crate::__CLAUSES::by_id($id).expect("clause not found in spec crate")
    };
}

pub const SPEC_GP_V2_3: Spec = SPEC_GP_V2_3_GENERATED;
pub const GRAPH: &StandardGraph = &STANDARD_GRAPH_GENERATED;
```

## Invariants enforced at build time

1. Every `sources.lock` entry has a matching file with the recorded hash.
2. Every slice references only transcription blocks that exist in the cache.
3. Every transform reference (pattern id / manual module) resolves.
4. Every `cross_refs` entry resolves to a clause in some available spec crate.
5. Every delta's `clause` exists in both `from` and `to` versions.
6. A clause with `kind = "Removed"` in a delta to version `V` must not appear in `V`'s slice set.
7. A clause with `kind = "Added"` in a delta from version `V` must not appear in `V`'s slice set.

Violations are compile errors on the spec crate; no downstream crate
can build until the spec crate is consistent.

## Dependency shape

```
simrs-spec-<id> ──▶ simrs-conformance (kernel types, Constraint trait)
                ──▶ simrs-conformance-macros (spec!, clause!, deltas!)
                ──▶ <transcriber crate> (build-dependency)
                ──▶ <slicer crate> (build-dependency)
                ──▶ <transformer crate(s)> (build-dependency)

Downstream rules / ADRs / tests depend on the spec crate and resolve
clauses via `gp_2_3::clause!("11.4.3")` paths.
```

Build-dependencies are isolated from runtime dependencies: the PDF
transcriber (pdfium, OCR engines) never ships in a downstream binary.

## Multi-version crates vs. sibling crates

Two encodings are supported:

- **Sibling crates per major version**: `simrs-spec-gp-2-1-1`,
  `simrs-spec-gp-2-3`. Each is its own crate with its own `sources/`
  and `slices/`. Deltas live in a shared `simrs-spec-gp-deltas` crate or
  in the newer version's `deltas/` directory referring to the older
  sibling.
- **Single crate with internal version graph**: `simrs-spec-gp` holds
  all versions. Useful when clause prose rarely changes and the delta
  set is small.

Phase A uses sibling crates (one for GP 2.3) to keep the encoding
simple; Phase B consolidates if it proves useful.

## The test-vector sibling

`simrs-ref` (the existing canonical test-vector crate) is the vector
counterpart to spec crates: it holds fixed inputs/outputs for
cryptographic algorithms cited by spec clauses. Spec clauses reference
test vectors via `DocumentRef::Simrs(GitPin, Locator)` with the
locator pointing into the `simrs-ref` module path. This closes the
loop: a spec clause saying "MILENAGE with TS1 keys shall produce RES X"
points at the typed `simrs_ref::milenage::vectors::TS1` value.
