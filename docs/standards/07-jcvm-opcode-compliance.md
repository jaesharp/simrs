# JCVM Opcode Compliance Audit

Tracking document for JCVM bytecode opcode and structural compliance
against the JCVM 3.x specification. Companion to
[06-globalplatform.md](06-globalplatform.md), which tracks the
broader GP/JC conformance plan.

[Back to Standards Map](README.md)

---

## Executive Summary

The opcode crate (`simrs-jcvm-opcodes`) was originally committed
before the JCVM spec numbering was finalised. As a result, **a
substantial fraction of the implemented opcodes use non-spec values**.
The current state is internally consistent (the interpreter, writer,
and tests all agree) but is **not interoperable with real Oracle-
converted CAP files** -- a CAP file produced by `converter.bat` from
the Java Card Development Kit will not execute correctly on simrs
without remapping.

The deviations are catalogued below and preserved as a tracked
gap, not papered over. The plan is to migrate to the spec values
under a feature flag, retain the legacy mapping for back-compat,
and validate with a converter-emitted reference CAP file.

### Compliance Status (2026-05-04)

| Class | Implemented | Spec-correct | Deviating | Missing |
|-------|-------------|--------------|-----------|---------|
| Misc / nop / aconst_null | 2 | 2 | 0 | 0 |
| Constant push (`*const_*`, `*push`) | 18 | 18 | 0 | 0 (`bipush` 0x12 reserved unused) |
| Local variable load (`*load*`) | 13 | 13 | 0 | 0 |
| Local variable store (`*store*`) | 13 | 4 | 9 | 0 |
| Array load (`*aload`) | 4 | 1 | 3 | 0 |
| Array store (`*astore`) | 4 | 1 | 3 | 0 |
| Stack manipulation (pop/dup/swap) | 5 | 4 | 1 | 1 (`swap_x`) |
| Arithmetic (s\* / i\*) | 12 | 12 | 0 | 0 |
| Bitwise / shift | 12 | 12 | 0 | 0 |
| Increment | 2 | 2 | 0 | 2 (`sinc_w` 0x96, `iinc_w` 0x97) |
| Type conversion | 4 | 4 | 0 | 0 |
| `icmp` | 1 | 1 | 0 | 0 |
| Conditional branches (narrow) | 16 | 16 | 0 | 0 |
| Unconditional branch (narrow) | 1 | 1 | 0 | 0 (`jsr` 0x71, `ret` 0x72 unimplemented -- correct: deprecated) |
| Switch | 4 | 4 | 0 | 0 |
| Return | 4 | 4 | 0 | 0 |
| Static field access (`*static_*`) | 6 | 6 | 0 | 0 (`*static_b` deviating, see below) |
| Instance field access (`*field_*`) | 6 | 6 | 0 | 0 (`*field_b` deviating, see below) |
| Static byte field (`getstatic_b`, `putstatic_b`) | 2 | 0 | 2 | 0 |
| Instance byte field (`getfield_b`, `putfield_b`) | 2 | 0 | 2 | 0 |
| Method invocation | 4 | 4 | 0 | 0 |
| Object creation | 4 | 4 | 0 | 0 |
| Exception | 1 | 1 | 0 | 0 |
| Type check | 2 | 2 | 0 | 0 |
| **Wide-offset conditional branches** | 16 | **uncertain (see below)** | -- | -- |
| `goto_w` | 1 | 1 | 0 | 0 |
| `*_this` field accessors (0xAD..0xB8 range) | 0 | 0 | 0 | 16 (`getfield_*_this` x4, `putfield_*_this` x4, `getfield_*_w` x4, `putfield_*_w` x4) |
| Reserved (`impdep1` 0xB9, `impdep2` 0xBA) | 0 | 0 | 0 | 2 |

**Net deviations: 20 opcodes; missing: ~20 opcodes.** Of the
missing, the `*_this` and `*_w` field accessors are the highest-
value gap for real-world CAP compatibility (see Phase 2 below).

### A note on verification

The simrs repo does not check spec PDFs into git
(`docs/specs/javacard/3.2/JCVMSpec.pdf` is referenced but not
present locally). The opcode values asserted in this document as
"spec" come from the audit author's recollection of JCVM 3.x
Table 7-1, cross-checked against the in-source `NOTE: spec=`
comments left by previous contributors who did have spec access.

Where a value is asserted with high confidence (because both the
recollection and the in-source NOTE agree), the entry below uses
no qualifier. Where only one source is available, the entry is
marked **(unverified)**. The whole audit should be checked against
a fresh read of the spec before any change lands.

---

## Per-Opcode Comparison

### Local variable store (`*store` / `*store_n`)

The codebase rotated the entire store family by one. Each spec
value is one less than the codebase value, except for ISTORE which
collides with ASTORE_0 in the codebase and got bumped two further
to 0x2F.

| Opcode | simrs-jcvm-opcodes | JCVM 3.x spec | In-source NOTE |
|--------|--------------------|---------------|----------------|
| `astore` | 0x29 | **0x28** | -- |
| `sstore` | 0x28 | **0x29** | yes |
| `istore` | 0x2F | **0x2A** | yes (collision with codebase `ASTORE_0`) |
| `astore_0` | 0x2A | **0x2B** | yes |
| `astore_1` | (not declared) | **0x2C** | -- |
| `astore_2` | (not declared) | **0x2D** | -- |
| `astore_3` | (not declared) | **0x2E** | -- |
| `sstore_0` | 0x2B | **0x2F** | yes |
| `sstore_1` | 0x2C | **0x30** | -- |
| `sstore_2` | 0x2D | **0x31** | -- |
| `sstore_3` | 0x2E | **0x32** | -- |
| `istore_0` | 0x33 | 0x33 | (matches) |
| `istore_1` | 0x34 | 0x34 | (matches) |
| `istore_2` | 0x35 | 0x35 | (matches) |
| `istore_3` | 0x36 | 0x36 | (matches) |

Note that `astore_1..3` are entirely absent from
`simrs-jcvm-opcodes`; the interpreter dispatches `ASTORE_0..ASTORE_3`
as a range pattern over `0x2A..0x2D`, which happens to overlap with
the codebase `SSTORE_0..SSTORE_2`. **This is an actual semantic
collision**, not just a numbering deviation -- only mitigated by
the fact that no real CAP file currently exercises this path.

### Array load / store

Codebase swapped two pairs.

| Opcode | simrs-jcvm-opcodes | JCVM 3.x spec | In-source NOTE |
|--------|--------------------|---------------|----------------|
| `aaload` | 0x37 | **0x24** | -- |
| `baload` | 0x25 | 0x25 | (matches) |
| `saload` | 0x24 | **0x26** | yes |
| `iaload` | 0x39 | **0x27** | -- |
| `aastore` | 0x38 | **0x37** | -- |
| `bastore` | 0x27 | **0x38** | yes |
| `sastore` | 0x26 | **0x39** | yes |
| `iastore` | 0x3A | 0x3A | (matches) |

`iaload`'s codebase value 0x39 collides with spec `sastore`. This
is the kind of swap that produces silent miscompilation when fed
a real CAP file.

### Stack manipulation: `swap` / `dup_x` / `swap_x`

JCVM 3.x defines 0x3F as `dup_x` (parameterised dup with an
operand byte) and 0x40 as `swap_x` (parameterised swap). The
codebase declares neither; instead it has `SWAP = 0x3F` with no
operand, used by the assembler/codegen as a primitive 2-operand
swap. This is non-spec.

| Opcode | simrs-jcvm-opcodes | JCVM 3.x spec | In-source NOTE |
|--------|--------------------|---------------|----------------|
| `dup_x` | (not declared) | **0x3F** | (codebase `SWAP` collides) |
| `swap_x` | (not declared) | **0x40** | -- |
| `swap` | 0x3F | (no plain `swap` opcode in JCVM) | yes |

### Field accessors: `*_b` variants

Spec interleaves `_a` / `_b` / `_s` / `_i` at consecutive opcodes
(0x7B..0x7E for getstatic, 0x83..0x86 for getfield, etc.). The
codebase committed `_a` / `_s` / `_i` at the spec values but
parked `_b` at 0xAD..0xB5 (the spec range used for `getfield_*_this`).

| Opcode | simrs-jcvm-opcodes | JCVM 3.x spec | In-source NOTE |
|--------|--------------------|---------------|----------------|
| `getstatic_a` | 0x7B | 0x7B | (matches) |
| `getstatic_b` | 0xB3 | **0x7C** | yes |
| `getstatic_s` | 0x7D | 0x7D | (matches) |
| `getstatic_i` | 0x7E | 0x7E | (matches) |
| `putstatic_a` | 0x7F | 0x7F | (matches) |
| `putstatic_b` | 0xB5 | **0x80** | yes |
| `putstatic_s` | 0x81 | 0x81 | (matches) |
| `putstatic_i` | 0x82 | 0x82 | (matches) |
| `getfield_a` | 0x83 | 0x83 | (matches) |
| `getfield_b` | 0xAD | **0x84** | yes |
| `getfield_s` | 0x85 | 0x85 | (matches) |
| `getfield_i` | 0x86 | 0x86 | (matches) |
| `putfield_a` | 0x87 | 0x87 | (matches) |
| `putfield_b` | 0xAF | **0x88** | yes |
| `putfield_s` | 0x89 | 0x89 | (matches) |
| `putfield_i` | 0x8A | 0x8A | (matches) |

The 0xAD/0xAF/0xB3/0xB5 squat **directly on top of the
`getfield_a_this`/`getfield_s_this`/`putfield_a_this`/`putfield_s_this`
opcodes** in the spec range. Implementing `*_this` later (Phase 3
in [06-globalplatform.md](06-globalplatform.md)) will require
relocating these legacy values first.

### Wide-offset conditional branches (UNVERIFIED)

The recent commit (`3737eef`, 2026-05-03) added 16 wide-offset
conditional branches at `0x96..=0xA5`. The audit author's
recollection of the JCVM 3.x table puts:

- `0x96` = `sinc_w` (extended-format short increment)
- `0x97` = `iinc_w` (extended-format int increment)
- `0x98..=0xA7` = wide branches (16 of them)

If that recollection is correct, the simrs wide-branch range is
**off by two** -- it sits on top of `sinc_w`/`iinc_w` and stops
at 0xA5 instead of running to 0xA7 (so `if_scmpgt_w` and
`if_scmple_w` would then be at the wrong values too).

**This needs verification** against a primary source before either
relocating the simrs constants or asserting the codebase is
correct. Possible sources: the JCVM 3.0.5 / 3.1 / 3.2 PDF, the
Oracle JCDK `tools.jar` opcode tables, or the `jvc_decoder` source
if any open-source converter project exposes it.

### Other deviations / NOTEs left in source

| Note | Issue |
|------|-------|
| `SWAP = 0x3F` documented as "spec calls this `dup_x`" | Real `dup_x` takes an operand byte; codebase `SWAP` is operand-less. Different semantics, same opcode value -- **not just a renaming** |
| `IIPUSH = 0x14` | Spec value (verified by recollection); 0x12/0x13 are reserved/`bipush`-`sipush` unused in JC |

---

## Structural compliance (CAP file format, not opcodes)

The CAP component model is in `simrs-jcvm/src/cap/components.rs`
and writer in `simrs-jacc/src/cap/writer.rs`. Status from
[06-globalplatform.md](06-globalplatform.md):

- **Header (tag 1):** complete
- **Directory (tag 2):** writer emits zero-size self-referential
  body per spec; parser walks-and-skips
- **Applet (tag 3):** complete
- **Import (tag 4):** complete
- **ConstantPool (tag 5):** raw 4-byte form preserved; decoded on
  demand via `CpInfo::as_*`. Surfaces Classref / InstanceFieldref
  / VirtualMethodref / SuperMethodref / StaticFieldref /
  StaticMethodref. Tag 7 unassigned in spec, silently skipped.
- **Class (tag 6):** MVP -- `class_info` header + `super_class_ref`
  + `interface_count`. `implemented_interfaces[]` walked-and-skipped;
  per-class virtual method tables unsurfaced
- **Method (tag 7):** complete
- **StaticField (tag 8):** summary only; full image
  (`array_init` + `non_default_values`) not surfaced
- **RefLocation (tag 9):** complete; both 1-byte and 2-byte tables
- **Export (tag 10):** complete
- **Descriptor (tag 11):** walk-and-skip; offsets cross-validated
  against Class component for security (Lancia/Bouffard CARDIS 2015)
- **Debug (tag 12):** walk-and-skip
- **StaticResources (tag 13):** walk-and-skip

No structural non-compliance flagged by the parser/writer code as
of 2026-05-04. Token-based linking at `invoke*` time (Phase 2 step 3)
is unimplemented.

---

## Migration plan

Bringing opcode compliance is non-trivial because the codebase has
~30 deviations, each touching the interpreter dispatch, the
assembler mnemonic table, the writer/converter, and a body of
tests that use raw hex bytes (e.g. `[0x7A]` for `return`).

### Phase A: feature-flagged spec compliance (proposed)

1. **Add `simrs-jcvm-opcodes::spec` submodule** with the spec-correct
   constant set. Both the legacy and spec sets compile by default.
2. **Add a `simrs-jcvm` build feature `spec-opcodes`** that
   re-exports the spec set as the canonical one. Off by default;
   on for converter-interop tests.
3. **CAP file header carries the encoder-version.** When the parser
   sees a CAP from the legacy encoder, it pre-rewrites bytecodes
   into the canonical spec set; same for the spec encoder going
   the other direction. This is a one-pass byte-substitution
   keyed on the opcode prefix. The dispatch path uses one set
   only.
4. **Differential test against an Oracle-converted CAP file.**
   Take a known-good `HelloWorld.cap` from the JCDK; run it
   through both spec and legacy paths; assert identical APDU
   responses.

### Phase B: drop the legacy set

Once Oracle-converted CAPs run cleanly through the spec path and
the existing tests are migrated to use named constants
(`opcodes::SRETURN`) instead of raw hex (`0x78`), delete the
legacy set and the rewrite layer.

### Phase C: fill the missing opcodes

`*_this` / `*_w` field accessors, `dup_x`, `swap_x`, `sinc_w`,
`iinc_w`, `impdep1`, `impdep2` -- in priority order. The `*_this`
opcodes are ~3-byte savings per access on a `this`-receiver field
read; converters emit them aggressively for instance-method
implementations, so missing them blocks most real applets.

`jsr` / `ret` are deprecated in JCVM 3.x and should not be
implemented (Oracle's converter doesn't emit them).

---

## Why this gap exists

Reconstructed from `git blame` and the in-source `NOTE:` comments:

- The opcode set in `simrs-jcvm-opcodes` predates the spec
  numbering being finalised in this codebase. Early choices
  (e.g. `SWAP=0x3F`, `SSTORE=0x28`) were made without spec
  reference and committed.
- Later contributors verified spec values against the JCVM PDF
  and added `NOTE: spec=...` comments rather than relocating the
  constants -- an explicit choice to avoid breaking the existing
  test suite mid-development.
- The decision was prudent at the time (it kept the build green)
  but the gap accumulated. This audit is the inflection point:
  either invest in compliance now, or accept that simrs is a
  "JCVM-shaped VM" rather than a JCVM.

---

## Open questions

1. **Wide-branch opcode range:** is 0x96..0xA5 correct, or should
   it be 0x98..0xA7 (with 0x96/0x97 reserved for `sinc_w`/`iinc_w`)?
   Need spec read.
2. **Does the spec define a plain `swap` (0x40 vs 0x3F)?** Or only
   the parameterised `swap_x`? The codebase `SWAP` would be a
   simrs-specific extension if the latter; that would warrant
   either a rename to make the extension status explicit, or
   removal in favour of `swap_x` proper.
3. **Are `bipush` (0x12) and `sipush` (0x13)** reserved/unused in
   JCVM, or is the codebase simply not implementing them? The
   `SIPUSH = SSPUSH` alias at 0x11 suggests the latter, which is
   a confusing naming choice if `sipush` is also a real spec
   opcode at 0x13.

These should be answered against the spec PDF before the migration
plan moves past the audit stage.
