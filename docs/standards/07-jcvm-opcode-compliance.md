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

Beyond opcode numbering, the structural audit (CAP file format,
type descriptors, ConstantPool tag values, access flags) found
**three additional possible deviations** in the Descriptor /
Class component encodings that are tracked under "Per-structure
audit" below and Open Questions 4 and 5.

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
`simrs-jcvm-opcodes` and from the interpreter dispatch. The
interpreter handles only `ASTORE_0` as a single-value arm at 0x2A;
the spec's optimised `astore_1..astore_3` opcodes have no handler
at all. (No collision *within* the codebase mapping -- the audit
author asserted one in an earlier draft and was wrong.)

The real issue is **spec-CAP shadow dispatch**: when a CAP file
emitted by Oracle's converter (which uses the spec mapping) runs
under the legacy dispatcher, opcodes 0x2B..=0x2E in that CAP file
**intend** `astore_0..astore_3` but **dispatch as** the codebase's
`sstore_0..sstore_3` -- silently writing the *short* value at the
top of the stack into the wrong local instead of the *reference*.
This is the worst kind of miscompilation: no error, wrong result.

A complete audit of all interpreter range patterns vs spec follows.

### Spec-CAP shadow dispatch (interpreter range patterns)

The interpreter dispatches 7 ranges as match arms in
`simrs-jcvm/src/lib.rs`. Within the codebase opcode mapping these
arms are non-overlapping (verified). The risk is what they
accidentally dispatch when fed a spec-encoded CAP file:

| Codebase range | Range arm dispatches as | Spec mapping at same range | Shadow risk |
|----------------|-------------------------|----------------------------|-------------|
| `SCONST_M1..=SCONST_5` (0x02..=0x08) | `sconst_*` push short literal | `sconst_*` push short literal | none -- mapping coincides |
| `ICONST_M1..=ICONST_5` (0x09..=0x0F) | `iconst_*` push int literal | `iconst_*` push int literal | none -- mapping coincides |
| `ALOAD_0..=ALOAD_3` (0x18..=0x1B) | aload local 0..3 | aload local 0..3 | none |
| `SLOAD_0..=SLOAD_3` (0x1C..=0x1F) | sload local 0..3 | sload local 0..3 | none |
| `ILOAD_0..=ILOAD_3` (0x20..=0x23) | iload local 0..3 | iload local 0..3 | none |
| `SSTORE_0..=SSTORE_3` (0x2B..=0x2E) | sstore local 0..3 | **astore local 0..3** | **YES -- silent ref-vs-short miscompile** |
| `ISTORE_0..=ISTORE_3` (0x33..=0x36) | istore local 0..3 | istore local 0..3 | none |

Plus the single-arm stores:

| Codebase opcode | Spec opcode at same byte | Shadow risk |
|-----------------|-------------------------|-------------|
| `ASTORE = 0x29` (with operand) | spec `sstore` at 0x29 | YES -- ref-vs-short miscompile |
| `SSTORE = 0x28` (with operand) | spec `astore` at 0x28 | YES -- short-vs-ref miscompile |
| `ISTORE = 0x2F` (with operand) | spec `sstore_0` (no operand!) | **YES -- worse: operand-width mismatch** |
| `ASTORE_0 = 0x2A` (no operand) | spec `istore` at 0x2A (operand!) | **YES -- operand-width mismatch** |

The last two are particularly nasty because they desynchronise the
PC -- a spec-CAP `istore <idx>` becomes a codebase `astore_0`
followed by a misinterpreted next byte. After this point, every
subsequent opcode is at the wrong PC.

Same shadow pattern in array load/store (all operand-less, so no
PC desync, but read-vs-write swaps are still corruption-causing):

| Byte | Codebase dispatch | Spec semantics | Shadow risk |
|------|-------------------|----------------|-------------|
| 0x24 | `saload` (read short) | `aaload` (read ref) | type-confused read |
| 0x26 | `sastore` (write) | `saload` (read) | **write where spec reads** |
| 0x27 | `bastore` (write) | `iaload` (read) | **write where spec reads** |
| 0x37 | `aaload` (read) | `aastore` (write) | **read where spec writes** |
| 0x38 | `aastore` (write) | `bastore` (write) | type-confused write |
| 0x39 | `iaload` (read) | `sastore` (write) | **read where spec writes** |

Field accessors (operand-width mismatches):

| Byte | Codebase | Spec | PC desync? |
|------|----------|------|------------|
| 0xAD | `getfield_b` (with CP-token operand) | `getfield_a_this` (operand-less) | **YES** |
| 0xAF | `putfield_b` (with operand) | `getfield_s_this` (operand-less) | **YES** |
| 0xB3 | `getstatic_b` (with operand) | `putfield_s_this` (operand-less) | **YES** |
| 0xB5 | `putstatic_b` (with operand) | `putfield_i_this` (operand-less) | **YES** |

Stack: `SWAP = 0x3F` (operand-less) shadowed by spec `dup_x` (with
operand) -- another PC desync.

**Implication for the migration plan:** Phase A's "rewrite spec
opcodes to codebase opcodes at parse time" must handle these
operand-width mismatches, not just opcode value swaps. A simple
byte-substitution table won't suffice for the operand-width
cases (codebase `ISTORE`/`ASTORE_0` vs spec, codebase `*field_b`
vs spec `*field_*_this`, codebase `SWAP` vs spec `dup_x`); the
rewriter has to actually decode and re-encode the instruction
stream.

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

### Component-level scope summary

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

Token-based linking at `invoke*` time (Phase 2 step 3) is
unimplemented.

### Per-structure audit

#### Verified spec-aligned

| Structure | Location | Spec value | Status |
|-----------|----------|------------|--------|
| Component tags 1..13 | `simrs-jacc/src/cap/writer.rs:27-39` | JCVM § 6.2 Table 6-1 | aligned |
| ConstantPool tag values 1..6 | `simrs-jcvm/src/cap/mod.rs:429-439` | JCVM § 6.8 Table 6-7 | aligned |
| CAP magic 0xDECAFFED | `simrs-jcvm/src/cap/mod.rs:64` | JCVM § 6.3 | aligned |
| `bspush` operand: 1B signed -> sign-extend to short | `simrs-jcvm/src/lib.rs:343` | JCVM § 7 | aligned |
| `sspush` operand: 2B BE -> push as short | `simrs-jcvm/src/lib.rs:354` | JCVM § 7 | aligned |
| `iipush` operand: 4B BE -> push as int | `simrs-jcvm/src/lib.rs:367` | JCVM § 7 | aligned |
| Switch operand layout (`stableswitch`) | `simrs-jcvm-opcodes/src/lib.rs:321` | JCVM § 7 | aligned |
| `sinc` / `iinc` operand layout: `local_idx`(u8), `const`(i8) | `simrs-jcvm-opcodes/src/lib.rs:249-254` | JCVM § 7 | aligned |
| newarray atype constants 0x0A/0x0B/0x0D | `simrs-jcvm-opcodes/src/lib.rs:483-488` | JCVM § 6 | aligned |

#### Possible deviations -- need verification

##### Type descriptor encoding (`simrs-jacc/src/cap/writer.rs:60`)

Writer declares `TYPE_DESC_VOID = 0x03` and a comment in
`build_descriptor_body` claims "void return with no parameters =
0x03 (void)". But:

- The same writer's `FieldInfo::type_token` documentation (line 67)
  lists `0x02 = boolean, 0x03 = byte, 0x04 = short` -- so 0x03 is
  `byte`, not `void`, in the field-descriptor context.
- Audit author's recollection of JCVM § 6.13 type_descriptor nibble
  encoding: `0x1 = void, 0x2 = boolean, 0x3 = byte, 0x4 = short,
  0x5 = int, 0x6..0xA = reference variants`. Under that encoding
  `void` should be `0x1`, not `0x3`.
- Additionally, type descriptors are spec-defined as
  **packed-nibble** sequences with a `nibble_count` byte prefix.
  The writer's `body.extend(repeat_n(TYPE_DESC_VOID, methods.len()))`
  emits one byte per method, which is not the spec layout.

If the recollection holds, **two bugs**: wrong nibble value and wrong
encoding shape. Not currently a runtime issue because the simrs
parser walks-and-skips Descriptor and the legacy blob path doesn't
read type_descriptors at all. A real JCRE would reject these CAPs.

##### Class component access flag bit positions (`simrs-jcvm/src/cap/mod.rs:118-127`)

`ClassInfo` doc comment claims:

- `ACC_INTERFACE` = 0x80 (bit 7)
- `ACC_SHAREABLE` = 0x40 (bit 6)
- `ACC_REMOTE` = 0x20 (bit 5)
- low 4 bits (0x0F) = `interface_count`

Audit author's recollection of JCVM § 6.9.4 (class_info structure):

- bit 7 = `ACC_INTERFACE` -- matches
- bits 6..4 = reserved (zero per spec)
- bits 3..0 = `interface_count` -- matches

Recollection puts `ACC_SHAREABLE` and `ACC_REMOTE` in the
`interface_info` structure (a sibling of `class_info`), not at
bits 6/5 of the class_info bitfield. **Possible doc error**, but
the code only uses `interface_count = bits & 0x0F` and treats the
high bit as `ACC_INTERFACE`, so the runtime behaviour is correct
even if the comment is wrong. Verify against spec.

##### Field type token width (`simrs-jacc/src/cap/writer.rs:67`)

`FieldInfo::type_token` is `u8` and used as a single byte in
field descriptors at `build_descriptor_body:483`. Audit author's
recollection of JCVM § 6.13 puts the field-descriptor type as a
**u16** (packed `is_primitive: u1 | type_index: u15` or full
classref encoding). If recollection holds, the writer is emitting
the wrong width. **Verify against spec.**

##### Wide-branch range (already covered)

See "Per-Opcode Comparison" section above. 0x96..=0xA5 in the
codebase vs 0x98..=0xA7 in audit author's recollection. This is
also a structural question because the wide-branch operand width
is 2 bytes (BE signed offset), and which opcode prefixes that
operand depends on the answer.

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
3. **CAP file header carries the encoder-version, and the parser
   runs a real instruction-stream rewriter** when the encoder
   doesn't match the dispatcher. **Note:** a flat byte-substitution
   table is insufficient because of the operand-width mismatches
   catalogued in "Spec-CAP shadow dispatch" above (legacy `ISTORE`,
   `ASTORE_0`, `SWAP`, and `*field_b` differ from spec opcodes in
   operand presence at the same byte). The rewriter must walk the
   bytecode by spec-instruction-length tables, not by raw bytes.
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
4. **Type descriptor encoding (§ 6.13):** is the void nibble 0x1
   or 0x3? Is the field-descriptor `type` field a u8 or a u16?
   Is the type_descriptor blob a sequence of packed nibbles with
   a `nibble_count` prefix, or one byte per method as the writer
   currently emits?
5. **`ACC_SHAREABLE` / `ACC_REMOTE` in class_info:** are these
   bits 6/5 of the class_info bitfield (current doc claim), or
   members of a separate `interface_info` structure? The runtime
   uses neither for behaviour, but the doc claim should match
   reality.

These should be answered against the spec PDF before the migration
plan moves past the audit stage.
