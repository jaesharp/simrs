# Session Handoff: 2026-03-26 through 2026-03-30

## What Was Built (35 commits)

### GP Compliance (commits 1-9)
- SCP03 secure channel protocol (GP 2.3.1 Amendment D)
  - AES-CMAC (RFC 4493) in simrs-iso9797
  - KDF, session keys, cryptograms, C-MAC, C-ENC, R-MAC
  - ScpVersion::Scp03, ScpId::Scp03, widened ICV [u8;16]
  - process_initialize_update_scp03 (29-byte response)
  - process_external_authenticate_scp03
  - Snapshot tag 4 for SCP03 Authenticated state
- ScpSessionHost trait (polymorphic BDD test dispatch)
- 8 GP 2.1.1 compliance fixes from differential testing
- Functional parity: IIN data, richer FCI with card recognition OIDs,
  GP 2.3 8-byte ISD AID, D6 padding oracle defense documented
- 11/11 differential divergences addressed vs Oracle jcsl
- 5 SCP03 BDD scenarios, 23 differential tests, 22 replay tests

### JVA Compiler Toolchain (commits 10-35)
- **simrs-jcasm**: proc-macro assembler (`jcasm!{}`)
  - 145 opcodes in assembler table
  - 75 tests (targeted + PBT)
- **simrs-jccompile**: compiler core library
  - IR: JcClass/JcMethod/JcStmt/JcExpr with full type system
  - Types: Short, Byte, Boolean, Int, IntArray, RefArray, Instance
  - Type checker with local/field resolution
  - Codegen emitting 123 of 144 opcodes
  - Optimizer: IR constant folding + DCE + strength reduction
  - Peephole optimizer with CFG metadata and branch-aware offset patching
  - Side-effect safety audit (is_side_effect_free guard on 6 transforms)
  - Source maps (.jvamap format)
  - 195 tests (135 unit + 60 integration)
- **simrs-jcasm-jva**: proc-macro high-level DSL (`jcapplet!{}`)
  - Fields, methods, let/assign/return/if/while/arithmetic
  - 15 integration tests
- **jvac**: full SDK compiler CLI
  - Java/JVA source parser (lexer + recursive descent)
  - .class/.jvc classfile reader (JVMS Chapter 4)
  - Full JCVM 3.1 CAP component writer (10 components)
  - Decompiler (disassembler + CFG analysis + source reconstruction)
  - 138 tests (69 unit + 15 compile + 54 decompile/roundtrip/PBT)
- **JCVM**: full instruction set
  - 144 opcodes (up from 43 at session start)
  - 356 tests with spec-level coverage
  - Native method dispatch for javacard.framework API (25 stubs)
  - LOAD/INSTALL/APDU dispatch wired through GP OPEN
- **JCVM security tests**: 8 BDD scenarios using jcasm assembler
  - Spec references to JCVM 3.1, JCRE 2.2.1, attack papers

## Test Counts (all passing)

| Crate/Tool | Tests |
|-----------|-------|
| simrs-jcvm (JCVM) | 356 |
| simrs-jccompile (compiler core) | 195 |
| jvac (SDK/CLI) | 138 |
| simrs-jcasm (assembler) | 75 |
| simrs-jcasm-jva (proc-macro DSL) | 15 |
| simrs-gp-open | 71 |
| simrs-gp-scp | 31 |
| simrs-gp-card | 15 |
| simrs-gp-keys | 14 |
| simrs-iso9797 | 17 |
| GP BDD scenarios | 102 (795 steps) |
| Differential tests | 45 (23 diff + 22 replay) |
| jcasm security tests | 32 |
| **TOTAL** | **~1100+** |

## Architecture

```
.java/.jva source -> jvac parser -> JcIR -> type check -> optimize -> codegen -> .cap
.class/.jvc file  -> jvac reader -> JcIR ---|                                    |
.cap file         -> jvac decompiler <------|--- disassemble / decompile          |
                                            |                                    v
jcasm!{}  -> proc-macro assembler -> bytecodes -> build_cap_blob -----------> .cap
jcapplet!{} -> proc-macro compiler -> JcIR -> codegen -> bytecodes --------> .cap
                                                                              |
GP LOAD APDU  <--- .cap blocks --->  parse_cap -> JcVM::load_package         |
GP INSTALL    <--- applet AID --->   AppletEntry + jcvm_pkg_idx              |
GP SELECT     <--- SELECT by AID -> channels[ch].selected_applet             |
APDU dispatch <--- any APDU -----> JcVM::execute(pkg_idx, process_method) -> response
```

## Key Files

### GP / SCP
- `crates/simrs-gp-open/src/lib.rs` -- GpOpen runtime + JCVM integration
- `crates/simrs-gp-open/src/commands.rs` -- LOAD, INSTALL, GET STATUS, etc.
- `crates/simrs-gp-scp/src/scp03.rs` -- SCP03 protocol implementation
- `crates/simrs-gp-scp/src/lib.rs` -- SCP state machine
- `crates/simrs-iso9797/src/lib.rs` -- AES-CMAC (RFC 4493)

### JCVM
- `crates/simrs-jcvm/src/lib.rs` -- VM interpreter (144 opcodes + 356 tests)
- `crates/simrs-jcvm/src/opcodes.rs` -- opcode constants + ExecResult
- `crates/simrs-jcvm/src/heap.rs` -- object heap with firewall
- `crates/simrs-jcvm/src/native.rs` -- Java Card API native stubs
- `crates/simrs-jcvm/src/cap.rs` -- CAP blob parser

### Compiler
- `crates/simrs-jccompile/src/ir.rs` -- intermediate representation
- `crates/simrs-jccompile/src/types.rs` -- Java Card type system
- `crates/simrs-jccompile/src/check.rs` -- type checker
- `crates/simrs-jccompile/src/codegen.rs` -- bytecode emission + CFG metadata
- `crates/simrs-jccompile/src/optimize.rs` -- IR optimizer + peephole
- `crates/simrs-jccompile/src/sourcemap.rs` -- .jvamap source maps

### SDK
- `tools/jvac/src/java_parser/` -- Java/JVA source lexer + parser
- `tools/jvac/src/classfile/` -- .class file reader + JcIR converter
- `tools/jvac/src/cap/writer.rs` -- full JCVM 3.1 CAP component writer
- `tools/jvac/src/decompile/` -- disassembler + CFG + source reconstruction
- `tools/jvac/src/main.rs` -- CLI entry point

### Assembler
- `crates/simrs-jcasm/src/` -- jcasm!{} proc-macro (145 opcodes)
- `crates/simrs-jcasm-jva/src/` -- jcapplet!{} proc-macro

## What's NOT Done (Next Session Priorities)

### P0: Pending from this session
1. **Optimizer security proof tests** -- the user requested tests that:
   - PROVE the JCVM has side effects (firewall, null, div-by-zero)
   - PROVE that unguarded optimizations break when applied to effectful code
   - Serve as regression tests for the is_side_effect_free() guards
   - This was the last item requested but not yet implemented

2. **Assembler optimizer** -- the jcasm proc-macro should also peephole-optimize
   its output, sharing the same patterns as the compiler peephole

### P1: Sprint 2 (real applet execution)
3. **More Java Card API methods** -- the native stubs are minimal. For real
   applets need: APDU buffer management, Util.arrayCopy with actual heap ops,
   ISOException.throwIt propagating SWs, OwnerPIN.check()
4. **Classfile bytecode translation** -- the .class reader parses classfiles
   but the JVM->JCVM bytecode mapping is incomplete
5. **Multi-class/package support** -- real applets import framework packages
6. **HelloWorld sample** -- compile and run the Oracle HelloWorld.java end-to-end

### P2: Infrastructure
7. **CardBackend trait** for BDD tests against both simrs and Oracle
   (design completed, not implemented -- see session analysis)
8. **jvad as standalone tool** (currently decompiler is inside jvac)
9. **JCVM package snapshot** -- packages/heap not persisted across card reset
10. **.jvamap integration** -- source maps emitted but not consumed by decompiler

### P3: Spec compliance
11. **JCVM opcode numbering audit** -- our opcode values may differ from the
    actual JCVM 3.1 spec table. Need to verify against the spec PDF at
    `telecom-standards/globalplatform/GPC_2.3_D_SCP03_v1.1.2.pdf` and
    the Java Card VM spec
12. **Full GP 2.3.1 support** -- contactless services, SSD management,
    receipt generation, CVM (Amendment C features)

## Spec References

All in `telecom-standards/globalplatform/`:
- `GPC_CardSpecification_v2.1.1.pdf` -- GP 2.1.1 (SCP01/02)
- `GPC_CardSpecification_v2.3.1.pdf` -- GP 2.3.1 (SCP03)
- `GPC_2.3_D_SCP03_v1.1.2.pdf` -- SCP03 Amendment D

Java Card specs in `~/Downloads/`:
- `java_card_spec-3_1_0-u5-b_70-09_mar_2021.zip`
- `java_card_spec-3_2_0-b_185-18_jan_2023.zip`

Oracle reference in `tools/oracle-jcvm-ref/`:
- `runtime/bin/jcsl.orig` -- Oracle Java Card Simulator binary
- `samples/HelloWorld/` -- reference test applet

## Known Issues

1. **JCVM opcode numbering** -- values used may differ from JCVM 3.1 spec.
   Verified to work internally but not tested against real converted .cap files.
   The `no_opcode_value_collisions` test in opcodes.rs prevents duplicate values.

2. **invokevirtual** -- currently treated same as invokestatic (no virtual
   method table dispatch). Works for static methods and native stubs but
   won't support inheritance/polymorphism.

3. **Peephole optimizer** -- safe with CFG metadata but conservative. Only
   optimizes within basic blocks with same-size or shrinking replacements.
   Could be more aggressive with proper liveness analysis.

4. **Optimizer is_side_effect_free** -- intentionally conservative. Marks
   SelfField as effectful even for intra-context access because the IR
   doesn't carry context ownership info. Could be refined.

5. **Decompiler if/else reconstruction** -- sometimes reconstructs if/else
   as single-iteration while loops (semantically equivalent but less readable).

6. **GP JCVM integration** -- LOAD accumulates CAP blocks but the load_buffer
   is not snapshotted. JCVM packages and heap are not persisted across
   save_state/restore_state.

## Development Environment

- Rust edition 2024 (workspace-level)
- no_std core crates (simrs-jcvm, simrs-jccompile, simrs-gp-open, etc.)
- std tools (jvac, simrs-differential-tests, simrs-gp-tests)
- proptest for PBT, cucumber for BDD, insta for snapshot testing
- proc-macro2/syn/quote for compile-time assembler and DSL
- Oracle jcsl at `tools/oracle-jcvm-ref/runtime/bin/jcsl.orig`
