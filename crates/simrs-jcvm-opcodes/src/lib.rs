//! JCVM bytecode opcode constants per JCVM 3.2 Chapter 7 (instruction
//! set; the table number was originally cited as 8-1 from a draft and
//! is not independently verified here).
//!
//! This is a leaf crate (`no_std`, zero dependencies) that provides the
//! canonical opcode numbering shared by the VM interpreter (`simrs-jcvm`),
//! the compiler (`simrs-jccompile`), and any other crate that needs to
//! emit or inspect JCVM bytecodes.
//!
//! # Opcode numbering
//!
//! All opcodes use the JCVM 3.2 specification numbering as recovered
//! from author recollection of Table 7-1. The codebase previously
//! had ~20 opcodes at non-spec values (a remnant of pre-spec-
//! finalisation choices); these were migrated to spec values in the
//! spec-compliance cutover commit.
//!
//! Two known residual deviations remain, tracked in
//! [`docs/standards/07-jcvm-opcode-compliance.md`](../../../../docs/standards/07-jcvm-opcode-compliance.md):
//!
//! - **`SWAP` at 0x3F (operand-less)** -- spec puts `dup_x` here
//!   with an operand byte, and `swap_x` at 0x40. Migrating this
//!   requires consumer-side changes across the assembler / codegen /
//!   tests / decompiler.
//! - **Wide-branch range 0x96..=0xA5** -- spec is widely understood
//!   to put `sinc_w`/`iinc_w` at 0x96/0x97 and the wide branches at
//!   0x98..=0xA7; pending spec-PDF verification before relocation.
//!
//! Missing opcodes (not yet implemented): `*_this` field accessors,
//! `*_w` wide field accessors, `dup_x`, `swap_x`, `sinc_w`,
//! `iinc_w`, `impdep1`, `impdep2`, `bipush`/`sipush` (if real).
//! `jsr`/`ret` are deprecated in JCVM 3.x and intentionally absent.

#![no_std]

// =========================================================================
// Opcode constants
//
// When adding a new opcode constant, also add it to `ALL_OPCODES` near
// the bottom of this file -- the compile-time uniqueness check uses
// that list, and a constant that's missing from the list silently
// escapes verification.
// =========================================================================

// --- Misc ---

/// `nop`: no operation
pub const NOP: u8 = 0x00;

// --- Constants: short ---

/// `sconst_m1`: push short -1
pub const SCONST_M1: u8 = 0x02;
/// `sconst_0`: push short 0
pub const SCONST_0: u8 = 0x03;
/// `sconst_1`: push short 1
pub const SCONST_1: u8 = 0x04;
/// `sconst_2`: push short 2
pub const SCONST_2: u8 = 0x05;
/// `sconst_3`: push short 3
pub const SCONST_3: u8 = 0x06;
/// `sconst_4`: push short 4
pub const SCONST_4: u8 = 0x07;
/// `sconst_5`: push short 5
pub const SCONST_5: u8 = 0x08;

// --- Constants: int (optional 32-bit support) ---

/// `iconst_m1`: push int -1 (as two stack words)
pub const ICONST_M1: u8 = 0x09;
/// `iconst_0`: push int 0
pub const ICONST_0: u8 = 0x0A;
/// `iconst_1`: push int 1
pub const ICONST_1: u8 = 0x0B;
/// `iconst_2`: push int 2
pub const ICONST_2: u8 = 0x0C;
/// `iconst_3`: push int 3
pub const ICONST_3: u8 = 0x0D;
/// `iconst_4`: push int 4
pub const ICONST_4: u8 = 0x0E;
/// `iconst_5`: push int 5
pub const ICONST_5: u8 = 0x0F;

// --- Constants: push immediates ---

/// `bspush`: push byte-extended-to-short
pub const BSPUSH: u8 = 0x10;
/// `sspush`: push short immediate (2 bytes, big-endian)
pub const SSPUSH: u8 = 0x11;
/// `iipush`: push int immediate (4 bytes, big-endian)
pub const IIPUSH: u8 = 0x14;

// --- Reference handling (references are u16 in JCVM) ---

/// `aconst_null`: push null reference (0x0000)
pub const ACONST_NULL: u8 = 0x01;

/// `aload`: load reference from local variable
pub const ALOAD: u8 = 0x15;
/// `aload_0`: load reference from local 0
pub const ALOAD_0: u8 = 0x18;
/// `aload_1`: load reference from local 1
pub const ALOAD_1: u8 = 0x19;
/// `aload_2`: load reference from local 2
pub const ALOAD_2: u8 = 0x1A;
/// `aload_3`: load reference from local 3
pub const ALOAD_3: u8 = 0x1B;

/// `astore`: store reference to local variable.
pub const ASTORE: u8 = 0x28;
/// `astore_0`: store reference to local 0.
pub const ASTORE_0: u8 = 0x2B;
/// `astore_1`: store reference to local 1.
pub const ASTORE_1: u8 = 0x2C;
/// `astore_2`: store reference to local 2.
pub const ASTORE_2: u8 = 0x2D;
/// `astore_3`: store reference to local 3.
pub const ASTORE_3: u8 = 0x2E;

// --- Local variable loads: short ---

/// `sload`: load short from local variable
pub const SLOAD: u8 = 0x16;
/// `sload_0`: load short from local 0
pub const SLOAD_0: u8 = 0x1C;
/// `sload_1`: load short from local 1
pub const SLOAD_1: u8 = 0x1D;
/// `sload_2`: load short from local 2
pub const SLOAD_2: u8 = 0x1E;
/// `sload_3`: load short from local 3
pub const SLOAD_3: u8 = 0x1F;

// --- Local variable loads: int ---

/// `iload`: load int from two consecutive locals (high, low)
pub const ILOAD: u8 = 0x17;
/// `iload_0`: load int from locals 0,1
pub const ILOAD_0: u8 = 0x20;
/// `iload_1`: load int from locals 1,2
pub const ILOAD_1: u8 = 0x21;
/// `iload_2`: load int from locals 2,3
pub const ILOAD_2: u8 = 0x22;
/// `iload_3`: load int from locals 3,4
pub const ILOAD_3: u8 = 0x23;

// --- Local variable stores: short ---

/// `sstore`: store short to local variable.
pub const SSTORE: u8 = 0x29;
/// `sstore_0`: store to local 0.
pub const SSTORE_0: u8 = 0x2F;
/// `sstore_1`: store to local 1.
pub const SSTORE_1: u8 = 0x30;
/// `sstore_2`: store to local 2.
pub const SSTORE_2: u8 = 0x31;
/// `sstore_3`: store to local 3.
pub const SSTORE_3: u8 = 0x32;

// --- Local variable stores: int ---

/// `istore`: store int to two consecutive locals (high, low).
pub const ISTORE: u8 = 0x2A;
/// `istore_0`: store int to locals 0,1
pub const ISTORE_0: u8 = 0x33;
/// `istore_1`: store int to locals 1,2
pub const ISTORE_1: u8 = 0x34;
/// `istore_2`: store int to locals 2,3
pub const ISTORE_2: u8 = 0x35;
/// `istore_3`: store int to locals 3,4
pub const ISTORE_3: u8 = 0x36;

// --- Array load/store ---

/// `aaload`: load reference from reference array.
pub const AALOAD: u8 = 0x24;
/// `baload`: load byte from byte array.
pub const BALOAD: u8 = 0x25;
/// `saload`: load short from short array.
pub const SALOAD: u8 = 0x26;
/// `iaload`: load int from int array (pushes two stack words).
pub const IALOAD: u8 = 0x27;
/// `aastore`: store reference to reference array.
pub const AASTORE: u8 = 0x37;
/// `bastore`: store byte to byte array.
pub const BASTORE: u8 = 0x38;
/// `sastore`: store short to short array.
pub const SASTORE: u8 = 0x39;
/// `iastore`: store int to int array (pops two stack words).
pub const IASTORE: u8 = 0x3A;

// --- Stack manipulation ---

/// `pop`: pop top of stack
pub const POP: u8 = 0x3B;
/// `pop2`: pop top two stack words
pub const POP2: u8 = 0x3C;
/// `dup`: duplicate top of stack
pub const DUP: u8 = 0x3D;
/// `dup2`: duplicate top two stack words
pub const DUP2: u8 = 0x3E;
/// `swap`: swap top two stack values.
///
/// **KNOWN DEVIATION**: spec puts `dup_x` at 0x3F (with operand
/// byte) and `swap_x` at 0x40 (with operand byte). Codebase `SWAP`
/// is operand-less and occupies the spec's `dup_x` byte. Migrating
/// this to spec semantics requires updating every consumer
/// (assembler, codegen, tests, decompiler) to emit operand bytes,
/// so it's deferred to a follow-up. Tracked in
/// `docs/standards/07-jcvm-opcode-compliance.md`.
pub const SWAP: u8 = 0x3F;

// --- Short arithmetic ---

/// `sadd`: short addition
pub const SADD: u8 = 0x41;
/// `ssub`: short subtraction
pub const SSUB: u8 = 0x43;
/// `smul`: short multiplication
pub const SMUL: u8 = 0x45;
/// `sdiv`: short division
pub const SDIV: u8 = 0x47;
/// `srem`: short remainder
pub const SREM: u8 = 0x49;
/// `sneg`: short negation
pub const SNEG: u8 = 0x4B;

// --- Int arithmetic (32-bit, two stack words) ---

/// `iadd`: int addition
pub const IADD: u8 = 0x42;
/// `isub`: int subtraction
pub const ISUB: u8 = 0x44;
/// `imul`: int multiplication
pub const IMUL: u8 = 0x46;
/// `idiv`: int division
pub const IDIV: u8 = 0x48;
/// `irem`: int remainder
pub const IREM: u8 = 0x4A;
/// `ineg`: int negation
pub const INEG: u8 = 0x4C;

// --- Short bitwise ---

/// `sshl`: short shift left (shift amount masked to 5 bits)
pub const SSHL: u8 = 0x4D;
/// `sshr`: short arithmetic shift right
pub const SSHR: u8 = 0x4F;
/// `sushr`: short logical (unsigned) shift right
pub const SUSHR: u8 = 0x51;
/// `sand`: short bitwise AND
pub const SAND: u8 = 0x53;
/// `sor`: short bitwise OR
pub const SOR: u8 = 0x55;
/// `sxor`: short bitwise XOR
pub const SXOR: u8 = 0x57;

// --- Int bitwise ---

/// `ishl`: int shift left (shift amount masked to 5 bits)
pub const ISHL: u8 = 0x4E;
/// `ishr`: int arithmetic shift right
pub const ISHR: u8 = 0x50;
/// `iushr`: int logical (unsigned) shift right
pub const IUSHR: u8 = 0x52;
/// `iand`: int bitwise AND
pub const IAND: u8 = 0x54;
/// `ior`: int bitwise OR
pub const IOR: u8 = 0x56;
/// `ixor`: int bitwise XOR
pub const IXOR: u8 = 0x58;

// --- Increment ---

/// `sinc`: increment short local by signed byte constant.
/// Format: `sinc` `local_idx`(u8) `const`(i8)
pub const SINC: u8 = 0x59;
/// `iinc`: increment int local pair by signed byte constant.
/// Format: `iinc` `local_idx`(u8) `const`(i8)
pub const IINC: u8 = 0x5A;

// --- Type conversion ---

/// `s2b`: short to byte (truncate to 8 bits, sign-extend back to 16)
pub const S2B: u8 = 0x5B;
/// `s2i`: short to int (sign-extend 16-bit to 32-bit, push 2 words)
pub const S2I: u8 = 0x5C;
/// `i2b`: int to byte (truncate to 8 bits, sign-extend to 16-bit short)
pub const I2B: u8 = 0x5D;
/// `i2s`: int to short (truncate to 16 bits)
pub const I2S: u8 = 0x5E;

// --- Int comparison ---

/// `icmp`: compare two ints, push -1, 0, or 1 as short
pub const ICMP: u8 = 0x5F;

// --- Comparison branches (1-byte signed offset) ---

/// `ifeq`: branch if top == 0
pub const IFEQ: u8 = 0x60;
/// `ifne`: branch if top != 0
pub const IFNE: u8 = 0x61;
/// `iflt`: branch if top < 0
pub const IFLT: u8 = 0x62;
/// `ifge`: branch if top >= 0
pub const IFGE: u8 = 0x63;
/// `ifgt`: branch if top > 0
pub const IFGT: u8 = 0x64;
/// `ifle`: branch if top <= 0
pub const IFLE: u8 = 0x65;
/// `ifnull`: branch if top is null (0)
pub const IFNULL: u8 = 0x66;
/// `ifnonnull`: branch if top is not null
pub const IFNONNULL: u8 = 0x67;

// --- Reference comparison branches ---

/// `if_acmpeq`: branch if two references are equal
pub const IF_ACMPEQ: u8 = 0x68;
/// `if_acmpne`: branch if two references are not equal
pub const IF_ACMPNE: u8 = 0x69;

// --- Short comparison branches ---

/// `if_scmpeq`: branch if two shorts are equal
pub const IF_SCMPEQ: u8 = 0x6A;
/// `if_scmpne`: branch if two shorts are not equal
pub const IF_SCMPNE: u8 = 0x6B;
/// `if_scmplt`: branch if first short < second
pub const IF_SCMPLT: u8 = 0x6C;
/// `if_scmpge`: branch if first short >= second
pub const IF_SCMPGE: u8 = 0x6D;
/// `if_scmpgt`: branch if first short > second
pub const IF_SCMPGT: u8 = 0x6E;
/// `if_scmple`: branch if first short <= second
pub const IF_SCMPLE: u8 = 0x6F;

// --- Unconditional branch ---

/// `goto`: unconditional branch (1-byte signed offset)
pub const GOTO: u8 = 0x70;

// --- Switch ---

/// `stableswitch`: short table switch.
/// Format: `default_offset`(2) | low(2) | high(2) | offsets\[(high-low+1) * 2\]
pub const STABLESWITCH: u8 = 0x73;
/// `itableswitch`: int table switch
pub const ITABLESWITCH: u8 = 0x74;
/// `slookupswitch`: short lookup switch.
/// Format: `default_offset`(2) | `npairs`(2) | \{ `match_value`(2) | offset(2) \} * npairs
pub const SLOOKUPSWITCH: u8 = 0x75;
/// `ilookupswitch`: int lookup switch
pub const ILOOKUPSWITCH: u8 = 0x76;

// --- Return ---

/// `areturn`: return reference from method
pub const ARETURN: u8 = 0x77;
/// `sreturn`: return short from method
pub const SRETURN: u8 = 0x78;
/// `ireturn`: return int (2 stack words) from method
pub const IRETURN: u8 = 0x79;
/// `return`: return void from method
pub const RETURN: u8 = 0x7A;

// --- Static field access ---

/// `getstatic_a`: get static reference field.
pub const GETSTATIC_A: u8 = 0x7B;
/// `getstatic_b`: get static byte field.
pub const GETSTATIC_B: u8 = 0x7C;
/// `getstatic_s`: get static short field.
pub const GETSTATIC_S: u8 = 0x7D;
/// `getstatic_i`: get static int field.
pub const GETSTATIC_I: u8 = 0x7E;
/// `putstatic_a`: put static reference field.
pub const PUTSTATIC_A: u8 = 0x7F;
/// `putstatic_b`: put static byte field.
pub const PUTSTATIC_B: u8 = 0x80;
/// `putstatic_s`: put static short field.
pub const PUTSTATIC_S: u8 = 0x81;
/// `putstatic_i`: put static int field.
pub const PUTSTATIC_I: u8 = 0x82;

// --- Instance field access ---

/// `getfield_a`: get reference field from instance.
pub const GETFIELD_A: u8 = 0x83;
/// `getfield_b`: get byte field from instance.
pub const GETFIELD_B: u8 = 0x84;
/// `getfield_s`: get short field from instance.
pub const GETFIELD_S: u8 = 0x85;
/// `getfield_i`: get int field from instance.
pub const GETFIELD_I: u8 = 0x86;
/// `putfield_a`: put reference field to instance.
pub const PUTFIELD_A: u8 = 0x87;
/// `putfield_b`: put byte field to instance.
pub const PUTFIELD_B: u8 = 0x88;
/// `putfield_s`: put short field to instance.
pub const PUTFIELD_S: u8 = 0x89;
/// `putfield_i`: put int field to instance.
pub const PUTFIELD_I: u8 = 0x8A;

// --- Method invocation ---

/// `invokevirtual`: invoke virtual method
pub const INVOKEVIRTUAL: u8 = 0x8B;
/// `invokespecial`: invoke special (init/super) method
pub const INVOKESPECIAL: u8 = 0x8C;
/// `invokestatic`: invoke a static method
pub const INVOKESTATIC: u8 = 0x8D;
/// `invokeinterface`: invoke interface method
pub const INVOKEINTERFACE: u8 = 0x8E;

// --- Object creation ---

/// `new`: create object instance
pub const NEW: u8 = 0x8F;
/// `newarray`: create primitive array
pub const NEWARRAY: u8 = 0x90;
/// `anewarray`: create reference array
pub const ANEWARRAY: u8 = 0x91;
/// `arraylength`: get array length
pub const ARRAYLENGTH: u8 = 0x92;

// --- Exception ---

/// `athrow`: throw exception
pub const ATHROW: u8 = 0x93;

// --- Type checking ---

/// `checkcast`: check type cast (stub: always succeeds for now)
pub const CHECKCAST: u8 = 0x94;
/// `instanceof`: check instance type (stub: always returns 1 for now)
pub const INSTANCEOF: u8 = 0x95;

// --- Wide branch ---
//
// All `*_w` variants take a 2-byte signed offset (big-endian) and
// compute the target as `(opcode_pc) + offset`, where `opcode_pc`
// is the address of the opcode itself (i.e. `pc - 3` after the
// 1-byte opcode + 2-byte operand have been consumed).
//
// JCVM 3.2 § 7.5: every narrow conditional branch at 0x60..=0x6F
// has a wide counterpart with the same stack effect and comparison;
// only the operand width differs. The wide form is emitted by the
// converter when the target is outside the narrow `[-128, +127]`
// byte-offset reach.
//
// **UNVERIFIED** opcode range: codebase places these at 0x96..=0xA5.
// The audit author's recollection of JCVM 3.x Table 7-1 puts them
// at 0x98..=0xA7, with 0x96/0x97 reserved for `sinc_w`/`iinc_w`
// (extended-format increments). If that recollection is correct,
// every wide-branch constant below is off by 2 and stops 2 short.
// This needs verification against a primary source before either
// relocating these constants or asserting the codebase is correct.
// See `docs/standards/07-jcvm-opcode-compliance.md` open question
// #1.

/// `ifeq_w`: branch if top == 0 (2-byte signed offset)
pub const IFEQ_W: u8 = 0x96;
/// `ifne_w`: branch if top != 0
pub const IFNE_W: u8 = 0x97;
/// `iflt_w`: branch if top < 0
pub const IFLT_W: u8 = 0x98;
/// `ifge_w`: branch if top >= 0
pub const IFGE_W: u8 = 0x99;
/// `ifgt_w`: branch if top > 0
pub const IFGT_W: u8 = 0x9A;
/// `ifle_w`: branch if top <= 0
pub const IFLE_W: u8 = 0x9B;
/// `ifnull_w`: branch if top is null (0)
pub const IFNULL_W: u8 = 0x9C;
/// `ifnonnull_w`: branch if top is not null
pub const IFNONNULL_W: u8 = 0x9D;
/// `if_acmpeq_w`: branch if two references are equal
pub const IF_ACMPEQ_W: u8 = 0x9E;
/// `if_acmpne_w`: branch if two references are not equal
pub const IF_ACMPNE_W: u8 = 0x9F;
/// `if_scmpeq_w`: branch if two shorts are equal
pub const IF_SCMPEQ_W: u8 = 0xA0;
/// `if_scmpne_w`: branch if two shorts are not equal
pub const IF_SCMPNE_W: u8 = 0xA1;
/// `if_scmplt_w`: branch if first short < second
pub const IF_SCMPLT_W: u8 = 0xA2;
/// `if_scmpge_w`: branch if first short >= second
pub const IF_SCMPGE_W: u8 = 0xA3;
/// `if_scmpgt_w`: branch if first short > second
pub const IF_SCMPGT_W: u8 = 0xA4;
/// `if_scmple_w`: branch if first short <= second
pub const IF_SCMPLE_W: u8 = 0xA5;

/// `goto_w`: unconditional branch (2-byte signed offset)
pub const GOTO_W: u8 = 0xA8;

// --- Aliases ---

/// `sipush`: alias for `sspush` (push short immediate)
pub const SIPUSH: u8 = SSPUSH;

// =========================================================================
// Newarray type tokens (JCVM 3.2; verified against 3.1 Table 6-3,
// retained unchanged in 3.2)
// =========================================================================

/// Newarray type token for `byte[]`.
pub const ARRAY_TYPE_BYTE: u8 = 0x0A;
/// Newarray type token for `short[]`.
pub const ARRAY_TYPE_SHORT: u8 = 0x0B;
/// Newarray type token for `int[]`.
pub const ARRAY_TYPE_INT: u8 = 0x0D;

// =========================================================================
// Compile-time uniqueness check
// =========================================================================

/// Canonical list of all defined opcode bytes -- everything in the
/// 0x00..=0xFF instruction-set range. Newarray atype constants
/// (`ARRAY_TYPE_*`) are deliberately excluded because they share the
/// 0x0A..=0x0D byte range with `iconst_*` opcodes by spec design (they
/// occupy different namespaces: instruction stream vs `newarray`
/// operand byte).
///
/// The `SIPUSH` alias is also excluded because it intentionally
/// coincides with `SSPUSH`.
const ALL_OPCODES: &[u8] = &[
    NOP,
    ACONST_NULL,
    SCONST_M1,
    SCONST_0,
    SCONST_1,
    SCONST_2,
    SCONST_3,
    SCONST_4,
    SCONST_5,
    ICONST_M1,
    ICONST_0,
    ICONST_1,
    ICONST_2,
    ICONST_3,
    ICONST_4,
    ICONST_5,
    BSPUSH,
    SSPUSH,
    IIPUSH,
    ALOAD,
    SLOAD,
    ILOAD,
    ALOAD_0,
    ALOAD_1,
    ALOAD_2,
    ALOAD_3,
    SLOAD_0,
    SLOAD_1,
    SLOAD_2,
    SLOAD_3,
    ILOAD_0,
    ILOAD_1,
    ILOAD_2,
    ILOAD_3,
    AALOAD,
    BALOAD,
    SALOAD,
    IALOAD,
    AASTORE,
    BASTORE,
    SASTORE,
    IASTORE,
    SSTORE,
    ASTORE,
    ASTORE_0,
    ASTORE_1,
    ASTORE_2,
    ASTORE_3,
    ISTORE,
    SSTORE_0,
    SSTORE_1,
    SSTORE_2,
    SSTORE_3,
    ISTORE_0,
    ISTORE_1,
    ISTORE_2,
    ISTORE_3,
    POP,
    POP2,
    DUP,
    DUP2,
    SWAP,
    SADD,
    IADD,
    SSUB,
    ISUB,
    SMUL,
    IMUL,
    SDIV,
    IDIV,
    SREM,
    IREM,
    SNEG,
    INEG,
    SSHL,
    ISHL,
    SSHR,
    ISHR,
    SUSHR,
    IUSHR,
    SAND,
    IAND,
    SOR,
    IOR,
    SXOR,
    IXOR,
    SINC,
    IINC,
    S2B,
    S2I,
    I2B,
    I2S,
    ICMP,
    IFEQ,
    IFNE,
    IFLT,
    IFGE,
    IFGT,
    IFLE,
    IFNULL,
    IFNONNULL,
    IF_ACMPEQ,
    IF_ACMPNE,
    IF_SCMPEQ,
    IF_SCMPNE,
    IF_SCMPLT,
    IF_SCMPGE,
    IF_SCMPGT,
    IF_SCMPLE,
    GOTO,
    STABLESWITCH,
    ITABLESWITCH,
    SLOOKUPSWITCH,
    ILOOKUPSWITCH,
    ARETURN,
    SRETURN,
    IRETURN,
    RETURN,
    GETSTATIC_A,
    GETSTATIC_B,
    GETSTATIC_S,
    GETSTATIC_I,
    PUTSTATIC_A,
    PUTSTATIC_B,
    PUTSTATIC_S,
    PUTSTATIC_I,
    GETFIELD_A,
    GETFIELD_B,
    GETFIELD_S,
    GETFIELD_I,
    PUTFIELD_A,
    PUTFIELD_B,
    PUTFIELD_S,
    PUTFIELD_I,
    INVOKEVIRTUAL,
    INVOKESPECIAL,
    INVOKESTATIC,
    INVOKEINTERFACE,
    NEW,
    NEWARRAY,
    ANEWARRAY,
    ARRAYLENGTH,
    ATHROW,
    CHECKCAST,
    INSTANCEOF,
    IFEQ_W,
    IFNE_W,
    IFLT_W,
    IFGE_W,
    IFGT_W,
    IFLE_W,
    IFNULL_W,
    IFNONNULL_W,
    IF_ACMPEQ_W,
    IF_ACMPNE_W,
    IF_SCMPEQ_W,
    IF_SCMPNE_W,
    IF_SCMPLT_W,
    IF_SCMPGE_W,
    IF_SCMPGT_W,
    IF_SCMPLE_W,
    GOTO_W,
];

/// Assert at compile time that every opcode in `ALL_OPCODES` is
/// pairwise distinct.
///
/// Panics during `cargo build` (not at run time) if two opcodes share
/// the same byte value. This is the structural guarantee that the
/// dispatcher cannot accidentally route the same byte to two different
/// match arms -- catches future regressions when adding opcodes.
const fn assert_opcodes_unique(opcodes: &[u8]) {
    let mut i = 0;
    while i < opcodes.len() {
        let mut j = i + 1;
        while j < opcodes.len() {
            assert!(opcodes[i] != opcodes[j], "duplicate opcode byte");
            j += 1;
        }
        i += 1;
    }
}

const _: () = assert_opcodes_unique(ALL_OPCODES);

#[cfg(test)]
mod uniqueness_tests {
    use super::*;

    /// The compile-time assertion `assert_opcodes_unique(ALL_OPCODES)`
    /// runs at build time. This runtime test re-verifies it with a
    /// human-readable diagnostic that names *which* entries collided
    /// (the const-fn `assert!` only says "duplicate opcode byte"),
    /// useful when extending `ALL_OPCODES`.
    #[test]
    fn all_opcodes_are_pairwise_distinct() {
        let mut seen: [Option<usize>; 256] = [None; 256];
        for (i, &opcode) in ALL_OPCODES.iter().enumerate() {
            let idx = opcode as usize;
            if let Some(j) = seen[idx] {
                panic!(
                    "duplicate opcode byte 0x{opcode:02X}: \
                     ALL_OPCODES[{j}] and ALL_OPCODES[{i}]",
                );
            }
            seen[idx] = Some(i);
        }
    }
}
