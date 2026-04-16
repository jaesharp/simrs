//! Bytecode execution engine for the JCVM.
//!
//! Implements the dispatch loop and individual opcode handlers per
//! JCVM 3.1 Chapter 7. The interpreter reads bytecodes from the
//! current method's bytecode buffer and manipulates the operand stack,
//! local variables, and heap.
//!
//! # Opcode numbering
//!
//! New opcodes added here use the JCVM 3.1 specification numbering
//! (Oracle, Chapter 8 -- Table 8-1). A handful of the *original*
//! opcodes were committed before the spec numbering was finalised and
//! may differ from the canonical values (marked with `NOTE:` comments).
//! These will be reconciled when testing against real converted `.cap`
//! files.
//!
//! # Opcodes implemented
//!
//! | Range | Category | Opcodes |
//! |-------|----------|---------|
//! | 0x00 | Misc | `nop` |
//! | 0x01 | Constants | `aconst_null` |
//! | 0x02-0x08 | Constants | `sconst_m1` .. `sconst_5` |
//! | 0x09-0x0F | Constants | `iconst_m1` .. `iconst_5` |
//! | 0x10-0x11 | Constants | `bspush`, `sspush` |
//! | 0x14 | Constants | `iipush` |
//! | 0x15 | Locals | `aload` |
//! | 0x16 | Locals | `sload` |
//! | 0x17 | Locals | `iload` |
//! | 0x18-0x1B | Locals | `aload_0` .. `aload_3` |
//! | 0x1C-0x1F | Locals | `sload_0` .. `sload_3` |
//! | 0x20-0x23 | Locals | `iload_0` .. `iload_3` |
//! | 0x24-0x27 | Arrays | `saload`, `baload`, `sastore`, `bastore` |
//! | 0x28-0x29 | Locals | `sstore`, `astore` |
//! | 0x2A | Locals | `astore_0` |
//! | 0x2B-0x2E | Locals | `sstore_0` .. `sstore_3` |
//! | 0x2F | Locals | `istore` |
//! | 0x33-0x36 | Locals | `istore_0` .. `istore_3` |
//! | 0x37 | Arrays | `aaload` |
//! | 0x38 | Arrays | `aastore` |
//! | 0x3A | Arrays | `iastore` |
//! | 0x39 | Arrays | `iaload` |
//! | 0x3B-0x3E | Stack | `pop`, `pop2`, `dup`, `dup2` |
//! | 0x3F | Stack | `swap` |
//! | 0x41-0x4B | Arithmetic | `sadd`..`sneg` (short, odd slots) |
//! | 0x42-0x4C | Arithmetic | `iadd`..`ineg` (int, even slots) |
//! | 0x4D-0x58 | Bitwise | `sshl`..`ixor` |
//! | 0x59-0x5A | Increment | `sinc`, `iinc` |
//! | 0x5B-0x5E | Conversion | `s2b`, `s2i`, `i2b`, `i2s` |
//! | 0x5F | Comparison | `icmp` |
//! | 0x60-0x67 | Branch | `ifeq`..`ifnonnull` |
//! | 0x68-0x69 | Branch | `if_acmpeq`, `if_acmpne` |
//! | 0x6A-0x6F | Branch | `if_scmpeq`..`if_scmple` |
//! | 0x70 | Branch | `goto` |
//! | 0x73-0x76 | Switch | `stableswitch`..`ilookupswitch` |
//! | 0x77 | Return | `areturn` |
//! | 0x78 | Return | `sreturn` |
//! | 0x79 | Return | `ireturn` |
//! | 0x7A | Return | `return` |
//! | 0x7B-0x7E | Fields | `getstatic_a`..`getstatic_i` |
//! | 0x7F-0x82 | Fields | `putstatic_a`..`putstatic_i` |
//! | 0x83-0x86 | Fields | `getfield_a`..`getfield_i` |
//! | 0x87-0x8A | Fields | `putfield_a`..`putfield_i` |
//! | 0x8B-0x8E | Invoke | `invokevirtual`..`invokeinterface` |
//! | 0x8F-0x92 | Object | `new`, `newarray`, `anewarray`, `arraylength` |
//! | 0x93 | Exception | `athrow` |
//! | 0x94-0x95 | Type | `checkcast`, `instanceof` |
//! | 0xA8 | Branch | `goto_w` |
//! | 0xAD | Fields | `getfield_b` (legacy, NOTE: spec=0x84) |
//! | 0xAF | Fields | `putfield_b` (legacy, NOTE: spec=0x88) |
//! | 0xB3 | Fields | `getstatic_b` (legacy, NOTE: spec=0x7C) |
//! | 0xB5 | Fields | `putstatic_b` (legacy, NOTE: spec=0x80) |

// =========================================================================
// Opcode constants
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

/// `astore`: store reference to local variable
pub const ASTORE: u8 = 0x29;
/// `astore_0`: store reference to local 0
/// NOTE: spec=0x2B, but established as 0x2A in this codebase.
pub const ASTORE_0: u8 = 0x2A;

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

/// `sstore`: store short to local variable
/// NOTE: spec=0x29, but established as 0x28 in this codebase.
pub const SSTORE: u8 = 0x28;
/// `sstore_0`: store to local 0
/// NOTE: spec=0x2F, but established as 0x2B in this codebase.
pub const SSTORE_0: u8 = 0x2B;
/// `sstore_1`: store to local 1
pub const SSTORE_1: u8 = 0x2C;
/// `sstore_2`: store to local 2
pub const SSTORE_2: u8 = 0x2D;
/// `sstore_3`: store to local 3
pub const SSTORE_3: u8 = 0x2E;

// --- Local variable stores: int ---

/// `istore`: store int to two consecutive locals (high, low)
/// NOTE: spec=0x2A, but that conflicts with `ASTORE_0`; using 0x2F.
pub const ISTORE: u8 = 0x2F;
/// `istore_0`: store int to locals 0,1
pub const ISTORE_0: u8 = 0x33;
/// `istore_1`: store int to locals 1,2
pub const ISTORE_1: u8 = 0x34;
/// `istore_2`: store int to locals 2,3
pub const ISTORE_2: u8 = 0x35;
/// `istore_3`: store int to locals 3,4
pub const ISTORE_3: u8 = 0x36;

// --- Array load/store ---

/// `saload`: load short from short array
/// NOTE: spec=0x26 (our code=0x24, swapped with aaload).
pub const SALOAD: u8 = 0x24;
/// `baload`: load byte from byte array
pub const BALOAD: u8 = 0x25;
/// `sastore`: store short to short array
/// NOTE: spec=0x39 (our code=0x26).
pub const SASTORE: u8 = 0x26;
/// `bastore`: store byte to byte array
/// NOTE: spec=0x38 (our code=0x27).
pub const BASTORE: u8 = 0x27;

/// `aaload`: load reference from reference array
pub const AALOAD: u8 = 0x37;
/// `aastore`: store reference to reference array
pub const AASTORE: u8 = 0x38;
/// `iaload`: load int from int array (pushes two stack words)
pub const IALOAD: u8 = 0x39;
/// `iastore`: store int to int array (pops two stack words)
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
/// `swap`: swap top two stack values
/// NOTE: spec calls this `dup_x` at 0x3F; real `swap_x` is 0x40.
/// Kept at 0x3F to match existing codebase convention.
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

// --- Static field access (spec-correct values) ---
// NOTE: The *_b variants below at 0x7C/0x80 are the spec-correct values.
// The legacy GETSTATIC_B/PUTSTATIC_B at 0xB3/0xB5 are kept for backward
// compatibility. New code should use the spec-correct constants.

/// `getstatic_a`: get static reference field (spec 0x7B)
pub const GETSTATIC_A: u8 = 0x7B;
/// `getstatic_s`: get static short field (spec 0x7D)
pub const GETSTATIC_S: u8 = 0x7D;
/// `getstatic_i`: get static int field (spec 0x7E)
pub const GETSTATIC_I: u8 = 0x7E;
/// `putstatic_a`: put static reference field (spec 0x7F)
pub const PUTSTATIC_A: u8 = 0x7F;
/// `putstatic_s`: put static short field (spec 0x81)
pub const PUTSTATIC_S: u8 = 0x81;
/// `putstatic_i`: put static int field (spec 0x82)
pub const PUTSTATIC_I: u8 = 0x82;

// --- Instance field access (spec-correct values) ---

/// `getfield_a`: get reference field from instance (spec 0x83)
pub const GETFIELD_A: u8 = 0x83;
/// `getfield_s`: get short field from instance (spec 0x85)
pub const GETFIELD_S: u8 = 0x85;
/// `getfield_i`: get int field from instance (spec 0x86)
pub const GETFIELD_I: u8 = 0x86;
/// `putfield_a`: put reference field to instance (spec 0x87)
pub const PUTFIELD_A: u8 = 0x87;
/// `putfield_s`: put short field to instance (spec 0x89)
pub const PUTFIELD_S: u8 = 0x89;
/// `putfield_i`: put int field to instance (spec 0x8A)
pub const PUTFIELD_I: u8 = 0x8A;

// --- Legacy field access (non-spec values, kept for backward compat) ---

/// `getfield_b`: read byte field from instance
/// NOTE: spec=0x84; kept at 0xAD for backward compatibility.
pub const GETFIELD_B: u8 = 0xAD;
/// `putfield_b`: write byte field to instance
/// NOTE: spec=0x88; kept at 0xAF for backward compatibility.
pub const PUTFIELD_B: u8 = 0xAF;
/// `getstatic_b`: get static byte field
/// NOTE: spec=0x7C; kept at 0xB3 for backward compatibility.
pub const GETSTATIC_B: u8 = 0xB3;
/// `putstatic_b`: put static byte field
/// NOTE: spec=0x80; kept at 0xB5 for backward compatibility.
pub const PUTSTATIC_B: u8 = 0xB5;

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

/// `goto_w`: unconditional branch (2-byte signed offset)
pub const GOTO_W: u8 = 0xA8;

// --- Aliases ---

/// `sipush`: alias for `sspush` (push short immediate)
pub const SIPUSH: u8 = SSPUSH;

/// Result of executing a single step or a full method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecResult {
    /// Method returned void.
    ReturnVoid,
    /// Method returned a short value.
    ReturnShort(i16),
    /// Method returned an int value (32-bit).
    ReturnInt(i32),
    /// Method returned a reference.
    ReturnRef(u16),
    /// Arithmetic exception (division by zero).
    ArithmeticException,
    /// Null pointer exception.
    NullPointerException,
    /// Array index out of bounds.
    ArrayIndexOutOfBounds,
    /// Array type mismatch (e.g. `saload` on `byte[]`).
    ArrayStoreException,
    /// Security exception (firewall violation).
    SecurityException,
    /// Stack overflow.
    StackOverflow,
    /// Stack underflow.
    StackUnderflow,
    /// Invalid or unimplemented opcode.
    InvalidOpcode(u8),
    /// Ran past end of bytecode.
    EndOfBytecode,
    /// Call frame overflow (too-deep call chain).
    FrameOverflow,
    /// Call frame underflow (return without caller).
    FrameUnderflow,
    /// Heap full (allocation failed).
    HeapFull,
    /// Invalid method reference.
    InvalidMethod,
    /// Execution limit exceeded (infinite loop guard).
    ExecutionLimit,
    /// Uncaught exception thrown by `athrow`.
    UncaughtException(u16),
    /// Negative array size.
    NegativeArraySize,
}

// ---------------------------------------------------------------------------
// Tests (opcode constants only -- execution tests are in lib.rs integration)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sconst_range() {
        assert_eq!(SCONST_M1, 0x02);
        assert_eq!(SCONST_0, 0x03);
        assert_eq!(SCONST_5, 0x08);
        assert_eq!(SCONST_5 - SCONST_M1, 6);
    }

    #[test]
    fn iconst_range() {
        assert_eq!(ICONST_M1, 0x09);
        assert_eq!(ICONST_0, 0x0A);
        assert_eq!(ICONST_5, 0x0F);
        assert_eq!(ICONST_5 - ICONST_M1, 6);
    }

    #[test]
    fn sload_range() {
        assert_eq!(SLOAD_0, 0x1C);
        assert_eq!(SLOAD_3, 0x1F);
    }

    #[test]
    fn iload_range() {
        assert_eq!(ILOAD_0, 0x20);
        assert_eq!(ILOAD_3, 0x23);
    }

    #[test]
    fn sstore_range() {
        assert_eq!(SSTORE_0, 0x2B);
        assert_eq!(SSTORE_3, 0x2E);
    }

    #[test]
    fn istore_range() {
        assert_eq!(ISTORE_0, 0x33);
        assert_eq!(ISTORE_3, 0x36);
    }

    #[test]
    fn arithmetic_opcodes() {
        assert_eq!(SADD, 0x41);
        assert_eq!(SSUB, 0x43);
        assert_eq!(SMUL, 0x45);
        assert_eq!(SDIV, 0x47);
        assert_eq!(SREM, 0x49);
        assert_eq!(SNEG, 0x4B);
    }

    #[test]
    fn int_arithmetic_opcodes() {
        assert_eq!(IADD, 0x42);
        assert_eq!(ISUB, 0x44);
        assert_eq!(IMUL, 0x46);
        assert_eq!(IDIV, 0x48);
        assert_eq!(IREM, 0x4A);
        assert_eq!(INEG, 0x4C);
    }

    #[test]
    fn short_bitwise_opcodes() {
        assert_eq!(SSHL, 0x4D);
        assert_eq!(SSHR, 0x4F);
        assert_eq!(SUSHR, 0x51);
        assert_eq!(SAND, 0x53);
        assert_eq!(SOR, 0x55);
        assert_eq!(SXOR, 0x57);
    }

    #[test]
    fn int_bitwise_opcodes() {
        assert_eq!(ISHL, 0x4E);
        assert_eq!(ISHR, 0x50);
        assert_eq!(IUSHR, 0x52);
        assert_eq!(IAND, 0x54);
        assert_eq!(IOR, 0x56);
        assert_eq!(IXOR, 0x58);
    }

    #[test]
    fn conversion_opcodes() {
        assert_eq!(S2B, 0x5B);
        assert_eq!(S2I, 0x5C);
        assert_eq!(I2B, 0x5D);
        assert_eq!(I2S, 0x5E);
    }

    #[test]
    fn nop_opcode() {
        assert_eq!(NOP, 0x00);
    }

    #[test]
    fn reference_opcodes() {
        assert_eq!(ACONST_NULL, 0x01);
        assert_eq!(ALOAD, 0x15);
        assert_eq!(ALOAD_0, 0x18);
        assert_eq!(ALOAD_1, 0x19);
        assert_eq!(ALOAD_2, 0x1A);
        assert_eq!(ALOAD_3, 0x1B);
        assert_eq!(ASTORE, 0x29);
        assert_eq!(ASTORE_0, 0x2A);
    }

    #[test]
    fn swap_opcode() {
        assert_eq!(SWAP, 0x3F);
    }

    #[test]
    fn comparison_branch_opcodes() {
        assert_eq!(IFEQ, 0x60);
        assert_eq!(IFNE, 0x61);
        assert_eq!(IFLT, 0x62);
        assert_eq!(IFGE, 0x63);
        assert_eq!(IFGT, 0x64);
        assert_eq!(IFLE, 0x65);
        assert_eq!(IFNULL, 0x66);
        assert_eq!(IFNONNULL, 0x67);
    }

    #[test]
    fn short_comparison_branch_opcodes() {
        assert_eq!(IF_SCMPEQ, 0x6A);
        assert_eq!(IF_SCMPNE, 0x6B);
        assert_eq!(IF_SCMPLT, 0x6C);
        assert_eq!(IF_SCMPGE, 0x6D);
        assert_eq!(IF_SCMPGT, 0x6E);
        assert_eq!(IF_SCMPLE, 0x6F);
    }

    #[test]
    fn static_field_opcodes() {
        assert_eq!(GETSTATIC_B, 0xB3);
        assert_eq!(PUTSTATIC_B, 0xB5);
    }

    #[test]
    fn invoke_opcodes() {
        assert_eq!(INVOKEVIRTUAL, 0x8B);
        assert_eq!(INVOKESPECIAL, 0x8C);
        assert_eq!(INVOKESTATIC, 0x8D);
        assert_eq!(INVOKEINTERFACE, 0x8E);
    }

    #[test]
    fn athrow_opcode() {
        assert_eq!(ATHROW, 0x93);
    }

    #[test]
    fn sipush_is_sspush_alias() {
        assert_eq!(SIPUSH, SSPUSH);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn no_opcode_value_collisions() {
        // Verify that all distinct opcode constants have unique values.
        let opcodes: &[(u8, &str)] = &[
            (NOP, "NOP"),
            (ACONST_NULL, "ACONST_NULL"),
            (SCONST_M1, "SCONST_M1"),
            (SCONST_0, "SCONST_0"),
            (SCONST_1, "SCONST_1"),
            (SCONST_2, "SCONST_2"),
            (SCONST_3, "SCONST_3"),
            (SCONST_4, "SCONST_4"),
            (SCONST_5, "SCONST_5"),
            (ICONST_M1, "ICONST_M1"),
            (ICONST_0, "ICONST_0"),
            (ICONST_1, "ICONST_1"),
            (ICONST_2, "ICONST_2"),
            (ICONST_3, "ICONST_3"),
            (ICONST_4, "ICONST_4"),
            (ICONST_5, "ICONST_5"),
            (BSPUSH, "BSPUSH"),
            (SSPUSH, "SSPUSH"),
            (IIPUSH, "IIPUSH"),
            (ALOAD, "ALOAD"),
            (SLOAD, "SLOAD"),
            (ILOAD, "ILOAD"),
            (ALOAD_0, "ALOAD_0"),
            (ALOAD_1, "ALOAD_1"),
            (ALOAD_2, "ALOAD_2"),
            (ALOAD_3, "ALOAD_3"),
            (SLOAD_0, "SLOAD_0"),
            (SLOAD_1, "SLOAD_1"),
            (SLOAD_2, "SLOAD_2"),
            (SLOAD_3, "SLOAD_3"),
            (ILOAD_0, "ILOAD_0"),
            (ILOAD_1, "ILOAD_1"),
            (ILOAD_2, "ILOAD_2"),
            (ILOAD_3, "ILOAD_3"),
            (SALOAD, "SALOAD"),
            (BALOAD, "BALOAD"),
            (SASTORE, "SASTORE"),
            (BASTORE, "BASTORE"),
            (AALOAD, "AALOAD"),
            (AASTORE, "AASTORE"),
            (IALOAD, "IALOAD"),
            (IASTORE, "IASTORE"),
            (SSTORE, "SSTORE"),
            (ASTORE, "ASTORE"),
            (ASTORE_0, "ASTORE_0"),
            (ISTORE, "ISTORE"),
            (SSTORE_0, "SSTORE_0"),
            (SSTORE_1, "SSTORE_1"),
            (SSTORE_2, "SSTORE_2"),
            (SSTORE_3, "SSTORE_3"),
            (ISTORE_0, "ISTORE_0"),
            (ISTORE_1, "ISTORE_1"),
            (ISTORE_2, "ISTORE_2"),
            (ISTORE_3, "ISTORE_3"),
            (POP, "POP"),
            (POP2, "POP2"),
            (DUP, "DUP"),
            (DUP2, "DUP2"),
            (SWAP, "SWAP"),
            (SADD, "SADD"),
            (IADD, "IADD"),
            (SSUB, "SSUB"),
            (ISUB, "ISUB"),
            (SMUL, "SMUL"),
            (IMUL, "IMUL"),
            (SDIV, "SDIV"),
            (IDIV, "IDIV"),
            (SREM, "SREM"),
            (IREM, "IREM"),
            (SNEG, "SNEG"),
            (INEG, "INEG"),
            (SSHL, "SSHL"),
            (ISHL, "ISHL"),
            (SSHR, "SSHR"),
            (ISHR, "ISHR"),
            (SUSHR, "SUSHR"),
            (IUSHR, "IUSHR"),
            (SAND, "SAND"),
            (IAND, "IAND"),
            (SOR, "SOR"),
            (IOR, "IOR"),
            (SXOR, "SXOR"),
            (IXOR, "IXOR"),
            (SINC, "SINC"),
            (IINC, "IINC"),
            (S2B, "S2B"),
            (S2I, "S2I"),
            (I2B, "I2B"),
            (I2S, "I2S"),
            (ICMP, "ICMP"),
            (IFEQ, "IFEQ"),
            (IFNE, "IFNE"),
            (IFLT, "IFLT"),
            (IFGE, "IFGE"),
            (IFGT, "IFGT"),
            (IFLE, "IFLE"),
            (IFNULL, "IFNULL"),
            (IFNONNULL, "IFNONNULL"),
            (IF_ACMPEQ, "IF_ACMPEQ"),
            (IF_ACMPNE, "IF_ACMPNE"),
            (IF_SCMPEQ, "IF_SCMPEQ"),
            (IF_SCMPNE, "IF_SCMPNE"),
            (IF_SCMPLT, "IF_SCMPLT"),
            (IF_SCMPGE, "IF_SCMPGE"),
            (IF_SCMPGT, "IF_SCMPGT"),
            (IF_SCMPLE, "IF_SCMPLE"),
            (GOTO, "GOTO"),
            (STABLESWITCH, "STABLESWITCH"),
            (ITABLESWITCH, "ITABLESWITCH"),
            (SLOOKUPSWITCH, "SLOOKUPSWITCH"),
            (ILOOKUPSWITCH, "ILOOKUPSWITCH"),
            (ARETURN, "ARETURN"),
            (SRETURN, "SRETURN"),
            (IRETURN, "IRETURN"),
            (RETURN, "RETURN"),
            (GETSTATIC_A, "GETSTATIC_A"),
            (GETSTATIC_S, "GETSTATIC_S"),
            (GETSTATIC_I, "GETSTATIC_I"),
            (PUTSTATIC_A, "PUTSTATIC_A"),
            (PUTSTATIC_S, "PUTSTATIC_S"),
            (PUTSTATIC_I, "PUTSTATIC_I"),
            (GETFIELD_A, "GETFIELD_A"),
            (GETFIELD_S, "GETFIELD_S"),
            (GETFIELD_I, "GETFIELD_I"),
            (PUTFIELD_A, "PUTFIELD_A"),
            (PUTFIELD_S, "PUTFIELD_S"),
            (PUTFIELD_I, "PUTFIELD_I"),
            (INVOKEVIRTUAL, "INVOKEVIRTUAL"),
            (INVOKESPECIAL, "INVOKESPECIAL"),
            (INVOKESTATIC, "INVOKESTATIC"),
            (INVOKEINTERFACE, "INVOKEINTERFACE"),
            (NEW, "NEW"),
            (NEWARRAY, "NEWARRAY"),
            (ANEWARRAY, "ANEWARRAY"),
            (ARRAYLENGTH, "ARRAYLENGTH"),
            (ATHROW, "ATHROW"),
            (CHECKCAST, "CHECKCAST"),
            (INSTANCEOF, "INSTANCEOF"),
            (GOTO_W, "GOTO_W"),
            (GETFIELD_B, "GETFIELD_B"),
            (PUTFIELD_B, "PUTFIELD_B"),
            (GETSTATIC_B, "GETSTATIC_B"),
            (PUTSTATIC_B, "PUTSTATIC_B"),
        ];
        for i in 0..opcodes.len() {
            for j in (i + 1)..opcodes.len() {
                assert_ne!(
                    opcodes[i].0, opcodes[j].0,
                    "opcode collision: {} and {} both have value 0x{:02X}",
                    opcodes[i].1, opcodes[j].1, opcodes[i].0
                );
            }
        }
    }
}
