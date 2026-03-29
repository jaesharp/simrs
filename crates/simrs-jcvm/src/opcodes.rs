//! Bytecode execution engine for the JCVM.
//!
//! Implements the dispatch loop and individual opcode handlers per
//! JCVM 2.1.1 Chapter 7. The interpreter reads bytecodes from the
//! current method's bytecode buffer and manipulates the operand stack,
//! local variables, and heap.
//!
//! # Opcodes implemented (MVP)
//!
//! | Range | Category | Opcodes |
//! |-------|----------|---------|
//! | 0x02-0x08 | Constants | `sconst_m1` .. `sconst_5` |
//! | 0x10-0x11 | Constants | `bspush`, `sspush` |
//! | 0x16 | Locals | `sload` |
//! | 0x1C-0x1F | Locals | `sload_0` .. `sload_3` |
//! | 0x28 | Locals | `sstore` |
//! | 0x2B-0x2E | Locals | `sstore_0` .. `sstore_3` |
//! | 0x3B | Stack | `pop` |
//! | 0x3D | Stack | `dup` |
//! | 0x41-0x4B | Arithmetic | `sadd`, `ssub`, `smul`, `sdiv`, `srem`, `sneg` |
//! | 0x6A-0x6B | Branch | `if_scmpeq`, `if_scmpne` |
//! | 0x70 | Branch | `goto` |
//! | 0x78 | Return | `sreturn` |
//! | 0x7A | Return | `return` |
//! | 0x8D | Invoke | `invokestatic` |
//! | 0x8F | Object | `new` |
//! | 0x90 | Array | `newarray` |
//! | 0x92 | Array | `arraylength` |
//! | 0xA8 | Branch | `goto_w` |
//! | 0x00 | Misc | `nop` |
//! | 0x01 | Constants | `aconst_null` |
//! | 0x15 | Locals | `aload` |
//! | 0x18-0x1B | Locals | `aload_0` .. `aload_3` |
//! | 0x29 | Locals | `astore` |
//! | 0x2A | Locals | `astore_0` |
//! | 0x3F | Stack | `swap` |
//! | 0x60-0x65 | Branch | `ifeq`, `ifne`, `iflt`, `ifge`, `ifgt`, `ifle` |
//! | 0x66-0x67 | Branch | `ifnull`, `ifnonnull` |
//! | 0x8B | Invoke | `invokevirtual` |
//! | 0x93 | Exception | `athrow` |
//! | 0xB3 | Fields | `getstatic_b` |
//! | 0xB5 | Fields | `putstatic_b` |

// --- Opcode constants ---

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

/// `bspush`: push byte-extended-to-short
pub const BSPUSH: u8 = 0x10;
/// `sspush`: push short immediate
pub const SSPUSH: u8 = 0x11;

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

/// `sstore`: store short to local variable
pub const SSTORE: u8 = 0x28;
/// `sstore_0`: store to local 0
pub const SSTORE_0: u8 = 0x2B;
/// `sstore_1`: store to local 1
pub const SSTORE_1: u8 = 0x2C;
/// `sstore_2`: store to local 2
pub const SSTORE_2: u8 = 0x2D;
/// `sstore_3`: store to local 3
pub const SSTORE_3: u8 = 0x2E;

/// `pop`: pop top of stack
pub const POP: u8 = 0x3B;
/// `dup`: duplicate top of stack
pub const DUP: u8 = 0x3D;

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

/// `if_scmpeq`: branch if two shorts are equal
pub const IF_SCMPEQ: u8 = 0x6A;
/// `if_scmpne`: branch if two shorts are not equal
pub const IF_SCMPNE: u8 = 0x6B;

/// `goto`: unconditional branch (1-byte signed offset)
pub const GOTO: u8 = 0x70;

/// `sreturn`: return short from method
pub const SRETURN: u8 = 0x78;
/// `return`: return void from method
pub const RETURN: u8 = 0x7A;

/// `invokestatic`: invoke a static method
pub const INVOKESTATIC: u8 = 0x8D;

/// `saload`: load short from short array
pub const SALOAD: u8 = 0x24;
/// `baload`: load byte from byte array
pub const BALOAD: u8 = 0x25;
/// `sastore`: store short to short array
pub const SASTORE: u8 = 0x26;
/// `bastore`: store byte to byte array
pub const BASTORE: u8 = 0x27;

/// `new`: create object instance
pub const NEW: u8 = 0x8F;
/// `newarray`: create primitive array
pub const NEWARRAY: u8 = 0x90;
/// `arraylength`: get array length
pub const ARRAYLENGTH: u8 = 0x92;

/// `getfield_b`: read byte field from instance
pub const GETFIELD_B: u8 = 0xAD;
/// `putfield_b`: write byte field to instance
pub const PUTFIELD_B: u8 = 0xAF;

/// `goto_w`: unconditional branch (2-byte signed offset)
pub const GOTO_W: u8 = 0xA8;

// --- Misc ---

/// `nop`: no operation
pub const NOP: u8 = 0x00;

// --- Reference handling (aliases for short ops; references are u16 in JCVM) ---

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
pub const ASTORE_0: u8 = 0x2A;

// --- Stack manipulation ---

/// `swap`: swap top two stack values
pub const SWAP: u8 = 0x3F;

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

// --- Static field access ---

/// `getstatic_b`: get static byte field
pub const GETSTATIC_B: u8 = 0xB3;
/// `putstatic_b`: put static byte field
pub const PUTSTATIC_B: u8 = 0xB5;

// --- Virtual dispatch ---

/// `invokevirtual`: invoke virtual method
pub const INVOKEVIRTUAL: u8 = 0x8B;

// --- Exception ---

/// `athrow`: throw exception
pub const ATHROW: u8 = 0x93;

/// `sipush`: alias for `sspush` (push short immediate)
pub const SIPUSH: u8 = SSPUSH;

/// Result of executing a single step or a full method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecResult {
    /// Method returned void.
    ReturnVoid,
    /// Method returned a short value.
    ReturnShort(i16),
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
}

// ---------------------------------------------------------------------------
// Tests (opcode constants only -- execution tests are in lib.rs integration)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sconst_range() {
        // sconst_m1 through sconst_5 should be consecutive 0x02..0x08.
        assert_eq!(SCONST_M1, 0x02);
        assert_eq!(SCONST_0, 0x03);
        assert_eq!(SCONST_5, 0x08);
        assert_eq!(SCONST_5 - SCONST_M1, 6);
    }

    #[test]
    fn sload_range() {
        assert_eq!(SLOAD_0, 0x1C);
        assert_eq!(SLOAD_3, 0x1F);
    }

    #[test]
    fn sstore_range() {
        assert_eq!(SSTORE_0, 0x2B);
        assert_eq!(SSTORE_3, 0x2E);
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
    fn static_field_opcodes() {
        assert_eq!(GETSTATIC_B, 0xB3);
        assert_eq!(PUTSTATIC_B, 0xB5);
    }

    #[test]
    fn invokevirtual_opcode() {
        assert_eq!(INVOKEVIRTUAL, 0x8B);
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
    fn no_opcode_value_collisions() {
        // Verify that all distinct opcode constants have unique values.
        // This catches accidental value reuse between opcodes.
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
            (BSPUSH, "BSPUSH"),
            (SSPUSH, "SSPUSH"),
            (ALOAD, "ALOAD"),
            (SLOAD, "SLOAD"),
            (ALOAD_0, "ALOAD_0"),
            (ALOAD_1, "ALOAD_1"),
            (ALOAD_2, "ALOAD_2"),
            (ALOAD_3, "ALOAD_3"),
            (SLOAD_0, "SLOAD_0"),
            (SLOAD_1, "SLOAD_1"),
            (SLOAD_2, "SLOAD_2"),
            (SLOAD_3, "SLOAD_3"),
            (SALOAD, "SALOAD"),
            (BALOAD, "BALOAD"),
            (SASTORE, "SASTORE"),
            (BASTORE, "BASTORE"),
            (SSTORE, "SSTORE"),
            (ASTORE, "ASTORE"),
            (ASTORE_0, "ASTORE_0"),
            (SSTORE_0, "SSTORE_0"),
            (SSTORE_1, "SSTORE_1"),
            (SSTORE_2, "SSTORE_2"),
            (SSTORE_3, "SSTORE_3"),
            (POP, "POP"),
            (DUP, "DUP"),
            (SWAP, "SWAP"),
            (SADD, "SADD"),
            (SSUB, "SSUB"),
            (SMUL, "SMUL"),
            (SDIV, "SDIV"),
            (SREM, "SREM"),
            (SNEG, "SNEG"),
            (IFEQ, "IFEQ"),
            (IFNE, "IFNE"),
            (IFLT, "IFLT"),
            (IFGE, "IFGE"),
            (IFGT, "IFGT"),
            (IFLE, "IFLE"),
            (IFNULL, "IFNULL"),
            (IFNONNULL, "IFNONNULL"),
            (IF_SCMPEQ, "IF_SCMPEQ"),
            (IF_SCMPNE, "IF_SCMPNE"),
            (GOTO, "GOTO"),
            (SRETURN, "SRETURN"),
            (RETURN, "RETURN"),
            (INVOKEVIRTUAL, "INVOKEVIRTUAL"),
            (INVOKESTATIC, "INVOKESTATIC"),
            (NEW, "NEW"),
            (NEWARRAY, "NEWARRAY"),
            (ARRAYLENGTH, "ARRAYLENGTH"),
            (ATHROW, "ATHROW"),
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
