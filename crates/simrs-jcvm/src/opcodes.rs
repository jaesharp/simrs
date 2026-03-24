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

/// `new`: create object instance
pub const NEW: u8 = 0x8F;
/// `newarray`: create primitive array
pub const NEWARRAY: u8 = 0x90;
/// `arraylength`: get array length
pub const ARRAYLENGTH: u8 = 0x92;

/// `goto_w`: unconditional branch (2-byte signed offset)
pub const GOTO_W: u8 = 0xA8;

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
}
