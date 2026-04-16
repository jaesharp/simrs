//! Bytecode execution engine for the JCVM -- opcode constants and result type.
//!
//! Opcode constants are provided by the [`simrs_jcvm_opcodes`] crate and
//! re-exported here so that existing `use simrs_jcvm::opcodes::*` paths
//! continue to work unchanged.
//!
//! The [`ExecResult`] enum (execution outcome) is defined here because it
//! is tightly coupled to the VM interpreter, not to the raw bytecode table.

#[allow(clippy::wildcard_imports)]
pub use simrs_jcvm_opcodes::*;

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
