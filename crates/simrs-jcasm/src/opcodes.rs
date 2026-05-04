//! Opcode table for the assembler.
//!
//! Maps mnemonic strings to (`opcode_byte`, `arg_kind`) pairs.
//!
//! Byte values are sourced from the canonical
//! [`simrs_jcvm_opcodes`] crate -- changing an opcode value there
//! automatically propagates here. Do NOT hardcode opcode bytes in
//! this file.

use simrs_jcvm_opcodes as op;

/// Argument kind for an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// No argument.
    None,
    /// 1-byte immediate (sign-extended to short for bspush).
    Imm8,
    /// 2-byte immediate (big-endian short for sspush).
    Imm16,
    /// 4-byte immediate (big-endian int for iipush).
    Imm32,
    /// 1-byte local variable index.
    Local,
    /// 1-byte field offset.
    FieldOffset,
    /// 1-byte type token (for new/newarray/anewarray).
    TypeToken,
    /// Branch label (resolved to 1-byte signed offset).
    Label,
    /// Wide branch label (resolved to 2-byte signed offset).
    WideLabel,
    /// 2 operands: `local_idx(u8)` + `const(i8)`.
    LocalImm8,
}

/// Entry in the opcode table.
pub struct OpcodeEntry {
    pub mnemonic: &'static str,
    pub byte: u8,
    pub arg: ArgKind,
}

/// Complete opcode table. Byte values come from `simrs_jcvm_opcodes`.
pub static OPCODE_TABLE: &[OpcodeEntry] = &[
    // Misc
    OpcodeEntry {
        mnemonic: "nop",
        byte: op::NOP,
        arg: ArgKind::None,
    },
    // Constants: short
    OpcodeEntry {
        mnemonic: "aconst_null",
        byte: op::ACONST_NULL,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_m1",
        byte: op::SCONST_M1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_0",
        byte: op::SCONST_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_1",
        byte: op::SCONST_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_2",
        byte: op::SCONST_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_3",
        byte: op::SCONST_3,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_4",
        byte: op::SCONST_4,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_5",
        byte: op::SCONST_5,
        arg: ArgKind::None,
    },
    // Constants: int
    OpcodeEntry {
        mnemonic: "iconst_m1",
        byte: op::ICONST_M1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_0",
        byte: op::ICONST_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_1",
        byte: op::ICONST_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_2",
        byte: op::ICONST_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_3",
        byte: op::ICONST_3,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_4",
        byte: op::ICONST_4,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_5",
        byte: op::ICONST_5,
        arg: ArgKind::None,
    },
    // Constants: push immediates
    OpcodeEntry {
        mnemonic: "bspush",
        byte: op::BSPUSH,
        arg: ArgKind::Imm8,
    },
    OpcodeEntry {
        mnemonic: "sspush",
        byte: op::SSPUSH,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "iipush",
        byte: op::IIPUSH,
        arg: ArgKind::Imm32,
    },
    // Reference locals
    OpcodeEntry {
        mnemonic: "aload",
        byte: op::ALOAD,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "aload_0",
        byte: op::ALOAD_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aload_1",
        byte: op::ALOAD_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aload_2",
        byte: op::ALOAD_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aload_3",
        byte: op::ALOAD_3,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore",
        byte: op::ASTORE,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "astore_0",
        byte: op::ASTORE_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore_1",
        byte: op::ASTORE_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore_2",
        byte: op::ASTORE_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore_3",
        byte: op::ASTORE_3,
        arg: ArgKind::None,
    },
    // Short locals
    OpcodeEntry {
        mnemonic: "sload",
        byte: op::SLOAD,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "sload_0",
        byte: op::SLOAD_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sload_1",
        byte: op::SLOAD_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sload_2",
        byte: op::SLOAD_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sload_3",
        byte: op::SLOAD_3,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore",
        byte: op::SSTORE,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "sstore_0",
        byte: op::SSTORE_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore_1",
        byte: op::SSTORE_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore_2",
        byte: op::SSTORE_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore_3",
        byte: op::SSTORE_3,
        arg: ArgKind::None,
    },
    // Int locals
    OpcodeEntry {
        mnemonic: "iload",
        byte: op::ILOAD,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "iload_0",
        byte: op::ILOAD_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iload_1",
        byte: op::ILOAD_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iload_2",
        byte: op::ILOAD_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iload_3",
        byte: op::ILOAD_3,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore",
        byte: op::ISTORE,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "istore_0",
        byte: op::ISTORE_0,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore_1",
        byte: op::ISTORE_1,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore_2",
        byte: op::ISTORE_2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore_3",
        byte: op::ISTORE_3,
        arg: ArgKind::None,
    },
    // Stack
    OpcodeEntry {
        mnemonic: "pop",
        byte: op::POP,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "pop2",
        byte: op::POP2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "dup",
        byte: op::DUP,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "dup2",
        byte: op::DUP2,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "swap",
        byte: op::SWAP,
        arg: ArgKind::None,
    },
    // Short arithmetic
    OpcodeEntry {
        mnemonic: "sadd",
        byte: op::SADD,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ssub",
        byte: op::SSUB,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "smul",
        byte: op::SMUL,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sdiv",
        byte: op::SDIV,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "srem",
        byte: op::SREM,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sneg",
        byte: op::SNEG,
        arg: ArgKind::None,
    },
    // Int arithmetic
    OpcodeEntry {
        mnemonic: "iadd",
        byte: op::IADD,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "isub",
        byte: op::ISUB,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "imul",
        byte: op::IMUL,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "idiv",
        byte: op::IDIV,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "irem",
        byte: op::IREM,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ineg",
        byte: op::INEG,
        arg: ArgKind::None,
    },
    // Short bitwise
    OpcodeEntry {
        mnemonic: "sshl",
        byte: op::SSHL,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sshr",
        byte: op::SSHR,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sushr",
        byte: op::SUSHR,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sand",
        byte: op::SAND,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sor",
        byte: op::SOR,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sxor",
        byte: op::SXOR,
        arg: ArgKind::None,
    },
    // Int bitwise
    OpcodeEntry {
        mnemonic: "ishl",
        byte: op::ISHL,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ishr",
        byte: op::ISHR,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iushr",
        byte: op::IUSHR,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iand",
        byte: op::IAND,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ior",
        byte: op::IOR,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ixor",
        byte: op::IXOR,
        arg: ArgKind::None,
    },
    // Increment
    OpcodeEntry {
        mnemonic: "sinc",
        byte: op::SINC,
        arg: ArgKind::LocalImm8,
    },
    OpcodeEntry {
        mnemonic: "iinc",
        byte: op::IINC,
        arg: ArgKind::LocalImm8,
    },
    // Conversions
    OpcodeEntry {
        mnemonic: "s2b",
        byte: op::S2B,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "s2i",
        byte: op::S2I,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "i2b",
        byte: op::I2B,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "i2s",
        byte: op::I2S,
        arg: ArgKind::None,
    },
    // Int comparison
    OpcodeEntry {
        mnemonic: "icmp",
        byte: op::ICMP,
        arg: ArgKind::None,
    },
    // Arrays
    OpcodeEntry {
        mnemonic: "aaload",
        byte: op::AALOAD,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "baload",
        byte: op::BALOAD,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "saload",
        byte: op::SALOAD,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iaload",
        byte: op::IALOAD,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aastore",
        byte: op::AASTORE,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "bastore",
        byte: op::BASTORE,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sastore",
        byte: op::SASTORE,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iastore",
        byte: op::IASTORE,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "arraylength",
        byte: op::ARRAYLENGTH,
        arg: ArgKind::None,
    },
    // Instance fields
    OpcodeEntry {
        mnemonic: "getfield_a",
        byte: op::GETFIELD_A,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getfield_b",
        byte: op::GETFIELD_B,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getfield_s",
        byte: op::GETFIELD_S,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getfield_i",
        byte: op::GETFIELD_I,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_a",
        byte: op::PUTFIELD_A,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_b",
        byte: op::PUTFIELD_B,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_s",
        byte: op::PUTFIELD_S,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_i",
        byte: op::PUTFIELD_I,
        arg: ArgKind::FieldOffset,
    },
    // Static fields
    OpcodeEntry {
        mnemonic: "getstatic_a",
        byte: op::GETSTATIC_A,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getstatic_b",
        byte: op::GETSTATIC_B,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getstatic_s",
        byte: op::GETSTATIC_S,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getstatic_i",
        byte: op::GETSTATIC_I,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_a",
        byte: op::PUTSTATIC_A,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_b",
        byte: op::PUTSTATIC_B,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_s",
        byte: op::PUTSTATIC_S,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_i",
        byte: op::PUTSTATIC_I,
        arg: ArgKind::FieldOffset,
    },
    // Objects
    OpcodeEntry {
        mnemonic: "new",
        byte: op::NEW,
        arg: ArgKind::TypeToken,
    },
    OpcodeEntry {
        mnemonic: "newarray",
        byte: op::NEWARRAY,
        arg: ArgKind::TypeToken,
    },
    OpcodeEntry {
        mnemonic: "anewarray",
        byte: op::ANEWARRAY,
        arg: ArgKind::TypeToken,
    },
    // Unary comparison branches
    OpcodeEntry {
        mnemonic: "ifeq",
        byte: op::IFEQ,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifne",
        byte: op::IFNE,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "iflt",
        byte: op::IFLT,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifge",
        byte: op::IFGE,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifgt",
        byte: op::IFGT,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifle",
        byte: op::IFLE,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifnull",
        byte: op::IFNULL,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifnonnull",
        byte: op::IFNONNULL,
        arg: ArgKind::Label,
    },
    // Reference comparison branches
    OpcodeEntry {
        mnemonic: "if_acmpeq",
        byte: op::IF_ACMPEQ,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_acmpne",
        byte: op::IF_ACMPNE,
        arg: ArgKind::Label,
    },
    // Short comparison branches
    OpcodeEntry {
        mnemonic: "if_scmpeq",
        byte: op::IF_SCMPEQ,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmpne",
        byte: op::IF_SCMPNE,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmplt",
        byte: op::IF_SCMPLT,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmpge",
        byte: op::IF_SCMPGE,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmpgt",
        byte: op::IF_SCMPGT,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmple",
        byte: op::IF_SCMPLE,
        arg: ArgKind::Label,
    },
    // Unconditional branches
    OpcodeEntry {
        mnemonic: "goto",
        byte: op::GOTO,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "goto_w",
        byte: op::GOTO_W,
        arg: ArgKind::WideLabel,
    },
    // Switch (variable-length -- assembler handles encoding)
    OpcodeEntry {
        mnemonic: "stableswitch",
        byte: op::STABLESWITCH,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "itableswitch",
        byte: op::ITABLESWITCH,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "slookupswitch",
        byte: op::SLOOKUPSWITCH,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ilookupswitch",
        byte: op::ILOOKUPSWITCH,
        arg: ArgKind::None,
    },
    // Invoke
    OpcodeEntry {
        mnemonic: "invokevirtual",
        byte: op::INVOKEVIRTUAL,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "invokespecial",
        byte: op::INVOKESPECIAL,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "invokestatic",
        byte: op::INVOKESTATIC,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "invokeinterface",
        byte: op::INVOKEINTERFACE,
        arg: ArgKind::Imm16,
    },
    // Exception
    OpcodeEntry {
        mnemonic: "athrow",
        byte: op::ATHROW,
        arg: ArgKind::None,
    },
    // Type checking
    OpcodeEntry {
        mnemonic: "checkcast",
        byte: op::CHECKCAST,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "instanceof",
        byte: op::INSTANCEOF,
        arg: ArgKind::Imm16,
    },
    // Return
    OpcodeEntry {
        mnemonic: "areturn",
        byte: op::ARETURN,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sreturn",
        byte: op::SRETURN,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ireturn",
        byte: op::IRETURN,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "return_void",
        byte: op::RETURN,
        arg: ArgKind::None,
    },
];

/// Look up an opcode by mnemonic.
pub fn lookup(mnemonic: &str) -> Option<&'static OpcodeEntry> {
    OPCODE_TABLE.iter().find(|e| e.mnemonic == mnemonic)
}
