//! Opcode table for the assembler.
//!
//! Maps mnemonic strings to (`opcode_byte`, `arg_kind`) pairs.

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

/// Complete opcode table matching simrs-jcvm/src/opcodes.rs.
pub static OPCODE_TABLE: &[OpcodeEntry] = &[
    // Misc
    OpcodeEntry {
        mnemonic: "nop",
        byte: 0x00,
        arg: ArgKind::None,
    },
    // Constants: short
    OpcodeEntry {
        mnemonic: "aconst_null",
        byte: 0x01,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_m1",
        byte: 0x02,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_0",
        byte: 0x03,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_1",
        byte: 0x04,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_2",
        byte: 0x05,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_3",
        byte: 0x06,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_4",
        byte: 0x07,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sconst_5",
        byte: 0x08,
        arg: ArgKind::None,
    },
    // Constants: int
    OpcodeEntry {
        mnemonic: "iconst_m1",
        byte: 0x09,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_0",
        byte: 0x0A,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_1",
        byte: 0x0B,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_2",
        byte: 0x0C,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_3",
        byte: 0x0D,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_4",
        byte: 0x0E,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iconst_5",
        byte: 0x0F,
        arg: ArgKind::None,
    },
    // Constants: push immediates
    OpcodeEntry {
        mnemonic: "bspush",
        byte: 0x10,
        arg: ArgKind::Imm8,
    },
    OpcodeEntry {
        mnemonic: "sspush",
        byte: 0x11,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "iipush",
        byte: 0x14,
        arg: ArgKind::Imm32,
    },
    // Reference locals
    OpcodeEntry {
        mnemonic: "aload",
        byte: 0x15,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "aload_0",
        byte: 0x18,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aload_1",
        byte: 0x19,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aload_2",
        byte: 0x1A,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aload_3",
        byte: 0x1B,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore",
        byte: 0x28,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "astore_0",
        byte: 0x2B,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore_1",
        byte: 0x2C,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore_2",
        byte: 0x2D,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "astore_3",
        byte: 0x2E,
        arg: ArgKind::None,
    },
    // Short locals
    OpcodeEntry {
        mnemonic: "sload",
        byte: 0x16,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "sload_0",
        byte: 0x1C,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sload_1",
        byte: 0x1D,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sload_2",
        byte: 0x1E,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sload_3",
        byte: 0x1F,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore",
        byte: 0x29,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "sstore_0",
        byte: 0x2F,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore_1",
        byte: 0x30,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore_2",
        byte: 0x31,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sstore_3",
        byte: 0x32,
        arg: ArgKind::None,
    },
    // Int locals
    OpcodeEntry {
        mnemonic: "iload",
        byte: 0x17,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "iload_0",
        byte: 0x20,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iload_1",
        byte: 0x21,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iload_2",
        byte: 0x22,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iload_3",
        byte: 0x23,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore",
        byte: 0x2A,
        arg: ArgKind::Local,
    },
    OpcodeEntry {
        mnemonic: "istore_0",
        byte: 0x33,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore_1",
        byte: 0x34,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore_2",
        byte: 0x35,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "istore_3",
        byte: 0x36,
        arg: ArgKind::None,
    },
    // Stack
    OpcodeEntry {
        mnemonic: "pop",
        byte: 0x3B,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "pop2",
        byte: 0x3C,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "dup",
        byte: 0x3D,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "dup2",
        byte: 0x3E,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "swap",
        byte: 0x3F,
        arg: ArgKind::None,
    },
    // Short arithmetic
    OpcodeEntry {
        mnemonic: "sadd",
        byte: 0x41,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ssub",
        byte: 0x43,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "smul",
        byte: 0x45,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sdiv",
        byte: 0x47,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "srem",
        byte: 0x49,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sneg",
        byte: 0x4B,
        arg: ArgKind::None,
    },
    // Int arithmetic
    OpcodeEntry {
        mnemonic: "iadd",
        byte: 0x42,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "isub",
        byte: 0x44,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "imul",
        byte: 0x46,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "idiv",
        byte: 0x48,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "irem",
        byte: 0x4A,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ineg",
        byte: 0x4C,
        arg: ArgKind::None,
    },
    // Short bitwise
    OpcodeEntry {
        mnemonic: "sshl",
        byte: 0x4D,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sshr",
        byte: 0x4F,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sushr",
        byte: 0x51,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sand",
        byte: 0x53,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sor",
        byte: 0x55,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sxor",
        byte: 0x57,
        arg: ArgKind::None,
    },
    // Int bitwise
    OpcodeEntry {
        mnemonic: "ishl",
        byte: 0x4E,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ishr",
        byte: 0x50,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iushr",
        byte: 0x52,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iand",
        byte: 0x54,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ior",
        byte: 0x56,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ixor",
        byte: 0x58,
        arg: ArgKind::None,
    },
    // Increment
    OpcodeEntry {
        mnemonic: "sinc",
        byte: 0x59,
        arg: ArgKind::LocalImm8,
    },
    OpcodeEntry {
        mnemonic: "iinc",
        byte: 0x5A,
        arg: ArgKind::LocalImm8,
    },
    // Conversions
    OpcodeEntry {
        mnemonic: "s2b",
        byte: 0x5B,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "s2i",
        byte: 0x5C,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "i2b",
        byte: 0x5D,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "i2s",
        byte: 0x5E,
        arg: ArgKind::None,
    },
    // Int comparison
    OpcodeEntry {
        mnemonic: "icmp",
        byte: 0x5F,
        arg: ArgKind::None,
    },
    // Arrays
    OpcodeEntry {
        mnemonic: "aaload",
        byte: 0x24,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "baload",
        byte: 0x25,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "saload",
        byte: 0x26,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iaload",
        byte: 0x27,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "aastore",
        byte: 0x37,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "bastore",
        byte: 0x38,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sastore",
        byte: 0x39,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "iastore",
        byte: 0x3A,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "arraylength",
        byte: 0x92,
        arg: ArgKind::None,
    },
    // Instance fields
    OpcodeEntry {
        mnemonic: "getfield_a",
        byte: 0x83,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getfield_b",
        byte: 0x84,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getfield_s",
        byte: 0x85,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getfield_i",
        byte: 0x86,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_a",
        byte: 0x87,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_b",
        byte: 0x88,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_s",
        byte: 0x89,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putfield_i",
        byte: 0x8A,
        arg: ArgKind::FieldOffset,
    },
    // Static fields
    OpcodeEntry {
        mnemonic: "getstatic_a",
        byte: 0x7B,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getstatic_b",
        byte: 0x7C,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getstatic_s",
        byte: 0x7D,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "getstatic_i",
        byte: 0x7E,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_a",
        byte: 0x7F,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_b",
        byte: 0x80,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_s",
        byte: 0x81,
        arg: ArgKind::FieldOffset,
    },
    OpcodeEntry {
        mnemonic: "putstatic_i",
        byte: 0x82,
        arg: ArgKind::FieldOffset,
    },
    // Objects
    OpcodeEntry {
        mnemonic: "new",
        byte: 0x8F,
        arg: ArgKind::TypeToken,
    },
    OpcodeEntry {
        mnemonic: "newarray",
        byte: 0x90,
        arg: ArgKind::TypeToken,
    },
    OpcodeEntry {
        mnemonic: "anewarray",
        byte: 0x91,
        arg: ArgKind::TypeToken,
    },
    // Unary comparison branches
    OpcodeEntry {
        mnemonic: "ifeq",
        byte: 0x60,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifne",
        byte: 0x61,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "iflt",
        byte: 0x62,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifge",
        byte: 0x63,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifgt",
        byte: 0x64,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifle",
        byte: 0x65,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifnull",
        byte: 0x66,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "ifnonnull",
        byte: 0x67,
        arg: ArgKind::Label,
    },
    // Reference comparison branches
    OpcodeEntry {
        mnemonic: "if_acmpeq",
        byte: 0x68,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_acmpne",
        byte: 0x69,
        arg: ArgKind::Label,
    },
    // Short comparison branches
    OpcodeEntry {
        mnemonic: "if_scmpeq",
        byte: 0x6A,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmpne",
        byte: 0x6B,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmplt",
        byte: 0x6C,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmpge",
        byte: 0x6D,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmpgt",
        byte: 0x6E,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "if_scmple",
        byte: 0x6F,
        arg: ArgKind::Label,
    },
    // Unconditional branches
    OpcodeEntry {
        mnemonic: "goto",
        byte: 0x70,
        arg: ArgKind::Label,
    },
    OpcodeEntry {
        mnemonic: "goto_w",
        byte: 0xA8,
        arg: ArgKind::WideLabel,
    },
    // Switch (variable-length -- assembler handles encoding)
    OpcodeEntry {
        mnemonic: "stableswitch",
        byte: 0x73,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "itableswitch",
        byte: 0x74,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "slookupswitch",
        byte: 0x75,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ilookupswitch",
        byte: 0x76,
        arg: ArgKind::None,
    },
    // Invoke
    OpcodeEntry {
        mnemonic: "invokevirtual",
        byte: 0x8B,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "invokespecial",
        byte: 0x8C,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "invokestatic",
        byte: 0x8D,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "invokeinterface",
        byte: 0x8E,
        arg: ArgKind::Imm16,
    },
    // Exception
    OpcodeEntry {
        mnemonic: "athrow",
        byte: 0x93,
        arg: ArgKind::None,
    },
    // Type checking
    OpcodeEntry {
        mnemonic: "checkcast",
        byte: 0x94,
        arg: ArgKind::Imm16,
    },
    OpcodeEntry {
        mnemonic: "instanceof",
        byte: 0x95,
        arg: ArgKind::Imm16,
    },
    // Return
    OpcodeEntry {
        mnemonic: "areturn",
        byte: 0x77,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "sreturn",
        byte: 0x78,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "ireturn",
        byte: 0x79,
        arg: ArgKind::None,
    },
    OpcodeEntry {
        mnemonic: "return_void",
        byte: 0x7A,
        arg: ArgKind::None,
    },
];

/// Look up an opcode by mnemonic.
pub fn lookup(mnemonic: &str) -> Option<&'static OpcodeEntry> {
    OPCODE_TABLE.iter().find(|e| e.mnemonic == mnemonic)
}
