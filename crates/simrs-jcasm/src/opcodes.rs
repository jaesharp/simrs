//! Opcode table for the assembler.
//!
//! Maps mnemonic strings to (opcode_byte, arg_kind) pairs.

/// Argument kind for an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// No argument.
    None,
    /// 1-byte immediate (sign-extended to short for bspush).
    Imm8,
    /// 2-byte immediate (big-endian short for sspush).
    Imm16,
    /// 1-byte local variable index.
    Local,
    /// 1-byte field offset.
    FieldOffset,
    /// 1-byte type token (for new/newarray).
    TypeToken,
    /// Branch label (resolved to 1-byte signed offset).
    Label,
    /// Wide branch label (resolved to 2-byte signed offset).
    WideLabel,
}

/// Entry in the opcode table.
pub struct OpcodeEntry {
    pub mnemonic: &'static str,
    pub byte: u8,
    pub arg: ArgKind,
}

/// Complete opcode table matching simrs-jcvm/src/opcodes.rs.
pub static OPCODE_TABLE: &[OpcodeEntry] = &[
    // Constants
    OpcodeEntry { mnemonic: "sconst_m1", byte: 0x02, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sconst_0",  byte: 0x03, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sconst_1",  byte: 0x04, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sconst_2",  byte: 0x05, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sconst_3",  byte: 0x06, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sconst_4",  byte: 0x07, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sconst_5",  byte: 0x08, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "bspush",    byte: 0x10, arg: ArgKind::Imm8 },
    OpcodeEntry { mnemonic: "sspush",    byte: 0x11, arg: ArgKind::Imm16 },

    // Locals
    OpcodeEntry { mnemonic: "sload",     byte: 0x16, arg: ArgKind::Local },
    OpcodeEntry { mnemonic: "sload_0",   byte: 0x1C, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sload_1",   byte: 0x1D, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sload_2",   byte: 0x1E, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sload_3",   byte: 0x1F, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sstore",    byte: 0x28, arg: ArgKind::Local },
    OpcodeEntry { mnemonic: "sstore_0",  byte: 0x2B, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sstore_1",  byte: 0x2C, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sstore_2",  byte: 0x2D, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sstore_3",  byte: 0x2E, arg: ArgKind::None },

    // Stack
    OpcodeEntry { mnemonic: "pop",       byte: 0x3B, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "dup",       byte: 0x3D, arg: ArgKind::None },

    // Arithmetic
    OpcodeEntry { mnemonic: "sadd",      byte: 0x41, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "ssub",      byte: 0x43, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "smul",      byte: 0x45, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sdiv",      byte: 0x47, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "srem",      byte: 0x49, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sneg",      byte: 0x4B, arg: ArgKind::None },

    // Arrays
    OpcodeEntry { mnemonic: "saload",       byte: 0x24, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "baload",       byte: 0x25, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "sastore",      byte: 0x26, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "bastore",      byte: 0x27, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "arraylength",  byte: 0x92, arg: ArgKind::None },

    // Fields
    OpcodeEntry { mnemonic: "getfield_b",   byte: 0xAD, arg: ArgKind::FieldOffset },
    OpcodeEntry { mnemonic: "putfield_b",   byte: 0xAF, arg: ArgKind::FieldOffset },

    // Objects
    OpcodeEntry { mnemonic: "new",          byte: 0x8F, arg: ArgKind::TypeToken },
    OpcodeEntry { mnemonic: "newarray",     byte: 0x90, arg: ArgKind::TypeToken },

    // Branches
    OpcodeEntry { mnemonic: "if_scmpeq",    byte: 0x6A, arg: ArgKind::Label },
    OpcodeEntry { mnemonic: "if_scmpne",    byte: 0x6B, arg: ArgKind::Label },
    OpcodeEntry { mnemonic: "goto",         byte: 0x70, arg: ArgKind::Label },
    OpcodeEntry { mnemonic: "goto_w",       byte: 0xA8, arg: ArgKind::WideLabel },

    // Invoke
    // invokestatic takes 2 bytes: (package_index, method_index).
    // For intra-package calls, use package_index=0.
    OpcodeEntry { mnemonic: "invokestatic", byte: 0x8D, arg: ArgKind::Imm16 },

    // Return
    OpcodeEntry { mnemonic: "sreturn",      byte: 0x78, arg: ArgKind::None },
    OpcodeEntry { mnemonic: "return_void",  byte: 0x7A, arg: ArgKind::None },
];

/// Look up an opcode by mnemonic.
pub fn lookup(mnemonic: &str) -> Option<&'static OpcodeEntry> {
    OPCODE_TABLE.iter().find(|e| e.mnemonic == mnemonic)
}
