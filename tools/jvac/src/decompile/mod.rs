//! CAP file decompiler.
//!
//! Three-layer decompilation pipeline:
//!
//! 1. **Disassembler** (`disasm`): bytecodes -> assembly text with opcode
//!    mnemonics and decoded arguments.
//! 2. **Control flow analyzer** (`cfgraph`): identifies basic blocks,
//!    if/else patterns, and while loops from the bytecode CFG.
//! 3. **Source reconstructor** (`reconstruct`): emits high-level JVA
//!    source from the recovered structure.

pub mod cfgraph;
pub mod disasm;
pub mod reconstruct;

/// Disassemble a CAP blob to JVA assembly (low-level).
///
/// Returns human-readable assembly text with opcode mnemonics,
/// resolved branch targets, and method/AID annotations.
///
/// # Errors
///
/// Returns an error if the CAP blob is malformed or contains
/// unrecognized opcodes.
pub fn disassemble(cap_data: &[u8]) -> Result<String, String> {
    disasm::disassemble_cap(cap_data)
}

/// Decompile a CAP blob to JVA source (high-level).
///
/// Performs full decompilation: disassembly, control flow analysis,
/// expression recovery, and source reconstruction.
///
/// # Errors
///
/// Returns an error if the CAP blob is malformed or decompilation
/// encounters an unsupported pattern.
pub fn decompile(cap_data: &[u8]) -> Result<String, String> {
    reconstruct::reconstruct_cap(cap_data)
}
