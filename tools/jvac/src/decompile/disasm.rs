//! Disassembler for JCVM bytecodes.
//!
//! Takes raw bytecodes from a CAP package and produces readable assembly
//! text with opcode mnemonics and decoded arguments. This is the reverse
//! of the `jcasm` assembler.

use std::fmt::Write as _;

use simrs_jcvm::opcodes;

/// Decoded instruction with its position, opcode, arguments, and mnemonic.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Program counter (byte offset) of this instruction.
    pub pc: usize,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Raw argument bytes (not including the opcode).
    pub args: Vec<u8>,
    /// Human-readable mnemonic.
    pub mnemonic: &'static str,
}

/// Decode all instructions from a method's bytecodes.
///
/// Returns a vector of decoded instructions.
///
/// # Errors
///
/// Returns an error if the bytecodes contain an unrecognized opcode
/// or are truncated mid-instruction.
pub fn decode_instructions(bytecodes: &[u8]) -> Result<Vec<Instruction>, String> {
    let mut instructions = Vec::new();
    let mut pc = 0;

    while pc < bytecodes.len() {
        let opcode = bytecodes[pc];
        let (mnemonic, arg_size) = decode_opcode(opcode)?;
        if pc + 1 + arg_size > bytecodes.len() {
            return Err(format!(
                "truncated instruction at PC {pc:#06X}: {mnemonic} expects {arg_size} arg bytes \
                 but only {} remain",
                bytecodes.len() - pc - 1
            ));
        }
        let args = bytecodes[pc + 1..pc + 1 + arg_size].to_vec();
        instructions.push(Instruction {
            pc,
            opcode,
            args,
            mnemonic,
        });
        pc += 1 + arg_size;
    }

    Ok(instructions)
}

/// Disassemble a single method's bytecodes to assembly text.
///
/// Each line is formatted as `{pc:04X}: {mnemonic} [{args}]`.
/// Branch targets are shown as resolved absolute PCs.
///
/// # Errors
///
/// Returns an error if decoding fails.
pub fn disassemble_method(bytecodes: &[u8]) -> Result<String, String> {
    let instructions = decode_instructions(bytecodes)?;
    let mut output = String::new();

    for instr in &instructions {
        output.push_str(&format_instruction(instr));
        output.push('\n');
    }

    Ok(output)
}

/// Disassemble a full CAP blob (all methods).
///
/// Parses the CAP binary format and disassembles each method, producing
/// output with AID header and method sections.
///
/// # Errors
///
/// Returns an error if the CAP is malformed or contains invalid opcodes.
#[allow(clippy::too_many_lines)]
pub fn disassemble_cap(cap_data: &[u8]) -> Result<String, String> {
    let pkg = simrs_jcvm::cap::parse_cap(cap_data).map_err(|e| format!("{e:?}"))?;
    let mut output = String::new();

    // Format AID.
    let aid = &pkg.aid[..pkg.aid_len as usize];
    output.push_str(".applet ");
    for (i, b) in aid.iter().enumerate() {
        if i > 0 {
            output.push('_');
        }
        let _ = write!(output, "{b:02X}");
    }
    output.push_str("\n\n");

    // Disassemble each method.
    for idx in 0..pkg.method_count {
        let method = pkg.method(idx).ok_or_else(|| {
            format!("method {idx} missing from package")
        })?;
        let bc = &method.bytecode[..method.bytecode_len as usize];
        let flags = if method.is_static() { "static " } else { "" };

        let _ = writeln!(
            output,
            ".method {idx} {flags}max_stack={} max_locals={}",
            method.max_stack, method.max_locals
        );

        let asm = disassemble_method(bc)?;
        // Indent each line.
        for line in asm.lines() {
            output.push_str("  ");
            output.push_str(line);
            output.push('\n');
        }

        output.push_str(".end\n\n");
    }

    Ok(output)
}

/// Resolve a 1-byte signed branch offset relative to a given PC.
#[allow(clippy::cast_sign_loss)]
fn resolve_branch(pc: usize, offset_byte: u8) -> usize {
    let signed = offset_byte.cast_signed();
    (pc.cast_signed() + isize::from(signed)).cast_unsigned()
}

/// Resolve a 2-byte signed branch offset relative to a given PC.
#[allow(clippy::cast_sign_loss)]
fn resolve_wide_branch(pc: usize, hi: u8, lo: u8) -> usize {
    let offset = i16::from_be_bytes([hi, lo]);
    (pc.cast_signed() + isize::from(offset)).cast_unsigned()
}

/// Format a single instruction as a string.
fn format_instruction(instr: &Instruction) -> String {
    let pc = instr.pc;
    let mnemonic = instr.mnemonic;

    match instr.opcode {
        // 1-byte instructions (no arguments).
        opcodes::NOP
        | opcodes::ACONST_NULL
        | opcodes::SCONST_M1
        | opcodes::SCONST_0
        | opcodes::SCONST_1
        | opcodes::SCONST_2
        | opcodes::SCONST_3
        | opcodes::SCONST_4
        | opcodes::SCONST_5
        | opcodes::ALOAD_0
        | opcodes::ALOAD_1
        | opcodes::ALOAD_2
        | opcodes::ALOAD_3
        | opcodes::SLOAD_0
        | opcodes::SLOAD_1
        | opcodes::SLOAD_2
        | opcodes::SLOAD_3
        | opcodes::ASTORE_0
        | opcodes::SSTORE_0
        | opcodes::SSTORE_1
        | opcodes::SSTORE_2
        | opcodes::SSTORE_3
        | opcodes::POP
        | opcodes::DUP
        | opcodes::SWAP
        | opcodes::SADD
        | opcodes::SSUB
        | opcodes::SMUL
        | opcodes::SDIV
        | opcodes::SREM
        | opcodes::SNEG
        | opcodes::BALOAD
        | opcodes::BASTORE
        | opcodes::SALOAD
        | opcodes::SASTORE
        | opcodes::ARRAYLENGTH
        | opcodes::SRETURN
        | opcodes::RETURN
        | opcodes::ATHROW => {
            format!("{pc:04X}: {mnemonic}")
        }

        // 2-byte: opcode + imm8
        opcodes::BSPUSH => {
            let val = instr.args[0].cast_signed();
            format!("{pc:04X}: {mnemonic} {val}")
        }

        // 2-byte/3-byte: opcode + single displayed argument
        // (sload/sstore/aload/astore use local index; new uses type token with reserved 2nd byte)
        opcodes::ALOAD | opcodes::ASTORE | opcodes::SLOAD | opcodes::SSTORE | opcodes::NEW => {
            let arg = instr.args[0];
            format!("{pc:04X}: {mnemonic} {arg}")
        }

        // 2-byte: opcode + type token
        opcodes::NEWARRAY => {
            let type_name = match instr.args[0] {
                0x0A => "byte",
                0x0B => "short",
                _ => "unknown",
            };
            format!("{pc:04X}: {mnemonic} {type_name}")
        }

        // 2-byte: opcode + signed offset (branch)
        opcodes::IFEQ
        | opcodes::IFNE
        | opcodes::IFLT
        | opcodes::IFGE
        | opcodes::IFGT
        | opcodes::IFLE
        | opcodes::IFNULL
        | opcodes::IFNONNULL
        | opcodes::IF_SCMPEQ
        | opcodes::IF_SCMPNE
        | opcodes::GOTO => {
            let target = resolve_branch(pc, instr.args[0]);
            format!("{pc:04X}: {mnemonic} 0x{target:04X}")
        }

        // 3-byte: opcode + imm16
        opcodes::SSPUSH => {
            let val = i16::from_be_bytes([instr.args[0], instr.args[1]]);
            format!("{pc:04X}: {mnemonic} {val}")
        }

        // 3-byte: opcode + two u8 arguments
        opcodes::INVOKESTATIC
        | opcodes::INVOKEVIRTUAL
        | opcodes::GETFIELD_B
        | opcodes::PUTFIELD_B
        | opcodes::GETSTATIC_B
        | opcodes::PUTSTATIC_B => {
            let arg0 = instr.args[0];
            let arg1 = instr.args[1];
            format!("{pc:04X}: {mnemonic} {arg0} {arg1}")
        }

        // 3-byte: opcode + signed offset (wide branch)
        opcodes::GOTO_W => {
            let target = resolve_wide_branch(pc, instr.args[0], instr.args[1]);
            format!("{pc:04X}: {mnemonic} 0x{target:04X}")
        }

        _ => {
            format!("{pc:04X}: <unknown 0x{:02X}>", instr.opcode)
        }
    }
}

/// Decode an opcode byte to its mnemonic and argument byte count.
///
/// Returns `(mnemonic, arg_byte_count)`.
///
/// The argument byte count reflects the actual VM instruction format,
/// which may differ from the jcasm macro's encoding (e.g., `getfield_b`
/// and `putfield_b` consume 2 argument bytes in the VM).
fn decode_opcode(opcode: u8) -> Result<(&'static str, usize), String> {
    match opcode {
        // Misc (1-byte)
        opcodes::NOP => Ok(("nop", 0)),

        // Constants (1-byte)
        opcodes::ACONST_NULL => Ok(("aconst_null", 0)),
        opcodes::SCONST_M1 => Ok(("sconst_m1", 0)),
        opcodes::SCONST_0 => Ok(("sconst_0", 0)),
        opcodes::SCONST_1 => Ok(("sconst_1", 0)),
        opcodes::SCONST_2 => Ok(("sconst_2", 0)),
        opcodes::SCONST_3 => Ok(("sconst_3", 0)),
        opcodes::SCONST_4 => Ok(("sconst_4", 0)),
        opcodes::SCONST_5 => Ok(("sconst_5", 0)),

        // Constants (2-byte, 3-byte)
        opcodes::BSPUSH => Ok(("bspush", 1)),
        opcodes::SSPUSH => Ok(("sspush", 2)),

        // Reference locals (1-byte, 2-byte)
        opcodes::ALOAD => Ok(("aload", 1)),
        opcodes::ALOAD_0 => Ok(("aload_0", 0)),
        opcodes::ALOAD_1 => Ok(("aload_1", 0)),
        opcodes::ALOAD_2 => Ok(("aload_2", 0)),
        opcodes::ALOAD_3 => Ok(("aload_3", 0)),
        opcodes::ASTORE => Ok(("astore", 1)),
        opcodes::ASTORE_0 => Ok(("astore_0", 0)),

        // Short locals (1-byte)
        opcodes::SLOAD_0 => Ok(("sload_0", 0)),
        opcodes::SLOAD_1 => Ok(("sload_1", 0)),
        opcodes::SLOAD_2 => Ok(("sload_2", 0)),
        opcodes::SLOAD_3 => Ok(("sload_3", 0)),
        opcodes::SSTORE_0 => Ok(("sstore_0", 0)),
        opcodes::SSTORE_1 => Ok(("sstore_1", 0)),
        opcodes::SSTORE_2 => Ok(("sstore_2", 0)),
        opcodes::SSTORE_3 => Ok(("sstore_3", 0)),

        // Short locals (2-byte)
        opcodes::SLOAD => Ok(("sload", 1)),
        opcodes::SSTORE => Ok(("sstore", 1)),

        // Stack (1-byte)
        opcodes::POP => Ok(("pop", 0)),
        opcodes::DUP => Ok(("dup", 0)),
        opcodes::SWAP => Ok(("swap", 0)),

        // Arithmetic (1-byte)
        opcodes::SADD => Ok(("sadd", 0)),
        opcodes::SSUB => Ok(("ssub", 0)),
        opcodes::SMUL => Ok(("smul", 0)),
        opcodes::SDIV => Ok(("sdiv", 0)),
        opcodes::SREM => Ok(("srem", 0)),
        opcodes::SNEG => Ok(("sneg", 0)),

        // Array (1-byte)
        opcodes::SALOAD => Ok(("saload", 0)),
        opcodes::BALOAD => Ok(("baload", 0)),
        opcodes::SASTORE => Ok(("sastore", 0)),
        opcodes::BASTORE => Ok(("bastore", 0)),
        opcodes::ARRAYLENGTH => Ok(("arraylength", 0)),

        // Unary comparison branches (2-byte: opcode + signed offset)
        opcodes::IFEQ => Ok(("ifeq", 1)),
        opcodes::IFNE => Ok(("ifne", 1)),
        opcodes::IFLT => Ok(("iflt", 1)),
        opcodes::IFGE => Ok(("ifge", 1)),
        opcodes::IFGT => Ok(("ifgt", 1)),
        opcodes::IFLE => Ok(("ifle", 1)),
        opcodes::IFNULL => Ok(("ifnull", 1)),
        opcodes::IFNONNULL => Ok(("ifnonnull", 1)),

        // Binary comparison branches (2-byte: opcode + signed offset)
        opcodes::IF_SCMPEQ => Ok(("if_scmpeq", 1)),
        opcodes::IF_SCMPNE => Ok(("if_scmpne", 1)),
        opcodes::GOTO => Ok(("goto", 1)),

        // Branch (3-byte: opcode + signed offset16)
        opcodes::GOTO_W => Ok(("goto_w", 2)),

        // Return (1-byte)
        opcodes::SRETURN => Ok(("sreturn", 0)),
        opcodes::RETURN => Ok(("return", 0)),

        // Invoke (3-byte: opcode + pkg_index + method_index)
        opcodes::INVOKESTATIC => Ok(("invokestatic", 2)),
        opcodes::INVOKEVIRTUAL => Ok(("invokevirtual", 2)),

        // Object (3-byte: opcode + type_token + reserved)
        opcodes::NEW => Ok(("new", 2)),

        // Array creation (2-byte: opcode + elem_type)
        opcodes::NEWARRAY => Ok(("newarray", 1)),

        // Field access (3-byte: opcode + field_offset + class_index)
        opcodes::GETFIELD_B => Ok(("getfield_b", 2)),
        opcodes::PUTFIELD_B => Ok(("putfield_b", 2)),
        opcodes::GETSTATIC_B => Ok(("getstatic_b", 2)),
        opcodes::PUTSTATIC_B => Ok(("putstatic_b", 2)),

        // Exception (1-byte)
        opcodes::ATHROW => Ok(("athrow", 0)),

        _ => Err(format!("unknown opcode: 0x{opcode:02X}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_sconst_instructions() {
        let bc = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let instrs = decode_instructions(&bc).unwrap();
        assert_eq!(instrs.len(), 7);
        assert_eq!(instrs[0].mnemonic, "sconst_m1");
        assert_eq!(instrs[6].mnemonic, "sconst_5");
    }

    #[test]
    fn decode_bspush() {
        let bc = [opcodes::BSPUSH, 42];
        let instrs = decode_instructions(&bc).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].mnemonic, "bspush");
        assert_eq!(instrs[0].args, vec![42]);
    }

    #[test]
    fn format_goto_with_resolved_target() {
        // goto at PC=5, offset=0xFB (-5) -> target PC=0
        let instr = Instruction {
            pc: 5,
            opcode: opcodes::GOTO,
            args: vec![0xFB],
            mnemonic: "goto",
        };
        let text = format_instruction(&instr);
        assert!(text.contains("0x0000"), "expected resolved target PC 0, got: {text}");
    }

    #[test]
    fn truncated_instruction_error() {
        // bspush without its argument byte.
        let bc = [opcodes::BSPUSH];
        let result = decode_instructions(&bc);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_opcode_error() {
        let bc = [0xFF];
        let result = decode_instructions(&bc);
        assert!(result.is_err());
    }
}
