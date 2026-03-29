//! Code generation for the `jcasm!` macro.
//!
//! Takes a parsed `AppletDef` and emits Rust code that produces
//! a `([u8; AID_LEN], Vec<Vec<u8>>)` tuple of (AID bytes, method bytecodes).

use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse2;

use crate::opcodes::{self, ArgKind};
use crate::parse::{AppletDef, InstrArg, Instruction};

/// Main entry point: parse + codegen.
pub fn generate(input: TokenStream) -> TokenStream {
    let applet = match parse2::<AppletDef>(input) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error(),
    };

    // Parse AID from hex-with-underscores format: "A0_00_00_01_51_00_00"
    let aid_bytes = match parse_aid_hex(&applet.aid_hex) {
        Ok(b) => b,
        Err(msg) => {
            return syn::Error::new(proc_macro2::Span::call_site(), msg)
                .to_compile_error();
        }
    };

    let aid_len = aid_bytes.len();
    let aid_tokens: Vec<_> = aid_bytes.iter().map(|b| quote! { #b }).collect();

    // Assemble each method.
    let mut method_tokens = Vec::new();
    for method in &applet.methods {
        match assemble_method(method) {
            Ok(bytes) => {
                let byte_tokens: Vec<_> = bytes.iter().map(|b| quote! { #b }).collect();
                let byte_count = bytes.len();
                method_tokens.push(quote! {
                    {
                        const BYTES: [u8; #byte_count] = [#(#byte_tokens),*];
                        &BYTES as &[u8]
                    }
                });
            }
            Err(e) => return e.to_compile_error(),
        }
    }

    let method_count = method_tokens.len();

    quote! {
        {
            const AID: [u8; #aid_len] = [#(#aid_tokens),*];
            const METHODS: [&[u8]; #method_count] = [#(#method_tokens),*];
            (&AID, &METHODS)
        }
    }
}

/// Parse AID from underscore-separated hex: "A0_00_00_01_51_00_00" -> [0xA0, 0x00, ...]
fn parse_aid_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| *c != '_').collect();
    if clean.len() % 2 != 0 {
        return Err(format!("AID hex has odd length: {s}"));
    }
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < clean.len() {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| format!("invalid hex in AID at position {i}: {e}"))?;
        bytes.push(byte);
        i += 2;
    }
    if bytes.is_empty() || bytes.len() > 16 {
        return Err(format!("AID length must be 1-16 bytes, got {}", bytes.len()));
    }
    Ok(bytes)
}

/// Assemble a method's instructions into bytecode.
fn assemble_method(
    method: &crate::parse::MethodDef,
) -> Result<Vec<u8>, syn::Error> {
    // Two-pass assembly for forward label references.

    // Pass 1: collect label positions and instruction sizes.
    let mut label_positions: HashMap<String, usize> = HashMap::new();
    let mut pc = 0usize;

    for instr in &method.instructions {
        match instr {
            Instruction::Label { name, span } => {
                if label_positions.contains_key(name) {
                    return Err(syn::Error::new(*span, format!("duplicate label: {name}")));
                }
                label_positions.insert(name.clone(), pc);
            }
            Instruction::Opcode { mnemonic, span, .. } => {
                let entry = opcodes::lookup(mnemonic).ok_or_else(|| {
                    syn::Error::new(*span, format!("unknown opcode: {mnemonic}"))
                })?;
                pc += instruction_size(entry.arg);
            }
        }
    }

    // Pass 2: emit bytecodes.
    let mut bytecode = Vec::new();
    let mut pc = 0usize;

    for instr in &method.instructions {
        match instr {
            Instruction::Label { .. } => {} // labels don't emit bytes
            Instruction::Opcode {
                mnemonic,
                arg,
                span,
            } => {
                let entry = opcodes::lookup(mnemonic).unwrap(); // validated in pass 1
                bytecode.push(entry.byte);

                match entry.arg {
                    ArgKind::None => {
                        if arg.is_some() {
                            return Err(syn::Error::new(
                                *span,
                                format!("{mnemonic} takes no arguments"),
                            ));
                        }
                    }
                    ArgKind::Imm8 | ArgKind::Local | ArgKind::FieldOffset
                    | ArgKind::TypeToken => {
                        let val = extract_int(arg, mnemonic, *span)?;
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        bytecode.push(val as u8);
                    }
                    ArgKind::Imm16 => {
                        let val = extract_int(arg, mnemonic, *span)?;
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        {
                            bytecode.push((val >> 8) as u8);
                            bytecode.push(val as u8);
                        }
                    }
                    ArgKind::Label => {
                        let target = extract_label(arg, mnemonic, *span)?;
                        let target_pc = label_positions.get(&target).ok_or_else(|| {
                            syn::Error::new(*span, format!("undefined label: {target}"))
                        })?;
                        // Offset is relative to the opcode position, signed 1-byte.
                        let instr_pc = pc; // pc of the opcode byte
                        let offset = (*target_pc as i64) - (instr_pc as i64);
                        if offset < -128 || offset > 127 {
                            return Err(syn::Error::new(
                                *span,
                                format!("branch offset {offset} out of range for {mnemonic}"),
                            ));
                        }
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        bytecode.push(offset as u8);
                    }
                    ArgKind::WideLabel => {
                        let target = extract_label(arg, mnemonic, *span)?;
                        let target_pc = label_positions.get(&target).ok_or_else(|| {
                            syn::Error::new(*span, format!("undefined label: {target}"))
                        })?;
                        let instr_pc = pc;
                        let offset = (*target_pc as i64) - (instr_pc as i64);
                        if offset < -32768 || offset > 32767 {
                            return Err(syn::Error::new(
                                *span,
                                format!("wide branch offset {offset} out of range"),
                            ));
                        }
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        {
                            bytecode.push((offset >> 8) as u8);
                            bytecode.push(offset as u8);
                        }
                    }
                    ArgKind::Imm32 => {
                        let val = extract_int(arg, mnemonic, *span)?;
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        {
                            bytecode.push((val >> 24) as u8);
                            bytecode.push((val >> 16) as u8);
                            bytecode.push((val >> 8) as u8);
                            bytecode.push(val as u8);
                        }
                    }
                    ArgKind::LocalImm8 => {
                        // Expects two arguments encoded as a single i64:
                        // high byte = local index, low byte = constant.
                        // For now, just encode as two bytes from the int arg.
                        let val = extract_int(arg, mnemonic, *span)?;
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        {
                            bytecode.push((val >> 8) as u8);
                            bytecode.push(val as u8);
                        }
                    }
                }

                pc += instruction_size(entry.arg);
            }
        }
    }

    Ok(bytecode)
}

/// Size of an instruction in bytes (opcode + arguments).
fn instruction_size(arg: ArgKind) -> usize {
    match arg {
        ArgKind::None => 1,
        ArgKind::Imm8 | ArgKind::Local | ArgKind::FieldOffset
        | ArgKind::TypeToken | ArgKind::Label => 2,
        ArgKind::Imm16 | ArgKind::WideLabel | ArgKind::LocalImm8 => 3,
        ArgKind::Imm32 => 5,
    }
}

/// Extract an integer argument or report error.
fn extract_int(
    arg: &Option<InstrArg>,
    mnemonic: &str,
    span: proc_macro2::Span,
) -> Result<i64, syn::Error> {
    match arg {
        Some(InstrArg::Int(v)) => Ok(*v),
        Some(InstrArg::Label(_)) => Err(syn::Error::new(
            span,
            format!("{mnemonic} expects an integer argument, got a label"),
        )),
        None => Err(syn::Error::new(
            span,
            format!("{mnemonic} requires an argument"),
        )),
    }
}

/// Extract a label argument or report error.
fn extract_label(
    arg: &Option<InstrArg>,
    mnemonic: &str,
    span: proc_macro2::Span,
) -> Result<String, syn::Error> {
    match arg {
        Some(InstrArg::Label(s)) => Ok(s.clone()),
        Some(InstrArg::Int(_)) => Err(syn::Error::new(
            span,
            format!("{mnemonic} expects a label argument, got an integer"),
        )),
        None => Err(syn::Error::new(
            span,
            format!("{mnemonic} requires a label argument"),
        )),
    }
}
