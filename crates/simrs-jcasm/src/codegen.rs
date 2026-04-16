//! Code generation for the `jcasm!` macro.
//!
//! Takes a parsed `AppletDef` and emits Rust code that produces
//! a `([u8; AID_LEN], Vec<Vec<u8>>)` tuple of (AID bytes, method bytecodes).

use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse2;

use simrs_jccompile::{
    compute_basic_blocks, parse_aid_hex, peephole_optimize_with_config, BranchInfo,
    BytecodeMetadata, PeepholeConfig,
};

use crate::opcodes::{self, ArgKind};
use crate::parse::{AppletDef, InstrArg, Instruction, OptDirective, OptKnob, OptLevel};

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
            return syn::Error::new(proc_macro2::Span::call_site(), msg).to_compile_error();
        }
    };

    // Convert optimization directive to PeepholeConfig.
    let (peephole_config, report) = opt_directive_to_config(applet.opt.as_ref());

    let aid_len = aid_bytes.len();
    let aid_tokens: Vec<_> = aid_bytes.iter().map(|b| quote! { #b }).collect();

    // Assemble each method.
    let mut method_tokens = Vec::new();
    for method in &applet.methods {
        match assemble_method(method, &peephole_config) {
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

    // Compile-time reporting (visible in cargo build output).
    if report {
        eprintln!("[jcasm] AID: {}", applet.aid_hex);
        for (i, method) in applet.methods.iter().enumerate() {
            let ct_tag = if method.constant_time {
                " [constant_time]"
            } else {
                ""
            };
            eprintln!("[jcasm]   method {i}: {}{ct_tag}", method.name);
        }
    }

    quote! {
        {
            const AID: [u8; #aid_len] = [#(#aid_tokens),*];
            const METHODS: [&[u8]; #method_count] = [#(#method_tokens),*];
            (&AID, &METHODS)
        }
    }
}

/// Assemble a method's instructions into bytecode.
fn assemble_method(
    method: &crate::parse::MethodDef,
    peephole_config: &PeepholeConfig,
) -> Result<Vec<u8>, syn::Error> {
    // Two-pass assembly for forward label references.
    let label_positions = collect_labels(&method.instructions)?;

    // Collect branch metadata during pass 2 for peephole optimization.
    #[allow(clippy::cast_possible_truncation)]
    let branch_targets: Vec<u16> = label_positions.values().map(|&p| p as u16).collect();
    let mut branches: Vec<BranchInfo> = Vec::new();

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
                emit_arg(
                    entry,
                    arg.as_ref(),
                    mnemonic,
                    *span,
                    pc,
                    &label_positions,
                    &mut bytecode,
                    &mut branches,
                )?;
                pc += instruction_size(entry.arg);
            }
        }
    }

    apply_peephole(&mut bytecode, branch_targets, branches, peephole_config);

    Ok(bytecode)
}

/// Encode an opcode's argument bytes into the bytecode stream.
#[allow(clippy::too_many_arguments)]
fn emit_arg(
    entry: &opcodes::OpcodeEntry,
    arg: Option<&InstrArg>,
    mnemonic: &str,
    span: proc_macro2::Span,
    pc: usize,
    label_positions: &HashMap<String, usize>,
    bytecode: &mut Vec<u8>,
    branches: &mut Vec<BranchInfo>,
) -> Result<(), syn::Error> {
    match entry.arg {
        ArgKind::None => {
            if arg.is_some() {
                return Err(syn::Error::new(
                    span,
                    format!("{mnemonic} takes no arguments"),
                ));
            }
        }
        ArgKind::Imm8 | ArgKind::Local | ArgKind::FieldOffset | ArgKind::TypeToken => {
            let val = extract_int(arg, mnemonic, span)?;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            bytecode.push(val as u8);
        }
        ArgKind::Imm16 => {
            let val = extract_int(arg, mnemonic, span)?;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                bytecode.push((val >> 8) as u8);
                bytecode.push(val as u8);
            }
        }
        ArgKind::Label => {
            let target = extract_label(arg, mnemonic, span)?;
            let target_pc = label_positions
                .get(&target)
                .ok_or_else(|| syn::Error::new(span, format!("undefined label: {target}")))?;
            #[allow(clippy::cast_possible_wrap)]
            let offset = (*target_pc as i64) - (pc as i64);
            if !(-128..=127).contains(&offset) {
                return Err(syn::Error::new(
                    span,
                    format!("branch offset {offset} out of range for {mnemonic}"),
                ));
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                branches.push(BranchInfo {
                    opcode_pc: pc as u16,
                    offset_pc: (pc + 1) as u16,
                    wide: false,
                    target_pc: *target_pc as u16,
                });
                bytecode.push(offset as u8);
            }
        }
        ArgKind::WideLabel => {
            let target = extract_label(arg, mnemonic, span)?;
            let target_pc = label_positions
                .get(&target)
                .ok_or_else(|| syn::Error::new(span, format!("undefined label: {target}")))?;
            #[allow(clippy::cast_possible_wrap)]
            let offset = (*target_pc as i64) - (pc as i64);
            if !(-32768..=32767).contains(&offset) {
                return Err(syn::Error::new(
                    span,
                    format!("wide branch offset {offset} out of range"),
                ));
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                branches.push(BranchInfo {
                    opcode_pc: pc as u16,
                    offset_pc: (pc + 1) as u16,
                    wide: true,
                    target_pc: *target_pc as u16,
                });
                bytecode.push((offset >> 8) as u8);
                bytecode.push(offset as u8);
            }
        }
        ArgKind::Imm32 => {
            let val = extract_int(arg, mnemonic, span)?;
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
            let val = extract_int(arg, mnemonic, span)?;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                bytecode.push((val >> 8) as u8);
                bytecode.push(val as u8);
            }
        }
    }
    Ok(())
}

/// Pass 1: collect label positions and validate opcodes.
fn collect_labels(instructions: &[Instruction]) -> Result<HashMap<String, usize>, syn::Error> {
    let mut label_positions: HashMap<String, usize> = HashMap::new();
    let mut pc = 0usize;

    for instr in instructions {
        match instr {
            Instruction::Label { name, span } => {
                if label_positions.contains_key(name) {
                    return Err(syn::Error::new(*span, format!("duplicate label: {name}")));
                }
                label_positions.insert(name.clone(), pc);
            }
            Instruction::Opcode { mnemonic, span, .. } => {
                let entry = opcodes::lookup(mnemonic)
                    .ok_or_else(|| syn::Error::new(*span, format!("unknown opcode: {mnemonic}")))?;
                pc += instruction_size(entry.arg);
            }
        }
    }

    Ok(label_positions)
}

/// Run peephole optimization over assembled bytecode.
fn apply_peephole(
    bytecode: &mut Vec<u8>,
    mut branch_targets: Vec<u16>,
    branches: Vec<BranchInfo>,
    config: &PeepholeConfig,
) {
    branch_targets.sort_unstable();
    branch_targets.dedup();
    let basic_blocks = compute_basic_blocks(&branch_targets, &branches, bytecode.len());
    let mut metadata = BytecodeMetadata {
        branch_targets,
        basic_blocks,
        branches,
    };
    peephole_optimize_with_config(bytecode, &mut metadata, config);
}

/// Convert a parsed optimization directive to a `PeepholeConfig`.
///
/// Returns `(config, report)`.
fn opt_directive_to_config(directive: Option<&OptDirective>) -> (PeepholeConfig, bool) {
    let Some(dir) = directive else {
        return (PeepholeConfig::all(), false);
    };

    let mut report = false;

    let mut config = match dir.level {
        OptLevel::None => PeepholeConfig::none(),
        OptLevel::Peephole | OptLevel::Full => {
            // If specific patterns are listed, start with none and enable only those.
            let has_patterns = dir.knobs.iter().any(|k| matches!(k, OptKnob::Pattern(_)));
            if has_patterns {
                let mut c = PeepholeConfig::none();
                c.enabled = true;
                c.max_passes = 64;
                c
            } else {
                PeepholeConfig::all()
            }
        }
    };

    // Apply knobs.
    for knob in &dir.knobs {
        match knob {
            OptKnob::Pattern(name) => match name.as_str() {
                "store_load_dup" => config.store_load_dup = true,
                "dead_push_pop" => config.dead_push_pop = true,
                "double_negation" => config.double_negation = true,
                "goto_next" => config.goto_next = true,
                "add_zero_identity" => config.add_zero_identity = true,
                "dead_store" => config.dead_store = true,
                _ => {} // parser already validates names
            },
            OptKnob::MaxPasses(n) => config.max_passes = *n,
            OptKnob::IrMaxIterations(_) => {} // jcasm has no IR; ignored
            OptKnob::Report => report = true,
        }
    }

    (config, report)
}

/// Size of an instruction in bytes (opcode + arguments).
const fn instruction_size(arg: ArgKind) -> usize {
    match arg {
        ArgKind::None => 1,
        ArgKind::Imm8
        | ArgKind::Local
        | ArgKind::FieldOffset
        | ArgKind::TypeToken
        | ArgKind::Label => 2,
        ArgKind::Imm16 | ArgKind::WideLabel | ArgKind::LocalImm8 => 3,
        ArgKind::Imm32 => 5,
    }
}

/// Extract an integer argument or report error.
fn extract_int(
    arg: Option<&InstrArg>,
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
    arg: Option<&InstrArg>,
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
