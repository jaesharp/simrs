//! Parser for the `jcasm!` macro DSL using `syn`.
//!
//! Parses:
//! ```text
//! applet AID_HEX {
//!     fn method_name() {
//!         opcode;
//!         opcode(arg);
//!         label:
//!     }
//! }
//! ```

use proc_macro2::Span;
use syn::parse::{Parse, ParseStream};
use syn::{braced, Ident, LitInt, Result, Token};

/// A parsed applet definition.
pub struct AppletDef {
    /// Optional `optimize` directive before `applet`.
    pub opt: Option<OptDirective>,
    pub aid_hex: String,
    pub methods: Vec<MethodDef>,
}

/// A parsed method definition.
pub struct MethodDef {
    #[allow(dead_code)]
    pub name: String,
    pub instructions: Vec<Instruction>,
    /// Whether this method is marked `constant_time`.
    pub constant_time: bool,
}

/// An optimization directive: `optimize <level>;` or `optimize <level>(<knobs>);`
pub struct OptDirective {
    pub level: OptLevel,
    pub knobs: Vec<OptKnob>,
}

/// Optimization level.
pub enum OptLevel {
    /// No optimization.
    None,
    /// Peephole bytecode optimization only (no IR passes).
    Peephole,
    /// Full optimization (IR + peephole).
    Full,
}

/// Individual optimization knob.
#[allow(dead_code)]
pub enum OptKnob {
    /// Enable a named peephole pattern.
    Pattern(String),
    /// Set `max_passes` for the peephole optimizer.
    MaxPasses(usize),
    /// Set `max_iterations` for the IR optimizer.
    IrMaxIterations(usize),
    /// Enable compile-time optimization reporting.
    Report,
}

/// A single instruction or label.
pub enum Instruction {
    /// An opcode with optional argument.
    Opcode {
        mnemonic: String,
        arg: Option<InstrArg>,
        span: Span,
    },
    /// A branch target label.
    Label { name: String, span: Span },
}

/// Instruction argument.
pub enum InstrArg {
    /// Integer literal (immediate, offset, index).
    Int(i64),
    /// Label reference (for branches).
    Label(String),
}

impl Parse for AppletDef {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        // Optional: `optimize <level>;` or `optimize <level>(<knobs>);`
        let opt = if input.peek(Ident) && input.peek2(Ident) {
            let fork = input.fork();
            let kw: Ident = fork.parse()?;
            if kw == "optimize" {
                // Consume from real stream.
                input.parse::<Ident>()?; // "optimize"
                Some(parse_opt_directive(input)?)
            } else {
                None
            }
        } else {
            None
        };

        // `applet AID_HEX { ... }`
        let kw: Ident = input.parse()?;
        if kw != "applet" {
            return Err(syn::Error::new(kw.span(), "expected `applet`"));
        }

        let aid_ident: Ident = input.parse()?;
        let aid_hex = aid_ident.to_string();

        let content;
        braced!(content in input);

        let mut methods = Vec::new();
        while !content.is_empty() {
            methods.push(content.parse::<MethodDef>()?);
        }

        Ok(Self {
            opt,
            aid_hex,
            methods,
        })
    }
}

impl Parse for MethodDef {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        // Optional: `constant_time` before `fn`
        let constant_time = if input.peek(Token![fn]) {
            // Next token is `fn` directly -- not constant_time
            false
        } else if input.peek(Ident) {
            let fork = input.fork();
            let kw: Ident = fork.parse()?;
            if kw == "constant_time" {
                input.parse::<Ident>()?; // consume "constant_time"
                true
            } else {
                false
            }
        } else {
            false
        };

        // `fn name() { ... }`
        input.parse::<Token![fn]>()?;
        let name: Ident = input.parse()?;

        // Parse empty parens
        let _parens;
        syn::parenthesized!(_parens in input);

        let body;
        braced!(body in input);

        let mut instructions = Vec::new();
        while !body.is_empty() {
            instructions.push(parse_instruction(&body)?);
        }

        Ok(Self {
            name: name.to_string(),
            instructions,
            constant_time,
        })
    }
}

fn parse_instruction(input: ParseStream<'_>) -> Result<Instruction> {
    let ident: Ident = input.parse()?;
    let name = ident.to_string();

    // Check for label: `name:`
    if input.peek(Token![:]) && !input.peek2(Token![:]) {
        input.parse::<Token![:]>()?;
        return Ok(Instruction::Label {
            name,
            span: ident.span(),
        });
    }

    // Check for argument in parens: `opcode(arg)`
    let arg = if input.peek(syn::token::Paren) {
        let content;
        syn::parenthesized!(content in input);

        if content.peek(LitInt) {
            let lit: LitInt = content.parse()?;
            let val = lit.base10_parse::<i64>()?;
            Some(InstrArg::Int(val))
        } else {
            let label: Ident = content.parse()?;
            Some(InstrArg::Label(label.to_string()))
        }
    } else {
        None
    };

    // Consume trailing semicolon if present
    if input.peek(Token![;]) {
        input.parse::<Token![;]>()?;
    }

    Ok(Instruction::Opcode {
        mnemonic: name,
        arg,
        span: ident.span(),
    })
}

/// Parse an optimization directive after the `optimize` keyword.
///
/// Syntax: `<level>;` or `<level>(<knob>, ...);`
/// where `<level>` is `none`, `peephole`, or `full`,
/// and `<knob>` is a pattern name, `report`, `max_passes = N`,
/// or `ir_max_iterations = N`.
fn parse_opt_directive(input: ParseStream<'_>) -> Result<OptDirective> {
    let level_ident: Ident = input.parse()?;
    let level = match level_ident.to_string().as_str() {
        "none" => OptLevel::None,
        "peephole" => OptLevel::Peephole,
        "full" => OptLevel::Full,
        other => {
            return Err(syn::Error::new(
                level_ident.span(),
                format!("expected `none`, `peephole`, or `full`, got `{other}`"),
            ));
        }
    };

    let knobs = if input.peek(syn::token::Paren) {
        let content;
        syn::parenthesized!(content in input);
        parse_opt_knobs(&content)?
    } else {
        Vec::new()
    };

    input.parse::<Token![;]>()?;

    Ok(OptDirective { level, knobs })
}

/// Parse comma-separated optimization knobs inside parentheses.
fn parse_opt_knobs(input: ParseStream<'_>) -> Result<Vec<OptKnob>> {
    let mut knobs = Vec::new();
    while !input.is_empty() {
        let ident: Ident = input.parse()?;
        let name = ident.to_string();

        // Check for `key = value` syntax.
        if input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
            let lit: LitInt = input.parse()?;
            let val = lit.base10_parse::<usize>()?;
            match name.as_str() {
                "max_passes" => knobs.push(OptKnob::MaxPasses(val)),
                "ir_max_iterations" => knobs.push(OptKnob::IrMaxIterations(val)),
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown optimization knob: `{other}`"),
                    ));
                }
            }
        } else {
            // Bare identifier: pattern name or `report`.
            match name.as_str() {
                "report" => knobs.push(OptKnob::Report),
                "store_load_dup" | "dead_push_pop" | "double_negation" | "goto_next"
                | "add_zero_identity" | "dead_store" => {
                    knobs.push(OptKnob::Pattern(name));
                }
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!(
                            "unknown pattern or knob: `{other}`. \
                             Valid patterns: store_load_dup, dead_push_pop, \
                             double_negation, goto_next, add_zero_identity, dead_store"
                        ),
                    ));
                }
            }
        }

        // Consume optional trailing comma.
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        }
    }
    Ok(knobs)
}
