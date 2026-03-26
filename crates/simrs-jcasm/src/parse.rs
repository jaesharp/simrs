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
    pub aid_hex: String,
    pub methods: Vec<MethodDef>,
}

/// A parsed method definition.
pub struct MethodDef {
    pub name: String,
    pub instructions: Vec<Instruction>,
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
    Label {
        name: String,
        span: Span,
    },
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

        Ok(AppletDef { aid_hex, methods })
    }
}

impl Parse for MethodDef {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
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

        Ok(MethodDef {
            name: name.to_string(),
            instructions,
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
