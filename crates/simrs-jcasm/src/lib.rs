//! Java Card assembler proc-macro for simrs JCVM.
//!
//! Provides the `jcasm!` macro that compiles Java Card assembly into
//! CAP-format bytecode at compile time. Assembly errors are reported
//! as compiler errors with source spans.
//!
//! # Example
//!
//! ```rust,ignore
//! use simrs_jcasm::jcasm;
//!
//! // Assemble a minimal applet
//! let (aid, methods) = jcasm! {
//!     applet A0_00_00_00_62_02_01 {
//!         fn process() {
//!             sload_0;
//!             bspush(8);
//!             baload;
//!             sreturn;
//!         }
//!     }
//! };
//! ```
//!
//! # Spec References
//!
//! - JCVM 3.1 Chapter 7: Bytecode instruction set
//! - GP 2.1.1 Appendix C: CAP file format
//! - JCRE 2.2.1 Chapter 6: Applet firewall

use proc_macro::TokenStream;

mod codegen;
mod opcodes;
mod parse;

/// Assemble Java Card bytecode at compile time.
///
/// Parses a Rust-like applet definition and emits a `(&[u8], &[&[u8]])`
/// tuple of `(aid_bytes, method_bytecodes)` that can be passed to
/// `simrs_jcvm::cap::build_cap_blob()`.
///
/// # Syntax
///
/// ```text
/// jcasm! {
///     applet AID_HEX_UNDERSCORED {
///         fn method_name() {
///             opcode;
///             opcode(arg);
///             label:
///             goto(label);
///         }
///     }
/// }
/// ```
///
/// # Opcodes
///
/// All JCVM opcodes from `simrs-jcvm/src/opcodes.rs` are supported:
/// `sconst_0`..`sconst_5`, `bspush(IMM8)`, `sspush(IMM16)`,
/// `sload(N)`, `sload_0`..`sload_3`, `sstore(N)`, `sstore_0`..`sstore_3`,
/// `pop`, `dup`, `sadd`, `ssub`, `smul`, `sdiv`, `srem`, `sneg`,
/// `baload`, `bastore`, `saload`, `sastore`, `arraylength`,
/// `getfield_b(OFFSET)`, `putfield_b(OFFSET)`, `new(TYPE)`, `newarray(TYPE)`,
/// `if_scmpeq(LABEL)`, `if_scmpne(LABEL)`, `goto(LABEL)`, `goto_w(LABEL)`,
/// `invokestatic(INDEX)`, `sreturn`, `return_void`.
#[proc_macro]
pub fn jcasm(input: TokenStream) -> TokenStream {
    let input2: proc_macro2::TokenStream = input.into();
    let output = codegen::generate(input2);
    output.into()
}
