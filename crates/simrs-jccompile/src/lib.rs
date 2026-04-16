//! JVA compiler core: IR, type system, type checker, and code generator
//! for Java Card smartcard applets.
//!
//! This crate compiles a high-level IR ([`ir::JcClass`]) into JCVM bytecodes
//! that can be loaded via `simrs_jcvm::cap::build_cap_blob` and executed
//! by the JCVM interpreter.
//!
//! # Architecture
//!
//! ```text
//! Frontend (parser)          This crate              Backend (JCVM)
//! ─────────────────  ──>  ────────────────  ──>  ─────────────────
//!   source text           types   - JcType         build_cap_blob
//!                         ir      - JcClass        parse_cap
//!                         check   - type checker   JcVM::execute
//!                         codegen - bytecode gen
//! ```
//!
//! # `no_std`
//!
//! This crate is `no_std` compatible. It uses `alloc` for `String` and `Vec`.

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod check;
pub mod codegen;
pub mod config;
pub mod error;
pub mod ir;
pub mod optimize;
pub mod sourcemap;
pub mod types;

// Re-export primary types for convenience.
pub use check::{check_class, CheckedClass, CheckedMethod};
pub use codegen::{
    compile_class, compile_class_with_config, compute_basic_blocks, BranchInfo, BytecodeMetadata,
    CompiledClass,
};
pub use config::{IrConfig, OptConfig, OptReport, PeepholeConfig};
pub use error::CompileError;
pub use ir::{BinOp, Condition, JcClass, JcExpr, JcField, JcMethod, JcStmt, LValue};
pub use optimize::{peephole_optimize, peephole_optimize_with_config};
pub use sourcemap::SourceMap;
pub use types::JcType;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Parse an AID from underscore-separated hex: `"A0_00_00_01_51_00_00"` -> `[0xA0, 0x00, ...]`
///
/// Strips underscores, parses hex byte pairs, and validates the result is 1-16 bytes.
///
/// # Errors
///
/// Returns an error if the hex string has odd length, contains invalid hex
/// digits, or produces a byte sequence outside the 1-16 byte range.
pub fn parse_aid_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| *c != '_').collect();
    if !clean.len().is_multiple_of(2) {
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
        return Err(format!(
            "AID length must be 1-16 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}
