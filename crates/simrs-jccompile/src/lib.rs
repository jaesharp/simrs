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
