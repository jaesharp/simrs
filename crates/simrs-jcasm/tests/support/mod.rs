//! Shared test support for simrs-jcasm integration tests.
//!
//! Provides:
//! - `CapBuilder` / `MethodBuilder` -- construct CAP blobs with exceptions and offsets
//! - `TestApplet` -- high-level assemble-load-execute runner
//! - `expect` -- assertion helpers for `ExecResult` and `ParseError`

#![allow(unused_imports, dead_code)]

#[allow(dead_code)]
pub mod builder;
pub mod expect;
#[allow(dead_code)]
pub mod runner;

pub use builder::{CapBuilder, ExceptionEntry, MethodBuilder};
pub use runner::TestApplet;
