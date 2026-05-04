//! Shared test support for simrs-jcasm integration tests.
//!
//! Provides:
//! - `CapBuilder` / `MethodBuilder` -- construct CAP blobs with exceptions and offsets
//! - `TestApplet` -- high-level assemble-load-execute runner
//! - `expect` -- assertion helpers for `ExecResult` and `ParseError`
//! - `run_jcasm` -- one-shot runner for `(aid, methods)` tuples produced by `jcasm!`

#![allow(unused_imports, dead_code)]

#[allow(dead_code)]
pub mod builder;
pub mod expect;
#[allow(dead_code)]
pub mod runner;

pub use builder::{CapBuilder, ExceptionEntry, MethodBuilder};
pub use runner::TestApplet;

use simrs_jcvm::JcVM;
use simrs_jcvm::cap::{build_cap_blob, parse_cap};
use simrs_jcvm::opcodes::ExecResult;

/// Buffer size for the CAP blob. 4096 bytes accommodates every test
/// in the integration suite; bump if a future test needs more.
const CAP_BUFFER_SIZE: usize = 4096;

/// One-shot end-to-end runner for `(aid, methods)` tuples produced
/// by the `jcasm!` macro. Builds a CAP blob, parses it, loads it
/// into a fresh `JcVM`, and executes method 0.
///
/// This is the canonical end-to-end pipeline for assemble-execute
/// integration tests. Three different test files previously each
/// defined their own copy of this helper; they all now route
/// through this one.
///
/// Panics if the CAP blob fails to parse or the package fails to
/// load -- those are infrastructure errors, not test failures, so
/// surfacing them as panics gives a cleaner failure mode than
/// returning `Result`.
#[must_use]
pub fn run_jcasm(aid: &[u8], methods: &[&[u8]]) -> ExecResult {
    let mut buf = [0u8; CAP_BUFFER_SIZE];
    let len = build_cap_blob(aid, methods, &mut buf);
    let pkg = parse_cap(&buf[..len]).expect("CAP blob parses");
    let mut vm = JcVM::<CAP_BUFFER_SIZE, 4>::new();
    let idx = vm.load_package(pkg).expect("package loads");
    vm.execute(idx, 0)
}
