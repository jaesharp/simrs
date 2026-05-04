//! End-to-end "`CapWriter::write` → `parse_cap` → `JcVM::execute`"
//! tests for the component-tagged CAP format.
//!
//! Existing writer tests in `crates/simrs-jacc/src/cap/writer.rs`
//! cover write→parse round-trip extensively (single method,
//! multi-method, max AID length, every component). What's missing
//! and filled here: write → parse → **execute**. The dispatcher
//! step would catch bugs where the writer's extended-header
//! framing or per-method offsets confuse the bytecode interpreter
//! even though the parser accepts the bytes.
//!
//! Companion to:
//!   - `simrs-jcasm/tests/jcvm_opcodes.rs` -- legacy blob format, every opcode
//!   - `simrs-jcasm/tests/integration_suite.rs` -- legacy blob format, families
//!   - `simrs-jcasm/tests/field_access_assemble_execute.rs` -- legacy blob format, fields
//!
//! This file is the only end-to-end test that actually executes
//! through the **component-tagged** CAP path.

use simrs_jacc::cap::{CapWriter, write_cap_full};
use simrs_jccompile::codegen::CompiledClass;
use simrs_jcvm::JcVM;
use simrs_jcvm::cap::parse_cap;
use simrs_jcvm::opcodes::ExecResult;

/// Run a `CompiledClass` through the **component-tagged** CAP path
/// (`CapWriter::write`, not the legacy `write_blob`), then parse +
/// execute method 0.
fn run_via_full_cap(compiled: &CompiledClass) -> ExecResult {
    let cap_bytes = CapWriter::new(compiled).write();
    // Sanity: this is the component-tagged shape; first byte is the
    // Header tag (1). If it were a legacy blob, the first byte would
    // be the magic 0xDE.
    assert_eq!(
        cap_bytes[0], 1,
        "CapWriter::write must produce a component-tagged CAP starting with TAG_HEADER (1)"
    );
    let pkg = parse_cap(&cap_bytes).expect("component-tagged CAP parses");
    let mut vm = JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).expect("package loads");
    vm.execute(idx, 0)
}

// =========================================================================
// Smoke tests -- one-method bodies
// =========================================================================

#[test]
fn full_cap_returns_short_zero() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x01],
        methods: vec![
            vec![0x03, 0x78], // sconst_0, sreturn
        ],
    };
    assert_eq!(run_via_full_cap(&compiled), ExecResult::ReturnShort(0));
}

#[test]
fn full_cap_returns_short_constant() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x02],
        methods: vec![
            vec![0x10, 42, 0x78], // bspush 42, sreturn
        ],
    };
    assert_eq!(run_via_full_cap(&compiled), ExecResult::ReturnShort(42));
}

#[test]
fn full_cap_returns_short_negative_via_bspush() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x03],
        methods: vec![
            // bspush -7 (0xF9 sign-extends to -7), sreturn
            vec![0x10, 0xF9, 0x78],
        ],
    };
    assert_eq!(run_via_full_cap(&compiled), ExecResult::ReturnShort(-7));
}

#[test]
fn full_cap_returns_short_via_sspush() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x04],
        methods: vec![
            // sspush 0x1234 (BE), sreturn
            vec![0x11, 0x12, 0x34, 0x78],
        ],
    };
    assert_eq!(run_via_full_cap(&compiled), ExecResult::ReturnShort(0x1234));
}

// =========================================================================
// Arithmetic survives the writer's framing
// =========================================================================

#[test]
fn full_cap_arithmetic_roundtrips() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x05],
        methods: vec![
            // sspush 100; sspush 30; ssub; sreturn -- expect 70
            vec![0x11, 0x00, 0x64, 0x11, 0x00, 0x1E, 0x43, 0x78],
        ],
    };
    assert_eq!(run_via_full_cap(&compiled), ExecResult::ReturnShort(70));
}

// =========================================================================
// Multi-method: ensure method offsets in the writer's Method
// component align with what the dispatcher expects.
// =========================================================================

#[test]
fn full_cap_multi_method_executes_method_0() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x06],
        methods: vec![
            // method 0: sconst_5; sreturn
            vec![0x08, 0x78],
            // method 1: bspush 99; sreturn (would conflict if offsets mis-resolved)
            vec![0x10, 99, 0x78],
        ],
    };
    assert_eq!(run_via_full_cap(&compiled), ExecResult::ReturnShort(5));
}

// =========================================================================
// AID round-trip validation: distinct AIDs survive the write/parse path.
// =========================================================================

#[test]
fn full_cap_short_aid_roundtrip() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        methods: vec![vec![0x03, 0x78]],
    };
    let cap = CapWriter::new(&compiled).write();
    let pkg = parse_cap(&cap).unwrap();
    assert_eq!(pkg.aid_slice(), &[0xA0, 0x00, 0x00, 0x00, 0x62]);
}

#[test]
fn full_cap_max_aid_roundtrip() {
    // ISO 7816-4 maximum AID length is 16 bytes.
    let compiled = CompiledClass {
        aid: (1..=16).collect(),
        methods: vec![vec![0x03, 0x78]],
    };
    let cap = CapWriter::new(&compiled).write();
    let pkg = parse_cap(&cap).unwrap();
    assert_eq!(pkg.aid_slice(), (1u8..=16).collect::<Vec<u8>>().as_slice());
}

// =========================================================================
// Builder API parity: write_cap_full() helper produces the same bytes
// as CapWriter::new().write(), and round-trips identically.
// =========================================================================

#[test]
fn write_cap_full_matches_builder() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x07],
        methods: vec![vec![0x03, 0x78]],
    };
    let from_builder = CapWriter::new(&compiled).write();
    let from_helper = write_cap_full(&compiled);
    assert_eq!(
        from_builder, from_helper,
        "write_cap_full must match CapWriter::new().write() byte-for-byte"
    );
}

#[test]
fn write_cap_full_executes_correctly() {
    let compiled = CompiledClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0xCA, 0x08],
        methods: vec![
            // sspush 0xBEEF (interpreted as i16 = -16657), sreturn
            vec![0x11, 0xBE, 0xEF, 0x78],
        ],
    };
    let cap = write_cap_full(&compiled);
    let pkg = parse_cap(&cap).expect("parse");
    let mut vm = JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).expect("load");
    let expected = 0xBEEFu16.cast_signed();
    assert_eq!(vm.execute(idx, 0), ExecResult::ReturnShort(expected));
}
