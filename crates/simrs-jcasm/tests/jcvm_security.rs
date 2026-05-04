//! JCVM security scenario tests.
//!
//! Uses the test support infrastructure (`CapBuilder`, `TestApplet`, expect)
//! to exercise security-relevant scenarios including exception table
//! validation, offset mismatch detection, and malformed CAP rejection.
//!
//! # Spec References
//!
//! - JCVM 3.2 Section 6.3: Descriptor/Class component cross-validation
//! - JCVM 3.2 Section 3.11.3: Array bounds and type checking
//! - JCVM spec exception table semantics: `handler_pc` bounds validation
//! - Lancia & Bouffard, "Java Card Virtual Machine Compromising from a
//!   Bytecode Verified Applet," CARDIS 2015
//! - Barbu, Hoogvorst & Duc, "Tampering with Java Card Exceptions,"
//!   SECRYPT 2012

#[path = "support/mod.rs"]
mod support;

use simrs_jcvm::cap::ParseError;
use simrs_jcvm::opcodes::ExecResult;
use support::TestApplet;
use support::builder::{CapBuilder, MethodBuilder};
use support::expect;

// =========================================================================
// Scenario 6: Descriptor/Class offset mismatch (Lancia & Bouffard CARDIS 2015)
//
// JCVM 3.2 Section 6.3: "The JCVM shall verify that method references
// in the Class component are consistent with the Method component."
//
// The CAP file stores method offsets in both the Descriptor component
// (used by BCV) and the Class component (used by on-card linker). If
// these disagree, the linker resolves virtual method calls to arbitrary
// memory locations. The loader must cross-validate these offsets.
// =========================================================================

/// JCVM 3.2 Section 6.3: Matching zero offsets (unused) are accepted.
#[test]
fn offset_mismatch_both_zero_accepted() {
    let m = MethodBuilder::new(&[0x7A]) // return_void
        .offsets(0, 0)
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_06_01");
    applet.method_with_exceptions(m);

    expect::returns_void(applet.run());
}

/// JCVM 3.2 Section 6.3: Matching non-zero offsets are accepted.
#[test]
fn offset_mismatch_both_equal_accepted() {
    let m = MethodBuilder::new(&[0x7A]).offsets(0x0042, 0x0042).build();

    let mut applet = TestApplet::new("A0_00_00_00_62_06_02");
    applet.method_with_exceptions(m);

    expect::returns_void(applet.run());
}

/// JCVM 3.2 Section 6.3: Mismatched offsets (descriptor != class) must be
/// rejected at parse time.
///
/// Lancia & Bouffard (CARDIS 2015): arbitrary offsets in the Class component
/// can redirect virtual method dispatch to attacker-chosen addresses.
#[test]
fn offset_mismatch_different_rejected() {
    let m = MethodBuilder::new(&[0x7A])
        .offsets(0x0010, 0x0020) // mismatch
        .build();

    let mut builder = CapBuilder::new(&[0xA0, 0x00, 0x00, 0x00, 0x62, 0x06, 0x03]);
    builder.add_method(m);

    let mut buf = [0u8; 512];
    let len = builder.build(&mut buf);
    let result = simrs_jcvm::cap::parse_cap(&buf[..len]);

    expect::parse_fails(&result, ParseError::OffsetMismatch);
}

/// JCVM 3.2 Section 6.3: Zeroed class offset with valid descriptor offset
/// (the CARDIS 2015 attack vector).
///
/// On a vulnerable card, the zeroed offset resolves to the start of the
/// Method component, enabling arbitrary code execution.
#[test]
fn offset_mismatch_zero_class_nonzero_descriptor() {
    let m = MethodBuilder::new(&[0x7A])
        .offsets(0x0010, 0x0000) // descriptor set, class zeroed
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_06_04");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    expect::parse_fails(&result, ParseError::OffsetMismatch);
}

/// JCVM 3.2 Section 6.3: Non-zero class offset with zeroed descriptor offset
/// (reverse mismatch).
#[test]
fn offset_mismatch_zero_descriptor_nonzero_class() {
    let m = MethodBuilder::new(&[0x7A])
        .offsets(0x0000, 0x0010) // descriptor zeroed, class set
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_06_05");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    expect::parse_fails(&result, ParseError::OffsetMismatch);
}

// =========================================================================
// Scenario 8: Exception handler OOB (handler_pc >= bytecode_len)
//
// Barbu, Hoogvorst & Duc, SECRYPT 2012:
// A malformed CAP file can set handler_pc to an address outside the
// method's bytecode range. When an exception is thrown, execution jumps
// to the crafted address -- potentially into another applet's bytecode.
//
// JCVM spec exception table semantics: "handler_pc shall be a valid
// bytecode index within the same method's bytecode array."
// =========================================================================

/// JCVM spec exception table: `handler_pc` pointing past end of bytecode
/// must be rejected.
///
/// Barbu et al. (SECRYPT 2012): attacker sets `handler_pc` to jump into
/// another applet's bytecode segment.
#[test]
fn exception_handler_oob_rejected() {
    let bytecode = [0x7A]; // 1 byte: return_void
    let m = MethodBuilder::new(&bytecode)
        .exception(0, 1, 5, 0) // handler_pc=5, but bytecode len is 1
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_08_01");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    expect::parse_fails(&result, ParseError::InvalidExceptionHandler);
}

/// JCVM spec exception table: `start_pc` >= `bytecode_len` must be rejected.
#[test]
fn exception_start_oob_rejected() {
    let bytecode = [0x03, 0x78]; // sconst_0, sreturn (2 bytes)
    let m = MethodBuilder::new(&bytecode)
        .exception(5, 6, 0, 0) // start_pc=5, but bytecode len is 2
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_08_02");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    expect::parse_fails(&result, ParseError::InvalidExceptionHandler);
}

/// JCVM spec exception table: `end_pc` > `bytecode_len` must be rejected.
#[test]
fn exception_end_oob_rejected() {
    let bytecode = [0x03, 0x78]; // 2 bytes
    let m = MethodBuilder::new(&bytecode)
        .exception(0, 10, 0, 0) // end_pc=10, but bytecode len is 2
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_08_03");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    expect::parse_fails(&result, ParseError::InvalidExceptionHandler);
}

/// JCVM spec exception table: `start_pc` >= `end_pc` must be rejected
/// (empty or inverted range).
#[test]
fn exception_start_ge_end_rejected() {
    let bytecode = [0x03, 0x03, 0x03, 0x78]; // 4 bytes
    let m = MethodBuilder::new(&bytecode)
        .exception(2, 1, 0, 0) // start >= end
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_08_04");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    expect::parse_fails(&result, ParseError::InvalidExceptionHandler);
}

/// JCVM spec exception table: valid exception table with handler within
/// bounds is accepted.
#[test]
fn exception_valid_accepted() {
    // 10 bytes of bytecode with a valid exception entry.
    let bytecode = [0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x7A];
    let m = MethodBuilder::new(&bytecode)
        .exception(0, 5, 7, 0) // all within bounds
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_08_05");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    assert!(
        result.is_ok(),
        "valid exception table should parse successfully"
    );
}

/// JCVM spec exception table: too many exception table entries must be
/// rejected (exceeds `MAX_EXCEPTIONS` limit).
#[test]
fn exception_too_many_rejected() {
    let bytecode = [0x03; 20]; // 20 bytes of filler
    let mut m = MethodBuilder::new(&bytecode);
    // Add 9 exceptions (MAX_EXCEPTIONS is 8).
    for i in 0..9u16 {
        m = m.exception(i, i + 1, 0, 0);
    }
    let m = m.build();

    let mut applet = TestApplet::new("A0_00_00_00_62_08_06");
    applet.method_with_exceptions(m);

    let result = applet.try_parse();
    expect::parse_fails(&result, ParseError::TooManyExceptions);
}

// =========================================================================
// Basic execution sanity through TestApplet
//
// JCVM 3.2 Chapter 7: Bytecode instruction set -- nominal behavior
// verification through the full assemble-load-execute pipeline.
// =========================================================================

/// JCVM 3.2 Chapter 7: sadd instruction -- simple arithmetic through the
/// full runner pipeline.
#[test]
fn runner_arithmetic_sanity() {
    // sconst_3, sconst_2, sadd, sreturn
    let result = TestApplet::new("A0_00_00_00_62_00_01")
        .method(&[0x06, 0x05, 0x41, 0x78])
        .run();

    expect::returns_short(result, 5);
}

/// JCVM 3.2 Chapter 7: `return_void` instruction.
#[test]
fn runner_return_void() {
    let result = TestApplet::new("A0_00_00_00_62_00_02")
        .method(&[0x7A])
        .run();

    expect::returns_void(result);
}

/// JCVM 3.2 Chapter 7: `sdiv` by zero must raise `ArithmeticException`.
///
/// "If the value of the divisor is zero, `sdiv` throws an
/// `ArithmeticException`."
#[test]
fn runner_div_by_zero() {
    // sconst_5, sconst_0, sdiv, sreturn
    let result = TestApplet::new("A0_00_00_00_62_00_03")
        .method(&[0x08, 0x03, 0x47, 0x78])
        .run();

    expect::raises(result, ExecResult::ArithmeticException);
}

// =========================================================================
// Pre-allocation tests
//
// JCVM 3.2 Section 3.11.3: arraylength instruction returns the length of
// the referenced array.
// =========================================================================

/// JCVM 3.2 Section 3.11.3: arraylength on a pre-allocated byte array
/// returns its length.
#[test]
fn prealloc_byte_array_length() {
    // sload_0, arraylength, sreturn
    let result = TestApplet::new("A0_00_00_00_62_00_04")
        .alloc_byte_array(0, 16)
        .method(&[0x1C, 0x92, 0x78])
        .run();

    expect::returns_short(result, 16);
}

/// JCVM 3.2 Section 3.11.3: arraylength on a pre-allocated short array
/// returns its length.
#[test]
fn prealloc_short_array_length() {
    // sload_1, arraylength, sreturn
    let result = TestApplet::new("A0_00_00_00_62_00_05")
        .alloc_short_array(1, 10)
        .method(&[0x1D, 0x92, 0x78])
        .run();

    expect::returns_short(result, 10);
}

// =========================================================================
// Malformed CAP blobs (parse rejection)
//
// JCVM 3.2 Section 6.3: CAP file structural integrity validation.
// (Earlier notes cited "GP 2.1.1 Appendix C" for the CAP file format;
// that was a misattribution -- the CAP format is defined in JCVM
// Chapter 6, not in the GlobalPlatform spec.)
// =========================================================================

/// JCVM 3.2 Section 6.3: Bad magic number must be rejected.
#[test]
fn malformed_bad_magic() {
    // Manually construct a blob with wrong magic.
    let mut buf = [0u8; 32];
    buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    buf[4] = 1; // aid_len
    buf[5] = 0xAA; // aid
    buf[6] = 0; // method count
    let result = simrs_jcvm::cap::parse_cap(&buf[..7]);
    expect::parse_fails(&result, ParseError::BadMagic);
}

/// JCVM 3.2 Section 6.3: AID exceeding 16 bytes must be rejected.
#[test]
fn malformed_aid_too_long() {
    let mut buf = [0u8; 32];
    buf[0..4].copy_from_slice(&simrs_jcvm::cap::CAP_MAGIC.to_be_bytes());
    buf[4] = 17; // aid_len > 16
    let result = simrs_jcvm::cap::parse_cap(&buf[..5 + 17]);
    expect::parse_fails(&result, ParseError::AidTooLong);
}

/// JCVM 3.2 Section 6.3: Truncated blob (too short for header) must be
/// rejected.
#[test]
fn malformed_truncated() {
    let result = simrs_jcvm::cap::parse_cap(&[0xDE, 0xCA]);
    expect::parse_fails(&result, ParseError::TooShort);
}

/// JCVM 3.2 Section 6.3: Bytecode exceeding `MAX_BYTECODE` (256) must be
/// rejected.
#[test]
fn malformed_bytecode_too_long() {
    let mut buf = [0u8; 32];
    buf[0..4].copy_from_slice(&simrs_jcvm::cap::CAP_MAGIC.to_be_bytes());
    buf[4] = 1; // aid_len
    buf[5] = 0xAA; // aid
    buf[6] = 1; // 1 method
    buf[7] = 0; // flags
    buf[8] = 0; // max_stack
    buf[9] = 0; // nargs
    buf[10] = 0; // max_locals
    buf[11] = 0x01; // bytecode_len high
    buf[12] = 0x01; // bytecode_len = 257 > MAX_BYTECODE
    let result = simrs_jcvm::cap::parse_cap(&buf[..13]);
    expect::parse_fails(&result, ParseError::BytecodeTooLong);
}
