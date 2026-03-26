//! JCVM security scenario tests.
//!
//! Uses the test support infrastructure (`CapBuilder`, `TestApplet`, expect)
//! to exercise security-relevant scenarios including exception table
//! validation, offset mismatch detection, and malformed CAP rejection.

#[path = "support/mod.rs"]
mod support;

use simrs_jcvm::cap::ParseError;
use simrs_jcvm::opcodes::ExecResult;
use support::builder::{CapBuilder, MethodBuilder};
use support::expect;
use support::TestApplet;

// =========================================================================
// Scenario 6: Descriptor/Class offset mismatch (Lancia & Bouffard CARDIS 2015)
// =========================================================================

/// Matching zero offsets are accepted (unused offsets).
#[test]
fn offset_mismatch_both_zero_accepted() {
    let m = MethodBuilder::new(&[0x7A]) // return_void
        .offsets(0, 0)
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_06_01");
    applet.method_with_exceptions(m);

    expect::returns_void(applet.run());
}

/// Matching non-zero offsets are accepted.
#[test]
fn offset_mismatch_both_equal_accepted() {
    let m = MethodBuilder::new(&[0x7A])
        .offsets(0x0042, 0x0042)
        .build();

    let mut applet = TestApplet::new("A0_00_00_00_62_06_02");
    applet.method_with_exceptions(m);

    expect::returns_void(applet.run());
}

/// Mismatched offsets (descriptor != class) must be rejected at parse time.
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

/// Zeroed class offset with valid descriptor offset (the CARDIS 2015 attack vector).
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

/// Non-zero class offset with zeroed descriptor offset (reverse mismatch).
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
// =========================================================================

/// Exception handler pointing past end of bytecode must be rejected.
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

/// Exception `start_pc` >= `bytecode_len` must be rejected.
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

/// Exception `end_pc` > `bytecode_len` must be rejected.
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

/// Exception `start_pc` >= `end_pc` must be rejected.
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

/// Valid exception table with handler within bounds is accepted.
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
    assert!(result.is_ok(), "valid exception table should parse successfully");
}

/// Too many exception table entries must be rejected.
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
// =========================================================================

/// Simple arithmetic through the full runner pipeline.
#[test]
fn runner_arithmetic_sanity() {
    // sconst_3, sconst_2, sadd, sreturn
    let result = TestApplet::new("A0_00_00_00_62_00_01")
        .method(&[0x06, 0x05, 0x41, 0x78])
        .run();

    expect::returns_short(result, 5);
}

/// Return void through the runner.
#[test]
fn runner_return_void() {
    let result = TestApplet::new("A0_00_00_00_62_00_02")
        .method(&[0x7A])
        .run();

    expect::returns_void(result);
}

/// Division by zero through the runner.
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
// =========================================================================

/// Allocate a byte array and verify its length via arraylength.
#[test]
fn prealloc_byte_array_length() {
    // sload_0, arraylength, sreturn
    let result = TestApplet::new("A0_00_00_00_62_00_04")
        .alloc_byte_array(0, 16)
        .method(&[0x1C, 0x92, 0x78])
        .run();

    expect::returns_short(result, 16);
}

/// Allocate a short array and verify its length.
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
// =========================================================================

/// Bad magic number.
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

/// AID too long.
#[test]
fn malformed_aid_too_long() {
    let mut buf = [0u8; 32];
    buf[0..4].copy_from_slice(&simrs_jcvm::cap::CAP_MAGIC.to_be_bytes());
    buf[4] = 17; // aid_len > 16
    let result = simrs_jcvm::cap::parse_cap(&buf[..5 + 17]);
    expect::parse_fails(&result, ParseError::AidTooLong);
}

/// Truncated blob (too short for method header).
#[test]
fn malformed_truncated() {
    let result = simrs_jcvm::cap::parse_cap(&[0xDE, 0xCA]);
    expect::parse_fails(&result, ParseError::TooShort);
}

/// Bytecode exceeds `MAX_BYTECODE` (256).
#[test]
fn malformed_bytecode_too_long() {
    let mut buf = [0u8; 32];
    buf[0..4].copy_from_slice(&simrs_jcvm::cap::CAP_MAGIC.to_be_bytes());
    buf[4] = 1;    // aid_len
    buf[5] = 0xAA; // aid
    buf[6] = 1;    // 1 method
    buf[7] = 0;    // flags
    buf[8] = 0;    // max_stack
    buf[9] = 0;    // nargs
    buf[10] = 0;   // max_locals
    buf[11] = 0x01; // bytecode_len high
    buf[12] = 0x01; // bytecode_len = 257 > MAX_BYTECODE
    let result = simrs_jcvm::cap::parse_cap(&buf[..13]);
    expect::parse_fails(&result, ParseError::BytecodeTooLong);
}
