//! Assertion helpers for JCVM test results.
//!
//! These provide clear panic messages when a JCVM execution or parse
//! result does not match expectations.

use simrs_jcvm::cap::{Package, ParseError};
use simrs_jcvm::opcodes::ExecResult;

/// Assert that `result` matches `expected`, with a clear diagnostic on failure.
pub fn raises(result: ExecResult, expected: ExecResult) {
    assert_eq!(result, expected, "expected {expected:?}, got {result:?}");
}

/// Assert that the execution returned void.
pub fn returns_void(result: ExecResult) {
    assert_eq!(
        result,
        ExecResult::ReturnVoid,
        "expected ReturnVoid, got {result:?}"
    );
}

/// Assert that the execution returned a specific short value.
pub fn returns_short(result: ExecResult, value: i16) {
    assert_eq!(
        result,
        ExecResult::ReturnShort(value),
        "expected ReturnShort({value}), got {result:?}"
    );
}

/// Assert that parsing failed with the expected error.
pub fn parse_fails(result: &Result<Package, ParseError>, expected: ParseError) {
    match result {
        Ok(_) => panic!("expected parse failure {expected:?}, but parsing succeeded"),
        Err(e) => assert_eq!(*e, expected, "expected {expected:?}, got {e:?}"),
    }
}
