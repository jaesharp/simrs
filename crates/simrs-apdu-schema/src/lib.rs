//! APDU response schema types for semantic comparison.
//!
//! Defines the vocabulary for describing APDU response field layouts and
//! comparison policies. Protocol crates use these types to declare
//! [`ResponseSchema`] statics describing their response formats.
//!
//! The comparison engine (which applies these schemas to actual response
//! data) lives elsewhere -- this crate is purely type definitions.
//!
//! # `no_std`
//!
//! Fully `no_std` with zero dependencies. All types use `&'static`
//! references and can be constructed as `const` / `static` items.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

/// How to compare a specific field between two responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldPolicy {
    /// Bytes must be identical.
    Exact,
    /// Lengths must match; content is ignored (nonces, challenges, cryptograms).
    LengthOnly,
    /// Field must be present in both; length and content are ignored.
    PresenceOnly,
    /// Field is ignored entirely (implementation-specific data).
    Ignore,
}

/// How to locate a field within response data bytes.
#[derive(Clone, Copy, Debug)]
pub enum FieldSpan {
    /// Fixed byte range: `offset..offset+len`.
    Bytes {
        /// Byte offset from start of response data.
        offset: usize,
        /// Number of bytes in the field.
        len: usize,
    },
    /// A BER-TLV tag (single-byte) at the top level of the response.
    Tag(u8),
    /// Nested TLV path: e.g. `[0x66, 0x73, 0x06]` means tag 06 inside 73
    /// inside 66.
    TagPath(&'static [u8]),
}

/// A named region within a response.
#[derive(Clone, Debug)]
pub struct FieldSpec {
    /// Human-readable field name for diagnostics.
    pub name: &'static str,
    /// How to locate this field in the response data.
    pub span: FieldSpan,
    /// Comparison policy.
    pub policy: FieldPolicy,
}

/// Describes the expected structure of a specific APDU response.
///
/// Protocol crates define these as `pub static` items next to their
/// response construction code. The comparison engine uses them to
/// compare responses field-by-field with appropriate policies.
///
/// # Example
///
/// ```
/// use simrs_apdu_schema::*;
///
/// pub static MY_RESPONSE_SCHEMA: ResponseSchema = ResponseSchema {
///     name: "MY_COMMAND",
///     expected_len: Some(16),
///     fields: &[
///         FieldSpec {
///             name: "version",
///             span: FieldSpan::Bytes { offset: 0, len: 1 },
///             policy: FieldPolicy::Exact,
///         },
///         FieldSpec {
///             name: "nonce",
///             span: FieldSpan::Bytes { offset: 1, len: 8 },
///             policy: FieldPolicy::LengthOnly,
///         },
///     ],
/// };
/// ```
#[derive(Clone, Debug)]
pub struct ResponseSchema {
    /// Schema name for diagnostics.
    pub name: &'static str,
    /// Expected response data length (`None` = variable length).
    pub expected_len: Option<usize>,
    /// Field specifications.
    pub fields: &'static [FieldSpec],
}
