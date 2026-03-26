//! Semantic APDU response comparison.
//!
//! Compares APDU responses by field *relationships* (structure, position,
//! length invariants) rather than raw byte content. This avoids false
//! positives for nonces, card challenges, cryptograms, and other
//! implementation-specific fields.
//!
//! # Architecture
//!
//! Schema types ([`FieldPolicy`], [`FieldSpec`], [`FieldSpan`],
//! [`ResponseSchema`]) are defined in [`simrs_apdu_schema`] and re-exported
//! here. Protocol crates define their own schemas as `pub static` items.
//!
//! The comparison engine ([`compare_with_schema`], [`compare_semantic`])
//! applies those schemas to actual response data and returns
//! [`SemanticResult`] with field-level detail.
//!
//! The [`SchemaRegistry`] maps APDU command patterns to schemas and is
//! assembled by the consumer (test harness, fuzzer, etc.).

use simrs_bertlv::Decoder;

// Re-export schema definition types from the foundation crate.
pub use simrs_apdu_schema::{FieldPolicy, FieldSpec, FieldSpan, ResponseSchema};

// ---------------------------------------------------------------------------
// Schema registry
// ---------------------------------------------------------------------------

/// APDU command matching pattern for schema lookup.
#[derive(Clone, Debug)]
pub enum CommandPattern {
    /// Match on CLA + INS.
    ClaIns(u8, u8),
    /// Match on CLA + INS + P1 + P2.
    ClaInsP1P2(u8, u8, u8, u8),
}

/// Maps APDU command patterns to response schemas.
///
/// Consumers build a registry at initialization time, then pass it to
/// [`compare_semantic`] for schema-aware comparison.
///
/// # Example
///
/// ```rust,ignore
/// use simrs_interposer::semantic::{SchemaRegistry, CommandPattern};
///
/// let mut registry = SchemaRegistry::new();
/// registry.register(
///     CommandPattern::ClaIns(0x80, 0x50),
///     &simrs_gp_scp::INIT_UPDATE_SCHEMA,
/// );
/// ```
pub struct SchemaRegistry {
    entries: Vec<(CommandPattern, &'static ResponseSchema)>,
}

impl SchemaRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a schema for a command pattern.
    pub fn register(&mut self, pattern: CommandPattern, schema: &'static ResponseSchema) {
        self.entries.push((pattern, schema));
    }

    /// Look up the schema for a given APDU command.
    ///
    /// Returns `None` if no registered pattern matches.
    pub fn lookup(&self, cmd: &[u8]) -> Option<&'static ResponseSchema> {
        if cmd.len() < 2 {
            return None;
        }
        let (cla, ins) = (cmd[0], cmd[1]);

        for (pattern, schema) in &self.entries {
            let matched = match *pattern {
                CommandPattern::ClaIns(c, i) => cla == c && ins == i,
                CommandPattern::ClaInsP1P2(c, i, p1, p2) => {
                    cmd.len() >= 4 && cla == c && ins == i && cmd[2] == p1 && cmd[3] == p2
                }
            };
            if matched {
                return Some(schema);
            }
        }
        None
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a registry pre-loaded with standard GlobalPlatform schemas.
///
/// Registers:
/// - INIT UPDATE (CLA=80 INS=50) from [`simrs_gp_scp::INIT_UPDATE_SCHEMA`]
/// - GET DATA 0066 (CLA=80 INS=CA P1=00 P2=66) from
///   [`simrs_gp_open::commands::GET_DATA_0066_SCHEMA`]
/// - SELECT (CLA=00 INS=A4) from [`simrs_iso7816::SELECT_SCHEMA`]
pub fn gp_schema_registry() -> SchemaRegistry {
    let mut r = SchemaRegistry::new();
    r.register(
        CommandPattern::ClaIns(0x80, 0x50),
        &simrs_gp_scp::INIT_UPDATE_SCHEMA,
    );
    r.register(
        CommandPattern::ClaInsP1P2(0x80, 0xCA, 0x00, 0x66),
        &simrs_gp_open::commands::GET_DATA_0066_SCHEMA,
    );
    r.register(
        CommandPattern::ClaIns(0x00, 0xA4),
        &simrs_iso7816::SELECT_SCHEMA,
    );
    r
}

// ---------------------------------------------------------------------------
// Comparison result types
// ---------------------------------------------------------------------------

/// Which side of the comparison is missing a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Field missing on the left (first) response.
    Left,
    /// Field missing on the right (second) response.
    Right,
}

/// What went wrong with a single field comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    /// Exact bytes differ.
    BytesDiffer {
        /// Bytes from the left (first) response.
        left: Vec<u8>,
        /// Bytes from the right (second) response.
        right: Vec<u8>,
    },
    /// Lengths differ (for `LengthOnly` policy).
    LengthDiffer {
        /// Length from the left (first) response.
        left: usize,
        /// Length from the right (second) response.
        right: usize,
    },
    /// Field present in one response but not the other.
    Missing {
        /// Which side is missing the field.
        side: Side,
    },
}

/// A single field-level mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldMismatch {
    /// Field name from the schema.
    pub field: &'static str,
    /// What went wrong.
    pub kind: MismatchKind,
}

/// Result of comparing two responses using a schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticResult {
    /// All fields match per their policies.
    Match,
    /// Status words differ (checked before field comparison).
    SwMismatch {
        /// SW from the left (first) response.
        left: [u8; 2],
        /// SW from the right (second) response.
        right: [u8; 2],
    },
    /// One or more field-level mismatches.
    FieldMismatches(Vec<FieldMismatch>),
    /// No schema matches this command; caller should use byte-level comparison.
    SchemaNotApplicable,
}

// ---------------------------------------------------------------------------
// Comparison logic
// ---------------------------------------------------------------------------

/// Compare two APDU responses using the registry to find the appropriate schema.
///
/// If no schema matches the command, returns
/// [`SemanticResult::SchemaNotApplicable`] so the caller can fall back to
/// byte-level comparison.
pub fn compare_semantic(
    registry: &SchemaRegistry,
    cmd: &[u8],
    left_data: &[u8],
    left_sw: [u8; 2],
    right_data: &[u8],
    right_sw: [u8; 2],
) -> SemanticResult {
    // 1. SW comparison (always exact).
    if left_sw != right_sw {
        return SemanticResult::SwMismatch {
            left: left_sw,
            right: right_sw,
        };
    }

    // 2. Look up schema.
    let Some(schema) = registry.lookup(cmd) else {
        return SemanticResult::SchemaNotApplicable;
    };

    compare_with_schema(schema, left_data, right_data)
}

/// Compare two response data buffers using a specific schema.
///
/// Assumes SWs have already been checked. Useful when the caller already
/// knows which schema to use.
pub fn compare_with_schema(
    schema: &ResponseSchema,
    left_data: &[u8],
    right_data: &[u8],
) -> SemanticResult {
    // Check expected length if specified.
    if let Some(expected) = schema.expected_len {
        if left_data.len() != expected || right_data.len() != expected {
            return SemanticResult::FieldMismatches(vec![FieldMismatch {
                field: "response_length",
                kind: MismatchKind::LengthDiffer {
                    left: left_data.len(),
                    right: right_data.len(),
                },
            }]);
        }
    }

    // Compare each field per its policy.
    let mut mismatches = Vec::new();
    for field in schema.fields {
        if let Some(mm) = compare_field(field, left_data, right_data) {
            mismatches.push(mm);
        }
    }

    if mismatches.is_empty() {
        SemanticResult::Match
    } else {
        SemanticResult::FieldMismatches(mismatches)
    }
}

/// Compare a single field between two response buffers.
fn compare_field(
    spec: &FieldSpec,
    left: &[u8],
    right: &[u8],
) -> Option<FieldMismatch> {
    let left_bytes = extract_field(&spec.span, left);
    let right_bytes = extract_field(&spec.span, right);

    match spec.policy {
        FieldPolicy::Ignore => None,

        FieldPolicy::PresenceOnly => match (left_bytes, right_bytes) {
            (Some(_), Some(_)) | (None, None) => None,
            (Some(_), None) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::Missing { side: Side::Right },
            }),
            (None, Some(_)) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::Missing { side: Side::Left },
            }),
        },

        FieldPolicy::LengthOnly => match (left_bytes, right_bytes) {
            (Some(l), Some(r)) if l.len() == r.len() => None,
            (Some(l), Some(r)) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::LengthDiffer {
                    left: l.len(),
                    right: r.len(),
                },
            }),
            (None, None) => None,
            (Some(_), None) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::Missing { side: Side::Right },
            }),
            (None, Some(_)) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::Missing { side: Side::Left },
            }),
        },

        FieldPolicy::Exact => match (left_bytes, right_bytes) {
            (Some(l), Some(r)) if l == r => None,
            (Some(l), Some(r)) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::BytesDiffer {
                    left: l.to_vec(),
                    right: r.to_vec(),
                },
            }),
            (None, None) => None,
            (Some(_), None) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::Missing { side: Side::Right },
            }),
            (None, Some(_)) => Some(FieldMismatch {
                field: spec.name,
                kind: MismatchKind::Missing { side: Side::Left },
            }),
        },
    }
}

// ---------------------------------------------------------------------------
// Field extraction
// ---------------------------------------------------------------------------

/// Extract bytes for a field span from response data.
fn extract_field<'a>(span: &FieldSpan, data: &'a [u8]) -> Option<&'a [u8]> {
    match span {
        FieldSpan::Bytes { offset, len } => data.get(*offset..*offset + *len),
        FieldSpan::Tag(tag) => find_tlv_tag(data, *tag),
        FieldSpan::TagPath(path) => find_tlv_path(data, path),
    }
}

/// Find a single-byte TLV tag at the top level of data.
///
/// Returns the value bytes (not including tag + length).
fn find_tlv_tag(data: &[u8], target: u8) -> Option<&[u8]> {
    let dec = Decoder::new(data);
    for obj in dec.flatten() {
        if obj.tag == target {
            return Some(obj.value);
        }
    }
    None
}

/// Walk a nested TLV path and return the innermost value.
///
/// For path `[0x66, 0x73, 0x06]`: finds tag 0x66 at the top level,
/// then tag 0x73 inside its value, then tag 0x06 inside that.
fn find_tlv_path<'a>(data: &'a [u8], path: &[u8]) -> Option<&'a [u8]> {
    if path.is_empty() {
        return Some(data);
    }
    let value = find_tlv_tag(data, path[0])?;
    if path.len() == 1 {
        Some(value)
    } else {
        find_tlv_path(value, &path[1..])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a GP schema registry for tests.
    fn test_registry() -> SchemaRegistry {
        gp_schema_registry()
    }

    // -- TLV helpers --

    #[test]
    fn find_tlv_tag_existing() {
        let data = [0x80, 0x02, 0x00, 0x10];
        assert_eq!(find_tlv_tag(&data, 0x80), Some([0x00, 0x10].as_slice()));
    }

    #[test]
    fn find_tlv_tag_missing() {
        let data = [0x80, 0x02, 0x00, 0x10];
        assert_eq!(find_tlv_tag(&data, 0x83), None);
    }

    #[test]
    fn find_tlv_tag_among_multiple() {
        let data = [0x80, 0x01, 0xAA, 0x83, 0x02, 0xBB, 0xCC];
        assert_eq!(find_tlv_tag(&data, 0x83), Some([0xBB, 0xCC].as_slice()));
    }

    #[test]
    fn find_tlv_tag_empty_data() {
        assert_eq!(find_tlv_tag(&[], 0x80), None);
    }

    #[test]
    fn find_tlv_path_nested() {
        let data = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x07,
            0x02,
        ];
        let oid = find_tlv_path(&data, &[0x66, 0x73, 0x06]);
        assert_eq!(
            oid,
            Some([0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01].as_slice())
        );
    }

    #[test]
    fn find_tlv_path_single_level() {
        let data = [0x80, 0x02, 0x00, 0x10];
        assert_eq!(
            find_tlv_path(&data, &[0x80]),
            Some([0x00, 0x10].as_slice())
        );
    }

    #[test]
    fn find_tlv_path_missing_intermediate() {
        let data = [0x66, 0x02, 0x80, 0x00];
        assert_eq!(find_tlv_path(&data, &[0x66, 0x73]), None);
    }

    #[test]
    fn find_tlv_path_empty() {
        let data = [0x01, 0x02];
        assert_eq!(find_tlv_path(&data, &[]), Some(data.as_slice()));
    }

    // -- extract_field --

    #[test]
    fn extract_field_bytes_in_range() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04];
        let span = FieldSpan::Bytes { offset: 1, len: 3 };
        assert_eq!(extract_field(&span, &data), Some([0x01, 0x02, 0x03].as_slice()));
    }

    #[test]
    fn extract_field_bytes_out_of_range() {
        let data = [0x00, 0x01];
        let span = FieldSpan::Bytes { offset: 1, len: 3 };
        assert_eq!(extract_field(&span, &data), None);
    }

    // -- compare_field --

    #[test]
    fn compare_field_ignore_always_none() {
        let spec = FieldSpec {
            name: "ignored",
            span: FieldSpan::Bytes { offset: 0, len: 4 },
            policy: FieldPolicy::Ignore,
        };
        assert_eq!(compare_field(&spec, &[1, 2, 3, 4], &[5, 6, 7, 8]), None);
    }

    #[test]
    fn compare_field_exact_match() {
        let spec = FieldSpec {
            name: "version",
            span: FieldSpan::Bytes { offset: 0, len: 1 },
            policy: FieldPolicy::Exact,
        };
        assert_eq!(compare_field(&spec, &[0x01], &[0x01]), None);
    }

    #[test]
    fn compare_field_exact_differ() {
        let spec = FieldSpec {
            name: "version",
            span: FieldSpan::Bytes { offset: 0, len: 1 },
            policy: FieldPolicy::Exact,
        };
        let result = compare_field(&spec, &[0x01], &[0x02]);
        assert_eq!(
            result,
            Some(FieldMismatch {
                field: "version",
                kind: MismatchKind::BytesDiffer {
                    left: vec![0x01],
                    right: vec![0x02],
                },
            })
        );
    }

    #[test]
    fn compare_field_length_only_same_len() {
        let spec = FieldSpec {
            name: "challenge",
            span: FieldSpan::Bytes { offset: 0, len: 8 },
            policy: FieldPolicy::LengthOnly,
        };
        assert_eq!(
            compare_field(&spec, &[1, 2, 3, 4, 5, 6, 7, 8], &[8, 7, 6, 5, 4, 3, 2, 1]),
            None
        );
    }

    #[test]
    fn compare_field_presence_both_present() {
        let spec = FieldSpec {
            name: "tag_66",
            span: FieldSpan::Tag(0x66),
            policy: FieldPolicy::PresenceOnly,
        };
        let left = [0x66, 0x02, 0xAA, 0xBB];
        let right = [0x66, 0x03, 0xCC, 0xDD, 0xEE];
        assert_eq!(compare_field(&spec, &left, &right), None);
    }

    #[test]
    fn compare_field_presence_right_missing() {
        let spec = FieldSpec {
            name: "tag_66",
            span: FieldSpan::Tag(0x66),
            policy: FieldPolicy::PresenceOnly,
        };
        let left = [0x66, 0x02, 0xAA, 0xBB];
        let right = [0x80, 0x02, 0xCC, 0xDD];
        assert_eq!(
            compare_field(&spec, &left, &right),
            Some(FieldMismatch {
                field: "tag_66",
                kind: MismatchKind::Missing { side: Side::Right },
            })
        );
    }

    // -- compare_semantic (with registry) --

    #[test]
    fn semantic_sw_mismatch_short_circuits() {
        let reg = test_registry();
        let cmd = [0x80, 0x50, 0x00, 0x00, 0x08];
        let result = compare_semantic(&reg, &cmd, &[0u8; 28], [0x90, 0x00], &[0u8; 28], [0x6A, 0x82]);
        assert_eq!(
            result,
            SemanticResult::SwMismatch {
                left: [0x90, 0x00],
                right: [0x6A, 0x82],
            }
        );
    }

    #[test]
    fn semantic_unknown_command_not_applicable() {
        let reg = test_registry();
        let cmd = [0x80, 0xFD, 0x00, 0x00];
        let result = compare_semantic(&reg, &cmd, &[], [0x6D, 0x00], &[], [0x6D, 0x00]);
        assert_eq!(result, SemanticResult::SchemaNotApplicable);
    }

    #[test]
    fn semantic_init_update_match_despite_different_challenges() {
        let reg = test_registry();
        let cmd = [0x80, 0x50, 0x00, 0x00, 0x08];

        let mut left = [0u8; 28];
        left[10] = 0x01;
        left[11] = 0x02;
        left[12..20].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        left[20..28].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);

        let mut right = [0u8; 28];
        right[0..10].fill(0xFF);
        right[10] = 0x01;
        right[11] = 0x02;
        right[12..20].copy_from_slice(&[0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22]);
        right[20..28].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        let result = compare_semantic(&reg, &cmd, &left, [0x90, 0x00], &right, [0x90, 0x00]);
        assert_eq!(result, SemanticResult::Match);
    }

    #[test]
    fn semantic_init_update_key_version_mismatch() {
        let reg = test_registry();
        let cmd = [0x80, 0x50, 0x00, 0x00, 0x08];

        let mut left = [0u8; 28];
        left[10] = 0x01;
        left[11] = 0x02;

        let mut right = [0u8; 28];
        right[10] = 0xFF;
        right[11] = 0x02;

        let result = compare_semantic(&reg, &cmd, &left, [0x90, 0x00], &right, [0x90, 0x00]);
        assert!(matches!(result, SemanticResult::FieldMismatches(_)));
        if let SemanticResult::FieldMismatches(ref mm) = result {
            assert_eq!(mm.len(), 1);
            assert_eq!(mm[0].field, "key_version");
        }
    }

    #[test]
    fn semantic_init_update_wrong_length() {
        let reg = test_registry();
        let cmd = [0x80, 0x50, 0x00, 0x00, 0x08];

        let result =
            compare_semantic(&reg, &cmd, &[0u8; 27], [0x90, 0x00], &[0u8; 28], [0x90, 0x00]);
        assert!(matches!(result, SemanticResult::FieldMismatches(_)));
        if let SemanticResult::FieldMismatches(ref mm) = result {
            assert_eq!(mm[0].field, "response_length");
        }
    }

    #[test]
    fn semantic_get_data_0066_match_different_lifecycle() {
        let reg = test_registry();
        let cmd = [0x80, 0xCA, 0x00, 0x66];

        let left = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x07,
            0x02,
        ];
        let right = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x0F,
            0x02,
        ];

        let result = compare_semantic(&reg, &cmd, &left, [0x90, 0x00], &right, [0x90, 0x00]);
        assert_eq!(result, SemanticResult::Match);
    }

    #[test]
    fn semantic_get_data_0066_different_oid() {
        let reg = test_registry();
        let cmd = [0x80, 0xCA, 0x00, 0x66];

        let left = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x07,
            0x02,
        ];
        let right = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x07,
            0x02,
        ];

        let result = compare_semantic(&reg, &cmd, &left, [0x90, 0x00], &right, [0x90, 0x00]);
        assert!(matches!(result, SemanticResult::FieldMismatches(_)));
        if let SemanticResult::FieldMismatches(ref mm) = result {
            assert!(mm.iter().any(|m| m.field == "gp_oid"));
        }
    }

    #[test]
    fn semantic_get_data_0066_missing_inner_tag() {
        let reg = test_registry();
        let cmd = [0x80, 0xCA, 0x00, 0x66];

        let left = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x07,
            0x02,
        ];
        let right = [0x66, 0x04, 0x80, 0x02, 0x00, 0x10];

        let result = compare_semantic(&reg, &cmd, &left, [0x90, 0x00], &right, [0x90, 0x00]);
        assert!(matches!(result, SemanticResult::FieldMismatches(_)));
        if let SemanticResult::FieldMismatches(ref mm) = result {
            assert!(mm.iter().any(|m| m.field == "inner_tag_73"));
        }
    }

    #[test]
    fn semantic_select_match_no_data_fields() {
        let reg = test_registry();
        let cmd = [0x00, 0xA4, 0x04, 0x00, 0x07];
        let result = compare_semantic(&reg, &cmd, &[], [0x90, 0x00], &[0x6F, 0x00], [0x90, 0x00]);
        assert_eq!(result, SemanticResult::Match);
    }

    // -- Registry --

    #[test]
    fn registry_lookup_known_commands() {
        let reg = test_registry();
        assert_eq!(reg.lookup(&[0x80, 0x50, 0x00, 0x00]).unwrap().name, "INIT_UPDATE");
        assert_eq!(reg.lookup(&[0x80, 0xCA, 0x00, 0x66]).unwrap().name, "GET_DATA_0066");
        assert_eq!(reg.lookup(&[0x00, 0xA4, 0x04, 0x00]).unwrap().name, "SELECT");
    }

    #[test]
    fn registry_lookup_unknown() {
        let reg = test_registry();
        assert!(reg.lookup(&[0x80, 0xFD, 0x00, 0x00]).is_none());
        assert!(reg.lookup(&[0x80]).is_none());
        assert!(reg.lookup(&[]).is_none());
    }

    #[test]
    fn registry_get_data_other_tag_not_matched() {
        let reg = test_registry();
        assert!(reg.lookup(&[0x80, 0xCA, 0x00, 0xE0]).is_none());
    }

    // -- Insta snapshots --

    #[test]
    fn snap_semantic_result_match() {
        insta::assert_snapshot!("semantic_result_match", format!("{:?}", SemanticResult::Match));
    }

    #[test]
    fn snap_semantic_result_sw_mismatch() {
        let result = SemanticResult::SwMismatch {
            left: [0x90, 0x00],
            right: [0x6A, 0x82],
        };
        insta::assert_snapshot!("semantic_result_sw_mismatch", format!("{result:?}"));
    }

    #[test]
    fn snap_semantic_result_field_mismatches() {
        let result = SemanticResult::FieldMismatches(vec![
            FieldMismatch {
                field: "key_version",
                kind: MismatchKind::BytesDiffer {
                    left: vec![0x01],
                    right: vec![0xFF],
                },
            },
            FieldMismatch {
                field: "inner_tag_73",
                kind: MismatchKind::Missing { side: Side::Right },
            },
        ]);
        insta::assert_snapshot!("semantic_result_field_mismatches", format!("{result:#?}"));
    }

    #[test]
    fn snap_init_update_semantic_comparison() {
        let reg = test_registry();
        let cmd = [0x80, 0x50, 0x00, 0x00, 0x08];

        let mut left = [0u8; 28];
        left[10] = 0x01;
        left[11] = 0x02;
        left[12..20].fill(0xAA);
        left[20..28].fill(0xBB);

        let mut right = [0u8; 28];
        right[0..10].fill(0xFF);
        right[10] = 0x01;
        right[11] = 0x02;
        right[12..20].fill(0xCC);
        right[20..28].fill(0xDD);

        let result = compare_semantic(&reg, &cmd, &left, [0x90, 0x00], &right, [0x90, 0x00]);
        insta::assert_snapshot!("init_update_semantic", format!("{result:?}"));
    }

    #[test]
    fn snap_get_data_0066_semantic_comparison() {
        let reg = test_registry();
        let cmd = [0x80, 0xCA, 0x00, 0x66];

        let left = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x07,
            0x02,
        ];
        let right = [
            0x66, 0x0D, 0x73, 0x0B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x0F,
            0x02,
        ];

        let result = compare_semantic(&reg, &cmd, &left, [0x90, 0x00], &right, [0x90, 0x00]);
        insta::assert_snapshot!("get_data_0066_semantic", format!("{result:?}"));
    }

    #[test]
    fn snap_registry_lookup_all() {
        let reg = test_registry();
        let commands: &[(&str, &[u8])] = &[
            ("INIT_UPDATE", &[0x80, 0x50, 0x00, 0x00, 0x08]),
            ("GET_DATA_0066", &[0x80, 0xCA, 0x00, 0x66]),
            ("SELECT", &[0x00, 0xA4, 0x04, 0x00, 0x07]),
            ("UNKNOWN", &[0x80, 0xFD, 0x00, 0x00]),
            ("SHORT_CMD", &[0x80]),
            ("EMPTY", &[]),
        ];
        let output: String = commands
            .iter()
            .map(|(label, cmd)| {
                let schema = reg.lookup(cmd);
                let name = schema.map_or("None", |s| s.name);
                format!("{label}: {name}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        insta::assert_snapshot!("registry_lookup_all", output);
    }
}
