//! N-way APDU comparison engine.
//!
//! [`DiffEngine`] replays APDUs through N [`Transport`] backends and
//! compares all responses pairwise using the divergence infrastructure.
//!
//! This is the reusable core extracted from the interposer's Diff mode.
//! It can be used directly (for differential testing) or wrapped by
//! [`ProxyLoop`](crate::proxy::ProxyLoop) for live interposition.
//!
//! # Example
//!
//! ```rust,ignore
//! let mut engine = DiffEngine::new();
//! engine.add_backend("simrs", Box::new(gp_terminal));
//! engine.add_backend("oracle", Box::new(jcsl_client));
//!
//! let results = engine.replay_one(&select_apdu);
//! engine.print_summary();
//! ```

use simrs_transport::{Transport, TransportError};

use crate::divergence::{self, CompareResult, DivergenceStats};
use crate::semantic::{self, SchemaRegistry, SemanticResult};

/// A single backend's response to an APDU.
struct BackendResponse {
    /// Response data (excluding SW).
    data: Vec<u8>,
    /// Status word byte 1.
    sw1: u8,
    /// Status word byte 2.
    sw2: u8,
}

/// Record of a single divergence detected during replay.
pub struct DiffRecord {
    /// Sequence number (0-indexed).
    pub seq: u64,
    /// The APDU command that produced this divergence.
    pub cmd: Vec<u8>,
    /// Index of the left backend in the comparison.
    pub left_idx: usize,
    /// Index of the right backend in the comparison.
    pub right_idx: usize,
    /// The comparison result.
    pub result: CompareResult,
}

/// Extended stats that distinguish expected differences from real divergences.
///
/// Tracks both byte-level (backwards compatible) and semantic comparison
/// results. Use alongside [`DiffEngine`] for richer differential analysis.
#[derive(Debug, Default)]
pub struct SemanticDivergenceStats {
    /// APDUs where semantic comparison found all fields match per policy.
    pub semantic_matches: u64,
    /// APDUs where semantic comparison found real field-level mismatches.
    pub semantic_mismatches: u64,
    /// APDUs where no schema was available (fell back to byte-level).
    pub schema_fallbacks: u64,
}

/// N-way APDU comparison engine.
///
/// Holds N [`Transport`] backends and replays APDUs through all of them,
/// comparing responses pairwise. Uses [`compare_responses`] and
/// [`DivergenceStats`] from the divergence module.
///
/// Backends are registered with human-readable labels for diagnostics.
pub struct DiffEngine {
    backends: Vec<(String, Box<dyn Transport<Error = TransportError>>)>,
    /// Accumulated byte-level comparison statistics.
    pub stats: DivergenceStats,
    /// Accumulated semantic comparison statistics.
    pub semantic_stats: SemanticDivergenceStats,
    /// Schema registry for semantic comparison.
    pub schema_registry: SchemaRegistry,
    /// All detected divergences for post-mortem analysis.
    pub divergences: Vec<DiffRecord>,
    seq_num: u64,
}

impl DiffEngine {
    /// Create a new engine with no backends.
    /// Create a new engine with no backends and an empty schema registry.
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            stats: DivergenceStats::default(),
            semantic_stats: SemanticDivergenceStats::default(),
            schema_registry: SchemaRegistry::new(),
            divergences: Vec::new(),
            seq_num: 0,
        }
    }

    /// Create a new engine with the standard GP schema registry pre-loaded.
    pub fn with_gp_schemas() -> Self {
        Self {
            backends: Vec::new(),
            stats: DivergenceStats::default(),
            semantic_stats: SemanticDivergenceStats::default(),
            schema_registry: semantic::gp_schema_registry(),
            divergences: Vec::new(),
            seq_num: 0,
        }
    }

    /// Register a backend with a label.
    ///
    /// Backends are compared pairwise: the first backend is compared
    /// against all subsequent ones.
    pub fn add_backend(
        &mut self,
        label: impl Into<String>,
        backend: Box<dyn Transport<Error = TransportError>>,
    ) {
        self.backends.push((label.into(), backend));
    }

    /// Number of registered backends.
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Replay a single APDU through all backends and compare pairwise.
    ///
    /// Returns one [`CompareResult`] per pair (first vs second, first vs
    /// third, etc.). If fewer than two backends are registered, returns
    /// an empty vec.
    ///
    /// # Panics
    ///
    /// Panics if any backend returns a transport error.
    pub fn replay_one(&mut self, cmd: &[u8]) -> Vec<CompareResult> {
        let responses = self.exchange_all(cmd);
        let results = self.compare_all(cmd, &responses);
        self.seq_num += 1;
        results
    }

    /// Replay a sequence of APDUs through all backends.
    ///
    /// Returns a reference to the accumulated stats.
    pub fn replay_sequence(&mut self, cmds: &[&[u8]]) -> &DivergenceStats {
        for cmd in cmds {
            self.replay_one(cmd);
        }
        &self.stats
    }

    /// Replay a single APDU with semantic comparison.
    ///
    /// Tries schema-based semantic comparison first. If no schema matches
    /// the command, falls back to byte-level comparison (recording the
    /// result as [`SemanticResult::SchemaNotApplicable`]).
    ///
    /// Also records byte-level stats for backwards compatibility.
    ///
    /// # Panics
    ///
    /// Panics if any backend returns a transport error.
    pub fn replay_one_semantic(&mut self, cmd: &[u8]) -> Vec<SemanticResult> {
        let responses = self.exchange_all(cmd);
        let results = self.compare_all_semantic(cmd, &responses);
        self.seq_num += 1;
        results
    }

    /// Print a human-readable summary to stderr.
    pub fn print_summary(&self) {
        let labels: Vec<&str> = self.backends.iter().map(|(l, _)| l.as_str()).collect();
        eprintln!("[DiffEngine] backends: [{}]", labels.join(", "));
        eprintln!(
            "[DiffEngine] total={} match={} sw_mismatch={} data_mismatch={} ignored={}",
            self.stats.total_apdus,
            self.stats.matches,
            self.stats.sw_mismatches,
            self.stats.data_mismatches,
            self.stats.shadow_ignored,
        );
        if !self.divergences.is_empty() {
            eprintln!(
                "[DiffEngine] {} divergences recorded",
                self.divergences.len()
            );
        }
    }

    // -- internal --

    /// Send the APDU to all backends and collect responses.
    fn exchange_all(&mut self, cmd: &[u8]) -> Vec<BackendResponse> {
        let mut responses = Vec::with_capacity(self.backends.len());
        for (label, backend) in &mut self.backends {
            let mut rsp_buf = [0u8; 261];
            let n = backend
                .exchange(cmd, &mut rsp_buf)
                .unwrap_or_else(|e| panic!("[DiffEngine] {label}: transport error: {e:?}"));

            if n >= 2 {
                responses.push(BackendResponse {
                    data: rsp_buf[..n - 2].to_vec(),
                    sw1: rsp_buf[n - 2],
                    sw2: rsp_buf[n - 1],
                });
            } else {
                responses.push(BackendResponse {
                    data: Vec::new(),
                    sw1: 0x6F,
                    sw2: 0x00,
                });
            }
        }
        responses
    }

    /// Compare all responses pairwise (first vs each subsequent).
    fn compare_all(&mut self, cmd: &[u8], responses: &[BackendResponse]) -> Vec<CompareResult> {
        if responses.len() < 2 {
            return Vec::new();
        }

        let first = &responses[0];
        let mut results = Vec::with_capacity(responses.len() - 1);

        for (idx, resp) in responses.iter().enumerate().skip(1) {
            let result = divergence::compare_responses(
                &first.data,
                first.sw1,
                first.sw2,
                Some((&resp.data, resp.sw1, resp.sw2)),
            );

            self.stats.record(&result);

            if result != CompareResult::Match {
                let msg = divergence::format_divergence(cmd, &result, self.seq_num);
                eprintln!(
                    "[DiffEngine] {} vs {}: {msg}",
                    self.backends[0].0, self.backends[idx].0
                );

                self.divergences.push(DiffRecord {
                    seq: self.seq_num,
                    cmd: cmd.to_vec(),
                    left_idx: 0,
                    right_idx: idx,
                    result: result.clone(),
                });
            }

            results.push(result);
        }

        results
    }

    /// Compare all responses pairwise using semantic schemas.
    ///
    /// Falls back to byte-level for unrecognized commands, recording
    /// `SchemaNotApplicable` in the results.
    fn compare_all_semantic(
        &mut self,
        cmd: &[u8],
        responses: &[BackendResponse],
    ) -> Vec<SemanticResult> {
        if responses.len() < 2 {
            return Vec::new();
        }

        let first = &responses[0];
        let mut results = Vec::with_capacity(responses.len() - 1);

        for (idx, resp) in responses.iter().enumerate().skip(1) {
            let result = semantic::compare_semantic(
                &self.schema_registry,
                cmd,
                &first.data,
                [first.sw1, first.sw2],
                &resp.data,
                [resp.sw1, resp.sw2],
            );

            // Also record byte-level stats for backwards compat.
            let byte_result = divergence::compare_responses(
                &first.data,
                first.sw1,
                first.sw2,
                Some((&resp.data, resp.sw1, resp.sw2)),
            );
            self.stats.record(&byte_result);

            // Record semantic stats.
            match &result {
                SemanticResult::Match => self.semantic_stats.semantic_matches += 1,
                SemanticResult::SwMismatch { .. } | SemanticResult::FieldMismatches(_) => {
                    self.semantic_stats.semantic_mismatches += 1;
                }
                SemanticResult::SchemaNotApplicable => {
                    self.semantic_stats.schema_fallbacks += 1;
                }
            }

            // Log semantic mismatches.
            if !matches!(
                result,
                SemanticResult::Match | SemanticResult::SchemaNotApplicable
            ) {
                eprintln!(
                    "[DiffEngine] {} vs {} (semantic): {result:?}",
                    self.backends[0].0, self.backends[idx].0,
                );
            }

            results.push(result);
        }

        results
    }
}

impl Default for DiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that always returns a fixed response.
    struct FixedTransport {
        data: Vec<u8>,
        sw1: u8,
        sw2: u8,
    }

    impl FixedTransport {
        fn new(data: &[u8], sw1: u8, sw2: u8) -> Self {
            Self {
                data: data.to_vec(),
                sw1,
                sw2,
            }
        }

        fn success() -> Self {
            Self::new(&[], 0x90, 0x00)
        }

        fn error_6a82() -> Self {
            Self::new(&[], 0x6A, 0x82)
        }
    }

    impl Transport for FixedTransport {
        type Error = TransportError;

        fn exchange(&mut self, _cmd: &[u8], rsp: &mut [u8]) -> Result<usize, TransportError> {
            let len = self.data.len() + 2;
            if len > rsp.len() {
                return Err(TransportError::BufferTooSmall);
            }
            rsp[..self.data.len()].copy_from_slice(&self.data);
            rsp[self.data.len()] = self.sw1;
            rsp[self.data.len() + 1] = self.sw2;
            Ok(len)
        }
    }

    #[test]
    fn empty_engine_returns_no_results() {
        let mut engine = DiffEngine::new();
        let results = engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);
        assert!(results.is_empty());
    }

    #[test]
    fn single_backend_returns_no_results() {
        let mut engine = DiffEngine::new();
        engine.add_backend("only", Box::new(FixedTransport::success()));
        let results = engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);
        assert!(results.is_empty());
    }

    #[test]
    fn two_matching_backends() {
        let mut engine = DiffEngine::new();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::success()));

        let results = engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], CompareResult::Match);
        assert_eq!(engine.stats.total_apdus, 1);
        assert_eq!(engine.stats.matches, 1);
    }

    #[test]
    fn two_diverging_backends() {
        let mut engine = DiffEngine::new();
        engine.add_backend("simrs", Box::new(FixedTransport::success()));
        engine.add_backend("oracle", Box::new(FixedTransport::error_6a82()));

        let results = engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], CompareResult::SwMismatch { .. }));
        assert_eq!(engine.stats.sw_mismatches, 1);
        assert_eq!(engine.divergences.len(), 1);
    }

    #[test]
    fn three_way_comparison() {
        let mut engine = DiffEngine::new();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::success()));
        engine.add_backend("c", Box::new(FixedTransport::error_6a82()));

        let results = engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], CompareResult::Match);
        assert!(matches!(results[1], CompareResult::SwMismatch { .. }));
    }

    #[test]
    fn data_mismatch_detected() {
        let mut engine = DiffEngine::new();
        engine.add_backend(
            "a",
            Box::new(FixedTransport::new(&[0x01, 0x02], 0x90, 0x00)),
        );
        engine.add_backend(
            "b",
            Box::new(FixedTransport::new(&[0x03, 0x04], 0x90, 0x00)),
        );

        let results = engine.replay_one(&[0x00, 0xB0, 0x00, 0x00]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], CompareResult::DataMismatch { .. }));
    }

    #[test]
    fn replay_sequence_accumulates() {
        let mut engine = DiffEngine::new();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::success()));

        let cmds: &[&[u8]] = &[
            &[0x00, 0xA4, 0x00, 0x00],
            &[0x80, 0xCA, 0x00, 0x66],
            &[0x80, 0x50, 0x00, 0x00],
        ];

        let stats = engine.replay_sequence(cmds);
        assert_eq!(stats.total_apdus, 3);
        assert_eq!(stats.matches, 3);
    }

    #[test]
    fn backend_count() {
        let mut engine = DiffEngine::new();
        assert_eq!(engine.backend_count(), 0);
        engine.add_backend("a", Box::new(FixedTransport::success()));
        assert_eq!(engine.backend_count(), 1);
        engine.add_backend("b", Box::new(FixedTransport::success()));
        assert_eq!(engine.backend_count(), 2);
    }

    #[test]
    fn print_summary_no_panic() {
        let mut engine = DiffEngine::new();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::error_6a82()));
        engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);
        engine.print_summary();
    }

    #[test]
    fn seq_num_increments() {
        let mut engine = DiffEngine::new();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::error_6a82()));

        engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);
        engine.replay_one(&[0x00, 0xA4, 0x00, 0x00]);

        assert_eq!(engine.divergences.len(), 2);
        assert_eq!(engine.divergences[0].seq, 0);
        assert_eq!(engine.divergences[1].seq, 1);
    }

    // -------------------------------------------------------------------
    // Insta snapshots
    // -------------------------------------------------------------------

    #[test]
    fn snap_stats_two_matching() {
        let mut engine = DiffEngine::new();
        engine.add_backend("simrs", Box::new(FixedTransport::success()));
        engine.add_backend("oracle", Box::new(FixedTransport::success()));

        let cmds: &[&[u8]] = &[
            &[0x00, 0xA4, 0x04, 0x00, 0x00],
            &[0x80, 0xCA, 0x00, 0x66],
            &[
                0x80, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ],
        ];
        engine.replay_sequence(cmds);

        insta::assert_snapshot!("stats_two_matching", format!("{:#?}", engine.stats));
    }

    #[test]
    fn snap_stats_all_diverging() {
        let mut engine = DiffEngine::new();
        engine.add_backend("simrs", Box::new(FixedTransport::success()));
        engine.add_backend("oracle", Box::new(FixedTransport::error_6a82()));

        let cmds: &[&[u8]] = &[
            &[0x00, 0xA4, 0x04, 0x00, 0x00],
            &[0x80, 0xCA, 0x00, 0x66],
            &[0x80, 0x50, 0x00, 0x00],
        ];
        engine.replay_sequence(cmds);

        insta::assert_snapshot!("stats_all_diverging", format!("{:#?}", engine.stats));
    }

    #[test]
    fn snap_stats_three_way_mixed() {
        let mut engine = DiffEngine::new();
        engine.add_backend("simrs", Box::new(FixedTransport::success()));
        engine.add_backend("oracle", Box::new(FixedTransport::success()));
        engine.add_backend("shadow", Box::new(FixedTransport::error_6a82()));

        engine.replay_one(&[0x00, 0xA4, 0x04, 0x00, 0x00]);
        engine.replay_one(&[0x80, 0xCA, 0x00, 0x66]);

        // simrs vs oracle: 2 matches; simrs vs shadow: 2 sw_mismatches
        insta::assert_snapshot!("stats_three_way_mixed", format!("{:#?}", engine.stats));
    }

    #[test]
    fn snap_data_mismatch_divergence() {
        let mut engine = DiffEngine::new();
        engine.add_backend(
            "a",
            Box::new(FixedTransport::new(&[0x01, 0x02, 0x03], 0x90, 0x00)),
        );
        engine.add_backend(
            "b",
            Box::new(FixedTransport::new(&[0xAA, 0xBB], 0x90, 0x00)),
        );

        let results = engine.replay_one(&[0x00, 0xB0, 0x00, 0x00]);
        let result_strs: Vec<String> = results.iter().map(|r| format!("{r:?}")).collect();
        let div_strs: Vec<String> = engine
            .divergences
            .iter()
            .map(|d| {
                format!(
                    "seq={} cmd={:02x?} left={} right={} result={:?}",
                    d.seq, d.cmd, d.left_idx, d.right_idx, d.result
                )
            })
            .collect();

        let output = format!(
            "results:\n{}\ndivergences:\n{}",
            result_strs.join("\n"),
            div_strs.join("\n"),
        );
        insta::assert_snapshot!("data_mismatch_divergence", output);
    }

    #[test]
    fn snap_replay_results_debug() {
        let mut engine = DiffEngine::new();
        engine.add_backend(
            "simrs",
            Box::new(FixedTransport::new(&[0x66, 0x10], 0x90, 0x00)),
        );
        engine.add_backend(
            "oracle",
            Box::new(FixedTransport::new(&[0x66, 0x12], 0x90, 0x00)),
        );

        let r1 = engine.replay_one(&[0x80, 0xCA, 0x00, 0x66]);
        let r2 = engine.replay_one(&[0x00, 0xA4, 0x04, 0x00, 0x00]);

        let output = format!("apdu_1: {r1:?}\napdu_2: {r2:?}");
        insta::assert_snapshot!("replay_results_debug", output);
    }

    // -------------------------------------------------------------------
    // Semantic comparison via DiffEngine
    // -------------------------------------------------------------------

    #[test]
    fn semantic_select_matching_backends() {
        let mut engine = DiffEngine::with_gp_schemas();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::success()));

        // SELECT command -- has a schema
        let results = engine.replay_one_semantic(&[0x00, 0xA4, 0x04, 0x00, 0x07]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], SemanticResult::Match);
        assert_eq!(engine.semantic_stats.semantic_matches, 1);
    }

    #[test]
    fn semantic_select_sw_mismatch() {
        let mut engine = DiffEngine::with_gp_schemas();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::error_6a82()));

        let results = engine.replay_one_semantic(&[0x00, 0xA4, 0x04, 0x00, 0x07]);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], SemanticResult::SwMismatch { .. }));
        assert_eq!(engine.semantic_stats.semantic_mismatches, 1);
    }

    #[test]
    fn semantic_unknown_command_falls_back() {
        let mut engine = DiffEngine::new();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::success()));

        // Unknown INS -- no schema registered
        let results = engine.replay_one_semantic(&[0x80, 0xFD, 0x00, 0x00]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], SemanticResult::SchemaNotApplicable);
        assert_eq!(engine.semantic_stats.schema_fallbacks, 1);
    }

    #[test]
    fn semantic_init_update_different_data_is_match() {
        // Two backends with different INIT UPDATE response data but same structure.
        let mut left_data = [0u8; 28];
        left_data[10] = 0x01; // key_version
        left_data[11] = 0x02; // scp_id
        left_data[12..20].fill(0xAA); // challenge
        left_data[20..28].fill(0xBB); // cryptogram

        let mut right_data = [0u8; 28];
        right_data[0..10].fill(0xFF); // different key diversification
        right_data[10] = 0x01; // same key_version
        right_data[11] = 0x02; // same scp_id
        right_data[12..20].fill(0xCC); // different challenge
        right_data[20..28].fill(0xDD); // different cryptogram

        let mut engine = DiffEngine::with_gp_schemas();
        engine.add_backend("a", Box::new(FixedTransport::new(&left_data, 0x90, 0x00)));
        engine.add_backend("b", Box::new(FixedTransport::new(&right_data, 0x90, 0x00)));

        let results =
            engine.replay_one_semantic(&[0x80, 0x50, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], SemanticResult::Match);
        assert_eq!(engine.semantic_stats.semantic_matches, 1);

        // Byte-level stats should show a data mismatch (backwards compat).
        assert_eq!(engine.stats.data_mismatches, 1);
    }

    #[test]
    fn semantic_mixed_sequence_stats() {
        let mut engine = DiffEngine::with_gp_schemas();
        engine.add_backend("a", Box::new(FixedTransport::success()));
        engine.add_backend("b", Box::new(FixedTransport::success()));

        // SELECT -> semantic match
        engine.replay_one_semantic(&[0x00, 0xA4, 0x04, 0x00, 0x07]);
        // Unknown INS -> schema fallback
        engine.replay_one_semantic(&[0x80, 0xFD, 0x00, 0x00]);
        // Another SELECT -> semantic match
        engine.replay_one_semantic(&[0x00, 0xA4, 0x04, 0x00, 0x07]);

        assert_eq!(engine.semantic_stats.semantic_matches, 2);
        assert_eq!(engine.semantic_stats.schema_fallbacks, 1);
        assert_eq!(engine.semantic_stats.semantic_mismatches, 0);
    }

    #[test]
    fn snap_semantic_stats_mixed() {
        let mut engine = DiffEngine::with_gp_schemas();
        engine.add_backend("simrs", Box::new(FixedTransport::success()));
        engine.add_backend("oracle", Box::new(FixedTransport::success()));

        engine.replay_one_semantic(&[0x00, 0xA4, 0x04, 0x00, 0x07]); // SELECT
        engine.replay_one_semantic(&[0x80, 0xCA, 0x00, 0x66]); // GET DATA 0066
        engine.replay_one_semantic(&[0x80, 0xFD, 0x00, 0x00]); // unknown

        let output = format!(
            "byte_level:\n{:#?}\nsemantic:\n{:#?}",
            engine.stats, engine.semantic_stats
        );
        insta::assert_snapshot!("semantic_stats_mixed", output);
    }
}
