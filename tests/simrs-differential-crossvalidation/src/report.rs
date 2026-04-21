//! Structured differential test reporting.
//!
//! Produces `JUnit` XML for CI integration and Markdown for human review.
//! Known divergences are documented with spec references and reasoning;
//! unexpected divergences are reported as failures (regressions).

use std::fmt::Write as _;

use crate::known_divergences;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Classification of a differential test outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DivergenceCategory {
    /// Both implementations returned the same status word.
    Match,
    /// Status words differ, but the divergence is documented and accepted.
    KnownDivergence {
        /// Identifier of the matching catalog entry (e.g., "D6").
        id: &'static str,
    },
    /// Status words differ and the divergence is not cataloged -- a regression.
    Regression,
}

/// A single differential test case with results from both implementations.
#[derive(Debug, Clone)]
pub struct DiffTestCase {
    /// Human-readable test name.
    pub name: String,
    /// Command APDU bytes.
    pub command: Vec<u8>,
    /// Full response from simrs (data + SW).
    pub simrs_response: Vec<u8>,
    /// Full response from the reference backend (data + SW).
    pub reference_response: Vec<u8>,
    /// simrs status word.
    pub simrs_sw: u16,
    /// Reference-backend status word.
    pub reference_sw: u16,
    /// Test outcome classification.
    pub outcome: DivergenceCategory,
    /// Execution time in milliseconds.
    pub duration_ms: u64,
}

/// Aggregated differential test report.
///
/// Collects individual test cases and can emit `JUnit` XML for CI
/// integration or Markdown for human review.
#[derive(Debug)]
pub struct DiffReport {
    /// Identifier of the reference backend that produced this report
    /// (`"jcsl"`, `"jcardengine"`). Empty string on old reports that
    /// predate the backend parameterisation.
    pub backend: String,
    /// UTC timestamp as seconds since epoch.
    pub timestamp: u64,
    /// Individual test cases.
    pub cases: Vec<DiffTestCase>,
    /// Ordered key/value pairs describing how this report was
    /// produced: backend binary/jar version, applet class, AID, key
    /// material, etc. Renders as an "Environment" section in Markdown
    /// and as a `<properties>` block in the `JUnit` XML so the combined
    /// report can surface each backend's setup alongside its cells.
    pub context: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Escape special XML characters in text content and attribute values.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Format a byte slice as uppercase hex with spaces.
fn hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a status word as uppercase hex.
fn sw_hex(sw: u16) -> String {
    format!("{sw:04X}")
}

/// Convert days since Unix epoch to (year, month, day).
///
/// Approximate civil calendar conversion -- sufficient for report timestamps.
const fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert milliseconds to a seconds string with 3 decimal places.
///
/// Precision loss from u64-to-f64 is acceptable here; test durations
/// are well within the 52-bit mantissa range.
#[allow(clippy::cast_precision_loss)]
fn ms_to_seconds(ms: u64) -> String {
    format!("{:.3}", ms as f64 / 1000.0)
}

/// Emit a single `<testcase>` element (open tag, body, close tag)
/// for the given case. Split out from [`DiffReport::to_junit_xml`]
/// so that function stays under clippy's `too_many_lines` threshold
/// without silencing the lint.
fn emit_junit_testcase(xml: &mut String, case: &DiffTestCase, classname: &str) {
    let case_time = ms_to_seconds(case.duration_ms);
    let name_escaped = xml_escape(&case.name);
    // Emit simrs-sw and reference-sw as attributes so the combiner
    // can render a proper cross-backend table without re-parsing
    // every <failure>/<system-out> body.
    let _ = writeln!(
        xml,
        "  <testcase name=\"{name_escaped}\" \
         classname=\"{class}\" time=\"{case_time}\" \
         simrs-sw=\"{simrs_sw}\" reference-sw=\"{reference_sw}\">",
        class = xml_escape(classname),
        simrs_sw = sw_hex(case.simrs_sw),
        reference_sw = sw_hex(case.reference_sw),
    );

    match &case.outcome {
        DivergenceCategory::Match => {
            let _ = writeln!(
                xml,
                "    <system-out>SW match: {}</system-out>",
                sw_hex(case.simrs_sw),
            );
        }
        DivergenceCategory::KnownDivergence { id } => {
            let div = known_divergences::lookup_by_id(id);
            let reason = div.map_or("(no reason on file)", |d| d.reason);
            let spec = div.map_or("(no spec ref)", |d| d.spec_ref);
            // Report as a passing test with documentation, not <skipped>.
            // The divergence is expected and documented -- it's not ignored.
            let _ = writeln!(
                xml,
                "    <system-out>DOCUMENTED DIVERGENCE {id}: simrs={simrs_sw} reference={reference_sw}\n\
                 Reason: {reason}\n\
                 Spec: {spec}\n\
                 Command: {cmd}\n\
                 simrs response:     {simrs_rsp}\n\
                 Reference response: {reference_rsp}</system-out>",
                simrs_sw = sw_hex(case.simrs_sw),
                reference_sw = sw_hex(case.reference_sw),
                reason = xml_escape(reason),
                spec = xml_escape(spec),
                cmd = hex_spaced(&case.command),
                simrs_rsp = hex_spaced(&case.simrs_response),
                reference_rsp = hex_spaced(&case.reference_response),
            );
        }
        DivergenceCategory::Regression => {
            let message = format!(
                "SW mismatch: simrs={} reference={}",
                sw_hex(case.simrs_sw),
                sw_hex(case.reference_sw),
            );
            let _ = writeln!(
                xml,
                "    <failure message=\"{msg}\">\
                 Command: {cmd}\n\
                 simrs SW:     {simrs_sw}\n\
                 Reference SW: {reference_sw}\n\
                 simrs response:     {simrs_rsp}\n\
                 Reference response: {reference_rsp}</failure>",
                msg = xml_escape(&message),
                cmd = hex_spaced(&case.command),
                simrs_sw = sw_hex(case.simrs_sw),
                reference_sw = sw_hex(case.reference_sw),
                simrs_rsp = hex_spaced(&case.simrs_response),
                reference_rsp = hex_spaced(&case.reference_response),
            );
        }
    }

    xml.push_str("  </testcase>\n");
}

/// Render the divergence-detail section of the Markdown report. Split
/// from [`DiffReport::to_markdown`] for the same line-budget reason.
fn render_divergences_md(md: &mut String, cases: &[DiffTestCase], reference_label: &str) {
    let divergences: Vec<_> = cases
        .iter()
        .filter(|c| c.outcome != DivergenceCategory::Match)
        .collect();
    if divergences.is_empty() {
        return;
    }
    md.push_str("\n## Divergences\n\n");
    for case in divergences {
        match &case.outcome {
            DivergenceCategory::KnownDivergence { id } => {
                let _ = writeln!(md, "### {} ({})\n", case.name, id);
                if let Some(div) = known_divergences::lookup_by_id(id) {
                    let _ = writeln!(md, "- **Reason:** {}", div.reason);
                    let _ = writeln!(md, "- **Spec:** {}", div.spec_ref);
                }
                let _ = writeln!(md, "- **Command:** `{}`", hex_spaced(&case.command));
                let _ = writeln!(
                    md,
                    "- **simrs:** {} | **{reference_label}:** {}\n",
                    sw_hex(case.simrs_sw),
                    sw_hex(case.reference_sw),
                );
            }
            DivergenceCategory::Regression => {
                let _ = writeln!(md, "### {} (REGRESSION)\n", case.name);
                let _ = writeln!(md, "- **Command:** `{}`", hex_spaced(&case.command));
                let _ = writeln!(
                    md,
                    "- **simrs:** {} | **{reference_label}:** {}",
                    sw_hex(case.simrs_sw),
                    sw_hex(case.reference_sw),
                );
                let _ = writeln!(
                    md,
                    "- **simrs response:** `{}`",
                    hex_spaced(&case.simrs_response)
                );
                let _ = writeln!(
                    md,
                    "- **{reference_label} response:** `{}`\n",
                    hex_spaced(&case.reference_response)
                );
            }
            DivergenceCategory::Match => {}
        }
    }
}

// ---------------------------------------------------------------------------
// DiffReport implementation
// ---------------------------------------------------------------------------

impl DiffReport {
    /// Create a new empty report, capturing the current UTC time.
    ///
    /// Prefer [`new_for_backend`](Self::new_for_backend) -- this
    /// shim leaves [`backend`](Self::backend) empty and is only
    /// retained for older callers.
    pub fn new() -> Self {
        Self::new_for_backend("")
    }

    /// Create a new empty report tagged with a reference-backend
    /// identifier (`"jcsl"`, `"jcardengine"`).
    pub fn new_for_backend(backend: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            backend: backend.to_owned(),
            timestamp,
            cases: Vec::new(),
            context: Vec::new(),
        }
    }

    /// Append an environment/context entry (key, value).
    ///
    /// Keys should be short and machine-friendly (e.g.
    /// `"applet.class"`); values are rendered verbatim so hex,
    /// versions, paths all work. Order is preserved -- callers decide
    /// display order. Use this to record backend-specific setup:
    /// binary path, jar version, SCP master key, installed applet,
    /// key derivation family, etc.
    pub fn add_context(&mut self, key: &str, value: &str) {
        self.context.push((key.to_owned(), value.to_owned()));
    }

    /// Add a test case to the report.
    pub fn add_case(&mut self, case: DiffTestCase) {
        self.cases.push(case);
    }

    /// One-line summary of test outcomes.
    pub fn summary(&self) -> String {
        let mut matches = 0usize;
        let mut known = 0usize;
        let mut regressions = 0usize;
        for case in &self.cases {
            match &case.outcome {
                DivergenceCategory::Match => matches += 1,
                DivergenceCategory::KnownDivergence { .. } => known += 1,
                DivergenceCategory::Regression => regressions += 1,
            }
        }
        let known_label = if known == 1 {
            "documented divergence"
        } else {
            "documented divergences"
        };
        let regression_label = if regressions == 1 {
            "regression"
        } else {
            "regressions"
        };
        format!("{matches} match, {known} {known_label}, {regressions} {regression_label}")
    }

    /// Whether any test case was classified as a regression.
    pub fn has_regressions(&self) -> bool {
        self.cases
            .iter()
            .any(|c| c.outcome == DivergenceCategory::Regression)
    }

    /// Emit `JUnit` XML suitable for CI test result ingestion.
    ///
    /// The XML is hand-formatted with `write!` to avoid pulling in
    /// an XML serialization dependency.
    pub fn to_junit_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<testsuites>\n");

        let total = self.cases.len();
        let failures = self
            .cases
            .iter()
            .filter(|c| c.outcome == DivergenceCategory::Regression)
            .count();
        // Known divergences are reported as passing tests (not skipped).
        let skipped = 0usize;
        let elapsed = ms_to_seconds(self.cases.iter().map(|c| c.duration_ms).sum());

        // ISO 8601 timestamp from epoch seconds.
        let epoch = self.timestamp;
        let secs = epoch % 60;
        let mins = (epoch / 60) % 60;
        let hours = (epoch / 3600) % 24;
        let days = epoch / 86400;
        // Approximate date from days since epoch (good enough for reports).
        let (year, month, day) = epoch_days_to_ymd(days);
        let iso_ts = format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z");

        let suite_name = if self.backend.is_empty() {
            "differential".to_string()
        } else {
            format!("differential-{}", self.backend)
        };
        let suite_classname = &suite_name;
        let _ = writeln!(
            xml,
            "  <testsuite name=\"{suite}\" tests=\"{total}\" \
             failures=\"{failures}\" skipped=\"{skipped}\" \
             time=\"{elapsed}\" timestamp=\"{iso_ts}\">",
            suite = xml_escape(&suite_name),
        );

        // Environment / backend context. Emitted as a `<properties>`
        // block inside the testsuite so the combiner (or any JUnit
        // consumer) can associate each property with its backend.
        if !self.context.is_empty() {
            xml.push_str("    <properties>\n");
            for (k, v) in &self.context {
                let _ = writeln!(
                    xml,
                    "      <property name=\"{k}\" value=\"{v}\"/>",
                    k = xml_escape(k),
                    v = xml_escape(v),
                );
            }
            xml.push_str("    </properties>\n");
        }

        for case in &self.cases {
            emit_junit_testcase(&mut xml, case, suite_classname);
        }

        xml.push_str("  </testsuite>\n");
        xml.push_str("</testsuites>\n");
        xml
    }

    /// Emit a Markdown report for human review.
    ///
    /// Includes a summary line, a result table, and detailed divergence
    /// notes for any documented divergences or regressions.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        if self.backend.is_empty() {
            md.push_str("# Differential Test Report\n\n");
        } else {
            let _ = writeln!(
                md,
                "# Differential Test Report ({backend})\n",
                backend = self.backend
            );
        }
        let _ = writeln!(md, "**Summary:** {}\n", self.summary());

        // Environment / context section -- records how this backend
        // was wired up for the run. Skipped when no context has been
        // recorded.
        if !self.context.is_empty() {
            md.push_str("## Environment\n\n");
            for (k, v) in &self.context {
                let _ = writeln!(md, "- **{k}:** {v}");
            }
            md.push('\n');
        }

        // Result table -- the "Reference" column header is explicit about
        // which backend produced the reference column.
        let reference_col = if self.backend.is_empty() {
            "Reference SW".to_string()
        } else {
            format!("{} SW", self.backend)
        };
        let _ = writeln!(
            md,
            "| # | Test | simrs SW | {reference_col} | Status | Note |"
        );
        md.push_str("|---|------|----------|-----------|--------|------|\n");

        for (i, case) in self.cases.iter().enumerate() {
            let idx = i + 1;
            let status = match &case.outcome {
                DivergenceCategory::Match => "PASS",
                DivergenceCategory::KnownDivergence { .. } => "KNOWN",
                DivergenceCategory::Regression => "FAIL",
            };
            let note = match &case.outcome {
                DivergenceCategory::Match => String::new(),
                DivergenceCategory::KnownDivergence { id } => (*id).to_string(),
                DivergenceCategory::Regression => "REGRESSION".to_string(),
            };
            let _ = writeln!(
                md,
                "| {idx} | {} | {} | {} | {status} | {note} |",
                case.name,
                sw_hex(case.simrs_sw),
                sw_hex(case.reference_sw),
            );
        }

        // Detailed divergence notes
        let reference_label = if self.backend.is_empty() {
            "Reference".to_string()
        } else {
            self.backend.clone()
        };
        render_divergences_md(&mut md, &self.cases, &reference_label);

        md
    }
}

impl Default for DiffReport {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Match test case for reuse.
    fn match_case() -> DiffTestCase {
        DiffTestCase {
            name: "SELECT ISD".to_string(),
            command: vec![
                0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00,
            ],
            simrs_response: vec![0x90, 0x00],
            reference_response: vec![0x90, 0x00],
            simrs_sw: 0x9000,
            reference_sw: 0x9000,
            outcome: DivergenceCategory::Match,
            duration_ms: 5,
        }
    }

    /// Build a `KnownDivergence` test case (D6).
    fn known_divergence_case() -> DiffTestCase {
        DiffTestCase {
            name: "EXTERNAL AUTHENTICATE bad MAC".to_string(),
            command: vec![
                0x84, 0x82, 0x03, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            ],
            simrs_response: vec![0x69, 0x88],
            reference_response: vec![0x69, 0x85],
            simrs_sw: 0x6988,
            reference_sw: 0x6985,
            outcome: DivergenceCategory::KnownDivergence { id: "D6" },
            duration_ms: 12,
        }
    }

    /// Build a Regression test case.
    fn regression_case() -> DiffTestCase {
        DiffTestCase {
            name: "GET STATUS".to_string(),
            command: vec![0x80, 0xF2, 0x40, 0x00, 0x02, 0x4F, 0x00],
            simrs_response: vec![0x6A, 0x88],
            reference_response: vec![0x6A, 0x82],
            simrs_sw: 0x6A88,
            reference_sw: 0x6A82,
            outcome: DivergenceCategory::Regression,
            duration_ms: 3,
        }
    }

    // -- JUnit XML tests --------------------------------------------------

    #[test]
    fn test_junit_xml_match() {
        let mut report = DiffReport::new();
        report.add_case(match_case());
        let xml = report.to_junit_xml();

        assert!(
            xml.contains("<?xml version=\"1.0\""),
            "must have XML declaration"
        );
        assert!(xml.contains("<testsuite"), "must have testsuite element");
        assert!(xml.contains("tests=\"1\""), "must report 1 test");
        assert!(xml.contains("failures=\"0\""), "must report 0 failures");
        assert!(xml.contains("skipped=\"0\""), "must report 0 skipped");
        assert!(
            xml.contains("<testcase name=\"SELECT ISD\""),
            "must have testcase"
        );
        assert!(
            xml.contains("<system-out>SW match: 9000</system-out>"),
            "must show SW match"
        );
        assert!(!xml.contains("<failure"), "match must not produce failure");
        assert!(!xml.contains("<skipped"), "match must not produce skipped");
    }

    #[test]
    fn test_junit_xml_known_divergence() {
        let mut report = DiffReport::new();
        report.add_case(known_divergence_case());
        let xml = report.to_junit_xml();

        assert!(
            xml.contains("skipped=\"0\""),
            "documented divergences are not skipped"
        );
        assert!(
            xml.contains("failures=\"0\""),
            "documented divergence is not a failure"
        );
        assert!(
            xml.contains("DOCUMENTED DIVERGENCE"),
            "must have documented divergence in system-out"
        );
        assert!(xml.contains("D6"), "must reference divergence ID");
        assert!(xml.contains("6988"), "must show simrs SW");
        assert!(xml.contains("6985"), "must show reference SW");
        assert!(xml.contains("padding oracle"), "must include reason text");
    }

    #[test]
    fn test_junit_xml_regression() {
        let mut report = DiffReport::new();
        report.add_case(regression_case());
        let xml = report.to_junit_xml();

        assert!(xml.contains("failures=\"1\""), "must report 1 failure");
        assert!(
            xml.contains("<failure message=\""),
            "must have failure element"
        );
        assert!(xml.contains("6A88"), "must show simrs SW in failure");
        assert!(xml.contains("6A82"), "must show reference SW in failure");
        assert!(
            xml.contains("SW mismatch"),
            "failure message must describe mismatch"
        );
    }

    #[test]
    fn test_junit_xml_escaping() {
        let mut report = DiffReport::new();
        let mut case = match_case();
        case.name = "test <with> \"special\" & 'chars'".to_string();
        report.add_case(case);
        let xml = report.to_junit_xml();

        assert!(
            xml.contains("test &lt;with&gt; &quot;special&quot; &amp; &apos;chars&apos;"),
            "special chars must be escaped in XML: {xml}"
        );
    }

    // -- Markdown tests ---------------------------------------------------

    #[test]
    fn test_markdown_summary() {
        let mut report = DiffReport::new();
        report.add_case(match_case());
        report.add_case(known_divergence_case());
        let md = report.to_markdown();

        assert!(
            md.contains("1 match, 1 documented divergence, 0 regressions"),
            "markdown must include summary line: {md}"
        );
        assert!(
            md.contains("| # | Test |"),
            "markdown must include table header"
        );
    }

    #[test]
    fn test_markdown_table_rows() {
        let mut report = DiffReport::new();
        report.add_case(match_case());
        report.add_case(regression_case());
        let md = report.to_markdown();

        assert!(md.contains("| PASS |"), "match row must show PASS");
        assert!(md.contains("| FAIL |"), "regression row must show FAIL");
        assert!(md.contains("REGRESSION"), "regression note must appear");
    }

    // -- Summary / has_regressions ----------------------------------------

    #[test]
    fn test_has_regressions_false_when_only_matches() {
        let mut report = DiffReport::new();
        report.add_case(match_case());
        assert!(
            !report.has_regressions(),
            "report with only matches must not have regressions"
        );
    }

    #[test]
    fn test_has_regressions_false_with_known_divergence() {
        let mut report = DiffReport::new();
        report.add_case(match_case());
        report.add_case(known_divergence_case());
        assert!(
            !report.has_regressions(),
            "documented divergences are not regressions"
        );
    }

    #[test]
    fn test_has_regressions_true_with_regression() {
        let mut report = DiffReport::new();
        report.add_case(match_case());
        report.add_case(regression_case());
        assert!(
            report.has_regressions(),
            "report with a regression must return true"
        );
    }

    #[test]
    fn test_summary_pluralization() {
        let mut report = DiffReport::new();
        report.add_case(match_case());
        assert!(
            report.summary().contains("0 regressions"),
            "zero should be plural"
        );
        assert!(
            report.summary().contains("0 documented divergences"),
            "zero should be plural"
        );

        let mut report2 = DiffReport::new();
        report2.add_case(known_divergence_case());
        assert!(
            report2.summary().contains("1 documented divergence,"),
            "one should be singular"
        );

        let mut report3 = DiffReport::new();
        report3.add_case(regression_case());
        assert!(
            report3.summary().contains("1 regression"),
            "one should be singular"
        );
        // Make sure "1 regression" is not "1 regressions"
        assert!(
            !report3.summary().contains("1 regressions"),
            "one regression must be singular"
        );
    }

    // -- hex/escape helpers -----------------------------------------------

    #[test]
    fn test_hex_spaced_formatting() {
        let bytes = [
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
        ];
        let formatted = hex_spaced(&bytes);
        assert_eq!(
            formatted, "00 A4 04 00 07 A0 00 00 00 87 10 02",
            "must be uppercase hex with single spaces"
        );
    }

    #[test]
    fn test_hex_spaced_empty() {
        assert_eq!(hex_spaced(&[]), "", "empty input produces empty string");
    }

    #[test]
    fn test_xml_escape_passthrough() {
        assert_eq!(xml_escape("hello world"), "hello world");
    }

    #[test]
    fn test_xml_escape_all_special_chars() {
        assert_eq!(
            xml_escape("a & b < c > d \" e ' f"),
            "a &amp; b &lt; c &gt; d &quot; e &apos; f"
        );
    }
}
