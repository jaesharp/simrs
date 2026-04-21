//! Cross-backend differential report combiner.
//!
//! Reads the per-backend `JUnit` XML files produced by [`report_gen`]
//! (one per [`BackendId`]) and emits a combined report that shows how
//! each APDU fared across every reference backend, plus a consensus
//! column for "do the reference backends agree with each other".
//!
//! # Inputs
//!
//! Looks for files named `differential-report-<backend>.xml` in
//! `SIMRS_DIFF_REPORT_DIR` (default: the crate root, i.e. the cwd
//! where `cargo test -p simrs-differential-crossvalidation` leaves
//! `report_gen` output). Missing backend files are tolerated: their
//! cells appear as `-` in the combined table so the same combiner
//! works whether you ran just jcsl, just jcardengine, or both.
//!
//! # Outputs
//!
//! - `differential-report-combined.xml` -- flat `JUnit` XML with one
//!   `<testsuite>` per backend (mirrors input) plus a synthetic
//!   `<testsuite name="consensus">` summarising per-row agreement.
//! - `differential-report-combined.md` -- single Markdown table, one
//!   row per test case with PASS/KNOWN/FAIL/- per backend and an
//!   explicit "simrs matches all" column.
//!
//! # Running
//!
//! ```bash
//! # After running report_gen for both backends:
//! cargo test -p simrs-differential-crossvalidation --test report_combine -- --nocapture
//! ```
//!
//! [`report_gen`]: ../report_gen/index.html
//! [`BackendId`]: simrs_differential_crossvalidation::BackendId

use simrs_differential_crossvalidation::{
    BackendId, default_report_dir,
    known_divergences::{self, CATALOG_PATH},
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Backends that might have per-backend reports. Iterated in the
/// enum's derived lex order (`Jcardengine` < `Jcsl`) so column order
/// is deterministic and alphabetical.
const BACKENDS: &[BackendId] = &[BackendId::Jcardengine, BackendId::Jcsl];

/// Per-test outcome as parsed back out of a `JUnit` XML.
///
/// The string carries enough detail (SW hex, divergence id) for the
/// Markdown rendering; `Status` captures the high-level bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    /// `<system-out>SW match: NNNN</system-out>` or equivalent.
    Match,
    /// `<system-out>DOCUMENTED DIVERGENCE <id>...` -- catalog entry
    /// applies; divergence expected.
    Known(String),
    /// `<failure ...>` element present -- uncataloged regression.
    Regression,
}

impl Status {
    const fn symbol(&self) -> &'static str {
        match self {
            Self::Match => "PASS",
            Self::Known(_) => "KNOWN",
            Self::Regression => "FAIL",
        }
    }
}

/// One parsed `<testcase>`, with both raw SWs and the outcome bucket.
#[derive(Debug, Clone)]
struct CaseRow {
    simrs_sw: String,
    reference_sw: String,
    status: Status,
}

/// All cases extracted from one backend's `JUnit` XML, plus the
/// environment/context properties emitted by the backend.
#[derive(Debug, Default)]
struct BackendReport {
    /// Map of case name -> row. `BTreeMap` so iteration is
    /// deterministic across runs.
    cases: BTreeMap<String, CaseRow>,
    /// Ordered environment entries extracted from the `<properties>`
    /// block inside the testsuite, preserving emission order.
    context: Vec<(String, String)>,
}

/// Minimal tag-and-body extractor for our single-purpose `JUnit`
/// subset. Avoids pulling in an XML parser for the ~10-line shape we
/// control: `<testcase name="..." simrs-sw="..." reference-sw="..."> ... </testcase>`
/// with one `<system-out>` or `<failure>` child.
fn parse_junit(xml: &str) -> BackendReport {
    let mut report = BackendReport {
        context: parse_properties(xml),
        ..BackendReport::default()
    };
    let mut cursor = 0usize;
    while let Some(start) = xml[cursor..].find("<testcase ") {
        let open = cursor + start;
        let Some(close) = xml[open..].find("</testcase>") else {
            break;
        };
        let end = open + close;
        let block = &xml[open..end];

        // Extract the name="..." attribute (single-quoted not supported
        // -- our emitter always uses double quotes).
        let Some(name) = extract_attr(block, "name") else {
            cursor = end;
            continue;
        };
        let simrs_sw = extract_attr(block, "simrs-sw").unwrap_or_else(|| "----".to_string());
        let reference_sw =
            extract_attr(block, "reference-sw").unwrap_or_else(|| "----".to_string());

        // Status: <failure> wins over <system-out> classification.
        let status = if block.contains("<failure ") {
            Status::Regression
        } else if let Some(divergence) = extract_known_divergence(block) {
            Status::Known(divergence)
        } else {
            Status::Match
        };

        report.cases.insert(
            name,
            CaseRow {
                simrs_sw,
                reference_sw,
                status,
            },
        );
        cursor = end + "</testcase>".len();
    }
    report
}

/// Extract the value of `attr="..."` from a block. Returns unescaped
/// text (reverses the `&amp;` / `&lt;` / etc. encoding used by
/// `report::xml_escape`).
fn extract_attr(block: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=\"");
    let start = block.find(&key)? + key.len();
    let rest = &block[start..];
    let end = rest.find('"')?;
    Some(xml_unescape(&rest[..end]))
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Pull every `<property name="..." value="..."/>` entry out of the
/// testsuite's `<properties>` block. Preserves emission order so the
/// combined report renders context entries the way each backend wrote
/// them. Returns an empty vector when the block is absent or empty.
fn parse_properties(xml: &str) -> Vec<(String, String)> {
    let Some(open) = xml.find("<properties>") else {
        return Vec::new();
    };
    let Some(close_rel) = xml[open..].find("</properties>") else {
        return Vec::new();
    };
    let block = &xml[open..open + close_rel];

    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(prop_start) = block[cursor..].find("<property ") {
        let abs = cursor + prop_start;
        let slice = &block[abs..];
        // Accept both self-closing `<property .../>` and the paired form.
        let end = slice.find("/>").or_else(|| slice.find('>'));
        let Some(end) = end else {
            break;
        };
        let head = &slice[..end];
        let name = extract_attr(head, "name");
        let value = extract_attr(head, "value");
        if let (Some(n), Some(v)) = (name, value) {
            out.push((n, v));
        }
        cursor = abs + end + 1;
    }
    out
}

/// Pull the divergence id out of a `DOCUMENTED DIVERGENCE <id>: ...`
/// system-out payload. Returns `None` if the block isn't a documented
/// divergence.
fn extract_known_divergence(block: &str) -> Option<String> {
    let anchor = block.find("DOCUMENTED DIVERGENCE ")? + "DOCUMENTED DIVERGENCE ".len();
    let rest = &block[anchor..];
    let end = rest.find(':').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

/// Load `differential-report-<backend>.xml` from `dir`. Returns
/// `None` if the file is absent -- caller treats as "backend didn't
/// run in this matrix".
fn try_load_backend(dir: &Path, backend: BackendId) -> Option<BackendReport> {
    let path = dir.join(format!("differential-report-{backend}.xml"));
    let xml = fs::read_to_string(&path).ok()?;
    Some(parse_junit(&xml))
}

/// Row-level aggregate status. Single source of truth combining the
/// per-backend `Status` cells for a test case into one verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowStatus {
    /// At least one backend in [`BACKENDS`] did not report this case.
    Missing,
    /// Every reporting backend returned `Match` -- simrs agrees with
    /// all of them.
    Pass,
    /// Every divergence in this row is cataloged (no `Regression`
    /// cells). simrs does not match all references, but the
    /// disagreements are documented.
    Known,
    /// At least one backend marked the row as a regression.
    Fail,
}

impl RowStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Missing => "-",
            Self::Pass => "PASS",
            Self::Known => "KNOWN",
            Self::Fail => "FAIL",
        }
    }

    /// `agree` column rendering. `Pass` is the only "yes"; everything
    /// else means simrs did not match every reference (or the row
    /// wasn't fully reported).
    const fn agree_label(self) -> &'static str {
        match self {
            Self::Missing => "-",
            Self::Pass => "yes",
            Self::Known | Self::Fail => "no",
        }
    }
}

/// Per-row bookkeeping emitted by [`render_row`]. Split out from
/// `to_markdown` so that function stays under clippy's
/// `too_many_lines` threshold and the row-rendering logic can be
/// unit-tested in isolation if needed.
struct RowStats {
    /// The cell values in column order (backends in `BACKENDS` order).
    cells: Vec<String>,
    /// SW that simrs returned for this case, picked from the first
    /// backend that reported it (deterministic simrs output implies
    /// every backend sees the same value).
    simrs_sw: String,
    /// Row-level PASS / KNOWN / FAIL / Missing aggregate.
    status: RowStatus,
}

fn render_row(reports: &BTreeMap<BackendId, BackendReport>, name: &str) -> RowStats {
    let simrs_sw = BACKENDS
        .iter()
        .find_map(|b| reports.get(b).and_then(|r| r.cases.get(name)))
        .map_or_else(|| "----".to_string(), |row| row.simrs_sw.clone());

    let mut simrs_agrees_everywhere = true;
    let mut present_in_all = true;
    let mut has_regression = false;
    let mut cells = Vec::new();
    for backend in BACKENDS {
        let cell = reports
            .get(backend)
            .and_then(|r| r.cases.get(name))
            .map_or_else(
                || {
                    present_in_all = false;
                    "-".to_string()
                },
                |row| match &row.status {
                    Status::Match => format!("{} PASS", row.reference_sw),
                    Status::Known(id) => {
                        simrs_agrees_everywhere = false;
                        // Link to the catalog entry's source line
                        // (repo-root-relative) so reviewers can read
                        // the justification in place.
                        let line = known_divergences::lookup_by_id(id).map_or(0, |d| d.line);
                        format!(
                            "{sw} [KNOWN ({id})]({path}#L{line})",
                            sw = row.reference_sw,
                            path = CATALOG_PATH,
                        )
                    }
                    Status::Regression => {
                        simrs_agrees_everywhere = false;
                        has_regression = true;
                        format!(
                            "{sw} [FAIL](./differential-report-{backend}.md#divergences)",
                            sw = row.reference_sw
                        )
                    }
                },
            );
        cells.push(cell);
    }
    let status = if !present_in_all {
        RowStatus::Missing
    } else if has_regression {
        RowStatus::Fail
    } else if simrs_agrees_everywhere {
        RowStatus::Pass
    } else {
        RowStatus::Known
    };
    RowStats {
        cells,
        simrs_sw,
        status,
    }
}

/// Build a Markdown table combining every backend's status per case.
///
/// Column order:
/// `# | status | Test | simrs | <backends in lex order> | agree`.
/// `status` is the row-level PASS/KNOWN/FAIL aggregate in the first
/// non-index slot so at-a-glance scans land on regressions first.
/// `agree` (yes/no) trails at the right edge where it has always
/// been; it duplicates some information from `status` but remains a
/// one-cell fast check of "did simrs match every reference in this
/// run". The `simrs` column shows the SW simrs returned, taken from
/// the first available per-backend report (simrs is deterministic so
/// all backends agree on that value). Each backend column shows
/// that backend's SW plus a PASS/FAIL/KNOWN tag.
fn to_markdown(reports: &BTreeMap<BackendId, BackendReport>) -> String {
    use std::fmt::Write as _;
    let mut md = String::new();
    md.push_str("# Differential Test Report (combined)\n\n");

    // Per-backend links so readers can drill into a specific backend's
    // full report from the combined view. Only emit links for backends
    // that actually produced a report this run.
    md.push_str("Per-backend reports:\n");
    let mut any_linked = false;
    for backend in BACKENDS {
        if reports.contains_key(backend) {
            any_linked = true;
            let _ = writeln!(
                md,
                "- **{backend}**: [Markdown](./differential-report-{backend}.md) \
                 | [JUnit XML](./differential-report-{backend}.xml)"
            );
        } else {
            let _ = writeln!(md, "- **{backend}**: _(no report this run)_");
        }
    }
    if !any_linked {
        md.push_str("- _(no per-backend reports available)_\n");
    }
    md.push('\n');

    // Per-backend environment sections: each backend records how it
    // was set up in its own JUnit `<properties>` block; surface those
    // here so the reviewer doesn't need to open three files to answer
    // "what keys was jcsl configured with?" etc.
    let any_context = reports.values().any(|r| !r.context.is_empty());
    if any_context {
        md.push_str("## Environment\n\n");
        for backend in BACKENDS {
            if let Some(rep) = reports.get(backend) {
                if rep.context.is_empty() {
                    continue;
                }
                let _ = writeln!(md, "### {backend}\n");
                for (k, v) in &rep.context {
                    let _ = writeln!(md, "- **{k}:** {v}");
                }
                md.push('\n');
            }
        }
    }

    // Header row -- status in the first non-index slot so scans land
    // on regressions first; simrs first in the SW group; backends
    // follow in lex (BackendId Ord) order; agree trails at the right.
    let mut header = String::from("| # | status | Test | simrs |");
    let mut separator = String::from("|---|--------|------|-------|");
    for backend in BACKENDS {
        let _ = write!(header, " {backend} |");
        separator.push_str("-----------|");
    }
    header.push_str(" agree |");
    separator.push_str("-------|");
    let _ = writeln!(md, "{header}\n{separator}");

    // Gather the union of case names so we include any that appear in
    // only one backend's report.
    let mut case_names: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for backend in BACKENDS {
        if let Some(rep) = reports.get(backend) {
            for name in rep.cases.keys() {
                if seen.insert(name.clone()) {
                    case_names.push(name.clone());
                }
            }
        }
    }

    let mut match_all = 0usize;
    let mut any_missing = 0usize;
    let mut any_regression = 0usize;
    for (i, name) in case_names.iter().enumerate() {
        let row_stats = render_row(reports, name);
        match row_stats.status {
            RowStatus::Pass => match_all += 1,
            RowStatus::Missing => any_missing += 1,
            RowStatus::Fail => any_regression += 1,
            RowStatus::Known => {}
        }
        let _ = write!(
            md,
            "| {} | {} | {} | {} |",
            i + 1,
            row_stats.status.label(),
            name,
            row_stats.simrs_sw
        );
        for cell in &row_stats.cells {
            let _ = write!(md, " {cell} |");
        }
        let _ = writeln!(md, " {} |", row_stats.status.agree_label());
    }

    let _ = writeln!(md);
    let _ = writeln!(md, "## Summary\n");
    let _ = writeln!(
        md,
        "- Cases where simrs matches every available reference: **{match_all}**/{total}",
        total = case_names.len()
    );
    let _ = writeln!(
        md,
        "- Rows containing at least one regression (FAIL): **{any_regression}**"
    );
    let _ = writeln!(
        md,
        "- Rows missing data from one or more backends (cell `-`): **{any_missing}**"
    );
    md
}

/// Build a synthesized consensus testsuite plus the union XML. Does
/// not re-emit the per-backend cases verbatim; downstream consumers
/// still have the individual files to drill into. Keeps the combined
/// XML small enough to inspect at a glance.
fn to_junit_xml(reports: &BTreeMap<BackendId, BackendReport>) -> String {
    use std::fmt::Write as _;
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<testsuites>\n");

    // One consensus testcase per case name -- fails when any backend
    // marked it a regression, skipped when at least one backend didn't
    // report it, passes otherwise.
    let mut case_names: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for backend in BACKENDS {
        if let Some(rep) = reports.get(backend) {
            for name in rep.cases.keys() {
                if seen.insert(name.clone()) {
                    case_names.push(name.clone());
                }
            }
        }
    }
    let total = case_names.len();
    let mut failures = 0usize;
    let mut skipped = 0usize;
    let mut rows: Vec<String> = Vec::new();
    for name in &case_names {
        let mut present_in_all = true;
        let mut regression = false;
        let mut details = Vec::new();
        for backend in BACKENDS {
            if let Some(row) = reports.get(backend).and_then(|r| r.cases.get(name)) {
                details.push(format!("{backend}={}", row.status.symbol()));
                if matches!(row.status, Status::Regression) {
                    regression = true;
                }
            } else {
                present_in_all = false;
                details.push(format!("{backend}=-"));
            }
        }
        let detail_line = details.join(" ");
        let name_esc = xml_escape(name);
        let detail_esc = xml_escape(&detail_line);
        if regression {
            failures += 1;
            rows.push(format!(
                "  <testcase name=\"{name_esc}\" classname=\"consensus\">\n    <failure message=\"simrs disagrees with at least one backend\">{detail_esc}</failure>\n  </testcase>\n"
            ));
        } else if !present_in_all {
            skipped += 1;
            rows.push(format!(
                "  <testcase name=\"{name_esc}\" classname=\"consensus\">\n    <skipped message=\"at least one backend did not report this case\"/>\n    <system-out>{detail_esc}</system-out>\n  </testcase>\n"
            ));
        } else {
            rows.push(format!(
                "  <testcase name=\"{name_esc}\" classname=\"consensus\">\n    <system-out>{detail_esc}</system-out>\n  </testcase>\n"
            ));
        }
    }
    let _ = writeln!(
        xml,
        "  <testsuite name=\"consensus\" tests=\"{total}\" failures=\"{failures}\" skipped=\"{skipped}\">"
    );
    for row in rows {
        xml.push_str(&row);
    }
    xml.push_str("  </testsuite>\n");
    xml.push_str("</testsuites>\n");
    xml
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[test]
fn combine_per_backend_reports() {
    let dir = default_report_dir();
    let mut reports: BTreeMap<BackendId, BackendReport> = BTreeMap::new();
    for backend in BACKENDS {
        match try_load_backend(&dir, *backend) {
            Some(r) => {
                eprintln!(
                    "loaded {} backend report ({} cases)",
                    backend,
                    r.cases.len()
                );
                reports.insert(*backend, r);
            }
            None => {
                eprintln!(
                    "no {backend} report at {}/differential-report-{backend}.xml -- continuing",
                    dir.display()
                );
            }
        }
    }

    if reports.is_empty() {
        eprintln!(
            "no per-backend reports found in {}; skipping combine",
            dir.display()
        );
        return;
    }

    let md = to_markdown(&reports);
    let xml = to_junit_xml(&reports);

    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir -p {dir:?}: {e}"));
    let md_path = dir.join("differential-report-combined.md");
    let xml_path = dir.join("differential-report-combined.xml");
    fs::write(&md_path, &md).unwrap_or_else(|e| panic!("write {md_path:?}: {e}"));
    fs::write(&xml_path, &xml).unwrap_or_else(|e| panic!("write {xml_path:?}: {e}"));
    eprintln!("wrote {}", md_path.display());
    eprintln!("wrote {}", xml_path.display());
    eprintln!("\n{md}");
}

// ---------------------------------------------------------------------------
// Parser unit tests -- exercise the JUnit subset we care about without
// needing the bridge or jcsl binary.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parse_match_case() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites><testsuite name="x" tests="1" failures="0">
<testcase name="SELECT ISD" classname="differential-jcsl" time="0.001" simrs-sw="9000" reference-sw="9000">
  <system-out>SW match: 9000</system-out>
</testcase></testsuite></testsuites>"#;
        let rep = parse_junit(xml);
        assert_eq!(rep.cases.len(), 1);
        let row = rep.cases.get("SELECT ISD").expect("case present");
        assert_eq!(row.status, Status::Match);
        assert_eq!(row.simrs_sw, "9000");
        assert_eq!(row.reference_sw, "9000");
    }

    #[test]
    fn parse_known_divergence_case() {
        let xml = r#"<testcase name="EXT AUTH bad MAC" classname="differential-jcsl" time="0.001" simrs-sw="6988" reference-sw="6985">
  <system-out>DOCUMENTED DIVERGENCE D6: simrs=6988 reference=6985
Reason: something
Spec: GP 2.1.1 Table 9-9</system-out>
</testcase>"#;
        let rep = parse_junit(xml);
        let row = rep.cases.get("EXT AUTH bad MAC").expect("case present");
        assert_eq!(row.status, Status::Known("D6".to_string()));
        assert_eq!(row.simrs_sw, "6988");
        assert_eq!(row.reference_sw, "6985");
    }

    #[test]
    fn parse_failure_case() {
        let xml = r#"<testcase name="GET STATUS" classname="differential-jcsl" time="0.001" simrs-sw="6A88" reference-sw="6A82">
  <failure message="SW mismatch: simrs=6A88 reference=6A82">Command: ...</failure>
</testcase>"#;
        let rep = parse_junit(xml);
        let row = rep.cases.get("GET STATUS").expect("case present");
        assert_eq!(row.status, Status::Regression);
        assert_eq!(row.simrs_sw, "6A88");
    }

    #[test]
    fn parse_multiple_cases_preserves_order_unimportant() {
        let xml = r#"
<testcase name="A" classname="x" simrs-sw="9000" reference-sw="9000"><system-out>SW match: 9000</system-out></testcase>
<testcase name="B" classname="x" simrs-sw="6A00" reference-sw="9000"><failure message="m"/></testcase>
<testcase name="C" classname="x" simrs-sw="9000" reference-sw="9000"><system-out>SW match: 9000</system-out></testcase>
"#;
        let rep = parse_junit(xml);
        assert_eq!(rep.cases.len(), 3);
        assert_eq!(rep.cases.get("A").map(|r| &r.status), Some(&Status::Match));
        assert_eq!(
            rep.cases.get("B").map(|r| &r.status),
            Some(&Status::Regression)
        );
        assert_eq!(rep.cases.get("C").map(|r| &r.status), Some(&Status::Match));
    }

    #[test]
    fn parse_missing_sw_attrs_fallback_to_placeholder() {
        // Backward compat: reports emitted before we added the
        // simrs-sw/reference-sw attributes should still parse; missing
        // attrs become the literal "----" placeholder.
        let xml = r#"<testcase name="old" classname="x"><system-out>SW match: 9000</system-out></testcase>"#;
        let rep = parse_junit(xml);
        let row = rep.cases.get("old").expect("case present");
        assert_eq!(row.simrs_sw, "----");
        assert_eq!(row.reference_sw, "----");
    }

    #[test]
    fn xml_escape_roundtrip() {
        let original = "a & b < c > d \" e ' f";
        let escaped = xml_escape(original);
        let unescaped = xml_unescape(&escaped);
        assert_eq!(unescaped, original);
    }
}
