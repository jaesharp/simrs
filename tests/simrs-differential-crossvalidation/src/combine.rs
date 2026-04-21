//! Parser for reading per-backend `JUnit` XML reports back into
//! structured form.
//!
//! Used both by the production combined-report renderer in
//! `tests/report_combine.rs` and by consistency tests that round-trip
//! a [`DiffReport`](crate::report::DiffReport) through its own XML
//! serializer and assert the resulting classification matches the
//! source.
//!
//! The parser is intentionally minimal: it handles the subset of
//! `JUnit` XML emitted by [`DiffReport::to_junit_xml`](crate::report::DiffReport::to_junit_xml),
//! not arbitrary `JUnit` output. Attributes use double quotes, every
//! `<testcase>` has exactly one of `<system-out>` or `<failure>`, and
//! the `<system-out>` body is short and plain text. Pulling in an XML
//! parser crate for these assumptions would be overkill.
//!
//! # Round-trip contract
//!
//! Every `DiffTestCase` emitted by `DiffReport::to_junit_xml(cfg)`
//! (where `cfg.include_*` allows it) parses back to a [`CaseRow`]
//! whose [`Status`] matches the case's original outcome. The
//! [`crate::report`] module's tests exercise this property for every
//! [`ReportConfig`](crate::report::ReportConfig) preset.

use std::collections::BTreeMap;

/// Classification of a case after parsing its rendered `JUnit` form.
///
/// Mirrors [`DivergenceCategory`](crate::report::DivergenceCategory)
/// but keyed off the rendered XML shape (`<failure>` → Regression,
/// `<system-out>DOCUMENTED DIVERGENCE <id>` → Known, otherwise Match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// `<system-out>SW match: NNNN</system-out>` or equivalent.
    Match,
    /// `<system-out>DOCUMENTED DIVERGENCE <id>...` — catalog entry
    /// applies; divergence expected.
    Known(String),
    /// `<failure ...>` element present — uncataloged regression.
    Regression,
}

impl Status {
    /// Short status label used in combined-report tables.
    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Match => "PASS",
            Self::Known(_) => "KNOWN",
            Self::Regression => "FAIL",
        }
    }
}

/// One parsed `<testcase>`, with both raw SWs and the outcome bucket.
#[derive(Debug, Clone)]
pub struct CaseRow {
    /// simrs status word as hex text ("9000", "6A82", etc.).
    pub simrs_sw: String,
    /// Reference-backend status word as hex text.
    pub reference_sw: String,
    /// Outcome classification derived from the XML structure.
    pub status: Status,
}

/// All cases extracted from one backend's `JUnit` XML, plus the
/// environment/context properties emitted by the backend.
#[derive(Debug, Default)]
pub struct BackendReport {
    /// Map of case name → row. `BTreeMap` so iteration is
    /// deterministic across runs.
    pub cases: BTreeMap<String, CaseRow>,
    /// Ordered environment entries extracted from the `<properties>`
    /// block inside the testsuite, preserving emission order.
    pub context: Vec<(String, String)>,
}

/// Parse one backend's `JUnit` XML into a [`BackendReport`].
///
/// Recognises the exact shape emitted by
/// [`DiffReport::to_junit_xml`](crate::report::DiffReport::to_junit_xml);
/// foreign `JUnit` XML may parse with degraded fidelity (missing
/// known-divergence IDs, missing SW attributes). Unknown elements are
/// tolerated.
#[must_use]
pub fn parse_junit(xml: &str) -> BackendReport {
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

        let Some(name) = extract_attr(block, "name") else {
            cursor = end;
            continue;
        };
        let simrs_sw = extract_attr(block, "simrs-sw").unwrap_or_else(|| "----".to_string());
        let reference_sw =
            extract_attr(block, "reference-sw").unwrap_or_else(|| "----".to_string());

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

/// Extract the value of `attr="..."` from a block.
///
/// Returns the unescaped text (reverses the `&amp;` / `&lt;` / etc.
/// encoding used by `report::xml_escape`).
#[must_use]
pub fn extract_attr(block: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=\"");
    let start = block.find(&key)? + key.len();
    let rest = &block[start..];
    let end = rest.find('"')?;
    Some(xml_unescape(&rest[..end]))
}

/// Reverse the escape transform applied by the `JUnit` emitter.
#[must_use]
pub fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Extract the environment/context properties from a testsuite XML.
///
/// Pulls every `<property name="..." value="..."/>` entry out of the
/// `<properties>` block. Preserves emission order so the combined
/// report renders context entries the way each backend wrote them.
/// Returns an empty vector when the block is absent or empty.
#[must_use]
pub fn parse_properties(xml: &str) -> Vec<(String, String)> {
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
        let Some(end_rel) = block[abs..].find("/>") else {
            break;
        };
        let prop = &block[abs..abs + end_rel];
        if let (Some(k), Some(v)) = (extract_attr(prop, "name"), extract_attr(prop, "value")) {
            out.push((k, v));
        }
        cursor = abs + end_rel + 2;
    }
    out
}

/// Extract the known-divergence id from a `<testcase>`'s body.
///
/// Recognises the `DOCUMENTED DIVERGENCE <id>` tag the emitter writes
/// at the start of `<system-out>` for cataloged divergences. Returns
/// `None` when the block has no such marker.
#[must_use]
pub fn extract_known_divergence(block: &str) -> Option<String> {
    let marker = "DOCUMENTED DIVERGENCE ";
    let start = block.find(marker)? + marker.len();
    let rest = &block[start..];
    let end = rest.find(|c: char| c.is_whitespace() || c == ':' || c == '<')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_xml_is_empty_report() {
        let r = parse_junit("");
        assert!(r.cases.is_empty());
        assert!(r.context.is_empty());
    }

    #[test]
    fn parse_single_testcase_match() {
        let xml = r#"
            <testcase name="SELECT ISD" simrs-sw="9000" reference-sw="9000">
              <system-out>SW match: 9000</system-out>
            </testcase>
        "#;
        let r = parse_junit(xml);
        assert_eq!(r.cases.len(), 1);
        let row = &r.cases["SELECT ISD"];
        assert_eq!(row.simrs_sw, "9000");
        assert_eq!(row.reference_sw, "9000");
        assert_eq!(row.status, Status::Match);
    }

    #[test]
    fn parse_single_testcase_regression() {
        let xml = r#"
            <testcase name="Unexpected SW" simrs-sw="9000" reference-sw="6D00">
              <failure message="regression">simrs=9000 reference=6D00</failure>
            </testcase>
        "#;
        let r = parse_junit(xml);
        assert_eq!(r.cases["Unexpected SW"].status, Status::Regression);
    }

    #[test]
    fn parse_single_testcase_known_divergence() {
        let xml = r#"
            <testcase name="EXTERNAL AUTHENTICATE bad MAC" simrs-sw="6988" reference-sw="6985">
              <system-out>DOCUMENTED DIVERGENCE D6: padding oracle defense</system-out>
            </testcase>
        "#;
        let r = parse_junit(xml);
        assert_eq!(
            r.cases["EXTERNAL AUTHENTICATE bad MAC"].status,
            Status::Known("D6".to_string())
        );
    }

    #[test]
    fn parse_properties_preserves_order() {
        let xml = r#"
          <properties>
            <property name="backend" value="jcsl"/>
            <property name="applet.aid" value="A000000151000000"/>
          </properties>
        "#;
        let ctx = parse_properties(xml);
        assert_eq!(
            ctx,
            vec![
                ("backend".to_string(), "jcsl".to_string()),
                ("applet.aid".to_string(), "A000000151000000".to_string()),
            ]
        );
    }

    #[test]
    fn xml_unescape_reverses_escape_policy() {
        assert_eq!(
            xml_unescape("a &amp; b &lt; c &gt; d &quot; e &apos; f"),
            "a & b < c > d \" e ' f"
        );
    }
}
