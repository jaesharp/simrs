//! Differential report generator.
//!
//! Runs APDU comparisons through [`DualCard`] and produces structured
//! `JUnit` XML + Markdown reports. Backend is selected at run-time by
//! the `SIMRS_DIFF_BACKEND` env var (defaults to `"jcsl"`). Skipped if
//! the chosen backend isn't discoverable (no jcsl binary, no
//! jcardengine bridge JAR, etc.).
//!
//! # Running
//!
//! ```bash
//! # Against Oracle jcsl (default)
//! cargo test -p simrs-differential-crossvalidation --test report_gen -- --nocapture
//!
//! # Against martinpaljak/JCardEngine
//! SIMRS_DIFF_BACKEND=jcardengine \
//!   cargo test -p simrs-differential-crossvalidation --test report_gen -- --nocapture
//! ```
//!
//! Output files are named `differential-report-<backend>.{xml,md}`.

use simrs_differential_crossvalidation::{
    BackendId, DualCard, DualResponse, ORACLE_ISD_AID, ReferenceBackend, SIMRS_ISD_AID,
    default_report_dir, known_divergences,
    report::{DiffReport, DiffTestCase, DivergenceCategory},
    select_aid, select_backend, try_create_dual_card_jcardengine, try_create_dual_card_jcsl,
};
use std::fs;
use std::time::Instant;

/// Convert a [`Duration`](std::time::Duration) to milliseconds as `u64`.
///
/// Truncation from `u128` is harmless -- individual APDU round-trips are
/// well under 2^64 milliseconds.
#[allow(clippy::cast_possible_truncation)]
const fn duration_ms(d: std::time::Duration) -> u64 {
    d.as_millis() as u64
}

/// Classify a [`DualResponse`] into a [`DivergenceCategory`] for the
/// given backend.
///
/// If both status words match, it is a `Match`. If they differ and a
/// known divergence catalog entry applies to this backend, it is a
/// `KnownDivergence`. Otherwise it is a `Regression`.
fn classify(dr: &DualResponse, backend: BackendId) -> DivergenceCategory {
    if dr.sw_match() {
        DivergenceCategory::Match
    } else if let Some(entry) =
        known_divergences::lookup_for_backend(dr.simrs.sw16(), dr.reference.sw16(), backend)
    {
        DivergenceCategory::KnownDivergence { id: entry.id }
    } else {
        DivergenceCategory::Regression
    }
}

/// Build a [`DiffTestCase`] from a name, command, [`DualResponse`], and
/// elapsed time. Classification is backend-aware so JCardEngine-only
/// catalog entries don't accidentally mask jcsl regressions.
fn build_case(
    name: &str,
    command: &[u8],
    dr: &DualResponse,
    elapsed: std::time::Duration,
    backend: BackendId,
) -> DiffTestCase {
    let outcome = classify(dr, backend);
    let mut simrs_response = dr.simrs.data.clone();
    simrs_response.extend_from_slice(&dr.simrs.sw);
    let mut reference_response = dr.reference.data.clone();
    reference_response.extend_from_slice(&dr.reference.sw);

    DiffTestCase {
        name: name.to_string(),
        command: command.to_vec(),
        simrs_response,
        reference_response,
        simrs_sw: dr.simrs.sw16(),
        reference_sw: dr.reference.sw16(),
        outcome,
        duration_ms: duration_ms(elapsed),
    }
}

/// Named APDU descriptor for the test matrix.
struct ApduSpec {
    name: &'static str,
    apdu: Vec<u8>,
}

/// Core driver: runs the APDU matrix against whatever [`ReferenceBackend`]
/// the caller has provided, returns the populated report. `context`
/// captures the backend's setup (binary/jar paths, keys, applet
/// class/AID) and is rendered into the report's "Environment" section.
fn run_matrix<B: ReferenceBackend>(
    mut dc: DualCard<B>,
    backend: BackendId,
    context: Vec<(String, String)>,
) -> DiffReport {
    let mut report = DiffReport::new_for_backend(backend.as_str());
    for (k, v) in context {
        report.add_context(&k, &v);
    }

    // -- Power on (ATR comparison) ------------------------------------------

    let t0 = Instant::now();
    let (simrs_atr, reference_atr) = dc.power_on();
    let atr_elapsed = t0.elapsed();

    // ATRs will always differ between the two implementations; treat as a
    // match if both are non-empty and start with a valid convention byte.
    // JCardEngine's default ATR is empty -- accept that as "power_on
    // round-tripped" and rely on subsequent APDUs to detect breakage.
    let atr_ok = if reference_atr.is_empty() {
        !simrs_atr.is_empty() && (simrs_atr[0] == 0x3B || simrs_atr[0] == 0x3F)
    } else {
        !simrs_atr.is_empty()
            && (simrs_atr[0] == 0x3B || simrs_atr[0] == 0x3F)
            && (reference_atr[0] == 0x3B || reference_atr[0] == 0x3F)
    };

    report.add_case(DiffTestCase {
        name: "Power on (ATR)".to_string(),
        command: vec![],
        simrs_response: simrs_atr,
        reference_response: reference_atr,
        simrs_sw: if atr_ok { 0x9000 } else { 0x6F00 },
        reference_sw: if atr_ok { 0x9000 } else { 0x6F00 },
        outcome: if atr_ok {
            DivergenceCategory::Match
        } else {
            DivergenceCategory::Regression
        },
        duration_ms: duration_ms(atr_elapsed),
    });

    // -- APDU matrix --------------------------------------------------------

    let specs: Vec<ApduSpec> = vec![
        ApduSpec {
            name: "SELECT simrs ISD AID",
            apdu: select_aid(&SIMRS_ISD_AID),
        },
        ApduSpec {
            name: "SELECT Oracle ISD AID",
            apdu: select_aid(&ORACLE_ISD_AID),
        },
        ApduSpec {
            name: "SELECT unknown AID",
            apdu: select_aid(&[0xFF, 0xEE, 0xDD, 0xCC, 0xBB]),
        },
        ApduSpec {
            name: "GET DATA card recognition (0066)",
            apdu: vec![0x80, 0xCA, 0x00, 0x66],
        },
        ApduSpec {
            name: "GET DATA CPLC (9F7F)",
            apdu: vec![0x80, 0xCA, 0x9F, 0x7F, 0x00],
        },
        ApduSpec {
            name: "GET DATA unknown tag (DEAD)",
            apdu: vec![0x80, 0xCA, 0xDE, 0xAD],
        },
        ApduSpec {
            name: "Invalid GP INS (80 FD)",
            apdu: vec![0x80, 0xFD, 0x00, 0x00],
        },
        ApduSpec {
            name: "Invalid ISO INS (00 FD)",
            apdu: vec![0x00, 0xFD, 0x00, 0x00],
        },
    ];

    for spec in &specs {
        let t = Instant::now();
        let dr = dc.exchange(&spec.apdu);
        let elapsed = t.elapsed();

        eprintln!(
            "{}: simrs={:04X} {}={:04X} match={}",
            spec.name,
            dr.simrs.sw16(),
            backend,
            dr.reference.sw16(),
            dr.sw_match(),
        );

        report.add_case(build_case(spec.name, &spec.apdu, &dr, elapsed, backend));
    }

    report
}

#[test]
fn generate_report() {
    let backend = select_backend();
    let dir = default_report_dir();
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir -p {dir:?}: {e}"));
    let xml_path = dir.join(format!("differential-report-{backend}.xml"));
    let md_path = dir.join(format!("differential-report-{backend}.md"));

    let report = match backend {
        BackendId::Jcsl => {
            let Some(dc) = try_create_dual_card_jcsl("report-gen") else {
                eprintln!("jcsl binary not found, skipping report generation");
                return;
            };
            let context = dc.reference.context_entries();
            run_matrix(dc, backend, context)
        }
        BackendId::Jcardengine => {
            let Some(dc) = try_create_dual_card_jcardengine("report-gen") else {
                eprintln!(
                    "jcardengine bridge not discovered, skipping report generation. \
                     Build with: gradle --project-dir tools/jcardengine-bridge build"
                );
                return;
            };
            let context = dc.reference.context_entries();
            run_matrix(dc, backend, context)
        }
    };

    // -- Write reports ------------------------------------------------------

    let xml = report.to_junit_xml();
    fs::write(&xml_path, &xml).unwrap_or_else(|e| panic!("failed to write {xml_path:?}: {e}"));
    eprintln!("Wrote {} ({} bytes)", xml_path.display(), xml.len());

    let md = report.to_markdown();
    fs::write(&md_path, &md).unwrap_or_else(|e| panic!("failed to write {md_path:?}: {e}"));
    eprintln!("Wrote {} ({} bytes)", md_path.display(), md.len());

    // -- Summary and regression check ---------------------------------------

    let summary = report.summary();
    eprintln!("\nDifferential report ({backend}): {summary}");

    // Regression-fatal applies to both backends now that
    // JCardEngine's narrower GP applet surface is cataloged under J1
    // (GET DATA tag absent), J2 (GET DATA unknown-tag collapses to
    // 6D00), and J3 (SELECT unknown-AID collapses to 6D00). A new
    // divergence between simrs and either reference is therefore a
    // genuine regression requiring catalog extension or code fix.
    assert!(
        !report.has_regressions(),
        "Differential report ({backend}) contains regressions:\n{md}",
    );
}
