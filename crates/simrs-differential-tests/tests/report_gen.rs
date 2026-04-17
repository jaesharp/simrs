//! Differential report generator.
//!
//! Runs APDU comparisons through [`DualCard`] and produces structured
//! `JUnit` XML + Markdown reports. Skipped if the jcsl binary is not
//! available.
//!
//! # Running
//!
//! ```bash
//! cargo test -p simrs-differential-tests --test report_gen -- --nocapture
//! ```

use simrs_differential_tests::{
    known_divergences,
    report::{DiffReport, DiffTestCase, DivergenceCategory},
    select_aid, try_create_dual_card, DualResponse, ORACLE_ISD_AID, SIMRS_ISD_AID,
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

/// Classify a [`DualResponse`] into a [`DivergenceCategory`].
///
/// If both status words match, it is a `Match`. If they differ and a
/// known divergence catalog entry exists, it is a `KnownDivergence`.
/// Otherwise it is a `Regression`.
fn classify(dr: &DualResponse) -> DivergenceCategory {
    if dr.sw_match() {
        DivergenceCategory::Match
    } else if let Some(entry) = known_divergences::lookup(dr.simrs.sw16(), dr.oracle.sw16()) {
        DivergenceCategory::KnownDivergence { id: entry.id }
    } else {
        DivergenceCategory::Regression
    }
}

/// Build a [`DiffTestCase`] from a name, command, [`DualResponse`], and
/// elapsed time.
fn build_case(
    name: &str,
    command: &[u8],
    dr: &DualResponse,
    elapsed: std::time::Duration,
) -> DiffTestCase {
    let outcome = classify(dr);
    let mut simrs_response = dr.simrs.data.clone();
    simrs_response.extend_from_slice(&dr.simrs.sw);
    let mut oracle_response = dr.oracle.data.clone();
    oracle_response.extend_from_slice(&dr.oracle.sw);

    DiffTestCase {
        name: name.to_string(),
        command: command.to_vec(),
        simrs_response,
        oracle_response,
        simrs_sw: dr.simrs.sw16(),
        oracle_sw: dr.oracle.sw16(),
        outcome,
        duration_ms: duration_ms(elapsed),
    }
}

/// Named APDU descriptor for the test matrix.
struct ApduSpec {
    name: &'static str,
    apdu: Vec<u8>,
}

#[test]
fn generate_report() {
    let Some(mut dc) = try_create_dual_card("report-gen") else {
        eprintln!("jcsl binary not found, skipping report generation");
        return;
    };

    let mut report = DiffReport::new();

    // -- Power on (ATR comparison) ------------------------------------------

    let t0 = Instant::now();
    let (simrs_atr, oracle_atr) = dc.power_on();
    let atr_elapsed = t0.elapsed();

    // ATRs will always differ between the two implementations; treat as a
    // match if both are non-empty and start with a valid convention byte.
    let atr_ok = !simrs_atr.is_empty()
        && !oracle_atr.is_empty()
        && (simrs_atr[0] == 0x3B || simrs_atr[0] == 0x3F)
        && (oracle_atr[0] == 0x3B || oracle_atr[0] == 0x3F);

    report.add_case(DiffTestCase {
        name: "Power on (ATR)".to_string(),
        command: vec![],
        simrs_response: simrs_atr,
        oracle_response: oracle_atr,
        simrs_sw: if atr_ok { 0x9000 } else { 0x6F00 },
        oracle_sw: if atr_ok { 0x9000 } else { 0x6F00 },
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
            "{}: simrs={:04X} oracle={:04X} match={}",
            spec.name,
            dr.simrs.sw16(),
            dr.oracle.sw16(),
            dr.sw_match(),
        );

        report.add_case(build_case(spec.name, &spec.apdu, &dr, elapsed));
    }

    // -- Write reports ------------------------------------------------------

    let xml = report.to_junit_xml();
    fs::write("differential-report.xml", &xml).expect("failed to write JUnit XML report");
    eprintln!("Wrote differential-report.xml ({} bytes)", xml.len());

    let md = report.to_markdown();
    fs::write("differential-report.md", &md).expect("failed to write Markdown report");
    eprintln!("Wrote differential-report.md ({} bytes)", md.len());

    // -- Summary and regression check ---------------------------------------

    let summary = report.summary();
    eprintln!("\nDifferential report: {summary}");

    assert!(
        !report.has_regressions(),
        "Differential report contains regressions:\n{md}",
    );
}
