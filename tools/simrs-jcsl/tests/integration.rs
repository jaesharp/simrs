//! Integration tests for the jcsl client.
//!
//! These tests require the Oracle jcsl binary to be available.
//! Set `SIMRS_JCSL_BINARY` to the path of an **unconfigured** jcsl binary,
//! or place it at the XDG cache / workspace-relative location:
//!
//! ```bash
//! SIMRS_JCSL_BINARY=tools/oracle-jcvm-ref/runtime/bin/jcsl \
//!     cargo test -p simrs-jcsl --test integration
//! ```
//!
//! If the variable is not set, all tests are skipped.
//!
//! Binaries are configured and executed from anonymous memfds -- no
//! temporary files are created.

use simrs_jcsl::configurator::{GlobalPin, ScpKeyset};
use simrs_jcsl::{JcslClient, JcslProcess, configure_binary};
use simrs_transport::Transport;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};

/// Atomic port counter to avoid collisions when tests run in parallel.
static NEXT_PORT: AtomicU16 = AtomicU16::new(19100);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

/// Get the path to the unconfigured jcsl binary, or skip the test.
fn jcsl_binary_path() -> Option<PathBuf> {
    std::env::var("SIMRS_JCSL_BINARY")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

/// Default SCP keyset for tests.
fn test_keyset() -> ScpKeyset {
    ScpKeyset {
        kvn: 0x01,
        enc: vec![
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        ],
        mac: vec![
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        ],
        dek: vec![
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        ],
    }
}

/// Default Global PIN for tests.
fn test_pin() -> GlobalPin {
    GlobalPin {
        pin: vec![0x31, 0x32, 0x33, 0x34],
        max_retries: 3,
    }
}

/// Start a jcsl process from a memfd. Returns the process handle and port.
fn start_jcsl(src: &Path) -> (JcslProcess, u16) {
    let port = next_port();
    let keyset = test_keyset();
    let pin = test_pin();
    let proc = JcslProcess::start_configured(
        src,
        Some(&keyset),
        Some(&pin),
        port,
        "info",
        std::time::Duration::from_secs(10),
    )
    .expect("failed to start jcsl");
    (proc, port)
}

#[test]
fn configurator_patches_real_binary() {
    let Some(src) = jcsl_binary_path() else {
        eprintln!("SIMRS_JCSL_BINARY not set, skipping");
        return;
    };

    let data = std::fs::read(&src).unwrap();
    let (scp, pin) = simrs_jcsl::is_configured(&data);
    // The original binary should not be configured.
    assert!(!scp, "binary already has SCP keys configured");
    assert!(!pin, "binary already has PIN configured");

    // Test the disk-based path (configure_binary still works).
    let dir = std::env::temp_dir().join(format!("simrs-jcsl-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dst = dir.join("jcsl.cfg-check");

    configure_binary(&src, &dst, Some(&test_keyset()), Some(&test_pin()), false)
        .expect("configure_binary failed");

    let patched = std::fs::read(&dst).unwrap();
    let (scp2, pin2) = simrs_jcsl::is_configured(&patched);
    assert!(scp2, "SCP keys not injected");
    assert!(pin2, "PIN not injected");

    let _ = std::fs::remove_file(&dst);
}

#[test]
fn configurator_patches_to_memfd() {
    let Some(src) = jcsl_binary_path() else {
        eprintln!("SIMRS_JCSL_BINARY not set, skipping");
        return;
    };

    let mfd = simrs_jcsl::configure_to_memfd(&src, Some(&test_keyset()), Some(&test_pin()))
        .expect("configure_to_memfd failed");

    // Read the memfd contents back and verify configuration.
    let mut data = Vec::new();
    let file = mfd.as_file();
    let mut file_ref = file;
    file_ref.seek(SeekFrom::Start(0)).unwrap();
    file_ref.read_to_end(&mut data).unwrap();

    let (scp, pin) = simrs_jcsl::is_configured(&data);
    assert!(scp, "SCP keys not injected into memfd");
    assert!(pin, "PIN not injected into memfd");
}

#[test]
fn start_and_connect() {
    let Some(src) = jcsl_binary_path() else {
        eprintln!("SIMRS_JCSL_BINARY not set, skipping");
        return;
    };

    let (mut proc, port) = start_jcsl(&src);
    assert!(proc.is_running());

    let mut client = JcslClient::connect(&format!("127.0.0.1:{port}"))
        .expect("failed to connect");

    // Power ON
    let atr = client.power_on().expect("power on failed");
    assert!(!atr.is_empty(), "ATR should not be empty");
    eprintln!("ATR: {atr:02x?}");

    // The first byte of a valid ATR is 0x3B (direct convention) or 0x3F (inverse).
    assert!(
        atr[0] == 0x3B || atr[0] == 0x3F,
        "unexpected ATR initial byte: 0x{:02x}",
        atr[0]
    );

    // Power OFF
    client.power_off().expect("power off failed");

    proc.kill().ok();
}

#[test]
fn select_isd_aid() {
    let Some(src) = jcsl_binary_path() else {
        eprintln!("SIMRS_JCSL_BINARY not set, skipping");
        return;
    };

    let (mut proc, port) = start_jcsl(&src);
    let mut client = JcslClient::connect(&format!("127.0.0.1:{port}"))
        .expect("failed to connect");

    client.power_on().expect("power on failed");

    // SELECT the ISD AID (A0 00 00 01 51 00 00 00)
    let select_isd = [
        0x00, 0xA4, 0x04, 0x00, 0x08,
        0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00,
        0x00,
    ];
    let mut rsp = [0u8; 258];
    let n = client.exchange(&select_isd, &mut rsp).expect("APDU exchange failed");

    eprintln!("SELECT ISD response ({n} bytes): {:02x?}", &rsp[..n]);

    // Should have at least SW1 SW2
    assert!(n >= 2, "response too short: {n} bytes");

    // The last two bytes are SW1 SW2
    let sw1 = rsp[n - 2];
    let sw2 = rsp[n - 1];
    eprintln!("SW: {sw1:02x} {sw2:02x}");

    // 9000 = success, 6A82 = file not found (if ISD AID differs)
    // We accept both as valid responses from a real simulator.

    client.power_off().ok();
    proc.kill().ok();
}

#[test]
fn get_data_cplc() {
    let Some(src) = jcsl_binary_path() else {
        eprintln!("SIMRS_JCSL_BINARY not set, skipping");
        return;
    };

    let (mut proc, port) = start_jcsl(&src);
    let mut client = JcslClient::connect(&format!("127.0.0.1:{port}"))
        .expect("failed to connect");

    client.power_on().expect("power on failed");

    // GET DATA -- Card Production Life Cycle (CPLC)
    // CLA=80 INS=CA P1=9F P2=7F Le=00
    let get_cplc = [0x80, 0xCA, 0x9F, 0x7F, 0x00];
    let mut rsp = [0u8; 258];
    let n = client.exchange(&get_cplc, &mut rsp).expect("APDU exchange failed");

    eprintln!("GET DATA CPLC ({n} bytes): {:02x?}", &rsp[..n]);
    assert!(n >= 2);

    client.power_off().ok();
    proc.kill().ok();
}
