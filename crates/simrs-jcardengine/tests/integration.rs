//! Integration smoke tests for the `JCardEngine` bridge.
//!
//! Gated on [`discover_bridge`] finding a bridge + engine JAR pair.
//! When absent (CI without the Gradle build run, for example) each
//! test prints a note and returns cleanly. When the bridge is
//! available the tests exercise both the happy path and failure modes
//! that upstream exceptions would otherwise hide.
//!
//! # Coverage
//!
//! - [`smoke_spawn_connect_power_cycle`] -- happy path: spawn,
//!   connect, `power_on`, `power_off`.
//! - [`smoke_bad_applet_class_surfaces_stderr`] -- bridge JVM aborts
//!   when `Class.forName` fails; we surface the stack trace via
//!   [`stderr_tail`].
//! - [`smoke_bad_aid_hex_surfaces_stderr`] -- bridge JVM aborts when
//!   `AIDUtil.create` rejects the hex string.
//! - [`smoke_apdu_before_power_on_rejected`] -- client rejects
//!   [`Transport::exchange`] before [`power_on`], returning `IoError`
//!   (no packet goes over the wire).
//!
//! Enable locally:
//!
//! ```bash
//! gradle --project-dir tools/jcardengine-bridge build
//! cargo test -p simrs-jcardengine --test integration -- --nocapture
//! ```
//!
//! Or point at a prebuilt install:
//!
//! ```bash
//! export SIMRS_JCARDENGINE_BRIDGE=/path/to/bridge.jar
//! export SIMRS_JCARDENGINE_LIB=/path/to/jcardengine-26.04.06.jar
//! cargo test -p simrs-jcardengine --test integration -- --nocapture
//! ```
//!
//! [`stderr_tail`]: simrs_jcardengine::JcardengineProcess::stderr_tail
//! [`Transport::exchange`]: simrs_transport::Transport::exchange
//! [`power_on`]: simrs_jcardengine::JcardengineClient::power_on

use simrs_jcardengine::{
    BridgeInstallation, JcardengineClient, JcardengineConfig, JcardengineProcess, discover_bridge,
};
use simrs_transport::{Transport, TransportError};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// Port counter starting above jcsl (19100+) and the jcardsim-wip
/// range (19300+). Collisions are avoided by atomic fetch-add.
static NEXT_PORT: AtomicU16 = AtomicU16::new(19500);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

/// `JCardEngine` (unlike its jcardsim ancestor) ships no sample
/// applets, so the bridge JAR bundles its own minimal
/// `com.simrs.jcardengine.HelloWorldApplet` for smoke testing.
const SMOKE_APPLET_CLASS: &str = "com.simrs.jcardengine.HelloWorldApplet";
const SMOKE_APPLET_AID: &str = "F000000001";

/// Resolve a bridge installation or `None`. Printed-and-skip behaviour
/// is shared by every test so CI without the Gradle build still runs
/// cargo test cleanly.
fn discover_or_skip(test_name: &str) -> Option<BridgeInstallation> {
    let found = discover_bridge();
    if found.is_none() {
        eprintln!(
            "simrs-jcardengine bridge not discovered (neither \
             SIMRS_JCARDENGINE_BRIDGE/_LIB nor ~/.cache/simrs/jcardengine/ \
             nor workspace build output). Skipping {test_name}."
        );
    }
    found
}

/// Build a valid default config pointing at a pre-located installation.
fn smoke_config(installation: BridgeInstallation, port: u16) -> JcardengineConfig {
    let mut cfg = JcardengineConfig::new(installation);
    cfg.port = port;
    cfg.applet_class = SMOKE_APPLET_CLASS.into();
    cfg.applet_aid_hex = SMOKE_APPLET_AID.into();
    cfg.startup_timeout = Duration::from_secs(20);
    cfg
}

#[test]
fn smoke_spawn_connect_power_cycle() {
    let Some(installation) = discover_or_skip("smoke_spawn_connect_power_cycle") else {
        return;
    };

    let port = next_port();
    let config = smoke_config(installation, port);

    let process = match JcardengineProcess::start(&config) {
        Ok(p) => p,
        Err(e) => panic!("bridge must spawn + announce LISTENING: {e}"),
    };
    assert_eq!(process.port(), port);

    let mut client = JcardengineClient::connect(&process.address())
        .unwrap_or_else(|e| panic!("connect failed: {e}; stderr:\n{}", process.stderr_tail()));

    match client.power_on() {
        Ok(atr) => {
            // Accept an empty ATR (jcardsim/JCardEngine default may be
            // unset) -- the point of the smoke test is that power_on
            // round-trips over the framing protocol, not semantic
            // check of ATR content.
            eprintln!("power_on returned ATR: {atr:02x?} (len {})", atr.len());
        }
        Err(e) => panic!(
            "power_on failed: {e:?}; bridge stderr:\n{}",
            process.stderr_tail()
        ),
    }
    assert!(client.is_powered());

    client.power_off().unwrap_or_else(|e| {
        panic!(
            "power_off failed: {e:?}; stderr:\n{}",
            process.stderr_tail()
        )
    });
    assert!(!client.is_powered());

    // Process drops here -> JVM killed.
}

/// If the applet class doesn't exist, the bridge JVM aborts before
/// ever reaching `ServerSocket.bind`. The Rust launcher then times out
/// waiting for `LISTENING <port>`, kills the child, and surfaces the
/// drained stderr tail -- which must contain the Java stack trace.
#[test]
fn smoke_bad_applet_class_surfaces_stderr() {
    let Some(installation) = discover_or_skip("smoke_bad_applet_class_surfaces_stderr") else {
        return;
    };

    let mut config = smoke_config(installation, next_port());
    config.applet_class = "com.example.ThisClassDoesNotExist".into();
    // Shorten the deadline: we expect the JVM to crash in milliseconds
    // on ClassNotFoundException, so there is nothing useful to wait
    // for. A 5s cap keeps the test snappy if the bridge misbehaves.
    config.startup_timeout = Duration::from_secs(5);

    let Err(err) = JcardengineProcess::start(&config) else {
        panic!("start unexpectedly succeeded with a bogus applet class");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("ClassNotFoundException") || msg.contains("bridge stderr"),
        "expected bridge stderr tail to carry the Java exception, got: {msg}"
    );
}

/// `AIDUtil.create` throws on anything that isn't a valid hex AID.
/// Same failure path as the bad-applet-class test: JVM dies during
/// startup, stderr tail surfaces, no `LISTENING` line appears.
#[test]
fn smoke_bad_aid_hex_surfaces_stderr() {
    let Some(installation) = discover_or_skip("smoke_bad_aid_hex_surfaces_stderr") else {
        return;
    };

    let mut config = smoke_config(installation, next_port());
    config.applet_aid_hex = "NOT_VALID_HEX".into();
    config.startup_timeout = Duration::from_secs(5);

    let Err(err) = JcardengineProcess::start(&config) else {
        panic!("start unexpectedly succeeded with a bogus AID");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("bridge stderr") || msg.contains("IllegalArgumentException"),
        "expected bridge stderr tail to carry the AID parse error, got: {msg}"
    );
}

/// `Transport::exchange` must refuse to send a frame before `power_on`.
/// Client-side check only -- no bytes leave the socket until after
/// power is applied. Failure mode is `TransportError::IoError` to
/// match the convention used in [`simrs_jcsl::client`].
#[test]
fn smoke_apdu_before_power_on_rejected() {
    let Some(installation) = discover_or_skip("smoke_apdu_before_power_on_rejected") else {
        return;
    };

    let port = next_port();
    let config = smoke_config(installation, port);

    let process =
        JcardengineProcess::start(&config).unwrap_or_else(|e| panic!("bridge must spawn: {e}"));

    let mut client = JcardengineClient::connect(&process.address())
        .unwrap_or_else(|e| panic!("connect failed: {e}; stderr:\n{}", process.stderr_tail()));

    // Deliberately skip power_on. Issue a trivial APDU that would
    // otherwise round-trip (SELECT by AID -- valid APDU shape).
    let cmd = [0x00u8, 0xA4, 0x04, 0x00, 0x00];
    let mut rsp = [0u8; 256];
    let result = client.exchange(&cmd, &mut rsp);
    match result {
        Err(TransportError::IoError) => {}
        Ok(n) => panic!("exchange succeeded with {n} bytes -- expected IoError (not powered)"),
        Err(other) => panic!("expected IoError, got {other:?}"),
    }
    assert!(!client.is_powered());
}
