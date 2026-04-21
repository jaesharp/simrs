//! Integration smoke test for the jcardsim bridge.
//!
//! Mirrors [`simrs-jcsl`'s integration harness](../../../simrs-jcsl/tests/integration.rs):
//! the test only runs when a bridge + jcardsim JAR pair is discoverable,
//! and skips cleanly otherwise. This keeps CI green without a Java
//! toolchain installed while still exercising the full path
//! (discover -> spawn JVM -> TCP connect -> `power_on` -> `power_off`
//! -> drop) when the environment is ready.
//!
//! To enable locally:
//!
//! ```bash
//! # Build the bridge + pull jcardsim:
//! ./gradlew --project-dir tools/jcardsim-bridge build
//!
//! # Or point at an already-built copy:
//! export SIMRS_JCARDSIM_BRIDGE=/path/to/bridge.jar
//! export SIMRS_JCARDSIM_LIB=/path/to/jcardsim-3.0.5.jar
//!
//! cargo test -p simrs-jcardsim --test integration -- --nocapture
//! ```

use simrs_jcardsim::{JcardsimClient, JcardsimConfig, JcardsimProcess, discover_bridge};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// Port counter. Starts above jcsl's 19100 range to avoid collisions
/// when both suites run in parallel.
static NEXT_PORT: AtomicU16 = AtomicU16::new(19300);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

/// jcardsim ships `com.licel.jcardsim.samples.HelloWorldApplet` in its
/// main JAR -- a trivial applet that responds to SELECT with 0x9000
/// and echoes back its AID.
const SMOKE_APPLET_CLASS: &str = "com.licel.jcardsim.samples.HelloWorldApplet";
const SMOKE_APPLET_AID: &str = "F000000001";

#[test]
fn smoke_spawn_connect_power_cycle() {
    let Some(installation) = discover_bridge() else {
        eprintln!(
            "simrs-jcardsim bridge not discovered (neither \
             SIMRS_JCARDSIM_BRIDGE/_LIB nor ~/.cache/simrs/jcardsim/ \
             nor workspace build output). Skipping smoke test."
        );
        return;
    };

    let port = next_port();
    let mut config = JcardsimConfig::new(installation);
    config.port = port;
    config.applet_class = SMOKE_APPLET_CLASS.into();
    config.applet_aid_hex = SMOKE_APPLET_AID.into();
    config.startup_timeout = Duration::from_secs(20);

    let process = JcardsimProcess::start(&config).expect("bridge must spawn + bind port");
    assert_eq!(process.port(), port);

    let mut client = JcardsimClient::connect(&process.address())
        .expect("client must connect once the bridge reports LISTENING");

    let atr = client.power_on().expect("power_on should return the ATR");
    assert!(!atr.is_empty(), "ATR must be non-empty");
    assert!(client.is_powered());

    client.power_off().expect("power_off should round-trip");
    assert!(!client.is_powered());

    // `process` drops here -> JVM killed. No stray children on disk.
}
