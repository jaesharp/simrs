//! Abstracted reference-backend interface for the differential harness.
//!
//! Historically the differential crate hard-coded Oracle `jcsl` as the
//! reference implementation. Now that we also run martinpaljak
//! [`JCardEngine`](https://github.com/martinpaljak/JCardEngine) as a
//! second reference, common parts of the harness are expressed in terms
//! of a trait so the rest of the crate can stay backend-agnostic.
//!
//! # Contract
//!
//! A [`ReferenceBackend`] owns a live child process (jcsl binary, or a
//! JVM hosting the `JCardEngine` bridge) and a TCP connection to it. It
//! exposes the three operations the harness cares about:
//!
//! 1. Power on and return the ATR.
//! 2. Transmit one APDU and return its full response (data || SW).
//! 3. Reconnect after a logical reset, so tests that power-cycle can
//!    continue without tearing the whole harness down. (Some backends
//!    do this implicitly; others, like jcsl, need a fresh TCP session.)
//!
//! Dropping the backend terminates the child process.

use std::io;
use std::time::Duration;

use simrs_jcardengine::{
    JcardengineClient, JcardengineConfig, JcardengineProcess,
    discovery::BridgeInstallation as JcardengineInstallation,
};
use simrs_jcsl::configurator::{GlobalPin, ScpKeyset};
use simrs_jcsl::{JcslClient, JcslProcess};
use simrs_transport::{Transport, TransportError};

use crate::{KEY_BYTES, next_port};

/// Uppercase hex-encode a byte slice. Kept private to this module;
/// the handful of callers all want the same "no separators, no 0x
/// prefix" spelling used in context report entries.
fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Classify an [`io::Error`] from the jcsl client into the harness's
/// [`TransportError`] vocabulary. Mirrors the policy used by
/// `simrs-jcardengine::client::map_io_err`: peer-closed errors collapse
/// to `Disconnected`, everything else to `IoError`.
fn map_jcsl_io_err(e: &io::Error) -> TransportError {
    use io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    match e.kind() {
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => {
            TransportError::Disconnected
        }
        _ => TransportError::IoError,
    }
}

/// Stable identifier for a reference backend.
///
/// Appears in generated report filenames
/// (`differential-report-<id>.xml`) and CI matrix cells -- keep the
/// string form lowercase and shell-safe. `Ord` is derived so
/// iteration order in the combined report is deterministic and
/// lexicographic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackendId {
    /// Oracle's `jcsl` binary (32-bit Linux, RAW framing).
    Jcsl,
    /// martinpaljak/`JCardEngine` JVM bridge.
    Jcardengine,
}

impl BackendId {
    /// Kebab-case identifier used in filenames and CI labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jcsl => "jcsl",
            Self::Jcardengine => "jcardengine",
        }
    }

    /// Parse from the `SIMRS_DIFF_BACKEND` env var spelling.
    ///
    /// # Errors
    ///
    /// Returns `Err(raw)` if `raw` is neither `"jcsl"` nor
    /// `"jcardengine"`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "jcsl" => Ok(Self::Jcsl),
            "jcardengine" => Ok(Self::Jcardengine),
            other => Err(other.to_string()),
        }
    }
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Abstract interface to a reference `JavaCard` simulator.
///
/// Implementors own the simulator's child process and TCP connection.
/// Contract notes:
///
/// - [`power_on`](Self::power_on) is idempotent in spirit: implementors
///   may send a new cold-reset each call or short-circuit if already
///   powered; the differential harness always calls it exactly once
///   per session.
/// - [`transmit_apdu`](Self::transmit_apdu) returns the full response
///   buffer including `SW1 SW2` at the end.
/// - [`reconnect`](Self::reconnect) does whatever is needed to make the
///   backend able to accept further APDUs after a simulated power
///   cycle. For backends that power-cycle inside the same TCP session,
///   this is a no-op.
pub trait ReferenceBackend {
    /// Stable identifier (for logs, filenames, matrix cells).
    fn backend_id(&self) -> BackendId;

    /// Cold-reset the card and return its ATR.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the backend connection fails.
    fn power_on(&mut self) -> Result<Vec<u8>, TransportError>;

    /// Send one APDU and return the full response buffer (data || SW).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the backend connection fails or
    /// truncates the response.
    fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError>;

    /// Re-establish the session after a simulated power cycle. Default
    /// implementation is a no-op, suitable for backends that can
    /// power-cycle inside one TCP connection.
    fn reconnect(&mut self) {}
}

// ---------------------------------------------------------------------------
// JcslBackend -- wraps Oracle jcsl (`JcslProcess` + `JcslClient`).
// ---------------------------------------------------------------------------

/// Reference-backend adapter around Oracle's `jcsl` simulator.
pub struct JcslBackend {
    client: JcslClient,
    port: u16,
    _proc: JcslProcess,
    /// Snapshot of the binary path + key material used, for
    /// [`context_entries`](Self::context_entries).
    binary_path: std::path::PathBuf,
    scp_kvn: u8,
    scp_keys_hex: String,
    pin_hex: String,
}

impl JcslBackend {
    /// Spawn `jcsl` with default GP test keys, PIN "1234", and connect.
    ///
    /// Returns `None` when [`simrs_jcsl::discover_binary`] fails --
    /// caller can skip gracefully.
    ///
    /// # Panics
    ///
    /// Panics if the binary exists but configuration or startup fails.
    #[must_use]
    pub fn try_start() -> Option<Self> {
        let src = simrs_jcsl::discover_binary()?;
        let port = next_port();
        let keyset = ScpKeyset {
            kvn: 0x01,
            enc: KEY_BYTES.to_vec(),
            mac: KEY_BYTES.to_vec(),
            dek: KEY_BYTES.to_vec(),
        };
        let pin_bytes = vec![0x31, 0x32, 0x33, 0x34];
        let gpin = GlobalPin {
            pin: pin_bytes.clone(),
            max_retries: 3,
        };
        let proc = JcslProcess::start_configured(
            &src,
            Some(&keyset),
            Some(&gpin),
            port,
            "info",
            Duration::from_secs(10),
        )
        .expect("failed to start jcsl");
        let client =
            JcslClient::connect(&format!("127.0.0.1:{port}")).expect("failed to connect to jcsl");
        let scp_keys_hex = hex_upper(&KEY_BYTES);
        let pin_hex = hex_upper(&pin_bytes);
        Some(Self {
            client,
            port,
            _proc: proc,
            binary_path: src,
            scp_kvn: keyset.kvn,
            scp_keys_hex,
            pin_hex,
        })
    }

    /// Key/value pairs describing this backend's runtime setup. Used
    /// by the report generator's "Environment" section; mirrors the
    /// shape of [`JcardengineBackend::context_entries`].
    #[must_use]
    pub fn context_entries(&self) -> Vec<(String, String)> {
        vec![
            ("backend".into(), BackendId::Jcsl.as_str().into()),
            ("binary".into(), self.binary_path.display().to_string()),
            ("applet.aid".into(), "A000000151000000".into()),
            ("scp.kvn".into(), format!("0x{:02X}", self.scp_kvn)),
            ("scp.enc_mac_dek_hex".into(), self.scp_keys_hex.clone()),
            ("cvm.global_pin_hex".into(), self.pin_hex.clone()),
        ]
    }
}

impl ReferenceBackend for JcslBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Jcsl
    }

    fn power_on(&mut self) -> Result<Vec<u8>, TransportError> {
        self.client.power_on().map_err(|e| map_jcsl_io_err(&e))
    }

    fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.client
            .transmit_apdu(apdu)
            .map_err(|e| map_jcsl_io_err(&e))
    }

    fn reconnect(&mut self) {
        // jcsl doesn't support power-cycling within one TCP session:
        // the server closes the connection on cold-reset. Reopen a
        // fresh client so subsequent APDUs have somewhere to land.
        self.client = JcslClient::connect(&format!("127.0.0.1:{}", self.port))
            .expect("failed to reconnect to jcsl");
    }
}

// ---------------------------------------------------------------------------
// JcardengineBackend -- wraps martinpaljak/JCardEngine bridge.
// ---------------------------------------------------------------------------

/// GP ISD applet class shipped inside `JCardEngine` itself.
///
/// The differential harness installs this so the bridge presents a
/// GlobalPlatform-compliant ISD -- matching jcsl's default
/// configuration -- rather than the minimal
/// [`JCE_SMOKE_APPLET_CLASS`] stand-in.
pub const JCE_GP_APPLET_CLASS: &str = "pro.javacard.engine.globalplatform.GlobalPlatformApplet";

/// AID that [`JCE_GP_APPLET_CLASS`] registers under.
///
/// Hard-coded in `JCardEngine`'s own bytecode and matches Oracle's GP
/// 2.3 default ISD AID, so both references can be SELECT-ed with the
/// same command.
pub const JCE_GP_APPLET_AID: &str = "A000000151000000";

/// Minimal applet class bundled in the bridge JAR.
///
/// See `tools/jcardengine-bridge/src/main/java/com/simrs/jcardengine/HelloWorldApplet.java`.
/// Retained for smoke-testing the bridge plumbing without paying for
/// the full `GlobalPlatformApplet` setup.
pub const JCE_SMOKE_APPLET_CLASS: &str = "com.simrs.jcardengine.HelloWorldApplet";

/// AID under which [`JCE_SMOKE_APPLET_CLASS`] is installed + selected.
pub const JCE_SMOKE_APPLET_AID: &str = "F000000001";

/// Reference-backend adapter around the `JCardEngine` bridge.
pub struct JcardengineBackend {
    client: JcardengineClient,
    powered: bool,
    _proc: JcardengineProcess,
    /// Snapshot of the bridge configuration -- surfaced via
    /// [`context_entries`](Self::context_entries) so the report
    /// generator can record how this backend was wired up.
    installation: JcardengineInstallation,
    master_key_hex: String,
}

impl JcardengineBackend {
    /// Discover + spawn the bridge JVM and connect.
    ///
    /// Installs `JCardEngine`'s GP ISD
    /// ([`JCE_GP_APPLET_CLASS`] at [`JCE_GP_APPLET_AID`]) seeded with
    /// the shared differential test master key
    /// ([`KEY_BYTES`](crate::KEY_BYTES)), matching jcsl's GP setup.
    /// Returns `None` if the bridge installation isn't available --
    /// caller can skip gracefully. Search order is driven by
    /// [`simrs_jcardengine::discover_bridge`] (env vars, XDG cache,
    /// workspace Gradle output).
    ///
    /// # Panics
    ///
    /// Panics if the installation exists but the JVM fails to spawn or
    /// the subsequent TCP connect fails.
    #[must_use]
    pub fn try_start() -> Option<Self> {
        let installation: JcardengineInstallation = simrs_jcardengine::discover_bridge()?;
        Some(Self::start_with(installation))
    }

    fn start_with(installation: JcardengineInstallation) -> Self {
        let port = next_port();
        let master_key_hex = hex_upper(&KEY_BYTES);

        let mut cfg = JcardengineConfig::new(installation.clone());
        cfg.port = port;
        cfg.applet_class = JCE_GP_APPLET_CLASS.into();
        cfg.applet_aid_hex = JCE_GP_APPLET_AID.into();
        cfg.gp_master_key_hex = Some(master_key_hex.clone());
        cfg.startup_timeout = Duration::from_secs(20);

        let proc = JcardengineProcess::start(&cfg).expect("failed to start jcardengine bridge");
        let address = proc.address();
        let client = JcardengineClient::connect(&address)
            .unwrap_or_else(|e| panic!("jcardengine connect failed: {e}"));
        Self {
            client,
            powered: false,
            _proc: proc,
            installation,
            master_key_hex,
        }
    }

    /// Key/value pairs describing this backend's runtime setup.
    /// Consumed by the differential report generator to populate the
    /// report's "Environment" section.
    #[must_use]
    pub fn context_entries(&self) -> Vec<(String, String)> {
        vec![
            ("backend".into(), BackendId::Jcardengine.as_str().into()),
            (
                "bridge.jar".into(),
                self.installation.bridge_jar.display().to_string(),
            ),
            (
                "engine.jar".into(),
                self.installation.jcardengine_jar.display().to_string(),
            ),
            ("applet.class".into(), JCE_GP_APPLET_CLASS.into()),
            ("applet.aid".into(), JCE_GP_APPLET_AID.into()),
            ("scp.master_key_hex".into(), self.master_key_hex.clone()),
            ("scp.variant".into(), "SCP03".into()),
        ]
    }
}

impl ReferenceBackend for JcardengineBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Jcardengine
    }

    fn power_on(&mut self) -> Result<Vec<u8>, TransportError> {
        let atr = self.client.power_on()?;
        self.powered = true;
        Ok(atr.to_vec())
    }

    fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        if !self.powered {
            return Err(TransportError::IoError);
        }
        let mut buf = vec![0u8; 512];
        let n = self.client.exchange(apdu, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    // reconnect() defaults to a no-op for jcardengine: the bridge
    // accept()s exactly once per spawn, and power cycles live inside
    // the same TCP session via framing-level POWER_OFF/POWER_ON. Tests
    // that simulate a reset should call power_off/power_on on the
    // client directly rather than reopening the socket.
}
