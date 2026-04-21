//! martinpaljak/`JCardEngine` reference backend.
//!
//! Entire module gated by `feature = "jcardengine-backend"`. Nothing
//! here compiles or pulls in the `simrs-jcardengine` dependency when
//! the feature is off.

use std::time::Duration;

use simrs_jcardengine::{
    JcardengineClient, JcardengineConfig, JcardengineProcess,
    discovery::BridgeInstallation as JcardengineInstallation,
};
use simrs_transport::{Transport, TransportError};

use crate::reference::{BackendId, ReferenceBackend, hex_upper};
use crate::{KEY_BYTES, next_port};

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
                crate::display_path(&self.installation.bridge_jar),
            ),
            (
                "engine.jar".into(),
                crate::display_path(&self.installation.jcardengine_jar),
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
    // the same TCP session via framing-level POWER_OFF/POWER_ON.
}

impl Transport for JcardengineBackend {
    type Error = TransportError;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.powered {
            return Err(TransportError::IoError);
        }
        self.client.exchange(cmd, rsp)
    }
}
