//! Lifecycle management for the jcardsim bridge JVM process.
//!
//! Mirrors [`simrs_jcsl::process`](../../simrs-jcsl/src/process.rs): a
//! builder-style [`JcardsimConfig`], a [`JcardsimProcess`] RAII handle,
//! and a TCP-port readiness check before [`client::JcardsimClient`]
//! connects.
//!
//! [`client::JcardsimClient`]: crate::client::JcardsimClient

use std::io;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::discovery::BridgeInstallation;

/// Default TCP port the bridge listens on. Different from jcsl (9025) so
/// both can run simultaneously during differential tests.
pub const DEFAULT_PORT: u16 = 9125;

/// Configuration for starting a bridge JVM.
#[derive(Debug, Clone)]
pub struct JcardsimConfig {
    /// Resolved bridge + jcardsim JAR locations.
    pub installation: BridgeInstallation,
    /// TCP port to listen on. 0 means "pick any free port"; the bound
    /// port is then readable from [`JcardsimProcess::port`].
    pub port: u16,
    /// Class name of the applet to install. Must be on the JVM
    /// classpath (either baked into the bridge jar or supplied via
    /// [`JcardsimConfig::extra_classpath`]).
    pub applet_class: String,
    /// Hex-encoded AID of the applet to install and select at startup.
    pub applet_aid_hex: String,
    /// Extra classpath entries (colon/semicolon joined by caller
    /// depending on host OS).
    pub extra_classpath: Vec<PathBuf>,
    /// Maximum time to wait for the server to become ready.
    pub startup_timeout: Duration,
    /// Path to the `java` executable. Defaults to `java` on PATH.
    pub java_binary: PathBuf,
}

impl JcardsimConfig {
    /// Build a default config around a located [`BridgeInstallation`].
    #[must_use]
    pub fn new(installation: BridgeInstallation) -> Self {
        Self {
            installation,
            port: DEFAULT_PORT,
            applet_class: String::new(),
            applet_aid_hex: String::new(),
            extra_classpath: Vec::new(),
            startup_timeout: Duration::from_secs(15),
            java_binary: PathBuf::from("java"),
        }
    }
}

/// Running bridge JVM process. Killed on drop.
pub struct JcardsimProcess {
    child: Child,
    /// Port the bridge is listening on. Cached from startup.
    port: u16,
}

impl JcardsimProcess {
    /// Spawn `java -cp <bridge>:<jcardsim>[:extras] com.simrs.jcardsim.Bridge`
    /// and wait for the TCP port to become accepting.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the JVM fails to spawn, the port never
    /// opens within [`JcardsimConfig::startup_timeout`], or the config is
    /// missing required applet settings.
    pub fn start(config: &JcardsimConfig) -> io::Result<Self> {
        if config.applet_class.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "JcardsimConfig::applet_class must be set",
            ));
        }
        if config.applet_aid_hex.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "JcardsimConfig::applet_aid_hex must be set",
            ));
        }

        let classpath = build_classpath(config);
        let port_str = config.port.to_string();

        let mut cmd = Command::new(&config.java_binary);
        cmd.arg("-cp")
            .arg(&classpath)
            .arg("com.simrs.jcardsim.Bridge")
            .arg("--port")
            .arg(&port_str)
            .arg("--applet-class")
            .arg(&config.applet_class)
            .arg("--applet-aid")
            .arg(&config.applet_aid_hex)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn()?;

        // The bridge prints "LISTENING <port>\n" on stdout once the
        // server socket is accept()ing. Scanning stdout decouples us
        // from polling the port (which might race on fast machines).
        // For now we fall back to a poll-the-port approach and revisit.
        let port = if config.port == 0 {
            // Port 0 is a future enhancement -- requires the bridge to
            // print the bound ephemeral port. Not yet implemented.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ephemeral port selection not yet implemented (set port != 0)",
            ));
        } else {
            config.port
        };

        wait_for_port(port, config.startup_timeout)?;

        Ok(Self { child, port })
    }

    /// Port the bridge is listening on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Address suitable for passing to `JcardsimClient::connect`.
    #[must_use]
    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Try to terminate the child gracefully (best-effort).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the kill syscall fails.
    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}

impl Drop for JcardsimProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build an OS-appropriate classpath string for `java -cp`.
fn build_classpath(config: &JcardsimConfig) -> String {
    let sep = if cfg!(target_os = "windows") {
        ";"
    } else {
        ":"
    };
    let mut entries: Vec<String> = vec![
        config.installation.bridge_jar.display().to_string(),
        config.installation.jcardsim_jar.display().to_string(),
    ];
    entries.extend(
        config
            .extra_classpath
            .iter()
            .map(|p| p.display().to_string()),
    );
    entries.join(sep)
}

/// Poll `127.0.0.1:port` until TCP `connect()` succeeds or the timeout
/// elapses.
fn wait_for_port(port: u16, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    loop {
        if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(250)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("bridge did not open port {port} within {timeout:?}"),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classpath_uses_platform_separator() {
        let inst = BridgeInstallation {
            bridge_jar: PathBuf::from("/a/bridge.jar"),
            jcardsim_jar: PathBuf::from("/a/jcardsim-3.0.5.jar"),
            source: crate::discovery::DiscoverySource::EnvVar,
        };
        let config = JcardsimConfig::new(inst);
        let cp = build_classpath(&config);
        if cfg!(target_os = "windows") {
            assert!(cp.contains(';'));
        } else {
            assert!(cp.contains(':'));
        }
    }

    #[test]
    fn default_port_distinct_from_jcsl() {
        assert_ne!(
            DEFAULT_PORT, 9025,
            "must not collide with jcsl default port"
        );
    }
}
