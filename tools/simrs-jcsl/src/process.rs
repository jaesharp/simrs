//! Oracle jcsl process lifecycle management.
//!
//! Handles starting, stopping, and monitoring the `jcsl` ELF binary.
//! The simulator is a 32-bit x86 Linux executable that listens on a
//! configurable TCP port.

use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Default TCP port for the jcsl simulator.
pub const DEFAULT_PORT: u16 = 9025;

/// Configuration for starting a jcsl instance.
#[derive(Debug, Clone)]
pub struct JcslConfig {
    /// Path to the jcsl binary.
    pub binary_path: PathBuf,
    /// TCP port to listen on.
    pub port: u16,
    /// Log level (finest, finer, fine, config, info, warning, severe).
    pub log_level: String,
    /// Optional EEPROM image to load.
    pub eeprom_in: Option<PathBuf>,
    /// Optional EEPROM image to save on shutdown.
    pub eeprom_out: Option<PathBuf>,
    /// Maximum time to wait for the server to become ready.
    pub startup_timeout: Duration,
}

impl Default for JcslConfig {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::from("tools/oracle-jcvm-ref/runtime/bin/jcsl"),
            port: DEFAULT_PORT,
            log_level: "info".to_owned(),
            eeprom_in: None,
            eeprom_out: None,
            startup_timeout: Duration::from_secs(10),
        }
    }
}

/// A running jcsl simulator process.
///
/// The process is killed when this handle is dropped.
pub struct JcslProcess {
    child: Child,
    port: u16,
    /// Directory containing the jcsl binary (needed for `LD_LIBRARY_PATH`).
    lib_dir: PathBuf,
}

impl JcslProcess {
    /// Start a new jcsl simulator process.
    ///
    /// Blocks until the server is listening on the configured port or
    /// the startup timeout expires.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the binary cannot be resolved, the process
    /// cannot be spawned, or the server does not become ready within the
    /// configured timeout.
    pub fn start(config: &JcslConfig) -> io::Result<Self> {
        let binary = config.binary_path.canonicalize().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot resolve jcsl binary path {}: {e}", config.binary_path.display()),
            )
        })?;

        let lib_dir = binary
            .parent()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "binary path has no parent directory")
            })?
            .to_path_buf();

        let mut cmd = Command::new(&binary);
        cmd.arg(format!("-p={}", config.port));
        cmd.arg(format!("-log_level={}", config.log_level));

        if let Some(ref eeprom_in) = config.eeprom_in {
            cmd.arg(format!("-i={}", eeprom_in.display()));
        }
        if let Some(ref eeprom_out) = config.eeprom_out {
            cmd.arg(format!("-o={}", eeprom_out.display()));
        }

        // The jcsl binary links against its bundled OpenSSL libraries.
        cmd.env("LD_LIBRARY_PATH", &lib_dir);

        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to spawn jcsl at {}: {e}", binary.display()),
            )
        })?;

        let mut proc = Self {
            child,
            port: config.port,
            lib_dir,
        };

        // Wait for the server to accept connections.
        if let Err(e) = proc.wait_for_ready(config.startup_timeout) {
            // Kill the process if we can't connect.
            let _ = proc.child.kill();
            return Err(e);
        }

        Ok(proc)
    }

    /// TCP port this instance is listening on.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Directory containing the jcsl binary and its shared libraries.
    pub fn lib_dir(&self) -> &Path {
        &self.lib_dir
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Kill the process.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the process cannot be killed.
    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }

    /// Wait for the process to exit and return the exit status.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if waiting fails.
    pub fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.child.wait()
    }

    /// Poll the TCP port until it accepts a connection.
    fn wait_for_ready(&mut self, timeout: Duration) -> io::Result<()> {
        let start = Instant::now();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port)
            .parse()
            .expect("valid socket address");

        loop {
            // Check if the process has already exited.
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(io::Error::other(format!(
                    "jcsl process exited during startup with status: {status}"
                )));
            }

            // Try connecting.
            if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                drop(stream);
                return Ok(());
            }

            if start.elapsed() > timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "jcsl did not become ready on port {} within {timeout:?}",
                        self.port
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for JcslProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = JcslConfig::default();
        assert_eq!(cfg.port, 9025);
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.eeprom_in.is_none());
        assert!(cfg.eeprom_out.is_none());
    }

    #[test]
    fn config_custom_port() {
        let cfg = JcslConfig {
            port: 19999,
            ..JcslConfig::default()
        };
        assert_eq!(cfg.port, 19999);
    }
}
