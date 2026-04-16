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
    /// Keeps the memfd alive for the process lifetime (if started via memfd).
    _memfd: Option<memfd::Memfd>,
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
                format!(
                    "cannot resolve jcsl binary path {}: {e}",
                    config.binary_path.display()
                ),
            )
        })?;

        let lib_dir = binary
            .parent()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "binary path has no parent directory",
                )
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
            _memfd: None,
        };

        // Wait for the server to accept connections.
        if let Err(e) = proc.wait_for_ready(config.startup_timeout) {
            // Kill the process if we can't connect.
            let _ = proc.child.kill();
            return Err(e);
        }

        Ok(proc)
    }

    /// Start from a sealed memfd instead of a file path.
    ///
    /// The memfd must contain a valid, sealed jcsl binary (created via
    /// [`configure_to_memfd`](crate::configure_to_memfd)). The process
    /// is executed via `/proc/self/fd/N`.
    ///
    /// `lib_dir` is the directory containing the jcsl shared libraries
    /// (typically the parent directory of the original unconfigured binary).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the process cannot be spawned or does not
    /// become ready within the timeout.
    pub fn start_memfd(
        mfd: memfd::Memfd,
        lib_dir: &Path,
        port: u16,
        log_level: &str,
        startup_timeout: Duration,
    ) -> io::Result<Self> {
        use std::os::fd::AsRawFd;

        let exe_path = format!("/proc/self/fd/{}", mfd.as_file().as_raw_fd());

        let mut cmd = Command::new(&exe_path);
        cmd.arg(format!("-p={port}"));
        cmd.arg(format!("-log_level={log_level}"));
        cmd.env("LD_LIBRARY_PATH", lib_dir);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn().map_err(|e| {
            io::Error::new(e.kind(), format!("failed to spawn jcsl from memfd: {e}"))
        })?;

        let mut proc = Self {
            child,
            port,
            lib_dir: lib_dir.to_path_buf(),
            _memfd: Some(mfd),
        };

        if let Err(e) = proc.wait_for_ready(startup_timeout) {
            let _ = proc.child.kill();
            return Err(e);
        }

        Ok(proc)
    }

    /// Configure a jcsl binary in memory and start it.
    ///
    /// Reads the source binary, patches SCP keys and PIN via
    /// [`configure_to_memfd`](crate::configure_to_memfd), and spawns the
    /// process from the anonymous memfd. No temporary files are created.
    ///
    /// This is the recommended way to start a jcsl instance for testing.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if configuration, memfd creation, or process
    /// startup fails.
    pub fn start_configured(
        src: &Path,
        keyset: Option<&crate::configurator::ScpKeyset>,
        pin: Option<&crate::configurator::GlobalPin>,
        port: u16,
        log_level: &str,
        startup_timeout: Duration,
    ) -> io::Result<Self> {
        let lib_dir = src.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "source binary path has no parent directory",
            )
        })?;

        let mfd = crate::configurator::configure_to_memfd(src, keyset, pin)
            .map_err(|e| io::Error::other(e.to_string()))?;

        Self::start_memfd(mfd, lib_dir, port, log_level, startup_timeout)
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

    // -------------------------------------------------------------------
    // Insta snapshots
    // -------------------------------------------------------------------

    #[test]
    fn snap_default_config_debug() {
        let cfg = JcslConfig::default();
        insta::assert_snapshot!("default_config_debug", format!("{cfg:#?}"));
    }

    #[test]
    fn snap_custom_config_debug() {
        let cfg = JcslConfig {
            binary_path: PathBuf::from("/home/user/.cache/simrs/jcsl"),
            port: 19200,
            log_level: "finest".to_owned(),
            eeprom_in: Some(PathBuf::from("/tmp/card.eeprom")),
            eeprom_out: Some(PathBuf::from("/tmp/card-out.eeprom")),
            startup_timeout: Duration::from_secs(30),
        };
        insta::assert_snapshot!("custom_config_debug", format!("{cfg:#?}"));
    }
}
