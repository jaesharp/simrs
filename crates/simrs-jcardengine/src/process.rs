//! Lifecycle management for the `JCardEngine` bridge JVM process.
//!
//! Two improvements over the jcardsim-wip iteration:
//!
//! 1. **Stdout-scan readiness**: instead of polling TCP until
//!    `connect()` succeeds, we read the child's stdout line-by-line
//!    and wait for `LISTENING <port>\n`. The bridge prints this after
//!    its `ServerSocket.accept()` is reachable, so the signal is
//!    exactly the accept-ready event we care about.
//! 2. **Stderr drain**: a background thread reads the child's stderr
//!    into a shared string. When any operation fails, we can include
//!    the last N lines in the error message -- Java exceptions no
//!    longer vanish into a closed pipe.

use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::discovery::BridgeInstallation;

/// Default listening port. Distinct from jcsl (9025) and jcardsim (9125)
/// so all three backends can coexist during differential runs.
pub const DEFAULT_PORT: u16 = 9225;

/// Size limit on the retained stderr tail (bytes). Protects against
/// runaway child output while still being plenty for a Java stack
/// trace.
const STDERR_TAIL_LIMIT: usize = 64 * 1024;

/// Configuration for starting a bridge JVM.
#[derive(Debug, Clone)]
pub struct JcardengineConfig {
    /// Resolved bridge + engine JAR locations.
    pub installation: BridgeInstallation,
    /// TCP port to listen on. Must be non-zero until the bridge
    /// supports ephemeral-port advertisement.
    pub port: u16,
    /// Fully-qualified class name of the applet to install.
    pub applet_class: String,
    /// Hex-encoded AID the applet is installed + selected under.
    pub applet_aid_hex: String,
    /// Optional hex-encoded SCP03 master key passed to the bridge.
    ///
    /// When set, the bridge constructs its `Simulator` with a
    /// `GlobalPlatform` instance seeded with
    /// `SCPConfig.SCP03(parseHex(value))` so the installed
    /// `GlobalPlatformApplet` participates in SCP03 with matching
    /// keys. When unset, the bridge uses the default simulator
    /// (sufficient for non-GP applets such as the bundled
    /// `HelloWorldApplet`).
    pub gp_master_key_hex: Option<String>,
    /// Extra classpath entries appended after bridge + engine.
    pub extra_classpath: Vec<PathBuf>,
    /// Maximum wall-clock wait for `LISTENING <port>`.
    pub startup_timeout: Duration,
    /// `java` binary path.
    ///
    /// Defaults to [`discover_java_binary`](crate::discovery::discover_java_binary),
    /// which prefers `SIMRS_JCARDENGINE_JAVA`, then `JAVA_HOME`, then a
    /// Gradle-cached JDK 17+, then `java` on `PATH`.
    pub java_binary: PathBuf,
}

impl JcardengineConfig {
    /// Default config pointing at a pre-located bridge installation.
    #[must_use]
    pub fn new(installation: BridgeInstallation) -> Self {
        Self {
            installation,
            port: DEFAULT_PORT,
            applet_class: String::new(),
            applet_aid_hex: String::new(),
            gp_master_key_hex: None,
            extra_classpath: Vec::new(),
            startup_timeout: Duration::from_secs(15),
            java_binary: crate::discovery::discover_java_binary(),
        }
    }
}

/// Running bridge JVM with captured stderr. Killed on drop.
pub struct JcardengineProcess {
    child: Child,
    port: u16,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    /// Kept only so the drain thread's lifetime is tied to Drop.
    stderr_thread: Option<JoinHandle<()>>,
}

impl JcardengineProcess {
    /// Spawn the bridge JVM and wait for its `LISTENING <port>` signal.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the JVM fails to spawn, required
    /// config fields are empty, or the child doesn't emit
    /// `LISTENING <expected_port>` within [`startup_timeout`]. Error
    /// messages include the captured stderr tail where useful.
    ///
    /// [`startup_timeout`]: JcardengineConfig::startup_timeout
    pub fn start(config: &JcardengineConfig) -> io::Result<Self> {
        if config.applet_class.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "JcardengineConfig::applet_class must be set",
            ));
        }
        if config.applet_aid_hex.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "JcardengineConfig::applet_aid_hex must be set",
            ));
        }
        if config.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ephemeral port selection not yet supported; pick a fixed port",
            ));
        }

        let classpath = build_classpath(config);

        let mut command = Command::new(&config.java_binary);
        command
            .arg("-cp")
            .arg(&classpath)
            .arg("com.simrs.jcardengine.Bridge")
            .arg("--port")
            .arg(config.port.to_string())
            .arg("--applet-class")
            .arg(&config.applet_class)
            .arg("--applet-aid")
            .arg(&config.applet_aid_hex);
        if let Some(hex) = &config.gp_master_key_hex {
            command.arg("--gp-master-key-hex").arg(hex);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Drain stderr on a background thread from the moment the
        // child is live. Callers can read `stderr_tail()` after any
        // failure -- Java exceptions thrown after startup are still
        // captured because the thread keeps running until child exit.
        let stderr_tail = Arc::new(Mutex::new(Vec::<u8>::new()));
        let stderr_thread = child.stderr.take().map(|stderr| {
            let buf = Arc::clone(&stderr_tail);
            thread::spawn(move || drain_stderr_into(stderr, &buf))
        });

        // Scan stdout for "LISTENING <expected_port>" up to the
        // startup timeout. If the child exits before that line, the
        // read loop ends (EOF) and we surface a helpful error.
        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::other("child JVM has no stdout pipe to scan for LISTENING")
        })?;

        match wait_for_listening(stdout, config.port, config.startup_timeout) {
            Ok(()) => {}
            Err(e) => {
                // Child almost certainly crashed; give the stderr
                // drain a moment to flush then include its tail.
                let _ = child.kill();
                thread::sleep(Duration::from_millis(50));
                let tail = String::from_utf8_lossy(
                    &stderr_tail.lock().map(|g| g.clone()).unwrap_or_default(),
                )
                .trim()
                .to_string();
                let msg = if tail.is_empty() {
                    format!("{e} (bridge stderr was empty)")
                } else {
                    format!("{e}; bridge stderr tail:\n{tail}")
                };
                return Err(io::Error::new(e.kind(), msg));
            }
        }

        Ok(Self {
            child,
            port: config.port,
            stderr_tail,
            stderr_thread,
        })
    }

    /// Port the bridge is listening on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// `"127.0.0.1:<port>"` convenience for [`JcardengineClient::connect`].
    ///
    /// [`JcardengineClient::connect`]: crate::client::JcardengineClient::connect
    #[must_use]
    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Snapshot of everything the bridge has written to stderr so far.
    ///
    /// Useful when a downstream operation (`power_on`, `exchange`)
    /// returns `Disconnected` -- the tail usually contains the Java
    /// exception that caused the disconnect.
    #[must_use]
    pub fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .map(|g| String::from_utf8_lossy(&g).into_owned())
            .unwrap_or_default()
    }
}

impl Drop for JcardengineProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The stderr thread will exit on EOF once child is reaped;
        // best-effort join without blocking indefinitely.
        if let Some(h) = self.stderr_thread.take() {
            let _ = h.join();
        }
    }
}

fn build_classpath(config: &JcardengineConfig) -> String {
    let sep = if cfg!(target_os = "windows") {
        ";"
    } else {
        ":"
    };
    // The Gradle `copyRuntimeDeps` task places bridge.jar, the
    // jcardengine engine jar, and *all* transitive runtime deps
    // (slf4j, byte-buddy, asm, jackson, bouncycastle, apdu4j-core,
    // ...) into a single directory. `java -cp <dir>/*` expands to
    // every jar in that directory at VM startup -- no per-dep plumbing
    // needed on this side. `Command::arg` passes the literal `*` to
    // exec/CreateProcess, so the shell doesn't re-expand it.
    let bridge_dir = config
        .installation
        .bridge_jar
        .parent()
        .map_or_else(|| config.installation.bridge_jar.clone(), Path::to_path_buf);
    let mut entries: Vec<String> = vec![bridge_dir.join("*").display().to_string()];
    entries.extend(
        config
            .extra_classpath
            .iter()
            .map(|p| p.display().to_string()),
    );
    entries.join(sep)
}

/// Background-thread body: copy child stderr into the shared tail
/// buffer, dropping oldest bytes once [`STDERR_TAIL_LIMIT`] is reached.
fn drain_stderr_into<R: Read>(mut reader: R, sink: &Arc<Mutex<Vec<u8>>>) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return, // EOF
            Ok(n) => {
                if let Ok(mut g) = sink.lock() {
                    g.extend_from_slice(&buf[..n]);
                    if g.len() > STDERR_TAIL_LIMIT {
                        let excess = g.len() - STDERR_TAIL_LIMIT;
                        g.drain(..excess);
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Read lines from `stdout` until we see `LISTENING <expected_port>`.
fn wait_for_listening(
    stdout: ChildStdout,
    expected_port: u16,
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let expected_line = format!("LISTENING {expected_port}");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("bridge did not announce '{expected_line}' within {timeout:?}"),
            ));
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "bridge stdout closed before announcing LISTENING",
                ));
            }
            Ok(_) => {
                if line.trim() == expected_line {
                    return Ok(());
                }
                // Other stdout lines are ignored (bridge may log
                // startup info).
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classpath_wildcards_bridge_dir() {
        // Construct paths platform-natively so build_classpath's
        // join-with-* output matches consistently across OSes.
        // `PathBuf::from("/a/bridge.jar")` on Windows preserves the
        // forward slashes unchanged; joining with `*` then produces
        // mixed-separator output (`/a\*`). Using a PathBuf assembled
        // component-by-component ensures the separators are all in
        // the platform's native style.
        let bridge_jar: PathBuf = ["a", "bridge.jar"].iter().collect();
        let engine_jar: PathBuf = ["a", "jcardengine-26.04.06.jar"].iter().collect();
        let inst = BridgeInstallation {
            bridge_jar,
            jcardengine_jar: engine_jar,
            source: crate::discovery::DiscoverySource::EnvVar,
        };
        let cp = build_classpath(&JcardengineConfig::new(inst));
        // Expected: "<bridge_dir>/*" with the platform's separator.
        let expected: PathBuf = ["a", "*"].iter().collect();
        assert_eq!(cp, expected.display().to_string());
    }

    #[test]
    fn classpath_appends_extra_with_platform_separator() {
        let inst = BridgeInstallation {
            bridge_jar: PathBuf::from("/a/bridge.jar"),
            jcardengine_jar: PathBuf::from("/a/jcardengine-26.04.06.jar"),
            source: crate::discovery::DiscoverySource::EnvVar,
        };
        let mut cfg = JcardengineConfig::new(inst);
        cfg.extra_classpath.push(PathBuf::from("/x/extra.jar"));
        let cp = build_classpath(&cfg);
        if cfg!(target_os = "windows") {
            assert!(cp.contains(';'), "want ';' in classpath: {cp}");
        } else {
            assert!(cp.contains(':'), "want ':' in classpath: {cp}");
        }
        assert!(cp.ends_with("extra.jar"));
    }

    #[test]
    fn default_port_distinct_from_jcsl_and_jcardsim() {
        assert_ne!(DEFAULT_PORT, 9025, "collides with jcsl");
        assert_ne!(DEFAULT_PORT, 9125, "collides with jcardsim-wip");
    }

    // ------------------------------------------------------------------
    // Config validation: start() must reject malformed configs
    // synchronously, before forking a JVM. Exercised without a real
    // bridge installation -- the paths below are never opened.
    // ------------------------------------------------------------------

    fn synthetic_installation() -> BridgeInstallation {
        BridgeInstallation {
            bridge_jar: PathBuf::from("/nonexistent/bridge.jar"),
            jcardengine_jar: PathBuf::from("/nonexistent/jcardengine-26.04.06.jar"),
            source: crate::discovery::DiscoverySource::EnvVar,
        }
    }

    /// `JcardengineProcess` wraps a live `Child` + streams and doesn't
    /// implement `Debug`, so `Result::unwrap_err` is unavailable. Peel
    /// off the error with a match and fail if the start actually
    /// succeeded (it shouldn't -- these tests use a bogus installation).
    fn expect_start_err(cfg: &JcardengineConfig) -> io::Error {
        match JcardengineProcess::start(cfg) {
            Ok(_) => panic!("JcardengineProcess::start succeeded unexpectedly"),
            Err(e) => e,
        }
    }

    #[test]
    fn start_rejects_empty_applet_class() {
        let mut cfg = JcardengineConfig::new(synthetic_installation());
        cfg.applet_aid_hex = "F000000001".into();
        cfg.port = 19900;
        let err = expect_start_err(&cfg);
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("applet_class"));
    }

    #[test]
    fn start_rejects_empty_applet_aid() {
        let mut cfg = JcardengineConfig::new(synthetic_installation());
        cfg.applet_class = "com.example.MyApplet".into();
        cfg.port = 19901;
        let err = expect_start_err(&cfg);
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("applet_aid_hex"));
    }

    #[test]
    fn start_rejects_port_zero() {
        let mut cfg = JcardengineConfig::new(synthetic_installation());
        cfg.applet_class = "com.example.MyApplet".into();
        cfg.applet_aid_hex = "F000000001".into();
        cfg.port = 0;
        let err = expect_start_err(&cfg);
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("ephemeral"));
    }
}
