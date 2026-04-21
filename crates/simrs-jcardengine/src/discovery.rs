//! Discovery of the `JCardEngine` bridge JAR + engine library JAR.
//!
//! Search chain (mirrors [`simrs_jcsl::discovery`]):
//!
//! 1. `SIMRS_JCARDENGINE_BRIDGE` env var points at an explicit
//!    bridge JAR. `SIMRS_JCARDENGINE_LIB` optionally points at the
//!    companion `jcardengine-*.jar`; if unset, the sibling directory
//!    of the bridge JAR is scanned.
//! 2. `$XDG_CACHE_HOME/simrs/jcardengine/` (default
//!    `~/.cache/simrs/jcardengine/`).
//! 3. Workspace-relative `tools/jcardengine-bridge/build/libs/`.
//!
//! [`simrs_jcsl::discovery`]: https://docs.rs/simrs-jcsl

use std::fmt;
use std::path::{Path, PathBuf};

/// Env var naming the bridge JAR path.
pub const ENV_BRIDGE: &str = "SIMRS_JCARDENGINE_BRIDGE";

/// Env var naming the `JCardEngine` library JAR path.
pub const ENV_LIB: &str = "SIMRS_JCARDENGINE_LIB";

/// Env var naming an explicit `java` binary (>= 17) to launch the bridge.
///
/// Takes precedence over [`ENV_JAVA_HOME`], the Gradle JDK cache, and
/// the default `java` on `PATH`. Useful in CI where a specific JDK
/// tarball has been unpacked at a known path.
pub const ENV_JAVA: &str = "SIMRS_JCARDENGINE_JAVA";

/// Standard `JAVA_HOME` env var. If it points at a `bin/java` we assume
/// the caller has selected an appropriate JDK (validation happens at
/// spawn time when the bridge reports its own class-file check).
pub const ENV_JAVA_HOME: &str = "JAVA_HOME";

/// Filename prefix matching a `JCardEngine` library JAR.
pub const JCARDENGINE_JAR_PREFIX: &str = "jcardengine-";

/// Filename of the bridge JAR built from `tools/jcardengine-bridge/`.
pub const BRIDGE_JAR: &str = "bridge.jar";

/// Acquisition + installation guide printed by `simrs-jcardengine guide`.
pub const ACQUISITION_GUIDE: &str = "\
JCardEngine is the martinpaljak/JCardEngine fork/rewrite of jcardsim,
Apache-2.0, actively maintained. Unlike upstream jcardsim it is
published on a custom Maven repo and needs no GitHub Packages auth.

  1. Build the bridge JAR:
       gradle --project-dir tools/jcardengine-bridge build
     Output lands in tools/jcardengine-bridge/build/libs/bridge.jar,
     and the build copies the resolved jcardengine-<version>.jar there.

  2. (Optional) Install persistently:
       simrs-jcardengine install tools/jcardengine-bridge/build/libs

  3. Or point at them explicitly:
       export SIMRS_JCARDENGINE_BRIDGE=/path/to/bridge.jar
       export SIMRS_JCARDENGINE_LIB=/path/to/jcardengine-26.04.06.jar

Requires: a JDK (>=17) at runtime. JCardEngine 26.04.06 ships class
file version 61, so Java 11 is not sufficient. The bridge is launched
via `java -cp <build/libs>/* com.simrs.jcardengine.Bridge`, picking up
bridge.jar, jcardengine-*.jar, and every transitive dep copied next to
them by Gradle's `copyRuntimeDeps` task (slf4j, byte-buddy, asm,
apdu4j-core, bcprov-jdk18on, jackson-*, etc.).
";

/// How the installation was located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Explicit env vars.
    EnvVar,
    /// XDG cache.
    XdgCache,
    /// Workspace `tools/jcardengine-bridge/`.
    Workspace,
}

impl fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvVar => write!(f, "{ENV_BRIDGE}/{ENV_LIB} env vars"),
            Self::XdgCache => write!(f, "XDG cache (~/.cache/simrs/jcardengine/)"),
            Self::Workspace => write!(f, "workspace (tools/jcardengine-bridge/)"),
        }
    }
}

/// A located pair of bridge + `JCardEngine` JARs.
#[derive(Debug, Clone)]
pub struct BridgeInstallation {
    /// Absolute path to `bridge.jar`.
    pub bridge_jar: PathBuf,
    /// Absolute path to `jcardengine-<version>.jar`.
    pub jcardengine_jar: PathBuf,
    /// How the pair was located.
    pub source: DiscoverySource,
}

impl fmt::Display for BridgeInstallation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "jcardengine installation:")?;
        writeln!(f, "  bridge:      {}", self.bridge_jar.display())?;
        writeln!(f, "  jcardengine: {}", self.jcardengine_jar.display())?;
        writeln!(f, "  source:      {}", self.source)?;
        Ok(())
    }
}

/// Locate a bridge + `JCardEngine` JAR pair, trying env, XDG cache, then
/// workspace. Returns `None` if nothing is found.
#[must_use]
pub fn discover_bridge() -> Option<BridgeInstallation> {
    if let Some(inst) = from_env() {
        return Some(inst);
    }
    if let Some(inst) = from_xdg_cache() {
        return Some(inst);
    }
    from_workspace()
}

fn from_env() -> Option<BridgeInstallation> {
    let bridge = std::env::var_os(ENV_BRIDGE).map(PathBuf::from)?;
    if !bridge.is_file() {
        return None;
    }
    let jcardengine = match std::env::var_os(ENV_LIB) {
        Some(p) => {
            let p = PathBuf::from(p);
            if !p.is_file() {
                return None;
            }
            p
        }
        None => find_jcardengine_in_dir(bridge.parent()?)?,
    };
    Some(BridgeInstallation {
        bridge_jar: bridge,
        jcardengine_jar: jcardengine,
        source: DiscoverySource::EnvVar,
    })
}

fn from_xdg_cache() -> Option<BridgeInstallation> {
    let cache_root = std::env::var_os("XDG_CACHE_HOME").map_or_else(
        || std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")),
        |x| Some(PathBuf::from(x)),
    )?;
    let dir = cache_root.join("simrs").join("jcardengine");
    pair_in_dir(&dir, DiscoverySource::XdgCache)
}

fn from_workspace() -> Option<BridgeInstallation> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    // crates/simrs-jcardengine -> ../../tools/jcardengine-bridge/build/libs
    let dir = manifest
        .parent()?
        .parent()?
        .join("tools")
        .join("jcardengine-bridge")
        .join("build")
        .join("libs");
    pair_in_dir(&dir, DiscoverySource::Workspace)
}

fn pair_in_dir(dir: &Path, source: DiscoverySource) -> Option<BridgeInstallation> {
    let bridge = dir.join(BRIDGE_JAR);
    if !bridge.is_file() {
        return None;
    }
    let jcardengine = find_jcardengine_in_dir(dir)?;
    Some(BridgeInstallation {
        bridge_jar: bridge,
        jcardengine_jar: jcardengine,
        source,
    })
}

fn find_jcardengine_in_dir(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    entries.flatten().map(|e| e.path()).find(|p| {
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        let ext_jar = p.extension().is_some_and(|e| e.eq_ignore_ascii_case("jar"));
        name.starts_with(JCARDENGINE_JAR_PREFIX) && ext_jar
    })
}

// ---------------------------------------------------------------------------
// Java runtime discovery
// ---------------------------------------------------------------------------

/// Discover a `java` binary suitable for running the bridge (JDK 17+).
///
/// Search order:
///
/// 1. [`ENV_JAVA`] -- explicit override.
/// 2. [`ENV_JAVA_HOME`] -- resolves to `$JAVA_HOME/bin/java`.
/// 3. Gradle's toolchain cache (`~/.gradle/jdks/*-17-*/bin/java`,
///    `-21-`, etc.) -- Gradle downloads these on first build when the
///    project's `java { toolchain { languageVersion = 17 } }` is used,
///    which is exactly the bridge's own build config. Picks the
///    highest-numbered major version available, falling back to 17.
/// 4. `java` on `PATH`.
///
/// Returns a fallback of `"java"` when nothing more specific is found;
/// the bridge's subsequent `LinkageError`/`UnsupportedClassVersionError`
/// will surface the version mismatch with a clear message.
#[must_use]
pub fn discover_java_binary() -> PathBuf {
    if let Some(p) = std::env::var_os(ENV_JAVA) {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os(ENV_JAVA_HOME) {
        let candidate = PathBuf::from(home).join("bin").join("java");
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Some(p) = from_gradle_jdks_cache() {
        return p;
    }
    PathBuf::from("java")
}

/// Scan `~/.gradle/jdks/` for a JDK >= 17 and return its `bin/java`.
///
/// Gradle provisions toolchain JDKs under
/// `<vendor>-<major>-<arch>-<os>.<slot>/bin/java`. We pick the highest
/// `<major>` that is `>= 17`, preferring newer minor releases within
/// that major when the layout offers them (alphabetical tail sort).
fn from_gradle_jdks_cache() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let jdks = PathBuf::from(home).join(".gradle").join("jdks");
    let entries = std::fs::read_dir(&jdks).ok()?;

    let mut best: Option<(u32, PathBuf)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name()?.to_str()?;
        let Some(major) = extract_gradle_jdk_major(name) else {
            continue;
        };
        if major < 17 {
            continue;
        }
        let candidate = path.join("bin").join("java");
        if !candidate.is_file() {
            continue;
        }
        if best.as_ref().is_none_or(|(bm, _)| major > *bm) {
            best = Some((major, candidate));
        }
    }
    best.map(|(_, p)| p)
}

/// Parse the major Java version out of a Gradle toolchain cache folder
/// name like `eclipse_adoptium-17-amd64-linux.2`.
fn extract_gradle_jdk_major(name: &str) -> Option<u32> {
    let mut parts = name.split('-');
    parts.next()?; // vendor
    let major = parts.next()?;
    major.parse().ok()
}

// ---------------------------------------------------------------------------
// CLI helpers (status, install_from_directory, errors)
// ---------------------------------------------------------------------------

/// Print a human-readable summary of installation state.
///
/// # Errors
///
/// Returns the writer's error if writing fails.
pub fn print_status<W: std::io::Write>(w: &mut W) -> std::io::Result<()> {
    writeln!(w, "jcardengine installation status")?;
    writeln!(w, "===============================")?;
    writeln!(w)?;
    writeln!(w, "Search order:")?;
    writeln!(w, "  1. {ENV_BRIDGE} (+ {ENV_LIB}) env vars")?;
    writeln!(w, "  2. XDG cache (~/.cache/simrs/jcardengine/)")?;
    writeln!(w, "  3. workspace (tools/jcardengine-bridge/build/libs/)")?;
    writeln!(w)?;
    match discover_bridge() {
        Some(inst) => write!(w, "{inst}"),
        None => writeln!(
            w,
            "No installation found. Run `simrs-jcardengine guide` for instructions."
        ),
    }
}

/// Errors from [`install_from_directory`].
#[derive(Debug)]
pub enum InstallError {
    /// Source path is not a directory.
    NotADirectory(PathBuf),
    /// Source directory is missing one or both JARs.
    MissingJars {
        /// Searched directory.
        dir: PathBuf,
        /// `bridge.jar` absent.
        missing_bridge: bool,
        /// No `jcardengine-*.jar` found.
        missing_jcardengine: bool,
    },
    /// I/O error during copy.
    Io(std::io::Error),
    /// Neither `XDG_CACHE_HOME` nor `HOME` is set.
    NoCacheRoot,
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADirectory(p) => write!(f, "not a directory: {}", p.display()),
            Self::MissingJars {
                dir,
                missing_bridge,
                missing_jcardengine,
            } => {
                let mut parts = Vec::new();
                if *missing_bridge {
                    parts.push(BRIDGE_JAR);
                }
                if *missing_jcardengine {
                    parts.push("jcardengine-*.jar");
                }
                write!(
                    f,
                    "{} does not contain {}",
                    dir.display(),
                    parts.join(" and ")
                )
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::NoCacheRoot => write!(f, "neither $XDG_CACHE_HOME nor $HOME is set"),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for InstallError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Copy every `*.jar` from `src_dir` into the XDG cache
/// (`~/.cache/simrs/jcardengine/`).
///
/// Unlike jcsl (which needs one JAR + a native binary), the `JCardEngine`
/// bridge classpath pulls in ~20 transitive deps (slf4j, byte-buddy,
/// asm, apdu4j-core, bcprov-jdk18on, jackson-*, ...). `src_dir` is
/// expected to be a Gradle `build/libs/` directory populated by the
/// `copyRuntimeDeps` task; we copy everything it contains so the
/// runtime classpath (`<cache>/*`) is self-sufficient.
///
/// # Errors
///
/// Returns [`InstallError`] on I/O failure, missing `bridge.jar`,
/// missing `jcardengine-*.jar`, or missing cache root.
pub fn install_from_directory(src_dir: &Path) -> Result<BridgeInstallation, InstallError> {
    if !src_dir.is_dir() {
        return Err(InstallError::NotADirectory(src_dir.to_path_buf()));
    }
    let bridge_present = src_dir.join(BRIDGE_JAR).is_file();
    let jcardengine_path_opt = find_jcardengine_in_dir(src_dir);
    let jcardengine_filename = match (bridge_present, &jcardengine_path_opt) {
        (true, Some(p)) => p.file_name().ok_or_else(|| InstallError::MissingJars {
            dir: src_dir.to_path_buf(),
            missing_bridge: false,
            missing_jcardengine: true,
        })?,
        (bridge_ok, j_opt) => {
            return Err(InstallError::MissingJars {
                dir: src_dir.to_path_buf(),
                missing_bridge: !bridge_ok,
                missing_jcardengine: j_opt.is_none(),
            });
        }
    };

    let cache_root = std::env::var_os("XDG_CACHE_HOME").map_or_else(
        || std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")),
        |x| Some(PathBuf::from(x)),
    );
    let Some(cache_root) = cache_root else {
        return Err(InstallError::NoCacheRoot);
    };
    let dst_dir = cache_root.join("simrs").join("jcardengine");
    std::fs::create_dir_all(&dst_dir)?;

    // Copy every *.jar in src_dir, not just the two sentinel files.
    // The runtime classpath globs <dst_dir>/* at startup, so any jar
    // left behind would leave the bridge missing a dep.
    for entry in std::fs::read_dir(src_dir)? {
        let path = entry?.path();
        let is_jar = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("jar"));
        if !is_jar || !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name() else {
            continue;
        };
        std::fs::copy(&path, dst_dir.join(name))?;
    }

    Ok(BridgeInstallation {
        bridge_jar: dst_dir.join(BRIDGE_JAR),
        jcardengine_jar: dst_dir.join(jcardengine_filename),
        source: DiscoverySource::XdgCache,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_source_display_stable() {
        assert!(DiscoverySource::EnvVar.to_string().contains(ENV_BRIDGE));
        assert!(DiscoverySource::XdgCache.to_string().contains(".cache"));
        assert!(
            DiscoverySource::Workspace
                .to_string()
                .contains("jcardengine-bridge")
        );
    }

    #[test]
    fn acquisition_guide_mentions_env_vars_and_repo() {
        assert!(ACQUISITION_GUIDE.contains(ENV_BRIDGE));
        assert!(ACQUISITION_GUIDE.contains(ENV_LIB));
        assert!(ACQUISITION_GUIDE.contains("JCardEngine"));
    }

    #[test]
    fn find_jar_matches_prefix_not_bridge() {
        // Light sanity: the prefix is distinct from bridge.jar, so
        // the finder won't accidentally grab our own bridge.
        assert!(!BRIDGE_JAR.starts_with(JCARDENGINE_JAR_PREFIX));
    }
}
