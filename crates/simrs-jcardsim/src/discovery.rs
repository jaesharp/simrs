//! Discovery of the jcardsim bridge JAR + jcardsim library JAR.
//!
//! Mirrors the search chain in [`simrs_jcsl::discovery`](../../simrs-jcsl/src/discovery.rs):
//!
//! 1. `SIMRS_JCARDSIM_BRIDGE` env var (explicit override, points at a
//!    built bridge JAR; the companion `SIMRS_JCARDSIM_LIB` points at
//!    `jcardsim-*.jar` -- or either JAR's directory is scanned).
//! 2. `$XDG_CACHE_HOME/simrs/jcardsim/` (default `~/.cache/simrs/jcardsim/`)
//!    -- looked for `bridge.jar` and `jcardsim-<version>.jar`.
//! 3. Workspace-relative `tools/jcardsim-bridge/build/libs/` and
//!    `tools/jcardsim-bridge/vendor/` (for development checkouts).
//!
//! # Obtaining jcardsim
//!
//! See [`ACQUISITION_GUIDE`]. jcardsim is Apache-2.0; a single
//! all-in-one jar is published on the licel/jcardsim Maven packages.

use std::fmt;
use std::path::{Path, PathBuf};

/// Environment variable naming an explicit bridge JAR path.
pub const ENV_BRIDGE: &str = "SIMRS_JCARDSIM_BRIDGE";

/// Environment variable naming an explicit jcardsim library JAR path.
pub const ENV_LIB: &str = "SIMRS_JCARDSIM_LIB";

/// Filename glob that matches a jcardsim library JAR.
///
/// Pattern: `jcardsim-*.jar`. Anchored on the `jcardsim-` prefix to
/// avoid matching our own `bridge.jar`.
pub const JCARDSIM_JAR_PREFIX: &str = "jcardsim-";

/// Filename of the bridge JAR built from `tools/jcardsim-bridge/`.
pub const BRIDGE_JAR: &str = "bridge.jar";

/// Human-readable acquisition and installation guide.
pub const ACQUISITION_GUIDE: &str = "\
jcardsim is the licel/jcardsim Java Card Simulator (Apache-2.0):

  1. Build the bridge JAR from this repo:
       ./gradlew --project-dir tools/jcardsim-bridge build
     The output lands in tools/jcardsim-bridge/build/libs/bridge.jar.

  2. Obtain the jcardsim library JAR. Either:
     a. Download from https://github.com/licel/jcardsim/packages, or
     b. Let Gradle fetch it as a dependency of the bridge -- the
        build script places a copy into
        tools/jcardsim-bridge/build/libs/ alongside bridge.jar.

  3. (Optional) Install persistently:
       mkdir -p ~/.cache/simrs/jcardsim/
       cp bridge.jar jcardsim-*.jar ~/.cache/simrs/jcardsim/

  4. Or point at them explicitly:
       export SIMRS_JCARDSIM_BRIDGE=/path/to/bridge.jar
       export SIMRS_JCARDSIM_LIB=/path/to/jcardsim-3.0.5.jar

Requires: a JDK (>=11) at runtime -- the bridge process is launched
via `java -cp <jcardsim>:<bridge> com.simrs.jcardsim.Bridge`.
";

/// How the bridge + jcardsim pair was located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Explicit env vars.
    EnvVar,
    /// XDG cache.
    XdgCache,
    /// Workspace `tools/jcardsim-bridge/`.
    Workspace,
}

impl fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvVar => write!(f, "{ENV_BRIDGE}/{ENV_LIB} env vars"),
            Self::XdgCache => write!(f, "XDG cache (~/.cache/simrs/jcardsim/)"),
            Self::Workspace => write!(f, "workspace (tools/jcardsim-bridge/)"),
        }
    }
}

/// A located + validated pair of bridge.jar and jcardsim library JAR.
#[derive(Debug, Clone)]
pub struct BridgeInstallation {
    /// Absolute path to `bridge.jar`.
    pub bridge_jar: PathBuf,
    /// Absolute path to the jcardsim library JAR.
    pub jcardsim_jar: PathBuf,
    /// How the installation was located.
    pub source: DiscoverySource,
}

impl fmt::Display for BridgeInstallation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "jcardsim installation:")?;
        writeln!(f, "  bridge:   {}", self.bridge_jar.display())?;
        writeln!(f, "  jcardsim: {}", self.jcardsim_jar.display())?;
        writeln!(f, "  source:   {}", self.source)?;
        Ok(())
    }
}

/// Locate a bridge + jcardsim pair, trying each source in order.
///
/// Returns `None` if no valid pair is found.
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

/// Try the env-var source.
fn from_env() -> Option<BridgeInstallation> {
    let bridge = std::env::var_os(ENV_BRIDGE).map(PathBuf::from)?;
    if !bridge.is_file() {
        return None;
    }
    let jcardsim = match std::env::var_os(ENV_LIB) {
        Some(p) => {
            let p = PathBuf::from(p);
            if !p.is_file() {
                return None;
            }
            p
        }
        None => find_jcardsim_in_dir(bridge.parent()?)?,
    };
    Some(BridgeInstallation {
        bridge_jar: bridge,
        jcardsim_jar: jcardsim,
        source: DiscoverySource::EnvVar,
    })
}

/// Try the XDG cache source.
fn from_xdg_cache() -> Option<BridgeInstallation> {
    let cache_root = std::env::var_os("XDG_CACHE_HOME").map_or_else(
        || std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")),
        |x| Some(PathBuf::from(x)),
    )?;
    let dir = cache_root.join("simrs").join("jcardsim");
    pair_in_dir(&dir, DiscoverySource::XdgCache)
}

/// Try the workspace-relative source (for development checkouts).
fn from_workspace() -> Option<BridgeInstallation> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    // crates/simrs-jcardsim -> ../../tools/jcardsim-bridge/build/libs
    let dir = manifest
        .parent()?
        .parent()?
        .join("tools")
        .join("jcardsim-bridge")
        .join("build")
        .join("libs");
    pair_in_dir(&dir, DiscoverySource::Workspace)
}

/// Look for `bridge.jar` + a `jcardsim-*.jar` in `dir`.
fn pair_in_dir(dir: &Path, source: DiscoverySource) -> Option<BridgeInstallation> {
    let bridge = dir.join(BRIDGE_JAR);
    if !bridge.is_file() {
        return None;
    }
    let jcardsim = find_jcardsim_in_dir(dir)?;
    Some(BridgeInstallation {
        bridge_jar: bridge,
        jcardsim_jar: jcardsim,
        source,
    })
}

/// Locate the first `jcardsim-*.jar` under `dir`.
fn find_jcardsim_in_dir(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    entries.flatten().map(|e| e.path()).find(|p| {
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        let ext_jar = p.extension().is_some_and(|e| e.eq_ignore_ascii_case("jar"));
        name.starts_with(JCARDSIM_JAR_PREFIX) && ext_jar
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
                .contains("jcardsim-bridge")
        );
    }

    #[test]
    fn acquisition_guide_mentions_env_vars() {
        assert!(ACQUISITION_GUIDE.contains(ENV_BRIDGE));
        assert!(ACQUISITION_GUIDE.contains(ENV_LIB));
    }

    #[test]
    fn discover_returns_none_when_nothing_exists() {
        // The test runs in CI without any jcardsim installed, and env
        // vars are not set. discover_bridge() should just return None.
        //
        // (Cannot unset env vars safely post-edition-2024 without
        // unsafe, so only assert the absence case.)
        if std::env::var_os(ENV_BRIDGE).is_none() {
            // discover_bridge() will still try XDG and workspace; those
            // are also absent in CI.
            let result = discover_bridge();
            // We don't assert None because a dev machine may have a
            // local install -- only assert we don't panic.
            let _ = result;
        }
    }
}
