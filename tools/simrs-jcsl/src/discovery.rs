//! Oracle jcsl binary discovery, validation, and installation.
//!
//! Provides a search chain for locating the jcsl binary, validation that
//! a candidate is a genuine (and optionally unconfigured) jcsl binary,
//! and installation from an Oracle Java Card SDK directory into the XDG
//! cache for persistent availability.
//!
//! # Discovery order
//!
//! [`discover()`] searches for the jcsl binary in this order:
//!
//! 1. `SIMRS_JCSL_BINARY` environment variable (explicit override)
//! 2. `$XDG_CACHE_HOME/simrs/jcsl` (default: `~/.cache/simrs/jcsl`)
//! 3. Workspace-relative `tools/simrs-jcsl/vendor/oracle-jcvm-ref/runtime/bin/jcsl.orig`
//!    (for development, found via `CARGO_MANIFEST_DIR`)
//!
//! # Obtaining the Oracle Java Card SDK
//!
//! The jcsl simulator is part of the Oracle Java Card Development Kit
//! Simulator. See [`ACQUISITION_GUIDE`] for instructions.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::configurator;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Expected files in the jcsl runtime directory (binary + shared libraries).
const RUNTIME_FILES: &[&str] = &["jcsl", "libcrypto.so.3", "libssl.so.3", "legacy.so"];

/// Symlinks that should exist alongside the binary.
const RUNTIME_SYMLINKS: &[(&str, &str)] = &[
    ("libcrypto.so", "libcrypto.so.3"),
    ("libssl.so", "libssl.so.3"),
];

/// Well-known path within an Oracle Java Card SDK directory.
const SDK_RUNTIME_BIN: &str = "runtime/bin/jcsl";

/// Human-readable instructions for obtaining the Oracle Java Card SDK.
pub const ACQUISITION_GUIDE: &str = "\
The jcsl simulator is part of the Oracle Java Card Development Kit Simulator,
available at no cost from Oracle (requires an Oracle account).

  1. Visit https://www.oracle.com/java/technologies/javacard-sdk-downloads.html

  2. Download the \"Java Card Development Kit Simulator\" for Linux x86.
     The file is typically named:
       java_card_kit-classic-3_2_0-linux-bin-do.zip  (or similar)

  3. Extract the archive:
       unzip java_card_kit-classic-*.zip -d /tmp/jcdk

  4. Install into the simrs cache:
       cargo run -p simrs-jcsl -- install /tmp/jcdk

     This copies the runtime files to ~/.cache/simrs/ where they are
     automatically discovered by the test harness.

  Alternatively, set the SIMRS_JCSL_BINARY environment variable to point
  directly at the jcsl binary:
       export SIMRS_JCSL_BINARY=/path/to/jcsl

Note: The jcsl binary is a 32-bit x86 Linux ELF executable. On 64-bit
systems you may need 32-bit compatibility libraries (libc6-i386 or
equivalent for your distribution).
";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How a jcsl installation was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Found via `SIMRS_JCSL_BINARY` environment variable.
    EnvVar,
    /// Found in XDG cache directory.
    XdgCache,
    /// Found relative to workspace (via `CARGO_MANIFEST_DIR`).
    Workspace,
}

impl fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvVar => write!(f, "SIMRS_JCSL_BINARY env var"),
            Self::XdgCache => write!(f, "XDG cache (~/.cache/simrs/)"),
            Self::Workspace => write!(f, "workspace (tools/simrs-jcsl/vendor/oracle-jcvm-ref/)"),
        }
    }
}

/// A validated jcsl installation.
#[derive(Debug)]
pub struct JcslInstallation {
    /// Path to the jcsl binary.
    pub binary: PathBuf,
    /// Directory containing the binary and its shared libraries.
    /// This is set as `LD_LIBRARY_PATH` when running the binary.
    pub lib_dir: PathBuf,
    /// How the installation was discovered.
    pub source: DiscoverySource,
    /// Whether the binary has SCP keys injected.
    pub scp_configured: bool,
    /// Whether the binary has a Global PIN injected.
    pub pin_configured: bool,
}

impl fmt::Display for JcslInstallation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "jcsl installation:")?;
        writeln!(f, "  binary:     {}", self.binary.display())?;
        writeln!(f, "  lib_dir:    {}", self.lib_dir.display())?;
        writeln!(f, "  source:     {}", self.source)?;
        writeln!(
            f,
            "  configured: scp={}, pin={}",
            if self.scp_configured { "yes" } else { "no" },
            if self.pin_configured { "yes" } else { "no" },
        )?;
        Ok(())
    }
}

/// Errors from validation.
#[derive(Debug)]
pub enum ValidationError {
    /// Path does not exist.
    NotFound(PathBuf),
    /// Path is not a regular file.
    NotAFile(PathBuf),
    /// File is not an ELF binary (first 4 bytes are not \x7fELF).
    NotElf(PathBuf),
    /// Binary does not contain the SCP keyset magic pattern.
    MissingSentinel(PathBuf),
    /// I/O error reading the file.
    Io(io::Error),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "not found: {}", p.display()),
            Self::NotAFile(p) => write!(f, "not a regular file: {}", p.display()),
            Self::NotElf(p) => write!(f, "not an ELF binary: {}", p.display()),
            Self::MissingSentinel(p) => {
                write!(
                    f,
                    "missing jcsl magic patterns (not a jcsl binary?): {}",
                    p.display()
                )
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ValidationError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Errors from installation.
#[derive(Debug)]
pub enum InstallError {
    /// SDK directory does not exist.
    SdkNotFound(PathBuf),
    /// SDK directory does not contain the expected runtime/bin/jcsl path.
    MissingRuntime(PathBuf),
    /// Validation of the source binary failed.
    Validation(ValidationError),
    /// I/O error during copy.
    Io(io::Error),
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SdkNotFound(p) => write!(f, "SDK directory not found: {}", p.display()),
            Self::MissingRuntime(p) => {
                write!(f, "SDK missing {SDK_RUNTIME_BIN}: {}", p.display())
            }
            Self::Validation(e) => write!(f, "validation failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for InstallError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ValidationError> for InstallError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Discover an existing jcsl installation.
///
/// Searches in order:
/// 1. `SIMRS_JCSL_BINARY` environment variable
/// 2. `$XDG_CACHE_HOME/simrs/jcsl` (default: `~/.cache/simrs/jcsl`)
/// 3. Workspace-relative `tools/simrs-jcsl/vendor/oracle-jcvm-ref/runtime/bin/jcsl.orig`
///
/// Returns `None` if no candidate exists on disk. Does not validate
/// the binary contents beyond checking existence; use [`validate()`]
/// for deeper checks.
pub fn discover() -> Option<JcslInstallation> {
    // 1. Explicit env var.
    if let Some(path) = std::env::var_os("SIMRS_JCSL_BINARY").map(PathBuf::from) {
        if path.exists() {
            return Some(build_installation(path, DiscoverySource::EnvVar));
        }
    }

    // 2. XDG cache.
    if let Some(dir) = xdg_cache_dir() {
        let candidate = dir.join("simrs").join("jcsl");
        if candidate.exists() {
            return Some(build_installation(candidate, DiscoverySource::XdgCache));
        }
    }

    // 3. Workspace-relative (CARGO_MANIFEST_DIR).
    if let Some(ws_root) = workspace_root() {
        // Prefer jcsl.orig (unconfigured backup) over jcsl (may be configured).
        for name in &["jcsl.orig", "jcsl"] {
            let candidate = ws_root
                .join("tools")
                .join("simrs-jcsl")
                .join("vendor")
                .join("runtime")
                .join("bin")
                .join(name);
            if candidate.exists() {
                return Some(build_installation(candidate, DiscoverySource::Workspace));
            }
        }
    }

    None
}

/// Return just the binary path, for callers that only need the path.
///
/// Convenience wrapper around [`discover()`].
pub fn discover_binary() -> Option<PathBuf> {
    discover().map(|inst| inst.binary)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that a path points to a genuine jcsl binary.
///
/// Checks:
/// - File exists and is a regular file
/// - Starts with ELF magic (`\x7fELF`)
/// - Contains the jcsl-specific SCP keyset magic pattern
///
/// Returns the configuration status (SCP keys, Global PIN).
///
/// # Errors
///
/// Returns a [`ValidationError`] if any check fails.
pub fn validate(path: &Path) -> Result<(bool, bool), ValidationError> {
    if !path.exists() {
        return Err(ValidationError::NotFound(path.to_path_buf()));
    }
    if !path.is_file() {
        return Err(ValidationError::NotAFile(path.to_path_buf()));
    }

    let data = fs::read(path)?;

    // Check ELF magic.
    if data.len() < 4 || &data[..4] != b"\x7fELF" {
        return Err(ValidationError::NotElf(path.to_path_buf()));
    }

    // Check for jcsl-specific sentinel patterns.
    let (scp, pin) = configurator::is_configured(&data);
    // is_configured returns true if the region is populated. But we also
    // need to verify the magic patterns exist at all. If neither magic is
    // found and neither is configured, it's not a jcsl binary.
    if !scp && !pin {
        // Check if the magic patterns are present (even if unconfigured).
        let has_scp_magic = data
            .windows(8)
            .any(|w| w == [0x3C, 0x5E, 0x5F, 0x3C, 0x41, 0x49, 0x3C, 0x3C]);
        let has_pin_magic = data
            .windows(8)
            .any(|w| w == [0x3C, 0x5C, 0x58, 0x3C, 0x41, 0x51, 0x5B, 0x3C]);

        if !has_scp_magic && !has_pin_magic {
            return Err(ValidationError::MissingSentinel(path.to_path_buf()));
        }
    }

    Ok((scp, pin))
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

/// Return the XDG cache directory for simrs.
///
/// `$XDG_CACHE_HOME/simrs/`, defaulting to `~/.cache/simrs/`.
pub fn cache_dir() -> Option<PathBuf> {
    xdg_cache_dir().map(|d| d.join("simrs"))
}

/// Install the jcsl runtime from an Oracle Java Card SDK directory
/// into the XDG cache.
///
/// Copies the binary, shared libraries, and symlinks from
/// `<sdk_dir>/runtime/bin/` to `~/.cache/simrs/`.
///
/// # Errors
///
/// Returns an [`InstallError`] if the SDK layout is unexpected,
/// the binary fails validation, or I/O operations fail.
pub fn install_from_sdk(sdk_dir: &Path) -> Result<JcslInstallation, InstallError> {
    if !sdk_dir.is_dir() {
        return Err(InstallError::SdkNotFound(sdk_dir.to_path_buf()));
    }

    let runtime_bin = sdk_dir.join("runtime").join("bin");
    let src_binary = runtime_bin.join("jcsl");
    if !src_binary.exists() {
        return Err(InstallError::MissingRuntime(sdk_dir.to_path_buf()));
    }

    // Validate the source binary.
    validate(&src_binary)?;

    let dst_dir = cache_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot determine XDG cache directory (HOME not set?)",
        )
    })?;

    fs::create_dir_all(&dst_dir)?;

    // Copy required files.
    for name in RUNTIME_FILES {
        let src = runtime_bin.join(name);
        let dst = dst_dir.join(name);
        if src.exists() {
            fs::copy(&src, &dst)?;
            // Preserve executable permission.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = fs::metadata(&src)?;
                let mode = meta.permissions().mode();
                fs::set_permissions(&dst, fs::Permissions::from_mode(mode))?;
            }
        } else {
            eprintln!("warning: expected file not found in SDK: {}", src.display());
        }
    }

    // Create symlinks.
    for (link_name, target) in RUNTIME_SYMLINKS {
        let link_path = dst_dir.join(link_name);
        // Remove existing link/file first.
        let _ = fs::remove_file(&link_path);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, &link_path)?;
        }
        #[cfg(not(unix))]
        {
            // On non-Unix, copy the file instead of symlinking.
            let src = dst_dir.join(target);
            if src.exists() {
                fs::copy(&src, &link_path)?;
            }
        }
    }

    let binary = dst_dir.join("jcsl");
    let (scp, pin) = validate(&binary)?;

    Ok(JcslInstallation {
        binary,
        lib_dir: dst_dir,
        source: DiscoverySource::XdgCache,
        scp_configured: scp,
        pin_configured: pin,
    })
}

/// Install the jcsl runtime from a standalone binary path (and its
/// sibling shared libraries) into the XDG cache.
///
/// Use this when you have the `runtime/bin/` directory contents but
/// not the full SDK.
///
/// # Errors
///
/// Returns an [`InstallError`] if the binary fails validation or I/O
/// operations fail.
pub fn install_from_binary(binary_path: &Path) -> Result<JcslInstallation, InstallError> {
    validate(binary_path)?;

    let src_dir = binary_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "binary path has no parent directory",
        )
    })?;

    let dst_dir = cache_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot determine XDG cache directory (HOME not set?)",
        )
    })?;

    fs::create_dir_all(&dst_dir)?;

    // Copy the binary itself.
    let dst_binary = dst_dir.join("jcsl");
    fs::copy(binary_path, &dst_binary)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(binary_path)?;
        fs::set_permissions(
            &dst_binary,
            fs::Permissions::from_mode(meta.permissions().mode()),
        )?;
    }

    // Copy sibling shared libraries if present.
    for name in &RUNTIME_FILES[1..] {
        let src = src_dir.join(name);
        let dst = dst_dir.join(name);
        if src.exists() {
            fs::copy(&src, &dst)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = fs::metadata(&src)?;
                fs::set_permissions(&dst, fs::Permissions::from_mode(meta.permissions().mode()))?;
            }
        }
    }

    // Create symlinks.
    for (link_name, target) in RUNTIME_SYMLINKS {
        let link_path = dst_dir.join(link_name);
        let _ = fs::remove_file(&link_path);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, &link_path)?;
        }
        #[cfg(not(unix))]
        {
            let src = dst_dir.join(target);
            if src.exists() {
                fs::copy(&src, &link_path)?;
            }
        }
    }

    let (scp, pin) = validate(&dst_binary)?;

    Ok(JcslInstallation {
        binary: dst_binary,
        lib_dir: dst_dir,
        source: DiscoverySource::XdgCache,
        scp_configured: scp,
        pin_configured: pin,
    })
}

// ---------------------------------------------------------------------------
// Status reporting
// ---------------------------------------------------------------------------

/// Print a human-readable status report to the given writer.
///
/// Reports each search location and whether it contains a valid binary.
///
/// # Errors
///
/// Returns an I/O error if writing to `w` fails.
pub fn print_status(w: &mut dyn io::Write) -> io::Result<()> {
    writeln!(w, "jcsl binary search locations:\n")?;

    // 1. Env var.
    match std::env::var_os("SIMRS_JCSL_BINARY") {
        Some(val) => {
            let path = PathBuf::from(&val);
            write!(w, "  1. SIMRS_JCSL_BINARY = {}", path.display())?;
            print_path_status(w, &path)?;
        }
        None => {
            writeln!(w, "  1. SIMRS_JCSL_BINARY  (not set)")?;
        }
    }

    // 2. XDG cache.
    match cache_dir() {
        Some(dir) => {
            let path = dir.join("jcsl");
            write!(w, "  2. {}", path.display())?;
            print_path_status(w, &path)?;
        }
        None => {
            writeln!(w, "  2. XDG cache  (HOME not set)")?;
        }
    }

    // 3. Workspace-relative.
    match workspace_root() {
        Some(ws) => {
            for name in &["jcsl.orig", "jcsl"] {
                let path = ws
                    .join("tools")
                    .join("simrs-jcsl")
                    .join("vendor")
                    .join("runtime")
                    .join("bin")
                    .join(name);
                write!(w, "  3. {}", path.display())?;
                print_path_status(w, &path)?;
            }
        }
        None => {
            writeln!(w, "  3. workspace  (CARGO_MANIFEST_DIR not set)")?;
        }
    }

    writeln!(w)?;

    // Discovery result.
    if let Some(inst) = discover() {
        writeln!(w, "Active installation (via {}):", inst.source)?;
        writeln!(w, "  binary: {}", inst.binary.display())?;
        writeln!(
            w,
            "  configured: scp={}, pin={}",
            if inst.scp_configured { "yes" } else { "no" },
            if inst.pin_configured { "yes" } else { "no" },
        )?;
    } else {
        writeln!(w, "No jcsl installation found.")?;
        writeln!(w)?;
        writeln!(w, "To obtain the Oracle Java Card Simulator:")?;
        write!(w, "{ACQUISITION_GUIDE}")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn xdg_cache_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
}

fn workspace_root() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR points to the crate's directory. For simrs-jcsl,
    // that's tools/simrs-jcsl/. The workspace root is two levels up.
    // For simrs-differential-tests, it's also tools/<name>/.
    // We try both patterns.
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .and_then(|dir| {
            // Try going up two levels (tools/<crate> -> workspace root).
            let candidate = dir.parent()?.parent()?;
            // Verify it looks like the workspace root by checking for Cargo.toml.
            if candidate.join("Cargo.toml").exists() {
                Some(candidate.to_path_buf())
            } else {
                None
            }
        })
}

fn build_installation(binary: PathBuf, source: DiscoverySource) -> JcslInstallation {
    let lib_dir = binary
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let (scp, pin) = fs::read(&binary)
        .ok()
        .map_or((false, false), |data| configurator::is_configured(&data));

    JcslInstallation {
        binary,
        lib_dir,
        source,
        scp_configured: scp,
        pin_configured: pin,
    }
}

fn print_path_status(w: &mut dyn io::Write, path: &Path) -> io::Result<()> {
    if path.exists() {
        match validate(path) {
            Ok((scp, pin)) => {
                writeln!(
                    w,
                    "  [valid, scp={}, pin={}]",
                    if scp { "configured" } else { "unconfigured" },
                    if pin { "configured" } else { "unconfigured" },
                )
            }
            Err(e) => writeln!(w, "  [invalid: {e}]"),
        }
    } else {
        writeln!(w, "  (not found)")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_cache_dir_from_home() {
        // This test relies on HOME being set, which is typical.
        if std::env::var_os("HOME").is_some() {
            let dir = xdg_cache_dir();
            assert!(dir.is_some());
            let dir = dir.unwrap();
            assert!(dir.to_string_lossy().contains(".cache") || dir.to_string_lossy().len() > 1);
        }
    }

    #[test]
    fn cache_dir_ends_with_simrs() {
        if let Some(dir) = cache_dir() {
            assert!(dir.ends_with("simrs"));
        }
    }

    #[test]
    fn validate_nonexistent() {
        let err = validate(Path::new("/nonexistent/jcsl")).unwrap_err();
        assert!(matches!(err, ValidationError::NotFound(_)));
    }

    #[test]
    fn validate_not_elf() {
        let tmp = std::env::temp_dir().join("simrs-test-not-elf");
        fs::write(&tmp, b"not an elf binary").unwrap();
        let err = validate(&tmp).unwrap_err();
        assert!(matches!(err, ValidationError::NotElf(_)));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn validate_elf_without_magic() {
        let tmp = std::env::temp_dir().join("simrs-test-no-magic");
        let mut data = vec![0u8; 1024];
        data[..4].copy_from_slice(b"\x7fELF");
        fs::write(&tmp, &data).unwrap();
        let err = validate(&tmp).unwrap_err();
        assert!(matches!(err, ValidationError::MissingSentinel(_)));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn validate_fake_jcsl() {
        let tmp = std::env::temp_dir().join("simrs-test-fake-jcsl");
        let mut data = vec![0u8; 1024];
        data[..4].copy_from_slice(b"\x7fELF");
        // Inject SCP magic at offset 100.
        let scp_magic = [0x3C, 0x5E, 0x5F, 0x3C, 0x41, 0x49, 0x3C, 0x3C];
        data[100..108].copy_from_slice(&scp_magic);
        // Inject PIN magic at offset 200.
        let pin_magic = [0x3C, 0x5C, 0x58, 0x3C, 0x41, 0x51, 0x5B, 0x3C];
        data[200..208].copy_from_slice(&pin_magic);
        fs::write(&tmp, &data).unwrap();

        let (scp, pin) = validate(&tmp).unwrap();
        assert!(!scp, "fake binary should not be scp-configured");
        assert!(!pin, "fake binary should not be pin-configured");
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn discovery_source_display() {
        assert_eq!(
            DiscoverySource::EnvVar.to_string(),
            "SIMRS_JCSL_BINARY env var"
        );
        assert_eq!(
            DiscoverySource::XdgCache.to_string(),
            "XDG cache (~/.cache/simrs/)"
        );
        assert_eq!(
            DiscoverySource::Workspace.to_string(),
            "workspace (tools/simrs-jcsl/vendor/oracle-jcvm-ref/)"
        );
    }

    #[test]
    fn print_status_does_not_panic() {
        let mut buf = Vec::new();
        print_status(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("jcsl binary search locations"));
    }

    #[test]
    fn install_error_display() {
        let err = InstallError::SdkNotFound(PathBuf::from("/tmp/nope"));
        assert!(err.to_string().contains("SDK directory not found"));
    }

    #[test]
    fn install_from_sdk_nonexistent() {
        let err = install_from_sdk(Path::new("/nonexistent/sdk")).unwrap_err();
        assert!(matches!(err, InstallError::SdkNotFound(_)));
    }

    // -------------------------------------------------------------------
    // Insta snapshots
    // -------------------------------------------------------------------

    #[test]
    fn snap_acquisition_guide() {
        insta::assert_snapshot!("acquisition_guide", ACQUISITION_GUIDE);
    }

    #[test]
    fn snap_discovery_source_display() {
        let output = format!(
            "EnvVar: {}\nXdgCache: {}\nWorkspace: {}",
            DiscoverySource::EnvVar,
            DiscoverySource::XdgCache,
            DiscoverySource::Workspace,
        );
        insta::assert_snapshot!("discovery_source_display", output);
    }

    #[test]
    fn snap_validation_error_messages() {
        let errors = [
            ValidationError::NotFound(PathBuf::from("/tmp/missing")),
            ValidationError::NotAFile(PathBuf::from("/tmp/a-directory")),
            ValidationError::NotElf(PathBuf::from("/tmp/plain.txt")),
            ValidationError::MissingSentinel(PathBuf::from("/tmp/random-elf")),
        ];
        let output: String = errors
            .iter()
            .map(|e| format!("  {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        insta::assert_snapshot!("validation_error_messages", output);
    }

    #[test]
    fn snap_install_error_messages() {
        let errors: Vec<String> = vec![
            InstallError::SdkNotFound(PathBuf::from("/opt/oracle/jcdk")).to_string(),
            InstallError::MissingRuntime(PathBuf::from("/opt/oracle/jcdk")).to_string(),
            InstallError::Validation(ValidationError::NotElf(PathBuf::from("/tmp/bad")))
                .to_string(),
        ];
        let output = errors
            .iter()
            .map(|e| format!("  {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        insta::assert_snapshot!("install_error_messages", output);
    }

    #[test]
    fn snap_installation_display() {
        let inst = JcslInstallation {
            binary: PathBuf::from("/home/user/.cache/simrs/jcsl"),
            lib_dir: PathBuf::from("/home/user/.cache/simrs"),
            source: DiscoverySource::XdgCache,
            scp_configured: false,
            pin_configured: false,
        };
        insta::assert_snapshot!("installation_display_unconfigured", inst.to_string());

        let inst2 = JcslInstallation {
            binary: PathBuf::from(
                "/workspace/tools/simrs-jcsl/vendor/oracle-jcvm-ref/runtime/bin/jcsl",
            ),
            lib_dir: PathBuf::from(
                "/workspace/tools/simrs-jcsl/vendor/oracle-jcvm-ref/runtime/bin",
            ),
            source: DiscoverySource::Workspace,
            scp_configured: true,
            pin_configured: true,
        };
        insta::assert_snapshot!("installation_display_configured", inst2.to_string());
    }

    /// Redact a single line of `print_status` output for snapshot stability.
    fn redact_status_line(line: &str) -> String {
        // Numbered search locations: "  2. /home/.../.cache/simrs/jcsl  [...]"
        if line.starts_with("  2. /") {
            let suffix = extract_bracket_suffix(line);
            format!("  2. <xdg_cache>/simrs/jcsl{suffix}")
        } else if line.starts_with("  3. /") {
            let name = if line.contains("jcsl.orig") {
                "jcsl.orig"
            } else {
                "jcsl"
            };
            let suffix = extract_bracket_suffix(line);
            format!("  3. <workspace>/tools/simrs-jcsl/vendor/oracle-jcvm-ref/runtime/bin/{name}{suffix}")
        } else if line.starts_with("  binary: /") {
            "  binary: <redacted>".to_string()
        } else {
            line.to_string()
        }
    }

    /// Extract the status suffix from a line: "  [valid, ...]" or "  (not found)".
    fn extract_bracket_suffix(line: &str) -> String {
        line.find("  [").map_or_else(
            || {
                if line.contains("(not found)") {
                    "  (not found)".to_string()
                } else {
                    String::new()
                }
            },
            |pos| line[pos..].to_string(),
        )
    }

    #[test]
    fn snap_print_status_no_env_no_binary() {
        // Run with isolated env: no SIMRS_JCSL_BINARY, point XDG to empty dir.
        let tmp = std::env::temp_dir().join("simrs-snap-status-empty");
        let _ = fs::create_dir_all(&tmp);

        // Save and clear env vars that affect discovery.
        let saved_jcsl = std::env::var_os("SIMRS_JCSL_BINARY");
        let saved_xdg = std::env::var_os("XDG_CACHE_HOME");
        std::env::remove_var("SIMRS_JCSL_BINARY");
        std::env::set_var("XDG_CACHE_HOME", &tmp);

        let mut buf = Vec::new();
        print_status(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Restore.
        if let Some(val) = saved_jcsl {
            std::env::set_var("SIMRS_JCSL_BINARY", val);
        }
        if let Some(val) = saved_xdg {
            std::env::set_var("XDG_CACHE_HOME", val);
        } else {
            std::env::remove_var("XDG_CACHE_HOME");
        }

        // Redact machine-specific paths for reproducibility.
        let redacted = output
            .lines()
            .map(redact_status_line)
            .collect::<Vec<_>>()
            .join("\n");

        insta::assert_snapshot!("print_status_no_jcsl", redacted);
        let _ = fs::remove_dir_all(&tmp);
    }
}
