//! Abstracted reference-backend interface for the differential harness.
//!
//! The per-backend implementations live in sibling submodules and are
//! gated by a single feature flag each:
//!
//! | Submodule                          | Feature                 |
//! |------------------------------------|-------------------------|
//! | [`jcsl`] (Oracle `jcsl`)           | `jcsl-backend`          |
//! | [`jcardengine`] (martinpaljak JCE) | `jcardengine-backend`   |
//!
//! A build with `--no-default-features --features jcsl-backend` pulls
//! in only the jcsl module and its transitive deps; the `JCardEngine`
//! path is absent at compile time, not stubbed at runtime. At least
//! one backend feature should be active for the crate to do anything
//! meaningful — both are enabled by default.
//!
//! # Contract
//!
//! A [`ReferenceBackend`] owns a live child process (jcsl binary, or a
//! JVM hosting the `JCardEngine` bridge) and a TCP connection to it.
//! It exposes three operations the harness cares about:
//!
//! 1. [`power_on`](ReferenceBackend::power_on) — cold-reset the card and return its ATR.
//! 2. [`transmit_apdu`](ReferenceBackend::transmit_apdu) — send one APDU and return its full response.
//! 3. [`reconnect`](ReferenceBackend::reconnect) — re-establish the session after a simulated power cycle.
//!    Some backends do this implicitly; others (like jcsl) need a
//!    fresh TCP session.
//!
//! Dropping the backend terminates the child process.

use simrs_transport::TransportError;

#[cfg(feature = "jcardengine-backend")]
pub mod jcardengine;
#[cfg(feature = "jcsl-backend")]
pub mod jcsl;

#[cfg(feature = "jcardengine-backend")]
pub use jcardengine::{
    JCE_GP_APPLET_AID, JCE_GP_APPLET_CLASS, JCE_SMOKE_APPLET_AID, JCE_SMOKE_APPLET_CLASS,
    JcardengineBackend,
};
#[cfg(feature = "jcsl-backend")]
pub use jcsl::JcslBackend;

/// Uppercase hex-encode a byte slice. Uses the "no separators, no 0x
/// prefix" spelling consumed by context report entries and the
/// `--gp-master-key-hex` bridge CLI option.
pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Stable identifier for a reference backend.
///
/// Appears in generated report filenames
/// (`differential-report-<id>.xml`) and CI matrix cells -- keep the
/// string form lowercase and shell-safe. `Ord` is derived so
/// iteration order in the combined report is deterministic and
/// lexicographic.
///
/// **Every variant is always present regardless of feature flags.**
/// The enum is the identity/taxonomy of reference backends we know
/// about; the catalog, report renderers, and known-divergence
/// records can address any backend whether or not its runtime is
/// linked into the current build. Only the *execution* path —
/// spawning a child process and exchanging APDUs — requires the
/// corresponding feature. Use [`BackendId::has_runtime`] to check
/// whether a given variant can actually run in the current build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackendId {
    /// Oracle's `jcsl` binary (32-bit Linux, RAW framing). Runtime
    /// available when the `jcsl-backend` feature is enabled.
    Jcsl,
    /// martinpaljak/`JCardEngine` JVM bridge. Runtime available when
    /// the `jcardengine-backend` feature is enabled.
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
    /// Accepts every known backend name regardless of feature flags;
    /// whether the named backend can actually run is a separate
    /// question answered by [`Self::has_runtime`].
    ///
    /// # Errors
    ///
    /// Returns `Err(raw)` if `raw` does not name any known backend.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "jcsl" => Ok(Self::Jcsl),
            "jcardengine" => Ok(Self::Jcardengine),
            other => Err(other.to_string()),
        }
    }

    /// Every known backend, in deterministic (lexicographic) order.
    /// Independent of feature flags.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Jcardengine, Self::Jcsl]
    }

    /// Backends whose runtime (child-process spawn + transport) is
    /// compiled into the current build. Subset of [`Self::all`]; the
    /// difference is the set of backends the current build can *name*
    /// but cannot *execute*.
    #[must_use]
    pub fn with_runtime() -> Vec<Self> {
        Self::all()
            .iter()
            .copied()
            .filter(|b| b.has_runtime())
            .collect()
    }

    /// Whether this backend's runtime is compiled into the current
    /// build. When `false`, [`try_start_backend`] returns `None` for
    /// this variant and matrix tests skip or panic (per the caller's
    /// policy).
    #[must_use]
    pub const fn has_runtime(self) -> bool {
        match self {
            Self::Jcsl => cfg!(feature = "jcsl-backend"),
            Self::Jcardengine => cfg!(feature = "jcardengine-backend"),
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

/// Start a reference backend of the given [`BackendId`], boxed behind
/// [`ReferenceBackend`] for callers that want to dispatch dynamically.
///
/// Returns `None` when the chosen backend isn't discoverable (jcsl
/// binary missing, jcardengine bridge not built). Matrix tests
/// typically convert that to a panic via
/// [`panic_backend_not_discoverable`](crate::panic_backend_not_discoverable);
/// fast-local harnesses may prefer to skip.
///
/// The returned trait object also implements [`Transport`](simrs_transport::Transport),
/// since every `ReferenceBackend` in this crate does — downstream
/// code that needs a `Box<dyn Transport>` can obtain one via a
/// manual cast once this helper returns.
#[must_use]
pub fn try_start_backend(id: BackendId) -> Option<Box<dyn ReferenceBackend>> {
    match id {
        BackendId::Jcsl => {
            #[cfg(feature = "jcsl-backend")]
            {
                JcslBackend::try_start().map(|b| Box::new(b) as Box<dyn ReferenceBackend>)
            }
            #[cfg(not(feature = "jcsl-backend"))]
            {
                None
            }
        }
        BackendId::Jcardengine => {
            #[cfg(feature = "jcardengine-backend")]
            {
                JcardengineBackend::try_start().map(|b| Box::new(b) as Box<dyn ReferenceBackend>)
            }
            #[cfg(not(feature = "jcardengine-backend"))]
            {
                None
            }
        }
    }
}

/// Start a backend, power it on, and return it.
///
/// Convenience wrapper for the common matrix-test / standalone-harness
/// pattern — `try_start_backend` followed by `power_on()`, with the
/// power-on failure treated as a panic (a backend that spawned but
/// won't power on is a configuration problem, not a skippable one).
///
/// Returns `None` when the backend isn't discoverable at all.
///
/// # Panics
///
/// Panics if the backend spawns but `power_on` fails — that is a
/// broken runtime, not a skippable environment condition.
#[must_use]
pub fn try_start_and_power_on(id: BackendId) -> Option<Box<dyn ReferenceBackend>> {
    let mut b = try_start_backend(id)?;
    b.power_on()
        .unwrap_or_else(|e| panic!("{id} power_on failed: {e:?}"));
    Some(b)
}
