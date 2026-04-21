//! Builder-pattern front-end for configuring differential test sessions.
//!
//! [`DiffSession`] wraps the interposer's [`DiffEngine`] with ergonomic
//! backend configuration. Reference backends are instantiated through
//! the [`ReferenceBackend`] factories in [`crate::reference`]; those
//! types already own their child processes (killed on drop) and
//! implement [`Transport`], so the session just boxes them into the
//! engine's backend registry -- no duplicated spawn logic here.
//!
//! # Scope
//!
//! Supports both Oracle `jcsl` and martinpaljak/`JCardEngine` as
//! managed reference backends. [`DualCard`](crate::DualCard) is the
//! [`ReferenceBackend`](crate::ReferenceBackend)-generic harness used
//! by the report generator; the session builder builds on the same
//! factories so both harnesses share one spawn path.
//!
//! # Example
//!
//! ```rust,ignore
//! let mut session = DiffSession::builder("my-test")
//!     .simrs_gp_card()
//!     .try_oracle_jcsl()        // or .try_jcardengine()
//!     .build()
//!     .expect("reference backend not available");
//!
//! let results = session.replay_one(&apdu);
//! session.print_summary();
//! ```

#[cfg(feature = "jcardengine-backend")]
use crate::reference::JcardengineBackend;
#[cfg(feature = "jcsl-backend")]
use crate::reference::JcslBackend;
use crate::{GpCardTerminal, KEY_BYTES, ReferenceBackend};
use simrs_gp_card::GpCard;
use simrs_gp_keys::KeySet;
use simrs_interposer::diff::{DiffEngine, DiffRecord};
use simrs_interposer::divergence::{CompareResult, DivergenceStats};
use simrs_transport::{Transport, TransportError};

// -------------------------------------------------------------------------
// Builder
// -------------------------------------------------------------------------

/// Specification for a backend to be materialised at build time.
///
/// Reference-backend variants eagerly own their spawned processes and
/// powered-on clients; `build()` just moves them into the [`DiffEngine`].
enum PendingBackend {
    /// In-process `GpCard` using the default SCP keys.
    SimrsGpCard,
    /// A pre-spawned, powered-on reference backend. Boxed behind
    /// [`Transport`] so jcsl and jcardengine share one slot.
    Reference {
        label: String,
        backend: Box<dyn Transport<Error = TransportError>>,
    },
    /// A user-supplied transport (used by the custom-transport branch
    /// of the builder for non-differential test harnesses).
    Custom {
        label: String,
        transport: Box<dyn Transport<Error = TransportError>>,
    },
}

/// Builder for configuring a [`DiffSession`].
///
/// Backends are added incrementally and materialised when
/// [`build()`](Self::build) is called. If any `try_*` backend is
/// unavailable, `build()` returns `None` so the calling test can skip
/// gracefully; matrix callers should treat `None` as a configuration
/// error and panic via [`panic_backend_not_discoverable`].
///
/// [`panic_backend_not_discoverable`]: crate::panic_backend_not_discoverable
#[must_use]
pub struct DiffSessionBuilder {
    #[allow(dead_code)] // diagnostic surface kept for future use
    label: String,
    pending: Vec<PendingBackend>,
    skipped: bool,
}

impl DiffSessionBuilder {
    fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            pending: Vec::new(),
            skipped: false,
        }
    }

    /// Add an in-process [`GpCard`] backend using the default SCP keys.
    ///
    /// The card is powered on automatically at [`build()`](Self::build).
    pub fn simrs_gp_card(mut self) -> Self {
        self.pending.push(PendingBackend::SimrsGpCard);
        self
    }

    /// Try to add an Oracle jcsl reference backend.
    ///
    /// Delegates to [`JcslBackend::try_start`]. If the jcsl binary is
    /// not discoverable the session is marked as skipped and
    /// [`build()`](Self::build) will return `None`; matrix callers
    /// should convert that into a panic so misconfigured CI fails
    /// loudly.
    ///
    /// # Panics
    ///
    /// If the jcsl binary is discoverable but the spawned process
    /// fails to complete a cold-reset (`power_on`). This indicates a
    /// broken jcsl binary, not a skippable environment issue.
    #[cfg(feature = "jcsl-backend")]
    pub fn try_oracle_jcsl(mut self) -> Self {
        match JcslBackend::try_start() {
            Some(mut backend) => {
                backend
                    .power_on()
                    .expect("jcsl power_on after try_start failed");
                self.pending.push(PendingBackend::Reference {
                    label: backend.backend_id().as_str().to_owned(),
                    backend: Box::new(backend),
                });
            }
            None => self.skipped = true,
        }
        self
    }

    /// Try to add a martinpaljak/`JCardEngine` reference backend.
    ///
    /// Delegates to [`JcardengineBackend::try_start`]. If the bridge
    /// installation isn't discoverable the session is marked as
    /// skipped and [`build()`](Self::build) will return `None`.
    ///
    /// # Panics
    ///
    /// If the bridge JAR is discoverable but the spawned JVM fails to
    /// complete a cold-reset (`power_on`). This indicates a broken
    /// bridge build, not a skippable environment issue.
    #[cfg(feature = "jcardengine-backend")]
    pub fn try_jcardengine(mut self) -> Self {
        match JcardengineBackend::try_start() {
            Some(mut backend) => {
                backend
                    .power_on()
                    .expect("jcardengine power_on after try_start failed");
                self.pending.push(PendingBackend::Reference {
                    label: backend.backend_id().as_str().to_owned(),
                    backend: Box::new(backend),
                });
            }
            None => self.skipped = true,
        }
        self
    }

    /// Add a pre-constructed [`Transport`] backend. Intended for
    /// non-differential harnesses that want the [`DiffEngine`]
    /// comparison machinery with their own transports.
    pub fn transport(
        mut self,
        label: &str,
        transport: Box<dyn Transport<Error = TransportError>>,
    ) -> Self {
        self.pending.push(PendingBackend::Custom {
            label: label.to_owned(),
            transport,
        });
        self
    }

    /// Build the session, materialising all backends.
    ///
    /// Returns `None` if any `try_*` backend was unavailable.
    #[must_use]
    pub fn build(self) -> Option<DiffSession> {
        if self.skipped {
            return None;
        }

        let mut engine = DiffEngine::new();
        for backend in self.pending {
            match backend {
                PendingBackend::SimrsGpCard => {
                    let keyset = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
                    let card = GpCard::with_default_atr(&keyset);
                    let mut terminal = GpCardTerminal::new(card);
                    terminal.power_on();
                    engine.add_backend("simrs", Box::new(terminal));
                }
                PendingBackend::Reference { label, backend } => {
                    engine.add_backend(label, backend);
                }
                PendingBackend::Custom { label, transport } => {
                    engine.add_backend(label, transport);
                }
            }
        }

        Some(DiffSession { engine })
    }
}

// -------------------------------------------------------------------------
// Session
// -------------------------------------------------------------------------

/// A configured differential test session.
///
/// Wraps the interposer's [`DiffEngine`]. Reference backends own their
/// child processes via their [`ReferenceBackend`] types; dropping the
/// session drops the engine, drops each backend box, and kills the
/// underlying processes via their respective `Drop` impls.
pub struct DiffSession {
    engine: DiffEngine,
}

impl DiffSession {
    /// Create a new builder for a differential test session.
    ///
    /// `label` is used for diagnostics.
    pub fn builder(label: &str) -> DiffSessionBuilder {
        DiffSessionBuilder::new(label)
    }

    /// Replay a single APDU through all backends and compare pairwise.
    pub fn replay_one(&mut self, cmd: &[u8]) -> Vec<CompareResult> {
        self.engine.replay_one(cmd)
    }

    /// Replay a sequence of APDUs through all backends.
    pub fn replay_sequence(&mut self, cmds: &[&[u8]]) -> &DivergenceStats {
        self.engine.replay_sequence(cmds)
    }

    /// Replay a single APDU with semantic (schema-aware) comparison.
    pub fn replay_one_semantic(
        &mut self,
        cmd: &[u8],
    ) -> Vec<simrs_interposer::semantic::SemanticResult> {
        self.engine.replay_one_semantic(cmd)
    }

    /// Access semantic comparison statistics.
    pub const fn semantic_stats(&self) -> &simrs_interposer::diff::SemanticDivergenceStats {
        &self.engine.semantic_stats
    }

    /// Print a human-readable summary to stderr.
    pub fn print_summary(&self) {
        self.engine.print_summary();
    }

    /// Access accumulated comparison statistics.
    pub const fn stats(&self) -> &DivergenceStats {
        &self.engine.stats
    }

    /// Access recorded divergences.
    pub fn divergences(&self) -> &[DiffRecord] {
        &self.engine.divergences
    }

    /// Access the underlying [`DiffEngine`] directly.
    pub const fn engine(&self) -> &DiffEngine {
        &self.engine
    }

    /// Mutably access the underlying [`DiffEngine`].
    pub const fn engine_mut(&mut self) -> &mut DiffEngine {
        &mut self.engine
    }
}
