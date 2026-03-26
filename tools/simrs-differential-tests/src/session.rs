//! Builder-pattern front-end for configuring differential test sessions.
//!
//! [`DiffSession`] wraps the interposer's [`DiffEngine`] with ergonomic
//! backend configuration and automatic resource management (jcsl processes,
//! temp files). It is the primary entry point for replay-based differential
//! tests.
//!
//! # Example
//!
//! ```rust,ignore
//! let mut session = DiffSession::builder("my-test")
//!     .simrs_gp_card()
//!     .try_oracle_jcsl()
//!     .build()
//!     .expect("jcsl not available");
//!
//! let results = session.replay_one(&apdu);
//! session.print_summary();
//! ```

use crate::{GpCardTerminal, KEY_BYTES, next_port};
use simrs_gp_card::GpCard;
use simrs_gp_keys::KeySet;
use simrs_interposer::diff::{DiffEngine, DiffRecord};
use simrs_interposer::divergence::{CompareResult, DivergenceStats};
use simrs_jcsl::configurator::{GlobalPin, ScpKeyset};
use simrs_jcsl::{JcslClient, JcslProcess};
use simrs_transport::{Transport, TransportError};

// -------------------------------------------------------------------------
// Builder
// -------------------------------------------------------------------------

/// Specification for a backend to be materialized at build time.
enum PendingBackend {
    /// In-process `GpCard` with optional custom keys.
    SimrsGpCard { keys: Option<KeySet> },
    /// Oracle jcsl over TCP (requires `SIMRS_JCSL_BINARY`).
    OracleJcsl,
    /// Pre-constructed `Transport`.
    Custom {
        label: String,
        transport: Box<dyn Transport<Error = TransportError>>,
    },
}

/// Builder for configuring a [`DiffSession`].
///
/// Backends are added incrementally and materialized when [`build()`](Self::build)
/// is called. If any `try_*` backend is unavailable, `build()` returns `None`
/// so the calling test can skip gracefully.
#[must_use]
pub struct DiffSessionBuilder {
    #[allow(dead_code)] // kept for API compatibility; was used for temp file naming
    label: String,
    pending: Vec<PendingBackend>,
    skipped: bool,
    scp_keys: [u8; 16],
    pin: Vec<u8>,
}

impl DiffSessionBuilder {
    fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            pending: Vec::new(),
            skipped: false,
            scp_keys: KEY_BYTES,
            pin: vec![0x31, 0x32, 0x33, 0x34],
        }
    }

    /// Add an in-process [`GpCard`] backend using the configured SCP keys.
    ///
    /// The card is powered on automatically.
    pub fn simrs_gp_card(mut self) -> Self {
        self.pending.push(PendingBackend::SimrsGpCard { keys: None });
        self
    }

    /// Add an in-process [`GpCard`] backend with explicit keys.
    ///
    /// The card is powered on automatically.
    pub fn simrs_gp_card_with_keys(mut self, keys: KeySet) -> Self {
        self.pending
            .push(PendingBackend::SimrsGpCard { keys: Some(keys) });
        self
    }

    /// Try to add an Oracle jcsl backend.
    ///
    /// Uses [`discover_jcsl_binary()`](crate::discover_jcsl_binary) to locate
    /// the jcsl binary. If no binary is found, the session is marked as
    /// skipped and [`build()`](Self::build) will return `None`.
    pub fn try_oracle_jcsl(mut self) -> Self {
        if simrs_jcsl::discover_binary().is_some() {
            self.pending.push(PendingBackend::OracleJcsl);
        } else {
            self.skipped = true;
        }
        self
    }

    /// Add a pre-constructed [`Transport`] backend.
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

    /// Override the SCP key material used for both simrs and Oracle.
    ///
    /// Default: [`KEY_BYTES`] (`0x40..0x4F`).
    pub const fn scp_keys(mut self, keys: [u8; 16]) -> Self {
        self.scp_keys = keys;
        self
    }

    /// Override the Global PIN used for Oracle jcsl configuration.
    ///
    /// Default: `[0x31, 0x32, 0x33, 0x34]` ("1234").
    pub fn global_pin(mut self, pin: Vec<u8>) -> Self {
        self.pin = pin;
        self
    }

    /// Build the session, materializing all backends.
    ///
    /// Returns `None` if any `try_*` backend was unavailable.
    ///
    /// # Panics
    ///
    /// Panics if a required external process (e.g., jcsl) fails to start.
    pub fn build(self) -> Option<DiffSession> {
        if self.skipped {
            return None;
        }

        let mut engine = DiffEngine::new();
        let mut resources = SessionResources::default();

        for backend in self.pending {
            match backend {
                PendingBackend::SimrsGpCard { keys } => {
                    let keyset = keys.unwrap_or_else(|| {
                        KeySet::des3_2key(self.scp_keys, self.scp_keys, self.scp_keys)
                    });
                    let card = GpCard::with_default_atr(&keyset);
                    let mut terminal = GpCardTerminal::new(card);
                    terminal.power_on();
                    engine.add_backend("simrs", Box::new(terminal));
                }
                PendingBackend::OracleJcsl => {
                    let src = simrs_jcsl::discover_binary()
                        .expect("jcsl binary checked in try_oracle_jcsl");

                    let port = next_port();
                    let keyset = ScpKeyset {
                        kvn: 0x01,
                        enc: self.scp_keys.to_vec(),
                        mac: self.scp_keys.to_vec(),
                        dek: self.scp_keys.to_vec(),
                    };
                    let gpin = GlobalPin {
                        pin: self.pin.clone(),
                        max_retries: 3,
                    };

                    let proc = JcslProcess::start_configured(
                        &src,
                        Some(&keyset),
                        Some(&gpin),
                        port,
                        "info",
                        std::time::Duration::from_secs(10),
                    )
                    .expect("failed to start jcsl");

                    let mut client = JcslClient::connect(&format!("127.0.0.1:{port}"))
                        .expect("failed to connect to jcsl");
                    client.power_on().expect("Oracle power_on failed");

                    engine.add_backend("oracle", Box::new(client));
                    resources.jcsl_processes.push(proc);
                }
                PendingBackend::Custom { label, transport } => {
                    engine.add_backend(label, transport);
                }
            }
        }

        Some(DiffSession {
            engine,
            _resources: resources,
        })
    }
}

// -------------------------------------------------------------------------
// Session
// -------------------------------------------------------------------------

/// Managed resources that are cleaned up when the session is dropped.
///
/// Jcsl processes are killed on drop via [`JcslProcess::drop`].
/// No temp files are created (binaries are executed from memfd).
#[derive(Default)]
struct SessionResources {
    /// Jcsl process handles (killed on drop via `JcslProcess::drop`).
    jcsl_processes: Vec<JcslProcess>,
}

/// A configured differential test session.
///
/// Wraps the interposer's [`DiffEngine`] with resource management for
/// jcsl processes and temporary files. Created via [`DiffSession::builder()`].
///
/// All replay and comparison methods delegate to the underlying [`DiffEngine`].
pub struct DiffSession {
    engine: DiffEngine,
    /// Held for Drop: kills jcsl processes and cleans up temp files.
    _resources: SessionResources,
}

impl DiffSession {
    /// Create a new builder for a differential test session.
    ///
    /// `label` is used for temp file naming and diagnostics.
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
