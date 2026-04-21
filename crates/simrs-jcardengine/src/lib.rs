//! [`martinpaljak/JCardEngine`](https://github.com/martinpaljak/JCardEngine)
//! Java Card Runtime Engine interface crate.
//!
//! `JCardEngine` is an Apache-2.0 fork (April 2024) of licel/jcardsim,
//! actively maintained and published auth-free on `mvn.javacard.pro`.
//! Use it as a reference JCVM alongside [`simrs-jcsl`] for differential
//! testing.
//!
//! # Module layout (mirrors [`simrs-jcsl`])
//!
//! 1. [`discovery`] -- locate `bridge.jar` + `jcardengine-*.jar` via
//!    env vars (`SIMRS_JCARDENGINE_BRIDGE`/`_LIB`), `XDG_CACHE_HOME`,
//!    or a workspace-relative Gradle build output.
//! 2. [`process`] -- spawn the Java bridge JVM, watch its stdout for
//!    `LISTENING <port>`, drain stderr into a shared buffer so Java
//!    exceptions surface in our error messages.
//! 3. [`protocol`] -- 4-byte framing protocol (command byte +
//!    reserved + big-endian u16 length + payload), identical in shape
//!    to `simrs-jcsl`'s Oracle RAW wire protocol so dump tools
//!    interoperate.
//! 4. [`client`] -- [`simrs_transport::Transport`] implementation
//!    over the bridge TCP connection.
//!
//! # Architecture
//!
//! ```text
//! +-----------------------+    TCP (length-framed)   +-----------------------+
//! | JcardengineClient     | <----------------------> | java -cp ... Bridge   |
//! | (Transport impl)      |   ephemeral port         | (`JCardEngine` + glue)|
//! +-----------------------+                          +-----------------------+
//!                                                              |
//!                                                              v
//!                                                    stderr -> Rust buffer
//!                                                    stdout "LISTENING <port>"
//! ```
//!
//! # Relationship to simrs-jcardsim (jcardsim-wip branch)
//!
//! An earlier iteration on `jcardsim-wip` wrapped `licel/jcardsim` with
//! the same architecture. Two reasons to prefer `JCardEngine` here:
//!
//! - Auth-free Maven repo (mvn.javacard.pro). jcardsim's upstream is
//!   GitHub Packages only, which demands a PAT even for public reads.
//! - Active upstream: `JCardEngine` ships a release every 1-2 weeks.
//!
//! Lessons folded in from the jcardsim-wip iteration: stdout-scan port
//! readiness (instead of polling) and stderr draining (so we can
//! actually diagnose bridge crashes).
//!
//! [`simrs-jcsl`]: https://docs.rs/simrs-jcsl
//!
//! # `std` required
//!
//! Uses TCP, filesystem, and process management; not `no_std`.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod discovery;
pub mod process;
pub mod protocol;

pub use client::JcardengineClient;
pub use discovery::{
    ACQUISITION_GUIDE, BridgeInstallation, DiscoverySource, discover_bridge,
    install_from_directory, print_status,
};
pub use process::{JcardengineConfig, JcardengineProcess};
