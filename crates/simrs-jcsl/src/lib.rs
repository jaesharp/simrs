//! Oracle Java Card Simulator (jcsl) interface crate.
//!
//! Provides four capabilities:
//!
//! 1. **Discovery** -- locates the jcsl binary via environment variable,
//!    XDG cache, or workspace-relative path. See [`discovery`].
//!
//! 2. **Configurator** -- patches a copy of the `jcsl` binary with SCP keys
//!    and a Global PIN, replacing the Java `Configurator.jar` tool.
//!
//! 3. **Process management** -- starts and stops the `jcsl` ELF binary,
//!    managing port allocation and `LD_LIBRARY_PATH`.
//!
//! 4. **TCP client** -- implements the Oracle RAW wire protocol and the
//!    [`simrs_transport::Transport`] trait for APDU exchange.
//!
//! # Intended use
//!
//! Differential testing: send identical APDU sequences to both simrs's
//! [`GpCard`](https://docs.rs/simrs-gp-card) and the Oracle reference
//! simulator, then compare responses byte-for-byte.
//!
//! # Architecture
//!
//! ```text
//! +------------------+      TCP (RAW protocol)      +------------------+
//! |   JcslClient     | <--------------------------> |   jcsl binary    |
//! | (Transport impl) |      port 9025               | (Oracle JC Sim)  |
//! +------------------+                               +------------------+
//!         |                                                   ^
//!         v                                                   |
//! +------------------+      configure_binary()      +------------------+
//! |   Configurator   | --------------------------> | jcsl.configured  |
//! | (binary patcher) |      SCP keys + PIN          | (patched copy)   |
//! +------------------+                               +------------------+
//! ```
//!
//! # Standards reference
//!
//! The jcsl simulator implements:
//! - Java Card v3.2 (JCVM + JCRE)
//! - `GlobalPlatform` v2.3
//! - Secure Channel Protocol '03' (SCP03)
//!
//! # `std` required
//!
//! This crate uses TCP, filesystem operations, and process management.
//! It is not `no_std`.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod configurator;
pub mod discovery;
pub mod process;
pub mod protocol;

// Re-export key types at crate root for convenience.
pub use client::JcslClient;
pub use configurator::{
    ConfigError, GlobalPin, ScpKeyset, configure_binary, configure_to_memfd, is_configured,
};
pub use discovery::{JcslInstallation, discover_binary};
pub use process::{JcslConfig, JcslProcess};
