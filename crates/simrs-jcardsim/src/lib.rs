//! [`licel/jcardsim`](https://github.com/licel/jcardsim) Java Card Simulator
//! interface crate -- pure-Java, Apache-2.0 reference JCVM that runs on any
//! JVM-capable platform (Linux `x86_64`/`aarch64`, macOS arm64, Windows, etc.).
//!
//! This crate is a peer of [`simrs-jcsl`](../simrs-jcsl/) and mirrors its
//! module layout so differential testing infrastructure can treat either
//! backend interchangeably.
//!
//! Four capabilities, one per module:
//!
//! 1. **Discovery** -- locates the `jcardsim-bridge.jar` (our Java host
//!    process) and the `jcardsim.jar` library via env vars, the XDG cache,
//!    or workspace-relative paths. See [`discovery`].
//!
//! 2. **Process management** -- starts `java` with both jars on the
//!    classpath, running [`com.simrs.jcardsim.Bridge`] which binds a TCP
//!    port and serves our framing protocol. See [`process`].
//!
//! 3. **Wire protocol** -- length-prefixed request/response framing that
//!    mirrors the jcsl RAW protocol in spirit (command byte + length
//!    header + payload). See [`protocol`].
//!
//! 4. **TCP client** -- implements [`simrs_transport::Transport`] on top
//!    of a connection to a running bridge. See [`client`].
//!
//! # Intended use
//!
//! Differential testing: send identical APDU sequences to simrs's
//! [`GpCard`](https://docs.rs/simrs-gp-card) and to jcardsim, then compare
//! responses byte-for-byte. Unlike jcsl, jcardsim runs anywhere a JVM
//! does, so differential coverage can extend to macOS / arm64 / Windows.
//!
//! # Architecture
//!
//! ```text
//! +------------------+      TCP (length-framed)     +----------------------+
//! | JcardsimClient   | <--------------------------> | java -cp ... Bridge  |
//! | (Transport impl) |      ephemeral port           | (jcardsim + bridge) |
//! +------------------+                                +----------------------+
//! ```
//!
//! # Standards reference
//!
//! jcardsim implements:
//! - Java Card v3.0.5 (JCVM + JCRE)
//! - `javacard.framework.*`, `javacard.security.*`, `javacardx.crypto.*`
//!
//! No `GlobalPlatform` / SCP layer in jcardsim itself -- GP functionality
//! must come from an installed applet. Acknowledged divergence from jcsl.
//!
//! # `std` required
//!
//! TCP, filesystem, process management. Not `no_std`.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod discovery;
pub mod process;
pub mod protocol;

pub use client::JcardsimClient;
pub use discovery::{ACQUISITION_GUIDE, BridgeInstallation, DiscoverySource, discover_bridge};
pub use process::{JcardsimConfig, JcardsimProcess};
