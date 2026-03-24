//! `JavaCard` Runtime Environment core per
//! [JC RE Specification 2.1.1](../../../../telecom-standards/javacard/2.1.1/JCRESpec.pdf).
//!
//! Provides the applet plugin interface, memory model, and transaction mechanism
//! for the simrs `GlobalPlatform` card emulator. Every applet -- whether implemented
//! natively in Rust or eventually interpreted via a JCVM bytecode engine -- implements
//! the [`Applet`] trait defined here.
//!
//! # Architecture
//!
//! The JCRE sits between the GP OPEN (card manager) and individual applets:
//!
//! ```text
//! GP OPEN (AID dispatch) --> JCRE (context switch) --> Applet::process()
//! ```
//!
//! # Memory Model (JC RE 2.1.1 Chapter 5)
//!
//! Three tiers of storage, matching JCOP hardware:
//!
//! | Tier | JCOP Equivalent | Rust Type | Snapshot | Clear Event |
//! |------|----------------|-----------|----------|-------------|
//! | Persistent | EEPROM | byte array | Yes | Never |
//! | `CLEAR_ON_RESET` | RAM | [`TransientResetArray`] | No | Card reset |
//! | `CLEAR_ON_DESELECT` | RAM | [`TransientDeselectArray`] | No | Applet deselect |
//!
//! # Transaction Mechanism (JC RE 2.1.1 Chapter 7)
//!
//! [`TransactionJournal`] provides atomic multi-field updates with rollback.
//! Transaction depth is 0 or 1 (no nesting). Transient objects are excluded
//! from rollback. Auto-abort on return from applet method with active transaction.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

// Re-export modules.
pub mod applet;
pub mod memory;
pub mod transaction;

// Re-export key types at crate root for convenience.
pub use applet::{Applet, AppletResult};
pub use memory::{TransientDeselectArray, TransientResetArray};
pub use transaction::TransactionJournal;
