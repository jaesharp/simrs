//! PIN/PUK management state machine.
//!
//! Implements VERIFY PIN (INS=20), CHANGE PIN (INS=24), DISABLE PIN (INS=26),
//! ENABLE PIN (INS=28), and UNBLOCK PIN / RESET RETRY COUNTER (INS=2C).
//! Tracks retry counters, blocked state, and enabled/disabled flag per PIN key.
//!
//! # Standards
//! - ETSI TS 102 221 V16.4.0 clause 11.1.9 -- VERIFY PIN
//! - ETSI TS 102 221 V16.4.0 clause 11.1.12 -- RESET RETRY COUNTER
//! - 3GPP TS 31.102 V17.5.0 clause 6.2 -- PIN management
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
