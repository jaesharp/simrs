//! Top-level SIM/USIM simulator -- state machine orchestrator.
//!
//! Provides the `Sim` type: an event-driven state machine that accepts
//! `SimEvent` messages and produces `SimResponse` messages. Routes APDUs
//! to the appropriate application layer (GSM or USIM) based on the selected
//! AID and CLA byte.
//!
//! # Architecture
//! ```text
//! SimEvent::ApduReceived(bytes)
//!     -> CLA dispatch -> simrs-gsm | simrs-usim
//!     -> SimResponse::Apdu(response_bytes)
//! ```
//!
//! # `no_std`
//! This crate is `no_std`. Enable the `gsm` and/or `usim` features to include
//! the respective application layers.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;
