//! SIM transport abstraction trait.
//!
//! Defines the `Transport` trait that decouples the SIM simulator from any
//! specific physical or virtual channel (TCP, shared memory, `VirtIO`, etc.).
//! Implementors deliver raw APDU bytes to the simulator and return responses.
//!
//! # `no_std`, `no_alloc`
//! This crate contains only trait definitions and is fully `no_std`.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
