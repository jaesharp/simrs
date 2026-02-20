//! SIM hardware slot abstraction trait.
//!
//! Defines the `SimPeripheral` trait representing a physical or virtual SIM
//! card slot. Implementations may be: a Shannon baseband MMIO controller,
//! a Linux ioctl interface, a `VirtIO` smart card device, or a test stub.
//!
//! # `no_std`
//! This crate contains only trait definitions and is fully `no_std`.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
