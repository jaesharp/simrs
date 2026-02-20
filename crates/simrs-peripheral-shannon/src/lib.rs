//! Samsung Shannon baseband SIM peripheral interface.
//!
//! Implements `SimPeripheral` for the Shannon baseband SIM controller.
//! The Shannon SIM hardware is exposed to the guest OS via MMIO registers;
//! simrs replaces the hardware with a `VirtIO` control device on the host,
//! intercepting APDU traffic at the HLE boundary.
//!
//! # Architecture
//! ```text
//! Shannon firmware (ARM guest in QEMU)
//!   -> MMIO write to SIM_TX register
//!   -> QEMU MMIO trap
//!   -> simrs-peripheral-shannon (host)
//!   -> simrs-transport-virtio (virtqueue)
//!   -> simrs-sim (APDU processing)
//! ```
//!
//! # `no_std`
//! This crate is `no_std`. MMIO register definitions are compile-time constants.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
