//! VirtIO smart card transport (guest-side driver).
//!
//! Implements `Transport` using VirtIO virtqueues, enabling a guest OS (e.g.
//! Shannon baseband firmware running in QEMU) to communicate with a simrs
//! SIM peripheral exposed on the host via the VirtIO VSOCK / custom device.
//!
//! # Standards
//! - OASIS VirtIO Specification 1.2 -- virtqueue mechanics
//! - ETSI TS 102 600 / ISO/IEC 7816-3 T=0 framing carried over virtqueue
//!
//! # `no_std`
//! This crate is fully `no_std` -- intended for bare-metal guest drivers.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
