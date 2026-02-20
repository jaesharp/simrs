//! Shared-memory SIM transport.
//!
//! Implements `Transport` using a shared-memory ring buffer. Suitable for
//! low-latency APDU exchange between a QEMU host process and simrs, or
//! between two processes on the same machine.
//!
//! # `no_std` + platform
//! Core logic is `no_std`. Platform integration (mmap, futex) is gated behind
//! the `std` feature and compiled only for supported targets.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
