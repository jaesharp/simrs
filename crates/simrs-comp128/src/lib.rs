//! COMP128v1 (A3/A8) GSM authentication algorithm.
//!
//! Implementation of the reversed COMP128 algorithm per Briceno, Goldberg, Wagner (1998).
//! Produces SRES (4 bytes) and Kc (8 bytes) from Ki (16 bytes) and RAND (16 bytes).
//!
//! # Standards
//! - GSM 11.11 v4.21.1 clause 11 -- A3/A8 algorithm interface
//! - 3GPP TS 51.011 V4.15.0 clause 11 -- RUN GSM ALGORITHM command
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All computation is done in-place on stack buffers.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
