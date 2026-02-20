//! AES-128 (Rijndael) block cipher -- encryption only.
//!
//! Self-contained implementation with no heap allocation. Used exclusively as the
//! underlying primitive for Milenage UMTS authentication.
//!
//! # Standards
//! - NIST FIPS 197 -- Advanced Encryption Standard (AES)
//! - ETSI TS 135 206 V17.0.0 annex 3 -- Rijndael as used in Milenage
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All state lives in a fixed-size `Rijndael` struct.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
