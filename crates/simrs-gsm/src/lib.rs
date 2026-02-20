//! GSM 11.11 SIM application layer.
//!
//! Handles GSM-class (CLA=0xA0) APDUs: SELECT, GET RESPONSE, READ BINARY,
//! STATUS, RUN GSM ALGORITHM (COMP128 A3/A8), UPDATE BINARY.
//! Constructs GSM 11.11 clause 9.2.1 SELECT response (23 bytes DF / 15 bytes EF).
//!
//! # Standards
//! - GSM 11.11 v4.21.1 (ETS 300 608) -- ME-SIM interface
//! - 3GPP TS 51.011 V4.15.0 -- SIM-ME interface (successor to GSM 11.11)
//!
//! # `no_std`
//! This crate is `no_std`.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
