//! ISO/IEC 7816 APDU types, CLA parsing, and status words.
//!
//! # Standards
//! - ISO/IEC 7816-4:2020 -- Organization, security, and commands for interchange
//! - ETSI TS 102 221 V16.4.0 clause 10.1.1 -- UICC-terminal interface CLA byte
//! - GSM 11.11 v4.21.1 clause 9 -- ME-SIM interface
//! - 3GPP TS 51.011 V4.15.0 clause 9 -- CLA class A0
//!
//! # `no_std`
//! This crate is `no_std`. Enable the `std` feature for `std::error::Error` impls.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;
