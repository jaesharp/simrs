//! ICC filesystem model: MF, DF, ADF, and EF nodes.
//!
//! Provides a hierarchical, arena-allocated (or const-static) filesystem tree
//! matching the UICC file system per ETSI TS 102 221. Selection context tracks
//! the current MF, DF, ADF, and EF across SELECT operations.
//!
//! # Standards
//! - ETSI TS 102 221 V16.4.0 clause 8 -- File system structure
//! - 3GPP TS 31.102 V17.5.0 clause 4 -- USIM file system
//! - GSM 11.11 v4.21.1 clause 10 -- SIM file system
//!
//! # `no_std`
//! This crate is `no_std`. The filesystem can be defined as `const` statics.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;
