//! Milenage UMTS authentication algorithm set (f1–f5, f1*, f5*).
//!
//! Implements the Milenage algorithm functions over AES-128 (Rijndael).
//! Produces MAC-A, RES, CK, IK, and AK from K, RAND, SQN, and AMF.
//!
//! # Standards
//! - ETSI TS 135 206 V17.0.0 -- Milenage algorithm specification
//! - ETSI TS 135 208 V17.0.0 -- Milenage test data (6 complete test sets)
//! - ETSI TS 133 102 V14.1.0 clause 6 -- 3GPP security architecture
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All Milenage state lives in a fixed-size struct.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;
