//! BER-TLV encoding and decoding.
//!
//! # Standards
//! - ETSI TS 101 220 V17.1.0 -- Assigned numbers and coding (BER-TLV tag assignments)
//! - ISO/IEC 8825-1 -- Basic Encoding Rules (BER)
//! - ETSI TS 102 221 V16.4.0 clause 11.1 -- FCP BER-TLV structures
//!
//! # `no_std`
//! This crate is `no_std`. Enable the `alloc` feature for heap-allocated buffers.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;
