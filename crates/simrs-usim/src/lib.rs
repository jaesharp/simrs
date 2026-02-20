//! 3GPP USIM application layer.
//!
//! Handles interindustry and ETSI-class APDUs: SELECT (FCP response), STATUS,
//! VERIFY PIN, UNBLOCK PIN, UPDATE BINARY, READ BINARY, READ RECORD,
//! UPDATE RECORD, AUTHENTICATE (Milenage), TERMINAL PROFILE, FETCH,
//! TERMINAL RESPONSE, ENVELOPE.
//!
//! Constructs FCP BER-TLV per ETSI TS 102 221 clause 11.1.1.3 using a
//! dry-run/real-run pattern for buffer-size determination.
//!
//! # Standards
//! - ETSI TS 102 221 V16.4.0 -- UICC-terminal interface
//! - 3GPP TS 31.101 V17.0.0 -- UICC-terminal interface (3GPP additions)
//! - 3GPP TS 31.102 V17.5.0 -- USIM application characteristics
//!
//! # `no_std`
//! This crate is `no_std`. All buffers are const-generic sized.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;
