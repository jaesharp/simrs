//! Proactive UICC command construction (Card Application Toolkit / CAT).
//!
//! Encodes proactive commands as BER-TLV envelopes for FETCH delivery.
//! Supported commands: DISPLAY TEXT, SET UP MENU, LAUNCH BROWSER, PLAY TONE,
//! OPEN CHANNEL, SET UP CALL, SEND SHORT MESSAGE.
//!
//! # Standards
//! - ETSI TS 102 223 V17.2.0 -- Card Application Toolkit (CAT)
//! - 3GPP TS 31.111 V17.0.0 -- USIM Application Toolkit (USAT)
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
