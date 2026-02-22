//! APDU interposer/proxy/shadow SIM with PCAP capture.
//!
//! Provides three operating modes for SIM APDU analysis:
//!
//! | Mode | Description |
//! |------|-------------|
//! | **Log** | Passthrough APDUs to real SIM, write PCAP |
//! | **Shadow** | Forward to both real and simulated SIM, compare responses |
//! | **Replace** | Use simrs SIM responses instead of real SIM |
//!
//! Connects to swICC PC/SC servers via [`simrs_transport_tcp`].

// Many 3GPP/swICC terms used in docs (OPc, USIM, ATR, swICC, etc.)
#![allow(clippy::doc_markdown)]

pub mod capture;
pub mod divergence;
pub mod mode;
pub mod proxy;
pub mod shadow;
