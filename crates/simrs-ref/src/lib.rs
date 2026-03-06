//! Reference test vectors for SIM/USIM algorithm validation.
//!
//! This crate provides reference test vectors for cross-validation against
//! multiple reference implementations. Vectors are sourced from:
//! - [ETSI TS 135 208 V17.0.0](https://www.etsi.org/deliver/etsi_ts/135200_135299/135208/17.00.00_60/ts_135208v170000p.pdf) (Milenage)
//! - ETSI TS 135 232 (TUAK)
//! - GSM 11.11 / 3GPP TS 51.011 (COMP128v1)
//! - swsim (Osmocom C reference)
//! - Osmocom libsimutils
//!
//! # Usage
//!
//! ```ignore
//! use simrs_ref::comp128::{vectors, run_vector};
//!
//! for v in vectors() {
//!     let result = simrs_comp128::comp128(&v.ki, &v.rand);
//!     assert_eq!(result.sres, v.expected_sres);
//!     assert_eq!(result.kc, v.expected_kc);
//! }
//! ```

/// Source of reference test vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceSource {
    /// ETSI/3GPP standards body with specification name.
    Standards(&'static str),
    /// Osmocom C implementation (swsim/libsimutils).
    Osmocom,
    /// swsim reference implementation.
    Swsim,
    /// Other implementation with name.
    Other(&'static str),
}

impl ReferenceSource {
    /// Returns a description of the source.
    #[inline]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Standards(spec) => spec,
            Self::Osmocom => "Osmocom (C)",
            Self::Swsim => "swsim",
            Self::Other(name) => name,
        }
    }
}

pub mod comp128;
pub mod milenage;
pub mod tuak;
pub mod protocol;
