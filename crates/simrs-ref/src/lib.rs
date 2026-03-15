//! Reference test vectors for SIM/USIM algorithm validation.
//!
//! This crate provides reference test vectors for cross-validation against
//! multiple reference implementations. Vectors are sourced from:
//! - [ETSI TS 135 208 V19.0.0](../../../docs/specs/3gpp/ts-35.208/ts_135208v190000p.pdf) (Milenage)
//! - [ETSI TS 135 232 V19.0.0](../../../docs/specs/3gpp/ts-35.232/ts_135232v190000p.pdf) (TUAK)
//! - [3GPP TS 51.011 V4.15.0](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf) (COMP128v1)
//! - swsim (Osmocom C reference)
//! - Osmocom libsimutils
//!
//! # Usage
//!
//! ```ignore
//! use simrs_ref::comp128::vectors;
//! use simrs_secret::Secret;
//!
//! for v in vectors() {
//!     let result = simrs_comp128::comp128(&Secret::new(v.ki), &v.rand);
//!     assert_eq!(result.signed_response, v.expected_sres);
//!     assert_eq!(*result.cipher_key.declassify_ref(), v.expected_kc);
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
pub mod protocol;
pub mod tuak;
