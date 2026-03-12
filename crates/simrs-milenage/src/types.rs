//! Semantic newtypes for 3GPP authentication key material.
//!
//! These types wrap raw byte arrays in domain-specific names with
//! [`Secret`] protection for sensitive values. Changing the inner
//! representation (e.g. adding zeroization) requires updating only
//! the type definition, not every consumer site.
//!
//! # Standards
//!
//! - [3GPP TS 33.102 V19.1.0](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf) -- security architecture (K, CK, IK, Kc definitions)
//! - [3GPP TS 35.206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf) -- Milenage algorithm specification

use simrs_consttime::{CtBool, CtEq};
use simrs_redact::Redact;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// SubscriberKey (K)
// ---------------------------------------------------------------------------

/// Subscriber authentication key K (128 bits).
///
/// The long-term shared secret between the USIM and the Authentication
/// Centre (AuC). All 3GPP authentication functions (f1--f5) derive their
/// outputs from K. K must never be exposed outside the secure domain.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy)]
pub struct SubscriberKey(Secret<[u8; 16]>);

impl SubscriberKey {
    /// Classify a raw 128-bit key as a [`SubscriberKey`].
    #[inline]
    pub const fn new(k: Secret<[u8; 16]>) -> Self {
        Self(k)
    }

    /// Borrow the raw key bytes.
    ///
    /// Each call site is a visible acknowledgement that secret key material
    /// is being accessed. Used inside algorithm implementations and for
    /// snapshot serialization.
    #[inline]
    pub const fn declassify(&self) -> &[u8; 16] {
        self.0.declassify_ref()
    }

    /// Borrow the inner [`Secret`] for passing to cryptographic primitives
    /// (e.g. Rijndael) without first declassifying.
    #[inline]
    pub const fn as_secret(&self) -> &Secret<[u8; 16]> {
        &self.0
    }
}

impl CtEq for SubscriberKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for SubscriberKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SubscriberKey").field(&Redact(self.0.declassify_ref())).finish()
    }
}

// ---------------------------------------------------------------------------
// CipherKey (CK)
// ---------------------------------------------------------------------------

/// Cipher key CK (128 bits, f3 output).
///
/// Session key for radio bearer encryption (3G) or as input to KASME
/// derivation (4G/5G).
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy)]
pub struct CipherKey(Secret<[u8; 16]>);

impl CipherKey {
    /// Wrap raw bytes as a [`CipherKey`].
    #[inline]
    pub(crate) const fn new(raw: [u8; 16]) -> Self {
        Self(Secret::new(raw))
    }

    /// Construct a [`CipherKey`] from a raw 128-bit byte array.
    ///
    /// Public equivalent of the crate-internal `new` constructor, for use by
    /// sibling algorithm crates (e.g. `simrs-tuak`) that compute CK outside
    /// `simrs-milenage`.
    #[inline]
    pub const fn from_bytes(raw: [u8; 16]) -> Self {
        Self(Secret::new(raw))
    }

    /// Borrow the raw key bytes.
    ///
    /// Each call site is a visible acknowledgement that secret key material
    /// is leaving the protected domain -- typically for APDU encoding or
    /// key derivation (C3, KASME).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 16] {
        self.0.declassify_ref()
    }
}

impl CtEq for CipherKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("CipherKey").field(&Redact(self.0.declassify_ref())).finish()
    }
}

// ---------------------------------------------------------------------------
// IntegrityKey (IK)
// ---------------------------------------------------------------------------

/// Integrity key IK (128 bits, f4 output).
///
/// Session key for radio bearer integrity protection (3G) or as input
/// to KASME derivation (4G/5G).
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy)]
pub struct IntegrityKey(Secret<[u8; 16]>);

impl IntegrityKey {
    /// Wrap raw bytes as an [`IntegrityKey`].
    #[inline]
    pub(crate) const fn new(raw: [u8; 16]) -> Self {
        Self(Secret::new(raw))
    }

    /// Construct an [`IntegrityKey`] from a raw 128-bit byte array.
    ///
    /// Public equivalent of the crate-internal `new` constructor, for use by
    /// sibling algorithm crates (e.g. `simrs-tuak`) that compute IK outside
    /// `simrs-milenage`.
    #[inline]
    pub const fn from_bytes(raw: [u8; 16]) -> Self {
        Self(Secret::new(raw))
    }

    /// Borrow the raw key bytes.
    ///
    /// Each call site is a visible acknowledgement that secret key material
    /// is leaving the protected domain -- typically for APDU encoding or
    /// key derivation (C3, KASME).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 16] {
        self.0.declassify_ref()
    }
}

impl CtEq for IntegrityKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for IntegrityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IntegrityKey").field(&Redact(self.0.declassify_ref())).finish()
    }
}

// ---------------------------------------------------------------------------
// GsmCipherKey (Kc)
// ---------------------------------------------------------------------------

/// GSM cipher key Kc (64 bits, C3 conversion of CK and IK).
///
/// Session key for A5/1 or A5/3 stream cipher encryption in UMTS-GSM
/// interworking. Derived as `Kc[i] = CK[i] ^ CK[i+8] ^ IK[i] ^ IK[i+8]`.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.8.1.2](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy)]
pub struct GsmCipherKey(Secret<[u8; 8]>);

impl GsmCipherKey {
    /// Wrap raw bytes as a [`GsmCipherKey`].
    #[inline]
    pub(crate) const fn new(raw: [u8; 8]) -> Self {
        Self(Secret::new(raw))
    }

    /// Borrow the raw key bytes.
    ///
    /// Each call site is a visible acknowledgement that secret key material
    /// is leaving the protected domain -- typically for APDU encoding.
    #[inline]
    pub const fn declassify(&self) -> &[u8; 8] {
        self.0.declassify_ref()
    }
}

impl CtEq for GsmCipherKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for GsmCipherKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GsmCipherKey").field(&Redact(self.0.declassify_ref())).finish()
    }
}
