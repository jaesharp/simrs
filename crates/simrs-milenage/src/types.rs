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
    pub const fn classify(raw: [u8; 16]) -> Self {
        Self(Secret::new(raw))
    }

    /// Adopt an already-classified [`Secret`] as a [`SubscriberKey`].
    ///
    /// Use when the source is already in the secret domain (e.g. a
    /// configuration field typed as `Secret<[u8; 16]>`).
    #[inline]
    pub const fn reclassify(secret: Secret<[u8; 16]>) -> Self {
        Self(secret)
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
    /// Classify raw bytes as a [`CipherKey`].
    #[inline]
    pub const fn classify(raw: [u8; 16]) -> Self {
        Self(Secret::new(raw))
    }

    /// Adopt an already-classified [`Secret`] as a [`CipherKey`].
    #[inline]
    pub const fn reclassify(secret: Secret<[u8; 16]>) -> Self {
        Self(secret)
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
    /// Classify raw bytes as an [`IntegrityKey`].
    #[inline]
    pub const fn classify(raw: [u8; 16]) -> Self {
        Self(Secret::new(raw))
    }

    /// Adopt an already-classified [`Secret`] as an [`IntegrityKey`].
    #[inline]
    pub const fn reclassify(secret: Secret<[u8; 16]>) -> Self {
        Self(secret)
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
    /// Classify raw bytes as a [`GsmCipherKey`].
    #[inline]
    pub(crate) const fn classify(raw: [u8; 8]) -> Self {
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

// ---------------------------------------------------------------------------
// Authentication domain newtypes (3GPP TS 33.102 V19.1.0 clause 6.3)
//
// These wrap wire-transmitted values (not secrets) in domain-specific
// names. Plain wrappers without Secret protection.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AuthChallenge (RAND)
// ---------------------------------------------------------------------------

/// Random challenge value used as input to all f1--f5 functions (128 bits).
///
/// A fresh random value generated by the network (AuC/HSS/AUSF) for each
/// authentication attempt. Wire-transmitted, not secret.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthChallenge([u8; 16]);

impl AuthChallenge {
    /// Create a new `AuthChallenge` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 16]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for AuthChallenge {
    fn from(raw: [u8; 16]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`AuthChallenge`].
///
/// The specs (TS 33.102 clause 6.3) use "RAND" (Random challenge).
/// We prefer `AuthChallenge` because it describes the value's role
/// without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP RAND (TS 33.102 6.3) -- prefer AuthChallenge")]
pub type Rand = AuthChallenge;

// ---------------------------------------------------------------------------
// SequenceNumber (SQN)
// ---------------------------------------------------------------------------

/// Authentication sequence number (48 bits).
///
/// Maintained by the AuC and USIM to detect replay attacks. Monotonically
/// increasing; each successful authentication increments it.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceNumber([u8; 6]);

impl SequenceNumber {
    /// Create a new `SequenceNumber` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 6]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for SequenceNumber {
    fn from(raw: [u8; 6]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`SequenceNumber`].
///
/// The specs (TS 33.102 clause 6.3) use "SQN" (Sequence Number).
/// We prefer `SequenceNumber` because it describes the value's role
/// without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP SQN (TS 33.102 6.3) -- prefer SequenceNumber")]
pub type Sqn = SequenceNumber;

// ---------------------------------------------------------------------------
// AuthManagementField (AMF)
// ---------------------------------------------------------------------------

/// Authentication management field (16 bits).
///
/// Carries operator-specific flags and the AMF separation bit (bit 0 of
/// the first byte) used to distinguish 3G/4G/5G authentication vectors.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthManagementField([u8; 2]);

impl AuthManagementField {
    /// Create a new `AuthManagementField` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 2]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 2] {
        &self.0
    }
}

impl From<[u8; 2]> for AuthManagementField {
    fn from(raw: [u8; 2]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`AuthManagementField`].
///
/// The specs (TS 33.102 clause 6.3) use "AMF" (Authentication Management
/// Field). We prefer `AuthManagementField` because it describes the value's
/// role without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP AMF (TS 33.102 6.3) -- prefer AuthManagementField")]
pub type Amf = AuthManagementField;

// ---------------------------------------------------------------------------
// AuthResponse (RES)
// ---------------------------------------------------------------------------

/// Authentication response (64 bits, f2 output).
///
/// Computed by the USIM and sent to the network to prove knowledge of the
/// subscriber key K. The network compares it against XRES.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthResponse([u8; 8]);

impl AuthResponse {
    /// Create a new `AuthResponse` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 8]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl From<[u8; 8]> for AuthResponse {
    fn from(raw: [u8; 8]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`AuthResponse`].
///
/// The specs (TS 33.102 clause 6.3) use "RES" (Authentication Response).
/// We prefer `AuthResponse` because it describes the value's role
/// without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP RES (TS 33.102 6.3) -- prefer AuthResponse")]
pub type Res = AuthResponse;

// ---------------------------------------------------------------------------
// NetworkMac (MAC-A)
// ---------------------------------------------------------------------------

/// Network authentication MAC (64 bits, f1 output).
///
/// Computed by the network and included in AUTN. The USIM verifies it
/// to authenticate the network. Comparison MUST be constant-time.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkMac([u8; 8]);

impl NetworkMac {
    /// Create a new `NetworkMac` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 8]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl From<[u8; 8]> for NetworkMac {
    fn from(raw: [u8; 8]) -> Self {
        Self(raw)
    }
}

impl CtEq for NetworkMac {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        simrs_consttime::ct_eq(&self.0, &other.0)
    }
}

/// 3GPP abbreviation for [`NetworkMac`].
///
/// The specs (TS 33.102 clause 6.3) use "MAC-A" (Network Authentication
/// MAC). We prefer `NetworkMac` because it describes the value's role
/// without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP MAC-A (TS 33.102 6.3) -- prefer NetworkMac")]
pub type MacA = NetworkMac;

// ---------------------------------------------------------------------------
// ResyncMac (MAC-S)
// ---------------------------------------------------------------------------

/// Resynchronization MAC (64 bits, f1* output).
///
/// Computed by the USIM and included in AUTS when the sequence number is
/// out of range. Comparison MUST be constant-time.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResyncMac([u8; 8]);

impl ResyncMac {
    /// Create a new `ResyncMac` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 8]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl From<[u8; 8]> for ResyncMac {
    fn from(raw: [u8; 8]) -> Self {
        Self(raw)
    }
}

impl CtEq for ResyncMac {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        simrs_consttime::ct_eq(&self.0, &other.0)
    }
}

/// 3GPP abbreviation for [`ResyncMac`].
///
/// The specs (TS 33.102 clause 6.3) use "MAC-S" (Resynchronization MAC).
/// We prefer `ResyncMac` because it describes the value's role
/// without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP MAC-S (TS 33.102 6.3) -- prefer ResyncMac")]
pub type MacS = ResyncMac;

// ---------------------------------------------------------------------------
// AnonymityKey (AK)
// ---------------------------------------------------------------------------

/// Anonymity key (48 bits, f5/f5* output).
///
/// Used to conceal the sequence number in AUTN and AUTS:
/// `AUTN[0..6] = SQN XOR AK`. The name is already semantically clear,
/// so no deprecated alias is provided.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymityKey([u8; 6]);

impl AnonymityKey {
    /// Create a new `AnonymityKey` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 6]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for AnonymityKey {
    fn from(raw: [u8; 6]) -> Self {
        Self(raw)
    }
}

// ---------------------------------------------------------------------------
// ResyncToken (AUTS)
// ---------------------------------------------------------------------------

/// Resynchronization token (112 bits).
///
/// Constructed by the USIM when SQN verification fails:
/// `AUTS = (SQN_MS XOR AK*) || MAC-S` (14 bytes).
/// Sent to the network so it can resynchronize SQN.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3.5](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResyncToken([u8; 14]);

impl ResyncToken {
    /// Create a new `ResyncToken` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 14]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 14] {
        &self.0
    }
}

impl From<[u8; 14]> for ResyncToken {
    fn from(raw: [u8; 14]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`ResyncToken`].
///
/// The specs (TS 33.102 clause 6.3.5) use "AUTS" (Authentication
/// Resynchronisation Token). We prefer `ResyncToken` because it describes
/// the value's role without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP AUTS (TS 33.102 6.3.5) -- prefer ResyncToken")]
pub type Auts = ResyncToken;

// ---------------------------------------------------------------------------
// AuthToken (AUTN)
// ---------------------------------------------------------------------------

/// Authentication token from the network (128 bits).
///
/// `AUTN = (SQN XOR AK) || AMF || MAC-A` (16 bytes).
/// Sent by the network so the USIM can verify it and recover SQN.
///
/// Per [3GPP TS 33.102 V19.1.0 clause 6.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthToken([u8; 16]);

impl AuthToken {
    /// Create a new `AuthToken` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 16]) -> Self {
        Self(raw)
    }
    /// View the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for AuthToken {
    fn from(raw: [u8; 16]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`AuthToken`].
///
/// The specs (TS 33.102 clause 6.3) use "AUTN" (Authentication Token).
/// We prefer `AuthToken` because it describes the value's role
/// without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP AUTN (TS 33.102 6.3) -- prefer AuthToken")]
pub type Autn = AuthToken;
