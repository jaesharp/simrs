//! Milenage UMTS authentication algorithm set (f1--f5, f1\*, f5\*).
//!
//! Implements the Milenage algorithm functions over AES-128 (Rijndael).
//! Produces MAC-A, RES, CK, IK, and AK from K, RAND, SQN, and AMF.
//!
//! # Algorithm Structure
//!
//! All functions share a common core: `TEMP = E_K[RAND XOR OPc]` where E_K is
//! AES-128 encryption under key K. Each function then computes:
//!
//! ```text
//! OUT_i = E_K[rot(TEMP XOR OPc, r_i) XOR c_i] XOR OPc
//! ```
//!
//! where (c_i, r_i) are per-function constants and `rot` is 128-bit left rotation.
//!
//! | Function | Output | Bytes | Extracted from | Uses |
//! |----------|--------|-------|----------------|------|
//! | f1       | MAC-A  | 8     | OUT1[0..8]     | (c1, r1) |
//! | f1\*     | MAC-S  | 8     | OUT1[8..16]    | (c1, r1) |
//! | f2       | RES    | 8     | OUT2[8..16]    | (c2, r2) |
//! | f3       | CK     | 16    | OUT3[0..16]    | (c3, r3) |
//! | f4       | IK     | 16    | OUT4[0..16]    | (c4, r4) |
//! | f5       | AK     | 6     | OUT2[0..6]     | (c2, r2) -- shares computation with f2 |
//! | f5\*     | AK\*   | 6     | OUT5[0..6]     | (c5, r5) |
//!
//! # Default Constants ([3GPP TS 35.206 V19.0.0 clause 4](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A28%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D))
//!
//! | Constant | Value | Notes |
//! |----------|-------|-------|
//! | c1 | `00...00` (128 zero bits) | Even parity (recommended) |
//! | c2 | `00...01` | Odd parity (recommended) |
//! | c3 | `00...02` | Odd parity |
//! | c4 | `00...04` | Odd parity |
//! | c5 | `00...08` | Odd parity |
//! | r1 | 64 bits | |
//! | r2 | 0 bits | |
//! | r3 | 32 bits | |
//! | r4 | 64 bits | |
//! | r5 | 96 bits | |
//!
//! Per clause 5.3: all (c_i, r_i) pairs must be distinct.
//!
//! # OPc Computation
//!
//! `OPc = E_K[OP] XOR OP` ([ETSI TS 135 206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf) Annex 1)
//!
//! OPc can be pre-computed off-card and stored directly, or computed on-card
//! from OP. The [`OperatorVariant`] enum represents both options.
//!
//! # Standards
//! - [ETSI TS 135 206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf) -- Milenage algorithm specification
//! - [ETSI TS 135 208 V19.0.0](../../../docs/specs/3gpp/ts-35.208/ts_135208v190000p.pdf) -- Milenage test data (6 complete test sets)
//! - [3GPP TS 33.102 V19.1.0 clause 6](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf#%5B%7B%22num%22%3A46%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C360%5D) -- 3GPP security architecture
//! - [3GPP TS 31.102 V19.4.0 clause 7.1.2.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A754%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C330%5D) -- AUTHENTICATE response
//!
//! # 3GPP Authentication Glossary
//!
//! These abbreviations from [3GPP TS 33.102 V19.1.0](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf) / [3GPP TS 35.206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf) appear throughout the
//! code. Several look similar (especially AUTN vs AUTS) but are distinct:
//!
//! | Abbreviation | Full Name | Bytes | Direction | Description |
//! |--------------|-----------|-------|-----------|-------------|
//! | RAND  | Random Challenge | 16 | Network -> USIM | Fresh random value from the network |
//! | AUTN  | Authentication Token | 16 | Network -> USIM | `(SQN XOR AK) \|\| AMF \|\| MAC-A` |
//! | AUTS  | Authentication Resynchronisation Token | 14 | USIM -> Network | `(SQN_MS XOR AK*) \|\| MAC-S` |
//! | SQN   | Sequence Number | 6 | (internal) | 48-bit counter for replay protection |
//! | SQN_HE | Sequence Number -- Home Environment | 6 | (USIM state) | Next expected SQN (replay threshold) |
//! | SQN_MS | Sequence Number -- Mobile Station | 6 | (in AUTS) | USIM's current SQN sent during resync |
//! | AMF   | Authentication Management Field | 2 | (in AUTN) | Operator-defined; bit 0 = separation bit |
//! | AK    | Anonymity Key | 6 | (derived) | f5 output; masks SQN in AUTN |
//! | AK*   | Resynch Anonymity Key | 6 | (derived) | f5\* output; masks SQN_MS in AUTS |
//! | MAC-A | Message Authentication Code -- Authentication | 8 | (in AUTN) | f1 output; network proves knowledge of K |
//! | MAC-S | Message Authentication Code -- Resync | 8 | (in AUTS) | f1\* output; authenticates resync request |
//! | XMAC-A | Expected MAC-A | 8 | (computed) | USIM's locally computed MAC-A for comparison |
//! | RES   | Authentication Response | 8 | USIM -> Network | f2 output; USIM proves knowledge of K |
//! | CK    | Cipher Key | 16 | (derived) | f3 output; radio bearer encryption |
//! | IK    | Integrity Key | 16 | (derived) | f4 output; radio bearer integrity |
//! | Kc    | GSM Cipher Key | 8 | (derived) | C3 conversion of CK/IK for 2G interworking |
//! | OP    | Operator Parameter | 16 | (provisioned) | Operator-specific constant |
//! | OPc   | Operator Cipher | 16 | (derived/stored) | `E_K[OP] XOR OP`; pre-computed OP variant |
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All state lives in [`MilenageParams`].
//!
//! # Example
//!
//! ```
//! use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
//! use simrs_secret::Secret;
//!
//! // ETSI TS 135 208 V19.0.0 Test Set 1 (clause 4.3.1)
//! let k    = [0x46,0x5B,0x5C,0xE8,0xB1,0x99,0xB4,0x9F,
//!             0xAA,0x5F,0x0A,0x2E,0xE2,0x38,0xA6,0xBC];
//! let opc  = [0xCD,0x63,0xCB,0x71,0x95,0x4A,0x9F,0x4E,
//!             0x48,0xA5,0x99,0x4E,0x37,0xA0,0x2B,0xAF];
//! let rand = [0x23,0x55,0x3C,0xBE,0x96,0x37,0xA8,0x9D,
//!             0x21,0x8A,0xE6,0x4D,0xAE,0x47,0xBF,0x35];
//! let sqn  = [0xFF,0x9B,0xB4,0xD0,0xB6,0x07];
//! let amf  = [0xB9,0xB9];
//!
//! let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new(opc)));
//!
//! assert_eq!(params.compute_auth_mac(&rand, &sqn, &amf),
//!            [0x4A,0x9F,0xFA,0xC3,0x54,0xDF,0xAF,0xB3]);
//! assert_eq!(params.compute_response(&rand),
//!            [0xA5,0x42,0x11,0xD5,0xE3,0xBA,0x50,0xBF]);
//! assert_eq!(params.compute_anonymity_key(&rand),
//!            [0xAA,0x68,0x9C,0x64,0x83,0x70]);
//! ```
//!
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// Milenage documentation uses many standard 3GPP terms (OPc, MAC-A, AuC, etc.)
// that clippy flags as needing backticks. These are domain-specific nomenclature,
// not Rust identifiers.
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

mod types;
pub use types::{CipherKey, GsmCipherKey, IntegrityKey, SubscriberKey};

// ct_eq is used in the AuthenticationAlgorithm::authenticate default method for
// constant-time MAC-A comparison (3GPP TS 33.102 V19.1.0 timing side-channel requirement).
// Both MilenageParams and TuakParams inherit this through the trait default.
use simrs_consttime::ct_eq;
use simrs_rijndael::Rijndael;
use simrs_redact::Redact;
use simrs_secret::Secret;

/// Operator variant: either raw OP (computed to OPc on-card) or pre-computed OPc.
///
/// # Standards
/// - [3GPP TS 35.206 V19.0.0 clause 5.1](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A30%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C624%5D) -- recommends pre-computing OPc off-card
/// - [ETSI TS 135 206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf) Annex 1 -- OPc computation: `OPc = E_K[OP] XOR OP`
///
/// ```
/// use simrs_milenage::OperatorVariant;
/// use simrs_secret::Secret;
///
/// // Pre-computed OPc (recommended for production)
/// let _opc = OperatorVariant::opc(Secret::new([0xCD; 16]));
///
/// // Raw OP (OPc computed at runtime from K and OP)
/// let _op = OperatorVariant::op(Secret::new([0xAB; 16]));
/// ```
#[derive(Clone, Copy)]
pub enum OperatorVariant {
    /// Pre-computed OPc (128 bits). Preferred -- avoids runtime AES call.
    Opc(Secret<[u8; 16]>),
    /// Raw OP. OPc will be derived as `E_K[OP] XOR OP` when needed.
    Op(Secret<[u8; 16]>),
}

impl OperatorVariant {
    /// Classify raw bytes as [`OperatorVariant::Opc`].
    #[inline]
    pub const fn opc(k: Secret<[u8; 16]>) -> Self {
        Self::Opc(k)
    }

    /// Classify raw bytes as [`OperatorVariant::Op`].
    #[inline]
    pub const fn op(k: Secret<[u8; 16]>) -> Self {
        Self::Op(k)
    }
}

impl core::fmt::Debug for OperatorVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Opc(v) => f.debug_tuple("OperatorVariant::Opc").field(&Redact(v.declassify_ref())).finish(),
            Self::Op(v) => f.debug_tuple("OperatorVariant::Op").field(&Redact(v.declassify_ref())).finish(),
        }
    }
}

/// Milenage algorithm parameters.
///
/// Contains the subscriber key K, the operator variant (OP or OPc), and the
/// per-function rotation/XOR constants (c1-c5, r1-r5).
///
/// # Construction
///
/// Use [`MilenageParams::with_defaults`] for the standard [ETSI TS 135 206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf) constants,
/// or [`MilenageParams::new`] for custom operator-chosen values.
///
/// ```
/// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
/// use simrs_secret::Secret;
///
/// let params = MilenageParams::with_defaults(
///     SubscriberKey::new(Secret::new([0xFF; 16])),  // K
///     OperatorVariant::opc(Secret::new([0xAA; 16])), // OPc
/// );
/// ```
#[derive(Clone)]
pub struct MilenageParams {
    /// Subscriber key K (128 bits).
    k: SubscriberKey,
    /// Pre-computed OPc (128 bits). Derived from OP if OperatorVariant::Op was given.
    opc: Secret<[u8; 16]>,
    /// Per-function XOR constants c1..c5 (128 bits each).
    ci: [[u8; 16]; 5],
    /// Per-function rotation constants r1..r5 (in bits).
    ri: [u8; 5],
    /// Next expected SQN (big-endian 48-bit counter).
    ///
    /// Tracks the USIM's replay protection state per [3GPP TS 33.102 V19.1.0 clause 6.3.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C557%5D).
    /// After a successful AUTHENTICATE with SQN=N, this advances to N+1.
    /// Initialized to zero (all SQNs accepted on first authentication).
    expected_sequence_number: [u8; 6],
}

impl core::fmt::Debug for MilenageParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MilenageParams")
            .field("k", &self.k) // SubscriberKey::Debug always prints [REDACTED]
            .field("opc", &Redact(self.opc.declassify_ref()))
            .field("ci", &self.ci)
            .field("ri", &self.ri)
            .field("expected_sequence_number", &self.expected_sequence_number)
            .finish()
    }
}

impl Default for MilenageParams {
    fn default() -> Self {
        Self::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])))
    }
}

/// Successful authentication output.
///
/// Per [3GPP TS 31.102 V19.4.0 clause 7.1.2.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A754%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C330%5D), the successful AUTHENTICATE
/// response (tag `0xDB`) contains RES, CK, IK, and optionally Kc.
///
/// ```
/// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey, AuthenticationAlgorithm};
/// use simrs_secret::Secret;
///
/// // Obtain an AuthenticationOutput from a real authentication.
/// let mut p = MilenageParams::with_defaults(
///     SubscriberKey::new(Secret::new([0u8; 16])),
///     OperatorVariant::opc(Secret::new([0u8; 16])),
/// );
/// let rand = [0u8; 16];
/// let sqn = [0u8; 6];
/// let amf = [0u8; 2];
/// let ak = p.compute_anonymity_key(&rand);
/// let mut autn = [0u8; 16];
/// for i in 0..6 { autn[i] = sqn[i] ^ ak[i]; }
/// autn[6..8].copy_from_slice(&amf);
/// autn[8..16].copy_from_slice(&p.compute_auth_mac(&rand, &sqn, &amf));
/// let out = p.authenticate(&rand, &autn).unwrap();
/// assert_eq!(out.response.len(), 8);
/// assert_eq!(out.cipher_key.declassify().len(), 16);
/// assert_eq!(out.integrity_key.declassify().len(), 16);
/// assert_eq!(out.gsm_cipher_key.declassify().len(), 8);
/// ```
#[derive(Clone, Copy)]
pub struct AuthenticationOutput {
    /// RES: authentication response (8 bytes, f2 output).
    /// Sent to the network to prove knowledge of K.
    pub response: [u8; 8],

    /// CK: ciphering key (16 bytes, f3 output).
    /// Used for radio bearer encryption (3G) or as input to KASME derivation (4G/5G).
    pub cipher_key: CipherKey,

    /// IK: integrity key (16 bytes, f4 output).
    /// Used for radio bearer integrity (3G) or as input to KASME derivation (4G/5G).
    pub integrity_key: IntegrityKey,

    /// Kc: GSM ciphering key (8 bytes, C3 conversion of CK and IK).
    /// For UMTS-GSM interworking per [3GPP TS 33.102 V19.1.0 clause 6.8.1.2](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf#%5B%7B%22num%22%3A98%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C250%5D).
    /// `Kc[i] = CK[i] XOR CK[i+8] XOR IK[i] XOR IK[i+8]` for i in 0..8.
    pub gsm_cipher_key: GsmCipherKey,
}

impl core::fmt::Debug for AuthenticationOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthenticationOutput")
            .field("response", &self.response)
            .field("cipher_key", &self.cipher_key)      // CipherKey::Debug prints [REDACTED]
            .field("integrity_key", &self.integrity_key) // IntegrityKey::Debug prints [REDACTED]
            .field("gsm_cipher_key", &self.gsm_cipher_key) // GsmCipherKey::Debug prints [REDACTED]
            .finish()
    }
}

/// Authentication error.
///
/// Per [3GPP TS 31.102 V19.4.0 clause 7.1.2.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A754%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C330%5D):
/// - MAC failure: XMAC-A != MAC-A from AUTN -> SW `98 62`
/// - Sync failure: SQN out of range -> tag `0xDC` with 14-byte AUTS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationError {
    /// MAC-A verification failed. The network's authentication token is invalid.
    /// USIM returns SW `98 62`.
    MacFailure,

    /// SQN is outside the acceptable range. Contains AUTS for resynchronization.
    /// AUTS = `(SQN_MS XOR AK*) || MAC-S` (14 bytes).
    /// USIM returns tag `0xDC` with AUTS.
    SyncFailure {
        /// AUTS resynchronization token (14 bytes).
        resync_token: [u8; 14],
    },
}

impl core::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MacFailure => f.write_str("MAC failure"),
            Self::SyncFailure { .. } => f.write_str("SQN out of range"),
        }
    }
}

/// Parameter validation error.
///
/// Per [3GPP TS 35.206 V19.0.0 clause 5.3](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A32%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C787%5D), all (c_i, r_i) pairs must be distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// Two or more (c_i, r_i) pairs are identical.
    DuplicateCiRi {
        /// Index of the first duplicate (0-based: 0=c1/r1, 4=c5/r5).
        first: u8,
        /// Index of the second duplicate.
        second: u8,
    },
}

impl core::fmt::Display for ParamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateCiRi { first, second } => {
                write!(f, "duplicate (Ci, Ri) constant pair at indices {first} and {second}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot cursor helpers
// ---------------------------------------------------------------------------

pub(crate) struct SnapWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SnapWriter<'a> {
    pub(crate) const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn put_bytes(&mut self, src: &[u8]) {
        self.buf[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
    }
    pub(crate) const fn finish(self) -> usize {
        self.pos
    }
}

pub(crate) struct SnapReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SnapReader<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn get_bytes(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.buf[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a 6-byte big-endian SQN to a u64.
#[allow(clippy::trivially_copy_pass_by_ref)] // consistent with other Milenage helpers taking &[u8; N]
pub(crate) const fn u48_from_be(b: &[u8; 6]) -> u64 {
    (b[0] as u64) << 40
        | (b[1] as u64) << 32
        | (b[2] as u64) << 24
        | (b[3] as u64) << 16
        | (b[4] as u64) << 8
        | (b[5] as u64)
}

/// Convert a u64 (lower 48 bits) to a 6-byte big-endian SQN.
#[allow(clippy::cast_possible_truncation)] // intentional: extracting individual bytes from u64
pub(crate) const fn u48_to_be(val: u64) -> [u8; 6] {
    let v = val & 0x0000_FFFF_FFFF_FFFF;
    [
        (v >> 40) as u8,
        (v >> 32) as u8,
        (v >> 24) as u8,
        (v >> 16) as u8,
        (v >> 8) as u8,
        v as u8,
    ]
}

/// Const-compatible constant-time equality for two 16-byte arrays.
///
/// Uses XOR accumulation (no early return) so execution time is independent
/// of where differences occur. The (c_i, r_i) values compared here are
/// public operator configuration, but constant-time costs nothing and
/// avoids any future misuse if this helper is called on secret data.
const fn param_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut acc = 0u8;
    let mut i = 0;
    while i < 16 {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    acc == 0
}

/// XOR two 16-byte blocks: `out = a XOR b`.
const fn xor128(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = a[i] ^ b[i];
        i += 1;
    }
    out
}

/// 128-bit left rotation by `r` bits.
/// Per [ETSI TS 135 206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf): `rot(x, r)` rotates x left by r bits.
fn rotl128(input: &[u8; 16], r: u8) -> [u8; 16] {
    let rot = (r % 128) as usize;
    let byte_shift = rot / 8;
    let bit_shift = rot % 8;

    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = input[(i + byte_shift) % 16] << bit_shift;
        if bit_shift != 0 {
            out[i] |= input[(i + byte_shift + 1) % 16] >> (8 - bit_shift);
        }
    }
    out
}

/// Compute OPc from OP: `OPc = E_K[OP] XOR OP`.
const fn compute_opc(aes: &Rijndael, op: &[u8; 16]) -> [u8; 16] {
    xor128(&aes.encrypt(op), op)
}

// ---------------------------------------------------------------------------
// AuthenticationAlgorithm trait
// ---------------------------------------------------------------------------

/// Authentication algorithm trait for UMTS/LTE/5G authentication.
///
/// Abstracts the f1-f5 function set per [3GPP TS 35.205 V19.0.0](../../../docs/specs/3gpp/ts-35.205/ts_135205v190000p.pdf). Implementations include
/// Milenage ([3GPP TS 35.206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf)) and TUAK ([3GPP TS 35.231 V19.0.0](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf)).
pub trait AuthenticationAlgorithm {
    /// Snapshot buffer size for this algorithm's state.
    const SNAPSHOT_SIZE: usize;

    /// Compute the network authentication code MAC-A (8 bytes).
    /// 3GPP function designation: f1.
    fn compute_auth_mac(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8];
    /// Compute the resynchronisation authentication code MAC-S (8 bytes).
    /// 3GPP function designation: f1*.
    fn compute_resync_mac(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8];
    /// Compute the authentication response RES (8 bytes).
    /// 3GPP function designation: f2.
    fn compute_response(&self, challenge: &[u8; 16]) -> [u8; 8];
    /// Compute the ciphering key CK (16 bytes).
    /// 3GPP function designation: f3.
    fn compute_cipher_key(&self, challenge: &[u8; 16]) -> CipherKey;
    /// Compute the integrity key IK (16 bytes).
    /// 3GPP function designation: f4.
    fn compute_integrity_key(&self, challenge: &[u8; 16]) -> IntegrityKey;
    /// Compute the anonymity key AK (6 bytes).
    /// 3GPP function designation: f5.
    fn compute_anonymity_key(&self, challenge: &[u8; 16]) -> [u8; 6];
    /// Compute the resynchronisation anonymity key AK* (6 bytes).
    /// 3GPP function designation: f5*.
    fn compute_resync_anonymity_key(&self, challenge: &[u8; 16]) -> [u8; 6];

    /// Return the expected sequence number (SQN_HE, 6 bytes big-endian).
    fn expected_sequence_number(&self) -> [u8; 6];
    /// Set the expected sequence number (SQN_HE, 6 bytes big-endian).
    fn set_expected_sequence_number(&mut self, sqn: [u8; 6]);

    /// Compute RES (8), CK (16), IK (16) in a single call.
    ///
    /// Default calls `compute_response`, `compute_cipher_key`, `compute_integrity_key`
    /// individually, which may duplicate shared internal computation.  Override when
    /// the algorithm can produce all three outputs from a single core invocation
    /// (e.g. TUAK's single Keccak call via `tuak_f2345_core`).
    fn compute_response_and_keys(&self, challenge: &[u8; 16]) -> ([u8; 8], CipherKey, IntegrityKey) {
        (
            self.compute_response(challenge),
            self.compute_cipher_key(challenge),
            self.compute_integrity_key(challenge),
        )
    }

    /// Full authentication: verify AUTN, check SQN freshness, compute RES/CK/IK/Kc.
    ///
    /// Performs the complete USIM-side authentication per [3GPP TS 33.102 V19.1.0 clause 6.3.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C557%5D):
    /// 1. Compute AK = f5(K, RAND)
    /// 2. Recover SQN = (SQN XOR AK from AUTN) XOR AK
    /// 3. Extract AMF from AUTN[6..8]
    /// 4. Compute XMAC-A = f1(K, RAND, SQN, AMF)
    /// 5. Compare XMAC-A with MAC-A from AUTN[8..16]
    /// 6. If match: compute RES, CK, IK, Kc and return [`AuthenticationOutput`]
    /// 7. If mismatch: return [`AuthenticationError::MacFailure`]
    ///
    /// # C3 Conversion (Kc derivation)
    ///
    /// Per [3GPP TS 33.102 V19.1.0 clause 6.8.1.2](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf#%5B%7B%22num%22%3A98%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C250%5D):
    /// ```text
    /// Kc[i] = CK[i] XOR CK[i+8] XOR IK[i] XOR IK[i+8]   for i in 0..8
    /// ```
    ///
    /// # Errors
    ///
    /// - [`AuthenticationError::MacFailure`] if XMAC-A does not match MAC-A from AUTN.
    /// - [`AuthenticationError::SyncFailure`] if SQN is below `expected_sequence_number` (stale/replayed).
    ///   Contains a 14-byte AUTS token for network resynchronization.
    ///
    /// # SQN Freshness Policy
    ///
    /// Simple monotonic acceptance: received SQN must be >= `expected_sequence_number`.
    /// On success, `expected_sequence_number` advances to SQN + 1. No upper window bound.
    /// Per [3GPP TS 33.102 V19.1.0 clause 6.3.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C557%5D).
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey, AuthenticationError, AuthenticationAlgorithm};
    /// use simrs_secret::Secret;
    ///
    /// let mut p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
    ///
    /// // Random AUTN will almost certainly fail MAC verification
    /// let result = p.authenticate(&[0u8; 16], &[0xFFu8; 16]);
    /// assert!(matches!(result, Err(AuthenticationError::MacFailure)));
    /// ```
    fn authenticate(
        &mut self,
        challenge: &[u8; 16],
        auth_token: &[u8; 16],
    ) -> Result<AuthenticationOutput, AuthenticationError> {
        // 1. Compute AK = f5(RAND)
        let anonymity_key = self.compute_anonymity_key(challenge);

        // 2. Recover SQN: AUTN[0..6] = SQN XOR AK
        let mut sequence_number = [0u8; 6];
        for i in 0..6 {
            sequence_number[i] = auth_token[i] ^ anonymity_key[i];
        }

        // 3. Extract AMF from AUTN[6..8]
        let management_field: [u8; 2] = [auth_token[6], auth_token[7]];

        // 4. Compute XMAC-A
        let expected_mac = self.compute_auth_mac(challenge, &sequence_number, &management_field);

        // 5. Compare with MAC-A from AUTN[8..16] (constant-time to prevent
        //    timing side-channel leakage of MAC byte positions)
        if !ct_eq(&expected_mac, &auth_token[8..16]).into_bool() {
            return Err(AuthenticationError::MacFailure);
        }

        // 5.5. SQN freshness check per 3GPP TS 33.102 V19.1.0 clause 6.3.3
        let sqn_val = u48_from_be(&sequence_number);
        let he_val = u48_from_be(&self.expected_sequence_number());
        if sqn_val < he_val {
            // SQN is stale -- construct AUTS for resynchronization.
            // AUTS = Conc(SQN_MS) || MAC-S  per 3GPP TS 33.102 V19.1.0 clause 6.3.5
            // Snapshot SQN_MS (our current expected SQN) before mutable calls.
            let reported_sequence_number = self.expected_sequence_number();
            let resync_anonymity_key = self.compute_resync_anonymity_key(challenge);
            let resync_mac = self.compute_resync_mac(challenge, &reported_sequence_number, &[0x00, 0x00]);
            let mut resync_token = [0u8; 14];
            for i in 0..6 {
                resync_token[i] = reported_sequence_number[i] ^ resync_anonymity_key[i];
            }
            resync_token[6..14].copy_from_slice(&resync_mac);
            return Err(AuthenticationError::SyncFailure { resync_token });
        }
        // Advance expected_sequence_number past the accepted SQN (saturate at max to prevent
        // wrap-around which would re-open the entire SQN window).
        self.set_expected_sequence_number(
            u48_to_be(sqn_val.saturating_add(1).min(0x0000_FFFF_FFFF_FFFF)),
        );

        // 6. Compute RES, CK, IK
        let (response, cipher_key, integrity_key) = self.compute_response_and_keys(challenge);

        // 7. C3 conversion: Kc[i] = CK[i] ^ CK[i+8] ^ IK[i] ^ IK[i+8]
        let ck = cipher_key.declassify();
        let ik = integrity_key.declassify();
        let mut kc = [0u8; 8];
        for i in 0..8 {
            kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
        }

        Ok(AuthenticationOutput { response, cipher_key, integrity_key, gsm_cipher_key: GsmCipherKey::new(kc) })
    }

    /// Serialize algorithm state.
    fn save_state(&self, buf: &mut [u8]) -> usize;
    /// Restore algorithm state.
    fn restore_state(&mut self, buf: &[u8]) -> bool;

    /// Deprecated: use [`compute_auth_mac`](AuthenticationAlgorithm::compute_auth_mac).
    #[deprecated(note = "use `compute_auth_mac` -- f1 is the 3GPP designation for MAC-A (network authentication code) computation")]
    fn f1(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        self.compute_auth_mac(challenge, sequence_number, management_field)
    }
    /// Deprecated: use [`compute_resync_mac`](AuthenticationAlgorithm::compute_resync_mac).
    #[deprecated(note = "use `compute_resync_mac` -- f1* is the 3GPP designation for MAC-S (resync authentication code) computation")]
    fn f1_star(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        self.compute_resync_mac(challenge, sequence_number, management_field)
    }
    /// Deprecated: use [`compute_response`](AuthenticationAlgorithm::compute_response).
    #[deprecated(note = "use `compute_response` -- f2 is the 3GPP designation for RES (authentication response) computation")]
    fn f2(&self, challenge: &[u8; 16]) -> [u8; 8] {
        self.compute_response(challenge)
    }
    /// Deprecated: use [`compute_cipher_key`](AuthenticationAlgorithm::compute_cipher_key).
    #[deprecated(note = "use `compute_cipher_key` -- f3 is the 3GPP designation for CK (ciphering key) computation")]
    fn f3(&self, challenge: &[u8; 16]) -> [u8; 16] {
        *self.compute_cipher_key(challenge).declassify()
    }
    /// Deprecated: use [`compute_integrity_key`](AuthenticationAlgorithm::compute_integrity_key).
    #[deprecated(note = "use `compute_integrity_key` -- f4 is the 3GPP designation for IK (integrity key) computation")]
    fn f4(&self, challenge: &[u8; 16]) -> [u8; 16] {
        *self.compute_integrity_key(challenge).declassify()
    }
    /// Deprecated: use [`compute_anonymity_key`](AuthenticationAlgorithm::compute_anonymity_key).
    #[deprecated(note = "use `compute_anonymity_key` -- f5 is the 3GPP designation for AK (anonymity key) computation")]
    fn f5(&self, challenge: &[u8; 16]) -> [u8; 6] {
        self.compute_anonymity_key(challenge)
    }
    /// Deprecated: use [`compute_resync_anonymity_key`](AuthenticationAlgorithm::compute_resync_anonymity_key).
    #[deprecated(note = "use `compute_resync_anonymity_key` -- f5* is the 3GPP designation for AK* (resync anonymity key) computation")]
    fn f5_star(&self, challenge: &[u8; 16]) -> [u8; 6] {
        self.compute_resync_anonymity_key(challenge)
    }
}

impl AuthenticationAlgorithm for MilenageParams {
    #[allow(clippy::use_self)] // Inherent const vs. trait const -- Self would be circular.
    const SNAPSHOT_SIZE: usize = MilenageParams::SNAPSHOT_SIZE;

    fn compute_auth_mac(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        self.compute_auth_mac(challenge, sequence_number, management_field)
    }

    fn compute_resync_mac(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        self.compute_resync_mac(challenge, sequence_number, management_field)
    }

    fn compute_response(&self, challenge: &[u8; 16]) -> [u8; 8] {
        self.compute_response(challenge)
    }

    fn compute_cipher_key(&self, challenge: &[u8; 16]) -> CipherKey {
        self.compute_cipher_key(challenge)
    }

    fn compute_integrity_key(&self, challenge: &[u8; 16]) -> IntegrityKey {
        self.compute_integrity_key(challenge)
    }

    fn compute_anonymity_key(&self, challenge: &[u8; 16]) -> [u8; 6] {
        self.compute_anonymity_key(challenge)
    }

    fn compute_resync_anonymity_key(&self, challenge: &[u8; 16]) -> [u8; 6] {
        self.compute_resync_anonymity_key(challenge)
    }

    fn expected_sequence_number(&self) -> [u8; 6] { self.expected_sequence_number }
    fn set_expected_sequence_number(&mut self, sqn: [u8; 6]) { self.expected_sequence_number = sqn; }

    fn save_state(&self, buf: &mut [u8]) -> usize {
        self.save_state(buf)
    }

    fn restore_state(&mut self, buf: &[u8]) -> bool {
        self.restore_state(buf)
    }
}

// ---------------------------------------------------------------------------
// Default constants (3GPP TS 35.206 V19.0.0 clause 4)
// ---------------------------------------------------------------------------

/// c1 = 00...00 (128 zero bits, even parity).
const DEFAULT_C1: [u8; 16] = [0; 16];
/// c2 = 00...01 (odd parity).
const DEFAULT_C2: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// c3 = 00...02 (odd parity).
const DEFAULT_C3: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// c4 = 00...04 (odd parity).
const DEFAULT_C4: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4];
/// c5 = 00...08 (odd parity).
const DEFAULT_C5: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8];

const DEFAULT_CI: [[u8; 16]; 5] = [DEFAULT_C1, DEFAULT_C2, DEFAULT_C3, DEFAULT_C4, DEFAULT_C5];
const DEFAULT_RI: [u8; 5] = [64, 0, 32, 64, 96];

// ---------------------------------------------------------------------------
// MilenageParams
// ---------------------------------------------------------------------------

impl MilenageParams {
    /// Create parameters with [ETSI TS 135 206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf) default constants.
    ///
    /// Default (c_i, r_i) values per clause 4:
    /// - c1=`00..00`, r1=64
    /// - c2=`00..01`, r2=0
    /// - c3=`00..02`, r3=32
    /// - c4=`00..04`, r4=64
    /// - c5=`00..08`, r5=96
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
    /// use simrs_secret::Secret;
    ///
    /// let p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
    /// // Default params always succeed (no duplicate ci/ri pairs)
    /// ```
    pub const fn with_defaults(k: SubscriberKey, op: OperatorVariant) -> Self {
        // Default constants are guaranteed distinct, so unwrap is safe.
        // But we don't call new() to avoid the O(n^2) check for a known-good set.
        let aes = Rijndael::new(k.as_secret());
        let opc = match op {
            OperatorVariant::Opc(opc) => opc,
            OperatorVariant::Op(op_val) => Secret::new(compute_opc(&aes, op_val.declassify_ref())),
        };
        Self {
            k,
            opc,
            ci: DEFAULT_CI,
            ri: DEFAULT_RI,
            expected_sequence_number: [0u8; 6],
        }
    }

    /// Create parameters with custom operator-chosen constants.
    ///
    /// # Errors
    ///
    /// Returns [`ParamError::DuplicateCiRi`] if any two (c_i, r_i) pairs are equal.
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey, ParamError};
    /// use simrs_secret::Secret;
    ///
    /// // Custom constants: use default ci values so all pairs are distinct
    /// let c1 = [0u8; 16];
    /// let mut c2 = [0u8; 16]; c2[15] = 1;
    /// let mut c3 = [0u8; 16]; c3[15] = 2;
    /// let mut c4 = [0u8; 16]; c4[15] = 4;
    /// let mut c5 = [0u8; 16]; c5[15] = 8;
    /// let ci = [c1, c2, c3, c4, c5];
    /// let ri = [64, 0, 32, 64, 96];
    ///
    /// let result = MilenageParams::new(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])), ci, ri);
    /// assert!(result.is_ok());
    ///
    /// // Duplicate (ci, ri) pair is rejected
    /// let ci_dup = [[0u8; 16]; 5]; // all zero
    /// let ri_dup = [0, 0, 32, 64, 96]; // r1==r2==0 with c1==c2
    /// let err = MilenageParams::new(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])), ci_dup, ri_dup);
    /// assert!(matches!(err, Err(ParamError::DuplicateCiRi { first: 0, second: 1 })));
    /// ```
    pub const fn new(
        k: SubscriberKey,
        op: OperatorVariant,
        ci: [[u8; 16]; 5],
        ri: [u8; 5],
    ) -> Result<Self, ParamError> {
        // Check all (ci, ri) pairs are distinct per 3GPP TS 35.206 V19.0.0 clause 5.3.
        let mut i = 0u8;
        while i < 5 {
            let mut j = i + 1;
            while j < 5 {
                if ri[i as usize] == ri[j as usize]
                    && param_eq16(&ci[i as usize], &ci[j as usize])
                {
                    return Err(ParamError::DuplicateCiRi {
                        first: i,
                        second: j,
                    });
                }
                j += 1;
            }
            i += 1;
        }

        let aes = Rijndael::new(k.as_secret());
        let opc = match op {
            OperatorVariant::Opc(opc) => opc,
            OperatorVariant::Op(op_val) => Secret::new(compute_opc(&aes, op_val.declassify_ref())),
        };
        Ok(Self { k, opc, ci, ri, expected_sequence_number: [0u8; 6] })
    }

    /// Compute the network authentication code MAC-A (8 bytes).
    ///
    /// Per [3GPP TS 35.206 V19.0.0 clause 3.1](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A26%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C323%5D):
    /// `MAC-A = OUT1[0..8]` where OUT1 uses (c1, r1) with input `SQN || AMF || SQN || AMF`.
    ///
    /// 3GPP function designation: f1.
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
    /// use simrs_secret::Secret;
    ///
    /// let p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
    /// let mac_a = p.compute_auth_mac(&[0u8; 16], &[0u8; 6], &[0u8; 2]);
    /// assert_eq!(mac_a.len(), 8);
    /// ```
    pub fn compute_auth_mac(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        let out1 = self.compute_out1(challenge, sequence_number, management_field);
        let mut mac_a = [0u8; 8];
        mac_a.copy_from_slice(&out1[..8]);
        mac_a
    }

    /// Deprecated: use [`compute_auth_mac`](MilenageParams::compute_auth_mac).
    #[deprecated(note = "use `compute_auth_mac` -- f1 is the 3GPP designation for MAC-A (network authentication code) computation")]
    pub fn f1(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        self.compute_auth_mac(challenge, sequence_number, management_field)
    }

    /// Compute the resynchronisation authentication code MAC-S (8 bytes).
    ///
    /// Per [3GPP TS 35.206 V19.0.0 clause 3.2](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A26%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C323%5D):
    /// `MAC-S = OUT1[8..16]` -- uses same computation as f1 but extracts the second half.
    ///
    /// 3GPP function designation: f1*.
    ///
    /// Used in AUTS construction for SQN resynchronization.
    pub fn compute_resync_mac(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        let out1 = self.compute_out1(challenge, sequence_number, management_field);
        let mut mac_s = [0u8; 8];
        mac_s.copy_from_slice(&out1[8..16]);
        mac_s
    }

    /// Deprecated: use [`compute_resync_mac`](MilenageParams::compute_resync_mac).
    #[deprecated(note = "use `compute_resync_mac` -- f1* is the 3GPP designation for MAC-S (resync authentication code) computation")]
    pub fn f1_star(&self, challenge: &[u8; 16], sequence_number: &[u8; 6], management_field: &[u8; 2]) -> [u8; 8] {
        self.compute_resync_mac(challenge, sequence_number, management_field)
    }

    /// Compute the authentication response RES (8 bytes).
    ///
    /// Per [3GPP TS 35.206 V19.0.0 clause 3.3](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A26%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C323%5D):
    /// `RES = OUT2[8..16]` where OUT2 uses (c2, r2).
    ///
    /// 3GPP function designation: f2.
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
    /// use simrs_secret::Secret;
    ///
    /// let p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
    /// let response = p.compute_response(&[0u8; 16]);
    /// assert_eq!(response.len(), 8);
    /// ```
    pub fn compute_response(&self, challenge: &[u8; 16]) -> [u8; 8] {
        let out2 = self.compute_outi(challenge, 1); // ci[1] = c2, ri[1] = r2
        let mut response = [0u8; 8];
        response.copy_from_slice(&out2[8..16]);
        response
    }

    /// Deprecated: use [`compute_response`](MilenageParams::compute_response).
    #[deprecated(note = "use `compute_response` -- f2 is the 3GPP designation for RES (authentication response) computation")]
    pub fn f2(&self, challenge: &[u8; 16]) -> [u8; 8] {
        self.compute_response(challenge)
    }

    /// Compute the ciphering key CK (16 bytes).
    ///
    /// Per [3GPP TS 35.206 V19.0.0 clause 3.4](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A26%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C323%5D):
    /// `CK = OUT3[0..16]` where OUT3 uses (c3, r3).
    ///
    /// 3GPP function designation: f3.
    pub fn compute_cipher_key(&self, challenge: &[u8; 16]) -> CipherKey {
        CipherKey::new(self.compute_outi(challenge, 2)) // ci[2] = c3, ri[2] = r3
    }

    /// Deprecated: use [`compute_cipher_key`](MilenageParams::compute_cipher_key).
    #[deprecated(note = "use `compute_cipher_key` -- f3 is the 3GPP designation for CK (ciphering key) computation")]
    pub fn f3(&self, challenge: &[u8; 16]) -> [u8; 16] {
        *self.compute_cipher_key(challenge).declassify()
    }

    /// Compute the integrity key IK (16 bytes).
    ///
    /// Per [3GPP TS 35.206 V19.0.0 clause 3.5](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A26%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C323%5D):
    /// `IK = OUT4[0..16]` where OUT4 uses (c4, r4).
    ///
    /// 3GPP function designation: f4.
    pub fn compute_integrity_key(&self, challenge: &[u8; 16]) -> IntegrityKey {
        IntegrityKey::new(self.compute_outi(challenge, 3)) // ci[3] = c4, ri[3] = r4
    }

    /// Deprecated: use [`compute_integrity_key`](MilenageParams::compute_integrity_key).
    #[deprecated(note = "use `compute_integrity_key` -- f4 is the 3GPP designation for IK (integrity key) computation")]
    pub fn f4(&self, challenge: &[u8; 16]) -> [u8; 16] {
        *self.compute_integrity_key(challenge).declassify()
    }

    /// Compute the anonymity key AK (6 bytes).
    ///
    /// Per [3GPP TS 35.206 V19.0.0 clause 3.6](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A26%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C323%5D):
    /// `AK = OUT2[0..6]` -- shares the same computation as f2.
    ///
    /// 3GPP function designation: f5.
    ///
    /// Used to conceal SQN in AUTN: `AUTN = (SQN XOR AK) || AMF || MAC-A`.
    pub fn compute_anonymity_key(&self, challenge: &[u8; 16]) -> [u8; 6] {
        let out2 = self.compute_outi(challenge, 1); // same (c2, r2) as f2
        let mut anonymity_key = [0u8; 6];
        anonymity_key.copy_from_slice(&out2[..6]);
        anonymity_key
    }

    /// Deprecated: use [`compute_anonymity_key`](MilenageParams::compute_anonymity_key).
    #[deprecated(note = "use `compute_anonymity_key` -- f5 is the 3GPP designation for AK (anonymity key) computation")]
    pub fn f5(&self, challenge: &[u8; 16]) -> [u8; 6] {
        self.compute_anonymity_key(challenge)
    }

    /// Compute the resynchronisation anonymity key AK* (6 bytes).
    ///
    /// Per [3GPP TS 35.206 V19.0.0 clause 3.7](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf#%5B%7B%22num%22%3A26%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C323%5D):
    /// `AK* = OUT5[0..6]` where OUT5 uses (c5, r5).
    ///
    /// 3GPP function designation: f5*.
    ///
    /// Used in AUTS construction: `AUTS = (SQN_MS XOR AK*) || MAC-S`.
    pub fn compute_resync_anonymity_key(&self, challenge: &[u8; 16]) -> [u8; 6] {
        let out5 = self.compute_outi(challenge, 4); // ci[4] = c5, ri[4] = r5
        let mut anonymity_key = [0u8; 6];
        anonymity_key.copy_from_slice(&out5[..6]);
        anonymity_key
    }

    /// Deprecated: use [`compute_resync_anonymity_key`](MilenageParams::compute_resync_anonymity_key).
    #[deprecated(note = "use `compute_resync_anonymity_key` -- f5* is the 3GPP designation for AK* (resync anonymity key) computation")]
    pub fn f5_star(&self, challenge: &[u8; 16]) -> [u8; 6] {
        self.compute_resync_anonymity_key(challenge)
    }

    // -- Internal computation --

    /// Compute TEMP = E_K[RAND XOR OPc] (shared by all functions).
    const fn compute_temp(&self, challenge: &[u8; 16]) -> [u8; 16] {
        let aes = Rijndael::new(self.k.as_secret());
        aes.encrypt(&xor128(challenge, self.opc.declassify_ref()))
    }

    /// Compute OUT_i for f2/f3/f4/f5/f5* (index 0-based into ci/ri arrays).
    ///
    /// `OUT_i = E_K[rot(TEMP XOR OPc, r_i) XOR c_i] XOR OPc`
    fn compute_outi(&self, challenge: &[u8; 16], idx: usize) -> [u8; 16] {
        let aes = Rijndael::new(self.k.as_secret());
        let temp = self.compute_temp(challenge);

        let temp_xor_opc = xor128(&temp, self.opc.declassify_ref());
        let rotated = rotl128(&temp_xor_opc, self.ri[idx]);
        let input = xor128(&rotated, &self.ci[idx]);

        xor128(&aes.encrypt(&input), self.opc.declassify_ref())
    }

    /// Compute OUT1 for f1/f1* (uses SQN, AMF, and (c1, r1)).
    ///
    /// Input to the second encryption is:
    /// `TEMP XOR rot((SQN||AMF||SQN||AMF) XOR OPc, r1) XOR c1`
    ///
    /// Note: f1/f1* differs from f2-f5 because it XORs the SQN/AMF block
    /// with OPc first, then rotates, then XORs with c1, then XORs with TEMP.
    #[allow(clippy::trivially_copy_pass_by_ref)] // consistent API with public methods
    fn compute_out1(
        &self,
        challenge: &[u8; 16],
        sequence_number: &[u8; 6],
        management_field: &[u8; 2],
    ) -> [u8; 16] {
        let aes = Rijndael::new(self.k.as_secret());
        let temp = self.compute_temp(challenge);

        // Build SQN || AMF || SQN || AMF (16 bytes)
        let mut sqn_amf = [0u8; 16];
        sqn_amf[..6].copy_from_slice(sequence_number);
        sqn_amf[6..8].copy_from_slice(management_field);
        sqn_amf[8..14].copy_from_slice(sequence_number);
        sqn_amf[14..16].copy_from_slice(management_field);

        // (SQN||AMF||SQN||AMF) XOR OPc
        let xored = xor128(&sqn_amf, self.opc.declassify_ref());

        // rot(..., r1)
        let rotated = rotl128(&xored, self.ri[0]);

        // rot(...) XOR c1
        let with_c = xor128(&rotated, &self.ci[0]);

        // TEMP XOR (rot(...) XOR c1)
        let enc_input = xor128(&temp, &with_c);

        // E_K[...] XOR OPc
        xor128(&aes.encrypt(&enc_input), self.opc.declassify_ref())
    }

    // -- snapshot --

    /// Snapshot buffer size: 123 bytes (K(16) + OPc(16) + ci(80) + ri(5) + expected_sequence_number(6)).
    pub const SNAPSHOT_SIZE: usize = 16 + 16 + 80 + 5 + 6;

    /// Serialize the Milenage parameters into `buf` as flat bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut w = SnapWriter::new(buf);
        w.put_bytes(self.k.declassify());
        w.put_bytes(self.opc.declassify_ref());
        for c in &self.ci {
            w.put_bytes(c);
        }
        w.put_bytes(&self.ri);
        w.put_bytes(&self.expected_sequence_number);
        w.finish()
    }

    /// Restore the Milenage parameters from `buf`.
    ///
    /// Returns `true` on success.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut r = SnapReader::new(buf);
        let mut k_bytes = [0u8; 16];
        r.get_bytes(&mut k_bytes);
        self.k = SubscriberKey::new(Secret::new(k_bytes));
        let mut opc_bytes = [0u8; 16];
        r.get_bytes(&mut opc_bytes);
        self.opc = Secret::new(opc_bytes);
        for c in &mut self.ci {
            r.get_bytes(c);
        }
        r.get_bytes(&mut self.ri);
        r.get_bytes(&mut self.expected_sequence_number);
        true
    }
}

// ---------------------------------------------------------------------------
// Deprecated accessor methods
// ---------------------------------------------------------------------------

impl AuthenticationOutput {
    /// Deprecated: use field `response` directly.
    #[deprecated(note = "use field `response` -- RES is the 3GPP abbreviation for Authentication Response")]
    pub const fn res(&self) -> [u8; 8] { self.response }
    /// Deprecated: use field `cipher_key` directly.
    #[deprecated(note = "use field `cipher_key` -- CK is the 3GPP abbreviation for Cipher Key")]
    pub fn ck(&self) -> [u8; 16] { *self.cipher_key.declassify() }
    /// Deprecated: use field `integrity_key` directly.
    #[deprecated(note = "use field `integrity_key` -- IK is the 3GPP abbreviation for Integrity Key")]
    pub fn ik(&self) -> [u8; 16] { *self.integrity_key.declassify() }
    /// Deprecated: use field `gsm_cipher_key` directly.
    #[deprecated(note = "use field `gsm_cipher_key` -- Kc is the 3GPP abbreviation for GSM Cipher Key")]
    pub fn kc(&self) -> [u8; 8] { *self.gsm_cipher_key.declassify() }
}

impl AuthenticationError {
    /// Deprecated: match on `SyncFailure { resync_token }` instead.
    #[deprecated(note = "match on `SyncFailure { resync_token }` -- AUTS is the 3GPP abbreviation for Authentication Resynchronisation Token")]
    pub const fn auts(&self) -> Option<[u8; 14]> {
        match self {
            Self::SyncFailure { resync_token } => Some(*resync_token),
            Self::MacFailure => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Deprecated aliases -- old abbreviated names
// ---------------------------------------------------------------------------

/// Deprecated alias for [`OperatorVariant`].
#[deprecated(note = "use `OperatorVariant` -- OP is the 3GPP Operator Parameter")]
pub type OpVariant = OperatorVariant;

/// Deprecated alias for [`AuthenticationOutput`].
#[deprecated(note = "use `AuthenticationOutput` -- renamed for clarity")]
pub type AuthOutput = AuthenticationOutput;

/// Deprecated alias for [`AuthenticationError`].
/// This type is used by both Milenage and TUAK; the old name incorrectly
/// implied Milenage-only usage.
#[deprecated(note = "use `AuthenticationError` -- renamed to reflect algorithm-independent usage")]
pub type MilenageError = AuthenticationError;

/// Deprecated alias for [`AuthenticationAlgorithm`].
#[deprecated(note = "use `AuthenticationAlgorithm`")]
pub use AuthenticationAlgorithm as AuthAlgorithm;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_secret::Secret;

    // ---------------------------------------------------------------
    // ETSI TS 135 208 V19.0.0 Test Set 1
    // These are the canonical Milenage test vectors.
    // ---------------------------------------------------------------

    // Test Set 1 parameters (3GPP TS 35.208 V19.0.0 clause 4.3.1)
    const TS1_K: SubscriberKey = SubscriberKey::new(Secret::new([
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F,
        0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC,
    ]));
    const TS1_OP: OperatorVariant = OperatorVariant::op(Secret::new([
        0xCD, 0xC2, 0x02, 0xD5, 0x12, 0x3E, 0x20, 0xF6,
        0x2B, 0x6D, 0x67, 0x6A, 0xC7, 0x2C, 0xB3, 0x18,
    ]));
    const TS1_OPC: OperatorVariant = OperatorVariant::opc(Secret::new([
        0xCD, 0x63, 0xCB, 0x71, 0x95, 0x4A, 0x9F, 0x4E,
        0x48, 0xA5, 0x99, 0x4E, 0x37, 0xA0, 0x2B, 0xAF,
    ]));
    const TS1_RAND: [u8; 16] = [
        0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
        0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
    ];
    const TS1_SQN: [u8; 6] = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
    const TS1_AMF: [u8; 2] = [0xB9, 0xB9];

    // Expected outputs for Test Set 1
    const TS1_F1_MAC_A: [u8; 8] = [0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
    const TS1_F1S_MAC_S: [u8; 8] = [0x01, 0xCF, 0xAF, 0x9E, 0xC4, 0xE8, 0x71, 0xE9];
    const TS1_F2_RES: [u8; 8] = [0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
    const TS1_F3_CK: [u8; 16] = [
        0xB4, 0x0B, 0xA9, 0xA3, 0xC5, 0x8B, 0x2A, 0x05,
        0xBB, 0xF0, 0xD9, 0x87, 0xB2, 0x1B, 0xF8, 0xCB,
    ];
    const TS1_F4_IK: [u8; 16] = [
        0xF7, 0x69, 0xBC, 0xD7, 0x51, 0x04, 0x46, 0x04,
        0x12, 0x76, 0x72, 0x71, 0x1C, 0x6D, 0x34, 0x41,
    ];
    const TS1_F5_AK: [u8; 6] = [0xAA, 0x68, 0x9C, 0x64, 0x83, 0x70];
    const TS1_F5S_AK: [u8; 6] = [0x45, 0x1E, 0x8B, 0xEC, 0xA4, 0x3B];

    // ---------------------------------------------------------------
    // ETSI TS 135 208 V19.0.0 Test Set 2 (clause 4.3.2)
    // ---------------------------------------------------------------

    const TS2_K: SubscriberKey = SubscriberKey::new(Secret::new([
        0x03, 0x96, 0xEB, 0x31, 0x7B, 0x6D, 0x1C, 0x36,
        0xF1, 0x9C, 0x1C, 0x84, 0xCD, 0x6F, 0xFD, 0x16,
    ]));
    const TS2_OP: OperatorVariant = OperatorVariant::op(Secret::new([
        0xFF, 0x53, 0xBA, 0xDE, 0x17, 0xDF, 0x5D, 0x4E,
        0x79, 0x30, 0x73, 0xCE, 0x9D, 0x75, 0x79, 0xFA,
    ]));
    const TS2_OPC: OperatorVariant = OperatorVariant::opc(Secret::new([
        0x53, 0xC1, 0x56, 0x71, 0xC6, 0x0A, 0x4B, 0x73,
        0x1C, 0x55, 0xB4, 0xA4, 0x41, 0xC0, 0xBD, 0xE2,
    ]));
    const TS2_RAND: [u8; 16] = [
        0xC0, 0x0D, 0x60, 0x31, 0x03, 0xDC, 0xEE, 0x52,
        0xC4, 0x47, 0x81, 0x19, 0x49, 0x42, 0x02, 0xE8,
    ];
    const TS2_SQN: [u8; 6] = [0xFD, 0x8E, 0xEF, 0x40, 0xDF, 0x7D];
    const TS2_AMF: [u8; 2] = [0xAF, 0x17];
    const TS2_F1_MAC_A: [u8; 8] = [0x5D, 0xF5, 0xB3, 0x18, 0x07, 0xE2, 0x58, 0xB0];
    const TS2_F1S_MAC_S: [u8; 8] = [0xA8, 0xC0, 0x16, 0xE5, 0x1E, 0xF4, 0xA3, 0x43];
    const TS2_F2_RES: [u8; 8] = [0xD3, 0xA6, 0x28, 0xED, 0x98, 0x86, 0x20, 0xF0];
    const TS2_F3_CK: [u8; 16] = [
        0x58, 0xC4, 0x33, 0xFF, 0x7A, 0x70, 0x82, 0xAC,
        0xD4, 0x24, 0x22, 0x0F, 0x2B, 0x67, 0xC5, 0x56,
    ];
    const TS2_F4_IK: [u8; 16] = [
        0x21, 0xA8, 0xC1, 0xF9, 0x29, 0x70, 0x2A, 0xDB,
        0x3E, 0x73, 0x84, 0x88, 0xB9, 0xF5, 0xC5, 0xDA,
    ];
    const TS2_F5_AK: [u8; 6] = [0xC4, 0x77, 0x83, 0x99, 0x5F, 0x72];
    const TS2_F5S_AK: [u8; 6] = [0x30, 0xF1, 0x19, 0x70, 0x61, 0xC1];

    // ---------------------------------------------------------------
    // ETSI TS 135 208 V19.0.0 Test Set 3 (clause 4.3.3)
    // ---------------------------------------------------------------

    const TS3_K: SubscriberKey = SubscriberKey::new(Secret::new([
        0xFE, 0xC8, 0x6B, 0xA6, 0xEB, 0x70, 0x7E, 0xD0,
        0x89, 0x05, 0x75, 0x7B, 0x1B, 0xB4, 0x4B, 0x8F,
    ]));
    const TS3_OP: OperatorVariant = OperatorVariant::op(Secret::new([
        0xDB, 0xC5, 0x9A, 0xDC, 0xB6, 0xF9, 0xA0, 0xEF,
        0x73, 0x54, 0x77, 0xB7, 0xFA, 0xDF, 0x83, 0x74,
    ]));
    const TS3_OPC: OperatorVariant = OperatorVariant::opc(Secret::new([
        0x10, 0x06, 0x02, 0x0F, 0x0A, 0x47, 0x8B, 0xF6,
        0xB6, 0x99, 0xF1, 0x5C, 0x06, 0x2E, 0x42, 0xB3,
    ]));
    const TS3_RAND: [u8; 16] = [
        0x9F, 0x7C, 0x8D, 0x02, 0x1A, 0xCC, 0xF4, 0xDB,
        0x21, 0x3C, 0xCF, 0xF0, 0xC7, 0xF7, 0x1A, 0x6A,
    ];
    const TS3_SQN: [u8; 6] = [0x9D, 0x02, 0x77, 0x59, 0x5F, 0xFC];
    const TS3_AMF: [u8; 2] = [0x72, 0x5C];
    const TS3_F1_MAC_A: [u8; 8] = [0x9C, 0xAB, 0xC3, 0xE9, 0x9B, 0xAF, 0x72, 0x81];
    const TS3_F1S_MAC_S: [u8; 8] = [0x95, 0x81, 0x4B, 0xA2, 0xB3, 0x04, 0x43, 0x24];
    const TS3_F2_RES: [u8; 8] = [0x80, 0x11, 0xC4, 0x8C, 0x0C, 0x21, 0x4E, 0xD2];
    const TS3_F3_CK: [u8; 16] = [
        0x5D, 0xBD, 0xBB, 0x29, 0x54, 0xE8, 0xF3, 0xCD,
        0xE6, 0x65, 0xB0, 0x46, 0x17, 0x9A, 0x50, 0x98,
    ];
    const TS3_F4_IK: [u8; 16] = [
        0x59, 0xA9, 0x2D, 0x3B, 0x47, 0x6A, 0x04, 0x43,
        0x48, 0x70, 0x55, 0xCF, 0x88, 0xB2, 0x30, 0x7B,
    ];
    const TS3_F5_AK: [u8; 6] = [0x33, 0x48, 0x4D, 0xC2, 0x13, 0x6B];
    const TS3_F5S_AK: [u8; 6] = [0xDE, 0xAC, 0xDD, 0x84, 0x8C, 0xC6];

    // ---------------------------------------------------------------
    // ETSI TS 135 208 V19.0.0 Test Set 4 (clause 4.3.4)
    // ---------------------------------------------------------------

    const TS4_K: SubscriberKey = SubscriberKey::new(Secret::new([
        0x9E, 0x59, 0x44, 0xAE, 0xA9, 0x4B, 0x81, 0x16,
        0x5C, 0x82, 0xFB, 0xF9, 0xF3, 0x2D, 0xB7, 0x51,
    ]));
    const TS4_OP: OperatorVariant = OperatorVariant::op(Secret::new([
        0x22, 0x30, 0x14, 0xC5, 0x80, 0x66, 0x94, 0xC0,
        0x07, 0xCA, 0x1E, 0xEE, 0xF5, 0x7F, 0x00, 0x4F,
    ]));
    const TS4_OPC: OperatorVariant = OperatorVariant::opc(Secret::new([
        0xA6, 0x4A, 0x50, 0x7A, 0xE1, 0xA2, 0xA9, 0x8B,
        0xB8, 0x8E, 0xB4, 0x21, 0x01, 0x35, 0xDC, 0x87,
    ]));
    const TS4_RAND: [u8; 16] = [
        0xCE, 0x83, 0xDB, 0xC5, 0x4A, 0xC0, 0x27, 0x4A,
        0x15, 0x7C, 0x17, 0xF8, 0x0D, 0x01, 0x7B, 0xD6,
    ];
    const TS4_SQN: [u8; 6] = [0x0B, 0x60, 0x4A, 0x81, 0xEC, 0xA8];
    const TS4_AMF: [u8; 2] = [0x9E, 0x09];
    const TS4_F1_MAC_A: [u8; 8] = [0x74, 0xA5, 0x82, 0x20, 0xCB, 0xA8, 0x4C, 0x49];
    const TS4_F1S_MAC_S: [u8; 8] = [0xAC, 0x2C, 0xC7, 0x4A, 0x96, 0x87, 0x18, 0x37];
    const TS4_F2_RES: [u8; 8] = [0xF3, 0x65, 0xCD, 0x68, 0x3C, 0xD9, 0x2E, 0x96];
    const TS4_F3_CK: [u8; 16] = [
        0xE2, 0x03, 0xED, 0xB3, 0x97, 0x15, 0x74, 0xF5,
        0xA9, 0x4B, 0x0D, 0x61, 0xB8, 0x16, 0x34, 0x5D,
    ];
    const TS4_F4_IK: [u8; 16] = [
        0x0C, 0x45, 0x24, 0xAD, 0xEA, 0xC0, 0x41, 0xC4,
        0xDD, 0x83, 0x0D, 0x20, 0x85, 0x4F, 0xC4, 0x6B,
    ];
    const TS4_F5_AK: [u8; 6] = [0xF0, 0xB9, 0xC0, 0x8A, 0xD0, 0x2E];
    const TS4_F5S_AK: [u8; 6] = [0x60, 0x85, 0xA8, 0x6C, 0x6F, 0x63];

    // ---------------------------------------------------------------
    // ETSI TS 135 208 V19.0.0 Test Set 5 (clause 4.3.5)
    // ---------------------------------------------------------------

    const TS5_K: SubscriberKey = SubscriberKey::new(Secret::new([
        0x4A, 0xB1, 0xDE, 0xB0, 0x5C, 0xA6, 0xCE, 0xB0,
        0x51, 0xFC, 0x98, 0xE7, 0x7D, 0x02, 0x6A, 0x84,
    ]));
    const TS5_OP: OperatorVariant = OperatorVariant::op(Secret::new([
        0x2D, 0x16, 0xC5, 0xCD, 0x1F, 0xDF, 0x6B, 0x22,
        0x38, 0x35, 0x84, 0xE3, 0xBE, 0xF2, 0xA8, 0xD8,
    ]));
    const TS5_OPC: OperatorVariant = OperatorVariant::opc(Secret::new([
        0xDC, 0xF0, 0x7C, 0xBD, 0x51, 0x85, 0x52, 0x90,
        0xB9, 0x2A, 0x07, 0xA9, 0x89, 0x1E, 0x52, 0x3E,
    ]));
    const TS5_RAND: [u8; 16] = [
        0x74, 0xB0, 0xCD, 0x60, 0x31, 0xA1, 0xC8, 0x33,
        0x9B, 0x2B, 0x6C, 0xE2, 0xB8, 0xC4, 0xA1, 0x86,
    ];
    const TS5_SQN: [u8; 6] = [0xE8, 0x80, 0xA1, 0xB5, 0x80, 0xB6];
    const TS5_AMF: [u8; 2] = [0x9F, 0x07];
    const TS5_F1_MAC_A: [u8; 8] = [0x49, 0xE7, 0x85, 0xDD, 0x12, 0x62, 0x6E, 0xF2];
    const TS5_F1S_MAC_S: [u8; 8] = [0x9E, 0x85, 0x79, 0x03, 0x36, 0xBB, 0x3F, 0xA2];
    const TS5_F2_RES: [u8; 8] = [0x58, 0x60, 0xFC, 0x1B, 0xCE, 0x35, 0x1E, 0x7E];
    const TS5_F3_CK: [u8; 16] = [
        0x76, 0x57, 0x76, 0x6B, 0x37, 0x3D, 0x1C, 0x21,
        0x38, 0xF3, 0x07, 0xE3, 0xDE, 0x92, 0x42, 0xF9,
    ];
    const TS5_F4_IK: [u8; 16] = [
        0x1C, 0x42, 0xE9, 0x60, 0xD8, 0x9B, 0x8F, 0xA9,
        0x9F, 0x27, 0x44, 0xE0, 0x70, 0x8C, 0xCB, 0x53,
    ];
    const TS5_F5_AK: [u8; 6] = [0x31, 0xE1, 0x1A, 0x60, 0x91, 0x18];
    const TS5_F5S_AK: [u8; 6] = [0xFE, 0x25, 0x55, 0xE5, 0x4A, 0xA9];

    // ---------------------------------------------------------------
    // ETSI TS 135 208 V19.0.0 Test Set 6 (clause 4.3.6)
    // ---------------------------------------------------------------

    const TS6_K: SubscriberKey = SubscriberKey::new(Secret::new([
        0x6C, 0x38, 0xA1, 0x16, 0xAC, 0x28, 0x0C, 0x45,
        0x4F, 0x59, 0x33, 0x2E, 0xE3, 0x5C, 0x8C, 0x4F,
    ]));
    const TS6_OP: OperatorVariant = OperatorVariant::op(Secret::new([
        0x1B, 0xA0, 0x0A, 0x1A, 0x7C, 0x67, 0x00, 0xAC,
        0x8C, 0x3F, 0xF3, 0xE9, 0x6A, 0xD0, 0x87, 0x25,
    ]));
    const TS6_OPC: OperatorVariant = OperatorVariant::opc(Secret::new([
        0x38, 0x03, 0xEF, 0x53, 0x63, 0xB9, 0x47, 0xC6,
        0xAA, 0xA2, 0x25, 0xE5, 0x8F, 0xAE, 0x39, 0x34,
    ]));
    const TS6_RAND: [u8; 16] = [
        0xEE, 0x64, 0x66, 0xBC, 0x96, 0x20, 0x2C, 0x5A,
        0x55, 0x7A, 0xBB, 0xEF, 0xF8, 0xBA, 0xBF, 0x63,
    ];
    const TS6_SQN: [u8; 6] = [0x41, 0x4B, 0x98, 0x22, 0x21, 0x81];
    const TS6_AMF: [u8; 2] = [0x44, 0x64];
    const TS6_F1_MAC_A: [u8; 8] = [0x07, 0x8A, 0xDF, 0xB4, 0x88, 0x24, 0x1A, 0x57];
    const TS6_F1S_MAC_S: [u8; 8] = [0x80, 0x24, 0x6B, 0x8D, 0x01, 0x86, 0xBC, 0xF1];
    const TS6_F2_RES: [u8; 8] = [0x16, 0xC8, 0x23, 0x3F, 0x05, 0xA0, 0xAC, 0x28];
    const TS6_F3_CK: [u8; 16] = [
        0x3F, 0x8C, 0x75, 0x87, 0xFE, 0x8E, 0x4B, 0x23,
        0x3A, 0xF6, 0x76, 0xAE, 0xDE, 0x30, 0xBA, 0x3B,
    ];
    const TS6_F4_IK: [u8; 16] = [
        0xA7, 0x46, 0x6C, 0xC1, 0xE6, 0xB2, 0xA1, 0x33,
        0x7D, 0x49, 0xD3, 0xB6, 0x6E, 0x95, 0xD7, 0xB4,
    ];
    const TS6_F5_AK: [u8; 6] = [0x45, 0xB0, 0xF6, 0x9A, 0xB0, 0x6C];
    const TS6_F5S_AK: [u8; 6] = [0x1F, 0x53, 0xCD, 0x2B, 0x11, 0x13];

    #[test]
    fn test_set_1_f1_mac_a() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(p.compute_auth_mac(&TS1_RAND, &TS1_SQN, &TS1_AMF), TS1_F1_MAC_A);
    }

    #[test]
    fn test_set_1_f1_star_mac_s() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(p.compute_resync_mac(&TS1_RAND, &TS1_SQN, &TS1_AMF), TS1_F1S_MAC_S);
    }

    #[test]
    fn test_set_1_f2_res() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(p.compute_response(&TS1_RAND), TS1_F2_RES);
    }

    #[test]
    fn test_set_1_f3_ck() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(*p.compute_cipher_key(&TS1_RAND).declassify(), TS1_F3_CK);
    }

    #[test]
    fn test_set_1_f4_ik() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(*p.compute_integrity_key(&TS1_RAND).declassify(), TS1_F4_IK);
    }

    #[test]
    fn test_set_1_f5_ak() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(p.compute_anonymity_key(&TS1_RAND), TS1_F5_AK);
    }

    #[test]
    fn test_set_1_f5_star_ak() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(p.compute_resync_anonymity_key(&TS1_RAND), TS1_F5S_AK);
    }

    // ---------------------------------------------------------------
    // OPc derivation: using OP must produce same results as using OPc
    // ---------------------------------------------------------------

    #[test]
    fn op_and_opc_produce_same_f2() {
        let p_opc = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        let p_op = MilenageParams::with_defaults(TS1_K, TS1_OP);
        assert_eq!(p_opc.compute_response(&TS1_RAND), p_op.compute_response(&TS1_RAND));
    }

    // ---------------------------------------------------------------
    // Full authentication
    // ---------------------------------------------------------------

    #[test]
    fn authenticate_with_valid_autn() {
        let mut p = MilenageParams::with_defaults(TS1_K, TS1_OPC);

        // Construct valid AUTN: (SQN XOR AK) || AMF || MAC-A
        let anonymity_key = p.compute_anonymity_key(&TS1_RAND);
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = TS1_SQN[i] ^ anonymity_key[i];
        }
        autn[6] = TS1_AMF[0];
        autn[7] = TS1_AMF[1];
        let auth_mac = p.compute_auth_mac(&TS1_RAND, &TS1_SQN, &TS1_AMF);
        autn[8..16].copy_from_slice(&auth_mac);

        let result = p.authenticate(&TS1_RAND, &autn);
        assert!(result.is_ok(), "valid AUTN must authenticate successfully");
        let out = result.unwrap();
        assert_eq!(out.response, TS1_F2_RES);
        assert_eq!(*out.cipher_key.declassify(), TS1_F3_CK);
        assert_eq!(*out.integrity_key.declassify(), TS1_F4_IK);
    }

    #[test]
    fn authenticate_with_bad_mac_fails() {
        let mut p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        // All-zero AUTN will have wrong MAC-A
        let result = p.authenticate(&TS1_RAND, &[0u8; 16]);
        assert!(matches!(result, Err(AuthenticationError::MacFailure)));
    }

    #[test]
    fn sqn_boundary_accepts_equal_rejects_below() {
        let mut p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        let amf = [0x80, 0x00];

        // Helper to build valid AUTN for a given SQN.
        let build_autn = |p: &MilenageParams, sqn: [u8; 6]| -> [u8; 16] {
            let anonymity_key = p.compute_anonymity_key(&TS1_RAND);
            let mut autn = [0u8; 16];
            for i in 0..6 {
                autn[i] = sqn[i] ^ anonymity_key[i];
            }
            autn[6..8].copy_from_slice(&amf);
            autn[8..16].copy_from_slice(&p.compute_auth_mac(&TS1_RAND, &sqn, &amf));
            autn
        };

        // SQN=5: accepted (expected_sequence_number starts at 0, so 5 >= 0).
        let sqn_5 = [0, 0, 0, 0, 0, 5];
        let autn = build_autn(&p, sqn_5);
        assert!(p.authenticate(&TS1_RAND, &autn).is_ok());
        // expected_sequence_number is now 6.

        // SQN=6: boundary -- exactly expected_sequence_number, should be accepted.
        let sqn_6 = [0, 0, 0, 0, 0, 6];
        let autn = build_autn(&p, sqn_6);
        assert!(p.authenticate(&TS1_RAND, &autn).is_ok());
        // expected_sequence_number is now 7.

        // SQN=6: now below expected_sequence_number=7, should be rejected as replay.
        let autn = build_autn(&p, sqn_6);
        assert!(
            matches!(p.authenticate(&TS1_RAND, &autn), Err(AuthenticationError::SyncFailure { .. })),
            "SQN below expected_sequence_number must trigger SyncFailure",
        );
    }

    // ---------------------------------------------------------------
    // C3 conversion (Kc derivation from CK and IK)
    // ---------------------------------------------------------------

    #[test]
    fn kc_is_c3_conversion_of_ck_ik() {
        let mut p = MilenageParams::with_defaults(TS1_K, TS1_OPC);

        // Construct valid AUTN
        let anonymity_key = p.compute_anonymity_key(&TS1_RAND);
        let mut autn = [0u8; 16];
        for i in 0..6 { autn[i] = TS1_SQN[i] ^ anonymity_key[i]; }
        autn[6..8].copy_from_slice(&TS1_AMF);
        autn[8..16].copy_from_slice(&p.compute_auth_mac(&TS1_RAND, &TS1_SQN, &TS1_AMF));

        let out = p.authenticate(&TS1_RAND, &autn).unwrap();

        // Verify C3 conversion: Kc[i] = CK[i]^CK[i+8]^IK[i]^IK[i+8]
        let ck = out.cipher_key.declassify();
        let ik = out.integrity_key.declassify();
        #[allow(clippy::needless_range_loop)] // indices into 4 arrays with offset
        let expected_gsm_cipher_key: [u8; 8] = {
            let mut gsm_cipher_key = [0u8; 8];
            for i in 0..8 {
                gsm_cipher_key[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
            }
            gsm_cipher_key
        };
        assert_eq!(*out.gsm_cipher_key.declassify(), expected_gsm_cipher_key, "Kc must be C3 conversion of CK||IK");
    }

    // ---------------------------------------------------------------
    // Determinism
    // ---------------------------------------------------------------

    #[test]
    fn deterministic() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        assert_eq!(p.compute_response(&TS1_RAND), p.compute_response(&TS1_RAND));
    }

    // ---------------------------------------------------------------
    // Parameter validation
    // ---------------------------------------------------------------

    #[test]
    fn duplicate_ci_ri_rejected() {
        // Make c1==c2 and r1==r2 (both zero) -> duplicate pair
        let ci = [[0u8; 16]; 5]; // all zero
        let ri = [0, 0, 32, 64, 96]; // r1==r2==0

        let result = MilenageParams::new(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])), ci, ri);
        assert!(matches!(result, Err(ParamError::DuplicateCiRi { first: 0, second: 1 })));
    }

    #[test]
    fn defaults_always_valid() {
        // with_defaults should never fail
        let p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let _ = p; // just verify construction succeeds
    }

    // ---------------------------------------------------------------
    // OPc computation verification
    // ---------------------------------------------------------------

    /// Extract the raw `[u8; 16]` from an [`OperatorVariant`] for use in
    /// low-level OPc derivation tests (which operate below the semantic-type
    /// boundary).
    fn ov_bytes(ov: &OperatorVariant) -> &[u8; 16] {
        match ov {
            OperatorVariant::Op(s) | OperatorVariant::Opc(s) => s.declassify_ref(),
        }
    }

    #[test]
    fn opc_derivation_matches_test_set_1() {
        // Verify that OPc = E_K[OP] XOR OP gives the expected OPc
        let aes = Rijndael::new(TS1_K.as_secret());
        let computed_opc = compute_opc(&aes, ov_bytes(&TS1_OP));
        assert_eq!(computed_opc, *ov_bytes(&TS1_OPC));
    }

    // ---------------------------------------------------------------
    // Validate all functions for test sets 2--6
    // ---------------------------------------------------------------

    #[allow(clippy::too_many_arguments, clippy::trivially_copy_pass_by_ref)]
    fn validate_test_set(
        name: &str,
        k: SubscriberKey, op: OperatorVariant, opc: OperatorVariant, challenge: &[u8; 16],
        sequence_number: &[u8; 6], management_field: &[u8; 2],
        expected_auth_mac: &[u8; 8], expected_resync_mac: &[u8; 8], expected_response: &[u8; 8],
        expected_cipher_key: &[u8; 16], expected_integrity_key: &[u8; 16], expected_anonymity_key: &[u8; 6], expected_resync_anonymity_key: &[u8; 6],
    ) {
        let p = MilenageParams::with_defaults(k, opc);
        assert_eq!(p.compute_auth_mac(challenge, sequence_number, management_field), *expected_auth_mac, "{name}: f1 mismatch");
        assert_eq!(p.compute_resync_mac(challenge, sequence_number, management_field), *expected_resync_mac, "{name}: f1* mismatch");
        assert_eq!(p.compute_response(challenge), *expected_response, "{name}: f2 mismatch");
        assert_eq!(*p.compute_cipher_key(challenge).declassify(), *expected_cipher_key, "{name}: f3 mismatch");
        assert_eq!(*p.compute_integrity_key(challenge).declassify(), *expected_integrity_key, "{name}: f4 mismatch");
        assert_eq!(p.compute_anonymity_key(challenge), *expected_anonymity_key, "{name}: f5 mismatch");
        assert_eq!(p.compute_resync_anonymity_key(challenge), *expected_resync_anonymity_key, "{name}: f5* mismatch");

        // Also verify that using OP produces the same results as OPc.
        let p_op = MilenageParams::with_defaults(k, op);
        assert_eq!(p_op.compute_response(challenge), *expected_response, "{name}: f2 via OP mismatch");
    }

    #[test]
    fn test_set_2_all() {
        validate_test_set("TS2", TS2_K, TS2_OP, TS2_OPC, &TS2_RAND, &TS2_SQN, &TS2_AMF,
            &TS2_F1_MAC_A, &TS2_F1S_MAC_S, &TS2_F2_RES, &TS2_F3_CK, &TS2_F4_IK, &TS2_F5_AK, &TS2_F5S_AK);
    }

    #[test]
    fn test_set_3_all() {
        validate_test_set("TS3", TS3_K, TS3_OP, TS3_OPC, &TS3_RAND, &TS3_SQN, &TS3_AMF,
            &TS3_F1_MAC_A, &TS3_F1S_MAC_S, &TS3_F2_RES, &TS3_F3_CK, &TS3_F4_IK, &TS3_F5_AK, &TS3_F5S_AK);
    }

    #[test]
    fn test_set_4_all() {
        validate_test_set("TS4", TS4_K, TS4_OP, TS4_OPC, &TS4_RAND, &TS4_SQN, &TS4_AMF,
            &TS4_F1_MAC_A, &TS4_F1S_MAC_S, &TS4_F2_RES, &TS4_F3_CK, &TS4_F4_IK, &TS4_F5_AK, &TS4_F5S_AK);
    }

    #[test]
    fn test_set_5_all() {
        validate_test_set("TS5", TS5_K, TS5_OP, TS5_OPC, &TS5_RAND, &TS5_SQN, &TS5_AMF,
            &TS5_F1_MAC_A, &TS5_F1S_MAC_S, &TS5_F2_RES, &TS5_F3_CK, &TS5_F4_IK, &TS5_F5_AK, &TS5_F5S_AK);
    }

    #[test]
    fn test_set_6_all() {
        validate_test_set("TS6", TS6_K, TS6_OP, TS6_OPC, &TS6_RAND, &TS6_SQN, &TS6_AMF,
            &TS6_F1_MAC_A, &TS6_F1S_MAC_S, &TS6_F2_RES, &TS6_F3_CK, &TS6_F4_IK, &TS6_F5_AK, &TS6_F5S_AK);
    }

    // ---------------------------------------------------------------
    // OPc derivation for test sets 2--6
    // ---------------------------------------------------------------

    #[test]
    fn opc_derivation_matches_test_set_2() {
        let aes = Rijndael::new(TS2_K.as_secret());
        let computed_opc = compute_opc(&aes, ov_bytes(&TS2_OP));
        assert_eq!(computed_opc, *ov_bytes(&TS2_OPC));
    }

    #[test]
    fn opc_derivation_matches_test_set_3() {
        let aes = Rijndael::new(TS3_K.as_secret());
        let computed_opc = compute_opc(&aes, ov_bytes(&TS3_OP));
        assert_eq!(computed_opc, *ov_bytes(&TS3_OPC));
    }

    #[test]
    fn opc_derivation_matches_test_set_4() {
        let aes = Rijndael::new(TS4_K.as_secret());
        let computed_opc = compute_opc(&aes, ov_bytes(&TS4_OP));
        assert_eq!(computed_opc, *ov_bytes(&TS4_OPC));
    }

    #[test]
    fn opc_derivation_matches_test_set_5() {
        let aes = Rijndael::new(TS5_K.as_secret());
        let computed_opc = compute_opc(&aes, ov_bytes(&TS5_OP));
        assert_eq!(computed_opc, *ov_bytes(&TS5_OPC));
    }

    #[test]
    fn opc_derivation_matches_test_set_6() {
        let aes = Rijndael::new(TS6_K.as_secret());
        let computed_opc = compute_opc(&aes, ov_bytes(&TS6_OP));
        assert_eq!(computed_opc, *ov_bytes(&TS6_OPC));
    }

    // ---------------------------------------------------------------
    // rotl128 internal test
    // ---------------------------------------------------------------

    #[test]
    fn rotl128_by_zero_is_identity() {
        let input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(rotl128(&input, 0), input);
    }

    #[test]
    fn rotl128_by_8_shifts_one_byte() {
        // Left rotation by 8 bits = shift byte array by 1 position.
        // byte[0] wraps to byte[15], all others shift left.
        let mut input = [0u8; 16];
        input[0] = 0xFF;
        let rotated = rotl128(&input, 8);
        let mut expected = [0u8; 16];
        expected[15] = 0xFF;
        assert_eq!(rotated, expected);
    }

    // -- SNAPSHOT tests --

    #[test]
    fn snapshot_size_correct() {
        assert_eq!(MilenageParams::SNAPSHOT_SIZE, 123);
    }

    #[test]
    fn snapshot_roundtrip_preserves_computation() {
        let orig = MilenageParams::with_defaults(TS1_K, TS1_OPC);

        let mut snap = [0u8; MilenageParams::SNAPSHOT_SIZE];
        assert_eq!(orig.save_state(&mut snap), 123);

        // Restore into a zeroed params.
        let mut restored = MilenageParams::default();
        assert!(restored.restore_state(&snap));

        // Restored params must produce the same output.
        assert_eq!(restored.compute_response(&TS1_RAND), TS1_F2_RES);
        assert_eq!(restored.compute_anonymity_key(&TS1_RAND), TS1_F5_AK);
    }

    #[test]
    fn snapshot_roundtrip_preserves_sqn_he() {
        let mut p = MilenageParams::with_defaults(TS1_K, TS1_OPC);

        // Advance expected_sequence_number by performing a successful authenticate.
        let anonymity_key = p.compute_anonymity_key(&TS1_RAND);
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = TS1_SQN[i] ^ anonymity_key[i];
        }
        autn[6..8].copy_from_slice(&TS1_AMF);
        autn[8..16].copy_from_slice(&p.compute_auth_mac(&TS1_RAND, &TS1_SQN, &TS1_AMF));
        p.authenticate(&TS1_RAND, &autn)
            .expect("setup authenticate must succeed");

        let mut snap = [0u8; MilenageParams::SNAPSHOT_SIZE];
        assert_eq!(p.save_state(&mut snap), MilenageParams::SNAPSHOT_SIZE);

        let mut restored = MilenageParams::default();
        assert!(restored.restore_state(&snap));

        // Replaying the same SQN must trigger SyncFailure on the restored
        // instance, proving expected_sequence_number was preserved through save/restore.
        let result = restored.authenticate(&TS1_RAND, &autn);
        assert!(
            matches!(result, Err(AuthenticationError::SyncFailure { .. })),
            "restored instance must reject the already-consumed SQN",
        );
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let p = MilenageParams::with_defaults(TS1_K, TS1_OPC);
        let mut small = [0u8; 50];
        assert_eq!(p.save_state(&mut small), 0);

        let mut p2 = MilenageParams::default();
        assert!(!p2.restore_state(&small));
    }

    // -- Constant-time comparison tests --

    #[test]
    fn ct_eq_equal_slices() {
        let a = [0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
        assert!(ct_eq(&a, &a).into_bool());
    }

    #[test]
    fn ct_eq_single_bit_difference() {
        let a = [0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
        // Flip a single bit in each position to ensure no early exit
        for i in 0..a.len() {
            for bit in 0..8u32 {
                let mut b = a;
                b[i] ^= 1 << bit;
                assert!(!ct_eq(&a, &b).into_bool(), "must detect bit {bit} difference at byte {i}");
            }
        }
    }

    #[test]
    fn ct_eq_different_lengths() {
        let a = [0x01, 0x02, 0x03];
        let b = [0x01, 0x02];
        assert!(!ct_eq(&a, &b).into_bool());
    }

    #[test]
    fn ct_eq_empty_slices() {
        let a: [u8; 0] = [];
        assert!(ct_eq(&a, &a).into_bool());
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use simrs_secret::Secret;

    proptest! {
        // Different keys must produce different response and anonymity key outputs.
        // This tests the core security property: key sensitivity.
        #[test]
        fn different_key_changes_response_and_anonymity_key(
            k1 in any::<[u8; 16]>(),
            k2 in any::<[u8; 16]>(),
            challenge in any::<[u8; 16]>(),
        ) {
            prop_assume!(k1 != k2);
            let p1 = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k1)), OperatorVariant::opc(Secret::new([0u8; 16])));
            let p2 = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k2)), OperatorVariant::opc(Secret::new([0u8; 16])));
            prop_assert_ne!(p1.compute_response(&challenge), p2.compute_response(&challenge), "different K must produce different RES");
            prop_assert_ne!(p1.compute_anonymity_key(&challenge), p2.compute_anonymity_key(&challenge), "different K must produce different AK");
        }
    }

    proptest! {
        // Kc must always be the C3 conversion of CK and IK.
        #[test]
        fn kc_is_always_c3(k in any::<[u8; 16]>(), challenge in any::<[u8; 16]>()) {
            let mut p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new([0u8; 16])));
            let ck = p.compute_cipher_key(&challenge);
            let ik = p.compute_integrity_key(&challenge);
            let ck_bytes = ck.declassify();
            let ik_bytes = ik.declassify();
            let mut expected_gsm_cipher_key = [0u8; 8];
            for i in 0..8 {
                expected_gsm_cipher_key[i] = ck_bytes[i] ^ ck_bytes[i + 8] ^ ik_bytes[i] ^ ik_bytes[i + 8];
            }

            // Build a valid AUTN to test authenticate()
            let sqn = [0u8; 6];
            let amf = [0u8; 2];
            let anonymity_key = p.compute_anonymity_key(&challenge);
            let mut autn = [0u8; 16];
            for i in 0..6 { autn[i] = sqn[i] ^ anonymity_key[i]; }
            autn[6..8].copy_from_slice(&amf);
            autn[8..16].copy_from_slice(&p.compute_auth_mac(&challenge, &sqn, &amf));

            let out = p.authenticate(&challenge, &autn).unwrap();
            prop_assert_eq!(*out.gsm_cipher_key.declassify(), expected_gsm_cipher_key);
        }
    }

    proptest! {
        // OP and pre-computed OPc must produce identical response output.
        #[test]
        fn op_vs_opc_equivalence(k in any::<[u8; 16]>(), op in any::<[u8; 16]>(), challenge in any::<[u8; 16]>()) {
            // Compute OPc manually
            let aes = Rijndael::new(&Secret::new(k));
            let opc = compute_opc(&aes, &op);

            let p_op = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::op(Secret::new(op)));
            let p_opc = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new(opc)));
            prop_assert_eq!(p_op.compute_response(&challenge), p_opc.compute_response(&challenge));
        }
    }

    proptest! {
        // Different RAND must produce different RES (with overwhelming probability).
        #[test]
        fn different_rand_different_res(
            k in any::<[u8; 16]>(),
            challenge1 in any::<[u8; 16]>(),
            challenge2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(challenge1 != challenge2);
            let p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new([0u8; 16])));
            // Collision is theoretically possible but astronomically unlikely
            prop_assert_ne!(p.compute_response(&challenge1), p.compute_response(&challenge2));
        }
    }

    proptest! {
        // f1 (MAC-A) must differ from f1* (MAC-S) for the same inputs.
        // These use different internal constants (c1 vs c6, r1 vs r6) so their
        // outputs must always be distinct.
        #[test]
        fn f1_neq_f1_star(
            k in any::<[u8; 16]>(),
            challenge in any::<[u8; 16]>(),
            sqn in any::<[u8; 6]>(),
            amf in any::<[u8; 2]>(),
        ) {
            let p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new([0u8; 16])));
            let mac_a = p.compute_auth_mac(&challenge, &sqn, &amf);
            let mac_s = p.compute_resync_mac(&challenge, &sqn, &amf);
            prop_assert_ne!(mac_a, mac_s, "f1 (MAC-A) must differ from f1* (MAC-S)");
        }
    }

    proptest! {
        // Output determinism: identical inputs always yield identical outputs.
        #[test]
        fn output_deterministic(k in any::<[u8; 16]>(), challenge in any::<[u8; 16]>()) {
            let p = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(k)), OperatorVariant::opc(Secret::new([0u8; 16])));
            prop_assert_eq!(
                p.compute_response(&challenge),
                p.compute_response(&challenge)
            );
            prop_assert_eq!(
                *p.compute_cipher_key(&challenge).declassify(),
                *p.compute_cipher_key(&challenge).declassify()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet via ct_test wrapper)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{ct_test, assert_no_timing_leak};

    /// Timing test for Milenage f2 (representative of f2345).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND.
    /// Class 1: random K with same OPc [0x83; 16], random RAND.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f2_ct() {
        let opc = [0x83u8; 16];
        let outcome = ct_test(77,
            |rng| {
                let key = [0x46u8; 16];
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |(key, opc, rand_bytes)| {
                let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(*key)), OperatorVariant::opc(Secret::new(*opc)));
                let response = params.compute_response(rand_bytes);
                black_box(response);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Timing test for Milenage f1 (compute_auth_mac).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND/SQN/AMF.
    /// Class 1: random K with same OPc [0x83; 16], random RAND/SQN/AMF.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f1_ct() {
        let opc = [0x83u8; 16];
        let outcome = ct_test(78,
            |rng| {
                let key = [0x46u8; 16];
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, opc, rand_bytes, sqn, amf)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, opc, rand_bytes, sqn, amf)
            },
            |(key, opc, rand_bytes, sqn, amf)| {
                let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(*key)), OperatorVariant::opc(Secret::new(*opc)));
                let mac = params.compute_auth_mac(rand_bytes, sqn, amf);
                black_box(mac);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Timing test for Milenage f1* (compute_resync_mac).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND/SQN/AMF.
    /// Class 1: random K with same OPc [0x83; 16], random RAND/SQN/AMF.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f1star_ct() {
        let opc = [0x83u8; 16];
        let outcome = ct_test(79,
            |rng| {
                let key = [0x46u8; 16];
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, opc, rand_bytes, sqn, amf)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, opc, rand_bytes, sqn, amf)
            },
            |(key, opc, rand_bytes, sqn, amf)| {
                let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(*key)), OperatorVariant::opc(Secret::new(*opc)));
                let mac = params.compute_resync_mac(rand_bytes, sqn, amf);
                black_box(mac);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Timing test for Milenage f3 (compute_cipher_key).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND.
    /// Class 1: random K with same OPc [0x83; 16], random RAND.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f3_ct() {
        let opc = [0x83u8; 16];
        let outcome = ct_test(80,
            |rng| {
                let key = [0x46u8; 16];
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |(key, opc, rand_bytes)| {
                let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(*key)), OperatorVariant::opc(Secret::new(*opc)));
                let ck = params.compute_cipher_key(rand_bytes);
                black_box(ck);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Timing test for Milenage f4 (compute_integrity_key).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND.
    /// Class 1: random K with same OPc [0x83; 16], random RAND.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f4_ct() {
        let opc = [0x83u8; 16];
        let outcome = ct_test(81,
            |rng| {
                let key = [0x46u8; 16];
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |(key, opc, rand_bytes)| {
                let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(*key)), OperatorVariant::opc(Secret::new(*opc)));
                let ik = params.compute_integrity_key(rand_bytes);
                black_box(ik);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Timing test for Milenage f5 (compute_anonymity_key).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND.
    /// Class 1: random K with same OPc [0x83; 16], random RAND.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f5_ct() {
        let opc = [0x83u8; 16];
        let outcome = ct_test(82,
            |rng| {
                let key = [0x46u8; 16];
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |(key, opc, rand_bytes)| {
                let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(*key)), OperatorVariant::opc(Secret::new(*opc)));
                let ak = params.compute_anonymity_key(rand_bytes);
                black_box(ak);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Timing test for Milenage f5* (compute_resync_anonymity_key).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND.
    /// Class 1: random K with same OPc [0x83; 16], random RAND.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f5star_ct() {
        let opc = [0x83u8; 16];
        let outcome = ct_test(83,
            |rng| {
                let key = [0x46u8; 16];
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut rand_bytes = [0u8; 16];
                rng.fill_bytes(&mut rand_bytes);
                (key, opc, rand_bytes)
            },
            |(key, opc, rand_bytes)| {
                let params = MilenageParams::with_defaults(SubscriberKey::new(Secret::new(*key)), OperatorVariant::opc(Secret::new(*opc)));
                let ak = params.compute_resync_anonymity_key(rand_bytes);
                black_box(ak);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
