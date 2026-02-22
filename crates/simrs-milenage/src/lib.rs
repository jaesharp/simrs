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
//! # Default Constants (ETSI TS 135 206 V17.0.0 clause 4)
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
//! `OPc = E_K[OP] XOR OP` (ETSI TS 135 206 V17.0.0 Annex 1)
//!
//! OPc can be pre-computed off-card and stored directly, or computed on-card
//! from OP. The [`OpVariant`] enum represents both options.
//!
//! # Standards
//! - ETSI TS 135 206 V17.0.0 -- Milenage algorithm specification
//! - ETSI TS 135 208 V17.0.0 -- Milenage test data (6 complete test sets)
//! - ETSI TS 133 102 V14.1.0 clause 6 -- 3GPP security architecture
//! - 3GPP TS 31.102 V17.5.0 clause 7.1.2.1 -- AUTHENTICATE response
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap. All state lives in [`MilenageParams`].
//!
//! # Example
//!
//! ```
//! use simrs_milenage::{MilenageParams, OpVariant};
//!
//! // ETSI TS 135 208 V17.0.0 Test Set 1
//! let k    = [0x46,0x5B,0x5C,0xE8,0xB1,0x99,0xB4,0x9F,
//!             0xAA,0x5F,0x0A,0x2E,0xE2,0x38,0xA6,0xBC];
//! let opc  = [0xCD,0x63,0xCB,0x71,0x95,0x4A,0x9F,0x4E,
//!             0x48,0xA5,0x99,0x4E,0x37,0xA0,0x2B,0xAF];
//! let rand = [0x23,0x55,0x3C,0xBE,0x96,0x37,0xA8,0x9D,
//!             0x21,0x8A,0xE6,0x4D,0xAE,0x47,0xBF,0x35];
//! let sqn  = [0xFF,0x9B,0xB4,0xD0,0xB6,0x07];
//! let amf  = [0xB9,0xB9];
//!
//! let params = MilenageParams::with_defaults(k, OpVariant::Opc(opc));
//!
//! assert_eq!(params.f1(&rand, &sqn, &amf),
//!            [0x4A,0x9F,0xFA,0xC3,0x54,0xDF,0xAF,0xB3]);
//! assert_eq!(params.f2(&rand),
//!            [0xA5,0x42,0x11,0xD5,0xE3,0xBA,0x50,0xBF]);
//! assert_eq!(params.f5(&rand),
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

use simrs_consttime::ct_eq;
use simrs_rijndael::Rijndael;

/// Operator variant: either raw OP (computed to OPc on-card) or pre-computed OPc.
///
/// # Standards
/// - ETSI TS 135 206 V17.0.0 clause 5.1 -- recommends pre-computing OPc off-card
/// - ETSI TS 135 206 V17.0.0 Annex 1 -- OPc computation: `OPc = E_K[OP] XOR OP`
///
/// ```
/// use simrs_milenage::OpVariant;
///
/// // Pre-computed OPc (recommended for production)
/// let _opc = OpVariant::Opc([0xCD; 16]);
///
/// // Raw OP (OPc computed at runtime from K and OP)
/// let _op = OpVariant::Op([0xAB; 16]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpVariant {
    /// Pre-computed OPc (128 bits). Preferred -- avoids runtime AES call.
    Opc([u8; 16]),
    /// Raw OP. OPc will be derived as `E_K[OP] XOR OP` when needed.
    Op([u8; 16]),
}

/// Milenage algorithm parameters.
///
/// Contains the subscriber key K, the operator variant (OP or OPc), and the
/// per-function rotation/XOR constants (c1-c5, r1-r5).
///
/// # Construction
///
/// Use [`MilenageParams::with_defaults`] for the standard ETSI TS 135 206 constants,
/// or [`MilenageParams::new`] for custom operator-chosen values.
///
/// ```
/// use simrs_milenage::{MilenageParams, OpVariant};
///
/// let params = MilenageParams::with_defaults(
///     [0xFF; 16],                    // K
///     OpVariant::Opc([0xAA; 16]),    // OPc
/// );
/// ```
#[derive(Debug, Clone)]
pub struct MilenageParams {
    /// Subscriber key K (128 bits).
    k: [u8; 16],
    /// Pre-computed OPc (128 bits). Derived from OP if OpVariant::Op was given.
    opc: [u8; 16],
    /// Per-function XOR constants c1..c5 (128 bits each).
    ci: [[u8; 16]; 5],
    /// Per-function rotation constants r1..r5 (in bits).
    ri: [u8; 5],
}

impl Default for MilenageParams {
    fn default() -> Self {
        Self::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]))
    }
}

/// Successful authentication output.
///
/// Per 3GPP TS 31.102 V17.5.0 clause 7.1.2.1, the successful AUTHENTICATE
/// response (tag `0xDB`) contains RES, CK, IK, and optionally Kc.
///
/// ```
/// use simrs_milenage::AuthOutput;
///
/// // AuthOutput fields are fixed-size arrays
/// let out = AuthOutput {
///     res: [0u8; 8],
///     ck:  [0u8; 16],
///     ik:  [0u8; 16],
///     kc:  [0u8; 8],
/// };
/// assert_eq!(out.res.len(), 8);
/// assert_eq!(out.ck.len(), 16);
/// assert_eq!(out.ik.len(), 16);
/// assert_eq!(out.kc.len(), 8);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOutput {
    /// RES: authentication response (8 bytes, f2 output).
    /// Sent to the network to prove knowledge of K.
    pub res: [u8; 8],

    /// CK: ciphering key (16 bytes, f3 output).
    /// Used for radio bearer encryption (3G) or as input to KASME derivation (4G/5G).
    pub ck: [u8; 16],

    /// IK: integrity key (16 bytes, f4 output).
    /// Used for radio bearer integrity (3G) or as input to KASME derivation (4G/5G).
    pub ik: [u8; 16],

    /// Kc: GSM ciphering key (8 bytes, C3 conversion of CK and IK).
    /// For UMTS-GSM interworking per TS 33.102 clause 6.8.1.2.
    /// `Kc[i] = CK[i] XOR CK[i+8] XOR IK[i] XOR IK[i+8]` for i in 0..8.
    pub kc: [u8; 8],
}

/// Authentication error.
///
/// Per 3GPP TS 31.102 V17.5.0 clause 7.1.2.1:
/// - MAC failure: XMAC-A != MAC-A from AUTN -> SW `98 62`
/// - Sync failure: SQN out of range -> tag `0xDC` with 14-byte AUTS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MilenageError {
    /// MAC-A verification failed. The network's authentication token is invalid.
    /// USIM returns SW `98 62`.
    MacFailure,

    /// SQN is outside the acceptable range. Contains AUTS for resynchronization.
    /// AUTS = `(SQN_MS XOR AK*) || MAC-S` (14 bytes).
    /// USIM returns tag `0xDC` with AUTS.
    SyncFailure {
        /// AUTS resynchronization token (14 bytes).
        auts: [u8; 14],
    },
}

impl core::fmt::Display for MilenageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MacFailure => f.write_str("MAC failure"),
            Self::SyncFailure { .. } => f.write_str("SQN out of range"),
        }
    }
}

/// Parameter validation error.
///
/// Per ETSI TS 135 206 V17.0.0 clause 5.3, all (c_i, r_i) pairs must be distinct.
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

/// Const-compatible equality check for two 16-byte arrays.
const fn const_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 16 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
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
/// Per ETSI TS 135 206: `rot(x, r)` rotates x left by r bits.
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
// AuthAlgorithm trait
// ---------------------------------------------------------------------------

/// Authentication algorithm trait for UMTS/LTE/5G authentication.
///
/// Abstracts the f1-f5 function set per TS 35.205. Implementations include
/// Milenage (TS 35.206) and TUAK (TS 35.231).
pub trait AuthAlgorithm {
    /// Snapshot buffer size for this algorithm's state.
    const SNAPSHOT_SIZE: usize;

    /// f1: Network authentication code MAC-A (8 bytes).
    fn f1(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8];
    /// f1*: Resynch authentication code MAC-S (8 bytes).
    fn f1_star(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8];
    /// f2: Authentication response RES (8 bytes).
    fn f2(&self, rand: &[u8; 16]) -> [u8; 8];
    /// f3: Ciphering key CK (16 bytes).
    fn f3(&self, rand: &[u8; 16]) -> [u8; 16];
    /// f4: Integrity key IK (16 bytes).
    fn f4(&self, rand: &[u8; 16]) -> [u8; 16];
    /// f5: Anonymity key AK (6 bytes).
    fn f5(&self, rand: &[u8; 16]) -> [u8; 6];
    /// f5*: Resynch anonymity key AK* (6 bytes).
    fn f5_star(&self, rand: &[u8; 16]) -> [u8; 6];

    /// Full authentication: verify AUTN, compute RES/CK/IK/Kc.
    ///
    /// # Errors
    ///
    /// Returns [`MilenageError::MacFailure`] if MAC verification fails,
    /// or [`MilenageError::SyncFailure`] if the sequence number is stale.
    fn authenticate(&self, rand: &[u8; 16], autn: &[u8; 16]) -> Result<AuthOutput, MilenageError>;

    /// Serialize algorithm state.
    fn save_state(&self, buf: &mut [u8]) -> usize;
    /// Restore algorithm state.
    fn restore_state(&mut self, buf: &[u8]) -> bool;
}

impl AuthAlgorithm for MilenageParams {
    #[allow(clippy::use_self)] // Inherent const vs. trait const -- Self would be circular.
    const SNAPSHOT_SIZE: usize = MilenageParams::SNAPSHOT_SIZE;

    fn f1(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        self.f1(rand, sqn, amf)
    }

    fn f1_star(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        self.f1_star(rand, sqn, amf)
    }

    fn f2(&self, rand: &[u8; 16]) -> [u8; 8] {
        self.f2(rand)
    }

    fn f3(&self, rand: &[u8; 16]) -> [u8; 16] {
        self.f3(rand)
    }

    fn f4(&self, rand: &[u8; 16]) -> [u8; 16] {
        self.f4(rand)
    }

    fn f5(&self, rand: &[u8; 16]) -> [u8; 6] {
        self.f5(rand)
    }

    fn f5_star(&self, rand: &[u8; 16]) -> [u8; 6] {
        self.f5_star(rand)
    }

    fn authenticate(&self, rand: &[u8; 16], autn: &[u8; 16]) -> Result<AuthOutput, MilenageError> {
        self.authenticate(rand, autn)
    }

    fn save_state(&self, buf: &mut [u8]) -> usize {
        self.save_state(buf)
    }

    fn restore_state(&mut self, buf: &[u8]) -> bool {
        self.restore_state(buf)
    }
}

// ---------------------------------------------------------------------------
// Default constants (ETSI TS 135 206 V17.0.0 clause 4)
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
    /// Create parameters with ETSI TS 135 206 V17.0.0 default constants.
    ///
    /// Default (c_i, r_i) values per clause 4:
    /// - c1=`00..00`, r1=64
    /// - c2=`00..01`, r2=0
    /// - c3=`00..02`, r3=32
    /// - c4=`00..04`, r4=64
    /// - c5=`00..08`, r5=96
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OpVariant};
    ///
    /// let p = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
    /// // Default params always succeed (no duplicate ci/ri pairs)
    /// ```
    pub const fn with_defaults(k: [u8; 16], op: OpVariant) -> Self {
        // Default constants are guaranteed distinct, so unwrap is safe.
        // But we don't call new() to avoid the O(n^2) check for a known-good set.
        let aes = Rijndael::new(&k);
        let opc = match op {
            OpVariant::Opc(opc) => opc,
            OpVariant::Op(op_val) => compute_opc(&aes, &op_val),
        };
        Self {
            k,
            opc,
            ci: DEFAULT_CI,
            ri: DEFAULT_RI,
        }
    }

    /// Create parameters with custom operator-chosen constants.
    ///
    /// # Errors
    ///
    /// Returns [`ParamError::DuplicateCiRi`] if any two (c_i, r_i) pairs are equal.
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OpVariant, ParamError};
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
    /// let result = MilenageParams::new([0u8; 16], OpVariant::Opc([0u8; 16]), ci, ri);
    /// assert!(result.is_ok());
    ///
    /// // Duplicate (ci, ri) pair is rejected
    /// let ci_dup = [[0u8; 16]; 5]; // all zero
    /// let ri_dup = [0, 0, 32, 64, 96]; // r1==r2==0 with c1==c2
    /// let err = MilenageParams::new([0u8; 16], OpVariant::Opc([0u8; 16]), ci_dup, ri_dup);
    /// assert!(matches!(err, Err(ParamError::DuplicateCiRi { first: 0, second: 1 })));
    /// ```
    pub const fn new(
        k: [u8; 16],
        op: OpVariant,
        ci: [[u8; 16]; 5],
        ri: [u8; 5],
    ) -> Result<Self, ParamError> {
        // Check all (ci, ri) pairs are distinct per TS 135 206 clause 5.3.
        let mut i = 0u8;
        while i < 5 {
            let mut j = i + 1;
            while j < 5 {
                if ri[i as usize] == ri[j as usize]
                    && const_eq16(&ci[i as usize], &ci[j as usize])
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

        let aes = Rijndael::new(&k);
        let opc = match op {
            OpVariant::Opc(opc) => opc,
            OpVariant::Op(op_val) => compute_opc(&aes, &op_val),
        };
        Ok(Self { k, opc, ci, ri })
    }

    /// f1: Network authentication code MAC-A (8 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.1:
    /// `MAC-A = OUT1[0..8]` where OUT1 uses (c1, r1) with input `SQN || AMF || SQN || AMF`.
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OpVariant};
    ///
    /// let p = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
    /// let mac_a = p.f1(&[0u8; 16], &[0u8; 6], &[0u8; 2]);
    /// assert_eq!(mac_a.len(), 8);
    /// ```
    pub fn f1(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let out1 = self.compute_out1(rand, sqn, amf);
        let mut mac_a = [0u8; 8];
        mac_a.copy_from_slice(&out1[..8]);
        mac_a
    }

    /// f1\*: Resynch authentication code MAC-S (8 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.2:
    /// `MAC-S = OUT1[8..16]` -- uses same computation as f1 but extracts the second half.
    ///
    /// Used in AUTS construction for SQN resynchronization.
    pub fn f1_star(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let out1 = self.compute_out1(rand, sqn, amf);
        let mut mac_s = [0u8; 8];
        mac_s.copy_from_slice(&out1[8..16]);
        mac_s
    }

    /// f2: Authentication response RES (8 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.3:
    /// `RES = OUT2[8..16]` where OUT2 uses (c2, r2).
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OpVariant};
    ///
    /// let p = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
    /// let res = p.f2(&[0u8; 16]);
    /// assert_eq!(res.len(), 8);
    /// ```
    pub fn f2(&self, rand: &[u8; 16]) -> [u8; 8] {
        let out2 = self.compute_outi(rand, 1); // ci[1] = c2, ri[1] = r2
        let mut res = [0u8; 8];
        res.copy_from_slice(&out2[8..16]);
        res
    }

    /// f3: Ciphering key CK (16 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.4:
    /// `CK = OUT3[0..16]` where OUT3 uses (c3, r3).
    pub fn f3(&self, rand: &[u8; 16]) -> [u8; 16] {
        self.compute_outi(rand, 2) // ci[2] = c3, ri[2] = r3
    }

    /// f4: Integrity key IK (16 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.5:
    /// `IK = OUT4[0..16]` where OUT4 uses (c4, r4).
    pub fn f4(&self, rand: &[u8; 16]) -> [u8; 16] {
        self.compute_outi(rand, 3) // ci[3] = c4, ri[3] = r4
    }

    /// f5: Anonymity key AK (6 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.6:
    /// `AK = OUT2[0..6]` -- shares the same computation as f2.
    ///
    /// Used to conceal SQN in AUTN: `AUTN = (SQN XOR AK) || AMF || MAC-A`.
    pub fn f5(&self, rand: &[u8; 16]) -> [u8; 6] {
        let out2 = self.compute_outi(rand, 1); // same (c2, r2) as f2
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out2[..6]);
        ak
    }

    /// f5\*: Resynch anonymity key AK\* (6 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.7:
    /// `AK* = OUT5[0..6]` where OUT5 uses (c5, r5).
    ///
    /// Used in AUTS construction: `AUTS = (SQN_MS XOR AK*) || MAC-S`.
    pub fn f5_star(&self, rand: &[u8; 16]) -> [u8; 6] {
        let out5 = self.compute_outi(rand, 4); // ci[4] = c5, ri[4] = r5
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out5[..6]);
        ak
    }

    /// Full authentication: verify AUTN, compute RES, CK, IK, Kc.
    ///
    /// Performs the complete USIM-side authentication per TS 33.102 clause 6.3.3:
    /// 1. Compute AK = f5(K, RAND)
    /// 2. Recover SQN = (SQN XOR AK from AUTN) XOR AK
    /// 3. Extract AMF from AUTN[6..8]
    /// 4. Compute XMAC-A = f1(K, RAND, SQN, AMF)
    /// 5. Compare XMAC-A with MAC-A from AUTN[8..16]
    /// 6. If match: compute RES, CK, IK, Kc and return [`AuthOutput`]
    /// 7. If mismatch: return [`MilenageError::MacFailure`]
    ///
    /// # C3 Conversion (Kc derivation)
    ///
    /// Per TS 33.102 clause 6.8.1.2:
    /// ```text
    /// Kc[i] = CK[i] XOR CK[i+8] XOR IK[i] XOR IK[i+8]   for i in 0..8
    /// ```
    ///
    /// # Errors
    ///
    /// - [`MilenageError::MacFailure`] if XMAC-A does not match MAC-A from AUTN.
    /// - [`MilenageError::SyncFailure`] if SQN verification fails (when caller
    ///   implements SQN checking and forwards the failure).
    ///
    /// # SQN Verification
    ///
    /// SQN verification is **not** performed in this function (the `SqnPolicy`
    /// is handled by the caller in `simrs-usim`). This function only verifies
    /// MAC-A.
    ///
    /// ```
    /// use simrs_milenage::{MilenageParams, OpVariant, MilenageError};
    ///
    /// let p = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
    ///
    /// // Random AUTN will almost certainly fail MAC verification
    /// let result = p.authenticate(&[0u8; 16], &[0xFFu8; 16]);
    /// assert!(matches!(result, Err(MilenageError::MacFailure)));
    /// ```
    pub fn authenticate(
        &self,
        rand: &[u8; 16],
        autn: &[u8; 16],
    ) -> Result<AuthOutput, MilenageError> {
        // 1. Compute AK = f5(RAND)
        let ak = self.f5(rand);

        // 2. Recover SQN: AUTN[0..6] = SQN XOR AK
        let mut sqn = [0u8; 6];
        for i in 0..6 {
            sqn[i] = autn[i] ^ ak[i];
        }

        // 3. Extract AMF from AUTN[6..8]
        let amf: [u8; 2] = [autn[6], autn[7]];

        // 4. Compute XMAC-A
        let xmac_a = self.f1(rand, &sqn, &amf);

        // 5. Compare with MAC-A from AUTN[8..16] (constant-time to prevent
        //    timing side-channel leakage of MAC byte positions)
        if !ct_eq(&xmac_a, &autn[8..16]) {
            return Err(MilenageError::MacFailure);
        }

        // 6. Compute RES, CK, IK
        let res = self.f2(rand);
        let ck = self.f3(rand);
        let ik = self.f4(rand);

        // 7. C3 conversion: Kc[i] = CK[i] ^ CK[i+8] ^ IK[i] ^ IK[i+8]
        let mut kc = [0u8; 8];
        for i in 0..8 {
            kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
        }

        Ok(AuthOutput { res, ck, ik, kc })
    }

    // -- Internal computation --

    /// Compute TEMP = E_K[RAND XOR OPc] (shared by all functions).
    const fn compute_temp(&self, rand: &[u8; 16]) -> [u8; 16] {
        let aes = Rijndael::new(&self.k);
        aes.encrypt(&xor128(rand, &self.opc))
    }

    /// Compute OUT_i for f2/f3/f4/f5/f5* (index 0-based into ci/ri arrays).
    ///
    /// `OUT_i = E_K[rot(TEMP XOR OPc, r_i) XOR c_i] XOR OPc`
    fn compute_outi(&self, rand: &[u8; 16], idx: usize) -> [u8; 16] {
        let aes = Rijndael::new(&self.k);
        let temp = self.compute_temp(rand);

        let temp_xor_opc = xor128(&temp, &self.opc);
        let rotated = rotl128(&temp_xor_opc, self.ri[idx]);
        let input = xor128(&rotated, &self.ci[idx]);

        xor128(&aes.encrypt(&input), &self.opc)
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
        rand: &[u8; 16],
        sqn: &[u8; 6],
        amf: &[u8; 2],
    ) -> [u8; 16] {
        let aes = Rijndael::new(&self.k);
        let temp = self.compute_temp(rand);

        // Build SQN || AMF || SQN || AMF (16 bytes)
        let mut sqn_amf = [0u8; 16];
        sqn_amf[..6].copy_from_slice(sqn);
        sqn_amf[6..8].copy_from_slice(amf);
        sqn_amf[8..14].copy_from_slice(sqn);
        sqn_amf[14..16].copy_from_slice(amf);

        // (SQN||AMF||SQN||AMF) XOR OPc
        let xored = xor128(&sqn_amf, &self.opc);

        // rot(..., r1)
        let rotated = rotl128(&xored, self.ri[0]);

        // rot(...) XOR c1
        let with_c = xor128(&rotated, &self.ci[0]);

        // TEMP XOR (rot(...) XOR c1)
        let enc_input = xor128(&temp, &with_c);

        // E_K[...] XOR OPc
        xor128(&aes.encrypt(&enc_input), &self.opc)
    }

    // -- snapshot --

    /// Snapshot buffer size: 117 bytes (K(16) + OPc(16) + ci(80) + ri(5)).
    pub const SNAPSHOT_SIZE: usize = 16 + 16 + 80 + 5;

    /// Serialize the Milenage parameters into `buf` as flat bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut w = SnapWriter::new(buf);
        w.put_bytes(&self.k);
        w.put_bytes(&self.opc);
        for c in &self.ci {
            w.put_bytes(c);
        }
        w.put_bytes(&self.ri);
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
        r.get_bytes(&mut self.k);
        r.get_bytes(&mut self.opc);
        for c in &mut self.ci {
            r.get_bytes(c);
        }
        r.get_bytes(&mut self.ri);
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // ETSI TS 135 208 V17.0.0 Test Set 1
    // These are the canonical Milenage test vectors.
    // ---------------------------------------------------------------

    // Test Set 1 parameters (TS 135 208 clause 5.1)
    const TS1_K: [u8; 16] = [
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F,
        0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC,
    ];
    const TS1_OP: [u8; 16] = [
        0xCD, 0xC2, 0x02, 0xD5, 0x12, 0x3E, 0x20, 0xF6,
        0x2B, 0x6D, 0x67, 0x6A, 0xC7, 0x2C, 0xB3, 0x18,
    ];
    const TS1_OPC: [u8; 16] = [
        0xCD, 0x63, 0xCB, 0x71, 0x95, 0x4A, 0x9F, 0x4E,
        0x48, 0xA5, 0x99, 0x4E, 0x37, 0xA0, 0x2B, 0xAF,
    ];
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

    #[test]
    fn test_set_1_f1_mac_a() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF), TS1_F1_MAC_A);
    }

    #[test]
    fn test_set_1_f1_star_mac_s() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f1_star(&TS1_RAND, &TS1_SQN, &TS1_AMF), TS1_F1S_MAC_S);
    }

    #[test]
    fn test_set_1_f2_res() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f2(&TS1_RAND), TS1_F2_RES);
    }

    #[test]
    fn test_set_1_f3_ck() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f3(&TS1_RAND), TS1_F3_CK);
    }

    #[test]
    fn test_set_1_f4_ik() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f4(&TS1_RAND), TS1_F4_IK);
    }

    #[test]
    fn test_set_1_f5_ak() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f5(&TS1_RAND), TS1_F5_AK);
    }

    #[test]
    fn test_set_1_f5_star_ak() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f5_star(&TS1_RAND), TS1_F5S_AK);
    }

    // ---------------------------------------------------------------
    // OPc derivation: using OP must produce same results as using OPc
    // ---------------------------------------------------------------

    #[test]
    fn op_and_opc_produce_same_f2() {
        let p_opc = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        let p_op = MilenageParams::with_defaults(TS1_K, OpVariant::Op(TS1_OP));
        assert_eq!(p_opc.f2(&TS1_RAND), p_op.f2(&TS1_RAND));
    }

    // ---------------------------------------------------------------
    // Full authentication
    // ---------------------------------------------------------------

    #[test]
    fn authenticate_with_valid_autn() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));

        // Construct valid AUTN: (SQN XOR AK) || AMF || MAC-A
        let ak = p.f5(&TS1_RAND);
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = TS1_SQN[i] ^ ak[i];
        }
        autn[6] = TS1_AMF[0];
        autn[7] = TS1_AMF[1];
        let mac_a = p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF);
        autn[8..16].copy_from_slice(&mac_a);

        let result = p.authenticate(&TS1_RAND, &autn);
        assert!(result.is_ok(), "valid AUTN must authenticate successfully");
        let out = result.unwrap();
        assert_eq!(out.res, TS1_F2_RES);
        assert_eq!(out.ck, TS1_F3_CK);
        assert_eq!(out.ik, TS1_F4_IK);
    }

    #[test]
    fn authenticate_with_bad_mac_fails() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        // All-zero AUTN will have wrong MAC-A
        let result = p.authenticate(&TS1_RAND, &[0u8; 16]);
        assert!(matches!(result, Err(MilenageError::MacFailure)));
    }

    // ---------------------------------------------------------------
    // C3 conversion (Kc derivation from CK and IK)
    // ---------------------------------------------------------------

    #[test]
    fn kc_is_c3_conversion_of_ck_ik() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));

        // Construct valid AUTN
        let ak = p.f5(&TS1_RAND);
        let mut autn = [0u8; 16];
        for i in 0..6 { autn[i] = TS1_SQN[i] ^ ak[i]; }
        autn[6..8].copy_from_slice(&TS1_AMF);
        autn[8..16].copy_from_slice(&p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF));

        let out = p.authenticate(&TS1_RAND, &autn).unwrap();

        // Verify C3 conversion: Kc[i] = CK[i]^CK[i+8]^IK[i]^IK[i+8]
        #[allow(clippy::needless_range_loop)] // indices into 4 arrays with offset
        let expected_kc: [u8; 8] = {
            let mut kc = [0u8; 8];
            for i in 0..8 {
                kc[i] = out.ck[i] ^ out.ck[i + 8] ^ out.ik[i] ^ out.ik[i + 8];
            }
            kc
        };
        assert_eq!(out.kc, expected_kc, "Kc must be C3 conversion of CK||IK");
    }

    // ---------------------------------------------------------------
    // Determinism
    // ---------------------------------------------------------------

    #[test]
    fn deterministic() {
        let p = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));
        assert_eq!(p.f2(&TS1_RAND), p.f2(&TS1_RAND));
    }

    // ---------------------------------------------------------------
    // Parameter validation
    // ---------------------------------------------------------------

    #[test]
    fn duplicate_ci_ri_rejected() {
        // Make c1==c2 and r1==r2 (both zero) -> duplicate pair
        let ci = [[0u8; 16]; 5]; // all zero
        let ri = [0, 0, 32, 64, 96]; // r1==r2==0

        let result = MilenageParams::new([0u8; 16], OpVariant::Opc([0u8; 16]), ci, ri);
        assert!(matches!(result, Err(ParamError::DuplicateCiRi { first: 0, second: 1 })));
    }

    #[test]
    fn defaults_always_valid() {
        // with_defaults should never fail
        let p = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let _ = p; // just verify construction succeeds
    }

    // ---------------------------------------------------------------
    // OPc computation verification
    // ---------------------------------------------------------------

    #[test]
    fn opc_derivation_matches_test_set_1() {
        // Verify that OPc = E_K[OP] XOR OP gives the expected OPc
        let aes = Rijndael::new(&TS1_K);
        let computed_opc = compute_opc(&aes, &TS1_OP);
        assert_eq!(computed_opc, TS1_OPC);
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
        assert_eq!(MilenageParams::SNAPSHOT_SIZE, 117);
    }

    #[test]
    fn snapshot_roundtrip_preserves_computation() {
        let orig = MilenageParams::with_defaults(TS1_K, OpVariant::Opc(TS1_OPC));

        let mut snap = [0u8; MilenageParams::SNAPSHOT_SIZE];
        assert_eq!(orig.save_state(&mut snap), 117);

        // Restore into a zeroed params.
        let mut restored = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        assert!(restored.restore_state(&snap));

        // Restored params must produce the same f2 output.
        assert_eq!(restored.f2(&TS1_RAND), TS1_F2_RES);
        assert_eq!(restored.f5(&TS1_RAND), TS1_F5_AK);
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let p = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let mut small = [0u8; 50];
        assert_eq!(p.save_state(&mut small), 0);

        let mut p2 = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        assert!(!p2.restore_state(&small));
    }

    // -- Constant-time comparison tests --

    #[test]
    fn ct_eq_equal_slices() {
        let a = [0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
        assert!(ct_eq(&a, &a));
    }

    #[test]
    fn ct_eq_single_bit_difference() {
        let a = [0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3];
        // Flip a single bit in each position to ensure no early exit
        for i in 0..a.len() {
            for bit in 0..8u32 {
                let mut b = a;
                b[i] ^= 1 << bit;
                assert!(!ct_eq(&a, &b), "must detect bit {bit} difference at byte {i}");
            }
        }
    }

    #[test]
    fn ct_eq_different_lengths() {
        let a = [0x01, 0x02, 0x03];
        let b = [0x01, 0x02];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn ct_eq_empty_slices() {
        let a: [u8; 0] = [];
        assert!(ct_eq(&a, &a));
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // f2 and f5 share the same OUT2 computation, so f5 must be
        // the first 6 bytes of OUT2 while f2 must be the last 8.
        // We can't directly test OUT2, but we can test that f2 and f5
        // are consistent: calling them both should produce valid, non-trivially-
        // related outputs.
        #[test]
        fn f2_f5_deterministic(k in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let p = MilenageParams::with_defaults(k, OpVariant::Opc([0u8; 16]));
            let res1 = p.f2(&rand);
            let res2 = p.f2(&rand);
            let ak1 = p.f5(&rand);
            let ak2 = p.f5(&rand);
            prop_assert_eq!(res1, res2);
            prop_assert_eq!(ak1, ak2);
        }
    }

    proptest! {
        // Kc must always be the C3 conversion of CK and IK.
        #[test]
        fn kc_is_always_c3(k in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            let p = MilenageParams::with_defaults(k, OpVariant::Opc([0u8; 16]));
            let ck = p.f3(&rand);
            let ik = p.f4(&rand);
            let mut expected_kc = [0u8; 8];
            for i in 0..8 {
                expected_kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
            }

            // Build a valid AUTN to test authenticate()
            let sqn = [0u8; 6];
            let amf = [0u8; 2];
            let ak = p.f5(&rand);
            let mut autn = [0u8; 16];
            for i in 0..6 { autn[i] = sqn[i] ^ ak[i]; }
            autn[6..8].copy_from_slice(&amf);
            autn[8..16].copy_from_slice(&p.f1(&rand, &sqn, &amf));

            let out = p.authenticate(&rand, &autn).unwrap();
            prop_assert_eq!(out.kc, expected_kc);
        }
    }

    proptest! {
        // OP and pre-computed OPc must produce identical f2 output.
        #[test]
        fn op_vs_opc_equivalence(k in any::<[u8; 16]>(), op in any::<[u8; 16]>(), rand in any::<[u8; 16]>()) {
            // Compute OPc manually
            let aes = Rijndael::new(&k);
            let opc = compute_opc(&aes, &op);

            let p_op = MilenageParams::with_defaults(k, OpVariant::Op(op));
            let p_opc = MilenageParams::with_defaults(k, OpVariant::Opc(opc));
            prop_assert_eq!(p_op.f2(&rand), p_opc.f2(&rand));
        }
    }

    proptest! {
        // Different RAND must produce different RES (with overwhelming probability).
        #[test]
        fn different_rand_different_res(
            k in any::<[u8; 16]>(),
            rand1 in any::<[u8; 16]>(),
            rand2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(rand1 != rand2);
            let p = MilenageParams::with_defaults(k, OpVariant::Opc([0u8; 16]));
            // Collision is theoretically possible but astronomically unlikely
            prop_assert_ne!(p.f2(&rand1), p.f2(&rand2));
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (DudeCT)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{dudect_test, Rng};

    /// DudeCT timing test for Milenage f2 (representative of f2345).
    ///
    /// Class 0: fixed K [0x46; 16] with OPc [0x83; 16], random RAND.
    /// Class 1: random K with same OPc [0x83; 16], random RAND.
    ///
    /// A constant-time implementation must show no measurable timing
    /// difference between classes -- the key must not influence execution
    /// time.
    #[test]
    fn test_milenage_f2_ct() {
        let mut rng = Rng::from_seed(77);
        let opc = [0x83u8; 16];
        let result = dudect_test(
            "Milenage f2 (fixed vs random key)",
            10_000,
            &mut rng,
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
                let params = MilenageParams::with_defaults(*key, OpVariant::Opc(*opc));
                let res = params.f2(rand_bytes);
                black_box(res);
            },
        );
        result.report();
        assert!(result.pass, "|t| = {:.3}", result.t_value.abs());
    }
}
