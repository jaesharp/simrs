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
//! use simrs_milenage::{MilenageParams, OpVariant, AuthOutput, MilenageError};
//!
//! // ETSI TS 135 208 V17.0.0 Test Set 1
//! let k   = hex!("465b5ce8 b199b49f aa5f0a2e e238a6bc");
//! let opc = hex!("cd63cb71 954a9f4e 48a5994e 37a02baf");
//! let rand= hex!("23553cbe 9637a89d 218ae64d ae47bf35");
//! let sqn = hex!("ff9bb4d0 b607");
//! let amf = hex!("b9b9");
//!
//! let params = MilenageParams::with_defaults(k, OpVariant::Opc(opc));
//!
//! // Individual function outputs
//! let mac_a = params.f1(&rand, &sqn, &amf);
//! assert_eq!(mac_a, hex!("4a9ffac3 54dfafb3"));
//!
//! let res = params.f2(&rand);
//! assert_eq!(res, hex!("a54211d5 e3ba50bf"));
//!
//! let ck = params.f3(&rand);
//! assert_eq!(ck, hex!("b40ba9a3 c58b2a05 bbf0d987 b21bf8cb"));
//!
//! let ik = params.f4(&rand);
//! assert_eq!(ik, hex!("f769bcd7 51044604 12767271 1c6d3441"));
//!
//! let ak = params.f5(&rand);
//! assert_eq!(ak, hex!("aa689c64 8370"));
//! ```
//!
//! ```
//! # // This example uses a helper macro for hex literals.
//! # // In real code, use a const hex parser or byte arrays.
//! # macro_rules! hex {
//! #     ($s:literal) => {{
//! #         const S: &str = $s;
//! #         const N: usize = S.len() / 2; // approximate
//! #         todo!("hex macro placeholder")
//! #     }};
//! # }
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// Milenage documentation uses many standard 3GPP terms (OPc, MAC-A, AuC, etc.)
// that clippy flags as needing backticks. These are domain-specific nomenclature,
// not Rust identifiers.
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

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
    _private: (), // fields will be added during implementation
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
    pub fn with_defaults(k: [u8; 16], op: OpVariant) -> Self {
        todo!("MilenageParams::with_defaults")
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
    /// // Custom constants (must all be distinct pairs)
    /// let ci = [[0u8; 16]; 5];
    /// let ri = [64, 0, 32, 64, 96];
    ///
    /// // This should fail: c1==c3 (both zero) and r1==r4 (both 64),
    /// // but (c1,r1)=(zero,64) != (c3,r3)=(zero,32), so it might pass.
    /// // Only fails if a COMPLETE (ci,ri) pair is duplicated.
    /// let result = MilenageParams::new([0u8; 16], OpVariant::Opc([0u8; 16]), ci, ri);
    /// // With default ri values and all-zero ci, pairs are distinct because ri differ.
    /// assert!(result.is_ok());
    /// ```
    pub fn new(
        k: [u8; 16],
        op: OpVariant,
        ci: [[u8; 16]; 5],
        ri: [u8; 5],
    ) -> Result<Self, ParamError> {
        todo!("MilenageParams::new")
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
        todo!("f1: MAC-A")
    }

    /// f1\*: Resynch authentication code MAC-S (8 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.2:
    /// `MAC-S = OUT1[8..16]` -- uses same computation as f1 but extracts the second half.
    ///
    /// Used in AUTS construction for SQN resynchronization.
    pub fn f1_star(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        todo!("f1*: MAC-S")
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
        todo!("f2: RES")
    }

    /// f3: Ciphering key CK (16 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.4:
    /// `CK = OUT3[0..16]` where OUT3 uses (c3, r3).
    pub fn f3(&self, rand: &[u8; 16]) -> [u8; 16] {
        todo!("f3: CK")
    }

    /// f4: Integrity key IK (16 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.5:
    /// `IK = OUT4[0..16]` where OUT4 uses (c4, r4).
    pub fn f4(&self, rand: &[u8; 16]) -> [u8; 16] {
        todo!("f4: IK")
    }

    /// f5: Anonymity key AK (6 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.6:
    /// `AK = OUT2[0..6]` -- shares the same computation as f2.
    ///
    /// Used to conceal SQN in AUTN: `AUTN = (SQN XOR AK) || AMF || MAC-A`.
    pub fn f5(&self, rand: &[u8; 16]) -> [u8; 6] {
        todo!("f5: AK")
    }

    /// f5\*: Resynch anonymity key AK\* (6 bytes).
    ///
    /// Per ETSI TS 135 206 V17.0.0 clause 3.7:
    /// `AK* = OUT5[0..6]` where OUT5 uses (c5, r5).
    ///
    /// Used in AUTS construction: `AUTS = (SQN_MS XOR AK*) || MAC-S`.
    pub fn f5_star(&self, rand: &[u8; 16]) -> [u8; 6] {
        todo!("f5*: AK*")
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
        todo!("authenticate: full AKA")
    }
}

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
        let mut expected_kc = [0u8; 8];
        for i in 0..8 {
            expected_kc[i] = out.ck[i] ^ out.ck[i + 8] ^ out.ik[i] ^ out.ik[i + 8];
        }
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
}
