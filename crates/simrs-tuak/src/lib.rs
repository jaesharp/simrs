//! TUAK authentication algorithm ([3GPP TS 35.231 V19.0.0](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf)).
//!
//! Pure Rust implementation of the TUAK authentication and key generation
//! functions for USIM. Built on Keccak-f\[1600\] via `simrs-keccak`.
//!
//! Implements the [`AuthenticationAlgorithm`] trait for integration with `simrs-usim`.
//!
//! # Algorithm Structure
//!
//! TUAK uses the Keccak-f\[1600\] permutation directly (not the sponge construction).
//! A 200-byte (1600-bit) state is constructed from:
//!
//! ```text
//! TOPc(32) || INSTANCE(1) || ALGONAME(7) || RAND(16) || AMF(2) || SQN(6)
//!          || K(16..32) || padding || zeros
//! ```
//!
//! All multi-byte fields are stored in reversed (big-endian-to-little-endian) byte
//! order within the Keccak state per [3GPP TS 35.231 V19.0.0 clause 4](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A33%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
//!
//! After applying Keccak-f\[1600\], outputs are extracted from specific byte positions
//! and reversed back to big-endian.
//!
//! # Output Sizes
//!
//! This implementation uses the standard USIM sizes:
//! - MAC-A / MAC-S: 64 bits (8 bytes)
//! - RES: 64 bits (8 bytes)
//! - CK: 128 bits (16 bytes)
//! - IK: 128 bits (16 bytes)
//! - AK / AK*: 48 bits (6 bytes)
//!
//! # TOPc Computation
//!
//! `TOPc` is derived from the operator constant `TOP` and the subscriber key `K`
//! by running Keccak-f\[1600\] with `TOP` in the TOPc position, `INSTANCE=0x00`,
//! and zeroed RAND/SQN/AMF fields. The first 32 bytes of the output become TOPc.
//!
//! # Standards
//! - [3GPP TS 35.231 V19.0.0](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf) -- TUAK algorithm specification
//! - [3GPP TS 35.232 V19.0.0](../../../docs/specs/3gpp/ts-35.232/ts_135232v190000p.pdf) -- TUAK implementers' test data
//! - [3GPP TS 35.233 V19.0.0](../../../docs/specs/3gpp/ts-35.233/ts_135233v190000p.pdf) -- TUAK design conformance test data
//!
//! # `no_std`
//! This crate is `no_std`. No heap allocation.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// TUAK documentation uses many standard 3GPP terms (TOPc, MAC-A, AuC, etc.)
// that clippy flags as needing backticks. These are domain-specific nomenclature.
#![allow(clippy::doc_markdown)]

#[cfg(feature = "std")]
extern crate std;

use simrs_keccak::keccak_f1600_bytes;
use simrs_milenage::{
    AnonymityKey, AuthChallenge, AuthManagementField, AuthResponse, AuthenticationAlgorithm,
    CipherKey, IntegrityKey, NetworkMac, ResyncMac, SequenceNumber, SubscriberKey,
};
use simrs_redact::Redact;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ALGONAME = "TUAK1.0" (7 bytes, ASCII).
const ALGONAME: [u8; 7] = *b"TUAK1.0";

/// INSTANCE byte for TOPc derivation (128-bit key).
const INSTANCE_TOPC: u8 = 0x00;

/// INSTANCE byte for f1: MAC-A 64-bit, 128-bit key.
///
/// Encoding: base 0x00 | MAC_LEN=64 (0x08).
const INSTANCE_F1: u8 = 0x08;

/// INSTANCE byte for f1*: MAC-S 64-bit, 128-bit key.
///
/// Encoding: base 0x80 | MAC_LEN=64 (0x08).
const INSTANCE_F1_STAR: u8 = 0x88;

/// INSTANCE byte for f2345: RES=64, CK=128, IK=128, 128-bit key.
///
/// Encoding: base 0x40 | RES_LEN=64 (0x08) | CK_256=0 | IK_256=0 | K_256=0.
const INSTANCE_F2345: u8 = 0x48;

/// INSTANCE byte for f5*: 128-bit key.
///
/// Encoding: base 0xC0.
const INSTANCE_F5_STAR: u8 = 0xC0;

// Byte offsets within the 200-byte Keccak state (3GPP TS 35.231 V19.0.0 clause 4).
const OFF_TOPC: usize = 0; // 32 bytes
const OFF_INSTANCE: usize = 32; // 1 byte
const OFF_ALGONAME: usize = 33; // 7 bytes
const OFF_RAND: usize = 40; // 16 bytes
const OFF_AMF: usize = 56; // 2 bytes
const OFF_SQN: usize = 58; // 6 bytes
const OFF_KEY: usize = 64; // 16 bytes (128-bit key) + 16 zeros
const OFF_PAD_1F: usize = 96; // 0x1F padding marker
const OFF_PAD_80: usize = 135; // 0x80 padding marker

// Output extraction byte offsets after Keccak permutation.
const OUT_OFF_MAC: usize = 0; // MAC-A / MAC-S: bytes 0..8
const OUT_OFF_RES: usize = 0; // RES: bytes 0..8
const OUT_OFF_CK: usize = 32; // CK: bytes 32..48
const OUT_OFF_IK: usize = 64; // IK: bytes 64..80
const OUT_OFF_AK: usize = 96; // AK: bytes 96..102

use simrs_milenage::{SnapReader, SnapWriter};

// ---------------------------------------------------------------------------
// OperatorVariant
// ---------------------------------------------------------------------------

/// Operator variant for initialization (analogous to Milenage's OperatorVariant).
///
/// Either a pre-computed TOPc (256-bit) or a raw TOP value from which
/// TOPc will be derived using Keccak-f\[1600\].
///
/// # Standards
/// - [3GPP TS 35.231 V19.0.0 clause 6.1](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A39%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C300%5D) -- TOPc derivation
///
/// ```
/// use simrs_tuak::OperatorVariant;
///
/// // Pre-computed operator cipher (recommended for production)
/// let _opc = OperatorVariant::operator_cipher([0xAA; 32]);
///
/// // Raw operator parameter (cipher derived at runtime from K)
/// let _op = OperatorVariant::operator_parameter([0xBB; 32]);
/// ```
#[derive(Clone, Copy)]
pub enum OperatorVariant {
    /// Pre-computed operator cipher (256 bits). Preferred -- avoids runtime Keccak call.
    OperatorCipher(Secret<[u8; 32]>),
    /// Raw operator parameter. Cipher will be derived as per [3GPP TS 35.231 V19.0.0 clause 6.1](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A39%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C300%5D).
    OperatorParameter(Secret<[u8; 32]>),
}

impl OperatorVariant {
    /// Classify raw bytes as a pre-computed operator cipher.
    #[inline]
    pub const fn operator_cipher(raw: [u8; 32]) -> Self {
        Self::OperatorCipher(Secret::new(raw))
    }

    /// Classify raw bytes as a raw operator parameter.
    #[inline]
    pub const fn operator_parameter(raw: [u8; 32]) -> Self {
        Self::OperatorParameter(Secret::new(raw))
    }

    /// 3GPP abbreviation for [`OperatorVariant::operator_cipher`].
    #[deprecated(note = "3GPP TOPc (TS 35.231 cl. 6.1) -- prefer operator_cipher()")]
    #[inline]
    pub const fn topc(raw: [u8; 32]) -> Self {
        Self::operator_cipher(raw)
    }

    /// 3GPP abbreviation for [`OperatorVariant::operator_parameter`].
    #[deprecated(note = "3GPP TOP (TS 35.231) -- prefer operator_parameter()")]
    #[inline]
    pub const fn top(raw: [u8; 32]) -> Self {
        Self::operator_parameter(raw)
    }
}

impl core::fmt::Debug for OperatorVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OperatorCipher(v) => f
                .debug_tuple("OperatorVariant::OperatorCipher")
                .field(&Redact(v.declassify_ref()))
                .finish(),
            Self::OperatorParameter(v) => f
                .debug_tuple("OperatorVariant::OperatorParameter")
                .field(&Redact(v.declassify_ref()))
                .finish(),
        }
    }
}

/// Deprecated: use [`OperatorVariant`].
#[deprecated(note = "use `OperatorVariant` -- TOP is the 3GPP TUAK Operator Parameter")]
pub type TopVariant = OperatorVariant;

// ---------------------------------------------------------------------------
// TuakParams
// ---------------------------------------------------------------------------

/// TUAK authentication parameters.
///
/// Contains the subscriber key K (128-bit), the derived operator constant TOPc
/// (256-bit), and standard USIM output sizes (MAC=64, RES=64, CK=128, IK=128).
///
/// # Construction
///
/// Use [`TuakParams::new`] for standard parameters.
///
/// ```
/// use simrs_tuak::{TuakParams, OperatorVariant};
/// use simrs_milenage::SubscriberKey;
///
/// let params = TuakParams::new(
///     SubscriberKey::classify([0xFF; 16]),      // K
///     OperatorVariant::operator_cipher([0xAA; 32]),
/// );
/// ```
#[derive(Clone)]
pub struct TuakParams {
    /// Subscriber key K (128 bits).
    key: SubscriberKey,
    /// Derived operator cipher constant (256 bits).
    operator_cipher: Secret<[u8; 32]>,
    /// Next expected SQN (big-endian 48-bit), for replay protection per
    /// [3GPP TS 33.102 V19.1.0 clause 6.3.3](../../../docs/specs/3gpp/ts-33.102/ts_133102v190100p.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C557%5D). Initialized to zero (accept any SQN).
    expected_sequence_number: [u8; 6],
}

impl core::fmt::Debug for TuakParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TuakParams")
            .field("key", &self.key)
            .field(
                "operator_cipher",
                &Redact(self.operator_cipher.declassify_ref()),
            )
            .field("expected_sequence_number", &self.expected_sequence_number)
            .finish()
    }
}

impl TuakParams {
    /// Create with standard parameters.
    ///
    /// If `variant` is [`OperatorVariant::OperatorParameter`], the operator cipher
    /// is derived from K using Keccak-f\[1600\] per [3GPP TS 35.231 V19.0.0 clause 6.1](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A39%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C300%5D).
    ///
    /// ```
    /// use simrs_tuak::{TuakParams, OperatorVariant};
    /// use simrs_milenage::SubscriberKey;
    ///
    /// let p = TuakParams::new(SubscriberKey::classify([0u8; 16]), OperatorVariant::operator_cipher([0u8; 32]));
    /// ```
    pub fn new(key: SubscriberKey, variant: OperatorVariant) -> Self {
        let operator_cipher = match variant {
            OperatorVariant::OperatorCipher(opc) => opc,
            OperatorVariant::OperatorParameter(op_val) => {
                Secret::new(compute_topc(key.declassify(), op_val.declassify_ref()))
            }
        };
        Self {
            key,
            operator_cipher,
            expected_sequence_number: [0u8; 6],
        }
    }

    /// Compute the network authentication code MAC-A (8 bytes).
    ///
    /// 3GPP function designation: f1.
    /// Per [3GPP TS 35.231 V19.0.0 clause 5.1](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A35%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C432%5D). Uses INSTANCE 0x08 (MAC=64, K=128).
    ///
    /// ```
    /// use simrs_tuak::{TuakParams, OperatorVariant};
    /// use simrs_milenage::{AuthChallenge, AuthManagementField, SequenceNumber, SubscriberKey};
    ///
    /// let p = TuakParams::new(SubscriberKey::classify([0u8; 16]), OperatorVariant::operator_cipher([0u8; 32]));
    /// let mac_a = p.compute_auth_mac(&AuthChallenge::new([0u8; 16]), &SequenceNumber::new([0u8; 6]), &AuthManagementField::new([0u8; 2]));
    /// assert_eq!(mac_a.as_bytes().len(), 8);
    /// ```
    pub fn compute_auth_mac(
        &self,
        challenge: &AuthChallenge,
        sequence_number: &SequenceNumber,
        management_field: &AuthManagementField,
    ) -> NetworkMac {
        let buf = tuak_f1_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
            sequence_number.as_bytes(),
            management_field.as_bytes(),
            INSTANCE_F1,
        );
        let mut mac_a = [0u8; 8];
        pull_data(&buf, OUT_OFF_MAC, &mut mac_a);
        NetworkMac::new(mac_a)
    }

    /// Deprecated: use [`compute_auth_mac`](TuakParams::compute_auth_mac).
    #[deprecated(
        note = "use `compute_auth_mac` -- f1 is the 3GPP designation for MAC-A (network authentication code) computation"
    )]
    pub fn f1(
        &self,
        challenge: &AuthChallenge,
        sequence_number: &SequenceNumber,
        management_field: &AuthManagementField,
    ) -> NetworkMac {
        self.compute_auth_mac(challenge, sequence_number, management_field)
    }

    /// Compute the resynchronisation authentication code MAC-S (8 bytes).
    ///
    /// 3GPP function designation: f1*.
    /// Per [3GPP TS 35.231 V19.0.0 clause 5.2](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A37%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C177%5D). Uses INSTANCE 0x88 (MAC=64, K=128).
    ///
    /// Used in AUTS construction for SQN resynchronization.
    pub fn compute_resync_mac(
        &self,
        challenge: &AuthChallenge,
        sequence_number: &SequenceNumber,
        management_field: &AuthManagementField,
    ) -> ResyncMac {
        let buf = tuak_f1_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
            sequence_number.as_bytes(),
            management_field.as_bytes(),
            INSTANCE_F1_STAR,
        );
        let mut mac_s = [0u8; 8];
        pull_data(&buf, OUT_OFF_MAC, &mut mac_s);
        ResyncMac::new(mac_s)
    }

    /// Deprecated: use [`compute_resync_mac`](TuakParams::compute_resync_mac).
    #[deprecated(
        note = "use `compute_resync_mac` -- f1* is the 3GPP designation for MAC-S (resync authentication code) computation"
    )]
    pub fn f1_star(
        &self,
        challenge: &AuthChallenge,
        sequence_number: &SequenceNumber,
        management_field: &AuthManagementField,
    ) -> ResyncMac {
        self.compute_resync_mac(challenge, sequence_number, management_field)
    }

    /// Compute the authentication response RES (8 bytes).
    ///
    /// 3GPP function designation: f2.
    /// Per [3GPP TS 35.231 V19.0.0 clause 5.3](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A39%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C639%5D). Uses INSTANCE 0x48
    /// (RES=64, CK=128, IK=128, K=128).
    ///
    /// ```
    /// use simrs_tuak::{TuakParams, OperatorVariant};
    /// use simrs_milenage::{AuthChallenge, SubscriberKey};
    ///
    /// let p = TuakParams::new(SubscriberKey::classify([0u8; 16]), OperatorVariant::operator_cipher([0u8; 32]));
    /// let res = p.compute_response(&AuthChallenge::new([0u8; 16]));
    /// assert_eq!(res.as_bytes().len(), 8);
    /// ```
    pub fn compute_response(&self, challenge: &AuthChallenge) -> AuthResponse {
        let buf = tuak_f2345_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
        );
        let mut res = [0u8; 8];
        pull_data(&buf, OUT_OFF_RES, &mut res);
        AuthResponse::new(res)
    }

    /// Deprecated: use [`compute_response`](TuakParams::compute_response).
    #[deprecated(
        note = "use `compute_response` -- f2 is the 3GPP designation for RES (authentication response) computation"
    )]
    pub fn f2(&self, challenge: &AuthChallenge) -> AuthResponse {
        self.compute_response(challenge)
    }

    /// Compute the ciphering key CK (16 bytes).
    ///
    /// 3GPP function designation: f3.
    /// Per [3GPP TS 35.231 V19.0.0 clause 5.4](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf).
    pub fn compute_cipher_key(&self, challenge: &AuthChallenge) -> CipherKey {
        let buf = tuak_f2345_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
        );
        let mut ck = [0u8; 16];
        pull_data(&buf, OUT_OFF_CK, &mut ck);
        CipherKey::classify(ck)
    }

    /// Deprecated: use [`compute_cipher_key`](TuakParams::compute_cipher_key).
    #[deprecated(
        note = "use `compute_cipher_key` -- f3 is the 3GPP designation for CK (ciphering key) computation"
    )]
    pub fn f3(&self, challenge: &AuthChallenge) -> CipherKey {
        self.compute_cipher_key(challenge)
    }

    /// Compute the integrity key IK (16 bytes).
    ///
    /// 3GPP function designation: f4.
    /// Per [3GPP TS 35.231 V19.0.0 clause 5.5](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf).
    pub fn compute_integrity_key(&self, challenge: &AuthChallenge) -> IntegrityKey {
        let buf = tuak_f2345_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
        );
        let mut ik = [0u8; 16];
        pull_data(&buf, OUT_OFF_IK, &mut ik);
        IntegrityKey::classify(ik)
    }

    /// Deprecated: use [`compute_integrity_key`](TuakParams::compute_integrity_key).
    #[deprecated(
        note = "use `compute_integrity_key` -- f4 is the 3GPP designation for IK (integrity key) computation"
    )]
    pub fn f4(&self, challenge: &AuthChallenge) -> IntegrityKey {
        self.compute_integrity_key(challenge)
    }

    /// Compute the anonymity key AK (6 bytes).
    ///
    /// 3GPP function designation: f5.
    /// Per [3GPP TS 35.231 V19.0.0 clause 5.6](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf). Shares computation with f2/f3/f4.
    ///
    /// Used to conceal SQN in AUTN: `AUTN = (SQN XOR AK) || AMF || MAC-A`.
    pub fn compute_anonymity_key(&self, challenge: &AuthChallenge) -> AnonymityKey {
        let buf = tuak_f2345_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
        );
        let mut anonymity_key = [0u8; 6];
        pull_data(&buf, OUT_OFF_AK, &mut anonymity_key);
        AnonymityKey::new(anonymity_key)
    }

    /// Deprecated: use [`compute_anonymity_key`](TuakParams::compute_anonymity_key).
    #[deprecated(
        note = "use `compute_anonymity_key` -- f5 is the 3GPP designation for AK (anonymity key) computation"
    )]
    pub fn f5(&self, challenge: &AuthChallenge) -> AnonymityKey {
        self.compute_anonymity_key(challenge)
    }

    /// Compute the resynchronisation anonymity key AK* (6 bytes).
    ///
    /// 3GPP function designation: f5*.
    /// Per [3GPP TS 35.231 V19.0.0 clause 5.7](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf). Uses INSTANCE 0xC0 (K=128).
    ///
    /// Used in AUTS construction: `AUTS = (SQN_MS XOR AK*) || MAC-S`.
    pub fn compute_resync_anonymity_key(&self, challenge: &AuthChallenge) -> AnonymityKey {
        let buf = tuak_f5star_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
        );
        let mut resync_anonymity_key = [0u8; 6];
        pull_data(&buf, OUT_OFF_AK, &mut resync_anonymity_key);
        AnonymityKey::new(resync_anonymity_key)
    }

    /// Deprecated: use [`compute_resync_anonymity_key`](TuakParams::compute_resync_anonymity_key).
    #[deprecated(
        note = "use `compute_resync_anonymity_key` -- f5* is the 3GPP designation for AK* (resync anonymity key) computation"
    )]
    pub fn f5_star(&self, challenge: &AuthChallenge) -> AnonymityKey {
        self.compute_resync_anonymity_key(challenge)
    }

    // -- snapshot --

    /// Snapshot buffer size: 54 bytes (K(16) + TOPc(32) + expected_sequence_number(6)).
    pub const SNAPSHOT_SIZE: usize = 16 + 32 + 6;

    /// Serialize the TUAK parameters into `buf` as flat bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut w = SnapWriter::new(buf);
        w.put_bytes(self.key.declassify());
        w.put_bytes(self.operator_cipher.declassify_ref());
        w.put_bytes(&self.expected_sequence_number);
        w.finish()
    }

    /// Construct TUAK parameters directly from a snapshot buffer.
    ///
    /// Returns `None` if `buf` is too small.
    #[must_use]
    pub fn from_snapshot(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return None;
        }
        let mut r = SnapReader::new(buf);
        let mut key_bytes = [0u8; 16];
        r.get_bytes(&mut key_bytes);
        let key = SubscriberKey::classify(key_bytes);
        let mut top_c_bytes = [0u8; 32];
        r.get_bytes(&mut top_c_bytes);
        let operator_cipher = Secret::new(top_c_bytes);
        let mut expected_sequence_number = [0u8; 6];
        r.get_bytes(&mut expected_sequence_number);
        Some(Self {
            key,
            operator_cipher,
            expected_sequence_number,
        })
    }

    /// Restore the TUAK parameters from `buf`.
    ///
    /// Returns `true` on success.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        Self::from_snapshot(buf).is_some_and(|new| {
            *self = new;
            true
        })
    }
}

// ---------------------------------------------------------------------------
// AuthenticationAlgorithm trait implementation
// ---------------------------------------------------------------------------

impl AuthenticationAlgorithm for TuakParams {
    #[allow(clippy::use_self)]
    const SNAPSHOT_SIZE: usize = TuakParams::SNAPSHOT_SIZE;

    fn compute_auth_mac(
        &self,
        challenge: &AuthChallenge,
        sequence_number: &SequenceNumber,
        management_field: &AuthManagementField,
    ) -> NetworkMac {
        self.compute_auth_mac(challenge, sequence_number, management_field)
    }

    fn compute_resync_mac(
        &self,
        challenge: &AuthChallenge,
        sequence_number: &SequenceNumber,
        management_field: &AuthManagementField,
    ) -> ResyncMac {
        self.compute_resync_mac(challenge, sequence_number, management_field)
    }

    fn compute_response(&self, challenge: &AuthChallenge) -> AuthResponse {
        self.compute_response(challenge)
    }

    fn compute_cipher_key(&self, challenge: &AuthChallenge) -> CipherKey {
        self.compute_cipher_key(challenge)
    }

    fn compute_integrity_key(&self, challenge: &AuthChallenge) -> IntegrityKey {
        self.compute_integrity_key(challenge)
    }

    fn compute_anonymity_key(&self, challenge: &AuthChallenge) -> AnonymityKey {
        self.compute_anonymity_key(challenge)
    }

    fn compute_resync_anonymity_key(&self, challenge: &AuthChallenge) -> AnonymityKey {
        self.compute_resync_anonymity_key(challenge)
    }

    fn expected_sequence_number(&self) -> SequenceNumber {
        SequenceNumber::new(self.expected_sequence_number)
    }
    fn set_expected_sequence_number(&mut self, sqn: SequenceNumber) {
        self.expected_sequence_number = *sqn.as_bytes();
    }

    /// Override: compute RES, CK, IK from a single `tuak_f2345_core` Keccak call.
    fn compute_response_and_keys(
        &self,
        challenge: &AuthChallenge,
    ) -> (AuthResponse, CipherKey, IntegrityKey) {
        let buf = tuak_f2345_core(
            self.key.declassify(),
            self.operator_cipher.declassify_ref(),
            challenge.as_bytes(),
        );
        let mut response = [0u8; 8];
        let mut ck = [0u8; 16];
        let mut ik = [0u8; 16];
        pull_data(&buf, OUT_OFF_RES, &mut response);
        pull_data(&buf, OUT_OFF_CK, &mut ck);
        pull_data(&buf, OUT_OFF_IK, &mut ik);
        (
            AuthResponse::new(response),
            CipherKey::classify(ck),
            IntegrityKey::classify(ik),
        )
    }

    fn save_state(&self, buf: &mut [u8]) -> usize {
        self.save_state(buf)
    }

    fn restore_state(&mut self, buf: &[u8]) -> bool {
        self.restore_state(buf)
    }

    fn from_snapshot(buf: &[u8]) -> Option<Self> {
        Self::from_snapshot(buf)
    }
}

// ---------------------------------------------------------------------------
// Internal: byte-reversal helpers for Keccak state construction
// ---------------------------------------------------------------------------

/// Copy `src` into `buf` at byte offset `offset` with reversed byte order.
///
/// Per [3GPP TS 35.231 V19.0.0 clause 4](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A33%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D): all multi-byte fields are stored most-significant
/// byte first in the algorithm description, but the Keccak state uses
/// little-endian lane ordering. The reference implementation reverses each
/// field before placing it in the state buffer.
fn push_data(buf: &mut [u8; 200], offset: usize, src: &[u8]) {
    for (i, &b) in src.iter().enumerate() {
        buf[offset + src.len() - 1 - i] = b;
    }
}

/// Extract `dst.len()` bytes from `buf` at byte offset `offset` with
/// reversed byte order (big-endian output from little-endian Keccak state).
fn pull_data(buf: &[u8; 200], offset: usize, dst: &mut [u8]) {
    let n = dst.len();
    for i in 0..n {
        dst[i] = buf[offset + n - 1 - i];
    }
}

// ---------------------------------------------------------------------------
// Internal: TUAK core functions
// ---------------------------------------------------------------------------

/// Construct the common part of the 200-byte Keccak state.
///
/// Places TOPc, INSTANCE, ALGONAME, padding markers, and zeros.
/// Caller fills in RAND, AMF, SQN, K as needed.
fn init_state(buf: &mut [u8; 200], key: &[u8; 16], top_c: &[u8; 32], instance: u8) {
    // Zero the entire buffer first.
    *buf = [0u8; 200];

    // TOPc (32 bytes, reversed)
    push_data(buf, OFF_TOPC, top_c);

    // INSTANCE (1 byte -- no reversal needed for single byte)
    buf[OFF_INSTANCE] = instance;

    // ALGONAME "TUAK1.0" (7 bytes, reversed)
    push_data(buf, OFF_ALGONAME, &ALGONAME);

    // K (16 bytes, reversed) -- bytes 64..79, rest (80..95) stay zero for 128-bit key
    push_data(buf, OFF_KEY, key);

    // Padding markers per 3GPP TS 35.231 V19.0.0 clause 4.
    buf[OFF_PAD_1F] = 0x1F;
    buf[OFF_PAD_80] = 0x80;
}

/// TUAK core for f1 / f1*: includes RAND, SQN, AMF.
#[allow(clippy::trivially_copy_pass_by_ref)] // consistent API with public methods
fn tuak_f1_core(
    key: &[u8; 16],
    top_c: &[u8; 32],
    challenge: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    instance: u8,
) -> [u8; 200] {
    let mut buf = [0u8; 200];
    init_state(&mut buf, key, top_c, instance);

    // RAND (16 bytes, reversed)
    push_data(&mut buf, OFF_RAND, challenge);

    // AMF (2 bytes, reversed)
    push_data(&mut buf, OFF_AMF, amf);

    // SQN (6 bytes, reversed)
    push_data(&mut buf, OFF_SQN, sqn);

    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);
    buf
}

/// TUAK core for f2/f3/f4/f5: includes RAND, zeroed AMF/SQN.
fn tuak_f2345_core(key: &[u8; 16], top_c: &[u8; 32], challenge: &[u8; 16]) -> [u8; 200] {
    let mut buf = [0u8; 200];
    init_state(&mut buf, key, top_c, INSTANCE_F2345);

    // RAND (16 bytes, reversed)
    push_data(&mut buf, OFF_RAND, challenge);

    // AMF and SQN are zero (already zeroed by init_state).

    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);
    buf
}

/// TUAK core for f5*: includes RAND, zeroed AMF/SQN.
fn tuak_f5star_core(key: &[u8; 16], top_c: &[u8; 32], challenge: &[u8; 16]) -> [u8; 200] {
    let mut buf = [0u8; 200];
    init_state(&mut buf, key, top_c, INSTANCE_F5_STAR);

    // RAND (16 bytes, reversed)
    push_data(&mut buf, OFF_RAND, challenge);

    // AMF and SQN are zero (already zeroed by init_state).

    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);
    buf
}

/// Compute TOPc from TOP and K per [3GPP TS 35.231 V19.0.0 clause 6.1](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf#%5B%7B%22num%22%3A39%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C300%5D).
///
/// Uses INSTANCE=0x00, zeroed RAND/AMF/SQN, with TOP in the TOPc position.
/// The first 32 bytes of the Keccak output (reversed) become TOPc.
fn compute_topc(key: &[u8; 16], top: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 200];
    init_state(&mut buf, key, top, INSTANCE_TOPC);

    // RAND, AMF, SQN are all zero (already zeroed by init_state).

    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);

    // Extract first 32 bytes (reversed)
    let mut topc = [0u8; 32];
    pull_data(&buf, 0, &mut topc);
    topc
}

// ---------------------------------------------------------------------------
// Internal test helper: configurable INSTANCE for conformance testing
// ---------------------------------------------------------------------------

/// Run TUAK core with arbitrary INSTANCE byte and return the full 200-byte
/// output state. Used by conformance tests that use non-standard output sizes.
#[cfg(test)]
#[allow(clippy::trivially_copy_pass_by_ref)] // consistent API
fn tuak_core_with_instance(
    key: &[u8],
    top_c: &[u8; 32],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    instance: u8,
) -> [u8; 200] {
    let mut buf = [0u8; 200];
    // Zero the entire buffer.
    // Place TOPc
    push_data(&mut buf, OFF_TOPC, top_c);
    // INSTANCE
    buf[OFF_INSTANCE] = instance;
    // ALGONAME
    push_data(&mut buf, OFF_ALGONAME, &ALGONAME);
    // RAND
    push_data(&mut buf, OFF_RAND, rand);
    // AMF
    push_data(&mut buf, OFF_AMF, amf);
    // SQN
    push_data(&mut buf, OFF_SQN, sqn);
    // K -- support both 16 and 32 byte keys
    if key.len() == 32 {
        push_data(&mut buf, OFF_KEY, key);
    } else {
        push_data(&mut buf, OFF_KEY, &key[..16]);
    }
    // Padding
    buf[OFF_PAD_1F] = 0x1F;
    buf[OFF_PAD_80] = 0x80;
    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);
    buf
}

/// Compute TOPc from TOP and K with arbitrary key length (for test conformance).
#[cfg(test)]
fn compute_topc_any(key: &[u8], top: &[u8; 32]) -> [u8; 32] {
    let instance = u8::from(key.len() == 32);
    let mut buf = [0u8; 200];
    push_data(&mut buf, OFF_TOPC, top);
    buf[OFF_INSTANCE] = instance;
    push_data(&mut buf, OFF_ALGONAME, &ALGONAME);
    if key.len() == 32 {
        push_data(&mut buf, OFF_KEY, key);
    } else {
        push_data(&mut buf, OFF_KEY, &key[..16]);
    }
    buf[OFF_PAD_1F] = 0x1F;
    buf[OFF_PAD_80] = 0x80;
    keccak_f1600_bytes(&mut buf);
    let mut topc = [0u8; 32];
    pull_data(&buf, 0, &mut topc);
    topc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_milenage::{AuthToken, AuthenticationError};

    // ---------------------------------------------------------------
    // Helper: parse hex string to byte array at compile time
    // ---------------------------------------------------------------

    /// Parse a hex string into a fixed-size byte array at runtime (test only).
    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2, "hex string length mismatch");
        let mut out = [0u8; N];
        for i in 0..N {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    // ---------------------------------------------------------------
    // 3GPP TS 35.233 V19.0.0 Test Set 1 (Section 6.3)
    //
    // K = 128-bit, MAC=64, RES=32, CK=128, IK=128
    // KeccakIterations = 1
    //
    // Note: RES=32 means INSTANCE for f2345 = 0x40 (not our standard 0x48).
    // We test TOPc derivation and f1/f1* using the exact spec values.
    // ---------------------------------------------------------------

    const TS1_K: [u8; 16] = [
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB,
    ];
    const TS1_TOP: [u8; 32] = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55,
    ];
    const TS1_RAND: [u8; 16] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42,
    ];
    const TS1_SQN: [u8; 6] = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
    const TS1_AMF: [u8; 2] = [0xFF, 0xFF];

    const TS1_TOPC: [u8; 32] = [
        0xBD, 0x04, 0xD9, 0x53, 0x0E, 0x87, 0x51, 0x3C, 0x5D, 0x83, 0x7A, 0xC2, 0xAD, 0x95, 0x46,
        0x23, 0xA8, 0xE2, 0x33, 0x0C, 0x11, 0x53, 0x05, 0xA7, 0x3E, 0xB4, 0x5D, 0x1F, 0x40, 0xCC,
        0xCB, 0xFF,
    ];

    // f1 MAC-A (8 bytes, MAC=64)
    const TS1_F1: [u8; 8] = [0xF9, 0xA5, 0x4E, 0x6A, 0xEA, 0xA8, 0x61, 0x8D];
    // f1* MAC-S (8 bytes, MAC=64)
    const TS1_F1_STAR: [u8; 8] = [0xE9, 0x4B, 0x4D, 0xC6, 0xC7, 0x29, 0x7D, 0xF3];
    // f2 RES (4 bytes, RES=32) -- uses INSTANCE 0x40
    const TS1_F2_RES_32: [u8; 4] = [0x65, 0x7A, 0xCD, 0x64];
    // f3 CK (16 bytes)
    const TS1_F3: [u8; 16] = [
        0xD7, 0x1A, 0x1E, 0x5C, 0x6C, 0xAF, 0xFE, 0x98, 0x6A, 0x26, 0xF7, 0x83, 0xE5, 0xC7, 0x8B,
        0xE1,
    ];
    // f4 IK (16 bytes)
    const TS1_F4: [u8; 16] = [
        0xBE, 0x84, 0x9F, 0xA2, 0x56, 0x4F, 0x86, 0x9A, 0xEC, 0xEE, 0x6F, 0x62, 0xD4, 0x33, 0x7E,
        0x72,
    ];
    // f5 AK (6 bytes)
    const TS1_F5: [u8; 6] = [0x71, 0x9F, 0x1E, 0x9B, 0x90, 0x54];
    // f5* AK* (6 bytes)
    const TS1_F5_STAR_AK: [u8; 6] = [0xE7, 0xAF, 0x6B, 0x3D, 0x0E, 0x38];

    #[test]
    fn topc_derivation_test_set_1() {
        let computed = compute_topc(&TS1_K, &TS1_TOP);
        assert_eq!(
            computed, TS1_TOPC,
            "TOPc derivation must match TS 35.233 Test Set 1"
        );
    }

    #[test]
    fn f1_test_set_1() {
        // Test set 1 uses MAC=64, K=128, so INSTANCE_F1=0x08 matches our standard.
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        assert_eq!(
            *p.compute_auth_mac(
                &AuthChallenge::new(TS1_RAND),
                &SequenceNumber::new(TS1_SQN),
                &AuthManagementField::new(TS1_AMF)
            )
            .as_bytes(),
            TS1_F1
        );
    }

    #[test]
    fn f1_star_test_set_1() {
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        assert_eq!(
            *p.compute_resync_mac(
                &AuthChallenge::new(TS1_RAND),
                &SequenceNumber::new(TS1_SQN),
                &AuthManagementField::new(TS1_AMF)
            )
            .as_bytes(),
            TS1_F1_STAR
        );
    }

    #[test]
    fn f2345_test_set_1_with_res32_instance() {
        // Test set 1 uses RES=32, so INSTANCE=0x40 (not our default 0x48).
        // We test with the exact INSTANCE to verify core Keccak construction.
        let topc = compute_topc_any(&TS1_K, &TS1_TOP);
        assert_eq!(topc, TS1_TOPC);

        // Use the configurable core with INSTANCE=0x40
        let buf = tuak_core_with_instance(
            &TS1_K, &topc, &TS1_RAND, &[0u8; 6], // SQN=0 for f2345
            &[0u8; 2], // AMF=0 for f2345
            0x40,      // INSTANCE for RES=32, CK=128, IK=128, K=128
        );

        // Extract RES (4 bytes for RES=32)
        let mut res = [0u8; 4];
        pull_data(&buf, OUT_OFF_RES, &mut res);
        assert_eq!(
            res, TS1_F2_RES_32,
            "f2 RES (32-bit) must match TS 35.233 Test Set 1"
        );

        // Extract CK (16 bytes)
        let mut ck = [0u8; 16];
        pull_data(&buf, OUT_OFF_CK, &mut ck);
        assert_eq!(ck, TS1_F3, "f3 CK must match TS 35.233 Test Set 1");

        // Extract IK (16 bytes)
        let mut ik = [0u8; 16];
        pull_data(&buf, OUT_OFF_IK, &mut ik);
        assert_eq!(ik, TS1_F4, "f4 IK must match TS 35.233 Test Set 1");

        // Extract AK (6 bytes)
        let mut ak = [0u8; 6];
        pull_data(&buf, OUT_OFF_AK, &mut ak);
        assert_eq!(ak, TS1_F5, "f5 AK must match TS 35.233 Test Set 1");
    }

    #[test]
    fn f5_star_test_set_1() {
        // f5* uses INSTANCE=0xC0, K=128.
        let topc = compute_topc_any(&TS1_K, &TS1_TOP);

        let buf = tuak_core_with_instance(
            &TS1_K, &topc, &TS1_RAND, &[0u8; 6], &[0u8; 2], 0xC0, // INSTANCE for f5*, K=128
        );

        let mut ak_star = [0u8; 6];
        pull_data(&buf, OUT_OFF_AK, &mut ak_star);
        assert_eq!(
            ak_star, TS1_F5_STAR_AK,
            "f5* AK* must match TS 35.233 Test Set 1"
        );
    }

    // ---------------------------------------------------------------
    // 3GPP TS 35.233 V19.0.0 Test Set 4 (Section 6.6)
    //
    // K = 128-bit, MAC=128, RES=128, CK=128, IK=128
    // KeccakIterations = 1
    //
    // Different sizes from our standard (MAC=128, RES=128),
    // but validates the core construction with a different key.
    // ---------------------------------------------------------------

    #[test]
    fn topc_derivation_test_set_4() {
        let k: [u8; 16] = hex_to_bytes("b8da837a50652d6ac7c97da14f6acc61");
        let top: [u8; 32] =
            hex_to_bytes("0952be13556c32ebc58195d9dd930493e12a9003669988ffde5fa1f0fe35cc01");
        let expected_topc: [u8; 32] =
            hex_to_bytes("2bc16eb657a68e1f446f08f57c0efb1d493527a2e652ce281eb6ca0e4487760a");
        let computed = compute_topc_any(&k, &top);
        assert_eq!(
            computed, expected_topc,
            "TOPc must match TS 35.233 Test Set 4"
        );
    }

    // ---------------------------------------------------------------
    // 3GPP TS 35.233 V19.0.0 Test Set 2 (Section 6.4)
    //
    // K = 256-bit, MAC=128, RES=64, CK=128, IK=128
    // KeccakIterations = 1
    //
    // Validates 256-bit key handling.
    // ---------------------------------------------------------------

    #[test]
    fn topc_derivation_test_set_2() {
        let k: [u8; 32] =
            hex_to_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");
        let top: [u8; 32] =
            hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let expected_topc: [u8; 32] =
            hex_to_bytes("305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524");
        let computed = compute_topc_any(&k, &top);
        assert_eq!(
            computed, expected_topc,
            "TOPc must match TS 35.233 Test Set 2"
        );
    }

    // ---------------------------------------------------------------
    // TOP / TOPc equivalence
    // ---------------------------------------------------------------

    #[test]
    fn top_and_topc_produce_same_response() {
        let topc = compute_topc(&TS1_K, &TS1_TOP);
        let p_top = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let p_topc = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_cipher(topc),
        );
        assert_eq!(
            p_top
                .compute_response(&AuthChallenge::new(TS1_RAND))
                .as_bytes(),
            p_topc
                .compute_response(&AuthChallenge::new(TS1_RAND))
                .as_bytes()
        );
    }

    // ---------------------------------------------------------------
    // Structural tests for standard output sizes
    // ---------------------------------------------------------------

    #[test]
    fn auth_mac_and_resync_mac_differ() {
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let auth_mac = p.compute_auth_mac(
            &AuthChallenge::new(TS1_RAND),
            &SequenceNumber::new(TS1_SQN),
            &AuthManagementField::new(TS1_AMF),
        );
        let resync_mac = p.compute_resync_mac(
            &AuthChallenge::new(TS1_RAND),
            &SequenceNumber::new(TS1_SQN),
            &AuthManagementField::new(TS1_AMF),
        );
        assert_ne!(
            *auth_mac.as_bytes(),
            *resync_mac.as_bytes(),
            "compute_auth_mac and compute_resync_mac must produce different outputs"
        );
    }

    #[test]
    fn anonymity_key_and_resync_anonymity_key_differ() {
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let anonymity_key = p.compute_anonymity_key(&AuthChallenge::new(TS1_RAND));
        let resync_anonymity_key = p.compute_resync_anonymity_key(&AuthChallenge::new(TS1_RAND));
        assert_ne!(
            anonymity_key, resync_anonymity_key,
            "compute_anonymity_key and compute_resync_anonymity_key must produce different outputs"
        );
    }

    #[test]
    fn different_challenge_different_outputs() {
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let challenge2 = [0x99u8; 16];
        assert_ne!(
            *p.compute_response(&AuthChallenge::new(TS1_RAND)).as_bytes(),
            *p.compute_response(&AuthChallenge::new(challenge2))
                .as_bytes()
        );
        assert_ne!(
            *p.compute_cipher_key(&AuthChallenge::new(TS1_RAND))
                .declassify(),
            *p.compute_cipher_key(&AuthChallenge::new(challenge2))
                .declassify()
        );
        assert_ne!(
            *p.compute_integrity_key(&AuthChallenge::new(TS1_RAND))
                .declassify(),
            *p.compute_integrity_key(&AuthChallenge::new(challenge2))
                .declassify()
        );
    }

    #[test]
    fn deterministic() {
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        assert_eq!(
            p.compute_response(&AuthChallenge::new(TS1_RAND)).as_bytes(),
            p.compute_response(&AuthChallenge::new(TS1_RAND)).as_bytes()
        );
        assert_eq!(
            *p.compute_cipher_key(&AuthChallenge::new(TS1_RAND))
                .declassify(),
            *p.compute_cipher_key(&AuthChallenge::new(TS1_RAND))
                .declassify()
        );
        assert_eq!(
            p.compute_anonymity_key(&AuthChallenge::new(TS1_RAND)),
            p.compute_anonymity_key(&AuthChallenge::new(TS1_RAND))
        );
    }

    #[test]
    fn all_functions_produce_nonzero_output() {
        // Use non-trivial key/TOP to avoid accidental zero outputs.
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        assert_ne!(
            *p.compute_auth_mac(
                &AuthChallenge::new(TS1_RAND),
                &SequenceNumber::new(TS1_SQN),
                &AuthManagementField::new(TS1_AMF)
            )
            .as_bytes(),
            [0u8; 8]
        );
        assert_ne!(
            *p.compute_resync_mac(
                &AuthChallenge::new(TS1_RAND),
                &SequenceNumber::new(TS1_SQN),
                &AuthManagementField::new(TS1_AMF)
            )
            .as_bytes(),
            [0u8; 8]
        );
        assert_ne!(
            *p.compute_response(&AuthChallenge::new(TS1_RAND)).as_bytes(),
            [0u8; 8]
        );
        assert_ne!(
            *p.compute_cipher_key(&AuthChallenge::new(TS1_RAND))
                .declassify(),
            [0u8; 16]
        );
        assert_ne!(
            *p.compute_integrity_key(&AuthChallenge::new(TS1_RAND))
                .declassify(),
            [0u8; 16]
        );
        assert_ne!(
            p.compute_anonymity_key(&AuthChallenge::new(TS1_RAND)),
            AnonymityKey::new([0u8; 6])
        );
        assert_ne!(
            p.compute_resync_anonymity_key(&AuthChallenge::new(TS1_RAND)),
            AnonymityKey::new([0u8; 6])
        );
    }

    // ---------------------------------------------------------------
    // Full authentication
    // ---------------------------------------------------------------

    #[test]
    fn authenticate_with_valid_autn() {
        let mut p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let challenge = AuthChallenge::new(TS1_RAND);
        let sqn = SequenceNumber::new(TS1_SQN);
        let amf = AuthManagementField::new(TS1_AMF);

        // Construct valid AUTN: (SQN XOR AK) || AMF || MAC-A
        let ak = p.compute_anonymity_key(&challenge);
        let mut auth_token = [0u8; 16];
        for (dst, (s, a)) in auth_token[..6]
            .iter_mut()
            .zip(sqn.as_bytes().iter().zip(ak.as_bytes()))
        {
            *dst = s ^ a;
        }
        auth_token[6] = amf.as_bytes()[0];
        auth_token[7] = amf.as_bytes()[1];
        let auth_mac = p.compute_auth_mac(&challenge, &sqn, &amf);
        auth_token[8..16].copy_from_slice(auth_mac.as_bytes());

        let result = p.authenticate(&challenge, &AuthToken::new(auth_token));
        assert!(result.is_ok(), "valid AUTN must authenticate successfully");
        let out = result.unwrap();
        assert_eq!(
            out.response.as_bytes(),
            p.compute_response(&challenge).as_bytes()
        );
        assert_eq!(
            *out.cipher_key.declassify(),
            *p.compute_cipher_key(&challenge).declassify()
        );
        assert_eq!(
            *out.integrity_key.declassify(),
            *p.compute_integrity_key(&challenge).declassify()
        );
    }

    #[test]
    fn authenticate_with_bad_mac_fails() {
        let mut p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        // All-0xFF AUTN will have wrong MAC-A
        let result = p.authenticate(&AuthChallenge::new(TS1_RAND), &AuthToken::new([0xFFu8; 16]));
        assert!(matches!(result, Err(AuthenticationError::MacFailure)));
    }

    #[test]
    fn authenticate_gsm_cipher_key_is_c3_conversion() {
        let mut p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let challenge = AuthChallenge::new(TS1_RAND);
        let sqn = SequenceNumber::new(TS1_SQN);
        let amf = AuthManagementField::new(TS1_AMF);

        // Build valid AUTN
        let ak = p.compute_anonymity_key(&challenge);
        let mut auth_token = [0u8; 16];
        for (dst, (s, a)) in auth_token[..6]
            .iter_mut()
            .zip(sqn.as_bytes().iter().zip(ak.as_bytes()))
        {
            *dst = s ^ a;
        }
        auth_token[6..8].copy_from_slice(amf.as_bytes());
        auth_token[8..16].copy_from_slice(p.compute_auth_mac(&challenge, &sqn, &amf).as_bytes());

        let out = p
            .authenticate(&challenge, &AuthToken::new(auth_token))
            .unwrap();

        // Verify C3 conversion: Kc[i] = CK[i] ^ CK[i+8] ^ IK[i] ^ IK[i+8]
        #[allow(clippy::needless_range_loop)] // indices into 4 arrays with offset
        let expected_gsm_cipher_key: [u8; 8] = {
            let ck = out.cipher_key.declassify();
            let ik = out.integrity_key.declassify();
            let mut gsm_key = [0u8; 8];
            for i in 0..8 {
                gsm_key[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
            }
            gsm_key
        };
        assert_eq!(
            *out.gsm_cipher_key.declassify(),
            expected_gsm_cipher_key,
            "gsm_cipher_key must be C3 conversion of CK||IK"
        );
    }

    // ---------------------------------------------------------------
    // Snapshot tests
    // ---------------------------------------------------------------

    #[test]
    fn snapshot_size_correct() {
        assert_eq!(TuakParams::SNAPSHOT_SIZE, 54);
    }

    #[test]
    fn snapshot_roundtrip_preserves_computation() {
        let orig = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );

        let mut snap = [0u8; TuakParams::SNAPSHOT_SIZE];
        assert_eq!(orig.save_state(&mut snap), 54);

        let restored =
            TuakParams::from_snapshot(&snap).expect("from_snapshot must succeed for valid buffer");

        // Restored params must produce the same outputs.
        assert_eq!(
            restored
                .compute_response(&AuthChallenge::new(TS1_RAND))
                .as_bytes(),
            orig.compute_response(&AuthChallenge::new(TS1_RAND))
                .as_bytes()
        );
        assert_eq!(
            restored.compute_anonymity_key(&AuthChallenge::new(TS1_RAND)),
            orig.compute_anonymity_key(&AuthChallenge::new(TS1_RAND))
        );
        assert_eq!(
            restored
                .compute_auth_mac(
                    &AuthChallenge::new(TS1_RAND),
                    &SequenceNumber::new(TS1_SQN),
                    &AuthManagementField::new(TS1_AMF)
                )
                .as_bytes(),
            orig.compute_auth_mac(
                &AuthChallenge::new(TS1_RAND),
                &SequenceNumber::new(TS1_SQN),
                &AuthManagementField::new(TS1_AMF)
            )
            .as_bytes()
        );
    }

    #[test]
    fn snapshot_roundtrip_preserves_expected_sequence_number() {
        let mut p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let challenge = AuthChallenge::new(TS1_RAND);
        let sqn = SequenceNumber::new(TS1_SQN);
        let amf = AuthManagementField::new(TS1_AMF);

        // Advance expected_sequence_number by performing a successful authenticate.
        let ak = p.compute_anonymity_key(&challenge);
        let mut autn_bytes = [0u8; 16];
        for (dst, (s, a)) in autn_bytes[..6]
            .iter_mut()
            .zip(sqn.as_bytes().iter().zip(ak.as_bytes()))
        {
            *dst = s ^ a;
        }
        autn_bytes[6..8].copy_from_slice(amf.as_bytes());
        autn_bytes[8..16].copy_from_slice(p.compute_auth_mac(&challenge, &sqn, &amf).as_bytes());
        let auth_token = AuthToken::new(autn_bytes);
        p.authenticate(&challenge, &auth_token)
            .expect("setup authenticate must succeed");

        let mut snap = [0u8; TuakParams::SNAPSHOT_SIZE];
        assert_eq!(p.save_state(&mut snap), TuakParams::SNAPSHOT_SIZE);

        let mut restored =
            TuakParams::from_snapshot(&snap).expect("from_snapshot must succeed for valid buffer");

        // Replaying the same SQN must trigger SyncFailure on the restored
        // instance, proving expected_sequence_number was preserved.
        let result = restored.authenticate(&challenge, &auth_token);
        assert!(
            matches!(result, Err(AuthenticationError::SyncFailure { .. })),
            "restored instance must reject the already-consumed SQN",
        );
    }

    #[test]
    fn sqn_boundary_accepts_equal_rejects_below() {
        let mut p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );
        let challenge = AuthChallenge::new(TS1_RAND);
        let amf = AuthManagementField::new([0x80, 0x00]);

        let build_auth_token = |p: &TuakParams, sqn: SequenceNumber| -> AuthToken {
            let ak = p.compute_anonymity_key(&challenge);
            let mut autn = [0u8; 16];
            for (dst, (s, a)) in autn[..6]
                .iter_mut()
                .zip(sqn.as_bytes().iter().zip(ak.as_bytes()))
            {
                *dst = s ^ a;
            }
            autn[6..8].copy_from_slice(amf.as_bytes());
            autn[8..16].copy_from_slice(p.compute_auth_mac(&challenge, &sqn, &amf).as_bytes());
            AuthToken::new(autn)
        };

        // SQN=5: accepted (expected_sequence_number starts at 0).
        let sqn_5 = SequenceNumber::new([0, 0, 0, 0, 0, 5]);
        let auth_token = build_auth_token(&p, sqn_5);
        assert!(p.authenticate(&challenge, &auth_token).is_ok());
        // expected_sequence_number is now 6.

        // SQN=6: boundary -- exactly expected_sequence_number, should be accepted.
        let sqn_6 = SequenceNumber::new([0, 0, 0, 0, 0, 6]);
        let auth_token = build_auth_token(&p, sqn_6);
        assert!(p.authenticate(&challenge, &auth_token).is_ok());
        // expected_sequence_number is now 7.

        // SQN=6: below expected_sequence_number=7, rejected as replay.
        let auth_token = build_auth_token(&p, sqn_6);
        assert!(
            matches!(
                p.authenticate(&challenge, &auth_token),
                Err(AuthenticationError::SyncFailure { .. })
            ),
            "SQN below expected_sequence_number must trigger SyncFailure",
        );
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let p = TuakParams::new(
            SubscriberKey::classify([0u8; 16]),
            OperatorVariant::operator_cipher([0u8; 32]),
        );
        let mut small = [0u8; 20];
        assert_eq!(p.save_state(&mut small), 0);

        let mut p2 = TuakParams::new(
            SubscriberKey::classify([0u8; 16]),
            OperatorVariant::operator_cipher([0u8; 32]),
        );
        assert!(!p2.restore_state(&small));
    }

    // ---------------------------------------------------------------
    // AuthenticationAlgorithm trait tests
    // ---------------------------------------------------------------

    #[test]
    fn trait_methods_match_inherent() {
        let p = TuakParams::new(
            SubscriberKey::classify(TS1_K),
            OperatorVariant::operator_parameter(TS1_TOP),
        );

        // Verify trait methods delegate to inherent methods.
        let challenge = AuthChallenge::new(TS1_RAND);
        let sqn = SequenceNumber::new(TS1_SQN);
        let amf = AuthManagementField::new(TS1_AMF);
        let trait_auth_mac = AuthenticationAlgorithm::compute_auth_mac(&p, &challenge, &sqn, &amf);
        let inherent_auth_mac = p.compute_auth_mac(&challenge, &sqn, &amf);
        assert_eq!(trait_auth_mac.as_bytes(), inherent_auth_mac.as_bytes());

        let trait_response = AuthenticationAlgorithm::compute_response(&p, &challenge);
        let inherent_response = p.compute_response(&challenge);
        assert_eq!(trait_response.as_bytes(), inherent_response.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn make_params(key: [u8; 16]) -> TuakParams {
        TuakParams::new(
            SubscriberKey::classify(key),
            OperatorVariant::operator_cipher([0x83u8; 32]),
        )
    }

    proptest! {
        // Different keys must produce different (RES, CK, IK, AK).
        #[test]
        fn different_keys_different_output(
            k1 in any::<[u8; 16]>(),
            k2 in any::<[u8; 16]>(),
            rand_raw in any::<[u8; 16]>(),
        ) {
            prop_assume!(k1 != k2);
            let challenge = AuthChallenge::new(rand_raw);
            let p1 = make_params(k1);
            let p2 = make_params(k2);

            let res1 = p1.compute_response(&challenge);
            let res2 = p2.compute_response(&challenge);
            let ck1 = *p1.compute_cipher_key(&challenge).declassify();
            let ck2 = *p2.compute_cipher_key(&challenge).declassify();
            let ik1 = *p1.compute_integrity_key(&challenge).declassify();
            let ik2 = *p2.compute_integrity_key(&challenge).declassify();
            let ak1 = p1.compute_anonymity_key(&challenge);
            let ak2 = p2.compute_anonymity_key(&challenge);

            // At least one of the four outputs must differ.
            let any_differ = res1.as_bytes() != res2.as_bytes() || ck1 != ck2 || ik1 != ik2 || ak1 != ak2;
            prop_assert!(any_differ, "different keys must produce different output tuples");
        }
    }

    proptest! {
        // f1 (auth MAC) != f1* (resync MAC) for the same inputs.
        #[test]
        fn f1_neq_f1_star(
            key in any::<[u8; 16]>(),
            rand_raw in any::<[u8; 16]>(),
            sqn_raw in any::<[u8; 6]>(),
            amf_raw in any::<[u8; 2]>(),
        ) {
            let challenge = AuthChallenge::new(rand_raw);
            let sqn = SequenceNumber::new(sqn_raw);
            let amf = AuthManagementField::new(amf_raw);
            let p = make_params(key);
            let mac_a = p.compute_auth_mac(&challenge, &sqn, &amf);
            let mac_s = p.compute_resync_mac(&challenge, &sqn, &amf);
            prop_assert_ne!(*mac_a.as_bytes(), *mac_s.as_bytes(), "f1 (MAC-A) must differ from f1* (MAC-S)");
        }
    }

    proptest! {
        // Output determinism: same inputs always produce identical outputs.
        #[test]
        fn output_deterministic(key in any::<[u8; 16]>(), rand_raw in any::<[u8; 16]>()) {
            let challenge = AuthChallenge::new(rand_raw);
            let p = make_params(key);
            let res1 = p.compute_response(&challenge);
            let res2 = p.compute_response(&challenge);
            prop_assert_eq!(res1.as_bytes(), res2.as_bytes());

            let ck1 = *p.compute_cipher_key(&challenge).declassify();
            let ck2 = *p.compute_cipher_key(&challenge).declassify();
            prop_assert_eq!(ck1, ck2);
        }
    }

    proptest! {
        // Different RAND values with the same key produce different RES.
        #[test]
        fn different_rand_different_res(
            key in any::<[u8; 16]>(),
            r1_raw in any::<[u8; 16]>(),
            r2_raw in any::<[u8; 16]>(),
        ) {
            prop_assume!(r1_raw != r2_raw);
            let p = make_params(key);
            let res1 = p.compute_response(&AuthChallenge::new(r1_raw));
            let res2 = p.compute_response(&AuthChallenge::new(r2_raw));
            prop_assert_ne!(res1.as_bytes(), res2.as_bytes(), "different RAND must produce different RES");
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet)
//
//   cargo test -p simrs-tuak --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    /// TUAK compute_response (representative of f2345): class 0 = fixed key
    /// with fixed TopC and random RAND; class 1 = random key with same fixed
    /// TopC and random RAND.  A non-constant-time implementation would show
    /// timing differences across different key values.
    #[test]
    fn test_tuak_compute_response_ct() {
        let topc = [0x83u8; 32];
        let outcome = ct_test(
            88,
            |rng| {
                let key = [0x46u8; 16];
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |(key, topc, challenge)| {
                let p = TuakParams::new(
                    SubscriberKey::classify(*key),
                    OperatorVariant::operator_cipher(*topc),
                );
                black_box(p.compute_response(&AuthChallenge::new(*challenge)));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// TUAK f1 (compute_auth_mac): class 0 = fixed key with random RAND,
    /// SQN, AMF; class 1 = random key with random RAND, SQN, AMF.
    #[test]
    fn test_tuak_compute_auth_mac_ct() {
        let topc = [0x83u8; 32];
        let outcome = ct_test(
            89,
            |rng| {
                let key = [0x46u8; 16];
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, topc, challenge, sqn, amf)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, topc, challenge, sqn, amf)
            },
            |(key, topc, challenge, sqn, amf)| {
                let p = TuakParams::new(
                    SubscriberKey::classify(*key),
                    OperatorVariant::operator_cipher(*topc),
                );
                black_box(p.compute_auth_mac(
                    &AuthChallenge::new(*challenge),
                    &SequenceNumber::new(*sqn),
                    &AuthManagementField::new(*amf),
                ));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// TUAK f1* (compute_resync_mac): class 0 = fixed key with random RAND,
    /// SQN, AMF; class 1 = random key with random RAND, SQN, AMF.
    #[test]
    fn test_tuak_compute_resync_mac_ct() {
        let topc = [0x83u8; 32];
        let outcome = ct_test(
            90,
            |rng| {
                let key = [0x46u8; 16];
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, topc, challenge, sqn, amf)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                let mut sqn = [0u8; 6];
                rng.fill_bytes(&mut sqn);
                let mut amf = [0u8; 2];
                rng.fill_bytes(&mut amf);
                (key, topc, challenge, sqn, amf)
            },
            |(key, topc, challenge, sqn, amf)| {
                let p = TuakParams::new(
                    SubscriberKey::classify(*key),
                    OperatorVariant::operator_cipher(*topc),
                );
                black_box(p.compute_resync_mac(
                    &AuthChallenge::new(*challenge),
                    &SequenceNumber::new(*sqn),
                    &AuthManagementField::new(*amf),
                ));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// TUAK f3 (compute_cipher_key): class 0 = fixed key with random RAND;
    /// class 1 = random key with random RAND.
    #[test]
    fn test_tuak_compute_cipher_key_ct() {
        let topc = [0x83u8; 32];
        let outcome = ct_test(
            91,
            |rng| {
                let key = [0x46u8; 16];
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |(key, topc, challenge)| {
                let p = TuakParams::new(
                    SubscriberKey::classify(*key),
                    OperatorVariant::operator_cipher(*topc),
                );
                black_box(p.compute_cipher_key(&AuthChallenge::new(*challenge)));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// TUAK f4 (compute_integrity_key): class 0 = fixed key with random RAND;
    /// class 1 = random key with random RAND.
    #[test]
    fn test_tuak_compute_integrity_key_ct() {
        let topc = [0x83u8; 32];
        let outcome = ct_test(
            92,
            |rng| {
                let key = [0x46u8; 16];
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |(key, topc, challenge)| {
                let p = TuakParams::new(
                    SubscriberKey::classify(*key),
                    OperatorVariant::operator_cipher(*topc),
                );
                black_box(p.compute_integrity_key(&AuthChallenge::new(*challenge)));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// TUAK f5 (compute_anonymity_key): class 0 = fixed key with random RAND;
    /// class 1 = random key with random RAND.
    #[test]
    fn test_tuak_compute_anonymity_key_ct() {
        let topc = [0x83u8; 32];
        let outcome = ct_test(
            93,
            |rng| {
                let key = [0x46u8; 16];
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |(key, topc, challenge)| {
                let p = TuakParams::new(
                    SubscriberKey::classify(*key),
                    OperatorVariant::operator_cipher(*topc),
                );
                black_box(p.compute_anonymity_key(&AuthChallenge::new(*challenge)));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// TUAK f5* (compute_resync_anonymity_key): class 0 = fixed key with
    /// random RAND; class 1 = random key with random RAND.
    #[test]
    fn test_tuak_compute_resync_anonymity_key_ct() {
        let topc = [0x83u8; 32];
        let outcome = ct_test(
            94,
            |rng| {
                let key = [0x46u8; 16];
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut challenge = [0u8; 16];
                rng.fill_bytes(&mut challenge);
                (key, topc, challenge)
            },
            |(key, topc, challenge)| {
                let p = TuakParams::new(
                    SubscriberKey::classify(*key),
                    OperatorVariant::operator_cipher(*topc),
                );
                black_box(p.compute_resync_anonymity_key(&AuthChallenge::new(*challenge)));
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
