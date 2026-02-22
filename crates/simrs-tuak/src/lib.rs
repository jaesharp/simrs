//! TUAK authentication algorithm (3GPP TS 35.231).
//!
//! Pure Rust implementation of the TUAK authentication and key generation
//! functions for USIM. Built on Keccak-f\[1600\] via `simrs-keccak`.
//!
//! Implements the [`AuthAlgorithm`] trait for integration with `simrs-usim`.
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
//! order within the Keccak state per TS 35.231 clause 4.
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
//! - 3GPP TS 35.231 V17.0.0 -- TUAK algorithm specification
//! - 3GPP TS 35.232 V17.0.0 -- TUAK implementers' test data
//! - 3GPP TS 35.233 V17.0.0 -- TUAK design conformance test data
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
use simrs_milenage::{AuthAlgorithm, AuthOutput, MilenageError};

/// Constant-time byte slice comparison. Returns true if all bytes are equal.
///
/// Always examines every byte regardless of where mismatches occur, preventing
/// timing side-channel attacks on MAC verification.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

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

// Byte offsets within the 200-byte Keccak state (TS 35.231 clause 4).
const OFF_TOPC: usize = 0;       // 32 bytes
const OFF_INSTANCE: usize = 32;  // 1 byte
const OFF_ALGONAME: usize = 33;  // 7 bytes
const OFF_RAND: usize = 40;      // 16 bytes
const OFF_AMF: usize = 56;       // 2 bytes
const OFF_SQN: usize = 58;       // 6 bytes
const OFF_KEY: usize = 64;       // 16 bytes (128-bit key) + 16 zeros
const OFF_PAD_1F: usize = 96;    // 0x1F padding marker
const OFF_PAD_80: usize = 135;   // 0x80 padding marker

// Output extraction byte offsets after Keccak permutation.
const OUT_OFF_MAC: usize = 0;    // MAC-A / MAC-S: bytes 0..8
const OUT_OFF_RES: usize = 0;    // RES: bytes 0..8
const OUT_OFF_CK: usize = 32;    // CK: bytes 32..48
const OUT_OFF_IK: usize = 64;    // IK: bytes 64..80
const OUT_OFF_AK: usize = 96;    // AK: bytes 96..102

// ---------------------------------------------------------------------------
// Snapshot cursor helpers (local -- milenage's are pub(crate))
// ---------------------------------------------------------------------------

struct SnapWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SnapWriter<'a> {
    const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn put_bytes(&mut self, src: &[u8]) {
        self.buf[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
    }
    const fn finish(self) -> usize {
        self.pos
    }
}

struct SnapReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SnapReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn get_bytes(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.buf[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
    }
}

// ---------------------------------------------------------------------------
// TopVariant
// ---------------------------------------------------------------------------

/// TOP variant for initialization (analogous to Milenage's OpVariant).
///
/// Either a pre-computed TOPc (256-bit) or a raw TOP value from which
/// TOPc will be derived using Keccak-f\[1600\].
///
/// # Standards
/// - 3GPP TS 35.231 clause 6.1 -- TOPc derivation
///
/// ```
/// use simrs_tuak::TopVariant;
///
/// // Pre-computed TOPc (recommended for production)
/// let _topc = TopVariant::TopC([0xAA; 32]);
///
/// // Raw TOP (TOPc computed at runtime from K and TOP)
/// let _top = TopVariant::Top([0xBB; 32]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopVariant {
    /// Pre-computed TOPc (256 bits). Preferred -- avoids runtime Keccak call.
    TopC([u8; 32]),
    /// Raw TOP. TOPc will be derived as per TS 35.231 clause 6.1.
    Top([u8; 32]),
}

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
/// use simrs_tuak::{TuakParams, TopVariant};
///
/// let params = TuakParams::new(
///     [0xFF; 16],                     // K
///     TopVariant::TopC([0xAA; 32]),   // TOPc
/// );
/// ```
#[derive(Debug, Clone)]
pub struct TuakParams {
    /// Subscriber key K (128 bits).
    key: [u8; 16],
    /// Derived operator constant TOPc (256 bits).
    top_c: [u8; 32],
}

impl Default for TuakParams {
    fn default() -> Self {
        Self::new([0u8; 16], TopVariant::TopC([0u8; 32]))
    }
}

impl TuakParams {
    /// Create with standard parameters.
    ///
    /// If `top` is [`TopVariant::Top`], TOPc is derived from K and TOP using
    /// Keccak-f\[1600\] per TS 35.231 clause 6.1.
    ///
    /// ```
    /// use simrs_tuak::{TuakParams, TopVariant};
    ///
    /// let p = TuakParams::new([0u8; 16], TopVariant::TopC([0u8; 32]));
    /// ```
    pub fn new(key: [u8; 16], top: TopVariant) -> Self {
        let top_c = match top {
            TopVariant::TopC(topc) => topc,
            TopVariant::Top(top_val) => compute_topc(&key, &top_val),
        };
        Self { key, top_c }
    }

    /// f1: Network authentication code MAC-A (8 bytes).
    ///
    /// Per 3GPP TS 35.231 clause 5.1. Uses INSTANCE 0x08 (MAC=64, K=128).
    ///
    /// ```
    /// use simrs_tuak::{TuakParams, TopVariant};
    ///
    /// let p = TuakParams::new([0u8; 16], TopVariant::TopC([0u8; 32]));
    /// let mac_a = p.f1(&[0u8; 16], &[0u8; 6], &[0u8; 2]);
    /// assert_eq!(mac_a.len(), 8);
    /// ```
    pub fn f1(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let buf = tuak_f1_core(
            &self.key,
            &self.top_c,
            rand,
            sqn,
            amf,
            INSTANCE_F1,
        );
        let mut mac_a = [0u8; 8];
        pull_data(&buf, OUT_OFF_MAC, &mut mac_a);
        mac_a
    }

    /// f1*: Resynch authentication code MAC-S (8 bytes).
    ///
    /// Per 3GPP TS 35.231 clause 5.2. Uses INSTANCE 0x88 (MAC=64, K=128).
    ///
    /// Used in AUTS construction for SQN resynchronization.
    pub fn f1_star(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let buf = tuak_f1_core(
            &self.key,
            &self.top_c,
            rand,
            sqn,
            amf,
            INSTANCE_F1_STAR,
        );
        let mut mac_s = [0u8; 8];
        pull_data(&buf, OUT_OFF_MAC, &mut mac_s);
        mac_s
    }

    /// f2: Authentication response RES (8 bytes).
    ///
    /// Per 3GPP TS 35.231 clause 5.3. Uses INSTANCE 0x48
    /// (RES=64, CK=128, IK=128, K=128).
    ///
    /// ```
    /// use simrs_tuak::{TuakParams, TopVariant};
    ///
    /// let p = TuakParams::new([0u8; 16], TopVariant::TopC([0u8; 32]));
    /// let res = p.f2(&[0u8; 16]);
    /// assert_eq!(res.len(), 8);
    /// ```
    pub fn f2(&self, rand: &[u8; 16]) -> [u8; 8] {
        let buf = tuak_f2345_core(&self.key, &self.top_c, rand);
        let mut res = [0u8; 8];
        pull_data(&buf, OUT_OFF_RES, &mut res);
        res
    }

    /// f3: Ciphering key CK (16 bytes).
    ///
    /// Per 3GPP TS 35.231 clause 5.4.
    pub fn f3(&self, rand: &[u8; 16]) -> [u8; 16] {
        let buf = tuak_f2345_core(&self.key, &self.top_c, rand);
        let mut ck = [0u8; 16];
        pull_data(&buf, OUT_OFF_CK, &mut ck);
        ck
    }

    /// f4: Integrity key IK (16 bytes).
    ///
    /// Per 3GPP TS 35.231 clause 5.5.
    pub fn f4(&self, rand: &[u8; 16]) -> [u8; 16] {
        let buf = tuak_f2345_core(&self.key, &self.top_c, rand);
        let mut ik = [0u8; 16];
        pull_data(&buf, OUT_OFF_IK, &mut ik);
        ik
    }

    /// f5: Anonymity key AK (6 bytes).
    ///
    /// Per 3GPP TS 35.231 clause 5.6. Shares computation with f2/f3/f4.
    ///
    /// Used to conceal SQN in AUTN: `AUTN = (SQN XOR AK) || AMF || MAC-A`.
    pub fn f5(&self, rand: &[u8; 16]) -> [u8; 6] {
        let buf = tuak_f2345_core(&self.key, &self.top_c, rand);
        let mut ak = [0u8; 6];
        pull_data(&buf, OUT_OFF_AK, &mut ak);
        ak
    }

    /// f5*: Resynch anonymity key AK* (6 bytes).
    ///
    /// Per 3GPP TS 35.231 clause 5.7. Uses INSTANCE 0xC0 (K=128).
    ///
    /// Used in AUTS construction: `AUTS = (SQN_MS XOR AK*) || MAC-S`.
    pub fn f5_star(&self, rand: &[u8; 16]) -> [u8; 6] {
        let buf = tuak_f5star_core(&self.key, &self.top_c, rand);
        let mut ak = [0u8; 6];
        pull_data(&buf, OUT_OFF_AK, &mut ak);
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
    ///
    /// # SQN Verification
    ///
    /// SQN verification is **not** performed here (handled by `simrs-usim`).
    ///
    /// ```
    /// use simrs_tuak::{TuakParams, TopVariant};
    /// use simrs_milenage::MilenageError;
    ///
    /// let p = TuakParams::new([0u8; 16], TopVariant::TopC([0u8; 32]));
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

        // 6. Compute RES, CK, IK from shared f2345 computation
        let buf = tuak_f2345_core(&self.key, &self.top_c, rand);
        let mut res = [0u8; 8];
        let mut ck = [0u8; 16];
        let mut ik = [0u8; 16];

        pull_data(&buf, OUT_OFF_RES, &mut res);
        pull_data(&buf, OUT_OFF_CK, &mut ck);
        pull_data(&buf, OUT_OFF_IK, &mut ik);

        // 7. C3 conversion: Kc[i] = CK[i] ^ CK[i+8] ^ IK[i] ^ IK[i+8]
        let mut kc = [0u8; 8];
        for i in 0..8 {
            kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
        }

        Ok(AuthOutput { res, ck, ik, kc })
    }

    // -- snapshot --

    /// Snapshot buffer size: 48 bytes (K(16) + TOPc(32)).
    pub const SNAPSHOT_SIZE: usize = 16 + 32;

    /// Serialize the TUAK parameters into `buf` as flat bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut w = SnapWriter::new(buf);
        w.put_bytes(&self.key);
        w.put_bytes(&self.top_c);
        w.finish()
    }

    /// Restore the TUAK parameters from `buf`.
    ///
    /// Returns `true` on success.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut r = SnapReader::new(buf);
        r.get_bytes(&mut self.key);
        r.get_bytes(&mut self.top_c);
        true
    }
}

// ---------------------------------------------------------------------------
// AuthAlgorithm trait implementation
// ---------------------------------------------------------------------------

impl AuthAlgorithm for TuakParams {
    #[allow(clippy::use_self)]
    const SNAPSHOT_SIZE: usize = TuakParams::SNAPSHOT_SIZE;

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

    fn authenticate(
        &self,
        rand: &[u8; 16],
        autn: &[u8; 16],
    ) -> Result<AuthOutput, MilenageError> {
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
// Internal: byte-reversal helpers for Keccak state construction
// ---------------------------------------------------------------------------

/// Copy `src` into `buf` at byte offset `offset` with reversed byte order.
///
/// Per TS 35.231 clause 4: all multi-byte fields are stored most-significant
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
fn init_state(
    buf: &mut [u8; 200],
    key: &[u8; 16],
    top_c: &[u8; 32],
    instance: u8,
) {
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

    // Padding markers per TS 35.231 clause 4.
    buf[OFF_PAD_1F] = 0x1F;
    buf[OFF_PAD_80] = 0x80;
}

/// TUAK core for f1 / f1*: includes RAND, SQN, AMF.
#[allow(clippy::trivially_copy_pass_by_ref)] // consistent API with public methods
fn tuak_f1_core(
    key: &[u8; 16],
    top_c: &[u8; 32],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    instance: u8,
) -> [u8; 200] {
    let mut buf = [0u8; 200];
    init_state(&mut buf, key, top_c, instance);

    // RAND (16 bytes, reversed)
    push_data(&mut buf, OFF_RAND, rand);

    // AMF (2 bytes, reversed)
    push_data(&mut buf, OFF_AMF, amf);

    // SQN (6 bytes, reversed)
    push_data(&mut buf, OFF_SQN, sqn);

    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);
    buf
}

/// TUAK core for f2/f3/f4/f5: includes RAND, zeroed AMF/SQN.
fn tuak_f2345_core(
    key: &[u8; 16],
    top_c: &[u8; 32],
    rand: &[u8; 16],
) -> [u8; 200] {
    let mut buf = [0u8; 200];
    init_state(&mut buf, key, top_c, INSTANCE_F2345);

    // RAND (16 bytes, reversed)
    push_data(&mut buf, OFF_RAND, rand);

    // AMF and SQN are zero (already zeroed by init_state).

    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);
    buf
}

/// TUAK core for f5*: includes RAND, zeroed AMF/SQN.
fn tuak_f5star_core(
    key: &[u8; 16],
    top_c: &[u8; 32],
    rand: &[u8; 16],
) -> [u8; 200] {
    let mut buf = [0u8; 200];
    init_state(&mut buf, key, top_c, INSTANCE_F5_STAR);

    // RAND (16 bytes, reversed)
    push_data(&mut buf, OFF_RAND, rand);

    // AMF and SQN are zero (already zeroed by init_state).

    // Apply Keccak-f\[1600\]
    keccak_f1600_bytes(&mut buf);
    buf
}

/// Compute TOPc from TOP and K per TS 35.231 clause 6.1.
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
    // 3GPP TS 35.233 Test Set 1 (Section 6.3)
    //
    // K = 128-bit, MAC=64, RES=32, CK=128, IK=128
    // KeccakIterations = 1
    //
    // Note: RES=32 means INSTANCE for f2345 = 0x40 (not our standard 0x48).
    // We test TOPc derivation and f1/f1* using the exact spec values.
    // ---------------------------------------------------------------

    const TS1_K: [u8; 16] = [
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
    ];
    const TS1_TOP: [u8; 32] = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    ];
    const TS1_RAND: [u8; 16] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    ];
    const TS1_SQN: [u8; 6] = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
    const TS1_AMF: [u8; 2] = [0xFF, 0xFF];

    const TS1_TOPC: [u8; 32] = [
        0xBD, 0x04, 0xD9, 0x53, 0x0E, 0x87, 0x51, 0x3C,
        0x5D, 0x83, 0x7A, 0xC2, 0xAD, 0x95, 0x46, 0x23,
        0xA8, 0xE2, 0x33, 0x0C, 0x11, 0x53, 0x05, 0xA7,
        0x3E, 0xB4, 0x5D, 0x1F, 0x40, 0xCC, 0xCB, 0xFF,
    ];

    // f1 MAC-A (8 bytes, MAC=64)
    const TS1_F1: [u8; 8] = [0xF9, 0xA5, 0x4E, 0x6A, 0xEA, 0xA8, 0x61, 0x8D];
    // f1* MAC-S (8 bytes, MAC=64)
    const TS1_F1_STAR: [u8; 8] = [0xE9, 0x4B, 0x4D, 0xC6, 0xC7, 0x29, 0x7D, 0xF3];
    // f2 RES (4 bytes, RES=32) -- uses INSTANCE 0x40
    const TS1_F2_RES_32: [u8; 4] = [0x65, 0x7A, 0xCD, 0x64];
    // f3 CK (16 bytes)
    const TS1_F3: [u8; 16] = [
        0xD7, 0x1A, 0x1E, 0x5C, 0x6C, 0xAF, 0xFE, 0x98,
        0x6A, 0x26, 0xF7, 0x83, 0xE5, 0xC7, 0x8B, 0xE1,
    ];
    // f4 IK (16 bytes)
    const TS1_F4: [u8; 16] = [
        0xBE, 0x84, 0x9F, 0xA2, 0x56, 0x4F, 0x86, 0x9A,
        0xEC, 0xEE, 0x6F, 0x62, 0xD4, 0x33, 0x7E, 0x72,
    ];
    // f5 AK (6 bytes)
    const TS1_F5: [u8; 6] = [0x71, 0x9F, 0x1E, 0x9B, 0x90, 0x54];
    // f5* AK* (6 bytes)
    const TS1_F5_STAR_AK: [u8; 6] = [0xE7, 0xAF, 0x6B, 0x3D, 0x0E, 0x38];

    #[test]
    fn topc_derivation_test_set_1() {
        let computed = compute_topc(&TS1_K, &TS1_TOP);
        assert_eq!(computed, TS1_TOPC, "TOPc derivation must match TS 35.233 Test Set 1");
    }

    #[test]
    fn f1_test_set_1() {
        // Test set 1 uses MAC=64, K=128, so INSTANCE_F1=0x08 matches our standard.
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        assert_eq!(p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF), TS1_F1);
    }

    #[test]
    fn f1_star_test_set_1() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        assert_eq!(p.f1_star(&TS1_RAND, &TS1_SQN, &TS1_AMF), TS1_F1_STAR);
    }

    #[test]
    fn f2345_test_set_1_with_res32_instance() {
        // Test set 1 uses RES=32, so INSTANCE=0x40 (not our default 0x48).
        // We test with the exact INSTANCE to verify core Keccak construction.
        let topc = compute_topc_any(&TS1_K, &TS1_TOP);
        assert_eq!(topc, TS1_TOPC);

        // Use the configurable core with INSTANCE=0x40
        let buf = tuak_core_with_instance(
            &TS1_K,
            &topc,
            &TS1_RAND,
            &[0u8; 6], // SQN=0 for f2345
            &[0u8; 2], // AMF=0 for f2345
            0x40,       // INSTANCE for RES=32, CK=128, IK=128, K=128
        );

        // Extract RES (4 bytes for RES=32)
        let mut res = [0u8; 4];
        pull_data(&buf, OUT_OFF_RES, &mut res);
        assert_eq!(res, TS1_F2_RES_32, "f2 RES (32-bit) must match TS 35.233 Test Set 1");

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
            &TS1_K,
            &topc,
            &TS1_RAND,
            &[0u8; 6],
            &[0u8; 2],
            0xC0, // INSTANCE for f5*, K=128
        );

        let mut ak_star = [0u8; 6];
        pull_data(&buf, OUT_OFF_AK, &mut ak_star);
        assert_eq!(ak_star, TS1_F5_STAR_AK, "f5* AK* must match TS 35.233 Test Set 1");
    }

    // ---------------------------------------------------------------
    // 3GPP TS 35.233 Test Set 4 (Section 6.6)
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
        let top: [u8; 32] = hex_to_bytes(
            "0952be13556c32ebc58195d9dd930493e12a9003669988ffde5fa1f0fe35cc01",
        );
        let expected_topc: [u8; 32] = hex_to_bytes(
            "2bc16eb657a68e1f446f08f57c0efb1d493527a2e652ce281eb6ca0e4487760a",
        );
        let computed = compute_topc_any(&k, &top);
        assert_eq!(computed, expected_topc, "TOPc must match TS 35.233 Test Set 4");
    }

    // ---------------------------------------------------------------
    // 3GPP TS 35.233 Test Set 2 (Section 6.4)
    //
    // K = 256-bit, MAC=128, RES=64, CK=128, IK=128
    // KeccakIterations = 1
    //
    // Validates 256-bit key handling.
    // ---------------------------------------------------------------

    #[test]
    fn topc_derivation_test_set_2() {
        let k: [u8; 32] = hex_to_bytes(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
        );
        let top: [u8; 32] = hex_to_bytes(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        let expected_topc: [u8; 32] = hex_to_bytes(
            "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524",
        );
        let computed = compute_topc_any(&k, &top);
        assert_eq!(computed, expected_topc, "TOPc must match TS 35.233 Test Set 2");
    }

    // ---------------------------------------------------------------
    // TOP / TOPc equivalence
    // ---------------------------------------------------------------

    #[test]
    fn top_and_topc_produce_same_f2() {
        let topc = compute_topc(&TS1_K, &TS1_TOP);
        let p_top = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        let p_topc = TuakParams::new(TS1_K, TopVariant::TopC(topc));
        assert_eq!(p_top.f2(&TS1_RAND), p_topc.f2(&TS1_RAND));
    }

    // ---------------------------------------------------------------
    // Structural tests for standard output sizes
    // ---------------------------------------------------------------

    #[test]
    fn f1_and_f1_star_differ() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        let mac_a = p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF);
        let mac_s = p.f1_star(&TS1_RAND, &TS1_SQN, &TS1_AMF);
        assert_ne!(mac_a, mac_s, "f1 and f1* must produce different outputs");
    }

    #[test]
    fn f5_and_f5_star_differ() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        let ak = p.f5(&TS1_RAND);
        let ak_star = p.f5_star(&TS1_RAND);
        assert_ne!(ak, ak_star, "f5 and f5* must produce different outputs");
    }

    #[test]
    fn different_rand_different_outputs() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        let rand2 = [0x99u8; 16];
        assert_ne!(p.f2(&TS1_RAND), p.f2(&rand2));
        assert_ne!(p.f3(&TS1_RAND), p.f3(&rand2));
        assert_ne!(p.f4(&TS1_RAND), p.f4(&rand2));
    }

    #[test]
    fn deterministic() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        assert_eq!(p.f2(&TS1_RAND), p.f2(&TS1_RAND));
        assert_eq!(p.f3(&TS1_RAND), p.f3(&TS1_RAND));
        assert_eq!(p.f5(&TS1_RAND), p.f5(&TS1_RAND));
    }

    #[test]
    fn all_functions_produce_nonzero_output() {
        // Use non-trivial key/TOP to avoid accidental zero outputs.
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        assert_ne!(p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF), [0u8; 8]);
        assert_ne!(p.f1_star(&TS1_RAND, &TS1_SQN, &TS1_AMF), [0u8; 8]);
        assert_ne!(p.f2(&TS1_RAND), [0u8; 8]);
        assert_ne!(p.f3(&TS1_RAND), [0u8; 16]);
        assert_ne!(p.f4(&TS1_RAND), [0u8; 16]);
        assert_ne!(p.f5(&TS1_RAND), [0u8; 6]);
        assert_ne!(p.f5_star(&TS1_RAND), [0u8; 6]);
    }

    // ---------------------------------------------------------------
    // Full authentication
    // ---------------------------------------------------------------

    #[test]
    fn authenticate_with_valid_autn() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        let rand = TS1_RAND;
        let sqn = TS1_SQN;
        let amf = TS1_AMF;

        // Construct valid AUTN: (SQN XOR AK) || AMF || MAC-A
        let ak = p.f5(&rand);
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = sqn[i] ^ ak[i];
        }
        autn[6] = amf[0];
        autn[7] = amf[1];
        let mac_a = p.f1(&rand, &sqn, &amf);
        autn[8..16].copy_from_slice(&mac_a);

        let result = p.authenticate(&rand, &autn);
        assert!(result.is_ok(), "valid AUTN must authenticate successfully");
        let out = result.unwrap();
        assert_eq!(out.res, p.f2(&rand));
        assert_eq!(out.ck, p.f3(&rand));
        assert_eq!(out.ik, p.f4(&rand));
    }

    #[test]
    fn authenticate_with_bad_mac_fails() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));
        // All-0xFF AUTN will have wrong MAC-A
        let result = p.authenticate(&TS1_RAND, &[0xFFu8; 16]);
        assert!(matches!(result, Err(MilenageError::MacFailure)));
    }

    #[test]
    fn authenticate_kc_is_c3_conversion() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));

        // Build valid AUTN
        let ak = p.f5(&TS1_RAND);
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = TS1_SQN[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&TS1_AMF);
        autn[8..16].copy_from_slice(&p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF));

        let out = p.authenticate(&TS1_RAND, &autn).unwrap();

        // Verify C3 conversion: Kc[i] = CK[i] ^ CK[i+8] ^ IK[i] ^ IK[i+8]
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
    // Snapshot tests
    // ---------------------------------------------------------------

    #[test]
    fn snapshot_size_correct() {
        assert_eq!(TuakParams::SNAPSHOT_SIZE, 48);
    }

    #[test]
    fn snapshot_roundtrip_preserves_computation() {
        let orig = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));

        let mut snap = [0u8; TuakParams::SNAPSHOT_SIZE];
        assert_eq!(orig.save_state(&mut snap), 48);

        // Restore into a zeroed params.
        let mut restored = TuakParams::new([0u8; 16], TopVariant::TopC([0u8; 32]));
        assert!(restored.restore_state(&snap));

        // Restored params must produce the same outputs.
        assert_eq!(restored.f2(&TS1_RAND), orig.f2(&TS1_RAND));
        assert_eq!(restored.f5(&TS1_RAND), orig.f5(&TS1_RAND));
        assert_eq!(
            restored.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF),
            orig.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF)
        );
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let p = TuakParams::new([0u8; 16], TopVariant::TopC([0u8; 32]));
        let mut small = [0u8; 20];
        assert_eq!(p.save_state(&mut small), 0);

        let mut p2 = TuakParams::new([0u8; 16], TopVariant::TopC([0u8; 32]));
        assert!(!p2.restore_state(&small));
    }

    // ---------------------------------------------------------------
    // AuthAlgorithm trait tests
    // ---------------------------------------------------------------

    #[test]
    fn trait_methods_match_inherent() {
        let p = TuakParams::new(TS1_K, TopVariant::Top(TS1_TOP));

        // Verify trait methods delegate to inherent methods.
        let trait_f1 = AuthAlgorithm::f1(&p, &TS1_RAND, &TS1_SQN, &TS1_AMF);
        let inherent_f1 = p.f1(&TS1_RAND, &TS1_SQN, &TS1_AMF);
        assert_eq!(trait_f1, inherent_f1);

        let trait_f2 = AuthAlgorithm::f2(&p, &TS1_RAND);
        let inherent_f2 = p.f2(&TS1_RAND);
        assert_eq!(trait_f2, inherent_f2);
    }
}
