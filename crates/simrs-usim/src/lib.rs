//! 3GPP USIM application layer.
//!
//! Handles interindustry (CLA=`0x00`) and ETSI-class (CLA=`0x80`) APDUs:
//! SELECT (with FCP BER-TLV response), GET RESPONSE, READ BINARY,
//! READ RECORD, UPDATE BINARY, UPDATE RECORD, INCREASE, STATUS,
//! AUTHENTICATE (Milenage), GET IDENTITY (SUCI), VERIFY PIN,
//! CHANGE REFERENCE DATA, DISABLE PIN, ENABLE PIN, UNBLOCK PIN,
//! TERMINAL PROFILE, FETCH, TERMINAL RESPONSE, and ENVELOPE.
//!
//! Constructs FCP BER-TLV per [ETSI TS 102 221 V18.3.0 clause 11.1.1.3](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A335%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C783%5D) using a
//! dry-run/real-run pattern for buffer-size determination.
//!
//! Post-APDU hook: if a proactive command is pending and SW would be
//! `90 00`, the status is overridden to `91 XX` where XX is the pending
//! command length.
//!
//! # Standards
//! - [ETSI TS 102 221 V18.3.0](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf) -- UICC-terminal interface
//! - [3GPP TS 31.101 V17.0.0](../../../docs/specs/3gpp/ts-31.101/ts_131101v170000p.pdf) -- UICC-terminal interface (3GPP additions)
//! - [3GPP TS 31.102 V19.4.0](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf) -- USIM application characteristics
//! - [ETSI TS 102 223 V18.2.0](../../../docs/specs/etsi/ts-102-223/ts_102223v180200p.pdf) -- Card Application Toolkit (proactive)
//!
//! # `no_std`
//! This crate is `no_std`. All buffers are stack-allocated.
//!
//! # Example
//!
//! ```
//! use simrs_usim::UsimApp;
//! use simrs_iso7816::Command;
//! use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef};
//! use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
//! use simrs_secret::Secret;
//!
//! static EF: EfDef = EfDef::transparent(
//!     Fid::new(0x2FE2),
//!     None,
//!     &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
//! );
//! static MF: DfDef = DfDef { fid: Fid::new(0x3F00), children: &[FileRef::Ef(&EF)] };
//!
//! let milenage = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
//! let mut app = UsimApp::new(&MF, &[], milenage);
//!
//! // SELECT MF (interindustry CLA)
//! let cmd = Command::parse(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]).unwrap();
//! let mut buf = [0u8; 256];
//! let rsp = app.handle(&cmd, &mut buf);
//! assert_eq!(rsp[0], 0x61); // SW1: data available via GET RESPONSE
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// USIM documentation uses many standard 3GPP terms (OPc, FCP, ADF, etc.)
#![allow(clippy::doc_markdown)]

pub mod profile;

use simrs_bertlv::Encoder;
use simrs_fs::{
    AdfSlot, DeactivationTracker, DfDef, EfDef, Fid, FsData, FsError,
    SelectionCtx, SelectedFile, Sfi,
};
use simrs_iso7816::{fcp, ins, sw2, write_data_sw, write_sw, Command, ResponseQueue, StatusWord};
use simrs_kdf::HmacSha256;
use simrs_milenage::{AuthenticationAlgorithm, AuthenticationError, CipherKey, IntegrityKey, MilenageParams};
use simrs_pin::{PinKey, PinManager};
#[cfg(test)]
use simrs_pin::PinValue;
use simrs_proactive::ProactiveState;
use simrs_redact::Redact;
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Filesystem data buffer capacity, selected by feature flag.
///
/// - `profile-full`: 16384 bytes (full [3GPP TS 31.102 V19.4.0](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf) catalog + ISIM/HPSIM/TELECOM)
/// - `profile-standard` (default): 4096 bytes (58 EFs: baseline USIM + DF_5GS)
/// - `profile-minimal`: 1024 bytes (33 EFs: LTE attach minimum + DF_5GS)
///
/// Note: DF_5GS (19 EFs) is included in all tiers.
#[cfg(feature = "profile-full")]
const FS_CAP: usize = 16384;
#[cfg(all(not(feature = "profile-full"), any(feature = "profile-standard", not(feature = "profile-minimal"))))]
const FS_CAP: usize = 4096;
#[cfg(all(feature = "profile-minimal", not(feature = "profile-standard"), not(feature = "profile-full")))]
const FS_CAP: usize = 1024;

/// Maximum number of EFs in the filesystem, selected by feature flag.
///
/// - `profile-full`: 290 (full [3GPP TS 31.102 V19.4.0](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf) + ISIM/HPSIM/TELECOM + legacy DFs)
/// - `profile-standard` (default): 80 (58 EFs + headroom for telecom/additive)
/// - `profile-minimal`: 40 (33 EFs + headroom)
///
/// Note: DF_5GS (19 EFs) is included in all tiers.
#[cfg(feature = "profile-full")]
const FS_MAX_EFS: usize = 290;
#[cfg(all(not(feature = "profile-full"), any(feature = "profile-standard", not(feature = "profile-minimal"))))]
const FS_MAX_EFS: usize = 80;
#[cfg(all(feature = "profile-minimal", not(feature = "profile-standard"), not(feature = "profile-full")))]
const FS_MAX_EFS: usize = 40;

/// CLA byte for ETSI CAT (proactive) commands.
const CLA_ETSI: u8 = 0x80;

/// Maximum FCP size (conservative upper bound for our file tree).
const FCP_BUF_CAP: usize = 64;

// ETSI TS 102 221 V18.3.0 clause 11.1.1.4.3: File descriptor byte values.
const FD_DF: u8 = 0x78;
const DATA_CODING_BER_TLV: u8 = 0x21;

// ETSI TS 102 221 V18.3.0 clause 11.1.1.4.9: Life cycle status.
const LIFECYCLE_ACTIVATED: u8 = 0x05;

// ETSI TS 102 221 V18.3.0 clause 11.1.1.4.8: SFI encoding.
const SFI_INDICATOR: u8 = 0x04;

// PIN status template DO values.
const PS_DO_TAG: u8 = 0x90;

// 3GPP TS 31.102 V19.4.0 clause 7.1.2: AUTHENTICATE protocol constants.
#[allow(dead_code)] // Used by upcoming GSM context AUTHENTICATE support.
const P2_GSM_CONTEXT: u8 = 0x00;
const P2_UMTS_CONTEXT: u8 = 0x81;
const AUTH_DATA_LEN: usize = 34;
#[allow(dead_code)] // Used by upcoming GSM context AUTHENTICATE support.
const GSM_AUTH_DATA_LEN: usize = 17; // 0x10 || RAND(16)
const AUTH_VECTOR_LEN_PREFIX: u8 = 0x10;
const AUTH_SUCCESS_TAG: u8 = 0xDB;
const AUTH_SYNC_FAILURE_TAG: u8 = 0xDC;
const RESYNC_TOKEN_LEN: u8 = 0x0E;
const AUTH_RESPONSE_LEN: u8 = 0x08;
const AUTH_KEY_LEN: u8 = 0x10;
const AUTH_SUCCESS_INNER_LEN: u8 = 1 + AUTH_RESPONSE_LEN + 1 + AUTH_KEY_LEN + 1 + AUTH_KEY_LEN;

// GSM context response constants (3GPP TS 31.102 V19.4.0 clause 7.1.2).
#[allow(dead_code)] // Used by upcoming GSM context AUTHENTICATE support.
const GSM_SRES_LEN: u8 = 0x04;
#[allow(dead_code)] // Used by upcoming GSM context AUTHENTICATE support.
const GSM_KC_LEN: u8 = 0x08;
// Total GSM response: 0x04 || SRES(4) || 0x08 || Kc(8) = 14 bytes.
#[allow(dead_code)] // Used by upcoming GSM context AUTHENTICATE support.
const GSM_AUTH_RSP_LEN: usize = 1 + 4 + 1 + 8;

// 3GPP TS 31.102 V19.4.0 clause 7.5: GET IDENTITY protocol constants.
const P2_SUCI_CONTEXT: u8 = 0x01;

// SUCI response TLV tag (TS 31.102 V19.4.0 clause 7.5.2.1).
const SUCI_TLV_TAG: u8 = 0xA1;
// SUPI type: IMSI (TS 24.501 Table 9.11.3.4.1).
const SUPI_TYPE_IMSI: u8 = 0x01;

// Protection scheme identifiers (TS 33.501 Annex C).
const SCHEME_NULL: u8 = 0x00;
const SCHEME_PROFILE_A: u8 = 0x01;
const SCHEME_PROFILE_B: u8 = 0x02;

// EF_SUCI_CALC_INFO TLV tags (TS 31.102 V19.4.0 clause 4.4.11.8).
const SUCI_CALC_INFO_SCHEME_LIST_TAG: u8 = 0xA0;
#[allow(dead_code)] // Used in GET IDENTITY handler.
const SUCI_CALC_INFO_HN_KEY_LIST_TAG: u8 = 0xA1;
#[allow(dead_code)] // Skipped during TLV iteration (parse_hn_public_key looks for KEY_TAG).
const SUCI_CALC_INFO_KEY_ID_TAG: u8 = 0x80;
const SUCI_CALC_INFO_KEY_TAG: u8 = 0x81;

// ---------------------------------------------------------------------------
// SuciSeed / SuciState
// ---------------------------------------------------------------------------

/// DRBG seed for SUCI ephemeral key generation.
///
/// Must be unique per card (e.g., derived from the subscriber key K or a
/// separately provisioned secret). Used as an HMAC-SHA-256 key to derive
/// fresh ephemeral private keys for each GET IDENTITY SUCI computation.
///
/// Per [3GPP TS 31.102 V19.4.0 clause 7.5.1.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf):
/// "The freshness and randomness of SUCI returned upon each call of the
/// command depends on the protection scheme configured."
#[derive(Clone, Copy)]
pub struct SuciSeed(Secret<[u8; 32]>);

impl SuciSeed {
    /// Create a new SUCI DRBG seed from raw bytes.
    pub const fn new(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }

    /// Access the underlying bytes for cryptographic operations.
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for SuciSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SuciSeed")
            .field(&Redact(self.0.declassify_ref()))
            .finish()
    }
}

/// SUCI on-card computation state.
///
/// Tracks the DRBG seed and a monotonic counter for ephemeral key derivation.
/// Provision on a [`UsimApp`] via [`suci_mut`](UsimApp::suci_mut):
///
/// ```ignore
/// *app.suci_mut() = Some(SuciState::new(seed));
/// ```
pub struct SuciState {
    seed: SuciSeed,
    counter: u64,
}

impl SuciState {
    /// Create a new SUCI computation state with the given DRBG seed.
    ///
    /// The counter starts at zero and advances with each GET IDENTITY call.
    pub const fn new(seed: SuciSeed) -> Self {
        Self { seed, counter: 0 }
    }

    /// Derive the next ephemeral key via HMAC-SHA-256(seed, counter_be).
    fn next_ephemeral_key(&mut self) -> [u8; 32] {
        let ctr_bytes = self.counter.to_be_bytes();
        let mut hmac = HmacSha256::new(&simrs_secret::Secret::new(*self.seed.declassify()));
        hmac.update(&ctr_bytes);
        let key = hmac.finalize();
        self.counter += 1;
        key
    }
}

// ---------------------------------------------------------------------------
// AuthenticationResult
// ---------------------------------------------------------------------------

/// AUTHENTICATE command result.
///
/// Per [3GPP TS 31.102 V19.4.0 clause 7.1.2.1](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A754%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C330%5D).
/// Encodes the three possible outcomes of UMTS AUTHENTICATE:
/// - Success: RES, CK, IK returned in tag 0xDB
/// - Sync failure: AUTS returned in tag 0xDC for resynchronization
/// - MAC failure: SW 98 62
#[derive(Debug, Clone, Copy)]
pub enum AuthenticationResult {
    /// Successful authentication. Contains RES (8 bytes), CK (16 bytes),
    /// IK (16 bytes). Encoded as tag 0xDB with nested TLV.
    Success {
        /// Authentication response (f2 output).
        response: [u8; 8],
        /// Ciphering key (f3 output).
        cipher_key: CipherKey,
        /// Integrity key (f4 output).
        integrity_key: IntegrityKey,
    },
    /// SQN synchronization failure. Contains AUTS (14 bytes).
    /// Encoded as tag 0xDC.
    SyncFailure {
        /// AUTS resynchronization token (14 bytes).
        resync_token: [u8; 14],
    },
    /// MAC verification failure. Returns SW 98 62.
    MacFailure,
}

/// Deprecated: use [`AuthenticationResult`].
#[deprecated(note = "use `AuthenticationResult`")]
pub type AuthenticateResult = AuthenticationResult;

impl AuthenticationResult {
    /// Encode the result into a byte buffer for APDU response.
    ///
    /// For `Success`: writes tag 0xDB, inner length, then length-prefixed
    /// RES, CK, IK. Total: 2 + (1+8) + (1+16) + (1+16) = 45 bytes.
    ///
    /// For `SyncFailure`: writes tag 0xDC, length 0x0E, then 14 AUTS bytes.
    /// Total: 16 bytes.
    ///
    /// For `MacFailure`: writes nothing (SW only). Returns 0.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match self {
            Self::Success { response, cipher_key, integrity_key } => {
                // 0xDB <inner_len> <res_len> [RES] <ck_len> [CK] <ik_len> [IK]
                let inner_len: u8 = AUTH_SUCCESS_INNER_LEN;
                let mut pos: usize = 0;
                buf[pos] = AUTH_SUCCESS_TAG;
                pos += 1;
                buf[pos] = inner_len;
                pos += 1;
                // RES
                buf[pos] = AUTH_RESPONSE_LEN;
                pos += 1;
                buf[pos..pos + 8].copy_from_slice(response);
                pos += 8;
                // CK
                buf[pos] = AUTH_KEY_LEN;
                pos += 1;
                buf[pos..pos + 16].copy_from_slice(cipher_key.declassify());
                pos += 16;
                // IK
                buf[pos] = AUTH_KEY_LEN;
                pos += 1;
                buf[pos..pos + 16].copy_from_slice(integrity_key.declassify());
                pos += 16;
                pos
            }
            Self::SyncFailure { resync_token } => {
                buf[0] = AUTH_SYNC_FAILURE_TAG;
                buf[1] = RESYNC_TOKEN_LEN;
                buf[2..16].copy_from_slice(resync_token);
                16
            }
            Self::MacFailure => 0,
        }
    }
}


// ---------------------------------------------------------------------------
// SUCI helpers (GET IDENTITY, TS 31.102 V19.4.0 clause 7.5)
// ---------------------------------------------------------------------------

/// Maximum packed MSIN length in bytes (10 BCD digits = 5 bytes).
///
/// A 15-digit IMSI with 2-digit MNC has 10 MSIN digits. With 3-digit
/// MNC the MSIN is 9 digits. Both pack into at most 5 bytes.
const MSIN_FIXED_LEN: usize = 5;

/// Extract MSIN from BCD-encoded EF.IMSI data as a fixed-size packed BCD buffer.
///
/// IMSI layout ([3GPP TS 31.102 V19.4.0 clause 4.2.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf)):
/// byte 0 = IMSI length (typically 0x08), bytes 1..9 = nibble-swapped BCD digits.
///
/// Returns a fixed [`MSIN_FIXED_LEN`]-byte buffer with packed BCD MSIN
/// (high nibble first, padded with 0xF). The fixed size prevents MSIN
/// length from leaking through response TLV sizes.
///
/// # Constant-Time
///
/// All 15 IMSI digit positions are always decoded. Digit count is derived
/// structurally from the IMSI length byte and parity indicator, not by
/// scanning digit values. No data-dependent branches on secret MSIN content.
fn extract_msin(imsi_data: &[u8], mnc_len: u8) -> [u8; MSIN_FIXED_LEN] {
    // Always decode all 15 possible IMSI digit positions.
    // Positions beyond the actual digit count keep their 0xF filler.
    let mut digits = [0x0Fu8; 15];

    // Byte 1 high nibble = first IMSI digit.
    digits[0] = (imsi_data[1] >> 4) & 0x0F;

    // Bytes 2..=8: low nibble = even-position digit, high nibble = odd-position digit.
    let mut i = 2usize;
    while i <= 8 {
        let pos = 2 * (i - 2) + 1;
        digits[pos] = imsi_data[i] & 0x0F;
        digits[pos + 1] = (imsi_data[i] >> 4) & 0x0F;
        i += 1;
    }

    // MSIN starts after MCC (3 digits) + MNC (mnc_len digits).
    // Always pack exactly MSIN_FIXED_LEN bytes (10 digit positions).
    let skip = 3 + mnc_len as usize;
    let mut msin = [0xFFu8; MSIN_FIXED_LEN];
    let mut b = 0usize;
    while b < MSIN_FIXED_LEN {
        let hi_pos = skip + 2 * b;
        let lo_pos = skip + 2 * b + 1;
        let hi = if hi_pos < 15 { digits[hi_pos] } else { 0x0F };
        let lo = if lo_pos < 15 { digits[lo_pos] } else { 0x0F };
        msin[b] = (hi << 4) | lo;
        b += 1;
    }

    msin
}

/// Extract MCC+MNC from IMSI as 3 BCD-encoded bytes for the SUCI TLV.
///
/// Returns 3 bytes: MCC digit1+digit2, MCC digit3 + MNC digit1, MNC digit2 (+ digit3 or 0xF).
///
/// # Constant-Time
///
/// All digit positions are decoded unconditionally. No data-dependent
/// branches on IMSI digit values.
fn extract_mcc_mnc(imsi_data: &[u8], mnc_len: u8) -> [u8; 3] {
    // Decode the first 6 IMSI digit positions (MCC + MNC at most 6 digits).
    let mut digits = [0x0Fu8; 6];

    digits[0] = (imsi_data[1] >> 4) & 0x0F;
    // Bytes 2 and 3 provide digits 1-4 (enough for MCC3 + MNC of up to 3).
    digits[1] = imsi_data[2] & 0x0F;
    digits[2] = (imsi_data[2] >> 4) & 0x0F;
    digits[3] = imsi_data[3] & 0x0F;
    digits[4] = (imsi_data[3] >> 4) & 0x0F;
    // Digit 5 (MNC digit 3) from byte 4, only used when mnc_len >= 3.
    digits[5] = imsi_data[4] & 0x0F;

    // Pack: byte0 = MCC1|MCC2, byte1 = MCC3|MNC1, byte2 = MNC2|MNC3_or_F
    let mnc3 = if mnc_len >= 3 { digits[5] } else { 0x0F };
    [
        (digits[0] << 4) | digits[1],
        (digits[2] << 4) | digits[3],
        (digits[4] << 4) | mnc3,
    ]
}

/// Parse the Home Network Public Key from EF_SUCI_CALC_INFO TLV data.
///
/// Starts searching at `offset` for tag 0xA1 (HN Public Key List), then
/// extracts the first key (tag 0x81) from within the list.
///
/// Returns a slice of the key bytes, or `None` if not found.
fn parse_hn_public_key(data: &[u8], offset: usize) -> Option<&[u8]> {
    if offset >= data.len() {
        return None;
    }
    // Expect tag 0xA1 (HN Public Key List).
    if data[offset] != SUCI_CALC_INFO_HN_KEY_LIST_TAG {
        return None;
    }
    if offset + 1 >= data.len() {
        return None;
    }
    let list_len = data[offset + 1] as usize;
    let list_start = offset + 2;
    if list_start + list_len > data.len() {
        return None;
    }

    // Walk the list looking for tag 0x81 (Key).
    let mut pos = list_start;
    while pos + 1 < list_start + list_len {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        if pos + 2 + len > list_start + list_len {
            return None;
        }
        if tag == SUCI_CALC_INFO_KEY_TAG {
            return Some(&data[pos + 2..pos + 2 + len]);
        }
        // Skip this TLV (could be tag 0x80 = Key Identifier).
        pos += 2 + len;
    }
    None
}

// ---------------------------------------------------------------------------
// UsimApp
// ---------------------------------------------------------------------------

/// 3GPP USIM application.
///
/// Handles interindustry (CLA=`0x00`) and ETSI-class (CLA=`0x80`) APDUs.
/// Owns filesystem context, PIN manager, authentication algorithm, proactive
/// state, and the response queue for GET RESPONSE.
///
/// The type parameter `A` selects the authentication algorithm.
/// The default is [`MilenageParams`] ([ETSI TS 135 206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf)).
pub struct UsimApp<A: AuthenticationAlgorithm = MilenageParams> {
    fs: SelectionCtx,
    data: FsData<FS_CAP, FS_MAX_EFS>,
    mf: &'static DfDef,
    adfs: &'static [AdfSlot],
    pin: PinManager<5>,
    auth: A,
    proactive: ProactiveState,
    rsp_queue: ResponseQueue<64>,
    /// Terminal capability data (up to 16 bytes).
    terminal_capability: [u8; 16],
    /// Length of stored terminal capability data.
    terminal_capability_len: u8,
    /// Deactivated file tracking (persistent -- survives reset, see
    /// [`DeactivationTracker`] docs).
    deactivation: DeactivationTracker,
    /// Logical channel contexts. Channel 0 is the basic channel (always open);
    /// its selection state lives in `self.fs`, so `channels[0]` is always `None`.
    /// Channels 1-3 are optional logical channels.
    channels: [Option<SelectionCtx>; 4],
    /// Tracks the last AID selected via SELECT by AID, for "next occurrence" iteration.
    last_aid_match: bool,
    /// Whether a proactive session is currently active.
    ///
    /// Set to `true` when a proactive command is queued or when FETCH
    /// delivers a command. Set to `false` when TERMINAL RESPONSE is
    /// received with a success result. Not persisted in snapshots
    /// (transient session state).
    proactive_session_active: bool,
    /// SUCI on-card computation state (GET IDENTITY, INS=0x78).
    ///
    /// `None` when SUCI computation is not provisioned. When present,
    /// GET IDENTITY with P2=0x01 uses this state to derive fresh ephemeral
    /// keys for ECIES encryption.
    suci: Option<SuciState>,
}

impl<A: AuthenticationAlgorithm> UsimApp<A> {
    /// Create a new USIM application.
    ///
    /// GET IDENTITY (INS=0x78) will return `6985` (conditions not satisfied)
    /// until SUCI is enabled via [`suci_mut`](Self::suci_mut).
    ///
    /// # Panics
    ///
    /// Panics if the static filesystem tree (MF + ADFs) does not fit in the
    /// internal `FsData` buffer (size depends on the selected profile tier).
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_usim::UsimApp;
    /// use simrs_fs::{DfDef, Fid, AdfSlot};
    /// use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
    /// use simrs_secret::Secret;
    ///
    /// static MF: DfDef = DfDef { fid: Fid::new(0x3F00), children: &[] };
    /// let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
    /// let app = UsimApp::new(&MF, &[], mil);
    /// ```
    pub fn new(
        mf: &'static DfDef,
        adfs: &'static [AdfSlot],
        auth: A,
    ) -> Self {
        Self::build(mf, adfs, auth)
    }

    fn build(
        mf: &'static DfDef,
        adfs: &'static [AdfSlot],
        auth: A,
    ) -> Self {
        let mut data = FsData::<FS_CAP, FS_MAX_EFS>::new();
        // Panic on init failure: the static filesystem tree must fit in CAP.
        if let Err(e) = data.init_with_adfs(mf, adfs) {
            panic!("FsData init failed: {}", e);
        }

        Self {
            fs: SelectionCtx::new(mf),
            data,
            mf,
            adfs,
            pin: PinManager::new(),
            auth,
            proactive: ProactiveState::new(),
            rsp_queue: ResponseQueue::new(),
            terminal_capability: [0u8; 16],
            terminal_capability_len: 0,
            deactivation: DeactivationTracker::new(),
            channels: [None, None, None, None],
            last_aid_match: false,
            proactive_session_active: false,
            suci: None,
        }
    }

    /// Access the PIN manager for configuration (add PINs).
    pub const fn pin_manager(&mut self) -> &mut PinManager<5> {
        &mut self.pin
    }

    /// Access the proactive state for queuing commands.
    pub const fn proactive_state(&mut self) -> &mut ProactiveState {
        &mut self.proactive
    }

    /// Access the SUCI computation state.
    ///
    /// Set to `Some` to enable GET IDENTITY (INS=0x78, P2=0x01) per
    /// [3GPP TS 31.102 V19.4.0 clause 7.5](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf).
    /// The filesystem must contain `EF_SUCI_CALC_INFO`, `EF_IMSI`, `EF_AD`,
    /// and `EF_ROUTING_INDICATOR`; if any are missing, GET IDENTITY returns
    /// SW 69 85 (conditions not satisfied) at runtime.
    pub const fn suci_mut(&mut self) -> &mut Option<SuciState> {
        &mut self.suci
    }

    /// Clear the response queue (pending GET RESPONSE data).
    ///
    /// Per [ETSI TS 102 221 V18.3.0 clause 12.1.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A483%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C655%5D), GET RESPONSE must immediately
    /// follow the command it retrieves data for; any intervening command
    /// clears the response queue.
    pub const fn clear_response_queue(&mut self) {
        self.rsp_queue.clear();
    }

    /// Reset the file selection context to MF (basic channel).
    ///
    /// After this call, the card behaves as if freshly activated with
    /// MF implicitly selected ([ETSI TS 102 221 V18.3.0 clause 8.4](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A265%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C220%5D)).
    pub const fn reset_file_selection(&mut self) {
        self.fs = SelectionCtx::new(self.mf);
    }

    /// Close supplementary logical channels (1-3).
    ///
    /// Channel 0 (basic channel) is not routed through `channels[]` --
    /// its selection context lives in `self.fs` directly
    /// ([ETSI TS 102 221 V18.3.0 clause 8.7](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A278%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C459%5D)).
    pub const fn close_all_channels(&mut self) {
        self.channels[1] = None;
        self.channels[2] = None;
        self.channels[3] = None;
    }

    /// Reset proactive session state (profile, pending command, events,
    /// terminal capability).
    ///
    /// Terminal capability is session-scoped data received via TERMINAL
    /// CAPABILITY ([ETSI TS 102 221 V18.3.0 clause 11.1.19](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A402%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C538%5D)) during card activation
    /// and must be re-sent by the terminal after each reset.
    ///
    /// Note: this corrects the previous `reset_session` which did not
    /// clear terminal capability; clause 11.1.19 specifies it as
    /// session-scoped.
    pub const fn reset_proactive_session(&mut self) {
        self.proactive_session_active = false;
        self.proactive.reset_session();
        self.terminal_capability = [0u8; 16];
        self.terminal_capability_len = 0;
    }

    /// Clear the last AID match flag.
    ///
    /// Resets the "next occurrence" iterator for SELECT by AID
    /// ([ETSI TS 102 221 V18.3.0 clause 11.1.1](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A331%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C371%5D)).
    pub const fn clear_last_aid_match(&mut self) {
        self.last_aid_match = false;
    }

    /// Advance all UICC-side proactive timers by `elapsed_secs`.
    ///
    /// Returns the number of timers that expired. The caller should
    /// read expired timer IDs via
    /// `proactive_state().take_expired_timer()` and generate Timer
    /// Expiry envelopes as appropriate.
    pub const fn tick(&mut self, elapsed_secs: u32) -> u8 {
        self.proactive.tick(elapsed_secs)
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes.
    pub const SNAPSHOT_SIZE: usize =
        SelectionCtx::SNAPSHOT_SIZE
        + FsData::<FS_CAP, FS_MAX_EFS>::SNAPSHOT_SIZE
        + PinManager::<5>::SNAPSHOT_SIZE
        + A::SNAPSHOT_SIZE
        + ProactiveState::SNAPSHOT_SIZE
        + ResponseQueue::<64>::SNAPSHOT_SIZE
        + 17 // terminal_capability (16 bytes) + terminal_capability_len (1 byte)
        + DeactivationTracker::SNAPSHOT_SIZE
        + 4 * (SelectionCtx::SNAPSHOT_SIZE + 1) // channels: 4 * (snapshot + is_open flag)
        + 1; // last_aid_match

    /// Byte offset of the `PinManager` region within a `UsimApp` snapshot.
    pub const PIN_SNAPSHOT_OFFSET: usize =
        SelectionCtx::SNAPSHOT_SIZE + FsData::<FS_CAP, FS_MAX_EFS>::SNAPSHOT_SIZE;

    /// Serialize the USIM application state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    /// The `adfs` reference is not serialized (static, reconstructed on restore).
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut off = 0;
        off += self.fs.save_state(&mut buf[off..]);
        off += self.data.save_state(&mut buf[off..]);
        off += self.pin.save_state(&mut buf[off..]);
        off += self.auth.save_state(&mut buf[off..]);
        off += self.proactive.save_state(&mut buf[off..]);
        off += self.rsp_queue.save_state(&mut buf[off..]);
        // terminal_capability
        buf[off..off + 16].copy_from_slice(&self.terminal_capability);
        off += 16;
        buf[off] = self.terminal_capability_len;
        off += 1;
        // deactivation tracker
        off += self.deactivation.save_state(&mut buf[off..]);
        // channels
        for ch in &self.channels {
            if let Some(ctx) = ch {
                buf[off] = 1;
                off += 1;
                off += ctx.save_state(&mut buf[off..]);
            } else {
                buf[off] = 0;
                off += 1;
                // Write zeros for the placeholder snapshot.
                let end = off + SelectionCtx::SNAPSHOT_SIZE;
                buf[off..end].fill(0);
                off = end;
            }
        }
        // last_aid_match
        buf[off] = u8::from(self.last_aid_match);
        off += 1;
        let _ = off;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the USIM application state from `buf`.
    ///
    /// Returns `true` on success. The `adfs` field is not restored from the
    /// snapshot; it remains as set during construction.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut off = 0;
        if !self.fs.restore_state(&buf[off..], self.adfs) {
            return false;
        }
        off += SelectionCtx::SNAPSHOT_SIZE;
        // Re-init FsData entries from the static tree, then overwrite
        // the buffer with the saved snapshot data.
        if self.data.init_with_adfs(self.mf, self.adfs).is_err() {
            return false;
        }
        if !self.data.restore_state(&buf[off..]) {
            return false;
        }
        off += FsData::<FS_CAP, FS_MAX_EFS>::SNAPSHOT_SIZE;
        if !self.pin.restore_state(&buf[off..]) {
            return false;
        }
        off += PinManager::<5>::SNAPSHOT_SIZE;
        if !self.auth.restore_state(&buf[off..]) {
            return false;
        }
        off += A::SNAPSHOT_SIZE;
        if !self.proactive.restore_state(&buf[off..]) {
            return false;
        }
        off += ProactiveState::SNAPSHOT_SIZE;
        if !self.rsp_queue.restore_state(&buf[off..]) {
            return false;
        }
        off += ResponseQueue::<64>::SNAPSHOT_SIZE;
        // terminal_capability
        self.terminal_capability.copy_from_slice(&buf[off..off + 16]);
        off += 16;
        self.terminal_capability_len = buf[off];
        off += 1;
        // deactivation tracker
        if !self.deactivation.restore_state(&buf[off..]) {
            return false;
        }
        off += DeactivationTracker::SNAPSHOT_SIZE;
        // channels
        for ch in &mut self.channels {
            let is_open = buf[off];
            off += 1;
            if is_open != 0 {
                let mut ctx = SelectionCtx::new(self.mf);
                if !ctx.restore_state(&buf[off..], self.adfs) {
                    return false;
                }
                *ch = Some(ctx);
            } else {
                *ch = None;
            }
            off += SelectionCtx::SNAPSHOT_SIZE;
        }
        // last_aid_match
        self.last_aid_match = buf[off] != 0;
        off += 1;
        let _ = off;
        true
    }

    /// Handle an APDU command. Returns a slice of `buf` containing
    /// the response: either just `[SW1, SW2]` or `[data..., SW1, SW2]`.
    ///
    /// Accepts CLA=`0x00` (interindustry) and CLA=`0x80` (ETSI CAT).
    /// Returns `6E 00` for any other CLA.
    ///
    /// After dispatching, if SW would be `90 00` and a proactive command
    /// is pending, overrides to `91 XX`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn handle<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let cla = cmd.cla();

        // CLA check: accept interindustry (0x00-0x03, 0x40-0x43, 0x60-0x63)
        // and 0x80 (ETSI CAT).
        if !cla.is_interindustry() && cla.raw() != CLA_ETSI {
            return write_sw(buf, StatusWord::ClassNotSupported);
        }

        // Resolve logical channel for interindustry CLA.
        let channel = cla.channel();

        // Route to channel's selection context if non-basic channel.
        // For channel 0, use self.fs directly.
        if cla.is_interindustry() && channel != 0 {
            // Check that the channel is open.
            if self.channels[channel as usize].is_none() {
                return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
            }
        }

        // Any command other than GET RESPONSE clears the response queue.
        if cmd.ins() != ins::GET_RESPONSE {
            self.rsp_queue.clear();
        }

        let rsp = if cla.raw() == CLA_ETSI {
            match cmd.ins() {
                ins::TERMINAL_PROFILE => self.handle_terminal_profile(cmd, buf),
                ins::FETCH => self.handle_fetch(cmd, buf),
                ins::TERMINAL_RESPONSE => self.handle_terminal_response(cmd, buf),
                ins::ENVELOPE => self.handle_envelope(cmd, buf),
                _ => write_sw(buf, StatusWord::InsNotSupported),
            }
        } else {
            // Interindustry commands.
            match cmd.ins() {
                ins::SELECT => self.handle_select(cmd, buf),
                ins::GET_RESPONSE => self.handle_get_response(cmd, buf),
                ins::READ_BINARY => self.handle_read_binary(cmd, buf),
                ins::READ_RECORD => self.handle_read_record(cmd, buf),
                ins::UPDATE_BINARY => self.handle_update_binary(cmd, buf),
                ins::UPDATE_RECORD => self.handle_update_record(cmd, buf),
                ins::INCREASE => self.handle_increase(cmd, buf),
                ins::SEARCH_RECORD => self.handle_search_record(cmd, buf),
                ins::STATUS => self.handle_status(cmd, buf),
                ins::AUTHENTICATE => self.handle_authenticate(cmd, buf),
                ins::GET_IDENTITY => self.handle_get_identity(cmd, buf),
                ins::VERIFY => self.handle_verify(cmd, buf),
                ins::CHANGE_REF_DATA => self.handle_change_ref_data(cmd, buf),
                ins::DISABLE_PIN => self.handle_disable_pin(cmd, buf),
                ins::ENABLE_PIN => self.handle_enable_pin(cmd, buf),
                ins::RESET_RETRY_CTR => self.handle_unblock(cmd, buf),
                ins::MANAGE_CHANNEL => self.handle_manage_channel(cmd, buf),
                ins::DEACTIVATE_FILE => self.handle_deactivate_file(cmd, buf),
                ins::ACTIVATE_FILE => self.handle_activate_file(cmd, buf),
                ins::TERMINAL_CAPABILITY => self.handle_terminal_capability(cmd, buf),
                _ => write_sw(buf, StatusWord::InsNotSupported),
            }
        };

        // Proactive override: if SW is 90 00 and a command is pending,
        // rewrite to 91 XX.
        let len = rsp.len();
        if len >= 2 {
            let (sw1, sw2) = self.proactive.override_status(buf[len - 2], buf[len - 1]);
            buf[len - 2] = sw1;
            buf[len - 1] = sw2;
        }
        &buf[..len]
    }

    // -- SELECT (P1=0x00 by FID, P1=0x04 by AID) --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_select<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // P2 determines response data format:
        // 0x00 = return FCI (treated as FCP per common practice) / first occurrence for AID.
        // 0x02 = next occurrence (for AID selection).
        // 0x04 = return FCP template.
        // 0x0C = no data returned, just SW 90 00.
        // Other values are rejected per ETSI TS 102 221.
        let p2_response = cmd.p2();
        let no_data = match p2_response {
            0x00 | 0x02 | 0x04 => false,
            0x0C => true,
            _ => return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        };
        match cmd.p1() {
            0x00 => {
                // P2=0x02 is only valid for AID selection (P1=0x04).
                if p2_response == 0x02 {
                    return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
                }
                // Select by FID.
                if cmd.data().len() != 2 {
                    return write_sw(buf, StatusWord::WrongLength);
                }
                let fid = Fid::from_be_bytes([cmd.data()[0], cmd.data()[1]]);
                match self.fs.select_by_fid(fid) {
                    Ok(sel) => {
                        // Check deactivation warning for EFs.
                        if let SelectedFile::Ef(ef) = sel {
                            if self.deactivation.is_deactivated(ef.fid()) {
                                if no_data {
                                    // Return warning SW 62 83.
                                    return write_sw(buf, StatusWord::Other(0x62, 0x83));
                                }
                                // Queue FCP but return warning status.
                                let fcp_len = build_fcp(sel, None, self.rsp_queue.buf_mut());
                                self.rsp_queue.set_len(fcp_len);
                                return write_sw(buf, StatusWord::Other(0x62, 0x83));
                            }
                        }
                        if no_data {
                            write_sw(buf, StatusWord::Success)
                        } else {
                            self.queue_fcp(sel, None, buf)
                        }
                    }
                    Err(FsError::FileNotFound) => write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND)),
                    Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
                }
            }
            0x04 => {
                // Select by AID.
                if p2_response == 0x02 {
                    // "Next occurrence" -- since we typically have only one ADF,
                    // after the first match, "next" always fails.
                    if self.last_aid_match {
                        return write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND));
                    }
                    // If no previous match, try first occurrence.
                }
                match self.fs.select_by_aid(cmd.data(), self.adfs) {
                    Ok(sel) => {
                        self.last_aid_match = true;
                        if no_data {
                            write_sw(buf, StatusWord::Success)
                        } else {
                            let aid = cmd.data();
                            self.queue_fcp(sel, Some(aid), buf)
                        }
                    }
                    Err(FsError::FileNotFound) => {
                        self.last_aid_match = false;
                        write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND))
                    }
                    Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
                }
            }
            0x08 | 0x09 => {
                // P2=0x02 is only valid for AID selection (P1=0x04).
                if p2_response == 0x02 {
                    return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
                }
                // Select by path: P1=0x08 from MF, P1=0x09 from current DF.
                let from_mf = cmd.p1() == 0x08;
                match self.fs.select_by_path(cmd.data(), from_mf) {
                    Ok(_) if no_data => write_sw(buf, StatusWord::Success),
                    Ok(sel) => self.queue_fcp(sel, None, buf),
                    Err(FsError::FileNotFound) => write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND)),
                    Err(FsError::InvalidPath) => write_sw(buf, StatusWord::WrongLength),
                    Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
                }
            }
            _ => write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    /// Build FCP, queue it, return 61 XX.
    #[allow(clippy::cast_possible_truncation)]
    fn queue_fcp<'buf>(
        &mut self,
        sel: SelectedFile,
        aid: Option<&[u8]>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let fcp_len = build_fcp(sel, aid, self.rsp_queue.buf_mut());
        self.rsp_queue.set_len(fcp_len);
        write_sw(buf, StatusWord::bytes_available(fcp_len as u8))
    }

    // -- GET RESPONSE --

    fn handle_get_response<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 || cmd.p2() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        self.rsp_queue.get_response(cmd.le(), buf)
    }

    // -- PIN access gate --

    /// Check whether PIN1 access is satisfied.
    ///
    /// Returns `true` if access is denied (caller should return
    /// `SECURITY_NOT_SATISFIED`).
    const fn pin1_denied(&self) -> bool {
        !self.pin.is_access_granted(PinKey::PIN1)
    }

    // -- READ BINARY --

    fn handle_read_binary<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }

        // SFI-based access: P1 bit 7 set means SFI in P1[4:0], offset in P2.
        let (ef, offset) = if cmd.p1() & 0x80 != 0 {
            let sfi_val = cmd.p1() & 0x1F;
            let Some(ef) = self.fs.find_ef_by_sfi(Sfi::from_raw(sfi_val)) else {
                return write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND));
            };
            (ef, u16::from(cmd.p2()))
        } else {
            let Some(ef) = self.fs.current_ef() else {
                return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
            };
            (ef, u16::from_be_bytes([cmd.p1(), cmd.p2()]))
        };
        // Check deactivation.
        if self.deactivation.is_deactivated(ef.fid()) {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        }
        let le = u16::from(cmd.le().unwrap_or(0));

        match self.data.read_binary(ef, offset, le) {
            Ok(data) => write_data_sw(buf, data, StatusWord::Success),
            Err(FsError::NotTransparent) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::OffsetOutOfRange) => write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND)),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- READ RECORD --

    /// Resolve record number from P1 and P2 mode bits.
    ///
    /// P2 low 3 bits encode the record access mode per [ETSI TS 102 221 V18.3.0 clause 11.1.5.2](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A365%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C479%5D):
    /// - 0x02: next record (P1 + 1; if P1 == 0, use record 1)
    /// - 0x03: previous record (P1 - 1)
    /// - 0x04: absolute (P1 = record number)
    ///
    /// Returns `Ok(record_number)` or `Err(status_word)` on invalid mode.
    fn resolve_record_num(p1: u8, p2: u8) -> Result<u8, StatusWord> {
        match p2 & 0x07 {
            0x04 => Ok(p1),
            0x02 => {
                // Next: if P1 == 0, start at record 1; otherwise P1 + 1.
                if p1 == 0 {
                    Ok(1)
                } else {
                    p1.checked_add(1).ok_or(StatusWord::wrong_params(sw2::RECORD_NOT_FOUND))
                }
            }
            0x03 => {
                // Previous: P1 - 1.
                if p1 <= 1 {
                    Err(StatusWord::wrong_params(sw2::RECORD_NOT_FOUND))
                } else {
                    Ok(p1 - 1)
                }
            }
            _ => Err(StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    fn handle_read_record<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let rec_num = match Self::resolve_record_num(cmd.p1(), cmd.p2()) {
            Ok(n) => n,
            Err(sw) => return write_sw(buf, sw),
        };

        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        // Check deactivation.
        if self.deactivation.is_deactivated(ef.fid()) {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        }

        match self.data.read_record(ef, rec_num) {
            Ok(data) => write_data_sw(buf, data, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::RecordOutOfRange) => write_sw(buf, StatusWord::wrong_params(sw2::RECORD_NOT_FOUND)),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- UPDATE BINARY --

    fn handle_update_binary<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }

        // SFI-based access: P1 bit 7 set means SFI in P1[4:0], offset in P2.
        let (ef, offset) = if cmd.p1() & 0x80 != 0 {
            let sfi_val = cmd.p1() & 0x1F;
            let Some(ef) = self.fs.find_ef_by_sfi(Sfi::from_raw(sfi_val)) else {
                return write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND));
            };
            (ef, u16::from(cmd.p2()))
        } else {
            let Some(ef) = self.fs.current_ef() else {
                return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
            };
            (ef, u16::from_be_bytes([cmd.p1(), cmd.p2()]))
        };
        // Check deactivation.
        if self.deactivation.is_deactivated(ef.fid()) {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        }

        match self.data.write_binary(ef, offset, cmd.data()) {
            Ok(()) => {
                #[cfg(feature = "profile-full")]
                self.increment_phonebook_counters(ef.fid());
                write_sw(buf, StatusWord::Success)
            }
            Err(FsError::NotTransparent) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::OffsetOutOfRange) => write_sw(buf, StatusWord::WrongLength),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- UPDATE RECORD --

    fn handle_update_record<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let rec_num = match Self::resolve_record_num(cmd.p1(), cmd.p2()) {
            Ok(n) => n,
            Err(sw) => return write_sw(buf, sw),
        };
        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        // Check deactivation.
        if self.deactivation.is_deactivated(ef.fid()) {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        }
        match self.data.write_record(ef, rec_num, cmd.data()) {
            Ok(()) => {
                #[cfg(feature = "profile-full")]
                self.increment_phonebook_counters(ef.fid());
                write_sw(buf, StatusWord::Success)
            }
            Err(FsError::NotRecordBased) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::RecordOutOfRange) => write_sw(buf, StatusWord::wrong_params(sw2::RECORD_NOT_FOUND)),
            Err(FsError::DataTooLarge) => write_sw(buf, StatusWord::WrongLength),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- INCREASE --

    fn handle_increase<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        match self.data.increase(ef, cmd.data()) {
            Ok(new_val) => write_data_sw(buf, new_val, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::IncreaseOverflow) => write_sw(buf, StatusWord::Other(0x98, 0x50)),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- DF_PHONEBOOK synchronization counters --

    /// Increment phonebook synchronization counters after a successful write.
    ///
    /// Per [3GPP TS 31.102 V19.4.0 clause 4.4.2.12](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A315%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C787%5D):
    /// - EF_PSC (4F22): 32-bit BE, incremented on ANY phonebook child write
    /// - EF_CC  (4F23): 16-bit BE, incremented on EF_ADN (4F31) write only
    ///
    /// EF_PUID (4F24) is NOT auto-incremented by the UICC.  It stores the
    /// highest UID value previously assigned and is managed by the ME, which
    /// writes the current maximum UID value directly.
    ///
    /// Counter EFs themselves (4F22/4F23/4F24) do NOT trigger increments.
    #[cfg(feature = "profile-full")]
    fn increment_phonebook_counters(&mut self, target_fid: Fid) {
        // Only act when current DF is DF_PHONEBOOK (5F3A).
        if self.fs.current_df().fid != Fid::new(0x5F3A) {
            return;
        }
        // Counter EFs themselves must not trigger recursive increments.
        let fid = target_fid.value();
        if fid == 0x4F22 || fid == 0x4F23 || fid == 0x4F24 {
            return;
        }
        // PSC: always increment for any phonebook child write.
        Self::increment_counter(&mut self.data, &profile::PB_EF_PSC, 4);
        // CC: increment only for ADN writes.
        if fid == 0x4F31 {
            Self::increment_counter(&mut self.data, &profile::PB_EF_CC, 2);
        }
    }

    /// Increment a big-endian unsigned integer stored in a transparent EF by 1.
    /// Wraps on overflow.
    #[cfg(feature = "profile-full")]
    fn increment_counter(
        data: &mut FsData<FS_CAP, FS_MAX_EFS>,
        ef: &'static EfDef,
        size: usize,
    ) {
        if let Ok(current) = data.read_binary(ef, 0, size as u16) {
            let mut val = [0u8; 4];
            let start = 4 - size;
            val[start..4].copy_from_slice(current);
            let mut carry = 1u16;
            for i in (start..4).rev() {
                let sum = u16::from(val[i]) + carry;
                val[i] = sum as u8;
                carry = sum >> 8;
            }
            let _ = data.write_binary(ef, 0, &val[start..4]);
        }
    }

    // -- STATUS --

    fn handle_status<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // Per ETSI TS 102 221 V18.3.0 clause 11.1.2:
        // P1: 0x00 = no indication (current DF info).
        // P1: 0x01 = current DF info (same as 0x00).
        // P1: 0x02 = no data returned, just SW 90 00.
        // P2: 0x00 = FCP template.
        // P2: 0x01 = DF name (AID) TLV if available, otherwise FCP.
        // P2: 0x0C = no data returned.
        match cmd.p1() {
            0x00 | 0x01 => self.status_with_data(cmd.p2(), buf),
            0x02 => write_sw(buf, StatusWord::Success),
            _ => write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    /// STATUS response for P1=0x00/0x01: return data according to P2.
    #[allow(clippy::cast_possible_truncation)]
    fn status_with_data<'buf>(
        &self,
        p2: u8,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        match p2 {
            0x00 => {
                let mut fcp_buf = [0u8; FCP_BUF_CAP];
                let fcp_len = build_fcp(
                    SelectedFile::Df(self.fs.current_df()),
                    None,
                    &mut fcp_buf,
                );
                write_data_sw(buf, &fcp_buf[..fcp_len], StatusWord::Success)
            }
            0x01 => {
                // Return just the AID as TLV tag 0x84 if an ADF is
                // selected; otherwise fall back to full FCP.
                let aid = self.fs.current_adf().and_then(|adf| {
                    self.adfs.iter().find(|s| core::ptr::eq(s.root, adf)).map(|s| s.aid)
                });
                if let Some(aid_bytes) = aid {
                    // tag 0x84, length, AID bytes.
                    let tlv_len = 2 + aid_bytes.len();
                    buf[0] = fcp::DF_NAME;
                    buf[1] = aid_bytes.len() as u8;
                    buf[2..2 + aid_bytes.len()].copy_from_slice(aid_bytes);
                    let sw_pos = tlv_len;
                    buf[sw_pos] = 0x90;
                    buf[sw_pos + 1] = 0x00;
                    &buf[..tlv_len + 2]
                } else {
                    let mut fcp_buf = [0u8; FCP_BUF_CAP];
                    let fcp_len = build_fcp(
                        SelectedFile::Df(self.fs.current_df()),
                        None,
                        &mut fcp_buf,
                    );
                    write_data_sw(buf, &fcp_buf[..fcp_len], StatusWord::Success)
                }
            }
            0x0C => write_sw(buf, StatusWord::Success),
            _ => write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    // -- AUTHENTICATE (Milenage UMTS / GSM context) --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_authenticate<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // Note: AUTHENTICATE does not require PIN1 verification per
        // ETSI TS 102 221 -- it has its own security context.
        match cmd.p2() {
            P2_UMTS_CONTEXT => self.handle_authenticate_umts(cmd, buf),
            P2_GSM_CONTEXT => self.handle_authenticate_gsm(cmd, buf),
            _ => write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    /// UMTS security context (P2=0x81): full AKA with RAND + AUTN.
    #[allow(clippy::cast_possible_truncation)]
    fn handle_authenticate_umts<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let data = cmd.data();
        // Data: 0x10 [RAND:16] 0x10 [AUTN:16] = 34 bytes.
        if data.len() != AUTH_DATA_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }
        if data[0] != AUTH_VECTOR_LEN_PREFIX || data[17] != AUTH_VECTOR_LEN_PREFIX {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&data[1..17]);
        let mut auth_token = [0u8; 16];
        auth_token.copy_from_slice(&data[18..34]);

        let auth_result = match self.auth.authenticate(&challenge, &auth_token) {
            Ok(output) => AuthenticationResult::Success {
                response: output.response,
                cipher_key: output.cipher_key,
                integrity_key: output.integrity_key,
            },
            Err(AuthenticationError::MacFailure) => AuthenticationResult::MacFailure,
            Err(AuthenticationError::SyncFailure { resync_token }) => {
                AuthenticationResult::SyncFailure { resync_token }
            }
        };

        if matches!(auth_result, AuthenticationResult::MacFailure) {
            write_sw(buf, StatusWord::AuthenticationError)
        } else {
            let q = self.rsp_queue.buf_mut();
            let n = auth_result.encode(q);
            self.rsp_queue.set_len(n);
            write_sw(buf, StatusWord::bytes_available(n as u8))
        }
    }

    /// GSM security context (P2=0x00): compute SRES and Kc from RAND.
    ///
    /// Per [3GPP TS 31.102 V19.4.0 clause 7.1.2](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf#%5B%7B%22num%22%3A717%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C738%5D) and TS 33.102 Annex B (c3 conversion):
    /// - SRES = f2(RAND) truncated to 4 bytes
    /// - CK = f3(RAND), IK = f4(RAND)
    /// - Kc = CK[0..8] xor CK[8..16] xor IK[0..8] xor IK[8..16]
    ///
    /// Response: 0x04 || SRES(4) || 0x08 || Kc(8), queued via GET RESPONSE.
    #[allow(clippy::cast_possible_truncation)]
    fn handle_authenticate_gsm<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let data = cmd.data();
        // Data: 0x10 [RAND:16] = 17 bytes.
        if data.len() != GSM_AUTH_DATA_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }
        if data[0] != AUTH_VECTOR_LEN_PREFIX {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&data[1..17]);

        // Compute SRES = f2(RAND)[0..4].
        let response = self.auth.compute_response(&challenge);
        let mut sres = [0u8; 4];
        sres.copy_from_slice(&response[..4]);

        // Compute Kc per TS 33.102 Annex B c3 conversion:
        // Kc = CK1 xor CK2 xor IK1 xor IK2
        // where CK = CK1(8) || CK2(8), IK = IK1(8) || IK2(8).
        let cipher_key = self.auth.compute_cipher_key(&challenge);
        let integrity_key = self.auth.compute_integrity_key(&challenge);
        let ck = cipher_key.declassify();
        let ik = integrity_key.declassify();
        let mut gsm_cipher_key = [0u8; 8];
        for i in 0..8 {
            gsm_cipher_key[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
        }

        // Encode response: 0x04 || SRES(4) || 0x08 || Kc(8).
        let q = self.rsp_queue.buf_mut();
        q[0] = GSM_SRES_LEN;
        q[1..5].copy_from_slice(&sres);
        q[5] = GSM_KC_LEN;
        q[6..14].copy_from_slice(&gsm_cipher_key);
        self.rsp_queue.set_len(GSM_AUTH_RSP_LEN);
        write_sw(buf, StatusWord::bytes_available(GSM_AUTH_RSP_LEN as u8))
    }

    // -- GET IDENTITY (SUCI computation, TS 31.102 V19.4.0 clause 7.5) --

    /// GET IDENTITY handler: computes SUCI on-card per
    /// [3GPP TS 31.102 V19.4.0 clause 7.5](../../../docs/specs/3gpp/ts-31.102/ts_131102v190400p.pdf).
    ///
    /// P2=0x01 is the SUCI context. Returns the SUCI as a TLV data object
    /// (tag 0xA1) via GET RESPONSE.
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    fn handle_get_identity<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        if cmd.p2() != P2_SUCI_CONTEXT {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }

        // SUCI computation requires provisioned DRBG seed.
        let Some(suci) = &mut self.suci else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::CONDITIONS_NOT_SATISFIED));
        };

        // Read EF_SUCI_CALC_INFO to determine protection scheme and HN public key.
        let calc_info_len = profile::EF_SUCI_CALC_INFO.data().len() as u16;
        let Ok(calc_info) = self.data.read_binary(&profile::EF_SUCI_CALC_INFO, 0, calc_info_len) else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::CONDITIONS_NOT_SATISFIED));
        };

        // Parse Protection Scheme Identifier List (tag 0xA0).
        if calc_info.len() < 4 || calc_info[0] != SUCI_CALC_INFO_SCHEME_LIST_TAG {
            return write_sw(buf, StatusWord::wrong_params(sw2::DATA_NOT_FOUND));
        }
        let scheme_list_len = calc_info[1] as usize;
        if calc_info.len() < 2 + scheme_list_len || scheme_list_len < 2 {
            return write_sw(buf, StatusWord::wrong_params(sw2::DATA_NOT_FOUND));
        }
        let protection_scheme = calc_info[2];
        let key_index = calc_info[3];

        // Read EF_IMSI for MSIN extraction.
        let Ok(imsi_data) = self.data.read_binary(&profile::EF_IMSI, 0, 9) else {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        };

        // Read EF_AD byte 3 for MNC length.
        let Ok(ad_data) = self.data.read_binary(&profile::EF_AD, 0, 4) else {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        };
        let mnc_len = if ad_data.len() >= 4 && (ad_data[3] == 2 || ad_data[3] == 3) {
            ad_data[3]
        } else {
            2 // default to 2-digit MNC
        };

        let msin = extract_msin(imsi_data, mnc_len);

        // Read Routing Indicator (EF 4F0A, 4 bytes BCD).
        let Ok(routing_ind) = self.data.read_binary(&profile::EF_ROUTING_INDICATOR, 0, 4) else {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        };

        // Extract MCC+MNC from IMSI for the home network identifier.
        let mcc_mnc = extract_mcc_mnc(imsi_data, mnc_len);

        // Encode SUCI TLV response per TS 31.102 V19.4.0 clause 7.5.2.1.
        // MSIN is always MSIN_FIXED_LEN bytes to prevent length leakage via SW2.
        let q = self.rsp_queue.buf_mut();
        match protection_scheme {
            SCHEME_NULL => {
                // Null scheme: MSIN in clear (no encryption).
                // SUCI = A1 <len> 01 <MCC+MNC:3> <RoutingInd:2> 00 <key_index> <MSIN_BCD:5>
                let inner_len = 1 + 3 + 2 + 1 + 1 + MSIN_FIXED_LEN;
                let mut pos = 0usize;
                q[pos] = SUCI_TLV_TAG; pos += 1;
                q[pos] = inner_len as u8; pos += 1;
                q[pos] = SUPI_TYPE_IMSI; pos += 1;
                q[pos..pos + 3].copy_from_slice(&mcc_mnc); pos += 3;
                q[pos..pos + 2].copy_from_slice(&[routing_ind[0], routing_ind[1]]); pos += 2;
                q[pos] = SCHEME_NULL; pos += 1;
                q[pos] = key_index; pos += 1;
                q[pos..pos + MSIN_FIXED_LEN].copy_from_slice(&msin); pos += MSIN_FIXED_LEN;
                self.rsp_queue.set_len(pos);
                write_sw(buf, StatusWord::bytes_available(pos as u8))
            }
            SCHEME_PROFILE_A => {
                // Profile A: X25519 ECIES.
                let Some(hn_key) = parse_hn_public_key(calc_info, 2 + scheme_list_len) else {
                    return write_sw(buf, StatusWord::wrong_params(sw2::DATA_NOT_FOUND));
                };
                if hn_key.len() != 32 {
                    return write_sw(buf, StatusWord::wrong_params(sw2::DATA_NOT_FOUND));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(hn_key);

                let eph_sk = Secret::new(suci.next_ephemeral_key());
                let result = simrs_ecies::ecies_profile_a_encrypt(&pk, &msin, &eph_sk);

                // Scheme output: ephemeral_pk(32) || ciphertext(MSIN_FIXED_LEN) || mac(8)
                let scheme_output_len = 32 + MSIN_FIXED_LEN + 8;
                let inner_len = 1 + 3 + 2 + 1 + 1 + scheme_output_len;
                let mut pos = 0usize;
                q[pos] = SUCI_TLV_TAG; pos += 1;
                q[pos] = inner_len as u8; pos += 1;
                q[pos] = SUPI_TYPE_IMSI; pos += 1;
                q[pos..pos + 3].copy_from_slice(&mcc_mnc); pos += 3;
                q[pos..pos + 2].copy_from_slice(&[routing_ind[0], routing_ind[1]]); pos += 2;
                q[pos] = SCHEME_PROFILE_A; pos += 1;
                q[pos] = key_index; pos += 1;
                q[pos..pos + 32].copy_from_slice(&result.ephemeral_pk); pos += 32;
                q[pos..pos + MSIN_FIXED_LEN].copy_from_slice(&result.ciphertext[..MSIN_FIXED_LEN]); pos += MSIN_FIXED_LEN;
                q[pos..pos + 8].copy_from_slice(&result.mac); pos += 8;
                self.rsp_queue.set_len(pos);
                write_sw(buf, StatusWord::bytes_available(pos as u8))
            }
            SCHEME_PROFILE_B => {
                // Profile B: P-256 ECIES.
                let Some(hn_key) = parse_hn_public_key(calc_info, 2 + scheme_list_len) else {
                    return write_sw(buf, StatusWord::wrong_params(sw2::DATA_NOT_FOUND));
                };
                if hn_key.len() != 65 {
                    return write_sw(buf, StatusWord::wrong_params(sw2::DATA_NOT_FOUND));
                }
                let mut pk = [0u8; 65];
                pk.copy_from_slice(hn_key);

                // Generate 4 ephemeral key candidates and select the first valid
                // one using constant-time masks, preventing timing leaks from
                // the rejection sampling loop.
                let c0 = suci.next_ephemeral_key();
                let c1 = suci.next_ephemeral_key();
                let c2 = suci.next_ephemeral_key();
                let c3 = suci.next_ephemeral_key();

                let v0 = simrs_ecies::p256::validate_scalar(&c0);
                let v1 = simrs_ecies::p256::validate_scalar(&c1);
                let v2 = simrs_ecies::p256::validate_scalar(&c2);
                let v3 = simrs_ecies::p256::validate_scalar(&c3);

                // Build selection masks: pick the first (lowest index) valid candidate.
                // m_i is all-ones if candidate i is selected, all-zeros otherwise.
                let m0 = u8::from(v0).wrapping_neg(); // 0xFF if v0, else 0x00
                let found0 = m0;
                let m1 = u8::from(v1).wrapping_neg() & !found0;
                let found1 = found0 | u8::from(v1).wrapping_neg();
                let m2 = u8::from(v2).wrapping_neg() & !found1;
                let found2 = found1 | u8::from(v2).wrapping_neg();
                let m3 = u8::from(v3).wrapping_neg() & !found2;
                let any_valid = found2 | u8::from(v3).wrapping_neg();

                if any_valid == 0 {
                    return write_sw(buf, StatusWord::NoPreciseDiagnosis);
                }

                let mut eph_sk = [0u8; 32];
                let mut j = 0;
                while j < 32 {
                    eph_sk[j] = (c0[j] & m0) | (c1[j] & m1) | (c2[j] & m2) | (c3[j] & m3);
                    j += 1;
                }

                let result = simrs_ecies::ecies_profile_b_encrypt(&pk, &msin, &Secret::new(eph_sk));

                // Scheme output: ephemeral_pk(33) || ciphertext(MSIN_FIXED_LEN) || mac(8)
                let scheme_output_len = 33 + MSIN_FIXED_LEN + 8;
                let inner_len = 1 + 3 + 2 + 1 + 1 + scheme_output_len;
                let mut pos = 0usize;
                q[pos] = SUCI_TLV_TAG; pos += 1;
                q[pos] = inner_len as u8; pos += 1;
                q[pos] = SUPI_TYPE_IMSI; pos += 1;
                q[pos..pos + 3].copy_from_slice(&mcc_mnc); pos += 3;
                q[pos..pos + 2].copy_from_slice(&[routing_ind[0], routing_ind[1]]); pos += 2;
                q[pos] = SCHEME_PROFILE_B; pos += 1;
                q[pos] = key_index; pos += 1;
                q[pos..pos + 33].copy_from_slice(&result.ephemeral_pk); pos += 33;
                q[pos..pos + MSIN_FIXED_LEN].copy_from_slice(&result.ciphertext[..MSIN_FIXED_LEN]); pos += MSIN_FIXED_LEN;
                q[pos..pos + 8].copy_from_slice(&result.mac); pos += 8;
                self.rsp_queue.set_len(pos);
                write_sw(buf, StatusWord::bytes_available(pos as u8))
            }
            _ => write_sw(buf, StatusWord::wrong_params(sw2::INCORRECT_DATA)),
        }
    }

    fn handle_verify<'buf>(&mut self, cmd: &Command<'_>, buf: &'buf mut [u8]) -> &'buf [u8] {
        simrs_pin::apdu_verify(&mut self.pin, cmd, buf)
    }

    fn handle_change_ref_data<'buf>(&mut self, cmd: &Command<'_>, buf: &'buf mut [u8]) -> &'buf [u8] {
        simrs_pin::apdu_change(&mut self.pin, cmd, buf)
    }

    fn handle_disable_pin<'buf>(&mut self, cmd: &Command<'_>, buf: &'buf mut [u8]) -> &'buf [u8] {
        simrs_pin::apdu_disable(&mut self.pin, cmd, buf)
    }

    fn handle_enable_pin<'buf>(&mut self, cmd: &Command<'_>, buf: &'buf mut [u8]) -> &'buf [u8] {
        simrs_pin::apdu_enable(&mut self.pin, cmd, buf)
    }

    fn handle_unblock<'buf>(&mut self, cmd: &Command<'_>, buf: &'buf mut [u8]) -> &'buf [u8] {
        simrs_pin::apdu_unblock(&mut self.pin, cmd, buf)
    }

    // -- SEARCH RECORD (7A) --

    fn handle_search_record<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        // Check deactivation.
        if self.deactivation.is_deactivated(ef.fid()) {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        }
        let pattern = cmd.data();
        match self.data.search_records(ef, pattern) {
            Ok((matches, count)) => {
                if count == 0 {
                    write_sw(buf, StatusWord::wrong_params(sw2::RECORD_NOT_FOUND))
                } else {
                    write_data_sw(buf, &matches[..count], StatusWord::Success)
                }
            }
            Err(FsError::NotRecordBased) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- TERMINAL CAPABILITY (7B) --

    fn handle_terminal_capability<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let data = cmd.data();
        let n = data.len().min(16);
        self.terminal_capability[..n].copy_from_slice(&data[..n]);
        // Zero remaining bytes if new data is shorter.
        if n < 16 {
            self.terminal_capability[n..].fill(0);
        }
        #[allow(clippy::cast_possible_truncation)]
        {
            self.terminal_capability_len = n as u8;
        }
        write_sw(buf, StatusWord::Success)
    }

    // -- DEACTIVATE FILE (7C) --

    fn handle_deactivate_file<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let _ = cmd;
        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        self.deactivation.deactivate_file(ef.fid());
        write_sw(buf, StatusWord::Success)
    }

    // -- ACTIVATE FILE (7C) --

    fn handle_activate_file<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let _ = cmd;
        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        // Activate: remove from deactivated list. If not deactivated, that's OK.
        let _ = self.deactivation.activate_file(ef.fid());
        write_sw(buf, StatusWord::Success)
    }

    // -- MANAGE CHANNEL (7E) --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_manage_channel<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        match cmd.p1() {
            0x00 => {
                // OPEN: allocate next free channel.
                for i in 1..4u8 {
                    if self.channels[i as usize].is_none() {
                        self.channels[i as usize] = Some(SelectionCtx::new(self.mf));
                        return write_data_sw(buf, &[i], StatusWord::Success);
                    }
                }
                // No free channel available.
                write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF))
            }
            0x80 => {
                // CLOSE: close channel specified in P2.
                let ch = cmd.p2();
                if ch == 0 {
                    // Cannot close basic channel.
                    return write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE));
                }
                if ch > 3 {
                    return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
                }
                if self.channels[ch as usize].is_none() {
                    // Channel not open.
                    return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
                }
                self.channels[ch as usize] = None;
                write_sw(buf, StatusWord::Success)
            }
            _ => write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    // -- TERMINAL PROFILE --

    fn handle_terminal_profile<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        self.proactive.set_terminal_profile(cmd.data());
        write_sw(buf, StatusWord::Success)
    }

    // -- FETCH --

    fn handle_fetch<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if !self.proactive.has_pending() {
            // Per TS 102 223: FETCH with no pending command is not allowed.
            return write_sw(buf, StatusWord::CommandNotAllowed(0x00));
        }

        let le = cmd.le().unwrap_or(0) as usize;
        let pending = self.proactive.pending_len();
        let fetch_len = if le == 0 { pending } else { le.min(pending) };

        if buf.len() < fetch_len + 2 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }

        let written = self.proactive.fetch(&mut buf[..fetch_len]);
        // Mark session as active: terminal has fetched the command.
        self.proactive_session_active = true;
        let [sw1, sw2_byte] = StatusWord::Success.to_bytes();
        buf[written] = sw1;
        buf[written + 1] = sw2_byte;
        &buf[..written + 2]
    }

    // -- TERMINAL RESPONSE --

    fn handle_terminal_response<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // If we have a valid Command Details TLV in the data but no active
        // proactive session, reject with 69 86 (command not allowed).
        if !self.proactive_session_active && Self::has_command_details(cmd.data()) {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        }
        // Session concludes with TERMINAL RESPONSE.
        self.proactive_session_active = false;

        let result = self.proactive.terminal_response(cmd.data());
        // Handle REFRESH action (7H).
        if let Some(tr) = result {
            // cmd_type 0x01 = REFRESH.
            if tr.cmd_type == 0x01 && tr.general_result == 0x00 {
                // The qualifier is encoded in the command details of the
                // proactive command, but we don't have it in TerminalResult.
                // We look at the original command's cmd_qualifier.
                // Since TerminalResult doesn't store qualifier, we use
                // a simpler approach: re-select MF for SIM Init,
                // full reset for UICC Reset.
                // We can infer refresh type from the TERMINAL RESPONSE data
                // by parsing command details.
                let refresh_qualifier = Self::parse_refresh_qualifier(cmd.data());
                match refresh_qualifier {
                    0x01 | 0x03 => {
                        // SIM Initialization / SIM Init and file change: re-select MF.
                        let _ = self.fs.select_by_fid(Fid::MF);
                    }
                    0x04 => {
                        // UICC Reset: reset to clean state.
                        self.fs = SelectionCtx::new(self.mf);
                        self.deactivation.clear();
                    }
                    _ => {
                        // Other refresh types: just clear pending state (already done).
                    }
                }
            }
        }
        write_sw(buf, StatusWord::Success)
    }

    /// Parse the refresh qualifier byte from a TERMINAL RESPONSE data field.
    ///
    /// Looks for Command Details TLV (tag 0x81) and returns the qualifier
    /// (byte index 2 of the value), or 0xFF if not found.
    fn parse_refresh_qualifier(data: &[u8]) -> u8 {
        // Simple TLV walk to find tag 0x81 (command details).
        let mut pos = 0;
        while pos < data.len() {
            let tag = data[pos];
            pos += 1;
            if pos >= data.len() { break; }
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() { break; }
            if tag == 0x81 && len >= 3 {
                // [cmd_number, cmd_type, cmd_qualifier]
                return data[pos + 2];
            }
            pos += len;
        }
        0xFF
    }

    /// Check whether `data` contains a Command Details TLV (tag 0x81).
    ///
    /// Used to distinguish well-formed TERMINAL RESPONSE data (which must
    /// have a corresponding proactive session) from trivial/empty payloads.
    fn has_command_details(data: &[u8]) -> bool {
        let mut pos = 0;
        while pos < data.len() {
            let tag = data[pos];
            pos += 1;
            if pos >= data.len() { break; }
            let len = data[pos] as usize;
            pos += 1;
            if pos + len > data.len() { break; }
            if tag == 0x81 && len >= 3 {
                return true;
            }
            pos += len;
        }
        false
    }

    /// Whether a proactive session is currently active (command fetched,
    /// awaiting TERMINAL RESPONSE).
    pub const fn is_proactive_session_active(&self) -> bool {
        self.proactive_session_active
    }

    // -- ENVELOPE --

    /// Envelope tag: SMS-PP Data Download ([ETSI TS 102 223 V18.2.0 clause 7.1](../../../docs/specs/etsi/ts-102-223/ts_102223v180200p.pdf)).
    const ENV_TAG_SMS_PP_DOWNLOAD: u8 = 0xD1;
    /// Envelope tag: Call Control by USIM ([ETSI TS 102 223 V18.2.0 clause 7.3](../../../docs/specs/etsi/ts-102-223/ts_102223v180200p.pdf)).
    const ENV_TAG_CALL_CONTROL: u8 = 0xD4;

    fn handle_envelope<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let data = cmd.data();

        // Per ETSI TS 102 221 V18.3.0 clause 11.2.2: ENVELOPE requires a prior
        // TERMINAL PROFILE to have been sent in this session.
        if !self.proactive.has_terminal_profile() {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        }

        // Reject empty data (no BER-TLV tag present).
        if data.is_empty() {
            return write_sw(buf, StatusWord::WrongLength);
        }

        // Minimum BER-TLV: tag byte + length byte (at least 2 bytes).
        if data.len() < 2 {
            return write_sw(buf, StatusWord::wrong_params(0x80));
        }

        // Validate BER-TLV length field.
        // Reject long-form BER length encoding (MSB set): T=0 APDUs are
        // bounded to 255-byte Lc, so the outer TLV length must fit in a
        // single short-form byte.
        if data[1] & 0x80 != 0 {
            return write_sw(buf, StatusWord::wrong_params(0x80));
        }
        // A zero-length value (L=00) is syntactically valid BER but
        // semantically invalid for all envelope types that require inner
        // TLVs (SMS-PP, Call Control, etc.).
        let tlv_len = data[1] as usize;
        if tlv_len == 0 || data.len() < 2 + tlv_len {
            return write_sw(buf, StatusWord::wrong_params(0x80));
        }

        // Determine envelope type from the outer BER-TLV tag byte.
        let tag = data[0];

        match tag {
            Self::ENV_TAG_SMS_PP_DOWNLOAD => {
                // SMS-PP Data Download: accept and pass to proactive state.
                self.proactive.process_envelope(data);
                write_sw(buf, StatusWord::Success)
            }
            Self::ENV_TAG_CALL_CONTROL => {
                // Call Control by USIM: allowed without modification.
                // Per ETSI TS 102 223 clause 7.3.1 the USIM may allow,
                // modify, or reject the call; this implementation always
                // allows without modification.
                write_sw(buf, StatusWord::Success)
            }
            _ => {
                // Menu Selection (D3), Event Download (D6), and all other
                // recognized tags: pass to proactive state for processing.
                if self.proactive.process_envelope(data) {
                    write_sw(buf, StatusWord::Success)
                } else {
                    // Unrecognized or malformed envelope.
                    write_sw(buf, StatusWord::wrong_params(0x80))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FCP BER-TLV builder per ETSI TS 102 221 V18.3.0 clause 11.1.1.3
// ---------------------------------------------------------------------------

/// Build an FCP template for the selected file.
///
/// Returns the number of bytes written to `out`. The FCP is a BER-TLV
/// structure with tag `fcp::TEMPLATE` (0x62).
///
/// Uses the dry-run/real-run pattern: first pass counts bytes, second
/// writes them.
fn build_fcp(
    sel: SelectedFile,
    aid: Option<&[u8]>,
    out: &mut [u8],
) -> usize {
    // Dry run to compute inner content length.
    let inner_len = fcp_inner_len(sel, aid);

    // Real run: write FCP template tag + length + inner content.
    let mut enc = Encoder::new(out);
    let _ = enc.raw(&[fcp::TEMPLATE]);
    // BER length of inner content.
    let _ = write_ber_len(&mut enc, inner_len);
    // Inner TLV objects.
    let _ = write_fcp_inner(&mut enc, sel, aid);
    enc.len()
}

/// Compute the byte length of the FCP inner content (without the template tag
/// and its length field).
fn fcp_inner_len(sel: SelectedFile, aid: Option<&[u8]>) -> usize {
    let mut enc = Encoder::dry_run();
    let _ = write_fcp_inner(&mut enc, sel, aid);
    enc.len()
}

/// Write the FCP inner TLV objects.
fn write_fcp_inner(
    enc: &mut Encoder<'_>,
    sel: SelectedFile,
    aid: Option<&[u8]>,
) -> Result<(), simrs_bertlv::BerError> {
    match sel {
        SelectedFile::Df(df) => write_fcp_df(enc, df, aid),
        SelectedFile::Ef(ef) => write_fcp_ef(enc, ef),
    }
}

/// FCP inner content for a DF/MF/ADF.
fn write_fcp_df(
    enc: &mut Encoder<'_>,
    df: &DfDef,
    aid: Option<&[u8]>,
) -> Result<(), simrs_bertlv::BerError> {
    // File descriptor: byte 0 = FD_DF, byte 1 = DATA_CODING_BER_TLV.
    enc.tag_length_value(fcp::FILE_DESCRIPTOR, &[FD_DF, DATA_CODING_BER_TLV])?;

    // File ID.
    let fid_be = df.fid.to_be_bytes();
    enc.tag_length_value(fcp::FILE_ID, &fid_be)?;

    // DF name (AID) -- only for ADF.
    if let Some(aid_bytes) = aid {
        enc.tag_length_value(fcp::DF_NAME, aid_bytes)?;
    }

    // Proprietary information (empty for now).
    enc.tag_length_value(fcp::PROPRIETARY_INFO, &[])?;

    // Life cycle status = activated.
    enc.tag_length_value(fcp::LIFECYCLE_STATUS, &[LIFECYCLE_ACTIVATED])?;

    // Security attributes compact: DF -- all operations always allowed.
    // AM byte = 0xFF (all operations), SC byte = 0x00 (always).
    enc.tag_length_value(fcp::SECURITY_ATTRS_COMPACT, &[0xFF, 0x00])?;

    // PIN status template DO.
    // Contains PS_DO (tag PS_DO_TAG) with PIN reference.
    let pin_status = [PS_DO_TAG, 0x01, 0x01]; // PS_DO: PIN1 reference
    enc.tag_length_value(fcp::PIN_STATUS_TEMPLATE, &pin_status)?;

    Ok(())
}

/// FCP inner content for an EF.
#[allow(clippy::cast_possible_truncation)]
fn write_fcp_ef(
    enc: &mut Encoder<'_>,
    ef: &EfDef,
) -> Result<(), simrs_bertlv::BerError> {
    // File descriptor.
    let (fd_data, fd_len) = ef.structure().fcp_descriptor_data();
    enc.tag_length_value(fcp::FILE_DESCRIPTOR, &fd_data[..fd_len])?;

    // File ID.
    let fid_be = ef.fid().to_be_bytes();
    enc.tag_length_value(fcp::FILE_ID, &fid_be)?;

    // File size.
    let size = ef.data().len() as u16;
    let size_be = size.to_be_bytes();
    enc.tag_length_value(fcp::FILE_SIZE, &size_be)?;

    // Short File Identifier (if assigned).
    if let Some(sfi) = ef.sfi() {
        // SFI is encoded as (sfi << 3) | SFI_INDICATOR per ETSI TS 102 221.
        enc.tag_length_value(fcp::SHORT_FILE_ID, &[(sfi.value() << 3) | SFI_INDICATOR])?;
    }

    // Life cycle status = activated.
    enc.tag_length_value(fcp::LIFECYCLE_STATUS, &[LIFECYCLE_ACTIVATED])?;

    // Security attributes compact: EF -- read+update require PIN1.
    // AM byte = 0x03 (read=0x01 | update=0x02), SC byte = 0x01 (PIN1 verified).
    enc.tag_length_value(fcp::SECURITY_ATTRS_COMPACT, &[0x03, 0x01])?;

    Ok(())
}

/// Write a BER-encoded length using the encoder.
fn write_ber_len(
    enc: &mut Encoder<'_>,
    len: usize,
) -> Result<(), simrs_bertlv::BerError> {
    #[allow(clippy::cast_possible_truncation)]
    if len <= simrs_bertlv::BER_SHORT_FORM_MAX {
        enc.raw(&[len as u8])
    } else {
        enc.raw(&[simrs_bertlv::BER_LONG_FORM_1, len as u8])
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use simrs_fs::{AdfSlot, EfDef, Fid, FileRef, Sfi};
    use simrs_milenage::{OperatorVariant, SubscriberKey};
    use simrs_proactive::ProactiveCommand;

    // -- Test filesystem --

    static EF_ICCID: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        Some(Sfi::new(2)),
        &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    );

    static EF_DIR_DATA: [u8; 16] = [
        0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_DIR: EfDef = EfDef::linear_fixed(
        Fid::new(0x2F00),
        Some(Sfi::new(30)),
        8, 2,
        &EF_DIR_DATA,
    );

    static EF_IMSI: EfDef = EfDef::transparent(
        Fid::new(0x6F07),
        Some(Sfi::new(7)),
        &[0x08, 0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
    );

    static EF_UST: EfDef = EfDef::transparent(
        Fid::new(0x6F38),
        None,
        &[0xFF, 0xFF, 0xFF, 0xFF],
    );

    static EF_FDN_DATA: [u8; 20] = [
        0x41, 0x6C, 0x69, 0x63, 0x65, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x42, 0x6F, 0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_FDN: EfDef = EfDef::linear_fixed(
        Fid::new(0x6F3B),
        None,
        10, 2,
        &EF_FDN_DATA,
    );

    static EF_ACC_DATA: [u8; 12] = [
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    static EF_ACC: EfDef = EfDef::cyclic(
        Fid::new(0x6F78),
        None,
        4, 3,
        &EF_ACC_DATA,
    );

    static ADF_USIM_ROOT: DfDef = DfDef {
        fid: Fid::new(0xFF01),
        children: &[
            FileRef::Ef(&EF_IMSI),
            FileRef::Ef(&EF_UST),
            FileRef::Ef(&EF_FDN),
            FileRef::Ef(&EF_ACC),
        ],
    };

    static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_ROOT,
    }];

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[
            FileRef::Ef(&EF_ICCID),
            FileRef::Ef(&EF_DIR),
        ],
    };

    // ETSI TS 135 208 Test Set 1 values.
    static K: SubscriberKey = SubscriberKey::new(Secret::new([
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F,
        0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC,
    ]));
    static OPC: OperatorVariant = OperatorVariant::opc(Secret::new([
        0xCD, 0x63, 0xCB, 0x71, 0x95, 0x4A, 0x9F, 0x4E,
        0x48, 0xA5, 0x99, 0x4E, 0x37, 0xA0, 0x2B, 0xAF,
    ]));

    fn app() -> UsimApp {
        let mil = MilenageParams::with_defaults(K, OPC);
        let mut a = UsimApp::new(&MF, &ADF_TABLE, mil);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        // Pre-verify PIN1 so existing tests can perform file operations
        // without explicit PIN verification via APDU.
        let _ = a.pin_manager().verify(PinKey::PIN1, &pin_val);
        a
    }

    /// Create an app with PIN1 enabled (not disabled) for PIN-gate tests.
    fn app_with_pin1_enabled() -> UsimApp {
        let mil = MilenageParams::with_defaults(K, OPC);
        let mut a = UsimApp::new(&MF, &ADF_TABLE, mil);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        a
    }

    fn send(app: &mut UsimApp, apdu: &[u8]) -> ([u8; 256], usize) {
        let cmd = Command::parse(apdu).unwrap();
        let mut buf = [0u8; 256];
        let rsp = app.handle(&cmd, &mut buf);
        let len = rsp.len();
        (buf, len)
    }

    fn sw(buf: &[u8], len: usize) -> (u8, u8) {
        (buf[len - 2], buf[len - 1])
    }

    // -- CLA routing --

    #[test]
    fn cla_00_accepted() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x6E);
    }

    #[test]
    fn cla_a0_rejected() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        assert_eq!(sw(&buf, len), (0x6E, 0x00));
    }

    #[test]
    fn cla_80_accepted_for_terminal_profile() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x80, 0x10, 0x00, 0x00]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x6E);
    }

    // -- SELECT by FID + FCP --

    #[test]
    fn select_mf_returns_61_xx() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0x61); // data available
    }

    #[test]
    fn get_response_after_select_mf_returns_fcp() {
        let mut app = app();
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let fcp_len = buf[1] as usize;

        let mut gr_apdu = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr_apdu[4] = fcp_len as u8;
        let (buf, len) = send(&mut app, &gr_apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, fcp_len + 2);
        // FCP starts with tag 0x62.
        assert_eq!(buf[0], 0x62);
        // Inner TLV objects start after 0x62 + length byte.
        let inner = &buf[2..fcp_len];
        assert!(find_tlv_tag(inner, 0x83).is_some());
        let fid_val = find_tlv_tag(inner, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00]);
    }

    #[test]
    fn select_ef_returns_fcp_with_file_size() {
        let mut app = app();
        // Select MF then EF.ICCID.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x20]); // consume
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let fcp_len = buf[1] as usize;
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = fcp_len as u8;
        let (buf, len) = send(&mut app, &gr);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let inner = &buf[2..fcp_len];
        // Tag 0x80: file size.
        let size_val = find_tlv_tag(inner, 0x80).unwrap();
        assert_eq!(size_val, &[0x00, 0x0A]); // 10 bytes
        // Tag 0x83: FID = 2FE2.
        let fid_val = find_tlv_tag(inner, 0x83).unwrap();
        assert_eq!(fid_val, &[0x2F, 0xE2]);
    }

    #[test]
    fn fcp_for_df_contains_pin_status() {
        let mut app = app();
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let fcp_len = buf[1] as usize;
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = fcp_len as u8;
        let (buf, _len) = send(&mut app, &gr);
        let inner = &buf[2..fcp_len];
        // Must contain 0xC6 (PIN status template).
        assert!(find_tlv_tag(inner, 0xC6).is_some());
        // Must contain 0x8C (security attributes).
        assert!(find_tlv_tag(inner, 0x8C).is_some());
    }

    // -- SELECT by AID --

    #[test]
    fn select_adf_usim_by_aid() {
        let mut app = app();
        let (buf, _len) = send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        assert_eq!(buf[0], 0x61); // FCP available
        let fcp_len = buf[1] as usize;
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = fcp_len as u8;
        let (buf, _) = send(&mut app, &gr);
        let inner = &buf[2..fcp_len];
        // Must contain tag 0x84 (DF name / AID).
        let aid_val = find_tlv_tag(inner, 0x84).unwrap();
        assert_eq!(aid_val, &USIM_AID);
    }

    #[test]
    fn select_unknown_aid_returns_6a82() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x82));
    }

    // -- GET RESPONSE --

    #[test]
    fn get_response_with_no_pending() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x10]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90);
    }

    #[test]
    fn non_get_response_clears_queue() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]); // queues FCP
        send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]); // STATUS clears queue
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x10]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90);
    }

    // -- READ BINARY --

    #[test]
    fn read_binary_full() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(
            &buf[..10],
            &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]
        );
    }

    #[test]
    fn read_binary_with_offset() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x02, 0x03]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..3], &[0x14, 0x80, 0x00]);
    }

    #[test]
    fn read_binary_past_end() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x08, 0x05]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90);
    }

    #[test]
    fn read_binary_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x86));
    }

    // -- READ RECORD --

    #[test]
    fn read_record_first() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]); // EF.DIR
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x61); // first record starts with TLV tag
        assert_eq!(len, 8 + 2);
    }

    #[test]
    fn read_record_beyond_last() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]);
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x03, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x6A, 0x83));
    }

    #[test]
    fn read_record_mode_absolute() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]); // EF.DIR
        // P2=0x04: absolute mode, P1=2 -> record 2.
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x02, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 8 + 2);
        // Record 2 is all 0xFF in EF.DIR.
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn read_record_mode_next() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]); // EF.DIR
        // P2=0x02: next mode, P1=0 -> record 1 (first).
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x00, 0x02, 0x08]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x61); // first record starts with TLV tag
        // P2=0x02: next mode, P1=1 -> record 2.
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x02, 0x08]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0xFF); // second record
    }

    #[test]
    fn read_record_mode_previous() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]); // EF.DIR
        // P2=0x03: previous mode, P1=2 -> record 1.
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x02, 0x03, 0x08]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x61); // first record
        // P2=0x03: previous mode, P1=1 -> error (no record 0).
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x03, 0x08]);
        assert_eq!(sw(&buf, len), (0x6A, 0x83));
    }

    // -- STATUS --

    #[test]
    fn status_returns_mf_fcp() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62); // FCP template tag
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00]);
    }

    #[test]
    fn status_after_selecting_adf() {
        let mut app = app();
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62);
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0xFF, 0x01]); // ADF root FID
    }

    // -- AUTHENTICATE --

    #[test]
    fn authenticate_umts_success() {
        let mut app = app();
        // Select ADF.USIM first (required for AUTHENTICATE).
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );

        // ETSI TS 135 208 Test Set 1 RAND and build AUTN.
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let mut params = MilenageParams::with_defaults(K, OPC);
        let sequence_number = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let management_field = [0xB9, 0xB9];
        let anonymity_key = params.compute_anonymity_key(&rand_val);
        let auth_mac = params.compute_auth_mac(&rand_val, &sequence_number, &management_field);

        // AUTN = SQN XOR AK || AMF || MAC-A
        let mut auth_token = [0u8; 16];
        for i in 0..6 {
            auth_token[i] = sequence_number[i] ^ anonymity_key[i];
        }
        auth_token[6..8].copy_from_slice(&management_field);
        auth_token[8..16].copy_from_slice(&auth_mac);

        // Build AUTHENTICATE APDU.
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0x88; // INS
        apdu[2] = 0x00; // P1
        apdu[3] = 0x81; // P2 = UMTS context
        apdu[4] = 0x22; // Lc = 34
        apdu[5] = 0x10; // RAND length
        apdu[6..22].copy_from_slice(&rand_val);
        apdu[22] = 0x10; // AUTN length
        apdu[23..39].copy_from_slice(&auth_token);

        let (buf, _len) = send(&mut app, &apdu);
        assert_eq!(buf[0], 0x61); // data available
        let rsp_len = buf[1] as usize;

        // GET RESPONSE.
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = rsp_len as u8;
        let (buf, len) = send(&mut app, &gr);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Response starts with 0xDB.
        assert_eq!(buf[0], 0xDB);

        // Verify against direct Milenage computation.
        let expected = params.authenticate(&rand_val, &auth_token).unwrap();
        // RES at offset 3 (after 0xDB, len, 0x08).
        assert_eq!(&buf[3..11], &expected.response);
        // CK at offset 12 (after 0x10).
        assert_eq!(&buf[12..28], expected.cipher_key.declassify().as_slice());
        // IK at offset 29 (after 0x10).
        assert_eq!(&buf[29..45], expected.integrity_key.declassify().as_slice());
    }

    #[test]
    fn authenticate_mac_failure() {
        let mut app = app();
        // Build AUTHENTICATE with garbage AUTN.
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00;
        apdu[1] = 0x88;
        apdu[3] = 0x81;
        apdu[4] = 0x22;
        apdu[5] = 0x10;
        // RAND = all zeros.
        apdu[22] = 0x10;
        // AUTN = all zeros (invalid MAC).

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x98, 0x62));
    }

    #[test]
    fn authenticate_wrong_data_length() {
        let mut app = app();
        // Only 8 bytes of data instead of 34.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x88, 0x00, 0x81, 0x08,
              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn authenticate_gsm_context_success() {
        let mut app = app();
        // Use ETSI TS 135 208 Test Set 1 RAND.
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];

        // Build AUTHENTICATE APDU: P2=0x00 (GSM context), data = 0x10 || RAND.
        let mut apdu = [0u8; 5 + 17];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0x88; // INS = AUTHENTICATE
        apdu[2] = 0x00; // P1
        apdu[3] = 0x00; // P2 = GSM context
        apdu[4] = 0x11; // Lc = 17
        apdu[5] = 0x10; // RAND length prefix
        apdu[6..22].copy_from_slice(&rand_val);

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x61, 0x0E)); // 14 bytes available

        // GET RESPONSE.
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x0E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Response: 0x04 || SRES(4) || 0x08 || Kc(8).
        assert_eq!(buf[0], 0x04); // SRES length tag
        assert_eq!(buf[5], 0x08); // Kc length tag

        // Verify SRES = f2(RAND)[0..4].
        let params = MilenageParams::with_defaults(K, OPC);
        let response = params.compute_response(&rand_val);
        assert_eq!(&buf[1..5], &response[..4]);

        // Verify Kc = CK1 xor CK2 xor IK1 xor IK2.
        let cipher_key = params.compute_cipher_key(&rand_val);
        let integrity_key = params.compute_integrity_key(&rand_val);
        let ck = cipher_key.declassify();
        let ik = integrity_key.declassify();
        let mut expected_kc = [0u8; 8];
        for i in 0..8 {
            expected_kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
        }
        assert_eq!(&buf[6..14], &expected_kc);
    }

    #[test]
    fn authenticate_gsm_context_wrong_length() {
        let mut app = app();
        // Send only 10 bytes of data instead of 17 (0x10 || RAND).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x88, 0x00, 0x00, 0x0A,
              0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn authenticate_unknown_p2_rejected() {
        let mut app = app();
        // P2=0x42 is not a valid security context.
        let mut apdu = [0u8; 5 + 17];
        apdu[0] = 0x00;
        apdu[1] = 0x88;
        apdu[2] = 0x00;
        apdu[3] = 0x42; // invalid P2
        apdu[4] = 0x11;
        apdu[5] = 0x10;
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x6A, 0x86)); // wrong P1-P2
    }

    // -- AuthenticationResult::encode --

    #[test]
    fn authenticate_result_encode_success() {
        // Use ETSI TS 135 208 Test Set 1 to produce known RES/CK/IK values.
        let mut params = MilenageParams::with_defaults(K, OPC);
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let sequence_number = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let management_field = [0xB9, 0xB9];

        let anonymity_key = params.compute_anonymity_key(&rand_val);
        let mut auth_token = [0u8; 16];
        for i in 0..6 {
            auth_token[i] = sequence_number[i] ^ anonymity_key[i];
        }
        auth_token[6..8].copy_from_slice(&management_field);
        auth_token[8..16].copy_from_slice(&params.compute_auth_mac(&rand_val, &sequence_number, &management_field));

        let output = params.authenticate(&rand_val, &auth_token).unwrap();
        let result = AuthenticationResult::Success {
            response: output.response,
            cipher_key: output.cipher_key,
            integrity_key: output.integrity_key,
        };

        let mut buf = [0u8; 64];
        let n = result.encode(&mut buf);

        // Total length: 2 (tag+len) + 1+8 (RES) + 1+16 (CK) + 1+16 (IK) = 45.
        assert_eq!(n, 45);
        assert_eq!(buf[0], 0xDB); // AUTH_SUCCESS_TAG
        assert_eq!(buf[1], 43);   // inner length = 1+8+1+16+1+16
        assert_eq!(buf[2], 0x08); // RES length prefix
        assert_eq!(&buf[3..11], &output.response);
        assert_eq!(buf[11], 0x10); // CK length prefix
        assert_eq!(&buf[12..28], output.cipher_key.declassify().as_slice());
        assert_eq!(buf[28], 0x10); // IK length prefix
        assert_eq!(&buf[29..45], output.integrity_key.declassify().as_slice());
    }

    #[test]
    fn authenticate_result_encode_sync_failure() {
        let resync_token: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        ];
        let result = AuthenticationResult::SyncFailure { resync_token };

        let mut buf = [0u8; 64];
        let n = result.encode(&mut buf);

        assert_eq!(n, 16); // tag + len + 14 bytes AUTS
        assert_eq!(buf[0], 0xDC); // AUTH_SYNC_FAILURE_TAG
        assert_eq!(buf[1], 0x0E); // 14
        assert_eq!(&buf[2..16], &resync_token);
    }

    #[test]
    fn authenticate_result_encode_mac_failure() {
        let result = AuthenticationResult::MacFailure;
        let mut buf = [0u8; 64];
        let n = result.encode(&mut buf);
        assert_eq!(n, 0); // No data payload, SW only.
    }

    // -- VERIFY PIN --

    #[test]
    fn verify_correct_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn verify_wrong_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn verify_blocked_pin() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    // -- UNBLOCK PIN --

    #[test]
    fn unblock_with_correct_puk() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x2C, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // New PIN "5678" works.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- CHANGE REFERENCE DATA --

    #[test]
    fn change_ref_data_success() {
        let mut app = app();
        // Old PIN "1234" + new PIN "5678".
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Verify with new PIN.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn change_ref_data_wrong_old_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x10,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn change_ref_data_blocked() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn change_ref_data_not_found() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0xFF, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn change_ref_data_wrong_length() {
        let mut app = app();
        // Only 8 bytes instead of 16.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    // -- DISABLE PIN --

    #[test]
    fn disable_pin_success() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // VERIFY should now return "disabled" (69 84).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x84));
    }

    #[test]
    fn disable_pin_wrong_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn disable_pin_blocked() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn disable_pin_not_found() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0xFF, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn disable_pin_wrong_length() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x04,
              0x31, 0x32, 0x33, 0x34],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn disable_pin_already_disabled() {
        let mut app = app();
        // Disable once.
        send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Second disable returns "already disabled" (69 84).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x84));
    }

    // -- ENABLE PIN --

    #[test]
    fn enable_pin_success() {
        let mut app = app();
        // Disable first.
        send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Enable.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // VERIFY should work again.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn enable_pin_wrong_pin() {
        let mut app = app();
        // Disable first.
        send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Enable with wrong PIN.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn enable_pin_blocked() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn enable_pin_not_found() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0xFF, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn enable_pin_wrong_length() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x04,
              0x31, 0x32, 0x33, 0x34],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn enable_pin_already_enabled() {
        let mut app = app();
        // PIN is already enabled by default. Enable again is a no-op success.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- TERMINAL PROFILE --

    #[test]
    fn terminal_profile_accepted() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- FETCH --

    #[test]
    fn fetch_retrieves_proactive_command() {
        let mut app = app();
        let text = b"Hello";
        let cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        app.proactive_state().queue_command(&cmd).unwrap();

        let pending = app.proactive_state().pending_len();
        let mut apdu = [0u8; 5];
        apdu[0] = 0x80;
        apdu[1] = 0x12;
        apdu[4] = pending as u8;

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Data starts with 0xD0 (proactive command envelope).
        assert_eq!(buf[0], 0xD0);
        // Proactive queue is now empty.
        assert!(!app.proactive_state().has_pending());
    }

    #[test]
    fn fetch_with_no_pending() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x80, 0x12, 0x00, 0x00, 0x00]);
        // TS 102 223: FETCH with no pending command -> Command Not Allowed (69 00).
        assert_eq!(sw(&buf, len), (0x69, 0x00));
    }

    // -- TERMINAL RESPONSE --

    #[test]
    fn terminal_response_accepted() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x80, 0x14, 0x00, 0x00, 0x02, 0x00, 0x00],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- ENVELOPE --

    /// Send TERMINAL PROFILE so the app accepts subsequent ENVELOPE commands.
    fn send_terminal_profile(app: &mut UsimApp) {
        let apdu = [
            0x80, 0x10, 0x00, 0x00, // CLA INS P1 P2
            0x04,                     // Lc = 4 bytes
            0xFF, 0xFF, 0xFF, 0xFF,  // profile data (all features)
        ];
        let (buf, len) = send(app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn envelope_zero_length_tlv_rejected() {
        let mut app = app();
        send_terminal_profile(&mut app);
        // Tag D0, length 0x00 -- zero-length TLV is semantically invalid.
        let (buf, len) = send(
            &mut app,
            &[0x80, 0xC2, 0x00, 0x00, 0x02, 0xD0, 0x00],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x80));
    }

    #[test]
    fn envelope_without_terminal_profile_rejected() {
        let mut app = app();
        // No TERMINAL PROFILE sent -- ENVELOPE must be rejected.
        let (buf, len) = send(
            &mut app,
            &[0x80, 0xC2, 0x00, 0x00, 0x06, 0xD1, 0x04, 0x82, 0x02, 0x83, 0x81],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x86));
    }

    #[test]
    fn envelope_rejected_after_reset() {
        let mut app = app();
        send_terminal_profile(&mut app);
        // Simulate card reset: mirrors Sim::apply_reset_effects in
        // simrs-sim/src/lib.rs (pin clearing is at Sim level, not here).
        // NOTE: if apply_reset_effects gains new subsystems, update here.
        app.clear_response_queue();
        app.reset_file_selection();
        app.close_all_channels();
        app.reset_proactive_session();
        app.clear_last_aid_match();
        // ENVELOPE must be rejected again -- no TERMINAL PROFILE in new session.
        let (buf, len) = send(
            &mut app,
            &[0x80, 0xC2, 0x00, 0x00, 0x06, 0xD1, 0x04, 0x82, 0x02, 0x83, 0x81],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x86));
    }

    #[test]
    fn envelope_menu_selection_via_apdu() {
        let mut app = app();
        send_terminal_profile(&mut app);
        // Build a Menu Selection envelope: D3 03 90 01 02
        // (tag D3, length 3, inner: tag 90, length 1, item_id = 2)
        let apdu = [
            0x80, 0xC2, 0x00, 0x00, // CLA INS P1 P2
            0x05,                     // Lc = 5 bytes of data
            0xD3, 0x03,               // Menu Selection tag + length
            0x90, 0x01, 0x02,         // Item Identifier: tag 90, len 1, value 2
        ];
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Verify the event was stored in proactive state.
        let event = app.proactive_state().take_event();
        assert_eq!(
            event,
            Some(simrs_proactive::EnvelopeEvent::MenuSelection { item_id: 0x02 })
        );
    }

    #[test]
    fn envelope_sms_pp_download_accepted() {
        let mut app = app();
        send_terminal_profile(&mut app);
        // SMS-PP Data Download envelope: tag D1, length 4, then some inner TLVs.
        let apdu = [
            0x80, 0xC2, 0x00, 0x00, // CLA INS P1 P2
            0x06,                     // Lc = 6 bytes of data
            0xD1, 0x04,               // SMS-PP Download tag + length
            0x82, 0x02, 0x83, 0x81,  // Device Identities: network -> UICC
        ];
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn envelope_call_control_allowed() {
        let mut app = app();
        send_terminal_profile(&mut app);
        // Call Control envelope: tag D4, length 4, then some inner TLVs.
        let apdu = [
            0x80, 0xC2, 0x00, 0x00, // CLA INS P1 P2
            0x06,                     // Lc = 6 bytes of data
            0xD4, 0x04,               // Call Control tag + length
            0x82, 0x02, 0x83, 0x81,  // Device Identities
        ];
        let (buf, len) = send(&mut app, &apdu);
        // Call Control: allowed without modification returns 90 00.
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn envelope_unknown_tag_rejected() {
        let mut app = app();
        send_terminal_profile(&mut app);
        // Unknown envelope tag (0xE0) -- not recognized by process_envelope(),
        // so the catch-all branch rejects it.
        let apdu = [
            0x80, 0xC2, 0x00, 0x00, // CLA INS P1 P2
            0x04,                     // Lc = 4 bytes of data
            0xE0, 0x02,               // Unknown tag + length
            0x01, 0x02,               // Arbitrary data
        ];
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x6A, 0x80));
    }

    #[test]
    fn terminal_profile_via_apdu() {
        let mut app = app();
        // Send TERMINAL_PROFILE with 4 bytes of profile data.
        let apdu = [
            0x80, 0x10, 0x00, 0x00, // CLA INS P1 P2
            0x04,                     // Lc = 4 bytes
            0xFF, 0x0F, 0x00, 0x80,  // profile data
        ];
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Verify the profile was stored.
        let ps = app.proactive_state();
        assert!(ps.terminal_supports(0, 0));  // byte 0 bit 0 of 0xFF
        assert!(ps.terminal_supports(0, 7));  // byte 0 bit 7 of 0xFF
        assert!(ps.terminal_supports(1, 0));  // byte 1 bit 0 of 0x0F
        assert!(ps.terminal_supports(1, 3));  // byte 1 bit 3 of 0x0F
        assert!(!ps.terminal_supports(1, 4)); // byte 1 bit 4 of 0x0F
        assert!(!ps.terminal_supports(2, 0)); // byte 2 = 0x00
        assert!(ps.terminal_supports(3, 7));  // byte 3 bit 7 of 0x80
        assert!(!ps.terminal_supports(4, 0)); // beyond profile
    }

    // -- Proactive SW override --

    #[test]
    fn proactive_override_90_to_91() {
        let mut app = app();
        let text = b"Hi";
        let cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        app.proactive_state().queue_command(&cmd).unwrap();
        let pending = app.proactive_state().pending_len();

        // VERIFY correct PIN (would normally return 90 00).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Overridden to 91 XX.
        assert_eq!(buf[len - 2], 0x91);
        assert_eq!(buf[len - 1] as usize, pending);
    }

    #[test]
    fn proactive_override_does_not_apply_to_errors() {
        let mut app = app();
        let text = b"Hi";
        let cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        app.proactive_state().queue_command(&cmd).unwrap();

        // SELECT nonexistent FID (error 6A 82 should not be overridden).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xA4, 0x00, 0x04, 0x02, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x82));
    }

    // -- UPDATE BINARY --

    #[test]
    fn update_binary_and_readback() {
        let mut app = app();
        // SELECT EF.ICCID
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY: offset 0, 3 bytes [0xAA, 0xBB, 0xCC]
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // READ BINARY to verify
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..3], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(buf[3], 0x80); // rest unchanged
    }

    #[test]
    fn update_binary_with_offset() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY at offset 5: 2 bytes [0xDD, 0xEE]
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x05, 0x02, 0xDD, 0xEE]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x04, 0x04]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..4], &[0x00, 0xDD, 0xEE, 0x00]);
    }

    #[test]
    fn update_binary_on_record_ef() {
        let mut app = app();
        // SELECT EF.DIR (linear-fixed)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x81)); // incompatible file structure
    }

    #[test]
    fn update_binary_past_end() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // EF.ICCID is 10 bytes. Write 3 at offset 9 exceeds.
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x09, 0x03, 0xAA, 0xBB, 0xCC]);
        assert_eq!(sw(&buf, len), (0x67, 0x00)); // wrong length
    }

    #[test]
    fn update_binary_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x86)); // no current EF
    }

    // -- UPDATE RECORD --

    #[test]
    fn update_record_and_readback() {
        let mut app = app();
        // SELECT ADF.USIM by AID, then EF.FDN
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // UPDATE RECORD 2 (10 bytes): "NewName" + padding
        let mut apdu = [0xFFu8; 5 + 10];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0xDC; // INS: UPDATE RECORD
        apdu[2] = 0x02; // P1: record 2
        apdu[3] = 0x04; // P2: absolute
        apdu[4] = 0x0A; // Lc: 10 bytes
        apdu[5] = 0x4E; // 'N'
        apdu[6] = 0x65; // 'e'
        apdu[7] = 0x77; // 'w'
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // READ RECORD 2
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x02, 0x04, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x4E); // 'N'
        assert_eq!(buf[1], 0x65); // 'e'
        assert_eq!(buf[2], 0x77); // 'w'
    }

    #[test]
    fn update_record_on_transparent() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xDC, 0x01, 0x04, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x81)); // incompatible file structure
    }

    #[test]
    fn update_record_wrong_size() {
        let mut app = app();
        // SELECT ADF.USIM, then EF.FDN (record_size=10)
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // Try writing 5 bytes (not 10)
        let (buf, len) = send(&mut app,
            &[0x00, 0xDC, 0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(sw(&buf, len), (0x67, 0x00)); // wrong length
    }

    #[test]
    fn update_record_out_of_range() {
        let mut app = app();
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // EF.FDN has 2 records. Try record 3.
        let mut apdu = [0xFFu8; 5 + 10];
        apdu[0] = 0x00;
        apdu[1] = 0xDC;
        apdu[2] = 0x03; // record 3
        apdu[3] = 0x04;
        apdu[4] = 0x0A; // 10 bytes
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x6A, 0x83)); // record not found
    }

    #[test]
    fn update_record_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0xDC, 0x01, 0x04, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x86)); // no current EF
    }

    #[test]
    fn update_record_mode_next() {
        let mut app = app();
        // SELECT ADF.USIM, then EF.FDN (linear-fixed, record_size=10, 2 records).
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // UPDATE RECORD with P2=0x02 (next), P1=1 -> writes record 2.
        let mut apdu = [0x58u8; 5 + 10];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0xDC; // INS = UPDATE RECORD
        apdu[2] = 0x01; // P1 = 1
        apdu[3] = 0x02; // P2 = next mode
        apdu[4] = 0x0A; // Lc = 10
        // data bytes 5..15 are 0x58 (from initialization)
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Verify record 2 was written (absolute read).
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x02, 0x04, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x58);
        // Verify record 1 was NOT changed (still 'Alice...').
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x41); // 'A'
    }

    // -- INCREASE --

    #[test]
    fn increase_on_cyclic_ef() {
        let mut app = app();
        // SELECT ADF.USIM, then EF.ACC (cyclic, FID 0x6F78)
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x78]);
        // INCREASE by [0x00, 0x00, 0x00, 0x05]: record 1 = 0x000100 + 5 = 0x000105
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 4 + 2); // 4-byte record + 2-byte SW
        assert_eq!(&buf[..4], &[0x00, 0x00, 0x01, 0x05]);
    }

    #[test]
    fn increase_on_transparent_fails() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x81)); // incompatible file structure
    }

    #[test]
    fn increase_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x86)); // no current EF
    }

    #[test]
    fn increase_to_max_then_overflow() {
        let mut app = app();
        // SELECT ADF.USIM, then EF.ACC (cyclic, record_size=4, 3 records).
        // Record 1 = [0x00, 0x00, 0x01, 0x00].
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x78]);
        // Increase to max: 0xFFFFFFFF - 0x00000100 = 0xFFFFFEFF.
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFE, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        // Now any further increase should overflow: SW 98 50.
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(sw(&buf, len), (0x98, 0x50));
    }

    // -- Unknown INS --

    #[test]
    fn unknown_ins_returns_6d00() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xFF, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x6D, 0x00));
    }

    // -- Snapshot --

    #[test]
    fn snapshot_size_correct() {
        // Snapshot = SelectionCtx + FsData<FS_CAP, FS_MAX_EFS> + PinManager<5> + Milenage
        //          + ProactiveState + ResponseQueue<64> + terminal_cap(17)
        //          + DeactivationTracker + channels(4*9=36) + last_aid_match(1)
        let expected =
            simrs_fs::SelectionCtx::SNAPSHOT_SIZE
            + simrs_fs::FsData::<{ super::FS_CAP }, { super::FS_MAX_EFS }>::SNAPSHOT_SIZE
            + simrs_pin::PinManager::<5>::SNAPSHOT_SIZE
            + <simrs_milenage::MilenageParams as simrs_milenage::AuthenticationAlgorithm>::SNAPSHOT_SIZE
            + simrs_proactive::ProactiveState::SNAPSHOT_SIZE
            + simrs_iso7816::ResponseQueue::<64>::SNAPSHOT_SIZE
            + 17 // terminal_capability (16) + len (1)
            + simrs_fs::DeactivationTracker::SNAPSHOT_SIZE
            + 4 * (simrs_fs::SelectionCtx::SNAPSHOT_SIZE + 1) // channels
            + 1; // last_aid_match
        assert_eq!(UsimApp::<MilenageParams>::SNAPSHOT_SIZE, expected);
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let mut src = app();
        // Select ADF.USIM by AID, then EF.IMSI.
        send(&mut src, &[0x00, 0xA4, 0x04, 0x04, 0x07,
                         0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut src, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
        // Degrade PIN retries.
        send(&mut src, &[0x00, 0x20, 0x00, 0x01, 0x08,
                         0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Save.
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let written = src.save_state(&mut snap);
        assert_eq!(written, UsimApp::<MilenageParams>::SNAPSHOT_SIZE);

        // Restore into fresh app (same adfs).
        let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));

        // PIN retries = 2 (wrong VERIFY degraded it before snapshot).
        let (buf, len) = send(&mut dst, &[0x00, 0x20, 0x00, 0x01, 0x00]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2));

        // Re-verify PIN1 so we can read files (PIN gate enforced).
        send(&mut dst,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Read EF.IMSI (fs state restored).
        let (buf, len) = send(&mut dst, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08);
    }

    #[test]
    fn snapshot_preserves_milenage_auth() {
        let src = app();
        // Build valid AUTN for ETSI test set 1.
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let params = MilenageParams::with_defaults(K, OPC);
        let sequence_number = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let management_field = [0xB9, 0xB9];
        let anonymity_key = params.compute_anonymity_key(&rand_val);
        let auth_mac = params.compute_auth_mac(&rand_val, &sequence_number, &management_field);
        let mut auth_token = [0u8; 16];
        for i in 0..6 {
            auth_token[i] = sequence_number[i] ^ anonymity_key[i];
        }
        auth_token[6..8].copy_from_slice(&management_field);
        auth_token[8..16].copy_from_slice(&auth_mac);

        // Save and restore.
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let _ = src.save_state(&mut snap);
        let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));

        // AUTHENTICATE should succeed with restored K/OPc.
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00;
        apdu[1] = 0x88;
        apdu[3] = 0x81;
        apdu[4] = 0x22;
        apdu[5] = 0x10;
        apdu[6..22].copy_from_slice(&rand_val);
        apdu[22] = 0x10;
        apdu[23..39].copy_from_slice(&auth_token);

        let (buf, _) = send(&mut dst, &apdu);
        assert_eq!(buf[0], 0x61); // data available
    }

    #[test]
    fn snapshot_preserves_proactive_state() {
        let mut src = app();
        let text = b"Snap";
        let pro_cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        src.proactive_state().queue_command(&pro_cmd).unwrap();
        let pending_before = src.proactive_state().pending_len();
        assert!(pending_before > 0);

        // Save and restore.
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let _ = src.save_state(&mut snap);
        let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));

        // Proactive command is still pending after restore.
        assert!(dst.proactive_state().has_pending());
        assert_eq!(dst.proactive_state().pending_len(), pending_before);
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let src = app();
        let mut small = [0u8; 10];
        assert_eq!(src.save_state(&mut small), 0);

        let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(!dst.restore_state(&small));
    }

    #[test]
    fn snapshot_restore_oversized_rsp_queue_len_returns_false() {
        // rsp_queue_len is the last byte of the ResponseQueue section.
        // Offset = SelectionCtx + FsData + PinManager + Milenage
        //        + ProactiveState + ResponseQueue data(64).
        const RSP_QUEUE_LEN_OFFSET: usize =
            simrs_fs::SelectionCtx::SNAPSHOT_SIZE
            + simrs_fs::FsData::<{ super::FS_CAP }, { super::FS_MAX_EFS }>::SNAPSHOT_SIZE
            + simrs_pin::PinManager::<5>::SNAPSHOT_SIZE
            + <simrs_milenage::MilenageParams as simrs_milenage::AuthenticationAlgorithm>::SNAPSHOT_SIZE
            + simrs_proactive::ProactiveState::SNAPSHOT_SIZE
            + 64; // ResponseQueue data bytes (not including len)
        let src = app();
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let _ = src.save_state(&mut snap);
        snap[RSP_QUEUE_LEN_OFFSET] = u8::MAX;
        let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(!dst.restore_state(&snap));
    }

    // -- Navigation round-trip --

    #[test]
    fn navigate_mf_adf_ef_read_mf_roundtrip() {
        let mut app = app();
        // Select MF.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        // Select ADF.USIM by AID.
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        // Select EF.IMSI by FID.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
        // READ BINARY.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08); // IMSI first byte
        assert_eq!(len, 9 + 2);
        // Select MF.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        // STATUS returns MF.
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62);
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00]);
    }

    // -- Test helper: find a TLV tag in a byte sequence --

    fn find_tlv_tag(data: &[u8], target_tag: u8) -> Option<&[u8]> {
        let mut pos = 0;
        while pos < data.len() {
            let tag = data[pos];
            pos += 1;
            if pos >= data.len() {
                break;
            }
            let len_byte = data[pos];
            pos += 1;
            let (value_len, extra) = if usize::from(len_byte) <= simrs_bertlv::BER_SHORT_FORM_MAX {
                (len_byte as usize, 0)
            } else if len_byte == simrs_bertlv::BER_LONG_FORM_1 && pos < data.len() {
                (data[pos] as usize, 1)
            } else {
                break;
            };
            pos += extra;
            if pos + value_len > data.len() {
                break;
            }
            if tag == target_tag {
                return Some(&data[pos..pos + value_len]);
            }
            pos += value_len;
        }
        None
    }

    // -- PIN gate tests --

    #[test]
    fn read_binary_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        // Select EF.ICCID under MF.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // READ BINARY without PIN1 verification.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x69, 0x82)); // security status not satisfied
    }

    #[test]
    fn read_binary_with_pin1_succeeds() {
        let mut app = app_with_pin1_enabled();
        // Verify PIN1.
        send(&mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Select EF.ICCID.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // READ BINARY should now succeed.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn update_binary_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY without PIN1.
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn read_record_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]); // EF.DIR
        // READ RECORD without PIN1.
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn increase_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        // Select ADF USIM, then EF.ACC (cyclic).
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x78]);
        // INCREASE without PIN1.
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn authenticate_without_pin1_succeeds() {
        // AUTHENTICATE has its own security context per ETSI TS 102 221
        // and does not require PIN1 verification.
        let mut app = app_with_pin1_enabled();
        // Build AUTHENTICATE APDU (P2=0x81 UMTS context).
        let mut apdu = [0u8; 4 + 1 + 34];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0x88; // INS
        apdu[2] = 0x00; // P1
        apdu[3] = 0x81; // P2
        apdu[4] = 0x22; // Lc = 34
        apdu[5] = 0x10; // RAND len prefix
        apdu[22] = 0x10; // AUTN len prefix
        let (buf, len) = send(&mut app, &apdu);
        // Should get MAC failure (98 62), not security error (69 82).
        assert_eq!(sw(&buf, len), (0x98, 0x62));
    }

    // -- SELECT by path tests --

    #[test]
    fn select_p1_08_path_from_mf() {
        let mut app = app();
        // SELECT by path from MF: EF.ICCID (2FE2).
        // P1=0x08, P2=0x04 (FCP requested), data = path bytes.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xA4, 0x08, 0x04, 0x02, 0x2F, 0xE2],
        );
        // Should return 61 XX (FCP available via GET RESPONSE).
        assert_eq!(buf[0], 0x61);
        assert_eq!(len, 2);
    }

    #[test]
    fn select_p1_09_path_from_current() {
        let mut app = app();
        // First select ADF USIM by AID to set current DF.
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        // SELECT by path from current DF: EF.IMSI (6F07).
        // P1=0x09, P2=0x04 (FCP requested), data = path bytes.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xA4, 0x09, 0x04, 0x02, 0x6F, 0x07],
        );
        assert_eq!(buf[0], 0x61);
        assert_eq!(len, 2);
    }

    // -- SFI-based READ/UPDATE BINARY tests --

    #[test]
    fn read_binary_by_sfi() {
        let mut app = app();
        // EF_ICCID has SFI=2 and is under MF. No need to SELECT the EF.
        // READ BINARY with SFI: P1 = 0x80 | SFI, P2 = offset.
        // P1 = 0x80 | 0x02 = 0x82, P2 = 0x00, Le = 0x0A.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x82, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 10 + 2); // 10 data bytes + SW
        assert_eq!(
            &buf[..10],
            &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]
        );
    }

    #[test]
    fn update_binary_by_sfi() {
        let mut app = app();
        // UPDATE BINARY via SFI=2 (EF_ICCID): P1 = 0x80 | 0x02 = 0x82,
        // P2 = 0x00 (offset), data = 2 bytes to write.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xD6, 0x82, 0x00, 0x02, 0xAA, 0xBB],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Verify the write by reading back via SFI.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x82, 0x00, 0x02]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..2], &[0xAA, 0xBB]);
    }

    #[test]
    fn read_binary_sfi_not_found() {
        let mut app = app();
        // SFI=31 does not exist under MF.
        // P1 = 0x80 | 0x1F = 0x9F, P2 = 0x00, Le = 0x01.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x9F, 0x00, 0x01]);
        // Should return 6A 82 (file not found).
        assert_eq!(sw(&buf, len), (0x6A, 0x82));
    }

    // -- STATUS P1/P2 variant tests (3C) --

    #[test]
    fn status_p1_01() {
        // P1=0x01 should behave the same as P1=0x00 (current DF info).
        let mut app = app();
        // STATUS with P1=0x01, P2=0x00 (FCP).
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x01, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62); // FCP template tag
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00]); // MF FID
    }

    #[test]
    fn status_p1_02_no_data() {
        // P1=0x02 should return just SW 90 00, no data.
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x02, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 2); // just SW, no data
    }

    #[test]
    fn status_invalid_p1() {
        // Invalid P1 (e.g. 0x05) should return 6A 86 (wrong P1-P2).
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x05, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x6A, 0x86));
    }

    #[test]
    fn status_default_p2() {
        // P2=0x01 with an ADF selected should return AID as TLV 0x84.
        let mut app = app();
        // Select ADF USIM by AID.
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        // STATUS P1=0x00, P2=0x01 (DF name / AID).
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x01, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Response should be TLV: tag 0x84, len 0x07, AID bytes.
        assert_eq!(buf[0], 0x84); // DF name tag
        assert_eq!(buf[1], 0x07); // AID length
        assert_eq!(&buf[2..9], &USIM_AID);
    }

    // -- SELECT P2 variant tests (3F) --

    #[test]
    fn select_p2_00_returns_fcp() {
        // P2=0x00 (FCI) should be treated same as P2=0x04, returning FCP.
        let mut app = app();
        let (buf, _len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        assert_eq!(buf[0], 0x61); // data available via GET RESPONSE
        let fcp_len = buf[1] as usize;
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = fcp_len as u8;
        let (buf, len) = send(&mut app, &gr);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62); // FCP template
    }

    #[test]
    fn select_p2_0c_no_data() {
        // P2=0x0C should perform the selection but return just SW 90 00.
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 2); // just SW, no data
    }

    #[test]
    fn select_p2_invalid_rejected() {
        // Invalid P2 (e.g. 0x08) should return 6A 86 (wrong P1-P2).
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x08, 0x02, 0x3F, 0x00]);
        assert_eq!(sw(&buf, len), (0x6A, 0x86));
    }

    // ===================================================================
    // Access control test matrix
    //
    // Systematically verifies that every command subject to PIN1 gating
    // is rejected (SW 69 82) when PIN1 has not been verified, and
    // succeeds (SW != 69 82) when PIN1 has been verified.
    //
    // Also verifies that commands which are NOT PIN-gated never return
    // 69 82, even when PIN1 has not been verified.
    // ===================================================================

    mod access_control {
        use super::*;

        /// Extract the two status-word bytes from a response buffer.
        fn sw_from_response(buf: &[u8], len: usize) -> (u8, u8) {
            (buf[len - 2], buf[len - 1])
        }

        /// Select EF.ICCID (transparent, FID 0x2FE2) under MF.
        fn select_ef_iccid(app: &mut UsimApp) {
            send(app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        }

        /// Select EF.DIR (linear-fixed, FID 0x2F00) under MF.
        fn select_ef_dir(app: &mut UsimApp) {
            send(app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]);
        }

        /// Select ADF.USIM by AID, then EF.ACC (cyclic, FID 0x6F78).
        fn select_ef_acc(app: &mut UsimApp) {
            send(app,
                &[0x00, 0xA4, 0x04, 0x04, 0x07,
                  0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
            send(app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x78]);
        }

        /// Select ADF.USIM by AID, then EF.FDN (linear-fixed, FID 0x6F3B).
        fn select_ef_fdn(app: &mut UsimApp) {
            send(app,
                &[0x00, 0xA4, 0x04, 0x04, 0x07,
                  0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
            send(app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        }

        /// Verify PIN1 with the correct value ("1234" padded).
        fn verify_pin1(app: &mut UsimApp) {
            send(app,
                &[0x00, 0x20, 0x00, 0x01, 0x08,
                  0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        }

        const SECURITY_NOT_SATISFIED: (u8, u8) = (0x69, 0x82);

        // ---------------------------------------------------------------
        // PIN1-GATED operations: must fail (69 82) without PIN1
        // ---------------------------------------------------------------

        // -- READ BINARY (INS 0xB0) --

        #[test]
        fn read_binary_rejected_without_pin1() {
            let mut app = app_with_pin1_enabled();
            select_ef_iccid(&mut app);
            let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
            assert_eq!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "READ BINARY must be rejected when PIN1 is not verified"
            );
        }

        #[test]
        fn read_binary_succeeds_with_pin1() {
            let mut app = app_with_pin1_enabled();
            verify_pin1(&mut app);
            select_ef_iccid(&mut app);
            let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
            assert_ne!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "READ BINARY must succeed when PIN1 is verified"
            );
        }

        // -- UPDATE BINARY (INS 0xD6) --

        #[test]
        fn update_binary_rejected_without_pin1() {
            let mut app = app_with_pin1_enabled();
            select_ef_iccid(&mut app);
            let (buf, len) = send(&mut app,
                &[0x00, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
            assert_eq!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "UPDATE BINARY must be rejected when PIN1 is not verified"
            );
        }

        #[test]
        fn update_binary_succeeds_with_pin1() {
            let mut app = app_with_pin1_enabled();
            verify_pin1(&mut app);
            select_ef_iccid(&mut app);
            let (buf, len) = send(&mut app,
                &[0x00, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
            assert_ne!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "UPDATE BINARY must succeed when PIN1 is verified"
            );
        }

        // -- READ RECORD (INS 0xB2) --

        #[test]
        fn read_record_rejected_without_pin1() {
            let mut app = app_with_pin1_enabled();
            select_ef_dir(&mut app);
            // P1=1, P2=0x04 (absolute), Le=0x08.
            let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x08]);
            assert_eq!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "READ RECORD must be rejected when PIN1 is not verified"
            );
        }

        #[test]
        fn read_record_succeeds_with_pin1() {
            let mut app = app_with_pin1_enabled();
            verify_pin1(&mut app);
            select_ef_dir(&mut app);
            let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x08]);
            assert_ne!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "READ RECORD must succeed when PIN1 is verified"
            );
        }

        // -- UPDATE RECORD (INS 0xDC) --

        #[test]
        fn update_record_rejected_without_pin1() {
            let mut app = app_with_pin1_enabled();
            select_ef_fdn(&mut app);
            // Write 10-byte record (matching EF.FDN record_size).
            let mut apdu = [0xFFu8; 5 + 10];
            apdu[0] = 0x00; // CLA
            apdu[1] = 0xDC; // INS = UPDATE RECORD
            apdu[2] = 0x01; // P1 = record 1
            apdu[3] = 0x04; // P2 = absolute
            apdu[4] = 0x0A; // Lc = 10
            let (buf, len) = send(&mut app, &apdu);
            assert_eq!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "UPDATE RECORD must be rejected when PIN1 is not verified"
            );
        }

        #[test]
        fn update_record_succeeds_with_pin1() {
            let mut app = app_with_pin1_enabled();
            verify_pin1(&mut app);
            select_ef_fdn(&mut app);
            let mut apdu = [0xFFu8; 5 + 10];
            apdu[0] = 0x00;
            apdu[1] = 0xDC;
            apdu[2] = 0x01;
            apdu[3] = 0x04;
            apdu[4] = 0x0A;
            let (buf, len) = send(&mut app, &apdu);
            assert_ne!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "UPDATE RECORD must succeed when PIN1 is verified"
            );
        }

        // -- INCREASE (INS 0x32) --

        #[test]
        fn increase_rejected_without_pin1() {
            let mut app = app_with_pin1_enabled();
            select_ef_acc(&mut app);
            // INCREASE by 1 (4-byte value for 4-byte record).
            let (buf, len) = send(&mut app,
                &[0x00, 0x32, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
            assert_eq!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "INCREASE must be rejected when PIN1 is not verified"
            );
        }

        #[test]
        fn increase_succeeds_with_pin1() {
            let mut app = app_with_pin1_enabled();
            verify_pin1(&mut app);
            select_ef_acc(&mut app);
            let (buf, len) = send(&mut app,
                &[0x00, 0x32, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
            assert_ne!(
                sw_from_response(&buf, len), SECURITY_NOT_SATISFIED,
                "INCREASE must succeed when PIN1 is verified"
            );
        }

        // ---------------------------------------------------------------
        // NON-PIN-GATED operations: must NOT return 69 82 even without
        // PIN1 verification
        // ---------------------------------------------------------------

        // -- SELECT (INS 0xA4) --

        #[test]
        fn select_not_gated_by_pin1() {
            let mut app = app_with_pin1_enabled();
            // SELECT MF by FID.
            let (buf, len) = send(&mut app,
                &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
            let status = sw_from_response(&buf, len);
            assert_ne!(
                status, SECURITY_NOT_SATISFIED,
                "SELECT must not be gated by PIN1"
            );
            // Expect 61 xx (data available) or 90 00.
            assert!(
                status.0 == 0x61 || status.0 == 0x90,
                "SELECT should return 61 xx or 90 00, got {:02X} {:02X}",
                status.0, status.1
            );
        }

        // -- AUTHENTICATE (INS 0x88) --

        #[test]
        fn authenticate_not_gated_by_pin1() {
            let mut app = app_with_pin1_enabled();
            // Build AUTHENTICATE APDU with P2=0x81 (UMTS context),
            // zeroed RAND + AUTN (will cause MAC failure, not security error).
            let mut apdu = [0u8; 5 + 34];
            apdu[0] = 0x00; // CLA
            apdu[1] = 0x88; // INS = AUTHENTICATE
            apdu[2] = 0x00; // P1
            apdu[3] = 0x81; // P2 = UMTS context
            apdu[4] = 0x22; // Lc = 34
            apdu[5] = 0x10; // RAND length prefix
            apdu[22] = 0x10; // AUTN length prefix
            let (buf, len) = send(&mut app, &apdu);
            let status = sw_from_response(&buf, len);
            assert_ne!(
                status, SECURITY_NOT_SATISFIED,
                "AUTHENTICATE must not be gated by PIN1"
            );
            // Expect 98 62 (MAC failure) since RAND/AUTN are zeroed.
            assert_eq!(
                status, (0x98, 0x62),
                "AUTHENTICATE with garbage AUTN should return MAC failure (98 62)"
            );
        }

        // -- STATUS (INS 0xF2) --

        #[test]
        fn status_not_gated_by_pin1() {
            let mut app = app_with_pin1_enabled();
            let (buf, len) = send(&mut app,
                &[0x00, 0xF2, 0x00, 0x00, 0x00]);
            let status = sw_from_response(&buf, len);
            assert_ne!(
                status, SECURITY_NOT_SATISFIED,
                "STATUS must not be gated by PIN1"
            );
            // Expect 90 00 (data inline) or 61 xx.
            assert!(
                status.0 == 0x90 || status.0 == 0x61,
                "STATUS should return 90 00 or 61 xx, got {:02X} {:02X}",
                status.0, status.1
            );
        }

        // -- GET RESPONSE (INS 0xC0) --

        #[test]
        fn get_response_not_gated_by_pin1() {
            let mut app = app_with_pin1_enabled();
            // Issue a SELECT first to queue FCP data, then GET RESPONSE.
            send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
            let (buf, len) = send(&mut app,
                &[0x00, 0xC0, 0x00, 0x00, 0x20]);
            let status = sw_from_response(&buf, len);
            assert_ne!(
                status, SECURITY_NOT_SATISFIED,
                "GET RESPONSE must not be gated by PIN1"
            );
        }

        // -- VERIFY (INS 0x20) --

        #[test]
        fn verify_not_gated_by_pin1() {
            let mut app = app_with_pin1_enabled();
            // Query PIN1 retry count (empty data).
            let (buf, len) = send(&mut app,
                &[0x00, 0x20, 0x00, 0x01, 0x00]);
            let status = sw_from_response(&buf, len);
            assert_ne!(
                status, SECURITY_NOT_SATISFIED,
                "VERIFY must not be gated by PIN1"
            );
        }

        // -- TERMINAL PROFILE (INS 0x10, CLA 0x80) --

        #[test]
        fn terminal_profile_not_gated_by_pin1() {
            let mut app = app_with_pin1_enabled();
            let (buf, len) = send(&mut app,
                &[0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
            let status = sw_from_response(&buf, len);
            assert_ne!(
                status, SECURITY_NOT_SATISFIED,
                "TERMINAL PROFILE must not be gated by PIN1"
            );
            assert!(
                status.0 == 0x90 || status.0 == 0x91,
                "TERMINAL PROFILE should return 90 00 or 91 xx, got {:02X} {:02X}",
                status.0, status.1
            );
        }

        // -- ENVELOPE (INS 0xC2, CLA 0x80) --

        #[test]
        fn envelope_not_gated_by_pin1() {
            let mut app = app_with_pin1_enabled();
            // Satisfy TERMINAL PROFILE precondition (also must not require PIN1).
            let (pbuf, plen) = send(&mut app,
                &[0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
            assert_ne!(
                sw_from_response(&pbuf, plen), SECURITY_NOT_SATISFIED,
                "TERMINAL PROFILE must not be gated by PIN1"
            );
            // ENVELOPE: any non-PIN1-gating error (e.g. 6A 80 for zero-length
            // TLV) is acceptable -- we only care that 69 82 is NOT returned.
            let (buf, len) = send(&mut app,
                &[0x80, 0xC2, 0x00, 0x00, 0x02, 0xD0, 0x00]);
            let status = sw_from_response(&buf, len);
            assert_ne!(
                status, SECURITY_NOT_SATISFIED,
                "ENVELOPE must not be gated by PIN1"
            );
        }
    }

    // ===================================================================
    // Proactive session lifecycle enforcement (8E)
    // ===================================================================

    #[test]
    fn fetch_without_pending_returns_warning() {
        let mut app = app();
        // FETCH (CLA=0x80, INS=0x12) with no queued proactive command.
        let (buf, len) = send(&mut app, &[0x80, 0x12, 0x00, 0x00, 0x00]);
        // Should return an error (69 00 = command not allowed).
        let (sw1, _sw2) = sw(&buf, len);
        assert_eq!(sw1, 0x69, "FETCH with no pending should return 69 XX");
    }

    #[test]
    fn terminal_response_without_session_rejected() {
        let mut app = app();
        // Craft a well-formed TERMINAL RESPONSE with Command Details (tag 0x81).
        // 81 03 [cmd_number=01] [cmd_type=21] [qualifier=00]
        // 83 01 [result=00]
        let data = [
            0x81, 0x03, 0x01, 0x21, 0x00, // Command Details
            0x83, 0x01, 0x00,              // Result: success
        ];
        let mut apdu = [0u8; 4 + 1 + 8];
        apdu[0] = 0x80; // CLA
        apdu[1] = 0x14; // INS TERMINAL RESPONSE
        apdu[2] = 0x00; // P1
        apdu[3] = 0x00; // P2
        apdu[4] = data.len() as u8; // Lc
        apdu[5..13].copy_from_slice(&data);

        let (buf, len) = send(&mut app, &apdu);
        // Should be rejected: 69 86 (command not allowed, no session).
        assert_eq!(sw(&buf, len), (0x69, 0x86),
            "TERMINAL RESPONSE with Command Details but no session should return 69 86");
    }

    #[test]
    fn normal_proactive_session_lifecycle() {
        use simrs_proactive::{ProactiveCommand, TextCoding};

        let mut app = app();
        // Queue a DISPLAY TEXT proactive command.
        app.proactive_state().queue_command(&ProactiveCommand::DisplayText {
            text: b"Test",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        }).unwrap();

        // After any APDU returning 90 00, the SW should be overridden to 91 XX.
        let (buf, len) = send(&mut app, &[0x80, 0x10, 0x00, 0x00]); // TERMINAL PROFILE
        let (sw1, sw2_fetch_len) = sw(&buf, len);
        assert_eq!(sw1, 0x91, "SW should be overridden to 91 XX when proactive pending");
        assert!(sw2_fetch_len > 0, "fetch length must be >0");

        // Now FETCH the command.
        let fetch_le = sw2_fetch_len;
        let mut fetch_apdu = [0x80, 0x12, 0x00, 0x00, 0x00];
        fetch_apdu[4] = fetch_le;
        let (buf, len) = send(&mut app, &fetch_apdu);
        let (sw1, sw2) = sw(&buf, len);
        assert_eq!((sw1, sw2), (0x90, 0x00), "FETCH should succeed");
        // Session should be active after FETCH.
        assert!(app.is_proactive_session_active(),
            "proactive session should be active after FETCH");

        // Send TERMINAL RESPONSE with valid Command Details.
        let tr_data = [
            0x81, 0x03, 0x01, 0x21, 0x00, // Command Details
            0x83, 0x01, 0x00,              // Result: success
        ];
        let mut tr_apdu = [0u8; 4 + 1 + 8];
        tr_apdu[0] = 0x80;
        tr_apdu[1] = 0x14;
        tr_apdu[2] = 0x00;
        tr_apdu[3] = 0x00;
        tr_apdu[4] = tr_data.len() as u8;
        tr_apdu[5..13].copy_from_slice(&tr_data);
        let (buf, len) = send(&mut app, &tr_apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00), "TERMINAL RESPONSE should succeed");

        // Session should be inactive after TERMINAL RESPONSE.
        assert!(!app.is_proactive_session_active(),
            "proactive session should be inactive after TERMINAL RESPONSE");
    }

    #[test]
    fn fetch_after_terminal_response_returns_warning() {
        use simrs_proactive::{ProactiveCommand, TextCoding};

        let mut app = app();
        // Queue and execute a full proactive session.
        app.proactive_state().queue_command(&ProactiveCommand::DisplayText {
            text: b"Test",
            coding: TextCoding::Gsm8Bit,
            high_priority: false,
        }).unwrap();

        // Send a TERMINAL PROFILE to trigger 91 XX override.
        let (buf, len) = send(&mut app, &[0x80, 0x10, 0x00, 0x00]);
        let fetch_le = buf[len - 1];

        // FETCH the command.
        let mut fetch_apdu = [0x80, 0x12, 0x00, 0x00, 0x00];
        fetch_apdu[4] = fetch_le;
        send(&mut app, &fetch_apdu);

        // Send TERMINAL RESPONSE.
        let tr_data = [
            0x81, 0x03, 0x01, 0x21, 0x00,
            0x83, 0x01, 0x00,
        ];
        let mut tr_apdu = [0u8; 4 + 1 + 8];
        tr_apdu[0] = 0x80;
        tr_apdu[1] = 0x14;
        tr_apdu[2] = 0x00;
        tr_apdu[3] = 0x00;
        tr_apdu[4] = tr_data.len() as u8;
        tr_apdu[5..13].copy_from_slice(&tr_data);
        send(&mut app, &tr_apdu);

        // Now FETCH again -- should fail with 69 00 (no pending command).
        let (buf, len) = send(&mut app, &[0x80, 0x12, 0x00, 0x00, 0x00]);
        let (sw1, _sw2) = sw(&buf, len);
        assert_eq!(sw1, 0x69, "FETCH after TERMINAL RESPONSE with no pending should return 69 XX");
    }

    // ===================================================================
    // 7A: SEARCH RECORD (INS 0xA2)
    // ===================================================================

    #[test]
    fn search_record_finds_match() {
        let mut app = app();
        // Select ADF.USIM, then EF.FDN (linear-fixed, 10-byte records).
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // SEARCH RECORD with pattern "Ali" (matches record 1: "Alice...").
        let (buf, len) = send(&mut app,
            &[0x00, 0xA2, 0x00, 0x04, 0x03, 0x41, 0x6C, 0x69]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Should return at least one record number.
        assert!(len > 2, "Expected data in response, got only SW");
        assert_eq!(buf[0], 0x01); // Record 1 matches "Ali"
    }

    #[test]
    fn search_record_no_match() {
        let mut app = app();
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // SEARCH RECORD with pattern "XYZ" (no match).
        let (buf, len) = send(&mut app,
            &[0x00, 0xA2, 0x00, 0x04, 0x03, 0x58, 0x59, 0x5A]);
        // 6A 83 = record not found.
        assert_eq!(sw(&buf, len), (0x6A, 0x83));
    }

    #[test]
    fn search_record_empty_pattern() {
        let mut app = app();
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // SEARCH RECORD with empty pattern (Lc=0 means all records match).
        let (buf, len) = send(&mut app, &[0x00, 0xA2, 0x00, 0x04, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Both records should match an empty pattern.
        assert!(len >= 4, "Expected at least 2 record numbers + SW");
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x02);
    }

    #[test]
    fn search_record_requires_pin1() {
        let mut app = app_with_pin1_enabled();
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // SEARCH RECORD without PIN1 verification.
        let (buf, len) = send(&mut app,
            &[0x00, 0xA2, 0x00, 0x04, 0x03, 0x41, 0x6C, 0x69]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    // ===================================================================
    // 7B: TERMINAL CAPABILITY (INS 0xAA)
    // ===================================================================

    #[test]
    fn terminal_capability_stores_data() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0xAA, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn terminal_capability_overwrite() {
        let mut app = app();
        send(&mut app,
            &[0x00, 0xAA, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xAA, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Verify snapshot roundtrip preserves the new data.
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let _ = app.save_state(&mut snap);
        let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));
    }

    #[test]
    fn terminal_capability_no_pin_required() {
        let mut app = app_with_pin1_enabled();
        let (buf, len) = send(&mut app,
            &[0x00, 0xAA, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn reset_proactive_session_clears_terminal_capability() {
        let mut app = app();

        // Set terminal capability via APDU.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xAA, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Verify it was stored.
        assert_eq!(app.terminal_capability_len, 4);
        assert_eq!(&app.terminal_capability[..4], &[0x01, 0x02, 0x03, 0x04]);

        // Reset proactive session -- should clear terminal capability.
        app.reset_proactive_session();

        assert_eq!(app.terminal_capability_len, 0);
        assert_eq!(app.terminal_capability, [0u8; 16]);
    }

    // ===================================================================
    // 7C: File Lifecycle (ACTIVATE/DEACTIVATE FILE)
    // ===================================================================

    #[test]
    fn deactivate_file_success() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0x04, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn activate_deactivated_file() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        send(&mut app, &[0x00, 0x04, 0x00, 0x00]);
        let (buf, len) = send(&mut app, &[0x00, 0x44, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn read_deactivated_file_rejected() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        send(&mut app, &[0x00, 0x04, 0x00, 0x00]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x69, 0x86));
    }

    #[test]
    fn select_deactivated_file_warns() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        send(&mut app, &[0x00, 0x04, 0x00, 0x00]);
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        assert_eq!(sw(&buf, len), (0x62, 0x83));
    }

    #[test]
    fn activate_already_active_ok() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0x44, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn deactivate_requires_current_ef() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0x04, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x69, 0x86));
    }

    // ===================================================================
    // 7E: MANAGE CHANNEL (INS 0x70)
    // ===================================================================

    #[test]
    fn manage_channel_open() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert!(len > 2, "Expected channel number in response data");
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn manage_channel_close() {
        let mut app = app();
        send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x80, 0x01]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn manage_channel_cannot_close_basic() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x80, 0x00]);
        assert_ne!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn manage_channel_max_channels() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x01);
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x02);
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x03);
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        assert_ne!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn channel_independent_selection() {
        let mut app = app();
        // Open channel 1.
        send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        // SELECT on open channel 1 (CLA=0x01) should be accepted (not rejected
        // for "channel not open"). The actual per-channel selection context is
        // tracked but commands still dispatch through the shared state.
        let (buf, _) = send(&mut app,
            &[0x01, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        // Should get 61 XX (data available) -- channel is open, command accepted.
        assert_eq!(buf[0], 0x61);
    }

    #[test]
    fn channel_cla_routing() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x01, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        assert_ne!(sw(&buf, len), (0x90, 0x00));
        assert_ne!(buf[0], 0x61);
    }

    #[test]
    fn manage_channel_no_pin_required() {
        let mut app = app_with_pin1_enabled();
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn close_already_closed_fails() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0x70, 0x80, 0x01]);
        assert_ne!(sw(&buf, len), (0x90, 0x00));
    }

    // ===================================================================
    // 7G: SELECT by AID Occurrence
    // ===================================================================

    #[test]
    fn select_aid_p2_00_first_occurrence() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0xA4, 0x04, 0x00, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        assert_eq!(buf[0], 0x61);
        let _ = len;
    }

    #[test]
    fn select_aid_p2_02_next_not_found() {
        let mut app = app();
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x00, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xA4, 0x04, 0x02, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        assert_eq!(sw(&buf, len), (0x6A, 0x82));
    }

    #[test]
    fn select_aid_unknown_p2_rejected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0xA4, 0x04, 0x06, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        assert_eq!(sw(&buf, len), (0x6A, 0x86));
    }

    // ===================================================================
    // 7H: REFRESH Action Wiring
    // ===================================================================

    #[test]
    fn refresh_sim_init_reselects_mf() {
        let mut app = app();
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        let cmd = simrs_proactive::ProactiveCommand::Refresh {
            qualifier: 0x01,
            file_list: &[],
        };
        app.proactive_state().queue_command(&cmd).unwrap();
        let (buf, len) = send(&mut app, &[0x80, 0x12, 0x00, 0x00, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let tr = [
            0x80, 0x14, 0x00, 0x00, 0x0C,
            0x81, 0x03, 0x01, 0x01, 0x01,
            0x82, 0x02, 0x82, 0x81,
            0x83, 0x01, 0x00,
        ];
        send(&mut app, &tr);
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00], "After REFRESH SIM Init, MF should be selected");
    }

    #[test]
    fn refresh_uicc_reset_clears_state() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        send(&mut app, &[0x00, 0x04, 0x00, 0x00]);
        let cmd = simrs_proactive::ProactiveCommand::Refresh {
            qualifier: 0x04,
            file_list: &[],
        };
        app.proactive_state().queue_command(&cmd).unwrap();
        send(&mut app, &[0x80, 0x12, 0x00, 0x00, 0xFF]);
        let tr = [
            0x80, 0x14, 0x00, 0x00, 0x0C,
            0x81, 0x03, 0x01, 0x01, 0x04,
            0x82, 0x02, 0x82, 0x81,
            0x83, 0x01, 0x00,
        ];
        send(&mut app, &tr);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn refresh_no_pending_ignored() {
        let mut app = app();
        // TERMINAL RESPONSE with Command Details but no active proactive
        // session is rejected by the session lifecycle enforcement (69 86).
        let tr = [
            0x80, 0x14, 0x00, 0x00, 0x0C,
            0x81, 0x03, 0x01, 0x01, 0x01,
            0x82, 0x02, 0x82, 0x81,
            0x83, 0x01, 0x00,
        ];
        let (buf, len) = send(&mut app, &tr);
        assert_eq!(sw(&buf, len), (0x69, 0x86));
    }

    #[test]
    fn terminal_response_refresh_success() {
        let mut app = app();
        let cmd = simrs_proactive::ProactiveCommand::Refresh {
            qualifier: 0x03,
            file_list: &[0x3F, 0x00],
        };
        app.proactive_state().queue_command(&cmd).unwrap();
        send(&mut app, &[0x80, 0x12, 0x00, 0x00, 0xFF]);
        let tr = [
            0x80, 0x14, 0x00, 0x00, 0x0C,
            0x81, 0x03, 0x01, 0x01, 0x03,
            0x82, 0x02, 0x82, 0x81,
            0x83, 0x01, 0x00,
        ];
        let (buf, len) = send(&mut app, &tr);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // ===================================================================
    // 7I: FCP Security Attributes (Tag 0x8C)
    // ===================================================================

    #[test]
    fn fcp_contains_security_attributes() {
        let mut app = app();
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let fcp_len = buf[1];
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let inner = &buf[2..buf[1] as usize + 2];
        assert!(find_tlv_tag(inner, 0x8C).is_some(),
            "FCP must contain security attributes compact (tag 0x8C)");
    }

    #[test]
    fn fcp_ef_security_requires_pin1() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let fcp_len = buf[1];
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let inner = &buf[2..buf[1] as usize + 2];
        let sec = find_tlv_tag(inner, 0x8C).expect("EF FCP must have tag 0x8C");
        assert_eq!(sec, &[0x03, 0x01],
            "EF security attributes should be [0x03, 0x01] (read+update require PIN1)");
    }

    #[test]
    fn fcp_df_security_always_allowed() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let fcp_len = buf[1];
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let inner = &buf[2..buf[1] as usize + 2];
        let sec = find_tlv_tag(inner, 0x8C).expect("DF FCP must have tag 0x8C");
        assert_eq!(sec, &[0xFF, 0x00],
            "DF security attributes should be [0xFF, 0x00] (always allowed)");
    }

    // -----------------------------------------------------------------------
    // AUTHENTICATE multi-step tests
    // -----------------------------------------------------------------------

    /// AUTHENTICATE UMTS (P2=0x81) with TS 135 208 Test Set 1 vectors.
    /// Verifies that the full RES/CK/IK response matches independently
    /// computed Milenage output byte-for-byte.
    #[test]
    fn authenticate_umts_known_vectors_res_ck_ik() {
        let mut app = app();
        // Select ADF USIM.
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );

        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];

        // Compute AUTN from known SQN and AMF.
        let mut params = MilenageParams::with_defaults(K, OPC);
        let sequence_number = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let management_field = [0xB9, 0xB9];
        let anonymity_key = params.compute_anonymity_key(&rand_val);
        let auth_mac = params.compute_auth_mac(&rand_val, &sequence_number, &management_field);

        let mut auth_token = [0u8; 16];
        for i in 0..6 { auth_token[i] = sequence_number[i] ^ anonymity_key[i]; }
        auth_token[6..8].copy_from_slice(&management_field);
        auth_token[8..16].copy_from_slice(&auth_mac);

        // Build AUTHENTICATE APDU.
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00;
        apdu[1] = 0x88;
        apdu[3] = 0x81;
        apdu[4] = 0x22;
        apdu[5] = 0x10;
        apdu[6..22].copy_from_slice(&rand_val);
        apdu[22] = 0x10;
        apdu[23..39].copy_from_slice(&auth_token);

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x61, 0x2D), "expected 61 2D (45 bytes available)");

        // GET RESPONSE
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x2D]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Independently compute expected values.
        let expected = params.authenticate(&rand_val, &auth_token).unwrap();

        // Verify RES (8 bytes at offset 3).
        assert_eq!(&buf[3..11], &expected.response,
            "RES must match Milenage f2 output");

        // Verify CK (16 bytes at offset 12).
        assert_eq!(&buf[12..28], expected.cipher_key.declassify().as_slice(),
            "CK must match Milenage f3 output");

        // Verify IK (16 bytes at offset 29).
        assert_eq!(&buf[29..45], expected.integrity_key.declassify().as_slice(),
            "IK must match Milenage f4 output");

        // Sanity: none of RES/CK/IK should be all-zeros (non-trivial output).
        assert_ne!(expected.response, [0u8; 8], "RES must not be all-zeros");
        assert_ne!(*expected.cipher_key.declassify(), [0u8; 16], "CK must not be all-zeros");
        assert_ne!(*expected.integrity_key.declassify(), [0u8; 16], "IK must not be all-zeros");
    }

    /// AUTHENTICATE with corrupted MAC in AUTN must return SW 98 62
    /// (authentication error). This uses a valid RAND but an AUTN with
    /// a deliberately wrong MAC-A.
    #[test]
    fn authenticate_umts_wrong_mac_returns_9862() {
        let mut app = app();
        // Use a non-zero RAND (not identity element).
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];

        // Build AUTN with a deliberately corrupted MAC (all 0xAA).
        let mut auth_token = [0u8; 16];
        // SQN^AK = arbitrary
        auth_token[0..6].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        // AMF = arbitrary
        auth_token[6..8].copy_from_slice(&[0x00, 0x00]);
        // MAC-A = garbage (extremely unlikely to match real MAC)
        auth_token[8..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);

        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00;
        apdu[1] = 0x88;
        apdu[3] = 0x81;
        apdu[4] = 0x22;
        apdu[5] = 0x10;
        apdu[6..22].copy_from_slice(&rand_val);
        apdu[22] = 0x10;
        apdu[23..39].copy_from_slice(&auth_token);

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(
            sw(&buf, len), (0x98, 0x62),
            "wrong MAC must return 98 62 (authentication error)"
        );
    }

    /// AUTHENTICATE P2 context selection: P2=0x81 is UMTS, P2=0x00 is GSM,
    /// and any other P2 value must be rejected with 6A 86.
    #[test]
    fn authenticate_p2_context_selection() {
        let mut app = app();

        // P2=0x81 (UMTS context) with garbage AUTN: should return 98 62 (MAC fail),
        // proving the UMTS path was entered.
        let mut umts_apdu = [0u8; 5 + 34];
        umts_apdu[0] = 0x00;
        umts_apdu[1] = 0x88;
        umts_apdu[3] = 0x81; // UMTS
        umts_apdu[4] = 0x22;
        umts_apdu[5] = 0x10;
        umts_apdu[22] = 0x10;
        let (buf, len) = send(&mut app, &umts_apdu);
        assert_eq!(sw(&buf, len), (0x98, 0x62),
            "P2=0x81 must route to UMTS AUTHENTICATE");

        // P2=0x00 (GSM context) with valid-format data: should return 61 0E (success),
        // proving the GSM path was entered.
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let mut gsm_apdu = [0u8; 5 + 17];
        gsm_apdu[0] = 0x00;
        gsm_apdu[1] = 0x88;
        gsm_apdu[3] = 0x00; // GSM
        gsm_apdu[4] = 0x11;
        gsm_apdu[5] = 0x10;
        gsm_apdu[6..22].copy_from_slice(&rand_val);
        let (buf, len) = send(&mut app, &gsm_apdu);
        assert_eq!(sw(&buf, len), (0x61, 0x0E),
            "P2=0x00 must route to GSM AUTHENTICATE and return 14 bytes");

        // P2=0x82 (GBA_U/bootstrap, not supported): should return 6A 86.
        let mut gba_apdu = [0u8; 5 + 34];
        gba_apdu[0] = 0x00;
        gba_apdu[1] = 0x88;
        gba_apdu[3] = 0x82; // GBA_U -- not supported
        gba_apdu[4] = 0x22;
        gba_apdu[5] = 0x10;
        gba_apdu[22] = 0x10;
        let (buf, len) = send(&mut app, &gba_apdu);
        assert_eq!(sw(&buf, len), (0x6A, 0x86),
            "P2=0x82 (unsupported context) must return 6A 86");

        // P2=0xFF (invalid): should also return 6A 86.
        let mut inv_apdu = [0u8; 5 + 34];
        inv_apdu[0] = 0x00;
        inv_apdu[1] = 0x88;
        inv_apdu[3] = 0xFF;
        inv_apdu[4] = 0x22;
        inv_apdu[5] = 0x10;
        inv_apdu[22] = 0x10;
        let (buf, len) = send(&mut app, &inv_apdu);
        assert_eq!(sw(&buf, len), (0x6A, 0x86),
            "P2=0xFF (invalid) must return 6A 86");
    }

    // -----------------------------------------------------------------------
    // Multi-step AUTHENTICATE protocol sequence tests
    // -----------------------------------------------------------------------

    /// Helper: build a valid AUTN for the given RAND using Test Set 1 SQN/AMF.
    fn build_autn(
        params: &MilenageParams,
        challenge: &[u8; 16],
        sequence_number: [u8; 6],
        management_field: [u8; 2],
    ) -> [u8; 16] {
        let anonymity_key = params.compute_anonymity_key(challenge);
        let auth_mac = params.compute_auth_mac(challenge, &sequence_number, &management_field);
        let mut auth_token = [0u8; 16];
        for i in 0..6 {
            auth_token[i] = sequence_number[i] ^ anonymity_key[i];
        }
        auth_token[6..8].copy_from_slice(&management_field);
        auth_token[8..16].copy_from_slice(&auth_mac);
        auth_token
    }

    /// Helper: build an AUTHENTICATE APDU (INS=0x88, P2=0x81 UMTS context).
    fn build_authenticate_apdu(challenge: &[u8; 16], auth_token: &[u8; 16]) -> [u8; 5 + 34] {
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0x88; // INS = AUTHENTICATE
        apdu[2] = 0x00; // P1
        apdu[3] = 0x81; // P2 = UMTS context
        apdu[4] = 0x22; // Lc = 34
        apdu[5] = 0x10; // RAND length prefix
        apdu[6..22].copy_from_slice(challenge);
        apdu[22] = 0x10; // AUTN length prefix
        apdu[23..39].copy_from_slice(auth_token);
        apdu
    }

    /// SELECT ADF USIM APDU (P1=0x04 select by AID, P2=0x04 FCP).
    const SELECT_ADF_USIM: [u8; 12] = [
        0x00, 0xA4, 0x04, 0x04, 0x07,
        0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
    ];

    /// Multi-step sequence: SELECT ADF USIM -> AUTHENTICATE -> verify
    /// RES/CK/IK in TLV response.
    ///
    /// Exercises the real modem boot flow where the baseband first selects the
    /// USIM application, then runs UMTS AUTHENTICATE with network-supplied
    /// RAND/AUTN, and parses the structured TLV response.
    #[test]
    fn multistep_select_adf_then_authenticate_verify_tlv() {
        let mut app = app();

        // Step 1: SELECT ADF.USIM by AID.
        let (buf, _len) = send(&mut app, &SELECT_ADF_USIM);
        assert_eq!(buf[0], 0x61,
            "SELECT ADF.USIM must return 61 XX (FCP available)");
        // Consume the FCP via GET RESPONSE so the pending buffer is cleared.
        let fcp_len = buf[1];
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00),
            "GET RESPONSE for SELECT FCP must succeed");

        // Step 2: AUTHENTICATE with valid AUTN.
        let mut params = MilenageParams::with_defaults(K, OPC);
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let sequence_number = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let management_field = [0xB9, 0xB9];
        let auth_token = build_autn(&params, &rand_val, sequence_number, management_field);
        let apdu = build_authenticate_apdu(&rand_val, &auth_token);

        let (buf, _len) = send(&mut app, &apdu);
        assert_eq!(buf[0], 0x61,
            "AUTHENTICATE must return 61 XX (response data available)");
        let rsp_len = buf[1] as usize;

        // Step 3: GET RESPONSE to retrieve the authentication vector.
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, rsp_len as u8]);
        assert_eq!(sw(&buf, len), (0x90, 0x00),
            "GET RESPONSE for AUTHENTICATE must succeed");

        // Step 4: Verify TLV structure.
        // Response format: 0xDB || inner_len || 0x08 || RES(8) || 0x10 || CK(16) || 0x10 || IK(16)
        assert_eq!(buf[0], 0xDB, "success tag must be 0xDB");
        assert_eq!(buf[1], 1 + 8 + 1 + 16 + 1 + 16,
            "inner length must encode RES(1+8) + CK(1+16) + IK(1+16) = 43");
        assert_eq!(buf[2], 0x08, "RES length prefix must be 0x08");

        let res_actual = &buf[3..11];
        assert_eq!(res_actual.len(), 8, "RES must be exactly 8 bytes");

        assert_eq!(buf[11], 0x10, "CK length prefix must be 0x10");
        let ck_actual = &buf[12..28];
        assert_eq!(ck_actual.len(), 16, "CK must be exactly 16 bytes");

        assert_eq!(buf[28], 0x10, "IK length prefix must be 0x10");
        let ik_actual = &buf[29..45];
        assert_eq!(ik_actual.len(), 16, "IK must be exactly 16 bytes");

        // Step 5: Cross-check against independent Milenage computation.
        let expected = params.authenticate(&rand_val, &auth_token).unwrap();
        assert_eq!(res_actual, &expected.response, "RES must match Milenage f2");
        assert_eq!(ck_actual, expected.cipher_key.declassify().as_slice(), "CK must match Milenage f3");
        assert_eq!(ik_actual, expected.integrity_key.declassify().as_slice(), "IK must match Milenage f4");

        // Non-triviality: none of the outputs should be all-zeros.
        assert_ne!(expected.response, [0u8; 8], "RES must not be trivial");
        assert_ne!(*expected.cipher_key.declassify(), [0u8; 16], "CK must not be trivial");
        assert_ne!(*expected.integrity_key.declassify(), [0u8; 16], "IK must not be trivial");
    }

    /// Multi-step sequence: SELECT ADF USIM -> AUTHENTICATE with bad AUTN ->
    /// verify SW 98 62 (MAC failure).
    ///
    /// Simulates a network attack or corruption scenario where the AUTN MAC
    /// does not match. The USIM must reject the authentication and return the
    /// correct status word without leaking any key material.
    #[test]
    fn multistep_select_adf_then_authenticate_bad_autn() {
        let mut app = app();

        // Step 1: SELECT ADF.USIM by AID.
        let (buf, _len) = send(&mut app, &SELECT_ADF_USIM);
        assert_eq!(buf[0], 0x61,
            "SELECT ADF.USIM must return 61 XX");
        // Consume FCP.
        let fcp_len = buf[1];
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Step 2: AUTHENTICATE with corrupted AUTN.
        // Use a valid RAND but construct an AUTN with a deliberately wrong
        // MAC-A (bitwise NOT of the real MAC).
        let params = MilenageParams::with_defaults(K, OPC);
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let sequence_number = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let management_field = [0xB9, 0xB9];
        let mut auth_token = build_autn(&params, &rand_val, sequence_number, management_field);

        // Corrupt the MAC-A (bytes 8..16) by bitwise NOT.
        for b in &mut auth_token[8..16] {
            *b = !*b;
        }

        let apdu = build_authenticate_apdu(&rand_val, &auth_token);
        let (buf, len) = send(&mut app, &apdu);

        // Must get SW 98 62 (authentication error / MAC failure).
        assert_eq!(sw(&buf, len), (0x98, 0x62),
            "corrupted AUTN MAC must produce SW 98 62");

        // Verify the response is just the 2-byte status word -- no data leaked.
        assert_eq!(len, 2,
            "MAC failure response must contain only the status word");
    }

    /// Multi-step sequence: two sequential AUTHENTICATEs with different RAND
    /// values produce different RES values.
    ///
    /// Verifies that the USIM correctly handles back-to-back AUTHENTICATE
    /// commands (as happens during inter-RAT handovers or re-authentication)
    /// and that distinct RAND inputs produce distinct outputs -- confirming
    /// the cipher is not stuck or returning stale results.
    #[test]
    fn multistep_two_sequential_authenticates_different_res() {
        let mut app = app();

        let params = MilenageParams::with_defaults(K, OPC);
        let sequence_number_1 = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        // Second AUTHENTICATE must use a higher SQN (monotonic SQN tracking).
        let sequence_number_2 = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x08];
        let management_field = [0xB9, 0xB9];

        // First AUTHENTICATE with ETSI TS 135 208 Test Set 1 RAND.
        let rand1: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let auth_token_1 = build_autn(&params, &rand1, sequence_number_1, management_field);
        let apdu1 = build_authenticate_apdu(&rand1, &auth_token_1);

        let (buf, _len) = send(&mut app, &apdu1);
        assert_eq!(buf[0], 0x61, "first AUTHENTICATE must succeed (61 XX)");
        let rsp_len1 = buf[1];
        let (buf1, len1) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, rsp_len1]);
        assert_eq!(sw(&buf1, len1), (0x90, 0x00),
            "first GET RESPONSE must succeed");
        let mut res1 = [0u8; 8];
        res1.copy_from_slice(&buf1[3..11]);

        // Second AUTHENTICATE with a different RAND (ETSI TS 135 208 Test Set 2)
        // and an incremented SQN (SQN tracking requires monotonic increase).
        let rand2: [u8; 16] = [
            0xB9, 0xBE, 0xAD, 0x00, 0x47, 0x5E, 0x7B, 0x05,
            0x7B, 0x54, 0x0E, 0xA4, 0x02, 0xD5, 0x55, 0xB4,
        ];
        let auth_token_2 = build_autn(&params, &rand2, sequence_number_2, management_field);
        let apdu2 = build_authenticate_apdu(&rand2, &auth_token_2);

        let (buf, _len) = send(&mut app, &apdu2);
        assert_eq!(buf[0], 0x61, "second AUTHENTICATE must succeed (61 XX)");
        let rsp_len2 = buf[1];
        let (buf2, len2) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, rsp_len2]);
        assert_eq!(sw(&buf2, len2), (0x90, 0x00),
            "second GET RESPONSE must succeed");
        let mut res2 = [0u8; 8];
        res2.copy_from_slice(&buf2[3..11]);

        // Both RES values must be non-trivial.
        assert_ne!(res1, [0u8; 8], "first RES must not be all-zeros");
        assert_ne!(res2, [0u8; 8], "second RES must not be all-zeros");

        // The two RES values must differ (different RAND => different output).
        assert_ne!(res1, res2,
            "different RAND values must produce different RES values");

        // Cross-check each RES against independent (fresh) Milenage computation.
        let mut check1 = MilenageParams::with_defaults(K, OPC);
        let expected1 = check1.authenticate(&rand1, &auth_token_1).unwrap();
        let mut check2 = MilenageParams::with_defaults(K, OPC);
        let expected2 = check2.authenticate(&rand2, &auth_token_2).unwrap();
        assert_eq!(res1, expected1.response,
            "first RES must match independent Milenage");
        assert_eq!(res2, expected2.response,
            "second RES must match independent Milenage");

        // CK and IK must also differ between the two runs.
        assert_ne!(&buf1[12..28], &buf2[12..28],
            "different RAND must produce different CK");
        assert_ne!(&buf1[29..45], &buf2[29..45],
            "different RAND must produce different IK");
    }

    // -----------------------------------------------------------------------
    // APDU-level tests using the reference profile (Phase 7)
    // -----------------------------------------------------------------------

    /// Helper: create a UsimApp from the reference profile with PIN verified.
    #[cfg(feature = "profile-full")]
    fn ref_app() -> UsimApp {
        use crate::profile;
        let mil = MilenageParams::with_defaults(K, OPC);
        let mut a = UsimApp::new(&profile::REFERENCE_MF, &profile::ADF_TABLE, mil);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        let _ = a.pin_manager().verify(PinKey::PIN1, &pin_val);
        a
    }

    /// SELECT EF.IMSI (6F07) by FID in ADF.USIM and verify FCP response.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_select_ef_imsi_by_fid() {
        let mut app = ref_app();
        // Select ADF.USIM by AID
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // Select EF.IMSI by FID
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
        assert_eq!(buf[0], 0x61, "SELECT EF.IMSI must return data-available SW");
        let fcp_len = buf[1];
        // GET RESPONSE
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62, "FCP must start with tag 0x62");
        let inner = &buf[2..fcp_len as usize];
        let fid_val = find_tlv_tag(inner, 0x83).unwrap();
        assert_eq!(fid_val, &[0x6F, 0x07], "FCP must contain FID 6F07");
    }

    /// READ BINARY on EF.IMSI returns default data from reference profile.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_binary_ef_imsi() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 9 + 2); // 9 data + 2 SW
        assert_eq!(buf[0], 0x08, "IMSI first byte (length) must be 0x08");
    }

    /// SELECT and READ BINARY on a full-tier transparent EF (EF.DCK, 6F2C).
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_binary_ef_dck() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x2C]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x10]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 16 + 2); // EF.DCK is 16 bytes
    }

    /// READ RECORD on EF.FDN (6F3B, linear-fixed) in reference profile.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_record_ef_fdn() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // EF.FDN in ref profile: 2 records x 30 bytes
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x1E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 30 + 2);
    }

    /// READ RECORD on EF.ACM (6F39, cyclic) in reference profile.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_record_ef_acm_cyclic() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x39]);
        // EF.ACM in ref profile: 3 records x 3 bytes
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x03]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 3 + 2);
    }

    /// UPDATE BINARY + re-read round-trip on EF.AD (6FAD).
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_update_binary_roundtrip_ef_ad() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0xAD]);
        // Write [0x81, 0x00, 0x00, 0x03] (mode=test, MNC len=3)
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x04, 0x81, 0x00, 0x00, 0x03]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Read back
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x04]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..4], &[0x81, 0x00, 0x00, 0x03]);
    }

    /// UPDATE RECORD + re-read round-trip on EF.SDN (6F49, linear-fixed).
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_update_record_roundtrip_ef_sdn() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x49]);
        // EF.SDN: 2 records x 30 bytes. Write record 1.
        let mut apdu = [0xA5u8; 5 + 30];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0xDC; // INS: UPDATE RECORD
        apdu[2] = 0x01; // P1: record 1
        apdu[3] = 0x04; // P2: absolute
        apdu[4] = 0x1E; // Lc: 30
        // Payload is 0xA5 repeated
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Read back record 1
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x1E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0xA5);
        assert_eq!(buf[29], 0xA5);
    }

    /// SELECT by path through sub-DFs: MF > ADF.USIM > DF.GSM-ACCESS > EF.Kc.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_select_path_to_ef_kc_in_gsm_access() {
        let mut app = ref_app();
        // Select ADF.USIM by AID
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // Select DF.GSM-ACCESS (5F3B) by FID
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x5F, 0x3B]);
        assert_eq!(buf[0], 0x61, "SELECT DF.GSM-ACCESS must return data-available");
        // Select EF.Kc (4F20) under DF.GSM-ACCESS
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x4F, 0x20]);
        assert_eq!(buf[0], 0x61, "SELECT EF.Kc must return data-available");
        let fcp_len = buf[1];
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let inner = &buf[2..fcp_len as usize];
        let fid_val = find_tlv_tag(inner, 0x83).unwrap();
        assert_eq!(fid_val, &[0x4F, 0x20], "FCP must contain FID 4F20");
        // Read EF.Kc data (9 bytes)
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 9 + 2);
        // Last byte is CKSN=7 (no key)
        assert_eq!(buf[8], 0x07, "EF.Kc CKSN must be 7 (no key)");
    }

    /// SELECT EF.KcGPRS (4F52) under DF.GSM-ACCESS and read.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_select_ef_kcgprs_in_gsm_access() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x5F, 0x3B]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x4F, 0x52]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[8], 0x07, "EF.KcGPRS CKSN must be 7 (no key)");
    }

    /// SELECT and read a DF_5GS EF: EF.5GS3GPPLOCI (4F01).
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_select_ef_5gs3gpploci() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // Select DF.5GS (5FC0)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x5F, 0xC0]);
        // Select EF.5GS3GPPLOCI (4F01)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x4F, 0x01]);
        // Read 20 bytes
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x14]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 20 + 2);
    }

    /// SELECT EF.ICCID from MF in reference profile.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_select_ef_iccid() {
        let mut app = ref_app();
        // MF is current by default
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 10 + 2);
        // First nibble-pair should be 0x98 (BCD for '89')
        assert_eq!(buf[0], 0x98, "EF.ICCID first byte must be 0x98");
    }

    /// SELECT EF.PL (2F05) under MF and read default data.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_ef_pl() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x05]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 10 + 2);
    }

    /// SELECT EF.ARR (2F06) under MF and read record.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_record_ef_arr() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x06]);
        // EF.ARR: 1 record x 8 bytes
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 8 + 2);
    }

    /// FCP for a full-tier EF (EF.VGCS) shows correct file size.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_fcp_ef_vgcs_file_size() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // EF.VGCS (6FB1) -- 40 bytes transparent
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0xB1]);
        let fcp_len = buf[1];
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let inner = &buf[2..fcp_len as usize];
        let size_val = find_tlv_tag(inner, 0x80).unwrap();
        assert_eq!(size_val, &[0x00, 0x28], "EF.VGCS file size must be 40 (0x28)");
    }

    // -----------------------------------------------------------------------
    // Adversarial / defensive tests (Phase 7)
    // -----------------------------------------------------------------------

    /// SELECT non-existent FID returns 6A 82 (file not found).
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_select_nonexistent_fid() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0xDE, 0xAD]);
        assert_eq!(sw(&buf, len), (0x6A, 0x82), "non-existent FID must return 6A82");
    }

    /// READ BINARY past end of file returns appropriate error SW.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_binary_past_end() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // EF.HPPLMN (6F31) is 1 byte. Read 2 bytes at offset 0.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x31]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x02]);
        let (sw1, _sw2) = sw(&buf, len);
        assert_ne!(sw1, 0x90, "READ BINARY past end must not succeed");
    }

    /// READ RECORD with record 0 is rejected (records are 1-based).
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_record_zero_rejected() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // EF.FDN (6F3B) linear-fixed
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x00, 0x04, 0x1E]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90, "READ RECORD with P1=0 must be rejected");
    }

    /// READ RECORD beyond last record returns 6A 83.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_record_beyond_last() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // EF.FDN: 2 records. Try record 3.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x03, 0x04, 0x1E]);
        assert_eq!(sw(&buf, len), (0x6A, 0x83), "record beyond last must return 6A83");
    }

    /// UPDATE BINARY with data exceeding file size is rejected.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_update_binary_exceeds_file_size() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // EF.HPPLMN (6F31) is 1 byte. Try writing 2 bytes at offset 0.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x31]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90, "UPDATE BINARY exceeding file size must fail");
    }

    /// UPDATE RECORD with wrong record size is rejected.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_update_record_wrong_size() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // EF.ECC (6FB7) linear-fixed: 16-byte records. Try writing 8 bytes.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0xB7]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xDC, 0x01, 0x04, 0x08,
              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(sw(&buf, len), (0x67, 0x00), "wrong record size must return 6700");
    }

    /// READ BINARY on a linear-fixed EF is rejected (incompatible structure).
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_binary_on_linear_fixed() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]); // EF.FDN
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x81),
            "READ BINARY on linear-fixed EF must return 6981");
    }

    /// READ RECORD on a transparent EF is rejected.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_read_record_on_transparent() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]); // EF.IMSI
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x09]);
        assert_eq!(sw(&buf, len), (0x69, 0x81),
            "READ RECORD on transparent EF must return 6981");
    }

    /// ISIM ADF can be selected and EFs accessed.
    #[cfg(all(feature = "profile-full", feature = "isim"))]
    #[test]
    fn ref_select_isim_adf_and_read_ef() {
        let mut app = ref_app();
        // Select ADF.ISIM by AID
        let (buf, _) = send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]);
        assert_eq!(buf[0], 0x61, "SELECT ADF.ISIM must return data-available");
        // Select EF.IMPI (6F02)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x02]);
        // Read 64 bytes
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x40]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 64 + 2);
    }

    /// HPSIM ADF can be selected and EFs accessed.
    #[cfg(all(feature = "profile-full", feature = "hpsim"))]
    #[test]
    fn ref_select_hpsim_adf_and_read_ef() {
        let mut app = ref_app();
        // Select ADF.HPSIM by AID
        let (buf, _) = send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x0A]);
        assert_eq!(buf[0], 0x61, "SELECT ADF.HPSIM must return data-available");
        // Select EF.HPST (6F07)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x02]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 2 + 2);
    }

    /// DF_TELECOM can be selected and EFs accessed.
    #[cfg(all(feature = "profile-full", feature = "telecom"))]
    #[test]
    fn ref_select_df_telecom_and_read_ef() {
        let mut app = ref_app();
        // Select DF_TELECOM (7F10)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x7F, 0x10]);
        // Select EF.ADN (6F3A)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3A]);
        // Read first record (30 bytes)
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x1E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 30 + 2);
    }

    /// Multiple full-tier EFs can be sequentially selected and read.
    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_sequential_select_multiple_efs() {
        let mut app = ref_app();
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);

        // Table of (FID_hi, FID_lo, expected_size) for transparent EFs
        let efs: [(u8, u8, u8); 6] = [
            (0x6F, 0x2C, 16),  // EF.DCK
            (0x6F, 0x32, 24),  // EF.CNL
            (0x6F, 0x37, 3),   // EF.ACMmax
            (0x6F, 0x41, 5),   // EF.PUCT
            (0x6F, 0x5B, 6),   // EF.START_HFN
            (0x6F, 0x5C, 3),   // EF.THRESHOLD
        ];

        for (hi, lo, size) in &efs {
            send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, *hi, *lo]);
            let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, *size]);
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "READ BINARY on EF {hi:#04X}{lo:02X} must succeed");
            assert_eq!(len, *size as usize + 2,
                "EF {hi:#04X}{lo:02X} data length mismatch");
        }
    }

    // -- DF_PHONEBOOK sync counter tests --

    /// Helper: select ADF.USIM by AID, then select DF_PHONEBOOK (5F3A).
    #[cfg(feature = "profile-full")]
    fn select_phonebook(app: &mut UsimApp) {
        // SELECT ADF.USIM
        send(app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        // SELECT DF_PHONEBOOK (5F3A)
        send(app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x5F, 0x3A]);
    }

    /// Helper: select an EF by FID within current DF.
    #[cfg(feature = "profile-full")]
    fn select_ef(app: &mut UsimApp, fid_hi: u8, fid_lo: u8) {
        send(app, &[0x00, 0xA4, 0x00, 0x04, 0x02, fid_hi, fid_lo]);
    }

    /// Helper: read a transparent EF and return its data bytes (up to 8 bytes).
    #[cfg(feature = "profile-full")]
    fn read_transparent(app: &mut UsimApp, fid_hi: u8, fid_lo: u8, size: u8) -> [u8; 8] {
        select_ef(app, fid_hi, fid_lo);
        let (buf, len) = send(app, &[0x00, 0xB0, 0x00, 0x00, size]);
        assert_eq!(sw(&buf, len), (0x90, 0x00), "READ BINARY failed for {fid_hi:#04X}{fid_lo:02X}");
        let mut out = [0u8; 8];
        out[..size as usize].copy_from_slice(&buf[..size as usize]);
        out
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_psc_increments_on_adn_update() {
        let mut app = ref_app();
        select_phonebook(&mut app);

        // PSC starts at 0.
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0, 0, 0, 0], "PSC must start at 0");

        // UPDATE RECORD on EF_ADN (4F31), record 1, 28 bytes.
        select_ef(&mut app, 0x4F, 0x31);
        let mut apdu = [0xA5u8; 5 + 28];
        apdu[0] = 0x00; apdu[1] = 0xDC; // UPDATE RECORD
        apdu[2] = 0x01; apdu[3] = 0x04; apdu[4] = 28; // rec 1, absolute
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00), "UPDATE RECORD ADN must succeed");

        // PSC must be 1.
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0, 0, 0, 1], "PSC must be 1 after one ADN update");

        // Second update.
        select_ef(&mut app, 0x4F, 0x31);
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0, 0, 0, 2], "PSC must be 2 after two ADN updates");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_cc_increments_only_on_adn() {
        let mut app = ref_app();
        select_phonebook(&mut app);

        // CC starts at 0.
        let cc = read_transparent(&mut app, 0x4F, 0x23, 2);
        assert_eq!(&cc[..2], [0, 0], "CC must start at 0");

        // UPDATE RECORD on EF_ADN (4F31) -> CC must increment.
        select_ef(&mut app, 0x4F, 0x31);
        let mut apdu = [0xA5u8; 5 + 28];
        apdu[0] = 0x00; apdu[1] = 0xDC;
        apdu[2] = 0x01; apdu[3] = 0x04; apdu[4] = 28;
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        let cc = read_transparent(&mut app, 0x4F, 0x23, 2);
        assert_eq!(&cc[..2], [0, 1], "CC must be 1 after ADN update");

        // UPDATE RECORD on EF_SNE (4F36) -> CC must NOT increment.
        select_ef(&mut app, 0x4F, 0x36);
        let mut apdu2 = [0xA5u8; 5 + 18];
        apdu2[0] = 0x00; apdu2[1] = 0xDC;
        apdu2[2] = 0x01; apdu2[3] = 0x04; apdu2[4] = 18;
        let (buf, len) = send(&mut app, &apdu2);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        let cc = read_transparent(&mut app, 0x4F, 0x23, 2);
        assert_eq!(&cc[..2], [0, 1], "CC must still be 1 after SNE update (not ADN)");

        // PSC must be 2 (both writes incremented it).
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0, 0, 0, 2], "PSC must be 2 after two phonebook writes");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_puid_not_auto_incremented() {
        // Per 3GPP TS 31.102 clause 4.4.2.12.4, EF_PUID stores the highest
        // UID value previously assigned and is managed by the ME, not the
        // UICC.  Writing to EF_UID must NOT auto-increment PUID.
        let mut app = ref_app();
        select_phonebook(&mut app);

        // PUID starts at 0.
        let puid = read_transparent(&mut app, 0x4F, 0x24, 2);
        assert_eq!(&puid[..2], [0, 0], "PUID must start at 0");

        // UPDATE RECORD on EF_UID (4F3B), record 1, 2 bytes.
        select_ef(&mut app, 0x4F, 0x3B);
        let (buf, len) = send(&mut app, &[0x00, 0xDC, 0x01, 0x04, 0x02, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // PUID must remain at 0 -- the UICC does not auto-increment it.
        let puid = read_transparent(&mut app, 0x4F, 0x24, 2);
        assert_eq!(&puid[..2], [0, 0], "PUID must NOT be auto-incremented by UICC");

        // PSC must still increment (it tracks any phonebook child write).
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0, 0, 0, 1], "PSC must be 1 after UID update");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_counter_write_no_self_trigger() {
        let mut app = ref_app();
        select_phonebook(&mut app);

        // Write directly to EF_PSC (4F22) with value 0x10.
        select_ef(&mut app, 0x4F, 0x22);
        let (buf, len) = send(&mut app, &[0x00, 0xD6, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x10]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Read back -- must be exactly what we wrote, no auto-increment.
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0x00, 0x00, 0x00, 0x10],
            "Writing to PSC directly must not trigger auto-increment");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_psc_wraps_at_overflow() {
        let mut app = ref_app();
        select_phonebook(&mut app);

        // Seed PSC to 0xFFFF_FFFE directly.
        select_ef(&mut app, 0x4F, 0x22);
        let (buf, len) = send(&mut app, &[0x00, 0xD6, 0x00, 0x00, 0x04,
            0xFF, 0xFF, 0xFF, 0xFE]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // One ADN write: PSC -> 0xFFFF_FFFF.
        select_ef(&mut app, 0x4F, 0x31);
        let mut apdu = [0xFFu8; 5 + 28];
        apdu[0] = 0x00; apdu[1] = 0xDC; apdu[2] = 0x01; apdu[3] = 0x04; apdu[4] = 28;
        for b in &mut apdu[5..] { *b = 0xA5; }
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0xFF, 0xFF, 0xFF, 0xFF]);

        // Second ADN write: PSC wraps to 0x0000_0000.
        select_ef(&mut app, 0x4F, 0x31);
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0x00, 0x00, 0x00, 0x00],
            "PSC must wrap to 0 on overflow");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_cc_wraps_at_overflow() {
        let mut app = ref_app();
        select_phonebook(&mut app);

        // Seed CC to 0xFFFE directly.
        select_ef(&mut app, 0x4F, 0x23);
        let (buf, len) = send(&mut app, &[0x00, 0xD6, 0x00, 0x00, 0x02,
            0xFF, 0xFE]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // One ADN write: CC -> 0xFFFF.
        select_ef(&mut app, 0x4F, 0x31);
        let mut apdu = [0xFFu8; 5 + 28];
        apdu[0] = 0x00; apdu[1] = 0xDC; apdu[2] = 0x01; apdu[3] = 0x04; apdu[4] = 28;
        for b in &mut apdu[5..] { *b = 0xA5; }
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let cc = read_transparent(&mut app, 0x4F, 0x23, 2);
        assert_eq!(&cc[..2], [0xFF, 0xFF]);

        // Second ADN write: CC wraps to 0x0000.
        select_ef(&mut app, 0x4F, 0x31);
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let cc = read_transparent(&mut app, 0x4F, 0x23, 2);
        assert_eq!(&cc[..2], [0x00, 0x00],
            "CC must wrap to 0 on overflow");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_update_outside_phonebook_no_counters() {
        let mut app = ref_app();
        // Select ADF.USIM
        send(&mut app, &[0x00, 0xA4, 0x04, 0x04, 0x07,
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);

        // UPDATE BINARY on EF.AD (6FAD, 4 bytes) under ADF.USIM root.
        select_ef(&mut app, 0x6F, 0xAD);
        let (buf, len) = send(&mut app, &[0x00, 0xD6, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x02]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Now navigate to DF_PHONEBOOK and check PSC -- must be unchanged.
        select_ef(&mut app, 0x5F, 0x3A);
        let psc = read_transparent(&mut app, 0x4F, 0x22, 4);
        assert_eq!(&psc[..4], [0, 0, 0, 0],
            "Updates outside DF_PHONEBOOK must not affect PSC");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_pbr_read_returns_tlv() {
        let mut app = ref_app();
        select_phonebook(&mut app);

        // READ RECORD on EF_PBR (4F30), record 1, 64 bytes.
        select_ef(&mut app, 0x4F, 0x30);
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x40]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // PBR record must start with A8 (Type 1 mandatory tag).
        assert_eq!(buf[0], 0xA8, "PBR record 1 must start with Type 1 tag A8");
        // Inside A8 construct, first TLV must be C0 (EF_ADN reference).
        let a8_len = buf[1] as usize;
        assert!(a8_len >= 4, "A8 must contain at least one file reference");
        assert_eq!(buf[2], 0xC0, "First Type 1 file ref must be C0 (ADN)");
    }

    #[cfg(feature = "profile-full")]
    #[test]
    fn ref_phonebook_ext1_record_structure() {
        let mut app = ref_app();
        select_phonebook(&mut app);

        // Read EF_EXT1 (4F32), record 1 -- 13 bytes, all 0xFF by default.
        select_ef(&mut app, 0x4F, 0x32);
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x0D]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 13 + 2, "EXT1 record must be 13 bytes + SW");
        // Default is all 0xFF.
        assert!(buf[..13].iter().all(|&b| b == 0xFF),
            "Default EXT1 record must be all 0xFF");

        // Write a valid EXT1 extension record.
        // Type=0x02 (called party subaddress), 11 bytes data, next=0xFF (no chain).
        let mut ext1 = [0xFFu8; 13];
        ext1[0] = 0x02; // type: called party subaddress
        ext1[1..12].copy_from_slice(&[0x91, 0x55, 0x55, 0x55, 0x55, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        ext1[12] = 0xFF; // no next record

        let mut apdu = [0u8; 5 + 13];
        apdu[0] = 0x00; apdu[1] = 0xDC; apdu[2] = 0x01; apdu[3] = 0x04; apdu[4] = 13;
        apdu[5..18].copy_from_slice(&ext1);
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Read back and verify.
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x0D]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x02, "EXT1 type byte must be 0x02");
        assert_eq!(buf[12], 0xFF, "EXT1 next record must be 0xFF");
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use simrs_fs::{EfDef, Fid, FileRef};
    use simrs_milenage::{OperatorVariant, SubscriberKey};
    use proptest::prelude::*;

    static PT_EF: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        None,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    );

    static PT_MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&PT_EF)],
    };

    // Linear-fixed EF for record-based proptest.
    static PT_LF_DATA: [u8; 30] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
        0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA,
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
    ];

    static PT_LF_EF: EfDef = EfDef::linear_fixed(
        Fid::new(0x6F3B),
        None,
        10, 3,
        &PT_LF_DATA,
    );

    static PT_ADF: DfDef = DfDef {
        fid: Fid::new(0xFF01),
        children: &[FileRef::Ef(&PT_LF_EF)],
    };

    static PT_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

    static PT_ADF_TABLE: [simrs_fs::AdfSlot; 1] = [simrs_fs::AdfSlot {
        aid: &PT_AID,
        root: &PT_ADF,
    }];

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        // Any valid READ BINARY offset+length within file returns 90 00.
        #[test]
        fn read_binary_in_bounds(offset in 0u8..8, length in 0u8..=8u8) {
            prop_assume!(u16::from(offset) + u16::from(length) <= 8);
            let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
            let mut app = UsimApp::new(&PT_MF, &[], mil);
            let sel = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let rb = [0x00, 0xB0, 0x00, offset, length];
            let cmd = Command::parse(&rb).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00));
            prop_assert_eq!(len, length as usize + 2);
        }

        // FCP for any selected file always starts with tag 0x62.
        #[test]
        fn fcp_always_starts_with_62(idx in 0usize..2) {
            let fids: [u16; 2] = [0x3F00, 0x2FE2];
            let fid = fids[idx];
            let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
            let mut app = UsimApp::new(&PT_MF, &[], mil);
            let fid_be = fid.to_be_bytes();
            let sel = [0x00, 0xA4, 0x00, 0x04, 0x02, fid_be[0], fid_be[1]];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _rsp = app.handle(&cmd, &mut buf);
            prop_assert_eq!(buf[0], 0x61); // data available

            let fcp_len = buf[1];
            let gr = [0x00, 0xC0, 0x00, 0x00, fcp_len];
            let cmd2 = Command::parse(&gr).unwrap();
            let rsp2 = app.handle(&cmd2, &mut buf);
            let len2 = rsp2.len();
            prop_assert_eq!((buf[len2-2], buf[len2-1]), (0x90, 0x00));
            prop_assert_eq!(buf[0], 0x62); // FCP template
        }

        // For any valid record number, READ RECORD succeeds.
        #[test]
        fn read_record_in_bounds(rec in 1u8..=3u8) {
            let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
            let mut app = UsimApp::new(&PT_MF, &PT_ADF_TABLE, mil);
            // Select ADF.USIM
            let sel_adf = [0x00, 0xA4, 0x04, 0x04, 0x07,
                0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];
            let cmd = Command::parse(&sel_adf).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);
            // Select EF.FDN (linear-fixed, 3 records x 10 bytes)
            let sel_ef = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B];
            let cmd = Command::parse(&sel_ef).unwrap();
            let _ = app.handle(&cmd, &mut buf);
            // READ RECORD
            let rr = [0x00, 0xB2, rec, 0x04, 0x0A];
            let cmd = Command::parse(&rr).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "READ RECORD {} must succeed", rec);
            prop_assert_eq!(len, 10 + 2, "record data must be 10 bytes");
        }

        // Arbitrary data written via UPDATE BINARY reads back identically.
        #[test]
        #[allow(clippy::cast_possible_truncation)] // data.len() is 1..=8, fits in u8
        fn update_binary_roundtrip(data in proptest::collection::vec(any::<u8>(), 1..=8)) {
            let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
            let mut app = UsimApp::new(&PT_MF, &[], mil);
            // Select the 8-byte transparent EF
            let sel = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            // Build UPDATE BINARY APDU
            let lc = data.len() as u8;
            let mut apdu = [0u8; 5 + 8];
            apdu[0] = 0x00; // CLA
            apdu[1] = 0xD6; // INS: UPDATE BINARY
            apdu[2] = 0x00; // P1: offset high
            apdu[3] = 0x00; // P2: offset low
            apdu[4] = lc;
            apdu[5..5 + data.len()].copy_from_slice(&data);

            let cmd = Command::parse(&apdu[..5 + data.len()]).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "UPDATE BINARY must succeed");

            // READ BINARY to verify
            let rb = [0x00, 0xB0, 0x00, 0x00, lc];
            let cmd = Command::parse(&rb).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "READ BINARY after update must succeed");
            prop_assert_eq!(&buf[..data.len()], &data[..],
                "read-back data must match written data");
        }

        // Out-of-bounds READ BINARY always fails (offset+length > file size).
        #[test]
        fn read_binary_out_of_bounds_fails(offset in 0u16..256, length in 1u8..=255u8) {
            prop_assume!(u32::from(offset) + u32::from(length) > 8); // beyond 8-byte EF
            let mil = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
            let mut app = UsimApp::new(&PT_MF, &[], mil);
            let sel = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let off_hi = (offset >> 8) as u8;
            let off_lo = (offset & 0xFF) as u8;
            let rb = [0x00, 0xB0, off_hi, off_lo, length];
            let cmd = Command::parse(&rb).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_ne!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "out-of-bounds READ BINARY must not succeed");
        }
    }

    /// GET IDENTITY returns 69 85 when SUCI is not provisioned.
    #[test]
    fn get_identity_without_suci_returns_conditions_not_satisfied() {
        let auth = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let mut app = UsimApp::new(&profile::REFERENCE_MF, &profile::ADF_TABLE, auth);
        assert!(app.suci_mut().is_none());
        let cmd_bytes = [0x00, 0x78, 0x00, 0x01];
        let cmd = Command::parse(&cmd_bytes).unwrap();
        let mut buf = [0u8; 256];
        let rsp = app.handle(&cmd, &mut buf);
        let len = rsp.len();
        assert_eq!((buf[len - 2], buf[len - 1]), (0x69, 0x85));
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (DudeCT)
//
//   cargo test -p simrs-usim --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{ct_test, assert_no_timing_leak};

    /// extract_msin timing must be independent of IMSI digit values.
    ///
    /// Both classes generate random IMSI data using bitwise ops (no division),
    /// then iterate the function 100x in the timed block to amplify any
    /// real CT violation above measurement noise.
    ///
    /// Class 0: random IMSI masked with 0x77 (low-value bytes).
    /// Class 1: random IMSI OR'd with 0x88 (high-value bytes).
    ///
    /// A non-CT implementation that branches on digit values (e.g.,
    /// scanning for 0xF terminators) would show timing differences.
    #[test]
    fn test_extract_msin_ct() {
        let outcome = ct_test(0x0051_0001,
            |rng| {
                // Class 0: random data AND 0x77 -> bytes in [0x00, 0x77].
                let mut imsi = [0x08u8, 0x09, 0, 0, 0, 0, 0, 0, 0];
                let mut rand_bytes = [0u8; 7];
                rng.fill_bytes(&mut rand_bytes);
                let mut i = 0;
                while i < 7 { imsi[i + 2] = rand_bytes[i] & 0x77; i += 1; }
                (imsi, 2u8)
            },
            |rng| {
                // Class 1: random data OR 0x88 -> bytes in [0x88, 0xFF].
                let mut imsi = [0x08u8, 0x09, 0, 0, 0, 0, 0, 0, 0];
                let mut rand_bytes = [0u8; 7];
                rng.fill_bytes(&mut rand_bytes);
                let mut i = 0;
                while i < 7 { imsi[i + 2] = rand_bytes[i] | 0x88; i += 1; }
                (imsi, 2u8)
            },
            |(imsi, mnc_len)| {
                // Iterate 100x to amplify signal above measurement noise.
                let mut acc = [0u8; MSIN_FIXED_LEN];
                let mut i = 0;
                while i < 100 {
                    let r = extract_msin(imsi, *mnc_len);
                    let mut j = 0;
                    while j < MSIN_FIXED_LEN { acc[j] ^= r[j]; j += 1; }
                    i += 1;
                }
                black_box(acc);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// extract_msin timing must be independent of MNC length parameter.
    ///
    /// Class 0: mnc_len = 2 (2-digit MNC, more MSIN digits).
    /// Class 1: mnc_len = 3 (3-digit MNC, fewer MSIN digits).
    ///
    /// The skip offset changes, but the function always decodes all 15
    /// positions and packs exactly MSIN_FIXED_LEN bytes. Iterated 100x
    /// to amplify any real timing difference above measurement noise.
    #[test]
    fn test_extract_msin_mnc_length_ct() {
        let outcome = ct_test(0x0051_0002,
            |rng| {
                let mut imsi = [0x08u8, 0x09, 0, 0, 0, 0, 0, 0, 0];
                let mut rand_bytes = [0u8; 7];
                rng.fill_bytes(&mut rand_bytes);
                imsi[2..9].copy_from_slice(&rand_bytes);
                (imsi, 2u8)
            },
            |rng| {
                let mut imsi = [0x08u8, 0x09, 0, 0, 0, 0, 0, 0, 0];
                let mut rand_bytes = [0u8; 7];
                rng.fill_bytes(&mut rand_bytes);
                imsi[2..9].copy_from_slice(&rand_bytes);
                (imsi, 3u8)
            },
            |(imsi, mnc_len)| {
                let mut acc = [0u8; MSIN_FIXED_LEN];
                let mut i = 0;
                while i < 100 {
                    let r = extract_msin(imsi, *mnc_len);
                    let mut j = 0;
                    while j < MSIN_FIXED_LEN { acc[j] ^= r[j]; j += 1; }
                    i += 1;
                }
                black_box(acc);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// extract_mcc_mnc timing must be independent of IMSI digit values.
    ///
    /// Both classes generate random IMSI data identically, then XOR with
    /// different constant masks (single AND instruction, no variable-time
    /// division). The timed block iterates 100x to amplify any real CT
    /// violation above measurement noise (function runs in ~3ns).
    ///
    /// Class 0: random IMSI masked with 0x44 (low nibbles).
    /// Class 1: random IMSI OR'd with 0x88 (high nibbles).
    #[test]
    fn test_extract_mcc_mnc_ct() {
        let outcome = ct_test(0x0051_0003,
            |rng| {
                // Class 0: random data AND 0x77 -> bytes in [0x00, 0x77].
                let mut imsi = [0x08u8, 0x09, 0, 0, 0, 0, 0, 0, 0];
                let mut rand_bytes = [0u8; 7];
                rng.fill_bytes(&mut rand_bytes);
                let mut i = 0;
                while i < 7 { imsi[i + 2] = rand_bytes[i] & 0x77; i += 1; }
                (imsi, 2u8)
            },
            |rng| {
                // Class 1: random data OR 0x88 -> bytes in [0x88, 0xFF].
                let mut imsi = [0x08u8, 0x09, 0, 0, 0, 0, 0, 0, 0];
                let mut rand_bytes = [0u8; 7];
                rng.fill_bytes(&mut rand_bytes);
                let mut i = 0;
                while i < 7 { imsi[i + 2] = rand_bytes[i] | 0x88; i += 1; }
                (imsi, 2u8)
            },
            |(imsi, mnc_len)| {
                // Iterate 100x to amplify signal above measurement noise.
                let mut acc = [0u8; 3];
                let mut i = 0;
                while i < 100 {
                    let r = extract_mcc_mnc(imsi, *mnc_len);
                    acc[0] ^= r[0]; acc[1] ^= r[1]; acc[2] ^= r[2];
                    i += 1;
                }
                black_box(acc);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Profile B constant-time scalar selection: mask arithmetic timing must
    /// be independent of which byte values flow through the OR combination.
    ///
    /// All candidates are valid P-256 scalars (matching production behavior
    /// where P(invalid) ~ 2^-128). Both classes always select candidate 0
    /// via the mask logic. The classes differ in candidate byte content:
    /// Class 0: c0 has low-byte values (0x01..0x20).
    /// Class 1: c0 has high-byte values (0xA0..0xBF).
    ///
    /// The mask AND+OR over all 32 bytes takes the same time regardless of
    /// the byte values involved. A branching implementation that iterated
    /// candidates and broke early would not exhibit this property.
    #[test]
    fn test_profile_b_scalar_selection_ct() {
        let outcome = ct_test(0x0051_0004,
            |rng| {
                // Class 0: all-valid candidates with low-byte c0.
                let mut c0 = [0u8; 32]; rng.fill_bytes(&mut c0);
                let mut c1 = [0u8; 32]; rng.fill_bytes(&mut c1);
                let mut c2 = [0u8; 32]; rng.fill_bytes(&mut c2);
                let mut c3 = [0u8; 32]; rng.fill_bytes(&mut c3);
                // Clamp c0 to low range [0x01..0x20].
                let mut i = 0;
                while i < 32 { c0[i] = (c0[i] % 0x20) + 0x01; i += 1; }
                // Ensure all are valid (mid-range values always are).
                c0[0] = 0x01; c1[0] = 0x10; c2[0] = 0x20; c3[0] = 0x30;
                (c0, c1, c2, c3)
            },
            |rng| {
                // Class 1: all-valid candidates with high-byte c0.
                let mut c0 = [0u8; 32]; rng.fill_bytes(&mut c0);
                let mut c1 = [0u8; 32]; rng.fill_bytes(&mut c1);
                let mut c2 = [0u8; 32]; rng.fill_bytes(&mut c2);
                let mut c3 = [0u8; 32]; rng.fill_bytes(&mut c3);
                // Clamp c0 to high range [0xA0..0xBF].
                let mut i = 0;
                while i < 32 { c0[i] = (c0[i] % 0x20) + 0xA0; i += 1; }
                c0[0] = 0xA0; c1[0] = 0x10; c2[0] = 0x20; c3[0] = 0x30;
                (c0, c1, c2, c3)
            },
            |(c0, c1, c2, c3)| {
                // All candidates are valid, so v0=v1=v2=v3=true always.
                // The mask logic always selects c0.
                let v0 = simrs_ecies::p256::validate_scalar(c0);
                let v1 = simrs_ecies::p256::validate_scalar(c1);
                let v2 = simrs_ecies::p256::validate_scalar(c2);
                let v3 = simrs_ecies::p256::validate_scalar(c3);

                let m0 = (v0 as u8).wrapping_neg();
                let found0 = m0;
                let m1 = (v1 as u8).wrapping_neg() & !found0;
                let found1 = found0 | (v1 as u8).wrapping_neg();
                let m2 = (v2 as u8).wrapping_neg() & !found1;
                let found2 = found1 | (v2 as u8).wrapping_neg();
                let m3 = (v3 as u8).wrapping_neg() & !found2;
                let _ = found2;

                let mut eph_sk = [0u8; 32];
                let mut j = 0;
                while j < 32 {
                    eph_sk[j] = (c0[j] & m0) | (c1[j] & m1) | (c2[j] & m2) | (c3[j] & m3);
                    j += 1;
                }
                black_box(eph_sk);
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// Integration-level test: handle_get_identity (null scheme) response
    /// timing must be independent of IMSI/MSIN content.
    ///
    /// Class 0: fixed IMSI (all-zero digits).
    /// Class 1: random IMSI (random digit patterns).
    ///
    /// This is the critical gap: previously only library-level primitives
    /// were covered, not the integration path where extract_msin + TLV
    /// encoding combine.
    #[test]
    fn test_get_identity_null_scheme_ct() {
        use simrs_milenage::{OperatorVariant, SubscriberKey};

        // Build two apps with different IMSI data.
        // We mutate EF_IMSI content between calls to get different MSIN values
        // while keeping the same app structure.

        let auth = MilenageParams::with_defaults(SubscriberKey::new(Secret::new([0u8; 16])), OperatorVariant::opc(Secret::new([0u8; 16])));
        let seed = SuciSeed::new([0x42u8; 32]);
        let mut app = UsimApp::new(
            &profile::REFERENCE_MF, &profile::ADF_TABLE, auth,
        );
        *app.suci_mut() = Some(SuciState::new(seed));

        // Prepare GET IDENTITY command (INS=0x78, P1=0x00, P2=0x01).
        let cmd_bytes = [0x00, 0x78, 0x00, 0x01];
        let cmd = Command::parse(&cmd_bytes).unwrap();

        // Write fixed IMSI before test loop.
        let fixed_imsi: [u8; 9] = [0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let outcome = ct_test(0x0051_0005,
            |rng| {
                let mut _discard = [0u8; 7];
                rng.fill_bytes(&mut _discard);
                fixed_imsi
            },
            |rng| {
                let mut imsi = [0x08u8, 0x09, 0, 0, 0, 0, 0, 0, 0];
                let mut rand_bytes = [0u8; 7];
                rng.fill_bytes(&mut rand_bytes);
                imsi[2..9].copy_from_slice(&rand_bytes);
                imsi
            },
            |imsi_data| {
                // Write IMSI to the filesystem, then invoke GET IDENTITY.
                app.data.write_binary(&profile::EF_IMSI, 0, imsi_data).unwrap();
                let mut buf = [0u8; 256];
                let rsp = app.handle(&cmd, &mut buf);
                black_box(rsp);
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
