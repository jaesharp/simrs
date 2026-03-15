//! HMAC-SHA-256 and 3GPP key derivation functions.
//!
//! Provides:
//! - [`HmacSha256`] streaming HMAC and [`hmac_sha256`] one-shot
//!   per [RFC 2104](../../../docs/specs/ietf/rfc2104.txt) / NIST FIPS 198-1
//! - [`kdf`] generic 3GPP KDF per
//!   [TS 33.220](../../../docs/specs/3gpp/ts-33.220/ts_133220v150200p.pdf) Annex B
//! - 4G EPS-AKA derivations ([`derive_eps_anchor_key`], [`derive_eps_base_station_key`],
//!   [`derive_algorithm_key`]) per
//!   [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A
//! - EAP-AKA' key derivation ([`derive_ck_prime_ik_prime`]) per
//!   [TS 33.402](../../../docs/specs/3gpp/ts-33.402/ts_133402v170000p.pdf) /
//!   [RFC 5448](../../../docs/specs/ietf/rfc5448.txt)
//! - 5G NR derivations ([`derive_auth_server_key`], [`derive_hash_response`],
//!   [`derive_security_anchor_key`], [`derive_mobility_management_key`],
//!   [`derive_nr_base_station_key`]) per
//!   [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
//!
//! # Example
//!
//! ```
//! use simrs_kdf::hmac_sha256;
//! use simrs_secret::Secret;
//!
//! let mac = hmac_sha256(&Secret::new(*b"key"), b"message");
//! assert_ne!(mac, [0u8; 32]);
//! ```
#![no_std]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::unreadable_literal)]

#[cfg(feature = "std")]
extern crate std;

use simrs_milenage::{AuthChallenge, CipherKey, IntegrityKey};
use simrs_secret::Secret;
use simrs_sha256::Sha256;

// ---------------------------------------------------------------------------
// Constants (RFC 2104)
// ---------------------------------------------------------------------------

/// HMAC block size (SHA-256 input block = 64 bytes).
const HMAC_BLOCK_SIZE: usize = 64;

/// Inner pad byte (RFC 2104 clause 2).
const IPAD: u8 = 0x36;

/// Outer pad byte (RFC 2104 clause 2).
const OPAD: u8 = 0x5C;

// ---------------------------------------------------------------------------
// HMAC-SHA-256 (RFC 2104 / NIST FIPS 198-1)
// ---------------------------------------------------------------------------

/// HMAC-SHA-256 streaming authenticator per [RFC 2104](../../../docs/specs/ietf/rfc2104.txt).
///
/// ```
/// use simrs_kdf::HmacSha256;
/// use simrs_secret::Secret;
///
/// let mut mac = HmacSha256::new(&Secret::new(*b"Jefe"));
/// mac.update(b"what do ya want ");
/// mac.update(b"for nothing?");
/// let tag = mac.finalize();
/// assert_eq!(
///     tag,
///     [
///         0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
///         0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
///         0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
///         0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
///     ]
/// );
/// ```
pub struct HmacSha256 {
    /// Inner hash (H(K XOR ipad || ...)).
    inner: Sha256,
    /// Outer key pad (K XOR opad), ready for the outer hash.
    opad_key: Secret<[u8; HMAC_BLOCK_SIZE]>,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA-256 instance with the given key.
    ///
    /// Keys longer than 64 bytes are first hashed with SHA-256 per RFC 2104
    /// clause 2. Keys shorter than 64 bytes are zero-padded.
    pub fn new<K: AsRef<[u8]>>(key: &Secret<K>) -> Self {
        let key = key.declassify_ref().as_ref();
        // Step 1: If key > block_size, hash it to 32 bytes.
        let mut key_block = [0u8; HMAC_BLOCK_SIZE];
        if key.len() > HMAC_BLOCK_SIZE {
            let hashed = simrs_sha256::sha256(key);
            key_block[..32].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Step 2: Compute ipad_key = key XOR ipad, opad_key = key XOR opad.
        let mut ipad_key = [0u8; HMAC_BLOCK_SIZE];
        let mut opad_key = [0u8; HMAC_BLOCK_SIZE];
        let mut i = 0;
        while i < HMAC_BLOCK_SIZE {
            ipad_key[i] = key_block[i] ^ IPAD;
            opad_key[i] = key_block[i] ^ OPAD;
            i += 1;
        }

        // Step 3: Start inner hash with ipad_key.
        let mut inner = Sha256::new();
        inner.update(&ipad_key);

        Self {
            inner,
            opad_key: Secret::new(opad_key),
        }
    }

    /// Feed data into the HMAC computation.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 256-bit HMAC tag.
    ///
    /// Consumes the authenticator. Computes:
    /// `H((K XOR opad) || H((K XOR ipad) || message))`
    pub fn finalize(self) -> [u8; 32] {
        // Inner hash result.
        let inner_hash = self.inner.finalize();

        // Outer hash: H(opad_key || inner_hash).
        let mut outer = Sha256::new();
        outer.update(self.opad_key.declassify_ref());
        outer.update(&inner_hash);
        outer.finalize()
    }
}

/// One-shot HMAC-SHA-256.
///
/// ```
/// use simrs_kdf::hmac_sha256;
/// use simrs_secret::Secret;
///
/// // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
/// let tag = hmac_sha256(&Secret::new(*b"Jefe"), b"what do ya want for nothing?");
/// assert_eq!(tag[0], 0x5b);
/// ```
pub fn hmac_sha256<K: AsRef<[u8]>>(key: &Secret<K>, data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

// ---------------------------------------------------------------------------
// 3GPP Generic KDF (TS 33.220 Annex B)
// ---------------------------------------------------------------------------

/// 3GPP key derivation function per [TS 33.220](../../../docs/specs/3gpp/ts-33.220/ts_133220v150200p.pdf) Annex B.
///
/// Computes `HMAC-SHA-256(key, S)` where:
/// ```text
/// S = FC || P0 || L0 || P1 || L1 || ...
/// ```
/// Each `Li` is the big-endian 16-bit encoding of the length of `Pi`.
///
/// # Panics
///
/// Panics if any parameter is longer than 65535 bytes.
pub fn kdf<K: AsRef<[u8]>>(key: &Secret<K>, fc: u8, params: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);

    // FC
    mac.update(&[fc]);

    // P0 || L0 || P1 || L1 || ...
    for p in params {
        mac.update(p);
        let len = p.len();
        assert!(len <= 0xFFFF, "KDF parameter too long");
        #[allow(clippy::cast_possible_truncation)] // guarded by assert above
        let len16 = len as u16;
        mac.update(&len16.to_be_bytes());
    }

    mac.finalize()
}

// ---------------------------------------------------------------------------
// 4G EPS-AKA key derivations (TS 33.401 Annex A)
// ---------------------------------------------------------------------------

/// Derive the EPS anchor key from CK, IK, PLMN-ID, and SQN XOR AK.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.2:
/// - FC = 0x10
/// - P0 = PLMN-ID (3 bytes, MCC/MNC encoded per TS 24.008)
/// - P1 = SQN XOR AK (6 bytes)
/// - Key = CK || IK (32 bytes)
pub fn derive_eps_anchor_key(
    ck: &CipherKey,
    ik: &IntegrityKey,
    network_id: &NetworkId,
    concealed_sqn: &ConcealedSequenceNumber,
) -> EpsAnchorKey {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck.declassify());
    key[16..].copy_from_slice(ik.declassify());
    EpsAnchorKey::classify(kdf(
        &Secret::new(key),
        0x10,
        &[network_id.as_bytes(), concealed_sqn.as_bytes()],
    ))
}

/// 3GPP abbreviation for [`derive_eps_anchor_key`].
#[deprecated(note = "3GPP K_ASME (TS 33.401 A.2) -- prefer derive_eps_anchor_key()")]
pub fn derive_kasme(
    ck: &CipherKey,
    ik: &IntegrityKey,
    network_id: &NetworkId,
    concealed_sqn: &ConcealedSequenceNumber,
) -> EpsAnchorKey {
    derive_eps_anchor_key(ck, ik, network_id, concealed_sqn)
}

/// Derive the EPS base station key from the EPS anchor key and uplink NAS count.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.3:
/// - FC = 0x11
/// - P0 = uplink NAS count (4 bytes, big-endian)
pub fn derive_eps_base_station_key(kasme: &EpsAnchorKey, ul_nas_count: u32) -> EpsBaseStationKey {
    let count_be = ul_nas_count.to_be_bytes();
    EpsBaseStationKey::classify(kdf(&Secret::new(*kasme.declassify()), 0x11, &[&count_be]))
}

/// 3GPP abbreviation for [`derive_eps_base_station_key`].
#[deprecated(note = "3GPP K_eNB (TS 33.401 A.3) -- prefer derive_eps_base_station_key()")]
pub fn derive_kenb(kasme: &EpsAnchorKey, ul_nas_count: u32) -> EpsBaseStationKey {
    derive_eps_base_station_key(kasme, ul_nas_count)
}

/// Derive algorithm-specific key from a parent key.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.7:
/// - FC = 0x15
/// - P0 = algorithm type distinguisher (1 byte)
/// - P1 = algorithm identity (1 byte)
///
/// Algorithm type distinguishers:
/// - 0x01: NAS encryption (`K_NASenc`)
/// - 0x02: NAS integrity (`K_NASint`)
/// - 0x03: RRC encryption (`K_RRCenc`)
/// - 0x04: RRC integrity (`K_RRCint`)
/// - 0x05: UP encryption (`K_UPenc`)
/// - 0x06: UP integrity (`K_UPint`)
pub fn derive_algorithm_key(key: &[u8; 32], alg_distinguisher: u8, alg_id: u8) -> AlgorithmKey {
    AlgorithmKey::classify(kdf(
        &Secret::new(*key),
        0x15,
        &[&[alg_distinguisher], &[alg_id]],
    ))
}

// ---------------------------------------------------------------------------
// EAP-AKA' key derivation (TS 33.402, RFC 5448)
// ---------------------------------------------------------------------------

/// Derive CK' and IK' for EAP-AKA' from CK, IK, the serving network name,
/// and the concealed sequence number (SQN XOR AK).
///
/// Per [TS 33.402](../../../docs/specs/3gpp/ts-33.402/ts_133402v170000p.pdf) /
/// [RFC 5448](../../../docs/specs/ietf/rfc5448.txt) Section 3.4:
/// - Key = CK || IK (32 bytes)
/// - FC = 0x20
/// - P0 = access network identity (variable-length, e.g. "WLAN" or "HRPD")
/// - P1 = SQN XOR AK (6 bytes)
///
/// Returns `(CK', IK')` where CK' = output\[0..16\] and IK' = output\[16..32\].
///
/// When the AMF separation bit (bit 0 of AMF byte 0) is set in the received
/// AUTN, the USIM should use this function to derive CK'/IK' from CK/IK
/// before returning them to the ME.
pub fn derive_ck_prime_ik_prime(
    ck: &CipherKey,
    ik: &IntegrityKey,
    network_name: &[u8],
    sqn_xor_ak: &ConcealedSequenceNumber,
) -> (CipherKey, IntegrityKey) {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck.declassify());
    key[16..].copy_from_slice(ik.declassify());
    let out = kdf(
        &Secret::new(key),
        0x20,
        &[network_name, sqn_xor_ak.as_bytes()],
    );
    let mut ck_prime = [0u8; 16];
    let mut ik_prime = [0u8; 16];
    ck_prime.copy_from_slice(&out[..16]);
    ik_prime.copy_from_slice(&out[16..32]);
    (
        CipherKey::classify(ck_prime),
        IntegrityKey::classify(ik_prime),
    )
}

// ---------------------------------------------------------------------------
// 5G NR key derivations (TS 33.501 Annex A)
// ---------------------------------------------------------------------------

/// Derive the authentication server key from CK', IK', serving network name,
/// and SQN XOR AK.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.2:
/// - FC = 0x6A
/// - P0 = serving network name (variable-length UTF-8, e.g. "5G:mnc001.mcc001.3gppnetwork.org")
/// - P1 = SQN XOR AK (6 bytes)
/// - Key = CK' || IK' (32 bytes, derived per TS 33.501 Annex A.2)
///
/// Note: the caller provides CK'/IK' (not raw CK/IK). For 5G-AKA, CK' and IK'
/// are derived from CK, IK per TS 33.501 C.2 using the serving network name.
pub fn derive_auth_server_key(
    ck: &CipherKey,
    ik: &IntegrityKey,
    serving_network_name: &[u8],
    concealed_sqn: &ConcealedSequenceNumber,
) -> AuthServerKey {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck.declassify());
    key[16..].copy_from_slice(ik.declassify());
    AuthServerKey::classify(kdf(
        &Secret::new(key),
        0x6A,
        &[serving_network_name, concealed_sqn.as_bytes()],
    ))
}

/// 3GPP abbreviation for [`derive_auth_server_key`].
#[deprecated(note = "3GPP K_AUSF (TS 33.501 A.2) -- prefer derive_auth_server_key()")]
pub fn derive_kausf(
    ck: &CipherKey,
    ik: &IntegrityKey,
    snn: &[u8],
    concealed_sqn: &ConcealedSequenceNumber,
) -> AuthServerKey {
    derive_auth_server_key(ck, ik, snn, concealed_sqn)
}

/// Derive the hash response from CK', IK', serving network name, RAND, and RES.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.4:
/// - FC = 0x6B
/// - P0 = serving network name
/// - P1 = RAND (16 bytes)
/// - P2 = RES (variable length, typically 8 or 16 bytes)
/// - Key = CK' || IK' (32 bytes)
///
/// Returns the 128 least-significant bits (bytes 16..32 of the HMAC output).
pub fn derive_hash_response(
    ck: &CipherKey,
    ik: &IntegrityKey,
    serving_network_name: &[u8],
    rand: &AuthChallenge,
    res: &[u8],
) -> HashResponse {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck.declassify());
    key[16..].copy_from_slice(ik.declassify());
    let full = kdf(
        &Secret::new(key),
        0x6B,
        &[serving_network_name, rand.as_bytes(), res],
    );
    // 128 LSBs = bytes 16..32
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[16..32]);
    HashResponse::new(out)
}

/// 3GPP abbreviation for [`derive_hash_response`].
#[deprecated(note = "3GPP RES* (TS 33.501 A.4) -- prefer derive_hash_response()")]
pub fn derive_res_star(
    ck: &CipherKey,
    ik: &IntegrityKey,
    snn: &[u8],
    rand: &AuthChallenge,
    res: &[u8],
) -> HashResponse {
    derive_hash_response(ck, ik, snn, rand, res)
}

/// Derive the security anchor key from the authentication server key and
/// serving network name.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.6:
/// - FC = 0x6C
/// - P0 = serving network name
pub fn derive_security_anchor_key(
    kausf: &AuthServerKey,
    serving_network_name: &[u8],
) -> SecurityAnchorKey {
    SecurityAnchorKey::classify(kdf(
        &Secret::new(*kausf.declassify()),
        0x6C,
        &[serving_network_name],
    ))
}

/// 3GPP abbreviation for [`derive_security_anchor_key`].
#[deprecated(note = "3GPP K_SEAF (TS 33.501 A.6) -- prefer derive_security_anchor_key()")]
pub fn derive_kseaf(kausf: &AuthServerKey, snn: &[u8]) -> SecurityAnchorKey {
    derive_security_anchor_key(kausf, snn)
}

/// Derive the mobility management key from the security anchor key, SUPI,
/// and ABBA parameter.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.7:
/// - FC = 0x6D
/// - P0 = SUPI (IMSI as ASCII digits)
/// - P1 = ABBA parameter (2 bytes for primary authentication)
pub fn derive_mobility_management_key(
    kseaf: &SecurityAnchorKey,
    supi: &[u8],
    abba: &[u8],
) -> MobilityManagementKey {
    MobilityManagementKey::classify(kdf(&Secret::new(*kseaf.declassify()), 0x6D, &[supi, abba]))
}

/// 3GPP abbreviation for [`derive_mobility_management_key`].
#[deprecated(note = "3GPP K_AMF (TS 33.501 A.7) -- prefer derive_mobility_management_key()")]
pub fn derive_kamf(kseaf: &SecurityAnchorKey, supi: &[u8], abba: &[u8]) -> MobilityManagementKey {
    derive_mobility_management_key(kseaf, supi, abba)
}

/// Derive the NR base station key from the mobility management key, uplink
/// NAS count, and access type.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.9:
/// - FC = 0x6E
/// - P0 = uplink NAS count (4 bytes, big-endian)
/// - P1 = access type distinguisher (1 byte: 0x01 = 3GPP, 0x02 = non-3GPP)
pub fn derive_nr_base_station_key(
    kamf: &MobilityManagementKey,
    ul_nas_count: u32,
    access_type: u8,
) -> NrBaseStationKey {
    let count_be = ul_nas_count.to_be_bytes();
    NrBaseStationKey::classify(kdf(
        &Secret::new(*kamf.declassify()),
        0x6E,
        &[&count_be, &[access_type]],
    ))
}

/// 3GPP abbreviation for [`derive_nr_base_station_key`].
#[deprecated(note = "3GPP K_gNB (TS 33.501 A.9) -- prefer derive_nr_base_station_key()")]
pub fn derive_kgnb(
    kamf: &MobilityManagementKey,
    ul_nas_count: u32,
    access_type: u8,
) -> NrBaseStationKey {
    derive_nr_base_station_key(kamf, ul_nas_count, access_type)
}

// ---------------------------------------------------------------------------
// GBA key derivation (TS 33.220 Annex B.3)
// ---------------------------------------------------------------------------

/// GBA bootstrapping session key (256 bits).
///
/// Constructed as `Ks = CK || IK` after a successful GBA bootstrap procedure.
/// Forms the root of the GBA key hierarchy for NAF-specific key derivation.
///
/// Per [TS 33.220](https://www.3gpp.org/DynaReport/33220.htm) clause 4.5.2.
#[derive(Clone, Copy)]
pub struct GbaSessionKey(Secret<[u8; 32]>);

impl GbaSessionKey {
    /// Construct a GBA session key from CK and IK (Ks = CK || IK).
    pub fn from_ck_ik(ck: &CipherKey, ik: &IntegrityKey) -> Self {
        let mut raw = [0u8; 32];
        raw[..16].copy_from_slice(ck.declassify());
        raw[16..].copy_from_slice(ik.declassify());
        Self(Secret::new(raw))
    }

    /// Classify a raw 256-bit value as a GBA session key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for GbaSessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GbaSessionKey([REDACTED])")
    }
}

/// GBA NAF-specific key (256 bits).
///
/// Derived from Ks using the 3GPP KDF with "gba-me" (external) or
/// "gba-u" (internal) label, RAND, IMPI, and `NAF_ID`.
///
/// Per [TS 33.220](https://www.3gpp.org/DynaReport/33220.htm) Annex B.3.
#[derive(Clone, Copy)]
pub struct GbaNafKey(Secret<[u8; 32]>);

impl GbaNafKey {
    /// Classify a raw 256-bit value as a GBA NAF key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for GbaNafKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GbaNafKey([REDACTED])")
    }
}

/// Derive the external NAF-specific key (`Ks_ext_NAF` / `Ks_NAF`) for GBA.
///
/// Per [TS 33.220](https://www.3gpp.org/DynaReport/33220.htm) Annex B.3:
/// - Key = Ks (= CK || IK, 32 bytes)
/// - FC = 0x01
/// - P0 = "gba-me" (6 bytes)
/// - P1 = RAND (16 bytes)
/// - P2 = IMPI (variable)
/// - P3 = `NAF_ID` (variable)
///
/// This is the key returned to the ME in `GBA_U`, or the sole NAF key in `GBA_ME`.
pub fn derive_gba_ext_naf_key(
    ks: &GbaSessionKey,
    rand: &[u8; 16],
    impi: &[u8],
    naf_id: &[u8],
) -> GbaNafKey {
    GbaNafKey::classify(kdf(
        &Secret::new(*ks.declassify()),
        0x01,
        &[b"gba-me", &rand[..], impi, naf_id],
    ))
}

/// Derive the internal NAF-specific key (`Ks_int_NAF`) for `GBA_U`.
///
/// Per [TS 33.220](https://www.3gpp.org/DynaReport/33220.htm) Annex B.3:
/// - Key = Ks (= CK || IK, 32 bytes)
/// - FC = 0x01
/// - P0 = "gba-u" (5 bytes)
/// - P1 = RAND (16 bytes)
/// - P2 = IMPI (variable)
/// - P3 = `NAF_ID` (variable)
///
/// This key stays on the UICC for use by on-card applications.
pub fn derive_gba_int_naf_key(
    ks: &GbaSessionKey,
    rand: &[u8; 16],
    impi: &[u8],
    naf_id: &[u8],
) -> GbaNafKey {
    GbaNafKey::classify(kdf(
        &Secret::new(*ks.declassify()),
        0x01,
        &[b"gba-u", &rand[..], impi, naf_id],
    ))
}

/// 3GPP abbreviation for [`derive_gba_ext_naf_key`].
#[deprecated(note = "3GPP Ks_NAF / Ks_ext_NAF (TS 33.220 B.3) -- prefer derive_gba_ext_naf_key()")]
pub fn derive_ks_naf(ks: &GbaSessionKey, rand: &[u8; 16], impi: &[u8], naf_id: &[u8]) -> GbaNafKey {
    derive_gba_ext_naf_key(ks, rand, impi, naf_id)
}

/// 3GPP abbreviation for [`derive_gba_int_naf_key`].
#[deprecated(note = "3GPP Ks_int_NAF (TS 33.220 B.3) -- prefer derive_gba_int_naf_key()")]
pub fn derive_ks_int_naf(
    ks: &GbaSessionKey,
    rand: &[u8; 16],
    impi: &[u8],
    naf_id: &[u8],
) -> GbaNafKey {
    derive_gba_int_naf_key(ks, rand, impi, naf_id)
}

// ---------------------------------------------------------------------------
// ANSI X9.63 KDF (SEC 1 v2.0 clause 3.6.1)
// ---------------------------------------------------------------------------

/// Maximum output length for [`kdf_x963`] (256 bytes = 8 SHA-256 blocks).
///
/// This limit is generous for ECIES Profile B which needs at most 48 bytes.
const KDF_X963_MAX_OUT: usize = 256;

/// ANSI X9.63 key derivation function using SHA-256.
///
/// Per SEC 1 v2.0 clause 3.6.1 / ANSI X9.63-2001:
/// ```text
/// K = SHA-256(Z || counter || SharedInfo) [|| SHA-256(Z || counter+1 || SharedInfo) || ...]
/// ```
/// where `counter` starts at `0x00000001` (big-endian 32-bit) and increments.
///
/// Writes `out_len` bytes of derived key material into `out`.
///
/// # Panics
///
/// Panics if `out_len > 256`, `out_len == 0`, or `out.len() < out_len`.
pub fn kdf_x963(z: &[u8], shared_info: &[u8], out_len: usize, out: &mut [u8]) {
    assert!(
        out_len > 0 && out_len <= KDF_X963_MAX_OUT,
        "invalid output length"
    );
    assert!(out.len() >= out_len, "output buffer too small");

    let mut counter: u32 = 1;
    let mut offset = 0;

    while offset < out_len {
        let mut h = Sha256::new();
        h.update(z);
        h.update(&counter.to_be_bytes());
        h.update(shared_info);
        let block = h.finalize();

        let remaining = out_len - offset;
        let copy_len = if remaining < 32 { remaining } else { 32 };
        let mut i = 0;
        while i < copy_len {
            out[offset + i] = block[i];
            i += 1;
        }
        offset += copy_len;
        counter += 1;
    }
}

// ---------------------------------------------------------------------------
// KDF output newtypes
// ---------------------------------------------------------------------------

// -- Secret-wrapped types (256-bit keys) ------------------------------------

/// 4G EPS anchor key (256 bits).
///
/// Derived from CK, IK, PLMN-ID and concealed sequence number.
/// Forms the root of the 4G key hierarchy.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.2.
#[derive(Clone, Copy)]
pub struct EpsAnchorKey(Secret<[u8; 32]>);

impl EpsAnchorKey {
    /// Classify a raw 256-bit value as an EPS anchor key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for EpsAnchorKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EpsAnchorKey([REDACTED])")
    }
}

/// 3GPP abbreviation for [`EpsAnchorKey`].
///
/// The specs (TS 33.401 Annex A.2) use the name "`K_ASME`" (Key for Access
/// Security Management Entity). We prefer `EpsAnchorKey` because it describes
/// the key's architectural role without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP K_ASME (TS 33.401 A.2) -- prefer EpsAnchorKey")]
pub type Kasme = EpsAnchorKey;

/// 4G base station key (256 bits).
///
/// Derived from `K_ASME` and uplink NAS count.
/// Used to protect the radio interface between UE and eNB.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.3.
#[derive(Clone, Copy)]
pub struct EpsBaseStationKey(Secret<[u8; 32]>);

impl EpsBaseStationKey {
    /// Classify a raw 256-bit value as an EPS base station key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for EpsBaseStationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EpsBaseStationKey([REDACTED])")
    }
}

/// 3GPP abbreviation for [`EpsBaseStationKey`].
///
/// The specs (TS 33.401 Annex A.3) use the name "`K_eNB`". We prefer
/// `EpsBaseStationKey` because it describes the key's role in protecting
/// the 4G radio interface without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP K_eNB (TS 33.401 A.3) -- prefer EpsBaseStationKey")]
pub type Kenb = EpsBaseStationKey;

/// Algorithm-derived key (256 bits).
///
/// Derived from a parent key with algorithm type distinguisher and identity.
/// Used for NAS, RRC, and UP encryption/integrity protection.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.7.
#[derive(Clone, Copy)]
pub struct AlgorithmKey(Secret<[u8; 32]>);

impl AlgorithmKey {
    /// Classify a raw 256-bit value as an algorithm-derived key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for AlgorithmKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AlgorithmKey([REDACTED])")
    }
}

/// 3GPP abbreviation for [`AlgorithmKey`].
///
/// The specs (TS 33.401 Annex A.7) use names like "`K_NASenc`", "`K_NASint`",
/// "`K_RRCenc`", etc. We prefer `AlgorithmKey` because it describes the
/// common derivation pattern without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP K_NAS/K_RRC/K_UP (TS 33.401 A.7) -- prefer AlgorithmKey")]
pub type NasKey = AlgorithmKey;

/// 5G authentication server function key (256 bits).
///
/// Derived from CK', IK', serving network name, and concealed sequence number.
/// First key in the 5G key hierarchy after authentication.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.2.
#[derive(Clone, Copy)]
pub struct AuthServerKey(Secret<[u8; 32]>);

impl AuthServerKey {
    /// Classify a raw 256-bit value as an authentication server key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for AuthServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthServerKey([REDACTED])")
    }
}

/// 3GPP abbreviation for [`AuthServerKey`].
///
/// The specs (TS 33.501 Annex A.2) use the name "`K_AUSF`" (Key for
/// Authentication Server Function). We prefer `AuthServerKey` because it
/// describes the key's role without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP K_AUSF (TS 33.501 A.2) -- prefer AuthServerKey")]
pub type Kausf = AuthServerKey;

/// 5G security anchor function key (256 bits).
///
/// Derived from `K_AUSF` and serving network name.
/// Anchors the 5G security context within the serving network.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.6.
#[derive(Clone, Copy)]
pub struct SecurityAnchorKey(Secret<[u8; 32]>);

impl SecurityAnchorKey {
    /// Classify a raw 256-bit value as a security anchor key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for SecurityAnchorKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecurityAnchorKey([REDACTED])")
    }
}

/// 3GPP abbreviation for [`SecurityAnchorKey`].
///
/// The specs (TS 33.501 Annex A.6) use the name "`K_SEAF`" (Key for
/// Security Anchor Function). We prefer `SecurityAnchorKey` because it
/// describes the key's architectural role without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP K_SEAF (TS 33.501 A.6) -- prefer SecurityAnchorKey")]
pub type Kseaf = SecurityAnchorKey;

/// 5G access and mobility management key (256 bits).
///
/// Derived from `K_SEAF`, SUPI, and ABBA parameter.
/// Used to derive further keys for NAS and AS protection.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.7.
#[derive(Clone, Copy)]
pub struct MobilityManagementKey(Secret<[u8; 32]>);

impl MobilityManagementKey {
    /// Classify a raw 256-bit value as a mobility management key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for MobilityManagementKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MobilityManagementKey([REDACTED])")
    }
}

/// 3GPP abbreviation for [`MobilityManagementKey`].
///
/// The specs (TS 33.501 Annex A.7) use the name "`K_AMF`" (Key for Access
/// and Mobility Management Function). We prefer `MobilityManagementKey`
/// because it describes the key's role without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP K_AMF (TS 33.501 A.7) -- prefer MobilityManagementKey")]
pub type Kamf = MobilityManagementKey;

/// 5G NR base station key (256 bits).
///
/// Derived from `K_AMF`, uplink NAS count, and access type distinguisher.
/// Used to protect the radio interface between UE and gNB.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.9.
#[derive(Clone, Copy)]
pub struct NrBaseStationKey(Secret<[u8; 32]>);

impl NrBaseStationKey {
    /// Classify a raw 256-bit value as an NR base station key.
    #[inline]
    pub const fn classify(raw: [u8; 32]) -> Self {
        Self(Secret::new(raw))
    }
    /// Borrow the raw key bytes (leaves the CT-protected domain).
    #[inline]
    pub const fn declassify(&self) -> &[u8; 32] {
        self.0.declassify_ref()
    }
}

impl core::fmt::Debug for NrBaseStationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NrBaseStationKey([REDACTED])")
    }
}

/// 3GPP abbreviation for [`NrBaseStationKey`].
///
/// The specs (TS 33.501 Annex A.9) use the name "`K_gNB`". We prefer
/// `NrBaseStationKey` because it describes the key's role in protecting
/// the 5G NR radio interface without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP K_gNB (TS 33.501 A.9) -- prefer NrBaseStationKey")]
pub type Kgnb = NrBaseStationKey;

// -- Plain-wrapped types ----------------------------------------------------

/// Public Land Mobile Network identity (3 bytes).
///
/// Encodes MCC/MNC per TS 24.008 clause 10.5.1.13.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkId([u8; 3]);

impl NetworkId {
    /// Create a network identity from raw MCC/MNC bytes.
    #[inline]
    pub const fn new(raw: [u8; 3]) -> Self {
        Self(raw)
    }
    /// Borrow the underlying 3-byte representation.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 3] {
        &self.0
    }
}
impl From<[u8; 3]> for NetworkId {
    fn from(raw: [u8; 3]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`NetworkId`].
///
/// The specs use "PLMN-ID" (Public Land Mobile Network Identifier).
/// We prefer `NetworkId` for readability.
#[deprecated(note = "3GPP PLMN-ID (TS 24.008) -- prefer NetworkId")]
pub type PlmnId = NetworkId;

/// Concealed sequence number (6 bytes).
///
/// The XOR of the authentication sequence number (SQN) and the anonymity
/// key (AK), used to hide the SQN during authentication.
///
/// Per TS 33.102 clause 6.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcealedSequenceNumber([u8; 6]);

impl ConcealedSequenceNumber {
    /// Create a concealed sequence number from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 6]) -> Self {
        Self(raw)
    }
    /// Borrow the underlying 6-byte representation.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}
impl From<[u8; 6]> for ConcealedSequenceNumber {
    fn from(raw: [u8; 6]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`ConcealedSequenceNumber`].
///
/// The specs (TS 33.102 clause 6.3) use "SQN XOR AK". We prefer
/// `ConcealedSequenceNumber` because it describes the value's purpose
/// without requiring knowledge of the AKA protocol internals.
#[deprecated(note = "3GPP SQN XOR AK (TS 33.102 6.3) -- prefer ConcealedSequenceNumber")]
pub type SqnXorAk = ConcealedSequenceNumber;

/// Hash response for 5G authentication (128 bits).
///
/// The 128 least-significant bits of the KDF output, used as RES*
/// in the 5G-AKA protocol.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashResponse([u8; 16]);

impl HashResponse {
    /// Create a hash response from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 16]) -> Self {
        Self(raw)
    }
    /// Borrow the underlying 16-byte representation.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
impl From<[u8; 16]> for HashResponse {
    fn from(raw: [u8; 16]) -> Self {
        Self(raw)
    }
}

/// 3GPP abbreviation for [`HashResponse`].
///
/// The specs (TS 33.501 Annex A.4) use "RES*" (hashed response).
/// We prefer `HashResponse` because it describes the value's role
/// without requiring 3GPP nomenclature.
#[deprecated(note = "3GPP RES* (TS 33.501 A.4) -- prefer HashResponse")]
pub type ResStar = HashResponse;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: decode a hex string to a fixed-size byte array.
    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "hex32 expects 64 hex chars");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = hex_byte(s.as_bytes()[i * 2], s.as_bytes()[i * 2 + 1]);
            i += 1;
        }
        out
    }

    fn hex_byte(hi: u8, lo: u8) -> u8 {
        let h = match hi {
            b'0'..=b'9' => hi - b'0',
            b'a'..=b'f' => hi - b'a' + 10,
            b'A'..=b'F' => hi - b'A' + 10,
            _ => panic!("bad hex"),
        };
        let l = match lo {
            b'0'..=b'9' => lo - b'0',
            b'a'..=b'f' => lo - b'a' + 10,
            b'A'..=b'F' => lo - b'A' + 10,
            _ => panic!("bad hex"),
        };
        (h << 4) | l
    }

    // -----------------------------------------------------------------------
    // RFC 4231 HMAC-SHA-256 test vectors (docs/specs/ietf/rfc4231.txt)
    // -----------------------------------------------------------------------

    #[test]
    fn rfc4231_tc1() {
        // Key = 20 bytes of 0x0b, Data = "Hi There"
        let key = [0x0bu8; 20];
        let tag = hmac_sha256(&Secret::new(key), b"Hi There");
        assert_eq!(
            tag,
            hex32("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn rfc4231_tc2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let tag = hmac_sha256(&Secret::new(*b"Jefe"), b"what do ya want for nothing?");
        assert_eq!(
            tag,
            hex32("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn rfc4231_tc3() {
        // Key = 20 bytes of 0xaa, Data = 50 bytes of 0xdd
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let tag = hmac_sha256(&Secret::new(key), &data);
        assert_eq!(
            tag,
            hex32("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
        );
    }

    #[test]
    fn rfc4231_tc4() {
        // Key = 0x01..0x19 (25 bytes), Data = 50 bytes of 0xcd
        let mut key = [0u8; 25];
        let mut i = 0u8;
        while i < 25 {
            key[i as usize] = i + 1;
            i += 1;
        }
        let data = [0xcdu8; 50];
        let tag = hmac_sha256(&Secret::new(key), &data);
        assert_eq!(
            tag,
            hex32("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
        );
    }

    #[test]
    fn rfc4231_tc5() {
        // Truncation test: Key = 20 bytes of 0x0c, Data = "Test With Truncation"
        // RFC 4231 gives only the first 128 bits (16 bytes) of the HMAC output.
        let key = [0x0cu8; 20];
        let tag = hmac_sha256(&Secret::new(key), b"Test With Truncation");
        // Verify the first 16 bytes match the RFC's truncated value.
        assert_eq!(
            &tag[..16],
            &[
                0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55,
                0x55, 0x2b
            ]
        );
    }

    #[test]
    fn rfc4231_tc6() {
        // Key = 131 bytes of 0xaa (longer than block size)
        // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let key = [0xaau8; 131];
        let tag = hmac_sha256(
            &Secret::new(key),
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            tag,
            hex32("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn rfc4231_tc7() {
        // Key = 131 bytes of 0xaa (longer than block size)
        // Data = "This is a test using a larger than block-size key and a larger
        //         than block-size data. ..."
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let tag = hmac_sha256(&Secret::new(key), data);
        assert_eq!(
            tag,
            hex32("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
        );
    }

    // -----------------------------------------------------------------------
    // HMAC streaming tests
    // -----------------------------------------------------------------------

    #[test]
    fn hmac_streaming_equivalence() {
        let key = b"test-key";
        let msg = b"hello world";

        let one_shot = hmac_sha256(&Secret::new(*key), msg);

        let mut mac = HmacSha256::new(&Secret::new(*key));
        mac.update(b"hello ");
        mac.update(b"world");
        let streamed = mac.finalize();

        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn hmac_empty_key() {
        // Empty key should still produce a valid MAC.
        let tag = hmac_sha256(&Secret::new(*b""), b"data");
        assert_ne!(tag, [0u8; 32]);
    }

    #[test]
    fn hmac_empty_data() {
        let tag = hmac_sha256(&Secret::new(*b"key"), b"");
        assert_ne!(tag, [0u8; 32]);
    }

    #[test]
    fn hmac_different_keys_different_tags() {
        let t1 = hmac_sha256(&Secret::new(*b"key1"), b"msg");
        let t2 = hmac_sha256(&Secret::new(*b"key2"), b"msg");
        assert_ne!(t1, t2);
    }

    #[test]
    fn hmac_different_data_different_tags() {
        let t1 = hmac_sha256(&Secret::new(*b"key"), b"msg1");
        let t2 = hmac_sha256(&Secret::new(*b"key"), b"msg2");
        assert_ne!(t1, t2);
    }

    // -----------------------------------------------------------------------
    // Generic KDF tests
    // -----------------------------------------------------------------------

    #[test]
    fn kdf_different_fc_different_output() {
        let key = [0x42u8; 32];
        let p = [0x01, 0x02, 0x03];
        let out1 = kdf(&Secret::new(key), 0x10, &[&p]);
        let out2 = kdf(&Secret::new(key), 0x11, &[&p]);
        assert_ne!(out1, out2);
    }

    #[test]
    fn kdf_different_params_different_output() {
        let key = [0x42u8; 32];
        let p1 = [0x01, 0x02, 0x03];
        let p2 = [0x01, 0x02, 0x04];
        let out1 = kdf(&Secret::new(key), 0x10, &[&p1]);
        let out2 = kdf(&Secret::new(key), 0x10, &[&p2]);
        assert_ne!(out1, out2);
    }

    #[test]
    fn kdf_deterministic() {
        let key = [0x42u8; 32];
        let p = [0x01, 0x02, 0x03];
        let out1 = kdf(&Secret::new(key), 0x10, &[&p]);
        let out2 = kdf(&Secret::new(key), 0x10, &[&p]);
        assert_eq!(out1, out2);
    }

    #[test]
    fn kdf_s_construction_manual() {
        // Manually verify: kdf(key, FC=0x10, params=[P0]) should compute
        // HMAC-SHA-256(key, 0x10 || P0 || L0)
        let key = [0xAA; 16];
        let p0 = [0x01, 0x02, 0x03]; // 3 bytes -> L0 = 0x0003

        let kdf_result = kdf(&Secret::new(key), 0x10, &[&p0]);

        // Manually construct S = FC || P0 || L0
        let s: [u8; 6] = [0x10, 0x01, 0x02, 0x03, 0x00, 0x03];
        let manual = hmac_sha256(&Secret::new(key), &s);

        assert_eq!(kdf_result, manual);
    }

    #[test]
    fn kdf_multi_param_s_construction() {
        // Verify S = FC || P0 || L0 || P1 || L1 with two params.
        let key = [0xBB; 32];
        let p0 = [0x0A, 0x0B]; // 2 bytes -> L0 = 0x0002
        let p1 = [0x0C]; // 1 byte  -> L1 = 0x0001

        let kdf_result = kdf(&Secret::new(key), 0x20, &[&p0, &p1]);

        // S = 0x20 || 0x0A 0x0B || 0x00 0x02 || 0x0C || 0x00 0x01
        let s: [u8; 8] = [0x20, 0x0A, 0x0B, 0x00, 0x02, 0x0C, 0x00, 0x01];
        let manual = hmac_sha256(&Secret::new(key), &s);

        assert_eq!(kdf_result, manual);
    }

    // -----------------------------------------------------------------------
    // 4G/5G derivation chain tests
    // -----------------------------------------------------------------------

    #[test]
    fn derive_eps_anchor_key_not_zero() {
        let ck = CipherKey::classify([0x11u8; 16]);
        let ik = IntegrityKey::classify([0x22u8; 16]);
        let plmn = NetworkId::new([0x00, 0xF1, 0x10]); // MCC=001, MNC=01
        let sqn_ak = ConcealedSequenceNumber::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let kasme = derive_eps_anchor_key(&ck, &ik, &plmn, &sqn_ak);
        assert_ne!(*kasme.declassify(), [0u8; 32]);
    }

    #[test]
    fn derive_eps_anchor_key_different_plmn() {
        let ck = CipherKey::classify([0x11u8; 16]);
        let ik = IntegrityKey::classify([0x22u8; 16]);
        let sqn_ak = ConcealedSequenceNumber::new([0x00; 6]);

        let k1 = derive_eps_anchor_key(&ck, &ik, &NetworkId::new([0x00, 0xF1, 0x10]), &sqn_ak);
        let k2 = derive_eps_anchor_key(&ck, &ik, &NetworkId::new([0x00, 0xF1, 0x20]), &sqn_ak);
        assert_ne!(*k1.declassify(), *k2.declassify());
    }

    #[test]
    fn derive_eps_anchor_key_verifies_kdf_construction() {
        // EPS anchor key = KDF(CK||IK, FC=0x10, P0=PLMN, P1=SQN^AK)
        let ck = CipherKey::classify([0x33u8; 16]);
        let ik = IntegrityKey::classify([0x44u8; 16]);
        let plmn = NetworkId::new([0x00, 0xF1, 0x10]);
        let sqn_ak = ConcealedSequenceNumber::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

        let kasme = derive_eps_anchor_key(&ck, &ik, &plmn, &sqn_ak);

        // Manually compute with kdf()
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(ck.declassify());
        key[16..].copy_from_slice(ik.declassify());
        let expected = kdf(
            &Secret::new(key),
            0x10,
            &[&plmn.as_bytes()[..], &sqn_ak.as_bytes()[..]],
        );

        assert_eq!(*kasme.declassify(), expected);
    }

    #[test]
    fn derive_eps_base_station_key_different_counts() {
        let kasme = EpsAnchorKey::classify([0x55u8; 32]);
        let k1 = derive_eps_base_station_key(&kasme, 0);
        let k2 = derive_eps_base_station_key(&kasme, 1);
        assert_ne!(*k1.declassify(), *k2.declassify());
    }

    #[test]
    fn derive_algorithm_key_nas_enc_vs_int() {
        let key = [0x66u8; 32];
        // NAS encryption (type=0x01) vs NAS integrity (type=0x02)
        let k_enc = derive_algorithm_key(&key, 0x01, 0x01);
        let k_int = derive_algorithm_key(&key, 0x02, 0x01);
        assert_ne!(*k_enc.declassify(), *k_int.declassify());
    }

    #[test]
    fn derive_auth_server_key_not_zero() {
        let ck = CipherKey::classify([0x11u8; 16]);
        let ik = IntegrityKey::classify([0x22u8; 16]);
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let sqn_ak = ConcealedSequenceNumber::new([0x00; 6]);
        let kausf = derive_auth_server_key(&ck, &ik, snn, &sqn_ak);
        assert_ne!(*kausf.declassify(), [0u8; 32]);
    }

    #[test]
    fn derive_auth_server_key_different_snn() {
        let ck = CipherKey::classify([0x11u8; 16]);
        let ik = IntegrityKey::classify([0x22u8; 16]);
        let sqn_ak = ConcealedSequenceNumber::new([0x00; 6]);

        let k1 = derive_auth_server_key(&ck, &ik, b"5G:mnc001.mcc001.3gppnetwork.org", &sqn_ak);
        let k2 = derive_auth_server_key(&ck, &ik, b"5G:mnc002.mcc001.3gppnetwork.org", &sqn_ak);
        assert_ne!(*k1.declassify(), *k2.declassify());
    }

    #[test]
    fn derive_hash_response_returns_128_lsb() {
        let ck = CipherKey::classify([0x11u8; 16]);
        let ik = IntegrityKey::classify([0x22u8; 16]);
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let rand = AuthChallenge::new([0x33u8; 16]);
        let res = [0x44u8; 8];

        let res_star = derive_hash_response(&ck, &ik, snn, &rand, &res);

        // Verify it's the 128 LSBs of the full HMAC
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(ck.declassify());
        key[16..].copy_from_slice(ik.declassify());
        let full = kdf(
            &Secret::new(key),
            0x6B,
            &[snn, &rand.as_bytes()[..], &res[..]],
        );

        assert_eq!(*res_star.as_bytes(), full[16..32]);
    }

    #[test]
    fn full_5g_key_chain() {
        // Verify the full 5G derivation chain produces distinct keys at each step.
        let ck = CipherKey::classify([0xAA; 16]);
        let ik = IntegrityKey::classify([0xBB; 16]);
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let sqn_ak = ConcealedSequenceNumber::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let supi = b"001010000000001"; // IMSI digits
        let abba = [0x00, 0x00];

        let kausf = derive_auth_server_key(&ck, &ik, snn, &sqn_ak);
        let kseaf = derive_security_anchor_key(&kausf, snn);
        let kamf = derive_mobility_management_key(&kseaf, supi, &abba);
        let kgnb = derive_nr_base_station_key(&kamf, 0, 0x01); // 3GPP access

        // All keys must be distinct
        assert_ne!(*kausf.declassify(), *kseaf.declassify());
        assert_ne!(*kseaf.declassify(), *kamf.declassify());
        assert_ne!(*kamf.declassify(), *kgnb.declassify());
        assert_ne!(*kausf.declassify(), *kamf.declassify());
        assert_ne!(*kausf.declassify(), *kgnb.declassify());
        assert_ne!(*kseaf.declassify(), *kgnb.declassify());

        // None should be all-zero
        assert_ne!(*kausf.declassify(), [0u8; 32]);
        assert_ne!(*kseaf.declassify(), [0u8; 32]);
        assert_ne!(*kamf.declassify(), [0u8; 32]);
        assert_ne!(*kgnb.declassify(), [0u8; 32]);
    }

    #[test]
    fn derive_nr_base_station_key_access_type_matters() {
        let kamf = MobilityManagementKey::classify([0xCC; 32]);
        let k_3gpp = derive_nr_base_station_key(&kamf, 0, 0x01);
        let k_non3gpp = derive_nr_base_station_key(&kamf, 0, 0x02);
        assert_ne!(*k_3gpp.declassify(), *k_non3gpp.declassify());
    }

    #[test]
    fn derive_security_anchor_key_verifies_kdf_construction() {
        let kausf = AuthServerKey::classify([0xDD; 32]);
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let kseaf = derive_security_anchor_key(&kausf, snn);
        let expected = kdf(&Secret::new([0xDD; 32]), 0x6C, &[snn]);
        assert_eq!(*kseaf.declassify(), expected);
    }

    #[test]
    fn derive_mobility_management_key_verifies_kdf_construction() {
        let kseaf = SecurityAnchorKey::classify([0xEE; 32]);
        let supi = b"001010000000001";
        let abba = [0x00, 0x00];
        let kamf = derive_mobility_management_key(&kseaf, supi, &abba);
        let expected = kdf(&Secret::new([0xEE; 32]), 0x6D, &[supi, &abba]);
        assert_eq!(*kamf.declassify(), expected);
    }

    // -----------------------------------------------------------------------
    // ANSI X9.63 KDF tests (NIST CAVP ansx963_2001, SHA-256)
    // -----------------------------------------------------------------------

    /// Decode a hex string into a byte buffer, returns the number of bytes.
    fn hex_decode(s: &str, out: &mut [u8]) -> usize {
        let len = s.len() / 2;
        assert!(out.len() >= len);
        let mut i = 0;
        while i < len {
            out[i] = hex_byte(s.as_bytes()[i * 2], s.as_bytes()[i * 2 + 1]);
            i += 1;
        }
        len
    }

    #[test]
    fn x963_kdf_nist_cavp_no_sharedinfo_1() {
        // NIST CAVP ansx963_2001 SHA-256, no SharedInfo, 128-bit output.
        let mut z = [0u8; 24];
        hex_decode("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08", &mut z);
        let mut expected = [0u8; 16];
        hex_decode("443024c3dae66b95e6f5670601558f71", &mut expected);

        let mut out = [0u8; 16];
        kdf_x963(&z, &[], 16, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn x963_kdf_nist_cavp_no_sharedinfo_2() {
        // NIST CAVP ansx963_2001 SHA-256, no SharedInfo, 128-bit output.
        let mut z = [0u8; 24];
        hex_decode("96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4", &mut z);
        let mut expected = [0u8; 16];
        hex_decode("b6295162a7804f5667ba9070f82fa522", &mut expected);

        let mut out = [0u8; 16];
        kdf_x963(&z, &[], 16, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn x963_kdf_nist_cavp_no_sharedinfo_3() {
        // NIST CAVP ansx963_2001 SHA-256, no SharedInfo, 128-bit output.
        let mut z = [0u8; 24];
        hex_decode("de4ec3f6b2e9b7b5b6160acd5363c1b1f250e17ee731dbd6", &mut z);
        let mut expected = [0u8; 16];
        hex_decode("c8df626d5caaabf8a1b2a3f9061d2420", &mut expected);

        let mut out = [0u8; 16];
        kdf_x963(&z, &[], 16, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn x963_kdf_nist_cavp_with_sharedinfo_1() {
        // NIST CAVP ansx963_2001 SHA-256, with SharedInfo, 1024-bit output.
        let mut z = [0u8; 24];
        hex_decode("22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d", &mut z);
        let mut si = [0u8; 16];
        hex_decode("75eef81aa3041e33b80971203d2c0c52", &mut si);

        let expected_hex = "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21";
        let mut expected = [0u8; 128];
        let exp_len = hex_decode(expected_hex, &mut expected);
        assert_eq!(exp_len, 128);

        let mut out = [0u8; 128];
        kdf_x963(&z, &si, 128, &mut out);
        assert_eq!(out[..], expected[..]);
    }

    #[test]
    fn x963_kdf_nist_cavp_with_sharedinfo_2() {
        // NIST CAVP ansx963_2001 SHA-256, with SharedInfo, 1024-bit output.
        let mut z = [0u8; 24];
        hex_decode("7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a", &mut z);
        let mut si = [0u8; 16];
        hex_decode("d65a4812733f8cdbcdfb4b2f4c191d87", &mut si);

        let expected_hex = "c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b";
        let mut expected = [0u8; 128];
        let exp_len = hex_decode(expected_hex, &mut expected);
        assert_eq!(exp_len, 128);

        let mut out = [0u8; 128];
        kdf_x963(&z, &si, 128, &mut out);
        assert_eq!(out[..], expected[..]);
    }

    #[test]
    fn x963_kdf_different_z_different_output() {
        let z1 = [0x01u8; 32];
        let z2 = [0x02u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        kdf_x963(&z1, &[], 32, &mut out1);
        kdf_x963(&z2, &[], 32, &mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn x963_kdf_different_sharedinfo_different_output() {
        let z = [0x42u8; 32];
        let si1 = [0x01];
        let si2 = [0x02];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        kdf_x963(&z, &si1, 32, &mut out1);
        kdf_x963(&z, &si2, 32, &mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn x963_kdf_single_block_manual() {
        // For 32-byte output with no SharedInfo, result == SHA-256(Z || 0x00000001).
        let z = [0xABu8; 20];
        let mut out = [0u8; 32];
        kdf_x963(&z, &[], 32, &mut out);

        let mut h = simrs_sha256::Sha256::new();
        h.update(&z);
        h.update(&[0x00, 0x00, 0x00, 0x01]);
        let expected = h.finalize();
        assert_eq!(out, expected);
    }

    // -----------------------------------------------------------------------
    // EAP-AKA' CK'/IK' derivation (RFC 5448 Appendix C test vectors)
    // -----------------------------------------------------------------------

    fn hex16(s: &str) -> [u8; 16] {
        assert_eq!(s.len(), 32, "hex16 expects 32 hex chars");
        let mut out = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            out[i] = hex_byte(s.as_bytes()[i * 2], s.as_bytes()[i * 2 + 1]);
            i += 1;
        }
        out
    }

    fn hex6(s: &str) -> [u8; 6] {
        assert_eq!(s.len(), 12, "hex6 expects 12 hex chars");
        let mut out = [0u8; 6];
        let mut i = 0;
        while i < 6 {
            out[i] = hex_byte(s.as_bytes()[i * 2], s.as_bytes()[i * 2 + 1]);
            i += 1;
        }
        out
    }

    #[test]
    fn rfc5448_case1_wlan() {
        // RFC 5448 Appendix C, Case 1: Network = "WLAN"
        let ck = CipherKey::classify(hex16("5349fbe098649f948f5d2e973a81c00f"));
        let ik = IntegrityKey::classify(hex16("9744871ad32bf9bbd1dd5ce54e3e2e5a"));
        let sqn_ak = ConcealedSequenceNumber::new(hex6("bb52e91c747a"));

        let (ck_prime, ik_prime) = derive_ck_prime_ik_prime(&ck, &ik, b"WLAN", &sqn_ak);

        assert_eq!(
            *ck_prime.declassify(),
            hex16("0093962d0dd84aa5684b045c9edffa04")
        );
        assert_eq!(
            *ik_prime.declassify(),
            hex16("ccfc230ca74fcc96c0a5d61164f5a76c")
        );
    }

    #[test]
    fn rfc5448_case2_hrpd() {
        // RFC 5448 Appendix C, Case 2: Network = "HRPD"
        let ck = CipherKey::classify(hex16("5349fbe098649f948f5d2e973a81c00f"));
        let ik = IntegrityKey::classify(hex16("9744871ad32bf9bbd1dd5ce54e3e2e5a"));
        let sqn_ak = ConcealedSequenceNumber::new(hex6("bb52e91c747a"));

        let (ck_prime, ik_prime) = derive_ck_prime_ik_prime(&ck, &ik, b"HRPD", &sqn_ak);

        assert_eq!(
            *ck_prime.declassify(),
            hex16("3820f0277fa5f77732b1fb1d90c1a0da")
        );
        assert_eq!(
            *ik_prime.declassify(),
            hex16("db94a0ab557ef6c9ab48619ca05b9a9f")
        );
    }

    #[test]
    fn rfc5448_case3_wlan_different_keys() {
        // RFC 5448 Appendix C, Case 3: different CK/IK, Network = "WLAN"
        let ck = CipherKey::classify(hex16("c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"));
        let ik = IntegrityKey::classify(hex16("b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"));
        let sqn_ak = ConcealedSequenceNumber::new(hex6("a0a0a0a0a0a0"));

        let (ck_prime, ik_prime) = derive_ck_prime_ik_prime(&ck, &ik, b"WLAN", &sqn_ak);

        assert_eq!(
            *ck_prime.declassify(),
            hex16("cd4c8e5c68f57dd1d7d7dfd0c538e577")
        );
        assert_eq!(
            *ik_prime.declassify(),
            hex16("3ece6b705dbbf7dfc459a11280c65524")
        );
    }

    #[test]
    fn derive_ck_prime_ik_prime_different_network_different_output() {
        let ck = CipherKey::classify([0x11u8; 16]);
        let ik = IntegrityKey::classify([0x22u8; 16]);
        let sqn_ak = ConcealedSequenceNumber::new([0x00; 6]);

        let (ck1, ik1) = derive_ck_prime_ik_prime(&ck, &ik, b"WLAN", &sqn_ak);
        let (ck2, ik2) = derive_ck_prime_ik_prime(&ck, &ik, b"HRPD", &sqn_ak);

        assert_ne!(*ck1.declassify(), *ck2.declassify());
        assert_ne!(*ik1.declassify(), *ik2.declassify());
    }

    #[test]
    fn derive_ck_prime_ik_prime_verifies_kdf_construction() {
        // CK'/IK' = KDF(CK||IK, FC=0x20, P0=network_name, P1=SQN^AK)
        let ck = CipherKey::classify([0x33u8; 16]);
        let ik = IntegrityKey::classify([0x44u8; 16]);
        let sqn_ak = ConcealedSequenceNumber::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let network = b"WLAN";

        let (ck_prime, ik_prime) = derive_ck_prime_ik_prime(&ck, &ik, network, &sqn_ak);

        let mut key = [0u8; 32];
        key[..16].copy_from_slice(ck.declassify());
        key[16..].copy_from_slice(ik.declassify());
        let expected = kdf(
            &Secret::new(key),
            0x20,
            &[&network[..], &sqn_ak.as_bytes()[..]],
        );

        assert_eq!(*ck_prime.declassify(), expected[..16]);
        assert_eq!(*ik_prime.declassify(), expected[16..32]);
    }

    // -----------------------------------------------------------------------
    // Anti-theater: cross-generation key isolation
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // GBA key derivation tests (TS 33.220 Annex B.3)
    // -----------------------------------------------------------------------

    #[test]
    fn gba_session_key_from_ck_ik() {
        let ck = CipherKey::classify([0x11u8; 16]);
        let ik = IntegrityKey::classify([0x22u8; 16]);
        let ks = GbaSessionKey::from_ck_ik(&ck, &ik);
        let raw = ks.declassify();
        assert_eq!(&raw[..16], &[0x11u8; 16]);
        assert_eq!(&raw[16..], &[0x22u8; 16]);
    }

    #[test]
    fn gba_ext_naf_key_verifies_kdf_construction() {
        // derive_gba_ext_naf_key = KDF(Ks, FC=0x01, "gba-me", RAND, IMPI, NAF_ID)
        let ks = GbaSessionKey::classify([0x42u8; 32]);
        let rand = [0x33u8; 16];
        let impi = b"user@operator.com";
        let naf_id = b"naf.example.com";

        let key = derive_gba_ext_naf_key(&ks, &rand, impi, naf_id);

        // Manual KDF computation
        let expected = kdf(
            &Secret::new([0x42u8; 32]),
            0x01,
            &[b"gba-me", &rand[..], &impi[..], &naf_id[..]],
        );
        assert_eq!(*key.declassify(), expected);
    }

    #[test]
    fn gba_int_naf_key_verifies_kdf_construction() {
        // derive_gba_int_naf_key = KDF(Ks, FC=0x01, "gba-u", RAND, IMPI, NAF_ID)
        let ks = GbaSessionKey::classify([0x42u8; 32]);
        let rand = [0x33u8; 16];
        let impi = b"user@operator.com";
        let naf_id = b"naf.example.com";

        let key = derive_gba_int_naf_key(&ks, &rand, impi, naf_id);

        let expected = kdf(
            &Secret::new([0x42u8; 32]),
            0x01,
            &[b"gba-u", &rand[..], &impi[..], &naf_id[..]],
        );
        assert_eq!(*key.declassify(), expected);
    }

    #[test]
    fn gba_ext_and_int_naf_keys_differ() {
        // "gba-me" vs "gba-u" label must produce different keys
        let ks = GbaSessionKey::classify([0x55u8; 32]);
        let rand = [0x77u8; 16];
        let impi = b"user@ims.mnc001.mcc001.3gppnetwork.org";
        let naf_id = b"naf.example.com\x01\x00\x00\x00\x01";

        let k_ext = derive_gba_ext_naf_key(&ks, &rand, impi, naf_id);
        let k_int = derive_gba_int_naf_key(&ks, &rand, impi, naf_id);
        assert_ne!(*k_ext.declassify(), *k_int.declassify());
    }

    #[test]
    fn gba_naf_key_different_rand() {
        let ks = GbaSessionKey::classify([0xAA; 32]);
        let impi = b"user@example.com";
        let naf_id = b"naf.example.com";

        let k1 = derive_gba_ext_naf_key(&ks, &[0x01u8; 16], impi, naf_id);
        let k2 = derive_gba_ext_naf_key(&ks, &[0x02u8; 16], impi, naf_id);
        assert_ne!(*k1.declassify(), *k2.declassify());
    }

    #[test]
    fn gba_naf_key_different_naf_id() {
        let ks = GbaSessionKey::classify([0xBB; 32]);
        let rand = [0xCC; 16];
        let impi = b"user@example.com";

        let k1 = derive_gba_ext_naf_key(&ks, &rand, impi, b"naf1.example.com");
        let k2 = derive_gba_ext_naf_key(&ks, &rand, impi, b"naf2.example.com");
        assert_ne!(*k1.declassify(), *k2.declassify());
    }

    #[test]
    fn gba_naf_key_different_impi() {
        let ks = GbaSessionKey::classify([0xDD; 32]);
        let rand = [0xEE; 16];
        let naf_id = b"naf.example.com";

        let k1 = derive_gba_ext_naf_key(&ks, &rand, b"alice@example.com", naf_id);
        let k2 = derive_gba_ext_naf_key(&ks, &rand, b"bob@example.com", naf_id);
        assert_ne!(*k1.declassify(), *k2.declassify());
    }

    #[test]
    fn gba_naf_key_deterministic() {
        let ks = GbaSessionKey::classify([0x42u8; 32]);
        let rand = [0x33u8; 16];
        let impi = b"user@operator.com";
        let naf_id = b"naf.example.com";

        let k1 = derive_gba_ext_naf_key(&ks, &rand, impi, naf_id);
        let k2 = derive_gba_ext_naf_key(&ks, &rand, impi, naf_id);
        assert_eq!(*k1.declassify(), *k2.declassify());
    }

    // -----------------------------------------------------------------------
    // Anti-theater: cross-generation key isolation
    // -----------------------------------------------------------------------

    #[test]
    fn eps_anchor_key_vs_auth_server_key_different_fc() {
        // 4G EPS anchor key (FC=0x10) and 5G auth server key (FC=0x6A) with same CK/IK must differ.
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_ak = [0x00; 6];

        // KASME uses PLMN-ID (3 bytes), KAUSF uses SNN (variable)
        // But even if we construct them with the same param layout, FC differs.
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&ck);
        key[16..].copy_from_slice(&ik);

        let param = [0x00, 0xF1, 0x10]; // 3 bytes
        let k4g = kdf(&Secret::new(key), 0x10, &[&param[..], &sqn_ak[..]]);
        let k5g = kdf(&Secret::new(key), 0x6A, &[&param[..], &sqn_ak[..]]);
        assert_ne!(k4g, k5g);
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
        // HMAC streaming equivalence: one-shot must equal multi-update.
        #[test]
        fn hmac_streaming_equivalence(
            key in any::<[u8; 32]>(),
            a in any::<[u8; 32]>(),
            a_len in 0usize..=32,
            b in any::<[u8; 32]>(),
            b_len in 0usize..=32,
        ) {
            let a = &a[..a_len];
            let b = &b[..b_len];

            let mut combined = [0u8; 64];
            combined[..a.len()].copy_from_slice(a);
            combined[a.len()..a.len() + b.len()].copy_from_slice(b);
            let one_shot = hmac_sha256(&Secret::new(key), &combined[..a.len() + b.len()]);

            let mut h = HmacSha256::new(&Secret::new(key));
            h.update(a);
            h.update(b);
            let streamed = h.finalize();

            prop_assert_eq!(one_shot, streamed);
        }
    }

    proptest! {
        // HMAC PRF: different keys with same data must produce different MACs.
        #[test]
        fn hmac_different_keys(
            k1 in any::<[u8; 32]>(),
            k2 in any::<[u8; 32]>(),
            data in any::<[u8; 32]>(),
        ) {
            prop_assume!(k1 != k2);
            let m1 = hmac_sha256(&Secret::new(k1), &data);
            let m2 = hmac_sha256(&Secret::new(k2), &data);
            prop_assert_ne!(m1, m2, "different keys must produce different MACs");
        }
    }

    proptest! {
        // KDF FC isolation: same key + params, different FC => different output.
        #[test]
        fn kdf_fc_isolation(
            key in any::<[u8; 32]>(),
            param in any::<[u8; 16]>(),
            fc1 in any::<u8>(),
            fc2 in any::<u8>(),
        ) {
            prop_assume!(fc1 != fc2);
            let k1 = kdf(&Secret::new(key), fc1, &[&param[..]]);
            let k2 = kdf(&Secret::new(key), fc2, &[&param[..]]);
            prop_assert_ne!(k1, k2, "different FC must produce different derived keys");
        }
    }

    proptest! {
        // KDF param isolation: same FC, different params => different output.
        #[test]
        fn kdf_param_isolation(
            key in any::<[u8; 32]>(),
            p1 in any::<[u8; 16]>(),
            p2 in any::<[u8; 16]>(),
        ) {
            prop_assume!(p1 != p2);
            let k1 = kdf(&Secret::new(key), 0x10, &[&p1[..]]);
            let k2 = kdf(&Secret::new(key), 0x10, &[&p2[..]]);
            prop_assert_ne!(k1, k2, "different params must produce different derived keys");
        }
    }

    proptest! {
        // 5G key chain: all derived keys in a chain must be mutually distinct.
        #[test]
        fn key_chain_distinct(
            ck in any::<[u8; 16]>(),
            ik in any::<[u8; 16]>(),
            snn_byte in any::<u8>(),
            sqn_ak in any::<[u8; 6]>(),
        ) {
            let snn = [snn_byte; 8]; // 8-byte SNN placeholder
            let kausf = derive_auth_server_key(&CipherKey::classify(ck), &IntegrityKey::classify(ik), &snn, &ConcealedSequenceNumber::new(sqn_ak));
            let kseaf = derive_security_anchor_key(&kausf, &snn);
            let supi = [0x01, 0x02, 0x03, 0x04, 0x05]; // 5-byte SUPI placeholder
            let abba = [0x00, 0x00];
            let kamf = derive_mobility_management_key(&kseaf, &supi, &abba);
            let kgnb = derive_nr_base_station_key(&kamf, 0, 0x01);

            // All four keys must be distinct.
            prop_assert_ne!(*kausf.declassify(), *kseaf.declassify(), "KAUSF != KSEAF");
            prop_assert_ne!(*kseaf.declassify(), *kamf.declassify(), "KSEAF != KAMF");
            prop_assert_ne!(*kamf.declassify(), *kgnb.declassify(), "KAMF != KgNB");
            prop_assert_ne!(*kausf.declassify(), *kamf.declassify(), "KAUSF != KAMF");
            prop_assert_ne!(*kausf.declassify(), *kgnb.declassify(), "KAUSF != KgNB");
            prop_assert_ne!(*kseaf.declassify(), *kgnb.declassify(), "KSEAF != KgNB");
        }
    }

    proptest! {
        // GBA: ext and int NAF keys must always differ (label isolation).
        #[test]
        fn gba_ext_int_naf_key_isolation(
            ks in any::<[u8; 32]>(),
            rand in any::<[u8; 16]>(),
            impi_len in 5usize..=32,
            impi_bytes in any::<[u8; 32]>(),
            naf_id_len in 5usize..=32,
            naf_id_bytes in any::<[u8; 32]>(),
        ) {
            let impi = &impi_bytes[..impi_len];
            let naf_id = &naf_id_bytes[..naf_id_len];
            let session = GbaSessionKey::classify(ks);
            let k_ext = derive_gba_ext_naf_key(&session, &rand, impi, naf_id);
            let k_int = derive_gba_int_naf_key(&session, &rand, impi, naf_id);
            prop_assert_ne!(*k_ext.declassify(), *k_int.declassify(),
                "Ks_ext_NAF and Ks_int_NAF must differ (different KDF labels)");
        }
    }

    proptest! {
        // X9.63 KDF: different Z values produce different output.
        #[test]
        fn kdf_x963_different_z(
            z1 in any::<[u8; 32]>(),
            z2 in any::<[u8; 32]>(),
            shared_info in any::<[u8; 16]>(),
        ) {
            prop_assume!(z1 != z2);
            let mut out1 = [0u8; 32];
            let mut out2 = [0u8; 32];
            kdf_x963(&z1, &shared_info, 32, &mut out1);
            kdf_x963(&z2, &shared_info, 32, &mut out2);
            prop_assert_ne!(out1, out2, "different Z must produce different KDF output");
        }
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet via ct_test wrapper)
//
//   cargo test -p simrs-kdf --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    /// HMAC-SHA-256 timing must be independent of key content.
    /// Class 0: fixed key, random data.
    /// Class 1: random key, random data.
    #[test]
    fn test_hmac_sha256_ct() {
        let outcome = ct_test(
            0xA0AC_256C,
            |rng| {
                let key = [0xAAu8; 32];
                let mut data = [0u8; 32];
                rng.fill_bytes(&mut data);
                (key, data)
            },
            |rng| {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                let mut data = [0u8; 32];
                rng.fill_bytes(&mut data);
                (key, data)
            },
            |(key, data)| {
                black_box(hmac_sha256(&Secret::new(*key), data));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// 3GPP KDF timing must be independent of key content.
    #[test]
    fn test_kdf_ct() {
        let outcome = ct_test(
            0x3BEE_CDFC,
            |rng| {
                let key = [0xBBu8; 32];
                let mut param = [0u8; 16];
                rng.fill_bytes(&mut param);
                (key, param)
            },
            |rng| {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                let mut param = [0u8; 16];
                rng.fill_bytes(&mut param);
                (key, param)
            },
            |(key, param)| {
                black_box(kdf(&Secret::new(*key), 0x10, &[&param[..]]));
            },
        );
        assert_no_timing_leak!(outcome);
    }

    /// X9.63 KDF timing must be independent of shared secret Z content.
    /// Class 0: fixed Z, random SharedInfo.
    /// Class 1: random Z, random SharedInfo.
    #[test]
    fn test_kdf_x963_ct() {
        let outcome = ct_test(
            0x963C_DFBA,
            |rng| {
                let z = [0xCCu8; 32];
                let mut si = [0u8; 33];
                rng.fill_bytes(&mut si);
                (z, si)
            },
            |rng| {
                let mut z = [0u8; 32];
                rng.fill_bytes(&mut z);
                let mut si = [0u8; 33];
                rng.fill_bytes(&mut si);
                (z, si)
            },
            |(z, si)| {
                let mut out = [0u8; 64];
                black_box(kdf_x963(z, si, 64, &mut out));
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
