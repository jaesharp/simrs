//! HMAC-SHA-256 and 3GPP key derivation functions.
//!
//! Provides:
//! - [`HmacSha256`] streaming HMAC and [`hmac_sha256`] one-shot
//!   per [RFC 2104](../../../docs/specs/ietf/rfc2104.txt) / NIST FIPS 198-1
//! - [`kdf`] generic 3GPP KDF per
//!   [TS 33.220](../../../docs/specs/3gpp/ts-33.220/ts_133220v150200p.pdf) Annex B
//! - 4G EPS-AKA derivations ([`derive_kasme`], [`derive_kenb`], [`derive_algorithm_key`])
//!   per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A
//! - 5G NR derivations ([`derive_kausf`], [`derive_res_star`], [`derive_kseaf`],
//!   [`derive_kamf`], [`derive_kgnb`]) per
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

        Self { inner, opad_key: Secret::new(opad_key) }
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

/// Derive `K_ASME` from CK, IK, PLMN-ID, and SQN XOR AK.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.2:
/// - FC = 0x10
/// - P0 = PLMN-ID (3 bytes, MCC/MNC encoded per TS 24.008)
/// - P1 = SQN XOR AK (6 bytes)
/// - Key = CK || IK (32 bytes)
pub fn derive_kasme(
    ck: &[u8; 16],
    ik: &[u8; 16],
    plmn_id: &[u8; 3],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    kdf(&Secret::new(key), 0x10, &[plmn_id, sqn_xor_ak])
}

/// Derive `K_eNB` from `K_ASME` and uplink NAS count.
///
/// Per [TS 33.401](../../../docs/specs/3gpp/ts-33.401/ts_133401v180300p.pdf) Annex A.3:
/// - FC = 0x11
/// - P0 = uplink NAS count (4 bytes, big-endian)
pub fn derive_kenb(kasme: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    let count_be = ul_nas_count.to_be_bytes();
    kdf(&Secret::new(*kasme), 0x11, &[&count_be])
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
pub fn derive_algorithm_key(
    key: &[u8; 32],
    alg_distinguisher: u8,
    alg_id: u8,
) -> [u8; 32] {
    kdf(&Secret::new(*key), 0x15, &[&[alg_distinguisher], &[alg_id]])
}

// ---------------------------------------------------------------------------
// 5G NR key derivations (TS 33.501 Annex A)
// ---------------------------------------------------------------------------

/// Derive `K_AUSF` from CK', IK', serving network name, and SQN XOR AK.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.2:
/// - FC = 0x6A
/// - P0 = serving network name (variable-length UTF-8, e.g. "5G:mnc001.mcc001.3gppnetwork.org")
/// - P1 = SQN XOR AK (6 bytes)
/// - Key = CK' || IK' (32 bytes, derived per TS 33.501 Annex A.2)
///
/// Note: the caller provides CK'/IK' (not raw CK/IK). For 5G-AKA, CK' and IK'
/// are derived from CK, IK per TS 33.501 C.2 using the serving network name.
pub fn derive_kausf(
    ck: &[u8; 16],
    ik: &[u8; 16],
    snn: &[u8],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    kdf(&Secret::new(key), 0x6A, &[snn, sqn_xor_ak])
}

/// Derive RES* from CK', IK', serving network name, RAND, and RES.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.4:
/// - FC = 0x6B
/// - P0 = serving network name
/// - P1 = RAND (16 bytes)
/// - P2 = RES (variable length, typically 8 or 16 bytes)
/// - Key = CK' || IK' (32 bytes)
///
/// Returns the 128 least-significant bits (bytes 16..32 of the HMAC output).
pub fn derive_res_star(
    ck: &[u8; 16],
    ik: &[u8; 16],
    snn: &[u8],
    rand: &[u8; 16],
    res: &[u8],
) -> [u8; 16] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    let full = kdf(&Secret::new(key), 0x6B, &[snn, rand, res]);
    // 128 LSBs = bytes 16..32
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[16..32]);
    out
}

/// Derive `K_SEAF` from `K_AUSF` and serving network name.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.6:
/// - FC = 0x6C
/// - P0 = serving network name
pub fn derive_kseaf(kausf: &[u8; 32], snn: &[u8]) -> [u8; 32] {
    kdf(&Secret::new(*kausf), 0x6C, &[snn])
}

/// Derive `K_AMF` from `K_SEAF`, SUPI, and ABBA parameter.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.7:
/// - FC = 0x6D
/// - P0 = SUPI (IMSI as ASCII digits)
/// - P1 = ABBA parameter (2 bytes for primary authentication)
pub fn derive_kamf(kseaf: &[u8; 32], supi: &[u8], abba: &[u8]) -> [u8; 32] {
    kdf(&Secret::new(*kseaf), 0x6D, &[supi, abba])
}

/// Derive `K_gNB` from `K_AMF`, uplink NAS count, and access type.
///
/// Per [TS 33.501](../../../docs/specs/3gpp/ts-33.501/ts_133501v170700p.pdf) Annex A.9:
/// - FC = 0x6E
/// - P0 = uplink NAS count (4 bytes, big-endian)
/// - P1 = access type distinguisher (1 byte: 0x01 = 3GPP, 0x02 = non-3GPP)
pub fn derive_kgnb(kamf: &[u8; 32], ul_nas_count: u32, access_type: u8) -> [u8; 32] {
    let count_be = ul_nas_count.to_be_bytes();
    kdf(&Secret::new(*kamf), 0x6E, &[&count_be, &[access_type]])
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
    assert!(out_len > 0 && out_len <= KDF_X963_MAX_OUT, "invalid output length");
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
        assert_eq!(tag, hex32("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    }

    #[test]
    fn rfc4231_tc2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let tag = hmac_sha256(&Secret::new(*b"Jefe"), b"what do ya want for nothing?");
        assert_eq!(tag, hex32("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    }

    #[test]
    fn rfc4231_tc3() {
        // Key = 20 bytes of 0xaa, Data = 50 bytes of 0xdd
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let tag = hmac_sha256(&Secret::new(key), &data);
        assert_eq!(tag, hex32("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
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
        assert_eq!(tag, hex32("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));
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
            &[0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0,
              0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b]
        );
    }

    #[test]
    fn rfc4231_tc6() {
        // Key = 131 bytes of 0xaa (longer than block size)
        // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let key = [0xaau8; 131];
        let tag = hmac_sha256(&Secret::new(key), b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(tag, hex32("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    }

    #[test]
    fn rfc4231_tc7() {
        // Key = 131 bytes of 0xaa (longer than block size)
        // Data = "This is a test using a larger than block-size key and a larger
        //         than block-size data. ..."
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let tag = hmac_sha256(&Secret::new(key), data);
        assert_eq!(tag, hex32("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
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
        let p1 = [0x0C];       // 1 byte  -> L1 = 0x0001

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
    fn derive_kasme_not_zero() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let plmn = [0x00, 0xF1, 0x10]; // MCC=001, MNC=01
        let sqn_ak = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let kasme = derive_kasme(&ck, &ik, &plmn, &sqn_ak);
        assert_ne!(kasme, [0u8; 32]);
    }

    #[test]
    fn derive_kasme_different_plmn() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_ak = [0x00; 6];

        let k1 = derive_kasme(&ck, &ik, &[0x00, 0xF1, 0x10], &sqn_ak);
        let k2 = derive_kasme(&ck, &ik, &[0x00, 0xF1, 0x20], &sqn_ak);
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_kasme_verifies_kdf_construction() {
        // KASME = KDF(CK||IK, FC=0x10, P0=PLMN, P1=SQN^AK)
        let ck = [0x33u8; 16];
        let ik = [0x44u8; 16];
        let plmn = [0x00, 0xF1, 0x10];
        let sqn_ak = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let kasme = derive_kasme(&ck, &ik, &plmn, &sqn_ak);

        // Manually compute with kdf()
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&ck);
        key[16..].copy_from_slice(&ik);
        let expected = kdf(&Secret::new(key), 0x10, &[&plmn[..], &sqn_ak[..]]);

        assert_eq!(kasme, expected);
    }

    #[test]
    fn derive_kenb_different_counts() {
        let kasme = [0x55u8; 32];
        let k1 = derive_kenb(&kasme, 0);
        let k2 = derive_kenb(&kasme, 1);
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_algorithm_key_nas_enc_vs_int() {
        let key = [0x66u8; 32];
        // NAS encryption (type=0x01) vs NAS integrity (type=0x02)
        let k_enc = derive_algorithm_key(&key, 0x01, 0x01);
        let k_int = derive_algorithm_key(&key, 0x02, 0x01);
        assert_ne!(k_enc, k_int);
    }

    #[test]
    fn derive_kausf_not_zero() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let sqn_ak = [0x00; 6];
        let kausf = derive_kausf(&ck, &ik, snn, &sqn_ak);
        assert_ne!(kausf, [0u8; 32]);
    }

    #[test]
    fn derive_kausf_different_snn() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_ak = [0x00; 6];

        let k1 = derive_kausf(&ck, &ik, b"5G:mnc001.mcc001.3gppnetwork.org", &sqn_ak);
        let k2 = derive_kausf(&ck, &ik, b"5G:mnc002.mcc001.3gppnetwork.org", &sqn_ak);
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_res_star_returns_128_lsb() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let rand = [0x33u8; 16];
        let res = [0x44u8; 8];

        let res_star = derive_res_star(&ck, &ik, snn, &rand, &res);

        // Verify it's the 128 LSBs of the full HMAC
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&ck);
        key[16..].copy_from_slice(&ik);
        let full = kdf(&Secret::new(key), 0x6B, &[snn, &rand[..], &res[..]]);

        assert_eq!(res_star, full[16..32]);
    }

    #[test]
    fn full_5g_key_chain() {
        // Verify the full 5G derivation chain produces distinct keys at each step.
        let ck = [0xAA; 16];
        let ik = [0xBB; 16];
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let sqn_ak = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let supi = b"001010000000001"; // IMSI digits
        let abba = [0x00, 0x00];

        let kausf = derive_kausf(&ck, &ik, snn, &sqn_ak);
        let kseaf = derive_kseaf(&kausf, snn);
        let kamf = derive_kamf(&kseaf, supi, &abba);
        let kgnb = derive_kgnb(&kamf, 0, 0x01); // 3GPP access

        // All keys must be distinct
        assert_ne!(kausf, kseaf);
        assert_ne!(kseaf, kamf);
        assert_ne!(kamf, kgnb);
        assert_ne!(kausf, kamf);
        assert_ne!(kausf, kgnb);
        assert_ne!(kseaf, kgnb);

        // None should be all-zero
        assert_ne!(kausf, [0u8; 32]);
        assert_ne!(kseaf, [0u8; 32]);
        assert_ne!(kamf, [0u8; 32]);
        assert_ne!(kgnb, [0u8; 32]);
    }

    #[test]
    fn derive_kgnb_access_type_matters() {
        let kamf = [0xCC; 32];
        let k_3gpp = derive_kgnb(&kamf, 0, 0x01);
        let k_non3gpp = derive_kgnb(&kamf, 0, 0x02);
        assert_ne!(k_3gpp, k_non3gpp);
    }

    #[test]
    fn derive_kseaf_verifies_kdf_construction() {
        let kausf = [0xDD; 32];
        let snn = b"5G:mnc001.mcc001.3gppnetwork.org";
        let kseaf = derive_kseaf(&kausf, snn);
        let expected = kdf(&Secret::new(kausf), 0x6C, &[snn]);
        assert_eq!(kseaf, expected);
    }

    #[test]
    fn derive_kamf_verifies_kdf_construction() {
        let kseaf = [0xEE; 32];
        let supi = b"001010000000001";
        let abba = [0x00, 0x00];
        let kamf = derive_kamf(&kseaf, supi, &abba);
        let expected = kdf(&Secret::new(kseaf), 0x6D, &[supi, &abba]);
        assert_eq!(kamf, expected);
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
    // Anti-theater: cross-generation key isolation
    // -----------------------------------------------------------------------

    #[test]
    fn kasme_vs_kausf_different_fc() {
        // 4G KASME (FC=0x10) and 5G KAUSF (FC=0x6A) with same CK/IK must differ.
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
            let kausf = derive_kausf(&ck, &ik, &snn, &sqn_ak);
            let kseaf = derive_kseaf(&kausf, &snn);
            let supi = [0x01, 0x02, 0x03, 0x04, 0x05]; // 5-byte SUPI placeholder
            let abba = [0x00, 0x00];
            let kamf = derive_kamf(&kseaf, &supi, &abba);
            let kgnb = derive_kgnb(&kamf, 0, 0x01);

            // All four keys must be distinct.
            prop_assert_ne!(kausf, kseaf, "KAUSF != KSEAF");
            prop_assert_ne!(kseaf, kamf, "KSEAF != KAMF");
            prop_assert_ne!(kamf, kgnb, "KAMF != KgNB");
            prop_assert_ne!(kausf, kamf, "KAUSF != KAMF");
            prop_assert_ne!(kausf, kgnb, "KAUSF != KgNB");
            prop_assert_ne!(kseaf, kgnb, "KSEAF != KgNB");
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
    use simrs_consttime_validation::{ct_test, assert_no_timing_leak};

    /// HMAC-SHA-256 timing must be independent of key content.
    /// Class 0: fixed key, random data.
    /// Class 1: random key, random data.
    #[test]
    fn test_hmac_sha256_ct() {
        let outcome = ct_test(0xA0AC_256C,
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
        let outcome = ct_test(0x3BEE_CDFC,
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
        let outcome = ct_test(0x963C_DFBA,
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
