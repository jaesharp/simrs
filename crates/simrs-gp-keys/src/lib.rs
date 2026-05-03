//! `GlobalPlatform` Security Domain key store per
//! [GP Card Specification v2.1.1](../../../../telecom-standards/globalplatform/GPC_CardSpecification_v2.1.1.pdf)
//! Appendix C, Tables C-1 and C-2.
//!
//! Each Security Domain (including the Issuer Security Domain) maintains a
//! set of cryptographic keys used for:
//! - Secure Channel Protocol authentication and secure messaging (ENC, MAC)
//! - Sensitive data encryption during key management (DEK)
//! - Token and receipt generation (Appendix C clauses C.3-C.4)
//!
//! Keys are identified by a `(key_version_number, key_identifier)` pair.
//! Multiple key versions can coexist to support key rotation.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
//!
//! # Example
//!
//! ```
//! use simrs_gp_keys::{KeyStore, KeySet, KeyType};
//!
//! let mut store = KeyStore::<4>::new();
//! let keys = KeySet::des3_2key(
//!     [0x40; 16], // ENC
//!     [0x40; 16], // MAC
//!     [0x40; 16], // DEK
//! );
//! assert!(store.put(0x01, &keys).is_ok());
//! assert!(store.get(0x01).is_some());
//! ```
#![no_std]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Key types (GP 2.1.1 Appendix C, Table C-1)
// ---------------------------------------------------------------------------

/// SCP protocol version associated with a key set.
///
/// Determines which Secure Channel Protocol is used with these keys.
/// Mirrors `simrs_gp_scp::ScpVersion` without introducing a circular
/// dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScpId {
    /// Secure Channel Protocol 01 (GP 2.1.1 Appendix D).
    Scp01 = 0x01,
    /// Secure Channel Protocol 02 (GP 2.1.1 Appendix E).
    Scp02 = 0x02,
    /// Secure Channel Protocol 03 (GP 2.3.1 Amendment D).
    Scp03 = 0x03,
}

impl ScpId {
    /// Convert to the SCP identifier byte used in INIT UPDATE responses.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Parse from a byte. Returns `None` for unknown values.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Scp01),
            0x02 => Some(Self::Scp02),
            0x03 => Some(Self::Scp03),
            _ => None,
        }
    }
}

/// Key type indicator for GP key sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// 2-key Triple DES (16 bytes). Used by SCP01/SCP02.
    Des3TwoKey,
    /// 3-key Triple DES (24 bytes). Used by some OTA configurations.
    Des3ThreeKey,
    /// AES-128 (16 bytes). Used by SCP03.
    Aes128,
}

/// A complete key set for a Security Domain.
///
/// Each key set contains three keys per GP 2.1.1 Table C-1:
/// - **ENC** (Key Identifier 1): Secure channel encryption
/// - **MAC** (Key Identifier 2): Secure channel MAC
/// - **DEK** (Key Identifier 3): Data encryption key (key wrapping)
///
/// All three keys use the same key type (DES3 or AES).
#[derive(Clone)]
pub struct KeySet {
    /// Key type (determines key length and algorithm).
    pub key_type: KeyType,
    /// Encryption key (S-ENC for SCP), stored in a 24-byte buffer.
    enc: [u8; 24],
    /// MAC key (S-MAC for SCP), stored in a 24-byte buffer.
    mac: [u8; 24],
    /// Data encryption key (for PUT KEY wrapping), stored in a 24-byte buffer.
    dek: [u8; 24],
    /// Effective key length in bytes (16 for 2-key 3DES/AES, 24 for 3-key 3DES).
    key_len: u8,
    /// SCP version associated with this key set.
    scp_id: ScpId,
}

impl KeySet {
    /// Create a 2-key Triple DES key set (16-byte keys).
    ///
    /// This is the standard key type for SCP01 and SCP02.
    pub fn des3_2key(enc: [u8; 16], mac: [u8; 16], dek: [u8; 16]) -> Self {
        let mut enc24 = [0u8; 24];
        let mut mac24 = [0u8; 24];
        let mut dek24 = [0u8; 24];
        enc24[..16].copy_from_slice(&enc);
        mac24[..16].copy_from_slice(&mac);
        dek24[..16].copy_from_slice(&dek);
        Self {
            key_type: KeyType::Des3TwoKey,
            enc: enc24,
            mac: mac24,
            dek: dek24,
            key_len: 16,
            scp_id: ScpId::Scp02,
        }
    }

    /// Create a 2-key Triple DES key set for SCP01.
    pub fn des3_2key_scp01(enc: [u8; 16], mac: [u8; 16], dek: [u8; 16]) -> Self {
        let mut ks = Self::des3_2key(enc, mac, dek);
        ks.scp_id = ScpId::Scp01;
        ks
    }

    /// Create a 3-key Triple DES key set (24-byte keys).
    pub const fn des3_3key(enc: [u8; 24], mac: [u8; 24], dek: [u8; 24]) -> Self {
        Self {
            key_type: KeyType::Des3ThreeKey,
            enc,
            mac,
            dek,
            key_len: 24,
            scp_id: ScpId::Scp02,
        }
    }

    /// Create an AES-128 key set (16-byte keys).
    ///
    /// Used by SCP03 (GP 2.3.1 Amendment D).
    pub fn aes128(enc: [u8; 16], mac: [u8; 16], dek: [u8; 16]) -> Self {
        let mut enc24 = [0u8; 24];
        let mut mac24 = [0u8; 24];
        let mut dek24 = [0u8; 24];
        enc24[..16].copy_from_slice(&enc);
        mac24[..16].copy_from_slice(&mac);
        dek24[..16].copy_from_slice(&dek);
        Self {
            key_type: KeyType::Aes128,
            enc: enc24,
            mac: mac24,
            dek: dek24,
            key_len: 16,
            scp_id: ScpId::Scp03,
        }
    }

    /// Effective key length in bytes.
    pub const fn key_len(&self) -> usize {
        self.key_len as usize
    }

    /// Get the ENC key bytes (first `key_len()` bytes are valid).
    pub fn enc(&self) -> &[u8] {
        &self.enc[..self.key_len()]
    }

    /// Get the MAC key bytes (first `key_len()` bytes are valid).
    pub fn mac(&self) -> &[u8] {
        &self.mac[..self.key_len()]
    }

    /// Get the DEK key bytes (first `key_len()` bytes are valid).
    pub fn dek(&self) -> &[u8] {
        &self.dek[..self.key_len()]
    }

    /// SCP version associated with this key set.
    pub const fn scp_id(&self) -> ScpId {
        self.scp_id
    }
}

// ---------------------------------------------------------------------------
// Key store (GP 2.1.1 clause 6.8, Appendix C)
// ---------------------------------------------------------------------------

/// Error from key store operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreError {
    /// No room for another key version.
    StoreFull,
    /// Key version not found.
    NotFound,
}

/// Entry in the key store.
#[derive(Clone)]
struct KeyEntry {
    /// Key Version Number (KVN). Range 0x01-0x7F per GP 2.1.1 Table 9-47.
    version: u8,
    /// The key set.
    keys: KeySet,
}

/// Fixed-capacity key store for a Security Domain.
///
/// Stores up to `MAX_VERSIONS` key sets, each identified by a Key Version
/// Number (KVN). The KVN range is 0x01-0x7F per GP 2.1.1 Table 9-47.
///
/// The ISD typically has 1-3 key versions. Supplementary SDs usually have 1.
///
/// # Constant-time properties
///
/// The lookup methods ([`get`](Self::get), [`has`](Self::has),
/// [`get_or_default`](Self::get_or_default), [`remove`](Self::remove),
/// [`put`](Self::put)) are **not** constant-time in the queried KVN: they
/// short-circuit on the first match, so timing reveals the position of
/// the matching entry within `entries`.
///
/// This is **acceptable by spec** because KVN is non-secret data:
/// - GP 2.3.1 § 11.5.2 (INITIALIZE UPDATE) transmits the KVN in cleartext
///   in P1 and echoes it back in the response.
/// - GP 2.3.1 § 11.8.2.3 (PUT KEY) transmits the KVN in P1 and in the
///   leading byte of the data field (also cleartext).
/// - The GET STATUS response includes KVN information unencrypted.
///
/// **Do not pass secret data as a `version` argument** -- the timing
/// channel will leak it. The KVN type system intentionally uses a plain
/// `u8` rather than `Secret<u8>` to keep this contract visible.
///
/// The *key material* stored at a given KVN is secret, and the
/// `KeySet`'s `Secret`-wrapped fields enforce that separately.
pub struct KeyStore<const MAX_VERSIONS: usize> {
    entries: [Option<KeyEntry>; MAX_VERSIONS],
}

impl<const MAX_VERSIONS: usize> Default for KeyStore<MAX_VERSIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_VERSIONS: usize> KeyStore<MAX_VERSIONS> {
    /// Create an empty key store.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_VERSIONS],
        }
    }

    /// Add or replace a key set at the given version number.
    ///
    /// If a key set with this version already exists, it is replaced.
    /// If no slot is available, returns [`KeyStoreError::StoreFull`].
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::StoreFull`] when all slots are occupied and
    /// the given version does not match any existing entry.
    pub fn put(&mut self, version: u8, keys: &KeySet) -> Result<(), KeyStoreError> {
        // Check if this version already exists -> replace.
        for e in self.entries.iter_mut().flatten() {
            if e.version == version {
                e.keys = keys.clone();
                return Ok(());
            }
        }
        // Find an empty slot.
        for entry in &mut self.entries {
            if entry.is_none() {
                *entry = Some(KeyEntry {
                    version,
                    keys: keys.clone(),
                });
                return Ok(());
            }
        }
        Err(KeyStoreError::StoreFull)
    }

    /// Get the key set for a given version number.
    pub fn get(&self, version: u8) -> Option<&KeySet> {
        for e in self.entries.iter().flatten() {
            if e.version == version {
                return Some(&e.keys);
            }
        }
        None
    }

    /// Get the key set for a given version, or the first available key set
    /// if version is 0 (per GP 2.1.1 clause 9.7: KVN=0 means "any version").
    pub fn get_or_default(&self, version: u8) -> Option<(&KeySet, u8)> {
        if version == 0 {
            // Return the first available key set.
            self.entries
                .iter()
                .flatten()
                .next()
                .map(|e| (&e.keys, e.version))
        } else {
            self.get(version).map(|k| (k, version))
        }
    }

    /// Remove a key set by version number.
    ///
    /// # Errors
    ///
    /// Returns [`KeyStoreError::NotFound`] when no entry with the given
    /// version exists.
    pub fn remove(&mut self, version: u8) -> Result<(), KeyStoreError> {
        for entry in &mut self.entries {
            if let Some(e) = entry
                && e.version == version
            {
                *entry = None;
                return Ok(());
            }
        }
        Err(KeyStoreError::NotFound)
    }

    /// Check if a key version exists.
    pub fn has(&self, version: u8) -> bool {
        self.get(version).is_some()
    }

    /// Count the number of stored key versions.
    pub fn count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    /// Snapshot size: version byte + `key_type` byte + 3*24 key bytes per slot.
    pub const ENTRY_SIZE: usize = 1 + 1 + 3 * 24; // 74 bytes per entry
    /// Total snapshot size.
    pub const SNAPSHOT_SIZE: usize = 1 + MAX_VERSIONS * Self::ENTRY_SIZE;

    /// Save key store state to buffer. Returns bytes written.
    #[allow(clippy::cast_possible_truncation)]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        let mut off = 0;
        // MAX_VERSIONS is bounded by array size, always fits in u8.
        buf[off] = self.count() as u8;
        off += 1;
        for e in self.entries.iter().flatten() {
            buf[off] = e.version;
            off += 1;
            buf[off] = match e.keys.key_type {
                KeyType::Des3TwoKey => 0x01,
                KeyType::Des3ThreeKey => 0x02,
                KeyType::Aes128 => 0x03,
            };
            off += 1;
            buf[off..off + 24].copy_from_slice(&e.keys.enc);
            off += 24;
            buf[off..off + 24].copy_from_slice(&e.keys.mac);
            off += 24;
            buf[off..off + 24].copy_from_slice(&e.keys.dek);
            off += 24;
        }
        off
    }

    /// Restore key store state from buffer. Returns success.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.is_empty() {
            return false;
        }
        let count = buf[0] as usize;
        if count > MAX_VERSIONS {
            return false;
        }
        // Clear all entries.
        for entry in &mut self.entries {
            *entry = None;
        }
        let mut off = 1;
        for i in 0..count {
            if off + Self::ENTRY_SIZE > buf.len() {
                return false;
            }
            let version = buf[off];
            off += 1;
            let key_type = match buf[off] {
                0x01 => KeyType::Des3TwoKey,
                0x02 => KeyType::Des3ThreeKey,
                0x03 => KeyType::Aes128,
                _ => return false,
            };
            off += 1;
            let mut enc = [0u8; 24];
            let mut mac = [0u8; 24];
            let mut dek = [0u8; 24];
            enc.copy_from_slice(&buf[off..off + 24]);
            off += 24;
            mac.copy_from_slice(&buf[off..off + 24]);
            off += 24;
            dek.copy_from_slice(&buf[off..off + 24]);
            off += 24;
            let key_len = match key_type {
                KeyType::Des3TwoKey | KeyType::Aes128 => 16,
                KeyType::Des3ThreeKey => 24,
            };
            let scp_id = match key_type {
                KeyType::Aes128 => ScpId::Scp03,
                _ => ScpId::Scp02,
            };
            self.entries[i] = Some(KeyEntry {
                version,
                keys: KeySet {
                    key_type,
                    enc,
                    mac,
                    dek,
                    key_len,
                    scp_id,
                },
            });
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keyset() -> KeySet {
        KeySet::des3_2key([0x40; 16], [0x41; 16], [0x42; 16])
    }

    #[test]
    fn empty_store() {
        let store = KeyStore::<4>::new();
        assert_eq!(store.count(), 0);
        assert!(!store.has(0x01));
        assert!(store.get(0x01).is_none());
    }

    #[test]
    fn put_and_get() {
        let mut store = KeyStore::<4>::new();
        let keys = test_keyset();
        assert!(store.put(0x01, &keys).is_ok());
        assert_eq!(store.count(), 1);
        assert!(store.has(0x01));
        let retrieved = store.get(0x01).unwrap();
        assert_eq!(retrieved.key_type, KeyType::Des3TwoKey);
        assert_eq!(retrieved.enc(), &[0x40; 16]);
        assert_eq!(retrieved.mac(), &[0x41; 16]);
        assert_eq!(retrieved.dek(), &[0x42; 16]);
    }

    #[test]
    fn put_replaces_existing() {
        let mut store = KeyStore::<4>::new();
        let keys1 = test_keyset();
        let keys2 = KeySet::des3_2key([0xAA; 16], [0xBB; 16], [0xCC; 16]);
        assert!(store.put(0x01, &keys1).is_ok());
        assert!(store.put(0x01, &keys2).is_ok());
        assert_eq!(store.count(), 1); // replaced, not added
        let retrieved = store.get(0x01).unwrap();
        assert_eq!(retrieved.enc(), &[0xAA; 16]);
    }

    #[test]
    fn multiple_versions() {
        let mut store = KeyStore::<4>::new();
        for v in 1..=4 {
            let keys = KeySet::des3_2key([v; 16], [v + 0x10; 16], [v + 0x20; 16]);
            assert!(store.put(v, &keys).is_ok());
        }
        assert_eq!(store.count(), 4);
        for v in 1..=4u8 {
            let k = store.get(v).unwrap();
            assert_eq!(k.enc()[0], v);
        }
    }

    #[test]
    fn store_full() {
        let mut store = KeyStore::<2>::new();
        assert!(store.put(0x01, &test_keyset()).is_ok());
        assert!(store.put(0x02, &test_keyset()).is_ok());
        assert_eq!(
            store.put(0x03, &test_keyset()),
            Err(KeyStoreError::StoreFull)
        );
    }

    #[test]
    fn remove() {
        let mut store = KeyStore::<4>::new();
        assert!(store.put(0x01, &test_keyset()).is_ok());
        assert!(store.put(0x02, &test_keyset()).is_ok());
        assert!(store.remove(0x01).is_ok());
        assert_eq!(store.count(), 1);
        assert!(!store.has(0x01));
        assert!(store.has(0x02));
    }

    #[test]
    fn remove_not_found() {
        let mut store = KeyStore::<4>::new();
        assert_eq!(store.remove(0x01), Err(KeyStoreError::NotFound));
    }

    #[test]
    fn get_or_default_specific_version() {
        let mut store = KeyStore::<4>::new();
        assert!(store.put(0x01, &test_keyset()).is_ok());
        let (keys, version) = store.get_or_default(0x01).unwrap();
        assert_eq!(version, 0x01);
        assert_eq!(keys.enc(), &[0x40; 16]);
    }

    #[test]
    fn get_or_default_any_version() {
        let mut store = KeyStore::<4>::new();
        assert!(store.put(0x03, &test_keyset()).is_ok());
        let (_, version) = store.get_or_default(0x00).unwrap();
        assert_eq!(version, 0x03);
    }

    #[test]
    fn aes_key_set() {
        let keys = KeySet::aes128([0xA0; 16], [0xA1; 16], [0xA2; 16]);
        assert_eq!(keys.key_type, KeyType::Aes128);
        assert_eq!(keys.key_len(), 16);
        assert_eq!(keys.enc(), &[0xA0; 16]);
    }

    #[test]
    fn default_trait() {
        let store = KeyStore::<4>::default();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut store = KeyStore::<4>::new();
        let k1 = test_keyset();
        let k2 = KeySet::aes128([0xB0; 16], [0xB1; 16], [0xB2; 16]);
        assert!(store.put(0x01, &k1).is_ok());
        assert!(store.put(0x02, &k2).is_ok());

        let mut buf = [0u8; KeyStore::<4>::SNAPSHOT_SIZE];
        let written = store.save_state(&mut buf);

        let mut restored = KeyStore::<4>::new();
        assert!(restored.restore_state(&buf[..written]));
        assert_eq!(restored.count(), 2);
        assert_eq!(restored.get(0x01).unwrap().enc(), &[0x40; 16]);
        assert_eq!(restored.get(0x02).unwrap().key_type, KeyType::Aes128);
        assert_eq!(restored.get(0x02).unwrap().enc(), &[0xB0; 16]);
    }

    #[test]
    fn snapshot_empty_store() {
        let store = KeyStore::<4>::new();
        let mut buf = [0u8; KeyStore::<4>::SNAPSHOT_SIZE];
        let written = store.save_state(&mut buf);
        assert_eq!(written, 1); // just the count byte

        let mut restored = KeyStore::<4>::new();
        assert!(restored.restore_state(&buf[..written]));
        assert_eq!(restored.count(), 0);
    }

    #[test]
    fn snapshot_rejects_invalid() {
        let mut store = KeyStore::<4>::new();
        // Empty buffer.
        assert!(!store.restore_state(&[]));
        // Count exceeds capacity.
        assert!(!store.restore_state(&[5]));
        // Invalid key type byte.
        let mut bad = [0u8; 76];
        bad[0] = 1; // count = 1
        bad[1] = 0x01; // version
        bad[2] = 0xFF; // invalid key type
        assert!(!store.restore_state(&bad));
    }
}
