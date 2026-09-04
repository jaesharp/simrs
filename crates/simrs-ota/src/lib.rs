//! OTA (Over-The-Air) secured packet structure for SIM card remote management.
//!
//! Implements the command and response packet formats defined in:
//! - [ETSI TS 102 225 V19.0.0](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf) -- Secured packet structure for the UICC
//! - [ETSI TS 102 226 V19.0.0](../../../docs/specs/etsi/ts-102-226/ts_102226v190000p.pdf) -- Remote APDU structure for UICC-based applications
//!
//! # Supported Security Modes
//!
//! - No security (security parameters indicate no redundancy check and no ciphering)
//! - Cryptographic Checksum (CC) using AES-128 CBC-MAC or DES/3DES CBC-MAC
//! - AES-128 CBC or DES/3DES CBC encryption for ciphering
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::doc_markdown)] // ETSI/3GPP terms: OTA, SecurityParameters, KeyIdentifier, ToolkitAppReference, etc.
#![allow(clippy::missing_errors_doc)] // Error types are self-documenting
#![allow(clippy::must_use_candidate)] // matches workspace lint config
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::match_same_arms)] // explicit arms improve readability for bitfield decode

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::ct_eq;
use simrs_des::{Des, TripleDes};
use simrs_secret::Secret;

// ---------------------------------------------------------------------------
// Newtypes: ToolkitAppReference (TAR) and OtaCounter
// ---------------------------------------------------------------------------

/// Toolkit Application Reference (3 bytes).
///
/// Identifies the target application on the SIM for OTA messaging.
/// Per ETSI TS 102 225 clause 5.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolkitAppReference([u8; 3]);
impl ToolkitAppReference {
    /// Create a new `ToolkitAppReference` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 3]) -> Self {
        Self(raw)
    }
    /// Access the raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 3] {
        &self.0
    }
}
impl From<[u8; 3]> for ToolkitAppReference {
    fn from(raw: [u8; 3]) -> Self {
        Self(raw)
    }
}

/// ETSI abbreviation for [`ToolkitAppReference`].
///
/// The specs (ETSI TS 102 225 clause 5.1.1) use "TAR" (Toolkit Application
/// Reference). We prefer `ToolkitAppReference` for self-documenting code.
#[deprecated(note = "ETSI TAR (TS 102 225 cl. 5.1.1) -- prefer ToolkitAppReference")]
pub type Tar = ToolkitAppReference;

/// OTA replay counter (5 bytes).
///
/// Monotonic counter for replay protection in OTA secured packets.
/// Per ETSI TS 102 225 clause 5.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtaCounter([u8; 5]);
impl OtaCounter {
    /// Create a new `OtaCounter` from raw bytes.
    #[inline]
    pub const fn new(raw: [u8; 5]) -> Self {
        Self(raw)
    }
    /// Access the raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }
}
impl From<[u8; 5]> for OtaCounter {
    fn from(raw: [u8; 5]) -> Self {
        Self(raw)
    }
}

/// AES block size in bytes.
const AES_BLOCK: usize = 16;

/// DES/3DES block size in bytes.
const DES_BLOCK: usize = 8;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// OTA packet processing error.
///
/// ```
/// use simrs_ota::OtaError;
///
/// let err = OtaError::BufferTooSmall;
/// assert_eq!(format!("{err}"), "output buffer too small");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaError {
    /// Output buffer is too small for the encoded packet.
    BufferTooSmall,
    /// Input packet has an invalid or inconsistent length.
    InvalidLength,
    /// MAC verification failed on a received packet.
    MacVerifyFailed,
    /// Replay counter is lower than expected.
    CounterLow,
    /// Unsupported or unknown cryptographic algorithm.
    UnknownAlgorithm,
}

impl core::fmt::Display for OtaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("output buffer too small"),
            Self::InvalidLength => f.write_str("invalid packet length"),
            Self::MacVerifyFailed => f.write_str("MAC verification failed"),
            Self::CounterLow => f.write_str("replay counter too low"),
            Self::UnknownAlgorithm => f.write_str("unknown cryptographic algorithm"),
        }
    }
}

// ---------------------------------------------------------------------------
// Redundancy check mode
// ---------------------------------------------------------------------------

/// Redundancy check mode -- [ETSI TS 102 225 V19.0.0 clause 5.1.1](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A124%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C514%5D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedundancyCheck {
    /// No redundancy check.
    None,
    /// Cyclic Redundancy Check (CRC).
    Crc,
    /// Cryptographic Checksum (MAC).
    CryptographicChecksum,
    /// Digital Signature.
    DigitalSignature,
}

// ---------------------------------------------------------------------------
// Cryptographic algorithm
// ---------------------------------------------------------------------------

/// Cryptographic algorithm identifier -- [ETSI TS 102 225 V19.0.0 clause 5.1.2](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A126%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C430%5D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgo {
    /// DES / Triple-DES.
    Des,
    /// AES.
    Aes,
    /// Proprietary algorithm.
    Proprietary(u8),
}

// ---------------------------------------------------------------------------
// Security Parameters (TS 102 225 clause 5.1.1)
// ---------------------------------------------------------------------------

/// Security parameters.
///
/// [ETSI TS 102 225 V19.0.0 clause 5.1.1](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A124%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C514%5D).
/// Two bytes controlling the security applied to a command or response packet.
///
/// ```
/// use simrs_ota::{SecurityParameters, RedundancyCheck};
///
/// // Security parameters with cryptographic checksum integrity and ciphering enabled
/// let sp = SecurityParameters { command_header: 0x06, response_header: 0x01 };
/// assert_eq!(sp.redundancy_check(), RedundancyCheck::CryptographicChecksum);
/// assert!(sp.ciphering());
/// assert!(sp.por_required());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityParameters {
    /// First byte (redundancy check, ciphering, counter indicators).
    pub command_header: u8,
    /// Second byte (PoR settings).
    pub response_header: u8,
}

/// ETSI abbreviation for [`SecurityParameters`].
#[deprecated(note = "ETSI SPI (TS 102 225 cl. 5.1.1) -- prefer SecurityParameters")]
pub type Spi = SecurityParameters;

impl SecurityParameters {
    /// Redundancy check mode (command_header bits 1-0).
    ///
    /// Per [ETSI TS 102 225 V19.0.0 clause 5.1.1](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A124%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C514%5D):
    /// - `00` = No redundancy check
    /// - `01` = Redundancy Check (CRC)
    /// - `10` = Cryptographic Checksum (CC)
    /// - `11` = Digital Signature (DS)
    pub const fn redundancy_check(&self) -> RedundancyCheck {
        match self.command_header & 0x03 {
            0x00 => RedundancyCheck::None,
            0x01 => RedundancyCheck::Crc,
            0x02 => RedundancyCheck::CryptographicChecksum,
            0x03 => RedundancyCheck::DigitalSignature,
            _ => RedundancyCheck::None, // unreachable but keeps const fn happy
        }
    }

    /// Whether ciphering is indicated (command_header bit 2).
    pub const fn ciphering(&self) -> bool {
        self.command_header & 0x04 != 0
    }

    /// Whether a replay counter is available (command_header bit 3).
    pub const fn counter_available(&self) -> bool {
        self.command_header & 0x08 != 0
    }

    /// Whether a Proof of Receipt (PoR) is required (response_header bit 0).
    pub const fn por_required(&self) -> bool {
        self.response_header & 0x01 != 0
    }

    /// Whether the PoR shall be ciphered (response_header bit 2).
    pub const fn por_ciphered(&self) -> bool {
        self.response_header & 0x04 != 0
    }
}

// ---------------------------------------------------------------------------
// Key Identifier (TS 102 225 clause 5.1.2)
// ---------------------------------------------------------------------------

/// Key identifier byte.
///
/// [ETSI TS 102 225 V19.0.0 clause 5.1.2](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A126%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C430%5D).
/// Encodes both the cryptographic algorithm and the key index used for
/// ciphering or integrity protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyIdentifier {
    raw: u8,
}

/// ETSI abbreviation for [`KeyIdentifier`].
#[deprecated(note = "ETSI KIc/KID (TS 102 225 cl. 5.1.2) -- prefer KeyIdentifier")]
pub type KeyId = KeyIdentifier;

impl KeyIdentifier {
    /// Create a `KeyIdentifier` from a raw byte.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Raw byte value.
    pub const fn raw(&self) -> u8 {
        self.raw
    }

    /// Cryptographic algorithm (bits 2-0).
    ///
    /// Per [ETSI TS 102 225 V19.0.0 clause 5.1.2](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A126%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C430%5D):
    /// - `001` = DES
    /// - `010` = AES ([ETSI TS 102 225 V19.0.0 Annex B](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf))
    /// - Other = Proprietary
    pub const fn algorithm(&self) -> CryptoAlgo {
        match self.raw & 0x07 {
            0x01 => CryptoAlgo::Des,
            0x02 => CryptoAlgo::Aes,
            other => CryptoAlgo::Proprietary(other),
        }
    }

    /// Key version/index number (bits 7-4).
    pub const fn key_index(&self) -> u8 {
        (self.raw >> 4) & 0x0F
    }
}

// ---------------------------------------------------------------------------
// OTA cryptographic key
// ---------------------------------------------------------------------------

/// Typed OTA cryptographic key.
///
/// Wraps the key material with its algorithm tag for compile-time safety.
/// DES keys use 8-byte blocks, AES keys use 16-byte blocks; the block size
/// affects padding, MAC size, and CBC region alignment.
#[derive(Clone)]
pub enum OtaCryptoKey {
    /// AES-128 (16-byte key, 16-byte block).
    Aes(Secret<[u8; 16]>),
    /// DES (8-byte key, 8-byte block).
    Des(Secret<[u8; 8]>),
    /// Triple-DES 2-key mode (16-byte key = K1||K2, K3=K1).
    TripleDes(Secret<[u8; 16]>),
    /// Triple-DES 3-key mode (24-byte key = K1||K2||K3).
    TripleDes3(Secret<[u8; 24]>),
}

impl OtaCryptoKey {
    /// Block size for this key's algorithm.
    pub const fn block_size(&self) -> usize {
        match self {
            Self::Aes(_) => AES_BLOCK,
            Self::Des(_) | Self::TripleDes(_) | Self::TripleDes3(_) => DES_BLOCK,
        }
    }
}

// ---------------------------------------------------------------------------
// Command Packet Header
// ---------------------------------------------------------------------------

/// Size of the full header: SecurityParameters(2) + CipheringKeyId(1) + IntegrityKeyId(1) + TargetApp(3) + CNTR(5) + PCNTR(1) = 13.
const HEADER_SIZE: usize = 13;

/// Size of the pre-target-app portion: SecurityParameters(2) + CipheringKeyId(1) + IntegrityKeyId(1) = 4.
const PRE_TAR_SIZE: usize = 4;

/// Command packet header.
///
/// [ETSI TS 102 225 V19.0.0 clause 5.1](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A118%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C555%5D).
/// Contains the security parameters, key identifiers, target application
/// reference (TAR), replay counter, and padding counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPacketHeader {
    /// Security parameters controlling redundancy check, ciphering, and PoR.
    pub security_parameters: SecurityParameters,
    /// Key identifier for ciphering.
    pub ciphering_key_id: KeyIdentifier,
    /// Key identifier for integrity.
    pub integrity_key_id: KeyIdentifier,
    /// Toolkit Application Reference (3 bytes).
    pub target_app: ToolkitAppReference,
    /// Replay detection counter (5 bytes).
    pub counter: OtaCounter,
    /// Padding counter (number of padding bytes appended).
    pub padding_counter: u8,
}

impl CommandPacketHeader {
    /// Create a default (empty) header.
    pub const fn new() -> Self {
        Self {
            security_parameters: SecurityParameters {
                command_header: 0,
                response_header: 0,
            },
            ciphering_key_id: KeyIdentifier::new(0),
            integrity_key_id: KeyIdentifier::new(0),
            target_app: ToolkitAppReference::new([0; 3]),
            counter: OtaCounter::new([0; 5]),
            padding_counter: 0,
        }
    }
}

impl Default for CommandPacketHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Remote APDU (ETSI TS 102 226 V19.0.0)
// ---------------------------------------------------------------------------

/// Remote APDU command structure.
///
/// Per [ETSI TS 102 226 V19.0.0 clause 5.2.1](../../../docs/specs/etsi/ts-102-226/ts_102226v190000p.pdf#%5B%7B%22num%22%3A176%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C472%5D).
/// Used to encode remote file management or applet management commands
/// that are transported inside an OTA command packet.
#[derive(Debug, Clone)]
pub struct RemoteApdu {
    /// CLA byte.
    pub cla: u8,
    /// INS byte.
    pub ins: u8,
    /// P1 parameter.
    pub p1: u8,
    /// P2 parameter.
    pub p2: u8,
    /// Command data.
    pub data: [u8; 255],
    /// Length of valid data in `data`.
    pub data_len: u8,
}

impl RemoteApdu {
    /// Create a new empty remote APDU.
    pub const fn new() -> Self {
        Self {
            cla: 0,
            ins: 0,
            p1: 0,
            p2: 0,
            data: [0u8; 255],
            data_len: 0,
        }
    }
}

impl Default for RemoteApdu {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a list of remote APDUs into a command data field.
///
/// Per [ETSI TS 102 226 V19.0.0](../../../docs/specs/etsi/ts-102-226/ts_102226v190000p.pdf), each APDU is encoded as:
/// `CLA | INS | P1 | P2 | Lc | Data[Lc]`
///
/// For case 1 (no data), it is just `CLA | INS | P1 | P2`.
///
/// ```
/// use simrs_ota::{RemoteApdu, encode_remote_apdus};
///
/// // SELECT MF (3F00) -- case 3 APDU with 2 bytes of data
/// let mut apdu = RemoteApdu::new();
/// apdu.cla = 0xA0;
/// apdu.ins = 0xA4;
/// apdu.p1 = 0x00;
/// apdu.p2 = 0x00;
/// apdu.data[0] = 0x3F;
/// apdu.data[1] = 0x00;
/// apdu.data_len = 2;
///
/// let mut buf = [0u8; 64];
/// let len = encode_remote_apdus(&[apdu], &mut buf).unwrap();
/// assert_eq!(len, 7); // CLA + INS + P1 + P2 + Lc + 2 data bytes
/// assert_eq!(&buf[..7], &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
/// ```
pub fn encode_remote_apdus(apdus: &[RemoteApdu], buf: &mut [u8]) -> Result<usize, OtaError> {
    let mut pos = 0;
    for apdu in apdus {
        let dlen = apdu.data_len as usize;
        // Case 1 (no data): 4 bytes, Case 3 (with data): 5 + dlen
        let needed = if dlen == 0 { 4 } else { 5 + dlen };
        if pos + needed > buf.len() {
            return Err(OtaError::BufferTooSmall);
        }
        buf[pos] = apdu.cla;
        buf[pos + 1] = apdu.ins;
        buf[pos + 2] = apdu.p1;
        buf[pos + 3] = apdu.p2;
        if dlen > 0 {
            buf[pos + 4] = apdu.data_len;
            buf[pos + 5..pos + 5 + dlen].copy_from_slice(&apdu.data[..dlen]);
        }
        pos += needed;
    }
    Ok(pos)
}

// ---------------------------------------------------------------------------
// Padding (ETSI TS 102 225 V19.0.0 clause 5.1.4)
// ---------------------------------------------------------------------------

/// Apply zero-byte padding to make `data` a multiple of `block_size`.
///
/// Copies `data` into `padded` and appends `0x00` bytes as needed.
/// Returns the padded length. If `data` is already block-aligned,
/// no padding is added.
fn apply_padding(data: &[u8], padded: &mut [u8], block_size: usize) -> Result<usize, OtaError> {
    let pad_len = if data.len().is_multiple_of(block_size) && !data.is_empty() {
        data.len()
    } else {
        (data.len() / block_size + 1) * block_size
    };
    if padded.len() < pad_len {
        return Err(OtaError::BufferTooSmall);
    }
    padded[..data.len()].copy_from_slice(data);
    for b in &mut padded[data.len()..pad_len] {
        *b = 0x00;
    }
    Ok(pad_len)
}

// ---------------------------------------------------------------------------
// AES-CBC-MAC (encrypt-only chain)
// ---------------------------------------------------------------------------

/// Compute AES-128 CBC-MAC over `data`.
///
/// `data` must be a multiple of 16 bytes (caller pads first). The IV is
/// all-zeros per the OTA specification default. Returns the 8-byte MAC
/// (left half of the final CBC block) per [ETSI TS 102 225 V19.0.0 Annex B](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf).
fn aes_cbc_mac(key: &Secret<[u8; 16]>, data: &[u8]) -> [u8; 8] {
    let full_mac = simrs_iso9797::aes128_cbc_mac(key, data);
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&full_mac[..8]);
    mac
}

// ---------------------------------------------------------------------------
// AES-CBC encrypt
// ---------------------------------------------------------------------------

/// AES-128 CBC encrypt `data` in-place.
///
/// `data` must be a multiple of 16 bytes. IV is all-zeros per
/// ETSI TS 102 225 V19.0.0 clause 5.1. Replay protection is provided
/// by the CNTR field inside the encrypted region.
fn aes_cbc_encrypt(key: &Secret<[u8; 16]>, data: &mut [u8]) {
    simrs_iso9797::aes128_cbc_encrypt(key, &[0u8; 16], data);
}

/// AES-128 CBC decrypt `data` in-place.
///
/// `data` must be a multiple of 16 bytes. IV is all-zeros per
/// ETSI TS 102 225 V19.0.0 clause 5.1.
fn aes_cbc_decrypt(key: &Secret<[u8; 16]>, data: &mut [u8]) {
    simrs_iso9797::aes128_cbc_decrypt(key, &[0u8; 16], data);
}

// ---------------------------------------------------------------------------
// DES/3DES-CBC-MAC, encrypt, decrypt
// ---------------------------------------------------------------------------

/// Trait-like helper: encrypt a single DES-sized block with the appropriate
/// DES/3DES variant selected by an `OtaCryptoKey`.
fn des_encrypt_block(key: &OtaCryptoKey, block: [u8; 8]) -> [u8; 8] {
    match key {
        OtaCryptoKey::Des(k) => Des::new(k).encrypt(&block),
        OtaCryptoKey::TripleDes(k) => TripleDes::new_2key(k).encrypt(&block),
        OtaCryptoKey::TripleDes3(k) => TripleDes::new_3key(k).encrypt(&block),
        OtaCryptoKey::Aes(_) => unreachable!(),
    }
}

/// Trait-like helper: decrypt a single DES-sized block.
fn des_decrypt_block(key: &OtaCryptoKey, block: [u8; 8]) -> [u8; 8] {
    match key {
        OtaCryptoKey::Des(k) => Des::new(k).decrypt(&block),
        OtaCryptoKey::TripleDes(k) => TripleDes::new_2key(k).decrypt(&block),
        OtaCryptoKey::TripleDes3(k) => TripleDes::new_3key(k).decrypt(&block),
        OtaCryptoKey::Aes(_) => unreachable!(),
    }
}

/// Compute DES/3DES CBC-MAC over `data`.
///
/// `data` must be a multiple of 8 bytes (caller pads first). IV is all-zeros.
/// Returns the 4-byte MAC (left half of the final CBC block) per
/// [ETSI TS 102 225 V19.0.0 clause 5.1.3.2](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf).
fn des_cbc_mac(key: &OtaCryptoKey, data: &[u8]) -> [u8; 4] {
    let full_mac = match key {
        OtaCryptoKey::Des(k) => simrs_iso9797::des_cbc_mac(k, data),
        OtaCryptoKey::TripleDes(k) => simrs_iso9797::des3_2key_cbc_mac(k, data),
        OtaCryptoKey::TripleDes3(k) => simrs_iso9797::des3_3key_cbc_mac(k, data),
        OtaCryptoKey::Aes(_) => unreachable!(),
    };
    let mut mac = [0u8; 4];
    mac.copy_from_slice(&full_mac[..4]);
    mac
}

/// DES/3DES CBC encrypt `data` in-place.
///
/// `data` must be a multiple of 8 bytes. IV is all-zeros.
fn des_cbc_encrypt(key: &OtaCryptoKey, data: &mut [u8]) {
    if let OtaCryptoKey::TripleDes(k) = key {
        simrs_iso9797::des3_2key_cbc_encrypt(k, &[0u8; 8], data);
    } else {
        let mut cv = [0u8; 8];
        let mut off = 0;
        while off + DES_BLOCK <= data.len() {
            let mut block = [0u8; 8];
            block.copy_from_slice(&data[off..off + 8]);
            for i in 0..8 {
                block[i] ^= cv[i];
            }
            cv = des_encrypt_block(key, block);
            data[off..off + 8].copy_from_slice(&cv);
            off += 8;
        }
    }
}

/// DES/3DES CBC decrypt `data` in-place.
///
/// `data` must be a multiple of 8 bytes. IV is all-zeros.
fn des_cbc_decrypt(key: &OtaCryptoKey, data: &mut [u8]) {
    if let OtaCryptoKey::TripleDes(k) = key {
        simrs_iso9797::des3_2key_cbc_decrypt(k, &[0u8; 8], data);
    } else {
        let mut prev_ct = [0u8; 8];
        let mut off = 0;
        while off + DES_BLOCK <= data.len() {
            let mut ct_block = [0u8; 8];
            ct_block.copy_from_slice(&data[off..off + 8]);
            let mut pt_block = des_decrypt_block(key, ct_block);
            for i in 0..8 {
                pt_block[i] ^= prev_ct[i];
            }
            data[off..off + 8].copy_from_slice(&pt_block);
            prev_ct = ct_block;
            off += 8;
        }
    }
}

// ---------------------------------------------------------------------------
// Command packet encoding (ETSI TS 102 225 V19.0.0 clause 5.1)
// ---------------------------------------------------------------------------

/// CC size for AES (8 bytes -- left half of final AES-CBC block).
const AES_CC_SIZE: usize = 8;

/// CC size for DES/3DES (4 bytes -- left half of final DES-CBC block).
const DES_CC_SIZE: usize = 4;

/// Returns the CC size for the given key, or 0 (AES default) if no key.
const fn cc_size_for(key: Option<&OtaCryptoKey>) -> usize {
    match key {
        Some(OtaCryptoKey::Des(_) | OtaCryptoKey::TripleDes(_) | OtaCryptoKey::TripleDes3(_)) => {
            DES_CC_SIZE
        }
        _ => AES_CC_SIZE,
    }
}

/// Returns the block size for the given key, or AES default if no key.
const fn block_size_for(key: Option<&OtaCryptoKey>) -> usize {
    match key {
        Some(k) => k.block_size(),
        None => AES_BLOCK,
    }
}

/// Encode a command packet.
///
/// Per [ETSI TS 102 225 V19.0.0 clause 5.1](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A118%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C555%5D).
/// The packet layout in `buf` is:
/// ```text
/// CPL(2) | CHL(1) | SecurityParameters(2) | CipheringKeyId(1) | IntegrityKeyId(1) | TargetApp(3) | CNTR(5) | PCNTR(1) | CC(4|8)? | data...
/// ```
///
/// - `hdr`: Command packet header (security parameters, key identifiers, target app, counter).
/// - `data`: Remote APDU payload ([ETSI TS 102 226 V19.0.0](../../../docs/specs/etsi/ts-102-226/ts_102226v190000p.pdf) encoded).
/// - `key_cipher`: Cryptographic key for ciphering (if security parameters indicate ciphering).
/// - `key_mac`: Cryptographic key for CC (if security parameters indicate CC).
/// - `buf`: Output buffer, must be large enough to hold the complete packet.
///
/// Returns the total number of bytes written to `buf`.
///
/// # Example: Encode and decode a command packet without security
///
/// ```
/// use simrs_ota::{CommandPacketHeader, SecurityParameters, KeyIdentifier, ToolkitAppReference, OtaCounter,
///                  encode_command_packet, decode_command_packet};
///
/// let hdr = CommandPacketHeader {
///     security_parameters: SecurityParameters { command_header: 0x00, response_header: 0x00 },
///     ciphering_key_id: KeyIdentifier::new(0x00),
///     integrity_key_id: KeyIdentifier::new(0x00),
///     target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
///     counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]),
///     padding_counter: 0,
/// };
/// let payload = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
///
/// let mut buf = [0u8; 256];
/// let len = encode_command_packet(&hdr, &payload, None, None, &mut buf).unwrap();
/// assert!(len > 0);
///
/// // Decode it back
/// let mut dec_hdr = CommandPacketHeader::new();
/// let mut dec_data = [0u8; 256];
/// let dlen = decode_command_packet(
///     &buf[..len], None, None, &mut dec_hdr, &mut dec_data,
/// ).unwrap();
/// assert_eq!(&dec_data[..dlen], &payload);
/// assert_eq!(*dec_hdr.target_app.as_bytes(), [0xB0, 0x00, 0x10]);
/// ```
pub fn encode_command_packet(
    hdr: &CommandPacketHeader,
    data: &[u8],
    key_cipher: Option<&OtaCryptoKey>,
    key_mac: Option<&OtaCryptoKey>,
    buf: &mut [u8],
) -> Result<usize, OtaError> {
    let has_cc = matches!(
        hdr.security_parameters.redundancy_check(),
        RedundancyCheck::CryptographicChecksum
    );
    let has_cipher = hdr.security_parameters.ciphering();

    let cc_sz = cc_size_for(key_mac);
    let rc_size = if has_cc { cc_sz } else { 0 };
    let blk = block_size_for(key_cipher.or(key_mac));

    // The secured data region (after target app) that gets ciphered:
    // CNTR(5) + PCNTR(1) + CC? + data
    let secured_data_len = 5 + 1 + rc_size + data.len();

    // If ciphering, pad the secured data to a block boundary.
    let (padded_secured_len, padding_count) = if has_cipher {
        let padded = secured_data_len.div_ceil(blk) * blk;
        (padded, padded - secured_data_len)
    } else {
        (secured_data_len, 0_usize)
    };

    // CHL = header bytes from SecurityParameters through CC (inclusive):
    // SecurityParameters(2) + CipheringKeyId(1) + IntegrityKeyId(1) + TargetApp(3) + CNTR(5) + PCNTR(1) + CC = 13 + rc_size
    #[allow(clippy::cast_possible_truncation)]
    let chl: u8 = (HEADER_SIZE + rc_size) as u8;

    // Packet layout:
    //   Offset 0-1:   CPL (2 bytes, big-endian)
    //   Offset 2:     CHL (1 byte)
    //   Offset 3-4:   SecurityParameters (2 bytes)
    //   Offset 5:     CipheringKeyId
    //   Offset 6:     IntegrityKeyId
    //   Offset 7-9:   TargetApp (3 bytes)
    //   Offset 10-14: CNTR (5 bytes)
    //   Offset 15:    PCNTR
    //   Offset 16..:  CC (cc_sz bytes if present)
    //   After CC:     data + padding

    let data_with_padding_len = data.len() + padding_count;
    let total = 2 + 1 + PRE_TAR_SIZE + 3 + 5 + 1 + rc_size + data_with_padding_len;

    if buf.len() < total {
        return Err(OtaError::BufferTooSmall);
    }

    // CPL = total - 2 (everything after the CPL field itself)
    #[allow(clippy::cast_possible_truncation)]
    let cpl = (total - 2) as u16;
    let cpl_bytes = cpl.to_be_bytes();
    buf[0] = cpl_bytes[0];
    buf[1] = cpl_bytes[1];
    buf[2] = chl;

    // Header fields
    buf[3] = hdr.security_parameters.command_header;
    buf[4] = hdr.security_parameters.response_header;
    buf[5] = hdr.ciphering_key_id.raw();
    buf[6] = hdr.integrity_key_id.raw();
    buf[7] = hdr.target_app.as_bytes()[0];
    buf[8] = hdr.target_app.as_bytes()[1];
    buf[9] = hdr.target_app.as_bytes()[2];
    buf[10] = hdr.counter.as_bytes()[0];
    buf[11] = hdr.counter.as_bytes()[1];
    buf[12] = hdr.counter.as_bytes()[2];
    buf[13] = hdr.counter.as_bytes()[3];
    buf[14] = hdr.counter.as_bytes()[4];

    #[allow(clippy::cast_possible_truncation)]
    {
        buf[15] = padding_count as u8;
    }

    let cc_offset = 16;
    let data_offset = cc_offset + rc_size;

    // Write data + zero-padding
    buf[data_offset..data_offset + data.len()].copy_from_slice(data);
    for b in &mut buf[data_offset + data.len()..data_offset + data_with_padding_len] {
        *b = 0x00;
    }

    // Compute CBC-MAC if CC mode
    if has_cc {
        if let Some(km) = key_mac {
            // Zero the CC field before MAC computation
            for b in &mut buf[cc_offset..cc_offset + cc_sz] {
                *b = 0x00;
            }
            // MAC input: header fields from SecurityParameters through end of data+padding
            let mac_region = &buf[3..total];
            let mut mac_buf = [0u8; 1024];
            let padded_len = apply_padding(mac_region, &mut mac_buf, blk)?;
            match km {
                OtaCryptoKey::Aes(k) => {
                    let mac = aes_cbc_mac(k, &mac_buf[..padded_len]);
                    buf[cc_offset..cc_offset + cc_sz].copy_from_slice(&mac);
                }
                des_key => {
                    let mac = des_cbc_mac(des_key, &mac_buf[..padded_len]);
                    buf[cc_offset..cc_offset + cc_sz].copy_from_slice(&mac);
                }
            }
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    // Encrypt: the ciphered region is CNTR through end of data+padding
    if has_cipher {
        if let Some(kc) = key_cipher {
            let cipher_region = &mut buf[10..total];
            debug_assert_eq!(cipher_region.len(), padded_secured_len);
            match kc {
                OtaCryptoKey::Aes(k) => aes_cbc_encrypt(k, cipher_region),
                des_key => des_cbc_encrypt(des_key, cipher_region),
            }
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    Ok(total)
}

// ---------------------------------------------------------------------------
// Command packet decoding (ETSI TS 102 225 V19.0.0 clause 5.1)
// ---------------------------------------------------------------------------

/// Decode and verify a command packet.
///
/// Per [ETSI TS 102 225 V19.0.0 clause 5.1](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A118%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C555%5D).
/// Encoding order is MAC-then-encrypt, so decoding is decrypt-then-verify-MAC.
///
/// - `packet`: The complete received packet bytes.
/// - `key_cipher`: Cryptographic key for deciphering (required if security parameters indicate ciphering).
/// - `key_mac`: Cryptographic key for CC verification (required if security parameters indicate CC).
/// - `hdr_out`: Decoded header is written here.
/// - `data_out`: Decoded command data is written here.
///
/// Returns the number of data bytes written to `data_out`.
pub fn decode_command_packet(
    packet: &[u8],
    key_cipher: Option<&OtaCryptoKey>,
    key_mac: Option<&OtaCryptoKey>,
    hdr_out: &mut CommandPacketHeader,
    data_out: &mut [u8],
) -> Result<usize, OtaError> {
    // Minimum: CPL(2) + CHL(1) + SecurityParameters(2) + CipheringKeyId(1) + IntegrityKeyId(1) + TargetApp(3) + CNTR(5) + PCNTR(1) = 16
    if packet.len() < 16 {
        return Err(OtaError::InvalidLength);
    }

    let cpl = u16::from_be_bytes([packet[0], packet[1]]) as usize;
    if cpl + 2 > packet.len() {
        return Err(OtaError::InvalidLength);
    }

    // CHL at packet[2] is not needed for decoding (we use fixed offsets)
    let total = cpl + 2;

    // Decode SecurityParameters, CipheringKeyId, IntegrityKeyId, TargetApp
    hdr_out.security_parameters = SecurityParameters {
        command_header: packet[3],
        response_header: packet[4],
    };
    hdr_out.ciphering_key_id = KeyIdentifier::new(packet[5]);
    hdr_out.integrity_key_id = KeyIdentifier::new(packet[6]);
    hdr_out.target_app = ToolkitAppReference::new([packet[7], packet[8], packet[9]]);

    let has_cc = matches!(
        hdr_out.security_parameters.redundancy_check(),
        RedundancyCheck::CryptographicChecksum
    );
    let has_cipher = hdr_out.security_parameters.ciphering();
    let cc_sz = cc_size_for(key_mac);
    let rc_size = if has_cc { cc_sz } else { 0 };
    let blk = block_size_for(key_cipher.or(key_mac));

    // The secured region (CNTR through end of packet) starts at offset 10.
    // Copy into a working buffer so we can decrypt in-place when ciphered.
    let secured_len = total - 10;
    let mut work = [0u8; 1024];
    if secured_len > work.len() {
        return Err(OtaError::BufferTooSmall);
    }
    work[..secured_len].copy_from_slice(&packet[10..total]);

    // Decrypt the secured region if ciphered.
    // Encode order is MAC-then-encrypt, so decode is decrypt-then-verify-MAC.
    if has_cipher {
        if let Some(kc) = key_cipher {
            match kc {
                OtaCryptoKey::Aes(k) => aes_cbc_decrypt(k, &mut work[..secured_len]),
                des_key => des_cbc_decrypt(des_key, &mut work[..secured_len]),
            }
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    // Parse CNTR and PCNTR from the (possibly decrypted) working buffer.
    // Layout: CNTR(5) + PCNTR(1) + CC(cc_sz)? + data + padding
    if secured_len < 6 + rc_size {
        return Err(OtaError::InvalidLength);
    }
    hdr_out.counter = OtaCounter::new([work[0], work[1], work[2], work[3], work[4]]);
    hdr_out.padding_counter = work[5];

    let cc_offset = 6; // within work buffer
    let data_offset = cc_offset + rc_size;

    // Verify MAC if CC mode.
    if has_cc {
        if let Some(km) = key_mac {
            // Extract the received MAC from the (decrypted) work buffer
            let mut received_mac = [0u8; AES_CC_SIZE]; // oversized for DES (4), fine
            received_mac[..cc_sz].copy_from_slice(&work[cc_offset..cc_offset + cc_sz]);

            // Re-build the MAC input: header fields (clear) + secured region (decrypted, CC zeroed)
            let mac_input_len = 7 + secured_len;
            let mut recompute_buf = [0u8; 1024];
            if mac_input_len > recompute_buf.len() {
                return Err(OtaError::BufferTooSmall);
            }
            recompute_buf[..7].copy_from_slice(&packet[3..10]);
            recompute_buf[7..7 + secured_len].copy_from_slice(&work[..secured_len]);
            // Zero the CC field (at offset 7 + 6 = 13 in the recompute buffer)
            let cc_in_buf = 7 + cc_offset;
            for b in &mut recompute_buf[cc_in_buf..cc_in_buf + cc_sz] {
                *b = 0x00;
            }
            let mut mac_padded = [0u8; 1024];
            let padded_len = apply_padding(&recompute_buf[..mac_input_len], &mut mac_padded, blk)?;
            match km {
                OtaCryptoKey::Aes(k) => {
                    let computed_mac = aes_cbc_mac(k, &mac_padded[..padded_len]);
                    if !ct_eq(&computed_mac, &received_mac[..cc_sz]).into_bool() {
                        return Err(OtaError::MacVerifyFailed);
                    }
                }
                des_key => {
                    let computed_mac = des_cbc_mac(des_key, &mac_padded[..padded_len]);
                    if !ct_eq(&computed_mac, &received_mac[..cc_sz]).into_bool() {
                        return Err(OtaError::MacVerifyFailed);
                    }
                }
            }
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    // Extract data (subtract padding bytes)
    let raw_data_len = secured_len - data_offset;
    let padding = hdr_out.padding_counter as usize;
    if padding > raw_data_len {
        return Err(OtaError::InvalidLength);
    }
    let data_len = raw_data_len - padding;
    if data_out.len() < data_len {
        return Err(OtaError::BufferTooSmall);
    }
    data_out[..data_len].copy_from_slice(&work[data_offset..data_offset + data_len]);

    Ok(data_len)
}

// ---------------------------------------------------------------------------
// Response packet encoding (ETSI TS 102 225 V19.0.0 clause 5.2)
// ---------------------------------------------------------------------------

/// Encode a response packet.
///
/// Per [ETSI TS 102 225 V19.0.0 clause 5.2](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A143%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C787%5D).
/// Layout:
/// ```text
/// RPL(2) | RHL(1) | TAR(3) | CNTR(5) | PCNTR(1) | STATUS(1) | CC(8)? | data...
/// ```
///
/// - `tar`: Toolkit Application Reference (echoed from command).
/// - `counter`: Replay counter (echoed or incremented).
/// - `status_code`: Response status code per [ETSI TS 102 225 V19.0.0 clause 5.2.1](../../../docs/specs/etsi/ts-102-225/ts_102225v190000p.pdf#%5B%7B%22num%22%3A143%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C787%5D).
/// - `data`: Response data.
/// - `security_params`: Security parameters from the original command (determines security applied to response).
/// - `key_cipher`: AES-128 key for ciphering the response.
/// - `key_mac`: AES-128 key for CC on the response.
/// - `buf`: Output buffer.
///
/// Returns the total number of bytes written.
///
/// ```
/// use simrs_ota::{SecurityParameters, ToolkitAppReference, OtaCounter, encode_response_packet};
///
/// let tar = ToolkitAppReference::new([0xB0, 0x00, 0x10]);
/// let counter = OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]);
/// let sp = SecurityParameters { command_header: 0x00, response_header: 0x00 }; // no security
///
/// let mut buf = [0u8; 256];
/// let len = encode_response_packet(
///     &tar, &counter, 0x00, &[], &sp, None, None, &mut buf,
/// ).unwrap();
///
/// // RPL(2) + RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STATUS(1) = 13
/// assert_eq!(len, 13);
/// assert_eq!(&buf[3..6], tar.as_bytes());
/// assert_eq!(buf[12], 0x00); // status code
/// ```
#[allow(clippy::too_many_arguments)]
pub fn encode_response_packet(
    tar: &ToolkitAppReference,
    counter: &OtaCounter,
    status_code: u8,
    data: &[u8],
    security_params: &SecurityParameters,
    key_cipher: Option<&OtaCryptoKey>,
    key_mac: Option<&OtaCryptoKey>,
    buf: &mut [u8],
) -> Result<usize, OtaError> {
    let has_cc = matches!(
        security_params.redundancy_check(),
        RedundancyCheck::CryptographicChecksum
    );
    let has_cipher = security_params.por_ciphered();
    let cc_sz = cc_size_for(key_mac);
    let rc_size = if has_cc { cc_sz } else { 0 };
    let blk = block_size_for(key_cipher.or(key_mac));

    // Secured data region (from CNTR): CNTR(5) + PCNTR(1) + STATUS(1) + CC? + data
    let secured_data_len = 5 + 1 + 1 + rc_size + data.len();
    let (padded_secured_len, padding_count) = if has_cipher {
        let padded = secured_data_len.div_ceil(blk) * blk;
        (padded, padded - secured_data_len)
    } else {
        (secured_data_len, 0_usize)
    };

    let data_with_padding_len = data.len() + padding_count;

    // RHL covers: TAR(3) + CNTR(5) + PCNTR(1) + STATUS(1) + CC
    #[allow(clippy::cast_possible_truncation)]
    let rhl: u8 = (3 + 5 + 1 + 1 + rc_size) as u8;

    // Total: RPL(2) + RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STATUS(1) + CC? + data + padding
    let total = 2 + 1 + 3 + 5 + 1 + 1 + rc_size + data_with_padding_len;

    if buf.len() < total {
        return Err(OtaError::BufferTooSmall);
    }

    #[allow(clippy::cast_possible_truncation)]
    let rpl = (total - 2) as u16;
    let rpl_bytes = rpl.to_be_bytes();
    buf[0] = rpl_bytes[0];
    buf[1] = rpl_bytes[1];
    buf[2] = rhl;
    buf[3] = tar.as_bytes()[0];
    buf[4] = tar.as_bytes()[1];
    buf[5] = tar.as_bytes()[2];
    buf[6] = counter.as_bytes()[0];
    buf[7] = counter.as_bytes()[1];
    buf[8] = counter.as_bytes()[2];
    buf[9] = counter.as_bytes()[3];
    buf[10] = counter.as_bytes()[4];

    #[allow(clippy::cast_possible_truncation)]
    {
        buf[11] = padding_count as u8;
    }
    buf[12] = status_code;

    let cc_offset = 13;
    let data_offset = cc_offset + rc_size;

    // Write data + zero-padding
    buf[data_offset..data_offset + data.len()].copy_from_slice(data);
    for b in &mut buf[data_offset + data.len()..data_offset + data_with_padding_len] {
        *b = 0x00;
    }

    // Compute CBC-MAC if CC mode
    if has_cc {
        if let Some(km) = key_mac {
            for b in &mut buf[cc_offset..cc_offset + cc_sz] {
                *b = 0x00;
            }
            let mac_region = &buf[3..total];
            let mut mac_buf = [0u8; 1024];
            let padded_len = apply_padding(mac_region, &mut mac_buf, blk)?;
            match km {
                OtaCryptoKey::Aes(k) => {
                    let mac = aes_cbc_mac(k, &mac_buf[..padded_len]);
                    buf[cc_offset..cc_offset + cc_sz].copy_from_slice(&mac);
                }
                des_key => {
                    let mac = des_cbc_mac(des_key, &mac_buf[..padded_len]);
                    buf[cc_offset..cc_offset + cc_sz].copy_from_slice(&mac);
                }
            }
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    // Encrypt if PoR ciphered
    if has_cipher {
        if let Some(kc) = key_cipher {
            let cipher_region = &mut buf[6..total];
            debug_assert_eq!(cipher_region.len(), padded_secured_len);
            match kc {
                OtaCryptoKey::Aes(k) => aes_cbc_encrypt(k, cipher_region),
                des_key => des_cbc_encrypt(des_key, cipher_region),
            }
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    Ok(total)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // 1. Security parameters redundancy check = None
    #[test]
    fn security_parameters_redundancy_check_none() {
        let sp = SecurityParameters {
            command_header: 0x00,
            response_header: 0x00,
        };
        assert_eq!(sp.redundancy_check(), RedundancyCheck::None);
    }

    // 2. Security parameters redundancy check = CryptographicChecksum
    #[test]
    fn security_parameters_redundancy_check_cc() {
        let sp = SecurityParameters {
            command_header: 0x02,
            response_header: 0x00,
        };
        assert_eq!(
            sp.redundancy_check(),
            RedundancyCheck::CryptographicChecksum
        );
    }

    // 3. Security parameters ciphering flag
    #[test]
    fn security_parameters_ciphering_enabled() {
        let sp_on = SecurityParameters {
            command_header: 0x04,
            response_header: 0x00,
        };
        assert!(sp_on.ciphering());
        let sp_off = SecurityParameters {
            command_header: 0x00,
            response_header: 0x00,
        };
        assert!(!sp_off.ciphering());
    }

    // 4. Security parameters counter available flag
    #[test]
    fn security_parameters_counter_available() {
        let sp_on = SecurityParameters {
            command_header: 0x08,
            response_header: 0x00,
        };
        assert!(sp_on.counter_available());
        let sp_off = SecurityParameters {
            command_header: 0x00,
            response_header: 0x00,
        };
        assert!(!sp_off.counter_available());
    }

    // 5. Key identifier AES algorithm
    #[test]
    fn key_identifier_aes_algorithm() {
        let kid = KeyIdentifier::new(0x12); // bits 2-0 = 0x02 = AES, key_index = 1
        assert_eq!(kid.algorithm(), CryptoAlgo::Aes);
    }

    // 6. Key identifier DES algorithm
    #[test]
    fn key_identifier_des_algorithm() {
        let kid = KeyIdentifier::new(0x01); // bits 2-0 = 0x01 = DES
        assert_eq!(kid.algorithm(), CryptoAlgo::Des);
    }

    // 7. Key index extraction
    #[test]
    fn key_identifier_key_index_extraction() {
        let kid = KeyIdentifier::new(0x32); // key_index = 3 (bits 7-4), algo = AES (bits 2-0 = 2)
        assert_eq!(kid.key_index(), 3);
        assert_eq!(kid.algorithm(), CryptoAlgo::Aes);
    }

    // 8. Padding: already aligned (no pad added)
    #[test]
    fn padding_exact_block_no_pad() {
        let data = [0xAAu8; 16];
        let mut padded = [0u8; 32];
        let len = apply_padding(&data, &mut padded, AES_BLOCK).unwrap();
        assert_eq!(len, 16);
        assert_eq!(&padded[..16], &data);
    }

    // 9. Padding: adds zeros
    #[test]
    fn padding_adds_zeros() {
        let data = [0xBBu8; 10];
        let mut padded = [0xFFu8; 32];
        let len = apply_padding(&data, &mut padded, AES_BLOCK).unwrap();
        assert_eq!(len, 16);
        assert_eq!(&padded[..10], &data);
        assert_eq!(&padded[10..16], &[0x00; 6]);
    }

    // 10. Encode command packet without any security
    #[test]
    fn encode_command_packet_no_security() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x00,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x00),
            integrity_key_id: KeyIdentifier::new(0x00),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00; 5]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];

        let mut buf = [0u8; 256];
        let len = encode_command_packet(&hdr, &data, None, None, &mut buf).unwrap();

        // CPL check
        let cpl = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(cpl + 2, len);

        // TargetApp at offset 7-9
        assert_eq!(&buf[7..10], &[0xB0, 0x00, 0x10]);

        // Data at offset 16 (no CC), 7 bytes
        assert_eq!(&buf[16..16 + 7], &data);
    }

    // 11. Encode command packet with CC (MAC)
    #[test]
    fn encode_command_packet_with_mac() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x02,
                response_header: 0x00,
            }, // CC mode
            ciphering_key_id: KeyIdentifier::new(0x02),
            integrity_key_id: KeyIdentifier::new(0x02),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_mac = OtaCryptoKey::Aes(Secret::new([0x40u8; 16]));

        let mut buf = [0u8; 256];
        let len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        // CC at offset 16, 8 bytes -- must not be all zeros
        let cc = &buf[16..24];
        assert_ne!(cc, &[0u8; 8]);

        // Data follows CC at offset 24
        assert_eq!(&buf[24..28], &data);

        // Total = 2 + 1 + 4 + 3 + 5 + 1 + 8 + 4 = 28
        assert_eq!(len, 28);
    }

    // 12. Encode then decode roundtrip (no security)
    #[test]
    fn decode_command_packet_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x00,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x00),
            integrity_key_id: KeyIdentifier::new(0x00),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x05]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, None, &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            None,
            None,
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(
            *decoded_hdr.target_app.as_bytes(),
            *hdr.target_app.as_bytes()
        );
        assert_eq!(*decoded_hdr.counter.as_bytes(), *hdr.counter.as_bytes());
        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 13. Encode then decode with MAC verification
    #[test]
    fn decode_command_packet_mac_verify() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x02,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x02),
            integrity_key_id: KeyIdentifier::new(0x02),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_mac = OtaCryptoKey::Aes(Secret::new([0x40u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            None,
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 14. Tampered data causes MAC failure
    #[test]
    fn decode_command_packet_bad_mac_fails() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x02,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x02),
            integrity_key_id: KeyIdentifier::new(0x02),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00; 5]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_mac = OtaCryptoKey::Aes(Secret::new([0x40u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        // Tamper with the last data byte
        buf[enc_len - 1] ^= 0xFF;

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let result = decode_command_packet(
            &buf[..enc_len],
            None,
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        );
        assert_eq!(result, Err(OtaError::MacVerifyFailed));
    }

    // 15. Response packet encoding
    #[test]
    fn encode_response_packet_basic() {
        let tar = ToolkitAppReference::new([0xB0, 0x00, 0x10]);
        let counter = OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]);
        let sp = SecurityParameters {
            command_header: 0x00,
            response_header: 0x00,
        };

        let mut buf = [0u8; 256];
        let len =
            encode_response_packet(&tar, &counter, 0x00, &[], &sp, None, None, &mut buf).unwrap();

        // RPL(2) + RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STATUS(1) = 13
        assert_eq!(len, 13);
        assert_eq!(&buf[3..6], tar.as_bytes());
        assert_eq!(buf[12], 0x00); // status
    }

    // 16. Single remote APDU encoding
    #[test]
    fn encode_remote_apdu_single() {
        let mut apdu = RemoteApdu::new();
        apdu.cla = 0xA0;
        apdu.ins = 0xA4;
        apdu.p1 = 0x00;
        apdu.p2 = 0x00;
        apdu.data[0] = 0x3F;
        apdu.data[1] = 0x00;
        apdu.data_len = 2;

        let mut buf = [0u8; 64];
        let len = encode_remote_apdus(&[apdu], &mut buf).unwrap();

        assert_eq!(len, 7);
        assert_eq!(&buf[..7], &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
    }

    // 17. Multiple remote APDUs
    #[test]
    fn encode_remote_apdu_multiple() {
        let mut apdu1 = RemoteApdu::new();
        apdu1.cla = 0xA0;
        apdu1.ins = 0xA4;
        apdu1.p1 = 0x00;
        apdu1.p2 = 0x00;
        apdu1.data[0] = 0x3F;
        apdu1.data[1] = 0x00;
        apdu1.data_len = 2;

        let apdu2 = RemoteApdu {
            cla: 0xA0,
            ins: 0xB0,
            p1: 0x00,
            p2: 0x00,
            data: [0u8; 255],
            data_len: 0,
        };

        let mut buf = [0u8; 64];
        let len = encode_remote_apdus(&[apdu1, apdu2], &mut buf).unwrap();

        // First: 7 bytes (case 3), second: 4 bytes (case 1)
        assert_eq!(len, 11);
        assert_eq!(&buf[7..11], &[0xA0, 0xB0, 0x00, 0x00]);
    }

    // 18. Command packet with counter field
    #[test]
    fn command_packet_with_counter() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x08,
                response_header: 0x00,
            }, // counter available
            ciphering_key_id: KeyIdentifier::new(0x00),
            integrity_key_id: KeyIdentifier::new(0x00),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x01, 0x23]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4];

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, None, &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            None,
            None,
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(
            *decoded_hdr.counter.as_bytes(),
            [0x00, 0x00, 0x00, 0x01, 0x23]
        );
        assert!(decoded_hdr.security_parameters.counter_available());
        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 19. Buffer too small triggers error
    #[test]
    fn buffer_too_small_error() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x00,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x00),
            integrity_key_id: KeyIdentifier::new(0x00),
            target_app: ToolkitAppReference::new([0x00; 3]),
            counter: OtaCounter::new([0x00; 5]),
            padding_counter: 0,
        };
        let data = [0x00u8; 10];
        let mut buf = [0u8; 4];
        let result = encode_command_packet(&hdr, &data, None, None, &mut buf);
        assert_eq!(result, Err(OtaError::BufferTooSmall));
    }

    // 20. AES-CBC-MAC known test vector
    #[test]
    fn cbc_mac_known_vector() {
        // With IV=0, CBC-MAC of a single block equals AES-ECB of that block.
        // Using NIST SP 800-38A Section F.1.1 values:
        //   Key:       2b7e1516 28aed2a6 abf71588 09cf4f3c
        //   Plaintext: 6bc1bee2 2e409f96 e93d7e11 7393172a
        //   AES-ECB:   3ad77bb4 0d7a3660 a89ecaf3 2466ef97
        // MAC (first 8 bytes of final ciphertext block): 3ad77bb4 0d7a3660
        let key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let plaintext: [u8; 16] = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        let expected_mac: [u8; 8] = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60];

        let mac = aes_cbc_mac(&Secret::new(key), &plaintext);
        assert_eq!(mac, expected_mac);
    }

    // 21. Encode then decode roundtrip with cipher only (no MAC)
    #[test]
    fn decode_command_packet_cipher_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x04,
                response_header: 0x00,
            }, // cipher, no CC
            ciphering_key_id: KeyIdentifier::new(0x02),
            integrity_key_id: KeyIdentifier::new(0x00),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
        let key_cipher = OtaCryptoKey::Aes(Secret::new([0x11u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len =
            encode_command_packet(&hdr, &data, Some(&key_cipher), None, &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            Some(&key_cipher),
            None,
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(
            *decoded_hdr.target_app.as_bytes(),
            *hdr.target_app.as_bytes()
        );
        assert_eq!(*decoded_hdr.counter.as_bytes(), *hdr.counter.as_bytes());
        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 22. Encode then decode roundtrip with cipher + MAC
    #[test]
    fn decode_command_packet_cipher_mac_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x06,
                response_header: 0x00,
            }, // cipher + CC
            ciphering_key_id: KeyIdentifier::new(0x02),
            integrity_key_id: KeyIdentifier::new(0x02),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_cipher = OtaCryptoKey::Aes(Secret::new([0x11u8; 16]));
        let key_mac = OtaCryptoKey::Aes(Secret::new([0x22u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len =
            encode_command_packet(&hdr, &data, Some(&key_cipher), Some(&key_mac), &mut buf)
                .unwrap();

        // Ciphertext region should not contain plaintext counter
        assert_ne!(&buf[10..15], hdr.counter.as_bytes());

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            Some(&key_cipher),
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(
            *decoded_hdr.target_app.as_bytes(),
            *hdr.target_app.as_bytes()
        );
        assert_eq!(*decoded_hdr.counter.as_bytes(), *hdr.counter.as_bytes());
        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 23. Tampered ciphertext causes MAC failure
    #[test]
    fn decode_command_packet_cipher_mac_tampered() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x06,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x02),
            integrity_key_id: KeyIdentifier::new(0x02),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00; 5]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_cipher = OtaCryptoKey::Aes(Secret::new([0x11u8; 16]));
        let key_mac = OtaCryptoKey::Aes(Secret::new([0x22u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len =
            encode_command_packet(&hdr, &data, Some(&key_cipher), Some(&key_mac), &mut buf)
                .unwrap();

        // Tamper with ciphertext
        buf[enc_len - 1] ^= 0xFF;

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let result = decode_command_packet(
            &buf[..enc_len],
            Some(&key_cipher),
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        );
        assert_eq!(result, Err(OtaError::MacVerifyFailed));
    }

    // 24. Ciphered packet without key returns error
    #[test]
    fn decode_command_packet_cipher_no_key() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x04,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x02),
            integrity_key_id: KeyIdentifier::new(0x00),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00; 5]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4];
        let key_cipher = OtaCryptoKey::Aes(Secret::new([0x11u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len =
            encode_command_packet(&hdr, &data, Some(&key_cipher), None, &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let result = decode_command_packet(
            &buf[..enc_len],
            None,
            None,
            &mut decoded_hdr,
            &mut decoded_data,
        );
        assert_eq!(result, Err(OtaError::UnknownAlgorithm));
    }

    // -----------------------------------------------------------------------
    // DES/3DES roundtrip tests
    // -----------------------------------------------------------------------

    // 25. 3DES (2-key) MAC-only roundtrip
    #[test]
    fn des_mac_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x02,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x01), // DES algo
            integrity_key_id: KeyIdentifier::new(0x01), // DES algo
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let key_mac = OtaCryptoKey::TripleDes(Secret::new([0x55u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            None,
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(&decoded_data[..dec_len], &data);
        assert_eq!(
            *decoded_hdr.target_app.as_bytes(),
            *hdr.target_app.as_bytes()
        );
    }

    // 26. 3DES (2-key) MAC tampered -> MacVerifyFailed
    #[test]
    fn des_mac_tampered() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x02,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x01),
            integrity_key_id: KeyIdentifier::new(0x01),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00; 5]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_mac = OtaCryptoKey::TripleDes(Secret::new([0x55u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        // Tamper with DES MAC (4 bytes at offset 16)
        buf[16] ^= 0xFF;

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let result = decode_command_packet(
            &buf[..enc_len],
            None,
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        );
        assert_eq!(result, Err(OtaError::MacVerifyFailed));
    }

    // 27. 3DES (2-key) cipher-only roundtrip
    #[test]
    fn des_cipher_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x04,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x01),
            integrity_key_id: KeyIdentifier::new(0x00),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x02]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let key_cipher = OtaCryptoKey::TripleDes(Secret::new([0x33u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len =
            encode_command_packet(&hdr, &data, Some(&key_cipher), None, &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            Some(&key_cipher),
            None,
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(&decoded_data[..dec_len], &data);
        assert_eq!(*decoded_hdr.counter.as_bytes(), *hdr.counter.as_bytes());
    }

    // 28. 3DES (2-key) cipher + MAC roundtrip
    #[test]
    fn des_cipher_mac_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x06,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x01),
            integrity_key_id: KeyIdentifier::new(0x01),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x03]),
            padding_counter: 0,
        };
        let data = [
            0xA0, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00, 0xC0, 0x00, 0x00, 0x10,
        ];
        let key_cipher = OtaCryptoKey::TripleDes(Secret::new([0x33u8; 16]));
        let key_mac = OtaCryptoKey::TripleDes(Secret::new([0x55u8; 16]));

        let mut buf = [0u8; 256];
        let enc_len =
            encode_command_packet(&hdr, &data, Some(&key_cipher), Some(&key_mac), &mut buf)
                .unwrap();

        // Ciphertext should not contain plaintext counter
        assert_ne!(&buf[10..15], hdr.counter.as_bytes());

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            Some(&key_cipher),
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(&decoded_data[..dec_len], &data);
        assert_eq!(
            *decoded_hdr.target_app.as_bytes(),
            *hdr.target_app.as_bytes()
        );
        assert_eq!(*decoded_hdr.counter.as_bytes(), *hdr.counter.as_bytes());
    }

    // 29. 3DES (3-key) cipher + MAC roundtrip
    #[test]
    fn des3_3key_cipher_mac_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x06,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x01),
            integrity_key_id: KeyIdentifier::new(0x01),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x04]),
            padding_counter: 0,
        };
        let data = [
            0x00, 0xA4, 0x04, 0x04, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02,
        ];
        let key_cipher = OtaCryptoKey::TripleDes3(Secret::new([0x11u8; 24]));
        let key_mac = OtaCryptoKey::TripleDes3(Secret::new([0x22u8; 24]));

        let mut buf = [0u8; 256];
        let enc_len =
            encode_command_packet(&hdr, &data, Some(&key_cipher), Some(&key_mac), &mut buf)
                .unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            Some(&key_cipher),
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 30. Single-DES MAC roundtrip
    #[test]
    fn des_single_key_mac_roundtrip() {
        let hdr = CommandPacketHeader {
            security_parameters: SecurityParameters {
                command_header: 0x02,
                response_header: 0x00,
            },
            ciphering_key_id: KeyIdentifier::new(0x01),
            integrity_key_id: KeyIdentifier::new(0x01),
            target_app: ToolkitAppReference::new([0xB0, 0x00, 0x10]),
            counter: OtaCounter::new([0x00; 5]),
            padding_counter: 0,
        };
        let data = [0xA0, 0xC0, 0x00, 0x00, 0x10];
        let key_mac = OtaCryptoKey::Des(Secret::new([0x77u8; 8]));

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len],
            None,
            Some(&key_mac),
            &mut decoded_hdr,
            &mut decoded_data,
        )
        .unwrap();

        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 31. DES response packet with CC
    #[test]
    fn des_response_packet_roundtrip() {
        let tar = ToolkitAppReference::new([0xB0, 0x00, 0x10]);
        let counter = OtaCounter::new([0x00, 0x00, 0x00, 0x00, 0x01]);
        // command_header 0x02 = CC mode (redundancy_check bits)
        let sp = SecurityParameters {
            command_header: 0x02,
            response_header: 0x01,
        };
        let key_mac = OtaCryptoKey::TripleDes(Secret::new([0x55u8; 16]));

        let mut buf = [0u8; 256];
        let len = encode_response_packet(
            &tar,
            &counter,
            0x00,
            &[],
            &sp,
            None,
            Some(&key_mac),
            &mut buf,
        )
        .unwrap();

        // Total: RPL(2) + RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STATUS(1) + CC(4) = 17
        assert_eq!(len, 17);
        // Verify CC bytes are non-zero (actual MAC was computed)
        assert_ne!(&buf[13..17], &[0u8; 4]);
    }
}

// ---------------------------------------------------------------------------
// Constant-time validation (tacet via ct_test wrapper)
//
//   cargo test -p simrs-ota --features ct-validation --release
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "ct-validation"))]
mod ct_validation {
    use super::*;
    use core::hint::black_box;
    use simrs_consttime_validation::{assert_no_timing_leak, ct_test};

    /// AES-CBC-MAC timing must be independent of key content.
    /// Class 0: fixed key, random 2-block data.
    /// Class 1: random key, random 2-block data.
    #[test]
    fn test_aes_cbc_mac_ct() {
        let outcome = ct_test(
            0x07A_CBC0,
            |rng| {
                let key = [0xAAu8; 16];
                let mut data = [0u8; 32];
                rng.fill_bytes(&mut data);
                (key, data)
            },
            |rng| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                let mut data = [0u8; 32];
                rng.fill_bytes(&mut data);
                (key, data)
            },
            |(key, data)| {
                black_box(aes_cbc_mac(&Secret::new(*key), data));
            },
        );
        assert_no_timing_leak!(outcome);
    }
}
