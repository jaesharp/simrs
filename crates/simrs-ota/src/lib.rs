//! OTA (Over-The-Air) secured packet structure for SIM card remote management.
//!
//! Implements the command and response packet formats defined in:
//! - ETSI TS 102 225 -- Secured packet structure for the UICC
//! - ETSI TS 102 226 -- Remote APDU structure for UICC-based applications
//!
//! # Supported Security Modes
//!
//! - No security (SPI indicates no redundancy check and no ciphering)
//! - Cryptographic Checksum (CC) using AES-128 CBC-MAC
//! - AES-128 CBC encryption for ciphering
//!
//! # Limitations
//!
//! - CBC decryption requires AES decrypt, which `simrs-rijndael` does not
//!   provide (encrypt-only). Decoding of ciphered packets is therefore not
//!   supported. CBC-MAC verification and CBC encryption work fine with
//!   encrypt-only.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::doc_markdown)]        // ETSI/3GPP terms: OTA, SPI, KIc, KID, TAR, etc.
#![allow(clippy::missing_errors_doc)]  // Error types are self-documenting
#![allow(clippy::must_use_candidate)]  // matches workspace lint config
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::match_same_arms)]     // explicit arms improve readability for bitfield decode

#[cfg(feature = "std")]
extern crate std;

use simrs_consttime::ct_eq;
use simrs_rijndael::Rijndael;

/// AES block size in bytes.
const BLOCK_SIZE: usize = 16;

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

/// Redundancy check mode -- TS 102 225 clause 5.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedundancyCheck {
    /// No redundancy check.
    None,
    /// Redundancy Check (CRC).
    Rc,
    /// Cryptographic Checksum (MAC).
    Cc,
    /// Digital Signature.
    Ds,
}

// ---------------------------------------------------------------------------
// Cryptographic algorithm
// ---------------------------------------------------------------------------

/// Cryptographic algorithm identifier -- TS 102 225 clause 5.1.2.
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
// SPI (Security Parameter Indicator)
// ---------------------------------------------------------------------------

/// Security Parameter Indicator (SPI) -- TS 102 225 clause 5.1.1.
///
/// Two bytes controlling the security applied to a command or response packet.
///
/// ```
/// use simrs_ota::{Spi, RedundancyCheck};
///
/// // SPI with CC integrity and ciphering enabled
/// let spi = Spi { spi1: 0x06, spi2: 0x01 };
/// assert_eq!(spi.redundancy_check(), RedundancyCheck::Cc);
/// assert!(spi.ciphering());
/// assert!(spi.por_required());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spi {
    /// First SPI byte (redundancy check, ciphering, counter indicators).
    pub spi1: u8,
    /// Second SPI byte (PoR settings).
    pub spi2: u8,
}

impl Spi {
    /// Redundancy check mode (SPI1 bits 1-0).
    ///
    /// Per TS 102 225 clause 5.1.1:
    /// - `00` = No redundancy check
    /// - `01` = Redundancy Check (CRC)
    /// - `10` = Cryptographic Checksum (CC)
    /// - `11` = Digital Signature (DS)
    pub const fn redundancy_check(&self) -> RedundancyCheck {
        match self.spi1 & 0x03 {
            0x00 => RedundancyCheck::None,
            0x01 => RedundancyCheck::Rc,
            0x02 => RedundancyCheck::Cc,
            0x03 => RedundancyCheck::Ds,
            _ => RedundancyCheck::None, // unreachable but keeps const fn happy
        }
    }

    /// Whether ciphering is indicated (SPI1 bit 2).
    pub const fn ciphering(&self) -> bool {
        self.spi1 & 0x04 != 0
    }

    /// Whether a replay counter is available (SPI1 bit 3).
    pub const fn counter_available(&self) -> bool {
        self.spi1 & 0x08 != 0
    }

    /// Whether a Proof of Receipt (PoR) is required (SPI2 bit 0).
    pub const fn por_required(&self) -> bool {
        self.spi2 & 0x01 != 0
    }

    /// Whether the PoR shall be ciphered (SPI2 bit 2).
    pub const fn por_ciphered(&self) -> bool {
        self.spi2 & 0x04 != 0
    }
}

// ---------------------------------------------------------------------------
// KIc / KID (Key Identifier)
// ---------------------------------------------------------------------------

/// Key Identifier byte (KIc or KID) -- TS 102 225 clause 5.1.2.
///
/// Encodes both the cryptographic algorithm and the key index used for
/// ciphering (KIc) or integrity (KID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyId {
    raw: u8,
}

impl KeyId {
    /// Create a `KeyId` from a raw byte.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Raw byte value.
    pub const fn raw(&self) -> u8 {
        self.raw
    }

    /// Cryptographic algorithm (bits 2-0).
    ///
    /// Per TS 102 225 clause 5.1.2:
    /// - `001` = DES
    /// - `010` = AES (TS 102 225 Annex B)
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
// Command Packet Header
// ---------------------------------------------------------------------------

/// Size of the full header: SPI(2) + KIc(1) + KID(1) + TAR(3) + CNTR(5) + PCNTR(1) = 13.
const HEADER_SIZE: usize = 13;

/// Size of the pre-TAR portion: SPI(2) + KIc(1) + KID(1) = 4.
const PRE_TAR_SIZE: usize = 4;

/// Command packet header -- TS 102 225 clause 5.1.
///
/// Contains the security parameters, key identifiers, target application
/// reference (TAR), replay counter, and padding counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPacketHeader {
    /// Security Parameter Indicator.
    pub spi: Spi,
    /// Key Identifier for ciphering (KIc).
    pub kic: KeyId,
    /// Key Identifier for integrity (KID).
    pub kid: KeyId,
    /// Toolkit Application Reference (3 bytes).
    pub tar: [u8; 3],
    /// Replay detection counter (5 bytes).
    pub counter: [u8; 5],
    /// Padding counter (number of padding bytes appended).
    pub padding_counter: u8,
}

impl CommandPacketHeader {
    /// Create a default (empty) header.
    pub const fn new() -> Self {
        Self {
            spi: Spi { spi1: 0, spi2: 0 },
            kic: KeyId::new(0),
            kid: KeyId::new(0),
            tar: [0; 3],
            counter: [0; 5],
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
// Remote APDU (TS 102 226)
// ---------------------------------------------------------------------------

/// Remote APDU command structure per TS 102 226 clause 5.2.1.
///
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
/// Per TS 102 226, each APDU is encoded as:
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
pub fn encode_remote_apdus(
    apdus: &[RemoteApdu],
    buf: &mut [u8],
) -> Result<usize, OtaError> {
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
// Padding (TS 102 225 clause 5.1.4)
// ---------------------------------------------------------------------------

/// Apply zero-byte padding to make `data` a multiple of `BLOCK_SIZE` (16).
///
/// Copies `data` into `padded` and appends `0x00` bytes as needed.
/// Returns the padded length. If `data` is already block-aligned,
/// no padding is added.
fn apply_padding(data: &[u8], padded: &mut [u8]) -> Result<usize, OtaError> {
    let pad_len = if data.len().is_multiple_of(BLOCK_SIZE) && !data.is_empty() {
        data.len()
    } else {
        (data.len() / BLOCK_SIZE + 1) * BLOCK_SIZE
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
/// (left half of the final CBC block) per TS 102 225 Annex B.
fn aes_cbc_mac(key: &[u8; 16], data: &[u8]) -> [u8; 8] {
    let rij = Rijndael::new(key);
    let mut cv = [0u8; 16]; // IV = 0

    let mut off = 0;
    while off + BLOCK_SIZE <= data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        // XOR with previous ciphertext (or IV)
        for i in 0..16 {
            block[i] ^= cv[i];
        }
        cv = rij.encrypt(&block);
        off += 16;
    }

    let mut mac = [0u8; 8];
    mac.copy_from_slice(&cv[..8]);
    mac
}

// ---------------------------------------------------------------------------
// AES-CBC encrypt
// ---------------------------------------------------------------------------

/// AES-128 CBC encrypt `data` in-place.
///
/// `data` must be a multiple of 16 bytes. IV is all-zeros.
fn aes_cbc_encrypt(key: &[u8; 16], data: &mut [u8]) {
    let rij = Rijndael::new(key);
    let mut cv = [0u8; 16]; // IV = 0

    let mut off = 0;
    while off + BLOCK_SIZE <= data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[off..off + 16]);
        for i in 0..16 {
            block[i] ^= cv[i];
        }
        cv = rij.encrypt(&block);
        data[off..off + 16].copy_from_slice(&cv);
        off += 16;
    }
}

// ---------------------------------------------------------------------------
// Command packet encoding (TS 102 225 clause 5.1)
// ---------------------------------------------------------------------------

/// MAC size in bytes (8-byte CC per TS 102 225 Annex B for AES).
const CC_SIZE: usize = 8;

/// Encode a command packet per TS 102 225 clause 5.1.
///
/// The packet layout in `buf` is:
/// ```text
/// CPL(2) | CHL(1) | SPI(2) | KIc(1) | KID(1) | TAR(3) | CNTR(5) | PCNTR(1) | CC(8)? | data...
/// ```
///
/// - `hdr`: Command packet header (SPI, keys, TAR, counter).
/// - `data`: Remote APDU payload (TS 102 226 encoded).
/// - `key_cipher`: AES-128 key for ciphering (if SPI indicates ciphering).
/// - `key_mac`: AES-128 key for CC (if SPI indicates CC).
/// - `buf`: Output buffer, must be large enough to hold the complete packet.
///
/// Returns the total number of bytes written to `buf`.
///
/// # Example: Encode and decode a command packet without security
///
/// ```
/// use simrs_ota::{CommandPacketHeader, Spi, KeyId, encode_command_packet, decode_command_packet};
///
/// let hdr = CommandPacketHeader {
///     spi: Spi { spi1: 0x00, spi2: 0x00 },
///     kic: KeyId::new(0x00),
///     kid: KeyId::new(0x00),
///     tar: [0xB0, 0x00, 0x10],
///     counter: [0x00, 0x00, 0x00, 0x00, 0x01],
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
/// assert_eq!(dec_hdr.tar, [0xB0, 0x00, 0x10]);
/// ```
pub fn encode_command_packet(
    hdr: &CommandPacketHeader,
    data: &[u8],
    key_cipher: Option<&[u8; 16]>,
    key_mac: Option<&[u8; 16]>,
    buf: &mut [u8],
) -> Result<usize, OtaError> {
    let has_cc = matches!(hdr.spi.redundancy_check(), RedundancyCheck::Cc);
    let has_cipher = hdr.spi.ciphering();

    let rc_size = if has_cc { CC_SIZE } else { 0 };

    // The secured data region (after TAR) that gets ciphered:
    // CNTR(5) + PCNTR(1) + CC? + data
    let secured_data_len = 5 + 1 + rc_size + data.len();

    // If ciphering, pad the secured data to a block boundary.
    let (padded_secured_len, padding_count) = if has_cipher {
        let padded = secured_data_len.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
        (padded, padded - secured_data_len)
    } else {
        (secured_data_len, 0_usize)
    };

    // CHL = header bytes from SPI through CC (inclusive):
    // SPI(2) + KIc(1) + KID(1) + TAR(3) + CNTR(5) + PCNTR(1) + CC = 13 + rc_size
    #[allow(clippy::cast_possible_truncation)]
    let chl: u8 = (HEADER_SIZE + rc_size) as u8;

    // Packet layout:
    //   Offset 0-1:   CPL (2 bytes, big-endian)
    //   Offset 2:     CHL (1 byte)
    //   Offset 3-4:   SPI (2 bytes)
    //   Offset 5:     KIc
    //   Offset 6:     KID
    //   Offset 7-9:   TAR (3 bytes)
    //   Offset 10-14: CNTR (5 bytes)
    //   Offset 15:    PCNTR
    //   Offset 16..:  CC (8 bytes if present)
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
    buf[3] = hdr.spi.spi1;
    buf[4] = hdr.spi.spi2;
    buf[5] = hdr.kic.raw();
    buf[6] = hdr.kid.raw();
    buf[7] = hdr.tar[0];
    buf[8] = hdr.tar[1];
    buf[9] = hdr.tar[2];
    buf[10] = hdr.counter[0];
    buf[11] = hdr.counter[1];
    buf[12] = hdr.counter[2];
    buf[13] = hdr.counter[3];
    buf[14] = hdr.counter[4];

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
            for b in &mut buf[cc_offset..cc_offset + CC_SIZE] {
                *b = 0x00;
            }
            // MAC input: header fields from SPI through end of data+padding
            let mac_region = &buf[3..total];
            let mut mac_buf = [0u8; 1024];
            let padded_len = apply_padding(mac_region, &mut mac_buf)?;
            let mac = aes_cbc_mac(km, &mac_buf[..padded_len]);
            buf[cc_offset..cc_offset + CC_SIZE].copy_from_slice(&mac);
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    // Encrypt: the ciphered region is CNTR through end of data+padding
    if has_cipher {
        if let Some(kc) = key_cipher {
            let cipher_region = &mut buf[10..total];
            debug_assert!(cipher_region.len() == padded_secured_len);
            aes_cbc_encrypt(kc, cipher_region);
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    Ok(total)
}

// ---------------------------------------------------------------------------
// Command packet decoding (TS 102 225 clause 5.1)
// ---------------------------------------------------------------------------

/// Decode and verify a command packet per TS 102 225 clause 5.1.
///
/// - `packet`: The complete received packet bytes.
/// - `key_cipher`: AES-128 key for deciphering (if ciphered). Currently not
///   supported since `simrs-rijndael` is encrypt-only. Pass `None` for
///   non-ciphered packets.
/// - `key_mac`: AES-128 key for CC verification (if CC present).
/// - `hdr_out`: Decoded header is written here.
/// - `data_out`: Decoded command data is written here.
///
/// Returns the number of data bytes written to `data_out`.
///
/// # Limitations
///
/// Decryption of ciphered packets is not supported (requires AES decrypt).
/// If the packet has ciphering enabled, returns `OtaError::UnknownAlgorithm`.
pub fn decode_command_packet(
    packet: &[u8],
    key_cipher: Option<&[u8; 16]>,
    key_mac: Option<&[u8; 16]>,
    hdr_out: &mut CommandPacketHeader,
    data_out: &mut [u8],
) -> Result<usize, OtaError> {
    // Minimum: CPL(2) + CHL(1) + SPI(2) + KIc(1) + KID(1) + TAR(3) + CNTR(5) + PCNTR(1) = 16
    if packet.len() < 16 {
        return Err(OtaError::InvalidLength);
    }

    let cpl = u16::from_be_bytes([packet[0], packet[1]]) as usize;
    if cpl + 2 > packet.len() {
        return Err(OtaError::InvalidLength);
    }

    // CHL at packet[2] is not needed for decoding (we use fixed offsets)
    let total = cpl + 2;

    // Decode SPI, KIc, KID, TAR
    hdr_out.spi = Spi { spi1: packet[3], spi2: packet[4] };
    hdr_out.kic = KeyId::new(packet[5]);
    hdr_out.kid = KeyId::new(packet[6]);
    hdr_out.tar = [packet[7], packet[8], packet[9]];

    let has_cc = matches!(hdr_out.spi.redundancy_check(), RedundancyCheck::Cc);
    let has_cipher = hdr_out.spi.ciphering();
    let rc_size = if has_cc { CC_SIZE } else { 0 };

    // CBC decrypt is not available (simrs-rijndael is encrypt-only)
    if has_cipher {
        let _ = key_cipher;
        return Err(OtaError::UnknownAlgorithm);
    }

    // Non-ciphered: all fields are in the clear
    hdr_out.counter = [packet[10], packet[11], packet[12], packet[13], packet[14]];
    hdr_out.padding_counter = packet[15];

    let cc_offset = 16;
    let data_offset = cc_offset + rc_size;

    if total < data_offset {
        return Err(OtaError::InvalidLength);
    }

    // Verify MAC if CC mode
    if has_cc {
        if let Some(km) = key_mac {
            if total < cc_offset + CC_SIZE {
                return Err(OtaError::InvalidLength);
            }
            // Extract the received MAC
            let mut received_mac = [0u8; CC_SIZE];
            received_mac.copy_from_slice(&packet[cc_offset..cc_offset + CC_SIZE]);

            // Re-compute MAC with CC field zeroed
            let region_len = total - 3; // from SPI to end
            let mut recompute_buf = [0u8; 1024];
            if region_len > recompute_buf.len() {
                return Err(OtaError::BufferTooSmall);
            }
            recompute_buf[..region_len].copy_from_slice(&packet[3..total]);
            // Zero the CC field within our copy (cc_offset - 3 = 13)
            let cc_in_copy = cc_offset - 3;
            for b in &mut recompute_buf[cc_in_copy..cc_in_copy + CC_SIZE] {
                *b = 0x00;
            }
            let mut mac_padded = [0u8; 1024];
            let padded_len = apply_padding(&recompute_buf[..region_len], &mut mac_padded)?;
            let computed_mac = aes_cbc_mac(km, &mac_padded[..padded_len]);

            if !ct_eq(&computed_mac, &received_mac) {
                return Err(OtaError::MacVerifyFailed);
            }
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    // Extract data (subtract padding bytes)
    let raw_data_len = total - data_offset;
    let padding = hdr_out.padding_counter as usize;
    if padding > raw_data_len {
        return Err(OtaError::InvalidLength);
    }
    let data_len = raw_data_len - padding;
    if data_out.len() < data_len {
        return Err(OtaError::BufferTooSmall);
    }
    data_out[..data_len].copy_from_slice(&packet[data_offset..data_offset + data_len]);

    Ok(data_len)
}

// ---------------------------------------------------------------------------
// Response packet encoding (TS 102 225 clause 5.2)
// ---------------------------------------------------------------------------

/// Encode a response packet per TS 102 225 clause 5.2.
///
/// Layout:
/// ```text
/// RPL(2) | RHL(1) | TAR(3) | CNTR(5) | PCNTR(1) | STATUS(1) | CC(8)? | data...
/// ```
///
/// - `tar`: Toolkit Application Reference (echoed from command).
/// - `counter`: Replay counter (echoed or incremented).
/// - `status_code`: Response status code per TS 102 225 clause 5.2.1.
/// - `data`: Response data.
/// - `spi`: SPI from the original command (determines security applied to response).
/// - `key_cipher`: AES-128 key for ciphering the response.
/// - `key_mac`: AES-128 key for CC on the response.
/// - `buf`: Output buffer.
///
/// Returns the total number of bytes written.
///
/// ```
/// use simrs_ota::{Spi, encode_response_packet};
///
/// let tar = [0xB0, 0x00, 0x10];
/// let counter = [0x00, 0x00, 0x00, 0x00, 0x01];
/// let spi = Spi { spi1: 0x00, spi2: 0x00 }; // no security
///
/// let mut buf = [0u8; 256];
/// let len = encode_response_packet(
///     &tar, &counter, 0x00, &[], &spi, None, None, &mut buf,
/// ).unwrap();
///
/// // RPL(2) + RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STATUS(1) = 13
/// assert_eq!(len, 13);
/// assert_eq!(&buf[3..6], &tar);
/// assert_eq!(buf[12], 0x00); // status code
/// ```
#[allow(clippy::too_many_arguments)]
pub fn encode_response_packet(
    tar: &[u8; 3],
    counter: &[u8; 5],
    status_code: u8,
    data: &[u8],
    spi: &Spi,
    key_cipher: Option<&[u8; 16]>,
    key_mac: Option<&[u8; 16]>,
    buf: &mut [u8],
) -> Result<usize, OtaError> {
    let has_cc = matches!(spi.redundancy_check(), RedundancyCheck::Cc);
    let has_cipher = spi.por_ciphered();
    let rc_size = if has_cc { CC_SIZE } else { 0 };

    // Secured data region (from CNTR): CNTR(5) + PCNTR(1) + STATUS(1) + CC? + data
    let secured_data_len = 5 + 1 + 1 + rc_size + data.len();
    let (padded_secured_len, padding_count) = if has_cipher {
        let padded = secured_data_len.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
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
    buf[3] = tar[0];
    buf[4] = tar[1];
    buf[5] = tar[2];
    buf[6] = counter[0];
    buf[7] = counter[1];
    buf[8] = counter[2];
    buf[9] = counter[3];
    buf[10] = counter[4];

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
            for b in &mut buf[cc_offset..cc_offset + CC_SIZE] {
                *b = 0x00;
            }
            // MAC over: TAR + CNTR + PCNTR + STATUS + CC(zeros) + data + padding
            let mac_region = &buf[3..total];
            let mut mac_buf = [0u8; 1024];
            let padded_len = apply_padding(mac_region, &mut mac_buf)?;
            let mac = aes_cbc_mac(km, &mac_buf[..padded_len]);
            buf[cc_offset..cc_offset + CC_SIZE].copy_from_slice(&mac);
        } else {
            return Err(OtaError::UnknownAlgorithm);
        }
    }

    // Encrypt if PoR ciphered
    if has_cipher {
        if let Some(kc) = key_cipher {
            let cipher_region = &mut buf[6..total];
            debug_assert!(cipher_region.len() == padded_secured_len);
            aes_cbc_encrypt(kc, cipher_region);
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

    // 1. SPI redundancy check = None
    #[test]
    fn spi_redundancy_check_none() {
        let spi = Spi { spi1: 0x00, spi2: 0x00 };
        assert_eq!(spi.redundancy_check(), RedundancyCheck::None);
    }

    // 2. SPI redundancy check = CC
    #[test]
    fn spi_redundancy_check_cc() {
        let spi = Spi { spi1: 0x02, spi2: 0x00 };
        assert_eq!(spi.redundancy_check(), RedundancyCheck::Cc);
    }

    // 3. SPI ciphering flag
    #[test]
    fn spi_ciphering_enabled() {
        let spi_on = Spi { spi1: 0x04, spi2: 0x00 };
        assert!(spi_on.ciphering());
        let spi_off = Spi { spi1: 0x00, spi2: 0x00 };
        assert!(!spi_off.ciphering());
    }

    // 4. SPI counter available flag
    #[test]
    fn spi_counter_available() {
        let spi_on = Spi { spi1: 0x08, spi2: 0x00 };
        assert!(spi_on.counter_available());
        let spi_off = Spi { spi1: 0x00, spi2: 0x00 };
        assert!(!spi_off.counter_available());
    }

    // 5. KID/KIc AES algorithm
    #[test]
    fn key_id_aes_algorithm() {
        let kid = KeyId::new(0x12); // bits 2-0 = 0x02 = AES, key_index = 1
        assert_eq!(kid.algorithm(), CryptoAlgo::Aes);
    }

    // 6. KID/KIc DES algorithm
    #[test]
    fn key_id_des_algorithm() {
        let kid = KeyId::new(0x01); // bits 2-0 = 0x01 = DES
        assert_eq!(kid.algorithm(), CryptoAlgo::Des);
    }

    // 7. Key index extraction
    #[test]
    fn key_id_key_index_extraction() {
        let kid = KeyId::new(0x32); // key_index = 3 (bits 7-4), algo = AES (bits 2-0 = 2)
        assert_eq!(kid.key_index(), 3);
        assert_eq!(kid.algorithm(), CryptoAlgo::Aes);
    }

    // 8. Padding: already aligned (no pad added)
    #[test]
    fn padding_exact_block_no_pad() {
        let data = [0xAAu8; 16];
        let mut padded = [0u8; 32];
        let len = apply_padding(&data, &mut padded).unwrap();
        assert_eq!(len, 16);
        assert_eq!(&padded[..16], &data);
    }

    // 9. Padding: adds zeros
    #[test]
    fn padding_adds_zeros() {
        let data = [0xBBu8; 10];
        let mut padded = [0xFFu8; 32];
        let len = apply_padding(&data, &mut padded).unwrap();
        assert_eq!(len, 16);
        assert_eq!(&padded[..10], &data);
        assert_eq!(&padded[10..16], &[0x00; 6]);
    }

    // 10. Encode command packet without any security
    #[test]
    fn encode_command_packet_no_security() {
        let hdr = CommandPacketHeader {
            spi: Spi { spi1: 0x00, spi2: 0x00 },
            kic: KeyId::new(0x00),
            kid: KeyId::new(0x00),
            tar: [0xB0, 0x00, 0x10],
            counter: [0x00; 5],
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];

        let mut buf = [0u8; 256];
        let len = encode_command_packet(&hdr, &data, None, None, &mut buf).unwrap();

        // CPL check
        let cpl = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(cpl + 2, len);

        // TAR at offset 7-9
        assert_eq!(&buf[7..10], &[0xB0, 0x00, 0x10]);

        // Data at offset 16 (no CC), 7 bytes
        assert_eq!(&buf[16..16 + 7], &data);
    }

    // 11. Encode command packet with CC (MAC)
    #[test]
    fn encode_command_packet_with_mac() {
        let hdr = CommandPacketHeader {
            spi: Spi { spi1: 0x02, spi2: 0x00 }, // CC mode
            kic: KeyId::new(0x02),
            kid: KeyId::new(0x02),
            tar: [0xB0, 0x00, 0x10],
            counter: [0x00, 0x00, 0x00, 0x00, 0x01],
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_mac = [0x40u8; 16];

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
            spi: Spi { spi1: 0x00, spi2: 0x00 },
            kic: KeyId::new(0x00),
            kid: KeyId::new(0x00),
            tar: [0xB0, 0x00, 0x10],
            counter: [0x00, 0x00, 0x00, 0x00, 0x05],
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, None, &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len], None, None, &mut decoded_hdr, &mut decoded_data,
        ).unwrap();

        assert_eq!(decoded_hdr.tar, hdr.tar);
        assert_eq!(decoded_hdr.counter, hdr.counter);
        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 13. Encode then decode with MAC verification
    #[test]
    fn decode_command_packet_mac_verify() {
        let hdr = CommandPacketHeader {
            spi: Spi { spi1: 0x02, spi2: 0x00 },
            kic: KeyId::new(0x02),
            kid: KeyId::new(0x02),
            tar: [0xB0, 0x00, 0x10],
            counter: [0x00, 0x00, 0x00, 0x00, 0x01],
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_mac = [0x40u8; 16];

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len], None, Some(&key_mac), &mut decoded_hdr, &mut decoded_data,
        ).unwrap();

        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 14. Tampered data causes MAC failure
    #[test]
    fn decode_command_packet_bad_mac_fails() {
        let hdr = CommandPacketHeader {
            spi: Spi { spi1: 0x02, spi2: 0x00 },
            kic: KeyId::new(0x02),
            kid: KeyId::new(0x02),
            tar: [0xB0, 0x00, 0x10],
            counter: [0x00; 5],
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4, 0x00, 0x00];
        let key_mac = [0x40u8; 16];

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, Some(&key_mac), &mut buf).unwrap();

        // Tamper with the last data byte
        buf[enc_len - 1] ^= 0xFF;

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let result = decode_command_packet(
            &buf[..enc_len], None, Some(&key_mac), &mut decoded_hdr, &mut decoded_data,
        );
        assert_eq!(result, Err(OtaError::MacVerifyFailed));
    }

    // 15. Response packet encoding
    #[test]
    fn encode_response_packet_basic() {
        let tar = [0xB0, 0x00, 0x10];
        let counter = [0x00, 0x00, 0x00, 0x00, 0x01];
        let spi = Spi { spi1: 0x00, spi2: 0x00 };

        let mut buf = [0u8; 256];
        let len = encode_response_packet(
            &tar, &counter, 0x00, &[], &spi, None, None, &mut buf,
        ).unwrap();

        // RPL(2) + RHL(1) + TAR(3) + CNTR(5) + PCNTR(1) + STATUS(1) = 13
        assert_eq!(len, 13);
        assert_eq!(&buf[3..6], &tar);
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
            spi: Spi { spi1: 0x08, spi2: 0x00 }, // counter available
            kic: KeyId::new(0x00),
            kid: KeyId::new(0x00),
            tar: [0xB0, 0x00, 0x10],
            counter: [0x00, 0x00, 0x00, 0x01, 0x23],
            padding_counter: 0,
        };
        let data = [0xA0, 0xA4];

        let mut buf = [0u8; 256];
        let enc_len = encode_command_packet(&hdr, &data, None, None, &mut buf).unwrap();

        let mut decoded_hdr = CommandPacketHeader::new();
        let mut decoded_data = [0u8; 256];
        let dec_len = decode_command_packet(
            &buf[..enc_len], None, None, &mut decoded_hdr, &mut decoded_data,
        ).unwrap();

        assert_eq!(decoded_hdr.counter, [0x00, 0x00, 0x00, 0x01, 0x23]);
        assert!(decoded_hdr.spi.counter_available());
        assert_eq!(&decoded_data[..dec_len], &data);
    }

    // 19. Buffer too small triggers error
    #[test]
    fn buffer_too_small_error() {
        let hdr = CommandPacketHeader {
            spi: Spi { spi1: 0x00, spi2: 0x00 },
            kic: KeyId::new(0x00),
            kid: KeyId::new(0x00),
            tar: [0x00; 3],
            counter: [0x00; 5],
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
        // Using NIST SP 800-38A F.1.1 values:
        //   Key:       2b7e1516 28aed2a6 abf71588 09cf4f3c
        //   Plaintext: 6bc1bee2 2e409f96 e93d7e11 7393172a
        //   AES-ECB:   3ad77bb4 0d7a3660 a89ecaf3 2466ef97
        // MAC (first 8 bytes of final ciphertext block): 3ad77bb4 0d7a3660
        let key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        ];
        let plaintext: [u8; 16] = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        ];
        let expected_mac: [u8; 8] = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60,
        ];

        let mac = aes_cbc_mac(&key, &plaintext);
        assert_eq!(mac, expected_mac);
    }
}
