//! Binary patcher for the Oracle jcsl simulator.
//!
//! Replaces the Java `Configurator.jar` tool with a pure-Rust
//! implementation that can inject SCP keys and a Global PIN into a
//! **copy** of the `jcsl` ELF binary.
//!
//! # Binary layout (reverse-engineered from `Configurator.class`)
//!
//! The unconfigured binary contains two sentinel patterns:
//!
//! ## SCP keyset region
//!
//! ```text
//! Offset  Size       Field
//! ------  ---------  -----
//!   +0    8          SCP_KEYSET_MAGIC
//!   +8    1          Key Version Number (KVN)
//!   +9    1          total key material length (3 * key_len)
//!  +10    key_len    ENC key
//!  +10+k  key_len    MAC key
//!  +10+2k key_len    DEK key
//! ```
//!
//! ## Global PIN region
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//!   +0    8     GLOBAL_PIN_MAGIC
//!   +8    16    PIN value (zero-padded to 16 bytes)
//!  +24    1     PIN length (actual number of PIN bytes)
//!  +25    1     Retry count
//! ```

use std::io;

/// 8-byte sentinel that marks the SCP keyset injection site.
const SCP_KEYSET_MAGIC: [u8; 8] = [0x3C, 0x5E, 0x5F, 0x3C, 0x41, 0x49, 0x3C, 0x3C];

/// 8-byte sentinel that marks the Global PIN injection site.
const GLOBAL_PIN_MAGIC: [u8; 8] = [0x3C, 0x5C, 0x58, 0x3C, 0x41, 0x51, 0x5B, 0x3C];

/// Maximum PIN length (bytes).  Fixed slot size in the binary.
const PIN_SLOT_SIZE: usize = 16;

/// SCP03 keyset (ENC + MAC + DEK) with a Key Version Number.
#[derive(Clone)]
pub struct ScpKeyset {
    /// Key Version Number (1..=0x6F per GP spec).
    pub kvn: u8,
    /// ENC key -- 16, 24, or 32 bytes.
    pub enc: Vec<u8>,
    /// MAC key -- same length as ENC.
    pub mac: Vec<u8>,
    /// DEK key -- same length as ENC.
    pub dek: Vec<u8>,
}

/// Global PIN value with retry counter.
#[derive(Clone)]
pub struct GlobalPin {
    /// PIN bytes (3..=16 bytes).
    pub pin: Vec<u8>,
    /// Maximum verification attempts before lockout.
    pub max_retries: u8,
}

/// Errors from the configurator.
#[derive(Debug)]
pub enum ConfigError {
    /// The SCP keyset magic was not found in the binary.
    ScpMagicNotFound,
    /// The Global PIN magic was not found in the binary.
    PinMagicNotFound,
    /// Key length is not 16, 24, or 32.
    InvalidKeyLength(usize),
    /// ENC, MAC, and DEK keys are not all the same length.
    KeyLengthMismatch,
    /// KVN is out of range (must be 1..=0x6F).
    InvalidKvn(u8),
    /// PIN length is out of range (must be 3..=16).
    InvalidPinLength(usize),
    /// Injection site already contains non-zero data and `force` is false.
    NonZeroData {
        /// Byte offset in the binary where non-zero data was found.
        offset: usize,
    },
    /// I/O error reading or writing the binary.
    Io(io::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScpMagicNotFound => f.write_str("SCP keyset magic not found in binary"),
            Self::PinMagicNotFound => f.write_str("Global PIN magic not found in binary"),
            Self::InvalidKeyLength(n) => {
                write!(f, "key length {n} invalid (must be 16, 24, or 32)")
            }
            Self::KeyLengthMismatch => {
                f.write_str("ENC, MAC, DEK keys must all be the same length")
            }
            Self::InvalidKvn(v) => write!(f, "KVN 0x{v:02x} out of range (must be 0x01..0x6F)"),
            Self::InvalidPinLength(n) => write!(f, "PIN length {n} invalid (must be 3..=16)"),
            Self::NonZeroData { offset } => {
                write!(
                    f,
                    "non-zero data at offset 0x{offset:x} (use force to overwrite)"
                )
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Write `data` into `binary` at `offset`, checking for non-zero bytes
/// unless `force` is set.
fn inject(binary: &mut [u8], offset: usize, data: &[u8], force: bool) -> Result<(), ConfigError> {
    let end = offset + data.len();
    if end > binary.len() {
        return Err(ConfigError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "injection site extends past end of binary",
        )));
    }
    if !force {
        for (i, &b) in binary[offset..end].iter().enumerate() {
            if b != 0 {
                return Err(ConfigError::NonZeroData { offset: offset + i });
            }
        }
    }
    binary[offset..end].copy_from_slice(data);
    Ok(())
}

/// Inject an SCP keyset into the binary.
///
/// The binary must contain [`SCP_KEYSET_MAGIC`].  Keys are written
/// immediately after the magic in the order: KVN, total-length,
/// ENC, MAC, DEK.
///
/// # Errors
///
/// Returns a [`ConfigError`] if the magic is not found, key lengths
/// are invalid, or the injection site contains non-zero data without
/// `force`.
pub fn inject_scp_keyset(
    binary: &mut [u8],
    keyset: &ScpKeyset,
    force: bool,
) -> Result<(), ConfigError> {
    // Validate
    let key_len = keyset.enc.len();
    if !matches!(key_len, 16 | 24 | 32) {
        return Err(ConfigError::InvalidKeyLength(key_len));
    }
    if keyset.mac.len() != key_len || keyset.dek.len() != key_len {
        return Err(ConfigError::KeyLengthMismatch);
    }
    if keyset.kvn < 1 || keyset.kvn > 0x6F {
        return Err(ConfigError::InvalidKvn(keyset.kvn));
    }

    // Locate magic
    let magic_offset =
        find_pattern(binary, &SCP_KEYSET_MAGIC).ok_or(ConfigError::ScpMagicNotFound)?;

    let mut pos = magic_offset + SCP_KEYSET_MAGIC.len();

    // KVN (1 byte)
    inject(binary, pos, &[keyset.kvn], force)?;
    pos += 1;

    // Total key material length (1 byte)
    #[allow(clippy::cast_possible_truncation)]
    let total_len = (3 * key_len) as u8;
    inject(binary, pos, &[total_len], force)?;
    pos += 1;

    // ENC key
    inject(binary, pos, &keyset.enc, force)?;
    pos += key_len;

    // MAC key
    inject(binary, pos, &keyset.mac, force)?;
    pos += key_len;

    // DEK key
    inject(binary, pos, &keyset.dek, force)?;

    Ok(())
}

/// Inject a Global PIN into the binary.
///
/// The binary must contain [`GLOBAL_PIN_MAGIC`].  The PIN is written
/// into a fixed 16-byte slot, followed by a 1-byte length and 1-byte
/// retry counter.
///
/// # Errors
///
/// Returns a [`ConfigError`] if the magic is not found, PIN length is
/// out of range (3..=16), or the injection site contains non-zero data
/// without `force`.
pub fn inject_global_pin(
    binary: &mut [u8],
    pin: &GlobalPin,
    force: bool,
) -> Result<(), ConfigError> {
    let pin_len = pin.pin.len();
    if !(3..=PIN_SLOT_SIZE).contains(&pin_len) {
        return Err(ConfigError::InvalidPinLength(pin_len));
    }

    let magic_offset =
        find_pattern(binary, &GLOBAL_PIN_MAGIC).ok_or(ConfigError::PinMagicNotFound)?;

    let mut pos = magic_offset + GLOBAL_PIN_MAGIC.len();

    // PIN value (left-justified in 16-byte slot)
    inject(binary, pos, &pin.pin, force)?;
    pos += PIN_SLOT_SIZE;

    // PIN length (1 byte)
    #[allow(clippy::cast_possible_truncation)]
    let len_byte = pin_len as u8;
    inject(binary, pos, &[len_byte], force)?;
    pos += 1;

    // Retry count (1 byte)
    inject(binary, pos, &[pin.max_retries], force)?;

    Ok(())
}

/// Read the binary file, apply configuration, write to a new path.
///
/// The source binary is not modified.
///
/// # Errors
///
/// Returns a [`ConfigError`] if the binary cannot be read, injection
/// fails, or the configured binary cannot be written.
pub fn configure_binary(
    src: &std::path::Path,
    dst: &std::path::Path,
    keyset: Option<&ScpKeyset>,
    pin: Option<&GlobalPin>,
    force: bool,
) -> Result<(), ConfigError> {
    let mut data = std::fs::read(src)?;

    if let Some(ks) = keyset {
        inject_scp_keyset(&mut data, ks, force)?;
    }
    if let Some(p) = pin {
        inject_global_pin(&mut data, p, force)?;
    }

    std::fs::write(dst, &data)?;

    // Preserve executable permission
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(src)?.permissions();
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(perms.mode()))?;
    }

    Ok(())
}

/// Read the binary file, apply configuration, return as a sealed memfd.
///
/// Creates an anonymous in-memory file via `memfd_create`, writes the
/// patched binary into it, and seals it against modification. The returned
/// [`Memfd`] must be kept alive for the lifetime of any process spawned
/// from it (the fd backs the anonymous inode).
///
/// This is the preferred alternative to [`configure_binary`] for test
/// harnesses: no temp files are created, eliminating ETXTBSY races and
/// cleanup burden.
///
/// # Errors
///
/// Returns a [`ConfigError`] if the binary cannot be read or injection
/// fails, or if `memfd_create` / sealing fails (wrapped as I/O error).
pub fn configure_to_memfd(
    src: &std::path::Path,
    keyset: Option<&ScpKeyset>,
    pin: Option<&GlobalPin>,
) -> Result<memfd::Memfd, ConfigError> {
    use std::io::Write;

    let mut data = std::fs::read(src)?;

    if let Some(ks) = keyset {
        inject_scp_keyset(&mut data, ks, false)?;
    }
    if let Some(p) = pin {
        inject_global_pin(&mut data, p, false)?;
    }

    let mfd = memfd::MemfdOptions::new()
        .allow_sealing(true)
        .close_on_exec(false)
        .create("jcsl")
        .map_err(|e| ConfigError::Io(io::Error::other(format!("memfd_create: {e}"))))?;

    mfd.as_file().write_all(&data)?;

    mfd.add_seals(&[
        memfd::FileSeal::SealWrite,
        memfd::FileSeal::SealShrink,
        memfd::FileSeal::SealGrow,
    ])
    .map_err(|e| ConfigError::Io(io::Error::other(format!("memfd seal: {e}"))))?;

    Ok(mfd)
}

/// Check whether the binary has been configured (non-zero data after magic).
pub fn is_configured(binary: &[u8]) -> (bool, bool) {
    let scp = find_pattern(binary, &SCP_KEYSET_MAGIC)
        .is_some_and(|idx| binary.get(idx + 8).copied().unwrap_or(0) != 0);
    let pin = find_pattern(binary, &GLOBAL_PIN_MAGIC)
        .is_some_and(|idx| binary.get(idx + 8).copied().unwrap_or(0) != 0);
    (scp, pin)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal fake binary containing both magic patterns.
    fn fake_binary() -> Vec<u8> {
        let mut bin = vec![0u8; 256];
        // Place PIN magic at offset 32
        bin[32..40].copy_from_slice(&GLOBAL_PIN_MAGIC);
        // Place SCP magic at offset 80
        bin[80..88].copy_from_slice(&SCP_KEYSET_MAGIC);
        bin
    }

    #[test]
    fn find_scp_magic() {
        let bin = fake_binary();
        assert_eq!(find_pattern(&bin, &SCP_KEYSET_MAGIC), Some(80));
    }

    #[test]
    fn find_pin_magic() {
        let bin = fake_binary();
        assert_eq!(find_pattern(&bin, &GLOBAL_PIN_MAGIC), Some(32));
    }

    #[test]
    fn inject_scp_keyset_16_byte() {
        let mut bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 0x01,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        inject_scp_keyset(&mut bin, &ks, false).unwrap();

        // After magic (offset 88): KVN=0x01, total=48
        assert_eq!(bin[88], 0x01);
        assert_eq!(bin[89], 48);
        // ENC at 90..106
        assert!(bin[90..106].iter().all(|&b| b == 0x40));
        // MAC at 106..122
        assert!(bin[106..122].iter().all(|&b| b == 0x41));
        // DEK at 122..138
        assert!(bin[122..138].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn inject_scp_keyset_24_byte() {
        let mut bin = vec![0u8; 512];
        bin[80..88].copy_from_slice(&SCP_KEYSET_MAGIC);
        let ks = ScpKeyset {
            kvn: 0x30,
            enc: vec![0xAA; 24],
            mac: vec![0xBB; 24],
            dek: vec![0xCC; 24],
        };
        inject_scp_keyset(&mut bin, &ks, false).unwrap();
        assert_eq!(bin[88], 0x30);
        assert_eq!(bin[89], 72); // 3*24
        assert!(bin[90..114].iter().all(|&b| b == 0xAA));
        assert!(bin[114..138].iter().all(|&b| b == 0xBB));
        assert!(bin[138..162].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn inject_scp_keyset_32_byte() {
        let mut bin = vec![0u8; 512];
        bin[80..88].copy_from_slice(&SCP_KEYSET_MAGIC);
        let ks = ScpKeyset {
            kvn: 0x6F,
            enc: vec![0x11; 32],
            mac: vec![0x22; 32],
            dek: vec![0x33; 32],
        };
        inject_scp_keyset(&mut bin, &ks, false).unwrap();
        assert_eq!(bin[88], 0x6F);
        assert_eq!(bin[89], 96); // 3*32
    }

    #[test]
    fn reject_invalid_key_length() {
        let mut bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 0x01,
            enc: vec![0x40; 15],
            mac: vec![0x41; 15],
            dek: vec![0x42; 15],
        };
        assert!(matches!(
            inject_scp_keyset(&mut bin, &ks, false),
            Err(ConfigError::InvalidKeyLength(15))
        ));
    }

    #[test]
    fn reject_mismatched_key_lengths() {
        let mut bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 0x01,
            enc: vec![0x40; 16],
            mac: vec![0x41; 24],
            dek: vec![0x42; 16],
        };
        assert!(matches!(
            inject_scp_keyset(&mut bin, &ks, false),
            Err(ConfigError::KeyLengthMismatch)
        ));
    }

    #[test]
    fn reject_kvn_zero() {
        let mut bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 0x00,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        assert!(matches!(
            inject_scp_keyset(&mut bin, &ks, false),
            Err(ConfigError::InvalidKvn(0))
        ));
    }

    #[test]
    fn reject_kvn_too_high() {
        let mut bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 0x70,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        assert!(matches!(
            inject_scp_keyset(&mut bin, &ks, false),
            Err(ConfigError::InvalidKvn(0x70))
        ));
    }

    #[test]
    fn reject_overwrite_without_force() {
        let mut bin = fake_binary();
        bin[88] = 0xFF; // non-zero at KVN slot
        let ks = ScpKeyset {
            kvn: 0x01,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        assert!(matches!(
            inject_scp_keyset(&mut bin, &ks, false),
            Err(ConfigError::NonZeroData { offset: 88 })
        ));
    }

    #[test]
    fn force_overwrite_succeeds() {
        let mut bin = fake_binary();
        bin[88] = 0xFF;
        let ks = ScpKeyset {
            kvn: 0x01,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        inject_scp_keyset(&mut bin, &ks, true).unwrap();
        assert_eq!(bin[88], 0x01); // overwritten
    }

    #[test]
    fn inject_pin_4_digit() {
        let mut bin = fake_binary();
        let pin = GlobalPin {
            pin: vec![0x31, 0x32, 0x33, 0x34],
            max_retries: 3,
        };
        super::inject_global_pin(&mut bin, &pin, false).unwrap();

        // PIN at offset 40 (32 + 8)
        assert_eq!(&bin[40..44], &[0x31, 0x32, 0x33, 0x34]);
        // Remaining PIN slot should be zero (already was)
        assert!(bin[44..56].iter().all(|&b| b == 0));
        // PIN length at 56 (40 + 16)
        assert_eq!(bin[56], 4);
        // Retry count at 57
        assert_eq!(bin[57], 3);
    }

    #[test]
    fn reject_pin_too_short() {
        let mut bin = fake_binary();
        let pin = GlobalPin {
            pin: vec![0x31, 0x32],
            max_retries: 3,
        };
        assert!(matches!(
            super::inject_global_pin(&mut bin, &pin, false),
            Err(ConfigError::InvalidPinLength(2))
        ));
    }

    #[test]
    fn reject_pin_too_long() {
        let mut bin = fake_binary();
        let pin = GlobalPin {
            pin: vec![0x31; 17],
            max_retries: 3,
        };
        assert!(matches!(
            super::inject_global_pin(&mut bin, &pin, false),
            Err(ConfigError::InvalidPinLength(17))
        ));
    }

    #[test]
    fn is_configured_unconfigured() {
        let bin = fake_binary();
        let (scp, pin) = is_configured(&bin);
        assert!(!scp);
        assert!(!pin);
    }

    #[test]
    fn is_configured_after_injection() {
        let mut bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 0x01,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        inject_scp_keyset(&mut bin, &ks, false).unwrap();

        let pin = GlobalPin {
            pin: vec![0x31, 0x32, 0x33, 0x34],
            max_retries: 3,
        };
        super::inject_global_pin(&mut bin, &pin, false).unwrap();

        let (scp, pin_ok) = is_configured(&bin);
        assert!(scp);
        assert!(pin_ok);
    }

    #[test]
    fn scp_magic_no_match_in_empty() {
        let bin = vec![0u8; 256];
        assert!(find_pattern(&bin, &SCP_KEYSET_MAGIC).is_none());
    }

    // -------------------------------------------------------------------
    // Insta snapshots
    // -------------------------------------------------------------------

    /// Hex dump of a byte region for snapshot readability.
    fn hex_region(bin: &[u8], offset: usize, len: usize) -> String {
        bin[offset..offset + len]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn snap_scp_injection_16byte() {
        let mut bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 0x01,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        inject_scp_keyset(&mut bin, &ks, false).unwrap();
        // Magic(8) + KVN(1) + total_len(1) + 3*16 keys = 58 bytes from offset 80
        insta::assert_snapshot!("scp_region_16byte", hex_region(&bin, 80, 58));
    }

    #[test]
    fn snap_scp_injection_32byte() {
        let mut bin = vec![0u8; 512];
        bin[80..88].copy_from_slice(&SCP_KEYSET_MAGIC);
        let ks = ScpKeyset {
            kvn: 0x6F,
            enc: vec![0x11; 32],
            mac: vec![0x22; 32],
            dek: vec![0x33; 32],
        };
        inject_scp_keyset(&mut bin, &ks, false).unwrap();
        // Magic(8) + KVN(1) + total_len(1) + 3*32 keys = 106 bytes from offset 80
        insta::assert_snapshot!("scp_region_32byte", hex_region(&bin, 80, 106));
    }

    #[test]
    fn snap_pin_injection_4digit() {
        let mut bin = fake_binary();
        let pin = GlobalPin {
            pin: vec![0x31, 0x32, 0x33, 0x34],
            max_retries: 3,
        };
        inject_global_pin(&mut bin, &pin, false).unwrap();
        // Magic(8) + PIN_slot(16) + len(1) + retries(1) = 26 bytes from offset 32
        insta::assert_snapshot!("pin_region_4digit", hex_region(&bin, 32, 26));
    }

    #[test]
    fn snap_pin_injection_16digit() {
        let mut bin = fake_binary();
        let pin = GlobalPin {
            pin: vec![
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                0x34, 0x35,
            ],
            max_retries: 10,
        };
        inject_global_pin(&mut bin, &pin, false).unwrap();
        insta::assert_snapshot!("pin_region_16digit", hex_region(&bin, 32, 26));
    }

    #[test]
    fn snap_config_error_messages() {
        let errors = [
            ConfigError::ScpMagicNotFound,
            ConfigError::PinMagicNotFound,
            ConfigError::InvalidKeyLength(15),
            ConfigError::KeyLengthMismatch,
            ConfigError::InvalidKvn(0x00),
            ConfigError::InvalidKvn(0x70),
            ConfigError::InvalidPinLength(2),
            ConfigError::InvalidPinLength(17),
            ConfigError::NonZeroData { offset: 0x58 },
        ];
        let output: String = errors
            .iter()
            .map(|e| format!("  {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        insta::assert_snapshot!("config_error_messages", output);
    }

    #[test]
    fn snap_is_configured_states() {
        // Unconfigured
        let bin = fake_binary();
        let (scp, pin) = is_configured(&bin);
        let unconfigured = format!("scp={scp}, pin={pin}");

        // SCP only
        let mut scp_bin = fake_binary();
        let ks = ScpKeyset {
            kvn: 1,
            enc: vec![0x40; 16],
            mac: vec![0x41; 16],
            dek: vec![0x42; 16],
        };
        inject_scp_keyset(&mut scp_bin, &ks, false).unwrap();
        let (scp, pin) = is_configured(&scp_bin);
        let scp_only = format!("scp={scp}, pin={pin}");

        // Both
        inject_global_pin(
            &mut scp_bin,
            &GlobalPin {
                pin: vec![0x31; 4],
                max_retries: 3,
            },
            false,
        )
        .unwrap();
        let (scp, pin) = is_configured(&scp_bin);
        let both = format!("scp={scp}, pin={pin}");

        let output = format!("unconfigured: {unconfigured}\nscp_only: {scp_only}\nboth: {both}");
        insta::assert_snapshot!("is_configured_states", output);
    }
}
