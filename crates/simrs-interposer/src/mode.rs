//! Interposer mode, configuration, and hex-parsing utilities.

use simrs_pcap::LinkType;

/// Operating mode for the APDU interposer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterposerMode {
    /// Passthrough APDUs to real SIM, write PCAP.
    Log,
    /// Forward to both real and simulated SIM, compare responses.
    Shadow,
    /// Use simrs SIM responses instead of real SIM.
    Replace,
    /// Compare responses from N SIM implementations (no shadow sim).
    Diff,
}

/// Authentication credentials for the shadow/replace SIM.
#[derive(Debug)]
pub struct AuthConfig {
    /// GSM Ki (128 bits).
    pub ki: [u8; 16],
    /// UMTS K (128 bits).
    pub k: [u8; 16],
    /// UMTS `OPc` (128 bits).
    pub opc: [u8; 16],
}

/// Full configuration for the interposer proxy.
#[derive(Debug)]
pub struct InterposerConfig {
    /// Operating mode.
    pub mode: InterposerMode,
    /// Address of the modem-side swICC server (we act as card).
    pub modem_addr: String,
    /// Address of the card-side swICC server (we send APDUs to real SIM).
    /// Used for Log, Shadow, Replace modes.
    pub card_addr: Option<String>,
    /// Addresses of N card-side swICC servers for Diff mode.
    /// Each connection receives the same APDUs and responses are compared.
    pub card_addrs: Vec<String>,
    /// Path for PCAP output file.
    pub pcap_path: Option<String>,
    /// PCAP link-layer type.
    pub link_type: LinkType,
    /// Authentication parameters for shadow/replace SIM.
    pub auth: Option<AuthConfig>,
}

/// Parse a hex string into a fixed-size byte array.
///
/// Returns `None` if the string has wrong length or invalid hex characters.
/// Does not accept a `0x` prefix (unlike `simrs-auth-cli`'s variant which
/// strips `0x`/`0X` and returns `Result<_, String>` with field-name context).
pub fn parse_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut result = [0u8; N];
    let mut i = 0;
    while i < N {
        let hi = hex_nibble(hex.as_bytes()[i * 2])?;
        let lo = hex_nibble(hex.as_bytes()[i * 2 + 1])?;
        result[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(result)
}

/// Parse a single hex character to a nibble value.
const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse an [`InterposerMode`] from a string.
///
/// Accepts `"log"`, `"shadow"`, `"replace"`, or `"diff"` (case-insensitive).
pub fn parse_mode(s: &str) -> Option<InterposerMode> {
    match s.to_ascii_lowercase().as_str() {
        "log" => Some(InterposerMode::Log),
        "shadow" => Some(InterposerMode::Shadow),
        "replace" => Some(InterposerMode::Replace),
        "diff" => Some(InterposerMode::Diff),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_valid_16_bytes() {
        let result: Option<[u8; 16]> =
            parse_hex("465b5ce8b199b49faa5f0a2ee238a6bc");
        assert!(result.is_some());
        let bytes = result.unwrap();
        assert_eq!(
            bytes,
            [0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F,
             0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC]
        );
    }

    #[test]
    fn parse_hex_uppercase() {
        let result: Option<[u8; 4]> = parse_hex("DEADBEEF");
        assert_eq!(result, Some([0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn parse_hex_invalid_chars() {
        let result: Option<[u8; 4]> = parse_hex("ZZZZZZZZ");
        assert!(result.is_none());
    }

    #[test]
    fn parse_hex_odd_length() {
        let result: Option<[u8; 2]> = parse_hex("ABC");
        assert!(result.is_none());
    }

    #[test]
    fn parse_hex_wrong_size() {
        // 8 hex chars but expecting 16 bytes
        let result: Option<[u8; 16]> = parse_hex("DEADBEEF");
        assert!(result.is_none());
    }

    #[test]
    fn parse_mode_valid() {
        assert_eq!(parse_mode("log"), Some(InterposerMode::Log));
        assert_eq!(parse_mode("shadow"), Some(InterposerMode::Shadow));
        assert_eq!(parse_mode("replace"), Some(InterposerMode::Replace));
        assert_eq!(parse_mode("diff"), Some(InterposerMode::Diff));
        assert_eq!(parse_mode("LOG"), Some(InterposerMode::Log));
        assert_eq!(parse_mode("Shadow"), Some(InterposerMode::Shadow));
    }

    #[test]
    fn parse_mode_invalid() {
        assert_eq!(parse_mode(""), None);
        assert_eq!(parse_mode("passthrough"), None);
        assert_eq!(parse_mode("mirror"), None);
    }
}
