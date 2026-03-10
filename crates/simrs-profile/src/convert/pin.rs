//! PE-PINCodes / PE-PUKCodes to simrs PIN configuration conversion.

use crate::pe::pin::{PePinCodes, PePukCodes};
use simrs_redact::Redact;

/// Extracted PIN configuration for a single PIN.
#[derive(Clone)]
pub struct PinConfig {
    /// PIN key reference (e.g. 0x01 = PIN1, 0x81 = PIN2).
    pub key_reference: u8,
    /// PIN value (8 bytes, ASCII digits + 0xFF padding).
    pub pin_value: [u8; 8],
    /// Linked PUK key reference, if any.
    pub puk_key_reference: Option<u8>,
    /// Maximum retry attempts.
    pub max_retries: u8,
    /// Whether the PIN is enabled.
    pub enabled: bool,
}

impl core::fmt::Debug for PinConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinConfig")
            .field("key_reference", &self.key_reference)
            .field("pin_value", &Redact(&self.pin_value))
            .field("puk_key_reference", &self.puk_key_reference)
            .field("max_retries", &self.max_retries)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Extracted PUK configuration for a single PUK.
#[derive(Clone)]
pub struct PukConfig {
    /// PUK key reference.
    pub key_reference: u8,
    /// PUK value (8 bytes).
    pub puk_value: [u8; 8],
    /// Maximum retry attempts.
    pub max_retries: u8,
}

impl core::fmt::Debug for PukConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PukConfig")
            .field("key_reference", &self.key_reference)
            .field("puk_value", &Redact(&self.puk_value))
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

/// Extract PIN configurations from a PE-PINCodes.
pub fn extract_pins(pe: &PePinCodes) -> Vec<PinConfig> {
    pe.pins
        .iter()
        .map(|c| {
            // max_retries_byte encodes: high nibble = max, low nibble = remaining.
            let max_retries = c.max_retries_byte >> 4;

            // pin_attributes bit 7: 0 = disabled, 1 = enabled (per TCA spec).
            // Default value 7 means bits 0-2 set but bit 7 clear = disabled.
            // Value 0x87 = enabled.
            let enabled = (c.pin_attributes & 0x80) != 0;

            PinConfig {
                key_reference: c.key_reference,
                pin_value: c.pin_value,
                puk_key_reference: c.unblocking_ref,
                max_retries,
                enabled,
            }
        })
        .collect()
}

/// Extract PUK configurations from a PE-PUKCodes.
pub fn extract_puks(pe: &PePukCodes) -> Vec<PukConfig> {
    pe.puks
        .iter()
        .map(|c| {
            let max_retries = c.max_retries_byte >> 4;

            PukConfig {
                key_reference: c.key_reference,
                puk_value: c.puk_value,
                max_retries,
            }
        })
        .collect()
}
