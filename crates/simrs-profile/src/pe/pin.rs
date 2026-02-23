//! PE-PINCodes and PE-PUKCodes parsers.

use crate::der_util;
use crate::error::ProfileError;

/// A single PIN configuration entry.
#[derive(Clone, Debug)]
pub struct PinConfiguration {
    /// PIN key reference (e.g. 0x01 = PIN1, 0x81 = PIN2).
    pub key_reference: u8,
    /// PIN value (8 bytes, ASCII digits + 0xFF padding).
    pub pin_value: [u8; 8],
    /// Unblocking PIN (PUK) key reference, if linked.
    pub unblocking_ref: Option<u8>,
    /// PIN attributes (default 7).
    pub pin_attributes: u8,
    /// Max retries and remaining retries (packed: high nibble = max,
    /// low nibble = remaining). Default 0x33 (3 max, 3 remaining).
    pub max_retries_byte: u8,
}

/// PE-PINCodes: PIN configuration (`ProfileElement` tag 2).
#[derive(Clone, Debug)]
pub struct PePinCodes {
    /// PIN configurations.
    pub pins: Vec<PinConfiguration>,
}

/// A single PUK configuration entry.
#[derive(Clone, Debug)]
pub struct PukConfiguration {
    /// PUK key reference.
    pub key_reference: u8,
    /// PUK value (8 bytes).
    pub puk_value: [u8; 8],
    /// Max retries byte (packed). Default 0xAA (10 max, 10 remaining).
    pub max_retries_byte: u8,
}

/// PE-PUKCodes: PUK configuration (`ProfileElement` tag 3).
#[derive(Clone, Debug)]
pub struct PePukCodes {
    /// PUK configurations.
    pub puks: Vec<PukConfiguration>,
}

impl PePinCodes {
    /// Parse PE-PINCodes from the value bytes.
    ///
    /// PE-PINCodes SEQUENCE with AUTOMATIC TAGS:
    /// - `[0]` `PEHeader`
    /// - `[1]` CHOICE { pinconfig SEQUENCE OF `PINConfiguration` | filePath }
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let inner = der_util::peel_optional_sequence(data)?;

        let tlvs: Vec<_> = der_util::iter_tlvs(inner)
            .collect::<Result<_, _>>()?;

        // Tag [1] is an EXPLICIT wrapper around the CHOICE (IMPLICIT
        // cannot directly tag a CHOICE). Inside [1], the CHOICE
        // alternatives with AUTOMATIC TAGS are:
        //   [0] pinconfig (SEQUENCE OF PINConfiguration)
        //   [1] filePath  (OCTET STRING)
        let choice_tlv = tlvs.iter()
            .find(|t| t.number == 1 && t.class == 2)
            .ok_or(ProfileError::MissingRequiredFile(1))?;

        // Parse the CHOICE alternative tag inside the EXPLICIT wrapper.
        let (alt_tlv, _) = der_util::parse_tlv(choice_tlv.value)?;

        let mut pins = Vec::new();

        if alt_tlv.class == 2 && alt_tlv.number == 0 {
            // [0] = pinconfig: SEQUENCE OF PINConfiguration.
            for tlv_result in der_util::iter_tlvs(alt_tlv.value) {
                let tlv = tlv_result?;
                if tlv.tag == 0x30 {
                    pins.push(Self::parse_pin_config(tlv.value)?);
                }
            }
        } else if alt_tlv.class == 2 && alt_tlv.number == 1 {
            // [1] = filePath: PIN storage via file reference is not supported.
            return Err(ProfileError::FileBasedPinNotSupported);
        }

        Ok(Self { pins })
    }

    /// Parse a single `PINConfiguration` SEQUENCE.
    fn parse_pin_config(data: &[u8]) -> Result<PinConfiguration, ProfileError> {
        let tlvs: Vec<_> = der_util::iter_tlvs(data)
            .collect::<Result<_, _>>()?;

        // PINConfiguration fields (AUTOMATIC TAGS):
        // [0] INTEGER keyReference
        // [1] OCTET STRING pinValue (8 bytes)
        // [2] INTEGER unblockingPINReference OPTIONAL
        // [3] INTEGER pinAttributes DEFAULT 7
        // [4] INTEGER maxNumOfAttemps-retryNumLeft DEFAULT 51 (0x33)

        let key_reference = tlvs.iter()
            .find(|t| t.number == 0 && t.class == 2)
            .and_then(|t| t.value.last().copied())
            .unwrap_or(0x01);

        let mut pin_value = [0xFF; 8];
        if let Some(tlv) = tlvs.iter().find(|t| t.number == 1 && t.class == 2) {
            let len = tlv.value.len().min(8);
            pin_value[..len].copy_from_slice(&tlv.value[..len]);
        }

        let unblocking_ref = tlvs.iter()
            .find(|t| t.number == 2 && t.class == 2)
            .and_then(|t| t.value.last().copied());

        let pin_attributes = tlvs.iter()
            .find(|t| t.number == 3 && t.class == 2)
            .and_then(|t| t.value.last().copied())
            .unwrap_or(7);

        let max_retries_byte = tlvs.iter()
            .find(|t| t.number == 4 && t.class == 2)
            .and_then(|t| t.value.last().copied())
            .unwrap_or(0x33);

        Ok(PinConfiguration {
            key_reference,
            pin_value,
            unblocking_ref,
            pin_attributes,
            max_retries_byte,
        })
    }
}

impl PePukCodes {
    /// Parse PE-PUKCodes from the value bytes.
    ///
    /// PE-PUKCodes SEQUENCE:
    /// - `[0]` `PEHeader`
    /// - `[1]` SEQUENCE OF `PUKConfiguration`
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let inner = der_util::peel_optional_sequence(data)?;

        let tlvs: Vec<_> = der_util::iter_tlvs(inner)
            .collect::<Result<_, _>>()?;

        let puk_data_tlv = tlvs.iter()
            .find(|t| t.number == 1 && t.class == 2)
            .ok_or(ProfileError::MissingRequiredFile(1))?;

        let mut puks = Vec::new();
        for tlv_result in der_util::iter_tlvs(puk_data_tlv.value) {
            let tlv = tlv_result?;
            if tlv.tag == 0x30 {
                puks.push(Self::parse_puk_config(tlv.value)?);
            }
        }

        Ok(Self { puks })
    }

    /// Parse a single `PUKConfiguration` SEQUENCE.
    fn parse_puk_config(data: &[u8]) -> Result<PukConfiguration, ProfileError> {
        let tlvs: Vec<_> = der_util::iter_tlvs(data)
            .collect::<Result<_, _>>()?;

        // PUKConfiguration fields (AUTOMATIC TAGS):
        // [0] INTEGER keyReference
        // [1] OCTET STRING pukValue (8 bytes)
        // [2] INTEGER maxNumOfAttemps-retryNumLeft DEFAULT 0xAA (170)

        let key_reference = tlvs.iter()
            .find(|t| t.number == 0 && t.class == 2)
            .and_then(|t| t.value.last().copied())
            .unwrap_or(0x01);

        let mut puk_value = [0xFF; 8];
        if let Some(tlv) = tlvs.iter().find(|t| t.number == 1 && t.class == 2) {
            let len = tlv.value.len().min(8);
            puk_value[..len].copy_from_slice(&tlv.value[..len]);
        }

        let max_retries_byte = tlvs.iter()
            .find(|t| t.number == 2 && t.class == 2)
            .and_then(|t| t.value.last().copied())
            .unwrap_or(0xAA);

        Ok(PukConfiguration {
            key_reference,
            puk_value,
            max_retries_byte,
        })
    }
}
