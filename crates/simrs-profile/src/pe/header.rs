//! PE-Header (`ProfileHeader`) parser.

use crate::der_util;
use crate::error::ProfileError;

/// Profile header metadata from a TCA Profile Package.
///
/// The header is always the first `ProfileElement` (tag 0) and contains
/// version info, ICCID, and capability requirements.
#[derive(Clone, Debug)]
pub struct ProfileHeader {
    /// Major version of the profile format.
    pub major_version: u8,
    /// Minor version of the profile format.
    pub minor_version: u8,
    /// ICCID (10 bytes, BCD-encoded).
    pub iccid: Vec<u8>,
    /// Raw bytes of the header for fields we don't parse yet.
    pub raw: Vec<u8>,
}

impl ProfileHeader {
    /// Parse a `ProfileHeader` from the value bytes of the PE.
    ///
    /// The `ProfileHeader` is a SEQUENCE containing:
    /// - major-version INTEGER
    /// - minor-version INTEGER
    /// - profileType `UTF8String` OPTIONAL
    /// - iccid OCTET STRING (SIZE(10))
    /// - ... additional optional fields
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Truncated`] if the data is too short
    /// to contain the required fields.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        // ProfileHeader is itself a SEQUENCE.
        let inner = der_util::peel_optional_sequence(data)?;

        let mut iter = der_util::iter_tlvs(inner);

        // First field: major-version (INTEGER, tag 0x02)
        let major = iter.next().ok_or(ProfileError::Truncated)?.map(|tlv| {
            if tlv.value.is_empty() {
                0
            } else {
                tlv.value[tlv.value.len() - 1]
            }
        })?;

        // Second field: minor-version (INTEGER, tag 0x02)
        let minor = iter.next().ok_or(ProfileError::Truncated)?.map(|tlv| {
            if tlv.value.is_empty() {
                0
            } else {
                tlv.value[tlv.value.len() - 1]
            }
        })?;

        // Remaining fields use AUTOMATIC TAGS (context-specific IMPLICIT):
        //   [2] profileType (UTF8String, optional)
        //   [3] iccid (OCTET STRING SIZE(10))
        //   [4] pol (OCTET STRING, optional)
        //   [5] eUICC-Mandatory-services (ServicesList, optional)
        //   ...
        // Find iccid at context tag [3].
        let mut iccid = Vec::new();
        for tlv_result in iter {
            let tlv = tlv_result?;
            if tlv.class == 2 && tlv.number == 3 && tlv.value.len() == 10 {
                iccid = tlv.value.to_vec();
                break;
            }
        }

        Ok(Self {
            major_version: major,
            minor_version: minor,
            iccid,
            raw: data.to_vec(),
        })
    }
}
