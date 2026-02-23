//! PE-SecurityDomain (tag 6) parser.

use crate::error::ProfileError;

/// PE-SecurityDomain: `GlobalPlatform` security domain install parameters
/// (`ProfileElement` tag 6).
///
/// This PE carries security domain configuration for `GlobalPlatform`
/// card management. The raw DER bytes are stored opaquely since simrs
/// does not implement GP security domain operations.
#[derive(Clone, Debug)]
pub struct PeSecurityDomain {
    /// Raw PE value bytes.
    pub data: Vec<u8>,
}

impl PeSecurityDomain {
    /// Parse from the PE value bytes.
    ///
    /// Stores the raw bytes without further interpretation.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the data is empty (should not happen
    /// for a well-formed PE).
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self {
            data: data.to_vec(),
        })
    }
}
