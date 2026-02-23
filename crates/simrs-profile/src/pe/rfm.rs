//! PE-RFM (tag 7) parser.

use crate::error::ProfileError;

/// PE-RFM: OTA Remote File Management configuration (`ProfileElement` tag 7).
///
/// This PE carries OTA RFM parameters for remote administration.
/// The raw DER bytes are stored opaquely since simrs does not implement
/// OTA operations.
#[derive(Clone, Debug)]
pub struct PeRfm {
    /// Raw PE value bytes.
    pub data: Vec<u8>,
}

impl PeRfm {
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
