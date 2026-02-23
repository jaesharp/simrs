//! PE-CDMAParameter (tag 5) parser.

use crate::error::ProfileError;

/// PE-CDMAParameter: CDMA authentication keys (`ProfileElement` tag 5).
///
/// This PE carries CDMA authentication parameters. Since CDMA is not
/// used in the simrs filesystem, the raw DER bytes are stored opaquely.
#[derive(Clone, Debug)]
pub struct PeCdmaParameter {
    /// Raw PE value bytes.
    pub data: Vec<u8>,
}

impl PeCdmaParameter {
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
