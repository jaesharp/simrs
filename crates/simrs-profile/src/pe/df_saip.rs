//! PE-DF-SAIP (tag 29) parser.

use super::parse_template_files;
use crate::error::ProfileError;
use crate::file::File;

/// PE-DF-SAIP: DF.SAIP under ADF.USIM (`ProfileElement` tag 29).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID,
/// `[2]` df-df-saip, `[3]` ef-suci-calc-info-usim (optional).
#[derive(Clone, Debug)]
pub struct PeDfSaip {
    /// All files: tag `[2]` is DF.SAIP, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PeDfSaip {
    /// Parse from the PE value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self {
            files: parse_template_files(data)?,
        })
    }
}
