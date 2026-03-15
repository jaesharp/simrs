//! PE-TELECOM (tag 18) parser.

use super::parse_template_files;
use crate::error::ProfileError;
use crate::file::File;

/// PE-TELECOM: DF.TELECOM and its child EFs (`ProfileElement` tag 18).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID, `[2]` df-telecom,
/// `[3]`-`[47]` optional EFs (contacts, SMS, graphics, multimedia, V2X).
#[derive(Clone, Debug)]
pub struct PeTelecom {
    /// All files: tag `[2]` is DF.TELECOM, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PeTelecom {
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
