//! PE-CD (tag 17) parser.

use crate::error::ProfileError;
use crate::file::File;
use super::parse_template_files;

/// PE-CD: DF.CD and its child EFs (`ProfileElement` tag 17).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID, `[2]` df-cd,
/// `[3]` ef-launchpad (optional), `[4]` ef-icon (optional).
#[derive(Clone, Debug)]
pub struct PeCd {
    /// All files: tag `[2]` is DF.CD, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PeCd {
    /// Parse from the PE value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self { files: parse_template_files(data)? })
    }
}
