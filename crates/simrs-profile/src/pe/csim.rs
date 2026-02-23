//! PE-CSIM (tag 25) parser.

use crate::error::ProfileError;
use crate::file::File;
use super::parse_template_files;

/// PE-CSIM: ADF.CSIM and its child EFs (`ProfileElement` tag 25).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID, `[2]` adf-csim,
/// `[3]` ef-arr, and additional CSIM EFs.
#[derive(Clone, Debug)]
pub struct PeCsim {
    /// All files: tag `[2]` is ADF.CSIM, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PeCsim {
    /// Parse from the PE value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self { files: parse_template_files(data)? })
    }
}
