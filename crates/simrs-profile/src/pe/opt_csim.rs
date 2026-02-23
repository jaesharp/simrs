//! PE-OPT-CSIM (tag 26) parser.

use crate::error::ProfileError;
use crate::file::File;
use super::parse_template_files;

/// PE-OPT-CSIM: optional CSIM EFs (`ProfileElement` tag 26).
///
/// All fields are OPTIONAL File types (tags `[2]`+), added to an
/// existing ADF.CSIM created by PE-CSIM.
#[derive(Clone, Debug)]
pub struct PeOptCsim {
    /// Optional EFs to add to ADF.CSIM.
    pub files: Vec<(u8, File)>,
}

impl PeOptCsim {
    /// Parse from the PE value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self { files: parse_template_files(data)? })
    }
}
