//! PE-OPT-USIM (tag 20) parser.

use super::parse_template_files;
use crate::error::ProfileError;
use crate::file::File;

/// PE-OPT-USIM: optional USIM EFs (`ProfileElement` tag 20).
///
/// All fields are OPTIONAL File types (tags `[2]`-`[87]`), added to an
/// existing ADF.USIM created by PE-USIM.
#[derive(Clone, Debug)]
pub struct PeOptUsim {
    /// Optional EFs to add to ADF.USIM.
    pub files: Vec<(u8, File)>,
}

impl PeOptUsim {
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
