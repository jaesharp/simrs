//! PE-OPT-ISIM (tag 22) parser.

use super::parse_template_files;
use crate::error::ProfileError;
use crate::file::File;

/// PE-OPT-ISIM: optional ISIM EFs (`ProfileElement` tag 22).
///
/// All fields are OPTIONAL File types (tags `[2]`-`[15]`), added to an
/// existing ADF.ISIM created by PE-ISIM.
#[derive(Clone, Debug)]
pub struct PeOptIsim {
    /// Optional EFs to add to ADF.ISIM.
    pub files: Vec<(u8, File)>,
}

impl PeOptIsim {
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
