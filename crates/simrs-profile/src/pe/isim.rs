//! PE-ISIM (tag 21) parser.

use super::parse_template_files;
use crate::error::ProfileError;
use crate::file::File;

/// PE-ISIM: ADF.ISIM and its child EFs (`ProfileElement` tag 21).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID, `[2]` adf-isim,
/// `[3]` ef-impi, `[4]` ef-impu, `[5]` ef-domain, `[6]` ef-ist,
/// `[7]` ef-ad (optional), `[8]` ef-arr.
#[derive(Clone, Debug)]
pub struct PeIsim {
    /// All files: tag `[2]` is ADF.ISIM, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PeIsim {
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
