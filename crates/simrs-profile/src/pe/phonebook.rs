//! PE-PHONEBOOK (tag 23) parser.

use crate::error::ProfileError;
use crate::file::File;
use super::parse_template_files;

/// PE-PHONEBOOK: DF.PHONEBOOK under ADF.USIM (`ProfileElement` tag 23).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID,
/// `[2]` df-phonebook, `[3]` ef-pbr (optional), `[4]` ef-adn (optional),
/// and additional optional phonebook EFs.
#[derive(Clone, Debug)]
pub struct PePhonebook {
    /// All files: tag `[2]` is DF.PHONEBOOK, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PePhonebook {
    /// Parse from the PE value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self { files: parse_template_files(data)? })
    }
}
