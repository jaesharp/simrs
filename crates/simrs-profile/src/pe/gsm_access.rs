//! PE-GSM-ACCESS (tag 24) parser.

use super::parse_template_files;
use crate::error::ProfileError;
use crate::file::File;

/// PE-GSM-ACCESS: DF.GSM-ACCESS under ADF.USIM (`ProfileElement` tag 24).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID,
/// `[2]` df-gsm-access, `[3]` ef-kc (opt), `[4]` ef-kcgprs (opt),
/// `[5]` ef-cpbcch (opt), `[6]` ef-invscan (opt).
#[derive(Clone, Debug)]
pub struct PeGsmAccess {
    /// All files: tag `[2]` is DF.GSM-ACCESS, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PeGsmAccess {
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
