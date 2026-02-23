//! PE-DF-5GS (tag 28) parser.

use crate::error::ProfileError;
use crate::file::File;
use super::parse_template_files;

/// PE-DF-5GS: DF.5GS under ADF.USIM (`ProfileElement` tag 28).
///
/// Fields (AUTOMATIC TAGS): `[0]` header, `[1]` templateID,
/// `[2]` df-df-5gs, `[3]`-`[21]` optional 5G EFs (loci, NSC, auth keys,
/// SUCI calc info, URSP, CAG, etc).
#[derive(Clone, Debug)]
pub struct PeDf5gs {
    /// All files: tag `[2]` is DF.5GS, rest are child EFs.
    pub files: Vec<(u8, File)>,
}

impl PeDf5gs {
    /// Parse from the PE value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        Ok(Self { files: parse_template_files(data)? })
    }
}
