//! PE-MF (Master File) parser.

use crate::der_util;
use crate::error::ProfileError;
use crate::file::File;

/// PE-MF: Master File structure (`ProfileElement` tag 16).
///
/// Contains the MF definition and its direct EF children
/// (ICCID, DIR, ARR, PL, UMPC).
#[derive(Clone, Debug)]
pub struct PeMf {
    /// MF directory FCP.
    pub mf: File,
    /// EF.PL (preferred languages) -- optional.
    pub ef_pl: Option<File>,
    /// EF.ICCID.
    pub ef_iccid: File,
    /// EF.DIR (application directory).
    pub ef_dir: File,
    /// EF.ARR (access rule reference).
    pub ef_arr: File,
    /// EF.UMPC -- optional.
    pub ef_umpc: Option<File>,
}

impl PeMf {
    /// Parse PE-MF from the value bytes of the `ProfileElement`.
    ///
    /// PE-MF is a SEQUENCE with AUTOMATIC TAGS:
    /// - `[0]` `PEHeader` (mf-header)
    /// - `[1]` OID (templateID)
    /// - `[2]` File (mf)
    /// - `[3]` File OPTIONAL (ef-pl)
    /// - `[4]` File (ef-iccid)
    /// - `[5]` File (ef-dir)
    /// - `[6]` File (ef-arr)
    /// - `[7]` File OPTIONAL (ef-umpc)
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed or
    /// required files are missing.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let inner = der_util::peel_optional_sequence(data)?;

        let tlvs: Vec<_> = der_util::iter_tlvs(inner).collect::<Result<_, _>>()?;

        // Context-specific constructed: tag_num -> 0xA0 | tag_num for num < 31.
        let parse_file = |tag_num: u8| -> Option<Result<File, ProfileError>> {
            let tag_byte = 0xA0 | tag_num;
            tlvs.iter()
                .find(|t| t.tag == tag_byte || (tag_num >= 31 && t.number == tag_num))
                .map(|t| File::from_bytes(t.value))
        };

        let mf = parse_file(2).ok_or(ProfileError::MissingMf)??;
        let ef_pl = parse_file(3).transpose()?;
        let ef_iccid = parse_file(4).ok_or(ProfileError::MissingRequiredFile(4))??;
        let ef_dir = parse_file(5).ok_or(ProfileError::MissingRequiredFile(5))??;
        let ef_arr = parse_file(6).ok_or(ProfileError::MissingRequiredFile(6))??;
        let ef_umpc = parse_file(7).transpose()?;

        Ok(Self {
            mf,
            ef_pl,
            ef_iccid,
            ef_dir,
            ef_arr,
            ef_umpc,
        })
    }
}
