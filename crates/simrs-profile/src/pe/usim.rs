//! PE-USIM (USIM Application) parser.

use crate::der_util;
use crate::error::ProfileError;
use crate::file::File;

/// PE-USIM: USIM application structure (`ProfileElement` tag 19).
///
/// Contains the ADF.USIM definition and its EF children.
/// Fields follow TCA PE_Definitions-3.3.1.asn `PE-USIM` SEQUENCE.
#[derive(Clone, Debug)]
pub struct PeUsim {
    /// ADF.USIM directory FCP (contains AID in dfName).
    pub adf_usim: File,
    /// EF.IMSI.
    pub ef_imsi: File,
    /// EF.ARR.
    pub ef_arr: File,
    /// EF.Keys (CK/IK) -- optional.
    pub ef_keys: Option<File>,
    /// EF.KeysPS -- optional.
    pub ef_keys_ps: Option<File>,
    /// EF.HPPLMN -- optional.
    pub ef_hpplmn: Option<File>,
    /// EF.UST (USIM Service Table).
    pub ef_ust: File,
    /// EF.FDN (Fixed Dialling Numbers) -- optional.
    pub ef_fdn: Option<File>,
    /// EF.SMS -- optional.
    pub ef_sms: Option<File>,
    /// EF.SMSP -- optional.
    pub ef_smsp: Option<File>,
    /// EF.SMSS -- optional.
    pub ef_smss: Option<File>,
    /// EF.SPN (Service Provider Name).
    pub ef_spn: File,
    /// EF.EST (Enabled Services Table).
    pub ef_est: File,
    /// EF.START-HFN -- optional.
    pub ef_start_hfn: Option<File>,
    /// EF.THRESHOLD -- optional.
    pub ef_threshold: Option<File>,
    /// EF.PSLOCI -- optional.
    pub ef_psloci: Option<File>,
    /// EF.ACC (Access Control Class).
    pub ef_acc: File,
    /// EF.FPLMN -- optional.
    pub ef_fplmn: Option<File>,
    /// EF.LOCI -- optional.
    pub ef_loci: Option<File>,
    /// EF.AD (Administrative Data) -- optional.
    pub ef_ad: Option<File>,
    /// EF.ECC (Emergency Call Codes).
    pub ef_ecc: File,
    /// EF.NETPAR -- optional.
    pub ef_netpar: Option<File>,
    /// EF.EPSLOCI -- optional.
    pub ef_epsloci: Option<File>,
    /// EF.EPSNSC -- optional.
    pub ef_epsnsc: Option<File>,
    /// Additional files from tags beyond the base set.
    pub extra_files: Vec<(u8, File)>,
}

impl PeUsim {
    /// Parse PE-USIM from the value bytes of the `ProfileElement`.
    ///
    /// PE-USIM is a SEQUENCE with AUTOMATIC TAGS. The tag numbers
    /// correspond to field positions in the ASN.1 definition:
    /// - `[0]` `PEHeader`
    /// - `[1]` OID (templateID)
    /// - `[2]` File (adf-usim)
    /// - `[3]` File (ef-imsi)
    /// - `[4]` File (ef-arr)
    /// - `[5]` File OPTIONAL (ef-keys)
    /// - `[6]` File OPTIONAL (ef-keysPS)
    /// - `[7]` File OPTIONAL (ef-hpplmn)
    /// - `[8]` File (ef-ust)
    /// - `[9]` File OPTIONAL (ef-fdn)
    /// - `[10]` File OPTIONAL (ef-sms)
    /// - `[11]` File OPTIONAL (ef-smsp)
    /// - `[12]` File OPTIONAL (ef-smss)
    /// - `[13]` File (ef-spn)
    /// - `[14]` File (ef-est)
    /// - `[15]` File OPTIONAL (ef-start-hfn)
    /// - `[16]` File OPTIONAL (ef-threshold)
    /// - `[17]` File OPTIONAL (ef-psloci)
    /// - `[18]` File (ef-acc)
    /// - `[19]` File OPTIONAL (ef-fplmn)
    /// - `[20]` File OPTIONAL (ef-loci)
    /// - `[21]` File OPTIONAL (ef-ad)
    /// - `[22]` File (ef-ecc)
    /// - `[23]` File OPTIONAL (ef-netpar)
    /// - `[24]` File OPTIONAL (ef-epsloci)
    /// - `[25]` File OPTIONAL (ef-epsnsc)
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed or
    /// required files are missing.
    #[allow(clippy::too_many_lines)]
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let inner = der_util::peel_optional_sequence(data)?;

        // Collect all TLVs. PE-USIM uses tags [0]-[25+], which with
        // IMPLICIT context-specific tagging means constructed tags
        // 0xA0 through 0xB9 (for tag numbers up to 25).
        // Tags 0-30 use single-byte encoding, tags >= 31 use multi-byte.
        let tlvs: Vec<_> = der_util::iter_tlvs(inner)
            .collect::<Result<_, _>>()?;

        let parse_file = |tag_num: u8| -> Option<Result<File, ProfileError>> {
            // Context-specific constructed: 0xA0 + tag_num (for num < 31)
            let tag_byte = 0xA0 | tag_num;
            tlvs.iter()
                .find(|t| t.tag == tag_byte || (tag_num >= 31 && t.number == tag_num))
                .map(|t| File::from_bytes(t.value))
        };

        let require_file =
            |tag_num: u8| -> Result<File, ProfileError> {
                parse_file(tag_num)
                    .ok_or(ProfileError::MissingRequiredFile(tag_num))?
            };

        let optional_file =
            |tag_num: u8| -> Result<Option<File>, ProfileError> {
                parse_file(tag_num).transpose()
            };

        // Collect any extra files beyond tag 25.
        let mut extra_files = Vec::new();
        for tlv in &tlvs {
            if tlv.class == 2 && tlv.number > 25 {
                if let Ok(f) = File::from_bytes(tlv.value) {
                    extra_files.push((tlv.number, f));
                }
            }
        }

        Ok(Self {
            adf_usim: require_file(2)?,
            ef_imsi: require_file(3)?,
            ef_arr: require_file(4)?,
            ef_keys: optional_file(5)?,
            ef_keys_ps: optional_file(6)?,
            ef_hpplmn: optional_file(7)?,
            ef_ust: require_file(8)?,
            ef_fdn: optional_file(9)?,
            ef_sms: optional_file(10)?,
            ef_smsp: optional_file(11)?,
            ef_smss: optional_file(12)?,
            ef_spn: require_file(13)?,
            ef_est: require_file(14)?,
            ef_start_hfn: optional_file(15)?,
            ef_threshold: optional_file(16)?,
            ef_psloci: optional_file(17)?,
            ef_acc: require_file(18)?,
            ef_fplmn: optional_file(19)?,
            ef_loci: optional_file(20)?,
            ef_ad: optional_file(21)?,
            ef_ecc: require_file(22)?,
            ef_netpar: optional_file(23)?,
            ef_epsloci: optional_file(24)?,
            ef_epsnsc: optional_file(25)?,
            extra_files,
        })
    }
}
