//! FCP (File Control Parameters) parsing.
//!
//! Manually decodes the TCA `Fcp` type because it contains PRIVATE-class
//! tags (0xC6, 0xC7) that the `der` crate's derive macros do not support.

use crate::der_util::{self, Tlv};
use crate::error::ProfileError;
use simrs_fs::{EfStructure, Fid, Sfi};

/// Parsed FCP (File Control Parameters) from a TCA Profile Package.
///
/// Field tag numbers follow [ETSI TS 102 221 V18.3.0 clause 11.1.1.3](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf#%5B%7B%22num%22%3A335%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C783%5D):
/// - `[0]` / 0x80 = EF file size
/// - `[2]` / 0x82 = file descriptor
/// - `[3]` / 0x83 = file ID
/// - `[4]` / 0x84 = DF name (AID)
/// - `[5]` / 0xA5 = proprietary info (constructed)
/// - `[8]` / 0x88 = short EF ID
/// - `[10]` / 0x8A = lifecycle status integer
/// - `[11]` / 0x8B = security attributes referenced
/// - PRIVATE `[6]` / 0xC6 = PIN status template DO
/// - PRIVATE `[7]` / 0xC7 = link path
#[derive(Clone, Debug, Default)]
pub struct Fcp {
    /// File descriptor bytes (2-4 bytes): structure + data coding + optional
    /// record count and record size.
    pub file_descriptor: Option<Vec<u8>>,
    /// File ID (2 bytes, big-endian).
    pub file_id: Option<[u8; 2]>,
    /// DF name / AID (5-16 bytes).
    pub df_name: Option<Vec<u8>>,
    /// Lifecycle status integer (default 0x05 = activated).
    pub lcsi: u8,
    /// Security attributes referenced.
    pub security_attrs: Option<Vec<u8>>,
    /// EF file size (variable-length big-endian integer).
    pub ef_file_size: Option<Vec<u8>>,
    /// PIN status template DO.
    pub pin_status: Option<Vec<u8>>,
    /// Short EF ID (5-bit value, encoded as byte >> 3).
    pub short_ef_id: Option<u8>,
    /// Proprietary information.
    pub proprietary: Option<Vec<u8>>,
    /// Link path.
    pub link_path: Option<Vec<u8>>,
}

impl Fcp {
    /// Parse an FCP from DER bytes (the value inside a SEQUENCE tag).
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any TLV in the FCP is malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let mut fcp = Self {
            lcsi: 0x05, // default: activated
            ..Default::default()
        };

        for tlv_result in der_util::iter_tlvs(data) {
            let tlv: Tlv<'_> = tlv_result?;
            // Tag byte encodes class + constructed + number.
            // Context-specific primitive: 0x80 + number
            // Context-specific constructed: 0xA0 + number
            // Private primitive: 0xC0 + number
            // Private constructed: 0xE0 + number
            match tlv.tag {
                0x80 => {
                    // [0] EF file size
                    fcp.ef_file_size = Some(tlv.value.to_vec());
                }
                0x82 => {
                    // [2] File descriptor
                    fcp.file_descriptor = Some(tlv.value.to_vec());
                }
                0x83 if tlv.value.len() >= 2 => {
                    // [3] File ID
                    fcp.file_id = Some([tlv.value[0], tlv.value[1]]);
                }
                0x84 => {
                    // [4] DF name (AID)
                    fcp.df_name = Some(tlv.value.to_vec());
                }
                0xA5 => {
                    // [5] Proprietary info (constructed)
                    fcp.proprietary = Some(tlv.value.to_vec());
                }
                0x88 if !tlv.value.is_empty() => {
                    // [8] Short EF ID
                    fcp.short_ef_id = Some(tlv.value[0]);
                }
                0x8A if !tlv.value.is_empty() => {
                    // [10] Lifecycle status integer
                    fcp.lcsi = tlv.value[0];
                }
                0x8B => {
                    // [11] Security attributes referenced
                    fcp.security_attrs = Some(tlv.value.to_vec());
                }
                0xC6 => {
                    // PRIVATE [6] PIN status template DO
                    fcp.pin_status = Some(tlv.value.to_vec());
                }
                0xC7 => {
                    // PRIVATE [7] Link path
                    fcp.link_path = Some(tlv.value.to_vec());
                }
                _ => {
                    // Skip unknown tags for forward compatibility.
                }
            }
        }

        Ok(fcp)
    }

    /// Extract the File ID as a [`Fid`].
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::MissingFileId`] if no file ID is present.
    pub fn parse_fid(&self) -> Result<Fid, ProfileError> {
        let bytes = self.file_id.ok_or(ProfileError::MissingFileId)?;
        let val = u16::from_be_bytes(bytes);
        Ok(Fid::from_raw(val))
    }

    /// Extract the Short File Identifier as an [`Sfi`], if present.
    ///
    /// The SFI is encoded in bits 7-3 of the `shortEFID` byte.
    pub fn parse_sfi(&self) -> Option<Sfi> {
        self.short_ef_id.and_then(|b| {
            let val = b >> 3;
            if (1..=30).contains(&val) {
                Some(Sfi::from_raw(val))
            } else {
                None
            }
        })
    }

    /// Determine the EF structure from the file descriptor bytes.
    ///
    /// The file descriptor byte (first byte) encodes:
    /// - `0x41` = transparent
    /// - `0x42` = linear fixed
    /// - `0x46` = cyclic
    /// - `0x39` = BER-TLV
    ///
    /// Per [ETSI TS 102 221 V18.3.0](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf), the file descriptor is:
    /// - byte 0: file descriptor byte (structure + shareable)
    /// - byte 1: data coding byte
    /// - For record-based, optionally 2-3 more bytes:
    ///   bytes 2-3: record length (u16 BE), byte 4: number of records
    ///
    /// When the file descriptor is only 4 bytes (no `num_records`), pass
    /// `total_file_size` to compute `num_records` = `file_size` / `record_size`.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::FileDescriptorTooShort`] if the file descriptor
    /// is missing or too short, or [`ProfileError::UnknownFileStructure`] for
    /// unrecognized file descriptor bytes.
    pub fn parse_structure(
        &self,
        total_file_size: Option<usize>,
    ) -> Result<EfStructure, ProfileError> {
        let fd = self
            .file_descriptor
            .as_ref()
            .ok_or(ProfileError::FileDescriptorTooShort)?;
        if fd.is_empty() {
            return Err(ProfileError::FileDescriptorTooShort);
        }

        let fdb = fd[0];
        // Bits 2-0 of the file descriptor byte encode the structure:
        // 001 = transparent, 010 = linear fixed, 110 = cyclic
        // Bit 3: 1 = BER-TLV (with bits 2-0 = 001)
        // The full byte also includes bit 6 (shareable) and bit 7 (not EF).
        //
        // Common values for EFs:
        // 0x41 = shareable transparent (0x40 | 0x01)
        // 0x42 = shareable linear fixed (0x40 | 0x02)
        // 0x46 = shareable cyclic (0x40 | 0x06)
        // 0x39 = BER-TLV structure (0x38 | 0x01)
        // Non-shareable variants: 0x01, 0x02, 0x06
        let structure_bits = fdb & 0x07;
        let ber_tlv_bit = fdb & 0x38;

        if ber_tlv_bit == 0x38 {
            return Ok(EfStructure::BerTlv);
        }

        match structure_bits {
            0x01 => Ok(EfStructure::Transparent),
            0x02 => {
                let (record_size, num_records) = Self::parse_record_params(fd, total_file_size)?;
                Ok(EfStructure::LinearFixed {
                    record_size,
                    num_records,
                })
            }
            0x06 => {
                let (record_size, num_records) = Self::parse_record_params(fd, total_file_size)?;
                Ok(EfStructure::Cyclic {
                    record_size,
                    num_records,
                })
            }
            _ => Err(ProfileError::UnknownFileStructure(fdb)),
        }
    }

    /// Parse record parameters from file descriptor bytes.
    ///
    /// For record-based EFs, the file descriptor has 4 or 5 bytes:
    /// - byte 0: file descriptor byte
    /// - byte 1: data coding byte
    /// - bytes 2-3: record length (big-endian u16)
    /// - byte 4: number of records (optional -- if absent, computed from
    ///   `total_file_size / record_size`)
    fn parse_record_params(
        fd: &[u8],
        total_file_size: Option<usize>,
    ) -> Result<(u8, u8), ProfileError> {
        if fd.len() < 4 {
            return Err(ProfileError::FileDescriptorTooShort);
        }
        let record_size = u16::from_be_bytes([fd[2], fd[3]]);

        let record_size_u8 =
            u8::try_from(record_size).map_err(|_| ProfileError::UnknownFileStructure(fd[0]))?;

        let num_records = if fd.len() >= 5 {
            fd[4]
        } else if let Some(file_size) = total_file_size {
            if record_size_u8 == 0 {
                return Err(ProfileError::FileDescriptorTooShort);
            }
            let n = file_size / record_size_u8 as usize;
            u8::try_from(n).map_err(|_| ProfileError::UnknownFileStructure(fd[0]))?
        } else {
            // No num_records in fd and no file size available.
            return Err(ProfileError::FileDescriptorTooShort);
        };

        Ok((record_size_u8, num_records))
    }

    /// Get the raw file size from the FCP's `ef_file_size` field (tag 0x80),
    /// if present.
    pub fn raw_file_size(&self) -> Option<usize> {
        self.ef_file_size
            .as_ref()
            .map(|b| der_util::decode_uint(b) as usize)
    }

    /// Check if this FCP describes a DF (not an EF).
    ///
    /// A DF has file descriptor byte with bit 5 set (0x38) but NOT
    /// in the BER-TLV pattern. Or more precisely, byte 0 has bits
    /// indicating "DF or ADF" rather than EF structure.
    /// Common DF descriptor bytes: 0x78 (DF, shareable).
    pub fn is_df(&self) -> bool {
        self.file_descriptor
            .as_ref()
            .is_some_and(|fd| !fd.is_empty() && (fd[0] & 0x38) == 0x38 && (fd[0] & 0x07) != 0x01)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_transparent_fcp() {
        // Minimal FCP: file descriptor [0x41, 0x21], file ID [0x6F, 0x07],
        // file size [0x09]
        let data = [
            0x82, 0x02, 0x41, 0x21, // file descriptor: transparent
            0x83, 0x02, 0x6F, 0x07, // file ID: 0x6F07
            0x80, 0x01, 0x09, // file size: 9
        ];
        let fcp = Fcp::from_bytes(&data).unwrap();
        assert_eq!(fcp.parse_fid().unwrap(), Fid::from_raw(0x6F07));
        let structure = fcp.parse_structure(None).unwrap();
        assert!(matches!(structure, EfStructure::Transparent));
        assert_eq!(fcp.raw_file_size(), Some(9));
    }

    #[test]
    fn parse_linear_fixed_fcp() {
        // File descriptor: linear fixed, rec_size=30, num_records=2
        let data = [
            0x82, 0x05, 0x42, 0x21, 0x00, 0x1E, 0x02, // LF: 30 bytes x 2 records
            0x83, 0x02, 0x6F, 0x40, // file ID: 0x6F40 (MSISDN)
            0x88, 0x01, 0x28, // SFI: 0x28 >> 3 = 5
        ];
        let fcp = Fcp::from_bytes(&data).unwrap();
        assert_eq!(fcp.parse_fid().unwrap(), Fid::from_raw(0x6F40));
        assert_eq!(fcp.parse_sfi().unwrap(), Sfi::from_raw(5));
        let structure = fcp.parse_structure(None).unwrap();
        assert!(matches!(
            structure,
            EfStructure::LinearFixed {
                record_size: 30,
                num_records: 2
            }
        ));
    }

    #[test]
    fn parse_linear_fixed_4byte_fd_with_file_size() {
        // File descriptor with only 4 bytes (no num_records in fd).
        // num_records = file_size / record_size = 132 / 33 = 4
        let data = [
            0x82, 0x04, 0x42, 0x21, 0x00, 0x21, // LF: record_size=33, no num_records
            0x83, 0x02, 0x2F, 0x00, // file ID: 0x2F00 (EF.DIR)
            0x80, 0x01, 0x84, // file size: 132
        ];
        let fcp = Fcp::from_bytes(&data).unwrap();
        let structure = fcp.parse_structure(Some(132)).unwrap();
        assert!(matches!(
            structure,
            EfStructure::LinearFixed {
                record_size: 33,
                num_records: 4
            }
        ));
    }

    #[test]
    fn parse_cyclic_fcp() {
        // File descriptor: cyclic, rec_size=3, num_records=3
        let data = [
            0x82, 0x05, 0x46, 0x21, 0x00, 0x03, 0x03, // cyclic: 3 bytes x 3 records
            0x83, 0x02, 0x6F, 0x39, // file ID: 0x6F39 (ACM)
        ];
        let fcp = Fcp::from_bytes(&data).unwrap();
        let structure = fcp.parse_structure(None).unwrap();
        assert!(matches!(
            structure,
            EfStructure::Cyclic {
                record_size: 3,
                num_records: 3
            }
        ));
    }

    #[test]
    fn private_tags_parsed() {
        let data = [
            0x82, 0x02, 0x41, 0x21, // file descriptor
            0x83, 0x02, 0x6F, 0x07, // file ID
            0xC6, 0x02, 0x01, 0x02, // PRIVATE [6] PIN status
            0xC7, 0x04, 0x3F, 0x00, 0x7F, 0x20, // PRIVATE [7] link path
        ];
        let fcp = Fcp::from_bytes(&data).unwrap();
        assert_eq!(fcp.pin_status.as_deref(), Some(&[0x01, 0x02][..]));
        assert_eq!(
            fcp.link_path.as_deref(),
            Some(&[0x3F, 0x00, 0x7F, 0x20][..])
        );
    }

    #[test]
    fn default_lcsi_is_activated() {
        let data = [0x82, 0x02, 0x41, 0x21, 0x83, 0x02, 0x6F, 0x07];
        let fcp = Fcp::from_bytes(&data).unwrap();
        assert_eq!(fcp.lcsi, 0x05);
    }
}
