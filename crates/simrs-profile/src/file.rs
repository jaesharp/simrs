//! TCA Profile Package `File` type parsing.
//!
//! A `File` in the TCA spec is `SEQUENCE OF CHOICE { doNotCreate, fileDescriptor,
//! fillFileOffset, fillFileContent }`. With AUTOMATIC TAGS these become context-
//! specific tags \[0\] through \[3\].

use crate::der_util;
use crate::error::ProfileError;
use crate::fcp::Fcp;

/// A parsed File definition from a TCA Profile Element.
///
/// Contains the FCP (file control parameters) and fill data directives
/// for populating the file content.
#[derive(Clone, Debug)]
pub struct File {
    /// If true, this file should not be created (PE says "doNotCreate").
    pub do_not_create: bool,
    /// File Control Parameters describing the file structure.
    pub fcp: Option<Fcp>,
    /// Ordered (offset, content) pairs for sparse data fill.
    /// Offsets are cumulative (each fillFileOffset advances a cursor).
    pub fills: Vec<(usize, Vec<u8>)>,
}

impl File {
    /// Parse a `File` from the value bytes of a SEQUENCE OF CHOICE.
    ///
    /// The TCA encoding uses AUTOMATIC TAGS within the File CHOICE:
    /// - `[0]` NULL = doNotCreate
    /// - `[1]` CONSTRUCTED = fileDescriptor (Fcp inside a SEQUENCE)
    /// - `[2]` PRIMITIVE = fillFileOffset (INTEGER, context \[2\])
    /// - `[3]` PRIMITIVE = fillFileContent (OCTET STRING, context \[3\])
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any TLV is malformed or the FCP
    /// cannot be parsed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let mut file = Self {
            do_not_create: false,
            fcp: None,
            fills: Vec::new(),
        };

        let mut cursor: usize = 0; // current fill offset

        for tlv_result in der_util::iter_tlvs(data) {
            let tlv = tlv_result?;
            match tlv.tag {
                // [0] PRIMITIVE: doNotCreate NULL
                0x80 => {
                    file.do_not_create = true;
                }
                // [1] CONSTRUCTED: fileDescriptor (Fcp)
                0xA1 => {
                    file.fcp = Some(Fcp::from_bytes(tlv.value)?);
                }
                // [2] PRIMITIVE: fillFileOffset (INTEGER)
                0x82 => {
                    let offset = der_util::decode_uint(tlv.value) as usize;
                    cursor += offset;
                }
                // [3] PRIMITIVE: fillFileContent (OCTET STRING)
                0x83 => {
                    file.fills.push((cursor, tlv.value.to_vec()));
                    cursor += tlv.value.len();
                }
                _ => {
                    // Skip unknown tags for forward compatibility.
                }
            }
        }

        Ok(file)
    }

    /// Build the complete file data buffer.
    ///
    /// Starts with an all-0xFF buffer of `total_size` bytes, then applies
    /// fill directives sequentially. Returns the populated buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::FillOverflow`] if fill data extends
    /// beyond the allocated buffer size.
    pub fn build_data(&self, total_size: usize) -> Result<Vec<u8>, ProfileError> {
        let mut data = vec![0xFF; total_size];

        for &(offset, ref content) in &self.fills {
            let end = offset + content.len();
            if end > data.len() {
                let fid = self
                    .fcp
                    .as_ref()
                    .and_then(|f| f.parse_fid().ok())
                    .unwrap_or(simrs_fs::Fid::from_raw(0xFFFF));
                return Err(ProfileError::FillOverflow {
                    fid,
                    offset,
                    len: content.len(),
                });
            }
            data[offset..end].copy_from_slice(content);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_do_not_create() {
        // [0] NULL (doNotCreate)
        let data = [0x80, 0x00];
        let file = File::from_bytes(&data).unwrap();
        assert!(file.do_not_create);
        assert!(file.fcp.is_none());
    }

    #[test]
    fn parse_simple_transparent_file() {
        // [1] CONSTRUCTED: FCP with file descriptor + file ID + file size
        // [3] OCTET STRING: fill content
        let mut data = Vec::new();

        // FCP: [1] CONSTRUCTED
        let fcp_inner = [
            0x82, 0x02, 0x41, 0x21, // file descriptor: transparent
            0x83, 0x02, 0x6F, 0x07, // file ID: 0x6F07
            0x80, 0x02, 0x00, 0x09, // file size: 9
        ];
        data.push(0xA1); // tag: context [1] constructed
        #[allow(clippy::cast_possible_truncation)]
        data.push(fcp_inner.len() as u8); // length (known < 256)
        data.extend_from_slice(&fcp_inner);

        // Fill content: 9 bytes of IMSI-like data
        let content = [0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0];
        data.push(0x83); // tag: context [3] primitive
        #[allow(clippy::cast_possible_truncation)]
        data.push(content.len() as u8); // length (known < 256)
        data.extend_from_slice(&content);

        let file = File::from_bytes(&data).unwrap();
        assert!(!file.do_not_create);
        assert!(file.fcp.is_some());
        assert_eq!(file.fills.len(), 1);
        assert_eq!(file.fills[0].0, 0); // offset 0
        assert_eq!(file.fills[0].1, content);

        // Build data
        let built = file.build_data(9).unwrap();
        assert_eq!(built, content);
    }

    #[test]
    fn parse_sparse_fill() {
        // fillFileOffset(3) + fillFileContent([AA, BB]) + fillFileContent([CC])
        let data = [
            0x82, 0x01, 0x03, // fillFileOffset: 3
            0x83, 0x02, 0xAA, 0xBB, // fillFileContent: [AA, BB] at offset 3
            0x83, 0x01, 0xCC, // fillFileContent: [CC] at offset 5
        ];
        let file = File::from_bytes(&data).unwrap();
        assert_eq!(file.fills.len(), 2);
        assert_eq!(file.fills[0].0, 3); // offset 3
        assert_eq!(file.fills[1].0, 5); // offset 3 + 2 = 5

        let built = file.build_data(8).unwrap();
        assert_eq!(built, [0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC, 0xFF, 0xFF]);
    }

    #[test]
    fn fill_overflow_detected() {
        let data = [
            0x83, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, // 5 bytes of content
        ];
        let file = File::from_bytes(&data).unwrap();
        assert!(file.build_data(3).is_err()); // only 3 bytes available
    }
}
