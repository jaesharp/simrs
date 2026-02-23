//! PE-GenericFileManagement (tag 1) parser.

use crate::der_util;
use crate::error::ProfileError;
use crate::file::File;

/// PE-GenericFileManagement: path-based file creation (`ProfileElement` tag 1).
///
/// Contains a sequence of file management commands. Each command navigates
/// to a target location by file path, then creates or modifies a file there.
#[derive(Clone, Debug)]
pub struct PeGfm {
    /// File management commands.
    pub commands: Vec<GfmCommand>,
}

/// A single file management command from PE-GFM.
///
/// Each command targets a location in the filesystem tree (via `path`)
/// and provides file creation/modification data.
#[derive(Clone, Debug)]
pub struct GfmCommand {
    /// Target path: 0, 2, 4, 6, or 8 bytes of big-endian FID pairs.
    pub path: Vec<u8>,
    /// File to create/modify at the target location.
    pub file: File,
}

impl PeGfm {
    /// Parse from the PE value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed.
    ///
    /// PE-GenericFileManagement SEQUENCE:
    /// - `[0]` `PEHeader`
    /// - `[1]` SEQUENCE OF `FileManagement`
    ///
    /// Each `FileManagement` is a SEQUENCE OF CHOICE:
    /// - `[0]` `filePath` (OCTET STRING) -- sets the target directory
    /// - `[APPLICATION 2]` (0x62) `createFCP` (`Fcp`) -- creates a file
    /// - `[2]` `fillFileOffset` (`UInt16`) -- advances the fill cursor
    /// - `[1]` `fillFileContent` (OCTET STRING) -- fills data
    ///
    /// A single `FileManagement` may contain multiple `filePath`/`createFCP`
    /// entries. Each `createFCP` emits a separate [`GfmCommand`] carrying
    /// the most recent `filePath` and any fills that follow it.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let inner = der_util::peel_optional_sequence(data)?;

        let tlvs: Vec<_> = der_util::iter_tlvs(inner)
            .collect::<Result<_, _>>()?;

        // Tag [1] is the SEQUENCE OF FileManagement.
        let cmd_seq_tlv = tlvs.iter()
            .find(|t| t.number == 1 && t.class == 2)
            .ok_or(ProfileError::MissingRequiredFile(1))?;

        let mut commands = Vec::new();

        // Each child of the SEQUENCE OF is a FileManagement (SEQUENCE OF CHOICE).
        for fm_result in der_util::iter_tlvs(cmd_seq_tlv.value) {
            let fm_tlv = fm_result?;
            if fm_tlv.tag != 0x30 {
                continue;
            }

            Self::parse_file_management(fm_tlv.value, &mut commands)?;
        }

        Ok(Self { commands })
    }

    /// Parse a single `FileManagement` SEQUENCE OF CHOICE into commands.
    ///
    /// Emits one [`GfmCommand`] per `createFCP` (0x62) encountered. The
    /// most recent `filePath` (0x80) is carried forward. Fill data
    /// (`fillFileOffset` 0x82, `fillFileContent` 0x81) is attached to the
    /// most recently created file.
    fn parse_file_management(
        data: &[u8],
        commands: &mut Vec<GfmCommand>,
    ) -> Result<(), ProfileError> {
        let mut path = Vec::new();
        let mut pending_fcp: Option<crate::fcp::Fcp> = None;
        let mut fills: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut cursor: usize = 0;

        for item_result in der_util::iter_tlvs(data) {
            let item = item_result?;
            match item.tag {
                // [0] filePath -- sets current target directory.
                0x80 => {
                    // Flush any pending command before changing path.
                    if let Some(fcp) = pending_fcp.take() {
                        commands.push(GfmCommand {
                            path: path.clone(),
                            file: File {
                                do_not_create: false,
                                fcp: Some(fcp),
                                fills: core::mem::take(&mut fills),
                            },
                        });
                        cursor = 0;
                    }
                    path = item.value.to_vec();
                }
                // [APPLICATION 2] CONSTRUCTED: createFCP -- creates a file.
                0x62 => {
                    // Flush any pending command before starting a new one.
                    if let Some(fcp) = pending_fcp.take() {
                        commands.push(GfmCommand {
                            path: path.clone(),
                            file: File {
                                do_not_create: false,
                                fcp: Some(fcp),
                                fills: core::mem::take(&mut fills),
                            },
                        });
                        cursor = 0;
                    }
                    pending_fcp = Some(crate::fcp::Fcp::from_bytes(item.value)?);
                }
                // [2] fillFileOffset
                0x82 => {
                    let offset = der_util::decode_uint(item.value) as usize;
                    cursor += offset;
                }
                // [1] fillFileContent
                0x81 => {
                    fills.push((cursor, item.value.to_vec()));
                    cursor += item.value.len();
                }
                _ => {}
            }
        }

        // Flush the last pending command.
        if let Some(fcp) = pending_fcp {
            commands.push(GfmCommand {
                path,
                file: File {
                    do_not_create: false,
                    fcp: Some(fcp),
                    fills,
                },
            });
        }

        Ok(())
    }
}
