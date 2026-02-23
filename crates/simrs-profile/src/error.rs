//! Profile parsing error types.

use simrs_fs::Fid;

/// Errors from profile parsing and conversion.
#[derive(Debug)]
pub enum ProfileError {
    /// Profile header missing or not the first element.
    MissingHeader,
    /// PE-MF element missing (required).
    MissingMf,
    /// PE-AKAParameter element missing.
    MissingAkaParameter,
    /// FCP missing from a File that requires it.
    MissingFcp,
    /// File descriptor byte indicates unknown structure.
    UnknownFileStructure(u8),
    /// FID field missing from FCP.
    MissingFileId,
    /// File fill data exceeds file size.
    FillOverflow {
        /// File ID where overflow occurred.
        fid: Fid,
        /// Byte offset of the fill.
        offset: usize,
        /// Length of the fill data.
        len: usize,
    },
    /// Key length invalid.
    InvalidKeyLength,
    /// `OPc` length invalid (expected 16 bytes for Milenage).
    InvalidOpcLength,
    /// `TOPc` length invalid (expected 32 bytes for TUAK).
    InvalidTopcLength,
    /// Algorithm ID not recognized.
    UnsupportedAlgorithm(u8),
    /// Mapping parameter format not supported.
    MappingParameterNotSupported,
    /// File-based PIN reference not supported.
    FileBasedPinNotSupported,
    /// `GenericFileManagement`: target path not found.
    PathNotFound(Vec<u8>),
    /// Record-based EF data length mismatch.
    DataLengthMismatch {
        /// File ID with the mismatch.
        fid: Fid,
        /// Expected data length.
        expected: usize,
        /// Actual data length.
        actual: usize,
    },
    /// Truncated DER data.
    Truncated,
    /// Invalid tag encountered.
    InvalidTag(u8),
    /// File descriptor too short.
    FileDescriptorTooShort,
    /// A required file field is absent from a structurally complete PE.
    MissingRequiredFile(u8),
}

impl core::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingHeader => write!(f, "profile header missing"),
            Self::MissingMf => write!(f, "PE-MF element missing"),
            Self::MissingAkaParameter => write!(f, "PE-AKAParameter missing"),
            Self::MissingFcp => write!(f, "FCP missing from file"),
            Self::UnknownFileStructure(b) => {
                write!(f, "unknown file structure byte: 0x{b:02X}")
            }
            Self::MissingFileId => write!(f, "file ID missing from FCP"),
            Self::FillOverflow { fid, offset, len } => {
                write!(
                    f,
                    "fill overflow at FID 0x{:04X}: offset {offset} + len {len}",
                    fid.value()
                )
            }
            Self::InvalidKeyLength => write!(f, "invalid key length"),
            Self::InvalidOpcLength => write!(f, "invalid OPc length"),
            Self::InvalidTopcLength => write!(f, "invalid TOPc length"),
            Self::UnsupportedAlgorithm(id) => {
                write!(f, "unsupported algorithm ID: {id}")
            }
            Self::MappingParameterNotSupported => {
                write!(f, "mapping parameter format not supported")
            }
            Self::FileBasedPinNotSupported => {
                write!(f, "file-based PIN reference not supported")
            }
            Self::PathNotFound(p) => write!(f, "path not found: {p:02X?}"),
            Self::DataLengthMismatch {
                fid,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "data length mismatch at FID 0x{:04X}: expected {expected}, got {actual}",
                    fid.value()
                )
            }
            Self::Truncated => write!(f, "truncated DER data"),
            Self::InvalidTag(t) => write!(f, "invalid tag: 0x{t:02X}"),
            Self::FileDescriptorTooShort => write!(f, "file descriptor too short"),
            Self::MissingRequiredFile(tag) => {
                write!(f, "required file at tag [{tag}] is absent from PE")
            }
        }
    }
}

impl std::error::Error for ProfileError {}
