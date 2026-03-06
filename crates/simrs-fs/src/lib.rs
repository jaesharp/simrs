//! ICC filesystem model: MF, DF, ADF, and EF nodes.
//!
//! Provides a hierarchical, `const`-static filesystem tree matching the UICC
//! file system per ETSI TS 102 221. Elementary files (EFs) come in three
//! structures: transparent (binary), linear fixed (records), and cyclic.
//! The [`SelectionCtx`] tracks the current MF, DF, ADF, and EF across
//! SELECT operations. The [`FsData`] store holds mutable copies of all EF
//! data for read-write operations.
//!
//! # Filesystem Tree
//!
//! The tree is defined as nested `const`/`static` items -- no runtime
//! allocation. EF content templates are `&'static [u8]`, supplied by the
//! consuming crate (e.g. `simrs-gsm`, `simrs-usim`). At runtime, [`FsData`]
//! copies these templates into a mutable buffer for read-write access.
//!
//! ```text
//! MF (3F00)
//! +-- EF.ICCID (2FE2) transparent
//! +-- EF.DIR (2F00) linear-fixed
//! +-- DF.GSM (7F20)
//! |   +-- EF.IMSI (6F07) transparent
//! +-- ADF.USIM (selected by AID)
//!     +-- EF.IMSI (6F07) transparent
//! ```
//!
//! # Selection Semantics
//!
//! | Method | P1 | Behaviour |
//! |--------|----|-----------|
//! | By FID | 0x00 | Search current DF's children; 0x3F00 = MF, 0x7FFF = reselect ADF |
//! | By AID | 0x04 | Match AID prefix against ADF table |
//!
//! # Standards
//! - [ETSI TS 102 221 V18.0.0 clause 8](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A259%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D) -- File system structure
//! - [ETSI TS 102 221 V18.0.0 clause 11.1.1](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A329%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C371%5D) -- SELECT
//! - [3GPP TS 31.102 V17.5.0 clause 4](https://www.etsi.org/deliver/etsi_ts/131100_131199/131102/17.05.00_60/ts_131102v170500p.pdf#%5B%7B%22num%22%3A48%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C729%5D) -- USIM file system
//! - [GSM 11.11 v4.21.1 (ETSI TS 151 011 V4.15.0) clause 10](https://www.etsi.org/deliver/etsi_ts/151000_151099/151011/04.15.00_60/ts_151011v041500p.pdf#%5B%7B%22num%22%3A105%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C727%5D) -- SIM file system
//!
//! # `no_std`
//! This crate is `no_std`. The filesystem can be defined as `const` statics.
//!
//! # Example
//!
//! ```
//! use simrs_fs::{DfDef, EfDef, Fid, FileRef, SelectionCtx, FsError, Sfi};
//!
//! static EF_ICCID: EfDef = EfDef::transparent(
//!     Fid::new(0x2FE2),
//!     Some(Sfi::new(2)),
//!     &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
//! );
//!
//! static MF: DfDef = DfDef {
//!     fid: Fid::MF,
//!     children: &[FileRef::Ef(&EF_ICCID)],
//! };
//!
//! let mut ctx = SelectionCtx::new(&MF);
//! ctx.select_by_fid(Fid::new(0x2FE2)).unwrap();
//! let data = ctx.read_binary(0, 10).unwrap();
//! assert_eq!(data, &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Two-byte file identifier.
///
/// Per [ETSI TS 102 221 V18.0.0 clause 8.3](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A263%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C489%5D).
/// Wraps a `u16` to prevent mixing file identifiers with arbitrary integers.
///
/// # Well-known FIDs
///
/// - [`Fid::MF`] (`0x3F00`): Master File
/// - [`Fid::CUR_ADF`] (`0x7FFF`): Reselect current ADF
/// - [`Fid::NONE`] (`0xFFFF`): Sentinel for "no selection" (used in snapshots)
///
/// ```
/// use simrs_fs::Fid;
/// assert_eq!(Fid::MF.value(), 0x3F00);
/// assert_ne!(Fid::MF, Fid::CUR_ADF);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fid(u16);

impl Fid {
    /// Master File (`0x3F00`).
    pub const MF: Self = Self(0x3F00);
    /// Reselect current ADF (`0x7FFF`).
    pub const CUR_ADF: Self = Self(0x7FFF);
    /// Sentinel: no file selected (`0xFFFF`).
    pub const NONE: Self = Self(0xFFFF);

    /// Create a FID with validation.
    ///
    /// # Panics
    ///
    /// Panics (at compile time for const contexts) if `val` is 0.
    ///
    /// ```
    /// use simrs_fs::Fid;
    /// let fid = Fid::new(0x6F07);
    /// assert_eq!(fid.value(), 0x6F07);
    /// ```
    ///
    /// ```compile_fail,E0080
    /// use simrs_fs::Fid;
    /// const BAD: Fid = Fid::new(0); // panics: FID must not be zero
    /// ```
    pub const fn new(val: u16) -> Self {
        assert!(val != 0, "FID must not be zero");
        Self(val)
    }

    /// Construct a FID from a raw value without validation.
    ///
    /// Use this for APDU parsing where any `u16` value must be accepted.
    pub const fn from_raw(val: u16) -> Self {
        Self(val)
    }

    /// Return the raw `u16` value.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Big-endian byte representation (for APDU encoding).
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Little-endian byte representation (for snapshot serialization).
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    /// Construct from little-endian bytes.
    pub const fn from_le_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_le_bytes(bytes))
    }

    /// Construct from big-endian bytes.
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }
}

impl core::fmt::Display for Fid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04X}", self.value())
    }
}

impl core::fmt::UpperHex for Fid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::UpperHex::fmt(&self.value(), f)
    }
}

/// Short File Identifier (SFI).
///
/// Per [ETSI TS 102 221 V18.0.0 clause 8.4.3](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A269%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D).
/// A 5-bit identifier (1--30) enabling direct file access without SELECT.
///
/// ```
/// use simrs_fs::Sfi;
/// let sfi = Sfi::new(7);
/// assert_eq!(sfi.value(), 7);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sfi(u8);

impl Sfi {
    /// Create an SFI with compile-time validation.
    ///
    /// # Panics
    ///
    /// Panics (at compile time for const contexts) if `val` is not in 1..=30.
    ///
    /// ```
    /// use simrs_fs::Sfi;
    /// let sfi = Sfi::new(7);
    /// assert_eq!(sfi.value(), 7);
    /// ```
    ///
    /// ```compile_fail,E0080
    /// use simrs_fs::Sfi;
    /// const BAD: Sfi = Sfi::new(31); // panics: out of range
    /// ```
    ///
    /// ```compile_fail,E0080
    /// use simrs_fs::Sfi;
    /// const BAD: Sfi = Sfi::new(0); // panics: out of range
    /// ```
    pub const fn new(val: u8) -> Self {
        assert!(val >= 1 && val <= 30, "SFI must be in range 1..=30");
        Self(val)
    }

    /// Construct an SFI from a raw value without validation.
    ///
    /// Use this for APDU parsing where any `u8` value must be accepted.
    pub const fn from_raw(val: u8) -> Self {
        Self(val)
    }

    /// Return the raw `u8` value.
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for Sfi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SFI({})", self.value())
    }
}

/// Elementary file internal structure.
///
/// Per [ETSI TS 102 221 V18.0.0 clause 8.2.2](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A261%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C701%5D).
///
/// # Example
///
/// ```
/// use simrs_fs::EfStructure;
/// let s = EfStructure::LinearFixed { record_size: 14, num_records: 5 };
/// assert!(matches!(s, EfStructure::LinearFixed { .. }));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfStructure {
    /// Binary blob, accessed by offset + length.
    Transparent,
    /// Fixed-size records, accessed by record number (1-based).
    LinearFixed {
        /// Bytes per record.
        record_size: u8,
        /// Total number of records.
        num_records: u8,
    },
    /// Fixed-size cyclic records (newest first), accessed by record number.
    Cyclic {
        /// Bytes per record.
        record_size: u8,
        /// Total number of records.
        num_records: u8,
    },
    /// BER-TLV structured EF.
    ///
    /// Per [ETSI TS 102 221 V18.0.0 clause 8.2.2.4](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A263%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C549%5D).
    /// Data is accessed by tag rather than byte offset or record number.
    /// For basic filesystem operations (read/write binary), this behaves
    /// like a transparent EF over the raw data buffer.
    BerTlv,
}

impl EfStructure {
    /// True for `Transparent` and `BerTlv` (binary-accessible via READ BINARY).
    pub const fn is_binary_accessible(&self) -> bool {
        matches!(self, Self::Transparent | Self::BerTlv)
    }

    /// True for `LinearFixed` and `Cyclic` (record-accessible via READ RECORD).
    pub const fn is_record_based(&self) -> bool {
        matches!(self, Self::LinearFixed { .. } | Self::Cyclic { .. })
    }

    /// Returns (`record_size`, `num_records`) for record-based EFs, `None` otherwise.
    pub const fn record_params(&self) -> Option<(u8, u8)> {
        match self {
            Self::LinearFixed { record_size, num_records }
            | Self::Cyclic { record_size, num_records } => Some((*record_size, *num_records)),
            Self::Transparent | Self::BerTlv => None,
        }
    }

    /// True only for Cyclic.
    pub const fn is_cyclic(&self) -> bool {
        matches!(self, Self::Cyclic { .. })
    }

    /// Record size for record-based, 0 for transparent/BER-TLV.
    pub const fn record_size(&self) -> u8 {
        match self {
            Self::LinearFixed { record_size, .. }
            | Self::Cyclic { record_size, .. } => *record_size,
            Self::Transparent | Self::BerTlv => 0,
        }
    }

    /// GSM 11.11 structure byte (0x00 transparent, 0x01 linear-fixed, 0x03 cyclic).
    pub const fn gsm_structure_byte(&self) -> u8 {
        match self {
            Self::Transparent | Self::BerTlv => 0x00,
            Self::LinearFixed { .. } => 0x01,
            Self::Cyclic { .. } => 0x03,
        }
    }

    /// GSM 11.11 byte 7 value: 0x01 for cyclic, 0x00 otherwise.
    pub const fn gsm_increase_byte(&self) -> u8 {
        match self {
            Self::Cyclic { .. } => 0x01,
            _ => 0x00,
        }
    }

    /// UICC FCP file descriptor byte per ETSI TS 102 221.
    pub const fn fcp_descriptor_byte(&self) -> u8 {
        match self {
            Self::Transparent => 0x41,
            Self::LinearFixed { .. } => 0x42,
            Self::Cyclic { .. } => 0x46,
            Self::BerTlv => 0x39,
        }
    }

    /// UICC FCP file descriptor TLV payload.
    ///
    /// Returns (`data_array`, length). For transparent/BER-TLV: 2 bytes
    /// (descriptor + data coding). For linear-fixed/cyclic: 5 bytes
    /// (descriptor + data coding + `num_records` + `record_size_be`).
    pub const fn fcp_descriptor_data(&self) -> ([u8; 5], usize) {
        const DATA_CODING_BER_TLV: u8 = 0x21;
        match self {
            Self::Transparent => ([0x41, DATA_CODING_BER_TLV, 0, 0, 0], 2),
            Self::BerTlv => ([0x39, DATA_CODING_BER_TLV, 0, 0, 0], 2),
            Self::LinearFixed { record_size, num_records } => {
                let rs_be = (*record_size as u16).to_be_bytes();
                ([0x42, DATA_CODING_BER_TLV, *num_records, rs_be[0], rs_be[1]], 5)
            }
            Self::Cyclic { record_size, num_records } => {
                let rs_be = (*record_size as u16).to_be_bytes();
                ([0x46, DATA_CODING_BER_TLV, *num_records, rs_be[0], rs_be[1]], 5)
            }
        }
    }

    /// Expected data length for this structure.
    ///
    /// `Transparent`/`BerTlv`: returns `None` (any length valid).
    /// Record-based: returns `Some(record_size * num_records)`.
    pub const fn expected_data_len(&self) -> Option<usize> {
        match self {
            Self::LinearFixed { record_size, num_records }
            | Self::Cyclic { record_size, num_records } => {
                Some(*record_size as usize * *num_records as usize)
            }
            Self::Transparent | Self::BerTlv => None,
        }
    }
}

/// Definition of an Elementary File (EF).
///
/// Data is a `&'static [u8]` slice supplied by the consuming crate.
/// For linear-fixed / cyclic files, the data is a contiguous block of
/// `record_size * num_records` bytes.
///
/// # Example
///
/// ```
/// use simrs_fs::{EfDef, Fid, Sfi};
/// static EF: EfDef = EfDef::transparent(
///     Fid::new(0x6F07),
///     Some(Sfi::new(7)),
///     &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0],
/// );
/// assert_eq!(EF.fid(), Fid::new(0x6F07));
/// ```
#[derive(Debug)]
pub struct EfDef {
    fid: Fid,
    sfi: Option<Sfi>,
    structure: EfStructure,
    data: &'static [u8],
}

impl EfDef {
    /// File identifier.
    pub const fn fid(&self) -> Fid { self.fid }
    /// Short file identifier, if assigned.
    pub const fn sfi(&self) -> Option<Sfi> { self.sfi }
    /// Internal structure (transparent, linear-fixed, cyclic, or BER-TLV).
    pub const fn structure(&self) -> EfStructure { self.structure }
    /// Raw file content template.
    pub const fn data(&self) -> &'static [u8] { self.data }

    /// Create a transparent EF.
    ///
    /// ```
    /// use simrs_fs::{EfDef, Fid};
    /// static EF: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &[0xFF; 10]);
    /// assert_eq!(EF.data().len(), 10);
    /// ```
    pub const fn transparent(fid: Fid, sfi: Option<Sfi>, data: &'static [u8]) -> Self {
        Self { fid, sfi, structure: EfStructure::Transparent, data }
    }

    /// Create a linear-fixed EF with compile-time data length validation.
    ///
    /// # Panics
    ///
    /// Panics at compile time if `data.len() != record_size * num_records`.
    ///
    /// ```
    /// use simrs_fs::{EfDef, Fid};
    /// static EF: EfDef = EfDef::linear_fixed(Fid::new(0x6F3A), None, 14, 2, &[0xFF; 28]);
    /// assert_eq!(EF.data().len(), 28);
    /// ```
    ///
    /// ```compile_fail,E0080
    /// use simrs_fs::{EfDef, Fid};
    /// // Wrong data length: 10 != 14 * 2
    /// static BAD: EfDef = EfDef::linear_fixed(Fid::new(0x6F3A), None, 14, 2, &[0xFF; 10]);
    /// ```
    pub const fn linear_fixed(
        fid: Fid, sfi: Option<Sfi>,
        record_size: u8, num_records: u8,
        data: &'static [u8],
    ) -> Self {
        assert!(
            data.len() == (record_size as usize) * (num_records as usize),
            "linear-fixed data length must equal record_size * num_records"
        );
        Self {
            fid, sfi,
            structure: EfStructure::LinearFixed { record_size, num_records },
            data,
        }
    }

    /// Create a cyclic EF with compile-time data length validation.
    ///
    /// # Panics
    ///
    /// Panics at compile time if `data.len() != record_size * num_records`.
    ///
    /// ```
    /// use simrs_fs::{EfDef, Fid};
    /// static EF: EfDef = EfDef::cyclic(Fid::new(0x6F39), None, 3, 3, &[0xFF; 9]);
    /// assert_eq!(EF.data().len(), 9);
    /// ```
    pub const fn cyclic(
        fid: Fid, sfi: Option<Sfi>,
        record_size: u8, num_records: u8,
        data: &'static [u8],
    ) -> Self {
        assert!(
            data.len() == (record_size as usize) * (num_records as usize),
            "cyclic data length must equal record_size * num_records"
        );
        Self {
            fid, sfi,
            structure: EfStructure::Cyclic { record_size, num_records },
            data,
        }
    }

    /// Create a BER-TLV structured EF.
    ///
    /// ```
    /// use simrs_fs::{EfDef, Fid};
    /// static EF: EfDef = EfDef::ber_tlv(Fid::new(0x6F42), None, &[0x00; 8]);
    /// assert_eq!(EF.data().len(), 8);
    /// ```
    pub const fn ber_tlv(fid: Fid, sfi: Option<Sfi>, data: &'static [u8]) -> Self {
        Self { fid, sfi, structure: EfStructure::BerTlv, data }
    }
}

/// Definition of a Dedicated File (DF) or Master File (MF).
///
/// Children are referenced by `&'static` pointers, enabling fully
/// `const`-static filesystem trees.
///
/// # Example
///
/// ```
/// use simrs_fs::{DfDef, EfDef, Fid, FileRef};
/// static EF: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &[0xFF; 10]);
/// static DF: DfDef = DfDef {
///     fid: Fid::new(0x7F20),
///     children: &[FileRef::Ef(&EF)],
/// };
/// assert_eq!(DF.fid, Fid::new(0x7F20));
/// assert_eq!(DF.children.len(), 1);
/// ```
#[derive(Debug)]
pub struct DfDef {
    /// File identifier (0x3F00 for MF, 0x7Fxx for DF).
    pub fid: Fid,
    /// Immediate children (EFs and sub-DFs).
    pub children: &'static [FileRef],
}

/// A child entry in a DF's children list.
///
/// # Example
///
/// ```
/// use simrs_fs::{FileRef, EfDef, DfDef, Fid};
/// static EF: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &[0xFF; 10]);
/// let r = FileRef::Ef(&EF);
/// assert!(matches!(r, FileRef::Ef(_)));
/// ```
#[derive(Debug)]
pub enum FileRef {
    /// Elementary file.
    Ef(&'static EfDef),
    /// Dedicated file (sub-directory).
    Df(&'static DfDef),
}

/// An Application Dedicated File (ADF) slot, mapping an AID to a DF tree.
///
/// # Example
///
/// ```
/// use simrs_fs::{AdfSlot, DfDef, Fid};
/// static ADF_ROOT: DfDef = DfDef { fid: Fid::new(0xFF01), children: &[] };
/// static USIM: AdfSlot = AdfSlot {
///     aid: &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
///     root: &ADF_ROOT,
/// };
/// assert_eq!(USIM.aid.len(), 7);
/// ```
#[derive(Debug)]
pub struct AdfSlot {
    /// Application Identifier (RID + PIX, 5--16 bytes).
    pub aid: &'static [u8],
    /// Root DF of this application.
    pub root: &'static DfDef,
}

/// Result of a SELECT operation.
#[derive(Clone, Copy)]
pub enum SelectedFile {
    /// A DF or MF was selected.
    Df(&'static DfDef),
    /// An EF was selected.
    Ef(&'static EfDef),
}

impl SelectedFile {
    /// File identifier of the selected file.
    pub const fn fid(&self) -> Fid {
        match self {
            Self::Df(df) => df.fid,
            Self::Ef(ef) => ef.fid,
        }
    }
}

impl PartialEq for SelectedFile {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Df(a), Self::Df(b)) => core::ptr::eq(*a, *b),
            (Self::Ef(a), Self::Ef(b)) => core::ptr::eq(*a, *b),
            _ => false,
        }
    }
}

impl Eq for SelectedFile {}

impl core::fmt::Debug for SelectedFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Df(df) => write!(f, "SelectedFile::Df(0x{:04X})", df.fid),
            Self::Ef(ef) => write!(f, "SelectedFile::Ef(0x{:04X})", ef.fid),
        }
    }
}

/// Filesystem error.
///
/// # Example
///
/// ```
/// use simrs_fs::FsError;
/// let e = FsError::FileNotFound;
/// assert_eq!(e, FsError::FileNotFound);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    /// No file with the given FID or AID was found.
    FileNotFound,
    /// Operation requires a selected EF, but none is selected.
    NoEfSelected,
    /// READ BINARY on a non-transparent EF.
    NotTransparent,
    /// READ RECORD on a transparent EF.
    NotRecordBased,
    /// Record number is 0 or exceeds the number of records.
    RecordOutOfRange,
    /// Offset + length exceeds the file size.
    OffsetOutOfRange,
    /// [`FsData`] buffer capacity exhausted during initialization.
    StoreFull,
    /// More than `MAX_EFS` elementary files in the filesystem tree.
    TooManyFiles,
    /// Write data does not fit: record size mismatch (UPDATE RECORD),
    /// value exceeds record size (INCREASE), or data beyond EF boundary.
    DataTooLarge,
    /// Path data is malformed (e.g. odd number of bytes).
    InvalidPath,
    /// INCREASE would overflow: the sum exceeds the maximum representable
    /// value for the record size.
    IncreaseOverflow,
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FileNotFound => f.write_str("file not found"),
            Self::NoEfSelected => f.write_str("no EF selected"),
            Self::NotTransparent => f.write_str("not a transparent EF"),
            Self::NotRecordBased => f.write_str("not a record-based EF"),
            Self::RecordOutOfRange => f.write_str("record out of range"),
            Self::OffsetOutOfRange => f.write_str("offset out of range"),
            Self::StoreFull => f.write_str("data store full"),
            Self::TooManyFiles => f.write_str("too many files"),
            Self::DataTooLarge => f.write_str("data too large"),
            Self::InvalidPath => f.write_str("invalid path"),
            Self::IncreaseOverflow => f.write_str("increase overflow: max value reached"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FsError {}

// ---------------------------------------------------------------------------
// FsData -- mutable file content store
// ---------------------------------------------------------------------------

/// Internal entry mapping an EF definition to its data region in the buffer.
#[derive(Clone, Copy)]
struct FsEntry {
    /// Reference to the static EF definition (used for identity-based lookup).
    ef: Option<&'static EfDef>,
    /// Byte offset into `FsData::buf` where this EF's data starts.
    offset: u16,
    /// Total length of this EF's data in bytes.
    len: u16,
}

/// Assert that all file identifiers in a slice are pairwise distinct.
///
/// Place this as a `const _: () = assert_fids_unique(&[...]);` assertion
/// adjacent to each DF definition to catch duplicate FIDs at compile time.
///
/// # Panics
///
/// Panics at compile time if any two values in `fids` are equal.
///
/// ```
/// use simrs_fs::assert_fids_unique;
/// const _: () = assert_fids_unique(&[0x6F07, 0x6FAD, 0x6F38]);
/// ```
///
/// ```compile_fail,E0080
/// use simrs_fs::assert_fids_unique;
/// const _: () = assert_fids_unique(&[0x6F07, 0x6FAD, 0x6F07]); // duplicate!
/// ```
pub const fn assert_fids_unique(fids: &[u16]) {
    let mut i = 0;
    while i < fids.len() {
        let mut j = i + 1;
        while j < fids.len() {
            assert!(fids[i] != fids[j], "duplicate FID in DF children");
            j += 1;
        }
        i += 1;
    }
}

/// Mutable file content store for read-write SIM filesystem operations.
///
/// Holds runtime-mutable copies of all EF data from a static filesystem tree.
/// The static [`EfDef::data`] slices serve as initial templates; [`FsData`]
/// copies them into an owned buffer at initialization. All subsequent reads
/// and writes go through this store.
///
/// `CAP` is the total buffer size in bytes (must be at least the sum of all
/// EF data in the tree). `MAX_EFS` is the maximum number of elementary files
/// the store can track -- set this to the number of EFs in your profile to
/// avoid wasting stack space.
///
/// # Standards
///
/// - [ETSI TS 102 221 V18.0.0 clause 11.1.3](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A359%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C413%5D) -- READ BINARY
/// - [ETSI TS 102 221 V18.0.0 clause 11.1.4](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A361%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C620%5D) -- UPDATE BINARY
/// - [ETSI TS 102 221 V18.0.0 clause 11.1.5](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A361%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C255%5D) -- READ RECORD
/// - [ETSI TS 102 221 V18.0.0 clause 11.1.6](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A365%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D) -- UPDATE RECORD
///
/// # Example
///
/// ```
/// use simrs_fs::{FsData, DfDef, EfDef, Fid, FileRef};
///
/// static EF: EfDef = EfDef::transparent(
///     Fid::new(0x2FE2), None, &[0x01, 0x02, 0x03, 0x04],
/// );
/// static MF: DfDef = DfDef { fid: Fid::MF, children: &[FileRef::Ef(&EF)] };
///
/// let mut store = FsData::<16, 2>::new();
/// store.init(&MF).unwrap();
///
/// // Read original data.
/// assert_eq!(store.read_binary(&EF, 0, 4).unwrap(), &[0x01, 0x02, 0x03, 0x04]);
///
/// // Write new data.
/// store.write_binary(&EF, 1, &[0xAA, 0xBB]).unwrap();
/// assert_eq!(store.read_binary(&EF, 0, 4).unwrap(), &[0x01, 0xAA, 0xBB, 0x04]);
/// ```
pub struct FsData<const CAP: usize, const MAX_EFS: usize> {
    buf: [u8; CAP],
    entries: [FsEntry; MAX_EFS],
    count: u8,
}

impl<const CAP: usize, const MAX_EFS: usize> Default for FsData<CAP, MAX_EFS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize, const MAX_EFS: usize> FsData<CAP, MAX_EFS> {
    /// Create a new, empty data store.
    ///
    /// Call [`init`](Self::init) or [`init_with_adfs`](Self::init_with_adfs)
    /// before use.
    pub const fn new() -> Self {
        const EMPTY: FsEntry = FsEntry {
            ef: None,
            offset: 0,
            len: 0,
        };
        Self {
            buf: [0u8; CAP],
            entries: [EMPTY; MAX_EFS],
            count: 0,
        }
    }

    /// Initialize from a static filesystem tree.
    ///
    /// Walks the tree depth-first, copying each EF's template data into the
    /// mutable buffer and recording its location in the index.
    ///
    /// # Errors
    ///
    /// - [`FsError::StoreFull`] if the total EF data exceeds `CAP`.
    /// - [`FsError::TooManyFiles`] if the tree contains more than `MAX_EFS` EFs.
    pub fn init(&mut self, root: &'static DfDef) -> Result<(), FsError> {
        self.count = 0;
        let mut offset: u16 = 0;
        self.walk_tree(root, &mut offset)
    }

    /// Initialize from a static filesystem tree plus ADF table.
    ///
    /// Walks the MF tree first, then each ADF's root tree.
    ///
    /// # Errors
    ///
    /// Same as [`init`](Self::init).
    pub fn init_with_adfs(
        &mut self,
        root: &'static DfDef,
        adfs: &'static [AdfSlot],
    ) -> Result<(), FsError> {
        self.count = 0;
        let mut offset: u16 = 0;
        self.walk_tree(root, &mut offset)?;
        for slot in adfs {
            self.walk_tree(slot.root, &mut offset)?;
        }
        Ok(())
    }

    /// Recursively walk a DF tree, copying EF data into the buffer.
    #[allow(clippy::cast_possible_truncation)]
    fn walk_tree(
        &mut self,
        df: &'static DfDef,
        next_offset: &mut u16,
    ) -> Result<(), FsError> {
        for child in df.children {
            match child {
                FileRef::Ef(ef) => {
                    if self.count as usize >= MAX_EFS {
                        return Err(FsError::TooManyFiles);
                    }
                    let data_len = ef.data.len();
                    let start = *next_offset as usize;
                    let end = start + data_len;
                    if end > CAP {
                        return Err(FsError::StoreFull);
                    }
                    self.buf[start..end].copy_from_slice(ef.data);
                    self.entries[self.count as usize] = FsEntry {
                        ef: Some(ef),
                        offset: *next_offset,
                        len: data_len as u16,
                    };
                    self.count += 1;
                    *next_offset += data_len as u16;
                }
                FileRef::Df(sub) => {
                    self.walk_tree(sub, next_offset)?;
                }
            }
        }
        Ok(())
    }

    /// Look up an entry by EF identity (pointer equality).
    ///
    /// Returns `(offset_in_buf, data_len)` or `None` if the EF is not in
    /// the store.
    fn find_entry(&self, ef: &EfDef) -> Option<(u16, u16)> {
        self.entries[..self.count as usize]
            .iter()
            .find(|e| matches!(e.ef, Some(stored) if core::ptr::eq(stored, ef)))
            .map(|e| (e.offset, e.len))
    }

    /// Total number of bytes used in the buffer.
    pub const fn used(&self) -> usize {
        if self.count == 0 {
            return 0;
        }
        let last = &self.entries[self.count as usize - 1];
        last.offset as usize + last.len as usize
    }

    /// Number of EFs registered in the store.
    pub const fn ef_count(&self) -> u8 {
        self.count
    }

    // -- Read operations ---------------------------------------------------

    /// Read binary data from a transparent EF.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotTransparent`] if the EF is record-based.
    /// - [`FsError::FileNotFound`] if the EF is not in the store.
    /// - [`FsError::OffsetOutOfRange`] if `offset + len` exceeds the file.
    pub fn read_binary(
        &self,
        ef: &EfDef,
        offset: u16,
        len: u16,
    ) -> Result<&[u8], FsError> {
        if !ef.structure.is_binary_accessible() {
            return Err(FsError::NotTransparent);
        }
        let (entry_off, entry_len) = self.find_entry(ef).ok_or(FsError::FileNotFound)?;
        let start = entry_off as usize + offset as usize;
        let end = start + len as usize;
        if end > entry_off as usize + entry_len as usize {
            return Err(FsError::OffsetOutOfRange);
        }
        Ok(&self.buf[start..end])
    }

    /// Read a record from a linear-fixed or cyclic EF.
    ///
    /// Record numbers are **1-based** per ISO/IEC 7816-4.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotRecordBased`] if the EF is transparent.
    /// - [`FsError::FileNotFound`] if the EF is not in the store.
    /// - [`FsError::RecordOutOfRange`] if `num` is 0 or exceeds `num_records`.
    pub fn read_record(&self, ef: &EfDef, num: u8) -> Result<&[u8], FsError> {
        let (record_size, num_records) = ef.structure.record_params().ok_or(FsError::NotRecordBased)?;
        if num == 0 || num > num_records {
            return Err(FsError::RecordOutOfRange);
        }
        let (entry_off, _entry_len) = self.find_entry(ef).ok_or(FsError::FileNotFound)?;
        let idx = (num - 1) as usize;
        let rs = record_size as usize;
        let start = entry_off as usize + idx * rs;
        let end = start + rs;
        Ok(&self.buf[start..end])
    }

    // -- Write operations --------------------------------------------------

    /// Write binary data to a transparent EF.
    ///
    /// Per [ETSI TS 102 221 V18.0.0 clause 11.1.4](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A361%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C620%5D), the data replaces existing content
    /// starting at `offset`.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotTransparent`] if the EF is record-based.
    /// - [`FsError::FileNotFound`] if the EF is not in the store.
    /// - [`FsError::OffsetOutOfRange`] if `offset + data.len()` exceeds the file.
    pub fn write_binary(
        &mut self,
        ef: &EfDef,
        offset: u16,
        data: &[u8],
    ) -> Result<(), FsError> {
        if !ef.structure.is_binary_accessible() {
            return Err(FsError::NotTransparent);
        }
        let (entry_off, entry_len) =
            self.find_entry(ef).ok_or(FsError::FileNotFound)?;
        let start = entry_off as usize + offset as usize;
        let end = start + data.len();
        if end > entry_off as usize + entry_len as usize {
            return Err(FsError::OffsetOutOfRange);
        }
        self.buf[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Write a full record to a linear-fixed or cyclic EF.
    ///
    /// Per [ETSI TS 102 221 V18.0.0 clause 11.1.6](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A365%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C785%5D), the data must be exactly
    /// `record_size` bytes and replaces the entire record.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotRecordBased`] if the EF is transparent.
    /// - [`FsError::FileNotFound`] if the EF is not in the store.
    /// - [`FsError::RecordOutOfRange`] if `num` is 0 or exceeds `num_records`.
    /// - [`FsError::DataTooLarge`] if `data.len()` does not match `record_size`.
    pub fn write_record(
        &mut self,
        ef: &EfDef,
        num: u8,
        data: &[u8],
    ) -> Result<(), FsError> {
        let (record_size, num_records) = ef.structure.record_params().ok_or(FsError::NotRecordBased)?;
        if num == 0 || num > num_records {
            return Err(FsError::RecordOutOfRange);
        }
        if data.len() != record_size as usize {
            return Err(FsError::DataTooLarge);
        }
        let (entry_off, _entry_len) =
            self.find_entry(ef).ok_or(FsError::FileNotFound)?;
        let idx = (num - 1) as usize;
        let rs = record_size as usize;
        let start = entry_off as usize + idx * rs;
        let end = start + rs;
        self.buf[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Increase a cyclic EF's most-recent record value by an addend.
    ///
    /// Per [ETSI TS 102 221 V18.0.0 clause 11.1.8](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A370%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C478%5D), INCREASE reads record 1 (the most
    /// recent in a cyclic EF), interprets it as a big-endian unsigned integer,
    /// adds the supplied big-endian `value`, writes the result back to record 1,
    /// and returns the updated record content.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotRecordBased`] if the EF is not cyclic.
    /// - [`FsError::FileNotFound`] if the EF is not in the store.
    /// - [`FsError::DataTooLarge`] if `value.len()` exceeds the record size.
    pub fn increase(
        &mut self,
        ef: &EfDef,
        value: &[u8],
    ) -> Result<&[u8], FsError> {
        if !ef.structure.is_cyclic() {
            return Err(FsError::NotRecordBased);
        }
        let record_size = ef.structure.record_size();
        let rs = record_size as usize;
        if value.len() > rs {
            return Err(FsError::DataTooLarge);
        }
        let (entry_off, _entry_len) =
            self.find_entry(ef).ok_or(FsError::FileNotFound)?;
        let start = entry_off as usize; // record 1 starts at offset 0
        let end = start + rs;

        // Big-endian addition: add `value` (right-aligned) to the record.
        // We work on a temporary copy so the original record is not modified
        // when overflow is detected.
        let mut tmp = [0u8; 256];
        tmp[..rs].copy_from_slice(&self.buf[start..end]);

        let mut carry: u16 = 0;
        let val_off = rs - value.len();
        let mut i = rs;
        while i > 0 {
            i -= 1;
            let rec_byte = u16::from(tmp[i]);
            let val_byte = if i >= val_off {
                u16::from(value[i - val_off])
            } else {
                0
            };
            let sum = rec_byte + val_byte + carry;
            #[allow(clippy::cast_possible_truncation)] // intentional: keep low byte
            let lo = sum as u8;
            tmp[i] = lo;
            carry = sum >> 8;
        }

        if carry > 0 {
            return Err(FsError::IncreaseOverflow);
        }

        self.buf[start..end].copy_from_slice(&tmp[..rs]);
        Ok(&self.buf[start..end])
    }

    // -- Search operations -------------------------------------------------

    /// Search linear-fixed records for a pattern. Returns matching record numbers.
    ///
    /// A record matches if it contains the pattern as a contiguous substring.
    /// Returns a tuple of (matching record numbers array, count of matches).
    /// At most 16 matching record numbers are returned.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotRecordBased`] if the EF is transparent.
    /// - [`FsError::FileNotFound`] if the EF is not in the store.
    pub fn search_records(&self, ef: &EfDef, pattern: &[u8]) -> Result<([u8; 16], usize), FsError> {
        let (record_size, num_records) = ef.structure.record_params().ok_or(FsError::NotRecordBased)?;
        let (entry_off, _entry_len) = self.find_entry(ef).ok_or(FsError::FileNotFound)?;
        let rs = record_size as usize;
        let mut result = [0u8; 16];
        let mut count = 0usize;

        for rec_num in 1..=num_records {
            let idx = (rec_num - 1) as usize;
            let start = entry_off as usize + idx * rs;
            let rec_data = &self.buf[start..start + rs];
            if contains_pattern(rec_data, pattern) && count < 16 {
                result[count] = rec_num;
                count += 1;
            }
        }
        Ok((result, count))
    }

    // -- Snapshot -----------------------------------------------------------

    /// Snapshot buffer size: the entire mutable data region.
    ///
    /// Only the data buffer is serialized. Entry metadata (EF pointers and
    /// offsets) is reconstructed from the static tree during
    /// [`init`](Self::init) / [`init_with_adfs`](Self::init_with_adfs).
    pub const SNAPSHOT_SIZE: usize = CAP;

    /// Serialize the mutable data into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, out: &mut [u8]) -> usize {
        if out.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        out[..CAP].copy_from_slice(&self.buf);
        CAP
    }

    /// Restore the mutable data from `buf`.
    ///
    /// The entry index must already be initialized via [`init`](Self::init)
    /// or [`init_with_adfs`](Self::init_with_adfs) before calling this method.
    ///
    /// Returns `true` on success.
    #[must_use]
    pub fn restore_state(&mut self, data: &[u8]) -> bool {
        if data.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        self.buf.copy_from_slice(&data[..CAP]);
        true
    }
}

// ---------------------------------------------------------------------------
// Snapshot cursor helpers
// ---------------------------------------------------------------------------

pub(crate) struct SnapWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SnapWriter<'a> {
    pub(crate) const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn put_u8(&mut self, v: u8) {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    pub(crate) fn put_bytes(&mut self, src: &[u8]) {
        self.buf[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
    }
    pub(crate) const fn finish(self) -> usize {
        self.pos
    }
}

pub(crate) struct SnapReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SnapReader<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn get_u8(&mut self) -> u8 {
        let v = self.buf[self.pos];
        self.pos += 1;
        v
    }
}

// ---------------------------------------------------------------------------
// SelectionCtx
// ---------------------------------------------------------------------------

/// Virtual selection context tracking the current MF, DF, ADF, and EF.
///
/// Mirrors the UICC file selection state per [ETSI TS 102 221 V18.0.0 clause 8.4](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A263%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C220%5D).
/// Constructed with a reference to the MF root; initial DF is MF.
///
/// # Example
///
/// ```
/// use simrs_fs::{SelectionCtx, DfDef, EfDef, Fid, FileRef};
///
/// static EF: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &[0x98, 0x10]);
/// static MF: DfDef = DfDef { fid: Fid::MF, children: &[FileRef::Ef(&EF)] };
///
/// let mut ctx = SelectionCtx::new(&MF);
/// let sel = ctx.select_by_fid(Fid::new(0x2FE2)).unwrap();
/// assert_eq!(sel.fid(), Fid::new(0x2FE2));
/// ```
pub struct SelectionCtx {
    mf: &'static DfDef,
    cur_df: &'static DfDef,
    cur_ef: Option<&'static EfDef>,
    cur_adf: Option<&'static DfDef>,
}

impl SelectionCtx {
    /// Create a new selection context rooted at the given MF.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_fs::{SelectionCtx, DfDef, Fid};
    /// static MF: DfDef = DfDef { fid: Fid::MF, children: &[] };
    /// let ctx = SelectionCtx::new(&MF);
    /// assert_eq!(ctx.current_df().fid, Fid::new(0x3F00));
    /// ```
    pub const fn new(mf: &'static DfDef) -> Self {
        Self {
            mf,
            cur_df: mf,
            cur_ef: None,
            cur_adf: None,
        }
    }

    /// Select a file by its two-byte FID.
    ///
    /// Special FIDs:
    /// - `0x3F00`: always selects MF, clears ADF and EF.
    /// - `0x7FFF`: reselects the current ADF (if any).
    ///
    /// Otherwise searches the current DF's immediate children.
    /// Selecting a DF moves the current DF and clears the EF.
    /// Selecting an EF sets the current EF without changing the DF.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::FileNotFound`] if the FID is not found among
    /// the current DF's children (or `0x7FFF` with no active ADF).
    pub fn select_by_fid(
        &mut self,
        fid: Fid,
    ) -> Result<SelectedFile, FsError> {
        // 0x3F00: select MF.
        if fid == Fid::MF {
            self.cur_df = self.mf;
            self.cur_ef = None;
            self.cur_adf = None;
            return Ok(SelectedFile::Df(self.mf));
        }
        // 0x7FFF: reselect current ADF.
        if fid == Fid::CUR_ADF {
            return match self.cur_adf {
                Some(adf) => {
                    self.cur_df = adf;
                    self.cur_ef = None;
                    Ok(SelectedFile::Df(adf))
                }
                None => Err(FsError::FileNotFound),
            };
        }
        // Search current DF's children.
        for child in self.cur_df.children {
            match child {
                FileRef::Ef(ef) if ef.fid == fid => {
                    self.cur_ef = Some(ef);
                    return Ok(SelectedFile::Ef(ef));
                }
                FileRef::Df(df) if df.fid == fid => {
                    self.cur_df = df;
                    self.cur_ef = None;
                    return Ok(SelectedFile::Df(df));
                }
                _ => {}
            }
        }
        Err(FsError::FileNotFound)
    }

    /// Select an application by AID (Application Identifier).
    ///
    /// Per ISO/IEC 7816-4: the sent AID is matched as a prefix against
    /// each ADF's stored AID. First match wins.
    ///
    /// On success, the current ADF and DF are set to the matching ADF's
    /// root, and the current EF is cleared.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::FileNotFound`] if no ADF's AID has a matching prefix.
    pub fn select_by_aid(
        &mut self,
        aid: &[u8],
        adfs: &'static [AdfSlot],
    ) -> Result<SelectedFile, FsError> {
        for slot in adfs {
            if slot.aid.len() >= aid.len() && slot.aid[..aid.len()] == *aid {
                self.cur_adf = Some(slot.root);
                self.cur_df = slot.root;
                self.cur_ef = None;
                return Ok(SelectedFile::Df(slot.root));
            }
        }
        Err(FsError::FileNotFound)
    }

    /// Read binary data from the currently selected transparent EF.
    ///
    /// Returns a slice of `len` bytes starting at `offset`.
    ///
    /// # Errors
    ///
    /// - [`FsError::NoEfSelected`] if no EF is selected.
    /// - [`FsError::NotTransparent`] if the EF is record-based.
    /// - [`FsError::OffsetOutOfRange`] if `offset + len` exceeds the file.
    #[allow(clippy::cast_possible_truncation)]
    pub fn read_binary(&self, offset: u16, len: u16) -> Result<&'static [u8], FsError> {
        let ef = self.cur_ef.ok_or(FsError::NoEfSelected)?;
        if !ef.structure.is_binary_accessible() {
            return Err(FsError::NotTransparent);
        }
        let start = offset as usize;
        let end = start + len as usize;
        if end > ef.data.len() {
            return Err(FsError::OffsetOutOfRange);
        }
        Ok(&ef.data[start..end])
    }

    /// Read a record from the currently selected linear-fixed or cyclic EF.
    ///
    /// Record numbers are **1-based** per ISO/IEC 7816-4.
    ///
    /// # Errors
    ///
    /// - [`FsError::NoEfSelected`] if no EF is selected.
    /// - [`FsError::NotRecordBased`] if the EF is transparent.
    /// - [`FsError::RecordOutOfRange`] if `num` is 0 or exceeds `num_records`.
    pub fn read_record(&self, num: u8) -> Result<&'static [u8], FsError> {
        let ef = self.cur_ef.ok_or(FsError::NoEfSelected)?;
        let (record_size, num_records) = ef.structure.record_params().ok_or(FsError::NotRecordBased)?;
        if num == 0 || num > num_records {
            return Err(FsError::RecordOutOfRange);
        }
        let idx = (num - 1) as usize;
        let rs = record_size as usize;
        let start = idx * rs;
        let end = start + rs;
        if end > ef.data.len() {
            return Err(FsError::RecordOutOfRange);
        }
        Ok(&ef.data[start..end])
    }

    /// The currently selected DF (or MF).
    pub const fn current_df(&self) -> &'static DfDef {
        self.cur_df
    }

    /// The currently selected EF, if any.
    pub const fn current_ef(&self) -> Option<&'static EfDef> {
        self.cur_ef
    }

    /// The currently active ADF, if any.
    pub const fn current_adf(&self) -> Option<&'static DfDef> {
        self.cur_adf
    }

    /// Select a file by walking a path of FID byte pairs.
    ///
    /// `path` must contain an even number of bytes; each consecutive pair
    /// is interpreted as a big-endian FID. If `from_mf` is `true`
    /// (P1=0x08), the context is reset to MF before walking. If `false`
    /// (P1=0x09), the walk starts from the current DF.
    ///
    /// An empty path (zero bytes) selects MF (when `from_mf`) or the
    /// current DF (when not `from_mf`).
    ///
    /// # Errors
    ///
    /// - [`FsError::InvalidPath`] if `path.len()` is odd.
    /// - [`FsError::FileNotFound`] if any intermediate FID is not found.
    pub fn select_by_path(
        &mut self,
        path: &[u8],
        from_mf: bool,
    ) -> Result<SelectedFile, FsError> {
        if !path.len().is_multiple_of(2) {
            return Err(FsError::InvalidPath);
        }
        if from_mf {
            self.cur_df = self.mf;
            self.cur_ef = None;
            self.cur_adf = None;
        }
        if path.is_empty() {
            return Ok(SelectedFile::Df(self.cur_df));
        }
        let mut last = SelectedFile::Df(self.cur_df);
        for pair in path.chunks_exact(2) {
            let fid = Fid::from_be_bytes([pair[0], pair[1]]);
            last = self.select_by_fid(fid)?;
        }
        Ok(last)
    }

    /// Find an EF by Short File Identifier among the current DF's children.
    ///
    /// Returns the matching EF definition if found, or `None` if no child
    /// EF has the given SFI.
    pub fn find_ef_by_sfi(&self, sfi: Sfi) -> Option<&'static EfDef> {
        for child in self.cur_df.children {
            if let FileRef::Ef(ef) = child {
                if ef.sfi == Some(sfi) {
                    return Some(ef);
                }
            }
        }
        None
    }

    // -- snapshot --

    /// Snapshot buffer size: 8 bytes.
    ///
    /// Layout: `cur_df` FID (2 LE) + `cur_ef` FID or `0xFFFF` (2 LE) +
    /// `cur_adf` FID or `0xFFFF` (2 LE) + reserved (2).
    pub const SNAPSHOT_SIZE: usize = 8;

    /// Serialize the selection state into `buf` as flat LE bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut w = SnapWriter::new(buf);
        w.put_bytes(&self.cur_df.fid.to_le_bytes());
        w.put_bytes(&self.cur_ef.map_or(Fid::NONE, |ef| ef.fid).to_le_bytes());
        w.put_bytes(&self.cur_adf.map_or(Fid::NONE, |adf| adf.fid).to_le_bytes());
        w.put_u8(0);
        w.put_u8(0);
        w.finish()
    }

    /// Restore the selection state from `buf`.
    ///
    /// Walks the MF tree and ADF table to resolve FIDs back to
    /// `&'static` references. Returns `true` on success.
    #[must_use]
    pub fn restore_state(
        &mut self,
        buf: &[u8],
        adfs: &'static [AdfSlot],
    ) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut r = SnapReader::new(buf);
        let df_fid = Fid::from_le_bytes([r.get_u8(), r.get_u8()]);
        let ef_fid = Fid::from_le_bytes([r.get_u8(), r.get_u8()]);
        let adf_fid = Fid::from_le_bytes([r.get_u8(), r.get_u8()]);

        // Resolve cur_adf.
        if adf_fid == Fid::NONE {
            self.cur_adf = None;
        } else if let Some(slot) = adfs.iter().find(|s| s.root.fid == adf_fid) {
            self.cur_adf = Some(slot.root);
        } else {
            return false;
        }

        // Resolve cur_df: search MF tree then ADF trees.
        if let Some(df) = find_df_recursive(self.mf, df_fid) {
            self.cur_df = df;
        } else if let Some(df) = adfs
            .iter()
            .find_map(|s| find_df_recursive(s.root, df_fid))
        {
            self.cur_df = df;
        } else {
            return false;
        }

        // Resolve cur_ef: must be a child of cur_df.
        if ef_fid == Fid::NONE {
            self.cur_ef = None;
        } else {
            let found = self.cur_df.children.iter().find_map(|child| {
                if let FileRef::Ef(ef) = child {
                    if ef.fid == ef_fid {
                        return Some(*ef);
                    }
                }
                None
            });
            if let Some(ef) = found {
                self.cur_ef = Some(ef);
            } else {
                return false;
            }
        }

        true
    }
}

/// Find a DF by FID in a tree rooted at `df`, depth-first.
fn find_df_recursive(df: &'static DfDef, fid: Fid) -> Option<&'static DfDef> {
    if df.fid == fid {
        return Some(df);
    }
    for child in df.children {
        if let FileRef::Df(sub) = child {
            if let Some(found) = find_df_recursive(sub, fid) {
                return Some(found);
            }
        }
    }
    None
}

/// Check if `haystack` contains `needle` as a contiguous substring.
fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Deactivation tracking
// ---------------------------------------------------------------------------

/// Tracks deactivated file FIDs. Up to 16 files can be deactivated.
///
/// Embedded in [`FsData`] or used alongside a [`SelectionCtx`] to track
/// file lifecycle state.
///
/// # Persistence
///
/// On real UICC hardware, file deactivation state is stored in EEPROM and
/// persists across card resets ([ETSI TS 102 221 V18.0.0 clause 11.1.14](https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/18.00.00_60/ts_102221v180000p.pdf#%5B%7B%22num%22%3A387%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C545%5D)). This
/// tracker models that persistent state and is intentionally **not** cleared
/// by [`ResetEffects`](crate::ResetEffects) or session-level resets.
pub struct DeactivationTracker {
    deactivated: [Fid; 16],
    deactivated_count: u8,
}

impl Default for DeactivationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DeactivationTracker {
    /// Create a new tracker with no deactivated files.
    pub const fn new() -> Self {
        Self {
            deactivated: [Fid::NONE; 16],
            deactivated_count: 0,
        }
    }

    /// Mark a file as deactivated. Returns `true` if the file was added.
    /// Returns `false` if already deactivated or capacity is full.
    pub fn deactivate_file(&mut self, fid: Fid) -> bool {
        if self.is_deactivated(fid) {
            return false;
        }
        if self.deactivated_count as usize >= 16 {
            return false;
        }
        self.deactivated[self.deactivated_count as usize] = fid;
        self.deactivated_count += 1;
        true
    }

    /// Remove a file from the deactivated list (re-activate it).
    /// Returns `true` if the file was found and removed.
    pub fn activate_file(&mut self, fid: Fid) -> bool {
        for i in 0..self.deactivated_count as usize {
            if self.deactivated[i] == fid {
                // Swap-remove: replace with last element.
                let last = self.deactivated_count as usize - 1;
                self.deactivated[i] = self.deactivated[last];
                self.deactivated[last] = Fid::NONE;
                self.deactivated_count -= 1;
                return true;
            }
        }
        false
    }

    /// Check if a file is deactivated.
    pub fn is_deactivated(&self, fid: Fid) -> bool {
        self.deactivated[..self.deactivated_count as usize].contains(&fid)
    }

    /// Snapshot buffer size: 16 FIDs (2 bytes each) + 1 count = 33.
    pub const SNAPSHOT_SIZE: usize = 16 * 2 + 1;

    /// Serialize the deactivation state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        for i in 0..16 {
            let le = self.deactivated[i].to_le_bytes();
            buf[i * 2] = le[0];
            buf[i * 2 + 1] = le[1];
        }
        buf[32] = self.deactivated_count;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the deactivation state from `buf`.
    ///
    /// Returns `true` on success.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        for i in 0..16 {
            self.deactivated[i] = Fid::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]);
        }
        let cnt = buf[32];
        if cnt as usize > 16 {
            return false;
        }
        self.deactivated_count = cnt;
        true
    }

    /// Reset: clear all deactivations.
    pub const fn clear(&mut self) {
        self.deactivated = [Fid::NONE; 16];
        self.deactivated_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    // -- Test filesystem tree --

    static EF_ICCID: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        Some(Sfi::new(2)),
        &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    );

    static EF_DIR_DATA: [u8; 16] = [
        // Record 1: 8 bytes
        0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00,
        // Record 2: 8 bytes
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_DIR: EfDef = EfDef::linear_fixed(
        Fid::new(0x2F00),
        Some(Sfi::new(30)),
        8, 2,
        &EF_DIR_DATA,
    );

    static EF_ADN_DATA: [u8; 42] = [
        // Record 1
        0x41, 0x6C, 0x69, 0x63, 0x65, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        // Record 2
        0x42, 0x6F, 0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        // Record 3
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_ADN: EfDef = EfDef::linear_fixed(
        Fid::new(0x6F3A),
        None,
        14, 3,
        &EF_ADN_DATA,
    );

    static DF_TELECOM: DfDef = DfDef {
        fid: Fid::new(0x7F10),
        children: &[FileRef::Ef(&EF_ADN)],
    };

    static EF_GSM_IMSI: EfDef = EfDef::transparent(
        Fid::new(0x6F07),
        Some(Sfi::new(7)),
        &[0x08, 0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
    );

    static EF_KC: EfDef = EfDef::transparent(
        Fid::new(0x6F20),
        None,
        &[0xFF; 9],
    );

    static DF_GSM: DfDef = DfDef {
        fid: Fid::new(0x7F20),
        children: &[FileRef::Ef(&EF_GSM_IMSI), FileRef::Ef(&EF_KC)],
    };

    const _: () = assert_fids_unique(&[
        0x6F07, // EF_GSM_IMSI
        0x6F20, // EF_KC
    ]);

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[
            FileRef::Ef(&EF_ICCID),
            FileRef::Ef(&EF_DIR),
            FileRef::Df(&DF_TELECOM),
            FileRef::Df(&DF_GSM),
        ],
    };

    const _: () = assert_fids_unique(&[
        0x2FE2, // EF_ICCID
        0x2F00, // EF_DIR
        0x7F10, // DF_TELECOM
        0x7F20, // DF_GSM
    ]);

    // ADF for USIM
    static EF_USIM_IMSI: EfDef = EfDef::transparent(
        Fid::new(0x6F07),
        Some(Sfi::new(7)),
        &[0x08, 0x29, 0x43, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
    );

    static ADF_USIM_ROOT: DfDef = DfDef {
        fid: Fid::new(0xFF01),
        children: &[FileRef::Ef(&EF_USIM_IMSI)],
    };

    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        root: &ADF_USIM_ROOT,
    }];

    // Cyclic EF for testing read_record on cyclic structure.
    static EF_CYCLIC_DATA: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, // record 1
        0x05, 0x06, 0x07, 0x08, // record 2
        0x09, 0x0A, 0x0B, 0x0C, // record 3
    ];

    static EF_CYCLIC: EfDef = EfDef::cyclic(
        Fid::new(0x6F4A),
        None,
        4, 3,
        &EF_CYCLIC_DATA,
    );

    static DF_TELECOM_WITH_CYCLIC: DfDef = DfDef {
        fid: Fid::new(0x7F10),
        children: &[FileRef::Ef(&EF_ADN), FileRef::Ef(&EF_CYCLIC)],
    };

    const _: () = assert_fids_unique(&[
        0x6F3A, // EF_ADN
        0x6F4A, // EF_CYCLIC
    ]);

    static MF_WITH_CYCLIC: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[
            FileRef::Ef(&EF_ICCID),
            FileRef::Ef(&EF_DIR),
            FileRef::Df(&DF_TELECOM_WITH_CYCLIC),
            FileRef::Df(&DF_GSM),
        ],
    };

    const _: () = assert_fids_unique(&[
        0x2FE2, // EF_ICCID
        0x2F00, // EF_DIR
        0x7F10, // DF_TELECOM_WITH_CYCLIC
        0x7F20, // DF_GSM
    ]);

    fn ctx() -> SelectionCtx {
        SelectionCtx::new(&MF)
    }

    // -- SELECT by FID tests --

    #[test]
    fn select_mf_resets_context() {
        let mut c = ctx();
        // Navigate into DF.GSM and select an EF.
        c.select_by_fid(Fid::new(0x7F20)).unwrap();
        c.select_by_fid(Fid::new(0x6F07)).unwrap();
        assert!(c.current_ef().is_some());
        // Select MF resets everything.
        c.select_by_fid(Fid::MF).unwrap();
        assert_eq!(c.current_df().fid, Fid::new(0x3F00));
        assert!(c.current_ef().is_none());
        assert!(c.current_adf().is_none());
    }

    #[test]
    fn select_ef_under_mf() {
        let mut c = ctx();
        let sel = c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        assert_eq!(sel.fid(), Fid::new(0x2FE2));
        assert!(matches!(sel, SelectedFile::Ef(_)));
        assert_eq!(c.current_df().fid, Fid::new(0x3F00)); // DF unchanged
    }

    #[test]
    fn select_df_under_mf() {
        let mut c = ctx();
        let sel = c.select_by_fid(Fid::new(0x7F20)).unwrap();
        assert_eq!(sel.fid(), Fid::new(0x7F20));
        assert!(matches!(sel, SelectedFile::Df(_)));
        assert_eq!(c.current_df().fid, Fid::new(0x7F20));
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn select_ef_under_df() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F20)).unwrap();
        let sel = c.select_by_fid(Fid::new(0x6F07)).unwrap();
        assert_eq!(sel.fid(), Fid::new(0x6F07));
        assert_eq!(c.current_df().fid, Fid::new(0x7F20)); // DF unchanged
    }

    #[test]
    fn select_nonexistent_fid() {
        let mut c = ctx();
        assert_eq!(
            c.select_by_fid(Fid::new(0xFFFF)),
            Err(FsError::FileNotFound)
        );
    }

    #[test]
    fn select_child_not_in_current_df() {
        let mut c = ctx();
        // 0x6F07 is under DF.GSM, not MF.
        assert_eq!(
            c.select_by_fid(Fid::new(0x6F07)),
            Err(FsError::FileNotFound)
        );
    }

    #[test]
    fn select_7fff_reselects_adf() {
        let mut c = ctx();
        c.select_by_aid(
            &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
            &ADF_TABLE,
        )
        .unwrap();
        // Select an EF first.
        c.select_by_fid(Fid::new(0x6F07)).unwrap();
        // 0x7FFF reselects the ADF root.
        let sel = c.select_by_fid(Fid::CUR_ADF).unwrap();
        assert!(matches!(sel, SelectedFile::Df(_)));
        assert_eq!(sel.fid(), Fid::new(0xFF01));
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn select_7fff_with_no_adf() {
        let mut c = ctx();
        assert_eq!(
            c.select_by_fid(Fid::CUR_ADF),
            Err(FsError::FileNotFound)
        );
    }

    // -- SELECT by AID tests --

    #[test]
    fn select_by_full_aid() {
        let mut c = ctx();
        let sel = c
            .select_by_aid(
                &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
                &ADF_TABLE,
            )
            .unwrap();
        assert_eq!(sel.fid(), Fid::new(0xFF01));
        assert!(c.current_adf().is_some());
        assert_eq!(c.current_df().fid, Fid::new(0xFF01));
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn select_by_partial_aid() {
        let mut c = ctx();
        let sel = c
            .select_by_aid(&[0xA0, 0x00, 0x00, 0x00, 0x87], &ADF_TABLE)
            .unwrap();
        assert_eq!(sel.fid(), Fid::new(0xFF01));
    }

    #[test]
    fn select_by_unknown_aid() {
        let mut c = ctx();
        assert_eq!(
            c.select_by_aid(&[0xFF, 0xFF, 0xFF, 0xFF], &ADF_TABLE),
            Err(FsError::FileNotFound)
        );
    }

    // -- READ BINARY tests --

    #[test]
    fn read_binary_full() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        let data = c.read_binary(0, 10).unwrap();
        assert_eq!(
            data,
            &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]
        );
    }

    #[test]
    fn read_binary_partial() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        let data = c.read_binary(2, 3).unwrap();
        assert_eq!(data, &[0x14, 0x80, 0x00]);
    }

    #[test]
    fn read_binary_no_ef_selected() {
        let c = ctx();
        assert_eq!(c.read_binary(0, 1), Err(FsError::NoEfSelected));
    }

    #[test]
    fn read_binary_on_linear_fixed() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x2F00)).unwrap(); // EF.DIR is linear-fixed
        assert_eq!(c.read_binary(0, 1), Err(FsError::NotTransparent));
    }

    #[test]
    fn read_binary_past_end() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        assert_eq!(c.read_binary(8, 5), Err(FsError::OffsetOutOfRange));
    }

    #[test]
    fn read_binary_zero_length() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        let data = c.read_binary(5, 0).unwrap();
        assert!(data.is_empty());
    }

    // -- READ RECORD tests --

    #[test]
    fn read_record_first() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F10)).unwrap(); // DF.TELECOM
        c.select_by_fid(Fid::new(0x6F3A)).unwrap(); // EF.ADN
        let rec = c.read_record(1).unwrap();
        assert_eq!(rec.len(), 14);
        assert_eq!(rec[0], 0x41); // 'A'
    }

    #[test]
    fn read_record_second() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F10)).unwrap();
        c.select_by_fid(Fid::new(0x6F3A)).unwrap();
        let rec = c.read_record(2).unwrap();
        assert_eq!(rec.len(), 14);
        assert_eq!(rec[0], 0x42); // 'B'
    }

    #[test]
    fn read_record_third() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F10)).unwrap();
        c.select_by_fid(Fid::new(0x6F3A)).unwrap();
        let rec = c.read_record(3).unwrap();
        assert_eq!(rec.len(), 14);
        assert_eq!(rec[0], 0xFF); // empty record
    }

    #[test]
    fn read_record_zero_invalid() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F10)).unwrap();
        c.select_by_fid(Fid::new(0x6F3A)).unwrap();
        assert_eq!(c.read_record(0), Err(FsError::RecordOutOfRange));
    }

    #[test]
    fn read_record_beyond_last() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F10)).unwrap();
        c.select_by_fid(Fid::new(0x6F3A)).unwrap();
        assert_eq!(c.read_record(4), Err(FsError::RecordOutOfRange));
    }

    #[test]
    fn read_record_on_transparent() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        assert_eq!(c.read_record(1), Err(FsError::NotRecordBased));
    }

    #[test]
    fn read_record_no_ef_selected() {
        let c = ctx();
        assert_eq!(c.read_record(1), Err(FsError::NoEfSelected));
    }

    #[test]
    fn read_record_from_linear_fixed_under_mf() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x2F00)).unwrap(); // EF.DIR
        let rec = c.read_record(1).unwrap();
        assert_eq!(rec.len(), 8);
        assert_eq!(rec[0], 0x61);
    }

    // -- Navigation sequence tests --

    #[test]
    fn navigate_mf_df_ef_mf_roundtrip() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F20)).unwrap();
        assert_eq!(c.current_df().fid, Fid::new(0x7F20));
        c.select_by_fid(Fid::new(0x6F07)).unwrap();
        assert!(c.current_ef().is_some());
        c.select_by_fid(Fid::MF).unwrap();
        assert_eq!(c.current_df().fid, Fid::new(0x3F00));
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn adf_ef_has_different_data_from_gsm_ef() {
        let mut c = ctx();
        // Select GSM IMSI.
        c.select_by_fid(Fid::new(0x7F20)).unwrap();
        c.select_by_fid(Fid::new(0x6F07)).unwrap();
        let gsm_imsi = c.read_binary(0, 9).unwrap();

        // Select USIM IMSI via AID.
        c.select_by_aid(
            &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
            &ADF_TABLE,
        )
        .unwrap();
        c.select_by_fid(Fid::new(0x6F07)).unwrap();
        let usim_imsi = c.read_binary(0, 9).unwrap();

        // Same FID, different data.
        assert_ne!(gsm_imsi, usim_imsi);
    }

    #[test]
    fn read_record_from_cyclic_ef() {
        let mut c = SelectionCtx::new(&MF_WITH_CYCLIC);
        c.select_by_fid(Fid::new(0x7F10)).unwrap(); // DF.TELECOM
        c.select_by_fid(Fid::new(0x6F4A)).unwrap(); // EF_CYCLIC
        assert_eq!(c.read_record(1).unwrap(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(c.read_record(2).unwrap(), &[0x05, 0x06, 0x07, 0x08]);
        assert_eq!(c.read_record(3).unwrap(), &[0x09, 0x0A, 0x0B, 0x0C]);
        assert_eq!(c.read_record(4), Err(FsError::RecordOutOfRange));
        assert_eq!(c.read_record(0), Err(FsError::RecordOutOfRange));
    }

    #[test]
    fn select_by_overlong_aid_returns_not_found() {
        let mut c = ctx();
        // Stored AID is 7 bytes; sending 8 must not match.
        assert_eq!(
            c.select_by_aid(
                &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF],
                &ADF_TABLE,
            ),
            Err(FsError::FileNotFound)
        );
    }

    #[test]
    fn selected_file_equality_by_identity() {
        let mut c = ctx();
        let sel1 = c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        let sel2 = c.select_by_fid(Fid::new(0x2FE2)).unwrap();
        assert_eq!(sel1, sel2);
    }

    #[test]
    fn selected_file_df_vs_ef_not_equal() {
        let mut c1 = ctx();
        let mut c2 = ctx();
        let df = c1.select_by_fid(Fid::new(0x7F20)).unwrap();
        let ef = c2.select_by_fid(Fid::new(0x2FE2)).unwrap();
        assert_ne!(df, ef);
    }

    // -- SNAPSHOT tests --

    #[test]
    fn snapshot_save_restore_mf_root() {
        let c = ctx();
        let mut buf = [0u8; SelectionCtx::SNAPSHOT_SIZE];
        assert_eq!(c.save_state(&mut buf), 8);

        let mut restored = SelectionCtx::new(&MF);
        // Move away from MF first.
        restored.select_by_fid(Fid::new(0x7F20)).unwrap();
        assert!(restored.restore_state(&buf, &[]));
        assert_eq!(restored.current_df().fid, Fid::new(0x3F00));
        assert!(restored.current_ef().is_none());
        assert!(restored.current_adf().is_none());
    }

    #[test]
    fn snapshot_save_restore_df_and_ef() {
        let mut c = ctx();
        c.select_by_fid(Fid::new(0x7F20)).unwrap();
        c.select_by_fid(Fid::new(0x6F07)).unwrap();

        let mut buf = [0u8; SelectionCtx::SNAPSHOT_SIZE];
        let _ = c.save_state(&mut buf);

        let mut restored = SelectionCtx::new(&MF);
        assert!(restored.restore_state(&buf, &[]));
        assert_eq!(restored.current_df().fid, Fid::new(0x7F20));
        assert_eq!(restored.current_ef().unwrap().fid, Fid::new(0x6F07));
    }

    #[test]
    fn snapshot_save_restore_adf() {
        let mut c = ctx();
        c.select_by_aid(
            &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
            &ADF_TABLE,
        )
        .unwrap();
        c.select_by_fid(Fid::new(0x6F07)).unwrap();

        let mut buf = [0u8; SelectionCtx::SNAPSHOT_SIZE];
        let _ = c.save_state(&mut buf);

        let mut restored = SelectionCtx::new(&MF);
        assert!(restored.restore_state(&buf, &ADF_TABLE));
        assert!(restored.current_adf().is_some());
        assert_eq!(restored.current_df().fid, Fid::new(0xFF01));
        assert_eq!(restored.current_ef().unwrap().fid, Fid::new(0x6F07));
    }

    #[test]
    fn snapshot_restore_unknown_df_returns_false() {
        let mut buf = [0u8; SelectionCtx::SNAPSHOT_SIZE];
        // Write unknown DF FID.
        buf[0] = 0xAA;
        buf[1] = 0xBB;
        buf[2] = 0xFF;
        buf[3] = 0xFF;
        buf[4] = 0xFF;
        buf[5] = 0xFF;

        let mut c = ctx();
        assert!(!c.restore_state(&buf, &[]));
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let c = ctx();
        let mut small = [0u8; 4];
        assert_eq!(c.save_state(&mut small), 0);

        let mut c2 = ctx();
        assert!(!c2.restore_state(&small, &[]));
    }

    // -- SELECT by path tests --

    #[test]
    fn select_by_path_from_mf() {
        let mut c = ctx();
        // Navigate away from MF first.
        c.select_by_fid(Fid::new(0x7F10)).unwrap();
        // Path from MF: DF.GSM (7F20) -> EF.IMSI (6F07).
        let sel = c
            .select_by_path(&[0x7F, 0x20, 0x6F, 0x07], true)
            .unwrap();
        assert_eq!(sel.fid(), Fid::new(0x6F07));
        assert!(matches!(sel, SelectedFile::Ef(_)));
        assert_eq!(c.current_df().fid, Fid::new(0x7F20));
    }

    #[test]
    fn select_by_path_from_current() {
        let mut c = ctx();
        // Navigate to DF.GSM first.
        c.select_by_fid(Fid::new(0x7F20)).unwrap();
        // Path from current DF: EF.IMSI (6F07).
        let sel = c
            .select_by_path(&[0x6F, 0x07], false)
            .unwrap();
        assert_eq!(sel.fid(), Fid::new(0x6F07));
        assert!(matches!(sel, SelectedFile::Ef(_)));
        assert_eq!(c.current_df().fid, Fid::new(0x7F20));
    }

    #[test]
    fn select_by_path_odd_length_fails() {
        let mut c = ctx();
        assert_eq!(
            c.select_by_path(&[0x7F, 0x20, 0x6F], true),
            Err(FsError::InvalidPath)
        );
    }

    #[test]
    fn select_by_path_intermediate_not_found() {
        let mut c = ctx();
        // First FID does not exist under MF.
        assert_eq!(
            c.select_by_path(&[0xAA, 0xBB, 0x6F, 0x07], true),
            Err(FsError::FileNotFound)
        );
    }

    #[test]
    fn select_by_path_empty() {
        let mut c = ctx();
        // Empty path from MF selects MF.
        let sel = c.select_by_path(&[], true).unwrap();
        assert_eq!(sel.fid(), Fid::new(0x3F00));
        assert!(matches!(sel, SelectedFile::Df(_)));

        // Navigate to DF.GSM.
        c.select_by_fid(Fid::new(0x7F20)).unwrap();
        // Empty path from current selects current DF.
        let sel = c.select_by_path(&[], false).unwrap();
        assert_eq!(sel.fid(), Fid::new(0x7F20));
        assert!(matches!(sel, SelectedFile::Df(_)));
    }

    // -- find_ef_by_sfi tests --

    #[test]
    fn find_ef_by_sfi_present() {
        let c = ctx();
        // EF_ICCID has SFI(2) and is a child of MF.
        let ef = c.find_ef_by_sfi(Sfi::new(2)).unwrap();
        assert_eq!(ef.fid, Fid::new(0x2FE2));
    }

    #[test]
    fn find_ef_by_sfi_absent() {
        let c = ctx();
        // No EF under MF has SFI(99).
        assert!(c.find_ef_by_sfi(Sfi::from_raw(99)).is_none());
    }

    #[test]
    fn find_ef_by_sfi_no_sfi_on_ef() {
        let mut c = ctx();
        // Navigate to DF.TELECOM. EF_ADN has sfi: None.
        c.select_by_fid(Fid::new(0x7F10)).unwrap();
        // SFI(1) should not match EF_ADN (which has no SFI).
        assert!(c.find_ef_by_sfi(Sfi::new(1)).is_none());
    }

    #[test]
    fn fs_error_display_non_empty() {
        let variants: &[FsError] = &[
            FsError::FileNotFound,
            FsError::NoEfSelected,
            FsError::NotTransparent,
            FsError::NotRecordBased,
            FsError::RecordOutOfRange,
            FsError::OffsetOutOfRange,
            FsError::StoreFull,
            FsError::TooManyFiles,
            FsError::DataTooLarge,
            FsError::InvalidPath,
            FsError::IncreaseOverflow,
        ];
        for v in variants {
            let s = alloc::format!("{v}");
            assert!(!s.is_empty(), "Display for {v:?} must produce non-empty string");
        }
    }

    #[test]
    fn ef_structure_is_binary_accessible() {
        assert!(EfStructure::Transparent.is_binary_accessible());
        assert!(EfStructure::BerTlv.is_binary_accessible());
        assert!(!EfStructure::LinearFixed { record_size: 10, num_records: 3 }.is_binary_accessible());
        assert!(!EfStructure::Cyclic { record_size: 10, num_records: 3 }.is_binary_accessible());
    }

    #[test]
    fn ef_structure_is_record_based() {
        assert!(!EfStructure::Transparent.is_record_based());
        assert!(!EfStructure::BerTlv.is_record_based());
        assert!(EfStructure::LinearFixed { record_size: 10, num_records: 3 }.is_record_based());
        assert!(EfStructure::Cyclic { record_size: 10, num_records: 3 }.is_record_based());
    }

    #[test]
    fn ef_structure_record_params() {
        assert_eq!(EfStructure::Transparent.record_params(), None);
        assert_eq!(EfStructure::BerTlv.record_params(), None);
        assert_eq!(
            EfStructure::LinearFixed { record_size: 14, num_records: 5 }.record_params(),
            Some((14, 5))
        );
        assert_eq!(
            EfStructure::Cyclic { record_size: 3, num_records: 10 }.record_params(),
            Some((3, 10))
        );
    }

    #[test]
    fn ef_structure_is_cyclic() {
        assert!(!EfStructure::Transparent.is_cyclic());
        assert!(!EfStructure::BerTlv.is_cyclic());
        assert!(!EfStructure::LinearFixed { record_size: 10, num_records: 3 }.is_cyclic());
        assert!(EfStructure::Cyclic { record_size: 10, num_records: 3 }.is_cyclic());
    }

    #[test]
    fn ef_structure_record_size() {
        assert_eq!(EfStructure::Transparent.record_size(), 0);
        assert_eq!(EfStructure::BerTlv.record_size(), 0);
        assert_eq!(EfStructure::LinearFixed { record_size: 14, num_records: 5 }.record_size(), 14);
        assert_eq!(EfStructure::Cyclic { record_size: 3, num_records: 10 }.record_size(), 3);
    }

    #[test]
    fn ef_structure_gsm_structure_byte() {
        assert_eq!(EfStructure::Transparent.gsm_structure_byte(), 0x00);
        assert_eq!(EfStructure::BerTlv.gsm_structure_byte(), 0x00);
        assert_eq!(EfStructure::LinearFixed { record_size: 14, num_records: 5 }.gsm_structure_byte(), 0x01);
        assert_eq!(EfStructure::Cyclic { record_size: 3, num_records: 10 }.gsm_structure_byte(), 0x03);
    }

    #[test]
    fn ef_structure_gsm_increase_byte() {
        assert_eq!(EfStructure::Transparent.gsm_increase_byte(), 0x00);
        assert_eq!(EfStructure::BerTlv.gsm_increase_byte(), 0x00);
        assert_eq!(EfStructure::LinearFixed { record_size: 14, num_records: 5 }.gsm_increase_byte(), 0x00);
        assert_eq!(EfStructure::Cyclic { record_size: 3, num_records: 10 }.gsm_increase_byte(), 0x01);
    }

    #[test]
    fn ef_structure_fcp_descriptor_byte() {
        assert_eq!(EfStructure::Transparent.fcp_descriptor_byte(), 0x41);
        assert_eq!(EfStructure::LinearFixed { record_size: 14, num_records: 5 }.fcp_descriptor_byte(), 0x42);
        assert_eq!(EfStructure::Cyclic { record_size: 3, num_records: 10 }.fcp_descriptor_byte(), 0x46);
        assert_eq!(EfStructure::BerTlv.fcp_descriptor_byte(), 0x39);
    }

    #[test]
    fn ef_structure_fcp_descriptor_data() {
        let (data, len) = EfStructure::Transparent.fcp_descriptor_data();
        assert_eq!(len, 2);
        assert_eq!(&data[..len], &[0x41, 0x21]);

        let (data, len) = EfStructure::BerTlv.fcp_descriptor_data();
        assert_eq!(len, 2);
        assert_eq!(&data[..len], &[0x39, 0x21]);

        let (data, len) = EfStructure::LinearFixed { record_size: 14, num_records: 5 }.fcp_descriptor_data();
        assert_eq!(len, 5);
        assert_eq!(&data[..len], &[0x42, 0x21, 5, 0x00, 14]);

        let (data, len) = EfStructure::Cyclic { record_size: 3, num_records: 10 }.fcp_descriptor_data();
        assert_eq!(len, 5);
        assert_eq!(&data[..len], &[0x46, 0x21, 10, 0x00, 3]);
    }

    #[test]
    fn ef_structure_expected_data_len() {
        assert_eq!(EfStructure::Transparent.expected_data_len(), None);
        assert_eq!(EfStructure::BerTlv.expected_data_len(), None);
        assert_eq!(EfStructure::LinearFixed { record_size: 14, num_records: 5 }.expected_data_len(), Some(70));
        assert_eq!(EfStructure::Cyclic { record_size: 3, num_records: 10 }.expected_data_len(), Some(30));
    }
}

// ---------------------------------------------------------------------------
// FsData tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fsdata_tests {
    use super::*;

    static EF_T: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        None,
        &[0x01, 0x02, 0x03, 0x04, 0x05],
    );

    static EF_LF: EfDef = EfDef::linear_fixed(
        Fid::new(0x2F00),
        None,
        4, 2,
        &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11],
    );

    static EF_CY: EfDef = EfDef::cyclic(
        Fid::new(0x6F4A),
        None,
        3, 2,
        &[0xA1, 0xA2, 0xA3, 0xB1, 0xB2, 0xB3],
    );

    static DF_SUB: DfDef = DfDef {
        fid: Fid::new(0x7F20),
        children: &[FileRef::Ef(&EF_LF), FileRef::Ef(&EF_CY)],
    };

    const _: () = assert_fids_unique(&[
        0x2F00, // EF_LF
        0x6F4A, // EF_CY
    ]);

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&EF_T), FileRef::Df(&DF_SUB)],
    };

    const _: () = assert_fids_unique(&[
        0x2FE2, // EF_T
        0x7F20, // DF_SUB
    ]);

    // Total EF data: 5 + 8 + 6 = 19 bytes.

    fn store() -> FsData<64, 8> {
        let mut s = FsData::<64, 8>::new();
        s.init(&MF).unwrap();
        s
    }

    // -- init --

    #[test]
    fn init_populates_entries() {
        let s = store();
        assert_eq!(s.ef_count(), 3);
        assert_eq!(s.used(), 19);
    }

    #[test]
    fn init_copies_template_data() {
        let s = store();
        assert_eq!(
            s.read_binary(&EF_T, 0, 5).unwrap(),
            &[0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn init_too_small_cap() {
        let mut s = FsData::<10, 8>::new();
        assert_eq!(s.init(&MF), Err(FsError::StoreFull));
    }

    #[test]
    fn init_with_adfs() {
        static ADF_EF: EfDef = EfDef::transparent(
            Fid::new(0x6F07),
            None,
            &[0xDD, 0xEE],
        );
        static ADF_ROOT: DfDef = DfDef {
            fid: Fid::new(0xFF01),
            children: &[FileRef::Ef(&ADF_EF)],
        };
        static ADFS: [AdfSlot; 1] = [AdfSlot {
            aid: &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
            root: &ADF_ROOT,
        }];

        let mut s = FsData::<64, 8>::new();
        s.init_with_adfs(&MF, &ADFS).unwrap();
        assert_eq!(s.ef_count(), 4); // 3 from MF + 1 from ADF
        assert_eq!(s.read_binary(&ADF_EF, 0, 2).unwrap(), &[0xDD, 0xEE]);
    }

    // -- read_binary --

    #[test]
    fn read_binary_full() {
        let s = store();
        assert_eq!(
            s.read_binary(&EF_T, 0, 5).unwrap(),
            &[0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn read_binary_partial() {
        let s = store();
        assert_eq!(
            s.read_binary(&EF_T, 1, 3).unwrap(),
            &[0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn read_binary_past_end() {
        let s = store();
        assert_eq!(
            s.read_binary(&EF_T, 3, 5),
            Err(FsError::OffsetOutOfRange)
        );
    }

    #[test]
    fn read_binary_on_record_ef() {
        let s = store();
        assert_eq!(
            s.read_binary(&EF_LF, 0, 4),
            Err(FsError::NotTransparent)
        );
    }

    #[test]
    fn read_binary_unknown_ef() {
        static UNKNOWN: EfDef = EfDef::transparent(
            Fid::new(0xAAAA),
            None,
            &[],
        );
        let s = store();
        assert_eq!(
            s.read_binary(&UNKNOWN, 0, 0),
            Err(FsError::FileNotFound)
        );
    }

    // -- read_record --

    #[test]
    fn read_record_linear_fixed() {
        let s = store();
        assert_eq!(
            s.read_record(&EF_LF, 1).unwrap(),
            &[0x0A, 0x0B, 0x0C, 0x0D]
        );
        assert_eq!(
            s.read_record(&EF_LF, 2).unwrap(),
            &[0x0E, 0x0F, 0x10, 0x11]
        );
    }

    #[test]
    fn read_record_cyclic() {
        let s = store();
        assert_eq!(
            s.read_record(&EF_CY, 1).unwrap(),
            &[0xA1, 0xA2, 0xA3]
        );
        assert_eq!(
            s.read_record(&EF_CY, 2).unwrap(),
            &[0xB1, 0xB2, 0xB3]
        );
    }

    #[test]
    fn read_record_out_of_range() {
        let s = store();
        assert_eq!(s.read_record(&EF_LF, 0), Err(FsError::RecordOutOfRange));
        assert_eq!(s.read_record(&EF_LF, 3), Err(FsError::RecordOutOfRange));
    }

    #[test]
    fn read_record_on_transparent() {
        let s = store();
        assert_eq!(s.read_record(&EF_T, 1), Err(FsError::NotRecordBased));
    }

    // -- write_binary --

    #[test]
    fn write_binary_and_readback() {
        let mut s = store();
        s.write_binary(&EF_T, 1, &[0xAA, 0xBB]).unwrap();
        assert_eq!(
            s.read_binary(&EF_T, 0, 5).unwrap(),
            &[0x01, 0xAA, 0xBB, 0x04, 0x05]
        );
    }

    #[test]
    fn write_binary_full_overwrite() {
        let mut s = store();
        s.write_binary(&EF_T, 0, &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4])
            .unwrap();
        assert_eq!(
            s.read_binary(&EF_T, 0, 5).unwrap(),
            &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4]
        );
    }

    #[test]
    fn write_binary_past_end() {
        let mut s = store();
        assert_eq!(
            s.write_binary(&EF_T, 4, &[0xAA, 0xBB]),
            Err(FsError::OffsetOutOfRange)
        );
    }

    #[test]
    fn write_binary_on_record_ef() {
        let mut s = store();
        assert_eq!(
            s.write_binary(&EF_LF, 0, &[0x00]),
            Err(FsError::NotTransparent)
        );
    }

    #[test]
    fn write_does_not_affect_other_efs() {
        let mut s = store();
        let rec1_before = s.read_record(&EF_LF, 1).unwrap().to_vec();
        s.write_binary(&EF_T, 0, &[0xFF; 5]).unwrap();
        let rec1_after = s.read_record(&EF_LF, 1).unwrap();
        assert_eq!(rec1_before, rec1_after);
    }

    // -- write_record --

    #[test]
    fn write_record_and_readback() {
        let mut s = store();
        s.write_record(&EF_LF, 2, &[0xCC, 0xDD, 0xEE, 0xFF])
            .unwrap();
        assert_eq!(
            s.read_record(&EF_LF, 2).unwrap(),
            &[0xCC, 0xDD, 0xEE, 0xFF]
        );
        // Record 1 unchanged.
        assert_eq!(
            s.read_record(&EF_LF, 1).unwrap(),
            &[0x0A, 0x0B, 0x0C, 0x0D]
        );
    }

    #[test]
    fn write_record_wrong_size() {
        let mut s = store();
        assert_eq!(
            s.write_record(&EF_LF, 1, &[0x00, 0x01]),
            Err(FsError::DataTooLarge)
        );
    }

    #[test]
    fn write_record_out_of_range() {
        let mut s = store();
        assert_eq!(
            s.write_record(&EF_LF, 0, &[0x00; 4]),
            Err(FsError::RecordOutOfRange)
        );
        assert_eq!(
            s.write_record(&EF_LF, 3, &[0x00; 4]),
            Err(FsError::RecordOutOfRange)
        );
    }

    #[test]
    fn write_record_on_transparent() {
        let mut s = store();
        assert_eq!(
            s.write_record(&EF_T, 1, &[0x00]),
            Err(FsError::NotRecordBased)
        );
    }

    #[test]
    fn write_record_cyclic() {
        let mut s = store();
        s.write_record(&EF_CY, 1, &[0xCC, 0xDD, 0xEE]).unwrap();
        assert_eq!(
            s.read_record(&EF_CY, 1).unwrap(),
            &[0xCC, 0xDD, 0xEE]
        );
    }

    // -- increase --

    #[test]
    fn increase_basic() {
        let mut s = store();
        // EF_CY record 1 = [0xA1, 0xA2, 0xA3]
        let result = s.increase(&EF_CY, &[0x00, 0x00, 0x01]).unwrap();
        assert_eq!(result, &[0xA1, 0xA2, 0xA4]);
    }

    #[test]
    fn increase_with_carry() {
        let mut s = store();
        // EF_CY record 1 = [0xA1, 0xA2, 0xA3], add [0x00, 0x00, 0xFF]
        let result = s.increase(&EF_CY, &[0x00, 0x00, 0xFF]).unwrap();
        // 0xA3 + 0xFF = 0x1A2, carry 1 to next byte: 0xA2+1 = 0xA3
        assert_eq!(result, &[0xA1, 0xA3, 0xA2]);
    }

    #[test]
    fn increase_short_value() {
        let mut s = store();
        // Add single byte [0x05] to 3-byte record [0xA1, 0xA2, 0xA3]
        let result = s.increase(&EF_CY, &[0x05]).unwrap();
        assert_eq!(result, &[0xA1, 0xA2, 0xA8]);
    }

    #[test]
    fn increase_on_transparent_fails() {
        let mut s = store();
        assert_eq!(
            s.increase(&EF_T, &[0x01]),
            Err(FsError::NotRecordBased)
        );
    }

    #[test]
    fn increase_on_linear_fixed_fails() {
        let mut s = store();
        assert_eq!(
            s.increase(&EF_LF, &[0x01]),
            Err(FsError::NotRecordBased)
        );
    }

    #[test]
    fn increase_value_too_large() {
        let mut s = store();
        // EF_CY has record_size=3, try adding 4 bytes
        assert_eq!(
            s.increase(&EF_CY, &[0x01, 0x02, 0x03, 0x04]),
            Err(FsError::DataTooLarge)
        );
    }

    #[test]
    fn increase_readback_matches() {
        let mut s = store();
        let result = s.increase(&EF_CY, &[0x00, 0x01, 0x00]).unwrap().to_vec();
        // Verify it persists via read_record
        let rec = s.read_record(&EF_CY, 1).unwrap();
        assert_eq!(result, rec);
    }

    #[test]
    fn increase_overflow_returns_error() {
        let mut s = store();
        // EF_CY record 1 = [0xA1, 0xA2, 0xA3] (3 bytes, max = 0xFFFFFF).
        // Adding 0xFFFFFF - 0xA1A2A3 + 1 = 0x5E5D5D will overflow.
        // First, set record to max: add (0xFF - 0xA1, 0xFF - 0xA2, 0xFF - 0xA3)
        // = (0x5E, 0x5D, 0x5C)
        let result = s.increase(&EF_CY, &[0x5E, 0x5D, 0x5C]).unwrap();
        assert_eq!(result, &[0xFF, 0xFF, 0xFF]);
        // Now any further increase should overflow.
        assert_eq!(
            s.increase(&EF_CY, &[0x00, 0x00, 0x01]),
            Err(FsError::IncreaseOverflow)
        );
        // Verify the record is unchanged after overflow.
        let rec = s.read_record(&EF_CY, 1).unwrap();
        assert_eq!(rec, &[0xFF, 0xFF, 0xFF]);
    }

    // -- snapshot --

    #[test]
    fn snapshot_roundtrip_preserves_writes() {
        let mut s = store();
        s.write_binary(&EF_T, 0, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
            .unwrap();
        s.write_record(&EF_LF, 1, &[0x11, 0x22, 0x33, 0x44])
            .unwrap();

        // Save.
        let mut snap = [0u8; 64];
        let n = s.save_state(&mut snap);
        assert_eq!(n, 64);

        // Create fresh store, init, then restore.
        let mut s2 = FsData::<64, 8>::new();
        s2.init(&MF).unwrap();
        assert!(s2.restore_state(&snap));

        // Verify writes survived.
        assert_eq!(
            s2.read_binary(&EF_T, 0, 5).unwrap(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
        );
        assert_eq!(
            s2.read_record(&EF_LF, 1).unwrap(),
            &[0x11, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn snapshot_small_buffer() {
        let s = store();
        let mut small = [0u8; 4];
        assert_eq!(s.save_state(&mut small), 0);

        let mut s2 = store();
        assert!(!s2.restore_state(&small));
    }

    // -- FID collision: same FID under different DFs --

    #[test]
    fn fid_collision_uses_pointer_identity() {
        static EF_A: EfDef = EfDef::transparent(
            Fid::new(0x6F07),
            None,
            &[0xAA, 0xBB],
        );
        static EF_B: EfDef = EfDef::transparent(
            Fid::new(0x6F07), // same FID, different static
            None,
            &[0xCC, 0xDD],
        );
        static DF_A: DfDef = DfDef {
            fid: Fid::new(0x7F20),
            children: &[FileRef::Ef(&EF_A)],
        };
        static DF_B: DfDef = DfDef {
            fid: Fid::new(0x7F21),
            children: &[FileRef::Ef(&EF_B)],
        };
        static ROOT: DfDef = DfDef {
            fid: Fid::new(0x3F00),
            children: &[FileRef::Df(&DF_A), FileRef::Df(&DF_B)],
        };

        let mut s = FsData::<64, 8>::new();
        s.init(&ROOT).unwrap();

        // Both EFs are tracked separately despite same FID.
        assert_eq!(s.read_binary(&EF_A, 0, 2).unwrap(), &[0xAA, 0xBB]);
        assert_eq!(s.read_binary(&EF_B, 0, 2).unwrap(), &[0xCC, 0xDD]);

        // Writing to one doesn't affect the other.
        s.write_binary(&EF_A, 0, &[0x11, 0x22]).unwrap();
        assert_eq!(s.read_binary(&EF_A, 0, 2).unwrap(), &[0x11, 0x22]);
        assert_eq!(s.read_binary(&EF_B, 0, 2).unwrap(), &[0xCC, 0xDD]);
    }

    // -- BER-TLV EF structure --

    #[test]
    fn ber_tlv_ef_can_be_created() {
        static EF_BT: EfDef = EfDef::ber_tlv(
            Fid::new(0x6F42),
            None,
            &[0xC0, 0x03, 0x01, 0x02, 0x03],
        );
        assert!(matches!(EF_BT.structure(), EfStructure::BerTlv));
        assert_eq!(EF_BT.fid(), Fid::new(0x6F42));
    }

    #[test]
    fn ber_tlv_ef_supports_binary_read_write() {
        static EF_BT: EfDef = EfDef::ber_tlv(
            Fid::new(0x6F42),
            None,
            &[0xC0, 0x03, 0x01, 0x02, 0x03],
        );
        static BT_MF: DfDef = DfDef {
            fid: Fid::new(0x3F00),
            children: &[FileRef::Ef(&EF_BT)],
        };

        let mut s = FsData::<64, 8>::new();
        s.init(&BT_MF).unwrap();

        // BER-TLV EFs support binary read (like transparent).
        let data = s.read_binary(&EF_BT, 0, 5).unwrap();
        assert_eq!(data, &[0xC0, 0x03, 0x01, 0x02, 0x03]);

        // Binary write also works.
        s.write_binary(&EF_BT, 0, &[0xD1, 0x02, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(
            s.read_binary(&EF_BT, 0, 5).unwrap(),
            &[0xD1, 0x02, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn ber_tlv_ef_rejects_record_operations() {
        static EF_BT: EfDef = EfDef::ber_tlv(
            Fid::new(0x6F42),
            None,
            &[0xC0, 0x03, 0x01, 0x02, 0x03],
        );
        static BT_MF: DfDef = DfDef {
            fid: Fid::new(0x3F00),
            children: &[FileRef::Ef(&EF_BT)],
        };

        let mut s = FsData::<64, 8>::new();
        s.init(&BT_MF).unwrap();

        assert_eq!(s.read_record(&EF_BT, 1), Err(FsError::NotRecordBased));
        assert_eq!(
            s.write_record(&EF_BT, 1, &[0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(FsError::NotRecordBased)
        );
        assert_eq!(s.increase(&EF_BT, &[0x01]), Err(FsError::NotRecordBased));
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Reuse the test filesystem from the unit tests module.
    // Since statics can't be shared across test modules easily,
    // we define minimal fixtures inline.

    static PT_EF: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        None,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    );

    static PT_EF_LF: EfDef = EfDef::linear_fixed(
        Fid::new(0x2F00),
        None,
        4, 2,
        &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11],
    );

    static PT_MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&PT_EF), FileRef::Ef(&PT_EF_LF)],
    };

    const _: () = assert_fids_unique(&[
        0x2FE2, // PT_EF
        0x2F00, // PT_EF_LF
    ]);

    proptest! {
        // Any valid offset+length within file size succeeds.
        #[test]
        fn read_binary_in_bounds(offset in 0u16..8, len in 0u16..=8u16) {
            prop_assume!(offset + len <= 8);
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(Fid::new(0x2FE2)).unwrap();
            let data = c.read_binary(offset, len).unwrap();
            prop_assert_eq!(data.len(), len as usize);
        }

        // Any offset+length exceeding file size fails with OffsetOutOfRange.
        #[test]
        fn read_binary_out_of_bounds(offset in 0u16..=8, len in 1u16..=8) {
            prop_assume!(offset + len > 8);
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(Fid::new(0x2FE2)).unwrap();
            prop_assert_eq!(c.read_binary(offset, len), Err(FsError::OffsetOutOfRange));
        }

        // Valid record numbers (1..=num_records) succeed.
        #[test]
        fn read_record_in_bounds(num in 1u8..=2) {
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(Fid::new(0x2F00)).unwrap();
            let rec = c.read_record(num).unwrap();
            prop_assert_eq!(rec.len(), 4);
        }

        // Invalid record numbers fail.
        #[test]
        fn read_record_out_of_bounds(num in 3u8..=255) {
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(Fid::new(0x2F00)).unwrap();
            prop_assert_eq!(c.read_record(num), Err(FsError::RecordOutOfRange));
        }
    }
}
