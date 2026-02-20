//! ICC filesystem model: MF, DF, ADF, and EF nodes.
//!
//! Provides a hierarchical, `const`-static filesystem tree matching the UICC
//! file system per ETSI TS 102 221. Elementary files (EFs) come in three
//! structures: transparent (binary), linear fixed (records), and cyclic.
//! The [`SelectionCtx`] tracks the current MF, DF, ADF, and EF across
//! SELECT operations.
//!
//! # Filesystem Tree
//!
//! The tree is defined as nested `const`/`static` items -- no runtime
//! allocation. EF content is `&'static [u8]`, supplied by the consuming
//! crate (e.g. `simrs-gsm`, `simrs-usim`).
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
//! - ETSI TS 102 221 V16.4.0 clause 8 -- File system structure
//! - ETSI TS 102 221 V16.4.0 clause 11.1.1 -- SELECT
//! - 3GPP TS 31.102 V17.5.0 clause 4 -- USIM file system
//! - GSM 11.11 v4.21.1 clause 10 -- SIM file system
//!
//! # `no_std`
//! This crate is `no_std`. The filesystem can be defined as `const` statics.
//!
//! # Example
//!
//! ```
//! use simrs_fs::{DfDef, EfDef, EfStructure, FileRef, SelectionCtx, FsError};
//!
//! static EF_ICCID: EfDef = EfDef {
//!     fid: 0x2FE2,
//!     sfi: Some(2),
//!     structure: EfStructure::Transparent,
//!     data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
//! };
//!
//! static MF: DfDef = DfDef {
//!     fid: 0x3F00,
//!     children: &[FileRef::Ef(&EF_ICCID)],
//! };
//!
//! let mut ctx = SelectionCtx::new(&MF);
//! ctx.select_by_fid(0x2FE2).unwrap();
//! let data = ctx.read_binary(0, 10).unwrap();
//! assert_eq!(data, &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]);
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Two-byte file identifier per ETSI TS 102 221 clause 8.2.
pub type Fid = u16;

/// Reserved FID: Master File.
pub const FID_MF: Fid = 0x3F00;
/// Reserved FID: reselect current ADF.
pub const FID_CUR_ADF: Fid = 0x7FFF;

/// Elementary file internal structure per ETSI TS 102 221 clause 8.3.
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
/// use simrs_fs::{EfDef, EfStructure};
/// static EF: EfDef = EfDef {
///     fid: 0x6F07,
///     sfi: Some(7),
///     structure: EfStructure::Transparent,
///     data: &[0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0xF0],
/// };
/// assert_eq!(EF.fid, 0x6F07);
/// ```
#[derive(Debug)]
pub struct EfDef {
    /// File identifier (2 bytes).
    pub fid: Fid,
    /// Short file identifier (1--30), or `None` if not assigned.
    pub sfi: Option<u8>,
    /// Internal structure (transparent, linear-fixed, or cyclic).
    pub structure: EfStructure,
    /// Raw file content. For record-based files: `record_size * num_records` bytes.
    pub data: &'static [u8],
}

/// Definition of a Dedicated File (DF) or Master File (MF).
///
/// Children are referenced by `&'static` pointers, enabling fully
/// `const`-static filesystem trees.
///
/// # Example
///
/// ```
/// use simrs_fs::{DfDef, EfDef, EfStructure, FileRef};
/// static EF: EfDef = EfDef {
///     fid: 0x2FE2,
///     sfi: None,
///     structure: EfStructure::Transparent,
///     data: &[0xFF; 10],
/// };
/// static DF: DfDef = DfDef {
///     fid: 0x7F20,
///     children: &[FileRef::Ef(&EF)],
/// };
/// assert_eq!(DF.fid, 0x7F20);
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
/// use simrs_fs::{FileRef, EfDef, DfDef, EfStructure};
/// static EF: EfDef = EfDef {
///     fid: 0x2FE2, sfi: None,
///     structure: EfStructure::Transparent, data: &[0xFF; 10],
/// };
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
/// use simrs_fs::{AdfSlot, DfDef};
/// static ADF_ROOT: DfDef = DfDef { fid: 0xFF01, children: &[] };
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
}

// ---------------------------------------------------------------------------
// SelectionCtx
// ---------------------------------------------------------------------------

/// Virtual selection context tracking the current MF, DF, ADF, and EF.
///
/// Mirrors the UICC file selection state per ETSI TS 102 221 clause 8.4.
/// Constructed with a reference to the MF root; initial DF is MF.
///
/// # Example
///
/// ```
/// use simrs_fs::{SelectionCtx, DfDef, EfDef, EfStructure, FileRef};
///
/// static EF: EfDef = EfDef {
///     fid: 0x2FE2, sfi: None,
///     structure: EfStructure::Transparent,
///     data: &[0x98, 0x10],
/// };
/// static MF: DfDef = DfDef { fid: 0x3F00, children: &[FileRef::Ef(&EF)] };
///
/// let mut ctx = SelectionCtx::new(&MF);
/// let sel = ctx.select_by_fid(0x2FE2).unwrap();
/// assert_eq!(sel.fid(), 0x2FE2);
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
    /// use simrs_fs::{SelectionCtx, DfDef};
    /// static MF: DfDef = DfDef { fid: 0x3F00, children: &[] };
    /// let ctx = SelectionCtx::new(&MF);
    /// assert_eq!(ctx.current_df().fid, 0x3F00);
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
        if fid == FID_MF {
            self.cur_df = self.mf;
            self.cur_ef = None;
            self.cur_adf = None;
            return Ok(SelectedFile::Df(self.mf));
        }
        // 0x7FFF: reselect current ADF.
        if fid == FID_CUR_ADF {
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
        if !matches!(ef.structure, EfStructure::Transparent) {
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
        let (record_size, num_records) = match ef.structure {
            EfStructure::LinearFixed {
                record_size,
                num_records,
            }
            | EfStructure::Cyclic {
                record_size,
                num_records,
            } => (record_size, num_records),
            EfStructure::Transparent => return Err(FsError::NotRecordBased),
        };
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

    // -- snapshot --

    /// Snapshot buffer size: 8 bytes.
    ///
    /// Layout: `cur_df` FID (2 LE) + `cur_ef` FID or `0xFFFF` (2 LE) +
    /// `cur_adf` FID or `0xFFFF` (2 LE) + reserved (2).
    pub const SNAPSHOT_SIZE: usize = 8;

    /// Serialize the selection state into `buf` as flat LE bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        buf[0..2].copy_from_slice(&self.cur_df.fid.to_le_bytes());
        buf[2..4].copy_from_slice(&self.cur_ef.map_or(0xFFFF_u16, |ef| ef.fid).to_le_bytes());
        buf[4..6].copy_from_slice(&self.cur_adf.map_or(0xFFFF_u16, |adf| adf.fid).to_le_bytes());
        buf[6] = 0;
        buf[7] = 0;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the selection state from `buf`.
    ///
    /// Walks the MF tree and ADF table to resolve FIDs back to
    /// `&'static` references. Returns `true` on success.
    pub fn restore_state(
        &mut self,
        buf: &[u8],
        adfs: &'static [AdfSlot],
    ) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let df_fid = u16::from(buf[0]) | (u16::from(buf[1]) << 8);
        let ef_fid = u16::from(buf[2]) | (u16::from(buf[3]) << 8);
        let adf_fid = u16::from(buf[4]) | (u16::from(buf[5]) << 8);

        // Resolve cur_adf.
        if adf_fid == 0xFFFF {
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
        if ef_fid == 0xFFFF {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test filesystem tree --

    static EF_ICCID: EfDef = EfDef {
        fid: 0x2FE2,
        sfi: Some(2),
        structure: EfStructure::Transparent,
        data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    };

    static EF_DIR_DATA: [u8; 16] = [
        // Record 1: 8 bytes
        0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00,
        // Record 2: 8 bytes
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_DIR: EfDef = EfDef {
        fid: 0x2F00,
        sfi: Some(30),
        structure: EfStructure::LinearFixed {
            record_size: 8,
            num_records: 2,
        },
        data: &EF_DIR_DATA,
    };

    static EF_ADN_DATA: [u8; 42] = [
        // Record 1
        0x41, 0x6C, 0x69, 0x63, 0x65, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        // Record 2
        0x42, 0x6F, 0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        // Record 3
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_ADN: EfDef = EfDef {
        fid: 0x6F3A,
        sfi: None,
        structure: EfStructure::LinearFixed {
            record_size: 14,
            num_records: 3,
        },
        data: &EF_ADN_DATA,
    };

    static DF_TELECOM: DfDef = DfDef {
        fid: 0x7F10,
        children: &[FileRef::Ef(&EF_ADN)],
    };

    static EF_GSM_IMSI: EfDef = EfDef {
        fid: 0x6F07,
        sfi: Some(7),
        structure: EfStructure::Transparent,
        data: &[0x08, 0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
    };

    static EF_KC: EfDef = EfDef {
        fid: 0x6F20,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &[0xFF; 9],
    };

    static DF_GSM: DfDef = DfDef {
        fid: 0x7F20,
        children: &[FileRef::Ef(&EF_GSM_IMSI), FileRef::Ef(&EF_KC)],
    };

    static MF: DfDef = DfDef {
        fid: 0x3F00,
        children: &[
            FileRef::Ef(&EF_ICCID),
            FileRef::Ef(&EF_DIR),
            FileRef::Df(&DF_TELECOM),
            FileRef::Df(&DF_GSM),
        ],
    };

    // ADF for USIM
    static EF_USIM_IMSI: EfDef = EfDef {
        fid: 0x6F07,
        sfi: Some(7),
        structure: EfStructure::Transparent,
        data: &[0x08, 0x29, 0x43, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
    };

    static ADF_USIM_ROOT: DfDef = DfDef {
        fid: 0xFF01,
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

    static EF_CYCLIC: EfDef = EfDef {
        fid: 0x6F4A,
        sfi: None,
        structure: EfStructure::Cyclic {
            record_size: 4,
            num_records: 3,
        },
        data: &EF_CYCLIC_DATA,
    };

    static DF_TELECOM_WITH_CYCLIC: DfDef = DfDef {
        fid: 0x7F10,
        children: &[FileRef::Ef(&EF_ADN), FileRef::Ef(&EF_CYCLIC)],
    };

    static MF_WITH_CYCLIC: DfDef = DfDef {
        fid: 0x3F00,
        children: &[
            FileRef::Ef(&EF_ICCID),
            FileRef::Ef(&EF_DIR),
            FileRef::Df(&DF_TELECOM_WITH_CYCLIC),
            FileRef::Df(&DF_GSM),
        ],
    };

    fn ctx() -> SelectionCtx {
        SelectionCtx::new(&MF)
    }

    // -- SELECT by FID tests --

    #[test]
    fn select_mf_resets_context() {
        let mut c = ctx();
        // Navigate into DF.GSM and select an EF.
        c.select_by_fid(0x7F20).unwrap();
        c.select_by_fid(0x6F07).unwrap();
        assert!(c.current_ef().is_some());
        // Select MF resets everything.
        c.select_by_fid(FID_MF).unwrap();
        assert_eq!(c.current_df().fid, 0x3F00);
        assert!(c.current_ef().is_none());
        assert!(c.current_adf().is_none());
    }

    #[test]
    fn select_ef_under_mf() {
        let mut c = ctx();
        let sel = c.select_by_fid(0x2FE2).unwrap();
        assert_eq!(sel.fid(), 0x2FE2);
        assert!(matches!(sel, SelectedFile::Ef(_)));
        assert_eq!(c.current_df().fid, 0x3F00); // DF unchanged
    }

    #[test]
    fn select_df_under_mf() {
        let mut c = ctx();
        let sel = c.select_by_fid(0x7F20).unwrap();
        assert_eq!(sel.fid(), 0x7F20);
        assert!(matches!(sel, SelectedFile::Df(_)));
        assert_eq!(c.current_df().fid, 0x7F20);
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn select_ef_under_df() {
        let mut c = ctx();
        c.select_by_fid(0x7F20).unwrap();
        let sel = c.select_by_fid(0x6F07).unwrap();
        assert_eq!(sel.fid(), 0x6F07);
        assert_eq!(c.current_df().fid, 0x7F20); // DF unchanged
    }

    #[test]
    fn select_nonexistent_fid() {
        let mut c = ctx();
        assert_eq!(
            c.select_by_fid(0xFFFF),
            Err(FsError::FileNotFound)
        );
    }

    #[test]
    fn select_child_not_in_current_df() {
        let mut c = ctx();
        // 0x6F07 is under DF.GSM, not MF.
        assert_eq!(
            c.select_by_fid(0x6F07),
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
        c.select_by_fid(0x6F07).unwrap();
        // 0x7FFF reselects the ADF root.
        let sel = c.select_by_fid(FID_CUR_ADF).unwrap();
        assert!(matches!(sel, SelectedFile::Df(_)));
        assert_eq!(sel.fid(), 0xFF01);
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn select_7fff_with_no_adf() {
        let mut c = ctx();
        assert_eq!(
            c.select_by_fid(FID_CUR_ADF),
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
        assert_eq!(sel.fid(), 0xFF01);
        assert!(c.current_adf().is_some());
        assert_eq!(c.current_df().fid, 0xFF01);
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn select_by_partial_aid() {
        let mut c = ctx();
        let sel = c
            .select_by_aid(&[0xA0, 0x00, 0x00, 0x00, 0x87], &ADF_TABLE)
            .unwrap();
        assert_eq!(sel.fid(), 0xFF01);
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
        c.select_by_fid(0x2FE2).unwrap();
        let data = c.read_binary(0, 10).unwrap();
        assert_eq!(
            data,
            &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]
        );
    }

    #[test]
    fn read_binary_partial() {
        let mut c = ctx();
        c.select_by_fid(0x2FE2).unwrap();
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
        c.select_by_fid(0x2F00).unwrap(); // EF.DIR is linear-fixed
        assert_eq!(c.read_binary(0, 1), Err(FsError::NotTransparent));
    }

    #[test]
    fn read_binary_past_end() {
        let mut c = ctx();
        c.select_by_fid(0x2FE2).unwrap();
        assert_eq!(c.read_binary(8, 5), Err(FsError::OffsetOutOfRange));
    }

    #[test]
    fn read_binary_zero_length() {
        let mut c = ctx();
        c.select_by_fid(0x2FE2).unwrap();
        let data = c.read_binary(5, 0).unwrap();
        assert!(data.is_empty());
    }

    // -- READ RECORD tests --

    #[test]
    fn read_record_first() {
        let mut c = ctx();
        c.select_by_fid(0x7F10).unwrap(); // DF.TELECOM
        c.select_by_fid(0x6F3A).unwrap(); // EF.ADN
        let rec = c.read_record(1).unwrap();
        assert_eq!(rec.len(), 14);
        assert_eq!(rec[0], 0x41); // 'A'
    }

    #[test]
    fn read_record_second() {
        let mut c = ctx();
        c.select_by_fid(0x7F10).unwrap();
        c.select_by_fid(0x6F3A).unwrap();
        let rec = c.read_record(2).unwrap();
        assert_eq!(rec.len(), 14);
        assert_eq!(rec[0], 0x42); // 'B'
    }

    #[test]
    fn read_record_third() {
        let mut c = ctx();
        c.select_by_fid(0x7F10).unwrap();
        c.select_by_fid(0x6F3A).unwrap();
        let rec = c.read_record(3).unwrap();
        assert_eq!(rec.len(), 14);
        assert_eq!(rec[0], 0xFF); // empty record
    }

    #[test]
    fn read_record_zero_invalid() {
        let mut c = ctx();
        c.select_by_fid(0x7F10).unwrap();
        c.select_by_fid(0x6F3A).unwrap();
        assert_eq!(c.read_record(0), Err(FsError::RecordOutOfRange));
    }

    #[test]
    fn read_record_beyond_last() {
        let mut c = ctx();
        c.select_by_fid(0x7F10).unwrap();
        c.select_by_fid(0x6F3A).unwrap();
        assert_eq!(c.read_record(4), Err(FsError::RecordOutOfRange));
    }

    #[test]
    fn read_record_on_transparent() {
        let mut c = ctx();
        c.select_by_fid(0x2FE2).unwrap();
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
        c.select_by_fid(0x2F00).unwrap(); // EF.DIR
        let rec = c.read_record(1).unwrap();
        assert_eq!(rec.len(), 8);
        assert_eq!(rec[0], 0x61);
    }

    // -- Navigation sequence tests --

    #[test]
    fn navigate_mf_df_ef_mf_roundtrip() {
        let mut c = ctx();
        c.select_by_fid(0x7F20).unwrap();
        assert_eq!(c.current_df().fid, 0x7F20);
        c.select_by_fid(0x6F07).unwrap();
        assert!(c.current_ef().is_some());
        c.select_by_fid(FID_MF).unwrap();
        assert_eq!(c.current_df().fid, 0x3F00);
        assert!(c.current_ef().is_none());
    }

    #[test]
    fn adf_ef_has_different_data_from_gsm_ef() {
        let mut c = ctx();
        // Select GSM IMSI.
        c.select_by_fid(0x7F20).unwrap();
        c.select_by_fid(0x6F07).unwrap();
        let gsm_imsi = c.read_binary(0, 9).unwrap();

        // Select USIM IMSI via AID.
        c.select_by_aid(
            &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
            &ADF_TABLE,
        )
        .unwrap();
        c.select_by_fid(0x6F07).unwrap();
        let usim_imsi = c.read_binary(0, 9).unwrap();

        // Same FID, different data.
        assert_ne!(gsm_imsi, usim_imsi);
    }

    #[test]
    fn read_record_from_cyclic_ef() {
        let mut c = SelectionCtx::new(&MF_WITH_CYCLIC);
        c.select_by_fid(0x7F10).unwrap(); // DF.TELECOM
        c.select_by_fid(0x6F4A).unwrap(); // EF_CYCLIC
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
        let sel1 = c.select_by_fid(0x2FE2).unwrap();
        let sel2 = c.select_by_fid(0x2FE2).unwrap();
        assert_eq!(sel1, sel2);
    }

    #[test]
    fn selected_file_df_vs_ef_not_equal() {
        let mut c1 = ctx();
        let mut c2 = ctx();
        let df = c1.select_by_fid(0x7F20).unwrap();
        let ef = c2.select_by_fid(0x2FE2).unwrap();
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
        restored.select_by_fid(0x7F20).unwrap();
        assert!(restored.restore_state(&buf, &[]));
        assert_eq!(restored.current_df().fid, 0x3F00);
        assert!(restored.current_ef().is_none());
        assert!(restored.current_adf().is_none());
    }

    #[test]
    fn snapshot_save_restore_df_and_ef() {
        let mut c = ctx();
        c.select_by_fid(0x7F20).unwrap();
        c.select_by_fid(0x6F07).unwrap();

        let mut buf = [0u8; SelectionCtx::SNAPSHOT_SIZE];
        c.save_state(&mut buf);

        let mut restored = SelectionCtx::new(&MF);
        assert!(restored.restore_state(&buf, &[]));
        assert_eq!(restored.current_df().fid, 0x7F20);
        assert_eq!(restored.current_ef().unwrap().fid, 0x6F07);
    }

    #[test]
    fn snapshot_save_restore_adf() {
        let mut c = ctx();
        c.select_by_aid(
            &[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
            &ADF_TABLE,
        )
        .unwrap();
        c.select_by_fid(0x6F07).unwrap();

        let mut buf = [0u8; SelectionCtx::SNAPSHOT_SIZE];
        c.save_state(&mut buf);

        let mut restored = SelectionCtx::new(&MF);
        assert!(restored.restore_state(&buf, &ADF_TABLE));
        assert!(restored.current_adf().is_some());
        assert_eq!(restored.current_df().fid, 0xFF01);
        assert_eq!(restored.current_ef().unwrap().fid, 0x6F07);
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

    static PT_EF: EfDef = EfDef {
        fid: 0x2FE2,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };

    static PT_EF_LF: EfDef = EfDef {
        fid: 0x2F00,
        sfi: None,
        structure: EfStructure::LinearFixed {
            record_size: 4,
            num_records: 2,
        },
        data: &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11],
    };

    static PT_MF: DfDef = DfDef {
        fid: 0x3F00,
        children: &[FileRef::Ef(&PT_EF), FileRef::Ef(&PT_EF_LF)],
    };

    proptest! {
        // Any valid offset+length within file size succeeds.
        #[test]
        fn read_binary_in_bounds(offset in 0u16..8, len in 0u16..=8u16) {
            prop_assume!(offset + len <= 8);
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(0x2FE2).unwrap();
            let data = c.read_binary(offset, len).unwrap();
            prop_assert_eq!(data.len(), len as usize);
        }

        // Any offset+length exceeding file size fails with OffsetOutOfRange.
        #[test]
        fn read_binary_out_of_bounds(offset in 0u16..=8, len in 1u16..=8) {
            prop_assume!(offset + len > 8);
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(0x2FE2).unwrap();
            prop_assert_eq!(c.read_binary(offset, len), Err(FsError::OffsetOutOfRange));
        }

        // Valid record numbers (1..=num_records) succeed.
        #[test]
        fn read_record_in_bounds(num in 1u8..=2) {
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(0x2F00).unwrap();
            let rec = c.read_record(num).unwrap();
            prop_assert_eq!(rec.len(), 4);
        }

        // Invalid record numbers fail.
        #[test]
        fn read_record_out_of_bounds(num in 3u8..=255) {
            let mut c = SelectionCtx::new(&PT_MF);
            c.select_by_fid(0x2F00).unwrap();
            prop_assert_eq!(c.read_record(num), Err(FsError::RecordOutOfRange));
        }
    }
}
