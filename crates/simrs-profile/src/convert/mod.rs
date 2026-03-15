//! Profile-to-simrs conversion layer.
//!
//! Converts parsed TCA Profile Elements into simrs filesystem types
//! (`DfDef`, `EfDef`, `AdfSlot`) using a `MutableTree` intermediate
//! representation that is frozen via `Box::leak` into `&'static` refs.

pub mod auth;
pub mod pin;

use crate::error::ProfileError;
use crate::file::File;
use crate::pe::{PeMf, PeUsim};
use simrs_fs::{AdfSlot, DfDef, EfDef, EfStructure, Fid, FileRef, Sfi};

/// USIM AID prefix (A0000000871002).
const USIM_AID_PREFIX: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

/// ISIM AID prefix (A0000000871004).
const ISIM_AID_PREFIX: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04];

/// CSIM AID prefix (A0000003431002).
const CSIM_AID_PREFIX: [u8; 7] = [0xA0, 0x00, 0x00, 0x03, 0x43, 0x10, 0x02];

/// A mutable filesystem tree under construction.
///
/// Profile Elements are applied to this tree incrementally. Once all
/// PEs have been processed, the tree is frozen into `&'static` references
/// via [`MutableTree::freeze`].
pub struct MutableTree {
    mf: Option<MutableDf>,
    adfs: Vec<(Vec<u8>, MutableDf)>,
}

struct MutableDf {
    fid: Fid,
    children: Vec<MutableChild>,
}

enum MutableChild {
    Ef(MutableEf),
    Df(MutableDf),
}

struct MutableEf {
    fid: Fid,
    sfi: Option<Sfi>,
    structure: EfStructure,
    data: Vec<u8>,
}

impl Default for MutableTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MutableTree {
    /// Create an empty tree.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mf: None,
            adfs: Vec::new(),
        }
    }

    /// Apply PE-MF: create the MF with its direct EF children.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file FCP is missing or malformed.
    pub fn apply_mf(&mut self, pe: &PeMf) -> Result<(), ProfileError> {
        let mut children = Vec::new();

        // EF.ICCID
        if let Some(ef) = Self::file_to_ef(&pe.ef_iccid)? {
            children.push(MutableChild::Ef(ef));
        }

        // EF.DIR
        if let Some(ef) = Self::file_to_ef(&pe.ef_dir)? {
            children.push(MutableChild::Ef(ef));
        }

        // EF.ARR
        if let Some(ef) = Self::file_to_ef(&pe.ef_arr)? {
            children.push(MutableChild::Ef(ef));
        }

        // EF.PL (optional)
        if let Some(ref f) = pe.ef_pl {
            if let Some(ef) = Self::file_to_ef(f)? {
                children.push(MutableChild::Ef(ef));
            }
        }

        // EF.UMPC (optional)
        if let Some(ref f) = pe.ef_umpc {
            if let Some(ef) = Self::file_to_ef(f)? {
                children.push(MutableChild::Ef(ef));
            }
        }

        self.mf = Some(MutableDf {
            fid: Fid::MF,
            children,
        });

        Ok(())
    }

    /// Apply PE-USIM: create ADF.USIM with its EF children.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file FCP is missing or malformed.
    pub fn apply_usim(&mut self, pe: &PeUsim) -> Result<(), ProfileError> {
        let mut children = Vec::new();

        // Process each named file field.
        macro_rules! add_required {
            ($field:expr) => {
                if let Some(ef) = Self::file_to_ef(&$field)? {
                    children.push(MutableChild::Ef(ef));
                }
            };
        }
        macro_rules! add_optional {
            ($field:expr) => {
                if let Some(ref f) = $field {
                    if let Some(ef) = Self::file_to_ef(f)? {
                        children.push(MutableChild::Ef(ef));
                    }
                }
            };
        }

        add_required!(pe.ef_imsi);
        add_required!(pe.ef_arr);
        add_optional!(pe.ef_keys);
        add_optional!(pe.ef_keys_ps);
        add_optional!(pe.ef_hpplmn);
        add_required!(pe.ef_ust);
        add_optional!(pe.ef_fdn);
        add_optional!(pe.ef_sms);
        add_optional!(pe.ef_smsp);
        add_optional!(pe.ef_smss);
        add_required!(pe.ef_spn);
        add_required!(pe.ef_est);
        add_optional!(pe.ef_start_hfn);
        add_optional!(pe.ef_threshold);
        add_optional!(pe.ef_psloci);
        add_required!(pe.ef_acc);
        add_optional!(pe.ef_fplmn);
        add_optional!(pe.ef_loci);
        add_optional!(pe.ef_ad);
        add_required!(pe.ef_ecc);
        add_optional!(pe.ef_netpar);
        add_optional!(pe.ef_epsloci);
        add_optional!(pe.ef_epsnsc);

        // Extra files
        for (_tag, f) in &pe.extra_files {
            if let Some(ef) = Self::file_to_ef(f)? {
                children.push(MutableChild::Ef(ef));
            }
        }

        // Extract AID from ADF FCP.
        let aid = pe
            .adf_usim
            .fcp
            .as_ref()
            .and_then(|fcp| fcp.df_name.clone())
            .unwrap_or_else(|| vec![0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);

        let adf_fid = pe
            .adf_usim
            .fcp
            .as_ref()
            .and_then(|fcp| fcp.parse_fid().ok())
            .unwrap_or(Fid::from_raw(0xFF01));

        self.adfs.push((
            aid,
            MutableDf {
                fid: adf_fid,
                children,
            },
        ));

        Ok(())
    }

    /// Get mutable reference to MF's children.
    fn mf_children(&mut self) -> Result<&mut Vec<MutableChild>, ProfileError> {
        self.mf
            .as_mut()
            .map(|df| &mut df.children)
            .ok_or(ProfileError::MissingMf)
    }

    /// Find an ADF by AID prefix and return mutable reference to its children.
    fn adf_children(&mut self, aid_prefix: &[u8]) -> Option<&mut Vec<MutableChild>> {
        self.adfs
            .iter_mut()
            .find(|(aid, _)| {
                aid.len() >= aid_prefix.len() && aid[..aid_prefix.len()] == *aid_prefix
            })
            .map(|(_, df)| &mut df.children)
    }

    /// Convert File entries from a template PE into [`MutableEf`] children.
    ///
    /// Skips files with `do_not_create` and files whose FCP indicates a DF.
    fn files_to_ef_children(
        files: &[(u8, crate::file::File)],
    ) -> Result<Vec<MutableChild>, ProfileError> {
        let mut children = Vec::new();
        for (_, file) in files {
            if let Some(ef) = Self::file_to_ef(file)? {
                children.push(MutableChild::Ef(ef));
            }
        }
        Ok(children)
    }

    /// Create a sub-DF from a root directory File and its child EF files.
    ///
    /// The `root_file`'s FCP provides the FID for the new DF.
    /// `child_files` are converted to EFs and placed under the new DF.
    fn build_sub_df(
        root_file: &crate::file::File,
        child_files: &[(u8, crate::file::File)],
    ) -> Result<MutableChild, ProfileError> {
        let fcp = root_file.fcp.as_ref().ok_or(ProfileError::MissingFcp)?;
        let fid = fcp.parse_fid()?;

        let children = Self::files_to_ef_children(child_files)?;

        Ok(MutableChild::Df(MutableDf { fid, children }))
    }

    /// Split a tagged file list into root DF (tag `[2]`) and child files
    /// (tags `[3]`+), build a `MutableChild::Df`.
    fn split_and_build_sub_df(files: &[(u8, File)]) -> Result<MutableChild, ProfileError> {
        let root_file = files
            .iter()
            .find(|(tag, _)| *tag == 2)
            .map(|(_, f)| f)
            .ok_or(ProfileError::MissingRequiredFile(2))?;
        let child_files: Vec<_> = files.iter().filter(|(tag, _)| *tag > 2).cloned().collect();
        Self::build_sub_df(root_file, &child_files)
    }

    /// Apply PE-TELECOM: create DF.TELECOM under MF.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_telecom(
        &mut self,
        pe: &crate::pe::telecom::PeTelecom,
    ) -> Result<(), ProfileError> {
        let sub_df = Self::split_and_build_sub_df(&pe.files)?;
        self.mf_children()?.push(sub_df);
        Ok(())
    }

    /// Apply PE-OPT-USIM: add optional EFs to existing ADF.USIM.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_opt_usim(
        &mut self,
        pe: &crate::pe::opt_usim::PeOptUsim,
    ) -> Result<(), ProfileError> {
        let new_children = Self::files_to_ef_children(&pe.files)?;
        if let Some(children) = self.adf_children(&USIM_AID_PREFIX) {
            children.extend(new_children);
        }
        // If ADF.USIM doesn't exist yet, silently skip (PE ordering issue).
        Ok(())
    }

    /// Apply PE-ISIM: create ADF.ISIM as a new ADF.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_isim(&mut self, pe: &crate::pe::isim::PeIsim) -> Result<(), ProfileError> {
        let adf_file = pe
            .files
            .iter()
            .find(|(tag, _)| *tag == 2)
            .map(|(_, f)| f)
            .ok_or(ProfileError::MissingRequiredFile(2))?;

        let child_files: Vec<_> = pe
            .files
            .iter()
            .filter(|(tag, _)| *tag > 2)
            .cloned()
            .collect();
        let children = Self::files_to_ef_children(&child_files)?;

        // Extract AID from ADF FCP.
        let aid = adf_file
            .fcp
            .as_ref()
            .and_then(|fcp| fcp.df_name.clone())
            .unwrap_or_else(|| ISIM_AID_PREFIX.to_vec());

        let adf_fid = adf_file
            .fcp
            .as_ref()
            .and_then(|fcp| fcp.parse_fid().ok())
            .unwrap_or(Fid::from_raw(0xFF02));

        self.adfs.push((
            aid,
            MutableDf {
                fid: adf_fid,
                children,
            },
        ));

        Ok(())
    }

    /// Apply PE-OPT-ISIM: add optional EFs to existing ADF.ISIM.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_opt_isim(
        &mut self,
        pe: &crate::pe::opt_isim::PeOptIsim,
    ) -> Result<(), ProfileError> {
        let new_children = Self::files_to_ef_children(&pe.files)?;
        if let Some(children) = self.adf_children(&ISIM_AID_PREFIX) {
            children.extend(new_children);
        }
        Ok(())
    }

    /// Apply a sub-DF PE under ADF.USIM. Silently skips if ADF.USIM
    /// doesn't exist yet (PE ordering edge case).
    fn apply_usim_sub_df(&mut self, files: &[(u8, File)]) -> Result<(), ProfileError> {
        let sub_df = Self::split_and_build_sub_df(files)?;
        if let Some(children) = self.adf_children(&USIM_AID_PREFIX) {
            children.push(sub_df);
        }
        Ok(())
    }

    /// Apply PE-GSM-ACCESS: create DF.GSM-ACCESS as sub-DF under ADF.USIM.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_gsm_access(
        &mut self,
        pe: &crate::pe::gsm_access::PeGsmAccess,
    ) -> Result<(), ProfileError> {
        self.apply_usim_sub_df(&pe.files)
    }

    /// Apply PE-DF-5GS: create DF.5GS as sub-DF under ADF.USIM.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_df_5gs(&mut self, pe: &crate::pe::df_5gs::PeDf5gs) -> Result<(), ProfileError> {
        self.apply_usim_sub_df(&pe.files)
    }

    /// Apply PE-DF-SAIP: create DF.SAIP as sub-DF under ADF.USIM.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_df_saip(&mut self, pe: &crate::pe::df_saip::PeDfSaip) -> Result<(), ProfileError> {
        self.apply_usim_sub_df(&pe.files)
    }

    /// Apply PE-CD: create DF.CD as sub-DF under MF.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_cd(&mut self, pe: &crate::pe::cd::PeCd) -> Result<(), ProfileError> {
        let sub_df = Self::split_and_build_sub_df(&pe.files)?;
        self.mf_children()?.push(sub_df);
        Ok(())
    }

    /// Apply PE-PHONEBOOK: create DF.PHONEBOOK as sub-DF under ADF.USIM.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_phonebook(
        &mut self,
        pe: &crate::pe::phonebook::PePhonebook,
    ) -> Result<(), ProfileError> {
        self.apply_usim_sub_df(&pe.files)
    }

    /// Apply PE-CSIM: create ADF.CSIM as a new ADF.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_csim(&mut self, pe: &crate::pe::csim::PeCsim) -> Result<(), ProfileError> {
        let adf_file = pe
            .files
            .iter()
            .find(|(tag, _)| *tag == 2)
            .map(|(_, f)| f)
            .ok_or(ProfileError::MissingRequiredFile(2))?;

        let child_files: Vec<_> = pe
            .files
            .iter()
            .filter(|(tag, _)| *tag > 2)
            .cloned()
            .collect();
        let children = Self::files_to_ef_children(&child_files)?;

        // Extract AID from ADF FCP.
        let aid = adf_file
            .fcp
            .as_ref()
            .and_then(|fcp| fcp.df_name.clone())
            .unwrap_or_else(|| CSIM_AID_PREFIX.to_vec());

        let adf_fid = adf_file
            .fcp
            .as_ref()
            .and_then(|fcp| fcp.parse_fid().ok())
            .unwrap_or(Fid::from_raw(0xFF03));

        self.adfs.push((
            aid,
            MutableDf {
                fid: adf_fid,
                children,
            },
        ));

        Ok(())
    }

    /// Apply PE-OPT-CSIM: add optional EFs to existing ADF.CSIM.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_opt_csim(
        &mut self,
        pe: &crate::pe::opt_csim::PeOptCsim,
    ) -> Result<(), ProfileError> {
        let new_children = Self::files_to_ef_children(&pe.files)?;
        if let Some(children) = self.adf_children(&CSIM_AID_PREFIX) {
            children.extend(new_children);
        }
        Ok(())
    }

    /// Apply PE-GFM: navigate tree by path and create/modify files.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if any file conversion fails.
    pub fn apply_gfm(&mut self, pe: &crate::pe::gfm::PeGfm) -> Result<(), ProfileError> {
        for cmd in &pe.commands {
            let Some(fcp) = cmd.file.fcp.as_ref() else {
                continue;
            };

            // Navigate to the target path. If the path references a DF
            // we haven't created (e.g. PE-PHONEBOOK not yet supported),
            // skip this command gracefully.
            let target = match self.find_by_path(&cmd.path) {
                Ok(t) => t,
                Err(ProfileError::PathNotFound(_)) => continue,
                Err(e) => return Err(e),
            };

            if fcp.is_df() {
                // GFM DF creation: add as a sub-DF at the target path.
                let fid = fcp.parse_fid()?;
                let exists = target.iter().any(|c| {
                    matches!(
                        c, MutableChild::Df(df) if df.fid == fid
                    )
                });
                if !exists {
                    target.push(MutableChild::Df(MutableDf {
                        fid,
                        children: Vec::new(),
                    }));
                }
            } else {
                // GFM EF creation.
                let Some(ef) = Self::file_to_ef(&cmd.file)? else {
                    continue;
                };
                target.push(MutableChild::Ef(ef));
            }
        }
        Ok(())
    }

    /// Navigate the filesystem tree by a path of FID pairs.
    ///
    /// The path is a sequence of 2-byte big-endian File IDs. An empty path
    /// targets the MF root. Paths starting with 0x3F00 skip the MF FID.
    /// Paths starting with an ADF temporary FID route through the ADF table.
    /// All other paths are treated as relative to MF.
    fn find_by_path(&mut self, path: &[u8]) -> Result<&mut Vec<MutableChild>, ProfileError> {
        if path.is_empty() {
            return self.mf_children();
        }

        if path.len() < 2 {
            return Err(ProfileError::PathNotFound(path.to_vec()));
        }
        let first_fid = u16::from_be_bytes([path[0], path[1]]);

        if first_fid == 0x3F00 {
            let children = self.mf_children()?;
            return Self::walk_df_path(children, &path[2..], path);
        }

        // Check ADFs by index to avoid borrow conflicts.
        if let Some(idx) = self
            .adfs
            .iter()
            .position(|(_, df)| df.fid.value() == first_fid)
        {
            let children = &mut self.adfs[idx].1.children;
            return Self::walk_df_path(children, &path[2..], path);
        }

        // Treat as relative to MF: first FID is a child of MF.
        let children = self.mf_children()?;
        Self::walk_df_path(children, path, path)
    }

    /// Walk a chain of FID pairs through a children vector.
    fn walk_df_path<'a>(
        mut current: &'a mut Vec<MutableChild>,
        remaining: &[u8],
        full_path: &[u8],
    ) -> Result<&'a mut Vec<MutableChild>, ProfileError> {
        let mut pos = 0;
        while pos + 1 < remaining.len() {
            let fid = u16::from_be_bytes([remaining[pos], remaining[pos + 1]]);
            let fid_obj = Fid::from_raw(fid);
            pos += 2;

            let found = current.iter_mut().find_map(|child| {
                if let MutableChild::Df(ref mut df) = child {
                    if df.fid == fid_obj {
                        return Some(&mut df.children);
                    }
                }
                None
            });

            match found {
                Some(c) => current = c,
                None => return Err(ProfileError::PathNotFound(full_path.to_vec())),
            }
        }
        Ok(current)
    }

    /// Convert a parsed [`File`] into a [`MutableEf`].
    ///
    /// Returns `None` if the file has a `doNotCreate` directive.
    ///
    /// Size computation follows TCA rules:
    /// 1. If the FCP has an explicit file size (tag 0x80), use it.
    /// 2. For transparent/BER-TLV EFs without explicit size: compute from
    ///    the maximum extent of fill data.
    /// 3. For record-based EFs: if the file descriptor has 5 bytes, use
    ///    `record_count` from byte 4. Otherwise compute from `file_size` / `record_size`.
    fn file_to_ef(file: &File) -> Result<Option<MutableEf>, ProfileError> {
        if file.do_not_create {
            return Ok(None);
        }

        let fcp = file.fcp.as_ref().ok_or(ProfileError::MissingFcp)?;

        // Skip DF-type files (handled separately by build_sub_df).
        // Also skip files with no file descriptor -- their structure
        // is defined by the template and we cannot determine it here.
        if fcp.is_df() || fcp.file_descriptor.is_none() {
            return Ok(None);
        }
        let fid = fcp.parse_fid()?;
        let sfi = fcp.parse_sfi();

        // Get explicit file size from FCP tag 0x80 (may be absent).
        let explicit_size = fcp.raw_file_size();

        // Compute fill extent: max(offset + content.len()) over all fills.
        let fill_extent = file
            .fills
            .iter()
            .map(|(offset, content)| offset + content.len())
            .max()
            .unwrap_or(0);

        // Determine total file size: use whichever is larger between the
        // explicit FCP size and the fill data extent. GFM commands may
        // declare a small efFileSize but provide more fill data.
        let total_size = explicit_size.map_or(fill_extent, |sz| sz.max(fill_extent));

        // Parse structure, passing total_size for record-based EFs that
        // need to compute num_records from file_size / record_size.
        let structure = fcp.parse_structure(Some(total_size))?;

        let data = file.build_data(total_size)?;

        // Validate record-based data length.
        if let Some(expected) = structure.expected_data_len() {
            if data.len() != expected {
                return Err(ProfileError::DataLengthMismatch {
                    fid,
                    expected,
                    actual: data.len(),
                });
            }
        }

        Ok(Some(MutableEf {
            fid,
            sfi,
            structure,
            data,
        }))
    }

    /// Freeze the mutable tree into leaked `&'static` references.
    ///
    /// This consumes the tree and produces:
    /// - `&'static DfDef` for the MF root
    /// - `&'static [AdfSlot]` for the ADF table
    ///
    /// All allocations are deliberately leaked for process lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::MissingMf`] if no MF was applied.
    pub fn freeze(self) -> Result<(&'static DfDef, &'static [AdfSlot]), ProfileError> {
        let mf = self.mf.ok_or(ProfileError::MissingMf)?;
        let static_mf = freeze_df(mf);

        let mut adf_slots: Vec<AdfSlot> = Vec::new();
        for (aid, df) in self.adfs {
            let static_root = freeze_df(df);
            let static_aid: &'static [u8] = Box::leak(aid.into_boxed_slice());
            adf_slots.push(AdfSlot {
                aid: static_aid,
                root: static_root,
            });
        }
        let static_adf_table: &'static [AdfSlot] = Box::leak(adf_slots.into_boxed_slice());

        Ok((static_mf, static_adf_table))
    }
}

/// Freeze a [`MutableDf`] into a leaked `&'static DfDef`.
fn freeze_df(df: MutableDf) -> &'static DfDef {
    let children: Vec<FileRef> = df
        .children
        .into_iter()
        .map(|child| match child {
            MutableChild::Ef(ef) => {
                let static_data: &'static [u8] = Box::leak(ef.data.into_boxed_slice());
                let ef_def = match ef.structure {
                    EfStructure::Transparent => EfDef::transparent(ef.fid, ef.sfi, static_data),
                    EfStructure::LinearFixed {
                        record_size,
                        num_records,
                    } => EfDef::linear_fixed(ef.fid, ef.sfi, record_size, num_records, static_data),
                    EfStructure::Cyclic {
                        record_size,
                        num_records,
                    } => EfDef::cyclic(ef.fid, ef.sfi, record_size, num_records, static_data),
                    EfStructure::BerTlv => EfDef::ber_tlv(ef.fid, ef.sfi, static_data),
                };
                FileRef::Ef(Box::leak(Box::new(ef_def)))
            }
            MutableChild::Df(sub_df) => FileRef::Df(freeze_df(sub_df)),
        })
        .collect();

    let static_children: &'static [FileRef] = Box::leak(children.into_boxed_slice());

    Box::leak(Box::new(DfDef {
        fid: df.fid,
        children: static_children,
    }))
}
