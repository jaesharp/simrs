//! GSM 11.11 SIM application layer.
//!
//! Handles GSM-class (CLA=`0xA0`) APDUs: SELECT, GET RESPONSE, READ BINARY,
//! READ RECORD, UPDATE BINARY, UPDATE RECORD, INCREASE, STATUS,
//! RUN GSM ALGORITHM (COMP128 A3/A8), VERIFY PIN, CHANGE REFERENCE DATA,
//! DISABLE PIN, ENABLE PIN, and UNBLOCK PIN.
//!
//! Constructs [ETSI TS 151 011 V4.15.0 clause 9.2.1](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C733%5D) SELECT responses:
//! - MF/DF: 23 bytes
//! - EF: 15 bytes
//!
//! # Architecture
//!
//! `GsmApp` owns a [`SelectionCtx`] for filesystem navigation, a
//! [`PinManager`] for PIN/PUK operations, a 16-byte Ki for COMP128
//! authentication, and a response queue for the GET RESPONSE pattern.
//!
//! The entry point is [`GsmApp::handle`], which accepts a parsed
//! [`Command`] and writes the response (data + SW) into a caller-supplied
//! buffer.
//!
//! # Standards
//! - [GSM 11.11 (ETSI TS 151 011 V4.15.0)](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf) -- ME-SIM interface
//! - [3GPP TS 51.011 V4.15.0](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf) -- SIM-ME interface
//!
//! # `no_std`
//! This crate is `no_std`.
//!
//! # Example
//!
//! ```
//! use simrs_gsm::{GsmApp, Ki};
//! use simrs_iso7816::Command;
//! use simrs_fs::{DfDef, EfDef, Fid, FileRef};
//! use simrs_pin::{PinKey, PinValue};
//!
//! static EF: EfDef = EfDef::transparent(
//!     Fid::new(0x2FE2),
//!     None,
//!     &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
//! );
//! static MF: DfDef = DfDef { fid: Fid::new(0x3F00), children: &[FileRef::Ef(&EF)] };
//!
//! let ki = Ki([0x01; 16]);
//! let mut app = GsmApp::new(&MF, ki);
//!
//! // SELECT MF
//! let cmd = Command::parse(&[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]).unwrap();
//! let mut buf = [0u8; 256];
//! let rsp = app.handle(&cmd, &mut buf);
//! assert_eq!(rsp[0], 0x9F); // SW1: response data available
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod profile;

use simrs_comp128::comp128;
use simrs_fs::{
    AdfSlot, DfDef, EfDef, Fid, FsData, FsError, SelectionCtx, SelectedFile,
};

// ---------------------------------------------------------------------------
// Feature-gated filesystem capacity constants
// ---------------------------------------------------------------------------

/// Filesystem data buffer capacity in bytes.
#[cfg(feature = "profile-full")]
const FS_CAP: usize = 8192;
/// Filesystem data buffer capacity in bytes.
#[cfg(all(not(feature = "profile-full"), all(feature = "profile-minimal", not(feature = "profile-standard"))))]
const FS_CAP: usize = 256;
/// Filesystem data buffer capacity in bytes.
#[cfg(all(not(feature = "profile-full"), any(feature = "profile-standard", not(feature = "profile-minimal"))))]
const FS_CAP: usize = 1024;

/// Maximum number of EF entries in the filesystem.
#[cfg(feature = "profile-full")]
const FS_MAX_EFS: usize = 160;
/// Maximum number of EF entries in the filesystem.
#[cfg(all(not(feature = "profile-full"), all(feature = "profile-minimal", not(feature = "profile-standard"))))]
const FS_MAX_EFS: usize = 16;
/// Maximum number of EF entries in the filesystem.
#[cfg(all(not(feature = "profile-full"), any(feature = "profile-standard", not(feature = "profile-minimal"))))]
const FS_MAX_EFS: usize = 32;
use simrs_iso7816::{ins, sw2, Command, ResponseQueue, StatusWord, write_data_sw, write_sw, write_sw_raw};
use simrs_pin::{PinKey, PinManager, PinResult, PinValue};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// COMP128 authentication key (Ki), 128 bits.
///
/// Newtype wrapper preventing accidental interchange with other 16-byte
/// key material (Milenage `K`, `OPc`). Derefs to `[u8; 16]` for transparent
/// use in cryptographic operations.
///
/// ```
/// use simrs_gsm::Ki;
/// let ki = Ki([0x11; 16]);
/// assert_eq!(ki[0], 0x11);
/// assert_eq!(ki.len(), 16);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ki(pub [u8; 16]);

impl Ki {
    /// Return a reference to the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::ops::Deref for Ki {
    type Target = [u8; 16];
    fn deref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::ops::DerefMut for Ki {
    fn deref_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}

impl core::fmt::Display for Ki {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// GSM CLA byte.
const CLA_GSM: u8 = 0xA0;

/// DF/MF SELECT response length per [ETSI TS 151 011 V4.15.0 clause 9.2.1](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C733%5D).
const DF_RSP_LEN: usize = 23;

/// EF SELECT response length per [ETSI TS 151 011 V4.15.0 clause 9.2.1](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C733%5D).
const EF_RSP_LEN: usize = 15;

// GSM 11.11 status words (proprietary, not reused from simrs-iso7816).
const SW_FILE_NOT_FOUND: [u8; 2] = [0x94, 0x04];
const SW_FILE_INCONSISTENT: [u8; 2] = [0x94, 0x08];
const SW_NO_EF_SELECTED: [u8; 2] = [0x94, 0x00];

// GSM 11.11 (ETSI TS 151 011 V4.15.0) clause 9.2.1 file type indicators.
const FILE_TYPE_MF: u8 = 0x01;
const FILE_TYPE_DF: u8 = 0x02;
const FILE_TYPE_EF: u8 = 0x04;

// GSM 11.11 proprietary SW1 (not in ISO 7816-4).
const SW1_RESPONSE_AVAILABLE: u8 = 0x9F;

// GSM 11.11 (ETSI TS 151 011 V4.15.0) clause 9.2.1 SELECT response structure.
const DF_GSM_DATA_LEN: u8 = 0x0A;
const EF_EXTRA_DATA_LEN: u8 = 0x02;
const FILE_STATUS_NOT_INVALIDATED: u8 = 0x01;
const FILE_CHARS_CLOCK_STOP: u8 = 0x32;

// GSM 11.11 (ETSI TS 151 011 V4.15.0) clause 9.2.1 CHV status values.
const NUM_CHV_LEVELS: u8 = 0x04;
const CHV_INIT_3_RETRIES: u8 = 0x83;
const UNBLOCK_CHV_INIT_10_RETRIES: u8 = 0x8A;

// GSM 11.11 proprietary status word: offset/record out of range.
const SW_OUT_OF_RANGE: [u8; 2] = [0x94, 0x02];

// COMP128 result structure.
const SRES_LEN: usize = 4;
const KC_LEN: usize = 8;
const COMP128_RESULT_LEN: usize = SRES_LEN + KC_LEN;

// PIN data widths (ETSI TS 102 221).
const PIN_DATA_LEN: usize = 8;
/// PUK(8) + new PIN(8) for RESET RETRY COUNTER.
const PUK_NEW_PIN_LEN: usize = PIN_DATA_LEN * 2;
/// Old PIN(8) + new PIN(8) for CHANGE REFERENCE DATA.
const CHANGE_PIN_DATA_LEN: usize = PIN_DATA_LEN * 2;

// ---------------------------------------------------------------------------
// GsmApp
// ---------------------------------------------------------------------------

/// GSM 11.11 / [3GPP TS 51.011 V4.15.0](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf) SIM application.
///
/// Handles CLA=`0xA0` APDUs. Owns filesystem context, PIN manager,
/// COMP128 key, and the response queue for GET RESPONSE.
pub struct GsmApp {
    fs: SelectionCtx,
    data: FsData<FS_CAP, FS_MAX_EFS>,
    mf: &'static DfDef,
    pin: PinManager<5>,
    ki: Ki,
    rsp_queue: ResponseQueue<23>,
}

impl GsmApp {
    /// Create a new GSM application rooted at the given MF.
    ///
    /// # Panics
    ///
    /// Panics if the total EF data in `mf` exceeds the profile-dependent
    /// `FsData` buffer capacity or the EF count limit.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_gsm::{GsmApp, Ki};
    /// use simrs_fs::{DfDef, Fid};
    ///
    /// static MF: DfDef = DfDef { fid: Fid::new(0x3F00), children: &[] };
    /// let app = GsmApp::new(&MF, Ki([0u8; 16]));
    /// ```
    pub fn new(mf: &'static DfDef, ki: Ki) -> Self {
        let mut data = FsData::new();
        data.init(mf).expect("FsData::init failed: filesystem too large for buffer");
        Self {
            fs: SelectionCtx::new(mf),
            data,
            mf,
            pin: PinManager::new(),
            ki,
            rsp_queue: ResponseQueue::new(),
        }
    }

    /// Access the PIN manager for configuration (add PINs).
    pub const fn pin_manager(&mut self) -> &mut PinManager<5> {
        &mut self.pin
    }

    /// Clear the response queue (pending GET RESPONSE data).
    pub const fn clear_response_queue(&mut self) {
        self.rsp_queue.clear();
    }

    /// Reset the file selection context to MF.
    pub const fn reset_file_selection(&mut self) {
        self.fs = SelectionCtx::new(self.mf);
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes.
    pub const SNAPSHOT_SIZE: usize =
        SelectionCtx::SNAPSHOT_SIZE + FsData::<FS_CAP, FS_MAX_EFS>::SNAPSHOT_SIZE + PinManager::<5>::SNAPSHOT_SIZE + 16 + ResponseQueue::<23>::SNAPSHOT_SIZE;

    /// Byte offset of the `PinManager` region within a `GsmApp` snapshot.
    pub const PIN_SNAPSHOT_OFFSET: usize =
        SelectionCtx::SNAPSHOT_SIZE + FsData::<FS_CAP, FS_MAX_EFS>::SNAPSHOT_SIZE;

    /// Serialize the GSM application state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut off = 0;
        off += self.fs.save_state(&mut buf[off..]);
        off += self.data.save_state(&mut buf[off..]);
        off += self.pin.save_state(&mut buf[off..]);
        buf[off..off + 16].copy_from_slice(&*self.ki);
        off += 16;
        off += self.rsp_queue.save_state(&mut buf[off..]);
        let _ = off;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the GSM application state from `buf`.
    ///
    /// Returns `true` on success. The `adfs` parameter is passed through
    /// to `SelectionCtx::restore_state` (typically `&[]` for GSM).
    #[must_use]
    pub fn restore_state(
        &mut self,
        buf: &[u8],
        adfs: &'static [AdfSlot],
    ) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut off = 0;
        if !self.fs.restore_state(&buf[off..], adfs) {
            return false;
        }
        off += SelectionCtx::SNAPSHOT_SIZE;
        // Rebuild FsData entry index from the static tree, then restore
        // the mutable buffer contents from the snapshot.
        if self.data.init(self.mf).is_err() {
            return false;
        }
        if !self.data.restore_state(&buf[off..]) {
            return false;
        }
        off += FsData::<FS_CAP, FS_MAX_EFS>::SNAPSHOT_SIZE;
        if !self.pin.restore_state(&buf[off..]) {
            return false;
        }
        off += PinManager::<5>::SNAPSHOT_SIZE;
        self.ki.copy_from_slice(&buf[off..off + 16]);
        off += 16;
        if !self.rsp_queue.restore_state(&buf[off..]) {
            return false;
        }
        off += ResponseQueue::<23>::SNAPSHOT_SIZE;
        let _ = off;
        true
    }

    /// Handle an APDU command. Returns a slice of `buf` containing
    /// the response: either just `[SW1, SW2]` or `[data..., SW1, SW2]`.
    ///
    /// # Errors
    ///
    /// Returns `6E 00` (class not supported) if CLA is not `0xA0`.
    /// Returns `6D 00` (instruction not supported) for unknown INS.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn handle<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // CLA check.
        if cmd.cla_raw() != CLA_GSM {
            return write_sw(buf, StatusWord::ClassNotSupported);
        }

        // Any command other than GET RESPONSE clears the response queue.
        if cmd.ins() != ins::GET_RESPONSE {
            self.rsp_queue.clear();
        }

        match cmd.ins() {
            ins::SELECT => self.handle_select(cmd, buf),
            ins::GET_RESPONSE => self.handle_get_response(cmd, buf),
            ins::READ_BINARY => self.handle_read_binary(cmd, buf),
            ins::READ_RECORD => self.handle_read_record(cmd, buf),
            ins::UPDATE_BINARY => self.handle_update_binary(cmd, buf),
            ins::UPDATE_RECORD => self.handle_update_record(cmd, buf),
            ins::INCREASE => self.handle_increase(cmd, buf),
            ins::STATUS => self.handle_status(cmd, buf),
            ins::AUTHENTICATE => self.handle_run_gsm_algo(cmd, buf),
            ins::VERIFY => self.handle_verify(cmd, buf),
            ins::CHANGE_REF_DATA => self.handle_change_ref_data(cmd, buf),
            ins::DISABLE_PIN => self.handle_disable_pin(cmd, buf),
            ins::ENABLE_PIN => self.handle_enable_pin(cmd, buf),
            ins::RESET_RETRY_CTR => self.handle_unblock(cmd, buf),
            _ => write_sw(buf, StatusWord::InsNotSupported),
        }
    }

    // -- SELECT --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_select<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 || cmd.p2() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        if cmd.data().len() != 2 {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let fid = Fid::from_be_bytes([cmd.data()[0], cmd.data()[1]]);
        match self.fs.select_by_fid(fid) {
            Ok(sel) => {
                // Build the GSM SELECT response and queue it.
                let rsp_len = match sel {
                    SelectedFile::Df(df) => {
                        build_df_response(df, self.rsp_queue.buf_mut());
                        DF_RSP_LEN
                    }
                    SelectedFile::Ef(ef) => {
                        build_ef_response(ef, self.rsp_queue.buf_mut());
                        EF_RSP_LEN
                    }
                };
                self.rsp_queue.set_len(rsp_len);
                // Return 9F XX (response data available).
                write_sw_raw(buf, SW1_RESPONSE_AVAILABLE, rsp_len as u8)
            }
            Err(FsError::FileNotFound) => write_sw_raw(buf, SW_FILE_NOT_FOUND[0], SW_FILE_NOT_FOUND[1]),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- GET RESPONSE --

    fn handle_get_response<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 || cmd.p2() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        self.rsp_queue.get_response(cmd.le(), buf)
    }

    // -- PIN access gate --

    /// Check whether PIN1 access is satisfied.
    ///
    /// Returns `true` if access is denied (caller should return
    /// `SECURITY_NOT_SATISFIED`).
    const fn pin1_denied(&self) -> bool {
        !self.pin.is_access_granted(PinKey::PIN1)
    }

    // -- READ BINARY --

    fn handle_read_binary<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let Some(ef) = self.fs.current_ef() else {
            return write_sw_raw(buf, SW_NO_EF_SELECTED[0], SW_NO_EF_SELECTED[1]);
        };
        let offset = u16::from_be_bytes([cmd.p1(), cmd.p2()]);
        let le = u16::from(cmd.le().unwrap_or(0));

        match self.data.read_binary(ef, offset, le) {
            Ok(data) => write_data_sw(buf, data, StatusWord::Success),
            Err(FsError::NotTransparent) => write_sw_raw(buf, SW_FILE_INCONSISTENT[0], SW_FILE_INCONSISTENT[1]),
            Err(FsError::OffsetOutOfRange) => write_sw_raw(buf, SW_OUT_OF_RANGE[0], SW_OUT_OF_RANGE[1]),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- READ RECORD --

    fn handle_read_record<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let Some(ef) = self.fs.current_ef() else {
            return write_sw_raw(buf, SW_NO_EF_SELECTED[0], SW_NO_EF_SELECTED[1]);
        };
        let rec_num = cmd.p1();
        // P2 = 0x04 means "absolute/current" mode per GSM 11.11.
        // We accept any P2 and just use the record number.

        match self.data.read_record(ef, rec_num) {
            Ok(data) => write_data_sw(buf, data, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw_raw(buf, SW_FILE_INCONSISTENT[0], SW_FILE_INCONSISTENT[1]),
            Err(FsError::RecordOutOfRange) => write_sw_raw(buf, SW_OUT_OF_RANGE[0], SW_OUT_OF_RANGE[1]),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- UPDATE BINARY --

    fn handle_update_binary<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let Some(ef) = self.fs.current_ef() else {
            return write_sw_raw(buf, SW_NO_EF_SELECTED[0], SW_NO_EF_SELECTED[1]);
        };
        let offset = u16::from_be_bytes([cmd.p1(), cmd.p2()]);
        match self.data.write_binary(ef, offset, cmd.data()) {
            Ok(()) => write_sw(buf, StatusWord::Success),
            Err(FsError::NotTransparent) => write_sw_raw(buf, SW_FILE_INCONSISTENT[0], SW_FILE_INCONSISTENT[1]),
            Err(FsError::OffsetOutOfRange) => write_sw_raw(buf, SW_OUT_OF_RANGE[0], SW_OUT_OF_RANGE[1]),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- UPDATE RECORD --

    fn handle_update_record<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let Some(ef) = self.fs.current_ef() else {
            return write_sw_raw(buf, SW_NO_EF_SELECTED[0], SW_NO_EF_SELECTED[1]);
        };
        let rec_num = cmd.p1();
        match self.data.write_record(ef, rec_num, cmd.data()) {
            Ok(()) => write_sw(buf, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw_raw(buf, SW_FILE_INCONSISTENT[0], SW_FILE_INCONSISTENT[1]),
            Err(FsError::RecordOutOfRange) => write_sw_raw(buf, SW_OUT_OF_RANGE[0], SW_OUT_OF_RANGE[1]),
            Err(FsError::DataTooLarge) => write_sw(buf, StatusWord::WrongLength),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- INCREASE --

    fn handle_increase<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let Some(ef) = self.fs.current_ef() else {
            return write_sw_raw(buf, SW_NO_EF_SELECTED[0], SW_NO_EF_SELECTED[1]);
        };
        match self.data.increase(ef, cmd.data()) {
            Ok(new_val) => write_data_sw(buf, new_val, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw_raw(buf, SW_FILE_INCONSISTENT[0], SW_FILE_INCONSISTENT[1]),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- STATUS --

    fn handle_status<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 || cmd.p2() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let mut rsp = [0u8; DF_RSP_LEN];
        build_df_response(self.fs.current_df(), &mut rsp);
        let le = cmd.le().unwrap_or(0) as usize;
        let n = if le == 0 { DF_RSP_LEN } else { le.min(DF_RSP_LEN) };
        write_data_sw(buf, &rsp[..n], StatusWord::Success)
    }

    // -- RUN GSM ALGORITHM (COMP128) --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_run_gsm_algo<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        if cmd.p1() != 0x00 || cmd.p2() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        if cmd.data().len() != 16 {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut rand = [0u8; 16];
        rand.copy_from_slice(cmd.data());
        let result = comp128(&self.ki, &rand);

        // Queue 12-byte result: 4-byte SRES + 8-byte Kc.
        self.rsp_queue.buf_mut()[..SRES_LEN].copy_from_slice(&result.sres);
        self.rsp_queue.buf_mut()[SRES_LEN..COMP128_RESULT_LEN].copy_from_slice(&result.kc);
        self.rsp_queue.set_len(COMP128_RESULT_LEN);

        write_sw_raw(buf, SW1_RESPONSE_AVAILABLE, COMP128_RESULT_LEN as u8)
    }

    // -- VERIFY PIN --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_verify<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let key = PinKey(cmd.p2());

        // Le=0 (5-byte APDU with P3=0): query retry count.
        if cmd.data().is_empty() {
            return match self.pin.retries(key) {
                Some(n) => write_sw(buf, StatusWord::pin_retries(n & 0x0F)),
                None => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
            };
        }

        if cmd.data().len() != PIN_DATA_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut pin_bytes = [0xFFu8; PIN_DATA_LEN];
        pin_bytes.copy_from_slice(cmd.data());
        let val = PinValue::new(pin_bytes);

        match self.pin.verify(key, &val) {
            PinResult::Success => write_sw(buf, StatusWord::Success),
            PinResult::WrongPin { retries_remaining } => {
                write_sw(buf, StatusWord::pin_retries(retries_remaining & 0x0F))
            }
            PinResult::Blocked => write_sw(buf, StatusWord::command_not_allowed(sw2::AUTH_METHOD_BLOCKED)),
            PinResult::Disabled => write_sw(buf, StatusWord::command_not_allowed(sw2::REF_DATA_NOT_USABLE)),
            PinResult::NotFound => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
        }
    }

    // -- CHANGE REFERENCE DATA --

    fn handle_change_ref_data<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let key = PinKey(cmd.p2());

        if cmd.data().len() != CHANGE_PIN_DATA_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut old_bytes = [0xFFu8; PIN_DATA_LEN];
        old_bytes.copy_from_slice(&cmd.data()[..PIN_DATA_LEN]);
        let old_pin = PinValue::new(old_bytes);

        let mut new_bytes = [0xFFu8; PIN_DATA_LEN];
        new_bytes.copy_from_slice(&cmd.data()[PIN_DATA_LEN..CHANGE_PIN_DATA_LEN]);
        let new_pin = PinValue::new(new_bytes);

        match self.pin.change(key, &old_pin, &new_pin) {
            PinResult::Success => write_sw(buf, StatusWord::Success),
            PinResult::WrongPin { retries_remaining } => {
                write_sw(buf, StatusWord::pin_retries(retries_remaining & 0x0F))
            }
            PinResult::Blocked => write_sw(buf, StatusWord::command_not_allowed(sw2::AUTH_METHOD_BLOCKED)),
            PinResult::Disabled => write_sw(buf, StatusWord::command_not_allowed(sw2::REF_DATA_NOT_USABLE)),
            PinResult::NotFound => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
        }
    }

    // -- DISABLE PIN --

    fn handle_disable_pin<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let key = PinKey(cmd.p2());

        if cmd.data().len() != PIN_DATA_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut pin_bytes = [0xFFu8; PIN_DATA_LEN];
        pin_bytes.copy_from_slice(cmd.data());
        let val = PinValue::new(pin_bytes);

        match self.pin.disable(key, &val) {
            PinResult::Success => write_sw(buf, StatusWord::Success),
            PinResult::WrongPin { retries_remaining } => {
                write_sw(buf, StatusWord::pin_retries(retries_remaining & 0x0F))
            }
            PinResult::Blocked => write_sw(buf, StatusWord::command_not_allowed(sw2::AUTH_METHOD_BLOCKED)),
            PinResult::Disabled => write_sw(buf, StatusWord::command_not_allowed(sw2::REF_DATA_NOT_USABLE)),
            PinResult::NotFound => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
        }
    }

    // -- ENABLE PIN --

    fn handle_enable_pin<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let key = PinKey(cmd.p2());

        if cmd.data().len() != PIN_DATA_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut pin_bytes = [0xFFu8; PIN_DATA_LEN];
        pin_bytes.copy_from_slice(cmd.data());
        let val = PinValue::new(pin_bytes);

        match self.pin.enable(key, &val) {
            PinResult::Success => write_sw(buf, StatusWord::Success),
            PinResult::WrongPin { retries_remaining } => {
                write_sw(buf, StatusWord::pin_retries(retries_remaining & 0x0F))
            }
            PinResult::Blocked => write_sw(buf, StatusWord::command_not_allowed(sw2::AUTH_METHOD_BLOCKED)),
            PinResult::Disabled => write_sw(buf, StatusWord::command_not_allowed(sw2::REF_DATA_NOT_USABLE)),
            PinResult::NotFound => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
        }
    }

    // -- UNBLOCK PIN --

    fn handle_unblock<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let key = PinKey(cmd.p2());

        // Le=0: query PUK retry count.
        if cmd.data().is_empty() {
            return match self.pin.puk_retries(key) {
                Some(n) => write_sw(buf, StatusWord::pin_retries(n & 0x0F)),
                None => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
            };
        }

        // Data must be 16 bytes: 8 PUK + 8 new PIN.
        if cmd.data().len() != PUK_NEW_PIN_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut puk_bytes = [0xFFu8; PIN_DATA_LEN];
        puk_bytes.copy_from_slice(&cmd.data()[..PIN_DATA_LEN]);
        let puk = PinValue::new(puk_bytes);

        let mut new_pin_bytes = [0xFFu8; PIN_DATA_LEN];
        new_pin_bytes.copy_from_slice(&cmd.data()[PIN_DATA_LEN..PUK_NEW_PIN_LEN]);
        let new_pin = PinValue::new(new_pin_bytes);

        match self.pin.unblock(key, &puk, &new_pin) {
            PinResult::Success => write_sw(buf, StatusWord::Success),
            PinResult::WrongPin { retries_remaining } => {
                write_sw(buf, StatusWord::pin_retries(retries_remaining & 0x0F))
            }
            PinResult::Blocked => write_sw(buf, StatusWord::command_not_allowed(sw2::AUTH_METHOD_BLOCKED)),
            PinResult::NotFound => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
            PinResult::Disabled => write_sw(buf, StatusWord::command_not_allowed(sw2::REF_DATA_NOT_USABLE)),
        }
    }
}

// ---------------------------------------------------------------------------
// GSM 11.11 SELECT response builders
// ---------------------------------------------------------------------------

/// Build a 23-byte DF/MF SELECT response per [ETSI TS 151 011 V4.15.0 clause 9.2.1](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C733%5D).
fn build_df_response(df: &DfDef, out: &mut [u8; 23]) {
    out.fill(0x00);

    // Bytes 0-1: RFU (0x0000).
    // Bytes 2-3: memory free (dummy).
    out[2] = 0x00;
    out[3] = 0x00;

    // Bytes 4-5: File ID (big-endian).
    let fid_be = df.fid.to_be_bytes();
    out[4] = fid_be[0];
    out[5] = fid_be[1];

    // Byte 6: file type (0x01 = MF, 0x02 = DF).
    out[6] = if df.fid == Fid::MF { FILE_TYPE_MF } else { FILE_TYPE_DF };

    // Bytes 7-11: RFU.
    // Byte 12: GSM-specific data length (10 bytes follow).
    out[12] = DF_GSM_DATA_LEN;

    // Byte 13: file characteristics.
    out[13] = FILE_CHARS_CLOCK_STOP; // Clock stop allowed, 1.8V+3V

    // Byte 14: number of child DFs.
    // Byte 15: number of child EFs.
    let mut num_subdirs: u8 = 0;
    let mut num_files: u8 = 0;
    for child in df.children {
        match child {
            simrs_fs::FileRef::Df(_) => num_subdirs = num_subdirs.saturating_add(1),
            simrs_fs::FileRef::Ef(_) => num_files = num_files.saturating_add(1),
        }
    }
    out[14] = num_subdirs;
    out[15] = num_files;

    // Byte 16: number of CHVs/codes/levels.
    out[16] = NUM_CHV_LEVELS;

    // Byte 17: RFU.
    // Bytes 18-21: CHV1 status, UNBLOCK CHV1, CHV2, UNBLOCK CHV2.
    out[18] = CHV_INIT_3_RETRIES; // CHV1: initialized, 3 retries
    out[19] = UNBLOCK_CHV_INIT_10_RETRIES; // UNBLOCK CHV1: initialized, 10 retries
    out[20] = CHV_INIT_3_RETRIES; // CHV2
    out[21] = UNBLOCK_CHV_INIT_10_RETRIES; // UNBLOCK CHV2
    // Byte 22: RFU.
}

/// Build a 15-byte EF SELECT response per [ETSI TS 151 011 V4.15.0 clause 9.2.1](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C733%5D).
#[allow(clippy::cast_possible_truncation)]
fn build_ef_response(ef: &EfDef, out: &mut [u8; 23]) {
    out.fill(0x00);

    // Bytes 0-1: RFU.
    // Bytes 2-3: file size (big-endian).
    let size = ef.data().len() as u16;
    let size_be = size.to_be_bytes();
    out[2] = size_be[0];
    out[3] = size_be[1];

    // Bytes 4-5: File ID.
    let fid_be = ef.fid().to_be_bytes();
    out[4] = fid_be[0];
    out[5] = fid_be[1];

    // Byte 6: file type = 0x04 (EF).
    out[6] = FILE_TYPE_EF;

    // Byte 7: 0x01 for cyclic, 0x00 otherwise.
    out[7] = ef.structure().gsm_increase_byte();

    // Bytes 8-10: access conditions (all zeros = always allowed).
    // Byte 11: file status (not invalidated).
    out[11] = FILE_STATUS_NOT_INVALIDATED;

    // Byte 12: data extra length.
    out[12] = EF_EXTRA_DATA_LEN;

    // Byte 13: EF structure.
    out[13] = ef.structure().gsm_structure_byte();

    // Byte 14: record length.
    out[14] = ef.structure().record_size();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_fs::{EfDef, Fid, FileRef, Sfi};

    // -- Test filesystem --

    static EF_ICCID: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        Some(Sfi::new(2)),
        &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    );

    static EF_DIR_DATA: [u8; 16] = [
        0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_DIR: EfDef = EfDef::linear_fixed(
        Fid::new(0x2F00),
        Some(Sfi::new(30)),
        8, 2,
        &EF_DIR_DATA,
    );

    static EF_ADN_DATA: [u8; 42] = [
        0x41, 0x6C, 0x69, 0x63, 0x65, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x42, 0x6F, 0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_ADN: EfDef = EfDef::linear_fixed(
        Fid::new(0x6F3A),
        None,
        14, 3,
        &EF_ADN_DATA,
    );

    static EF_CCP_DATA: [u8; 12] = [
        0x00, 0x00, 0x01, 0x00,  // record 1: value = 0x000100
        0x00, 0x00, 0x00, 0x00,  // record 2
        0x00, 0x00, 0x00, 0x00,  // record 3
    ];

    static EF_CCP: EfDef = EfDef::cyclic(
        Fid::new(0x6F14),
        None,
        4, 3,
        &EF_CCP_DATA,
    );

    static DF_TELECOM: DfDef = DfDef {
        fid: Fid::new(0x7F10),
        children: &[FileRef::Ef(&EF_ADN), FileRef::Ef(&EF_CCP)],
    };

    static EF_IMSI: EfDef = EfDef::transparent(
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
        children: &[FileRef::Ef(&EF_IMSI), FileRef::Ef(&EF_KC)],
    };

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[
            FileRef::Ef(&EF_ICCID),
            FileRef::Ef(&EF_DIR),
            FileRef::Df(&DF_TELECOM),
            FileRef::Df(&DF_GSM),
        ],
    };

    static KI: Ki = Ki([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                         0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);

    fn app() -> GsmApp {
        let mut a = GsmApp::new(&MF, KI);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        // Pre-verify PIN1 so existing tests can perform file operations
        // without explicit PIN verification via APDU.
        let _ = a.pin_manager().verify(PinKey::PIN1, &pin_val);
        a
    }

    /// Create an app with PIN1 enabled but not verified for PIN-gate tests.
    fn app_with_pin1_enabled() -> GsmApp {
        let mut a = GsmApp::new(&MF, KI);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        a
    }

    fn send(app: &mut GsmApp, apdu: &[u8]) -> ([u8; 256], usize) {
        let cmd = Command::parse(apdu).unwrap();
        let mut buf = [0u8; 256];
        let rsp = app.handle(&cmd, &mut buf);
        let len = rsp.len();
        (buf, len)
    }

    fn sw(buf: &[u8], len: usize) -> (u8, u8) {
        (buf[len - 2], buf[len - 1])
    }

    // -- CLA routing --

    #[test]
    fn cla_a0_accepted() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x6E); // not "class not supported"
    }

    #[test]
    fn cla_00_rejected() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        assert_eq!(sw(&buf, len), (0x6E, 0x00));
    }

    // -- SELECT + GET RESPONSE --

    #[test]
    fn select_mf_returns_9f_17() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0x9F);
        assert_eq!(buf[1], 23); // DF response = 23 bytes
    }

    #[test]
    fn get_response_after_select_mf() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]);
        assert_eq!(len, 23 + 2); // 23 data + 2 SW
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[4], 0x3F); // FID high
        assert_eq!(buf[5], 0x00); // FID low
        assert_eq!(buf[6], 0x01); // file type = MF
    }

    #[test]
    fn select_ef_returns_9f_0f() {
        let mut app = app();
        // Select MF first, then EF.ICCID.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]); // clear queue
        let (buf, _len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        assert_eq!(buf[0], 0x9F);
        assert_eq!(buf[1], 15); // EF response = 15 bytes
    }

    #[test]
    fn get_response_after_select_ef() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x0F]);
        assert_eq!(len, 15 + 2);
        assert_eq!(buf[4], 0x2F); // FID high
        assert_eq!(buf[5], 0xE2); // FID low
        assert_eq!(buf[6], 0x04); // file type = EF
        assert_eq!(buf[13], 0x00); // transparent
    }

    #[test]
    fn select_df_response() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        let (buf, _len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]);
        assert_eq!(buf[4], 0x7F);
        assert_eq!(buf[5], 0x20);
        assert_eq!(buf[6], 0x02); // file type = DF
    }

    #[test]
    fn select_nonexistent_fid() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x94, 0x04));
    }

    #[test]
    fn get_response_with_no_pending_data() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90); // not success
    }

    #[test]
    fn non_get_response_clears_queue() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]); // queues response
        send(&mut app, &[0xA0, 0xF2, 0x00, 0x00, 0x17]); // STATUS clears queue
        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]); // GET RSP
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90); // no data
    }

    // -- READ BINARY --

    #[test]
    fn read_binary_full() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(
            &buf[..10],
            &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]
        );
    }

    #[test]
    fn read_binary_with_offset() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x02, 0x03]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..3], &[0x14, 0x80, 0x00]);
    }

    #[test]
    fn read_binary_past_end() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x08, 0x05]);
        assert_eq!(sw(&buf, len), (0x94, 0x02)); // offset error
    }

    #[test]
    fn read_binary_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x94, 0x00)); // no EF
    }

    #[test]
    fn read_binary_on_linear_fixed() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0x00]); // EF.DIR
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x94, 0x08)); // file inconsistent
    }

    // -- READ RECORD --

    #[test]
    fn read_record_first() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]); // DF.TELECOM
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A]); // EF.ADN
        let (buf, len) = send(&mut app, &[0xA0, 0xB2, 0x01, 0x04, 0x0E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x41); // 'A'
        assert_eq!(len, 14 + 2);
    }

    #[test]
    fn read_record_second() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB2, 0x02, 0x04, 0x0E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x42); // 'B'
    }

    #[test]
    fn read_record_zero_invalid() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB2, 0x00, 0x04, 0x0E]);
        assert_eq!(sw(&buf, len), (0x94, 0x02));
    }

    #[test]
    fn read_record_beyond_last() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB2, 0x04, 0x04, 0x0E]);
        assert_eq!(sw(&buf, len), (0x94, 0x02));
    }

    #[test]
    fn read_record_on_transparent() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB2, 0x01, 0x04, 0x0A]);
        assert_eq!(sw(&buf, len), (0x94, 0x08));
    }

    // -- STATUS --

    #[test]
    fn status_returns_mf_info() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xF2, 0x00, 0x00, 0x17]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[4], 0x3F);
        assert_eq!(buf[5], 0x00);
        assert_eq!(len, 23 + 2);
    }

    #[test]
    fn status_after_selecting_df_gsm() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        let (buf, len) = send(&mut app, &[0xA0, 0xF2, 0x00, 0x00, 0x17]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[4], 0x7F);
        assert_eq!(buf[5], 0x20);
    }

    // -- RUN GSM ALGORITHM --

    #[test]
    fn run_gsm_algo_returns_12_bytes() {
        let mut app = app();
        let rand: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let mut apdu = [0u8; 4 + 1 + 16];
        apdu[0] = 0xA0;
        apdu[1] = 0x88;
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = 0x10;
        apdu[5..21].copy_from_slice(&rand);

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x9F, 0x0C)); // 12 bytes available

        // GET RESPONSE to retrieve the result.
        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x0C]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 12 + 2);

        // Verify against direct COMP128 computation.
        let expected = comp128(&KI, &rand);
        assert_eq!(&buf[..4], &expected.sres);
        assert_eq!(&buf[4..12], &expected.kc);
    }

    #[test]
    fn run_gsm_algo_wrong_length() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0x88, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(sw(&buf, len), (0x67, 0x00)); // wrong length
    }

    // -- VERIFY PIN --

    #[test]
    fn verify_correct_pin() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn verify_wrong_pin() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2)); // 2 retries
    }

    #[test]
    fn verify_blocked_pin() {
        let mut app = app();
        let wrong = [0xA0, 0x20, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        // Now blocked. Correct PIN should return 69 83.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    // -- UNBLOCK PIN --

    #[test]
    fn unblock_with_correct_puk() {
        let mut app = app();
        // Block PIN1.
        let wrong = [0xA0, 0x20, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        // Unblock: PUK "12345678" + new PIN "5678".
        let (buf, len) = send(&mut app,
            &[0xA0, 0x2C, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Verify with new PIN.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- CHANGE REFERENCE DATA --

    #[test]
    fn change_ref_data_success() {
        let mut app = app();
        // Old PIN "1234" + new PIN "5678".
        let (buf, len) = send(&mut app,
            &[0xA0, 0x24, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Verify with new PIN.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn change_ref_data_wrong_old_pin() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x24, 0x00, 0x01, 0x10,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2)); // 2 retries
    }

    #[test]
    fn change_ref_data_blocked() {
        let mut app = app();
        let wrong = [0xA0, 0x20, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(&mut app,
            &[0xA0, 0x24, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn change_ref_data_not_found() {
        let mut app = app();
        // P2=0xFF is not a registered key.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x24, 0x00, 0xFF, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn change_ref_data_wrong_length() {
        let mut app = app();
        // Only 8 bytes instead of 16.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x24, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    // -- DISABLE PIN --

    #[test]
    fn disable_pin_success() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // VERIFY should now return "disabled" (69 84).
        let (buf, len) = send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x84));
    }

    #[test]
    fn disable_pin_wrong_pin() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn disable_pin_blocked() {
        let mut app = app();
        let wrong = [0xA0, 0x20, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn disable_pin_not_found() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x26, 0x00, 0xFF, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn disable_pin_wrong_length() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x04, 0x31, 0x32, 0x33, 0x34]);
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn disable_pin_already_disabled() {
        let mut app = app();
        // Disable once.
        send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Second disable returns "already disabled" (69 84).
        let (buf, len) = send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x84));
    }

    // -- ENABLE PIN --

    #[test]
    fn enable_pin_success() {
        let mut app = app();
        // Disable first.
        send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Enable.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x28, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // VERIFY should work again.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn enable_pin_wrong_pin() {
        let mut app = app();
        // Disable first.
        send(&mut app,
            &[0xA0, 0x26, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Enable with wrong PIN.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x28, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn enable_pin_blocked() {
        let mut app = app();
        let wrong = [0xA0, 0x20, 0x00, 0x01, 0x08, 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(&mut app,
            &[0xA0, 0x28, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn enable_pin_not_found() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x28, 0x00, 0xFF, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn enable_pin_wrong_length() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x28, 0x00, 0x01, 0x04, 0x31, 0x32, 0x33, 0x34]);
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn enable_pin_already_enabled() {
        let mut app = app();
        // PIN is already enabled by default. Enable again is a no-op success.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x28, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- UPDATE BINARY --

    #[test]
    fn update_binary_and_readback() {
        let mut app = app();
        // SELECT EF.ICCID
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY: offset 0, 3 bytes [0xAA, 0xBB, 0xCC]
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // READ BINARY to verify
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..3], &[0xAA, 0xBB, 0xCC]);
        // Rest unchanged
        assert_eq!(buf[3], 0x80);
    }

    #[test]
    fn update_binary_with_offset() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY at offset 5: 2 bytes [0xDD, 0xEE]
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x05, 0x02, 0xDD, 0xEE]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // READ BINARY offset 4, length 4
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x04, 0x04]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..4], &[0x00, 0xDD, 0xEE, 0x00]);
    }

    #[test]
    fn update_binary_on_record_ef() {
        let mut app = app();
        // SELECT EF.DIR (linear-fixed)
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0x00]);
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x00, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x94, 0x08)); // file inconsistent
    }

    #[test]
    fn update_binary_past_end() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // EF.ICCID is 10 bytes. Write 3 bytes at offset 9 would exceed.
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x09, 0x03, 0xAA, 0xBB, 0xCC]);
        assert_eq!(sw(&buf, len), (0x94, 0x02)); // out of range
    }

    #[test]
    fn update_binary_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x00, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x94, 0x00)); // no EF
    }

    // -- UPDATE RECORD --

    #[test]
    fn update_record_and_readback() {
        let mut app = app();
        // SELECT DF.TELECOM, then EF.ADN
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A]);
        // UPDATE RECORD 3 (14 bytes) with new data
        let mut apdu = [0u8; 5 + 14];
        apdu[0] = 0xA0; // CLA
        apdu[1] = 0xDC; // INS: UPDATE RECORD
        apdu[2] = 0x03; // P1: record 3
        apdu[3] = 0x04; // P2: absolute
        apdu[4] = 0x0E; // Lc: 14 bytes
        // Fill record with "Charlie" + padding
        apdu[5] = 0x43; // 'C'
        apdu[6] = 0x68; // 'h'
        apdu[7] = 0x61; // 'a'
        apdu[8] = 0x72; // 'r'
        apdu[9..19].fill(0xFF);
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // READ RECORD 3
        let (buf, len) = send(&mut app, &[0xA0, 0xB2, 0x03, 0x04, 0x0E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x43); // 'C'
        assert_eq!(buf[1], 0x68); // 'h'
    }

    #[test]
    fn update_record_on_transparent() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // Try UPDATE RECORD on transparent EF
        let (buf, len) = send(&mut app,
            &[0xA0, 0xDC, 0x01, 0x04, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x94, 0x08)); // file inconsistent
    }

    #[test]
    fn update_record_wrong_size() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A]);
        // EF.ADN has record_size=14, try writing 8 bytes
        let (buf, len) = send(&mut app,
            &[0xA0, 0xDC, 0x01, 0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(sw(&buf, len), (0x67, 0x00)); // wrong length
    }

    #[test]
    fn update_record_out_of_range() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A]);
        // EF.ADN has 3 records. Try record 4.
        let mut apdu = [0xFFu8; 5 + 14];
        apdu[0] = 0xA0;
        apdu[1] = 0xDC;
        apdu[2] = 0x04; // record 4
        apdu[3] = 0x04;
        apdu[4] = 0x0E; // 14 bytes
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x94, 0x02)); // out of range
    }

    #[test]
    fn update_record_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0xDC, 0x01, 0x04, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x94, 0x00)); // no EF
    }

    // -- INCREASE --

    #[test]
    fn increase_on_cyclic_ef() {
        let mut app = app();
        // SELECT DF.TELECOM, then EF.CCP (cyclic, FID 0x6F14)
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x14]);
        // INCREASE by [0x00, 0x00, 0x00, 0x05]: record 1 = 0x000100 + 5 = 0x000105
        let (buf, len) = send(&mut app,
            &[0xA0, 0x32, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Response contains the new value (4 bytes) + SW
        assert_eq!(len, 4 + 2);
        assert_eq!(&buf[..4], &[0x00, 0x00, 0x01, 0x05]);
    }

    #[test]
    fn increase_on_transparent_fails() {
        let mut app = app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app,
            &[0xA0, 0x32, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(sw(&buf, len), (0x94, 0x08)); // file inconsistent
    }

    #[test]
    fn increase_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0xA0, 0x32, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(sw(&buf, len), (0x94, 0x00)); // no EF
    }

    // -- Unknown INS --

    #[test]
    fn unknown_ins_returns_6d00() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xFF, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x6D, 0x00));
    }

    // -- Navigation round-trip --

    #[test]
    fn navigate_mf_df_ef_read_mf_roundtrip() {
        let mut app = app();
        // SELECT MF.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]); // consume
        // SELECT DF.GSM.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]); // consume
        // SELECT EF.IMSI.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07]);
        // READ BINARY.
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08); // IMSI first byte
        assert_eq!(len, 9 + 2);
        // SELECT MF.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        // STATUS shows MF.
        let (buf, _len) = send(&mut app, &[0xA0, 0xF2, 0x00, 0x00, 0x17]);
        assert_eq!(buf[4], 0x3F);
        assert_eq!(buf[5], 0x00);
    }

    // -- EF structure in SELECT response --

    #[test]
    fn ef_linear_fixed_response_structure() {
        let mut app = app();
        // Navigate to EF.DIR (linear-fixed).
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0x00]);
        let (buf, _len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x0F]);
        assert_eq!(buf[13], 0x01); // linear-fixed
        assert_eq!(buf[14], 8); // record size
    }

    // -- Snapshot --

    #[test]
    fn snapshot_size_correct() {
        // SelectionCtx + FsData + PinManager<5> + Ki(16) + ResponseQueue<23>
        let expected = simrs_fs::SelectionCtx::SNAPSHOT_SIZE
            + simrs_fs::FsData::<{ super::FS_CAP }, { super::FS_MAX_EFS }>::SNAPSHOT_SIZE
            + simrs_pin::PinManager::<5>::SNAPSHOT_SIZE
            + 16
            + simrs_iso7816::ResponseQueue::<23>::SNAPSHOT_SIZE;
        assert_eq!(GsmApp::SNAPSHOT_SIZE, expected);
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let mut app = app();
        // Navigate to DF.GSM and select EF.IMSI so fs state is non-trivial.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]); // consume
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07]);
        // Degrade PIN retries by one wrong attempt.
        send(&mut app, &[0xA0, 0x20, 0x00, 0x01, 0x08,
                         0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Save state.
        let mut snap = [0u8; GsmApp::SNAPSHOT_SIZE];
        let written = app.save_state(&mut snap);
        assert_eq!(written, GsmApp::SNAPSHOT_SIZE);

        // Create a fresh app and restore into it.
        let mut restored = GsmApp::new(&MF, Ki([0u8; 16]));
        assert!(restored.restore_state(&snap, &[]));

        // Verify: PIN retries are 2 (degraded from 3).
        let (buf, len) = send(&mut restored, &[0xA0, 0x20, 0x00, 0x01, 0x00]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2));

        // Re-verify PIN1 so we can read files (PIN gate enforced).
        send(&mut restored,
            &[0xA0, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Verify: read EF.IMSI works (fs state restored to DF.GSM + EF.IMSI).
        let (buf, len) = send(&mut restored, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08); // IMSI first byte
    }

    #[test]
    fn snapshot_preserves_ki_and_auth() {
        let mut app = app();
        // Run GSM algorithm with known RAND.
        let rand_bytes: [u8; 16] = [0xAA; 16];
        let mut algo_apdu = [0u8; 21];
        algo_apdu[0] = 0xA0;
        algo_apdu[1] = 0x88;
        algo_apdu[4] = 0x10;
        algo_apdu[5..21].copy_from_slice(&rand_bytes);
        send(&mut app, &algo_apdu);
        let (orig_buf, orig_len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x0C]);
        assert_eq!(sw(&orig_buf, orig_len), (0x90, 0x00));
        let mut orig_result = [0u8; 12];
        orig_result.copy_from_slice(&orig_buf[..12]);

        // Save and restore.
        let mut snap = [0u8; GsmApp::SNAPSHOT_SIZE];
        let _ = app.save_state(&mut snap);
        let mut restored = GsmApp::new(&MF, Ki([0u8; 16]));
        assert!(restored.restore_state(&snap, &[]));

        // Same RAND must produce same result (Ki preserved).
        send(&mut restored, &algo_apdu);
        let (buf, len) = send(&mut restored, &[0xA0, 0xC0, 0x00, 0x00, 0x0C]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..12], &orig_result);
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let src = app();
        let mut small = [0u8; 10];
        assert_eq!(src.save_state(&mut small), 0);

        let mut dst = app();
        assert!(!dst.restore_state(&small, &[]));
    }

    #[test]
    fn snapshot_restore_oversized_rsp_queue_len_returns_false() {
        let src = app();
        let mut snap = [0u8; GsmApp::SNAPSHOT_SIZE];
        let _ = src.save_state(&mut snap);
        // rsp_queue_len is the last byte of the snapshot.
        *snap.last_mut().unwrap() = u8::MAX;
        let mut dst = app();
        assert!(!dst.restore_state(&snap, &[]));
    }

    // -- PIN gate tests --

    #[test]
    fn gsm_read_binary_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        // Select EF.ICCID.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // READ BINARY without PIN1 verification.
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x69, 0x82)); // security status not satisfied
    }

    #[test]
    fn gsm_run_gsm_algo_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        // RUN GSM ALGORITHM without PIN1 verification.
        let mut apdu = [0u8; 4 + 1 + 16];
        apdu[0] = 0xA0;
        apdu[1] = 0x88;
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = 0x10;
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn gsm_update_binary_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        // Select EF.ICCID.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY without PIN1.
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn gsm_verify_then_read_succeeds() {
        let mut app = app_with_pin1_enabled();
        // Verify PIN1.
        send(&mut app,
            &[0xA0, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Select EF.ICCID.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // READ BINARY should now succeed.
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -----------------------------------------------------------------------
    // Access control test matrix
    //
    // Systematically verifies that PIN1-gated operations are denied when
    // PIN1 is enabled but not verified, and allowed when PIN1 has been
    // verified.  Also verifies that non-PIN1-gated operations are NOT
    // blocked by unverified PIN1.
    //
    // SW (0x69, 0x82) = SECURITY_NOT_SATISFIED (the PIN gate rejection).
    // -----------------------------------------------------------------------

    mod access_control {
        use super::*;

        /// Security-status-not-satisfied status word produced by `pin1_denied()`.
        const SW_SECURITY: (u8, u8) = (0x69, 0x82);

        /// VERIFY APDU for correct PIN1 ("1234" padded to 8 bytes).
        const VERIFY_PIN1: [u8; 13] = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        /// SELECT EF.ICCID (transparent, under MF).
        const SELECT_EF_ICCID: [u8; 7] = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2];

        // -- Fixture helpers ------------------------------------------------

        /// App with PIN1 enabled and NOT verified.  File operations that
        /// check `pin1_denied()` must fail with `SW_SECURITY`.
        fn denied_fixture() -> GsmApp {
            app_with_pin1_enabled()
        }

        /// App with PIN1 enabled AND verified.  File operations that
        /// check `pin1_denied()` must succeed (SW != `SW_SECURITY`).
        fn allowed_fixture() -> GsmApp {
            let mut a = app_with_pin1_enabled();
            // Verify PIN1 via the PIN manager directly (not via APDU)
            // so we don't conflate APDU-level behaviour.
            let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
            let _ = a.pin_manager().verify(PinKey::PIN1, &pin_val);
            a
        }

        // ===================================================================
        // PIN1-GATED operations -- must FAIL without PIN1, succeed with PIN1
        // ===================================================================

        // -- READ BINARY (INS 0xB0) -----------------------------------------

        #[test]
        fn read_binary_denied_without_pin1() {
            let mut app = denied_fixture();
            send(&mut app, &SELECT_EF_ICCID);
            let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
            assert_eq!(sw(&buf, len), SW_SECURITY,
                "READ BINARY must be rejected when PIN1 is not verified");
        }

        #[test]
        fn read_binary_allowed_with_pin1() {
            let mut app = allowed_fixture();
            send(&mut app, &SELECT_EF_ICCID);
            let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "READ BINARY must not be rejected when PIN1 is verified");
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "READ BINARY should succeed with 90 00");
        }

        // -- UPDATE BINARY (INS 0xD6) --------------------------------------

        #[test]
        fn update_binary_denied_without_pin1() {
            let mut app = denied_fixture();
            send(&mut app, &SELECT_EF_ICCID);
            let (buf, len) = send(&mut app,
                &[0xA0, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
            assert_eq!(sw(&buf, len), SW_SECURITY,
                "UPDATE BINARY must be rejected when PIN1 is not verified");
        }

        #[test]
        fn update_binary_allowed_with_pin1() {
            let mut app = allowed_fixture();
            send(&mut app, &SELECT_EF_ICCID);
            let (buf, len) = send(&mut app,
                &[0xA0, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "UPDATE BINARY must not be rejected when PIN1 is verified");
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "UPDATE BINARY should succeed with 90 00");
        }

        // -- RUN GSM ALGORITHM (INS 0x88) -----------------------------------

        /// Build a RUN GSM ALGORITHM APDU with a 16-byte RAND.
        fn run_gsm_algo_apdu() -> [u8; 21] {
            let mut apdu = [0u8; 21];
            apdu[0] = 0xA0;
            apdu[1] = 0x88;
            apdu[2] = 0x00;
            apdu[3] = 0x00;
            apdu[4] = 0x10;
            // Non-trivial RAND to avoid any identity-element concerns.
            apdu[5..21].copy_from_slice(
                &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                  0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01]);
            apdu
        }

        #[test]
        fn run_gsm_algo_denied_without_pin1() {
            let mut app = denied_fixture();
            let (buf, len) = send(&mut app, &run_gsm_algo_apdu());
            assert_eq!(sw(&buf, len), SW_SECURITY,
                "RUN GSM ALGORITHM must be rejected when PIN1 is not verified");
        }

        #[test]
        fn run_gsm_algo_allowed_with_pin1() {
            let mut app = allowed_fixture();
            let (buf, len) = send(&mut app, &run_gsm_algo_apdu());
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "RUN GSM ALGORITHM must not be rejected when PIN1 is verified");
            // Successful RUN GSM ALGORITHM returns 9F 0C (12 bytes available).
            assert_eq!(sw(&buf, len), (0x9F, 0x0C),
                "RUN GSM ALGORITHM should queue 12-byte response");
        }

        // ===================================================================
        // NON-PIN1-GATED operations -- must succeed without PIN1
        // ===================================================================

        // -- SELECT (INS 0xA4) ----------------------------------------------

        #[test]
        fn select_allowed_without_pin1() {
            let mut app = denied_fixture();
            let (buf, len) = send(&mut app,
                &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "SELECT must not be blocked by unverified PIN1");
            // SELECT MF returns 9F 17 (23-byte response queued).
            assert_eq!((buf[0], buf[1]), (0x9F, 23),
                "SELECT MF should return 9F 17");
        }

        // -- STATUS (INS 0xF2) ----------------------------------------------

        #[test]
        fn status_allowed_without_pin1() {
            let mut app = denied_fixture();
            let (buf, len) = send(&mut app,
                &[0xA0, 0xF2, 0x00, 0x00, 0x17]);
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "STATUS must not be blocked by unverified PIN1");
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "STATUS should succeed with 90 00");
        }

        // -- VERIFY (INS 0x20) ----------------------------------------------

        #[test]
        fn verify_allowed_without_pin1() {
            let mut app = denied_fixture();
            // VERIFY itself must not require PIN1 to be pre-verified.
            // Send VERIFY with the correct PIN1.
            let (buf, len) = send(&mut app, &VERIFY_PIN1);
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "VERIFY must not be blocked by unverified PIN1");
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "VERIFY with correct PIN should succeed");
        }

        #[test]
        fn verify_retry_query_allowed_without_pin1() {
            let mut app = denied_fixture();
            // VERIFY with P3=0 (Le=0) queries retry count -- also not gated.
            let (buf, len) = send(&mut app,
                &[0xA0, 0x20, 0x00, 0x01, 0x00]);
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "VERIFY retry query must not be blocked by unverified PIN1");
            // Expect 63 C3 (3 retries remaining).
            assert_eq!(sw(&buf, len), (0x63, 0xC3),
                "VERIFY retry query should report 3 retries");
        }

        // -- GET RESPONSE (INS 0xC0) ----------------------------------------

        #[test]
        fn get_response_allowed_without_pin1() {
            let mut app = denied_fixture();
            // SELECT queues a response; GET RESPONSE retrieves it.
            // Neither operation is PIN-gated.
            send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
            let (buf, len) = send(&mut app,
                &[0xA0, 0xC0, 0x00, 0x00, 0x17]);
            assert_ne!(sw(&buf, len), SW_SECURITY,
                "GET RESPONSE must not be blocked by unverified PIN1");
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "GET RESPONSE should deliver queued data with 90 00");
        }

        // ===================================================================
        // Cross-check: verify that denied operations become allowed after
        // PIN1 verification via APDU (end-to-end, not just fixture-based).
        // ===================================================================

        #[test]
        fn read_binary_denied_then_verify_then_allowed() {
            let mut app = denied_fixture();
            send(&mut app, &SELECT_EF_ICCID);

            // Step 1: READ BINARY must fail.
            let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
            assert_eq!(sw(&buf, len), SW_SECURITY,
                "READ BINARY must fail before VERIFY");

            // Step 2: VERIFY PIN1.
            let (buf, len) = send(&mut app, &VERIFY_PIN1);
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "VERIFY PIN1 should succeed");

            // Step 3: Re-select (SELECT clears queue but not PIN state).
            send(&mut app, &SELECT_EF_ICCID);

            // Step 4: READ BINARY must now succeed.
            let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "READ BINARY must succeed after VERIFY");
        }

        #[test]
        fn update_binary_denied_then_verify_then_allowed() {
            let mut app = denied_fixture();
            send(&mut app, &SELECT_EF_ICCID);

            // Step 1: UPDATE BINARY must fail.
            let (buf, len) = send(&mut app,
                &[0xA0, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
            assert_eq!(sw(&buf, len), SW_SECURITY,
                "UPDATE BINARY must fail before VERIFY");

            // Step 2: VERIFY PIN1.
            let (buf, len) = send(&mut app, &VERIFY_PIN1);
            assert_eq!(sw(&buf, len), (0x90, 0x00));

            // Step 3: Re-select.
            send(&mut app, &SELECT_EF_ICCID);

            // Step 4: UPDATE BINARY must now succeed.
            let (buf, len) = send(&mut app,
                &[0xA0, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "UPDATE BINARY must succeed after VERIFY");
        }

        #[test]
        fn run_gsm_algo_denied_then_verify_then_allowed() {
            let mut app = denied_fixture();

            // Step 1: RUN GSM ALGORITHM must fail.
            let (buf, len) = send(&mut app, &run_gsm_algo_apdu());
            assert_eq!(sw(&buf, len), SW_SECURITY,
                "RUN GSM ALGORITHM must fail before VERIFY");

            // Step 2: VERIFY PIN1.
            let (buf, len) = send(&mut app, &VERIFY_PIN1);
            assert_eq!(sw(&buf, len), (0x90, 0x00));

            // Step 3: RUN GSM ALGORITHM must now succeed.
            let (buf, len) = send(&mut app, &run_gsm_algo_apdu());
            assert_eq!(sw(&buf, len), (0x9F, 0x0C),
                "RUN GSM ALGORITHM must succeed after VERIFY");
        }
    }

    // -----------------------------------------------------------------------
    // PIN exhaustion sequence -- APDU-level integration test
    // -----------------------------------------------------------------------

    /// Full APDU-level PIN exhaustion sequence per [3GPP TS 51.011 V4.15.0](../../../docs/specs/3gpp/ts-51.011/ts_151011v041500p.pdf).
    ///
    /// Sends 3 wrong VERIFY PINs, checking remaining tries decrement from
    /// 3 -> 2 -> 1 -> blocked. Then verifies that a correct PIN is also
    /// rejected while blocked (SW 69 83).
    ///
    /// This tests the real protocol behavior end-to-end through the APDU
    /// handler, not just the PIN state machine directly.
    #[test]
    fn pin_exhaustion_sequence_via_apdu() {
        let mut app = app_with_pin1_enabled();

        // Wrong PIN: "9999" (0x39 0x39 0x39 0x39 padded with 0xFF).
        let wrong_pin = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        // Correct PIN: "1234" (0x31 0x32 0x33 0x34 padded with 0xFF).
        let correct_pin = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        // Attempt 1 (wrong): should return 63 C2 (2 retries remaining).
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC2),
            "first wrong PIN: expected 2 retries remaining (63 C2)"
        );

        // Attempt 2 (wrong): should return 63 C1 (1 retry remaining).
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC1),
            "second wrong PIN: expected 1 retry remaining (63 C1)"
        );

        // Attempt 3 (wrong): should return 63 C0 (0 retries remaining -- blocked).
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC0),
            "third wrong PIN: expected 0 retries remaining (63 C0)"
        );

        // PIN is now blocked. Correct PIN must be rejected with 69 83.
        let (buf, len) = send(&mut app, &correct_pin);
        assert_eq!(
            sw(&buf, len), (0x69, 0x83),
            "correct PIN while blocked must return 69 83 (authentication method blocked)"
        );

        // Another wrong PIN while blocked must also return 69 83.
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x69, 0x83),
            "wrong PIN while blocked must return 69 83"
        );
    }

    /// After exhausting PIN1, unblock it via UNBLOCK CHV (INS 0x2C) with the
    /// correct PUK and a new PIN, then verify the new PIN works.
    ///
    /// This is the full APDU-level recovery sequence: exhaust PIN -> unblock
    /// with PUK -> verify with new PIN -> confirm file access restored.
    #[test]
    fn puk_unblock_after_pin_exhaustion_via_apdu() {
        let mut app = app_with_pin1_enabled();

        // Wrong PIN: "9999".
        let wrong_pin = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        // Exhaust all 3 PIN retries.
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC2),
            "first wrong PIN: expected 2 retries remaining"
        );
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC1),
            "second wrong PIN: expected 1 retry remaining"
        );
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC0),
            "third wrong PIN: expected 0 retries (blocked)"
        );

        // Confirm PIN is blocked.
        let correct_old_pin = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let (buf, len) = send(&mut app, &correct_old_pin);
        assert_eq!(
            sw(&buf, len), (0x69, 0x83),
            "PIN must be blocked after 3 wrong attempts"
        );

        // UNBLOCK CHV: PUK "12345678" + new PIN "5678".
        let unblock_apdu = [
            0xA0, 0x2C, 0x00, 0x01, 0x10,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // PUK
            0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, // new PIN "5678"
        ];
        let (buf, len) = send(&mut app, &unblock_apdu);
        assert_eq!(
            sw(&buf, len), (0x90, 0x00),
            "UNBLOCK CHV with correct PUK must succeed"
        );

        // Verify with the new PIN "5678".
        let new_pin_verify = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let (buf, len) = send(&mut app, &new_pin_verify);
        assert_eq!(
            sw(&buf, len), (0x90, 0x00),
            "VERIFY with new PIN after unblock must succeed"
        );

        // Confirm retry counter was restored to maximum (3).
        // Query via VERIFY with P3=0.
        let retry_query = [0xA0, 0x20, 0x00, 0x01, 0x00];
        let (buf, len) = send(&mut app, &retry_query);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC3),
            "PIN retry counter must be restored to 3 after unblock"
        );

        // Confirm PIN-gated file access works: SELECT EF.ICCID + READ BINARY.
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(
            sw(&buf, len), (0x90, 0x00),
            "READ BINARY must succeed after PUK unblock + PIN verify"
        );
    }

    /// Exhaust all 10 PUK retries via UNBLOCK CHV (INS 0x2C) with wrong PUK
    /// values, verifying the retry counter decrements each time, and confirm
    /// the PUK is permanently blocked afterward.
    #[test]
    fn puk_exhaustion_via_apdu() {
        let mut app = app_with_pin1_enabled();

        // First block PIN1 so UNBLOCK CHV is the relevant operation.
        let wrong_pin = [
            0xA0, 0x20, 0x00, 0x01, 0x08,
            0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        send(&mut app, &wrong_pin);
        send(&mut app, &wrong_pin);
        send(&mut app, &wrong_pin);

        // Confirm PIN is blocked.
        let (buf, len) = send(&mut app, &wrong_pin);
        assert_eq!(
            sw(&buf, len), (0x69, 0x83),
            "PIN must be blocked before PUK exhaustion test"
        );

        // Wrong PUK: "99999999" + dummy new PIN "1111".
        let wrong_puk = [
            0xA0, 0x2C, 0x00, 0x01, 0x10,
            0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, // wrong PUK
            0x31, 0x31, 0x31, 0x31, 0xFF, 0xFF, 0xFF, 0xFF, // new PIN (irrelevant)
        ];

        // Send 10 wrong PUK attempts, verifying retry counter decrements.
        // PUK starts with 10 retries.
        for attempt in 1..=10u8 {
            let expected_remaining = 10 - attempt;
            let (buf, len) = send(&mut app, &wrong_puk);

            if expected_remaining > 0 {
                assert_eq!(
                    sw(&buf, len),
                    (0x63, 0xC0 | expected_remaining),
                    "PUK attempt {attempt}: expected {expected_remaining} retries remaining"
                );
            } else {
                // Last attempt: 0 retries remaining -> 63 C0.
                assert_eq!(
                    sw(&buf, len), (0x63, 0xC0),
                    "PUK attempt 10: expected 0 retries remaining (63 C0)"
                );
            }
        }

        // PUK is now permanently blocked. Correct PUK must be rejected.
        let correct_puk = [
            0xA0, 0x2C, 0x00, 0x01, 0x10,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // correct PUK
            0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF, // new PIN
        ];
        let (buf, len) = send(&mut app, &correct_puk);
        assert_eq!(
            sw(&buf, len), (0x69, 0x83),
            "correct PUK while PUK-blocked must return 69 83"
        );

        // Another wrong PUK while blocked must also return 69 83.
        let (buf, len) = send(&mut app, &wrong_puk);
        assert_eq!(
            sw(&buf, len), (0x69, 0x83),
            "wrong PUK while PUK-blocked must return 69 83"
        );

        // Query PUK retry counter via UNBLOCK CHV with P3=0.
        let puk_retry_query = [0xA0, 0x2C, 0x00, 0x01, 0x00];
        let (buf, len) = send(&mut app, &puk_retry_query);
        assert_eq!(
            sw(&buf, len), (0x63, 0xC0),
            "PUK retry query must report 0 retries after exhaustion"
        );
    }

    // -----------------------------------------------------------------------
    // Reference profile tests -- Phase 7
    // -----------------------------------------------------------------------

    /// Create a [`GsmApp`] from the reference GSM profile with PIN1 verified.
    fn ref_app() -> GsmApp {
        use crate::profile;
        let ki = Ki([0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F,
                     0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC]);
        let mut a = GsmApp::new(&profile::REFERENCE_MF_GSM, ki);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        let _ = a.pin_manager().verify(PinKey::PIN1, &pin_val);
        a
    }

    // -- SELECT and READ on reference profile EFs --

    /// SELECT MF on reference profile returns response data available.
    #[test]
    fn ref_select_mf() {
        let mut app = ref_app();
        let (buf, len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0x9F, "SELECT MF must return 9F XX");
        assert_eq!(buf[1], 23, "MF response must be 23 bytes");
    }

    /// SELECT DF.GSM and verify response has correct FID.
    #[test]
    fn ref_select_df_gsm() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x17]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[4], 0x7F, "FID high byte");
        assert_eq!(buf[5], 0x20, "FID low byte");
        assert_eq!(buf[6], 0x02, "file type = DF");
    }

    /// SELECT EF.ICCID from MF and read its 10-byte content.
    #[test]
    fn ref_read_ef_iccid() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 10 + 2, "EF.ICCID must be 10 bytes");
        // First nibble-swapped byte should be 0x98 (ICCID starts with 89)
        assert_eq!(buf[0], 0x98, "EF.ICCID first byte must be 0x98");
    }

    /// SELECT DF.GSM, then EF.IMSI, and verify content.
    #[test]
    fn ref_read_ef_imsi() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 9 + 2, "EF.IMSI must be 9 bytes");
        assert_eq!(buf[0], 0x08, "IMSI length byte must be 0x08");
    }

    /// READ EF.Kc (9 bytes) and verify CKSN.
    #[test]
    fn ref_read_ef_kc() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x20]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 9 + 2);
        assert_eq!(buf[8], 0x07, "EF.Kc CKSN must be 0x07 (no key)");
    }

    /// READ EF.SST (14 bytes).
    #[test]
    fn ref_read_ef_sst() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x38]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0E]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 14 + 2);
    }

    /// READ EF.LOCI (11 bytes) and verify structure.
    #[test]
    fn ref_read_ef_loci() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x7E]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0B]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 11 + 2);
        assert_eq!(buf[10], 0x03, "LOCI update status must be 0x03");
    }

    /// SELECT EF.AD (3 bytes) and read.
    #[test]
    fn ref_read_ef_ad() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0xAD]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x03]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 3 + 2);
    }

    /// UPDATE BINARY on EF.AD and verify round-trip.
    #[test]
    fn ref_update_binary_roundtrip_ef_ad() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0xAD]);
        // Write [0xAA, 0xBB, 0xCC]
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Read back
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x03]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..3], &[0xAA, 0xBB, 0xCC],
            "read-back must match written data");
    }

    /// Navigate MF -> DF.GSM -> EF.IMSI -> MF -> EF.ICCID round-trip.
    #[test]
    fn ref_navigation_roundtrip() {
        let mut app = ref_app();
        // MF -> DF.GSM
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        // EF.IMSI
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08, "IMSI length byte");
        // Back to MF
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
        // EF.ICCID
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x98, "ICCID first byte");
    }

    /// SELECT EF response structure fields for a transparent EF from reference profile.
    #[test]
    fn ref_ef_select_response_structure() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x38]); // EF.SST
        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x0F]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[4], 0x6F, "FID high");
        assert_eq!(buf[5], 0x38, "FID low");
        assert_eq!(buf[6], 0x04, "file type = EF");
        assert_eq!(buf[13], 0x00, "structure = transparent");
        // File size (bytes 2-3, big-endian) should be 14.
        let file_size = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(file_size, 14, "EF.SST file size must be 14 bytes");
    }

    /// Sequential SELECT of multiple EFs in DF.GSM.
    #[test]
    fn ref_sequential_select_df_gsm_efs() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);

        // Table of (FID_hi, FID_lo, expected_data_size) for transparent EFs.
        let efs: [(u8, u8, u8); 7] = [
            (0x6F, 0x07, 9),   // EF.IMSI
            (0x6F, 0x20, 9),   // EF.Kc
            (0x6F, 0x31, 1),   // EF.HPPLMN
            (0x6F, 0x38, 14),  // EF.SST
            (0x6F, 0x78, 2),   // EF.ACC
            (0x6F, 0x7E, 11),  // EF.LOCI
            (0x6F, 0xAD, 3),   // EF.AD
        ];

        for (hi, lo, size) in &efs {
            send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, *hi, *lo]);
            let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, *size]);
            assert_eq!(sw(&buf, len), (0x90, 0x00),
                "READ BINARY on EF {hi:#04X}{lo:02X} must succeed");
            assert_eq!(len, *size as usize + 2,
                "EF {hi:#04X}{lo:02X} data length mismatch");
        }
    }

    /// RUN GSM ALGORITHM on reference profile produces valid COMP128 result.
    #[test]
    fn ref_run_gsm_algo() {
        let mut app = ref_app();
        let rand: [u8; 16] = [0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
                               0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35];
        let mut apdu = [0u8; 21];
        apdu[0] = 0xA0;
        apdu[1] = 0x88;
        apdu[4] = 0x10;
        apdu[5..21].copy_from_slice(&rand);

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x9F, 0x0C), "RUN GSM ALGO must queue 12 bytes");

        let (buf, len) = send(&mut app, &[0xA0, 0xC0, 0x00, 0x00, 0x0C]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 12 + 2);

        // Verify against direct COMP128 computation.
        let ki = Ki([0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F,
                     0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC]);
        let expected = comp128(&ki, &rand);
        assert_eq!(&buf[..4], &expected.sres, "SRES mismatch");
        assert_eq!(&buf[4..12], &expected.kc, "Kc mismatch");
    }

    // -----------------------------------------------------------------------
    // Adversarial / defensive tests -- Phase 7
    // -----------------------------------------------------------------------

    /// SELECT nonexistent FID on reference profile.
    #[test]
    fn ref_select_nonexistent_fid() {
        let mut app = ref_app();
        let (buf, len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0xDE, 0xAD]);
        assert_eq!(sw(&buf, len), (0x94, 0x04), "nonexistent FID must return 94 04");
    }

    /// READ BINARY past end of EF.ICCID.
    #[test]
    fn ref_read_binary_past_end() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        // EF.ICCID is 10 bytes. Read 5 bytes at offset 8 goes past end.
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x08, 0x05]);
        assert_eq!(sw(&buf, len), (0x94, 0x02), "read past end must return 94 02");
    }

    /// UPDATE BINARY past end of EF.
    #[test]
    fn ref_update_binary_past_end() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0xAD]); // EF.AD (3 bytes)
        // Write 4 bytes at offset 1 = 5 bytes total, exceeds 3.
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x01, 0x04, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(sw(&buf, len), (0x94, 0x02), "update past end must return 94 02");
    }

    /// READ BINARY with no EF selected on reference profile.
    #[test]
    fn ref_read_binary_no_ef() {
        let mut app = ref_app();
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x94, 0x00), "no EF selected must return 94 00");
    }

    /// RUN GSM ALGORITHM with wrong-length RAND.
    #[test]
    fn ref_run_gsm_algo_wrong_length() {
        let mut app = ref_app();
        // Only 8 bytes instead of 16.
        let (buf, len) = send(&mut app,
            &[0xA0, 0x88, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(sw(&buf, len), (0x67, 0x00), "wrong RAND length must return 67 00");
    }

    /// STATUS on reference profile shows MF by default.
    #[test]
    fn ref_status_shows_mf() {
        let mut app = ref_app();
        let (buf, len) = send(&mut app, &[0xA0, 0xF2, 0x00, 0x00, 0x17]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[4], 0x3F);
        assert_eq!(buf[5], 0x00);
    }

    /// Multiple updates at different offsets verify each other.
    #[test]
    fn ref_multi_update_binary() {
        let mut app = ref_app();
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
        send(&mut app, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x7B]); // EF.FPLMN (12 bytes)

        // Write [0x11, 0x22] at offset 0
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x00, 0x02, 0x11, 0x22]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Write [0x33, 0x44] at offset 4
        let (buf, len) = send(&mut app,
            &[0xA0, 0xD6, 0x00, 0x04, 0x02, 0x33, 0x44]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Read all 12 bytes -- first 2 changed, bytes 4-5 changed, rest unchanged
        let (buf, len) = send(&mut app, &[0xA0, 0xB0, 0x00, 0x00, 0x0C]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x11);
        assert_eq!(buf[1], 0x22);
        assert_eq!(buf[2], 0xFF); // unchanged
        assert_eq!(buf[3], 0xFF); // unchanged
        assert_eq!(buf[4], 0x33);
        assert_eq!(buf[5], 0x44);
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use simrs_fs::{EfDef, Fid, FileRef};
    use proptest::prelude::*;

    static PT_EF: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        None,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    );

    static PT_MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&PT_EF)],
    };

    // Linear-fixed EF for record-based proptest.
    static PT_LF_DATA: [u8; 18] = [
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
    ];

    static PT_LF_EF: EfDef = EfDef::linear_fixed(
        Fid::new(0x6F3A),
        None,
        6, 3,
        &PT_LF_DATA,
    );

    static PT_DF: DfDef = DfDef {
        fid: Fid::new(0x7F20),
        children: &[FileRef::Ef(&PT_LF_EF)],
    };

    static PT_MF2: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&PT_EF), FileRef::Df(&PT_DF)],
    };

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        // Any valid READ BINARY offset+length within file returns 90 00.
        #[test]
        fn read_binary_in_bounds(offset in 0u8..8, length in 0u8..=8u8) {
            prop_assume!(u16::from(offset) + u16::from(length) <= 8);
            let mut app = GsmApp::new(&PT_MF, Ki([0u8; 16]));
            let sel = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let rb = [0xA0, 0xB0, 0x00, offset, length];
            let cmd = Command::parse(&rb).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00));
            prop_assert_eq!(len, length as usize + 2);
        }

        // RUN GSM ALGORITHM always produces 12-byte result matching comp128.
        #[test]
        fn run_gsm_algo_matches_comp128(rand in proptest::collection::vec(any::<u8>(), 16..=16)) {
            let ki = Ki([0xAB; 16]);
            let mut app = GsmApp::new(&PT_MF, ki);
            let mut apdu = [0u8; 21];
            apdu[0] = 0xA0;
            apdu[1] = 0x88;
            apdu[4] = 0x10;
            apdu[5..21].copy_from_slice(&rand);

            let cmd = Command::parse(&apdu).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let cmd2 = Command::parse(&[0xA0, 0xC0, 0x00, 0x00, 0x0C]).unwrap();
            let rsp = app.handle(&cmd2, &mut buf);
            let len = rsp.len();
            prop_assert_eq!(len, 14);

            let mut rand_arr = [0u8; 16];
            rand_arr.copy_from_slice(&rand);
            let expected = comp128(&ki, &rand_arr);
            prop_assert_eq!(&buf[..4], &expected.sres);
            prop_assert_eq!(&buf[4..12], &expected.kc);
        }

        // Out-of-bounds READ BINARY always fails.
        #[test]
        fn read_binary_out_of_bounds_fails(offset in 0u16..256, length in 1u8..=255u8) {
            prop_assume!(u32::from(offset) + u32::from(length) > 8);
            let mut app = GsmApp::new(&PT_MF, Ki([0u8; 16]));
            let sel = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let off_hi = (offset >> 8) as u8;
            let off_lo = (offset & 0xFF) as u8;
            let rb = [0xA0, 0xB0, off_hi, off_lo, length];
            let cmd = Command::parse(&rb).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_ne!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "out-of-bounds READ BINARY must not succeed");
        }

        // Arbitrary data written via UPDATE BINARY reads back identically.
        #[test]
        #[allow(clippy::cast_possible_truncation)] // data.len() is 1..=8, fits in u8
        fn update_binary_roundtrip(data in proptest::collection::vec(any::<u8>(), 1..=8)) {
            let mut app = GsmApp::new(&PT_MF, Ki([0u8; 16]));
            let sel = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let lc = data.len() as u8;
            let mut apdu = [0u8; 5 + 8];
            apdu[0] = 0xA0;
            apdu[1] = 0xD6;
            apdu[2] = 0x00;
            apdu[3] = 0x00;
            apdu[4] = lc;
            apdu[5..5 + data.len()].copy_from_slice(&data);

            let cmd = Command::parse(&apdu[..5 + data.len()]).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "UPDATE BINARY must succeed");

            let rb = [0xA0, 0xB0, 0x00, 0x00, lc];
            let cmd = Command::parse(&rb).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "READ BINARY after update must succeed");
            prop_assert_eq!(&buf[..data.len()], &data[..],
                "read-back data must match written data");
        }

        // For any valid record number, READ RECORD succeeds.
        #[test]
        fn read_record_in_bounds(rec in 1u8..=3u8) {
            let mut app = GsmApp::new(&PT_MF2, Ki([0u8; 16]));
            // Navigate to DF, then EF
            let sel_df = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20];
            let cmd = Command::parse(&sel_df).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let sel_ef = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A];
            let cmd = Command::parse(&sel_ef).unwrap();
            let _ = app.handle(&cmd, &mut buf);

            let rr = [0xA0, 0xB2, rec, 0x04, 0x06];
            let cmd = Command::parse(&rr).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00),
                "READ RECORD {} must succeed", rec);
            prop_assert_eq!(len, 6 + 2, "record data must be 6 bytes");
        }
    }
}
