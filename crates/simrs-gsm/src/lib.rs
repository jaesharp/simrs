//! GSM 11.11 SIM application layer.
//!
//! Handles GSM-class (CLA=`0xA0`) APDUs: SELECT, GET RESPONSE, READ BINARY,
//! READ RECORD, STATUS, RUN GSM ALGORITHM (COMP128 A3/A8), VERIFY PIN,
//! and UNBLOCK PIN.
//!
//! Constructs GSM 11.11 clause 9.2.1 SELECT responses:
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
//! - GSM 11.11 v4.21.1 (ETS 300 608) -- ME-SIM interface
//! - 3GPP TS 51.011 V4.15.0 -- SIM-ME interface
//!
//! # `no_std`
//! This crate is `no_std`.
//!
//! # Example
//!
//! ```
//! use simrs_gsm::GsmApp;
//! use simrs_iso7816::Command;
//! use simrs_fs::{DfDef, EfDef, EfStructure, FileRef};
//! use simrs_pin::{PinKey, PinValue};
//!
//! static EF: EfDef = EfDef {
//!     fid: 0x2FE2, sfi: None,
//!     structure: EfStructure::Transparent,
//!     data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
//! };
//! static MF: DfDef = DfDef { fid: 0x3F00, children: &[FileRef::Ef(&EF)] };
//!
//! let ki = [0x01; 16];
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

use simrs_comp128::comp128;
use simrs_fs::{
    AdfSlot, DfDef, EfDef, EfStructure, FsError, SelectionCtx, SelectedFile,
};
use simrs_iso7816::{ins, Command, StatusWord};
use simrs_pin::{PinKey, PinManager, PinResult, PinValue};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// GSM CLA byte.
const CLA_GSM: u8 = 0xA0;

/// Maximum response queue size (SELECT response).
const RSP_QUEUE_CAP: usize = 23;

/// DF/MF SELECT response length per GSM 11.11 clause 9.2.1.
const DF_RSP_LEN: usize = 23;

/// EF SELECT response length per GSM 11.11 clause 9.2.1.
const EF_RSP_LEN: usize = 15;

// GSM 11.11 status words (proprietary, not reused from simrs-iso7816).
const SW_FILE_NOT_FOUND: [u8; 2] = [0x94, 0x04];
const SW_FILE_INCONSISTENT: [u8; 2] = [0x94, 0x08];
const SW_NO_EF_SELECTED: [u8; 2] = [0x94, 0x00];

// ---------------------------------------------------------------------------
// GsmApp
// ---------------------------------------------------------------------------

/// GSM 11.11 SIM application.
///
/// Handles CLA=`0xA0` APDUs. Owns filesystem context, PIN manager,
/// COMP128 key, and the response queue for GET RESPONSE.
pub struct GsmApp {
    fs: SelectionCtx,
    pin: PinManager<5>,
    ki: [u8; 16],
    rsp_queue: [u8; RSP_QUEUE_CAP],
    rsp_queue_len: u8,
}

impl GsmApp {
    /// Create a new GSM application rooted at the given MF.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_gsm::GsmApp;
    /// use simrs_fs::DfDef;
    ///
    /// static MF: DfDef = DfDef { fid: 0x3F00, children: &[] };
    /// let app = GsmApp::new(&MF, [0u8; 16]);
    /// ```
    pub const fn new(mf: &'static DfDef, ki: [u8; 16]) -> Self {
        Self {
            fs: SelectionCtx::new(mf),
            pin: PinManager::new(),
            ki,
            rsp_queue: [0u8; RSP_QUEUE_CAP],
            rsp_queue_len: 0,
        }
    }

    /// Access the PIN manager for configuration (add PINs).
    pub const fn pin_manager(&mut self) -> &mut PinManager<5> {
        &mut self.pin
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes (159).
    pub const SNAPSHOT_SIZE: usize =
        SelectionCtx::SNAPSHOT_SIZE + PinManager::<5>::SNAPSHOT_SIZE + 16 + RSP_QUEUE_CAP + 1;

    /// Serialize the GSM application state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut off = 0;
        off += self.fs.save_state(&mut buf[off..]);
        off += self.pin.save_state(&mut buf[off..]);
        buf[off..off + 16].copy_from_slice(&self.ki);
        off += 16;
        buf[off..off + RSP_QUEUE_CAP].copy_from_slice(&self.rsp_queue);
        off += RSP_QUEUE_CAP;
        buf[off] = self.rsp_queue_len;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the GSM application state from `buf`.
    ///
    /// Returns `true` on success. The `adfs` parameter is passed through
    /// to `SelectionCtx::restore_state` (typically `&[]` for GSM).
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
        if !self.pin.restore_state(&buf[off..]) {
            return false;
        }
        off += PinManager::<5>::SNAPSHOT_SIZE;
        self.ki.copy_from_slice(&buf[off..off + 16]);
        off += 16;
        self.rsp_queue.copy_from_slice(&buf[off..off + RSP_QUEUE_CAP]);
        off += RSP_QUEUE_CAP;
        let queue_len = buf[off];
        if queue_len as usize > RSP_QUEUE_CAP {
            return false;
        }
        self.rsp_queue_len = queue_len;
        true
    }

    /// Handle an APDU command. Returns a slice of `buf` containing
    /// the response: either just `[SW1, SW2]` or `[data..., SW1, SW2]`.
    ///
    /// # Errors
    ///
    /// Returns `6E 00` (class not supported) if CLA is not `0xA0`.
    /// Returns `6D 00` (instruction not supported) for unknown INS.
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
            self.rsp_queue_len = 0;
        }

        match cmd.ins() {
            ins::SELECT => self.handle_select(cmd, buf),
            ins::GET_RESPONSE => self.handle_get_response(cmd, buf),
            ins::READ_BINARY => self.handle_read_binary(cmd, buf),
            ins::READ_RECORD => self.handle_read_record(cmd, buf),
            ins::STATUS => self.handle_status(cmd, buf),
            ins::AUTHENTICATE => self.handle_run_gsm_algo(cmd, buf),
            ins::VERIFY => self.handle_verify(cmd, buf),
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
            return write_sw_raw(buf, 0x6A, 0x86);
        }
        if cmd.data().len() != 2 {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let fid = u16::from_be_bytes([cmd.data()[0], cmd.data()[1]]);
        match self.fs.select_by_fid(fid) {
            Ok(sel) => {
                // Build the GSM SELECT response and queue it.
                let rsp_len = match sel {
                    SelectedFile::Df(df) => {
                        build_df_response(df, &mut self.rsp_queue);
                        DF_RSP_LEN
                    }
                    SelectedFile::Ef(ef) => {
                        build_ef_response(ef, &mut self.rsp_queue);
                        EF_RSP_LEN
                    }
                };
                self.rsp_queue_len = rsp_len as u8;
                // Return 9F XX (response data available).
                write_sw_raw(buf, 0x9F, rsp_len as u8)
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
            return write_sw_raw(buf, 0x6A, 0x86);
        }
        let len = self.rsp_queue_len as usize;
        if len == 0 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }
        let le = cmd.le().unwrap_or(0) as usize;
        let n = if le == 0 { len } else { le.min(len) };
        if buf.len() < n + 2 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }
        buf[..n].copy_from_slice(&self.rsp_queue[..n]);
        buf[n] = 0x90;
        buf[n + 1] = 0x00;
        self.rsp_queue_len = 0;
        &buf[..n + 2]
    }

    // -- READ BINARY --

    fn handle_read_binary<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let offset = u16::from_be_bytes([cmd.p1(), cmd.p2()]);
        let le = u16::from(cmd.le().unwrap_or(0));

        match self.fs.read_binary(offset, le) {
            Ok(data) => {
                let n = data.len();
                if buf.len() < n + 2 {
                    return write_sw(buf, StatusWord::NoPreciseDiagnosis);
                }
                buf[..n].copy_from_slice(data);
                buf[n] = 0x90;
                buf[n + 1] = 0x00;
                &buf[..n + 2]
            }
            Err(FsError::NoEfSelected) => write_sw_raw(buf, SW_NO_EF_SELECTED[0], SW_NO_EF_SELECTED[1]),
            Err(FsError::NotTransparent) => write_sw_raw(buf, SW_FILE_INCONSISTENT[0], SW_FILE_INCONSISTENT[1]),
            Err(FsError::OffsetOutOfRange) => write_sw_raw(buf, 0x94, 0x02),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- READ RECORD --

    fn handle_read_record<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let rec_num = cmd.p1();
        // P2 = 0x04 means "absolute/current" mode per GSM 11.11.
        // We accept any P2 and just use the record number.

        match self.fs.read_record(rec_num) {
            Ok(data) => {
                let n = data.len();
                if buf.len() < n + 2 {
                    return write_sw(buf, StatusWord::NoPreciseDiagnosis);
                }
                buf[..n].copy_from_slice(data);
                buf[n] = 0x90;
                buf[n + 1] = 0x00;
                &buf[..n + 2]
            }
            Err(FsError::NoEfSelected) => write_sw_raw(buf, SW_NO_EF_SELECTED[0], SW_NO_EF_SELECTED[1]),
            Err(FsError::NotRecordBased) => write_sw_raw(buf, SW_FILE_INCONSISTENT[0], SW_FILE_INCONSISTENT[1]),
            Err(FsError::RecordOutOfRange) => write_sw_raw(buf, 0x94, 0x02),
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
            return write_sw_raw(buf, 0x6A, 0x86);
        }
        let mut rsp = [0u8; DF_RSP_LEN];
        build_df_response(self.fs.current_df(), &mut rsp);
        let le = cmd.le().unwrap_or(0) as usize;
        let n = if le == 0 { DF_RSP_LEN } else { le.min(DF_RSP_LEN) };
        if buf.len() < n + 2 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }
        buf[..n].copy_from_slice(&rsp[..n]);
        buf[n] = 0x90;
        buf[n + 1] = 0x00;
        &buf[..n + 2]
    }

    // -- RUN GSM ALGORITHM (COMP128) --

    fn handle_run_gsm_algo<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 || cmd.p2() != 0x00 {
            return write_sw_raw(buf, 0x6A, 0x86);
        }
        if cmd.data().len() != 16 {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut rand = [0u8; 16];
        rand.copy_from_slice(cmd.data());
        let result = comp128(&self.ki, &rand);

        // Queue 12-byte result: 4-byte SRES + 8-byte Kc.
        self.rsp_queue[..4].copy_from_slice(&result.sres);
        self.rsp_queue[4..12].copy_from_slice(&result.kc);
        self.rsp_queue_len = 12;

        write_sw_raw(buf, 0x9F, 0x0C)
    }

    // -- VERIFY PIN --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_verify<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw_raw(buf, 0x6A, 0x86);
        }
        let key = PinKey(cmd.p2());

        // Le=0 (5-byte APDU with P3=0): query retry count.
        if cmd.data().is_empty() {
            return match self.pin.retries(key) {
                Some(n) => write_sw(buf, StatusWord::pin_retries(n & 0x0F)),
                None => write_sw(buf, StatusWord::wrong_params(0x88)),
            };
        }

        if cmd.data().len() != 8 {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut pin_bytes = [0xFFu8; 8];
        pin_bytes.copy_from_slice(cmd.data());
        let val = PinValue::new(pin_bytes);

        match self.pin.verify(key, &val) {
            PinResult::Success => write_sw(buf, StatusWord::Success),
            PinResult::WrongPin { retries_remaining } => {
                write_sw(buf, StatusWord::pin_retries(retries_remaining & 0x0F))
            }
            PinResult::Blocked => write_sw(buf, StatusWord::command_not_allowed(0x83)),
            PinResult::Disabled => write_sw(buf, StatusWord::command_not_allowed(0x84)),
            PinResult::NotFound => write_sw(buf, StatusWord::wrong_params(0x88)),
        }
    }

    // -- UNBLOCK PIN --

    fn handle_unblock<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw_raw(buf, 0x6A, 0x86);
        }
        let key = PinKey(cmd.p2());

        // Le=0: query PUK retry count.
        if cmd.data().is_empty() {
            return match self.pin.puk_retries(key) {
                Some(n) => write_sw(buf, StatusWord::pin_retries(n & 0x0F)),
                None => write_sw(buf, StatusWord::wrong_params(0x88)),
            };
        }

        // Data must be 16 bytes: 8 PUK + 8 new PIN.
        if cmd.data().len() != 16 {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut puk_bytes = [0xFFu8; 8];
        puk_bytes.copy_from_slice(&cmd.data()[..8]);
        let puk = PinValue::new(puk_bytes);

        let mut new_pin_bytes = [0xFFu8; 8];
        new_pin_bytes.copy_from_slice(&cmd.data()[8..16]);
        let new_pin = PinValue::new(new_pin_bytes);

        match self.pin.unblock(key, &puk, &new_pin) {
            PinResult::Success => write_sw(buf, StatusWord::Success),
            PinResult::WrongPin { retries_remaining } => {
                write_sw(buf, StatusWord::pin_retries(retries_remaining & 0x0F))
            }
            PinResult::Blocked => write_sw(buf, StatusWord::command_not_allowed(0x83)),
            PinResult::NotFound => write_sw(buf, StatusWord::wrong_params(0x88)),
            PinResult::Disabled => write_sw(buf, StatusWord::command_not_allowed(0x84)),
        }
    }
}

// ---------------------------------------------------------------------------
// GSM 11.11 SELECT response builders
// ---------------------------------------------------------------------------

/// Build a 23-byte DF/MF SELECT response per GSM 11.11 clause 9.2.1.
fn build_df_response(df: &DfDef, out: &mut [u8; RSP_QUEUE_CAP]) {
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
    out[6] = if df.fid == 0x3F00 { 0x01 } else { 0x02 };

    // Bytes 7-11: RFU.
    // Byte 12: GSM-specific data length (10 bytes follow).
    out[12] = 0x0A;

    // Byte 13: file characteristics.
    out[13] = 0x32; // Clock stop allowed, 1.8V+3V

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
    out[16] = 0x04;

    // Byte 17: RFU.
    // Bytes 18-21: CHV1 status, UNBLOCK CHV1, CHV2, UNBLOCK CHV2.
    out[18] = 0x83; // CHV1: initialized, 3 retries
    out[19] = 0x8A; // UNBLOCK CHV1: initialized, 10 retries
    out[20] = 0x83; // CHV2
    out[21] = 0x8A; // UNBLOCK CHV2
    // Byte 22: RFU.
}

/// Build a 15-byte EF SELECT response per GSM 11.11 clause 9.2.1.
#[allow(clippy::cast_possible_truncation)]
fn build_ef_response(ef: &EfDef, out: &mut [u8; RSP_QUEUE_CAP]) {
    out.fill(0x00);

    // Bytes 0-1: RFU.
    // Bytes 2-3: file size (big-endian).
    let size = ef.data.len() as u16;
    let size_be = size.to_be_bytes();
    out[2] = size_be[0];
    out[3] = size_be[1];

    // Bytes 4-5: File ID.
    let fid_be = ef.fid.to_be_bytes();
    out[4] = fid_be[0];
    out[5] = fid_be[1];

    // Byte 6: file type = 0x04 (EF).
    out[6] = 0x04;

    // Byte 7: 0x01 for cyclic, 0x00 otherwise.
    out[7] = match ef.structure {
        EfStructure::Cyclic { .. } => 0x01,
        _ => 0x00,
    };

    // Bytes 8-10: access conditions (all zeros = always allowed).
    // Byte 11: file status (0x01 = not invalidated).
    out[11] = 0x01;

    // Byte 12: data extra length.
    out[12] = 0x02;

    // Byte 13: EF structure.
    out[13] = match ef.structure {
        EfStructure::Transparent => 0x00,
        EfStructure::LinearFixed { .. } => 0x01,
        EfStructure::Cyclic { .. } => 0x03,
    };

    // Byte 14: record length.
    out[14] = match ef.structure {
        EfStructure::LinearFixed { record_size, .. }
        | EfStructure::Cyclic { record_size, .. } => record_size,
        EfStructure::Transparent => 0x00,
    };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a `StatusWord` into buf and return a 2-byte slice.
fn write_sw(buf: &mut [u8], sw: StatusWord) -> &[u8] {
    let [sw1, sw2] = sw.to_bytes();
    write_sw_raw(buf, sw1, sw2)
}

/// Write raw SW1/SW2 into buf and return a 2-byte slice.
fn write_sw_raw(buf: &mut [u8], sw1: u8, sw2: u8) -> &[u8] {
    buf[0] = sw1;
    buf[1] = sw2;
    &buf[..2]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_fs::{EfDef, EfStructure, FileRef};

    // -- Test filesystem --

    static EF_ICCID: EfDef = EfDef {
        fid: 0x2FE2,
        sfi: Some(2),
        structure: EfStructure::Transparent,
        data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    };

    static EF_DIR_DATA: [u8; 16] = [
        0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00,
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
        0x41, 0x6C, 0x69, 0x63, 0x65, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x42, 0x6F, 0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
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

    static EF_IMSI: EfDef = EfDef {
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
        children: &[FileRef::Ef(&EF_IMSI), FileRef::Ef(&EF_KC)],
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

    static KI: [u8; 16] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

    fn app() -> GsmApp {
        let mut a = GsmApp::new(&MF, KI);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey(0x01), &pin_val, 3, &puk_val, 10, true)
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
        // fs(8) + pin(111) + ki(16) + rsp_queue(23) + rsp_queue_len(1) = 159
        assert_eq!(GsmApp::SNAPSHOT_SIZE, 159);
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
        let mut restored = GsmApp::new(&MF, [0u8; 16]);
        assert!(restored.restore_state(&snap, &[]));

        // Verify: read EF.IMSI works (fs state restored to DF.GSM + EF.IMSI).
        let (buf, len) = send(&mut restored, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08); // IMSI first byte

        // Verify: PIN retries are 2 (degraded from 3).
        let (buf, len) = send(&mut restored, &[0xA0, 0x20, 0x00, 0x01, 0x00]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
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
        app.save_state(&mut snap);
        let mut restored = GsmApp::new(&MF, [0u8; 16]);
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
        src.save_state(&mut snap);
        // rsp_queue_len is the last byte of the snapshot.
        *snap.last_mut().unwrap() = u8::MAX;
        let mut dst = app();
        assert!(!dst.restore_state(&snap, &[]));
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use simrs_fs::{EfDef, EfStructure, FileRef};
    use proptest::prelude::*;

    static PT_EF: EfDef = EfDef {
        fid: 0x2FE2,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };

    static PT_MF: DfDef = DfDef {
        fid: 0x3F00,
        children: &[FileRef::Ef(&PT_EF)],
    };

    proptest! {
        // Any valid READ BINARY offset+length within file returns 90 00.
        #[test]
        fn read_binary_in_bounds(offset in 0u8..8, length in 0u8..=8u8) {
            prop_assume!(u16::from(offset) + u16::from(length) <= 8);
            let mut app = GsmApp::new(&PT_MF, [0u8; 16]);
            let sel = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            app.handle(&cmd, &mut buf);

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
            let ki = [0xAB; 16];
            let mut app = GsmApp::new(&PT_MF, ki);
            let mut apdu = [0u8; 21];
            apdu[0] = 0xA0;
            apdu[1] = 0x88;
            apdu[4] = 0x10;
            apdu[5..21].copy_from_slice(&rand);

            let cmd = Command::parse(&apdu).unwrap();
            let mut buf = [0u8; 256];
            app.handle(&cmd, &mut buf);

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
    }
}
