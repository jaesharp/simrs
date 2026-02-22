//! 3GPP USIM application layer.
//!
//! Handles interindustry (CLA=`0x00`) and ETSI-class (CLA=`0x80`) APDUs:
//! SELECT (with FCP BER-TLV response), GET RESPONSE, READ BINARY,
//! READ RECORD, UPDATE BINARY, UPDATE RECORD, INCREASE, STATUS,
//! AUTHENTICATE (Milenage), VERIFY PIN, CHANGE REFERENCE DATA,
//! DISABLE PIN, ENABLE PIN, UNBLOCK PIN, TERMINAL PROFILE, FETCH,
//! TERMINAL RESPONSE, and ENVELOPE.
//!
//! Constructs FCP BER-TLV per ETSI TS 102 221 clause 11.1.1.3 using a
//! dry-run/real-run pattern for buffer-size determination.
//!
//! Post-APDU hook: if a proactive command is pending and SW would be
//! `90 00`, the status is overridden to `91 XX` where XX is the pending
//! command length.
//!
//! # Standards
//! - ETSI TS 102 221 V16.4.0 -- UICC-terminal interface
//! - 3GPP TS 31.101 V17.0.0 -- UICC-terminal interface (3GPP additions)
//! - 3GPP TS 31.102 V17.5.0 -- USIM application characteristics
//! - ETSI TS 102 223 V17.2.0 -- Card Application Toolkit (proactive)
//!
//! # `no_std`
//! This crate is `no_std`. All buffers are stack-allocated.
//!
//! # Example
//!
//! ```
//! use simrs_usim::UsimApp;
//! use simrs_iso7816::Command;
//! use simrs_fs::{AdfSlot, DfDef, EfDef, EfStructure, Fid, FileRef};
//! use simrs_milenage::{MilenageParams, OpVariant};
//!
//! static EF: EfDef = EfDef {
//!     fid: Fid(0x2FE2), sfi: None,
//!     structure: EfStructure::Transparent,
//!     data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
//! };
//! static MF: DfDef = DfDef { fid: Fid(0x3F00), children: &[FileRef::Ef(&EF)] };
//!
//! let milenage = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
//! let mut app = UsimApp::new(&MF, &[], milenage);
//!
//! // SELECT MF (interindustry CLA)
//! let cmd = Command::parse(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]).unwrap();
//! let mut buf = [0u8; 256];
//! let rsp = app.handle(&cmd, &mut buf);
//! assert_eq!(rsp[0], 0x61); // SW1: data available via GET RESPONSE
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
// USIM documentation uses many standard 3GPP terms (OPc, FCP, ADF, etc.)
#![allow(clippy::doc_markdown)]

use simrs_bertlv::Encoder;
use simrs_fs::{
    AdfSlot, DfDef, EfDef, EfStructure, Fid, FsData, FsError, SelectionCtx, SelectedFile,
};
use simrs_iso7816::{fcp, ins, sw2, write_data_sw, write_sw, Command, ResponseQueue, StatusWord};
use simrs_milenage::{AuthAlgorithm, MilenageError, MilenageParams};
use simrs_pin::{PinKey, PinManager, PinResult, PinValue};
use simrs_proactive::ProactiveState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// CLA byte for interindustry commands.
const CLA_INTER: u8 = 0x00;

/// CLA byte for ETSI CAT (proactive) commands.
const CLA_ETSI: u8 = 0x80;

/// Maximum FCP size (conservative upper bound for our file tree).
const FCP_BUF_CAP: usize = 64;

// ETSI TS 102 221 clause 11.1.1.4.1: File descriptor byte values.
const FD_DF: u8 = 0x78;
const FD_TRANSPARENT: u8 = 0x41;
const FD_LINEAR_FIXED: u8 = 0x42;
const FD_CYCLIC: u8 = 0x46;
const DATA_CODING_BER_TLV: u8 = 0x21;

// ETSI TS 102 221 clause 11.1.1.4.9: Life cycle status.
const LIFECYCLE_ACTIVATED: u8 = 0x05;

// ETSI TS 102 221 clause 11.1.1.4.7: Security attribute compact format.
const SECURITY_ALWAYS: u8 = 0x7F;

// ETSI TS 102 221 clause 11.1.1.4.8: SFI encoding.
const SFI_INDICATOR: u8 = 0x04;

// PIN status template DO values.
const PS_DO_TAG: u8 = 0x90;

// 3GPP TS 31.102 clause 7.1.2: AUTHENTICATE protocol constants.
const P2_UMTS_CONTEXT: u8 = 0x81;
const AUTH_DATA_LEN: usize = 34;
const AUTH_VECTOR_LEN_PREFIX: u8 = 0x10;
const AUTH_SUCCESS_TAG: u8 = 0xDB;
const AUTH_SYNC_FAILURE_TAG: u8 = 0xDC;
const AUTS_LEN: u8 = 0x0E;
const AUTH_RES_LEN: u8 = 0x08;
const AUTH_CK_IK_LEN: u8 = 0x10;
const AUTH_SUCCESS_INNER_LEN: u8 = 1 + AUTH_RES_LEN + 1 + AUTH_CK_IK_LEN + 1 + AUTH_CK_IK_LEN;

// ---------------------------------------------------------------------------
// AuthenticateResult
// ---------------------------------------------------------------------------

/// AUTHENTICATE command result per TS 31.102 clause 7.1.2.1.
///
/// Encodes the three possible outcomes of UMTS AUTHENTICATE:
/// - Success: RES, CK, IK returned in tag 0xDB
/// - Sync failure: AUTS returned in tag 0xDC for resynchronization
/// - MAC failure: SW 98 62
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticateResult {
    /// Successful authentication. Contains RES (8 bytes), CK (16 bytes),
    /// IK (16 bytes). Encoded as tag 0xDB with nested TLV.
    Success {
        /// Authentication response (f2 output).
        res: [u8; 8],
        /// Ciphering key (f3 output).
        ck: [u8; 16],
        /// Integrity key (f4 output).
        ik: [u8; 16],
    },
    /// SQN synchronization failure. Contains AUTS (14 bytes).
    /// Encoded as tag 0xDC.
    SyncFailure {
        /// AUTS resynchronization token (14 bytes).
        auts: [u8; 14],
    },
    /// MAC verification failure. Returns SW 98 62.
    MacFailure,
}

impl AuthenticateResult {
    /// Encode the result into a byte buffer for APDU response.
    ///
    /// For `Success`: writes tag 0xDB, inner length, then length-prefixed
    /// RES, CK, IK. Total: 2 + (1+8) + (1+16) + (1+16) = 45 bytes.
    ///
    /// For `SyncFailure`: writes tag 0xDC, length 0x0E, then 14 AUTS bytes.
    /// Total: 16 bytes.
    ///
    /// For `MacFailure`: writes nothing (SW only). Returns 0.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match self {
            Self::Success { res, ck, ik } => {
                // 0xDB <inner_len> <res_len> [RES] <ck_len> [CK] <ik_len> [IK]
                let inner_len: u8 = AUTH_SUCCESS_INNER_LEN;
                let mut pos: usize = 0;
                buf[pos] = AUTH_SUCCESS_TAG;
                pos += 1;
                buf[pos] = inner_len;
                pos += 1;
                // RES
                buf[pos] = AUTH_RES_LEN;
                pos += 1;
                buf[pos..pos + 8].copy_from_slice(res);
                pos += 8;
                // CK
                buf[pos] = AUTH_CK_IK_LEN;
                pos += 1;
                buf[pos..pos + 16].copy_from_slice(ck);
                pos += 16;
                // IK
                buf[pos] = AUTH_CK_IK_LEN;
                pos += 1;
                buf[pos..pos + 16].copy_from_slice(ik);
                pos += 16;
                pos
            }
            Self::SyncFailure { auts } => {
                buf[0] = AUTH_SYNC_FAILURE_TAG;
                buf[1] = AUTS_LEN;
                buf[2..16].copy_from_slice(auts);
                16
            }
            Self::MacFailure => 0,
        }
    }
}

// PIN data widths (ETSI TS 102 221).
const PIN_DATA_LEN: usize = 8;
/// PUK(8) + new PIN(8) for RESET RETRY COUNTER.
const PUK_NEW_PIN_LEN: usize = PIN_DATA_LEN * 2;
/// Old PIN(8) + new PIN(8) for CHANGE REFERENCE DATA.
const CHANGE_PIN_DATA_LEN: usize = PIN_DATA_LEN * 2;

// ---------------------------------------------------------------------------
// UsimApp
// ---------------------------------------------------------------------------

/// 3GPP USIM application.
///
/// Handles interindustry (CLA=`0x00`) and ETSI-class (CLA=`0x80`) APDUs.
/// Owns filesystem context, PIN manager, authentication algorithm, proactive
/// state, and the response queue for GET RESPONSE.
///
/// The type parameter `A` selects the authentication algorithm.
/// The default is [`MilenageParams`] (TS 35.206).
pub struct UsimApp<A: AuthAlgorithm = MilenageParams> {
    fs: SelectionCtx,
    data: FsData<512>,
    mf: &'static DfDef,
    adfs: &'static [AdfSlot],
    pin: PinManager<5>,
    auth: A,
    proactive: ProactiveState,
    rsp_queue: ResponseQueue<64>,
}

impl<A: AuthAlgorithm> UsimApp<A> {
    /// Create a new USIM application.
    ///
    /// # Panics
    ///
    /// Panics if the static filesystem tree (MF + ADFs) does not fit in the
    /// internal 512-byte `FsData` buffer or contains more than 32 EFs.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_usim::UsimApp;
    /// use simrs_fs::{DfDef, Fid, AdfSlot};
    /// use simrs_milenage::{MilenageParams, OpVariant};
    ///
    /// static MF: DfDef = DfDef { fid: Fid(0x3F00), children: &[] };
    /// let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
    /// let app = UsimApp::new(&MF, &[], mil);
    /// ```
    pub fn new(
        mf: &'static DfDef,
        adfs: &'static [AdfSlot],
        auth: A,
    ) -> Self {
        let mut data = FsData::<512>::new();
        // Panic on init failure: the static filesystem tree must fit in CAP.
        if let Err(e) = data.init_with_adfs(mf, adfs) {
            panic!("FsData init failed: {}", e);
        }
        Self {
            fs: SelectionCtx::new(mf),
            data,
            mf,
            adfs,
            pin: PinManager::new(),
            auth,
            proactive: ProactiveState::new(),
            rsp_queue: ResponseQueue::new(),
        }
    }

    /// Access the PIN manager for configuration (add PINs).
    pub const fn pin_manager(&mut self) -> &mut PinManager<5> {
        &mut self.pin
    }

    /// Access the proactive state for queuing commands.
    pub const fn proactive_state(&mut self) -> &mut ProactiveState {
        &mut self.proactive
    }

    /// Advance all UICC-side proactive timers by `elapsed_secs`.
    ///
    /// Returns the number of timers that expired. The caller should
    /// read expired timer IDs via
    /// `proactive_state().take_expired_timer()` and generate Timer
    /// Expiry envelopes as appropriate.
    pub const fn tick(&mut self, elapsed_secs: u32) -> u8 {
        self.proactive.tick(elapsed_secs)
    }

    // -- snapshot --

    /// Snapshot buffer size in bytes.
    pub const SNAPSHOT_SIZE: usize =
        SelectionCtx::SNAPSHOT_SIZE
        + FsData::<512>::SNAPSHOT_SIZE
        + PinManager::<5>::SNAPSHOT_SIZE
        + A::SNAPSHOT_SIZE
        + ProactiveState::SNAPSHOT_SIZE
        + ResponseQueue::<64>::SNAPSHOT_SIZE;

    /// Serialize the USIM application state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    /// The `adfs` reference is not serialized (static, reconstructed on restore).
    #[must_use]
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut off = 0;
        off += self.fs.save_state(&mut buf[off..]);
        off += self.data.save_state(&mut buf[off..]);
        off += self.pin.save_state(&mut buf[off..]);
        off += self.auth.save_state(&mut buf[off..]);
        off += self.proactive.save_state(&mut buf[off..]);
        off += self.rsp_queue.save_state(&mut buf[off..]);
        let _ = off;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the USIM application state from `buf`.
    ///
    /// Returns `true` on success. The `adfs` field is not restored from the
    /// snapshot; it remains as set during construction.
    #[must_use]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut off = 0;
        if !self.fs.restore_state(&buf[off..], self.adfs) {
            return false;
        }
        off += SelectionCtx::SNAPSHOT_SIZE;
        // Re-init FsData entries from the static tree, then overwrite
        // the buffer with the saved snapshot data.
        if self.data.init_with_adfs(self.mf, self.adfs).is_err() {
            return false;
        }
        if !self.data.restore_state(&buf[off..]) {
            return false;
        }
        off += FsData::<512>::SNAPSHOT_SIZE;
        if !self.pin.restore_state(&buf[off..]) {
            return false;
        }
        off += PinManager::<5>::SNAPSHOT_SIZE;
        if !self.auth.restore_state(&buf[off..]) {
            return false;
        }
        off += A::SNAPSHOT_SIZE;
        if !self.proactive.restore_state(&buf[off..]) {
            return false;
        }
        off += ProactiveState::SNAPSHOT_SIZE;
        if !self.rsp_queue.restore_state(&buf[off..]) {
            return false;
        }
        off += ResponseQueue::<64>::SNAPSHOT_SIZE;
        let _ = off;
        true
    }

    /// Handle an APDU command. Returns a slice of `buf` containing
    /// the response: either just `[SW1, SW2]` or `[data..., SW1, SW2]`.
    ///
    /// Accepts CLA=`0x00` (interindustry) and CLA=`0x80` (ETSI CAT).
    /// Returns `6E 00` for any other CLA.
    ///
    /// After dispatching, if SW would be `90 00` and a proactive command
    /// is pending, overrides to `91 XX`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn handle<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let cla = cmd.cla_raw();

        // CLA check: accept 0x00 (interindustry) and 0x80 (ETSI CAT).
        if cla != CLA_INTER && cla != CLA_ETSI {
            return write_sw(buf, StatusWord::ClassNotSupported);
        }

        // Any command other than GET RESPONSE clears the response queue.
        if cmd.ins() != ins::GET_RESPONSE {
            self.rsp_queue.clear();
        }

        let rsp = match (cla, cmd.ins()) {
            // -- Interindustry commands (CLA=0x00) --
            (CLA_INTER, ins::SELECT) => self.handle_select(cmd, buf),
            (CLA_INTER, ins::GET_RESPONSE) => self.handle_get_response(cmd, buf),
            (CLA_INTER, ins::READ_BINARY) => self.handle_read_binary(cmd, buf),
            (CLA_INTER, ins::READ_RECORD) => self.handle_read_record(cmd, buf),
            (CLA_INTER, ins::UPDATE_BINARY) => self.handle_update_binary(cmd, buf),
            (CLA_INTER, ins::UPDATE_RECORD) => self.handle_update_record(cmd, buf),
            (CLA_INTER, ins::INCREASE) => self.handle_increase(cmd, buf),
            (CLA_INTER, ins::STATUS) => self.handle_status(cmd, buf),
            (CLA_INTER, ins::AUTHENTICATE) => self.handle_authenticate(cmd, buf),
            (CLA_INTER, ins::VERIFY) => self.handle_verify(cmd, buf),
            (CLA_INTER, ins::CHANGE_REF_DATA) => self.handle_change_ref_data(cmd, buf),
            (CLA_INTER, ins::DISABLE_PIN) => self.handle_disable_pin(cmd, buf),
            (CLA_INTER, ins::ENABLE_PIN) => self.handle_enable_pin(cmd, buf),
            (CLA_INTER, ins::RESET_RETRY_CTR) => self.handle_unblock(cmd, buf),
            // -- ETSI CAT commands (CLA=0x80) --
            (CLA_ETSI, ins::TERMINAL_PROFILE) => self.handle_terminal_profile(cmd, buf),
            (CLA_ETSI, ins::FETCH) => self.handle_fetch(cmd, buf),
            (CLA_ETSI, ins::TERMINAL_RESPONSE) => self.handle_terminal_response(cmd, buf),
            (CLA_ETSI, ins::ENVELOPE) => self.handle_envelope(cmd, buf),
            _ => write_sw(buf, StatusWord::InsNotSupported),
        };

        // Proactive override: if SW is 90 00 and a command is pending,
        // rewrite to 91 XX.
        let len = rsp.len();
        if len >= 2 {
            let (sw1, sw2) = self.proactive.override_status(buf[len - 2], buf[len - 1]);
            buf[len - 2] = sw1;
            buf[len - 1] = sw2;
        }
        &buf[..len]
    }

    // -- SELECT (P1=0x00 by FID, P1=0x04 by AID) --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_select<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        match cmd.p1() {
            0x00 => {
                // Select by FID.
                if cmd.data().len() != 2 {
                    return write_sw(buf, StatusWord::WrongLength);
                }
                let fid = Fid::from_be_bytes([cmd.data()[0], cmd.data()[1]]);
                match self.fs.select_by_fid(fid) {
                    Ok(sel) => self.queue_fcp(sel, None, buf),
                    Err(FsError::FileNotFound) => write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND)),
                    Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
                }
            }
            0x04 => {
                // Select by AID.
                match self.fs.select_by_aid(cmd.data(), self.adfs) {
                    Ok(sel) => {
                        let aid = cmd.data();
                        self.queue_fcp(sel, Some(aid), buf)
                    }
                    Err(FsError::FileNotFound) => write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND)),
                    Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
                }
            }
            _ => write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    /// Build FCP, queue it, return 61 XX.
    #[allow(clippy::cast_possible_truncation)]
    fn queue_fcp<'buf>(
        &mut self,
        sel: SelectedFile,
        aid: Option<&[u8]>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let fcp_len = build_fcp(sel, aid, self.rsp_queue.buf_mut());
        self.rsp_queue.set_len(fcp_len);
        write_sw(buf, StatusWord::bytes_available(fcp_len as u8))
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
        let offset = u16::from_be_bytes([cmd.p1(), cmd.p2()]);
        let le = u16::from(cmd.le().unwrap_or(0));

        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };

        match self.data.read_binary(ef, offset, le) {
            Ok(data) => write_data_sw(buf, data, StatusWord::Success),
            Err(FsError::NotTransparent) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::OffsetOutOfRange) => write_sw(buf, StatusWord::wrong_params(sw2::FILE_NOT_FOUND)),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- READ RECORD --

    fn handle_read_record<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let rec_num = cmd.p1();

        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };

        match self.data.read_record(ef, rec_num) {
            Ok(data) => write_data_sw(buf, data, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::RecordOutOfRange) => write_sw(buf, StatusWord::wrong_params(sw2::RECORD_NOT_FOUND)),
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
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        let offset = u16::from_be_bytes([cmd.p1(), cmd.p2()]);
        match self.data.write_binary(ef, offset, cmd.data()) {
            Ok(()) => write_sw(buf, StatusWord::Success),
            Err(FsError::NotTransparent) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::OffsetOutOfRange) => write_sw(buf, StatusWord::WrongLength),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- UPDATE RECORD --

    fn handle_update_record<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        let rec_num = cmd.p1();
        match self.data.write_record(ef, rec_num, cmd.data()) {
            Ok(()) => write_sw(buf, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(FsError::RecordOutOfRange) => write_sw(buf, StatusWord::wrong_params(sw2::RECORD_NOT_FOUND)),
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
        if self.pin1_denied() { return write_sw(buf, StatusWord::command_not_allowed(sw2::SECURITY_NOT_SATISFIED)); }
        let Some(ef) = self.fs.current_ef() else {
            return write_sw(buf, StatusWord::command_not_allowed(sw2::NO_CURRENT_EF));
        };
        match self.data.increase(ef, cmd.data()) {
            Ok(new_val) => write_data_sw(buf, new_val, StatusWord::Success),
            Err(FsError::NotRecordBased) => write_sw(buf, StatusWord::command_not_allowed(sw2::INCOMPATIBLE_FILE_STRUCTURE)),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- STATUS --

    fn handle_status<'buf>(
        &self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // Per ETSI TS 102 221 clause 11.1.2:
        // P1: 0x00 = no indication (current DF).
        // P2: 0x00 = FCP template, 0x0C = no data returned.
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        match cmd.p2() {
            0x00 => {
                let mut fcp_buf = [0u8; FCP_BUF_CAP];
                let fcp_len = build_fcp(
                    SelectedFile::Df(self.fs.current_df()),
                    None,
                    &mut fcp_buf,
                );
                write_data_sw(buf, &fcp_buf[..fcp_len], StatusWord::Success)
            }
            0x0C => write_sw(buf, StatusWord::Success),
            _ => write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2)),
        }
    }

    // -- AUTHENTICATE (Milenage UMTS context) --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_authenticate<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // Note: AUTHENTICATE does not require PIN1 verification per
        // ETSI TS 102 221 -- it has its own security context.
        // P2=0x81: UMTS/EPS AKA security context.
        if cmd.p2() != P2_UMTS_CONTEXT {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }

        let data = cmd.data();
        // Data: 0x10 [RAND:16] 0x10 [AUTN:16] = 34 bytes.
        if data.len() != AUTH_DATA_LEN {
            return write_sw(buf, StatusWord::WrongLength);
        }
        if data[0] != AUTH_VECTOR_LEN_PREFIX || data[17] != AUTH_VECTOR_LEN_PREFIX {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut rand = [0u8; 16];
        rand.copy_from_slice(&data[1..17]);
        let mut autn = [0u8; 16];
        autn.copy_from_slice(&data[18..34]);

        let auth_result = match self.auth.authenticate(&rand, &autn) {
            Ok(output) => AuthenticateResult::Success {
                res: output.res,
                ck: output.ck,
                ik: output.ik,
            },
            Err(MilenageError::MacFailure) => AuthenticateResult::MacFailure,
            Err(MilenageError::SyncFailure { auts }) => {
                AuthenticateResult::SyncFailure { auts }
            }
        };

        if auth_result == AuthenticateResult::MacFailure {
            write_sw(buf, StatusWord::AuthenticationError)
        } else {
            let q = self.rsp_queue.buf_mut();
            let n = auth_result.encode(q);
            self.rsp_queue.set_len(n);
            write_sw(buf, StatusWord::bytes_available(n as u8))
        }
    }

    // -- VERIFY PIN --

    fn handle_verify<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw(buf, StatusWord::wrong_params(sw2::WRONG_P1_P2));
        }
        let key = PinKey(cmd.p2());

        // Empty data: query retry count.
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

        if cmd.data().is_empty() {
            return match self.pin.puk_retries(key) {
                Some(n) => write_sw(buf, StatusWord::pin_retries(n & 0x0F)),
                None => write_sw(buf, StatusWord::wrong_params(sw2::REFERENCE_NOT_FOUND)),
            };
        }

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

    // -- TERMINAL PROFILE --

    fn handle_terminal_profile<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        self.proactive.set_terminal_profile(cmd.data());
        write_sw(buf, StatusWord::Success)
    }

    // -- FETCH --

    fn handle_fetch<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if !self.proactive.has_pending() {
            // Per TS 102 223: FETCH with no pending command is not allowed.
            return write_sw(buf, StatusWord::CommandNotAllowed(0x00));
        }

        let le = cmd.le().unwrap_or(0) as usize;
        let pending = self.proactive.pending_len();
        let fetch_len = if le == 0 { pending } else { le.min(pending) };

        if buf.len() < fetch_len + 2 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }

        let written = self.proactive.fetch(&mut buf[..fetch_len]);
        let [sw1, sw2_byte] = StatusWord::Success.to_bytes();
        buf[written] = sw1;
        buf[written + 1] = sw2_byte;
        &buf[..written + 2]
    }

    // -- TERMINAL RESPONSE --

    fn handle_terminal_response<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let _ = self.proactive.terminal_response(cmd.data());
        write_sw(buf, StatusWord::Success)
    }

    // -- ENVELOPE --

    fn handle_envelope<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        self.proactive.process_envelope(cmd.data());
        write_sw(buf, StatusWord::Success)
    }
}

// ---------------------------------------------------------------------------
// FCP BER-TLV builder per ETSI TS 102 221 clause 11.1.1.3
// ---------------------------------------------------------------------------

/// Build an FCP template for the selected file.
///
/// Returns the number of bytes written to `out`. The FCP is a BER-TLV
/// structure with tag `fcp::TEMPLATE` (0x62).
///
/// Uses the dry-run/real-run pattern: first pass counts bytes, second
/// writes them.
fn build_fcp(
    sel: SelectedFile,
    aid: Option<&[u8]>,
    out: &mut [u8],
) -> usize {
    // Dry run to compute inner content length.
    let inner_len = fcp_inner_len(sel, aid);

    // Real run: write FCP template tag + length + inner content.
    let mut enc = Encoder::new(out);
    let _ = enc.raw(&[fcp::TEMPLATE]);
    // BER length of inner content.
    let _ = write_ber_len(&mut enc, inner_len);
    // Inner TLV objects.
    let _ = write_fcp_inner(&mut enc, sel, aid);
    enc.len()
}

/// Compute the byte length of the FCP inner content (without the template tag
/// and its length field).
fn fcp_inner_len(sel: SelectedFile, aid: Option<&[u8]>) -> usize {
    let mut enc = Encoder::dry_run();
    let _ = write_fcp_inner(&mut enc, sel, aid);
    enc.len()
}

/// Write the FCP inner TLV objects.
fn write_fcp_inner(
    enc: &mut Encoder<'_>,
    sel: SelectedFile,
    aid: Option<&[u8]>,
) -> Result<(), simrs_bertlv::BerError> {
    match sel {
        SelectedFile::Df(df) => write_fcp_df(enc, df, aid),
        SelectedFile::Ef(ef) => write_fcp_ef(enc, ef),
    }
}

/// FCP inner content for a DF/MF/ADF.
fn write_fcp_df(
    enc: &mut Encoder<'_>,
    df: &DfDef,
    aid: Option<&[u8]>,
) -> Result<(), simrs_bertlv::BerError> {
    // File descriptor: byte 0 = FD_DF, byte 1 = DATA_CODING_BER_TLV.
    enc.tag_length_value(fcp::FILE_DESCRIPTOR, &[FD_DF, DATA_CODING_BER_TLV])?;

    // File ID.
    let fid_be = df.fid.to_be_bytes();
    enc.tag_length_value(fcp::FILE_ID, &fid_be)?;

    // DF name (AID) -- only for ADF.
    if let Some(aid_bytes) = aid {
        enc.tag_length_value(fcp::DF_NAME, aid_bytes)?;
    }

    // Proprietary information (empty for now).
    enc.tag_length_value(fcp::PROPRIETARY_INFO, &[])?;

    // Life cycle status = activated.
    enc.tag_length_value(fcp::LIFECYCLE_STATUS, &[LIFECYCLE_ACTIVATED])?;

    // Security attributes compact (always allowed + 7 zeros).
    enc.tag_length_value(fcp::SECURITY_ATTRS_COMPACT, &[SECURITY_ALWAYS, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;

    // PIN status template DO.
    // Contains PS_DO (tag PS_DO_TAG) with PIN reference.
    let pin_status = [PS_DO_TAG, 0x01, 0x01]; // PS_DO: PIN1 reference
    enc.tag_length_value(fcp::PIN_STATUS_TEMPLATE, &pin_status)?;

    Ok(())
}

/// FCP inner content for an EF.
#[allow(clippy::cast_possible_truncation)]
fn write_fcp_ef(
    enc: &mut Encoder<'_>,
    ef: &EfDef,
) -> Result<(), simrs_bertlv::BerError> {
    // File descriptor.
    match ef.structure {
        EfStructure::Transparent => {
            enc.tag_length_value(fcp::FILE_DESCRIPTOR, &[FD_TRANSPARENT, DATA_CODING_BER_TLV])?;
        }
        EfStructure::LinearFixed { record_size, num_records } => {
            let rec_be = u16::from(record_size).to_be_bytes();
            enc.tag_length_value(
                fcp::FILE_DESCRIPTOR,
                &[FD_LINEAR_FIXED, DATA_CODING_BER_TLV, num_records, rec_be[0], rec_be[1]],
            )?;
        }
        EfStructure::Cyclic { record_size, num_records } => {
            let rec_be = u16::from(record_size).to_be_bytes();
            enc.tag_length_value(
                fcp::FILE_DESCRIPTOR,
                &[FD_CYCLIC, DATA_CODING_BER_TLV, num_records, rec_be[0], rec_be[1]],
            )?;
        }
    }

    // File ID.
    let fid_be = ef.fid.to_be_bytes();
    enc.tag_length_value(fcp::FILE_ID, &fid_be)?;

    // File size.
    let size = ef.data.len() as u16;
    let size_be = size.to_be_bytes();
    enc.tag_length_value(fcp::FILE_SIZE, &size_be)?;

    // Short File Identifier (if assigned).
    if let Some(sfi) = ef.sfi {
        // SFI is encoded as (sfi << 3) | SFI_INDICATOR per ETSI TS 102 221.
        enc.tag_length_value(fcp::SHORT_FILE_ID, &[(sfi.value() << 3) | SFI_INDICATOR])?;
    }

    // Life cycle status = activated.
    enc.tag_length_value(fcp::LIFECYCLE_STATUS, &[LIFECYCLE_ACTIVATED])?;

    // Security attributes compact.
    enc.tag_length_value(fcp::SECURITY_ATTRS_COMPACT, &[SECURITY_ALWAYS, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;

    Ok(())
}

/// Write a BER-encoded length using the encoder.
fn write_ber_len(
    enc: &mut Encoder<'_>,
    len: usize,
) -> Result<(), simrs_bertlv::BerError> {
    #[allow(clippy::cast_possible_truncation)]
    if len <= simrs_bertlv::BER_SHORT_FORM_MAX {
        enc.raw(&[len as u8])
    } else {
        enc.raw(&[simrs_bertlv::BER_LONG_FORM_1, len as u8])
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use simrs_fs::{AdfSlot, EfDef, EfStructure, Fid, FileRef, Sfi};
    use simrs_milenage::OpVariant;
    use simrs_proactive::ProactiveCommand;

    // -- Test filesystem --

    static EF_ICCID: EfDef = EfDef {
        fid: Fid(0x2FE2),
        sfi: Some(Sfi(2)),
        structure: EfStructure::Transparent,
        data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    };

    static EF_DIR_DATA: [u8; 16] = [
        0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_DIR: EfDef = EfDef {
        fid: Fid(0x2F00),
        sfi: Some(Sfi(30)),
        structure: EfStructure::LinearFixed {
            record_size: 8,
            num_records: 2,
        },
        data: &EF_DIR_DATA,
    };

    static EF_IMSI: EfDef = EfDef {
        fid: Fid(0x6F07),
        sfi: Some(Sfi(7)),
        structure: EfStructure::Transparent,
        data: &[0x08, 0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
    };

    static EF_UST: EfDef = EfDef {
        fid: Fid(0x6F38),
        sfi: None,
        structure: EfStructure::Transparent,
        data: &[0xFF, 0xFF, 0xFF, 0xFF],
    };

    static EF_FDN_DATA: [u8; 20] = [
        0x41, 0x6C, 0x69, 0x63, 0x65, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x42, 0x6F, 0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    static EF_FDN: EfDef = EfDef {
        fid: Fid(0x6F3B),
        sfi: None,
        structure: EfStructure::LinearFixed {
            record_size: 10,
            num_records: 2,
        },
        data: &EF_FDN_DATA,
    };

    static EF_ACC_DATA: [u8; 12] = [
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    static EF_ACC: EfDef = EfDef {
        fid: Fid(0x6F78),
        sfi: None,
        structure: EfStructure::Cyclic {
            record_size: 4,
            num_records: 3,
        },
        data: &EF_ACC_DATA,
    };

    static ADF_USIM_ROOT: DfDef = DfDef {
        fid: Fid(0xFF01),
        children: &[
            FileRef::Ef(&EF_IMSI),
            FileRef::Ef(&EF_UST),
            FileRef::Ef(&EF_FDN),
            FileRef::Ef(&EF_ACC),
        ],
    };

    static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_ROOT,
    }];

    static MF: DfDef = DfDef {
        fid: Fid(0x3F00),
        children: &[
            FileRef::Ef(&EF_ICCID),
            FileRef::Ef(&EF_DIR),
        ],
    };

    // ETSI TS 135 208 Test Set 1 values.
    static K: [u8; 16] = [
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F,
        0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC,
    ];
    static OPC: [u8; 16] = [
        0xCD, 0x63, 0xCB, 0x71, 0x95, 0x4A, 0x9F, 0x4E,
        0x48, 0xA5, 0x99, 0x4E, 0x37, 0xA0, 0x2B, 0xAF,
    ];

    fn app() -> UsimApp {
        let mil = MilenageParams::with_defaults(K, OpVariant::Opc(OPC));
        let mut a = UsimApp::new(&MF, &ADF_TABLE, mil);
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

    /// Create an app with PIN1 enabled (not disabled) for PIN-gate tests.
    fn app_with_pin1_enabled() -> UsimApp {
        let mil = MilenageParams::with_defaults(K, OpVariant::Opc(OPC));
        let mut a = UsimApp::new(&MF, &ADF_TABLE, mil);
        let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
        a.pin_manager()
            .add_pin(PinKey::PIN1, &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        a
    }

    fn send(app: &mut UsimApp, apdu: &[u8]) -> ([u8; 256], usize) {
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
    fn cla_00_accepted() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x6E);
    }

    #[test]
    fn cla_a0_rejected() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0xA0, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        assert_eq!(sw(&buf, len), (0x6E, 0x00));
    }

    #[test]
    fn cla_80_accepted_for_terminal_profile() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x80, 0x10, 0x00, 0x00]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x6E);
    }

    // -- SELECT by FID + FCP --

    #[test]
    fn select_mf_returns_61_xx() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0x61); // data available
    }

    #[test]
    fn get_response_after_select_mf_returns_fcp() {
        let mut app = app();
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let fcp_len = buf[1] as usize;

        let mut gr_apdu = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr_apdu[4] = fcp_len as u8;
        let (buf, len) = send(&mut app, &gr_apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, fcp_len + 2);
        // FCP starts with tag 0x62.
        assert_eq!(buf[0], 0x62);
        // Inner TLV objects start after 0x62 + length byte.
        let inner = &buf[2..fcp_len];
        assert!(find_tlv_tag(inner, 0x83).is_some());
        let fid_val = find_tlv_tag(inner, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00]);
    }

    #[test]
    fn select_ef_returns_fcp_with_file_size() {
        let mut app = app();
        // Select MF then EF.ICCID.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x20]); // consume
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let fcp_len = buf[1] as usize;
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = fcp_len as u8;
        let (buf, len) = send(&mut app, &gr);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let inner = &buf[2..fcp_len];
        // Tag 0x80: file size.
        let size_val = find_tlv_tag(inner, 0x80).unwrap();
        assert_eq!(size_val, &[0x00, 0x0A]); // 10 bytes
        // Tag 0x83: FID = 2FE2.
        let fid_val = find_tlv_tag(inner, 0x83).unwrap();
        assert_eq!(fid_val, &[0x2F, 0xE2]);
    }

    #[test]
    fn fcp_for_df_contains_pin_status() {
        let mut app = app();
        let (buf, _) = send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        let fcp_len = buf[1] as usize;
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = fcp_len as u8;
        let (buf, _len) = send(&mut app, &gr);
        let inner = &buf[2..fcp_len];
        // Must contain 0xC6 (PIN status template).
        assert!(find_tlv_tag(inner, 0xC6).is_some());
        // Must contain 0x8C (security attributes).
        assert!(find_tlv_tag(inner, 0x8C).is_some());
    }

    // -- SELECT by AID --

    #[test]
    fn select_adf_usim_by_aid() {
        let mut app = app();
        let (buf, _len) = send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        assert_eq!(buf[0], 0x61); // FCP available
        let fcp_len = buf[1] as usize;
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = fcp_len as u8;
        let (buf, _) = send(&mut app, &gr);
        let inner = &buf[2..fcp_len];
        // Must contain tag 0x84 (DF name / AID).
        let aid_val = find_tlv_tag(inner, 0x84).unwrap();
        assert_eq!(aid_val, &USIM_AID);
    }

    #[test]
    fn select_unknown_aid_returns_6a82() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x82));
    }

    // -- GET RESPONSE --

    #[test]
    fn get_response_with_no_pending() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x10]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90);
    }

    #[test]
    fn non_get_response_clears_queue() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]); // queues FCP
        send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]); // STATUS clears queue
        let (buf, len) = send(&mut app, &[0x00, 0xC0, 0x00, 0x00, 0x10]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90);
    }

    // -- READ BINARY --

    #[test]
    fn read_binary_full() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(
            &buf[..10],
            &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0]
        );
    }

    #[test]
    fn read_binary_with_offset() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x02, 0x03]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..3], &[0x14, 0x80, 0x00]);
    }

    #[test]
    fn read_binary_past_end() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x08, 0x05]);
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90);
    }

    #[test]
    fn read_binary_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x86));
    }

    // -- READ RECORD --

    #[test]
    fn read_record_first() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]); // EF.DIR
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x61); // first record starts with TLV tag
        assert_eq!(len, 8 + 2);
    }

    #[test]
    fn read_record_beyond_last() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]);
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x03, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x6A, 0x83));
    }

    // -- STATUS --

    #[test]
    fn status_returns_mf_fcp() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62); // FCP template tag
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00]);
    }

    #[test]
    fn status_after_selecting_adf() {
        let mut app = app();
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62);
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0xFF, 0x01]); // ADF root FID
    }

    // -- AUTHENTICATE --

    #[test]
    fn authenticate_umts_success() {
        let mut app = app();
        // Select ADF.USIM first (required for AUTHENTICATE).
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );

        // ETSI TS 135 208 Test Set 1 RAND and build AUTN.
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let params = MilenageParams::with_defaults(K, OpVariant::Opc(OPC));
        let sqn = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let amf = [0xB9, 0xB9];
        let ak = params.f5(&rand_val);
        let mac_a = params.f1(&rand_val, &sqn, &amf);

        // AUTN = SQN XOR AK || AMF || MAC-A
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = sqn[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&amf);
        autn[8..16].copy_from_slice(&mac_a);

        // Build AUTHENTICATE APDU.
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0x88; // INS
        apdu[2] = 0x00; // P1
        apdu[3] = 0x81; // P2 = UMTS context
        apdu[4] = 0x22; // Lc = 34
        apdu[5] = 0x10; // RAND length
        apdu[6..22].copy_from_slice(&rand_val);
        apdu[22] = 0x10; // AUTN length
        apdu[23..39].copy_from_slice(&autn);

        let (buf, _len) = send(&mut app, &apdu);
        assert_eq!(buf[0], 0x61); // data available
        let rsp_len = buf[1] as usize;

        // GET RESPONSE.
        let mut gr = [0x00, 0xC0, 0x00, 0x00, 0x00];
        gr[4] = rsp_len as u8;
        let (buf, len) = send(&mut app, &gr);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Response starts with 0xDB.
        assert_eq!(buf[0], 0xDB);

        // Verify against direct Milenage computation.
        let expected = params.authenticate(&rand_val, &autn).unwrap();
        // RES at offset 3 (after 0xDB, len, 0x08).
        assert_eq!(&buf[3..11], &expected.res);
        // CK at offset 12 (after 0x10).
        assert_eq!(&buf[12..28], &expected.ck);
        // IK at offset 29 (after 0x10).
        assert_eq!(&buf[29..45], &expected.ik);
    }

    #[test]
    fn authenticate_mac_failure() {
        let mut app = app();
        // Build AUTHENTICATE with garbage AUTN.
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00;
        apdu[1] = 0x88;
        apdu[3] = 0x81;
        apdu[4] = 0x22;
        apdu[5] = 0x10;
        // RAND = all zeros.
        apdu[22] = 0x10;
        // AUTN = all zeros (invalid MAC).

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x98, 0x62));
    }

    #[test]
    fn authenticate_wrong_data_length() {
        let mut app = app();
        // Only 8 bytes of data instead of 34.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x88, 0x00, 0x81, 0x08,
              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    // -- AuthenticateResult::encode --

    #[test]
    fn authenticate_result_encode_success() {
        // Use ETSI TS 135 208 Test Set 1 to produce known RES/CK/IK values.
        let params = MilenageParams::with_defaults(K, OpVariant::Opc(OPC));
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let sqn = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let amf = [0xB9, 0xB9];

        let ak = params.f5(&rand_val);
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = sqn[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&amf);
        autn[8..16].copy_from_slice(&params.f1(&rand_val, &sqn, &amf));

        let output = params.authenticate(&rand_val, &autn).unwrap();
        let result = AuthenticateResult::Success {
            res: output.res,
            ck: output.ck,
            ik: output.ik,
        };

        let mut buf = [0u8; 64];
        let n = result.encode(&mut buf);

        // Total length: 2 (tag+len) + 1+8 (RES) + 1+16 (CK) + 1+16 (IK) = 45.
        assert_eq!(n, 45);
        assert_eq!(buf[0], 0xDB); // AUTH_SUCCESS_TAG
        assert_eq!(buf[1], 43);   // inner length = 1+8+1+16+1+16
        assert_eq!(buf[2], 0x08); // RES length prefix
        assert_eq!(&buf[3..11], &output.res);
        assert_eq!(buf[11], 0x10); // CK length prefix
        assert_eq!(&buf[12..28], &output.ck);
        assert_eq!(buf[28], 0x10); // IK length prefix
        assert_eq!(&buf[29..45], &output.ik);
    }

    #[test]
    fn authenticate_result_encode_sync_failure() {
        let auts: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        ];
        let result = AuthenticateResult::SyncFailure { auts };

        let mut buf = [0u8; 64];
        let n = result.encode(&mut buf);

        assert_eq!(n, 16); // tag + len + 14 bytes AUTS
        assert_eq!(buf[0], 0xDC); // AUTH_SYNC_FAILURE_TAG
        assert_eq!(buf[1], 0x0E); // 14
        assert_eq!(&buf[2..16], &auts);
    }

    #[test]
    fn authenticate_result_encode_mac_failure() {
        let result = AuthenticateResult::MacFailure;
        let mut buf = [0u8; 64];
        let n = result.encode(&mut buf);
        assert_eq!(n, 0); // No data payload, SW only.
    }

    // -- VERIFY PIN --

    #[test]
    fn verify_correct_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn verify_wrong_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn verify_blocked_pin() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    // -- UNBLOCK PIN --

    #[test]
    fn unblock_with_correct_puk() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x2C, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // New PIN "5678" works.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- CHANGE REFERENCE DATA --

    #[test]
    fn change_ref_data_success() {
        let mut app = app();
        // Old PIN "1234" + new PIN "5678".
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Verify with new PIN.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn change_ref_data_wrong_old_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x10,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn change_ref_data_blocked() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn change_ref_data_not_found() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0xFF, 0x10,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
              0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn change_ref_data_wrong_length() {
        let mut app = app();
        // Only 8 bytes instead of 16.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x24, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    // -- DISABLE PIN --

    #[test]
    fn disable_pin_success() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // VERIFY should now return "disabled" (69 84).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x84));
    }

    #[test]
    fn disable_pin_wrong_pin() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn disable_pin_blocked() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn disable_pin_not_found() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0xFF, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn disable_pin_wrong_length() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x04,
              0x31, 0x32, 0x33, 0x34],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn disable_pin_already_disabled() {
        let mut app = app();
        // Disable once.
        send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Second disable returns "already disabled" (69 84).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x84));
    }

    // -- ENABLE PIN --

    #[test]
    fn enable_pin_success() {
        let mut app = app();
        // Disable first.
        send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Enable.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // VERIFY should work again.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn enable_pin_wrong_pin() {
        let mut app = app();
        // Disable first.
        send(
            &mut app,
            &[0x00, 0x26, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Enable with wrong PIN.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
    }

    #[test]
    fn enable_pin_blocked() {
        let mut app = app();
        let wrong = [0x00, 0x20, 0x00, 0x01, 0x08,
                     0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        send(&mut app, &wrong);
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x69, 0x83));
    }

    #[test]
    fn enable_pin_not_found() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0xFF, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x88));
    }

    #[test]
    fn enable_pin_wrong_length() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x04,
              0x31, 0x32, 0x33, 0x34],
        );
        assert_eq!(sw(&buf, len), (0x67, 0x00));
    }

    #[test]
    fn enable_pin_already_enabled() {
        let mut app = app();
        // PIN is already enabled by default. Enable again is a no-op success.
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x28, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- TERMINAL PROFILE --

    #[test]
    fn terminal_profile_accepted() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- FETCH --

    #[test]
    fn fetch_retrieves_proactive_command() {
        let mut app = app();
        let text = b"Hello";
        let cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        app.proactive_state().queue_command(&cmd).unwrap();

        let pending = app.proactive_state().pending_len();
        let mut apdu = [0u8; 5];
        apdu[0] = 0x80;
        apdu[1] = 0x12;
        apdu[4] = pending as u8;

        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // Data starts with 0xD0 (proactive command envelope).
        assert_eq!(buf[0], 0xD0);
        // Proactive queue is now empty.
        assert!(!app.proactive_state().has_pending());
    }

    #[test]
    fn fetch_with_no_pending() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x80, 0x12, 0x00, 0x00, 0x00]);
        // TS 102 223: FETCH with no pending command -> Command Not Allowed (69 00).
        assert_eq!(sw(&buf, len), (0x69, 0x00));
    }

    // -- TERMINAL RESPONSE --

    #[test]
    fn terminal_response_accepted() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x80, 0x14, 0x00, 0x00, 0x02, 0x00, 0x00],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    // -- ENVELOPE --

    #[test]
    fn envelope_accepted() {
        let mut app = app();
        let (buf, len) = send(
            &mut app,
            &[0x80, 0xC2, 0x00, 0x00, 0x02, 0xD0, 0x00],
        );
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn envelope_menu_selection_via_apdu() {
        let mut app = app();
        // Build a Menu Selection envelope: D3 03 90 01 02
        // (tag D3, length 3, inner: tag 90, length 1, item_id = 2)
        let apdu = [
            0x80, 0xC2, 0x00, 0x00, // CLA INS P1 P2
            0x05,                     // Lc = 5 bytes of data
            0xD3, 0x03,               // Menu Selection tag + length
            0x90, 0x01, 0x02,         // Item Identifier: tag 90, len 1, value 2
        ];
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Verify the event was stored in proactive state.
        let event = app.proactive_state().take_event();
        assert_eq!(
            event,
            Some(simrs_proactive::EnvelopeEvent::MenuSelection { item_id: 0x02 })
        );
    }

    #[test]
    fn terminal_profile_via_apdu() {
        let mut app = app();
        // Send TERMINAL_PROFILE with 4 bytes of profile data.
        let apdu = [
            0x80, 0x10, 0x00, 0x00, // CLA INS P1 P2
            0x04,                     // Lc = 4 bytes
            0xFF, 0x0F, 0x00, 0x80,  // profile data
        ];
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));

        // Verify the profile was stored.
        let ps = app.proactive_state();
        assert!(ps.terminal_supports(0, 0));  // byte 0 bit 0 of 0xFF
        assert!(ps.terminal_supports(0, 7));  // byte 0 bit 7 of 0xFF
        assert!(ps.terminal_supports(1, 0));  // byte 1 bit 0 of 0x0F
        assert!(ps.terminal_supports(1, 3));  // byte 1 bit 3 of 0x0F
        assert!(!ps.terminal_supports(1, 4)); // byte 1 bit 4 of 0x0F
        assert!(!ps.terminal_supports(2, 0)); // byte 2 = 0x00
        assert!(ps.terminal_supports(3, 7));  // byte 3 bit 7 of 0x80
        assert!(!ps.terminal_supports(4, 0)); // beyond profile
    }

    // -- Proactive SW override --

    #[test]
    fn proactive_override_90_to_91() {
        let mut app = app();
        let text = b"Hi";
        let cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        app.proactive_state().queue_command(&cmd).unwrap();
        let pending = app.proactive_state().pending_len();

        // VERIFY correct PIN (would normally return 90 00).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        // Overridden to 91 XX.
        assert_eq!(buf[len - 2], 0x91);
        assert_eq!(buf[len - 1] as usize, pending);
    }

    #[test]
    fn proactive_override_does_not_apply_to_errors() {
        let mut app = app();
        let text = b"Hi";
        let cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        app.proactive_state().queue_command(&cmd).unwrap();

        // SELECT nonexistent FID (error 6A 82 should not be overridden).
        let (buf, len) = send(
            &mut app,
            &[0x00, 0xA4, 0x00, 0x04, 0x02, 0xFF, 0xFF],
        );
        assert_eq!(sw(&buf, len), (0x6A, 0x82));
    }

    // -- UPDATE BINARY --

    #[test]
    fn update_binary_and_readback() {
        let mut app = app();
        // SELECT EF.ICCID
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY: offset 0, 3 bytes [0xAA, 0xBB, 0xCC]
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // READ BINARY to verify
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..3], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(buf[3], 0x80); // rest unchanged
    }

    #[test]
    fn update_binary_with_offset() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY at offset 5: 2 bytes [0xDD, 0xEE]
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x05, 0x02, 0xDD, 0xEE]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x04, 0x04]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(&buf[..4], &[0x00, 0xDD, 0xEE, 0x00]);
    }

    #[test]
    fn update_binary_on_record_ef() {
        let mut app = app();
        // SELECT EF.DIR (linear-fixed)
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x81)); // incompatible file structure
    }

    #[test]
    fn update_binary_past_end() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // EF.ICCID is 10 bytes. Write 3 at offset 9 exceeds.
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x09, 0x03, 0xAA, 0xBB, 0xCC]);
        assert_eq!(sw(&buf, len), (0x67, 0x00)); // wrong length
    }

    #[test]
    fn update_binary_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x86)); // no current EF
    }

    // -- UPDATE RECORD --

    #[test]
    fn update_record_and_readback() {
        let mut app = app();
        // SELECT ADF.USIM by AID, then EF.FDN
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // UPDATE RECORD 2 (10 bytes): "NewName" + padding
        let mut apdu = [0xFFu8; 5 + 10];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0xDC; // INS: UPDATE RECORD
        apdu[2] = 0x02; // P1: record 2
        apdu[3] = 0x04; // P2: absolute
        apdu[4] = 0x0A; // Lc: 10 bytes
        apdu[5] = 0x4E; // 'N'
        apdu[6] = 0x65; // 'e'
        apdu[7] = 0x77; // 'w'
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        // READ RECORD 2
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x02, 0x04, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x4E); // 'N'
        assert_eq!(buf[1], 0x65); // 'e'
        assert_eq!(buf[2], 0x77); // 'w'
    }

    #[test]
    fn update_record_on_transparent() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app,
            &[0x00, 0xDC, 0x01, 0x04, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x81)); // incompatible file structure
    }

    #[test]
    fn update_record_wrong_size() {
        let mut app = app();
        // SELECT ADF.USIM, then EF.FDN (record_size=10)
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // Try writing 5 bytes (not 10)
        let (buf, len) = send(&mut app,
            &[0x00, 0xDC, 0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(sw(&buf, len), (0x67, 0x00)); // wrong length
    }

    #[test]
    fn update_record_out_of_range() {
        let mut app = app();
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x3B]);
        // EF.FDN has 2 records. Try record 3.
        let mut apdu = [0xFFu8; 5 + 10];
        apdu[0] = 0x00;
        apdu[1] = 0xDC;
        apdu[2] = 0x03; // record 3
        apdu[3] = 0x04;
        apdu[4] = 0x0A; // 10 bytes
        let (buf, len) = send(&mut app, &apdu);
        assert_eq!(sw(&buf, len), (0x6A, 0x83)); // record not found
    }

    #[test]
    fn update_record_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0xDC, 0x01, 0x04, 0x01, 0xFF]);
        assert_eq!(sw(&buf, len), (0x69, 0x86)); // no current EF
    }

    // -- INCREASE --

    #[test]
    fn increase_on_cyclic_ef() {
        let mut app = app();
        // SELECT ADF.USIM, then EF.ACC (cyclic, FID 0x6F78)
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x78]);
        // INCREASE by [0x00, 0x00, 0x00, 0x05]: record 1 = 0x000100 + 5 = 0x000105
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(len, 4 + 2); // 4-byte record + 2-byte SW
        assert_eq!(&buf[..4], &[0x00, 0x00, 0x01, 0x05]);
    }

    #[test]
    fn increase_on_transparent_fails() {
        let mut app = app();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x81)); // incompatible file structure
    }

    #[test]
    fn increase_no_ef_selected() {
        let mut app = app();
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x01, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x86)); // no current EF
    }

    // -- Unknown INS --

    #[test]
    fn unknown_ins_returns_6d00() {
        let mut app = app();
        let (buf, len) = send(&mut app, &[0x00, 0xFF, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x6D, 0x00));
    }

    // -- Snapshot --

    #[test]
    fn snapshot_size_correct() {
        // SelectionCtx(8) + FsData::<512>(512) + PinManager::<5>(111) + Milenage(117)
        // + ProactiveState(373) + ResponseQueue::<64>(65) = 1186
        assert_eq!(UsimApp::<MilenageParams>::SNAPSHOT_SIZE, 1186);
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let mut src = app();
        // Select ADF.USIM by AID, then EF.IMSI.
        send(&mut src, &[0x00, 0xA4, 0x04, 0x04, 0x07,
                         0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut src, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
        // Degrade PIN retries.
        send(&mut src, &[0x00, 0x20, 0x00, 0x01, 0x08,
                         0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Save.
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let written = src.save_state(&mut snap);
        assert_eq!(written, UsimApp::<MilenageParams>::SNAPSHOT_SIZE);

        // Restore into fresh app (same adfs).
        let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));

        // PIN retries = 2 (wrong VERIFY degraded it before snapshot).
        let (buf, len) = send(&mut dst, &[0x00, 0x20, 0x00, 0x01, 0x00]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2));

        // Re-verify PIN1 so we can read files (PIN gate enforced).
        send(&mut dst,
            &[0x00, 0x20, 0x00, 0x01, 0x08,
              0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Read EF.IMSI (fs state restored).
        let (buf, len) = send(&mut dst, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08);
    }

    #[test]
    fn snapshot_preserves_milenage_auth() {
        let src = app();
        // Build valid AUTN for ETSI test set 1.
        let rand_val: [u8; 16] = [
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
            0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
        ];
        let params = MilenageParams::with_defaults(K, OpVariant::Opc(OPC));
        let sqn = [0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07];
        let amf = [0xB9, 0xB9];
        let ak = params.f5(&rand_val);
        let mac_a = params.f1(&rand_val, &sqn, &amf);
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = sqn[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&amf);
        autn[8..16].copy_from_slice(&mac_a);

        // Save and restore.
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let _ = src.save_state(&mut snap);
        let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));

        // AUTHENTICATE should succeed with restored K/OPc.
        let mut apdu = [0u8; 5 + 34];
        apdu[0] = 0x00;
        apdu[1] = 0x88;
        apdu[3] = 0x81;
        apdu[4] = 0x22;
        apdu[5] = 0x10;
        apdu[6..22].copy_from_slice(&rand_val);
        apdu[22] = 0x10;
        apdu[23..39].copy_from_slice(&autn);

        let (buf, _) = send(&mut dst, &apdu);
        assert_eq!(buf[0], 0x61); // data available
    }

    #[test]
    fn snapshot_preserves_proactive_state() {
        let mut src = app();
        let text = b"Snap";
        let pro_cmd = ProactiveCommand::DisplayText {
            text,
            coding: simrs_proactive::TextCoding::Gsm8Bit,
            high_priority: false,
        };
        src.proactive_state().queue_command(&pro_cmd).unwrap();
        let pending_before = src.proactive_state().pending_len();
        assert!(pending_before > 0);

        // Save and restore.
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let _ = src.save_state(&mut snap);
        let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));

        // Proactive command is still pending after restore.
        assert!(dst.proactive_state().has_pending());
        assert_eq!(dst.proactive_state().pending_len(), pending_before);
    }

    #[test]
    fn snapshot_small_buffer_returns_zero_or_false() {
        let src = app();
        let mut small = [0u8; 10];
        assert_eq!(src.save_state(&mut small), 0);

        let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(!dst.restore_state(&small));
    }

    #[test]
    fn snapshot_restore_oversized_rsp_queue_len_returns_false() {
        let src = app();
        let mut snap = [0u8; UsimApp::<MilenageParams>::SNAPSHOT_SIZE];
        let _ = src.save_state(&mut snap);
        // rsp_queue_len is the last byte of the snapshot.
        *snap.last_mut().unwrap() = u8::MAX;
        let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(!dst.restore_state(&snap));
    }

    // -- Navigation round-trip --

    #[test]
    fn navigate_mf_adf_ef_read_mf_roundtrip() {
        let mut app = app();
        // Select MF.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        // Select ADF.USIM by AID.
        send(
            &mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
        // Select EF.IMSI by FID.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x07]);
        // READ BINARY.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08); // IMSI first byte
        assert_eq!(len, 9 + 2);
        // Select MF.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
        // STATUS returns MF.
        let (buf, len) = send(&mut app, &[0x00, 0xF2, 0x00, 0x00, 0x00]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x62);
        let fcp_len = buf[1] as usize;
        let fcp = &buf[2..2 + fcp_len];
        let fid_val = find_tlv_tag(fcp, 0x83).unwrap();
        assert_eq!(fid_val, &[0x3F, 0x00]);
    }

    // -- Test helper: find a TLV tag in a byte sequence --

    fn find_tlv_tag(data: &[u8], target_tag: u8) -> Option<&[u8]> {
        let mut pos = 0;
        while pos < data.len() {
            let tag = data[pos];
            pos += 1;
            if pos >= data.len() {
                break;
            }
            let len_byte = data[pos];
            pos += 1;
            let (value_len, extra) = if usize::from(len_byte) <= simrs_bertlv::BER_SHORT_FORM_MAX {
                (len_byte as usize, 0)
            } else if len_byte == simrs_bertlv::BER_LONG_FORM_1 && pos < data.len() {
                (data[pos] as usize, 1)
            } else {
                break;
            };
            pos += extra;
            if pos + value_len > data.len() {
                break;
            }
            if tag == target_tag {
                return Some(&data[pos..pos + value_len]);
            }
            pos += value_len;
        }
        None
    }

    // -- PIN gate tests --

    #[test]
    fn read_binary_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        // Select EF.ICCID under MF.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // READ BINARY without PIN1 verification.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x69, 0x82)); // security status not satisfied
    }

    #[test]
    fn read_binary_with_pin1_succeeds() {
        let mut app = app_with_pin1_enabled();
        // Verify PIN1.
        send(&mut app,
            &[0x00, 0x20, 0x00, 0x01, 0x08, 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Select EF.ICCID.
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // READ BINARY should now succeed.
        let (buf, len) = send(&mut app, &[0x00, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
    }

    #[test]
    fn update_binary_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2]);
        // UPDATE BINARY without PIN1.
        let (buf, len) = send(&mut app,
            &[0x00, 0xD6, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn read_record_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]); // EF.DIR
        // READ RECORD without PIN1.
        let (buf, len) = send(&mut app, &[0x00, 0xB2, 0x01, 0x04, 0x08]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn increase_without_pin1_rejected() {
        let mut app = app_with_pin1_enabled();
        // Select ADF USIM, then EF.ACC (cyclic).
        send(&mut app,
            &[0x00, 0xA4, 0x04, 0x04, 0x07,
              0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]);
        send(&mut app, &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x78]);
        // INCREASE without PIN1.
        let (buf, len) = send(&mut app,
            &[0x00, 0x32, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01]);
        assert_eq!(sw(&buf, len), (0x69, 0x82));
    }

    #[test]
    fn authenticate_without_pin1_succeeds() {
        // AUTHENTICATE has its own security context per ETSI TS 102 221
        // and does not require PIN1 verification.
        let mut app = app_with_pin1_enabled();
        // Build AUTHENTICATE APDU (P2=0x81 UMTS context).
        let mut apdu = [0u8; 4 + 1 + 34];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0x88; // INS
        apdu[2] = 0x00; // P1
        apdu[3] = 0x81; // P2
        apdu[4] = 0x22; // Lc = 34
        apdu[5] = 0x10; // RAND len prefix
        apdu[22] = 0x10; // AUTN len prefix
        let (buf, len) = send(&mut app, &apdu);
        // Should get MAC failure (98 62), not security error (69 82).
        assert_eq!(sw(&buf, len), (0x98, 0x62));
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use simrs_fs::{EfDef, EfStructure, Fid, FileRef};
    use simrs_milenage::OpVariant;
    use proptest::prelude::*;

    static PT_EF: EfDef = EfDef {
        fid: Fid(0x2FE2),
        sfi: None,
        structure: EfStructure::Transparent,
        data: &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };

    static PT_MF: DfDef = DfDef {
        fid: Fid(0x3F00),
        children: &[FileRef::Ef(&PT_EF)],
    };

    proptest! {
        // Any valid READ BINARY offset+length within file returns 90 00.
        #[test]
        fn read_binary_in_bounds(offset in 0u8..8, length in 0u8..=8u8) {
            prop_assume!(u16::from(offset) + u16::from(length) <= 8);
            let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
            let mut app = UsimApp::new(&PT_MF, &[], mil);
            let sel = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _ = app.handle(&cmd, &mut buf);

            let rb = [0x00, 0xB0, 0x00, offset, length];
            let cmd = Command::parse(&rb).unwrap();
            let rsp = app.handle(&cmd, &mut buf);
            let len = rsp.len();
            prop_assert_eq!((buf[len-2], buf[len-1]), (0x90, 0x00));
            prop_assert_eq!(len, length as usize + 2);
        }

        // FCP for any selected file always starts with tag 0x62.
        #[test]
        fn fcp_always_starts_with_62(idx in 0usize..2) {
            let fids: [u16; 2] = [0x3F00, 0x2FE2];
            let fid = fids[idx];
            let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
            let mut app = UsimApp::new(&PT_MF, &[], mil);
            let fid_be = fid.to_be_bytes();
            let sel = [0x00, 0xA4, 0x00, 0x04, 0x02, fid_be[0], fid_be[1]];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            let _rsp = app.handle(&cmd, &mut buf);
            prop_assert_eq!(buf[0], 0x61); // data available

            let fcp_len = buf[1];
            let gr = [0x00, 0xC0, 0x00, 0x00, fcp_len];
            let cmd2 = Command::parse(&gr).unwrap();
            let rsp2 = app.handle(&cmd2, &mut buf);
            let len2 = rsp2.len();
            prop_assert_eq!((buf[len2-2], buf[len2-1]), (0x90, 0x00));
            prop_assert_eq!(buf[0], 0x62); // FCP template
        }
    }
}
