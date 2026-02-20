//! 3GPP USIM application layer.
//!
//! Handles interindustry (CLA=`0x00`) and ETSI-class (CLA=`0x80`) APDUs:
//! SELECT (with FCP BER-TLV response), GET RESPONSE, READ BINARY,
//! READ RECORD, STATUS, AUTHENTICATE (Milenage), VERIFY PIN, UNBLOCK PIN,
//! TERMINAL PROFILE, FETCH, TERMINAL RESPONSE, and ENVELOPE.
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
//! use simrs_fs::{AdfSlot, DfDef, EfDef, EfStructure, FileRef};
//! use simrs_milenage::{MilenageParams, OpVariant};
//!
//! static EF: EfDef = EfDef {
//!     fid: 0x2FE2, sfi: None,
//!     structure: EfStructure::Transparent,
//!     data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
//! };
//! static MF: DfDef = DfDef { fid: 0x3F00, children: &[FileRef::Ef(&EF)] };
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
    AdfSlot, DfDef, EfDef, EfStructure, FsError, SelectionCtx, SelectedFile,
};
use simrs_iso7816::{ins, Command, StatusWord};
use simrs_milenage::{MilenageError, MilenageParams};
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

/// Maximum response queue size (FCP or AUTHENTICATE response).
const RSP_QUEUE_CAP: usize = 64;

// ---------------------------------------------------------------------------
// UsimApp
// ---------------------------------------------------------------------------

/// 3GPP USIM application.
///
/// Handles interindustry (CLA=`0x00`) and ETSI-class (CLA=`0x80`) APDUs.
/// Owns filesystem context, PIN manager, Milenage parameters, proactive
/// state, and the response queue for GET RESPONSE.
pub struct UsimApp {
    fs: SelectionCtx,
    adfs: &'static [AdfSlot],
    pin: PinManager<5>,
    milenage: MilenageParams,
    proactive: ProactiveState,
    rsp_queue: [u8; RSP_QUEUE_CAP],
    rsp_queue_len: u8,
}

impl UsimApp {
    /// Create a new USIM application.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_usim::UsimApp;
    /// use simrs_fs::{DfDef, AdfSlot};
    /// use simrs_milenage::{MilenageParams, OpVariant};
    ///
    /// static MF: DfDef = DfDef { fid: 0x3F00, children: &[] };
    /// let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
    /// let app = UsimApp::new(&MF, &[], mil);
    /// ```
    pub const fn new(
        mf: &'static DfDef,
        adfs: &'static [AdfSlot],
        milenage: MilenageParams,
    ) -> Self {
        Self {
            fs: SelectionCtx::new(mf),
            adfs,
            pin: PinManager::new(),
            milenage,
            proactive: ProactiveState::new(),
            rsp_queue: [0u8; RSP_QUEUE_CAP],
            rsp_queue_len: 0,
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

    // -- snapshot --

    /// Snapshot buffer size in bytes (560).
    pub const SNAPSHOT_SIZE: usize =
        SelectionCtx::SNAPSHOT_SIZE
        + PinManager::<5>::SNAPSHOT_SIZE
        + MilenageParams::SNAPSHOT_SIZE
        + ProactiveState::SNAPSHOT_SIZE
        + RSP_QUEUE_CAP
        + 1;

    /// Serialize the USIM application state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    /// The `adfs` reference is not serialized (static, reconstructed on restore).
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        let mut off = 0;
        off += self.fs.save_state(&mut buf[off..]);
        off += self.pin.save_state(&mut buf[off..]);
        off += self.milenage.save_state(&mut buf[off..]);
        off += self.proactive.save_state(&mut buf[off..]);
        buf[off..off + RSP_QUEUE_CAP].copy_from_slice(&self.rsp_queue);
        off += RSP_QUEUE_CAP;
        buf[off] = self.rsp_queue_len;
        Self::SNAPSHOT_SIZE
    }

    /// Restore the USIM application state from `buf`.
    ///
    /// Returns `true` on success. The `adfs` field is not restored from the
    /// snapshot; it remains as set during construction.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let mut off = 0;
        if !self.fs.restore_state(&buf[off..], self.adfs) {
            return false;
        }
        off += SelectionCtx::SNAPSHOT_SIZE;
        if !self.pin.restore_state(&buf[off..]) {
            return false;
        }
        off += PinManager::<5>::SNAPSHOT_SIZE;
        if !self.milenage.restore_state(&buf[off..]) {
            return false;
        }
        off += MilenageParams::SNAPSHOT_SIZE;
        if !self.proactive.restore_state(&buf[off..]) {
            return false;
        }
        off += ProactiveState::SNAPSHOT_SIZE;
        self.rsp_queue.copy_from_slice(&buf[off..off + RSP_QUEUE_CAP]);
        off += RSP_QUEUE_CAP;
        self.rsp_queue_len = buf[off];
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
            self.rsp_queue_len = 0;
        }

        let rsp = match (cla, cmd.ins()) {
            // -- Interindustry commands (CLA=0x00) --
            (CLA_INTER, ins::SELECT) => self.handle_select(cmd, buf),
            (CLA_INTER, ins::GET_RESPONSE) => self.handle_get_response(cmd, buf),
            (CLA_INTER, ins::READ_BINARY) => self.handle_read_binary(cmd, buf),
            (CLA_INTER, ins::READ_RECORD) => self.handle_read_record(cmd, buf),
            (CLA_INTER, ins::STATUS) => self.handle_status(cmd, buf),
            (CLA_INTER, ins::AUTHENTICATE) => self.handle_authenticate(cmd, buf),
            (CLA_INTER, ins::VERIFY) => self.handle_verify(cmd, buf),
            (CLA_INTER, ins::RESET_RETRY_CTR) => self.handle_unblock(cmd, buf),
            // -- ETSI CAT commands (CLA=0x80) --
            (CLA_ETSI, ins::TERMINAL_PROFILE) => self.handle_terminal_profile(buf),
            (CLA_ETSI, ins::FETCH) => self.handle_fetch(cmd, buf),
            (CLA_ETSI, ins::TERMINAL_RESPONSE) => self.handle_terminal_response(cmd, buf),
            (CLA_ETSI, ins::ENVELOPE) => self.handle_envelope(buf),
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
                let fid = u16::from_be_bytes([cmd.data()[0], cmd.data()[1]]);
                match self.fs.select_by_fid(fid) {
                    Ok(sel) => self.queue_fcp(sel, None, buf),
                    Err(FsError::FileNotFound) => write_sw_raw(buf, 0x6A, 0x82),
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
                    Err(FsError::FileNotFound) => write_sw_raw(buf, 0x6A, 0x82),
                    Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
                }
            }
            _ => write_sw_raw(buf, 0x6A, 0x86),
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
        let fcp_len = build_fcp(sel, aid, &mut self.rsp_queue);
        self.rsp_queue_len = fcp_len as u8;
        write_sw_raw(buf, 0x61, fcp_len as u8)
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
        let copy_len = if le == 0 { len } else { le.min(len) };
        if buf.len() < copy_len + 2 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }
        buf[..copy_len].copy_from_slice(&self.rsp_queue[..copy_len]);
        buf[copy_len] = 0x90;
        buf[copy_len + 1] = 0x00;
        self.rsp_queue_len = 0;
        &buf[..copy_len + 2]
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
                let data_len = data.len();
                if buf.len() < data_len + 2 {
                    return write_sw(buf, StatusWord::NoPreciseDiagnosis);
                }
                buf[..data_len].copy_from_slice(data);
                buf[data_len] = 0x90;
                buf[data_len + 1] = 0x00;
                &buf[..data_len + 2]
            }
            Err(FsError::NoEfSelected) => write_sw_raw(buf, 0x69, 0x86),
            Err(FsError::NotTransparent) => write_sw_raw(buf, 0x69, 0x81),
            Err(FsError::OffsetOutOfRange) => write_sw_raw(buf, 0x6A, 0x82),
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

        match self.fs.read_record(rec_num) {
            Ok(data) => {
                let data_len = data.len();
                if buf.len() < data_len + 2 {
                    return write_sw(buf, StatusWord::NoPreciseDiagnosis);
                }
                buf[..data_len].copy_from_slice(data);
                buf[data_len] = 0x90;
                buf[data_len + 1] = 0x00;
                &buf[..data_len + 2]
            }
            Err(FsError::NoEfSelected) => write_sw_raw(buf, 0x69, 0x86),
            Err(FsError::NotRecordBased) => write_sw_raw(buf, 0x69, 0x81),
            Err(FsError::RecordOutOfRange) => write_sw_raw(buf, 0x6A, 0x83),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- STATUS --

    fn handle_status<'buf>(
        &self,
        _cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // Return FCP of current DF.
        let mut fcp_buf = [0u8; FCP_BUF_CAP];
        let fcp_len = build_fcp(
            SelectedFile::Df(self.fs.current_df()),
            None,
            &mut fcp_buf,
        );
        if buf.len() < fcp_len + 2 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }
        buf[..fcp_len].copy_from_slice(&fcp_buf[..fcp_len]);
        buf[fcp_len] = 0x90;
        buf[fcp_len + 1] = 0x00;
        &buf[..fcp_len + 2]
    }

    // -- AUTHENTICATE (Milenage UMTS context) --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_authenticate<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // P2=0x81: UMTS/EPS AKA security context.
        if cmd.p2() != 0x81 {
            return write_sw_raw(buf, 0x6A, 0x86);
        }

        let data = cmd.data();
        // Data: 0x10 [RAND:16] 0x10 [AUTN:16] = 34 bytes.
        if data.len() != 34 {
            return write_sw(buf, StatusWord::WrongLength);
        }
        if data[0] != 0x10 || data[17] != 0x10 {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let mut rand = [0u8; 16];
        rand.copy_from_slice(&data[1..17]);
        let mut autn = [0u8; 16];
        autn.copy_from_slice(&data[18..34]);

        match self.milenage.authenticate(&rand, &autn) {
            Ok(result) => {
                // Build response: 0xDB <len> <RES_len> [RES] <CK_len> [CK] <IK_len> [IK]
                // 0xDB + len + (1+8) + (1+16) + (1+16) = 2 + 9 + 17 + 17 = 45
                let inner_len: u8 = 1 + 8 + 1 + 16 + 1 + 16; // = 43
                let mut pos: usize = 0;
                self.rsp_queue[pos] = 0xDB;
                pos += 1;
                self.rsp_queue[pos] = inner_len;
                pos += 1;
                // RES
                self.rsp_queue[pos] = 0x08;
                pos += 1;
                self.rsp_queue[pos..pos + 8].copy_from_slice(&result.res);
                pos += 8;
                // CK
                self.rsp_queue[pos] = 0x10;
                pos += 1;
                self.rsp_queue[pos..pos + 16].copy_from_slice(&result.ck);
                pos += 16;
                // IK
                self.rsp_queue[pos] = 0x10;
                pos += 1;
                self.rsp_queue[pos..pos + 16].copy_from_slice(&result.ik);
                pos += 16;

                self.rsp_queue_len = pos as u8;
                write_sw_raw(buf, 0x61, pos as u8)
            }
            Err(MilenageError::MacFailure) => write_sw_raw(buf, 0x98, 0x62),
            Err(MilenageError::SyncFailure { auts }) => {
                // Response: 0xDC 0x0E [AUTS:14]
                self.rsp_queue[0] = 0xDC;
                self.rsp_queue[1] = 0x0E;
                self.rsp_queue[2..16].copy_from_slice(&auts);
                self.rsp_queue_len = 16;
                write_sw_raw(buf, 0x61, 16)
            }
        }
    }

    // -- VERIFY PIN --

    fn handle_verify<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if cmd.p1() != 0x00 {
            return write_sw_raw(buf, 0x6A, 0x86);
        }
        let key = PinKey(cmd.p2());

        // Empty data: query retry count.
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

        if cmd.data().is_empty() {
            return match self.pin.puk_retries(key) {
                Some(n) => write_sw(buf, StatusWord::pin_retries(n & 0x0F)),
                None => write_sw(buf, StatusWord::wrong_params(0x88)),
            };
        }

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

    // -- TERMINAL PROFILE --

    #[allow(clippy::unused_self)]
    fn handle_terminal_profile<'buf>(&self, buf: &'buf mut [u8]) -> &'buf [u8] {
        // Accept and ignore the terminal profile data.
        write_sw(buf, StatusWord::Success)
    }

    // -- FETCH --

    fn handle_fetch<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        if !self.proactive.has_pending() {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }

        let le = cmd.le().unwrap_or(0) as usize;
        let pending = self.proactive.pending_len();
        let fetch_len = if le == 0 { pending } else { le.min(pending) };

        if buf.len() < fetch_len + 2 {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis);
        }

        let written = self.proactive.fetch(&mut buf[..fetch_len]);
        buf[written] = 0x90;
        buf[written + 1] = 0x00;
        &buf[..written + 2]
    }

    // -- TERMINAL RESPONSE --

    fn handle_terminal_response<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        self.proactive.terminal_response(cmd.data());
        write_sw(buf, StatusWord::Success)
    }

    // -- ENVELOPE --

    #[allow(clippy::unused_self)]
    fn handle_envelope<'buf>(&self, buf: &'buf mut [u8]) -> &'buf [u8] {
        // Accept envelope data. Stub: no processing.
        write_sw(buf, StatusWord::Success)
    }
}

// ---------------------------------------------------------------------------
// FCP BER-TLV builder per ETSI TS 102 221 clause 11.1.1.3
// ---------------------------------------------------------------------------

/// Build an FCP template for the selected file.
///
/// Returns the number of bytes written to `out`. The FCP is a BER-TLV
/// structure with tag 0x62.
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

    // Real run: write 0x62 + length + inner content.
    let mut enc = Encoder::new(out);
    // Tag 0x62.
    let _ = enc.raw(&[0x62]);
    // BER length of inner content.
    let _ = write_ber_len(&mut enc, inner_len);
    // Inner TLV objects.
    let _ = write_fcp_inner(&mut enc, sel, aid);
    enc.len()
}

/// Compute the byte length of the FCP inner content (without the 0x62 tag
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
    // Tag 0x82: File descriptor.
    // DF descriptor: byte 0 = 0x78 (DF), byte 1 = 0x21 (data coding = BER-TLV).
    enc.tag_length_value(0x82, &[0x78, 0x21])?;

    // Tag 0x83: File ID.
    let fid_be = df.fid.to_be_bytes();
    enc.tag_length_value(0x83, &fid_be)?;

    // Tag 0x84: DF name (AID) -- only for ADF.
    if let Some(aid_bytes) = aid {
        enc.tag_length_value(0x84, aid_bytes)?;
    }

    // Tag 0xA5: Proprietary information (empty for now).
    enc.tag_length_value(0xA5, &[])?;

    // Tag 0x8A: Life cycle status = 0x05 (activated).
    enc.tag_length_value(0x8A, &[0x05])?;

    // Tag 0x8C: Security attributes compact (always allowed = 0x7F + 7 zeros).
    enc.tag_length_value(0x8C, &[0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;

    // Tag 0xC6: PIN status template DO.
    // Contains PS_DO (tag 0x90) with PIN reference.
    let pin_status = [0x90, 0x01, 0x01]; // PS_DO: PIN1 reference
    enc.tag_length_value(0xC6, &pin_status)?;

    Ok(())
}

/// FCP inner content for an EF.
#[allow(clippy::cast_possible_truncation)]
fn write_fcp_ef(
    enc: &mut Encoder<'_>,
    ef: &EfDef,
) -> Result<(), simrs_bertlv::BerError> {
    // Tag 0x82: File descriptor.
    match ef.structure {
        EfStructure::Transparent => {
            // Transparent: byte 0 = 0x41 (working EF, transparent).
            enc.tag_length_value(0x82, &[0x41, 0x21])?;
        }
        EfStructure::LinearFixed { record_size, num_records } => {
            // Linear fixed: byte 0 = 0x42, + 3 extra bytes: data coding + record len(2).
            let rec_be = u16::from(record_size).to_be_bytes();
            enc.tag_length_value(
                0x82,
                &[0x42, 0x21, num_records, rec_be[0], rec_be[1]],
            )?;
        }
        EfStructure::Cyclic { record_size, num_records } => {
            // Cyclic: byte 0 = 0x46 (cyclic), + 3 extra bytes.
            let rec_be = u16::from(record_size).to_be_bytes();
            enc.tag_length_value(
                0x82,
                &[0x46, 0x21, num_records, rec_be[0], rec_be[1]],
            )?;
        }
    }

    // Tag 0x83: File ID.
    let fid_be = ef.fid.to_be_bytes();
    enc.tag_length_value(0x83, &fid_be)?;

    // Tag 0x80: File size.
    let size = ef.data.len() as u16;
    let size_be = size.to_be_bytes();
    enc.tag_length_value(0x80, &size_be)?;

    // Tag 0x88: Short File Identifier (if assigned).
    if let Some(sfi) = ef.sfi {
        // SFI is encoded as (sfi << 3) | 0x04 per ETSI TS 102 221.
        enc.tag_length_value(0x88, &[(sfi << 3) | 0x04])?;
    }

    // Tag 0x8A: Life cycle status = 0x05 (activated).
    enc.tag_length_value(0x8A, &[0x05])?;

    // Tag 0x8C: Security attributes compact.
    enc.tag_length_value(0x8C, &[0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;

    Ok(())
}

/// Write a BER-encoded length using the encoder.
fn write_ber_len(
    enc: &mut Encoder<'_>,
    len: usize,
) -> Result<(), simrs_bertlv::BerError> {
    #[allow(clippy::cast_possible_truncation)]
    if len <= 0x7F {
        enc.raw(&[len as u8])
    } else {
        enc.raw(&[0x81, len as u8])
    }
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
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use simrs_fs::{AdfSlot, EfDef, EfStructure, FileRef};
    use simrs_milenage::OpVariant;
    use simrs_proactive::ProactiveCommand;

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

    static EF_IMSI: EfDef = EfDef {
        fid: 0x6F07,
        sfi: Some(7),
        structure: EfStructure::Transparent,
        data: &[0x08, 0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
    };

    static EF_UST: EfDef = EfDef {
        fid: 0x6F38,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &[0xFF, 0xFF, 0xFF, 0xFF],
    };

    static ADF_USIM_ROOT: DfDef = DfDef {
        fid: 0xFF01,
        children: &[FileRef::Ef(&EF_IMSI), FileRef::Ef(&EF_UST)],
    };

    static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_ROOT,
    }];

    static MF: DfDef = DfDef {
        fid: 0x3F00,
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
            .add_pin(PinKey(0x01), &pin_val, 3, &puk_val, 10, true)
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
        let (sw1, _) = sw(&buf, len);
        assert_ne!(sw1, 0x90);
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
        // fs(8) + pin(111) + milenage(117) + proactive(259) + rsp_queue(64) + rsp_queue_len(1) = 560
        assert_eq!(UsimApp::SNAPSHOT_SIZE, 560);
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
        let mut snap = [0u8; UsimApp::SNAPSHOT_SIZE];
        let written = src.save_state(&mut snap);
        assert_eq!(written, UsimApp::SNAPSHOT_SIZE);

        // Restore into fresh app (same adfs).
        let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
        let mut dst = UsimApp::new(&MF, &ADF_TABLE, mil);
        assert!(dst.restore_state(&snap));

        // Read EF.IMSI (fs state restored).
        let (buf, len) = send(&mut dst, &[0x00, 0xB0, 0x00, 0x00, 0x09]);
        assert_eq!(sw(&buf, len), (0x90, 0x00));
        assert_eq!(buf[0], 0x08);

        // PIN retries = 2.
        let (buf, len) = send(&mut dst, &[0x00, 0x20, 0x00, 0x01, 0x00]);
        assert_eq!(sw(&buf, len), (0x63, 0xC2));
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
        let mut snap = [0u8; UsimApp::SNAPSHOT_SIZE];
        src.save_state(&mut snap);
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
        let mut snap = [0u8; UsimApp::SNAPSHOT_SIZE];
        src.save_state(&mut snap);
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
            let (value_len, extra) = if len_byte <= 0x7F {
                (len_byte as usize, 0)
            } else if len_byte == 0x81 && pos < data.len() {
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
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use simrs_fs::{EfDef, EfStructure, FileRef};
    use simrs_milenage::OpVariant;
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
            let mil = MilenageParams::with_defaults([0u8; 16], OpVariant::Opc([0u8; 16]));
            let mut app = UsimApp::new(&PT_MF, &[], mil);
            let sel = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2];
            let cmd = Command::parse(&sel).unwrap();
            let mut buf = [0u8; 256];
            app.handle(&cmd, &mut buf);

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
