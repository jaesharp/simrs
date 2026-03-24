//! GlobalPlatform Applet adapter for SIM/USIM application layers.
//!
//! Wraps [`UsimApp`](simrs_usim::UsimApp) (and optionally
//! [`GsmApp`](simrs_gsm::GsmApp)) as a [`simrs_jcre::Applet`], allowing
//! the SIM/USIM stack to be installed inside a GP card runtime.
//!
//! Unlike [`Sim`](crate::Sim), this adapter does **not** own card-level
//! state (ATR, `CardState`, reset policy). Those are managed by the GP
//! card manager. `SimApplet` owns only the application-layer objects and
//! routes APDUs by CLA family, producing [`AppletResult`] instead of
//! [`SimResponse`](crate::SimResponse).

use simrs_iso7816::{Command, StatusWord};
use simrs_jcre::{Applet, AppletResult};
use simrs_milenage::AuthenticationAlgorithm;

#[cfg(feature = "gsm")]
use simrs_gsm::GsmApp;
#[cfg(feature = "usim")]
use simrs_usim::UsimApp;

use crate::{classify_cla, ClaFamily};

#[cfg(feature = "usim")]
use simrs_fs::{AdfSlot, DfDef};

// ---------------------------------------------------------------------------
// SimApplet
// ---------------------------------------------------------------------------

/// SIM/USIM application layers wrapped as a GP Applet.
///
/// `A` is the authentication algorithm (e.g. `MilenageParams`).
/// Enable `usim` and/or `gsm` features to include the respective layers.
pub struct SimApplet<A: AuthenticationAlgorithm> {
    #[cfg(feature = "usim")]
    usim: UsimApp<A>,
    #[cfg(feature = "gsm")]
    gsm: GsmApp,
    /// Internal response buffer for APDU processing.
    rsp_buf: [u8; 256],
    #[cfg(not(feature = "usim"))]
    _auth: core::marker::PhantomData<A>,
}

impl<A: AuthenticationAlgorithm> SimApplet<A> {
    /// Create a new `SimApplet` with USIM (and optionally GSM) application layers.
    ///
    /// This mirrors the [`UsimApp::new`](simrs_usim::UsimApp::new) constructor.
    /// The `mf` and `adfs` parameters define the filesystem tree for the USIM.
    #[cfg(all(feature = "usim", not(feature = "gsm")))]
    pub fn new(mf: &'static DfDef, adfs: &'static [AdfSlot], auth: A) -> Self {
        Self {
            usim: UsimApp::new(mf, adfs, auth),
            rsp_buf: [0u8; 256],
        }
    }

    /// Create a new `SimApplet` with both USIM and GSM application layers.
    #[cfg(all(feature = "usim", feature = "gsm"))]
    pub fn new(mf: &'static DfDef, adfs: &'static [AdfSlot], auth: A) -> Self {
        Self {
            usim: UsimApp::new(mf, adfs, auth),
            gsm: GsmApp::new(mf, simrs_gsm::SubscriberKey::classify([0u8; 16])),
            rsp_buf: [0u8; 256],
        }
    }

    /// Create a new `SimApplet` with both USIM and GSM, providing a
    /// pre-configured `GsmApp`.
    #[cfg(all(feature = "usim", feature = "gsm"))]
    pub fn with_gsm(mf: &'static DfDef, adfs: &'static [AdfSlot], auth: A, gsm: GsmApp) -> Self {
        Self {
            usim: UsimApp::new(mf, adfs, auth),
            gsm,
            rsp_buf: [0u8; 256],
        }
    }

    /// Access the USIM application layer.
    #[cfg(feature = "usim")]
    pub const fn usim_app_mut(&mut self) -> &mut UsimApp<A> {
        &mut self.usim
    }

    /// Access the GSM application layer.
    #[cfg(feature = "gsm")]
    pub const fn gsm_app_mut(&mut self) -> &mut GsmApp {
        &mut self.gsm
    }

    /// Route an APDU to the appropriate application layer, returning the
    /// number of response bytes written to `out`, or a status word on error.
    fn route_apdu(&mut self, cmd_bytes: &[u8], out: &mut [u8]) -> AppletResult {
        if cmd_bytes.len() < 4 {
            return AppletResult::Sw(StatusWord::WrongLength);
        }

        let Ok(cmd) = Command::parse(cmd_bytes) else {
            return AppletResult::Sw(StatusWord::WrongLength);
        };

        let cla = cmd.cla_raw();
        let family = classify_cla(cla);

        // Route by CLA family, replicating Sim::handle_apdu logic.
        let rsp_slice = match family {
            #[cfg(feature = "gsm")]
            ClaFamily::Gsm => self.gsm.handle(&cmd, &mut self.rsp_buf),

            #[cfg(not(feature = "gsm"))]
            ClaFamily::Gsm => {
                return AppletResult::Sw(StatusWord::ClassNotSupported);
            }

            #[cfg(feature = "usim")]
            ClaFamily::Interindustry | ClaFamily::EtsiProprietary => {
                self.usim.handle(&cmd, &mut self.rsp_buf)
            }

            #[cfg(not(feature = "usim"))]
            ClaFamily::Interindustry | ClaFamily::EtsiProprietary => {
                return AppletResult::Sw(StatusWord::ClassNotSupported);
            }

            ClaFamily::Unknown => {
                return AppletResult::Sw(StatusWord::ClassNotSupported);
            }
        };

        // Application layers return [data..., SW1, SW2].
        if rsp_slice.len() < 2 {
            return AppletResult::Sw(StatusWord::NoPreciseDiagnosis);
        }

        let sw_offset = rsp_slice.len() - 2;
        let sw = StatusWord::from_bytes(rsp_slice[sw_offset], rsp_slice[sw_offset + 1]);
        let data_len = sw_offset;

        if data_len > 0 {
            // Copy response data to `out`.
            if out.len() < data_len {
                return AppletResult::Sw(StatusWord::WrongLength);
            }
            out[..data_len].copy_from_slice(&rsp_slice[..data_len]);
        }

        // If the SW is a success family (90 XX, 91 XX, 61 XX, 9F XX),
        // return Ok(n). Otherwise return the SW as an error.
        let [sw1, _sw2] = sw.to_bytes();
        match sw1 {
            0x90 | 0x91 | 0x61 | 0x9F => AppletResult::Ok(data_len),
            _ => {
                // For error SWs that carry data (some proprietary schemes),
                // still include the data length. But standard practice is
                // to signal via Sw for error status words.
                AppletResult::Sw(sw)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Applet trait implementation
// ---------------------------------------------------------------------------

impl<A: AuthenticationAlgorithm> Applet for SimApplet<A> {
    fn process(&mut self, cmd: &[u8], out: &mut [u8]) -> AppletResult {
        self.route_apdu(cmd, out)
    }

    fn select(&mut self, _out: &mut [u8]) -> AppletResult {
        AppletResult::Ok(0)
    }

    fn deselect(&mut self) {
        // Clear response queues and PIN verified state on deselect,
        // matching CLEAR_ON_DESELECT semantics (JC RE 2.1.1 clause 3.4).
        #[cfg(feature = "usim")]
        {
            self.usim.clear_response_queue();
            self.usim.pin_manager().reset_verified();
        }
        #[cfg(feature = "gsm")]
        {
            self.gsm.clear_response_queue();
            self.gsm.pin_manager().reset_verified();
        }
    }

    fn snapshot_size(&self) -> usize {
        let mut size = 0usize;
        #[cfg(feature = "usim")]
        {
            size += UsimApp::<A>::SNAPSHOT_SIZE;
        }
        #[cfg(feature = "gsm")]
        {
            size += GsmApp::SNAPSHOT_SIZE;
        }
        size
    }

    fn save_state(&self, buf: &mut [u8]) -> usize {
        let total = self.snapshot_size();
        if buf.len() < total {
            return 0;
        }
        let mut off = 0;
        #[cfg(feature = "usim")]
        {
            off += self.usim.save_state(&mut buf[off..]);
        }
        #[cfg(feature = "gsm")]
        {
            off += self.gsm.save_state(&mut buf[off..]);
        }
        let _ = off;
        total
    }

    fn restore_state(&mut self, buf: &[u8]) -> bool {
        let total = self.snapshot_size();
        if buf.len() < total {
            return false;
        }
        let mut off = 0;
        #[cfg(feature = "usim")]
        {
            if !self.usim.restore_state(&buf[off..]) {
                return false;
            }
            off += UsimApp::<A>::SNAPSHOT_SIZE;
        }
        #[cfg(feature = "gsm")]
        {
            if !self.gsm.restore_state(&buf[off..], &[]) {
                return false;
            }
            off += GsmApp::SNAPSHOT_SIZE;
        }
        let _ = off;
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::large_stack_arrays)]
mod tests {
    use super::*;
    use simrs_jcre::Applet;
    use simrs_milenage::MilenageParams;

    #[cfg(feature = "usim")]
    use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef};
    #[cfg(feature = "usim")]
    use simrs_milenage::{OperatorVariant, SubscriberKey};

    // -- Test filesystem --

    #[cfg(feature = "usim")]
    static ICCID_DATA: [u8; 10] = [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

    #[cfg(feature = "usim")]
    static EF_ICCID: EfDef = EfDef::transparent(Fid::new(0x2FE2), None, &ICCID_DATA);

    #[cfg(feature = "usim")]
    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    #[cfg(feature = "usim")]
    static IMSI_DATA: [u8; 9] = [0x08, 0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01];

    #[cfg(feature = "usim")]
    static EF_IMSI: EfDef = EfDef::transparent(Fid::new(0x6F07), None, &IMSI_DATA);

    #[cfg(feature = "usim")]
    static ADF_USIM_DF: DfDef = DfDef {
        fid: Fid::new(0x7FFF),
        children: &[FileRef::Ef(&EF_IMSI)],
    };

    #[cfg(feature = "usim")]
    static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

    #[cfg(feature = "usim")]
    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &USIM_AID,
        root: &ADF_USIM_DF,
    }];

    #[cfg(feature = "usim")]
    fn make_applet() -> SimApplet<MilenageParams> {
        let mil = MilenageParams::with_defaults(
            SubscriberKey::classify([0u8; 16]),
            OperatorVariant::operator_cipher([0u8; 16]),
        );
        SimApplet::new(&MF, &ADF_TABLE, mil)
    }

    // -----------------------------------------------------------------------
    // process() routes CLA=0x00 APDU to USIM
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn process_routes_cla_00_to_usim() {
        let mut applet = make_applet();
        let mut out = [0u8; 256];

        // SELECT MF: CLA=0x00 INS=0xA4 P1=0x00 P2=0x04 Lc=0x02 data=3F00
        let cmd = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let result = applet.process(&cmd, &mut out);

        // USIM SELECT returns 61 XX (data available via GET RESPONSE),
        // which is a success family SW -> AppletResult::Ok(0) with no data
        // in the output buffer (the data is queued internally).
        match result {
            AppletResult::Ok(n) => {
                // SELECT with FCI queues a response; the actual data comes
                // via GET RESPONSE. Data length from process should be 0.
                assert_eq!(n, 0, "SELECT should produce 0 data bytes (response queued)");
            }
            AppletResult::Sw(sw) => {
                // 61 XX is also acceptable -- the Applet trait maps it to Ok(0).
                let [sw1, _sw2] = sw.to_bytes();
                panic!("expected Ok from USIM SELECT, got SW {sw1:02X}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // process() routes CLA=0xA0 APDU to GSM
    // -----------------------------------------------------------------------

    #[cfg(all(feature = "gsm", feature = "usim"))]
    #[test]
    fn process_routes_cla_a0_to_gsm() {
        let mut applet = make_applet();
        let mut out = [0u8; 256];

        // SELECT MF via GSM: CLA=0xA0 INS=0xA4 P1=0x00 P2=0x00 Lc=0x02 data=3F00
        let cmd = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
        let result = applet.process(&cmd, &mut out);

        // GSM SELECT returns 9F XX (data available via GET RESPONSE),
        // which is a success family SW -> AppletResult::Ok(0).
        match result {
            AppletResult::Ok(n) => {
                assert_eq!(n, 0, "GSM SELECT should produce 0 data bytes");
            }
            AppletResult::Sw(sw) => {
                let [sw1, _sw2] = sw.to_bytes();
                panic!("expected Ok from GSM SELECT, got SW {sw1:02X}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // process() rejects unknown CLA
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn process_rejects_unknown_cla() {
        let mut applet = make_applet();
        let mut out = [0u8; 256];

        // CLA=0xF0 is not assigned to any family.
        let cmd = [0xF0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
        let result = applet.process(&cmd, &mut out);

        assert!(
            matches!(result, AppletResult::Sw(sw) if sw.to_bytes() == [0x6E, 0x00]),
            "unknown CLA should return 6E 00, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // process() rejects short APDUs
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn process_rejects_short_apdu() {
        let mut applet = make_applet();
        let mut out = [0u8; 256];

        // Only 3 bytes -- too short for a valid APDU.
        let cmd = [0x00, 0xA4, 0x00];
        let result = applet.process(&cmd, &mut out);

        assert!(
            matches!(result, AppletResult::Sw(_)),
            "short APDU should return an error SW, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // select() returns Ok
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn select_returns_ok() {
        let mut applet = make_applet();
        let mut out = [0u8; 256];
        let result = applet.select(&mut out);
        assert_eq!(result, AppletResult::Ok(0));
    }

    // -----------------------------------------------------------------------
    // deselect() is callable (does not panic)
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn deselect_is_callable() {
        let mut applet = make_applet();
        applet.deselect();
        // No panic, no return value to check. Verify the applet is still
        // functional after deselect by issuing a new command.
        let mut out = [0u8; 256];
        let result = applet.select(&mut out);
        assert_eq!(result, AppletResult::Ok(0));
    }

    // -----------------------------------------------------------------------
    // snapshot_size() returns consistent value
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn snapshot_size_is_consistent() {
        let applet = make_applet();
        let s1 = applet.snapshot_size();
        let s2 = applet.snapshot_size();
        assert_eq!(s1, s2, "snapshot_size must be deterministic");
        assert!(s1 > 0, "snapshot_size must be non-zero with usim enabled");
    }

    // -----------------------------------------------------------------------
    // save_state / restore_state round-trip
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn snapshot_roundtrip() {
        // Use a const-sized buffer large enough for the snapshot.
        // UsimApp + GsmApp snapshots fit well within 8192 bytes.
        const BUF: usize = 8192;

        let mut applet = make_applet();
        let mut out = [0u8; 256];

        // Issue a STATUS command to change internal state (response queue, etc.)
        let status_cmd = [0x00, 0xF2, 0x00, 0x0C]; // STATUS P2=0x0C no FCI
        let _ = applet.process(&status_cmd, &mut out);

        // Save state.
        let size = applet.snapshot_size();
        assert!(size <= BUF, "snapshot_size exceeds test buffer");
        let mut snap = [0u8; BUF];
        let written = applet.save_state(&mut snap);
        assert_eq!(
            written, size,
            "save_state should write exactly snapshot_size bytes"
        );

        // Restore into a fresh applet.
        let mut applet2 = make_applet();
        assert!(
            applet2.restore_state(&snap[..size]),
            "restore_state should succeed with valid snapshot"
        );

        // The restored applet should have the same snapshot.
        let mut snap2 = [0u8; BUF];
        let written2 = applet2.save_state(&mut snap2);
        assert_eq!(written2, size);
        assert_eq!(
            &snap[..size],
            &snap2[..size],
            "restored applet should produce identical snapshot"
        );
    }

    // -----------------------------------------------------------------------
    // save_state rejects undersized buffer
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn save_state_rejects_small_buffer() {
        let applet = make_applet();
        let mut small = [0u8; 0];
        assert_eq!(applet.save_state(&mut small), 0);
    }

    // -----------------------------------------------------------------------
    // restore_state rejects undersized buffer
    // -----------------------------------------------------------------------

    #[cfg(feature = "usim")]
    #[test]
    fn restore_state_rejects_small_buffer() {
        let mut applet = make_applet();
        assert!(!applet.restore_state(&[]));
    }
}
