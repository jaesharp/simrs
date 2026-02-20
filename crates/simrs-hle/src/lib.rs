//! HLE (High-Level Emulation) SIM peripheral for QEMU.
//!
//! Provides a safe Rust API around a thread-local [`Sim`](simrs_sim::Sim)
//! instance. QEMU hooks firmware function calls (e.g. `sim_send_apdu`) and
//! forwards APDU buffers to simrs via these functions instead of emulating
//! the physical SIM controller.
//!
//! # Thread-local design
//!
//! The SIM instance lives in a `thread_local! { RefCell<Option<Sim<256>>> }`.
//! This avoids global mutable state and is safe for single-threaded QEMU
//! plugin use. Each thread gets its own independent SIM.
//!
//! # C-ABI cdylib
//!
//! C-ABI exports (`extern "C"` with raw pointer parameters) are deferred
//! to an out-of-workspace crate because the workspace enforces
//! `unsafe_code = "forbid"`. This crate provides the safe Rust foundation.
//!
//! # HLE vs Register-Level
//! HLE operates at APDU granularity -- bypassing T=0 electrical protocol --
//! enabling ~100,000 APDUs/sec vs ~100 APDUs/sec for register-level emulation.
#![deny(unsafe_code)]
#![warn(missing_docs)]

use core::cell::RefCell;
use simrs_fs::DfDef;
use simrs_milenage::{MilenageParams, OpVariant};
use simrs_sim::{Sim, SimEvent, SimResponse};

thread_local! {
    static SIM: RefCell<Option<Sim<256>>> = const { RefCell::new(None) };
}

/// Initialize the thread-local SIM instance.
///
/// Creates a new `Sim<256>` with the given ATR and MF tree, configured
/// with the provided Milenage parameters. Must be called before any
/// other `hle_*` function.
///
/// Calling this again replaces the previous instance.
pub fn hle_init(
    atr: &'static [u8],
    mf: &'static DfDef,
    ki: [u8; 16],
    k: [u8; 16],
    opc: [u8; 16],
) {
    let mut sim = Sim::<256>::new(atr, mf);
    let mil = MilenageParams::with_defaults(k, OpVariant::Opc(opc));
    *sim.usim_app_mut() = simrs_usim::UsimApp::new(mf, &[], mil);
    *sim.gsm_app_mut() = simrs_gsm::GsmApp::new(mf, ki);
    SIM.with(|cell| {
        *cell.borrow_mut() = Some(sim);
    });
}

/// Reset the SIM to power-on state.
///
/// Sends a `PowerOn` event. Returns the ATR length, or 0 if not initialized.
pub fn hle_reset() -> usize {
    SIM.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let Some(sim) = borrow.as_mut() else {
            return 0;
        };
        match sim.process(SimEvent::PowerOn) {
            SimResponse::Atr(atr) => atr.len(),
            _ => 0,
        }
    })
}

/// Process one APDU command.
///
/// `cmd` is the raw APDU bytes. Response data (if any) is written to `rsp`.
/// Returns `Some((data_len, sw1, sw2))` on success, or `None` if the SIM
/// is not initialized or the response was ignored.
///
/// The caller must ensure `rsp` is large enough (256 bytes recommended).
pub fn hle_apdu(cmd: &[u8], rsp: &mut [u8]) -> Option<(usize, u8, u8)> {
    SIM.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let sim = borrow.as_mut()?;
        match sim.process(SimEvent::Apdu(cmd)) {
            SimResponse::Apdu { data, sw1, sw2 } => {
                let n = data.len().min(rsp.len());
                rsp[..n].copy_from_slice(&data[..n]);
                Some((n, sw1, sw2))
            }
            _ => None,
        }
    })
}

/// Save the SIM state into `buf`.
///
/// Returns the number of bytes written, or 0 if not initialized or
/// `buf` is too small.
pub fn hle_snapshot_save(buf: &mut [u8]) -> usize {
    SIM.with(|cell| {
        let borrow = cell.borrow();
        let Some(sim) = borrow.as_ref() else {
            return 0;
        };
        sim.save_state(buf)
    })
}

/// Restore the SIM state from `buf`.
///
/// Returns `true` on success, `false` if not initialized or invalid data.
pub fn hle_snapshot_restore(buf: &[u8]) -> bool {
    SIM.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let Some(sim) = borrow.as_mut() else {
            return false;
        };
        sim.restore_state(buf)
    })
}

/// Return the snapshot buffer size required.
pub const fn hle_snapshot_size() -> usize {
    Sim::<256>::SNAPSHOT_SIZE
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_fs::{EfDef, EfStructure, FileRef};

    static EF_ICCID: EfDef = EfDef {
        fid: 0x2FE2,
        sfi: None,
        structure: EfStructure::Transparent,
        data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    };

    static MF: DfDef = DfDef {
        fid: 0x3F00,
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static ATR: [u8; 2] = [0x3B, 0x00];

    fn init() {
        hle_init(&ATR, &MF, [0x11; 16], [0x22; 16], [0x33; 16]);
    }

    #[test]
    fn reset_before_init_returns_zero() {
        // Each test gets its own thread_local, but to be safe:
        SIM.with(|cell| *cell.borrow_mut() = None);
        assert_eq!(hle_reset(), 0);
    }

    #[test]
    fn init_and_reset() {
        init();
        let atr_len = hle_reset();
        assert_eq!(atr_len, ATR.len());
    }

    #[test]
    fn apdu_without_init_returns_none() {
        SIM.with(|cell| *cell.borrow_mut() = None);
        let mut rsp = [0u8; 256];
        assert!(hle_apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp).is_none());
    }

    #[test]
    fn apdu_before_power_on_returns_none() {
        init();
        let mut rsp = [0u8; 256];
        // No PowerOn yet -> Ignored -> None
        assert!(hle_apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp).is_none());
    }

    #[test]
    fn select_mf_after_power_on() {
        init();
        hle_reset();
        let mut rsp = [0u8; 256];
        let result = hle_apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp);
        let (_, sw1, _) = result.expect("APDU should succeed");
        assert_eq!(sw1, 0x61); // data available via GET RESPONSE
    }

    #[test]
    fn snapshot_save_restore_roundtrip() {
        init();
        hle_reset();
        // Do something to change state.
        let mut rsp = [0u8; 256];
        hle_apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp);

        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert_eq!(n, hle_snapshot_size());

        // Re-init (wipes state).
        init();
        assert!(hle_snapshot_restore(&snap[..n]));

        // Card should be Ready after restore.
        let result = hle_apdu(&[0xF0, 0xA4, 0x00, 0x00], &mut rsp);
        let (_, sw1, sw2) = result.expect("should get APDU response");
        assert_eq!((sw1, sw2), (0x6E, 0x00)); // unsupported CLA
    }

    #[test]
    fn snapshot_size_nonzero() {
        assert!(hle_snapshot_size() > 0);
    }

    #[test]
    fn snapshot_save_without_init_returns_zero() {
        SIM.with(|cell| *cell.borrow_mut() = None);
        let mut buf = [0u8; 1024];
        assert_eq!(hle_snapshot_save(&mut buf), 0);
    }
}
