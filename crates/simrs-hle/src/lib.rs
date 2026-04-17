//! HLE (High-Level Emulation) SIM peripheral for QEMU.
//!
//! Provides a safe Rust API around a thread-local `SimInstance`
//! enum that dispatches to either Milenage or TUAK authentication.
//! QEMU hooks firmware function calls (e.g. `sim_send_apdu`) and
//! forwards APDU buffers to simrs via these functions instead of emulating
//! the physical SIM controller.
//!
//! # Thread-local design
//!
//! The SIM instance lives in a `thread_local! { RefCell<Option<SimInstance>> }`.
//! This avoids global mutable state and is safe for single-threaded QEMU
//! plugin use. Each thread gets its own independent SIM.
//!
//! # Authentication algorithms
//!
//! Two algorithms are supported:
//! - **Milenage** ([3GPP TS 35.206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf)): initialized via [`hle_init`]
//! - **TUAK** ([3GPP TS 35.231 V19.0.0](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf)): initialized via [`hle_init_tuak`]
//!
//! All other `hle_*` functions dispatch transparently to whichever
//! algorithm was selected at init time.
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
use simrs_fs::{AdfSlot, DfDef};
use simrs_gp_card::GpCard;
use simrs_gp_keys::KeySet;
use simrs_milenage::{MilenageParams, OperatorVariant as MilOp, SubscriberKey};
use simrs_profile::{AuthConfig, ProfileConfig};
use simrs_sim::gp_adapter::SimApplet;
use simrs_sim::{Sim, SimEvent, SimResponse};
use simrs_tuak::{OperatorVariant as TuakOp, TuakParams};

/// Re-export [`simrs_gsm::SubscriberKey`] so callers of [`hle_init`] don't
/// need a direct dependency on `simrs-gsm`.
pub use simrs_gsm::SubscriberKey as GsmSubscriberKey;

// ---------------------------------------------------------------------------
// SimInstance enum -- runtime-selected authentication algorithm
// ---------------------------------------------------------------------------

/// Runtime-selected authentication algorithm.
///
/// All variants are large stack-allocated types (8--10 kB) to support
/// `no_std` / no-heap environments.  The size difference between
/// variants is intentional and does not warrant `Box` indirection.
#[allow(clippy::large_enum_variant)]
enum SimInstance {
    /// Milenage ([3GPP TS 35.206 V19.0.0](../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf)).
    Milenage(Sim<MilenageParams, 256>),
    /// TUAK ([3GPP TS 35.231 V19.0.0](../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf)).
    Tuak(Sim<TuakParams, 256>),
    /// `GlobalPlatform` card with SIM applet (Milenage).
    GpMilenage(GpCard<261>),
}

thread_local! {
    static SIM: RefCell<Option<SimInstance>> = const { RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// Dispatch macro
// ---------------------------------------------------------------------------

/// Dispatch to the inner `Sim` or `GpCard` regardless of auth algorithm.
///
/// Both `Sim` and `GpCard` expose `process(SimEvent) -> SimResponse` and
/// `state_hash() -> u64`, so the same body compiles for all variants.
macro_rules! with_sim {
    ($default:expr, |$sim:ident| $body:expr) => {
        SIM.with(|cell| {
            let mut borrow = cell.borrow_mut();
            match borrow.as_mut() {
                Some(SimInstance::Milenage($sim)) => $body,
                Some(SimInstance::Tuak($sim)) => $body,
                Some(SimInstance::GpMilenage($sim)) => $body,
                None => $default,
            }
        })
    };
}

// ---------------------------------------------------------------------------
// Maximum snapshot size
// ---------------------------------------------------------------------------

/// Maximum snapshot size across all card types (includes 1-byte discriminant).
pub const MAX_SNAPSHOT_SIZE: usize = 1 + {
    let mil = Sim::<MilenageParams, 256>::SNAPSHOT_SIZE;
    let tuak = Sim::<TuakParams, 256>::SNAPSHOT_SIZE;
    let gp = GpCard::<261>::SNAPSHOT_SIZE;
    let mut max = mil;
    if tuak > max {
        max = tuak;
    }
    if gp > max {
        max = gp;
    }
    max
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the thread-local SIM instance with Milenage authentication.
///
/// Creates a new `Sim<MilenageParams, 256>` with the given ATR and MF tree,
/// configured with the provided Milenage parameters. Must be called before
/// any other `hle_*` function.
///
/// Calling this (or [`hle_init_tuak`]) again replaces the previous instance.
pub fn hle_init(
    atr: &'static [u8],
    mf: &'static DfDef,
    ki: GsmSubscriberKey,
    k: [u8; 16],
    opc: [u8; 16],
) {
    SIM.with(|cell| {
        let mil =
            MilenageParams::with_defaults(SubscriberKey::classify(k), MilOp::operator_cipher(opc));
        let gsm = simrs_gsm::GsmApp::new(mf, ki);
        let usim = simrs_usim::UsimApp::new(mf, &[], mil);
        let sim = Sim::<MilenageParams, 256>::new(atr, gsm, usim);
        *cell.borrow_mut() = Some(SimInstance::Milenage(sim));
    });
}

/// Initialize the thread-local SIM instance with TUAK authentication.
///
/// `k` is the 128-bit subscriber key K.
/// `topc` is the 256-bit `TOPc` (derived operator variant).
///
/// Calling this (or [`hle_init`]) again replaces the previous instance.
pub fn hle_init_tuak(
    atr: &'static [u8],
    mf: &'static DfDef,
    ki: GsmSubscriberKey,
    k: [u8; 16],
    topc: [u8; 32],
) {
    SIM.with(|cell| {
        let tuak = TuakParams::new(SubscriberKey::classify(k), TuakOp::operator_cipher(topc));
        let gsm = simrs_gsm::GsmApp::new(mf, ki);
        let usim = simrs_usim::UsimApp::new(mf, &[], tuak);
        let sim = Sim::<TuakParams, 256>::new(atr, gsm, usim);
        *cell.borrow_mut() = Some(SimInstance::Tuak(sim));
    });
}

/// Initialize with Milenage authentication and a custom ADF table.
///
/// Like [`hle_init`] but allows passing an ADF table for application
/// selection by AID. The `adf_table` entries map AIDs to their root DFs.
pub fn hle_init_with_adf(
    atr: &'static [u8],
    mf: &'static DfDef,
    ki: GsmSubscriberKey,
    k: [u8; 16],
    opc: [u8; 16],
    adf_table: &'static [AdfSlot],
) {
    SIM.with(|cell| {
        let mil =
            MilenageParams::with_defaults(SubscriberKey::classify(k), MilOp::operator_cipher(opc));
        let gsm = simrs_gsm::GsmApp::new(mf, ki);
        let usim = simrs_usim::UsimApp::new(mf, adf_table, mil);
        let sim = Sim::<MilenageParams, 256>::new(atr, gsm, usim);
        *cell.borrow_mut() = Some(SimInstance::Milenage(sim));
    });
}

/// Initialize with TUAK authentication and a custom ADF table.
///
/// Like [`hle_init_tuak`] but allows passing an ADF table for application
/// selection by AID.
pub fn hle_init_tuak_with_adf(
    atr: &'static [u8],
    mf: &'static DfDef,
    ki: GsmSubscriberKey,
    k: [u8; 16],
    topc: [u8; 32],
    adf_table: &'static [AdfSlot],
) {
    SIM.with(|cell| {
        let tuak = TuakParams::new(SubscriberKey::classify(k), TuakOp::operator_cipher(topc));
        let gsm = simrs_gsm::GsmApp::new(mf, ki);
        let usim = simrs_usim::UsimApp::new(mf, adf_table, tuak);
        let sim = Sim::<TuakParams, 256>::new(atr, gsm, usim);
        *cell.borrow_mut() = Some(SimInstance::Tuak(sim));
    });
}

/// Initialize the thread-local SIM as a `GlobalPlatform` card with a SIM applet.
///
/// Creates a `GpCard<261>` with an ISD key set and a Milenage-based SIM
/// applet registered at the USIM AID. The card supports both GP card
/// management (SELECT ISD, INITIALIZE UPDATE, etc.) and SIM/USIM
/// operations (SELECT USIM AID, then standard 3GPP APDUs).
///
/// Calling this (or any other `hle_init*` function) replaces the previous instance.
#[allow(clippy::too_many_arguments)]
pub fn hle_init_gp(
    atr: &'static [u8],
    isd_enc: [u8; 16],
    isd_mac: [u8; 16],
    isd_dek: [u8; 16],
    mf: &'static DfDef,
    adfs: &'static [AdfSlot],
    ki: [u8; 16],
    k: [u8; 16],
    opc: [u8; 16],
) {
    let isd_keys = KeySet::des3_2key(isd_enc, isd_mac, isd_dek);
    let mil =
        MilenageParams::with_defaults(SubscriberKey::classify(k), MilOp::operator_cipher(opc));
    let gsm = simrs_gsm::GsmApp::new(mf, GsmSubscriberKey::classify(ki));
    let sim_applet = SimApplet::with_gsm(mf, adfs, mil, gsm);
    let card = GpCard::with_sim(atr, &isd_keys, sim_applet);
    SIM.with(|cell| {
        *cell.borrow_mut() = Some(SimInstance::GpMilenage(card));
    });
}

/// Initialize the thread-local SIM from a parsed [`ProfileConfig`].
///
/// Dispatches to [`hle_init_with_adf`] or [`hle_init_tuak_with_adf`]
/// based on the authentication algorithm in the profile. The subscriber key for
/// the GSM app layer is derived from the first 16 bytes of the auth key.
///
/// If the profile has `AuthConfig::None`, a zeroed Milenage configuration
/// is used as a fallback.
pub fn hle_init_from_profile(config: &ProfileConfig) {
    match &config.auth {
        AuthConfig::Milenage { k, opc } => {
            hle_init_with_adf(
                config.atr,
                config.mf,
                GsmSubscriberKey::classify(*k),
                *k,
                *opc,
                config.adf_table,
            );
        }
        AuthConfig::Tuak { k, topc } => {
            hle_init_tuak_with_adf(
                config.atr,
                config.mf,
                GsmSubscriberKey::classify(*k),
                *k,
                *topc,
                config.adf_table,
            );
        }
        AuthConfig::None => {
            // No auth parameters -- use zeroed Milenage as fallback.
            hle_init_with_adf(
                config.atr,
                config.mf,
                GsmSubscriberKey::classify([0u8; 16]),
                [0u8; 16],
                [0u8; 16],
                config.adf_table,
            );
        }
    }
}

/// Reset the SIM to power-on state.
///
/// Sends a `PowerOn` event. Returns the ATR length, or 0 if not initialized.
pub fn hle_reset() -> usize {
    with_sim!(0, |sim| {
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
    with_sim!(None, |sim| {
        match sim.process(SimEvent::Apdu(cmd)) {
            SimResponse::Apdu { data, sw } => {
                let [sw1, sw2] = sw.to_bytes();
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
/// The first byte is a discriminant (0x00 = Milenage, 0x01 = TUAK,
/// 0x02 = GP+Milenage), followed by the card snapshot data.
///
/// Returns the number of bytes written (including discriminant), or 0 if
/// not initialized or `buf` is too small.
pub fn hle_snapshot_save(buf: &mut [u8]) -> usize {
    SIM.with(|cell| {
        let mut borrow = cell.borrow_mut();
        match borrow.as_mut() {
            Some(SimInstance::Milenage(sim)) => {
                if buf.len() < 1 + Sim::<MilenageParams, 256>::SNAPSHOT_SIZE {
                    return 0;
                }
                buf[0] = 0x00; // Milenage discriminant
                let n = sim.save_state(&mut buf[1..]);
                if n == 0 {
                    0
                } else {
                    1 + n
                }
            }
            Some(SimInstance::Tuak(sim)) => {
                if buf.len() < 1 + Sim::<TuakParams, 256>::SNAPSHOT_SIZE {
                    return 0;
                }
                buf[0] = 0x01; // TUAK discriminant
                let n = sim.save_state(&mut buf[1..]);
                if n == 0 {
                    0
                } else {
                    1 + n
                }
            }
            Some(SimInstance::GpMilenage(card)) => {
                if buf.len() < 1 + GpCard::<261>::SNAPSHOT_SIZE {
                    return 0;
                }
                buf[0] = 0x02; // GP+Milenage discriminant
                let n = card.save_state(&mut buf[1..]);
                if n == 0 {
                    0
                } else {
                    1 + n
                }
            }
            None => 0,
        }
    })
}

/// Restore the SIM state from `buf`.
///
/// The first byte must match the discriminant of the current instance
/// (0x00 = Milenage, 0x01 = TUAK, 0x02 = GP+Milenage). Returns `true`
/// on success, `false` if the buffer is empty, discriminant mismatches,
/// or the SIM is not initialized.
pub fn hle_snapshot_restore(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    SIM.with(|cell| {
        let mut borrow = cell.borrow_mut();
        match (buf[0], borrow.as_mut()) {
            (0x00, Some(SimInstance::Milenage(sim))) => sim.restore_state(&buf[1..]),
            (0x01, Some(SimInstance::Tuak(sim))) => sim.restore_state(&buf[1..]),
            (0x02, Some(SimInstance::GpMilenage(card))) => card.restore_state(&buf[1..]),
            _ => false, // discriminant mismatch or not initialized
        }
    })
}

/// Return the maximum snapshot buffer size required (across all algorithms).
///
/// Includes the 1-byte discriminant.
pub const fn hle_snapshot_size() -> usize {
    MAX_SNAPSHOT_SIZE
}

/// Return the exact snapshot size for the currently initialized algorithm.
///
/// Returns 0 if not initialized.
pub fn hle_snapshot_size_current() -> usize {
    SIM.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some(SimInstance::Milenage(_)) => 1 + Sim::<MilenageParams, 256>::SNAPSHOT_SIZE,
            Some(SimInstance::Tuak(_)) => 1 + Sim::<TuakParams, 256>::SNAPSHOT_SIZE,
            Some(SimInstance::GpMilenage(_)) => 1 + GpCard::<261>::SNAPSHOT_SIZE,
            None => 0,
        }
    })
}

/// Advance UICC-side proactive timers by `elapsed_secs`.
///
/// Returns a bitmask of expired timer IDs (bit 0 = timer 1, ..., bit 7 = timer 8),
/// or 0 if not initialized or no timers expired.
///
/// GP cards do not support proactive timers; `Tick` is forwarded but
/// always returns 0 for the `GpMilenage` variant.
pub fn hle_tick(elapsed_secs: u32) -> u8 {
    SIM.with(|cell| {
        let mut borrow = cell.borrow_mut();
        match borrow.as_mut() {
            Some(SimInstance::Milenage(sim)) => tick_sim(sim, elapsed_secs),
            Some(SimInstance::Tuak(sim)) => tick_sim(sim, elapsed_secs),
            Some(SimInstance::GpMilenage(card)) => {
                // GP card has no proactive timers; just forward Tick.
                let _ = card.process(SimEvent::Tick(elapsed_secs));
                0
            }
            None => 0,
        }
    })
}

/// Shared tick logic for `Sim<A, N>` variants.
fn tick_sim<A: simrs_milenage::AuthenticationAlgorithm, const N: usize>(
    sim: &mut Sim<A, N>,
    elapsed_secs: u32,
) -> u8 {
    let _ = sim.process(SimEvent::Tick(elapsed_secs));
    let mut mask: u8 = 0;
    loop {
        let id = sim.usim_app_mut().proactive_state().take_expired_timer();
        if id == 0 {
            break;
        }
        // Timer IDs are 1..=8, map to bits 0..=7.
        if id <= 8 {
            mask |= 1 << (id - 1);
        }
    }
    mask
}

/// Compute an FNV-1a deduplication hash of the current SIM state.
///
/// Returns 0 if the SIM is not initialized.
pub fn hle_state_hash() -> u64 {
    with_sim!(0, |sim| sim.state_hash())
}

// ---------------------------------------------------------------------------
// Convenience defaults for export crates
// ---------------------------------------------------------------------------

/// Standard reference ATR.
///
/// This 4-byte ATR is intentionally compact. It works reliably with
/// firmware SIM drivers that treat ATR as opaque bytes rather than
/// parsing the ISO/IEC 7816-3 T0/TA1/historical structure.
pub static DEFAULT_ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

/// Initialize the SIM with the standard USIM profile and Milenage auth.
///
/// Uses [`DEFAULT_ATR`], the reference MF filesystem, and the full ADF table.
/// This is the common init path shared by all export crates (C, Rust, Python).
pub fn hle_init_standard(ki: [u8; 16], k: [u8; 16], opc: [u8; 16]) {
    hle_init_with_adf(
        &DEFAULT_ATR,
        &simrs_usim::profile::REFERENCE_MF,
        GsmSubscriberKey::classify(ki),
        k,
        opc,
        &simrs_usim::profile::ADF_TABLE,
    );
}

/// Initialize the SIM from a TCA eUICC profile DER.
///
/// # Errors
///
/// Returns `Err(ProfileError)` if the DER is malformed or missing required PEs.
pub fn hle_init_standard_profile(der: &[u8]) -> Result<(), simrs_profile::ProfileError> {
    let config = simrs_profile::load_profile(der)?;
    hle_init_from_profile(&config);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_fs::{AdfSlot, EfDef, Fid, FileRef};

    static EF_ICCID: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        None,
        &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
    );

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static ATR: [u8; 2] = [0x3B, 0x00];

    fn init() {
        hle_init(
            &ATR,
            &MF,
            GsmSubscriberKey::classify([0x11; 16]),
            [0x22; 16],
            [0x33; 16],
        );
    }

    fn init_tuak() {
        hle_init_tuak(
            &ATR,
            &MF,
            GsmSubscriberKey::classify([0x11; 16]),
            [0x22; 16],
            [0x33; 32],
        );
    }

    // -------------------------------------------------------------------
    // Existing Milenage tests (unchanged behavior)
    // -------------------------------------------------------------------

    #[test]
    fn reset_before_init_returns_zero() {
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
        assert!(n > 0, "snapshot save must succeed");
        assert_eq!(n, hle_snapshot_size_current());

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
        let mut buf = [0u8; 4096];
        assert_eq!(hle_snapshot_save(&mut buf), 0);
    }

    #[test]
    fn state_hash_without_init_returns_zero() {
        SIM.with(|cell| *cell.borrow_mut() = None);
        assert_eq!(hle_state_hash(), 0);
    }

    #[test]
    fn state_hash_changes_after_apdu() {
        init();
        hle_reset();
        let h1 = hle_state_hash();
        assert_ne!(h1, 0, "hash should be nonzero after init");

        let mut rsp = [0u8; 256];
        hle_apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp);
        let h2 = hle_state_hash();
        assert_ne!(h1, h2, "hash should change after SELECT MF");
    }

    #[test]
    fn hle_tick_without_init_returns_zero() {
        SIM.with(|cell| *cell.borrow_mut() = None);
        assert_eq!(hle_tick(10), 0);
    }

    #[test]
    fn hle_tick_with_no_timers_returns_zero() {
        init();
        hle_reset();
        assert_eq!(hle_tick(10), 0);
    }

    #[test]
    fn hle_tick_expires_timer_returns_bitmask() {
        init();
        hle_reset();
        // Start timer 1 with BCD [0x00, 0x00, 0x10] = 10 seconds.
        SIM.with(|cell| {
            let mut borrow = cell.borrow_mut();
            if let Some(SimInstance::Milenage(sim)) = borrow.as_mut() {
                assert!(sim
                    .usim_app_mut()
                    .proactive_state()
                    .start_timer(1, [0x00, 0x00, 0x10]));
            } else {
                panic!("expected Milenage instance");
            }
        });
        // Tick 11 seconds -- timer 1 should expire.
        let mask = hle_tick(11);
        assert_eq!(mask, 1, "bit 0 should be set for timer 1");
    }

    #[test]
    fn hle_tick_multiple_timers_combined_mask() {
        init();
        hle_reset();
        // Start timers 1 and 3 with BCD [0x00, 0x00, 0x05] = 5 seconds.
        SIM.with(|cell| {
            let mut borrow = cell.borrow_mut();
            if let Some(SimInstance::Milenage(sim)) = borrow.as_mut() {
                let ps = sim.usim_app_mut().proactive_state();
                assert!(ps.start_timer(1, [0x00, 0x00, 0x05]));
                assert!(ps.start_timer(3, [0x00, 0x00, 0x05]));
            } else {
                panic!("expected Milenage instance");
            }
        });
        // Tick 6 seconds -- both timers should expire.
        let mask = hle_tick(6);
        assert_eq!(
            mask, 0b0000_0101,
            "bits 0 and 2 should be set for timers 1 and 3"
        );
    }

    // -------------------------------------------------------------------
    // TUAK-specific tests
    // -------------------------------------------------------------------

    #[test]
    fn hle_init_tuak_basic() {
        init_tuak();
        let atr_len = hle_reset();
        assert_eq!(
            atr_len,
            ATR.len(),
            "TUAK sim should reset with correct ATR length"
        );
    }

    #[test]
    fn hle_apdu_with_tuak() {
        init_tuak();
        hle_reset();
        let mut rsp = [0u8; 256];
        let result = hle_apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp);
        let (_, sw1, _) = result.expect("SELECT MF APDU should succeed with TUAK");
        assert_eq!(sw1, 0x61);
    }

    #[test]
    fn hle_snapshot_tuak_roundtrip() {
        init_tuak();
        hle_reset();
        let mut rsp = [0u8; 256];
        hle_apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp);

        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert!(n > 0, "TUAK snapshot save must succeed");
        assert_eq!(n, hle_snapshot_size_current());

        // Re-init with TUAK (wipes state).
        init_tuak();
        assert!(hle_snapshot_restore(&snap[..n]));

        // Card should be Ready after restore.
        let result = hle_apdu(&[0xF0, 0xA4, 0x00, 0x00], &mut rsp);
        let (_, sw1, sw2) = result.expect("should get APDU response after TUAK restore");
        assert_eq!((sw1, sw2), (0x6E, 0x00));
    }

    #[test]
    fn hle_tick_with_tuak() {
        init_tuak();
        hle_reset();
        // No timers running -> should return 0.
        assert_eq!(hle_tick(10), 0);
    }

    #[test]
    fn hle_state_hash_tuak() {
        init_tuak();
        hle_reset();
        let h = hle_state_hash();
        assert_ne!(h, 0, "TUAK hash should be nonzero after init+reset");
    }

    #[test]
    fn hle_reset_tuak() {
        init_tuak();
        // Reset twice should work.
        let len1 = hle_reset();
        let len2 = hle_reset();
        assert_eq!(len1, ATR.len());
        assert_eq!(len2, ATR.len());
    }

    #[test]
    fn hle_snapshot_discriminant_milenage() {
        init();
        hle_reset();
        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert!(n > 0);
        assert_eq!(snap[0], 0x00, "Milenage discriminant must be 0x00");
    }

    #[test]
    fn hle_snapshot_discriminant_tuak() {
        init_tuak();
        hle_reset();
        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert!(n > 0);
        assert_eq!(snap[0], 0x01, "TUAK discriminant must be 0x01");
    }

    #[test]
    fn hle_snapshot_cross_algorithm_restore_fails() {
        // Init with Milenage, save snapshot.
        init();
        hle_reset();
        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert!(n > 0);

        // Switch to TUAK, try to restore Milenage snapshot -> must fail.
        init_tuak();
        assert!(
            !hle_snapshot_restore(&snap[..n]),
            "restoring Milenage snapshot into TUAK instance must fail"
        );
    }

    // -------------------------------------------------------------------
    // ADF table passthrough tests
    // -------------------------------------------------------------------

    static ADF_ROOT: DfDef = DfDef {
        fid: Fid::new(0xFF01),
        children: &[],
    };

    static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

    static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
        aid: &USIM_AID,
        root: &ADF_ROOT,
    }];

    #[test]
    fn hle_init_with_adf_table() {
        hle_init_with_adf(
            &ATR,
            &MF,
            GsmSubscriberKey::classify([0x11; 16]),
            [0x22; 16],
            [0x33; 16],
            &ADF_TABLE,
        );
        hle_reset();
        let mut rsp = [0u8; 256];
        // SELECT by AID: 00 A4 04 00 07 [AID] 00
        let mut cmd = [0u8; 4 + 1 + 7 + 1];
        cmd[0] = 0x00; // CLA
        cmd[1] = 0xA4; // INS SELECT
        cmd[2] = 0x04; // P1 select by AID
        cmd[3] = 0x00; // P2
        cmd[4] = 0x07; // Lc
        cmd[5..12].copy_from_slice(&USIM_AID);
        cmd[12] = 0x00; // Le
        let result = hle_apdu(&cmd, &mut rsp);
        let (_, sw1, _) = result.expect("SELECT by AID should succeed with ADF table");
        // 0x61 = bytes available (FCP queued for GET RESPONSE)
        assert_eq!(
            sw1, 0x61,
            "SELECT by AID should return 61 XX with ADF table"
        );
    }

    #[test]
    fn hle_init_default_no_adf() {
        // Standard init passes empty ADF table; SELECT by AID should fail.
        init();
        hle_reset();
        let mut rsp = [0u8; 256];
        let mut cmd = [0u8; 4 + 1 + 7 + 1];
        cmd[0] = 0x00;
        cmd[1] = 0xA4;
        cmd[2] = 0x04;
        cmd[3] = 0x00;
        cmd[4] = 0x07;
        cmd[5..12].copy_from_slice(&USIM_AID);
        cmd[12] = 0x00;
        let result = hle_apdu(&cmd, &mut rsp);
        let (_, sw1, sw2) = result.expect("should get response");
        // 6A 82 = file/application not found
        assert_eq!(
            (sw1, sw2),
            (0x6A, 0x82),
            "SELECT by AID with no ADF table should return file not found"
        );
    }

    // -------------------------------------------------------------------
    // GP card (GpMilenage) tests
    // -------------------------------------------------------------------

    static GP_ATR: [u8; 3] = [0x3B, 0x90, 0x00];

    fn init_gp() {
        hle_init_gp(
            &GP_ATR, [0x40; 16], // ISD ENC
            [0x40; 16], // ISD MAC
            [0x40; 16], // ISD DEK
            &MF, &ADF_TABLE, [0x11; 16], // Ki
            [0x22; 16], // K
            [0x33; 16], // OPc
        );
    }

    #[test]
    fn hle_init_gp_creates_instance() {
        init_gp();
        // Verify the instance is present by checking snapshot size is nonzero.
        assert!(hle_snapshot_size_current() > 0);
    }

    #[test]
    fn hle_reset_gp_returns_atr() {
        init_gp();
        let atr_len = hle_reset();
        assert_eq!(atr_len, GP_ATR.len());
    }

    #[test]
    fn hle_apdu_gp_select_isd() {
        init_gp();
        hle_reset();
        let mut rsp = [0u8; 261];
        // SELECT ISD by AID: 00 A4 04 00 07 A0 00 00 01 51 00 00
        let isd_aid: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];
        let mut cmd = [0u8; 12];
        cmd[0] = 0x00; // CLA
        cmd[1] = 0xA4; // INS SELECT
        cmd[2] = 0x04; // P1 select by name
        cmd[3] = 0x00; // P2
        cmd[4] = 0x07; // Lc
        cmd[5..12].copy_from_slice(&isd_aid);
        let result = hle_apdu(&cmd, &mut rsp);
        let (_, sw1, sw2) = result.expect("SELECT ISD should succeed on GP card");
        assert_eq!((sw1, sw2), (0x90, 0x00), "SELECT ISD should return 90 00");
    }

    #[test]
    fn hle_snapshot_gp_roundtrip() {
        init_gp();
        hle_reset();
        // Issue an APDU to change state.
        let mut rsp = [0u8; 261];
        let isd_aid: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];
        let mut cmd = [0u8; 12];
        cmd[0] = 0x00;
        cmd[1] = 0xA4;
        cmd[2] = 0x04;
        cmd[3] = 0x00;
        cmd[4] = 0x07;
        cmd[5..12].copy_from_slice(&isd_aid);
        hle_apdu(&cmd, &mut rsp);

        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert!(n > 0, "GP snapshot save must succeed");
        assert_eq!(n, hle_snapshot_size_current());

        // Re-init (wipes state).
        init_gp();
        assert!(hle_snapshot_restore(&snap[..n]));

        // Card should be ready after restore.
        let result = hle_apdu(&cmd, &mut rsp);
        let (_, sw1, sw2) = result.expect("should get APDU response after GP restore");
        assert_eq!(
            (sw1, sw2),
            (0x90, 0x00),
            "SELECT ISD should still work after restore"
        );
    }

    #[test]
    fn hle_snapshot_discriminant_gp() {
        init_gp();
        hle_reset();
        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert!(n > 0);
        assert_eq!(snap[0], 0x02, "GP discriminant must be 0x02");
    }

    #[test]
    fn hle_snapshot_cross_gp_restore_fails() {
        // Init with GP, save snapshot.
        init_gp();
        hle_reset();
        let mut snap = vec![0u8; hle_snapshot_size()];
        let n = hle_snapshot_save(&mut snap);
        assert!(n > 0);

        // Switch to Milenage, try to restore GP snapshot -> must fail.
        init();
        assert!(
            !hle_snapshot_restore(&snap[..n]),
            "restoring GP snapshot into Milenage instance must fail"
        );
    }

    #[test]
    fn hle_state_hash_gp() {
        init_gp();
        hle_reset();
        let h = hle_state_hash();
        assert_ne!(h, 0, "GP hash should be nonzero after init+reset");
    }

    #[test]
    fn hle_state_hash_gp_differs_before_and_after_power_on() {
        init_gp();
        // Before power-on: card state is Off.
        let h_off = hle_state_hash();
        assert_ne!(h_off, 0, "GP hash should be nonzero even when off");
        // After power-on: card state is Ready.
        hle_reset();
        let h_on = hle_state_hash();
        assert_ne!(
            h_off, h_on,
            "GP hash should differ between Off and Ready states"
        );
    }

    #[test]
    fn hle_tick_gp_returns_zero() {
        init_gp();
        hle_reset();
        // GP card has no proactive timers; tick should always return 0.
        assert_eq!(hle_tick(10), 0);
    }
}
