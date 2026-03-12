//! Deterministic SIM state serialization for snapshot-based fuzzing.
//!
//! Provides the [`Snapshot`] trait with `save()` and `restore()` methods for
//! complete, byte-exact SIM state capture. The [`Sim`] type
//! implements this trait via delegation to its internal `save_state`/`restore_state`
//! methods.
//!
//! The serialized blob is stored alongside QEMU VM snapshots to ensure the
//! SIM state and guest CPU/memory state are always synchronized.
//!
//! # Determinism guarantees
//! - No timestamps, RNG output, or platform-specific data included
//! - Fixed-size serialization format (no dynamic allocation in save/restore)
//! - Identical blob across platforms for the same logical state
//!
//! # `no_std`
//! Core trait and serialization logic are `no_std`.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

use simrs_milenage::AuthenticationAlgorithm;
use simrs_sim::Sim;

/// Deterministic state serialization trait for snapshot-based fuzzing.
///
/// Implementors must produce byte-exact, platform-independent snapshots.
/// The `SIZE` associated constant declares the fixed buffer size required.
pub trait Snapshot {
    /// Fixed snapshot buffer size in bytes.
    const SIZE: usize;

    /// Serialize the current state into `buf`.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    fn save(&self, buf: &mut [u8]) -> usize;

    /// Restore state from `buf`.
    ///
    /// Returns `true` on success, `false` if the buffer is too small or
    /// contains invalid data.
    fn restore(&mut self, buf: &[u8]) -> bool;
}

impl<A: AuthenticationAlgorithm, const RSP_CAP: usize> Snapshot for Sim<A, RSP_CAP> {
    const SIZE: usize = Self::SNAPSHOT_SIZE;

    fn save(&self, buf: &mut [u8]) -> usize {
        self.save_state(buf)
    }

    fn restore(&mut self, buf: &[u8]) -> bool {
        self.restore_state(buf)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_sim::{SimEvent, SimResponse};
    use simrs_fs::{DfDef, Fid};
    use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};

    static MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[],
    };

    static ATR: [u8; 2] = [0x3B, 0x00];

    fn make_sim() -> Sim<MilenageParams, 256> {
        let gsm = simrs_gsm::GsmApp::new(&MF, simrs_gsm::Ki::new(simrs_secret::Secret::new([0u8; 16])));
        let mil = MilenageParams::with_defaults(SubscriberKey::new(simrs_secret::Secret::new([0u8; 16])), OperatorVariant::opc(simrs_secret::Secret::new([0u8; 16])));
        let usim = simrs_usim::UsimApp::new(&MF, &[], mil);
        Sim::<MilenageParams, 256>::new(&ATR, gsm, usim)
    }

    #[test]
    fn trait_size_matches_struct_const() {
        assert_eq!(
            <Sim<MilenageParams, 256> as Snapshot>::SIZE,
            Sim::<MilenageParams, 256>::SNAPSHOT_SIZE,
        );
    }

    #[test]
    fn trait_save_restore_roundtrip() {
        let mut sim = make_sim();
        let _ = sim.process(SimEvent::PowerOn);

        let mut buf = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let n = Snapshot::save(&sim, &mut buf);
        assert_eq!(n, <Sim<MilenageParams, 256> as Snapshot>::SIZE);

        let mut restored = make_sim();
        assert!(Snapshot::restore(&mut restored, &buf[..n]));

        // Card should be Ready after restore.
        let rsp = restored.process(SimEvent::Apdu(&[0xF0, 0xA4, 0x00, 0x00]));
        match rsp {
            SimResponse::Apdu { sw, .. } => {
                assert_eq!(sw.to_bytes(), [0x6E, 0x00]);
            }
            _ => panic!("expected Apdu, card should be Ready"),
        }
    }

    #[test]
    fn trait_save_small_buffer_returns_zero() {
        let sim = make_sim();
        let mut small = [0u8; 0];
        assert_eq!(Snapshot::save(&sim, &mut small), 0);
    }

    #[test]
    fn trait_restore_small_buffer_returns_false() {
        let mut sim = make_sim();
        assert!(!Snapshot::restore(&mut sim, &[]));
    }

    #[test]
    fn trait_restore_invalid_data_returns_false() {
        let mut sim = make_sim();
        let mut buf = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let n = Snapshot::save(&sim, &mut buf);
        buf[0] = 0xFF; // invalid card state
        assert!(!Snapshot::restore(&mut sim, &buf[..n]));
    }

    #[test]
    fn different_rsp_cap_sizes() {
        // Verify the trait works with a different RSP_CAP.
        let gsm1 = simrs_gsm::GsmApp::new(&MF, simrs_gsm::Ki::new(simrs_secret::Secret::new([0u8; 16])));
        let mil1 = MilenageParams::with_defaults(SubscriberKey::new(simrs_secret::Secret::new([0u8; 16])), OperatorVariant::opc(simrs_secret::Secret::new([0u8; 16])));
        let usim1 = simrs_usim::UsimApp::new(&MF, &[], mil1);
        let sim_small = Sim::<MilenageParams, 64>::new(&ATR, gsm1, usim1);

        let gsm2 = simrs_gsm::GsmApp::new(&MF, simrs_gsm::Ki::new(simrs_secret::Secret::new([0u8; 16])));
        let mil2 = MilenageParams::with_defaults(SubscriberKey::new(simrs_secret::Secret::new([0u8; 16])), OperatorVariant::opc(simrs_secret::Secret::new([0u8; 16])));
        let usim2 = simrs_usim::UsimApp::new(&MF, &[], mil2);
        let sim_large = Sim::<MilenageParams, 512>::new(&ATR, gsm2, usim2);

        // SNAPSHOT_SIZE should be identical (RSP_CAP is transient, not serialized).
        assert_eq!(
            <Sim<MilenageParams, 64> as Snapshot>::SIZE,
            <Sim<MilenageParams, 512> as Snapshot>::SIZE,
        );

        let mut buf1 = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let mut buf2 = [0u8; Sim::<MilenageParams, 256>::SNAPSHOT_SIZE];
        let n1 = Snapshot::save(&sim_small, &mut buf1);
        let n2 = Snapshot::save(&sim_large, &mut buf2);
        assert_eq!(n1, n2);
        assert_eq!(&buf1[..n1], &buf2[..n2]);
    }

    #[test]
    fn state_hash_via_sim() {
        let mut sim = make_sim();
        let h1 = sim.state_hash();
        let _ = sim.process(SimEvent::PowerOn);
        let h2 = sim.state_hash();
        assert_ne!(h1, h2);
    }
}
