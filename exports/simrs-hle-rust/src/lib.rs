//! LGPL-licensed Rust API for the SimRS smart card simulator.
//!
//! This crate provides the same API surface as the C bindings
//! ([`simrs-hle-capi`](../simrs-hle-capi/)) but as safe Rust, enabling
//! use from proprietary Rust applications under LGPL-2.0-or-later.
//!
//! # Thread Safety
//!
//! Each OS thread gets its own independent SIM instance via thread-local
//! storage. All calls for a given SIM session must happen on the same thread.

/// Initialize the SIM with Milenage authentication.
///
/// `ki`, `k`, `opc` must each be exactly 16 bytes.
/// Uses the standard USIM profile filesystem and reference ATR.
pub fn init(ki: [u8; 16], k: [u8; 16], opc: [u8; 16]) {
    simrs_hle::hle_init_standard(ki, k, opc);
}

/// Initialize the SIM from a TCA eUICC Profile Package (DER-encoded).
///
/// Returns `true` on success, `false` on failure (malformed DER, missing PEs).
pub fn init_profile(der: &[u8]) -> bool {
    simrs_hle::hle_init_standard_profile(der).is_ok()
}

/// Power-on reset. Returns the ATR bytes, or `None` if not initialized.
pub fn reset() -> Option<&'static [u8]> {
    let len = simrs_hle::hle_reset();
    if len == 0 {
        None
    } else {
        Some(&simrs_hle::DEFAULT_ATR[..len])
    }
}

/// Process one APDU command.
///
/// Returns `Some((data, sw1, sw2))` on success, `None` if not initialized.
/// `data` is a slice of the response buffer containing the response data.
pub fn apdu<'a>(cmd: &[u8], rsp: &'a mut [u8]) -> Option<(&'a [u8], u8, u8)> {
    simrs_hle::hle_apdu(cmd, rsp).map(|(n, sw1, sw2)| (&rsp[..n], sw1, sw2))
}

/// Save the current SIM state to a buffer.
///
/// Returns the number of bytes written, or 0 on error.
/// Use [`snapshot_size`] to determine the required buffer size.
pub fn snapshot_save(buf: &mut [u8]) -> usize {
    simrs_hle::hle_snapshot_save(buf)
}

/// Restore SIM state from a buffer.
///
/// The SIM must have been initialized with the same algorithm
/// (Milenage/TUAK) as when the snapshot was saved.
///
/// Returns `true` on success, `false` on failure.
pub fn snapshot_restore(buf: &[u8]) -> bool {
    simrs_hle::hle_snapshot_restore(buf)
}

/// Maximum snapshot buffer size required (constant).
pub const fn snapshot_size() -> usize {
    simrs_hle::hle_snapshot_size()
}

/// FNV-1a hash of the current SIM state. Returns 0 if not initialized.
pub fn state_hash() -> u64 {
    simrs_hle::hle_state_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_reset_apdu_roundtrip() {
        init([0u8; 16], [0u8; 16], [0u8; 16]);
        let atr = reset().expect("reset should return ATR");
        assert_eq!(atr[0], 0x3B);

        let mut rsp = [0u8; 258];
        let (_, sw1, _) = apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp)
            .expect("SELECT MF should succeed");
        assert_eq!(sw1, 0x61);
    }

    #[test]
    fn snapshot_roundtrip() {
        init([0u8; 16], [0u8; 16], [0u8; 16]);
        reset();
        let mut rsp = [0u8; 258];
        apdu(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp);

        let mut snap = vec![0u8; snapshot_size()];
        let n = snapshot_save(&mut snap);
        assert!(n > 0);

        let h1 = state_hash();
        init([0u8; 16], [0u8; 16], [0u8; 16]);
        reset();
        assert!(snapshot_restore(&snap[..n]));
        assert_eq!(state_hash(), h1);
    }

    #[test]
    fn bad_profile_returns_false() {
        assert!(!init_profile(&[0xFF; 8]));
    }
}
