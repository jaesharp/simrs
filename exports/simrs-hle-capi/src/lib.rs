//! C-ABI wrapper for simrs-hle.
//!
//! Provides `extern "C"` functions that can be loaded via `ctypes.CDLL` from
//! Python (FirmWire's SimrsPeripheral) or any C/C++ host.
//!
//! This crate lives outside the simrs workspace because the workspace enforces
//! `unsafe_code = "forbid"`, and C-ABI exports require raw pointer dereference.
//!
//! # Thread safety
//!
//! simrs-hle uses thread-local storage internally. Each OS thread gets its own
//! independent SIM instance. The caller must ensure that all calls for a given
//! SIM session happen on the same thread (which is the natural case for QEMU's
//! single-threaded vCPU loop).

use std::cell::Cell;

// Thread-local ATR pointer/length. Defaults to the module-level `ATR` static
// but is overridden when a profile with its own ATR is loaded via
// `simrs_init_profile`.
//
// Both the default `ATR` static and the `ProfileConfig.atr` field are
// `&'static [u8]`, so the raw pointer remains valid for the thread's lifetime.
thread_local! {
    static CURRENT_ATR: Cell<(*const u8, usize)> = const {
        Cell::new((simrs_hle::DEFAULT_ATR.as_ptr(), simrs_hle::DEFAULT_ATR.len()))
    };
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initialize the SIM with Milenage authentication.
///
/// `ki`, `k`, `opc` must each point to exactly 16 bytes.
/// Uses the standard USIM profile filesystem and reference ATR.
///
/// # Safety
///
/// All three pointers must be valid, aligned, and point to at least 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn simrs_init(
    ki: *const u8,
    k: *const u8,
    opc: *const u8,
) {
    let ki_arr: [u8; 16] = core::slice::from_raw_parts(ki, 16).try_into().unwrap();
    let k_arr: [u8; 16] = core::slice::from_raw_parts(k, 16).try_into().unwrap();
    let opc_arr: [u8; 16] = core::slice::from_raw_parts(opc, 16).try_into().unwrap();

    CURRENT_ATR.set((simrs_hle::DEFAULT_ATR.as_ptr(), simrs_hle::DEFAULT_ATR.len()));
    simrs_hle::hle_init_standard(ki_arr, k_arr, opc_arr);
}

/// Initialize the SIM from a TCA eUICC Profile Package (DER-encoded).
///
/// Parses the profile, extracts auth parameters, builds the filesystem tree,
/// and configures the HLE SIM accordingly. The profile's own ATR is stored
/// for use by subsequent `simrs_reset` calls.
///
/// Returns 1 on success, 0 on failure (malformed DER, missing PEs, etc.).
///
/// # Safety
///
/// `der_ptr` must point to at least `der_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn simrs_init_profile(
    der_ptr: *const u8,
    der_len: u32,
) -> u32 {
    let der_bytes = core::slice::from_raw_parts(der_ptr, der_len as usize);
    let config = match simrs_profile::load_profile(der_bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    CURRENT_ATR.set((config.atr.as_ptr(), config.atr.len()));
    simrs_hle::hle_init_from_profile(&config);
    1
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

/// Power-on reset. Writes ATR bytes to `atr_buf` and returns ATR length.
///
/// Returns 0 if SIM is not initialized or `atr_buf_len` is too small.
///
/// # Safety
///
/// `atr_buf` must point to at least `atr_buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn simrs_reset(
    atr_buf: *mut u8,
    atr_buf_len: u32,
) -> u32 {
    let atr_len = simrs_hle::hle_reset();
    if atr_len == 0 {
        return 0;
    }
    // Read ATR pointer and length from the thread-local set at init time.
    let (atr_ptr, atr_sz) = CURRENT_ATR.get();
    if (atr_buf_len as usize) < atr_sz {
        return 0;
    }
    core::ptr::copy_nonoverlapping(atr_ptr, atr_buf, atr_sz);
    atr_sz as u32
}

// ---------------------------------------------------------------------------
// APDU processing
// ---------------------------------------------------------------------------

/// Process one APDU command.
///
/// Writes response data followed by SW1 and SW2 into `rsp_buf`.
/// Returns total response length (data_len + 2 for SW1/SW2), or 0 on error.
///
/// # Safety
///
/// - `cmd` must point to at least `cmd_len` readable bytes.
/// - `rsp_buf` must point to at least `rsp_buf_len` writable bytes.
///   Recommended minimum: 258 bytes (256 data + 2 status).
#[no_mangle]
pub unsafe extern "C" fn simrs_apdu(
    cmd: *const u8,
    cmd_len: u32,
    rsp_buf: *mut u8,
    rsp_buf_len: u32,
) -> u32 {
    let cmd_slice = core::slice::from_raw_parts(cmd, cmd_len as usize);

    // HLE returns data in rsp, plus separate SW1/SW2.
    // We need space for data + 2 status bytes.
    let rsp_slice = core::slice::from_raw_parts_mut(rsp_buf, rsp_buf_len as usize);

    // Use a temporary buffer for hle_apdu since it returns data without SW.
    let mut tmp = [0u8; 256];
    match simrs_hle::hle_apdu(cmd_slice, &mut tmp) {
        Some((data_len, sw1, sw2)) => {
            let total = data_len + 2;
            if total > rsp_buf_len as usize {
                return 0;
            }
            rsp_slice[..data_len].copy_from_slice(&tmp[..data_len]);
            rsp_slice[data_len] = sw1;
            rsp_slice[data_len + 1] = sw2;
            total as u32
        }
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// Save SIM state to `buf`. Returns bytes written, or 0 on error.
///
/// # Safety
///
/// `buf` must point to at least `buf_len` writable bytes.
/// Use `simrs_snapshot_size()` to determine required buffer size.
#[no_mangle]
pub unsafe extern "C" fn simrs_snapshot_save(
    buf: *mut u8,
    buf_len: u32,
) -> u32 {
    let slice = core::slice::from_raw_parts_mut(buf, buf_len as usize);
    simrs_hle::hle_snapshot_save(slice) as u32
}

/// Restore SIM state from `buf`. Returns 1 on success, 0 on failure.
///
/// The SIM must already be initialized (via `simrs_init`)
/// with the same algorithm that was used when the snapshot was saved.
///
/// # Safety
///
/// `buf` must point to at least `buf_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn simrs_snapshot_restore(
    buf: *const u8,
    buf_len: u32,
) -> u32 {
    let slice = core::slice::from_raw_parts(buf, buf_len as usize);
    if simrs_hle::hle_snapshot_restore(slice) { 1 } else { 0 }
}

/// Maximum snapshot buffer size required (constant).
#[no_mangle]
pub extern "C" fn simrs_snapshot_size() -> u32 {
    simrs_hle::hle_snapshot_size() as u32
}

// ---------------------------------------------------------------------------
// State hash
// ---------------------------------------------------------------------------

/// FNV-1a hash of current SIM state. Returns 0 if not initialized.
#[no_mangle]
pub extern "C" fn simrs_state_hash() -> u64 {
    simrs_hle::hle_state_hash()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_and_reset() {
        unsafe { simrs_init([0u8; 16].as_ptr(), [0u8; 16].as_ptr(), [0u8; 16].as_ptr()) };
        let mut atr_buf = [0u8; 32];
        let atr_len = unsafe { simrs_reset(atr_buf.as_mut_ptr(), atr_buf.len() as u32) };
        assert_eq!(atr_len, simrs_hle::DEFAULT_ATR.len() as u32);
        assert_eq!(&atr_buf[..atr_len as usize], &simrs_hle::DEFAULT_ATR);
    }

    #[test]
    fn apdu_select_mf() {
        unsafe { simrs_init([0u8; 16].as_ptr(), [0u8; 16].as_ptr(), [0u8; 16].as_ptr()) };
        let mut atr = [0u8; 32];
        unsafe { simrs_reset(atr.as_mut_ptr(), 32) };

        // SELECT MF (3F00)
        let cmd = [0x00u8, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let mut rsp = [0u8; 258];
        let rsp_len = unsafe {
            simrs_apdu(cmd.as_ptr(), cmd.len() as u32, rsp.as_mut_ptr(), 258)
        };
        assert!(rsp_len >= 2, "should get at least SW1 SW2");
        // SW1 should be 0x61 (data available via GET RESPONSE)
        assert_eq!(rsp[(rsp_len - 2) as usize], 0x61);
    }

    #[test]
    fn snapshot_roundtrip() {
        unsafe { simrs_init([0u8; 16].as_ptr(), [0u8; 16].as_ptr(), [0u8; 16].as_ptr()) };
        let mut atr = [0u8; 32];
        unsafe { simrs_reset(atr.as_mut_ptr(), 32) };

        // Do some work
        let cmd = [0x00u8, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let mut rsp = [0u8; 258];
        unsafe { simrs_apdu(cmd.as_ptr(), cmd.len() as u32, rsp.as_mut_ptr(), 258) };

        let hash_before = simrs_state_hash();

        // Save snapshot
        let snap_size = simrs_snapshot_size();
        let mut snap = vec![0u8; snap_size as usize];
        let saved = unsafe { simrs_snapshot_save(snap.as_mut_ptr(), snap_size) };
        assert!(saved > 0);

        // Re-init (wipes state)
        unsafe { simrs_init([0u8; 16].as_ptr(), [0u8; 16].as_ptr(), [0u8; 16].as_ptr()) };
        unsafe { simrs_reset(atr.as_mut_ptr(), 32) };

        // Restore
        let ok = unsafe { simrs_snapshot_restore(snap.as_ptr(), saved) };
        assert_eq!(ok, 1);

        let hash_after = simrs_state_hash();
        assert_eq!(hash_before, hash_after);
    }

    #[test]
    fn init_profile_returns_profile_atr() {
        let der = include_bytes!(
            "../../../crates/simrs-profile/tests/fixtures/profiles/TS48v1_A.der"
        );
        let ok = unsafe { simrs_init_profile(der.as_ptr(), der.len() as u32) };
        assert_eq!(ok, 1, "simrs_init_profile should succeed");

        let mut atr_buf = [0u8; 64];
        let atr_len = unsafe { simrs_reset(atr_buf.as_mut_ptr(), atr_buf.len() as u32) };

        // Profile ATR is 18 bytes (simrs_profile::DEFAULT_ATR), not the
        // 4-byte default ATR used by simrs_init.
        assert_eq!(atr_len, 18);
        assert_ne!(
            &atr_buf[..atr_len as usize],
            &simrs_hle::DEFAULT_ATR[..],
            "profile ATR must differ from the default 4-byte ATR"
        );
        // First byte is always 0x3B (direct convention).
        assert_eq!(atr_buf[0], 0x3B);
    }

    #[test]
    fn init_profile_bad_der_returns_zero() {
        let garbage = [0xFFu8; 8];
        let ok = unsafe { simrs_init_profile(garbage.as_ptr(), garbage.len() as u32) };
        assert_eq!(ok, 0, "invalid DER should return failure");
    }
}
