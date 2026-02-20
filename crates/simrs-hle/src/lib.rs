//! HLE (High-Level Emulation) SIM peripheral for QEMU.
//!
//! Exposes the simrs SIM simulator as a C-ABI shared library suitable for
//! loading as a QEMU plugin or TCG helper. QEMU hooks firmware function calls
//! (e.g. `sim_send_apdu`) and forwards APDU buffers to simrs via these
//! exported functions instead of emulating the physical SIM controller.
//!
//! # C-ABI Exports
//! - `simrs_hle_reset()` -- reset the SIM to power-on state
//! - `simrs_hle_apdu(cmd, cmd_len, rsp, rsp_len)` -- process one APDU
//! - `simrs_hle_snapshot_save(buf, buf_len) -> actual_len` -- serialize state
//! - `simrs_hle_snapshot_restore(buf, buf_len)` -- restore serialized state
//!
//! # HLE vs Register-Level
//! HLE operates at APDU granularity -- bypassing T=0 electrical protocol --
//! enabling ~100,000 APDUs/sec vs ~100 APDUs/sec for register-level emulation.
//!
//! Compiled as both `rlib` (for Rust consumers) and `cdylib` (for QEMU).
