# simrs-hle-capi

C-ABI cdylib wrapper for `simrs-hle`. Loadable via `ctypes.CDLL` from Python
or any C/C++ host.

This crate lives **outside the simrs workspace** because the workspace enforces
`unsafe_code = "forbid"`, and C-ABI exports require raw pointer dereference.

For a higher-level Python API with thread safety, see
[simrs-hle-pythonapi](../simrs-hle-pythonapi/).

## Build

```sh
cargo build --manifest-path exports/simrs-hle-capi/Cargo.toml --release
```

Output: `target/release/libsimrs_hle_capi.so` (Linux) or `.dylib` (macOS).

## Exported Symbols

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `simrs_init` | `(ki: *const u8, k: *const u8, opc: *const u8)` | Init with Milenage auth (each ptr = 16 bytes) |
| `simrs_init_default` | `()` | Init with all-zero test credentials |
| `simrs_init_profile` | `(der: *const u8, der_len: u32) -> u32` | Init from TCA DER profile (1=ok, 0=fail) |
| `simrs_reset` | `(atr_buf: *mut u8, atr_buf_len: u32) -> u32` | Power-on reset, returns ATR length |
| `simrs_apdu` | `(cmd: *const u8, cmd_len: u32, rsp_buf: *mut u8, rsp_buf_len: u32) -> u32` | Process one APDU, returns response length |
| `simrs_snapshot_save` | `(buf: *mut u8, buf_len: u32) -> u32` | Save SIM state |
| `simrs_snapshot_restore` | `(buf: *const u8, buf_len: u32) -> u32` | Restore SIM state (1=ok, 0=fail) |
| `simrs_snapshot_size` | `() -> u32` | Required snapshot buffer size |
| `simrs_state_hash` | `() -> u64` | FNV-1a hash of current state |

## Thread Safety

`simrs-hle` uses thread-local storage. Each OS thread gets its own independent
SIM instance. All calls for a given SIM session must happen on the same thread.
