# simrs-hle-ffi

C-ABI cdylib wrapper for `simrs-hle`. Loadable via `ctypes.CDLL` from Python
(FirmWire's `SimrsPeripheral`) or any C/C++ host.

This crate lives **outside the simrs workspace** because the workspace enforces
`unsafe_code = "forbid"`, and C-ABI exports require raw pointer dereference.

## Build

```sh
cd tools/simrs-hle-ffi
cargo build --release
```

Output: `target/release/libsimrs_hle_ffi.so` (Linux) or `.dylib` (macOS).

## Exported Symbols

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `simrs_init` | `(ki: *const u8, k: *const u8, opc: *const u8)` | Init with Milenage auth (each ptr = 16 bytes) |
| `simrs_init_default` | `()` | Init with all-zero test credentials |
| `simrs_reset` | `(atr_buf: *mut u8, atr_buf_len: u32) -> u32` | Power-on reset, returns ATR length |
| `simrs_apdu` | `(cmd: *const u8, cmd_len: u32, rsp_buf: *mut u8, rsp_buf_len: u32) -> u32` | Process one APDU, returns response length |
| `simrs_snapshot_save` | `(buf: *mut u8, buf_len: u32) -> u32` | Save SIM state |
| `simrs_snapshot_restore` | `(buf: *const u8, buf_len: u32) -> u32` | Restore SIM state (1=ok, 0=fail) |
| `simrs_snapshot_size` | `() -> u32` | Required snapshot buffer size |
| `simrs_state_hash` | `() -> u64` | FNV-1a hash of current state |

## Python Example

```python
import ctypes

lib = ctypes.CDLL("target/release/libsimrs_hle_ffi.so")
lib.simrs_init_default()

atr = (ctypes.c_uint8 * 32)()
atr_len = lib.simrs_reset(atr, 32)

cmd = (ctypes.c_uint8 * 7)(0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00)
rsp = (ctypes.c_uint8 * 258)()
rsp_len = lib.simrs_apdu(cmd, len(cmd), rsp, 258)
sw = bytes(rsp[rsp_len - 2 : rsp_len])
```

## Thread Safety

`simrs-hle` uses thread-local storage. Each OS thread gets its own independent
SIM instance. Ensure all calls for a given SIM session happen on the same thread.
