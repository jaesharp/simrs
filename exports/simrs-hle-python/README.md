# simrs-hle-python

Python bindings for the SimRS smart card simulator.

Wraps the [simrs-hle-capi](../simrs-hle-capi/) C API via ctypes with a
Pythonic interface, thread safety management, and proper error handling.

## Usage

```python
from simrs import Sim, generate_credentials

# Generate credentials (optionally seeded for determinism)
creds = generate_credentials(seed=42)

# Create a SIM -- key material is always required
sim = Sim.with_credentials(creds)
atr = sim.reset()

# Send APDUs
data, sw1, sw2 = sim.apdu_hex("00 A4 04 00 07 A0000000871002")

# Snapshot and restore state
state = sim.snapshot()
sim.restore(state)

# Context manager shuts down the worker thread
with Sim.with_credentials(creds) as sim:
    sim.reset()
    rsp = sim.apdu_hex("00A40004023F00")
```

## Thread Safety

By default, each `Sim` instance spawns a dedicated worker thread. All C API
calls are dispatched to that thread, so the `Sim` can be safely shared across
Python threads.

For lighter-weight usage where cross-thread access is not needed, pass
`thread_safe=False` to pin the Sim to the creating thread:

```python
sim = Sim.with_credentials(creds, thread_safe=False)
```

Accessing a pinned Sim from a different thread raises `SimError`.

## Building and Testing

Requires `uv` (for managed Python environment) and the Rust toolchain.

```sh
# Build the C shared library and run all Python tests
cargo test --manifest-path exports/simrs-hle-python/Cargo.toml
```

The `build.rs` automatically builds the `simrs-hle-capi` cdylib before tests
run. The Rust integration test invokes `uv run pytest` which provisions a
Python environment with pytest from the lockfile.

## API

### Construction

- `Sim.with_credentials(creds, *, thread_safe=True)` -- create from a `Credentials` instance
- `Sim.from_profile(der_bytes, *, thread_safe=True)` -- create from a TCA eUICC DER profile
- `generate_credentials(seed=None)` -- generate credentials (random or deterministic)

### Operations

- `sim.reset() -> bytes` -- power-on reset, returns ATR
- `sim.apdu(command) -> ApduResponse` -- send raw APDU bytes
- `sim.apdu_hex(hex_string) -> ApduResponse` -- send APDU from hex string (spaces allowed)
- `sim.snapshot() -> bytes` -- save SIM state
- `sim.restore(snapshot)` -- restore from snapshot
- `sim.state_hash() -> int` -- FNV-1a hash of current state
- `sim.close()` -- shut down worker thread (also called by context manager exit)
