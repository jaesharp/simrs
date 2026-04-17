"""SimRS -- Python bindings for the SimRS smart card simulator.

Wraps the simrs-hle-capi shared library via ctypes. Requires
``libsimrs_hle_capi.so`` (Linux) or ``libsimrs_hle_capi.dylib`` (macOS)
to be built first::

    cargo build --manifest-path exports/simrs-hle-capi/Cargo.toml --release
"""

from simrs._sim import Sim, generate_credentials, Credentials, SimError, ApduResponse

__all__ = ["Sim", "generate_credentials", "Credentials", "ApduResponse", "SimError"]
