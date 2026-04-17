"""Core SimRS bindings over ctypes."""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NamedTuple


class SimError(Exception):
    """Raised when a SimRS C API call fails."""


class ApduResponse(NamedTuple):
    """Result of an APDU exchange."""

    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> int:
        """Status word as a 16-bit integer."""
        return (self.sw1 << 8) | self.sw2

    @property
    def success(self) -> bool:
        """True if SW is 9000 (normal completion)."""
        return self.sw1 == 0x90 and self.sw2 == 0x00

    def __repr__(self) -> str:
        sw_hex = f"{self.sw1:02X}{self.sw2:02X}"
        if self.data:
            return f"ApduResponse(data={self.data.hex()}, sw={sw_hex})"
        return f"ApduResponse(sw={sw_hex})"


@dataclass(frozen=True)
class Credentials:
    """SIM authentication credentials."""

    ki: bytes
    k: bytes
    opc: bytes

    def __post_init__(self) -> None:
        if len(self.ki) != 16:
            raise ValueError(f"ki must be 16 bytes, got {len(self.ki)}")
        if len(self.k) != 16:
            raise ValueError(f"k must be 16 bytes, got {len(self.k)}")
        if len(self.opc) != 16:
            raise ValueError(f"opc must be 16 bytes, got {len(self.opc)}")


def generate_credentials(seed: int | None = None) -> Credentials:
    """Generate SIM authentication credentials.

    Args:
        seed: Optional integer seed for deterministic generation.
              The same seed always produces the same credentials.
              If None, credentials are derived from os.urandom.

    Returns:
        A Credentials instance with 16-byte ki, k, and opc fields.
    """
    if seed is not None:
        seed_bytes = struct.pack("<q", seed)
        h0 = hashlib.sha256(b"simrs-ki\x00" + seed_bytes).digest()
        h1 = hashlib.sha256(b"simrs-k\x00" + seed_bytes).digest()
        h2 = hashlib.sha256(b"simrs-opc\x00" + seed_bytes).digest()
        return Credentials(ki=h0[:16], k=h1[:16], opc=h2[:16])

    return Credentials(
        ki=os.urandom(16),
        k=os.urandom(16),
        opc=os.urandom(16),
    )


def _find_library() -> str:
    """Locate the simrs-hle-capi shared library.

    Search order:
    1. SIMRS_LIB environment variable (explicit path)
    2. Sibling crate target (exports/simrs-hle-capi/target/{release,debug}/)
    """
    env_path = os.environ.get("SIMRS_LIB")
    if env_path:
        return env_path

    if sys.platform == "darwin":
        lib_name = "libsimrs_hle_capi.dylib"
    elif sys.platform == "win32":
        lib_name = "simrs_hle_capi.dll"
    else:
        lib_name = "libsimrs_hle_capi.so"

    exports_dir = Path(__file__).resolve().parent.parent.parent.parent

    candidates = [
        exports_dir / "simrs-hle-capi" / "target" / "release" / lib_name,
        exports_dir / "simrs-hle-capi" / "target" / "debug" / lib_name,
    ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    raise SimError(
        f"Cannot find {lib_name}. Build it first:\n"
        "  cargo build --manifest-path exports/simrs-hle-capi/Cargo.toml --release\n"
        "Or set SIMRS_LIB=/path/to/libsimrs_hle_capi.so"
    )


def _load_library(path: str | None = None) -> ctypes.CDLL:
    """Load and configure the C library."""
    lib_path = path or _find_library()
    lib = ctypes.CDLL(lib_path)

    lib.simrs_init.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.simrs_init.restype = None

    lib.simrs_init_profile.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
    lib.simrs_init_profile.restype = ctypes.c_uint32

    lib.simrs_reset.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
    lib.simrs_reset.restype = ctypes.c_uint32

    lib.simrs_apdu.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    lib.simrs_apdu.restype = ctypes.c_uint32

    lib.simrs_snapshot_save.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
    lib.simrs_snapshot_save.restype = ctypes.c_uint32

    lib.simrs_init_from_snapshot.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
    lib.simrs_init_from_snapshot.restype = ctypes.c_uint32

    lib.simrs_snapshot_size.argtypes = []
    lib.simrs_snapshot_size.restype = ctypes.c_uint32

    lib.simrs_state_hash.argtypes = []
    lib.simrs_state_hash.restype = ctypes.c_uint64

    return lib


class Sim:
    """A SimRS smart card simulator instance.

    By default, each Sim spawns a dedicated worker thread so the instance
    can be safely used from any Python thread. Pass ``thread_safe=False``
    for a lighter-weight mode that pins the Sim to the creating thread
    and raises on cross-thread access.

    Use one of the class methods to create an instance::

        creds = generate_credentials(seed=42)
        sim = Sim.with_credentials(creds)

        sim = Sim.from_profile(der_bytes)
    """

    def __init__(self) -> None:
        raise TypeError(
            "Use Sim.with_credentials(creds) or Sim.from_profile(der) "
            "to create a Sim instance"
        )

    @classmethod
    def with_credentials(
        cls,
        credentials: Credentials,
        *,
        lib_path: str | None = None,
        thread_safe: bool = True,
    ) -> Sim:
        """Create a SIM with explicit authentication credentials.

        Args:
            credentials: A Credentials instance (from generate_credentials()
                         or constructed directly).
            lib_path: Optional explicit path to the shared library.
            thread_safe: If True (default), spawns a dedicated worker thread
                         so the Sim can be used from any Python thread. If
                         False, pins to the creating thread and raises SimError
                         on cross-thread access.

        Raises:
            SimError: If the shared library cannot be found.
        """
        instance = object.__new__(cls)
        instance._lib = _load_library(lib_path)
        instance._setup_dispatch(thread_safe)
        instance._call(
            instance._lib.simrs_init,
            credentials.ki, credentials.k, credentials.opc,
        )
        instance._initialized = True
        return instance

    @classmethod
    def from_profile(
        cls,
        der: bytes,
        *,
        lib_path: str | None = None,
        thread_safe: bool = True,
    ) -> Sim:
        """Create a SIM from a TCA eUICC Profile Package (DER-encoded).

        Args:
            der: Raw DER bytes of the profile package.
            lib_path: Optional explicit path to the shared library.
            thread_safe: If True (default), spawns a dedicated worker thread.

        Raises:
            SimError: If the profile cannot be parsed.
        """
        instance = object.__new__(cls)
        instance._lib = _load_library(lib_path)
        instance._setup_dispatch(thread_safe)
        result = instance._call(instance._lib.simrs_init_profile, der, len(der))
        if result == 0:
            raise SimError("Failed to load profile (malformed DER or missing PEs)")
        instance._initialized = True
        return instance

    def _setup_dispatch(self, thread_safe: bool) -> None:
        if thread_safe:
            self._executor: ThreadPoolExecutor | None = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="simrs",
            )
            self._owner_thread: int | None = None
        else:
            self._executor = None
            self._owner_thread = threading.get_ident()

    def _call(self, fn: Callable[..., Any], *args: Any) -> Any:
        """Dispatch a C API call to the correct thread."""
        if self._executor is not None:
            return self._executor.submit(fn, *args).result()

        if threading.get_ident() != self._owner_thread:
            raise SimError(
                "Sim accessed from a different thread than it was created on. "
                "Use thread_safe=True (the default) for cross-thread access."
            )
        return fn(*args)

    def reset(self) -> bytes:
        """Power-on reset. Returns the ATR (Answer To Reset) bytes.

        Raises:
            SimError: If the SIM is not initialized or ATR buffer is too small.
        """
        self._check_initialized()
        atr_buf = ctypes.create_string_buffer(64)
        atr_len = self._call(self._lib.simrs_reset, atr_buf, 64)
        if atr_len == 0:
            raise SimError("Reset failed (SIM not initialized?)")
        return atr_buf.raw[:atr_len]

    def apdu(self, command: bytes) -> ApduResponse:
        """Send an APDU command and receive the response.

        Args:
            command: Raw APDU bytes (minimum 4: CLA INS P1 P2).

        Returns:
            An ApduResponse with data, sw1, and sw2 fields.

        Raises:
            ValueError: If command is shorter than 4 bytes.
            SimError: If the APDU exchange fails.
        """
        self._check_initialized()
        if len(command) < 4:
            raise ValueError(f"APDU must be at least 4 bytes, got {len(command)}")

        rsp_buf = ctypes.create_string_buffer(258)
        rsp_len = self._call(self._lib.simrs_apdu, command, len(command), rsp_buf, 258)
        if rsp_len == 0:
            raise SimError("APDU processing failed")
        if rsp_len < 2:
            raise SimError(f"Response too short: {rsp_len} bytes")

        raw = rsp_buf.raw[:rsp_len]
        return ApduResponse(
            data=raw[:-2],
            sw1=raw[-2],
            sw2=raw[-1],
        )

    def apdu_hex(self, hex_string: str) -> ApduResponse:
        """Send an APDU from a hex string.

        Spaces are stripped automatically::

            sim.apdu_hex("00 A4 04 00 07 A0000000871002")
        """
        cleaned = hex_string.replace(" ", "")
        return self.apdu(bytes.fromhex(cleaned))

    def snapshot(self) -> bytes:
        """Save the current SIM state to a byte buffer.

        Returns:
            Opaque snapshot bytes that can be passed to restore().

        Raises:
            SimError: If the snapshot fails.
        """
        self._check_initialized()
        size = self._call(self._lib.simrs_snapshot_size)
        buf = ctypes.create_string_buffer(size)
        written = self._call(self._lib.simrs_snapshot_save, buf, size)
        if written == 0:
            raise SimError("Snapshot save failed")
        return buf.raw[:written]

    def restore(self, snapshot: bytes) -> None:
        """Restore SIM state from a previous snapshot.

        The SIM must have been initialized with the same algorithm
        (Milenage/TUAK) as when the snapshot was taken.

        Args:
            snapshot: Bytes previously returned by snapshot().

        Raises:
            SimError: If restoration fails (algorithm mismatch, corrupt data).
        """
        self._check_initialized()
        result = self._call(self._lib.simrs_init_from_snapshot, snapshot, len(snapshot))
        if result == 0:
            raise SimError(
                "Snapshot restore failed (algorithm mismatch or corrupt data)"
            )

    def state_hash(self) -> int:
        """Compute a non-cryptographic hash (FNV-1a) of the current SIM state.

        Useful for state deduplication in fuzzing or test infrastructure.

        Returns:
            64-bit hash value.
        """
        self._check_initialized()
        return self._call(self._lib.simrs_state_hash)

    def _check_initialized(self) -> None:
        if not self._initialized:
            raise SimError("SIM not initialized")

    def __enter__(self) -> Sim:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Shut down the worker thread (thread_safe mode).

        Safe to call multiple times or in pinned mode (no-op).
        """
        executor = getattr(self, "_executor", None)
        if executor is not None:
            executor.shutdown(wait=True)
            self._executor = None

    def __del__(self) -> None:
        self.close()

    def __repr__(self) -> str:
        if getattr(self, "_owner_thread", None) is not None:
            return "Sim(mode=pinned)"
        return "Sim(mode=thread-safe)"
