"""Tests for the simrs Python bindings.

Requires the shared library to be built first:
    cargo build --manifest-path exports/simrs-hle-capi/Cargo.toml --release
"""

import threading

import pytest

from simrs import Sim, generate_credentials, Credentials, ApduResponse, SimError


class TestCredentials:
    def test_valid(self):
        creds = Credentials(ki=bytes(16), k=bytes(16), opc=bytes(16))
        assert len(creds.ki) == 16

    def test_short_ki_rejected(self):
        with pytest.raises(ValueError, match="ki must be 16 bytes"):
            Credentials(ki=b"short", k=bytes(16), opc=bytes(16))

    def test_short_k_rejected(self):
        with pytest.raises(ValueError, match="k must be 16 bytes"):
            Credentials(ki=bytes(16), k=b"short", opc=bytes(16))

    def test_short_opc_rejected(self):
        with pytest.raises(ValueError, match="opc must be 16 bytes"):
            Credentials(ki=bytes(16), k=bytes(16), opc=b"short")

    def test_frozen(self):
        creds = Credentials(ki=bytes(16), k=bytes(16), opc=bytes(16))
        with pytest.raises(AttributeError):
            creds.ki = bytes(16)


class TestGenerateCredentials:
    def test_random(self):
        c1 = generate_credentials()
        c2 = generate_credentials()
        assert c1 != c2

    def test_seeded_deterministic(self):
        c1 = generate_credentials(seed=42)
        c2 = generate_credentials(seed=42)
        assert c1 == c2

    def test_different_seeds_differ(self):
        c1 = generate_credentials(seed=1)
        c2 = generate_credentials(seed=2)
        assert c1 != c2

    def test_key_lengths(self):
        creds = generate_credentials(seed=0)
        assert len(creds.ki) == 16
        assert len(creds.k) == 16
        assert len(creds.opc) == 16


class TestSimConstruction:
    def test_bare_init_raises(self):
        with pytest.raises(TypeError, match="Sim.with_credentials"):
            Sim()

    def test_bad_profile_raises(self):
        with pytest.raises(SimError, match="malformed DER"):
            Sim.from_profile(b"\xff" * 8)


class TestSimOperations:
    """Tests that work in both thread-safe and pinned modes."""

    @pytest.fixture(params=[True, False], ids=["thread-safe", "pinned"])
    def sim(self, request):
        creds = generate_credentials(seed=12345)
        s = Sim.with_credentials(creds, thread_safe=request.param)
        s.reset()
        yield s
        s.close()

    def test_reset_returns_atr(self):
        creds = generate_credentials(seed=1)
        sim = Sim.with_credentials(creds)
        atr = sim.reset()
        assert len(atr) > 0
        assert atr[0] == 0x3B
        sim.close()

    def test_select_mf(self, sim):
        rsp = sim.apdu(bytes.fromhex("00A40004023F00"))
        assert isinstance(rsp, ApduResponse)
        assert rsp.sw1 == 0x61

    def test_apdu_hex(self, sim):
        rsp = sim.apdu_hex("00 A4 04 00 07 A0000000871002")
        assert rsp.sw1 in (0x61, 0x90)

    def test_apdu_too_short(self, sim):
        with pytest.raises(ValueError, match="at least 4 bytes"):
            sim.apdu(b"\x00\xA4")

    def test_apdu_response_sw_property(self, sim):
        rsp = sim.apdu_hex("00A40004023F00")
        assert rsp.sw == (rsp.sw1 << 8) | rsp.sw2

    def test_context_manager(self):
        creds = generate_credentials(seed=99)
        with Sim.with_credentials(creds) as sim:
            sim.reset()
            rsp = sim.apdu_hex("00A40004023F00")
            assert rsp.sw1 == 0x61

    def test_repr_thread_safe(self):
        sim = Sim.with_credentials(generate_credentials(seed=1))
        assert "thread-safe" in repr(sim)
        sim.close()

    def test_repr_pinned(self):
        sim = Sim.with_credentials(generate_credentials(seed=1), thread_safe=False)
        assert "pinned" in repr(sim)
        sim.close()

    def test_close_idempotent(self):
        sim = Sim.with_credentials(generate_credentials(seed=1))
        sim.close()
        sim.close()


class TestSnapshot:
    @pytest.fixture(params=[True, False], ids=["thread-safe", "pinned"])
    def sim(self, request):
        creds = generate_credentials(seed=1)
        s = Sim.with_credentials(creds, thread_safe=request.param)
        s.reset()
        yield s
        s.close()

    def test_snapshot_is_bytes(self, sim):
        snap = sim.snapshot()
        assert isinstance(snap, bytes)
        assert len(snap) > 0

    def test_state_hash_changes_after_apdu(self, sim):
        h1 = sim.state_hash()
        sim.apdu_hex("00A40004023F00")
        h2 = sim.state_hash()
        assert h1 != h2

    def test_restore_reverts_state(self, sim):
        snap = sim.snapshot()
        h_before = sim.state_hash()

        sim.apdu_hex("00A40004023F00")
        sim.apdu_hex("00A4040007 A0000000871002")
        assert sim.state_hash() != h_before

        sim.restore(snap)
        assert sim.state_hash() == h_before

    def test_restore_bad_data_raises(self, sim):
        with pytest.raises(SimError, match="restore failed"):
            sim.restore(b"\xff" * 64)

    def test_multiple_snapshot_restore_cycles(self, sim):
        snap_initial = sim.snapshot()
        h_initial = sim.state_hash()

        sim.apdu_hex("00A40004023F00")
        snap_after_select = sim.snapshot()
        h_after_select = sim.state_hash()

        sim.restore(snap_initial)
        assert sim.state_hash() == h_initial

        sim.restore(snap_after_select)
        assert sim.state_hash() == h_after_select

    def test_snapshot_roundtrip_fresh_instance(self, sim):
        sim.apdu_hex("00A40004023F00")
        snap = sim.snapshot()
        h1 = sim.state_hash()

        sim2 = Sim.with_credentials(generate_credentials(seed=1))
        sim2.reset()
        sim2.restore(snap)
        h2 = sim2.state_hash()
        sim2.close()

        assert h1 == h2


class TestThreadSafety:
    """The C API uses thread-local storage. The default thread-safe mode
    spawns a dedicated worker thread. Pinned mode rejects cross-thread use."""

    def test_thread_safe_cross_thread_access(self):
        """Thread-safe Sim can be used from any thread."""
        sim = Sim.with_credentials(generate_credentials(seed=1))
        sim.reset()
        results = {}

        def worker():
            rsp = sim.apdu_hex("00A40004023F00")
            results["sw"] = rsp.sw

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        sim.close()

        assert results["sw"] == (0x61 << 8) | results["sw"] & 0xFF

    def test_pinned_rejects_cross_thread(self):
        """Pinned Sim raises when accessed from a different thread."""
        sim = Sim.with_credentials(
            generate_credentials(seed=1), thread_safe=False,
        )
        sim.reset()
        errors = []

        def worker():
            try:
                sim.apdu_hex("00A40004023F00")
            except SimError as e:
                errors.append(e)

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        sim.close()

        assert len(errors) == 1
        assert "different thread" in str(errors[0])

    def test_multiple_thread_safe_instances(self):
        """Multiple thread-safe Sims each get independent state."""
        results = {}
        errors = []

        def worker(thread_id, seed):
            try:
                sim = Sim.with_credentials(generate_credentials(seed=seed))
                sim.reset()
                sim.apdu_hex("00A40004023F00")
                results[thread_id] = sim.state_hash()
                sim.close()
            except Exception as e:
                errors.append((thread_id, e))

        threads = [
            threading.Thread(target=worker, args=(i, i * 100))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert len(results) == 4
        # Different credentials produce different hashes.
        assert len(set(results.values())) == 4

    def test_concurrent_apdu_exchange(self):
        """Multiple thread-safe Sims process APDUs concurrently."""
        errors = []
        successes = []

        def worker(seed):
            try:
                sim = Sim.with_credentials(generate_credentials(seed=seed))
                sim.reset()
                for _ in range(10):
                    rsp = sim.apdu_hex("00A40004023F00")
                    assert rsp.sw1 in (0x61, 0x90)
                sim.close()
                successes.append(seed)
            except Exception as e:
                errors.append((seed, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert len(successes) == 4

    def test_snapshot_restore_across_threads(self):
        """A snapshot from one thread-safe Sim can be restored on another."""
        sim1 = Sim.with_credentials(generate_credentials(seed=42))
        sim1.reset()
        sim1.apdu_hex("00A40004023F00")
        snap = sim1.snapshot()
        h1 = sim1.state_hash()
        sim1.close()

        result = {}

        def restorer():
            sim2 = Sim.with_credentials(generate_credentials(seed=42))
            sim2.reset()
            sim2.restore(snap)
            result["hash"] = sim2.state_hash()
            sim2.close()

        t = threading.Thread(target=restorer)
        t.start()
        t.join()

        assert result["hash"] == h1
