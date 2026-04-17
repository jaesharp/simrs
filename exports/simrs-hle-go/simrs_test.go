package simrs

import (
	"runtime"
	"testing"
)

func init() {
	// Pin to OS thread since the C API uses thread-local storage.
	runtime.LockOSThread()
}

func setupSim(t *testing.T) {
	t.Helper()
	Init([16]byte{}, [16]byte{}, [16]byte{})
	_, err := Reset()
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
}

func TestResetReturnsATR(t *testing.T) {
	Init([16]byte{}, [16]byte{}, [16]byte{})
	atr, err := Reset()
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	if len(atr) == 0 {
		t.Fatal("ATR is empty")
	}
	if atr[0] != 0x3B {
		t.Fatalf("ATR[0] = 0x%02X, want 0x3B", atr[0])
	}
}

func TestSelectMF(t *testing.T) {
	setupSim(t)
	rsp, err := Apdu([]byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00})
	if err != nil {
		t.Fatalf("APDU failed: %v", err)
	}
	if len(rsp) < 2 {
		t.Fatalf("Response too short: %d bytes", len(rsp))
	}
	sw1 := rsp[len(rsp)-2]
	if sw1 != 0x61 {
		t.Fatalf("SW1 = 0x%02X, want 0x61", sw1)
	}
}

func TestSnapshotRoundtrip(t *testing.T) {
	setupSim(t)
	Apdu([]byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00})

	snap, err := SnapshotSave()
	if err != nil {
		t.Fatalf("SnapshotSave failed: %v", err)
	}
	if len(snap) == 0 {
		t.Fatal("Snapshot is empty")
	}

	h1 := StateHash()

	Init([16]byte{}, [16]byte{}, [16]byte{})
	Reset()
	err = SnapshotRestore(snap)
	if err != nil {
		t.Fatalf("SnapshotRestore failed: %v", err)
	}

	h2 := StateHash()
	if h1 != h2 {
		t.Fatalf("Hash mismatch: 0x%X != 0x%X", h1, h2)
	}
}

func TestStateHashChanges(t *testing.T) {
	setupSim(t)
	h1 := StateHash()
	Apdu([]byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00})
	h2 := StateHash()
	if h1 == h2 {
		t.Fatal("Hash should change after APDU")
	}
}

func TestBadProfileFails(t *testing.T) {
	err := InitProfile([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("Expected error for bad DER")
	}
}

func TestBadSnapshotFails(t *testing.T) {
	setupSim(t)
	err := SnapshotRestore([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("Expected error for bad snapshot")
	}
}

func TestSnapshotSize(t *testing.T) {
	if SnapshotSize() == 0 {
		t.Fatal("SnapshotSize should be nonzero")
	}
}
