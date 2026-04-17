// Package simrs provides Go bindings for the SimRS smart card simulator.
//
// Each goroutine that uses this package gets its own independent SIM instance
// via the underlying C library's thread-local storage. All calls for a given
// SIM session must happen on the same OS thread -- use runtime.LockOSThread().
package simrs

/*
#cgo LDFLAGS: -lsimrs_hle_capi
#include "simrs.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

var (
	ErrNotInitialized = errors.New("simrs: SIM not initialized")
	ErrApduFailed     = errors.New("simrs: APDU processing failed")
	ErrSnapshotFailed = errors.New("simrs: snapshot operation failed")
	ErrProfileFailed  = errors.New("simrs: failed to load profile")
)

// Init initializes the SIM with Milenage authentication credentials.
// ki, k, and opc must each be exactly 16 bytes.
func Init(ki, k, opc [16]byte) {
	C.simrs_init(
		(*C.uint8_t)(unsafe.Pointer(&ki[0])),
		(*C.uint8_t)(unsafe.Pointer(&k[0])),
		(*C.uint8_t)(unsafe.Pointer(&opc[0])),
	)
}

// InitProfile initializes the SIM from a TCA eUICC Profile Package (DER-encoded).
func InitProfile(der []byte) error {
	result := C.simrs_init_profile(
		(*C.uint8_t)(unsafe.Pointer(&der[0])),
		C.uint32_t(len(der)),
	)
	if result == 0 {
		return ErrProfileFailed
	}
	return nil
}

// Reset performs a power-on reset and returns the ATR bytes.
func Reset() ([]byte, error) {
	var buf [64]byte
	n := C.simrs_reset(
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.uint32_t(len(buf)),
	)
	if n == 0 {
		return nil, ErrNotInitialized
	}
	atr := make([]byte, n)
	copy(atr, buf[:n])
	return atr, nil
}

// Apdu sends an APDU command and returns the response (data + SW1 + SW2).
func Apdu(cmd []byte) ([]byte, error) {
	var rspBuf [258]byte
	n := C.simrs_apdu(
		(*C.uint8_t)(unsafe.Pointer(&cmd[0])),
		C.uint32_t(len(cmd)),
		(*C.uint8_t)(unsafe.Pointer(&rspBuf[0])),
		C.uint32_t(len(rspBuf)),
	)
	if n == 0 {
		return nil, ErrApduFailed
	}
	rsp := make([]byte, n)
	copy(rsp, rspBuf[:n])
	return rsp, nil
}

// SnapshotSave saves the current SIM state.
func SnapshotSave() ([]byte, error) {
	size := C.simrs_snapshot_size()
	buf := make([]byte, size)
	n := C.simrs_snapshot_save(
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		size,
	)
	if n == 0 {
		return nil, ErrSnapshotFailed
	}
	return buf[:n], nil
}

// SnapshotRestore restores SIM state from a previous snapshot.
func SnapshotRestore(snap []byte) error {
	result := C.simrs_snapshot_restore(
		(*C.uint8_t)(unsafe.Pointer(&snap[0])),
		C.uint32_t(len(snap)),
	)
	if result == 0 {
		return ErrSnapshotFailed
	}
	return nil
}

// SnapshotSize returns the maximum snapshot buffer size required.
func SnapshotSize() int {
	return int(C.simrs_snapshot_size())
}

// StateHash returns an FNV-1a hash of the current SIM state.
func StateHash() uint64 {
	return uint64(C.simrs_state_hash())
}
