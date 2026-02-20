//! Linux/Android OS-embedded SIM peripheral.
//!
//! Implements `SimPeripheral` via Linux kernel ioctl interfaces for SIM card
//! slot management. Supports Android's RIL (Radio Interface Layer) SIM socket
//! protocol and direct kernel character device interfaces.
//!
//! Requires `std` (POSIX file descriptors, ioctl syscall).
