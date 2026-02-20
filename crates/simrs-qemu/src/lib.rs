//! QEMU virtual smart card integration.
//!
//! Bridges the simrs SIM simulator to QEMU's virtual smart card interface.
//! Connects via the shared-memory transport and services APDU requests
//! arriving from QEMU's `ccid-card-passthru` or custom smart card device.
//!
//! # Integration
//! Run as a standalone daemon:
//! ```text
//! simrs-qemu --shmem /dev/shm/simrs0 --fs usim.json
//! ```
//!
//! Requires `std` (file system access for loading filesystem definitions,
//! POSIX shared memory).
