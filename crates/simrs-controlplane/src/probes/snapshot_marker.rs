//! `P1 = 0x05` `SnapshotMarker` probe: a persistent counter exposed
//! via APDUs so snapshot/restore tests can verify they are observing
//! the state they intended.
//!
//! - `P2 = 0x00` get current counter value (4 bytes BE, no data input).
//! - `P2 = 0x01` increment the counter and return the new value
//!   (4 bytes BE, no data input). Wrap-on-overflow semantics so a
//!   test that runs 2^32 iterations does not panic.
//!
//! Typical flow for a snapshot-restore test:
//!
//! 1. Increment the counter a known number of times.
//! 2. Capture a snapshot of the card state.
//! 3. Increment further.
//! 4. Restore the snapshot.
//! 5. GET the counter and assert it matches the captured value.

use crate::applet::AppletState;
use crate::protocol::{SW_INCORRECT_P1P2, SW_OK};

/// Sub-operation: return the current counter.
pub const P2_GET: u8 = 0x00;

/// Sub-operation: increment and return the new counter value.
pub const P2_INCREMENT: u8 = 0x01;

/// Response payload size (u32 big-endian).
pub const VALUE_LEN: usize = 4;

/// Handle a `SnapshotMarker` APDU.
#[must_use]
pub fn handle(state: &mut AppletState, p2: u8, _data: &[u8], rsp: &mut Vec<u8>) -> [u8; 2] {
    match p2 {
        P2_GET => {
            rsp.extend_from_slice(&state.snapshot_counter.to_be_bytes());
            SW_OK
        }
        P2_INCREMENT => {
            // Saturating would hide counter overflow in long-running
            // fuzz loops; wrapping is honest and documented.
            state.snapshot_counter = state.snapshot_counter.wrapping_add(1);
            rsp.extend_from_slice(&state.snapshot_counter.to_be_bytes());
            SW_OK
        }
        _ => SW_INCORRECT_P1P2,
    }
}
