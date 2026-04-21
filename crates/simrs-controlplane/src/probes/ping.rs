//! `P1 = 0x08` Misc probe: ping / version.
//!
//! - `P2 = 0x00` ping: echo the request data field back in the response.
//! - `P2 = 0x01` version: return an ASCII version tag identifying the
//!   applet implementation. Used by the differential harness to
//!   confirm both backends are running the same control-plane version
//!   before interpreting the other probes' results.
//!
//! Responses are plain byte sequences (not BER-TLV): these commands
//! predate any probe that needs structured output, and keeping them
//! simple lets the differential harness check byte-exact equality.

use crate::applet::AppletState;
use crate::protocol::{SW_INCORRECT_P1P2, SW_OK};

/// Sub-operation: echo the command data field in the response.
pub const P2_PING: u8 = 0x00;

/// Sub-operation: return the applet version string.
pub const P2_VERSION: u8 = 0x01;

/// Human-readable version tag. Kept ASCII + byte-stable so references
/// (Rust / Java) can agree bit-for-bit.
///
/// Bump when the command surface changes in an observable way.
pub const VERSION_STRING: &[u8] = b"simrs-controlplane/1";

/// Handle a Misc (ping/version) APDU.
#[must_use]
pub fn handle(_state: &mut AppletState, p2: u8, data: &[u8], rsp: &mut Vec<u8>) -> [u8; 2] {
    match p2 {
        P2_PING => {
            rsp.extend_from_slice(data);
            SW_OK
        }
        P2_VERSION => {
            rsp.extend_from_slice(VERSION_STRING);
            SW_OK
        }
        _ => SW_INCORRECT_P1P2,
    }
}
