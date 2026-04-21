//! `P1 = 0x03` `FaultInjection` probe.
//!
//! Arms the dispatcher so the *next* incoming command returns a
//! caller-chosen status word without running its handler. Plays the
//! same role in simrs's control plane that `qemu-monitor inject-nmi`
//! or Xen's `xl trigger` play for a virtualization dom0: the
//! privileged management path reaches into the hypervisor and
//! perturbs the execution of an otherwise-opaque guest so tests can
//! observe how the rest of the system handles faults.
//!
//! - `P2 = 0x00` `ARM_DEFAULT`: arm a fault with SW `6F 00` (general
//!   error) for the next command. No data.
//! - `P2 = 0x01` `ARM_CUSTOM`: arm with caller-supplied SW (data
//!   field is exactly 2 bytes: `SW1 SW2`). Any 2-byte value accepted
//!   so tests can use non-standard SWs to verify upstream handling.
//! - `P2 = 0x02` `DISARM`: clear any pending arm. Idempotent.
//!
//! The `FaultInjection` APDU itself is *not* affected by the arm it
//! sets -- the dispatcher's arm check runs before its normal P1/P2
//! routing, and setting the flag via the handler happens after that
//! check. See [`crate::applet::ControlplaneApplet::process`].

use crate::applet::AppletState;
use crate::protocol::{SW_INCORRECT_DATA, SW_INCORRECT_P1P2, SW_OK};

/// Sub-operation: arm the next command with `6F 00` (general error).
pub const P2_ARM_DEFAULT: u8 = 0x00;

/// Sub-operation: arm the next command with a caller-supplied SW.
pub const P2_ARM_CUSTOM: u8 = 0x01;

/// Sub-operation: clear any pending arm.
pub const P2_DISARM: u8 = 0x02;

/// Default SW delivered by `ARM_DEFAULT`.
pub const DEFAULT_FAULT_SW: [u8; 2] = [0x6F, 0x00];

/// Handle a `FaultInjection` APDU.
#[must_use]
pub fn handle(state: &mut AppletState, p2: u8, data: &[u8], _rsp: &mut Vec<u8>) -> [u8; 2] {
    // Resolve the new arm state, or bail with an error SW. Keeping
    // the state mutation out of each match arm makes the three
    // sub-ops trivially symmetric.
    let new_arm = match p2 {
        P2_ARM_DEFAULT => Some(DEFAULT_FAULT_SW),
        P2_ARM_CUSTOM => {
            if data.len() != 2 {
                return SW_INCORRECT_DATA;
            }
            Some([data[0], data[1]])
        }
        P2_DISARM => None,
        _ => return SW_INCORRECT_P1P2,
    };
    state.armed_fault = new_arm;
    SW_OK
}
