//! `P1 = 0x09` `NestedCard` probe: dom0 hosts a second-level card
//! and orchestrates lifecycle events on it.
//!
//! This is the "can a hypervisor run a hypervisor?" test. The outer
//! control-plane applet carries an optional nested
//! [`ControlplaneCard`] whose inner `Transport` is a
//! [`NullTransport`] (always-`9000` stub). Commands addressed to the
//! nested card's control-plane AID land in the inner applet via a
//! `FORWARD` sub-op on the outer, demonstrating that the wrapper
//! composes recursively and that state on the inner applet
//! (`SnapshotMarker`, `Prng`, etc.) is independent of the outer.
//!
//! - `P2 = 0x00` `SPAWN`: instantiate the nested card. Idempotent;
//!   re-spawning drops any prior nested state. Returns `9000`.
//! - `P2 = 0x01` `DESTROY`: drop the nested card. `9000` whether
//!   or not a nested card was present.
//! - `P2 = 0x02` `FORWARD`: data field is a full APDU to route to
//!   the nested card. Outer response payload is the nested card's
//!   full response (data || SW). Outer SW is `9000` on successful
//!   forward (whatever the inner's SW was is inside the payload),
//!   `69 85` if no nested card has been spawned.
//!
//! The explicit wrap-and-forward design makes the nesting boundary
//! observable: the terminal always knows whether it is talking to
//! the outer or the inner, and inner failures don't masquerade as
//! outer failures.

use simrs_transport::{Transport, TransportError};

use crate::applet::ControlplaneApplet;
use crate::capability::{Capability, CapabilitySet};
use crate::card::ControlplaneCard;
use crate::protocol::{SW_INCORRECT_DATA, SW_INCORRECT_P1P2, SW_OK};

/// Sub-operation: spawn the nested card.
pub const P2_SPAWN: u8 = 0x00;

/// Sub-operation: drop the nested card.
pub const P2_DESTROY: u8 = 0x01;

/// Sub-operation: forward the data field as an APDU to the nested card.
pub const P2_FORWARD: u8 = 0x02;

/// Sub-operation: drop a capability on the nested-card handle.
///
/// The data field is a single [`Capability`] wire byte. Monotonic:
/// cannot be undone. Applied *to this handle only* -- other handles
/// to the same logical card (once we support shared ownership) keep
/// their own capability sets.
pub const P2_DROP_CAP: u8 = 0x03;

/// `69 85` -- conditions-of-use not satisfied. Returned by FORWARD
/// when no nested card has been spawned.
pub const SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];

/// `69 82` -- security status not satisfied. Returned when the
/// handle's capability set does not include the requested operation.
pub const SW_SECURITY_NOT_SATISFIED: [u8; 2] = [0x69, 0x82];

/// Minimal `Transport` that answers every command with SW `9000`.
///
/// Used as the innermost layer of a nested-card stack so nesting
/// tests exercise the wrapper composition without needing a full
/// simulated card at the bottom.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullTransport;

impl Transport for NullTransport {
    type Error = TransportError;

    fn exchange(&mut self, _cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        if rsp.len() < 2 {
            return Err(TransportError::BufferTooSmall);
        }
        rsp[0] = 0x90;
        rsp[1] = 0x00;
        Ok(2)
    }
}

/// Handle to an owned nested card.
///
/// Wraps a trait object so the outer applet can hold different
/// inner-card types interchangeably; in practice today it's always
/// [`ControlplaneCard<NullTransport>`](ControlplaneCard). Carries a
/// [`CapabilitySet`] separately so multiple handles to the same card
/// (future work) can hold independent capability sets.
pub struct NestedCardHandle {
    card: Box<dyn Transport<Error = TransportError>>,
    capabilities: CapabilitySet,
}

impl NestedCardHandle {
    /// Create a fresh default nested card: an inner
    /// `ControlplaneCard` wrapping a [`NullTransport`], with the
    /// fully-privileged capability set.
    #[must_use]
    pub fn default_inner() -> Self {
        Self {
            card: Box::new(ControlplaneCard::new(NullTransport)),
            capabilities: CapabilitySet::full(),
        }
    }

    /// Construct from parts (testing + advanced composition).
    #[must_use]
    pub fn from_parts(
        card: Box<dyn Transport<Error = TransportError>>,
        capabilities: CapabilitySet,
    ) -> Self {
        Self { card, capabilities }
    }

    /// Current capability set for this handle.
    #[must_use]
    pub const fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    /// Monotonically drop a capability from this handle's set.
    /// Idempotent; has no effect if the cap is already absent.
    pub const fn drop_capability(&mut self, cap: Capability) {
        self.capabilities = self.capabilities.drop(cap);
    }

    /// Forward `cmd` to the nested card; write its response into
    /// `out` and return the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] on forwarding failure.
    pub fn forward(&mut self, cmd: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
        self.card.exchange(cmd, out)
    }
}

impl core::fmt::Debug for NestedCardHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NestedCardHandle")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

/// Handle a `NestedCard` APDU.
///
/// Response-buffer sizing: the handler reserves 512 bytes internally
/// for the inner card's response. Real-world APDUs fit comfortably
/// under this; anything larger is truncated with a `6A 80` SW.
#[must_use]
pub fn handle(applet: &mut ControlplaneApplet, p2: u8, data: &[u8], rsp: &mut Vec<u8>) -> [u8; 2] {
    match p2 {
        P2_SPAWN => {
            applet.set_nested(Some(NestedCardHandle::default_inner()));
            SW_OK
        }
        P2_DESTROY => {
            applet.set_nested(None);
            SW_OK
        }
        P2_FORWARD => {
            let Some(nested) = applet.nested_mut() else {
                return SW_CONDITIONS_NOT_SATISFIED;
            };
            // Capability gate: the FORWARD sub-op itself requires
            // the `NestCards` capability on the handle. A handle
            // that has dropped this capability can still be queried
            // (capabilities are visible on the handle struct) but
            // cannot forward traffic into the nested card.
            if !nested.capabilities().contains(Capability::NestCards) {
                return SW_SECURITY_NOT_SATISFIED;
            }
            let mut buf = [0u8; 512];
            nested
                .forward(data, &mut buf)
                .map_or(SW_INCORRECT_DATA, |n| {
                    rsp.extend_from_slice(&buf[..n]);
                    SW_OK
                })
        }
        P2_DROP_CAP => {
            let Some(nested) = applet.nested_mut() else {
                return SW_CONDITIONS_NOT_SATISFIED;
            };
            if data.len() != 1 {
                return SW_INCORRECT_DATA;
            }
            let Some(cap) = Capability::from_byte(data[0]) else {
                return SW_INCORRECT_DATA;
            };
            nested.drop_capability(cap);
            SW_OK
        }
        _ => SW_INCORRECT_P1P2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::applet::ControlplaneApplet;
    use crate::protocol::{CLA, INS};

    fn short_apdu(p2: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![CLA, INS, 0x09, p2];
        #[allow(clippy::cast_possible_truncation)]
        out.push(data.len() as u8);
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn spawn_forward_destroy_cycle() {
        let mut applet = ControlplaneApplet::new();
        let mut rsp = Vec::new();

        // Initially no nested card.
        let forward = short_apdu(P2_FORWARD, &[CLA, INS, 0x08, 0x00]);
        rsp.clear();
        assert_eq!(
            applet.process(&forward, &mut rsp),
            SW_CONDITIONS_NOT_SATISFIED
        );

        // Spawn and try again.
        rsp.clear();
        let spawn = short_apdu(P2_SPAWN, &[]);
        assert_eq!(applet.process(&spawn, &mut rsp), SW_OK);
        assert!(applet.has_nested());

        // Forward a ping through to the nested card. The nested
        // card's controlplane applet isn't selected yet, so the
        // ping will fall through to NullTransport (returning 9000).
        rsp.clear();
        assert_eq!(applet.process(&forward, &mut rsp), SW_OK);
        // Outer SW OK; payload is the nested card's response: just
        // "9000" from NullTransport.
        assert_eq!(rsp, vec![0x90, 0x00]);

        // Destroy and confirm.
        rsp.clear();
        assert_eq!(
            applet.process(&short_apdu(P2_DESTROY, &[]), &mut rsp),
            SW_OK
        );
        assert!(!applet.has_nested());
    }

    #[test]
    fn dropping_nestcards_capability_blocks_forward_on_that_handle() {
        let mut applet = ControlplaneApplet::new();
        let mut rsp = Vec::new();

        assert_eq!(applet.process(&short_apdu(P2_SPAWN, &[]), &mut rsp), SW_OK);

        // Drop the NestCards capability on this handle.
        rsp.clear();
        let drop = short_apdu(P2_DROP_CAP, &[Capability::NestCards.as_byte()]);
        assert_eq!(applet.process(&drop, &mut rsp), SW_OK);

        // Subsequent FORWARD must fail with SECURITY_NOT_SATISFIED.
        rsp.clear();
        let forward = short_apdu(P2_FORWARD, &[CLA, INS, 0x08, 0x00]);
        assert_eq!(
            applet.process(&forward, &mut rsp),
            SW_SECURITY_NOT_SATISFIED
        );
        assert!(rsp.is_empty());
    }

    #[test]
    fn sibling_handle_unaffected_by_drop_on_one_handle() {
        // Construct two handles independently. Each has its own
        // capability set; dropping a cap on one must not touch the
        // other. (The single-slot applet here only holds one handle
        // at a time, so we assert at the handle level rather than
        // through two live applet slots -- multi-slot lands next.)
        use crate::card::ControlplaneCard;

        let privileged = NestedCardHandle::default_inner();
        let mut reduced = NestedCardHandle::from_parts(
            Box::new(ControlplaneCard::new(NullTransport)),
            CapabilitySet::full(),
        );
        reduced.drop_capability(Capability::NestCards);

        assert!(privileged.capabilities().contains(Capability::NestCards));
        assert!(!reduced.capabilities().contains(Capability::NestCards));
        // Liveness remains on both.
        assert!(privileged.capabilities().contains(Capability::Liveness));
        assert!(reduced.capabilities().contains(Capability::Liveness));
    }

    #[test]
    fn drop_unknown_capability_byte_returns_6a80() {
        let mut applet = ControlplaneApplet::new();
        let mut rsp = Vec::new();
        assert_eq!(applet.process(&short_apdu(P2_SPAWN, &[]), &mut rsp), SW_OK);
        rsp.clear();
        let drop = short_apdu(P2_DROP_CAP, &[0xFF]);
        assert_eq!(applet.process(&drop, &mut rsp), SW_INCORRECT_DATA);
    }

    #[test]
    fn drop_without_nested_returns_6985() {
        let mut applet = ControlplaneApplet::new();
        let mut rsp = Vec::new();
        let drop = short_apdu(P2_DROP_CAP, &[Capability::Liveness.as_byte()]);
        assert_eq!(applet.process(&drop, &mut rsp), SW_CONDITIONS_NOT_SATISFIED);
    }
}
