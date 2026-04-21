//! Composable [`Transport`] wrapper that intercepts SELECT for the
//! control-plane AID and delegates every other APDU to an inner
//! [`Transport`] (the real card under test).
//!
//! This wrapper is the only integration path the control plane needs.
//! No feature flag on any production crate, no dispatcher surgery --
//! tests wrap whatever `Transport` impl they already have in a
//! `ControlplaneCard` and SELECT the control-plane AID to switch
//! context.
//!
//! # Example (conceptual)
//!
//! ```rust,ignore
//! let inner: impl Transport = /* real card / bridge */;
//! let mut card = ControlplaneCard::new(inner);
//! // SELECT control-plane AID
//! card.exchange(&[0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x62, 0xFF, 0x00, 0x01], &mut rsp)?;
//! // subsequent 80 F0 ... commands land in the applet
//! card.exchange(&[0x80, 0xF0, 0x08, 0x00], &mut rsp)?; // ping
//! // SELECT another AID -> control plane deselects, delegates resume
//! ```

use simrs_transport::{Transport, TransportError};

use crate::aid::is_controlplane_aid;
use crate::applet::ControlplaneApplet;
use crate::protocol::{SW_APP_NOT_FOUND, SW_OK};

/// ISO 7816-4 SELECT APDU bytes: `CLA=00 INS=A4 P1=04 P2=00`. A SELECT
/// by name/AID is recognised when the first four bytes match.
const SELECT_CLA: u8 = 0x00;
const SELECT_INS: u8 = 0xA4;
const SELECT_P1_BY_NAME: u8 = 0x04;

/// [`Transport`] wrapper that intercepts SELECT for the control-plane
/// AID. All non-matching traffic is forwarded to `inner` unchanged.
///
/// The wrapper is generic over the inner transport so it composes
/// with any card implementation: in-process `GpCard`, TCP-backed
/// reference clients (jcsl, jcardengine), or mock transports.
pub struct ControlplaneCard<Inner: Transport> {
    inner: Inner,
    applet: ControlplaneApplet,
    /// Whether the control-plane applet is the currently-selected
    /// application on the default logical channel. Wrapper-owned --
    /// the applet itself is stateless-per-command.
    selected: bool,
}

impl<Inner: Transport> ControlplaneCard<Inner> {
    /// Wrap `inner` with a freshly-initialised control-plane applet.
    pub fn new(inner: Inner) -> Self {
        Self {
            inner,
            applet: ControlplaneApplet::new(),
            selected: false,
        }
    }

    /// Borrow the inner transport immutably (for tests that need to
    /// poke at the underlying card state).
    #[must_use]
    pub const fn inner(&self) -> &Inner {
        &self.inner
    }

    /// Borrow the inner transport mutably.
    pub const fn inner_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }

    /// Borrow the control-plane applet (for preseeding state in tests).
    pub const fn applet_mut(&mut self) -> &mut ControlplaneApplet {
        &mut self.applet
    }

    /// Whether the control-plane applet is currently selected.
    #[must_use]
    pub const fn is_selected(&self) -> bool {
        self.selected
    }
}

/// Classify an incoming APDU so `exchange` knows where to route it.
enum Routing<'a> {
    /// `cmd` is a SELECT; if `aid` is ours, route to applet; otherwise
    /// route to `inner` and deselect the applet.
    Select { aid: &'a [u8] },
    /// Routed based on whether the applet is currently selected.
    NonSelect,
}

fn classify(cmd: &[u8]) -> Routing<'_> {
    if cmd.len() >= 5 && cmd[0] == SELECT_CLA && cmd[1] == SELECT_INS && cmd[2] == SELECT_P1_BY_NAME
    {
        let lc = cmd[4] as usize;
        if cmd.len() >= 5 + lc {
            return Routing::Select {
                aid: &cmd[5..5 + lc],
            };
        }
    }
    Routing::NonSelect
}

impl<Inner: Transport> Transport for ControlplaneCard<Inner>
where
    Inner::Error: From<TransportError>,
{
    type Error = Inner::Error;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        match classify(cmd) {
            Routing::Select { aid } => {
                if is_controlplane_aid(aid) {
                    self.selected = true;
                    write_response(rsp, &[], SW_OK)
                } else {
                    self.selected = false;
                    self.inner.exchange(cmd, rsp)
                }
            }
            Routing::NonSelect if self.selected => {
                let mut data = Vec::with_capacity(256);
                let sw = self.applet.process(cmd, &mut data);
                write_response(rsp, &data, sw)
            }
            Routing::NonSelect => self.inner.exchange(cmd, rsp),
        }
    }
}

/// Assemble a `data || SW` response into `rsp`, returning the total
/// bytes written. Fails with [`TransportError::BufferTooSmall`] if
/// `rsp` cannot hold `data.len() + 2` bytes.
fn write_response<E: From<TransportError>>(
    rsp: &mut [u8],
    data: &[u8],
    sw: [u8; 2],
) -> Result<usize, E> {
    let needed = data.len() + 2;
    if rsp.len() < needed {
        return Err(E::from(TransportError::BufferTooSmall));
    }
    rsp[..data.len()].copy_from_slice(data);
    rsp[data.len()] = sw[0];
    rsp[data.len() + 1] = sw[1];
    Ok(needed)
}

/// Silence the unused-import lint on non-error paths. `SW_APP_NOT_FOUND`
/// is reserved for a future enhancement that synthesizes the response
/// when the inner transport doesn't know the SELECT'd AID.
const _: [u8; 2] = SW_APP_NOT_FOUND;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aid::CONTROLPLANE_AID;
    use crate::protocol::{CLA, INS};

    /// Minimal inner transport that echoes the CLA byte and returns
    /// `90 00`. Lets us detect when the wrapper delegated vs handled.
    struct EchoInner {
        last_cmd: Vec<u8>,
    }

    impl EchoInner {
        const fn new() -> Self {
            Self {
                last_cmd: Vec::new(),
            }
        }
    }

    impl Transport for EchoInner {
        type Error = TransportError;

        fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
            self.last_cmd = cmd.to_vec();
            if rsp.len() < 2 {
                return Err(TransportError::BufferTooSmall);
            }
            rsp[0] = 0x90;
            rsp[1] = 0x00;
            Ok(2)
        }
    }

    fn select_cp_aid_apdu() -> Vec<u8> {
        let lc = u8::try_from(CONTROLPLANE_AID.len()).expect("AID fits in a byte");
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, lc];
        apdu.extend_from_slice(&CONTROLPLANE_AID);
        apdu
    }

    #[test]
    fn select_controlplane_aid_is_intercepted() {
        let mut card = ControlplaneCard::new(EchoInner::new());
        let select = select_cp_aid_apdu();
        let mut rsp = [0u8; 32];
        let n = card.exchange(&select, &mut rsp).unwrap();
        assert_eq!(&rsp[..n], &SW_OK);
        // Inner should NOT have seen the SELECT.
        assert!(card.inner().last_cmd.is_empty());
        assert!(card.is_selected());
    }

    #[test]
    fn select_other_aid_is_delegated_and_deselects_applet() {
        let mut card = ControlplaneCard::new(EchoInner::new());
        // First SELECT our AID so the applet is "selected".
        let _ = card.exchange(&select_cp_aid_apdu(), &mut [0u8; 4]).unwrap();
        assert!(card.is_selected());

        // Now SELECT a different AID.
        let isd_select = [
            0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00,
        ];
        let mut rsp = [0u8; 8];
        let n = card.exchange(&isd_select, &mut rsp).unwrap();
        assert_eq!(&rsp[..n], &[0x90, 0x00]);
        assert_eq!(card.inner().last_cmd, isd_select);
        assert!(!card.is_selected());
    }

    #[test]
    fn ping_after_select_dispatches_to_applet() {
        let mut card = ControlplaneCard::new(EchoInner::new());
        let _ = card.exchange(&select_cp_aid_apdu(), &mut [0u8; 4]).unwrap();

        let ping = [CLA, INS, 0x08, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let mut rsp = [0u8; 16];
        let n = card.exchange(&ping, &mut rsp).unwrap();
        assert_eq!(&rsp[..n - 2], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(&rsp[n - 2..n], &SW_OK);
        // Inner must not see applet traffic while selected.
        assert!(card.inner().last_cmd.is_empty());
    }

    #[test]
    fn non_select_when_applet_not_selected_delegates() {
        let mut card = ControlplaneCard::new(EchoInner::new());
        // No SELECT yet.
        let cmd = [0x80, 0xF0, 0x08, 0x00];
        let mut rsp = [0u8; 8];
        let _ = card.exchange(&cmd, &mut rsp).unwrap();
        assert_eq!(card.inner().last_cmd, cmd);
    }

    #[test]
    fn non_select_after_other_aid_selected_delegates() {
        let mut card = ControlplaneCard::new(EchoInner::new());
        // Select controlplane first...
        let _ = card.exchange(&select_cp_aid_apdu(), &mut [0u8; 4]).unwrap();
        // ...then something else.
        let isd_select = [
            0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00,
        ];
        let _ = card.exchange(&isd_select, &mut [0u8; 8]).unwrap();
        // Now an 80 F0 command should delegate, not intercept.
        let cmd = [0x80, 0xF0, 0x08, 0x00];
        let mut rsp = [0u8; 8];
        let _ = card.exchange(&cmd, &mut rsp).unwrap();
        assert_eq!(card.inner().last_cmd, cmd);
    }

    #[test]
    fn version_after_select_returns_version_string() {
        let mut card = ControlplaneCard::new(EchoInner::new());
        let _ = card.exchange(&select_cp_aid_apdu(), &mut [0u8; 4]).unwrap();
        let ver = [CLA, INS, 0x08, 0x01];
        let mut rsp = [0u8; 64];
        let n = card.exchange(&ver, &mut rsp).unwrap();
        assert_eq!(&rsp[n - 2..n], &SW_OK);
        assert_eq!(&rsp[..n - 2], crate::probes::ping::VERSION_STRING);
    }
}
