//! AID constants for the control-plane applet.
//!
//! The AID lives under RID `A0 00 00 00 62` ("Java Card for Open
//! Platform", ISO/IEC 7816-5 registered) with a PIX whose leading
//! `FF` byte marks it as reserved-for-test-use, so it cannot collide
//! with production applets.

/// Full applet AID: 8 bytes.
///
/// Terminals SELECT this AID to reach the control-plane dispatcher.
pub const CONTROLPLANE_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0xFF, 0x00, 0x01];

/// Package AID (7 bytes) -- the applet's enclosing CAP file. Used on
/// the reference-backend side where the `.cap` install metadata
/// requires a distinct package identifier.
pub const CONTROLPLANE_PACKAGE_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0xFF, 0x00];

/// True iff `candidate` is the control-plane applet AID.
///
/// The check is exact (length + bytes). Partial-AID SELECT is not
/// supported for the control plane -- the applet is test-only and
/// its AID is single-purpose.
#[must_use]
pub fn is_controlplane_aid(candidate: &[u8]) -> bool {
    candidate == CONTROLPLANE_AID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aid_length_is_8() {
        assert_eq!(CONTROLPLANE_AID.len(), 8);
    }

    #[test]
    fn package_aid_is_prefix_of_applet_aid() {
        assert_eq!(CONTROLPLANE_PACKAGE_AID.len(), 7);
        assert_eq!(
            &CONTROLPLANE_AID[..CONTROLPLANE_PACKAGE_AID.len()],
            &CONTROLPLANE_PACKAGE_AID
        );
    }

    #[test]
    fn recognises_exact_aid() {
        assert!(is_controlplane_aid(&CONTROLPLANE_AID));
    }

    #[test]
    fn rejects_partial_aid() {
        assert!(!is_controlplane_aid(&CONTROLPLANE_AID[..7]));
        assert!(!is_controlplane_aid(&CONTROLPLANE_AID[..6]));
    }

    #[test]
    fn rejects_different_aid() {
        let isd = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
        assert!(!is_controlplane_aid(&isd));
    }
}
