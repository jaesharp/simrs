//! Wire-protocol constants for the control-plane APDU surface.
//!
//! All commands share the shape `80 F0 <P1> <P2> <Lc> <data> <Le>`.
//! `P1` selects the probe category; `P2` sub-selects the operation
//! within that category.

/// CLA byte for every control-plane command after SELECT.
///
/// `0x80` is the GP "proprietary interindustry" CLA. Use of CLA
/// rather than CLA+secure-messaging bits means the applet does not
/// require SCP authentication -- it is unauthenticated by design so
/// tests can SELECT it immediately after ATR.
pub const CLA: u8 = 0x80;

/// INS byte. `0xF0` is in the proprietary range (INS >= 0x80 with
/// CLA 0x80) and matches the suggestion in the design document
/// (`docs/architecture/controlplane-applet.md`).
pub const INS: u8 = 0xF0;

/// `P1` byte that selects the probe category. Values follow the
/// design-document table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Category {
    /// JCVM state (opcode counters, method-depth history).
    JcvmState = 0x01,
    /// JCRE heap accounting (persistent + transient bytes).
    JcreHeap = 0x02,
    /// Fault injection (throw exceptions, force SW).
    FaultInjection = 0x03,
    /// PRNG control (seed override, deterministic read).
    Prng = 0x04,
    /// Persistent snapshot marker (for snapshot-restore testing).
    SnapshotMarker = 0x05,
    /// Applet firewall probe (attempt cross-context access).
    FirewallProbe = 0x06,
    /// Interposer control (start/stop APDU recording).
    InterposerControl = 0x07,
    /// Miscellaneous (ping / version).
    Misc = 0x08,
    /// Nested card lifecycle: dom0 spawns an inner card, forwards
    /// APDUs to it, verifies state isolation. Exercises the
    /// recursive-hypervisor invariant.
    NestedCard = 0x09,
}

impl Category {
    /// Parse a `P1` byte into a [`Category`]. Returns `None` for any
    /// unknown value so the dispatcher can reply with `6A 86`.
    #[must_use]
    pub const fn from_p1(p1: u8) -> Option<Self> {
        match p1 {
            0x01 => Some(Self::JcvmState),
            0x02 => Some(Self::JcreHeap),
            0x03 => Some(Self::FaultInjection),
            0x04 => Some(Self::Prng),
            0x05 => Some(Self::SnapshotMarker),
            0x06 => Some(Self::FirewallProbe),
            0x07 => Some(Self::InterposerControl),
            0x08 => Some(Self::Misc),
            0x09 => Some(Self::NestedCard),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Status words (ISO 7816-4 Table 6)
// ---------------------------------------------------------------------------

/// `90 00` -- success.
pub const SW_OK: [u8; 2] = [0x90, 0x00];

/// `6A 86` -- incorrect P1/P2 (unknown category or sub-operation).
pub const SW_INCORRECT_P1P2: [u8; 2] = [0x6A, 0x86];

/// `6A 80` -- incorrect parameters in data field.
pub const SW_INCORRECT_DATA: [u8; 2] = [0x6A, 0x80];

/// `6D 00` -- INS not supported.
pub const SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6D, 0x00];

/// `6E 00` -- CLA not supported.
pub const SW_CLA_NOT_SUPPORTED: [u8; 2] = [0x6E, 0x00];

/// `6A 82` -- referenced data not found (used for SELECT miss).
pub const SW_APP_NOT_FOUND: [u8; 2] = [0x6A, 0x82];

/// `67 00` -- wrong length (short APDU header incomplete).
pub const SW_WRONG_LENGTH: [u8; 2] = [0x67, 0x00];

/// Minimum short-APDU header length: `CLA INS P1 P2` = 4 bytes.
pub const HEADER_LEN: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_roundtrip() {
        for p1 in 0x01..=0x08u8 {
            let cat = Category::from_p1(p1).expect("known category");
            assert_eq!(cat as u8, p1);
        }
    }

    #[test]
    fn unknown_p1_is_none() {
        assert!(Category::from_p1(0x00).is_none());
        assert!(Category::from_p1(0x0A).is_none());
        assert!(Category::from_p1(0xFF).is_none());
    }

    #[test]
    fn cla_ins_match_design() {
        assert_eq!(CLA, 0x80);
        assert_eq!(INS, 0xF0);
    }
}
