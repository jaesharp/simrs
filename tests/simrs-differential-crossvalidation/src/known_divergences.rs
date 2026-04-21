//! Catalog of known and accepted divergences between simrs and a
//! reference `JavaCard` simulator.
//!
//! Each entry documents WHY the difference is acceptable with spec
//! references. This serves as a living record of intentional
//! behavioural differences so that differential test runs can
//! distinguish regressions from accepted deviations.
//!
//! Entries can be scoped to specific backends via the
//! [`KnownDivergence::backends`] filter: jcsl-specific divergences
//! (GP 2.1.1 vs 2.3 AID length, padding-oracle SW uniformity) apply
//! to jcsl only; `JCardEngine`'s narrower `GlobalPlatformApplet`
//! surface (GET DATA coverage, SELECT-unknown-AID handling)
//! generates its own entries tagged for jcardengine.

use crate::BackendId;

/// A documented divergence between simrs and a reference `JavaCard`
/// simulator.
///
/// Each entry carries a unique identifier, a human-readable
/// description, the reason the divergence is acceptable, and a
/// specification reference justifying the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDivergence {
    /// Short unique identifier (e.g., "D6").
    pub id: &'static str,
    /// What the divergence looks like in practice.
    pub description: &'static str,
    /// Status word returned by simrs for this case.
    pub simrs_sw: u16,
    /// Status word returned by the reference backend for this case.
    pub reference_sw: u16,
    /// Why the divergence is acceptable.
    pub reason: &'static str,
    /// Specification reference justifying the decision.
    pub spec_ref: &'static str,
    /// Reference backends this entry applies to. Empty means "any";
    /// when populated, the lookup must match the running backend.
    pub backends: &'static [BackendId],
}

/// Static catalog of all known and accepted divergences.
pub static KNOWN_DIVERGENCES: &[KnownDivergence] = &[
    KnownDivergence {
        id: "D2",
        description: "SELECT with 8-byte ISD AID (GP 2.3 default)",
        simrs_sw: 0x6A82,
        reference_sw: 0x9000,
        reason: "simrs ISD AID is 7 bytes (GP 2.1.1 default A0000001510000); \
                 both reference backends use the 8-byte GP 2.3 default \
                 A000000151000000. simrs supports custom AID via \
                 with_isd_aid() but the default configuration uses the \
                 shorter GP 2.1.1 AID.",
        spec_ref: "GP 2.1.1 clause 6.1 (ISD AID is card-specific)",
        backends: &[],
    },
    KnownDivergence {
        id: "D6",
        description: "EXTERNAL AUTHENTICATE failure status word",
        simrs_sw: 0x6988,
        reference_sw: 0x6985,
        reason: "Uniform error response for all authentication failures \
                 (padding oracle defense per Avoine & Ferreira, TCHES 2018)",
        spec_ref: "GP 2.1.1 Table 9-9 (both 6985 and 6988 are valid)",
        backends: &[BackendId::Jcsl],
    },
    KnownDivergence {
        id: "J1",
        description: "GET DATA -- JCardEngine GP applet does not implement tag",
        simrs_sw: 0x9000,
        reference_sw: 0x6D00,
        reason: "JCardEngine 26.04.06's GlobalPlatformApplet implements a \
                 narrower command surface than Oracle jcsl: GET DATA for \
                 tags 0066 (card recognition) and 9F7F (CPLC) is absent \
                 and falls through to the Applet default 'INS not \
                 supported' (6D00). simrs and jcsl both implement these \
                 tags per the spec.",
        spec_ref: "GP 2.1.1 Table 9-37 (GET DATA tags are optional)",
        backends: &[BackendId::Jcardengine],
    },
    KnownDivergence {
        id: "J2",
        description: "GET DATA unknown tag -- JCardEngine returns 6D00 instead of 6A88",
        simrs_sw: 0x6A88,
        reference_sw: 0x6D00,
        reason: "simrs and jcsl distinguish 'referenced data not found' (6A88) \
                 from 'INS not supported' (6D00); JCardEngine's GP applet \
                 short-circuits any unhandled INS to 6D00 regardless of P1P2.",
        spec_ref: "ISO 7816-4 Table 6 (6A88 vs 6D00 both valid for unsupported)",
        backends: &[BackendId::Jcardengine],
    },
    KnownDivergence {
        id: "J3",
        description: "SELECT unknown AID -- JCardEngine returns 6D00 instead of 6A82",
        simrs_sw: 0x6A82,
        reference_sw: 0x6D00,
        reason: "simrs and jcsl return 'application not found' (6A82) for a \
                 SELECT to an unregistered AID. JCardEngine's \
                 GlobalPlatformApplet short-circuits to 6D00 (INS not \
                 supported) via the default Applet.process() fallthrough.",
        spec_ref: "ISO 7816-4 Table 6 (6A82 is the conforming code)",
        backends: &[BackendId::Jcardengine],
    },
];

/// Look up a known divergence by the (simrs, reference) status word pair.
///
/// Returns the first matching entry, or `None` if this SW pair is not
/// cataloged as a known divergence. Entries with a non-empty
/// [`KnownDivergence::backends`] filter only match when `backend` is
/// one of the listed backends.
#[must_use]
pub fn lookup_for_backend(
    simrs_sw: u16,
    reference_sw: u16,
    backend: BackendId,
) -> Option<&'static KnownDivergence> {
    KNOWN_DIVERGENCES.iter().find(|d| {
        d.simrs_sw == simrs_sw
            && d.reference_sw == reference_sw
            && (d.backends.is_empty() || d.backends.contains(&backend))
    })
}

/// Backend-blind lookup by SW pair.
///
/// Legacy entry point kept for callers that pre-date the backend
/// filter. New code should prefer [`lookup_for_backend`] for
/// classification or [`lookup_by_id`] for display -- the SW-pair
/// lookup returns the first match only, which is ambiguous when two
/// entries share a pair with different backend scopes.
#[must_use]
pub fn lookup(simrs_sw: u16, reference_sw: u16) -> Option<&'static KnownDivergence> {
    KNOWN_DIVERGENCES
        .iter()
        .find(|d| d.simrs_sw == simrs_sw && d.reference_sw == reference_sw)
}

/// Look up an entry by its [`KnownDivergence::id`] string.
///
/// Unambiguous: every entry has a unique `id`. Used by the report
/// emitters to resolve reason/spec text for a pre-classified case
/// without re-running the SW-pair match.
#[must_use]
pub fn lookup_by_id(id: &str) -> Option<&'static KnownDivergence> {
    KNOWN_DIVERGENCES.iter().find(|d| d.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_divergence_lookup() {
        let d = lookup(0x6988, 0x6985);
        assert!(d.is_some(), "D6 divergence must be found");
        let d = d.unwrap();
        assert_eq!(d.id, "D6");
        assert_eq!(d.simrs_sw, 0x6988);
        assert_eq!(d.reference_sw, 0x6985);
        assert!(d.reason.contains("padding oracle"));
        assert!(d.spec_ref.contains("GP 2.1.1"));
    }

    #[test]
    fn test_lookup_returns_none_for_unknown_pair() {
        assert!(
            lookup(0x9000, 0x9000).is_none(),
            "matching SWs should not be in divergence catalog"
        );
        assert!(
            lookup(0x6A82, 0x6A88).is_none(),
            "uncataloged pair should return None"
        );
    }

    #[test]
    fn test_lookup_order_matters() {
        // (reference, simrs) reversed should NOT match D6.
        assert!(
            lookup(0x6985, 0x6988).is_none(),
            "reversed SW pair must not match"
        );
    }
}
