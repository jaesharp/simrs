//! Catalog of known and accepted divergences between simrs and Oracle jcsl.
//!
//! Each entry documents WHY the difference is acceptable with spec references.
//! This serves as a living record of intentional behavioral differences so
//! that differential test runs can distinguish regressions from accepted
//! deviations.

/// A documented divergence between simrs and the Oracle jcsl reference.
///
/// Each entry carries a unique identifier, a human-readable description,
/// the reason the divergence is acceptable, and a specification reference
/// justifying the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDivergence {
    /// Short unique identifier (e.g., "D6").
    pub id: &'static str,
    /// What the divergence looks like in practice.
    pub description: &'static str,
    /// Status word returned by simrs for this case.
    pub simrs_sw: u16,
    /// Status word returned by Oracle jcsl for this case.
    pub oracle_sw: u16,
    /// Why the divergence is acceptable.
    pub reason: &'static str,
    /// Specification reference justifying the decision.
    pub spec_ref: &'static str,
}

/// Static catalog of all known and accepted divergences.
pub static KNOWN_DIVERGENCES: &[KnownDivergence] = &[
    KnownDivergence {
        id: "D2",
        description: "SELECT with 8-byte ISD AID (Oracle GP 2.3 default)",
        simrs_sw: 0x6A82,
        oracle_sw: 0x9000,
        reason: "simrs ISD AID is 7 bytes (GP 2.1.1 default A0000001510000); \
                 Oracle uses 8 bytes (GP 2.3 default A000000151000000). \
                 simrs supports custom AID via with_isd_aid() but the \
                 default configuration uses the shorter GP 2.1.1 AID.",
        spec_ref: "GP 2.1.1 clause 6.1 (ISD AID is card-specific)",
    },
    KnownDivergence {
        id: "D6",
        description: "EXTERNAL AUTHENTICATE failure status word",
        simrs_sw: 0x6988,
        oracle_sw: 0x6985,
        reason: "Uniform error response for all authentication failures \
                 (padding oracle defense per Avoine & Ferreira, TCHES 2018)",
        spec_ref: "GP 2.1.1 Table 9-9 (both 6985 and 6988 are valid)",
    },
];

/// Look up a known divergence by the (simrs, oracle) status word pair.
///
/// Returns the first matching entry, or `None` if this SW pair is not
/// cataloged as a known divergence.
pub fn lookup(simrs_sw: u16, oracle_sw: u16) -> Option<&'static KnownDivergence> {
    KNOWN_DIVERGENCES
        .iter()
        .find(|d| d.simrs_sw == simrs_sw && d.oracle_sw == oracle_sw)
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
        assert_eq!(d.oracle_sw, 0x6985);
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
        // (oracle, simrs) reversed should NOT match D6.
        assert!(
            lookup(0x6985, 0x6988).is_none(),
            "reversed SW pair must not match"
        );
    }
}
