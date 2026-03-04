//! Protocol-level reference test vectors.
//!
//! This module provides reference APDU sequences and expected responses
//! for cross-validating the SIM/USIM protocol implementation.
//!
//! These are positive tests - verifying correct behavior against known-good
//! reference outputs. Negative tests (vulnerability detection) are handled
//! by simrs-security-tests.

use crate::ReferenceSource;

/// Reference APDU sequence for protocol testing.
#[derive(Debug, Clone)]
pub struct ApduSequence {
    /// Human-readable name for this sequence.
    pub name: &'static str,
    /// The APDU commands in sequence.
    pub commands: &'static [&'static [u8]],
    /// Expected responses (one per command).
    pub expected_responses: &'static [&'static [u8]],
    /// Source of this reference sequence.
    pub source: ReferenceSource,
}

/// Returns all reference APDU sequences.
pub fn sequences() -> &'static [ApduSequence] {
    &[]
}