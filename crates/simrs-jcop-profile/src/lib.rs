//! JCOP variant profile definitions per the
//! [IBM JCOP Family](../../../../docs/specs/ibm-jcop/JCOP_Family.pdf) datasheet
//! (legacy compat target; profiles below are JCOP10-31bio family
//! variants that pre-date the GP 2.3.1 / JC 3.2 mainline).
//!
//! Each JCOP card model maps to a [`JcopProfile`] specifying its hardware
//! capabilities: EEPROM size, RAM budget, SCP version, crypto algorithms,
//! and interface support.
//!
//! # Variants
//!
//! | Variant | JC | GP | EEPROM | SCP | RSA max | Contactless |
//! |---------|----|----|--------|-----|---------|-------------|
//! | JCOP10 | 2.1.1 | OP 2.0.1 | 8KB | SCP01 | 1024 | No |
//! | JCOP20 | 2.1.1 | OP 2.0.1 | 16KB | SCP02 | 2048 | No |
//! | JCOP21 | 2.1.1 | OP 2.0.1 | 16KB | SCP02 | 2048 | ISO 14443A |
//! | `JCOP21id` | 2.1.1 | OP 2.0.1 | 32KB | SCP02 | 2048 | ISO 14443A |
//! | `JCOP31bio` | 2.1.1 | OP 2.0.1 | 32KB | SCP02 | 2048 | ISO 14443A |
//!
//! # `no_std`
//! This crate is fully `no_std`. Pure data definitions, no dependencies.
//!
//! # Example
//!
//! ```
//! use simrs_jcop_profile::{JcopVariant, JcopProfile, JCOP21_PROFILE};
//!
//! assert_eq!(JCOP21_PROFILE.variant, JcopVariant::Jcop21);
//! assert!(JCOP21_PROFILE.contactless);
//! assert_eq!(JCOP21_PROFILE.scp_version, simrs_jcop_profile::ScpVersion::Scp02);
//! ```
#![no_std]

#[cfg(feature = "std")]
extern crate std;

/// JCOP card variant identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JcopVariant {
    /// JCOP10: Contact-only, 8KB EEPROM, SCP01, RSA-1024 max.
    Jcop10,
    /// JCOP20: Contact-only, 16KB EEPROM, SCP02, RSA-2048, VOP Config 2.
    Jcop20,
    /// JCOP21: Dual-interface (contact + ISO 14443A T=CL), 16KB.
    Jcop21,
    /// `JCOP21id`: Dual-interface, 32KB, FIPS 140-2 L3, multiple SDs, DAP.
    Jcop21Id,
    /// `JCOP31bio`: Dual-interface, 32KB, biometry support.
    Jcop31Bio,
}

/// Secure Channel Protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpVersion {
    /// SCP01: static 3DES session keys (GP 2.1.1 Appendix D).
    Scp01,
    /// SCP02: sequence counter key derivation (GP 2.1.1 Appendix E).
    Scp02,
}

/// Contact interface protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactProtocol {
    /// T=0 character-level protocol.
    T0,
    /// T=1 block-level protocol.
    T1,
}

/// Complete JCOP variant profile.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
pub struct JcopProfile {
    /// Card variant identifier.
    pub variant: JcopVariant,
    /// EEPROM size in bytes.
    pub eeprom_size: usize,
    /// RAM transient-reset memory in bytes.
    pub ram_transient_reset: usize,
    /// RAM transient-deselect memory in bytes.
    pub ram_transient_deselect: usize,
    /// Maximum APDU buffer size in bytes (always 261 for JCOP).
    pub apdu_buffer_size: usize,
    /// Transaction buffer size in bytes.
    pub transaction_buffer_size: usize,
    /// Maximum number of Security Domains (including ISD).
    pub max_security_domains: usize,
    /// Maximum number of installable applets.
    pub max_applets: usize,
    /// Secure Channel Protocol version.
    pub scp_version: ScpVersion,
    /// Maximum RSA key size in bits.
    pub max_rsa_key_bits: usize,
    /// Contact interface protocols supported.
    pub contact_protocols: &'static [ContactProtocol],
    /// Whether ISO 14443A contactless (T=CL) is supported.
    pub contactless: bool,
    /// Whether DAP (Data Authentication Pattern) verification is supported.
    pub dap_supported: bool,
    /// Whether FIPS 140-2 Level 3 mode is supported.
    pub fips_mode: bool,
    /// Whether biometric template matching is supported.
    pub biometry: bool,
    /// DES/3DES supported (all variants).
    pub des_supported: bool,
    /// SHA-1 supported (JCOP20+).
    pub sha1_supported: bool,
    /// MD5 supported (JCOP20+).
    pub md5_supported: bool,
    /// RSA supported (all variants, key size varies).
    pub rsa_supported: bool,
}

/// Both T=0 and T=1 contact protocols.
static BOTH_PROTOCOLS: [ContactProtocol; 2] = [ContactProtocol::T0, ContactProtocol::T1];

/// JCOP10 profile: Contact-only, 8KB, SCP01, RSA-1024.
pub const JCOP10_PROFILE: JcopProfile = JcopProfile {
    variant: JcopVariant::Jcop10,
    eeprom_size: 8 * 1024,
    ram_transient_reset: 1200,
    ram_transient_deselect: 1100,
    apdu_buffer_size: 261,
    transaction_buffer_size: 512,
    max_security_domains: 1,
    max_applets: 4,
    scp_version: ScpVersion::Scp01,
    max_rsa_key_bits: 1024,
    contact_protocols: &BOTH_PROTOCOLS,
    contactless: false,
    dap_supported: false,
    fips_mode: false,
    biometry: false,
    des_supported: true,
    sha1_supported: false,
    md5_supported: false,
    rsa_supported: true,
};

/// JCOP20 profile: Contact-only, 16KB, SCP02, RSA-2048.
pub const JCOP20_PROFILE: JcopProfile = JcopProfile {
    variant: JcopVariant::Jcop20,
    eeprom_size: 16 * 1024,
    ram_transient_reset: 1200,
    ram_transient_deselect: 1100,
    apdu_buffer_size: 261,
    transaction_buffer_size: 512,
    max_security_domains: 2,
    max_applets: 8,
    scp_version: ScpVersion::Scp02,
    max_rsa_key_bits: 2048,
    contact_protocols: &BOTH_PROTOCOLS,
    contactless: false,
    dap_supported: false,
    fips_mode: false,
    biometry: false,
    des_supported: true,
    sha1_supported: true,
    md5_supported: true,
    rsa_supported: true,
};

/// JCOP21 profile: Dual-interface, 16KB, SCP02, RSA-2048, ISO 14443A.
pub const JCOP21_PROFILE: JcopProfile = JcopProfile {
    variant: JcopVariant::Jcop21,
    eeprom_size: 16 * 1024,
    ram_transient_reset: 1200,
    ram_transient_deselect: 1100,
    apdu_buffer_size: 261,
    transaction_buffer_size: 512,
    max_security_domains: 2,
    max_applets: 8,
    scp_version: ScpVersion::Scp02,
    max_rsa_key_bits: 2048,
    contact_protocols: &BOTH_PROTOCOLS,
    contactless: true,
    dap_supported: false,
    fips_mode: false,
    biometry: false,
    des_supported: true,
    sha1_supported: true,
    md5_supported: true,
    rsa_supported: true,
};

/// `JCOP21id` profile: Dual-interface, 32KB, SCP02, FIPS 140-2 L3, DAP.
pub const JCOP21ID_PROFILE: JcopProfile = JcopProfile {
    variant: JcopVariant::Jcop21Id,
    eeprom_size: 32 * 1024,
    ram_transient_reset: 1200,
    ram_transient_deselect: 1100,
    apdu_buffer_size: 261,
    transaction_buffer_size: 768,
    max_security_domains: 4,
    max_applets: 16,
    scp_version: ScpVersion::Scp02,
    max_rsa_key_bits: 2048,
    contact_protocols: &BOTH_PROTOCOLS,
    contactless: true,
    dap_supported: true,
    fips_mode: true,
    biometry: false,
    des_supported: true,
    sha1_supported: true,
    md5_supported: true,
    rsa_supported: true,
};

/// `JCOP31bio` profile: Dual-interface, 32KB, SCP02, biometry.
pub const JCOP31BIO_PROFILE: JcopProfile = JcopProfile {
    variant: JcopVariant::Jcop31Bio,
    eeprom_size: 32 * 1024,
    ram_transient_reset: 1200,
    ram_transient_deselect: 1100,
    apdu_buffer_size: 261,
    transaction_buffer_size: 768,
    max_security_domains: 4,
    max_applets: 16,
    scp_version: ScpVersion::Scp02,
    max_rsa_key_bits: 2048,
    contact_protocols: &BOTH_PROTOCOLS,
    contactless: true,
    dap_supported: true,
    fips_mode: false,
    biometry: true,
    des_supported: true,
    sha1_supported: true,
    md5_supported: true,
    rsa_supported: true,
};

/// All JCOP profiles in order.
pub const ALL_PROFILES: [JcopProfile; 5] = [
    JCOP10_PROFILE,
    JCOP20_PROFILE,
    JCOP21_PROFILE,
    JCOP21ID_PROFILE,
    JCOP31BIO_PROFILE,
];

/// Look up a profile by variant.
pub const fn profile_for(variant: JcopVariant) -> &'static JcopProfile {
    match variant {
        JcopVariant::Jcop10 => &JCOP10_PROFILE,
        JcopVariant::Jcop20 => &JCOP20_PROFILE,
        JcopVariant::Jcop21 => &JCOP21_PROFILE,
        JcopVariant::Jcop21Id => &JCOP21ID_PROFILE,
        JcopVariant::Jcop31Bio => &JCOP31BIO_PROFILE,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    #[test]
    fn all_profiles_have_261_byte_apdu_buffer() {
        for profile in &ALL_PROFILES {
            assert_eq!(profile.apdu_buffer_size, 261, "{:?}", profile.variant);
        }
    }

    #[test]
    fn jcop10_is_scp01() {
        assert_eq!(JCOP10_PROFILE.scp_version, ScpVersion::Scp01);
    }

    #[test]
    fn jcop20_plus_are_scp02() {
        for profile in &ALL_PROFILES[1..] {
            assert_eq!(
                profile.scp_version,
                ScpVersion::Scp02,
                "{:?}",
                profile.variant
            );
        }
    }

    #[test]
    fn jcop10_no_contactless() {
        assert!(!JCOP10_PROFILE.contactless);
        assert!(!JCOP20_PROFILE.contactless);
    }

    #[test]
    fn jcop21_plus_have_contactless() {
        assert!(JCOP21_PROFILE.contactless);
        assert!(JCOP21ID_PROFILE.contactless);
        assert!(JCOP31BIO_PROFILE.contactless);
    }

    #[test]
    fn jcop21id_has_dap_and_fips() {
        assert!(JCOP21ID_PROFILE.dap_supported);
        assert!(JCOP21ID_PROFILE.fips_mode);
    }

    #[test]
    fn jcop31bio_has_biometry() {
        assert!(JCOP31BIO_PROFILE.biometry);
        assert!(!JCOP21_PROFILE.biometry);
    }

    #[test]
    fn eeprom_sizes_ascending() {
        assert_eq!(JCOP10_PROFILE.eeprom_size, 8192);
        assert_eq!(JCOP20_PROFILE.eeprom_size, 16384);
        assert_eq!(JCOP21_PROFILE.eeprom_size, 16384);
        assert_eq!(JCOP21ID_PROFILE.eeprom_size, 32768);
        assert_eq!(JCOP31BIO_PROFILE.eeprom_size, 32768);
    }

    #[test]
    fn transaction_buffer_sizes() {
        assert_eq!(JCOP10_PROFILE.transaction_buffer_size, 512);
        assert_eq!(JCOP20_PROFILE.transaction_buffer_size, 512);
        assert_eq!(JCOP21_PROFILE.transaction_buffer_size, 512);
        assert_eq!(JCOP21ID_PROFILE.transaction_buffer_size, 768);
        assert_eq!(JCOP31BIO_PROFILE.transaction_buffer_size, 768);
    }

    #[test]
    fn max_rsa_key_bits() {
        assert_eq!(JCOP10_PROFILE.max_rsa_key_bits, 1024);
        for profile in &ALL_PROFILES[1..] {
            assert_eq!(profile.max_rsa_key_bits, 2048, "{:?}", profile.variant);
        }
    }

    #[test]
    fn max_security_domains() {
        assert_eq!(JCOP10_PROFILE.max_security_domains, 1);
        assert_eq!(JCOP20_PROFILE.max_security_domains, 2);
        assert_eq!(JCOP21ID_PROFILE.max_security_domains, 4);
    }

    #[test]
    fn profile_lookup() {
        assert_eq!(
            profile_for(JcopVariant::Jcop10).variant,
            JcopVariant::Jcop10
        );
        assert_eq!(
            profile_for(JcopVariant::Jcop31Bio).variant,
            JcopVariant::Jcop31Bio
        );
    }

    #[test]
    fn jcop10_no_sha1_md5() {
        assert!(!JCOP10_PROFILE.sha1_supported);
        assert!(!JCOP10_PROFILE.md5_supported);
    }

    #[test]
    fn jcop20_plus_have_sha1_md5() {
        for profile in &ALL_PROFILES[1..] {
            assert!(profile.sha1_supported, "{:?}", profile.variant);
            assert!(profile.md5_supported, "{:?}", profile.variant);
        }
    }

    #[test]
    fn all_have_des_and_rsa() {
        for profile in &ALL_PROFILES {
            assert!(profile.des_supported, "{:?}", profile.variant);
            assert!(profile.rsa_supported, "{:?}", profile.variant);
        }
    }
}
