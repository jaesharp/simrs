//! TCA eUICC Profile Package parser.
//!
//! Parses DER-encoded profile packages per the TCA (Trusted Connectivity
//! Alliance) eUICC Profile Package Interoperability Technical Specification
//! v3.3.1 and converts them into simrs filesystem trees.
//!
//! # Standards
//!
//! | Spec | Coverage |
//! |------|----------|
//! | TCA eUICC Profile Package v3.3.1 | Profile Element parsing, filesystem conversion |
//! | GSMA SGP.22 v2.6 | Profile Package is the UPP format from SGP.22 |
//! | [ETSI TS 102 221 V18.3.0](../../../docs/specs/etsi/ts-102-221/ts_102221v180300p.pdf) | FCP file descriptor interpretation |
//!
//! # Architecture
//!
//! ```text
//! DER bytes -> parse_profile_package() -> Vec<ProfileElement>
//!                                              |
//!                                         MutableTree
//!                                              |
//!                                         freeze() via Box::leak
//!                                              |
//!                                         ProfileConfig {
//!                                             mf: &'static DfDef,
//!                                             adf_table: &'static [AdfSlot],
//!                                             auth: AuthConfig,
//!                                             ...
//!                                         }
//! ```
//!
//! The `Box::leak` bridge converts heap-allocated parse results into the
//! `&'static` references that `FsData::init_with_adfs()` requires. This is
//! a one-time allocation when loading a profile, intentionally leaked for
//! process lifetime.
#![warn(missing_docs)]

pub mod convert;
pub mod der_util;
pub mod error;
pub mod fcp;
pub mod file;
pub mod pe;

pub use convert::auth::AuthConfig;
pub use convert::pin::{PinConfig, PukConfig};
pub use error::ProfileError;

use convert::auth::extract_auth;
use convert::pin::{extract_pins, extract_puks};
use convert::MutableTree;
use pe::ProfileElement;
use simrs_fs::{AdfSlot, DfDef};

/// Default ATR for profile-loaded SIMs.
///
/// TS 0 protocol, T=0, historical bytes "simrs-profile".
static DEFAULT_ATR: [u8; 18] = [
    0x3B, 0x9F, 0x95, 0x80, 0x1F, 0xC3, 0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x13, 0x57, 0x86, 0x81,
    0x02, 0x86,
];

/// Fully parsed profile ready for SIM initialization.
///
/// Contains all the data extracted from a TCA Profile Package:
/// the frozen filesystem tree, authentication parameters, and
/// PIN/PUK configurations.
pub struct ProfileConfig {
    /// ICCID (10 bytes, BCD-encoded).
    pub iccid: Vec<u8>,
    /// MF root of the frozen filesystem tree.
    pub mf: &'static DfDef,
    /// ADF table (maps AIDs to their root DFs).
    pub adf_table: &'static [AdfSlot],
    /// Authentication configuration (Milenage, TUAK, or None).
    pub auth: AuthConfig,
    /// PIN configurations extracted from PE-PINCodes.
    pub pins: Vec<PinConfig>,
    /// PUK configurations extracted from PE-PUKCodes.
    pub puks: Vec<PukConfig>,
    /// ATR bytes for this profile.
    pub atr: &'static [u8],
}

/// Load a TCA eUICC Profile Package from DER-encoded bytes.
///
/// Parses all Profile Elements, builds a filesystem tree, and extracts
/// authentication and PIN/PUK parameters. The filesystem tree is frozen
/// into `&'static` references via `Box::leak` -- this is intentional for
/// process-lifetime allocation.
///
/// # Errors
///
/// Returns [`ProfileError`] if:
/// - The DER structure is malformed
/// - Required PEs (Header, MF) are missing
/// - File data lengths don't match FCP declarations
/// - Auth parameters are invalid or unsupported
pub fn load_profile(der_bytes: &[u8]) -> Result<ProfileConfig, ProfileError> {
    let elements = pe::parse_profile_package(der_bytes)?;

    let mut tree = MutableTree::new();
    let mut iccid = Vec::new();
    let mut auth = AuthConfig::None;
    let mut pins = Vec::new();
    let mut puks = Vec::new();
    let mut had_header = false;
    let mut had_mf = false;
    let mut deferred_gfm = Vec::new();

    // First pass: process all template PEs, deferring GFM.
    // GFM commands reference paths created by template PEs (MF, USIM,
    // TELECOM, etc.) and must run after those PEs exist in the tree.
    for element in &elements {
        match element {
            ProfileElement::Header(hdr) => {
                iccid.clone_from(&hdr.iccid);
                had_header = true;
            }
            ProfileElement::Mf(pe_mf) => {
                tree.apply_mf(pe_mf)?;
                had_mf = true;
            }
            ProfileElement::Usim(pe_usim) => {
                tree.apply_usim(pe_usim)?;
            }
            ProfileElement::AkaParameter(pe_aka) => {
                auth = extract_auth(pe_aka)?;
            }
            ProfileElement::PinCodes(pe_pins) => {
                pins.extend(extract_pins(pe_pins));
            }
            ProfileElement::PukCodes(pe_puks) => {
                puks.extend(extract_puks(pe_puks));
            }
            ProfileElement::Gfm(pe_gfm) => {
                deferred_gfm.push(pe_gfm);
            }
            ProfileElement::Telecom(pe_telecom) => {
                tree.apply_telecom(pe_telecom)?;
            }
            ProfileElement::OptUsim(pe_opt_usim) => {
                tree.apply_opt_usim(pe_opt_usim)?;
            }
            ProfileElement::Isim(pe_isim) => {
                tree.apply_isim(pe_isim)?;
            }
            ProfileElement::OptIsim(pe_opt_isim) => {
                tree.apply_opt_isim(pe_opt_isim)?;
            }
            ProfileElement::Cd(pe_cd) => {
                tree.apply_cd(pe_cd)?;
            }
            ProfileElement::Phonebook(pe_phonebook) => {
                tree.apply_phonebook(pe_phonebook)?;
            }
            ProfileElement::GsmAccess(pe_gsm_access) => {
                tree.apply_gsm_access(pe_gsm_access)?;
            }
            ProfileElement::Csim(pe_csim) => {
                tree.apply_csim(pe_csim)?;
            }
            ProfileElement::OptCsim(pe_opt_csim) => {
                tree.apply_opt_csim(pe_opt_csim)?;
            }
            ProfileElement::Df5gs(pe_df_5gs) => {
                tree.apply_df_5gs(pe_df_5gs)?;
            }
            ProfileElement::DfSaip(pe_df_saip) => {
                tree.apply_df_saip(pe_df_saip)?;
            }
            ProfileElement::End => break,
            // Non-template PEs (CDMA, SecurityDomain, RFM) and
            // unknown/unsupported types have no filesystem impact.
            ProfileElement::CdmaParameter(_)
            | ProfileElement::SecurityDomain(_)
            | ProfileElement::Rfm(_)
            | ProfileElement::Unknown(_) => {}
        }
    }

    // Second pass: process deferred GFM commands.
    for pe_gfm in deferred_gfm {
        tree.apply_gfm(pe_gfm)?;
    }

    if !had_header {
        return Err(ProfileError::MissingHeader);
    }
    if !had_mf {
        return Err(ProfileError::MissingMf);
    }

    let (mf, adf_table) = tree.freeze()?;

    Ok(ProfileConfig {
        iccid,
        mf,
        adf_table,
        auth,
        pins,
        puks,
        atr: &DEFAULT_ATR,
    })
}
