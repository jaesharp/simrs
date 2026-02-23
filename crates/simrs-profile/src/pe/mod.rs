//! Profile Element parsers.
//!
//! The TCA Profile Package is a `SEQUENCE OF ProfileElement` where each
//! `ProfileElement` is a CHOICE with context-specific IMPLICIT tags
//! (AUTOMATIC TAGS at module level).

pub mod aka;
pub mod df_5gs;
pub mod df_saip;
pub mod gfm;
pub mod gsm_access;
pub mod header;
pub mod isim;
pub mod mf;
pub mod opt_isim;
pub mod opt_usim;
pub mod pin;
pub mod telecom;
pub mod usim;

use crate::der_util;
use crate::error::ProfileError;
use crate::file::File;

pub use aka::{AlgoConfig, PeAkaParameter};
pub use df_5gs::PeDf5gs;
pub use df_saip::PeDfSaip;
pub use gfm::PeGfm;
pub use gsm_access::PeGsmAccess;
pub use header::ProfileHeader;
pub use isim::PeIsim;
pub use mf::PeMf;
pub use opt_isim::PeOptIsim;
pub use opt_usim::PeOptUsim;
pub use pin::{PePinCodes, PePukCodes, PinConfiguration, PukConfiguration};
pub use telecom::PeTelecom;
pub use usim::PeUsim;

/// Parse a template-based PE: skip header `[0]` and templateID `[1]`,
/// collect all constructed context-specific File fields from tags `[2]` onward.
///
/// Most PE types follow this pattern: `SEQUENCE { header PEHeader, templateID OID, file1 File, ... }`.
/// This helper collects the File-typed fields into `(tag_number, File)` pairs.
///
/// # Errors
///
/// Returns [`ProfileError`] if the DER structure is malformed.
pub fn parse_template_files(data: &[u8]) -> Result<Vec<(u8, File)>, ProfileError> {
    let inner = der_util::peel_optional_sequence(data)?;
    let mut files = Vec::new();
    for tlv_result in der_util::iter_tlvs(inner) {
        let tlv = tlv_result?;
        // Skip header [0] and templateID [1]; collect [2]+ as File fields.
        if tlv.class == 2 && tlv.number >= 2 {
            let file = File::from_bytes(tlv.value)?;
            files.push((tlv.number, file));
        }
    }
    Ok(files)
}

/// A parsed Profile Element from the TCA Profile Package.
///
/// Tag assignments per TCA v3.3.1 ASN.1 with AUTOMATIC TAGS:
///
/// | Tag | PE Type |
/// |-----|---------|
/// | 0 | `ProfileHeader` |
/// | 1 | `PE-GenericFileManagement` |
/// | 2 | `PE-PINCodes` |
/// | 3 | `PE-PUKCodes` |
/// | 4 | `PE-AKAParameter` |
/// | 5-9 | CDMA, SecurityDomain, RFM, Application, NonStandard |
/// | 10 | `PE-End` |
/// | 11-15 | Reserved (PE-Dummy) |
/// | 16 | `PE-MF` |
/// | 17 | `PE-CD` |
/// | 18 | `PE-TELECOM` |
/// | 19 | `PE-USIM` |
/// | 20 | `PE-OPT-USIM` |
/// | 21 | `PE-ISIM` |
/// | 22 | `PE-OPT-ISIM` |
/// | 23 | `PE-PHONEBOOK` |
/// | 24 | `PE-GSM-ACCESS` |
/// | 25-33 | CSIM, OPT-CSIM, EAP, DF-5GS, DF-SAIP, DF-SNPN, ... |
#[derive(Clone, Debug)]
pub enum ProfileElement {
    /// Profile header (tag 0). Must be the first element.
    Header(ProfileHeader),
    /// PIN codes (tag 2).
    PinCodes(PePinCodes),
    /// PUK codes (tag 3).
    PukCodes(PePukCodes),
    /// AKA authentication parameters (tag 4).
    AkaParameter(PeAkaParameter),
    /// End marker (tag 10).
    End,
    /// Master File structure (tag 16).
    Mf(Box<PeMf>),
    /// USIM application (tag 19).
    Usim(Box<PeUsim>),
    /// Generic file management (tag 1).
    Gfm(PeGfm),
    /// DF.TELECOM structure (tag 18).
    Telecom(Box<PeTelecom>),
    /// Optional USIM EFs (tag 20).
    OptUsim(Box<PeOptUsim>),
    /// ISIM application (tag 21).
    Isim(Box<PeIsim>),
    /// Optional ISIM EFs (tag 22).
    OptIsim(Box<PeOptIsim>),
    /// DF.GSM-ACCESS under ADF.USIM (tag 24).
    GsmAccess(Box<PeGsmAccess>),
    /// DF.5GS under ADF.USIM (tag 28).
    Df5gs(Box<PeDf5gs>),
    /// DF.SAIP under ADF.USIM (tag 29).
    DfSaip(Box<PeDfSaip>),
    /// Unknown/unsupported PE type (silently skipped).
    Unknown(u8),
}

/// Parse a complete TCA Profile Package from DER bytes.
///
/// The input may be:
/// - A raw concatenation of `ProfileElement` TLVs (as found in pySim test
///   profiles and most tooling output)
/// - Wrapped in a SEQUENCE (tag 0x30)
/// - Wrapped in a context-tagged SEQUENCE (`[2]` per `EUICCProfilePackage`)
///
/// Unknown PE types are recorded as `ProfileElement::Unknown(tag_number)`
/// and silently skipped -- this provides forward compatibility with newer
/// TCA spec versions.
///
/// # Errors
///
/// Returns [`ProfileError`] if the DER structure is malformed or if a
/// known PE type contains invalid data.
pub fn parse_profile_package(
    der_bytes: &[u8],
) -> Result<Vec<ProfileElement>, ProfileError> {
    // Detect whether input is wrapped in SEQUENCE or is raw PE concatenation.
    let inner = if der_bytes.first() == Some(&0x30) {
        // SEQUENCE-wrapped: unwrap to get inner content.
        der_util::unwrap_sequence(der_bytes)?
    } else if der_bytes.first().is_some_and(|&b| b == 0xA2) {
        // [2] SEQUENCE wrapper (EUICCProfilePackage): peel both layers.
        let (outer, _) = der_util::parse_tlv(der_bytes)?;
        der_util::unwrap_sequence(outer.value)?
    } else {
        // Raw PE concatenation (most common in test profiles).
        der_bytes
    };

    let mut elements = Vec::new();

    for tlv_result in der_util::iter_tlvs(inner) {
        let tlv = tlv_result?;

        // ProfileElement CHOICE uses context-specific constructed tags.
        // Tag class must be context-specific (class 2).
        if tlv.class != 2 {
            // Not a context-specific tag -- skip.
            elements.push(ProfileElement::Unknown(tlv.tag));
            continue;
        }

        let pe = match tlv.number {
            0 => ProfileElement::Header(ProfileHeader::from_bytes(tlv.value)?),
            2 => ProfileElement::PinCodes(PePinCodes::from_bytes(tlv.value)?),
            3 => ProfileElement::PukCodes(PePukCodes::from_bytes(tlv.value)?),
            4 => {
                ProfileElement::AkaParameter(PeAkaParameter::from_bytes(tlv.value)?)
            }
            1 => ProfileElement::Gfm(PeGfm::from_bytes(tlv.value)?),
            10 => ProfileElement::End,
            16 => ProfileElement::Mf(Box::new(PeMf::from_bytes(tlv.value)?)),
            18 => ProfileElement::Telecom(Box::new(PeTelecom::from_bytes(tlv.value)?)),
            19 => ProfileElement::Usim(Box::new(PeUsim::from_bytes(tlv.value)?)),
            20 => ProfileElement::OptUsim(Box::new(PeOptUsim::from_bytes(tlv.value)?)),
            21 => ProfileElement::Isim(Box::new(PeIsim::from_bytes(tlv.value)?)),
            22 => ProfileElement::OptIsim(Box::new(PeOptIsim::from_bytes(tlv.value)?)),
            24 => ProfileElement::GsmAccess(Box::new(PeGsmAccess::from_bytes(tlv.value)?)),
            28 => ProfileElement::Df5gs(Box::new(PeDf5gs::from_bytes(tlv.value)?)),
            29 => ProfileElement::DfSaip(Box::new(PeDfSaip::from_bytes(tlv.value)?)),
            tag => ProfileElement::Unknown(tag),
        };

        elements.push(pe);
    }

    Ok(elements)
}
