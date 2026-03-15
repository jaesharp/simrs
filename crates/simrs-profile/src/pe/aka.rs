//! PE-AKAParameter parser.

use crate::der_util;
use crate::error::ProfileError;
use simrs_redact::Redact;

/// PE-AKAParameter: authentication algorithm configuration (tag 4).
#[derive(Clone, Debug)]
pub struct PeAkaParameter {
    /// Algorithm configuration (Milenage, TUAK, or mapping).
    pub algo: AlgoConfig,
    /// SQN management options (default 0x02).
    pub sqn_options: u8,
    /// SQN delta (6 bytes, default 0x000010000000).
    pub sqn_delta: [u8; 6],
    /// SQN age limit (6 bytes).
    pub sqn_age_limit: [u8; 6],
}

/// Algorithm configuration from PE-AKAParameter.
#[derive(Clone)]
pub enum AlgoConfig {
    /// Direct algorithm parameters.
    Algo {
        /// Algorithm ID: 1=Milenage, 2=TUAK, 3=XOR-3G.
        algorithm_id: u8,
        /// Subscriber key K (16 or 32 bytes).
        key: Vec<u8>,
        /// `OPc` (16 bytes for Milenage) or `TOPc` (32 bytes for TUAK).
        opc: Vec<u8>,
    },
    /// Mapping to another application's parameters.
    Mapping {
        /// Mapping options byte.
        options: u8,
        /// Source application AID.
        source_aid: Vec<u8>,
    },
}

impl core::fmt::Debug for AlgoConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Algo {
                algorithm_id,
                key,
                opc,
            } => f
                .debug_struct("AlgoConfig::Algo")
                .field("algorithm_id", algorithm_id)
                .field("key", &Redact(key.as_slice()))
                .field("opc", &Redact(opc.as_slice()))
                .finish(),
            Self::Mapping {
                options,
                source_aid,
            } => f
                .debug_struct("AlgoConfig::Mapping")
                .field("options", options)
                .field("source_aid", source_aid)
                .finish(),
        }
    }
}

impl PeAkaParameter {
    /// Parse `PE-AKAParameter` from the value bytes.
    ///
    /// `PE-AKAParameter` SEQUENCE with AUTOMATIC TAGS:
    /// - `[0]` `PEHeader`
    /// - `[1]` CHOICE { algoParameter | mappingParameter }
    /// - `[2]` OCTET STRING DEFAULT '02'H (sqnOptions)
    /// - `[3]` OCTET STRING DEFAULT ... (sqnDelta)
    /// - `[4]` OCTET STRING (sqnAgeLimit)
    /// - `[5]` SEQUENCE OF OCTET STRING (sqnInit)
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] if the DER structure is malformed or
    /// the algorithm configuration cannot be parsed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProfileError> {
        let inner = der_util::peel_optional_sequence(data)?;

        let tlvs: Vec<_> = der_util::iter_tlvs(inner).collect::<Result<_, _>>()?;

        // Tag [1] is the algoConfiguration CHOICE.
        // With AUTOMATIC TAGS on the outer SEQUENCE, algoConfiguration
        // gets tag [1]. The CHOICE inside uses its own tagging.
        let algo_tlv = tlvs
            .iter()
            .find(|t| t.number == 1 && t.class == 2)
            .ok_or(ProfileError::MissingAkaParameter)?;

        let algo = Self::parse_algo_config(algo_tlv.value)?;

        // sqnOptions: tag [2], default 0x02
        let sqn_options = tlvs
            .iter()
            .find(|t| t.number == 2 && t.class == 2)
            .and_then(|t| t.value.first().copied())
            .unwrap_or(0x02);

        // sqnDelta: tag [3], default 0x000010000000
        let sqn_delta = tlvs.iter().find(|t| t.number == 3 && t.class == 2).map_or(
            [0x00, 0x00, 0x10, 0x00, 0x00, 0x00],
            |t| {
                let mut arr = [0u8; 6];
                let len = t.value.len().min(6);
                arr[6 - len..].copy_from_slice(&t.value[..len]);
                arr
            },
        );

        // sqnAgeLimit: tag [4]
        let sqn_age_limit = tlvs.iter().find(|t| t.number == 4 && t.class == 2).map_or(
            [0x00, 0x00, 0x10, 0x00, 0x00, 0x00],
            |t| {
                let mut arr = [0u8; 6];
                let len = t.value.len().min(6);
                arr[6 - len..].copy_from_slice(&t.value[..len]);
                arr
            },
        );

        Ok(Self {
            algo,
            sqn_options,
            sqn_delta,
            sqn_age_limit,
        })
    }

    /// Parse the algoConfiguration CHOICE.
    fn parse_algo_config(data: &[u8]) -> Result<AlgoConfig, ProfileError> {
        // With AUTOMATIC TAGS on the TCA module, the CHOICE alternatives
        // are tagged in definition order:
        //   [0] = mappingParameter (MappingParameter)
        //   [1] = algoParameter (AlgoParameter)
        //
        // The outer PE-AKAParameter SEQUENCE applies EXPLICIT tagging to
        // the CHOICE field (since IMPLICIT can't tag a CHOICE directly).
        // So `data` here is the value inside the [1] EXPLICIT wrapper,
        // and starts with the CHOICE alternative tag.

        // Try to parse as raw SEQUENCE (algoParameter without CHOICE tags).
        if data.first() == Some(&0x30) {
            let seq = der_util::unwrap_sequence(data)?;
            return Self::parse_algo_parameter(seq);
        }

        // Check for context-specific tags within the CHOICE.
        let (tlv, _) = der_util::parse_tlv(data)?;
        if tlv.class == 2 && tlv.number == 0 {
            // [0] = mappingParameter
            return Self::parse_mapping_parameter(tlv.value);
        }
        if tlv.class == 2 && tlv.number == 1 {
            // [1] = algoParameter
            return Self::parse_algo_parameter(tlv.value);
        }

        // Fallback: try raw SEQUENCE
        Self::parse_algo_parameter(data)
    }

    /// Parse `AlgoParameter` SEQUENCE.
    fn parse_algo_parameter(data: &[u8]) -> Result<AlgoConfig, ProfileError> {
        let tlvs: Vec<_> = der_util::iter_tlvs(data).collect::<Result<_, _>>()?;

        // AlgoParameter fields (AUTOMATIC TAGS):
        // [0] INTEGER algorithmID
        // [1] OCTET STRING algorithmOptions
        // [2] OCTET STRING key
        // [3] OCTET STRING opc
        // [4] OCTET STRING rotationConstants (optional, default)
        // [5] OCTET STRING xoringConstants (optional, default)
        // [6] OCTET STRING authCounterMax (optional)
        // [7] INTEGER numberOfKeccak (optional, default 1)

        let algorithm_id = tlvs
            .iter()
            .find(|t| t.number == 0 && t.class == 2)
            .and_then(|t| t.value.last().copied())
            .unwrap_or(1);

        let key = tlvs
            .iter()
            .find(|t| t.number == 2 && t.class == 2)
            .map(|t| t.value.to_vec())
            .unwrap_or_default();

        let opc = tlvs
            .iter()
            .find(|t| t.number == 3 && t.class == 2)
            .map(|t| t.value.to_vec())
            .unwrap_or_default();

        Ok(AlgoConfig::Algo {
            algorithm_id,
            key,
            opc,
        })
    }

    /// Parse `MappingParameter` SEQUENCE.
    fn parse_mapping_parameter(data: &[u8]) -> Result<AlgoConfig, ProfileError> {
        let tlvs: Vec<_> = der_util::iter_tlvs(data).collect::<Result<_, _>>()?;

        let options = tlvs
            .first()
            .and_then(|t| t.value.first().copied())
            .unwrap_or(0);

        let source_aid = tlvs.get(1).map(|t| t.value.to_vec()).unwrap_or_default();

        Ok(AlgoConfig::Mapping {
            options,
            source_aid,
        })
    }
}
