//! PE-AKAParameter to simrs auth parameter conversion.

use crate::error::ProfileError;
use crate::pe::aka::{AlgoConfig, PeAkaParameter};

/// Extracted authentication configuration.
#[derive(Clone, Debug)]
pub enum AuthConfig {
    /// Milenage ([3GPP TS 35.206 V19.0.0](../../../../docs/specs/3gpp/ts-35.206/ts_135206v190000p.pdf)) authentication.
    Milenage {
        /// 128-bit subscriber key K.
        k: [u8; 16],
        /// 128-bit operator variant `OPc`.
        opc: [u8; 16],
    },
    /// TUAK ([3GPP TS 35.231 V19.0.0](../../../../docs/specs/3gpp/ts-35.231/ts_135231v190000p.pdf)) authentication.
    Tuak {
        /// 128-bit subscriber key K.
        k: [u8; 16],
        /// 256-bit operator variant `TOPc`.
        topc: [u8; 32],
    },
    /// No authentication parameters present.
    None,
}

/// Extract authentication configuration from a PE-AKAParameter.
///
/// # Errors
///
/// Returns [`ProfileError`] if the key length, `OPc`/`TOPc` length is
/// invalid, or if the algorithm ID is unsupported.
pub fn extract_auth(pe: &PeAkaParameter) -> Result<AuthConfig, ProfileError> {
    match &pe.algo {
        AlgoConfig::Algo {
            algorithm_id,
            key,
            opc,
        } => {
            let k: [u8; 16] = key
                .as_slice()
                .try_into()
                .map_err(|_| ProfileError::InvalidKeyLength)?;

            match algorithm_id {
                1 => {
                    // Milenage
                    let opc_arr: [u8; 16] = opc
                        .as_slice()
                        .try_into()
                        .map_err(|_| ProfileError::InvalidOpcLength)?;
                    Ok(AuthConfig::Milenage { k, opc: opc_arr })
                }
                2 => {
                    // TUAK
                    let topc: [u8; 32] = opc
                        .as_slice()
                        .try_into()
                        .map_err(|_| ProfileError::InvalidTopcLength)?;
                    Ok(AuthConfig::Tuak { k, topc })
                }
                3 => {
                    // XOR-3G test algorithm -- treat as Milenage with
                    // zeroed OPc (closest supported approximation).
                    let opc_arr: [u8; 16] = if opc.len() >= 16 {
                        opc[..16]
                            .try_into()
                            .map_err(|_| ProfileError::InvalidOpcLength)?
                    } else {
                        [0u8; 16]
                    };
                    Ok(AuthConfig::Milenage { k, opc: opc_arr })
                }
                id => Err(ProfileError::UnsupportedAlgorithm(*id)),
            }
        }
        AlgoConfig::Mapping { .. } => Err(ProfileError::MappingParameterNotSupported),
    }
}
