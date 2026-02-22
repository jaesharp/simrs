//! Response comparison and divergence tracking.

/// Result of comparing a real SIM response with a shadow SIM response.
#[derive(Debug, PartialEq, Eq)]
pub enum CompareResult {
    /// Both responses match (same SW and same data).
    Match,
    /// Status words differ.
    SwMismatch {
        /// Real SIM status word.
        real_sw: (u8, u8),
        /// Shadow SIM status word.
        shadow_sw: (u8, u8),
    },
    /// Status words match but response data differs.
    DataMismatch {
        /// Common status word.
        sw: (u8, u8),
        /// Length of real response data.
        real_len: usize,
        /// Length of shadow response data.
        shadow_len: usize,
    },
    /// Shadow SIM returned `Ignored` (did not process the APDU).
    ShadowIgnored {
        /// Real SIM status word.
        real_sw: (u8, u8),
    },
}

/// Accumulated divergence statistics across an interposer session.
#[derive(Debug, Default)]
pub struct DivergenceStats {
    /// Total APDUs processed.
    pub total_apdus: u64,
    /// APDUs where real and shadow responses matched.
    pub matches: u64,
    /// APDUs where status words differed.
    pub sw_mismatches: u64,
    /// APDUs where data content differed (SW matched).
    pub data_mismatches: u64,
    /// APDUs where the shadow SIM returned Ignored.
    pub shadow_ignored: u64,
}

impl DivergenceStats {
    /// Record a comparison result into the stats.
    pub const fn record(&mut self, result: &CompareResult) {
        self.total_apdus += 1;
        match result {
            CompareResult::Match => self.matches += 1,
            CompareResult::SwMismatch { .. } => self.sw_mismatches += 1,
            CompareResult::DataMismatch { .. } => self.data_mismatches += 1,
            CompareResult::ShadowIgnored { .. } => self.shadow_ignored += 1,
        }
    }
}

/// Compare real versus shadow APDU responses.
///
/// If `shadow` is `None`, the shadow SIM ignored the APDU.
pub fn compare_responses(
    real_data: &[u8],
    real_sw1: u8,
    real_sw2: u8,
    shadow: Option<(&[u8], u8, u8)>,
) -> CompareResult {
    let Some((shadow_data, shadow_sw1, shadow_sw2)) = shadow else {
        return CompareResult::ShadowIgnored {
            real_sw: (real_sw1, real_sw2),
        };
    };

    if real_sw1 != shadow_sw1 || real_sw2 != shadow_sw2 {
        return CompareResult::SwMismatch {
            real_sw: (real_sw1, real_sw2),
            shadow_sw: (shadow_sw1, shadow_sw2),
        };
    }

    if real_data != shadow_data {
        return CompareResult::DataMismatch {
            sw: (real_sw1, real_sw2),
            real_len: real_data.len(),
            shadow_len: shadow_data.len(),
        };
    }

    CompareResult::Match
}

/// Format a hex dump of bytes for logging.
pub fn hex_dump(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Format a divergence for stderr logging.
pub fn format_divergence(
    cmd: &[u8],
    result: &CompareResult,
    seq_num: u64,
) -> String {
    let cmd_hex = hex_dump(cmd);
    match result {
        CompareResult::Match => {
            format!("[{seq_num}] MATCH cmd={cmd_hex}")
        }
        CompareResult::SwMismatch {
            real_sw,
            shadow_sw,
        } => {
            format!(
                "[{seq_num}] SW MISMATCH cmd={cmd_hex} real={:02X}{:02X} shadow={:02X}{:02X}",
                real_sw.0, real_sw.1, shadow_sw.0, shadow_sw.1
            )
        }
        CompareResult::DataMismatch {
            sw,
            real_len,
            shadow_len,
        } => {
            format!(
                "[{seq_num}] DATA MISMATCH cmd={cmd_hex} sw={:02X}{:02X} real_len={real_len} shadow_len={shadow_len}",
                sw.0, sw.1
            )
        }
        CompareResult::ShadowIgnored { real_sw } => {
            format!(
                "[{seq_num}] SHADOW IGNORED cmd={cmd_hex} real_sw={:02X}{:02X}",
                real_sw.0, real_sw.1
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- compare_responses tests --

    #[test]
    fn compare_match() {
        let result = compare_responses(&[0x01, 0x02], 0x90, 0x00, Some((&[0x01, 0x02], 0x90, 0x00)));
        assert_eq!(result, CompareResult::Match);
    }

    #[test]
    fn compare_empty_data_match() {
        let result = compare_responses(&[], 0x90, 0x00, Some((&[], 0x90, 0x00)));
        assert_eq!(result, CompareResult::Match);
    }

    #[test]
    fn compare_sw_mismatch() {
        let result = compare_responses(&[], 0x90, 0x00, Some((&[], 0x6E, 0x00)));
        assert_eq!(
            result,
            CompareResult::SwMismatch {
                real_sw: (0x90, 0x00),
                shadow_sw: (0x6E, 0x00),
            }
        );
    }

    #[test]
    fn compare_data_mismatch() {
        let result = compare_responses(
            &[0x01, 0x02],
            0x90,
            0x00,
            Some((&[0x03, 0x04], 0x90, 0x00)),
        );
        assert_eq!(
            result,
            CompareResult::DataMismatch {
                sw: (0x90, 0x00),
                real_len: 2,
                shadow_len: 2,
            }
        );
    }

    #[test]
    fn compare_data_length_mismatch() {
        let result = compare_responses(
            &[0x01],
            0x61,
            0x0F,
            Some((&[0x01, 0x02, 0x03], 0x61, 0x0F)),
        );
        assert_eq!(
            result,
            CompareResult::DataMismatch {
                sw: (0x61, 0x0F),
                real_len: 1,
                shadow_len: 3,
            }
        );
    }

    #[test]
    fn compare_shadow_ignored() {
        let result = compare_responses(&[0x01], 0x90, 0x00, None);
        assert_eq!(
            result,
            CompareResult::ShadowIgnored {
                real_sw: (0x90, 0x00),
            }
        );
    }

    // -- stats tests --

    #[test]
    fn stats_accumulation() {
        let mut stats = DivergenceStats::default();

        stats.record(&CompareResult::Match);
        stats.record(&CompareResult::Match);
        stats.record(&CompareResult::SwMismatch {
            real_sw: (0x90, 0x00),
            shadow_sw: (0x6E, 0x00),
        });
        stats.record(&CompareResult::DataMismatch {
            sw: (0x90, 0x00),
            real_len: 10,
            shadow_len: 5,
        });
        stats.record(&CompareResult::ShadowIgnored {
            real_sw: (0x90, 0x00),
        });

        assert_eq!(stats.total_apdus, 5);
        assert_eq!(stats.matches, 2);
        assert_eq!(stats.sw_mismatches, 1);
        assert_eq!(stats.data_mismatches, 1);
        assert_eq!(stats.shadow_ignored, 1);
    }

    #[test]
    fn stats_default_is_zero() {
        let stats = DivergenceStats::default();
        assert_eq!(stats.total_apdus, 0);
        assert_eq!(stats.matches, 0);
        assert_eq!(stats.sw_mismatches, 0);
        assert_eq!(stats.data_mismatches, 0);
        assert_eq!(stats.shadow_ignored, 0);
    }

    // -- hex_dump tests --

    #[test]
    fn hex_dump_basic() {
        assert_eq!(hex_dump(&[0x00, 0xA4, 0x00, 0x04]), "00 A4 00 04");
    }

    #[test]
    fn hex_dump_empty() {
        assert_eq!(hex_dump(&[]), "");
    }

    #[test]
    fn hex_dump_single_byte() {
        assert_eq!(hex_dump(&[0xFF]), "FF");
    }

    // -- format_divergence tests --

    #[test]
    fn format_divergence_match() {
        let msg = format_divergence(
            &[0x00, 0xA4],
            &CompareResult::Match,
            42,
        );
        assert!(msg.contains("[42]"));
        assert!(msg.contains("MATCH"));
        assert!(msg.contains("00 A4"));
    }

    #[test]
    fn format_divergence_sw_mismatch() {
        let msg = format_divergence(
            &[0x00, 0xA4],
            &CompareResult::SwMismatch {
                real_sw: (0x90, 0x00),
                shadow_sw: (0x6E, 0x00),
            },
            7,
        );
        assert!(msg.contains("[7]"));
        assert!(msg.contains("SW MISMATCH"));
        assert!(msg.contains("9000"));
        assert!(msg.contains("6E00"));
    }

    #[test]
    fn format_divergence_data_mismatch() {
        let msg = format_divergence(
            &[0x00, 0xB0],
            &CompareResult::DataMismatch {
                sw: (0x90, 0x00),
                real_len: 10,
                shadow_len: 5,
            },
            3,
        );
        assert!(msg.contains("DATA MISMATCH"));
        assert!(msg.contains("real_len=10"));
        assert!(msg.contains("shadow_len=5"));
    }

    #[test]
    fn format_divergence_shadow_ignored() {
        let msg = format_divergence(
            &[0xF0, 0xFF],
            &CompareResult::ShadowIgnored {
                real_sw: (0x6D, 0x00),
            },
            1,
        );
        assert!(msg.contains("SHADOW IGNORED"));
        assert!(msg.contains("6D00"));
    }
}
