//! Differential test infrastructure for comparing simrs `GpCard` against
//! the Oracle Java Card Simulator (jcsl).
//!
//! Three layers:
//!
//! 1. **[`DiffSession`]** -- builder-pattern front-end for configuring
//!    differential test sessions. Wraps the interposer's [`DiffEngine`]
//!    with ergonomic backend selection and automatic resource management.
//!
//! 2. **[`DualCard`]** -- low-level harness for tests that need asymmetric
//!    access to both implementations (e.g., selecting different AIDs on
//!    each side, reconnecting Oracle after a reset).
//!
//! 3. **[`GpCardTerminal`]** -- wraps an in-process `GpCard` as a
//!    [`Transport`] for use in the interposer's comparison engine.
//!
//! # jcsl binary discovery
//!
//! The Oracle jcsl binary is located via [`discover_jcsl_binary()`], which
//! searches in order:
//!
//! 1. `SIMRS_JCSL_BINARY` environment variable (explicit override)
//! 2. `$XDG_CACHE_HOME/simrs/jcsl` (default: `~/.cache/simrs/jcsl`)
//! 3. Workspace-relative `tools/simrs-jcsl/vendor/oracle-jcvm-ref/runtime/bin/jcsl.orig`
//!
//! If none of these paths exist, all Oracle-dependent tests are skipped.
//!
//! ```bash
//! # Explicit path:
//! SIMRS_JCSL_BINARY=/path/to/jcsl cargo test -p simrs-differential-crossvalidation
//!
//! # Or place the binary in the XDG cache:
//! cp jcsl ~/.cache/simrs/jcsl
//! cargo test -p simrs-differential-crossvalidation
//! ```

pub mod known_divergences;
pub mod report;
mod session;

pub use session::{DiffSession, DiffSessionBuilder};

// Re-export key interposer types so consumers don't need to depend on
// simrs-interposer directly.
pub use simrs_interposer::diff::{DiffEngine, DiffRecord};
pub use simrs_interposer::divergence::{CompareResult, DivergenceStats};

use simrs_card_api::{SimEvent, SimResponse};
use simrs_gp_card::GpCard;
use simrs_gp_keys::KeySet;
use simrs_jcsl::configurator::{GlobalPin, ScpKeyset};
use simrs_jcsl::{JcslClient, JcslProcess};
use simrs_transport::{Transport, TransportError};

/// Allocate a free TCP port from the OS.
///
/// Binds to port 0, reads the assigned port, then drops the listener.
/// There is a small TOCTOU window, but this is far more reliable than
/// a hardcoded counter when multiple test binaries run in parallel.
pub(crate) fn next_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("OS should be able to allocate an ephemeral port")
        .local_addr()
        .expect("bound listener should have a local address")
        .port()
}

// Re-export jcsl discovery for convenience.
pub use simrs_jcsl::discover_binary as discover_jcsl_binary;

// ---------------------------------------------------------------------------
// GpCardTerminal -- wraps GpCard as Transport (mirrors SimTerminal pattern)
// ---------------------------------------------------------------------------

/// Wraps an in-process [`GpCard`] as a [`Transport`].
///
/// Mirrors the `SimTerminal` pattern from `simrs-interposer`:
/// APDU bytes in, data+SW bytes out. This allows `GpCard` to be
/// used interchangeably with `JcslClient` in the [`DiffEngine`].
pub struct GpCardTerminal {
    card: GpCard<261>,
    powered: bool,
}

impl GpCardTerminal {
    /// Create a new terminal wrapping the given card.
    pub const fn new(card: GpCard<261>) -> Self {
        Self {
            card,
            powered: false,
        }
    }

    /// Power on the card if not already powered.
    pub fn power_on(&mut self) {
        if !self.powered {
            let _ = self.card.process(SimEvent::PowerOn);
            self.powered = true;
        }
    }

    /// Access the inner card.
    pub const fn card(&self) -> &GpCard<261> {
        &self.card
    }
}

impl Transport for GpCardTerminal {
    type Error = TransportError;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, TransportError> {
        if !self.powered {
            self.power_on();
        }

        match self.card.process(SimEvent::Apdu(cmd)) {
            SimResponse::Apdu { data, sw } => {
                let [sw1, sw2] = sw.to_bytes();
                let len = data.len() + 2;
                if len > rsp.len() {
                    return Err(TransportError::BufferTooSmall);
                }
                rsp[..data.len()].copy_from_slice(data);
                rsp[data.len()] = sw1;
                rsp[data.len() + 1] = sw2;
                Ok(len)
            }
            SimResponse::Ignored | SimResponse::Atr(_) => {
                rsp[0] = 0x6F;
                rsp[1] = 0x00;
                Ok(2)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ApduResponse (structured response for individual test assertions)
// ---------------------------------------------------------------------------

/// Parsed APDU response: data bytes + status word.
#[derive(Clone)]
pub struct ApduResponse {
    /// Response data (excluding SW1 SW2).
    pub data: Vec<u8>,
    /// Status word as [SW1, SW2].
    pub sw: [u8; 2],
}

impl ApduResponse {
    /// Parse a raw response buffer (data || SW1 || SW2) into structured form.
    pub fn from_raw(raw: &[u8]) -> Self {
        if raw.len() < 2 {
            return Self {
                data: Vec::new(),
                sw: [0x6F, 0x00],
            };
        }
        let sw_off = raw.len() - 2;
        Self {
            data: raw[..sw_off].to_vec(),
            sw: [raw[sw_off], raw[sw_off + 1]],
        }
    }

    /// Status word as a u16 (e.g., 0x9000).
    pub const fn sw16(&self) -> u16 {
        u16::from_be_bytes(self.sw)
    }

    /// Whether the status word indicates success (90 00).
    pub fn is_success(&self) -> bool {
        self.sw == [0x90, 0x00]
    }
}

impl std::fmt::Debug for ApduResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ApduResponse {{ data[{}]: {:02x?}, sw: {:02X}{:02X} }}",
            self.data.len(),
            self.data,
            self.sw[0],
            self.sw[1],
        )
    }
}

// ---------------------------------------------------------------------------
// DualResponse (for individual tests)
// ---------------------------------------------------------------------------

/// Result of sending the same APDU to both implementations.
#[derive(Debug)]
pub struct DualResponse {
    /// Response from the simrs in-process `GpCard`.
    pub simrs: ApduResponse,
    /// Response from the Oracle jcsl simulator.
    pub oracle: ApduResponse,
}

impl DualResponse {
    /// Whether both implementations returned the same status word.
    pub fn sw_match(&self) -> bool {
        self.simrs.sw == self.oracle.sw
    }

    /// Whether both implementations returned the same SW1 byte.
    pub const fn sw1_match(&self) -> bool {
        self.simrs.sw[0] == self.oracle.sw[0]
    }
}

// ---------------------------------------------------------------------------
// Shared key material
// ---------------------------------------------------------------------------

/// SCP key bytes used for both simrs and Oracle jcsl.
///
/// Default `GlobalPlatform` test keys (all 0x40..0x4F).
pub const KEY_BYTES: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

/// ISD AID used by simrs (7 bytes, GP 2.1.1 default).
pub const SIMRS_ISD_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

/// ISD AID used by Oracle jcsl (8 bytes, GP 2.3 default).
pub const ORACLE_ISD_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

/// Build a SELECT-by-AID APDU: `00 A4 04 00 <Lc> <AID>`.
///
/// Returns a heap-allocated APDU suitable for use with [`DualCard::exchange`]
/// and [`DiffSession::replay_one`].
///
/// Note: `simrs-globalplatform-conformance-validation` has a similar `select_by_aid` that returns a
/// fixed-size `[u8; 261]` for its stack-buffer BDD harness. The two are
/// intentionally separate because they target different caller conventions.
#[allow(clippy::cast_possible_truncation)]
pub fn select_aid(aid: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    apdu.extend_from_slice(aid);
    apdu
}

// ---------------------------------------------------------------------------
// DualCard (low-level harness for individual tests)
// ---------------------------------------------------------------------------

/// Dual-card test harness.
///
/// Holds an in-process `GpCard` and a live connection to the Oracle jcsl
/// simulator. Methods send the same commands to both and collect the
/// results.
pub struct DualCard {
    /// In-process simrs card.
    pub simrs: GpCard<261>,
    /// Oracle jcsl TCP client.
    pub oracle: JcslClient,
    /// TCP port for reconnection.
    port: u16,
    /// Oracle jcsl process handle (dropped on test cleanup).
    _proc: JcslProcess,
}

impl DualCard {
    /// Power on both cards and return their ATRs.
    ///
    /// # Panics
    ///
    /// Panics if Oracle power-on fails.
    pub fn power_on(&mut self) -> (Vec<u8>, Vec<u8>) {
        let simrs_atr = match self.simrs.process(SimEvent::PowerOn) {
            SimResponse::Atr(atr) => atr.to_vec(),
            other => panic!("expected ATR from simrs PowerOn, got: {other:?}"),
        };
        let oracle_atr = self.oracle.power_on().expect("Oracle power_on failed");
        (simrs_atr, oracle_atr)
    }

    /// Send an APDU to both cards and collect responses.
    ///
    /// # Panics
    ///
    /// Panics if Oracle APDU exchange fails.
    pub fn exchange(&mut self, apdu: &[u8]) -> DualResponse {
        let simrs_rsp = match self.simrs.process(SimEvent::Apdu(apdu)) {
            SimResponse::Apdu { data, sw } => {
                let [sw1, sw2] = sw.to_bytes();
                ApduResponse {
                    data: data.to_vec(),
                    sw: [sw1, sw2],
                }
            }
            SimResponse::Ignored => ApduResponse {
                data: Vec::new(),
                sw: [0x6F, 0x00],
            },
            other @ SimResponse::Atr(_) => panic!("unexpected simrs response: {other:?}"),
        };

        let oracle_raw = self
            .oracle
            .transmit_apdu(apdu)
            .expect("Oracle APDU exchange failed");
        let oracle_rsp = ApduResponse::from_raw(&oracle_raw);

        DualResponse {
            simrs: simrs_rsp,
            oracle: oracle_rsp,
        }
    }

    /// Reconnect to the Oracle jcsl simulator.
    ///
    /// The jcsl server does not support power-cycling within a single TCP
    /// connection. Call this after a logical reset to establish a fresh
    /// session.
    ///
    /// # Panics
    ///
    /// Panics if the reconnection fails.
    pub fn reconnect_oracle(&mut self) {
        self.oracle = JcslClient::connect(&format!("127.0.0.1:{}", self.port))
            .expect("failed to reconnect to jcsl");
    }
}

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

/// Try to create a [`DualCard`] harness.
///
/// Returns `None` if `SIMRS_JCSL_BINARY` is not set or the binary
/// does not exist, allowing tests to skip gracefully.
///
/// The Oracle binary is configured and executed from an anonymous
/// memfd -- no temporary files are created.
///
/// # Panics
///
/// Panics if the binary exists but configuration or startup fails.
pub fn try_create_dual_card(_label: &str) -> Option<DualCard> {
    let src = discover_jcsl_binary()?;
    let port = next_port();

    let keyset = ScpKeyset {
        kvn: 0x01,
        enc: KEY_BYTES.to_vec(),
        mac: KEY_BYTES.to_vec(),
        dek: KEY_BYTES.to_vec(),
    };
    let gpin = GlobalPin {
        pin: vec![0x31, 0x32, 0x33, 0x34],
        max_retries: 3,
    };

    let proc = JcslProcess::start_configured(
        &src,
        Some(&keyset),
        Some(&gpin),
        port,
        "info",
        std::time::Duration::from_secs(10),
    )
    .expect("failed to start jcsl");

    let client =
        JcslClient::connect(&format!("127.0.0.1:{port}")).expect("failed to connect to jcsl");

    let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
    let mut card = GpCard::with_default_atr(&keys);
    // Add AES-128 keys at version 0x03 for SCP03 testing.
    let aes_keys = KeySet::aes128(KEY_BYTES, KEY_BYTES, KEY_BYTES);
    let _ = card.open_mut().add_key(0x03, &aes_keys);

    Some(DualCard {
        simrs: card,
        oracle: client,
        port,
        _proc: proc,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // ApduResponse snapshots
    // -------------------------------------------------------------------

    #[test]
    fn snap_apdu_response_success_no_data() {
        let rsp = ApduResponse::from_raw(&[0x90, 0x00]);
        insta::assert_snapshot!("apdu_rsp_success_no_data", format!("{rsp:?}"));
    }

    #[test]
    fn snap_apdu_response_success_with_data() {
        let rsp = ApduResponse::from_raw(&[
            0x66, 0x10, 0x73, 0x0E, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x60,
            0x03, 0x01, 0x02, 0x90, 0x00,
        ]);
        insta::assert_snapshot!("apdu_rsp_success_with_data", format!("{rsp:?}"));
    }

    #[test]
    fn snap_apdu_response_error_6a82() {
        let rsp = ApduResponse::from_raw(&[0x6A, 0x82]);
        insta::assert_snapshot!("apdu_rsp_error_6a82", format!("{rsp:?}"));
    }

    #[test]
    fn snap_apdu_response_short_buffer() {
        let rsp = ApduResponse::from_raw(&[0x90]);
        insta::assert_snapshot!("apdu_rsp_short_buffer", format!("{rsp:?}"));
    }

    #[test]
    fn snap_apdu_response_empty() {
        let rsp = ApduResponse::from_raw(&[]);
        insta::assert_snapshot!("apdu_rsp_empty", format!("{rsp:?}"));
    }

    // -------------------------------------------------------------------
    // GpCardTerminal snapshots (in-process, no jcsl needed)
    // -------------------------------------------------------------------

    #[test]
    fn snap_gp_terminal_select_isd() {
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let card = GpCard::with_default_atr(&keys);
        let mut terminal = GpCardTerminal::new(card);
        terminal.power_on();

        // SELECT ISD by AID
        let cmd = [
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00,
        ];
        let mut rsp = [0u8; 261];
        let n = terminal.exchange(&cmd, &mut rsp).unwrap();
        let parsed = ApduResponse::from_raw(&rsp[..n]);
        insta::assert_snapshot!("gp_terminal_select_isd", format!("{parsed:?}"));
    }

    #[test]
    fn snap_gp_terminal_select_unknown_aid() {
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let card = GpCard::with_default_atr(&keys);
        let mut terminal = GpCardTerminal::new(card);
        terminal.power_on();

        let cmd = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB];
        let mut rsp = [0u8; 261];
        let n = terminal.exchange(&cmd, &mut rsp).unwrap();
        let parsed = ApduResponse::from_raw(&rsp[..n]);
        insta::assert_snapshot!("gp_terminal_select_unknown", format!("{parsed:?}"));
    }

    #[test]
    fn snap_gp_terminal_get_data_0066() {
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let card = GpCard::with_default_atr(&keys);
        let mut terminal = GpCardTerminal::new(card);
        terminal.power_on();

        let cmd = [0x80, 0xCA, 0x00, 0x66];
        let mut rsp = [0u8; 261];
        let n = terminal.exchange(&cmd, &mut rsp).unwrap();
        let parsed = ApduResponse::from_raw(&rsp[..n]);
        insta::assert_snapshot!("gp_terminal_get_data_0066", format!("{parsed:?}"));
    }

    #[test]
    fn snap_gp_terminal_invalid_ins() {
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let card = GpCard::with_default_atr(&keys);
        let mut terminal = GpCardTerminal::new(card);
        terminal.power_on();

        let cmd = [0x80, 0xFD, 0x00, 0x00];
        let mut rsp = [0u8; 261];
        let n = terminal.exchange(&cmd, &mut rsp).unwrap();
        let parsed = ApduResponse::from_raw(&rsp[..n]);
        insta::assert_snapshot!("gp_terminal_invalid_ins", format!("{parsed:?}"));
    }

    #[test]
    fn snap_gp_terminal_init_update() {
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let card = GpCard::with_default_atr(&keys);
        let mut terminal = GpCardTerminal::new(card);
        terminal.power_on();

        // SELECT ISD first
        let sel = [
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00,
        ];
        let mut rsp = [0u8; 261];
        let _ = terminal.exchange(&sel, &mut rsp).unwrap();

        // INITIALIZE UPDATE
        let cmd = [
            0x80, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let n = terminal.exchange(&cmd, &mut rsp).unwrap();
        let parsed = ApduResponse::from_raw(&rsp[..n]);

        // INIT UPDATE response contains random card challenge, so snapshot
        // only the structure: data length and SW.
        let stable = format!(
            "sw={:02X}{:02X} data_len={} success={}",
            parsed.sw[0],
            parsed.sw[1],
            parsed.data.len(),
            parsed.is_success()
        );
        insta::assert_snapshot!("gp_terminal_init_update_structure", stable);
    }

    // -------------------------------------------------------------------
    // Constants snapshots
    // -------------------------------------------------------------------

    #[test]
    fn snap_key_bytes() {
        let hex: String = KEY_BYTES
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        insta::assert_snapshot!("key_bytes", hex);
    }

    #[test]
    fn snap_isd_aids() {
        let simrs_hex: String = SIMRS_ISD_AID
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let oracle_hex: String = ORACLE_ISD_AID
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let output = format!("simrs_isd:  {simrs_hex}\noracle_isd: {oracle_hex}");
        insta::assert_snapshot!("isd_aids", output);
    }

    // -------------------------------------------------------------------
    // DualResponse snapshots (constructed manually, no jcsl needed)
    // -------------------------------------------------------------------

    #[test]
    fn snap_dual_response_matching() {
        let dr = DualResponse {
            simrs: ApduResponse::from_raw(&[0x90, 0x00]),
            oracle: ApduResponse::from_raw(&[0x90, 0x00]),
        };
        let output = format!(
            "simrs: {:?}\noracle: {:?}\nsw_match: {}\nsw1_match: {}",
            dr.simrs,
            dr.oracle,
            dr.sw_match(),
            dr.sw1_match()
        );
        insta::assert_snapshot!("dual_response_matching", output);
    }

    #[test]
    fn snap_dual_response_sw_mismatch() {
        let dr = DualResponse {
            simrs: ApduResponse::from_raw(&[0x90, 0x00]),
            oracle: ApduResponse::from_raw(&[0x6A, 0x82]),
        };
        let output = format!(
            "simrs: {:?}\noracle: {:?}\nsw_match: {}\nsw1_match: {}",
            dr.simrs,
            dr.oracle,
            dr.sw_match(),
            dr.sw1_match()
        );
        insta::assert_snapshot!("dual_response_sw_mismatch", output);
    }

    #[test]
    fn snap_dual_response_sw1_match_sw2_differ() {
        let dr = DualResponse {
            simrs: ApduResponse::from_raw(&[0x6A, 0x82]),
            oracle: ApduResponse::from_raw(&[0x6A, 0x88]),
        };
        let output = format!(
            "simrs: {:?}\noracle: {:?}\nsw_match: {}\nsw1_match: {}",
            dr.simrs,
            dr.oracle,
            dr.sw_match(),
            dr.sw1_match()
        );
        insta::assert_snapshot!("dual_response_sw1_match_sw2_differ", output);
    }
}
