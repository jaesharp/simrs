//! Main interposer event loop.

use simrs_transport::{CardEvent, CardTransport, Transport, TransportError};
use simrs_transport_tcp::{SwIccClient, SwIccTerminal};

use crate::capture::PcapCapture;
use crate::divergence::{compare_responses, format_divergence, CompareResult, DivergenceStats};
use crate::mode::{InterposerConfig, InterposerMode};
use crate::shadow::ShadowSim;

// ---------------------------------------------------------------------------
// Error wrapper
// ---------------------------------------------------------------------------

/// Interposer error type, wrapping transport and I/O errors.
#[derive(Debug)]
pub enum InterposerError {
    /// Transport-layer error.
    Transport(TransportError),
    /// File I/O error.
    Io(std::io::Error),
    /// Other error (string description).
    Other(String),
}

impl std::fmt::Display for InterposerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for InterposerError {}

impl From<TransportError> for InterposerError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

impl From<std::io::Error> for InterposerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ---------------------------------------------------------------------------
// ProxyLoop
// ---------------------------------------------------------------------------

/// The main proxy event loop.
///
/// Sits between a modem (via SwIccClient) and optionally N real SIM cards
/// (via SwIccTerminal), with optional shadow comparison and PCAP capture.
pub struct ProxyLoop {
    modem: SwIccClient,
    /// Single card connection (for Log/Shadow/Replace modes).
    card: Option<SwIccTerminal>,
    /// Multiple card connections for Diff mode (N-way comparison).
    #[allow(dead_code)]
    diff_cards: Vec<SwIccTerminal>,
    shadow: Option<ShadowSim>,
    capture: Option<PcapCapture>,
    stats: DivergenceStats,
    seq_num: u64,
    mode: InterposerMode,
    cmd_buf: [u8; 261],
    rsp_buf: [u8; 261],
}

impl ProxyLoop {
    /// Connect to the configured swICC servers and create a proxy loop.
    ///
    /// # Errors
    ///
    /// Returns an error if TCP connections fail or PCAP file creation fails.
    pub fn connect(config: &InterposerConfig) -> Result<Self, InterposerError> {
        let modem = SwIccClient::connect(&config.modem_addr)?;

        // Single card connection for Log/Shadow/Replace modes.
        let card = config
            .card_addr
            .as_ref()
            .map(|addr| SwIccTerminal::connect(addr))
            .transpose()?;

        // Multiple card connections for Diff mode (N-way comparison).
        let diff_cards = config
            .card_addrs
            .iter()
            .map(|addr| SwIccTerminal::connect(addr))
            .collect::<Result<Vec<_>, _>>()?;

        let capture = config
            .pcap_path
            .as_ref()
            .map(|path| PcapCapture::create(path, config.link_type))
            .transpose()?;

        // Build shadow sim if auth config is provided and mode requires it.
        let shadow = config
            .auth
            .as_ref()
            .filter(|_| matches!(config.mode, InterposerMode::Shadow | InterposerMode::Replace))
            .map(|auth| ShadowSim::new(auth, &SHADOW_ATR, &SHADOW_MF));

        Ok(Self {
            modem,
            card,
            diff_cards,
            shadow,
            capture,
            stats: DivergenceStats::default(),
            seq_num: 0,
            mode: config.mode,
            cmd_buf: [0u8; 261],
            rsp_buf: [0u8; 261],
        })
    }

    /// Create a proxy loop from pre-made components (for testing).
    ///
    /// Parameters: (modem, card, diff_cards, shadow, capture, mode)
    #[cfg(test)]
    pub fn from_parts(
        modem: SwIccClient,
        card: Option<SwIccTerminal>,
        diff_cards: Vec<SwIccTerminal>,
        shadow: Option<ShadowSim>,
        capture: Option<PcapCapture>,
        mode: InterposerMode,
    ) -> Self {
        Self {
            modem,
            card,
            diff_cards,
            shadow,
            capture,
            stats: DivergenceStats::default(),
            seq_num: 0,
            mode,
            cmd_buf: [0u8; 261],
            rsp_buf: [0u8; 261],
        }
    }

    /// Process a single event from the modem side.
    ///
    /// Returns `false` if the session should end (Shutdown or disconnect).
    ///
    /// # Errors
    ///
    /// Returns an error on transport or I/O failures.
    pub fn step(&mut self) -> Result<bool, InterposerError> {
        let event = self.modem.recv(&mut self.cmd_buf)?;

        match event {
            CardEvent::PowerOn | CardEvent::WarmReset => {
                self.handle_reset(event)?;
            }
            CardEvent::Apdu(len) => {
                self.handle_apdu(len)?;
            }
            CardEvent::Shutdown => {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Run the main event loop until shutdown or error.
    ///
    /// # Errors
    ///
    /// Returns an error on transport or I/O failures.
    pub fn run(&mut self) -> Result<(), InterposerError> {
        loop {
            if !self.step()? {
                break;
            }
        }
        if let Some(cap) = &mut self.capture {
            cap.flush()?;
        }
        Ok(())
    }

    /// Print summary statistics to stderr.
    pub fn print_summary(&self) {
        eprintln!(
            "[simrs-interposer] summary: total={} match={} sw_mismatch={} data_mismatch={} ignored={}",
            self.stats.total_apdus,
            self.stats.matches,
            self.stats.sw_mismatches,
            self.stats.data_mismatches,
            self.stats.shadow_ignored,
        );
    }

    /// Access the accumulated stats (for testing).
    #[cfg(test)]
    pub const fn stats(&self) -> &DivergenceStats {
        &self.stats
    }

    // -- internal handlers --

    /// Handle a power-on or warm reset event.
    fn handle_reset(
        &mut self,
        event: CardEvent,
    ) -> Result<(), InterposerError> {
        let is_cold = event == CardEvent::PowerOn;

        // Handle Diff mode reset - reset all cards and use first ATR
        if self.mode == InterposerMode::Diff && !self.diff_cards.is_empty() {
            return self.handle_reset_diff(is_cold);
        }

        // Get ATR from real card if available.
        let atr_data: Vec<u8> = self
            .card
            .as_mut()
            .map(|card| {
                if is_cold {
                    card.reset_cold()
                } else {
                    card.reset_warm()
                }
            })
            .transpose()?
            .map_or_else(Vec::new, |msg| msg.buf().to_vec());

        // Process shadow SIM.
        let shadow_atr: Vec<u8> = self
            .shadow
            .as_mut()
            .map_or_else(Vec::new, |shadow| {
                if is_cold {
                    shadow.power_on().to_vec()
                } else {
                    shadow.reset().to_vec()
                }
            });

        // Record ATR in PCAP.
        if let Some(cap) = &mut self.capture {
            if !atr_data.is_empty() {
                cap.record_atr(&atr_data)?;
            }
        }

        // Send ATR to modem.
        // In Replace mode with shadow, use shadow ATR.
        let send_atr = if self.mode == InterposerMode::Replace && !shadow_atr.is_empty() {
            &shadow_atr
        } else {
            &atr_data
        };

        if !send_atr.is_empty() {
            self.modem.send_atr(send_atr)?;
        }

        Ok(())
    }

    /// Handle reset in Diff mode - reset all N cards.
    fn handle_reset_diff(&mut self, is_cold: bool) -> Result<(), InterposerError> {
        let mut atr_data: Vec<u8> = vec![];

        for card in &mut self.diff_cards {
            let msg = if is_cold {
                card.reset_cold()
            } else {
                card.reset_warm()
            };
            // Use first successful ATR
            if atr_data.is_empty() {
                if let Ok(msg) = msg {
                    atr_data = msg.buf().to_vec();
                }
            }
        }

        // Record ATR in PCAP.
        if let Some(cap) = &mut self.capture {
            if !atr_data.is_empty() {
                cap.record_atr(&atr_data)?;
            }
        }

        // Send ATR to modem.
        if !atr_data.is_empty() {
            self.modem.send_atr(&atr_data)?;
        }

        Ok(())
    }

    /// Handle an APDU event.
    #[allow(clippy::too_many_lines)]
    fn handle_apdu(&mut self, len: usize) -> Result<(), InterposerError> {
        self.seq_num += 1;

        // Copy the command so we can use it after borrowing self.
        let mut cmd = [0u8; 261];
        cmd[..len].copy_from_slice(&self.cmd_buf[..len]);
        let cmd_slice = &cmd[..len];

        // Record command APDU in PCAP.
        if let Some(cap) = &mut self.capture {
            cap.record_apdu(simrs_pcap::Direction::Command, cmd_slice)?;
        }

        // Handle Diff mode - N-way comparison
        if self.mode == InterposerMode::Diff && !self.diff_cards.is_empty() {
            return self.handle_apdu_diff(cmd_slice);
        }

        // Forward to real card.
        let real_result: Option<(Vec<u8>, u8, u8)> = if let Some(card) = &mut self.card {
            let n = card.exchange(cmd_slice, &mut self.rsp_buf)?;
            if n >= 2 {
                let sw1 = self.rsp_buf[n - 2];
                let sw2 = self.rsp_buf[n - 1];
                let data = self.rsp_buf[..n - 2].to_vec();
                Some((data, sw1, sw2))
            } else {
                None
            }
        } else {
            None
        };

        // Process through shadow SIM.
        let shadow_result: Option<(Vec<u8>, u8, u8)> = self.shadow.as_mut().and_then(|shadow| {
            shadow
                .process_apdu(cmd_slice)
                .map(|(data, sw1, sw2)| (data.to_vec(), sw1, sw2))
        });

        // Compare if both are present.
        if let Some((ref real_data, real_sw1, real_sw2)) = real_result {
            let shadow_ref = shadow_result
                .as_ref()
                .map(|(d, s1, s2)| (d.as_slice(), *s1, *s2));

            let cmp = compare_responses(real_data, real_sw1, real_sw2, shadow_ref);

            if cmp != CompareResult::Match {
                let msg = format_divergence(cmd_slice, &cmp, self.seq_num);
                eprintln!("[simrs-interposer] {msg}");

                // Record mismatch in PCAP.
                if let Some(cap) = &mut self.capture {
                    let mut full_rsp = real_data.clone();
                    full_rsp.push(real_sw1);
                    full_rsp.push(real_sw2);
                    cap.record_apdu_mismatch(
                        simrs_pcap::Direction::Response,
                        &full_rsp,
                    )?;
                }
            }

            self.stats.record(&cmp);
        }

        // Determine what to send back to the modem.
        let response_to_send = self.build_response(real_result, shadow_result);

        // Record response in PCAP.
        if let Some(cap) = &mut self.capture {
            cap.record_apdu(simrs_pcap::Direction::Response, &response_to_send)?;
        }

        // Send response to modem.
        self.modem.send(&response_to_send)?;

        Ok(())
    }

    /// Handle APDU in Diff mode - compare N card responses.
    fn handle_apdu_diff(&mut self, cmd_slice: &[u8]) -> Result<(), InterposerError> {
        // Collect responses from all diff cards
        let mut card_responses: Vec<(Vec<u8>, u8, u8)> = Vec::new();
        let mut rsp_buf = [0u8; 261];

        for card in &mut self.diff_cards {
            let n = card.exchange(cmd_slice, &mut rsp_buf)?;
            if n >= 2 {
                let sw1 = rsp_buf[n - 2];
                let sw2 = rsp_buf[n - 1];
                let data = rsp_buf[..n - 2].to_vec();
                card_responses.push((data, sw1, sw2));
            } else {
                card_responses.push((vec![], 0x6F, 0x00));
            }
        }

        // Compare all responses pairwise
        if card_responses.len() >= 2 {
            let first = &card_responses[0];
            for (idx, resp) in card_responses.iter().enumerate().skip(1) {
                let cmp = compare_responses(
                    &first.0,
                    first.1,
                    first.2,
                    Some((&resp.0, resp.1, resp.2)),
                );
                self.stats.record(&cmp);

                if cmp != CompareResult::Match {
                    eprintln!(
                        "[simrs-interposer] Diff: card 0 vs card {idx}: {cmp:?}",
                    );
                }
            }
        }

        // Return first card's response
        let response = card_responses
            .first()
            .map_or_else(|| vec![0x6F, 0x00], |(data, sw1, sw2)| {
                let mut rsp = data.clone();
                rsp.push(*sw1);
                rsp.push(*sw2);
                rsp
            });

        // Record response in PCAP.
        if let Some(cap) = &mut self.capture {
            cap.record_apdu(simrs_pcap::Direction::Response, &response)?;
        }

        // Send response to modem.
        self.modem.send(&response)?;

        Ok(())
    }

    /// Build the response bytes to send back to the modem.
    fn build_response(
        &self,
        real: Option<(Vec<u8>, u8, u8)>,
        shadow: Option<(Vec<u8>, u8, u8)>,
    ) -> Vec<u8> {
        let pack = |data: Vec<u8>, sw1: u8, sw2: u8| -> Vec<u8> {
            let mut rsp = data;
            rsp.push(sw1);
            rsp.push(sw2);
            rsp
        };

        match self.mode {
            InterposerMode::Replace => {
                if let Some((d, s1, s2)) = shadow {
                    pack(d, s1, s2)
                } else if let Some((d, s1, s2)) = real {
                    pack(d, s1, s2)
                } else {
                    vec![0x6F, 0x00]
                }
            }
            InterposerMode::Log | InterposerMode::Shadow => {
                if let Some((d, s1, s2)) = real {
                    pack(d, s1, s2)
                } else if let Some((d, s1, s2)) = shadow {
                    pack(d, s1, s2)
                } else {
                    vec![0x6F, 0x00]
                }
            }
            InterposerMode::Diff => {
                // Diff mode: responses already compared, return first available
                if let Some((d, s1, s2)) = real {
                    pack(d, s1, s2)
                } else {
                    vec![0x6F, 0x00]
                }
            }
        }
    }
}

// -- Minimal static filesystem for the shadow SIM --

use simrs_fs::{DfDef, EfDef, Fid, FileRef};

static SHADOW_ICCID_DATA: [u8; 10] =
    [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

static SHADOW_EF_ICCID: EfDef = EfDef::transparent(
    Fid::new(0x2FE2),
    None,
    &SHADOW_ICCID_DATA,
);

static SHADOW_MF: DfDef = DfDef {
    fid: Fid::new(0x3F00),
    children: &[FileRef::Ef(&SHADOW_EF_ICCID)],
};

static SHADOW_ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Create a connected pair: (SwIccClient for the proxy, SwIccTerminal as test driver).
    ///
    /// The test driver (SwIccTerminal) acts as the modem: it sends resets and APDUs.
    /// The proxy's modem side (SwIccClient) receives them.
    fn modem_pair() -> (SwIccClient, SwIccTerminal) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let terminal_stream = std::net::TcpStream::connect(addr).unwrap();
        let (client_stream, _) = listener.accept().unwrap();
        (
            SwIccClient::from_stream(client_stream),
            SwIccTerminal::from_stream(terminal_stream),
        )
    }

    /// Create a connected pair for the card side.
    /// The proxy's card side is a SwIccTerminal (sends APDUs to fake card).
    /// The fake card is a SwIccClient (receives APDUs, sends responses).
    fn card_pair() -> (SwIccTerminal, SwIccClient) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let terminal_stream = std::net::TcpStream::connect(addr).unwrap();
        let (card_stream, _) = listener.accept().unwrap();
        (
            SwIccTerminal::from_stream(terminal_stream),
            SwIccClient::from_stream(card_stream),
        )
    }

    fn test_auth_config() -> crate::mode::AuthConfig {
        crate::mode::AuthConfig {
            ki: [0x11u8; 16],
            k: [0x22u8; 16],
            opc: [0x33u8; 16],
        }
    }

    #[test]
    fn proxy_from_parts_constructs() {
        let (modem_client, _modem_driver) = modem_pair();
        let proxy = ProxyLoop::from_parts(
            modem_client,
            None,
            vec![],
            None,
            None,
            InterposerMode::Log,
        );
        assert_eq!(proxy.stats.total_apdus, 0);
    }

    #[test]
    fn log_mode_passthrough() {
        let (modem_client, mut modem_driver) = modem_pair();
        let (card_terminal, mut fake_card) = card_pair();

        let mut proxy = ProxyLoop::from_parts(
            modem_client,
            Some(card_terminal),
            vec![],
            None,
            None,
            InterposerMode::Log,
        );

        let handle = std::thread::spawn(move || {
            let atr_rsp = modem_driver.reset_cold().unwrap();
            assert_eq!(atr_rsp.buf(), &[0x3B, 0x9F]);

            let mut rsp = [0u8; 258];
            let n = modem_driver
                .exchange(&[0x00, 0xB0, 0x00, 0x00, 0x02], &mut rsp)
                .unwrap();
            assert_eq!(&rsp[..n], &[0xDE, 0xAD, 0x90, 0x00]);

            modem_driver
        });

        let card_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 261];
            let event = fake_card.recv(&mut buf).unwrap();
            assert_eq!(event, CardEvent::PowerOn);
            fake_card.send_atr(&[0x3B, 0x9F]).unwrap();

            let event = fake_card.recv(&mut buf).unwrap();
            if let CardEvent::Apdu(_) = event {
                fake_card.send(&[0xDE, 0xAD, 0x90, 0x00]).unwrap();
            }

            fake_card
        });

        let cont = proxy.step().unwrap();
        assert!(cont);
        let cont = proxy.step().unwrap();
        assert!(cont);

        let _ = handle.join().unwrap();
        let _ = card_handle.join().unwrap();
    }

    #[test]
    fn shadow_mode_processes() {
        let (modem_client, mut modem_driver) = modem_pair();
        let (card_terminal, mut fake_card) = card_pair();

        let shadow = ShadowSim::new(&test_auth_config(), &SHADOW_ATR, &SHADOW_MF);

        let mut proxy = ProxyLoop::from_parts(
            modem_client,
            Some(card_terminal),
            vec![],
            Some(shadow),
            None,
            InterposerMode::Shadow,
        );

        let handle = std::thread::spawn(move || {
            let _atr = modem_driver.reset_cold().unwrap();

            let mut rsp = [0u8; 258];
            let _n = modem_driver
                .exchange(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp)
                .unwrap();

            modem_driver
        });

        let card_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 261];
            let event = fake_card.recv(&mut buf).unwrap();
            assert_eq!(event, CardEvent::PowerOn);
            fake_card.send_atr(&[0x3B, 0x9F, 0x96, 0x80]).unwrap();

            let event = fake_card.recv(&mut buf).unwrap();
            if let CardEvent::Apdu(_) = event {
                fake_card.send(&[0x61, 0x0F]).unwrap();
            }

            fake_card
        });

        let cont = proxy.step().unwrap();
        assert!(cont);
        let cont = proxy.step().unwrap();
        assert!(cont);

        assert_eq!(proxy.stats().total_apdus, 1);

        let _ = handle.join().unwrap();
        let _ = card_handle.join().unwrap();
    }

    #[test]
    fn replace_mode_uses_shadow() {
        let (modem_client, mut modem_driver) = modem_pair();
        let (card_terminal, mut fake_card) = card_pair();

        let shadow = ShadowSim::new(&test_auth_config(), &SHADOW_ATR, &SHADOW_MF);

        let mut proxy = ProxyLoop::from_parts(
            modem_client,
            Some(card_terminal),
            vec![],
            Some(shadow),
            None,
            InterposerMode::Replace,
        );

        let handle = std::thread::spawn(move || {
            let _atr = modem_driver.reset_cold().unwrap();

            let mut rsp = [0u8; 258];
            let n = modem_driver
                .exchange(&[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00], &mut rsp)
                .unwrap();

            // In Replace mode, the shadow's response is used.
            // Shadow SIM (USIM): SELECT MF -> 61 XX.
            let sw1 = rsp[n - 2];
            assert_eq!(sw1, 0x61, "Replace mode should return shadow response");

            modem_driver
        });

        let card_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 261];
            let event = fake_card.recv(&mut buf).unwrap();
            assert_eq!(event, CardEvent::PowerOn);
            fake_card.send_atr(&[0x3B, 0x00]).unwrap();

            let event = fake_card.recv(&mut buf).unwrap();
            if let CardEvent::Apdu(_) = event {
                // Real card returns something different.
                fake_card.send(&[0x6E, 0x00]).unwrap();
            }

            fake_card
        });

        let cont = proxy.step().unwrap();
        assert!(cont);
        let cont = proxy.step().unwrap();
        assert!(cont);

        assert_eq!(proxy.stats().total_apdus, 1);
        assert_eq!(proxy.stats().sw_mismatches, 1);

        let _ = handle.join().unwrap();
        let _ = card_handle.join().unwrap();
    }

    #[test]
    fn stats_start_at_zero() {
        let (modem_client, _modem_driver) = modem_pair();
        let proxy = ProxyLoop::from_parts(
            modem_client,
            None,
            vec![],
            None,
            None,
            InterposerMode::Log,
        );
        let stats = proxy.stats();
        assert_eq!(stats.total_apdus, 0);
        assert_eq!(stats.matches, 0);
    }

    #[test]
    fn print_summary_no_panic() {
        let (modem_client, _modem_driver) = modem_pair();
        let proxy = ProxyLoop::from_parts(
            modem_client,
            None,
            vec![],
            None,
            None,
            InterposerMode::Log,
        );
        proxy.print_summary();
    }
}
