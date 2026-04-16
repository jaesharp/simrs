//! simrs-swicc -- boot a simrs SIM card and expose it as a swICC PC/SC
//! virtual reader over TCP.
//!
//! Listens for a single connection from a swICC PC/SC server, then enters
//! an event loop: receive APDUs from the terminal, hand them to the SIM
//! state machine, and send the response back.
//!
//! This is a development tool -- single connection, no TLS, no auth.

// Allow 3GPP acronyms in doc comments (APDU, USIM, ATR, etc.)
#![allow(clippy::doc_markdown)]

use std::net::TcpListener;
use std::process;

use clap::Parser;
use simrs_gsm::SubscriberKey as GsmSubscriberKey;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_sim::{Sim, SimEvent, SimResponse};
use simrs_transport::{CardEvent, CardTransport};
use simrs_transport_tcp::SwIccClient;
use simrs_usim::profile::{ADF_TABLE, REFERENCE_MF};

/// Boot a simrs SIM card and expose it as a swICC PC/SC virtual reader.
#[derive(Parser)]
#[command(name = "simrs-swicc")]
struct Cli {
    /// TCP port to listen on.
    #[arg(long, default_value_t = 37324)]
    port: u16,

    /// Print APDUs to stderr.
    #[arg(short, long)]
    verbose: bool,
}

/// Default ATR returned on cold/warm reset.
///
/// 3B 9F 96 80 -- matches the shadow SIM ATR used elsewhere in simrs.
static ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

/// Default test Ki (GSM subscriber key).
const DEFAULT_KI: GsmSubscriberKey = GsmSubscriberKey::classify([0x11; 16]);
/// Default test K (USIM subscriber key).
const DEFAULT_K: SubscriberKey = SubscriberKey::classify([0x22; 16]);
/// Default test OPc (pre-computed operator cipher).
const DEFAULT_OPC: OperatorVariant = OperatorVariant::operator_cipher([0x33; 16]);

/// Create a SIM instance with default test credentials and the reference
/// filesystem.
fn create_sim() -> Sim<MilenageParams, 256> {
    let gsm = simrs_gsm::GsmApp::new(&REFERENCE_MF, DEFAULT_KI);
    let mil = MilenageParams::with_defaults(DEFAULT_K, DEFAULT_OPC);
    let usim = simrs_usim::UsimApp::new(&REFERENCE_MF, &ADF_TABLE, mil);
    Sim::new(&ATR, gsm, usim)
}

/// Format bytes as a hex string (uppercase, space-separated).
fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Handle a reset event (cold or warm). Returns `false` if the session
/// should end due to an error.
fn handle_reset(
    sim: &mut Sim<MilenageParams, 256>,
    client: &mut SwIccClient,
    event: SimEvent<'_>,
    verbose: bool,
) -> bool {
    if let SimResponse::Atr(atr) = sim.process(event) {
        if verbose {
            eprintln!(">> ATR: {}", hex(atr));
        }
        if let Err(e) = client.send_atr(atr) {
            eprintln!("send ATR error: {e}");
            return false;
        }
    } else {
        eprintln!("unexpected response to reset");
        return false;
    }
    true
}

/// Handle an APDU event. Returns `false` if the session should end due
/// to an error.
fn handle_apdu(
    sim: &mut Sim<MilenageParams, 256>,
    client: &mut SwIccClient,
    cmd: &[u8],
    verbose: bool,
) -> bool {
    match sim.process(SimEvent::Apdu(cmd)) {
        SimResponse::Apdu { data, sw } => {
            let [sw1, sw2] = sw.to_bytes();

            // Build response: data || sw1 || sw2
            let rsp_len = data.len() + 2;
            let mut rsp = vec![0u8; rsp_len];
            rsp[..data.len()].copy_from_slice(data);
            rsp[data.len()] = sw1;
            rsp[data.len() + 1] = sw2;

            if verbose {
                eprintln!(">> R-APDU: {}", hex(&rsp));
            }

            if let Err(e) = client.send(&rsp) {
                eprintln!("send error: {e}");
                return false;
            }
        }
        SimResponse::Ignored => {
            if verbose {
                eprintln!(">> (ignored -- returning 6F 00)");
            }
            if let Err(e) = client.send(&[0x6F, 0x00]) {
                eprintln!("send error: {e}");
                return false;
            }
        }
        SimResponse::Atr(_) => {
            eprintln!("unexpected ATR response to APDU");
            return false;
        }
    }
    true
}

fn main() {
    let cli = Cli::parse();

    let mut sim = create_sim();

    let addr = format!("127.0.0.1:{}", cli.port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind {addr}: {e}");
            process::exit(1);
        }
    };

    eprintln!("listening on {addr} -- waiting for swICC server connection");

    let (stream, peer) = match listener.accept() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("error: accept failed: {e}");
            process::exit(1);
        }
    };

    eprintln!("connection from {peer}");

    let mut client = SwIccClient::from_stream(stream);
    let mut cmd_buf = [0u8; 261];

    loop {
        let event = match client.recv(&mut cmd_buf) {
            Ok(ev) => ev,
            Err(e) => {
                eprintln!("transport error: {e}");
                break;
            }
        };

        match event {
            CardEvent::PowerOn => {
                if cli.verbose {
                    eprintln!("<< POWER ON (cold reset)");
                }
                if !handle_reset(&mut sim, &mut client, SimEvent::PowerOn, cli.verbose) {
                    break;
                }
            }

            CardEvent::WarmReset => {
                if cli.verbose {
                    eprintln!("<< WARM RESET");
                }
                if !handle_reset(&mut sim, &mut client, SimEvent::Reset, cli.verbose) {
                    break;
                }
            }

            CardEvent::Apdu(len) => {
                let cmd = &cmd_buf[..len];
                if cli.verbose {
                    eprintln!("<< C-APDU: {}", hex(cmd));
                }
                if !handle_apdu(&mut sim, &mut client, cmd, cli.verbose) {
                    break;
                }
            }

            CardEvent::Shutdown => {
                if cli.verbose {
                    eprintln!("<< SHUTDOWN");
                }
                break;
            }
        }
    }

    eprintln!("session ended");
}
