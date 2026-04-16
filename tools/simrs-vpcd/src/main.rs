//! simrs-vpcd -- boot a simrs SIM card and expose it as a vpcd (Virtual PCD)
//! virtual smart card over TCP.
//!
//! Speaks the vpcd wire protocol: every message is a 2-byte big-endian length
//! prefix followed by a payload. Control commands (length == 1) manage the
//! card lifecycle; longer payloads are C-APDUs forwarded to the SIM.
//!
//! Default port: 35963 (the standard vpcd port).
//!
//! This is a development tool -- single connection, no TLS, no auth.

// Allow 3GPP acronyms in doc comments (APDU, USIM, ATR, etc.)
#![allow(clippy::doc_markdown)]

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process;

use clap::Parser;
use simrs_card_api::{SimEvent, SimResponse};
use simrs_gsm::SubscriberKey as GsmSubscriberKey;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_sim::Sim;
use simrs_usim::profile::{ADF_TABLE, REFERENCE_MF};

// ---- vpcd control bytes ---------------------------------------------------

/// Power off.
const VPCD_CTRL_OFF: u8 = 0;
/// Power on.
const VPCD_CTRL_ON: u8 = 1;
/// Warm reset.
const VPCD_CTRL_RESET: u8 = 2;
/// Return the stored ATR.
const VPCD_CTRL_ATR: u8 = 4;

// ---- CLI ------------------------------------------------------------------

/// Boot a simrs SIM card and expose it as a vpcd virtual smart card.
#[derive(Parser)]
#[command(name = "simrs-vpcd")]
struct Cli {
    /// TCP port to listen on (vpcd default: 35963).
    #[arg(long, default_value_t = 35963)]
    port: u16,

    /// Print APDUs and control events to stderr.
    #[arg(short, long)]
    verbose: bool,
}

// ---- vpcd wire protocol ---------------------------------------------------

/// Receive one length-prefixed message from the vpcd peer.
fn recv_msg(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

/// Send one length-prefixed message to the vpcd peer.
///
/// # Panics
///
/// Panics if `data` is longer than `u16::MAX` bytes.
fn send_msg(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = u16::try_from(data.len())
        .expect("vpcd payload exceeds u16::MAX")
        .to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    stream.flush()
}

// ---- SIM setup ------------------------------------------------------------

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

// ---- helpers --------------------------------------------------------------

/// Format bytes as a hex string (uppercase, space-separated).
fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---- event loop -----------------------------------------------------------

/// Run the vpcd event loop on an accepted connection.
///
/// Returns when the peer disconnects or an unrecoverable error occurs.
#[allow(clippy::too_many_lines)]
fn serve(stream: &mut TcpStream, sim: &mut Sim<MilenageParams, 256>, verbose: bool) {
    let mut stored_atr: Vec<u8> = Vec::new();

    loop {
        let msg = match recv_msg(stream) {
            Ok(m) => m,
            Err(e) => {
                // EOF is a normal disconnect.
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    eprintln!("peer disconnected");
                } else {
                    eprintln!("recv error: {e}");
                }
                return;
            }
        };

        if msg.len() == 1 {
            // Control command.
            match msg[0] {
                VPCD_CTRL_ON => {
                    if verbose {
                        eprintln!("<< POWER ON");
                    }
                    if let SimResponse::Atr(atr) = sim.process(SimEvent::PowerOn) {
                        stored_atr = atr.to_vec();
                        if verbose {
                            eprintln!(">> ATR: {}", hex(&stored_atr));
                        }
                    }
                    if let Err(e) = send_msg(stream, &stored_atr) {
                        eprintln!("send ATR error: {e}");
                        return;
                    }
                }

                VPCD_CTRL_OFF => {
                    if verbose {
                        eprintln!("<< POWER OFF");
                    }
                    let _ = sim.process(SimEvent::PowerOff);
                    stored_atr.clear();
                    // vpcd does not expect a response to Power Off.
                }

                VPCD_CTRL_RESET => {
                    if verbose {
                        eprintln!("<< RESET");
                    }
                    if let SimResponse::Atr(atr) = sim.process(SimEvent::Reset) {
                        stored_atr = atr.to_vec();
                        if verbose {
                            eprintln!(">> ATR: {}", hex(&stored_atr));
                        }
                    }
                    if let Err(e) = send_msg(stream, &stored_atr) {
                        eprintln!("send ATR error: {e}");
                        return;
                    }
                }

                VPCD_CTRL_ATR => {
                    if verbose {
                        eprintln!("<< GET ATR");
                        eprintln!(">> ATR: {}", hex(&stored_atr));
                    }
                    if let Err(e) = send_msg(stream, &stored_atr) {
                        eprintln!("send ATR error: {e}");
                        return;
                    }
                }

                other => {
                    eprintln!("unknown control byte: 0x{other:02X}");
                }
            }
        } else {
            // C-APDU.
            if verbose {
                eprintln!("<< C-APDU: {}", hex(&msg));
            }

            match sim.process(SimEvent::Apdu(&msg)) {
                SimResponse::Apdu { data, sw } => {
                    let [sw1, sw2] = sw.to_bytes();
                    let mut rsp = Vec::with_capacity(data.len() + 2);
                    rsp.extend_from_slice(data);
                    rsp.push(sw1);
                    rsp.push(sw2);

                    if verbose {
                        eprintln!(">> R-APDU: {}", hex(&rsp));
                    }

                    if let Err(e) = send_msg(stream, &rsp) {
                        eprintln!("send error: {e}");
                        return;
                    }
                }
                SimResponse::Ignored => {
                    if verbose {
                        eprintln!(">> (ignored -- returning 6F 00)");
                    }
                    if let Err(e) = send_msg(stream, &[0x6F, 0x00]) {
                        eprintln!("send error: {e}");
                        return;
                    }
                }
                SimResponse::Atr(_) => {
                    eprintln!("unexpected ATR response to APDU");
                    return;
                }
            }
        }
    }
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

    eprintln!("listening on {addr} -- waiting for vpcd connection");

    let (mut stream, peer) = match listener.accept() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("error: accept failed: {e}");
            process::exit(1);
        }
    };

    eprintln!("connection from {peer}");

    serve(&mut stream, &mut sim, cli.verbose);

    eprintln!("session ended");
}
