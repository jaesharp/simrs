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
use simrs_card_api::DEFAULT_ATR as ATR;
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

    /// 15-digit IMSI written to EF.IMSI (test-PLMN default: 001/01).
    #[arg(long, value_parser = parse_imsi, default_value = "001010000000001")]
    imsi: Imsi,

    /// 19 or 20 digit ICCID written to EF.ICCID.
    #[arg(long, value_parser = parse_iccid, default_value = "8988211000000000001")]
    iccid: Iccid,

    /// GSM Ki as 32 hex chars.
    #[arg(long, value_parser = parse_hex16, default_value = "11111111111111111111111111111111")]
    ki: Hex16,

    /// USIM subscriber key K as 32 hex chars.
    #[arg(long, value_parser = parse_hex16, default_value = "22222222222222222222222222222222")]
    k: Hex16,

    /// Milenage OPc (pre-computed operator cipher) as 32 hex chars.
    /// Mutually exclusive with `--op`.
    #[arg(
        long,
        value_parser = parse_hex16,
        default_value = "33333333333333333333333333333333",
        conflicts_with = "op"
    )]
    opc: Hex16,

    /// Milenage OP (raw operator parameter) as 32 hex chars.
    /// When supplied, OPc is derived at runtime as `E_K[OP] XOR OP`.
    /// Mutually exclusive with `--opc`.
    #[arg(long, value_parser = parse_hex16)]
    op: Option<Hex16>,

    /// Print APDUs to stderr.
    #[arg(short, long)]
    verbose: bool,
}

// ---- argument parsers -----------------------------------------------------

/// Wrapper around a 16-byte key so clap treats it as a single value rather
/// than an array of u8 arguments.
#[derive(Clone, Debug)]
struct Hex16(pub [u8; 16]);

/// 9-byte EF.IMSI payload as a single clap value.
#[derive(Clone, Debug)]
struct Imsi(pub [u8; 9]);

/// 10-byte EF.ICCID payload as a single clap value.
#[derive(Clone, Debug)]
struct Iccid(pub [u8; 10]);

/// Parse exactly 32 hex characters into a 16-byte key.
fn parse_hex16(s: &str) -> Result<Hex16, String> {
    if s.len() != 32 {
        return Err(format!("expected 32 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(Hex16(out))
}

/// Parse a single ASCII hex digit (0-9, a-f, A-F).
fn hex_digit(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex digit: {:?}", c as char)),
    }
}

/// Parse a 15-digit IMSI into the 9-byte EF.IMSI encoding.
///
/// Encoding per [3GPP TS 31.102] / [3GPP TS 24.008 clause 10.5.1.4]:
/// byte 0 = length-of-IMSI-data in bytes (always 0x08 for 15 digits);
/// byte 1 high nibble = digit 1, low nibble = parity (0x09 for 15-digit odd-length);
/// bytes 2..=8 = remaining 14 digits as nibble-swapped BCD pairs.
fn parse_imsi(s: &str) -> Result<Imsi, String> {
    if s.len() != 15 {
        return Err(format!("IMSI must be 15 digits, got {}", s.len()));
    }
    let mut digits = [0u8; 15];
    for (i, c) in s.bytes().enumerate() {
        if !c.is_ascii_digit() {
            return Err(format!("IMSI must be digits only, found {:?}", c as char));
        }
        digits[i] = c - b'0';
    }
    let mut out = [0u8; 9];
    out[0] = 0x08;
    // High nibble = digit 1, low nibble = parity (0x09 = odd-length=1, digit-1-of-IMSI-3GPP-type)
    out[1] = (digits[0] << 4) | 0x09;
    for i in 0..7 {
        let lo = digits[1 + 2 * i];
        let hi = digits[2 + 2 * i];
        out[2 + i] = (hi << 4) | lo;
    }
    Ok(Imsi(out))
}

/// Parse a 19 or 20 digit ICCID into the 10-byte EF.ICCID encoding.
///
/// Encoding per [ETSI TS 102 221 clause 13.2]: nibble-swapped BCD,
/// padded with a 0xF nibble if length is odd.
fn parse_iccid(s: &str) -> Result<Iccid, String> {
    if s.len() != 19 && s.len() != 20 {
        return Err(format!("ICCID must be 19 or 20 digits, got {}", s.len()));
    }
    let mut digits = [0xFu8; 20];
    for (i, c) in s.bytes().enumerate() {
        if !c.is_ascii_digit() {
            return Err(format!("ICCID must be digits only, found {:?}", c as char));
        }
        digits[i] = c - b'0';
    }
    let mut out = [0u8; 10];
    for i in 0..10 {
        let lo = digits[2 * i];
        let hi = digits[2 * i + 1];
        out[i] = (hi << 4) | lo;
    }
    Ok(Iccid(out))
}

/// USIM AID `A0000000871002` per [ETSI TS 101 220].
const USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

/// Create a SIM instance configured from the CLI credentials and seed
/// EF.IMSI / EF.ICCID with the requested values via in-process APDUs.
fn create_sim(cli: &Cli) -> Sim<MilenageParams, 256> {
    let gsm = simrs_gsm::GsmApp::new(&REFERENCE_MF, GsmSubscriberKey::classify(cli.ki.0));
    let op_variant = cli.op.as_ref().map_or_else(
        || OperatorVariant::operator_cipher(cli.opc.0),
        |op| OperatorVariant::operator_parameter(op.0),
    );
    let mil = MilenageParams::with_defaults(SubscriberKey::classify(cli.k.0), op_variant);
    let usim = simrs_usim::UsimApp::new(&REFERENCE_MF, &ADF_TABLE, mil);
    let mut sim = Sim::new(&ATR, gsm, usim);
    seed_filesystem(&mut sim, cli);
    sim
}

/// Seed the SIM filesystem (EF.IMSI, EF.ICCID) with values from the CLI
/// by issuing in-process APDUs. Called immediately after `Sim::new`, before
/// any external client connects. EF data is owned by the runtime `FsData`
/// after `Sim::new` copies the template, so UPDATE BINARY writes through.
/// Panics if the SIM rejects the write -- that would mean the static
/// profile is misconfigured.
fn seed_filesystem(sim: &mut Sim<MilenageParams, 256>, cli: &Cli) {
    // Power on so the file system is ready for APDU traffic.
    let _ = sim.process(SimEvent::PowerOn);

    // ICCID lives under the MF, which is implicitly selected after power-on.
    select_ef(sim, 0x2FE2);
    update_binary(sim, &cli.iccid.0);

    // Move into ADF.USIM, then write EF.IMSI.
    select_adf(sim, &USIM_AID);
    select_ef(sim, 0x6F07);
    update_binary(sim, &cli.imsi.0);

    // Power off so the external client's POWER ON starts from a fresh
    // activation state (selection context, response queue, etc.).
    // EF data is retained across power cycles -- the seeded IMSI / ICCID
    // remain visible to subsequent READ BINARY calls.
    let _ = sim.process(SimEvent::PowerOff);
}

/// Issue SELECT (P1=00 P2=04 select-by-FID, no Le) for the given two-byte FID.
fn select_ef(sim: &mut Sim<MilenageParams, 256>, fid: u16) {
    let [hi, lo] = fid.to_be_bytes();
    let cmd = [0x00, 0xA4, 0x00, 0x04, 0x02, hi, lo];
    expect_ok(&sim.process(SimEvent::Apdu(&cmd)), "SELECT EF");
}

/// Issue SELECT by AID (P1=04 P2=04) for the given application identifier.
fn select_adf(sim: &mut Sim<MilenageParams, 256>, aid: &[u8]) {
    let lc = u8::try_from(aid.len()).expect("AID exceeds 255 bytes");
    let mut cmd = Vec::with_capacity(5 + aid.len());
    cmd.extend_from_slice(&[0x00, 0xA4, 0x04, 0x04, lc]);
    cmd.extend_from_slice(aid);
    expect_ok(&sim.process(SimEvent::Apdu(&cmd)), "SELECT ADF");
}

/// Issue UPDATE BINARY (offset 0) writing the full payload.
fn update_binary(sim: &mut Sim<MilenageParams, 256>, payload: &[u8]) {
    let lc = u8::try_from(payload.len()).expect("EF payload exceeds 255 bytes");
    let mut cmd = Vec::with_capacity(5 + payload.len());
    cmd.extend_from_slice(&[0x00, 0xD6, 0x00, 0x00, lc]);
    cmd.extend_from_slice(payload);
    expect_ok(&sim.process(SimEvent::Apdu(&cmd)), "UPDATE BINARY");
}

/// Panic if `rsp` is not a success status word.
fn expect_ok(rsp: &SimResponse<'_>, op: &str) {
    match rsp {
        SimResponse::Apdu { sw, .. } => {
            let [sw1, sw2] = sw.to_bytes();
            assert!(
                matches!(sw1, 0x90 | 0x91 | 0x61),
                "seed: {op} failed with SW={sw1:02X}{sw2:02X}"
            );
        }
        SimResponse::Ignored | SimResponse::Atr(_) => {
            panic!("seed: {op} produced unexpected response");
        }
    }
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

    let mut sim = create_sim(&cli);

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

#[cfg(test)]
mod tests {
    use super::{Hex16, Iccid, Imsi, parse_hex16, parse_iccid, parse_imsi};

    #[test]
    fn parse_hex16_lowercase_and_uppercase() {
        let Hex16(lo) = parse_hex16("0123456789abcdef0123456789abcdef").unwrap();
        let Hex16(hi) = parse_hex16("0123456789ABCDEF0123456789ABCDEF").unwrap();
        assert_eq!(lo, hi);
        assert_eq!(lo[0], 0x01);
        assert_eq!(lo[7], 0xEF);
        assert_eq!(lo[15], 0xEF);
    }

    #[test]
    fn parse_hex16_rejects_short() {
        assert!(parse_hex16("00").is_err());
    }

    #[test]
    fn parse_hex16_rejects_non_hex() {
        assert!(parse_hex16("zz23456789abcdef0123456789abcdef").is_err());
    }

    #[test]
    fn parse_imsi_default_value() {
        let Imsi(bytes) = parse_imsi("001010000000001").unwrap();
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[1], 0x09);
        assert_eq!(bytes[2], 0x10);
        assert_eq!(bytes[3], 0x10);
        assert_eq!(bytes[8], 0x10);
    }

    #[test]
    fn parse_imsi_rejects_wrong_length() {
        assert!(parse_imsi("12345").is_err());
        assert!(parse_imsi("1234567890123456").is_err());
    }

    #[test]
    fn parse_imsi_rejects_non_digits() {
        assert!(parse_imsi("00101000000000a").is_err());
    }

    #[test]
    fn parse_iccid_20_digits() {
        let Iccid(bytes) = parse_iccid("89882110000000000010").unwrap();
        assert_eq!(bytes[0], 0x98);
        assert_eq!(bytes[1], 0x88);
        assert_eq!(bytes[9], 0x01);
    }

    #[test]
    fn parse_iccid_19_digits_pads_with_f() {
        let Iccid(bytes) = parse_iccid("8988211000000000001").unwrap();
        assert_eq!(bytes[0], 0x98);
        assert_eq!(bytes[9], 0xF1);
    }

    #[test]
    fn parse_iccid_rejects_short() {
        assert!(parse_iccid("89").is_err());
    }
}
