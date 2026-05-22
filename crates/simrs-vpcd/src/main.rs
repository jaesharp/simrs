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
use simrs_card_api::{DEFAULT_ATR as ATR, SimEvent, SimResponse};
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

    /// Print APDUs and control events to stderr.
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

/// Panic if `rsp` is not a success status word (SW1 == 0x90, SW1 == 0x91,
/// or SELECT-style 0x61xx with response data pending).
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

    let mut sim = create_sim(&cli);

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
        // 001010000000001 -- generic test PLMN
        let Imsi(bytes) = parse_imsi("001010000000001").unwrap();
        // byte 0: length = 8
        assert_eq!(bytes[0], 0x08);
        // byte 1: high nibble = digit 1 (0), low nibble = parity (9)
        assert_eq!(bytes[1], 0x09);
        // bytes 2..=8: nibble-swapped pairs of remaining digits 2-15
        // digits 2..15 = 0,1,0,1,0,0,0,0,0,0,0,0,0,1
        // pairs (lo, hi) -> bytes: (0,1)=0x10, (0,1)=0x10, (0,0)=0x00, (0,0)=0x00, (0,0)=0x00, (0,0)=0x00, (0,1)=0x10
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
        // Last byte: digit 19 low nibble + 0xF pad high nibble.
        assert_eq!(bytes[9], 0xF1);
    }

    #[test]
    fn parse_iccid_rejects_short() {
        assert!(parse_iccid("89").is_err());
    }
}
