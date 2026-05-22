//! simrs-simtrace2 -- boot a simrs SIM card and serve it directly over USB
//! to an Osmocom SIMtrace2 board running cardem firmware.
//!
//! This is the "Path B" deployment shape: a single process replacing the
//! `simtrace2-cardem-pcsc + pcscd + vsmartcard-vpcd + simrs-vpcd` stack
//! used in Path A. APDUs flow Phone -> SIMtrace2 board -> USB -> this
//! process directly into the simrs Sim state machine.
//!
//! USB enumeration filters by VID:PID. Defaults match the upstream
//! SIMtrace2 cardem firmware (`1d50:60e3`). The ngff-cardem (`1d50:616e`)
//! and octsimtest (`1d50:616d`) variants are auto-accepted when no
//! explicit `--product-id` is given.
//!
//! See `docs/runbooks/simtrace2-cardem-path-a.md` for hardware bring-up
//! and udev permission setup; both apply to Path B as well.

// Allow 3GPP / USB acronyms.
#![allow(clippy::doc_markdown)]

use std::process;

use clap::Parser;
use simrs_card_api::{DEFAULT_ATR as ATR, SimEvent, SimResponse};
use simrs_gsm::SubscriberKey as GsmSubscriberKey;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_sim::Sim;
use simrs_transport::{CardEvent, CardTransport};
use simrs_transport_simtrace2::{DeviceFilter, Simtrace2Transport};
use simrs_usim::profile::{ADF_TABLE, REFERENCE_MF};

// ---- CLI ------------------------------------------------------------------

/// Boot a simrs SIM card and serve it over USB to a SIMtrace2 board.
#[derive(Parser)]
#[command(name = "simrs-simtrace2")]
struct Cli {
    /// USB vendor ID in hex (default 1d50 -- OpenMoko).
    #[arg(long, value_parser = parse_hex_u16, default_value = "1d50")]
    vendor_id: u16,

    /// USB product ID in hex (default 60e3 -- SIMtrace2 cardem).
    /// Pass another value to talk to ngff-cardem (616e) or octsimtest (616d).
    #[arg(long, value_parser = parse_hex_u16, default_value = "60e3")]
    product_id: u16,

    /// Disambiguate between multiple connected boards with the same VID:PID.
    /// Format: `BUS:ADDR` where `BUS` is the platform-specific bus
    /// identifier (numeric on Linux) and `ADDR` is the USB device address
    /// reported by `lsusb`.
    #[arg(long, value_parser = parse_bus_device)]
    bus_device: Option<(String, u8)>,

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

    /// Print APDUs and lifecycle events to stderr.
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

/// Parse a 16-bit hex value (e.g. `1d50`, `0x1d50`).
fn parse_hex_u16(s: &str) -> Result<u16, String> {
    let trimmed = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u16::from_str_radix(trimmed, 16).map_err(|e| format!("invalid hex u16 {s:?}: {e}"))
}

/// Parse `BUS:ADDR` where `ADDR` is base-10 in the 0..=255 range.
fn parse_bus_device(s: &str) -> Result<(String, u8), String> {
    let (bus, addr) = s
        .split_once(':')
        .ok_or_else(|| format!("expected BUS:ADDR, got {s:?}"))?;
    if bus.is_empty() {
        return Err("bus identifier must not be empty".to_string());
    }
    let addr = addr
        .parse::<u8>()
        .map_err(|e| format!("invalid device address {addr:?}: {e}"))?;
    Ok((bus.to_string(), addr))
}

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
/// by issuing in-process APDUs.
fn seed_filesystem(sim: &mut Sim<MilenageParams, 256>, cli: &Cli) {
    let _ = sim.process(SimEvent::PowerOn);

    select_ef(sim, 0x2FE2);
    update_binary(sim, &cli.iccid.0);

    select_adf(sim, &USIM_AID);
    select_ef(sim, 0x6F07);
    update_binary(sim, &cli.imsi.0);

    let _ = sim.process(SimEvent::PowerOff);
}

fn select_ef(sim: &mut Sim<MilenageParams, 256>, fid: u16) {
    let [hi, lo] = fid.to_be_bytes();
    let cmd = [0x00, 0xA4, 0x00, 0x04, 0x02, hi, lo];
    expect_ok(&sim.process(SimEvent::Apdu(&cmd)), "SELECT EF");
}

fn select_adf(sim: &mut Sim<MilenageParams, 256>, aid: &[u8]) {
    let lc = u8::try_from(aid.len()).expect("AID exceeds 255 bytes");
    let mut cmd = Vec::with_capacity(5 + aid.len());
    cmd.extend_from_slice(&[0x00, 0xA4, 0x04, 0x04, lc]);
    cmd.extend_from_slice(aid);
    expect_ok(&sim.process(SimEvent::Apdu(&cmd)), "SELECT ADF");
}

fn update_binary(sim: &mut Sim<MilenageParams, 256>, payload: &[u8]) {
    let lc = u8::try_from(payload.len()).expect("EF payload exceeds 255 bytes");
    let mut cmd = Vec::with_capacity(5 + payload.len());
    cmd.extend_from_slice(&[0x00, 0xD6, 0x00, 0x00, lc]);
    cmd.extend_from_slice(payload);
    expect_ok(&sim.process(SimEvent::Apdu(&cmd)), "UPDATE BINARY");
}

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

fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn handle_reset(
    sim: &mut Sim<MilenageParams, 256>,
    transport: &mut Simtrace2Transport,
    event: SimEvent<'_>,
    verbose: bool,
) -> bool {
    if let SimResponse::Atr(atr) = sim.process(event) {
        if verbose {
            eprintln!(">> ATR: {}", hex(atr));
        }
        if let Err(e) = transport.send_atr(atr) {
            eprintln!("send ATR error: {e}");
            return false;
        }
    } else {
        eprintln!("unexpected response to reset");
        return false;
    }
    true
}

fn handle_apdu(
    sim: &mut Sim<MilenageParams, 256>,
    transport: &mut Simtrace2Transport,
    cmd: &[u8],
    verbose: bool,
) -> bool {
    match sim.process(SimEvent::Apdu(cmd)) {
        SimResponse::Apdu { data, sw } => {
            let [sw1, sw2] = sw.to_bytes();
            let mut rsp = Vec::with_capacity(data.len() + 2);
            rsp.extend_from_slice(data);
            rsp.push(sw1);
            rsp.push(sw2);
            if verbose {
                eprintln!(">> R-APDU: {}", hex(&rsp));
            }
            if let Err(e) = transport.send(&rsp) {
                eprintln!("send error: {e}");
                return false;
            }
        }
        SimResponse::Ignored => {
            if verbose {
                eprintln!(">> (ignored -- returning 6F 00)");
            }
            if let Err(e) = transport.send(&[0x6F, 0x00]) {
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

    let filter = DeviceFilter {
        vendor_id: Some(cli.vendor_id),
        product_id: Some(cli.product_id),
        bus_device: cli.bus_device.clone(),
    };
    let mut transport = match Simtrace2Transport::open(&filter) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: failed to open SIMtrace2 device: {e}");
            process::exit(1);
        }
    };
    eprintln!("opened SIMtrace2 device {:04x}:{:04x}", cli.vendor_id, cli.product_id);

    // Pre-stage the ATR before the phone releases RST. See ISO 7816-3
    // clause 6.3 for the 400-40 000 cycle window.
    if let Err(e) = transport.send_atr(&ATR) {
        eprintln!("error: failed to pre-stage ATR: {e}");
        process::exit(1);
    }
    if cli.verbose {
        eprintln!(">> ATR (initial): {}", hex(&ATR));
    }

    let mut cmd_buf = [0u8; 261];

    loop {
        let event = match transport.recv(&mut cmd_buf) {
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
                if !handle_reset(&mut sim, &mut transport, SimEvent::PowerOn, cli.verbose) {
                    break;
                }
            }
            CardEvent::WarmReset => {
                if cli.verbose {
                    eprintln!("<< WARM RESET");
                }
                if !handle_reset(&mut sim, &mut transport, SimEvent::Reset, cli.verbose) {
                    break;
                }
            }
            CardEvent::Apdu(len) => {
                let cmd = &cmd_buf[..len];
                if cli.verbose {
                    eprintln!("<< C-APDU: {}", hex(cmd));
                }
                if !handle_apdu(&mut sim, &mut transport, cmd, cli.verbose) {
                    break;
                }
            }
            CardEvent::Shutdown => {
                if cli.verbose {
                    eprintln!("<< SHUTDOWN (VCC removed)");
                }
                let _ = sim.process(SimEvent::PowerOff);
                // Keep looping -- the phone may power us back up.
            }
        }
    }

    eprintln!("session ended");
}

#[cfg(test)]
mod tests {
    use super::{Hex16, Iccid, Imsi, parse_bus_device, parse_hex16, parse_hex_u16, parse_iccid, parse_imsi};

    #[test]
    fn parse_hex_u16_accepts_bare_and_prefixed() {
        assert_eq!(parse_hex_u16("1d50").unwrap(), 0x1d50);
        assert_eq!(parse_hex_u16("0x60e3").unwrap(), 0x60e3);
        assert_eq!(parse_hex_u16("0X616E").unwrap(), 0x616e);
    }

    #[test]
    fn parse_hex_u16_rejects_invalid() {
        assert!(parse_hex_u16("gggg").is_err());
        assert!(parse_hex_u16("12345").is_err());
    }

    #[test]
    fn parse_bus_device_ok() {
        let (bus, addr) = parse_bus_device("01:23").unwrap();
        assert_eq!(bus, "01");
        assert_eq!(addr, 23);
    }

    #[test]
    fn parse_bus_device_rejects_no_colon() {
        assert!(parse_bus_device("0123").is_err());
    }

    #[test]
    fn parse_bus_device_rejects_invalid_addr() {
        assert!(parse_bus_device("01:abc").is_err());
        assert!(parse_bus_device("01:300").is_err());
    }

    #[test]
    fn parse_bus_device_rejects_empty_bus() {
        assert!(parse_bus_device(":23").is_err());
    }

    #[test]
    fn parse_hex16_round_trip() {
        let Hex16(bytes) = parse_hex16("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[15], 0xef);
    }

    #[test]
    fn parse_imsi_default() {
        let Imsi(bytes) = parse_imsi("001010000000001").unwrap();
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[1], 0x09);
    }

    #[test]
    fn parse_iccid_round_trip() {
        let Iccid(bytes) = parse_iccid("89882110000000000010").unwrap();
        assert_eq!(bytes[0], 0x98);
        assert_eq!(bytes[9], 0x01);
    }
}
