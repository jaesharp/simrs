//! Milenage authentication vector generation CLI.
//!
//! Thin wrapper around `simrs-milenage` for use by the `BridgeWire` mini-MME
//! and other test tools that need LTE/UMTS authentication vectors.
//!
//! # Subcommands
//!
//! - `gen-vector`: Compute (RAND, AUTN, XRES, CK, IK) from subscriber credentials.
//!   Outputs JSON to stdout. The Python mini-MME calls this via `subprocess.run()`.
//!
//! - `verify`: Check that RES matches XRES. Exit code 0 on match, 1 on mismatch.

use std::process;

use clap::{Parser, Subcommand};
use simrs_milenage::{MilenageParams, OperatorVariant};

#[derive(Parser)]
#[command(name = "simrs-auth")]
#[command(about = "Milenage authentication vector generation for LTE/UMTS")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate authentication vector (MME/HSS side).
    ///
    /// Computes RAND, AUTN, XRES, CK, IK from subscriber key material.
    /// RAND is generated randomly unless --rand is provided.
    GenVector {
        /// Subscriber key K (32 hex chars).
        #[arg(long)]
        k: String,

        /// Pre-computed `OPc` (32 hex chars).
        #[arg(long)]
        opc: String,

        /// Sequence number SQN (12 hex chars).
        #[arg(long)]
        sqn: String,

        /// Authentication management field AMF (4 hex chars).
        #[arg(long)]
        amf: String,

        /// Fixed RAND value (32 hex chars). Randomly generated if omitted.
        #[arg(long)]
        rand: Option<String>,
    },

    /// Verify authentication response: exit 0 if RES == XRES, else exit 1.
    Verify {
        /// Expected response XRES (16 hex chars).
        #[arg(long)]
        xres: String,

        /// Actual response RES (16 hex chars).
        #[arg(long)]
        res: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::GenVector {
            k,
            opc,
            sqn,
            amf,
            rand,
        } => cmd_gen_vector(&k, &opc, &sqn, &amf, rand.as_deref()),
        Command::Verify { xres, res } => cmd_verify(&xres, &res),
    }
}

fn cmd_gen_vector(k_hex: &str, opc_hex: &str, sqn_hex: &str, amf_hex: &str, rand_hex: Option<&str>) {
    let k: [u8; 16] = parse_hex_or_exit(k_hex, "K");
    let opc: [u8; 16] = parse_hex_or_exit(opc_hex, "OPc");
    let sequence_number: [u8; 6] = parse_hex_or_exit(sqn_hex, "SQN");
    let management_field: [u8; 2] = parse_hex_or_exit(amf_hex, "AMF");

    let rand_bytes: [u8; 16] = rand_hex.map_or_else(
        || {
            let mut buf = [0u8; 16];
            getrandom::getrandom(&mut buf).unwrap_or_else(|e| {
                eprintln!("error: failed to generate RAND: {e}");
                process::exit(1);
            });
            buf
        },
        |r| parse_hex_or_exit(r, "RAND"),
    );

    // Standard ETSI TS 135 206 clause 4 operator constants (c1..c5, r1..r5).
    let params = MilenageParams::with_defaults(k, OperatorVariant::Opc(opc));

    // MME-side auth vector computation:
    // anonymity_key  = f5(RAND)
    // auth_mac       = f1(RAND, SQN, AMF)
    // auth_token     = (SQN XOR anonymity_key) || AMF || auth_mac
    // expected_response = f2(RAND), cipher_key = f3(RAND), integrity_key = f4(RAND)
    let anonymity_key = params.compute_anonymity_key(&rand_bytes);
    let auth_mac = params.compute_auth_mac(&rand_bytes, &sequence_number, &management_field);
    let expected_response = params.compute_response(&rand_bytes);
    let cipher_key = params.compute_cipher_key(&rand_bytes);
    let integrity_key = params.compute_integrity_key(&rand_bytes);

    let auth_token = build_auth_token(sequence_number, anonymity_key, management_field, auth_mac);

    // JSON output -- consumed by Python subprocess.run() callers.
    // All values are lowercase hex without 0x prefix.
    println!(
        "{{\n  \"rand\": \"{}\",\n  \"autn\": \"{}\",\n  \"xres\": \"{}\",\n  \"ck\": \"{}\",\n  \"ik\": \"{}\"\n}}",
        hex_encode(&rand_bytes),
        hex_encode(&auth_token),
        hex_encode(&expected_response),
        hex_encode(&cipher_key),
        hex_encode(&integrity_key),
    );
}

fn cmd_verify(xres_hex: &str, res_hex: &str) {
    let expected_response: [u8; 8] = parse_hex_or_exit(xres_hex, "XRES");
    let res: [u8; 8] = parse_hex_or_exit(res_hex, "RES");

    if constant_time_eq(expected_response, res) {
        println!("{{\"match\": true}}");
    } else {
        println!("{{\"match\": false}}");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// AUTN construction
// ---------------------------------------------------------------------------

/// Build AUTN = (SQN XOR AK) || AMF || MAC-A (16 bytes).
fn build_auth_token(
    sequence_number: [u8; 6],
    anonymity_key: [u8; 6],
    management_field: [u8; 2],
    auth_mac: [u8; 8],
) -> [u8; 16] {
    let mut auth_token = [0u8; 16];
    for (dst, (s, a)) in auth_token[..6]
        .iter_mut()
        .zip(sequence_number.iter().zip(anonymity_key.iter()))
    {
        *dst = s ^ a;
    }
    auth_token[6..8].copy_from_slice(&management_field);
    auth_token[8..16].copy_from_slice(&auth_mac);
    auth_token
}

/// Constant-time equality for authentication tokens.
/// XOR-folds all bytes unconditionally to avoid timing side-channels.
fn constant_time_eq(a: [u8; 8], b: [u8; 8]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn parse_hex<const N: usize>(s: &str, name: &str) -> Result<[u8; N], String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() != N * 2 {
        return Err(format!("{name} must be {} hex chars, got {}", N * 2, s.len()));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("{name} invalid hex at byte {i}: {e}"))?;
    }
    Ok(out)
}

fn parse_hex_or_exit<const N: usize>(s: &str, name: &str) -> [u8; N] {
    parse_hex(s, name).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1);
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ETSI TS 135 208 V19.0.0 Test Set 1
    const TS1_K: &str = "465B5CE8B199B49FAA5F0A2EE238A6BC";
    const TS1_OPC: &str = "CD63CB71954A9F4E48A5994E37A02BAF";
    const TS1_RAND: &str = "23553CBE9637A89D218AE64DAE47BF35";
    const TS1_SQN: &str = "FF9BB4D0B607";
    const TS1_AMF: &str = "B9B9";

    // Expected outputs
    const TS1_XRES: &str = "a54211d5e3ba50bf";
    const TS1_CK: &str = "b40ba9a3c58b2a05bbf0d987b21bf8cb";
    const TS1_IK: &str = "f769bcd751044604127672711c6d3441";
    const TS1_AUTN: &str = "55f328b43577b9b94a9ffac354dfafb3";

    #[test]
    fn gen_vector_matches_etsi_test_set_1() {
        let k: [u8; 16] = parse_hex(TS1_K, "K").unwrap();
        let opc: [u8; 16] = parse_hex(TS1_OPC, "OPc").unwrap();
        let sequence_number: [u8; 6] = parse_hex(TS1_SQN, "SQN").unwrap();
        let management_field: [u8; 2] = parse_hex(TS1_AMF, "AMF").unwrap();
        let rand_bytes: [u8; 16] = parse_hex(TS1_RAND, "RAND").unwrap();

        let params = MilenageParams::with_defaults(k, OperatorVariant::Opc(opc));
        let anonymity_key = params.compute_anonymity_key(&rand_bytes);
        let auth_mac = params.compute_auth_mac(&rand_bytes, &sequence_number, &management_field);
        let expected_response = params.compute_response(&rand_bytes);
        let cipher_key = params.compute_cipher_key(&rand_bytes);
        let integrity_key = params.compute_integrity_key(&rand_bytes);
        let auth_token = build_auth_token(sequence_number, anonymity_key, management_field, auth_mac);

        assert_eq!(hex_encode(&expected_response), TS1_XRES);
        assert_eq!(hex_encode(&cipher_key), TS1_CK);
        assert_eq!(hex_encode(&integrity_key), TS1_IK);
        assert_eq!(hex_encode(&auth_token), TS1_AUTN);
    }

    #[test]
    fn parse_hex_valid() {
        let result: [u8; 4] = parse_hex("DEADBEEF", "test").unwrap();
        assert_eq!(result, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_hex_with_0x_prefix() {
        let result: [u8; 2] = parse_hex("0xFF00", "test").unwrap();
        assert_eq!(result, [0xFF, 0x00]);
    }

    #[test]
    fn parse_hex_wrong_length() {
        let result = parse_hex::<4>("DEAD", "test");
        assert!(result.is_err());
    }

    #[test]
    fn parse_hex_invalid_chars() {
        let result = parse_hex::<2>("ZZZZ", "test");
        assert!(result.is_err());
    }

    #[test]
    fn constant_time_eq_match() {
        assert!(constant_time_eq([1, 2, 3, 4, 5, 6, 7, 8], [1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn constant_time_eq_mismatch() {
        assert!(!constant_time_eq([1, 2, 3, 4, 5, 6, 7, 8], [1, 2, 3, 4, 5, 6, 7, 9]));
    }

    #[test]
    fn hex_encode_roundtrip() {
        let bytes = [0x00, 0xFF, 0xAB, 0x12];
        assert_eq!(hex_encode(&bytes), "00ffab12");
    }
}
