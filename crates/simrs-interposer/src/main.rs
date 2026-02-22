//! CLI binary for the APDU interposer.

use simrs_interposer::mode::{
    parse_hex, parse_mode, AuthConfig, InterposerConfig, InterposerMode,
};
use simrs_interposer::proxy::ProxyLoop;
use simrs_pcap::LinkType;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    };

    let mut proxy = ProxyLoop::connect(&config).unwrap_or_else(|e| {
        eprintln!("[simrs-interposer] connection failed: {e}");
        std::process::exit(1);
    });

    eprintln!("[simrs-interposer] connected, mode={:?}", config.mode);

    if let Err(e) = proxy.run() {
        eprintln!("[simrs-interposer] error: {e}");
    }

    proxy.print_summary();
}

/// Parse command-line arguments into an [`InterposerConfig`].
///
/// # Errors
///
/// Returns a descriptive error string for invalid or missing arguments.
#[allow(clippy::too_many_lines)]
fn parse_args(args: &[String]) -> Result<InterposerConfig, String> {
    let mut mode = InterposerMode::Log;
    let mut modem_addr = String::from("127.0.0.1:37324");
    let mut card_addr: Option<String> = None;
    let mut pcap_path: Option<String> = None;
    let mut link_type = LinkType::User0;
    let mut ki: Option<[u8; 16]> = None;
    let mut k: Option<[u8; 16]> = None;
    let mut opc: Option<[u8; 16]> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                return Err("help requested".to_string());
            }
            "--mode" => {
                i += 1;
                let val = args.get(i).ok_or("--mode requires a value")?;
                mode = parse_mode(val).ok_or_else(|| {
                    format!("invalid mode '{val}': expected log, shadow, or replace")
                })?;
            }
            "--modem" => {
                i += 1;
                modem_addr.clone_from(
                    args.get(i).ok_or("--modem requires an address")?,
                );
            }
            "--card" => {
                i += 1;
                card_addr = Some(
                    args.get(i)
                        .ok_or("--card requires an address")?
                        .clone(),
                );
            }
            "--pcap" => {
                i += 1;
                pcap_path = Some(
                    args.get(i)
                        .ok_or("--pcap requires a file path")?
                        .clone(),
                );
            }
            "--link-type" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or("--link-type requires a value")?;
                link_type = match val.as_str() {
                    "gsmtap" | "GsmTap" => LinkType::GsmTap,
                    "user0" | "User0" => LinkType::User0,
                    _ => {
                        return Err(format!(
                            "invalid link-type '{val}': expected gsmtap or user0"
                        ));
                    }
                };
            }
            "--ki" => {
                i += 1;
                let val = args.get(i).ok_or("--ki requires a 32-char hex string")?;
                ki = Some(parse_hex(val).ok_or_else(|| {
                    format!("invalid Ki hex: '{val}' (expected 32 hex chars)")
                })?);
            }
            "--k" => {
                i += 1;
                let val = args.get(i).ok_or("--k requires a 32-char hex string")?;
                k = Some(parse_hex(val).ok_or_else(|| {
                    format!("invalid K hex: '{val}' (expected 32 hex chars)")
                })?);
            }
            "--opc" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or("--opc requires a 32-char hex string")?;
                opc = Some(parse_hex(val).ok_or_else(|| {
                    format!("invalid OPc hex: '{val}' (expected 32 hex chars)")
                })?);
            }
            other => {
                return Err(format!("unknown argument: '{other}'"));
            }
        }
        i += 1;
    }

    let auth = if ki.is_some() || k.is_some() || opc.is_some() {
        Some(AuthConfig {
            ki: ki.unwrap_or([0u8; 16]),
            k: k.unwrap_or([0u8; 16]),
            opc: opc.unwrap_or([0u8; 16]),
        })
    } else {
        None
    };

    Ok(InterposerConfig {
        mode,
        modem_addr,
        card_addr,
        pcap_path,
        link_type,
        auth,
    })
}

/// Print usage information to stderr.
fn print_usage() {
    eprintln!("Usage: simrs-interposer [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --mode <log|shadow|replace>   Operating mode (default: log)");
    eprintln!("  --modem <addr:port>           Modem-side swICC address (default: 127.0.0.1:37324)");
    eprintln!("  --card <addr:port>            Card-side swICC address");
    eprintln!("  --pcap <path>                 PCAP output file path");
    eprintln!("  --link-type <gsmtap|user0>    PCAP link-layer type (default: user0)");
    eprintln!("  --ki <hex>                    GSM Ki (32 hex chars)");
    eprintln!("  --k <hex>                     UMTS K (32 hex chars)");
    eprintln!("  --opc <hex>                   UMTS OPc (32 hex chars)");
    eprintln!("  -h, --help                    Print this help message");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_full() {
        let args: Vec<String> = [
            "--mode",
            "shadow",
            "--modem",
            "192.168.1.1:5000",
            "--card",
            "192.168.1.2:5001",
            "--pcap",
            "/tmp/test.pcap",
            "--link-type",
            "gsmtap",
            "--ki",
            "11111111111111111111111111111111",
            "--k",
            "22222222222222222222222222222222",
            "--opc",
            "33333333333333333333333333333333",
        ]
        .iter()
        .map(|s| String::from(*s))
        .collect();

        let config = parse_args(&args).unwrap();
        assert_eq!(config.mode, InterposerMode::Shadow);
        assert_eq!(config.modem_addr, "192.168.1.1:5000");
        assert_eq!(config.card_addr.as_deref(), Some("192.168.1.2:5001"));
        assert_eq!(config.pcap_path.as_deref(), Some("/tmp/test.pcap"));
        assert_eq!(config.link_type, LinkType::GsmTap);
        let auth = config.auth.unwrap();
        assert_eq!(auth.ki, [0x11u8; 16]);
        assert_eq!(auth.k, [0x22u8; 16]);
        assert_eq!(auth.opc, [0x33u8; 16]);
    }

    #[test]
    fn parse_args_defaults() {
        let args: Vec<String> = vec![];
        let config = parse_args(&args).unwrap();
        assert_eq!(config.mode, InterposerMode::Log);
        assert_eq!(config.modem_addr, "127.0.0.1:37324");
        assert!(config.card_addr.is_none());
        assert!(config.pcap_path.is_none());
        assert_eq!(config.link_type, LinkType::User0);
        assert!(config.auth.is_none());
    }

    #[test]
    fn parse_args_help_returns_err() {
        let args = [String::from("--help")];
        let result = parse_args(&args);
        assert!(result.is_err());
    }

    #[test]
    fn parse_args_unknown_flag() {
        let args = [String::from("--unknown")];
        let result = parse_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown argument"));
    }
}
