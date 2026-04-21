//! CLI for managing the jcardsim bridge installation.
//!
//! Mirrors [`simrs-jcsl`](../../simrs-jcsl/src/main.rs) so the two
//! backends feel interchangeable from the developer side.
//!
//! # Usage
//!
//! ```text
//! simrs-jcardsim status              Show installation status
//! simrs-jcardsim install <dir>       Copy bridge.jar + jcardsim-*.jar
//!                                    from <dir> into ~/.cache/simrs/jcardsim/
//! simrs-jcardsim guide               Print acquisition instructions
//! simrs-jcardsim help                Show this help
//! ```
//!
//! No `validate` subcommand (unlike jcsl): jcardsim ships as a plain
//! Apache-2.0 JAR, so there's no binary-level patching to verify.

use simrs_jcardsim::discovery;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("status") => cmd_status(),
        Some("install") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: simrs-jcardsim install <dir>");
                return ExitCode::from(2);
            };
            cmd_install(Path::new(path))
        }
        Some("guide") => cmd_guide(),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("unknown command: {unknown}");
            eprintln!();
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!("simrs-jcardsim -- licel/jcardsim Java Card Simulator management");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  status            Show installation status");
    eprintln!("  install <dir>     Copy bridge.jar + jcardsim-*.jar from <dir>");
    eprintln!("                    into ~/.cache/simrs/jcardsim/");
    eprintln!("  guide             Print acquisition instructions");
    eprintln!("  help              Show this help");
}

fn cmd_status() -> ExitCode {
    let stdout = &mut std::io::stdout().lock();
    if let Err(e) = discovery::print_status(stdout) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn cmd_install(dir: &Path) -> ExitCode {
    match discovery::install_from_directory(dir) {
        Ok(inst) => {
            eprintln!("Installed successfully.");
            eprintln!();
            print!("{inst}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_guide() -> ExitCode {
    print!("{}", discovery::ACQUISITION_GUIDE);
    ExitCode::SUCCESS
}
