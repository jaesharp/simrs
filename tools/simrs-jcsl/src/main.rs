//! CLI for managing the Oracle jcsl simulator installation.
//!
//! # Usage
//!
//! ```text
//! simrs-jcsl status              Show jcsl installation status
//! simrs-jcsl install <path>      Install from Oracle SDK directory or binary
//! simrs-jcsl validate <path>     Validate a jcsl binary
//! simrs-jcsl guide               Print acquisition instructions
//! simrs-jcsl help                Show this help
//! ```

use simrs_jcsl::discovery;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("status") => cmd_status(),
        Some("install") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: simrs-jcsl install <sdk-dir-or-binary>");
                return ExitCode::from(2);
            };
            cmd_install(Path::new(path))
        }
        Some("validate") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: simrs-jcsl validate <binary>");
                return ExitCode::from(2);
            };
            cmd_validate(Path::new(path))
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
    eprintln!("simrs-jcsl -- Oracle Java Card Simulator management");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  status              Show jcsl installation status");
    eprintln!("  install <path>      Install from Oracle SDK directory or binary");
    eprintln!("  validate <path>     Validate a jcsl binary");
    eprintln!("  guide               Print acquisition instructions");
    eprintln!("  help                Show this help");
}

fn cmd_status() -> ExitCode {
    let stdout = &mut std::io::stdout().lock();
    if let Err(e) = discovery::print_status(stdout) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn cmd_install(path: &Path) -> ExitCode {
    // Determine whether the path is an SDK directory or a binary.
    let result = if path.is_dir() {
        eprintln!("Installing from SDK directory: {}", path.display());
        discovery::install_from_sdk(path)
    } else if path.is_file() {
        eprintln!("Installing from binary: {}", path.display());
        discovery::install_from_binary(path)
    } else {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::FAILURE;
    };

    match result {
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

fn cmd_validate(path: &Path) -> ExitCode {
    match discovery::validate(path) {
        Ok((scp, pin)) => {
            println!("Valid jcsl binary: {}", path.display());
            println!(
                "  SCP keys: {}",
                if scp { "configured" } else { "unconfigured" }
            );
            println!(
                "  Global PIN: {}",
                if pin { "configured" } else { "unconfigured" }
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Validation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_guide() -> ExitCode {
    print!("{}", discovery::ACQUISITION_GUIDE);
    ExitCode::SUCCESS
}
