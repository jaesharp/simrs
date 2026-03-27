//! jvac -- JVA smartcard applet compiler.
//!
//! Compiles `.java`/`.jva` source files or `.class`/`.jvc` classfiles
//! into `.cap` bytecode packages for the JCVM.
//!
//! Also supports decompilation of `.cap` files back to assembly or
//! high-level JVA source.

use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    if args[1] == "--version" || args[1] == "-V" {
        println!("jvac 0.1.0 (simrs JVA compiler)");
        return;
    }

    // Check for decompilation flags.
    if args[1] == "--disasm" {
        if args.len() < 3 {
            eprintln!("error: --disasm requires an input file");
            std::process::exit(1);
        }
        run_disasm(&args[2]);
        return;
    }

    if args[1] == "--decompile" {
        if args.len() < 3 {
            eprintln!("error: --decompile requires an input file");
            std::process::exit(1);
        }
        run_decompile(&args[2]);
        return;
    }

    let input = &args[1];
    let output = find_output_arg(&args).unwrap_or_else(|| default_output(input));
    let input_path = Path::new(input);

    let result = match input_path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("java" | "jva") => compile_source(input),
        Some("class" | "jvc") => compile_classfile(input),
        _ => Err(format!("unknown file type: {input}")),
    };

    match result {
        Ok(cap_bytes) => {
            fs::write(&output, &cap_bytes).expect("failed to write output");
            eprintln!("wrote {} bytes to {}", cap_bytes.len(), output);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Disassemble a CAP file to assembly text on stdout.
fn run_disasm(path: &str) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: failed to read {path}: {e}");
            std::process::exit(1);
        }
    };
    match jvac::decompile::disassemble(&data) {
        Ok(asm) => print!("{asm}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Decompile a CAP file to JVA source on stdout.
fn run_decompile(path: &str) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: failed to read {path}: {e}");
            std::process::exit(1);
        }
    };
    match jvac::decompile::decompile(&data) {
        Ok(source) => print!("{source}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Compile a Java/JVA source file to CAP.
fn compile_source(path: &str) -> Result<Vec<u8>, String> {
    let source = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {path}: {e}"))?;
    let class = jvac::java_parser::parse_source(&source)?;
    let compiled = simrs_jccompile::compile_class(&class).map_err(|errors| {
        errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    Ok(jvac::cap::write_cap(&compiled))
}

/// Compile a Java classfile to CAP.
fn compile_classfile(path: &str) -> Result<Vec<u8>, String> {
    let data = fs::read(path)
        .map_err(|e| format!("failed to read {path}: {e}"))?;
    let default_aid = [0xA0, 0x00, 0x00, 0x00, 0x62];
    let class = jvac::classfile::read_and_convert(&data, &default_aid)?;
    let compiled = simrs_jccompile::compile_class(&class).map_err(|errors| {
        errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    Ok(jvac::cap::write_cap(&compiled))
}

/// Find the `-o`/`--output` argument.
fn find_output_arg(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if (args[i] == "-o" || args[i] == "--output") && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

/// Derive a default output path by replacing the input extension with `.cap`.
fn default_output(input: &str) -> String {
    let path = PathBuf::from(input);
    path.with_extension("cap")
        .to_string_lossy()
        .into_owned()
}

/// Print usage information.
fn print_usage() {
    eprintln!("Usage: jvac <input> [-o <output>]");
    eprintln!("       jvac --disasm <input.cap>");
    eprintln!("       jvac --decompile <input.cap>");
    eprintln!();
    eprintln!("Compiles Java Card source (.java/.jva) or classfiles (.class/.jvc)");
    eprintln!("into CAP packages (.cap) for the JCVM.");
    eprintln!();
    eprintln!("Decompilation modes:");
    eprintln!("  --disasm <file>      Disassemble CAP to assembly text");
    eprintln!("  --decompile <file>   Decompile CAP to JVA source");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --output <file>  Output file (default: <input>.cap)");
    eprintln!("  --version            Print version");
    eprintln!("  --help               Print this help");
}
