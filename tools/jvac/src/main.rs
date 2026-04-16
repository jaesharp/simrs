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
    let emit_source_map = has_flag(&args, "--source-map");
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

            if emit_source_map {
                let map_path = source_map_path(&output);
                let source_map = build_source_map(input, &cap_bytes);
                let map_text = source_map.to_text();
                fs::write(&map_path, map_text.as_bytes()).expect("failed to write source map");
                eprintln!("wrote source map to {map_path}");
            }
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
    let source = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
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
    let data = fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))?;
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

/// Check whether a boolean flag is present in the arguments.
fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Derive a default output path by replacing the input extension with `.cap`.
fn default_output(input: &str) -> String {
    let path = PathBuf::from(input);
    path.with_extension("cap").to_string_lossy().into_owned()
}

/// Derive the `.jvamap` path from the `.cap` output path.
fn source_map_path(output: &str) -> String {
    let path = PathBuf::from(output);
    path.with_extension("jvamap").to_string_lossy().into_owned()
}

/// Build a source map from the compiled CAP file.
///
/// For now, this creates a minimal source map by parsing the CAP blob
/// and recording each method's bytecodes with PC offsets starting at
/// line 1 (since we don't yet track source lines through compilation).
/// The structure is correct and ready for future source-level tracking.
fn build_source_map(input: &str, cap_bytes: &[u8]) -> simrs_jccompile::SourceMap {
    let source_name = Path::new(input)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(input);

    // Try to extract AID from the CAP blob.
    let aid = extract_aid_from_cap(cap_bytes);

    let mut sm = simrs_jccompile::SourceMap::new(source_name, &aid);

    // Parse the CAP to get method info.
    if let Ok(pkg) = simrs_jcvm::cap::parse_cap(cap_bytes) {
        for method_idx in 0..pkg.method_count {
            if let Some(method) = pkg.method(method_idx) {
                let method_name = format!("method_{method_idx}");
                let m = sm.add_method(&method_name);
                // Map PC 0 -> line 1 for each method (stub: actual line
                // tracking will come when the codegen emits source locations).
                if method.bytecode_len > 0 {
                    sm.add_entry(m, 0, 1, 1);
                }
            }
        }
    }

    sm
}

/// Extract the AID from a CAP blob (simplified format).
///
/// The format is: magic(4) | `aid_len`(1) | aid(`aid_len`) | ...
fn extract_aid_from_cap(data: &[u8]) -> Vec<u8> {
    if data.len() < 5 {
        return Vec::new();
    }
    let aid_len = data[4] as usize;
    if data.len() < 5 + aid_len {
        return Vec::new();
    }
    data[5..5 + aid_len].to_vec()
}

/// Print usage information.
fn print_usage() {
    eprintln!("Usage: jvac <input> [-o <output>] [--source-map]");
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
    eprintln!("  --source-map         Emit .jvamap source map alongside output");
    eprintln!("  --version            Print version");
    eprintln!("  --help               Print this help");
}
