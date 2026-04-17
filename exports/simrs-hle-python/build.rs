/// Ensure the simrs-hle-capi cdylib (.so/.dylib) is built before tests run.
///
/// The Cargo dependency on simrs-hle-capi compiles it as an rlib, but the
/// Python bindings need the cdylib. This build script shells out to cargo
/// to build the sibling crate's cdylib target.
fn main() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("simrs-hle-capi")
        .join("Cargo.toml");

    println!("cargo::rerun-if-changed={}", manifest.display());

    let status = std::process::Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(&manifest)
        .status()
        .expect("failed to invoke cargo to build simrs-hle-capi cdylib");

    assert!(status.success(), "simrs-hle-capi cdylib build failed");
}
