use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    let capi_manifest = manifest_dir.join("../simrs-hle-capi/Cargo.toml");
    let status = Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(&capi_manifest)
        .status()
        .expect("failed to build simrs-hle-capi");
    assert!(status.success(), "simrs-hle-capi build failed");

    println!("cargo::rerun-if-changed=Sources/SimRS/Sim.swift");
    println!("cargo::rerun-if-changed=Tests/SimRSTests/SimTests.swift");
}
