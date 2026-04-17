use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-env-changed=SIMRS_CAPI_PREBUILT_DIR");
    println!("cargo::rerun-if-changed=simrs.go");
    println!("cargo::rerun-if-changed=simrs_test.go");

    // CI supplies SIMRS_CAPI_PREBUILT_DIR to reuse a single capi build across
    // all language jobs. If it's unset, we fall back to a sibling cargo build.
    if std::env::var_os("SIMRS_CAPI_PREBUILT_DIR").is_some() {
        return;
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let capi_manifest = manifest_dir.join("../simrs-hle-capi/Cargo.toml");
    let status = Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(&capi_manifest)
        .status()
        .expect("failed to build simrs-hle-capi");
    assert!(status.success(), "simrs-hle-capi build failed");
}
