//! Integration test that runs .NET tests via `dotnet test`.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn dotnet_bindings() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let capi_lib_dir = find_capi_lib_dir(&manifest_dir);

    let status = Command::new("dotnet")
        .args(["test", "--verbosity", "normal"])
        .current_dir(&manifest_dir)
        .env(
            "LD_LIBRARY_PATH",
            &capi_lib_dir,
        )
        .status()
        .expect("failed to run dotnet test -- is the .NET SDK installed?");

    assert!(status.success(), "dotnet test failed with exit code {status}");
}

fn find_capi_lib_dir(manifest_dir: &std::path::Path) -> PathBuf {
    let capi_target = manifest_dir.join("../simrs-hle-capi/target");
    for profile in ["debug", "release"] {
        let candidate = capi_target.join(profile);
        if candidate.join("libsimrs_hle_capi.so").exists() {
            return candidate;
        }
    }
    panic!("Could not find libsimrs_hle_capi.so");
}
