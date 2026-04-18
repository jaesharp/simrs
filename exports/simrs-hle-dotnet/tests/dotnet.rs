//! Integration test that runs .NET tests via `dotnet test`.

use std::env::consts::{DLL_PREFIX, DLL_SUFFIX};
use std::path::PathBuf;
use std::process::Command;

fn capi_lib() -> String {
    format!("{DLL_PREFIX}simrs_hle_capi{DLL_SUFFIX}")
}

#[test]
fn dotnet_bindings() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let capi_lib_dir = find_capi_lib_dir(&manifest_dir);

    // LD_LIBRARY_PATH for Linux, DYLD_LIBRARY_PATH for macOS -- the CoreCLR
    // P/Invoke loader respects both.
    let status = Command::new("dotnet")
        .args(["test", "--verbosity", "normal"])
        .current_dir(&manifest_dir)
        .env("LD_LIBRARY_PATH", &capi_lib_dir)
        .env("DYLD_LIBRARY_PATH", &capi_lib_dir)
        .status()
        .expect("failed to run dotnet test -- is the .NET SDK installed?");

    assert!(status.success(), "dotnet test failed with exit code {status}");
}

fn find_capi_lib_dir(manifest_dir: &std::path::Path) -> PathBuf {
    if let Some(prebuilt) = std::env::var_os("SIMRS_CAPI_PREBUILT_DIR") {
        return PathBuf::from(prebuilt);
    }
    let capi_target = manifest_dir.join("../simrs-hle-capi/target");
    let capi = capi_lib();
    for profile in ["debug", "release"] {
        let candidate = capi_target.join(profile);
        if candidate.join(&capi).exists() {
            return candidate;
        }
    }
    panic!("Could not find {capi}");
}
