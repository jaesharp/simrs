//! Integration test that runs Swift tests via `swift test`.

use std::env::consts::{DLL_PREFIX, DLL_SUFFIX};
use std::path::PathBuf;
use std::process::Command;

fn capi_lib() -> String {
    format!("{DLL_PREFIX}simrs_hle_capi{DLL_SUFFIX}")
}

#[test]
fn swift_bindings() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let capi_lib_dir = find_capi_lib_dir(&manifest_dir);
    let capi_header_dir = find_header_dir(&manifest_dir);

    let status = Command::new("swift")
        .args(["test"])
        .current_dir(&manifest_dir)
        .env("LIBRARY_PATH", &capi_lib_dir)
        // LD_LIBRARY_PATH for Linux, DYLD_LIBRARY_PATH for macOS.
        .env("LD_LIBRARY_PATH", &capi_lib_dir)
        .env("DYLD_LIBRARY_PATH", &capi_lib_dir)
        .env("C_INCLUDE_PATH", &capi_header_dir)
        .status()
        .expect("failed to run swift test -- is Swift installed?");

    assert!(status.success(), "swift test failed with exit code {status}");
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

fn find_header_dir(manifest_dir: &std::path::Path) -> PathBuf {
    if let Some(prebuilt) = std::env::var_os("SIMRS_CAPI_PREBUILT_DIR") {
        return PathBuf::from(prebuilt);
    }
    let capi_target = manifest_dir.join("../simrs-hle-capi/target");
    for profile in ["debug", "release"] {
        let build_dir = capi_target.join(profile).join("build");
        if let Ok(entries) = std::fs::read_dir(&build_dir) {
            for entry in entries.flatten() {
                let out = entry.path().join("out/simrs.h");
                if out.exists() {
                    return entry.path().join("out");
                }
            }
        }
    }
    panic!("Could not find generated simrs.h");
}
