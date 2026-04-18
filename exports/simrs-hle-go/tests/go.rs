//! Integration test that runs Go tests via `go test`.

use std::env::consts::{DLL_PREFIX, DLL_SUFFIX};
use std::path::PathBuf;
use std::process::Command;

fn capi_lib() -> String {
    format!("{DLL_PREFIX}simrs_hle_capi{DLL_SUFFIX}")
}

#[test]
fn go_bindings() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let capi_lib_dir = find_capi_lib_dir(&manifest_dir);
    let capi_header_dir = find_header_dir(&manifest_dir);

    // macOS uses DYLD_LIBRARY_PATH at runtime; Linux uses LD_LIBRARY_PATH.
    // Set both so the test harness is platform-independent.
    let status = Command::new("go")
        .args(["test", "-v", "-count=1", "./..."])
        .current_dir(&manifest_dir)
        .env(
            "CGO_LDFLAGS",
            format!("-L{} -lsimrs_hle_capi", capi_lib_dir.display()),
        )
        .env("CGO_CFLAGS", format!("-I{}", capi_header_dir.display()))
        .env("LD_LIBRARY_PATH", &capi_lib_dir)
        .env("DYLD_LIBRARY_PATH", &capi_lib_dir)
        .status()
        .expect("failed to run go test -- is Go installed?");

    assert!(status.success(), "go test failed with exit code {status}");
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
