//! Integration test that runs Swift tests via `swift test`.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn swift_bindings() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let capi_lib_dir = find_capi_lib_dir(&manifest_dir);
    let capi_header_dir = find_header_dir(&manifest_dir);
    let linkage = std::env::var("SIMRS_CAPI_LINKAGE").unwrap_or_else(|_| "dynamic".into());

    let mut cmd = Command::new("swift");
    cmd.args(["test"])
        .current_dir(&manifest_dir)
        .env("LIBRARY_PATH", &capi_lib_dir)
        .env("LD_LIBRARY_PATH", &capi_lib_dir)
        .env("C_INCLUDE_PATH", &capi_header_dir);

    if linkage == "static" {
        // Force the linker to resolve against the static archive.
        cmd.env(
            "LDFLAGS",
            format!(
                "-Wl,-Bstatic -L{} -lsimrs_hle_capi -Wl,-Bdynamic -lpthread -ldl -lm",
                capi_lib_dir.display()
            ),
        );
    }

    let status = cmd
        .status()
        .expect("failed to run swift test -- is Swift installed?");

    assert!(status.success(), "swift test failed with exit code {status}");
}

fn find_capi_lib_dir(manifest_dir: &std::path::Path) -> PathBuf {
    if let Some(prebuilt) = std::env::var_os("SIMRS_CAPI_PREBUILT_DIR") {
        return PathBuf::from(prebuilt);
    }
    let capi_target = manifest_dir.join("../simrs-hle-capi/target");
    for profile in ["debug", "release"] {
        let candidate = capi_target.join(profile);
        if candidate.join("libsimrs_hle_capi.so").exists() {
            return candidate;
        }
    }
    panic!("Could not find libsimrs_hle_capi.so");
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
