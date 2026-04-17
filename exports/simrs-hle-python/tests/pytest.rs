//! Integration test that runs the Python test suite via uv + pytest.
//!
//! The `simrs-hle-capi` cdylib is built as a dependency of this crate,
//! so the shared library is available before pytest runs.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn python_bindings() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib_path = find_cdylib();

    let status = Command::new("uv")
        .args(["run", "--group", "test", "-m", "pytest", "tests/", "-v", "--tb=short"])
        .current_dir(&manifest_dir)
        .env("SIMRS_LIB", &lib_path)
        .status()
        .expect("failed to run uv -- is it installed?");

    assert!(status.success(), "pytest failed with exit code {status}");
}

fn find_cdylib() -> String {
    // The cdylib is built in simrs-hle-capi's own target directory
    // (separate workspace from the main simrs workspace).
    let hle_capi_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("simrs-hle-capi")
        .join("target");

    let lib_name = if cfg!(target_os = "macos") {
        "libsimrs_hle_capi.dylib"
    } else {
        "libsimrs_hle_capi.so"
    };

    for profile in ["debug", "release"] {
        let candidate = hle_capi_dir.join(profile).join(lib_name);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }

    panic!(
        "Could not find {lib_name} in {}/{{debug,release}}/. \
         Build it first: cargo build --manifest-path exports/simrs-hle-capi/Cargo.toml",
        hle_capi_dir.display()
    );
}
