//! Integration test that runs Go tests via `go test`.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn go_bindings() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let capi_lib_dir = find_capi_lib_dir(&manifest_dir);
    let capi_header_dir = find_header_dir(&manifest_dir);
    let linkage = std::env::var("SIMRS_CAPI_LINKAGE").unwrap_or_else(|_| "dynamic".into());

    // simrs.go embeds `#cgo LDFLAGS: -lsimrs_hle_capi`, so the linker always
    // sees -lsimrs_hle_capi on the command line. We just need to point it at
    // a directory where the library can be found and (for static mode) tell
    // it to prefer the .a over any .so sitting next to it.
    let cgo_ldflags = match linkage.as_str() {
        "static" => format!(
            "-L{dir} -Wl,-Bstatic -lsimrs_hle_capi -Wl,-Bdynamic -lpthread -ldl -lm",
            dir = capi_lib_dir.display()
        ),
        _ => format!("-L{} -lsimrs_hle_capi", capi_lib_dir.display()),
    };

    let status = Command::new("go")
        .args(["test", "-v", "-count=1", "./..."])
        .current_dir(&manifest_dir)
        .env("CGO_LDFLAGS", cgo_ldflags)
        .env("CGO_CFLAGS", format!("-I{}", capi_header_dir.display()))
        .env("LD_LIBRARY_PATH", &capi_lib_dir)
        .status()
        .expect("failed to run go test -- is Go installed?");

    assert!(status.success(), "go test failed with exit code {status}");
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
