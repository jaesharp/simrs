//! Integration test that runs Java tests via jbang.

use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "macos")]
const CAPI_LIB: &str = "libsimrs_hle_capi.dylib";
#[cfg(not(target_os = "macos"))]
const CAPI_LIB: &str = "libsimrs_hle_capi.so";

#[cfg(target_os = "macos")]
const JNI_LIB: &str = "libsimrs_jni.dylib";
#[cfg(not(target_os = "macos"))]
const JNI_LIB: &str = "libsimrs_jni.so";

#[test]
fn java_bindings() {
    run_jbang_test("src/test/java/com/simrs/SimTest.java");
}

#[test]
fn kotlin_bindings() {
    run_jbang_test("src/test/kotlin/com/simrs/SimKotlinTest.kt");
}

fn run_jbang_test(test_path: &str) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = find_out_dir();
    let capi_lib_dir = find_capi_lib_dir(&manifest_dir);
    let test_file = manifest_dir.join(test_path);
    let classes_dir = out_dir.join("classes");

    // The JNI shim lives in out_dir; its dlopen of the capi cdylib at load
    // time resolves against capi_lib_dir.
    let lib_path = format!("{}:{}", out_dir.display(), capi_lib_dir.display());

    let status = Command::new("jbang")
        .arg("run")
        .arg("--cp")
        .arg(&classes_dir)
        .arg(&test_file)
        .env("JAVA_TOOL_OPTIONS", format!("-Djava.library.path={lib_path}"))
        .env("LD_LIBRARY_PATH", &lib_path)
        .status()
        .expect("failed to run jbang -- is it installed?");

    assert!(status.success(), "test failed with exit code {status}");
}

fn find_out_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = manifest_dir.join("target");

    for profile in ["debug", "release"] {
        let build_dir = target_dir.join(profile).join("build");
        if let Ok(entries) = std::fs::read_dir(&build_dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("simrs-hle-java")
                    && entry.path().join("out").join(JNI_LIB).exists()
                {
                    return entry.path().join("out");
                }
            }
        }
    }
    panic!("Could not find {JNI_LIB} in target/build/simrs-hle-java-*/out/");
}

fn find_capi_lib_dir(manifest_dir: &std::path::Path) -> PathBuf {
    if let Some(prebuilt) = std::env::var_os("SIMRS_CAPI_PREBUILT_DIR") {
        return PathBuf::from(prebuilt);
    }
    let capi_target = manifest_dir.join("../simrs-hle-capi/target");
    for profile in ["debug", "release"] {
        let candidate = capi_target.join(profile);
        if candidate.join(CAPI_LIB).exists() {
            return candidate;
        }
    }
    panic!("Could not find {CAPI_LIB}");
}
