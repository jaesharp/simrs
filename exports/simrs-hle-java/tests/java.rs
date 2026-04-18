//! Integration test that runs Java tests via jbang.

use std::env::consts::{DLL_PREFIX, DLL_SUFFIX};
use std::path::PathBuf;
use std::process::Command;

fn capi_lib() -> String {
    format!("{DLL_PREFIX}simrs_hle_capi{DLL_SUFFIX}")
}

fn jni_lib() -> String {
    format!("{DLL_PREFIX}simrs_jni{DLL_SUFFIX}")
}

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

    // LD_LIBRARY_PATH for Linux, DYLD_LIBRARY_PATH for macOS.
    let status = Command::new("jbang")
        .arg("run")
        .arg("--cp")
        .arg(&classes_dir)
        .arg(&test_file)
        .env("JAVA_TOOL_OPTIONS", format!("-Djava.library.path={lib_path}"))
        .env("LD_LIBRARY_PATH", &lib_path)
        .env("DYLD_LIBRARY_PATH", &lib_path)
        .status()
        .expect("failed to run jbang -- is it installed?");

    assert!(status.success(), "test failed with exit code {status}");
}

fn find_out_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = manifest_dir.join("target");
    let jni = jni_lib();

    for profile in ["debug", "release"] {
        let build_dir = target_dir.join(profile).join("build");
        if let Ok(entries) = std::fs::read_dir(&build_dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("simrs-hle-java")
                    && entry.path().join("out").join(&jni).exists()
                {
                    return entry.path().join("out");
                }
            }
        }
    }
    panic!("Could not find {jni} in target/build/simrs-hle-java-*/out/");
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
