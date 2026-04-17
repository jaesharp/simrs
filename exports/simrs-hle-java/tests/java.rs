//! Integration test that runs Java tests via jbang.

use std::path::PathBuf;
use std::process::Command;

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

    let status = Command::new("jbang")
        .arg("run")
        .arg("--cp")
        .arg(&classes_dir)
        .arg(&test_file)
        .env(
            "JAVA_TOOL_OPTIONS",
            format!(
                "-Djava.library.path={}:{}",
                out_dir.display(),
                capi_lib_dir.display()
            ),
        )
        .env(
            "LD_LIBRARY_PATH",
            format!("{}:{}", out_dir.display(), capi_lib_dir.display()),
        )
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
                if entry.file_name().to_string_lossy().starts_with("simrs-hle-java") {
                    let out = entry.path().join("out");
                    if out.join("libsimrs_jni.so").exists() {
                        return out;
                    }
                }
            }
        }
    }
    panic!("Could not find libsimrs_jni.so in target/build/simrs-hle-java-*/out/");
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
