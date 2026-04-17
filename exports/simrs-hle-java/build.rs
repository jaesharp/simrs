use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-env-changed=SIMRS_CAPI_PREBUILT_DIR");
    println!("cargo::rerun-if-env-changed=SIMRS_CAPI_LINKAGE");
    println!("cargo::rerun-if-changed=src/main/c/simrs_jni.c");
    println!("cargo::rerun-if-changed=src/main/java/com/simrs/Sim.java");
    println!("cargo::rerun-if-changed=src/main/kotlin/com/simrs/SimKotlin.kt");

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let (capi_lib_dir, capi_header_dir) = resolve_capi(&manifest_dir);

    let java_home = std::env::var("JAVA_HOME").unwrap_or_else(|_| find_java_home());
    let jni_include = PathBuf::from(&java_home).join("include");
    let jni_include_linux = jni_include.join("linux");

    let jni_c = manifest_dir.join("src/main/c/simrs_jni.c");
    let jni_so = out_dir.join("libsimrs_jni.so");
    let linkage = std::env::var("SIMRS_CAPI_LINKAGE").unwrap_or_else(|_| "dynamic".into());

    let mut cc_cmd = Command::new("cc");
    cc_cmd
        .args(["-shared", "-fPIC", "-o"])
        .arg(&jni_so)
        .arg(&jni_c)
        .arg(format!("-I{}", jni_include.display()))
        .arg(format!("-I{}", jni_include_linux.display()))
        .arg(format!("-I{}", capi_header_dir.display()));

    match linkage.as_str() {
        "static" => {
            cc_cmd
                .arg("-Wl,--whole-archive")
                .arg(capi_lib_dir.join("libsimrs_hle_capi.a"))
                .arg("-Wl,--no-whole-archive")
                .args(["-lpthread", "-ldl", "-lm", "-lgcc_s"]);
        }
        _ => {
            cc_cmd
                .arg(format!("-L{}", capi_lib_dir.display()))
                .arg("-lsimrs_hle_capi")
                .arg(format!("-Wl,-rpath,{}", capi_lib_dir.display()));
        }
    }

    let cc_status = cc_cmd
        .status()
        .expect("failed to compile JNI shim (is a C compiler installed?)");
    assert!(cc_status.success(), "JNI shim compilation failed");

    let java_src = manifest_dir.join("src/main/java/com/simrs/Sim.java");
    let classes_dir = out_dir.join("classes");
    std::fs::create_dir_all(&classes_dir).unwrap();

    let javac_status = Command::new("javac")
        .arg("-d")
        .arg(&classes_dir)
        .arg(&java_src)
        .status()
        .expect("javac not found -- is a JDK installed?");
    assert!(javac_status.success(), "javac compilation failed");

    let kotlin_src = manifest_dir.join("src/main/kotlin/com/simrs/SimKotlin.kt");
    let kotlinc_status = Command::new("kotlinc")
        .arg("-cp")
        .arg(&classes_dir)
        .arg("-d")
        .arg(&classes_dir)
        .arg(&kotlin_src)
        .status()
        .expect("kotlinc not found -- Kotlin 2.x requires JDK 11+");
    assert!(kotlinc_status.success(), "kotlinc compilation failed");
}

/// Resolve the capi library + header directories, preferring a prebuilt dir
/// supplied via `SIMRS_CAPI_PREBUILT_DIR` over an ad-hoc `cargo build`.
fn resolve_capi(manifest_dir: &Path) -> (PathBuf, PathBuf) {
    if let Some(prebuilt) = std::env::var_os("SIMRS_CAPI_PREBUILT_DIR") {
        let dir = PathBuf::from(prebuilt);
        assert!(
            dir.join("simrs.h").exists(),
            "SIMRS_CAPI_PREBUILT_DIR={} does not contain simrs.h",
            dir.display()
        );
        return (dir.clone(), dir);
    }

    let capi_manifest = manifest_dir.join("../simrs-hle-capi/Cargo.toml");
    let status = Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(&capi_manifest)
        .status()
        .expect("failed to build simrs-hle-capi");
    assert!(status.success(), "simrs-hle-capi build failed");

    let capi_target = manifest_dir.join("../simrs-hle-capi/target");
    let lib_dir = if capi_target.join("release/libsimrs_hle_capi.so").exists() {
        capi_target.join("release")
    } else {
        capi_target.join("debug")
    };
    let header_dir = find_header_dir(&capi_target);
    (lib_dir, header_dir)
}

fn find_header_dir(capi_target: &Path) -> PathBuf {
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
    panic!("Could not find generated simrs.h in capi target/build/*/out/");
}

fn find_java_home() -> String {
    let output = Command::new("java")
        .args(["-XshowSettings:property", "-version"])
        .output()
        .expect("java not found");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("java.home") {
            if let Some(val) = trimmed.split('=').nth(1) {
                return val.trim().to_string();
            }
        }
    }
    panic!("Could not determine JAVA_HOME. Set JAVA_HOME or install a JDK.");
}
