fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let config = cbindgen::Config::from_file(format!("{crate_dir}/cbindgen.toml"))
        .expect("cbindgen.toml not found");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen failed")
        .write_to_file(format!("{out_dir}/simrs.h"));

    println!("cargo::rerun-if-changed=src/lib.rs");
    println!("cargo::rerun-if-changed=cbindgen.toml");
}
