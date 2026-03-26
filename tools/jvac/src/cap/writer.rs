//! CAP file writer.
//!
//! Produces binary CAP blobs from compiled JCVM bytecodes using the
//! [`simrs_jcvm::cap::build_cap_blob`] format.

use simrs_jccompile::codegen::CompiledClass;

/// Maximum output buffer size for a single CAP file.
const CAP_BUF_SIZE: usize = 8192;

/// Write a compiled class to CAP blob format.
///
/// Returns the CAP bytes suitable for loading via `simrs_jcvm::cap::parse_cap`.
pub fn write_cap(compiled: &CompiledClass) -> Vec<u8> {
    let methods: Vec<&[u8]> = compiled.methods.iter().map(Vec::as_slice).collect();
    let mut buf = vec![0u8; CAP_BUF_SIZE];
    let len = simrs_jcvm::cap::build_cap_blob(&compiled.aid, &methods, &mut buf);
    buf.truncate(len);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_jcvm::cap::parse_cap;

    #[test]
    fn write_and_parse_roundtrip() {
        let compiled = CompiledClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            methods: vec![
                vec![0x03, 0x78], // sconst_0, sreturn
            ],
        };
        let cap_bytes = write_cap(&compiled);
        assert!(!cap_bytes.is_empty());

        let pkg = parse_cap(&cap_bytes).unwrap();
        assert!(pkg.aid_matches(&[0xA0, 0x00, 0x00, 0x00, 0x62]));
        assert_eq!(pkg.method_count, 1);
        let m = pkg.method(0).unwrap();
        assert_eq!(m.bytecode_len, 2);
        assert_eq!(&m.bytecode[..2], &[0x03, 0x78]);
    }

    #[test]
    fn write_multiple_methods() {
        let compiled = CompiledClass {
            aid: vec![0xA0, 0x01, 0x02, 0x03, 0x04],
            methods: vec![
                vec![0x04, 0x78],       // sconst_1, sreturn
                vec![0x10, 42, 0x78],   // bspush 42, sreturn
            ],
        };
        let cap_bytes = write_cap(&compiled);
        let pkg = parse_cap(&cap_bytes).unwrap();
        assert_eq!(pkg.method_count, 2);
    }
}
