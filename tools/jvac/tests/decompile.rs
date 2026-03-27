//! Integration tests for the jvac decompiler.
//!
//! Tests the disassembly and decompilation of CAP bytecodes back to
//! assembly text and high-level JVA source.

use simrs_jcasm::jcasm;
use simrs_jcvm::cap::build_cap_blob;

/// Helper: build a CAP blob from a jcasm applet definition.
fn build_cap(aid: &[u8], methods: &[&[u8]]) -> Vec<u8> {
    let mut buf = [0u8; 4096];
    let len = build_cap_blob(aid, methods, &mut buf);
    buf[..len].to_vec()
}

// -----------------------------------------------------------------------
// Disassembly tests
// -----------------------------------------------------------------------

#[test]
fn disassemble_simple_return() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_01 {
            fn process() { bspush(42); sreturn; }
        }
    };
    let cap = build_cap(aid, methods);

    let asm = jvac::decompile::disassemble(&cap).unwrap();
    assert!(asm.contains("bspush"), "expected bspush in:\n{asm}");
    assert!(asm.contains("42"), "expected 42 in:\n{asm}");
    assert!(asm.contains("sreturn"), "expected sreturn in:\n{asm}");
}

#[test]
fn disassemble_arithmetic() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_02 {
            fn process() { sconst_3; sconst_2; sadd; sreturn; }
        }
    };
    let cap = build_cap(aid, methods);

    let asm = jvac::decompile::disassemble(&cap).unwrap();
    assert!(asm.contains("sconst_3"), "expected sconst_3 in:\n{asm}");
    assert!(asm.contains("sconst_2"), "expected sconst_2 in:\n{asm}");
    assert!(asm.contains("sadd"), "expected sadd in:\n{asm}");
}

#[test]
fn disassemble_contains_applet_aid() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_01 {
            fn process() { sconst_0; sreturn; }
        }
    };
    let cap = build_cap(aid, methods);

    let asm = jvac::decompile::disassemble(&cap).unwrap();
    assert!(asm.contains(".applet"), "expected .applet in:\n{asm}");
    assert!(asm.contains("A0"), "expected AID byte A0 in:\n{asm}");
}

#[test]
fn disassemble_contains_method_header() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_01 {
            fn process() { sconst_1; sreturn; }
        }
    };
    let cap = build_cap(aid, methods);

    let asm = jvac::decompile::disassemble(&cap).unwrap();
    assert!(asm.contains(".method"), "expected .method in:\n{asm}");
    assert!(asm.contains(".end"), "expected .end in:\n{asm}");
}

#[test]
fn disassemble_branch_instruction() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_03 {
            fn process() {
                sconst_3;
                sconst_3;
                if_scmpeq(eq);
                sconst_0;
                sreturn;
                eq:
                sconst_1;
                sreturn;
            }
        }
    };
    let cap = build_cap(aid, methods);

    let asm = jvac::decompile::disassemble(&cap).unwrap();
    assert!(asm.contains("if_scmpeq"), "expected if_scmpeq in:\n{asm}");
    // The target should be a resolved PC, formatted as 0xNNNN.
    assert!(asm.contains("0x"), "expected resolved target in:\n{asm}");
}

// -----------------------------------------------------------------------
// Decompilation tests
// -----------------------------------------------------------------------

#[test]
fn decompile_simple_return() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_01 {
            fn process() { bspush(42); sreturn; }
        }
    };
    let cap = build_cap(aid, methods);

    let source = jvac::decompile::decompile(&cap).unwrap();
    assert!(source.contains("return"), "expected return in:\n{source}");
    assert!(source.contains("42"), "expected 42 in:\n{source}");
}

#[test]
fn decompile_arithmetic_expression() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_02 {
            fn process() { sconst_3; sconst_2; sadd; sreturn; }
        }
    };
    let cap = build_cap(aid, methods);

    let source = jvac::decompile::decompile(&cap).unwrap();
    // Should reconstruct "3 + 2" or similar.
    assert!(source.contains('+') || source.contains("add"), "expected + in:\n{source}");
    assert!(source.contains("return"), "expected return in:\n{source}");
}

#[test]
fn decompile_with_branch() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_03 {
            fn process() {
                sconst_3;
                sconst_3;
                if_scmpeq(eq);
                sconst_0;
                sreturn;
                eq:
                sconst_1;
                sreturn;
            }
        }
    };
    let cap = build_cap(aid, methods);

    let source = jvac::decompile::decompile(&cap).unwrap();
    assert!(
        source.contains("if") || source.contains("=="),
        "expected if or == in:\n{source}"
    );
}

#[test]
fn decompile_local_variable_assignment() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_04 {
            fn process() {
                bspush(10);
                sstore_0;
                sload_0;
                sreturn;
            }
        }
    };
    let cap = build_cap(aid, methods);

    let source = jvac::decompile::decompile(&cap).unwrap();
    assert!(source.contains("local_0"), "expected local_0 in:\n{source}");
    assert!(source.contains("10"), "expected 10 in:\n{source}");
}

#[test]
fn decompile_subtraction() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_05 {
            fn process() { sconst_5; sconst_2; ssub; sreturn; }
        }
    };
    let cap = build_cap(aid, methods);

    let source = jvac::decompile::decompile(&cap).unwrap();
    assert!(source.contains('-'), "expected - in:\n{source}");
}

#[test]
fn decompile_void_return() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_01_06 {
            fn process() { return_void; }
        }
    };
    let cap = build_cap(aid, methods);

    let source = jvac::decompile::decompile(&cap).unwrap();
    assert!(source.contains("return"), "expected return in:\n{source}");
    assert!(source.contains("void"), "expected void return type in:\n{source}");
}

// -----------------------------------------------------------------------
// Round-trip tests
// -----------------------------------------------------------------------

#[test]
fn roundtrip_compile_decompile() {
    // Compile JVA source, then decompile, verify it's readable.
    let source = r#"
        public class Test extends Applet {
            public static short process() {
                short a = 10;
                short b = 20;
                return (short)(a + b);
            }
        }
    "#;
    let class = jvac::java_parser::parse_source(source).unwrap();
    let compiled = simrs_jccompile::compile_class(&class).unwrap();
    let cap = jvac::cap::write_cap(&compiled);

    let decompiled = jvac::decompile::decompile(&cap).unwrap();
    assert!(decompiled.contains("return"), "expected return in:\n{decompiled}");
    // The decompiled source should be functionally readable.
    assert!(!decompiled.is_empty());
}

#[test]
fn roundtrip_compile_disassemble() {
    let source = r#"
        public class Test extends Applet {
            public static short process() {
                return 42;
            }
        }
    "#;
    let class = jvac::java_parser::parse_source(source).unwrap();
    let compiled = simrs_jccompile::compile_class(&class).unwrap();
    let cap = jvac::cap::write_cap(&compiled);

    let asm = jvac::decompile::disassemble(&cap).unwrap();
    assert!(asm.contains("bspush"), "expected bspush in:\n{asm}");
    assert!(asm.contains("sreturn"), "expected sreturn in:\n{asm}");
}
