//! Integration tests for the jcasm! macro.

use simrs_jcasm::jcasm;

#[test]
fn assemble_minimal_return() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_01 {
            fn process() {
                return_void;
            }
        }
    };

    assert_eq!(aid, &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x02, 0x01]);
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0], &[0x7A]); // RETURN opcode
}

#[test]
fn assemble_array_bounds_test() {
    // JCVM 3.2 Section 3.11.3: Array bounds enforcement
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_02 {
            fn process() {
                sload_0;
                bspush(8);
                baload;
                sreturn;
            }
        }
    };

    assert_eq!(aid, &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x02, 0x02]);
    assert_eq!(methods[0], &[0x1C, 0x10, 0x08, 0x25, 0x78]);
}

#[test]
fn assemble_firewall_test() {
    // JCVM 3.2 Section 6.2.4: Firewall enforcement on getfield_b
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_03 {
            fn process() {
                sload_0;
                getfield_b(0);
                sreturn;
            }
        }
    };

    assert_eq!(methods[0], &[0x1C, 0x84, 0x00, 0x78]);
}

#[test]
fn assemble_type_confusion_test() {
    // Type confusion: saload on byte[] should raise ArrayStoreException
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_04 {
            fn process() {
                sload_0;
                sconst_0;
                saload;
                sreturn;
            }
        }
    };

    assert_eq!(methods[0], &[0x1C, 0x03, 0x26, 0x78]);
}

#[test]
fn assemble_branch_forward() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_05 {
            fn process() {
                sconst_0;
                sconst_1;
                if_scmpeq(skip);
                sconst_2;
                skip:
                sreturn;
            }
        }
    };

    // sconst_0(1) + sconst_1(1) + if_scmpeq(2) + sconst_2(1) + sreturn(1) = 6 bytes
    // if_scmpeq at pc=2, target "skip" at pc=5, offset = 5-2 = 3
    assert_eq!(methods[0], &[0x03, 0x04, 0x6A, 0x03, 0x05, 0x78]);
}

#[test]
fn assemble_branch_backward() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_06 {
            fn process() {
                top:
                sconst_0;
                goto(top);
            }
        }
    };

    // top at pc=0, sconst_0(1), goto at pc=1, offset = 0-1 = -1 = 0xFF
    assert_eq!(methods[0], &[0x03, 0x70, 0xFF]);
}

#[test]
fn assemble_multiple_methods() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_07 {
            fn install() {
                return_void;
            }
            fn process() {
                sconst_1;
                sreturn;
            }
        }
    };

    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0], &[0x7A]); // install: return
    assert_eq!(methods[1], &[0x04, 0x78]); // process: sconst_1, sreturn
}

#[test]
fn assemble_arithmetic() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_08 {
            fn process() {
                sconst_3;
                sconst_2;
                sadd;
                sreturn;
            }
        }
    };

    assert_eq!(methods[0], &[0x06, 0x05, 0x41, 0x78]);
}

/// Build a CAP blob from assembled bytecode and parse it.
#[test]
fn assemble_and_parse_cap() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_01 {
            fn process() {
                sload_0;
                bspush(8);
                baload;
                sreturn;
            }
        }
    };

    let mut blob = [0u8; 256];
    let len = simrs_jcvm::cap::build_cap_blob(aid, methods, &mut blob);
    let pkg = simrs_jcvm::cap::parse_cap(&blob[..len]).expect("valid CAP");

    assert_eq!(pkg.aid_len, 7);
    assert_eq!(&pkg.aid[..7], &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x02, 0x01]);
    assert_eq!(pkg.method_count, 1);
}

/// Full round-trip: assemble -> CAP -> load -> execute.
#[test]
fn assemble_load_execute() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_02_01 {
            fn process() {
                sconst_3;
                sconst_2;
                sadd;
                sreturn;
            }
        }
    };

    let mut blob = [0u8; 256];
    let len = simrs_jcvm::cap::build_cap_blob(aid, methods, &mut blob);
    let pkg = simrs_jcvm::cap::parse_cap(&blob[..len]).unwrap();

    let mut vm = simrs_jcvm::JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).expect("load succeeded");
    let result = vm.execute(idx, 0);

    assert_eq!(result, simrs_jcvm::opcodes::ExecResult::ReturnShort(5)); // 3 + 2 = 5
}
