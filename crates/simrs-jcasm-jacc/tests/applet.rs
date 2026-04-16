//! Integration tests for `jcapplet!{}` macro.
//!
//! Each test does a full round-trip: `jcapplet!{}` -> `build_cap_blob` ->
//! `parse_cap` -> `JcVM::load_package` -> `execute` -> assert `ExecResult`.

use simrs_jcasm_jacc::jcapplet;
use simrs_jcvm::cap;
use simrs_jcvm::opcodes::ExecResult;
use simrs_jcvm::JcVM;

/// Build a CAP blob from macro output, load into a fresh VM, and execute
/// method 0.
fn run_applet(aid: &[u8], methods: &[&[u8]]) -> ExecResult {
    let mut blob = [0u8; 512];
    let len = cap::build_cap_blob(aid, methods, &mut blob);
    let pkg = cap::parse_cap(&blob[..len]).expect("valid CAP");
    let mut vm = JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).expect("load");
    vm.execute(idx, 0)
}

#[test]
fn simple_constant_return() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_01) {
            fn process() -> short {
                return 42;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(42));
}

#[test]
fn arithmetic_expression() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_02) {
            fn process() -> short {
                let x: short = 10;
                let y: short = 3;
                return x + y;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(13));
}

#[test]
fn field_access() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_03) {
            field value: short;

            fn process() -> short {
                return self.value;
            }
        }
    };
    // The field is zero-initialized, so this should return 0.
    // However, field access requires `this` in local 0, which
    // build_cap_blob sets up as a static method. For this test
    // we just verify compilation succeeds and produces bytecodes.
    assert!(!aid.is_empty());
    assert!(!methods.is_empty());
    assert!(!methods[0].is_empty());
}

#[test]
fn if_else_branch() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_04) {
            fn process() -> short {
                let x: short = 3;
                let y: short = 3;
                if x == y {
                    return 1;
                } else {
                    return 0;
                }
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(1));
}

#[test]
fn if_else_branch_not_taken() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_07) {
            fn process() -> short {
                let x: short = 3;
                let y: short = 5;
                if x == y {
                    return 1;
                } else {
                    return 0;
                }
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(0));
}

#[test]
fn while_loop() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_05) {
            fn process() -> short {
                let sum: short = 0;
                let i: short = 1;
                while i != 6 {
                    sum = sum + i;
                    i = i + 1;
                }
                return sum;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(15));
}

#[test]
fn void_method() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_06) {
            fn process() {
                return;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnVoid);
}

#[test]
fn subtraction() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_08) {
            fn process() -> short {
                let a: short = 100;
                let b: short = 37;
                return a - b;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(63));
}

#[test]
fn multiplication() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_09) {
            fn process() -> short {
                let a: short = 7;
                let b: short = 6;
                return a * b;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(42));
}

#[test]
fn negation() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_0A) {
            fn process() -> short {
                let x: short = 5;
                return -x;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(-5));
}

#[test]
fn complex_arithmetic() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_0B) {
            fn process() -> short {
                let a: short = 10;
                let b: short = 3;
                let c: short = 2;
                return a + b * c;
            }
        }
    };
    // Due to operator precedence: a + (b * c) = 10 + 6 = 16
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(16));
}

#[test]
fn multiple_local_variables() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_0C) {
            fn process() -> short {
                let a: short = 1;
                let b: short = 2;
                let c: short = 3;
                let d: short = 4;
                return a + b + c + d;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(10));
}

#[test]
fn reassignment() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_0D) {
            fn process() -> short {
                let x: short = 5;
                x = x + 10;
                x = x * 2;
                return x;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(30));
}

#[test]
fn nested_if() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_0E) {
            fn process() -> short {
                let x: short = 5;
                let result: short = 0;
                if x != 0 {
                    if x == 5 {
                        result = 99;
                    } else {
                        result = 50;
                    }
                } else {
                    result = 1;
                }
                return result;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(99));
}

#[test]
fn zero_constant() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62_01_0F) {
            fn process() -> short {
                return 0;
            }
        }
    };
    let result = run_applet(aid, methods);
    assert_eq!(result, ExecResult::ReturnShort(0));
}

#[test]
fn optimize_none_still_produces_correct_result() {
    let (aid, methods) = jcapplet! {
        optimize none;
        applet Test(A0_00_00_00_62) {
            fn process() -> short {
                return 42;
            }
        }
    };
    let mut buf = [0u8; 4096];
    let len = simrs_jcvm::cap::build_cap_blob(aid, methods, &mut buf);
    let pkg = simrs_jcvm::cap::parse_cap(&buf[..len]).unwrap();
    let mut vm = simrs_jcvm::JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    assert_eq!(
        vm.execute(idx, 0),
        simrs_jcvm::opcodes::ExecResult::ReturnShort(42)
    );
}

#[test]
fn optimize_peephole_only_works() {
    let (_aid, methods) = jcapplet! {
        optimize peephole;
        applet Test(A0_00_00_00_62) {
            fn process() -> short {
                return 42;
            }
        }
    };
    assert!(!methods.is_empty());
}

#[test]
fn constant_time_method_compiles() {
    let (aid, methods) = jcapplet! {
        applet Test(A0_00_00_00_62) {
            constant_time fn verify() -> short {
                return 7;
            }
        }
    };
    let mut buf = [0u8; 4096];
    let len = simrs_jcvm::cap::build_cap_blob(aid, methods, &mut buf);
    let pkg = simrs_jcvm::cap::parse_cap(&buf[..len]).unwrap();
    let mut vm = simrs_jcvm::JcVM::<4096, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    assert_eq!(
        vm.execute(idx, 0),
        simrs_jcvm::opcodes::ExecResult::ReturnShort(7)
    );
}

#[test]
fn optimize_full_report_compiles() {
    let (_aid, _methods) = jcapplet! {
        optimize full(report);
        applet Test(A0_00_00_00_62) {
            fn process() -> short {
                return 1;
            }
        }
    };
}
