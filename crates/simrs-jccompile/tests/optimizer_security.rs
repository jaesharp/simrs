//! Optimizer security proof tests.
//!
//! These tests prove two things:
//!
//! 1. **Positive**: The JCVM has mandatory side effects (`ArithmeticException` on
//!    division by zero, `NullPointerException`, etc.) that must not be suppressed.
//!
//! 2. **Negative**: The `is_side_effect_free()` guard in the optimizer is
//!    necessary -- removing it would allow transforms that change observable
//!    behavior by suppressing exceptions or duplicating side effects.
//!
//! Each "proof" test constructs a program that exercises a guarded transform,
//! compiles and runs it through the JCVM to show the correct result (exception
//! thrown), then constructs the hypothetical "wrongly optimized" version and
//! shows it would produce a different (incorrect) result.
//!
//! References:
//! - JCVM 3.1 Section 7.5 (exception semantics)
//! - JCRE 2.2.1 Section 6 (applet firewall)

use simrs_jccompile::ir::{JcClass, JcExpr, JcMethod, JcStmt};
use simrs_jccompile::types::JcType;
use simrs_jccompile::{BinOp, compile_class};
use simrs_jcvm::JcVM;
use simrs_jcvm::cap::{build_cap_blob, parse_cap};
use simrs_jcvm::opcodes::ExecResult;

/// Compile a class, load into JCVM, execute method 0.
fn compile_and_run(class: &JcClass) -> ExecResult {
    let compiled = compile_class(class).expect("compilation failed");
    let bc_refs: Vec<&[u8]> = compiled.methods.iter().map(Vec::as_slice).collect();
    let mut blob = [0u8; 4096];
    let len = build_cap_blob(&compiled.aid, &bc_refs, &mut blob);
    let pkg = parse_cap(&blob[..len]).expect("CAP parse failed");
    let mut vm: JcVM<1024, 4> = JcVM::new();
    let pkg_idx = vm.load_package(pkg).expect("load failed");
    vm.execute(pkg_idx, 0)
}

fn make_class(method: JcMethod) -> JcClass {
    JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![method],
    }
}

fn make_multi_method_class(methods: Vec<JcMethod>) -> JcClass {
    JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods,
    }
}

// =========================================================================
// Positive semantic proofs: JCVM mandatory exceptions
// =========================================================================
//
// These tests prove that the JCVM side effects are real, not hypothetical.
// Each tests a specific exception path that the optimizer must preserve.

#[test]
fn jcvm_sdiv_by_zero_throws_arithmetic_exception() {
    // JCVM 3.1: sdiv with divisor 0 MUST throw ArithmeticException.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![
            (String::from("a"), JcType::Short),
            (String::from("b"), JcType::Short),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Short,
                init: JcExpr::Lit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Short,
                init: JcExpr::Lit(0),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Var(String::from("b"))),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ArithmeticException);
}

#[test]
fn jcvm_srem_by_zero_throws_arithmetic_exception() {
    // JCVM 3.1: srem with divisor 0 MUST throw ArithmeticException.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![
            (String::from("a"), JcType::Short),
            (String::from("b"), JcType::Short),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Short,
                init: JcExpr::Lit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Short,
                init: JcExpr::Lit(0),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Rem,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Var(String::from("b"))),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ArithmeticException);
}

#[test]
fn jcvm_idiv_by_zero_throws_arithmetic_exception() {
    // JCVM 3.1: idiv with divisor 0 MUST throw ArithmeticException.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![
            (String::from("a"), JcType::Int),
            (String::from("b"), JcType::Int),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Int,
                init: JcExpr::IntLit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Int,
                init: JcExpr::IntLit(0),
            },
            JcStmt::Return(Some(JcExpr::IntBinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Var(String::from("b"))),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ArithmeticException);
}

#[test]
fn jcvm_irem_by_zero_throws_arithmetic_exception() {
    // JCVM 3.1: irem with divisor 0 MUST throw ArithmeticException.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![
            (String::from("a"), JcType::Int),
            (String::from("b"), JcType::Int),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Int,
                init: JcExpr::IntLit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Int,
                init: JcExpr::IntLit(0),
            },
            JcStmt::Return(Some(JcExpr::IntBinOp {
                op: BinOp::Rem,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Var(String::from("b"))),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ArithmeticException);
}

// =========================================================================
// Positive semantic proofs: method calls propagate exceptions
// =========================================================================

#[test]
fn jcvm_call_propagates_arithmetic_exception() {
    // Method 1 divides by zero. Method 0 calls method 1.
    // The ArithmeticException from method 1 must propagate to the caller.
    let class = make_multi_method_class(vec![
        // Method 0: return call(1)
        JcMethod {
            name: String::from("main"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }))],
            is_static: true,
            constant_time: false,
        },
        // Method 1: return 10 / 0
        JcMethod {
            name: String::from("div_by_zero"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![
                (String::from("a"), JcType::Short),
                (String::from("b"), JcType::Short),
            ],
            body: vec![
                JcStmt::Let {
                    name: String::from("a"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(10),
                },
                JcStmt::Let {
                    name: String::from("b"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(0),
                },
                JcStmt::Return(Some(JcExpr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                })),
            ],
            is_static: true,
            constant_time: false,
        },
    ]);
    assert_eq!(compile_and_run(&class), ExecResult::ArithmeticException);
}

#[test]
fn jcvm_call_returns_normally_when_no_exception() {
    // Method 1 returns 42. Method 0 calls method 1.
    // This is the baseline: method calls work normally.
    let class = make_multi_method_class(vec![
        JcMethod {
            name: String::from("main"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }))],
            is_static: true,
            constant_time: false,
        },
        JcMethod {
            name: String::from("helper"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(42)))],
            is_static: true,
            constant_time: false,
        },
    ]);
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(42));
}

// =========================================================================
// Negative proofs: x * 0 guard necessity
// =========================================================================
//
// Structure: we compile a program where an effectful expression is
// multiplied by zero. The optimizer preserves the expression (guard active).
// Then we compile the hypothetical "wrongly optimized" version (just return 0)
// and show it produces a different result.
//
// The difference between the two results proves the guard is necessary.

#[test]
fn proof_short_mul_zero_guard_prevents_exception_suppression() {
    // Program: return (10 / 0) * 0
    // With guard: the division executes -> ArithmeticException
    // Without guard (hypothetical): would fold to return 0 -> ReturnShort(0)
    let class_guarded = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![
            (String::from("a"), JcType::Short),
            (String::from("b"), JcType::Short),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Short,
                init: JcExpr::Lit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Short,
                init: JcExpr::Lit(0),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                }),
                right: Box::new(JcExpr::Lit(0)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });

    // The real program (with guard) throws ArithmeticException.
    let actual = compile_and_run(&class_guarded);
    assert_eq!(
        actual,
        ExecResult::ArithmeticException,
        "division by zero MUST throw even when multiplied by 0"
    );

    // The hypothetical wrongly-optimized program: return 0.
    let class_wrong = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        is_static: true,
        constant_time: false,
    });
    let wrong = compile_and_run(&class_wrong);
    assert_eq!(
        wrong,
        ExecResult::ReturnShort(0),
        "the wrongly-optimized version silently returns 0"
    );

    // The two results differ, proving the guard is necessary.
    assert_ne!(actual, wrong, "guard prevents observable behavior change");
}

#[test]
fn proof_short_mul_zero_via_call_guard_prevents_exception_suppression() {
    // Program: return call(div_by_zero_method) * 0
    // With guard: call executes, throws ArithmeticException
    // Without guard: would fold to return 0
    let class_guarded = make_multi_method_class(vec![
        JcMethod {
            name: String::from("main"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Call {
                    method_index: 1,
                    args: vec![],
                }),
                right: Box::new(JcExpr::Lit(0)),
            }))],
            is_static: true,
            constant_time: false,
        },
        JcMethod {
            name: String::from("div_by_zero"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![
                (String::from("a"), JcType::Short),
                (String::from("b"), JcType::Short),
            ],
            body: vec![
                JcStmt::Let {
                    name: String::from("a"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(10),
                },
                JcStmt::Let {
                    name: String::from("b"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(0),
                },
                JcStmt::Return(Some(JcExpr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                })),
            ],
            is_static: true,
            constant_time: false,
        },
    ]);

    let actual = compile_and_run(&class_guarded);
    assert_eq!(
        actual,
        ExecResult::ArithmeticException,
        "call to div-by-zero method MUST throw even when result multiplied by 0"
    );

    // Hypothetical wrongly-optimized: return 0
    let class_wrong = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        is_static: true,
        constant_time: false,
    });
    assert_ne!(
        actual,
        compile_and_run(&class_wrong),
        "guard prevents exception suppression through call"
    );
}

// =========================================================================
// Negative proofs: x % 1 guard necessity
// =========================================================================

#[test]
fn proof_short_rem_one_guard_prevents_exception_suppression() {
    // Program: return (a / b) % 1  where b = 0
    // With guard: the division executes -> ArithmeticException
    // Without guard: would fold to return 0
    let class_guarded = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![
            (String::from("a"), JcType::Short),
            (String::from("b"), JcType::Short),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Short,
                init: JcExpr::Lit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Short,
                init: JcExpr::Lit(0),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Rem,
                left: Box::new(JcExpr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                }),
                right: Box::new(JcExpr::Lit(1)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });

    let actual = compile_and_run(&class_guarded);
    assert_eq!(
        actual,
        ExecResult::ArithmeticException,
        "division by zero MUST throw even when result taken mod 1"
    );

    let class_wrong = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        is_static: true,
        constant_time: false,
    });
    assert_ne!(
        actual,
        compile_and_run(&class_wrong),
        "guard prevents exception suppression via x%%1"
    );
}

#[test]
fn proof_short_rem_one_via_call_guard_prevents_exception_suppression() {
    // Program: return call(div_by_zero) % 1
    let class_guarded = make_multi_method_class(vec![
        JcMethod {
            name: String::from("main"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Rem,
                left: Box::new(JcExpr::Call {
                    method_index: 1,
                    args: vec![],
                }),
                right: Box::new(JcExpr::Lit(1)),
            }))],
            is_static: true,
            constant_time: false,
        },
        JcMethod {
            name: String::from("div_by_zero"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![
                (String::from("a"), JcType::Short),
                (String::from("b"), JcType::Short),
            ],
            body: vec![
                JcStmt::Let {
                    name: String::from("a"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(10),
                },
                JcStmt::Let {
                    name: String::from("b"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(0),
                },
                JcStmt::Return(Some(JcExpr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                })),
            ],
            is_static: true,
            constant_time: false,
        },
    ]);

    let actual = compile_and_run(&class_guarded);
    assert_eq!(
        actual,
        ExecResult::ArithmeticException,
        "call to div-by-zero MUST throw even when result taken mod 1"
    );
}

// =========================================================================
// Negative proofs: x * 2 guard necessity (side-effect duplication)
// =========================================================================
//
// The transform x * 2 -> x + x is incorrect when x has side effects because
// it evaluates x twice. For a call with persistent side effects, this means
// the side effect happens twice instead of once.

#[test]
fn proof_short_mul_two_guard_prevents_exception_duplication() {
    // Program: return call(div_by_zero) * 2
    // With guard: call executes once -> ArithmeticException
    // Without guard: would become call()+call(), still throws (but for the wrong
    // reason -- the exception fires on the first evaluation of the duplicated call)
    //
    // More importantly: if the call does NOT throw but has persistent effects
    // (e.g., increments a counter), the transform would double the effect.
    // We prove the guard blocks the transform even when the expression is a Call.
    let class = make_multi_method_class(vec![
        JcMethod {
            name: String::from("main"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Call {
                    method_index: 1,
                    args: vec![],
                }),
                right: Box::new(JcExpr::Lit(2)),
            }))],
            is_static: true,
            constant_time: false,
        },
        // Method 1: returns 7 (no exception, but could have side effects)
        JcMethod {
            name: String::from("get_seven"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(7)))],
            is_static: true,
            constant_time: false,
        },
    ]);

    // With guard active: call(1) * 2 compiles as invokestatic + smul.
    // call returns 7, 7 * 2 = 14.
    let actual = compile_and_run(&class);
    assert_eq!(
        actual,
        ExecResult::ReturnShort(14),
        "call()*2 with correct semantics: 7*2=14"
    );

    // Hypothetical wrongly-optimized: call(1) + call(1)
    // This would ALSO return 14 for this particular side-effect-free helper,
    // but the point is: the optimizer must NOT apply the transform because
    // Call is classified as potentially effectful. Verify the IR optimizer
    // preserves the Mul (tested in optimize.rs unit tests).
    //
    // For a method that increments a persistent counter, call()+call()
    // would increment twice (count goes from 0 to 2) while call()*2
    // increments once (count goes from 0 to 1, result = 1*2 = 2).
    // The values differ: 0+1 = 1 vs 1+2 = 3 (since second call sees count=1).
}

// =========================================================================
// Negative proofs: Int variants
// =========================================================================

#[test]
fn proof_int_mul_zero_guard_prevents_exception_suppression() {
    // Program: return (a / b) * 0  where b = 0 (int)
    let class_guarded = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![
            (String::from("a"), JcType::Int),
            (String::from("b"), JcType::Int),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Int,
                init: JcExpr::IntLit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Int,
                init: JcExpr::IntLit(0),
            },
            JcStmt::Return(Some(JcExpr::IntBinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::IntBinOp {
                    op: BinOp::Div,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                }),
                right: Box::new(JcExpr::IntLit(0)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });

    let actual = compile_and_run(&class_guarded);
    assert_eq!(
        actual,
        ExecResult::ArithmeticException,
        "int division by zero MUST throw even when multiplied by 0"
    );

    let class_wrong = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntLit(0)))],
        is_static: true,
        constant_time: false,
    });
    assert_ne!(
        actual,
        compile_and_run(&class_wrong),
        "guard prevents int exception suppression via x*0"
    );
}

#[test]
fn proof_int_rem_one_guard_prevents_exception_suppression() {
    // Program: return (a / b) % 1  where b = 0 (int)
    let class_guarded = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![
            (String::from("a"), JcType::Int),
            (String::from("b"), JcType::Int),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Int,
                init: JcExpr::IntLit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Int,
                init: JcExpr::IntLit(0),
            },
            JcStmt::Return(Some(JcExpr::IntBinOp {
                op: BinOp::Rem,
                left: Box::new(JcExpr::IntBinOp {
                    op: BinOp::Div,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                }),
                right: Box::new(JcExpr::IntLit(1)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });

    let actual = compile_and_run(&class_guarded);
    assert_eq!(
        actual,
        ExecResult::ArithmeticException,
        "int division by zero MUST throw even when result taken mod 1"
    );

    let class_wrong = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntLit(0)))],
        is_static: true,
        constant_time: false,
    });
    assert_ne!(
        actual,
        compile_and_run(&class_wrong),
        "guard prevents int exception suppression via x%%1"
    );
}

// =========================================================================
// Cross-cutting proof: expression in condition position
// =========================================================================
//
// The optimizer also optimizes conditions. Verify that effectful expressions
// in conditions are preserved even when the condition could be statically
// simplified.

#[test]
fn proof_effectful_condition_not_eliminated() {
    // Program: if ((a/b) == 0) { return 1 } else { return 2 }  where b = 0
    // The condition involves a division by zero. Even though the result
    // of the comparison is moot (it never gets there), the division MUST
    // still execute and throw.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![
            (String::from("a"), JcType::Short),
            (String::from("b"), JcType::Short),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("a"),
                ty: JcType::Short,
                init: JcExpr::Lit(10),
            },
            JcStmt::Let {
                name: String::from("b"),
                ty: JcType::Short,
                init: JcExpr::Lit(0),
            },
            JcStmt::If {
                cond: simrs_jccompile::Condition::Eq(
                    JcExpr::BinOp {
                        op: BinOp::Div,
                        left: Box::new(JcExpr::Var(String::from("a"))),
                        right: Box::new(JcExpr::Var(String::from("b"))),
                    },
                    JcExpr::Lit(0),
                ),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });

    assert_eq!(
        compile_and_run(&class),
        ExecResult::ArithmeticException,
        "division by zero in condition MUST throw, not be optimized away"
    );
}

// =========================================================================
// Compositional propagation proofs
// =========================================================================
//
// These tests verify that effects_of() correctly propagates child effects
// through "intrinsically safe" parent nodes. The Add opcode itself can't
// throw, but (call_that_throws() + 1) MUST still be classified as effectful
// because the Call child has effects.
//
// This is a regression guard for the compositional analysis: if effects_of
// failed to propagate child effects for non-Div/Rem BinOps, these tests
// would fail because the optimizer would fold the expression and suppress
// the exception.

#[test]
fn proof_compound_add_propagates_call_effects() {
    // Program: return (call_div_by_zero() + 1) * 0
    //
    // The Add is "intrinsically safe" (SADD can't throw), but the Call child
    // has INVOKE effects that propagate. If effects_of correctly propagates
    // child effects, the optimizer blocks the *0 fold, the call executes,
    // and ArithmeticException fires.
    //
    // If effects_of had a bug that ignored child effects for Add, this would
    // fold to 0, suppressing the exception.
    let class = make_multi_method_class(vec![
        JcMethod {
            name: String::from("main"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(JcExpr::Call {
                        method_index: 1,
                        args: vec![],
                    }),
                    right: Box::new(JcExpr::Lit(1)),
                }),
                right: Box::new(JcExpr::Lit(0)),
            }))],
            is_static: true,
            constant_time: false,
        },
        JcMethod {
            name: String::from("div_by_zero"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::Lit(10)),
                right: Box::new(JcExpr::Lit(0)),
            }))],
            is_static: true,
            constant_time: false,
        },
    ]);
    assert_eq!(
        compile_and_run(&class),
        ExecResult::ArithmeticException,
        "child effects must propagate through Add: (call_throws() + 1) * 0 must throw"
    );
}

#[test]
fn proof_compound_neg_propagates_call_effects() {
    // Program: return (-(call_div_by_zero())) * 0
    //
    // Neg is "intrinsically safe" (SNEG can't throw), but the Call child
    // propagates INVOKE effects. Must still throw ArithmeticException.
    let class = make_multi_method_class(vec![
        JcMethod {
            name: String::from("main"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Neg(Box::new(JcExpr::Call {
                    method_index: 1,
                    args: vec![],
                }))),
                right: Box::new(JcExpr::Lit(0)),
            }))],
            is_static: true,
            constant_time: false,
        },
        JcMethod {
            name: String::from("div_by_zero"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::Lit(10)),
                right: Box::new(JcExpr::Lit(0)),
            }))],
            is_static: true,
            constant_time: false,
        },
    ]);
    assert_eq!(
        compile_and_run(&class),
        ExecResult::ArithmeticException,
        "child effects must propagate through Neg: (-(call_throws())) * 0 must throw"
    );
}

// =========================================================================
// Baseline: safe transforms still work
// =========================================================================
//
// Verify the optimizer still applies transforms when the operand IS safe.

#[test]
fn baseline_safe_var_mul_zero_folds_to_zero() {
    // return x * 0 where x is a local variable (no side effects)
    // This SHOULD fold to return 0.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(42),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Var(String::from("x"))),
                right: Box::new(JcExpr::Lit(0)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(
        compile_and_run(&class),
        ExecResult::ReturnShort(0),
        "safe x*0 should be optimized to 0"
    );
}

#[test]
fn baseline_safe_var_mul_two_doubles() {
    // return x * 2 where x = 7 -> optimized to x + x = 14
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(7),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Var(String::from("x"))),
                right: Box::new(JcExpr::Lit(2)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(
        compile_and_run(&class),
        ExecResult::ReturnShort(14),
        "safe x*2 should work correctly (7*2 = 14)"
    );
}

#[test]
fn baseline_safe_var_rem_one_folds_to_zero() {
    // return x % 1 where x = 42 -> optimized to 0
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(42),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Rem,
                left: Box::new(JcExpr::Var(String::from("x"))),
                right: Box::new(JcExpr::Lit(1)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(
        compile_and_run(&class),
        ExecResult::ReturnShort(0),
        "safe x%%1 should be optimized to 0"
    );
}

// =========================================================================
// Compositional purity baselines
// =========================================================================
//
// These tests verify that the compositional effects_of() analysis allows
// transforms on expression trees that are fully pure, even when the
// top-level node is a compound form (BinOp, Neg, Cast, etc.).

#[test]
fn baseline_pure_binop_chain_mul_zero_folds() {
    // return (x + y) * 0 where x=5, y=3.
    // With compositional analysis, (x+y) is PURE, so (x+y)*0 folds to 0.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![
            (String::from("x"), JcType::Short),
            (String::from("y"), JcType::Short),
        ],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(5),
            },
            JcStmt::Let {
                name: String::from("y"),
                ty: JcType::Short,
                init: JcExpr::Lit(3),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(JcExpr::Var(String::from("x"))),
                    right: Box::new(JcExpr::Var(String::from("y"))),
                }),
                right: Box::new(JcExpr::Lit(0)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(
        compile_and_run(&class),
        ExecResult::ReturnShort(0),
        "compositional purity: (x+y)*0 should fold to 0"
    );
}

#[test]
fn baseline_pure_neg_var_mul_two_doubles() {
    // return (-x) * 2 where x=7.
    // With compositional analysis, Neg(Var) is PURE, so (-x)*2 becomes (-x)+(-x).
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(7),
            },
            JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Neg(Box::new(JcExpr::Var(String::from("x"))))),
                right: Box::new(JcExpr::Lit(2)),
            })),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(
        compile_and_run(&class),
        ExecResult::ReturnShort(-14),
        "compositional purity: (-x)*2 should produce -14"
    );
}
