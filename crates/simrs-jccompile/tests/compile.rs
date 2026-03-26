//! Integration tests: compile `JcClass` IR, load via JCVM, execute, verify.

use simrs_jccompile::ir::{Condition, JcClass, JcExpr, JcMethod, JcStmt, LValue};
use simrs_jccompile::types::JcType;
use simrs_jccompile::{compile_class, BinOp};
use simrs_jcvm::cap::{build_cap_blob, parse_cap};
use simrs_jcvm::opcodes::ExecResult;
use simrs_jcvm::JcVM;

/// Helper: compile a class, build a CAP blob, load into a VM, execute method 0.
fn compile_and_run(class: &JcClass) -> ExecResult {
    let compiled = compile_class(class).expect("compilation failed");

    // Build bytecode slice references for build_cap_blob.
    let bc_refs: Vec<&[u8]> = compiled.methods.iter().map(Vec::as_slice).collect();

    let mut blob = [0u8; 4096];
    let len = build_cap_blob(&compiled.aid, &bc_refs, &mut blob);
    let pkg = parse_cap(&blob[..len]).expect("CAP parse failed");

    let mut vm: JcVM<1024, 4> = JcVM::new();
    let pkg_idx = vm.load_package(pkg).expect("load failed");
    vm.execute(pkg_idx, 0)
}

// -----------------------------------------------------------------------
// Test: simple constant return
// -----------------------------------------------------------------------

#[test]
fn constant_return_42() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("process"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(42)))],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(42));
}

#[test]
fn constant_return_zero() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0));
}

#[test]
fn constant_return_negative() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(-1)))],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(-1));
}

#[test]
fn constant_return_large() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(1000)))],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1000));
}

// -----------------------------------------------------------------------
// Test: arithmetic
// -----------------------------------------------------------------------

#[test]
fn arithmetic_add() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Lit(3)),
                right: Box::new(JcExpr::Lit(2)),
            }))],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(5));
}

#[test]
fn arithmetic_sub() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Sub,
                left: Box::new(JcExpr::Lit(5)),
                right: Box::new(JcExpr::Lit(3)),
            }))],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(2));
}

#[test]
fn arithmetic_mul() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Lit(4)),
                right: Box::new(JcExpr::Lit(3)),
            }))],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(12));
}

// -----------------------------------------------------------------------
// Test: local variables
// -----------------------------------------------------------------------

#[test]
fn local_variables_add() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
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
                    init: JcExpr::Lit(3),
                },
                JcStmt::Let {
                    name: String::from("y"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(2),
                },
                JcStmt::Return(Some(JcExpr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(JcExpr::Var(String::from("x"))),
                    right: Box::new(JcExpr::Var(String::from("y"))),
                })),
            ],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(5));
}

// -----------------------------------------------------------------------
// Test: if/else
// -----------------------------------------------------------------------

#[test]
fn if_else_eq_true_branch() {
    // x = 0; if x == 0 { return 1 } else { return 2 }
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(0),
                },
                JcStmt::If {
                    cond: Condition::Eq(
                        JcExpr::Var(String::from("x")),
                        JcExpr::Lit(0),
                    ),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
                },
            ],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn if_else_eq_false_branch() {
    // x = 1; if x == 0 { return 1 } else { return 2 }
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(1),
                },
                JcStmt::If {
                    cond: Condition::Eq(
                        JcExpr::Var(String::from("x")),
                        JcExpr::Lit(0),
                    ),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
                },
            ],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(2));
}

// -----------------------------------------------------------------------
// Test: while loop
// -----------------------------------------------------------------------

#[test]
fn while_loop_sum_1_to_5() {
    // i=1; sum=0; while(i != 6) { sum = sum + i; i = i + 1; } return sum;
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![
                (String::from("i"), JcType::Short),
                (String::from("sum"), JcType::Short),
            ],
            body: vec![
                JcStmt::Let {
                    name: String::from("i"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(1),
                },
                JcStmt::Let {
                    name: String::from("sum"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(0),
                },
                JcStmt::While {
                    cond: Condition::Ne(
                        JcExpr::Var(String::from("i")),
                        JcExpr::Lit(6),
                    ),
                    body: vec![
                        JcStmt::Assign {
                            target: LValue::Var(String::from("sum")),
                            value: JcExpr::BinOp {
                                op: BinOp::Add,
                                left: Box::new(JcExpr::Var(String::from("sum"))),
                                right: Box::new(JcExpr::Var(String::from("i"))),
                            },
                        },
                        JcStmt::Assign {
                            target: LValue::Var(String::from("i")),
                            value: JcExpr::BinOp {
                                op: BinOp::Add,
                                left: Box::new(JcExpr::Var(String::from("i"))),
                                right: Box::new(JcExpr::Lit(1)),
                            },
                        },
                    ],
                },
                JcStmt::Return(Some(JcExpr::Var(String::from("sum")))),
            ],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(15));
}

// -----------------------------------------------------------------------
// Test: negation
// -----------------------------------------------------------------------

#[test]
fn negation() {
    // x = 7; return -x;
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
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
                JcStmt::Return(Some(JcExpr::Neg(Box::new(JcExpr::Var(String::from("x")))))),
            ],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(-7));
}

// -----------------------------------------------------------------------
// Test: void return
// -----------------------------------------------------------------------

#[test]
fn void_return() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Void,
            locals: vec![],
            body: vec![JcStmt::Return(None)],
            is_static: true,
        }],
    };
    assert_eq!(compile_and_run(&class), ExecResult::ReturnVoid);
}

// -----------------------------------------------------------------------
// Test: compilation error for undefined variable
// -----------------------------------------------------------------------

#[test]
fn compile_error_undefined_var() {
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Var(String::from("x"))))],
            is_static: true,
        }],
    };
    let result = compile_class(&class);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(!errors.is_empty());
    assert!(errors[0].message.contains("undefined variable"));
}
