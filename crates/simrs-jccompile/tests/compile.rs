//! Integration tests: compile `JcClass` IR, load via JCVM, execute, verify.

use simrs_jccompile::ir::{Condition, JcClass, JcExpr, JcField, JcMethod, JcStmt, LValue};
use simrs_jccompile::types::JcType;
use simrs_jccompile::{BinOp, compile_class};
use simrs_jcvm::JcVM;
use simrs_jcvm::cap::{build_cap_blob, parse_cap};
use simrs_jcvm::opcodes::ExecResult;

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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
                    cond: Condition::Eq(JcExpr::Var(String::from("x")), JcExpr::Lit(0)),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
                },
            ],
            is_static: true,
            constant_time: false,
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
                    cond: Condition::Eq(JcExpr::Var(String::from("x")), JcExpr::Lit(0)),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
                },
            ],
            is_static: true,
            constant_time: false,
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
                    cond: Condition::Ne(JcExpr::Var(String::from("i")), JcExpr::Lit(6)),
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
        }],
    };
    let result = compile_class(&class);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(!errors.is_empty());
    assert!(errors[0].message.contains("undefined variable"));
}

// =======================================================================
// NEW TESTS: Extended opcode coverage
// =======================================================================

/// Helper: build a minimal static method class.
fn make_class(method: JcMethod) -> JcClass {
    JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![],
        methods: vec![method],
    }
}

// -----------------------------------------------------------------------
// Int literal
// -----------------------------------------------------------------------

#[test]
fn int_literal_small() {
    // return int 3
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntLit(3)))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(3));
}

#[test]
fn int_literal_large() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntLit(100_000)))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(100_000));
}

#[test]
fn int_literal_negative() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntLit(-1)))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(-1));
}

// -----------------------------------------------------------------------
// Int arithmetic
// -----------------------------------------------------------------------

#[test]
fn int_add() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::IntLit(50_000)),
            right: Box::new(JcExpr::IntLit(50_000)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(100_000));
}

#[test]
fn int_sub() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
            op: BinOp::Sub,
            left: Box::new(JcExpr::IntLit(100_000)),
            right: Box::new(JcExpr::IntLit(1)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(99_999));
}

#[test]
fn int_mul() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::IntLit(1000)),
            right: Box::new(JcExpr::IntLit(1000)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(1_000_000));
}

#[test]
fn int_div() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
            op: BinOp::Div,
            left: Box::new(JcExpr::IntLit(100_000)),
            right: Box::new(JcExpr::IntLit(3)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(33_333));
}

// -----------------------------------------------------------------------
// Short bitwise operations
// -----------------------------------------------------------------------

#[test]
fn short_bitwise_and() {
    // 0xFF & 0x0F = 0x0F = 15
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::BinOp {
            op: BinOp::And,
            left: Box::new(JcExpr::Lit(0xFF)),
            right: Box::new(JcExpr::Lit(0x0F)),
        }))],
        is_static: true,
        constant_time: false,
    });
    // 0xFF as i16 = 255. 255 & 15 = 15.
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(15));
}

#[test]
fn short_bitwise_or() {
    // 0x0F | 0xF0 = 0xFF = 255
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::BinOp {
            op: BinOp::Or,
            left: Box::new(JcExpr::Lit(0x0F)),
            right: Box::new(JcExpr::Lit(0xF0)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0xFF));
}

#[test]
fn short_bitwise_xor() {
    // 0xFF ^ 0x0F = 0xF0 = 240
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::BinOp {
            op: BinOp::Xor,
            left: Box::new(JcExpr::Lit(0xFF)),
            right: Box::new(JcExpr::Lit(0x0F)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0xF0));
}

#[test]
fn short_shift_left() {
    // 1 << 3 = 8
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::BinOp {
            op: BinOp::Shl,
            left: Box::new(JcExpr::Lit(1)),
            right: Box::new(JcExpr::Lit(3)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(8));
}

#[test]
fn short_shift_right() {
    // 16 >> 2 = 4
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::BinOp {
            op: BinOp::Shr,
            left: Box::new(JcExpr::Lit(16)),
            right: Box::new(JcExpr::Lit(2)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(4));
}

#[test]
fn short_unsigned_shift_right() {
    // -1 >>> 1 as short (logical shift right by 1 of 0xFFFF = 0x7FFF = 32767)
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::BinOp {
            op: BinOp::Ushr,
            left: Box::new(JcExpr::Lit(-1)),
            right: Box::new(JcExpr::Lit(1)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0x7FFF));
}

// -----------------------------------------------------------------------
// Type conversions (s2b, s2i, i2s, i2b)
// -----------------------------------------------------------------------

#[test]
fn cast_s2b() {
    // Cast short 300 to byte -> truncate to low 8 bits, sign-extend.
    // 300 = 0x012C -> byte 0x2C = 44
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Cast {
            from: JcType::Short,
            to: JcType::Byte,
            expr: Box::new(JcExpr::Lit(300)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(44));
}

#[test]
fn cast_s2i() {
    // Cast short 42 to int, return as int.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Cast {
            from: JcType::Short,
            to: JcType::Int,
            expr: Box::new(JcExpr::Lit(42)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(42));
}

#[test]
fn cast_s2i_negative() {
    // Cast short -1 to int, should sign-extend to int -1.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Cast {
            from: JcType::Short,
            to: JcType::Int,
            expr: Box::new(JcExpr::Lit(-1)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(-1));
}

#[test]
fn cast_i2s() {
    // Cast int 42 to short.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Cast {
            from: JcType::Int,
            to: JcType::Short,
            expr: Box::new(JcExpr::IntLit(42)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(42));
}

#[test]
fn cast_i2b() {
    // Cast int 300 to byte -> truncate to low 8 bits, sign-extend to short.
    // 300 = 0x12C -> byte 0x2C = 44
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Cast {
            from: JcType::Int,
            to: JcType::Byte,
            expr: Box::new(JcExpr::IntLit(300)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(44));
}

// -----------------------------------------------------------------------
// Comparison conditions: Lt, Ge, Gt, Le
// -----------------------------------------------------------------------

#[test]
fn condition_lt_true() {
    // x=3; if x < 5 { return 1 } else { return 0 }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(3),
            },
            JcStmt::If {
                cond: Condition::Lt(JcExpr::Var(String::from("x")), JcExpr::Lit(5)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn condition_lt_false() {
    // x=5; if x < 5 { return 1 } else { return 0 }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(5),
            },
            JcStmt::If {
                cond: Condition::Lt(JcExpr::Var(String::from("x")), JcExpr::Lit(5)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0));
}

#[test]
fn condition_ge_true() {
    // x=5; if x >= 5 { return 1 } else { return 0 }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(5),
            },
            JcStmt::If {
                cond: Condition::Ge(JcExpr::Var(String::from("x")), JcExpr::Lit(5)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn condition_gt_true() {
    // x=5; if x > 3 { return 1 } else { return 0 }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(5),
            },
            JcStmt::If {
                cond: Condition::Gt(JcExpr::Var(String::from("x")), JcExpr::Lit(3)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn condition_le_true() {
    // x=3; if x <= 5 { return 1 } else { return 0 }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(3),
            },
            JcStmt::If {
                cond: Condition::Le(JcExpr::Var(String::from("x")), JcExpr::Lit(5)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

// -----------------------------------------------------------------------
// Int comparison conditions (icmp + branch)
// -----------------------------------------------------------------------

#[test]
fn int_condition_eq_true() {
    // if 100000 == 100000 { return 1 } else { return 0 }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::If {
            cond: Condition::IntEq(JcExpr::IntLit(100_000), JcExpr::IntLit(100_000)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        }],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn int_condition_eq_false() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::If {
            cond: Condition::IntEq(JcExpr::IntLit(100_000), JcExpr::IntLit(200_000)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        }],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0));
}

#[test]
fn int_condition_lt() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::If {
            cond: Condition::IntLt(JcExpr::IntLit(50_000), JcExpr::IntLit(100_000)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        }],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn int_condition_ge() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::If {
            cond: Condition::IntGe(JcExpr::IntLit(100_000), JcExpr::IntLit(100_000)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        }],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn int_condition_ne() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::If {
            cond: Condition::IntNe(JcExpr::IntLit(1), JcExpr::IntLit(2)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        }],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn int_condition_gt() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::If {
            cond: Condition::IntGt(JcExpr::IntLit(200_000), JcExpr::IntLit(100_000)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        }],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

#[test]
fn int_condition_le() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::If {
            cond: Condition::IntLe(JcExpr::IntLit(100_000), JcExpr::IntLit(100_000)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
        }],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

// -----------------------------------------------------------------------
// Int negation
// -----------------------------------------------------------------------

#[test]
fn int_negation() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntNeg(Box::new(
            JcExpr::IntLit(100_000),
        ))))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(-100_000));
}

// -----------------------------------------------------------------------
// Int compare (icmp)
// -----------------------------------------------------------------------

#[test]
fn int_compare_less() {
    // icmp(1, 2) = -1
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntCompare(
            Box::new(JcExpr::IntLit(1)),
            Box::new(JcExpr::IntLit(2)),
        )))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(-1));
}

#[test]
fn int_compare_equal() {
    // icmp(5, 5) = 0
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntCompare(
            Box::new(JcExpr::IntLit(5)),
            Box::new(JcExpr::IntLit(5)),
        )))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0));
}

#[test]
fn int_compare_greater() {
    // icmp(10, 3) = 1
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntCompare(
            Box::new(JcExpr::IntLit(10)),
            Box::new(JcExpr::IntLit(3)),
        )))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(1));
}

// -----------------------------------------------------------------------
// sinc / iinc
// -----------------------------------------------------------------------

#[test]
fn sinc_increment() {
    // x = 10; sinc x, 5; return x -> 15
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(10),
            },
            JcStmt::Increment {
                var: String::from("x"),
                amount: 5,
            },
            JcStmt::Return(Some(JcExpr::Var(String::from("x")))),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(15));
}

#[test]
fn sinc_decrement() {
    // x = 10; sinc x, -3; return x -> 7
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(10),
            },
            JcStmt::Increment {
                var: String::from("x"),
                amount: -3,
            },
            JcStmt::Return(Some(JcExpr::Var(String::from("x")))),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(7));
}

#[test]
fn iinc_increment() {
    // x = int 10; iinc x, 5; return x -> 15
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![(String::from("x"), JcType::Int)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Int,
                init: JcExpr::IntLit(10),
            },
            JcStmt::Increment {
                var: String::from("x"),
                amount: 5,
            },
            JcStmt::Return(Some(JcExpr::Var(String::from("x")))),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(15));
}

// -----------------------------------------------------------------------
// Int local variables (iload/istore)
// -----------------------------------------------------------------------

#[test]
fn int_local_roundtrip() {
    // x = int 100000; return x
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![(String::from("x"), JcType::Int)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Int,
                init: JcExpr::IntLit(100_000),
            },
            JcStmt::Return(Some(JcExpr::Var(String::from("x")))),
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(100_000));
}

// -----------------------------------------------------------------------
// Switch statement
// -----------------------------------------------------------------------

#[test]
fn switch_case_match() {
    // x=2; switch(x) { case 1: return 10; case 2: return 20; default: return 0; }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(2),
            },
            JcStmt::Switch {
                key: JcExpr::Var(String::from("x")),
                cases: vec![
                    (1, vec![JcStmt::Return(Some(JcExpr::Lit(10)))]),
                    (2, vec![JcStmt::Return(Some(JcExpr::Lit(20)))]),
                ],
                default: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(20));
}

#[test]
fn switch_default_case() {
    // x=99; switch(x) { case 1: return 10; default: return 0; }
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![(String::from("x"), JcType::Short)],
        body: vec![
            JcStmt::Let {
                name: String::from("x"),
                ty: JcType::Short,
                init: JcExpr::Lit(99),
            },
            JcStmt::Switch {
                key: JcExpr::Var(String::from("x")),
                cases: vec![(1, vec![JcStmt::Return(Some(JcExpr::Lit(10)))])],
                default: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            },
        ],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(0));
}

// -----------------------------------------------------------------------
// Field access by type
// -----------------------------------------------------------------------

#[test]
fn field_access_short() {
    // Instance field of type Short: putfield_s / getfield_s
    let class = JcClass {
        aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
        fields: vec![JcField {
            name: String::from("val"),
            ty: JcType::Short,
            offset: 0,
        }],
        methods: vec![JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![
                // self.val = 42
                JcStmt::Assign {
                    target: LValue::Field {
                        field_name: String::from("val"),
                    },
                    value: JcExpr::Lit(42),
                },
                // return self.val
                JcStmt::Return(Some(JcExpr::SelfField(String::from("val")))),
            ],
            is_static: false,
            constant_time: false,
        }],
    };
    // Verify compilation succeeds (the JCVM execution test for instance
    // methods requires a full object model, so we just check compilation).
    let compiled = compile_class(&class);
    assert!(compiled.is_ok());
}

// -----------------------------------------------------------------------
// Compilation of invalid cast
// -----------------------------------------------------------------------

#[test]
fn compile_error_invalid_cast() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Short,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::Cast {
            from: JcType::Byte,
            to: JcType::Instance,
            expr: Box::new(JcExpr::Lit(0)),
        }))],
        is_static: true,
        constant_time: false,
    });
    let result = compile_class(&class);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// Int bitwise operations (executed end-to-end)
// -----------------------------------------------------------------------

#[test]
fn int_bitwise_and() {
    // 0x0000_FFFF & 0x0000_0F0F = 0x0000_0F0F = 3855
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
            op: BinOp::And,
            left: Box::new(JcExpr::IntLit(0x0000_FFFF)),
            right: Box::new(JcExpr::IntLit(0x0000_0F0F)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(0x0F0F));
}

#[test]
fn int_bitwise_or() {
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
            op: BinOp::Or,
            left: Box::new(JcExpr::IntLit(0x00F0)),
            right: Box::new(JcExpr::IntLit(0x000F)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(0x00FF));
}

#[test]
fn int_shift_left() {
    // 1 << 20 = 1_048_576
    // NOTE: JCVM ishl takes an int value and a *short* shift amount.
    let class = make_class(JcMethod {
        name: String::from("f"),
        params: vec![],
        return_ty: JcType::Int,
        locals: vec![],
        body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
            op: BinOp::Shl,
            left: Box::new(JcExpr::IntLit(1)),
            right: Box::new(JcExpr::Lit(20)),
        }))],
        is_static: true,
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnInt(1_048_576));
}

// -----------------------------------------------------------------------
// While loop with Lt condition
// -----------------------------------------------------------------------

#[test]
fn while_loop_with_lt() {
    // i=0; sum=0; while(i < 5) { sum = sum + i; i = i + 1; } return sum;
    // sum = 0+1+2+3+4 = 10
    let class = make_class(JcMethod {
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
                init: JcExpr::Lit(0),
            },
            JcStmt::Let {
                name: String::from("sum"),
                ty: JcType::Short,
                init: JcExpr::Lit(0),
            },
            JcStmt::While {
                cond: Condition::Lt(JcExpr::Var(String::from("i")), JcExpr::Lit(5)),
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
        constant_time: false,
    });
    assert_eq!(compile_and_run(&class), ExecResult::ReturnShort(10));
}
