//! Peephole optimization tests for the jcasm! assembler.
//!
//! Verifies that the compiler peephole optimizer fires correctly when
//! integrated into the assembler pipeline. Each of the 9 peephole patterns
//! is tested, plus end-to-end execution and branch-awareness tests.

use simrs_jcasm::jcasm;
use simrs_jcvm::JcVM;
use simrs_jcvm::cap::{build_cap_blob, parse_cap};
use simrs_jcvm::opcodes::{
    DUP, ExecResult, RETURN as RETURN_VOID, SCONST_1, SCONST_3, SCONST_5, SRETURN, SSTORE_0,
    SSTORE_1,
};

// =========================================================================
// Pattern 1: sstore_N; sload_N -> dup; sstore_N
// =========================================================================

#[test]
fn peephole_store_load_to_dup_store() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                sstore_0;
                sload_0;
                sreturn;
            }
        }
    };
    // sstore_0; sload_0 -> dup; sstore_0
    // Result: sconst_1, dup, sstore_0, sreturn
    assert_eq!(methods[0], &[SCONST_1, DUP, SSTORE_0, SRETURN]);
}

// =========================================================================
// Pattern 2: sconst_*; pop -> removed
// =========================================================================

#[test]
fn peephole_sconst_pop_removed() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_3;
                pop;
                sconst_1;
                sreturn;
            }
        }
    };
    // sconst_3; pop removed, leaving sconst_1; sreturn
    assert_eq!(methods[0], &[SCONST_1, SRETURN]);
}

// =========================================================================
// Pattern 3: bspush X; pop -> removed
// =========================================================================

#[test]
fn peephole_bspush_pop_removed() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                bspush(42);
                pop;
                sconst_5;
                sreturn;
            }
        }
    };
    // bspush 42; pop removed (3 bytes), leaving sconst_5; sreturn
    assert_eq!(methods[0], &[SCONST_5, SRETURN]);
}

// =========================================================================
// Pattern 4: sspush X; pop -> removed
// =========================================================================

#[test]
fn peephole_sspush_pop_removed() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sspush(1000);
                pop;
                sconst_3;
                sreturn;
            }
        }
    };
    // sspush 1000; pop removed (4 bytes), leaving sconst_3; sreturn
    assert_eq!(methods[0], &[SCONST_3, SRETURN]);
}

// =========================================================================
// Pattern 5: sneg; sneg -> removed (double negation)
// =========================================================================

#[test]
fn peephole_double_sneg_removed() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_5;
                sneg;
                sneg;
                sreturn;
            }
        }
    };
    // sneg; sneg removed, leaving sconst_5; sreturn
    assert_eq!(methods[0], &[SCONST_5, SRETURN]);
}

// =========================================================================
// Pattern 6: ineg; ineg -> removed (double int negation)
// =========================================================================

#[test]
fn peephole_double_ineg_removed() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                iconst_1;
                ineg;
                ineg;
                ireturn;
            }
        }
    };
    // ineg; ineg removed (2 bytes), leaving iconst_1; ireturn
    assert_eq!(methods[0].len(), 2);
    // iconst_1 is 0x0B, ireturn is 0x79
    assert_eq!(methods[0][0], 0x0B);
    assert_eq!(methods[0][1], 0x79);
}

// =========================================================================
// Pattern 7: goto next -> removed (noop jump)
// =========================================================================

#[test]
fn peephole_goto_next_removed() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                goto(skip);
                skip:
                sreturn;
            }
        }
    };
    // goto with target = next instruction (offset +2) removed.
    // Result: sconst_1; sreturn
    assert_eq!(methods[0], &[SCONST_1, SRETURN]);
}

// =========================================================================
// Pattern 8: sconst_0; sadd -> removed (identity addition)
// =========================================================================

#[test]
fn peephole_sconst0_sadd_removed() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                sconst_0;
                sadd;
                sreturn;
            }
        }
    };
    // sconst_0; sadd removed, leaving sconst_1; sreturn
    assert_eq!(methods[0], &[SCONST_1, SRETURN]);
}

// =========================================================================
// Pattern 9: sstore_N; sstore_N -> pop; sstore_N (dead first store)
// =========================================================================

#[test]
fn peephole_duplicate_store_to_pop_store() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                sconst_3;
                sstore_1;
                sstore_1;
                return_void;
            }
        }
    };
    // Cascading optimization:
    // 1. sstore_1; sstore_1 -> pop; sstore_1
    //    => sconst_1, sconst_3, pop, sstore_1, return_void
    // 2. sconst_3; pop -> removed
    //    => sconst_1, sstore_1, return_void
    assert_eq!(methods[0], &[SCONST_1, SSTORE_1, RETURN_VOID]);
}

// =========================================================================
// Combined patterns: multiple peephole optimizations cascade
// =========================================================================

#[test]
fn peephole_cascading_optimizations() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_5;
                sconst_0;
                sadd;
                sneg;
                sneg;
                sreturn;
            }
        }
    };
    // Round 1: sconst_0+sadd removed -> sconst_5, sneg, sneg, sreturn
    // Round 2: sneg+sneg removed -> sconst_5, sreturn
    assert_eq!(methods[0], &[SCONST_5, SRETURN]);
}

// =========================================================================
// End-to-end: optimized program runs correctly in JCVM
// =========================================================================

#[test]
fn peephole_optimized_program_executes_correctly() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_5;
                sconst_0;
                sadd;
                sneg;
                sneg;
                sreturn;
            }
        }
    };

    // Should produce sconst_5; sreturn after optimization.
    assert_eq!(methods[0], &[SCONST_5, SRETURN]);

    // Execute in JCVM: should return 5.
    let mut buf = [0u8; 4096];
    let len = build_cap_blob(aid, methods, &mut buf);
    let pkg = parse_cap(&buf[..len]).unwrap();
    let mut vm = JcVM::<1024, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    assert_eq!(vm.execute(idx, 0), ExecResult::ReturnShort(5));
}

#[test]
fn peephole_store_load_program_executes_correctly() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_3;
                sstore_0;
                sload_0;
                sreturn;
            }
        }
    };

    // sstore_0; sload_0 -> dup; sstore_0
    assert_eq!(methods[0], &[SCONST_3, DUP, SSTORE_0, SRETURN]);

    let mut buf = [0u8; 4096];
    let len = build_cap_blob(aid, methods, &mut buf);
    let pkg = parse_cap(&buf[..len]).unwrap();
    let mut vm = JcVM::<1024, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    assert_eq!(vm.execute(idx, 0), ExecResult::ReturnShort(3));
}

// =========================================================================
// Branch-awareness: peephole must not break control flow
// =========================================================================

#[test]
fn peephole_preserves_branch_target_semantics() {
    // A peephole pattern (sconst_0+sadd) spans a branch target boundary.
    // The optimizer must NOT apply the pattern at or across a branch target.
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                ifeq(target);
                sconst_3;
                sreturn;
                target:
                sconst_0;
                sadd;
                sreturn;
            }
        }
    };

    // The sconst_0 at `target:` is a branch target.
    // The peephole must NOT remove sconst_0+sadd here because sconst_0
    // is a branch target and removing it would corrupt the branch offset.
    // Verify that the fallthrough path (sconst_1 != 0, so ifeq not taken)
    // correctly returns 3.
    let mut buf = [0u8; 4096];
    let len = build_cap_blob(aid, methods, &mut buf);
    let pkg = parse_cap(&buf[..len]).unwrap();
    let mut vm = JcVM::<1024, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    assert_eq!(vm.execute(idx, 0), ExecResult::ReturnShort(3));
}

#[test]
fn peephole_optimizes_outside_branch_target() {
    // Peephole pattern NOT at a branch target should still fire.
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_5;
                sconst_0;
                sadd;
                goto(done);
                done:
                sreturn;
            }
        }
    };

    // sconst_0+sadd at the start is not a branch target -> removed.
    // goto(done) where done is next instruction -> also removed.
    // Result: sconst_5; sreturn
    assert_eq!(methods[0], &[SCONST_5, SRETURN]);

    let mut buf = [0u8; 4096];
    let len = build_cap_blob(aid, methods, &mut buf);
    let pkg = parse_cap(&buf[..len]).unwrap();
    let mut vm = JcVM::<1024, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    assert_eq!(vm.execute(idx, 0), ExecResult::ReturnShort(5));
}

// =========================================================================
// No-optimization baseline: verify unoptimizable code is unchanged
// =========================================================================

#[test]
fn no_optimization_when_no_patterns() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_3;
                sconst_1;
                sadd;
                sreturn;
            }
        }
    };
    // sconst_3 + sconst_1 + sadd is real computation, not sconst_0+sadd.
    // No peephole pattern applies.
    assert_eq!(methods[0], &[SCONST_3, SCONST_1, 0x41, SRETURN]);
}

// =========================================================================
// Configurable optimization: `optimize none;` disables all optimization
// =========================================================================

#[test]
fn optimize_none_preserves_all_instructions() {
    let (_aid, methods) = jcasm! {
        optimize none;
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                sconst_0;
                sadd;
                sneg;
                sneg;
                sreturn;
            }
        }
    };
    // All 6 instructions present (peephole disabled)
    assert_eq!(methods[0].len(), 6);
}

// =========================================================================
// Per-pattern selection: only double_negation enabled
// =========================================================================

#[test]
fn per_pattern_only_double_negation() {
    let (_aid, methods) = jcasm! {
        optimize peephole(double_negation);
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                sconst_0;
                sadd;         // NOT removed (add_zero_identity disabled)
                sneg;
                sneg;         // removed (double_negation enabled)
                sreturn;
            }
        }
    };
    // sconst_0+sadd preserved (3 bytes: 0x03, 0x41), sneg+sneg removed
    // Result: sconst_1(1) + sconst_0(1) + sadd(1) + sreturn(1) = 4 bytes
    assert_eq!(methods[0].len(), 4);
    assert_eq!(methods[0][0], 0x04); // sconst_1
    assert_eq!(methods[0][1], 0x03); // sconst_0
    assert_eq!(methods[0][2], 0x41); // sadd
    assert_eq!(methods[0][3], 0x78); // sreturn
}

// =========================================================================
// Per-pattern selection: only add_zero_identity enabled
// =========================================================================

#[test]
fn per_pattern_only_add_zero_identity() {
    let (_aid, methods) = jcasm! {
        optimize peephole(add_zero_identity);
        applet A0_00_00_00_62 {
            fn test() {
                sconst_1;
                sconst_0;
                sadd;         // removed (add_zero_identity enabled)
                sneg;
                sneg;         // NOT removed (double_negation disabled)
                sreturn;
            }
        }
    };
    // sconst_0+sadd removed, sneg+sneg preserved
    // Result: sconst_1(1) + sneg(1) + sneg(1) + sreturn(1) = 4 bytes
    assert_eq!(methods[0].len(), 4);
    assert_eq!(methods[0][0], 0x04); // sconst_1
    assert_eq!(methods[0][1], 0x4B); // sneg
    assert_eq!(methods[0][2], 0x4B); // sneg
    assert_eq!(methods[0][3], 0x78); // sreturn
}

// =========================================================================
// `max_passes = 1` limits cascading
// =========================================================================

#[test]
fn max_passes_one_limits_iteration() {
    let (_aid, methods) = jcasm! {
        optimize peephole(max_passes = 1);
        applet A0_00_00_00_62 {
            fn test() {
                sconst_5;
                sconst_0;
                sadd;         // removed in pass 1
                sneg;
                sneg;         // removed in pass 1
                sreturn;
            }
        }
    };
    // Both patterns are independent and fire in one pass
    assert_eq!(methods[0], &[0x08, 0x78]); // sconst_5, sreturn
}

// =========================================================================
// `constant_time fn` still gets peephole-optimized (CT-safe)
// =========================================================================

#[test]
fn constant_time_method_still_peephole_optimized() {
    let (_aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            constant_time fn verify() {
                sconst_1;
                sconst_0;
                sadd;
                sreturn;
            }
        }
    };
    // Peephole patterns are CT-safe, so sconst_0+sadd is removed
    assert_eq!(methods[0], &[0x04, 0x78]); // sconst_1, sreturn
}

// =========================================================================
// `constant_time fn` combined with `optimize none;` disables optimization
// =========================================================================

#[test]
fn constant_time_with_optimize_none_no_optimization() {
    let (_aid, methods) = jcasm! {
        optimize none;
        applet A0_00_00_00_62 {
            constant_time fn verify() {
                sconst_1;
                sconst_0;
                sadd;
                sreturn;
            }
        }
    };
    // optimize none disables peephole regardless of CT
    assert_eq!(methods[0].len(), 4);
}

// =========================================================================
// `optimize full;` is the same as default
// =========================================================================

#[test]
fn optimize_full_same_as_default() {
    let (_aid, methods_full) = jcasm! {
        optimize full;
        applet A0_00_00_00_62 {
            fn test() {
                sconst_5;
                sconst_0;
                sadd;
                sneg;
                sneg;
                sreturn;
            }
        }
    };
    let (_aid2, methods_default) = jcasm! {
        applet A0_00_00_00_62 {
            fn test() {
                sconst_5;
                sconst_0;
                sadd;
                sneg;
                sneg;
                sreturn;
            }
        }
    };
    assert_eq!(methods_full[0], methods_default[0]);
}

// =========================================================================
// `report` knob compiles and optimizes (no output verification)
// =========================================================================

#[test]
fn report_knob_compiles_and_optimizes() {
    let (_aid, methods) = jcasm! {
        optimize peephole(report);
        applet A0_00_00_00_62 {
            fn test() {
                sconst_0;
                sadd;
                sconst_1;
                sreturn;
            }
        }
    };
    assert_eq!(methods[0].len(), 2);
}

// =========================================================================
// End-to-end: constant_time method executes correctly in JCVM
// =========================================================================

#[test]
fn constant_time_method_executes_correctly_in_jcvm() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62 {
            constant_time fn test() {
                sconst_5;
                sconst_0;
                sadd;
                sneg;
                sneg;
                sreturn;
            }
        }
    };
    // CT-safe peephole applied
    assert_eq!(methods[0], &[0x08, 0x78]);
    // Executes correctly
    let mut buf = [0u8; 4096];
    let len = build_cap_blob(aid, methods, &mut buf);
    let pkg = parse_cap(&buf[..len]).unwrap();
    let mut vm = JcVM::<1024, 4>::new();
    let idx = vm.load_package(pkg).unwrap();
    assert_eq!(vm.execute(idx, 0), ExecResult::ReturnShort(5));
}
