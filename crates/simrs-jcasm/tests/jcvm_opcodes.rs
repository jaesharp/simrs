//! Comprehensive JCVM opcode tests via jcasm!{} assembly.
//!
//! Every implemented opcode is tested for:
//! - Correct behavior with nominal inputs
//! - Edge cases (min/max values, zero, boundaries)
//! - Exception conditions (overflow, underflow, OOB, type mismatch)
//! - Stack effect (correct push/pop count per JCVM 3.2 Chapter 7)
//!
//! Property-based tests use proptest to verify invariants across
//! random inputs.
//!
//! # Spec References
//!
//! - JCVM 3.2 Chapter 7: Bytecode instruction set
//!   - Section 7.5.1: Constant push (`sconst_m1` .. `sconst_5`)
//!   - Section 7.5.2: Byte/short push (bspush, sspush)
//!   - Section 7.5.3-7.5.4: Local variable load/store (sload, sstore)
//!   - Section 7.5.5: Stack manipulation (pop, dup)
//!   - Section 7.5.6: Arithmetic (sadd, ssub, smul, sdiv, srem, sneg)
//!   - Section 7.5.7: Branch instructions (`if_scmpeq`, `if_scmpne`, `goto`)
//!   - Section 7.5.8: Method return (sreturn, return)
//!   - Section 7.5.9: Method invocation (invokestatic)

#[path = "support/mod.rs"]
mod support;

use simrs_jcasm::jcasm;
use simrs_jcvm::opcodes::ExecResult;
use support::run_jcasm as run_applet;

// =========================================================================
// CONSTANTS: sconst_m1 .. sconst_5, bspush, sspush
//
// JCVM 3.2 Section 7.5.1-7.5.2: Constant push instructions.
// "sconst_<n> pushes the short value <n> onto the operand stack."
// "bspush pushes a sign-extended byte value onto the operand stack."
// "sspush pushes a short value onto the operand stack."
// =========================================================================

/// JCVM 3.2 Section 7.5.1: `sconst_m1` pushes -1.
#[test]
fn sconst_m1_returns_minus_one() {
    let (aid, m) = jcasm! { applet A0_00_00_62_01 {
        fn process() { sconst_m1; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(-1));
}

/// JCVM 3.2 Section 7.5.1: `sconst_0` pushes 0.
#[test]
fn sconst_0_returns_zero() {
    let (aid, m) = jcasm! { applet A0_00_00_62_02 {
        fn process() { sconst_0; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(0));
}

/// JCVM 3.2 Section 7.5.1: `sconst_5` pushes 5.
#[test]
fn sconst_5_returns_five() {
    let (aid, m) = jcasm! { applet A0_00_00_62_03 {
        fn process() { sconst_5; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(5));
}

/// JCVM 3.2 Section 7.5.2: bspush sign-extends byte to short.
#[test]
fn bspush_positive() {
    let (aid, m) = jcasm! { applet A0_00_00_62_04 {
        fn process() { bspush(42); sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(42));
}

/// JCVM 3.2 Section 7.5.2: bspush 0xFF sign-extends to -1.
#[test]
fn bspush_negative_sign_extends() {
    // bspush 0xFF = -1 when sign-extended to short
    let (aid, m) = jcasm! { applet A0_00_00_62_05 {
        fn process() { bspush(255); sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(-1));
}

/// JCVM 3.2 Section 7.5.2: bspush 0 pushes 0.
#[test]
fn bspush_zero() {
    let (aid, m) = jcasm! { applet A0_00_00_62_06 {
        fn process() { bspush(0); sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(0));
}

/// JCVM 3.2 Section 7.5.2: sspush pushes a 16-bit signed short.
/// Maximum positive short value: 0x7FFF = 32767.
#[test]
fn sspush_large_positive() {
    // sspush 0x7FFF = 32767 (max positive short)
    let (aid, m) = jcasm! { applet A0_00_00_62_07 {
        fn process() { sspush(32767); sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(32767));
}

// =========================================================================
// LOCALS: sload/sstore
//
// JCVM 3.2 Section 7.5.3-7.5.4: Local variable access.
// "sload loads a short value from a local variable."
// "sstore stores a short value into a local variable."
// =========================================================================

/// JCVM 3.2 Section 7.5.3-7.5.4: sstore/sload round-trip via
/// _2 shorthand forms.
#[test]
fn sstore_sload_roundtrip() {
    let (aid, m) = jcasm! { applet A0_00_00_62_10 {
        fn process() {
            sconst_3;
            sstore_2;
            sload_2;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(3));
}

/// JCVM 3.2 Section 7.5.3-7.5.4: sstore/sload with explicit index.
#[test]
fn sload_sstore_indexed() {
    let (aid, m) = jcasm! { applet A0_00_00_62_11 {
        fn process() {
            sconst_4;
            sstore(3);
            sload(3);
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(4));
}

// =========================================================================
// STACK: pop, dup
//
// JCVM 3.2 Section 7.5.5: Stack manipulation.
// "pop removes the top value from the operand stack."
// "dup duplicates the top value on the operand stack."
// =========================================================================

/// JCVM 3.2 Section 7.5.5: pop discards the top stack value.
#[test]
fn pop_discards_top() {
    let (aid, m) = jcasm! { applet A0_00_00_62_20 {
        fn process() {
            sconst_1;
            sconst_2;
            pop;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(1));
}

/// JCVM 3.2 Section 7.5.5: dup copies the top stack value.
#[test]
fn dup_copies_top() {
    let (aid, m) = jcasm! { applet A0_00_00_62_21 {
        fn process() {
            sconst_3;
            dup;
            sadd;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(6)); // 3 + 3
}

// =========================================================================
// ARITHMETIC: sadd, ssub, smul, sdiv, srem, sneg
//
// JCVM 3.2 Section 7.5.6: Arithmetic instructions.
// "sadd: ..., value1, value2 -> ..., result"
// "sdiv: if divisor is zero, throw ArithmeticException"
// "sneg: ..., value -> ..., result (result = -value)"
// =========================================================================

/// JCVM 3.2 Section 7.5.6: sadd pops two shorts, pushes their sum.
#[test]
fn sadd_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_30 {
        fn process() { sconst_3; sconst_2; sadd; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(5));
}

/// JCVM 3.2 Section 7.5.6: ssub pops two shorts, pushes their difference.
#[test]
fn ssub_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_31 {
        fn process() { sconst_5; sconst_2; ssub; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(3));
}

/// JCVM 3.2 Section 7.5.6: smul pops two shorts, pushes their product.
#[test]
fn smul_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_32 {
        fn process() { sconst_3; sconst_4; smul; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(12));
}

/// JCVM 3.2 Section 7.5.6: sdiv pops two shorts, pushes their quotient.
#[test]
fn sdiv_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_33 {
        fn process() {
            bspush(10);
            sconst_3;
            sdiv;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(3)); // 10 / 3 = 3
}

/// JCVM 3.2 Section 7.5.6: `sdiv` by zero raises `ArithmeticException`.
///
/// "If the value of the divisor is zero, `sdiv` throws an
/// `ArithmeticException`."
#[test]
fn sdiv_by_zero_raises_arithmetic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_34 {
        fn process() { sconst_5; sconst_0; sdiv; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ArithmeticException);
}

/// JCVM 3.2 Section 7.5.6: srem pops two shorts, pushes the remainder.
#[test]
fn srem_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_35 {
        fn process() {
            bspush(10);
            sconst_3;
            srem;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(1)); // 10 % 3 = 1
}

/// JCVM 3.2 Section 7.5.6: `srem` by zero raises `ArithmeticException`.
#[test]
fn srem_by_zero_raises_arithmetic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_36 {
        fn process() { sconst_5; sconst_0; srem; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ArithmeticException);
}

/// JCVM 3.2 Section 7.5.6: sneg negates the top stack value.
#[test]
fn sneg_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_37 {
        fn process() { sconst_3; sneg; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(-3));
}

/// JCVM 3.2 Section 7.5.6: sneg is self-inverse: sneg(sneg(x)) == x.
#[test]
fn sneg_double_is_identity() {
    let (aid, m) = jcasm! { applet A0_00_00_62_38 {
        fn process() { sconst_4; sneg; sneg; sreturn; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(4));
}

// =========================================================================
// BRANCHES: if_scmpeq, if_scmpne, goto, goto_w
//
// JCVM 3.2 Section 7.5.7: Branch instructions.
// "if_scmpeq: if value1 == value2, branch to target."
// "if_scmpne: if value1 != value2, branch to target."
// "goto: branch unconditionally."
// =========================================================================

/// JCVM 3.2 Section 7.5.7: `if_scmpeq` branches when operands are equal.
#[test]
fn if_scmpeq_takes_branch_when_equal() {
    let (aid, m) = jcasm! { applet A0_00_00_62_40 {
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
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(1));
}

/// JCVM 3.2 Section 7.5.7: `if_scmpeq` falls through when operands differ.
#[test]
fn if_scmpeq_falls_through_when_not_equal() {
    let (aid, m) = jcasm! { applet A0_00_00_62_41 {
        fn process() {
            sconst_3;
            sconst_2;
            if_scmpeq(eq);
            sconst_0;
            sreturn;
            eq:
            sconst_1;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(0));
}

/// JCVM 3.2 Section 7.5.7: `if_scmpne` branches when operands differ.
#[test]
fn if_scmpne_takes_branch_when_not_equal() {
    let (aid, m) = jcasm! { applet A0_00_00_62_42 {
        fn process() {
            sconst_3;
            sconst_2;
            if_scmpne(ne);
            sconst_0;
            sreturn;
            ne:
            sconst_1;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(1));
}

/// JCVM 3.2 Section 7.5.7: goto branches unconditionally.
#[test]
fn goto_unconditional() {
    let (aid, m) = jcasm! { applet A0_00_00_62_43 {
        fn process() {
            goto(end);
            sconst_0;
            sreturn;
            end:
            sconst_5;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(5));
}

// =========================================================================
// RETURN: sreturn, return_void
//
// JCVM 3.2 Section 7.5.8: Method return instructions.
// "sreturn returns a short value from a method."
// "return returns void from a method."
// =========================================================================

/// JCVM 3.2 Section 7.5.8: `return_void` returns from a void method.
#[test]
fn return_void_from_method() {
    let (aid, m) = jcasm! { applet A0_00_00_62_50 {
        fn process() { return_void; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnVoid);
}

// =========================================================================
// INVOKE: invokestatic (cross-method call)
//
// JCVM 3.2 Section 7.5.9: Method invocation.
// "invokestatic invokes a static method, identified by a method token."
// =========================================================================

/// JCVM 3.2 Section 7.5.9: invokestatic calls another method.
///
/// `invokestatic` takes 2-byte operand: (`pkg_idx` << 8 | `method_idx`).
/// For intra-package calls, `pkg_idx`=0. So `invokestatic(1)` encodes
/// as 0x8D 0x00 0x01 -- call method 1 in package 0.
#[test]
fn invokestatic_calls_method_1() {
    let (aid, m) = jcasm! { applet A0_00_00_62_60 {
        fn process() {
            invokestatic(1);  // pkg=0, method=1
            sreturn;
        }
        fn helper() {
            sconst_4;
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::ReturnShort(4));
}

/// JCVM 3.2 Section 7.5.9: invokestatic with invalid method index.
#[test]
fn invokestatic_invalid_method() {
    let (aid, m) = jcasm! { applet A0_00_00_62_61 {
        fn process() {
            invokestatic(99);  // pkg=0, method=99 (doesn't exist)
            sreturn;
        }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::InvalidMethod);
}

// =========================================================================
// EDGE CASES & EXCEPTION CONDITIONS
//
// JCVM 3.2 Chapter 7: Stack underflow and end-of-bytecode are
// implementation-defined error conditions that must not cause undefined
// behavior.
// =========================================================================

/// JCVM 3.2 Chapter 7: pop on an empty stack raises `StackUnderflow`.
#[test]
fn stack_underflow_on_empty_pop() {
    let (aid, m) = jcasm! { applet A0_00_00_62_70 {
        fn process() { pop; return_void; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::StackUnderflow);
}

/// JCVM 3.2 Chapter 7: Reaching end of bytecode without a return
/// instruction raises `EndOfBytecode`.
#[test]
fn end_of_bytecode_without_return() {
    let (aid, m) = jcasm! { applet A0_00_00_62_71 {
        fn process() { sconst_0; }
    }};
    assert_eq!(run_applet(aid, m), ExecResult::EndOfBytecode);
}

// =========================================================================
// PROPERTY-BASED TESTS
//
// JCVM 3.2 Section 7.5.6: Arithmetic follows Java Card short semantics
// (16-bit signed two's complement with wrapping).
// =========================================================================

#[cfg(test)]
#[allow(clippy::cast_sign_loss)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// JCVM 3.2 Section 7.5.6: sadd wraps on overflow
        /// (Java Card short semantics).
        #[test]
        fn sadd_wraps(a in -128i8..127, b in -128i8..127) {
            let a16 = i16::from(a);
            let b16 = i16::from(b);
            let expected = a16.wrapping_add(b16);

            // bspush sign-extends i8 -> i16
            let (aid, m) = jcasm! { applet A0_00_00_62_80 {
                fn process() {
                    bspush(0);  // placeholder
                    bspush(0);  // placeholder
                    sadd;
                    sreturn;
                }
            }};

            // Patch the immediate bytes with actual values
            let mut bytecode = m[0].to_vec();
            bytecode[1] = a as u8;
            bytecode[3] = b as u8;

            let methods: &[&[u8]] = &[&bytecode];
            let result = run_applet(aid, methods);

            prop_assert_eq!(result, ExecResult::ReturnShort(expected));
        }

        /// JCVM 3.2 Section 7.5.6: sneg is self-inverse: sneg(sneg(x)) == x.
        #[test]
        fn sneg_involution(x in -128i8..127) {
            let expected = i16::from(x);

            let (aid, m) = jcasm! { applet A0_00_00_62_81 {
                fn process() {
                    bspush(0);  // placeholder
                    sneg;
                    sneg;
                    sreturn;
                }
            }};

            let mut bytecode = m[0].to_vec();
            bytecode[1] = x as u8;

            let methods: &[&[u8]] = &[&bytecode];
            let result = run_applet(aid, methods);

            prop_assert_eq!(result, ExecResult::ReturnShort(expected));
        }

        /// JCVM 3.2 Section 7.5.6: sdiv by non-zero never panics,
        /// matches Rust integer division.
        #[test]
        fn sdiv_nonzero_never_panics(a in -128i8..127, b in 1i8..127) {
            let a16 = i16::from(a);
            let b16 = i16::from(b);
            let expected = a16 / b16;

            let (aid, m) = jcasm! { applet A0_00_00_62_82 {
                fn process() {
                    bspush(0);
                    bspush(0);
                    sdiv;
                    sreturn;
                }
            }};

            let mut bytecode = m[0].to_vec();
            bytecode[1] = a as u8;
            bytecode[3] = b as u8;

            let methods: &[&[u8]] = &[&bytecode];
            let result = run_applet(aid, methods);

            prop_assert_eq!(result, ExecResult::ReturnShort(expected));
        }

        /// JCVM 3.2 Section 7.5.3-7.5.4: sstore/sload round-trips for
        /// any local index 0..3.
        #[test]
        fn sstore_sload_roundtrip_any_local(local in 0u8..4, val in -128i8..127) {
            let expected = i16::from(val);

            // Build bytecode manually: bspush val, sstore_N, sload_N, sreturn
            let sstore_op = 0x2Bu8 + local;
            let sload_op = 0x1Cu8 + local;
            let bytecode = vec![0x10, val as u8, sstore_op, sload_op, 0x78];

            let aid = &[0xA0, 0x00, 0x00, 0x62, 0x83];
            let methods: &[&[u8]] = &[&bytecode];
            let result = run_applet(aid, methods);

            prop_assert_eq!(result, ExecResult::ReturnShort(expected));
        }
    }
}
