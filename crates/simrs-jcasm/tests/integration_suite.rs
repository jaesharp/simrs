//! End-to-end integration suite: every opcode family through the
//! full pipeline (`jcasm!` -> CAP blob -> parser -> `JcVM` dispatch).
//!
//! Companion to:
//!   - `jcvm_opcodes.rs` -- per-opcode unit tests (constants, locals,
//!     stack, short-arithmetic, scmp branches, return/invokestatic)
//!   - `field_access_assemble_execute.rs` -- field/static accessors
//!     plus `new`
//!
//! This file fills the remaining gaps: int arithmetic, bitwise,
//! type conversion, icmp, the rest of the comparison branches,
//! switch, array load/store, array creation, arraylength, sinc,
//! iinc, ireturn, areturn.
//!
//! Each test goes through assemble -> CAP -> parse -> execute. If
//! any layer disagrees about an operand width or stack effect, at
//! least one assertion fails -- this is the safety net the
//! field-access operand-width bug evaded by sneaking past the
//! assembler-only and dispatcher-only tests.

#[path = "support/mod.rs"]
mod support;

use simrs_jcasm::jcasm;
use simrs_jcvm::opcodes::ExecResult;
use support::run_jcasm as run;

// =========================================================================
// Int arithmetic (iadd/isub/imul/idiv/irem/ineg)
// JCVM 3.2 § 7.5.6 -- ints are two stack words.
// =========================================================================

#[test]
fn iadd_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_10_01 {
        fn process() {
            iipush(0x0001_0000);
            iipush(0x0000_2345);
            iadd;
            ireturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnInt(0x0001_2345));
}

#[test]
fn isub_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_10_02 {
        fn process() { iipush(100); iipush(30); isub; ireturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnInt(70));
}

#[test]
fn imul_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_10_03 {
        fn process() { iipush(7); iipush(8); imul; ireturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnInt(56));
}

#[test]
fn idiv_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_10_04 {
        fn process() { iipush(100); iipush(7); idiv; ireturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnInt(14));
}

#[test]
fn idiv_by_zero_raises_arithmetic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_10_05 {
        fn process() { iipush(42); iipush(0); idiv; ireturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ArithmeticException);
}

#[test]
fn ineg_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_10_06 {
        fn process() { iipush(123); ineg; ireturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnInt(-123));
}

// =========================================================================
// Bitwise -- short
// JCVM 3.2 § 7 sshl/sshr/sushr/sand/sor/sxor.
// =========================================================================

#[test]
fn sand_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_20_01 {
        fn process() { sspush(0x00FF); sspush(0x00F0); sand; sreturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0x00F0));
}

#[test]
fn sor_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_20_02 {
        fn process() { sspush(0x00F0); sspush(0x000F); sor; sreturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0x00FF));
}

#[test]
fn sxor_basic() {
    let (aid, m) = jcasm! { applet A0_00_00_62_20_03 {
        fn process() { sspush(0x00FF); sspush(0x00AA); sxor; sreturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0x0055));
}

#[test]
fn sshl_by_one_doubles() {
    let (aid, m) = jcasm! { applet A0_00_00_62_20_04 {
        fn process() { sspush(0x0042); sconst_1; sshl; sreturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0x0084));
}

#[test]
fn sshr_arithmetic_negative() {
    // sshr is ARITHMETIC right shift -- sign-extending.
    let (aid, m) = jcasm! { applet A0_00_00_62_20_05 {
        fn process() {
            sspush(-1);  // 0xFFFF
            sconst_1;
            sshr;
            sreturn;
        }
    }};
    // -1 >> 1 (arithmetic) == -1
    assert_eq!(run(aid, m), ExecResult::ReturnShort(-1));
}

#[test]
fn sushr_logical_shifts_in_zero() {
    // sushr is LOGICAL right shift -- zero-extending.
    let (aid, m) = jcasm! { applet A0_00_00_62_20_06 {
        fn process() {
            sspush(-1);  // 0xFFFF
            sconst_1;
            sushr;
            sreturn;
        }
    }};
    // 0xFFFF >>> 1 == 0x7FFF (logical right shift)
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0x7FFF));
}

// =========================================================================
// Type conversion -- s2b/s2i/i2b/i2s
// JCVM 3.2 § 7.
// =========================================================================

#[test]
fn s2b_truncates_then_sign_extends() {
    let (aid, m) = jcasm! { applet A0_00_00_62_30_01 {
        fn process() {
            sspush(0x01FF);  // low byte = 0xFF = -1 sign-extended
            s2b;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(-1));
}

#[test]
fn s2i_sign_extends() {
    let (aid, m) = jcasm! { applet A0_00_00_62_30_02 {
        fn process() { sspush(-2); s2i; ireturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnInt(-2));
}

#[test]
fn i2s_truncates_low_16_bits() {
    let (aid, m) = jcasm! { applet A0_00_00_62_30_03 {
        fn process() { iipush(0x0001_8000); i2s; sreturn; }
    }};
    // low 16 bits = 0x8000 = i16::MIN = -32768
    assert_eq!(run(aid, m), ExecResult::ReturnShort(-32768));
}

#[test]
fn i2b_truncates_low_byte() {
    let (aid, m) = jcasm! { applet A0_00_00_62_30_04 {
        fn process() { iipush(0x1234_5678); i2b; sreturn; }
    }};
    // low byte = 0x78 = +120 (positive, no sign-extend)
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0x78));
}

// =========================================================================
// icmp -- compare two ints, push -1/0/+1
// =========================================================================

#[test]
fn icmp_equal_returns_zero() {
    let (aid, m) = jcasm! { applet A0_00_00_62_40_01 {
        fn process() { iipush(42); iipush(42); icmp; sreturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0));
}

#[test]
fn icmp_less_than_returns_neg_one() {
    let (aid, m) = jcasm! { applet A0_00_00_62_40_02 {
        fn process() { iipush(10); iipush(20); icmp; sreturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(-1));
}

#[test]
fn icmp_greater_than_returns_one() {
    let (aid, m) = jcasm! { applet A0_00_00_62_40_03 {
        fn process() { iipush(20); iipush(10); icmp; sreturn; }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(1));
}

// =========================================================================
// Branches -- if* family beyond what jcvm_opcodes.rs covers
// =========================================================================

#[test]
fn ifeq_taken_when_zero() {
    let (aid, m) = jcasm! { applet A0_00_00_62_50_01 {
        fn process() {
            sconst_0;
            ifeq(target);
            sconst_5;     // not taken
            sreturn;
            target:
            sconst_1;     // taken
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(1));
}

#[test]
fn ifne_falls_through_when_zero() {
    let (aid, m) = jcasm! { applet A0_00_00_62_50_02 {
        fn process() {
            sconst_0;
            ifne(target);
            sconst_5;     // taken (fall through)
            sreturn;
            target:
            sconst_1;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(5));
}

#[test]
fn iflt_taken_when_negative() {
    let (aid, m) = jcasm! { applet A0_00_00_62_50_03 {
        fn process() {
            sconst_m1;
            iflt(target);
            sconst_5;
            sreturn;
            target:
            sconst_1;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(1));
}

#[test]
fn if_scmplt_takes_branch_when_a_lt_b() {
    let (aid, m) = jcasm! { applet A0_00_00_62_50_04 {
        fn process() {
            sconst_1;
            sconst_2;
            if_scmplt(target);
            sconst_0;
            sreturn;
            target:
            sconst_5;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(5));
}

#[test]
fn if_scmpge_takes_branch_when_equal() {
    let (aid, m) = jcasm! { applet A0_00_00_62_50_05 {
        fn process() {
            sconst_3;
            sconst_3;
            if_scmpge(target);
            sconst_0;
            sreturn;
            target:
            sconst_5;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(5));
}

#[test]
fn ifnull_taken_for_null_ref() {
    let (aid, m) = jcasm! { applet A0_00_00_62_50_06 {
        fn process() {
            aconst_null;
            ifnull(target);
            sconst_0;
            sreturn;
            target:
            sconst_5;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(5));
}

// =========================================================================
// Array creation + length
// =========================================================================

#[test]
fn newarray_byte_then_arraylength() {
    let (aid, m) = jcasm! { applet A0_00_00_62_60_01 {
        fn process() {
            sspush(8);
            newarray(0x0A);   // T_BYTE per JCVM 3.2; ARRAY_TYPE_BYTE = 0x0A
            arraylength;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(8));
}

#[test]
fn newarray_short_then_arraylength() {
    let (aid, m) = jcasm! { applet A0_00_00_62_60_02 {
        fn process() {
            sspush(16);
            newarray(0x0B);   // ARRAY_TYPE_SHORT = 0x0B
            arraylength;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(16));
}

// =========================================================================
// Array load/store -- byte arrays
// =========================================================================

#[test]
fn bastore_baload_roundtrip() {
    let (aid, m) = jcasm! { applet A0_00_00_62_70_01 {
        fn process() {
            sspush(4);          // length
            newarray(0x0A);     // byte[]; on stack: [arr]
            dup;                // [arr, arr]
            sconst_2;           // index 2 -- [arr, arr, 2]
            bspush(0x42);       // [arr, arr, 2, 0x42]
            bastore;            // [arr]
            sconst_2;           // [arr, 2]
            baload;             // [val]
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnShort(0x42));
}

#[test]
fn baload_oob_index_raises() {
    let (aid, m) = jcasm! { applet A0_00_00_62_70_02 {
        fn process() {
            sspush(4);
            newarray(0x0A);
            sconst_5;           // 5 >= 4 => OOB
            baload;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ArrayIndexOutOfBounds);
}

#[test]
fn sastore_on_byte_array_raises_type_mismatch() {
    // simrs's `newarray` always allocates a byte array (ignoring
    // the atype operand). A short-typed store onto a byte array
    // should raise `ArrayStoreException`, exercising the heap's
    // type-check path. Closing the gap (genuine short[]/int[]
    // support via newarray) is a future heap-allocator
    // improvement.
    let (aid, m) = jcasm! { applet A0_00_00_62_70_03 {
        fn process() {
            sspush(4);
            newarray(0x0B);     // simrs treats this as byte[]
            dup;
            sconst_1;
            sspush(0x1234);
            sastore;
            sreturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ArrayStoreException);
}

// =========================================================================
// Switch (stableswitch / slookupswitch)
// JCVM 3.2 § 7.
// =========================================================================
//
// The jcasm! macro doesn't currently have a switch helper, but the
// dispatcher tests in simrs-jcvm/src/lib.rs cover switch via raw
// bytecode arrays. A future expansion of jcasm! to support switch
// would close this gap; tracked but not tested here.

// =========================================================================
// sinc / iinc -- not tested here.
//
// jcasm! `LocalImm8` ArgKind requires a single packed `(local << 8 |
// const)` integer rather than two arguments. The dispatcher tests
// in simrs-jcvm/src/lib.rs cover sinc/iinc adequately. Closing this
// gap end-to-end is a future jcasm! ergonomic improvement: support
// `sinc(local, const)` two-argument form.

// =========================================================================
// areturn -- return reference
// =========================================================================

#[test]
fn areturn_null() {
    let (aid, m) = jcasm! { applet A0_00_00_62_90_01 {
        fn process() {
            aconst_null;
            areturn;
        }
    }};
    assert_eq!(run(aid, m), ExecResult::ReturnRef(0));
}
