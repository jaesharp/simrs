//! End-to-end "assemble through `jcasm!` → execute through `JcVM`" tests
//! for instance and static field accessors.
//!
//! These tests exist specifically to catch operand-width mismatches
//! between the assembler (`simrs-jcasm`), IR codegen (`simrs-jccompile`),
//! and the bytecode dispatcher (`simrs-jcvm`). Pre-2026-05-04 a real
//! latent bug had the assembler emitting 1-byte operands while the
//! dispatcher consumed 2 -- assembler-emitted bytecode could not
//! execute correctly through the dispatcher. No test crossed that
//! interface, so the bug went undetected.
//!
//! Each test below:
//! 1. Assembles a method through `jcasm!` (verifies the byte sequence),
//! 2. Loads the resulting CAP blob into a `JcVM`,
//! 3. Executes the method,
//! 4. Asserts the expected return value.
//!
//! If any of the operand widths drift again (assembler vs codegen vs
//! dispatcher), at least one of these tests will fail at execute time.

#[path = "support/mod.rs"]
mod support;

use simrs_jcasm::jcasm;
use simrs_jcvm::opcodes::ExecResult;
use support::run_jcasm as run;

// =========================================================================
// Instance field accessors -- 1-byte operand (per JCVM 3.2 § 7).
//
// `getfield_b(0)` should assemble to [0x84, 0x00] and dispatch
// through one operand byte. If the assembler emits N bytes but the
// dispatcher consumes M bytes (N != M), the next instruction's
// opcode gets misinterpreted as either an operand or as the next
// opcode at the wrong PC -- one of the assertions below will fail.
// =========================================================================

#[test]
fn instance_putfield_getfield_byte_roundtrip() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_01 {
            fn test() {
                new(4);
                dup;
                bspush(0x42);
                putfield_b(0);
                getfield_b(0);
                sreturn;
            }
        }
    };
    assert_eq!(run(aid, methods), ExecResult::ReturnShort(0x42));
}

#[test]
fn instance_putfield_getfield_short_roundtrip() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_02 {
            fn test() {
                new(4);
                dup;
                sspush(0x1234);
                putfield_s(0);
                getfield_s(0);
                sreturn;
            }
        }
    };
    assert_eq!(run(aid, methods), ExecResult::ReturnShort(0x1234));
}

#[test]
fn instance_putfield_getfield_ref_roundtrip() {
    // Store a non-null reference (we synthesise via bspush + truncation
    // semantics, since aconst_null is the only ref-typed const we have).
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_03 {
            fn test() {
                new(4);
                dup;
                bspush(7);
                putfield_a(0);
                getfield_a(0);
                sreturn;
            }
        }
    };
    assert_eq!(run(aid, methods), ExecResult::ReturnShort(7));
}

#[test]
fn instance_putfield_getfield_int_roundtrip() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_04 {
            fn test() {
                new(8);
                dup;
                iipush(0x12345678);
                putfield_i(0);
                getfield_i(0);
                ireturn;
            }
        }
    };
    assert_eq!(run(aid, methods), ExecResult::ReturnInt(0x1234_5678));
}

#[test]
fn instance_putfield_getfield_short_at_offset() {
    // Verifies the operand byte actually reaches the dispatcher's
    // `field_offset` parameter -- if the assembler/dispatcher
    // disagreed on operand width, this would write to the wrong
    // offset and the read wouldn't see the value.
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_05 {
            fn test() {
                new(8);
                dup;
                sspush(0xABCD);
                putfield_s(2);
                getfield_s(2);
                sreturn;
            }
        }
    };
    let expected = 0xABCDu16.cast_signed();
    assert_eq!(run(aid, methods), ExecResult::ReturnShort(expected));
}

// =========================================================================
// Static byte field accessors -- 1-byte operand.
// =========================================================================

#[test]
fn static_byte_putstatic_getstatic_roundtrip() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_06 {
            fn test() {
                bspush(0x55);
                putstatic_b(0);
                getstatic_b(0);
                sreturn;
            }
        }
    };
    assert_eq!(run(aid, methods), ExecResult::ReturnShort(0x55));
}

// =========================================================================
// Static word/ref/int field accessors -- 2-byte u16 BE index.
//
// A different operand-width convention from instance fields and
// static_b. The assembler entries for these are `ArgKind::Imm16`
// (2 bytes); the dispatcher reads `[hi, lo]` as u16 BE. If they
// disagree, the index lookup goes wrong and the value won't
// round-trip.
// =========================================================================

#[test]
fn static_short_putstatic_getstatic_roundtrip() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_07 {
            fn test() {
                sspush(0x4321);
                putstatic_s(0x0000);
                getstatic_s(0x0000);
                sreturn;
            }
        }
    };
    assert_eq!(run(aid, methods), ExecResult::ReturnShort(0x4321));
}

#[test]
fn static_int_putstatic_getstatic_roundtrip() {
    let (aid, methods) = jcasm! {
        applet A0_00_00_00_62_FA_08 {
            fn test() {
                iipush(0x1234_5678);
                putstatic_i(0x0010);
                getstatic_i(0x0010);
                ireturn;
            }
        }
    };
    assert_eq!(run(aid, methods), ExecResult::ReturnInt(0x1234_5678));
}
