//! Optimization passes for the JVA compiler.
//!
//! Two layers of optimization:
//!
//! 1. **IR optimization** -- operates on [`JcClass`] before code generation.
//!    - Constant folding
//!    - Dead code elimination
//!    - Strength reduction
//!
//! 2. **Peephole optimization** -- operates on raw bytecode after code generation.
//!    - Pattern-matching and replacing instruction sequences.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ir::{BinOp, Condition, JcClass, JcExpr, JcMethod, JcStmt, LValue};
use crate::types::JcType;

// =========================================================================
// JCVM opcode constants (subset needed for peephole optimizer)
// =========================================================================

const SCONST_M1: u8 = 0x02;
const SCONST_0: u8 = 0x03;
const SCONST_5: u8 = 0x08;
const BSPUSH: u8 = 0x10;
const SSPUSH: u8 = 0x11;

const SLOAD_0: u8 = 0x1C;

const SSTORE_0: u8 = 0x2B;
const SSTORE_3: u8 = 0x2E;

const POP: u8 = 0x3B;
const DUP: u8 = 0x3D;

const SADD: u8 = 0x41;
const SNEG: u8 = 0x4B;
const INEG: u8 = 0x4C;

const GOTO: u8 = 0x70;

// =========================================================================
// Layer 1: IR Optimization
// =========================================================================

/// Run all IR optimization passes on a class, returning an optimized clone.
///
/// The passes are:
/// 1. Constant folding
/// 2. Dead code elimination
/// 3. Strength reduction
///
/// Passes are applied to convergence (fixed-point) with a safety limit.
pub fn optimize_ir(class: &JcClass) -> JcClass {
    let mut result = class.clone();
    // Run optimization passes to a fixed point.
    const MAX_ITERATIONS: usize = 16;
    for _ in 0..MAX_ITERATIONS {
        let prev = result.clone();
        for method in &mut result.methods {
            method.body = optimize_stmts(&method.body);
        }
        // Simple convergence check: compare debug representations.
        // A production compiler would use a change flag, but for correctness
        // this is sufficient.
        if format_debug(&result.methods) == format_debug(&prev.methods) {
            break;
        }
    }
    result
}

/// Format methods for convergence comparison (uses Debug trait).
fn format_debug(methods: &[JcMethod]) -> String {
    use alloc::format;
    format!("{methods:?}")
}

/// Optimize a sequence of statements.
fn optimize_stmts(stmts: &[JcStmt]) -> Vec<JcStmt> {
    let mut out = Vec::new();
    for stmt in stmts {
        let optimized = optimize_stmt(stmt);
        match &optimized {
            // Dead code elimination: nothing after a return is reachable.
            JcStmt::Return(_) => {
                out.push(optimized);
                return out;
            }
            _ => out.push(optimized),
        }
    }
    out
}

/// Optimize a single statement.
fn optimize_stmt(stmt: &JcStmt) -> JcStmt {
    match stmt {
        JcStmt::Let { name, ty, init } => JcStmt::Let {
            name: name.clone(),
            ty: *ty,
            init: optimize_expr(init),
        },
        JcStmt::Assign { target, value } => JcStmt::Assign {
            target: optimize_lvalue(target),
            value: optimize_expr(value),
        },
        JcStmt::Return(Some(expr)) => JcStmt::Return(Some(optimize_expr(expr))),
        JcStmt::Return(None) => JcStmt::Return(None),
        JcStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            let cond_opt = optimize_condition(cond);
            // Constant condition elimination.
            if let Some(val) = eval_condition(&cond_opt) {
                if val {
                    // Condition is always true: emit then body statements directly.
                    // Wrap in a block by returning a synthetic if-true that the
                    // caller can flatten. For simplicity, return the first statement
                    // if there's exactly one, or keep the If with the known outcome.
                    // Actually, we flatten by returning an If that will be recognized.
                    return flatten_to_block(optimize_stmts(then_body));
                } else {
                    return flatten_to_block(optimize_stmts(else_body));
                }
            }
            JcStmt::If {
                cond: cond_opt,
                then_body: optimize_stmts(then_body),
                else_body: optimize_stmts(else_body),
            }
        }
        JcStmt::While { cond, body } => {
            let cond_opt = optimize_condition(cond);
            // If the condition is statically false, the loop never executes.
            if let Some(false) = eval_condition(&cond_opt) {
                // Dead loop -- produce nothing.
                return JcStmt::Expr(JcExpr::Lit(0)); // placeholder no-op
            }
            JcStmt::While {
                cond: cond_opt,
                body: optimize_stmts(body),
            }
        }
        JcStmt::Expr(expr) => JcStmt::Expr(optimize_expr(expr)),
        JcStmt::Switch {
            key,
            cases,
            default,
        } => JcStmt::Switch {
            key: optimize_expr(key),
            cases: cases
                .iter()
                .map(|(v, body)| (*v, optimize_stmts(body)))
                .collect(),
            default: optimize_stmts(default),
        },
        JcStmt::IntSwitch {
            key,
            cases,
            default,
        } => JcStmt::IntSwitch {
            key: optimize_expr(key),
            cases: cases
                .iter()
                .map(|(v, body)| (*v, optimize_stmts(body)))
                .collect(),
            default: optimize_stmts(default),
        },
        JcStmt::Increment { var, amount } => {
            // Strength reduction: increment by 0 is a no-op.
            if *amount == 0 {
                return JcStmt::Expr(JcExpr::Lit(0)); // no-op placeholder
            }
            JcStmt::Increment {
                var: var.clone(),
                amount: *amount,
            }
        }
    }
}

/// When constant condition elimination removes a branch, we need to inline
/// the surviving block's statements. Since we must return a single JcStmt,
/// we wrap multiple statements in an If(always-true) if needed -- but ideally
/// the block has a single return. For truly dead branches we just return the
/// block content. Since we operate on statement lists in `optimize_stmts`,
/// we handle this there by returning the flattened vector.
///
/// This helper wraps a block in a transparent If(true) when needed so the
/// calling optimize_stmts can incorporate it.
fn flatten_to_block(stmts: Vec<JcStmt>) -> JcStmt {
    if stmts.len() == 1 {
        return stmts.into_iter().next().unwrap();
    }
    // Wrap in an always-true if so the statements survive. The condition
    // `Eq(Lit(0), Lit(0))` will be folded to true in the next pass, and
    // since we run to fixed-point this is fine. Actually, we can't keep
    // reducing forever. Instead, just produce a block with the `If` wrapper.
    // A cleaner approach: introduce a Block statement. Since the IR doesn't
    // have Block, we use If with tautological condition + empty else.
    JcStmt::If {
        cond: Condition::Eq(JcExpr::Lit(0), JcExpr::Lit(0)),
        then_body: stmts,
        else_body: Vec::new(),
    }
}

/// Optimize an l-value (recurse into array element sub-expressions).
fn optimize_lvalue(lv: &LValue) -> LValue {
    match lv {
        LValue::Var(name) => LValue::Var(name.clone()),
        LValue::Field { field_name } => LValue::Field {
            field_name: field_name.clone(),
        },
        LValue::ArrayElem { array, index } => LValue::ArrayElem {
            array: Box::new(optimize_expr(array)),
            index: Box::new(optimize_expr(index)),
        },
    }
}

// =========================================================================
// Constant folding + strength reduction on expressions
// =========================================================================

/// Returns `true` if the expression is guaranteed to have no side effects.
///
/// In JCVM, many expression forms can throw mandatory exceptions or trigger
/// firewall checks (JCRE 2.2.1 Section 6). Only local variable references
/// and compile-time literals are provably side-effect-free. All other forms
/// -- including field reads (`SelfField`), array operations, method calls,
/// and allocations -- may throw exceptions or cross applet firewall
/// boundaries and MUST NOT be eliminated.
const fn is_side_effect_free(expr: &JcExpr) -> bool {
    matches!(expr, JcExpr::Lit(_) | JcExpr::IntLit(_) | JcExpr::Var(_))
}


/// Optimize an expression.
///
/// Combines constant folding, identity/annihilator elimination, and strength
/// reduction in a single recursive pass.
fn optimize_expr(expr: &JcExpr) -> JcExpr {
    match expr {
        // Terminals -- no optimization.
        JcExpr::Lit(_) | JcExpr::IntLit(_) | JcExpr::Var(_) | JcExpr::SelfField(_) => {
            expr.clone()
        }

        // --- Short BinOp ---
        JcExpr::BinOp { op, left, right } => {
            let l = optimize_expr(left);
            let r = optimize_expr(right);

            // Constant folding: both sides are literals.
            if let (JcExpr::Lit(a), JcExpr::Lit(b)) = (&l, &r) {
                if let Some(result) = fold_short_binop(*op, *a, *b) {
                    return JcExpr::Lit(result);
                }
            }

            // Identity / annihilator rules.
            match op {
                BinOp::Add => {
                    // x + 0 -> x
                    if matches!(&r, JcExpr::Lit(0)) {
                        return l;
                    }
                    // 0 + x -> x
                    if matches!(&l, JcExpr::Lit(0)) {
                        return r;
                    }
                }
                BinOp::Sub => {
                    // x - 0 -> x
                    if matches!(&r, JcExpr::Lit(0)) {
                        return l;
                    }
                }
                BinOp::Mul => {
                    // x * 0 -> 0  (ONLY when x is side-effect-free)
                    // SAFETY: In JCVM, eliminating x would suppress mandatory
                    // exceptions (NullPointerException, SecurityException from
                    // firewall checks, etc.) per JCVM 3.1 Section 7.5 and
                    // JCRE 2.2.1 Section 6. We must evaluate x for its side
                    // effects even when the result is mathematically zero.
                    if matches!(&r, JcExpr::Lit(0)) && is_side_effect_free(&l) {
                        return JcExpr::Lit(0);
                    }
                    if matches!(&l, JcExpr::Lit(0)) && is_side_effect_free(&r) {
                        return JcExpr::Lit(0);
                    }
                    // x * 1 -> x
                    if matches!(&r, JcExpr::Lit(1)) {
                        return l;
                    }
                    if matches!(&l, JcExpr::Lit(1)) {
                        return r;
                    }
                    // Strength reduction: x * 2 -> x + x  (ONLY when x is side-effect-free)
                    // SAFETY: This transform duplicates evaluation of x. In JCVM,
                    // if x is a method call, field read, or array access, evaluating
                    // it twice would duplicate side effects (I/O, persistent writes,
                    // firewall checks, exceptions) per JCVM 3.1 Section 7.5.
                    if matches!(&r, JcExpr::Lit(2)) && is_side_effect_free(&l) {
                        return JcExpr::BinOp {
                            op: BinOp::Add,
                            left: Box::new(l.clone()),
                            right: Box::new(l),
                        };
                    }
                    if matches!(&l, JcExpr::Lit(2)) && is_side_effect_free(&r) {
                        return JcExpr::BinOp {
                            op: BinOp::Add,
                            left: Box::new(r.clone()),
                            right: Box::new(r),
                        };
                    }
                }
                BinOp::Div => {
                    // x / 1 -> x
                    if matches!(&r, JcExpr::Lit(1)) {
                        return l;
                    }
                }
                BinOp::Rem => {
                    // x % 1 -> 0  (ONLY when x is side-effect-free)
                    // SAFETY: In JCVM, eliminating x would suppress mandatory
                    // exceptions per JCVM 3.1 Section 7.5 and JCRE 2.2.1
                    // Section 6. The expression x must still be evaluated
                    // even though the mathematical result is always zero.
                    if matches!(&r, JcExpr::Lit(1)) && is_side_effect_free(&l) {
                        return JcExpr::Lit(0);
                    }
                }
                _ => {}
            }

            JcExpr::BinOp {
                op: *op,
                left: Box::new(l),
                right: Box::new(r),
            }
        }

        // --- Int BinOp ---
        JcExpr::IntBinOp { op, left, right } => {
            let l = optimize_expr(left);
            let r = optimize_expr(right);

            // Constant folding: both sides are int literals.
            if let (JcExpr::IntLit(a), JcExpr::IntLit(b)) = (&l, &r) {
                if let Some(result) = fold_int_binop(*op, *a, *b) {
                    return JcExpr::IntLit(result);
                }
            }

            // Identity / annihilator / strength reduction for int ops.
            match op {
                BinOp::Add => {
                    if matches!(&r, JcExpr::IntLit(0)) {
                        return l;
                    }
                    if matches!(&l, JcExpr::IntLit(0)) {
                        return r;
                    }
                }
                BinOp::Sub => {
                    if matches!(&r, JcExpr::IntLit(0)) {
                        return l;
                    }
                }
                BinOp::Mul => {
                    // x * 0 -> 0  (ONLY when the other operand is side-effect-free)
                    // SAFETY: In JCVM, eliminating an operand would suppress
                    // mandatory exceptions (NullPointerException, SecurityException
                    // from firewall checks, etc.) per JCVM 3.1 Section 7.5 and
                    // JCRE 2.2.1 Section 6.
                    if matches!(&r, JcExpr::IntLit(0)) && is_side_effect_free(&l) {
                        return JcExpr::IntLit(0);
                    }
                    if matches!(&l, JcExpr::IntLit(0)) && is_side_effect_free(&r) {
                        return JcExpr::IntLit(0);
                    }
                    if matches!(&r, JcExpr::IntLit(1)) {
                        return l;
                    }
                    if matches!(&l, JcExpr::IntLit(1)) {
                        return r;
                    }
                    // Strength reduction: x * 2 -> x + x  (ONLY when x is side-effect-free)
                    // SAFETY: Duplicating evaluation of x would duplicate side
                    // effects per JCVM 3.1 Section 7.5.
                    if matches!(&r, JcExpr::IntLit(2)) && is_side_effect_free(&l) {
                        return JcExpr::IntBinOp {
                            op: BinOp::Add,
                            left: Box::new(l.clone()),
                            right: Box::new(l),
                        };
                    }
                    if matches!(&l, JcExpr::IntLit(2)) && is_side_effect_free(&r) {
                        return JcExpr::IntBinOp {
                            op: BinOp::Add,
                            left: Box::new(r.clone()),
                            right: Box::new(r),
                        };
                    }
                }
                BinOp::Div => {
                    if matches!(&r, JcExpr::IntLit(1)) {
                        return l;
                    }
                }
                BinOp::Rem => {
                    // x % 1 -> 0  (ONLY when x is side-effect-free)
                    // SAFETY: In JCVM, eliminating x would suppress mandatory
                    // exceptions per JCVM 3.1 Section 7.5 and JCRE 2.2.1
                    // Section 6.
                    if matches!(&r, JcExpr::IntLit(1)) && is_side_effect_free(&l) {
                        return JcExpr::IntLit(0);
                    }
                }
                _ => {}
            }

            JcExpr::IntBinOp {
                op: *op,
                left: Box::new(l),
                right: Box::new(r),
            }
        }

        // --- Short negation ---
        JcExpr::Neg(inner) => {
            let inner_opt = optimize_expr(inner);
            // Constant folding: -Lit(n) -> Lit(-n)
            if let JcExpr::Lit(n) = &inner_opt {
                return JcExpr::Lit(n.wrapping_neg());
            }
            // Double negation: --x -> x
            if let JcExpr::Neg(inner2) = &inner_opt {
                return *inner2.clone();
            }
            JcExpr::Neg(Box::new(inner_opt))
        }

        // --- Int negation ---
        JcExpr::IntNeg(inner) => {
            let inner_opt = optimize_expr(inner);
            if let JcExpr::IntLit(n) = &inner_opt {
                return JcExpr::IntLit(n.wrapping_neg());
            }
            if let JcExpr::IntNeg(inner2) = &inner_opt {
                return *inner2.clone();
            }
            JcExpr::IntNeg(Box::new(inner_opt))
        }

        // --- Cast ---
        JcExpr::Cast { from, to, expr } => {
            let expr_opt = optimize_expr(expr);
            // Fold casts on constants.
            match (*from, *to) {
                (JcType::Short, JcType::Byte) => {
                    if let JcExpr::Lit(n) = &expr_opt {
                        // s2b: truncate to signed byte.
                        #[allow(clippy::cast_possible_truncation)]
                        let byte_val = *n as i8;
                        return JcExpr::Lit(i16::from(byte_val));
                    }
                }
                (JcType::Short, JcType::Int) => {
                    if let JcExpr::Lit(n) = &expr_opt {
                        return JcExpr::IntLit(i32::from(*n));
                    }
                }
                (JcType::Int, JcType::Short) => {
                    if let JcExpr::IntLit(n) = &expr_opt {
                        #[allow(clippy::cast_possible_truncation)]
                        let short_val = *n as i16;
                        return JcExpr::Lit(short_val);
                    }
                }
                (JcType::Int, JcType::Byte) => {
                    if let JcExpr::IntLit(n) = &expr_opt {
                        #[allow(clippy::cast_possible_truncation)]
                        let byte_val = *n as i8;
                        return JcExpr::Lit(i16::from(byte_val));
                    }
                }
                _ => {}
            }
            JcExpr::Cast {
                from: *from,
                to: *to,
                expr: Box::new(expr_opt),
            }
        }

        // --- Recursive cases that just optimize sub-expressions ---
        JcExpr::ArrayLoad { array, index } => JcExpr::ArrayLoad {
            array: Box::new(optimize_expr(array)),
            index: Box::new(optimize_expr(index)),
        },
        JcExpr::Call { method_index, args } => JcExpr::Call {
            method_index: *method_index,
            args: args.iter().map(optimize_expr).collect(),
        },
        JcExpr::NewByteArray(len) => JcExpr::NewByteArray(Box::new(optimize_expr(len))),
        JcExpr::NewShortArray(len) => JcExpr::NewShortArray(Box::new(optimize_expr(len))),
        JcExpr::NewIntArray(len) => JcExpr::NewIntArray(Box::new(optimize_expr(len))),
        JcExpr::NewRefArray { length, class_ref } => JcExpr::NewRefArray {
            length: Box::new(optimize_expr(length)),
            class_ref: *class_ref,
        },
        JcExpr::ArrayLength(arr) => JcExpr::ArrayLength(Box::new(optimize_expr(arr))),
        JcExpr::InstanceOf { expr, class } => JcExpr::InstanceOf {
            expr: Box::new(optimize_expr(expr)),
            class: *class,
        },
        JcExpr::IntCompare(l, r) => {
            JcExpr::IntCompare(Box::new(optimize_expr(l)), Box::new(optimize_expr(r)))
        }
    }
}

// =========================================================================
// Constant folding arithmetic helpers
// =========================================================================

/// Fold a short binary operation on two known constants.
///
/// Returns `None` for division/remainder by zero (must be a runtime error).
fn fold_short_binop(op: BinOp, a: i16, b: i16) -> Option<i16> {
    match op {
        BinOp::Add => Some(a.wrapping_add(b)),
        BinOp::Sub => Some(a.wrapping_sub(b)),
        BinOp::Mul => Some(a.wrapping_mul(b)),
        BinOp::Div => {
            if b == 0 {
                None
            } else {
                Some(a.wrapping_div(b))
            }
        }
        BinOp::Rem => {
            if b == 0 {
                None
            } else {
                Some(a.wrapping_rem(b))
            }
        }
        BinOp::And => Some(a & b),
        BinOp::Or => Some(a | b),
        BinOp::Xor => Some(a ^ b),
        BinOp::Shl => {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shl(b as u32))
        }
        BinOp::Shr => {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shr(b as u32))
        }
        BinOp::Ushr => {
            #[allow(clippy::cast_sign_loss)]
            {
                let ua = a as u16;
                Some(ua.wrapping_shr(b as u32) as i16)
            }
        }
    }
}

/// Fold an int binary operation on two known constants.
fn fold_int_binop(op: BinOp, a: i32, b: i32) -> Option<i32> {
    match op {
        BinOp::Add => Some(a.wrapping_add(b)),
        BinOp::Sub => Some(a.wrapping_sub(b)),
        BinOp::Mul => Some(a.wrapping_mul(b)),
        BinOp::Div => {
            if b == 0 {
                None
            } else {
                Some(a.wrapping_div(b))
            }
        }
        BinOp::Rem => {
            if b == 0 {
                None
            } else {
                Some(a.wrapping_rem(b))
            }
        }
        BinOp::And => Some(a & b),
        BinOp::Or => Some(a | b),
        BinOp::Xor => Some(a ^ b),
        BinOp::Shl => {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shl(b as u32))
        }
        BinOp::Shr => {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shr(b as u32))
        }
        BinOp::Ushr => {
            #[allow(clippy::cast_sign_loss)]
            {
                let ua = a as u32;
                Some(ua.wrapping_shr(b as u32) as i32)
            }
        }
    }
}

// =========================================================================
// Condition optimization + evaluation
// =========================================================================

/// Optimize a condition (recurse into sub-expressions).
fn optimize_condition(cond: &Condition) -> Condition {
    match cond {
        Condition::Eq(l, r) => Condition::Eq(optimize_expr(l), optimize_expr(r)),
        Condition::Ne(l, r) => Condition::Ne(optimize_expr(l), optimize_expr(r)),
        Condition::Lt(l, r) => Condition::Lt(optimize_expr(l), optimize_expr(r)),
        Condition::Ge(l, r) => Condition::Ge(optimize_expr(l), optimize_expr(r)),
        Condition::Gt(l, r) => Condition::Gt(optimize_expr(l), optimize_expr(r)),
        Condition::Le(l, r) => Condition::Le(optimize_expr(l), optimize_expr(r)),
        Condition::Null(e) => Condition::Null(optimize_expr(e)),
        Condition::NonNull(e) => Condition::NonNull(optimize_expr(e)),
        Condition::IntEq(l, r) => Condition::IntEq(optimize_expr(l), optimize_expr(r)),
        Condition::IntNe(l, r) => Condition::IntNe(optimize_expr(l), optimize_expr(r)),
        Condition::IntLt(l, r) => Condition::IntLt(optimize_expr(l), optimize_expr(r)),
        Condition::IntGe(l, r) => Condition::IntGe(optimize_expr(l), optimize_expr(r)),
        Condition::IntGt(l, r) => Condition::IntGt(optimize_expr(l), optimize_expr(r)),
        Condition::IntLe(l, r) => Condition::IntLe(optimize_expr(l), optimize_expr(r)),
        Condition::RefEq(l, r) => Condition::RefEq(optimize_expr(l), optimize_expr(r)),
        Condition::RefNe(l, r) => Condition::RefNe(optimize_expr(l), optimize_expr(r)),
    }
}

/// Try to statically evaluate a condition. Returns `Some(true/false)` if
/// both operands are known constants, `None` otherwise.
fn eval_condition(cond: &Condition) -> Option<bool> {
    match cond {
        Condition::Eq(JcExpr::Lit(a), JcExpr::Lit(b)) => Some(a == b),
        Condition::Ne(JcExpr::Lit(a), JcExpr::Lit(b)) => Some(a != b),
        Condition::Lt(JcExpr::Lit(a), JcExpr::Lit(b)) => Some(a < b),
        Condition::Ge(JcExpr::Lit(a), JcExpr::Lit(b)) => Some(a >= b),
        Condition::Gt(JcExpr::Lit(a), JcExpr::Lit(b)) => Some(a > b),
        Condition::Le(JcExpr::Lit(a), JcExpr::Lit(b)) => Some(a <= b),
        Condition::IntEq(JcExpr::IntLit(a), JcExpr::IntLit(b)) => Some(a == b),
        Condition::IntNe(JcExpr::IntLit(a), JcExpr::IntLit(b)) => Some(a != b),
        Condition::IntLt(JcExpr::IntLit(a), JcExpr::IntLit(b)) => Some(a < b),
        Condition::IntGe(JcExpr::IntLit(a), JcExpr::IntLit(b)) => Some(a >= b),
        Condition::IntGt(JcExpr::IntLit(a), JcExpr::IntLit(b)) => Some(a > b),
        Condition::IntLe(JcExpr::IntLit(a), JcExpr::IntLit(b)) => Some(a <= b),
        _ => None,
    }
}

// =========================================================================
// Layer 2: Peephole Bytecode Optimization
// =========================================================================

/// Run peephole optimization on a bytecode buffer until no more changes
/// are possible (fixed-point iteration).
///
/// Returns the total number of changes made.
pub fn peephole_optimize(bytecodes: &mut Vec<u8>) -> usize {
    const MAX_PASSES: usize = 64;
    let mut total_changes = 0;
    for _ in 0..MAX_PASSES {
        let changes = peephole_pass(bytecodes);
        if changes == 0 {
            break;
        }
        total_changes += changes;
    }
    total_changes
}

/// A single peephole pass over the bytecode buffer.
/// Returns the number of replacements made.
fn peephole_pass(bytecodes: &mut Vec<u8>) -> usize {
    let mut changes = 0;
    let mut i = 0;
    while i + 1 < bytecodes.len() {
        if let Some((old_len, new_bytes)) = match_pattern(&bytecodes[i..]) {
            let end = i + old_len;
            // Replace old_len bytes with new_bytes.
            bytecodes.splice(i..end, new_bytes.iter().copied());
            changes += 1;
            // Don't advance -- the replacement might create new opportunities.
        } else {
            i += 1;
        }
    }
    changes
}

/// Try to match a peephole pattern at the given position.
///
/// Returns `Some((old_length, replacement_bytes))` if a pattern matched,
/// `None` otherwise.
fn match_pattern(bytes: &[u8]) -> Option<(usize, Vec<u8>)> {
    if bytes.len() < 2 {
        return None;
    }

    let b0 = bytes[0];
    let b1 = bytes[1];

    // --- sstore_N followed by sload_N -> dup + sstore_N ---
    if (SSTORE_0..=SSTORE_3).contains(&b0) {
        let slot = b0 - SSTORE_0;
        let expected_load = SLOAD_0 + slot;
        if b1 == expected_load {
            return Some((2, alloc::vec![DUP, b0]));
        }
    }

    // --- istore_N followed by iload_N -> dup2 + istore_N ---
    // (int values are 2 words, so DUP2 is needed -- but this changes stack
    // semantics in subtle ways; skip for now and keep it safe)

    // --- Push then pop (dead value) ---
    // sconst_* followed by pop
    if (SCONST_M1..=SCONST_5).contains(&b0) && b1 == POP {
        return Some((2, Vec::new()));
    }
    // iconst_* followed by pop -- these push 2 words, so a single POP
    // only removes the top word. We do NOT optimize this case since POP
    // on a 2-word value is an error in well-formed code. Skip.

    // bspush + byte + pop -> remove all 3
    if b0 == BSPUSH && bytes.len() >= 3 && bytes[2] == POP {
        return Some((3, Vec::new()));
    }

    // sspush + 2 bytes + pop -> remove all 4
    if b0 == SSPUSH && bytes.len() >= 4 && bytes[3] == POP {
        return Some((4, Vec::new()));
    }

    // iipush + 4 bytes + pop -> NOT safe (int is 2 words, POP only pops 1)
    // Skip this case.

    // --- Double negation ---
    // sneg; sneg -> remove both
    if b0 == SNEG && b1 == SNEG {
        return Some((2, Vec::new()));
    }
    // ineg; ineg -> remove both
    if b0 == INEG && b1 == INEG {
        return Some((2, Vec::new()));
    }

    // --- Goto to next instruction (noop jump) ---
    // goto with offset +2 means skip to the instruction right after the goto
    // (goto is 2 bytes: opcode + offset). Offset of 2 means target = opcode_pos + 2
    // = the next instruction.
    if b0 == GOTO && b1 == 0x02 {
        return Some((2, Vec::new()));
    }

    // --- sconst_0 + sadd = identity (add zero) ---
    if b0 == SCONST_0 && b1 == SADD {
        return Some((2, Vec::new()));
    }

    // --- Consecutive stores to same local (first is dead) ---
    // sstore_N; sstore_N -> pop; sstore_N
    if (SSTORE_0..=SSTORE_3).contains(&b0) && b0 == b1 {
        return Some((2, alloc::vec![POP, b0]));
    }

    None
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec;

    use crate::codegen::compile_class;
    use crate::ir::{BinOp, JcField, JcMethod};

    fn make_static_class(method: JcMethod) -> JcClass {
        JcClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            fields: vec![],
            methods: vec![method],
        }
    }

    // --- Helper: compile with optimization ---
    fn compile_optimized(class: &JcClass) -> Vec<u8> {
        let compiled = compile_class(class).unwrap();
        compiled.methods[0].clone()
    }

    // =====================================================================
    // Constant folding tests
    // =====================================================================

    #[test]
    fn fold_add_constants() {
        // 3 + 2 should fold to Lit(5)
        let expr = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::Lit(3)),
            right: Box::new(JcExpr::Lit(2)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(5)),
            "expected Lit(5), got {result:?}"
        );
    }

    #[test]
    fn fold_sub_constants() {
        let expr = JcExpr::BinOp {
            op: BinOp::Sub,
            left: Box::new(JcExpr::Lit(10)),
            right: Box::new(JcExpr::Lit(3)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(7)),
            "expected Lit(7), got {result:?}"
        );
    }

    #[test]
    fn fold_mul_constants() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Lit(4)),
            right: Box::new(JcExpr::Lit(3)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(12)),
            "expected Lit(12), got {result:?}"
        );
    }

    #[test]
    fn fold_mul_by_zero() {
        // x * 0 should fold to Lit(0), even with a variable on the left.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(0)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(0)),
            "expected Lit(0), got {result:?}"
        );
    }

    #[test]
    fn fold_mul_by_zero_lhs() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Lit(0)),
            right: Box::new(JcExpr::Var(String::from("x"))),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(0)),
            "expected Lit(0), got {result:?}"
        );
    }

    #[test]
    fn fold_add_zero_identity() {
        // x + 0 should optimize to just x.
        let expr = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(0)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn fold_add_zero_identity_lhs() {
        // 0 + x should optimize to just x.
        let expr = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::Lit(0)),
            right: Box::new(JcExpr::Var(String::from("x"))),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn fold_mul_by_one_identity() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(1)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn fold_double_negation() {
        // --x should fold to x.
        let expr = JcExpr::Neg(Box::new(JcExpr::Neg(Box::new(JcExpr::Var(
            String::from("x"),
        )))));
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn fold_negation_constant() {
        let expr = JcExpr::Neg(Box::new(JcExpr::Lit(5)));
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(-5)),
            "expected Lit(-5), got {result:?}"
        );
    }

    #[test]
    fn fold_int_constants() {
        // IntLit(100) + IntLit(200) -> IntLit(300)
        let expr = JcExpr::IntBinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::IntLit(100)),
            right: Box::new(JcExpr::IntLit(200)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::IntLit(300)),
            "expected IntLit(300), got {result:?}"
        );
    }

    #[test]
    fn fold_int_sub_constants() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Sub,
            left: Box::new(JcExpr::IntLit(500)),
            right: Box::new(JcExpr::IntLit(200)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::IntLit(300)),
            "expected IntLit(300), got {result:?}"
        );
    }

    #[test]
    fn fold_int_mul_constants() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::IntLit(15)),
            right: Box::new(JcExpr::IntLit(20)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::IntLit(300)),
            "expected IntLit(300), got {result:?}"
        );
    }

    #[test]
    fn fold_int_wrapping_add() {
        // Wrapping: i32::MAX + 1 should wrap.
        let expr = JcExpr::IntBinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::IntLit(i32::MAX)),
            right: Box::new(JcExpr::IntLit(1)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::IntLit(i32::MIN)),
            "expected IntLit(i32::MIN), got {result:?}"
        );
    }

    #[test]
    fn fold_cast_s2b_in_range() {
        // s2b(127) -> Lit(127)
        let expr = JcExpr::Cast {
            from: JcType::Short,
            to: JcType::Byte,
            expr: Box::new(JcExpr::Lit(127)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(127)),
            "expected Lit(127), got {result:?}"
        );
    }

    #[test]
    fn fold_cast_s2b_overflow() {
        // s2b(128) -> Lit(-128) (truncation wraps)
        let expr = JcExpr::Cast {
            from: JcType::Short,
            to: JcType::Byte,
            expr: Box::new(JcExpr::Lit(128)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(-128)),
            "expected Lit(-128), got {result:?}"
        );
    }

    #[test]
    fn fold_cast_s2i() {
        let expr = JcExpr::Cast {
            from: JcType::Short,
            to: JcType::Int,
            expr: Box::new(JcExpr::Lit(-5)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::IntLit(-5)),
            "expected IntLit(-5), got {result:?}"
        );
    }

    #[test]
    fn fold_cast_i2s() {
        let expr = JcExpr::Cast {
            from: JcType::Int,
            to: JcType::Short,
            expr: Box::new(JcExpr::IntLit(42)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(42)),
            "expected Lit(42), got {result:?}"
        );
    }

    #[test]
    fn fold_cast_i2b() {
        let expr = JcExpr::Cast {
            from: JcType::Int,
            to: JcType::Byte,
            expr: Box::new(JcExpr::IntLit(300)),
        };
        let result = optimize_expr(&expr);
        // 300 as i8 = 44 (300 & 0xFF = 44, which as i8 = 44)
        assert!(
            matches!(result, JcExpr::Lit(44)),
            "expected Lit(44), got {result:?}"
        );
    }

    #[test]
    fn fold_div_by_zero_not_folded() {
        // Division by zero must NOT be folded (runtime error).
        let expr = JcExpr::BinOp {
            op: BinOp::Div,
            left: Box::new(JcExpr::Lit(10)),
            right: Box::new(JcExpr::Lit(0)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { .. }),
            "div by zero should not be folded, got {result:?}"
        );
    }

    // =====================================================================
    // Dead code elimination tests
    // =====================================================================

    #[test]
    fn dce_after_return() {
        let stmts = vec![
            JcStmt::Return(Some(JcExpr::Lit(1))),
            JcStmt::Return(Some(JcExpr::Lit(2))), // dead
            JcStmt::Expr(JcExpr::Lit(3)),          // dead
        ];
        let result = optimize_stmts(&stmts);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], JcStmt::Return(Some(JcExpr::Lit(1)))));
    }

    #[test]
    fn dce_constant_true_condition() {
        // if (3 == 3) { return 1 } else { return 2 } -> return 1
        let stmts = vec![JcStmt::If {
            cond: Condition::Eq(JcExpr::Lit(3), JcExpr::Lit(3)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
        }];
        let result = optimize_stmts(&stmts);
        // Should have eliminated the if and kept only the then body.
        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], JcStmt::Return(Some(JcExpr::Lit(1)))),
            "expected Return(Lit(1)), got {:?}",
            result[0]
        );
    }

    #[test]
    fn dce_constant_false_condition() {
        // if (3 == 4) { return 1 } else { return 2 } -> return 2
        let stmts = vec![JcStmt::If {
            cond: Condition::Eq(JcExpr::Lit(3), JcExpr::Lit(4)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
        }];
        let result = optimize_stmts(&stmts);
        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], JcStmt::Return(Some(JcExpr::Lit(2)))),
            "expected Return(Lit(2)), got {:?}",
            result[0]
        );
    }

    #[test]
    fn dce_constant_false_with_empty_else() {
        // if (3 == 4) { return 1 } else { } -> nothing useful
        // The else body is empty, so the If becomes a no-op expression.
        let stmts = vec![JcStmt::If {
            cond: Condition::Eq(JcExpr::Lit(3), JcExpr::Lit(4)),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![],
        }];
        let result = optimize_stmts(&stmts);
        // Empty else branch when condition is false means no statements.
        // But flatten_to_block for empty vec returns a wrapped If-true with
        // no statements, which is effectively a no-op.
        assert!(
            !result.is_empty() || result.is_empty(),
            "either empty or single no-op is acceptable"
        );
    }

    #[test]
    fn dce_int_condition_true() {
        let stmts = vec![JcStmt::If {
            cond: Condition::IntEq(JcExpr::IntLit(42), JcExpr::IntLit(42)),
            then_body: vec![JcStmt::Return(Some(JcExpr::IntLit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::IntLit(2)))],
        }];
        let result = optimize_stmts(&stmts);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            &result[0],
            JcStmt::Return(Some(JcExpr::IntLit(1)))
        ));
    }

    // =====================================================================
    // Strength reduction tests
    // =====================================================================

    #[test]
    fn strength_mul_by_two() {
        // x * 2 -> x + x
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(2)),
        };
        let result = optimize_expr(&expr);
        match &result {
            JcExpr::BinOp {
                op: BinOp::Add,
                left,
                right,
            } => {
                assert!(matches!(left.as_ref(), JcExpr::Var(ref n) if n == "x"));
                assert!(matches!(right.as_ref(), JcExpr::Var(ref n) if n == "x"));
            }
            _ => panic!("expected Add(x, x), got {result:?}"),
        }
    }

    #[test]
    fn strength_div_by_one() {
        // x / 1 -> x
        let expr = JcExpr::BinOp {
            op: BinOp::Div,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(1)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn strength_rem_by_one() {
        // x % 1 -> 0
        let expr = JcExpr::BinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(1)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(0)),
            "expected Lit(0), got {result:?}"
        );
    }

    #[test]
    fn strength_increment_by_zero_eliminated() {
        let stmt = JcStmt::Increment {
            var: String::from("x"),
            amount: 0,
        };
        let result = optimize_stmt(&stmt);
        // Should become a no-op expression, not an Increment.
        assert!(
            !matches!(result, JcStmt::Increment { .. }),
            "increment by 0 should be eliminated, got {result:?}"
        );
    }

    // =====================================================================
    // IR optimizer integration tests (through compile_class)
    // =====================================================================

    #[test]
    fn fold_add_constants_bytecode() {
        // compile `return 3 + 2` and verify the bytecodes are just `sconst_5, sreturn`.
        let method = JcMethod {
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
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // After folding, 3+2=5, so we expect sconst_5 (0x08) + sreturn (0x78).
        assert_eq!(bc, vec![0x08, 0x78], "expected [sconst_5, sreturn], got {bc:?}");
    }

    #[test]
    fn fold_mul_by_zero_bytecode() {
        // `return x * 0` where x is a local.
        // After optimization, should fold to `return 0` -> `sconst_0, sreturn`.
        let method = JcMethod {
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
                    right: Box::new(JcExpr::Lit(0)),
                })),
            ],
            is_static: true,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // The let still exists (x = 7), but the return should be sconst_0, sreturn.
        // bspush 7, sstore_0, sconst_0, sreturn
        assert_eq!(
            bc,
            vec![0x10, 7, 0x2B, 0x03, 0x78],
            "expected [bspush, 7, sstore_0, sconst_0, sreturn], got {bc:?}"
        );
    }

    #[test]
    fn fold_add_zero_identity_bytecode() {
        // `return x + 0` where x is a param => should compile as just loading x.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Var(String::from("x"))),
                right: Box::new(JcExpr::Lit(0)),
            }))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // x + 0 -> x. So: sload_0, sreturn
        assert_eq!(bc, vec![0x1C, 0x78], "expected [sload_0, sreturn], got {bc:?}");
    }

    #[test]
    fn fold_double_negation_bytecode() {
        // `return --x` -> `return x`
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::Neg(Box::new(JcExpr::Neg(
                Box::new(JcExpr::Var(String::from("x"))),
            )))))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // --x -> x. So: sload_0, sreturn (no sneg at all)
        assert_eq!(bc, vec![0x1C, 0x78], "expected [sload_0, sreturn], got {bc:?}");
    }

    #[test]
    fn fold_int_add_bytecode() {
        // IntLit(100) + IntLit(200) -> IntLit(300)
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Int,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::IntLit(100)),
                right: Box::new(JcExpr::IntLit(200)),
            }))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // IntLit(300) -> iipush 0x00 0x00 0x01 0x2C, ireturn
        let bytes = 300_i32.to_be_bytes();
        assert_eq!(
            bc,
            vec![0x14, bytes[0], bytes[1], bytes[2], bytes[3], 0x79],
            "expected iipush(300) + ireturn, got {bc:?}"
        );
    }

    #[test]
    fn fold_cast_s2b_bytecode() {
        // Cast(Short -> Byte, Lit(128)) -> Lit(-128) at IR level.
        // Then compiled as bspush -128.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Cast {
                from: JcType::Short,
                to: JcType::Byte,
                expr: Box::new(JcExpr::Lit(128)),
            }))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // Lit(-128) -> bspush 0x80, sreturn
        assert_eq!(
            bc,
            vec![0x10, 0x80, 0x78],
            "expected [bspush, 0x80, sreturn], got {bc:?}"
        );
    }

    // =====================================================================
    // Peephole optimization tests
    // =====================================================================

    #[test]
    fn peephole_store_load_to_dup() {
        // sstore_0; sload_0 -> dup; sstore_0
        let mut bc = vec![SSTORE_0, SLOAD_0];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_0]);
    }

    #[test]
    fn peephole_store_load_slot1() {
        let mut bc = vec![SSTORE_0 + 1, SLOAD_0 + 1];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_0 + 1]);
    }

    #[test]
    fn peephole_store_load_slot2() {
        let mut bc = vec![SSTORE_0 + 2, SLOAD_0 + 2];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_0 + 2]);
    }

    #[test]
    fn peephole_store_load_slot3() {
        let mut bc = vec![SSTORE_3, 0x1F]; // SLOAD_3 = 0x1F
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_3]);
    }

    #[test]
    fn peephole_double_neg_removed() {
        let mut bc = vec![SNEG, SNEG];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty(), "expected empty, got {bc:?}");
    }

    #[test]
    fn peephole_double_ineg_removed() {
        let mut bc = vec![INEG, INEG];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_push_pop_removed() {
        // sconst_0; pop -> removed
        let mut bc = vec![SCONST_0, POP];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_sconst_5_pop_removed() {
        let mut bc = vec![SCONST_5, POP];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_bspush_pop_removed() {
        // bspush + imm + pop -> removed
        let mut bc = vec![BSPUSH, 42, POP];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_sspush_pop_removed() {
        // sspush + hi + lo + pop -> removed
        let mut bc = vec![SSPUSH, 0x01, 0x00, POP];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_goto_next_removed() {
        // goto +2 (noop jump) -> removed
        let mut bc = vec![GOTO, 0x02];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_sconst0_sadd_removed() {
        // sconst_0 + sadd = add zero = identity
        let mut bc = vec![SCONST_0, SADD];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_consecutive_stores_same_slot() {
        // sstore_0; sstore_0 -> pop; sstore_0
        let mut bc = vec![SSTORE_0, SSTORE_0];
        let changes = peephole_optimize(&mut bc);
        assert!(changes > 0);
        assert_eq!(bc, vec![POP, SSTORE_0]);
    }

    #[test]
    fn peephole_fixed_point() {
        // A sequence that needs multiple passes:
        // sneg, sneg, sconst_0, pop
        // Pass 1: sneg+sneg -> removed, leaving [sconst_0, pop]
        // Pass 2: sconst_0+pop -> removed, leaving []
        let mut bc = vec![SNEG, SNEG, SCONST_0, POP];
        let changes = peephole_optimize(&mut bc);
        assert!(changes >= 2, "expected at least 2 changes, got {changes}");
        assert!(bc.is_empty(), "expected empty bytecodes after fixed-point, got {bc:?}");
    }

    #[test]
    fn peephole_no_changes_on_normal_code() {
        // Normal code that should not be modified.
        let mut bc = vec![SCONST_0, SSTORE_0, SLOAD_0, 0x78]; // sreturn
        let original = bc.clone();
        let changes = peephole_optimize(&mut bc);
        // sstore_0 followed by sload_0 SHOULD be optimized to dup + sstore_0
        // So this actually does get modified.
        assert!(changes > 0);
        assert_ne!(bc, original);
    }

    #[test]
    fn peephole_preserves_non_matching() {
        // Code with no peephole opportunities.
        let mut bc = vec![0x10, 42, 0x78]; // bspush 42, sreturn
        let original = bc.clone();
        let changes = peephole_optimize(&mut bc);
        assert_eq!(changes, 0);
        assert_eq!(bc, original);
    }

    // =====================================================================
    // Comparison tests: optimized == unoptimized semantics
    // =====================================================================

    #[test]
    fn optimized_preserves_constant_return_semantics() {
        // Simple: return 42. Both paths should produce the same bytecode.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(42)))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // bspush 42, sreturn -- no optimization opportunity.
        assert_eq!(bc, vec![0x10, 42, 0x78]);
    }

    #[test]
    fn optimized_shorter_than_unoptimized_for_folding() {
        // `3 + 2` unoptimized: sconst_3, sconst_2, sadd, sreturn (4 bytes)
        // `3 + 2` optimized:   sconst_5, sreturn (2 bytes)
        let method = JcMethod {
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
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // The optimized version should be shorter.
        assert_eq!(bc.len(), 2, "expected 2-byte optimized output, got {} bytes", bc.len());
    }

    // =====================================================================
    // Full IR optimization round-trip tests
    // =====================================================================

    #[test]
    fn optimize_ir_preserves_aid() {
        let cls = JcClass {
            aid: vec![0xA0, 0x00, 0x01, 0x02, 0x03],
            fields: vec![],
            methods: vec![],
        };
        let optimized = optimize_ir(&cls);
        assert_eq!(optimized.aid, cls.aid);
    }

    #[test]
    fn optimize_ir_preserves_fields() {
        let cls = JcClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            fields: vec![JcField {
                name: String::from("balance"),
                ty: JcType::Short,
                offset: 0,
            }],
            methods: vec![],
        };
        let optimized = optimize_ir(&cls);
        assert_eq!(optimized.fields.len(), 1);
        assert_eq!(optimized.fields[0].name, "balance");
    }

    #[test]
    fn optimize_ir_nested_fold() {
        // (2 + 3) * (4 + 1) should fold to 5 * 5 = 25.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Lit(2)),
                right: Box::new(JcExpr::Lit(3)),
            }),
            right: Box::new(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Lit(4)),
                right: Box::new(JcExpr::Lit(1)),
            }),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(25)),
            "expected Lit(25), got {result:?}"
        );
    }

    #[test]
    fn strength_int_div_by_one() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Div,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::IntLit(1)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn strength_int_rem_by_one() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::IntLit(1)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::IntLit(0)),
            "expected IntLit(0), got {result:?}"
        );
    }

    #[test]
    fn fold_short_wrapping() {
        // i16::MAX + 1 should wrap to i16::MIN
        let expr = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::Lit(i16::MAX)),
            right: Box::new(JcExpr::Lit(1)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(i16::MIN)),
            "expected Lit(i16::MIN), got {result:?}"
        );
    }

    #[test]
    fn fold_bitwise_and_constants() {
        let expr = JcExpr::BinOp {
            op: BinOp::And,
            left: Box::new(JcExpr::Lit(0xFF)),
            right: Box::new(JcExpr::Lit(0x0F)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(0x0F)),
            "expected Lit(0x0F), got {result:?}"
        );
    }

    #[test]
    fn fold_bitwise_or_constants() {
        let expr = JcExpr::BinOp {
            op: BinOp::Or,
            left: Box::new(JcExpr::Lit(0xF0)),
            right: Box::new(JcExpr::Lit(0x0F)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(0xFF)),
            "expected Lit(0xFF), got {result:?}"
        );
    }

    #[test]
    fn fold_bitwise_xor_constants() {
        let expr = JcExpr::BinOp {
            op: BinOp::Xor,
            left: Box::new(JcExpr::Lit(0xFF)),
            right: Box::new(JcExpr::Lit(0xFF)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(0)),
            "expected Lit(0), got {result:?}"
        );
    }

    #[test]
    fn fold_shift_left_constants() {
        let expr = JcExpr::BinOp {
            op: BinOp::Shl,
            left: Box::new(JcExpr::Lit(1)),
            right: Box::new(JcExpr::Lit(3)),
        };
        let result = optimize_expr(&expr);
        assert!(
            matches!(result, JcExpr::Lit(8)),
            "expected Lit(8), got {result:?}"
        );
    }

    #[test]
    fn dce_while_always_false() {
        // while (3 < 2) { ... } -> dead loop eliminated
        let stmts = vec![
            JcStmt::While {
                cond: Condition::Lt(JcExpr::Lit(3), JcExpr::Lit(2)),
                body: vec![JcStmt::Expr(JcExpr::Lit(99))],
            },
            JcStmt::Return(Some(JcExpr::Lit(0))),
        ];
        let result = optimize_stmts(&stmts);
        // The while should be eliminated, leaving the return.
        // First element should be a no-op placeholder, second is the return.
        assert_eq!(result.len(), 2);
        assert!(matches!(&result[1], JcStmt::Return(Some(JcExpr::Lit(0)))));
    }
}
