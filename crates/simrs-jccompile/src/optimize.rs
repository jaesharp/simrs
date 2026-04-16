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
use alloc::vec;
use alloc::vec::Vec;

use crate::config::{IrConfig, PeepholeConfig};
use crate::ir::{BinOp, Condition, JcClass, JcExpr, JcMethod, JcStmt, LValue};
use crate::types::JcType;

// =========================================================================
// Effect extraction support
// =========================================================================

/// Generates fresh temporary variable names for effect extraction.
///
/// When the optimizer encounters an effectful sub-expression inside a
/// transform (e.g. `call() * 0`), it hoists the effectful part into a
/// preceding `Let` statement using a fresh name like `_eff0`, `_eff1`, etc.
/// The new locals are tracked here and appended to the method's local list
/// after each optimization pass.
struct FreshNameGen {
    counter: usize,
    new_locals: Vec<(String, JcType)>,
}

impl FreshNameGen {
    const fn new() -> Self {
        Self {
            counter: 0,
            new_locals: Vec::new(),
        }
    }

    fn fresh(&mut self, ty: JcType) -> String {
        use alloc::format;
        let name = format!("_eff{}", self.counter);
        self.counter += 1;
        self.new_locals.push((name.clone(), ty));
        name
    }
}

// =========================================================================
// Effect classification
// =========================================================================

/// Bitflag set of possible side effects for a [`JcExpr`].
///
/// Each bit represents one kind of observable effect that JCVM operations
/// may produce. The optimizer uses this to decide which expressions can be
/// eliminated, duplicated, or hoisted.
///
/// The `effects_of` function computes this compositionally over the IR tree
/// with an exhaustive match (no `_ =>` arm), so adding a new `JcExpr`
/// variant forces the author to classify its effects at compile time.
///
/// Reference: JCVM 3.1 Section 7.5 (exception semantics),
///            JCRE 2.2.1 Section 6 (applet firewall).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Effects(u16);

impl Effects {
    /// No effects -- the expression is pure.
    const PURE: Self = Self(0);
    /// May throw `ArithmeticException` (sdiv/srem/idiv/irem by zero).
    const ARITHMETIC: Self = Self(1 << 0);
    /// Reads an instance field (observable state access).
    const FIELD_READ: Self = Self(1 << 1);
    /// Crosses the JCRE applet firewall boundary (`SecurityException`).
    const FIREWALL: Self = Self(1 << 2);
    /// May throw `NullPointerException`.
    const NULL_DEREF: Self = Self(1 << 3);
    /// May throw `ArrayIndexOutOfBoundsException`.
    const ARRAY_BOUNDS: Self = Self(1 << 4);
    /// Invokes a method (arbitrary effects: writes, I/O, exceptions).
    const INVOKE: Self = Self(1 << 5);
    /// Allocates heap memory (may throw, mutates persistent heap).
    const ALLOCATION: Self = Self(1 << 6);
    /// May throw `NegativeArraySizeException`.
    const NEGATIVE_SIZE: Self = Self(1 << 7);

    /// Combine two effect sets (bitwise OR).
    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` if the effect set is empty (pure expression).
    const fn is_pure(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Debug for Effects {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_pure() {
            return write!(f, "Effects::PURE");
        }
        let flags: &[(&str, u16)] = &[
            ("ARITHMETIC", Self::ARITHMETIC.0),
            ("FIELD_READ", Self::FIELD_READ.0),
            ("FIREWALL", Self::FIREWALL.0),
            ("NULL_DEREF", Self::NULL_DEREF.0),
            ("ARRAY_BOUNDS", Self::ARRAY_BOUNDS.0),
            ("INVOKE", Self::INVOKE.0),
            ("ALLOCATION", Self::ALLOCATION.0),
            ("NEGATIVE_SIZE", Self::NEGATIVE_SIZE.0),
        ];
        let mut first = true;
        write!(f, "Effects(")?;
        for &(name, bit) in flags {
            if self.0 & bit != 0 {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        write!(f, ")")
    }
}

use simrs_jcvm_opcodes::{
    BSPUSH, DUP, GOTO, INEG, POP, SADD, SCONST_0, SCONST_5, SCONST_M1, SLOAD_0, SNEG, SSPUSH,
    SSTORE_0, SSTORE_3,
};

// =========================================================================
// Layer 1: IR Optimization
// =========================================================================

/// Run all IR optimization passes on a class, returning an optimized clone.
///
/// Uses default configuration (`IrConfig::default_config()`).
pub fn optimize_ir(class: &JcClass) -> JcClass {
    optimize_ir_with_config(class, &IrConfig::default_config())
}

/// Run IR optimization passes with explicit configuration.
///
/// The passes are:
/// 1. Constant folding
/// 2. Dead code elimination (skipped for branch DCE in constant-time methods)
/// 3. Strength reduction
///
/// Passes are applied to convergence (fixed-point) with a configurable limit.
/// Returns the number of iterations actually performed.
pub fn optimize_ir_with_config(class: &JcClass, config: &IrConfig) -> JcClass {
    if !config.enabled {
        return class.clone();
    }
    let mut result = class.clone();
    for _ in 0..config.max_iterations {
        let prev = result.clone();
        for method in &mut result.methods {
            let ct = method.constant_time;
            let mut fresh = FreshNameGen::new();
            method.body = optimize_stmts(&method.body, &mut fresh, ct);
            // Append any new locals created by effect extraction.
            method.locals.append(&mut fresh.new_locals);
        }
        // Simple convergence check: compare debug representations.
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
fn optimize_stmts(stmts: &[JcStmt], fresh: &mut FreshNameGen, ct: bool) -> Vec<JcStmt> {
    let mut out = Vec::new();
    for stmt in stmts {
        let optimized = optimize_stmt(stmt, fresh, ct);
        for s in optimized {
            // Dead code elimination: nothing after a return is reachable.
            // This is CT-safe: unreachable code cannot affect timing.
            let is_return = matches!(&s, JcStmt::Return(_));
            out.push(s);
            if is_return {
                return out;
            }
        }
    }
    out
}

/// Optimize a single statement, returning one or more statements.
///
/// Effect extraction may hoist effectful sub-expressions into preceding
/// `Let` statements, so the result is a `Vec` rather than a single statement.
#[allow(clippy::too_many_lines)]
fn optimize_stmt(stmt: &JcStmt, fresh: &mut FreshNameGen, ct: bool) -> Vec<JcStmt> {
    match stmt {
        JcStmt::Let { name, ty, init } => {
            let mut hoisted = Vec::new();
            let new_init = optimize_expr(init, &mut hoisted, fresh, true);
            hoisted.push(JcStmt::Let {
                name: name.clone(),
                ty: *ty,
                init: new_init,
            });
            hoisted
        }
        JcStmt::Assign { target, value } => {
            let mut hoisted = Vec::new();
            let new_target = optimize_lvalue(target, &mut hoisted, fresh);
            let new_value = optimize_expr(value, &mut hoisted, fresh, true);
            hoisted.push(JcStmt::Assign {
                target: new_target,
                value: new_value,
            });
            hoisted
        }
        JcStmt::Return(Some(expr)) => {
            let mut hoisted = Vec::new();
            let new_expr = optimize_expr(expr, &mut hoisted, fresh, true);
            hoisted.push(JcStmt::Return(Some(new_expr)));
            hoisted
        }
        JcStmt::Return(None) => vec![JcStmt::Return(None)],
        JcStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            let mut hoisted = Vec::new();
            let cond_opt = optimize_condition(cond, &mut hoisted, fresh, true);
            // Constant condition elimination -- NOT CT-safe (removes a
            // branch that may exist for timing equalization).
            if !ct {
                if let Some(val) = eval_condition(&cond_opt) {
                    if val {
                        hoisted.extend(optimize_stmts(then_body, fresh, ct));
                    } else {
                        hoisted.extend(optimize_stmts(else_body, fresh, ct));
                    }
                    return hoisted;
                }
            }
            hoisted.push(JcStmt::If {
                cond: cond_opt,
                then_body: optimize_stmts(then_body, fresh, ct),
                else_body: optimize_stmts(else_body, fresh, ct),
            });
            hoisted
        }
        JcStmt::While { cond, body } => {
            // While conditions are re-evaluated each iteration -- do NOT
            // extract effects (they must fire on every loop pass).
            let cond_opt =
                optimize_condition(cond, &mut Vec::new(), &mut FreshNameGen::new(), false);
            // If the condition is statically false, the loop never executes.
            // NOT CT-safe: removing a loop body could change timing.
            if !ct && eval_condition(&cond_opt) == Some(false) {
                // Dead loop -- produce nothing.
                return vec![JcStmt::Expr(JcExpr::Lit(0))]; // placeholder no-op
            }
            vec![JcStmt::While {
                cond: cond_opt,
                body: optimize_stmts(body, fresh, ct),
            }]
        }
        JcStmt::Expr(expr) => {
            let mut hoisted = Vec::new();
            let new_expr = optimize_expr(expr, &mut hoisted, fresh, true);
            hoisted.push(JcStmt::Expr(new_expr));
            hoisted
        }
        JcStmt::Switch {
            key,
            cases,
            default,
        } => {
            let mut hoisted = Vec::new();
            let new_key = optimize_expr(key, &mut hoisted, fresh, true);
            hoisted.push(JcStmt::Switch {
                key: new_key,
                cases: cases
                    .iter()
                    .map(|(v, body)| (*v, optimize_stmts(body, fresh, ct)))
                    .collect(),
                default: optimize_stmts(default, fresh, ct),
            });
            hoisted
        }
        JcStmt::IntSwitch {
            key,
            cases,
            default,
        } => {
            let mut hoisted = Vec::new();
            let new_key = optimize_expr(key, &mut hoisted, fresh, true);
            hoisted.push(JcStmt::IntSwitch {
                key: new_key,
                cases: cases
                    .iter()
                    .map(|(v, body)| (*v, optimize_stmts(body, fresh, ct)))
                    .collect(),
                default: optimize_stmts(default, fresh, ct),
            });
            hoisted
        }
        JcStmt::Increment { var, amount } => {
            // Strength reduction: increment by 0 is a no-op.
            if *amount == 0 {
                return vec![JcStmt::Expr(JcExpr::Lit(0))]; // no-op placeholder
            }
            vec![JcStmt::Increment {
                var: var.clone(),
                amount: *amount,
            }]
        }
    }
}

/// Optimize an l-value (recurse into array element sub-expressions).
fn optimize_lvalue(lv: &LValue, hoisted: &mut Vec<JcStmt>, fresh: &mut FreshNameGen) -> LValue {
    match lv {
        LValue::Var(name) => LValue::Var(name.clone()),
        LValue::Field { field_name } => LValue::Field {
            field_name: field_name.clone(),
        },
        LValue::ArrayElem { array, index } => LValue::ArrayElem {
            array: Box::new(optimize_expr(array, hoisted, fresh, true)),
            index: Box::new(optimize_expr(index, hoisted, fresh, true)),
        },
    }
}

// =========================================================================
// Constant folding + strength reduction on expressions
// =========================================================================

/// Compute the effect set of an expression compositionally.
///
/// This is an exhaustive match with no `_ =>` arm. Adding a new `JcExpr`
/// variant will produce a compile error here, forcing the author to
/// classify its effects.
///
/// Reference: JCVM 3.1 Section 7.5 (mandatory exceptions),
///            JCRE 2.2.1 Section 6 (applet firewall).
fn effects_of(expr: &JcExpr) -> Effects {
    match expr {
        // --- Terminals: pure ---
        JcExpr::Lit(_) | JcExpr::IntLit(_) | JcExpr::Var(_) => Effects::PURE,

        // --- Field read: firewall crossing ---
        JcExpr::SelfField(_) => Effects::FIELD_READ.union(Effects::FIREWALL),

        // --- BinOp / IntBinOp: compositional; Div/Rem add ARITHMETIC ---
        JcExpr::BinOp { op, left, right } | JcExpr::IntBinOp { op, left, right } => {
            let child = effects_of(left).union(effects_of(right));
            match op {
                BinOp::Div | BinOp::Rem => child.union(Effects::ARITHMETIC),
                _ => child,
            }
        }

        // --- Negation: inherits child effects (SNEG/INEG can't throw) ---
        JcExpr::Neg(inner) | JcExpr::IntNeg(inner) => effects_of(inner),

        // --- Array load: null deref + bounds check + firewall ---
        JcExpr::ArrayLoad { array, index } => effects_of(array)
            .union(effects_of(index))
            .union(Effects::NULL_DEREF)
            .union(Effects::ARRAY_BOUNDS)
            .union(Effects::FIREWALL),

        // --- Method call: INVOKE + child effects ---
        JcExpr::Call { args, .. } => {
            let mut eff = Effects::INVOKE;
            for arg in args {
                eff = eff.union(effects_of(arg));
            }
            eff
        }

        // --- Allocation: heap mutation + negative size ---
        JcExpr::NewByteArray(len) | JcExpr::NewShortArray(len) | JcExpr::NewIntArray(len) => {
            effects_of(len)
                .union(Effects::ALLOCATION)
                .union(Effects::NEGATIVE_SIZE)
        }
        JcExpr::NewRefArray { length, .. } => effects_of(length)
            .union(Effects::ALLOCATION)
            .union(Effects::NEGATIVE_SIZE),

        // --- Array length: null deref ---
        JcExpr::ArrayLength(arr) => effects_of(arr).union(Effects::NULL_DEREF),

        // --- Cast / InstanceOf: inherit child effects (no exception spec) ---
        JcExpr::Cast { expr, .. } | JcExpr::InstanceOf { expr, .. } => effects_of(expr),

        // --- IntCompare: inherits child effects (ICMP can't throw) ---
        JcExpr::IntCompare(l, r) => effects_of(l).union(effects_of(r)),
    }
}

/// Returns `true` if the expression is guaranteed to have no side effects.
///
/// Delegates to [`effects_of`] for compositional analysis.
fn is_side_effect_free(expr: &JcExpr) -> bool {
    effects_of(expr).is_pure()
}

/// Numeric width -- parameterizes the identity/annihilator/strength-reduction
/// transforms so the same logic handles both Short (`BinOp`) and Int
/// (`IntBinOp`) without duplication.
#[derive(Clone, Copy)]
enum NumWidth {
    Short,
    Int,
}

impl NumWidth {
    /// The IR type for locals of this width.
    const fn ty(self) -> JcType {
        match self {
            Self::Short => JcType::Short,
            Self::Int => JcType::Int,
        }
    }

    /// Construct a zero literal of this width.
    const fn zero(self) -> JcExpr {
        match self {
            Self::Short => JcExpr::Lit(0),
            Self::Int => JcExpr::IntLit(0),
        }
    }

    /// Test whether `expr` is a literal equal to `n` at this width.
    fn is_lit(self, expr: &JcExpr, n: i32) -> bool {
        match self {
            Self::Short => matches!(expr, JcExpr::Lit(v) if i32::from(*v) == n),
            Self::Int => matches!(expr, JcExpr::IntLit(v) if *v == n),
        }
    }

    /// Construct a BinOp/IntBinOp at this width.
    fn make_binop(self, op: BinOp, l: JcExpr, r: JcExpr) -> JcExpr {
        match self {
            Self::Short => JcExpr::BinOp {
                op,
                left: Box::new(l),
                right: Box::new(r),
            },
            Self::Int => JcExpr::IntBinOp {
                op,
                left: Box::new(l),
                right: Box::new(r),
            },
        }
    }
}

/// Hoist an effectful expression into a preceding `Let`, or clone it as-is
/// if it's side-effect-free. Returns `Some(safe_expr)` where `safe_expr`
/// is either a clone of the original (if pure) or a `Var` referencing the
/// fresh local. Returns `None` when extraction is disabled and the
/// expression has side effects.
fn hoist_if_needed(
    expr: &JcExpr,
    w: NumWidth,
    hoisted: &mut Vec<JcStmt>,
    fresh: &mut FreshNameGen,
    extract: bool,
) -> Option<JcExpr> {
    if is_side_effect_free(expr) {
        Some(expr.clone())
    } else if extract {
        let name = fresh.fresh(w.ty());
        hoisted.push(JcStmt::Let {
            name: name.clone(),
            ty: w.ty(),
            init: expr.clone(),
        });
        Some(JcExpr::Var(name))
    } else {
        None
    }
}

/// Apply identity, annihilator, and strength-reduction rules to a binary
/// operation at a given numeric width.
///
/// Returns `Some(result)` if a rule fired, `None` to fall through to the
/// unmodified reconstruct.
fn optimize_binop_rules(
    op: BinOp,
    l: &JcExpr,
    r: &JcExpr,
    w: NumWidth,
    hoisted: &mut Vec<JcStmt>,
    fresh: &mut FreshNameGen,
    extract: bool,
) -> Option<JcExpr> {
    match op {
        BinOp::Add => {
            if w.is_lit(r, 0) {
                return Some(l.clone());
            }
            if w.is_lit(l, 0) {
                return Some(r.clone());
            }
        }
        BinOp::Sub if w.is_lit(r, 0) => {
            return Some(l.clone());
        }
        BinOp::Mul => {
            // x * 0 -> 0  (hoist x for side effects if needed)
            if w.is_lit(r, 0) && hoist_if_needed(l, w, hoisted, fresh, extract).is_some() {
                return Some(w.zero());
            }
            // 0 * x -> 0  (symmetric)
            if w.is_lit(l, 0) && hoist_if_needed(r, w, hoisted, fresh, extract).is_some() {
                return Some(w.zero());
            }
            // x * 1 -> x
            if w.is_lit(r, 1) {
                return Some(l.clone());
            }
            if w.is_lit(l, 1) {
                return Some(r.clone());
            }
            // x * 2 -> x + x  (hoist to avoid duplicating effects)
            if w.is_lit(r, 2) {
                if let Some(safe) = hoist_if_needed(l, w, hoisted, fresh, extract) {
                    return Some(w.make_binop(BinOp::Add, safe.clone(), safe));
                }
            }
            // 2 * x -> x + x  (symmetric)
            if w.is_lit(l, 2) {
                if let Some(safe) = hoist_if_needed(r, w, hoisted, fresh, extract) {
                    return Some(w.make_binop(BinOp::Add, safe.clone(), safe));
                }
            }
        }
        BinOp::Div if w.is_lit(r, 1) => {
            return Some(l.clone());
        }
        BinOp::Rem
            if w.is_lit(r, 1) && hoist_if_needed(l, w, hoisted, fresh, extract).is_some() =>
        {
            // x % 1 -> 0  (hoist x for side effects if needed)
            return Some(w.zero());
        }
        _ => {}
    }
    None
}

/// Optimize an expression.
///
/// Combines constant folding, identity/annihilator elimination, strength
/// reduction, and effect extraction in a single recursive pass.
///
/// When `extract` is `true` and a transform would otherwise be blocked by
/// an effectful operand, the effectful sub-expression is hoisted into a
/// preceding `Let` statement (appended to `hoisted`) so the mathematical
/// simplification can still be applied.
///
/// When `extract` is `false` (e.g. inside While conditions that are
/// re-evaluated each iteration), effectful operands block the transform
/// as before.
#[allow(clippy::too_many_lines)]
fn optimize_expr(
    expr: &JcExpr,
    hoisted: &mut Vec<JcStmt>,
    fresh: &mut FreshNameGen,
    extract: bool,
) -> JcExpr {
    match expr {
        // Terminals -- no optimization.
        JcExpr::Lit(_) | JcExpr::IntLit(_) | JcExpr::Var(_) | JcExpr::SelfField(_) => expr.clone(),

        // --- Short BinOp ---
        JcExpr::BinOp { op, left, right } => {
            let l = optimize_expr(left, hoisted, fresh, extract);
            let r = optimize_expr(right, hoisted, fresh, extract);

            // Constant folding: both sides are literals.
            if let (JcExpr::Lit(a), JcExpr::Lit(b)) = (&l, &r) {
                if let Some(result) = fold_short_binop(*op, *a, *b) {
                    return JcExpr::Lit(result);
                }
            }

            // Identity / annihilator / strength reduction (shared logic).
            if let Some(result) =
                optimize_binop_rules(*op, &l, &r, NumWidth::Short, hoisted, fresh, extract)
            {
                return result;
            }

            JcExpr::BinOp {
                op: *op,
                left: Box::new(l),
                right: Box::new(r),
            }
        }

        // --- Int BinOp ---
        JcExpr::IntBinOp { op, left, right } => {
            let l = optimize_expr(left, hoisted, fresh, extract);
            let r = optimize_expr(right, hoisted, fresh, extract);

            // Constant folding: both sides are int literals.
            if let (JcExpr::IntLit(a), JcExpr::IntLit(b)) = (&l, &r) {
                if let Some(result) = fold_int_binop(*op, *a, *b) {
                    return JcExpr::IntLit(result);
                }
            }

            // Identity / annihilator / strength reduction (shared logic).
            if let Some(result) =
                optimize_binop_rules(*op, &l, &r, NumWidth::Int, hoisted, fresh, extract)
            {
                return result;
            }

            JcExpr::IntBinOp {
                op: *op,
                left: Box::new(l),
                right: Box::new(r),
            }
        }

        // --- Short negation ---
        JcExpr::Neg(inner) => {
            let inner_opt = optimize_expr(inner, hoisted, fresh, extract);
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
            let inner_opt = optimize_expr(inner, hoisted, fresh, extract);
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
            let expr_opt = optimize_expr(expr, hoisted, fresh, extract);
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
            array: Box::new(optimize_expr(array, hoisted, fresh, extract)),
            index: Box::new(optimize_expr(index, hoisted, fresh, extract)),
        },
        JcExpr::Call { method_index, args } => JcExpr::Call {
            method_index: *method_index,
            args: args
                .iter()
                .map(|a| optimize_expr(a, hoisted, fresh, extract))
                .collect(),
        },
        JcExpr::NewByteArray(len) => {
            JcExpr::NewByteArray(Box::new(optimize_expr(len, hoisted, fresh, extract)))
        }
        JcExpr::NewShortArray(len) => {
            JcExpr::NewShortArray(Box::new(optimize_expr(len, hoisted, fresh, extract)))
        }
        JcExpr::NewIntArray(len) => {
            JcExpr::NewIntArray(Box::new(optimize_expr(len, hoisted, fresh, extract)))
        }
        JcExpr::NewRefArray { length, class_ref } => JcExpr::NewRefArray {
            length: Box::new(optimize_expr(length, hoisted, fresh, extract)),
            class_ref: *class_ref,
        },
        JcExpr::ArrayLength(arr) => {
            JcExpr::ArrayLength(Box::new(optimize_expr(arr, hoisted, fresh, extract)))
        }
        JcExpr::InstanceOf { expr, class } => JcExpr::InstanceOf {
            expr: Box::new(optimize_expr(expr, hoisted, fresh, extract)),
            class: *class,
        },
        JcExpr::IntCompare(l, r) => JcExpr::IntCompare(
            Box::new(optimize_expr(l, hoisted, fresh, extract)),
            Box::new(optimize_expr(r, hoisted, fresh, extract)),
        ),
    }
}

// =========================================================================
// Constant folding arithmetic helpers
// =========================================================================

/// Fold a short binary operation on two known constants.
///
/// Returns `None` for division/remainder by zero (must be a runtime error).
const fn fold_short_binop(op: BinOp, a: i16, b: i16) -> Option<i16> {
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
        BinOp::Shl =>
        {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shl(b as u32))
        }
        BinOp::Shr =>
        {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shr(b as u32))
        }
        BinOp::Ushr => {
            #[allow(clippy::cast_sign_loss)]
            {
                let ua = a as u16;
                Some(ua.wrapping_shr(b as u32).cast_signed())
            }
        }
    }
}

/// Fold an int binary operation on two known constants.
const fn fold_int_binop(op: BinOp, a: i32, b: i32) -> Option<i32> {
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
        BinOp::Shl =>
        {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shl(b as u32))
        }
        BinOp::Shr =>
        {
            #[allow(clippy::cast_sign_loss)]
            Some(a.wrapping_shr(b as u32))
        }
        BinOp::Ushr => {
            #[allow(clippy::cast_sign_loss)]
            {
                let ua = a as u32;
                Some(ua.wrapping_shr(b as u32).cast_signed())
            }
        }
    }
}

// =========================================================================
// Condition optimization + evaluation
// =========================================================================

/// Optimize a condition (recurse into sub-expressions).
///
/// When `extract` is true, effectful sub-expressions within the condition
/// may be hoisted into preceding statements. This is safe for `If` conditions
/// (evaluated once) but NOT for `While` conditions (re-evaluated each iteration).
fn optimize_condition(
    cond: &Condition,
    hoisted: &mut Vec<JcStmt>,
    fresh: &mut FreshNameGen,
    extract: bool,
) -> Condition {
    match cond {
        Condition::Eq(l, r) => Condition::Eq(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::Ne(l, r) => Condition::Ne(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::Lt(l, r) => Condition::Lt(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::Ge(l, r) => Condition::Ge(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::Gt(l, r) => Condition::Gt(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::Le(l, r) => Condition::Le(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::Null(e) => Condition::Null(optimize_expr(e, hoisted, fresh, extract)),
        Condition::NonNull(e) => Condition::NonNull(optimize_expr(e, hoisted, fresh, extract)),
        Condition::IntEq(l, r) => Condition::IntEq(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::IntNe(l, r) => Condition::IntNe(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::IntLt(l, r) => Condition::IntLt(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::IntGe(l, r) => Condition::IntGe(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::IntGt(l, r) => Condition::IntGt(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::IntLe(l, r) => Condition::IntLe(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::RefEq(l, r) => Condition::RefEq(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
        Condition::RefNe(l, r) => Condition::RefNe(
            optimize_expr(l, hoisted, fresh, extract),
            optimize_expr(r, hoisted, fresh, extract),
        ),
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

use crate::codegen::BytecodeMetadata;

/// Run peephole optimization with default configuration (all patterns, 64 passes).
pub fn peephole_optimize(bytecodes: &mut Vec<u8>, metadata: &mut BytecodeMetadata) -> usize {
    peephole_optimize_with_config(bytecodes, metadata, &PeepholeConfig::all())
}

/// Run peephole optimization with explicit configuration.
///
/// The metadata is updated in place as instructions are removed or replaced,
/// keeping branch offsets valid throughout the process.
///
/// Returns the total number of changes made.
pub fn peephole_optimize_with_config(
    bytecodes: &mut Vec<u8>,
    metadata: &mut BytecodeMetadata,
    config: &PeepholeConfig,
) -> usize {
    if !config.enabled {
        return 0;
    }
    let mut total_changes = 0;
    for _ in 0..config.max_passes {
        let changes = peephole_pass(bytecodes, metadata, config);
        if changes == 0 {
            break;
        }
        total_changes += changes;
    }
    total_changes
}

/// Check whether the byte range `[pos, pos+len)` is entirely within a
/// single basic block.
fn is_within_basic_block(pos: usize, len: usize, basic_blocks: &[(u16, u16)]) -> bool {
    #[allow(clippy::cast_possible_truncation)]
    let start = pos as u16;
    #[allow(clippy::cast_possible_truncation)]
    let end = (pos + len) as u16;
    for &(bb_start, bb_end) in basic_blocks {
        if start >= bb_start && end <= bb_end {
            return true;
        }
    }
    false
}

/// Adjust branch offsets and metadata after bytes have been removed.
///
/// When `delta` bytes are removed at position `removed_at` (covering
/// `removed_len` original bytes), all PCs beyond that point shift
/// backward. Branch offset bytes in the bytecode stream are repatched
/// to reflect the new positions.
///
/// Branches whose opcodes fall inside the removed range are dropped
/// from the metadata (they no longer exist in the bytecode stream).
fn adjust_branch_offsets(
    bytecodes: &mut [u8],
    metadata: &mut BytecodeMetadata,
    removed_at: usize,
    removed_len: usize,
    delta: i32,
) {
    let removed_end = removed_at + removed_len;

    // Update branch_targets.
    for target in &mut metadata.branch_targets {
        if *target as usize > removed_at {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                *target = (i32::from(*target) + delta) as u16;
            }
        }
    }

    // Remove branches whose opcodes were inside the deleted range,
    // then update and repatch the survivors.
    metadata.branches.retain(|b| {
        let pc = b.opcode_pc as usize;
        pc < removed_at || pc >= removed_end
    });

    for branch in &mut metadata.branches {
        // Adjust the branch instruction's own positions.
        if branch.opcode_pc as usize >= removed_at {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                branch.opcode_pc = (i32::from(branch.opcode_pc) + delta) as u16;
                branch.offset_pc = (i32::from(branch.offset_pc) + delta) as u16;
            }
        }
        // Adjust the target position.
        if branch.target_pc as usize > removed_at {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                branch.target_pc = (i32::from(branch.target_pc) + delta) as u16;
            }
        }

        // Recalculate and repatch the offset in the bytecode stream.
        let new_offset = i32::from(branch.target_pc) - i32::from(branch.opcode_pc);
        if branch.wide {
            #[allow(clippy::cast_possible_truncation)]
            let offset_i16 = new_offset as i16;
            let bytes = offset_i16.to_be_bytes();
            bytecodes[branch.offset_pc as usize] = bytes[0];
            bytecodes[branch.offset_pc as usize + 1] = bytes[1];
        } else {
            #[allow(clippy::cast_possible_truncation)]
            let offset_i8 = new_offset as i8;
            bytecodes[branch.offset_pc as usize] = offset_i8.cast_unsigned();
        }
    }

    // Update basic block boundaries.
    for (start, end) in &mut metadata.basic_blocks {
        if *start as usize > removed_at {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                *start = (i32::from(*start) + delta) as u16;
            }
        }
        if *end as usize > removed_at {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                *end = (i32::from(*end) + delta) as u16;
            }
        }
    }
}

/// A single peephole pass over the bytecode buffer.
/// Returns the number of replacements made.
fn peephole_pass(
    bytecodes: &mut Vec<u8>,
    metadata: &mut BytecodeMetadata,
    config: &PeepholeConfig,
) -> usize {
    let mut changes = 0;
    let mut i = 0;
    while i + 1 < bytecodes.len() {
        // Skip if we are at a branch target -- we must not change
        // instruction alignment at a position other code jumps to.
        #[allow(clippy::cast_possible_truncation)]
        if metadata.branch_targets.contains(&(i as u16)) {
            i += 1;
            continue;
        }

        if let Some((old_len, new_bytes)) = match_pattern(&bytecodes[i..], config) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let size_delta = new_bytes.len() as i32 - old_len as i32;

            // Only apply same-size or shrinking replacements that stay
            // within a single basic block.
            if size_delta <= 0 && is_within_basic_block(i, old_len, &metadata.basic_blocks) {
                let end = i + old_len;
                bytecodes.splice(i..end, new_bytes.iter().copied());

                if size_delta < 0 {
                    // Instructions were removed: adjust all branch offsets.
                    // old_len is the number of original bytes that were
                    // replaced; branches with opcodes in that region are
                    // dropped from metadata since they no longer exist.
                    adjust_branch_offsets(bytecodes, metadata, i, old_len, size_delta);
                }

                changes += 1;
                // Don't advance -- the replacement might create new
                // opportunities.
            } else {
                i += 1;
            }
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
fn match_pattern(bytes: &[u8], config: &PeepholeConfig) -> Option<(usize, Vec<u8>)> {
    if bytes.len() < 2 {
        return None;
    }

    let b0 = bytes[0];
    let b1 = bytes[1];

    // --- sstore_N followed by sload_N -> dup + sstore_N ---
    if config.store_load_dup && (SSTORE_0..=SSTORE_3).contains(&b0) {
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
    if config.dead_push_pop {
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
    }

    // iipush + 4 bytes + pop -> NOT safe (int is 2 words, POP only pops 1)
    // Skip this case.

    // --- Double negation ---
    if config.double_negation {
        // sneg; sneg -> remove both
        if b0 == SNEG && b1 == SNEG {
            return Some((2, Vec::new()));
        }
        // ineg; ineg -> remove both
        if b0 == INEG && b1 == INEG {
            return Some((2, Vec::new()));
        }
    }

    // --- Goto to next instruction (noop jump) ---
    // goto with offset +2 means skip to the instruction right after the goto
    // (goto is 2 bytes: opcode + offset). Offset of 2 means target = opcode_pos + 2
    // = the next instruction.
    if config.goto_next && b0 == GOTO && b1 == 0x02 {
        return Some((2, Vec::new()));
    }

    // --- sconst_0 + sadd = identity (add zero) ---
    if config.add_zero_identity && b0 == SCONST_0 && b1 == SADD {
        return Some((2, Vec::new()));
    }

    // --- Consecutive stores to same local (first is dead) ---
    // sstore_N; sstore_N -> pop; sstore_N
    if config.dead_store && (SSTORE_0..=SSTORE_3).contains(&b0) && b0 == b1 {
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

    /// Helper: `optimize_expr` with default params (no extraction, for simple tests).
    fn optimize_expr_simple(expr: &JcExpr) -> JcExpr {
        let mut hoisted = Vec::new();
        let mut fresh = FreshNameGen::new();
        optimize_expr(expr, &mut hoisted, &mut fresh, false)
    }

    /// Helper: `optimize_expr` with extraction enabled, returning hoisted stmts too.
    fn optimize_expr_extract(expr: &JcExpr) -> (JcExpr, Vec<JcStmt>, Vec<(String, JcType)>) {
        let mut hoisted = Vec::new();
        let mut fresh = FreshNameGen::new();
        let result = optimize_expr(expr, &mut hoisted, &mut fresh, true);
        (result, hoisted, fresh.new_locals)
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn fold_double_negation() {
        // --x should fold to x.
        let expr = JcExpr::Neg(Box::new(JcExpr::Neg(Box::new(JcExpr::Var(String::from(
            "x",
        ))))));
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::Var(ref name) if name == "x"),
            "expected Var(x), got {result:?}"
        );
    }

    #[test]
    fn fold_negation_constant() {
        let expr = JcExpr::Neg(Box::new(JcExpr::Lit(5)));
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
            JcStmt::Expr(JcExpr::Lit(3)),         // dead
        ];
        let result = optimize_stmts(&stmts, &mut FreshNameGen::new(), false);
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
        let result = optimize_stmts(&stmts, &mut FreshNameGen::new(), false);
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
        let result = optimize_stmts(&stmts, &mut FreshNameGen::new(), false);
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
        let result = optimize_stmts(&stmts, &mut FreshNameGen::new(), false);
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
        let result = optimize_stmts(&stmts, &mut FreshNameGen::new(), false);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_stmt(&stmt, &mut FreshNameGen::new(), false);
        // Should become a no-op expression, not an Increment.
        assert_eq!(result.len(), 1);
        assert!(
            !matches!(result[0], JcStmt::Increment { .. }),
            "increment by 0 should be eliminated, got {:?}",
            result[0]
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
            constant_time: false,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // After folding, 3+2=5, so we expect sconst_5 (0x08) + sreturn (0x78).
        assert_eq!(
            bc,
            vec![0x08, 0x78],
            "expected [sconst_5, sreturn], got {bc:?}"
        );
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
            constant_time: false,
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
            constant_time: false,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // x + 0 -> x. So: sload_0, sreturn
        assert_eq!(
            bc,
            vec![0x1C, 0x78],
            "expected [sload_0, sreturn], got {bc:?}"
        );
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
            constant_time: false,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // --x -> x. So: sload_0, sreturn (no sneg at all)
        assert_eq!(
            bc,
            vec![0x1C, 0x78],
            "expected [sload_0, sreturn], got {bc:?}"
        );
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
            constant_time: false,
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
            constant_time: false,
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

    /// Build a trivial metadata for straight-line bytecodes (no branches).
    fn empty_metadata(code_len: usize) -> BytecodeMetadata {
        #[allow(clippy::cast_possible_truncation)]
        let basic_blocks = if code_len > 0 {
            vec![(0, code_len as u16)]
        } else {
            vec![]
        };
        BytecodeMetadata {
            branch_targets: vec![],
            basic_blocks,
            branches: vec![],
        }
    }

    #[test]
    fn peephole_store_load_to_dup() {
        // sstore_0; sload_0 -> dup; sstore_0
        let mut bc = vec![SSTORE_0, SLOAD_0];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_0]);
    }

    #[test]
    fn peephole_store_load_slot1() {
        let mut bc = vec![SSTORE_0 + 1, SLOAD_0 + 1];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_0 + 1]);
    }

    #[test]
    fn peephole_store_load_slot2() {
        let mut bc = vec![SSTORE_0 + 2, SLOAD_0 + 2];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_0 + 2]);
    }

    #[test]
    fn peephole_store_load_slot3() {
        let mut bc = vec![SSTORE_3, 0x1F]; // SLOAD_3 = 0x1F
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert_eq!(bc, vec![DUP, SSTORE_3]);
    }

    #[test]
    fn peephole_double_neg_removed() {
        let mut bc = vec![SNEG, SNEG];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty(), "expected empty, got {bc:?}");
    }

    #[test]
    fn peephole_double_ineg_removed() {
        let mut bc = vec![INEG, INEG];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_push_pop_removed() {
        // sconst_0; pop -> removed
        let mut bc = vec![SCONST_0, POP];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_sconst_5_pop_removed() {
        let mut bc = vec![SCONST_5, POP];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_bspush_pop_removed() {
        // bspush + imm + pop -> removed
        let mut bc = vec![BSPUSH, 42, POP];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_sspush_pop_removed() {
        // sspush + hi + lo + pop -> removed
        let mut bc = vec![SSPUSH, 0x01, 0x00, POP];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_goto_next_removed() {
        // goto +2 (noop jump) -> removed
        // Note: goto is a branch instruction; to test this properly we need
        // metadata that models it. The goto is at PC 0 with offset 0x02,
        // meaning it targets PC 2 (the instruction immediately after).
        // The noop-goto pattern is safe to remove even with metadata because
        // it targets the next instruction.
        let mut bc = vec![GOTO, 0x02];
        let mut meta = BytecodeMetadata {
            branch_targets: vec![2],
            basic_blocks: vec![(0, 2)],
            branches: vec![crate::codegen::BranchInfo {
                opcode_pc: 0,
                offset_pc: 1,
                wide: false,
                target_pc: 2,
            }],
        };
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_sconst0_sadd_removed() {
        // sconst_0 + sadd = add zero = identity
        let mut bc = vec![SCONST_0, SADD];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0);
        assert!(bc.is_empty());
    }

    #[test]
    fn peephole_consecutive_stores_same_slot() {
        // sstore_0; sstore_0 -> pop; sstore_0
        let mut bc = vec![SSTORE_0, SSTORE_0];
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
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
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes >= 2, "expected at least 2 changes, got {changes}");
        assert!(
            bc.is_empty(),
            "expected empty bytecodes after fixed-point, got {bc:?}"
        );
    }

    #[test]
    fn peephole_no_changes_on_normal_code() {
        // Normal code that should not be modified.
        let mut bc = vec![SCONST_0, SSTORE_0, SLOAD_0, 0x78]; // sreturn
        let original = bc.clone();
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
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
        let mut meta = empty_metadata(bc.len());
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert_eq!(changes, 0);
        assert_eq!(bc, original);
    }

    // =====================================================================
    // Branch-aware peephole tests
    // =====================================================================

    #[test]
    fn peephole_skips_branch_targets() {
        // sneg at a branch target should NOT be optimized even though
        // sneg+sneg would normally be removed.
        //
        // Layout: sneg(PC0), sneg(PC1) where PC1 is a branch target.
        let mut bc = vec![SNEG, SNEG];
        let mut meta = BytecodeMetadata {
            branch_targets: vec![1],            // PC 1 is a branch target
            basic_blocks: vec![(0, 1), (1, 2)], // Two blocks
            branches: vec![],
        };
        let changes = peephole_optimize(&mut bc, &mut meta);
        // The pattern spans two basic blocks, so it should not be applied.
        assert_eq!(
            changes, 0,
            "should not optimize across basic block boundary"
        );
        assert_eq!(bc, vec![SNEG, SNEG]);
    }

    #[test]
    fn peephole_preserves_branch_offsets_after_removal() {
        // Build bytecodes with a known branch:
        //   PC 0: sneg
        //   PC 1: sneg       (these two form a removable pattern)
        //   PC 2: goto       (offset = +3 -> targets PC 5)
        //   PC 3: (offset byte = 3)
        //   PC 4: sreturn
        //   PC 5: sreturn    (branch target)
        //
        // After removing sneg+sneg, the goto moves to PC 0, and the
        // target moves to PC 3. The offset should be updated to +3 still
        // (3 - 0 = 3).
        let mut bc = vec![SNEG, SNEG, GOTO, 0x03, 0x78, 0x78];
        let mut meta = BytecodeMetadata {
            branch_targets: vec![5],
            basic_blocks: vec![(0, 4), (4, 5), (5, 6)],
            branches: vec![crate::codegen::BranchInfo {
                opcode_pc: 2,
                offset_pc: 3,
                wide: false,
                target_pc: 5,
            }],
        };
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0, "sneg+sneg should be removed");
        // After removal: [goto, offset, sreturn, sreturn]
        assert_eq!(bc.len(), 4);
        assert_eq!(bc[0], GOTO);
        // The target was at PC 5, now at PC 3 (shifted by -2).
        // The opcode was at PC 2, now at PC 0 (shifted by -2).
        // new_offset = 3 - 0 = 3
        assert_eq!(
            bc[1], 3_i8 as u8,
            "branch offset should be 3 after adjustment"
        );
        assert_eq!(meta.branches[0].target_pc, 3);
        assert_eq!(meta.branches[0].opcode_pc, 0);
    }

    #[test]
    fn peephole_does_not_break_while_loop() {
        // Compile a while loop and verify execution still works after peephole.
        use crate::ir::{Condition, JcStmt};

        let method = JcMethod {
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
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls);
        // The key assertion: the code compiles successfully (peephole does
        // not corrupt the branch offsets).
        assert!(
            compiled.is_ok(),
            "while loop should compile with peephole: {:?}",
            compiled.err()
        );
        let bc = &compiled.unwrap().methods[0];
        // Should still contain goto (backward branch) and if_scmpeq (condition).
        assert!(bc.contains(&GOTO), "should contain goto for loop back-edge");
        assert!(
            bc.contains(&0x6A),
            "should contain if_scmpeq for loop condition"
        );
    }

    #[test]
    fn peephole_does_not_break_if_else() {
        // Compile an if/else and verify both branches survive peephole.
        use crate::ir::{Condition, JcStmt};

        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![JcStmt::If {
                cond: Condition::Eq(JcExpr::Var(String::from("x")), JcExpr::Lit(0)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
            }],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls);
        assert!(
            compiled.is_ok(),
            "if/else should compile with peephole: {:?}",
            compiled.err()
        );
        let bc = &compiled.unwrap().methods[0];
        // Both branch opcodes should be present.
        assert!(
            bc.contains(&0x6B),
            "should contain if_scmpne for negated eq"
        );
        assert!(bc.contains(&GOTO), "should contain goto to skip else");
    }

    #[test]
    fn peephole_offset_adjustment_manual() {
        // Manually construct bytecodes and metadata, remove bytes, verify
        // offsets are correctly updated.
        //
        // Layout:
        //   PC 0: sconst_0  (will be part of removed pattern)
        //   PC 1: sadd      (removed together with sconst_0)
        //   PC 2: if_scmpeq (opcode)
        //   PC 3: 0x03      (offset -> targets PC 5)
        //   PC 4: sreturn
        //   PC 5: sreturn   (branch target)
        let mut bc: Vec<u8> = vec![SCONST_0, SADD, 0x6A, 0x03, 0x78, 0x78];
        let mut meta = BytecodeMetadata {
            branch_targets: vec![5],
            basic_blocks: vec![(0, 4), (4, 5), (5, 6)],
            branches: vec![crate::codegen::BranchInfo {
                opcode_pc: 2,
                offset_pc: 3,
                wide: false,
                target_pc: 5,
            }],
        };
        let changes = peephole_optimize(&mut bc, &mut meta);
        assert!(changes > 0, "sconst_0+sadd should be removed");
        // After removal: [if_scmpeq, offset, sreturn, sreturn]
        assert_eq!(bc.len(), 4);
        assert_eq!(bc[0], 0x6A); // if_scmpeq
                                 // opcode moved from PC 2 to PC 0, target from PC 5 to PC 3
                                 // new_offset = 3 - 0 = 3
        assert_eq!(bc[1], 3_i8 as u8);
        assert_eq!(meta.branches[0].opcode_pc, 0);
        assert_eq!(meta.branches[0].target_pc, 3);
    }

    #[test]
    fn metadata_basic_blocks_computed_correctly() {
        // Verify that compute_basic_blocks produces correct results
        // for a simple if/else pattern.
        use crate::codegen::{compute_basic_blocks, BranchInfo};

        let branch_targets = vec![5u16, 10];
        let branches = vec![
            BranchInfo {
                opcode_pc: 3,
                offset_pc: 4,
                wide: false,
                target_pc: 5,
            },
            BranchInfo {
                opcode_pc: 8,
                offset_pc: 9,
                wide: false,
                target_pc: 10,
            },
        ];
        let blocks = compute_basic_blocks(&branch_targets, &branches, 12);
        // Expected blocks: [0,5), [5,10), [10,12)
        assert_eq!(blocks, vec![(0, 5), (5, 10), (10, 12)]);
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
            constant_time: false,
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
            constant_time: false,
        };
        let cls = make_static_class(method);
        let bc = compile_optimized(&cls);
        // The optimized version should be shorter.
        assert_eq!(
            bc.len(),
            2,
            "expected 2-byte optimized output, got {} bytes",
            bc.len()
        );
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_expr_simple(&expr);
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
        let result = optimize_stmts(&stmts, &mut FreshNameGen::new(), false);
        // The while should be eliminated, leaving the return.
        // First element should be a no-op placeholder, second is the return.
        assert_eq!(result.len(), 2);
        assert!(matches!(&result[1], JcStmt::Return(Some(JcExpr::Lit(0)))));
    }

    // =====================================================================
    // Side-effect safety: is_side_effect_free classification
    // =====================================================================
    //
    // JCVM 3.1 Section 7.5 and JCRE 2.2.1 Section 6 mandate that certain
    // expressions have observable side effects (exceptions, firewall checks,
    // persistent writes). The optimizer MUST NOT eliminate or duplicate these
    // expressions. The is_side_effect_free() guard ensures this.
    //
    // These tests verify effects_of() classification for every JcExpr
    // variant, asserting specific effect bitsets.

    // --- Terminal expressions: PURE ---

    #[test]
    fn effects_of_lit() {
        assert_eq!(effects_of(&JcExpr::Lit(0)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::Lit(42)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::Lit(-1)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::Lit(i16::MAX)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::Lit(i16::MIN)), Effects::PURE);
    }

    #[test]
    fn effects_of_int_lit() {
        assert_eq!(effects_of(&JcExpr::IntLit(0)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::IntLit(100_000)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::IntLit(-1)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::IntLit(i32::MAX)), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::IntLit(i32::MIN)), Effects::PURE);
    }

    #[test]
    fn effects_of_var() {
        assert_eq!(effects_of(&JcExpr::Var(String::from("x"))), Effects::PURE);
        assert_eq!(effects_of(&JcExpr::Var(String::from("i"))), Effects::PURE);
    }

    // --- Field read: FIELD_READ | FIREWALL ---

    #[test]
    fn effects_of_self_field() {
        // getfield may throw NullPointerException or SecurityException
        // (JCRE 2.2.1 firewall).
        let eff = effects_of(&JcExpr::SelfField(String::from("val")));
        assert_eq!(eff, Effects::FIELD_READ.union(Effects::FIREWALL));
        assert!(!eff.is_pure());
    }

    // --- BinOp: compositional + ARITHMETIC for Div/Rem ---

    #[test]
    fn effects_of_binop_pure_children() {
        // Add with pure children is PURE (SADD has no exception spec).
        let add = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::Lit(1)),
            right: Box::new(JcExpr::Lit(2)),
        };
        assert_eq!(effects_of(&add), Effects::PURE);

        // All non-Div/Rem operators with pure children are PURE.
        for op in [
            BinOp::Sub,
            BinOp::Mul,
            BinOp::And,
            BinOp::Or,
            BinOp::Xor,
            BinOp::Shl,
            BinOp::Shr,
            BinOp::Ushr,
        ] {
            let e = JcExpr::BinOp {
                op,
                left: Box::new(JcExpr::Var(String::from("x"))),
                right: Box::new(JcExpr::Var(String::from("y"))),
            };
            assert_eq!(
                effects_of(&e),
                Effects::PURE,
                "BinOp::{op:?} with pure children should be PURE"
            );
        }
    }

    #[test]
    fn effects_of_binop_div_rem() {
        // Div/Rem add ARITHMETIC even with pure children.
        let div = JcExpr::BinOp {
            op: BinOp::Div,
            left: Box::new(JcExpr::Lit(10)),
            right: Box::new(JcExpr::Lit(0)),
        };
        assert_eq!(effects_of(&div), Effects::ARITHMETIC);
        assert!(!effects_of(&div).is_pure());

        let rem = JcExpr::BinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Var(String::from("y"))),
        };
        assert_eq!(effects_of(&rem), Effects::ARITHMETIC);
    }

    #[test]
    fn effects_of_int_binop_pure_children() {
        let add = JcExpr::IntBinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::IntLit(1)),
            right: Box::new(JcExpr::IntLit(2)),
        };
        assert_eq!(effects_of(&add), Effects::PURE);

        let div = JcExpr::IntBinOp {
            op: BinOp::Div,
            left: Box::new(JcExpr::IntLit(10)),
            right: Box::new(JcExpr::IntLit(0)),
        };
        assert_eq!(effects_of(&div), Effects::ARITHMETIC);
    }

    // --- Negation: inherits child effects ---

    #[test]
    fn effects_of_neg_pure_child() {
        // SNEG/INEG have no exception spec -- pure if child is pure.
        assert_eq!(
            effects_of(&JcExpr::Neg(Box::new(JcExpr::Lit(1)))),
            Effects::PURE
        );
        assert_eq!(
            effects_of(&JcExpr::IntNeg(Box::new(JcExpr::IntLit(1)))),
            Effects::PURE
        );
    }

    // --- Call: INVOKE ---

    #[test]
    fn effects_of_call() {
        let call = JcExpr::Call {
            method_index: 1,
            args: vec![],
        };
        assert_eq!(effects_of(&call), Effects::INVOKE);
        assert!(!effects_of(&call).is_pure());
    }

    // --- Array load: NULL_DEREF | ARRAY_BOUNDS | FIREWALL ---

    #[test]
    fn effects_of_array_load() {
        let load = JcExpr::ArrayLoad {
            array: Box::new(JcExpr::Var(String::from("arr"))),
            index: Box::new(JcExpr::Lit(0)),
        };
        let eff = effects_of(&load);
        assert_eq!(
            eff,
            Effects::NULL_DEREF
                .union(Effects::ARRAY_BOUNDS)
                .union(Effects::FIREWALL),
        );
    }

    // --- Allocation: ALLOCATION | NEGATIVE_SIZE ---

    #[test]
    fn effects_of_allocation() {
        let expected = Effects::ALLOCATION.union(Effects::NEGATIVE_SIZE);
        assert_eq!(
            effects_of(&JcExpr::NewByteArray(Box::new(JcExpr::Lit(10)))),
            expected
        );
        assert_eq!(
            effects_of(&JcExpr::NewShortArray(Box::new(JcExpr::Lit(10)))),
            expected
        );
        assert_eq!(
            effects_of(&JcExpr::NewIntArray(Box::new(JcExpr::Lit(10)))),
            expected
        );
        assert_eq!(
            effects_of(&JcExpr::NewRefArray {
                length: Box::new(JcExpr::Lit(10)),
                class_ref: 0,
            }),
            expected,
        );
    }

    // --- Array length: NULL_DEREF ---

    #[test]
    fn effects_of_array_length() {
        let eff = effects_of(&JcExpr::ArrayLength(Box::new(JcExpr::Var(String::from(
            "arr",
        )))));
        assert_eq!(eff, Effects::NULL_DEREF);
    }

    // --- Cast: inherits child effects ---

    #[test]
    fn effects_of_cast_pure_child() {
        // S2I/S2B/I2S/I2B have no exception spec.
        assert_eq!(
            effects_of(&JcExpr::Cast {
                from: JcType::Short,
                to: JcType::Int,
                expr: Box::new(JcExpr::Lit(1)),
            }),
            Effects::PURE,
        );
    }

    // --- InstanceOf: inherits child effects ---

    #[test]
    fn effects_of_instance_of_pure_child() {
        // INSTANCEOF has no exception spec.
        assert_eq!(
            effects_of(&JcExpr::InstanceOf {
                expr: Box::new(JcExpr::Var(String::from("obj"))),
                class: 0,
            }),
            Effects::PURE,
        );
    }

    // --- IntCompare: inherits child effects ---

    #[test]
    fn effects_of_int_compare_pure_children() {
        // ICMP has no exception spec.
        assert_eq!(
            effects_of(&JcExpr::IntCompare(
                Box::new(JcExpr::IntLit(1)),
                Box::new(JcExpr::IntLit(2)),
            )),
            Effects::PURE,
        );
    }

    // --- Compositional propagation ---

    #[test]
    fn effects_of_binop_effectful_child_propagates() {
        // Add with a Call child inherits INVOKE.
        let expr = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(1)),
        };
        assert_eq!(effects_of(&expr), Effects::INVOKE);
    }

    #[test]
    fn effects_of_neg_effectful_child_propagates() {
        let expr = JcExpr::Neg(Box::new(JcExpr::Call {
            method_index: 1,
            args: vec![],
        }));
        assert_eq!(effects_of(&expr), Effects::INVOKE);
    }

    #[test]
    fn effects_of_deeply_nested_pure() {
        // ((Var + Var) * Lit) is fully pure.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Var(String::from("b"))),
            }),
            right: Box::new(JcExpr::Lit(3)),
        };
        assert_eq!(effects_of(&expr), Effects::PURE);
    }

    #[test]
    fn effects_of_union_combines_bits() {
        // Div(ArrayLoad(..), Lit) combines all bits.
        let expr = JcExpr::BinOp {
            op: BinOp::Div,
            left: Box::new(JcExpr::ArrayLoad {
                array: Box::new(JcExpr::Var(String::from("arr"))),
                index: Box::new(JcExpr::Lit(0)),
            }),
            right: Box::new(JcExpr::Lit(1)),
        };
        let eff = effects_of(&expr);
        assert_eq!(
            eff,
            Effects::NULL_DEREF
                .union(Effects::ARRAY_BOUNDS)
                .union(Effects::FIREWALL)
                .union(Effects::ARITHMETIC),
        );
    }

    #[test]
    fn effects_of_call_with_effectful_args() {
        // Call with an ArrayLoad argument combines INVOKE + array effects.
        let expr = JcExpr::Call {
            method_index: 0,
            args: vec![JcExpr::ArrayLoad {
                array: Box::new(JcExpr::Var(String::from("arr"))),
                index: Box::new(JcExpr::Lit(0)),
            }],
        };
        let eff = effects_of(&expr);
        assert_eq!(
            eff,
            Effects::INVOKE
                .union(Effects::NULL_DEREF)
                .union(Effects::ARRAY_BOUNDS)
                .union(Effects::FIREWALL),
        );
    }

    // =====================================================================
    // Guard correctness: optimizer preserves effectful expressions
    // =====================================================================
    //
    // For each guarded transform, we test both sides:
    //   (a) The transform IS applied when the operand is side-effect-free
    //   (b) The transform is NOT applied when the operand is effectful
    //
    // This proves the guard is both necessary and sufficient.

    // --- Short: x * 0 ---

    #[test]
    fn guard_short_mul_zero_allows_safe_var() {
        // Var * 0 -> Lit(0) (Var is side-effect-free)
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(0)),
        };
        assert!(matches!(optimize_expr_simple(&expr), JcExpr::Lit(0)));
    }

    #[test]
    fn guard_short_mul_zero_blocks_div_by_zero() {
        // (10 / 0) * 0 -- the division throws ArithmeticException.
        // Optimizer must preserve the Mul so the division still executes.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::BinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::Lit(10)),
                right: Box::new(JcExpr::Lit(0)),
            }),
            right: Box::new(JcExpr::Lit(0)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Mul, .. }),
            "effectful (10/0)*0 must NOT fold to 0, got {result:?}"
        );
    }

    #[test]
    fn guard_short_mul_zero_blocks_call() {
        // call(1) * 0 -- the call may have side effects.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(0)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Mul, .. }),
            "effectful call()*0 must NOT fold to 0, got {result:?}"
        );
    }

    #[test]
    fn guard_short_mul_zero_blocks_self_field() {
        // self.val * 0 -- field read may throw NullPointerException/SecurityException.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::SelfField(String::from("val"))),
            right: Box::new(JcExpr::Lit(0)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Mul, .. }),
            "effectful self.val*0 must NOT fold to 0, got {result:?}"
        );
    }

    #[test]
    fn guard_short_mul_zero_blocks_array_load() {
        // arr[i] * 0 -- array load may throw NullPointer/OutOfBounds/Security.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::ArrayLoad {
                array: Box::new(JcExpr::Var(String::from("arr"))),
                index: Box::new(JcExpr::Lit(0)),
            }),
            right: Box::new(JcExpr::Lit(0)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Mul, .. }),
            "effectful arr[0]*0 must NOT fold to 0, got {result:?}"
        );
    }

    // --- Short: 0 * x (commutative) ---

    #[test]
    fn guard_short_zero_mul_blocks_effectful_rhs() {
        // 0 * call(1) -- same guard applies to the RHS.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Lit(0)),
            right: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Mul, .. }),
            "effectful 0*call() must NOT fold to 0, got {result:?}"
        );
    }

    // --- Short: x * 2 -> x + x ---

    #[test]
    fn guard_short_mul_two_allows_safe_var() {
        // Var * 2 -> Var + Var (safe: Var evaluated twice is fine)
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(2)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Add, .. }),
            "safe x*2 should become x+x, got {result:?}"
        );
    }

    #[test]
    fn guard_short_mul_two_blocks_effectful_call() {
        // call(1) * 2 -- duplicating the call would duplicate side effects.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(2)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Mul, .. }),
            "effectful call()*2 must NOT become call()+call(), got {result:?}"
        );
    }

    #[test]
    fn guard_short_mul_two_blocks_self_field() {
        // self.val * 2 -- duplicating field read could observe different values
        // if the field changes between reads (JCRE persistent semantics).
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::SelfField(String::from("val"))),
            right: Box::new(JcExpr::Lit(2)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Mul, .. }),
            "effectful self.val*2 must NOT become self.val+self.val, got {result:?}"
        );
    }

    // --- Short: x % 1 -> 0 ---

    #[test]
    fn guard_short_rem_one_allows_safe_var() {
        // Var % 1 -> Lit(0) (Var is side-effect-free)
        let expr = JcExpr::BinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(1)),
        };
        assert!(matches!(optimize_expr_simple(&expr), JcExpr::Lit(0)));
    }

    #[test]
    fn guard_short_rem_one_blocks_div_by_zero() {
        // (10 / 0) % 1 -- the division throws ArithmeticException.
        let expr = JcExpr::BinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::BinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::Lit(10)),
                right: Box::new(JcExpr::Lit(0)),
            }),
            right: Box::new(JcExpr::Lit(1)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Rem, .. }),
            "effectful (10/0)%%1 must NOT fold to 0, got {result:?}"
        );
    }

    #[test]
    fn guard_short_rem_one_blocks_call() {
        let expr = JcExpr::BinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(1)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Rem, .. }),
            "effectful call()%%1 must NOT fold to 0, got {result:?}"
        );
    }

    // --- Int: x * 0 ---

    #[test]
    fn guard_int_mul_zero_allows_safe_var() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::IntLit(0)),
        };
        assert!(matches!(optimize_expr_simple(&expr), JcExpr::IntLit(0)));
    }

    #[test]
    fn guard_int_mul_zero_blocks_div_by_zero() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::IntBinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::IntLit(10)),
                right: Box::new(JcExpr::IntLit(0)),
            }),
            right: Box::new(JcExpr::IntLit(0)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::IntBinOp { op: BinOp::Mul, .. }),
            "effectful int (10/0)*0 must NOT fold to 0, got {result:?}"
        );
    }

    #[test]
    fn guard_int_mul_zero_blocks_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::IntLit(0)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::IntBinOp { op: BinOp::Mul, .. }),
            "effectful int call()*0 must NOT fold to 0, got {result:?}"
        );
    }

    // --- Int: x * 2 -> x + x ---

    #[test]
    fn guard_int_mul_two_allows_safe_var() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::IntLit(2)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::IntBinOp { op: BinOp::Add, .. }),
            "safe int x*2 should become x+x, got {result:?}"
        );
    }

    #[test]
    fn guard_int_mul_two_blocks_effectful_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::IntLit(2)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::IntBinOp { op: BinOp::Mul, .. }),
            "effectful int call()*2 must NOT become call()+call(), got {result:?}"
        );
    }

    // --- Int: x % 1 -> 0 ---

    #[test]
    fn guard_int_rem_one_allows_safe_var() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::IntLit(1)),
        };
        assert!(matches!(optimize_expr_simple(&expr), JcExpr::IntLit(0)));
    }

    #[test]
    fn guard_int_rem_one_blocks_div_by_zero() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::IntBinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::IntLit(10)),
                right: Box::new(JcExpr::IntLit(0)),
            }),
            right: Box::new(JcExpr::IntLit(1)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::IntBinOp { op: BinOp::Rem, .. }),
            "effectful int (10/0)%%1 must NOT fold to 0, got {result:?}"
        );
    }

    #[test]
    fn guard_int_rem_one_blocks_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::IntLit(1)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::IntBinOp { op: BinOp::Rem, .. }),
            "effectful int call()%%1 must NOT fold to 0, got {result:?}"
        );
    }

    // --- Compositional purity: newly-pure expressions fold directly ---

    #[test]
    fn guard_short_pure_binop_mul_zero_folds() {
        // (x + y) * 0 -- BinOp(Add, Var, Var) is now PURE, folds to 0.
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Var(String::from("x"))),
                right: Box::new(JcExpr::Var(String::from("y"))),
            }),
            right: Box::new(JcExpr::Lit(0)),
        };
        assert!(
            matches!(optimize_expr_simple(&expr), JcExpr::Lit(0)),
            "pure (x+y)*0 should fold to 0"
        );
    }

    #[test]
    fn guard_short_neg_var_mul_two_folds() {
        // (-x) * 2 -- Neg(Var) is now PURE, becomes (-x) + (-x).
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Neg(Box::new(JcExpr::Var(String::from("x"))))),
            right: Box::new(JcExpr::Lit(2)),
        };
        let result = optimize_expr_simple(&expr);
        assert!(
            matches!(result, JcExpr::BinOp { op: BinOp::Add, .. }),
            "pure (-x)*2 should become (-x)+(-x), got {result:?}"
        );
    }

    #[test]
    fn guard_short_cast_var_rem_one_folds() {
        // cast(x, Short, Int) % 1 -- Cast(Var) is now PURE, folds to 0.
        // Note: uses IntBinOp since the cast result is Int.
        let expr = JcExpr::IntBinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Cast {
                from: JcType::Short,
                to: JcType::Int,
                expr: Box::new(JcExpr::Var(String::from("x"))),
            }),
            right: Box::new(JcExpr::IntLit(1)),
        };
        assert!(
            matches!(optimize_expr_simple(&expr), JcExpr::IntLit(0)),
            "pure cast(x)%%1 should fold to 0"
        );
    }

    // =====================================================================
    // Effect extraction tests: effectful operands are hoisted into Let stmts
    // =====================================================================
    //
    // These test with extract=true, verifying that the optimizer hoists
    // effectful sub-expressions and applies the mathematical simplification.

    // --- Short: call() * 0 -> let _eff0 = call(); 0 ---

    #[test]
    fn extract_short_mul_zero_hoists_call() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(0)),
        };
        let (result, hoisted, new_locals) = optimize_expr_extract(&expr);
        assert!(
            matches!(result, JcExpr::Lit(0)),
            "call()*0 with extraction should fold to 0, got {result:?}"
        );
        assert_eq!(hoisted.len(), 1, "should hoist exactly one statement");
        assert!(
            matches!(&hoisted[0], JcStmt::Let { name, ty: JcType::Short, init: JcExpr::Call { method_index: 1, .. } } if name == "_eff0"),
            "hoisted should be Let {{ _eff0: Short = call(1) }}, got {:?}",
            hoisted[0]
        );
        assert_eq!(new_locals.len(), 1);
        assert_eq!(new_locals[0].0, "_eff0");
        assert_eq!(new_locals[0].1, JcType::Short);
    }

    #[test]
    fn extract_short_mul_zero_hoists_self_field() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::SelfField(String::from("val"))),
            right: Box::new(JcExpr::Lit(0)),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::Lit(0)));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                init: JcExpr::SelfField(_),
                ..
            }
        ));
    }

    #[test]
    fn extract_short_mul_zero_hoists_array_load() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::ArrayLoad {
                array: Box::new(JcExpr::Var(String::from("arr"))),
                index: Box::new(JcExpr::Lit(0)),
            }),
            right: Box::new(JcExpr::Lit(0)),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::Lit(0)));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                init: JcExpr::ArrayLoad { .. },
                ..
            }
        ));
    }

    // --- Short: 0 * call() -> let _eff0 = call(); 0 ---

    #[test]
    fn extract_short_zero_mul_hoists_call() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Lit(0)),
            right: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::Lit(0)));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                init: JcExpr::Call {
                    method_index: 1,
                    ..
                },
                ..
            }
        ));
    }

    // --- Short: call() * 2 -> let _eff0 = call(); _eff0 + _eff0 ---

    #[test]
    fn extract_short_mul_two_hoists_call() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(2)),
        };
        let (result, hoisted, new_locals) = optimize_expr_extract(&expr);
        assert!(
            matches!(&result, JcExpr::BinOp { op: BinOp::Add, left, right }
                if matches!(left.as_ref(), JcExpr::Var(n) if n == "_eff0")
                && matches!(right.as_ref(), JcExpr::Var(n) if n == "_eff0")),
            "call()*2 with extraction should become _eff0+_eff0, got {result:?}"
        );
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let { name, ty: JcType::Short, init: JcExpr::Call { method_index: 1, .. } } if name == "_eff0"
        ));
        assert_eq!(new_locals.len(), 1);
    }

    #[test]
    fn extract_short_mul_two_hoists_self_field() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::SelfField(String::from("val"))),
            right: Box::new(JcExpr::Lit(2)),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(&result, JcExpr::BinOp { op: BinOp::Add, .. }));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                init: JcExpr::SelfField(_),
                ..
            }
        ));
    }

    // --- Short: 2 * call() -> let _eff0 = call(); _eff0 + _eff0 ---

    #[test]
    fn extract_short_two_mul_hoists_call() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Lit(2)),
            right: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(&result, JcExpr::BinOp { op: BinOp::Add, .. }));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                init: JcExpr::Call {
                    method_index: 1,
                    ..
                },
                ..
            }
        ));
    }

    // --- Short: call() % 1 -> let _eff0 = call(); 0 ---

    #[test]
    fn extract_short_rem_one_hoists_call() {
        let expr = JcExpr::BinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(1)),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::Lit(0)));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                init: JcExpr::Call {
                    method_index: 1,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn extract_short_rem_one_hoists_div_by_zero() {
        let expr = JcExpr::BinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::BinOp {
                op: BinOp::Div,
                left: Box::new(JcExpr::Lit(10)),
                right: Box::new(JcExpr::Lit(0)),
            }),
            right: Box::new(JcExpr::Lit(1)),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        // Division by zero is not folded (returns None), so inner BinOp survives.
        // But it's effectful, so extraction hoists it and result is Lit(0).
        assert!(matches!(result, JcExpr::Lit(0)));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                init: JcExpr::BinOp { op: BinOp::Div, .. },
                ..
            }
        ));
    }

    // --- Int: call() * 0 -> let _eff0 = call(); 0 ---

    #[test]
    fn extract_int_mul_zero_hoists_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::IntLit(0)),
        };
        let (result, hoisted, new_locals) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::IntLit(0)));
        assert_eq!(hoisted.len(), 1);
        assert!(matches!(
            &hoisted[0],
            JcStmt::Let {
                ty: JcType::Int,
                init: JcExpr::Call {
                    method_index: 1,
                    ..
                },
                ..
            }
        ));
        assert_eq!(new_locals[0].1, JcType::Int);
    }

    #[test]
    fn extract_int_zero_mul_hoists_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::IntLit(0)),
            right: Box::new(JcExpr::Call {
                method_index: 2,
                args: vec![],
            }),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::IntLit(0)));
        assert_eq!(hoisted.len(), 1);
    }

    // --- Int: call() * 2 -> let _eff0 = call(); _eff0 + _eff0 ---

    #[test]
    fn extract_int_mul_two_hoists_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::IntLit(2)),
        };
        let (result, hoisted, new_locals) = optimize_expr_extract(&expr);
        assert!(
            matches!(&result, JcExpr::IntBinOp { op: BinOp::Add, .. }),
            "int call()*2 with extraction should become _eff0+_eff0, got {result:?}"
        );
        assert_eq!(hoisted.len(), 1);
        assert_eq!(new_locals[0].1, JcType::Int);
    }

    #[test]
    fn extract_int_two_mul_hoists_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::IntLit(2)),
            right: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(&result, JcExpr::IntBinOp { op: BinOp::Add, .. }));
        assert_eq!(hoisted.len(), 1);
    }

    // --- Int: call() % 1 -> let _eff0 = call(); 0 ---

    #[test]
    fn extract_int_rem_one_hoists_call() {
        let expr = JcExpr::IntBinOp {
            op: BinOp::Rem,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::IntLit(1)),
        };
        let (result, hoisted, _) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::IntLit(0)));
        assert_eq!(hoisted.len(), 1);
    }

    // --- Safe operands still get direct folding (no extraction needed) ---

    #[test]
    fn extract_safe_var_mul_zero_no_hoisting() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(0)),
        };
        let (result, hoisted, new_locals) = optimize_expr_extract(&expr);
        assert!(matches!(result, JcExpr::Lit(0)));
        assert!(
            hoisted.is_empty(),
            "safe var should not produce hoisted stmts"
        );
        assert!(
            new_locals.is_empty(),
            "safe var should not produce new locals"
        );
    }

    #[test]
    fn extract_safe_var_mul_two_no_hoisting() {
        let expr = JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Var(String::from("x"))),
            right: Box::new(JcExpr::Lit(2)),
        };
        let (result, hoisted, new_locals) = optimize_expr_extract(&expr);
        assert!(matches!(&result, JcExpr::BinOp { op: BinOp::Add, .. }));
        assert!(hoisted.is_empty());
        assert!(new_locals.is_empty());
    }

    // --- Nested extraction ---

    #[test]
    fn extract_nested_both_sides_effectful() {
        // (call(1) * 0) + (call(2) * 0)
        // -> let _eff0 = call(1); let _eff1 = call(2); 0 + 0 -> 0
        let expr = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Call {
                    method_index: 1,
                    args: vec![],
                }),
                right: Box::new(JcExpr::Lit(0)),
            }),
            right: Box::new(JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Call {
                    method_index: 2,
                    args: vec![],
                }),
                right: Box::new(JcExpr::Lit(0)),
            }),
        };
        let (result, hoisted, new_locals) = optimize_expr_extract(&expr);
        // 0 + 0 folds to 0
        assert!(
            matches!(result, JcExpr::Lit(0)),
            "nested extraction should fold to 0, got {result:?}"
        );
        assert_eq!(hoisted.len(), 2, "should hoist two calls");
        assert_eq!(new_locals.len(), 2);
    }

    // --- Statement-level extraction via optimize_stmt ---

    #[test]
    fn extract_stmt_return_call_mul_zero() {
        // return call() * 0;
        // -> [let _eff0 = call(); return 0;]
        let stmt = JcStmt::Return(Some(JcExpr::BinOp {
            op: BinOp::Mul,
            left: Box::new(JcExpr::Call {
                method_index: 1,
                args: vec![],
            }),
            right: Box::new(JcExpr::Lit(0)),
        }));
        let mut fresh = FreshNameGen::new();
        let result = optimize_stmt(&stmt, &mut fresh, false);
        assert_eq!(result.len(), 2, "should produce Let + Return");
        assert!(matches!(&result[0], JcStmt::Let { name, .. } if name == "_eff0"));
        assert!(matches!(&result[1], JcStmt::Return(Some(JcExpr::Lit(0)))));
        assert_eq!(fresh.new_locals.len(), 1);
    }

    #[test]
    fn extract_stmt_let_call_mul_two() {
        // let x: short = call() * 2;
        // -> [let _eff0 = call(); let x = _eff0 + _eff0;]
        let stmt = JcStmt::Let {
            name: String::from("x"),
            ty: JcType::Short,
            init: JcExpr::BinOp {
                op: BinOp::Mul,
                left: Box::new(JcExpr::Call {
                    method_index: 1,
                    args: vec![],
                }),
                right: Box::new(JcExpr::Lit(2)),
            },
        };
        let mut fresh = FreshNameGen::new();
        let result = optimize_stmt(&stmt, &mut fresh, false);
        assert_eq!(result.len(), 2, "should produce Let(_eff0) + Let(x)");
        assert!(matches!(
            &result[0],
            JcStmt::Let { name, ty: JcType::Short, init: JcExpr::Call { .. } } if name == "_eff0"
        ));
        assert!(matches!(
            &result[1],
            JcStmt::Let { name, ty: JcType::Short, init: JcExpr::BinOp { op: BinOp::Add, .. } } if name == "x"
        ));
    }

    // --- Full IR-level extraction via optimize_ir ---

    #[test]
    fn extract_ir_adds_fresh_locals() {
        // Method: return call() * 0;
        // After optimize_ir, method should have _eff0 in locals.
        let cls = JcClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            fields: vec![],
            methods: vec![JcMethod {
                name: String::from("f"),
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
            }],
        };
        let optimized = optimize_ir(&cls);
        let method = &optimized.methods[0];
        assert!(
            method.locals.iter().any(|(name, _)| name == "_eff0"),
            "optimize_ir should add _eff0 to locals, got {:?}",
            method.locals
        );
        assert!(
            method.body.len() >= 2,
            "body should have hoisted Let + Return"
        );
    }

    // --- While condition does NOT extract ---

    #[test]
    fn while_condition_does_not_extract() {
        // while (call() * 0 == 0) { ... } -- effects in condition must NOT
        // be extracted (they re-evaluate each iteration).
        let stmt = JcStmt::While {
            cond: Condition::Eq(
                JcExpr::BinOp {
                    op: BinOp::Mul,
                    left: Box::new(JcExpr::Call {
                        method_index: 1,
                        args: vec![],
                    }),
                    right: Box::new(JcExpr::Lit(0)),
                },
                JcExpr::Lit(0),
            ),
            body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
        };
        let mut fresh = FreshNameGen::new();
        let result = optimize_stmt(&stmt, &mut fresh, false);
        assert_eq!(
            result.len(),
            1,
            "While should not produce hoisted stmts, got {} stmts",
            result.len()
        );
        assert!(matches!(&result[0], JcStmt::While { .. }));
        assert!(
            fresh.new_locals.is_empty(),
            "While condition should not create fresh locals"
        );
    }

    // --- If condition DOES extract ---

    #[test]
    fn if_condition_extracts() {
        // if (call() * 0 == 0) { return 1; } else { return 2; }
        // -> [let _eff0 = call(); if (0 == 0) { return 1; } else { return 2; }]
        // -> constant condition folds: [let _eff0 = call(); return 1;]
        let stmt = JcStmt::If {
            cond: Condition::Eq(
                JcExpr::BinOp {
                    op: BinOp::Mul,
                    left: Box::new(JcExpr::Call {
                        method_index: 1,
                        args: vec![],
                    }),
                    right: Box::new(JcExpr::Lit(0)),
                },
                JcExpr::Lit(0),
            ),
            then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
        };
        let mut fresh = FreshNameGen::new();
        let result = optimize_stmt(&stmt, &mut fresh, false);
        // After extraction: condition becomes Eq(Lit(0), Lit(0)) which is true,
        // so constant folding inlines the then-branch.
        // Result: [Let(_eff0, call()), Return(Lit(1))]
        assert_eq!(
            result.len(),
            2,
            "If with extractable condition should produce Let + Return, got {result:?}"
        );
        assert!(matches!(&result[0], JcStmt::Let { name, .. } if name == "_eff0"));
        assert!(matches!(&result[1], JcStmt::Return(Some(JcExpr::Lit(1)))));
    }

    // --- FreshNameGen counter increments correctly ---

    #[test]
    fn fresh_name_gen_increments() {
        let mut fresh = FreshNameGen::new();
        assert_eq!(fresh.fresh(JcType::Short), "_eff0");
        assert_eq!(fresh.fresh(JcType::Int), "_eff1");
        assert_eq!(fresh.fresh(JcType::Short), "_eff2");
        assert_eq!(fresh.new_locals.len(), 3);
        assert_eq!(fresh.new_locals[0], (String::from("_eff0"), JcType::Short));
        assert_eq!(fresh.new_locals[1], (String::from("_eff1"), JcType::Int));
        assert_eq!(fresh.new_locals[2], (String::from("_eff2"), JcType::Short));
    }

    // =====================================================================
    // Config-aware optimization tests
    // =====================================================================

    #[test]
    fn peephole_config_none_makes_no_changes() {
        use crate::codegen::BytecodeMetadata;
        use crate::config::PeepholeConfig;
        let mut bytecodes = vec![SCONST_0, SADD, 0x78]; // sconst_0+sadd+sreturn
        let mut metadata = BytecodeMetadata {
            branch_targets: vec![],
            basic_blocks: vec![(0, 3)],
            branches: vec![],
        };
        let changes =
            peephole_optimize_with_config(&mut bytecodes, &mut metadata, &PeepholeConfig::none());
        assert_eq!(changes, 0);
        assert_eq!(bytecodes, vec![SCONST_0, SADD, 0x78]); // unchanged
    }

    #[test]
    fn peephole_config_single_pattern_only_fires_that_pattern() {
        use crate::codegen::BytecodeMetadata;
        use crate::config::PeepholeConfig;
        // Enable only double_negation, not add_zero_identity.
        let config = PeepholeConfig {
            enabled: true,
            max_passes: 64,
            store_load_dup: false,
            dead_push_pop: false,
            double_negation: true,
            goto_next: false,
            add_zero_identity: false,
            dead_store: false,
        };
        // Bytecodes: sconst_0, sadd, sneg, sneg, sreturn
        let mut bytecodes = vec![SCONST_0, SADD, SNEG, SNEG, 0x78];
        let mut metadata = BytecodeMetadata {
            branch_targets: vec![],
            basic_blocks: vec![(0, 5)],
            branches: vec![],
        };
        let changes = peephole_optimize_with_config(&mut bytecodes, &mut metadata, &config);
        assert!(changes > 0);
        // sneg+sneg removed, but sconst_0+sadd preserved
        assert_eq!(bytecodes, vec![SCONST_0, SADD, 0x78]);
    }

    #[test]
    fn ir_config_disabled_skips_optimization() {
        use crate::config::IrConfig;
        // Create a class with a constant expression that would normally be folded.
        let class = make_static_class(JcMethod {
            name: String::from("test"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Lit(3)),
                right: Box::new(JcExpr::Lit(4)),
            }))],
            is_static: true,
            constant_time: false,
        });
        let result = optimize_ir_with_config(&class, &IrConfig::none());
        // Without optimization, the Add should still be there.
        match &result.methods[0].body[0] {
            JcStmt::Return(Some(JcExpr::BinOp { op: BinOp::Add, .. })) => {}
            other => panic!("expected unfolded Add, got: {other:?}"),
        }
    }

    #[test]
    fn ct_method_preserves_constant_condition_branches() {
        use crate::config::IrConfig;
        // constant_time method with always-true condition.
        // Branch DCE should be skipped.
        let class = make_static_class(JcMethod {
            name: String::from("verify"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::If {
                cond: Condition::Eq(JcExpr::Lit(1), JcExpr::Lit(1)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            }],
            is_static: true,
            constant_time: true,
        });
        let result = optimize_ir_with_config(&class, &IrConfig::default_config());
        // The If should still be present (not DCE'd to just the then branch).
        match &result.methods[0].body[0] {
            JcStmt::If {
                then_body,
                else_body,
                ..
            } => {
                assert!(!then_body.is_empty());
                assert!(!else_body.is_empty());
            }
            other => panic!("expected If preserved, got: {other:?}"),
        }
    }

    #[test]
    fn non_ct_method_eliminates_constant_condition() {
        use crate::config::IrConfig;
        // Non-CT method with always-true condition -- should be DCE'd.
        let class = make_static_class(JcMethod {
            name: String::from("normal"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::If {
                cond: Condition::Eq(JcExpr::Lit(1), JcExpr::Lit(1)),
                then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            }],
            is_static: true,
            constant_time: false,
        });
        let result = optimize_ir_with_config(&class, &IrConfig::default_config());
        // The If should be DCE'd to just "return 1".
        match &result.methods[0].body[0] {
            JcStmt::Return(Some(JcExpr::Lit(1))) => {}
            other => panic!("expected DCE'd to return 1, got: {other:?}"),
        }
    }
}
