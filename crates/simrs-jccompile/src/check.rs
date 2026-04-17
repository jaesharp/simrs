//! Type checker for the JVA IR.
//!
//! Validates a [`JcClass`] and builds the local variable index maps
//! needed by the code generator.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CompileError;
use crate::ir::{BinOp, Condition, JcClass, JcExpr, JcMethod, JcStmt, LValue};
use crate::types::JcType;

/// A type-checked class ready for code generation.
#[derive(Debug, Clone)]
pub struct CheckedClass {
    /// The original class AID.
    pub aid: Vec<u8>,
    /// Type-checked methods with resolved local indices.
    pub methods: Vec<CheckedMethod>,
}

/// A type-checked method with resolved variable mappings.
#[derive(Debug, Clone)]
pub struct CheckedMethod {
    /// Local variable name to stack-slot index mapping.
    pub local_map: Vec<(String, u8)>,
    /// Field name to byte-offset mapping.
    pub field_map: Vec<(String, u8)>,
    /// Field name to type mapping.
    pub field_types: Vec<(String, JcType)>,
    /// Original method data (kept for codegen).
    pub method: JcMethod,
}

impl CheckedMethod {
    /// Look up a local variable's stack slot index by name.
    pub fn local_index(&self, name: &str) -> Option<u8> {
        self.local_map
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, i)| *i)
    }

    /// Look up a field's byte offset by name.
    pub fn field_offset(&self, name: &str) -> Option<u8> {
        self.field_map
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, o)| *o)
    }

    /// Look up a local variable's type by name.
    pub fn local_type(&self, name: &str) -> Option<JcType> {
        self.method
            .locals
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, ty)| *ty)
    }

    /// Look up a field's type by name.
    pub fn field_type(&self, name: &str) -> Option<JcType> {
        self.field_types
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, ty)| *ty)
    }
}

/// Type-check a class, producing a [`CheckedClass`] or a list of errors.
///
/// # Errors
///
/// Returns a non-empty `Vec<CompileError>` if any validation fails.
pub fn check_class(class: &JcClass) -> Result<CheckedClass, Vec<CompileError>> {
    let mut errors = Vec::new();

    // Build field map and field type map (shared across all methods).
    let field_map: Vec<(String, u8)> = class
        .fields
        .iter()
        .map(|f| (f.name.clone(), f.offset))
        .collect();

    let field_types: Vec<(String, JcType)> = class
        .fields
        .iter()
        .map(|f| (f.name.clone(), f.ty))
        .collect();

    let mut checked_methods = Vec::new();
    for method in &class.methods {
        let mut method_errors = Vec::new();

        // Build local variable map.
        // For instance methods, slot 0 is `this`; for static methods, slots
        // start at 0 with the first parameter.
        let mut local_map: Vec<(String, u8)> = Vec::new();
        let mut slot: u8 = 0;

        if !method.is_static {
            // Slot 0 is the implicit `this` reference.
            local_map.push((String::from("this"), slot));
            slot += 1;
        }

        for (name, ty) in &method.locals {
            local_map.push((name.clone(), slot));
            slot += ty.stack_size();
        }

        // Validate the method body.
        check_stmts(
            &method.body,
            &local_map,
            &field_map,
            &method.locals,
            method,
            class,
            &mut method_errors,
        );

        for e in &method_errors {
            errors.push(CompileError {
                method: method.name.clone(),
                message: e.clone(),
            });
        }

        checked_methods.push(CheckedMethod {
            local_map,
            field_map: field_map.clone(),
            field_types: field_types.clone(),
            method: method.clone(),
        });
    }

    if errors.is_empty() {
        Ok(CheckedClass {
            aid: class.aid.clone(),
            methods: checked_methods,
        })
    } else {
        Err(errors)
    }
}

/// Validate a sequence of statements.
fn check_stmts(
    stmts: &[JcStmt],
    local_map: &[(String, u8)],
    field_map: &[(String, u8)],
    locals: &[(String, JcType)],
    method: &JcMethod,
    class: &JcClass,
    errors: &mut Vec<String>,
) {
    for stmt in stmts {
        check_stmt(stmt, local_map, field_map, locals, method, class, errors);
    }
}

/// Validate a single statement.
#[allow(clippy::too_many_arguments)]
fn check_stmt(
    stmt: &JcStmt,
    local_map: &[(String, u8)],
    field_map: &[(String, u8)],
    locals: &[(String, JcType)],
    method: &JcMethod,
    class: &JcClass,
    errors: &mut Vec<String>,
) {
    match stmt {
        JcStmt::Let { name, init, .. } => {
            // Verify the variable is declared in locals.
            if !local_map.iter().any(|(n, _)| n == name) {
                errors.push(format!("undeclared local variable `{name}`"));
            }
            check_expr(init, local_map, field_map, locals, class, errors);
        }
        JcStmt::Assign { target, value } => {
            check_lvalue(target, local_map, field_map, locals, class, errors);
            check_expr(value, local_map, field_map, locals, class, errors);
        }
        JcStmt::Return(Some(expr)) => {
            if method.return_ty == JcType::Void {
                errors.push(String::from("void method cannot return a value"));
            }
            check_expr(expr, local_map, field_map, locals, class, errors);
        }
        JcStmt::Return(None) => {
            if method.return_ty != JcType::Void {
                errors.push(String::from("non-void method must return a value"));
            }
        }
        JcStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            check_condition(cond, local_map, field_map, locals, class, errors);
            check_stmts(
                then_body, local_map, field_map, locals, method, class, errors,
            );
            check_stmts(
                else_body, local_map, field_map, locals, method, class, errors,
            );
        }
        JcStmt::While { cond, body } => {
            check_condition(cond, local_map, field_map, locals, class, errors);
            check_stmts(body, local_map, field_map, locals, method, class, errors);
        }
        JcStmt::Expr(expr) => {
            check_expr(expr, local_map, field_map, locals, class, errors);
        }
        JcStmt::Switch {
            key,
            cases,
            default,
        } => {
            check_expr(key, local_map, field_map, locals, class, errors);
            for (_val, body) in cases {
                check_stmts(body, local_map, field_map, locals, method, class, errors);
            }
            check_stmts(default, local_map, field_map, locals, method, class, errors);
        }
        JcStmt::IntSwitch {
            key,
            cases,
            default,
        } => {
            check_expr(key, local_map, field_map, locals, class, errors);
            for (_val, body) in cases {
                check_stmts(body, local_map, field_map, locals, method, class, errors);
            }
            check_stmts(default, local_map, field_map, locals, method, class, errors);
        }
        JcStmt::Increment { var, .. } => {
            if !local_map.iter().any(|(n, _)| n == var) {
                errors.push(format!("undefined variable `{var}` in increment"));
            }
        }
    }
}

/// Validate an l-value.
fn check_lvalue(
    lv: &LValue,
    local_map: &[(String, u8)],
    field_map: &[(String, u8)],
    locals: &[(String, JcType)],
    class: &JcClass,
    errors: &mut Vec<String>,
) {
    match lv {
        LValue::Var(name) => {
            if !local_map.iter().any(|(n, _)| n == name) {
                errors.push(format!("undefined variable `{name}`"));
            }
        }
        LValue::Field { field_name } => {
            if !field_map.iter().any(|(n, _)| n == field_name) {
                errors.push(format!("undefined field `{field_name}`"));
            }
        }
        LValue::ArrayElem { array, index } => {
            check_expr(array, local_map, field_map, locals, class, errors);
            check_expr(index, local_map, field_map, locals, class, errors);
        }
    }
}

/// Validate a condition.
fn check_condition(
    cond: &Condition,
    local_map: &[(String, u8)],
    field_map: &[(String, u8)],
    locals: &[(String, JcType)],
    class: &JcClass,
    errors: &mut Vec<String>,
) {
    match cond {
        // Null/non-null reference checks (single operand).
        Condition::Null(e) | Condition::NonNull(e) => {
            check_expr(e, local_map, field_map, locals, class, errors);
        }
        // Short, int, and reference comparisons (all two-operand).
        Condition::Eq(l, r)
        | Condition::Ne(l, r)
        | Condition::Lt(l, r)
        | Condition::Ge(l, r)
        | Condition::Gt(l, r)
        | Condition::Le(l, r)
        | Condition::IntEq(l, r)
        | Condition::IntNe(l, r)
        | Condition::IntLt(l, r)
        | Condition::IntGe(l, r)
        | Condition::IntGt(l, r)
        | Condition::IntLe(l, r)
        | Condition::RefEq(l, r)
        | Condition::RefNe(l, r) => {
            check_expr(l, local_map, field_map, locals, class, errors);
            check_expr(r, local_map, field_map, locals, class, errors);
        }
    }
}

/// Validate an expression.
#[allow(clippy::too_many_lines)]
fn check_expr(
    expr: &JcExpr,
    local_map: &[(String, u8)],
    field_map: &[(String, u8)],
    locals: &[(String, JcType)],
    class: &JcClass,
    errors: &mut Vec<String>,
) {
    match expr {
        JcExpr::Lit(_) | JcExpr::IntLit(_) => {}
        JcExpr::Var(name) => {
            if !local_map.iter().any(|(n, _)| n == name) {
                errors.push(format!("undefined variable `{name}`"));
            }
        }
        JcExpr::SelfField(name) => {
            if !field_map.iter().any(|(n, _)| n == name) {
                errors.push(format!("undefined field `{name}`"));
            }
        }
        JcExpr::BinOp { op, left, right } => {
            check_expr(left, local_map, field_map, locals, class, errors);
            check_expr(right, local_map, field_map, locals, class, errors);
            // For bitwise ops, both operands must be numeric (short).
            // For arithmetic ops, same requirement.
            if let (Some(lt), Some(rt)) = (
                expr_type(left, locals, &class.fields),
                expr_type(right, locals, &class.fields),
            ) {
                let need_numeric = matches!(
                    op,
                    BinOp::Add
                        | BinOp::Sub
                        | BinOp::Mul
                        | BinOp::Div
                        | BinOp::Rem
                        | BinOp::And
                        | BinOp::Or
                        | BinOp::Xor
                        | BinOp::Shl
                        | BinOp::Shr
                        | BinOp::Ushr
                );
                if need_numeric {
                    if !lt.is_numeric() {
                        errors.push(format!(
                            "left operand of arithmetic op has non-numeric type {lt:?}"
                        ));
                    }
                    if !rt.is_numeric() {
                        errors.push(format!(
                            "right operand of arithmetic op has non-numeric type {rt:?}"
                        ));
                    }
                }
            }
        }
        JcExpr::IntBinOp { op, left, right } => {
            check_expr(left, local_map, field_map, locals, class, errors);
            check_expr(right, local_map, field_map, locals, class, errors);
            // Left operand must be int; for shift ops the right operand
            // (shift amount) is a short per JCVM spec.
            let is_shift = matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Ushr);
            if let Some(lt) = expr_type(left, locals, &class.fields)
                && !lt.is_int()
            {
                errors.push(format!(
                    "left operand of int arithmetic op has non-int type {lt:?}"
                ));
            }
            if let Some(rt) = expr_type(right, locals, &class.fields) {
                if is_shift {
                    // Shift amount must be numeric (short/byte).
                    if !rt.is_numeric() && !rt.is_int() {
                        errors.push(format!(
                            "right operand of int shift op has non-numeric type {rt:?}"
                        ));
                    }
                } else if !rt.is_int() {
                    errors.push(format!(
                        "right operand of int arithmetic op has non-int type {rt:?}"
                    ));
                }
            }
        }
        JcExpr::Neg(inner) | JcExpr::IntNeg(inner) => {
            check_expr(inner, local_map, field_map, locals, class, errors);
        }
        JcExpr::ArrayLoad { array, index } => {
            check_expr(array, local_map, field_map, locals, class, errors);
            check_expr(index, local_map, field_map, locals, class, errors);
            if let Some(arr_ty) = expr_type(array, locals, &class.fields)
                && !arr_ty.is_array()
            {
                errors.push(format!("array load on non-array type {arr_ty:?}"));
            }
        }
        JcExpr::Call { args, .. } => {
            for arg in args {
                check_expr(arg, local_map, field_map, locals, class, errors);
            }
        }
        JcExpr::NewByteArray(len) | JcExpr::NewShortArray(len) | JcExpr::NewIntArray(len) => {
            check_expr(len, local_map, field_map, locals, class, errors);
        }
        JcExpr::NewRefArray { length, .. } => {
            check_expr(length, local_map, field_map, locals, class, errors);
        }
        JcExpr::ArrayLength(arr) => {
            check_expr(arr, local_map, field_map, locals, class, errors);
        }
        JcExpr::Cast { from, to, expr } => {
            check_expr(expr, local_map, field_map, locals, class, errors);
            // Validate conversion pair.
            let valid = matches!(
                (from, to),
                (JcType::Short | JcType::Int, JcType::Byte)
                    | (JcType::Short, JcType::Int)
                    | (JcType::Int, JcType::Short)
            );
            if !valid {
                errors.push(format!("invalid cast from {from:?} to {to:?}"));
            }
        }
        JcExpr::InstanceOf { expr, .. } => {
            check_expr(expr, local_map, field_map, locals, class, errors);
        }
        JcExpr::IntCompare(left, right) => {
            check_expr(left, local_map, field_map, locals, class, errors);
            check_expr(right, local_map, field_map, locals, class, errors);
        }
    }
}

/// Attempt to determine the type of an expression (best-effort for MVP).
fn expr_type(
    expr: &JcExpr,
    locals: &[(String, JcType)],
    fields: &[crate::ir::JcField],
) -> Option<JcType> {
    match expr {
        JcExpr::Var(name) => locals.iter().find(|(n, _)| n == name).map(|(_, ty)| *ty),
        JcExpr::SelfField(name) => fields.iter().find(|f| f.name == *name).map(|f| f.ty),
        JcExpr::ArrayLoad { array, .. } => match expr_type(array, locals, fields)? {
            JcType::ByteArray => Some(JcType::Byte),
            JcType::ShortArray => Some(JcType::Short),
            JcType::IntArray => Some(JcType::Int),
            JcType::RefArray => Some(JcType::Instance),
            _ => None,
        },
        JcExpr::Call { .. } => None, // Cannot resolve without callee info.
        JcExpr::NewByteArray(_) => Some(JcType::ByteArray),
        JcExpr::NewShortArray(_) => Some(JcType::ShortArray),
        JcExpr::NewIntArray(_) => Some(JcType::IntArray),
        JcExpr::NewRefArray { .. } => Some(JcType::RefArray),
        JcExpr::IntLit(_) | JcExpr::IntBinOp { .. } | JcExpr::IntNeg(_) => Some(JcType::Int),
        JcExpr::Lit(_)
        | JcExpr::BinOp { .. }
        | JcExpr::Neg(_)
        | JcExpr::ArrayLength(_)
        | JcExpr::InstanceOf { .. }
        | JcExpr::IntCompare(_, _) => Some(JcType::Short),
        JcExpr::Cast { to, .. } => Some(*to),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BinOp, JcField, JcMethod};
    use alloc::boxed::Box;
    use alloc::vec;

    fn make_simple_class(method: JcMethod) -> JcClass {
        JcClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            fields: vec![],
            methods: vec![method],
        }
    }

    #[test]
    fn check_valid_constant_return() {
        let method = JcMethod {
            name: String::from("process"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(42)))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_simple_class(method);
        let result = check_class(&cls);
        assert!(result.is_ok());
    }

    #[test]
    fn check_undefined_variable() {
        let method = JcMethod {
            name: String::from("process"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Var(String::from("x"))))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_simple_class(method);
        let result = check_class(&cls);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("undefined variable `x`"))
        );
    }

    #[test]
    fn check_undefined_field() {
        let method = JcMethod {
            name: String::from("process"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::SelfField(String::from(
                "balance",
            ))))],
            is_static: false,
            constant_time: false,
        };
        let cls = make_simple_class(method);
        let result = check_class(&cls);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("undefined field `balance`"))
        );
    }

    #[test]
    fn check_void_return_with_value() {
        let method = JcMethod {
            name: String::from("init"),
            params: vec![],
            return_ty: JcType::Void,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_simple_class(method);
        let result = check_class(&cls);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("void method cannot return a value"))
        );
    }

    #[test]
    fn check_local_map_includes_params() {
        let method = JcMethod {
            name: String::from("add"),
            params: vec![
                (String::from("a"), JcType::Short),
                (String::from("b"), JcType::Short),
            ],
            return_ty: JcType::Short,
            locals: vec![
                (String::from("a"), JcType::Short),
                (String::from("b"), JcType::Short),
            ],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Var(String::from("b"))),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_simple_class(method);
        let result = check_class(&cls).unwrap();
        let cm = &result.methods[0];
        assert_eq!(cm.local_index("a"), Some(0));
        assert_eq!(cm.local_index("b"), Some(1));
    }

    #[test]
    fn check_instance_method_this_at_slot_zero() {
        let method = JcMethod {
            name: String::from("get_balance"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::SelfField(String::from(
                "balance",
            ))))],
            is_static: false,
            constant_time: false,
        };
        let cls = JcClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            fields: vec![JcField {
                name: String::from("balance"),
                ty: JcType::Short,
                offset: 0,
            }],
            methods: vec![method],
        };
        let result = check_class(&cls).unwrap();
        let cm = &result.methods[0];
        assert_eq!(cm.local_index("this"), Some(0));
    }

    #[test]
    fn check_arithmetic_on_non_numeric() {
        let method = JcMethod {
            name: String::from("bad"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("arr"), JcType::ByteArray)],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Var(String::from("arr"))),
                right: Box::new(JcExpr::Lit(1)),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_simple_class(method);
        let result = check_class(&cls);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("non-numeric type"))
        );
    }
}
