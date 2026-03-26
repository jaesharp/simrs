//! Intermediate representation for JVA smartcard programs.
//!
//! These AST nodes are produced by the frontend parser and consumed by
//! the type checker ([`crate::check`]) and code generator ([`crate::codegen`]).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::types::JcType;

/// A complete Java Card class/applet.
#[derive(Debug, Clone)]
pub struct JcClass {
    /// Application Identifier (5-16 bytes).
    pub aid: Vec<u8>,
    /// Instance fields.
    pub fields: Vec<JcField>,
    /// Methods (both static and instance).
    pub methods: Vec<JcMethod>,
}

/// An instance field declaration.
#[derive(Debug, Clone)]
pub struct JcField {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: JcType,
    /// Byte offset within the instance data (assigned by the frontend or checker).
    pub offset: u8,
}

/// A method declaration.
#[derive(Debug, Clone)]
pub struct JcMethod {
    /// Method name.
    pub name: String,
    /// Parameter list: `(name, type)` pairs.
    pub params: Vec<(String, JcType)>,
    /// Return type.
    pub return_ty: JcType,
    /// Local variable declarations (includes parameters at the start).
    pub locals: Vec<(String, JcType)>,
    /// Method body (sequence of statements).
    pub body: Vec<JcStmt>,
    /// Whether this is a static method.
    pub is_static: bool,
}

/// A statement in a method body.
#[derive(Debug, Clone)]
pub enum JcStmt {
    /// Local variable declaration with initializer.
    Let {
        /// Variable name.
        name: String,
        /// Declared type.
        ty: JcType,
        /// Initializer expression.
        init: JcExpr,
    },
    /// Assignment to an l-value.
    Assign {
        /// Assignment target.
        target: LValue,
        /// Value expression.
        value: JcExpr,
    },
    /// Return statement (with optional value).
    Return(Option<JcExpr>),
    /// Conditional branch.
    If {
        /// Branch condition.
        cond: Condition,
        /// Then-branch body.
        then_body: Vec<Self>,
        /// Else-branch body.
        else_body: Vec<Self>,
    },
    /// While loop.
    While {
        /// Loop condition.
        cond: Condition,
        /// Loop body.
        body: Vec<Self>,
    },
    /// Expression statement (result discarded).
    Expr(JcExpr),
}

/// A comparison condition for `if` and `while`.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Equality comparison.
    Eq(JcExpr, JcExpr),
    /// Inequality comparison.
    Ne(JcExpr, JcExpr),
}

/// An assignment target (l-value).
#[derive(Debug, Clone)]
pub enum LValue {
    /// Local variable.
    Var(String),
    /// Instance field (`self.field`).
    Field {
        /// Field name.
        field_name: String,
    },
    /// Array element.
    ArrayElem {
        /// Array expression.
        array: Box<JcExpr>,
        /// Index expression.
        index: Box<JcExpr>,
    },
}

/// An expression that produces a value.
#[derive(Debug, Clone)]
pub enum JcExpr {
    /// Integer literal (fits in i16).
    Lit(i16),
    /// Local variable reference.
    Var(String),
    /// Instance field read (`self.field_name`).
    SelfField(String),
    /// Binary arithmetic operation.
    BinOp {
        /// Operator.
        op: BinOp,
        /// Left operand.
        left: Box<Self>,
        /// Right operand.
        right: Box<Self>,
    },
    /// Arithmetic negation.
    Neg(Box<Self>),
    /// Array element read.
    ArrayLoad {
        /// Array expression.
        array: Box<Self>,
        /// Index expression.
        index: Box<Self>,
    },
    /// Static method call.
    Call {
        /// Method index in the package.
        method_index: u8,
        /// Argument expressions.
        args: Vec<Self>,
    },
    /// Allocate a new byte array.
    NewByteArray(Box<Self>),
    /// Allocate a new short array.
    NewShortArray(Box<Self>),
    /// Get array length.
    ArrayLength(Box<Self>),
}

/// Binary arithmetic operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Division.
    Div,
    /// Remainder.
    Rem,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn class_construction() {
        let cls = JcClass {
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
        assert_eq!(cls.aid.len(), 5);
        assert_eq!(cls.methods.len(), 1);
        assert_eq!(cls.methods[0].name, "process");
    }

    #[test]
    fn binop_expression() {
        let expr = JcExpr::BinOp {
            op: BinOp::Add,
            left: Box::new(JcExpr::Lit(3)),
            right: Box::new(JcExpr::Lit(2)),
        };
        match expr {
            JcExpr::BinOp { op, .. } => assert_eq!(op, BinOp::Add),
            _ => panic!("expected BinOp"),
        }
    }
}
