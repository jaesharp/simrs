//! DSL parser and code generator for `jcapplet!{}`.
//!
//! Parses the Rust-like JVA syntax using `syn`, converts it to the
//! `simrs_jccompile::ir` types, compiles via `compile_class()`, and
//! emits Rust code via `quote`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{braced, parenthesized, Ident, LitInt, Result, Token};

use simrs_jccompile::ir::{
    BinOp, Condition, JcClass, JcExpr, JcField, JcMethod, JcStmt, LValue,
};
use simrs_jccompile::types::JcType;

// ---------------------------------------------------------------------------
// AST types (parsed from the DSL, before conversion to IR)
// ---------------------------------------------------------------------------

/// A parsed applet definition.
struct AppletDef {
    /// Applet name (used for error messages, not in output).
    _name: Ident,
    /// AID in hex-with-underscores format.
    aid_hex: String,
    /// Field declarations.
    fields: Vec<FieldDef>,
    /// Method declarations.
    methods: Vec<MethodDef>,
}

/// A parsed field declaration: `field name: type;`
struct FieldDef {
    name: Ident,
    ty: JcType,
}

/// A parsed method declaration: `fn name(params) [-> type] { body }`
struct MethodDef {
    name: Ident,
    params: Vec<(Ident, JcType)>,
    return_ty: JcType,
    body: Vec<Stmt>,
}

/// A parsed statement.
enum Stmt {
    /// `let name: type = expr;`
    Let {
        name: Ident,
        ty: JcType,
        init: Expr,
    },
    /// `target = expr;`
    Assign { target: AssignTarget, value: Expr },
    /// `return [expr];`
    Return(Option<Expr>),
    /// `if lhs == rhs { ... } else { ... }` or `if lhs != rhs { ... } else { ... }`
    If {
        cond: Cond,
        then_body: Vec<Self>,
        else_body: Vec<Self>,
    },
    /// `while lhs != rhs { ... }` (or `==`)
    While { cond: Cond, body: Vec<Self> },
    /// Expression statement: `expr;`
    Expression(Expr),
}

/// A parsed condition: `expr == expr` or `expr != expr`.
enum Cond {
    Eq(Expr, Expr),
    Ne(Expr, Expr),
}

/// An assignment target.
enum AssignTarget {
    /// Plain variable: `name`
    Var(Ident),
    /// Instance field: `self.name`
    SelfField(Ident),
    /// Array element: `arr[idx]`
    ArrayElem { array: Expr, index: Expr },
}

/// A parsed expression.
enum Expr {
    /// Integer literal.
    Lit(i16),
    /// Variable reference.
    Var(Ident),
    /// `self.field`
    SelfField(Ident),
    /// Binary operation.
    BinOp {
        op: BinOp,
        left: Box<Self>,
        right: Box<Self>,
    },
    /// Negation: `-expr`
    Neg(Box<Self>),
    /// Array access: `arr[idx]`
    ArrayLoad {
        array: Box<Self>,
        index: Box<Self>,
    },
    /// Method call: `name(args)`
    Call { name: Ident, args: Vec<Self> },
    /// `new_byte_array(len)`
    NewByteArray(Box<Self>),
    /// `new_short_array(len)`
    NewShortArray(Box<Self>),
    /// `expr.len()`
    ArrayLength(Box<Self>),
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a `JcType` from an identifier.
fn parse_jc_type(ident: &Ident) -> Result<JcType> {
    match ident.to_string().as_str() {
        "short" => Ok(JcType::Short),
        "byte" => Ok(JcType::Byte),
        "bool" => Ok(JcType::Boolean),
        _ => Err(syn::Error::new(
            ident.span(),
            format!("unknown type `{ident}`, expected `short`, `byte`, or `bool`"),
        )),
    }
}

impl Parse for AppletDef {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        // `applet Name(AID_HEX) { ... }`
        let kw: Ident = input.parse()?;
        if kw != "applet" {
            return Err(syn::Error::new(kw.span(), "expected `applet`"));
        }

        let name: Ident = input.parse()?;

        // Parse AID in parens: `(A0_00_00_00_62_01_01)`
        let aid_content;
        parenthesized!(aid_content in input);
        let aid_ident: Ident = aid_content.parse()?;
        let aid_hex = aid_ident.to_string();

        // Parse body
        let body;
        braced!(body in input);

        let mut fields = Vec::new();
        let mut methods = Vec::new();

        while !body.is_empty() {
            // Peek to determine if this is a field or method.
            if body.peek(Token![fn]) {
                methods.push(parse_method_def(&body)?);
            } else {
                // Must be `field name: type;`
                let kw: Ident = body.parse()?;
                if kw != "field" {
                    return Err(syn::Error::new(
                        kw.span(),
                        "expected `field` or `fn`",
                    ));
                }
                let field_name: Ident = body.parse()?;
                body.parse::<Token![:]>()?;
                let ty_ident: Ident = body.parse()?;
                let ty = parse_jc_type(&ty_ident)?;
                body.parse::<Token![;]>()?;
                fields.push(FieldDef {
                    name: field_name,
                    ty,
                });
            }
        }

        Ok(Self {
            _name: name,
            aid_hex,
            fields,
            methods,
        })
    }
}

/// Parse a method definition: `fn name(params) [-> type] { body }`
fn parse_method_def(input: ParseStream<'_>) -> Result<MethodDef> {
    input.parse::<Token![fn]>()?;
    let name: Ident = input.parse()?;

    // Parse parameters
    let params_content;
    parenthesized!(params_content in input);
    let mut params = Vec::new();
    while !params_content.is_empty() {
        let param_name: Ident = params_content.parse()?;
        params_content.parse::<Token![:]>()?;
        let ty_ident: Ident = params_content.parse()?;
        let ty = parse_jc_type(&ty_ident)?;
        params.push((param_name, ty));
        if !params_content.is_empty() {
            params_content.parse::<Token![,]>()?;
        }
    }

    // Parse optional return type
    let return_ty = if input.peek(Token![->]) {
        input.parse::<Token![->]>()?;
        let ty_ident: Ident = input.parse()?;
        parse_jc_type(&ty_ident)?
    } else {
        JcType::Void
    };

    // Parse body
    let body_content;
    braced!(body_content in input);
    let mut body = Vec::new();
    while !body_content.is_empty() {
        body.push(parse_stmt(&body_content)?);
    }

    Ok(MethodDef {
        name,
        params,
        return_ty,
        body,
    })
}

/// Parse a statement.
#[allow(clippy::too_many_lines)]
fn parse_stmt(input: ParseStream<'_>) -> Result<Stmt> {
    // `let name: type = expr;`
    if input.peek(Token![let]) {
        input.parse::<Token![let]>()?;
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty_ident: Ident = input.parse()?;
        let ty = parse_jc_type(&ty_ident)?;
        input.parse::<Token![=]>()?;
        let init = parse_expr(input)?;
        input.parse::<Token![;]>()?;
        return Ok(Stmt::Let { name, ty, init });
    }

    // `return [expr];`
    if input.peek(Token![return]) {
        input.parse::<Token![return]>()?;
        if input.peek(Token![;]) {
            input.parse::<Token![;]>()?;
            return Ok(Stmt::Return(None));
        }
        let expr = parse_expr(input)?;
        input.parse::<Token![;]>()?;
        return Ok(Stmt::Return(Some(expr)));
    }

    // `if expr == expr { ... } [else { ... }]`
    if input.peek(Token![if]) {
        input.parse::<Token![if]>()?;
        let cond = parse_condition(input)?;
        let then_content;
        braced!(then_content in input);
        let mut then_body = Vec::new();
        while !then_content.is_empty() {
            then_body.push(parse_stmt(&then_content)?);
        }

        let mut else_body = Vec::new();
        if input.peek(Token![else]) {
            input.parse::<Token![else]>()?;
            let else_content;
            braced!(else_content in input);
            while !else_content.is_empty() {
                else_body.push(parse_stmt(&else_content)?);
            }
        }

        return Ok(Stmt::If {
            cond,
            then_body,
            else_body,
        });
    }

    // `while cond { ... }`
    if input.peek(Token![while]) {
        input.parse::<Token![while]>()?;
        let cond = parse_condition(input)?;
        let body_content;
        braced!(body_content in input);
        let mut body = Vec::new();
        while !body_content.is_empty() {
            body.push(parse_stmt(&body_content)?);
        }
        return Ok(Stmt::While { cond, body });
    }

    // Assignment or expression statement.
    // `self.field = expr;`
    // `name = expr;`
    // `arr[idx] = expr;`
    // `expr;`

    // Try to parse self.field assignment
    if input.peek(Token![self]) && input.peek2(Token![.]) {
        let fork = input.fork();
        fork.parse::<Token![self]>()?;
        fork.parse::<Token![.]>()?;
        let field_name: Ident = fork.parse()?;
        if fork.peek(Token![=]) {
            // Commit: this is self.field = expr;
            input.parse::<Token![self]>()?;
            input.parse::<Token![.]>()?;
            let field_name: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value = parse_expr(input)?;
            input.parse::<Token![;]>()?;
            return Ok(Stmt::Assign {
                target: AssignTarget::SelfField(field_name),
                value,
            });
        }
        // Not an assignment; fall through to expression statement.
        drop(field_name);
    }

    // Try ident = expr; (simple variable assignment)
    if input.peek(Ident) && !input.peek2(Token![.]) && !input.peek2(syn::token::Paren) {
        let fork = input.fork();
        let _name: Ident = fork.parse()?;
        // Check for array index: name[idx] = expr;
        if fork.peek(syn::token::Bracket) {
            // Parse: name[idx] = expr;
            let array_name: Ident = input.parse()?;
            let idx_content;
            syn::bracketed!(idx_content in input);
            let index = parse_expr(&idx_content)?;
            if input.peek(Token![=]) {
                input.parse::<Token![=]>()?;
                let value = parse_expr(input)?;
                input.parse::<Token![;]>()?;
                return Ok(Stmt::Assign {
                    target: AssignTarget::ArrayElem {
                        array: Expr::Var(array_name),
                        index,
                    },
                    value,
                });
            }
            // Not an assignment, reconstruct as expression -- but this is
            // ambiguous. For simplicity, error out.
            return Err(syn::Error::new(
                array_name.span(),
                "expected `=` after array index in statement position",
            ));
        }
        if fork.peek(Token![=]) {
            // Simple variable assignment
            let name: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value = parse_expr(input)?;
            input.parse::<Token![;]>()?;
            return Ok(Stmt::Assign {
                target: AssignTarget::Var(name),
                value,
            });
        }
    }

    // Expression statement
    let expr = parse_expr(input)?;
    input.parse::<Token![;]>()?;
    Ok(Stmt::Expression(expr))
}

/// Parse a condition: `expr == expr` or `expr != expr`.
fn parse_condition(input: ParseStream<'_>) -> Result<Cond> {
    let left = parse_expr(input)?;
    if input.peek(Token![==]) {
        input.parse::<Token![==]>()?;
        let right = parse_expr(input)?;
        Ok(Cond::Eq(left, right))
    } else if input.peek(Token![!=]) {
        input.parse::<Token![!=]>()?;
        let right = parse_expr(input)?;
        Ok(Cond::Ne(left, right))
    } else {
        Err(syn::Error::new(
            input.span(),
            "expected `==` or `!=` in condition",
        ))
    }
}

/// Parse an expression with operator precedence.
///
/// Precedence (lowest to highest):
/// 1. Additive: `+`, `-`
/// 2. Multiplicative: `*`, `/`, `%`
/// 3. Unary: `-expr`
/// 4. Primary: literals, variables, `self.field`, `(expr)`, calls, array access
fn parse_expr(input: ParseStream<'_>) -> Result<Expr> {
    parse_additive(input)
}

/// Parse additive expressions: `term (+|- term)*`
fn parse_additive(input: ParseStream<'_>) -> Result<Expr> {
    let mut left = parse_multiplicative(input)?;
    loop {
        if input.peek(Token![+]) {
            input.parse::<Token![+]>()?;
            let right = parse_multiplicative(input)?;
            left = Expr::BinOp {
                op: BinOp::Add,
                left: Box::new(left),
                right: Box::new(right),
            };
        } else if input.peek(Token![-]) {
            input.parse::<Token![-]>()?;
            let right = parse_multiplicative(input)?;
            left = Expr::BinOp {
                op: BinOp::Sub,
                left: Box::new(left),
                right: Box::new(right),
            };
        } else {
            break;
        }
    }
    Ok(left)
}

/// Parse multiplicative expressions: `unary (*|/|% unary)*`
fn parse_multiplicative(input: ParseStream<'_>) -> Result<Expr> {
    let mut left = parse_unary(input)?;
    loop {
        if input.peek(Token![*]) {
            input.parse::<Token![*]>()?;
            let right = parse_unary(input)?;
            left = Expr::BinOp {
                op: BinOp::Mul,
                left: Box::new(left),
                right: Box::new(right),
            };
        } else if input.peek(Token![/]) {
            input.parse::<Token![/]>()?;
            let right = parse_unary(input)?;
            left = Expr::BinOp {
                op: BinOp::Div,
                left: Box::new(left),
                right: Box::new(right),
            };
        } else if input.peek(Token![%]) {
            input.parse::<Token![%]>()?;
            let right = parse_unary(input)?;
            left = Expr::BinOp {
                op: BinOp::Rem,
                left: Box::new(left),
                right: Box::new(right),
            };
        } else {
            break;
        }
    }
    Ok(left)
}

/// Parse unary expressions: `-expr` or postfix
fn parse_unary(input: ParseStream<'_>) -> Result<Expr> {
    if input.peek(Token![-]) {
        input.parse::<Token![-]>()?;
        let inner = parse_unary(input)?;
        return Ok(Expr::Neg(Box::new(inner)));
    }
    parse_postfix(input)
}

/// Parse postfix operations: `primary[idx]`, `primary.len()`
fn parse_postfix(input: ParseStream<'_>) -> Result<Expr> {
    let mut expr = parse_primary(input)?;
    loop {
        if input.peek(syn::token::Bracket) {
            let idx_content;
            syn::bracketed!(idx_content in input);
            let index = parse_expr(&idx_content)?;
            expr = Expr::ArrayLoad {
                array: Box::new(expr),
                index: Box::new(index),
            };
        } else if input.peek(Token![.]) {
            input.parse::<Token![.]>()?;
            let method_name: Ident = input.parse()?;
            if method_name == "len" {
                let _parens;
                parenthesized!(_parens in input);
                expr = Expr::ArrayLength(Box::new(expr));
            } else {
                return Err(syn::Error::new(
                    method_name.span(),
                    format!("unknown method `.{method_name}()`, only `.len()` is supported"),
                ));
            }
        } else {
            break;
        }
    }
    Ok(expr)
}

/// Parse a primary expression.
fn parse_primary(input: ParseStream<'_>) -> Result<Expr> {
    // Parenthesized expression
    if input.peek(syn::token::Paren) {
        let content;
        parenthesized!(content in input);
        return parse_expr(&content);
    }

    // Integer literal
    if input.peek(LitInt) {
        let lit: LitInt = input.parse()?;
        let val: i16 = lit.base10_parse()?;
        return Ok(Expr::Lit(val));
    }

    // `self.field`
    if input.peek(Token![self]) {
        input.parse::<Token![self]>()?;
        input.parse::<Token![.]>()?;
        let field_name: Ident = input.parse()?;
        return Ok(Expr::SelfField(field_name));
    }

    // Identifier: variable, function call, or new_*_array
    if input.peek(Ident) {
        let ident: Ident = input.parse()?;
        let name_str = ident.to_string();

        // new_byte_array(len) or new_short_array(len)
        if name_str == "new_byte_array" {
            let args_content;
            parenthesized!(args_content in input);
            let len_expr = parse_expr(&args_content)?;
            return Ok(Expr::NewByteArray(Box::new(len_expr)));
        }
        if name_str == "new_short_array" {
            let args_content;
            parenthesized!(args_content in input);
            let len_expr = parse_expr(&args_content)?;
            return Ok(Expr::NewShortArray(Box::new(len_expr)));
        }

        // Function call: name(args)
        if input.peek(syn::token::Paren) {
            let args_content;
            parenthesized!(args_content in input);
            let mut args = Vec::new();
            while !args_content.is_empty() {
                args.push(parse_expr(&args_content)?);
                if !args_content.is_empty() {
                    args_content.parse::<Token![,]>()?;
                }
            }
            return Ok(Expr::Call { name: ident, args });
        }

        // Simple variable reference
        return Ok(Expr::Var(ident));
    }

    Err(syn::Error::new(
        input.span(),
        "expected expression (literal, variable, `self.field`, or `(expr)`)",
    ))
}

// ---------------------------------------------------------------------------
// Conversion to IR
// ---------------------------------------------------------------------------

/// Parse AID from underscore-separated hex: `"A0_00_00_01_51_00_00"` -> bytes.
fn parse_aid_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| *c != '_').collect();
    if !clean.len().is_multiple_of(2) {
        return Err(format!("AID hex has odd length: {s}"));
    }
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < clean.len() {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| format!("invalid hex in AID at position {i}: {e}"))?;
        bytes.push(byte);
        i += 2;
    }
    if bytes.is_empty() || bytes.len() > 16 {
        return Err(format!(
            "AID length must be 1-16 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Convert a parsed `AppletDef` to a `JcClass`.
fn applet_to_ir(
    applet: &AppletDef,
    method_names: &[String],
) -> std::result::Result<JcClass, syn::Error> {
    let aid = parse_aid_hex(&applet.aid_hex)
        .map_err(|msg| syn::Error::new(proc_macro2::Span::call_site(), msg))?;

    // Build fields with auto-computed offsets.
    let mut fields = Vec::new();
    let mut field_offset: u8 = 0;
    for fd in &applet.fields {
        let size = match fd.ty {
            JcType::Byte | JcType::Boolean => 1,
            _ => 2,
        };
        fields.push(JcField {
            name: fd.name.to_string(),
            ty: fd.ty,
            offset: field_offset,
        });
        field_offset = field_offset.checked_add(size).ok_or_else(|| {
            syn::Error::new(fd.name.span(), "field offsets overflow u8")
        })?;
    }

    let has_fields = !fields.is_empty();

    // Build methods.
    let mut methods = Vec::new();
    for md in &applet.methods {
        // Determine if this is an instance method (has fields => instance).
        let is_static = !has_fields;

        // Collect locals: parameters first, then let-declared locals from body.
        let mut locals: Vec<(String, JcType)> = Vec::new();
        for (pname, pty) in &md.params {
            locals.push((pname.to_string(), *pty));
        }
        collect_locals(&md.body, &mut locals);

        // Convert statements.
        let body = stmts_to_ir(&md.body, method_names)?;

        methods.push(JcMethod {
            name: md.name.to_string(),
            params: md.params.iter().map(|(n, t)| (n.to_string(), *t)).collect(),
            return_ty: md.return_ty,
            locals,
            body,
            is_static,
        });
    }

    Ok(JcClass {
        aid,
        fields,
        methods,
    })
}

/// Collect local variable names from `let` statements in a method body.
fn collect_locals(stmts: &[Stmt], locals: &mut Vec<(String, JcType)>) {
    for stmt in stmts {
        match stmt {
            Stmt::Let { name, ty, .. } => {
                let name_str = name.to_string();
                if !locals.iter().any(|(n, _)| *n == name_str) {
                    locals.push((name_str, *ty));
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_locals(then_body, locals);
                collect_locals(else_body, locals);
            }
            Stmt::While { body, .. } => {
                collect_locals(body, locals);
            }
            _ => {}
        }
    }
}

/// Convert parsed statements to IR statements.
fn stmts_to_ir(
    stmts: &[Stmt],
    method_names: &[String],
) -> std::result::Result<Vec<JcStmt>, syn::Error> {
    stmts.iter().map(|s| stmt_to_ir(s, method_names)).collect()
}

/// Convert a single parsed statement to IR.
fn stmt_to_ir(
    stmt: &Stmt,
    method_names: &[String],
) -> std::result::Result<JcStmt, syn::Error> {
    match stmt {
        Stmt::Let { name, ty, init } => Ok(JcStmt::Let {
            name: name.to_string(),
            ty: *ty,
            init: expr_to_ir(init, method_names)?,
        }),
        Stmt::Assign { target, value } => {
            let ir_target = match target {
                AssignTarget::Var(name) => LValue::Var(name.to_string()),
                AssignTarget::SelfField(name) => LValue::Field {
                    field_name: name.to_string(),
                },
                AssignTarget::ArrayElem { array, index } => LValue::ArrayElem {
                    array: Box::new(expr_to_ir(array, method_names)?),
                    index: Box::new(expr_to_ir(index, method_names)?),
                },
            };
            Ok(JcStmt::Assign {
                target: ir_target,
                value: expr_to_ir(value, method_names)?,
            })
        }
        Stmt::Return(None) => Ok(JcStmt::Return(None)),
        Stmt::Return(Some(expr)) => {
            Ok(JcStmt::Return(Some(expr_to_ir(expr, method_names)?)))
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => Ok(JcStmt::If {
            cond: cond_to_ir(cond, method_names)?,
            then_body: stmts_to_ir(then_body, method_names)?,
            else_body: stmts_to_ir(else_body, method_names)?,
        }),
        Stmt::While { cond, body } => Ok(JcStmt::While {
            cond: cond_to_ir(cond, method_names)?,
            body: stmts_to_ir(body, method_names)?,
        }),
        Stmt::Expression(expr) => Ok(JcStmt::Expr(expr_to_ir(expr, method_names)?)),
    }
}

/// Convert a parsed condition to IR.
fn cond_to_ir(
    cond: &Cond,
    method_names: &[String],
) -> std::result::Result<Condition, syn::Error> {
    match cond {
        Cond::Eq(left, right) => Ok(Condition::Eq(
            expr_to_ir(left, method_names)?,
            expr_to_ir(right, method_names)?,
        )),
        Cond::Ne(left, right) => Ok(Condition::Ne(
            expr_to_ir(left, method_names)?,
            expr_to_ir(right, method_names)?,
        )),
    }
}

/// Convert a parsed expression to IR.
fn expr_to_ir(
    expr: &Expr,
    method_names: &[String],
) -> std::result::Result<JcExpr, syn::Error> {
    match expr {
        Expr::Lit(n) => Ok(JcExpr::Lit(*n)),
        Expr::Var(ident) => Ok(JcExpr::Var(ident.to_string())),
        Expr::SelfField(ident) => Ok(JcExpr::SelfField(ident.to_string())),
        Expr::BinOp { op, left, right } => Ok(JcExpr::BinOp {
            op: *op,
            left: Box::new(expr_to_ir(left, method_names)?),
            right: Box::new(expr_to_ir(right, method_names)?),
        }),
        Expr::Neg(inner) => Ok(JcExpr::Neg(Box::new(expr_to_ir(inner, method_names)?))),
        Expr::ArrayLoad { array, index } => Ok(JcExpr::ArrayLoad {
            array: Box::new(expr_to_ir(array, method_names)?),
            index: Box::new(expr_to_ir(index, method_names)?),
        }),
        Expr::Call { name, args } => {
            let name_str = name.to_string();
            let method_index = method_names
                .iter()
                .position(|n| *n == name_str)
                .ok_or_else(|| {
                    syn::Error::new(
                        name.span(),
                        format!("undefined method `{name_str}`"),
                    )
                })?;
            #[allow(clippy::cast_possible_truncation)]
            let idx = method_index as u8;
            let ir_args: std::result::Result<Vec<JcExpr>, _> =
                args.iter().map(|a| expr_to_ir(a, method_names)).collect();
            Ok(JcExpr::Call {
                method_index: idx,
                args: ir_args?,
            })
        }
        Expr::NewByteArray(len) => {
            Ok(JcExpr::NewByteArray(Box::new(expr_to_ir(len, method_names)?)))
        }
        Expr::NewShortArray(len) => {
            Ok(JcExpr::NewShortArray(Box::new(expr_to_ir(len, method_names)?)))
        }
        Expr::ArrayLength(arr) => {
            Ok(JcExpr::ArrayLength(Box::new(expr_to_ir(arr, method_names)?)))
        }
    }
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

/// Main entry point: parse, convert to IR, compile, emit Rust code.
pub fn generate(input: TokenStream) -> TokenStream {
    let applet = match syn::parse2::<AppletDef>(input) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error(),
    };

    // Collect method names for call resolution.
    let method_names: Vec<String> = applet.methods.iter().map(|m| m.name.to_string()).collect();

    // Convert to IR.
    let class = match applet_to_ir(&applet, &method_names) {
        Ok(c) => c,
        Err(e) => return e.to_compile_error(),
    };

    // Compile via simrs-jccompile.
    let compiled = match simrs_jccompile::compile_class(&class) {
        Ok(c) => c,
        Err(errors) => {
            let msg = errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return syn::Error::new(proc_macro2::Span::call_site(), msg)
                .to_compile_error();
        }
    };

    // Emit Rust code.
    let aid_bytes = &compiled.aid;
    let aid_len = aid_bytes.len();
    let aid_tokens: Vec<_> = aid_bytes.iter().map(|b| quote! { #b }).collect();

    let mut method_tokens = Vec::new();
    for method_bc in &compiled.methods {
        let byte_tokens: Vec<_> = method_bc.iter().map(|b| quote! { #b }).collect();
        let byte_count = method_bc.len();
        method_tokens.push(quote! {
            {
                const BYTES: [u8; #byte_count] = [#(#byte_tokens),*];
                &BYTES as &[u8]
            }
        });
    }
    let method_count = method_tokens.len();

    quote! {
        {
            const AID: [u8; #aid_len] = [#(#aid_tokens),*];
            const METHODS: [&[u8]; #method_count] = [#(#method_tokens),*];
            (&AID, &METHODS)
        }
    }
}
