//! Source reconstruction from structured control flow.
//!
//! Converts the recovered [`Structure`](super::cfgraph::Structure) tree
//! into readable JVA source text.

use std::fmt::Write as _;

use super::cfgraph::{
    self, Condition, Expression, Statement, Structure,
};

/// Reconstruct JVA source from a method's bytecodes.
///
/// Performs the full decompilation pipeline:
/// 1. Decode instructions
/// 2. Build CFG
/// 3. Pattern-match control flow
/// 4. Recover stack operations as expressions
/// 5. Emit formatted source
///
/// # Errors
///
/// Returns an error if decoding or CFG construction fails.
pub fn reconstruct_method(bytecodes: &[u8]) -> Result<String, String> {
    let blocks = cfgraph::build_cfg(bytecodes)?;
    if blocks.is_empty() {
        return Ok(String::new());
    }

    let structure = cfgraph::recover_structure(&blocks);
    let mut output = String::new();
    emit_structure(&structure, &mut output, 2);
    Ok(output)
}

/// Reconstruct JVA source from a full CAP blob.
///
/// Produces an applet definition with all methods decompiled to
/// high-level source.
///
/// # Errors
///
/// Returns an error if the CAP is malformed or decompilation fails.
pub fn reconstruct_cap(cap_data: &[u8]) -> Result<String, String> {
    let pkg = simrs_jcvm::cap::parse_cap(cap_data).map_err(|e| format!("{e:?}"))?;
    let mut output = String::new();

    // Format AID.
    let aid = &pkg.aid[..pkg.aid_len as usize];
    output.push_str("applet ");
    for (i, b) in aid.iter().enumerate() {
        if i > 0 {
            output.push('_');
        }
        let _ = write!(output, "{b:02X}");
    }
    output.push_str(" {\n");

    // Reconstruct each method.
    for idx in 0..pkg.method_count {
        let method = pkg.method(idx).ok_or_else(|| {
            format!("method {idx} missing from package")
        })?;
        let bc = &method.bytecode[..method.bytecode_len as usize];

        let return_type = infer_return_type(bc);
        let static_kw = if method.is_static() { "static " } else { "" };

        let _ = writeln!(
            output,
            "    fn {static_kw}method_{idx}() -> {return_type} {{"
        );

        match reconstruct_method(bc) {
            Ok(body) => output.push_str(&body),
            Err(e) => { let _ = writeln!(output, "        // decompilation error: {e}"); }
        }

        output.push_str("    }\n\n");
    }

    output.push_str("}\n");
    Ok(output)
}

/// Infer the return type of a method from its bytecodes.
///
/// Looks for `sreturn` (returns short) or `return` (returns void).
fn infer_return_type(bytecodes: &[u8]) -> &'static str {
    for &b in bytecodes {
        if b == simrs_jcvm::opcodes::SRETURN {
            return "short";
        }
        if b == simrs_jcvm::opcodes::RETURN {
            return "void";
        }
    }
    "void"
}

/// Emit a structure as formatted source text.
fn emit_structure(structure: &Structure, output: &mut String, indent: usize) {
    let pad = " ".repeat(indent * 4);
    match structure {
        Structure::Sequence(items) => {
            for item in items {
                emit_structure(item, output, indent);
            }
        }

        Structure::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            let _ = writeln!(output, "{pad}if ({}) {{", format_condition(condition));
            emit_structure(then_body, output, indent + 1);
            let _ = writeln!(output, "{pad}}} else {{");
            emit_structure(else_body, output, indent + 1);
            let _ = writeln!(output, "{pad}}}");
        }

        Structure::While { condition, body } => {
            let _ = writeln!(output, "{pad}while ({}) {{", format_condition(condition));
            emit_structure(body, output, indent + 1);
            let _ = writeln!(output, "{pad}}}");

        }

        Structure::Return(None) => {
            let _ = writeln!(output, "{pad}return;");
        }

        Structure::Return(Some(expr)) => {
            let _ = writeln!(output, "{pad}return {};", format_expression(expr));
        }

        Structure::Stmt(stmt) => {
            emit_statement(stmt, output, &pad);
        }
    }
}

/// Emit a statement as formatted source text.
fn emit_statement(stmt: &Statement, output: &mut String, pad: &str) {
    match stmt {
        Statement::Assign(idx, expr) => {
            let _ = writeln!(output, "{pad}local_{idx} = {};", format_expression(expr));
        }
        Statement::FieldPut { obj, offset, value } => {
            let _ = writeln!(
                output, "{pad}{}.field_{offset} = {};",
                format_expression(obj), format_expression(value)
            );
        }
        Statement::ArrayStore { array, index, value } => {
            let _ = writeln!(
                output, "{pad}{}[{}] = {};",
                format_expression(array),
                format_expression(index),
                format_expression(value)
            );
        }
        Statement::Discard(expr) => {
            let _ = writeln!(output, "{pad}{};", format_expression(expr));
        }
    }
}

/// Format a condition as a string.
fn format_condition(cond: &Condition) -> String {
    match cond {
        Condition::Eq(left, right) => {
            format!(
                "{} == {}",
                format_expression(left),
                format_expression(right)
            )
        }
        Condition::Ne(left, right) => {
            format!(
                "{} != {}",
                format_expression(left),
                format_expression(right)
            )
        }
    }
}

/// Format an expression as a string.
fn format_expression(expr: &Expression) -> String {
    match expr {
        Expression::Literal(n) => format!("{n}"),
        Expression::Local(idx) => format!("local_{idx}"),
        Expression::BinOp { op, left, right } => {
            let left_str = format_expression_maybe_parens(left);
            let right_str = format_expression_maybe_parens(right);
            format!("{left_str} {op} {right_str}")
        }
        Expression::Neg(inner) => {
            format!("-{}", format_expression_maybe_parens(inner))
        }
        Expression::ArrayLoad { array, index } => {
            format!("{}[{}]", format_expression(array), format_expression(index))
        }
        Expression::FieldGet { obj, offset } => {
            format!("{}.field_{offset}", format_expression(obj))
        }
        Expression::ArrayLength(arr) => {
            format!("{}.length", format_expression(arr))
        }
        Expression::Dup(inner) => format_expression(inner),
        Expression::Invoke { pkg, method, args } => {
            let args_str: Vec<String> = args.iter().map(format_expression).collect();
            if *pkg == 0 {
                format!("method_{method}({})", args_str.join(", "))
            } else {
                format!("pkg{pkg}::method_{method}({})", args_str.join(", "))
            }
        }
        Expression::NewObject(type_token) => {
            format!("new Object(/* type={type_token} */)")
        }
        Expression::NewArray { elem_type, length } => {
            format!("new {elem_type}[{}]", format_expression(length))
        }
    }
}

/// Format an expression, adding parentheses if needed for precedence.
fn format_expression_maybe_parens(expr: &Expression) -> String {
    match expr {
        Expression::BinOp { .. } | Expression::Neg(_) => {
            format!("({})", format_expression(expr))
        }
        _ => format_expression(expr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_jcvm::opcodes;

    #[test]
    fn reconstruct_simple_return() {
        // bspush 42, sreturn
        let bc = [opcodes::BSPUSH, 42, opcodes::SRETURN];
        let source = reconstruct_method(&bc).unwrap();
        assert!(source.contains("return"), "expected return in: {source}");
        assert!(source.contains("42"), "expected 42 in: {source}");
    }

    #[test]
    fn reconstruct_arithmetic() {
        // sconst_3, sconst_2, sadd, sreturn
        let bc = [opcodes::SCONST_3, opcodes::SCONST_2, opcodes::SADD, opcodes::SRETURN];
        let source = reconstruct_method(&bc).unwrap();
        assert!(source.contains('+'), "expected + in: {source}");
        assert!(source.contains("return"), "expected return in: {source}");
    }

    #[test]
    fn format_nested_expression() {
        let expr = Expression::BinOp {
            op: "+",
            left: Box::new(Expression::Local(0)),
            right: Box::new(Expression::BinOp {
                op: "*",
                left: Box::new(Expression::Literal(2)),
                right: Box::new(Expression::Literal(3)),
            }),
        };
        let text = format_expression(&expr);
        assert!(text.contains('+'));
        assert!(text.contains('*'));
    }
}
