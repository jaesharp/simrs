//! Bytecode code generator for the JVA IR.
//!
//! Compiles a type-checked [`JcClass`](crate::ir::JcClass) into JCVM
//! bytecodes that can be loaded via
//! [`build_cap_blob`](simrs_jcvm::cap::build_cap_blob).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::check::{check_class, CheckedMethod};
use crate::error::CompileError;
use crate::ir::{BinOp, Condition, JcClass, JcExpr, JcStmt, LValue};
use crate::types::JcType;

// ---- JCVM opcode constants (mirrored from simrs-jcvm) ----

const SCONST_M1: u8 = 0x02;
const SCONST_0: u8 = 0x03;
const SCONST_5: u8 = 0x08;
const BSPUSH: u8 = 0x10;
const SSPUSH: u8 = 0x11;
const SLOAD: u8 = 0x16;
const SLOAD_0: u8 = 0x1C;
const SLOAD_3: u8 = 0x1F;
const BALOAD: u8 = 0x25;
const SALOAD: u8 = 0x24;
const BASTORE: u8 = 0x27;
const SASTORE: u8 = 0x26;
const SSTORE: u8 = 0x28;
const SSTORE_0: u8 = 0x2B;
const SSTORE_3: u8 = 0x2E;
const SADD: u8 = 0x41;
const SSUB: u8 = 0x43;
const SMUL: u8 = 0x45;
const SDIV: u8 = 0x47;
const SREM: u8 = 0x49;
const SNEG: u8 = 0x4B;
const IF_SCMPEQ: u8 = 0x6A;
const IF_SCMPNE: u8 = 0x6B;
const GOTO: u8 = 0x70;
const SRETURN: u8 = 0x78;
const RETURN: u8 = 0x7A;
const INVOKESTATIC: u8 = 0x8D;
const NEWARRAY: u8 = 0x90;
const ARRAYLENGTH: u8 = 0x92;
const GETFIELD_B: u8 = 0xAD;
const PUTFIELD_B: u8 = 0xAF;

/// Newarray type token for `byte[]`.
const ARRAY_TYPE_BYTE: u8 = 0x0A;
/// Newarray type token for `short[]`.
const ARRAY_TYPE_SHORT: u8 = 0x0B;

/// A compiled class ready for loading into the JCVM.
#[derive(Debug, Clone)]
pub struct CompiledClass {
    /// Application Identifier.
    pub aid: Vec<u8>,
    /// Bytecodes for each method, in declaration order.
    pub methods: Vec<Vec<u8>>,
}

/// Compile a class from IR to bytecode.
///
/// 1. Type-checks the class.
/// 2. Compiles each method body to bytecodes.
/// 3. Returns AID + method bytecodes.
///
/// # Errors
///
/// Returns compilation errors from type checking or code generation.
pub fn compile_class(class: &JcClass) -> Result<CompiledClass, Vec<CompileError>> {
    let checked = check_class(class)?;

    let mut methods = Vec::new();
    let mut errors = Vec::new();

    for cm in &checked.methods {
        match compile_method(cm) {
            Ok(bytecode) => methods.push(bytecode),
            Err(e) => errors.push(CompileError {
                method: cm.method.name.clone(),
                message: e,
            }),
        }
    }

    if errors.is_empty() {
        Ok(CompiledClass {
            aid: checked.aid,
            methods,
        })
    } else {
        Err(errors)
    }
}

/// A forward reference to be patched after the first pass.
struct ForwardRef {
    /// Position of the offset byte(s) in the bytecode buffer.
    patch_pos: usize,
    /// Position of the opcode (for computing relative offset).
    opcode_pos: usize,
    /// Target label ID.
    label: usize,
}

/// Code generation context for a single method.
struct MethodCodegen {
    /// Output bytecode buffer.
    code: Vec<u8>,
    /// Next label ID.
    next_label: usize,
    /// Map from label ID to bytecode position (filled in during emission).
    label_positions: Vec<Option<usize>>,
    /// Forward references to patch.
    forward_refs: Vec<ForwardRef>,
}

impl MethodCodegen {
    const fn new() -> Self {
        Self {
            code: Vec::new(),
            next_label: 0,
            label_positions: Vec::new(),
            forward_refs: Vec::new(),
        }
    }

    /// Allocate a new label, returning its ID.
    fn new_label(&mut self) -> usize {
        let id = self.next_label;
        self.next_label += 1;
        self.label_positions.push(None);
        id
    }

    /// Bind a label to the current position.
    fn bind_label(&mut self, label: usize) {
        self.label_positions[label] = Some(self.code.len());
    }

    /// Emit a raw byte.
    fn emit(&mut self, byte: u8) {
        self.code.push(byte);
    }

    /// Emit a branch instruction with a label reference.
    ///
    /// The offset byte is set to 0 as a placeholder and recorded for patching.
    fn emit_branch(&mut self, opcode: u8, label: usize) {
        let opcode_pos = self.code.len();
        self.emit(opcode);
        let patch_pos = self.code.len();
        self.emit(0); // placeholder offset
        self.forward_refs.push(ForwardRef {
            patch_pos,
            opcode_pos,
            label,
        });
    }

    /// Emit a `goto` instruction with a label reference.
    fn emit_goto(&mut self, label: usize) {
        self.emit_branch(GOTO, label);
    }

    /// Resolve all forward references.
    ///
    /// The JCVM branch offset is relative to the opcode itself:
    /// `target_pc = opcode_pc + signed_offset`
    fn resolve(&mut self) -> Result<(), String> {
        for fref in &self.forward_refs {
            let Some(target_pos) = self.label_positions[fref.label] else {
                return Err(format!("unresolved label {}", fref.label));
            };
            // offset = target_pos - opcode_pos (signed)
            let offset = target_pos.cast_signed() - fref.opcode_pos.cast_signed();
            let Ok(offset_i8) = i8::try_from(offset) else {
                return Err(format!(
                    "branch offset {offset} out of i8 range at position {}",
                    fref.opcode_pos
                ));
            };
            self.code[fref.patch_pos] = offset_i8.cast_unsigned();
        }
        Ok(())
    }
}

/// Compile a single method to bytecodes.
fn compile_method(cm: &CheckedMethod) -> Result<Vec<u8>, String> {
    let mut cg = MethodCodegen::new();

    for stmt in &cm.method.body {
        emit_stmt(&mut cg, stmt, cm)?;
    }

    cg.resolve()?;
    Ok(cg.code)
}

/// Emit bytecodes for a statement.
fn emit_stmt(cg: &mut MethodCodegen, stmt: &JcStmt, cm: &CheckedMethod) -> Result<(), String> {
    match stmt {
        JcStmt::Let { name, init, .. } => {
            emit_expr(cg, init, cm)?;
            emit_sstore(cg, cm, name)?;
            Ok(())
        }
        JcStmt::Assign { target, value } => emit_assign(cg, target, value, cm),
        JcStmt::Return(None) => {
            cg.emit(RETURN);
            Ok(())
        }
        JcStmt::Return(Some(expr)) => {
            emit_expr(cg, expr, cm)?;
            cg.emit(SRETURN);
            Ok(())
        }
        JcStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            let else_label = cg.new_label();
            let end_label = cg.new_label();

            // Emit condition: jump to else_label if condition is FALSE.
            emit_condition_negate(cg, cond, else_label, cm)?;

            // Then body.
            for s in then_body {
                emit_stmt(cg, s, cm)?;
            }
            cg.emit_goto(end_label);

            // Else body.
            cg.bind_label(else_label);
            for s in else_body {
                emit_stmt(cg, s, cm)?;
            }

            cg.bind_label(end_label);
            Ok(())
        }
        JcStmt::While { cond, body } => {
            let top_label = cg.new_label();
            let end_label = cg.new_label();

            cg.bind_label(top_label);

            // Emit condition: jump to end_label if condition is FALSE.
            emit_condition_negate(cg, cond, end_label, cm)?;

            // Loop body.
            for s in body {
                emit_stmt(cg, s, cm)?;
            }
            cg.emit_goto(top_label);

            cg.bind_label(end_label);
            Ok(())
        }
        JcStmt::Expr(expr) => {
            emit_expr(cg, expr, cm)?;
            // Discard result -- but for MVP, many expressions (like Call)
            // might not leave anything on the stack, so we skip the pop.
            // A more complete compiler would track stack effects.
            Ok(())
        }
    }
}

/// Emit the negated condition (branch to `target` when condition is FALSE).
fn emit_condition_negate(
    cg: &mut MethodCodegen,
    cond: &Condition,
    target: usize,
    cm: &CheckedMethod,
) -> Result<(), String> {
    match cond {
        Condition::Eq(left, right) => {
            // Jump if NOT equal.
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPNE, target);
        }
        Condition::Ne(left, right) => {
            // Jump if equal (negation of not-equal).
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPEQ, target);
        }
    }
    Ok(())
}

/// Emit an assignment.
fn emit_assign(
    cg: &mut MethodCodegen,
    target: &LValue,
    value: &JcExpr,
    cm: &CheckedMethod,
) -> Result<(), String> {
    match target {
        LValue::Var(name) => {
            emit_expr(cg, value, cm)?;
            emit_sstore(cg, cm, name)?;
            Ok(())
        }
        LValue::Field { field_name } => {
            // Push `this` (local 0), then value, then putfield_b.
            emit_sload(cg, 0);
            emit_expr(cg, value, cm)?;
            let offset = cm.field_offset(field_name).ok_or_else(|| {
                format!("codegen: undefined field `{field_name}`")
            })?;
            cg.emit(PUTFIELD_B);
            cg.emit(offset);
            cg.emit(0); // reserved class index byte
            Ok(())
        }
        LValue::ArrayElem { array, index } => {
            emit_expr(cg, array, cm)?;
            emit_expr(cg, index, cm)?;
            emit_expr(cg, value, cm)?;
            // Determine array element type for store instruction.
            let store_op = array_store_op(array, cm);
            cg.emit(store_op);
            Ok(())
        }
    }
}

/// Emit an sstore instruction for a named local.
fn emit_sstore(cg: &mut MethodCodegen, cm: &CheckedMethod, name: &str) -> Result<(), String> {
    let idx = cm.local_index(name).ok_or_else(|| {
        format!("codegen: undefined local `{name}`")
    })?;
    if idx <= (SSTORE_3 - SSTORE_0) {
        cg.emit(SSTORE_0 + idx);
    } else {
        cg.emit(SSTORE);
        cg.emit(idx);
    }
    Ok(())
}

/// Emit an sload instruction for a given slot index.
fn emit_sload(cg: &mut MethodCodegen, idx: u8) {
    if idx <= (SLOAD_3 - SLOAD_0) {
        cg.emit(SLOAD_0 + idx);
    } else {
        cg.emit(SLOAD);
        cg.emit(idx);
    }
}

/// Emit bytecodes for an expression (result pushed onto the stack).
fn emit_expr(cg: &mut MethodCodegen, expr: &JcExpr, cm: &CheckedMethod) -> Result<(), String> {
    match expr {
        JcExpr::Lit(n) => {
            emit_lit(cg, *n);
            Ok(())
        }
        JcExpr::Var(name) => {
            let idx = cm.local_index(name).ok_or_else(|| {
                format!("codegen: undefined local `{name}`")
            })?;
            emit_sload(cg, idx);
            Ok(())
        }
        JcExpr::SelfField(name) => {
            // Push `this` (local 0), then getfield_b.
            emit_sload(cg, 0);
            let offset = cm.field_offset(name).ok_or_else(|| {
                format!("codegen: undefined field `{name}`")
            })?;
            cg.emit(GETFIELD_B);
            cg.emit(offset);
            cg.emit(0); // reserved class index byte
            Ok(())
        }
        JcExpr::BinOp { op, left, right } => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            let opcode = match op {
                BinOp::Add => SADD,
                BinOp::Sub => SSUB,
                BinOp::Mul => SMUL,
                BinOp::Div => SDIV,
                BinOp::Rem => SREM,
            };
            cg.emit(opcode);
            Ok(())
        }
        JcExpr::Neg(inner) => {
            emit_expr(cg, inner, cm)?;
            cg.emit(SNEG);
            Ok(())
        }
        JcExpr::ArrayLoad { array, index } => {
            emit_expr(cg, array, cm)?;
            emit_expr(cg, index, cm)?;
            let load_op = array_load_op(array, cm);
            cg.emit(load_op);
            Ok(())
        }
        JcExpr::Call { method_index, args } => {
            for arg in args {
                emit_expr(cg, arg, cm)?;
            }
            cg.emit(INVOKESTATIC);
            cg.emit(0); // package index (same package)
            cg.emit(*method_index);
            Ok(())
        }
        JcExpr::NewByteArray(len) => {
            emit_expr(cg, len, cm)?;
            cg.emit(NEWARRAY);
            cg.emit(ARRAY_TYPE_BYTE);
            Ok(())
        }
        JcExpr::NewShortArray(len) => {
            emit_expr(cg, len, cm)?;
            cg.emit(NEWARRAY);
            cg.emit(ARRAY_TYPE_SHORT);
            Ok(())
        }
        JcExpr::ArrayLength(arr) => {
            emit_expr(cg, arr, cm)?;
            cg.emit(ARRAYLENGTH);
            Ok(())
        }
    }
}

/// Emit an integer literal using the most compact encoding.
fn emit_lit(cg: &mut MethodCodegen, n: i16) {
    // sconst_m1 (0x02) through sconst_5 (0x08) cover -1..5.
    // Range: SCONST_M1 maps to -1, SCONST_5 maps to 5.
    let lo = i16::from(SCONST_M1) - i16::from(SCONST_0); // -1
    let hi = i16::from(SCONST_5) - i16::from(SCONST_0);  // 5
    if n >= lo && n <= hi {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let opcode = (i16::from(SCONST_0) + n) as u8;
        cg.emit(opcode);
    } else if let Ok(byte_val) = i8::try_from(n) {
        cg.emit(BSPUSH);
        cg.emit(byte_val.cast_unsigned());
    } else {
        cg.emit(SSPUSH);
        let bytes = n.to_be_bytes();
        cg.emit(bytes[0]);
        cg.emit(bytes[1]);
    }
}

/// Determine the array load opcode based on the array expression's type.
fn array_load_op(array: &JcExpr, cm: &CheckedMethod) -> u8 {
    if let Some(ty) = resolve_expr_type(array, cm) {
        if ty == JcType::ShortArray {
            return SALOAD;
        }
    }
    BALOAD // default to byte array
}

/// Determine the array store opcode based on the array expression's type.
fn array_store_op(array: &JcExpr, cm: &CheckedMethod) -> u8 {
    if let Some(ty) = resolve_expr_type(array, cm) {
        if ty == JcType::ShortArray {
            return SASTORE;
        }
    }
    BASTORE // default to byte array
}

/// Resolve the type of an expression for codegen purposes.
fn resolve_expr_type(expr: &JcExpr, cm: &CheckedMethod) -> Option<JcType> {
    match expr {
        JcExpr::Var(name) => cm.local_type(name),
        JcExpr::NewByteArray(_) => Some(JcType::ByteArray),
        JcExpr::NewShortArray(_) => Some(JcType::ShortArray),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;
    use crate::ir::JcMethod;

    fn make_static_class(method: JcMethod) -> JcClass {
        JcClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            fields: vec![],
            methods: vec![method],
        }
    }

    #[test]
    fn compile_constant_return() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(42)))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert_eq!(compiled.methods.len(), 1);
        // bspush 42, sreturn
        assert_eq!(compiled.methods[0], vec![BSPUSH, 42, SRETURN]);
    }

    #[test]
    fn compile_small_constants() {
        // sconst_0 (literal 0)
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert_eq!(compiled.methods[0], vec![SCONST_0, SRETURN]);
    }

    #[test]
    fn compile_sconst_m1() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(-1)))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert_eq!(compiled.methods[0], vec![SCONST_M1, SRETURN]);
    }

    #[test]
    fn compile_sconst_5() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(5)))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert_eq!(compiled.methods[0], vec![SCONST_5, SRETURN]);
    }

    #[test]
    fn compile_large_constant() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::Lit(1000)))],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // sspush 0x03 0xE8, sreturn
        assert_eq!(
            compiled.methods[0],
            vec![SSPUSH, 0x03, 0xE8, SRETURN]
        );
    }

    #[test]
    fn compile_addition() {
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
        let compiled = compile_class(&cls).unwrap();
        // sconst_3, sconst_2, sadd, sreturn
        assert_eq!(
            compiled.methods[0],
            vec![0x06, 0x05, SADD, SRETURN]
        );
    }

    #[test]
    fn compile_negation() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![
                (String::from("x"), JcType::Short),
            ],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(7),
                },
                JcStmt::Return(Some(JcExpr::Neg(Box::new(JcExpr::Var(String::from("x")))))),
            ],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // bspush 7, sstore_0, sload_0, sneg, sreturn
        assert_eq!(
            compiled.methods[0],
            vec![BSPUSH, 7, SSTORE_0, SLOAD_0, SNEG, SRETURN]
        );
    }

    #[test]
    fn compile_local_variables() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![
                (String::from("x"), JcType::Short),
                (String::from("y"), JcType::Short),
            ],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(3),
                },
                JcStmt::Let {
                    name: String::from("y"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(2),
                },
                JcStmt::Return(Some(JcExpr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(JcExpr::Var(String::from("x"))),
                    right: Box::new(JcExpr::Var(String::from("y"))),
                })),
            ],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // sconst_3, sstore_0, sconst_2, sstore_1, sload_0, sload_1, sadd, sreturn
        assert_eq!(
            compiled.methods[0],
            vec![0x06, SSTORE_0, 0x05, SSTORE_0 + 1, SLOAD_0, SLOAD_0 + 1, SADD, SRETURN]
        );
    }

    #[test]
    fn compile_void_return() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Void,
            locals: vec![],
            body: vec![JcStmt::Return(None)],
            is_static: true,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert_eq!(compiled.methods[0], vec![RETURN]);
    }

    #[test]
    fn compile_if_else() {
        // if x == 0 { return 1 } else { return 2 }
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(0),
                },
                JcStmt::If {
                    cond: Condition::Eq(
                        JcExpr::Var(String::from("x")),
                        JcExpr::Lit(0),
                    ),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
                },
            ],
            is_static: true,
        };
        let cls = make_static_class(method);
        let result = compile_class(&cls);
        assert!(result.is_ok());
        let compiled = result.unwrap();
        // Verify the bytecodes contain branch instructions.
        let bc = &compiled.methods[0];
        assert!(bc.contains(&IF_SCMPNE));
        assert!(bc.contains(&GOTO));
    }

    #[test]
    fn compile_while_loop() {
        // sum 1..5: i=1; sum=0; while(i != 6) { sum = sum + i; i = i + 1; } return sum;
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
                    cond: Condition::Ne(
                        JcExpr::Var(String::from("i")),
                        JcExpr::Lit(6),
                    ),
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
        };
        let cls = make_static_class(method);
        let result = compile_class(&cls);
        assert!(result.is_ok());
        let compiled = result.unwrap();
        let bc = &compiled.methods[0];
        // Should contain a goto (backward branch for loop) and if_scmpeq (condition negation of Ne).
        assert!(bc.contains(&GOTO));
        assert!(bc.contains(&IF_SCMPEQ));
    }
}
