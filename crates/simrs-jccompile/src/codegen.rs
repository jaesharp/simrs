//! Bytecode code generator for the JVA IR.
//!
//! Compiles a type-checked [`JcClass`](crate::ir::JcClass) into JCVM
//! bytecodes that can be loaded via
//! [`build_cap_blob`](simrs_jcvm::cap::build_cap_blob).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::check::{CheckedMethod, check_class};
use crate::error::CompileError;
use crate::ir::{BinOp, Condition, JcClass, JcExpr, JcStmt, LValue};
use crate::types::JcType;

use simrs_jcvm_opcodes::{
    AALOAD, AASTORE, ALOAD, ALOAD_0, ANEWARRAY, ARETURN, ARRAY_TYPE_BYTE, ARRAY_TYPE_INT,
    ARRAY_TYPE_SHORT, ARRAYLENGTH, ASTORE, ASTORE_0, BALOAD, BASTORE, BSPUSH, GETFIELD_A,
    GETFIELD_B, GETFIELD_I, GETFIELD_S, GOTO, I2B, I2S, IADD, IALOAD, IAND, IASTORE, ICMP,
    ICONST_0, IDIV, IF_ACMPEQ, IF_ACMPNE, IF_SCMPEQ, IF_SCMPGE, IF_SCMPGT, IF_SCMPLE, IF_SCMPLT,
    IF_SCMPNE, IFEQ, IFGE, IFGT, IFLE, IFLT, IFNE, IFNONNULL, IFNULL, IINC, IIPUSH, ILOAD, ILOAD_0,
    ILOAD_3, ILOOKUPSWITCH, IMUL, INEG, INSTANCEOF, INVOKESTATIC, IOR, IREM, IRETURN, ISHL, ISHR,
    ISTORE, ISTORE_0, ISTORE_3, ISUB, IUSHR, IXOR, NEWARRAY, PUTFIELD_A, PUTFIELD_B, PUTFIELD_I,
    PUTFIELD_S, RETURN, S2B, S2I, SADD, SALOAD, SAND, SASTORE, SCONST_0, SCONST_5, SCONST_M1, SDIV,
    SINC, SLOAD, SLOAD_0, SLOAD_3, SLOOKUPSWITCH, SMUL, SNEG, SOR, SREM, SRETURN, SSHL, SSHR,
    SSPUSH, SSTORE, SSTORE_0, SSTORE_3, SSUB, SUSHR, SXOR,
};

// =========================================================================
// Compiled class
// =========================================================================

/// A compiled class ready for loading into the JCVM.
#[derive(Debug, Clone)]
pub struct CompiledClass {
    /// Application Identifier.
    pub aid: Vec<u8>,
    /// Bytecodes for each method, in declaration order.
    pub methods: Vec<Vec<u8>>,
}

// =========================================================================
// Bytecode metadata for safe peephole optimization
// =========================================================================

/// Metadata emitted alongside bytecodes for safe peephole optimization.
///
/// The peephole optimizer needs to know about branch targets and basic block
/// boundaries so it can avoid corrupting control flow when replacing or
/// removing instructions.
#[derive(Debug, Clone)]
pub struct BytecodeMetadata {
    /// PCs that are branch targets (must maintain instruction alignment).
    pub branch_targets: Vec<u16>,
    /// Basic blocks: (`start_pc`, `end_pc`) ranges where `end_pc` is exclusive.
    pub basic_blocks: Vec<(u16, u16)>,
    /// Branch instructions with offset info for repatching.
    pub branches: Vec<BranchInfo>,
}

/// Information about a single branch instruction in the bytecode stream.
#[derive(Debug, Clone)]
pub struct BranchInfo {
    /// PC of the branch opcode.
    pub opcode_pc: u16,
    /// PC of the offset byte(s) within the instruction.
    pub offset_pc: u16,
    /// Whether this is a wide (2-byte) offset.
    pub wide: bool,
    /// Target PC (resolved).
    pub target_pc: u16,
}

/// Compute basic block boundaries from branch targets and branch instructions.
///
/// A basic block starts:
///   - at PC 0 (method entry)
///   - at every branch target
///   - at the instruction after every branch instruction
///
/// A basic block ends:
///   - just before the next basic block start
///   - at the end of the bytecode stream
pub fn compute_basic_blocks(
    branch_targets: &[u16],
    branches: &[BranchInfo],
    code_len: usize,
) -> Vec<(u16, u16)> {
    if code_len == 0 {
        return Vec::new();
    }

    // Collect all block-start PCs.
    let mut starts = Vec::new();
    starts.push(0u16);

    // Every branch target starts a new block.
    for &target in branch_targets {
        starts.push(target);
    }

    // The instruction after each branch starts a new block.
    for branch in branches {
        let after_branch = if branch.wide {
            // opcode + 2-byte offset = 3 bytes
            branch.opcode_pc + 3
        } else {
            // opcode + 1-byte offset = 2 bytes
            branch.opcode_pc + 2
        };
        #[allow(clippy::cast_possible_truncation)]
        let code_len_u16 = code_len as u16;
        if after_branch < code_len_u16 {
            starts.push(after_branch);
        }
    }

    starts.sort_unstable();
    starts.dedup();

    // Build (start, end) pairs.
    let mut blocks = Vec::new();
    for i in 0..starts.len() {
        let start = starts[i];
        #[allow(clippy::cast_possible_truncation)]
        let end = if i + 1 < starts.len() {
            starts[i + 1]
        } else {
            code_len as u16
        };
        if start < end {
            blocks.push((start, end));
        }
    }
    blocks
}

/// Compile a class from IR to bytecode.
///
/// 1. Runs IR optimization passes (constant folding, DCE, strength reduction).
/// 2. Type-checks the optimized class.
/// 3. Compiles each method body to bytecodes.
/// 4. Runs peephole optimization on each method's bytecodes.
/// 5. Returns AID + method bytecodes.
///
/// # Errors
///
/// Returns compilation errors from type checking or code generation.
pub fn compile_class(class: &JcClass) -> Result<CompiledClass, Vec<CompileError>> {
    use crate::config::OptConfig;
    let (compiled, _report) = compile_class_with_config(class, &OptConfig::full())?;
    Ok(compiled)
}

/// Compile a class with explicit optimization configuration.
///
/// Returns the compiled class and an optimization report.
///
/// # Errors
///
/// Returns compilation errors from type checking or code generation.
pub fn compile_class_with_config(
    class: &JcClass,
    config: &crate::config::OptConfig,
) -> Result<(CompiledClass, crate::config::OptReport), Vec<CompileError>> {
    use crate::config::{MethodReport, OptReport};

    let optimized = crate::optimize::optimize_ir_with_config(class, &config.ir);
    let checked = check_class(&optimized)?;

    let mut methods = Vec::new();
    let mut method_reports = Vec::new();
    let mut errors = Vec::new();

    for cm in &checked.methods {
        match compile_method(cm) {
            Ok((mut bytecode, mut metadata)) => {
                let bytes_before = bytecode.len();
                let changes = crate::optimize::peephole_optimize_with_config(
                    &mut bytecode,
                    &mut metadata,
                    &config.peephole,
                );
                method_reports.push(MethodReport {
                    peephole_changes: changes,
                    bytes_before,
                    bytes_after: bytecode.len(),
                });
                methods.push(bytecode);
            }
            Err(e) => errors.push(CompileError {
                method: cm.method.name.clone(),
                message: e,
            }),
        }
    }

    if errors.is_empty() {
        let report = OptReport {
            ir_iterations: 0, // TODO: return from optimize_ir_with_config
            methods: method_reports,
        };
        Ok((
            CompiledClass {
                aid: checked.aid,
                methods,
            },
            report,
        ))
    } else {
        Err(errors)
    }
}

// =========================================================================
// Label / forward-ref infrastructure
// =========================================================================

/// A forward reference to be patched after the first pass.
struct ForwardRef {
    /// Position of the offset byte(s) in the bytecode buffer.
    patch_pos: usize,
    /// Position of the opcode (for computing relative offset).
    opcode_pos: usize,
    /// Target label ID.
    label: usize,
    /// Whether this is a 2-byte (i16) offset (for switch instructions).
    wide: bool,
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

    /// Emit a 2-byte big-endian value.
    fn emit_u16(&mut self, val: u16) {
        let bytes = val.to_be_bytes();
        self.code.push(bytes[0]);
        self.code.push(bytes[1]);
    }

    /// Emit a 2-byte big-endian signed value.
    fn emit_i16(&mut self, val: i16) {
        let bytes = val.to_be_bytes();
        self.code.push(bytes[0]);
        self.code.push(bytes[1]);
    }

    /// Emit a 4-byte big-endian signed value.
    fn emit_i32(&mut self, val: i32) {
        let bytes = val.to_be_bytes();
        for b in bytes {
            self.code.push(b);
        }
    }

    /// Emit a branch instruction with a label reference (1-byte offset).
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
            wide: false,
        });
    }

    /// Emit a 2-byte wide branch offset placeholder for switch instructions.
    /// `base_pos` is the position of the switch opcode for offset calculation.
    fn emit_wide_branch(&mut self, label: usize, base_pos: usize) {
        let patch_pos = self.code.len();
        self.emit(0);
        self.emit(0); // 2-byte placeholder
        self.forward_refs.push(ForwardRef {
            patch_pos,
            opcode_pos: base_pos,
            label,
            wide: true,
        });
    }

    /// Emit a `goto` instruction with a label reference.
    fn emit_goto(&mut self, label: usize) {
        self.emit_branch(GOTO, label);
    }

    /// Current bytecode position.
    const fn pos(&self) -> usize {
        self.code.len()
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
            if fref.wide {
                let Ok(offset_i16) = i16::try_from(offset) else {
                    return Err(format!(
                        "wide branch offset {offset} out of i16 range at position {}",
                        fref.opcode_pos
                    ));
                };
                let bytes = offset_i16.to_be_bytes();
                self.code[fref.patch_pos] = bytes[0];
                self.code[fref.patch_pos + 1] = bytes[1];
            } else {
                let Ok(offset_i8) = i8::try_from(offset) else {
                    return Err(format!(
                        "branch offset {offset} out of i8 range at position {}",
                        fref.opcode_pos
                    ));
                };
                self.code[fref.patch_pos] = offset_i8.cast_unsigned();
            }
        }
        Ok(())
    }

    /// Extract bytecode metadata after `resolve()` has been called.
    ///
    /// This captures branch targets, branch instruction info, and basic block
    /// boundaries that the peephole optimizer needs for safe code patching.
    fn metadata(&self) -> BytecodeMetadata {
        let mut branch_targets = Vec::new();
        let mut branches = Vec::new();

        for fref in &self.forward_refs {
            let target = self.label_positions[fref.label].unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let target_u16 = target as u16;
            branch_targets.push(target_u16);
            #[allow(clippy::cast_possible_truncation)]
            branches.push(BranchInfo {
                opcode_pc: fref.opcode_pos as u16,
                offset_pc: fref.patch_pos as u16,
                wide: fref.wide,
                target_pc: target_u16,
            });
        }

        branch_targets.sort_unstable();
        branch_targets.dedup();

        let basic_blocks = compute_basic_blocks(&branch_targets, &branches, self.code.len());

        BytecodeMetadata {
            branch_targets,
            basic_blocks,
            branches,
        }
    }
}

// =========================================================================
// Method compilation
// =========================================================================

/// Compile a single method to bytecodes and emit metadata for the optimizer.
fn compile_method(cm: &CheckedMethod) -> Result<(Vec<u8>, BytecodeMetadata), String> {
    let mut cg = MethodCodegen::new();

    for stmt in &cm.method.body {
        emit_stmt(&mut cg, stmt, cm)?;
    }

    cg.resolve()?;
    let metadata = cg.metadata();
    Ok((cg.code, metadata))
}

// =========================================================================
// Statement emission
// =========================================================================

/// Emit bytecodes for a statement.
fn emit_stmt(cg: &mut MethodCodegen, stmt: &JcStmt, cm: &CheckedMethod) -> Result<(), String> {
    match stmt {
        JcStmt::Let { name, init, .. } => {
            emit_expr(cg, init, cm)?;
            emit_store_local(cg, cm, name)?;
            Ok(())
        }
        JcStmt::Assign { target, value } => emit_assign(cg, target, value, cm),
        JcStmt::Return(None) => {
            cg.emit(RETURN);
            Ok(())
        }
        JcStmt::Return(Some(expr)) => {
            emit_expr(cg, expr, cm)?;
            let ret_op = return_opcode_for_type(cm.method.return_ty);
            cg.emit(ret_op);
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
        JcStmt::Switch {
            key,
            cases,
            default,
        } => emit_switch_short(cg, key, cases, default, cm),
        JcStmt::IntSwitch {
            key,
            cases,
            default,
        } => emit_switch_int(cg, key, cases, default, cm),
        JcStmt::Increment { var, amount } => {
            let idx = cm
                .local_index(var)
                .ok_or_else(|| format!("codegen: undefined local `{var}` in increment"))?;
            let ty = cm.local_type(var).unwrap_or(JcType::Short);
            if ty.is_int() {
                cg.emit(IINC);
            } else {
                cg.emit(SINC);
            }
            cg.emit(idx);
            #[allow(clippy::cast_sign_loss)]
            cg.emit(*amount as u8);
            Ok(())
        }
    }
}

/// Emit a short switch statement using `slookupswitch`.
fn emit_switch_short(
    cg: &mut MethodCodegen,
    key: &JcExpr,
    cases: &[(i16, Vec<JcStmt>)],
    default: &[JcStmt],
    cm: &CheckedMethod,
) -> Result<(), String> {
    emit_expr(cg, key, cm)?;

    let switch_pos = cg.pos();
    cg.emit(SLOOKUPSWITCH);

    // Allocate labels for each case body and default.
    let default_label = cg.new_label();
    let end_label = cg.new_label();

    // default offset (2 bytes, patched later)
    cg.emit_wide_branch(default_label, switch_pos);

    // npairs (2 bytes)
    #[allow(clippy::cast_possible_truncation)]
    let npairs = cases.len() as u16;
    cg.emit_u16(npairs);

    // For each case: match_value(2) + offset(2)
    let mut case_labels = Vec::new();
    for (val, _body) in cases {
        cg.emit_i16(*val);
        let case_label = cg.new_label();
        cg.emit_wide_branch(case_label, switch_pos);
        case_labels.push(case_label);
    }

    // Emit case bodies.
    for (i, (_val, body)) in cases.iter().enumerate() {
        cg.bind_label(case_labels[i]);
        for s in body {
            emit_stmt(cg, s, cm)?;
        }
        cg.emit_goto(end_label);
    }

    // Default body.
    cg.bind_label(default_label);
    for s in default {
        emit_stmt(cg, s, cm)?;
    }

    cg.bind_label(end_label);
    Ok(())
}

/// Emit an int switch statement using `ilookupswitch`.
fn emit_switch_int(
    cg: &mut MethodCodegen,
    key: &JcExpr,
    cases: &[(i32, Vec<JcStmt>)],
    default: &[JcStmt],
    cm: &CheckedMethod,
) -> Result<(), String> {
    emit_expr(cg, key, cm)?;

    let switch_pos = cg.pos();
    cg.emit(ILOOKUPSWITCH);

    let default_label = cg.new_label();
    let end_label = cg.new_label();

    // default offset (2 bytes)
    cg.emit_wide_branch(default_label, switch_pos);

    // npairs (2 bytes)
    #[allow(clippy::cast_possible_truncation)]
    let npairs = cases.len() as u16;
    cg.emit_u16(npairs);

    // For each case: match_value(4) + offset(2)
    let mut case_labels = Vec::new();
    for (val, _body) in cases {
        cg.emit_i32(*val);
        let case_label = cg.new_label();
        cg.emit_wide_branch(case_label, switch_pos);
        case_labels.push(case_label);
    }

    // Emit case bodies.
    for (i, (_val, body)) in cases.iter().enumerate() {
        cg.bind_label(case_labels[i]);
        for s in body {
            emit_stmt(cg, s, cm)?;
        }
        cg.emit_goto(end_label);
    }

    // Default body.
    cg.bind_label(default_label);
    for s in default {
        emit_stmt(cg, s, cm)?;
    }

    cg.bind_label(end_label);
    Ok(())
}

// =========================================================================
// Condition emission
// =========================================================================

/// Emit the negated condition (branch to `target` when condition is FALSE).
fn emit_condition_negate(
    cg: &mut MethodCodegen,
    cond: &Condition,
    target: usize,
    cm: &CheckedMethod,
) -> Result<(), String> {
    match cond {
        // --- Short comparisons: negate by swapping the branch opcode ---
        Condition::Eq(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPNE, target);
        }
        Condition::Ne(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPEQ, target);
        }
        Condition::Lt(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPGE, target); // negate: not-lt = ge
        }
        Condition::Ge(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPLT, target); // negate: not-ge = lt
        }
        Condition::Gt(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPLE, target); // negate: not-gt = le
        }
        Condition::Le(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_SCMPGT, target); // negate: not-le = gt
        }

        // --- Null/NonNull ---
        Condition::Null(expr) => {
            emit_expr(cg, expr, cm)?;
            cg.emit_branch(IFNONNULL, target); // negate: not-null = nonnull
        }
        Condition::NonNull(expr) => {
            emit_expr(cg, expr, cm)?;
            cg.emit_branch(IFNULL, target); // negate: not-nonnull = null
        }

        // --- Int comparisons: icmp + if<cond> ---
        // For int comparisons, we emit both operands, then ICMP (which pushes
        // -1, 0, or 1 as a short), then branch using the single-operand
        // ifeq/ifne/iflt/ifge/ifgt/ifle opcodes.
        Condition::IntEq(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit(ICMP);
            cg.emit_branch(IFNE, target); // negate: not-eq = ne
        }
        Condition::IntNe(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit(ICMP);
            cg.emit_branch(IFEQ, target); // negate: not-ne = eq
        }
        Condition::IntLt(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit(ICMP);
            cg.emit_branch(IFGE, target); // negate: not-lt = ge
        }
        Condition::IntGe(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit(ICMP);
            cg.emit_branch(IFLT, target); // negate: not-ge = lt
        }
        Condition::IntGt(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit(ICMP);
            cg.emit_branch(IFLE, target); // negate: not-gt = le
        }
        Condition::IntLe(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit(ICMP);
            cg.emit_branch(IFGT, target); // negate: not-le = gt
        }

        // --- Reference comparisons ---
        Condition::RefEq(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_ACMPNE, target); // negate: not-eq = ne
        }
        Condition::RefNe(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit_branch(IF_ACMPEQ, target); // negate: not-ne = eq
        }
    }
    Ok(())
}

// =========================================================================
// Assignment emission
// =========================================================================

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
            emit_store_local(cg, cm, name)?;
            Ok(())
        }
        LValue::Field { field_name } => {
            // Push `this` (local 0), then value, then putfield.
            emit_aload(cg, 0);
            emit_expr(cg, value, cm)?;
            let offset = cm
                .field_offset(field_name)
                .ok_or_else(|| format!("codegen: undefined field `{field_name}`"))?;
            let field_ty = cm.field_type(field_name).unwrap_or(JcType::Byte);
            let op = putfield_opcode(field_ty);
            cg.emit(op);
            cg.emit(offset);
            Ok(())
        }
        LValue::ArrayElem { array, index } => {
            emit_expr(cg, array, cm)?;
            emit_expr(cg, index, cm)?;
            emit_expr(cg, value, cm)?;
            let store_op = array_store_op(array, cm);
            cg.emit(store_op);
            Ok(())
        }
    }
}

// =========================================================================
// Local variable load/store helpers
// =========================================================================

/// Emit a store instruction for a named local, choosing the opcode based on type.
fn emit_store_local(cg: &mut MethodCodegen, cm: &CheckedMethod, name: &str) -> Result<(), String> {
    let idx = cm
        .local_index(name)
        .ok_or_else(|| format!("codegen: undefined local `{name}`"))?;
    let ty = cm.local_type(name).unwrap_or(JcType::Short);

    if ty.is_int() {
        emit_istore(cg, idx);
    } else if ty.is_reference() {
        emit_astore(cg, idx);
    } else {
        emit_sstore(cg, idx);
    }
    Ok(())
}

/// Emit a load instruction for a named local, choosing the opcode based on type.
fn emit_load_local(cg: &mut MethodCodegen, cm: &CheckedMethod, name: &str) -> Result<(), String> {
    let idx = cm
        .local_index(name)
        .ok_or_else(|| format!("codegen: undefined local `{name}`"))?;
    let ty = cm.local_type(name).unwrap_or(JcType::Short);

    if ty.is_int() {
        emit_iload(cg, idx);
    } else if ty.is_reference() {
        emit_aload(cg, idx);
    } else {
        emit_sload(cg, idx);
    }
    Ok(())
}

/// Emit `sstore` for a given slot index.
fn emit_sstore(cg: &mut MethodCodegen, idx: u8) {
    if idx <= (SSTORE_3 - SSTORE_0) {
        cg.emit(SSTORE_0 + idx);
    } else {
        cg.emit(SSTORE);
        cg.emit(idx);
    }
}

/// Emit `sload` for a given slot index.
fn emit_sload(cg: &mut MethodCodegen, idx: u8) {
    if idx <= (SLOAD_3 - SLOAD_0) {
        cg.emit(SLOAD_0 + idx);
    } else {
        cg.emit(SLOAD);
        cg.emit(idx);
    }
}

/// Emit `iload` for a given slot index.
fn emit_iload(cg: &mut MethodCodegen, idx: u8) {
    if idx <= (ILOAD_3 - ILOAD_0) {
        cg.emit(ILOAD_0 + idx);
    } else {
        cg.emit(ILOAD);
        cg.emit(idx);
    }
}

/// Emit `istore` for a given slot index.
fn emit_istore(cg: &mut MethodCodegen, idx: u8) {
    if idx <= (ISTORE_3 - ISTORE_0) {
        cg.emit(ISTORE_0 + idx);
    } else {
        cg.emit(ISTORE);
        cg.emit(idx);
    }
}

/// Emit `aload` for a given slot index.
fn emit_aload(cg: &mut MethodCodegen, idx: u8) {
    if idx <= (ALOAD_0.wrapping_add(3) - ALOAD_0) {
        cg.emit(ALOAD_0 + idx);
    } else {
        cg.emit(ALOAD);
        cg.emit(idx);
    }
}

/// Emit `astore` for a given slot index.
fn emit_astore(cg: &mut MethodCodegen, idx: u8) {
    // ASTORE_0 through ASTORE_0+3 (note: only ASTORE_0 is explicitly defined,
    // but slots 0..3 use the compact form).
    if idx <= 3 {
        cg.emit(ASTORE_0 + idx);
    } else {
        cg.emit(ASTORE);
        cg.emit(idx);
    }
}

// =========================================================================
// Expression emission
// =========================================================================

/// Emit bytecodes for an expression (result pushed onto the stack).
#[allow(clippy::too_many_lines)]
fn emit_expr(cg: &mut MethodCodegen, expr: &JcExpr, cm: &CheckedMethod) -> Result<(), String> {
    match expr {
        JcExpr::Lit(n) => {
            emit_short_lit(cg, *n);
            Ok(())
        }
        JcExpr::IntLit(n) => {
            emit_int_lit(cg, *n);
            Ok(())
        }
        JcExpr::Var(name) => emit_load_local(cg, cm, name),
        JcExpr::SelfField(name) => {
            // Push `this` (local 0), then getfield.
            emit_aload(cg, 0);
            let offset = cm
                .field_offset(name)
                .ok_or_else(|| format!("codegen: undefined field `{name}`"))?;
            let field_ty = cm.field_type(name).unwrap_or(JcType::Byte);
            let op = getfield_opcode(field_ty);
            cg.emit(op);
            cg.emit(offset);
            Ok(())
        }
        JcExpr::BinOp { op, left, right } => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            let opcode = short_binop_opcode(*op);
            cg.emit(opcode);
            Ok(())
        }
        JcExpr::IntBinOp { op, left, right } => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            let opcode = int_binop_opcode(*op);
            cg.emit(opcode);
            Ok(())
        }
        JcExpr::Neg(inner) => {
            emit_expr(cg, inner, cm)?;
            cg.emit(SNEG);
            Ok(())
        }
        JcExpr::IntNeg(inner) => {
            emit_expr(cg, inner, cm)?;
            cg.emit(INEG);
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
        JcExpr::NewIntArray(len) => {
            emit_expr(cg, len, cm)?;
            cg.emit(NEWARRAY);
            cg.emit(ARRAY_TYPE_INT);
            Ok(())
        }
        JcExpr::NewRefArray { length, class_ref } => {
            emit_expr(cg, length, cm)?;
            cg.emit(ANEWARRAY);
            cg.emit_u16(*class_ref);
            Ok(())
        }
        JcExpr::ArrayLength(arr) => {
            emit_expr(cg, arr, cm)?;
            cg.emit(ARRAYLENGTH);
            Ok(())
        }
        JcExpr::Cast { from, to, expr } => {
            emit_expr(cg, expr, cm)?;
            let op = match (*from, *to) {
                (JcType::Short, JcType::Byte) => S2B,
                (JcType::Short, JcType::Int) => S2I,
                (JcType::Int, JcType::Byte) => I2B,
                (JcType::Int, JcType::Short) => I2S,
                _ => return Err(format!("codegen: unsupported cast {from:?} -> {to:?}")),
            };
            cg.emit(op);
            Ok(())
        }
        JcExpr::InstanceOf { expr, class } => {
            emit_expr(cg, expr, cm)?;
            cg.emit(INSTANCEOF);
            let bytes = class.to_be_bytes();
            cg.emit(bytes[0]);
            cg.emit(bytes[1]);
            Ok(())
        }
        JcExpr::IntCompare(left, right) => {
            emit_expr(cg, left, cm)?;
            emit_expr(cg, right, cm)?;
            cg.emit(ICMP);
            Ok(())
        }
    }
}

// =========================================================================
// Literal emission
// =========================================================================

/// Emit a short literal using the most compact encoding.
fn emit_short_lit(cg: &mut MethodCodegen, n: i16) {
    // sconst_m1 (0x02) through sconst_5 (0x08) cover -1..5.
    let lo = i16::from(SCONST_M1) - i16::from(SCONST_0); // -1
    let hi = i16::from(SCONST_5) - i16::from(SCONST_0); // 5
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

/// Emit an int literal using the most compact encoding.
fn emit_int_lit(cg: &mut MethodCodegen, n: i32) {
    // iconst_m1 (0x09) through iconst_5 (0x0F) cover -1..5.
    if (-1..=5).contains(&n) {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let opcode = ICONST_0.wrapping_add_signed(n as i8);
        cg.emit(opcode);
    } else {
        cg.emit(IIPUSH);
        let bytes = n.to_be_bytes();
        for b in bytes {
            cg.emit(b);
        }
    }
}

// =========================================================================
// Opcode selection helpers
// =========================================================================

/// Select the correct short binary operation opcode.
const fn short_binop_opcode(op: BinOp) -> u8 {
    match op {
        BinOp::Add => SADD,
        BinOp::Sub => SSUB,
        BinOp::Mul => SMUL,
        BinOp::Div => SDIV,
        BinOp::Rem => SREM,
        BinOp::And => SAND,
        BinOp::Or => SOR,
        BinOp::Xor => SXOR,
        BinOp::Shl => SSHL,
        BinOp::Shr => SSHR,
        BinOp::Ushr => SUSHR,
    }
}

/// Select the correct int binary operation opcode.
const fn int_binop_opcode(op: BinOp) -> u8 {
    match op {
        BinOp::Add => IADD,
        BinOp::Sub => ISUB,
        BinOp::Mul => IMUL,
        BinOp::Div => IDIV,
        BinOp::Rem => IREM,
        BinOp::And => IAND,
        BinOp::Or => IOR,
        BinOp::Xor => IXOR,
        BinOp::Shl => ISHL,
        BinOp::Shr => ISHR,
        BinOp::Ushr => IUSHR,
    }
}

/// Select the return opcode for a given return type.
const fn return_opcode_for_type(ty: JcType) -> u8 {
    match ty {
        JcType::Void => RETURN,
        JcType::Int => IRETURN,
        JcType::Instance
        | JcType::ByteArray
        | JcType::ShortArray
        | JcType::IntArray
        | JcType::RefArray => ARETURN,
        JcType::Byte | JcType::Short | JcType::Boolean => SRETURN,
    }
}

/// Select the getfield opcode for a given field type.
const fn getfield_opcode(ty: JcType) -> u8 {
    match ty {
        JcType::Byte | JcType::Boolean | JcType::Void => GETFIELD_B,
        JcType::Short => GETFIELD_S,
        JcType::Int => GETFIELD_I,
        JcType::Instance
        | JcType::ByteArray
        | JcType::ShortArray
        | JcType::IntArray
        | JcType::RefArray => GETFIELD_A,
    }
}

/// Select the putfield opcode for a given field type.
const fn putfield_opcode(ty: JcType) -> u8 {
    match ty {
        JcType::Byte | JcType::Boolean | JcType::Void => PUTFIELD_B,
        JcType::Short => PUTFIELD_S,
        JcType::Int => PUTFIELD_I,
        JcType::Instance
        | JcType::ByteArray
        | JcType::ShortArray
        | JcType::IntArray
        | JcType::RefArray => PUTFIELD_A,
    }
}

/// Determine the array load opcode based on the array expression's type.
fn array_load_op(array: &JcExpr, cm: &CheckedMethod) -> u8 {
    if let Some(ty) = resolve_expr_type(array, cm) {
        return match ty {
            JcType::ShortArray => SALOAD,
            JcType::IntArray => IALOAD,
            JcType::RefArray => AALOAD,
            _ => BALOAD,
        };
    }
    BALOAD // default to byte array
}

/// Determine the array store opcode based on the array expression's type.
fn array_store_op(array: &JcExpr, cm: &CheckedMethod) -> u8 {
    if let Some(ty) = resolve_expr_type(array, cm) {
        return match ty {
            JcType::ShortArray => SASTORE,
            JcType::IntArray => IASTORE,
            JcType::RefArray => AASTORE,
            _ => BASTORE,
        };
    }
    BASTORE // default to byte array
}

/// Resolve the type of an expression for codegen purposes.
fn resolve_expr_type(expr: &JcExpr, cm: &CheckedMethod) -> Option<JcType> {
    match expr {
        JcExpr::Var(name) => cm.local_type(name),
        JcExpr::SelfField(name) => cm.field_type(name),
        JcExpr::NewByteArray(_) => Some(JcType::ByteArray),
        JcExpr::NewShortArray(_) => Some(JcType::ShortArray),
        JcExpr::NewIntArray(_) => Some(JcType::IntArray),
        JcExpr::NewRefArray { .. } => Some(JcType::RefArray),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::JcMethod;
    use alloc::boxed::Box;
    use alloc::vec;

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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
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
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // sspush 0x03 0xE8, sreturn
        assert_eq!(compiled.methods[0], vec![SSPUSH, 0x03, 0xE8, SRETURN]);
    }

    #[test]
    fn compile_addition() {
        // Use a variable operand so the optimizer cannot fold the addition.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("a"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("a"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Lit(2)),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // sload_0, sconst_2, sadd, sreturn
        assert_eq!(compiled.methods[0], vec![SLOAD_0, 0x05, SADD, SRETURN]);
    }

    #[test]
    fn compile_negation() {
        // Use a parameter so the store+load sequence does not appear.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::Neg(Box::new(JcExpr::Var(
                String::from("x"),
            )))))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // sload_0, sneg, sreturn
        assert_eq!(compiled.methods[0], vec![SLOAD_0, SNEG, SRETURN]);
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
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // sconst_3, sstore_0, sconst_2, sstore_1, sload_0, sload_1, sadd, sreturn
        assert_eq!(
            compiled.methods[0],
            vec![
                0x06,
                SSTORE_0,
                0x05,
                SSTORE_0 + 1,
                SLOAD_0,
                SLOAD_0 + 1,
                SADD,
                SRETURN
            ]
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
            constant_time: false,
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
                    cond: Condition::Eq(JcExpr::Var(String::from("x")), JcExpr::Lit(0)),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(2)))],
                },
            ],
            is_static: true,
            constant_time: false,
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
        let result = compile_class(&cls);
        assert!(result.is_ok());
        let compiled = result.unwrap();
        let bc = &compiled.methods[0];
        // Should contain a goto (backward branch for loop) and if_scmpeq (condition negation of Ne).
        assert!(bc.contains(&GOTO));
        assert!(bc.contains(&IF_SCMPEQ));
    }

    // --- New tests for extended opcodes ---

    #[test]
    fn compile_int_literal_small() {
        // IntLit(3) should emit iconst_3
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Int,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::IntLit(3)))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // iconst_3 = 0x0D, ireturn = 0x79
        assert_eq!(compiled.methods[0], vec![ICONST_0 + 3, IRETURN]);
    }

    #[test]
    fn compile_int_literal_large() {
        // IntLit(100_000) should emit iipush + 4 bytes
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Int,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::IntLit(100_000)))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        let bytes = 100_000_i32.to_be_bytes();
        assert_eq!(
            compiled.methods[0],
            vec![0x14, bytes[0], bytes[1], bytes[2], bytes[3], 0x79]
        );
    }

    #[test]
    fn compile_int_add() {
        // Use a variable operand so the optimizer cannot fold the addition.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("a"), JcType::Int)],
            return_ty: JcType::Int,
            locals: vec![(String::from("a"), JcType::Int)],
            body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
                op: BinOp::Add,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::IntLit(2)),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // iload_0, iconst_2, iadd, ireturn
        assert_eq!(
            compiled.methods[0],
            vec![ILOAD_0, ICONST_0 + 2, IADD, IRETURN]
        );
    }

    #[test]
    fn compile_int_negation() {
        // Use a variable so the optimizer cannot fold the negation.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Int)],
            return_ty: JcType::Int,
            locals: vec![(String::from("x"), JcType::Int)],
            body: vec![JcStmt::Return(Some(JcExpr::IntNeg(Box::new(JcExpr::Var(
                String::from("x"),
            )))))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert_eq!(compiled.methods[0], vec![ILOAD_0, INEG, IRETURN]);
    }

    #[test]
    fn compile_short_bitwise_and() {
        // Use a variable operand to prevent constant folding.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("a"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("a"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::And,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Lit(3)),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&SAND));
    }

    #[test]
    fn compile_short_bitwise_or_xor() {
        // Use variable operands to prevent constant folding.
        let method = JcMethod {
            name: String::from("f"),
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
                op: BinOp::Or,
                left: Box::new(JcExpr::BinOp {
                    op: BinOp::Xor,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                }),
                right: Box::new(JcExpr::Lit(1)),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&SXOR));
        assert!(compiled.methods[0].contains(&SOR));
    }

    #[test]
    fn compile_short_shifts() {
        // Use a variable operand to prevent constant folding.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("a"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("a"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::BinOp {
                op: BinOp::Shl,
                left: Box::new(JcExpr::Var(String::from("a"))),
                right: Box::new(JcExpr::Lit(3)),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&SSHL));
    }

    #[test]
    fn compile_cast_s2b() {
        // Use a variable operand to prevent the optimizer from folding the cast.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Short)],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::Cast {
                from: JcType::Short,
                to: JcType::Byte,
                expr: Box::new(JcExpr::Var(String::from("x"))),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&S2B));
    }

    #[test]
    fn compile_cast_s2i() {
        // Use a variable operand to prevent the optimizer from folding the cast.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Short)],
            return_ty: JcType::Int,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![JcStmt::Return(Some(JcExpr::Cast {
                from: JcType::Short,
                to: JcType::Int,
                expr: Box::new(JcExpr::Var(String::from("x"))),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&S2I));
        assert!(compiled.methods[0].contains(&IRETURN));
    }

    #[test]
    fn compile_cast_i2s() {
        // Use a variable operand to prevent the optimizer from folding the cast.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Int)],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Int)],
            body: vec![JcStmt::Return(Some(JcExpr::Cast {
                from: JcType::Int,
                to: JcType::Short,
                expr: Box::new(JcExpr::Var(String::from("x"))),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&I2S));
    }

    #[test]
    fn compile_cast_i2b() {
        // Use a variable operand to prevent the optimizer from folding the cast.
        let method = JcMethod {
            name: String::from("f"),
            params: vec![(String::from("x"), JcType::Int)],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Int)],
            body: vec![JcStmt::Return(Some(JcExpr::Cast {
                from: JcType::Int,
                to: JcType::Byte,
                expr: Box::new(JcExpr::Var(String::from("x"))),
            }))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&I2B));
    }

    #[test]
    fn compile_condition_lt() {
        // if x < 5 { return 1 } else { return 0 }
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(3),
                },
                JcStmt::If {
                    cond: Condition::Lt(JcExpr::Var(String::from("x")), JcExpr::Lit(5)),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
                },
            ],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // Negation of Lt is Ge
        assert!(compiled.methods[0].contains(&IF_SCMPGE));
    }

    #[test]
    fn compile_condition_gt() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(3),
                },
                JcStmt::If {
                    cond: Condition::Gt(JcExpr::Var(String::from("x")), JcExpr::Lit(5)),
                    then_body: vec![JcStmt::Return(Some(JcExpr::Lit(1)))],
                    else_body: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
                },
            ],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        // Negation of Gt is Le
        assert!(compiled.methods[0].contains(&IF_SCMPLE));
    }

    #[test]
    fn compile_sinc() {
        // x = 0; sinc x, 5; return x
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
                JcStmt::Increment {
                    var: String::from("x"),
                    amount: 5,
                },
                JcStmt::Return(Some(JcExpr::Var(String::from("x")))),
            ],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&SINC));
    }

    #[test]
    fn compile_int_compare() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::IntCompare(
                Box::new(JcExpr::IntLit(3)),
                Box::new(JcExpr::IntLit(5)),
            )))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&ICMP));
    }

    #[test]
    fn compile_instanceof() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("obj"), JcType::Instance)],
            body: vec![
                JcStmt::Let {
                    name: String::from("obj"),
                    ty: JcType::Instance,
                    init: JcExpr::IntLit(0), // placeholder -- null-ish
                },
                JcStmt::Return(Some(JcExpr::InstanceOf {
                    expr: Box::new(JcExpr::Var(String::from("obj"))),
                    class: 0x0001,
                })),
            ],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&INSTANCEOF));
    }

    #[test]
    fn compile_slookupswitch() {
        // switch(x) { case 1: return 10; case 2: return 20; default: return 0; }
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![(String::from("x"), JcType::Short)],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Short,
                    init: JcExpr::Lit(1),
                },
                JcStmt::Switch {
                    key: JcExpr::Var(String::from("x")),
                    cases: vec![
                        (1, vec![JcStmt::Return(Some(JcExpr::Lit(10)))]),
                        (2, vec![JcStmt::Return(Some(JcExpr::Lit(20)))]),
                    ],
                    default: vec![JcStmt::Return(Some(JcExpr::Lit(0)))],
                },
            ],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&SLOOKUPSWITCH));
    }

    #[test]
    fn compile_ireturn() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Int,
            locals: vec![],
            body: vec![JcStmt::Return(Some(JcExpr::IntLit(42)))],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&IRETURN));
    }

    #[test]
    fn compile_int_binop_all() {
        // Use variable operands to prevent constant folding.
        for (op, expected) in [
            (BinOp::Add, IADD),
            (BinOp::Sub, ISUB),
            (BinOp::Mul, IMUL),
            (BinOp::Div, IDIV),
            (BinOp::Rem, IREM),
            (BinOp::And, IAND),
            (BinOp::Or, IOR),
            (BinOp::Xor, IXOR),
            (BinOp::Shl, ISHL),
            (BinOp::Shr, ISHR),
            (BinOp::Ushr, IUSHR),
        ] {
            let method = JcMethod {
                name: String::from("f"),
                params: vec![
                    (String::from("a"), JcType::Int),
                    (String::from("b"), JcType::Int),
                ],
                return_ty: JcType::Int,
                locals: vec![
                    (String::from("a"), JcType::Int),
                    (String::from("b"), JcType::Int),
                ],
                body: vec![JcStmt::Return(Some(JcExpr::IntBinOp {
                    op,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                }))],
                is_static: true,
                constant_time: false,
            };
            let cls = make_static_class(method);
            let compiled = compile_class(&cls).unwrap();
            assert!(
                compiled.methods[0].contains(&expected),
                "expected opcode 0x{expected:02X} for {op:?}"
            );
        }
    }

    #[test]
    fn compile_short_binop_all() {
        // Use variable operands to prevent constant folding.
        for (op, expected) in [
            (BinOp::Add, SADD),
            (BinOp::Sub, SSUB),
            (BinOp::Mul, SMUL),
            (BinOp::Div, SDIV),
            (BinOp::Rem, SREM),
            (BinOp::And, SAND),
            (BinOp::Or, SOR),
            (BinOp::Xor, SXOR),
            (BinOp::Shl, SSHL),
            (BinOp::Shr, SSHR),
            (BinOp::Ushr, SUSHR),
        ] {
            let method = JcMethod {
                name: String::from("f"),
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
                    op,
                    left: Box::new(JcExpr::Var(String::from("a"))),
                    right: Box::new(JcExpr::Var(String::from("b"))),
                }))],
                is_static: true,
                constant_time: false,
            };
            let cls = make_static_class(method);
            let compiled = compile_class(&cls).unwrap();
            assert!(
                compiled.methods[0].contains(&expected),
                "expected opcode 0x{expected:02X} for {op:?}"
            );
        }
    }

    #[test]
    fn compile_new_int_array() {
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Short,
            locals: vec![],
            body: vec![
                JcStmt::Expr(JcExpr::NewIntArray(Box::new(JcExpr::Lit(5)))),
                JcStmt::Return(Some(JcExpr::Lit(0))),
            ],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&NEWARRAY));
        assert!(compiled.methods[0].contains(&ARRAY_TYPE_INT));
    }

    #[test]
    fn compile_int_local_store_load() {
        // Verify int locals use iload/istore
        let method = JcMethod {
            name: String::from("f"),
            params: vec![],
            return_ty: JcType::Int,
            locals: vec![(String::from("x"), JcType::Int)],
            body: vec![
                JcStmt::Let {
                    name: String::from("x"),
                    ty: JcType::Int,
                    init: JcExpr::IntLit(42),
                },
                JcStmt::Return(Some(JcExpr::Var(String::from("x")))),
            ],
            is_static: true,
            constant_time: false,
        };
        let cls = make_static_class(method);
        let compiled = compile_class(&cls).unwrap();
        assert!(compiled.methods[0].contains(&ISTORE_0));
        assert!(compiled.methods[0].contains(&ILOAD_0));
    }
}
