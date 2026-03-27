//! Control flow graph analysis for JCVM bytecodes.
//!
//! Builds a CFG from decoded instructions and identifies structured
//! control flow patterns (if/else, while loops) by pattern matching
//! on the graph topology.

use std::collections::{BTreeMap, BTreeSet};

use simrs_jcvm::opcodes;

use super::disasm::{self, Instruction};

/// A basic block in the control flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Index of this block in the blocks array.
    pub index: usize,
    /// PC of the first instruction (inclusive).
    pub start_pc: usize,
    /// PC just past the last instruction (exclusive).
    pub end_pc: usize,
    /// Instructions in this block.
    pub instructions: Vec<Instruction>,
    /// Indices of successor blocks.
    pub successors: Vec<usize>,
    /// Block termination kind.
    pub kind: BlockKind,
}

/// How a basic block terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// Falls through to the next block.
    Sequential,
    /// Conditional branch: two successors (fall-through, then branch target).
    ConditionalJump,
    /// Unconditional branch: one successor.
    UnconditionalJump,
    /// Method return: no successors.
    Return,
}

/// Resolve a 1-byte signed branch offset relative to a given PC.
#[allow(clippy::cast_sign_loss)]
fn resolve_branch(pc: usize, offset_byte: u8) -> usize {
    let signed = offset_byte.cast_signed();
    (pc.cast_signed() + isize::from(signed)).cast_unsigned()
}

/// Resolve a 2-byte signed branch offset relative to a given PC.
#[allow(clippy::cast_sign_loss)]
fn resolve_wide_branch(pc: usize, hi: u8, lo: u8) -> usize {
    let offset = i16::from_be_bytes([hi, lo]);
    (pc.cast_signed() + isize::from(offset)).cast_unsigned()
}

/// Build a control flow graph from a method's bytecodes.
///
/// Returns a vector of basic blocks with successor linkage.
///
/// # Errors
///
/// Returns an error if decoding the bytecodes fails.
#[allow(clippy::too_many_lines)]
pub fn build_cfg(bytecodes: &[u8]) -> Result<Vec<BasicBlock>, String> {
    let instructions = disasm::decode_instructions(bytecodes)?;
    if instructions.is_empty() {
        return Ok(Vec::new());
    }

    // Step 1: Find all block-start PCs.
    let mut block_starts: BTreeSet<usize> = BTreeSet::new();
    block_starts.insert(0);

    for instr in &instructions {
        match instr.opcode {
            opcodes::IF_SCMPEQ | opcodes::IF_SCMPNE | opcodes::GOTO => {
                let target = resolve_branch(instr.pc, instr.args[0]);
                let fall_through = instr.pc + 1 + instr.args.len();
                block_starts.insert(target);
                block_starts.insert(fall_through);
            }
            opcodes::GOTO_W => {
                let target = resolve_wide_branch(instr.pc, instr.args[0], instr.args[1]);
                let fall_through = instr.pc + 1 + instr.args.len();
                block_starts.insert(target);
                block_starts.insert(fall_through);
            }
            opcodes::SRETURN | opcodes::RETURN => {
                let fall_through = instr.pc + 1;
                if fall_through < bytecodes.len() {
                    block_starts.insert(fall_through);
                }
            }
            _ => {}
        }
    }

    // Remove any block starts past the end of bytecodes.
    let block_starts: Vec<usize> = block_starts
        .into_iter()
        .filter(|&pc| pc < bytecodes.len())
        .collect();

    // Build an index: PC -> instruction index.
    let pc_to_idx: BTreeMap<usize, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, instr)| (instr.pc, i))
        .collect();

    // Step 2: Partition instructions into basic blocks.
    let start_to_block: BTreeMap<usize, usize> = block_starts
        .iter()
        .enumerate()
        .map(|(i, &pc)| (pc, i))
        .collect();

    let mut blocks: Vec<BasicBlock> = Vec::new();
    for (block_idx, &start_pc) in block_starts.iter().enumerate() {
        let next_start = block_starts
            .get(block_idx + 1)
            .copied()
            .unwrap_or(bytecodes.len());

        let Some(&start_instr_idx) = pc_to_idx.get(&start_pc) else {
            // Block start points to middle of an instruction -- skip.
            continue;
        };

        let mut block_instrs = Vec::new();
        let mut end_pc = start_pc;
        for instr in &instructions[start_instr_idx..] {
            if instr.pc >= next_start {
                break;
            }
            end_pc = instr.pc + 1 + instr.args.len();
            block_instrs.push(instr.clone());
        }

        let (kind, successors) = classify_block_exit(
            &block_instrs, block_idx, &block_starts, &start_to_block,
        );

        blocks.push(BasicBlock {
            index: block_idx,
            start_pc,
            end_pc,
            instructions: block_instrs,
            successors,
            kind,
        });
    }

    Ok(blocks)
}

/// Classify how a basic block exits based on its last instruction.
fn classify_block_exit(
    instrs: &[Instruction],
    block_idx: usize,
    block_starts: &[usize],
    start_to_block: &BTreeMap<usize, usize>,
) -> (BlockKind, Vec<usize>) {
    let Some(last) = instrs.last() else {
        return (BlockKind::Sequential, Vec::new());
    };

    match last.opcode {
        opcodes::SRETURN | opcodes::RETURN => (BlockKind::Return, Vec::new()),
        opcodes::GOTO => {
            let target = resolve_branch(last.pc, last.args[0]);
            let succ = start_to_block.get(&target).copied().unwrap_or(0);
            (BlockKind::UnconditionalJump, vec![succ])
        }
        opcodes::GOTO_W => {
            let target = resolve_wide_branch(last.pc, last.args[0], last.args[1]);
            let succ = start_to_block.get(&target).copied().unwrap_or(0);
            (BlockKind::UnconditionalJump, vec![succ])
        }
        opcodes::IF_SCMPEQ | opcodes::IF_SCMPNE => {
            let target = resolve_branch(last.pc, last.args[0]);
            let fall_through = last.pc + 1 + last.args.len();
            let fall_succ = start_to_block.get(&fall_through).copied().unwrap_or(0);
            let branch_succ = start_to_block.get(&target).copied().unwrap_or(0);
            (BlockKind::ConditionalJump, vec![fall_succ, branch_succ])
        }
        _ => {
            if block_idx + 1 < block_starts.len() {
                (BlockKind::Sequential, vec![block_idx + 1])
            } else {
                (BlockKind::Sequential, Vec::new())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Structured control flow recovery
// ---------------------------------------------------------------------------

/// A stack-based expression recovered from bytecode operations.
#[derive(Debug, Clone)]
pub enum Expression {
    /// Integer literal (from `sconst_*`, `bspush`, `sspush`).
    Literal(i16),
    /// Local variable load.
    Local(u8),
    /// Binary operation.
    BinOp {
        /// Operator symbol (e.g. "+", "-", "*", "/", "%").
        op: &'static str,
        /// Left operand.
        left: Box<Self>,
        /// Right operand.
        right: Box<Self>,
    },
    /// Unary negation.
    Neg(Box<Self>),
    /// Array element load.
    ArrayLoad {
        /// Array reference expression.
        array: Box<Self>,
        /// Index expression.
        index: Box<Self>,
    },
    /// Field read.
    FieldGet {
        /// Object reference expression.
        obj: Box<Self>,
        /// Field byte offset within the instance.
        offset: u8,
    },
    /// Array length.
    ArrayLength(Box<Self>),
    /// Duplicate of top-of-stack (when we cannot simplify).
    Dup(Box<Self>),
    /// Static method call.
    Invoke {
        /// Package index (0 = same package).
        pkg: u8,
        /// Method index within the package.
        method: u8,
        /// Call arguments.
        args: Vec<Self>,
    },
    /// New object.
    NewObject(u8),
    /// New array.
    NewArray {
        /// Element type name ("byte" or "short").
        elem_type: &'static str,
        /// Array length expression.
        length: Box<Self>,
    },
}

/// A condition recovered from a conditional branch.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Two expressions compared for equality (from `if_scmpeq`).
    Eq(Expression, Expression),
    /// Two expressions compared for inequality (from `if_scmpne`).
    Ne(Expression, Expression),
}

/// A recovered high-level statement.
#[derive(Debug, Clone)]
pub enum Statement {
    /// Local variable assignment: `sstore`.
    Assign(u8, Expression),
    /// Field write: `putfield_b`.
    FieldPut {
        /// Object reference expression.
        obj: Expression,
        /// Field byte offset within the instance.
        offset: u8,
        /// Value to store.
        value: Expression,
    },
    /// Array store.
    ArrayStore {
        /// Array reference expression.
        array: Expression,
        /// Index expression.
        index: Expression,
        /// Value to store.
        value: Expression,
    },
    /// Expression whose result is discarded (pop).
    Discard(Expression),
}

/// High-level structured control flow recovered from the CFG.
#[derive(Debug, Clone)]
pub enum Structure {
    /// A sequence of structures.
    Sequence(Vec<Self>),
    /// An if/else control flow.
    IfElse {
        /// Branch condition.
        condition: Condition,
        /// Then-branch body.
        then_body: Box<Self>,
        /// Else-branch body.
        else_body: Box<Self>,
    },
    /// A while loop.
    While {
        /// Loop continuation condition.
        condition: Condition,
        /// Loop body.
        body: Box<Self>,
    },
    /// Return with an optional expression.
    Return(Option<Expression>),
    /// A simple statement (assignment, array store, etc.).
    Stmt(Statement),
}

/// Simulate the operand stack abstractly to recover expressions from
/// a sequence of instructions.
///
/// Returns `(statements, remaining_stack)`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn recover_expressions(
    instructions: &[Instruction],
) -> (Vec<Statement>, Vec<Expression>) {
    let mut stack: Vec<Expression> = Vec::new();
    let mut stmts: Vec<Statement> = Vec::new();

    for instr in instructions {
        match instr.opcode {
            // Push constants.
            opcodes::SCONST_M1 => stack.push(Expression::Literal(-1)),
            opcodes::SCONST_0 => stack.push(Expression::Literal(0)),
            opcodes::SCONST_1 => stack.push(Expression::Literal(1)),
            opcodes::SCONST_2 => stack.push(Expression::Literal(2)),
            opcodes::SCONST_3 => stack.push(Expression::Literal(3)),
            opcodes::SCONST_4 => stack.push(Expression::Literal(4)),
            opcodes::SCONST_5 => stack.push(Expression::Literal(5)),

            opcodes::BSPUSH => {
                let val = instr.args[0].cast_signed();
                stack.push(Expression::Literal(i16::from(val)));
            }
            opcodes::SSPUSH => {
                let val = i16::from_be_bytes([instr.args[0], instr.args[1]]);
                stack.push(Expression::Literal(val));
            }

            // Load locals.
            opcodes::SLOAD_0 => stack.push(Expression::Local(0)),
            opcodes::SLOAD_1 => stack.push(Expression::Local(1)),
            opcodes::SLOAD_2 => stack.push(Expression::Local(2)),
            opcodes::SLOAD_3 => stack.push(Expression::Local(3)),
            opcodes::SLOAD => stack.push(Expression::Local(instr.args[0])),

            // Store locals.
            opcodes::SSTORE_0 | opcodes::SSTORE_1 | opcodes::SSTORE_2
            | opcodes::SSTORE_3 => {
                let idx = instr.opcode - opcodes::SSTORE_0;
                let expr = stack.pop().unwrap_or(Expression::Literal(0));
                stmts.push(Statement::Assign(idx, expr));
            }
            opcodes::SSTORE => {
                let idx = instr.args[0];
                let expr = stack.pop().unwrap_or(Expression::Literal(0));
                stmts.push(Statement::Assign(idx, expr));
            }

            // Stack manipulation.
            opcodes::POP => {
                if let Some(expr) = stack.pop() {
                    stmts.push(Statement::Discard(expr));
                }
            }
            opcodes::DUP => {
                if let Some(top) = stack.last().cloned() {
                    stack.push(Expression::Dup(Box::new(top)));
                }
            }

            // Arithmetic.
            opcodes::SADD => binary_op(&mut stack, "+"),
            opcodes::SSUB => binary_op(&mut stack, "-"),
            opcodes::SMUL => binary_op(&mut stack, "*"),
            opcodes::SDIV => binary_op(&mut stack, "/"),
            opcodes::SREM => binary_op(&mut stack, "%"),
            opcodes::SNEG => {
                let val = stack.pop().unwrap_or(Expression::Literal(0));
                stack.push(Expression::Neg(Box::new(val)));
            }

            // Array operations.
            opcodes::BALOAD | opcodes::SALOAD => {
                let index = stack.pop().unwrap_or(Expression::Literal(0));
                let array = stack.pop().unwrap_or(Expression::Literal(0));
                stack.push(Expression::ArrayLoad {
                    array: Box::new(array),
                    index: Box::new(index),
                });
            }
            opcodes::BASTORE | opcodes::SASTORE => {
                let value = stack.pop().unwrap_or(Expression::Literal(0));
                let index = stack.pop().unwrap_or(Expression::Literal(0));
                let array = stack.pop().unwrap_or(Expression::Literal(0));
                stmts.push(Statement::ArrayStore { array, index, value });
            }
            opcodes::ARRAYLENGTH => {
                let arr = stack.pop().unwrap_or(Expression::Literal(0));
                stack.push(Expression::ArrayLength(Box::new(arr)));
            }

            // Field access.
            opcodes::GETFIELD_B => {
                let offset = instr.args[0];
                let obj = stack.pop().unwrap_or(Expression::Literal(0));
                stack.push(Expression::FieldGet {
                    obj: Box::new(obj),
                    offset,
                });
            }
            opcodes::PUTFIELD_B => {
                let offset = instr.args[0];
                let value = stack.pop().unwrap_or(Expression::Literal(0));
                let obj = stack.pop().unwrap_or(Expression::Literal(0));
                stmts.push(Statement::FieldPut { obj, offset, value });
            }

            // Object/array creation.
            opcodes::NEW => {
                let type_token = instr.args[0];
                stack.push(Expression::NewObject(type_token));
            }
            opcodes::NEWARRAY => {
                let elem_type = match instr.args[0] {
                    0x0A => "byte",
                    0x0B => "short",
                    _ => "unknown",
                };
                let length = stack.pop().unwrap_or(Expression::Literal(0));
                stack.push(Expression::NewArray {
                    elem_type,
                    length: Box::new(length),
                });
            }

            // Invoke.
            opcodes::INVOKESTATIC => {
                let pkg = instr.args[0];
                let method = instr.args[1];
                stack.push(Expression::Invoke {
                    pkg,
                    method,
                    args: Vec::new(),
                });
            }

            // Return and branch instructions are not handled here --
            // they are processed at the structure recovery level.
            _ => {}
        }
    }

    (stmts, stack)
}

/// Extract a condition from a conditional branch's preceding stack state.
///
/// The conditional branch pops two values and compares them.
pub fn extract_condition(stack: &mut Vec<Expression>, opcode: u8) -> Condition {
    let right = stack.pop().unwrap_or(Expression::Literal(0));
    let left = stack.pop().unwrap_or(Expression::Literal(0));
    if opcode == opcodes::IF_SCMPNE {
        Condition::Ne(left, right)
    } else {
        Condition::Eq(left, right)
    }
}

/// Recover structured control flow from a CFG.
///
/// This performs a simple pattern-matching pass over the basic blocks
/// to identify if/else and while loop structures.
#[must_use]
pub fn recover_structure(blocks: &[BasicBlock]) -> Structure {
    if blocks.is_empty() {
        return Structure::Sequence(Vec::new());
    }

    let mut visited = vec![false; blocks.len()];
    recover_block_range(blocks, 0, &mut visited)
}

/// Recursively recover structured control flow starting from a given block.
fn recover_block_range(
    blocks: &[BasicBlock],
    start: usize,
    visited: &mut [bool],
) -> Structure {
    let mut structures: Vec<Structure> = Vec::new();
    let mut current = start;

    while current < blocks.len() && !visited[current] {
        visited[current] = true;
        let block = &blocks[current];

        match block.kind {
            BlockKind::Return => {
                recover_return_block(block, &mut structures);
                break;
            }

            BlockKind::Sequential => {
                let (stmts, _stack) = recover_expressions(&block.instructions);
                structures.extend(stmts.into_iter().map(Structure::Stmt));
                if let Some(&next) = block.successors.first() {
                    current = next;
                } else {
                    break;
                }
            }

            BlockKind::UnconditionalJump => {
                let non_branch: Vec<_> = block.instructions.iter()
                    .filter(|i| !is_jump(i.opcode))
                    .cloned()
                    .collect();
                let (stmts, _stack) = recover_expressions(&non_branch);
                structures.extend(stmts.into_iter().map(Structure::Stmt));
                if let Some(&target) = block.successors.first() {
                    if target <= current {
                        break;
                    }
                    current = target;
                } else {
                    break;
                }
            }

            BlockKind::ConditionalJump => {
                let fall_through = block.successors.first().copied().unwrap_or(0);
                let branch_target = block.successors.get(1).copied().unwrap_or(0);

                if let Some(while_struct) = try_detect_while(blocks, current, visited) {
                    structures.push(while_struct);
                    current = branch_target;
                    continue;
                }

                if let Some((if_struct, merge_block)) =
                    try_detect_if_else(blocks, current, visited)
                {
                    structures.push(if_struct);
                    current = merge_block;
                    continue;
                }

                // Fallback: emit as sequence.
                let non_branch: Vec<_> = block.instructions.iter()
                    .filter(|i| !is_conditional_branch(i.opcode))
                    .cloned()
                    .collect();
                let (stmts, _stack) = recover_expressions(&non_branch);
                structures.extend(stmts.into_iter().map(Structure::Stmt));
                current = fall_through;
            }
        }
    }

    unwrap_singleton(structures)
}

/// Recover a return block's statements and return expression.
fn recover_return_block(block: &BasicBlock, structures: &mut Vec<Structure>) {
    let non_branch: Vec<_> = block.instructions.iter()
        .filter(|i| !is_return(i.opcode))
        .cloned()
        .collect();
    let (stmts, stack) = recover_expressions(&non_branch);
    structures.extend(stmts.into_iter().map(Structure::Stmt));
    let ret_expr = stack.into_iter().last();
    structures.push(Structure::Return(ret_expr));
}

/// Try to detect a while loop starting at the given conditional block.
///
/// Pattern:
///   `block[current]` = conditional jump (test)
///     - fall-through = body start
///     - branch target = after loop
///   `block[body_end]` = unconditional jump back to current
fn try_detect_while(
    blocks: &[BasicBlock],
    cond_idx: usize,
    visited: &mut [bool],
) -> Option<Structure> {
    let cond_block = &blocks[cond_idx];
    if cond_block.kind != BlockKind::ConditionalJump {
        return None;
    }

    let fall_through = *cond_block.successors.first()?;
    let exit_target = *cond_block.successors.get(1)?;

    if exit_target <= fall_through {
        return None;
    }

    let body_blocks: Vec<usize> = (fall_through..exit_target)
        .filter(|&i| i < blocks.len())
        .collect();

    let has_back_edge = body_blocks.iter().any(|&i| {
        blocks[i].kind == BlockKind::UnconditionalJump
            && blocks[i].successors.first().copied() == Some(cond_idx)
    });

    if !has_back_edge {
        return None;
    }

    let last_instr = cond_block.instructions.last()?;
    let non_branch: Vec<_> = cond_block.instructions.iter()
        .filter(|i| !is_conditional_branch(i.opcode))
        .cloned()
        .collect();
    let (pre_stmts, mut stack) = recover_expressions(&non_branch);
    let condition = extract_condition(&mut stack, last_instr.opcode);

    for &i in &body_blocks {
        visited[i] = true;
    }

    let body = recover_body_blocks(blocks, &body_blocks);
    let while_struct = Structure::While {
        condition,
        body: Box::new(body),
    };

    if pre_stmts.is_empty() {
        Some(while_struct)
    } else {
        let mut seq: Vec<Structure> = pre_stmts.into_iter().map(Structure::Stmt).collect();
        seq.push(while_struct);
        Some(Structure::Sequence(seq))
    }
}

/// Try to detect an if/else pattern starting at the given conditional block.
///
/// Pattern:
///   `block[current]` = conditional jump
///     - fall-through to `then_start`
///     - branch to `else_start`
///   `block[then_end]` = unconditional jump to `merge_point`
///   `block[else_end]` falls through to `merge_point`
fn try_detect_if_else(
    blocks: &[BasicBlock],
    cond_idx: usize,
    visited: &mut [bool],
) -> Option<(Structure, usize)> {
    let cond_block = &blocks[cond_idx];
    if cond_block.kind != BlockKind::ConditionalJump {
        return None;
    }

    let then_start = *cond_block.successors.first()?;
    let else_start = *cond_block.successors.get(1)?;

    let last_instr = cond_block.instructions.last()?;
    let non_branch: Vec<_> = cond_block.instructions.iter()
        .filter(|i| !is_conditional_branch(i.opcode))
        .cloned()
        .collect();
    let (_pre_stmts, mut stack) = recover_expressions(&non_branch);

    // The branch opcode is the NEGATION of the source condition; invert.
    let condition = extract_condition_inverted(&mut stack, last_instr.opcode);

    let then_blocks: Vec<usize> = (then_start..else_start)
        .filter(|&i| i < blocks.len())
        .collect();

    let merge_point = then_blocks.last().and_then(|&last_then| {
        if blocks[last_then].kind == BlockKind::UnconditionalJump {
            blocks[last_then].successors.first().copied()
        } else if blocks[last_then].kind == BlockKind::Return {
            Some(else_start + 1)
        } else {
            None
        }
    }).unwrap_or(else_start);

    let else_blocks: Vec<usize> = (else_start..merge_point)
        .filter(|&i| i < blocks.len())
        .collect();

    for &i in &then_blocks {
        visited[i] = true;
    }
    for &i in &else_blocks {
        visited[i] = true;
    }

    let then_body = recover_body_blocks(blocks, &then_blocks);
    let else_body = if else_blocks.is_empty() {
        Structure::Sequence(Vec::new())
    } else {
        recover_body_blocks(blocks, &else_blocks)
    };

    let if_struct = Structure::IfElse {
        condition,
        then_body: Box::new(then_body),
        else_body: Box::new(else_body),
    };

    Some((if_struct, merge_point))
}

/// Recover the structure of a set of body blocks (for loop or if/else arms).
fn recover_body_blocks(blocks: &[BasicBlock], indices: &[usize]) -> Structure {
    let mut structures: Vec<Structure> = Vec::new();

    for &idx in indices {
        let block = &blocks[idx];

        if block.kind == BlockKind::Return {
            recover_return_block(block, &mut structures);
        } else {
            let non_branch: Vec<_> = block.instructions.iter()
                .filter(|i| !is_jump(i.opcode) && !is_conditional_branch(i.opcode))
                .cloned()
                .collect();
            let (stmts, _stack) = recover_expressions(&non_branch);
            structures.extend(stmts.into_iter().map(Structure::Stmt));
        }
    }

    unwrap_singleton(structures)
}

/// Extract a condition and invert it (for if/else pattern where the branch
/// opcode is the negation of the source condition).
fn extract_condition_inverted(stack: &mut Vec<Expression>, opcode: u8) -> Condition {
    let right = stack.pop().unwrap_or(Expression::Literal(0));
    let left = stack.pop().unwrap_or(Expression::Literal(0));
    // Invert: `if_scmpne` -> source was Eq, `if_scmpeq` -> source was Ne.
    if opcode == opcodes::IF_SCMPNE {
        Condition::Eq(left, right)
    } else {
        Condition::Ne(left, right)
    }
}

/// Unwrap a single-element vec into its element, or wrap in Sequence.
fn unwrap_singleton(mut v: Vec<Structure>) -> Structure {
    if v.len() == 1 {
        v.pop().unwrap()
    } else {
        Structure::Sequence(v)
    }
}

const fn is_return(opcode: u8) -> bool {
    opcode == opcodes::SRETURN || opcode == opcodes::RETURN
}

const fn is_jump(opcode: u8) -> bool {
    opcode == opcodes::GOTO || opcode == opcodes::GOTO_W
}

const fn is_conditional_branch(opcode: u8) -> bool {
    opcode == opcodes::IF_SCMPEQ || opcode == opcodes::IF_SCMPNE
}

fn binary_op(stack: &mut Vec<Expression>, op: &'static str) {
    let right = stack.pop().unwrap_or(Expression::Literal(0));
    let left = stack.pop().unwrap_or(Expression::Literal(0));
    stack.push(Expression::BinOp {
        op,
        left: Box::new(left),
        right: Box::new(right),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cfg_simple_return() {
        // sconst_1, sreturn
        let bc = [0x04, 0x78];
        let blocks = build_cfg(&bc).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].kind, BlockKind::Return);
        assert!(blocks[0].successors.is_empty());
    }

    #[test]
    fn build_cfg_with_branch() {
        // sconst_3, sconst_3, if_scmpeq(+4), sconst_0, sreturn, sconst_1, sreturn
        let bc = [
            0x06, 0x06, // sconst_3, sconst_3
            0x6A, 0x04, // if_scmpeq offset=4 (target=PC 2+4=6)
            0x03, 0x78, // sconst_0, sreturn (fall-through)
            0x04, 0x78, // sconst_1, sreturn (branch target)
        ];
        let blocks = build_cfg(&bc).unwrap();
        assert!(blocks.len() >= 2);
        assert_eq!(blocks[0].kind, BlockKind::ConditionalJump);
    }

    #[test]
    fn recover_expressions_arithmetic() {
        let instrs = vec![
            Instruction { pc: 0, opcode: opcodes::SCONST_3, args: vec![], mnemonic: "sconst_3" },
            Instruction { pc: 1, opcode: opcodes::SCONST_2, args: vec![], mnemonic: "sconst_2" },
            Instruction { pc: 2, opcode: opcodes::SADD, args: vec![], mnemonic: "sadd" },
        ];
        let (_stmts, stack) = recover_expressions(&instrs);
        assert_eq!(stack.len(), 1);
        match &stack[0] {
            Expression::BinOp { op, .. } => assert_eq!(*op, "+"),
            other => panic!("expected BinOp, got {other:?}"),
        }
    }

    #[test]
    fn recover_expressions_store() {
        let instrs = vec![
            Instruction { pc: 0, opcode: opcodes::BSPUSH, args: vec![42], mnemonic: "bspush" },
            Instruction { pc: 2, opcode: opcodes::SSTORE_0, args: vec![], mnemonic: "sstore_0" },
        ];
        let (stmts, stack) = recover_expressions(&instrs);
        assert!(stack.is_empty());
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            Statement::Assign(0, Expression::Literal(42)) => {}
            other => panic!("expected Assign(0, Literal(42)), got {other:?}"),
        }
    }
}
