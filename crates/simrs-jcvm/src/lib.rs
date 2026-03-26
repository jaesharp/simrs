//! `JavaCard` Virtual Machine bytecode interpreter.
//!
//! Implements a fully deterministic, snapshotable JCVM per
//! [JCVM 2.1.1](../../../../telecom-standards/javacard/2.1.1/JCVMSpec.pdf).
//! All mutable state serializes via `save_state`/`restore_state`. `no_std`,
//! `no_alloc`.
//!
//! # Architecture
//!
//! ```text
//! JcVM<HEAP_SIZE, MAX_PACKAGES>
//!   +-- ObjectHeap<HEAP_SIZE>     (persistent, snapshotted)
//!   +-- Package[MAX_PACKAGES]     (persistent, snapshotted)
//!   +-- static_fields[1024]       (persistent, snapshotted)
//!   +-- stack[64]                 (transient, zeroed on restore)
//!   +-- frames[8]                 (transient, zeroed on restore)
//!   +-- locals[128]               (transient, zeroed on restore)
//! ```
//!
//! # Applet Integration
//!
//! [`JcVMApplet`] wraps a `JcVM` and implements the JCRE [`Applet`](simrs_jcre::Applet)
//! trait, allowing bytecode applets to be loaded into the GP card alongside
//! native Rust applets.
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod cap;
pub mod firewall;
pub mod frame;
pub mod heap;
pub mod opcodes;
pub mod transaction;

use cap::Package;
use frame::{CallFrame, MAX_FRAMES, MAX_LOCALS, MAX_STACK};
use heap::{ObjRef, ObjectHeap};
use opcodes::ExecResult;
use simrs_jcre::{Applet, AppletResult};
use transaction::TransactionJournal;

/// Default transaction journal capacity (entries).
const JOURNAL_CAP: usize = 256;

/// Maximum execution steps before the interpreter aborts (infinite loop guard).
const EXEC_LIMIT: u32 = 100_000;

/// The `JavaCard` Virtual Machine.
///
/// `HEAP_SIZE`: backing store for the object heap (bytes).
/// `MAX_PACKAGES`: maximum loaded packages (applets).
///
/// All persistent state (heap, packages, static fields) is included in
/// snapshots. Transient state (stack, frames, locals, current context)
/// is zeroed on restore, matching the JCRE spec: transient state is lost
/// on card reset.
pub struct JcVM<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> {
    // --- Persistent state (included in snapshot) ---
    /// Object heap.
    heap: ObjectHeap<HEAP_SIZE>,
    /// Loaded packages.
    packages: [Option<Package>; MAX_PACKAGES],
    /// Static field storage.
    static_fields: [u8; 1024],
    /// Transaction journal.
    journal: TransactionJournal<JOURNAL_CAP>,

    // --- Transient state (NOT in snapshot, zeroed on restore) ---
    /// Operand stack (16-bit words).
    stack: [u16; MAX_STACK],
    /// Operand stack pointer (points to next free slot).
    stack_ptr: u8,
    /// Call frame stack.
    frames: [CallFrame; MAX_FRAMES],
    /// Call frame pointer (current depth).
    frame_ptr: u8,
    /// Local variable area (16-bit words).
    locals: [u16; MAX_LOCALS],
    /// Currently active package index.
    current_pkg: u8,
    /// Currently executing method index within the package.
    current_method: u8,
    /// Program counter (offset into current method's bytecode).
    pc: u16,
    /// Active applet context (package ID for firewall checks).
    current_context: u8,
    /// Process method index (set during install).
    process_method: u8,
}

impl<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> JcVM<HEAP_SIZE, MAX_PACKAGES> {
    /// Create a new, empty JCVM.
    pub const fn new() -> Self {
        Self {
            heap: ObjectHeap::new(),
            packages: [None; MAX_PACKAGES],
            static_fields: [0u8; 1024],
            journal: TransactionJournal::new(),
            stack: [0u16; MAX_STACK],
            stack_ptr: 0,
            frames: [CallFrame::empty(); MAX_FRAMES],
            frame_ptr: 0,
            locals: [0u16; MAX_LOCALS],
            current_pkg: 0,
            current_method: 0,
            pc: 0,
            current_context: 0,
            process_method: 0,
        }
    }

    /// Load a parsed package into the next available slot.
    ///
    /// Returns the package index, or `None` if all slots are full.
    pub fn load_package(&mut self, pkg: Package) -> Option<u8> {
        for (i, slot) in self.packages.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(pkg);
                #[allow(clippy::cast_possible_truncation)]
                return Some(i as u8);
            }
        }
        None
    }

    /// Find a loaded package by AID. Returns the package index.
    pub fn find_package_by_aid(&self, aid: &[u8]) -> Option<u8> {
        for (i, slot) in self.packages.iter().enumerate() {
            if let Some(pkg) = slot {
                let pkg_aid = &pkg.aid[..pkg.aid_len as usize];
                if pkg_aid == aid {
                    #[allow(clippy::cast_possible_truncation)]
                    return Some(i as u8);
                }
            }
        }
        None
    }

    /// Mutable reference to the transaction journal.
    pub fn journal_mut(&mut self) -> &mut TransactionJournal<JOURNAL_CAP> {
        &mut self.journal
    }

    /// Abort the current transaction, rolling back heap writes.
    pub fn abort_transaction(
        &mut self,
    ) -> Result<(), transaction::TransactionError> {
        self.journal.abort(&mut self.heap)
    }

    /// Set the process method index for APDU dispatch.
    ///
    /// When `JcVMApplet::process()` is called, the VM will execute this
    /// method from the currently selected package.
    pub const fn set_process_method(&mut self, method_idx: u8) {
        self.process_method = method_idx;
    }

    /// Execute a method identified by package index and method index.
    ///
    /// Resets transient state and runs the bytecode interpreter until the
    /// method returns or an exception occurs.
    pub fn execute(&mut self, pkg_idx: u8, method_idx: u8) -> ExecResult {
        // Reset transient state.
        self.stack = [0u16; MAX_STACK];
        self.stack_ptr = 0;
        self.frames = [CallFrame::empty(); MAX_FRAMES];
        self.frame_ptr = 0;
        self.locals = [0u16; MAX_LOCALS];
        self.current_pkg = pkg_idx;
        self.current_method = method_idx;
        self.current_context = pkg_idx;
        self.pc = 0;

        self.run()
    }

    /// Execute starting from an already-configured state (for invokestatic resumption).
    #[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
    fn run(&mut self) -> ExecResult {
        let mut steps: u32 = 0;

        loop {
            steps += 1;
            if steps > EXEC_LIMIT {
                return ExecResult::ExecutionLimit;
            }

            // Fetch the current method's bytecode.
            let Some((bytecode_len, bytecode)) = self.current_bytecode() else {
                return ExecResult::InvalidMethod;
            };

            if self.pc >= bytecode_len {
                return ExecResult::EndOfBytecode;
            }

            let opcode = bytecode[self.pc as usize];
            self.pc += 1;

            match opcode {
                // --- Constants ---
                opcodes::SCONST_M1..=opcodes::SCONST_5 => {
                    let val = i16::from(opcode) - i16::from(opcodes::SCONST_0);
                    if let Err(e) = self.push(val.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::BSPUSH => {
                    let Some(b) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    // Sign-extend byte to short.
                    let val = i16::from(b.cast_signed());
                    if let Err(e) = self.push(val.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SSPUSH => {
                    let Some(hi) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(lo) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = u16::from_be_bytes([hi, lo]);
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                // --- Local variable loads ---
                opcodes::SLOAD => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = self.get_local(idx);
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                opcodes::SLOAD_0..=opcodes::SLOAD_3 => {
                    let idx = opcode - opcodes::SLOAD_0;
                    let val = self.get_local(idx);
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                // --- Local variable stores ---
                opcodes::SSTORE => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    self.set_local(idx, val);
                }

                opcodes::SSTORE_0..=opcodes::SSTORE_3 => {
                    let idx = opcode - opcodes::SSTORE_0;
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    self.set_local(idx, val);
                }

                // --- Stack manipulation ---
                opcodes::POP => {
                    if let Err(e) = self.pop() {
                        return e;
                    }
                }

                opcodes::DUP => {
                    let val = match self.peek() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                // --- Arithmetic ---
                opcodes::SADD => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a.wrapping_add(b).cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SSUB => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a.wrapping_sub(b).cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SMUL => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a.wrapping_mul(b).cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SDIV => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if b == 0 {
                        return ExecResult::ArithmeticException;
                    }
                    // Java-style division: truncates toward zero.
                    // Handle i16::MIN / -1 overflow.
                    let result = if a == i16::MIN && b == -1 {
                        i16::MIN // wrapping behavior per JVM spec
                    } else {
                        a / b
                    };
                    if let Err(e) = self.push(result.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SREM => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if b == 0 {
                        return ExecResult::ArithmeticException;
                    }
                    // Handle i16::MIN % -1 overflow.
                    let result = if a == i16::MIN && b == -1 { 0 } else { a % b };
                    if let Err(e) = self.push(result.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SNEG => {
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a.wrapping_neg().cast_unsigned()) {
                        return e;
                    }
                }

                // --- Control flow ---
                opcodes::GOTO => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    // Offset is relative to the goto opcode itself.
                    // goto_pc = self.pc - 2 (opcode byte + offset byte).
                    let goto_pc = self.pc.wrapping_sub(2);
                    let signed_offset = offset.cast_signed();
                    self.pc =
                        (i32::from(goto_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                }

                opcodes::GOTO_W => {
                    let Some(hi) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(lo) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let offset = i16::from_be_bytes([hi, lo]);
                    // goto_w_pc = self.pc - 3 (opcode + 2 offset bytes).
                    let goto_pc = self.pc.wrapping_sub(3);
                    self.pc = (i32::from(goto_pc) + i32::from(offset)).cast_unsigned() as u16;
                }

                opcodes::IF_SCMPEQ => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if a == b {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPNE => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if a != b {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                // --- Return ---
                opcodes::SRETURN => {
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    // If there are no frames to pop, this is a top-level return.
                    if self.frame_ptr == 0 {
                        return ExecResult::ReturnShort(val);
                    }
                    // Pop the call frame and push the return value.
                    self.frame_ptr -= 1;
                    let f = self.frames[self.frame_ptr as usize];
                    self.current_pkg = f.return_pkg;
                    self.current_method = f.return_method;
                    self.pc = f.return_pc;
                    self.stack_ptr = f.stack_base;
                    // Push return value onto caller's stack.
                    if let Err(e) = self.push(val.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::RETURN => {
                    if self.frame_ptr == 0 {
                        return ExecResult::ReturnVoid;
                    }
                    self.frame_ptr -= 1;
                    let f = self.frames[self.frame_ptr as usize];
                    self.current_pkg = f.return_pkg;
                    self.current_method = f.return_method;
                    self.pc = f.return_pc;
                    self.stack_ptr = f.stack_base;
                }

                // --- Method invocation ---
                opcodes::INVOKESTATIC => {
                    let result = self.exec_invokestatic(bytecode, bytecode_len);
                    if let Some(err) = result {
                        return err;
                    }
                }

                // --- Object creation ---
                opcodes::NEW => {
                    let Some(field_bytes) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    // Consume second byte (reserved/class index).
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    match self
                        .heap
                        .alloc_instance(self.current_context, u16::from(field_bytes))
                    {
                        Some(obj) => {
                            if let Err(e) = self.push(obj.0) {
                                return e;
                            }
                        }
                        None => return ExecResult::HeapFull,
                    }
                }

                opcodes::NEWARRAY => {
                    // Operand: 1 byte (element type). For byte arrays.
                    let Some(_elem_type) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let length = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if length < 0 {
                        return ExecResult::ArrayIndexOutOfBounds;
                    }
                    match self
                        .heap
                        .alloc_byte_array(self.current_context, length.cast_unsigned())
                    {
                        Some(obj) => {
                            if let Err(e) = self.push(obj.0) {
                                return e;
                            }
                        }
                        None => return ExecResult::HeapFull,
                    }
                }

                // --- Array load/store ---
                opcodes::BALOAD => {
                    let index = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let arr_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(arr_ref);
                    match self.heap.baload(obj, index, self.current_context) {
                        Ok(val) => {
                            if let Err(e) = self.push(u16::from(val)) {
                                return e;
                            }
                        }
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException
                        }
                    }
                }

                opcodes::BASTORE => {
                    let value = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let index = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let arr_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(arr_ref);
                    #[allow(clippy::cast_possible_truncation)]
                    match self
                        .heap
                        .bastore(obj, index, value as u8, self.current_context)
                    {
                        Ok(()) => {}
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException
                        }
                    }
                }

                opcodes::SALOAD => {
                    let index = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let arr_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(arr_ref);
                    match self.heap.saload(obj, index, self.current_context) {
                        Ok(val) => {
                            if let Err(e) = self.push(val.cast_unsigned()) {
                                return e;
                            }
                        }
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException
                        }
                    }
                }

                opcodes::SASTORE => {
                    let value = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let index = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let arr_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(arr_ref);
                    match self
                        .heap
                        .sastore(obj, index, value, self.current_context)
                    {
                        Ok(()) => {}
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException
                        }
                    }
                }

                // --- Field access ---
                opcodes::GETFIELD_B => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    // Consume second byte (class index, reserved).
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    let obj_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(obj_ref);
                    match self
                        .heap
                        .getfield_b(obj, u16::from(field_offset), self.current_context)
                    {
                        Ok(val) => {
                            if let Err(e) = self.push(u16::from(val)) {
                                return e;
                            }
                        }
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                opcodes::PUTFIELD_B => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    // Consume second byte (class index, reserved).
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    let value = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(obj_ref);
                    #[allow(clippy::cast_possible_truncation)]
                    match self
                        .heap
                        .putfield_b(obj, u16::from(field_offset), value as u8, self.current_context)
                    {
                        Ok(()) => {}
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                opcodes::ARRAYLENGTH => {
                    let obj_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(obj_ref);
                    if obj.is_null() {
                        return ExecResult::NullPointerException;
                    }
                    match self.heap.array_length(obj) {
                        Some(len) => {
                            if let Err(e) = self.push(len) {
                                return e;
                            }
                        }
                        None => return ExecResult::NullPointerException,
                    }
                }

                _ => return ExecResult::InvalidOpcode(opcode),
            }
        }
    }

    /// Handle `invokestatic` opcode. Returns `Some(ExecResult)` on error, `None` on success.
    fn exec_invokestatic(
        &mut self,
        bytecode: [u8; cap::MAX_BYTECODE],
        bytecode_len: u16,
    ) -> Option<ExecResult> {
        // Operand: 2 bytes -- byte1 = pkg_idx, byte2 = method_idx.
        let Some(target_pkg) = self.fetch_u8(bytecode, bytecode_len) else {
            return Some(ExecResult::EndOfBytecode);
        };
        let Some(target_method) = self.fetch_u8(bytecode, bytecode_len) else {
            return Some(ExecResult::EndOfBytecode);
        };

        // Validate target method exists.
        let Some((callee_nargs, callee_max_locals)) = self.method_info(target_pkg, target_method)
        else {
            return Some(ExecResult::InvalidMethod);
        };

        // Check frame depth.
        if self.frame_ptr as usize >= MAX_FRAMES {
            return Some(ExecResult::FrameOverflow);
        }

        // Compute new locals base.
        let current_locals_base = if self.frame_ptr > 0 {
            self.frames[self.frame_ptr as usize - 1].locals_base
        } else {
            0
        };
        let caller_locals = self
            .method_info(self.current_pkg, self.current_method)
            .map_or(0, |(_, ml)| ml);
        let new_locals_base = current_locals_base.saturating_add(caller_locals);

        if new_locals_base as usize + callee_max_locals as usize > MAX_LOCALS {
            return Some(ExecResult::StackOverflow);
        }

        // Pop arguments from stack into callee's locals.
        let args_start = new_locals_base as usize;
        for i in (0..callee_nargs as usize).rev() {
            let val = match self.pop() {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            if args_start + i < MAX_LOCALS {
                self.locals[args_start + i] = val;
            }
        }
        // Zero remaining locals.
        for i in callee_nargs as usize..callee_max_locals as usize {
            if args_start + i < MAX_LOCALS {
                self.locals[args_start + i] = 0;
            }
        }

        self.frames[self.frame_ptr as usize] = CallFrame {
            return_pkg: self.current_pkg,
            return_method: self.current_method,
            return_pc: self.pc,
            locals_base: new_locals_base,
            stack_base: self.stack_ptr,
        };
        self.frame_ptr += 1;

        self.current_pkg = target_pkg;
        self.current_method = target_method;
        self.pc = 0;

        None
    }

    // -----------------------------------------------------------------------
    // Stack operations
    // -----------------------------------------------------------------------

    /// Push a 16-bit value onto the operand stack.
    const fn push(&mut self, val: u16) -> Result<(), ExecResult> {
        if self.stack_ptr as usize >= MAX_STACK {
            return Err(ExecResult::StackOverflow);
        }
        self.stack[self.stack_ptr as usize] = val;
        self.stack_ptr += 1;
        Ok(())
    }

    /// Pop a 16-bit value from the operand stack.
    const fn pop(&mut self) -> Result<u16, ExecResult> {
        if self.stack_ptr == 0 {
            return Err(ExecResult::StackUnderflow);
        }
        self.stack_ptr -= 1;
        Ok(self.stack[self.stack_ptr as usize])
    }

    /// Pop a value and interpret it as i16.
    const fn pop_i16(&mut self) -> Result<i16, ExecResult> {
        match self.pop() {
            Ok(v) => Ok(v.cast_signed()),
            Err(e) => Err(e),
        }
    }

    /// Peek at the top of the stack without removing.
    const fn peek(&self) -> Result<u16, ExecResult> {
        if self.stack_ptr == 0 {
            return Err(ExecResult::StackUnderflow);
        }
        Ok(self.stack[self.stack_ptr as usize - 1])
    }

    // -----------------------------------------------------------------------
    // Local variable operations
    // -----------------------------------------------------------------------

    /// Get a local variable by index (relative to current frame's base).
    const fn get_local(&self, idx: u8) -> u16 {
        let base = if self.frame_ptr > 0 {
            self.frames[self.frame_ptr as usize - 1].locals_base as usize
        } else {
            0
        };
        let abs = base + idx as usize;
        if abs < MAX_LOCALS {
            self.locals[abs]
        } else {
            0
        }
    }

    /// Set a local variable by index (relative to current frame's base).
    const fn set_local(&mut self, idx: u8, val: u16) {
        let base = if self.frame_ptr > 0 {
            self.frames[self.frame_ptr as usize - 1].locals_base as usize
        } else {
            0
        };
        let abs = base + idx as usize;
        if abs < MAX_LOCALS {
            self.locals[abs] = val;
        }
    }

    // -----------------------------------------------------------------------
    // Bytecode fetch helpers
    // -----------------------------------------------------------------------

    /// Get the current method's bytecode buffer and length.
    fn current_bytecode(&self) -> Option<(u16, [u8; cap::MAX_BYTECODE])> {
        let pkg = self.packages.get(self.current_pkg as usize)?.as_ref()?;
        let method = pkg.method(self.current_method)?;
        Some((method.bytecode_len, method.bytecode))
    }

    /// Fetch the next byte from the bytecode stream, advancing PC.
    const fn fetch_u8(
        &mut self,
        bytecode: [u8; cap::MAX_BYTECODE],
        bytecode_len: u16,
    ) -> Option<u8> {
        if self.pc >= bytecode_len {
            return None;
        }
        let val = bytecode[self.pc as usize];
        self.pc += 1;
        Some(val)
    }

    /// Get (nargs, `max_locals`) for a given package/method pair.
    fn method_info(&self, pkg_idx: u8, method_idx: u8) -> Option<(u8, u8)> {
        let pkg = self.packages.get(pkg_idx as usize)?.as_ref()?;
        let method = pkg.method(method_idx)?;
        Some((method.nargs, method.max_locals))
    }

    // -----------------------------------------------------------------------
    // Snapshot support
    // -----------------------------------------------------------------------

    /// Save persistent state to buffer. Returns bytes written, or 0 if buffer too small.
    ///
    /// Only persistent state is saved: heap, packages, static fields.
    /// Transient state (stack, frames, locals) is NOT saved.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        let mut off = 0;

        // Heap.
        let heap_snap_size = self.heap.snapshot_size();
        if buf.len() < off + heap_snap_size {
            return 0;
        }
        let n = self.heap.save_state(&mut buf[off..]);
        if n == 0 {
            return 0;
        }
        off += n;

        // Packages: save count then each package.
        #[allow(clippy::cast_possible_truncation)]
        let pkg_count = self.packages.iter().filter(|p| p.is_some()).count() as u8;
        if off >= buf.len() {
            return 0;
        }
        buf[off] = pkg_count;
        off += 1;

        for slot in &self.packages {
            if off >= buf.len() {
                return 0;
            }
            match slot {
                None => {
                    buf[off] = 0;
                    off += 1;
                }
                Some(pkg) => {
                    buf[off] = 1;
                    off += 1;
                    let n = pkg.save_state(&mut buf[off..]);
                    if n == 0 {
                        return 0;
                    }
                    off += n;
                }
            }
        }

        // Static fields.
        if off + 1024 > buf.len() {
            return 0;
        }
        buf[off..off + 1024].copy_from_slice(&self.static_fields);
        off += 1024;

        // Process method.
        if off >= buf.len() {
            return 0;
        }
        buf[off] = self.process_method;
        off += 1;

        off
    }

    /// Restore persistent state from buffer. Returns true on success.
    ///
    /// Transient state is zeroed (matching JCRE card-reset behaviour).
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        let mut off = 0;

        // Restore heap.
        if !self.heap.restore_state(&buf[off..]) {
            return false;
        }
        // Calculate how many bytes the heap snapshot consumed.
        if buf.len() < off + 2 {
            return false;
        }
        let heap_free = u16::from_le_bytes([buf[off], buf[off + 1]]);
        off += 2 + heap_free as usize;

        // Packages.
        if off >= buf.len() {
            return false;
        }
        // Skip package count byte (not needed for restoration -- we iterate all slots).
        off += 1;

        for slot in &mut self.packages {
            if off >= buf.len() {
                return false;
            }
            let present = buf[off];
            off += 1;
            if present == 0 {
                *slot = None;
            } else {
                let mut pkg = Package::empty();
                if !pkg.restore_state(&buf[off..]) {
                    return false;
                }
                // Calculate consumed bytes (we need to advance off).
                let n = pkg.save_state(&mut [0u8; Package::MAX_SNAPSHOT_SIZE]);
                off += n;
                *slot = Some(pkg);
            }
        }

        // Static fields.
        if off + 1024 > buf.len() {
            return false;
        }
        self.static_fields.copy_from_slice(&buf[off..off + 1024]);
        off += 1024;

        // Process method.
        if off >= buf.len() {
            return false;
        }
        self.process_method = buf[off];

        // Zero transient state.
        self.stack = [0u16; MAX_STACK];
        self.stack_ptr = 0;
        self.frames = [CallFrame::empty(); MAX_FRAMES];
        self.frame_ptr = 0;
        self.locals = [0u16; MAX_LOCALS];
        self.current_pkg = 0;
        self.current_method = 0;
        self.pc = 0;
        self.current_context = 0;

        true
    }

    /// Access the heap (for test inspection).
    pub const fn heap(&self) -> &ObjectHeap<HEAP_SIZE> {
        &self.heap
    }

    /// Access the heap mutably.
    pub const fn heap_mut(&mut self) -> &mut ObjectHeap<HEAP_SIZE> {
        &mut self.heap
    }
}

impl<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> Default for JcVM<HEAP_SIZE, MAX_PACKAGES> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JcVMApplet: Applet trait implementation wrapping the JCVM
// ---------------------------------------------------------------------------

/// Wrapper that exposes a loaded JCVM package as a JCRE [`Applet`].
///
/// The `process()` method executes the configured process method bytecode
/// within the VM, passing the APDU command data via local variables.
pub struct JcVMApplet<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> {
    /// The underlying virtual machine.
    vm: JcVM<HEAP_SIZE, MAX_PACKAGES>,
    /// Package index of the applet to execute.
    pkg_idx: u8,
}

impl<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> JcVMApplet<HEAP_SIZE, MAX_PACKAGES> {
    /// Create a new applet wrapper for the given VM and package index.
    pub const fn new(vm: JcVM<HEAP_SIZE, MAX_PACKAGES>, pkg_idx: u8) -> Self {
        Self { vm, pkg_idx }
    }

    /// Access the underlying VM.
    pub const fn vm(&self) -> &JcVM<HEAP_SIZE, MAX_PACKAGES> {
        &self.vm
    }

    /// Access the underlying VM mutably.
    pub const fn vm_mut(&mut self) -> &mut JcVM<HEAP_SIZE, MAX_PACKAGES> {
        &mut self.vm
    }
}

impl<const HEAP_SIZE: usize, const MAX_PACKAGES: usize> Applet
    for JcVMApplet<HEAP_SIZE, MAX_PACKAGES>
{
    fn process(&mut self, _cmd: &[u8], out: &mut [u8]) -> AppletResult {
        let method_idx = self.vm.process_method;
        let result = self.vm.execute(self.pkg_idx, method_idx);

        match result {
            ExecResult::ReturnVoid => AppletResult::Ok(0),
            ExecResult::ReturnShort(val) => {
                if out.len() >= 2 {
                    let bytes = val.to_be_bytes();
                    out[0] = bytes[0];
                    out[1] = bytes[1];
                    AppletResult::Ok(2)
                } else {
                    AppletResult::Sw(simrs_iso7816::StatusWord::WrongLength)
                }
            }
            _ => AppletResult::Sw(simrs_iso7816::StatusWord::NoPreciseDiagnosis),
        }
    }

    fn snapshot_size(&self) -> usize {
        // Upper bound: heap max + packages + static fields + process_method.
        ObjectHeap::<HEAP_SIZE>::MAX_SNAPSHOT_SIZE
            + 1
            + MAX_PACKAGES * (1 + Package::MAX_SNAPSHOT_SIZE)
            + 1024
            + 1
    }

    fn save_state(&self, buf: &mut [u8]) -> usize {
        self.vm.save_state(buf)
    }

    fn restore_state(&mut self, buf: &[u8]) -> bool {
        self.vm.restore_state(buf)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::large_stack_arrays)]
mod tests {
    use super::*;
    use cap::build_cap_blob;
    use opcodes::*;

    /// Helper: create a VM with a single package containing one static method.
    fn vm_with_method(bytecode: &[u8]) -> JcVM<4096, 4> {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x01];
        let mut blob = [0u8; 512];
        let len = build_cap_blob(&aid, &[bytecode], &mut blob);
        let pkg = cap::parse_cap(&blob[..len]).unwrap();

        let mut vm = JcVM::<4096, 4>::new();
        vm.load_package(pkg).unwrap();
        vm
    }

    /// Helper: create a VM with a single package containing multiple methods.
    fn vm_with_methods(bytecodes: &[&[u8]]) -> JcVM<4096, 4> {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x01];
        let mut blob = [0u8; 2048];
        let len = build_cap_blob(&aid, bytecodes, &mut blob);
        let pkg = cap::parse_cap(&blob[..len]).unwrap();

        let mut vm = JcVM::<4096, 4>::new();
        vm.load_package(pkg).unwrap();
        vm
    }

    // -----------------------------------------------------------------------
    // find_package_by_aid
    // -----------------------------------------------------------------------

    #[test]
    fn find_package_by_aid_returns_index() {
        let aid1 = [0xA0, 0x00, 0x00, 0x00, 0x01];
        let aid2 = [0xA0, 0x00, 0x00, 0x00, 0x02];
        let bytecode: &[u8] = &[SCONST_0, SRETURN];

        let mut vm = JcVM::<4096, 4>::new();

        let mut blob = [0u8; 512];
        let len = build_cap_blob(&aid1, &[bytecode], &mut blob);
        let pkg1 = cap::parse_cap(&blob[..len]).unwrap();
        vm.load_package(pkg1).unwrap();

        let len = build_cap_blob(&aid2, &[bytecode], &mut blob);
        let pkg2 = cap::parse_cap(&blob[..len]).unwrap();
        vm.load_package(pkg2).unwrap();

        assert_eq!(vm.find_package_by_aid(&aid1), Some(0));
        assert_eq!(vm.find_package_by_aid(&aid2), Some(1));
        assert_eq!(vm.find_package_by_aid(&[0xFF]), None);
    }

    // -----------------------------------------------------------------------
    // Short arithmetic
    // -----------------------------------------------------------------------

    #[test]
    fn sadd_two_constants() {
        // sconst_3 (push 3), sconst_5 (push 5), sadd, sreturn
        let bc = [SCONST_3, SCONST_5, SADD, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(8));
    }

    #[test]
    fn ssub_positive_result() {
        // sconst_5, sconst_3, ssub -> 5 - 3 = 2
        let bc = [SCONST_5, SCONST_3, SSUB, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    #[test]
    fn ssub_negative_result() {
        // sconst_3, sconst_5, ssub -> 3 - 5 = -2
        let bc = [SCONST_3, SCONST_5, SSUB, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-2));
    }

    #[test]
    fn smul_basic() {
        // sconst_3, sconst_4, smul -> 3 * 4 = 12
        let bc = [SCONST_3, SCONST_4, SMUL, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(12));
    }

    #[test]
    fn sdiv_basic() {
        // bspush 10, sconst_3, sdiv -> 10 / 3 = 3 (truncated)
        let bc = [BSPUSH, 10, SCONST_3, SDIV, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn sdiv_by_zero() {
        // sconst_5, sconst_0, sdiv -> ArithmeticException
        let bc = [SCONST_5, SCONST_0, SDIV, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArithmeticException);
    }

    #[test]
    fn srem_basic() {
        // bspush 10, sconst_3, srem -> 10 % 3 = 1
        let bc = [BSPUSH, 10, SCONST_3, SREM, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn srem_by_zero() {
        // sconst_5, sconst_0, srem -> ArithmeticException
        let bc = [SCONST_5, SCONST_0, SREM, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArithmeticException);
    }

    #[test]
    fn sneg_positive() {
        // sconst_5, sneg -> -5
        let bc = [SCONST_5, SNEG, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-5));
    }

    #[test]
    fn sneg_negative() {
        // sconst_m1, sneg -> 1
        let bc = [SCONST_M1, SNEG, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn sadd_negative_values() {
        // bspush -3, bspush -7, sadd -> -10
        let bc = [
            BSPUSH,
            (-3i8).cast_unsigned(),
            BSPUSH,
            (-7i8).cast_unsigned(),
            SADD,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-10));
    }

    #[test]
    fn smul_negative() {
        // sconst_3, sconst_m1, smul -> -3
        let bc = [SCONST_3, SCONST_M1, SMUL, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-3));
    }

    #[test]
    fn sdiv_min_by_neg1() {
        // Push i16::MIN (-32768), push -1, sdiv -> -32768 (wrapping)
        let min_bytes = i16::MIN.cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, min_bytes[0], min_bytes[1], SCONST_M1, SDIV, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(i16::MIN));
    }

    #[test]
    fn srem_min_by_neg1() {
        // i16::MIN % -1 -> 0
        let min_bytes = i16::MIN.cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, min_bytes[0], min_bytes[1], SCONST_M1, SREM, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    // -----------------------------------------------------------------------
    // Stack operations
    // -----------------------------------------------------------------------

    #[test]
    fn push_pop_constant() {
        // sconst_4, sreturn -> 4
        let bc = [SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    #[test]
    fn sconst_m1_pushes_minus_one() {
        let bc = [SCONST_M1, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    #[test]
    fn bspush_positive() {
        let bc = [BSPUSH, 42, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(42));
    }

    #[test]
    fn bspush_negative() {
        let bc = [BSPUSH, (-100i8).cast_unsigned(), SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-100));
    }

    #[test]
    fn sspush_large_value() {
        // Push 0x1234
        let bc = [SSPUSH, 0x12, 0x34, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0x1234));
    }

    #[test]
    fn dup_duplicates_top() {
        // sconst_3, dup, sadd -> 3 + 3 = 6
        let bc = [SCONST_3, DUP, SADD, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(6));
    }

    #[test]
    fn pop_discards_value() {
        // sconst_5, sconst_3, pop, sreturn -> 5 (the 3 was discarded)
        let bc = [SCONST_5, SCONST_3, POP, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn pop_empty_stack_underflow() {
        let bc = [POP];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    #[test]
    fn dup_empty_stack_underflow() {
        let bc = [DUP];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    // -----------------------------------------------------------------------
    // Local variables
    // -----------------------------------------------------------------------

    #[test]
    fn sstore_sload_roundtrip() {
        // sconst_5, sstore_0, sload_0, sreturn -> 5
        let bc = [SCONST_5, SSTORE_0, SLOAD_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn sstore_sload_with_index() {
        // sconst_3, sstore 2, sload 2, sreturn -> 3
        let bc = [SCONST_3, SSTORE, 2, SLOAD, 2, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn multiple_locals() {
        // Store 3 in local 0, 5 in local 1, load both, add, return.
        let bc = [
            SCONST_3, SSTORE_0, SCONST_5, SSTORE_1, SLOAD_0, SLOAD_1, SADD, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(8));
    }

    #[test]
    fn sload_2_and_3() {
        // Store values in locals 2 and 3, load and add.
        let bc = [
            BSPUSH, 10, SSTORE_2, BSPUSH, 20, SSTORE_3, SLOAD_2, SLOAD_3, SADD, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(30));
    }

    // -----------------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------------

    #[test]
    fn goto_forward() {
        // sconst_1, goto +3 (jump to sreturn), sconst_5 (skipped), sreturn
        let bc = [SCONST_1, GOTO, 3, SCONST_5, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn goto_w_forward() {
        // sconst_2, goto_w +5, sconst_5 (skipped), pop, sreturn
        let bc = [SCONST_2, GOTO_W, 0x00, 0x05, SCONST_5, POP, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    #[test]
    fn if_scmpeq_taken() {
        // sconst_1, sconst_3, sconst_3, if_scmpeq +3 -> jump to sreturn
        let bc = [
            SCONST_1, SCONST_3, SCONST_3, IF_SCMPEQ, 3, SCONST_5, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmpeq_not_taken() {
        // Push 3, push 4, if_scmpeq (not taken), fall through to sconst_5, sreturn.
        let bc = [SCONST_3, SCONST_4, IF_SCMPEQ, 3, SCONST_5, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_scmpne_taken() {
        // sconst_1, sconst_3, sconst_4, if_scmpne +3, sconst_5, sreturn
        // 3 != 4 -> branch taken, skip sconst_5.
        let bc = [
            SCONST_1, SCONST_3, SCONST_4, IF_SCMPNE, 3, SCONST_5, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmpne_not_taken() {
        // sconst_3, sconst_3, if_scmpne (not taken), sconst_5, sreturn -> 5.
        let bc = [SCONST_3, SCONST_3, IF_SCMPNE, 3, SCONST_5, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn simple_loop() {
        // Sum 1..5 using a loop.
        // local 0 = counter (starts at 5), local 1 = accumulator (starts at 0).
        let bc = [
            SCONST_5,                // 0
            SSTORE_0,                // 1
            SCONST_0,                // 2
            SSTORE_1,                // 3
            SLOAD_0,                 // 4  LOOP
            SCONST_0,                // 5
            IF_SCMPEQ,               // 6
            12,                      // 7  offset: 6+12=18 (END)
            SLOAD_1,                 // 8
            SLOAD_0,                 // 9
            SADD,                    // 10
            SSTORE_1,                // 11
            SLOAD_0,                 // 12
            SCONST_1,                // 13
            SSUB,                    // 14
            SSTORE_0,                // 15
            GOTO,                    // 16
            (-12i8).cast_unsigned(), // 17  offset: 16-12=4 (LOOP)
            SLOAD_1,                 // 18  END
            SRETURN,                 // 19
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(15));
    }

    #[test]
    fn return_void() {
        let bc = [RETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnVoid);
    }

    // -----------------------------------------------------------------------
    // Array bounds checking
    // -----------------------------------------------------------------------

    #[test]
    fn newarray_and_arraylength() {
        // Push 5 (length), newarray(byte=10), arraylength, sreturn -> 5.
        let bc = [SCONST_5, NEWARRAY, 10, ARRAYLENGTH, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn newarray_negative_length() {
        // Push -1 (length), newarray -> ArrayIndexOutOfBounds.
        let bc = [SCONST_M1, NEWARRAY, 10];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArrayIndexOutOfBounds);
    }

    #[test]
    fn arraylength_null_ref() {
        // Push 0 (null), arraylength -> NullPointerException.
        let bc = [SCONST_0, ARRAYLENGTH];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    #[test]
    fn new_object() {
        // new (4 field bytes, class 0), verify ref is non-null.
        let bc = [
            NEW, 4, 0,        // 0-2: allocate instance
            SSTORE_0, // 3:   store objref
            SLOAD_0,  // 4:   push objref
            SCONST_0, // 5:   push 0
            IF_SCMPNE, 5,        // 6-7: if objref != 0, goto PC=11
            SCONST_0, // 8:   ref was null (should not happen)
            SRETURN,  // 9:   return 0
            RETURN,   // 10:  dead code
            SCONST_1, // 11:  ref was non-null (expected)
            SRETURN,  // 12:  return 1
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    // -----------------------------------------------------------------------
    // Firewall: cross-context field access -> SecurityException
    // -----------------------------------------------------------------------

    #[test]
    fn firewall_cross_context_denied() {
        let mut heap = heap::ObjectHeap::<1024>::new();
        let obj = heap.alloc_instance(1, 4).unwrap();
        // Context 2 trying to access object owned by context 1.
        assert!(heap.getfield_b(obj, 0, 2).is_err());
    }

    // -----------------------------------------------------------------------
    // Snapshot round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_roundtrip_preserves_heap_and_packages() {
        let bc = [SCONST_3, SRETURN];
        let mut vm = vm_with_method(&bc);
        vm.set_process_method(0);

        // Execute to verify it works.
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));

        // Allocate something on the heap.
        vm.heap_mut().alloc_byte_array(0, 10).unwrap();

        // Save state.
        let mut buf = [0u8; 65536];
        let n = vm.save_state(&mut buf);
        assert!(n > 0);

        // Restore into a new VM.
        let mut vm2 = JcVM::<4096, 4>::new();
        assert!(vm2.restore_state(&buf[..n]));

        // The restored VM should execute the same bytecode.
        assert_eq!(vm2.execute(0, 0), ExecResult::ReturnShort(3));

        // Heap state should be preserved (free pointer advanced by the array alloc).
        assert_eq!(vm.heap().used(), vm2.heap().used());
    }

    #[test]
    fn snapshot_transient_state_zeroed() {
        let bc = [SCONST_5, SSTORE_0, SLOAD_0, SRETURN];
        let mut vm = vm_with_method(&bc);

        // Execute to populate transient state.
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));

        // Save and restore.
        let mut buf = [0u8; 65536];
        let n = vm.save_state(&mut buf);
        let mut vm2 = JcVM::<4096, 4>::new();
        assert!(vm2.restore_state(&buf[..n]));

        // Transient state should be zeroed -- executing again should work from scratch.
        assert_eq!(vm2.execute(0, 0), ExecResult::ReturnShort(5));
    }

    // -----------------------------------------------------------------------
    // Method invocation
    // -----------------------------------------------------------------------

    #[test]
    fn invokestatic_simple() {
        // Method 0: invokestatic(0, 1), sreturn -- calls method 1, returns its result.
        // Method 1: sconst_5, sreturn -- returns 5.
        let method0 = [INVOKESTATIC, 0, 1, SRETURN];
        let method1 = [SCONST_5, SRETURN];
        let mut vm = vm_with_methods(&[&method0, &method1]);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn invokestatic_void_return() {
        // Method 0: invokestatic(0, 1), sconst_3, sreturn.
        // Method 1: return (void).
        let method0 = [INVOKESTATIC, 0, 1, SCONST_3, SRETURN];
        let method1 = [RETURN];
        let mut vm = vm_with_methods(&[&method0, &method1]);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn invokestatic_invalid_method() {
        // invokestatic referencing non-existent method 99.
        let bc = [INVOKESTATIC, 0, 99];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::InvalidMethod);
    }

    // -----------------------------------------------------------------------
    // Invalid opcode
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_opcode_reported() {
        let bc = [0xFF]; // undefined opcode
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::InvalidOpcode(0xFF));
    }

    #[test]
    fn end_of_bytecode_detected() {
        let bc: &[u8] = &[];
        let mut vm = vm_with_method(bc);
        assert_eq!(vm.execute(0, 0), ExecResult::EndOfBytecode);
    }

    // -----------------------------------------------------------------------
    // Applet trait integration
    // -----------------------------------------------------------------------

    #[test]
    fn applet_trait_process() {
        let bc = [SCONST_3, SRETURN];
        let vm = vm_with_method(&bc);
        let mut applet = JcVMApplet::<4096, 4>::new(vm, 0);
        applet.vm_mut().set_process_method(0);

        let mut out = [0u8; 8];
        let result = applet.process(&[], &mut out);
        assert_eq!(result, AppletResult::Ok(2));
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x03);
    }

    #[test]
    fn applet_trait_snapshot() {
        let bc = [SCONST_5, SRETURN];
        let vm = vm_with_method(&bc);
        let mut applet = JcVMApplet::<4096, 4>::new(vm, 0);
        applet.vm_mut().set_process_method(0);

        let size = applet.snapshot_size();
        assert!(size > 0);

        let mut snap = [0u8; 65536];
        let n = applet.save_state(&mut snap);
        assert!(n > 0);

        let vm2 = JcVM::<4096, 4>::new();
        let mut applet2 = JcVMApplet::<4096, 4>::new(vm2, 0);
        assert!(applet2.restore_state(&snap[..n]));

        let mut out = [0u8; 8];
        let result = applet2.process(&[], &mut out);
        assert_eq!(result, AppletResult::Ok(2));
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x05);
    }

    // -----------------------------------------------------------------------
    // Execution limit
    // -----------------------------------------------------------------------

    #[test]
    fn execution_limit_prevents_infinite_loop() {
        // goto -2 -> infinite loop at PC=0.
        let bc = [GOTO, 0];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ExecutionLimit);
    }
}
