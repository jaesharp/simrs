//! `JavaCard` Virtual Machine bytecode interpreter.
//!
//! Implements a fully deterministic, snapshotable JCVM per
//! [JCVM 2.1.1](../../../../docs/specs/javacard/2.1.1/JCVMSpec.pdf).
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

/// Force the compiler to treat the referenced memory location as
/// observable, preventing store-to-dead-field elimination of the
/// null-hypervisor counters when no public accessor is compiled in.
///
/// Crucial to the null-hypervisor timing contract: a build with the
/// `controlplane-hooks` feature off must execute the same stores as
/// a build with the feature on, so tests cannot fingerprint which
/// configuration is running from timing alone.
// `#[inline(always)]` is intentional: the wrapper must disappear
// so the `black_box` is applied at the caller's site, not behind an
// extra call-frame that would change the measured timing shape.
#[allow(clippy::inline_always)]
#[inline(always)]
const fn pin_observation<T>(t: &T) -> &T {
    core::hint::black_box(t)
}

pub mod cap;
pub mod firewall;
pub mod frame;
pub mod heap;
#[cfg(feature = "controlplane-hooks")]
pub mod hypervisor;
pub mod native;
pub mod opcodes;
pub mod ring_buffer;
pub mod transaction;

#[cfg(feature = "controlplane-hooks")]
pub use hypervisor::{Hypervisor, NullHypervisor};
pub use ring_buffer::{Event, RingBuffer};

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

    // --- Null-hypervisor observation counters ---
    // Always present and always updated. These are the "default
    // hypervisor" view of guest execution -- a simulator always has
    // the information needed to answer these questions, so there is
    // no reason to make observing it a paravirt mode. Public access
    // to the values (inherent accessors + `Hypervisor` trait impl)
    // is gated by the `controlplane-hooks` feature so production
    // crates can refuse to expose the surface.
    /// Per-opcode execution count. Indexed by the raw opcode byte.
    opcode_counts: [u64; 256],
    /// Total instructions executed across the VM's lifetime.
    total_instructions: u64,
    /// High-water mark of `frame_ptr + 1` (i.e. method-call depth)
    /// observed across the VM's lifetime.
    max_frame_depth: u32,
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
            opcode_counts: [0; 256],
            total_instructions: 0,
            max_frame_depth: 0,
        }
    }

    // ---- Null-hypervisor observation accessors --------------------------
    // Public surface gated by `controlplane-hooks`. The underlying
    // counters are always present and always updated; this gate only
    // controls whether downstream crates can read them. Returning
    // by-value keeps the accessors cheap to cross crate boundaries.

    /// Per-opcode execution counts. Indexed by the raw opcode byte.
    #[cfg(feature = "controlplane-hooks")]
    #[must_use]
    pub const fn opcode_counts(&self) -> [u64; 256] {
        self.opcode_counts
    }

    /// Total instructions executed since the VM was constructed.
    #[cfg(feature = "controlplane-hooks")]
    #[must_use]
    pub const fn total_instructions(&self) -> u64 {
        self.total_instructions
    }

    /// High-water mark of method-call depth seen during execution.
    #[cfg(feature = "controlplane-hooks")]
    #[must_use]
    pub const fn max_frame_depth(&self) -> u32 {
        self.max_frame_depth
    }

    /// Reset all null-hypervisor counters to zero. Dom0 can call
    /// this to bracket a measurement window.
    #[cfg(feature = "controlplane-hooks")]
    pub const fn reset_controlplane_counters(&mut self) {
        self.opcode_counts = [0; 256];
        self.total_instructions = 0;
        self.max_frame_depth = 0;
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
    pub const fn journal_mut(&mut self) -> &mut TransactionJournal<JOURNAL_CAP> {
        &mut self.journal
    }

    /// Abort the current transaction, rolling back heap writes.
    ///
    /// # Errors
    ///
    /// Returns [`transaction::TransactionError::NotActive`] if no transaction is active.
    pub fn abort_transaction(&mut self) -> Result<(), transaction::TransactionError> {
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

            // Null-hypervisor observation: always tallied regardless
            // of feature flag. Pinned via black_box so a build
            // without the `controlplane-hooks` feature still executes
            // the stores (timing must be indistinguishable from the
            // feature-on build).
            self.opcode_counts[opcode as usize] =
                self.opcode_counts[opcode as usize].saturating_add(1);
            self.total_instructions = self.total_instructions.saturating_add(1);
            let _ = pin_observation(&self.opcode_counts);
            let _ = pin_observation(&self.total_instructions);

            match opcode {
                // --- NOP ---
                opcodes::NOP => {}

                // --- Constants ---
                opcodes::ACONST_NULL => {
                    if let Err(e) = self.push(0) {
                        return e;
                    }
                }

                opcodes::SCONST_M1..=opcodes::SCONST_5 => {
                    let val = i16::from(opcode) - i16::from(opcodes::SCONST_0);
                    if let Err(e) = self.push(val.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::ICONST_M1..=opcodes::ICONST_5 => {
                    let val = i32::from(opcode) - i32::from(opcodes::ICONST_0);
                    if let Err(e) = self.push_int(val) {
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

                opcodes::IIPUSH => {
                    let Some(val) = self.fetch_i32(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    if let Err(e) = self.push_int(val) {
                        return e;
                    }
                }

                // --- Reference loads (same as sload; references are u16) ---
                opcodes::ALOAD => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = self.get_local(idx);
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                opcodes::ALOAD_0..=opcodes::ALOAD_3 => {
                    let idx = opcode - opcodes::ALOAD_0;
                    let val = self.get_local(idx);
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

                // --- Int local loads (two consecutive locals: hi at idx, lo at idx+1) ---
                opcodes::ILOAD => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let hi = self.get_local(idx);
                    let lo = self.get_local(idx.wrapping_add(1));
                    if let Err(e) = self.push(hi) {
                        return e;
                    }
                    if let Err(e) = self.push(lo) {
                        return e;
                    }
                }

                opcodes::ILOAD_0..=opcodes::ILOAD_3 => {
                    let idx = opcode - opcodes::ILOAD_0;
                    let hi = self.get_local(idx);
                    let lo = self.get_local(idx.wrapping_add(1));
                    if let Err(e) = self.push(hi) {
                        return e;
                    }
                    if let Err(e) = self.push(lo) {
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

                // --- Reference stores (same as sstore; references are u16) ---
                opcodes::ASTORE => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    self.set_local(idx, val);
                }

                opcodes::ASTORE_0 => {
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    self.set_local(0, val);
                }

                // --- Int local stores (two consecutive locals: hi at idx, lo at idx+1) ---
                opcodes::ISTORE => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let lo = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let hi = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    self.set_local(idx, hi);
                    self.set_local(idx.wrapping_add(1), lo);
                }

                opcodes::ISTORE_0..=opcodes::ISTORE_3 => {
                    let idx = opcode - opcodes::ISTORE_0;
                    let lo = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let hi = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    self.set_local(idx, hi);
                    self.set_local(idx.wrapping_add(1), lo);
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

                opcodes::POP2 => {
                    if let Err(e) = self.pop() {
                        return e;
                    }
                    if let Err(e) = self.pop() {
                        return e;
                    }
                }

                opcodes::DUP2 => {
                    if self.stack_ptr < 2 {
                        return ExecResult::StackUnderflow;
                    }
                    let w1 = self.stack[self.stack_ptr as usize - 2];
                    let w2 = self.stack[self.stack_ptr as usize - 1];
                    if let Err(e) = self.push(w1) {
                        return e;
                    }
                    if let Err(e) = self.push(w2) {
                        return e;
                    }
                }

                opcodes::SWAP => {
                    let a = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a) {
                        return e;
                    }
                    if let Err(e) = self.push(b) {
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

                // --- Int arithmetic ---
                opcodes::IADD => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(a.wrapping_add(b)) {
                        return e;
                    }
                }

                opcodes::ISUB => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(a.wrapping_sub(b)) {
                        return e;
                    }
                }

                opcodes::IMUL => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(a.wrapping_mul(b)) {
                        return e;
                    }
                }

                opcodes::IDIV => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if b == 0 {
                        return ExecResult::ArithmeticException;
                    }
                    let result = if a == i32::MIN && b == -1 {
                        i32::MIN
                    } else {
                        a / b
                    };
                    if let Err(e) = self.push_int(result) {
                        return e;
                    }
                }

                opcodes::IREM => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if b == 0 {
                        return ExecResult::ArithmeticException;
                    }
                    let result = if a == i32::MIN && b == -1 { 0 } else { a % b };
                    if let Err(e) = self.push_int(result) {
                        return e;
                    }
                }

                opcodes::INEG => {
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(a.wrapping_neg()) {
                        return e;
                    }
                }

                // --- Short bitwise ---
                opcodes::SSHL => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let shift = b.cast_unsigned() & 0x1F;
                    #[allow(clippy::cast_possible_truncation)]
                    let result = ((i32::from(a) << shift) & 0xFFFF) as i16;
                    if let Err(e) = self.push(result.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SSHR => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let shift = b.cast_unsigned() & 0x1F;
                    #[allow(clippy::cast_possible_truncation)]
                    let result = (i32::from(a) >> shift) as i16;
                    if let Err(e) = self.push(result.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::SUSHR => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let shift = b.cast_unsigned() & 0x1F;
                    let result = a >> shift;
                    if let Err(e) = self.push(result) {
                        return e;
                    }
                }

                opcodes::SAND => {
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a & b) {
                        return e;
                    }
                }

                opcodes::SOR => {
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a | b) {
                        return e;
                    }
                }

                opcodes::SXOR => {
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push(a ^ b) {
                        return e;
                    }
                }

                // --- Int bitwise ---
                opcodes::ISHL => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let shift = u32::from(b.cast_unsigned()) & 0x1F;
                    if let Err(e) = self.push_int(a.wrapping_shl(shift)) {
                        return e;
                    }
                }

                opcodes::ISHR => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let shift = u32::from(b.cast_unsigned()) & 0x1F;
                    if let Err(e) = self.push_int(a.wrapping_shr(shift)) {
                        return e;
                    }
                }

                opcodes::IUSHR => {
                    let b = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let shift = u32::from(b.cast_unsigned()) & 0x1F;
                    let result = a.cast_unsigned().wrapping_shr(shift).cast_signed();
                    if let Err(e) = self.push_int(result) {
                        return e;
                    }
                }

                opcodes::IAND => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(a & b) {
                        return e;
                    }
                }

                opcodes::IOR => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(a | b) {
                        return e;
                    }
                }

                opcodes::IXOR => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(a ^ b) {
                        return e;
                    }
                }

                // --- Increment ---
                opcodes::SINC => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(c) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = self.get_local(idx).cast_signed();
                    let inc = c.cast_signed();
                    self.set_local(idx, val.wrapping_add(i16::from(inc)).cast_unsigned());
                }

                opcodes::IINC => {
                    let Some(idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(c) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let hi = self.get_local(idx);
                    let lo = self.get_local(idx.wrapping_add(1));
                    let val = (u32::from(hi) << 16 | u32::from(lo)).cast_signed();
                    let inc = i32::from(c.cast_signed());
                    let result = val.wrapping_add(inc).cast_unsigned();
                    #[allow(clippy::cast_possible_truncation)]
                    self.set_local(idx, (result >> 16) as u16);
                    #[allow(clippy::cast_possible_truncation)]
                    self.set_local(idx.wrapping_add(1), result as u16);
                }

                // --- Conversions ---
                opcodes::S2B => {
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    #[allow(clippy::cast_possible_truncation)]
                    let result = i16::from(a as i8);
                    if let Err(e) = self.push(result.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::S2I => {
                    let a = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = self.push_int(i32::from(a)) {
                        return e;
                    }
                }

                opcodes::I2B => {
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    #[allow(clippy::cast_possible_truncation)]
                    let result = i16::from(a as i8);
                    if let Err(e) = self.push(result.cast_unsigned()) {
                        return e;
                    }
                }

                opcodes::I2S => {
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    #[allow(clippy::cast_possible_truncation)]
                    let result = a as i16;
                    if let Err(e) = self.push(result.cast_unsigned()) {
                        return e;
                    }
                }

                // --- Int comparison ---
                opcodes::ICMP => {
                    let b = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let result: i16 = match a.cmp(&b) {
                        core::cmp::Ordering::Greater => 1,
                        core::cmp::Ordering::Equal => 0,
                        core::cmp::Ordering::Less => -1,
                    };
                    if let Err(e) = self.push(result.cast_unsigned()) {
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

                opcodes::IF_SCMPLT => {
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
                    if a < b {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPGE => {
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
                    if a >= b {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPGT => {
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
                    if a > b {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPLE => {
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
                    if a <= b {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                // --- Reference comparison branches ---
                opcodes::IF_ACMPEQ => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
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

                opcodes::IF_ACMPNE => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
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

                // --- Unary comparison branches ---
                opcodes::IFEQ => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val == 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFNE => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val != 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFLT => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val < 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFGE => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val >= 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFGT => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val > 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFLE => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val <= 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFNULL => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val == 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFNONNULL => {
                    let Some(offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val != 0 {
                        let if_pc = self.pc.wrapping_sub(2);
                        let signed_offset = offset.cast_signed();
                        self.pc =
                            (i32::from(if_pc) + i32::from(signed_offset)).cast_unsigned() as u16;
                    }
                }

                // --- Wide-offset conditional branches (JCVM 3.2 § 7.5) ---
                //
                // Each `*_w` opcode mirrors its narrow counterpart at
                // 0x60..=0x6F: same stack effect, same comparison; only
                // the operand is a 2-byte signed offset instead of 1.
                // The branch target is `(opcode_pc) + offset` where
                // `opcode_pc = pc - 3` (1-byte opcode + 2-byte operand
                // already consumed). The converter emits `_w` when the
                // narrow `[-128, +127]` byte-offset reach is too short.
                opcodes::IFEQ_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val == 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFNE_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val != 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFLT_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val < 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFGE_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val >= 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFGT_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val > 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFLE_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val <= 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFNULL_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val == 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IFNONNULL_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val != 0 {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_ACMPEQ_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if a == b {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_ACMPNE_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let b = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let a = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if a != b {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPEQ_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
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
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPNE_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
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
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPLT_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
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
                    if a < b {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPGE_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
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
                    if a >= b {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPGT_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
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
                    if a > b {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
                    }
                }

                opcodes::IF_SCMPLE_W => {
                    let Some(offset) = self.fetch_i16(bytecode, bytecode_len) else {
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
                    if a <= b {
                        let if_pc = self.pc.wrapping_sub(3);
                        self.pc = (i32::from(if_pc) + i32::from(offset)).cast_unsigned() as u16;
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

                opcodes::ARETURN => {
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if self.frame_ptr == 0 {
                        return ExecResult::ReturnRef(val);
                    }
                    self.frame_ptr -= 1;
                    let f = self.frames[self.frame_ptr as usize];
                    self.current_pkg = f.return_pkg;
                    self.current_method = f.return_method;
                    self.pc = f.return_pc;
                    self.stack_ptr = f.stack_base;
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                opcodes::IRETURN => {
                    let val = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if self.frame_ptr == 0 {
                        return ExecResult::ReturnInt(val);
                    }
                    self.frame_ptr -= 1;
                    let f = self.frames[self.frame_ptr as usize];
                    self.current_pkg = f.return_pkg;
                    self.current_method = f.return_method;
                    self.pc = f.return_pc;
                    self.stack_ptr = f.stack_base;
                    if let Err(e) = self.push_int(val) {
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
                // invokespecial is stubbed as invokestatic for now.
                opcodes::INVOKESTATIC | opcodes::INVOKESPECIAL => {
                    let result = self.exec_invokestatic(bytecode, bytecode_len);
                    if let Some(err) = result {
                        return err;
                    }
                }

                // --- Static field access ---
                opcodes::GETSTATIC_B => {
                    // Operand: 2 bytes -- field_offset, reserved.
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    // Consume second byte (reserved/class index).
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    let idx = u16::from(field_offset) as usize;
                    let val = if idx < self.static_fields.len() {
                        u16::from(self.static_fields[idx])
                    } else {
                        0
                    };
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                opcodes::PUTSTATIC_B => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let idx = u16::from(field_offset) as usize;
                    if idx < self.static_fields.len() {
                        #[allow(clippy::cast_possible_truncation)]
                        {
                            self.static_fields[idx] = val as u8;
                        }
                    }
                }

                // --- Virtual dispatch ---
                // First check if this is a native framework method call.
                // The 2-byte operand encodes (class_id, method_id) for native
                // methods. If dispatch_native returns NotNative, fall through
                // to normal bytecode dispatch.
                opcodes::INVOKEVIRTUAL => {
                    let saved_pc = self.pc;
                    let Some(byte1) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(byte2) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let native_result = native::dispatch_native(byte1, byte2, self);
                    match native_result {
                        native::NativeResult::Void => {}
                        native::NativeResult::Short(v) => {
                            if let Err(e) = self.push(v.cast_unsigned()) {
                                return e;
                            }
                        }
                        native::NativeResult::Int(v) => {
                            if let Err(e) = self.push_int(v) {
                                return e;
                            }
                        }
                        native::NativeResult::Ref(r) => {
                            if let Err(e) = self.push(r) {
                                return e;
                            }
                        }
                        native::NativeResult::Exception(e) => return e,
                        native::NativeResult::NotNative => {
                            // Rewind PC and fall through to normal dispatch.
                            self.pc = saved_pc;
                            let result = self.exec_invokestatic(bytecode, bytecode_len);
                            if let Some(err) = result {
                                return err;
                            }
                        }
                    }
                }

                // --- Exception ---
                opcodes::ATHROW => {
                    let reason = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    return ExecResult::UncaughtException(reason);
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
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
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
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
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
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                    }
                }

                opcodes::SASTORE | opcodes::AASTORE => {
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
                    match self.heap.sastore(obj, index, value, self.current_context) {
                        Ok(()) => {}
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
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
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
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
                    match self.heap.putfield_b(
                        obj,
                        u16::from(field_offset),
                        value as u8,
                        self.current_context,
                    ) {
                        Ok(()) => {}
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
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

                // --- Reference array load/store ---
                opcodes::AALOAD => {
                    let index = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let arr_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(arr_ref);
                    // aaload uses short array access (references are u16 = short)
                    match self.heap.saload(obj, index, self.current_context) {
                        Ok(val) => {
                            if let Err(e) = self.push(val.cast_unsigned()) {
                                return e;
                            }
                        }
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                    }
                }

                // Int array load: reads 2 consecutive short elements as one int
                opcodes::IALOAD => {
                    let index = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let arr_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(arr_ref);
                    // Read hi and lo as two consecutive short array elements
                    let hi_idx = index.wrapping_mul(2);
                    let lo_idx = hi_idx.wrapping_add(1);
                    let hi = match self.heap.saload(obj, hi_idx, self.current_context) {
                        Ok(v) => v,
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                    };
                    let lo = match self.heap.saload(obj, lo_idx, self.current_context) {
                        Ok(v) => v,
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                    };
                    let val = (u32::from(hi.cast_unsigned()) << 16 | u32::from(lo.cast_unsigned()))
                        .cast_signed();
                    if let Err(e) = self.push_int(val) {
                        return e;
                    }
                }

                opcodes::IASTORE => {
                    let val = match self.pop_int() {
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
                    let bits = val.cast_unsigned();
                    #[allow(clippy::cast_possible_truncation)]
                    let hi = (bits >> 16) as i16;
                    #[allow(clippy::cast_possible_truncation)]
                    let lo = bits as i16;
                    let hi_idx = index.wrapping_mul(2);
                    let lo_idx = hi_idx.wrapping_add(1);
                    match self.heap.sastore(obj, hi_idx, hi, self.current_context) {
                        Ok(()) => {}
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                    }
                    match self.heap.sastore(obj, lo_idx, lo, self.current_context) {
                        Ok(()) => {}
                        Err(heap::AccessError::NullRef) => return ExecResult::NullPointerException,
                        Err(heap::AccessError::OutOfBounds) => {
                            return ExecResult::ArrayIndexOutOfBounds;
                        }
                        Err(heap::AccessError::TypeMismatch) => {
                            return ExecResult::ArrayStoreException;
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                    }
                }

                // --- Instance field access: short ---
                opcodes::GETFIELD_S => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
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
                        .getfield_s(obj, u16::from(field_offset), self.current_context)
                    {
                        Ok(val) => {
                            if let Err(e) = self.push(val.cast_unsigned()) {
                                return e;
                            }
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                opcodes::PUTFIELD_S => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    let value = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(obj_ref);
                    match self.heap.putfield_s(
                        obj,
                        u16::from(field_offset),
                        value,
                        self.current_context,
                    ) {
                        Ok(()) => {}
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                // --- Instance field access: reference ---
                opcodes::GETFIELD_A => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
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
                        .getfield_a(obj, u16::from(field_offset), self.current_context)
                    {
                        Ok(val) => {
                            if let Err(e) = self.push(val) {
                                return e;
                            }
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                opcodes::PUTFIELD_A => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
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
                    match self.heap.putfield_a(
                        obj,
                        u16::from(field_offset),
                        value,
                        self.current_context,
                    ) {
                        Ok(()) => {}
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                // --- Instance field access: int ---
                opcodes::GETFIELD_I => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
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
                        .getfield_i(obj, u16::from(field_offset), self.current_context)
                    {
                        Ok(val) => {
                            if let Err(e) = self.push_int(val) {
                                return e;
                            }
                        }
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                opcodes::PUTFIELD_I => {
                    let Some(field_offset) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    let val = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let obj = ObjRef(obj_ref);
                    match self.heap.putfield_i(
                        obj,
                        u16::from(field_offset),
                        val,
                        self.current_context,
                    ) {
                        Ok(()) => {}
                        Err(heap::AccessError::Security(_)) => {
                            return ExecResult::SecurityException;
                        }
                        Err(_) => return ExecResult::NullPointerException,
                    }
                }

                // --- Static field access: short (2 bytes) ---
                opcodes::GETSTATIC_S | opcodes::GETSTATIC_A => {
                    let Some(hi) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(lo) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let idx = u16::from_be_bytes([hi, lo]) as usize;
                    let val = if idx + 1 < self.static_fields.len() {
                        u16::from_be_bytes([self.static_fields[idx], self.static_fields[idx + 1]])
                    } else {
                        0
                    };
                    if let Err(e) = self.push(val) {
                        return e;
                    }
                }

                opcodes::PUTSTATIC_S | opcodes::PUTSTATIC_A => {
                    let Some(hi) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(lo) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let idx = u16::from_be_bytes([hi, lo]) as usize;
                    if idx + 1 < self.static_fields.len() {
                        let bytes = val.to_be_bytes();
                        self.static_fields[idx] = bytes[0];
                        self.static_fields[idx + 1] = bytes[1];
                    }
                }

                // --- Static field access: int (4 bytes) ---
                opcodes::GETSTATIC_I => {
                    let Some(hi) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(lo) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let idx = u16::from_be_bytes([hi, lo]) as usize;
                    let val = if idx + 3 < self.static_fields.len() {
                        i32::from_be_bytes([
                            self.static_fields[idx],
                            self.static_fields[idx + 1],
                            self.static_fields[idx + 2],
                            self.static_fields[idx + 3],
                        ])
                    } else {
                        0
                    };
                    if let Err(e) = self.push_int(val) {
                        return e;
                    }
                }

                opcodes::PUTSTATIC_I => {
                    let Some(hi) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(lo) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let val = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let idx = u16::from_be_bytes([hi, lo]) as usize;
                    if idx + 3 < self.static_fields.len() {
                        let bytes = val.to_be_bytes();
                        self.static_fields[idx] = bytes[0];
                        self.static_fields[idx + 1] = bytes[1];
                        self.static_fields[idx + 2] = bytes[2];
                        self.static_fields[idx + 3] = bytes[3];
                    }
                }

                // --- Invoke: invokeinterface ---
                // Consumes 2 bytes: pkg/class_id, method_id.
                // Check native dispatch first, then fall through.
                opcodes::INVOKEINTERFACE => {
                    let saved_pc = self.pc;
                    let Some(byte1) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(byte2) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let native_result = native::dispatch_native(byte1, byte2, self);
                    match native_result {
                        native::NativeResult::Void => {}
                        native::NativeResult::Short(v) => {
                            if let Err(e) = self.push(v.cast_unsigned()) {
                                return e;
                            }
                        }
                        native::NativeResult::Int(v) => {
                            if let Err(e) = self.push_int(v) {
                                return e;
                            }
                        }
                        native::NativeResult::Ref(r) => {
                            if let Err(e) = self.push(r) {
                                return e;
                            }
                        }
                        native::NativeResult::Exception(e) => return e,
                        native::NativeResult::NotNative => {
                            self.pc = saved_pc;
                            let result = self.exec_invokestatic(bytecode, bytecode_len);
                            if let Some(err) = result {
                                return err;
                            }
                        }
                    }
                }

                // --- Object creation: anewarray ---
                opcodes::ANEWARRAY => {
                    let Some(_class_idx) = self.fetch_u8(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let length = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if length < 0 {
                        return ExecResult::NegativeArraySize;
                    }
                    match self
                        .heap
                        .alloc_short_array(self.current_context, length.cast_unsigned())
                    {
                        Some(obj) => {
                            if let Err(e) = self.push(obj.0) {
                                return e;
                            }
                        }
                        None => return ExecResult::HeapFull,
                    }
                }

                // --- Type checking (stubs) ---
                opcodes::CHECKCAST => {
                    // Consume 2-byte class index operand.
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    // Stub: always succeeds. The objectref stays on the stack.
                }

                opcodes::INSTANCEOF => {
                    // Consume 2-byte class index operand.
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    if self.fetch_u8(bytecode, bytecode_len).is_none() {
                        return ExecResult::EndOfBytecode;
                    }
                    // Pop objectref, push result.
                    let obj_ref = match self.pop() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    // Stub: null -> 0, non-null -> 1.
                    let result: u16 = u16::from(obj_ref != 0);
                    if let Err(e) = self.push(result) {
                        return e;
                    }
                }

                // --- Switch: stableswitch ---
                opcodes::STABLESWITCH => {
                    let switch_pc = self.pc.wrapping_sub(1); // PC of the opcode
                    let Some(default_offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(low) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(high) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let key = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if key >= low && key <= high {
                        #[allow(clippy::cast_sign_loss)] // key >= low is checked above
                        let table_idx = (key - low) as usize;
                        // Skip to the correct offset entry.
                        #[allow(clippy::cast_possible_truncation)]
                        let entry_pc = self.pc.wrapping_add((table_idx * 2) as u16);
                        if entry_pc + 1 >= bytecode_len {
                            return ExecResult::EndOfBytecode;
                        }
                        let offset = i16::from_be_bytes([
                            bytecode[entry_pc as usize],
                            bytecode[entry_pc as usize + 1],
                        ]);
                        self.pc = (i32::from(switch_pc) + i32::from(offset)).cast_unsigned() as u16;
                    } else {
                        self.pc = (i32::from(switch_pc) + i32::from(default_offset)).cast_unsigned()
                            as u16;
                    }
                }

                // --- Switch: slookupswitch ---
                opcodes::SLOOKUPSWITCH => {
                    let switch_pc = self.pc.wrapping_sub(1);
                    let Some(default_offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(npairs) = self.fetch_u16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let key = match self.pop_i16() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let pairs_start = self.pc;
                    let mut found = false;
                    for i in 0..npairs {
                        let entry_off = pairs_start.wrapping_add(i.wrapping_mul(4));
                        if entry_off + 3 >= bytecode_len {
                            return ExecResult::EndOfBytecode;
                        }
                        let match_val = i16::from_be_bytes([
                            bytecode[entry_off as usize],
                            bytecode[entry_off as usize + 1],
                        ]);
                        if match_val == key {
                            let offset = i16::from_be_bytes([
                                bytecode[entry_off as usize + 2],
                                bytecode[entry_off as usize + 3],
                            ]);
                            self.pc =
                                (i32::from(switch_pc) + i32::from(offset)).cast_unsigned() as u16;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        self.pc = (i32::from(switch_pc) + i32::from(default_offset)).cast_unsigned()
                            as u16;
                    }
                }

                // --- Switch: itableswitch (int key) ---
                opcodes::ITABLESWITCH => {
                    let switch_pc = self.pc.wrapping_sub(1);
                    let Some(default_offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(low) = self.fetch_i32(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(high) = self.fetch_i32(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let key = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if key >= low && key <= high {
                        #[allow(clippy::cast_sign_loss)] // key >= low is checked above
                        let table_idx = (key - low) as usize;
                        #[allow(clippy::cast_possible_truncation)]
                        let entry_pc = self.pc.wrapping_add((table_idx * 2) as u16);
                        if entry_pc + 1 >= bytecode_len {
                            return ExecResult::EndOfBytecode;
                        }
                        let offset = i16::from_be_bytes([
                            bytecode[entry_pc as usize],
                            bytecode[entry_pc as usize + 1],
                        ]);
                        self.pc = (i32::from(switch_pc) + i32::from(offset)).cast_unsigned() as u16;
                    } else {
                        self.pc = (i32::from(switch_pc) + i32::from(default_offset)).cast_unsigned()
                            as u16;
                    }
                }

                // --- Switch: ilookupswitch (int key) ---
                opcodes::ILOOKUPSWITCH => {
                    let switch_pc = self.pc.wrapping_sub(1);
                    let Some(default_offset) = self.fetch_i16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let Some(npairs) = self.fetch_u16(bytecode, bytecode_len) else {
                        return ExecResult::EndOfBytecode;
                    };
                    let key = match self.pop_int() {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let pairs_start = self.pc;
                    let mut found = false;
                    for i in 0..npairs {
                        // Each pair: match_value(4) + offset(2) = 6 bytes
                        let entry_off = pairs_start.wrapping_add(i.wrapping_mul(6));
                        if entry_off + 5 >= bytecode_len {
                            return ExecResult::EndOfBytecode;
                        }
                        let match_val = i32::from_be_bytes([
                            bytecode[entry_off as usize],
                            bytecode[entry_off as usize + 1],
                            bytecode[entry_off as usize + 2],
                            bytecode[entry_off as usize + 3],
                        ]);
                        if match_val == key {
                            let offset = i16::from_be_bytes([
                                bytecode[entry_off as usize + 4],
                                bytecode[entry_off as usize + 5],
                            ]);
                            self.pc =
                                (i32::from(switch_pc) + i32::from(offset)).cast_unsigned() as u16;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        self.pc = (i32::from(switch_pc) + i32::from(default_offset)).cast_unsigned()
                            as u16;
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

        // Null-hypervisor depth tracker. Unconditional, branchless
        // (`u32::max` lowers to `cmov`) and pinned via black_box so
        // feature-off builds still execute the store -- keeping the
        // invoke-path timing identical regardless of whether a
        // public accessor was compiled in.
        let depth = u32::from(self.frame_ptr);
        self.max_frame_depth = u32::max(self.max_frame_depth, depth);
        let _ = pin_observation(&self.max_frame_depth);

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
    pub(crate) const fn pop(&mut self) -> Result<u16, ExecResult> {
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

    /// Pop a 32-bit int from the stack (two u16 words: high pushed first, low on top).
    fn pop_int(&mut self) -> Result<i32, ExecResult> {
        let lo = self.pop()?;
        let hi = self.pop()?;
        Ok((u32::from(hi) << 16 | u32::from(lo)).cast_signed())
    }

    /// Push a 32-bit int onto the stack (two u16 words: high first, low second).
    fn push_int(&mut self, val: i32) -> Result<(), ExecResult> {
        let bits = val.cast_unsigned();
        #[allow(clippy::cast_possible_truncation)]
        self.push((bits >> 16) as u16)?; // high word
        #[allow(clippy::cast_possible_truncation)]
        self.push(bits as u16)?; // low word
        Ok(())
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

    /// Fetch the next 2 bytes as a big-endian i16.
    fn fetch_i16(&mut self, bytecode: [u8; cap::MAX_BYTECODE], bytecode_len: u16) -> Option<i16> {
        let hi = self.fetch_u8(bytecode, bytecode_len)?;
        let lo = self.fetch_u8(bytecode, bytecode_len)?;
        Some(i16::from_be_bytes([hi, lo]))
    }

    /// Fetch the next 2 bytes as a big-endian u16.
    fn fetch_u16(&mut self, bytecode: [u8; cap::MAX_BYTECODE], bytecode_len: u16) -> Option<u16> {
        let hi = self.fetch_u8(bytecode, bytecode_len)?;
        let lo = self.fetch_u8(bytecode, bytecode_len)?;
        Some(u16::from_be_bytes([hi, lo]))
    }

    /// Fetch the next 4 bytes as a big-endian i32.
    fn fetch_i32(&mut self, bytecode: [u8; cap::MAX_BYTECODE], bytecode_len: u16) -> Option<i32> {
        let b0 = self.fetch_u8(bytecode, bytecode_len)?;
        let b1 = self.fetch_u8(bytecode, bytecode_len)?;
        let b2 = self.fetch_u8(bytecode, bytecode_len)?;
        let b3 = self.fetch_u8(bytecode, bytecode_len)?;
        Some(i32::from_be_bytes([b0, b1, b2, b3]))
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

    // -----------------------------------------------------------------------
    // Public stack/heap accessors for native method dispatch
    // -----------------------------------------------------------------------

    /// Push a 16-bit value onto the operand stack (public, for native dispatch).
    ///
    /// # Errors
    ///
    /// Returns [`ExecResult::StackOverflow`] if the stack is full.
    pub const fn push_pub(&mut self, val: u16) -> Result<(), ExecResult> {
        self.push(val)
    }

    /// Pop a 16-bit value and interpret as i16 (public, for native dispatch).
    ///
    /// # Errors
    ///
    /// Returns [`ExecResult::StackUnderflow`] if the stack is empty.
    pub const fn pop_i16_pub(&mut self) -> Result<i16, ExecResult> {
        self.pop_i16()
    }

    /// Allocate a 256-byte APDU buffer on the heap.
    pub fn alloc_apdu_buffer(&mut self) -> Option<ObjRef> {
        self.heap.alloc_byte_array(self.current_context, 256)
    }

    /// Allocate a byte array on the heap with the given length.
    pub fn alloc_byte_array(&mut self, length: u16) -> Option<ObjRef> {
        self.heap.alloc_byte_array(self.current_context, length)
    }

    /// Allocate a short array on the heap with the given length.
    pub fn alloc_short_array(&mut self, length: u16) -> Option<ObjRef> {
        self.heap.alloc_short_array(self.current_context, length)
    }

    /// Write a byte to a byte array (convenience for native methods / tests).
    pub fn heap_bastore(&mut self, obj: ObjRef, index: u16, value: u8) {
        let _ = self.heap.bastore(obj, index, value, self.current_context);
    }

    /// Read a byte from a byte array (convenience for native methods / tests).
    pub fn heap_baload(&self, obj: ObjRef, index: u16) -> Option<u8> {
        self.heap.baload(obj, index, self.current_context).ok()
    }

    /// `Util.arrayCopy` implementation: copy bytes between byte arrays on the heap.
    ///
    /// Returns `destOff + length` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ExecResult::ArrayIndexOutOfBounds`] for invalid offsets/lengths.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn native_array_copy(
        &mut self,
        src: ObjRef,
        src_off: i16,
        dest: ObjRef,
        dest_off: i16,
        length: i16,
    ) -> Result<i16, ExecResult> {
        if length < 0 || src_off < 0 || dest_off < 0 {
            return Err(ExecResult::ArrayIndexOutOfBounds);
        }
        if length == 0 {
            return Ok(dest_off);
        }
        // Read all bytes from src first (to handle overlapping same-array copies).
        let mut buf = [0u8; 256];
        let len = length as usize;
        if len > buf.len() {
            return Err(ExecResult::ArrayIndexOutOfBounds);
        }
        for (i, slot) in buf.iter_mut().enumerate().take(len) {
            let idx = (src_off as usize + i) as u16;
            match self.heap.baload(src, idx, self.current_context) {
                Ok(v) => *slot = v,
                Err(_) => return Err(ExecResult::ArrayIndexOutOfBounds),
            }
        }
        // Write to dest.
        for (i, &val) in buf.iter().enumerate().take(len) {
            let idx = (dest_off as usize + i) as u16;
            if self
                .heap
                .bastore(dest, idx, val, self.current_context)
                .is_err()
            {
                return Err(ExecResult::ArrayIndexOutOfBounds);
            }
        }
        Ok(dest_off.wrapping_add(length))
    }

    /// `Util.arrayCompare` implementation: compare bytes lexicographically.
    ///
    /// Returns -1, 0, or 1.
    ///
    /// # Errors
    ///
    /// Returns [`ExecResult::ArrayIndexOutOfBounds`] for invalid offsets/lengths.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn native_array_compare(
        &self,
        src: ObjRef,
        src_off: i16,
        dest: ObjRef,
        dest_off: i16,
        length: i16,
    ) -> Result<i8, ExecResult> {
        if length < 0 || src_off < 0 || dest_off < 0 {
            return Err(ExecResult::ArrayIndexOutOfBounds);
        }
        for i in 0..length as usize {
            let s_idx = (src_off as usize + i) as u16;
            let d_idx = (dest_off as usize + i) as u16;
            let s_val = self
                .heap
                .baload(src, s_idx, self.current_context)
                .map_err(|_| ExecResult::ArrayIndexOutOfBounds)?;
            let d_val = self
                .heap
                .baload(dest, d_idx, self.current_context)
                .map_err(|_| ExecResult::ArrayIndexOutOfBounds)?;
            if s_val < d_val {
                return Ok(-1);
            }
            if s_val > d_val {
                return Ok(1);
            }
        }
        Ok(0)
    }

    /// `Util.getShort` implementation: read a big-endian short from a byte array.
    ///
    /// # Errors
    ///
    /// Returns [`ExecResult::ArrayIndexOutOfBounds`] for invalid offsets.
    pub fn native_get_short(&self, arr: ObjRef, offset: i16) -> Result<i16, ExecResult> {
        if offset < 0 {
            return Err(ExecResult::ArrayIndexOutOfBounds);
        }
        let hi = self
            .heap
            .baload(arr, offset.cast_unsigned(), self.current_context)
            .map_err(|_| ExecResult::ArrayIndexOutOfBounds)?;
        let lo = self
            .heap
            .baload(arr, offset.cast_unsigned() + 1, self.current_context)
            .map_err(|_| ExecResult::ArrayIndexOutOfBounds)?;
        Ok(i16::from_be_bytes([hi, lo]))
    }

    /// `Util.setShort` implementation: write a big-endian short to a byte array.
    ///
    /// Returns `bOff + 2`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecResult::ArrayIndexOutOfBounds`] for invalid offsets.
    pub fn native_set_short(
        &mut self,
        arr: ObjRef,
        offset: i16,
        value: i16,
    ) -> Result<i16, ExecResult> {
        if offset < 0 {
            return Err(ExecResult::ArrayIndexOutOfBounds);
        }
        let bytes = value.to_be_bytes();
        self.heap
            .bastore(arr, offset.cast_unsigned(), bytes[0], self.current_context)
            .map_err(|_| ExecResult::ArrayIndexOutOfBounds)?;
        self.heap
            .bastore(
                arr,
                offset.cast_unsigned() + 1,
                bytes[1],
                self.current_context,
            )
            .map_err(|_| ExecResult::ArrayIndexOutOfBounds)?;
        Ok(offset.wrapping_add(2))
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

    // -------------------------------------------------------------------
    // Wide-offset conditional branches (JCVM 3.2 § 7.5)
    // -------------------------------------------------------------------
    //
    // Each test exercises:
    //   * the comparison logic: branches taken when the predicate
    //     holds, fallthrough otherwise
    //   * the wide operand decoding: 2-byte big-endian signed offset
    //   * the relative-to-opcode addressing: target = (pc-3) + offset
    //
    // Bytecode shape used throughout (forward jump, taken):
    //   [..push operands..]
    //   [<opcode>, hi, lo,  -- 3-byte branch
    //    SCONST_5, SRETURN, -- fall-through path returns 5
    //    SCONST_1, SRETURN] -- taken path returns 1
    //
    // The opcode is at PC = N (the operand-push length); after the
    // operand bytes, PC = N+3. With offset = 5, target = N + 5.

    #[test]
    fn ifeq_w_taken_when_zero() {
        let bc = [
            SCONST_0, IFEQ_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifeq_w_not_taken_when_nonzero_falls_through() {
        let bc = [
            SCONST_3, IFEQ_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ifne_w_taken_when_nonzero() {
        let bc = [
            SCONST_3, IFNE_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn iflt_w_taken_when_negative() {
        // sconst_m1 pushes -1.
        let bc = [
            SCONST_M1, IFLT_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifge_w_taken_when_zero() {
        // Zero is the boundary: ifge means >= 0, which includes 0.
        let bc = [
            SCONST_0, IFGE_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifgt_w_taken_when_positive() {
        let bc = [
            SCONST_3, IFGT_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifle_w_taken_when_zero() {
        // <= 0 boundary case at zero.
        let bc = [
            SCONST_0, IFLE_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifnull_w_taken_when_null() {
        // ACONST_NULL pushes 0 as a reference.
        let bc = [
            ACONST_NULL,
            IFNULL_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifnonnull_w_taken_when_nonnull() {
        let bc = [
            SCONST_3,
            IFNONNULL_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_acmpeq_w_taken_when_equal_refs() {
        // Two ACONST_NULLs are equal references.
        let bc = [
            ACONST_NULL,
            ACONST_NULL,
            IF_ACMPEQ_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_acmpne_w_taken_when_unequal_refs() {
        // ACONST_NULL (0) vs SCONST_1 (1): different reference values.
        let bc = [
            ACONST_NULL,
            SCONST_1,
            IF_ACMPNE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmpeq_w_taken_when_shorts_equal() {
        let bc = [
            SCONST_3,
            SCONST_3,
            IF_SCMPEQ_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmpne_w_taken_when_shorts_differ() {
        let bc = [
            SCONST_3,
            SCONST_4,
            IF_SCMPNE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmplt_w_taken_when_first_lt_second() {
        let bc = [
            SCONST_2,
            SCONST_5,
            IF_SCMPLT_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmpge_w_taken_when_equal() {
        // Boundary: equal shorts satisfy `>=`.
        let bc = [
            SCONST_3,
            SCONST_3,
            IF_SCMPGE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmpgt_w_taken_when_first_gt_second() {
        let bc = [
            SCONST_5,
            SCONST_2,
            IF_SCMPGT_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmple_w_taken_when_equal() {
        // Boundary: equal shorts satisfy `<=`.
        let bc = [
            SCONST_3,
            SCONST_3,
            IF_SCMPLE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifeq_w_reaches_offset_beyond_narrow_range() {
        // The whole point of the wide form: jump distances that the
        // narrow `[-128,+127]` byte-offset can't express. Layout:
        //   [0]    sconst_0          -- predicate value
        //   [1]    ifeq_w 0x00 0xC7  -- offset 199 doesn't fit in i8
        //   [4]    nop * 196         -- padding
        //   [200]  sconst_1
        //   [201]  sreturn
        // Branch target = (opcode_pc=1) + 199 = 200.
        let mut bc = [NOP; 202];
        bc[0] = SCONST_0;
        bc[1] = IFEQ_W;
        bc[2] = 0x00;
        bc[3] = 0xC7;
        // bc[4..200] left as NOP padding.
        bc[200] = SCONST_1;
        bc[201] = SRETURN;
        let mut vm = vm_with_method(&bc);
        assert_eq!(
            vm.execute(0, 0),
            ExecResult::ReturnShort(1),
            "wide IFEQ_W must reach offset 199 -- beyond narrow i8 range"
        );
    }

    #[test]
    fn ifeq_w_handles_negative_offset_for_backward_branch() {
        // Sign-extension regression: a 0xFFFx offset must move PC
        // backward. We jump forward over a return, then back into it.
        //
        //   [0]   goto_w +6            -- forward to pc=6
        //   [3]   nop                  -- padding
        //   [4]   sconst_1
        //   [5]   sreturn              <- backward IFEQ_W target
        //   [6]   sconst_0             -- predicate (true for IFEQ)
        //   [7]   ifeq_w 0xFFFD (-3)   -- opcode_pc=7, target = 7-3 = 4
        //   [10]  sconst_5
        //   [11]  sreturn              -- not reached if branch taken
        let bc = [
            GOTO_W, 0x00, 0x06, NOP, SCONST_1, SRETURN, SCONST_0, IFEQ_W, 0xFF, 0xFD, SCONST_5,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(
            vm.execute(0, 0),
            ExecResult::ReturnShort(1),
            "backward IFEQ_W with offset 0xFFFD must land at pc=4 (sconst_1; sreturn)"
        );
    }

    // -------------------------------------------------------------------
    // Wide-branch boundary / fall-through cases
    // -------------------------------------------------------------------
    //
    // These tests catch off-by-one mistakes in the comparison operator
    // -- e.g. `<` vs `<=`, `>` vs `>=`. A taken-only test for `iflt_w`
    // can't tell whether the implementation is `<` or `<=` because both
    // branch on a negative input. The boundary case at 0 disambiguates:
    // strictly-less must NOT branch on 0, and `<=` would.
    //
    // Same shape as the "taken" tests but the predicate is at the
    // boundary; expectation is fall-through to SCONST_5 (returns 5).

    #[test]
    fn iflt_w_not_taken_at_zero_boundary() {
        let bc = [
            SCONST_0, IFLT_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ifge_w_not_taken_when_negative() {
        let bc = [
            SCONST_M1, IFGE_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ifgt_w_not_taken_at_zero_boundary() {
        let bc = [
            SCONST_0, IFGT_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ifle_w_not_taken_when_positive() {
        let bc = [
            SCONST_3, IFLE_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ifne_w_not_taken_when_zero() {
        let bc = [
            SCONST_0, IFNE_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ifnull_w_not_taken_when_nonnull() {
        let bc = [
            SCONST_3, IFNULL_W, 0x00, 0x05, SCONST_5, SRETURN, SCONST_1, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ifnonnull_w_not_taken_when_null() {
        let bc = [
            ACONST_NULL,
            IFNONNULL_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_acmpeq_w_not_taken_when_unequal() {
        let bc = [
            ACONST_NULL,
            SCONST_1,
            IF_ACMPEQ_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_acmpne_w_not_taken_when_equal() {
        let bc = [
            ACONST_NULL,
            ACONST_NULL,
            IF_ACMPNE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_scmpeq_w_not_taken_when_unequal() {
        let bc = [
            SCONST_3,
            SCONST_4,
            IF_SCMPEQ_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_scmpne_w_not_taken_when_equal() {
        let bc = [
            SCONST_3,
            SCONST_3,
            IF_SCMPNE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_scmplt_w_not_taken_when_equal_boundary() {
        // Boundary: strict `<` must not branch on equal values.
        let bc = [
            SCONST_3,
            SCONST_3,
            IF_SCMPLT_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_scmpge_w_not_taken_when_first_less() {
        let bc = [
            SCONST_2,
            SCONST_5,
            IF_SCMPGE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_scmpgt_w_not_taken_when_equal_boundary() {
        // Boundary: strict `>` must not branch on equal values.
        let bc = [
            SCONST_3,
            SCONST_3,
            IF_SCMPGT_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn if_scmple_w_not_taken_when_first_greater() {
        let bc = [
            SCONST_5,
            SCONST_2,
            IF_SCMPLE_W,
            0x00,
            0x05,
            SCONST_5,
            SRETURN,
            SCONST_1,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
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

    // -----------------------------------------------------------------------
    // NOP
    // -----------------------------------------------------------------------

    #[test]
    fn nop_does_nothing() {
        let bc = [NOP, SCONST_3, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn nop_multiple() {
        let bc = [NOP, NOP, NOP, SCONST_5, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    // -----------------------------------------------------------------------
    // ACONST_NULL
    // -----------------------------------------------------------------------

    #[test]
    fn aconst_null_pushes_zero() {
        let bc = [ACONST_NULL, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    // -----------------------------------------------------------------------
    // Reference load/store (ALOAD/ASTORE)
    // -----------------------------------------------------------------------

    #[test]
    fn aload_astore_roundtrip() {
        // Store 42 via astore, load via aload.
        let bc = [BSPUSH, 42, ASTORE, 0, ALOAD, 0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(42));
    }

    #[test]
    fn aload_0_astore_0_roundtrip() {
        let bc = [SCONST_5, ASTORE_0, ALOAD_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn aload_0_through_3() {
        // Store distinct values in locals 0-3, load and add pairs.
        let bc = [
            BSPUSH, 10, ASTORE_0, BSPUSH, 20, SSTORE, 1, // use sstore for local 1
            ALOAD_0, ALOAD_1, SADD, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(30));
    }

    #[test]
    fn aload_2_and_3() {
        let bc = [
            BSPUSH, 7, SSTORE, 2, BSPUSH, 3, SSTORE, 3, ALOAD_2, ALOAD_3, SADD, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(10));
    }

    // -----------------------------------------------------------------------
    // SWAP
    // -----------------------------------------------------------------------

    #[test]
    fn swap_reverses_top_two() {
        // Push 3, push 5, swap -> top is 3, second is 5.
        // Then ssub: second - top = 5 - 3 = 2.
        let bc = [SCONST_3, SCONST_5, SWAP, SSUB, SRETURN];
        let mut vm = vm_with_method(&bc);
        // After swap: stack is [5, 3], ssub pops 3 (b) then 5 (a) -> 5 - 3 = 2.
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    #[test]
    fn swap_empty_stack_underflow() {
        let bc = [SWAP];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    #[test]
    fn swap_one_element_underflow() {
        let bc = [SCONST_1, SWAP];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    // -----------------------------------------------------------------------
    // IFEQ / IFNE / IFLT / IFGE / IFGT / IFLE
    // -----------------------------------------------------------------------

    #[test]
    fn ifeq_taken_when_zero() {
        // Push sentinel 1, push 0, ifeq +4, sconst_0 (skipped), sreturn (skipped), sreturn.
        // PC layout: 0:sconst_1, 1:sconst_0, 2:ifeq, 3:offset, 4:sconst_0, 5:sreturn, 6:sreturn
        // ifeq opcode at PC=2, offset=4 -> target = 2+4 = 6 (the final sreturn).
        let bc = [SCONST_1, SCONST_0, IFEQ, 4, SCONST_0, SRETURN, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifeq_not_taken_when_nonzero() {
        let bc = [SCONST_5, IFEQ, 3, SCONST_3, SRETURN];
        let mut vm = vm_with_method(&bc);
        // 5 != 0, so fall through.
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn ifne_taken_when_nonzero() {
        let bc = [SCONST_1, SCONST_5, IFNE, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        // 5 != 0, so branch taken.
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifne_not_taken_when_zero() {
        let bc = [SCONST_0, IFNE, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    #[test]
    fn iflt_taken_when_negative() {
        let bc = [SCONST_1, SCONST_M1, IFLT, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        // -1 < 0, branch taken.
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn iflt_not_taken_when_positive() {
        let bc = [SCONST_5, IFLT, 3, SCONST_3, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn ifge_taken_when_zero() {
        let bc = [SCONST_1, SCONST_0, IFGE, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifge_taken_when_positive() {
        let bc = [SCONST_1, SCONST_3, IFGE, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifge_not_taken_when_negative() {
        let bc = [SCONST_M1, IFGE, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    #[test]
    fn ifgt_taken_when_positive() {
        let bc = [SCONST_1, SCONST_3, IFGT, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifgt_not_taken_when_zero() {
        let bc = [SCONST_0, IFGT, 3, SCONST_2, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    #[test]
    fn ifle_taken_when_zero() {
        let bc = [SCONST_1, SCONST_0, IFLE, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifle_taken_when_negative() {
        let bc = [SCONST_1, SCONST_M1, IFLE, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifle_not_taken_when_positive() {
        let bc = [SCONST_5, IFLE, 3, SCONST_2, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    // -----------------------------------------------------------------------
    // IFNULL / IFNONNULL
    // -----------------------------------------------------------------------

    #[test]
    fn ifnull_taken_when_null() {
        let bc = [SCONST_1, ACONST_NULL, IFNULL, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifnull_not_taken_when_nonnull() {
        let bc = [SCONST_5, IFNULL, 3, SCONST_3, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn ifnonnull_taken_when_nonnull() {
        let bc = [SCONST_1, SCONST_5, IFNONNULL, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn ifnonnull_not_taken_when_null() {
        let bc = [ACONST_NULL, IFNONNULL, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    // -----------------------------------------------------------------------
    // GETSTATIC_B / PUTSTATIC_B
    // -----------------------------------------------------------------------

    #[test]
    fn putstatic_getstatic_roundtrip() {
        // putstatic_b field_offset=0, then getstatic_b field_offset=0.
        let bc = [BSPUSH, 42, PUTSTATIC_B, 0, 0, GETSTATIC_B, 0, 0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(42));
    }

    #[test]
    fn getstatic_default_zero() {
        // Read a static field that has not been written.
        let bc = [GETSTATIC_B, 5, 0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    #[test]
    fn putstatic_truncates_to_byte() {
        // Write 0x1234 to static field -- only low byte (0x34 = 52) should persist.
        let bc = [
            SSPUSH,
            0x01,
            0x34,
            PUTSTATIC_B,
            0,
            0,
            GETSTATIC_B,
            0,
            0,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0x34));
    }

    // -----------------------------------------------------------------------
    // INVOKEVIRTUAL (stub: same as invokestatic)
    // -----------------------------------------------------------------------

    #[test]
    fn invokevirtual_calls_method() {
        // Method 0: invokevirtual(0, 1), sreturn.
        // Method 1: sconst_3, sreturn.
        let method0 = [INVOKEVIRTUAL, 0, 1, SRETURN];
        let method1 = [SCONST_3, SRETURN];
        let mut vm = vm_with_methods(&[&method0, &method1]);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    // -----------------------------------------------------------------------
    // ATHROW
    // -----------------------------------------------------------------------

    #[test]
    fn athrow_uncaught() {
        let bc = [SSPUSH, 0x6F, 0x00, ATHROW];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::UncaughtException(0x6F00));
    }

    #[test]
    fn athrow_null() {
        let bc = [ACONST_NULL, ATHROW];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::UncaughtException(0));
    }

    // -----------------------------------------------------------------------
    // SIPUSH (alias for SSPUSH)
    // -----------------------------------------------------------------------

    #[test]
    fn sipush_is_sspush() {
        let bc = [SIPUSH, 0x00, 0x0A, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(10));
    }

    // -----------------------------------------------------------------------
    // INT CONSTANTS (iconst_m1..iconst_5, iipush)
    // -----------------------------------------------------------------------

    #[test]
    fn iconst_0_pushes_int_zero() {
        // iconst_0 pushes int 0, i2s truncates to short 0, sreturn.
        let bc = [ICONST_0, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    #[test]
    fn iconst_5_pushes_int_five() {
        let bc = [ICONST_5, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn iconst_m1_pushes_int_negative_one() {
        let bc = [ICONST_M1, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    #[test]
    fn iipush_pushes_int() {
        // iipush 0x00012345, i2s -> 0x2345 = 9029
        let bc = [IIPUSH, 0x00, 0x01, 0x23, 0x45, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0x2345));
    }

    #[test]
    fn iipush_negative() {
        // iipush -1 (0xFFFFFFFF), ireturn -> ReturnInt(-1)
        let bc = [IIPUSH, 0xFF, 0xFF, 0xFF, 0xFF, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(-1));
    }

    // -----------------------------------------------------------------------
    // INT ARITHMETIC (iadd, isub, imul, idiv, irem, ineg)
    // -----------------------------------------------------------------------

    #[test]
    fn iadd_basic() {
        // iconst_3 + iconst_5 = 8
        let bc = [ICONST_3, ICONST_5, IADD, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(8));
    }

    #[test]
    fn isub_basic() {
        let bc = [ICONST_5, ICONST_3, ISUB, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    #[test]
    fn imul_basic() {
        let bc = [ICONST_3, ICONST_4, IMUL, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(12));
    }

    #[test]
    fn idiv_basic() {
        // 5 / 3 = 1
        let bc = [ICONST_5, ICONST_3, IDIV, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn idiv_by_zero() {
        let bc = [ICONST_5, ICONST_0, IDIV];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArithmeticException);
    }

    #[test]
    fn irem_basic() {
        // 5 % 3 = 2
        let bc = [ICONST_5, ICONST_3, IREM, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    #[test]
    fn irem_by_zero() {
        let bc = [ICONST_5, ICONST_0, IREM];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArithmeticException);
    }

    #[test]
    fn ineg_basic() {
        let bc = [ICONST_5, INEG, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-5));
    }

    #[test]
    fn iadd_large_values() {
        // 0x10000 + 0x10000 = 0x20000 (crosses 16-bit boundary)
        let bc = [
            IIPUSH, 0x00, 0x01, 0x00, 0x00, // push 65536
            IIPUSH, 0x00, 0x01, 0x00, 0x00, // push 65536
            IADD, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(131_072));
    }

    // -----------------------------------------------------------------------
    // SHORT BITWISE (sshl, sshr, sushr, sand, sor, sxor)
    // -----------------------------------------------------------------------

    #[test]
    fn sshl_basic() {
        // 3 << 2 = 12
        let bc = [SCONST_3, SCONST_2, SSHL, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(12));
    }

    #[test]
    fn sshr_basic() {
        // -16 >> 2 = -4 (arithmetic shift)
        let bc = [BSPUSH, (-16i8).cast_unsigned(), SCONST_2, SSHR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-4));
    }

    #[test]
    fn sushr_basic() {
        // -1 (0xFFFF) >>> 8 = 0x00FF = 255
        let bc = [SCONST_M1, BSPUSH, 8, SUSHR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(255));
    }

    #[test]
    fn sand_basic() {
        // 0xFF & 0x0F = 0x0F = 15
        let bc = [
            BSPUSH,
            0xFF_u8.cast_signed().cast_unsigned(),
            BSPUSH,
            0x0F,
            SAND,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(15));
    }

    #[test]
    fn sor_basic() {
        // 0x0F | 0xF0 = 0xFF = -1 (as i16 after sign extension from byte)
        let bc = [BSPUSH, 0x0F, BSPUSH, 0x70, SOR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0x7F));
    }

    #[test]
    fn sxor_basic() {
        // 0xFF ^ 0xFF = 0
        let bc = [SCONST_M1, SCONST_M1, SXOR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    #[test]
    fn sshl_shift_mask() {
        // Shift amount masked to 5 bits: 33 & 0x1F = 1, so 1 << 1 = 2
        let bc = [SCONST_1, BSPUSH, 33, SSHL, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(2));
    }

    // -----------------------------------------------------------------------
    // INT BITWISE (ishl, ishr, iushr, iand, ior, ixor)
    // -----------------------------------------------------------------------

    #[test]
    fn ishl_basic() {
        // 3 << 16 = 196608
        let bc = [ICONST_3, BSPUSH, 16, ISHL, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(196_608));
    }

    #[test]
    fn ishr_basic() {
        // -1 >> 16 = -1 (arithmetic shift preserves sign)
        let bc = [ICONST_M1, BSPUSH, 16, ISHR, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(-1));
    }

    #[test]
    fn iushr_basic() {
        // -1 (0xFFFFFFFF) >>> 16 = 0x0000FFFF = 65535
        let bc = [ICONST_M1, BSPUSH, 16, IUSHR, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(65535));
    }

    #[test]
    fn iand_basic() {
        // 0xFFFFFFFF & 5 = 5
        let bc = [ICONST_M1, ICONST_5, IAND, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn ior_basic() {
        let bc = [ICONST_1, ICONST_2, IOR, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn ixor_basic() {
        // 5 ^ 3 = 6
        let bc = [ICONST_5, ICONST_3, IXOR, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(6));
    }

    // -----------------------------------------------------------------------
    // INCREMENT (sinc, iinc)
    // -----------------------------------------------------------------------

    #[test]
    fn sinc_basic() {
        // Store 10 in local 0, sinc 0, 5 -> local 0 becomes 15.
        let bc = [BSPUSH, 10, SSTORE_0, SINC, 0, 5, SLOAD_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(15));
    }

    #[test]
    fn sinc_negative() {
        // Store 10, sinc by -3 -> 7.
        let bc = [
            BSPUSH,
            10,
            SSTORE_0,
            SINC,
            0,
            (-3i8).cast_unsigned(),
            SLOAD_0,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(7));
    }

    #[test]
    fn iinc_basic() {
        // Store int 100 in locals 0,1, iinc 0 5 -> 105.
        let bc = [
            IIPUSH, 0x00, 0x00, 0x00, 100, ISTORE_0, IINC, 0, 5, ILOAD_0, I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(105));
    }

    // -----------------------------------------------------------------------
    // CONVERSIONS (s2b, s2i, i2b, i2s)
    // -----------------------------------------------------------------------

    #[test]
    fn s2b_truncates_to_byte() {
        // Push 0x1FF (511 as short), s2b -> -1 (sign-extended from 0xFF)
        let bc = [SSPUSH, 0x01, 0xFF, S2B, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    #[test]
    fn s2i_sign_extends() {
        // Push short -1, s2i -> int -1 (0xFFFFFFFF).
        let bc = [SCONST_M1, S2I, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(-1));
    }

    #[test]
    fn s2i_positive() {
        let bc = [SCONST_5, S2I, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(5));
    }

    #[test]
    fn i2b_truncates_to_byte() {
        // Push int 0x12FF, i2b -> -1 (0xFF sign-extended)
        let bc = [IIPUSH, 0x00, 0x00, 0x12, 0xFF, I2B, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    #[test]
    fn i2s_truncates() {
        // Push int 0x00012345, i2s -> 0x2345 = 9029
        let bc = [IIPUSH, 0x00, 0x01, 0x23, 0x45, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0x2345));
    }

    // -----------------------------------------------------------------------
    // ICMP
    // -----------------------------------------------------------------------

    #[test]
    fn icmp_greater() {
        let bc = [ICONST_5, ICONST_3, ICMP, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn icmp_equal() {
        let bc = [ICONST_3, ICONST_3, ICMP, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    #[test]
    fn icmp_less() {
        let bc = [ICONST_1, ICONST_5, ICMP, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    // -----------------------------------------------------------------------
    // INT LOCALS (iload, iload_0..3, istore, istore_0..3)
    // -----------------------------------------------------------------------

    #[test]
    fn istore_iload_roundtrip() {
        // Push int 42, store to locals 0,1, load back, check via i2s.
        let bc = [
            IIPUSH, 0x00, 0x00, 0x00, 42, ISTORE_0, ILOAD_0, I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(42));
    }

    #[test]
    fn istore_iload_with_index() {
        let bc = [
            IIPUSH, 0x00, 0x00, 0x00, 99, ISTORE, 2, ILOAD, 2, I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(99));
    }

    #[test]
    fn iload_2_and_3() {
        let bc = [
            IIPUSH, 0x00, 0x00, 0x00, 10, ISTORE_2, IIPUSH, 0x00, 0x00, 0x00, 20, ISTORE, 4,
            ILOAD_2, ILOAD, 4, IADD, I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(30));
    }

    // -----------------------------------------------------------------------
    // IRETURN / ARETURN
    // -----------------------------------------------------------------------

    #[test]
    fn ireturn_basic() {
        let bc = [ICONST_3, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(3));
    }

    #[test]
    fn areturn_basic() {
        // areturn with a non-null reference (just a number).
        let bc = [BSPUSH, 42, ARETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnRef(42));
    }

    #[test]
    fn areturn_null() {
        let bc = [ACONST_NULL, ARETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnRef(0));
    }

    // -----------------------------------------------------------------------
    // POP2 / DUP2
    // -----------------------------------------------------------------------

    #[test]
    fn pop2_removes_two_words() {
        // Push 1, 2, 3, pop2 -> top is 1.
        let bc = [SCONST_1, SCONST_2, SCONST_3, POP2, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn dup2_duplicates_two_words() {
        // Push 3, 5, dup2 -> stack is [3, 5, 3, 5], sadd -> 8 on top of [3, 5].
        // Then sadd -> 13, sadd -> 16... Let's just verify dup2 then add.
        let bc = [SCONST_3, SCONST_5, DUP2, SADD, SRETURN];
        let mut vm = vm_with_method(&bc);
        // dup2: stack = [3, 5, 3, 5]. sadd: 3+5=8, stack = [3, 5, 8].
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(8));
    }

    // -----------------------------------------------------------------------
    // SHORT COMPARISON BRANCHES (if_scmplt/ge/gt/le)
    // -----------------------------------------------------------------------

    #[test]
    fn if_scmplt_taken() {
        // Push sentinel 1, push 3, push 5, if_scmplt -> 3 < 5 is true, branch.
        let bc = [
            SCONST_1, SCONST_3, SCONST_5, IF_SCMPLT, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmplt_not_taken() {
        let bc = [SCONST_5, SCONST_3, IF_SCMPLT, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    #[test]
    fn if_scmpge_taken() {
        let bc = [
            SCONST_1, SCONST_5, SCONST_3, IF_SCMPGE, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmpgt_taken() {
        let bc = [
            SCONST_1, SCONST_5, SCONST_3, IF_SCMPGT, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_scmple_taken() {
        let bc = [
            SCONST_1, SCONST_3, SCONST_5, IF_SCMPLE, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    // -----------------------------------------------------------------------
    // REFERENCE COMPARISON BRANCHES (if_acmpeq, if_acmpne)
    // -----------------------------------------------------------------------

    #[test]
    fn if_acmpeq_taken() {
        // Push sentinel 1, push null, push null, if_acmpeq -> taken.
        let bc = [
            SCONST_1,
            ACONST_NULL,
            ACONST_NULL,
            IF_ACMPEQ,
            3,
            SCONST_0,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn if_acmpne_taken() {
        let bc = [
            SCONST_1, SCONST_0, SCONST_1, IF_ACMPNE, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    // -----------------------------------------------------------------------
    // SWITCH (stableswitch, slookupswitch)
    // -----------------------------------------------------------------------

    #[test]
    fn stableswitch_in_range() {
        // Switch on value 2, range [1..3], offset table maps to specific PCs.
        // stableswitch opcode at PC 1 (after sconst_2 at PC 0).
        // Format: default_offset(2) | low(2) | high(2) | offset[0](2) | offset[1](2) | offset[2](2)
        // offsets relative to stableswitch opcode (PC 1).
        // After the instruction: 1 + 1 + 2 + 2 + 2 + 6 = PC 14.
        // We want case 2 (index 1) to jump to some target.
        let bc = [
            SCONST_2,     // PC 0
            STABLESWITCH, // PC 1
            0x00,
            15, // default_offset = 15 -> PC 16 (dead code area)
            0x00,
            0x01, // low = 1
            0x00,
            0x03, // high = 3
            0x00,
            13, // offset for key=1: -> PC 1+13 = 14
            0x00,
            13, // offset for key=2: -> PC 1+13 = 14
            0x00,
            13, // offset for key=3: -> PC 1+13 = 14
            SCONST_3,
            SRETURN, // PC 14, 15 -- all cases land here
            SCONST_0,
            SRETURN, // PC 16, 17 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn stableswitch_default() {
        // Switch on value 10, range [1..3] -> falls to default.
        // BSPUSH at PC 0-1, STABLESWITCH at PC 2.
        // After header: 1+2+2+2+6 = 13 bytes, so cases at PC 15, default at PC 17.
        let bc = [
            BSPUSH,
            10,           // PC 0-1
            STABLESWITCH, // PC 2
            0x00,
            15, // default_offset = 15 -> PC 2+15 = 17
            0x00,
            0x01, // low = 1
            0x00,
            0x03, // high = 3
            0x00,
            13, // offset key=1 -> PC 2+13 = 15
            0x00,
            13, // offset key=2
            0x00,
            13, // offset key=3
            SCONST_3,
            SRETURN, // PC 15, 16 -- cases
            SCONST_5,
            SRETURN, // PC 17, 18 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn slookupswitch_match() {
        // lookupswitch: key=5, pairs: {5 -> target, 10 -> other}
        let bc = [
            SCONST_5,
            SLOOKUPSWITCH, // PC 1
            0x00,
            15, // default_offset = 15 -> PC 16
            0x00,
            0x02, // npairs = 2
            0x00,
            0x05, // match 5
            0x00,
            11, // offset -> PC 1+11 = 12
            0x00,
            0x0A, // match 10
            0x00,
            11, // offset -> PC 1+11 = 12
            SCONST_3,
            SRETURN, // PC 12, 13 -- match target
            SCONST_0,
            SRETURN, // PC 14, 15 (padding)
            SCONST_M1,
            SRETURN, // PC 16, 17 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn slookupswitch_default() {
        // lookupswitch: key=99, no match -> default.
        // BSPUSH at PC 0-1, SLOOKUPSWITCH at PC 2.
        // Header: 1+2+2 = 5 bytes, pairs: 1*4 = 4 bytes, so match at PC 11, default at PC 13.
        let bc = [
            BSPUSH,
            99,            // PC 0-1
            SLOOKUPSWITCH, // PC 2
            0x00,
            11, // default_offset = 11 -> PC 2+11 = 13
            0x00,
            0x01, // npairs = 1
            0x00,
            0x05, // match 5
            0x00,
            9, // offset -> PC 2+9 = 11
            SCONST_3,
            SRETURN, // PC 11, 12 -- match
            SCONST_M1,
            SRETURN, // PC 13, 14 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    // -----------------------------------------------------------------------
    // FIELD ACCESS: SHORT, REFERENCE, INT
    // -----------------------------------------------------------------------

    #[test]
    fn putfield_getfield_short_roundtrip() {
        // Allocate object with 4 field bytes, store short 0x1234, read it back.
        let bc = [
            NEW, 4, 0,   // 0-2: allocate instance
            DUP, // 3: dup objref
            SSPUSH, 0x12, 0x34, // 4-6: push 0x1234
            PUTFIELD_S, 0, 0, // 7-9: store short at offset 0
            GETFIELD_S, 0, 0,       // 10-12: read short at offset 0
            SRETURN, // 13
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0x1234));
    }

    #[test]
    fn putfield_getfield_ref_roundtrip() {
        // Store a reference value in an object field.
        let bc = [
            NEW, 4, 0,   // 0-2: allocate
            DUP, // 3: dup objref
            BSPUSH, 42, // 4-5: push 42
            PUTFIELD_A, 0, 0, // 6-8: store ref at offset 0
            GETFIELD_A, 0, 0,       // 9-11: read ref at offset 0
            SRETURN, // 12
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(42));
    }

    #[test]
    fn putfield_getfield_int_roundtrip() {
        // Store int in an object field (needs at least 4 bytes).
        let bc = [
            NEW, 8, 0,   // 0-2: allocate instance with 8 field bytes
            DUP, // 3: dup objref
            IIPUSH, 0x00, 0x01, 0x23, 0x45, // 4-8: push int
            PUTFIELD_I, 0, 0, // 9-11: store int at offset 0
            GETFIELD_I, 0, 0,       // 12-14: read int at offset 0
            IRETURN, // 15
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(0x0001_2345));
    }

    // -----------------------------------------------------------------------
    // STATIC FIELD ACCESS: SHORT, INT
    // -----------------------------------------------------------------------

    #[test]
    fn putstatic_getstatic_short_roundtrip() {
        let bc = [
            SSPUSH,
            0x12,
            0x34,
            PUTSTATIC_S,
            0x00,
            0x00,
            GETSTATIC_S,
            0x00,
            0x00,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0x1234));
    }

    #[test]
    fn putstatic_getstatic_int_roundtrip() {
        let bc = [
            IIPUSH,
            0x00,
            0x01,
            0x23,
            0x45,
            PUTSTATIC_I,
            0x00,
            0x10,
            GETSTATIC_I,
            0x00,
            0x10,
            IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(0x0001_2345));
    }

    // -----------------------------------------------------------------------
    // INVOKE: invokespecial / invokeinterface
    // -----------------------------------------------------------------------

    #[test]
    fn invokespecial_calls_method() {
        let method0 = [INVOKESPECIAL, 0, 1, SRETURN];
        let method1 = [SCONST_3, SRETURN];
        let mut vm = vm_with_methods(&[&method0, &method1]);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn invokeinterface_calls_method() {
        let method0 = [INVOKEINTERFACE, 0, 1, SRETURN];
        let method1 = [SCONST_4, SRETURN];
        let mut vm = vm_with_methods(&[&method0, &method1]);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    // -----------------------------------------------------------------------
    // CHECKCAST / INSTANCEOF (stubs)
    // -----------------------------------------------------------------------

    #[test]
    fn checkcast_noop() {
        // checkcast always succeeds, objectref stays on stack.
        let bc = [SCONST_5, CHECKCAST, 0, 0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    #[test]
    fn instanceof_nonnull() {
        let bc = [SCONST_5, INSTANCEOF, 0, 0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    #[test]
    fn instanceof_null() {
        let bc = [ACONST_NULL, INSTANCEOF, 0, 0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    // -----------------------------------------------------------------------
    // ANEWARRAY
    // -----------------------------------------------------------------------

    #[test]
    fn anewarray_and_arraylength() {
        let bc = [SCONST_3, ANEWARRAY, 0, ARRAYLENGTH, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    #[test]
    fn anewarray_negative_length() {
        let bc = [SCONST_M1, ANEWARRAY, 0];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NegativeArraySize);
    }

    // =======================================================================
    // PRIORITY 1: Arithmetic exceptions -- div/rem by zero
    // JCVM 3.1 Ch7 sdiv/srem/idiv/irem: "If the value of the divisor
    // is zero, sdiv/srem/idiv/irem throws an ArithmeticException."
    // =======================================================================

    /// JCVM 3.1 Ch7 srem: `ArithmeticException` when divisor is zero.
    /// (`sdiv_by_zero` already exists above; this tests srem with an
    /// explicit non-trivial dividend to avoid identity traps.)
    #[test]
    fn srem_by_zero_nontrivial_dividend() {
        let min_bytes = i16::MIN.cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, min_bytes[0], min_bytes[1], SCONST_0, SREM];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArithmeticException);
    }

    /// JCVM 3.1 Ch7 idiv: `ArithmeticException` with `i32::MIN` dividend and 0 divisor.
    #[test]
    fn idiv_by_zero_min_dividend() {
        let bc = [
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            ICONST_0, IDIV,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArithmeticException);
    }

    /// JCVM 3.1 Ch7 irem: `ArithmeticException` with `i32::MIN` dividend and 0 divisor.
    #[test]
    fn irem_by_zero_min_dividend() {
        let bc = [
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            ICONST_0, IREM,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArithmeticException);
    }

    /// JCVM 3.1 Ch7 idiv: `i32::MIN` / -1 = `i32::MIN` (wrapping, not exception).
    #[test]
    fn idiv_min_by_neg1() {
        let bc = [
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            ICONST_M1, IDIV, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(i32::MIN));
    }

    /// JCVM 3.1 Ch7 irem: `i32::MIN` % -1 = 0 (wrapping, not exception).
    #[test]
    fn irem_min_by_neg1() {
        let bc = [
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            ICONST_M1, IREM, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(0));
    }

    // =======================================================================
    // PRIORITY 2: Overflow/wrapping per Java semantics
    // JCVM 3.1 Ch7: arithmetic wraps modulo 2^16 / 2^32.
    // =======================================================================

    /// JCVM 3.1 Ch7 sadd: `i16::MAX` + 1 wraps to `i16::MIN`.
    #[test]
    fn sadd_overflow_wraps() {
        let max_bytes = i16::MAX.cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, max_bytes[0], max_bytes[1], SCONST_1, SADD, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(i16::MIN));
    }

    /// JCVM 3.1 Ch7 ssub: `i16::MIN` - 1 wraps to `i16::MAX`.
    #[test]
    fn ssub_underflow_wraps() {
        let min_bytes = i16::MIN.cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, min_bytes[0], min_bytes[1], SCONST_1, SSUB, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(i16::MAX));
    }

    /// JCVM 3.1 Ch7 smul: 0x7FFF * 2 wraps.
    #[test]
    fn smul_overflow_wraps() {
        let max_bytes = i16::MAX.cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, max_bytes[0], max_bytes[1], SCONST_2, SMUL, SRETURN];
        let mut vm = vm_with_method(&bc);
        let expected = i16::MAX.wrapping_mul(2);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
    }

    /// JCVM 3.1 Ch7 iadd: `i32::MAX` + 1 wraps to `i32::MIN`.
    #[test]
    fn iadd_overflow_wraps() {
        let bc = [
            IIPUSH, 0x7F, 0xFF, 0xFF, 0xFF, // i32::MAX
            ICONST_1, IADD, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(i32::MIN));
    }

    /// JCVM 3.1 Ch7 isub: `i32::MIN` - 1 wraps to `i32::MAX`.
    #[test]
    fn isub_underflow_wraps() {
        let bc = [
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            ICONST_1, ISUB, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(i32::MAX));
    }

    /// JCVM 3.1 Ch7 imul: `i32::MAX` * 2 wraps.
    #[test]
    fn imul_overflow_wraps() {
        let bc = [
            IIPUSH, 0x7F, 0xFF, 0xFF, 0xFF, // i32::MAX
            ICONST_2, IMUL, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(
            vm.execute(0, 0),
            ExecResult::ReturnInt(i32::MAX.wrapping_mul(2))
        );
    }

    /// JCVM 3.1 Ch7 sneg: `sneg(i16::MIN)` wraps to `i16::MIN`.
    #[test]
    fn sneg_min_wraps() {
        let min_bytes = i16::MIN.cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, min_bytes[0], min_bytes[1], SNEG, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(i16::MIN));
    }

    /// JCVM 3.1 Ch7 ineg: `ineg(i32::MIN)` wraps to `i32::MIN`.
    #[test]
    fn ineg_min_wraps() {
        let bc = [
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            INEG, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(i32::MIN));
    }

    // =======================================================================
    // PRIORITY 3: Bitwise edge cases
    // JCVM 3.1 Ch7 sshl/sshr/sushr: shift amount masked to low 5 bits.
    // =======================================================================

    /// JCVM 3.1 Ch7 sshl: shift by 0 is identity.
    #[test]
    fn sshl_by_zero() {
        let bc = [SCONST_5, SCONST_0, SSHL, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    /// JCVM 3.1 Ch7 sshl: shift by 15 pushes sign bit into MSB.
    #[test]
    fn sshl_by_15() {
        let bc = [SCONST_1, BSPUSH, 15, SSHL, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(i16::MIN));
    }

    /// JCVM 3.1 Ch7 sshl: shift by 16 (masked to 16 & 0x1F = 16) zeroes short.
    #[test]
    fn sshl_by_16() {
        let bc = [SCONST_1, BSPUSH, 16, SSHL, SRETURN];
        let mut vm = vm_with_method(&bc);
        // 1 << 16 = 0x10000, masked to 16 bits = 0
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    /// JCVM 3.1 Ch7 sshr: shift by 0 is identity.
    #[test]
    fn sshr_by_zero() {
        let bc = [SCONST_M1, SCONST_0, SSHR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    /// JCVM 3.1 Ch7 sshr: shift by 15 extracts sign.
    #[test]
    fn sshr_by_15() {
        let min_bytes = i16::MIN.cast_unsigned().to_be_bytes();
        let bc = [
            SSPUSH,
            min_bytes[0],
            min_bytes[1],
            BSPUSH,
            15,
            SSHR,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    /// JCVM 3.1 Ch7 sushr: shift by 15 extracts unsigned MSB.
    #[test]
    fn sushr_by_15() {
        let bc = [SCONST_M1, BSPUSH, 15, SUSHR, SRETURN];
        let mut vm = vm_with_method(&bc);
        // 0xFFFF >>> 15 = 1
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    /// JCVM 3.1 Ch7 sand: AND with 0 is 0.
    #[test]
    fn sand_with_zero() {
        let bc = [SCONST_M1, SCONST_0, SAND, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    /// JCVM 3.1 Ch7 sand: AND with 0xFFFF is identity.
    #[test]
    fn sand_with_all_ones() {
        let bc = [SCONST_5, SCONST_M1, SAND, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    /// JCVM 3.1 Ch7 sor: OR with 0 is identity.
    #[test]
    fn sor_with_zero() {
        let bc = [SCONST_3, SCONST_0, SOR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    /// JCVM 3.1 Ch7 sor: OR with 0xFFFF is 0xFFFF.
    #[test]
    fn sor_with_all_ones() {
        let bc = [SCONST_0, SCONST_M1, SOR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    /// JCVM 3.1 Ch7 sxor: XOR with 0 is identity.
    #[test]
    fn sxor_with_zero() {
        let bc = [SCONST_5, SCONST_0, SXOR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    /// JCVM 3.1 Ch7 sxor: XOR with self is 0.
    #[test]
    fn sxor_self_is_zero() {
        let bc = [SCONST_5, SCONST_5, SXOR, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    /// JCVM 3.1 Ch7 ishl: shift by 31 puts bit 0 into sign position.
    #[test]
    fn ishl_by_31() {
        let bc = [ICONST_1, BSPUSH, 31, ISHL, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(i32::MIN));
    }

    /// JCVM 3.1 Ch7 ishr: arithmetic shift of -1 by 31 is still -1.
    #[test]
    fn ishr_neg1_by_31() {
        let bc = [ICONST_M1, BSPUSH, 31, ISHR, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(-1));
    }

    /// JCVM 3.1 Ch7 iushr: unsigned shift of -1 by 31 is 1.
    #[test]
    fn iushr_neg1_by_31() {
        let bc = [ICONST_M1, BSPUSH, 31, IUSHR, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(1));
    }

    // =======================================================================
    // PRIORITY 4: Conversion edge cases
    // JCVM 3.1 Ch7 s2b/i2s: narrowing conversions truncate then sign-extend.
    // =======================================================================

    /// JCVM 3.1 Ch7 s2b: s2b(127) = 127 (fits in byte).
    #[test]
    fn s2b_127() {
        let bc = [BSPUSH, 127, S2B, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(127));
    }

    /// JCVM 3.1 Ch7 s2b: s2b(128) = -128 (truncate to 0x80 then sign-extend).
    #[test]
    fn s2b_128() {
        let val_bytes = 128u16.to_be_bytes();
        let bc = [SSPUSH, val_bytes[0], val_bytes[1], S2B, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-128));
    }

    /// JCVM 3.1 Ch7 s2b: s2b(-128) = -128 (already fits in signed byte).
    #[test]
    fn s2b_neg128() {
        let bc = [BSPUSH, (-128i8).cast_unsigned(), S2B, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-128));
    }

    /// JCVM 3.1 Ch7 s2b: s2b(-129) = 127 (truncates: 0xFF7F & 0xFF = 0x7F = 127).
    #[test]
    fn s2b_neg129() {
        let val = (-129i16).cast_unsigned().to_be_bytes();
        let bc = [SSPUSH, val[0], val[1], S2B, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(127));
    }

    /// JCVM 3.1 Ch7 s2b: s2b(0) = 0.
    #[test]
    fn s2b_zero() {
        let bc = [SCONST_0, S2B, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    /// JCVM 3.1 Ch7 i2s: i2s(32767) = 32767 (fits in short).
    #[test]
    fn i2s_max_short() {
        let bc = [
            IIPUSH, 0x00, 0x00, 0x7F, 0xFF, // 32767
            I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(32767));
    }

    /// JCVM 3.1 Ch7 i2s: i2s(32768) = -32768 (truncate low 16 bits = 0x8000).
    #[test]
    fn i2s_32768() {
        let bc = [
            IIPUSH, 0x00, 0x00, 0x80, 0x00, // 32768
            I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-32768));
    }

    /// JCVM 3.1 Ch7 i2s: i2s(-32768) = -32768 (already fits).
    #[test]
    fn i2s_neg32768() {
        let bc = [
            IIPUSH, 0xFF, 0xFF, 0x80, 0x00, // -32768
            I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-32768));
    }

    /// JCVM 3.1 Ch7 i2s: i2s(0) = 0.
    #[test]
    fn i2s_zero() {
        let bc = [ICONST_0, I2S, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    /// JCVM 3.1 Ch7 i2b: i2b(127) = 127.
    #[test]
    fn i2b_127() {
        let bc = [
            IIPUSH, 0x00, 0x00, 0x00, 127, // 127
            I2B, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(127));
    }

    /// JCVM 3.1 Ch7 i2b: i2b(128) = -128.
    #[test]
    fn i2b_128() {
        let bc = [
            IIPUSH, 0x00, 0x00, 0x00, 0x80, // 128
            I2B, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-128));
    }

    // =======================================================================
    // PRIORITY 5: Branch tests -- true and false for each comparison
    // Most branches have existing taken/not-taken tests. Adding missing ones.
    // =======================================================================

    /// JCVM 3.1 Ch7 `if_scmpge`: not taken when a < b.
    #[test]
    fn if_scmpge_not_taken() {
        let bc = [SCONST_3, SCONST_5, IF_SCMPGE, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    /// JCVM 3.1 Ch7 `if_scmpge`: taken when a == b (edge: equality).
    #[test]
    fn if_scmpge_taken_equal() {
        let bc = [
            SCONST_1, SCONST_3, SCONST_3, IF_SCMPGE, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    /// JCVM 3.1 Ch7 `if_scmpgt`: not taken when a == b.
    #[test]
    fn if_scmpgt_not_taken() {
        let bc = [SCONST_3, SCONST_3, IF_SCMPGT, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    /// JCVM 3.1 Ch7 `if_scmpgt`: not taken when a < b.
    #[test]
    fn if_scmpgt_not_taken_less() {
        let bc = [SCONST_3, SCONST_5, IF_SCMPGT, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    /// JCVM 3.1 Ch7 `if_scmple`: not taken when a > b.
    #[test]
    fn if_scmple_not_taken() {
        let bc = [SCONST_5, SCONST_3, IF_SCMPLE, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    /// JCVM 3.1 Ch7 `if_scmple`: taken when a == b (edge: equality).
    #[test]
    fn if_scmple_taken_equal() {
        let bc = [
            SCONST_1, SCONST_3, SCONST_3, IF_SCMPLE, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    /// JCVM 3.1 Ch7 `if_scmpeq`: with negative values, true case.
    #[test]
    fn if_scmpeq_negative_taken() {
        let bc = [
            SCONST_1, SCONST_M1, SCONST_M1, IF_SCMPEQ, 3, SCONST_0, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    /// JCVM 3.1 Ch7 `if_acmpeq`: not taken when references differ.
    #[test]
    fn if_acmpeq_not_taken() {
        let bc = [SCONST_1, SCONST_2, IF_ACMPEQ, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    /// JCVM 3.1 Ch7 `if_acmpne`: not taken when references are equal.
    #[test]
    fn if_acmpne_not_taken() {
        let bc = [ACONST_NULL, ACONST_NULL, IF_ACMPNE, 3, SCONST_4, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(4));
    }

    /// JCVM 3.1 Ch7 iflt: not taken when val == 0 (boundary).
    #[test]
    fn iflt_not_taken_when_zero() {
        let bc = [SCONST_0, IFLT, 3, SCONST_3, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    /// JCVM 3.1 Ch7 ifgt: not taken when val == -1 (negative).
    #[test]
    fn ifgt_not_taken_when_negative() {
        let bc = [SCONST_M1, IFGT, 3, SCONST_3, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    /// JCVM 3.1 Ch7 ifle: taken when val == 0 (boundary: equal to zero).
    #[test]
    fn ifle_taken_when_zero_boundary() {
        let bc = [SCONST_1, SCONST_0, IFLE, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    /// JCVM 3.1 Ch7 ifge: taken when val == 0 (boundary: equal to zero).
    #[test]
    fn ifge_taken_when_zero_boundary() {
        let bc = [SCONST_1, SCONST_0, IFGE, 3, SCONST_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    // =======================================================================
    // PRIORITY 6: Stack underflow for each category
    // =======================================================================

    /// JCVM 3.1 Ch7 sadd: `StackUnderflow` on empty stack.
    #[test]
    fn sadd_underflow() {
        let bc = [SCONST_1, SADD];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    /// JCVM 3.1 Ch7 sreturn: `StackUnderflow` when returning with empty stack.
    #[test]
    fn sreturn_underflow() {
        let bc = [SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    /// JCVM 3.1 Ch7 ireturn: `StackUnderflow` on empty stack (needs 2 words).
    #[test]
    fn ireturn_underflow() {
        let bc = [IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    /// JCVM 3.1 Ch7 dup2: `StackUnderflow` when only 1 element.
    #[test]
    fn dup2_underflow_one_element() {
        let bc = [SCONST_1, DUP2];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    /// JCVM 3.1 Ch7 dup2: `StackUnderflow` when stack is empty.
    #[test]
    fn dup2_underflow_empty() {
        let bc = [DUP2];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    /// JCVM 3.1 Ch7 pop2: `StackUnderflow` when only 1 element.
    #[test]
    fn pop2_underflow_one_element() {
        let bc = [SCONST_1, POP2];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    /// JCVM 3.1 Ch7 iadd: `StackUnderflow` with only one int on stack.
    #[test]
    fn iadd_underflow() {
        let bc = [ICONST_1, IADD];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::StackUnderflow);
    }

    // =======================================================================
    // PRIORITY 7: Null reference exceptions
    // =======================================================================

    /// JCVM 3.1 Ch7 `getfield_b`: `NullPointerException` on null objectref.
    #[test]
    fn getfield_b_null_ref() {
        let bc = [ACONST_NULL, GETFIELD_B, 0, 0];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    /// JCVM 3.1 Ch7 `getfield_s`: `NullPointerException` on null objectref.
    #[test]
    fn getfield_s_null_ref() {
        let bc = [ACONST_NULL, GETFIELD_S, 0, 0];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    /// JCVM 3.1 Ch7 `getfield_i`: `NullPointerException` on null objectref.
    #[test]
    fn getfield_i_null_ref() {
        let bc = [ACONST_NULL, GETFIELD_I, 0, 0];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    /// JCVM 3.1 Ch7 `putfield_b`: `NullPointerException` on null objectref.
    #[test]
    fn putfield_b_null_ref() {
        let bc = [ACONST_NULL, SCONST_1, PUTFIELD_B, 0, 0];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    /// JCVM 3.1 Ch7 baload: `NullPointerException` on null arrayref.
    #[test]
    fn baload_null_ref() {
        let bc = [ACONST_NULL, SCONST_0, BALOAD];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    /// JCVM 3.1 Ch7 bastore: `NullPointerException` on null arrayref.
    #[test]
    fn bastore_null_ref() {
        let bc = [ACONST_NULL, SCONST_0, SCONST_1, BASTORE];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    /// JCVM 3.1 Ch7 saload: `NullPointerException` on null arrayref.
    #[test]
    fn saload_null_ref() {
        let bc = [ACONST_NULL, SCONST_0, SALOAD];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    // =======================================================================
    // PRIORITY 8: Array bounds checking
    // =======================================================================

    /// JCVM 3.1 Ch7 baload: `ArrayIndexOutOfBounds` when index == length.
    #[test]
    fn baload_out_of_bounds() {
        // Create byte array of length 3, then load index 3 (OOB).
        let bc = [
            SCONST_3, NEWARRAY, 10,       // alloc byte[3]
            SCONST_3, // push index 3 (== length)
            BALOAD,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArrayIndexOutOfBounds);
    }

    /// JCVM 3.1 Ch7 baload: index 0 (first element) succeeds.
    #[test]
    fn baload_index_zero() {
        let bc = [
            SCONST_3, NEWARRAY, 10, // alloc byte[3]
            DUP, SCONST_0, // index
            BSPUSH, 42,       // value
            BASTORE,  // store 42 at index 0
            SCONST_0, // index
            BALOAD,   // load from index 0
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(42));
    }

    /// JCVM 3.1 Ch7 baload: index length-1 (last element) succeeds.
    #[test]
    fn baload_last_index() {
        let bc = [
            SCONST_3, NEWARRAY, 10, // alloc byte[3]
            DUP, SCONST_2, // index = length-1 = 2
            BSPUSH, 99,       // value
            BASTORE,  // store
            SCONST_2, // index
            BALOAD,   // load
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(99));
    }

    /// JCVM 3.1 Ch7 bastore: `ArrayIndexOutOfBounds` when index == length.
    #[test]
    fn bastore_out_of_bounds() {
        let bc = [
            SCONST_3, NEWARRAY, 10,       // alloc byte[3]
            SCONST_3, // index 3 (OOB)
            SCONST_1, // value
            BASTORE,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ArrayIndexOutOfBounds);
    }

    // =======================================================================
    // PRIORITY 9: sinc/iinc edge cases
    // =======================================================================

    /// JCVM 3.1 Ch7 sinc: increment by max positive byte constant (127).
    #[test]
    fn sinc_max_positive() {
        let bc = [SCONST_0, SSTORE_0, SINC, 0, 127, SLOAD_0, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(127));
    }

    /// JCVM 3.1 Ch7 sinc: increment overflow wraps (32767 + 1 = -32768).
    #[test]
    fn sinc_overflow_wraps() {
        let max_bytes = i16::MAX.cast_unsigned().to_be_bytes();
        let bc = [
            SSPUSH,
            max_bytes[0],
            max_bytes[1],
            SSTORE_0,
            SINC,
            0,
            1,
            SLOAD_0,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(i16::MIN));
    }

    /// JCVM 3.1 Ch7 sinc: increment by min negative byte constant (-128).
    #[test]
    fn sinc_min_negative() {
        let bc = [
            SCONST_0,
            SSTORE_0,
            SINC,
            0,
            (-128i8).cast_unsigned(),
            SLOAD_0,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-128));
    }

    /// JCVM 3.1 Ch7 iinc: increment by negative constant.
    #[test]
    fn iinc_negative() {
        let bc = [
            IIPUSH,
            0x00,
            0x00,
            0x00,
            100,
            ISTORE_0,
            IINC,
            0,
            (-5i8).cast_unsigned(),
            ILOAD_0,
            I2S,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(95));
    }

    /// JCVM 3.1 Ch7 iinc: int increment overflow wraps.
    #[test]
    fn iinc_overflow_wraps() {
        let bc = [
            IIPUSH, 0x7F, 0xFF, 0xFF, 0xFF, // i32::MAX
            ISTORE_0, IINC, 0, 1, ILOAD_0, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(i32::MIN));
    }

    // =======================================================================
    // PRIORITY 10: Switch tests (additional coverage)
    // =======================================================================

    /// JCVM 3.1 Ch7 stableswitch: key at low boundary (key == low).
    #[test]
    fn stableswitch_low_boundary() {
        let bc = [
            SCONST_1,     // PC 0: key = 1 (== low)
            STABLESWITCH, // PC 1
            0x00,
            15, // default_offset = 15 -> PC 16
            0x00,
            0x01, // low = 1
            0x00,
            0x03, // high = 3
            0x00,
            13, // offset for key=1: -> PC 1+13 = 14
            0x00,
            13, // offset for key=2
            0x00,
            13, // offset for key=3
            SCONST_3,
            SRETURN, // PC 14, 15 -- case target
            SCONST_0,
            SRETURN, // PC 16, 17 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    /// JCVM 3.1 Ch7 stableswitch: key at high boundary (key == high).
    #[test]
    fn stableswitch_high_boundary() {
        let bc = [
            SCONST_3,     // PC 0: key = 3 (== high)
            STABLESWITCH, // PC 1
            0x00,
            15, // default_offset -> PC 16
            0x00,
            0x01, // low = 1
            0x00,
            0x03, // high = 3
            0x00,
            13, // offset for key=1
            0x00,
            13, // offset for key=2
            0x00,
            13, // offset for key=3: -> PC 14
            SCONST_5,
            SRETURN, // PC 14, 15 -- case target
            SCONST_0,
            SRETURN, // PC 16, 17 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    /// JCVM 3.1 Ch7 slookupswitch: no pairs, always goes to default.
    #[test]
    fn slookupswitch_empty_default() {
        let bc = [
            SCONST_5,      // PC 0
            SLOOKUPSWITCH, // PC 1
            0x00,
            5, // default_offset = 5 -> PC 1+5 = 6
            0x00,
            0x00, // npairs = 0
            SCONST_M1,
            SRETURN, // PC 6, 7 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    /// JCVM 3.1 Ch7 stableswitch: key below low goes to default.
    #[test]
    fn stableswitch_below_low_default() {
        let bc = [
            SCONST_0,     // PC 0: key = 0 (< low=1)
            STABLESWITCH, // PC 1
            0x00,
            15, // default_offset -> PC 16
            0x00,
            0x01, // low = 1
            0x00,
            0x03, // high = 3
            0x00,
            13, // offset for key=1
            0x00,
            13, // offset for key=2
            0x00,
            13, // offset for key=3
            SCONST_3,
            SRETURN, // PC 14, 15
            SCONST_5,
            SRETURN, // PC 16, 17 -- default
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    // =======================================================================
    // PRIORITY 11: Field access variants
    // =======================================================================

    /// JCVM 3.1 Ch7 `getfield_s`/`putfield_s`: store at non-zero offset.
    #[test]
    fn putfield_getfield_short_offset2() {
        let bc = [
            NEW, 8, 0, // alloc with 8 field bytes
            DUP, SSPUSH, 0xAB, 0xCD, // push 0xABCD (as signed i16 = -21555)
            PUTFIELD_S, 2, 0, // store short at field offset 2
            GETFIELD_S, 2, 0, // load short at field offset 2
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        let expected = 0xABCDu16.cast_signed();
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
    }

    /// JCVM 3.1 Ch7 `getfield_i`/`putfield_i`: store negative int.
    #[test]
    fn putfield_getfield_int_negative() {
        let bc = [
            NEW, 8, 0, // alloc with 8 field bytes
            DUP, IIPUSH, 0xFF, 0xFF, 0xFF, 0xFE, // push -2
            PUTFIELD_I, 0, 0, GETFIELD_I, 0, 0, IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(-2));
    }

    /// JCVM 3.1 Ch7 `getfield_a`/`putfield_a`: store and retrieve null reference.
    #[test]
    fn putfield_getfield_ref_null() {
        let bc = [
            NEW,
            4,
            0,
            DUP,
            ACONST_NULL,
            PUTFIELD_A,
            0,
            0,
            GETFIELD_A,
            0,
            0,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(0));
    }

    /// JCVM 3.1 Ch7 `putfield_s`: `NullPointerException` on null objectref.
    #[test]
    fn putfield_s_null_ref() {
        let bc = [ACONST_NULL, SCONST_1, PUTFIELD_S, 0, 0];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::NullPointerException);
    }

    // =======================================================================
    // PRIORITY 12: Static field variants
    // =======================================================================

    /// JCVM 3.1 Ch7 `getstatic_s`/`putstatic_s`: negative value roundtrip.
    #[test]
    fn putstatic_getstatic_short_negative() {
        let val = (-12345i16).cast_unsigned().to_be_bytes();
        let bc = [
            SSPUSH,
            val[0],
            val[1],
            PUTSTATIC_S,
            0x00,
            0x10,
            GETSTATIC_S,
            0x00,
            0x10,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-12345));
    }

    /// JCVM 3.1 Ch7 `getstatic_i`/`putstatic_i`: negative int roundtrip.
    #[test]
    fn putstatic_getstatic_int_negative() {
        let bc = [
            IIPUSH,
            0xFF,
            0xFF,
            0xFF,
            0xFE, // -2
            PUTSTATIC_I,
            0x00,
            0x20,
            GETSTATIC_I,
            0x00,
            0x20,
            IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(-2));
    }

    /// JCVM 3.1 Ch7 `getstatic_a`/`putstatic_a`: reference roundtrip.
    #[test]
    fn putstatic_getstatic_ref_roundtrip() {
        let bc = [
            BSPUSH,
            77,
            PUTSTATIC_A,
            0x00,
            0x30,
            GETSTATIC_A,
            0x00,
            0x30,
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(77));
    }

    /// JCVM 3.1 Ch7 `getstatic_i`: default zero for unwritten int field.
    #[test]
    fn getstatic_i_default_zero() {
        let bc = [GETSTATIC_I, 0x00, 0x40, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(0));
    }

    // =======================================================================
    // PRIORITY 13: dup2/pop2 detailed tests
    // =======================================================================

    /// JCVM 3.1 Ch7 dup2: duplicates two words, verify both copies.
    #[test]
    fn dup2_full_verification() {
        // Stack: [3, 5], dup2 -> [3, 5, 3, 5].
        // pop top 5, pop 3, pop 5, return remaining 3.
        let bc = [
            SCONST_3, SCONST_5, DUP2, POP,     // remove top 5 -> [3, 5, 3]
            POP,     // remove 3 -> [3, 5]
            POP,     // remove 5 -> [3]
            SRETURN, // return 3
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    /// JCVM 3.1 Ch7 pop2: leaves remaining stack intact.
    #[test]
    fn pop2_preserves_lower_stack() {
        // Stack: [1, 2, 3, 4], pop2 -> [1, 2].
        let bc = [
            SCONST_1, SCONST_2, SCONST_3, SCONST_4, POP2, // remove 4 and 3
            SADD, // 1 + 2 = 3
            SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(3));
    }

    /// JCVM 3.1 Ch7 pop2: removes exactly 2 words (not more).
    #[test]
    fn pop2_exactly_two_words() {
        // Stack: [5, 6, 7], pop2 removes 7 and 6, leaving 5.
        let bc = [SCONST_5, BSPUSH, 6, BSPUSH, 7, POP2, SRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(5));
    }

    /// JCVM 3.1 Ch7 dup2: with int value (2 words = 1 int).
    #[test]
    fn dup2_with_int() {
        // Push int 42, dup2 (duplicates 2 stack words = the full int).
        // Stack: [42_hi, 42_lo, 42_hi, 42_lo]. Pop top int, return remaining int.
        let bc = [
            IIPUSH, 0x00, 0x00, 0x00, 42, DUP2,
            // Pop the duplicate int by converting to short and discarding
            I2S, POP, I2S, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(42));
    }

    // =======================================================================
    // PRIORITY 14: areturn/ireturn variants
    // =======================================================================

    /// JCVM 3.1 Ch7 areturn: returns correct `ExecResult::ReturnRef` variant.
    #[test]
    fn areturn_nonzero_ref() {
        let bc = [SSPUSH, 0x12, 0x34, ARETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnRef(0x1234));
    }

    /// JCVM 3.1 Ch7 ireturn: returns correct `ExecResult::ReturnInt` with negative.
    #[test]
    fn ireturn_negative() {
        let bc = [ICONST_M1, IRETURN];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(-1));
    }

    /// JCVM 3.1 Ch7 ireturn: returns large positive value.
    #[test]
    fn ireturn_large_positive() {
        let bc = [
            IIPUSH, 0x7F, 0xFF, 0xFF, 0xFF, // i32::MAX
            IRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(i32::MAX));
    }

    /// JCVM 3.1 Ch7 areturn: after invokestatic returns ref to caller.
    #[test]
    fn areturn_through_invokestatic() {
        // Method 0: invokestatic(0, 1), areturn
        // Method 1: push 0x42, areturn
        let method0 = [INVOKESTATIC, 0, 1, ARETURN];
        let method1 = [BSPUSH, 0x42, ARETURN];
        let mut vm = vm_with_methods(&[&method0, &method1]);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnRef(0x42));
    }

    // =======================================================================
    // PRIORITY 15: ICMP edge cases
    // =======================================================================

    /// JCVM 3.1 Ch7 icmp: comparison with large negative values.
    #[test]
    fn icmp_min_vs_max() {
        let bc = [
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            IIPUSH, 0x7F, 0xFF, 0xFF, 0xFF, // i32::MAX
            ICMP, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(-1));
    }

    /// JCVM 3.1 Ch7 icmp: max vs min returns 1.
    #[test]
    fn icmp_max_vs_min() {
        let bc = [
            IIPUSH, 0x7F, 0xFF, 0xFF, 0xFF, // i32::MAX
            IIPUSH, 0x80, 0x00, 0x00, 0x00, // i32::MIN
            ICMP, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(1));
    }

    // =======================================================================
    // PRIORITY 16: Byte array store/load roundtrip
    // =======================================================================

    /// JCVM 3.1 Ch7 bastore/baload: store and retrieve multiple values.
    #[test]
    fn bastore_baload_multi() {
        let bc = [
            SCONST_3, NEWARRAY, 10, // alloc byte[3]
            DUP, DUP, DUP, // 3 extra refs on stack
            SCONST_0, BSPUSH, 10, BASTORE, // [0] = 10
            SCONST_1, BSPUSH, 20, BASTORE, // [1] = 20
            SCONST_2, BSPUSH, 30, BASTORE, // [2] = 30
            // Now load [1] and return it
            SCONST_1, BALOAD, SRETURN,
        ];
        let mut vm = vm_with_method(&bc);
        assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(20));
    }

    // =======================================================================
    // PRIORITY 17: proptest PBT for short arithmetic
    // =======================================================================

    mod pbt {
        extern crate alloc;
        use super::*;
        use alloc::vec;
        use alloc::vec::Vec;
        use proptest::prelude::*;

        /// Helper: build bytecode that pushes two shorts, applies an opcode, returns.
        fn short_binop_bc(a: i16, b: i16, opcode: u8) -> Vec<u8> {
            let a_bytes = a.cast_unsigned().to_be_bytes();
            let b_bytes = b.cast_unsigned().to_be_bytes();
            vec![
                SSPUSH, a_bytes[0], a_bytes[1], SSPUSH, b_bytes[0], b_bytes[1], opcode, SRETURN,
            ]
        }

        /// Helper: build bytecode that pushes two ints, applies an opcode, returns.
        fn int_binop_bc(a: i32, b: i32, opcode: u8) -> Vec<u8> {
            let a_bytes = a.to_be_bytes();
            let b_bytes = b.to_be_bytes();
            vec![
                IIPUSH, a_bytes[0], a_bytes[1], a_bytes[2], a_bytes[3], IIPUSH, b_bytes[0],
                b_bytes[1], b_bytes[2], b_bytes[3], opcode, IRETURN,
            ]
        }

        proptest! {
            /// JCVM 3.1 Ch7 sadd: matches `i16::wrapping_add` for all inputs.
            #[test]
            fn sadd_matches_wrapping_add(a in any::<i16>(), b in any::<i16>()) {
                let bc = short_binop_bc(a, b, SADD);
                let mut vm = vm_with_method(&bc);
                let expected = a.wrapping_add(b);
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 ssub: matches `i16::wrapping_sub` for all inputs.
            #[test]
            fn ssub_matches_wrapping_sub(a in any::<i16>(), b in any::<i16>()) {
                let bc = short_binop_bc(a, b, SSUB);
                let mut vm = vm_with_method(&bc);
                let expected = a.wrapping_sub(b);
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 smul: matches `i16::wrapping_mul` for all inputs.
            #[test]
            fn smul_matches_wrapping_mul(a in any::<i16>(), b in any::<i16>()) {
                let bc = short_binop_bc(a, b, SMUL);
                let mut vm = vm_with_method(&bc);
                let expected = a.wrapping_mul(b);
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 sand: matches Rust bitwise AND.
            #[test]
            fn sand_matches_bitwise_and(a in any::<u16>(), b in any::<u16>()) {
                let a_i = a.cast_signed();
                let b_i = b.cast_signed();
                let bc = short_binop_bc(a_i, b_i, SAND);
                let mut vm = vm_with_method(&bc);
                let expected = (a & b).cast_signed();
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 sor: matches Rust bitwise OR.
            #[test]
            fn sor_matches_bitwise_or(a in any::<u16>(), b in any::<u16>()) {
                let a_i = a.cast_signed();
                let b_i = b.cast_signed();
                let bc = short_binop_bc(a_i, b_i, SOR);
                let mut vm = vm_with_method(&bc);
                let expected = (a | b).cast_signed();
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 sxor: matches Rust bitwise XOR.
            #[test]
            fn sxor_matches_bitwise_xor(a in any::<u16>(), b in any::<u16>()) {
                let a_i = a.cast_signed();
                let b_i = b.cast_signed();
                let bc = short_binop_bc(a_i, b_i, SXOR);
                let mut vm = vm_with_method(&bc);
                let expected = (a ^ b).cast_signed();
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 sshl: matches `(i32::from(a) << (b & 0x1F))` truncated to i16.
            #[test]
            fn sshl_matches_reference(a in any::<i16>(), b in any::<i16>()) {
                let bc = short_binop_bc(a, b, SSHL);
                let mut vm = vm_with_method(&bc);
                let shift = b.cast_unsigned() & 0x1F;
                #[allow(clippy::cast_possible_truncation)]
                let expected = ((i32::from(a) << shift) & 0xFFFF) as i16;
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 sshr: matches `(i32::from(a) >> (b & 0x1F))` truncated to i16.
            #[test]
            fn sshr_matches_reference(a in any::<i16>(), b in any::<i16>()) {
                let bc = short_binop_bc(a, b, SSHR);
                let mut vm = vm_with_method(&bc);
                let shift = b.cast_unsigned() & 0x1F;
                #[allow(clippy::cast_possible_truncation)]
                let expected = (i32::from(a) >> shift) as i16;
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 iadd: matches `i32::wrapping_add` for all inputs.
            #[test]
            fn iadd_matches_wrapping_add(a in any::<i32>(), b in any::<i32>()) {
                let bc = int_binop_bc(a, b, IADD);
                let mut vm = vm_with_method(&bc);
                let expected = a.wrapping_add(b);
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(expected));
            }

            /// JCVM 3.1 Ch7 isub: matches `i32::wrapping_sub` for all inputs.
            #[test]
            fn isub_matches_wrapping_sub(a in any::<i32>(), b in any::<i32>()) {
                let bc = int_binop_bc(a, b, ISUB);
                let mut vm = vm_with_method(&bc);
                let expected = a.wrapping_sub(b);
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(expected));
            }

            /// JCVM 3.1 Ch7 imul: matches `i32::wrapping_mul` for all inputs.
            #[test]
            fn imul_matches_wrapping_mul(a in any::<i32>(), b in any::<i32>()) {
                let bc = int_binop_bc(a, b, IMUL);
                let mut vm = vm_with_method(&bc);
                let expected = a.wrapping_mul(b);
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(expected));
            }

            /// JCVM 3.1 Ch7 idiv: non-zero divisor matches Rust truncating division.
            #[test]
            fn idiv_matches_truncating_div(
                a in any::<i32>(),
                b in any::<i32>().prop_filter("non-zero", |b| *b != 0)
            ) {
                let bc = int_binop_bc(a, b, IDIV);
                let mut vm = vm_with_method(&bc);
                let expected = if a == i32::MIN && b == -1 {
                    i32::MIN
                } else {
                    a / b
                };
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnInt(expected));
            }

            /// JCVM 3.1 Ch7 s2b: truncates low 8 bits then sign-extends to i16.
            #[test]
            fn s2b_matches_reference(a in any::<i16>()) {
                let a_bytes = a.cast_unsigned().to_be_bytes();
                let bc = vec![SSPUSH, a_bytes[0], a_bytes[1], S2B, SRETURN];
                let mut vm = vm_with_method(&bc);
                #[allow(clippy::cast_possible_truncation)]
                let expected = i16::from(a as i8);
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 i2s: truncates low 16 bits.
            #[test]
            fn i2s_matches_reference(a in any::<i32>()) {
                let a_bytes = a.to_be_bytes();
                let bc = vec![
                    IIPUSH, a_bytes[0], a_bytes[1], a_bytes[2], a_bytes[3],
                    I2S, SRETURN,
                ];
                let mut vm = vm_with_method(&bc);
                #[allow(clippy::cast_possible_truncation)]
                let expected = a as i16;
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }

            /// JCVM 3.1 Ch7 sinc: matches wrapping_add with i8 constant.
            #[test]
            fn sinc_matches_wrapping_add(val in any::<i16>(), inc in any::<i8>()) {
                let val_bytes = val.cast_unsigned().to_be_bytes();
                let bc = vec![
                    SSPUSH, val_bytes[0], val_bytes[1],
                    SSTORE_0,
                    SINC, 0, inc.cast_unsigned(),
                    SLOAD_0,
                    SRETURN,
                ];
                let mut vm = vm_with_method(&bc);
                let expected = val.wrapping_add(i16::from(inc));
                prop_assert_eq!(vm.execute(0, 0), ExecResult::ReturnShort(expected));
            }
        }
    }
}
