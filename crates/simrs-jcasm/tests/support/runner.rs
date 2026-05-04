//! `TestApplet` runner for high-level JCVM security tests.
//!
//! Combines CAP building, JCVM loading, pre-allocation, and execution
//! into a single fluent API.
//!
//! # Pre-allocation
//!
//! The `alloc_*` methods schedule heap allocations that happen before
//! execution. Each allocation produces an `ObjRef` that is stored into
//! a local variable via a bytecode preamble. The preamble is prepended
//! to method 0's bytecode as `sspush(ref.0); sstore(local)` pairs.
//!
//! # Example
//!
//! ```rust,ignore
//! use support::{TestApplet, expect};
//!
//! let result = TestApplet::new("A0_00_00_00_62")
//!     .method(&[0x7A])  // return_void
//!     .run();
//!
//! expect::returns_void(result);
//! ```

use super::builder::{CapBuilder, MethodBuilder};
use simrs_jcvm::JcVM;
use simrs_jcvm::cap::{Package, ParseError};
use simrs_jcvm::opcodes::ExecResult;

/// A pre-execution heap allocation request.
#[derive(Clone, Debug)]
enum Allocation {
    ByteArray { local: u8, len: u16 },
    ShortArray { local: u8, len: u16 },
    Instance { local: u8, fields: u8 },
}

/// High-level test applet builder and runner.
#[derive(Clone, Debug)]
pub struct TestApplet {
    aid: Vec<u8>,
    cap_builder: CapBuilder,
    allocations: Vec<Allocation>,
    context: u8,
}

impl TestApplet {
    /// Create a new test applet with an AID in hex-with-underscores format.
    ///
    /// Example: `TestApplet::new("A0_00_00_00_62")`
    pub fn new(aid_hex: &str) -> Self {
        let aid =
            simrs_jccompile::parse_aid_hex(aid_hex).unwrap_or_else(|e| panic!("invalid AID: {e}"));
        Self {
            cap_builder: CapBuilder::new(&aid),
            aid,
            allocations: Vec::new(),
            context: 0,
        }
    }

    /// Add a method from raw bytecode (simple, no exceptions).
    pub fn method(&mut self, bytecode: &[u8]) -> &mut Self {
        self.cap_builder.add_method(MethodBuilder::new(bytecode));
        self
    }

    /// Add a method with full control (exceptions, offsets, etc.).
    pub fn method_with_exceptions(&mut self, m: MethodBuilder) -> &mut Self {
        self.cap_builder.add_method(m);
        self
    }

    /// Schedule a byte array allocation, storing the ref in `local`.
    pub fn alloc_byte_array(&mut self, local: u8, len: u16) -> &mut Self {
        self.allocations.push(Allocation::ByteArray { local, len });
        self
    }

    /// Schedule a short array allocation, storing the ref in `local`.
    pub fn alloc_short_array(&mut self, local: u8, len: u16) -> &mut Self {
        self.allocations.push(Allocation::ShortArray { local, len });
        self
    }

    /// Schedule an instance allocation, storing the ref in `local`.
    pub fn alloc_instance(&mut self, local: u8, fields: u8) -> &mut Self {
        self.allocations
            .push(Allocation::Instance { local, fields });
        self
    }

    /// Set the owner context for pre-allocated objects.
    pub const fn set_context(&mut self, ctx: u8) -> &mut Self {
        self.context = ctx;
        self
    }

    /// Build the CAP blob, parse it, load into a fresh VM, execute method 0.
    ///
    /// Pre-allocations are performed on the heap before execution, with
    /// a bytecode preamble injected into method 0 to store object references
    /// into local variables.
    pub fn run(&self) -> ExecResult {
        let mut builder = self.cap_builder.clone();

        // If we have allocations, we need to inject preamble bytecode into method 0.
        // Build a fresh VM first so we can allocate on its heap.
        let mut vm = JcVM::<4096, 4>::new();

        if !self.allocations.is_empty() {
            // Perform heap allocations and collect (local, ObjRef) pairs.
            let mut ref_assignments: Vec<(u8, u16)> = Vec::new();

            for alloc in &self.allocations {
                match alloc {
                    Allocation::ByteArray { local, len } => {
                        let obj_ref = vm
                            .heap_mut()
                            .alloc_byte_array(self.context, *len)
                            .expect("heap allocation failed");
                        ref_assignments.push((*local, obj_ref.0));
                    }
                    Allocation::ShortArray { local, len } => {
                        let obj_ref = vm
                            .heap_mut()
                            .alloc_short_array(self.context, *len)
                            .expect("heap allocation failed");
                        ref_assignments.push((*local, obj_ref.0));
                    }
                    Allocation::Instance { local, fields } => {
                        let obj_ref = vm
                            .heap_mut()
                            .alloc_instance(self.context, u16::from(*fields))
                            .expect("heap allocation failed");
                        ref_assignments.push((*local, obj_ref.0));
                    }
                }
            }

            // Build a preamble: for each (local, ref_val),
            // emit sspush(ref_val) + sstore(local).
            // sspush is 0x11 + 2-byte BE immediate.
            // sstore is 0x28 + 1-byte local index.
            let mut preamble = Vec::new();
            for (local, ref_val) in &ref_assignments {
                // sspush ref_val
                preamble.push(0x11); // SSPUSH
                #[allow(clippy::cast_possible_truncation)]
                {
                    preamble.push((*ref_val >> 8) as u8);
                    preamble.push(*ref_val as u8);
                }
                // sstore local
                preamble.push(0x29); // SSTORE
                preamble.push(*local);
            }

            // Rebuild the CapBuilder with the preamble prepended to method 0.
            // We need to clone and modify method 0's bytecode.
            let mut new_builder = CapBuilder::new(&self.aid);
            let methods = &builder.methods;

            for (i, m) in methods.iter().enumerate() {
                if i == 0 {
                    // Prepend preamble to method 0.
                    let mut combined = preamble.clone();
                    combined.extend_from_slice(&m.bytecode);
                    let mut new_m = MethodBuilder::new(&combined);
                    new_m.exceptions.clone_from(&m.exceptions);
                    new_m.descriptor_offset = m.descriptor_offset;
                    new_m.class_offset = m.class_offset;
                    new_m.max_stack = m.max_stack;
                    new_m.max_locals = m.max_locals;
                    new_m.nargs = m.nargs;
                    new_m.flags = m.flags;
                    new_builder.add_method(new_m);
                } else {
                    new_builder.add_method(m.clone());
                }
            }

            builder = new_builder;
        }

        // Build the CAP blob.
        let mut buf = [0u8; 1024];
        let len = builder.build(&mut buf);

        // Parse it.
        let pkg = simrs_jcvm::cap::parse_cap(&buf[..len]).expect("CAP parse failed in run()");

        // Load into the VM.
        let idx = vm.load_package(pkg).expect("load_package failed");

        // Execute method 0.
        vm.execute(idx, 0)
    }

    /// Build the CAP blob and attempt to parse it.
    ///
    /// Used for testing malformed CAPs that should fail at parse time.
    pub fn try_parse(&self) -> Result<Package, ParseError> {
        let mut buf = [0u8; 1024];
        let len = self.cap_builder.build(&mut buf);
        simrs_jcvm::cap::parse_cap(&buf[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_return_void() {
        let result = TestApplet::new("A0_00_00_00_62")
            .method(&[0x7A]) // return_void
            .run();
        assert_eq!(result, ExecResult::ReturnVoid);
    }

    #[test]
    fn simple_return_short() {
        // sconst_3 + sreturn
        let result = TestApplet::new("A0_00_00_00_63")
            .method(&[0x06, 0x78])
            .run();
        assert_eq!(result, ExecResult::ReturnShort(3));
    }

    #[test]
    fn try_parse_valid() {
        let result = TestApplet::new("A0_00_00_00_64")
            .method(&[0x7A])
            .try_parse();
        assert!(result.is_ok());
    }

    #[test]
    fn with_byte_array_allocation() {
        // Allocate a byte array of length 8 into local 0,
        // then load it and get its length.
        // sload_0, arraylength, sreturn
        let result = TestApplet::new("A0_00_00_00_65")
            .alloc_byte_array(0, 8)
            .method(&[0x1C, 0x92, 0x78]) // sload_0, arraylength, sreturn
            .run();
        assert_eq!(result, ExecResult::ReturnShort(8));
    }

    #[test]
    fn with_short_array_allocation() {
        // Allocate a short array of length 5 into local 1,
        // then load it and get its length.
        // sload_1, arraylength, sreturn
        let result = TestApplet::new("A0_00_00_00_66")
            .alloc_short_array(1, 5)
            .method(&[0x1D, 0x92, 0x78]) // sload_1, arraylength, sreturn
            .run();
        assert_eq!(result, ExecResult::ReturnShort(5));
    }

    #[test]
    fn parse_aid_hex_basic() {
        use simrs_jccompile::parse_aid_hex;
        assert_eq!(parse_aid_hex("A0_00_00").unwrap(), vec![0xA0, 0x00, 0x00]);
        assert_eq!(parse_aid_hex("FF").unwrap(), vec![0xFF]);
        assert_eq!(
            parse_aid_hex("A0_00_00_00_62_02_01").unwrap(),
            vec![0xA0, 0x00, 0x00, 0x00, 0x62, 0x02, 0x01]
        );
    }
}
