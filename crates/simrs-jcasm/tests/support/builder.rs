//! CAP builder for constructing CAP blobs with full control over
//! exception tables and offset fields.
//!
//! This extends the basic `build_cap_blob()` in simrs-jcvm by supporting:
//! - Exception table entries per method
//! - Configurable descriptor/class offsets (for offset-mismatch tests)
//! - Configurable method flags, `max_stack`, `max_locals`, nargs
//! - Malformed blobs (for loader defense tests)
//!
//! The binary format matches what `simrs_jcvm::cap::parse_cap()` expects:
//!
//! ```text
//! DECAFFED(4) | aid_len(1) | aid(N) | method_count(1)
//! Per method:
//!   flags(1) | max_stack(1) | nargs(1) | max_locals(1)
//!   | bytecode_len(2 BE) | bytecode(N)
//!   | exc_count(1) | { start_pc(2) end_pc(2) handler_pc(2) catch_type(2) } * exc_count
//!   | descriptor_offset(2 BE) | class_offset(2 BE)
//! ```

use simrs_jcvm::cap::{CAP_MAGIC, METHOD_FLAG_STATIC};

/// A single exception table entry for the builder.
#[derive(Clone, Copy, Debug)]
pub struct ExceptionEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: u16,
}

/// Builder for a single method within a CAP blob.
#[derive(Clone, Debug)]
pub struct MethodBuilder {
    pub bytecode: Vec<u8>,
    pub exceptions: Vec<ExceptionEntry>,
    pub descriptor_offset: u16,
    pub class_offset: u16,
    pub max_stack: u8,
    pub max_locals: u8,
    pub nargs: u8,
    pub flags: u8,
}

impl MethodBuilder {
    /// Create a new method builder from raw bytecode.
    pub fn new(bytecode: &[u8]) -> Self {
        Self {
            bytecode: bytecode.to_vec(),
            exceptions: Vec::new(),
            descriptor_offset: 0,
            class_offset: 0,
            max_stack: 8,
            max_locals: 4,
            nargs: 0,
            flags: METHOD_FLAG_STATIC,
        }
    }

    /// Add an exception table entry.
    pub fn exception(mut self, start: u16, end: u16, handler: u16, catch_type: u16) -> Self {
        self.exceptions.push(ExceptionEntry {
            start_pc: start,
            end_pc: end,
            handler_pc: handler,
            catch_type,
        });
        self
    }

    /// Set descriptor and class offsets (for cross-validation / mismatch tests).
    pub const fn offsets(mut self, descriptor: u16, class: u16) -> Self {
        self.descriptor_offset = descriptor;
        self.class_offset = class;
        self
    }

    /// Set the maximum operand stack depth.
    pub const fn max_stack(mut self, n: u8) -> Self {
        self.max_stack = n;
        self
    }

    /// Set the maximum local variable count.
    pub const fn max_locals(mut self, n: u8) -> Self {
        self.max_locals = n;
        self
    }

    /// Set the number of arguments.
    pub const fn nargs(mut self, n: u8) -> Self {
        self.nargs = n;
        self
    }

    /// Set method flags.
    pub const fn flags(mut self, f: u8) -> Self {
        self.flags = f;
        self
    }

    /// Identity, for chaining readability.
    pub const fn build(self) -> Self {
        self
    }
}

/// Builder for a complete CAP blob.
#[derive(Clone, Debug)]
pub struct CapBuilder {
    pub aid: Vec<u8>,
    pub methods: Vec<MethodBuilder>,
}

impl CapBuilder {
    /// Create a new CAP builder with the given AID.
    pub fn new(aid: &[u8]) -> Self {
        Self {
            aid: aid.to_vec(),
            methods: Vec::new(),
        }
    }

    /// Create a `MethodBuilder` from raw bytecode (convenience constructor).
    pub fn method(bytecode: &[u8]) -> MethodBuilder {
        MethodBuilder::new(bytecode)
    }

    /// Add a method to the CAP.
    pub fn add_method(&mut self, m: MethodBuilder) -> &mut Self {
        self.methods.push(m);
        self
    }

    /// Build the CAP blob into the provided buffer.
    ///
    /// Returns the number of bytes written. Panics if the buffer is too small.
    #[allow(clippy::cast_possible_truncation)]
    pub fn build(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        // Magic: 0xDECAFFED (4 bytes, big-endian).
        buf[pos..pos + 4].copy_from_slice(&CAP_MAGIC.to_be_bytes());
        pos += 4;

        // AID length (1 byte).
        let aid_len = self.aid.len();
        buf[pos] = aid_len as u8;
        pos += 1;

        // AID bytes.
        buf[pos..pos + aid_len].copy_from_slice(&self.aid);
        pos += aid_len;

        // Method count (1 byte).
        buf[pos] = self.methods.len() as u8;
        pos += 1;

        // Each method.
        for m in &self.methods {
            // flags(1) | max_stack(1) | nargs(1) | max_locals(1)
            buf[pos] = m.flags;
            buf[pos + 1] = m.max_stack;
            buf[pos + 2] = m.nargs;
            buf[pos + 3] = m.max_locals;
            pos += 4;

            // bytecode_len(2 BE) | bytecode(N)
            let bc_len = m.bytecode.len() as u16;
            buf[pos..pos + 2].copy_from_slice(&bc_len.to_be_bytes());
            pos += 2;
            buf[pos..pos + m.bytecode.len()].copy_from_slice(&m.bytecode);
            pos += m.bytecode.len();

            // exc_count(1) | { start_pc(2) end_pc(2) handler_pc(2) catch_type(2) } * exc_count
            buf[pos] = m.exceptions.len() as u8;
            pos += 1;
            for exc in &m.exceptions {
                buf[pos..pos + 2].copy_from_slice(&exc.start_pc.to_be_bytes());
                buf[pos + 2..pos + 4].copy_from_slice(&exc.end_pc.to_be_bytes());
                buf[pos + 4..pos + 6].copy_from_slice(&exc.handler_pc.to_be_bytes());
                buf[pos + 6..pos + 8].copy_from_slice(&exc.catch_type.to_be_bytes());
                pos += 8;
            }

            // descriptor_offset(2 BE) | class_offset(2 BE)
            buf[pos..pos + 2].copy_from_slice(&m.descriptor_offset.to_be_bytes());
            buf[pos + 2..pos + 4].copy_from_slice(&m.class_offset.to_be_bytes());
            pos += 4;
        }

        pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_jcvm::cap::{parse_cap, ParseError};

    #[test]
    fn builder_roundtrip_simple_method() {
        // Build a CAP with one simple method, parse it back, verify fields.
        let bytecode = [0x04, 0x78]; // sconst_1, sreturn
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62];

        let mut builder = CapBuilder::new(&aid);
        builder.add_method(MethodBuilder::new(&bytecode));

        let mut buf = [0u8; 512];
        let len = builder.build(&mut buf);
        let pkg = parse_cap(&buf[..len]).expect("should parse");

        assert!(pkg.aid_matches(&aid));
        assert_eq!(pkg.method_count, 1);
        let m = pkg.method(0).unwrap();
        assert_eq!(m.bytecode_len, 2);
        assert_eq!(&m.bytecode[..2], &[0x04, 0x78]);
        assert!(m.is_static());
        assert_eq!(m.max_stack, 8);
        assert_eq!(m.max_locals, 4);
    }

    #[test]
    fn builder_with_valid_exception_table() {
        // 10 bytes of bytecode, exception covering [0..5) with handler at 7.
        let bytecode = [0x03; 10]; // 10 NOPs (sconst_0 is a harmless filler)
        let aid = [0xA0, 0x01];

        let m = MethodBuilder::new(&bytecode)
            .exception(0, 5, 7, 0)
            .build();

        let mut builder = CapBuilder::new(&aid);
        builder.add_method(m);

        let mut buf = [0u8; 512];
        let len = builder.build(&mut buf);
        let pkg = parse_cap(&buf[..len]).expect("should parse");

        let method = pkg.method(0).unwrap();
        let exc = method.exception_table[0].unwrap();
        assert_eq!(exc.start_pc, 0);
        assert_eq!(exc.end_pc, 5);
        assert_eq!(exc.handler_pc, 7);
        assert_eq!(exc.catch_type, 0);
    }

    #[test]
    fn builder_offset_mismatch_rejected() {
        // Descriptor and class offsets differ -- parse_cap should reject.
        let bytecode = [0x7A]; // return_void
        let aid = [0xA0, 0x02];

        let m = MethodBuilder::new(&bytecode)
            .offsets(0x0010, 0x0020) // mismatch
            .build();

        let mut builder = CapBuilder::new(&aid);
        builder.add_method(m);

        let mut buf = [0u8; 512];
        let len = builder.build(&mut buf);
        let result = parse_cap(&buf[..len]);

        match result {
            Err(e) => assert_eq!(e, ParseError::OffsetMismatch),
            Ok(_) => panic!("expected OffsetMismatch, but parsing succeeded"),
        }
    }

    #[test]
    fn builder_exception_oob_rejected() {
        // Exception handler_pc beyond bytecode length.
        let bytecode = [0x7A]; // 1 byte of bytecode
        let aid = [0xA0, 0x03];

        // handler_pc=5 but bytecode is only 1 byte long
        let m = MethodBuilder::new(&bytecode)
            .exception(0, 1, 5, 0)
            .build();

        let mut builder = CapBuilder::new(&aid);
        builder.add_method(m);

        let mut buf = [0u8; 512];
        let len = builder.build(&mut buf);
        let result = parse_cap(&buf[..len]);

        match result {
            Err(e) => assert_eq!(e, ParseError::InvalidExceptionHandler),
            Ok(_) => panic!("expected InvalidExceptionHandler, but parsing succeeded"),
        }
    }

    #[test]
    fn builder_multiple_methods() {
        let aid = [0xA0, 0x04];
        let bc1 = [0x7A]; // return_void
        let bc2 = [0x04, 0x78]; // sconst_1, sreturn

        let mut builder = CapBuilder::new(&aid);
        builder
            .add_method(MethodBuilder::new(&bc1))
            .add_method(MethodBuilder::new(&bc2));

        let mut buf = [0u8; 512];
        let len = builder.build(&mut buf);
        let pkg = parse_cap(&buf[..len]).expect("should parse");

        assert_eq!(pkg.method_count, 2);
        assert_eq!(pkg.method(0).unwrap().bytecode_len, 1);
        assert_eq!(pkg.method(1).unwrap().bytecode_len, 2);
    }

    #[test]
    fn builder_matching_offsets_accepted() {
        // Matching non-zero offsets should be accepted.
        let bytecode = [0x7A];
        let aid = [0xA0, 0x05];

        let m = MethodBuilder::new(&bytecode)
            .offsets(0x0042, 0x0042) // matching
            .build();

        let mut builder = CapBuilder::new(&aid);
        builder.add_method(m);

        let mut buf = [0u8; 512];
        let len = builder.build(&mut buf);
        let pkg = parse_cap(&buf[..len]).expect("should parse with matching offsets");

        let method = pkg.method(0).unwrap();
        assert_eq!(method.descriptor_offset, 0x0042);
        assert_eq!(method.class_offset, 0x0042);
    }
}
