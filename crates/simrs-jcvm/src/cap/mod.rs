//! CAP file parser for JCVM bytecode packages.
//!
//! Parses the binary CAP format per JCVM 2.1.1 Chapter 6 (p65-116). Real
//! CAP files are ZIP archives containing 11 component files; for embedded
//! `no_std` use we parse a simplified binary blob format that concatenates
//! the essential components.
//!
//! # Full CAP Component Model (JCVM 2.1.1 Table 6-1/6-2)
//!
//! 1. Header -- magic `0xDECAFFED`, minor/major version, package AID
//! 2. Directory -- component size table, static field sizes, import count
//! 3. Applet -- AID to `install_method_offset` mapping, one per applet
//! 4. Import -- imported packages with AIDs and versions
//! 5. `ConstantPool` -- resolved refs: class, field, method
//! 6. Class -- hierarchy, interfaces, field count, public method table
//! 7. Method -- bytecode: flags, `max_stack`, nargs, `max_locals`, bytecode\[\]
//! 8. `StaticField` -- initial values for static fields
//! 9. `ReferenceLocation` -- offsets for runtime token resolution
//! 10. Export -- published tokens for inter-package linking
//! 11. Descriptor -- debug info (optional)
//!
//! # Binary Blob Format
//!
//! ```text
//! [ magic: 4 bytes (0xDECAFFED) ]
//! [ AID length: 1 byte ]
//! [ AID: up to 16 bytes ]
//! [ method count: 1 byte ]
//! [ method 0: MethodInfo ]
//! [ method 1: MethodInfo ]
//! ...
//! ```
//!
//! Each `MethodInfo` in the blob:
//! ```text
//! [ flags: 1 byte ]
//! [ max_stack: 1 byte ]
//! [ nargs: 1 byte ]
//! [ max_locals: 1 byte ]
//! [ bytecode_len: 2 bytes (u16 BE) ]
//! [ bytecode: bytecode_len bytes ]
//! ```

/// Maximum AID length per ISO 7816-4 (5-16 bytes).
pub const MAX_AID_LEN: usize = 16;

/// Maximum methods per package.
pub const MAX_METHODS: usize = 32;

/// Maximum bytecode size per method.
pub const MAX_BYTECODE: usize = 256;

/// CAP file magic number.
pub const CAP_MAGIC: u32 = 0xDECA_FFED;

/// Method flag: static method.
pub const METHOD_FLAG_STATIC: u8 = 0x08;

/// Maximum exception table entries per method.
pub const MAX_EXCEPTIONS: usize = 8;

/// Maximum Constant Pool entries the runtime tracks per package.
///
/// JCVM 3.2 § 6.8 allows up to `0xFFFF` entries; this cap covers the
/// common embedded applet range. Real Oracle CAP files typically
/// allocate a few dozen entries even for moderate-sized applets;
/// raising this is a per-deployment knob.
pub const MAX_CP_ENTRIES: usize = 64;

/// Constant Pool entry tag per JCVM 3.2 § 6.8 Table 6-7.
pub mod cp_tag {
    /// Classref -- reference to a class.
    pub const CLASSREF: u8 = 1;
    /// `InstanceFieldref` -- reference to an instance field.
    pub const INSTANCE_FIELDREF: u8 = 2;
    /// `VirtualMethodref` -- reference to a virtual method.
    pub const VIRTUAL_METHODREF: u8 = 3;
    /// `SuperMethodref` -- reference to a method invoked via `invokespecial` super.
    pub const SUPER_METHODREF: u8 = 4;
    /// `StaticFieldref` -- reference to a static field.
    pub const STATIC_FIELDREF: u8 = 5;
    /// `StaticMethodref` -- reference to a static method.
    pub const STATIC_METHODREF: u8 = 6;
}

/// A class reference -- either internal (offset within this CAP's
/// Class component) or external (a token-pair into another package's
/// Export table).
///
/// Per JCVM 3.2 § 6.8.1: byte 0 high bit selects the form. When set,
/// the lower 7 bits of byte 0 carry the package token and byte 1 is
/// the class token. When clear, bytes 0..2 are a big-endian u16 offset
/// into this package's Class component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassRef {
    /// Offset into this package's Class component.
    Internal(u16),
    /// External: token-pair into another package's Export table.
    External {
        /// Index into the Import component identifying the package.
        package_token: u8,
        /// Index into that package's Export table identifying the class.
        class_token: u8,
    },
}

/// A static field or static method reference -- either internal
/// (offset within this CAP's `StaticField` / Method component) or
/// external (a token-triple into another package).
///
/// Per JCVM 3.2 § 6.8.5 / § 6.8.6: byte 0 high bit selects the form.
/// External form encodes `(package_token, class_token, token)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticRef {
    /// Internal offset into this package's `StaticField` / Method component.
    Internal(u16),
    /// External: token-triple into another package.
    External {
        /// Index into the Import component identifying the package.
        package_token: u8,
        /// Index into that package's Export table identifying the class.
        class_token: u8,
        /// Index into the class's static-field or static-method table.
        token: u8,
    },
}

/// A Constant Pool entry as it appears on disk: a 1-byte tag followed
/// by 3 bytes whose interpretation depends on the tag (JCVM 3.2 § 6.8).
///
/// The runtime stores entries in this raw form and decodes on demand
/// via the [`Self::as_classref`] / [`Self::as_instance_fieldref`] /
/// [`Self::as_virtual_methodref`] / [`Self::as_super_methodref`] /
/// [`Self::as_static_fieldref`] / [`Self::as_static_methodref`] helpers.
/// This keeps `Package` snapshot small (4 bytes per entry) and defers
/// the spec's tag-dependent layout selection to call sites that need it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CpInfo {
    /// Entry tag per [`cp_tag`]. `0` indicates an unused / default-empty slot.
    pub tag: u8,
    /// 3-byte payload, interpretation depends on `tag`.
    pub info: [u8; 3],
}

impl CpInfo {
    /// Decode a 2-byte / token-pair `class_ref` per JCVM 3.2 § 6.8.1
    /// from the first two bytes of `info`.
    const fn decode_class_ref(info: [u8; 3]) -> ClassRef {
        // High bit of byte 0 selects external form.
        if info[0] & 0x80 != 0 {
            ClassRef::External {
                package_token: info[0] & 0x7F,
                class_token: info[1],
            }
        } else {
            ClassRef::Internal(u16::from_be_bytes([info[0], info[1]]))
        }
    }

    /// Decode a 3-byte `static_field_ref` / `static_method_ref` per
    /// JCVM 3.2 § 6.8.5 / § 6.8.6.
    const fn decode_static_ref(info: [u8; 3]) -> StaticRef {
        if info[0] & 0x80 != 0 {
            StaticRef::External {
                package_token: info[0] & 0x7F,
                class_token: info[1],
                token: info[2],
            }
        } else {
            // Internal form: byte 0 is reserved/zero; bytes 1..3 are the offset.
            StaticRef::Internal(u16::from_be_bytes([info[1], info[2]]))
        }
    }

    /// Decode this entry as a Classref. Returns `None` if `tag` is not
    /// [`cp_tag::CLASSREF`].
    #[must_use]
    pub const fn as_classref(&self) -> Option<ClassRef> {
        if self.tag == cp_tag::CLASSREF {
            Some(Self::decode_class_ref(self.info))
        } else {
            None
        }
    }

    /// Decode this entry as an `InstanceFieldref`: `(class, field_token)`.
    /// Returns `None` if `tag` is not [`cp_tag::INSTANCE_FIELDREF`].
    #[must_use]
    pub const fn as_instance_fieldref(&self) -> Option<(ClassRef, u8)> {
        if self.tag == cp_tag::INSTANCE_FIELDREF {
            Some((Self::decode_class_ref(self.info), self.info[2]))
        } else {
            None
        }
    }

    /// Decode this entry as a `VirtualMethodref`: `(class, method_token, is_private)`.
    /// The high bit of the token byte distinguishes package-private
    /// `invokespecial` targets from regular virtual invocations per
    /// JCVM 3.2 § 6.8.3.
    /// Returns `None` if `tag` is not [`cp_tag::VIRTUAL_METHODREF`].
    #[must_use]
    pub const fn as_virtual_methodref(&self) -> Option<(ClassRef, u8, bool)> {
        if self.tag == cp_tag::VIRTUAL_METHODREF {
            let class = Self::decode_class_ref(self.info);
            let token_byte = self.info[2];
            Some((class, token_byte & 0x7F, token_byte & 0x80 != 0))
        } else {
            None
        }
    }

    /// Decode this entry as a `SuperMethodref`: `(class, method_token)`.
    /// Returns `None` if `tag` is not [`cp_tag::SUPER_METHODREF`].
    #[must_use]
    pub const fn as_super_methodref(&self) -> Option<(ClassRef, u8)> {
        if self.tag == cp_tag::SUPER_METHODREF {
            Some((Self::decode_class_ref(self.info), self.info[2]))
        } else {
            None
        }
    }

    /// Decode this entry as a `StaticFieldref`. Returns `None` if `tag`
    /// is not [`cp_tag::STATIC_FIELDREF`].
    #[must_use]
    pub const fn as_static_fieldref(&self) -> Option<StaticRef> {
        if self.tag == cp_tag::STATIC_FIELDREF {
            Some(Self::decode_static_ref(self.info))
        } else {
            None
        }
    }

    /// Decode this entry as a `StaticMethodref`. Returns `None` if `tag`
    /// is not [`cp_tag::STATIC_METHODREF`].
    #[must_use]
    pub const fn as_static_methodref(&self) -> Option<StaticRef> {
        if self.tag == cp_tag::STATIC_METHODREF {
            Some(Self::decode_static_ref(self.info))
        } else {
            None
        }
    }
}

/// An entry in a method's exception handler table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExceptionEntry {
    /// Start of the try region (inclusive).
    pub start_pc: u16,
    /// End of the try region (exclusive).
    pub end_pc: u16,
    /// PC of the handler code.
    pub handler_pc: u16,
    /// Catch type (0 = catch-all).
    pub catch_type: u16,
}

/// Information about a single method in a package.
#[derive(Clone, Copy)]
pub struct MethodInfo {
    /// Method flags (bit 3 = static).
    pub flags: u8,
    /// Maximum operand stack depth (in 16-bit words).
    pub max_stack: u8,
    /// Number of arguments.
    pub nargs: u8,
    /// Maximum local variables (including arguments).
    pub max_locals: u8,
    /// Bytecode buffer.
    pub bytecode: [u8; MAX_BYTECODE],
    /// Actual bytecode length.
    pub bytecode_len: u16,
    /// Exception handler table.
    pub exception_table: [Option<ExceptionEntry>; MAX_EXCEPTIONS],
    /// Descriptor-component method offset (for cross-validation).
    pub descriptor_offset: u16,
    /// Class-component method offset (for cross-validation).
    pub class_offset: u16,
}

impl MethodInfo {
    /// Create an empty method info.
    pub const fn empty() -> Self {
        Self {
            flags: 0,
            max_stack: 0,
            nargs: 0,
            max_locals: 0,
            bytecode: [0u8; MAX_BYTECODE],
            bytecode_len: 0,
            exception_table: [None; MAX_EXCEPTIONS],
            descriptor_offset: 0,
            class_offset: 0,
        }
    }

    /// Whether this method is static.
    pub const fn is_static(&self) -> bool {
        self.flags & METHOD_FLAG_STATIC != 0
    }
}

/// A loaded CAP package.
#[derive(Clone, Copy)]
pub struct Package {
    /// Application Identifier.
    pub aid: [u8; MAX_AID_LEN],
    /// AID length.
    pub aid_len: u8,
    /// Methods in this package.
    pub methods: [Option<MethodInfo>; MAX_METHODS],
    /// Number of methods loaded.
    pub method_count: u8,
    /// Constant Pool entries (JCVM 3.2 § 6.8). Stored in raw 4-byte
    /// form; decode via `CpInfo::as_*` helpers at resolve-time.
    pub constant_pool: [CpInfo; MAX_CP_ENTRIES],
    /// Number of valid Constant Pool entries (`<= MAX_CP_ENTRIES`).
    pub cp_count: u16,
}

impl Package {
    /// Create an empty package.
    pub const fn empty() -> Self {
        Self {
            aid: [0u8; MAX_AID_LEN],
            aid_len: 0,
            methods: [None; MAX_METHODS],
            method_count: 0,
            constant_pool: [CpInfo {
                tag: 0,
                info: [0u8; 3],
            }; MAX_CP_ENTRIES],
            cp_count: 0,
        }
    }

    /// Check if this package's AID matches the given AID slice.
    pub fn aid_matches(&self, aid: &[u8]) -> bool {
        let len = self.aid_len as usize;
        if aid.len() != len {
            return false;
        }
        self.aid[..len] == *aid
    }

    /// Get the AID as a slice.
    pub fn aid_slice(&self) -> &[u8] {
        &self.aid[..self.aid_len as usize]
    }

    /// Look up a method by index.
    pub const fn method(&self, index: u8) -> Option<&MethodInfo> {
        if (index as usize) < MAX_METHODS {
            self.methods[index as usize].as_ref()
        } else {
            None
        }
    }

    /// Look up a Constant Pool entry by index. Returns `None` for
    /// indices beyond [`Self::cp_count`] or [`MAX_CP_ENTRIES`].
    #[must_use]
    pub const fn cp_entry(&self, index: u16) -> Option<&CpInfo> {
        let idx = index as usize;
        if index < self.cp_count && idx < MAX_CP_ENTRIES {
            Some(&self.constant_pool[idx])
        } else {
            None
        }
    }
}

/// Error returned when CAP parsing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer too short to contain the expected data.
    TooShort,
    /// Magic number mismatch (expected `0xDECAFFED`).
    BadMagic,
    /// AID length exceeds maximum (16 bytes).
    AidTooLong,
    /// Too many methods (exceeds `MAX_METHODS`).
    TooManyMethods,
    /// Method bytecode exceeds `MAX_BYTECODE`.
    BytecodeTooLong,
    /// Exception handler `handler_pc` outside method bytecode range.
    InvalidExceptionHandler,
    /// Descriptor and Class component method offsets do not match.
    OffsetMismatch,
    /// Too many exception table entries.
    TooManyExceptions,
    /// Constant Pool count exceeds `MAX_CP_ENTRIES`.
    TooManyConstantPoolEntries,
    /// Constant Pool entry has an unknown / unsupported tag.
    UnknownConstantPoolTag,
}

pub mod components;

/// Parse a CAP file into a [`Package`].
///
/// Auto-detects the input format:
///
/// - **Standard component-tagged CAP** (JCVM 3.2 Chapter 6): a sequence
///   of `tag(1) | size(2 BE) | body` triples starting with the
///   Header component (tag = 1). Produced by Oracle's converter and
///   by [`simrs_jacc::CapWriter::write`].
/// - **Simplified internal blob**: starts with magic `0xDECAFFED`.
///   Produced by [`build_cap_blob`] for `no_std` embedded loading
///   where the full component machinery would be overkill.
///
/// Both formats yield the same [`Package`] structure.
///
/// # Errors
///
/// Returns [`ParseError`] if the input is empty or malformed in the
/// detected format.
pub fn parse_cap(data: &[u8]) -> Result<Package, ParseError> {
    match data.first() {
        // Header component tag — standard JCVM 3.2 CAP file.
        Some(&components::tag::HEADER) => components::parse(data),
        // Anything else: try the simplified blob path. The first byte
        // of `CAP_MAGIC` (`0xDE`) ends up here, as do malformed inputs
        // (which the blob parser will reject with a more specific
        // error than a tag mismatch could give).
        _ => parse_cap_blob(data),
    }
}

/// Parse a simplified-blob CAP into a [`Package`].
///
/// The simplified blob is a flat concatenation of magic + AID + method
/// records, designed for `no_std` embedded loading without the
/// full component machinery. See module-level docs for the layout.
///
/// Most callers want [`parse_cap`] (which auto-detects format);
/// this entry point is exposed for tests and tooling that specifically
/// need the simplified path.
///
/// # Errors
///
/// Returns [`ParseError`] if the blob is malformed.
#[allow(clippy::too_many_lines)]
pub fn parse_cap_blob(data: &[u8]) -> Result<Package, ParseError> {
    let mut pos = 0;

    // Magic (4 bytes).
    if data.len() < pos + 4 {
        return Err(ParseError::TooShort);
    }
    let magic = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    if magic != CAP_MAGIC {
        return Err(ParseError::BadMagic);
    }
    pos += 4;

    // AID length (1 byte).
    if data.len() < pos + 1 {
        return Err(ParseError::TooShort);
    }
    let aid_len = data[pos];
    pos += 1;
    if aid_len as usize > MAX_AID_LEN {
        return Err(ParseError::AidTooLong);
    }

    // AID bytes.
    if data.len() < pos + aid_len as usize {
        return Err(ParseError::TooShort);
    }
    let mut aid = [0u8; MAX_AID_LEN];
    aid[..aid_len as usize].copy_from_slice(&data[pos..pos + aid_len as usize]);
    pos += aid_len as usize;

    // Method count (1 byte).
    if data.len() < pos + 1 {
        return Err(ParseError::TooShort);
    }
    let method_count = data[pos];
    pos += 1;
    if method_count as usize > MAX_METHODS {
        return Err(ParseError::TooManyMethods);
    }

    // Parse each method.
    let mut methods: [Option<MethodInfo>; MAX_METHODS] = [None; MAX_METHODS];
    for slot in methods.iter_mut().take(method_count as usize) {
        // flags, max_stack, nargs, max_locals (4 bytes).
        if data.len() < pos + 4 {
            return Err(ParseError::TooShort);
        }
        let flags = data[pos];
        let max_stack = data[pos + 1];
        let nargs = data[pos + 2];
        let max_locals = data[pos + 3];
        pos += 4;

        // bytecode_len (2 bytes, big-endian).
        if data.len() < pos + 2 {
            return Err(ParseError::TooShort);
        }
        let bytecode_len = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        if bytecode_len as usize > MAX_BYTECODE {
            return Err(ParseError::BytecodeTooLong);
        }

        // bytecode.
        if data.len() < pos + bytecode_len as usize {
            return Err(ParseError::TooShort);
        }
        let mut bytecode = [0u8; MAX_BYTECODE];
        bytecode[..bytecode_len as usize].copy_from_slice(&data[pos..pos + bytecode_len as usize]);
        pos += bytecode_len as usize;

        // Parse optional exception table + offsets (extended format).
        let mut exception_table = [None; MAX_EXCEPTIONS];
        let mut descriptor_offset: u16 = 0;
        let mut class_offset: u16 = 0;

        if pos < data.len() {
            let exc_count = data[pos] as usize;
            pos += 1;
            if exc_count > MAX_EXCEPTIONS {
                return Err(ParseError::TooManyExceptions);
            }
            for exc_slot in exception_table.iter_mut().take(exc_count) {
                if data.len() < pos + 8 {
                    return Err(ParseError::TooShort);
                }
                let start_pc = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let end_pc = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                let handler_pc = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
                let catch_type = u16::from_be_bytes([data[pos + 6], data[pos + 7]]);
                pos += 8;

                // Validate exception handler bounds per JCVM spec.
                if handler_pc >= bytecode_len
                    || start_pc >= bytecode_len
                    || end_pc > bytecode_len
                    || start_pc >= end_pc
                {
                    return Err(ParseError::InvalidExceptionHandler);
                }
                *exc_slot = Some(ExceptionEntry {
                    start_pc,
                    end_pc,
                    handler_pc,
                    catch_type,
                });
            }

            // Parse descriptor and class offsets.
            if data.len() >= pos + 4 {
                descriptor_offset = u16::from_be_bytes([data[pos], data[pos + 1]]);
                class_offset = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                pos += 4;

                // Cross-validate: if either is non-zero, both must match.
                // A zeroed Class offset with a valid Descriptor offset is the
                // Lancia & Bouffard (CARDIS 2015) attack vector.
                if (descriptor_offset != 0 || class_offset != 0)
                    && descriptor_offset != class_offset
                {
                    return Err(ParseError::OffsetMismatch);
                }
            }
        }

        *slot = Some(MethodInfo {
            flags,
            max_stack,
            nargs,
            max_locals,
            bytecode,
            bytecode_len,
            exception_table,
            descriptor_offset,
            class_offset,
        });
    }

    Ok(Package {
        aid,
        aid_len,
        methods,
        method_count,
        constant_pool: [CpInfo::default(); MAX_CP_ENTRIES],
        cp_count: 0,
    })
}

/// Build a minimal CAP blob for testing.
///
/// Constructs a valid binary blob with static methods containing the
/// given bytecodes. The AID is set to `aid`.
#[allow(clippy::cast_possible_truncation)]
pub fn build_cap_blob(aid: &[u8], bytecodes: &[&[u8]], buf: &mut [u8]) -> usize {
    let mut pos = 0;

    // Magic.
    buf[pos..pos + 4].copy_from_slice(&CAP_MAGIC.to_be_bytes());
    pos += 4;

    // AID.
    let aid_len = aid.len().min(MAX_AID_LEN);
    buf[pos] = aid_len as u8;
    pos += 1;
    buf[pos..pos + aid_len].copy_from_slice(&aid[..aid_len]);
    pos += aid_len;

    // Method count.
    let count = bytecodes.len().min(MAX_METHODS);
    buf[pos] = count as u8;
    pos += 1;

    // Methods.
    for bc in bytecodes.iter().take(count) {
        let bc_len = bc.len().min(MAX_BYTECODE);
        buf[pos] = METHOD_FLAG_STATIC; // flags: static
        buf[pos + 1] = 8; // max_stack
        buf[pos + 2] = 0; // nargs
        buf[pos + 3] = 4; // max_locals
        pos += 4;
        buf[pos..pos + 2].copy_from_slice(&(bc_len as u16).to_be_bytes());
        pos += 2;
        buf[pos..pos + bc_len].copy_from_slice(&bc[..bc_len]);
        pos += bc_len;
        // Exception table: 0 entries.
        buf[pos] = 0;
        pos += 1;
        // Matching descriptor/class offsets (both 0 = unused).
        buf[pos..pos + 4].fill(0);
        pos += 4;
    }

    pos
}

// ---------------------------------------------------------------------------
// Snapshot support for Package
// ---------------------------------------------------------------------------

impl Package {
    /// Maximum snapshot size for a single package.
    ///
    /// Layout per method: present(1) + flags(1) + `max_stack`(1) + nargs(1) +
    ///   `max_locals`(1) + `bytecode_len`(2) + bytecode(256) +
    ///   `exc_count`(1) + exceptions(8\*8) + offsets(4).
    /// Constant pool: `cp_count`(2) + entries(`MAX_CP_ENTRIES` * 4).
    pub const MAX_SNAPSHOT_SIZE: usize = 1
        + MAX_AID_LEN
        + 1
        + MAX_METHODS * (1 + 1 + 1 + 1 + 1 + 2 + MAX_BYTECODE + 1 + MAX_EXCEPTIONS * 8 + 4)
        + 2
        + MAX_CP_ENTRIES * 4;

    /// Save package state to buffer. Returns bytes written, or 0 if buffer too small.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        let mut off = 0;
        let min_size = 1 + MAX_AID_LEN + 1;
        if buf.len() < min_size {
            return 0;
        }

        buf[off] = self.aid_len;
        off += 1;
        buf[off..off + MAX_AID_LEN].copy_from_slice(&self.aid);
        off += MAX_AID_LEN;
        buf[off] = self.method_count;
        off += 1;

        for method_slot in &self.methods {
            if off >= buf.len() {
                return 0;
            }
            match method_slot {
                None => {
                    buf[off] = 0; // not present
                    off += 1;
                }
                Some(m) => {
                    buf[off] = 1; // present
                    off += 1;
                    buf[off] = m.flags;
                    off += 1;
                    buf[off] = m.max_stack;
                    off += 1;
                    buf[off] = m.nargs;
                    off += 1;
                    buf[off] = m.max_locals;
                    off += 1;
                    buf[off..off + 2].copy_from_slice(&m.bytecode_len.to_le_bytes());
                    off += 2;
                    let bc_len = m.bytecode_len as usize;
                    if off + bc_len + 1 + MAX_EXCEPTIONS * 8 + 4 > buf.len() {
                        return 0;
                    }
                    buf[off..off + bc_len].copy_from_slice(&m.bytecode[..bc_len]);
                    off += bc_len;
                    // Exception table.
                    let exc_count = m.exception_table.iter().filter(|e| e.is_some()).count();
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        buf[off] = exc_count as u8;
                    }
                    off += 1;
                    for exc in m.exception_table.iter().flatten() {
                        buf[off..off + 2].copy_from_slice(&exc.start_pc.to_le_bytes());
                        off += 2;
                        buf[off..off + 2].copy_from_slice(&exc.end_pc.to_le_bytes());
                        off += 2;
                        buf[off..off + 2].copy_from_slice(&exc.handler_pc.to_le_bytes());
                        off += 2;
                        buf[off..off + 2].copy_from_slice(&exc.catch_type.to_le_bytes());
                        off += 2;
                    }
                    // Offsets.
                    buf[off..off + 2].copy_from_slice(&m.descriptor_offset.to_le_bytes());
                    off += 2;
                    buf[off..off + 2].copy_from_slice(&m.class_offset.to_le_bytes());
                    off += 2;
                }
            }
        }

        // Constant pool: cp_count (u16 LE) + cp_count entries of 4 bytes each.
        if off + 2 + (self.cp_count as usize) * 4 > buf.len() {
            return 0;
        }
        buf[off..off + 2].copy_from_slice(&self.cp_count.to_le_bytes());
        off += 2;
        for entry in &self.constant_pool[..self.cp_count as usize] {
            buf[off] = entry.tag;
            buf[off + 1..off + 4].copy_from_slice(&entry.info);
            off += 4;
        }

        off
    }

    /// Restore package state from buffer. Returns success.
    #[allow(clippy::too_many_lines)]
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        let mut off = 0;
        let min_size = 1 + MAX_AID_LEN + 1;
        if buf.len() < min_size {
            return false;
        }

        self.aid_len = buf[off];
        off += 1;
        if self.aid_len as usize > MAX_AID_LEN {
            return false;
        }
        self.aid.copy_from_slice(&buf[off..off + MAX_AID_LEN]);
        off += MAX_AID_LEN;
        self.method_count = buf[off];
        off += 1;

        for method_slot in &mut self.methods {
            if off >= buf.len() {
                return false;
            }
            let present = buf[off];
            off += 1;
            if present == 0 {
                *method_slot = None;
            } else {
                if off + 6 > buf.len() {
                    return false;
                }
                let flags = buf[off];
                off += 1;
                let max_stack = buf[off];
                off += 1;
                let nargs = buf[off];
                off += 1;
                let max_locals = buf[off];
                off += 1;
                let bytecode_len = u16::from_le_bytes([buf[off], buf[off + 1]]);
                off += 2;
                if bytecode_len as usize > MAX_BYTECODE || off + bytecode_len as usize > buf.len() {
                    return false;
                }
                let mut bytecode = [0u8; MAX_BYTECODE];
                let bc_len = bytecode_len as usize;
                bytecode[..bc_len].copy_from_slice(&buf[off..off + bc_len]);
                off += bc_len;
                // Exception table.
                let mut exception_table = [None; MAX_EXCEPTIONS];
                if off < buf.len() {
                    let exc_count = buf[off] as usize;
                    off += 1;
                    for exc_slot in exception_table
                        .iter_mut()
                        .take(exc_count.min(MAX_EXCEPTIONS))
                    {
                        if off + 8 > buf.len() {
                            return false;
                        }
                        let start_pc = u16::from_le_bytes([buf[off], buf[off + 1]]);
                        let end_pc = u16::from_le_bytes([buf[off + 2], buf[off + 3]]);
                        let handler_pc = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
                        let catch_type = u16::from_le_bytes([buf[off + 6], buf[off + 7]]);
                        off += 8;
                        *exc_slot = Some(ExceptionEntry {
                            start_pc,
                            end_pc,
                            handler_pc,
                            catch_type,
                        });
                    }
                }
                // Offsets.
                let mut descriptor_offset = 0u16;
                let mut class_offset = 0u16;
                if off + 4 <= buf.len() {
                    descriptor_offset = u16::from_le_bytes([buf[off], buf[off + 1]]);
                    class_offset = u16::from_le_bytes([buf[off + 2], buf[off + 3]]);
                    off += 4;
                }

                *method_slot = Some(MethodInfo {
                    flags,
                    max_stack,
                    nargs,
                    max_locals,
                    bytecode,
                    bytecode_len,
                    exception_table,
                    descriptor_offset,
                    class_offset,
                });
            }
        }

        // Constant pool: trailing block. Older snapshots without CP
        // simply lack these bytes, in which case we leave `cp_count`
        // and `constant_pool` at their default-empty initial state.
        self.cp_count = 0;
        self.constant_pool = [CpInfo::default(); MAX_CP_ENTRIES];
        if off + 2 <= buf.len() {
            let cp_count = u16::from_le_bytes([buf[off], buf[off + 1]]);
            off += 2;
            if cp_count as usize > MAX_CP_ENTRIES {
                return false;
            }
            if off + (cp_count as usize) * 4 > buf.len() {
                return false;
            }
            for entry in self.constant_pool.iter_mut().take(cp_count as usize) {
                entry.tag = buf[off];
                entry.info.copy_from_slice(&buf[off + 1..off + 4]);
                off += 4;
            }
            self.cp_count = cp_count;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_cap() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62];
        let bytecode: &[u8] = &[0x04, 0x78]; // sconst_1, sreturn
        let mut blob = [0u8; 512];
        let len = build_cap_blob(&aid, &[bytecode], &mut blob);

        let pkg = parse_cap(&blob[..len]).unwrap();
        assert!(pkg.aid_matches(&aid));
        assert_eq!(pkg.method_count, 1);
        let m = pkg.method(0).unwrap();
        assert!(m.is_static());
        assert_eq!(m.bytecode_len, 2);
        assert_eq!(&m.bytecode[..2], &[0x04, 0x78]);
    }

    #[test]
    fn parse_bad_magic() {
        let data = [0x00, 0x00, 0x00, 0x00];
        assert!(matches!(parse_cap(&data), Err(ParseError::BadMagic)));
    }

    #[test]
    fn parse_too_short() {
        assert!(matches!(
            parse_cap(&[0xDE, 0xCA]),
            Err(ParseError::TooShort)
        ));
    }

    #[test]
    fn parse_aid_too_long() {
        let mut blob = [0u8; 32];
        blob[0..4].copy_from_slice(&CAP_MAGIC.to_be_bytes());
        blob[4] = 17; // AID length > 16
        assert!(matches!(parse_cap(&blob), Err(ParseError::AidTooLong)));
    }

    #[test]
    fn parse_too_many_methods() {
        let mut blob = [0u8; 32];
        blob[0..4].copy_from_slice(&CAP_MAGIC.to_be_bytes());
        blob[4] = 1; // AID len
        blob[5] = 0xAA; // AID byte
        blob[6] = 33; // 33 methods > MAX_METHODS
        assert!(matches!(
            parse_cap(&blob[..7]),
            Err(ParseError::TooManyMethods)
        ));
    }

    #[test]
    fn parse_bytecode_too_long() {
        let mut blob = [0u8; 32];
        blob[0..4].copy_from_slice(&CAP_MAGIC.to_be_bytes());
        blob[4] = 1; // AID len
        blob[5] = 0xAA; // AID
        blob[6] = 1; // 1 method
        blob[7] = 0; // flags
        blob[8] = 0; // max_stack
        blob[9] = 0; // nargs
        blob[10] = 0; // max_locals
        blob[11] = 0x01; // bytecode_len high byte
        blob[12] = 0x01; // bytecode_len = 257 > MAX_BYTECODE
        assert!(matches!(
            parse_cap(&blob[..13]),
            Err(ParseError::BytecodeTooLong)
        ));
    }

    #[test]
    fn package_aid_mismatch() {
        let pkg = Package::empty();
        assert!(!pkg.aid_matches(&[0xAA]));
    }

    #[test]
    fn method_index_out_of_range() {
        let pkg = Package::empty();
        assert!(pkg.method(0).is_none());
        assert!(pkg.method(255).is_none());
    }

    #[test]
    fn build_multiple_methods() {
        let aid = [0xA0, 0x00];
        let bc1: &[u8] = &[0x03, 0x78]; // sconst_0, sreturn
        let bc2: &[u8] = &[0x04, 0x41, 0x78]; // sconst_1, sadd, sreturn
        let mut blob = [0u8; 512];
        let len = build_cap_blob(&aid, &[bc1, bc2], &mut blob);

        let pkg = parse_cap(&blob[..len]).unwrap();
        assert_eq!(pkg.method_count, 2);
        assert_eq!(pkg.method(0).unwrap().bytecode_len, 2);
        assert_eq!(pkg.method(1).unwrap().bytecode_len, 3);
    }

    #[test]
    fn package_snapshot_roundtrip() {
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62];
        let bytecode: &[u8] = &[0x04, 0x78];
        let mut blob = [0u8; 512];
        let len = build_cap_blob(&aid, &[bytecode], &mut blob);
        let pkg = parse_cap(&blob[..len]).unwrap();

        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        assert!(n > 0);

        let mut pkg2 = Package::empty();
        assert!(pkg2.restore_state(&snap[..n]));
        assert!(pkg2.aid_matches(&aid));
        assert_eq!(pkg2.method_count, 1);
        let m = pkg2.method(0).unwrap();
        assert_eq!(m.bytecode_len, 2);
        assert_eq!(&m.bytecode[..2], &[0x04, 0x78]);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn package_snapshot_roundtrip_with_constant_pool() {
        // Snapshot a Package whose CP has every entry-type variant
        // and verify each entry round-trips byte-for-byte. Picks
        // adversarial info bytes (all distinct, high-bit set in some
        // positions) so a wrong-byte or wrong-offset bug would surface.
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62];
        let mut pkg = Package::empty();
        pkg.aid_len = aid.len() as u8;
        pkg.aid[..aid.len()].copy_from_slice(&aid);
        pkg.method_count = 0;

        let entries = [
            (cp_tag::CLASSREF, [0x12, 0x34, 0x00]),
            (cp_tag::CLASSREF, [0x80 | 0x05, 0x42, 0x00]),
            (cp_tag::INSTANCE_FIELDREF, [0x00, 0x10, 0x07]),
            (cp_tag::VIRTUAL_METHODREF, [0x00, 0x20, 0x82]),
            (cp_tag::SUPER_METHODREF, [0x80 | 0x03, 0x09, 0x05]),
            (cp_tag::STATIC_FIELDREF, [0x00, 0xAB, 0xCD]),
            (cp_tag::STATIC_METHODREF, [0x80 | 0x07, 0x11, 0x33]),
        ];
        for (i, (tag, info)) in entries.iter().enumerate() {
            pkg.constant_pool[i] = CpInfo {
                tag: *tag,
                info: *info,
            };
        }
        pkg.cp_count = entries.len() as u16;

        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        assert!(n > 0);

        let mut pkg2 = Package::empty();
        assert!(pkg2.restore_state(&snap[..n]));
        assert_eq!(pkg2.cp_count, entries.len() as u16);
        for (i, (tag, info)) in entries.iter().enumerate() {
            let entry = pkg2.cp_entry(i as u16).expect("entry present");
            assert_eq!(entry.tag, *tag, "tag at index {i}");
            assert_eq!(entry.info, *info, "info at index {i}");
        }
    }

    #[test]
    fn old_snapshot_without_constant_pool_block_restores_to_empty_cp() {
        // Forward compatibility: a snapshot saved before the CP block
        // existed simply ends after the methods. `restore_state` must
        // accept that and surface `cp_count = 0` rather than failing.
        // Construct one such snapshot by save-then-truncate.
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        assert!(n >= 2);
        // Drop the trailing 2-byte cp_count + entries. The pre-CP
        // snapshot ends right after the per-method block.
        let truncated = &snap[..n - 2];

        let mut pkg2 = Package::empty();
        // Pre-populate to make the assertion meaningful: if restore
        // forgot to reset cp_count, this `7` would survive.
        pkg2.cp_count = 7;
        assert!(pkg2.restore_state(truncated));
        assert_eq!(pkg2.cp_count, 0);
    }

    #[test]
    fn restore_rejects_snapshot_with_cp_count_over_max() {
        // A malformed/attacker-controlled snapshot that claims more
        // CP entries than we can hold must be rejected. Silently
        // truncating would let a forged snapshot drop entries.
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        // Overwrite the stored cp_count with MAX+1 (LE u16).
        let cp_count_off = n - 2; // last 2 bytes are cp_count when cp is empty
        #[allow(clippy::cast_possible_truncation)]
        let bad = (MAX_CP_ENTRIES as u16) + 1;
        snap[cp_count_off..cp_count_off + 2].copy_from_slice(&bad.to_le_bytes());

        let mut pkg2 = Package::empty();
        assert!(
            !pkg2.restore_state(&snap[..n]),
            "restore must reject cp_count > MAX_CP_ENTRIES"
        );
    }

    #[test]
    fn restore_rejects_snapshot_with_truncated_cp_entries() {
        // Snapshot's cp_count claims more entries than the buffer
        // holds. Reading past the buffer would be out-of-bounds.
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        // Claim 3 entries but truncate the buffer to fit only 1.
        pkg.cp_count = 3;
        pkg.constant_pool[0] = CpInfo {
            tag: cp_tag::CLASSREF,
            info: [0x00, 0x01, 0x00],
        };
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        // Drop the last 2 entries (8 bytes) but keep cp_count = 3.
        let truncated_len = n - 8;

        let mut pkg2 = Package::empty();
        assert!(
            !pkg2.restore_state(&snap[..truncated_len]),
            "restore must reject truncated CP entries"
        );
    }

    #[test]
    fn cp_entry_past_cp_count_returns_none() {
        // API contract: cp_entry must bound-check against the live
        // cp_count, not just MAX_CP_ENTRIES. Stale entries beyond
        // cp_count must not leak out.
        let mut pkg = Package::empty();
        pkg.cp_count = 2;
        // Plant a "stale" entry at index 5 (past cp_count) to ensure
        // the bounds check is on cp_count rather than tag != 0.
        pkg.constant_pool[5] = CpInfo {
            tag: cp_tag::CLASSREF,
            info: [0xDE, 0xAD, 0xBE],
        };
        assert!(
            pkg.cp_entry(0).is_some(),
            "default-empty entry at 0 still present"
        );
        assert!(
            pkg.cp_entry(1).is_some(),
            "default-empty entry at 1 still present"
        );
        assert!(pkg.cp_entry(2).is_none(), "index == cp_count must be None");
        assert!(
            pkg.cp_entry(5).is_none(),
            "stale entry past cp_count must not leak"
        );
        #[allow(clippy::cast_possible_truncation)]
        let max_idx = MAX_CP_ENTRIES as u16;
        assert!(
            pkg.cp_entry(max_idx).is_none(),
            "MAX_CP_ENTRIES must be None"
        );
        assert!(pkg.cp_entry(u16::MAX).is_none(), "u16::MAX must be None");
    }
}
