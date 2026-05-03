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

/// Maximum applets advertised by a single CAP package.
///
/// JCVM 3.2 § 6.5 puts no spec-level cap; this matches the highest SD
/// count any JCOP profile in `docs/standards/06-globalplatform.md`
/// declares (`JCOP21id` and `JCOP31bio`: 4 SDs).
pub const MAX_APPLETS_PER_PACKAGE: usize = 4;

/// Maximum packages a single CAP can import.
///
/// JCVM 3.2 § 6.7 caps `count` at 128 (a u8); this conservative
/// runtime cap covers typical applets that import
/// `javacard.framework`, `javacard.security`, `javacardx.crypto`,
/// and a small handful of vendor packages.
pub const MAX_IMPORTS_PER_PACKAGE: usize = 8;

/// Maximum classes that a single package can export
/// (JCVM 3.2 § 6.13).
pub const MAX_EXPORTED_CLASSES_PER_PACKAGE: usize = 4;

/// Maximum static fields a single exported class can publish.
pub const MAX_EXPORTED_FIELDS_PER_CLASS: usize = 16;

/// Maximum static methods a single exported class can publish.
pub const MAX_EXPORTED_METHODS_PER_CLASS: usize = 16;

/// Maximum 1-byte CP-token reference locations the runtime tracks.
///
/// JCVM 3.2 § 6.12 carries one entry per byte in the Method /
/// `StaticField` components that contains a 1-byte CP token; real
/// applets typically have 50..200. This conservative cap covers
/// small and moderate applets and is a per-deployment knob.
pub const MAX_REF_LOC_BYTE_INDICES: usize = 128;

/// Maximum 2-byte CP-token reference locations the runtime tracks.
pub const MAX_REF_LOC_BYTE2_INDICES: usize = 64;

// ---------------------------------------------------------------------------
// Snapshot slot/block sizes -- single source of truth.
//
// `save_state`, `restore_state`, [`Package::MAX_SNAPSHOT_SIZE`], and the
// test-only offset helpers all compute the same per-slot byte counts.
// Naming each one once here keeps the four sites in lockstep: bumping a
// `MAX_*` constant cascades correctly, and adding new fields to a slot's
// payload only requires updating its formula here.
// ---------------------------------------------------------------------------

/// One absent or present applet slot: present(1) + `aid_len`(1) +
/// aid(`MAX_AID_LEN`) + `install_method_offset`(2).
pub(crate) const APPLET_SLOT_SIZE: usize = 1 + 1 + MAX_AID_LEN + 2;

/// One absent or present import slot: present(1) + `minor`(1) +
/// `major`(1) + `aid_len`(1) + aid(`MAX_AID_LEN`).
pub(crate) const IMPORT_SLOT_SIZE: usize = 1 + 1 + 1 + 1 + MAX_AID_LEN;

/// One absent or present export slot: present(1) + `class_offset`(2) +
/// `static_field_count`(1) + `static_method_count`(1) +
/// `MAX_EXPORTED_FIELDS_PER_CLASS` * 2 + `MAX_EXPORTED_METHODS_PER_CLASS` * 2.
pub(crate) const EXPORT_SLOT_SIZE: usize =
    1 + 2 + 1 + 1 + MAX_EXPORTED_FIELDS_PER_CLASS * 2 + MAX_EXPORTED_METHODS_PER_CLASS * 2;

/// Snapshot bytes for the whole applet block: count(1) + slots.
pub(crate) const APPLET_BLOCK_SIZE: usize = 1 + MAX_APPLETS_PER_PACKAGE * APPLET_SLOT_SIZE;

/// Snapshot bytes for the whole import block: count(1) + slots.
pub(crate) const IMPORT_BLOCK_SIZE: usize = 1 + MAX_IMPORTS_PER_PACKAGE * IMPORT_SLOT_SIZE;

/// Snapshot bytes for the whole export block: count(1) + slots.
pub(crate) const EXPORT_BLOCK_SIZE: usize = 1 + MAX_EXPORTED_CLASSES_PER_PACKAGE * EXPORT_SLOT_SIZE;

/// Snapshot bytes for the method-component-offsets parallel array
/// (always `MAX_METHODS * 2` regardless of `method_count`).
pub(crate) const METHOD_OFFSETS_BLOCK_SIZE: usize = MAX_METHODS * 2;

/// Snapshot bytes for the reference-location block:
/// `byte_count`(2) + `byte_deltas`(`MAX_REF_LOC_BYTE_INDICES`) +
/// `byte2_count`(2) + `byte2_deltas`(`MAX_REF_LOC_BYTE2_INDICES`).
pub(crate) const REF_LOC_BLOCK_SIZE: usize =
    2 + MAX_REF_LOC_BYTE_INDICES + 2 + MAX_REF_LOC_BYTE2_INDICES;

/// One entry in the Export component (JCVM 3.2 § 6.13).
///
/// The `class_token` carried in external CP references is an index
/// into a package's [`Package::exports`] table; that yields this
/// struct, whose `static_field_offsets` and `static_method_offsets`
/// arrays are then indexed by the field/method token in the original
/// reference to land on the offset within the `StaticField` / Method
/// component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportInfo {
    /// Offset into the Class component naming the exported class.
    pub class_offset: u16,
    /// Number of valid entries in [`Self::static_field_offsets`].
    pub static_field_count: u8,
    /// Number of valid entries in [`Self::static_method_offsets`].
    pub static_method_count: u8,
    /// Offsets of exported static fields within the `StaticField`
    /// component, indexed by the importer's `static_field_token`.
    pub static_field_offsets: [u16; MAX_EXPORTED_FIELDS_PER_CLASS],
    /// Offsets of exported static methods within the Method
    /// component, indexed by the importer's `static_method_token`.
    pub static_method_offsets: [u16; MAX_EXPORTED_METHODS_PER_CLASS],
}

impl ExportInfo {
    /// Create an empty export info.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            class_offset: 0,
            static_field_count: 0,
            static_method_count: 0,
            static_field_offsets: [0u16; MAX_EXPORTED_FIELDS_PER_CLASS],
            static_method_offsets: [0u16; MAX_EXPORTED_METHODS_PER_CLASS],
        }
    }

    /// Look up an exported static-field offset by its token.
    /// Returns `None` for tokens beyond [`Self::static_field_count`]
    /// or [`MAX_EXPORTED_FIELDS_PER_CLASS`].
    #[must_use]
    pub const fn static_field_offset(&self, token: u8) -> Option<u16> {
        let idx = token as usize;
        if (token as u16) < (self.static_field_count as u16) && idx < MAX_EXPORTED_FIELDS_PER_CLASS
        {
            Some(self.static_field_offsets[idx])
        } else {
            None
        }
    }

    /// Look up an exported static-method offset by its token.
    /// Returns `None` for tokens beyond [`Self::static_method_count`]
    /// or [`MAX_EXPORTED_METHODS_PER_CLASS`].
    #[must_use]
    pub const fn static_method_offset(&self, token: u8) -> Option<u16> {
        let idx = token as usize;
        if (token as u16) < (self.static_method_count as u16)
            && idx < MAX_EXPORTED_METHODS_PER_CLASS
        {
            Some(self.static_method_offsets[idx])
        } else {
            None
        }
    }
}

/// One imported-package entry in the Import component
/// (JCVM 3.2 § 6.7).
///
/// External references in `ConstantPool` entries identify the
/// imported package by `package_token`, an index into this table.
/// Resolving such references requires looking up the imported AID
/// here, then finding the matching loaded [`Package`] in the JCVM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportInfo {
    /// Imported package's minor version.
    pub minor_version: u8,
    /// Imported package's major version.
    pub major_version: u8,
    /// Imported package AID.
    pub aid: [u8; MAX_AID_LEN],
    /// Number of valid bytes in `aid`.
    pub aid_len: u8,
}

impl ImportInfo {
    /// Create an empty import info.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            minor_version: 0,
            major_version: 0,
            aid: [0u8; MAX_AID_LEN],
            aid_len: 0,
        }
    }

    /// Returns this import's AID as a slice.
    #[must_use]
    pub fn aid_slice(&self) -> &[u8] {
        &self.aid[..self.aid_len as usize]
    }
}

/// One applet's entry in the Applet component (JCVM 3.2 § 6.5).
///
/// Each applet carries its own AID (which the Card Manager uses for
/// SELECT-by-AID) and the offset of its `install` method inside the
/// Method component. INSTALL [for install] dispatches to that offset
/// when the applet's first instance is being created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppletInfo {
    /// Applet AID.
    pub aid: [u8; MAX_AID_LEN],
    /// Number of valid bytes in `aid` (5..=16 per ISO 7816-4).
    pub aid_len: u8,
    /// Offset of the applet's `install` method inside the Method
    /// component body (JCVM 3.2 § 6.5).
    pub install_method_offset: u16,
}

impl AppletInfo {
    /// Create an empty applet info (zero AID, zero offset).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            aid: [0u8; MAX_AID_LEN],
            aid_len: 0,
            install_method_offset: 0,
        }
    }

    /// Returns this applet's AID as a slice.
    #[must_use]
    pub fn aid_slice(&self) -> &[u8] {
        &self.aid[..self.aid_len as usize]
    }

    /// Returns whether this applet's AID matches the given AID slice.
    #[must_use]
    pub fn aid_matches(&self, aid: &[u8]) -> bool {
        let len = self.aid_len as usize;
        aid.len() == len && self.aid[..len] == *aid
    }
}

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
    /// Each method's byte offset within the Method component body
    /// (parallel to [`Self::methods`], indexed by method index).
    /// Populated by the component-tagged parser from the Descriptor
    /// component; left at zero by the simplified-blob parser, which
    /// has no concept of component-relative offsets. Used to resolve
    /// the Applet component's `install_method_offset` to a method
    /// index for INSTALL [for install] dispatch.
    pub method_offsets: [u16; MAX_METHODS],
    /// Constant Pool entries (JCVM 3.2 § 6.8). Stored in raw 4-byte
    /// form; decode via `CpInfo::as_*` helpers at resolve-time.
    pub constant_pool: [CpInfo; MAX_CP_ENTRIES],
    /// Number of valid Constant Pool entries (`<= MAX_CP_ENTRIES`).
    pub cp_count: u16,
    /// Applet entries (JCVM 3.2 § 6.5). Surfaces each applet's AID
    /// and `install` method offset for Card-Manager dispatch.
    pub applets: [Option<AppletInfo>; MAX_APPLETS_PER_PACKAGE],
    /// Number of valid applet entries (`<= MAX_APPLETS_PER_PACKAGE`).
    pub applet_count: u8,
    /// Imported-package entries (JCVM 3.2 § 6.7). The `package_token`
    /// in external CP references is an index into this table.
    pub imports: [Option<ImportInfo>; MAX_IMPORTS_PER_PACKAGE],
    /// Number of valid import entries (`<= MAX_IMPORTS_PER_PACKAGE`).
    pub import_count: u8,
    /// Exported-class entries (JCVM 3.2 § 6.13). The `class_token`
    /// carried in external CP references against this package is an
    /// index into this table.
    pub exports: [Option<ExportInfo>; MAX_EXPORTED_CLASSES_PER_PACKAGE],
    /// Number of valid export entries (`<= MAX_EXPORTED_CLASSES_PER_PACKAGE`).
    pub export_count: u8,
    /// Delta-encoded byte offsets of 1-byte CP tokens in the Method
    /// and `StaticField` components (JCVM 3.2 § 6.12). The token
    /// patcher walks these deltas to find every byte that holds a
    /// CP index needing resolution.
    pub ref_loc_byte_deltas: [u8; MAX_REF_LOC_BYTE_INDICES],
    /// Number of valid entries in [`Self::ref_loc_byte_deltas`].
    pub ref_loc_byte_count: u16,
    /// Delta-encoded byte offsets of 2-byte CP tokens.
    pub ref_loc_byte2_deltas: [u8; MAX_REF_LOC_BYTE2_INDICES],
    /// Number of valid entries in [`Self::ref_loc_byte2_deltas`].
    pub ref_loc_byte2_count: u16,
}

impl Package {
    /// Create an empty package.
    pub const fn empty() -> Self {
        Self {
            aid: [0u8; MAX_AID_LEN],
            aid_len: 0,
            methods: [None; MAX_METHODS],
            method_count: 0,
            method_offsets: [0u16; MAX_METHODS],
            constant_pool: [CpInfo {
                tag: 0,
                info: [0u8; 3],
            }; MAX_CP_ENTRIES],
            cp_count: 0,
            applets: [None; MAX_APPLETS_PER_PACKAGE],
            applet_count: 0,
            imports: [None; MAX_IMPORTS_PER_PACKAGE],
            import_count: 0,
            exports: [None; MAX_EXPORTED_CLASSES_PER_PACKAGE],
            export_count: 0,
            ref_loc_byte_deltas: [0u8; MAX_REF_LOC_BYTE_INDICES],
            ref_loc_byte_count: 0,
            ref_loc_byte2_deltas: [0u8; MAX_REF_LOC_BYTE2_INDICES],
            ref_loc_byte2_count: 0,
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

    /// Look up an applet by index. Returns `None` for indices beyond
    /// [`Self::applet_count`] or [`MAX_APPLETS_PER_PACKAGE`].
    #[must_use]
    pub const fn applet(&self, index: u8) -> Option<&AppletInfo> {
        let idx = index as usize;
        if (index as u16) < (self.applet_count as u16) && idx < MAX_APPLETS_PER_PACKAGE {
            self.applets[idx].as_ref()
        } else {
            None
        }
    }

    /// Look up an applet by AID. Returns the first match, or `None`.
    /// Used by the Card Manager's SELECT-by-AID dispatch.
    #[must_use]
    pub fn applet_by_aid(&self, aid: &[u8]) -> Option<&AppletInfo> {
        self.applets
            .iter()
            .flatten()
            .find(|info| info.aid_matches(aid))
    }

    /// Resolve a Method-component byte offset to a method index.
    ///
    /// Used by INSTALL [for install] dispatch: the Applet component
    /// records each applet's `install_method_offset` as a byte offset
    /// into the Method component body, but the JCVM addresses methods
    /// by index. This walks [`Self::method_offsets`] (only valid
    /// indices `< method_count`) and returns the matching index, or
    /// `None` if no method begins at that offset.
    ///
    /// Returns `None` for the simplified-blob path: that path leaves
    /// every offset at 0, so a non-zero query never matches and a
    /// zero query collides with the unset slots.
    #[must_use]
    pub fn method_index_by_component_offset(&self, offset: u16) -> Option<u8> {
        for i in 0..self.method_count {
            let idx = i as usize;
            if idx >= MAX_METHODS {
                break;
            }
            if self.method_offsets[idx] == offset && self.methods[idx].is_some() {
                return Some(i);
            }
        }
        None
    }

    /// Look up an imported-package entry by `package_token`. Returns
    /// `None` for indices beyond [`Self::import_count`] or
    /// [`MAX_IMPORTS_PER_PACKAGE`].
    ///
    /// CP entries with `ClassRef::External { package_token, .. }`
    /// pass that `package_token` here to retrieve the importer's
    /// view of the dependency (AID + version).
    #[must_use]
    pub const fn import(&self, package_token: u8) -> Option<&ImportInfo> {
        let idx = package_token as usize;
        if (package_token as u16) < (self.import_count as u16) && idx < MAX_IMPORTS_PER_PACKAGE {
            self.imports[idx].as_ref()
        } else {
            None
        }
    }

    /// Look up an exported class by `class_token`. Returns `None` for
    /// tokens beyond [`Self::export_count`] or
    /// [`MAX_EXPORTED_CLASSES_PER_PACKAGE`].
    ///
    /// CP entries that target a class within this package via an
    /// external token resolve through this table to retrieve the
    /// class's `class_offset` and per-class field/method tables.
    #[must_use]
    pub const fn export(&self, class_token: u8) -> Option<&ExportInfo> {
        let idx = class_token as usize;
        if (class_token as u16) < (self.export_count as u16)
            && idx < MAX_EXPORTED_CLASSES_PER_PACKAGE
        {
            self.exports[idx].as_ref()
        } else {
            None
        }
    }

    /// Slice of valid 1-byte-token reference-location deltas
    /// (JCVM 3.2 § 6.12). The token patcher walks this sequence,
    /// accumulating each byte as a delta from the previous absolute
    /// offset; per spec, a byte of `0xFF` means "advance 254 and
    /// continue without emitting a patch site".
    #[must_use]
    pub fn ref_loc_byte_deltas(&self) -> &[u8] {
        let n = (self.ref_loc_byte_count as usize).min(MAX_REF_LOC_BYTE_INDICES);
        &self.ref_loc_byte_deltas[..n]
    }

    /// Slice of valid 2-byte-token reference-location deltas.
    #[must_use]
    pub fn ref_loc_byte2_deltas(&self) -> &[u8] {
        let n = (self.ref_loc_byte2_count as usize).min(MAX_REF_LOC_BYTE2_INDICES);
        &self.ref_loc_byte2_deltas[..n]
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
    /// Applet component declares more applets than `MAX_APPLETS_PER_PACKAGE`.
    TooManyApplets,
    /// Import component declares more imports than `MAX_IMPORTS_PER_PACKAGE`.
    TooManyImports,
    /// Export component declares more classes than `MAX_EXPORTED_CLASSES_PER_PACKAGE`.
    TooManyExportedClasses,
    /// One exported class names more static fields than
    /// `MAX_EXPORTED_FIELDS_PER_CLASS`.
    TooManyExportedFields,
    /// One exported class names more static methods than
    /// `MAX_EXPORTED_METHODS_PER_CLASS`.
    TooManyExportedMethods,
    /// `RefLocation` byte-index list exceeds `MAX_REF_LOC_BYTE_INDICES`.
    TooManyRefLocByteIndices,
    /// `RefLocation` byte2-index list exceeds `MAX_REF_LOC_BYTE2_INDICES`.
    TooManyRefLocByte2Indices,
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
        method_offsets: [0u16; MAX_METHODS],
        constant_pool: [CpInfo::default(); MAX_CP_ENTRIES],
        cp_count: 0,
        applets: [None; MAX_APPLETS_PER_PACKAGE],
        applet_count: 0,
        imports: [None; MAX_IMPORTS_PER_PACKAGE],
        import_count: 0,
        exports: [None; MAX_EXPORTED_CLASSES_PER_PACKAGE],
        export_count: 0,
        ref_loc_byte_deltas: [0u8; MAX_REF_LOC_BYTE_INDICES],
        ref_loc_byte_count: 0,
        ref_loc_byte2_deltas: [0u8; MAX_REF_LOC_BYTE2_INDICES],
        ref_loc_byte2_count: 0,
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
    /// Applets: `applet_count`(1) + per-applet (present(1) + `aid_len`(1) +
    ///   aid(`MAX_AID_LEN`) + `install_method_offset`(2)).
    /// Imports: `import_count`(1) + per-import (present(1) + `minor`(1) +
    ///   `major`(1) + `aid_len`(1) + aid(`MAX_AID_LEN`)).
    /// Exports: `export_count`(1) + per-class (present(1) +
    ///   `class_offset`(2) + `static_field_count`(1) +
    ///   `static_method_count`(1) +
    ///   `static_field_offsets`(`MAX_EXPORTED_FIELDS_PER_CLASS` * 2) +
    ///   `static_method_offsets`(`MAX_EXPORTED_METHODS_PER_CLASS` * 2)).
    pub const MAX_SNAPSHOT_SIZE: usize = 1
        + MAX_AID_LEN
        + 1
        + MAX_METHODS * (1 + 1 + 1 + 1 + 1 + 2 + MAX_BYTECODE + 1 + MAX_EXCEPTIONS * 8 + 4)
        + 2
        + MAX_CP_ENTRIES * 4
        + APPLET_BLOCK_SIZE
        + IMPORT_BLOCK_SIZE
        + METHOD_OFFSETS_BLOCK_SIZE
        + EXPORT_BLOCK_SIZE
        + REF_LOC_BLOCK_SIZE;

    /// Save package state to buffer. Returns bytes written, or 0 if buffer too small.
    #[allow(clippy::too_many_lines)]
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

        // Applets: applet_count(1) + per-applet (present, aid_len, aid, offset).
        if off + APPLET_BLOCK_SIZE > buf.len() {
            return 0;
        }
        buf[off] = self.applet_count;
        off += 1;
        for slot in &self.applets {
            match slot {
                None => {
                    buf[off] = 0; // not present
                    off += APPLET_SLOT_SIZE;
                }
                Some(a) => {
                    buf[off] = 1; // present
                    off += 1;
                    buf[off] = a.aid_len;
                    off += 1;
                    buf[off..off + MAX_AID_LEN].copy_from_slice(&a.aid);
                    off += MAX_AID_LEN;
                    buf[off..off + 2].copy_from_slice(&a.install_method_offset.to_le_bytes());
                    off += 2;
                }
            }
        }

        // Imports: import_count(1) + per-import (present, minor, major, aid_len, aid).
        if off + IMPORT_BLOCK_SIZE > buf.len() {
            return 0;
        }
        buf[off] = self.import_count;
        off += 1;
        for slot in &self.imports {
            match slot {
                None => {
                    buf[off] = 0; // not present
                    off += IMPORT_SLOT_SIZE;
                }
                Some(i) => {
                    buf[off] = 1; // present
                    off += 1;
                    buf[off] = i.minor_version;
                    off += 1;
                    buf[off] = i.major_version;
                    off += 1;
                    buf[off] = i.aid_len;
                    off += 1;
                    buf[off..off + MAX_AID_LEN].copy_from_slice(&i.aid);
                    off += MAX_AID_LEN;
                }
            }
        }

        // Method component offsets: MAX_METHODS * u16 LE.
        if off + METHOD_OFFSETS_BLOCK_SIZE > buf.len() {
            return 0;
        }
        for off_val in &self.method_offsets {
            buf[off..off + 2].copy_from_slice(&off_val.to_le_bytes());
            off += 2;
        }

        // Exports: export_count(1) + per-class (present, class_offset,
        // static_field_count, static_method_count, static_field_offsets,
        // static_method_offsets).
        if off + EXPORT_BLOCK_SIZE > buf.len() {
            return 0;
        }
        buf[off] = self.export_count;
        off += 1;
        for slot in &self.exports {
            match slot {
                None => {
                    buf[off] = 0; // not present
                    off += EXPORT_SLOT_SIZE;
                }
                Some(e) => {
                    buf[off] = 1; // present
                    off += 1;
                    buf[off..off + 2].copy_from_slice(&e.class_offset.to_le_bytes());
                    off += 2;
                    buf[off] = e.static_field_count;
                    off += 1;
                    buf[off] = e.static_method_count;
                    off += 1;
                    for f in &e.static_field_offsets {
                        buf[off..off + 2].copy_from_slice(&f.to_le_bytes());
                        off += 2;
                    }
                    for m in &e.static_method_offsets {
                        buf[off..off + 2].copy_from_slice(&m.to_le_bytes());
                        off += 2;
                    }
                }
            }
        }

        // RefLocation: byte_count(2 LE) + MAX_REF_LOC_BYTE_INDICES bytes +
        // byte2_count(2 LE) + MAX_REF_LOC_BYTE2_INDICES bytes.
        if off + REF_LOC_BLOCK_SIZE > buf.len() {
            return 0;
        }
        buf[off..off + 2].copy_from_slice(&self.ref_loc_byte_count.to_le_bytes());
        off += 2;
        buf[off..off + MAX_REF_LOC_BYTE_INDICES].copy_from_slice(&self.ref_loc_byte_deltas);
        off += MAX_REF_LOC_BYTE_INDICES;
        buf[off..off + 2].copy_from_slice(&self.ref_loc_byte2_count.to_le_bytes());
        off += 2;
        buf[off..off + MAX_REF_LOC_BYTE2_INDICES].copy_from_slice(&self.ref_loc_byte2_deltas);
        off += MAX_REF_LOC_BYTE2_INDICES;

        off
    }

    /// Restore package state from buffer. Returns success.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
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

        // Applets: trailing block. Older snapshots without the
        // applet section restore to `applet_count = 0`, mirroring the
        // CP forward-compat path.
        self.applet_count = 0;
        self.applets = [None; MAX_APPLETS_PER_PACKAGE];
        if off < buf.len() {
            self.applet_count = buf[off];
            off += 1;
            if self.applet_count as usize > MAX_APPLETS_PER_PACKAGE {
                return false;
            }
            for slot in &mut self.applets {
                if off >= buf.len() {
                    return false;
                }
                let present = buf[off];
                off += 1;
                if present == 0 {
                    *slot = None;
                    // Skip the unused payload (aid_len + aid + offset).
                    off += 1 + MAX_AID_LEN + 2;
                    continue;
                }
                if off + 1 + MAX_AID_LEN + 2 > buf.len() {
                    return false;
                }
                let aid_len = buf[off];
                off += 1;
                if aid_len as usize > MAX_AID_LEN {
                    return false;
                }
                let mut aid = [0u8; MAX_AID_LEN];
                aid.copy_from_slice(&buf[off..off + MAX_AID_LEN]);
                off += MAX_AID_LEN;
                let install_method_offset = u16::from_le_bytes([buf[off], buf[off + 1]]);
                off += 2;
                *slot = Some(AppletInfo {
                    aid,
                    aid_len,
                    install_method_offset,
                });
            }
        }

        // Imports: trailing block. Forward-compat for snapshots saved
        // before the import section existed: leave `import_count = 0`
        // and `imports` at default-empty.
        self.import_count = 0;
        self.imports = [None; MAX_IMPORTS_PER_PACKAGE];
        if off < buf.len() {
            self.import_count = buf[off];
            off += 1;
            if self.import_count as usize > MAX_IMPORTS_PER_PACKAGE {
                return false;
            }
            for slot in &mut self.imports {
                if off >= buf.len() {
                    return false;
                }
                let present = buf[off];
                off += 1;
                if present == 0 {
                    *slot = None;
                    off += 1 + 1 + 1 + MAX_AID_LEN;
                    continue;
                }
                if off + 1 + 1 + 1 + MAX_AID_LEN > buf.len() {
                    return false;
                }
                let minor_version = buf[off];
                off += 1;
                let major_version = buf[off];
                off += 1;
                let aid_len = buf[off];
                off += 1;
                if aid_len as usize > MAX_AID_LEN {
                    return false;
                }
                let mut aid = [0u8; MAX_AID_LEN];
                aid.copy_from_slice(&buf[off..off + MAX_AID_LEN]);
                off += MAX_AID_LEN;
                *slot = Some(ImportInfo {
                    minor_version,
                    major_version,
                    aid,
                    aid_len,
                });
            }
        }

        // Method component offsets: trailing block. Older snapshots
        // without this block restore to all-zeros (matching the
        // simplified-blob default).
        self.method_offsets = [0u16; MAX_METHODS];
        if off + METHOD_OFFSETS_BLOCK_SIZE <= buf.len() {
            for slot in &mut self.method_offsets {
                *slot = u16::from_le_bytes([buf[off], buf[off + 1]]);
                off += 2;
            }
        }

        // Exports: trailing block. Forward-compat for snapshots saved
        // before the export section existed.
        self.export_count = 0;
        self.exports = [None; MAX_EXPORTED_CLASSES_PER_PACKAGE];
        if off < buf.len() {
            self.export_count = buf[off];
            off += 1;
            if self.export_count as usize > MAX_EXPORTED_CLASSES_PER_PACKAGE {
                return false;
            }
            // Bytes per slot after the present-flag byte: same payload
            // for both the absent-skip and the present-parse arms.
            let payload_size = EXPORT_SLOT_SIZE - 1;
            for slot in &mut self.exports {
                if off >= buf.len() {
                    return false;
                }
                let present = buf[off];
                off += 1;
                if present == 0 {
                    *slot = None;
                    off += payload_size;
                    continue;
                }
                if off + payload_size > buf.len() {
                    return false;
                }
                let class_offset = u16::from_le_bytes([buf[off], buf[off + 1]]);
                off += 2;
                let static_field_count = buf[off];
                off += 1;
                let static_method_count = buf[off];
                off += 1;
                if static_field_count as usize > MAX_EXPORTED_FIELDS_PER_CLASS
                    || static_method_count as usize > MAX_EXPORTED_METHODS_PER_CLASS
                {
                    return false;
                }
                let mut static_field_offsets = [0u16; MAX_EXPORTED_FIELDS_PER_CLASS];
                for f in &mut static_field_offsets {
                    *f = u16::from_le_bytes([buf[off], buf[off + 1]]);
                    off += 2;
                }
                let mut static_method_offsets = [0u16; MAX_EXPORTED_METHODS_PER_CLASS];
                for m in &mut static_method_offsets {
                    *m = u16::from_le_bytes([buf[off], buf[off + 1]]);
                    off += 2;
                }
                *slot = Some(ExportInfo {
                    class_offset,
                    static_field_count,
                    static_method_count,
                    static_field_offsets,
                    static_method_offsets,
                });
            }
        }

        // RefLocation: trailing block. Forward-compat for snapshots
        // saved before the ref-loc section existed.
        self.ref_loc_byte_count = 0;
        self.ref_loc_byte_deltas = [0u8; MAX_REF_LOC_BYTE_INDICES];
        self.ref_loc_byte2_count = 0;
        self.ref_loc_byte2_deltas = [0u8; MAX_REF_LOC_BYTE2_INDICES];
        if off + REF_LOC_BLOCK_SIZE <= buf.len() {
            let byte_count = u16::from_le_bytes([buf[off], buf[off + 1]]);
            off += 2;
            if byte_count as usize > MAX_REF_LOC_BYTE_INDICES {
                return false;
            }
            self.ref_loc_byte_count = byte_count;
            self.ref_loc_byte_deltas
                .copy_from_slice(&buf[off..off + MAX_REF_LOC_BYTE_INDICES]);
            off += MAX_REF_LOC_BYTE_INDICES;
            let byte2_count = u16::from_le_bytes([buf[off], buf[off + 1]]);
            off += 2;
            if byte2_count as usize > MAX_REF_LOC_BYTE2_INDICES {
                return false;
            }
            self.ref_loc_byte2_count = byte2_count;
            self.ref_loc_byte2_deltas
                .copy_from_slice(&buf[off..off + MAX_REF_LOC_BYTE2_INDICES]);
            off += MAX_REF_LOC_BYTE2_INDICES;
        }
        let _ = off;

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

    // Block-size constants live at module scope (above `impl Package`) so
    // `save_state`, `restore_state`, `MAX_SNAPSHOT_SIZE`, and these test
    // helpers all consult one source of truth. Bumping a `MAX_*` field
    // count then cascades through every site without per-call-site
    // re-derivation.

    /// Total trailing block size after the CP block: applet +
    /// import + method-offsets + export + ref-loc.
    const TRAILING_BLOCKS_AFTER_CP: usize = APPLET_BLOCK_SIZE
        + IMPORT_BLOCK_SIZE
        + METHOD_OFFSETS_BLOCK_SIZE
        + EXPORT_BLOCK_SIZE
        + REF_LOC_BLOCK_SIZE;

    /// Locate the `cp_count` u16 in a snapshot whose CP, applet,
    /// import, export, and ref-loc blocks are all empty.
    const fn cp_count_offset_when_empty(n: usize) -> usize {
        n - TRAILING_BLOCKS_AFTER_CP - 2
    }

    /// Locate the `applet_count` byte in a snapshot whose applet,
    /// import, method-offsets, export, and ref-loc blocks are empty.
    const fn applet_count_offset_when_empty(n: usize) -> usize {
        n - REF_LOC_BLOCK_SIZE
            - EXPORT_BLOCK_SIZE
            - METHOD_OFFSETS_BLOCK_SIZE
            - IMPORT_BLOCK_SIZE
            - APPLET_BLOCK_SIZE
    }

    /// Locate the `import_count` byte in a snapshot whose import,
    /// method-offsets, export, and ref-loc blocks are empty.
    const fn import_count_offset_when_empty(n: usize) -> usize {
        n - REF_LOC_BLOCK_SIZE - EXPORT_BLOCK_SIZE - METHOD_OFFSETS_BLOCK_SIZE - IMPORT_BLOCK_SIZE
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
        // Overwrite cp_count at its computed offset (between the
        // method block and the applet block).
        let cp_count_off = cp_count_offset_when_empty(n);
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
        // Claim 3 entries but truncate so that only 1 entry fits
        // after the cp_count header. cp_count is at `cp_count_offset()`;
        // entries start at `cp_count_offset() + 2`. Allow exactly
        // 1 entry (4 bytes) of CP payload, then truncate.
        pkg.cp_count = 3;
        pkg.constant_pool[0] = CpInfo {
            tag: cp_tag::CLASSREF,
            info: [0x00, 0x01, 0x00],
        };
        pkg.constant_pool[1] = CpInfo {
            tag: cp_tag::CLASSREF,
            info: [0x00, 0x02, 0x00],
        };
        pkg.constant_pool[2] = CpInfo {
            tag: cp_tag::CLASSREF,
            info: [0x00, 0x03, 0x00],
        };
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        // cp_count sits right after the method block. With cp_count = 3,
        // the snapshot wrote 3 * 4 = 12 entry bytes after cp_count,
        // then the empty applet block, the empty import block, the
        // method-offsets block, and the empty export block at the tail.
        let cp_count_off = n - TRAILING_BLOCKS_AFTER_CP - 12 - 2;
        // Truncate to: cp_count_off + cp_count(2) + 1 entry(4) -- 2
        // entries short. The parser must refuse to read past the
        // buffer when cp_count promises 3 entries but only 1 fits.
        let truncated_len = cp_count_off + 2 + 4;

        let mut pkg2 = Package::empty();
        assert!(
            !pkg2.restore_state(&snap[..truncated_len]),
            "restore must reject truncated CP entries"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn package_snapshot_roundtrip_with_applets() {
        // Snapshot a Package whose applets section has both a present
        // and an absent slot (count < MAX_APPLETS_PER_PACKAGE) so the
        // restore path exercises both branches.
        let pkg_aid = [0xA0, 0x00, 0x00, 0x00, 0x62];
        let mut pkg = Package::empty();
        pkg.aid_len = pkg_aid.len() as u8;
        pkg.aid[..pkg_aid.len()].copy_from_slice(&pkg_aid);
        let mut a1 = AppletInfo::empty();
        a1.aid[..3].copy_from_slice(&[0xA0, 0x11, 0x22]);
        a1.aid_len = 3;
        a1.install_method_offset = 0x0123;
        let mut a2 = AppletInfo::empty();
        a2.aid[..16].copy_from_slice(&[0xCC; 16]);
        a2.aid_len = 16;
        a2.install_method_offset = 0xBEEF;
        pkg.applets[0] = Some(a1);
        pkg.applets[1] = Some(a2);
        pkg.applet_count = 2;

        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        assert!(n > 0);

        let mut pkg2 = Package::empty();
        assert!(pkg2.restore_state(&snap[..n]));
        assert_eq!(pkg2.applet_count, 2);
        assert_eq!(pkg2.applets[0], Some(a1));
        assert_eq!(pkg2.applets[1], Some(a2));
        assert_eq!(pkg2.applets[2], None);
    }

    #[test]
    fn restore_rejects_snapshot_with_applet_count_over_max() {
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        let off = applet_count_offset_when_empty(n);
        #[allow(clippy::cast_possible_truncation)]
        let bad = (MAX_APPLETS_PER_PACKAGE as u8) + 1;
        snap[off] = bad;

        let mut pkg2 = Package::empty();
        assert!(
            !pkg2.restore_state(&snap[..n]),
            "restore must reject applet_count > MAX_APPLETS_PER_PACKAGE"
        );
    }

    #[test]
    fn old_snapshot_without_applet_block_restores_to_empty_applets() {
        // Forward compat: snapshots saved before the applet/import/
        // offsets/export blocks existed end after the CP block.
        // Restore must accept the truncated form and surface zeros
        // for everything beyond the CP.
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        let truncated = &snap[..n - TRAILING_BLOCKS_AFTER_CP];

        let mut pkg2 = Package::empty();
        // Pre-populate to make the assertion meaningful.
        pkg2.applet_count = 7;
        pkg2.import_count = 9;
        pkg2.export_count = 3;
        pkg2.method_offsets[0] = 0xBEEF;
        pkg2.ref_loc_byte_count = 5;
        pkg2.ref_loc_byte2_count = 7;
        assert!(pkg2.restore_state(truncated));
        assert_eq!(pkg2.applet_count, 0);
        assert_eq!(pkg2.import_count, 0);
        assert_eq!(pkg2.export_count, 0);
        assert_eq!(pkg2.method_offsets[0], 0);
        assert_eq!(pkg2.ref_loc_byte_count, 0);
        assert_eq!(pkg2.ref_loc_byte2_count, 0);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn package_snapshot_roundtrip_with_imports() {
        // Snapshot a Package with two imports of distinct
        // versions/AIDs and verify they round-trip byte-for-byte.
        let mut pkg = Package::empty();
        pkg.aid_len = 5;
        pkg.aid[..5].copy_from_slice(&[0xA0, 0, 0, 0, 0x62]);
        let mut i1 = ImportInfo::empty();
        i1.aid[..7].copy_from_slice(&[0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01]);
        i1.aid_len = 7;
        i1.minor_version = 0x05;
        i1.major_version = 0x01;
        let mut i2 = ImportInfo::empty();
        i2.aid[..16].copy_from_slice(&[0xCC; 16]);
        i2.aid_len = 16;
        i2.minor_version = 0xAB;
        i2.major_version = 0xCD;
        pkg.imports[0] = Some(i1);
        pkg.imports[1] = Some(i2);
        pkg.import_count = 2;

        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        assert!(n > 0);

        let mut pkg2 = Package::empty();
        assert!(pkg2.restore_state(&snap[..n]));
        assert_eq!(pkg2.import_count, 2);
        assert_eq!(pkg2.imports[0], Some(i1));
        assert_eq!(pkg2.imports[1], Some(i2));
        assert_eq!(pkg2.imports[2], None);
    }

    #[test]
    fn restore_rejects_snapshot_with_import_count_over_max() {
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        let off = import_count_offset_when_empty(n);
        #[allow(clippy::cast_possible_truncation)]
        let bad = (MAX_IMPORTS_PER_PACKAGE as u8) + 1;
        snap[off] = bad;

        let mut pkg2 = Package::empty();
        assert!(
            !pkg2.restore_state(&snap[..n]),
            "restore must reject import_count > MAX_IMPORTS_PER_PACKAGE"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn package_snapshot_roundtrip_with_exports() {
        // Snapshot a Package with two exported classes (one fields-only,
        // one methods-only) and verify they round-trip byte-for-byte.
        let mut pkg = Package::empty();
        pkg.aid_len = 5;
        pkg.aid[..5].copy_from_slice(&[0xA0, 0, 0, 0, 0x62]);
        let mut e0 = ExportInfo::empty();
        e0.class_offset = 0x1234;
        e0.static_field_count = 2;
        e0.static_field_offsets[0] = 0x10;
        e0.static_field_offsets[1] = 0x20;
        let mut e1 = ExportInfo::empty();
        e1.class_offset = 0x5678;
        e1.static_method_count = 3;
        e1.static_method_offsets[0] = 0x100;
        e1.static_method_offsets[1] = 0x200;
        e1.static_method_offsets[2] = 0x300;
        pkg.exports[0] = Some(e0);
        pkg.exports[1] = Some(e1);
        pkg.export_count = 2;

        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        assert!(n > 0);

        let mut pkg2 = Package::empty();
        assert!(pkg2.restore_state(&snap[..n]));
        assert_eq!(pkg2.export_count, 2);
        assert_eq!(pkg2.exports[0], Some(e0));
        assert_eq!(pkg2.exports[1], Some(e1));
        assert_eq!(pkg2.exports[2], None);
    }

    #[test]
    fn restore_rejects_snapshot_with_export_count_over_max() {
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        // export_count is the first byte of the export block; the
        // ref-loc block follows it at the tail.
        let off = n - REF_LOC_BLOCK_SIZE - EXPORT_BLOCK_SIZE;
        #[allow(clippy::cast_possible_truncation)]
        let bad = (MAX_EXPORTED_CLASSES_PER_PACKAGE as u8) + 1;
        snap[off] = bad;

        let mut pkg2 = Package::empty();
        assert!(
            !pkg2.restore_state(&snap[..n]),
            "restore must reject export_count > MAX_EXPORTED_CLASSES_PER_PACKAGE"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn package_snapshot_roundtrip_with_ref_loc_deltas() {
        // Snapshot adversarial ref-loc deltas (including 0xFF
        // continuation bytes) and verify they round-trip byte-for-byte.
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        pkg.ref_loc_byte_deltas[0] = 0x10;
        pkg.ref_loc_byte_deltas[1] = 0xFF;
        pkg.ref_loc_byte_deltas[2] = 0x05;
        pkg.ref_loc_byte_count = 3;
        pkg.ref_loc_byte2_deltas[0] = 0x21;
        pkg.ref_loc_byte2_deltas[1] = 0xFE;
        pkg.ref_loc_byte2_count = 2;

        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        assert!(n > 0);

        let mut pkg2 = Package::empty();
        assert!(pkg2.restore_state(&snap[..n]));
        assert_eq!(pkg2.ref_loc_byte_count, 3);
        assert_eq!(pkg2.ref_loc_byte_deltas(), &[0x10, 0xFF, 0x05]);
        assert_eq!(pkg2.ref_loc_byte2_count, 2);
        assert_eq!(pkg2.ref_loc_byte2_deltas(), &[0x21, 0xFE]);
    }

    #[test]
    fn restore_rejects_snapshot_with_ref_loc_byte_count_over_max() {
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        // ref_loc_byte_count is the first u16 of the ref-loc block.
        let off = n - REF_LOC_BLOCK_SIZE;
        #[allow(clippy::cast_possible_truncation)]
        let bad = (MAX_REF_LOC_BYTE_INDICES as u16) + 1;
        snap[off..off + 2].copy_from_slice(&bad.to_le_bytes());

        let mut pkg2 = Package::empty();
        assert!(
            !pkg2.restore_state(&snap[..n]),
            "restore must reject ref_loc_byte_count > MAX_REF_LOC_BYTE_INDICES"
        );
    }

    #[test]
    fn old_snapshot_without_export_block_restores_to_empty_exports() {
        // Forward compat: drop both ref-loc and export blocks to
        // simulate a snapshot saved before either existed.
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        let truncated = &snap[..n - REF_LOC_BLOCK_SIZE - EXPORT_BLOCK_SIZE];

        let mut pkg2 = Package::empty();
        pkg2.export_count = 7;
        pkg2.ref_loc_byte_count = 5;
        assert!(pkg2.restore_state(truncated));
        assert_eq!(pkg2.export_count, 0);
        assert_eq!(pkg2.ref_loc_byte_count, 0);
    }

    #[test]
    fn old_snapshot_without_import_block_restores_to_empty_imports() {
        // A snapshot ending right after the applet block predates
        // the import / method-offsets / export / ref-loc blocks;
        // restore must accept and zero each of them.
        let mut pkg = Package::empty();
        pkg.aid_len = 1;
        pkg.aid[0] = 0xAA;
        let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
        let n = pkg.save_state(&mut snap);
        let truncated = &snap[..n
            - REF_LOC_BLOCK_SIZE
            - EXPORT_BLOCK_SIZE
            - METHOD_OFFSETS_BLOCK_SIZE
            - IMPORT_BLOCK_SIZE];

        let mut pkg2 = Package::empty();
        pkg2.import_count = 7;
        pkg2.export_count = 9;
        pkg2.method_offsets[1] = 0xCAFE;
        pkg2.ref_loc_byte_count = 5;
        assert!(pkg2.restore_state(truncated));
        assert_eq!(pkg2.import_count, 0);
        assert_eq!(pkg2.export_count, 0);
        assert_eq!(pkg2.method_offsets[1], 0);
        assert_eq!(pkg2.ref_loc_byte_count, 0);
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
