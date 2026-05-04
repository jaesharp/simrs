//! Standard component-tagged CAP file parser per JCVM 3.2 Chapter 6.
//!
//! Real Oracle-converter CAP files are a sequence of tag+length+body
//! triples. This module decodes them and extracts the same
//! [`Package`] structure that [`super::parse_cap`] (the simplified
//! blob parser) produces, so downstream callers (the JCVM
//! interpreter, the registry) don't need to care which format the
//! source bytes were in.
//!
//! # Components
//!
//! Per JCVM 3.2 Section 6.1, a CAP file is a concatenation of
//! components. Each component has the layout:
//!
//! ```text
//! tag:  u8     -- one of the constants in [`tag`]
//! size: u16 BE -- size of `info` (excludes tag and size bytes)
//! info: [u8; size]
//! ```
//!
//! The components must appear in the spec-defined order. This MVP
//! parser extracts:
//!
//! - **Header** (tag 1): magic + package AID.
//! - **Directory** (tag 2): component sizes (currently informational
//!   only -- the parser uses the per-component size header for
//!   advance, not the directory's table).
//! - **Method** (tag 7): per-method bytecodes.
//!
//! Other components (`Applet`, `Import`, `ConstantPool`, `Class`,
//! `StaticField`, `RefLocation`, `Export`, `Descriptor`, `Debug`,
//! `StaticResources`) are recognised but skipped. Token-based
//! linking via `ConstantPool` resolution is a follow-up.
//!
//! # Format detection
//!
//! [`super::parse_cap`] dispatches between this parser and the
//! simplified blob parser by looking at the first byte: `0x01`
//! (Header tag) selects the component-tagged format; `0xDE` (start
//! of `0xDECAFFED`) selects the simplified blob.

use super::{
    AppletInfo, CAP_MAGIC, ClassInfo, CpInfo, ExportInfo, ImportInfo, MAX_AID_LEN,
    MAX_APPLETS_PER_PACKAGE, MAX_BYTECODE, MAX_CLASSES_PER_PACKAGE, MAX_CP_ENTRIES,
    MAX_EXPORTED_CLASSES_PER_PACKAGE, MAX_EXPORTED_FIELDS_PER_CLASS,
    MAX_EXPORTED_METHODS_PER_CLASS, MAX_IMPORTS_PER_PACKAGE, MAX_METHODS, MAX_REF_LOC_BYTE_INDICES,
    MAX_REF_LOC_BYTE2_INDICES, MethodInfo, Package, ParseError, cp_tag,
};

/// Component tag constants per JCVM 3.2 Section 6.2.
pub mod tag {
    /// Header component (always tag 1, always first).
    pub const HEADER: u8 = 1;
    /// Directory component.
    pub const DIRECTORY: u8 = 2;
    /// Applet component.
    pub const APPLET: u8 = 3;
    /// Import component.
    pub const IMPORT: u8 = 4;
    /// Constant Pool component.
    pub const CONSTANT_POOL: u8 = 5;
    /// Class component.
    pub const CLASS: u8 = 6;
    /// Method component.
    pub const METHOD: u8 = 7;
    /// Static Field component.
    pub const STATIC_FIELD: u8 = 8;
    /// Reference Location component.
    pub const REFERENCE_LOCATION: u8 = 9;
    /// Export component.
    pub const EXPORT: u8 = 10;
    /// Descriptor component.
    pub const DESCRIPTOR: u8 = 11;
    /// Debug component (optional).
    pub const DEBUG: u8 = 12;
    /// Static Resources component (JC 3.0.5+).
    pub const STATIC_RESOURCES: u8 = 13;
}

/// Method header flag bits per JCVM 3.2 § 6.10.1.
mod method_flags {
    /// Extended header format (used when `max_stack`/`nargs`/`max_locals`
    /// don't fit in the compact nibble layout).
    pub const EXTENDED: u8 = 0x08;
    /// Compact-header `nargs` mask.
    pub const COMPACT_NARGS_MASK: u8 = 0x0F;
}

/// Read a `u32` big-endian, advancing `pos`.
fn read_u32_be(data: &[u8], pos: &mut usize) -> Result<u32, ParseError> {
    if data.len() < *pos + 4 {
        return Err(ParseError::TooShort);
    }
    let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

/// Parse the Header component body and extract the package AID.
///
/// Layout per JCVM 3.2 § 6.3:
/// ```text
/// magic           u32 BE    -- always 0xDECAFFED
/// minor_version   u8        -- CAP minor version
/// major_version   u8        -- CAP major version
/// flags           u8        -- bit 0 = has applet, bit 1 = extended,
///                              bit 2 = has package_name (3.0+)
/// package_info:
///   minor_version u8
///   major_version u8
///   aid_length    u8
///   aid           [u8; aid_length]
/// (optional) package_name: name_length u8 + name bytes
/// ```
///
/// Returns `(aid, aid_len)`.
fn parse_header(body: &[u8]) -> Result<([u8; MAX_AID_LEN], u8), ParseError> {
    let mut pos = 0;

    let magic = read_u32_be(body, &mut pos)?;
    if magic != CAP_MAGIC {
        return Err(ParseError::BadMagic);
    }

    // Skip minor/major version + flags (3 bytes).
    if body.len() < pos + 3 {
        return Err(ParseError::TooShort);
    }
    pos += 3;

    // package_info: minor (1) + major (1) + aid_length (1).
    if body.len() < pos + 3 {
        return Err(ParseError::TooShort);
    }
    pos += 2; // package version
    let aid_len = body[pos];
    pos += 1;
    if aid_len as usize > MAX_AID_LEN {
        return Err(ParseError::AidTooLong);
    }
    if body.len() < pos + aid_len as usize {
        return Err(ParseError::TooShort);
    }
    let mut aid = [0u8; MAX_AID_LEN];
    aid[..aid_len as usize].copy_from_slice(&body[pos..pos + aid_len as usize]);
    Ok((aid, aid_len))
}

/// Parse the Method component body and extract bytecodes.
///
/// Layout per JCVM 3.2 § 6.10:
/// ```text
/// handler_count    u8
/// handlers         [exception_handler_info; handler_count]  -- 8 bytes each
/// methods          method_info[]  -- variable; ends at body end
/// ```
///
/// Each `method_info` is one of:
/// ```text
/// // compact (flags bit 3 == 0):
///   flags + max_stack: u8 (high nibble = flags, low nibble = max_stack)
///   nargs + max_locals: u8 (high = nargs, low = max_locals)
///   bytecodes: variable
///
/// // extended (flags bit 3 == 1):
///   flags: u8
///   max_stack: u8
///   nargs: u8
///   max_locals: u8
///   bytecodes: variable
/// ```
///
/// Method bytecode boundaries inside the component are determined by
/// the surrounding components (Class, Descriptor) -- the Method
/// component itself doesn't say how long each method's bytecode is.
/// MVP behaviour: drive the boundaries from a slice of method offsets
/// plus lengths derived from the Descriptor or Class component. When
/// neither is supplied, the parser falls back to treating the entire
/// post-handler region as a single method so callers can at least
/// extract a single-method package.
///
/// `method_offsets` is a slice of `(offset, bytecode_count)` pairs
/// covering the methods in this component; offsets are relative to the
/// start of the Method component body and point at the start of each
/// `method_info` header. `bytecode_count` is the bytecode length only
/// (excludes the 2- or 4-byte header). When empty, the parser
/// extracts a single method spanning the whole post-handler-table
/// region.
/// Decoded methods plus their per-method offsets within the Method
/// component body (parallel arrays indexed by method index).
type ParsedMethods = ([Option<MethodInfo>; MAX_METHODS], [u16; MAX_METHODS], u8);

#[allow(clippy::cast_possible_truncation)]
fn parse_methods(body: &[u8], method_offsets: &[(u16, u16)]) -> Result<ParsedMethods, ParseError> {
    if body.is_empty() {
        return Err(ParseError::TooShort);
    }
    let handler_count = body[0] as usize;
    // Each handler is 8 bytes: start_offset(2) end_offset(2)
    // handler_offset(2) catch_type_index(2). Skip over them; this MVP
    // doesn't surface them through the simplified `Package` struct.
    let methods_start = 1 + handler_count * 8;
    if body.len() < methods_start {
        return Err(ParseError::TooShort);
    }

    let mut methods: [Option<MethodInfo>; MAX_METHODS] = [None; MAX_METHODS];
    let mut offsets: [u16; MAX_METHODS] = [0u16; MAX_METHODS];
    let mut count: u8 = 0;

    if method_offsets.is_empty() {
        // Fallback: treat the whole post-handler region as a single
        // method. Bytecodes run to the end of the body. Without a
        // Descriptor we can't pin down the exact offset, so leave
        // `offsets[0]` at 0 -- callers using the resolver will get
        // None for any non-zero query, which is the right answer.
        let m = parse_one_method(&body[methods_start..])?;
        methods[0] = Some(m);
        count = 1;
        return Ok((methods, offsets, count));
    }

    for &(offset, bytecode_count) in method_offsets {
        if count as usize >= MAX_METHODS {
            return Err(ParseError::TooManyMethods);
        }
        let start = offset as usize;
        if start >= body.len() {
            return Err(ParseError::TooShort);
        }
        // Header size depends on the EXTENDED bit of the first byte.
        let header_size = if body[start] & method_flags::EXTENDED != 0 {
            4
        } else {
            2
        };
        let end = start
            .checked_add(header_size)
            .and_then(|h| h.checked_add(bytecode_count as usize))
            .ok_or(ParseError::TooShort)?;
        if end > body.len() {
            return Err(ParseError::TooShort);
        }
        let m = parse_one_method(&body[start..end])?;
        methods[count as usize] = Some(m);
        offsets[count as usize] = offset;
        count += 1;
    }
    Ok((methods, offsets, count))
}

/// Parse a single `method_info` whose bytecode spans the rest of `slice`.
fn parse_one_method(slice: &[u8]) -> Result<MethodInfo, ParseError> {
    if slice.is_empty() {
        return Err(ParseError::TooShort);
    }
    let header_byte = slice[0];
    let extended = header_byte & method_flags::EXTENDED != 0;

    let (flags, max_stack, nargs, max_locals, header_len) = if extended {
        // Extended: flags / max_stack / nargs / max_locals each their own byte.
        if slice.len() < 4 {
            return Err(ParseError::TooShort);
        }
        (slice[0], slice[1], slice[2], slice[3], 4usize)
    } else {
        // Compact: header_byte high nibble = flags, low nibble = max_stack.
        // Next byte high nibble = nargs, low nibble = max_locals.
        if slice.len() < 2 {
            return Err(ParseError::TooShort);
        }
        let flags = (header_byte >> 4) & method_flags::COMPACT_NARGS_MASK;
        let max_stack = header_byte & method_flags::COMPACT_NARGS_MASK;
        let nargs = (slice[1] >> 4) & method_flags::COMPACT_NARGS_MASK;
        let max_locals = slice[1] & method_flags::COMPACT_NARGS_MASK;
        (flags, max_stack, nargs, max_locals, 2usize)
    };

    let bytecode_slice = &slice[header_len..];
    if bytecode_slice.len() > MAX_BYTECODE {
        return Err(ParseError::BytecodeTooLong);
    }
    let mut bytecode = [0u8; MAX_BYTECODE];
    bytecode[..bytecode_slice.len()].copy_from_slice(bytecode_slice);

    // bytecode_slice.len() is bounded by MAX_BYTECODE (256) above, so
    // the cast is provably non-truncating.
    #[allow(clippy::cast_possible_truncation)]
    let bytecode_len = bytecode_slice.len() as u16;
    Ok(MethodInfo {
        flags,
        max_stack,
        nargs,
        max_locals,
        bytecode,
        bytecode_len,
        exception_table: [None; super::MAX_EXCEPTIONS],
        descriptor_offset: 0,
        class_offset: 0,
    })
}

/// Parse the Descriptor component body and extract `(method_offset,
/// bytecode_count)` pairs in declaration order.
///
/// Layout per JCVM 3.2 § 6.14 (simplified to what we need):
/// ```text
/// class_count: u8
/// for each class:
///   token: u8
///   access_flags: u8
///   class_ref: u16 BE
///   interface_count: u8
///   field_count: u16 BE
///   method_count: u16 BE
///   interfaces: [u16; interface_count]
///   field descriptors: field_count entries (variable)
///   method descriptors: method_count entries (12 bytes each in our writer's shape)
/// type_descriptor_count: u16 BE
/// type_descriptors: [u8]
/// ```
///
/// Returns the list of `(method_offset_in_method_component,
/// bytecode_count)` pairs collected across all classes in declaration
/// order. The MVP assumes the writer's shape (single class, fixed
/// descriptor sizes, primitive fields) -- a full Descriptor parser is
/// a follow-up.
#[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
fn parse_descriptor_method_offsets(
    body: &[u8],
) -> Result<([(u16, u16); MAX_METHODS], u8), ParseError> {
    let mut pos = 0;
    if body.is_empty() {
        return Err(ParseError::TooShort);
    }
    let class_count = body[pos] as usize;
    pos += 1;

    let mut offsets: [(u16, u16); MAX_METHODS] = [(0, 0); MAX_METHODS];
    let mut total: u8 = 0;

    for _ in 0..class_count {
        // class descriptor header: token(1) + access_flags(1) +
        // class_ref(2) + interface_count(1) + field_count(2) +
        // method_count(2) = 9 bytes.
        if body.len() < pos + 9 {
            return Err(ParseError::TooShort);
        }
        let interface_count = body[pos + 4] as usize;
        let field_count = u16::from_be_bytes([body[pos + 5], body[pos + 6]]) as usize;
        let method_count = u16::from_be_bytes([body[pos + 7], body[pos + 8]]) as usize;
        pos += 9;

        // Skip interfaces: u16 each.
        if body.len() < pos + interface_count * 2 {
            return Err(ParseError::TooShort);
        }
        pos += interface_count * 2;

        // Skip field descriptors: 5 bytes each (token + access + ref(2) + type)
        // per the writer's shape.
        if body.len() < pos + field_count * 5 {
            return Err(ParseError::TooShort);
        }
        pos += field_count * 5;

        // Method descriptors: 12 bytes each in writer-shape.
        // token(1) + access(1) + method_offset(2) + type_offset(2) +
        // bytecode_count(2) + handler_count(2) + handler_index(2)
        for _ in 0..method_count {
            if total as usize >= MAX_METHODS {
                return Err(ParseError::TooManyMethods);
            }
            if body.len() < pos + 12 {
                return Err(ParseError::TooShort);
            }
            // Skip token + access (2 bytes).
            let method_offset = u16::from_be_bytes([body[pos + 2], body[pos + 3]]);
            // Skip type_offset (2 bytes -> at pos+4).
            let bytecode_count = u16::from_be_bytes([body[pos + 6], body[pos + 7]]);
            offsets[total as usize] = (method_offset, bytecode_count);
            total += 1;
            pos += 12;
        }
    }
    Ok((offsets, total))
}

/// Parse the Class component body (JCVM 3.2 § 6.9).
///
/// MVP scope: walks `class_info` records (top bit of bitfield clear),
/// surfacing the fixed 10-byte header and tracking each one's
/// component-relative offset for CP `Classref::Internal(offset)`
/// resolution. Variable-size sub-fields (virtual method tables and
/// `implemented_interfaces[]`) are walked-and-skipped during parse
/// but not stored on `Package`.
///
/// Rejects:
/// - Records with `ACC_INTERFACE` (bitfield bit 7) set: that's an
///   `interface_info` per JCVM 3.2 § 6.9.3, which the MVP doesn't
///   yet decode -> `ClassInterfaceNotSupported`.
/// - More than `MAX_CLASSES_PER_PACKAGE` classes -> `TooManyClasses`.
/// - Truncated bodies at any point -> `TooShort`.
fn parse_class_component(
    body: &[u8],
) -> Result<([Option<ClassInfo>; MAX_CLASSES_PER_PACKAGE], u8), ParseError> {
    let mut pos = 0usize;
    let mut classes: [Option<ClassInfo>; MAX_CLASSES_PER_PACKAGE] = [None; MAX_CLASSES_PER_PACKAGE];
    let mut count: u8 = 0;

    while pos < body.len() {
        if (count as usize) >= MAX_CLASSES_PER_PACKAGE {
            return Err(ParseError::TooManyClasses);
        }
        // bitfield(1) + super_class_ref(2) + 7 fixed bytes = 10 bytes.
        if body.len() < pos + 10 {
            return Err(ParseError::TooShort);
        }
        let component_offset = {
            #[allow(clippy::cast_possible_truncation)]
            let v = pos as u16;
            v
        };
        let bitfield = body[pos];
        if bitfield & 0x80 != 0 {
            return Err(ParseError::ClassInterfaceNotSupported);
        }
        let interface_count = bitfield & 0x0F;
        let super_class_ref = super::decode_class_ref_3([body[pos + 1], body[pos + 2], 0]);
        let declared_instance_size = body[pos + 3];
        let first_reference_token = body[pos + 4];
        let reference_count = body[pos + 5];
        let public_method_table_base = body[pos + 6];
        let public_method_table_count = body[pos + 7];
        let package_method_table_base = body[pos + 8];
        let package_method_table_count = body[pos + 9];
        pos += 10;

        // Walk past public_virtual_method_table[public_count] (u16 each).
        let pub_table_bytes = (public_method_table_count as usize) * 2;
        if body.len() < pos + pub_table_bytes {
            return Err(ParseError::TooShort);
        }
        pos += pub_table_bytes;

        // Walk past package_virtual_method_table[package_count] (u16 each).
        let pkg_table_bytes = (package_method_table_count as usize) * 2;
        if body.len() < pos + pkg_table_bytes {
            return Err(ParseError::TooShort);
        }
        pos += pkg_table_bytes;

        // Walk past implemented_interfaces[interface_count]:
        // each is class_ref(2) + count(1) + indices[count] (variable).
        for _ in 0..interface_count {
            if body.len() < pos + 3 {
                return Err(ParseError::TooShort);
            }
            let inner_count = body[pos + 2] as usize;
            let advance = 3 + inner_count;
            if body.len() < pos + advance {
                return Err(ParseError::TooShort);
            }
            pos += advance;
        }

        classes[count as usize] = Some(ClassInfo {
            component_offset,
            super_class_ref,
            declared_instance_size,
            first_reference_token,
            reference_count,
            public_method_table_base,
            public_method_table_count,
            package_method_table_base,
            package_method_table_count,
            interface_count,
        });
        count += 1;
    }

    Ok((classes, count))
}

/// Parse the `StaticField` component body (JCVM 3.2 § 6.10).
///
/// Layout:
/// ```text
/// image_size:           u2 BE
/// reference_count:      u2 BE
/// array_init_count:     u2 BE
/// array_init[]:         variable, count entries
/// default_value_count:  u2 BE
/// non_default_values[]: u1 * default_value_count
/// ```
///
/// MVP behaviour: surfaces only `image_size` + `reference_count`.
/// Rejects packages that declare any `array_init[]` entries or any
/// `non_default_values[]` -- their semantics belong to the static-
/// field allocator, which doesn't yet exist on this runtime, and
/// silently dropping them would mis-initialise static state.
fn parse_static_field_component(body: &[u8]) -> Result<(u16, u16), ParseError> {
    if body.len() < 8 {
        return Err(ParseError::TooShort);
    }
    let image_size = u16::from_be_bytes([body[0], body[1]]);
    let reference_count = u16::from_be_bytes([body[2], body[3]]);
    let array_init_count = u16::from_be_bytes([body[4], body[5]]);
    if array_init_count != 0 {
        return Err(ParseError::StaticFieldArrayInitsUnsupported);
    }
    let default_value_count = u16::from_be_bytes([body[6], body[7]]);
    if default_value_count != 0 {
        return Err(ParseError::StaticFieldNonDefaultValuesUnsupported);
    }
    Ok((image_size, reference_count))
}

/// Parse the Reference Location component body (JCVM 3.2 § 6.12).
///
/// Layout:
/// ```text
/// byte_index_count:           u2 BE
/// offsets_to_byte_indices:    u1 * byte_index_count
/// byte2_index_count:          u2 BE
/// offsets_to_byte2_indices:   u1 * byte2_index_count
/// ```
///
/// Stored as raw delta bytes; consumers (the future token-patch
/// pass) reconstruct absolute offsets by accumulating deltas, with
/// the spec-defined `0xFF` continuation byte meaning "advance 254
/// without emitting a patch site here".
///
/// Rejects:
/// - 1-byte index count > `MAX_REF_LOC_BYTE_INDICES` -> `TooManyRefLocByteIndices`
/// - 2-byte index count > `MAX_REF_LOC_BYTE2_INDICES` -> `TooManyRefLocByte2Indices`
#[allow(clippy::similar_names)] // narrow_count vs wide_count would mislead.
fn parse_ref_location_component(
    body: &[u8],
) -> Result<
    (
        [u8; MAX_REF_LOC_BYTE_INDICES],
        u16,
        [u8; MAX_REF_LOC_BYTE2_INDICES],
        u16,
    ),
    ParseError,
> {
    let mut pos = 0usize;
    if body.len() < pos + 2 {
        return Err(ParseError::TooShort);
    }
    let byte_count = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 2;
    if byte_count as usize > MAX_REF_LOC_BYTE_INDICES {
        return Err(ParseError::TooManyRefLocByteIndices);
    }
    if body.len() < pos + byte_count as usize {
        return Err(ParseError::TooShort);
    }
    let mut byte_deltas = [0u8; MAX_REF_LOC_BYTE_INDICES];
    byte_deltas[..byte_count as usize].copy_from_slice(&body[pos..pos + byte_count as usize]);
    pos += byte_count as usize;

    if body.len() < pos + 2 {
        return Err(ParseError::TooShort);
    }
    let byte2_count = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 2;
    if byte2_count as usize > MAX_REF_LOC_BYTE2_INDICES {
        return Err(ParseError::TooManyRefLocByte2Indices);
    }
    if body.len() < pos + byte2_count as usize {
        return Err(ParseError::TooShort);
    }
    let mut byte2_deltas = [0u8; MAX_REF_LOC_BYTE2_INDICES];
    byte2_deltas[..byte2_count as usize].copy_from_slice(&body[pos..pos + byte2_count as usize]);

    Ok((byte_deltas, byte_count, byte2_deltas, byte2_count))
}

/// Parse the Export component body (JCVM 3.2 § 6.13).
///
/// Layout:
/// ```text
/// class_count: u8
/// classes[class_count]:
///   class_offset:           u2 BE
///   static_field_count:     u1
///   static_method_count:    u1
///   static_field_offsets:   u2 BE * static_field_count
///   static_method_offsets:  u2 BE * static_method_count
/// ```
///
/// Rejects:
/// - `class_count > MAX_EXPORTED_CLASSES_PER_PACKAGE` -> `TooManyExportedClasses`
/// - `static_field_count > MAX_EXPORTED_FIELDS_PER_CLASS` -> `TooManyExportedFields`
/// - `static_method_count > MAX_EXPORTED_METHODS_PER_CLASS` -> `TooManyExportedMethods`
fn parse_export_component(
    body: &[u8],
) -> Result<([Option<ExportInfo>; MAX_EXPORTED_CLASSES_PER_PACKAGE], u8), ParseError> {
    if body.is_empty() {
        return Err(ParseError::TooShort);
    }
    let class_count = body[0] as usize;
    if class_count > MAX_EXPORTED_CLASSES_PER_PACKAGE {
        return Err(ParseError::TooManyExportedClasses);
    }
    let mut pos = 1usize;
    let mut exports: [Option<ExportInfo>; MAX_EXPORTED_CLASSES_PER_PACKAGE] =
        [None; MAX_EXPORTED_CLASSES_PER_PACKAGE];
    for slot in exports.iter_mut().take(class_count) {
        if pos + 4 > body.len() {
            return Err(ParseError::TooShort);
        }
        let class_offset = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let static_field_count = body[pos + 2];
        let static_method_count = body[pos + 3];
        pos += 4;
        if static_field_count as usize > MAX_EXPORTED_FIELDS_PER_CLASS {
            return Err(ParseError::TooManyExportedFields);
        }
        if static_method_count as usize > MAX_EXPORTED_METHODS_PER_CLASS {
            return Err(ParseError::TooManyExportedMethods);
        }
        let total_offsets = (static_field_count as usize + static_method_count as usize) * 2;
        if pos + total_offsets > body.len() {
            return Err(ParseError::TooShort);
        }
        let mut static_field_offsets = [0u16; MAX_EXPORTED_FIELDS_PER_CLASS];
        for f in static_field_offsets
            .iter_mut()
            .take(static_field_count as usize)
        {
            *f = u16::from_be_bytes([body[pos], body[pos + 1]]);
            pos += 2;
        }
        let mut static_method_offsets = [0u16; MAX_EXPORTED_METHODS_PER_CLASS];
        for m in static_method_offsets
            .iter_mut()
            .take(static_method_count as usize)
        {
            *m = u16::from_be_bytes([body[pos], body[pos + 1]]);
            pos += 2;
        }
        *slot = Some(ExportInfo {
            class_offset,
            static_field_count,
            static_method_count,
            static_field_offsets,
            static_method_offsets,
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let count_u8 = class_count as u8;
    Ok((exports, count_u8))
}

/// Parse the Import component body (JCVM 3.2 § 6.7).
///
/// Layout:
/// ```text
/// count: u8
/// packages[count]:
///   minor_version: u8
///   major_version: u8
///   aid_length:    u8
///   aid:           u8[aid_length]
/// ```
///
/// Rejects:
/// - `count > MAX_IMPORTS_PER_PACKAGE` -> `TooManyImports`
/// - `aid_length > MAX_AID_LEN`        -> `AidTooLong`
fn parse_import_component(
    body: &[u8],
) -> Result<([Option<ImportInfo>; MAX_IMPORTS_PER_PACKAGE], u8), ParseError> {
    if body.is_empty() {
        return Err(ParseError::TooShort);
    }
    let count = body[0] as usize;
    if count > MAX_IMPORTS_PER_PACKAGE {
        return Err(ParseError::TooManyImports);
    }
    let mut pos = 1usize;
    let mut imports: [Option<ImportInfo>; MAX_IMPORTS_PER_PACKAGE] =
        [None; MAX_IMPORTS_PER_PACKAGE];
    for slot in imports.iter_mut().take(count) {
        if pos + 3 > body.len() {
            return Err(ParseError::TooShort);
        }
        let minor_version = body[pos];
        let major_version = body[pos + 1];
        let aid_len = body[pos + 2];
        pos += 3;
        if aid_len as usize > MAX_AID_LEN {
            return Err(ParseError::AidTooLong);
        }
        if pos + aid_len as usize > body.len() {
            return Err(ParseError::TooShort);
        }
        let mut aid = [0u8; MAX_AID_LEN];
        aid[..aid_len as usize].copy_from_slice(&body[pos..pos + aid_len as usize]);
        pos += aid_len as usize;
        *slot = Some(ImportInfo {
            minor_version,
            major_version,
            aid,
            aid_len,
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let count_u8 = count as u8;
    Ok((imports, count_u8))
}

/// Parse the Applet component body (JCVM 3.2 § 6.5).
///
/// Layout:
/// ```text
/// count: u8
/// applets[count]:
///   aid_length:               u8
///   aid:                      u8[aid_length]
///   install_method_offset:    u16 BE
/// ```
///
/// Returns the populated applet array plus the count. Rejects:
/// - `count > MAX_APPLETS_PER_PACKAGE` -> `TooManyApplets`
/// - `aid_length` outside ISO 7816-4's `[5, 16]` range -> `AidTooLong`
///   (length 0..=4 are technically spec-rejectable but writers in
///   the wild emit them; we accept lengths up to `MAX_AID_LEN` and
///   trust the caller. Lengths above 16 are always rejected.)
fn parse_applet_component(
    body: &[u8],
) -> Result<([Option<AppletInfo>; MAX_APPLETS_PER_PACKAGE], u8), ParseError> {
    if body.is_empty() {
        return Err(ParseError::TooShort);
    }
    let count = body[0] as usize;
    if count > MAX_APPLETS_PER_PACKAGE {
        return Err(ParseError::TooManyApplets);
    }
    let mut pos = 1usize;
    let mut applets: [Option<AppletInfo>; MAX_APPLETS_PER_PACKAGE] =
        [None; MAX_APPLETS_PER_PACKAGE];
    for slot in applets.iter_mut().take(count) {
        if pos + 1 > body.len() {
            return Err(ParseError::TooShort);
        }
        let aid_len = body[pos];
        pos += 1;
        if aid_len as usize > MAX_AID_LEN {
            return Err(ParseError::AidTooLong);
        }
        if pos + aid_len as usize + 2 > body.len() {
            return Err(ParseError::TooShort);
        }
        let mut aid = [0u8; MAX_AID_LEN];
        aid[..aid_len as usize].copy_from_slice(&body[pos..pos + aid_len as usize]);
        pos += aid_len as usize;
        let install_method_offset = u16::from_be_bytes([body[pos], body[pos + 1]]);
        pos += 2;
        *slot = Some(AppletInfo {
            aid,
            aid_len,
            install_method_offset,
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let count_u8 = count as u8;
    Ok((applets, count_u8))
}

/// Parse the `ConstantPool` component body and extract entries.
///
/// Layout per JCVM 3.2 § 6.8:
/// ```text
/// count: u16 BE
/// constant_pool: cp_info[count]   -- 4 bytes per entry
///
/// cp_info {
///   tag:  u8                      -- 1=Classref, 2=InstanceFieldref,
///                                    3=VirtualMethodref, 4=SuperMethodref,
///                                    5=StaticFieldref, 6=StaticMethodref
///   info: u8[3]                   -- tag-dependent layout
/// }
/// ```
///
/// Unknown tags are rejected: an unfamiliar tag means a future spec
/// addition we don't model and silently ignoring it would let
/// downstream resolution mis-decode the entry.
fn parse_constant_pool(body: &[u8]) -> Result<([CpInfo; MAX_CP_ENTRIES], u16), ParseError> {
    if body.len() < 2 {
        return Err(ParseError::TooShort);
    }
    let count = u16::from_be_bytes([body[0], body[1]]);
    if count as usize > MAX_CP_ENTRIES {
        return Err(ParseError::TooManyConstantPoolEntries);
    }
    let count_usize = count as usize;
    if body.len() < 2 + count_usize * 4 {
        return Err(ParseError::TooShort);
    }
    let mut entries = [CpInfo::default(); MAX_CP_ENTRIES];
    for (i, slot) in entries.iter_mut().take(count_usize).enumerate() {
        let off = 2 + i * 4;
        let tag = body[off];
        match tag {
            cp_tag::CLASSREF
            | cp_tag::INSTANCE_FIELDREF
            | cp_tag::VIRTUAL_METHODREF
            | cp_tag::SUPER_METHODREF
            | cp_tag::STATIC_FIELDREF
            | cp_tag::STATIC_METHODREF => {}
            _ => return Err(ParseError::UnknownConstantPoolTag),
        }
        slot.tag = tag;
        slot.info.copy_from_slice(&body[off + 1..off + 4]);
    }
    Ok((entries, count))
}

/// Parse a component-tagged CAP file into the simplified [`Package`]
/// structure used by the JCVM interpreter.
///
/// # Errors
///
/// Returns [`ParseError`] if any component header is malformed or the
/// extracted Package would exceed `MAX_*` capacity bounds.
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub fn parse(data: &[u8]) -> Result<Package, ParseError> {
    let mut pos = 0;
    let mut aid = [0u8; MAX_AID_LEN];
    let mut aid_len: u8 = 0;
    let mut method_body: Option<&[u8]> = None;
    let mut descriptor_body: Option<&[u8]> = None;
    let mut constant_pool = [CpInfo::default(); MAX_CP_ENTRIES];
    let mut cp_count: u16 = 0;
    let mut applets: [Option<AppletInfo>; MAX_APPLETS_PER_PACKAGE] =
        [None; MAX_APPLETS_PER_PACKAGE];
    let mut applet_count: u8 = 0;
    let mut imports: [Option<ImportInfo>; MAX_IMPORTS_PER_PACKAGE] =
        [None; MAX_IMPORTS_PER_PACKAGE];
    let mut import_count: u8 = 0;
    let mut exports: [Option<ExportInfo>; MAX_EXPORTED_CLASSES_PER_PACKAGE] =
        [None; MAX_EXPORTED_CLASSES_PER_PACKAGE];
    let mut export_count: u8 = 0;
    let mut ref_loc_byte_deltas = [0u8; MAX_REF_LOC_BYTE_INDICES];
    let mut ref_loc_byte_count: u16 = 0;
    let mut ref_loc_byte2_deltas = [0u8; MAX_REF_LOC_BYTE2_INDICES];
    let mut ref_loc_byte2_count: u16 = 0;
    let mut static_field_image_size: u16 = 0;
    let mut static_reference_count: u16 = 0;
    let mut classes: [Option<ClassInfo>; MAX_CLASSES_PER_PACKAGE] = [None; MAX_CLASSES_PER_PACKAGE];
    let mut class_count: u8 = 0;

    while pos < data.len() {
        if data.len() < pos + 3 {
            return Err(ParseError::TooShort);
        }
        let component_tag = data[pos];
        let size = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if data.len() < pos + size {
            return Err(ParseError::TooShort);
        }
        let body = &data[pos..pos + size];
        pos += size;

        match component_tag {
            tag::HEADER => {
                let (a, n) = parse_header(body)?;
                aid = a;
                aid_len = n;
            }
            tag::METHOD => {
                method_body = Some(body);
            }
            tag::DESCRIPTOR => {
                descriptor_body = Some(body);
            }
            tag::CONSTANT_POOL => {
                let (cp, n) = parse_constant_pool(body)?;
                constant_pool = cp;
                cp_count = n;
            }
            tag::APPLET => {
                let (a, n) = parse_applet_component(body)?;
                applets = a;
                applet_count = n;
            }
            tag::IMPORT => {
                let (i, n) = parse_import_component(body)?;
                imports = i;
                import_count = n;
            }
            tag::EXPORT => {
                let (e, n) = parse_export_component(body)?;
                exports = e;
                export_count = n;
            }
            tag::REFERENCE_LOCATION => {
                let (b1, n1, b2, n2) = parse_ref_location_component(body)?;
                ref_loc_byte_deltas = b1;
                ref_loc_byte_count = n1;
                ref_loc_byte2_deltas = b2;
                ref_loc_byte2_count = n2;
            }
            tag::STATIC_FIELD => {
                let (image, refs) = parse_static_field_component(body)?;
                static_field_image_size = image;
                static_reference_count = refs;
            }
            tag::CLASS => {
                let (c, n) = parse_class_component(body)?;
                classes = c;
                class_count = n;
            }
            // Recognised-but-skipped components (Directory, Debug,
            // StaticResources) and unknown components (vendor-custom)
            // all fall through.
            _ => {}
        }
    }

    // Method component is required to materialise a Package.
    let method_body = method_body.ok_or(ParseError::TooShort)?;

    // Build the per-method offset table from the Descriptor when
    // available; without one, fall back to the "single method" shape.
    let (offsets, count) = match descriptor_body {
        Some(d) => parse_descriptor_method_offsets(d)?,
        None => ([(0, 0); MAX_METHODS], 0),
    };
    let offset_slice = &offsets[..count as usize];

    let (methods, method_offsets, method_count) = parse_methods(method_body, offset_slice)?;

    Ok(Package {
        aid,
        aid_len,
        methods,
        method_count,
        method_offsets,
        constant_pool,
        cp_count,
        applets,
        applet_count,
        imports,
        import_count,
        exports,
        export_count,
        ref_loc_byte_deltas,
        ref_loc_byte_count,
        ref_loc_byte2_deltas,
        ref_loc_byte2_count,
        static_field_image_size,
        static_reference_count,
        classes,
        class_count,
    })
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Encode a single component as `tag(1) | size(2 BE) | body`.
    fn emit(out: &mut Vec<u8>, component_tag: u8, body: &[u8]) {
        out.push(component_tag);
        #[allow(clippy::cast_possible_truncation)]
        let size = body.len() as u16;
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(body);
    }

    /// Header component body. `flags` defaults to `0x01` (has applet).
    fn header_body(aid: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&CAP_MAGIC.to_be_bytes());
        body.push(0); // CAP minor
        body.push(3); // CAP major
        body.push(0x01); // flags: has applet
        body.push(1); // package minor
        body.push(0); // package major
        #[allow(clippy::cast_possible_truncation)]
        let aid_len = aid.len() as u8;
        body.push(aid_len);
        body.extend_from_slice(aid);
        body
    }

    /// Method component body: `handler_count(0) | extended_method...`.
    /// One method per bytecode slice. The extended-header layout is
    /// `flags | max_stack | nargs | max_locals` followed by raw bytecode.
    fn method_body(methods: &[(&[u8], u8, u8, u8, u8)]) -> Vec<u8> {
        // Each tuple: (bytecode, flags, max_stack, nargs, max_locals).
        let mut body = Vec::new();
        body.push(0); // handler_count
        for (bc, flags, max_stack, nargs, max_locals) in methods {
            body.push(method_flags::EXTENDED | *flags);
            body.push(*max_stack);
            body.push(*nargs);
            body.push(*max_locals);
            body.extend_from_slice(bc);
        }
        body
    }

    /// Build a minimal Header + Method CAP. Bytecodes are passed as a
    /// list to allow multi-method parsing tests with an explicit
    /// Descriptor.
    fn build_cap(
        aid: &[u8],
        methods: &[(&[u8], u8, u8, u8, u8)],
        descriptor_body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(aid));
        emit(&mut out, tag::METHOD, &method_body(methods));
        if let Some(d) = descriptor_body {
            emit(&mut out, tag::DESCRIPTOR, d);
        }
        out
    }

    /// Compute the byte offset of method `index` inside a Method
    /// component body, given the per-method bytecode lengths. Mirrors
    /// the layout `method_body` emits.
    fn method_offset(bytecode_lens: &[usize], index: usize) -> u16 {
        // 1 byte handler_count + (4 byte extended header + bytecode) per prior method.
        let mut o = 1usize;
        for &len in &bytecode_lens[..index] {
            o += 4 + len;
        }
        #[allow(clippy::cast_possible_truncation)]
        {
            o as u16
        }
    }

    /// Build a minimal Descriptor body that matches `simrs_jacc`'s
    /// shape: one class with no fields, `methods.len()` method
    /// descriptors with the offsets/counts the parser needs.
    #[allow(clippy::cast_possible_truncation)]
    fn descriptor_body_for(bytecode_lens: &[usize]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(1); // class_count
        // class header: token(1) + access(1) + class_ref(2) +
        // interface_count(1) + field_count(2) + method_count(2)
        body.push(0); // token
        body.push(0x01); // access (PUBLIC)
        body.extend_from_slice(&0u16.to_be_bytes()); // class_ref
        body.push(0); // interface_count
        body.extend_from_slice(&0u16.to_be_bytes()); // field_count
        body.extend_from_slice(&(bytecode_lens.len() as u16).to_be_bytes());
        // No interfaces, no fields. Method descriptors:
        for (i, &len) in bytecode_lens.iter().enumerate() {
            body.push(i as u8); // token
            body.push(0x09); // access PUBLIC|STATIC
            body.extend_from_slice(&method_offset(bytecode_lens, i).to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes()); // type_offset
            body.extend_from_slice(&(len as u16).to_be_bytes()); // bytecode_count
            body.extend_from_slice(&0u16.to_be_bytes()); // handler_count
            body.extend_from_slice(&0u16.to_be_bytes()); // handler_index
        }
        // Type descriptor: count + nibble-encoded (one byte per method;
        // 0x03 = void).
        body.extend_from_slice(&(bytecode_lens.len() as u16).to_be_bytes());
        body.extend(core::iter::repeat_n(0x03u8, bytecode_lens.len()));
        body
    }

    // -----------------------------------------------------------------------
    // Single-method, no Descriptor: fallback path
    // -----------------------------------------------------------------------

    #[test]
    fn header_extracts_aid_byte_for_byte() {
        // Reality check: an arbitrary 8-byte AID must round-trip exactly.
        let aid = [0xA0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
        let cap = build_cap(&aid, &[(&[0x78][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.aid_slice(), &aid);
        assert_eq!(pkg.aid_len, 8);
    }

    #[test]
    fn header_accepts_minimum_aid_length_5() {
        // ISO 7816-4 says AIDs are 5..=16 bytes. The parser must
        // accept the lower bound.
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62];
        let cap = build_cap(&aid, &[(&[0x78][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.aid_slice(), &aid);
    }

    #[test]
    fn header_accepts_maximum_aid_length_16() {
        let aid = [0xAA; MAX_AID_LEN];
        let cap = build_cap(&aid, &[(&[0x78][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.aid_slice(), &aid);
    }

    #[test]
    fn header_rejects_aid_length_over_16() {
        // Hand-build a Header body with aid_len = 17 (over the limit).
        let mut header = Vec::new();
        header.extend_from_slice(&CAP_MAGIC.to_be_bytes());
        header.push(0); // CAP minor
        header.push(3); // CAP major
        header.push(0x01);
        header.push(1);
        header.push(0);
        header.push(17); // bogus
        header.extend_from_slice(&[0xAA; 17]);
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::AidTooLong)));
    }

    #[test]
    fn extended_method_header_reads_each_byte_independently() {
        // Adversarial: pick distinct values for every header byte so a
        // copy/paste bug between fields would mis-assign.
        let aid = [0xA0, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x12, 0x34, 0x78][..], 0x05, 7, 2, 9)], None);
        let pkg = parse(&cap).expect("parse");
        let m = pkg.method(0).expect("method 0");
        // flags carries our test bits ORed with EXTENDED.
        assert_eq!(m.flags, method_flags::EXTENDED | 0x05);
        assert_eq!(m.max_stack, 7);
        assert_eq!(m.nargs, 2);
        assert_eq!(m.max_locals, 9);
        assert_eq!(m.bytecode_len, 3);
        assert_eq!(&m.bytecode[..3], &[0x12, 0x34, 0x78]);
    }

    #[test]
    fn compact_method_header_unpacks_high_and_low_nibbles() {
        // Compact layout (low-nibble bit 3 clear, i.e. ACC_EXTENDED unset):
        //   byte 0: flags<<4 | max_stack
        //   byte 1: nargs<<4 | max_locals
        // In compact form, max_stack is restricted to 0..=7 because bit
        // 3 of byte 0 is the ACC_EXTENDED indicator. Pick distinct
        // nibble values within the valid range to detect swap bugs.
        let aid = [0xA0, 0, 0, 0, 0x62];
        let method: Vec<u8> = vec![
            0,                  // handler_count
            (0x05 << 4) | 0x07, // flags=0x05 (bits 0,2), max_stack=0x07 (max valid for compact)
            (0x03 << 4) | 0x0C, // nargs=0x03, max_locals=0x0C
            0x78,               // sreturn
        ];
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::METHOD, &method);
        let pkg = parse(&cap).expect("parse");
        let m = pkg.method(0).expect("method 0");
        assert_eq!(m.flags, 0x05, "flags came from high nibble of byte 0");
        assert_eq!(
            m.max_stack, 0x07,
            "max_stack came from low nibble of byte 0"
        );
        assert_eq!(m.nargs, 0x03, "nargs came from high nibble of byte 1");
        assert_eq!(
            m.max_locals, 0x0C,
            "max_locals came from low nibble of byte 1"
        );
        assert_eq!(m.bytecode_len, 1);
        assert_eq!(m.bytecode[0], 0x78);
    }

    #[test]
    fn compact_method_header_max_stack_8_disambiguates_to_extended() {
        // Bit 3 of byte 0 is the ACC_EXTENDED indicator. A compact
        // method that wanted max_stack=8 (which would set that bit)
        // can't be encoded in compact form -- the spec disambiguates
        // by interpreting any bit-3-set byte as extended. Verify the
        // parser follows the spec.
        let aid = [0xA0, 0, 0, 0, 0x62];
        // Byte 0 = 0x58 "looks compact" (high nibble 0x05, low nibble
        // 0x08) but its bit 3 is set, which is the ACC_EXTENDED
        // indicator. The parser MUST treat it as extended.
        let method: Vec<u8> = vec![
            0,    // handler_count
            0x58, // flags / would-be (compact flags 5, max_stack 8)
            0x07, // extended-form max_stack
            0x00, // nargs
            0x04, // max_locals
            0x78, // sreturn
        ];
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::METHOD, &method);
        let pkg = parse(&cap).expect("parse");
        let m = pkg.method(0).expect("method 0");
        // Extended interpretation: flags = 0x58 (the whole byte),
        // max_stack = 0x07, nargs = 0x00, max_locals = 0x04.
        assert_eq!(m.flags, 0x58, "extended form takes the whole byte as flags");
        assert_eq!(m.max_stack, 0x07);
        assert_eq!(m.max_locals, 0x04);
    }

    // -----------------------------------------------------------------------
    // Multi-method via Descriptor
    // -----------------------------------------------------------------------

    #[test]
    fn descriptor_drives_per_method_bytecode_split() {
        // Two methods with distinct bytecodes; the parser must walk
        // the Descriptor's offset/length pairs to slice them apart.
        // If the Descriptor is ignored, the fallback would treat both
        // as a single method's bytecode -- the per-method asserts
        // below would fail.
        let aid = [0xA0, 0, 0, 0, 0x62];
        let bc0 = [0x03u8, 0x78]; // sconst_0, sreturn
        let bc1 = [0x04u8, 0x05, 0x41, 0x78]; // sconst_1, sconst_2, sadd, sreturn
        let methods = [
            (bc0.as_slice(), 0x80, 4, 0, 1),
            (bc1.as_slice(), 0x80, 4, 0, 1),
        ];
        let lens = [bc0.len(), bc1.len()];
        let desc = descriptor_body_for(&lens);
        let cap = build_cap(&aid, &methods, Some(&desc));

        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.method_count, 2);
        let m0 = pkg.method(0).expect("method 0");
        let m1 = pkg.method(1).expect("method 1");
        assert_eq!(m0.bytecode_len as usize, bc0.len());
        assert_eq!(&m0.bytecode[..bc0.len()], &bc0);
        assert_eq!(m1.bytecode_len as usize, bc1.len());
        assert_eq!(&m1.bytecode[..bc1.len()], &bc1);
    }

    #[test]
    fn descriptor_offsets_match_handcomputed_layout() {
        // Reference validation: the helper `method_offset` mirrors the
        // writer's layout. If either drifts, multi-method parsing
        // breaks. Anchor the helper output with literal values so
        // future changes to either side fail loudly.
        let lens = [3usize, 5, 2];
        assert_eq!(
            method_offset(&lens, 0),
            1,
            "first method starts after handler_count"
        );
        assert_eq!(
            method_offset(&lens, 1),
            1 + 4 + 3,
            "skip method 0 (4 hdr + 3 bc)"
        );
        assert_eq!(method_offset(&lens, 2), 1 + (4 + 3) + (4 + 5));
    }

    // -----------------------------------------------------------------------
    // Adversarial / boundary
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_unknown_magic_in_header() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut cap = build_cap(&aid, &[(&[0x78][..], 0x80, 4, 0, 1)], None);
        // Header component starts at byte 3 (tag(1) + size(2)); magic
        // is the first 4 body bytes -> bytes 3..7.
        cap[3..7].copy_from_slice(&[0xFF; 4]);
        assert!(matches!(parse(&cap), Err(ParseError::BadMagic)));
    }

    #[test]
    fn rejects_truncated_at_every_prefix_length() {
        // Every prefix shorter than the full CAP must error, never
        // panic. Catches off-by-one and missing bounds checks.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x10u8, 0x2A, 0x78][..], 0x80, 4, 0, 1)], None);
        for n in 0..cap.len() {
            // At least one of these must error; importantly, none must
            // panic. (No `assert!` -- just exercising the path.)
            let _ = parse(&cap[..n]);
        }
    }

    #[test]
    fn empty_input_errors_fast() {
        assert!(matches!(parse(&[]), Err(ParseError::TooShort)));
    }

    #[test]
    fn missing_method_component_errors() {
        // Header alone is not enough to materialise a Package.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    #[test]
    fn unknown_component_tag_is_skipped_not_rejected() {
        // Vendor-custom components past tag 13 (StaticResources) must
        // not break parsing. Slip an unknown tag between Header and
        // Method.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, 0xFE, &[0x00, 0x01, 0x02, 0x03]); // unknown
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78][..], 0x80, 4, 0, 1)]),
        );
        let pkg = parse(&cap).expect("unknown components must be skipped");
        assert_eq!(pkg.method_count, 1);
    }

    #[test]
    fn component_size_overrun_errors() {
        // Adversarial: a component declares a size larger than the
        // remaining buffer. Must error, not panic.
        let mut cap = Vec::new();
        cap.push(tag::HEADER);
        cap.extend_from_slice(&0xFFFFu16.to_be_bytes()); // claim 64K body
        cap.extend_from_slice(&CAP_MAGIC.to_be_bytes()); // only 4 bytes of body
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    #[test]
    fn rejects_max_methods_plus_one() {
        // Boundary: MAX_METHODS+1 method descriptors must error
        // rather than overflow the fixed-size array.
        // Build a Descriptor that claims `MAX_METHODS + 1` methods.
        let mut desc = Vec::new();
        desc.push(1); // class_count
        desc.push(0);
        desc.push(0x01);
        desc.extend_from_slice(&0u16.to_be_bytes());
        desc.push(0); // interface_count
        desc.extend_from_slice(&0u16.to_be_bytes()); // field_count
        #[allow(clippy::cast_possible_truncation)]
        let m_count = (MAX_METHODS + 1) as u16;
        desc.extend_from_slice(&m_count.to_be_bytes());
        // Method descriptors: 12 bytes each, content irrelevant -- the
        // count is what triggers the boundary check.
        for _ in 0..=MAX_METHODS {
            desc.extend_from_slice(&[0u8; 12]);
        }
        // Type descriptor count + entries.
        desc.extend_from_slice(&m_count.to_be_bytes());
        desc.extend(core::iter::repeat_n(0x03u8, MAX_METHODS + 1));

        let mut cap = Vec::new();
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78][..], 0x80, 4, 0, 1)]),
        );
        emit(&mut cap, tag::DESCRIPTOR, &desc);
        assert!(matches!(parse(&cap), Err(ParseError::TooManyMethods)));
    }

    #[test]
    fn rejects_bytecode_over_max() {
        // Adversarial: one method's bytecode advertises a length
        // exceeding `MAX_BYTECODE`. Must error, not silently truncate.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let big_bc: Vec<u8> = (0..=MAX_BYTECODE)
            .map(|i| u8::try_from(i & 0xFF).expect("masked to byte"))
            .collect();
        let methods = [(big_bc.as_slice(), 0x80, 4, 0, 1)];
        let lens = [big_bc.len()];
        let desc = descriptor_body_for(&lens);
        let cap = build_cap(&aid, &methods, Some(&desc));
        assert!(matches!(parse(&cap), Err(ParseError::BytecodeTooLong)));
    }

    // -----------------------------------------------------------------------
    // End-to-end via simrs_jacc::CapWriter::write
    // -----------------------------------------------------------------------
    //
    // simrs-jacc is a downstream crate, so we can't import it here
    // without a circular dep. Instead, the equivalent end-to-end test
    // lives in `simrs-jacc/tests/compile_source.rs` (see "round-trips
    // CapWriter::write through parse_cap"). This module's tests use
    // hand-built CAPs that mirror the writer's layout.

    // -----------------------------------------------------------------------
    // Dispatcher round-trip: parse_cap auto-detects the format
    // -----------------------------------------------------------------------

    #[test]
    fn dispatcher_routes_component_tagged_to_components_parser() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        // First byte must be the Header tag (1) so the dispatcher
        // selects this parser. Anchor that invariant explicitly so a
        // future writer change can't silently break dispatch.
        assert_eq!(cap[0], tag::HEADER);
        let pkg = super::super::parse_cap(&cap).expect("parse_cap dispatch");
        assert_eq!(pkg.aid_slice(), &aid);
    }

    #[test]
    fn dispatcher_routes_simplified_blob_to_blob_parser() {
        // Simplified blob starts with `0xDECAFFED`. First byte (0xDE)
        // is not a known component tag; dispatcher must fall through
        // to the blob path.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut blob = [0u8; 64];
        let len = super::super::build_cap_blob(&aid, &[&[0x78u8][..]], &mut blob);
        assert_eq!(blob[0], 0xDE);
        let pkg = super::super::parse_cap(&blob[..len]).expect("blob via dispatch");
        assert!(pkg.aid_matches(&aid));
        assert_eq!(pkg.method_count, 1);
    }

    // -----------------------------------------------------------------------
    // ConstantPool component
    // -----------------------------------------------------------------------

    /// Build a `ConstantPool` component body. Each entry is exactly
    /// `tag(1) | info[3]`.
    #[allow(clippy::cast_possible_truncation)]
    fn cp_body(entries: &[(u8, [u8; 3])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for (tag, info) in entries {
            body.push(*tag);
            body.extend_from_slice(info);
        }
        body
    }

    /// Build a CAP with Header + Method + an explicit `ConstantPool`
    /// component, in spec-prescribed component order.
    fn build_cap_with_cp(aid: &[u8], cp_entries: &[(u8, [u8; 3])]) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(aid));
        emit(&mut out, tag::CONSTANT_POOL, &cp_body(cp_entries));
        emit(
            &mut out,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        out
    }

    #[test]
    fn empty_constant_pool_yields_zero_count() {
        // Real Oracle CAPs commonly emit `count = 0` when the applet
        // makes no cross-class references. Parser must accept and
        // surface `cp_count == 0`.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(&aid, &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.cp_count, 0);
        assert!(pkg.cp_entry(0).is_none());
    }

    #[test]
    fn classref_internal_decodes_to_offset_with_high_bit_clear() {
        // High bit of byte 0 clear -> internal class_ref is u16 BE
        // offset into Class component. Pick a non-zero, non-symmetric
        // value so a byte-swap or off-by-one would show up.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(&aid, &[(cp_tag::CLASSREF, [0x12, 0x34, 0x00])]);
        let pkg = parse(&cap).expect("parse");
        let entry = pkg.cp_entry(0).expect("entry 0");
        assert_eq!(entry.tag, cp_tag::CLASSREF);
        assert_eq!(
            entry.as_classref(),
            Some(super::super::ClassRef::Internal(0x1234))
        );
    }

    #[test]
    fn classref_external_splits_high_bit_into_package_and_class_tokens() {
        // High bit set -> external; lower 7 bits of byte 0 = package_token,
        // byte 1 = class_token. Pick distinct values so a swap is visible.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(&aid, &[(cp_tag::CLASSREF, [0x80 | 0x05, 0x42, 0x00])]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(
            pkg.cp_entry(0).and_then(super::super::CpInfo::as_classref),
            Some(super::super::ClassRef::External {
                package_token: 0x05,
                class_token: 0x42,
            })
        );
    }

    #[test]
    fn instance_fieldref_carries_class_and_token() {
        // info layout: class_ref(2) || token(1).
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(&aid, &[(cp_tag::INSTANCE_FIELDREF, [0x00, 0x10, 0x07])]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(
            pkg.cp_entry(0)
                .and_then(super::super::CpInfo::as_instance_fieldref),
            Some((super::super::ClassRef::Internal(0x0010), 0x07))
        );
    }

    #[test]
    fn virtual_methodref_extracts_private_bit_from_token_high_bit() {
        // High bit of token byte = isPrivate (JCVM 3.2 § 6.8.3).
        // Test both states adversarially: 0x82 (private + token 0x02)
        // and 0x02 (non-private + token 0x02). A naive `& 0xFF` would
        // collapse them.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(
            &aid,
            &[
                (cp_tag::VIRTUAL_METHODREF, [0x00, 0x20, 0x82]),
                (cp_tag::VIRTUAL_METHODREF, [0x00, 0x20, 0x02]),
            ],
        );
        let pkg = parse(&cap).expect("parse");
        assert_eq!(
            pkg.cp_entry(0)
                .and_then(super::super::CpInfo::as_virtual_methodref),
            Some((super::super::ClassRef::Internal(0x0020), 0x02, true))
        );
        assert_eq!(
            pkg.cp_entry(1)
                .and_then(super::super::CpInfo::as_virtual_methodref),
            Some((super::super::ClassRef::Internal(0x0020), 0x02, false))
        );
    }

    #[test]
    fn super_methodref_decodes_to_class_and_token() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(
            &aid,
            &[(cp_tag::SUPER_METHODREF, [0x80 | 0x03, 0x09, 0x05])],
        );
        let pkg = parse(&cap).expect("parse");
        assert_eq!(
            pkg.cp_entry(0)
                .and_then(super::super::CpInfo::as_super_methodref),
            Some((
                super::super::ClassRef::External {
                    package_token: 0x03,
                    class_token: 0x09,
                },
                0x05,
            ))
        );
    }

    #[test]
    fn static_fieldref_internal_uses_two_byte_offset() {
        // Internal static_field_ref: byte 0 reserved/zero, bytes 1..3 = u16 BE.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(&aid, &[(cp_tag::STATIC_FIELDREF, [0x00, 0xAB, 0xCD])]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(
            pkg.cp_entry(0)
                .and_then(super::super::CpInfo::as_static_fieldref),
            Some(super::super::StaticRef::Internal(0xABCD))
        );
    }

    #[test]
    fn static_methodref_external_carries_full_token_triple() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(
            &aid,
            &[(cp_tag::STATIC_METHODREF, [0x80 | 0x07, 0x11, 0x33])],
        );
        let pkg = parse(&cap).expect("parse");
        assert_eq!(
            pkg.cp_entry(0)
                .and_then(super::super::CpInfo::as_static_methodref),
            Some(super::super::StaticRef::External {
                package_token: 0x07,
                class_token: 0x11,
                token: 0x33,
            })
        );
    }

    #[test]
    fn cp_decoder_rejects_wrong_tag() {
        // Cross-tag decode must return None. A Classref entry asked
        // to decode as an InstanceFieldref should refuse rather than
        // silently mis-interpret the info bytes.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(&aid, &[(cp_tag::CLASSREF, [0x12, 0x34, 0x00])]);
        let pkg = parse(&cap).expect("parse");
        let entry = pkg.cp_entry(0).expect("entry 0");
        assert!(entry.as_classref().is_some());
        assert!(entry.as_instance_fieldref().is_none());
        assert!(entry.as_virtual_methodref().is_none());
        assert!(entry.as_super_methodref().is_none());
        assert!(entry.as_static_fieldref().is_none());
        assert!(entry.as_static_methodref().is_none());
    }

    #[test]
    fn rejects_constant_pool_count_over_max() {
        // A Constant Pool declaring `MAX_CP_ENTRIES + 1` entries is
        // beyond what we can store; reject up-front so callers don't
        // silently lose tail entries.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut entries = Vec::new();
        for _ in 0..=MAX_CP_ENTRIES {
            entries.push((cp_tag::CLASSREF, [0x00, 0x00, 0x00]));
        }
        let cap = build_cap_with_cp(&aid, &entries);
        assert!(matches!(
            parse(&cap),
            Err(ParseError::TooManyConstantPoolEntries)
        ));
    }

    #[test]
    fn accepts_constant_pool_at_exactly_max() {
        // Boundary: exactly MAX_CP_ENTRIES must succeed.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut entries = Vec::new();
        for i in 0..MAX_CP_ENTRIES {
            #[allow(clippy::cast_possible_truncation)]
            let lo = i as u8;
            entries.push((cp_tag::CLASSREF, [0x00, lo, 0x00]));
        }
        let cap = build_cap_with_cp(&aid, &entries);
        let pkg = parse(&cap).expect("parse at exactly MAX_CP_ENTRIES");
        #[allow(clippy::cast_possible_truncation)]
        let expected_count = MAX_CP_ENTRIES as u16;
        assert_eq!(pkg.cp_count, expected_count);
        // Spot-check the first and last entries decode independently.
        assert_eq!(
            pkg.cp_entry(0).and_then(super::super::CpInfo::as_classref),
            Some(super::super::ClassRef::Internal(0x0000))
        );
        #[allow(clippy::cast_possible_truncation)]
        let last_idx = (MAX_CP_ENTRIES - 1) as u16;
        #[allow(clippy::cast_possible_truncation)]
        let last_lo = (MAX_CP_ENTRIES - 1) as u8;
        assert_eq!(
            pkg.cp_entry(last_idx)
                .and_then(super::super::CpInfo::as_classref),
            Some(super::super::ClassRef::Internal(u16::from(last_lo)))
        );
    }

    #[test]
    fn rejects_unknown_constant_pool_tag() {
        // Tag 7 is unassigned in JCVM 3.2 § 6.8 Table 6-7. Silently
        // accepting it would let downstream code mis-decode the info
        // bytes against whatever helper happened to match by accident.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_cp(&aid, &[(7, [0x00, 0x00, 0x00])]);
        assert!(matches!(
            parse(&cap),
            Err(ParseError::UnknownConstantPoolTag)
        ));
    }

    #[test]
    fn rejects_truncated_constant_pool_body() {
        // count says 2 entries but only 1 entry's worth of bytes
        // follow. The parser must refuse rather than reading past
        // the body.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_be_bytes());
        body.push(cp_tag::CLASSREF);
        body.extend_from_slice(&[0x00, 0x00, 0x00]);
        // Missing the second entry's 4 bytes.
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::CONSTANT_POOL, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    #[test]
    fn cp_count_zero_with_no_constant_pool_component() {
        // A CAP with no ConstantPool component at all (the writer's
        // current default for empty applets) must yield `cp_count == 0`,
        // not a parse error.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.cp_count, 0);
    }

    #[test]
    fn rejects_zero_byte_constant_pool_body() {
        // A malformed CAP that declares CONSTANT_POOL with size = 0
        // has no room for the mandatory `count: u16` header. Reject
        // up-front rather than misreading whatever follows.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::CONSTANT_POOL, &[]);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    // -----------------------------------------------------------------------
    // Applet component
    // -----------------------------------------------------------------------

    /// Build an Applet component body. Each entry is
    /// `aid_length(1) | aid(aid_length) | install_method_offset(2 BE)`.
    #[allow(clippy::cast_possible_truncation)]
    fn applet_body(entries: &[(&[u8], u16)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(entries.len() as u8);
        for (aid, offset) in entries {
            body.push(aid.len() as u8);
            body.extend_from_slice(aid);
            body.extend_from_slice(&offset.to_be_bytes());
        }
        body
    }

    /// Build a CAP with Header + Applet + Method.
    fn build_cap_with_applets(package_aid: &[u8], applet_entries: &[(&[u8], u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(package_aid));
        emit(&mut out, tag::APPLET, &applet_body(applet_entries));
        emit(
            &mut out,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        out
    }

    #[test]
    fn no_applet_component_yields_zero_applet_count() {
        // A CAP without an Applet component (e.g. a library package)
        // surfaces `applet_count == 0`, not a parse error.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.applet_count, 0);
        assert!(pkg.applet(0).is_none());
    }

    #[test]
    fn empty_applet_component_yields_zero_applet_count() {
        // A library CAP that explicitly emits an Applet component
        // with `count = 0` must also yield zero applets.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_applets(&aid, &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.applet_count, 0);
    }

    #[test]
    fn single_applet_records_aid_and_install_offset() {
        let pkg_aid = [0xA0u8, 0x00, 0x00, 0x00, 0x62];
        let app_aid = [0xA0u8, 0x01, 0x02, 0x03, 0x04];
        let cap = build_cap_with_applets(&pkg_aid, &[(&app_aid, 0x0123)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.applet_count, 1);
        let info = pkg.applet(0).expect("applet 0");
        assert_eq!(info.aid_slice(), &app_aid);
        assert_eq!(
            info.install_method_offset, 0x0123,
            "install_method_offset must round-trip the 2-byte BE field"
        );
    }

    #[test]
    fn multiple_applets_preserve_distinct_aids_and_offsets() {
        // Distinct AIDs of distinct lengths + non-zero offsets verify
        // the parser advances `pos` correctly between entries.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let a1 = [0xA0u8, 0x11, 0x22];
        let a1 = a1.as_ref();
        let a2 = [0xA0u8, 0x33, 0x44, 0x55, 0x66, 0x77];
        let cap = build_cap_with_applets(&pkg_aid, &[(a1, 0x0001), (a2.as_ref(), 0x00FE)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.applet_count, 2);
        assert_eq!(pkg.applet(0).unwrap().aid_slice(), a1);
        assert_eq!(pkg.applet(0).unwrap().install_method_offset, 0x0001);
        assert_eq!(pkg.applet(1).unwrap().aid_slice(), a2.as_ref());
        assert_eq!(pkg.applet(1).unwrap().install_method_offset, 0x00FE);
    }

    #[test]
    fn applet_aid_at_min_iso7816_length_5_accepted() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let app_aid = [0xA0u8, 0x00, 0x00, 0x00, 0x05];
        let cap = build_cap_with_applets(&pkg_aid, &[(&app_aid, 0)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.applet(0).unwrap().aid_slice(), &app_aid);
    }

    #[test]
    fn applet_aid_at_max_iso7816_length_16_accepted() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let app_aid = [0xAAu8; MAX_AID_LEN];
        let cap = build_cap_with_applets(&pkg_aid, &[(&app_aid, 0)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.applet(0).unwrap().aid_len, 16);
        assert_eq!(pkg.applet(0).unwrap().aid_slice(), &app_aid);
    }

    #[test]
    fn applet_aid_length_over_16_rejected() {
        // Hand-build an Applet body with aid_length = 17.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.push(1); // count
        body.push(17); // bogus aid_length
        body.extend_from_slice(&[0xAA; 17]);
        body.extend_from_slice(&0u16.to_be_bytes());
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&pkg_aid));
        emit(&mut cap, tag::APPLET, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::AidTooLong)));
    }

    #[test]
    fn rejects_applet_count_over_max() {
        // Declaring more applets than `MAX_APPLETS_PER_PACKAGE` is
        // out of band -- silent truncation would lose entries.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut entries: Vec<(&[u8], u16)> = Vec::new();
        let dummy: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x01];
        for _ in 0..=MAX_APPLETS_PER_PACKAGE {
            entries.push((dummy, 0));
        }
        let cap = build_cap_with_applets(&pkg_aid, &entries);
        assert!(matches!(parse(&cap), Err(ParseError::TooManyApplets)));
    }

    #[test]
    fn accepts_applets_at_exactly_max() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut entries: Vec<(&[u8], u16)> = Vec::new();
        let dummy: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x01];
        for _ in 0..MAX_APPLETS_PER_PACKAGE {
            entries.push((dummy, 0));
        }
        let cap = build_cap_with_applets(&pkg_aid, &entries);
        let pkg = parse(&cap).expect("parse at MAX_APPLETS_PER_PACKAGE");
        #[allow(clippy::cast_possible_truncation)]
        let expected = MAX_APPLETS_PER_PACKAGE as u8;
        assert_eq!(pkg.applet_count, expected);
    }

    #[test]
    fn rejects_truncated_applet_body_mid_entry() {
        // count says 1 but the entry is short by 2 bytes (missing offset).
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.push(1);
        body.push(5); // aid_length
        body.extend_from_slice(&[0xA0u8, 0x00, 0x00, 0x00, 0x01]);
        // Missing 2-byte install_method_offset.
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&pkg_aid));
        emit(&mut cap, tag::APPLET, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    #[test]
    fn applet_by_aid_lookup_finds_match() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let a1: &[u8] = &[0xA0, 0x11, 0x22];
        let a2: &[u8] = &[0xA0, 0x33, 0x44, 0x55];
        let cap = build_cap_with_applets(&pkg_aid, &[(a1, 0x0001), (a2, 0x0002)]);
        let pkg = parse(&cap).expect("parse");
        let info = pkg.applet_by_aid(a2).expect("applet_by_aid match");
        assert_eq!(info.install_method_offset, 0x0002);
        assert!(pkg.applet_by_aid(&[0xFF, 0xFF]).is_none());
    }

    #[test]
    fn applet_index_past_count_returns_none() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let app_aid = [0xA0u8, 0, 0, 0, 0x01];
        let cap = build_cap_with_applets(&pkg_aid, &[(&app_aid, 0)]);
        let pkg = parse(&cap).expect("parse");
        assert!(pkg.applet(0).is_some());
        assert!(pkg.applet(1).is_none());
        #[allow(clippy::cast_possible_truncation)]
        let max_idx = MAX_APPLETS_PER_PACKAGE as u8;
        assert!(pkg.applet(max_idx).is_none());
        assert!(pkg.applet(u8::MAX).is_none());
    }

    // -----------------------------------------------------------------------
    // Import component
    // -----------------------------------------------------------------------

    /// Build an Import component body. Each entry is
    /// `minor(1) | major(1) | aid_length(1) | aid(aid_length)`.
    #[allow(clippy::cast_possible_truncation)]
    fn import_body(entries: &[(u8, u8, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(entries.len() as u8);
        for (minor, major, aid) in entries {
            body.push(*minor);
            body.push(*major);
            body.push(aid.len() as u8);
            body.extend_from_slice(aid);
        }
        body
    }

    /// Build a CAP with Header + Import + Method.
    fn build_cap_with_imports(pkg_aid: &[u8], imports: &[(u8, u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(pkg_aid));
        emit(&mut out, tag::IMPORT, &import_body(imports));
        emit(
            &mut out,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        out
    }

    #[test]
    fn no_import_component_yields_zero_import_count() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.import_count, 0);
        assert!(pkg.import(0).is_none());
    }

    #[test]
    fn empty_import_component_yields_zero_import_count() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_imports(&aid, &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.import_count, 0);
    }

    #[test]
    fn single_import_records_aid_and_version() {
        // Adversarial: distinct minor/major bytes catch a swap, and
        // a non-trivial AID catches a slice-offset bug.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let imp_aid: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01]; // javacard.framework
        let cap = build_cap_with_imports(&pkg_aid, &[(0x05, 0x03, imp_aid)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.import_count, 1);
        let info = pkg.import(0).expect("import 0");
        assert_eq!(info.minor_version, 0x05);
        assert_eq!(info.major_version, 0x03);
        assert_eq!(info.aid_slice(), imp_aid);
    }

    #[test]
    fn multiple_imports_preserve_order_and_distinct_versions() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let a1: &[u8] = &[0xA0, 0x11, 0x22];
        let a2: &[u8] = &[0xA0, 0x33, 0x44, 0x55, 0x66, 0x77];
        let cap = build_cap_with_imports(&pkg_aid, &[(0x01, 0x02, a1), (0x07, 0x08, a2)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.import_count, 2);
        let i0 = pkg.import(0).unwrap();
        let i1 = pkg.import(1).unwrap();
        assert_eq!(i0.aid_slice(), a1);
        assert_eq!(i0.minor_version, 0x01);
        assert_eq!(i0.major_version, 0x02);
        assert_eq!(i1.aid_slice(), a2);
        assert_eq!(i1.minor_version, 0x07);
        assert_eq!(i1.major_version, 0x08);
    }

    #[test]
    fn import_aid_at_min_iso7816_length_5_accepted() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let imp_aid: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x05];
        let cap = build_cap_with_imports(&pkg_aid, &[(0, 0, imp_aid)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.import(0).unwrap().aid_slice(), imp_aid);
    }

    #[test]
    fn import_aid_at_max_iso7816_length_16_accepted() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let imp_aid: &[u8] = &[0xCC; MAX_AID_LEN];
        let cap = build_cap_with_imports(&pkg_aid, &[(0, 0, imp_aid)]);
        let pkg = parse(&cap).expect("parse");
        let info = pkg.import(0).unwrap();
        assert_eq!(info.aid_len, 16);
        assert_eq!(info.aid_slice(), imp_aid);
    }

    #[test]
    fn import_aid_length_over_16_rejected() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = vec![
            1,  // count
            0,  // minor
            0,  // major
            17, // bogus aid_length
        ];
        body.extend_from_slice(&[0xAA; 17]);
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&pkg_aid));
        emit(&mut cap, tag::IMPORT, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::AidTooLong)));
    }

    #[test]
    fn rejects_import_count_over_max() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let dummy: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x01];
        let mut entries: Vec<(u8, u8, &[u8])> = Vec::new();
        for _ in 0..=MAX_IMPORTS_PER_PACKAGE {
            entries.push((0, 0, dummy));
        }
        let cap = build_cap_with_imports(&pkg_aid, &entries);
        assert!(matches!(parse(&cap), Err(ParseError::TooManyImports)));
    }

    #[test]
    fn accepts_imports_at_exactly_max() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let dummy: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x01];
        let mut entries: Vec<(u8, u8, &[u8])> = Vec::new();
        for _ in 0..MAX_IMPORTS_PER_PACKAGE {
            entries.push((0, 0, dummy));
        }
        let cap = build_cap_with_imports(&pkg_aid, &entries);
        let pkg = parse(&cap).expect("parse at MAX_IMPORTS_PER_PACKAGE");
        #[allow(clippy::cast_possible_truncation)]
        let expected = MAX_IMPORTS_PER_PACKAGE as u8;
        assert_eq!(pkg.import_count, expected);
    }

    #[test]
    fn rejects_truncated_import_body_mid_entry() {
        // count says 1, header says aid_length = 5, but body is short.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = vec![
            1, // count
            0, // minor
            0, // major
            5, // aid_length
        ];
        body.extend_from_slice(&[0xA0u8, 0x00, 0x00]); // 3 bytes; missing 2.
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&pkg_aid));
        emit(&mut cap, tag::IMPORT, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    // -----------------------------------------------------------------------
    // Method-component offset -> method index resolution
    // -----------------------------------------------------------------------

    #[test]
    fn method_offsets_populated_from_descriptor_match_layout() {
        // With a Descriptor present, every method's offset within the
        // Method component must round-trip through `method_offsets`.
        // Construction mirrors `descriptor_drives_per_method_bytecode_split`:
        // three methods of distinct bytecode lengths, expected offsets
        // computed via the same `method_offset` helper used to build
        // the Descriptor body.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let m1: &[u8] = &[0x03, 0x78];
        let m2: &[u8] = &[0x04, 0x41, 0x78];
        let m3: &[u8] = &[0x05, 0x78];
        let bytecode_lens = [m1.len(), m2.len(), m3.len()];
        let descriptor = descriptor_body_for(&bytecode_lens);
        let cap = build_cap(
            &aid,
            &[
                (m1, 0x80, 4, 0, 1),
                (m2, 0x80, 4, 0, 1),
                (m3, 0x80, 4, 0, 1),
            ],
            Some(&descriptor),
        );
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.method_count, 3);
        assert_eq!(pkg.method_offsets[0], method_offset(&bytecode_lens, 0));
        assert_eq!(pkg.method_offsets[1], method_offset(&bytecode_lens, 1));
        assert_eq!(pkg.method_offsets[2], method_offset(&bytecode_lens, 2));
    }

    #[test]
    fn method_index_by_offset_resolves_each_method() {
        // The Applet component's `install_method_offset` is one of
        // these offsets; the dispatch path needs to map it back to
        // the method index.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let m1: &[u8] = &[0x78];
        let m2: &[u8] = &[0x04, 0x78];
        let bytecode_lens = [m1.len(), m2.len()];
        let descriptor = descriptor_body_for(&bytecode_lens);
        let cap = build_cap(
            &aid,
            &[(m1, 0x80, 4, 0, 1), (m2, 0x80, 4, 0, 1)],
            Some(&descriptor),
        );
        let pkg = parse(&cap).expect("parse");
        let off0 = method_offset(&bytecode_lens, 0);
        let off1 = method_offset(&bytecode_lens, 1);
        assert_eq!(pkg.method_index_by_component_offset(off0), Some(0));
        assert_eq!(pkg.method_index_by_component_offset(off1), Some(1));
    }

    #[test]
    fn method_index_by_offset_returns_none_for_unknown_offset() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let m1: &[u8] = &[0x78];
        let bytecode_lens = [m1.len()];
        let descriptor = descriptor_body_for(&bytecode_lens);
        let cap = build_cap(&aid, &[(m1, 0x80, 4, 0, 1)], Some(&descriptor));
        let pkg = parse(&cap).expect("parse");
        // Pick an offset the parser didn't record.
        assert_eq!(pkg.method_index_by_component_offset(0xFFFE), None);
    }

    #[test]
    fn method_index_by_offset_does_not_match_unset_slots_with_zero() {
        // Slots past `method_count` keep `method_offsets[i] == 0`.
        // Querying for offset 0 must NOT match those stale slots --
        // only a method that was actually parsed at offset 0 should
        // resolve. With a Descriptor, no method actually starts at
        // offset 0 (the handler_count byte sits there), so the
        // resolver must return None.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let m1: &[u8] = &[0x78];
        let bytecode_lens = [m1.len()];
        let descriptor = descriptor_body_for(&bytecode_lens);
        let cap = build_cap(&aid, &[(m1, 0x80, 4, 0, 1)], Some(&descriptor));
        let pkg = parse(&cap).expect("parse");
        // The first method's actual offset is 1 (handler_count).
        assert_eq!(pkg.method_index_by_component_offset(1), Some(0));
        assert_eq!(
            pkg.method_index_by_component_offset(0),
            None,
            "offset 0 must not collide with unset slots"
        );
    }

    #[test]
    fn method_index_by_offset_returns_none_for_blob_path() {
        // The simplified-blob parser leaves every offset at 0.
        // A non-zero query reliably returns None; querying for 0
        // would collide with all unset slots, which is also wrong --
        // the resolver bounds-checks against `method_count` and
        // requires the slot's `methods[i]` to be `Some`, but the blob
        // path's method 0 IS Some at offset 0. That's the documented
        // limitation: blob-path packages have no offset-to-index
        // mapping. Verify the non-zero case explicitly.
        let aid = [0xA0u8, 0x00, 0x00, 0x00, 0x62];
        let bc: &[u8] = &[0x78];
        let mut blob = [0u8; 64];
        let len = super::super::build_cap_blob(&aid, &[bc], &mut blob);
        let pkg = super::super::parse_cap(&blob[..len]).expect("blob parse");
        assert_eq!(pkg.method_count, 1);
        assert_eq!(pkg.method_offsets[0], 0);
        assert_eq!(pkg.method_index_by_component_offset(0xABCD), None);
    }

    // -----------------------------------------------------------------------
    // Export component
    // -----------------------------------------------------------------------

    /// Build an Export component body. Each entry is
    /// `class_offset(2 BE) | static_field_count(1) | static_method_count(1)
    /// | static_field_offsets(2 BE * fc) | static_method_offsets(2 BE * mc)`.
    #[allow(clippy::cast_possible_truncation)]
    fn export_body(classes: &[(u16, &[u16], &[u16])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(classes.len() as u8);
        for (class_offset, fields, methods) in classes {
            body.extend_from_slice(&class_offset.to_be_bytes());
            body.push(fields.len() as u8);
            body.push(methods.len() as u8);
            for f in *fields {
                body.extend_from_slice(&f.to_be_bytes());
            }
            for m in *methods {
                body.extend_from_slice(&m.to_be_bytes());
            }
        }
        body
    }

    /// Build a CAP with Header + Export + Method.
    fn build_cap_with_exports(pkg_aid: &[u8], classes: &[(u16, &[u16], &[u16])]) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(pkg_aid));
        emit(&mut out, tag::EXPORT, &export_body(classes));
        emit(
            &mut out,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        out
    }

    #[test]
    fn no_export_component_yields_zero_export_count() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.export_count, 0);
        assert!(pkg.export(0).is_none());
    }

    #[test]
    fn empty_export_component_yields_zero_export_count() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_exports(&aid, &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.export_count, 0);
    }

    #[test]
    fn single_exported_class_records_offset_and_token_tables() {
        // Adversarial offsets: distinct, non-zero, and not aligned
        // so a wrong-byte or swap bug in u16 BE decoding shows up.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let class_offset = 0x1234u16;
        let fields: &[u16] = &[0x0050, 0x00A0];
        let methods: &[u16] = &[0x0001, 0x000F, 0x00FE];
        let cap = build_cap_with_exports(&pkg_aid, &[(class_offset, fields, methods)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.export_count, 1);
        let info = pkg.export(0).expect("class 0");
        assert_eq!(info.class_offset, 0x1234);
        assert_eq!(info.static_field_count, 2);
        assert_eq!(info.static_method_count, 3);
        assert_eq!(info.static_field_offset(0), Some(0x0050));
        assert_eq!(info.static_field_offset(1), Some(0x00A0));
        assert_eq!(info.static_field_offset(2), None);
        assert_eq!(info.static_method_offset(0), Some(0x0001));
        assert_eq!(info.static_method_offset(1), Some(0x000F));
        assert_eq!(info.static_method_offset(2), Some(0x00FE));
        assert_eq!(info.static_method_offset(3), None);
    }

    #[test]
    fn multiple_exported_classes_preserve_distinct_tables() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let f0: &[u16] = &[0x10];
        let m0: &[u16] = &[];
        let f1: &[u16] = &[];
        let m1: &[u16] = &[0x20, 0x21];
        let cap = build_cap_with_exports(&pkg_aid, &[(0x0100, f0, m0), (0x0200, f1, m1)]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.export_count, 2);
        let c0 = pkg.export(0).unwrap();
        let c1 = pkg.export(1).unwrap();
        assert_eq!(c0.class_offset, 0x0100);
        assert_eq!(c0.static_field_count, 1);
        assert_eq!(c0.static_method_count, 0);
        assert_eq!(c0.static_field_offset(0), Some(0x10));
        assert_eq!(c1.class_offset, 0x0200);
        assert_eq!(c1.static_field_count, 0);
        assert_eq!(c1.static_method_count, 2);
        assert_eq!(c1.static_method_offset(1), Some(0x21));
    }

    #[test]
    fn rejects_export_class_count_over_max() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let no_offsets: &[u16] = &[];
        let mut classes: Vec<(u16, &[u16], &[u16])> = Vec::new();
        for _ in 0..=MAX_EXPORTED_CLASSES_PER_PACKAGE {
            classes.push((0, no_offsets, no_offsets));
        }
        let cap = build_cap_with_exports(&pkg_aid, &classes);
        assert!(matches!(
            parse(&cap),
            Err(ParseError::TooManyExportedClasses)
        ));
    }

    #[test]
    fn rejects_export_field_count_over_max() {
        // Hand-build an Export body that names MAX_EXPORTED_FIELDS_PER_CLASS + 1 fields.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let too_many = MAX_EXPORTED_FIELDS_PER_CLASS + 1;
        #[allow(clippy::cast_possible_truncation)]
        let fc = too_many as u8;
        let mut body = Vec::new();
        body.push(1); // class_count
        body.extend_from_slice(&0u16.to_be_bytes()); // class_offset
        body.push(fc);
        body.push(0); // method_count
        for i in 0..too_many {
            #[allow(clippy::cast_possible_truncation)]
            let v = i as u16;
            body.extend_from_slice(&v.to_be_bytes());
        }
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&pkg_aid));
        emit(&mut cap, tag::EXPORT, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(
            parse(&cap),
            Err(ParseError::TooManyExportedFields)
        ));
    }

    #[test]
    fn rejects_export_method_count_over_max() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let too_many = MAX_EXPORTED_METHODS_PER_CLASS + 1;
        #[allow(clippy::cast_possible_truncation)]
        let mc = too_many as u8;
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.push(0); // field_count
        body.push(mc);
        for i in 0..too_many {
            #[allow(clippy::cast_possible_truncation)]
            let v = i as u16;
            body.extend_from_slice(&v.to_be_bytes());
        }
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&pkg_aid));
        emit(&mut cap, tag::EXPORT, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(
            parse(&cap),
            Err(ParseError::TooManyExportedMethods)
        ));
    }

    #[test]
    fn rejects_truncated_export_body_mid_offsets() {
        // count says 1, header claims 2 fields, but offsets array is short.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.push(2); // field_count
        body.push(0); // method_count
        body.extend_from_slice(&0u16.to_be_bytes()); // only 1 of 2 fields
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&pkg_aid));
        emit(&mut cap, tag::EXPORT, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    // -----------------------------------------------------------------------
    // Reference Location component
    // -----------------------------------------------------------------------

    /// Build a `RefLocation` component body from raw delta lists.
    #[allow(clippy::cast_possible_truncation, clippy::similar_names)]
    fn ref_loc_body(byte_deltas: &[u8], byte2_deltas: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(byte_deltas.len() as u16).to_be_bytes());
        body.extend_from_slice(byte_deltas);
        body.extend_from_slice(&(byte2_deltas.len() as u16).to_be_bytes());
        body.extend_from_slice(byte2_deltas);
        body
    }

    /// Build a CAP with Header + `RefLocation` + Method.
    #[allow(clippy::similar_names)]
    fn build_cap_with_ref_loc(pkg_aid: &[u8], byte_deltas: &[u8], byte2_deltas: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(pkg_aid));
        emit(
            &mut out,
            tag::REFERENCE_LOCATION,
            &ref_loc_body(byte_deltas, byte2_deltas),
        );
        emit(
            &mut out,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        out
    }

    #[test]
    fn no_ref_location_component_yields_zero_counts() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.ref_loc_byte_count, 0);
        assert_eq!(pkg.ref_loc_byte2_count, 0);
        assert_eq!(pkg.ref_loc_byte_deltas(), &[] as &[u8]);
        assert_eq!(pkg.ref_loc_byte2_deltas(), &[] as &[u8]);
    }

    #[test]
    fn empty_ref_location_component_yields_zero_counts() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_ref_loc(&aid, &[], &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.ref_loc_byte_count, 0);
        assert_eq!(pkg.ref_loc_byte2_count, 0);
    }

    #[test]
    fn single_byte_delta_round_trips() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_ref_loc(&aid, &[0x05], &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.ref_loc_byte_count, 1);
        assert_eq!(pkg.ref_loc_byte_deltas(), &[0x05]);
        assert_eq!(pkg.ref_loc_byte2_count, 0);
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn multi_delta_lists_preserve_byte_order_and_0xff_continuation() {
        // The 0xFF continuation byte is part of the spec's delta
        // encoding (advance 254 without emitting a patch site).
        // The parser stores it verbatim -- decoding is consumer-side.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let byte_deltas = [0x10, 0xFF, 0x05, 0x00, 0xFE];
        let byte2_deltas = [0x07, 0x21, 0xFF, 0x40];
        let cap = build_cap_with_ref_loc(&aid, &byte_deltas, &byte2_deltas);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.ref_loc_byte_count, 5);
        assert_eq!(pkg.ref_loc_byte_deltas(), &byte_deltas);
        assert_eq!(pkg.ref_loc_byte2_count, 4);
        assert_eq!(pkg.ref_loc_byte2_deltas(), &byte2_deltas);
    }

    #[test]
    fn rejects_byte_index_count_over_max() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let too_many = vec![0u8; MAX_REF_LOC_BYTE_INDICES + 1];
        let cap = build_cap_with_ref_loc(&aid, &too_many, &[]);
        assert!(matches!(
            parse(&cap),
            Err(ParseError::TooManyRefLocByteIndices)
        ));
    }

    #[test]
    fn rejects_byte2_index_count_over_max() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let too_many = vec![0u8; MAX_REF_LOC_BYTE2_INDICES + 1];
        let cap = build_cap_with_ref_loc(&aid, &[], &too_many);
        assert!(matches!(
            parse(&cap),
            Err(ParseError::TooManyRefLocByte2Indices)
        ));
    }

    #[test]
    fn accepts_ref_loc_at_exactly_max() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let max_byte = vec![0xAAu8; MAX_REF_LOC_BYTE_INDICES];
        let max_byte2 = vec![0xBBu8; MAX_REF_LOC_BYTE2_INDICES];
        let cap = build_cap_with_ref_loc(&aid, &max_byte, &max_byte2);
        let pkg = parse(&cap).expect("parse at MAX_REF_LOC_*");
        #[allow(clippy::cast_possible_truncation)]
        let expected_byte = MAX_REF_LOC_BYTE_INDICES as u16;
        #[allow(clippy::cast_possible_truncation)]
        let expected_byte2 = MAX_REF_LOC_BYTE2_INDICES as u16;
        assert_eq!(pkg.ref_loc_byte_count, expected_byte);
        assert_eq!(pkg.ref_loc_byte2_count, expected_byte2);
        assert_eq!(pkg.ref_loc_byte_deltas(), max_byte.as_slice());
        assert_eq!(pkg.ref_loc_byte2_deltas(), max_byte2.as_slice());
    }

    #[test]
    fn rejects_truncated_byte_deltas() {
        // count says 3 but only 1 byte follows.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.extend_from_slice(&3u16.to_be_bytes());
        body.push(0xAA);
        // Note: the 2nd count would need to follow but we're already short.
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::REFERENCE_LOCATION, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    #[test]
    fn rejects_truncated_byte2_deltas() {
        // First list ends cleanly; second list count promises more
        // than the body holds.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&5u16.to_be_bytes());
        body.extend_from_slice(&[0x10, 0x20]); // only 2 of 5 bytes
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::REFERENCE_LOCATION, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    #[test]
    fn ref_loc_accessors_bound_to_count_not_storage() {
        // If `ref_loc_byte_count` is 2, accessor must yield 2 bytes
        // even though the underlying array has MAX_REF_LOC_BYTE_INDICES
        // capacity. Stale bytes past `count` must not leak.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_ref_loc(&aid, &[0x10, 0x20], &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.ref_loc_byte_deltas().len(), 2);
        assert_eq!(pkg.ref_loc_byte_deltas(), &[0x10, 0x20]);
    }

    // -----------------------------------------------------------------------
    // StaticField component
    // -----------------------------------------------------------------------

    /// Build a `StaticField` component body. The MVP only emits the
    /// fixed prefix; tests for `array_init` and `non_default_values`
    /// rejection use hand-crafted bodies.
    fn static_field_body(image_size: u16, reference_count: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&image_size.to_be_bytes());
        body.extend_from_slice(&reference_count.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // array_init_count
        body.extend_from_slice(&0u16.to_be_bytes()); // default_value_count
        body
    }

    /// Build a CAP with Header + `StaticField` + Method.
    fn build_cap_with_static_field(
        pkg_aid: &[u8],
        image_size: u16,
        reference_count: u16,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(pkg_aid));
        emit(
            &mut out,
            tag::STATIC_FIELD,
            &static_field_body(image_size, reference_count),
        );
        emit(
            &mut out,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        out
    }

    #[test]
    fn no_static_field_component_yields_zero_image_and_refs() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.static_field_image_size, 0);
        assert_eq!(pkg.static_reference_count, 0);
    }

    #[test]
    fn static_field_image_size_and_refs_round_trip() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        // Adversarial: distinct, non-zero values catch a u16 BE swap.
        let cap = build_cap_with_static_field(&aid, 0x1234, 0x0007);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.static_field_image_size, 0x1234);
        assert_eq!(pkg.static_reference_count, 0x0007);
    }

    #[test]
    fn rejects_static_field_with_array_inits() {
        // MVP doesn't yet decode array_init records; reject up-front
        // rather than silently dropping them.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // image_size
        body.extend_from_slice(&0u16.to_be_bytes()); // reference_count
        body.extend_from_slice(&1u16.to_be_bytes()); // array_init_count = 1 (unsupported)
        body.extend_from_slice(&0u16.to_be_bytes()); // default_value_count
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::STATIC_FIELD, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(
            parse(&cap),
            Err(ParseError::StaticFieldArrayInitsUnsupported)
        ));
    }

    #[test]
    fn rejects_static_field_with_non_default_values() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // image_size
        body.extend_from_slice(&0u16.to_be_bytes()); // reference_count
        body.extend_from_slice(&0u16.to_be_bytes()); // array_init_count
        body.extend_from_slice(&3u16.to_be_bytes()); // default_value_count = 3 (unsupported)
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::STATIC_FIELD, &body);
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(
            parse(&cap),
            Err(ParseError::StaticFieldNonDefaultValuesUnsupported)
        ));
    }

    #[test]
    fn rejects_truncated_static_field_body() {
        // A body shorter than the 8-byte fixed prefix is invalid.
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let mut cap = Vec::new();
        emit(&mut cap, tag::HEADER, &header_body(&aid));
        emit(&mut cap, tag::STATIC_FIELD, &[0u8, 0, 0, 0, 0, 0]); // only 6 of 8
        emit(
            &mut cap,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    // -----------------------------------------------------------------------
    // Class component
    // -----------------------------------------------------------------------

    /// Build a single `class_info` body with the `simrs-jacc` shape:
    /// bitfield + `super_class_ref` + 7 fixed bytes + N u16 public-method
    /// table entries + zero package methods + zero `implemented_interfaces`.
    #[allow(clippy::cast_possible_truncation)]
    fn class_info_body(public_method_offsets: &[u16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x00); // bitfield: not interface, no implemented_interfaces
        body.extend_from_slice(&0xFFFFu16.to_be_bytes()); // super = java.lang.Object
        body.push(0); // declared_instance_size
        body.push(0); // first_reference_token
        body.push(0); // reference_count
        body.push(0); // public_method_table_base
        body.push(public_method_offsets.len() as u8);
        body.push(0); // package_method_table_base
        body.push(0); // package_method_table_count
        for off in public_method_offsets {
            body.extend_from_slice(&off.to_be_bytes());
        }
        body
    }

    /// Build a CAP with Header + Class + Method.
    fn build_cap_with_class(pkg_aid: &[u8], class_body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        emit(&mut out, tag::HEADER, &header_body(pkg_aid));
        emit(&mut out, tag::CLASS, class_body);
        emit(
            &mut out,
            tag::METHOD,
            &method_body(&[(&[0x78u8][..], 0x80, 4, 0, 1)]),
        );
        out
    }

    #[test]
    fn no_class_component_yields_zero_class_count() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap(&aid, &[(&[0x78u8][..], 0x80, 4, 0, 1)], None);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.class_count, 0);
        assert!(pkg.class(0).is_none());
    }

    #[test]
    fn empty_class_component_yields_zero_class_count() {
        let aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_class(&aid, &[]);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.class_count, 0);
    }

    #[test]
    fn single_class_records_offset_and_super_ref() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let body = class_info_body(&[0x0001, 0x0010]);
        let cap = build_cap_with_class(&pkg_aid, &body);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.class_count, 1);
        let info = pkg.class(0).expect("class 0");
        assert_eq!(info.component_offset, 0);
        assert_eq!(
            info.super_class_ref,
            super::super::ClassRef::External {
                package_token: 0x7F,
                class_token: 0xFF,
            },
            "0xFFFF in 2-byte form decodes as external token-pair"
        );
        assert_eq!(info.public_method_table_count, 2);
        assert_eq!(info.package_method_table_count, 0);
        assert_eq!(info.interface_count, 0);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn multi_class_preserves_per_class_offsets() {
        // Two back-to-back class_infos. The second's offset is the
        // first's full size.
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let body0 = class_info_body(&[0x0001]); // 12 bytes (10 fixed + 1 u16)
        let body1 = class_info_body(&[]); // 10 bytes (10 fixed + 0)
        let mut combined = Vec::new();
        combined.extend_from_slice(&body0);
        combined.extend_from_slice(&body1);
        let cap = build_cap_with_class(&pkg_aid, &combined);
        let pkg = parse(&cap).expect("parse");
        assert_eq!(pkg.class_count, 2);
        assert_eq!(pkg.class(0).unwrap().component_offset, 0);
        assert_eq!(pkg.class(1).unwrap().component_offset, body0.len() as u16);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn class_by_component_offset_resolves() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let body0 = class_info_body(&[0x0001]);
        let body1 = class_info_body(&[]);
        let body0_len = body0.len() as u16;
        let mut combined = Vec::new();
        combined.extend_from_slice(&body0);
        combined.extend_from_slice(&body1);
        let cap = build_cap_with_class(&pkg_aid, &combined);
        let pkg = parse(&cap).expect("parse");
        // Class at offset 0 resolves to class index 0; class at
        // offset = body0.len() resolves to class index 1.
        assert!(pkg.class_by_component_offset(0).is_some());
        assert_eq!(
            pkg.class_by_component_offset(body0_len)
                .map(|c| c.component_offset),
            Some(body0_len)
        );
        // An offset that doesn't match any class returns None.
        assert!(pkg.class_by_component_offset(0xFFFE).is_none());
    }

    #[test]
    fn rejects_class_with_acc_interface_bit() {
        // bitfield with bit 7 set indicates interface_info, which
        // the MVP parser doesn't yet decode.
        let mut body = Vec::new();
        body.push(0x80); // ACC_INTERFACE
        // (a real interface_info has different layout than class_info,
        // but we don't need to construct it correctly to verify
        // rejection by the bit-7 check.)
        body.extend_from_slice(&0u16.to_be_bytes()); // some bytes
        body.extend_from_slice(&[0u8; 7]);
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_class(&pkg_aid, &body);
        assert!(matches!(
            parse(&cap),
            Err(ParseError::ClassInterfaceNotSupported)
        ));
    }

    #[test]
    fn rejects_more_classes_than_max() {
        // MAX_CLASSES_PER_PACKAGE + 1 minimal class_infos (no methods).
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let one = class_info_body(&[]);
        let mut combined = Vec::new();
        for _ in 0..=MAX_CLASSES_PER_PACKAGE {
            combined.extend_from_slice(&one);
        }
        let cap = build_cap_with_class(&pkg_aid, &combined);
        assert!(matches!(parse(&cap), Err(ParseError::TooManyClasses)));
    }

    #[test]
    fn accepts_classes_at_exactly_max() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let one = class_info_body(&[]);
        let mut combined = Vec::new();
        for _ in 0..MAX_CLASSES_PER_PACKAGE {
            combined.extend_from_slice(&one);
        }
        let cap = build_cap_with_class(&pkg_aid, &combined);
        let pkg = parse(&cap).expect("parse at exactly MAX_CLASSES_PER_PACKAGE");
        #[allow(clippy::cast_possible_truncation)]
        let expected = MAX_CLASSES_PER_PACKAGE as u8;
        assert_eq!(pkg.class_count, expected);
    }

    #[test]
    fn rejects_truncated_class_body_mid_method_table() {
        // bitfield = 0, public_method_table_count = 2 but the body
        // ends right after the fixed 10 bytes -- no room for the u16
        // entries the count promises.
        let mut body = Vec::new();
        body.push(0x00);
        body.extend_from_slice(&0xFFFFu16.to_be_bytes());
        body.push(0);
        body.push(0);
        body.push(0);
        body.push(0);
        body.push(2); // public_method_table_count = 2 (4 bytes that aren't there)
        body.push(0);
        body.push(0);
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let cap = build_cap_with_class(&pkg_aid, &body);
        assert!(matches!(parse(&cap), Err(ParseError::TooShort)));
    }

    #[test]
    fn class_index_past_count_returns_none() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let body = class_info_body(&[]);
        let cap = build_cap_with_class(&pkg_aid, &body);
        let pkg = parse(&cap).expect("parse");
        assert!(pkg.class(0).is_some());
        assert!(pkg.class(1).is_none());
        #[allow(clippy::cast_possible_truncation)]
        let max_idx = MAX_CLASSES_PER_PACKAGE as u8;
        assert!(pkg.class(max_idx).is_none());
        assert!(pkg.class(u8::MAX).is_none());
    }

    #[test]
    fn export_index_past_count_returns_none() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let no_offsets: &[u16] = &[];
        let cap = build_cap_with_exports(&pkg_aid, &[(0x10, no_offsets, no_offsets)]);
        let pkg = parse(&cap).expect("parse");
        assert!(pkg.export(0).is_some());
        assert!(pkg.export(1).is_none());
        #[allow(clippy::cast_possible_truncation)]
        let max_idx = MAX_EXPORTED_CLASSES_PER_PACKAGE as u8;
        assert!(pkg.export(max_idx).is_none());
        assert!(pkg.export(u8::MAX).is_none());
    }

    #[test]
    fn import_index_past_count_returns_none() {
        let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
        let imp_aid: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x01];
        let cap = build_cap_with_imports(&pkg_aid, &[(0, 0, imp_aid)]);
        let pkg = parse(&cap).expect("parse");
        assert!(pkg.import(0).is_some());
        assert!(pkg.import(1).is_none());
        #[allow(clippy::cast_possible_truncation)]
        let max_idx = MAX_IMPORTS_PER_PACKAGE as u8;
        assert!(pkg.import(max_idx).is_none());
        assert!(pkg.import(u8::MAX).is_none());
    }

    // =======================================================================
    // Property-based tests for every component-tagged parser
    // =======================================================================
    //
    // Each component this session added (ConstantPool, Applet, Import,
    // Export, RefLocation, StaticField, Class) gets the same trio of
    // proptest! coverage:
    //
    //   1. **Snapshot round-trip** -- random Package state with
    //      arbitrary field values for that component, save_state ->
    //      restore_state -> assert byte-identical fields. Catches
    //      save/restore drift, byte-order bugs, position bugs.
    //
    //   2. **Variable-walk** (where applicable) -- for components
    //      whose body has counted variable-size sub-records (CP entries,
    //      applets, imports, exports, ref-loc deltas, classes), run
    //      counts across their full type range and verify the parser
    //      recovers the same counts and entries.
    //
    //   3. **Truncation never panics** -- build a valid body, truncate
    //      at every prefix length, assert parse() returns either Ok or
    //      Err but never panics. Catches missing bounds checks before
    //      array indexing.
    //
    // Pattern modeled on simrs-bertlv (round-trip property test) and
    // simrs-rijndael (proptest over input space). simrs-jcvm/src/lib.rs
    // already has a proptest workspace dependency wired up.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_lossless,
        clippy::unnecessary_cast,
        clippy::needless_range_loop
    )]
    mod prop {
        use super::*;
        // Pull in cap-level types directly. `mod tests`'s `use super::{...}`
        // imports are private and don't re-export through `super::*` here, so
        // we'd otherwise need awkward `super::super::super::ClassInfo` paths
        // sprinkled through every proptest body. `ClassRef` lives at the
        // cap module level (not re-exported into `mod components`) since
        // production code in this file doesn't reference it directly --
        // only the prop tests do.
        use super::super::super::ClassRef;
        use super::super::{AppletInfo, ClassInfo, CpInfo, ExportInfo, ImportInfo};
        use proptest::prelude::*;

        // ---------------------------------------------------------------
        // ConstantPool
        // ---------------------------------------------------------------

        /// Strategy: a `(tag, [u8; 3])` pair where tag is in the
        /// spec-valid 1..=6 range. Used by the CP round-trip proptest.
        fn cp_entry_strategy() -> impl Strategy<Value = (u8, [u8; 3])> {
            (1u8..=6, any::<[u8; 3]>())
        }

        proptest! {
            /// Parser accepts arbitrary valid CP bodies up to MAX_CP_ENTRIES.
            /// Every entry returned by `cp_entry(i)` decodes to the exact
            /// `(tag, info)` pair we wrote.
            #[test]
            fn cp_parser_round_trips_arbitrary_entries(
                entries in proptest::collection::vec(cp_entry_strategy(), 0..=64),
            ) {
                let aid = [0xA0u8, 0, 0, 0, 0x62];
                let cap = build_cap_with_cp(&aid, &entries);
                let pkg = parse(&cap).expect("parse");
                prop_assert_eq!(pkg.cp_count as usize, entries.len());
                for (i, (tag, info)) in entries.iter().enumerate() {
                    let entry = pkg.cp_entry(i as u16).expect("entry present");
                    prop_assert_eq!(entry.tag, *tag);
                    prop_assert_eq!(&entry.info, info);
                }
            }

            /// Truncation never panics.
            #[test]
            fn cp_parser_truncation_never_panics(
                entry_count in 0u16..=8,
                truncate_at in 0usize..=512,
            ) {
                let aid = [0xA0u8, 0, 0, 0, 0x62];
                let entries: Vec<(u8, [u8; 3])> = (0..entry_count)
                    .map(|i| (((i % 6) + 1) as u8, [i as u8, 0, 0]))
                    .collect();
                let cap = build_cap_with_cp(&aid, &entries);
                let prefix = truncate_at.min(cap.len());
                let _ = parse(&cap[..prefix]);
            }
        }

        // ---------------------------------------------------------------
        // Applet
        // ---------------------------------------------------------------

        /// Strategy: an `(aid, offset)` pair where the AID has length
        /// in the ISO 7816-4 valid range `[5, 16]` and bytes are
        /// arbitrary. Used by the Applet round-trip proptest.
        fn applet_entry_strategy() -> impl Strategy<Value = (Vec<u8>, u16)> {
            (proptest::collection::vec(any::<u8>(), 5..=16), any::<u16>())
        }

        proptest! {
            /// Parser surfaces every applet with byte-identical AID + offset.
            #[test]
            fn applet_parser_round_trips_arbitrary_entries(
                entries in proptest::collection::vec(applet_entry_strategy(), 0..=4),
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let entry_refs: Vec<(&[u8], u16)> = entries
                    .iter()
                    .map(|(aid, offset)| (aid.as_slice(), *offset))
                    .collect();
                let cap = build_cap_with_applets(&pkg_aid, &entry_refs);
                let pkg = parse(&cap).expect("parse");
                prop_assert_eq!(pkg.applet_count as usize, entries.len());
                for (i, (aid, offset)) in entries.iter().enumerate() {
                    let info = pkg.applet(i as u8).expect("applet present");
                    prop_assert_eq!(info.aid_slice(), aid.as_slice());
                    prop_assert_eq!(info.install_method_offset, *offset);
                }
            }

            #[test]
            fn applet_parser_truncation_never_panics(
                applet_count in 0u8..=4u8,
                truncate_at in 0usize..=256,
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let dummy: &[u8] = &[0xA0, 0, 0, 0, 0x01, 0x02];
                let entries: Vec<(&[u8], u16)> = (0..applet_count)
                    .map(|i| (dummy, u16::from(i)))
                    .collect();
                let cap = build_cap_with_applets(&pkg_aid, &entries);
                let prefix = truncate_at.min(cap.len());
                let _ = parse(&cap[..prefix]);
            }
        }

        // ---------------------------------------------------------------
        // Import
        // ---------------------------------------------------------------

        /// Strategy: a `(minor, major, aid)` triple matching the
        /// `import_info` shape used by the Import round-trip proptest.
        fn import_entry_strategy() -> impl Strategy<Value = (u8, u8, Vec<u8>)> {
            (
                any::<u8>(),
                any::<u8>(),
                proptest::collection::vec(any::<u8>(), 5..=16),
            )
        }

        proptest! {
            #[test]
            fn import_parser_round_trips_arbitrary_entries(
                entries in proptest::collection::vec(import_entry_strategy(), 0..=8),
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let entry_refs: Vec<(u8, u8, &[u8])> = entries
                    .iter()
                    .map(|(minor, major, aid)| (*minor, *major, aid.as_slice()))
                    .collect();
                let cap = build_cap_with_imports(&pkg_aid, &entry_refs);
                let pkg = parse(&cap).expect("parse");
                prop_assert_eq!(pkg.import_count as usize, entries.len());
                for (i, (minor, major, aid)) in entries.iter().enumerate() {
                    let info = pkg.import(i as u8).expect("import present");
                    prop_assert_eq!(info.minor_version, *minor);
                    prop_assert_eq!(info.major_version, *major);
                    prop_assert_eq!(info.aid_slice(), aid.as_slice());
                }
            }

            #[test]
            fn import_parser_truncation_never_panics(
                import_count in 0u8..=8u8,
                truncate_at in 0usize..=512,
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let dummy: &[u8] = &[0xA0, 0, 0, 0, 0x01];
                let entries: Vec<(u8, u8, &[u8])> = (0..import_count)
                    .map(|_| (0, 0, dummy))
                    .collect();
                let cap = build_cap_with_imports(&pkg_aid, &entries);
                let prefix = truncate_at.min(cap.len());
                let _ = parse(&cap[..prefix]);
            }
        }

        // ---------------------------------------------------------------
        // Export
        // ---------------------------------------------------------------

        /// Strategy: a `(class_offset, static_field_offsets,
        /// static_method_offsets)` triple matching the Export
        /// component's per-class entry. Field/method counts stay
        /// within `MAX_EXPORTED_*_PER_CLASS` to keep the parser's
        /// happy path; the rejection paths for over-cap counts are
        /// covered by separate fixed-input tests.
        fn export_class_strategy() -> impl Strategy<Value = (u16, Vec<u16>, Vec<u16>)> {
            (
                any::<u16>(),
                proptest::collection::vec(any::<u16>(), 0..=MAX_EXPORTED_FIELDS_PER_CLASS),
                proptest::collection::vec(any::<u16>(), 0..=MAX_EXPORTED_METHODS_PER_CLASS),
            )
        }

        proptest! {
            #[test]
            fn export_parser_round_trips_arbitrary_classes(
                classes in proptest::collection::vec(export_class_strategy(), 0..=4),
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let class_refs: Vec<(u16, &[u16], &[u16])> = classes
                    .iter()
                    .map(|(o, f, m)| (*o, f.as_slice(), m.as_slice()))
                    .collect();
                let cap = build_cap_with_exports(&pkg_aid, &class_refs);
                let pkg = parse(&cap).expect("parse");
                prop_assert_eq!(pkg.export_count as usize, classes.len());
                for (i, (offset, fields, methods)) in classes.iter().enumerate() {
                    let info = pkg.export(i as u8).expect("export present");
                    prop_assert_eq!(info.class_offset, *offset);
                    prop_assert_eq!(info.static_field_count as usize, fields.len());
                    prop_assert_eq!(info.static_method_count as usize, methods.len());
                    for (j, f) in fields.iter().enumerate() {
                        prop_assert_eq!(info.static_field_offset(j as u8), Some(*f));
                    }
                    for (j, m) in methods.iter().enumerate() {
                        prop_assert_eq!(info.static_method_offset(j as u8), Some(*m));
                    }
                }
            }

            #[test]
            fn export_parser_truncation_never_panics(
                class_count in 0u8..=4u8,
                fields_count in 0u8..=8u8,
                methods_count in 0u8..=8u8,
                truncate_at in 0usize..=512,
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let fields: Vec<u16> = (0..fields_count).map(u16::from).collect();
                let methods: Vec<u16> = (0..methods_count).map(u16::from).collect();
                let class_refs: Vec<(u16, &[u16], &[u16])> = (0..class_count)
                    .map(|_| (0u16, fields.as_slice(), methods.as_slice()))
                    .collect();
                let cap = build_cap_with_exports(&pkg_aid, &class_refs);
                let prefix = truncate_at.min(cap.len());
                let _ = parse(&cap[..prefix]);
            }
        }

        // ---------------------------------------------------------------
        // RefLocation
        // ---------------------------------------------------------------

        proptest! {
            #[test]
            fn ref_loc_parser_round_trips_arbitrary_deltas(
                byte_deltas in proptest::collection::vec(any::<u8>(), 0..=MAX_REF_LOC_BYTE_INDICES),
                byte2_deltas in proptest::collection::vec(any::<u8>(), 0..=MAX_REF_LOC_BYTE2_INDICES),
            ) {
                let aid = [0xA0u8, 0, 0, 0, 0x62];
                let cap = build_cap_with_ref_loc(&aid, &byte_deltas, &byte2_deltas);
                let pkg = parse(&cap).expect("parse");
                prop_assert_eq!(pkg.ref_loc_byte_count as usize, byte_deltas.len());
                prop_assert_eq!(pkg.ref_loc_byte2_count as usize, byte2_deltas.len());
                prop_assert_eq!(pkg.ref_loc_byte_deltas(), byte_deltas.as_slice());
                prop_assert_eq!(pkg.ref_loc_byte2_deltas(), byte2_deltas.as_slice());
            }

            #[test]
            fn ref_loc_parser_truncation_never_panics(
                byte_count in 0usize..=64,
                byte2_count in 0usize..=32,
                truncate_at in 0usize..=512,
            ) {
                let aid = [0xA0u8, 0, 0, 0, 0x62];
                let byte_deltas = vec![0xAAu8; byte_count];
                let byte2_deltas = vec![0xBBu8; byte2_count];
                let cap = build_cap_with_ref_loc(&aid, &byte_deltas, &byte2_deltas);
                let prefix = truncate_at.min(cap.len());
                let _ = parse(&cap[..prefix]);
            }
        }

        // ---------------------------------------------------------------
        // StaticField
        // ---------------------------------------------------------------

        proptest! {
            #[test]
            fn static_field_parser_round_trips_image_and_refs(
                image_size in 0u16..=u16::MAX,
                reference_count in 0u16..=u16::MAX,
            ) {
                let aid = [0xA0u8, 0, 0, 0, 0x62];
                let cap = build_cap_with_static_field(&aid, image_size, reference_count);
                let pkg = parse(&cap).expect("parse");
                prop_assert_eq!(pkg.static_field_image_size, image_size);
                prop_assert_eq!(pkg.static_reference_count, reference_count);
            }

            #[test]
            fn static_field_parser_truncation_never_panics(
                truncate_at in 0usize..=128,
            ) {
                let aid = [0xA0u8, 0, 0, 0, 0x62];
                let cap = build_cap_with_static_field(&aid, 0xABCD, 0x1234);
                let prefix = truncate_at.min(cap.len());
                let _ = parse(&cap[..prefix]);
            }
        }

        // ---------------------------------------------------------------
        // Class
        // ---------------------------------------------------------------

        /// Build a `class_info` body with caller-controlled method/interface
        /// counts for proptest variable-walk validation.
        #[allow(clippy::cast_possible_truncation)]
        fn build_class_info_with_counts(
            public_count: u8,
            package_count: u8,
            interface_count: u8,
        ) -> Vec<u8> {
            let interface_bits = interface_count & 0x0F;
            let mut body = Vec::new();
            body.push(interface_bits);
            body.extend_from_slice(&0xFFFFu16.to_be_bytes());
            body.push(0); // declared_instance_size
            body.push(0); // first_reference_token
            body.push(0); // reference_count
            body.push(0); // public_method_table_base
            body.push(public_count);
            body.push(0); // package_method_table_base
            body.push(package_count);
            for i in 0..public_count {
                body.extend_from_slice(&u16::from(i).to_be_bytes());
            }
            for i in 0..package_count {
                body.extend_from_slice(&u16::from(i).to_be_bytes());
            }
            for _ in 0..interface_bits {
                body.extend_from_slice(&0u16.to_be_bytes());
                body.push(0); // count = 0 indices
            }
            body
        }

        proptest! {
            /// Parser walks every variable-size sub-section correctly.
            #[test]
            fn class_parser_handles_arbitrary_variable_table_sizes(
                public_count in 0u8..=255,
                package_count in 0u8..=255,
                interface_count in 0u8..=15,
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let body = build_class_info_with_counts(
                    public_count, package_count, interface_count,
                );
                let cap = build_cap_with_class(&pkg_aid, &body);
                let pkg = parse(&cap).expect("parse");
                prop_assert_eq!(pkg.class_count, 1);
                let info = pkg.class(0).expect("class 0");
                prop_assert_eq!(info.public_method_table_count, public_count);
                prop_assert_eq!(info.package_method_table_count, package_count);
                prop_assert_eq!(info.interface_count, interface_count);
                prop_assert_eq!(info.component_offset, 0);
            }

            /// Snapshot round-trip property over arbitrary `ClassInfo`.
            #[test]
            fn class_snapshot_save_restore_round_trip(
                component_offset in 0u16..=u16::MAX,
                super_internal in 0u16..=0x7FFF,
                super_external_pkg in 0u8..=0x7F,
                super_external_class in 0u8..=0xFF,
                use_external in any::<bool>(),
                instance_size in 0u8..=255,
                first_ref in 0u8..=255,
                ref_count in 0u8..=255,
                pub_base in 0u8..=255,
                pub_count in 0u8..=255,
                pkg_base in 0u8..=255,
                pkg_count in 0u8..=255,
                iface_count in 0u8..=15,
            ) {
                let super_class_ref = if use_external {
                    ClassRef::External {
                        package_token: super_external_pkg,
                        class_token: super_external_class,
                    }
                } else {
                    ClassRef::Internal(super_internal)
                };
                let info = ClassInfo {
                    component_offset,
                    super_class_ref,
                    declared_instance_size: instance_size,
                    first_reference_token: first_ref,
                    reference_count: ref_count,
                    public_method_table_base: pub_base,
                    public_method_table_count: pub_count,
                    package_method_table_base: pkg_base,
                    package_method_table_count: pkg_count,
                    interface_count: iface_count,
                };

                let mut pkg = Package::empty();
                pkg.aid_len = 1;
                pkg.aid[0] = 0xAA;
                pkg.classes[0] = Some(info);
                pkg.class_count = 1;

                let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
                let n = pkg.save_state(&mut snap);
                prop_assert!(n > 0);

                let mut pkg2 = Package::empty();
                prop_assert!(pkg2.restore_state(&snap[..n]));
                prop_assert_eq!(pkg2.class_count, 1);
                prop_assert_eq!(pkg2.classes[0], Some(info));
            }

            #[test]
            fn class_parser_truncation_never_panics(
                public_count in 0u8..=8,
                interface_count in 0u8..=4,
                truncate_at in 0usize..=256,
            ) {
                let pkg_aid = [0xA0u8, 0, 0, 0, 0x62];
                let body = build_class_info_with_counts(public_count, 0, interface_count);
                let cap = build_cap_with_class(&pkg_aid, &body);
                let prefix = truncate_at.min(cap.len());
                let _ = parse(&cap[..prefix]);
            }
        }

        // ===============================================================
        // Snapshot round-trip proptests
        // ===============================================================
        //
        // For every component, plant arbitrary state directly on a
        // `Package`, save_state -> restore_state -> assert byte-identical
        // recovery. These complement the parser round-trip proptests
        // above (which run bytes->Package->fields) by covering the
        // Package->bytes->Package direction. Together they verify that
        // both the on-disk and on-snapshot serialisations are lossless
        // for every component.

        proptest! {
            /// CP snapshot round-trip with arbitrary entries.
            #[test]
            fn cp_snapshot_save_restore_round_trip(
                entries in proptest::collection::vec(cp_entry_strategy(), 0..=MAX_CP_ENTRIES),
            ) {
                let mut pkg = Package::empty();
                pkg.aid_len = 1;
                pkg.aid[0] = 0xAA;
                for (i, (tag, info)) in entries.iter().enumerate() {
                    pkg.constant_pool[i] = CpInfo {
                        tag: *tag,
                        info: *info,
                    };
                }
                pkg.cp_count = entries.len() as u16;

                let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
                let n = pkg.save_state(&mut snap);
                prop_assert!(n > 0);

                let mut pkg2 = Package::empty();
                prop_assert!(pkg2.restore_state(&snap[..n]));
                prop_assert_eq!(pkg2.cp_count as usize, entries.len());
                for (i, (tag, info)) in entries.iter().enumerate() {
                    let entry = pkg2.cp_entry(i as u16).expect("entry present");
                    prop_assert_eq!(entry.tag, *tag);
                    prop_assert_eq!(&entry.info, info);
                }
            }

            /// Applet snapshot round-trip with arbitrary entries.
            #[test]
            fn applet_snapshot_save_restore_round_trip(
                entries in proptest::collection::vec(applet_entry_strategy(), 0..=MAX_APPLETS_PER_PACKAGE),
            ) {
                let mut pkg = Package::empty();
                pkg.aid_len = 1;
                pkg.aid[0] = 0xAA;
                for (i, (aid, offset)) in entries.iter().enumerate() {
                    let mut info = AppletInfo::empty();
                    info.aid_len = aid.len() as u8;
                    info.aid[..aid.len()].copy_from_slice(aid);
                    info.install_method_offset = *offset;
                    pkg.applets[i] = Some(info);
                }
                pkg.applet_count = entries.len() as u8;

                let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
                let n = pkg.save_state(&mut snap);
                prop_assert!(n > 0);

                let mut pkg2 = Package::empty();
                prop_assert!(pkg2.restore_state(&snap[..n]));
                prop_assert_eq!(pkg2.applet_count as usize, entries.len());
                for (i, (aid, offset)) in entries.iter().enumerate() {
                    let info = pkg2.applet(i as u8).expect("applet present");
                    prop_assert_eq!(info.aid_slice(), aid.as_slice());
                    prop_assert_eq!(info.install_method_offset, *offset);
                }
            }

            /// Import snapshot round-trip with arbitrary entries.
            #[test]
            fn import_snapshot_save_restore_round_trip(
                entries in proptest::collection::vec(import_entry_strategy(), 0..=MAX_IMPORTS_PER_PACKAGE),
            ) {
                let mut pkg = Package::empty();
                pkg.aid_len = 1;
                pkg.aid[0] = 0xAA;
                for (i, (minor, major, aid)) in entries.iter().enumerate() {
                    let mut info = ImportInfo::empty();
                    info.minor_version = *minor;
                    info.major_version = *major;
                    info.aid_len = aid.len() as u8;
                    info.aid[..aid.len()].copy_from_slice(aid);
                    pkg.imports[i] = Some(info);
                }
                pkg.import_count = entries.len() as u8;

                let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
                let n = pkg.save_state(&mut snap);
                prop_assert!(n > 0);

                let mut pkg2 = Package::empty();
                prop_assert!(pkg2.restore_state(&snap[..n]));
                prop_assert_eq!(pkg2.import_count as usize, entries.len());
                for (i, (minor, major, aid)) in entries.iter().enumerate() {
                    let info = pkg2.import(i as u8).expect("import present");
                    prop_assert_eq!(info.minor_version, *minor);
                    prop_assert_eq!(info.major_version, *major);
                    prop_assert_eq!(info.aid_slice(), aid.as_slice());
                }
            }

            /// Export snapshot round-trip with arbitrary classes.
            #[test]
            fn export_snapshot_save_restore_round_trip(
                classes in proptest::collection::vec(export_class_strategy(), 0..=MAX_EXPORTED_CLASSES_PER_PACKAGE),
            ) {
                let mut pkg = Package::empty();
                pkg.aid_len = 1;
                pkg.aid[0] = 0xAA;
                for (i, (offset, fields, methods)) in classes.iter().enumerate() {
                    let mut info = ExportInfo::empty();
                    info.class_offset = *offset;
                    info.static_field_count = fields.len() as u8;
                    info.static_method_count = methods.len() as u8;
                    for (j, f) in fields.iter().enumerate() {
                        info.static_field_offsets[j] = *f;
                    }
                    for (j, m) in methods.iter().enumerate() {
                        info.static_method_offsets[j] = *m;
                    }
                    pkg.exports[i] = Some(info);
                }
                pkg.export_count = classes.len() as u8;

                let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
                let n = pkg.save_state(&mut snap);
                prop_assert!(n > 0);

                let mut pkg2 = Package::empty();
                prop_assert!(pkg2.restore_state(&snap[..n]));
                prop_assert_eq!(pkg2.export_count as usize, classes.len());
                for (i, (offset, fields, methods)) in classes.iter().enumerate() {
                    let info = pkg2.export(i as u8).expect("export present");
                    prop_assert_eq!(info.class_offset, *offset);
                    prop_assert_eq!(info.static_field_count as usize, fields.len());
                    prop_assert_eq!(info.static_method_count as usize, methods.len());
                    for (j, f) in fields.iter().enumerate() {
                        prop_assert_eq!(info.static_field_offset(j as u8), Some(*f));
                    }
                    for (j, m) in methods.iter().enumerate() {
                        prop_assert_eq!(info.static_method_offset(j as u8), Some(*m));
                    }
                }
            }

            /// RefLocation snapshot round-trip with arbitrary deltas.
            #[test]
            fn ref_loc_snapshot_save_restore_round_trip(
                byte_deltas in proptest::collection::vec(any::<u8>(), 0..=MAX_REF_LOC_BYTE_INDICES),
                byte2_deltas in proptest::collection::vec(any::<u8>(), 0..=MAX_REF_LOC_BYTE2_INDICES),
            ) {
                let mut pkg = Package::empty();
                pkg.aid_len = 1;
                pkg.aid[0] = 0xAA;
                for (i, b) in byte_deltas.iter().enumerate() {
                    pkg.ref_loc_byte_deltas[i] = *b;
                }
                pkg.ref_loc_byte_count = byte_deltas.len() as u16;
                for (i, b) in byte2_deltas.iter().enumerate() {
                    pkg.ref_loc_byte2_deltas[i] = *b;
                }
                pkg.ref_loc_byte2_count = byte2_deltas.len() as u16;

                let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
                let n = pkg.save_state(&mut snap);
                prop_assert!(n > 0);

                let mut pkg2 = Package::empty();
                prop_assert!(pkg2.restore_state(&snap[..n]));
                prop_assert_eq!(pkg2.ref_loc_byte_count as usize, byte_deltas.len());
                prop_assert_eq!(pkg2.ref_loc_byte_deltas(), byte_deltas.as_slice());
                prop_assert_eq!(pkg2.ref_loc_byte2_count as usize, byte2_deltas.len());
                prop_assert_eq!(pkg2.ref_loc_byte2_deltas(), byte2_deltas.as_slice());
            }

            /// StaticField snapshot round-trip with arbitrary values.
            #[test]
            fn static_field_snapshot_save_restore_round_trip(
                image_size in any::<u16>(),
                reference_count in any::<u16>(),
            ) {
                let mut pkg = Package::empty();
                pkg.aid_len = 1;
                pkg.aid[0] = 0xAA;
                pkg.static_field_image_size = image_size;
                pkg.static_reference_count = reference_count;

                let mut snap = [0u8; Package::MAX_SNAPSHOT_SIZE];
                let n = pkg.save_state(&mut snap);
                prop_assert!(n > 0);

                let mut pkg2 = Package::empty();
                prop_assert!(pkg2.restore_state(&snap[..n]));
                prop_assert_eq!(pkg2.static_field_image_size, image_size);
                prop_assert_eq!(pkg2.static_reference_count, reference_count);
            }
        }
    }
}
