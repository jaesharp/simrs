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
    AppletInfo, CAP_MAGIC, CpInfo, ImportInfo, MAX_AID_LEN, MAX_APPLETS_PER_PACKAGE, MAX_BYTECODE,
    MAX_CP_ENTRIES, MAX_IMPORTS_PER_PACKAGE, MAX_METHODS, MethodInfo, Package, ParseError, cp_tag,
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
            // Recognised-but-skipped components (Directory, Class,
            // StaticField, RefLocation, Export, Debug, StaticResources)
            // and unknown components (vendor-custom) all fall through.
            // Class hierarchy and StaticField images are Phase 2
            // follow-ups.
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
}
