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

use super::{CAP_MAGIC, MAX_AID_LEN, MAX_BYTECODE, MAX_METHODS, MethodInfo, Package, ParseError};

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
#[allow(clippy::cast_possible_truncation)]
fn parse_methods(
    body: &[u8],
    method_offsets: &[(u16, u16)],
) -> Result<([Option<MethodInfo>; MAX_METHODS], u8), ParseError> {
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
    let mut count: u8 = 0;

    if method_offsets.is_empty() {
        // Fallback: treat the whole post-handler region as a single
        // method. Bytecodes run to the end of the body.
        let m = parse_one_method(&body[methods_start..])?;
        methods[0] = Some(m);
        count = 1;
        return Ok((methods, count));
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
        count += 1;
    }
    Ok((methods, count))
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
            // Recognised-but-skipped components (Directory, Applet,
            // Import, ConstantPool, Class, StaticField, RefLocation,
            // Export, Debug, StaticResources) and unknown components
            // (vendor-custom) all fall through. ConstantPool linking,
            // Class hierarchy, and StaticField images are Phase 2
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

    let (methods, method_count) = parse_methods(method_body, offset_slice)?;

    Ok(Package {
        aid,
        aid_len,
        methods,
        method_count,
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
}
