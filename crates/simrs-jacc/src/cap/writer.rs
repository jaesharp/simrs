//! CAP file writer.
//!
//! Produces binary CAP blobs from compiled JCVM bytecodes.
//!
//! Two output formats are supported:
//!
//! - **Full CAP** ([`CapWriter::write`]): Produces a proper JCVM 3.1 Chapter 6
//!   component-based CAP binary with tag+length-prefixed components in order.
//!
//! - **Simplified blob** ([`write_cap`]): Produces the compact binary blob format
//!   understood by [`simrs_jcvm::cap::parse_cap`] for `no_std` embedded loading.

use simrs_jccompile::codegen::CompiledClass;
use simrs_jcvm::cap::{CAP_MAGIC, METHOD_FLAG_STATIC};

/// CAP file format version: Java Card 3.1 (major=3, minor=1).
const CAP_MAJOR_VERSION: u8 = 3;
const CAP_MINOR_VERSION: u8 = 1;

/// Package format version for our generated packages.
const PACKAGE_MAJOR_VERSION: u8 = 1;
const PACKAGE_MINOR_VERSION: u8 = 0;

/// Component tags per JCVM 3.1 Section 6.2.
const TAG_HEADER: u8 = 1;
const TAG_DIRECTORY: u8 = 2;
const TAG_APPLET: u8 = 3;
const TAG_IMPORT: u8 = 4;
const TAG_CONSTANT_POOL: u8 = 5;
const TAG_CLASS: u8 = 6;
const TAG_METHOD: u8 = 7;
const TAG_STATIC_FIELD: u8 = 8;
const TAG_REFERENCE_LOCATION: u8 = 9;
const TAG_EXPORT: u8 = 10;
const TAG_DESCRIPTOR: u8 = 11;
const TAG_DEBUG: u8 = 12;
const TAG_STATIC_RESOURCES: u8 = 13;

/// Number of component size slots in the directory component.
/// Covers tags 1..13 (header through `StaticResources`), indexed as tag-1.
const COMPONENT_SIZE_COUNT: usize = 13;

/// Header component flags.
const FLAG_HAS_APPLET: u8 = 0x01;

/// Method header flags: bit 3 = extended header format.
const METHOD_HEADER_EXTENDED: u8 = 0x08;

/// Default stack/locals for compiled methods.
const DEFAULT_MAX_STACK: u8 = 8;
const DEFAULT_MAX_LOCALS: u8 = 4;

/// Class access flags for the descriptor component.
const ACC_PUBLIC: u8 = 0x01;
const ACC_STATIC: u8 = 0x08;

/// Type descriptor nibble for `void` return.
const TYPE_DESC_VOID: u8 = 0x03;

/// Information about a field in the class.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name (for debugging).
    pub name: String,
    /// Field type token (0x02 = boolean, 0x03 = byte, 0x04 = short).
    pub type_token: u8,
    /// Byte offset within instance data.
    pub offset: u8,
    /// Whether the field is static.
    pub is_static: bool,
}

/// Internal sizes of each component (excluding tag+length prefix).
#[derive(Debug, Clone, Default)]
struct ComponentSizes {
    sizes: [u16; COMPONENT_SIZE_COUNT],
}

impl ComponentSizes {
    /// Set the size for a component by its tag.
    #[allow(clippy::cast_possible_truncation, clippy::missing_const_for_fn)]
    fn set(&mut self, tag: u8, size: u16) {
        let idx = (tag - 1) as usize;
        if idx < COMPONENT_SIZE_COUNT {
            self.sizes[idx] = size;
        }
    }
}

/// Full CAP file writer per JCVM 3.1 Chapter 6.
///
/// Builds all required components from a compiled class and produces
/// either the full component-based format or the simplified blob format.
pub struct CapWriter {
    /// Package AID (5-16 bytes).
    aid: Vec<u8>,
    /// Compiled bytecodes per method, in declaration order.
    methods: Vec<Vec<u8>>,
    /// Field information for the class.
    fields: Vec<FieldInfo>,
    /// Applet AID (usually same as package AID).
    applet_aid: Vec<u8>,
    /// Index of the install method (0-based).
    install_method: u8,
}

impl CapWriter {
    /// Create a new `CapWriter` from a compiled class.
    ///
    /// The applet AID defaults to the package AID, and the install method
    /// defaults to method 0.
    #[must_use]
    pub fn new(compiled: &CompiledClass) -> Self {
        Self {
            aid: compiled.aid.clone(),
            methods: compiled.methods.clone(),
            fields: Vec::new(),
            applet_aid: compiled.aid.clone(),
            install_method: 0,
        }
    }

    /// Set the applet AID (if different from the package AID).
    #[must_use]
    pub fn with_applet_aid(mut self, aid: Vec<u8>) -> Self {
        self.applet_aid = aid;
        self
    }

    /// Set the install method index.
    #[must_use]
    pub const fn with_install_method(mut self, index: u8) -> Self {
        self.install_method = index;
        self
    }

    /// Add field information to the writer.
    #[must_use]
    pub fn with_fields(mut self, fields: Vec<FieldInfo>) -> Self {
        self.fields = fields;
        self
    }

    /// Write the full JCVM 3.1 component-based CAP format.
    ///
    /// Returns a binary blob containing all components concatenated in order,
    /// each prefixed with `tag(1) | size(2 BE) | data(size)`.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        // Phase 1: Build all component bodies (data without tag+length prefix).
        let header_body = self.build_header_body();
        let applet_body = self.build_applet_body();
        let import_body = build_import_body();
        let constant_pool_body = build_constant_pool_body();
        let class_body = self.build_class_body();
        let method_body = self.build_method_body();
        let static_field_body = self.build_static_field_body();
        let ref_location_body = build_reference_location_body();
        let export_body = build_export_body();
        let descriptor_body = self.build_descriptor_body();
        let debug_body = build_debug_body();
        let static_resources_body = build_static_resources_body();

        // Phase 2: Compute component sizes (body only, tag+length excluded
        // per JCVM 3.1 Section 6.6 -- the directory stores the body size).
        let mut sizes = ComponentSizes::default();
        sizes.set(TAG_HEADER, header_body.len() as u16);
        // Directory size is set to 0 (self-referential per spec).
        sizes.set(TAG_DIRECTORY, 0);
        sizes.set(TAG_APPLET, applet_body.len() as u16);
        sizes.set(TAG_IMPORT, import_body.len() as u16);
        sizes.set(TAG_CONSTANT_POOL, constant_pool_body.len() as u16);
        sizes.set(TAG_CLASS, class_body.len() as u16);
        sizes.set(TAG_METHOD, method_body.len() as u16);
        sizes.set(TAG_STATIC_FIELD, static_field_body.len() as u16);
        sizes.set(TAG_REFERENCE_LOCATION, ref_location_body.len() as u16);
        sizes.set(TAG_EXPORT, export_body.len() as u16);
        sizes.set(TAG_DESCRIPTOR, descriptor_body.len() as u16);
        sizes.set(TAG_DEBUG, debug_body.len() as u16);
        sizes.set(TAG_STATIC_RESOURCES, static_resources_body.len() as u16);

        // Phase 3: Build the directory component (needs sizes).
        let directory_body = self.build_directory_body(&sizes);

        // Phase 4: Concatenate all components in order per JCVM 3.2 § 6.2.
        let mut out = Vec::new();

        emit_component(&mut out, TAG_HEADER, &header_body);
        emit_component(&mut out, TAG_DIRECTORY, &directory_body);
        emit_component(&mut out, TAG_APPLET, &applet_body);
        emit_component(&mut out, TAG_IMPORT, &import_body);
        emit_component(&mut out, TAG_CONSTANT_POOL, &constant_pool_body);
        emit_component(&mut out, TAG_CLASS, &class_body);
        emit_component(&mut out, TAG_METHOD, &method_body);
        emit_component(&mut out, TAG_STATIC_FIELD, &static_field_body);
        emit_component(&mut out, TAG_REFERENCE_LOCATION, &ref_location_body);
        emit_component(&mut out, TAG_EXPORT, &export_body);
        emit_component(&mut out, TAG_DESCRIPTOR, &descriptor_body);
        emit_component(&mut out, TAG_DEBUG, &debug_body);
        emit_component(&mut out, TAG_STATIC_RESOURCES, &static_resources_body);

        out
    }

    /// Write the simplified blob format compatible with
    /// [`simrs_jcvm::cap::parse_cap`].
    ///
    /// This produces the compact binary blob used for `no_std` embedded loading.
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_blob(&self) -> Vec<u8> {
        let methods_ref: Vec<&[u8]> = self.methods.iter().map(Vec::as_slice).collect();
        let mut buf = vec![0u8; 8192];
        let len = simrs_jcvm::cap::build_cap_blob(&self.aid, &methods_ref, &mut buf);
        buf.truncate(len);
        buf
    }

    // -----------------------------------------------------------------------
    // Component body builders (produce data without tag+length prefix)
    // -----------------------------------------------------------------------

    /// Build the Header component body (JCVM 3.1 Section 6.3).
    #[allow(clippy::cast_possible_truncation)]
    fn build_header_body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // magic: 4 bytes
        body.extend_from_slice(&CAP_MAGIC.to_be_bytes());

        // minor_version, major_version: 1 byte each
        body.push(CAP_MINOR_VERSION);
        body.push(CAP_MAJOR_VERSION);

        // flags: 1 byte (bit 0 = has applet component)
        body.push(FLAG_HAS_APPLET);

        // package_info:
        //   minor_version: 1 byte
        //   major_version: 1 byte
        //   aid_length: 1 byte
        //   aid: aid_length bytes
        body.push(PACKAGE_MINOR_VERSION);
        body.push(PACKAGE_MAJOR_VERSION);
        let aid_len = self.aid.len().min(16);
        body.push(aid_len as u8);
        body.extend_from_slice(&self.aid[..aid_len]);

        // No package_name (flag bit 2 not set).

        body
    }

    /// Build the Directory component body (JCVM 3.1 Section 6.6).
    #[allow(clippy::cast_possible_truncation)]
    fn build_directory_body(&self, sizes: &ComponentSizes) -> Vec<u8> {
        let mut body = Vec::new();

        // component_sizes: 13 x u16 BE (one slot per JCVM 3.2 § 6.2 tag).
        for size in &sizes.sizes {
            body.extend_from_slice(&size.to_be_bytes());
        }

        // static_field_image_size: u16 BE
        let static_count = self.fields.iter().filter(|f| f.is_static).count();
        body.extend_from_slice(&(static_count as u16).to_be_bytes());

        // import_count: u8
        body.push(0); // no imports for standalone applets

        // applet_count: u8
        body.push(1); // single applet

        // custom_count: u8
        body.push(0); // no custom components

        body
    }

    /// Build the Applet component body (JCVM 3.1 Section 6.5).
    #[allow(clippy::cast_possible_truncation)]
    fn build_applet_body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // count: u8
        body.push(1);

        // applet entry:
        //   aid_length: u8
        //   aid: aid_length bytes
        //   install_method_offset: u16 BE
        let aid_len = self.applet_aid.len().min(16);
        body.push(aid_len as u8);
        body.extend_from_slice(&self.applet_aid[..aid_len]);

        // install_method_offset: offset into method component.
        // For method N, the offset is computed as:
        //   handler_count(1) + sum of previous method sizes
        let offset = self.method_offset(self.install_method);
        body.extend_from_slice(&offset.to_be_bytes());

        body
    }

    /// Build the Class component body (JCVM 3.1 Section 6.9).
    #[allow(clippy::cast_possible_truncation)]
    fn build_class_body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // Single class definition:
        let instance_field_count = self.fields.iter().filter(|f| !f.is_static).count();

        // bitfield: u8 (bit 7 = interface flag, bits 0-3 = interface count)
        // Not an interface, no implemented interfaces.
        body.push(0x00);

        // super_class_ref: u16 BE (0xFFFF = java.lang.Object)
        body.extend_from_slice(&0xFFFFu16.to_be_bytes());

        // declared_instance_size: u8 (bytes of instance fields)
        body.push(instance_field_count as u8);

        // first_reference_token: u8
        body.push(0);

        // reference_count: u8
        body.push(0);

        // public_method_table_base: u8
        body.push(0);

        // public_method_table_count: u8
        body.push(self.methods.len() as u8);

        // package_method_table_base: u8
        body.push(0);

        // package_method_table_count: u8
        body.push(self.methods.len() as u8);

        // public_virtual_method_table: one entry per method.
        // Each entry is a u16 offset into method component.
        for i in 0..self.methods.len() {
            let offset = self.method_offset(i as u8);
            body.extend_from_slice(&offset.to_be_bytes());
        }

        body
    }

    /// Build the Method component body (JCVM 3.1 Section 6.10).
    fn build_method_body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // handler_count: u8 (no exception handlers)
        body.push(0);

        // Methods: each with extended header + bytecodes.
        for bytecode in &self.methods {
            // Extended header format (used when max_stack or nargs or
            // max_locals exceed 4 bits).
            //
            // method_header:
            //   flags byte: u8
            //     bit 3 = extended flag (always 1 for us)
            //   max_stack: u8
            //   nargs: u8
            //   max_locals: u8

            let flags = METHOD_FLAG_STATIC | METHOD_HEADER_EXTENDED;
            body.push(flags);
            body.push(DEFAULT_MAX_STACK);
            body.push(0); // nargs
            body.push(DEFAULT_MAX_LOCALS);

            // bytecodes
            body.extend_from_slice(bytecode);
        }

        body
    }

    /// Build the `StaticField` component body (JCVM 3.2 § 6.10).
    ///
    /// Spec layout: `image_size(u2) + reference_count(u2) +
    /// array_init_count(u2) + array_init[] + default_value_count(u2) +
    /// non_default_values[]`. The tail two trailing fields are spec-
    /// required; emitting only the first six bytes -- as this writer
    /// did before -- produces a CAP that strict parsers reject.
    #[allow(clippy::cast_possible_truncation)]
    fn build_static_field_body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // image_size: u16 BE -- size in bytes of the static-field image.
        let static_count = self.fields.iter().filter(|f| f.is_static).count();
        body.extend_from_slice(&(static_count as u16).to_be_bytes());

        // reference_count: u16 BE -- number of reference-typed entries.
        body.extend_from_slice(&0u16.to_be_bytes());

        // array_init_count: u16 BE -- no static-array initialisers.
        body.extend_from_slice(&0u16.to_be_bytes());

        // (array_init[] omitted because array_init_count == 0)

        // default_value_count: u16 BE -- length of the trailing
        // non_default_values blob; zero for our standalone applets,
        // which leave every static field at its default zero value.
        body.extend_from_slice(&0u16.to_be_bytes());

        // (non_default_values[] omitted because count == 0)

        body
    }

    /// Build the Descriptor component body (JCVM 3.1 Section 6.14).
    #[allow(clippy::cast_possible_truncation)]
    fn build_descriptor_body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // class_count: u8
        body.push(1); // single class

        // class descriptor:
        //   token: u8
        body.push(0); // class token 0

        //   access_flags: u8
        body.push(ACC_PUBLIC);

        //   class_ref (internal): u16 BE -- offset into class component
        body.extend_from_slice(&0u16.to_be_bytes());

        //   interface_count: u8
        body.push(0);

        //   field_count: u16 BE
        body.extend_from_slice(&(self.fields.len() as u16).to_be_bytes());

        //   method_count: u16 BE
        body.extend_from_slice(&(self.methods.len() as u16).to_be_bytes());

        // interfaces: [u16; 0] -- none

        // field descriptors
        for (i, field) in self.fields.iter().enumerate() {
            // token: u8
            body.push(i as u8);
            // access_flags: u8
            let flags = if field.is_static {
                ACC_PUBLIC | ACC_STATIC
            } else {
                ACC_PUBLIC
            };
            body.push(flags);
            // field_ref: u16 BE (offset or index)
            body.extend_from_slice(&u16::from(field.offset).to_be_bytes());
            // type: u8 (primitive type token)
            body.push(field.type_token);
        }

        // method descriptors
        for (i, bc) in self.methods.iter().enumerate() {
            let method_off = self.method_offset(i as u8);

            // token: u8
            body.push(i as u8);
            // access_flags: u8
            body.push(ACC_PUBLIC | ACC_STATIC);
            // method_offset: u16 BE (offset into method component)
            body.extend_from_slice(&method_off.to_be_bytes());
            // type_offset: u16 BE (offset into type descriptor area)
            // For simple void() or short() methods, point to a sentinel.
            body.extend_from_slice(&0u16.to_be_bytes());
            // bytecode_count: u16 BE
            body.extend_from_slice(&(bc.len() as u16).to_be_bytes());
            // exception_handler_count: u16 BE
            body.extend_from_slice(&0u16.to_be_bytes());
            // exception_handler_index: u16 BE
            body.extend_from_slice(&0u16.to_be_bytes());
        }

        // type_descriptors: nibble-encoded type sequences.
        // For our simple methods, emit a minimal type descriptor:
        // void return with no parameters = 0x03 (void) terminated.
        // This is a simplified encoding; a full implementation would
        // encode each method's actual signature.

        // Type descriptor count (u16 BE) -- one entry per method.
        body.extend_from_slice(&(self.methods.len() as u16).to_be_bytes());
        // Each type descriptor: nibble-encoded void() = 0x03.
        body.extend(core::iter::repeat_n(TYPE_DESC_VOID, self.methods.len()));

        body
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Compute the offset of method `index` within the method component body.
    ///
    /// The offset accounts for the `handler_count` byte (1) plus
    /// the extended header (4 bytes) and bytecodes of each preceding method.
    #[allow(clippy::cast_possible_truncation)]
    fn method_offset(&self, index: u8) -> u16 {
        // Skip handler_count byte.
        let mut offset: usize = 1;
        for i in 0..index as usize {
            if i < self.methods.len() {
                // Extended header: 4 bytes + bytecode length.
                offset += 4 + self.methods[i].len();
            }
        }
        offset as u16
    }
}

// ---------------------------------------------------------------------------
// Free-standing component builders for components that need no instance state
// ---------------------------------------------------------------------------

/// Build the Import component body (JCVM 3.1 Section 6.7).
///
/// Empty for standalone applets with no external references.
fn build_import_body() -> Vec<u8> {
    // count: u8 (no imports for standalone applets)
    vec![0]
}

/// Build the Constant Pool component body (JCVM 3.1 Section 6.8).
///
/// Empty for simple applets.
fn build_constant_pool_body() -> Vec<u8> {
    // count: u16 BE (empty)
    vec![0, 0]
}

/// Build the `ReferenceLocation` component body (JCVM 3.2 § 6.12).
///
/// Per spec the body has two count-prefixed delta lists. For
/// standalone applets with no external references, both counts are
/// zero -- so the body is exactly four zero bytes (two u16 BE counts
/// of zero) rather than an empty buffer; the runtime parser
/// requires the count fields to be present.
fn build_reference_location_body() -> Vec<u8> {
    vec![0, 0, 0, 0]
}

/// Build the Export component body (JCVM 3.2 Section 6.13).
///
/// Standalone applets export no symbols, so the body is just a
/// `class_count = 0`. Real library packages would emit class
/// descriptors with their public field/method tokens.
fn build_export_body() -> Vec<u8> {
    // class_count: u8 (no exports for standalone applets)
    vec![0]
}

/// Build the Debug component body (JCVM 3.2 Section 6.15).
///
/// Empty for release builds; the spec allows the component to be
/// omitted entirely, but emitting a zero-length body keeps the
/// component-tag sequence dense and makes round-trip testing
/// uniform across builds.
#[allow(clippy::missing_const_for_fn)]
fn build_debug_body() -> Vec<u8> {
    Vec::new()
}

/// Build the `StaticResources` component body (JCVM 3.2 Section 6.16,
/// added in CAP v2.3 / JC 3.0.5).
///
/// `count = 0` -- no embedded binary resources. Bumping this requires
/// per-resource records of `(resource_id u16 BE, length u16 BE, bytes)`.
fn build_static_resources_body() -> Vec<u8> {
    // count: u16 BE (no resources)
    vec![0, 0]
}

/// Emit a complete component: tag(1) | size(2 BE) | body.
#[allow(clippy::cast_possible_truncation)]
fn emit_component(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// Write a compiled class to the simplified CAP blob format.
///
/// Returns the CAP bytes suitable for loading via `simrs_jcvm::cap::parse_cap`.
///
/// This function preserves backward compatibility with the existing
/// `no_std` runtime loader.
#[must_use]
pub fn write_cap(compiled: &CompiledClass) -> Vec<u8> {
    CapWriter::new(compiled).write_blob()
}

/// Write a compiled class to the full JCVM 3.1 component-based CAP format.
///
/// Returns the CAP bytes with proper component tag+length framing.
#[must_use]
pub fn write_cap_full(compiled: &CompiledClass) -> Vec<u8> {
    CapWriter::new(compiled).write()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_jcvm::cap::parse_cap;

    fn sample_compiled() -> CompiledClass {
        CompiledClass {
            aid: vec![0xA0, 0x00, 0x00, 0x00, 0x62],
            methods: vec![
                vec![0x03, 0x78], // sconst_0, sreturn
            ],
        }
    }

    fn sample_compiled_multi() -> CompiledClass {
        CompiledClass {
            aid: vec![0xA0, 0x01, 0x02, 0x03, 0x04],
            methods: vec![
                vec![0x04, 0x78],     // sconst_1, sreturn
                vec![0x10, 42, 0x78], // bspush 42, sreturn
            ],
        }
    }

    // -- Backward compatibility tests (simplified blob format) --

    #[test]
    fn write_and_parse_roundtrip() {
        let compiled = sample_compiled();
        let cap_bytes = write_cap(&compiled);
        assert!(!cap_bytes.is_empty());

        let pkg = parse_cap(&cap_bytes).unwrap();
        assert!(pkg.aid_matches(&[0xA0, 0x00, 0x00, 0x00, 0x62]));
        assert_eq!(pkg.method_count, 1);
        let m = pkg.method(0).unwrap();
        assert_eq!(m.bytecode_len, 2);
        assert_eq!(&m.bytecode[..2], &[0x03, 0x78]);
    }

    #[test]
    fn write_multiple_methods() {
        let compiled = sample_compiled_multi();
        let cap_bytes = write_cap(&compiled);
        let pkg = parse_cap(&cap_bytes).unwrap();
        assert_eq!(pkg.method_count, 2);
    }

    #[test]
    fn old_format_blobs_still_parse() {
        // Build a blob the old way (build_cap_blob) and verify parse_cap reads it.
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62];
        let bc: &[u8] = &[0x04, 0x78];
        let mut buf = [0u8; 512];
        let len = simrs_jcvm::cap::build_cap_blob(&aid, &[bc], &mut buf);
        let pkg = parse_cap(&buf[..len]).unwrap();
        assert!(pkg.aid_matches(&aid));
        assert_eq!(pkg.method_count, 1);
    }

    // -- Component-tagged round-trip via the new parser ---------------------
    //
    // These tests are the cross-crate validation for
    // `simrs_jcvm::cap::components` -- they prove the writer's output
    // is consumed correctly by the new parser, end to end.

    #[test]
    fn component_tagged_roundtrip_single_method_aid_and_bytecode() {
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();
        // Sanity: this is the component-tagged shape (Header tag = 1).
        assert_eq!(cap[0], TAG_HEADER);

        // parse_cap must auto-route to the components parser.
        let pkg = parse_cap(&cap).expect("component-tagged parse");
        assert_eq!(
            pkg.aid_slice(),
            &compiled.aid,
            "AID round-trips byte-for-byte through writer + parser"
        );
        assert_eq!(pkg.method_count, 1);
        let m = pkg.method(0).unwrap();
        assert_eq!(m.bytecode_len as usize, compiled.methods[0].len());
        assert_eq!(
            &m.bytecode[..compiled.methods[0].len()],
            compiled.methods[0].as_slice(),
            "bytecode survives the writer's extended-header framing"
        );
    }

    #[test]
    fn component_tagged_roundtrip_multi_method_distinct_bodies() {
        // Adversarial: the two methods have different lengths AND
        // different content. A parser that conflates the methods (e.g.
        // single-method fallback path) would mis-attribute bytecodes;
        // a parser that mis-computes the per-method offset/length
        // would get the byte count wrong.
        let compiled = sample_compiled_multi();
        let cap = CapWriter::new(&compiled).write();

        let pkg = parse_cap(&cap).expect("multi-method parse");
        // method_count is u8; sample_compiled_multi has 2 methods, so
        // the cast is provably non-truncating in this test.
        #[allow(clippy::cast_possible_truncation)]
        let expected_count = compiled.methods.len() as u8;
        assert_eq!(pkg.method_count, expected_count);
        for (i, expected_bc) in compiled.methods.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let m = pkg.method(i as u8).unwrap_or_else(|| panic!("method {i}"));
            assert_eq!(
                m.bytecode_len as usize,
                expected_bc.len(),
                "method {i} length round-trips"
            );
            assert_eq!(
                &m.bytecode[..expected_bc.len()],
                expected_bc.as_slice(),
                "method {i} bytecode round-trips byte-for-byte"
            );
        }
    }

    #[test]
    fn component_tagged_roundtrip_with_aid_at_max_length() {
        // Boundary check: AIDs are 5..=16 bytes per ISO 7816-4. The
        // writer's Header packs aid_length as a u8 followed by aid
        // bytes; the parser must walk the same field correctly when
        // the AID hits the upper bound.
        let aid: Vec<u8> = (0..16u8).collect();
        let compiled = CompiledClass {
            aid: aid.clone(),
            methods: vec![vec![0x78]],
        };
        let cap = CapWriter::new(&compiled).write();
        let pkg = parse_cap(&cap).expect("16-byte AID parse");
        assert_eq!(pkg.aid_slice(), aid.as_slice());
    }

    #[test]
    fn writer_output_first_byte_is_header_tag_for_dispatch() {
        // The dispatcher in `parse_cap` distinguishes formats by the
        // first byte: tag 1 = component-tagged, 0xDE = simplified
        // blob. If the writer ever changes which component appears
        // first, this test fails loudly so the dispatcher can be
        // adjusted in lockstep.
        let cap = CapWriter::new(&sample_compiled()).write();
        assert_eq!(
            cap[0], TAG_HEADER,
            "Header must be the first component for parse_cap dispatch to work"
        );
    }

    #[test]
    fn component_tagged_roundtrip_constant_pool_count_zero() {
        // The writer currently emits a Constant Pool component with
        // `count = 0` (the applet uses no cross-class references).
        // The runtime parser must accept that and surface
        // `cp_count == 0`. If a future writer change starts emitting
        // real CP entries, this test will need to be widened to
        // assert the entries match what was written.
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();
        let pkg = parse_cap(&cap).expect("parse component-tagged CAP");
        assert_eq!(pkg.cp_count, 0);
        assert!(
            pkg.cp_entry(0).is_none(),
            "no entries should be reachable when cp_count is 0"
        );
    }

    // -- Full CAP format tests --

    #[test]
    fn full_cap_starts_with_header_component() {
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();

        // First byte is the header tag.
        assert_eq!(cap[0], TAG_HEADER);

        // Bytes 1-2 are the header body size (u16 BE).
        let header_size = u16::from_be_bytes([cap[1], cap[2]]);
        assert!(header_size > 0);

        // Header body starts with magic 0xDECAFFED.
        let magic = u32::from_be_bytes([cap[3], cap[4], cap[5], cap[6]]);
        assert_eq!(magic, CAP_MAGIC);
    }

    #[test]
    fn full_cap_component_tags_in_order() {
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();

        // Walk the components and collect tags.
        let mut tags = Vec::new();
        let mut pos = 0;
        while pos < cap.len() {
            let tag = cap[pos];
            let size = u16::from_be_bytes([cap[pos + 1], cap[pos + 2]]) as usize;
            tags.push(tag);
            pos += 3 + size;
        }

        // Expected component order per JCVM 3.2 § 6.2:
        // 1,2,3,4,5,6,7,8,9,10,11,12,13.
        let expected = vec![
            TAG_HEADER,
            TAG_DIRECTORY,
            TAG_APPLET,
            TAG_IMPORT,
            TAG_CONSTANT_POOL,
            TAG_CLASS,
            TAG_METHOD,
            TAG_STATIC_FIELD,
            TAG_REFERENCE_LOCATION,
            TAG_EXPORT,
            TAG_DESCRIPTOR,
            TAG_DEBUG,
            TAG_STATIC_RESOURCES,
        ];
        assert_eq!(tags, expected);
    }

    #[test]
    fn export_component_is_empty() {
        // Standalone applet -- Export component carries `class_count = 0`
        // (1 byte). Anything beyond that means we accidentally promoted
        // an internal symbol to the export table.
        let cap = CapWriter::new(&sample_compiled()).write();
        let body = find_component_body(&cap, TAG_EXPORT).expect("Export component present");
        assert_eq!(body, &[0u8], "Export must contain only `class_count = 0`");
    }

    #[test]
    fn debug_component_is_empty() {
        // Release-shape: Debug body has zero length. The component
        // is still emitted (tag + size=0) so the directory's
        // size-by-tag table stays well-formed.
        let cap = CapWriter::new(&sample_compiled()).write();
        let body = find_component_body(&cap, TAG_DEBUG).expect("Debug component present");
        assert!(body.is_empty(), "Debug body should be zero-length");
    }

    #[test]
    fn static_resources_component_is_empty_count_pair() {
        // StaticResources count is u16 BE; 0x0000 means "no resources".
        let cap = CapWriter::new(&sample_compiled()).write();
        let body = find_component_body(&cap, TAG_STATIC_RESOURCES)
            .expect("StaticResources component present");
        assert_eq!(
            body,
            &[0u8, 0u8],
            "StaticResources must carry a u16 BE count of 0"
        );
    }

    #[test]
    fn full_cap_with_new_components_still_round_trips_through_dispatcher() {
        // Adding Export/Debug/StaticResources must not break the
        // dispatcher's ability to load the CAP. Header-tag dispatch
        // selects the component-tagged parser; the new components
        // are recognised-but-skipped by the runtime parser today,
        // so the AID and method should still come through.
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();
        let pkg = parse_cap(&cap).expect("parse component-tagged CAP with new components");
        assert!(pkg.aid_matches(&compiled.aid));
        assert_eq!(pkg.method_count, 1);
    }

    #[test]
    fn writer_static_field_round_trips_to_zero_image_and_refs() {
        // The writer emits image_size = static-field count = 0 for
        // a class with no static fields, plus zero ref/array/default
        // counts. The runtime parser must surface both numbers.
        let cap = CapWriter::new(&sample_compiled()).write();
        let pkg = parse_cap(&cap).expect("parse");
        assert_eq!(pkg.static_field_image_size, 0);
        assert_eq!(pkg.static_reference_count, 0);
    }

    #[test]
    fn writer_ref_location_round_trips_to_zero_deltas() {
        // The writer emits a zero-length RefLocation body; runtime
        // surfaces both delta lists as empty.
        let cap = CapWriter::new(&sample_compiled()).write();
        let pkg = parse_cap(&cap).expect("parse");
        assert_eq!(pkg.ref_loc_byte_count, 0);
        assert_eq!(pkg.ref_loc_byte2_count, 0);
        assert_eq!(pkg.ref_loc_byte_deltas(), &[] as &[u8]);
        assert_eq!(pkg.ref_loc_byte2_deltas(), &[] as &[u8]);
    }

    #[test]
    fn writer_export_component_round_trips_to_zero_classes() {
        // The writer emits an Export component with `class_count = 0`.
        // The runtime parser must surface `export_count == 0`.
        let cap = CapWriter::new(&sample_compiled()).write();
        let pkg = parse_cap(&cap).expect("parse");
        assert_eq!(pkg.export_count, 0);
        assert!(pkg.export(0).is_none());
    }

    #[test]
    fn writer_import_component_round_trips_to_zero_imports() {
        // The writer emits an empty Import component (`count = 0`)
        // for standalone applets. The runtime parser must surface
        // `import_count == 0` and refuse to dereference any package
        // token via `pkg.import(..)`.
        let cap = CapWriter::new(&sample_compiled()).write();
        let pkg = parse_cap(&cap).expect("parse");
        assert_eq!(pkg.import_count, 0);
        assert!(pkg.import(0).is_none());
    }

    #[test]
    fn writer_applet_component_round_trips_through_runtime_parser() {
        // The writer emits a 1-applet body with the install method
        // pointing at method 0. The runtime parser must surface that
        // applet on `pkg.applets[0]` with the matching AID and offset.
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();
        let pkg = parse_cap(&cap).expect("parse");
        assert_eq!(
            pkg.applet_count, 1,
            "writer emits exactly one applet by default"
        );
        let info = pkg.applet(0).expect("applet 0 present");
        assert_eq!(
            info.aid_slice(),
            compiled.aid.as_slice(),
            "applet AID defaults to package AID"
        );
        // The writer's install_method_offset for method 0 is the
        // header_count(1) prefix of the Method component body, i.e. 1.
        assert_eq!(
            info.install_method_offset, 1,
            "method 0's offset is right after the 1-byte handler_count"
        );
    }

    #[test]
    fn full_cap_header_contains_aid() {
        let compiled = CompiledClass {
            aid: vec![0xB0, 0x01, 0x02, 0x03, 0x04, 0x05],
            methods: vec![vec![0x03, 0x78]],
        };
        let cap = CapWriter::new(&compiled).write();

        // Parse header component body.
        assert_eq!(cap[0], TAG_HEADER);
        let header_size = u16::from_be_bytes([cap[1], cap[2]]) as usize;
        let header_body = &cap[3..3 + header_size];

        // magic(4) + minor(1) + major(1) + flags(1) + pkg_minor(1) + pkg_major(1) + aid_len(1)
        let aid_len_pos = 4 + 1 + 1 + 1 + 1 + 1;
        let aid_len = header_body[aid_len_pos] as usize;
        assert_eq!(aid_len, 6);
        let aid_start = aid_len_pos + 1;
        assert_eq!(
            &header_body[aid_start..aid_start + aid_len],
            &[0xB0, 0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn full_cap_directory_has_correct_sizes() {
        let compiled = sample_compiled();
        let writer = CapWriter::new(&compiled);
        let cap = writer.write();

        // Find the directory component (second component).
        let header_size = u16::from_be_bytes([cap[1], cap[2]]) as usize;
        let dir_start = 3 + header_size;
        assert_eq!(cap[dir_start], TAG_DIRECTORY);
        let dir_size = u16::from_be_bytes([cap[dir_start + 1], cap[dir_start + 2]]) as usize;
        let dir_body = &cap[dir_start + 3..dir_start + 3 + dir_size];

        // First 26 bytes are 13 x u16 component sizes per JCVM 3.2 § 6.2.
        // sizes[0] = header component body size
        let stored_header_size = u16::from_be_bytes([dir_body[0], dir_body[1]]);
        assert_eq!(stored_header_size as usize, header_size);

        // sizes[1] = directory size (must be 0, self-referential)
        let stored_dir_size = u16::from_be_bytes([dir_body[2], dir_body[3]]);
        assert_eq!(stored_dir_size, 0);
    }

    #[test]
    fn full_cap_applet_component_has_aid() {
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();

        // Walk to the applet component (tag 3).
        let applet_body = find_component_body(&cap, TAG_APPLET);
        assert!(applet_body.is_some());
        let applet_body = applet_body.unwrap();

        // count: u8
        assert_eq!(applet_body[0], 1);

        // aid_length: u8
        let aid_len = applet_body[1] as usize;
        assert_eq!(aid_len, 5);

        // aid bytes
        assert_eq!(
            &applet_body[2..2 + aid_len],
            &[0xA0, 0x00, 0x00, 0x00, 0x62]
        );
    }

    #[test]
    fn full_cap_method_component_contains_bytecodes() {
        let compiled = sample_compiled_multi();
        let cap = CapWriter::new(&compiled).write();

        let method_body = find_component_body(&cap, TAG_METHOD).unwrap();

        // handler_count: u8 = 0
        assert_eq!(method_body[0], 0);

        // Method 0: extended header (4 bytes) + bytecodes [0x04, 0x78].
        // The flags byte contains both METHOD_FLAG_STATIC and
        // METHOD_HEADER_EXTENDED (both are bit 3, so value = 0x08).
        let expected_flags = METHOD_FLAG_STATIC | METHOD_HEADER_EXTENDED;
        assert_eq!(method_body[1], expected_flags);
        // max_stack
        assert_eq!(method_body[2], DEFAULT_MAX_STACK);
        // nargs
        assert_eq!(method_body[3], 0);
        // max_locals
        assert_eq!(method_body[4], DEFAULT_MAX_LOCALS);
        // bytecodes for method 0
        assert_eq!(&method_body[5..7], &[0x04, 0x78]);

        // Method 1: header (4 bytes) + bytecodes [0x10, 42, 0x78]
        assert_eq!(method_body[7], expected_flags);
        assert_eq!(&method_body[11..14], &[0x10, 42, 0x78]);
    }

    #[test]
    fn full_cap_method_offsets_are_consistent() {
        let compiled = sample_compiled_multi();
        let writer = CapWriter::new(&compiled);

        // Method 0 offset: 1 (handler_count byte)
        assert_eq!(writer.method_offset(0), 1);

        // Method 1 offset: 1 + 4 (header) + 2 (bytecodes of method 0) = 7
        assert_eq!(writer.method_offset(1), 7);
    }

    #[test]
    fn full_cap_total_structure_parse() {
        // Verify every component can be walked without running off the end.
        let compiled = sample_compiled_multi();
        let cap = CapWriter::new(&compiled).write();

        let mut pos = 0;
        let mut component_count = 0;
        while pos < cap.len() {
            assert!(pos + 3 <= cap.len(), "truncated component at offset {pos}");
            let tag = cap[pos];
            let size = u16::from_be_bytes([cap[pos + 1], cap[pos + 2]]) as usize;
            assert!(
                pos + 3 + size <= cap.len(),
                "component tag={tag} at offset {pos} declares size {size} but only {} bytes remain",
                cap.len() - pos - 3
            );
            pos += 3 + size;
            component_count += 1;
        }
        // Exactly consumed all bytes.
        assert_eq!(pos, cap.len());
        // We emit all 13 components (tags 1..=13) per JCVM 3.2 § 6.2.
        assert_eq!(component_count, 13);
    }

    #[test]
    fn full_cap_descriptor_has_method_entries() {
        let compiled = sample_compiled_multi();
        let cap = CapWriter::new(&compiled).write();
        let desc_body = find_component_body(&cap, TAG_DESCRIPTOR).unwrap();

        // class_count: u8
        assert_eq!(desc_body[0], 1);
        // class token
        assert_eq!(desc_body[1], 0);
        // access_flags
        assert_eq!(desc_body[2], ACC_PUBLIC);
    }

    #[test]
    fn full_cap_empty_components_have_minimal_size() {
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();

        // Import component should have body size = 1 (just the count byte).
        let import_body = find_component_body(&cap, TAG_IMPORT).unwrap();
        assert_eq!(import_body.len(), 1);
        assert_eq!(import_body[0], 0); // 0 imports

        // Constant pool: body size = 2 (u16 count = 0).
        let cp_body = find_component_body(&cap, TAG_CONSTANT_POOL).unwrap();
        assert_eq!(cp_body.len(), 2);

        // Reference location: body size = 4 (two u16 BE counts of 0).
        let rl_body = find_component_body(&cap, TAG_REFERENCE_LOCATION).unwrap();
        assert_eq!(rl_body, &[0u8, 0, 0, 0]);
    }

    #[test]
    fn full_cap_static_field_component() {
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();
        let sf_body = find_component_body(&cap, TAG_STATIC_FIELD).unwrap();

        // image_size(2) + reference_count(2) + array_init_count(2) +
        // default_value_count(2) = 8 bytes -- the spec-mandated minimum
        // for an applet with no static fields and no array initialisers.
        assert_eq!(sf_body.len(), 8);
        // All zeros for a class with no static fields.
        assert!(sf_body.iter().all(|&b| b == 0));
    }

    #[test]
    fn full_cap_class_component_structure() {
        let compiled = sample_compiled();
        let cap = CapWriter::new(&compiled).write();
        let class_body = find_component_body(&cap, TAG_CLASS).unwrap();

        // bitfield: 0x00
        assert_eq!(class_body[0], 0x00);

        // super_class_ref: 0xFFFF (java.lang.Object)
        assert_eq!(class_body[1], 0xFF);
        assert_eq!(class_body[2], 0xFF);

        // declared_instance_size: 0
        assert_eq!(class_body[3], 0);
    }

    #[test]
    fn write_cap_full_function() {
        let compiled = sample_compiled();
        let cap = write_cap_full(&compiled);
        // Should start with header component.
        assert_eq!(cap[0], TAG_HEADER);
        // Should be a valid component stream.
        let mut pos = 0;
        while pos < cap.len() {
            let size = u16::from_be_bytes([cap[pos + 1], cap[pos + 2]]) as usize;
            pos += 3 + size;
        }
        assert_eq!(pos, cap.len());
    }

    #[test]
    fn cap_writer_builder_pattern() {
        let compiled = sample_compiled();
        let writer = CapWriter::new(&compiled)
            .with_applet_aid(vec![0xA0, 0x00, 0x00, 0x01, 0x01])
            .with_install_method(0);
        let cap = writer.write();
        let applet_body = find_component_body(&cap, TAG_APPLET).unwrap();
        // Verify the custom applet AID is in the applet component.
        assert_eq!(applet_body[1], 5); // aid_length
        assert_eq!(&applet_body[2..7], &[0xA0, 0x00, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn cap_writer_with_fields() {
        let compiled = sample_compiled();
        let writer = CapWriter::new(&compiled).with_fields(vec![
            FieldInfo {
                name: String::from("balance"),
                type_token: 0x04, // short
                offset: 0,
                is_static: false,
            },
            FieldInfo {
                name: String::from("counter"),
                type_token: 0x03, // byte
                offset: 1,
                is_static: true,
            },
        ]);
        let cap = writer.write();

        // Static field component should reflect one static field.
        let sf_body = find_component_body(&cap, TAG_STATIC_FIELD).unwrap();
        let image_size = u16::from_be_bytes([sf_body[0], sf_body[1]]);
        assert_eq!(image_size, 1); // 1 static field

        // Class component should have 1 instance field.
        let class_body = find_component_body(&cap, TAG_CLASS).unwrap();
        // declared_instance_size at offset 3
        assert_eq!(class_body[3], 1);

        // Descriptor should list 2 fields.
        let desc_body = find_component_body(&cap, TAG_DESCRIPTOR).unwrap();
        // field_count offset: class_count(1) + token(1) + access(1) + class_ref(2) + iface_count(1) = 6
        let field_count = u16::from_be_bytes([desc_body[6], desc_body[7]]);
        assert_eq!(field_count, 2);
    }

    #[test]
    fn full_cap_directory_sizes_match_actual_components() {
        // Verify that every size stored in the directory matches
        // the actual component body size.
        let compiled = sample_compiled_multi();
        let cap = CapWriter::new(&compiled).write();

        // Collect actual body sizes by tag.
        let mut actual_sizes: Vec<(u8, usize)> = Vec::new();
        let mut pos = 0;
        while pos + 3 <= cap.len() {
            let tag = cap[pos];
            let size = u16::from_be_bytes([cap[pos + 1], cap[pos + 2]]) as usize;
            actual_sizes.push((tag, size));
            pos += 3 + size;
        }

        // Read directory component sizes.
        let dir_body = find_component_body(&cap, TAG_DIRECTORY).unwrap();
        for &(tag, actual_size) in &actual_sizes {
            if tag == TAG_DIRECTORY {
                // Directory records its own size as 0 per spec.
                let stored = u16::from_be_bytes([dir_body[2], dir_body[3]]);
                assert_eq!(stored, 0);
                continue;
            }
            if !(1..=13).contains(&tag) {
                continue;
            }
            let idx = ((tag - 1) * 2) as usize;
            if idx + 1 < dir_body.len() {
                let stored = u16::from_be_bytes([dir_body[idx], dir_body[idx + 1]]) as usize;
                assert_eq!(
                    stored, actual_size,
                    "directory size mismatch for component tag={tag}: stored={stored} actual={actual_size}"
                );
            }
        }
    }

    // -- Test helper --

    /// Find a component body by tag, walking the component stream.
    fn find_component_body(cap: &[u8], target_tag: u8) -> Option<Vec<u8>> {
        let mut pos = 0;
        while pos + 3 <= cap.len() {
            let tag = cap[pos];
            let size = u16::from_be_bytes([cap[pos + 1], cap[pos + 2]]) as usize;
            if pos + 3 + size > cap.len() {
                return None;
            }
            if tag == target_tag {
                return Some(cap[pos + 3..pos + 3 + size].to_vec());
            }
            pos += 3 + size;
        }
        None
    }
}
