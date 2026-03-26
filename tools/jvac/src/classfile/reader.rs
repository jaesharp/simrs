//! Java classfile parser (JVMS Chapter 4).
//!
//! Parses the binary `.class` format into an in-memory representation
//! suitable for conversion to the JVA IR.

/// Magic number for Java classfiles.
pub const CLASS_MAGIC: u32 = 0xCAFE_BABE;

/// A parsed Java classfile.
#[derive(Debug, Clone)]
pub struct ClassFile {
    /// Class file version (minor, major).
    pub version: (u16, u16),
    /// Fully qualified class name (e.g., `com/example/Wallet`).
    pub class_name: String,
    /// Superclass name.
    pub super_class: String,
    /// Fields.
    pub fields: Vec<FieldInfo>,
    /// Methods.
    pub methods: Vec<MethodInfo>,
}

/// A field in the classfile.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name.
    pub name: String,
    /// JVM field descriptor (e.g., `S`, `B`, `[B`).
    pub descriptor: String,
    /// Access flags.
    pub access_flags: u16,
}

/// A method in the classfile.
#[derive(Debug, Clone)]
pub struct MethodInfo {
    /// Method name.
    pub name: String,
    /// JVM method descriptor (e.g., `(SS)S`).
    pub descriptor: String,
    /// Access flags.
    pub access_flags: u16,
    /// JVM bytecodes from the Code attribute (if present).
    pub code: Option<Vec<u8>>,
    /// Maximum operand stack depth.
    pub max_stack: u16,
    /// Maximum local variable count.
    pub max_locals: u16,
}

/// Access flag: static method/field.
pub const ACC_STATIC: u16 = 0x0008;

/// Constant pool entry types.
///
/// Many variant fields are only used for parsing (to correctly advance the
/// cursor) and not inspected later; that is intentional.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CpEntry {
    /// Placeholder for index 0 or long/double continuation.
    Unused,
    /// UTF-8 string constant.
    Utf8(String),
    /// `CONSTANT_Integer`.
    Integer(i32),
    /// `CONSTANT_Float`.
    Float(u32),
    /// `CONSTANT_Long` (occupies two slots).
    Long(i64),
    /// `CONSTANT_Double` (occupies two slots).
    Double(u64),
    /// `CONSTANT_Class` (`name_index`).
    Class(u16),
    /// `CONSTANT_String` (`string_index`).
    StringRef(u16),
    /// `CONSTANT_Fieldref` (`class_index`, `name_and_type_index`).
    Fieldref(u16, u16),
    /// `CONSTANT_Methodref` (`class_index`, `name_and_type_index`).
    Methodref(u16, u16),
    /// `CONSTANT_InterfaceMethodref` (`class_index`, `name_and_type_index`).
    InterfaceMethodref(u16, u16),
    /// `CONSTANT_NameAndType` (`name_index`, `descriptor_index`).
    NameAndType(u16, u16),
    /// `CONSTANT_MethodHandle`.
    MethodHandle(u8, u16),
    /// `CONSTANT_MethodType` (`descriptor_index`).
    MethodType(u16),
    /// `CONSTANT_InvokeDynamic`.
    InvokeDynamic(u16, u16),
}

/// A cursor for reading binary data.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.remaining() < 1 {
            return Err(String::from("unexpected end of classfile"));
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        if self.remaining() < 2 {
            return Err(String::from("unexpected end of classfile"));
        }
        let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        if self.remaining() < 4 {
            return Err(String::from("unexpected end of classfile"));
        }
        let val = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.remaining() < n {
            return Err(String::from("unexpected end of classfile"));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn skip(&mut self, n: usize) -> Result<(), String> {
        if self.remaining() < n {
            return Err(String::from("unexpected end of classfile"));
        }
        self.pos += n;
        Ok(())
    }
}

/// Parse a Java classfile from raw bytes.
///
/// # Errors
///
/// Returns a descriptive error string if the classfile is malformed.
pub fn read_classfile(data: &[u8]) -> Result<ClassFile, String> {
    let mut r = Reader::new(data);

    // Magic.
    let magic = r.read_u32()?;
    if magic != CLASS_MAGIC {
        return Err(format!(
            "bad classfile magic: expected 0xCAFEBABE, got {magic:#010X}"
        ));
    }

    // Version.
    let minor = r.read_u16()?;
    let major = r.read_u16()?;

    // Constant pool.
    let cp_count = r.read_u16()?;
    let pool = parse_constant_pool(&mut r, cp_count)?;

    // Access flags.
    let _access_flags = r.read_u16()?;

    // This class.
    let this_class_idx = r.read_u16()?;
    let class_name = resolve_class_name(&pool, this_class_idx)?;

    // Super class.
    let super_class_idx = r.read_u16()?;
    let super_class = if super_class_idx == 0 {
        String::from("java/lang/Object")
    } else {
        resolve_class_name(&pool, super_class_idx)?
    };

    // Interfaces (skip).
    let interfaces_count = r.read_u16()?;
    r.skip(interfaces_count as usize * 2)?;

    // Fields.
    let fields_count = r.read_u16()?;
    let mut fields = Vec::with_capacity(fields_count as usize);
    for _ in 0..fields_count {
        fields.push(parse_field(&mut r, &pool)?);
    }

    // Methods.
    let methods_count = r.read_u16()?;
    let mut methods = Vec::with_capacity(methods_count as usize);
    for _ in 0..methods_count {
        methods.push(parse_method(&mut r, &pool)?);
    }

    // Attributes (class-level, skip).
    let attrs_count = r.read_u16()?;
    for _ in 0..attrs_count {
        skip_attribute(&mut r)?;
    }

    Ok(ClassFile {
        version: (minor, major),
        class_name,
        super_class,
        fields,
        methods,
    })
}

/// Parse the constant pool.
#[allow(clippy::too_many_lines)]
fn parse_constant_pool(r: &mut Reader<'_>, count: u16) -> Result<Vec<CpEntry>, String> {
    let mut pool = Vec::with_capacity(count as usize);
    pool.push(CpEntry::Unused); // index 0 is unused

    let mut i = 1u16;
    while i < count {
        let tag = r.read_u8()?;
        let entry = match tag {
            1 => {
                // CONSTANT_Utf8
                let length = r.read_u16()?;
                let bytes = r.read_bytes(length as usize)?;
                let s = String::from_utf8_lossy(bytes).into_owned();
                CpEntry::Utf8(s)
            }
            3 => {
                // CONSTANT_Integer
                let val = r.read_u32()?.cast_signed();
                CpEntry::Integer(val)
            }
            4 => {
                // CONSTANT_Float
                let bits = r.read_u32()?;
                CpEntry::Float(bits)
            }
            5 => {
                // CONSTANT_Long (takes two slots)
                let high = r.read_u32()?;
                let low = r.read_u32()?;
                let val = (i64::from(high) << 32) | i64::from(low);
                pool.push(CpEntry::Long(val));
                pool.push(CpEntry::Unused);
                i += 2;
                continue;
            }
            6 => {
                // CONSTANT_Double (takes two slots)
                let high = r.read_u32()?;
                let low = r.read_u32()?;
                let bits = (u64::from(high) << 32) | u64::from(low);
                pool.push(CpEntry::Double(bits));
                pool.push(CpEntry::Unused);
                i += 2;
                continue;
            }
            7 => {
                // CONSTANT_Class
                let name_index = r.read_u16()?;
                CpEntry::Class(name_index)
            }
            8 => {
                // CONSTANT_String
                let string_index = r.read_u16()?;
                CpEntry::StringRef(string_index)
            }
            9 => {
                // CONSTANT_Fieldref
                let class_index = r.read_u16()?;
                let nat_index = r.read_u16()?;
                CpEntry::Fieldref(class_index, nat_index)
            }
            10 => {
                // CONSTANT_Methodref
                let class_index = r.read_u16()?;
                let nat_index = r.read_u16()?;
                CpEntry::Methodref(class_index, nat_index)
            }
            11 => {
                // CONSTANT_InterfaceMethodref
                let class_index = r.read_u16()?;
                let nat_index = r.read_u16()?;
                CpEntry::InterfaceMethodref(class_index, nat_index)
            }
            12 => {
                // CONSTANT_NameAndType
                let name_index = r.read_u16()?;
                let desc_index = r.read_u16()?;
                CpEntry::NameAndType(name_index, desc_index)
            }
            15 => {
                // CONSTANT_MethodHandle
                let kind = r.read_u8()?;
                let reference = r.read_u16()?;
                CpEntry::MethodHandle(kind, reference)
            }
            16 => {
                // CONSTANT_MethodType
                let desc_index = r.read_u16()?;
                CpEntry::MethodType(desc_index)
            }
            18 => {
                // CONSTANT_InvokeDynamic
                let bootstrap = r.read_u16()?;
                let nat = r.read_u16()?;
                CpEntry::InvokeDynamic(bootstrap, nat)
            }
            _ => {
                return Err(format!("unknown constant pool tag: {tag}"));
            }
        };
        pool.push(entry);
        i += 1;
    }

    Ok(pool)
}

/// Resolve a `CONSTANT_Class` entry to its name string.
fn resolve_class_name(pool: &[CpEntry], index: u16) -> Result<String, String> {
    match pool.get(index as usize) {
        Some(CpEntry::Class(name_idx)) => resolve_utf8(pool, *name_idx),
        _ => Err(format!("expected Class at constant pool index {index}")),
    }
}

/// Resolve a `CONSTANT_Utf8` entry.
fn resolve_utf8(pool: &[CpEntry], index: u16) -> Result<String, String> {
    match pool.get(index as usize) {
        Some(CpEntry::Utf8(s)) => Ok(s.clone()),
        _ => Err(format!("expected Utf8 at constant pool index {index}")),
    }
}

/// Parse a `field_info` structure.
fn parse_field(r: &mut Reader<'_>, pool: &[CpEntry]) -> Result<FieldInfo, String> {
    let access_flags = r.read_u16()?;
    let name_index = r.read_u16()?;
    let descriptor_index = r.read_u16()?;

    let name = resolve_utf8(pool, name_index)?;
    let descriptor = resolve_utf8(pool, descriptor_index)?;

    // Skip attributes.
    let attrs_count = r.read_u16()?;
    for _ in 0..attrs_count {
        skip_attribute(r)?;
    }

    Ok(FieldInfo {
        name,
        descriptor,
        access_flags,
    })
}

/// Parse a `method_info` structure.
fn parse_method(r: &mut Reader<'_>, pool: &[CpEntry]) -> Result<MethodInfo, String> {
    let access_flags = r.read_u16()?;
    let name_index = r.read_u16()?;
    let descriptor_index = r.read_u16()?;

    let name = resolve_utf8(pool, name_index)?;
    let descriptor = resolve_utf8(pool, descriptor_index)?;

    let mut code: Option<Vec<u8>> = None;
    let mut max_stack: u16 = 0;
    let mut max_locals: u16 = 0;

    // Parse attributes to find Code.
    let attrs_count = r.read_u16()?;
    for _ in 0..attrs_count {
        let attr_name_index = r.read_u16()?;
        let attr_length = r.read_u32()?;
        let attr_name = resolve_utf8(pool, attr_name_index).unwrap_or_default();

        if attr_name == "Code" {
            max_stack = r.read_u16()?;
            max_locals = r.read_u16()?;
            let code_length = r.read_u32()?;
            let bytecode = r.read_bytes(code_length as usize)?;
            code = Some(bytecode.to_vec());
            // Exception table.
            let exception_count = r.read_u16()?;
            r.skip(exception_count as usize * 8)?;
            // Code attributes.
            let code_attrs_count = r.read_u16()?;
            for _ in 0..code_attrs_count {
                skip_attribute(r)?;
            }
        } else {
            r.skip(attr_length as usize)?;
        }
    }

    Ok(MethodInfo {
        name,
        descriptor,
        access_flags,
        code,
        max_stack,
        max_locals,
    })
}

/// Skip an `attribute_info` structure.
fn skip_attribute(r: &mut Reader<'_>) -> Result<(), String> {
    let _name_index = r.read_u16()?;
    let length = r.read_u32()?;
    r.skip(length as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_magic() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let err = read_classfile(&data).unwrap_err();
        assert!(err.contains("bad classfile magic"));
    }

    #[test]
    fn too_short() {
        let data = [0xCA, 0xFE, 0xBA];
        let err = read_classfile(&data).unwrap_err();
        assert!(err.contains("unexpected end"));
    }

    /// Build a minimal valid classfile for testing.
    fn build_minimal_classfile() -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic.
        buf.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        // Version: minor=0, major=51 (Java 7).
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&51u16.to_be_bytes());

        // Constant pool count = 5 (entries 1..4).
        buf.extend_from_slice(&5u16.to_be_bytes());

        // #1: Utf8 "Test"
        buf.push(1); // tag
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(b"Test");

        // #2: Class -> #1
        buf.push(7);
        buf.extend_from_slice(&1u16.to_be_bytes());

        // #3: Utf8 "java/lang/Object"
        buf.push(1);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(b"java/lang/Object");

        // #4: Class -> #3
        buf.push(7);
        buf.extend_from_slice(&3u16.to_be_bytes());

        // Access flags: public.
        buf.extend_from_slice(&0x0021u16.to_be_bytes());
        // This class: #2.
        buf.extend_from_slice(&2u16.to_be_bytes());
        // Super class: #4.
        buf.extend_from_slice(&4u16.to_be_bytes());
        // Interfaces count: 0.
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Fields count: 0.
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Methods count: 0.
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Attributes count: 0.
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf
    }

    #[test]
    fn parse_minimal_classfile() {
        let data = build_minimal_classfile();
        let cf = read_classfile(&data).unwrap();
        assert_eq!(cf.class_name, "Test");
        assert_eq!(cf.super_class, "java/lang/Object");
        assert_eq!(cf.version, (0, 51));
        assert!(cf.fields.is_empty());
        assert!(cf.methods.is_empty());
    }
}
