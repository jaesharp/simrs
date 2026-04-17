//! Convert a parsed [`ClassFile`] into the [`JcClass`] IR.
//!
//! Maps JVM field/method descriptors to JCVM types and translates JVM
//! bytecodes to JCVM bytecodes via a direct translation table.

use simrs_jccompile::ir::{JcClass, JcExpr, JcField, JcMethod, JcStmt};
use simrs_jccompile::types::JcType;

use super::reader::{ACC_STATIC, ClassFile, MethodInfo};

/// Convert a classfile to `JcClass` IR.
///
/// # Errors
///
/// Returns a descriptive error string on conversion failure.
pub fn classfile_to_ir(cf: &ClassFile, aid: &[u8]) -> Result<JcClass, String> {
    let mut fields = Vec::new();
    for (i, f) in cf.fields.iter().enumerate() {
        let ty = descriptor_to_type(&f.descriptor)?;
        fields.push(JcField {
            name: f.name.clone(),
            ty,
            #[allow(clippy::cast_possible_truncation)]
            offset: i as u8,
        });
    }

    let mut methods = Vec::new();
    for m in &cf.methods {
        // Skip class initializers for MVP.
        if m.name == "<clinit>" {
            continue;
        }
        methods.push(convert_method(m)?);
    }

    Ok(JcClass {
        aid: aid.to_vec(),
        fields,
        methods,
    })
}

/// Convert a JVM method descriptor to parameter types and return type.
///
/// Descriptor format: `(param_types)return_type`
fn parse_method_descriptor(desc: &str) -> Result<(Vec<JcType>, JcType), String> {
    let bytes = desc.as_bytes();
    if bytes.is_empty() || bytes[0] != b'(' {
        return Err(format!("invalid method descriptor: {desc}"));
    }

    let mut pos = 1; // skip '('
    let mut params = Vec::new();

    while pos < bytes.len() && bytes[pos] != b')' {
        let (ty, advance) = parse_descriptor_type(&bytes[pos..])?;
        params.push(ty);
        pos += advance;
    }

    if pos >= bytes.len() {
        return Err(format!("unterminated method descriptor: {desc}"));
    }
    pos += 1; // skip ')'

    let (ret_ty, _) = if pos < bytes.len() && bytes[pos] == b'V' {
        (JcType::Void, 1)
    } else if pos < bytes.len() {
        parse_descriptor_type(&bytes[pos..])?
    } else {
        (JcType::Void, 0)
    };

    Ok((params, ret_ty))
}

/// Parse a single type from a JVM descriptor, returning the type and number
/// of bytes consumed.
fn parse_descriptor_type(desc: &[u8]) -> Result<(JcType, usize), String> {
    if desc.is_empty() {
        return Err(String::from("empty descriptor"));
    }
    match desc[0] {
        b'B' => Ok((JcType::Byte, 1)),
        b'S' | b'I' => Ok((JcType::Short, 1)), // Java Card convention: int -> short
        b'Z' => Ok((JcType::Boolean, 1)),
        b'V' => Ok((JcType::Void, 1)),
        b'[' => {
            // Array type.
            if desc.len() < 2 {
                return Err(String::from("truncated array descriptor"));
            }
            match desc[1] {
                b'S' | b'I' => Ok((JcType::ShortArray, 2)),
                _ => Ok((JcType::ByteArray, 2)), // byte and all others
            }
        }
        b'L' => {
            // Object type: Lfoo/bar/Baz;
            let mut end = 1;
            while end < desc.len() && desc[end] != b';' {
                end += 1;
            }
            Ok((JcType::Instance, end + 1))
        }
        _ => Err(format!("unknown descriptor type: {}", desc[0] as char)),
    }
}

/// Convert a JVM field descriptor to a `JcType`.
fn descriptor_to_type(desc: &str) -> Result<JcType, String> {
    let (ty, _) = parse_descriptor_type(desc.as_bytes())?;
    Ok(ty)
}

/// Convert a single method.
fn convert_method(m: &MethodInfo) -> Result<JcMethod, String> {
    let is_static = m.access_flags & ACC_STATIC != 0;
    let (param_types, return_ty) = parse_method_descriptor(&m.descriptor)?;

    // Build parameter list with synthetic names.
    let params: Vec<(String, JcType)> = param_types
        .iter()
        .enumerate()
        .map(|(i, ty)| (format!("arg{i}"), *ty))
        .collect();

    // Locals = params (the checker will assign slots).
    let locals = params.clone();

    // Convert bytecodes.
    let body = m.code.as_ref().map_or_else(
        || vec![JcStmt::Return(None)],
        |code| translate_bytecodes(code),
    );

    Ok(JcMethod {
        name: m.name.clone(),
        params,
        return_ty,
        locals,
        body,
        is_static,
        constant_time: false,
    })
}

/// Translate JVM bytecodes to `JcIR` statements.
///
/// This is a simplified translator that recognizes common JVM patterns
/// and maps them to JCVM IR constructs. For complex bytecode sequences,
/// it falls back to a return statement.
fn translate_bytecodes(code: &[u8]) -> Vec<JcStmt> {
    if code.is_empty() {
        return vec![JcStmt::Return(None)];
    }

    let mut stmts = Vec::new();
    let mut pos = 0;

    while pos < code.len() {
        match code[pos] {
            // iconst_m1..iconst_5 (0x02..0x08)
            0x02..=0x08 => {
                let val = i16::from(code[pos]) - 0x03; // iconst_0 = 0x03
                stmts.push(JcStmt::Return(Some(JcExpr::Lit(val))));
                break;
            }
            // bipush (0x10)
            0x10 => {
                if pos + 1 >= code.len() {
                    break;
                }
                let val = i16::from(code[pos + 1].cast_signed());
                stmts.push(JcStmt::Return(Some(JcExpr::Lit(val))));
                break;
            }
            // sipush (0x11)
            0x11 => {
                if pos + 2 >= code.len() {
                    break;
                }
                let val = i16::from_be_bytes([code[pos + 1], code[pos + 2]]);
                stmts.push(JcStmt::Return(Some(JcExpr::Lit(val))));
                break;
            }
            // return (0xB1 in JVM, 0x7A in JCVM)
            0xB1 | 0x7A => {
                stmts.push(JcStmt::Return(None));
                break;
            }
            // ireturn (0xAC in JVM, 0x78 in JCVM as sreturn)
            0xAC | 0x78 => {
                // The value should already be on the stack from previous
                // instructions. If we haven't pushed a return yet, emit
                // a placeholder.
                if stmts.is_empty() {
                    stmts.push(JcStmt::Return(Some(JcExpr::Lit(0))));
                }
                break;
            }
            // For all other bytecodes, skip and emit a void return at the end.
            _ => {
                pos += jvm_instruction_size(code, pos);
            }
        }
    }

    if stmts.is_empty() {
        stmts.push(JcStmt::Return(None));
    }

    stmts
}

/// Determine the size of a JVM instruction at the given position.
fn jvm_instruction_size(code: &[u8], pos: usize) -> usize {
    if pos >= code.len() {
        return 1;
    }
    match code[pos] {
        // 2-byte instructions
        0x10 // bipush
        | 0x12 // ldc
        | 0x15..=0x19 // iload..aload (with index)
        | 0xBC // newarray
        => 2,
        // 3-byte instructions
        0x11 // sipush
        | 0x13..=0x14 // ldc_w, ldc2_w
        | 0x84 // iinc
        | 0x99..=0xA7 // if* branches + goto
        | 0xB2..=0xB8 // field/method access
        | 0xBB // new
        | 0xBD // anewarray
        | 0xC0..=0xC1 // checkcast, instanceof
        => 3,
        // Wide (varies, approximated)
        0xC4 => 4,
        // All other instructions default to 1 byte
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_descriptor() {
        let (params, ret) = parse_method_descriptor("()V").unwrap();
        assert!(params.is_empty());
        assert_eq!(ret, JcType::Void);
    }

    #[test]
    fn parse_descriptor_with_params() {
        let (params, ret) = parse_method_descriptor("(SS)S").unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], JcType::Short);
        assert_eq!(params[1], JcType::Short);
        assert_eq!(ret, JcType::Short);
    }

    #[test]
    fn parse_descriptor_with_array() {
        let (params, ret) = parse_method_descriptor("([B)V").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], JcType::ByteArray);
        assert_eq!(ret, JcType::Void);
    }

    #[test]
    fn parse_descriptor_with_object() {
        let (params, ret) = parse_method_descriptor("(Ljava/lang/Object;)I").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], JcType::Instance);
        assert_eq!(ret, JcType::Short); // int -> short
    }

    #[test]
    fn descriptor_to_type_byte() {
        assert_eq!(descriptor_to_type("B").unwrap(), JcType::Byte);
    }

    #[test]
    fn descriptor_to_type_short() {
        assert_eq!(descriptor_to_type("S").unwrap(), JcType::Short);
    }

    #[test]
    fn descriptor_to_type_byte_array() {
        assert_eq!(descriptor_to_type("[B").unwrap(), JcType::ByteArray);
    }
}
