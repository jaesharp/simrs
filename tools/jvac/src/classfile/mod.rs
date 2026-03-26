//! Java classfile reader and converter.
//!
//! Reads `.class` and `.jvc` binary classfiles and converts them to the
//! [`simrs_jccompile::ir::JcClass`] IR for compilation to JCVM bytecode.

pub mod convert;
pub mod reader;

/// Read a classfile from bytes and convert to `JcClass` IR.
///
/// # Errors
///
/// Returns a descriptive error string on read or conversion failure.
pub fn read_and_convert(
    data: &[u8],
    aid: &[u8],
) -> Result<simrs_jccompile::ir::JcClass, String> {
    let cf = reader::read_classfile(data)?;
    convert::classfile_to_ir(&cf, aid)
}
