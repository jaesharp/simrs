//! Java/JVA source parser.
//!
//! Combines the lexer and recursive descent parser to convert Java Card
//! source text into the [`simrs_jccompile::ir::JcClass`] intermediate
//! representation.

pub mod lexer;
pub mod parser;

/// Parse a Java/JVA source string into a `JcClass` IR.
///
/// # Errors
///
/// Returns a descriptive error string with line/column information on
/// parse failure.
pub fn parse_source(source: &str) -> Result<simrs_jccompile::ir::JcClass, String> {
    let tokens = lexer::tokenize(source)?;
    parser::parse(&tokens)
}
