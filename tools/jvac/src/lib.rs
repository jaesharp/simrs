//! JVA smartcard applet compiler.
//!
//! Compiles `.java`/`.jva` source files or `.class`/`.jvc` classfiles into
//! `.cap` bytecode packages for execution on the JCVM.
//!
//! # Architecture
//!
//! ```text
//!   .java/.jva  -->  java_parser (lexer + parser)  -->  JcClass IR
//!   .class/.jvc -->  classfile (reader + convert)  -->  JcClass IR
//!                                                         |
//!                                   simrs_jccompile::compile_class
//!                                                         |
//!                                                    CompiledClass
//!                                                         |
//!                                              cap::write_cap  -->  .cap
//! ```

pub mod cap;
pub mod classfile;
pub mod java_parser;

pub use simrs_jccompile::{codegen, error, ir, types};
