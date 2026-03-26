//! CAP file output.
//!
//! Wraps the compiled JCVM bytecodes into the binary CAP blob format
//! used by `simrs-jcvm`.

pub mod writer;
pub use writer::write_cap;
