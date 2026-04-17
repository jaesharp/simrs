//! CAP file output.
//!
//! Wraps the compiled JCVM bytecodes into binary CAP format.
//!
//! Two output modes are available:
//!
//! - [`write_cap`]: Simplified blob format for the `no_std` JCVM runtime.
//! - [`write_cap_full`] / [`CapWriter`]: Full JCVM 3.1 component-based CAP.

pub mod writer;
pub use writer::{CapWriter, FieldInfo, write_cap, write_cap_full};
