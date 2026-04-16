//! JVA smartcard applet compiler proc-macro.
//!
//! Provides the `jcapplet!{}` macro that parses a Rust-like JVA syntax
//! and compiles it to JCVM bytecodes using the `simrs-jccompile` compiler
//! core. The output format matches `jcasm!{}` so both are interchangeable
//! with `build_cap_blob`.
//!
//! # Example
//!
//! ```rust,ignore
//! use simrs_jcasm_jacc::jcapplet;
//!
//! let (aid, methods) = jcapplet! {
//!     applet Wallet(A0_00_00_00_62_01_01) {
//!         field balance: short;
//!
//!         fn process(amount: short) -> short {
//!             let new_balance: short = self.balance + amount;
//!             self.balance = new_balance;
//!             return new_balance;
//!         }
//!     }
//! };
//! ```

use proc_macro::TokenStream;

mod frontend;

/// Compile a JVA applet definition to JCVM bytecodes at compile time.
///
/// Parses a Rust-like applet definition and emits a `(&[u8], &[&[u8]])`
/// tuple of `(aid_bytes, method_bytecodes)` that can be passed to
/// `simrs_jcvm::cap::build_cap_blob()`.
#[proc_macro]
pub fn jcapplet(input: TokenStream) -> TokenStream {
    let input2: proc_macro2::TokenStream = input.into();
    let output = frontend::generate(input2);
    output.into()
}
