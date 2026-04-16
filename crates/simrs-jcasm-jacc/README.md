# simrs-jcasm-jacc

JVA smartcard applet compiler proc-macro.

Provides the `jcapplet!{}` macro that parses a Rust-like JVA syntax and
compiles it to JCVM bytecodes using the `simrs-jccompile` compiler core.
Output format matches `jcasm!{}` so both are interchangeable with
`build_cap_blob`.
