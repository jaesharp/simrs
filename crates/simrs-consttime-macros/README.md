# simrs-consttime-macros

Proc macros for constant-time cryptographic primitives.

Provides `#[derive(CtEq)]`, `#[derive(CtSelect)]`, and
`#[derive(CtSwap)]` which generate constant-time trait implementations
for structs containing byte-array fields.

Users should depend on `simrs-consttime` (which re-exports the derives),
not on this crate directly.
