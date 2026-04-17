//! Python bindings for SimRS.
//!
//! This crate exists solely to pull in the `simrs-hle-capi` cdylib dependency
//! so that `cargo test` builds the shared library before the integration test
//! invokes pytest via uv.
