//! Probe implementations, one module per `P1` category.
//!
//! Each probe module exposes a single entry point
//! `handle(state: &mut AppletState, p2: u8, data: &[u8], rsp: &mut Vec<u8>) -> [u8; 2]`
//! that writes response-data bytes into `rsp` and returns the SW.
//!
//! Only the categories that have been implemented are wired in
//! [`crate::applet::ControlplaneApplet::process`]; unimplemented
//! categories return `6A 86` at the dispatch layer.

pub mod fault;
pub mod jcvm_state;
pub mod nested_card;
pub mod ping;
pub mod prng;
pub mod snapshot_marker;
