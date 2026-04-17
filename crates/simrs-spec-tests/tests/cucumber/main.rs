// Cucumber step functions use macro-generated signatures that trigger these lints.
#![allow(
    missing_docs,
    clippy::needless_pass_by_value,
    clippy::needless_pass_by_ref_mut,
    clippy::trivial_regex,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::struct_excessive_bools,
    clippy::option_option,
    clippy::missing_fields_in_debug,
    clippy::items_after_statements,
    clippy::similar_names,
    clippy::redundant_pub_crate,
    clippy::used_underscore_items,
    clippy::used_underscore_binding,
    clippy::cast_possible_truncation,
    clippy::borrow_as_ptr,
    clippy::uninlined_format_args,
    clippy::branches_sharing_code,
    clippy::option_if_let_else,
    clippy::format_collect,
    clippy::tuple_array_conversions,
    clippy::no_effect_underscore_binding
)]
//! Cucumber-rs test runner for the simrs specification suite.
//!
//! Step definitions are organized by feature domain, mirroring the
//! feature files symlinked in `features/`:
//!
//!   - `bertlv`        -- BER-TLV encoding/decoding
//!   - `comp128`       -- COMP128v1 authentication
//!   - `fs`            -- SIM filesystem operations
//!   - `gsm`           -- GSM SIM application
//!   - `iso7816`       -- ISO 7816 APDU framing
//!   - `milenage`      -- Milenage authentication
//!   - `pin`           -- PIN/PUK management
//!   - `proactive`     -- Proactive UICC commands
//!   - `sim`           -- Top-level SIM state machine
//!   - `transport`     -- Transport abstraction
//!   - `transport_tcp` -- TCP transport
//!   - `usim`          -- USIM application
//!
//! Shared SIM initialization, generic APDU, and generic SW assertions
//! live in `common`. The `world` module defines `SpecWorld` and helper
//! functions used by all step definition modules.

mod world;
use cucumber::World as _;

mod common;

mod bertlv;
mod comp128;
mod fs;
mod gsm;
mod iso7816;
mod milenage;
mod pin;
mod proactive;
mod sim;
mod transport;
mod transport_tcp;
mod usim;

fn main() {
    futures::executor::block_on(world::SpecWorld::run("features/"));
}
