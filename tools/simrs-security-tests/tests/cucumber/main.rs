// Cucumber step functions use macro-generated signatures that trigger these lints.
#![allow(
    missing_docs,
    clippy::needless_pass_by_value,
    clippy::needless_pass_by_ref_mut,
    clippy::trivial_regex,
    clippy::missing_const_for_fn
)]
//! Cucumber-rs test runner for simrs security regression testing.
//!
//! Step definitions are organized by vulnerability class, mirroring the
//! feature files in `features/`:
//!
//!   - `pin_state_machine` -- PIN/PUK state machine attacks
//!   - `apdu_boundary`     -- APDU boundary conditions and malformed input
//!   - `fs_access_control` -- Filesystem access control bypass
//!   - `ota_envelope`      -- OTA/ENVELOPE injection
//!   - `auth_protocol`     -- AUTHENTICATE protocol attacks
//!   - `data_leakage`      -- GET RESPONSE data leakage
//!   - `confinement`       -- Command side-effect confinement (no dedicated step module)
//!
//! Shared SIM initialization, generic APDU, and generic SW assertions
//! live in `common`. The `world` module defines `SimWorld` and helper
//! functions used by all step definition modules.

mod world;
use cucumber::World as _;

mod common;
mod interposer;
mod snapshot;

mod pin_state_machine;
mod apdu_boundary;
mod fs_access_control;
mod ota_envelope;
mod auth_protocol;
mod data_leakage;

fn main() {
    futures::executor::block_on(world::SimWorld::run("features/"));
}
