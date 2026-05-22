//! Hardware-required integration tests.
//!
//! These tests open a real SIMtrace2 board on the local USB bus and are
//! marked `#[ignore]` so they don't run in CI or `cargo test --workspace`.
//! Run them with:
//!
//! ```text
//! cargo test -p simrs-transport-simtrace2 -- --ignored
//! ```
//!
//! The board must be running cardem firmware and present at the default
//! VID:PID (`1d50:60e3`). udev permissions must grant the running user
//! access to the device (see `docs/runbooks/simtrace2-cardem-path-a.md`).

use simrs_transport::CardTransport;
use simrs_transport_simtrace2::{DeviceFilter, Simtrace2Transport};

#[test]
#[ignore = "requires SIMtrace2 hardware on USB"]
fn opens_device_and_sends_atr() {
    // Just opening the transport exercises USB enumeration, interface
    // claim, alt-setting selection, and the initial Config + CardInsert
    // round-trip. If this passes, the device handle is healthy.
    let mut transport =
        Simtrace2Transport::open(DeviceFilter::default()).expect("open SIMtrace2");
    transport
        .send_atr(&simrs_card_api::DEFAULT_ATR)
        .expect("pre-stage ATR");
    // Don't enter the recv() loop here -- without a phone driving the
    // slot, recv() will time out. The point of this test is to verify
    // that the device handle survives setup.
}
