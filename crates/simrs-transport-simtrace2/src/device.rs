//! USB enumeration and interface claiming for SIMtrace2 boards.
//!
//! This module is the thin layer around `nusb` that turns a VID/PID filter
//! into a fully-claimed cardem interface with three claimed endpoints (bulk
//! IN, bulk OUT, interrupt IN). It is kept apart from
//! [`crate::cardem::Simtrace2Transport`] so that the transport can be tested
//! in isolation by injecting open endpoints from elsewhere if needed.

use nusb::transfer::{Bulk, In, Interrupt, Out};
use nusb::{DeviceInfo, Endpoint, Interface, MaybeFuture};

use crate::protocol::{
    EP_BULK_IN, EP_BULK_OUT, EP_INT_IN, PID_NGFF_CARDEM, PID_OCTSIMTEST, PID_SIMTRACE2,
    VID_OPENMOKO,
};
use crate::Error;

/// The interface number on which cardem operates.
///
/// SIMtrace2's USB descriptors expose two interfaces: interface 0 is the
/// "phone" side (USIM1 endpoints) which is the one we use for cardem.
/// Reference: [`firmware/libcommon/include/simtrace_usb.h`](https://github.com/osmocom/simtrace2/blob/master/firmware/libcommon/include/simtrace_usb.h).
pub const CARDEM_INTERFACE: u8 = 0;

/// Alternate setting selected after claiming the interface.
pub const CARDEM_ALT_SETTING: u8 = 0;

/// Bundle of claimed endpoints + the interface handle.
///
/// The interface is held to keep it claimed for the lifetime of these
/// endpoints; dropping it releases the USB interface back to the kernel.
pub struct CardemEndpoints {
    /// Bulk OUT endpoint used to send `TxData`, `SetAtr`, `CardInsert`,
    /// and `Config` messages to the firmware.
    pub bulk_out: Endpoint<Bulk, Out>,
    /// Bulk IN endpoint used to receive `RxData` and (when the IRQ feature
    /// is not enabled) `Status` / `Pts` messages from the firmware.
    pub bulk_in: Endpoint<Bulk, In>,
    /// Interrupt IN endpoint used to receive asynchronous `Status` updates.
    pub int_in: Endpoint<Interrupt, In>,
    /// Held interface handle. Kept solely to retain the claim; consumers
    /// generally don't touch this field directly.
    pub _interface: Interface,
}

/// Selector controlling which board is opened.
#[derive(Clone, Debug, Default)]
pub struct DeviceFilter {
    /// USB vendor ID. `None` means use [`VID_OPENMOKO`].
    pub vendor_id: Option<u16>,
    /// USB product ID. `None` means use [`PID_SIMTRACE2`].
    pub product_id: Option<u16>,
    /// Optional `(bus_id, device_address)` selector for disambiguating
    /// between multiple boards with the same VID:PID. `bus_id` is a
    /// platform-specific identifier (numeric on Linux, see
    /// [`nusb::DeviceInfo::bus_id`]).
    pub bus_device: Option<(String, u8)>,
}

impl DeviceFilter {
    /// Effective vendor ID (filter value or default).
    pub fn effective_vendor(&self) -> u16 {
        self.vendor_id.unwrap_or(VID_OPENMOKO)
    }

    /// Effective product ID (filter value or default).
    pub fn effective_product(&self) -> u16 {
        self.product_id.unwrap_or(PID_SIMTRACE2)
    }

    /// Whether this `DeviceInfo` matches the filter.
    fn matches(&self, info: &DeviceInfo) -> bool {
        if info.vendor_id() != self.effective_vendor()
            || info.product_id() != self.effective_product()
        {
            return false;
        }
        if let Some((bus, addr)) = &self.bus_device {
            if info.bus_id() != bus || info.device_address() != *addr {
                return false;
            }
        }
        true
    }
}

/// Look up a SIMtrace2 board matching the filter and open all three
/// cardem endpoints on it.
///
/// # Errors
///
/// Returns:
/// - [`Error::DeviceNotFound`] if no board on the bus matches the filter
///   (including the case where a board is present but in DFU mode at
///   [`crate::protocol::PID_SIMTRACE2_DFU`] -- the caller should reflash or
///   exit DFU before retrying).
/// - [`Error::DfuModeDetected`] if the only matching board is in DFU mode.
/// - [`Error::Usb`] for any underlying USB / kernel failure.
pub fn open_endpoints(filter: DeviceFilter) -> Result<CardemEndpoints, Error> {
    let mut found_runtime: Option<DeviceInfo> = None;
    let mut found_dfu: Option<DeviceInfo> = None;
    let vendor = filter.effective_vendor();
    let product_explicit = filter.product_id.is_some();
    let product = filter.effective_product();

    for info in nusb::list_devices().wait().map_err(Error::from_io)? {
        if info.vendor_id() == vendor
            && info.product_id() == crate::protocol::PID_SIMTRACE2_DFU
        {
            // DFU bootloader -- can't talk cardem to this until reflashed.
            found_dfu = Some(info);
            continue;
        }
        if filter.matches(&info) {
            found_runtime = Some(info);
            break;
        }
        // Auto-accept ngff-cardem and octsimtest variants when the user did
        // not explicitly pin a PID. Both run the same cardem firmware and
        // expose the same endpoint layout.
        if !product_explicit
            && product == PID_SIMTRACE2
            && info.vendor_id() == vendor
            && (info.product_id() == PID_NGFF_CARDEM || info.product_id() == PID_OCTSIMTEST)
        {
            // Honour the bus_device disambiguation if it was supplied.
            if let Some((bus, addr)) = &filter.bus_device {
                if info.bus_id() != bus || info.device_address() != *addr {
                    continue;
                }
            }
            found_runtime = Some(info);
            break;
        }
    }

    let info = match (found_runtime, found_dfu) {
        (Some(rt), _) => rt,
        (None, Some(_)) => return Err(Error::DfuModeDetected),
        (None, None) => return Err(Error::DeviceNotFound),
    };

    let device = info.open().wait().map_err(Error::from_io)?;
    let interface = device
        .claim_interface(CARDEM_INTERFACE)
        .wait()
        .map_err(Error::from_io)?;
    interface
        .set_alt_setting(CARDEM_ALT_SETTING)
        .wait()
        .map_err(Error::from_io)?;

    let bulk_out = interface
        .endpoint::<Bulk, Out>(EP_BULK_OUT)
        .map_err(Error::from_io)?;
    let bulk_in = interface
        .endpoint::<Bulk, In>(EP_BULK_IN)
        .map_err(Error::from_io)?;
    let int_in = interface
        .endpoint::<Interrupt, In>(EP_INT_IN)
        .map_err(Error::from_io)?;

    Ok(CardemEndpoints {
        bulk_out,
        bulk_in,
        int_in,
        _interface: interface,
    })
}
