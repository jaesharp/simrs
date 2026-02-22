//! Shadow SIM: wraps a `Sim<MilenageParams>` for shadow comparison.

use simrs_fs::DfDef;
use simrs_milenage::{MilenageParams, OpVariant};
use simrs_sim::{Sim, SimEvent, SimResponse};

use crate::mode::AuthConfig;

/// A shadow SIM instance that processes APDUs in parallel with a real card.
pub struct ShadowSim {
    sim: Sim<MilenageParams, 256>,
    rsp_buf: [u8; 261],
}

impl ShadowSim {
    /// Create a shadow SIM with the given auth config and filesystem.
    ///
    /// The GSM Ki and USIM K/OPc are configured from the [`AuthConfig`].
    /// The filesystem uses the provided MF definition.
    pub fn new(
        config: &AuthConfig,
        atr: &'static [u8],
        mf: &'static DfDef,
    ) -> Self {
        let mut sim = Sim::<MilenageParams, 256>::new(atr, mf);

        // Configure GSM app with Ki.
        {
            use simrs_gsm::GsmApp;
            let gsm = sim.gsm_app_mut();
            *gsm = GsmApp::new(mf, simrs_gsm::Ki(config.ki));
        }

        // Configure USIM app with K/OPc.
        {
            use simrs_usim::UsimApp;
            let mil = MilenageParams::with_defaults(config.k, OpVariant::Opc(config.opc));
            let usim = sim.usim_app_mut();
            *usim = UsimApp::new(mf, &[], mil);
        }

        Self {
            sim,
            rsp_buf: [0u8; 261],
        }
    }

    /// Process a power-on event. Returns ATR bytes.
    pub fn power_on(&mut self) -> &[u8] {
        match self.sim.process(SimEvent::PowerOn) {
            SimResponse::Atr(atr) => atr,
            _ => &[],
        }
    }

    /// Process a warm reset. Returns ATR bytes.
    pub fn reset(&mut self) -> &[u8] {
        match self.sim.process(SimEvent::Reset) {
            SimResponse::Atr(atr) => atr,
            _ => &[],
        }
    }

    /// Process an APDU. Returns `(response_data, sw1, sw2)` or `None` if ignored.
    pub fn process_apdu(&mut self, cmd: &[u8]) -> Option<(&[u8], u8, u8)> {
        match self.sim.process(SimEvent::Apdu(cmd)) {
            SimResponse::Apdu { data, sw1, sw2 } => {
                // Copy data into our response buffer so we can return
                // a reference that outlives the borrow on self.sim.
                self.rsp_buf[..data.len()].copy_from_slice(data);
                Some((&self.rsp_buf[..data.len()], sw1, sw2))
            }
            SimResponse::Ignored | SimResponse::Atr(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_fs::{DfDef, EfDef, Fid, FileRef};

    static ICCID_DATA: [u8; 10] =
        [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

    static EF_ICCID: EfDef = EfDef::transparent(
        Fid::new(0x2FE2),
        None,
        &ICCID_DATA,
    );

    static TEST_MF: DfDef = DfDef {
        fid: Fid::new(0x3F00),
        children: &[FileRef::Ef(&EF_ICCID)],
    };

    static TEST_ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

    fn test_auth_config() -> AuthConfig {
        AuthConfig {
            ki: [0x11u8; 16],
            k: [0x22u8; 16],
            opc: [0x33u8; 16],
        }
    }

    #[test]
    fn create_shadow_sim() {
        let config = test_auth_config();
        let _shadow = ShadowSim::new(&config, &TEST_ATR, &TEST_MF);
    }

    #[test]
    fn power_on_returns_atr() {
        let config = test_auth_config();
        let mut shadow = ShadowSim::new(&config, &TEST_ATR, &TEST_MF);
        let atr = shadow.power_on();
        assert_eq!(atr, &TEST_ATR);
    }

    #[test]
    fn process_select_mf_returns_response() {
        let config = test_auth_config();
        let mut shadow = ShadowSim::new(&config, &TEST_ATR, &TEST_MF);
        shadow.power_on();

        // SELECT MF via USIM CLA (0x00)
        let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let result = shadow.process_apdu(&select_mf);
        assert!(result.is_some(), "SELECT MF should produce a response");
        let (_, sw1, _) = result.unwrap();
        // USIM SELECT returns 61 XX (data available via GET RESPONSE)
        assert_eq!(sw1, 0x61);
    }

    #[test]
    fn process_before_power_on_returns_none() {
        let config = test_auth_config();
        let mut shadow = ShadowSim::new(&config, &TEST_ATR, &TEST_MF);
        let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        let result = shadow.process_apdu(&select_mf);
        assert!(result.is_none());
    }

    #[test]
    fn reset_clears_state() {
        let config = test_auth_config();
        let mut shadow = ShadowSim::new(&config, &TEST_ATR, &TEST_MF);
        shadow.power_on();

        // SELECT something to change state
        let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];
        shadow.process_apdu(&select_mf);

        // Reset should return ATR
        let atr = shadow.reset();
        assert_eq!(atr, &TEST_ATR);

        // After reset, should still accept APDUs
        let result = shadow.process_apdu(&select_mf);
        assert!(result.is_some());
    }
}
