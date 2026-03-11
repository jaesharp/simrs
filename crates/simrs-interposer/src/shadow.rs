//! Shadow SIM: wraps a `Sim<MilenageParams>` for shadow comparison.
//!
//! Also provides `SimTerminal` which implements the `Transport` trait
//! for use in Diff mode with N-way comparison.

use simrs_fs::DfDef;
use simrs_milenage::{MilenageParams, OperatorVariant, SubscriberKey};
use simrs_sim::{Sim, SimEvent, SimResponse};
use simrs_transport::{Transport, TransportError};

use crate::mode::AuthConfig;

/// A shadow SIM instance that processes APDUs in parallel with a real card.
pub struct ShadowSim {
    sim: Sim<MilenageParams, 256>,
    rsp_buf: [u8; 261],
}

/// A SIM instance wrapped as a Transport for use in Diff mode.
///
/// This allows comparing two simrs instances directly without
/// going through TCP. The APDUs are sent to both and responses compared.
pub struct SimTerminal {
    sim: Sim<MilenageParams, 256>,
    rsp_buf: [u8; 261],
    powered_on: bool,
}

impl SimTerminal {
    /// Create a new SimTerminal with the given auth config and filesystem.
    pub fn new(config: &AuthConfig, atr: &'static [u8], mf: &'static DfDef) -> Self {
        let gsm = simrs_gsm::GsmApp::new(mf, simrs_gsm::Ki::new(config.ki));
        let mil = MilenageParams::with_defaults(SubscriberKey::new(config.k), OperatorVariant::opc(config.opc));
        let usim = simrs_usim::UsimApp::new(mf, &[], mil);
        let sim = Sim::<MilenageParams, 256>::new(atr, gsm, usim);

        Self {
            sim,
            rsp_buf: [0u8; 261],
            powered_on: false,
        }
    }

    /// Process a power-on event. Returns ATR bytes.
    ///
    /// Idempotent: if already powered on, returns an empty slice
    /// without resetting the SIM state.
    pub fn power_on(&mut self) -> &[u8] {
        if self.powered_on {
            return &[];
        }
        self.powered_on = true;
        match self.sim.process(SimEvent::PowerOn) {
            SimResponse::Atr(atr) => atr,
            _ => &[],
        }
    }

    /// Reset the SIM (warm reset). Returns ATR bytes.
    ///
    /// Applies the configured reset policy (standard policy clears all
    /// session state including PIN verified flags, file selection, and
    /// pending GET RESPONSE data).
    pub fn reset(&mut self) -> &[u8] {
        self.powered_on = true;
        match self.sim.process(SimEvent::Reset) {
            SimResponse::Atr(atr) => atr,
            _ => &[],
        }
    }

    /// Process an APDU. Returns `(response_data, sw1, sw2)` or `None` if ignored.
    pub fn process_apdu(&mut self, cmd: &[u8]) -> Option<(&[u8], u8, u8)> {
        match self.sim.process(SimEvent::Apdu(cmd)) {
            SimResponse::Apdu { data, sw1, sw2 } => {
                self.rsp_buf[..data.len()].copy_from_slice(data);
                Some((&self.rsp_buf[..data.len()], sw1, sw2))
            }
            SimResponse::Ignored | SimResponse::Atr(_) => None,
        }
    }
}

impl Transport for SimTerminal {
    type Error = TransportError;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.powered_on {
            self.power_on();
        }

        match self.sim.process(SimEvent::Apdu(cmd)) {
            SimResponse::Apdu { data, sw1, sw2 } => {
                let len = data.len() + 2;
                if len > rsp.len() {
                    return Err(TransportError::BufferTooSmall);
                }
                rsp[..data.len()].copy_from_slice(data);
                rsp[data.len()] = sw1;
                rsp[data.len() + 1] = sw2;
                Ok(len)
            }
            SimResponse::Ignored => {
                // Return 6F00 (technical problem)
                rsp[0] = 0x6F;
                rsp[1] = 0x00;
                Ok(2)
            }
            SimResponse::Atr(_) => {
                // Return 6F00 if not powered on
                rsp[0] = 0x6F;
                rsp[1] = 0x00;
                Ok(2)
            }
        }
    }
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
        let gsm = simrs_gsm::GsmApp::new(mf, simrs_gsm::Ki::new(config.ki));
        let mil = MilenageParams::with_defaults(SubscriberKey::new(config.k), OperatorVariant::opc(config.opc));
        let usim = simrs_usim::UsimApp::new(mf, &[], mil);
        let sim = Sim::<MilenageParams, 256>::new(atr, gsm, usim);

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
    use simrs_secret::Secret;

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
            ki: Secret::new([0x11u8; 16]),
            k: Secret::new([0x22u8; 16]),
            opc: Secret::new([0x33u8; 16]),
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

    // === SimTerminal tests ===

    #[test]
    fn simterminal_transport_exchange() {
        let config = test_auth_config();
        let mut terminal = SimTerminal::new(&config, &TEST_ATR, &TEST_MF);

        let mut rsp_buf = [0u8; 261];
        let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];

        let n = terminal.exchange(&select_mf, &mut rsp_buf).unwrap();
        assert!(n >= 2, "Should return at least SW1/SW2");
    }

    #[test]
    fn simterminal_same_config_same_response() {
        let config = test_auth_config();
        let mut term1 = SimTerminal::new(&config, &TEST_ATR, &TEST_MF);
        let mut term2 = SimTerminal::new(&config, &TEST_ATR, &TEST_MF);

        let mut rsp1 = [0u8; 261];
        let mut rsp2 = [0u8; 261];
        let select_mf = [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00];

        let n1 = term1.exchange(&select_mf, &mut rsp1).unwrap();
        let n2 = term2.exchange(&select_mf, &mut rsp2).unwrap();

        // Responses should be identical with same config
        assert_eq!(n1, n2);
        assert_eq!(&rsp1[..n1], &rsp2[..n2]);
    }

    #[test]
    fn simterminal_different_ki_different_response() {
        let mut config1 = test_auth_config();
        let mut config2 = test_auth_config();

        // Different Ki
        config1.ki = Secret::new([0x11u8; 16]);
        config2.ki = Secret::new([0x22u8; 16]);

        let mut term1 = SimTerminal::new(&config1, &TEST_ATR, &TEST_MF);
        let mut term2 = SimTerminal::new(&config2, &TEST_ATR, &TEST_MF);

        let mut rsp1 = [0u8; 261];
        let mut rsp2 = [0u8; 261];

        // Run GSM ALGORITHM command which uses Ki
        // This returns 9F 0C (12 bytes available) - need GET RESPONSE
        let run_gsm_algo = [0xA0, 0x88, 0x00, 0x00, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        let _n1 = term1.exchange(&run_gsm_algo, &mut rsp1).unwrap();
        let _n2 = term2.exchange(&run_gsm_algo, &mut rsp2).unwrap();

        // GET RESPONSE to fetch the 12-byte SRES + Kc
        let get_resp = [0xA0, 0xC0, 0x00, 0x00, 0x0C];

        let n1 = term1.exchange(&get_resp, &mut rsp1).unwrap();
        let n2 = term2.exchange(&get_resp, &mut rsp2).unwrap();

        // Both should return SRES(4) + Kc(8) + SW(2) = 14 bytes
        assert!(n1 >= 14, "Should return SRES(4) + Kc(8) + SW(2), got {n1}");
        assert!(n2 >= 14, "Should return SRES(4) + Kc(8) + SW(2), got {n2}");

        // With different Ki, the SRES/Kc data must differ
        assert_ne!(&rsp1[..n1 - 2], &rsp2[..n2 - 2],
            "Different Ki should produce different SRES/Kc");
    }
}
