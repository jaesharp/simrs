use cucumber::World;
use simrs_card_api::{SimEvent, SimResponse};
use simrs_gp_card::GpCard;
use simrs_gp_keys::KeySet;
use simrs_gp_scp::ScpVersion;

/// Default test key material (matches simrs-gp-tests lib.rs constants).
const KEY_BYTES: [u8; 16] = [0x40; 16];

/// Test world for GlobalPlatform BDD scenarios.
///
/// Holds a live `GpCard<261>` instance and tracks APDU exchange state.
#[derive(World)]
pub struct GpWorld {
    /// The in-process GP card being tested.
    pub card: GpCard<261>,
    /// Whether the card has been powered on.
    pub powered: bool,
    /// Last raw response (data + SW1 + SW2).
    pub last_response: Vec<u8>,
    /// Last SW1.
    pub sw1: u8,
    /// Last SW2.
    pub sw2: u8,
    /// Whether an SCP session has been established.
    pub scp_authenticated: bool,
    /// Expected card lifecycle state (for verification).
    pub expected_card_lifecycle: u8,
    /// Host challenge used in the last INITIALIZE UPDATE.
    pub host_challenge: [u8; 8],
    /// Session ENC key (derived during SCP handshake).
    pub session_enc: [u8; 16],
    /// Session MAC key (derived during SCP handshake).
    pub session_mac: [u8; 16],
    /// Card challenge extracted from INIT UPDATE response.
    pub card_challenge: [u8; 8],
    /// Last C-MAC value (for ICV chaining).
    pub last_cmac: [u8; 8],
    /// SCP version used for the current session.
    pub scp_version: ScpVersion,
    /// Security level from EXTERNAL AUTHENTICATE.
    pub security_level: u8,
    /// Last APDU bytes sent (for replay tests).
    pub last_sent_apdu: Vec<u8>,
    /// Saved old session MAC key (for re-auth tests).
    pub old_session_mac: [u8; 16],
    /// Key version to use for INIT UPDATE (default: TEST_KEY_VERSION).
    pub init_update_kv: u8,
    /// Saved AID from FCI response (for next-occurrence comparison).
    pub saved_fci_aid: Vec<u8>,
    /// Computed host cryptogram (for EXT AUTH steps).
    pub host_cryptogram: [u8; 8],
}

impl std::fmt::Debug for GpWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpWorld")
            .field("powered", &self.powered)
            .field("sw", &format_args!("{:02X}{:02X}", self.sw1, self.sw2))
            .field("scp_authenticated", &self.scp_authenticated)
            .field("lifecycle", &format_args!("0x{:02X}", self.expected_card_lifecycle))
            .finish()
    }
}

impl Default for GpWorld {
    fn default() -> Self {
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let card = GpCard::with_default_atr(&keys);
        Self {
            card,
            powered: false,
            last_response: Vec::new(),
            sw1: 0,
            sw2: 0,
            scp_authenticated: false,
            expected_card_lifecycle: 0x01, // OP_READY
            host_challenge: [0; 8],
            session_enc: [0; 16],
            session_mac: [0; 16],
            card_challenge: [0; 8],
            last_cmac: [0; 8],
            scp_version: ScpVersion::Scp02,
            security_level: 0,
            last_sent_apdu: Vec::new(),
            old_session_mac: [0; 16],
            init_update_kv: 0x01, // default key version (TEST_KEY_VERSION)
            saved_fci_aid: Vec::new(),
            host_cryptogram: [0; 8],
        }
    }
}

impl GpWorld {
    /// Ensure the card is powered on.
    pub fn ensure_powered(&mut self) {
        if !self.powered {
            let _ = self.card.process(SimEvent::PowerOn);
            self.powered = true;
        }
    }

    /// Send an APDU and record the response.
    pub fn send_apdu(&mut self, apdu: &[u8]) {
        self.ensure_powered();
        match self.card.process(SimEvent::Apdu(apdu)) {
            SimResponse::Apdu { data, sw } => {
                let [sw1, sw2] = sw.to_bytes();
                self.last_response = Vec::with_capacity(data.len() + 2);
                self.last_response.extend_from_slice(data);
                self.last_response.push(sw1);
                self.last_response.push(sw2);
                self.sw1 = sw1;
                self.sw2 = sw2;
            }
            SimResponse::Ignored => {
                self.last_response = vec![0x6F, 0x00];
                self.sw1 = 0x6F;
                self.sw2 = 0x00;
            }
            SimResponse::Atr(_) => {
                self.last_response.clear();
                self.sw1 = 0;
                self.sw2 = 0;
            }
        }
    }

    /// Get the response data (excluding SW1 SW2).
    pub fn response_data(&self) -> &[u8] {
        if self.last_response.len() >= 2 {
            &self.last_response[..self.last_response.len() - 2]
        } else {
            &[]
        }
    }

    /// Set the card lifecycle by establishing a temporary SCP session
    /// and issuing SET STATUS commands through the APDU interface.
    ///
    /// Used by Given steps that need to set up a specific card state
    /// before the test's own SCP session.
    pub fn set_lifecycle(&mut self, target: u8) {
        if target == 0x01 {
            // OP_READY is the default -- nothing to do.
            self.ensure_powered();
            return;
        }

        // Establish a temporary SCP session for the lifecycle transitions.
        self.establish_scp02_session(0x00);

        // Chain through valid transitions to reach the target state.
        let transitions: &[u8] = match target {
            0x07 => &[0x07],             // INITIALIZED
            0x0F => &[0x07, 0x0F],       // INITIALIZED -> SECURED
            0x7F => &[0x07, 0x0F, 0x7F], // -> CARD_LOCKED
            0xFF => &[0xFF],             // TERMINATED (any -> terminated)
            _ => &[],
        };

        for &state_byte in transitions {
            self.send_gp_command(
                &[0x80, 0xF0, 0x80, state_byte],
                simrs_gp_tests::ISD_AID,
            );
            assert_eq!(
                self.sw1, 0x90,
                "lifecycle transition to 0x{state_byte:02X} failed: {:02X}{:02X}",
                self.sw1, self.sw2,
            );
        }

        // Reset SCP state so the test's own SCP session starts fresh.
        self.card.open_mut().reset_scp_state();
        self.scp_authenticated = false;
    }

    /// Reset the card (power cycle).
    pub fn reset_card(&mut self) {
        let _ = self.card.process(SimEvent::Reset);
        self.scp_authenticated = false;
        self.security_level = 0;
        self.session_enc = [0; 16];
        self.session_mac = [0; 16];
        self.last_cmac = [0; 8];
    }

    /// Send a GP management command, automatically wrapping with C-MAC
    /// if a C-MAC session is active.
    pub fn send_gp_command(&mut self, header: &[u8; 4], data: &[u8]) {
        if self.scp_authenticated && self.security_level & 0x01 != 0 {
            self.send_apdu_with_cmac(header, data);
        } else {
            // Build plain APDU.
            #[allow(clippy::cast_possible_truncation)]
            if data.is_empty() {
                self.send_apdu(header);
            } else {
                let total = 5 + data.len();
                let mut apdu = vec![0u8; total];
                apdu[..4].copy_from_slice(header);
                apdu[4] = data.len() as u8;
                apdu[5..].copy_from_slice(data);
                self.send_apdu(&apdu);
            }
        }
    }

    /// Establish an SCP02 session via INITIALIZE UPDATE + EXTERNAL AUTHENTICATE.
    ///
    /// Selects the ISD, sends INITIALIZE UPDATE, derives session keys,
    /// computes the host cryptogram and C-MAC, then sends EXTERNAL AUTHENTICATE.
    ///
    /// # Panics
    ///
    /// Panics if any step of the handshake fails.
    pub fn establish_scp02_session(&mut self, security_level: u8) {
        self.ensure_powered();
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);

        // 1. SELECT ISD.
        let sel = simrs_gp_tests::select_by_aid(simrs_gp_tests::ISD_AID);
        let sel_len = 5 + simrs_gp_tests::ISD_AID.len();
        self.send_apdu(&sel[..sel_len]);
        assert_eq!(
            self.sw1, 0x90,
            "SELECT ISD failed: {:02X}{:02X}",
            self.sw1, self.sw2
        );

        // 2. INITIALIZE UPDATE.
        let hc: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        self.host_challenge = hc;
        let iu_apdu = simrs_gp_tests::initialize_update(
            self.init_update_kv,
            simrs_gp_tests::TEST_KEY_ID,
            &hc,
        );
        self.send_apdu(&iu_apdu);
        assert_eq!(
            self.sw1, 0x90,
            "INITIALIZE UPDATE failed: {:02X}{:02X}",
            self.sw1, self.sw2
        );

        let data = self.response_data().to_vec();
        assert_eq!(data.len(), 28, "INIT UPDATE response must be 28 bytes");

        // Extract card challenge (bytes 12..20 for SCP01, 12..14 seq + 14..20 challenge for SCP02).
        let scp_id = data[11];
        self.scp_version = if scp_id == 0x02 {
            ScpVersion::Scp02
        } else {
            ScpVersion::Scp01
        };

        // 3. Derive session keys.
        match self.scp_version {
            ScpVersion::Scp01 => {
                let mut cc = [0u8; 8];
                cc.copy_from_slice(&data[12..20]);
                self.card_challenge = cc;

                let (enc, mac, _dek) =
                    simrs_gp_scp::derive_scp01_session_keys(&keys, &hc, &cc);
                self.session_enc = enc;
                self.session_mac = mac;

                // 4. Compute host cryptogram.
                let host_crypto =
                    simrs_gp_scp::compute_scp01_host_cryptogram(&enc, &hc, &cc);

                // 5. Compute C-MAC for EXTERNAL AUTHENTICATE.
                let (cmac, _) = simrs_gp_scp::generate_cmac(
                    &mac,
                    &[0x84, 0x82, security_level, 0x00],
                    &host_crypto,
                    &[0u8; 8],
                    ScpVersion::Scp01,
                );

                // 6. Send EXTERNAL AUTHENTICATE.
                let ea_apdu = simrs_gp_tests::external_authenticate(
                    security_level,
                    &host_crypto,
                    &cmac,
                );
                self.send_apdu(&ea_apdu);
                self.last_cmac = cmac;
            }
            ScpVersion::Scp02 => {
                let seq = u16::from_be_bytes([data[12], data[13]]);
                let mut cc6 = [0u8; 6];
                cc6.copy_from_slice(&data[14..20]);
                // Store full 8-byte buffer with seq_counter prefix for compat.
                let mut cc8 = [0u8; 8];
                cc8[2..8].copy_from_slice(&cc6);
                self.card_challenge = cc8;

                let (enc, mac, _rmac, _dek) =
                    simrs_gp_scp::derive_scp02_session_keys(&keys, seq);
                self.session_enc = enc;
                self.session_mac = mac;

                // Host cryptogram for SCP02.
                let host_crypto =
                    simrs_gp_scp::compute_scp02_host_cryptogram(&enc, &hc, seq, &cc6);

                // C-MAC for EXTERNAL AUTHENTICATE.
                let (cmac, _) = simrs_gp_scp::generate_cmac(
                    &mac,
                    &[0x84, 0x82, security_level, 0x00],
                    &host_crypto,
                    &[0u8; 8],
                    ScpVersion::Scp02,
                );

                let ea_apdu = simrs_gp_tests::external_authenticate(
                    security_level,
                    &host_crypto,
                    &cmac,
                );
                self.send_apdu(&ea_apdu);
                self.last_cmac = cmac;
            }
        }

        assert_eq!(
            self.sw1, 0x90,
            "EXTERNAL AUTHENTICATE failed: {:02X}{:02X}",
            self.sw1, self.sw2
        );
        self.scp_authenticated = true;
        self.security_level = security_level;
    }

    /// Send an APDU wrapped with C-MAC using the current session keys.
    ///
    /// Computes C-MAC over the modified header + data, appends the 8-byte
    /// MAC to the data field, sets CLA secure messaging bit, adjusts Lc,
    /// and sends the wrapped APDU.
    #[allow(clippy::cast_possible_truncation)]
    pub fn send_apdu_with_cmac(&mut self, header: &[u8; 4], data: &[u8]) {
        // SCP01: ICV is always zeros. SCP02: chain from last C-MAC.
        let icv = match self.scp_version {
            simrs_gp_scp::ScpVersion::Scp01 => [0u8; 8],
            simrs_gp_scp::ScpVersion::Scp02 => self.last_cmac,
        };
        let (cmac, new_icv) = simrs_gp_scp::generate_cmac(
            &self.session_mac,
            header,
            data,
            &icv,
            self.scp_version,
        );
        self.last_cmac = new_icv;

        // Build wrapped APDU: CLA|0x04 || INS || P1 || P2 || Lc || data || cmac
        let new_lc = data.len() + 8;
        let total = 5 + new_lc;
        let mut apdu = vec![0u8; total];
        apdu[0] = header[0] | 0x04; // set secure messaging bit
        apdu[1] = header[1];
        apdu[2] = header[2];
        apdu[3] = header[3];
        apdu[4] = new_lc as u8;
        apdu[5..5 + data.len()].copy_from_slice(data);
        apdu[5 + data.len()..total].copy_from_slice(&cmac);

        self.last_sent_apdu = apdu.clone();
        self.send_apdu(&apdu);
    }

    /// Install a test applet via INSTALL [for install and make selectable].
    ///
    /// Uses `send_gp_command` which auto-wraps with C-MAC if needed.
    #[allow(clippy::cast_possible_truncation)]
    pub fn install_test_applet(&mut self, aid: &[u8]) {
        let data_len = 3 + aid.len(); // load(0) + module(0) + aid_len(1) + aid
        let mut data = vec![0u8; data_len];
        data[0] = 0x00; // load file AID len = 0
        data[1] = 0x00; // module AID len = 0
        data[2] = aid.len() as u8;
        data[3..3 + aid.len()].copy_from_slice(aid);

        self.send_gp_command(&[0x80, 0xE6, 0x0C, 0x00], &data);
        assert_eq!(
            self.sw1, 0x90,
            "INSTALL for test applet {:02X?} failed: {:02X}{:02X}",
            aid, self.sw1, self.sw2,
        );
    }
}
