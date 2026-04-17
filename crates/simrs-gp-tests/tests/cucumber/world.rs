use cucumber::World;
use simrs_card_api::{SimEvent, SimResponse};
use simrs_gp_card::GpCard;
use simrs_gp_keys::KeySet;
use simrs_gp_scp::ScpVersion;

/// Default test key material (matches simrs-gp-tests lib.rs constants).
const KEY_BYTES: [u8; 16] = [0x40; 16];

/// Host-side SCP session: wraps commands with version-specific MAC.
///
/// Trait polymorphism eliminates version dispatch at call sites.
/// Each SCP version carries its own chaining state and key material.
pub trait ScpSessionHost {
    /// SCP version for this session.
    fn version(&self) -> ScpVersion;
    /// Session S-ENC key.
    fn session_enc(&self) -> [u8; 16];
    /// Session S-MAC key.
    fn session_mac(&self) -> [u8; 16];
    /// Security level (P1 from EXT AUTH).
    fn security_level(&self) -> u8;
    /// Compute C-MAC for a command and advance chaining state.
    /// Returns `(8-byte MAC, new chaining state is updated internally)`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn generate_cmac(&mut self, header: &[u8; 4], data: &[u8]) -> [u8; 8];
    /// Get the 8-byte ICV for C-ENC IV derivation (SCP01/02 only).
    fn icv_for_cenc(&self) -> [u8; 8];
}

/// SCP01 host session (ICV always zeros, no chaining).
pub struct Scp01Session {
    pub enc: [u8; 16],
    pub mac: [u8; 16],
    pub sec_level: u8,
}

impl ScpSessionHost for Scp01Session {
    fn version(&self) -> ScpVersion {
        ScpVersion::Scp01
    }
    fn session_enc(&self) -> [u8; 16] {
        self.enc
    }
    fn session_mac(&self) -> [u8; 16] {
        self.mac
    }
    fn security_level(&self) -> u8 {
        self.sec_level
    }
    fn generate_cmac(&mut self, header: &[u8; 4], data: &[u8]) -> [u8; 8] {
        let (cmac, _) =
            simrs_gp_scp::generate_cmac(&self.mac, header, data, &[0u8; 8], ScpVersion::Scp01);
        cmac
    }
    fn icv_for_cenc(&self) -> [u8; 8] {
        [0u8; 8]
    }
}

/// SCP02 host session (8-byte 3DES ICV chaining).
pub struct Scp02Session {
    pub enc: [u8; 16],
    pub mac: [u8; 16],
    pub sec_level: u8,
    pub icv: [u8; 8],
}

impl ScpSessionHost for Scp02Session {
    fn version(&self) -> ScpVersion {
        ScpVersion::Scp02
    }
    fn session_enc(&self) -> [u8; 16] {
        self.enc
    }
    fn session_mac(&self) -> [u8; 16] {
        self.mac
    }
    fn security_level(&self) -> u8 {
        self.sec_level
    }
    fn generate_cmac(&mut self, header: &[u8; 4], data: &[u8]) -> [u8; 8] {
        let (cmac, new_icv) =
            simrs_gp_scp::generate_cmac(&self.mac, header, data, &self.icv, ScpVersion::Scp02);
        self.icv = new_icv;
        cmac
    }
    fn icv_for_cenc(&self) -> [u8; 8] {
        self.icv
    }
}

/// SCP03 host session (16-byte AES-CMAC chaining).
pub struct Scp03Session {
    pub enc: [u8; 16],
    pub mac: [u8; 16],
    pub sec_level: u8,
    pub mac_chaining: [u8; 16],
}

impl ScpSessionHost for Scp03Session {
    fn version(&self) -> ScpVersion {
        ScpVersion::Scp03
    }
    fn session_enc(&self) -> [u8; 16] {
        self.enc
    }
    fn session_mac(&self) -> [u8; 16] {
        self.mac
    }
    fn security_level(&self) -> u8 {
        self.sec_level
    }
    fn generate_cmac(&mut self, header: &[u8; 4], data: &[u8]) -> [u8; 8] {
        let (cmac, new_cv) =
            simrs_gp_scp::scp03_generate_cmac(&self.mac, &self.mac_chaining, header, data);
        self.mac_chaining = new_cv;
        cmac
    }
    fn icv_for_cenc(&self) -> [u8; 8] {
        // SCP03 C-ENC uses counter-derived IV, not ICV.
        [0u8; 8]
    }
}

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
    /// Expected card lifecycle state (for verification).
    pub expected_card_lifecycle: u8,
    /// Host challenge used in the last INITIALIZE UPDATE.
    pub host_challenge: [u8; 8],
    /// Card challenge extracted from INIT UPDATE response.
    pub card_challenge: [u8; 8],
    /// Active SCP session (None before EXT AUTH succeeds).
    pub scp_session: Option<Box<dyn ScpSessionHost + Send>>,
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
    /// JCVM instance for bytecode-level security tests.
    pub jcvm: Box<simrs_jcvm::JcVM<4096, 4>>,
    /// Last JCVM execution result.
    pub jcvm_result: Option<simrs_jcvm::opcodes::ExecResult>,
    /// Byte array ref allocated by scenario setup.
    pub jcvm_array_ref: simrs_jcvm::heap::ObjRef,
    /// Second array ref (for type confusion tests).
    pub jcvm_array_ref2: simrs_jcvm::heap::ObjRef,
    /// Instance object ref (for firewall tests).
    pub jcvm_obj_ref: simrs_jcvm::heap::ObjRef,
    /// PIN try counter value (for transaction tests).
    pub pin_try_counter: u8,
}

impl std::fmt::Debug for GpWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpWorld")
            .field("powered", &self.powered)
            .field("sw", &format_args!("{:02X}{:02X}", self.sw1, self.sw2))
            .field("scp_authenticated", &self.scp_session.is_some())
            .field(
                "lifecycle",
                &format_args!("0x{:02X}", self.expected_card_lifecycle),
            )
            .finish()
    }
}

impl Default for GpWorld {
    fn default() -> Self {
        let keys = KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let mut card = GpCard::with_default_atr(&keys);
        // Add AES-128 keys at version 0x03 for SCP03 testing.
        let aes_keys = KeySet::aes128(KEY_BYTES, KEY_BYTES, KEY_BYTES);
        let _ = card.open_mut().add_key(0x03, &aes_keys);
        Self {
            card,
            powered: false,
            last_response: Vec::new(),
            sw1: 0,
            sw2: 0,
            expected_card_lifecycle: 0x01, // OP_READY
            host_challenge: [0; 8],
            card_challenge: [0; 8],
            scp_session: None,
            last_sent_apdu: Vec::new(),
            old_session_mac: [0; 16],
            init_update_kv: 0x01, // default key version (TEST_KEY_VERSION)
            saved_fci_aid: Vec::new(),
            host_cryptogram: [0; 8],
            jcvm: Box::new(simrs_jcvm::JcVM::new()),
            jcvm_result: None,
            jcvm_array_ref: simrs_jcvm::heap::ObjRef::NULL,
            jcvm_array_ref2: simrs_jcvm::heap::ObjRef::NULL,
            jcvm_obj_ref: simrs_jcvm::heap::ObjRef::NULL,
            pin_try_counter: 0,
        }
    }
}

impl GpWorld {
    /// Shorthand: is an SCP session active?
    pub fn scp_authenticated(&self) -> bool {
        self.scp_session.is_some()
    }
    /// Shorthand: session ENC key (panics if no session).
    pub fn session_enc(&self) -> [u8; 16] {
        self.scp_session.as_ref().unwrap().session_enc()
    }
    /// Shorthand: session MAC key (panics if no session).
    pub fn session_mac(&self) -> [u8; 16] {
        self.scp_session.as_ref().unwrap().session_mac()
    }
    /// Shorthand: security level (panics if no session).
    pub fn security_level(&self) -> u8 {
        self.scp_session.as_ref().unwrap().security_level()
    }
    /// Shorthand: SCP version (panics if no session).
    pub fn scp_version(&self) -> ScpVersion {
        self.scp_session.as_ref().unwrap().version()
    }

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
            self.send_gp_command(&[0x80, 0xF0, 0x80, state_byte], simrs_gp_tests::ISD_AID);
            assert_eq!(
                self.sw1, 0x90,
                "lifecycle transition to 0x{state_byte:02X} failed: {:02X}{:02X}",
                self.sw1, self.sw2,
            );
        }

        // Reset SCP state so the test's own SCP session starts fresh.
        self.card.open_mut().reset_scp_state();
        self.scp_session = None;
    }

    /// Reset the card (power cycle).
    pub fn reset_card(&mut self) {
        let _ = self.card.process(SimEvent::Reset);
        self.scp_session = None;
    }

    /// Send a GP management command, automatically wrapping with C-MAC
    /// if a C-MAC session is active.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn send_gp_command(&mut self, header: &[u8; 4], data: &[u8]) {
        if self
            .scp_session
            .as_ref()
            .is_some_and(|s| s.security_level() & 0x01 != 0)
        {
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
    #[allow(clippy::too_many_lines)]
    pub fn establish_scp02_session(&mut self, security_level: u8) {
        self.ensure_powered();
        // Key type depends on key version: 0x03 = AES (SCP03), else 3DES.
        let keys = if self.init_update_kv == 0x03 {
            KeySet::aes128(KEY_BYTES, KEY_BYTES, KEY_BYTES)
        } else {
            KeySet::des3_2key(KEY_BYTES, KEY_BYTES, KEY_BYTES)
        };

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
        assert!(data.len() >= 28, "INIT UPDATE response must be >= 28 bytes");

        // Extract card challenge (bytes 12..20 for SCP01, 12..14 seq + 14..20 challenge for SCP02).
        let scp_id = data[11];
        let scp_version = match scp_id {
            0x01 => ScpVersion::Scp01,
            0x03 => ScpVersion::Scp03,
            _ => ScpVersion::Scp02,
        };

        // 3. Derive session keys and create session object.
        match scp_version {
            ScpVersion::Scp01 => {
                let mut cc = [0u8; 8];
                cc.copy_from_slice(&data[12..20]);
                self.card_challenge = cc;

                let (enc, mac, _dek) = simrs_gp_scp::derive_scp01_session_keys(&keys, &hc, &cc);

                // 4. Compute host cryptogram.
                let host_crypto = simrs_gp_scp::compute_scp01_host_cryptogram(&enc, &hc, &cc);

                // 5. Compute C-MAC for EXTERNAL AUTHENTICATE.
                let (cmac, _) = simrs_gp_scp::generate_cmac(
                    &mac,
                    &[0x84, 0x82, security_level, 0x00],
                    &host_crypto,
                    &[0u8; 8],
                    ScpVersion::Scp01,
                );

                // 6. Send EXTERNAL AUTHENTICATE.
                let ea_apdu =
                    simrs_gp_tests::external_authenticate(security_level, &host_crypto, &cmac);
                self.send_apdu(&ea_apdu);
                self.scp_session = Some(Box::new(Scp01Session {
                    enc,
                    mac,
                    sec_level: security_level,
                }));
            }
            ScpVersion::Scp02 => {
                let seq = u16::from_be_bytes([data[12], data[13]]);
                let mut cc6 = [0u8; 6];
                cc6.copy_from_slice(&data[14..20]);
                // Store full 8-byte buffer with seq_counter prefix for compat.
                let mut cc8 = [0u8; 8];
                cc8[2..8].copy_from_slice(&cc6);
                self.card_challenge = cc8;

                let (enc, mac, _rmac, _dek) = simrs_gp_scp::derive_scp02_session_keys(&keys, seq);

                // Host cryptogram for SCP02.
                let host_crypto = simrs_gp_scp::compute_scp02_host_cryptogram(&enc, &hc, seq, &cc6);

                // C-MAC for EXTERNAL AUTHENTICATE.
                let (cmac, _) = simrs_gp_scp::generate_cmac(
                    &mac,
                    &[0x84, 0x82, security_level, 0x00],
                    &host_crypto,
                    &[0u8; 8],
                    ScpVersion::Scp02,
                );

                let ea_apdu =
                    simrs_gp_tests::external_authenticate(security_level, &host_crypto, &cmac);
                self.send_apdu(&ea_apdu);
                let mut icv = [0u8; 8];
                icv.copy_from_slice(&cmac);
                self.scp_session = Some(Box::new(Scp02Session {
                    enc,
                    mac,
                    sec_level: security_level,
                    icv,
                }));
            }
            ScpVersion::Scp03 => {
                // SCP03: 29-byte response.
                // [0..10] key_div, [10] key_ver, [11] scp_id(0x03), [12] i_param,
                // [13..21] card_challenge, [21..29] card_cryptogram
                let mut cc = [0u8; 8];
                cc.copy_from_slice(&data[13..21]);
                self.card_challenge = cc;

                let mut static_key = [0u8; 16];
                static_key.copy_from_slice(keys.enc());

                let (enc, mac, _rmac) =
                    simrs_gp_scp::derive_scp03_session_keys(&static_key, &static_key, &hc, &cc);

                let host_crypto = simrs_gp_scp::compute_scp03_host_cryptogram(&mac, &hc, &cc);

                let (cmac, new_cv) = simrs_gp_scp::scp03_generate_cmac(
                    &mac,
                    &[0u8; 16],
                    &[0x84, 0x82, security_level, 0x00],
                    &host_crypto,
                );

                let ea_apdu =
                    simrs_gp_tests::external_authenticate(security_level, &host_crypto, &cmac);
                self.send_apdu(&ea_apdu);
                self.scp_session = Some(Box::new(Scp03Session {
                    enc,
                    mac,
                    sec_level: security_level,
                    mac_chaining: new_cv,
                }));
            }
        }

        assert_eq!(
            self.sw1, 0x90,
            "EXTERNAL AUTHENTICATE failed: {:02X}{:02X}",
            self.sw1, self.sw2
        );
    }

    /// Send an APDU wrapped with C-MAC using the current session keys.
    ///
    /// Computes C-MAC over the modified header + data, appends the 8-byte
    /// MAC to the data field, sets CLA secure messaging bit, adjusts Lc,
    /// and sends the wrapped APDU.
    #[allow(clippy::cast_possible_truncation, clippy::trivially_copy_pass_by_ref)]
    pub fn send_apdu_with_cmac(&mut self, header: &[u8; 4], data: &[u8]) {
        let session = self.scp_session.as_mut().expect("no SCP session for C-MAC");
        let cmac = session.generate_cmac(header, data);

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

        self.last_sent_apdu.clone_from(&apdu);
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
