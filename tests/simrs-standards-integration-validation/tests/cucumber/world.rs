#![allow(missing_docs)]
//! `SpecWorld` state and helper functions shared across all step definition modules.

use cucumber::World;
use simrs_fs::{FsError, SelectedFile, SelectionCtx};
use simrs_milenage::{AuthenticationError, AuthenticationOutput, MilenageParams};
use simrs_pin::{PinError, PinManager, PinResult};
use simrs_proactive::ProactiveState;
use simrs_sim::Sim;
use simrs_standards_integration_validation::{send_apdu, verify_pin1};

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

#[derive(Default, World)]
#[allow(dead_code)] // Fields are scaffolded for step definitions added incrementally.
pub struct SpecWorld {
    // ---- APDU-level state (SIM integration testing) ----
    pub sim: Option<Box<Sim<MilenageParams, 256>>>,
    pub powered_on: bool,
    pub last_sw: Option<(u8, u8)>,
    pub last_data: Vec<u8>,
    pub last_ignored: bool,
    /// Set when the last `sim.process()` returned `SimResponse::Atr`.
    pub last_atr: bool,
    /// When `true`, CLA-dependent shared steps use GSM CLA (0xA0).
    /// Set by `Given a GsmApp with:`, cleared by `Given a UsimApp with:`.
    pub gsm_mode: bool,

    // ---- Library-level state slots (unit-style BDD) ----
    /// Raw hex input bytes for library-level tests.
    pub hex_input: Vec<u8>,
    /// Computed output bytes (generic slot).
    pub hex_output: Vec<u8>,

    // COMP128
    pub ki: Option<[u8; 16]>,
    pub rand_val: Option<[u8; 16]>,
    pub sres: Option<[u8; 4]>,
    pub kc: Option<[u8; 8]>,
    /// Alternate SRES for comparison scenarios (e.g. "the two SRES values differ").
    pub sres_alt: Option<[u8; 4]>,
    /// Alternate Kc for comparison scenarios.
    pub kc_alt: Option<[u8; 8]>,

    // Milenage
    pub milenage_k: Option<[u8; 16]>,
    pub milenage_opc: Option<[u8; 16]>,
    pub milenage_op: Option<[u8; 16]>,
    pub milenage_challenge: Option<[u8; 16]>,
    pub milenage_sequence_number: Option<[u8; 6]>,
    pub milenage_management_field: Option<[u8; 2]>,
    pub milenage_auth_mac: Option<[u8; 8]>,
    pub milenage_resync_mac: Option<[u8; 8]>,
    pub milenage_response: Option<[u8; 8]>,
    pub milenage_cipher_key: Option<[u8; 16]>,
    pub milenage_integrity_key: Option<[u8; 16]>,
    pub milenage_anonymity_key: Option<[u8; 6]>,
    pub milenage_resync_anonymity_key: Option<[u8; 6]>,
    pub milenage_gsm_cipher_key: Option<[u8; 8]>,
    pub milenage_auth_token: Option<[u8; 16]>,
    pub milenage_auth_result: Option<Result<AuthenticationOutput, AuthenticationError>>,
    /// Secondary f2 result for equivalence comparison.
    pub milenage_f2_alt: Option<[u8; 8]>,
    /// Param construction result (for validation tests).
    pub milenage_param_result: Option<Result<MilenageParams, simrs_milenage::ParamError>>,

    // Proactive
    pub proactive_state: Option<ProactiveState>,
    pub proactive_encoded: Vec<u8>,
    pub proactive_encoded_len: usize,
    pub proactive_dry_run_len: Option<usize>,
    pub proactive_error: Option<simrs_proactive::ProactiveError>,
    pub proactive_override_result: Option<(u8, u8)>,

    // ISO 7816 -- APDU parsing / CLA / StatusWord
    pub parsed_ins: Option<u8>,
    pub parsed_data: Vec<u8>,
    pub parsed_le: Option<Option<u8>>,
    pub parsed_cla_class: Option<String>,
    pub parsed_sw: Option<(u8, u8)>,
    pub parse_error: Option<String>,

    // BER-TLV
    pub tlv_bytes: Vec<u8>,
    pub tlv_tag: Option<u32>,
    pub tlv_length: Option<usize>,
    pub tlv_value: Vec<u8>,
    /// Encoder output buffer (written bytes).
    pub tlv_encoder_output: Vec<u8>,
    /// Encoder position (bytes written / counted).
    pub tlv_encoder_pos: usize,
    /// List of decoded TLV objects: (tag, value).
    pub tlv_decoded: Vec<(u8, Vec<u8>)>,
    /// Input TLVs for roundtrip tests: (tag, value).
    pub tlv_input_pairs: Vec<(u8, Vec<u8>)>,
    /// Dry-run byte count.
    pub tlv_dry_run_count: Option<usize>,

    // PIN/PUK management
    pub pin_manager: Option<Box<PinManager<5>>>,
    /// Most recent PinResult from a PIN operation.
    pub pin_result: Option<PinResult>,
    /// Most recent PinError from add_pin or similar.
    pub pin_error: Option<PinError>,
    /// Stash of multiple PinResult values (for multi-attempt scenarios).
    pub pin_results: Vec<PinResult>,

    // Filesystem (SelectionCtx-level tests)
    pub fs_ctx: Option<SelectionCtx>,
    pub fs_result: Option<Result<SelectedFile, FsError>>,
    pub fs_read_data: Vec<u8>,

    // Transport
    pub transport_event: Option<simrs_transport::CardEvent>,
    pub transport_error: Option<simrs_transport::TransportError>,

    // TCP transport (swICC)
    pub tcp_msg: Option<simrs_transport_tcp::SwIccMessage>,
    pub tcp_wire: Vec<u8>,
    pub tcp_decode_error: Option<simrs_transport::TransportError>,

    // Generic error slot
    pub last_error: Option<String>,
}

impl std::fmt::Debug for SpecWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpecWorld")
            .field("sim", &self.sim.as_ref().map(|_| "<Sim>"))
            .field("powered_on", &self.powered_on)
            .field("last_sw", &self.last_sw)
            .field(
                "last_data",
                &self
                    .last_data
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            )
            .field("last_ignored", &self.last_ignored)
            .field("hex_input.len", &self.hex_input.len())
            .field("hex_output.len", &self.hex_output.len())
            .field("last_error", &self.last_error)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helpers (pub -- used by step definition modules)
// ---------------------------------------------------------------------------

pub fn sim_mut(world: &mut SpecWorld) -> &mut Sim<MilenageParams, 256> {
    world.sim.as_mut().expect("SIM not initialised")
}

/// Send a raw APDU byte slice and store the result in world state.
pub fn do_send_apdu(world: &mut SpecWorld, cmd: &[u8]) {
    let sim = sim_mut(world);
    if let Some((data, sw1, sw2)) = send_apdu(sim, cmd) {
        world.last_sw = Some((sw1, sw2));
        world.last_data = data;
        world.last_ignored = false;
        world.last_atr = false;
    } else {
        world.last_sw = None;
        world.last_data = Vec::new();
        world.last_ignored = true;
        world.last_atr = false;
    }
}

/// Verify PIN1 with correct PIN so FS commands succeed.
pub fn ensure_pin1_verified(world: &mut SpecWorld) {
    let sim = sim_mut(world);
    verify_pin1(sim);
}
