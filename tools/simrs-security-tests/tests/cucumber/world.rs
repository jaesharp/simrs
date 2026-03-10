#![allow(missing_docs)]
//! `SimWorld` state and helper functions shared across all step definition modules.

use std::collections::HashSet;

use cucumber::World;
use simrs_iso7816::ins;
use simrs_pin::PinKey;
use simrs_security_tests::{send_apdu, send_apdu_sw, verify_pin1, TestSim};
use simrs_sim::{SimEvent, SimResponse};

use super::snapshot::{SnapshotRegistry, StatePath};

// ---------------------------------------------------------------------------
// Interposer (declarative APDU mutation rules)
// ---------------------------------------------------------------------------

/// Which commands an interposer rule matches.
#[derive(Clone, Debug)]
pub enum CommandMatcher {
    /// Match by INS byte.
    ByIns(u8),
    /// Match every command.
    All,
}

/// What the interposer does to a matched command.
#[derive(Clone, Debug)]
pub enum Mutation {
    /// Override P1.
    SetP1(u8),
    /// Override P2.
    SetP2(u8),
    /// Override CLA.
    SetCla(u8),
    /// Truncate the data field to N bytes.
    TruncateData(usize),
    /// Drop the command entirely (don't send to SIM).
    Drop,
}

/// A declarative interposer rule: when a command matches, apply a mutation.
#[derive(Clone, Debug)]
pub struct InterposerRule {
    pub matcher: CommandMatcher,
    pub mutation: Mutation,
}

/// Result of applying interposer rules to a command.
enum InterposerResult {
    /// Send the (possibly mutated) command to the SIM.
    Send(Vec<u8>),
    /// The command was dropped by the interposer.
    Dropped,
}

/// INS name to byte mapping for interposer Given steps.
pub fn ins_from_name(name: &str) -> u8 {
    match name {
        "VERIFY" => ins::VERIFY,
        "CHANGE" | "CHANGE REFERENCE DATA" => ins::CHANGE_REF_DATA,
        "DISABLE" | "DISABLE PIN" => ins::DISABLE_PIN,
        "ENABLE" | "ENABLE PIN" => ins::ENABLE_PIN,
        "UNBLOCK" | "RESET RETRY COUNTER" => ins::RESET_RETRY_CTR,
        "SELECT" => ins::SELECT,
        "READ BINARY" => ins::READ_BINARY,
        "UPDATE BINARY" => ins::UPDATE_BINARY,
        "READ RECORD" => ins::READ_RECORD,
        "GET RESPONSE" => ins::GET_RESPONSE,
        "AUTHENTICATE" => ins::AUTHENTICATE,
        "TERMINAL PROFILE" => ins::TERMINAL_PROFILE,
        "ENVELOPE" => ins::ENVELOPE,
        "GET IDENTITY" => ins::GET_IDENTITY,
        _ => panic!("Unknown command name for interposer: {name:?}"),
    }
}

/// Apply all interposer rules to a command byte slice.
fn apply_interposer_rules(rules: &[InterposerRule], cmd: &[u8]) -> InterposerResult {
    if rules.is_empty() || cmd.len() < 4 {
        return InterposerResult::Send(cmd.to_vec());
    }

    let mut result = cmd.to_vec();
    for rule in rules {
        let matches = match &rule.matcher {
            CommandMatcher::ByIns(target_ins) => result.len() >= 2 && result[1] == *target_ins,
            CommandMatcher::All => true,
        };
        if !matches {
            continue;
        }
        match &rule.mutation {
            Mutation::SetP1(v) => {
                if result.len() >= 3 {
                    result[2] = *v;
                }
            }
            Mutation::SetP2(v) => {
                if result.len() >= 4 {
                    result[3] = *v;
                }
            }
            Mutation::SetCla(v) => {
                if !result.is_empty() {
                    result[0] = *v;
                }
            }
            Mutation::TruncateData(max_len) => {
                // If data starts at byte 5 (after CLA INS P1 P2 Lc)
                if result.len() > 5 {
                    let data_start = 5;
                    let new_end = (data_start + max_len).min(result.len());
                    result.truncate(new_end);
                    // Update Lc
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        result[4] = (new_end - data_start) as u8;
                    }
                }
            }
            Mutation::Drop => {
                return InterposerResult::Dropped;
            }
        }
    }
    InterposerResult::Send(result)
}

// ---------------------------------------------------------------------------
// Phase / Response state machine
// ---------------------------------------------------------------------------

/// SIM lifecycle phase.
///
/// Encodes the test harness's view of the SIM's lifecycle:
/// - `Uninit`: no SIM exists (cucumber `Default` state)
/// - `Active`: SIM struct exists; `powered` tracks whether `PowerOn` has been sent
#[derive(Default)]
pub enum Phase {
    #[default]
    Uninit,
    Active {
        sim: Box<TestSim>,
        response: Response,
        powered: bool,
    },
}

impl std::fmt::Debug for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uninit => write!(f, "Uninit"),
            Self::Active { response, powered, .. } => {
                if *powered {
                    write!(f, "Active({response:?})")
                } else {
                    write!(f, "Active(unpowered)")
                }
            }
        }
    }
}

/// Result of the most recent APDU dispatch within the `Active` phase.
///
/// - `Idle`: no APDU sent since power-on/reset
/// - `Dropped`: APDU produced no response (interposer `Drop` or SIM returned `None`)
/// - `Received`: APDU returned a status word and (possibly empty) data
#[derive(Clone, Default)]
pub enum Response {
    #[default]
    Idle,
    Dropped,
    Received { sw: (u8, u8), data: Vec<u8> },
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Dropped => write!(f, "Dropped"),
            Self::Received { sw: (sw1, sw2), data } => {
                write!(f, "Received {{ sw: {sw1:02X} {sw2:02X}, data: {} bytes", data.len())?;
                if !data.is_empty() {
                    write!(f, " [")?;
                    for (i, b) in data.iter().enumerate() {
                        if i > 0 {
                            write!(f, " ")?;
                        }
                        write!(f, "{b:02X}")?;
                    }
                    write!(f, "]")?;
                }
                write!(f, " }}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

#[derive(Default, World)]
pub struct SimWorld {
    /// SIM lifecycle phase (owns the SIM and its last response).
    pub phase: Phase,
    /// Stashed response for "second call differs from first" assertions.
    pub first_auth_response: Option<Response>,
    /// OTA encoded packet stash (used between Given and When in OTA tests).
    pub ota_packet: Vec<u8>,
    /// Per-APDU log for mixed-length sequence assertions: (`apdu_len`, `was_processed`).
    pub apdu_log: Vec<(usize, bool)>,
    /// SW2 from the most recent 61 XX response (saved before GET RESPONSE overwrites it).
    pub prev_sw2_61: Option<u8>,
    /// Declarative interposer rules (applied in `do_send_apdu`).
    pub interposer_rules: Vec<InterposerRule>,
    /// Full state snapshot captured BEFORE first APDU.
    pub state_before: Option<Vec<u8>>,
    /// Full state snapshot captured AFTER each `do_send_apdu` call.
    pub state_after: Option<Vec<u8>>,
    /// Registry built from `state_before` (maps bytes to typed `StatePath`s).
    pub registry: Option<SnapshotRegistry>,
    /// Typed paths reserved as expected-changed by When steps.
    pub reservations: HashSet<StatePath>,
}

impl std::fmt::Debug for SimWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimWorld")
            .field("phase", &self.phase)
            .field("first_auth_response", &self.first_auth_response)
            .field("ota_packet_len", &self.ota_packet.len())
            .field("apdu_log_len", &self.apdu_log.len())
            .field("prev_sw2_61", &self.prev_sw2_61)
            .field("interposer_rules", &self.interposer_rules.len())
            .field("state_before", &self.state_before.as_ref().map(Vec::len))
            .field("state_after", &self.state_after.as_ref().map(Vec::len))
            .field("registry", &self.registry.as_ref().map(|_| "<SnapshotRegistry>"))
            .field("reservations", &self.reservations.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SimWorld accessor methods
// ---------------------------------------------------------------------------

impl SimWorld {
    /// Get `&mut TestSim`.
    pub fn sim_mut(&mut self) -> &mut TestSim {
        match &mut self.phase {
            Phase::Active { sim, .. } => sim,
            Phase::Uninit => panic!("SIM not initialised"),
        }
    }

    /// Get `&TestSim`.
    pub fn sim_ref(&self) -> &TestSim {
        match &self.phase {
            Phase::Active { sim, .. } => sim,
            Phase::Uninit => panic!("SIM not initialised"),
        }
    }

    /// Get the current `Response`. Panics if `Uninit`.
    pub fn response(&self) -> &Response {
        match &self.phase {
            Phase::Active { response, .. } => response,
            Phase::Uninit => panic!("SIM not initialised"),
        }
    }

    /// Get the SW from the last `Received` response. Panics if `Dropped` or `Idle`.
    pub fn last_sw(&self) -> (u8, u8) {
        match self.response() {
            Response::Received { sw, .. } => *sw,
            Response::Dropped => panic!("No SW available (APDU was dropped)"),
            Response::Idle => panic!("No SW available (no APDU sent)"),
        }
    }

    /// Get the SW as `Option` -- returns `None` for `Dropped`, `Idle`, or `Uninit`.
    pub fn last_sw_opt(&self) -> Option<(u8, u8)> {
        match &self.phase {
            Phase::Active { response: Response::Received { sw, .. }, .. } => Some(*sw),
            _ => None,
        }
    }

    /// Get the response data from the last `Received` response. Panics if not `Received`.
    pub fn last_data(&self) -> &[u8] {
        match self.response() {
            Response::Received { data, .. } => data,
            Response::Dropped => panic!("No data available (APDU was dropped)"),
            Response::Idle => panic!("No data available (no APDU sent)"),
        }
    }

    /// True if the last response was `Dropped`.
    pub fn last_apdu_dropped(&self) -> bool {
        matches!(self.response(), Response::Dropped)
    }

    /// True if the SIM has been powered on (ATR received).
    pub fn is_powered(&self) -> bool {
        matches!(self.phase, Phase::Active { powered: true, .. })
    }

    /// Set the phase to `Active` (powered) with the given SIM.
    pub fn activate(&mut self, sim: Box<TestSim>) {
        self.phase = Phase::Active {
            sim,
            response: Response::Idle,
            powered: true,
        };
    }

    /// Set the phase to `Active` (unpowered) with the given SIM.
    pub fn create_unpowered(&mut self, sim: Box<TestSim>) {
        self.phase = Phase::Active {
            sim,
            response: Response::Idle,
            powered: false,
        };
    }

    /// Send `PowerOn` and transition to powered state.
    pub fn power_on(&mut self) -> Vec<u8> {
        let mut sim = match std::mem::take(&mut self.phase) {
            Phase::Active { sim, .. } => sim,
            Phase::Uninit => panic!("SIM not initialised"),
        };
        let resp = sim.process(SimEvent::PowerOn);
        let atr = match resp {
            SimResponse::Atr(atr) => atr.to_vec(),
            other => panic!("Expected ATR, got {other:?}"),
        };
        self.phase = Phase::Active {
            sim,
            response: Response::Idle,
            powered: true,
        };
        atr
    }

    /// Record a successful APDU response.
    pub fn record_response(&mut self, sw: (u8, u8), data: Vec<u8>) {
        match &mut self.phase {
            Phase::Active { response, .. } => {
                *response = Response::Received { sw, data };
            }
            Phase::Uninit => panic!("Cannot record response: SIM not initialised"),
        }
    }

    /// Record that the APDU was dropped (no response produced).
    pub fn record_dropped(&mut self) {
        match &mut self.phase {
            Phase::Active { response, .. } => {
                *response = Response::Dropped;
            }
            Phase::Uninit => panic!("Cannot record dropped: SIM not initialised"),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (pub -- used by step definition modules)
// ---------------------------------------------------------------------------

/// Capture a full byte-level snapshot of the SIM state.
pub fn capture_snapshot(sim: &TestSim) -> Vec<u8> {
    let mut buf = vec![0u8; TestSim::SNAPSHOT_SIZE];
    let n = sim.save_state(&mut buf);
    assert_eq!(n, TestSim::SNAPSHOT_SIZE, "save_state wrote unexpected size");
    buf
}

/// Capture the "before" snapshot and build the registry if not already done.
pub fn ensure_state_before(world: &mut SimWorld) {
    if world.state_before.is_none() {
        let snap = capture_snapshot(world.sim_ref());
        let reg = SnapshotRegistry::from_snapshot(&snap);
        world.state_before = Some(snap);
        world.registry = Some(reg);
    }
}

/// Clear snapshot state so the next `do_send_apdu` captures a fresh baseline.
///
/// Call this at the end of Given steps that route through `do_send_apdu`.
/// Without this, the one-shot `ensure_state_before` fires during the Given step
/// and the baseline includes pre-Given state, making Then "no SIM state has
/// changed" see Given-step changes as unexpected diffs.
pub fn reset_state_snapshots(world: &mut SimWorld) {
    world.state_before = None;
    world.state_after = None;
    world.registry = None;
    world.reservations.clear();
}

/// Send a raw APDU byte slice and store the result in world state.
///
/// Applies any active interposer rules before forwarding to the SIM.
/// Auto-captures a byte-level snapshot before the first APDU and
/// updates the "after" snapshot after every APDU.
pub fn do_send_apdu(world: &mut SimWorld, cmd: &[u8]) {
    // Auto-capture state snapshot before first APDU.
    ensure_state_before(world);

    // Apply interposer rules.
    let result = apply_interposer_rules(&world.interposer_rules, cmd);
    let wire_cmd = match result {
        InterposerResult::Send(cmd) => cmd,
        InterposerResult::Dropped => {
            world.record_dropped();
            world.apdu_log.push((cmd.len(), false));
            return;
        }
    };

    let apdu_len = wire_cmd.len();
    let response = send_apdu(world.sim_mut(), &wire_cmd);

    if let Some((data, sw1, sw2)) = response {
        // Save SW2 from 61 XX responses before the next command overwrites it.
        if sw1 == 0x61 {
            world.prev_sw2_61 = Some(sw2);
        }
        world.record_response((sw1, sw2), data);
        world.apdu_log.push((apdu_len, true));
    } else {
        world.record_dropped();
        world.apdu_log.push((apdu_len, false));
    }

    // Update "after" snapshot for state-diff assertions.
    world.state_after = Some(capture_snapshot(world.sim_ref()));
}

/// Query PIN1 retry counter via empty-data VERIFY APDU.
/// Returns the remaining retries (the X in SW 63 CX).
pub fn query_pin1_retries(world: &mut SimWorld) -> u8 {
    let cmd = simrs_security_tests::apdu::verify_query(PinKey::PIN1).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &cmd);
    if sw1 == 0x63 {
        sw2 & 0x0F
    } else if sw1 == 0x69 && sw2 == 0x83 {
        // Blocked
        0
    } else if sw1 == 0x69 && sw2 == 0x84 {
        // Disabled -- query cannot return retry count via this mechanism;
        // use pin_manager directly.
        let pm = world.sim_mut().usim_app_mut().pin_manager();
        pm.retries(PinKey::PIN1).unwrap_or(0)
    } else {
        panic!("Unexpected SW from VERIFY query: {sw1:02X} {sw2:02X}");
    }
}

/// Query PUK1 retry counter via empty-data UNBLOCK APDU.
pub fn query_puk1_retries(world: &mut SimWorld) -> u8 {
    let cmd = simrs_security_tests::apdu::unblock_query(PinKey::PIN1).build();
    let (sw1, sw2) = send_apdu_sw(world.sim_mut(), &cmd);
    if sw1 == 0x63 {
        sw2 & 0x0F
    } else if sw1 == 0x69 && sw2 == 0x83 {
        0
    } else {
        panic!("Unexpected SW from UNBLOCK query: {sw1:02X} {sw2:02X}");
    }
}

/// Select ADF.USIM by AID: A0 00 00 00 87 10 02
pub fn select_adf_usim(world: &mut SimWorld) {
    use simrs_security_tests::apdu;
    let cmd = apdu::select_aid(&apdu::AID_USIM).build();
    do_send_apdu(world, &cmd);
    // If SELECT returned 61 XX, consume the FCP.
    if let Some((0x61, le)) = world.last_sw_opt() {
        let get_resp = apdu::get_response(le).build();
        do_send_apdu(world, &get_resp);
    }
}

/// Select MF and consume the FCP.
pub fn select_mf_and_consume(world: &mut SimWorld) {
    use simrs_security_tests::apdu;
    let cmd = apdu::select_fid(apdu::FID_MF).build();
    do_send_apdu(world, &cmd);
    if let Some((0x61, le)) = world.last_sw_opt() {
        let get_resp = apdu::get_response(le).build();
        do_send_apdu(world, &get_resp);
    }
}

/// Verify PIN1 with correct PIN so FS commands succeed.
pub fn ensure_pin1_verified(world: &mut SimWorld) {
    verify_pin1(world.sim_mut());
}

/// Send TERMINAL PROFILE with a 4-byte all-ones bitmap.
pub fn send_terminal_profile(world: &mut SimWorld) {
    let cmd = simrs_security_tests::apdu::terminal_profile(&[0xFF; 4]).build();
    do_send_apdu(world, &cmd);
}

// ---------------------------------------------------------------------------
// AUTHENTICATE Response Parsing
// ---------------------------------------------------------------------------

/// Parsed UMTS AUTHENTICATE success response (tag DB).
///
/// Per 3GPP TS 31.102, format inside tag DB:
///   `[L_RES] [RES] [L_CK] [CK] [L_IK] [IK] [L_KC] [Kc]?`
pub struct AuthDbResponse<'a> {
    pub res: &'a [u8],
    pub ck: &'a [u8],
    pub ik: &'a [u8],
}

/// Parse a UMTS AUTHENTICATE success response (tag DB).
///
/// Returns `None` if the data doesn't start with 0xDB or is too short.
pub fn parse_db_response(data: &[u8]) -> Option<AuthDbResponse<'_>> {
    if data.is_empty() || data[0] != 0xDB {
        return None;
    }
    let (total_len, mut pos) = tlv_read_length(data, 1);
    if pos + total_len > data.len() {
        return None;
    }
    // RES: length-prefixed
    if pos >= data.len() {
        return None;
    }
    let res_len = data[pos] as usize;
    pos += 1;
    if pos + res_len > data.len() {
        return None;
    }
    let res = &data[pos..pos + res_len];
    pos += res_len;
    // CK: length-prefixed
    if pos >= data.len() {
        return None;
    }
    let ck_len = data[pos] as usize;
    pos += 1;
    if pos + ck_len > data.len() {
        return None;
    }
    let ck = &data[pos..pos + ck_len];
    pos += ck_len;
    // IK: length-prefixed
    if pos >= data.len() {
        return None;
    }
    let ik_len = data[pos] as usize;
    pos += 1;
    if pos + ik_len > data.len() {
        return None;
    }
    let ik = &data[pos..pos + ik_len];
    Some(AuthDbResponse { res, ck, ik })
}

// ---------------------------------------------------------------------------
// TLV Parsing Helpers
// ---------------------------------------------------------------------------

/// Read a BER-TLV length at the given offset. Returns `(length, new_offset)`.
pub fn tlv_read_length(data: &[u8], offset: usize) -> (usize, usize) {
    if offset >= data.len() {
        return (0, offset);
    }
    let first = data[offset];
    if first < 0x80 {
        (first as usize, offset + 1)
    } else if first == 0x81 && offset + 1 < data.len() {
        (data[offset + 1] as usize, offset + 2)
    } else if first == 0x82 && offset + 2 < data.len() {
        let len = ((data[offset + 1] as usize) << 8) | (data[offset + 2] as usize);
        (len, offset + 3)
    } else {
        (0, offset + 1)
    }
}

/// Search for a TLV tag inside an FCP structure. If `expected_value` is
/// Some, also checks that the value matches.
pub fn fcp_find_tag(data: &[u8], tag: u8, expected_value: Option<&[u8]>) -> bool {
    if data.len() < 2 || data[0] != 0x62 {
        return false;
    }
    let (inner_len, offset) = tlv_read_length(data, 1);
    let end = (offset + inner_len).min(data.len());
    let inner = &data[offset..end];
    let mut pos = 0;
    while pos < inner.len() {
        let t = inner[pos];
        pos += 1;
        if pos >= inner.len() {
            break;
        }
        let (len, new_pos) = tlv_read_length(inner, pos);
        pos = new_pos;
        let val_end = (pos + len).min(inner.len());
        if t == tag {
            if let Some(expected) = expected_value {
                if &inner[pos..val_end] == expected {
                    return true;
                }
            } else {
                return true;
            }
        }
        pos = val_end;
    }
    false
}

/// Check if `needle` is a contiguous subsequence of `haystack`.
pub fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
