//! `GlobalPlatform` OPEN runtime and Issuer Security Domain (ISD) per
//! [GP Card Specification v2.1.1](../../../../telecom-standards/globalplatform/GPC_CardSpecification_v2.1.1.pdf)
//! Chapters 5-9.
//!
//! The GP OPEN is the card manager that dispatches APDUs to on-card applets.
//! It maintains the applet registry, manages logical channels, enforces
//! lifecycle state transitions, and handles the GP secure channel protocol.
//!
//! # Architecture
//!
//! ```text
//! Terminal --> T=0 --> GpOpen::handle()
//!                       |
//!                       +-- GP management commands (CLA 0x80/0x84)
//!                       |     SELECT, GET STATUS, SET STATUS, MANAGE CHANNEL,
//!                       |     INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, ...
//!                       |
//!                       +-- Applet dispatch (CLA per applet)
//!                             AID-based SELECT -> Applet::select()
//!                             All other -> Applet::process()
//! ```
//!
//! # `no_std`
//! This crate is fully `no_std`. No heap allocation.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod channel;
pub mod commands;
pub mod lifecycle;
pub mod registry;
pub mod snapshot;

// Re-exports for convenience.
pub use channel::ChannelState;
pub use commands::{
    INS_DELETE, INS_EXTERNAL_AUTHENTICATE, INS_GET_DATA, INS_GET_STATUS, INS_INITIALIZE_UPDATE,
    INS_INSTALL, INS_LOAD, INS_MANAGE_CHANNEL, INS_PUT_KEY, INS_SET_STATUS, INS_STORE_DATA,
};
pub use lifecycle::{AppletLifecycle, CardLifecycle};
pub use registry::{AppletEntry, LoadFileEntry, SecurityDomain};
pub use simrs_gp_scp::ScpState;

use simrs_gp_keys::KeyStore;
use simrs_gp_scp::{
    ScpError, ScpVersion, process_external_authenticate, process_initialize_update, unwrap_command,
};
use simrs_iso7816::{Command, StatusWord, ins, write_data_sw, write_sw};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// CLA for GP proprietary commands (no secure messaging).
const CLA_GP: u8 = 0x80;
/// CLA for GP proprietary commands (secure messaging / C-MAC).
const CLA_GP_SM: u8 = 0x84;

/// Default ISD AID per GP 2.1.1: A0 00 00 01 51 00 00.
const DEFAULT_ISD_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

/// Default ISD AID per GP 2.3.1: A0 00 00 01 51 00 00 00.
const DEFAULT_ISD_AID_GP23: [u8; 8] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

/// Fixed maximum load files (no const generic -- keeps API stable).
const MAX_LOAD_FILES: usize = 8;

/// Key diversification data (10 bytes) returned during INITIALIZE UPDATE.
/// For now, static zeroes. Real implementations derive this from card data.
const KEY_DIVERSIFICATION: [u8; 10] = [0x00; 10];

/// Applet dispatch callback type.
///
/// Receives `(registry_index, cmd_apdu_bytes, response_buffer)` and returns
/// the number of response bytes written (including SW1 SW2).
pub type AppletDispatchFn<'a> = dyn FnMut(u8, &[u8], &mut [u8]) -> usize + 'a;

// ---------------------------------------------------------------------------
// GpOpen
// ---------------------------------------------------------------------------

/// The `GlobalPlatform` OPEN runtime and Issuer Security Domain (ISD).
///
/// Generic parameters:
/// - `MAX_APPLETS`: maximum number of registered applets.
/// - `MAX_SDS`: maximum number of supplementary Security Domains.
pub struct GpOpen<const MAX_APPLETS: usize, const MAX_SDS: usize> {
    card_lifecycle: CardLifecycle,
    isd: SecurityDomain,
    sds: [Option<SecurityDomain>; MAX_SDS],
    registry: [Option<AppletEntry>; MAX_APPLETS],
    load_files: [Option<registry::LoadFileEntry>; MAX_LOAD_FILES],
    channels: [ChannelState; 4],
    scp_state: ScpState,
    key_store: KeyStore<4>,
    sequence_counter: u16,
    default_selected: Option<u8>,
    iin: [u8; 16],
    iin_len: u8,
    /// JCVM bytecode interpreter for loaded Java Card applets (boxed to
    /// avoid stack overflow -- `JcVM<4096,4>` is ~50 KB).
    jcvm: alloc::boxed::Box<simrs_jcvm::JcVM<4096, 4>>,
    /// Buffer for accumulating LOAD command data blocks.
    load_buffer: [u8; 4096],
    /// Current fill level of the load buffer.
    load_buffer_len: usize,
}

impl<const MAX_APPLETS: usize, const MAX_SDS: usize> GpOpen<MAX_APPLETS, MAX_SDS> {
    /// Create a new GP OPEN runtime with the default ISD AID.
    ///
    /// The card starts in `OpReady` lifecycle. The ISD is always present
    /// and is the default selected applet on channel 0. The key store
    /// is initialized with the provided key set at version 0x01.
    pub fn new(keys: &simrs_gp_keys::KeySet) -> Self {
        let mut key_store = KeyStore::new();
        // Ignore store-full error: capacity is 4, we're adding 1.
        let _ = key_store.put(0x01, keys);

        Self {
            card_lifecycle: CardLifecycle::OpReady,
            isd: SecurityDomain::new(&DEFAULT_ISD_AID, AppletLifecycle::Selectable, 0x1E),
            sds: [const { None }; MAX_SDS],
            registry: [const { None }; MAX_APPLETS],
            load_files: [const { None }; MAX_LOAD_FILES],
            channels: [
                ChannelState::open_default(), // basic channel always open
                ChannelState::Closed,
                ChannelState::Closed,
                ChannelState::Closed,
            ],
            scp_state: ScpState::NoSession,
            key_store,
            sequence_counter: 0,
            default_selected: None,
            iin: *b"ISD_IIN\0\0\0\0\0\0\0\0\0",
            iin_len: 7,
            jcvm: alloc::boxed::Box::new(simrs_jcvm::JcVM::new()),
            load_buffer: [0u8; 4096],
            load_buffer_len: 0,
        }
    }

    /// Create with a custom ISD AID.
    pub fn with_isd_aid(isd_aid: &[u8], keys: &simrs_gp_keys::KeySet) -> Self {
        let mut gp = Self::new(keys);
        gp.isd = SecurityDomain::new(isd_aid, AppletLifecycle::Selectable, 0x1E);
        gp
    }

    /// Create with the GP 2.3.1 default 8-byte ISD AID.
    pub fn new_gp23(keys: &simrs_gp_keys::KeySet) -> Self {
        Self::with_isd_aid(&DEFAULT_ISD_AID_GP23, keys)
    }

    /// Current card lifecycle state.
    pub const fn card_lifecycle(&self) -> CardLifecycle {
        self.card_lifecycle
    }

    /// Configured Issuer Identification Number (IIN), if any.
    pub fn iin(&self) -> Option<&[u8]> {
        if self.iin_len > 0 {
            Some(&self.iin[..self.iin_len as usize])
        } else {
            None
        }
    }

    /// Reference to the embedded JCVM.
    pub fn jcvm(&self) -> &simrs_jcvm::JcVM<4096, 4> {
        &self.jcvm
    }

    /// Mutable reference to the embedded JCVM.
    pub fn jcvm_mut(&mut self) -> &mut simrs_jcvm::JcVM<4096, 4> {
        &mut self.jcvm
    }

    /// Reference to the ISD.
    pub const fn isd(&self) -> &SecurityDomain {
        &self.isd
    }

    /// Reference to the applet registry.
    pub const fn registry(&self) -> &[Option<AppletEntry>; MAX_APPLETS] {
        &self.registry
    }

    /// Mutable reference to the applet registry.
    pub const fn registry_mut(&mut self) -> &mut [Option<AppletEntry>; MAX_APPLETS] {
        &mut self.registry
    }

    /// Reference to supplementary Security Domains.
    pub const fn sds(&self) -> &[Option<SecurityDomain>; MAX_SDS] {
        &self.sds
    }

    /// Mutable reference to supplementary Security Domains.
    pub const fn sds_mut(&mut self) -> &mut [Option<SecurityDomain>; MAX_SDS] {
        &mut self.sds
    }

    /// Reference to load file entries.
    pub const fn load_files(&self) -> &[Option<registry::LoadFileEntry>; MAX_LOAD_FILES] {
        &self.load_files
    }

    /// Mutable reference to load file entries.
    pub const fn load_files_mut(
        &mut self,
    ) -> &mut [Option<registry::LoadFileEntry>; MAX_LOAD_FILES] {
        &mut self.load_files
    }

    /// Reference to the channel states.
    pub const fn channels(&self) -> &[ChannelState; 4] {
        &self.channels
    }

    /// The SCP session state.
    pub const fn scp_state(&self) -> &ScpState {
        &self.scp_state
    }

    /// Reset the SCP session state to `NoSession`.
    ///
    /// Called on card reset (warm or cold) to invalidate any in-progress
    /// secure channel authentication per GP 2.1.1 clause 7.1.
    pub const fn reset_scp_state(&mut self) {
        self.scp_state = ScpState::NoSession;
    }

    /// Set the SCP state to `Authenticated` for testing.
    ///
    /// Bypasses the full SCP handshake. Only available in test builds.
    #[cfg(test)]
    pub const fn set_authenticated_for_test(&mut self) {
        self.scp_state = ScpState::Authenticated {
            session_enc: [0u8; 16],
            session_mac: [0u8; 16],
            session_rmac: [0u8; 16],
            session_dek: [0u8; 16],
            security_level: 0x00,
            icv: [0u8; 16],
            rmac_active: false,
            scp_version: ScpVersion::Scp02,
            enc_counter: 0,
        };
    }

    /// SCP02 sequence counter.
    pub const fn sequence_counter(&self) -> u16 {
        self.sequence_counter
    }

    /// Reset the SCP02 sequence counter to zero.
    ///
    /// Used to simulate card personalization or test setup where the
    /// counter needs to start from a known value.
    pub const fn reset_sequence_counter(&mut self) {
        self.sequence_counter = 0;
    }

    /// Add a key set to the key store at the given version.
    ///
    /// Used for test setup to add SCP01 keys at a different version.
    ///
    /// # Errors
    ///
    /// Returns [`simrs_gp_keys::KeyStoreError::StoreFull`] when all slots are occupied.
    pub fn add_key(
        &mut self,
        version: u8,
        keys: &simrs_gp_keys::KeySet,
    ) -> Result<(), simrs_gp_keys::KeyStoreError> {
        self.key_store.put(version, keys)
    }

    /// Set the SCP02 sequence counter to an arbitrary value.
    ///
    /// Used for testing counter boundary conditions (e.g. 0xFFFF wrap).
    pub const fn set_sequence_counter(&mut self, value: u16) {
        self.sequence_counter = value;
    }

    /// Handle an incoming APDU. Returns a slice of `buf` containing the
    /// response (data + SW1 SW2).
    ///
    /// This is the main entry point for APDU processing. It:
    /// 1. Parses the APDU header
    /// 2. Routes GP management commands (CLA 0x80/0x84)
    /// 3. Routes SELECT by AID to the applet registry
    /// 4. Returns the appropriate status word
    ///
    /// Non-GP, non-SELECT commands return 6D 00 (INS not supported) because
    /// no applet dispatch callback is provided. Use
    /// [`handle_with_dispatch`](Self::handle_with_dispatch) to forward
    /// commands to applet implementations.
    #[allow(clippy::cast_possible_truncation)]
    pub fn handle<'buf>(&mut self, cmd_bytes: &[u8], buf: &'buf mut [u8]) -> &'buf [u8] {
        self.handle_with_dispatch(cmd_bytes, buf, None)
    }

    /// Handle an incoming APDU with optional applet dispatch.
    ///
    /// When a non-GP, non-SELECT command arrives and an applet is selected
    /// on the current logical channel, the `dispatch` callback is invoked
    /// with `(registry_index, cmd_bytes, buf)` and must return the number
    /// of response bytes written to `buf` (including SW1 SW2).
    ///
    /// If no applet is selected or no dispatch callback is provided,
    /// returns 6D 00 (INS not supported).
    #[allow(clippy::cast_possible_truncation)]
    pub fn handle_with_dispatch<'buf>(
        &mut self,
        cmd_bytes: &[u8],
        buf: &'buf mut [u8],
        mut dispatch: Option<&mut AppletDispatchFn<'_>>,
    ) -> &'buf [u8] {
        // Parse APDU.
        let Ok(cmd) = Command::parse(cmd_bytes) else {
            return write_sw(buf, StatusWord::WrongLength);
        };

        let cla_raw = cmd.cla().raw();

        // GP management commands: CLA = 0x80 or 0x84.
        if cla_raw == CLA_GP || cla_raw == CLA_GP_SM {
            return self.handle_gp_command(cmd_bytes, &cmd, buf);
        }

        // Interindustry SELECT by name (P1=0x04): dispatch to registry.
        if cmd.cla().is_interindustry() && cmd.ins() == ins::SELECT && cmd.p1() == 0x04 {
            return self.handle_select_by_aid(&cmd, buf);
        }

        // Interindustry MANAGE CHANNEL (ISO 7816-4 clause 7.1.2).
        if cmd.cla().is_interindustry() && cmd.ins() == INS_MANAGE_CHANNEL {
            return self.handle_manage_channel(&cmd, buf);
        }

        // If the card is terminated, reject everything.
        if self.card_lifecycle == CardLifecycle::Terminated {
            return write_sw(buf, StatusWord::command_not_allowed(0x85));
        }

        // Attempt applet dispatch: if an applet is selected on this channel,
        // try JCVM dispatch first, then fall through to external callback.
        let channel = cmd.cla().channel();
        if let Some(applet_idx) = self.selected_applet_index(channel) {
            // Try JCVM dispatch first (bytecode applets).
            if let Some(n) = self.dispatch_to_jcvm(applet_idx, cmd_bytes, buf) {
                return &buf[..n];
            }
            // Fall through to external dispatch callback.
            if let Some(ref mut cb) = dispatch {
                let n = cb(applet_idx, cmd_bytes, buf);
                return &buf[..n];
            }
        }

        // No applet selected or no dispatch callback: the OPEN cannot
        // handle this command directly.
        write_sw(buf, StatusWord::InsNotSupported)
    }

    /// Get the registry index of the applet selected on the given channel.
    pub const fn selected_applet_index(&self, channel: u8) -> Option<u8> {
        if (channel as usize) < self.channels.len() {
            self.channels[channel as usize].selected_applet()
        } else {
            None
        }
    }

    // -- GP command routing --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_gp_command<'buf>(
        &mut self,
        raw: &[u8],
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        // INITIALIZE UPDATE and EXTERNAL AUTHENTICATE have their own SCP
        // handling and bypass C-MAC unwrapping.
        match cmd.ins() {
            INS_INITIALIZE_UPDATE => return self.handle_initialize_update(cmd, buf),
            INS_EXTERNAL_AUTHENTICATE => return self.handle_external_authenticate(cmd, buf),
            _ => {}
        }

        // GP 2.1.1 clause 9: reject unknown INS before checking auth state.
        // This ensures invalid INS returns 6D00 regardless of auth, matching
        // Oracle behavior and preventing INS enumeration via auth state.
        let known_ins = matches!(
            cmd.ins(),
            ins::SELECT
                | INS_GET_STATUS
                | INS_SET_STATUS
                | INS_GET_DATA
                | INS_MANAGE_CHANNEL
                | INS_INSTALL
                | INS_DELETE
                | INS_LOAD
                | INS_PUT_KEY
                | INS_STORE_DATA
        );
        if !known_ins {
            return write_sw(buf, StatusWord::InsNotSupported);
        }

        // GP 2.1.1 clause 8: commands that require an authenticated SCP session.
        // Exempt: SELECT, GET DATA, MANAGE CHANNEL -- these work without auth.
        let auth_exempt = matches!(cmd.ins(), ins::SELECT | INS_GET_DATA | INS_MANAGE_CHANNEL);
        if !auth_exempt && !matches!(self.scp_state, ScpState::Authenticated { .. }) {
            return write_sw(buf, StatusWord::command_not_allowed(0x85));
        }

        // C-MAC verification: when an authenticated C-MAC session is active,
        // commands requiring auth must include and pass C-MAC verification.
        // GP 2.1.1 clause 8.3.1.
        if !auth_exempt
            && let ScpState::Authenticated {
                security_level,
                scp_version,
                ..
            } = self.scp_state
            && security_level & 0x01 != 0
        {
            let mut uw_data = [0u8; 256];
            let uw_result = if scp_version == ScpVersion::Scp03 {
                self.scp03_unwrap(raw, &mut uw_data)
            } else {
                unwrap_command(&mut self.scp_state, raw, &mut uw_data)
            };
            match uw_result {
                Ok(data_len) => {
                    // Rebuild APDU without C-MAC for dispatch.
                    let mut uw_apdu = [0u8; 261];
                    uw_apdu[..4].copy_from_slice(&raw[..4]);
                    let uw_len = if data_len > 0 {
                        uw_apdu[4] = data_len as u8;
                        uw_apdu[5..5 + data_len].copy_from_slice(&uw_data[..data_len]);
                        5 + data_len
                    } else {
                        4
                    };
                    let Ok(uw_cmd) = Command::parse(&uw_apdu[..uw_len]) else {
                        return write_sw(buf, StatusWord::WrongLength);
                    };
                    return self.dispatch_gp(&uw_cmd, buf);
                }
                Err(ScpError::CmacMismatch) => {
                    return write_sw(buf, StatusWord::command_not_allowed(0x88));
                }
                Err(ScpError::SecureMessagingMissing) => {
                    return write_sw(buf, StatusWord::command_not_allowed(0x87));
                }
                Err(_) => {
                    return write_sw(buf, StatusWord::NoPreciseDiagnosis);
                }
            }
        }

        self.dispatch_gp(cmd, buf)
    }

    /// Inner dispatch for GP management commands (after auth and C-MAC checks).
    fn dispatch_gp<'buf>(&mut self, cmd: &Command<'_>, buf: &'buf mut [u8]) -> &'buf [u8] {
        match cmd.ins() {
            ins::SELECT => {
                if cmd.p1() == 0x04 {
                    self.handle_select_by_aid(cmd, buf)
                } else {
                    write_sw(buf, StatusWord::wrong_params(0x86))
                }
            }
            INS_GET_STATUS => commands::get_status(
                &self.isd,
                &self.registry,
                &self.sds,
                &self.load_files,
                cmd,
                buf,
            ),
            INS_SET_STATUS => {
                let n = commands::set_status(
                    &mut self.card_lifecycle,
                    &mut self.isd,
                    &mut self.registry,
                    &mut self.sds,
                    cmd,
                    buf,
                );
                &buf[..n]
            }
            INS_MANAGE_CHANNEL => self.handle_manage_channel(cmd, buf),
            INS_INSTALL => {
                let n = commands::install(
                    &mut self.card_lifecycle,
                    &mut self.registry,
                    &mut self.load_files,
                    &self.jcvm,
                    cmd,
                    buf,
                );
                &buf[..n]
            }
            INS_DELETE => {
                let n = commands::delete(
                    &mut self.registry,
                    &mut self.sds,
                    &mut self.load_files,
                    cmd,
                    buf,
                );
                &buf[..n]
            }
            INS_LOAD => {
                let n = commands::load(
                    &mut self.jcvm,
                    &mut self.load_buffer,
                    &mut self.load_buffer_len,
                    cmd,
                    buf,
                );
                &buf[..n]
            }
            INS_GET_DATA => {
                commands::get_data(self.card_lifecycle, self.isd.aid(), self.iin(), cmd, buf)
            }
            INS_PUT_KEY => {
                let n = commands::put_key_stub(buf);
                &buf[..n]
            }
            INS_STORE_DATA => {
                let n = commands::store_data_stub(buf);
                &buf[..n]
            }
            _ => write_sw(buf, StatusWord::InsNotSupported),
        }
    }

    // -- JCVM dispatch --

    /// Try to dispatch an APDU to the JCVM for a bytecode applet.
    ///
    /// Returns `Some(response_len)` if the applet is a JCVM applet and
    /// execution completed, `None` if the applet is not a JCVM applet.
    #[allow(clippy::cast_possible_truncation)]
    fn dispatch_to_jcvm(
        &mut self,
        applet_idx: u8,
        _cmd_bytes: &[u8],
        buf: &mut [u8],
    ) -> Option<usize> {
        let entry = self.registry[applet_idx as usize].as_ref()?;
        let pkg_idx = entry.jcvm_pkg_idx()?;
        let method = entry.jcvm_process_method();

        let result = self.jcvm.execute(pkg_idx, method);

        Some(match result {
            simrs_jcvm::opcodes::ExecResult::ReturnVoid => {
                buf[0] = 0x90;
                buf[1] = 0x00;
                2
            }
            simrs_jcvm::opcodes::ExecResult::ReturnShort(val) => {
                let bytes = val.to_be_bytes();
                buf[0] = bytes[0];
                buf[1] = bytes[1];
                buf[2] = 0x90;
                buf[3] = 0x00;
                4
            }
            _ => {
                buf[0] = 0x6F;
                buf[1] = 0x00;
                2
            }
        })
    }

    // -- SELECT by AID --

    #[allow(clippy::cast_possible_truncation)]
    fn handle_select_by_aid<'buf>(&mut self, cmd: &Command<'_>, buf: &'buf mut [u8]) -> &'buf [u8] {
        let aid = cmd.data();
        if aid.is_empty() {
            return write_sw(buf, StatusWord::WrongLength);
        }

        let channel = cmd.cla().channel();
        let p2 = cmd.p2();

        // P2=0x02: next occurrence -- find next match after currently selected.
        if p2 == 0x02 {
            let start = self
                .selected_applet_index(channel)
                .map_or(0, |i| i as usize);
            if let Some(idx) = registry::find_by_aid_after(&self.registry, aid, start) {
                self.select_on_channel(channel, idx as u8);
                let entry = self.registry[idx].as_ref();
                let selected_aid = entry.map_or(aid, registry::AppletEntry::aid);
                let lc = entry.map_or(0x00, |e| e.lifecycle().to_byte());
                return Self::select_response(buf, selected_aid, lc, self.card_lifecycle);
            }
            return write_sw(buf, StatusWord::wrong_params(0x82));
        }

        // P2=0x00: first or only occurrence.
        // Check if selecting the ISD itself (exact or partial match).
        if registry::aid_exact_match(self.isd.aid(), aid)
            || registry::partial_aid_matches(self.isd.aid(), aid)
        {
            self.deselect_channel(channel);
            return Self::select_response(
                buf,
                self.isd.aid(),
                self.isd.lifecycle().to_byte(),
                self.card_lifecycle,
            );
        }

        // Search registry for matching AID (exact, prefix, or partial).
        if let Some(idx) = registry::find_by_aid(&self.registry, aid) {
            self.select_on_channel(channel, idx as u8);
            let entry = self.registry[idx].as_ref();
            let selected_aid = entry.map_or(aid, registry::AppletEntry::aid);
            let lc = entry.map_or(0x00, |e| e.lifecycle().to_byte());
            return Self::select_response(buf, selected_aid, lc, self.card_lifecycle);
        }

        // Not found.
        write_sw(buf, StatusWord::wrong_params(0x82))
    }

    const fn select_on_channel(&mut self, channel: u8, idx: u8) {
        if (channel as usize) < self.channels.len() {
            self.channels[channel as usize].select_applet(idx);
        }
    }

    const fn deselect_channel(&mut self, channel: u8) {
        if (channel as usize) < self.channels.len() {
            self.channels[channel as usize].deselect();
        }
    }

    /// Build FCI response for SELECT per GP 2.1.1 clause 9.9.3.1 Table 9-13:
    /// `6F { 84 { AID } A5 { 73 { OIDs } 9F65 { lifecycle } } }`.
    ///
    /// The A5 template includes card recognition data (tag 73) containing
    /// GP OIDs and protocol identifiers, matching Oracle Java Card behavior.
    #[allow(clippy::cast_possible_truncation)]
    fn select_response<'buf>(
        buf: &'buf mut [u8],
        aid: &[u8],
        lifecycle: u8,
        card_lifecycle: CardLifecycle,
    ) -> &'buf [u8] {
        let tag73_inner = commands::build_card_recognition_oids(card_lifecycle);
        let tag73_block = 2 + tag73_inner.len(); // tag 73(1) + len(1) + inner(49) = 51
        let lifecycle_tlv = 4usize; // tag 9F65(2) + len(1) + lifecycle(1)
        let a5_inner = tag73_block + lifecycle_tlv;
        let a5_block = 2 + a5_inner; // tag A5(1) + len(1) + inner
        let inner_len = 2 + aid.len() + a5_block; // tag 84(1) + len(1) + aid + A5 block
        let fci_len = 2 + inner_len; // tag 6F(1) + len(1) + inner
        let mut fci = [0u8; 80];
        let mut off = 0;
        fci[off] = 0x6F;
        fci[off + 1] = inner_len as u8;
        off += 2;
        fci[off] = 0x84;
        fci[off + 1] = aid.len() as u8;
        off += 2;
        fci[off..off + aid.len()].copy_from_slice(aid);
        off += aid.len();
        fci[off] = 0xA5;
        fci[off + 1] = a5_inner as u8;
        off += 2;
        fci[off] = 0x73;
        fci[off + 1] = tag73_inner.len() as u8;
        off += 2;
        fci[off..off + tag73_inner.len()].copy_from_slice(&tag73_inner);
        off += tag73_inner.len();
        fci[off] = 0x9F;
        fci[off + 1] = 0x65;
        fci[off + 2] = 0x01;
        fci[off + 3] = lifecycle;
        write_data_sw(buf, &fci[..fci_len], StatusWord::Success)
    }

    // -- MANAGE CHANNEL --

    fn handle_manage_channel<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        match channel::manage_channel(&mut self.channels, cmd.p1(), cmd.p2()) {
            Ok(ch_num) => {
                if cmd.p1() == channel::MANAGE_CHANNEL_OPEN {
                    // Return the assigned channel number.
                    write_data_sw(buf, &[ch_num], StatusWord::Success)
                } else {
                    write_sw(buf, StatusWord::Success)
                }
            }
            Err(sw) => write_sw(buf, sw),
        }
    }

    // -- SCP03 C-MAC unwrap helper --

    fn scp03_unwrap(&mut self, apdu: &[u8], output: &mut [u8]) -> Result<usize, ScpError> {
        if let ScpState::Authenticated {
            session_enc,
            session_mac,
            security_level,
            icv,
            enc_counter,
            scp_version: ScpVersion::Scp03,
            ..
        } = &mut self.scp_state
        {
            simrs_gp_scp::scp03::unwrap_command(
                session_enc,
                session_mac,
                *security_level,
                icv,
                enc_counter,
                apdu,
                output,
            )
        } else {
            Err(ScpError::InvalidState)
        }
    }

    // -- SCP: INITIALIZE UPDATE --

    fn handle_initialize_update<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let data = cmd.data();
        if data.len() < 8 {
            return write_sw(buf, StatusWord::WrongLength);
        }
        let mut host_challenge = [0u8; 8];
        host_challenge.copy_from_slice(&data[..8]);

        let key_version = cmd.p1();

        // Look up key set.
        let Some((keys, actual_version)) = self.key_store.get_or_default(key_version) else {
            return write_sw(buf, StatusWord::wrong_params(0x86));
        };

        // Select SCP version from the key set.
        let scp_version = match keys.scp_id() {
            simrs_gp_keys::ScpId::Scp01 => ScpVersion::Scp01,
            simrs_gp_keys::ScpId::Scp02 => ScpVersion::Scp02,
            simrs_gp_keys::ScpId::Scp03 => ScpVersion::Scp03,
        };

        // Generate card challenge. For deterministic testing, derive from
        // sequence counter. SCP02 places seq counter in first 2 bytes.
        let mut card_challenge = [0u8; 8];
        #[allow(clippy::cast_possible_truncation)]
        {
            card_challenge[6] = (self.sequence_counter >> 8) as u8;
            card_challenge[7] = self.sequence_counter as u8;
            if scp_version == ScpVersion::Scp02 {
                card_challenge[0] = (self.sequence_counter >> 8) as u8;
                card_challenge[1] = self.sequence_counter as u8;
            }
        }

        if scp_version == ScpVersion::Scp03 {
            let response = simrs_gp_scp::process_initialize_update_scp03(
                &mut self.scp_state,
                actual_version,
                &host_challenge,
                keys,
                &card_challenge,
                &KEY_DIVERSIFICATION,
            );
            return write_data_sw(buf, &response, StatusWord::Success);
        }

        let response = process_initialize_update(
            &mut self.scp_state,
            scp_version,
            actual_version,
            &host_challenge,
            keys,
            &card_challenge,
            &KEY_DIVERSIFICATION,
            Some(self.sequence_counter),
        );

        // GP 2.1.1 Appendix E: increment sequence counter after each
        // successful INITIALIZE UPDATE.
        self.sequence_counter = self.sequence_counter.wrapping_add(1);

        write_data_sw(buf, &response, StatusWord::Success)
    }

    // -- SCP: EXTERNAL AUTHENTICATE --

    fn handle_external_authenticate<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
    ) -> &'buf [u8] {
        let data = cmd.data();
        if data.len() < 16 {
            return write_sw(buf, StatusWord::WrongLength);
        }
        let mut host_crypto_and_mac = [0u8; 16];
        host_crypto_and_mac.copy_from_slice(&data[..16]);

        let security_level = cmd.p1();

        // Dispatch SCP03 or SCP01/02 based on InitUpdateDone state.
        let is_scp03 = matches!(
            self.scp_state,
            ScpState::InitUpdateDone {
                scp_version: ScpVersion::Scp03,
                ..
            }
        );

        let result = if is_scp03 {
            simrs_gp_scp::process_external_authenticate_scp03(
                &mut self.scp_state,
                security_level,
                &host_crypto_and_mac,
            )
        } else {
            process_external_authenticate(&mut self.scp_state, security_level, &host_crypto_and_mac)
        };

        // All EXTERNAL AUTHENTICATE failures return 69 88 regardless of
        // whether the host cryptogram, C-MAC, or both are wrong. This is a
        // deliberate countermeasure against the padding oracle attack
        // described by Avoine & Ferreira ("Rescuing Mutual Authentication",
        // TCHES 2018), which exploits distinguishable error responses to
        // recover session keys offline. GP 2.1.1 Table 9-9 permits both
        // 69 85 and 69 88; we use 69 88 uniformly to close the oracle.
        // Oracle jcsl returns 69 85 -- also spec-compliant, but
        // distinguishable across failure modes.
        match result {
            Ok(()) => write_sw(buf, StatusWord::Success),
            Err(simrs_gp_scp::ScpError::InvalidState) => {
                write_sw(buf, StatusWord::command_not_allowed(0x85))
            }
            Err(
                simrs_gp_scp::ScpError::HostCryptogramMismatch
                | simrs_gp_scp::ScpError::CmacMismatch,
            ) => write_sw(buf, StatusWord::command_not_allowed(0x88)),
            Err(_) => write_sw(buf, StatusWord::NoPreciseDiagnosis),
        }
    }

    // -- Snapshot --

    /// Snapshot size for this `GpOpen` configuration.
    pub const SNAPSHOT_SIZE: usize = snapshot::snapshot_size(MAX_APPLETS, MAX_SDS);

    /// Save the entire state to `buf`. Returns bytes written, or 0 if
    /// `buf` is too small.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        snapshot::save_state(
            self.card_lifecycle,
            &self.isd,
            &self.sds,
            &self.registry,
            &self.load_files,
            &self.channels,
            &self.scp_state,
            self.sequence_counter,
            self.default_selected,
            buf,
        )
    }

    /// Restore state from `buf`. Returns `true` on success.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        snapshot::restore_state(
            &mut self.card_lifecycle,
            &mut self.isd,
            &mut self.sds,
            &mut self.registry,
            &mut self.load_files,
            &mut self.channels,
            &mut self.scp_state,
            &mut self.sequence_counter,
            &mut self.default_selected,
            buf,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_gp_keys::KeySet;

    fn test_keys() -> KeySet {
        let k = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        KeySet::des3_2key(k, k, k)
    }

    fn make_gp() -> GpOpen<8, 2> {
        let mut gp = GpOpen::new(&test_keys());
        gp.set_authenticated_for_test();
        gp
    }

    /// Make a `GpOpen` instance without SCP authentication (for testing auth enforcement).
    #[allow(dead_code)]
    fn make_gp_unauthenticated() -> GpOpen<8, 2> {
        GpOpen::new(&test_keys())
    }

    // -- Basic construction --

    #[test]
    fn new_starts_op_ready() {
        let gp = make_gp();
        assert_eq!(gp.card_lifecycle(), CardLifecycle::OpReady);
    }

    #[test]
    fn isd_has_default_aid() {
        let gp = make_gp();
        assert_eq!(gp.isd().aid(), &DEFAULT_ISD_AID);
    }

    #[test]
    fn basic_channel_open_on_init() {
        let gp = make_gp();
        assert!(gp.channels()[0].is_open());
        assert!(!gp.channels()[1].is_open());
    }

    // -- SELECT by AID --

    #[test]
    fn select_isd_by_aid() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        // SELECT by AID: 00 A4 04 00 07 <ISD AID>
        let mut apdu = [0u8; 12];
        apdu[0] = 0x00; // CLA interindustry
        apdu[1] = 0xA4; // INS SELECT
        apdu[2] = 0x04; // P1 = select by name
        apdu[3] = 0x00; // P2
        apdu[4] = 0x07; // Lc = 7
        apdu[5..12].copy_from_slice(&DEFAULT_ISD_AID);

        let rsp = gp.handle(&apdu, &mut buf);
        // FCI + SW 90 00.
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        assert!(rsp.len() > 2, "SELECT should return FCI data");
    }

    #[test]
    fn select_registered_applet() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Register an applet via INSTALL.
        let app_aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        // INSTALL APDU: 80 E6 0C 00 Lc [load_aid_len=0] [module_aid_len=0] [app_aid_len=6] [app_aid]
        // APDU: CLA(1) INS(1) P1(1) P2(1) Lc(1) + data(9) = 14 bytes
        // Data: load_aid_len(1)=0 + module_aid_len(1)=0 + app_aid_len(1)=6 + aid(6) = 9
        let mut install_apdu = [0u8; 14];
        install_apdu[0] = CLA_GP;
        install_apdu[1] = INS_INSTALL;
        install_apdu[2] = 0x0C; // P1 = install for install & make selectable
        install_apdu[3] = 0x00;
        install_apdu[4] = 0x09; // Lc = 9
        install_apdu[5] = 0x00; // load file AID len = 0
        install_apdu[6] = 0x00; // module AID len = 0
        install_apdu[7] = 0x06; // app AID len = 6
        install_apdu[8..14].copy_from_slice(&app_aid);

        let rsp = gp.handle(&install_apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00], "INSTALL should succeed");

        // Now SELECT by AID.
        let mut select_apdu = [0u8; 11];
        select_apdu[0] = 0x00;
        select_apdu[1] = 0xA4;
        select_apdu[2] = 0x04;
        select_apdu[3] = 0x00;
        select_apdu[4] = 0x06;
        select_apdu[5..11].copy_from_slice(&app_aid);

        let rsp = gp.handle(&select_apdu, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "SELECT by AID should succeed"
        );

        // Verify the applet is selected on channel 0.
        assert!(gp.selected_applet_index(0).is_some());
    }

    #[test]
    fn select_unknown_aid_returns_not_found() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x6A, 0x82]); // file/app not found
    }

    // -- MANAGE CHANNEL --

    #[test]
    fn manage_channel_open_close() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Open channel: 80 70 00 00
        let open = [CLA_GP, INS_MANAGE_CHANNEL, 0x00, 0x00];
        let rsp = gp.handle(&open, &mut buf);
        // Response: channel number + 90 00
        assert_eq!(rsp.len(), 3);
        assert_eq!(rsp[0], 0x01); // channel 1
        assert_eq!(&rsp[1..], &[0x90, 0x00]);
        assert!(gp.channels()[1].is_open());

        // Close channel 1: 80 70 80 01
        let close = [CLA_GP, INS_MANAGE_CHANNEL, 0x80, 0x01];
        let rsp = gp.handle(&close, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);
        assert!(!gp.channels()[1].is_open());
    }

    #[test]
    fn manage_channel_close_basic_fails() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let close_basic = [CLA_GP, INS_MANAGE_CHANNEL, 0x80, 0x00];
        let rsp = gp.handle(&close_basic, &mut buf);
        // Should fail: can't close basic channel.
        assert_eq!(rsp[0], 0x69); // command not allowed
    }

    // -- GET STATUS --

    #[test]
    fn get_status_isd() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // GET STATUS P1=0x80 (ISD): 80 F2 80 00
        let apdu = [CLA_GP, INS_GET_STATUS, 0x80, 0x00];
        let rsp = gp.handle(&apdu, &mut buf);

        // Response: E3 TLV per GP 2.1.1 Table 9-7 + SW(2)
        // E3 { 4F { AID(7) } 9F70 01 { lifecycle } C5 01 { privileges } } + SW
        // = 2 + (2+7) + 4 + 3 + 2 = 20
        assert_eq!(rsp.len(), 20);
        assert_eq!(rsp[0], 0xE3); // E3 tag
        assert_eq!(rsp[2], 0x4F); // 4F tag (AID)
        assert_eq!(rsp[3], 7); // AID length
        assert_eq!(&rsp[4..11], &DEFAULT_ISD_AID);
        assert_eq!(
            &rsp[11..15],
            &[0x9F, 0x70, 0x01, AppletLifecycle::Selectable.to_byte()]
        );
        assert_eq!(&rsp[15..18], &[0xC5, 0x01, 0x9E]); // ISD privileges
        assert_eq!(&rsp[18..20], &[0x90, 0x00]); // SW
    }

    #[test]
    fn get_status_apps_empty() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // GET STATUS P1=0x40 (apps): 80 F2 40 00
        let apdu = [CLA_GP, INS_GET_STATUS, 0x40, 0x00];
        let rsp = gp.handle(&apdu, &mut buf);

        // No apps registered, should be just SW.
        assert_eq!(rsp, &[0x90, 0x00]);
    }

    // -- SET STATUS --

    #[test]
    fn set_status_card_lifecycle_transitions() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // OP_READY -> INITIALIZED
        let apdu = [
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Initialized.to_byte(),
        ];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);
        assert_eq!(gp.card_lifecycle(), CardLifecycle::Initialized);

        // INITIALIZED -> SECURED
        let apdu = [
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Secured.to_byte(),
        ];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);
        assert_eq!(gp.card_lifecycle(), CardLifecycle::Secured);
    }

    #[test]
    fn set_status_invalid_card_transition() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // OP_READY -> SECURED (skip INITIALIZED) should fail.
        let apdu = [
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Secured.to_byte(),
        ];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[0], 0x69); // command not allowed
        assert_eq!(gp.card_lifecycle(), CardLifecycle::OpReady);
    }

    // -- SCP delegation --

    #[test]
    fn initialize_update_returns_28_bytes() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // INITIALIZE UPDATE: 80 50 00 00 08 <host_challenge[8]>
        let mut apdu = [0u8; 13];
        apdu[0] = CLA_GP;
        apdu[1] = INS_INITIALIZE_UPDATE;
        apdu[2] = 0x00; // P1 = key version 0 (any)
        apdu[3] = 0x00;
        apdu[4] = 0x08; // Lc
        apdu[5..13].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let rsp = gp.handle(&apdu, &mut buf);
        // Response: 28 data bytes + SW(2) = 30
        assert_eq!(rsp.len(), 30);
        assert_eq!(&rsp[28..30], &[0x90, 0x00]);

        // Verify SCP state is now InitUpdateDone.
        assert!(matches!(gp.scp_state(), ScpState::InitUpdateDone { .. }));
    }

    #[test]
    fn external_authenticate_without_init_update_fails() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // EXTERNAL AUTHENTICATE without prior INITIALIZE UPDATE.
        let mut apdu = [0u8; 21];
        apdu[0] = CLA_GP_SM;
        apdu[1] = INS_EXTERNAL_AUTHENTICATE;
        apdu[2] = 0x00; // security level
        apdu[3] = 0x00;
        apdu[4] = 0x10; // Lc = 16
        // 16 bytes of data (host cryptogram + MAC)
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[0], 0x69); // command not allowed
    }

    // -- GET DATA --

    #[test]
    fn get_data_card_recognition() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // GET DATA tag 0066: 80 CA 00 66
        let apdu = [CLA_GP, INS_GET_DATA, 0x00, 0x66];
        let rsp = gp.handle(&apdu, &mut buf);
        // Should return card recognition data + SW.
        assert!(rsp.len() > 2);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        // First byte should be tag 0x66.
        assert_eq!(rsp[0], 0x66);
    }

    #[test]
    fn get_data_unknown_tag() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        let apdu = [CLA_GP, INS_GET_DATA, 0xFF, 0xFF];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x6A, 0x88]); // reference data not found
    }

    // -- DELETE --

    #[test]
    fn delete_registered_applet() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // First install an applet.
        let app_aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        let mut install_apdu = [0u8; 14];
        install_apdu[0] = CLA_GP;
        install_apdu[1] = INS_INSTALL;
        install_apdu[2] = 0x0C;
        install_apdu[3] = 0x00;
        install_apdu[4] = 9;
        install_apdu[5] = 0x00; // load AID len
        install_apdu[6] = 0x00; // module AID len
        install_apdu[7] = 0x06; // app AID len
        install_apdu[8..14].copy_from_slice(&app_aid);

        let rsp = gp.handle(&install_apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);

        // Verify it's registered.
        assert!(registry::find_by_aid(&gp.registry, &app_aid).is_some());

        // DELETE: 80 E4 00 00 08 4F 06 <AID>
        let mut delete_apdu = [0u8; 13];
        delete_apdu[0] = CLA_GP;
        delete_apdu[1] = INS_DELETE;
        delete_apdu[2] = 0x00;
        delete_apdu[3] = 0x00;
        delete_apdu[4] = 0x08; // Lc
        delete_apdu[5] = 0x4F; // tag
        delete_apdu[6] = 0x06; // AID length
        delete_apdu[7..13].copy_from_slice(&app_aid);

        let rsp = gp.handle(&delete_apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);

        // Verify it's gone.
        assert!(registry::find_by_aid(&gp.registry, &app_aid).is_none());
    }

    // -- Snapshot --

    #[test]
    #[allow(clippy::large_stack_arrays)]
    fn snapshot_roundtrip() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Install an applet.
        let app_aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        let mut install_apdu = [0u8; 14];
        install_apdu[0] = CLA_GP;
        install_apdu[1] = INS_INSTALL;
        install_apdu[2] = 0x0C;
        install_apdu[3] = 0x00;
        install_apdu[4] = 9;
        install_apdu[5] = 0x00;
        install_apdu[6] = 0x00;
        install_apdu[7] = 0x06;
        install_apdu[8..14].copy_from_slice(&app_aid);
        gp.handle(&install_apdu, &mut buf);

        // Transition card lifecycle.
        let apdu = [
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Initialized.to_byte(),
        ];
        gp.handle(&apdu, &mut buf);

        // Save state.
        let mut snap_buf = [0u8; GpOpen::<8, 2>::SNAPSHOT_SIZE];
        let written = gp.save_state(&mut snap_buf);
        assert!(written > 0, "snapshot should write bytes");

        // Restore into a fresh instance.
        let mut gp2: GpOpen<8, 2> = GpOpen::new(&test_keys());
        assert!(gp2.restore_state(&snap_buf[..written]));

        // Verify restored state.
        assert_eq!(gp2.card_lifecycle(), CardLifecycle::Initialized);
        assert!(registry::find_by_aid(gp2.registry(), &app_aid).is_some());
    }

    #[test]
    fn snapshot_small_buffer_returns_zero() {
        let gp = make_gp();
        let mut small = [0u8; 2];
        assert_eq!(gp.save_state(&mut small), 0);
    }

    #[test]
    fn snapshot_invalid_data_returns_false() {
        let mut gp = make_gp();
        assert!(!gp.restore_state(&[]));
    }

    // -- Terminated card rejects commands --

    #[test]
    fn terminated_card_rejects_interindustry() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Terminate the card through lifecycle transitions.
        gp.card_lifecycle = CardLifecycle::Terminated;

        // Any interindustry command should be rejected.
        let apdu = [0x00, 0xB0, 0x00, 0x00]; // READ BINARY
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[0], 0x69); // command not allowed
    }

    // -- CLA routing --

    #[test]
    fn unknown_cla_returns_ins_not_supported() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        // CLA 0xA0 (GSM proprietary) -- not GP and not interindustry with SELECT by AID.
        let apdu = [0xA0, 0xA4, 0x00, 0x00];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x6D, 0x00]); // INS not supported
    }

    // -- Applet dispatch via handle_with_dispatch --

    /// Helper: install an applet and SELECT it on channel 0. Returns the
    /// registry index.
    fn install_and_select(gp: &mut GpOpen<8, 2>, aid: &[u8]) -> u8 {
        let mut buf = [0u8; 256];

        // INSTALL for install & make selectable.
        let aid_len = aid.len();
        let lc = 3 + aid_len; // load(0) + module(0) + aid_len(1) + aid
        let mut install_apdu = [0u8; 32];
        install_apdu[0] = CLA_GP;
        install_apdu[1] = INS_INSTALL;
        install_apdu[2] = 0x0C;
        install_apdu[3] = 0x00;
        #[allow(clippy::cast_possible_truncation)]
        {
            install_apdu[4] = lc as u8;
        }
        install_apdu[5] = 0x00; // load AID len
        install_apdu[6] = 0x00; // module AID len
        #[allow(clippy::cast_possible_truncation)]
        {
            install_apdu[7] = aid_len as u8;
        }
        install_apdu[8..8 + aid_len].copy_from_slice(aid);

        let rsp = gp.handle(&install_apdu[..5 + lc], &mut buf);
        assert_eq!(rsp, &[0x90, 0x00], "INSTALL should succeed");

        // SELECT by AID on channel 0.
        let mut select_apdu = [0u8; 32];
        select_apdu[0] = 0x00; // CLA interindustry, channel 0
        select_apdu[1] = 0xA4; // INS SELECT
        select_apdu[2] = 0x04; // P1 = by name
        select_apdu[3] = 0x00;
        #[allow(clippy::cast_possible_truncation)]
        {
            select_apdu[4] = aid_len as u8;
        }
        select_apdu[5..5 + aid_len].copy_from_slice(aid);

        let rsp = gp.handle(&select_apdu[..5 + aid_len], &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "SELECT should succeed"
        );

        gp.selected_applet_index(0)
            .expect("applet should be selected after SELECT")
    }

    #[test]
    fn dispatch_forwards_unknown_command_to_applet() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        let expected_idx = install_and_select(&mut gp, &aid);

        // Send a non-GP, non-SELECT interindustry command (READ BINARY).
        let apdu = [0x00, 0xB0, 0x00, 0x00];
        let mut called = false;
        let mut seen_idx = 0u8;

        let rsp = gp.handle_with_dispatch(
            &apdu,
            &mut buf,
            Some(&mut |idx, _cmd, out| {
                called = true;
                seen_idx = idx;
                // Write a fake response: 01 02 90 00
                out[0] = 0x01;
                out[1] = 0x02;
                out[2] = 0x90;
                out[3] = 0x00;
                4
            }),
        );

        assert!(called, "dispatch callback must be invoked");
        assert_eq!(seen_idx, expected_idx);
        assert_eq!(rsp, &[0x01, 0x02, 0x90, 0x00]);
    }

    #[test]
    fn dispatch_not_called_when_no_applet_selected() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // No applet selected on channel 0 -- should return INS not supported
        // even when a dispatch callback is provided.
        let apdu = [0x00, 0xB0, 0x00, 0x00]; // READ BINARY
        let mut called = false;

        let rsp = gp.handle_with_dispatch(
            &apdu,
            &mut buf,
            Some(&mut |_idx, _cmd, _out| {
                called = true;
                0
            }),
        );

        assert!(
            !called,
            "dispatch must NOT be called when no applet is selected"
        );
        assert_eq!(rsp, &[0x6D, 0x00]); // INS not supported
    }

    #[test]
    fn dispatch_none_returns_ins_not_supported_when_applet_selected() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        install_and_select(&mut gp, &aid);

        // Applet is selected but no dispatch callback provided (None).
        let apdu = [0x00, 0xB0, 0x00, 0x00]; // READ BINARY
        let rsp = gp.handle_with_dispatch(&apdu, &mut buf, None);
        assert_eq!(rsp, &[0x6D, 0x00]); // INS not supported
    }

    #[test]
    fn gp_commands_handled_by_open_even_with_dispatch() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        install_and_select(&mut gp, &aid);

        let mut called = false;

        // GET STATUS (GP management command) should be handled by GpOpen
        // and NOT forwarded to the dispatch callback.
        let apdu = [CLA_GP, INS_GET_STATUS, 0x40, 0x00];
        let rsp = gp.handle_with_dispatch(
            &apdu,
            &mut buf,
            Some(&mut |_idx, _cmd, _out| {
                called = true;
                0
            }),
        );

        assert!(
            !called,
            "GP management commands must NOT be dispatched to applet"
        );
        // GET STATUS P1=0x40 should return the registered applet + SW.
        let sw = &rsp[rsp.len() - 2..];
        assert_eq!(sw, &[0x90, 0x00]);
    }

    #[test]
    fn select_by_aid_handled_by_open_even_with_dispatch() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        install_and_select(&mut gp, &aid);

        let mut called = false;

        // Interindustry SELECT by AID should be handled by GpOpen registry,
        // not dispatched to the applet callback.
        let mut select_apdu = [0u8; 12];
        select_apdu[0] = 0x00;
        select_apdu[1] = 0xA4;
        select_apdu[2] = 0x04;
        select_apdu[3] = 0x00;
        select_apdu[4] = 0x07;
        select_apdu[5..12].copy_from_slice(&DEFAULT_ISD_AID);

        let rsp = gp.handle_with_dispatch(
            &select_apdu,
            &mut buf,
            Some(&mut |_idx, _cmd, _out| {
                called = true;
                0
            }),
        );

        assert!(!called, "SELECT by AID must NOT be dispatched to applet");
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
    }

    #[test]
    fn dispatch_receives_full_apdu_bytes() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        install_and_select(&mut gp, &aid);

        // Send a command with data: 00 B2 01 04 05 <5 bytes data>
        let apdu = [0x00, 0xB2, 0x01, 0x04, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut received_cmd: [u8; 32] = [0; 32];
        let mut received_len = 0usize;

        let _rsp = gp.handle_with_dispatch(
            &apdu,
            &mut buf,
            Some(&mut |_idx, cmd, out| {
                received_len = cmd.len();
                received_cmd[..cmd.len()].copy_from_slice(cmd);
                out[0] = 0x90;
                out[1] = 0x00;
                2
            }),
        );

        assert_eq!(received_len, apdu.len());
        assert_eq!(&received_cmd[..received_len], &apdu);
    }

    #[test]
    fn terminated_card_rejects_even_with_dispatch() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        install_and_select(&mut gp, &aid);

        // Terminate the card.
        gp.card_lifecycle = CardLifecycle::Terminated;

        let mut called = false;
        let apdu = [0x00, 0xB0, 0x00, 0x00];
        let rsp = gp.handle_with_dispatch(
            &apdu,
            &mut buf,
            Some(&mut |_idx, _cmd, _out| {
                called = true;
                0
            }),
        );

        assert!(!called, "terminated card must NOT dispatch to applet");
        assert_eq!(rsp[0], 0x69); // command not allowed
    }

    #[test]
    fn handle_delegates_to_handle_with_dispatch_none() {
        // Verify that handle() still returns INS not supported for unknown
        // interindustry commands when an applet is selected (backwards compat).
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        install_and_select(&mut gp, &aid);

        let apdu = [0x00, 0xB0, 0x00, 0x00]; // READ BINARY
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x6D, 0x00]); // INS not supported (no dispatch)
    }

    // -- JCVM integration: LOAD -> INSTALL -> SELECT -> APDU --

    /// Build an INSTALL [for load] APDU.
    #[allow(clippy::cast_possible_truncation)]
    fn build_install_for_load(lf_aid: &[u8]) -> [u8; 32] {
        let isd_aid: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];
        let mut data = [0u8; 24];
        let mut dlen = 0;
        data[dlen] = lf_aid.len() as u8;
        dlen += 1;
        data[dlen..dlen + lf_aid.len()].copy_from_slice(lf_aid);
        dlen += lf_aid.len();
        data[dlen] = isd_aid.len() as u8;
        dlen += 1;
        data[dlen..dlen + isd_aid.len()].copy_from_slice(&isd_aid);
        dlen += isd_aid.len();
        data[dlen] = 0; // hash len
        dlen += 1;
        data[dlen] = 0; // params len
        dlen += 1;
        data[dlen] = 0; // token len
        dlen += 1;

        let mut apdu = [0u8; 32];
        apdu[0] = CLA_GP;
        apdu[1] = INS_INSTALL;
        apdu[2] = 0x02; // P1 = for load
        apdu[3] = 0x00;
        apdu[4] = dlen as u8;
        apdu[5..5 + dlen].copy_from_slice(&data[..dlen]);
        apdu
    }

    /// Build an INSTALL [for install and make selectable] APDU.
    #[allow(clippy::cast_possible_truncation)]
    fn build_install_for_ims(lf_aid: &[u8], mod_aid: &[u8], app_aid: &[u8]) -> [u8; 64] {
        let mut data = [0u8; 56];
        let mut dlen = 0;
        data[dlen] = lf_aid.len() as u8;
        dlen += 1;
        data[dlen..dlen + lf_aid.len()].copy_from_slice(lf_aid);
        dlen += lf_aid.len();
        data[dlen] = mod_aid.len() as u8;
        dlen += 1;
        data[dlen..dlen + mod_aid.len()].copy_from_slice(mod_aid);
        dlen += mod_aid.len();
        data[dlen] = app_aid.len() as u8;
        dlen += 1;
        data[dlen..dlen + app_aid.len()].copy_from_slice(app_aid);
        dlen += app_aid.len();
        data[dlen] = 0; // privileges len
        dlen += 1;
        data[dlen] = 0; // params len
        dlen += 1;
        data[dlen] = 0; // token len
        dlen += 1;

        let mut apdu = [0u8; 64];
        apdu[0] = CLA_GP;
        apdu[1] = INS_INSTALL;
        apdu[2] = 0x0C; // P1 = for install and make selectable
        apdu[3] = 0x00;
        apdu[4] = dlen as u8;
        apdu[5..5 + dlen].copy_from_slice(&data[..dlen]);
        apdu
    }

    #[test]
    #[allow(clippy::large_stack_arrays, clippy::cast_possible_truncation)]
    fn load_install_select_execute_jcvm_applet() {
        use simrs_jcasm::jcasm;

        let keys = test_keys();
        let mut gp = GpOpen::<16, 4>::new(&keys);
        gp.set_authenticated_for_test();

        // 1. Build a CAP blob with jcasm (returns 42).
        let (aid, methods) = jcasm! {
            applet A0_00_00_00_62_01_01 {
                fn process() {
                    bspush(42);
                    sreturn;
                }
            }
        };
        let mut cap_blob = [0u8; 256];
        let cap_len = simrs_jcvm::cap::build_cap_blob(aid, methods, &mut cap_blob);

        // 2. INSTALL [for load].
        let pkg_aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
        let install_load = build_install_for_load(&pkg_aid);
        let total_load = 5 + install_load[4] as usize;
        let mut buf = [0u8; 261];
        let rsp = gp.handle(&install_load[..total_load], &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "INSTALL [for load] should succeed"
        );

        // 3. LOAD (single block, P1=0x80 = last block).
        let mut load_apdu = [0u8; 261];
        load_apdu[0] = CLA_GP;
        load_apdu[1] = INS_LOAD;
        load_apdu[2] = 0x80; // P1: last block
        load_apdu[3] = 0x00;
        load_apdu[4] = cap_len as u8;
        load_apdu[5..5 + cap_len].copy_from_slice(&cap_blob[..cap_len]);
        let rsp = gp.handle(&load_apdu[..5 + cap_len], &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00], "LOAD should succeed");

        // 4. INSTALL [for install and make selectable].
        let instance_aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01, 0x01];
        let install_ims = build_install_for_ims(&pkg_aid, &pkg_aid, &instance_aid);
        let total_ims = 5 + install_ims[4] as usize;
        let rsp = gp.handle(&install_ims[..total_ims], &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "INSTALL [for install and make selectable] should succeed"
        );

        // 5. SELECT applet.
        let mut select = [0u8; 13];
        select[0] = 0x00;
        select[1] = 0xA4;
        select[2] = 0x04;
        select[3] = 0x00;
        select[4] = instance_aid.len() as u8;
        select[5..5 + instance_aid.len()].copy_from_slice(&instance_aid);
        let rsp = gp.handle(&select[..5 + instance_aid.len()], &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "SELECT should succeed"
        );

        // 6. Send APDU to applet -> should return 42.
        // CLA 0x00 = interindustry (NOT 0x80 which is GP management).
        let apdu = [0x00, 0x01, 0x00, 0x00];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "APDU dispatch should succeed"
        );
        assert_eq!(rsp.len(), 4, "expected 2 bytes data + 2 bytes SW");
        let value = i16::from_be_bytes([rsp[0], rsp[1]]);
        assert_eq!(value, 42, "JCVM applet should return 42");
    }
}
