//! `GlobalPlatform` OPEN runtime and Issuer Security Domain (ISD).
//!
//! Implementation derived from
//! [GP Card Specification v2.1.1](../../../../docs/specs/globalplatform/GPC_CardSpecification_v2.1.1.pdf)
//! Chapters 5-9 (the spec the inline clauses below were verified
//! against); the primary spec target is GP 2.3.1, which restructures
//! the same content into Chapters 5-11 -- see
//! [docs/standards/06-globalplatform.md](../../../../docs/standards/06-globalplatform.md).
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
use simrs_iso7816::{Command, StatusWord, ins, write_apdu_with_data, write_data_sw, write_sw};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// CLA for GP proprietary commands (no secure messaging).
const CLA_GP: u8 = 0x80;
/// CLA for GP proprietary commands (secure messaging / C-MAC).
const CLA_GP_SM: u8 = 0x84;

/// Default ISD AID per GP 2.3.1: `A0 00 00 01 51 00 00 00`.
///
/// This is the AID used by `GpOpen::new()` and matches the Oracle `jcsl`
/// reference simulator. Code or tests that specifically need the legacy
/// 7-byte form can use [`LEGACY_ISD_AID_GP21`] together with
/// [`GpOpen::new_legacy_gp21`].
pub const DEFAULT_ISD_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

/// Legacy ISD AID per GP 2.1.1 (JCOP10..JCOP31bio): `A0 00 00 01 51 00 00`.
///
/// Used by [`GpOpen::new_legacy_gp21`] and by test vectors / differential
/// cross-validation suites that target the legacy 7-byte AID. New code
/// targeting GP 2.3.1 should use [`DEFAULT_ISD_AID`].
pub const LEGACY_ISD_AID_GP21: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

/// Fixed maximum load files (no const generic -- keeps API stable).
const MAX_LOAD_FILES: usize = 8;

/// Default applet-registry capacity used by [`GpCard`] and most callers.
///
/// Sized for typical multi-applet workloads (USIM + ISD + a handful of
/// applications). Override with the `MAX_APPLETS` const generic on
/// [`GpOpen`] when more or fewer slots are needed.
///
/// [`GpCard`]: simrs_gp_card::GpCard
pub const DEFAULT_MAX_APPLETS: usize = 16;

/// Default supplementary-Security-Domain capacity used by [`GpCard`].
///
/// Override with the `MAX_SDS` const generic on [`GpOpen`] for cards
/// that host more SDs (e.g. multi-issuer schemes).
///
/// [`GpCard`]: simrs_gp_card::GpCard
pub const DEFAULT_MAX_SDS: usize = 4;

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
/// - `E`: on-card entropy source ([`simrs_card_api::EntropySource`]).
///   Production callers inject a hardware-backed implementation; tests
///   inject [`simrs_card_api::DeterministicRng`] with an explicit seed.
/// - `MAX_APPLETS`: maximum number of registered applets.
/// - `MAX_SDS`: maximum number of supplementary Security Domains.
pub struct GpOpen<E: simrs_card_api::EntropySource, const MAX_APPLETS: usize, const MAX_SDS: usize>
{
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
    /// Persistent state for in-flight STORE DATA chains (GP 2.3.1 § 11.11).
    store_data_state: commands::StoreDataState,
    /// Registry index of the personalization recipient set by INSTALL
    /// [for personalization]. The next completed STORE DATA chain is
    /// dispatched to this applet's `processData()`. Cleared after dispatch
    /// or by an SCP session reset.
    personalization_target: Option<u8>,
    /// SCP03 `i` parameter advertised in INITIALIZE UPDATE response.
    ///
    /// Default `0x00` matches existing behaviour (random card challenge,
    /// no R-MAC/R-ENC). Real cards typically advertise `0x70` (R-MAC +
    /// R-ENC + pseudo-random). See `set_scp03_i_param`.
    scp03_i_param: u8,
    /// Pseudo-random card-challenge counter (24-bit) for SCP03
    /// `i & 0x40 != 0`. Increments after each INITIALIZE UPDATE.
    scp03_pseudo_random_counter: u32,
    /// SCP02 `i` parameter reflected in GET DATA card recognition data
    /// (Table E-1 of GP 2.3.1 Appendix E). Default `0x15` (3 keys,
    /// ICV encryption, explicit challenge) matches the JCOP family.
    /// `0x05` advertises pseudo-random challenge mode but is not yet
    /// honoured in `card_challenge` derivation (Phase 1.5).
    scp02_i_param: u8,
    /// On-card entropy source used for SCP01/SCP02-explicit-mode and
    /// SCP03-random card-challenge generation (GP 2.3.1 § E.4.2.1,
    /// Amd D § 6.2.2). Generic so this is zero-overhead and `no_alloc`.
    rng: E,
}

impl<E: simrs_card_api::EntropySource, const MAX_APPLETS: usize, const MAX_SDS: usize>
    GpOpen<E, MAX_APPLETS, MAX_SDS>
{
    /// Create a new GP OPEN runtime with the default ISD AID.
    ///
    /// The card starts in `OpReady` lifecycle. The ISD is always present
    /// and is the default selected applet on channel 0. The key store
    /// is initialized with the provided key set at version 0x01.
    ///
    /// `rng` is the on-card entropy source used for SCP01 and
    /// SCP02-explicit-mode card-challenge generation (GP 2.3.1
    /// § E.4.2.1).
    pub fn new(keys: &simrs_gp_keys::KeySet, rng: E) -> Self {
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
            store_data_state: commands::StoreDataState::new(),
            personalization_target: None,
            scp03_i_param: 0x00,
            scp03_pseudo_random_counter: 0,
            scp02_i_param: 0x15,
            rng,
        }
    }

    /// Configure the SCP03 `i` parameter advertised in INITIALIZE UPDATE.
    ///
    /// Recognised bits per GP 2.3.1 Amendment D § 6.2:
    /// - `0x10`: R-MAC supported.
    /// - `0x20`: R-ENC supported.
    /// - `0x40`: pseudo-random card challenge mode (vs. random when clear).
    ///
    /// `JCOP3x` and most modern cards advertise `0x70`. Default is `0x00` for
    /// maximum backward compatibility with existing differential test
    /// fixtures.
    pub const fn set_scp03_i_param(&mut self, i_param: u8) {
        self.scp03_i_param = i_param;
    }

    /// Read the configured SCP03 `i` parameter.
    #[must_use]
    pub const fn scp03_i_param(&self) -> u8 {
        self.scp03_i_param
    }

    /// Configure the SCP02 `i` parameter advertised in GET DATA card
    /// recognition data (tag 0066, OID 1.2.840.114283.4.2).
    ///
    /// Recognised bits per GP 2.3.1 Appendix E Table E-1:
    /// - `0x01`: ICV encryption applied.
    /// - `0x04`: 3 secure-channel keys (vs. 1 base key derivation).
    /// - `0x10`: explicit challenge (vs. pseudo-random when clear).
    /// - `0x40`: R-MAC support.
    ///
    /// Default is `0x15` (3 keys, ICV encryption, explicit challenge),
    /// matching JCOP10..JCOP31bio behaviour.
    pub const fn set_scp02_i_param(&mut self, i_param: u8) {
        self.scp02_i_param = i_param;
    }

    /// Read the configured SCP02 `i` parameter.
    #[must_use]
    pub const fn scp02_i_param(&self) -> u8 {
        self.scp02_i_param
    }

    /// Create with a custom ISD AID.
    pub fn with_isd_aid(isd_aid: &[u8], keys: &simrs_gp_keys::KeySet, rng: E) -> Self {
        let mut gp = Self::new(keys, rng);
        gp.isd = SecurityDomain::new(isd_aid, AppletLifecycle::Selectable, 0x1E);
        gp
    }

    /// Create with the legacy GP 2.1.1 7-byte ISD AID.
    ///
    /// Use this only when reproducing JCOP10..JCOP31bio behaviour or
    /// when running differential cross-validation against test vectors
    /// that hard-code the 7-byte AID. New code should call
    /// [`Self::new`].
    pub fn new_legacy_gp21(keys: &simrs_gp_keys::KeySet, rng: E) -> Self {
        Self::with_isd_aid(&LEGACY_ISD_AID_GP21, keys, rng)
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

    /// Mutable access to the SCP session state for tests that need to
    /// inject canned values (e.g. forged R-MAC ICV, tampered keys).
    /// Not part of the public API surface.
    #[cfg(test)]
    pub const fn scp_state_mut_for_test(&mut self) -> &mut ScpState {
        &mut self.scp_state
    }

    /// Reset the SCP session state to `NoSession`.
    ///
    /// Called on card reset (warm or cold) to invalidate any in-progress
    /// secure channel authentication per GP 2.1.1 clause 7.1. Also
    /// discards any half-built STORE DATA chain or pending
    /// personalization target -- these are scoped to the SCP session.
    pub const fn reset_scp_state(&mut self) {
        self.scp_state = ScpState::NoSession;
        self.store_data_state.clear();
        self.personalization_target = None;
    }

    /// Set the SCP state to `Authenticated` for testing.
    ///
    /// Bypasses the full SCP handshake. Only available in test builds.
    /// All session keys default to zero -- callers exercising commands
    /// that depend on a non-trivial key (e.g. PUT KEY's DEK unwrap)
    /// should use [`set_authenticated_for_test_with_keys`](Self::set_authenticated_for_test_with_keys).
    #[cfg(test)]
    pub const fn set_authenticated_for_test(&mut self) {
        self.set_authenticated_for_test_with_keys(
            [0u8; 16],
            [0u8; 16],
            [0u8; 16],
            ScpVersion::Scp02,
        );
    }

    /// Set the SCP state to `Authenticated` with caller-supplied session
    /// keys. Used by tests that exercise crypto-dependent commands like
    /// PUT KEY where a non-trivial DEK is required.
    #[cfg(test)]
    pub const fn set_authenticated_for_test_with_keys(
        &mut self,
        session_enc: [u8; 16],
        command_mac: [u8; 16],
        session_dek: [u8; 16],
        scp_version: ScpVersion,
    ) {
        self.scp_state = ScpState::Authenticated {
            session_enc,
            command_mac,
            response_mac: [0u8; 16],
            session_dek,
            security_level: 0x00,
            icv: [0u8; 16],
            rmac_icv: [0u8; 8],
            rmac_active: false,
            scp_version,
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
    ///
    /// When the SCP session has R-MAC active (SCP01/02), the response is
    /// post-processed to insert the running R-MAC trailer between the
    /// response data and SW per GP 2.3.1 Appendix E.4.6.
    #[allow(clippy::cast_possible_truncation)]
    pub fn handle_with_dispatch<'buf>(
        &mut self,
        cmd_bytes: &[u8],
        buf: &'buf mut [u8],
        dispatch: Option<&mut AppletDispatchFn<'_>>,
    ) -> &'buf [u8] {
        // The R-MAC chain (GP 2.3.1 Appendix E.4.6.3) consumes the
        // post-secure-messaging command data field. For C-MAC'd commands
        // the wire-level data field includes the C-MAC trailer, so we
        // need the unwrapped form. `handle_gp_command` populates this
        // buffer when it does C-MAC unwrap; otherwise `maybe_wrap_rmac`
        // falls back to the wire data (correct for plain CLA=0x80
        // commands that have no trailer to strip).
        let mut unwrapped_cmd_data: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let inner_len = self.handle_inner(cmd_bytes, buf, dispatch, &mut unwrapped_cmd_data);
        let final_len = self.maybe_wrap_rmac(cmd_bytes, buf, inner_len, &unwrapped_cmd_data);
        &buf[..final_len]
    }

    /// Inner dispatcher that returns the response length written to `buf`.
    /// The outer `handle_with_dispatch` post-processes for R-MAC.
    ///
    /// `unwrapped_cmd_data` is filled with the post-secure-messaging
    /// command data field when secure messaging unwrap occurs (so the
    /// R-MAC wrap can use the spec-correct input). Left empty when the
    /// command had no C-MAC trailer to strip.
    #[allow(clippy::cast_possible_truncation)]
    fn handle_inner(
        &mut self,
        cmd_bytes: &[u8],
        buf: &mut [u8],
        mut dispatch: Option<&mut AppletDispatchFn<'_>>,
        unwrapped_cmd_data: &mut alloc::vec::Vec<u8>,
    ) -> usize {
        // Parse APDU.
        let Ok(cmd) = Command::parse(cmd_bytes) else {
            return write_sw(buf, StatusWord::WrongLength).len();
        };

        let cla_raw = cmd.cla().raw();

        // GP management commands: CLA = 0x80 or 0x84.
        if cla_raw == CLA_GP || cla_raw == CLA_GP_SM {
            return self
                .handle_gp_command(
                    cmd_bytes,
                    &cmd,
                    buf,
                    dispatch.as_deref_mut(),
                    unwrapped_cmd_data,
                )
                .len();
        }

        // Interindustry SELECT by name (P1=0x04): dispatch to registry.
        if cmd.cla().is_interindustry() && cmd.ins() == ins::SELECT && cmd.p1() == 0x04 {
            return self.handle_select_by_aid(&cmd, buf).len();
        }

        // Interindustry MANAGE CHANNEL (ISO 7816-4 clause 7.1.2).
        if cmd.cla().is_interindustry() && cmd.ins() == INS_MANAGE_CHANNEL {
            return self.handle_manage_channel(&cmd, buf).len();
        }

        // If the card is terminated, reject everything.
        if self.card_lifecycle == CardLifecycle::Terminated {
            return write_sw(buf, StatusWord::command_not_allowed(0x85)).len();
        }

        // Attempt applet dispatch: if an applet is selected on this channel,
        // try JCVM dispatch first, then fall through to external callback.
        let channel = cmd.cla().channel();
        if let Some(applet_idx) = self.selected_applet_index(channel) {
            // Try JCVM dispatch first (bytecode applets).
            if let Some(n) = self.dispatch_to_jcvm(applet_idx, cmd_bytes, buf) {
                return n;
            }
            // Fall through to external dispatch callback.
            if let Some(ref mut cb) = dispatch {
                return cb(applet_idx, cmd_bytes, buf);
            }
        }

        // No applet selected or no dispatch callback: the OPEN cannot
        // handle this command directly.
        write_sw(buf, StatusWord::InsNotSupported).len()
    }

    /// If R-MAC is active in the current SCP session, insert the R-MAC
    /// trailer between the response data and SW. Returns the new length.
    ///
    /// `buf[..inner_len]` holds `data... || SW1 SW2`. After wrapping,
    /// `buf[..inner_len + 8]` holds `data... || R-MAC[8] || SW1 SW2`.
    /// EXTERNAL AUTHENTICATE responses are exempt: it's the command that
    /// transitions to Authenticated, and the response cannot include a
    /// trailer the host hasn't yet validated.
    ///
    /// `unwrapped_cmd_data` carries the post-secure-messaging command
    /// data field when `handle_gp_command` performed C-MAC unwrap.
    /// When non-empty it is the R-MAC input per GP 2.3.1
    /// Appendix E.4.6.3; otherwise we fall back to
    /// `Command::parse(cmd_bytes).data()` which is the same bytes (no
    /// trailer to strip) for plain `CLA=0x80` commands.
    fn maybe_wrap_rmac(
        &mut self,
        cmd_bytes: &[u8],
        buf: &mut [u8],
        inner_len: usize,
        unwrapped_cmd_data: &[u8],
    ) -> usize {
        if inner_len < 2 {
            return inner_len;
        }
        // Skip commands whose responses do not carry an R-MAC trailer
        // by spec: SCP setup (INITIALIZE UPDATE / EXTERNAL AUTHENTICATE)
        // precedes the secure channel; BEGIN R-MAC SESSION's response
        // is the seeding act itself (Appendix E.6) and END R-MAC
        // SESSION returns the running chain value rather than wrapping
        // it.
        if cmd_bytes.len() >= 2 {
            let ins = cmd_bytes[1];
            if ins == INS_INITIALIZE_UPDATE
                || ins == INS_EXTERNAL_AUTHENTICATE
                || ins == commands::INS_BEGIN_RMAC_SESSION
                || ins == commands::INS_END_RMAC_SESSION
            {
                return inner_len;
            }
        }
        let data_len = inner_len - 2;
        let sw1 = buf[data_len];
        let sw2 = buf[data_len + 1];

        match self.scp_state {
            simrs_gp_scp::ScpState::Authenticated {
                rmac_active: true,
                scp_version: ScpVersion::Scp01 | ScpVersion::Scp02,
                ..
            } => self.wrap_rmac_scp01_02(cmd_bytes, buf, inner_len, unwrapped_cmd_data, sw1, sw2),
            simrs_gp_scp::ScpState::Authenticated {
                scp_version: ScpVersion::Scp03,
                security_level,
                response_mac,
                session_enc,
                icv,
                ..
            } if security_level & 0x10 != 0 => Self::wrap_rmac_scp03(
                buf,
                inner_len,
                sw1,
                sw2,
                security_level,
                &response_mac,
                &session_enc,
                &icv,
            ),
            _ => inner_len,
        }
    }

    /// SCP01/02 R-MAC wrap (GP 2.3.1 Appendix E.4.6.3). Updates the
    /// running R-MAC ICV in `self.scp_state`.
    fn wrap_rmac_scp01_02(
        &mut self,
        cmd_bytes: &[u8],
        buf: &mut [u8],
        inner_len: usize,
        unwrapped_cmd_data: &[u8],
        sw1: u8,
        sw2: u8,
    ) -> usize {
        // Need 8 bytes of headroom for the R-MAC trailer.
        if inner_len + 8 > buf.len() {
            return inner_len;
        }
        // R-MAC input = post-secure-messaging command data. Prefer the
        // unwrapped form (C-MAC'd commands); otherwise the parsed wire
        // data is already post-unwrap (plain `CLA=0x80` commands).
        let cmd_data: alloc::vec::Vec<u8> = if unwrapped_cmd_data.is_empty() {
            Command::parse(cmd_bytes)
                .map(|c| c.data().to_vec())
                .unwrap_or_default()
        } else {
            unwrapped_cmd_data.to_vec()
        };
        let data_len = inner_len - 2;
        let response_data: alloc::vec::Vec<u8> = buf[..data_len].to_vec();
        let mut output = [0u8; 270];
        let n = simrs_gp_scp::wrap_response(
            &mut self.scp_state,
            &cmd_data,
            &response_data,
            sw1,
            sw2,
            &mut output,
        );
        buf[..n].copy_from_slice(&output[..n]);
        n
    }

    /// SCP03 R-MAC + optional R-ENC wrap (GP 2.3.1 Amd D § 6.2.7).
    /// Reads from `response_mac`/`session_enc`/`icv`; does not advance
    /// any chaining state on the card side because SCP03 R-MAC chains
    /// on the host-shared MAC chaining value already maintained
    /// per-command.
    #[allow(clippy::too_many_arguments)]
    fn wrap_rmac_scp03(
        buf: &mut [u8],
        inner_len: usize,
        sw1: u8,
        sw2: u8,
        security_level: u8,
        response_mac: &[u8; 16],
        session_enc: &[u8; 16],
        icv: &[u8; 16],
    ) -> usize {
        // SCP03 R-ENC can grow the response (Method 2 padding pads up
        // to 16 bytes). Worst case: 256 + 15 (pad) + 8 (R-MAC) + 2 (SW)
        // = 281 bytes. Skip wrapping if the buffer can't hold that.
        let pad_overhead = if security_level & 0x20 != 0 { 15 } else { 0 };
        if inner_len + pad_overhead + 8 > buf.len() {
            return inner_len;
        }
        let data_len = inner_len - 2;
        let response_data: alloc::vec::Vec<u8> = buf[..data_len].to_vec();
        let mut output = [0u8; 290];
        let n = simrs_gp_scp::scp03_wrap_response(
            response_mac,
            session_enc,
            security_level,
            icv,
            &response_data,
            sw1,
            sw2,
            &mut output,
        );
        buf[..n].copy_from_slice(&output[..n]);
        n
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
        mut dispatch: Option<&mut AppletDispatchFn<'_>>,
        unwrapped_cmd_data: &mut alloc::vec::Vec<u8>,
    ) -> &'buf [u8] {
        // INITIALIZE UPDATE and EXTERNAL AUTHENTICATE have their own SCP
        // handling and bypass C-MAC unwrapping.
        match cmd.ins() {
            INS_INITIALIZE_UPDATE => return self.handle_initialize_update(cmd, buf),
            INS_EXTERNAL_AUTHENTICATE => return self.handle_external_authenticate(cmd, buf),
            _ => {}
        }

        // GP 2.3.1 clause 11 (legacy 2.1.1 clause 9): reject unknown INS
        // before checking auth state. This ensures invalid INS returns 6D00
        // regardless of auth, matching Oracle behavior and preventing INS
        // enumeration via auth state.
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
                | commands::INS_BEGIN_RMAC_SESSION
                | commands::INS_END_RMAC_SESSION
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
                    // Surface the post-unwrap data field for R-MAC chaining
                    // per GP 2.3.1 Appendix E.4.6.3.
                    unwrapped_cmd_data.extend_from_slice(uw_cmd.data());
                    return self.dispatch_gp(&uw_cmd, buf, dispatch.as_deref_mut());
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

        self.dispatch_gp(cmd, buf, dispatch)
    }

    /// Inner dispatch for GP management commands (after auth and C-MAC checks).
    #[allow(clippy::too_many_lines)]
    fn dispatch_gp<'buf>(
        &mut self,
        cmd: &Command<'_>,
        buf: &'buf mut [u8],
        dispatch: Option<&mut AppletDispatchFn<'_>>,
    ) -> &'buf [u8] {
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
                    &mut self.personalization_target,
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
            INS_GET_DATA => commands::get_data(
                self.card_lifecycle,
                self.isd.aid(),
                self.iin(),
                self.scp02_i_param,
                cmd,
                buf,
            ),
            INS_PUT_KEY => {
                let n = commands::put_key(&mut self.key_store, &self.scp_state, cmd, buf);
                &buf[..n]
            }
            INS_STORE_DATA => {
                let outcome = commands::store_data_block(&mut self.store_data_state, cmd);
                match outcome {
                    commands::StoreDataOutcome::Accepted => write_sw(buf, StatusWord::Success),
                    commands::StoreDataOutcome::Error(sw) => write_sw(buf, sw),
                    commands::StoreDataOutcome::Complete => {
                        // Copy the assembled payload out of `state` so it
                        // doesn't compete with `&mut self` borrows during
                        // dispatch.
                        let mut payload_buf = [0u8; commands::STORE_DATA_BUFFER_LEN];
                        let payload_len = self.store_data_state.fill_len();
                        payload_buf[..payload_len]
                            .copy_from_slice(self.store_data_state.assembled());
                        self.store_data_state.clear();
                        let n = self.dispatch_store_data_payload(
                            &payload_buf[..payload_len],
                            dispatch,
                            buf,
                        );
                        self.personalization_target = None;
                        &buf[..n]
                    }
                }
            }
            commands::INS_BEGIN_RMAC_SESSION => {
                let n = commands::begin_rmac_session(&mut self.scp_state, cmd, buf);
                &buf[..n]
            }
            commands::INS_END_RMAC_SESSION => {
                let n = commands::end_rmac_session(&mut self.scp_state, cmd, buf);
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
    fn dispatch_to_jcvm(
        &mut self,
        applet_idx: u8,
        _cmd_bytes: &[u8],
        buf: &mut [u8],
    ) -> Option<usize> {
        let entry = self.registry[applet_idx as usize].as_ref()?;
        let pkg_idx = entry.jcvm_pkg_idx()?;
        let method = entry.jcvm_process_method();
        Some(Self::write_jcvm_result(
            self.jcvm.execute(pkg_idx, method),
            buf,
        ))
    }

    // -- STORE DATA dispatch --

    /// Dispatch an assembled STORE DATA payload to the personalization
    /// recipient (GP 2.3.1 § 7.3, § 11.11).
    ///
    /// Resolution order:
    /// 1. No `personalization_target` set -- the data belongs to the SD
    ///    that owns the SCP session (the ISD here). Accept silently.
    /// 2. Target is a JCVM bytecode applet -- invoke its process method
    ///    (acting as `processData()` in this runtime). Note: the JCVM
    ///    dispatch model in this codebase does not surface APDU bytes
    ///    to the applet, so the assembled payload is observed by the
    ///    JCVM only via side-channels (e.g. shared memory). This is a
    ///    JCVM-runtime limitation, not a STORE DATA dispatch one.
    /// 3. Target is a non-JCVM applet and a dispatch callback is
    ///    provided -- synthesise a final-block STORE DATA APDU
    ///    `(CLA=0x80 INS=0xE2 P1=0x80 P2=0x00 Lc=N data...)` and pass
    ///    it to the callback with the target's registry index. The
    ///    callback's response SW becomes the STORE DATA response SW.
    /// 4. Target is non-JCVM and no callback is provided -- fall
    ///    through to SD-level acceptance.
    ///
    /// External-dispatch payloads are limited to 255 bytes (short APDU
    /// `Lc`); larger assembled payloads return `6A 84` ("not enough
    /// memory space"). Lifting that limit requires extended-length
    /// APDU support (Phase 4).
    ///
    /// Writes the response (recipient data + SW, or just SW for the
    /// silent SD-level acceptance path) into `buf` and returns the
    /// number of bytes written.
    fn dispatch_store_data_payload(
        &mut self,
        payload: &[u8],
        dispatch: Option<&mut AppletDispatchFn<'_>>,
        buf: &mut [u8],
    ) -> usize {
        let Some(idx) = self.personalization_target else {
            // No INSTALL [for personalization] preceded this chain:
            // GP 2.3.1 § 7.3 routes the data to the SD that owns the
            // SCP session (the ISD in our runtime). Accept silently.
            return write_sw(buf, StatusWord::Success).len();
        };
        let Some(entry) = self.registry[idx as usize].as_ref() else {
            return write_sw(buf, StatusWord::wrong_params(0x82)).len();
        };
        if let Some(pkg_idx) = entry.jcvm_pkg_idx() {
            let method = entry.jcvm_process_method();
            // Reuse the JCVM dispatch writer for consistent SW + return-data
            // formatting between the regular APDU path and STORE DATA.
            return Self::write_jcvm_result(self.jcvm.execute(pkg_idx, method), buf);
        }
        // Non-JCVM applet path.
        if let Some(cb) = dispatch {
            return Self::dispatch_store_data_external(idx, payload, cb, buf);
        }
        // Non-JCVM, no callback: fall through to SD-level acceptance.
        write_sw(buf, StatusWord::Success).len()
    }

    /// Format a JCVM `ExecResult` as an APDU response in `buf`. Returns
    /// bytes written. Shared by `dispatch_to_jcvm` and
    /// `dispatch_store_data_payload` so both paths produce identical
    /// response shapes.
    #[allow(clippy::cast_possible_truncation)]
    fn write_jcvm_result(result: simrs_jcvm::opcodes::ExecResult, buf: &mut [u8]) -> usize {
        match result {
            simrs_jcvm::opcodes::ExecResult::ReturnVoid => {
                let sw = StatusWord::Success.to_bytes();
                buf[0] = sw[0];
                buf[1] = sw[1];
                2
            }
            simrs_jcvm::opcodes::ExecResult::ReturnShort(val) => {
                let bytes = val.to_be_bytes();
                buf[0] = bytes[0];
                buf[1] = bytes[1];
                let sw = StatusWord::Success.to_bytes();
                buf[2] = sw[0];
                buf[3] = sw[1];
                4
            }
            _ => write_sw(buf, StatusWord::NoPreciseDiagnosis).len(),
        }
    }

    /// Build a synthetic last-block STORE DATA APDU around `payload` and
    /// hand it to the dispatch callback. Returns bytes written to `buf`
    /// (the recipient's response: data + SW). Returns `6A 84` if the
    /// payload exceeds the short-APDU limit.
    fn dispatch_store_data_external(
        applet_idx: u8,
        payload: &[u8],
        cb: &mut AppletDispatchFn<'_>,
        buf: &mut [u8],
    ) -> usize {
        if payload.len() > 255 {
            return write_sw(buf, StatusWord::wrong_params(0x84)).len();
        }
        let mut synth = [0u8; 261];
        let synth_apdu = write_apdu_with_data(
            &mut synth,
            CLA_GP,
            INS_STORE_DATA,
            0x80, // last block
            0x00,
            payload,
        );
        // Run the callback into a scratch buffer first, then copy to
        // `buf`. The callback's signature requires a `&mut [u8]` it can
        // own for the duration of the call; we can't lend it `buf`
        // because we need the synthetic APDU to outlive the call.
        let mut rsp = [0u8; 261];
        let n = cb(applet_idx, synth_apdu, &mut rsp);
        if n < 2 || n > buf.len() {
            return write_sw(buf, StatusWord::NoPreciseDiagnosis).len();
        }
        buf[..n].copy_from_slice(&rsp[..n]);
        n
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
                return Self::select_response(
                    buf,
                    selected_aid,
                    lc,
                    self.card_lifecycle,
                    self.scp02_i_param,
                );
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
                self.scp02_i_param,
            );
        }

        // Search registry for matching AID (exact, prefix, or partial).
        if let Some(idx) = registry::find_by_aid(&self.registry, aid) {
            self.select_on_channel(channel, idx as u8);
            let entry = self.registry[idx].as_ref();
            let selected_aid = entry.map_or(aid, registry::AppletEntry::aid);
            let lc = entry.map_or(0x00, |e| e.lifecycle().to_byte());
            return Self::select_response(
                buf,
                selected_aid,
                lc,
                self.card_lifecycle,
                self.scp02_i_param,
            );
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
        scp02_i_param: u8,
    ) -> &'buf [u8] {
        let tag73_inner = commands::build_card_recognition_oids(card_lifecycle, scp02_i_param);
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
            command_mac,
            security_level,
            icv,
            enc_counter,
            scp_version: ScpVersion::Scp03,
            ..
        } = &mut self.scp_state
        {
            simrs_gp_scp::scp03::unwrap_command(
                session_enc,
                command_mac,
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

        // Generate the 8-byte card_challenge buffer per GP 2.3.1
        // § E.4.2.1:
        //
        // - SCP02 pseudo-random mode (`scp02_i_param & 0x10 == 0`):
        //   derived from the sequence counter using the static S-ENC
        //   key per Appendix E.4.2.1.5; right-aligned in the buffer
        //   (bytes [2..8]). No RNG read.
        // - SCP02 explicit mode (default i=0x15): random 6-byte
        //   challenge in `card_challenge[2..8]`.
        // - SCP01: random 8-byte challenge filling the whole buffer.
        let mut card_challenge = [0u8; 8];
        if scp_version == ScpVersion::Scp02 && self.scp02_i_param & 0x10 == 0 {
            card_challenge = simrs_gp_scp::scp02_pseudo_random_card_challenge(
                keys.enc()
                    .try_into()
                    .expect("static_S-ENC must be 16 bytes"),
                self.sequence_counter,
            );
        } else if scp_version == ScpVersion::Scp02 {
            self.rng.fill_bytes(&mut card_challenge[2..8]);
        } else {
            self.rng.fill_bytes(&mut card_challenge);
        }

        if scp_version == ScpVersion::Scp03 {
            let (response, response_len) = simrs_gp_scp::process_initialize_update_scp03(
                &mut self.scp_state,
                actual_version,
                &host_challenge,
                keys,
                &card_challenge,
                &KEY_DIVERSIFICATION,
                self.scp03_i_param,
                self.scp03_pseudo_random_counter,
            );
            // GP 2.3.1 Amd D § 6.2.2: increment the pseudo-random challenge
            // counter when in pseudo-random mode so each session sees a fresh
            // card_challenge. In random mode the counter is unused.
            if self.scp03_i_param & 0x40 != 0 {
                self.scp03_pseudo_random_counter =
                    self.scp03_pseudo_random_counter.wrapping_add(1) & 0x00FF_FFFF;
            }
            return write_data_sw(buf, &response[..response_len], StatusWord::Success);
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
            self.personalization_target,
            buf,
        )
    }

    /// Restore state from `buf`. Returns `true` on success.
    ///
    /// Transient state not persisted by snapshots (in-flight STORE DATA
    /// chains, JCVM heap) is reset on restore so the runtime starts
    /// from a clean transient slate.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        let ok = snapshot::restore_state(
            &mut self.card_lifecycle,
            &mut self.isd,
            &mut self.sds,
            &mut self.registry,
            &mut self.load_files,
            &mut self.channels,
            &mut self.scp_state,
            &mut self.sequence_counter,
            &mut self.default_selected,
            &mut self.personalization_target,
            buf,
        );
        if ok {
            self.store_data_state.clear();
        }
        ok
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_card_api::DeterministicRng;
    use simrs_gp_keys::KeySet;

    /// Test-fixture capacity for the applet registry. Smaller than the
    /// production [`DEFAULT_MAX_APPLETS`] so tests exercise the
    /// "registry full" branches without over-allocating stack frames.
    const TEST_MAX_APPLETS: usize = 8;
    /// Test-fixture capacity for supplementary Security Domains.
    const TEST_MAX_SDS: usize = 2;
    /// Fixed seed for the test entropy source. Distinct from any
    /// production seed so a future test that asserts byte-equality
    /// against a recorded fixture is anchored to a known value.
    const TEST_RNG_SEED: u64 = 0xCAFE_BABE_DEAD_BEEF;

    /// Concrete `GpOpen` shape used by every test in this module.
    type TestGpOpen = GpOpen<DeterministicRng, TEST_MAX_APPLETS, TEST_MAX_SDS>;

    fn test_keys() -> KeySet {
        let k = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
            0x4E, 0x4F,
        ];
        KeySet::des3_2key(k, k, k)
    }

    fn make_gp() -> TestGpOpen {
        let mut gp = TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        gp.set_authenticated_for_test();
        gp
    }

    /// Make a `GpOpen` instance without SCP authentication (for testing auth enforcement).
    #[allow(dead_code)]
    fn make_gp_unauthenticated() -> TestGpOpen {
        TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED))
    }

    use simrs_iso7816::{apdu_header, apdu_with_data, apdu_with_response_len};

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
        // SELECT by AID: 00 A4 04 00 <Lc> <ISD AID>
        let apdu = apdu_with_data(0x00, 0xA4, 0x04, 0x00, &DEFAULT_ISD_AID);
        let rsp = gp.handle(&apdu, &mut buf);
        // FCI + SW 90 00.
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        assert!(rsp.len() > 2, "SELECT should return FCI data");
    }

    #[test]
    fn select_registered_applet() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Register an applet via INSTALL [for install & make selectable].
        // INSTALL data layout: load_aid_len(0) || module_aid_len(0)
        //                       || app_aid_len(6) || app_aid.
        let app_aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        let install_data = [
            0x00, 0x00, 0x06, app_aid[0], app_aid[1], app_aid[2], app_aid[3], app_aid[4],
            app_aid[5],
        ];
        let install_apdu = apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &install_data);
        let rsp = gp.handle(&install_apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00], "INSTALL should succeed");

        // SELECT by AID.
        let select_apdu = apdu_with_data(0x00, 0xA4, 0x04, 0x00, &app_aid);
        let rsp = gp.handle(&select_apdu, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "SELECT by AID should succeed"
        );

        assert!(gp.selected_applet_index(0).is_some());
    }

    #[test]
    fn select_unknown_aid_returns_not_found() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let apdu = apdu_with_data(0x00, 0xA4, 0x04, 0x00, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
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

        let apdu = apdu_header(CLA_GP, INS_GET_STATUS, 0x80, 0x00);
        let rsp = gp.handle(&apdu, &mut buf);

        // Response: E3 TLV per GP 2.1.1 Table 9-7 + SW(2)
        // E3 { 4F { AID(8) } 9F70 01 { lifecycle } C5 01 { privileges } } + SW
        // = 2 + (2+8) + 4 + 3 + 2 = 21
        assert_eq!(rsp.len(), 21);
        assert_eq!(rsp[0], 0xE3); // E3 tag
        assert_eq!(rsp[2], 0x4F); // 4F tag (AID)
        assert_eq!(rsp[3], 8); // AID length (GP 2.3.1 default)
        assert_eq!(&rsp[4..12], &DEFAULT_ISD_AID);
        assert_eq!(
            &rsp[12..16],
            &[0x9F, 0x70, 0x01, AppletLifecycle::Selectable.to_byte()]
        );
        assert_eq!(&rsp[16..19], &[0xC5, 0x01, 0x9E]); // ISD privileges
        assert_eq!(&rsp[19..21], &[0x90, 0x00]); // SW
    }

    #[test]
    fn get_status_apps_empty() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        let apdu = apdu_header(CLA_GP, INS_GET_STATUS, 0x40, 0x00);
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
        let apdu = apdu_header(
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Initialized.to_byte(),
        );
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);
        assert_eq!(gp.card_lifecycle(), CardLifecycle::Initialized);

        // INITIALIZED -> SECURED
        let apdu = apdu_header(
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Secured.to_byte(),
        );
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);
        assert_eq!(gp.card_lifecycle(), CardLifecycle::Secured);
    }

    #[test]
    fn set_status_invalid_card_transition() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // OP_READY -> SECURED (skip INITIALIZED) should fail.
        let apdu = apdu_header(
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Secured.to_byte(),
        );
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[0], 0x69); // command not allowed
        assert_eq!(gp.card_lifecycle(), CardLifecycle::OpReady);
    }

    // -- SCP delegation --

    #[test]
    fn initialize_update_returns_28_bytes() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // INITIALIZE UPDATE with key_version = 0 (any), 8-byte host challenge.
        let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let apdu = apdu_with_data(CLA_GP, INS_INITIALIZE_UPDATE, 0x00, 0x00, &host_challenge);
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

        // EXTERNAL AUTHENTICATE without prior INITIALIZE UPDATE: 16-byte
        // body of zeros (host_cryptogram[8] || C-MAC[8]).
        let apdu = apdu_with_data(CLA_GP_SM, INS_EXTERNAL_AUTHENTICATE, 0x00, 0x00, &[0u8; 16]);
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[0], 0x69); // command not allowed
    }

    // -- GET DATA --

    #[test]
    fn get_data_card_recognition() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        let apdu = apdu_header(CLA_GP, INS_GET_DATA, 0x00, 0x66);
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

        let apdu = apdu_header(CLA_GP, INS_GET_DATA, 0xFF, 0xFF);
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
        let install_data = [
            0x00, 0x00, 0x06, app_aid[0], app_aid[1], app_aid[2], app_aid[3], app_aid[4],
            app_aid[5],
        ];
        let install_apdu = apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &install_data);
        let rsp = gp.handle(&install_apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00]);

        // Verify it's registered.
        assert!(registry::find_by_aid(&gp.registry, &app_aid).is_some());

        // DELETE: data is `4F 06 <AID>` per GP 2.3.1 § 11.2.2.
        let delete_data = [
            0x4F, 0x06, app_aid[0], app_aid[1], app_aid[2], app_aid[3], app_aid[4], app_aid[5],
        ];
        let delete_apdu = apdu_with_data(CLA_GP, INS_DELETE, 0x00, 0x00, &delete_data);
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
        let install_data = [
            0x00, 0x00, 0x06, app_aid[0], app_aid[1], app_aid[2], app_aid[3], app_aid[4],
            app_aid[5],
        ];
        let install_apdu = apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &install_data);
        gp.handle(&install_apdu, &mut buf);

        // Transition card lifecycle.
        let apdu = apdu_header(
            CLA_GP,
            INS_SET_STATUS,
            0x80,
            CardLifecycle::Initialized.to_byte(),
        );
        gp.handle(&apdu, &mut buf);

        // Save state.
        let mut snap_buf = [0u8; TestGpOpen::SNAPSHOT_SIZE];
        let written = gp.save_state(&mut snap_buf);
        assert!(written > 0, "snapshot should write bytes");

        // Restore into a fresh instance.
        let mut gp2: TestGpOpen =
            TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
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
    fn snapshot_persists_personalization_target() {
        let mut gp = make_gp();
        // Forge a personalization target as if INSTALL [for personalization]
        // had recorded the applet at registry index 3.
        gp.personalization_target = Some(3);

        let mut snap_buf = [0u8; TestGpOpen::SNAPSHOT_SIZE];
        let written = gp.save_state(&mut snap_buf);
        assert!(written > 0);

        let mut gp2: TestGpOpen =
            TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        assert!(gp2.restore_state(&snap_buf[..written]));
        assert_eq!(gp2.personalization_target, Some(3));
    }

    #[test]
    fn snapshot_restore_clears_in_flight_store_data_chain() {
        // The STORE DATA accumulator is transient -- it must be cleared
        // on restore so a partial chain in the source doesn't leak into
        // the destination.
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Start a chain: send a non-last block.
        let block0 = apdu_with_data(0x84, INS_STORE_DATA, 0x00, 0x00, &[1, 2, 3]);
        gp.handle(&block0, &mut buf);
        assert!(gp.store_data_state.fill_len() > 0);

        let mut snap_buf = [0u8; TestGpOpen::SNAPSHOT_SIZE];
        let written = gp.save_state(&mut snap_buf);

        let mut gp2: TestGpOpen =
            TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        // Forge in-progress state in the destination too -- restore must
        // wipe it regardless of the source.
        let block_a = apdu_with_data(0x84, INS_STORE_DATA, 0x00, 0x00, &[7, 7, 7]);
        gp2.set_authenticated_for_test();
        gp2.handle(&block_a, &mut buf);
        assert!(gp2.store_data_state.fill_len() > 0);

        assert!(gp2.restore_state(&snap_buf[..written]));
        assert_eq!(gp2.store_data_state.fill_len(), 0);
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
        let apdu = apdu_header(0x00, 0xB0, 0x00, 0x00); // READ BINARY
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[0], 0x69); // command not allowed
    }

    // -- CLA routing --

    #[test]
    fn unknown_cla_returns_ins_not_supported() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        // CLA 0xA0 (GSM proprietary) -- not GP and not interindustry with SELECT by AID.
        let apdu = apdu_header(0xA0, 0xA4, 0x00, 0x00);
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x6D, 0x00]); // INS not supported
    }

    // -- Applet dispatch via handle_with_dispatch --

    /// Helper: install an applet and SELECT it on channel 0. Returns the
    /// registry index.
    fn install_and_select(gp: &mut TestGpOpen, aid: &[u8]) -> u8 {
        let mut buf = [0u8; 256];

        // INSTALL [for install & make selectable]: data layout is
        // load_aid_len(0) || module_aid_len(0) || app_aid_len || app_aid.
        let mut install_data = alloc::vec::Vec::with_capacity(3 + aid.len());
        install_data.push(0x00);
        install_data.push(0x00);
        #[allow(clippy::cast_possible_truncation)]
        install_data.push(aid.len() as u8);
        install_data.extend_from_slice(aid);
        let install_apdu = apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &install_data);
        let rsp = gp.handle(&install_apdu, &mut buf);
        assert_eq!(rsp, &[0x90, 0x00], "INSTALL should succeed");

        // SELECT by AID on channel 0.
        let select_apdu = apdu_with_data(0x00, 0xA4, 0x04, 0x00, aid);
        let rsp = gp.handle(&select_apdu, &mut buf);
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
        let apdu = apdu_header(0x00, 0xB0, 0x00, 0x00);
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
        let apdu = apdu_header(0x00, 0xB0, 0x00, 0x00); // READ BINARY
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
        let apdu = apdu_header(0x00, 0xB0, 0x00, 0x00); // READ BINARY
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
        let apdu = apdu_header(CLA_GP, INS_GET_STATUS, 0x40, 0x00);
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
        let select_apdu = apdu_with_data(0x00, 0xA4, 0x04, 0x00, &DEFAULT_ISD_AID);
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

        // READ RECORD with 5-byte body: 00 B2 01 04 05 11 22 33 44 55.
        let apdu = apdu_with_data(0x00, 0xB2, 0x01, 0x04, &[0x11, 0x22, 0x33, 0x44, 0x55]);
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
        let apdu = apdu_header(0x00, 0xB0, 0x00, 0x00);
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

        let apdu = apdu_header(0x00, 0xB0, 0x00, 0x00); // READ BINARY
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp, &[0x6D, 0x00]); // INS not supported (no dispatch)
    }

    // -- JCVM integration: LOAD -> INSTALL -> SELECT -> APDU --

    /// Build an INSTALL [for load] APDU per GP 2.3.1 § 11.5.2.3.4.
    ///
    /// Data layout: `load_file_aid_len || load_file_aid || sd_aid_len ||
    /// sd_aid || hash_len(0) || params_len(0) || token_len(0)`.
    fn build_install_for_load(lf_aid: &[u8]) -> alloc::vec::Vec<u8> {
        let isd_aid = DEFAULT_ISD_AID;
        let mut data = alloc::vec::Vec::with_capacity(lf_aid.len() + isd_aid.len() + 6);
        #[allow(clippy::cast_possible_truncation)]
        data.push(lf_aid.len() as u8);
        data.extend_from_slice(lf_aid);
        #[allow(clippy::cast_possible_truncation)]
        data.push(isd_aid.len() as u8);
        data.extend_from_slice(&isd_aid);
        data.extend_from_slice(&[0, 0, 0]); // hash, params, token (all empty)
        apdu_with_data(CLA_GP, INS_INSTALL, 0x02, 0x00, &data)
    }

    /// Build an INSTALL [for personalization] APDU per GP 2.3.1
    /// § 11.5.2.3.6. The load file and module AIDs are zero-length;
    /// the application AID identifies the personalization recipient.
    fn build_install_for_personalization(app_aid: &[u8]) -> alloc::vec::Vec<u8> {
        let mut data = alloc::vec::Vec::with_capacity(app_aid.len() + 6);
        data.push(0u8); // load_aid_len = 0
        data.push(0u8); // module_aid_len = 0
        #[allow(clippy::cast_possible_truncation)]
        data.push(app_aid.len() as u8);
        data.extend_from_slice(app_aid);
        data.extend_from_slice(&[0, 0, 0]); // privs, params, token (all empty)
        apdu_with_data(CLA_GP, INS_INSTALL, 0x20, 0x00, &data)
    }

    /// Build an INSTALL [for install and make selectable] APDU per
    /// GP 2.3.1 § 11.5.2.3.5.
    ///
    /// Data layout: `lf_aid_len || lf_aid || mod_aid_len || mod_aid ||
    /// app_aid_len || app_aid || privs_len(0) || params_len(0) ||
    /// token_len(0)`.
    fn build_install_for_ims(lf_aid: &[u8], mod_aid: &[u8], app_aid: &[u8]) -> alloc::vec::Vec<u8> {
        let mut data =
            alloc::vec::Vec::with_capacity(lf_aid.len() + mod_aid.len() + app_aid.len() + 6);
        #[allow(clippy::cast_possible_truncation)]
        data.push(lf_aid.len() as u8);
        data.extend_from_slice(lf_aid);
        #[allow(clippy::cast_possible_truncation)]
        data.push(mod_aid.len() as u8);
        data.extend_from_slice(mod_aid);
        #[allow(clippy::cast_possible_truncation)]
        data.push(app_aid.len() as u8);
        data.extend_from_slice(app_aid);
        data.extend_from_slice(&[0, 0, 0]); // privs, params, token (all empty)
        apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &data)
    }

    #[test]
    #[allow(clippy::large_stack_arrays, clippy::cast_possible_truncation)]
    fn load_install_select_execute_jcvm_applet() {
        use simrs_jcasm::jcasm;

        let keys = test_keys();
        let mut gp = GpOpen::<DeterministicRng, DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS>::new(
            &keys,
            DeterministicRng::new(TEST_RNG_SEED),
        );
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
        let mut buf = [0u8; 261];
        let rsp = gp.handle(&install_load, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "INSTALL [for load] should succeed"
        );

        // 3. LOAD (single block, P1=0x80 = last block).
        let load_apdu = apdu_with_data(CLA_GP, INS_LOAD, 0x80, 0x00, &cap_blob[..cap_len]);
        let rsp = gp.handle(&load_apdu, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00], "LOAD should succeed");

        // 4. INSTALL [for install and make selectable].
        let instance_aid = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01, 0x01];
        let install_ims = build_install_for_ims(&pkg_aid, &pkg_aid, &instance_aid);
        let rsp = gp.handle(&install_ims, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "INSTALL [for install and make selectable] should succeed"
        );

        // 5. SELECT applet.
        let select = apdu_with_data(0x00, 0xA4, 0x04, 0x00, &instance_aid);
        let rsp = gp.handle(&select, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "SELECT should succeed"
        );

        // 6. Send APDU to applet -> should return 42.
        // CLA 0x00 = interindustry (NOT 0x80 which is GP management).
        let apdu = apdu_header(0x00, 0x01, 0x00, 0x00);
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

    // -- Phase 1 GP 2.3.1 closeout: PUT KEY / STORE DATA / R-MAC / SCP --

    /// Build a complete PUT KEY data field for three 3DES 16-byte keys at the
    /// given KVN. Format per GP 2.3.1 § 11.8.2.3. Each block is 22 bytes
    /// (1 KTI + 1 KCL + 16 wrapped-key + 1 KCV-len + 3 KCV); plus 1 leading
    /// KVN byte = 67 bytes total.
    ///
    /// `wrap_dek` is the session DEK used to wrap each key component with
    /// 3DES-ECB (per GP 2.3.1 § 11.8.2.3.1). Each KCV is computed from the
    /// *plaintext* key (not the wrapped form) per Appendix B.4.
    fn put_key_des3_data(
        kvn: u8,
        wrap_dek: &[u8; 16],
        enc: [u8; 16],
        mac: [u8; 16],
        dek: [u8; 16],
    ) -> [u8; 67] {
        let mut data = [0u8; 67];
        data[0] = kvn;
        let mut off = 1;
        for k in [enc, mac, dek] {
            let wrapped = simrs_gp_scp::keywrap::wrap_3des_ecb(wrap_dek, k);
            let kcv = simrs_gp_scp::keywrap::kcv_3des(&k);
            data[off] = 0x80; // KTI: 3DES
            data[off + 1] = 16;
            data[off + 2..off + 18].copy_from_slice(&wrapped);
            data[off + 18] = 0x03; // KCV length
            data[off + 19..off + 22].copy_from_slice(&kcv);
            off += 22;
        }
        data
    }

    /// Establish an Authenticated SCP02 session with a known, non-zero
    /// session DEK. Required for PUT KEY tests since a zero DEK obscures
    /// the unwrap step (zero key + any plaintext gives a deterministic
    /// but non-identifying ciphertext).
    fn make_gp_with_dek(dek: [u8; 16]) -> (TestGpOpen, [u8; 16]) {
        let mut gp = TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        gp.set_authenticated_for_test_with_keys([0u8; 16], [0u8; 16], dek, ScpVersion::Scp02);
        (gp, dek)
    }

    #[test]
    fn put_key_installs_des3_keyset_and_returns_kvn_and_kcvs() {
        // Use a non-zero session DEK so the unwrap step actually transforms
        // bytes -- the alternative (zero DEK) would let a no-op unwrap
        // accidentally pass.
        let dek = [0x55u8; 16];
        let (mut gp, wrap_dek) = make_gp_with_dek(dek);
        let new_kvn = 0x33;
        let enc = [0xA0u8; 16];
        let mac = [0xA1u8; 16];
        let dek_new = [0xA2u8; 16];

        let payload = put_key_des3_data(new_kvn, &wrap_dek, enc, mac, dek_new);
        let apdu = apdu_with_data(0x84, INS_PUT_KEY, new_kvn, 0x01, &payload);

        let mut buf = [0u8; 256];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "PUT KEY should succeed with valid DEK-wrap + KCV; got {:02X?}",
            &rsp[rsp.len() - 2..]
        );
        // Response: KVN || KCV1(3) || KCV2(3) || KCV3(3) -- 10 bytes + 2 SW.
        assert_eq!(rsp.len(), 12, "expected KVN + 9 KCV bytes + SW");
        assert_eq!(rsp[0], new_kvn);
        // Echoed KCVs must equal the ones the test computed from plaintext.
        let expected_kcv_enc = simrs_gp_scp::keywrap::kcv_3des(&enc);
        let expected_kcv_mac = simrs_gp_scp::keywrap::kcv_3des(&mac);
        let expected_kcv_dek = simrs_gp_scp::keywrap::kcv_3des(&dek_new);
        assert_eq!(&rsp[1..4], &expected_kcv_enc);
        assert_eq!(&rsp[4..7], &expected_kcv_mac);
        assert_eq!(&rsp[7..10], &expected_kcv_dek);

        // PUT KEY without SCP auth must fail.
        let mut gp_check = TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        let mut buf2 = [0u8; 256];
        let rsp2 = gp_check.handle(&apdu, &mut buf2);
        assert_ne!(
            &rsp2[rsp2.len() - 2..],
            &[0x90, 0x00],
            "PUT KEY without SCP auth must fail"
        );
    }

    #[test]
    fn put_key_rejects_kcv_mismatch() {
        // Send valid DEK-wrapped keys but a wrong KCV byte. The card must
        // reject rather than silently installing.
        //
        // Payload layout per put_key_des3_data:
        //   [0]    KVN
        //   [1]    KTI (block 0)
        //   [2]    KCL = 16
        //   [3..19]  wrapped key
        //   [19]   KCV length = 3
        //   [20..23] KCV bytes        <-- corrupting one of these
        let dek = [0x55u8; 16];
        let (mut gp, wrap_dek) = make_gp_with_dek(dek);
        let mut payload =
            put_key_des3_data(0x22, &wrap_dek, [0xA0u8; 16], [0xA1u8; 16], [0xA2u8; 16]);
        payload[20] ^= 0x01;

        let apdu = apdu_with_data(0x84, INS_PUT_KEY, 0x22, 0x01, &payload);
        let mut buf = [0u8; 256];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[rsp.len() - 2..], [0x6A, 0x80]);
    }

    #[test]
    fn put_key_rejects_wrong_dek() {
        // Wrap with the wrong DEK so unwrap produces garbage; KCV will
        // not match the plaintext-derived value -> rejection.
        let session_dek = [0x55u8; 16];
        let attacker_dek = [0xAAu8; 16];
        let (mut gp, _) = make_gp_with_dek(session_dek);
        let payload = put_key_des3_data(
            0x22,
            &attacker_dek,
            [0xA0u8; 16],
            [0xA1u8; 16],
            [0xA2u8; 16],
        );
        let apdu = apdu_with_data(0x84, INS_PUT_KEY, 0x22, 0x01, &payload);
        let mut buf = [0u8; 256];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(
            rsp[rsp.len() - 2..],
            [0x6A, 0x80],
            "PUT KEY wrapped with wrong DEK must fail KCV check"
        );
    }

    #[test]
    fn put_key_rejects_mismatched_p1_kvn() {
        let dek = [0x55u8; 16];
        let (mut gp, wrap_dek) = make_gp_with_dek(dek);
        let payload = put_key_des3_data(0x22, &wrap_dek, [0u8; 16], [0u8; 16], [0u8; 16]);
        // P1 says 0x33 but the data field's KVN byte is 0x22 -- the spec
        // requires they agree (or P1 = 0).
        let apdu = apdu_with_data(0x84, INS_PUT_KEY, 0x33, 0x01, &payload);

        let mut buf = [0u8; 256];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[rsp.len() - 2..], [0x6A, 0x80]);
    }

    #[test]
    fn put_key_round_trip_install_then_init_update_with_new_kvn() {
        // Functional check: PUT KEY at KVN=K must actually install keys at K
        // such that a subsequent INITIALIZE UPDATE with key_version=K finds
        // them and derives session keys from them. Without this round-trip
        // the unit test for PUT KEY only verifies the response shape.
        let session_dek = [0x55u8; 16];
        let (mut gp, wrap_dek) = make_gp_with_dek(session_dek);
        let new_kvn = 0x33;

        // Distinguishable key bytes to make missing-install bugs visible.
        let new_enc = [0xAAu8; 16];
        let new_mac = [0xBBu8; 16];
        let new_dek = [0xCCu8; 16];
        let payload = put_key_des3_data(new_kvn, &wrap_dek, new_enc, new_mac, new_dek);
        let put_apdu = apdu_with_data(0x84, INS_PUT_KEY, new_kvn, 0x01, &payload);

        let mut buf = [0u8; 256];
        let rsp = gp.handle(&put_apdu, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00], "PUT KEY must succeed");

        // Reset SCP so we can drive a fresh handshake against the new KVN.
        gp.reset_scp_state();

        // INITIALIZE UPDATE with key_version = new_kvn. If the keystore
        // didn't actually install at this KVN, `get_or_default(0x33)` returns
        // None and we'd get 6A86 (key not found). 9000 here is the proof.
        let host_challenge = [0u8; 8];
        let init_apdu = apdu_with_data(0x80, INS_INITIALIZE_UPDATE, new_kvn, 0x00, &host_challenge);
        let rsp = gp.handle(&init_apdu, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "INITIALIZE UPDATE with the new KVN must succeed -- this is what proves PUT KEY actually installed"
        );

        // Response is 28 bytes for SCP02. KVN byte at offset 10 must echo
        // the installed KVN.
        assert_eq!(rsp.len(), 30, "expected 28 bytes data + 2 SW");
        assert_eq!(
            rsp[10], new_kvn,
            "INIT UPDATE response key_version must reflect installed KVN"
        );
        assert_eq!(
            rsp[11], 0x02,
            "SCP identifier must be 0x02 for the 3DES keyset we installed"
        );

        // Cryptogram computed from the new session keys must be non-trivial.
        // (A bug returning the static zero cryptogram would slip past a
        // shape-only check.)
        assert_ne!(&rsp[20..28], &[0u8; 8][..], "cryptogram must be non-zero");

        // SCP state should have advanced into InitUpdateDone. That's the
        // evidence the PUT-KEY'd static keys reached the KDF.
        assert!(
            matches!(
                gp.scp_state(),
                ScpState::InitUpdateDone {
                    scp_version: ScpVersion::Scp02,
                    ..
                }
            ),
            "scp_state must be InitUpdateDone after successful INIT UPDATE",
        );
    }

    #[test]
    fn put_key_rejects_truncated_block() {
        let mut gp = make_gp();
        // Hand-roll a malformed payload: Key Component Length claims 17
        // bytes but only the bytes for length 16 are present.
        let mut payload = [0u8; 67];
        payload[0] = 0x22; // KVN
        payload[1] = 0x80; // KTI 3DES
        payload[2] = 17; // overstated Key Component Length

        let apdu = apdu_with_data(0x84, INS_PUT_KEY, 0x22, 0x01, &payload);
        let mut buf = [0u8; 256];
        let rsp = gp.handle(&apdu, &mut buf);
        // Either truncation (6700) or wrong-params (6A80) -- both
        // protocol-conformant rejections. Asserting non-success keeps
        // the test robust to either.
        assert_ne!(rsp[rsp.len() - 2..], [0x90, 0x00]);
    }

    #[test]
    fn store_data_chain_accumulates_in_order() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Block 0: not-last, payload 8 bytes.
        let a1 = apdu_with_data(0x84, INS_STORE_DATA, 0x00, 0x00, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(gp.handle(&a1, &mut buf)[..2], [0x90, 0x00]);

        // Block 1: last, payload 4 bytes.
        let a2 = apdu_with_data(0x84, INS_STORE_DATA, 0x80, 0x01, &[9, 10, 11, 12]);
        assert_eq!(gp.handle(&a2, &mut buf)[..2], [0x90, 0x00]);

        // A new chain is allowed immediately afterwards.
        assert_eq!(gp.handle(&a1, &mut buf)[..2], [0x90, 0x00]);
    }

    #[test]
    fn store_data_rejects_out_of_order_block_index() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        let a1 = apdu_with_data(0x84, INS_STORE_DATA, 0x00, 0x00, &[1, 2, 3, 4]);
        assert_eq!(gp.handle(&a1, &mut buf)[..2], [0x90, 0x00]);

        // Second block must have P2 == 0x01; sending 0x05 is an error.
        let a2 = apdu_with_data(0x84, INS_STORE_DATA, 0x80, 0x05, &[5, 6, 7, 8]);
        assert_eq!(gp.handle(&a2, &mut buf)[..2], [0x6A, 0x86]);
    }

    #[test]
    fn install_for_personalization_unknown_aid_returns_6a82() {
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let unknown_aid = [0xFFu8; 8];
        let cmd = build_install_for_personalization(&unknown_aid);
        let rsp = gp.handle(&cmd, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x6A, 0x82]);
        assert!(gp.personalization_target.is_none());
    }

    #[test]
    #[allow(clippy::large_stack_arrays, clippy::cast_possible_truncation)]
    fn store_data_dispatches_to_jcvm_personalization_target() {
        use simrs_jcasm::jcasm;

        let keys = test_keys();
        let mut gp = GpOpen::<DeterministicRng, DEFAULT_MAX_APPLETS, DEFAULT_MAX_SDS>::new(
            &keys,
            DeterministicRng::new(TEST_RNG_SEED),
        );
        gp.set_authenticated_for_test();

        // Build a CAP blob whose `process()` returns a recognisable value.
        // STORE DATA dispatch goes to the same method (`processData()`
        // is conflated with `process()` in this runtime).
        let (aid, methods) = jcasm! {
            applet A0_00_00_00_77_01_01 {
                fn process() {
                    bspush(99);
                    sreturn;
                }
            }
        };
        let mut cap_blob = [0u8; 256];
        let cap_len = simrs_jcvm::cap::build_cap_blob(aid, methods, &mut cap_blob);

        let pkg_aid = [0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x01];
        let instance_aid = [0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x01, 0x01];
        let mut buf = [0u8; 261];

        // Load and install the applet.
        gp.handle(&build_install_for_load(&pkg_aid), &mut buf);
        let load_apdu = apdu_with_data(CLA_GP, INS_LOAD, 0x80, 0x00, &cap_blob[..cap_len]);
        gp.handle(&load_apdu, &mut buf);
        gp.handle(
            &build_install_for_ims(&pkg_aid, &pkg_aid, &instance_aid),
            &mut buf,
        );

        // INSTALL [for personalization] selects the applet as the recipient.
        let perso = build_install_for_personalization(&instance_aid);
        let rsp = gp.handle(&perso, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        assert!(gp.personalization_target.is_some());

        // STORE DATA last block dispatches the payload to the applet.
        let a1 = apdu_with_data(0x84, INS_STORE_DATA, 0x80, 0x00, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let rsp = gp.handle(&a1, &mut buf);
        assert_eq!(
            &rsp[rsp.len() - 2..],
            &[0x90, 0x00],
            "STORE DATA dispatch should succeed"
        );
        // The personalization target is consumed by dispatch.
        assert!(gp.personalization_target.is_none());
    }

    #[test]
    fn store_data_without_install_for_personalization_succeeds_at_sd_level() {
        // GP 2.3.1 § 7.3: with no prior INSTALL [for personalization]
        // the data is owned by the SD that holds the SCP session
        // (the ISD here). Our runtime accepts it silently.
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        assert!(gp.personalization_target.is_none());

        let a1 = apdu_with_data(0x84, INS_STORE_DATA, 0x80, 0x00, &[1, 2, 3]);
        assert_eq!(gp.handle(&a1, &mut buf)[..2], [0x90, 0x00]);
    }

    #[test]
    fn reset_scp_state_clears_personalization_target() {
        let mut gp = make_gp();
        // Forge a personalization target as if INSTALL [for perso] had run.
        gp.personalization_target = Some(0);

        gp.reset_scp_state();
        assert!(gp.personalization_target.is_none());
    }

    #[test]
    fn store_data_dispatches_to_external_callback_for_non_jcvm_applet() {
        // INSTALL [for personalization] of a non-JCVM applet, then a
        // STORE DATA chain whose final block triggers external dispatch
        // via AppletDispatchFn.
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Register a non-JCVM applet (no jcvm_pkg_idx).
        let app_aid: [u8; 6] = [0xA0, 0x00, 0x00, 0x00, 0x99, 0x01];
        // load_aid_len(0) || module_aid_len(0) || app_aid_len(6) || app_aid || privs/params/token (0,0,0).
        let install_data: [u8; 12] = [
            0x00, 0x00, 0x06, app_aid[0], app_aid[1], app_aid[2], app_aid[3], app_aid[4],
            app_aid[5], 0, 0, 0,
        ];
        let install_apdu = apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &install_data);
        gp.handle(&install_apdu, &mut buf);

        // INSTALL [for personalization].
        let perso = build_install_for_personalization(&app_aid);
        let rsp = gp.handle(&perso, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        assert!(gp.personalization_target.is_some());

        // Last STORE DATA block; payload assembled = [0xCA, 0xFE, 0xBA, 0xBE].
        let payload = [0xCAu8, 0xFE, 0xBA, 0xBE];

        // Capture what the dispatch callback observes.
        let mut seen_payload: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut seen_idx: Option<u8> = None;
        let result_len = {
            let mut cb = |applet_idx: u8, cmd: &[u8], rsp: &mut [u8]| -> usize {
                seen_idx = Some(applet_idx);
                // Parse the synthetic APDU: CLA INS P1 P2 Lc data...
                if cmd.len() >= 5 {
                    let lc = cmd[4] as usize;
                    seen_payload.extend_from_slice(&cmd[5..5 + lc]);
                }
                rsp[0] = 0x90;
                rsp[1] = 0x00;
                2
            };
            let store = apdu_with_data(0x84, INS_STORE_DATA, 0x80, 0x00, &payload);
            // Drive the chain through handle_with_dispatch so the callback
            // is plumbed.
            let dispatched = gp.handle_with_dispatch(
                &store,
                &mut buf,
                Some(&mut cb as &mut AppletDispatchFn<'_>),
            );
            dispatched.len()
        };

        assert_eq!(result_len, 2, "expected SW only");
        assert_eq!(&buf[..2], &[0x90, 0x00]);
        assert_eq!(
            seen_payload, payload,
            "callback must see the assembled payload"
        );
        assert!(seen_idx.is_some(), "callback must receive the applet index");
        assert!(
            gp.personalization_target.is_none(),
            "target consumed after dispatch"
        );
    }

    #[test]
    fn store_data_external_dispatch_propagates_response_data_and_sw() {
        // The recipient's processData() may return data + SW; STORE DATA's
        // response carries that through unchanged (GP 2.3.1 § 11.11.3).
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        let app_aid: [u8; 6] = [0xA0, 0x00, 0x00, 0x00, 0x99, 0x02];
        let install_data: [u8; 12] = [
            0x00, 0x00, 0x06, app_aid[0], app_aid[1], app_aid[2], app_aid[3], app_aid[4],
            app_aid[5], 0, 0, 0,
        ];
        let install_apdu = apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &install_data);
        gp.handle(&install_apdu, &mut buf);
        let perso = build_install_for_personalization(&app_aid);
        gp.handle(&perso, &mut buf);

        // Recipient returns three bytes of data followed by 6A 88
        // ("referenced data not found") -- a non-success SW so we can
        // verify both the data and the non-trivial SW propagate.
        let mut cb = |_idx: u8, _cmd: &[u8], rsp: &mut [u8]| -> usize {
            rsp[0] = 0x11;
            rsp[1] = 0x22;
            rsp[2] = 0x33;
            rsp[3] = 0x6A;
            rsp[4] = 0x88;
            5
        };
        let store = apdu_with_data(0x84, INS_STORE_DATA, 0x80, 0x00, &[0xAA, 0xBB]);
        let dispatched = gp
            .handle_with_dispatch(&store, &mut buf, Some(&mut cb as &mut AppletDispatchFn<'_>))
            .to_vec();

        assert_eq!(
            dispatched.as_slice(),
            &[0x11, 0x22, 0x33, 0x6A, 0x88],
            "recipient response (data + SW) must propagate verbatim"
        );
    }

    #[test]
    fn store_data_external_dispatch_rejects_payload_over_255_bytes() {
        // Short APDU Lc caps payloads at 255 bytes. Larger payloads
        // come back as 6A 84 until extended-length APDU support lands.
        let mut gp = make_gp();
        let mut buf = [0u8; 512];

        let app_aid: [u8; 6] = [0xA0, 0x00, 0x00, 0x00, 0x99, 0x03];
        let install_data: [u8; 12] = [
            0x00, 0x00, 0x06, app_aid[0], app_aid[1], app_aid[2], app_aid[3], app_aid[4],
            app_aid[5], 0, 0, 0,
        ];
        gp.handle(
            &apdu_with_data(CLA_GP, INS_INSTALL, 0x0C, 0x00, &install_data),
            &mut buf,
        );
        gp.handle(&build_install_for_personalization(&app_aid), &mut buf);

        // Two 200-byte chained blocks => 400-byte assembled payload.
        let block0: alloc::vec::Vec<u8> = alloc::vec![0xAAu8; 200];
        let block1: alloc::vec::Vec<u8> = alloc::vec![0xBBu8; 200];
        gp.handle(
            &apdu_with_data(0x84, INS_STORE_DATA, 0x00, 0x00, &block0),
            &mut buf,
        );
        let mut callback_called = false;
        let mut cb = |_idx: u8, _cmd: &[u8], rsp: &mut [u8]| -> usize {
            callback_called = true;
            rsp[0] = 0x90;
            rsp[1] = 0x00;
            2
        };
        let last = apdu_with_data(0x84, INS_STORE_DATA, 0x80, 0x01, &block1);
        let dispatched = gp
            .handle_with_dispatch(&last, &mut buf, Some(&mut cb as &mut AppletDispatchFn<'_>))
            .to_vec();

        assert_eq!(&dispatched[..], &[0x6A, 0x84]);
        assert!(
            !callback_called,
            "callback must not be invoked when payload exceeds short-APDU limit"
        );
    }

    #[test]
    fn begin_rmac_session_sets_flag_and_end_clears_it() {
        let mut gp = make_gp();
        let mut buf = [0u8; 16];

        // BEGIN R-MAC SESSION: CLA 0x84, INS 0x7A, P1=0x00, P2=0x01, no body.
        let begin = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        let rsp = gp.handle(&begin, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);

        match gp.scp_state() {
            ScpState::Authenticated { rmac_active, .. } => {
                assert!(
                    *rmac_active,
                    "rmac_active should be set after BEGIN R-MAC SESSION"
                );
            }
            _ => panic!("expected Authenticated state"),
        }

        // END R-MAC SESSION: P1=0x00, P2=0x00.
        let end = apdu_header(0x84, commands::INS_END_RMAC_SESSION, 0x00, 0x00);
        let rsp = gp.handle(&end, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);

        match gp.scp_state() {
            ScpState::Authenticated { rmac_active, .. } => {
                assert!(
                    !*rmac_active,
                    "rmac_active should be cleared after END R-MAC SESSION"
                );
            }
            _ => panic!("expected Authenticated state"),
        }
    }

    #[test]
    fn begin_rmac_session_requires_authentication() {
        let mut gp = make_gp_unauthenticated();
        let mut buf = [0u8; 16];
        let begin = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        let rsp = gp.handle(&begin, &mut buf);
        assert_eq!(rsp[rsp.len() - 2..], [0x69, 0x85]);
    }

    #[test]
    fn rmac_active_appends_8_byte_trailer_to_responses() {
        // After BEGIN R-MAC SESSION, every subsequent response has an
        // 8-byte R-MAC inserted between data and SW.
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Baseline: GET DATA without R-MAC.
        let get_data = apdu_with_response_len(0x84, INS_GET_DATA, 0x00, 0x66, 0x00);
        let baseline = gp.handle(&get_data, &mut buf).len();

        // Activate R-MAC.
        let begin = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        gp.handle(&begin, &mut buf);

        // Same GET DATA -- the response should be 8 bytes longer.
        let with_rmac = gp.handle(&get_data, &mut buf).len();
        assert_eq!(
            with_rmac,
            baseline + 8,
            "R-MAC trailer should add 8 bytes to the response"
        );
    }

    #[test]
    fn scp03_rmac_appends_8_byte_trailer_when_security_level_bit_set() {
        // SCP03 R-MAC is set at session-establishment time via the
        // EXTERNAL AUTHENTICATE P1 high bits. When `security_level &
        // 0x10` is set, every response must carry an 8-byte R-MAC
        // trailer per GP 2.3.1 Amd D § 6.2.7.
        let mut gp = make_gp_unauthenticated();
        // Synthesize an authenticated SCP03 session with R-MAC active.
        *gp.scp_state_mut_for_test() = ScpState::Authenticated {
            session_enc: [0x33; 16],
            command_mac: [0x33; 16],
            response_mac: [0x77; 16],
            session_dek: [0x33; 16],
            security_level: 0x10, // R-MAC, no R-ENC
            icv: [0u8; 16],
            rmac_icv: [0u8; 8],
            rmac_active: true,
            scp_version: ScpVersion::Scp03,
            enc_counter: 0,
        };

        let mut buf = [0u8; 256];
        let get_data = apdu_with_response_len(0x80, INS_GET_DATA, 0x00, 0x66, 0x00);

        // Baseline (no R-MAC) length first, in a separate buffer.
        let mut gp_baseline = make_gp_unauthenticated();
        let mut baseline_buf = [0u8; 256];
        let baseline_len = gp_baseline.handle(&get_data, &mut baseline_buf).len();

        let rsp_len = gp.handle(&get_data, &mut buf).len();
        assert_eq!(&buf[rsp_len - 2..rsp_len], &[0x90, 0x00]);
        assert_eq!(
            rsp_len,
            baseline_len + 8,
            "SCP03 R-MAC must add an 8-byte trailer"
        );
    }

    #[test]
    fn rmac_input_uses_post_unwrap_data_for_cmac_commands() {
        // Drive an SCP02 C-MAC + R-MAC session and verify the R-MAC
        // chain advances using the *post-unwrap* command data field
        // (per GP 2.3.1 Appendix E.4.6.3) rather than the wire bytes
        // that include the C-MAC trailer.
        //
        // Strategy: replay the same logical command twice, each time
        // capturing the running R-MAC ICV. If the implementation
        // mistakenly fed the wire data (including the C-MAC) into
        // R-MAC, the chain would still advance, but the captured
        // value would not match a hand-computed R-MAC over the
        // post-unwrap data. We verify the implementation matches
        // the post-unwrap reference value.
        use simrs_gp_scp::{generate_cmac, wrap_response};

        let command_mac = [0x42u8; 16];
        let response_mac = [0x77u8; 16];

        let mut gp = make_gp_unauthenticated();
        // SCP02 with C-MAC + R-MAC active, fresh chaining ICVs.
        *gp.scp_state_mut_for_test() = ScpState::Authenticated {
            session_enc: [0u8; 16],
            command_mac,
            response_mac,
            session_dek: [0u8; 16],
            security_level: 0x11, // C-MAC + R-MAC
            icv: [0u8; 16],
            rmac_icv: [0u8; 8],
            rmac_active: true,
            scp_version: ScpVersion::Scp02,
            enc_counter: 0,
        };

        // Build a C-MAC'd SET STATUS APDU. SET STATUS has a 1-byte
        // payload (the new lifecycle byte). The wire APDU is
        // `84 F0 80 0F 09 0F mac[8]`.
        let lifecycle_byte = CardLifecycle::Initialized.to_byte();
        let plaintext_data = [lifecycle_byte];
        let header = [0x84u8, INS_SET_STATUS, 0x80, lifecycle_byte];
        // GP 2.3.1 Appendix E.4.4 (SCP02): the first C-MAC ICV after
        // EXTERNAL AUTHENTICATE is derived from the all-zero seed block.
        // Test fixture passes the spec-mandated zero seed to mirror
        // production behaviour -- CodeQL false positive on
        // `rust/hard-coded-cryptographic-value`.
        let (mac, _new_icv) = generate_cmac(
            &command_mac,
            &header,
            &plaintext_data,
            &[0u8; 8],
            ScpVersion::Scp02,
        );
        let mut wire_data = alloc::vec::Vec::with_capacity(plaintext_data.len() + 8);
        wire_data.extend_from_slice(&plaintext_data);
        wire_data.extend_from_slice(&mac);
        let wire_apdu = apdu_with_data(0x84, INS_SET_STATUS, 0x80, lifecycle_byte, &wire_data);

        let mut buf = [0u8; 256];
        let rsp = gp.handle(&wire_apdu, &mut buf);
        // Response: data (none for SET STATUS) || R-MAC[8] || SW(2).
        assert_eq!(rsp.len(), 10, "SCP02 SET STATUS R-MAC response = 8 + 2 SW");
        assert_eq!(&rsp[8..], &[0x90, 0x00], "SET STATUS should succeed");
        let observed_rmac: [u8; 8] = rsp[..8].try_into().unwrap();

        // Compute the reference R-MAC over the *post-unwrap* command
        // data field (just `plaintext_data`, no MAC trailer) using a
        // throwaway state. If we matched on the wire form instead,
        // the input would be `wire_data` (plaintext + MAC), and the
        // computed value would differ.
        let mut ref_state = ScpState::Authenticated {
            session_enc: [0u8; 16],
            command_mac,
            response_mac,
            session_dek: [0u8; 16],
            security_level: 0x11,
            icv: [0u8; 16],
            rmac_icv: [0u8; 8],
            rmac_active: true,
            scp_version: ScpVersion::Scp02,
            enc_counter: 0,
        };
        let mut ref_out = [0u8; 32];
        wrap_response(
            &mut ref_state,
            &plaintext_data, // post-unwrap data
            &[],             // empty response data
            0x90,
            0x00,
            &mut ref_out,
        );
        let expected_rmac: [u8; 8] = ref_out[..8].try_into().unwrap();
        assert_eq!(
            observed_rmac, expected_rmac,
            "R-MAC must be computed over post-unwrap command data, \
             not the wire form (which includes the C-MAC trailer)"
        );

        // Sanity check: same computation with the wire form (incl. the
        // C-MAC trailer) MUST differ -- otherwise the test is a tautology.
        let mut wrong_state = ScpState::Authenticated {
            session_enc: [0u8; 16],
            command_mac,
            response_mac,
            session_dek: [0u8; 16],
            security_level: 0x11,
            icv: [0u8; 16],
            rmac_icv: [0u8; 8],
            rmac_active: true,
            scp_version: ScpVersion::Scp02,
            enc_counter: 0,
        };
        let mut wrong_out = [0u8; 32];
        wrap_response(
            &mut wrong_state,
            &wire_data,
            &[],
            0x90,
            0x00,
            &mut wrong_out,
        );
        assert_ne!(
            &wrong_out[..8],
            &expected_rmac[..],
            "post-unwrap and wire-form R-MAC inputs must produce different MACs"
        );
    }

    #[test]
    fn rmac_chain_advances_across_commands() {
        // The running R-MAC ICV is updated after each wrapped response.
        // Sending the same command twice in a row must yield different
        // R-MAC trailers because the ICV has changed.
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        let begin = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        gp.handle(&begin, &mut buf);

        let get_data = apdu_with_response_len(0x84, INS_GET_DATA, 0x00, 0x66, 0x00);

        let rsp1 = gp.handle(&get_data, &mut buf).to_vec();
        let trailer1: [u8; 8] = rsp1[rsp1.len() - 10..rsp1.len() - 2]
            .try_into()
            .expect("8-byte R-MAC");

        let rsp2 = gp.handle(&get_data, &mut buf).to_vec();
        let trailer2: [u8; 8] = rsp2[rsp2.len() - 10..rsp2.len() - 2]
            .try_into()
            .expect("8-byte R-MAC");

        assert_ne!(
            trailer1, trailer2,
            "R-MAC chain should advance: same command yields different R-MAC trailers"
        );
    }

    #[test]
    fn end_rmac_session_p1_03_returns_running_rmac() {
        // P1 = 0x03 returns the current running R-MAC chaining value
        // followed by SW = 9000.
        let mut gp = make_gp();
        let mut buf = [0u8; 256];

        // Activate R-MAC.
        let begin = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        gp.handle(&begin, &mut buf);
        // Drive the chain by executing a command.
        let get_data = apdu_with_response_len(0x84, INS_GET_DATA, 0x00, 0x66, 0x00);
        gp.handle(&get_data, &mut buf);

        // Capture rmac_icv before END.
        let icv_before = match gp.scp_state() {
            ScpState::Authenticated { rmac_icv, .. } => *rmac_icv,
            _ => panic!("expected Authenticated state"),
        };
        assert_ne!(icv_before, [0u8; 8], "chain should have advanced past zero");

        // END R-MAC SESSION P1=0x03.
        let end = apdu_header(0x84, commands::INS_END_RMAC_SESSION, 0x03, 0x00);
        let rsp = gp.handle(&end, &mut buf);
        // Response: 8-byte chain || 90 00. END R-MAC itself is not
        // R-MAC-wrapped (rmac_active is cleared inside the handler
        // before the outer wrap_response sees the state).
        assert_eq!(rsp.len(), 10);
        assert_eq!(&rsp[..8], &icv_before);
        assert_eq!(&rsp[8..], &[0x90, 0x00]);
        // rmac_icv is cleared after END.
        match gp.scp_state() {
            ScpState::Authenticated {
                rmac_icv,
                rmac_active,
                ..
            } => {
                assert_eq!(*rmac_icv, [0u8; 8]);
                assert!(!*rmac_active);
            }
            _ => panic!("expected Authenticated state"),
        }
    }

    #[test]
    fn rmac_chain_resets_on_begin_rmac_session() {
        // BEGIN R-MAC SESSION resets the running R-MAC ICV to all zeros.
        // We can't observe the reset directly because the BEGIN response
        // is itself R-MAC-wrapped, which advances the ICV. Instead,
        // verify the property indirectly: the post-BEGIN ICV is the
        // same regardless of the prior ICV value.
        let begin = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        let mut buf = [0u8; 256];

        let mut gp_a = make_gp();
        gp_a.handle(&begin, &mut buf);
        let icv_a = match gp_a.scp_state() {
            ScpState::Authenticated { rmac_icv, .. } => *rmac_icv,
            _ => panic!("expected Authenticated state"),
        };

        let mut gp_b = make_gp();
        // Forge a non-zero rmac_icv before BEGIN -- this should be
        // wiped by BEGIN R-MAC SESSION.
        match gp_b.scp_state_mut_for_test() {
            ScpState::Authenticated { rmac_icv, .. } => {
                *rmac_icv = [0xAA; 8];
            }
            _ => panic!("expected Authenticated state"),
        }
        gp_b.handle(&begin, &mut buf);
        let icv_b = match gp_b.scp_state() {
            ScpState::Authenticated { rmac_icv, .. } => *rmac_icv,
            _ => panic!("expected Authenticated state"),
        };

        assert_eq!(
            icv_a, icv_b,
            "BEGIN R-MAC SESSION must zero rmac_icv before the response wrap"
        );
    }

    #[test]
    fn begin_rmac_session_with_data_seeds_chain_per_appendix_e6() {
        // Per GP 2.3.1 Appendix E.6, BEGIN R-MAC SESSION's optional
        // data field seeds the running R-MAC ICV via
        // CBC-MAC(S-RMAC, IV=0, Method-2-padded(data)).
        //
        // BEGIN with empty data -> rmac_icv stays zero.
        // BEGIN with data -> rmac_icv = MAC(data) (non-zero, deterministic).
        let mut gp_empty = make_gp();
        let mut buf = [0u8; 256];
        let begin_empty = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        gp_empty.handle(&begin_empty, &mut buf);
        match gp_empty.scp_state() {
            ScpState::Authenticated { rmac_icv, .. } => {
                assert_eq!(*rmac_icv, [0u8; 8], "empty data leaves chain at zero");
            }
            _ => panic!("expected Authenticated"),
        }

        let mut gp_data = make_gp();
        let payload = [0xCAu8, 0xFE, 0xBA, 0xBE];
        let begin_data =
            apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &payload);
        gp_data.handle(&begin_data, &mut buf);
        let seeded_icv = match gp_data.scp_state() {
            ScpState::Authenticated { rmac_icv, .. } => *rmac_icv,
            _ => panic!("expected Authenticated"),
        };
        assert_ne!(seeded_icv, [0u8; 8], "non-empty data must seed the chain");

        // Compute the reference via the LOWER-level primitives (not via
        // `seed_rmac_chain_scp02`, which is the helper under test): pad
        // with Method 2 and run 3DES-CBC-MAC with IV=0 and the session
        // R-MAC key (zero in tests since make_gp() defaults them to
        // zero). If the helper had a bug, this independent path would
        // disagree.
        let response_mac_key = match gp_data.scp_state() {
            ScpState::Authenticated { response_mac, .. } => *response_mac,
            _ => panic!("expected Authenticated"),
        };
        let mut padded_ref = [0u8; 32];
        let padded_ref_len = simrs_iso9797::pad_method2(&payload, 8, &mut padded_ref);
        let key = simrs_secret::Secret::new(response_mac_key);
        // GP 2.3.1 Appendix E.6: R-MAC seed reference computation uses
        // `CBC-MAC(S-RMAC, IV = 0, Method-2-pad(data))`. Test asserts
        // the production helper matches this independent reference.
        // Zero IV is spec-mandated -- CodeQL false positive on
        // `rust/hard-coded-cryptographic-value`.
        let expected =
            simrs_gp_scp::des3_2key_cbc_mac_with_iv(&key, [0u8; 8], &padded_ref[..padded_ref_len]);
        assert_eq!(
            seeded_icv, expected,
            "rmac_icv must equal the spec-defined CBC-MAC of the data field"
        );

        // Empty-data and non-empty-data paths must produce distinct chains.
        match gp_empty.scp_state() {
            ScpState::Authenticated { rmac_icv, .. } => {
                assert_ne!(
                    *rmac_icv, seeded_icv,
                    "empty- vs non-empty-data BEGIN must seed differently"
                );
            }
            _ => panic!("expected Authenticated"),
        }
    }

    #[test]
    fn begin_rmac_session_response_is_not_rmac_wrapped() {
        // BEGIN R-MAC SESSION's own response is the seeding act; it
        // must NOT carry an R-MAC trailer (Appendix E.6).
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        let begin = apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]);
        let rsp = gp.handle(&begin, &mut buf);
        // Response is just SW = 9000, no 8-byte trailer.
        assert_eq!(rsp, &[0x90, 0x00]);
    }

    #[test]
    fn end_rmac_session_response_is_not_rmac_wrapped() {
        // END R-MAC SESSION (P1=0x03) returns the running chain value
        // followed by SW. The response itself is not R-MAC-wrapped.
        let mut gp = make_gp();
        let mut buf = [0u8; 256];
        gp.handle(
            &apdu_with_data(0x84, commands::INS_BEGIN_RMAC_SESSION, 0x00, 0x01, &[]),
            &mut buf,
        );
        // Drive the chain with a real wrapped command first.
        gp.handle(
            &apdu_with_response_len(0x84, INS_GET_DATA, 0x00, 0x66, 0x00),
            &mut buf,
        );
        let end = apdu_header(0x84, commands::INS_END_RMAC_SESSION, 0x03, 0x00);
        let rsp = gp.handle(&end, &mut buf);
        // Response = 8-byte chain || SW(2). No additional R-MAC trailer.
        assert_eq!(rsp.len(), 10, "END R-MAC P1=0x03 returns chain + SW only");
        assert_eq!(&rsp[8..], &[0x90, 0x00]);
    }

    #[test]
    fn scp03_i_param_default_is_zero_and_setter_round_trips() {
        let gp = make_gp_unauthenticated();
        assert_eq!(gp.scp03_i_param(), 0x00, "default i_param must be 0x00");

        let mut gp = make_gp_unauthenticated();
        gp.set_scp03_i_param(0x70);
        assert_eq!(gp.scp03_i_param(), 0x70);
    }

    #[test]
    fn scp02_i_param_default_is_15_and_appears_in_get_data() {
        let mut gp = make_gp_unauthenticated();
        assert_eq!(gp.scp02_i_param(), 0x15);

        gp.set_scp02_i_param(0x05);

        // GET DATA tag 0066 (Card Recognition Data).
        let apdu = apdu_with_response_len(0x80, INS_GET_DATA, 0x00, 0x66, 0x00);
        let mut buf = [0u8; 256];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        // SCP02 OID `06 09 2A 86 48 86 FC 6B 04 02 <i>` ends with the
        // configured i parameter byte.
        let marker = [0x06u8, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x02];
        let pos = rsp
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("SCP02 OID marker must appear in card recognition data");
        assert_eq!(rsp[pos + marker.len()], 0x05);
    }

    #[test]
    fn scp02_pseudo_random_mode_derives_card_challenge_from_seq_counter() {
        // i_param with bit 4 cleared (e.g. 0x05) selects pseudo-random
        // card-challenge derivation per GP 2.3.1 Appendix E.4.2.1.5.
        // The card_challenge appears at bytes [14..20] of the INIT UPDATE
        // response (after kdiv[10] || keyver[1] || scp_id[1] || seq[2]).
        let mut gp = TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        gp.set_scp02_i_param(0x05);
        gp.set_sequence_counter(0x1234);

        let host_challenge = [0u8; 8];
        let init_apdu = apdu_with_data(CLA_GP, INS_INITIALIZE_UPDATE, 0x01, 0x00, &host_challenge);
        let mut buf = [0u8; 256];
        let rsp = gp.handle(&init_apdu, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        assert_eq!(
            rsp.len(),
            30,
            "SCP02 INIT UPDATE response is 28 bytes + 2 SW"
        );

        // Capture the 6-byte card_challenge from the response.
        let mut cc_first = [0u8; 6];
        cc_first.copy_from_slice(&rsp[14..20]);

        // Independently compute what the spec-correct derivation should produce.
        let expected_cc8 = simrs_gp_scp::scp02_pseudo_random_card_challenge(
            test_keys().enc().try_into().unwrap(),
            0x1234,
        );
        assert_eq!(
            &cc_first[..],
            &expected_cc8[2..8],
            "card_challenge must match independent pseudo-random derivation"
        );

        // Reset SCP, change the sequence counter, and verify the
        // challenge changes.
        gp.reset_scp_state();
        gp.set_sequence_counter(0x5678);
        let rsp = gp.handle(&init_apdu, &mut buf);
        assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]);
        let mut cc_second = [0u8; 6];
        cc_second.copy_from_slice(&rsp[14..20]);
        assert_ne!(
            cc_first, cc_second,
            "different sequence counters must produce different pseudo-random card_challenges"
        );
    }

    #[test]
    fn scp02_explicit_mode_card_challenge_differs_from_pseudo_random() {
        // i_param with bit 4 set (default 0x15) selects explicit mode.
        // The placeholder we use in explicit mode is *not* the same byte
        // pattern the pseudo-random derivation produces, so flipping the
        // i bit must visibly change the response.
        let host_challenge = [0u8; 8];
        let init_apdu = apdu_with_data(CLA_GP, INS_INITIALIZE_UPDATE, 0x01, 0x00, &host_challenge);

        // Explicit mode (default).
        let mut gp_e = TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        gp_e.set_scp02_i_param(0x15);
        gp_e.set_sequence_counter(0x1234);
        let mut buf = [0u8; 256];
        let rsp = gp_e.handle(&init_apdu, &mut buf);
        let mut cc_explicit = [0u8; 6];
        cc_explicit.copy_from_slice(&rsp[14..20]);

        // Pseudo-random mode.
        let mut gp_pr = TestGpOpen::new(&test_keys(), DeterministicRng::new(TEST_RNG_SEED));
        gp_pr.set_scp02_i_param(0x05);
        gp_pr.set_sequence_counter(0x1234);
        let rsp = gp_pr.handle(&init_apdu, &mut buf);
        let mut cc_pr = [0u8; 6];
        cc_pr.copy_from_slice(&rsp[14..20]);

        assert_ne!(
            cc_explicit, cc_pr,
            "explicit-mode placeholder and pseudo-random derivation must produce visibly different card_challenges for the same seq counter"
        );
    }

    #[test]
    fn unknown_gp_ins_still_returns_6d00_after_phase1_inserts() {
        // After adding INS 0x7A / 0x78, an unknown INS like 0xFE must
        // still fail with 6D00 rather than being mis-classified.
        let mut gp = make_gp();
        let apdu = apdu_header(0x80, 0xFE, 0x00, 0x00);
        let mut buf = [0u8; 16];
        let rsp = gp.handle(&apdu, &mut buf);
        assert_eq!(rsp[rsp.len() - 2..], [0x6D, 0x00]);
    }
}
