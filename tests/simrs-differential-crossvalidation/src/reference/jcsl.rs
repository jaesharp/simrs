//! Oracle `jcsl` reference backend.
//!
//! Entire module gated by `feature = "jcsl-backend"`. Nothing here
//! compiles or pulls in the `simrs-jcsl` dependency when the feature
//! is off.

use std::io;
use std::time::Duration;

use simrs_jcsl::configurator::{GlobalPin, ScpKeyset};
use simrs_jcsl::{JcslClient, JcslProcess};
use simrs_transport::{Transport, TransportError};

use crate::reference::{BackendId, ReferenceBackend, hex_upper};
use crate::{KEY_BYTES, next_port};

/// Classify an [`io::Error`] from the jcsl client into the harness's
/// [`TransportError`] vocabulary. Peer-closed errors collapse to
/// `Disconnected`, everything else to `IoError`.
fn map_io_err(e: &io::Error) -> TransportError {
    use io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    match e.kind() {
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => {
            TransportError::Disconnected
        }
        _ => TransportError::IoError,
    }
}

/// Reference-backend adapter around Oracle's `jcsl` simulator.
pub struct JcslBackend {
    client: JcslClient,
    port: u16,
    _proc: JcslProcess,
    /// Snapshot of the binary path + key material used, for
    /// [`context_entries`](Self::context_entries).
    binary_path: std::path::PathBuf,
    scp_kvn: u8,
    scp_keys_hex: String,
    pin_hex: String,
}

impl JcslBackend {
    /// Spawn `jcsl` with default GP test keys, PIN "1234", and connect.
    ///
    /// Returns `None` when [`simrs_jcsl::discover_binary`] fails --
    /// caller can skip gracefully.
    ///
    /// # Panics
    ///
    /// Panics if the binary exists but configuration or startup fails.
    #[must_use]
    pub fn try_start() -> Option<Self> {
        let src = simrs_jcsl::discover_binary()?;
        // Serialise the (next_port, spawn, wait-for-listen) handshake
        // so parallel backend spawns can't race on the same ephemeral
        // port. Released once the child is bound and the client has
        // connected; subsequent APDU exchanges are lock-free.
        let _spawn = crate::backend_spawn_lock();
        let port = next_port();
        let keyset = ScpKeyset {
            kvn: 0x01,
            enc: KEY_BYTES.to_vec(),
            mac: KEY_BYTES.to_vec(),
            dek: KEY_BYTES.to_vec(),
        };
        let pin_bytes = vec![0x31, 0x32, 0x33, 0x34];
        let gpin = GlobalPin {
            pin: pin_bytes.clone(),
            max_retries: 3,
        };
        let proc = JcslProcess::start_configured(
            &src,
            Some(&keyset),
            Some(&gpin),
            port,
            "info",
            Duration::from_secs(10),
        )
        .expect("failed to start jcsl");
        let client =
            JcslClient::connect(&format!("127.0.0.1:{port}")).expect("failed to connect to jcsl");
        let scp_keys_hex = hex_upper(&KEY_BYTES);
        let pin_hex = hex_upper(&pin_bytes);
        Some(Self {
            client,
            port,
            _proc: proc,
            binary_path: src,
            scp_kvn: keyset.kvn,
            scp_keys_hex,
            pin_hex,
        })
    }

    /// Key/value pairs describing this backend's runtime setup. Used
    /// by the report generator's "Environment" section.
    #[must_use]
    pub fn context_entries(&self) -> Vec<(String, String)> {
        vec![
            ("backend".into(), BackendId::Jcsl.as_str().into()),
            ("binary".into(), crate::display_path(&self.binary_path)),
            ("applet.aid".into(), "A000000151000000".into()),
            ("scp.kvn".into(), format!("0x{:02X}", self.scp_kvn)),
            ("scp.enc_mac_dek_hex".into(), self.scp_keys_hex.clone()),
            ("cvm.global_pin_hex".into(), self.pin_hex.clone()),
        ]
    }
}

impl ReferenceBackend for JcslBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Jcsl
    }

    fn power_on(&mut self) -> Result<Vec<u8>, TransportError> {
        self.client.power_on().map_err(|e| map_io_err(&e))
    }

    fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.client.transmit_apdu(apdu).map_err(|e| map_io_err(&e))
    }

    fn reconnect(&mut self) {
        // jcsl doesn't support power-cycling within one TCP session:
        // the server closes the connection on cold-reset. Reopen a
        // fresh client so subsequent APDUs have somewhere to land.
        self.client = JcslClient::connect(&format!("127.0.0.1:{}", self.port))
            .expect("failed to reconnect to jcsl");
    }
}

impl Transport for JcslBackend {
    type Error = TransportError;

    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error> {
        self.client.exchange(cmd, rsp)
    }
}
