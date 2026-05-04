//! Applet trait and result types per [JC RE 2.1.1 Chapter 3](../../../../docs/specs/javacard/2.1.1/JCRESpec.pdf).
//!
//! GP/JC dual-spec note: the inline clauses below were verified
//! against the JCRE 2.1.1 PDF linked above; JCRE 3.2 retains the
//! same applet lifecycle.
//!
//! The [`Applet`] trait is the central extension point for the GP card platform.
//! Every on-card application implements this trait to receive APDU commands.
//!
//! # Lifecycle (JC RE 2.1.1 clauses 3.1-3.5)
//!
//! 1. `install()` -- called once during INSTALL [for install]. Creates the applet
//!    instance and registers it with the JCRE.
//! 2. `select()` -- called when the applet is selected via SELECT [by AID].
//! 3. `process()` -- called for each non-SELECT APDU while selected.
//! 4. `deselect()` -- called when another applet is selected or the card resets.
//!
//! # Power Loss and Reset (JC RE 2.1.1 clause 3.5)
//!
//! On power loss or card reset:
//! - `CLEAR_ON_RESET` transient arrays are zeroed
//! - `CLEAR_ON_DESELECT` transient arrays are zeroed (reset implies deselect)
//! - Active transaction is aborted (rolled back)
//! - No applet method is called (the JCRE handles cleanup internally)

use simrs_iso7816::StatusWord;

/// Result of an applet operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppletResult {
    /// Success: `n` bytes of response data written to the output buffer.
    Ok(usize),
    /// Error: return this status word, no response data.
    Sw(StatusWord),
}

/// A `JavaCard` applet instance.
///
/// This is the Rust-native equivalent of `javacard.framework.Applet`.
/// Applets are compiled to Rust and implement this trait to integrate
/// with the JCRE dispatch.
///
/// # Snapshot Support
///
/// Every applet must support deterministic state serialization via
/// [`snapshot_size`](Applet::snapshot_size), [`save_state`](Applet::save_state),
/// and [`restore_state`](Applet::restore_state). This enables the simrs
/// fuzzing workflow (snapshot/restore at 1M ops/sec).
///
/// # Example
///
/// ```rust,ignore
/// struct HelloApplet {
///     counter: u16,
/// }
///
/// impl Applet for HelloApplet {
///     fn process(&mut self, cmd: &[u8], out: &mut [u8]) -> AppletResult {
///         self.counter += 1;
///         out[0] = (self.counter >> 8) as u8;
///         out[1] = self.counter as u8;
///         AppletResult::Ok(2)
///     }
///
///     fn snapshot_size(&self) -> usize { 2 }
///     fn save_state(&self, buf: &mut [u8]) -> usize {
///         buf[0] = (self.counter >> 8) as u8;
///         buf[1] = self.counter as u8;
///         2
///     }
///     fn restore_state(&mut self, buf: &[u8]) -> bool {
///         if buf.len() < 2 { return false; }
///         self.counter = u16::from_be_bytes([buf[0], buf[1]]);
///         true
///     }
/// }
/// ```
pub trait Applet {
    /// Process an APDU command.
    ///
    /// `cmd` contains the full APDU (CLA INS P1 P2 [Lc data]).
    /// Write response data into `out` and return [`AppletResult::Ok(n)`] with
    /// the number of bytes written, or [`AppletResult::Sw`] with an error status word.
    ///
    /// The JCRE calls this for every non-SELECT command while the applet is selected.
    fn process(&mut self, cmd: &[u8], out: &mut [u8]) -> AppletResult;

    /// Called when the applet is selected (SELECT [by AID]).
    ///
    /// Write optional FCI data into `out`. Return [`AppletResult::Ok(n)`] to accept
    /// selection (with `n` bytes of FCI data), or [`AppletResult::Sw`] to reject.
    ///
    /// Default: accept selection with no FCI data.
    fn select(&mut self, _out: &mut [u8]) -> AppletResult {
        AppletResult::Ok(0)
    }

    /// Called when the applet is deselected.
    ///
    /// The JCRE calls this when another applet is selected on the same logical
    /// channel, or on card reset. After this call, `CLEAR_ON_DESELECT` transient
    /// arrays are zeroed.
    ///
    /// Default: no-op.
    fn deselect(&mut self) {}

    /// Snapshot size for this applet's mutable state (bytes).
    ///
    /// Must return a constant value for a given applet type. The GP card
    /// pre-allocates snapshot buffers based on this size.
    fn snapshot_size(&self) -> usize;

    /// Save mutable state into `buf`. Returns bytes written.
    ///
    /// Must write exactly [`snapshot_size()`](Applet::snapshot_size) bytes.
    /// The serialization must be deterministic: identical state produces
    /// identical bytes.
    fn save_state(&self, buf: &mut [u8]) -> usize;

    /// Restore mutable state from `buf`. Returns `true` on success.
    ///
    /// `buf` contains data previously written by [`save_state`](Applet::save_state).
    /// Returns `false` if the buffer is too short or corrupted.
    fn restore_state(&mut self, buf: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct CounterApplet {
        count: u16,
    }

    impl CounterApplet {
        fn new() -> Self {
            Self { count: 0 }
        }
    }

    impl Applet for CounterApplet {
        fn process(&mut self, _cmd: &[u8], out: &mut [u8]) -> AppletResult {
            self.count = self.count.wrapping_add(1);
            if out.len() < 2 {
                return AppletResult::Sw(StatusWord::WrongLength);
            }
            let bytes = self.count.to_be_bytes();
            out[0] = bytes[0];
            out[1] = bytes[1];
            AppletResult::Ok(2)
        }

        fn snapshot_size(&self) -> usize {
            2
        }

        fn save_state(&self, buf: &mut [u8]) -> usize {
            let bytes = self.count.to_be_bytes();
            buf[0] = bytes[0];
            buf[1] = bytes[1];
            2
        }

        fn restore_state(&mut self, buf: &[u8]) -> bool {
            if buf.len() < 2 {
                return false;
            }
            self.count = u16::from_be_bytes([buf[0], buf[1]]);
            true
        }
    }

    #[test]
    fn applet_process_increments_counter() {
        let mut applet = CounterApplet::new();
        let mut out = [0u8; 4];
        let result = applet.process(&[], &mut out);
        assert_eq!(result, AppletResult::Ok(2));
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x01);

        let result = applet.process(&[], &mut out);
        assert_eq!(result, AppletResult::Ok(2));
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x02);
    }

    #[test]
    fn applet_select_default_accepts() {
        let mut applet = CounterApplet::new();
        let mut out = [0u8; 4];
        assert_eq!(applet.select(&mut out), AppletResult::Ok(0));
    }

    #[test]
    fn applet_snapshot_roundtrip() {
        let mut applet = CounterApplet::new();
        let mut out = [0u8; 4];

        // Increment to 5.
        for _ in 0..5 {
            applet.process(&[], &mut out);
        }
        assert_eq!(applet.count, 5);

        // Save.
        let mut snap = [0u8; 2];
        let written = applet.save_state(&mut snap);
        assert_eq!(written, 2);
        assert_eq!(snap, [0x00, 0x05]);

        // Restore into a new applet.
        let mut applet2 = CounterApplet::new();
        assert!(applet2.restore_state(&snap));
        assert_eq!(applet2.count, 5);

        // Next process increments from 5.
        applet2.process(&[], &mut out);
        assert_eq!(out[..2], [0x00, 0x06]);
    }

    #[test]
    fn applet_restore_rejects_short_buffer() {
        let mut applet = CounterApplet::new();
        assert!(!applet.restore_state(&[0x01]));
    }

    #[test]
    fn applet_process_small_buffer_returns_error() {
        let mut applet = CounterApplet::new();
        let mut out = [0u8; 1]; // too small for 2-byte response
        let result = applet.process(&[], &mut out);
        assert!(matches!(result, AppletResult::Sw(_)));
    }
}
