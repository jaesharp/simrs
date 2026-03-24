//! Transaction mechanism per [JC RE 2.1.1 Chapter 7](../../../../telecom-standards/javacard/2.1.1/JCRESpec.pdf).
//!
//! Provides atomic multi-field updates with rollback. The [`TransactionJournal`]
//! records byte-level writes during a transaction. On commit, the journal is
//! discarded. On abort (or power loss), the journal is replayed in reverse to
//! restore the previous state.
//!
//! # Key Properties (JC RE 2.1.1 clauses 7.1-7.9)
//!
//! - **No nesting** (clause 7.4): `begin_transaction()` while a transaction is
//!   active returns [`TransactionError::AlreadyInProgress`].
//! - **Auto-abort** (clause 7.6.2): if an applet returns from `process()`/`select()`
//!   with a transaction in progress, the JCRE auto-aborts it.
//! - **Transients excluded** (clause 7.7): transient object updates are NOT
//!   rolled back on abort.
//! - **Commit capacity** (clause 7.8): finite, determined by JCOP transaction
//!   buffer size (512 bytes for JCOP10/20/21, 768 bytes for JCOP21id/31bio).
//!
//! # Snapshot
//!
//! The journal itself is persistent (survives power loss for rollback).
//! It is included in snapshots so that a snapshot taken mid-transaction
//! can be restored and the transaction correctly aborted.

/// Error from transaction operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    /// `begin_transaction()` called while a transaction is already active.
    AlreadyInProgress,
    /// No transaction is active (for `commit`/`abort`).
    NotInProgress,
    /// Transaction journal is full (commit capacity exceeded).
    JournalFull,
}

/// A single entry in the transaction journal.
///
/// Records a byte-level write: the buffer offset, the old value (for rollback),
/// and the new value (for replay).
#[derive(Clone, Copy)]
struct JournalEntry {
    /// Offset into the persistent buffer where the write occurred.
    offset: u16,
    /// Previous value at this offset (for rollback on abort).
    old_value: u8,
}

/// Transaction journal for atomic multi-field updates.
///
/// `CAP` is the maximum number of byte-level writes that can be recorded
/// in a single transaction. This maps to the JCOP transaction buffer size:
/// - JCOP10/20/21: `CAP = 512`
/// - JCOP21id/31bio: `CAP = 768`
///
/// # Usage
///
/// ```
/// use simrs_jcre::TransactionJournal;
///
/// let mut journal = TransactionJournal::<512>::new();
/// assert!(!journal.is_active());
/// assert_eq!(journal.depth(), 0);
/// ```
pub struct TransactionJournal<const CAP: usize> {
    /// Journal entries recording each byte-level write.
    entries: [JournalEntry; CAP],
    /// Number of entries currently in the journal.
    count: u16,
    /// Whether a transaction is currently active.
    active: bool,
}

impl<const CAP: usize> TransactionJournal<CAP> {
    /// Create a new empty transaction journal.
    pub const fn new() -> Self {
        Self {
            entries: [JournalEntry {
                offset: 0,
                old_value: 0,
            }; CAP],
            count: 0,
            active: false,
        }
    }

    /// Begin a new transaction.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::AlreadyInProgress`] if a transaction is already active
    /// (JC RE 2.1.1 clause 7.4: no nesting).
    pub const fn begin_transaction(&mut self) -> Result<(), TransactionError> {
        if self.active {
            return Err(TransactionError::AlreadyInProgress);
        }
        self.active = true;
        self.count = 0;
        Ok(())
    }

    /// Commit the current transaction.
    ///
    /// All conditional writes become permanent. The journal is cleared.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::NotInProgress`] if no transaction is active.
    pub const fn commit_transaction(&mut self) -> Result<(), TransactionError> {
        if !self.active {
            return Err(TransactionError::NotInProgress);
        }
        self.active = false;
        self.count = 0;
        Ok(())
    }

    /// Abort the current transaction.
    ///
    /// Replays the journal in reverse to restore all modified bytes to their
    /// previous values in `persistent_buf`.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::NotInProgress`] if no transaction is active.
    pub fn abort_transaction(&mut self, persistent_buf: &mut [u8]) -> Result<(), TransactionError> {
        if !self.active {
            return Err(TransactionError::NotInProgress);
        }
        // Replay in reverse order to restore previous values.
        let mut i = self.count;
        while i > 0 {
            i -= 1;
            let entry = self.entries[i as usize];
            if (entry.offset as usize) < persistent_buf.len() {
                persistent_buf[entry.offset as usize] = entry.old_value;
            }
        }
        self.active = false;
        self.count = 0;
        Ok(())
    }

    /// Record a byte-level write during an active transaction.
    ///
    /// Call this BEFORE modifying the persistent buffer. It records the
    /// old value for potential rollback.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::JournalFull`] if the journal capacity is exceeded.
    /// Returns [`TransactionError::NotInProgress`] if no transaction is active.
    pub const fn record_write(
        &mut self,
        offset: u16,
        old_value: u8,
    ) -> Result<(), TransactionError> {
        if !self.active {
            return Err(TransactionError::NotInProgress);
        }
        if self.count as usize >= CAP {
            return Err(TransactionError::JournalFull);
        }
        self.entries[self.count as usize] = JournalEntry { offset, old_value };
        self.count += 1;
        Ok(())
    }

    /// Whether a transaction is currently active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Transaction depth: 0 (no transaction) or 1 (transaction active).
    ///
    /// Per JC RE 2.1.1 clause 7.4: nesting is not supported.
    pub const fn depth(&self) -> u8 {
        if self.active {
            1
        } else {
            0
        }
    }

    /// Number of journal entries recorded in the current transaction.
    pub const fn entry_count(&self) -> u16 {
        self.count
    }

    /// Remaining capacity (bytes that can still be recorded).
    pub const fn remaining(&self) -> usize {
        CAP - self.count as usize
    }

    // -----------------------------------------------------------------------
    // Snapshot support
    // -----------------------------------------------------------------------

    /// Snapshot size: active flag + count + entries.
    pub const SNAPSHOT_SIZE: usize = 1 + 2 + CAP * 3;

    /// Save journal state to buffer. Returns bytes written.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        let mut off = 0;
        buf[off] = u8::from(self.active);
        off += 1;
        buf[off..off + 2].copy_from_slice(&self.count.to_le_bytes());
        off += 2;
        for i in 0..self.count as usize {
            let entry = self.entries[i];
            buf[off..off + 2].copy_from_slice(&entry.offset.to_le_bytes());
            off += 2;
            buf[off] = entry.old_value;
            off += 1;
        }
        off
    }

    /// Restore journal state from buffer. Returns success.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < 3 {
            return false;
        }
        self.active = buf[0] != 0;
        self.count = u16::from_le_bytes([buf[1], buf[2]]);
        if self.count as usize > CAP {
            self.count = 0;
            self.active = false;
            return false;
        }
        let mut off = 3;
        for i in 0..self.count as usize {
            if off + 3 > buf.len() {
                self.count = 0;
                self.active = false;
                return false;
            }
            let offset = u16::from_le_bytes([buf[off], buf[off + 1]]);
            off += 2;
            let old_value = buf[off];
            off += 1;
            self.entries[i] = JournalEntry { offset, old_value };
        }
        true
    }
}

impl<const CAP: usize> Default for TransactionJournal<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_journal_is_inactive() {
        let j = TransactionJournal::<512>::new();
        assert!(!j.is_active());
        assert_eq!(j.depth(), 0);
        assert_eq!(j.entry_count(), 0);
        assert_eq!(j.remaining(), 512);
    }

    #[test]
    fn begin_commit_lifecycle() {
        let mut j = TransactionJournal::<512>::new();
        assert!(j.begin_transaction().is_ok());
        assert!(j.is_active());
        assert_eq!(j.depth(), 1);
        assert!(j.commit_transaction().is_ok());
        assert!(!j.is_active());
        assert_eq!(j.depth(), 0);
    }

    #[test]
    fn no_nesting() {
        let mut j = TransactionJournal::<512>::new();
        assert!(j.begin_transaction().is_ok());
        assert_eq!(
            j.begin_transaction(),
            Err(TransactionError::AlreadyInProgress)
        );
    }

    #[test]
    fn commit_without_begin_errors() {
        let mut j = TransactionJournal::<512>::new();
        assert_eq!(j.commit_transaction(), Err(TransactionError::NotInProgress));
    }

    #[test]
    fn abort_without_begin_errors() {
        let mut j = TransactionJournal::<512>::new();
        let mut buf = [0u8; 8];
        assert_eq!(
            j.abort_transaction(&mut buf),
            Err(TransactionError::NotInProgress)
        );
    }

    #[test]
    fn record_and_abort_restores_values() {
        let mut j = TransactionJournal::<512>::new();
        let mut persistent = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let original = persistent;

        j.begin_transaction().unwrap();

        // Record writes at offsets 2 and 5.
        j.record_write(2, persistent[2]).unwrap();
        persistent[2] = 0xAA;
        j.record_write(5, persistent[5]).unwrap();
        persistent[5] = 0xBB;

        // Persistent buffer is modified.
        assert_eq!(persistent[2], 0xAA);
        assert_eq!(persistent[5], 0xBB);

        // Abort restores original values.
        j.abort_transaction(&mut persistent).unwrap();
        assert_eq!(persistent, original);
    }

    #[test]
    fn commit_makes_changes_permanent() {
        let mut j = TransactionJournal::<512>::new();
        let mut persistent = [0x00; 4];

        j.begin_transaction().unwrap();
        j.record_write(0, persistent[0]).unwrap();
        persistent[0] = 0xFF;
        j.commit_transaction().unwrap();

        // After commit, the value stays changed.
        assert_eq!(persistent[0], 0xFF);

        // New abort has nothing to undo.
        j.begin_transaction().unwrap();
        j.abort_transaction(&mut persistent).unwrap();
        assert_eq!(persistent[0], 0xFF); // still 0xFF
    }

    #[test]
    fn journal_full() {
        let mut j = TransactionJournal::<4>::new();
        j.begin_transaction().unwrap();
        for i in 0..4u16 {
            assert!(j.record_write(i, 0).is_ok());
        }
        assert_eq!(j.remaining(), 0);
        assert_eq!(j.record_write(4, 0), Err(TransactionError::JournalFull));
    }

    #[test]
    fn record_without_transaction_errors() {
        let mut j = TransactionJournal::<512>::new();
        assert_eq!(j.record_write(0, 0), Err(TransactionError::NotInProgress));
    }

    #[test]
    fn snapshot_roundtrip_empty() {
        let j = TransactionJournal::<512>::new();
        let mut buf = [0u8; TransactionJournal::<512>::SNAPSHOT_SIZE];
        let written = j.save_state(&mut buf);

        let mut j2 = TransactionJournal::<512>::new();
        assert!(j2.restore_state(&buf[..written]));
        assert!(!j2.is_active());
        assert_eq!(j2.entry_count(), 0);
    }

    #[test]
    fn snapshot_roundtrip_active_transaction() {
        let mut j = TransactionJournal::<512>::new();
        j.begin_transaction().unwrap();
        j.record_write(10, 0xAA).unwrap();
        j.record_write(20, 0xBB).unwrap();

        let mut buf = [0u8; TransactionJournal::<512>::SNAPSHOT_SIZE];
        let written = j.save_state(&mut buf);

        let mut j2 = TransactionJournal::<512>::new();
        assert!(j2.restore_state(&buf[..written]));
        assert!(j2.is_active());
        assert_eq!(j2.entry_count(), 2);

        // Abort should replay the 2 entries.
        let mut persistent = [0u8; 32];
        persistent[10] = 0xFF; // modified value
        persistent[20] = 0xFF; // modified value
        j2.abort_transaction(&mut persistent).unwrap();
        assert_eq!(persistent[10], 0xAA); // restored
        assert_eq!(persistent[20], 0xBB); // restored
    }

    #[test]
    fn snapshot_rejects_invalid() {
        let mut j = TransactionJournal::<4>::new();
        // Empty buffer.
        assert!(!j.restore_state(&[]));
        // Count exceeds capacity.
        assert!(!j.restore_state(&[0, 5, 0])); // count=5 > CAP=4
                                               // Short data for declared count.
        assert!(!j.restore_state(&[0, 2, 0, 0x0A, 0x00])); // 2 entries declared, only 1 partial
    }

    #[test]
    fn abort_replays_in_reverse_order() {
        let mut j = TransactionJournal::<512>::new();
        let mut persistent = [0x00; 4];

        j.begin_transaction().unwrap();

        // Write offset 0 twice with different old values.
        j.record_write(0, persistent[0]).unwrap(); // old = 0x00
        persistent[0] = 0x11;
        j.record_write(0, persistent[0]).unwrap(); // old = 0x11
        persistent[0] = 0x22;

        // Abort: reverse replay -> first restore 0x11, then restore 0x00.
        j.abort_transaction(&mut persistent).unwrap();
        assert_eq!(persistent[0], 0x00); // restored to original
    }
}
