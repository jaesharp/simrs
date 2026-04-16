//! Transaction journal per JCRE 2.2.1 Chapter 7.
//!
//! Provides begin/commit/abort semantics for persistent heap writes.
//! The journal records `(heap_offset, old_byte)` pairs so that
//! `abort()` can roll back all writes within the transaction.
//!
//! # Security invariant
//!
//! PIN try counter decrements **bypass** the journal (JCRE 2.2.1 clause 7.7).
//! An `abortTransaction()` after a failed `PIN.check()` must NOT restore the
//! counter, preventing the Witteman (2003) unlimited-PIN-guesses attack.
//!
//! # Overflow defense
//!
//! Per JCRE 2.2.1 clause 7.6, writing more than `CAP` bytes within a single
//! transaction returns [`TransactionError::BufferFull`] without performing
//! the write (Hogenboom & Mostowski, WISSEC 2009 defense).

use crate::heap::ObjectHeap;

/// Error from a transaction operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    /// No transaction is active.
    NotActive,
    /// A transaction is already in progress.
    AlreadyActive,
    /// Transaction journal capacity exceeded (JCRE 2.2.1 clause 7.6).
    BufferFull,
}

/// Fixed-capacity transaction journal.
///
/// `CAP` is the maximum number of byte-level writes tracked per transaction.
pub struct TransactionJournal<const CAP: usize> {
    /// Journal entries: (heap byte offset, old byte value).
    entries: [(u16, u8); CAP],
    /// Number of entries used.
    count: u16,
    /// Whether a transaction is active.
    active: bool,
}

impl<const CAP: usize> TransactionJournal<CAP> {
    /// Create a new, inactive journal.
    pub const fn new() -> Self {
        Self {
            entries: [(0, 0); CAP],
            count: 0,
            active: false,
        }
    }

    /// Whether a transaction is currently active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Begin a new transaction.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::AlreadyActive`] if a transaction is in progress.
    pub const fn begin(&mut self) -> Result<(), TransactionError> {
        if self.active {
            return Err(TransactionError::AlreadyActive);
        }
        self.active = true;
        self.count = 0;
        Ok(())
    }

    /// Record a persistent write for potential rollback.
    ///
    /// Must be called **before** the actual write occurs, passing the
    /// current (old) byte value at the given heap offset.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::BufferFull`] if the journal is full.
    /// Returns [`TransactionError::NotActive`] if no transaction is active.
    pub const fn record_write(
        &mut self,
        heap_offset: u16,
        old_byte: u8,
    ) -> Result<(), TransactionError> {
        if !self.active {
            return Err(TransactionError::NotActive);
        }
        if self.count as usize >= CAP {
            return Err(TransactionError::BufferFull);
        }
        self.entries[self.count as usize] = (heap_offset, old_byte);
        self.count += 1;
        Ok(())
    }

    /// Commit the current transaction (discard journal, keep writes).
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::NotActive`] if no transaction is active.
    pub const fn commit(&mut self) -> Result<(), TransactionError> {
        if !self.active {
            return Err(TransactionError::NotActive);
        }
        self.active = false;
        self.count = 0;
        Ok(())
    }

    /// Abort the current transaction (roll back all recorded writes).
    ///
    /// Restores each recorded byte to its pre-transaction value in the heap.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::NotActive`] if no transaction is active.
    pub fn abort<const H: usize>(
        &mut self,
        heap: &mut ObjectHeap<H>,
    ) -> Result<(), TransactionError> {
        if !self.active {
            return Err(TransactionError::NotActive);
        }
        // Roll back in reverse order (most recent write first).
        for i in (0..self.count as usize).rev() {
            let (offset, old_byte) = self.entries[i];
            heap.raw_write(offset as usize, old_byte);
        }
        self.active = false;
        self.count = 0;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Snapshot support
    // -----------------------------------------------------------------------

    /// Snapshot size: active(1) + count(2) + entries(count * 3).
    pub const fn snapshot_size(&self) -> usize {
        1 + 2 + (self.count as usize) * 3
    }

    /// Maximum snapshot size.
    pub const MAX_SNAPSHOT_SIZE: usize = 1 + 2 + CAP * 3;

    /// Save journal state to buffer. Returns bytes written.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        let needed = self.snapshot_size();
        if buf.len() < needed {
            return 0;
        }
        buf[0] = u8::from(self.active);
        buf[1..3].copy_from_slice(&self.count.to_le_bytes());
        let mut off = 3;
        for i in 0..self.count as usize {
            let (offset, old_byte) = self.entries[i];
            buf[off..off + 2].copy_from_slice(&offset.to_le_bytes());
            buf[off + 2] = old_byte;
            off += 3;
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
            return false;
        }
        let mut off = 3;
        for i in 0..self.count as usize {
            if off + 3 > buf.len() {
                return false;
            }
            let offset = u16::from_le_bytes([buf[off], buf[off + 1]]);
            let old_byte = buf[off + 2];
            self.entries[i] = (offset, old_byte);
            off += 3;
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
    fn begin_commit_cycle() {
        let mut journal = TransactionJournal::<64>::new();
        assert!(!journal.is_active());
        assert!(journal.begin().is_ok());
        assert!(journal.is_active());
        assert!(journal.commit().is_ok());
        assert!(!journal.is_active());
    }

    #[test]
    fn begin_twice_errors() {
        let mut journal = TransactionJournal::<64>::new();
        assert!(journal.begin().is_ok());
        assert_eq!(journal.begin(), Err(TransactionError::AlreadyActive));
    }

    #[test]
    fn commit_without_begin_errors() {
        let mut journal = TransactionJournal::<64>::new();
        assert_eq!(journal.commit(), Err(TransactionError::NotActive));
    }

    #[test]
    fn abort_rolls_back_writes() {
        let mut heap = ObjectHeap::<256>::new();
        let arr = heap.alloc_byte_array(0, 4).unwrap();

        // Write some data.
        let _ = heap.bastore(arr, 0, 0xAA, 0);
        let _ = heap.bastore(arr, 1, 0xBB, 0);

        let mut journal = TransactionJournal::<64>::new();
        journal.begin().unwrap();

        // Record old values before overwriting.
        let off0 = heap.array_element_offset(arr, 0, 1).unwrap();
        let off1 = heap.array_element_offset(arr, 1, 1).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        journal
            .record_write(off0 as u16, heap.raw_read(off0).unwrap())
            .unwrap();
        #[allow(clippy::cast_possible_truncation)]
        journal
            .record_write(off1 as u16, heap.raw_read(off1).unwrap())
            .unwrap();

        // Overwrite.
        let _ = heap.bastore(arr, 0, 0x11, 0);
        let _ = heap.bastore(arr, 1, 0x22, 0);
        assert_eq!(heap.baload(arr, 0, 0).unwrap(), 0x11);
        assert_eq!(heap.baload(arr, 1, 0).unwrap(), 0x22);

        // Abort: should restore to 0xAA, 0xBB.
        journal.abort(&mut heap).unwrap();
        assert_eq!(heap.baload(arr, 0, 0).unwrap(), 0xAA);
        assert_eq!(heap.baload(arr, 1, 0).unwrap(), 0xBB);
    }

    #[test]
    fn buffer_full_rejects_write() {
        let mut journal = TransactionJournal::<2>::new();
        journal.begin().unwrap();
        assert!(journal.record_write(10, 0).is_ok());
        assert!(journal.record_write(11, 0).is_ok());
        assert_eq!(
            journal.record_write(12, 0),
            Err(TransactionError::BufferFull)
        );
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut journal = TransactionJournal::<64>::new();
        journal.begin().unwrap();
        journal.record_write(100, 0xDE).unwrap();
        journal.record_write(200, 0xAD).unwrap();

        let mut buf = [0u8; TransactionJournal::<64>::MAX_SNAPSHOT_SIZE];
        let n = journal.save_state(&mut buf);
        assert!(n > 0);

        let mut j2 = TransactionJournal::<64>::new();
        assert!(j2.restore_state(&buf[..n]));
        assert!(j2.is_active());
    }
}
