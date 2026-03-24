//! Transient memory arrays per [JC RE 2.1.1 Chapter 5](../../../../telecom-standards/javacard/2.1.1/JCRESpec.pdf).
//!
//! `JavaCard` defines two transient memory tiers that are NOT included in
//! snapshots and are automatically cleared on specific events:
//!
//! - [`TransientResetArray`]: cleared on card reset (cold or warm)
//! - [`TransientDeselectArray`]: cleared on applet deselection (which also
//!   happens during reset, since reset deselects all applets)
//!
//! # Key Properties (JC RE 2.1.1 clause 5)
//!
//! - Only the *contents* are transient; the object reference itself persists.
//! - Transient arrays are never written to EEPROM (security requirement).
//! - Transient arrays are NOT affected by transactions (JC RE 2.1.1 clause 7.7):
//!   `abortTransaction()` does NOT roll back transient field updates.

/// Transient memory cleared on card reset.
///
/// Used for session-scoped data that should survive applet deselection
/// but not card power-cycle. Examples: cached computations, session flags.
///
/// # `no_std`
/// Fixed-size, stack-allocated. Not included in snapshots.
pub struct TransientResetArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> TransientResetArray<N> {
    /// Create a new zero-initialized transient array.
    pub const fn new() -> Self {
        Self { data: [0u8; N] }
    }

    /// Get the array contents.
    pub const fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable access to the array contents.
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Read a byte at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= N`.
    pub const fn get(&self, index: usize) -> u8 {
        self.data[index]
    }

    /// Write a byte at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= N`.
    pub const fn set(&mut self, index: usize, value: u8) {
        self.data[index] = value;
    }

    /// Clear all bytes to zero. Called by the JCRE on card reset.
    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    /// Length of the array.
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether the array is empty.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> Default for TransientResetArray<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Transient memory cleared on applet deselection.
///
/// Used for data that should only exist while the applet is selected.
/// Examples: authentication session state, temporary keys, challenge values.
///
/// Also cleared on card reset (since reset implies deselection of all applets).
///
/// # `no_std`
/// Fixed-size, stack-allocated. Not included in snapshots.
pub struct TransientDeselectArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> TransientDeselectArray<N> {
    /// Create a new zero-initialized transient array.
    pub const fn new() -> Self {
        Self { data: [0u8; N] }
    }

    /// Get the array contents.
    pub const fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable access to the array contents.
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Read a byte at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= N`.
    pub const fn get(&self, index: usize) -> u8 {
        self.data[index]
    }

    /// Write a byte at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= N`.
    pub const fn set(&mut self, index: usize, value: u8) {
        self.data[index] = value;
    }

    /// Clear all bytes to zero. Called by the JCRE on applet deselection and card reset.
    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    /// Length of the array.
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether the array is empty.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> Default for TransientDeselectArray<N> {
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
    fn transient_reset_new_is_zero() {
        let arr = TransientResetArray::<8>::new();
        assert_eq!(arr.as_slice(), &[0u8; 8]);
    }

    #[test]
    fn transient_reset_set_get() {
        let mut arr = TransientResetArray::<4>::new();
        arr.set(0, 0xAA);
        arr.set(3, 0xBB);
        assert_eq!(arr.get(0), 0xAA);
        assert_eq!(arr.get(1), 0x00);
        assert_eq!(arr.get(3), 0xBB);
    }

    #[test]
    fn transient_reset_clear() {
        let mut arr = TransientResetArray::<4>::new();
        arr.as_mut_slice().fill(0xFF);
        assert_eq!(arr.as_slice(), &[0xFF; 4]);
        arr.clear();
        assert_eq!(arr.as_slice(), &[0u8; 4]);
    }

    #[test]
    fn transient_deselect_new_is_zero() {
        let arr = TransientDeselectArray::<8>::new();
        assert_eq!(arr.as_slice(), &[0u8; 8]);
    }

    #[test]
    fn transient_deselect_clear() {
        let mut arr = TransientDeselectArray::<4>::new();
        arr.as_mut_slice().fill(0xFF);
        arr.clear();
        assert_eq!(arr.as_slice(), &[0u8; 4]);
    }

    #[test]
    fn transient_len_and_empty() {
        let arr = TransientResetArray::<8>::new();
        assert_eq!(arr.len(), 8);
        assert!(!arr.is_empty());

        let empty = TransientResetArray::<0>::new();
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }
}
