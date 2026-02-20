//! PIN/PUK management state machine.
//!
//! Implements the PIN lifecycle per ETSI TS 102 221: verify, change,
//! disable, enable, and unblock (reset retry counter). Each PIN slot
//! tracks its value, retry counter, enabled/disabled flag, and session
//! verification state. Each slot also holds an associated PUK with its
//! own retry counter for unblock operations.
//!
//! The manager is generic over `N`, the maximum number of PIN slots.
//! Typical usage: `PinManager<5>` for PIN1, PIN2, ADM1, ADM2, Universal.
//!
//! # State Machine
//!
//! ```text
//!  Disabled ──ENABLE(correct)──> Enabled+Unverified
//!     ^                            │        │
//!     │                        VERIFY(ok)  VERIFY(wrong, n>0)
//!     │                            v        │
//!  DISABLE(correct)         Enabled+Verified │
//!     │                            │        │
//!     └────────────────────────────┘  VERIFY(wrong, n=0)
//!                                           v
//!                                        Blocked
//!                                           │
//!                                    UNBLOCK(correct PUK)
//!                                           v
//!                                   Enabled+Unverified
//! ```
//!
//! # Standards
//! - ETSI TS 102 221 V16.4.0 clause 11.1.9 -- VERIFY PIN
//! - ETSI TS 102 221 V16.4.0 clause 11.1.10 -- CHANGE REFERENCE DATA
//! - ETSI TS 102 221 V16.4.0 clause 11.1.11 -- DISABLE VERIFICATION REQUIREMENT
//! - ETSI TS 102 221 V16.4.0 clause 11.1.12 -- ENABLE VERIFICATION REQUIREMENT
//! - ETSI TS 102 221 V16.4.0 clause 11.1.13 -- RESET RETRY COUNTER
//! - 3GPP TS 31.102 V17.5.0 clause 6.2 -- PIN management
//!
//! # `no_std`, `no_alloc`
//! This crate uses no heap.
//!
//! # Example
//!
//! ```
//! use simrs_pin::{PinManager, PinKey, PinValue, PinResult};
//!
//! let mut mgr = PinManager::<5>::new();
//! let pin1 = PinKey(0x01);
//! let pin_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
//! let puk_val = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
//!
//! mgr.add_pin(pin1, &pin_val, 3, &puk_val, 10, true).unwrap();
//!
//! // Wrong PIN decrements counter
//! let wrong = PinValue::new([0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF]);
//! assert!(matches!(mgr.verify(pin1, &wrong), PinResult::WrongPin { retries_remaining: 2 }));
//!
//! // Correct PIN resets counter and marks verified
//! assert!(matches!(mgr.verify(pin1, &pin_val), PinResult::Success));
//! assert!(mgr.is_verified(pin1));
//! assert_eq!(mgr.retries(pin1), Some(3));
//! ```
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// PIN key reference per ETSI TS 102 221 Table 9.3.
///
/// Common values:
/// - `0x01`: PIN Appl 1 (global)
/// - `0x81`: PIN Appl 1 (local / second)
/// - `0x02`: PIN Appl 2
/// - `0x0A`: ADM1
/// - `0x0B`: ADM2
/// - `0x11`: Universal PIN
///
/// # Example
///
/// ```
/// use simrs_pin::PinKey;
/// let pin1 = PinKey(0x01);
/// let pin2 = PinKey(0x81);
/// assert_ne!(pin1, pin2);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinKey(pub u8);

/// 8-byte PIN or PUK value, ASCII-encoded digits padded with `0xFF`.
///
/// Per ETSI TS 102 221, PIN values are 4--8 ASCII digit characters
/// (`0x30`--`0x39`), right-padded with `0xFF` to fill 8 bytes.
///
/// # Example
///
/// ```
/// use simrs_pin::PinValue;
/// // PIN "1234" in ASCII encoding
/// let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
/// assert_eq!(pin.len, 4);
/// assert_eq!(pin.bytes[0], 0x31); // ASCII '1'
/// ```
#[derive(Clone, Copy, Debug)]
pub struct PinValue {
    /// Raw 8-byte encoding: ASCII digits followed by `0xFF` padding.
    pub bytes: [u8; 8],
    /// Number of significant (non-padding) bytes, 0--8.
    pub len: u8,
}

impl PinValue {
    /// An empty PIN value (all `0xFF`).
    pub const EMPTY: Self = Self {
        bytes: [0xFF; 8],
        len: 0,
    };

    /// Create a PIN value from raw 8-byte encoding.
    ///
    /// Computes `len` automatically as the index of the first `0xFF` byte.
    /// If no `0xFF` appears, `len` is 8.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_pin::PinValue;
    /// let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    /// assert_eq!(pin.len, 8);
    /// ```
    #[allow(clippy::cast_possible_truncation)] // i is always 0..8
    pub const fn new(bytes: [u8; 8]) -> Self {
        let mut len = 8u8;
        let mut i = 0;
        while i < 8 {
            if bytes[i] == 0xFF {
                len = i as u8;
                break;
            }
            i += 1;
        }
        Self { bytes, len }
    }
}

impl PartialEq for PinValue {
    fn eq(&self, other: &Self) -> bool {
        // Compare full 8-byte encoding; properly padded PINs match iff digits match.
        self.bytes == other.bytes
    }
}

impl Eq for PinValue {}

/// Result of a PIN operation.
///
/// Maps to ISO/IEC 7816-4 status words in the upper layer:
/// - `Success` -> `90 00`
/// - `WrongPin { n }` -> `63 C{n}`
/// - `Blocked` -> `69 83`
/// - `Disabled` -> `69 84` (referenced data reversibly blocked)
/// - `NotFound` -> `6A 88` (referenced data not found)
///
/// # Example
///
/// ```
/// use simrs_pin::PinResult;
/// let r = PinResult::WrongPin { retries_remaining: 2 };
/// assert_eq!(r, PinResult::WrongPin { retries_remaining: 2 });
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinResult {
    /// Operation succeeded.
    Success,
    /// Wrong PIN/PUK value; `retries_remaining` may be 0 (just became blocked).
    WrongPin {
        /// Retries left after this failed attempt.
        retries_remaining: u8,
    },
    /// PIN is blocked (retry counter was already 0 before this attempt).
    Blocked,
    /// PIN is disabled; verification requirement not active.
    Disabled,
    /// No PIN configured for this key reference.
    NotFound,
}

/// Configuration error when adding a PIN slot.
///
/// # Example
///
/// ```
/// use simrs_pin::{PinManager, PinKey, PinValue, PinError};
/// let mut mgr = PinManager::<1>::new();
/// let k = PinKey(0x01);
/// let v = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
/// mgr.add_pin(k, &v, 3, &v, 10, true).unwrap();
/// assert_eq!(mgr.add_pin(k, &v, 3, &v, 10, true), Err(PinError::DuplicateKey));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinError {
    /// A PIN with this key reference already exists.
    DuplicateKey,
    /// All `N` slots are occupied.
    SlotsFull,
}

// ---------------------------------------------------------------------------
// Internal slot
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PinSlot {
    key: u8,
    pin: [u8; 8],
    pin_retries: u8,
    pin_max: u8,
    puk: [u8; 8],
    puk_retries: u8,
    enabled: bool,
    /// Session-level verification flag.
    ///
    /// Access externally via [`PinManager::is_verified`], which also returns
    /// `true` when `enabled == false` (disabled PINs satisfy the security
    /// condition automatically per ETSI TS 102 221 clause 11.1.11).
    verified: bool,
}

impl PinSlot {
    const EMPTY: Self = Self {
        key: 0,
        pin: [0xFF; 8],
        pin_retries: 0,
        pin_max: 0,
        puk: [0xFF; 8],
        puk_retries: 0,
        enabled: false,
        verified: false,
    };
}

// ---------------------------------------------------------------------------
// PinManager
// ---------------------------------------------------------------------------

/// PIN/PUK management state machine with `N` slots.
///
/// Manages PIN verification, change, enable/disable, and PUK-based unblock.
/// Each slot holds a PIN value + retry counter and an associated PUK value +
/// retry counter.
///
/// # Example
///
/// ```
/// use simrs_pin::{PinManager, PinKey, PinValue, PinResult};
///
/// let mut mgr = PinManager::<2>::new();
/// let pin1 = PinKey(0x01);
/// let pin2 = PinKey(0x81);
/// let v1 = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
/// let v2 = PinValue::new([0x34, 0x33, 0x32, 0x31, 0xFF, 0xFF, 0xFF, 0xFF]);
/// let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
///
/// mgr.add_pin(pin1, &v1, 3, &puk, 10, true).unwrap();
/// mgr.add_pin(pin2, &v2, 3, &puk, 10, true).unwrap();
///
/// // PINs are independent
/// assert!(matches!(mgr.verify(pin1, &v1), PinResult::Success));
/// assert!(!mgr.is_verified(pin2));
/// ```
pub struct PinManager<const N: usize> {
    slots: [PinSlot; N],
    count: u8,
}

impl<const N: usize> Default for PinManager<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PinManager<N> {
    /// Create an empty PIN manager with no configured slots.
    ///
    /// # Panics
    ///
    /// Compile-time panic if `N > 255` (internal counter is `u8`).
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_pin::{PinManager, PinKey};
    /// let mgr = PinManager::<5>::new();
    /// assert_eq!(mgr.retries(PinKey(0x01)), None);
    /// ```
    pub const fn new() -> Self {
        assert!(N <= 255, "PinManager: N must be <= 255 (count is u8)");
        Self {
            slots: [PinSlot::EMPTY; N],
            count: 0,
        }
    }

    /// Configure a new PIN slot.
    ///
    /// # Errors
    ///
    /// - [`PinError::DuplicateKey`] if `key` is already configured.
    /// - [`PinError::SlotsFull`] if all `N` slots are occupied.
    pub const fn add_pin(
        &mut self,
        key: PinKey,
        pin: &PinValue,
        pin_max_retries: u8,
        puk: &PinValue,
        puk_max_retries: u8,
        enabled: bool,
    ) -> Result<(), PinError> {
        // Reject duplicates.
        let mut i = 0;
        while i < self.count as usize {
            if self.slots[i].key == key.0 {
                return Err(PinError::DuplicateKey);
            }
            i += 1;
        }
        if self.count as usize >= N {
            return Err(PinError::SlotsFull);
        }
        let idx = self.count as usize;
        self.slots[idx] = PinSlot {
            key: key.0,
            pin: pin.bytes,
            pin_retries: pin_max_retries,
            pin_max: pin_max_retries,
            puk: puk.bytes,
            puk_retries: puk_max_retries,
            enabled,
            verified: false,
        };
        self.count += 1;
        Ok(())
    }

    /// Verify a PIN value.
    ///
    /// Per ETSI TS 102 221 clause 11.1.9:
    /// - Correct PIN: counter reset to max, verified flag set.
    /// - Wrong PIN: counter decremented; returns remaining retries.
    /// - Already blocked (counter = 0): returns [`PinResult::Blocked`].
    /// - PIN disabled: returns [`PinResult::Disabled`].
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_pin::{PinManager, PinKey, PinValue, PinResult};
    /// let mut mgr = PinManager::<1>::new();
    /// let k = PinKey(0x01);
    /// let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
    /// let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    /// mgr.add_pin(k, &pin, 3, &puk, 10, true).unwrap();
    ///
    /// assert!(matches!(mgr.verify(k, &pin), PinResult::Success));
    /// assert!(mgr.is_verified(k));
    /// ```
    pub fn verify(&mut self, key: PinKey, val: &PinValue) -> PinResult {
        let Some(idx) = self.find_index(key) else {
            return PinResult::NotFound;
        };
        let slot = &mut self.slots[idx];
        if !slot.enabled {
            return PinResult::Disabled;
        }
        if slot.pin_retries == 0 {
            return PinResult::Blocked;
        }
        if slot.pin == val.bytes {
            slot.pin_retries = slot.pin_max;
            slot.verified = true;
            PinResult::Success
        } else {
            slot.pin_retries -= 1;
            slot.verified = false;
            PinResult::WrongPin {
                retries_remaining: slot.pin_retries,
            }
        }
    }

    /// Change a PIN value.
    ///
    /// Per ETSI TS 102 221 clause 11.1.10: old PIN must be correct.
    /// On success the PIN value is replaced and the retry counter is reset.
    /// The verified flag is **not** set (CHANGE does not satisfy the
    /// security condition).
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_pin::{PinManager, PinKey, PinValue, PinResult};
    /// let mut mgr = PinManager::<1>::new();
    /// let k = PinKey(0x01);
    /// let old = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
    /// let new = PinValue::new([0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
    /// let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    /// mgr.add_pin(k, &old, 3, &puk, 10, true).unwrap();
    ///
    /// assert!(matches!(mgr.change(k, &old, &new), PinResult::Success));
    /// assert!(matches!(mgr.verify(k, &new), PinResult::Success));
    /// ```
    pub fn change(&mut self, key: PinKey, old: &PinValue, new_pin: &PinValue) -> PinResult {
        let Some(idx) = self.find_index(key) else {
            return PinResult::NotFound;
        };
        let slot = &mut self.slots[idx];
        // CHANGE is permitted on disabled PINs per ETSI TS 102 221 clause 11.1.10
        // (no explicit restriction on disabled state). This allows administrative
        // value rotation without re-enabling the PIN.
        if slot.pin_retries == 0 {
            return PinResult::Blocked;
        }
        if slot.pin != old.bytes {
            slot.pin_retries -= 1;
            return PinResult::WrongPin {
                retries_remaining: slot.pin_retries,
            };
        }
        slot.pin = new_pin.bytes;
        slot.pin_retries = slot.pin_max;
        // CHANGE does not set verified.
        PinResult::Success
    }

    /// Disable PIN verification requirement.
    ///
    /// Per ETSI TS 102 221 clause 11.1.11: current PIN must be correct.
    /// After disabling, the security condition is automatically satisfied.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_pin::{PinManager, PinKey, PinValue, PinResult};
    /// let mut mgr = PinManager::<1>::new();
    /// let k = PinKey(0x01);
    /// let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
    /// let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    /// mgr.add_pin(k, &pin, 3, &puk, 10, true).unwrap();
    ///
    /// assert!(matches!(mgr.disable(k, &pin), PinResult::Success));
    /// assert!(!mgr.is_enabled(k));
    /// assert!(mgr.is_verified(k)); // disabled => condition satisfied
    /// ```
    pub fn disable(&mut self, key: PinKey, val: &PinValue) -> PinResult {
        let Some(idx) = self.find_index(key) else {
            return PinResult::NotFound;
        };
        let slot = &mut self.slots[idx];
        if !slot.enabled {
            return PinResult::Disabled;
        }
        if slot.pin_retries == 0 {
            return PinResult::Blocked;
        }
        if slot.pin != val.bytes {
            slot.pin_retries -= 1;
            return PinResult::WrongPin {
                retries_remaining: slot.pin_retries,
            };
        }
        slot.pin_retries = slot.pin_max;
        slot.enabled = false;
        slot.verified = false;
        PinResult::Success
    }

    /// Enable PIN verification requirement.
    ///
    /// Per ETSI TS 102 221 clause 11.1.12: current PIN must be correct.
    /// After enabling, the PIN is in the unverified state.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_pin::{PinManager, PinKey, PinValue, PinResult};
    /// let mut mgr = PinManager::<1>::new();
    /// let k = PinKey(0x01);
    /// let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
    /// let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    /// mgr.add_pin(k, &pin, 3, &puk, 10, false).unwrap(); // starts disabled
    ///
    /// assert!(matches!(mgr.enable(k, &pin), PinResult::Success));
    /// assert!(mgr.is_enabled(k));
    /// assert!(!mgr.is_verified(k)); // must VERIFY separately
    /// ```
    pub fn enable(&mut self, key: PinKey, val: &PinValue) -> PinResult {
        let Some(idx) = self.find_index(key) else {
            return PinResult::NotFound;
        };
        let slot = &mut self.slots[idx];
        if slot.pin_retries == 0 {
            return PinResult::Blocked;
        }
        if slot.enabled {
            return PinResult::Success;
        }
        if slot.pin != val.bytes {
            slot.pin_retries -= 1;
            return PinResult::WrongPin {
                retries_remaining: slot.pin_retries,
            };
        }
        slot.pin_retries = slot.pin_max;
        slot.enabled = true;
        slot.verified = false;
        PinResult::Success
    }

    /// Unblock a PIN using the associated PUK.
    ///
    /// Per ETSI TS 102 221 clause 11.1.13: verifies the PUK, sets a new
    /// PIN value, and resets the PIN retry counter. The PUK counter is
    /// **not** reset on success (per spec). On PUK failure the PUK counter
    /// is decremented; when exhausted the PIN is permanently blocked.
    ///
    /// # Example
    ///
    /// ```
    /// use simrs_pin::{PinManager, PinKey, PinValue, PinResult};
    /// let mut mgr = PinManager::<1>::new();
    /// let k = PinKey(0x01);
    /// let pin = PinValue::new([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF]);
    /// let puk = PinValue::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);
    /// mgr.add_pin(k, &pin, 3, &puk, 10, true).unwrap();
    ///
    /// // Block the PIN
    /// for _ in 0..3 { mgr.verify(k, &PinValue::EMPTY); }
    /// assert!(mgr.is_blocked(k));
    ///
    /// // Unblock with correct PUK
    /// let new_pin = PinValue::new([0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF]);
    /// assert!(matches!(mgr.unblock(k, &puk, &new_pin), PinResult::Success));
    /// assert_eq!(mgr.retries(k), Some(3));
    /// assert!(matches!(mgr.verify(k, &new_pin), PinResult::Success));
    /// ```
    pub fn unblock(&mut self, key: PinKey, puk: &PinValue, new_pin: &PinValue) -> PinResult {
        let Some(idx) = self.find_index(key) else {
            return PinResult::NotFound;
        };
        let slot = &mut self.slots[idx];
        if slot.puk_retries == 0 {
            return PinResult::Blocked;
        }
        if slot.puk != puk.bytes {
            slot.puk_retries -= 1;
            return PinResult::WrongPin {
                retries_remaining: slot.puk_retries,
            };
        }
        // PUK correct: reset PIN.
        slot.pin = new_pin.bytes;
        slot.pin_retries = slot.pin_max;
        slot.enabled = true;
        slot.verified = false;
        // PUK counter is NOT reset on success (per ETSI TS 102 221).
        PinResult::Success
    }

    /// Query the PIN retry counter for a key reference.
    ///
    /// Returns `None` if the key is not configured.
    pub fn retries(&self, key: PinKey) -> Option<u8> {
        self.find_index(key).map(|i| self.slots[i].pin_retries)
    }

    /// Query the PUK retry counter for a key reference.
    ///
    /// Returns `None` if the key is not configured.
    pub fn puk_retries(&self, key: PinKey) -> Option<u8> {
        self.find_index(key).map(|i| self.slots[i].puk_retries)
    }

    /// Whether the PIN security condition is satisfied.
    ///
    /// Returns `true` if the PIN has been successfully verified this session
    /// **or** if the PIN is disabled (per ETSI TS 102 221: disabled PINs
    /// have their security condition automatically satisfied).
    ///
    /// Returns `false` for unknown keys.
    pub fn is_verified(&self, key: PinKey) -> bool {
        self.find_index(key)
            .is_some_and(|i| self.slots[i].verified || !self.slots[i].enabled)
    }

    /// Whether the PIN is currently enabled.
    ///
    /// Returns `false` for unknown keys.
    pub fn is_enabled(&self, key: PinKey) -> bool {
        self.find_index(key)
            .is_some_and(|i| self.slots[i].enabled)
    }

    /// Whether the PIN is blocked (retry counter = 0).
    ///
    /// Returns `false` for unknown keys.
    pub fn is_blocked(&self, key: PinKey) -> bool {
        self.find_index(key)
            .is_some_and(|i| self.slots[i].pin_retries == 0)
    }

    /// Clear all verified flags (session reset).
    ///
    /// Called on card reset / power cycle. Retry counters and PIN values
    /// are preserved; only the session-level verification state is cleared.
    pub const fn reset_verified(&mut self) {
        let mut i = 0;
        while i < self.count as usize {
            self.slots[i].verified = false;
            i += 1;
        }
    }

    // -- snapshot --

    /// Snapshot buffer size: `1 + N * 22` bytes.
    ///
    /// Each slot serializes as 22 bytes. The leading byte is the slot count.
    pub const SNAPSHOT_SIZE: usize = 1 + N * 22;

    /// Serialize the PIN manager state into `buf` as flat LE bytes.
    ///
    /// Returns the number of bytes written, or 0 if `buf` is too small.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return 0;
        }
        buf[0] = self.count;
        let mut off = 1;
        let mut i = 0;
        while i < N {
            let s = &self.slots[i];
            buf[off] = s.key;
            buf[off + 1..off + 9].copy_from_slice(&s.pin);
            buf[off + 9] = s.pin_retries;
            buf[off + 10] = s.pin_max;
            buf[off + 11..off + 19].copy_from_slice(&s.puk);
            buf[off + 19] = s.puk_retries;
            buf[off + 20] = u8::from(s.enabled);
            buf[off + 21] = u8::from(s.verified);
            off += 22;
            i += 1;
        }
        Self::SNAPSHOT_SIZE
    }

    /// Restore the PIN manager state from `buf`.
    ///
    /// Returns `true` on success. Returns `false` if `buf` is too small
    /// or contains an invalid count.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < Self::SNAPSHOT_SIZE {
            return false;
        }
        let count = buf[0];
        if count as usize > N {
            return false;
        }
        self.count = count;
        let mut off = 1;
        let mut i = 0;
        while i < N {
            let s = &mut self.slots[i];
            s.key = buf[off];
            s.pin.copy_from_slice(&buf[off + 1..off + 9]);
            s.pin_retries = buf[off + 9];
            s.pin_max = buf[off + 10];
            s.puk.copy_from_slice(&buf[off + 11..off + 19]);
            s.puk_retries = buf[off + 19];
            s.enabled = buf[off + 20] != 0;
            s.verified = buf[off + 21] != 0;
            off += 22;
            i += 1;
        }
        true
    }

    // -- internal helpers --

    const fn find_index(&self, key: PinKey) -> Option<usize> {
        let mut i = 0;
        while i < self.count as usize {
            if self.slots[i].key == key.0 {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn pin(digits: &[u8]) -> PinValue {
        let mut bytes = [0xFF; 8];
        for (i, &d) in digits.iter().enumerate() {
            bytes[i] = d;
        }
        PinValue::new(bytes)
    }

    fn ascii_pin(s: &str) -> PinValue {
        let mut bytes = [0xFF; 8];
        for (i, b) in s.bytes().enumerate() {
            bytes[i] = b;
        }
        PinValue::new(bytes)
    }

    fn setup() -> PinManager<5> {
        let mut mgr = PinManager::<5>::new();
        let pin_val = ascii_pin("1234");
        let puk_val = ascii_pin("12345678");
        mgr.add_pin(PinKey(0x01), &pin_val, 3, &puk_val, 10, true)
            .unwrap();
        mgr
    }

    const PIN1: PinKey = PinKey(0x01);

    // -- VERIFY tests (Gherkin: VERIFY scenarios) --

    #[test]
    fn verify_correct_pin_succeeds() {
        let mut mgr = setup();
        assert_eq!(mgr.verify(PIN1, &ascii_pin("1234")), PinResult::Success);
        assert!(mgr.is_verified(PIN1));
        assert_eq!(mgr.retries(PIN1), Some(3));
    }

    #[test]
    fn verify_wrong_pin_decrements_counter() {
        let mut mgr = setup();
        assert_eq!(
            mgr.verify(PIN1, &ascii_pin("9999")),
            PinResult::WrongPin {
                retries_remaining: 2
            }
        );
        assert!(!mgr.is_verified(PIN1));
        assert_eq!(mgr.retries(PIN1), Some(2));
    }

    #[test]
    fn verify_wrong_three_times_blocks() {
        let mut mgr = setup();
        let wrong = ascii_pin("9999");
        assert_eq!(
            mgr.verify(PIN1, &wrong),
            PinResult::WrongPin {
                retries_remaining: 2
            }
        );
        assert_eq!(
            mgr.verify(PIN1, &wrong),
            PinResult::WrongPin {
                retries_remaining: 1
            }
        );
        // Third attempt: counter hits 0 -> WrongPin{0}, not Blocked.
        assert_eq!(
            mgr.verify(PIN1, &wrong),
            PinResult::WrongPin {
                retries_remaining: 0
            }
        );
        assert!(mgr.is_blocked(PIN1));
    }

    #[test]
    fn verify_on_blocked_pin_returns_blocked() {
        let mut mgr = setup();
        let wrong = ascii_pin("0000");
        for _ in 0..3 {
            mgr.verify(PIN1, &wrong);
        }
        // Now blocked. Correct PIN should return Blocked, not Success.
        assert_eq!(mgr.verify(PIN1, &ascii_pin("1234")), PinResult::Blocked);
        // Counter stays at 0.
        assert_eq!(mgr.retries(PIN1), Some(0));
    }

    #[test]
    fn verify_on_disabled_pin_returns_disabled() {
        let mut mgr = setup();
        mgr.disable(PIN1, &ascii_pin("1234"));
        assert_eq!(mgr.verify(PIN1, &ascii_pin("1234")), PinResult::Disabled);
        // Counter not decremented.
        assert_eq!(mgr.retries(PIN1), Some(3));
    }

    #[test]
    fn verify_correct_resets_counter() {
        let mut mgr = setup();
        // Use up two retries.
        mgr.verify(PIN1, &ascii_pin("0000"));
        mgr.verify(PIN1, &ascii_pin("0000"));
        assert_eq!(mgr.retries(PIN1), Some(1));
        // Correct PIN resets to max.
        assert_eq!(mgr.verify(PIN1, &ascii_pin("1234")), PinResult::Success);
        assert_eq!(mgr.retries(PIN1), Some(3));
    }

    #[test]
    fn verify_unknown_key_returns_not_found() {
        let mut mgr = setup();
        assert_eq!(
            mgr.verify(PinKey(0xFF), &ascii_pin("1234")),
            PinResult::NotFound
        );
    }

    #[test]
    fn disabled_pin_satisfies_security_condition() {
        let mut mgr = setup();
        mgr.disable(PIN1, &ascii_pin("1234"));
        assert!(mgr.is_verified(PIN1));
    }

    // -- CHANGE tests --

    #[test]
    fn change_with_correct_old_pin() {
        let mut mgr = setup();
        let new_pin = ascii_pin("5678");
        assert_eq!(
            mgr.change(PIN1, &ascii_pin("1234"), &new_pin),
            PinResult::Success
        );
        // New PIN works.
        assert_eq!(mgr.verify(PIN1, &new_pin), PinResult::Success);
        // Old PIN fails.
        assert!(matches!(
            mgr.verify(PIN1, &ascii_pin("1234")),
            PinResult::WrongPin { .. }
        ));
        assert_eq!(mgr.retries(PIN1), Some(2)); // decremented by wrong verify
    }

    #[test]
    fn change_with_wrong_old_pin() {
        let mut mgr = setup();
        assert_eq!(
            mgr.change(PIN1, &ascii_pin("0000"), &ascii_pin("5678")),
            PinResult::WrongPin {
                retries_remaining: 2
            }
        );
        // Old PIN still works.
        assert_eq!(mgr.verify(PIN1, &ascii_pin("1234")), PinResult::Success);
    }

    #[test]
    fn change_on_blocked_pin() {
        let mut mgr = setup();
        let wrong = ascii_pin("0000");
        for _ in 0..3 {
            mgr.verify(PIN1, &wrong);
        }
        assert_eq!(
            mgr.change(PIN1, &ascii_pin("1234"), &ascii_pin("5678")),
            PinResult::Blocked
        );
    }

    #[test]
    fn change_does_not_set_verified() {
        let mut mgr = setup();
        mgr.change(PIN1, &ascii_pin("1234"), &ascii_pin("5678"));
        assert!(!mgr.is_verified(PIN1));
    }

    // -- DISABLE tests --

    #[test]
    fn disable_with_correct_pin() {
        let mut mgr = setup();
        assert_eq!(mgr.disable(PIN1, &ascii_pin("1234")), PinResult::Success);
        assert!(!mgr.is_enabled(PIN1));
        assert!(mgr.is_verified(PIN1)); // disabled => condition satisfied
    }

    #[test]
    fn disable_with_wrong_pin() {
        let mut mgr = setup();
        assert_eq!(
            mgr.disable(PIN1, &ascii_pin("0000")),
            PinResult::WrongPin {
                retries_remaining: 2
            }
        );
        assert!(mgr.is_enabled(PIN1));
    }

    #[test]
    fn disable_already_disabled() {
        let mut mgr = setup();
        mgr.disable(PIN1, &ascii_pin("1234"));
        assert_eq!(mgr.disable(PIN1, &ascii_pin("1234")), PinResult::Disabled);
    }

    #[test]
    fn disable_on_blocked_pin() {
        let mut mgr = setup();
        for _ in 0..3 {
            mgr.verify(PIN1, &ascii_pin("0000"));
        }
        assert_eq!(mgr.disable(PIN1, &ascii_pin("1234")), PinResult::Blocked);
    }

    // -- ENABLE tests --

    #[test]
    fn enable_disabled_pin_with_correct_pin() {
        let mut mgr = setup();
        mgr.disable(PIN1, &ascii_pin("1234"));
        assert_eq!(mgr.enable(PIN1, &ascii_pin("1234")), PinResult::Success);
        assert!(mgr.is_enabled(PIN1));
        assert!(!mgr.is_verified(PIN1)); // must VERIFY separately
    }

    #[test]
    fn enable_with_wrong_pin() {
        let mut mgr = setup();
        mgr.disable(PIN1, &ascii_pin("1234"));
        assert_eq!(
            mgr.enable(PIN1, &ascii_pin("0000")),
            PinResult::WrongPin {
                retries_remaining: 2
            }
        );
        assert!(!mgr.is_enabled(PIN1));
    }

    #[test]
    fn enable_already_enabled_is_noop() {
        let mut mgr = setup();
        // Verify first so verified flag is set.
        mgr.verify(PIN1, &ascii_pin("1234"));
        assert!(mgr.is_verified(PIN1));
        // Enable on already-enabled PIN is a no-op success.
        assert_eq!(mgr.enable(PIN1, &ascii_pin("1234")), PinResult::Success);
        // Verified flag preserved (not cleared).
        assert!(mgr.is_verified(PIN1));
    }

    #[test]
    fn enable_on_blocked_pin() {
        let mut mgr = setup();
        for _ in 0..3 {
            mgr.verify(PIN1, &ascii_pin("0000"));
        }
        assert_eq!(mgr.enable(PIN1, &ascii_pin("1234")), PinResult::Blocked);
    }

    // -- UNBLOCK tests --

    #[test]
    fn unblock_with_correct_puk() {
        let mut mgr = setup();
        for _ in 0..3 {
            mgr.verify(PIN1, &ascii_pin("0000"));
        }
        assert!(mgr.is_blocked(PIN1));

        let new_pin = ascii_pin("5678");
        assert_eq!(
            mgr.unblock(PIN1, &ascii_pin("12345678"), &new_pin),
            PinResult::Success
        );
        assert!(mgr.is_enabled(PIN1));
        assert_eq!(mgr.retries(PIN1), Some(3));
        assert!(!mgr.is_verified(PIN1));
        assert_eq!(mgr.verify(PIN1, &new_pin), PinResult::Success);
    }

    #[test]
    fn unblock_with_wrong_puk() {
        let mut mgr = setup();
        for _ in 0..3 {
            mgr.verify(PIN1, &ascii_pin("0000"));
        }
        assert_eq!(
            mgr.unblock(PIN1, &ascii_pin("00000000"), &ascii_pin("5678")),
            PinResult::WrongPin {
                retries_remaining: 9
            }
        );
        assert_eq!(mgr.puk_retries(PIN1), Some(9));
    }

    #[test]
    fn unblock_with_exhausted_puk_returns_blocked() {
        let mut mgr = setup();
        for _ in 0..3 {
            mgr.verify(PIN1, &ascii_pin("0000"));
        }
        // Exhaust PUK.
        for _ in 0..10 {
            mgr.unblock(PIN1, &ascii_pin("00000000"), &ascii_pin("5678"));
        }
        assert_eq!(mgr.puk_retries(PIN1), Some(0));
        // Now even correct PUK fails.
        assert_eq!(
            mgr.unblock(PIN1, &ascii_pin("12345678"), &ascii_pin("5678")),
            PinResult::Blocked
        );
    }

    #[test]
    fn unblock_does_not_reset_puk_counter() {
        let mut mgr = setup();
        for _ in 0..3 {
            mgr.verify(PIN1, &ascii_pin("0000"));
        }
        // One wrong PUK attempt.
        mgr.unblock(PIN1, &ascii_pin("00000000"), &ascii_pin("5678"));
        assert_eq!(mgr.puk_retries(PIN1), Some(9));
        // Correct PUK unblocks but PUK counter stays at 9.
        mgr.unblock(PIN1, &ascii_pin("12345678"), &ascii_pin("5678"));
        assert_eq!(mgr.puk_retries(PIN1), Some(9));
    }

    // -- CONFIGURATION tests --

    #[test]
    fn duplicate_key_rejected() {
        let mut mgr = setup();
        let v = ascii_pin("9999");
        assert_eq!(
            mgr.add_pin(PIN1, &v, 3, &v, 10, true),
            Err(PinError::DuplicateKey)
        );
    }

    #[test]
    fn slots_full_rejected() {
        let mut mgr = PinManager::<1>::new();
        let v = ascii_pin("1234");
        let p = ascii_pin("12345678");
        mgr.add_pin(PinKey(0x01), &v, 3, &p, 10, true).unwrap();
        assert_eq!(
            mgr.add_pin(PinKey(0x02), &v, 3, &p, 10, true),
            Err(PinError::SlotsFull)
        );
    }

    #[test]
    fn independent_pins_do_not_interfere() {
        let mut mgr = PinManager::<5>::new();
        let p1_val = ascii_pin("1234");
        let p2_val = ascii_pin("4321");
        let puk = ascii_pin("12345678");
        mgr.add_pin(PinKey(0x01), &p1_val, 3, &puk, 10, true)
            .unwrap();
        mgr.add_pin(PinKey(0x81), &p2_val, 3, &puk, 10, true)
            .unwrap();

        // Wrong PIN1 attempt.
        mgr.verify(PinKey(0x01), &ascii_pin("0000"));
        // PIN2 unaffected.
        assert_eq!(mgr.retries(PinKey(0x81)), Some(3));
        assert!(!mgr.is_blocked(PinKey(0x81)));
    }

    // -- SESSION RESET test --

    #[test]
    fn reset_clears_verified_flags() {
        let mut mgr = setup();
        mgr.verify(PIN1, &ascii_pin("1234"));
        assert!(mgr.is_verified(PIN1));
        mgr.reset_verified();
        // Verified cleared, but counter preserved.
        assert!(!mgr.is_verified(PIN1));
        assert_eq!(mgr.retries(PIN1), Some(3));
    }

    // -- PinValue tests --

    #[test]
    fn pin_value_len_computed_correctly() {
        assert_eq!(PinValue::EMPTY.len, 0);
        assert_eq!(ascii_pin("1234").len, 4);
        assert_eq!(ascii_pin("12345678").len, 8);
        assert_eq!(pin(&[0x30, 0x31]).len, 2);
    }

    #[test]
    fn pin_value_equality() {
        let a = ascii_pin("1234");
        let b = ascii_pin("1234");
        let c = ascii_pin("4321");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -- SNAPSHOT tests --

    #[test]
    fn snapshot_size_correct() {
        assert_eq!(PinManager::<5>::SNAPSHOT_SIZE, 1 + 5 * 22);
        assert_eq!(PinManager::<1>::SNAPSHOT_SIZE, 23);
    }

    #[test]
    fn save_restore_roundtrip_preserves_state() {
        let mut mgr = setup();
        // Verify PIN to set the verified flag.
        mgr.verify(PIN1, &ascii_pin("1234"));
        assert!(mgr.is_verified(PIN1));

        let mut buf = [0u8; PinManager::<5>::SNAPSHOT_SIZE];
        let written = mgr.save_state(&mut buf);
        assert_eq!(written, PinManager::<5>::SNAPSHOT_SIZE);

        let mut restored = PinManager::<5>::new();
        assert!(restored.restore_state(&buf));

        // All state should match.
        assert_eq!(restored.retries(PIN1), Some(3));
        assert!(restored.is_verified(PIN1));
        assert!(restored.is_enabled(PIN1));
        assert!(!restored.is_blocked(PIN1));
    }

    #[test]
    fn save_restore_preserves_degraded_counters() {
        let mut mgr = setup();
        // Two wrong attempts.
        mgr.verify(PIN1, &ascii_pin("9999"));
        mgr.verify(PIN1, &ascii_pin("9999"));
        assert_eq!(mgr.retries(PIN1), Some(1));

        let mut buf = [0u8; PinManager::<5>::SNAPSHOT_SIZE];
        mgr.save_state(&mut buf);

        let mut restored = PinManager::<5>::new();
        assert!(restored.restore_state(&buf));
        assert_eq!(restored.retries(PIN1), Some(1));
        // Correct PIN should still work.
        assert_eq!(restored.verify(PIN1, &ascii_pin("1234")), PinResult::Success);
    }

    #[test]
    fn save_restore_with_multiple_pins() {
        let mut mgr = PinManager::<5>::new();
        let puk = ascii_pin("12345678");
        mgr.add_pin(PinKey(0x01), &ascii_pin("1111"), 3, &puk, 10, true).unwrap();
        mgr.add_pin(PinKey(0x81), &ascii_pin("2222"), 5, &puk, 8, false).unwrap();
        mgr.add_pin(PinKey(0x0A), &ascii_pin("3333"), 2, &puk, 4, true).unwrap();

        mgr.verify(PinKey(0x01), &ascii_pin("1111"));
        // Wrong attempt on PIN 0x0A.
        mgr.verify(PinKey(0x0A), &ascii_pin("0000"));

        let mut buf = [0u8; PinManager::<5>::SNAPSHOT_SIZE];
        mgr.save_state(&mut buf);

        let mut restored = PinManager::<5>::new();
        assert!(restored.restore_state(&buf));

        // PIN 0x01: verified, 3 retries (reset on success).
        assert!(restored.is_verified(PinKey(0x01)));
        assert_eq!(restored.retries(PinKey(0x01)), Some(3));

        // PIN 0x81: disabled, not verified, 5 retries.
        assert!(!restored.is_enabled(PinKey(0x81)));
        assert_eq!(restored.retries(PinKey(0x81)), Some(5));

        // PIN 0x0A: enabled, 1 retry remaining.
        assert!(restored.is_enabled(PinKey(0x0A)));
        assert_eq!(restored.retries(PinKey(0x0A)), Some(1));
    }

    #[test]
    fn save_into_small_buffer_returns_zero() {
        let mgr = setup();
        let mut buf = [0u8; 10];
        assert_eq!(mgr.save_state(&mut buf), 0);
    }

    #[test]
    fn restore_from_small_buffer_returns_false() {
        let mut mgr = PinManager::<5>::new();
        let buf = [0u8; 10];
        assert!(!mgr.restore_state(&buf));
    }

    #[test]
    fn restore_with_invalid_count_returns_false() {
        let mut mgr = PinManager::<1>::new();
        // count=2 but N=1.
        let mut buf = [0u8; PinManager::<1>::SNAPSHOT_SIZE];
        buf[0] = 2;
        assert!(!mgr.restore_state(&buf));
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Generate a valid ASCII-encoded PIN (4-8 digits + 0xFF padding).
    fn arb_pin_value() -> impl Strategy<Value = PinValue> {
        prop::collection::vec(0x30u8..=0x39, 4..=8).prop_map(|digits| {
            let mut bytes = [0xFF; 8];
            for (i, &d) in digits.iter().enumerate() {
                bytes[i] = d;
            }
            PinValue::new(bytes)
        })
    }

    proptest! {
        // Correct PIN always verifies successfully regardless of value.
        #[test]
        fn correct_pin_always_succeeds(pin_val in arb_pin_value(), puk_val in arb_pin_value()) {
            let mut mgr = PinManager::<1>::new();
            mgr.add_pin(PinKey(0x01), &pin_val, 3, &puk_val, 10, true).unwrap();
            prop_assert_eq!(mgr.verify(PinKey(0x01), &pin_val), PinResult::Success);
            prop_assert!(mgr.is_verified(PinKey(0x01)));
        }

        // Retry counter decrements exactly once per wrong attempt.
        #[test]
        fn wrong_pin_decrements_once(
            pin_val in arb_pin_value(),
            wrong_val in arb_pin_value(),
            max_retries in 1u8..=10,
        ) {
            // Ensure wrong_val differs from pin_val.
            prop_assume!(pin_val != wrong_val);
            let puk = PinValue::new([0x30; 8]);
            let mut mgr = PinManager::<1>::new();
            mgr.add_pin(PinKey(0x01), &pin_val, max_retries, &puk, 10, true).unwrap();
            mgr.verify(PinKey(0x01), &wrong_val);
            prop_assert_eq!(mgr.retries(PinKey(0x01)), Some(max_retries - 1));
        }

        // After unblock, the new PIN works and old PIN does not.
        #[test]
        fn unblock_installs_new_pin(
            old_pin in arb_pin_value(),
            new_pin in arb_pin_value(),
            puk_val in arb_pin_value(),
        ) {
            let mut mgr = PinManager::<1>::new();
            mgr.add_pin(PinKey(0x01), &old_pin, 1, &puk_val, 10, true).unwrap();
            // Block by one wrong attempt (max_retries = 1).
            mgr.verify(PinKey(0x01), &PinValue::EMPTY);
            prop_assert!(mgr.is_blocked(PinKey(0x01)));
            // Unblock.
            prop_assert_eq!(
                mgr.unblock(PinKey(0x01), &puk_val, &new_pin),
                PinResult::Success,
            );
            // New PIN works.
            prop_assert_eq!(mgr.verify(PinKey(0x01), &new_pin), PinResult::Success);
        }

        // Disable then enable round-trips back to unverified enabled state.
        #[test]
        fn disable_enable_roundtrip(pin_val in arb_pin_value(), puk_val in arb_pin_value()) {
            let mut mgr = PinManager::<1>::new();
            mgr.add_pin(PinKey(0x01), &pin_val, 3, &puk_val, 10, true).unwrap();
            prop_assert_eq!(mgr.disable(PinKey(0x01), &pin_val), PinResult::Success);
            prop_assert!(!mgr.is_enabled(PinKey(0x01)));
            prop_assert!(mgr.is_verified(PinKey(0x01))); // disabled => satisfied
            prop_assert_eq!(mgr.enable(PinKey(0x01), &pin_val), PinResult::Success);
            prop_assert!(mgr.is_enabled(PinKey(0x01)));
            prop_assert!(!mgr.is_verified(PinKey(0x01))); // must VERIFY again
        }
    }
}
