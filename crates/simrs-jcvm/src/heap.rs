//! Fixed-size object heap for the JCVM.
//!
//! Provides an arena allocator within a `[u8; HEAP_SIZE]` backing array.
//! Every object carries a header with its owner context, type tag, and size.
//! No deallocation -- the heap grows monotonically (matching real `JavaCard`
//! behaviour where garbage collection is rare/optional).
//!
//! # Object Layout
//!
//! ```text
//! [ Header (4 bytes) ] [ Fields / Array data ... ]
//!   byte 0: owner context (package ID)
//!   byte 1: type tag (ObjectKind)
//!   byte 2-3: payload size (u16 LE, NOT including header)
//! ```
//!
//! # Array Layout
//!
//! Arrays have an additional 2-byte length prefix after the header:
//! ```text
//! [ Header (4 bytes) ] [ length: u16 LE ] [ element data ... ]
//! ```

use crate::firewall::{self, SecurityException};

/// Size of the object header in the heap.
const HEADER_SIZE: usize = 4;

/// Size of the array length prefix (after the header).
const ARRAY_LENGTH_PREFIX: usize = 2;

/// Object handle: an index into the heap.
///
/// Zero is reserved as "null reference".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjRef(pub u16);

impl ObjRef {
    /// The null reference (no object).
    pub const NULL: Self = Self(0);

    /// Whether this reference is null.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Type tag stored in the object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectKind {
    /// Class instance with fields.
    Instance = 0,
    /// Byte array (`byte[]`).
    ByteArray = 1,
    /// Short array (`short[]`).
    ShortArray = 2,
}

impl ObjectKind {
    /// Convert from raw byte, returning `None` for unknown tags.
    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Instance),
            1 => Some(Self::ByteArray),
            2 => Some(Self::ShortArray),
            _ => None,
        }
    }
}

/// Fixed-size object heap with arena allocation.
///
/// `HEAP_SIZE` is the total backing store in bytes. Typical values:
/// - Tests: 1024-4096
/// - Production: 8192-32768 (matching JCOP EEPROM budgets)
pub struct ObjectHeap<const HEAP_SIZE: usize> {
    /// Backing store for all objects.
    data: [u8; HEAP_SIZE],
    /// Next free byte offset (bump allocator).
    free: u16,
}

#[allow(clippy::cast_possible_truncation)]
impl<const HEAP_SIZE: usize> ObjectHeap<HEAP_SIZE> {
    /// Create an empty heap.
    ///
    /// Offset 0 is reserved (null sentinel), so the first allocation starts at
    /// offset 1. This wastes one byte but simplifies null-checking.
    pub const fn new() -> Self {
        Self {
            data: [0u8; HEAP_SIZE],
            free: 1, // 0 reserved for null
        }
    }

    /// Allocate a class instance with `field_bytes` of field storage.
    ///
    /// Returns `None` if the heap is full.
    pub fn alloc_instance(&mut self, owner_context: u8, field_bytes: u16) -> Option<ObjRef> {
        let total = HEADER_SIZE + field_bytes as usize;
        let offset = self.bump_alloc(total)?;
        self.write_header(offset, owner_context, ObjectKind::Instance, field_bytes);
        // Zero-initialize fields (already zeroed in backing store, but be explicit).
        let field_start = offset + HEADER_SIZE;
        self.data[field_start..field_start + field_bytes as usize].fill(0);
        Some(ObjRef(offset as u16))
    }

    /// Allocate a byte array of `length` elements.
    ///
    /// Returns `None` if the heap is full.
    pub fn alloc_byte_array(&mut self, owner_context: u8, length: u16) -> Option<ObjRef> {
        let payload = ARRAY_LENGTH_PREFIX + length as usize;
        let total = HEADER_SIZE + payload;
        let offset = self.bump_alloc(total)?;
        self.write_header(offset, owner_context, ObjectKind::ByteArray, payload as u16);
        // Write array length.
        let len_off = offset + HEADER_SIZE;
        self.data[len_off..len_off + 2].copy_from_slice(&length.to_le_bytes());
        // Zero-initialize elements.
        let elem_start = len_off + ARRAY_LENGTH_PREFIX;
        self.data[elem_start..elem_start + length as usize].fill(0);
        Some(ObjRef(offset as u16))
    }

    /// Allocate a short array of `length` elements.
    ///
    /// Returns `None` if the heap is full.
    pub fn alloc_short_array(&mut self, owner_context: u8, length: u16) -> Option<ObjRef> {
        let byte_len = (length as usize) * 2;
        let payload = ARRAY_LENGTH_PREFIX + byte_len;
        let total = HEADER_SIZE + payload;
        let offset = self.bump_alloc(total)?;
        self.write_header(
            offset,
            owner_context,
            ObjectKind::ShortArray,
            payload as u16,
        );
        let len_off = offset + HEADER_SIZE;
        self.data[len_off..len_off + 2].copy_from_slice(&length.to_le_bytes());
        let elem_start = len_off + ARRAY_LENGTH_PREFIX;
        self.data[elem_start..elem_start + byte_len].fill(0);
        Some(ObjRef(offset as u16))
    }

    /// Get the owner context of an object.
    ///
    /// Returns `None` if the reference is null or invalid.
    pub const fn owner_of(&self, obj: ObjRef) -> Option<u8> {
        if obj.is_null() {
            return None;
        }
        let off = obj.0 as usize;
        if off + HEADER_SIZE > self.free as usize {
            return None;
        }
        Some(self.data[off])
    }

    /// Get the type tag of an object.
    pub const fn kind_of(&self, obj: ObjRef) -> Option<ObjectKind> {
        if obj.is_null() {
            return None;
        }
        let off = obj.0 as usize;
        if off + HEADER_SIZE > self.free as usize {
            return None;
        }
        ObjectKind::from_u8(self.data[off + 1])
    }

    /// Get the array length (element count) of an array object.
    ///
    /// Returns `None` for non-array objects or null references.
    pub fn array_length(&self, obj: ObjRef) -> Option<u16> {
        let kind = self.kind_of(obj)?;
        match kind {
            ObjectKind::ByteArray | ObjectKind::ShortArray => {
                let off = obj.0 as usize + HEADER_SIZE;
                Some(u16::from_le_bytes([self.data[off], self.data[off + 1]]))
            }
            ObjectKind::Instance => None,
        }
    }

    /// Read a byte from a byte array at the given index, checking the firewall.
    ///
    /// # Errors
    ///
    /// Returns `Err(SecurityException)` if the current context does not own the array.
    /// Returns `Ok(None)` for null ref, wrong type, or out-of-bounds index.
    pub fn baload(
        &self,
        obj: ObjRef,
        index: u16,
        current_context: u8,
    ) -> Result<Option<u8>, SecurityException> {
        let Some(owner) = self.owner_of(obj) else {
            return Ok(None);
        };
        firewall::check_access(current_context, owner)?;

        if !matches!(self.kind_of(obj), Some(ObjectKind::ByteArray)) {
            return Ok(None);
        }
        let length = self.array_length(obj).unwrap_or(0);
        if index >= length {
            return Ok(None);
        }
        let elem_off = obj.0 as usize + HEADER_SIZE + ARRAY_LENGTH_PREFIX + index as usize;
        Ok(Some(self.data[elem_off]))
    }

    /// Write a byte to a byte array at the given index, checking the firewall.
    ///
    /// # Errors
    ///
    /// Returns `Err(SecurityException)` for cross-context access.
    /// Returns `Ok(false)` for null ref, wrong type, or out-of-bounds.
    pub fn bastore(
        &mut self,
        obj: ObjRef,
        index: u16,
        value: u8,
        current_context: u8,
    ) -> Result<bool, SecurityException> {
        let Some(owner) = self.owner_of(obj) else {
            return Ok(false);
        };
        firewall::check_access(current_context, owner)?;

        if !matches!(self.kind_of(obj), Some(ObjectKind::ByteArray)) {
            return Ok(false);
        }
        let length = self.array_length(obj).unwrap_or(0);
        if index >= length {
            return Ok(false);
        }
        let elem_off = obj.0 as usize + HEADER_SIZE + ARRAY_LENGTH_PREFIX + index as usize;
        self.data[elem_off] = value;
        Ok(true)
    }

    /// Read a short from a short array at the given index, checking the firewall.
    ///
    /// # Errors
    ///
    /// Returns `Err(SecurityException)` for cross-context access.
    pub fn saload(
        &self,
        obj: ObjRef,
        index: u16,
        current_context: u8,
    ) -> Result<Option<i16>, SecurityException> {
        let Some(owner) = self.owner_of(obj) else {
            return Ok(None);
        };
        firewall::check_access(current_context, owner)?;

        if !matches!(self.kind_of(obj), Some(ObjectKind::ShortArray)) {
            return Ok(None);
        }
        let length = self.array_length(obj).unwrap_or(0);
        if index >= length {
            return Ok(None);
        }
        let byte_off = obj.0 as usize + HEADER_SIZE + ARRAY_LENGTH_PREFIX + (index as usize) * 2;
        let val = i16::from_be_bytes([self.data[byte_off], self.data[byte_off + 1]]);
        Ok(Some(val))
    }

    /// Write a short to a short array at the given index, checking the firewall.
    ///
    /// # Errors
    ///
    /// Returns `Err(SecurityException)` for cross-context access.
    pub fn sastore(
        &mut self,
        obj: ObjRef,
        index: u16,
        value: i16,
        current_context: u8,
    ) -> Result<bool, SecurityException> {
        let Some(owner) = self.owner_of(obj) else {
            return Ok(false);
        };
        firewall::check_access(current_context, owner)?;

        if !matches!(self.kind_of(obj), Some(ObjectKind::ShortArray)) {
            return Ok(false);
        }
        let length = self.array_length(obj).unwrap_or(0);
        if index >= length {
            return Ok(false);
        }
        let byte_off = obj.0 as usize + HEADER_SIZE + ARRAY_LENGTH_PREFIX + (index as usize) * 2;
        let bytes = value.to_be_bytes();
        self.data[byte_off] = bytes[0];
        self.data[byte_off + 1] = bytes[1];
        Ok(true)
    }

    /// Read a field byte from an instance object.
    ///
    /// # Errors
    ///
    /// Returns `Err(SecurityException)` for cross-context access.
    pub fn getfield_b(
        &self,
        obj: ObjRef,
        field_offset: u16,
        current_context: u8,
    ) -> Result<Option<u8>, SecurityException> {
        let Some(owner) = self.owner_of(obj) else {
            return Ok(None);
        };
        firewall::check_access(current_context, owner)?;

        if !matches!(self.kind_of(obj), Some(ObjectKind::Instance)) {
            return Ok(None);
        }
        let off = obj.0 as usize + HEADER_SIZE + field_offset as usize;
        if off >= self.free as usize {
            return Ok(None);
        }
        Ok(Some(self.data[off]))
    }

    /// Write a field byte to an instance object.
    ///
    /// # Errors
    ///
    /// Returns `Err(SecurityException)` for cross-context access.
    pub fn putfield_b(
        &mut self,
        obj: ObjRef,
        field_offset: u16,
        value: u8,
        current_context: u8,
    ) -> Result<bool, SecurityException> {
        let Some(owner) = self.owner_of(obj) else {
            return Ok(false);
        };
        firewall::check_access(current_context, owner)?;

        if !matches!(self.kind_of(obj), Some(ObjectKind::Instance)) {
            return Ok(false);
        }
        let off = obj.0 as usize + HEADER_SIZE + field_offset as usize;
        if off >= self.free as usize {
            return Ok(false);
        }
        self.data[off] = value;
        Ok(true)
    }

    /// Total heap capacity in bytes.
    pub const fn capacity(&self) -> usize {
        HEAP_SIZE
    }

    /// Bytes currently allocated (including the null sentinel).
    pub const fn used(&self) -> usize {
        self.free as usize
    }

    /// Bytes remaining for new allocations.
    pub const fn remaining(&self) -> usize {
        HEAP_SIZE - self.free as usize
    }

    // -----------------------------------------------------------------------
    // Snapshot support
    // -----------------------------------------------------------------------

    /// Snapshot size: free pointer (2 bytes) + heap data up to `free`.
    pub const fn snapshot_size(&self) -> usize {
        2 + self.free as usize
    }

    /// Maximum possible snapshot size.
    pub const MAX_SNAPSHOT_SIZE: usize = 2 + HEAP_SIZE;

    /// Save heap state to buffer. Returns bytes written.
    pub fn save_state(&self, buf: &mut [u8]) -> usize {
        let needed = self.snapshot_size();
        if buf.len() < needed {
            return 0;
        }
        buf[0..2].copy_from_slice(&self.free.to_le_bytes());
        let f = self.free as usize;
        buf[2..2 + f].copy_from_slice(&self.data[..f]);
        needed
    }

    /// Restore heap state from buffer. Returns success.
    pub fn restore_state(&mut self, buf: &[u8]) -> bool {
        if buf.len() < 2 {
            return false;
        }
        let free = u16::from_le_bytes([buf[0], buf[1]]);
        if free as usize > HEAP_SIZE || buf.len() < 2 + free as usize {
            return false;
        }
        self.free = free;
        let f = free as usize;
        self.data[..f].copy_from_slice(&buf[2..2 + f]);
        // Zero the rest to avoid stale data.
        self.data[f..].fill(0);
        true
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Bump-allocate `size` bytes. Returns the start offset or `None` if full.
    fn bump_alloc(&mut self, size: usize) -> Option<usize> {
        let offset = self.free as usize;
        let new_free = offset.checked_add(size)?;
        if new_free > HEAP_SIZE {
            return None;
        }
        // Check that new_free fits in u16.
        if new_free > u16::MAX as usize {
            return None;
        }
        self.free = new_free as u16;
        Some(offset)
    }

    /// Write a 4-byte object header at the given offset.
    fn write_header(&mut self, offset: usize, owner: u8, kind: ObjectKind, payload_size: u16) {
        self.data[offset] = owner;
        self.data[offset + 1] = kind as u8;
        self.data[offset + 2..offset + 4].copy_from_slice(&payload_size.to_le_bytes());
    }
}

impl<const HEAP_SIZE: usize> Default for ObjectHeap<HEAP_SIZE> {
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
    fn new_heap_starts_at_offset_1() {
        let heap = ObjectHeap::<1024>::new();
        assert_eq!(heap.used(), 1);
        assert_eq!(heap.remaining(), 1023);
    }

    #[test]
    fn null_ref_returns_none() {
        let heap = ObjectHeap::<1024>::new();
        assert!(ObjRef::NULL.is_null());
        assert_eq!(heap.owner_of(ObjRef::NULL), None);
        assert_eq!(heap.kind_of(ObjRef::NULL), None);
        assert_eq!(heap.array_length(ObjRef::NULL), None);
    }

    #[test]
    fn alloc_instance_and_read_fields() {
        let mut heap = ObjectHeap::<1024>::new();
        let obj = heap.alloc_instance(1, 4).unwrap();
        assert!(!obj.is_null());
        assert_eq!(heap.owner_of(obj), Some(1));
        assert_eq!(heap.kind_of(obj), Some(ObjectKind::Instance));

        // Fields are zero-initialized.
        assert_eq!(heap.getfield_b(obj, 0, 1).unwrap(), Some(0));
        assert_eq!(heap.getfield_b(obj, 3, 1).unwrap(), Some(0));

        // Write and read back.
        assert!(heap.putfield_b(obj, 2, 0xAB, 1).unwrap());
        assert_eq!(heap.getfield_b(obj, 2, 1).unwrap(), Some(0xAB));
    }

    #[test]
    fn alloc_byte_array_and_access() {
        let mut heap = ObjectHeap::<1024>::new();
        let arr = heap.alloc_byte_array(2, 8).unwrap();
        assert_eq!(heap.kind_of(arr), Some(ObjectKind::ByteArray));
        assert_eq!(heap.array_length(arr), Some(8));

        // Zero-initialized.
        assert_eq!(heap.baload(arr, 0, 2).unwrap(), Some(0));

        // Write and read.
        assert!(heap.bastore(arr, 3, 0xFF, 2).unwrap());
        assert_eq!(heap.baload(arr, 3, 2).unwrap(), Some(0xFF));

        // Out of bounds returns None (not panic).
        assert_eq!(heap.baload(arr, 8, 2).unwrap(), None);
        assert!(!heap.bastore(arr, 8, 0, 2).unwrap());
    }

    #[test]
    fn alloc_short_array_and_access() {
        let mut heap = ObjectHeap::<1024>::new();
        let arr = heap.alloc_short_array(3, 4).unwrap();
        assert_eq!(heap.kind_of(arr), Some(ObjectKind::ShortArray));
        assert_eq!(heap.array_length(arr), Some(4));

        // Write and read.
        assert!(heap.sastore(arr, 1, -1234, 3).unwrap());
        assert_eq!(heap.saload(arr, 1, 3).unwrap(), Some(-1234));

        // Out of bounds.
        assert_eq!(heap.saload(arr, 4, 3).unwrap(), None);
    }

    #[test]
    fn firewall_blocks_cross_context_instance_access() {
        let mut heap = ObjectHeap::<1024>::new();
        let obj = heap.alloc_instance(1, 4).unwrap();

        // Same context: OK.
        assert!(heap.getfield_b(obj, 0, 1).is_ok());
        assert!(heap.putfield_b(obj, 0, 0xAA, 1).is_ok());

        // Different context: SecurityException.
        assert_eq!(heap.getfield_b(obj, 0, 2), Err(SecurityException));
        assert_eq!(heap.putfield_b(obj, 0, 0xBB, 2), Err(SecurityException));
    }

    #[test]
    fn firewall_blocks_cross_context_array_access() {
        let mut heap = ObjectHeap::<1024>::new();
        let arr = heap.alloc_byte_array(1, 4).unwrap();

        assert_eq!(heap.baload(arr, 0, 2), Err(SecurityException));
        assert_eq!(heap.bastore(arr, 0, 0, 2), Err(SecurityException));
    }

    #[test]
    fn heap_full_returns_none() {
        let mut heap = ObjectHeap::<16>::new();
        // 15 bytes available. Instance with 11 bytes of fields = 4 header + 11 = 15 bytes.
        assert!(heap.alloc_instance(0, 11).is_some());
        // No space left.
        assert!(heap.alloc_instance(0, 1).is_none());
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut heap = ObjectHeap::<1024>::new();
        let obj = heap.alloc_instance(1, 4).unwrap();
        heap.putfield_b(obj, 0, 0xDE, 1).unwrap();
        heap.putfield_b(obj, 1, 0xAD, 1).unwrap();

        let mut buf = [0u8; ObjectHeap::<1024>::MAX_SNAPSHOT_SIZE];
        let n = heap.save_state(&mut buf);
        assert!(n > 0);

        let mut heap2 = ObjectHeap::<1024>::new();
        assert!(heap2.restore_state(&buf[..n]));
        assert_eq!(heap2.used(), heap.used());
        assert_eq!(heap2.getfield_b(obj, 0, 1).unwrap(), Some(0xDE));
        assert_eq!(heap2.getfield_b(obj, 1, 1).unwrap(), Some(0xAD));
    }

    #[test]
    fn snapshot_rejects_invalid_buffer() {
        let mut heap = ObjectHeap::<64>::new();
        assert!(!heap.restore_state(&[]));
        assert!(!heap.restore_state(&[0]));
        // free pointer beyond heap size.
        assert!(!heap.restore_state(&[0xFF, 0xFF]));
    }

    #[test]
    fn instance_array_length_returns_none() {
        let mut heap = ObjectHeap::<1024>::new();
        let obj = heap.alloc_instance(0, 4).unwrap();
        assert_eq!(heap.array_length(obj), None);
    }

    #[test]
    fn multiple_allocations_coexist() {
        let mut heap = ObjectHeap::<1024>::new();
        let a = heap.alloc_instance(0, 4).unwrap();
        let b = heap.alloc_byte_array(1, 8).unwrap();
        let c = heap.alloc_short_array(2, 3).unwrap();

        // All distinct.
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);

        // Each has correct kind.
        assert_eq!(heap.kind_of(a), Some(ObjectKind::Instance));
        assert_eq!(heap.kind_of(b), Some(ObjectKind::ByteArray));
        assert_eq!(heap.kind_of(c), Some(ObjectKind::ShortArray));

        // Each has correct owner.
        assert_eq!(heap.owner_of(a), Some(0));
        assert_eq!(heap.owner_of(b), Some(1));
        assert_eq!(heap.owner_of(c), Some(2));
    }
}
