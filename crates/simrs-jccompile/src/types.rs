//! Java Card type system.
//!
//! Defines the primitive and reference types available in the JVA
//! smartcard language, matching the JCVM 2.1.1 type system.

/// A type in the Java Card type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JcType {
    /// No value (return type only).
    Void,
    /// Signed 8-bit integer.
    Byte,
    /// Signed 16-bit integer.
    Short,
    /// Boolean (1-bit logical, stored as a word on the stack).
    Boolean,
    /// Signed 32-bit integer (optional Java Card 3.x support).
    Int,
    /// Array of bytes (`byte[]`).
    ByteArray,
    /// Array of shorts (`short[]`).
    ShortArray,
    /// Array of ints (`int[]`).
    IntArray,
    /// Array of references (`Object[]`).
    RefArray,
    /// Reference to a heap-allocated object instance.
    Instance,
}

impl JcType {
    /// Number of 16-bit stack words this type occupies.
    ///
    /// `Int` occupies 2 words (32 bits across two 16-bit slots).
    /// All other scalar and reference types consume 1 word; `Void` consumes 0.
    #[inline]
    pub const fn stack_size(self) -> u8 {
        match self {
            Self::Void => 0,
            Self::Int => 2,
            Self::Byte | Self::Short | Self::Boolean
            | Self::ByteArray | Self::ShortArray | Self::IntArray | Self::RefArray
            | Self::Instance => 1,
        }
    }

    /// Whether this type is a numeric type (valid for short arithmetic).
    #[inline]
    pub const fn is_numeric(self) -> bool {
        matches!(self, Self::Byte | Self::Short)
    }

    /// Whether this type is the 32-bit int type.
    #[inline]
    pub const fn is_int(self) -> bool {
        matches!(self, Self::Int)
    }

    /// Whether this type is an array type.
    #[inline]
    pub const fn is_array(self) -> bool {
        matches!(self, Self::ByteArray | Self::ShortArray | Self::IntArray | Self::RefArray)
    }

    /// Whether this type is a reference type (arrays, instances).
    #[inline]
    pub const fn is_reference(self) -> bool {
        matches!(
            self,
            Self::ByteArray | Self::ShortArray | Self::IntArray | Self::RefArray | Self::Instance
        )
    }

    /// Whether this type is a reference array type.
    #[inline]
    pub const fn is_ref_array(self) -> bool {
        matches!(self, Self::RefArray)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_sizes() {
        assert_eq!(JcType::Void.stack_size(), 0);
        assert_eq!(JcType::Byte.stack_size(), 1);
        assert_eq!(JcType::Short.stack_size(), 1);
        assert_eq!(JcType::Boolean.stack_size(), 1);
        assert_eq!(JcType::Int.stack_size(), 2);
        assert_eq!(JcType::ByteArray.stack_size(), 1);
        assert_eq!(JcType::ShortArray.stack_size(), 1);
        assert_eq!(JcType::IntArray.stack_size(), 1);
        assert_eq!(JcType::RefArray.stack_size(), 1);
        assert_eq!(JcType::Instance.stack_size(), 1);
    }

    #[test]
    fn numeric_classification() {
        assert!(JcType::Byte.is_numeric());
        assert!(JcType::Short.is_numeric());
        assert!(!JcType::Void.is_numeric());
        assert!(!JcType::Boolean.is_numeric());
        assert!(!JcType::Int.is_numeric());
        assert!(!JcType::ByteArray.is_numeric());
        assert!(!JcType::Instance.is_numeric());
    }

    #[test]
    fn int_classification() {
        assert!(JcType::Int.is_int());
        assert!(!JcType::Short.is_int());
        assert!(!JcType::Byte.is_int());
        assert!(!JcType::ByteArray.is_int());
    }

    #[test]
    fn array_classification() {
        assert!(JcType::ByteArray.is_array());
        assert!(JcType::ShortArray.is_array());
        assert!(JcType::IntArray.is_array());
        assert!(JcType::RefArray.is_array());
        assert!(!JcType::Byte.is_array());
        assert!(!JcType::Short.is_array());
        assert!(!JcType::Void.is_array());
    }

    #[test]
    fn reference_classification() {
        assert!(JcType::ByteArray.is_reference());
        assert!(JcType::ShortArray.is_reference());
        assert!(JcType::IntArray.is_reference());
        assert!(JcType::RefArray.is_reference());
        assert!(JcType::Instance.is_reference());
        assert!(!JcType::Byte.is_reference());
        assert!(!JcType::Short.is_reference());
        assert!(!JcType::Int.is_reference());
        assert!(!JcType::Void.is_reference());
    }

    #[test]
    fn ref_array_classification() {
        assert!(JcType::RefArray.is_ref_array());
        assert!(!JcType::ByteArray.is_ref_array());
        assert!(!JcType::ShortArray.is_ref_array());
        assert!(!JcType::Instance.is_ref_array());
    }
}
