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
    /// Array of bytes (`byte[]`).
    ByteArray,
    /// Array of shorts (`short[]`).
    ShortArray,
    /// Reference to a heap-allocated object instance.
    Instance,
}

impl JcType {
    /// Number of 16-bit stack words this type occupies.
    ///
    /// All scalar and reference types consume 1 word; `Void` consumes 0.
    #[inline]
    pub const fn stack_size(self) -> u8 {
        match self {
            Self::Void => 0,
            Self::Byte | Self::Short | Self::Boolean | Self::ByteArray | Self::ShortArray | Self::Instance => 1,
        }
    }

    /// Whether this type is a numeric type (valid for arithmetic).
    #[inline]
    pub const fn is_numeric(self) -> bool {
        matches!(self, Self::Byte | Self::Short)
    }

    /// Whether this type is an array type.
    #[inline]
    pub const fn is_array(self) -> bool {
        matches!(self, Self::ByteArray | Self::ShortArray)
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
        assert_eq!(JcType::ByteArray.stack_size(), 1);
        assert_eq!(JcType::ShortArray.stack_size(), 1);
        assert_eq!(JcType::Instance.stack_size(), 1);
    }

    #[test]
    fn numeric_classification() {
        assert!(JcType::Byte.is_numeric());
        assert!(JcType::Short.is_numeric());
        assert!(!JcType::Void.is_numeric());
        assert!(!JcType::Boolean.is_numeric());
        assert!(!JcType::ByteArray.is_numeric());
        assert!(!JcType::Instance.is_numeric());
    }

    #[test]
    fn array_classification() {
        assert!(JcType::ByteArray.is_array());
        assert!(JcType::ShortArray.is_array());
        assert!(!JcType::Byte.is_array());
        assert!(!JcType::Short.is_array());
        assert!(!JcType::Void.is_array());
    }
}
