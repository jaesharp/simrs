//! Compilation error types.

use alloc::string::String;

/// A single compilation error with method context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    /// Method in which the error occurred (empty for class-level errors).
    pub method: String,
    /// Human-readable error description.
    pub message: String,
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.method.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "in method `{}`: {}", self.method, self.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn display_with_method() {
        let e = CompileError {
            method: String::from("process"),
            message: String::from("undefined variable `x`"),
        };
        assert_eq!(e.to_string(), "in method `process`: undefined variable `x`");
    }

    #[test]
    fn display_without_method() {
        let e = CompileError {
            method: String::new(),
            message: String::from("AID too long"),
        };
        assert_eq!(e.to_string(), "AID too long");
    }
}
