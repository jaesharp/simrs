//! Call frames, operand stack, and local variables for the JCVM.
//!
//! The JCVM execution model uses a stack of call frames, each associated
//! with a method invocation. Each frame tracks the return address (package
//! index + method index + PC) and the base offset into the shared local
//! variable area.
//!
//! # Layout
//!
//! ```text
//! JcVM state:
//!   stack[64]     -- shared operand stack (16-bit words)
//!   stack_ptr     -- top of operand stack
//!   locals[128]   -- shared local variable area (16-bit words)
//!   frames[8]     -- call frame stack
//!   frame_ptr     -- current frame depth
//! ```
//!
//! When a method is invoked, a new [`CallFrame`] is pushed recording the
//! caller's state. On return, the frame is popped and execution resumes
//! at the saved PC.

/// A single call frame on the JCVM call stack.
///
/// Records the return context so that `sreturn` / `return` can resume
/// the caller.
#[derive(Clone, Copy)]
pub struct CallFrame {
    /// Package index of the caller method.
    pub return_pkg: u8,
    /// Method index of the caller method.
    pub return_method: u8,
    /// Program counter to resume at in the caller.
    pub return_pc: u16,
    /// Base offset into the locals array for this frame.
    pub locals_base: u8,
    /// Base offset into the operand stack for this frame.
    pub stack_base: u8,
}

impl CallFrame {
    /// Create an empty (zeroed) call frame.
    pub const fn empty() -> Self {
        Self {
            return_pkg: 0,
            return_method: 0,
            return_pc: 0,
            locals_base: 0,
            stack_base: 0,
        }
    }
}

/// Maximum operand stack depth (in 16-bit words).
pub const MAX_STACK: usize = 64;

/// Maximum call frame depth.
pub const MAX_FRAMES: usize = 8;

/// Maximum local variable slots (in 16-bit words).
pub const MAX_LOCALS: usize = 128;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_frame_is_zeroed() {
        let f = CallFrame::empty();
        assert_eq!(f.return_pkg, 0);
        assert_eq!(f.return_method, 0);
        assert_eq!(f.return_pc, 0);
        assert_eq!(f.locals_base, 0);
        assert_eq!(f.stack_base, 0);
    }

    #[test]
    fn frame_stores_return_info() {
        let f = CallFrame {
            return_pkg: 2,
            return_method: 5,
            return_pc: 42,
            locals_base: 8,
            stack_base: 3,
        };
        assert_eq!(f.return_pkg, 2);
        assert_eq!(f.return_method, 5);
        assert_eq!(f.return_pc, 42);
        assert_eq!(f.locals_base, 8);
        assert_eq!(f.stack_base, 3);
    }
}
