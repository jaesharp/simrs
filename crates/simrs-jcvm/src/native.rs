//! Native method implementations for the `javacard.framework` API.
//!
//! When a Java Card applet calls framework methods like `APDU.getBuffer()`
//! or `Util.arrayCopy()`, the JCVM recognises these as native calls and
//! dispatches to the Rust implementations in this module.
//!
//! Each native method is identified by a `(class_id, method_id)` pair.
//! The converter/compiler assigns well-known IDs for framework classes,
//! and the invoke handlers check these before falling through to normal
//! bytecode dispatch.

use crate::JcVM;
use crate::heap::ObjRef;
use crate::opcodes::ExecResult;

// =========================================================================
// Well-known class IDs for javacard.framework classes
// =========================================================================

/// Class identifiers for the Java Card framework API.
pub mod class_id {
    /// `javacard.framework.Applet`
    pub const APPLET: u8 = 0x01;
    /// `javacard.framework.APDU`
    pub const APDU: u8 = 0x02;
    /// `javacard.framework.Util`
    pub const UTIL: u8 = 0x03;
    /// `javacard.framework.ISO7816`
    pub const ISO7816: u8 = 0x04;
    /// `javacard.framework.ISOException`
    pub const ISO_EXCEPTION: u8 = 0x05;
    /// `javacard.framework.JCSystem`
    pub const JC_SYSTEM: u8 = 0x06;
    /// `javacard.framework.OwnerPIN`
    pub const OWNER_PIN: u8 = 0x07;
}

// =========================================================================
// Method IDs within each class
// =========================================================================

/// Method identifiers within each framework class.
pub mod method_id {
    // -- Applet --
    /// `Applet.register()`
    pub const REGISTER: u8 = 0x01;
    /// `Applet.selectingApplet()`
    pub const SELECTING_APPLET: u8 = 0x02;

    // -- APDU --
    /// `APDU.getBuffer()`
    pub const GET_BUFFER: u8 = 0x01;
    /// `APDU.setIncomingAndReceive()`
    pub const SET_INCOMING_AND_RECEIVE: u8 = 0x02;
    /// `APDU.setOutgoing()`
    pub const SET_OUTGOING: u8 = 0x03;
    /// `APDU.setOutgoingLength(short)`
    pub const SET_OUTGOING_LENGTH: u8 = 0x04;
    /// `APDU.sendBytes(short, short)`
    pub const SEND_BYTES: u8 = 0x05;
    /// `APDU.setOutgoingAndSend(short, short)`
    pub const SET_OUTGOING_AND_SEND: u8 = 0x06;
    /// `APDU.receiveBytes(short)`
    pub const RECEIVE_BYTES: u8 = 0x07;
    /// `APDU.sendBytesLong(byte[], short, short)`
    pub const SEND_BYTES_LONG: u8 = 0x08;

    // -- Util --
    /// `Util.arrayCopy(byte[], short, byte[], short, short)`
    pub const ARRAY_COPY: u8 = 0x01;
    /// `Util.arrayCopyNonAtomic(byte[], short, byte[], short, short)`
    pub const ARRAY_COPY_NON_ATOMIC: u8 = 0x02;
    /// `Util.arrayCompare(byte[], short, byte[], short, short)`
    pub const ARRAY_COMPARE: u8 = 0x03;
    /// `Util.makeShort(byte, byte)`
    pub const MAKE_SHORT: u8 = 0x04;
    /// `Util.getShort(byte[], short)`
    pub const GET_SHORT: u8 = 0x05;
    /// `Util.setShort(byte[], short, short)`
    pub const SET_SHORT: u8 = 0x06;

    // -- ISOException --
    /// `ISOException.throwIt(short)`
    pub const THROW_IT: u8 = 0x01;

    // -- JCSystem --
    /// `JCSystem.beginTransaction()`
    pub const BEGIN_TRANSACTION: u8 = 0x01;
    /// `JCSystem.commitTransaction()`
    pub const COMMIT_TRANSACTION: u8 = 0x02;
    /// `JCSystem.abortTransaction()`
    pub const ABORT_TRANSACTION: u8 = 0x03;
    /// `JCSystem.makeTransientByteArray(short, byte)`
    pub const MAKE_TRANSIENT_BYTE_ARRAY: u8 = 0x04;
    /// `JCSystem.makeTransientShortArray(short, byte)`
    pub const MAKE_TRANSIENT_SHORT_ARRAY: u8 = 0x05;
}

// =========================================================================
// Native result type
// =========================================================================

/// Result of a native method dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeResult {
    /// Void return (no value pushed to stack).
    Void,
    /// Return a short (16-bit) value to be pushed on the stack.
    Short(i16),
    /// Return an int (32-bit) value to be pushed as two stack words.
    Int(i32),
    /// Return an object reference to be pushed on the stack.
    Ref(u16),
    /// The method threw an exception.
    Exception(ExecResult),
    /// The (`class_id`, `method_id`) pair does not correspond to a native method.
    NotNative,
}

// =========================================================================
// Native method dispatch
// =========================================================================

/// Dispatch a native method call identified by `(class_id, method_id)`.
///
/// The VM's operand stack should already contain the arguments (if any).
/// This function pops arguments as needed and returns the result.
///
/// Returns [`NativeResult::NotNative`] if the pair is not a recognised
/// native method, in which case the caller should fall through to normal
/// bytecode dispatch.
#[allow(clippy::too_many_lines)]
pub fn dispatch_native<const H: usize, const P: usize>(
    class_id: u8,
    method_id: u8,
    vm: &mut JcVM<H, P>,
) -> NativeResult {
    match (class_id, method_id) {
        // -----------------------------------------------------------------
        // Applet
        // -----------------------------------------------------------------
        (class_id::APPLET, method_id::REGISTER) => {
            // Applet.register() -- stub: nothing to do.
            NativeResult::Void
        }
        (class_id::APPLET, method_id::SELECTING_APPLET) => {
            // Applet.selectingApplet() -> boolean (false = 0).
            NativeResult::Short(0)
        }

        // -----------------------------------------------------------------
        // APDU
        // -----------------------------------------------------------------
        (class_id::APDU, method_id::GET_BUFFER) => {
            // APDU.getBuffer() -> byte[].
            // Allocate a 256-byte APDU buffer on the heap if not already
            // present. For the stub, allocate fresh each time.
            vm.alloc_apdu_buffer()
                .map_or(NativeResult::Exception(ExecResult::HeapFull), |obj_ref| {
                    NativeResult::Ref(obj_ref.0)
                })
        }
        (class_id::APDU, method_id::SET_INCOMING_AND_RECEIVE) => {
            // APDU.setIncomingAndReceive() -> short (number of bytes received).
            // Stub: return 0 (no data received).
            NativeResult::Short(0)
        }
        (class_id::APDU, method_id::SET_OUTGOING) => {
            // APDU.setOutgoing() -> short (expected length).
            // Stub: return 256 (maximum).
            NativeResult::Short(256)
        }
        (class_id::APDU, method_id::SET_OUTGOING_LENGTH) => {
            // APDU.setOutgoingLength(short len) -> void.
            // Pop the length argument and discard (stub).
            let _len = vm.pop();
            NativeResult::Void
        }
        (class_id::APDU, method_id::SEND_BYTES) => {
            // APDU.sendBytes(short offset, short length) -> void.
            let _length = vm.pop();
            let _offset = vm.pop();
            NativeResult::Void
        }
        (class_id::APDU, method_id::SET_OUTGOING_AND_SEND) => {
            // APDU.setOutgoingAndSend(short offset, short length) -> void.
            let _length = vm.pop();
            let _offset = vm.pop();
            NativeResult::Void
        }
        (class_id::APDU, method_id::RECEIVE_BYTES) => {
            // APDU.receiveBytes(short offset) -> short.
            let _offset = vm.pop();
            NativeResult::Short(0)
        }
        (class_id::APDU, method_id::SEND_BYTES_LONG) => {
            // APDU.sendBytesLong(byte[] outData, short offset, short length) -> void.
            let _length = vm.pop();
            let _offset = vm.pop();
            let _out_data = vm.pop();
            NativeResult::Void
        }

        // -----------------------------------------------------------------
        // Util
        // -----------------------------------------------------------------
        (class_id::UTIL, method_id::ARRAY_COPY) => {
            // Util.arrayCopy(src, srcOff, dest, destOff, length) -> short.
            // Pop arguments (pushed left-to-right, so pop right-to-left).
            let length = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let dest_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let dest_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let src_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let src_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };

            match vm.native_array_copy(ObjRef(src_ref), src_off, ObjRef(dest_ref), dest_off, length)
            {
                Ok(result_off) => NativeResult::Short(result_off),
                Err(e) => NativeResult::Exception(e),
            }
        }
        (class_id::UTIL, method_id::ARRAY_COPY_NON_ATOMIC) => {
            // Same signature as arrayCopy but outside transaction scope.
            // Stub: delegate to same implementation.
            let length = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let dest_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let dest_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let src_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let src_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };

            match vm.native_array_copy(ObjRef(src_ref), src_off, ObjRef(dest_ref), dest_off, length)
            {
                Ok(result_off) => NativeResult::Short(result_off),
                Err(e) => NativeResult::Exception(e),
            }
        }
        (class_id::UTIL, method_id::ARRAY_COMPARE) => {
            // Util.arrayCompare(src, srcOff, dest, destOff, length) -> byte.
            let length = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let dest_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let dest_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let src_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let src_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };

            match vm.native_array_compare(
                ObjRef(src_ref),
                src_off,
                ObjRef(dest_ref),
                dest_off,
                length,
            ) {
                Ok(cmp) => NativeResult::Short(i16::from(cmp)),
                Err(e) => NativeResult::Exception(e),
            }
        }
        (class_id::UTIL, method_id::MAKE_SHORT) => {
            // Util.makeShort(byte b1, byte b2) -> short.
            #[allow(clippy::cast_possible_truncation)]
            let b2 = match vm.pop() {
                Ok(v) => v as u8,
                Err(e) => return NativeResult::Exception(e),
            };
            #[allow(clippy::cast_possible_truncation)]
            let b1 = match vm.pop() {
                Ok(v) => v as u8,
                Err(e) => return NativeResult::Exception(e),
            };
            NativeResult::Short(i16::from_be_bytes([b1, b2]))
        }
        (class_id::UTIL, method_id::GET_SHORT) => {
            // Util.getShort(byte[] bArray, short bOff) -> short.
            let b_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let arr_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            match vm.native_get_short(ObjRef(arr_ref), b_off) {
                Ok(val) => NativeResult::Short(val),
                Err(e) => NativeResult::Exception(e),
            }
        }
        (class_id::UTIL, method_id::SET_SHORT) => {
            // Util.setShort(byte[] bArray, short bOff, short value) -> short.
            let value = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let b_off = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            let arr_ref = match vm.pop() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            match vm.native_set_short(ObjRef(arr_ref), b_off, value) {
                Ok(next_off) => NativeResult::Short(next_off),
                Err(e) => NativeResult::Exception(e),
            }
        }

        // -----------------------------------------------------------------
        // ISOException
        // -----------------------------------------------------------------
        (class_id::ISO_EXCEPTION, method_id::THROW_IT) => {
            // ISOException.throwIt(short sw) -> never returns.
            let sw = vm.pop().unwrap_or(0x6F00); // internal error SW if stack is empty
            NativeResult::Exception(ExecResult::UncaughtException(sw))
        }

        // -----------------------------------------------------------------
        // JCSystem
        // -----------------------------------------------------------------
        (class_id::JC_SYSTEM, method_id::BEGIN_TRANSACTION) => {
            // JCSystem.beginTransaction() -> void.
            let _ = vm.journal_mut().begin();
            NativeResult::Void
        }
        (class_id::JC_SYSTEM, method_id::COMMIT_TRANSACTION) => {
            // JCSystem.commitTransaction() -> void.
            let _ = vm.journal_mut().commit();
            NativeResult::Void
        }
        (class_id::JC_SYSTEM, method_id::ABORT_TRANSACTION) => {
            // JCSystem.abortTransaction() -> void.
            let _ = vm.abort_transaction();
            NativeResult::Void
        }
        (class_id::JC_SYSTEM, method_id::MAKE_TRANSIENT_BYTE_ARRAY) => {
            // JCSystem.makeTransientByteArray(short length, byte event) -> byte[].
            let _event = vm.pop();
            let length = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            if length < 0 {
                return NativeResult::Exception(ExecResult::NegativeArraySize);
            }
            vm.alloc_byte_array(length.cast_unsigned())
                .map_or(NativeResult::Exception(ExecResult::HeapFull), |obj| {
                    NativeResult::Ref(obj.0)
                })
        }
        (class_id::JC_SYSTEM, method_id::MAKE_TRANSIENT_SHORT_ARRAY) => {
            // JCSystem.makeTransientShortArray(short length, byte event) -> short[].
            let _event = vm.pop();
            let length = match vm.pop_i16_pub() {
                Ok(v) => v,
                Err(e) => return NativeResult::Exception(e),
            };
            if length < 0 {
                return NativeResult::Exception(ExecResult::NegativeArraySize);
            }
            vm.alloc_short_array(length.cast_unsigned())
                .map_or(NativeResult::Exception(ExecResult::HeapFull), |obj| {
                    NativeResult::Ref(obj.0)
                })
        }

        // -----------------------------------------------------------------
        // Not a native method
        // -----------------------------------------------------------------
        _ => NativeResult::NotNative,
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JcVM;

    /// Helper: create a fresh VM for testing.
    fn test_vm() -> JcVM<4096, 4> {
        JcVM::new()
    }

    // -- Applet tests --

    #[test]
    fn applet_register_returns_void() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::APPLET, method_id::REGISTER, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    #[test]
    fn applet_selecting_applet_returns_false() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::APPLET, method_id::SELECTING_APPLET, &mut vm);
        assert_eq!(result, NativeResult::Short(0));
    }

    // -- APDU tests --

    #[test]
    fn apdu_get_buffer_returns_ref() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::APDU, method_id::GET_BUFFER, &mut vm);
        match result {
            NativeResult::Ref(r) => assert_ne!(r, 0, "should not be null ref"),
            other => panic!("expected Ref, got {other:?}"),
        }
    }

    #[test]
    fn apdu_set_incoming_and_receive_returns_zero() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::APDU, method_id::SET_INCOMING_AND_RECEIVE, &mut vm);
        assert_eq!(result, NativeResult::Short(0));
    }

    #[test]
    fn apdu_set_outgoing_returns_256() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::APDU, method_id::SET_OUTGOING, &mut vm);
        assert_eq!(result, NativeResult::Short(256));
    }

    #[test]
    fn apdu_set_outgoing_length_pops_arg() {
        let mut vm = test_vm();
        let _ = vm.push_pub(100);
        let result = dispatch_native(class_id::APDU, method_id::SET_OUTGOING_LENGTH, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    #[test]
    fn apdu_send_bytes_pops_two_args() {
        let mut vm = test_vm();
        let _ = vm.push_pub(0); // offset
        let _ = vm.push_pub(10); // length
        let result = dispatch_native(class_id::APDU, method_id::SEND_BYTES, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    #[test]
    fn apdu_set_outgoing_and_send_pops_two_args() {
        let mut vm = test_vm();
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(10);
        let result = dispatch_native(class_id::APDU, method_id::SET_OUTGOING_AND_SEND, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    #[test]
    fn apdu_receive_bytes_pops_arg() {
        let mut vm = test_vm();
        let _ = vm.push_pub(0);
        let result = dispatch_native(class_id::APDU, method_id::RECEIVE_BYTES, &mut vm);
        assert_eq!(result, NativeResult::Short(0));
    }

    #[test]
    fn apdu_send_bytes_long_pops_three_args() {
        let mut vm = test_vm();
        let _ = vm.push_pub(0); // outData ref
        let _ = vm.push_pub(0); // offset
        let _ = vm.push_pub(10); // length
        let result = dispatch_native(class_id::APDU, method_id::SEND_BYTES_LONG, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    // -- Util tests --

    #[test]
    fn util_make_short_combines_bytes() {
        let mut vm = test_vm();
        let _ = vm.push_pub(0xDE); // b1
        let _ = vm.push_pub(0xAD); // b2
        let result = dispatch_native(class_id::UTIL, method_id::MAKE_SHORT, &mut vm);
        assert_eq!(
            result,
            NativeResult::Short(i16::from_be_bytes([0xDE, 0xAD]))
        );
    }

    #[test]
    fn util_make_short_zero() {
        let mut vm = test_vm();
        let _ = vm.push_pub(0x00);
        let _ = vm.push_pub(0x00);
        let result = dispatch_native(class_id::UTIL, method_id::MAKE_SHORT, &mut vm);
        assert_eq!(result, NativeResult::Short(0));
    }

    #[test]
    fn util_array_copy_basic() {
        let mut vm = test_vm();
        // Allocate src and dest arrays.
        let src = vm.alloc_byte_array(4).unwrap();
        let dest = vm.alloc_byte_array(4).unwrap();

        // Write some data to src.
        vm.heap_bastore(src, 0, 0x11);
        vm.heap_bastore(src, 1, 0x22);
        vm.heap_bastore(src, 2, 0x33);
        vm.heap_bastore(src, 3, 0x44);

        // Push args: src, srcOff, dest, destOff, length.
        let _ = vm.push_pub(src.0);
        let _ = vm.push_pub(0); // srcOff
        let _ = vm.push_pub(dest.0);
        let _ = vm.push_pub(0); // destOff
        let _ = vm.push_pub(4); // length

        let result = dispatch_native(class_id::UTIL, method_id::ARRAY_COPY, &mut vm);
        // Returns destOff + length = 0 + 4 = 4.
        assert_eq!(result, NativeResult::Short(4));

        // Verify dest contents.
        assert_eq!(vm.heap_baload(dest, 0), Some(0x11));
        assert_eq!(vm.heap_baload(dest, 1), Some(0x22));
        assert_eq!(vm.heap_baload(dest, 2), Some(0x33));
        assert_eq!(vm.heap_baload(dest, 3), Some(0x44));
    }

    #[test]
    fn util_array_copy_non_atomic_basic() {
        let mut vm = test_vm();
        let src = vm.alloc_byte_array(2).unwrap();
        let dest = vm.alloc_byte_array(2).unwrap();

        vm.heap_bastore(src, 0, 0xAA);
        vm.heap_bastore(src, 1, 0xBB);

        let _ = vm.push_pub(src.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(dest.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(2);

        let result = dispatch_native(class_id::UTIL, method_id::ARRAY_COPY_NON_ATOMIC, &mut vm);
        assert_eq!(result, NativeResult::Short(2));
        assert_eq!(vm.heap_baload(dest, 0), Some(0xAA));
        assert_eq!(vm.heap_baload(dest, 1), Some(0xBB));
    }

    #[test]
    fn util_array_compare_equal() {
        let mut vm = test_vm();
        let a = vm.alloc_byte_array(3).unwrap();
        let b = vm.alloc_byte_array(3).unwrap();

        for i in 0..3 {
            vm.heap_bastore(a, i, 0x42);
            vm.heap_bastore(b, i, 0x42);
        }

        let _ = vm.push_pub(a.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(b.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(3);

        let result = dispatch_native(class_id::UTIL, method_id::ARRAY_COMPARE, &mut vm);
        assert_eq!(result, NativeResult::Short(0));
    }

    #[test]
    fn util_array_compare_less() {
        let mut vm = test_vm();
        let a = vm.alloc_byte_array(2).unwrap();
        let b = vm.alloc_byte_array(2).unwrap();

        vm.heap_bastore(a, 0, 0x01);
        vm.heap_bastore(a, 1, 0x02);
        vm.heap_bastore(b, 0, 0x01);
        vm.heap_bastore(b, 1, 0x03);

        let _ = vm.push_pub(a.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(b.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(2);

        let result = dispatch_native(class_id::UTIL, method_id::ARRAY_COMPARE, &mut vm);
        assert_eq!(result, NativeResult::Short(-1));
    }

    #[test]
    fn util_array_compare_greater() {
        let mut vm = test_vm();
        let a = vm.alloc_byte_array(1).unwrap();
        let b = vm.alloc_byte_array(1).unwrap();

        vm.heap_bastore(a, 0, 0xFF);
        vm.heap_bastore(b, 0, 0x00);

        let _ = vm.push_pub(a.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(b.0);
        let _ = vm.push_pub(0);
        let _ = vm.push_pub(1);

        let result = dispatch_native(class_id::UTIL, method_id::ARRAY_COMPARE, &mut vm);
        assert_eq!(result, NativeResult::Short(1));
    }

    #[test]
    fn util_get_short_reads_big_endian() {
        let mut vm = test_vm();
        let arr = vm.alloc_byte_array(4).unwrap();
        vm.heap_bastore(arr, 0, 0x12);
        vm.heap_bastore(arr, 1, 0x34);

        let _ = vm.push_pub(arr.0);
        let _ = vm.push_pub(0);

        let result = dispatch_native(class_id::UTIL, method_id::GET_SHORT, &mut vm);
        assert_eq!(result, NativeResult::Short(0x1234));
    }

    #[test]
    fn util_set_short_writes_big_endian() {
        let mut vm = test_vm();
        let arr = vm.alloc_byte_array(4).unwrap();

        let _ = vm.push_pub(arr.0);
        let _ = vm.push_pub(0); // offset
        let _ = vm.push_pub(0x5678_u16); // value

        let result = dispatch_native(class_id::UTIL, method_id::SET_SHORT, &mut vm);
        // Returns bOff + 2 = 2.
        assert_eq!(result, NativeResult::Short(2));
        assert_eq!(vm.heap_baload(arr, 0), Some(0x56));
        assert_eq!(vm.heap_baload(arr, 1), Some(0x78));
    }

    // -- ISOException tests --

    #[test]
    fn iso_exception_throw_it() {
        let mut vm = test_vm();
        let _ = vm.push_pub(0x6A82); // SW_FILE_NOT_FOUND
        let result = dispatch_native(class_id::ISO_EXCEPTION, method_id::THROW_IT, &mut vm);
        assert_eq!(
            result,
            NativeResult::Exception(ExecResult::UncaughtException(0x6A82))
        );
    }

    #[test]
    fn iso_exception_throw_it_empty_stack() {
        let mut vm = test_vm();
        // Stack is empty; should use fallback SW.
        let result = dispatch_native(class_id::ISO_EXCEPTION, method_id::THROW_IT, &mut vm);
        assert_eq!(
            result,
            NativeResult::Exception(ExecResult::UncaughtException(0x6F00))
        );
    }

    // -- JCSystem tests --

    #[test]
    fn jc_system_begin_transaction() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::JC_SYSTEM, method_id::BEGIN_TRANSACTION, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    #[test]
    fn jc_system_commit_transaction() {
        let mut vm = test_vm();
        let _ = vm.journal_mut().begin();
        let result = dispatch_native(class_id::JC_SYSTEM, method_id::COMMIT_TRANSACTION, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    #[test]
    fn jc_system_abort_transaction() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::JC_SYSTEM, method_id::ABORT_TRANSACTION, &mut vm);
        assert_eq!(result, NativeResult::Void);
    }

    #[test]
    fn jc_system_make_transient_byte_array() {
        let mut vm = test_vm();
        let _ = vm.push_pub(8); // length
        let _ = vm.push_pub(0); // event (CLEAR_ON_RESET)
        let result = dispatch_native(
            class_id::JC_SYSTEM,
            method_id::MAKE_TRANSIENT_BYTE_ARRAY,
            &mut vm,
        );
        match result {
            NativeResult::Ref(r) => assert_ne!(r, 0),
            other => panic!("expected Ref, got {other:?}"),
        }
    }

    #[test]
    fn jc_system_make_transient_short_array() {
        let mut vm = test_vm();
        let _ = vm.push_pub(4); // length
        let _ = vm.push_pub(0); // event
        let result = dispatch_native(
            class_id::JC_SYSTEM,
            method_id::MAKE_TRANSIENT_SHORT_ARRAY,
            &mut vm,
        );
        match result {
            NativeResult::Ref(r) => assert_ne!(r, 0),
            other => panic!("expected Ref, got {other:?}"),
        }
    }

    #[test]
    fn jc_system_make_transient_byte_array_negative_size() {
        let mut vm = test_vm();
        // Push -1 as short (0xFFFF).
        let _ = vm.push_pub((-1_i16).cast_unsigned());
        let _ = vm.push_pub(0); // event
        let result = dispatch_native(
            class_id::JC_SYSTEM,
            method_id::MAKE_TRANSIENT_BYTE_ARRAY,
            &mut vm,
        );
        assert_eq!(
            result,
            NativeResult::Exception(ExecResult::NegativeArraySize)
        );
    }

    // -- Unknown class/method --

    #[test]
    fn unknown_class_returns_not_native() {
        let mut vm = test_vm();
        let result = dispatch_native(0xFF, 0xFF, &mut vm);
        assert_eq!(result, NativeResult::NotNative);
    }

    #[test]
    fn unknown_method_returns_not_native() {
        let mut vm = test_vm();
        let result = dispatch_native(class_id::APPLET, 0xFF, &mut vm);
        assert_eq!(result, NativeResult::NotNative);
    }

    // -- Class/method ID uniqueness --

    #[test]
    fn class_ids_are_distinct() {
        let ids = [
            class_id::APPLET,
            class_id::APDU,
            class_id::UTIL,
            class_id::ISO7816,
            class_id::ISO_EXCEPTION,
            class_id::JC_SYSTEM,
            class_id::OWNER_PIN,
        ];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "class ID collision at indices {i} and {j}");
            }
        }
    }

    #[test]
    fn util_array_copy_with_offsets() {
        let mut vm = test_vm();
        let src = vm.alloc_byte_array(6).unwrap();
        let dest = vm.alloc_byte_array(6).unwrap();

        vm.heap_bastore(src, 2, 0xAA);
        vm.heap_bastore(src, 3, 0xBB);

        let _ = vm.push_pub(src.0);
        let _ = vm.push_pub(2); // srcOff
        let _ = vm.push_pub(dest.0);
        let _ = vm.push_pub(1); // destOff
        let _ = vm.push_pub(2); // length

        let result = dispatch_native(class_id::UTIL, method_id::ARRAY_COPY, &mut vm);
        assert_eq!(result, NativeResult::Short(3)); // destOff + length = 1 + 2

        assert_eq!(vm.heap_baload(dest, 0), Some(0x00));
        assert_eq!(vm.heap_baload(dest, 1), Some(0xAA));
        assert_eq!(vm.heap_baload(dest, 2), Some(0xBB));
    }

    #[test]
    fn util_get_short_at_offset() {
        let mut vm = test_vm();
        let arr = vm.alloc_byte_array(4).unwrap();
        vm.heap_bastore(arr, 2, 0xAB);
        vm.heap_bastore(arr, 3, 0xCD);

        let _ = vm.push_pub(arr.0);
        let _ = vm.push_pub(2); // offset

        let result = dispatch_native(class_id::UTIL, method_id::GET_SHORT, &mut vm);
        assert_eq!(
            result,
            NativeResult::Short(i16::from_be_bytes([0xAB, 0xCD]))
        );
    }

    #[test]
    fn util_set_short_at_offset() {
        let mut vm = test_vm();
        let arr = vm.alloc_byte_array(6).unwrap();

        let _ = vm.push_pub(arr.0);
        let _ = vm.push_pub(3); // offset
        let _ = vm.push_pub(0x1234_u16);

        let result = dispatch_native(class_id::UTIL, method_id::SET_SHORT, &mut vm);
        assert_eq!(result, NativeResult::Short(5)); // 3 + 2
        assert_eq!(vm.heap_baload(arr, 3), Some(0x12));
        assert_eq!(vm.heap_baload(arr, 4), Some(0x34));
    }
}
