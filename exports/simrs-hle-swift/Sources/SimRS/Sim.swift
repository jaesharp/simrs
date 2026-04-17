import CSimRS
import Foundation

/// SimRS smart card simulator -- Swift bindings.
///
/// Thread safety: each instance dispatches all C API calls to a dedicated
/// thread to satisfy the thread-local storage requirement.
public final class Sim {
    private let queue = DispatchQueue(label: "com.simrs.sim")

    /// Initialize the SIM with Milenage authentication credentials.
    ///
    /// - Parameters:
    ///   - ki: 16-byte GSM subscriber key
    ///   - k: 16-byte Milenage subscriber key
    ///   - opc: 16-byte Milenage operator variant OPc
    public init(ki: [UInt8], k: [UInt8], opc: [UInt8]) {
        precondition(ki.count == 16, "ki must be 16 bytes")
        precondition(k.count == 16, "k must be 16 bytes")
        precondition(opc.count == 16, "opc must be 16 bytes")
        queue.sync {
            ki.withUnsafeBufferPointer { kiPtr in
                k.withUnsafeBufferPointer { kPtr in
                    opc.withUnsafeBufferPointer { opcPtr in
                        simrs_init(kiPtr.baseAddress!, kPtr.baseAddress!, opcPtr.baseAddress!)
                    }
                }
            }
        }
    }

    /// Power-on reset.
    ///
    /// - Returns: ATR (Answer To Reset) bytes
    public func reset() -> [UInt8] {
        return queue.sync {
            var buf = [UInt8](repeating: 0, count: 64)
            let len = simrs_reset(&buf, UInt32(buf.count))
            return Array(buf[..<Int(len)])
        }
    }

    /// Send an APDU command and receive the response.
    ///
    /// - Parameter command: raw APDU bytes (minimum 4: CLA INS P1 P2)
    /// - Returns: response bytes (data + SW1 + SW2)
    public func apdu(_ command: [UInt8]) -> [UInt8] {
        precondition(command.count >= 4, "APDU must be at least 4 bytes")
        return queue.sync {
            var rspBuf = [UInt8](repeating: 0, count: 258)
            let len = command.withUnsafeBufferPointer { cmdPtr in
                simrs_apdu(cmdPtr.baseAddress!, UInt32(command.count), &rspBuf, UInt32(rspBuf.count))
            }
            return Array(rspBuf[..<Int(len)])
        }
    }

    /// Save the current SIM state.
    ///
    /// - Returns: opaque snapshot bytes
    public func snapshot() -> [UInt8] {
        return queue.sync {
            let size = simrs_snapshot_size()
            var buf = [UInt8](repeating: 0, count: Int(size))
            let written = simrs_snapshot_save(&buf, size)
            return Array(buf[..<Int(written)])
        }
    }

    /// Restore SIM state from a previous snapshot.
    ///
    /// - Parameter snapshot: bytes previously returned by `snapshot()`
    /// - Returns: true on success
    @discardableResult
    public func restore(_ snapshot: [UInt8]) -> Bool {
        return queue.sync {
            snapshot.withUnsafeBufferPointer { ptr in
                simrs_init_from_snapshot(ptr.baseAddress!, UInt32(snapshot.count)) != 0
            }
        }
    }

    /// Compute a non-cryptographic hash (FNV-1a) of the current SIM state.
    public func stateHash() -> UInt64 {
        return queue.sync {
            simrs_state_hash()
        }
    }
}
