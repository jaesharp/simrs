package com.simrs;

/**
 * SimRS smart card simulator -- Java bindings via JNI.
 *
 * <p>Each instance is bound to the OS thread that created it (the underlying
 * C API uses thread-local storage). All method calls must happen on the
 * creating thread.
 *
 * <pre>{@code
 * byte[] ki = new byte[16], k = new byte[16], opc = new byte[16];
 * // fill ki, k, opc with real credentials...
 * Sim sim = new Sim(ki, k, opc);
 * byte[] atr = sim.reset();
 * byte[] response = sim.apdu(new byte[]{0x00, (byte)0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00});
 * }</pre>
 */
public class Sim implements AutoCloseable {

    static {
        System.loadLibrary("simrs_jni");
    }

    /**
     * Initialize the SIM with Milenage authentication credentials.
     *
     * @param ki  16-byte GSM subscriber key
     * @param k   16-byte Milenage subscriber key
     * @param opc 16-byte Milenage operator variant OPc
     * @throws IllegalArgumentException if any key is not exactly 16 bytes
     */
    public Sim(byte[] ki, byte[] k, byte[] opc) {
        if (ki.length != 16) throw new IllegalArgumentException("ki must be 16 bytes");
        if (k.length != 16) throw new IllegalArgumentException("k must be 16 bytes");
        if (opc.length != 16) throw new IllegalArgumentException("opc must be 16 bytes");
        nativeInit(ki, k, opc);
    }

    /**
     * Initialize the SIM from a TCA eUICC Profile Package (DER-encoded).
     *
     * @param der raw DER bytes of the profile package
     * @return a new Sim instance
     * @throws IllegalArgumentException if the profile cannot be parsed
     */
    public static Sim fromProfile(byte[] der) {
        Sim sim = new Sim();
        if (!nativeInitProfile(der)) {
            throw new IllegalArgumentException("Failed to load profile (malformed DER or missing PEs)");
        }
        return sim;
    }

    /** Private constructor for fromProfile(). */
    private Sim() {}

    /**
     * Power-on reset.
     *
     * @return ATR (Answer To Reset) bytes
     * @throws IllegalStateException if the SIM is not initialized
     */
    public byte[] reset() {
        byte[] atr = nativeReset();
        if (atr == null) throw new IllegalStateException("Reset failed (SIM not initialized?)");
        return atr;
    }

    /**
     * Send an APDU command and receive the response.
     *
     * @param command raw APDU bytes (minimum 4: CLA INS P1 P2)
     * @return response bytes (data + SW1 + SW2)
     * @throws IllegalArgumentException if command is shorter than 4 bytes
     * @throws IllegalStateException    if APDU processing fails
     */
    public byte[] apdu(byte[] command) {
        if (command.length < 4) throw new IllegalArgumentException("APDU must be at least 4 bytes");
        byte[] rsp = nativeApdu(command);
        if (rsp == null) throw new IllegalStateException("APDU processing failed");
        return rsp;
    }

    /**
     * Save the current SIM state.
     *
     * @return opaque snapshot bytes
     * @throws IllegalStateException if snapshot fails
     */
    public byte[] snapshot() {
        byte[] snap = nativeSnapshotSave();
        if (snap == null) throw new IllegalStateException("Snapshot save failed");
        return snap;
    }

    /**
     * Restore SIM state from a previous snapshot.
     *
     * @param snapshot bytes previously returned by {@link #snapshot()}
     * @throws IllegalStateException if restoration fails
     */
    public void restore(byte[] snapshot) {
        if (!nativeSnapshotRestore(snapshot)) {
            throw new IllegalStateException("Snapshot restore failed (algorithm mismatch or corrupt data)");
        }
    }

    /**
     * Compute a non-cryptographic hash (FNV-1a) of the current SIM state.
     *
     * @return 64-bit hash value
     */
    public long stateHash() {
        return nativeStateHash();
    }

    @Override
    public void close() {
        // Thread-local cleanup happens when the thread exits.
    }

    // --- Native methods ---

    private static native void nativeInit(byte[] ki, byte[] k, byte[] opc);
    private static native boolean nativeInitProfile(byte[] der);
    private native byte[] nativeReset();
    private native byte[] nativeApdu(byte[] command);
    private native byte[] nativeSnapshotSave();
    private native boolean nativeSnapshotRestore(byte[] snapshot);
    private native long nativeStateHash();
    private static native int nativeSnapshotSize();
}
