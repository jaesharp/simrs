package com.simrs;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;

/**
 * SimRS smart card simulator -- Java bindings via JNI.
 *
 * <p>Thread-safe by default: each instance dispatches all native calls to a
 * dedicated worker thread to satisfy the C library's thread-local storage
 * requirement. Pass {@code threadSafe=false} for pinned mode (caller manages
 * threading; faster but errors on cross-thread access).
 *
 * <pre>{@code
 * byte[] ki = new byte[16], k = new byte[16], opc = new byte[16];
 * try (Sim sim = new Sim(ki, k, opc)) {
 *     byte[] atr = sim.reset();
 *     byte[] response = sim.apdu(new byte[]{0x00, (byte)0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00});
 * }
 * }</pre>
 */
public class Sim implements AutoCloseable {

    static {
        System.loadLibrary("simrs_jni");
    }

    private final ExecutorService executor;
    private final long ownerThreadId;
    private volatile boolean closed = false;

    /**
     * Initialize the SIM with Milenage authentication credentials (thread-safe mode).
     */
    public Sim(byte[] ki, byte[] k, byte[] opc) {
        this(ki, k, opc, true);
    }

    /**
     * Initialize the SIM with Milenage authentication credentials.
     *
     * @param ki         16-byte GSM subscriber key
     * @param k          16-byte Milenage subscriber key
     * @param opc        16-byte Milenage operator variant OPc
     * @param threadSafe if true, uses a dedicated worker thread; if false, pins to creating thread
     */
    public Sim(byte[] ki, byte[] k, byte[] opc, boolean threadSafe) {
        this(threadSafe);
        if (ki.length != 16) throw new IllegalArgumentException("ki must be 16 bytes");
        if (k.length != 16) throw new IllegalArgumentException("k must be 16 bytes");
        if (opc.length != 16) throw new IllegalArgumentException("opc must be 16 bytes");
        dispatch(() -> { nativeInit(ki, k, opc); return null; });
    }

    /** Create a SIM from a TCA eUICC Profile Package (thread-safe mode). */
    public static Sim fromProfile(byte[] der) {
        return fromProfile(der, true);
    }

    /** Create a SIM from a TCA eUICC Profile Package. */
    public static Sim fromProfile(byte[] der, boolean threadSafe) {
        Sim sim = new Sim(threadSafe);
        try {
            boolean ok = sim.dispatch(() -> nativeInitProfile(der));
            if (!ok) {
                sim.close();
                throw new IllegalArgumentException("Failed to load profile");
            }
            return sim;
        } catch (RuntimeException e) {
            sim.close();
            throw e;
        }
    }

    /**
     * Create a Sim from a previously-saved snapshot.
     *
     * <p>The snapshot contains all SIM state including credentials; no keys
     * are needed. Useful for transferring state across threads or processes.
     */
    public static Sim fromSnapshot(byte[] snapshot) {
        return fromSnapshot(snapshot, true);
    }

    /** Create a Sim from a snapshot with explicit threading mode. */
    public static Sim fromSnapshot(byte[] snapshot, boolean threadSafe) {
        Sim sim = new Sim(threadSafe);
        try {
            boolean ok = sim.dispatch(() -> nativeInitFromSnapshot(snapshot));
            if (!ok) {
                sim.close();
                throw new IllegalArgumentException("Failed to init from snapshot (malformed or unknown profile)");
            }
            return sim;
        } catch (RuntimeException e) {
            sim.close();
            throw e;
        }
    }

    /** Private constructor for fromProfile(). */
    private Sim(boolean threadSafe) {
        if (threadSafe) {
            this.executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "simrs-worker");
                t.setDaemon(true);
                return t;
            });
            this.ownerThreadId = -1;
        } else {
            this.executor = null;
            this.ownerThreadId = Thread.currentThread().getId();
        }
    }

    /** Power-on reset. */
    public byte[] reset() {
        byte[] atr = dispatch(() -> nativeReset());
        if (atr == null) throw new IllegalStateException("Reset failed");
        return atr;
    }

    /** Send an APDU command and receive the response. */
    public byte[] apdu(byte[] command) {
        if (command.length < 4) throw new IllegalArgumentException("APDU must be at least 4 bytes");
        byte[] rsp = dispatch(() -> nativeApdu(command));
        if (rsp == null) throw new IllegalStateException("APDU processing failed");
        return rsp;
    }

    /** Save the current SIM state. */
    public byte[] snapshot() {
        byte[] snap = dispatch(() -> nativeSnapshotSave());
        if (snap == null) throw new IllegalStateException("Snapshot save failed");
        return snap;
    }

    /** FNV-1a hash of the current SIM state. */
    public long stateHash() {
        return dispatch(() -> nativeStateHash());
    }

    private <T> T dispatch(Callable<T> task) {
        if (closed) throw new IllegalStateException("Sim is closed");
        if (executor == null) {
            if (Thread.currentThread().getId() != ownerThreadId) {
                throw new IllegalStateException(
                    "Sim accessed from a different thread. Construct with threadSafe=true for cross-thread access.");
            }
            try {
                return task.call();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        try {
            return executor.submit(task).get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            throw new RuntimeException(cause);
        }
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        if (executor != null) executor.shutdown();
    }

    // --- Native methods ---

    private static native void nativeInit(byte[] ki, byte[] k, byte[] opc);
    private static native boolean nativeInitProfile(byte[] der);
    private static native boolean nativeInitFromSnapshot(byte[] snapshot);
    private static native byte[] nativeReset();
    private static native byte[] nativeApdu(byte[] command);
    private static native byte[] nativeSnapshotSave();
    private static native long nativeStateHash();
    private static native int nativeSnapshotSize();
}
