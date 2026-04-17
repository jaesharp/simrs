///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.junit.jupiter:junit-jupiter:5.12.2
//DEPS org.junit.platform:junit-platform-launcher:1.12.2
//DEPS org.junit.platform:junit-platform-console-standalone:1.12.2

package com.simrs;

import org.junit.jupiter.api.Test;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

class SimTest {

    private static Sim createSim() {
        return new Sim(new byte[16], new byte[16], new byte[16]);
    }

    @Test
    void initRequires16ByteKeys() {
        assertThrows(IllegalArgumentException.class, () ->
            new Sim(new byte[8], new byte[16], new byte[16]));
        assertThrows(IllegalArgumentException.class, () ->
            new Sim(new byte[16], new byte[8], new byte[16]));
        assertThrows(IllegalArgumentException.class, () ->
            new Sim(new byte[16], new byte[16], new byte[8]));
    }

    @Test
    void resetReturnsAtr() {
        Sim sim = createSim();
        byte[] atr = sim.reset();
        assertNotNull(atr);
        assertTrue(atr.length > 0);
        assertEquals((byte) 0x3B, atr[0]);
    }

    @Test
    void selectMf() {
        Sim sim = createSim();
        sim.reset();
        byte[] rsp = sim.apdu(new byte[]{0x00, (byte) 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00});
        assertNotNull(rsp);
        assertTrue(rsp.length >= 2);
        assertEquals((byte) 0x61, rsp[rsp.length - 2]);
    }

    @Test
    void apduTooShortThrows() {
        Sim sim = createSim();
        sim.reset();
        assertThrows(IllegalArgumentException.class, () ->
            sim.apdu(new byte[]{0x00, (byte) 0xA4}));
    }

    @Test
    void snapshotRoundtrip() {
        Sim sim = createSim();
        sim.reset();
        sim.apdu(new byte[]{0x00, (byte) 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00});

        byte[] snap = sim.snapshot();
        assertNotNull(snap);
        assertTrue(snap.length > 0);

        long h1 = sim.stateHash();

        Sim sim2 = Sim.fromSnapshot(snap);
        assertEquals(h1, sim2.stateHash());
    }

    @Test
    void stateHashChangesAfterApdu() {
        Sim sim = createSim();
        sim.reset();
        long h1 = sim.stateHash();
        sim.apdu(new byte[]{0x00, (byte) 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00});
        long h2 = sim.stateHash();
        assertNotEquals(h1, h2);
    }

    @Test
    void badProfileThrows() {
        assertThrows(IllegalArgumentException.class, () ->
            Sim.fromProfile(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                       (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}));
    }

    @Test
    void badSnapshotThrows() {
        assertThrows(IllegalArgumentException.class, () ->
            Sim.fromSnapshot(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}));
    }

    // --- Main: run tests via JUnit Platform Launcher ---

    public static void main(String[] args) {
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request()
            .selectors(selectClass(SimTest.class))
            .build();

        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        Launcher launcher = LauncherFactory.create();
        launcher.execute(request, listener);

        TestExecutionSummary summary = listener.getSummary();
        summary.printTo(new java.io.PrintWriter(System.out));

        if (summary.getTotalFailureCount() > 0) {
            summary.getFailures().forEach(f ->
                f.getException().printStackTrace());
            System.exit(1);
        }
    }
}
