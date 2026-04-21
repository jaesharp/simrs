package com.simrs.jcardengine;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.Util;

/**
 * Minimal JavaCard applet bundled in the bridge JAR for smoke testing.
 *
 * <p>JCardEngine 26.04.06 does not ship any sample applets (jcardsim's
 * {@code com.licel.jcardsim.samples.HelloWorldApplet} is absent from
 * the fork). This class fills that gap so the Rust integration test
 * has a stable target: SELECT returns success, any other INS echoes
 * the five-byte literal {@code 'H','e','l','l','o'}.
 *
 * <p>Behaviour intentionally trivial -- the smoke test's job is to
 * exercise the framing protocol and process lifecycle, not the applet
 * surface.
 */
public final class HelloWorldApplet extends Applet {

    private static final byte[] HELLO = new byte[] { 'H', 'e', 'l', 'l', 'o' };

    /** Entry point invoked by the JCRE during {@code install}. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorldApplet().register();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return; // respond 9000 to SELECT implicitly
        }
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(HELLO, (short) 0, buffer, (short) 0, (short) HELLO.length);
        apdu.setOutgoingAndSend((short) 0, (short) HELLO.length);
    }
}
