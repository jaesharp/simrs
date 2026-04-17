/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.oracle.jcclassic.samples.arrayview.ServerApplet;

import com.oracle.jcclassic.samples.arrayview.MyShareable.MyShareable;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.MultiSelectable;
import javacard.framework.Shareable;
import javacard.framework.Util;

public class ServerApplet extends Applet implements MyShareable, MultiSelectable {
    private final static byte OK                          = (byte)0x00;
    private final static byte NOT_OK                      = (byte)0x01;

    public byte[] localRscView = null;

    private final static short DATA_SIZE = 10;

    /**
     * Constructor.
     *
     * @param bArray from install().
     * @param bOffset from install().
     * @param bLength from install().
     */
    public ServerApplet(byte bArray[], short bOffset, byte bLength) {
        localRscView = new byte[DATA_SIZE];
        // register this applet instance with JCRE using the default AID
        register();
    }

    /*
     * install() - create and install an instance of the ServerApplet class
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ServerApplet(bArray, bOffset, bLength);
    }

    /*
     * process() - process APDU commands
     */
    @Override
    public void process(APDU apdu) {

        // Server is supposed to be used with Sharing only, the process method is only throwing an ISOException
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    /*
     * getShareableInterfaceObject - Called by the JCRE to obtain a shareable interface object from this server applet.
     */
    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return this;
    }

    // Shared methods

    @Override
    public byte handleRscView(byte[] rsc) {

        // The provided ArrayView on the client's resource is read-only
        // it is ok to copy it
        Util.arrayCopy(rsc, (short)0, localRscView, (short)0, DATA_SIZE);

        // It's also ok to read single elements from it
        byte firstByte = rsc[0];

        try {
            // Try to write into the read-only ArrayView - this is not allowed
            rsc[1] = firstByte;
            // At this point, a Security Exception should have been thrown
            return NOT_OK;
        }
        catch(SecurityException e) {
            // If the exception has been thrown, everything is as expected
            return OK;
        }
    }

     @Override
    public boolean select() {
         // Not intended to be selected
         return false;
    }

    @Override
    public void deselect() {
        // Nothing to do
    }

    @Override
    public boolean select(boolean appInstAlreadySelected) {
        // Not intended to be selected
        return false;
    }

    @Override
    public void deselect(boolean appInstStillSelected) {
        // Nothing to do
    }
}
