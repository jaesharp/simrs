/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.oracle.jcclassic.samples.arrayview.ClientApplet;

import java.io.IOException;

import com.oracle.jcclassic.samples.arrayview.MyShareable.MyShareable;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.framework.Resources;
import javacard.framework.Util;

public class ClientApplet extends Applet implements MultiSelectable {

    // Class variables.
    private final static byte SW1_RESULT             = (byte)0x90; // SW1 byte
    private final static byte OK                     = (byte)0x00; // SW2 byte
    private final static byte FAILED_RESOURCE_ACCESS = (byte)0x7E; // SW2 byte
    private final static byte FAILED_RESOURCE_VIEW   = (byte)0x7F; // SW2 byte

    // Server applet AID
    private final static byte[] SERVER_APPLET_AID_BYTES = { (byte) 0xA0, 0x00, 0x00, 0x00, (byte) 0x62, 0x03, 0x01, 0x0C, 0x0C, 0x02 };

    private final static short DATA_SIZE = 10;

    MyShareable sio = null;

    /**
     * constructor
     * @param bArray from install().
     * @param bOffset from install().
     * @param bLength from install().
     */
    protected ClientApplet(byte bArray[], short bOffset, byte bLength) {
        // register this applet instance with JCRE using the default AID
        register();
    }

    /*
     * install() - create and install an instance of the ClientApplet class
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ClientApplet(bArray, bOffset, bLength);
    }

    /*
     * Gets the SIO of server applet.
     */
    private boolean getSIO() {

        if (this.sio == null) {
            this.sio = (MyShareable)JCSystem.getAppletShareableInterfaceObject(
                JCSystem.lookupAID(SERVER_APPLET_AID_BYTES,(short)0, (byte)(SERVER_APPLET_AID_BYTES.length)),
                (byte)0);
        }
        return (this.sio != null);
    }

    /*
     * process() - process APDU commands
     */
    @Override
    public void process(APDU apdu) {

        if (selectingApplet()) {
            return;
        }

        // Any other INS is accepted
        byte status = this.provideRscView(apdu.getBuffer());
        // Signal success
        ISOException.throwIt (Util.makeShort(SW1_RESULT, status));
    }

    public byte provideRscView(byte[] buffer) {

        Resources resources = null;
        byte[] resourceView = null;
        byte[] arrayView    = null;

        if(!getSIO()){
           ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        try{
            resources = Resources.getResources();
        } catch (RuntimeException e){
            ISOException.throwIt (Util.makeShort(SW1_RESULT, FAILED_RESOURCE_ACCESS));
        }

        try{
            // Create a resource view on the first ten bytes of the resource
            resourceView = resources.getView((short)1, (short)0, DATA_SIZE);
            // Now we create in the context of the 'sio' another read-only view on the first 10 bytes of the resource.
            // Only the server context will be able to access to this view.
            arrayView = JCSystem.makeByteArrayView(resourceView, (short)0, DATA_SIZE, JCSystem.ATTR_READABLE_VIEW, sio);
        } catch (IOException | RuntimeException e){
            ISOException.throwIt (Util.makeShort(SW1_RESULT, FAILED_RESOURCE_VIEW));
        }

        // Now we provide the ArrayView to the server side
        return sio.handleRscView(arrayView);
    }

    @Override
    public boolean select() {
        return getSIO();
    }

    @Override
    public void deselect() {
        sio = null;
    }

    @Override
    public boolean select(boolean appInstAlreadySelected) {
        return getSIO();
    }

    @Override
    public void deselect(boolean appInstStillSelected) {
        sio = null;
    }
}
