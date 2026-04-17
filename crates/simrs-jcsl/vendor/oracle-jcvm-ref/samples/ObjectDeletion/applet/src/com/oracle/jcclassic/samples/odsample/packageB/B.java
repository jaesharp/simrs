/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
 */

package com.oracle.jcclassic.samples.odsample.packageB;

import com.oracle.jcclassic.samples.odsample.libPackageC.C;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.SystemException;

/**
 * package AID - 0xA0 0x00 0x00 0x00 0x62 0x03 0x01 0x0C 0x07 0x02
 * applet AID    0xA0 0x00 0x00 0x00 0x62 0x03 0x01 0x0C 0x07 0x02 0x01
 *
 * Applet used to demonstrate applet deletion and package deletion. It also
 * demonstrates dependencies by sharing references to objects and sharable
 * references across packages
 */
public class B extends Applet implements Shareable, AppletEvent {

    static BTreeNode sObjBTN = null;
    static B sbFirst = null;
    short data;
    BTreeNode oBTN = null;
    B bFirst = null;
    B bRef = null;

    /**
     * method instantiates an instance of B passing the arguments
     */
    public static void install(byte[] bArr, short bOffset, byte bLength) {
        new B(bArr, bOffset, bLength);
    }

    /**
     * method returns pointer to this instance, ignores the param
     */
    @Override
    public Shareable getShareableInterfaceObject(AID client_aid, byte param) {
        return this;
    }

    private static void setSbFirst ( B b){
        sbFirst = b;
    }

    /**
     * Constructor. Makes 2nd instance have a reference to the 1st instance. The
     * 2nd instance also has a reference to the BTreeNode object owned by the
     * 1st instance. Also registers with either the default AID or the one
     * provided in parameters
     */
    private B(byte[] bArray, short offset, byte length) {
        data = C.DATA;
        if (sObjBTN == null) {
            oBTN = new BTreeNode(data);
            sObjBTN = oBTN;
            setSbFirst(this);
            bFirst = this;
        } else {
            // move static reference to BTreeNode object into instance field
            oBTN = sObjBTN;
            sObjBTN = null;
            // move static reference to B's first instance into instance field
            bFirst = sbFirst;
            setSbFirst(null);
            try {
                JCSystem.requestObjectDeletion();
            }
            catch (SystemException ex) {}
        }
        // register
        try {
            if (bArray[offset] == (short) 0) {
                this.register();
            } else {
                this.register(bArray, (short) (offset + 1), bArray[offset]);
            }
        }
        catch (SystemException ex) {}
    }

    /**
     * method processes the APDU commands passed to this applet instance. It
     * only accepts the SELECT and SETUP dependency(0x12) commands.
     */
    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            return;
        } else if (buffer[ISO7816.OFFSET_CLA] == (byte) 0x80) {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case 0x12:
                    // setup reference from B's first instance to this
                    bFirst = this;
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }


    /**
     * method resets reference in bRef field to null. This is called to remove
     * applet dependency
     */
    public void resetReference() {
        bRef = null;
    }

    /**
     * Read access to B
     */
    B getReference() {
        return bRef;
    }

    /**
     * Write access to B
     */
    void setReference(B ref) {
        bRef = ref;
    }

    /**
     * uninstall method called before applet deletion
     */
    @Override
    public void uninstall() {
        bFirst.resetReference();
    }
}
