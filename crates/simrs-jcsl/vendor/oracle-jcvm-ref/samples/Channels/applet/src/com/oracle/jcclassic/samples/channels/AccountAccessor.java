/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.oracle.jcclassic.samples.channels;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacardx.apdu.ExtendedLength;

/**
 * This applet keeps track of the account information for a fictional wireless
 * device connecting to a network service. The device has a home area, but it is
 * also capable of operating in remote areas at a higher rate. Using the device
 * debuts the amount of available credits. The terminal can also add credits to
 * the account via a specific command.
 */

public class AccountAccessor extends Applet implements MultiSelectable, ExtendedLength {

    // code of CLA byte in the command APDU header
    final static byte AA_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte GET_BALANCE = (byte) 0x10;
    final static byte CREDIT = (byte) 0x20;

    final static short MAX_BALANCE = (short) 0x7FFF;
    final static short SW_MAX_BALANCE_EXCEEDED = (short) 0x6A54;
    final static short SW_INVALID_TRANSACTION_AMOUNT = (short) 0x6A55;

    // Account status constants
    final static byte AREA_HOME = (byte) 0;
    final static byte AREA_REMOTE = (byte) 1;

    // ConnectionManager AID
    final static byte[] CONNECTION_MGR_AID_BYTES = { (byte) 0xA0, 0, 0, 0, (byte) 0x62, 0x03, 0x01, 0x0C, 0x0B, 0x2 };

    // error return status
    final static short SW_NO_CONNECTION = (short) 0x6905;

    // Connection data
    private short[] chargeRate;
    private short balance;
    private short homeArea;

    static AccountAccessor theAccount = null;

    private static void setAccount(AccountAccessor account) {
        theAccount = account;
    }

    private AccountAccessor(byte[] bArray, short bOffset, byte bLength) {
        chargeRate = new short[2];
        setAccount(this);

        byte iLen = bArray[bOffset]; // aid length
        bOffset   = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset   = (short) (bOffset + cLen + 1);
        // byte aLen = bArray[bOffset];     // applet data length
        bOffset   = (short) (bOffset+1);    // applet data

        // Set up initial account information
        balance = 0;
        homeArea = (short) ((short) (bArray[bOffset++] << (short) 8) | (short) (bArray[bOffset++] & 0x00FF));

        chargeRate[AREA_HOME]   = (short) ((short) (bArray[bOffset++] << (short) 8) | (short) (bArray[bOffset++] & (short) 0x00FF));
        chargeRate[AREA_REMOTE] = (short) ((short) (bArray[bOffset++] << (short) 8) | (short) (bArray[bOffset] & (short) 0x00FF));

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new AccountAccessor(bArray, bOffset, bLength);
    }

    @Override
    public boolean select() {
        return true;
    }

    @Override
    public void deselect() {
        // Nothing to do
    }

    public boolean select(boolean appInstAlreadySelected) {
        return true;
    }

    public void deselect(boolean appInstStillSelected) {
        // Nothing to do
    }

    @Override
    public void process(APDU apdu) {

        byte[] buffer = apdu.getBuffer();

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    boolean debit(short areaCode, boolean contactless) {
        short amtToDebit;
        if (areaCode == homeArea) {
            amtToDebit = chargeRate[AREA_HOME];
        } else {
            amtToDebit = chargeRate[AREA_REMOTE];
        }
        // charge more if contactless
        if (contactless) {
            amtToDebit += 20;
        }

        if (balance >= amtToDebit) {
            JCSystem.beginTransaction();
            balance = (short) (balance - amtToDebit);
            JCSystem.commitTransaction();
            return true;
        }
        return false;
    }

    public static AccountAccessor getAccount() {
        return theAccount;
    }

    private void credit(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if ((numBytes != 2) || (byteRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short creditAmount = (short) ((short) (buffer[ISO7816.OFFSET_CDATA]     << (short) 8) |
                                      (short) (buffer[ISO7816.OFFSET_CDATA + 1] &  (short) 0xFF));

        // Note: creditAmount always <= 32767 (0x7fff) because variable type is short
        if (creditAmount < (short) 0) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        if ((short) (balance + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_MAX_BALANCE_EXCEEDED);
        }

        JCSystem.beginTransaction();
        balance = (short) (balance + creditAmount);
        JCSystem.commitTransaction();

    }

    private void getBalance(APDU apdu) {

        AID connection_aid = JCSystem.lookupAID(CONNECTION_MGR_AID_BYTES, (short) 0,
                (byte) CONNECTION_MGR_AID_BYTES.length);
        if (!(JCSystem.isAppletActive(connection_aid))) {
            ISOException.throwIt(SW_NO_CONNECTION);
        }

        byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        apdu.setOutgoingLength((byte) 2);

        buffer[0] = (byte) (balance >> (short) 8);
        buffer[1] = (byte) (balance & (short) 0x00FF);

        apdu.sendBytes((short) 0, (short) 2);
    }

}
