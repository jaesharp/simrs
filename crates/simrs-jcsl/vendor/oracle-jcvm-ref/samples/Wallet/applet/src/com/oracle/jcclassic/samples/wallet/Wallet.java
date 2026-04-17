/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */
package com.oracle.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.security.util.MonotonicCounter;

public class Wallet extends Applet {

    // code of CLA byte in the command APDU header
    final static byte WALLET_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte VERIFY      = (byte) 0x20;
    final static byte CREDIT      = (byte) 0x30;
    final static byte DEBIT       = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte GEN_KEYPAIR = (byte) 0x70;

    // maximum balance
    final static short MAX_BALANCE = 0x7FFF;

    // maximum transaction amount
    final static byte MAX_TRANSACTION_AMOUNT = 127;

    // maximum number of incorrect tries before the PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;

    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;

    // signal that the PIN verification is required
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    // signal invalid transaction amount: 
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;

    // signal that the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;

    // signal that the keys can not be generated
    final static short SW_KEY_GENERATION_FAILED = 0x6A86;

    // size of Monotonic Counter
    final static short COUNTER_SIZE = (short) 4;

    private short balance;
    private final OwnerPIN pin;
    private final Signer signer;
    private final MonotonicCounter counter;

    private Wallet(byte[] params, short offset, byte length) {

        // Allocate objects required during the application lifetime
        this.pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        this.signer  = (Signer) new SignerImplementation();
        this.counter = MonotonicCounter.getInstance(COUNTER_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT);

        // The install parameters (from install method) are encoded in (L,V) format
        // and contain the following (see JCRE 11.2.1):
        // - instance AID to use for this Applet instance
        // - control info (Installer specific)
        // - applet data that can be used to personalize the Applet
        byte iLen = (byte)(params[(short)(offset)] & 0x7F);                    // instance AID length
        byte cLen = (byte)(params[(short)(offset + iLen + 1)] & 0x7F);         // control info length
        byte aLen = (byte)(params[(short)(offset + iLen + cLen + 2)] & 0x7F);  // applet data length

        // check if install parameters contain illegal value(s)
        if ((short)(iLen + cLen + aLen + 3) > length) {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }
        // The applet data contains the PIN value
        pin.update(params, (short) (offset + iLen + cLen + 3), aLen);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance and register it
        new Wallet(bArray, bOffset, bLength).register();
    }

    @Override
    public boolean select() {
        // The applet declines to be selected if the pin is blocked.
        // This implies that the Applet must now be deleted and re-installed
        return (pin.getTriesRemaining() != 0);
    }

    @Override
    public void deselect() {
        // reset the pin value
        pin.reset();
     }
   
    @Override
    public void process(APDU apdu) {

        // APDU object carries a byte array (buffer) to transfer incoming and outgoing 
        // APDU command and response between the client application and the Applet

        // Immediately returns if the APDU command is a SELECT
        if (selectingApplet()) {
            return;
        }

        // At this point, only the first header bytes [CLA, INS, P1, P2, P3] are 
        // available in the APDU buffer.
        byte[] buffer = apdu.getBuffer();
        
        // verify that the received command has the expected CLA byte
        // which specifies the command structure
        if (buffer[ISO7816.OFFSET_CLA] != WALLET_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // switch based on the INS byte of the APDU header to 
        // the implementations for the different commands
        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verifyPin(apdu);
                return;
            case GEN_KEYPAIR:
                genKeyPair(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // Implement the CREDIT command
    private void credit(APDU apdu) {

        // user authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        // Lc byte denotes the number of bytes in the
        // data field of the command APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        if ((numBytes != 1) || (byteRead != 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get the credit amount
        byte creditAmount = buffer[ISO7816.OFFSET_CDATA];

        // check the credit amount 
        if (((creditAmount & 0xFF) > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }

        // credit the amount
        balance = (short) (balance + creditAmount);

        // add receipt and send response
        short offset = addReceipt(creditAmount, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, offset);

    }

    // Implement the DEBIT command
    private void debit(APDU apdu) {

        // user authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        byte numBytes = (buffer[ISO7816.OFFSET_LC]);

        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if ((numBytes != 1) || (byteRead != 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get debit amount
        byte debitAmount = buffer[ISO7816.OFFSET_CDATA];

        // check debit amount
        if (((debitAmount & 0xFF) > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance - debitAmount) < (short) 0) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }

        balance = (short) (balance - debitAmount);

        // add receipt and send response
        short offset = addReceipt(debitAmount, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, offset);

    }

    // Implement the GET BALANCE command
    private void getBalance(APDU apdu) {

        // Configure the APDU protocol for sending data
        // and retrieve the response length expected by the client
        short le = apdu.setOutgoing();

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Configure the data length for the response
        apdu.setOutgoingLength((byte) 2);

        // copy the balance value into the APDU buffer (big-endian)
        Util.setShort(apdu.getBuffer(), (short)0, balance);

        // send the 2-byte balance stored at the offset 0 in the APDU buffer
        apdu.sendBytes((short) 0, (short) 2);
    }

    // Implement a VERIFY PIN command
    private void verifyPin(APDU apdu) {

        byte[] buffer = apdu.getBuffer();

        // Receive the PIN data in the APDU buffer, at offset ISO7816.OFFSET_CDATA
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // Check PIN data
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }

    // Implement the GENERATE KEY command
    private void genKeyPair(APDU apdu) {

        // user authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        // Create the KeyPair and send back the public key
        try {
            signer.genKeyPair();

            // export the generated public key in APDU buffer
            short temp = signer.getPublicKey(apdu.getBuffer());

            // Send the public key
            apdu.setOutgoingAndSend((short) 0, temp);

        } catch(CryptoException e) {
            ISOException.throwIt(SW_KEY_GENERATION_FAILED);
        }
    }

    // Generates a response buffer with
    // - the transaction amount
    // - the incremented value of the monotonic counter
    // - a signature
    private short addReceipt(short amount, byte[] output, short offset) {
        short position = offset;
        try {
            counter.incrementBy((short) 1);

            // write amount + counter
            position = Util.setShort(output, position, amount);
            position = counter.get(output, position);

            // write signature
            position += signer.sign(
                // creates a read-only view on input data to sign
                JCSystem.makeByteArrayView(output, offset, (short)(position - offset), JCSystem.ATTR_READABLE_VIEW, null), 
                // creates a write-only view on the output buffer where the signature must be stored
                JCSystem.makeByteArrayView(output, position, (short)(output.length - position), JCSystem.ATTR_WRITABLE_VIEW, null)
            );

        } catch (ArithmeticException | CryptoException | SystemException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        return position;
    }
}
