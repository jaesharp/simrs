/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */
package com.oracle.jcclassic.samples.wallet;

public interface Signer {

    /**
     * Create a new key pair.
     * The type and length of the keys is defined byt the service.
     */
    public void genKeyPair();

    /**
     * Copy the Public Key value in the buffer.
     * @param buffer the output buffer to update with the public key
     * @return the data length copied in the buffer
     */
    public short getPublicKey(byte[] buffer);

    /**
     * Retrieve the length of the Signature
     * @return the signature length
     */
    public short getSignatureLength();

    /**
     * Sign the input data and write the signature in the output buffer.
     * @param input the data to sign
     * @param output the signature
     * @return the signature length
     */
    public short sign(byte[] input, byte[] output);

}
