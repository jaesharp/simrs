/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */
package com.oracle.jcclassic.samples.wallet;

import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.NamedParameterSpec;
import javacard.security.Signature;
import javacard.security.XECPrivateKey;
import javacard.security.XECPublicKey;
import javacardx.crypto.Cipher;

public class SignerImplementation implements Signer {

    private final KeyPair kp;
    private final Signature signEngine;

    public SignerImplementation() {

        // Retrieve the domain parameters for the standardized secp256r1 curve
        NamedParameterSpec nps = NamedParameterSpec.getInstance(NamedParameterSpec.SECP256R1);

        // Allocate the private and public key objects and KeyPair with these keys
        XECPrivateKey prv_key = (XECPrivateKey) KeyBuilder.buildXECKey(nps, (short) (KeyBuilder.ATTR_PRIVATE | JCSystem.MEMORY_TYPE_PERSISTENT), false);
        XECPublicKey pub_key = (XECPublicKey) KeyBuilder.buildXECKey(nps, (short) (KeyBuilder.ATTR_PUBLIC | JCSystem.MEMORY_TYPE_PERSISTENT), false);
        this.kp = new KeyPair(pub_key, prv_key);

        // Create the Signature engine
        this.signEngine = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
    }

    @Override
    public void genKeyPair() {
        // Generate key values
        kp.genKeyPair();

        // Initialize the signature engine with the new key value
        // This operation may update persistent memory so it's only done when key value changes.
        this.signEngine.init(kp.getPrivate(), Signature.MODE_SIGN);
    }

    @Override
    public short sign(byte[] input, byte[] output) {
        return this.signEngine.sign(input, (short) 0, (short) input.length, output, (short) 0);
    }

    @Override
    public short getPublicKey(byte[] buffer) {

        XECPublicKey pub_key = (XECPublicKey)kp.getPublic();

        if ( (pub_key == null)  || !pub_key.isInitialized()) {
            return 0;
        }
        return pub_key.getEncoded(buffer, (short) 0);
    }

    @Override
    public short getSignatureLength() {
        return this.signEngine.getLength();
    }
}
