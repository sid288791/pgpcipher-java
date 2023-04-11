package com.sid.pgpcipher.openPGP;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

public class KeyPairGenerator {

    PGPKeyPair createKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException, PGPException {
        java.security.KeyPairGenerator kpGen = java.security.KeyPairGenerator.getInstance("DH","BC");
        kpGen.initialize(2048);
        KeyPair kp = kpGen.generateKeyPair();
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT,kp,new Date());
        return pgpKeyPair;
    }
}
