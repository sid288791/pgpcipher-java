package com.sid.pgpcipher.openPGP;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

public class EncryptionByPubKey {

    public static byte[] encryptFile(PGPPublicKey publicKey, byte[] data) throws IOException, PGPException {
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom()).setProvider("BC"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
                .setProvider("BC"));

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream cout = encGen.open(encOut, new byte[4096]);

        PGPLiteralDataGenerator ldata = new PGPLiteralDataGenerator();
        OutputStream pout = ldata.open(cout, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
        pout.write(data);
        pout.close();
        cout.close();
        return encOut.toByteArray();
    }
}

