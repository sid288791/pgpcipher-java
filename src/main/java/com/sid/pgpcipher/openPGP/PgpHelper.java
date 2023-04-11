package com.sid.pgpcipher.openPGP;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.nio.charset.Charset;
import java.util.Iterator;

public class PgpHelper {

    static byte[] compressFile(String fileName, int algo) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algo);
        PGPUtil.writeFileToLiteralData(comData.open(bout), PGPLiteralData.BINARY, new File(fileName));
        comData.close();
        return bout.toByteArray();
    }

    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyId, char[] pass) throws PGPException {
        PGPSecretKey pgpSecretKey = pgpSec.getSecretKey(keyId);
        return pgpSecretKey != null ? pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass)) : null;
    }

    public static PGPPublicKey readPubKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPubKey(keyIn);
        keyIn.close();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(out);
        pubKey.encode(armoredOutputStream);
        String str = new String(out.toByteArray(), Charset.forName("US-ASCII"));
        System.out.println(str);
        return pubKey;
    }

    private static PGPPublicKey readPubKey(InputStream keyIn) throws IOException, PGPException {

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
        Iterator itr = pgpPub.getKeyRings();
        while (itr.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) itr.next();
            Iterator keyitr = keyRing.getPublicKeys();
            while (keyitr.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyitr.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }

        }
        throw new IllegalArgumentException("no encryption key in key ring");
    }

    public static PGPPrivateKey readSecretKey(String fileName, String pass) throws PGPException, IOException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secretKey = readSecretKey(keyIn);
        keyIn.close();
        return secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass.toCharArray()));
    }

    private static PGPSecretKey readSecretKey(InputStream keyIn) throws IOException, PGPException {

        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
            Iterator keyItr = keyRing.getSecretKeys();
            while (keyItr.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyItr.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("no encryption key in key ring");

    }
}


