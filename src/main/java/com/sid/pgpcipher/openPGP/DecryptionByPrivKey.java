package com.sid.pgpcipher.openPGP;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.InputStream;

public class DecryptionByPrivKey {

    public static byte[] decryptFile(PGPPrivateKey privateKey, byte[] encryptData) throws IOException, PGPException {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(encryptData);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();

        PGPPublicKeyEncryptedData encData = null;
        for (PGPEncryptedData pgpEnc : encList){
            PGPPublicKeyEncryptedData pkEnc = (PGPPublicKeyEncryptedData) pgpEnc;
            if(pkEnc.getKeyID() == privateKey.getKeyID()){
                encData = pkEnc;
                break;
            }
        }
        if (encData == null){
            throw new IllegalStateException("matching encrypted data not found");
        }

        PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC")
                .build(privateKey);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);
        byte[] literalData = Streams.readAll(clear);
        clear.close();

        if(encData.verify()){
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
            byte[] data = Streams.readAll(litData.getInputStream());
            return data;
        }

        throw new IllegalStateException("modification check failed");
    }
}
