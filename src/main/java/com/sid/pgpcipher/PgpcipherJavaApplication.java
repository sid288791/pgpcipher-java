package com.sid.pgpcipher;

import com.sid.pgpcipher.openPGP.DecryptionByPrivKey;
import com.sid.pgpcipher.openPGP.EncryptionByPubKey;
import com.sid.pgpcipher.openPGP.PgpHelper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;

@SpringBootApplication
public class PgpcipherJavaApplication {

	public static void main(String[] args) throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());

        String file_to_enc = "";
        byte[] msg = Files.readAllBytes(Paths.get(file_to_enc));

        String pub_key_asc_file = "";
        PGPPublicKey pgpPublicKey = PgpHelper.readPubKey(pub_key_asc_file);

        String enc_output_file = "";
        byte[] encData = EncryptionByPubKey.encryptFile(pgpPublicKey,msg);
        FileUtils.writeByteArrayToFile(new File(enc_output_file),encData);

        String priv_key = "";
        String passPhrase = "";
        PGPPrivateKey pgpPrivateKey = PgpHelper.readSecretKey(priv_key,passPhrase);

        String enc_file = "";
        byte[] encFileData = Files.readAllBytes(Paths.get(enc_file));

        byte[] decData = DecryptionByPrivKey.decryptFile(pgpPrivateKey,encFileData);

        String dec_output_file = "";
        FileUtils.writeByteArrayToFile(new File(dec_output_file),decData);
	}

}
