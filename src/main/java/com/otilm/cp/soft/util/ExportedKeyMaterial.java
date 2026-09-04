package com.otilm.cp.soft.util;

import com.otilm.cp.soft.exception.KeyManagementException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;

/**
 * Protects a key on its way out of a token.
 *
 * <p>
 * The contract pins one protection profile, the same one material arriving is protected with, so a key leaving is
 * readable by whatever the platform hands it to. The envelope has to open in external tools, so the passphrase is used
 * exactly as the request supplied it.
 * </p>
 */
public final class ExportedKeyMaterial {

    /** The iterations the contract recommends, well inside the range it accepts. */
    private static final int ITERATIONS = 600_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private ExportedKeyMaterial() {
    }

    /**
     * The given key as protected key material.
     *
     * @param privateKey the key leaving the token
     * @param passphrase the passphrase the request asked it to be protected under
     * @return the DER-encoded PKCS#8 EncryptedPrivateKeyInfo
     */
    public static byte[] protect(PrivateKey privateKey, String passphrase) {
        try {
            JceOpenSSLPKCS8EncryptorBuilder encryptor = new JceOpenSSLPKCS8EncryptorBuilder(
                    NISTObjectIdentifiers.id_aes256_CBC);
            encryptor.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            // RFC 8018 states the parameters of the key derivation as NULL, and the contract accepts only that shape.
            encryptor.setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));
            encryptor.setIterationCount(ITERATIONS);
            encryptor.setRandom(RANDOM);
            encryptor.setPassword(passphrase.toCharArray());

            OutputEncryptor protection = encryptor.build();
            return new PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo.getInstance(privateKey.getEncoded()))
                    .build(protection)
                    .getEncoded();
        } catch (Exception e) {
            throw new KeyManagementException("The key could not be protected on its way out of the token");
        }
    }
}
