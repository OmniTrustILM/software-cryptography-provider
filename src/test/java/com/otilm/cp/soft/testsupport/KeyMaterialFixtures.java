package com.otilm.cp.soft.testsupport;

import java.security.PrivateKey;
import java.security.SecureRandom;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;

/**
 * Protected key material of the shape the platform sends, so an import can be exercised without one.
 *
 * <p>
 * The contract pins one protection profile: PBES2 over PBKDF2-HMAC-SHA256 with AES-256-CBC. What is produced here has
 * to sit inside that profile, since the connector refuses anything outside it before the material is opened.
 * </p>
 */
public final class KeyMaterialFixtures {

    /** The passphrase the platform generates for one import, which travels beside the material. */
    public static final String PASSPHRASE = "8f3c1d9a-4b21-4e6f-9c17-2d0a5b8e7f43";

    /** The iterations the contract recommends, which is well inside the range it accepts. */
    private static final int ITERATIONS = 600_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyMaterialFixtures() {
    }

    /**
     * The given private key as protected key material.
     *
     * @param privateKey the key to protect
     * @param passphrase the passphrase to protect it under
     * @return the DER-encoded PKCS#8 EncryptedPrivateKeyInfo
     */
    public static byte[] protect(PrivateKey privateKey, String passphrase) {
        try {
            JceOpenSSLPKCS8EncryptorBuilder encryptor = new JceOpenSSLPKCS8EncryptorBuilder(
                    NISTObjectIdentifiers.id_aes256_CBC);
            encryptor.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            // RFC 8018 states the PRF parameters as NULL, and the contract accepts only that shape.
            encryptor.setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));
            encryptor.setIterationCount(ITERATIONS);
            encryptor.setRandom(RANDOM);
            encryptor.setPassword(passphrase.toCharArray());

            return new PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo.getInstance(privateKey.getEncoded()))
                    .build(encryptor.build())
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot protect the key material", e);
        }
    }
}
