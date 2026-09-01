package com.czertainly.cp.soft.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Produces secrets in the encoding this release replaced.
 *
 * <p>This is the encryption side of the old scheme, which {@link SecretsUtil} no longer has:
 * it writes only the current encoding, and keeps the old one for reading. Reproducing the old
 * writer here is what lets the compatibility path be tested against values shaped like the
 * ones already sitting in deployed databases, rather than against something the current code
 * produced.</p>
 */
final class LegacySecrets {

    private static final String ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
    private static final int ITERATIONS = 1000;

    private LegacySecrets() {
    }

    static String encryptV1(String secret, String encryptionKey) {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE,
                    factory.generateSecret(new PBEKeySpec(encryptionKey.toCharArray(), salt, ITERATIONS)));
            byte[] encrypted = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));

            return SecretEncodingVersion.V1.getVersion()
                    + "|" + Base64.getEncoder().encodeToString(encrypted)
                    + "|" + Base64.getEncoder().encodeToString(salt)
                    + "|" + ITERATIONS;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot produce a value in the previous encoding", e);
        }
    }
}
