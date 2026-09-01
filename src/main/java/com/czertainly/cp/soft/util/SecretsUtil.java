package com.czertainly.cp.soft.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Encrypts and decrypts the secrets held in the database.
 *
 * <p>Values are self-describing: the first field of an encoded secret names its encoding, so
 * {@link #decodeAndDecryptSecretString(String)} can read whatever is stored without being told
 * which scheme produced it. New values are always written as
 * {@link SecretEncodingVersion#V2 V2}; {@link SecretEncodingVersion#V1 V1} is decrypted so
 * values written before the upgrade stay readable.</p>
 */
@Component
public class SecretsUtil {

    private static final Logger logger = LoggerFactory.getLogger(SecretsUtil.class);

    /** The fallback in {@code application.yml}, repeated here so its use can be reported. */
    static final String PUBLISHED_DEFAULT_KEY = "tU)u&N~B{sqQh{imRDl}";

    // V2: authenticated encryption, with the key derived per value from the stored salt.
    private static final String AEAD_ALGORITHM = "AES/GCM/NoPadding";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600000;
    private static final int AES_KEY_BIT_LENGTH = 256;
    private static final int GCM_IV_BYTE_LENGTH = 12;
    private static final int GCM_TAG_BIT_LENGTH = 128;
    private static final int SALT_BYTE_LENGTH = 32;

    /**
     * Bounds on the iteration count read back from a stored value. The count travels with the
     * secret so it can be raised over time, which also means a tampered value could otherwise
     * ask for an unbounded amount of work.
     */
    private static final int MIN_ITERATIONS = 1000;
    private static final int MAX_ITERATIONS = 5000000;

    // V1: the original scheme. Read only, kept so values written before the upgrade decrypt.
    private static final String LEGACY_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";

    private final SecureRandom random = new SecureRandom();

    private String encryptionKey;

    @Autowired
    public void setEncryptionKey(@Value("${secrets.encryption.key}") String key) {
        this.encryptionKey = key;
        if (PUBLISHED_DEFAULT_KEY.equals(key)) {
            logger.warn("ENCRYPTION_KEY is not set, so secrets are protected with the default key "
                    + "published in this connector's source. Anyone with a copy of the database can "
                    + "read them. Set ENCRYPTION_KEY to a value of your own.");
        }
    }

    /**
     * Publishes this instance for the entity accessors.
     *
     * <p>Deliberately not done when the key is set: migrations and tests build their own
     * instances, and registering those would let whichever was configured last decide the key
     * the entity uses. Only a Spring-managed bean reaches this.</p>
     */
    @PostConstruct
    void registerAsShared() {
        SecretsUtilHolder.configure(this);
    }

    /**
     * Encrypts and encodes a secret. Always produces {@link SecretEncodingVersion#V2}.
     *
     * @return the encoded secret, or {@code null} if {@code secret} was {@code null}
     */
    public String encryptAndEncodeSecretString(String secret) {
        if (secret == null) {
            return null;
        }

        byte[] salt = randomBytes(SALT_BYTE_LENGTH);
        byte[] iv = randomBytes(GCM_IV_BYTE_LENGTH);

        try {
            Cipher cipher = Cipher.getInstance(AEAD_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, deriveKey(salt, ITERATIONS),
                    new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv));
            byte[] encrypted = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));

            return SecretEncodingVersion.V2.getVersion()
                    + "|" + Base64.getEncoder().encodeToString(encrypted)
                    + "|" + Base64.getEncoder().encodeToString(salt)
                    + "|" + Base64.getEncoder().encodeToString(iv)
                    + "|" + ITERATIONS;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException("Cannot encrypt secret with " + AEAD_ALGORITHM, e);
        }
    }

    /**
     * Decrypts a stored secret, reading whichever encoding it declares.
     *
     * @throws IllegalArgumentException if the value is malformed
     * @throws IllegalStateException if it cannot be decrypted with the configured key
     */
    public String decodeAndDecryptSecretString(String secret) {
        return switch (SecretEncodingVersion.of(secret)) {
            case V2 -> decryptV2(secret);
            case V1 -> decryptV1(secret);
        };
    }

    private String decryptV2(String secret) {
        String[] parts = secret.split("\\|");
        if (parts.length != 5) {
            throw new IllegalArgumentException("Secret string is not in the correct format");
        }

        byte[] encrypted = decode(parts[1]);
        byte[] salt = decode(parts[2]);
        byte[] iv = decode(parts[3]);
        int iterations = iterationsOf(parts[4]);

        if (iv.length != GCM_IV_BYTE_LENGTH) {
            throw new IllegalArgumentException("Secret string is not in the correct format");
        }

        try {
            Cipher cipher = Cipher.getInstance(AEAD_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(salt, iterations),
                    new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (BadPaddingException e) {
            // AEADBadTagException extends BadPaddingException, so this is the authentication
            // failure GCM raises when the key is wrong or the value has been altered.
            throw new IllegalStateException("Secret failed authentication: it was encrypted with a "
                    + "different key, or the stored value has been altered", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            throw new IllegalStateException("Cannot decrypt secret with " + AEAD_ALGORITHM, e);
        }
    }

    /**
     * Reads a value written by the scheme this release replaced.
     *
     * <p>The scheme is unauthenticated and its padding is why it was replaced. It is kept
     * because the values are already in deployed databases: without it they could not be read,
     * and so could not be re-encrypted. Nothing writes this encoding.</p>
     */
    @SuppressWarnings("java:S5542")
    private String decryptV1(String secret) {
        String[] parts = secret.split("\\|");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Secret string is not in the correct format");
        }

        byte[] encrypted = decode(parts[1]);
        byte[] salt = decode(parts[2]);
        int iterations = iterationsOf(parts[3]);

        try {
            Cipher cipher = Cipher.getInstance(LEGACY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(LEGACY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE,
                    factory.generateSecret(new PBEKeySpec(encryptionKey.toCharArray(), salt, iterations)));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException
                 | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException
                 | BadPaddingException e) {
            throw new IllegalStateException("Cannot decrypt secret written with the previous scheme", e);
        }
    }

    private SecretKey deriveKey(byte[] salt, int iterations) {
        try {
            PBEKeySpec keySpec =
                    new PBEKeySpec(encryptionKey.toCharArray(), salt, iterations, AES_KEY_BIT_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            return new SecretKeySpec(factory.generateSecret(keySpec).getEncoded(), ENCRYPTION_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + KEY_DERIVATION_ALGORITHM + " not found", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid key specification", e);
        }
    }

    private static int iterationsOf(String value) {
        int iterations;
        try {
            iterations = Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Secret string is not in the correct format", e);
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("Iteration count out of range: " + iterations);
        }
        return iterations;
    }

    private static byte[] decode(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Secret string is not in the correct format", e);
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
