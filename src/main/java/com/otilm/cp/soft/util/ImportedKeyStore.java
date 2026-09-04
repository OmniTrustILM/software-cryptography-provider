package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.exception.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.Stream;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Puts an imported key pair into a token's keystore, in the shape a generated one is stored in.
 *
 * <p>
 * A keystore entry holding a private key must carry a certificate chain, so a generated key is stored beside a
 * self-signed certificate that exists only to satisfy that rule. An imported key is stored the same way, so both kinds
 * of key look alike to everything that reads the keystore afterwards.
 * </p>
 *
 * <p>
 * The size a key row records comes from the parameter set, which is where a generated key takes it from as well. An
 * imported key does not carry the parameter set in its request, so it is read back from the key, which states it.
 * </p>
 */
public final class ImportedKeyStore {

    private ImportedKeyStore() {
    }

    /**
     * Stores an imported key pair under the given alias.
     *
     * @param keyStore the token's keystore
     * @param alias the alias the key is known by in the keystore
     * @param algorithm the algorithm the key material held
     * @param keyPair the imported key pair
     * @param password the code that opens the keystore
     */
    public static void store(KeyStore keyStore, String alias, KeyAlgorithm algorithm, KeyPair keyPair,
            String password) {
        X509Certificate certificate = orphanCertificate(algorithm, keyPair);
        try {
            keyStore
                    .setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(),
                            new X509Certificate[]{certificate});
        } catch (KeyStoreException e) {
            throw new KeyManagementException("The imported key could not be stored in the token");
        }
    }

    /**
     * The certificate an imported key is stored beside. Which algorithm can sign it decides how it is made: a signing
     * key signs its own, and a key exchange algorithm cannot sign at all, so its certificate is signed by a key that is
     * thrown away immediately and must never be trusted.
     */
    private static X509Certificate orphanCertificate(KeyAlgorithm algorithm, KeyPair keyPair) {
        return switch (algorithm) {
            case RSA -> X509Util.generateRsaOrphanX509Certificate(keyPair);
            case ECDSA -> X509Util.generateEcdsaOrphanX509Certificate(keyPair);
            case FALCON -> X509Util.generateFalconOrphanX509Certificate(keyPair, falconDegree(keyPair));
            case MLKEM -> X509Util.generateMLKEMOrphanX509Certificate(keyPair);
            // The key states its own parameter set, and that is the name it signs under.
            case MLDSA,
                    SLHDSA ->
                X509Util
                        .generateOrphanX509Certificate(keyPair, keyPair.getPrivate().getAlgorithm(),
                                BouncyCastleProvider.PROVIDER_NAME);
            default -> throw new KeyManagementException(
                    "An imported " + algorithm.getCode() + " key cannot be stored by this provider");
        };
    }

    /** Which Falcon the key is, which the certificate is signed under. The key names it as {@code FALCON-512}. */
    private static FalconDegree falconDegree(KeyPair keyPair) {
        String named = keyPair.getPrivate().getAlgorithm().replace('-', '_').toUpperCase();
        for (FalconDegree degree : FalconDegree.values()) {
            if (degree.name().equals(named)) {
                return degree;
            }
        }
        throw new KeyManagementException("The imported Falcon key states a degree this provider does not support");
    }

    /**
     * The size of an imported public key in bits, as a key row records it.
     *
     * @param algorithm the algorithm the key material held
     * @param keyPair the imported key pair
     * @return the size in bits
     */
    public static int publicKeySize(KeyAlgorithm algorithm, KeyPair keyPair) {
        return switch (algorithm) {
            case RSA -> modulusSize(keyPair);
            // A generated elliptic-curve public key records the field size twice over, for its two coordinates.
            case ECDSA -> fieldSize(keyPair) * 2;
            default -> sizesOf(algorithm, keyPair).publicBits();
        };
    }

    /**
     * The size of an imported private key in bits, as a key row records it.
     *
     * @param algorithm the algorithm the key material held
     * @param keyPair the imported key pair
     * @return the size in bits
     */
    public static int privateKeySize(KeyAlgorithm algorithm, KeyPair keyPair) {
        return switch (algorithm) {
            case RSA -> modulusSize(keyPair);
            case ECDSA -> fieldSize(keyPair);
            default -> sizesOf(algorithm, keyPair).privateBits();
        };
    }

    /**
     * The sizes the parameter set defines, which is where a generated key takes them from too. They cannot be measured
     * off the key: the encoded private key of a lattice or hash-based algorithm carries more than the key itself, so a
     * Falcon private key measures nearly a kilobyte over its stated size.
     */
    private static KeySizes sizesOf(KeyAlgorithm algorithm, KeyPair keyPair) {
        String named = keyPair.getPrivate().getAlgorithm();
        return switch (algorithm) {
            case FALCON -> {
                FalconDegree degree = falconDegree(keyPair);
                yield new KeySizes(degree.getPublicKeySize(), degree.getPrivateKeySize());
            }
            case MLDSA -> Stream
                    .of(MLDSASecurityCategory.values())
                    .filter(category -> named.endsWith("-" + category.getParameterSet()))
                    .findFirst()
                    .map(category -> new KeySizes(category.getPublicKeySize(), category.getPrivateKeySize()))
                    .orElseThrow(() -> unknownParameterSet(named));
            case SLHDSA -> Stream
                    .of(SLHDSASecurityCategory.values())
                    .filter(category -> named.contains("-" + category.getSecurityParameterLength()))
                    .findFirst()
                    .map(category -> new KeySizes(category.getPublicKeySize(), category.getPrivateKeySize()))
                    .orElseThrow(() -> unknownParameterSet(named));
            case MLKEM -> Stream
                    .of(MLKEMSecurityCategory.values())
                    .filter(category -> named.equals(category.getParameterSet()))
                    .findFirst()
                    .map(category -> new KeySizes(category.getPublicKeySize(), category.getPrivateKeySize()))
                    .orElseThrow(() -> unknownParameterSet(named));
            default -> throw new KeyManagementException(
                    "The size of an imported " + algorithm.getCode() + " key is not known to this provider");
        };
    }

    private static KeyManagementException unknownParameterSet(String named) {
        return new KeyManagementException(
                "The imported key states the parameter set " + named + ", which this provider does not support");
    }

    private static int modulusSize(KeyPair keyPair) {
        return ((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength();
    }

    private static int fieldSize(KeyPair keyPair) {
        return ((ECPrivateKey) keyPair.getPrivate()).getParameters().getCurve().getFieldSize();
    }

    /** What one parameter set says the two halves of its keys measure, in bits. */
    private record KeySizes(int publicBits, int privateBits) {
    }

}
