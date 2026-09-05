package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.cp.soft.exception.KeyDecryptionFailedException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.KeyTypeNotImportableException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pqc.jcajce.interfaces.FalconPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * A key pair read out of protected key material the platform sent.
 *
 * <p>
 * The material carries only the private key, so the public half is worked out from it: every algorithm this provider
 * supports either states the public key inside the private one or lets it be computed. The provider stores both halves,
 * so a key that arrives cannot be stored until its public half is known.
 * </p>
 *
 * <p>
 * Which algorithm the material holds is not stated anywhere in the request: the key's own structure says it. Rather
 * than mapping every object identifier a parameter set can carry, each algorithm this provider supports is offered the
 * material and the one that accepts it is the answer. That is a handful of cheap parses on a few kilobytes, and it
 * cannot fall behind the set of algorithms the provider supports.
 * </p>
 */
public final class ImportedKeyMaterial {

    /**
     * The algorithms offered the material, and how each one is read. The algorithms that also sign a digest of a
     * message state a parameter set of their own for that form, which the reader of the plain form refuses, so each is
     * offered under both names.
     */
    private static final List<Reader> READERS = List
            .of(reader(KeyAlgorithm.RSA), reader(KeyAlgorithm.ECDSA), reader(KeyAlgorithm.MLDSA),
                    new Reader(KeyAlgorithm.MLDSA, "HASH-ML-DSA", BouncyCastleProvider.PROVIDER_NAME),
                    reader(KeyAlgorithm.SLHDSA),
                    new Reader(KeyAlgorithm.SLHDSA, "HASH-SLH-DSA", BouncyCastleProvider.PROVIDER_NAME),
                    reader(KeyAlgorithm.MLKEM), new Reader(KeyAlgorithm.FALCON, KeyAlgorithm.FALCON.getCode(),
                            BouncyCastlePQCProvider.PROVIDER_NAME));

    /** An algorithm read under the name it calls itself, by the provider that implements most of them. */
    private static Reader reader(KeyAlgorithm algorithm) {
        return new Reader(algorithm, algorithm.getCode(), BouncyCastleProvider.PROVIDER_NAME);
    }

    private final KeyAlgorithm algorithm;

    private final KeyPair keyPair;

    private ImportedKeyMaterial(KeyAlgorithm algorithm, KeyPair keyPair) {
        this.algorithm = algorithm;
        this.keyPair = keyPair;
    }

    /**
     * Opens protected key material and reads the key pair out of it.
     *
     * <p>
     * The protection profile is the one the contract pins, and the envelope was checked against it before this is
     * called, so material that does not open is material the passphrase does not match. The profile carries no
     * integrity protection, so opening it says something about the passphrase and nothing about who produced it.
     * </p>
     *
     * @param envelope the DER-encoded PKCS#8 EncryptedPrivateKeyInfo
     * @param passphrase the passphrase the platform protected it under
     * @return the key pair the material carries
     */
    public static ImportedKeyMaterial open(byte[] envelope, String passphrase) {
        PKCS8EncodedKeySpec privateKeySpec = decrypt(envelope, passphrase);
        for (Reader reader : READERS) {
            PrivateKey privateKey = reader.read(privateKeySpec);
            if (privateKey != null) {
                return new ImportedKeyMaterial(reader.algorithm(),
                        new KeyPair(publicKeyOf(privateKey, reader), privateKey));
            }
        }
        throw noReaderAccepted(privateKeySpec);
    }

    /**
     * @return the algorithm the material holds
     */
    public KeyAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * @return the key pair, whose public half was worked out from the private one
     */
    public KeyPair keyPair() {
        return keyPair;
    }

    /**
     * Why no reader took the key. A key that is a private key of an algorithm this provider does not hold is a key type
     * it cannot take in, which the contract names, and is told apart from bytes that are no key at all.
     */
    private static RuntimeException noReaderAccepted(PKCS8EncodedKeySpec privateKeySpec) {
        try {
            String named = PrivateKeyInfo
                    .getInstance(privateKeySpec.getEncoded())
                    .getPrivateKeyAlgorithm()
                    .getAlgorithm()
                    .getId();
            return new KeyTypeNotImportableException(
                    "A key of algorithm " + named + " cannot be imported into this token");
        } catch (RuntimeException e) {
            return new KeyManagementException("The key material holds no private key");
        }
    }

    /**
     * The private key inside the envelope. The pinned profile is PBES2, whose parameters live in the envelope itself,
     * so the decryption is driven by what the envelope states rather than by anything the request said.
     */
    private static PKCS8EncodedKeySpec decrypt(byte[] envelope, String passphrase) {
        try {
            PKCS8EncryptedPrivateKeyInfo protectedKey = new PKCS8EncryptedPrivateKeyInfo(envelope);
            InputDecryptorProvider decryptor = new JcePKCSPBEInputDecryptorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(passphrase.toCharArray());
            return new PKCS8EncodedKeySpec(protectedKey.decryptPrivateKeyInfo(decryptor).getEncoded());
        } catch (IOException e) {
            throw new KeyDecryptionFailedException("The key material is not protected key material");
        } catch (PKCSException e) {
            throw new KeyDecryptionFailedException(
                    "The key material does not open with the passphrase that came with it");
        }
    }

    /**
     * The public half of an imported key. The lattice and hash-based algorithms state it inside the private key, RSA
     * carries the two numbers it is made of, and an elliptic-curve public key is the curve's generator taken to the
     * power of the private value.
     */
    private static PublicKey publicKeyOf(PrivateKey privateKey, Reader reader) {
        try {
            return switch (privateKey) {
                case RSAPrivateCrtKey rsa -> KeyFactory
                        .getInstance(KeyAlgorithm.RSA.getCode(), BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
                case ECPrivateKey ec -> KeyFactory
                        .getInstance(KeyAlgorithm.ECDSA.getCode(), BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(
                                new ECPublicKeySpec(ec.getParameters().getG().multiply(ec.getD()), ec.getParameters()));
                case MLDSAPrivateKey mldsa -> mldsa.getPublicKey();
                case SLHDSAPrivateKey slhdsa -> slhdsa.getPublicKey();
                case MLKEMPrivateKey mlkem -> mlkem.getPublicKey();
                case FalconPrivateKey falcon -> falcon.getPublicKey();
                default -> throw new KeyManagementException(
                        "The public half of an imported " + reader.algorithm().getCode() + " key cannot be worked out");
            };
        } catch (GeneralSecurityException e) {
            throw new KeyManagementException(
                    "The public half of an imported " + reader.algorithm().getCode() + " key cannot be worked out");
        }
    }

    /**
     * One algorithm the material is offered to. A reader that does not recognise the material answers with nothing,
     * which is how the algorithm is identified rather than by reading an object identifier.
     */
    private record Reader(KeyAlgorithm algorithm, String named, String provider) {

        private PrivateKey read(PKCS8EncodedKeySpec privateKeySpec) {
            try {
                return KeyFactory.getInstance(named, provider).generatePrivate(privateKeySpec);
            } catch (GeneralSecurityException e) {
                return null;
            }
        }
    }
}
