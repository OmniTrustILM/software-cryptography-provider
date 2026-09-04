package com.otilm.cp.soft.util;

import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public class KeyStoreUtil {

    public static final String CERTIFICATE_EXCEPTION_FOR_KEY_STORE = "Certificate exception for KeyStore";
    public static final String INVALID_KEY_STORE = "Invalid KeyStore ";
    public static final String CANNOT_CREATE_NEW_KEY_STORE = "Cannot create new KeyStore";
    public static final String INVALID_ALGORITHM_FOR_KEY_STORE = "Invalid algorithm for KeyStore ";
    public static final String PROVIDER_NOT_FOUND = "Provider not found";
    public static final String CODE_REQUIRED = "A keystore can be neither made nor opened without a code";

    private KeyStoreUtil() {
    }

    /**
     * The code as a keystore takes it. A code that is not there is a caller that did not require one of its own, which
     * is a fault in this connector rather than anything about the request, so it is stated as one.
     */
    private static char[] password(String code) {
        if (code == null) {
            throw new IllegalArgumentException(CODE_REQUIRED);
        }
        return code.toCharArray();
    }

    public static byte[] createNewKeystore(String type, String code) {
        try {
            KeyStore ks = KeyStore.getInstance(type, BouncyCastleProvider.PROVIDER_NAME);
            char[] password = password(code);
            ks.load(null, password);

            // store the keystore
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, password);

            return baos.toByteArray();
        } catch (CertificateException e) {
            throw new IllegalStateException(CERTIFICATE_EXCEPTION_FOR_KEY_STORE, e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(INVALID_KEY_STORE, e);
        } catch (IOException e) {
            throw new IllegalStateException(CANNOT_CREATE_NEW_KEY_STORE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(INVALID_ALGORITHM_FOR_KEY_STORE, e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        }
    }

    public static byte[] saveKeystore(KeyStore ks, String code) {
        try {
            char[] password = code.toCharArray();
            // store the keystore
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, password);

            return baos.toByteArray();
        } catch (CertificateException e) {
            throw new IllegalStateException(CERTIFICATE_EXCEPTION_FOR_KEY_STORE, e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(INVALID_KEY_STORE, e);
        } catch (IOException e) {
            throw new IllegalStateException(CANNOT_CREATE_NEW_KEY_STORE, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(INVALID_ALGORITHM_FOR_KEY_STORE, e);
        }
    }

    public static KeyStore loadKeystore(byte[] data, String code) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            char[] password = password(code);
            ks.load(new ByteArrayInputStream(data), password);
            return ks;
        } catch (CertificateException e) {
            throw new IllegalStateException(CERTIFICATE_EXCEPTION_FOR_KEY_STORE, e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(INVALID_KEY_STORE, e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot instantiate KeyStore: " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(INVALID_ALGORITHM_FOR_KEY_STORE, e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        }
    }

    public static SpkiKeyValue spkiKeyValueFromKeyStore(KeyStore keyStore, String alias) {
        try {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            return new SpkiKeyValue(Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded()));
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot get public key with alias '" + alias + "' from KeyStore", e);
        }
    }

    public static SpkiKeyValue spkiKeyValueFromPrivateKey(KeyStore keyStore, String alias, String password) {
        try {
            MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyStore.getKey(alias, password.toCharArray());
            return new SpkiKeyValue(Base64.getEncoder().encodeToString(privateKey.getPublicKey().getEncoded()));
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot open KeyStore", e);
        } catch (UnrecoverableKeyException e) {
            throw new IllegalStateException("Cannot get private key with alias '" + alias + "' from KeyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm", e);
        }
    }

    public static void generateRsaKey(KeyStore keyStore, String alias, int keySize, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(keySize);
            final KeyPair kp = kpg.generateKeyPair();

            final X509Certificate cert = X509Util.generateRsaOrphanX509Certificate(kp);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate RSA key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        }
    }

    public static void generateEcdsaKey(KeyStore keyStore, String alias, EcdsaCurveName curveName, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec(curveName.name()));
            final KeyPair kp = kpg.generateKeyPair();

            final X509Certificate cert = X509Util.generateEcdsaOrphanX509Certificate(kp);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate ECDSA key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ECDSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid curve name `" + curveName.getName() + "`", e);
        }
    }

    public static void generateFalconKey(KeyStore keyStore, String alias, FalconDegree degree, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BCPQC");

            switch (degree) {
                case FALCON_512 -> kpg.initialize(FalconParameterSpec.falcon_512);
                case FALCON_1024 -> kpg.initialize(FalconParameterSpec.falcon_1024);
                default -> throw new IllegalStateException("Invalid Falcon degree");
            }

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert;

            if (degree == FalconDegree.FALCON_512) {
                cert = X509Util.generateFalconOrphanX509Certificate(kp, FalconDegree.FALCON_512);
            } else {
                cert = X509Util.generateFalconOrphanX509Certificate(kp, FalconDegree.FALCON_1024);
            }
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Falcon algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid Falcon algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate Falcon key", e);
        }
    }

    public static void generateMLDSAKey(KeyStore keyStore, String alias, MLDSASecurityCategory level,
            boolean forPreHash, String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);

            String algorithm = "ML-DSA-" + level.getParameterSet() + (forPreHash ? "-WITH-SHA512" : "");

            kpg.initialize(MLDSAParameterSpec.fromName(algorithm));

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert = X509Util
                    .generateOrphanX509Certificate(kp, algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ML-DSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid ML-DSA algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate ML-DSA key", e);
        }
    }

    public static void generateSlhDsaKey(KeyStore keyStore, String alias, SLHDSAHash hash,
            SLHDSASecurityCategory securityCategory, SLHDSASignatureMode tradeoff, boolean preHashKey,
            String password) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", BouncyCastleProvider.PROVIDER_NAME);

            String algorithm = "SLH-DSA-%s-%s%s"
                    .formatted(hash.getHashName(), securityCategory.getSecurityParameterLength(),
                            tradeoff.getParameterName());

            algorithm = addPreHashSuffix(hash, securityCategory, preHashKey, algorithm);

            kpg.initialize(SLHDSAParameterSpec.fromName(algorithm));

            final KeyPair kp = kpg.generateKeyPair();
            final X509Certificate cert = X509Util
                    .generateOrphanX509Certificate(kp, "SLH-DSA", BouncyCastleProvider.PROVIDER_NAME);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), chain);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SLH-DSA algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid SLH-DSA algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate SLH-DSA key", e);
        }
    }

    private static String addPreHashSuffix(SLHDSAHash hash, SLHDSASecurityCategory securityCategory, boolean preHashKey,
            String algorithm) {
        if (preHashKey) {
            String hashSuffix = "-WITH-";
            if (hash == SLHDSAHash.SHA2) {
                hashSuffix += "SHA";
                if (securityCategory == SLHDSASecurityCategory.CATEGORY_1) {
                    hashSuffix += "256";
                } else {
                    hashSuffix += "512";
                }
            } else {
                hashSuffix += "SHAKE";
                if (securityCategory == SLHDSASecurityCategory.CATEGORY_1) {
                    hashSuffix += "128";
                } else {
                    hashSuffix += "256";
                }
            }
            algorithm += hashSuffix;
        }
        return algorithm;
    }

    public static BCMLKEMPublicKey generateMLKEMKey(KeyStore keyStore, String alias,
            MLKEMSecurityCategory securityCategory, String password) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(MLKEMParameterSpec.fromName(securityCategory.getParameterSet()));

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            final X509Certificate cert = X509Util.generateMLKEMOrphanX509Certificate(keyPair);
            final X509Certificate[] chain = new X509Certificate[]{cert};

            keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), chain);

            PublicKey publicKey = keyPair.getPublic();
            if (!(publicKey instanceof BCMLKEMPublicKey)) {
                throw new IllegalStateException("Generated public key is not of type BCMLKEMPublicKey");
            }
            return (BCMLKEMPublicKey) publicKey;

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ML-KEM algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(PROVIDER_NOT_FOUND, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid ML-KEM algorithm parameters", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot generate ML-KEM key", e);
        }
    }

    public static void deleteAliasFromKeyStore(KeyStore keyStore, String alias) {
        try {
            keyStore.deleteEntry(alias);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot remove alias '" + alias + "'", e);
        }
    }

    /**
     * Returns the private key from cached key material. Use on the crypto operation hot path.
     */
    public static PrivateKey getPrivateKey(CachedKeyData key, CachedKeyMaterial material) {
        PrivateKey pk = material.privateKeys().get(key.alias());
        if (pk == null) {
            throw new CryptographicOperationException("No private key for alias '" + key.alias()
                    + "' in cached material for token " + key.tokenInstanceUuid());
        }
        return pk;
    }

    /**
     * Returns the public key from cached key material. Use on the crypto operation hot path.
     */
    public static PublicKey getPublicKey(CachedKeyData key, CachedKeyMaterial material) {
        PublicKey pub = material.publicKeys().get(key.alias());
        if (pub == null) {
            throw new CryptographicOperationException("No public key for alias '" + key.alias()
                    + "' in cached material for token " + key.tokenInstanceUuid());
        }
        return pub;
    }

}
