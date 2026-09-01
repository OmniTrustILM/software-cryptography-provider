package com.otilm.cp.soft.util;

import com.otilm.cp.soft.collection.FalconDegree;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class X509Util {

    private X509Util() {
    }
    private static final SecureRandom random = new SecureRandom();

    public static X509Certificate generateRsaOrphanX509Certificate(KeyPair keyPair) {
        return generateOrphanX509Certificate(keyPair, "SHA512WithRSAEncryption", BouncyCastleProvider.PROVIDER_NAME);
    }

    public static X509Certificate generateEcdsaOrphanX509Certificate(KeyPair keyPair) {
        return generateOrphanX509Certificate(keyPair, "SHA512WithECDSA", BouncyCastleProvider.PROVIDER_NAME);
    }

    public static X509Certificate generateFalconOrphanX509Certificate(KeyPair keyPair, FalconDegree degree) {
        return switch (degree) {
            case FALCON_512 ->
                    generateOrphanX509Certificate(keyPair, "Falcon-512", BouncyCastlePQCProvider.PROVIDER_NAME);
            case FALCON_1024 ->
                    generateOrphanX509Certificate(keyPair, "Falcon-1024", BouncyCastlePQCProvider.PROVIDER_NAME);
        };
    }

    /**
     * ML-KEM is a KEM, not a signing algorithm, so it cannot self-sign an X.509 certificate. We generate
     * an orphan certificate signed by an ephemeral EC key that embeds the ML-KEM public key in its SubjectPublicKeyInfo.
     *
     * <p>The ephemeral EC key is intentionally unverifiable (the signing key is discarded immediately) and
     * must NEVER be used as a trust anchor.</p>
     */
    public static X509Certificate generateMLKEMOrphanX509Certificate(KeyPair mlkemKeyPair) {
        try {
            // ML-KEM cannot sign; generate a short-lived EC key pair just for signing the cert.
            KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            ecKpg.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
            KeyPair signingPair = ecKpg.generateKeyPair();

            X500Name owner = new X500Name("CN=generatedCertificate,O=orphan");

            final Date notBefore = new Date(System.currentTimeMillis() - 86400000L * 365);
            final Date notAfter  = new Date(System.currentTimeMillis() + 86400000L * 365 * 30);

            // Embed the ML-KEM public key in the certificate's SubjectPublicKeyInfo.
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    owner, new BigInteger(64, random), notBefore, notAfter, owner, mlkemKeyPair.getPublic());

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signingPair.getPrivate());

            X509CertificateHolder certHolder = builder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certHolder);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC algorithm not found", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Invalid EC parameters", e);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Cannot create content signer", e);
        } catch (CertificateException e) {
            throw new IllegalStateException("Error building ML-KEM orphan certificate", e);
        }
    }

    public static X509Certificate generateOrphanX509Certificate(KeyPair keyPair, String signatureAlgorithm, String provider) {
        X500Name owner = new X500Name("CN=generatedCertificate,O=orphan");

        // current time minus 1 year, just in case software clock goes back due to time synchronization
        final Date notBefore = new Date(System.currentTimeMillis() - 86400000L * 365);
        final Date notAfter = new Date(System.currentTimeMillis() + 86400000L * 365 * 30); // 30 years from now

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                owner, new BigInteger( 64, random ), notBefore, notAfter, owner, keyPair.getPublic() );

        PrivateKey privateKey = keyPair.getPrivate();

        try {
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(privateKey);

            X509CertificateHolder certHolder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certHolder);

            //check so that cert is valid
            cert.verify(keyPair.getPublic());

            return cert;
        } catch (CertificateException e) {
            throw new IllegalStateException("Error reading the certificate", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm", e);
        } catch (SignatureException e) {
            throw new IllegalStateException("Error building the signature ", e);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Operator cannot be created", e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid key pair", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider not found", e);
        }
    }

}
