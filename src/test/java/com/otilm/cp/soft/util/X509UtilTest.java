package com.otilm.cp.soft.util;

import com.otilm.cp.soft.collection.FalconDegree;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X509UtilTest {

    @BeforeAll
    static void registerProviders() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    @Test
    void generateRsaOrphanCertificateEmbedPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = X509Util.generateRsaOrphanX509Certificate(kp);

        assertNotNull(cert);
        assertArrayEquals(kp.getPublic().getEncoded(), cert.getPublicKey().getEncoded());
        assertDoesNotThrow((Executable) cert::checkValidity);
    }

    @Test
    void generateEcdsaOrphanCertificateEmbedPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = X509Util.generateEcdsaOrphanX509Certificate(kp);

        assertNotNull(cert);
        assertArrayEquals(kp.getPublic().getEncoded(), cert.getPublicKey().getEncoded());
        assertDoesNotThrow((Executable) cert::checkValidity);
    }

    @Test
    void generateFalcon512OrphanCertificateEmbedPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", BouncyCastlePQCProvider.PROVIDER_NAME);
        kpg.initialize(FalconParameterSpec.falcon_512);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = X509Util.generateFalconOrphanX509Certificate(kp, FalconDegree.FALCON_512);

        assertNotNull(cert);
        assertArrayEquals(kp.getPublic().getEncoded(), cert.getPublicKey().getEncoded());
    }

    @Test
    void generateFalcon1024OrphanCertificateEmbedPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", BouncyCastlePQCProvider.PROVIDER_NAME);
        kpg.initialize(FalconParameterSpec.falcon_1024);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = X509Util.generateFalconOrphanX509Certificate(kp, FalconDegree.FALCON_1024);

        assertNotNull(cert);
        assertArrayEquals(kp.getPublic().getEncoded(), cert.getPublicKey().getEncoded());
    }

    @Test
    void generateMlkemOrphanCertificateEmbedsMlkemPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLKEMParameterSpec.fromName("ML-KEM-768"));
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = X509Util.generateMLKEMOrphanX509Certificate(kp);

        assertNotNull(cert);
        assertArrayEquals(kp.getPublic().getEncoded(), cert.getPublicKey().getEncoded(),
                "Certificate SubjectPublicKeyInfo must embed the ML-KEM public key");
        assertDoesNotThrow((Executable) cert::checkValidity);
        // Signed by an ephemeral EC key — the cert cannot self-verify against the ML-KEM public key.
        assertTrue(cert.getSigAlgName().toUpperCase().contains("ECDSA"),
                "ML-KEM orphan cert must be signed with ECDSA (not ML-KEM itself)");
    }

    @Test
    void generateMlkemOrphanCertificateForAllParameterSets() throws Exception {
        for (String paramSet : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(MLKEMParameterSpec.fromName(paramSet));
            KeyPair kp = kpg.generateKeyPair();

            X509Certificate cert = X509Util.generateMLKEMOrphanX509Certificate(kp);

            assertNotNull(cert, "Certificate must be generated for " + paramSet);
            assertArrayEquals(kp.getPublic().getEncoded(), cert.getPublicKey().getEncoded(),
                    "Public key mismatch for " + paramSet);
        }
    }

    @Test
    void generateOrphanCertificateHas30YearValidity() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = X509Util.generateEcdsaOrphanX509Certificate(kp);

        long now = System.currentTimeMillis();
        long remainingMs = cert.getNotAfter().getTime() - now;
        long thirtyYearsMs = 86400_000L * 365 * 30;
        // notBefore is 1 year in the past (clock-skew tolerance); measure from now to notAfter.
        // Allow ±2 days for rounding/leap years.
        assertTrue(Math.abs(remainingMs - thirtyYearsMs) < 86400_000L * 2,
                "Certificate validity must be approximately 30 years from now");
    }
}
