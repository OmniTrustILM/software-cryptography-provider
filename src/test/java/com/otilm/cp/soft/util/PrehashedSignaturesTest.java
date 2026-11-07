package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrehashedSignaturesTest {

    private static final byte[] MESSAGE = "A message whose digest is signed".getBytes(StandardCharsets.UTF_8);

    private static final Set<SignatureAlgorithm> ADMITTED = EnumSet
            .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                    SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithm.SHA512_WITH_RSA_PSS,
                    SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithm.SHA384_WITH_ECDSA,
                    SignatureAlgorithm.SHA512_WITH_ECDSA);

    private static KeyPair rsa;
    private static KeyPair p256;
    private static KeyPair p384;

    @BeforeAll
    static void generateKeys() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        rsa = rsaGenerator.generateKeyPair();
        KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
        ecGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        p256 = ecGenerator.generateKeyPair();
        ecGenerator.initialize(new ECGenParameterSpec("secp384r1"));
        p384 = ecGenerator.generateKeyPair();
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class,
            names = {
                    "SHA256_WITH_RSA",
                    "SHA384_WITH_RSA",
                    "SHA512_WITH_RSA",
                    "SHA256_WITH_RSA_PSS",
                    "SHA384_WITH_RSA_PSS",
                    "SHA512_WITH_RSA_PSS",
                    "SHA256_WITH_ECDSA",
                    "SHA384_WITH_ECDSA",
                    "SHA512_WITH_ECDSA"})
    void signsADigestThatVerifiesOverItsMessage(SignatureAlgorithm algorithm) throws Exception {
        // given
        DigestAlgorithm hash = SignatureAlgorithms.digestOf(algorithm);
        byte[] digest = MessageDigest.getInstance(hash.getCode()).digest(MESSAGE);
        KeyPair pair = algorithm.name().endsWith("ECDSA") ? p384 : rsa;

        // when
        byte[] signature = PrehashedSignatures.sign(algorithm, pair.getPrivate(), digest);

        // then
        assertTrue(verifies(algorithm, pair.getPublic(), signature, 0));
    }

    @Test
    void verifiesWithAProviderOtherThanBouncyCastle() throws Exception {
        // given
        String bouncyCastle = BouncyCastleProvider.PROVIDER_NAME;

        // when
        String rsaProvider = Signature.getInstance("SHA256withRSA").getProvider().getName();
        String pssProvider = Signature.getInstance("RSASSA-PSS").getProvider().getName();
        String ecdsaProvider = Signature.getInstance("SHA256withECDSA").getProvider().getName();
        String unhashedRsaProvider = Signature.getInstance("NONEwithRSA").getProvider().getName();

        // then
        assertNotEquals(bouncyCastle, rsaProvider);
        assertNotEquals(bouncyCastle, pssProvider);
        assertNotEquals(bouncyCastle, ecdsaProvider);
        assertNotEquals(bouncyCastle, unhashedRsaProvider);
    }

    @Test
    void wrapsAnRsaDigestInDigestInfoWithExplicitNullParameters() throws Exception {
        // given
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(MESSAGE);

        // when
        byte[] signature = PrehashedSignatures.sign(SignatureAlgorithm.SHA256_WITH_RSA, rsa.getPrivate(), digest);

        // then
        byte[] prefix = HexFormat.of().parseHex("3031300d060960864801650304020105000420");
        byte[] expected = Arrays.copyOf(prefix, prefix.length + digest.length);
        System.arraycopy(digest, 0, expected, prefix.length, digest.length);
        // The unhashed JDK verifier accepts the signature only over exactly these bytes, so it pins the encoding.
        Signature verifier = Signature.getInstance("NONEwithRSA");
        verifier.initVerify(rsa.getPublic());
        verifier.update(expected);
        assertTrue(verifier.verify(signature));
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = {"SHA384_WITH_ECDSA", "SHA512_WITH_ECDSA"})
    void signsADigestLongerThanTheCurveOrder(SignatureAlgorithm algorithm) throws Exception {
        // given
        byte[] digest = MessageDigest.getInstance(SignatureAlgorithms.digestOf(algorithm).getCode()).digest(MESSAGE);

        // when
        byte[] signature = PrehashedSignatures.sign(algorithm, p256.getPrivate(), digest);

        // then
        assertTrue(verifies(algorithm, p256.getPublic(), signature, 0));
    }

    @Test
    void pssSignatureFailsUnderAnotherSaltLength() throws Exception {
        // given
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(MESSAGE);
        byte[] signature = PrehashedSignatures.sign(SignatureAlgorithm.SHA256_WITH_RSA_PSS, rsa.getPrivate(), digest);

        // when
        boolean underSaltTwenty = verifies(SignatureAlgorithm.SHA256_WITH_RSA_PSS, rsa.getPublic(), signature, 20);

        // then
        assertFalse(underSaltTwenty);
    }

    @Test
    void refusesACodeItDoesNotAdmit() {
        // given
        byte[] digest = new byte[32];

        // when
        boolean admitted = PrehashedSignatures.admits(SignatureAlgorithm.ML_DSA_65);

        // then
        assertFalse(admitted);
        assertThrows(IllegalArgumentException.class,
                () -> PrehashedSignatures.sign(SignatureAlgorithm.ML_DSA_65, rsa.getPrivate(), digest));
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class,
            names = {"SHA256_WITH_RSA", "SHA256_WITH_RSA_PSS", "SHA256_WITH_ECDSA", "SHA512_WITH_RSA_PSS"})
    void refusesADigestOfTheWrongLength(SignatureAlgorithm algorithm) {
        // given
        int expected = SignatureAlgorithms.digestOf(algorithm).getDigestSizeBytes();
        KeyPair pair = algorithm.name().endsWith("ECDSA") ? p256 : rsa;

        // when
        Executable tooShort = () -> PrehashedSignatures.sign(algorithm, pair.getPrivate(), new byte[expected - 1]);
        Executable tooLong = () -> PrehashedSignatures.sign(algorithm, pair.getPrivate(), new byte[expected + 1]);
        Executable muchLonger = () -> PrehashedSignatures.sign(algorithm, pair.getPrivate(), new byte[96]);

        // then
        assertThrows(IllegalArgumentException.class, tooShort);
        assertThrows(IllegalArgumentException.class, tooLong);
        assertThrows(IllegalArgumentException.class, muchLonger);
    }

    @Test
    void digestOfCoversExactlyTheNineCodes() {
        // given
        Set<SignatureAlgorithm> covered = Arrays
                .stream(SignatureAlgorithm.values())
                .filter(algorithm -> SignatureAlgorithms.digestOf(algorithm) != null)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(SignatureAlgorithm.class)));

        // when
        boolean allAdmitted = ADMITTED.stream().allMatch(PrehashedSignatures::admits);

        // then
        assertEquals(ADMITTED, covered);
        assertTrue(allAdmitted);
    }

    private static boolean verifies(SignatureAlgorithm algorithm, PublicKey key, byte[] signature, int saltOverride)
            throws Exception {
        DigestAlgorithm hash = SignatureAlgorithms.digestOf(algorithm);
        String name = hash.getCode();
        Signature verifier;
        if (algorithm.name().endsWith("RSA_PSS")) {
            verifier = Signature.getInstance("RSASSA-PSS");
            int salt = saltOverride > 0 ? saltOverride : hash.getDigestSizeBytes();
            verifier.setParameter(new PSSParameterSpec(name, "MGF1", new MGF1ParameterSpec(name), salt, 1));
        } else if (algorithm.name().endsWith("RSA")) {
            verifier = Signature.getInstance(name.replace("-", "") + "withRSA");
        } else {
            verifier = Signature.getInstance(name.replace("-", "") + "withECDSA");
        }
        verifier.initVerify(key);
        verifier.update(MESSAGE);
        return verifier.verify(signature);
    }
}
