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
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PrehashedSignaturesTest {

    private static final byte[] MESSAGE = "A message whose digest is signed".getBytes(StandardCharsets.UTF_8);

    private static final Set<SignatureAlgorithm> BOUND = EnumSet
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
        assertThat(verifies(algorithm, pair.getPublic(), signature, 0)).isTrue();
    }

    @Test
    void verifiesWithAProviderOtherThanBouncyCastle() throws Exception {
        // then
        assertThat(Signature.getInstance("SHA256withRSA").getProvider().getName())
                .isNotEqualTo(BouncyCastleProvider.PROVIDER_NAME);
        assertThat(Signature.getInstance("RSASSA-PSS").getProvider().getName())
                .isNotEqualTo(BouncyCastleProvider.PROVIDER_NAME);
        assertThat(Signature.getInstance("SHA256withECDSA").getProvider().getName())
                .isNotEqualTo(BouncyCastleProvider.PROVIDER_NAME);
        assertThat(Cipher.getInstance("RSA/ECB/PKCS1Padding").getProvider().getName())
                .isNotEqualTo(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    void wrapsAnRsaDigestInDigestInfoWithExplicitNullParameters() throws Exception {
        // given
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(MESSAGE);

        // when
        byte[] signature = PrehashedSignatures.sign(SignatureAlgorithm.SHA256_WITH_RSA, rsa.getPrivate(), digest);

        // then
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsa.getPublic());
        byte[] prefix = HexFormat.of().parseHex("3031300d060960864801650304020105000420");
        byte[] expected = Arrays.copyOf(prefix, prefix.length + digest.length);
        System.arraycopy(digest, 0, expected, prefix.length, digest.length);
        assertThat(cipher.doFinal(signature)).isEqualTo(expected);
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = {"SHA384_WITH_ECDSA", "SHA512_WITH_ECDSA"})
    void signsADigestLongerThanTheCurveOrder(SignatureAlgorithm algorithm) throws Exception {
        // given
        byte[] digest = MessageDigest.getInstance(SignatureAlgorithms.digestOf(algorithm).getCode()).digest(MESSAGE);

        // when
        byte[] signature = PrehashedSignatures.sign(algorithm, p256.getPrivate(), digest);

        // then
        assertThat(verifies(algorithm, p256.getPublic(), signature, 0)).isTrue();
    }

    @Test
    void pssSignatureFailsUnderAnotherSaltLength() throws Exception {
        // given
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(MESSAGE);
        byte[] signature = PrehashedSignatures.sign(SignatureAlgorithm.SHA256_WITH_RSA_PSS, rsa.getPrivate(), digest);

        // when
        boolean underSaltTwenty = verifies(SignatureAlgorithm.SHA256_WITH_RSA_PSS, rsa.getPublic(), signature, 20);

        // then
        assertThat(underSaltTwenty).isFalse();
    }

    @Test
    void refusesACodeOutsideTheBound() {
        // given
        byte[] digest = new byte[32];

        // then
        assertThat(PrehashedSignatures.admits(SignatureAlgorithm.ML_DSA_65)).isFalse();
        assertThatThrownBy(() -> PrehashedSignatures.sign(SignatureAlgorithm.ML_DSA_65, rsa.getPrivate(), digest))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void digestOfCoversExactlyTheNineCodes() {
        // when
        Set<SignatureAlgorithm> covered = Arrays
                .stream(SignatureAlgorithm.values())
                .filter(algorithm -> SignatureAlgorithms.digestOf(algorithm) != null)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(SignatureAlgorithm.class)));

        // then
        assertThat(covered).isEqualTo(BOUND);
        assertThat(BOUND).allMatch(PrehashedSignatures::admits);
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
