package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import com.otilm.cp.soft.exception.KeyTypeNotImportableException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A key that arrived as material has to be described exactly as the same key would have been had this provider
 * generated it: the description is what a caller reads back, and for the algorithms that also sign a digest it is what
 * decides how the key is signed with. The two descriptions are built from different things — a request in one case, the
 * key itself in the other — so nothing but a comparison keeps them in step.
 */
class ImportedKeyDescriptionTest {

    private static final String CODE = "00000000";

    @BeforeAll
    static void registerProviders() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /** Every parameter set this provider can generate, beside the description a generated key of it carries. */
    static Stream<Arguments> generated() {
        return Stream
                .concat(Stream
                        .of(Arguments
                                .of("RSA-2048", KeyAlgorithm.RSA,
                                        (Generator) keyStore -> KeyStoreUtil.generateRsaKey(keyStore, "k", 2048, CODE),
                                        Map.of("location", "managed by external token"))),
                        Stream
                                .concat(ecdsa(), Stream
                                        .concat(falcon(), Stream.concat(mldsa(), Stream.concat(slhdsa(), mlkem())))));
    }

    private static Stream<Arguments> ecdsa() {
        return Stream
                .of(EcdsaCurveName.values())
                .map(curve -> Arguments
                        .of(curve.getName(), KeyAlgorithm.ECDSA,
                                (Generator) keyStore -> KeyStoreUtil.generateEcdsaKey(keyStore, "k", curve, CODE),
                                Map.of("curve.name", curve.name(), "curve.description", curve.getDescription())));
    }

    private static Stream<Arguments> falcon() {
        return Stream
                .of(FalconDegree.values())
                .map(degree -> Arguments
                        .of(degree.name(), KeyAlgorithm.FALCON,
                                (Generator) keyStore -> KeyStoreUtil.generateFalconKey(keyStore, "k", degree, CODE),
                                Map.of("degree", Integer.toString(degree.getDegree()))));
    }

    private static Stream<Arguments> mldsa() {
        return Stream
                .of(MLDSASecurityCategory.values())
                .flatMap(level -> Stream
                        .of(Boolean.FALSE, Boolean.TRUE)
                        .map(prehash -> Arguments
                                .of(level.name() + (prehash ? " pre-hash" : ""), KeyAlgorithm.MLDSA,
                                        (Generator) keyStore -> KeyStoreUtil
                                                .generateMLDSAKey(keyStore, "k", level, prehash, CODE),
                                        Map
                                                .of("level", Integer.toString(level.getNistSecurityCategory()),
                                                        "prehash", String.valueOf(prehash)))));
    }

    private static Stream<Arguments> slhdsa() {
        return Stream
                .of(SLHDSASecurityCategory.values())
                .flatMap(category -> Stream
                        .of(SLHDSAHash.values())
                        .flatMap(hash -> Stream
                                .of(SLHDSASignatureMode.values())
                                .flatMap(mode -> Stream
                                        .of(false, true)
                                        .map(prehash -> Arguments
                                                .of(category.name()
                                                        + " " + hash + " " + mode + (prehash ? " pre-hash" : ""),
                                                        KeyAlgorithm.SLHDSA,
                                                        (Generator) keyStore -> KeyStoreUtil
                                                                .generateSlhDsaKey(keyStore, "k", hash, category, mode,
                                                                        prehash, CODE),
                                                        Map
                                                                .of("securityCategory",
                                                                        category.getNistSecurityCategory(), "hash",
                                                                        hash.getHashName(), "tradeoff", mode.name(),
                                                                        "prehash", String.valueOf(prehash)))))));
    }

    private static Stream<Arguments> mlkem() {
        return Stream
                .of(MLKEMSecurityCategory.values())
                .map(category -> Arguments
                        .of(category.getParameterSet(), KeyAlgorithm.MLKEM,
                                (Generator) keyStore -> KeyStoreUtil.generateMLKEMKey(keyStore, "k", category, CODE),
                                Map.of("securityCategory", String.valueOf(category.getNistSecurityCategory()))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("generated")
    void describesAnImportedKeyAsAGeneratedOneOfTheSameParameterSetIsDescribed(String named, KeyAlgorithm algorithm,
            Generator generator, Map<String, String> asGenerated) throws Exception {
        // given
        KeyStore keyStore = KeyStoreUtil.loadKeystore(KeyStoreUtil.createNewKeystore("PKCS12", CODE), CODE);
        generator.into(keyStore);
        KeyPair generatedPair = new KeyPair(keyStore.getCertificate("k").getPublicKey(),
                (java.security.PrivateKey) keyStore.getKey("k", CODE.toCharArray()));

        // when
        CustomKeyValue described = PrivateKeyDescriptor.of(algorithm, generatedPair);

        // then
        assertEquals(asGenerated, described.getValues(),
                () -> "an imported " + named + " key would be described differently from a generated one");
    }

    /**
     * A curve is not identified by the size of its field: several curves share one. A key on a curve this provider does
     * not offer must not be recorded as the published curve of the same size, which would leave the row naming a curve
     * the key is not on — and that name is the reference the platform holds for the key. It is refused instead.
     */
    @ParameterizedTest
    @ValueSource(strings = {"secp256k1", "brainpoolP256r1", "sect283k1"})
    void refusesAKeyOnACurveItDoesNotOfferRatherThanCallingItAnother(String curve) throws Exception {
        // given
        KeyPairGenerator generator = KeyPairGenerator
                .getInstance(KeyAlgorithm.ECDSA.getCode(), BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair pair = generator.generateKeyPair();

        // when
        // then
        KeyTypeNotImportableException refused = assertThrows(KeyTypeNotImportableException.class,
                () -> PrivateKeyDescriptor.of(KeyAlgorithm.ECDSA, pair));
        assertTrue(refused.getMessage().contains(curve),
                () -> "the refusal has to name the curve, not another: " + refused.getMessage());
    }

    /** One curve answers to several names, and a key naming it by any of them is a key on the curve it offers. */
    @Test
    void takesAKeyThatNamesAnOfferedCurveByAnotherOfItsNames() throws Exception {
        // given
        KeyPairGenerator generator = KeyPairGenerator
                .getInstance(KeyAlgorithm.ECDSA.getCode(), BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair pair = generator.generateKeyPair();

        // when
        CustomKeyValue described = PrivateKeyDescriptor.of(KeyAlgorithm.ECDSA, pair);

        // then
        assertEquals(EcdsaCurveName.secp256r1.getName(), described.getValues().get("curve.name"),
                "prime256v1 is the same curve as secp256r1");
    }

    /** The two halves of the arrangement a generated key is made by, so each parameter set can state its own. */
    @FunctionalInterface
    interface Generator {

        void into(KeyStore keyStore);
    }

}
