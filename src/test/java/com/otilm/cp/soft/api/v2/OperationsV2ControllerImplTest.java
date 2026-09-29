package com.otilm.cp.soft.api.v2;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.VerificationResponseItemV2Dto;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.FalconKeyAttributes;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.RsaCipherAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 operations over a key this provider holds. The work is the same the V1 interfaces perform, so what these cover
 * is the V2 surface: the schema an operation publishes, the round trip through a key addressed by metadata, and the
 * refusals for work this connector never defers.
 */
@SpringBootTest
class OperationsV2ControllerImplTest {

    private static final byte[] MESSAGE = "the message to sign".getBytes(StandardCharsets.UTF_8);

    private OperationsV2ControllerImpl controller;

    private KeyV2ControllerImpl keys;

    private TokenContextService tokenContextService;

    private KeyManagementService keyManagementService;

    private KeyDataRepository keyDataRepository;

    @Autowired
    void setController(OperationsV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setKeys(KeyV2ControllerImpl keys) {
        this.keys = keys;
    }

    @Autowired
    void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }

    @Autowired
    void setKeyManagementService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @Autowired
    void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @Test
    void signsAndVerifiesThroughKeysAddressedByMetadata() {
        // given
        KeyPair pair = rsaKeyPair("v2-sign");
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(rsaSignatureAttributes());
        signing.setData(List.of(item("one", MESSAGE)));

        // when
        SignDataResponseV2Dto signed = controller.signData(signing).getBody();

        // then
        assertNotNull(signed);
        assertEquals(1, signed.getSignatures().size());
        assertEquals("one", signed.getSignatures().get(0).getIdentifier());

        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        apply(verification, pair.tokenAttributes(), pair.publicKeyMeta());
        verification.setSignatureAttributes(rsaSignatureAttributes());
        verification.setData(List.of(item("one", MESSAGE)));
        verification.setSignatures(signed.getSignatures());

        VerifyDataResponseV2Dto verified = controller.verifyData(verification);
        assertTrue(verified.getVerifications().get(0).getResult(), "the signature this provider made must verify");
    }

    /**
     * The contract correlates signed data and signatures by identifier, so a caller may list them in different orders.
     * The code performing the verification pairs the two lists by position, which would verify each signature against
     * the wrong data.
     */
    @Test
    void verifiesEachSignatureAgainstItsOwnDataWhateverOrderTheyArriveIn() {
        // given
        byte[] second = "a second message".getBytes(StandardCharsets.UTF_8);
        KeyPair pair = rsaKeyPair("v2-verify-order");
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(rsaSignatureAttributes());
        signing.setData(List.of(item("one", MESSAGE), item("two", second)));
        SignDataResponseV2Dto signed = controller.signData(signing).getBody();
        assertNotNull(signed);

        // when
        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        apply(verification, pair.tokenAttributes(), pair.publicKeyMeta());
        verification.setSignatureAttributes(rsaSignatureAttributes());
        verification.setData(List.of(item("one", MESSAGE), item("two", second)));
        verification.setSignatures(List.of(signed.getSignatures().get(1), signed.getSignatures().get(0)));

        VerifyDataResponseV2Dto verified = controller.verifyData(verification);

        // then
        Map<String, Boolean> byIdentifier = verified
                .getVerifications()
                .stream()
                .collect(Collectors
                        .toMap(VerificationResponseItemV2Dto::getIdentifier, VerificationResponseItemV2Dto::getResult));
        assertEquals(Map.of("one", true, "two", true), byIdentifier);
    }

    /**
     * Every item of a cipher result must carry the identifier the request gave it, and they must stay distinct within
     * the batch, which is how a caller pairs a result with what it sent. Two items are used because a batch is where
     * pairing by anything else breaks down.
     */
    @Test
    void encryptsAndDecryptsThroughKeysAddressedByMetadata() {
        // given
        byte[] second = "a second message".getBytes(StandardCharsets.UTF_8);
        KeyPair pair = rsaKeyPair("v2-cipher");
        CipherDataRequestV2Dto encryption = new CipherDataRequestV2Dto();
        apply(encryption, pair.tokenAttributes(), pair.publicKeyMeta());
        encryption.setCipherAttributes(rsaCipherAttributes());
        encryption.setCipherData(List.of(cipherItem("one", MESSAGE), cipherItem("two", second)));

        // when
        List<CipherDataV2Dto> encrypted = controller.encryptData(encryption).getEncryptedData();

        // then
        assertEquals(List.of("one", "two"), encrypted.stream().map(CipherDataV2Dto::getIdentifier).toList());

        CipherDataRequestV2Dto decryption = new CipherDataRequestV2Dto();
        apply(decryption, pair.tokenAttributes(), pair.privateKeyMeta());
        decryption.setCipherAttributes(rsaCipherAttributes());
        decryption.setCipherData(encrypted);

        List<CipherDataV2Dto> decrypted = controller.decryptData(decryption).getDecryptedData();
        Map<String, byte[]> byIdentifier = decrypted
                .stream()
                .collect(Collectors.toMap(CipherDataV2Dto::getIdentifier, CipherDataV2Dto::getData));
        assertArrayEquals(MESSAGE, byIdentifier.get("one"));
        assertArrayEquals(second, byIdentifier.get("two"));
    }

    /**
     * Data that is not this key's ciphertext is reported by the cipher code both generations share, as a validation
     * failure of its own kind. The V2 advice names that kind so the caller receives a problem document; without it the
     * connector-wide advice would answer in the V1 shape and quote the underlying message.
     */
    @Test
    void refusesDataThatIsNotCiphertextForTheKey() {
        // given
        KeyPair pair = rsaKeyPair("v2-cipher-garbage");
        CipherDataRequestV2Dto decryption = new CipherDataRequestV2Dto();
        apply(decryption, pair.tokenAttributes(), pair.privateKeyMeta());
        decryption.setCipherAttributes(rsaCipherAttributes());
        decryption.setCipherData(List.of(cipherItem("one", MESSAGE)));

        // when
        // then
        assertThrows(ValidationException.class, () -> controller.decryptData(decryption));
    }

    @Test
    void rsaKeyPublishesReservedSignatureAlgorithm() {
        // given
        KeyPair pair = rsaKeyPair("v2-sign-attrs");
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.privateKeyMeta());

        // when
        List<BaseAttribute> attributes = controller.listSignAttributes(request);

        // then
        assertEquals(List.of(SignatureAlgorithmAttribute.NAME),
                attributes.stream().map(BaseAttribute::getName).toList());
        DataAttributeV3 algorithm = (DataAttributeV3) attributes.get(0);
        assertEquals(
                List
                        .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                                SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                                SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithm.SHA512_WITH_RSA_PSS),
                algorithm
                        .getContent()
                        .stream()
                        .map(value -> SignatureAlgorithm.findByCode((String) value.getData()))
                        .toList());
    }

    @Test
    void rsa1024KeyOmitsSha512PssFromSignSchema() {
        KeyPair pair = rsaKeyPair("v2-small-rsa-sign", 1024);
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.privateKeyMeta());

        DataAttributeV3 algorithm = (DataAttributeV3) controller.listSignAttributes(request).get(0);

        assertEquals(
                List
                        .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                                SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                                SignatureAlgorithm.SHA384_WITH_RSA_PSS),
                algorithm
                        .getContent()
                        .stream()
                        .map(value -> SignatureAlgorithm.findByCode((String) value.getData()))
                        .toList());
    }

    @Test
    void ecdsaKeyOffersItsThreeSignatureAlgorithms() {
        KeyPair pair = ecdsaKeyPair("v2-ecdsa-attrs");
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.privateKeyMeta());

        DataAttributeV3 algorithm = (DataAttributeV3) controller.listSignAttributes(request).get(0);

        assertEquals(
                List
                        .of(SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithm.SHA384_WITH_ECDSA,
                                SignatureAlgorithm.SHA512_WITH_ECDSA),
                algorithm
                        .getContent()
                        .stream()
                        .map(value -> SignatureAlgorithm.findByCode((String) value.getData()))
                        .toList());
    }

    @Test
    void ecdsaSha384SelectionProducesExternallyVerifiableSignature() throws GeneralSecurityException {
        KeyPair pair = ecdsaKeyPair("v2-ecdsa-sign");
        List<RequestAttribute> choice = List
                .of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA384_WITH_ECDSA));
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(choice);
        signing.setData(List.of(item("one", MESSAGE)));

        SignDataResponseV2Dto signed = controller.signData(signing).getBody();
        assertNotNull(signed);
        assertTrue(verifiesExternally(pair.publicKeySpki(), "EC", "SHA384withECDSA", MESSAGE,
                signed.getSignatures().get(0).getData()));

        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        apply(verification, pair.tokenAttributes(), pair.publicKeyMeta());
        verification.setSignatureAttributes(choice);
        verification.setData(List.of(item("one", MESSAGE)));
        verification.setSignatures(signed.getSignatures());

        assertTrue(controller.verifyData(verification).getVerifications().get(0).getResult());
    }

    @Test
    void rsaPssSha384SelectionProducesExternallyVerifiableSignature() throws GeneralSecurityException {
        KeyPair pair = rsaKeyPair("v2-rsa-pss-sign");
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing
                .setSignatureAttributes(
                        List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA384_WITH_RSA_PSS)));
        signing.setData(List.of(item("one", MESSAGE)));

        SignDataResponseV2Dto signed = controller.signData(signing).getBody();
        assertNotNull(signed);

        assertTrue(verifiesExternally(pair.publicKeySpki(), "RSA", "SHA384withRSAandMGF1", MESSAGE,
                signed.getSignatures().get(0).getData()));
    }

    @Test
    void mldsa65KeyOffersAndUsesItsParameterSet() {
        KeyPair pair = mldsaKeyPair("v2-mldsa-attrs");
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.privateKeyMeta());

        DataAttributeV3 algorithm = (DataAttributeV3) controller.listSignAttributes(request).get(0);

        assertEquals(List.of(SignatureAlgorithm.ML_DSA_65),
                algorithm
                        .getContent()
                        .stream()
                        .map(value -> SignatureAlgorithm.findByCode((String) value.getData()))
                        .toList());
        signsAndVerifies(pair, SignatureAlgorithm.ML_DSA_65);
        signsAfterPublicHalfIsDestroyed(pair, SignatureAlgorithm.ML_DSA_65);
    }

    @Test
    void rsaKeyRefusesAnEcdsaSignatureSelection() {
        KeyPair pair = rsaKeyPair("v2-rsa-wrong-signature");
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing
                .setSignatureAttributes(
                        List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_ECDSA)));
        signing.setData(List.of(item("one", MESSAGE)));

        assertThrows(ParameterUnsupportedException.class, () -> controller.signData(signing));
    }

    @Test
    void rsaKeyRefusesToVerifyUnderAnEcdsaSignatureSelection() {
        // given
        KeyPair pair = rsaKeyPair("v2-rsa-wrong-verification");
        VerifyDataRequestV2Dto verification = verification(pair, SignatureAlgorithm.SHA256_WITH_ECDSA);

        // when
        // then
        assertThrows(ParameterUnsupportedException.class, () -> controller.verifyData(verification));
    }

    @Test
    void mldsa65KeyRefusesToSignUnderAnotherParameterSet() {
        // given
        KeyPair pair = mldsaKeyPair("v2-mldsa-mismatch-sign");
        SignDataRequestV2Dto signing = signing(pair,
                List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.ML_DSA_44)));

        // when
        // then
        assertThrows(ParameterUnsupportedException.class, () -> controller.signData(signing));
    }

    @Test
    void mldsa65KeyRefusesToVerifyUnderAnotherParameterSet() {
        // given
        KeyPair pair = mldsaKeyPair("v2-mldsa-mismatch-verify");
        VerifyDataRequestV2Dto verification = verification(pair, SignatureAlgorithm.ML_DSA_44);

        // when
        // then
        assertThrows(ParameterUnsupportedException.class, () -> controller.verifyData(verification));
    }

    static Stream<Arguments> selectionsNamingNoAlgorithm() {
        RequestAttributeV2 v2Typed = new RequestAttributeV2();
        v2Typed.setName(SignatureAlgorithmAttribute.NAME);
        v2Typed.setContent(List.of(new StringAttributeContentV2("SHA256withRSA", "SHA256withRSA")));
        RequestAttributeV3 unknown = new RequestAttributeV3(SignatureAlgorithmAttribute.ATTRIBUTE_UUID,
                SignatureAlgorithmAttribute.NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("MD5withRSA", "MD5withRSA")));
        return Stream
                .of(Arguments.of("missing", List.of()), Arguments.of("unknown", List.of(unknown)),
                        Arguments.of("v2-typed", List.of(v2Typed)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("selectionsNamingNoAlgorithm")
    void refusesASignatureSelectionThatNamesNoAlgorithm(String selection, List<RequestAttribute> attributes) {
        // given
        KeyPair pair = rsaKeyPair("v2-no-selection");
        SignDataRequestV2Dto signing = signing(pair, attributes);

        // when
        // then
        assertThrows(ValidationException.class, () -> controller.signData(signing));
    }

    @Test
    void falcon1024KeyOffersAndUsesItsParameterSet() {
        KeyPair pair = falconKeyPair("v2-falcon-attrs");
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.privateKeyMeta());

        DataAttributeV3 algorithm = (DataAttributeV3) controller.listSignAttributes(request).get(0);

        assertEquals(List.of(SignatureAlgorithm.FALCON_1024),
                algorithm
                        .getContent()
                        .stream()
                        .map(value -> SignatureAlgorithm.findByCode((String) value.getData()))
                        .toList());
        signsAndVerifies(pair, SignatureAlgorithm.FALCON_1024);
        signsAfterPublicHalfIsDestroyed(pair, SignatureAlgorithm.FALCON_1024);
    }

    @Test
    void slhdsaSha2KeyOffersAndUsesItsParameterSet() {
        KeyPair pair = slhdsaKeyPair("v2-slhdsa-attrs");
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.privateKeyMeta());

        DataAttributeV3 algorithm = (DataAttributeV3) controller.listSignAttributes(request).get(0);

        assertEquals(List.of(SignatureAlgorithm.SLH_DSA_SHA2_128S),
                algorithm
                        .getContent()
                        .stream()
                        .map(value -> SignatureAlgorithm.findByCode((String) value.getData()))
                        .toList());
        signsAndVerifies(pair, SignatureAlgorithm.SLH_DSA_SHA2_128S);
        signsAfterPublicHalfIsDestroyed(pair, SignatureAlgorithm.SLH_DSA_SHA2_128S);
    }

    /** V1 still creates these, and both generations serve the same keys, so V2 meets them and has to refuse them. */
    static Stream<Arguments> v1KeysNoPlatformAlgorithmNames() {
        return Stream
                .of(Arguments.of("Falcon-512", List.of(algorithm(KeyAlgorithm.FALCON), falconDegree(512))), Arguments
                        .of("HashML-DSA-65", List.of(algorithm(KeyAlgorithm.MLDSA), mldsaLevel(), mldsaPrehash(true))),
                        Arguments.of("SLH-DSA-SHAKE-128S", slhdsa("SHAKE256", "SHAKE", false)),
                        Arguments.of("HashSLH-DSA-SHA2-128S", slhdsa("SHA2", "SHA2", true)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("v1KeysNoPlatformAlgorithmNames")
    void refusesToOfferASignatureForAV1KeyNoPlatformAlgorithmNames(String variant, List<RequestAttribute> parameters)
            throws NotFoundException {
        // given
        KeyPair pair = v1KeyPair("v2-unsignable", parameters);
        KeyScopedRequestV2Dto request = scoped(pair.tokenAttributes(), pair.privateKeyMeta());

        // when
        // then
        assertThrows(ParameterUnsupportedException.class, () -> controller.listSignAttributes(request));
    }

    /** Without the public row the parameter set is read from the private row instead, which is a path of its own. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("v1KeysNoPlatformAlgorithmNames")
    void refusesToOfferASignatureForSuchAKeyOnceItsPublicHalfIsGone(String variant, List<RequestAttribute> parameters)
            throws NotFoundException {
        // given
        KeyPair pair = v1KeyPair("v2-unsignable-private", parameters);
        destroy(pair.tokenAttributes(), pair.publicKeyMeta());
        KeyScopedRequestV2Dto request = scoped(pair.tokenAttributes(), pair.privateKeyMeta());

        // when
        // then
        assertThrows(ParameterUnsupportedException.class, () -> controller.listSignAttributes(request));
    }

    /** A row that lost its pre-hash selection describes no parameter set, which is a fault in what is stored. */
    @Test
    void refusesToReadASignatureOffAPrivateRowStatingNoPreHashSelection() {
        // given
        KeyPair pair = mldsaKeyPair("v2-mldsa-no-prehash");
        destroy(pair.tokenAttributes(), pair.publicKeyMeta());
        KeyData row = row(pair.privateKeyMeta());
        HashMap<String, String> parameters = new HashMap<>(((CustomKeyValue) row.getValue()).getValues());
        parameters.remove("prehash");
        CustomKeyValue value = new CustomKeyValue();
        value.setValues(parameters);
        row.setValue(value);
        keyDataRepository.saveAndFlush(row);
        KeyScopedRequestV2Dto request = scoped(pair.tokenAttributes(), pair.privateKeyMeta());

        // when
        // then
        assertThrows(CryptographicOperationException.class, () -> controller.listSignAttributes(request));
    }

    /**
     * Import stores no RSA key too small for every algorithm, since it signs the certificate beside the key with the
     * largest of them, so the row is made to record one.
     */
    @Test
    void refusesToOfferASignatureForAnRsaKeyTooSmallForAny() {
        // given
        KeyPair pair = rsaKeyPair("v2-rsa-too-small", 1024);
        KeyData row = row(pair.privateKeyMeta());
        row.setLength(480);
        keyDataRepository.saveAndFlush(row);
        KeyScopedRequestV2Dto request = scoped(pair.tokenAttributes(), pair.privateKeyMeta());

        // when
        // then
        assertThrows(ParameterUnsupportedException.class, () -> controller.listSignAttributes(request));
    }

    static Stream<Arguments> creationsLeavingOutWhatV2Fixes() {
        return Stream
                .of(Arguments.of(SignatureAlgorithm.FALCON_1024, List.of(algorithm(KeyAlgorithm.FALCON))),
                        Arguments
                                .of(SignatureAlgorithm.ML_DSA_65, List.of(algorithm(KeyAlgorithm.MLDSA), mldsaLevel())),
                        Arguments
                                .of(SignatureAlgorithm.SLH_DSA_SHA2_128S, List
                                        .of(algorithm(KeyAlgorithm.SLHDSA),
                                                stringValue(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY,
                                                        "CATEGORY_1", "1"),
                                                stringValue(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE,
                                                        "SMALL", "SMALL"))));
    }

    /**
     * V2 leaves out the choices beyond what a platform algorithm names, so a creation stating none still makes a key.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("creationsLeavingOutWhatV2Fixes")
    void createsTheOneParameterSetV2OffersWhereACreationStatesNone(SignatureAlgorithm offered,
            List<RequestAttribute> parameters) {
        // given
        KeyPair pair = v2KeyPair("v2-fixed-parameters", parameters);

        // when
        List<SignatureAlgorithm> algorithms = offered(pair.tokenAttributes(), pair.privateKeyMeta());

        // then
        assertEquals(List.of(offered), algorithms);
    }

    @Test
    void publishesWhatEncryptingWithTheKeyNeeds() {
        // given
        KeyPair pair = rsaKeyPair("v2-cipher-attrs");
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.publicKeyMeta());

        // when
        List<String> names = controller.listEncryptAttributes(request).stream().map(BaseAttribute::getName).toList();

        // then
        assertTrue(names.contains(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME), () -> "got " + names);
    }

    @Test
    void generatesRandomDataOfTheRequestedLength() {
        // given
        RandomDataRequestV2Dto request = new RandomDataRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-random")));
        request.setTokenProfileAttributes(List.of());
        request.setOperationAttributes(List.of());
        request.setLength(32);

        // when
        byte[] data = controller.randomData(request).getData();

        // then
        assertEquals(32, data.length);
    }

    @Test
    void publishesNoAttributesForRandomData() {
        // given
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-random-attrs")));
        request.setTokenProfileAttributes(List.of());

        // when
        // then
        assertTrue(controller.listRandomAttributes(request).isEmpty());
    }

    @Test
    void refusesToDeferSigningAndTracksNothing() {
        // given
        KeyPair pair = rsaKeyPair("v2-sign-async");
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.ASYNCHRONOUS);
        signing.setSignatureAttributes(rsaSignatureAttributes());
        signing.setData(List.of(item("one", MESSAGE)));

        // when
        // then
        OperationTrackingRequestV2Dto tracking = new OperationTrackingRequestV2Dto();

        assertThrows(NotSupportedException.class, () -> controller.signData(signing));
        assertThrows(OperationNotTrackedException.class, () -> controller.getSignStatus(tracking));
        assertThrows(OperationNotTrackedException.class, () -> controller.cancelSign(tracking));
    }

    private KeyPair rsaKeyPair(String prefix) {
        return rsaKeyPair(prefix, 2048);
    }

    private KeyPair rsaKeyPair(String prefix, int keySize) {
        CreateKeyRequestV2Dto creation = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName(prefix), "key-" + System.nanoTime());
        ((RequestAttributeV2) creation
                .getCreateKeyAttributes()
                .stream()
                .filter(attribute -> RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE.equals(attribute.getName()))
                .findFirst()
                .orElseThrow()).setContent(List.of(new IntegerAttributeContentV2(keySize)));
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) keys.createKey(creation).getBody();
        assertNotNull(created);
        return new KeyPair(creation.getTokenAttributes(), created.getPublicKeyData().getKeyMeta(),
                created.getPrivateKeyData().getKeyMeta(), created.getPublicKeyData().getKeyData().getPublicKeySpki());
    }

    private KeyPair ecdsaKeyPair(String prefix) {
        return v2KeyPair(prefix, List.of(algorithm(KeyAlgorithm.ECDSA), ecdsaCurve()));
    }

    private static RequestAttribute ecdsaCurve() {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE);
        attribute.setContent(List.of(new StringAttributeContentV2("secp256r1", "secp256r1")));
        return attribute;
    }

    /** An ML-DSA-65 key, stating the pre-hash choice V2 leaves out with the one value it offers there. */
    private KeyPair mldsaKeyPair(String prefix) {
        return v2KeyPair(prefix, List.of(algorithm(KeyAlgorithm.MLDSA), mldsaLevel(), mldsaPrehash(false)));
    }

    private static RequestAttribute mldsaLevel() {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL);
        attribute.setContent(List.of(new IntegerAttributeContentV2("MLDSA_65", 3)));
        return attribute;
    }

    private static RequestAttribute mldsaPrehash(boolean prehash) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH);
        attribute.setContent(List.of(new BooleanAttributeContentV2(prehash)));
        return attribute;
    }

    /** A Falcon-1024 key, stating the degree V2 leaves out with the one value it offers there. */
    private KeyPair falconKeyPair(String prefix) {
        return v2KeyPair(prefix, List.of(algorithm(KeyAlgorithm.FALCON), falconDegree(1024)));
    }

    private static RequestAttribute falconDegree(int degree) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE);
        attribute.setContent(List.of(new IntegerAttributeContentV2("FALCON_" + degree, degree)));
        return attribute;
    }

    /** An SLH-DSA-SHA2-128S key, stating the choices V2 leaves out with the one value it offers there. */
    private KeyPair slhdsaKeyPair(String prefix) {
        return v2KeyPair(prefix, slhdsa("SHA2", "SHA2", false));
    }

    private static List<RequestAttribute> slhdsa(String hashReference, String hashName, boolean prehash) {
        return List
                .of(algorithm(KeyAlgorithm.SLHDSA),
                        stringValue(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY, "CATEGORY_1", "1"),
                        stringValue(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH, hashReference, hashName),
                        stringValue(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE, "SMALL", "SMALL"),
                        booleanValue(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH, prehash));
    }

    private static RequestAttribute algorithm(KeyAlgorithm algorithm) {
        return TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, algorithm.getCode());
    }

    private KeyPair v2KeyPair(String prefix, List<RequestAttribute> parameters) {
        CreateKeyRequestV2Dto creation = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName(prefix), "key-" + System.nanoTime());
        creation.setCreateKeyAttributes(aliased(parameters));
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) keys.createKey(creation).getBody();
        assertNotNull(created);
        return new KeyPair(creation.getTokenAttributes(), created.getPublicKeyData().getKeyMeta(),
                created.getPrivateKeyData().getKeyMeta(), created.getPublicKeyData().getKeyData().getPublicKeySpki());
    }

    /** A key created through V1 under a token a V2 context addresses, named the way V2 names any key. */
    private KeyPair v1KeyPair(String prefix, List<RequestAttribute> parameters) throws NotFoundException {
        List<RequestAttribute> tokenAttributes = TokenContextFixtures.newToken(TokenContextFixtures.uniqueName(prefix));
        UUID token = tokenContextService.resolve(tokenAttributes).instance().getUuid();
        CreateKeyRequestDto creation = new CreateKeyRequestDto();
        creation.setCreateKeyAttributes(aliased(parameters));
        KeyPairDataResponseDto created = keyManagementService.createKeyPair(token, creation);
        return new KeyPair(tokenAttributes,
                List.of(KeyAttributes.buildKeyReferenceMetadata(created.getPublicKeyData().getUuid())),
                List.of(KeyAttributes.buildKeyReferenceMetadata(created.getPrivateKeyData().getUuid())), null);
    }

    private static List<RequestAttribute> aliased(List<RequestAttribute> parameters) {
        List<RequestAttribute> attributes = new ArrayList<>(parameters);
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, "key-" + System.nanoTime()));
        return attributes;
    }

    private KeyData row(List<MetadataAttribute> keyMeta) {
        String reference = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(KeyAttributes.ATTRIBUTE_META_KEY_REFERENCE, keyMeta,
                        StringAttributeContentV2.class)
                .getData();
        return keyDataRepository.findByUuid(UUID.fromString(reference)).orElseThrow();
    }

    private void destroy(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> keyMeta) {
        DestroyKeyRequestV2Dto destruction = new DestroyKeyRequestV2Dto();
        apply(destruction, tokenAttributes, keyMeta);
        destruction.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        keys.destroyKey(destruction);
    }

    private List<SignatureAlgorithm> offered(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> keyMeta) {
        DataAttributeV3 selection = (DataAttributeV3) controller
                .listSignAttributes(scoped(tokenAttributes, keyMeta))
                .get(0);
        return selection
                .getContent()
                .stream()
                .map(value -> SignatureAlgorithm.findByCode((String) value.getData()))
                .toList();
    }

    private static KeyScopedRequestV2Dto scoped(List<RequestAttribute> tokenAttributes,
            List<MetadataAttribute> keyMeta) {
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, tokenAttributes, keyMeta);
        return request;
    }

    private static SignDataRequestV2Dto signing(KeyPair pair, List<RequestAttribute> signatureAttributes) {
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(signatureAttributes);
        signing.setData(List.of(item("one", MESSAGE)));
        return signing;
    }

    private static VerifyDataRequestV2Dto verification(KeyPair pair, SignatureAlgorithm algorithm) {
        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        apply(verification, pair.tokenAttributes(), pair.publicKeyMeta());
        verification.setSignatureAttributes(List.of(SignatureAlgorithmAttribute.request(algorithm)));
        verification.setData(List.of(item("one", MESSAGE)));
        verification.setSignatures(List.of(item("one", new byte[]{1})));
        return verification;
    }

    private static RequestAttribute stringValue(String name, String reference, String data) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(reference, data)));
        return attribute;
    }

    private static RequestAttribute booleanValue(String name, boolean value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new BooleanAttributeContentV2(value)));
        return attribute;
    }

    private static void apply(KeyScopedRequestV2Dto request, List<RequestAttribute> tokenAttributes,
            List<MetadataAttribute> keyMeta) {
        request.setTokenAttributes(tokenAttributes);
        request.setTokenProfileAttributes(List.of());
        request.setKeyMeta(keyMeta);
    }

    private void signsAndVerifies(KeyPair pair, SignatureAlgorithm algorithm) {
        List<RequestAttribute> choice = List.of(SignatureAlgorithmAttribute.request(algorithm));
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair.tokenAttributes(), pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(choice);
        signing.setData(List.of(item("one", MESSAGE)));
        SignDataResponseV2Dto signed = controller.signData(signing).getBody();
        assertNotNull(signed);

        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        apply(verification, pair.tokenAttributes(), pair.publicKeyMeta());
        verification.setSignatureAttributes(choice);
        verification.setData(List.of(item("one", MESSAGE)));
        verification.setSignatures(signed.getSignatures());
        assertTrue(controller.verifyData(verification).getVerifications().get(0).getResult());
    }

    private void signsAfterPublicHalfIsDestroyed(KeyPair pair, SignatureAlgorithm algorithm) {
        destroy(pair.tokenAttributes(), pair.publicKeyMeta());

        assertEquals(List.of(algorithm), offered(pair.tokenAttributes(), pair.privateKeyMeta()));

        SignDataRequestV2Dto signing = signing(pair, List.of(SignatureAlgorithmAttribute.request(algorithm)));
        SignDataResponseV2Dto signed = controller.signData(signing).getBody();
        assertNotNull(signed);
        assertEquals(1, signed.getSignatures().size());
    }

    private static List<RequestAttribute> rsaSignatureAttributes() {
        return List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_RSA));
    }

    private static List<RequestAttribute> rsaCipherAttributes() {
        return List
                .of(TokenContextFixtures.string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, "PKCS1-v1_5"));
    }

    private static SignatureDataV2Dto item(String identifier, byte[] data) {
        SignatureDataV2Dto signature = new SignatureDataV2Dto();
        signature.setIdentifier(identifier);
        signature.setData(data);
        return signature;
    }

    private static CipherDataV2Dto cipherItem(String identifier, byte[] data) {
        CipherDataV2Dto cipher = new CipherDataV2Dto();
        cipher.setIdentifier(identifier);
        cipher.setData(data);
        return cipher;
    }

    private static boolean verifiesExternally(byte[] spki, String keyAlgorithm, String signatureAlgorithm, byte[] data,
            byte[] signature) throws GeneralSecurityException {
        var publicKey = KeyFactory
                .getInstance(keyAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(new X509EncodedKeySpec(spki));
        Signature verifier = Signature.getInstance(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private record KeyPair(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> publicKeyMeta,
            List<MetadataAttribute> privateKeyMeta, byte[] publicKeySpki) {
    }
}
