package com.otilm.cp.soft.api.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.VerificationResponseItemV2Dto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.attribute.RsaCipherAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
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

    @Autowired
    void setController(OperationsV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setKeys(KeyV2ControllerImpl keys) {
        this.keys = keys;
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
    void publishesWhatSigningWithTheKeyNeeds() {
        // given
        KeyPair pair = rsaKeyPair("v2-sign-attrs");
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair.tokenAttributes(), pair.privateKeyMeta());

        // when
        List<BaseAttribute> attributes = controller.listSignAttributes(request);

        // then
        List<String> names = attributes.stream().map(BaseAttribute::getName).toList();
        assertEquals(
                List.of(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST),
                names);
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
        request.setKeyUsages(Set.of(KeyUsage.SIGN));
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
        request.setKeyUsages(Set.of(KeyUsage.SIGN));

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
        CreateKeyRequestV2Dto creation = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName(prefix), "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) keys.createKey(creation).getBody();
        assertNotNull(created);
        return new KeyPair(creation.getTokenAttributes(), created.getPublicKeyData().getKeyMeta(),
                created.getPrivateKeyData().getKeyMeta());
    }

    private static void apply(KeyScopedRequestV2Dto request, List<RequestAttribute> tokenAttributes,
            List<MetadataAttribute> keyMeta) {
        request.setTokenAttributes(tokenAttributes);
        request.setTokenProfileAttributes(List.of());
        request.setKeyUsages(Set.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        request.setKeyMeta(keyMeta);
    }

    private static List<RequestAttribute> rsaSignatureAttributes() {
        return List
                .of(TokenContextFixtures
                        .string(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                                RsaSignatureScheme.PKCS1_v1_5.getCode()),
                        TokenContextFixtures
                                .string(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, DigestAlgorithm.SHA_256.getCode()));
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

    private record KeyPair(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> publicKeyMeta,
            List<MetadataAttribute> privateKeyMeta) {
    }
}
