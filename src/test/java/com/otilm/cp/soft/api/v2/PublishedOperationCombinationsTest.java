package com.otilm.cp.soft.api.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.DecryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every combination this connector publishes as a choice is either performed or refused for what it is.
 *
 * <p>
 * The operation attributes are what a caller picks from, and each is a choice of its own, so nothing in the schema can
 * say that one choice rules out a value of another — a digest one signature scheme signs with and another does not. A
 * caller can therefore always assemble a combination that cannot be performed, and the answer has to say so rather than
 * fail as though the connector had broken.
 * </p>
 *
 * <p>
 * The choices come from enumerations the interfaces define, which grow, so what is published is walked here rather than
 * listed: a value added to one of them is either performed or named as one this connector cannot perform.
 * </p>
 */
@SpringBootTest
class PublishedOperationCombinationsTest {

    private static final byte[] MESSAGE = "a message to sign".getBytes(StandardCharsets.UTF_8);

    private static final byte[] PLAINTEXT = "a short secret".getBytes(StandardCharsets.UTF_8);

    private OperationsV2ControllerImpl operations;

    private KeyV2ControllerImpl keys;

    @Autowired
    void setOperations(OperationsV2ControllerImpl operations) {
        this.operations = operations;
    }

    @Autowired
    void setKeys(KeyV2ControllerImpl keys) {
        this.keys = keys;
    }

    @Test
    void signsAndVerifiesWithEveryCombinationItPublishesForAnRsaKey() {
        // given
        KeyPair pair = keyPair("v2-published-rsa-sign");
        List<BaseAttribute> published = operations.listSignAttributes(scoped(pair, pair.privateKeyMeta()));
        int performed = 0;

        // when
        // then
        for (List<RequestAttribute> chosen : everyChoiceIn(published)) {
            performed += performedOrRefusedForWhatItIs(() -> signsAndVerifies(pair, chosen), chosen) ? 1 : 0;
        }
        assertTrue(performed > 0, "a schema whose every combination is refused offers nothing");
    }

    @Test
    void encryptsAndDecryptsWithEveryCombinationItPublishesForAnRsaKey() {
        // given
        KeyPair pair = keyPair("v2-published-rsa-cipher");
        List<BaseAttribute> published = operations.listEncryptAttributes(scoped(pair, pair.publicKeyMeta()));
        int performed = 0;

        // when
        // then
        for (List<RequestAttribute> chosen : everyChoiceIn(published)) {
            performed += performedOrRefusedForWhatItIs(() -> encryptsAndDecrypts(pair, chosen), chosen) ? 1 : 0;
        }
        assertTrue(performed > 0, "a schema whose every combination is refused offers nothing");
    }

    /**
     * Whether the combination was performed. One that cannot be has to be named as such: any other failure is the
     * connector breaking on a combination it published, which is what a caller cannot act on.
     */
    private static boolean performedOrRefusedForWhatItIs(Runnable operation, List<RequestAttribute> chosen) {
        try {
            operation.run();
            return true;
        } catch (ParameterUnsupportedException | ValidationException e) {
            return false;
        } catch (RuntimeException e) {
            throw new AssertionError(describe(chosen) + " was published and then failed with " + e, e);
        }
    }

    private void signsAndVerifies(KeyPair pair, List<RequestAttribute> signatureAttributes) {
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair, pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(signatureAttributes);
        signing.setData(List.of(signed("one", MESSAGE)));

        SignDataResponseV2Dto made = operations.signData(signing).getBody();
        assertNotNull(made, () -> "nothing was signed with " + describe(signatureAttributes));

        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        apply(verification, pair, pair.publicKeyMeta());
        verification.setSignatureAttributes(signatureAttributes);
        verification.setData(List.of(signed("one", MESSAGE)));
        verification.setSignatures(made.getSignatures());

        assertTrue(operations.verifyData(verification).getVerifications().get(0).getResult(),
                () -> "a signature made with " + describe(signatureAttributes) + " did not verify");
    }

    private void encryptsAndDecrypts(KeyPair pair, List<RequestAttribute> cipherAttributes) {
        CipherDataRequestV2Dto encryption = new CipherDataRequestV2Dto();
        apply(encryption, pair, pair.publicKeyMeta());
        encryption.setCipherAttributes(cipherAttributes);
        encryption.setCipherData(List.of(cipher("one", PLAINTEXT)));

        EncryptDataResponseV2Dto encrypted = operations.encryptData(encryption);
        assertNotNull(encrypted, () -> "nothing was encrypted with " + describe(cipherAttributes));

        CipherDataRequestV2Dto decryption = new CipherDataRequestV2Dto();
        apply(decryption, pair, pair.privateKeyMeta());
        decryption.setCipherAttributes(cipherAttributes);
        decryption.setCipherData(encrypted.getEncryptedData());

        DecryptDataResponseV2Dto decrypted = operations.decryptData(decryption);
        assertArrayEquals(PLAINTEXT, decrypted.getDecryptedData().get(0).getData(),
                () -> "what was encrypted with " + describe(cipherAttributes) + " did not come back");
    }

    /**
     * Every way of answering the published attributes, one value at a time. Each attribute offering a list is walked
     * through its own values while the others hold their first, which covers every published value without multiplying
     * the attributes together.
     */
    private static List<List<RequestAttribute>> everyChoiceIn(List<BaseAttribute> published) {
        List<List<RequestAttribute>> choices = new ArrayList<>();
        for (BaseAttribute varying : published) {
            for (BaseAttributeContentV2<?> value : valuesOf(varying)) {
                List<RequestAttribute> chosen = new ArrayList<>();
                for (BaseAttribute attribute : published) {
                    BaseAttributeContentV2<?> taken = attribute == varying ? value : valuesOf(attribute).get(0);
                    chosen.add(stating(attribute.getName(), taken));
                }
                choices.add(chosen);
            }
        }
        return choices;
    }

    private static List<BaseAttributeContentV2<?>> valuesOf(BaseAttribute attribute) {
        return ((DataAttributeV2) attribute).getContent();
    }

    private static RequestAttribute stating(String name, BaseAttributeContentV2<?> value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(value));
        return attribute;
    }

    private static String describe(List<RequestAttribute> chosen) {
        return chosen.stream().map(attribute -> attribute.getName() + "=" + attribute.getContent()).toList().toString();
    }

    private KeyPair keyPair(String prefix) {
        CreateKeyRequestV2Dto creation = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName(prefix), "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) keys.createKey(creation).getBody();
        assertNotNull(created);
        return new KeyPair(creation.getTokenAttributes(), created.getPublicKeyData().getKeyMeta(),
                created.getPrivateKeyData().getKeyMeta());
    }

    private static KeyScopedRequestV2Dto scoped(KeyPair pair, List<MetadataAttribute> keyMeta) {
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair, keyMeta);
        return request;
    }

    private static void apply(KeyScopedRequestV2Dto request, KeyPair pair, List<MetadataAttribute> keyMeta) {
        request.setTokenAttributes(pair.tokenAttributes());
        request.setTokenProfileAttributes(List.of());
        request.setKeyUsages(Set.of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        request.setKeyMeta(keyMeta);
    }

    private static SignatureDataV2Dto signed(String identifier, byte[] data) {
        SignatureDataV2Dto item = new SignatureDataV2Dto();
        item.setIdentifier(identifier);
        item.setData(data);
        return item;
    }

    private static CipherDataV2Dto cipher(String identifier, byte[] data) {
        CipherDataV2Dto item = new CipherDataV2Dto();
        item.setIdentifier(identifier);
        item.setData(data);
        return item;
    }

    private record KeyPair(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> publicKeyMeta,
            List<MetadataAttribute> privateKeyMeta) {
    }
}
