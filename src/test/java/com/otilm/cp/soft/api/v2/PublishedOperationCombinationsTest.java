package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.DecryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Checks advertised V2 choices against the operations. Every RSA signing choice must work; cipher combinations may be
 * performed or refused with a parameter error.
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
    void rsaKeySignsAndVerifiesWithEveryPublishedAlgorithm() throws GeneralSecurityException {
        // given
        KeyPair pair = keyPair("v2-published-rsa-sign");
        List<BaseAttribute> published = operations.listSignAttributes(scoped(pair, pair.privateKeyMeta()));
        List<List<RequestAttribute>> choices = everyChoiceIn(published);

        // when
        // then
        assertFalse(choices.isEmpty());
        for (List<RequestAttribute> chosen : choices) {
            signsAndVerifies(pair, chosen);
        }
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
        } catch (ParameterUnsupportedException e) {
            return false;
        } catch (RuntimeException e) {
            throw new AssertionError(describe(chosen) + " was published and then failed with " + e, e);
        }
    }

    private void signsAndVerifies(KeyPair pair, List<RequestAttribute> signatureAttributes)
            throws GeneralSecurityException {
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        apply(signing, pair, pair.privateKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(signatureAttributes);
        signing.setData(List.of(signed("one", MESSAGE)));

        SignDataResponseV2Dto made = operations.signData(signing).getBody();
        assertNotNull(made, () -> "nothing was signed with " + describe(signatureAttributes));
        SignatureAlgorithm selected = SignatureAlgorithmAttribute.selectedAlgorithm(signatureAttributes);
        Signature externalVerifier = Signature
                .getInstance(rsaSignatureName(selected), BouncyCastleProvider.PROVIDER_NAME);
        externalVerifier
                .initVerify(KeyFactory
                        .getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(new X509EncodedKeySpec(pair.publicKeySpki())));
        externalVerifier.update(MESSAGE);
        assertTrue(externalVerifier.verify(made.getSignatures().get(0).getData()),
                () -> selected + " did not produce its selected RSA signature");

        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        apply(verification, pair, pair.publicKeyMeta());
        verification.setSignatureAttributes(signatureAttributes);
        verification.setData(List.of(signed("one", MESSAGE)));
        verification.setSignatures(made.getSignatures());

        assertTrue(operations.verifyData(verification).getVerifications().get(0).getResult(),
                () -> "a signature made with " + describe(signatureAttributes) + " did not verify");
    }

    private static String rsaSignatureName(SignatureAlgorithm selected) {
        return switch (selected) {
            case SHA256_WITH_RSA -> "SHA256withRSA";
            case SHA384_WITH_RSA -> "SHA384withRSA";
            case SHA512_WITH_RSA -> "SHA512withRSA";
            case SHA256_WITH_RSA_PSS -> "SHA256withRSAandMGF1";
            case SHA384_WITH_RSA_PSS -> "SHA384withRSAandMGF1";
            case SHA512_WITH_RSA_PSS -> "SHA512withRSAandMGF1";
            default -> throw new AssertionError("Unexpected RSA signature selection: " + selected);
        };
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

    /** Expands independent schema choices so interactions between attributes are exercised. */
    private static List<List<RequestAttribute>> everyChoiceIn(List<BaseAttribute> published) {
        List<List<RequestAttribute>> choices = new ArrayList<>();
        choices.add(new ArrayList<>());
        for (BaseAttribute attribute : published) {
            List<List<RequestAttribute>> widened = new ArrayList<>();
            for (List<RequestAttribute> chosen : choices) {
                for (RequestAttribute selection : selectionsOf(attribute)) {
                    List<RequestAttribute> widerChoice = new ArrayList<>(chosen);
                    widerChoice.add(selection);
                    widened.add(widerChoice);
                }
            }
            choices = widened;
        }
        return choices;
    }

    private static List<RequestAttribute> selectionsOf(BaseAttribute attribute) {
        if (attribute instanceof DataAttributeV3 data) {
            return data
                    .getContent()
                    .stream()
                    .map(value -> SignatureAlgorithmAttribute
                            .request(SignatureAlgorithm.findByCode((String) value.getData())))
                    .map(RequestAttribute.class::cast)
                    .toList();
        }
        return ((DataAttributeV2) attribute)
                .getContent()
                .stream()
                .map(value -> stating(attribute.getName(), value))
                .toList();
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
                created.getPrivateKeyData().getKeyMeta(), created.getPublicKeyData().getKeyData().getPublicKeySpki());
    }

    private static KeyScopedRequestV2Dto scoped(KeyPair pair, List<MetadataAttribute> keyMeta) {
        KeyScopedRequestV2Dto request = new KeyScopedRequestV2Dto();
        apply(request, pair, keyMeta);
        return request;
    }

    private static void apply(KeyScopedRequestV2Dto request, KeyPair pair, List<MetadataAttribute> keyMeta) {
        request.setTokenAttributes(pair.tokenAttributes());
        request.setTokenProfileAttributes(List.of());
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
            List<MetadataAttribute> privateKeyMeta, byte[] publicKeySpki) {
    }
}
