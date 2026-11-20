package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import com.otilm.api.model.connector.cryptography.v2.OperationValidationResult;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyResultRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.cp.soft.testsupport.KeyImportFixtures;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import jakarta.validation.Validator;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A creation or import answer the platform refuses orphans the new key in the token.
 */
@SpringBootTest
class KeyPairResponseContractTest {

    private KeyV2ControllerImpl controller;

    private OperationResponseValidator contract;

    @Autowired
    void setController(KeyV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setValidator(Validator validator) {
        this.contract = new OperationResponseValidator(validator);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("com.otilm.cp.soft.testsupport.KeyRequestFixtures#everyKeyPairV2Creates")
    void answersACreationWithAValidKeyPair(String variant, List<RequestAttribute> parameters) throws IOException {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .keyPair(TokenContextFixtures.uniqueName("v2-contract-create"), "key-" + System.nanoTime(), parameters);

        // when
        ResponseEntity<KeyCreationResponseV2Dto> answer = controller.createKey(request);

        // then
        assertAccepted(contract.validateCreateKey(request, answer));
        assertDescribesThePrivateHalf(answer.getBody());
    }

    @Test
    void answersARepeatedCreationWithAValidKeyPair() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-contract-replay"), "key-" + System.nanoTime());
        controller.createKey(request);

        // when
        OperationValidationResult validation = contract.validateCreateKey(request, controller.createKey(request));

        // then
        assertAccepted(validation);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("com.otilm.cp.soft.testsupport.KeyImportFixtures#everyKeyV2Imports")
    void answersAnImportWithAValidKeyPair(String variant, KeyImportFixtures.Generation generation) throws IOException {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .importOf(TokenContextFixtures.uniqueName("v2-contract-import"),
                        KeyImportFixtures.generatedKey(generation));

        // when
        ResponseEntity<KeyCreationResponseV2Dto> answer = controller.importKey(request);

        // then
        assertAccepted(contract.keyTransfer().validateImportKey(request, answer));
        assertDescribesThePrivateHalf(answer.getBody());
    }

    @Test
    void answersARepeatedImportWithAValidKeyPair() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-contract-import-again"));
        controller.importKey(request);

        // when
        OperationValidationResult validation = contract
                .keyTransfer()
                .validateImportKey(request, controller.importKey(request));

        // then
        assertAccepted(validation);
    }

    @Test
    void answersAnImportResultWithAValidKeyPair() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-contract-import-result"));
        controller.importKey(request);

        ImportKeyResultRequestV2Dto lost = new ImportKeyResultRequestV2Dto();
        lost.setTokenAttributes(request.getTokenAttributes());
        lost.setKeyImportId(request.getKeyImportId());

        // when
        OperationValidationResult validation = contract
                .keyTransfer()
                .validateImportKeyStatus(controller.getImportKeyResult(lost));

        // then
        assertAccepted(validation);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("com.otilm.cp.soft.testsupport.KeyRequestFixtures#everyKeyPairV2Creates")
    void answersAnExportWithAValidDescriptor(String variant, List<RequestAttribute> parameters) {
        // given
        List<RequestAttribute> exportable = new ArrayList<>(parameters);
        exportable.add(KeyRequestFixtures.exportableIntent(true));
        CreateKeyRequestV2Dto creation = KeyRequestFixtures
                .keyPair(TokenContextFixtures.uniqueName("v2-contract-export"), "key-" + System.nanoTime(), exportable);
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) controller.createKey(creation).getBody();
        assertNotNull(created);
        ExportKeyRequestV2Dto request = exportOf(creation, created);

        // when
        ExportKeyResponseV2Dto exported = controller.exportKey(request);

        // then
        assertAccepted(contract.keyTransfer().validateExportKey(request, ResponseEntity.ok(exported)));
        assertAccepted(contract
                .keyTransfer()
                .validateExportedKeyDescriptor(created.getPublicKeyData().getKeyData(), exported));
    }

    private static ExportKeyRequestV2Dto exportOf(CreateKeyRequestV2Dto creation, KeyPairDataResponseV2Dto created) {
        ExportKeyRequestV2Dto request = new ExportKeyRequestV2Dto();
        request.setTokenAttributes(creation.getTokenAttributes());
        request.setTokenProfileAttributes(List.of());
        request.setKeyMeta(created.getPrivateKeyData().getKeyMeta());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setExportKeyAttributes(List.of());
        request.setPassphrase("a passphrase the caller chose");
        return request;
    }

    private static void assertAccepted(OperationValidationResult validation) {
        assertTrue(validation.isValid(), () -> "the platform refuses this response: " + validation.getCause());
    }

    private static void assertDescribesThePrivateHalf(KeyCreationResponseV2Dto answer) throws IOException {
        KeyPairDataResponseV2Dto pair = (KeyPairDataResponseV2Dto) answer;
        PrivateKeyDataV2Dto privateHalf = pair.getPrivateKeyData().getKeyData();
        assertNotNull(privateHalf.getAlgorithmIdentifier(), "the private half names its parameters");
        assertEquals(expectedPrivateLength(pair.getPublicKeyData().getKeyData()), privateHalf.getLength(),
                "the private half's stated size");
    }

    /** An RSA identifier carries no size. The modulus gives it. */
    private static Integer expectedPrivateLength(PublicKeyDataV2Dto publicHalf) throws IOException {
        if (publicHalf.getAlgorithm() != KeyAlgorithm.RSA) {
            return null;
        }
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicHalf.getPublicKeySpki());
        return RSAPublicKey.getInstance(spki.parsePublicKey()).getModulus().bitLength();
    }
}
