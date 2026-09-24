package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import com.otilm.api.model.connector.cryptography.v2.OperationValidationResult;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyResultRequestV2Dto;
import com.otilm.cp.soft.testsupport.KeyImportFixtures;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every key-pair response passes the platform's validation. A refused response orphans the key in the token.
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

    @Test
    void answersACreationWithAValidKeyPair() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-contract-create"), "key-" + System.nanoTime());

        // when
        OperationValidationResult validation = contract.validateCreateKey(request, controller.createKey(request));

        // then
        assertAccepted(validation);
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

    @Test
    void answersAnImportWithAValidKeyPair() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-contract-import"));

        // when
        OperationValidationResult validation = contract
                .keyTransfer()
                .validateImportKey(request, controller.importKey(request));

        // then
        assertAccepted(validation);
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

    private static void assertAccepted(OperationValidationResult validation) {
        assertTrue(validation.isValid(), () -> "the platform refuses this response: " + validation.getCause());
    }
}
