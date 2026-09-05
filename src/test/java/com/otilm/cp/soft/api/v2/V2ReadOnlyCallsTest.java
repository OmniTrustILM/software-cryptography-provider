package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyAttributesRequestV2Dto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A call that only describes what this connector accepts leaves nothing behind.
 *
 * <p>
 * The V2 interfaces have no operation that creates a token, so a context asking for one by name brings it into
 * existence the first time it is used. Asking which key types can be imported, or what a creation asks for, is not
 * using it: a platform enumerating what a connector offers would otherwise leave a token and a keystore behind for
 * every name it asked about.
 * </p>
 */
@SpringBootTest
class V2ReadOnlyCallsTest {

    private KeyV2ControllerImpl controller;

    private OperationsV2ControllerImpl operations;

    private TokenInstanceRepository tokenInstanceRepository;

    @Autowired
    void setController(KeyV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setOperations(OperationsV2ControllerImpl operations) {
        this.operations = operations;
    }

    @Autowired
    void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Test
    void bringsNoTokenIntoExistenceToSayWhichKeyTypesItTakesIn() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-read-import-types");
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(name));
        request.setTokenProfileAttributes(List.of());

        // when
        assertFalse(controller.listImportableKeyTypes(request).isEmpty());

        // then
        assertNoTokenNamed(name);
    }

    @Test
    void bringsNoTokenIntoExistenceToSayWhichKeyTypesItLetsOut() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-read-export-types");
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(name));
        request.setTokenProfileAttributes(List.of());

        // when
        assertFalse(controller.listExportableKeyTypes(request).isEmpty());

        // then
        assertNoTokenNamed(name);
    }

    @Test
    void bringsNoTokenIntoExistenceToSayWhatACreationAsksFor() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-read-create-attrs");
        CreateKeyAttributesRequestV2Dto request = new CreateKeyAttributesRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(name));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setKeyUsages(Set.of(KeyUsage.SIGN, KeyUsage.VERIFY));

        // when
        assertFalse(controller.listCreateKeyAttributes(request).isEmpty());

        // then
        assertNoTokenNamed(name);
    }

    @Test
    void bringsNoTokenIntoExistenceToSayWhatAnImportAsksFor() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-read-import-attrs");
        ImportKeyAttributesRequestV2Dto request = new ImportKeyAttributesRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(name));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setKeyUsages(Set.of(KeyUsage.SIGN, KeyUsage.VERIFY));

        // when
        assertFalse(controller.listImportKeyAttributes(request).isEmpty());

        // then
        assertNoTokenNamed(name);
    }

    @Test
    void bringsNoTokenIntoExistenceToSayWhatRandomDataAsksFor() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-read-random-attrs");
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(name));
        request.setTokenProfileAttributes(List.of());

        // when
        operations.listRandomAttributes(request);

        // then
        assertNoTokenNamed(name);
    }

    /** A context selecting a token that is not there addresses nothing, whether or not the call would create one. */
    @Test
    void refusesAContextSelectingATokenThatIsNotThere() {
        // given
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request
                .setTokenAttributes(
                        TokenContextFixtures.existingToken(UUID.randomUUID(), "gone", TokenContextFixtures.CODE));
        request.setTokenProfileAttributes(List.of());

        // when
        // then
        assertThrows(ResourceMissingException.class, () -> controller.listImportableKeyTypes(request));
    }

    private void assertNoTokenNamed(String name) {
        assertTrue(tokenInstanceRepository.findAll().stream().noneMatch(token -> name.equals(token.getName())),
                () -> "a call that only describes what this connector accepts created the token " + name);
    }
}
