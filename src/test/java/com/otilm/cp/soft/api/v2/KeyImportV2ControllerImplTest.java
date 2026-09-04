package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyResultRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportableKeyTypeV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.exception.ExportableNotSupportedException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.KeyTypeNotImportableException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.testsupport.KeyImportFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An import brings a key the platform already holds into a token, and the key it produces has to be the same kind of
 * key a creation produces: addressed by the handles published for it, and usable by the operations.
 */
@SpringBootTest
class KeyImportV2ControllerImplTest {

    private KeyV2ControllerImpl controller;

    private OperationsV2ControllerImpl operations;

    @Autowired
    void setController(KeyV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setOperations(OperationsV2ControllerImpl operations) {
        this.operations = operations;
    }

    @Test
    void importsAKeyAndPublishesAHandleForEachHalf() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import"));

        // when
        KeyPairDataResponseV2Dto imported = (KeyPairDataResponseV2Dto) controller.importKey(request).getBody();

        // then
        assertNotNull(imported);
        assertEquals(KeyRequestType.KEY_PAIR, imported.getKeyRequestType());
        assertNotNull(imported.getPublicKeyData().getKeyData().getPublicKeySpki(),
                "the public half travels as its SPKI, as a created key's does");
        assertFalse(imported.getPublicKeyData().getKeyMeta().isEmpty());
        assertFalse(imported.getPrivateKeyData().getKeyMeta().isEmpty());
        assertEquals(KeyAlgorithm.RSA, imported.getPrivateKeyData().getKeyData().getAlgorithm());
    }

    /** An imported key is a key like any other, so the operations must work through the handles it published. */
    @Test
    void signsWithAnImportedKey() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import-sign"));
        KeyPairDataResponseV2Dto imported = (KeyPairDataResponseV2Dto) controller.importKey(request).getBody();
        assertNotNull(imported);

        // when
        // then
        assertTrue(
                KeyImportFixtures
                        .signsAndVerifies(operations, request.getTokenAttributes(),
                                imported.getPrivateKeyData().getKeyMeta(), imported.getPublicKeyData().getKeyMeta()),
                "a signature made with an imported key must verify with its own public half");
    }

    /** A caller that lost the response repeats the request, and must be given the key rather than a second one. */
    @Test
    void answersARepeatedImportWithTheKeyItAlreadyMade() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import-again"));
        KeyPairDataResponseV2Dto first = (KeyPairDataResponseV2Dto) controller.importKey(request).getBody();

        // when
        KeyPairDataResponseV2Dto repeat = (KeyPairDataResponseV2Dto) controller.importKey(request).getBody();

        // then
        assertNotNull(first);
        assertNotNull(repeat);
        assertEquals(first.getPrivateKeyData().getKeyMeta().toString(),
                repeat.getPrivateKeyData().getKeyMeta().toString());
    }

    @Test
    void refusesAnImportIdentifierReusedForADifferentRequest() {
        // given
        ImportKeyRequestV2Dto first = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import-clash"));
        controller.importKey(first);

        ImportKeyRequestV2Dto other = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-import-clash-other"));
        other.setKeyImportId(first.getKeyImportId());

        // when
        // then
        assertThrows(OperationConflictException.class, () -> controller.importKey(other));
    }

    /**
     * The contract has the key itself decide whether two imports are the same request, since the platform protects the
     * material afresh every time. Everything but the key is held equal here, so only the key can be what makes them
     * different.
     */
    @Test
    void refusesAnImportIdentifierReusedForAnotherKey() {
        // given
        ImportKeyRequestV2Dto first = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import-swap"));
        controller.importKey(first);

        ImportKeyRequestV2Dto anotherKey = KeyImportFixtures.sameRequestCarrying(first, KeyImportFixtures.anotherKey());

        // when
        // then
        assertThrows(OperationConflictException.class, () -> controller.importKey(anotherKey));
    }

    /**
     * The identity the platform holds for a key belongs to one key, and no repeating would free it, so a second import
     * claiming it is refused as a conflict rather than told to try again.
     */
    @Test
    void refusesASecondImportClaimingAnIdentityTheFirstHolds() {
        // given
        ImportKeyRequestV2Dto first = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import-ref"));
        controller.importKey(first);

        ImportKeyRequestV2Dto other = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-import-ref-other"));
        other.setKeyReference(first.getKeyReference());

        // when
        // then
        assertThrows(OperationConflictException.class, () -> controller.importKey(other));
    }

    /** A repeat carrying the wrong passphrase has not proved it holds the key, so it is not answered as a repeat. */
    @Test
    void refusesARepeatThatCannotOpenItsOwnMaterial() {
        // given
        ImportKeyRequestV2Dto first = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import-wrong"));
        controller.importKey(first);

        ImportKeyRequestV2Dto wrongPassphrase = KeyImportFixtures.sameRequestCarrying(first, first.getMaterial());
        wrongPassphrase.setPassphrase("not the passphrase it was protected under");

        // when
        // then
        assertThrows(KeyManagementException.class, () -> controller.importKey(wrongPassphrase));
    }

    /** An algorithm this provider does not hold is a key type it cannot take in, not an unreadable key. */
    @Test
    void refusesAnAlgorithmItDoesNotHold() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-import-ed25519"));
        request.setMaterial(KeyImportFixtures.ed25519Material());

        // when
        // then
        assertThrows(KeyTypeNotImportableException.class, () -> controller.importKey(request));
    }

    /**
     * Whether a key may leave the token can never be changed afterwards, so a key that stays exportable cannot be
     * accepted while this connector does not offer export.
     */
    @Test
    void refusesAKeyThatStaysExportable() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-import-exportable"));
        request.setExportable(true);

        // when
        // then
        assertThrows(ExportableNotSupportedException.class, () -> controller.importKey(request));
    }

    /** A caller that never heard the answer asks what became of the import under the identifier it used. */
    @Test
    void tellsACallerWhatBecameOfAnImport() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-import-result"));
        KeyPairDataResponseV2Dto imported = (KeyPairDataResponseV2Dto) controller.importKey(request).getBody();
        assertNotNull(imported);

        ImportKeyResultRequestV2Dto lost = new ImportKeyResultRequestV2Dto();
        lost.setTokenAttributes(request.getTokenAttributes());
        lost.setKeyImportId(request.getKeyImportId());

        // when
        KeyCreationStatusResponseV2Dto status = controller.getImportKeyResult(lost);

        // then
        assertEquals(OperationStatus.COMPLETED, status.getStatus());
        KeyPairOperationStatusResponseV2Dto pair = (KeyPairOperationStatusResponseV2Dto) status;
        assertEquals(imported.getPrivateKeyData().getKeyMeta().toString(),
                pair.getResult().getPrivateKeyData().getKeyMeta().toString());
    }

    /**
     * Opening one token says nothing about a key in another, and an import identifier is a value a caller could guess
     * its way to, so what an import produced is only ever answered to the token holding it.
     */
    @Test
    void tellsNoOtherTokenWhatAnImportProduced() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-import-mine"));
        controller.importKey(request);

        ImportKeyResultRequestV2Dto asAnotherToken = new ImportKeyResultRequestV2Dto();
        asAnotherToken
                .setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-import-theirs")));
        asAnotherToken.setKeyImportId(request.getKeyImportId());

        // when
        // then
        assertThrows(ResourceMissingException.class, () -> controller.getImportKeyResult(asAnotherToken));
    }

    @Test
    void refusesToReportOnAnImportItNeverMade() {
        // given
        ImportKeyResultRequestV2Dto unknown = new ImportKeyResultRequestV2Dto();
        unknown.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-import-none")));
        unknown.setKeyImportId(UUID.randomUUID().toString());

        // when
        // then
        assertThrows(ResourceMissingException.class, () -> controller.getImportKeyResult(unknown));
    }

    /** An import completes inline, so there is never one in flight to report on or to call off. */
    @Test
    void tracksNoImportInFlight() {
        // given
        var tracking = KeyImportFixtures.tracking();

        // when
        // then
        assertThrows(OperationNotTrackedException.class, () -> controller.getImportKeyStatus(tracking));
        assertThrows(OperationNotTrackedException.class, () -> controller.cancelImportKey(tracking));
    }

    @Test
    void advertisesEveryAlgorithmItCanCreateAsImportable() {
        // given
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-import-types")));
        request.setTokenProfileAttributes(List.of());

        // when
        List<ImportableKeyTypeV2Dto> importable = controller.listImportableKeyTypes(request);

        // then
        assertEquals(1, importable.size(), "only key pairs can be imported, since only they can be created");
        assertEquals(KeyRequestType.KEY_PAIR, importable.get(0).getKeyRequestType());
        assertEquals(java.util.Set
                .of(KeyAlgorithm.RSA, KeyAlgorithm.ECDSA, KeyAlgorithm.FALCON, KeyAlgorithm.MLDSA, KeyAlgorithm.SLHDSA,
                        KeyAlgorithm.MLKEM),
                importable.get(0).getAlgorithms());
    }

    /** The material states the algorithm and its parameter set, so an import asks only where to keep the key. */
    @Test
    void asksOnlyWhereToKeepAnImportedKey() {
        // given
        ImportKeyAttributesRequestV2Dto request = new ImportKeyAttributesRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-import-attrs")));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);

        // when
        List<BaseAttribute> attributes = controller.listImportKeyAttributes(request);

        // then
        assertEquals(List.of(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS),
                attributes.stream().map(BaseAttribute::getName).toList());
    }
}
