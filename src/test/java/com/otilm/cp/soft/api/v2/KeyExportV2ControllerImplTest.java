package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportableKeyTypeV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.cp.soft.exception.KeyMaterialMismatchException;
import com.otilm.cp.soft.exception.KeyNotExportableException;
import com.otilm.cp.soft.testsupport.KeyImportFixtures;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import com.otilm.cp.soft.util.ImportedKeyMaterial;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A key leaves a token as protected material under the passphrase the request carried, and only if it was allowed out
 * when it was made. What comes back has to be the key that went in, and has to open in whatever the platform hands it
 * to, so the round trip is what these check rather than the shape of the answer.
 */
@SpringBootTest
class KeyExportV2ControllerImplTest {

    private static final String PASSPHRASE = "a passphrase the caller chose";

    private KeyV2ControllerImpl controller;

    @Autowired
    void setController(KeyV2ControllerImpl controller) {
        this.controller = controller;
    }

    /** The key that comes out is the key that went in, and it opens under the passphrase that was asked for. */
    @Test
    void givesBackTheKeyThatWasImported() {
        // given
        ImportKeyRequestV2Dto imported = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-export-round"));
        imported.setExportable(true);
        KeyPairDataResponseV2Dto key = (KeyPairDataResponseV2Dto) controller.importKey(imported).getBody();
        assertNotNull(key);

        // when
        ExportKeyResponseV2Dto exported = controller.exportKey(request(imported, key, imported.getKeyReference()));

        // then
        ImportedKeyMaterial opened = ImportedKeyMaterial
                .open(exported.getMaterial().getEncryptedPrivateKeyInfo(), PASSPHRASE);
        assertEquals(KeyAlgorithm.RSA, opened.algorithm());

        ImportedKeyMaterial went = ImportedKeyMaterial
                .open(imported.getMaterial().getEncryptedPrivateKeyInfo(), KeyImportFixtures.PASSPHRASE);
        assertArrayEquals(went.keyPair().getPrivate().getEncoded(), opened.keyPair().getPrivate().getEncoded(),
                "the key that came out must be the key that went in");
    }

    /** The material has to open in external tools, so it sits in the profile the contract pins. */
    @Test
    void protectsWhatItGivesBackInTheProfileTheContractPins() {
        // given
        ImportKeyRequestV2Dto imported = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-export-profile"));
        imported.setExportable(true);
        KeyPairDataResponseV2Dto key = (KeyPairDataResponseV2Dto) controller.importKey(imported).getBody();
        assertNotNull(key);

        // when
        ExportKeyResponseV2Dto exported = controller.exportKey(request(imported, key, null));

        // then
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(exported.getMaterial().getEncryptedPrivateKeyInfo());
        assertTrue(material.isWithinMaximumLength());
        assertTrue(material.isCanonicalEnvelope());
        assertTrue(material.isPinnedProtectionScheme());
        assertTrue(material.isPinnedProtectionParameters());
        assertTrue(material.isWholeCipherBlocks());
    }

    /** A key pair is described by its public key, since a private-key descriptor says nothing that can be checked. */
    @Test
    void describesWhatItExportedByItsPublicKey() {
        // given
        ImportKeyRequestV2Dto imported = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-export-described"));
        imported.setExportable(true);
        KeyPairDataResponseV2Dto key = (KeyPairDataResponseV2Dto) controller.importKey(imported).getBody();
        assertNotNull(key);

        // when
        ExportKeyResponseV2Dto exported = controller.exportKey(request(imported, key, null));

        // then
        PublicKeyDataV2Dto described = (PublicKeyDataV2Dto) exported.getKeyData();
        assertArrayEquals(key.getPublicKeyData().getKeyData().getPublicKeySpki(), described.getPublicKeySpki(),
                "the platform compares this with the record it already holds");
    }

    /** The identity is echoed only when the request states one, so the platform can confirm what it received. */
    @Test
    void echoesTheIdentityOnlyWhenTheRequestStatesOne() {
        // given
        ImportKeyRequestV2Dto imported = KeyImportFixtures.rsaImport(TokenContextFixtures.uniqueName("v2-export-echo"));
        imported.setExportable(true);
        KeyPairDataResponseV2Dto key = (KeyPairDataResponseV2Dto) controller.importKey(imported).getBody();
        assertNotNull(key);

        // when
        // then
        assertEquals(imported.getKeyReference(),
                controller.exportKey(request(imported, key, imported.getKeyReference())).getKeyReference());
        assertNull(controller.exportKey(request(imported, key, null)).getKeyReference(),
                "a request carrying no identity must not be answered with one");
    }

    /** A request naming an identity the key does not carry is asking about another key. */
    @Test
    void refusesAnIdentityTheKeyDoesNotCarry() {
        // given
        ImportKeyRequestV2Dto imported = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-export-other-identity"));
        imported.setExportable(true);
        KeyPairDataResponseV2Dto key = (KeyPairDataResponseV2Dto) controller.importKey(imported).getBody();
        assertNotNull(key);

        ExportKeyRequestV2Dto asAnotherKey = request(imported, key, UUID.randomUUID().toString());

        // when
        // then
        assertThrows(KeyMaterialMismatchException.class, () -> controller.exportKey(asAnotherKey));
    }

    /**
     * A key generated without asking to be exportable stays in the token. The permission is set once when the key is
     * made and never raised, so nothing about the export request can grant it.
     */
    @Test
    void refusesAKeyThatWasNeverAllowedOut() {
        // given
        var creation = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-export-refused"), "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) controller.createKey(creation).getBody();
        assertNotNull(created);

        ExportKeyRequestV2Dto request = new ExportKeyRequestV2Dto();
        request.setTokenAttributes(creation.getTokenAttributes());
        request.setTokenProfileAttributes(List.of());
        request.setKeyMeta(created.getPrivateKeyData().getKeyMeta());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setExportKeyAttributes(List.of());
        request.setPassphrase(PASSPHRASE);

        // when
        // then
        assertThrows(KeyNotExportableException.class, () -> controller.exportKey(request));
    }

    @Test
    void letsOutEveryAlgorithmItCanTakeIn() {
        // given
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-export-types")));
        request.setTokenProfileAttributes(List.of());

        // when
        List<ExportableKeyTypeV2Dto> exportable = controller.listExportableKeyTypes(request);

        // then
        assertEquals(1, exportable.size());
        assertEquals(KeyRequestType.KEY_PAIR, exportable.get(0).getKeyRequestType());
        assertEquals(Set
                .of(KeyAlgorithm.RSA, KeyAlgorithm.ECDSA, KeyAlgorithm.FALCON, KeyAlgorithm.MLDSA, KeyAlgorithm.SLHDSA,
                        KeyAlgorithm.MLKEM),
                exportable.get(0).getAlgorithms());
    }

    /** The request already carries the key and the passphrase, and an attribute may carry neither. */
    @Test
    void asksForNothingToExportAKey() {
        // given
        ImportKeyRequestV2Dto imported = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-export-attrs"));
        imported.setExportable(true);
        KeyPairDataResponseV2Dto key = (KeyPairDataResponseV2Dto) controller.importKey(imported).getBody();
        assertNotNull(key);

        var scoped = new com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto();
        scoped.setTokenAttributes(imported.getTokenAttributes());
        scoped.setTokenProfileAttributes(List.of());
        scoped.setKeyMeta(key.getPrivateKeyData().getKeyMeta());

        // when
        // then
        assertTrue(controller.listExportKeyAttributes(scoped).isEmpty());
    }

    private static ExportKeyRequestV2Dto request(ImportKeyRequestV2Dto imported, KeyPairDataResponseV2Dto key,
            String reference) {
        ExportKeyRequestV2Dto request = new ExportKeyRequestV2Dto();
        request.setTokenAttributes(imported.getTokenAttributes());
        request.setTokenProfileAttributes(List.of());
        request.setKeyMeta(key.getPrivateKeyData().getKeyMeta());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setExportKeyAttributes(List.of());
        request.setKeyReference(reference);
        request.setPassphrase(PASSPHRASE);
        return request;
    }
}
