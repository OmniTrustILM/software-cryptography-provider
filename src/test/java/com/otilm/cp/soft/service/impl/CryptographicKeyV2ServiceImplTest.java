package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.service.CryptographicKeyV2Service;
import com.otilm.cp.soft.testsupport.KeyImportFixtures;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A v2 creation or import names its key itself when the request leaves the alias out, so one set of creation attributes
 * can be used for any number of keys on a token.
 */
@SpringBootTest
class CryptographicKeyV2ServiceImplTest {

    private CryptographicKeyV2Service service;

    private KeyDataRepository keyDataRepository;

    private AttributeServiceImpl attributeService;

    @Autowired
    void setService(CryptographicKeyV2Service service) {
        this.service = service;
    }

    @Autowired
    void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @Autowired
    void setAttributeService(AttributeServiceImpl attributeService) {
        this.attributeService = attributeService;
    }

    @Test
    void v2SchemaOffersTheAliasAsOptional() {
        // given
        BaseAttribute alias = KeyAttributes.buildOptionalDataKeyAlias();

        // when
        // then
        assertEquals(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_UUID, alias.getUuid());
        assertEquals(false, properties(alias).isRequired());
    }

    @Test
    void v1SchemaStillRequiresTheAlias() {
        // given
        // when
        BaseAttribute alias = attributeService
                .getCreateKeyAttributes()
                .stream()
                .filter(attribute -> KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS.equals(attribute.getName()))
                .findFirst()
                .orElseThrow();

        // then
        assertTrue(properties(alias).isRequired());
    }

    @Test
    void creationsWithoutAnAliasEachGetOneDerivedFromTheirCreationId() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-derived-alias");
        CreateKeyRequestV2Dto first = withoutAlias(KeyRequestFixtures.rsaKeyPair(token, "unused"));
        // A form whose optional alias was left empty sends it blank, which names no key either.
        CreateKeyRequestV2Dto second = KeyRequestFixtures.rsaKeyPair(token, " ");

        // when
        service.createKey(first);
        service.createKey(second);

        // then
        String firstAlias = aliasOf(first.getKeyCreationId());
        String secondAlias = aliasOf(second.getKeyCreationId());
        assertEquals(derived(first.getKeyCreationId()), firstAlias);
        assertEquals(derived(second.getKeyCreationId()), secondAlias);
        assertNotEquals(firstAlias, secondAlias);
    }

    @Test
    void repeatingACreationWithoutAnAliasAnswersWithTheFirstKey() {
        // given
        CreateKeyRequestV2Dto request = withoutAlias(
                KeyRequestFixtures.rsaKeyPair(TokenContextFixtures.uniqueName("v2-derived-replay"), "unused"));
        KeyPairDataResponseV2Dto original = service.createKey(request);

        // when
        KeyPairDataResponseV2Dto repeated = service.createKey(request);

        // then
        assertEquals(original.getPrivateKeyData().getKeyMeta().toString(),
                repeated.getPrivateKeyData().getKeyMeta().toString());
        assertEquals(2, keyDataRepository.findByKeyCreationId(request.getKeyCreationId()).size());
    }

    @Test
    void repeatingACreationWithItsDerivedAliasStatedIsADifferentRequest() {
        // given
        CreateKeyRequestV2Dto request = withoutAlias(
                KeyRequestFixtures.rsaKeyPair(TokenContextFixtures.uniqueName("v2-derived-stated"), "unused"));
        service.createKey(request);
        CreateKeyRequestV2Dto stated = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("unused"), derived(request.getKeyCreationId()));
        stated.setTokenAttributes(request.getTokenAttributes());
        stated.setKeyCreationId(request.getKeyCreationId());

        // when
        // then
        assertThrows(OperationConflictException.class, () -> service.createKey(stated));
    }

    @Test
    void anImportWithoutAnAliasGetsOneDerivedFromItsImportId() {
        // given
        ImportKeyRequestV2Dto request = KeyImportFixtures
                .rsaImport(TokenContextFixtures.uniqueName("v2-import-no-alias"));
        request.setImportKeyAttributes(List.of());

        // when
        service.importKey(request);

        // then
        List<String> aliases = keyDataRepository
                .findByKeyImportId(request.getKeyImportId())
                .stream()
                .map(KeyData::getName)
                .distinct()
                .toList();
        assertEquals(List.of(derived(request.getKeyImportId())), aliases);
    }

    @Test
    void anExplicitAliasIsUsedAsGivenAndADuplicateIsStillRefused() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-explicit-alias");
        String alias = "explicit-" + System.nanoTime();
        CreateKeyRequestV2Dto first = KeyRequestFixtures.rsaKeyPair(token, alias);
        CreateKeyRequestV2Dto duplicate = KeyRequestFixtures.rsaKeyPair(token, alias);

        // when
        service.createKey(first);

        // then
        assertEquals(alias, aliasOf(first.getKeyCreationId()));
        assertThrows(KeyManagementException.class, () -> service.createKey(duplicate));
    }

    private static CreateKeyRequestV2Dto withoutAlias(CreateKeyRequestV2Dto request) {
        request
                .getCreateKeyAttributes()
                .removeIf(attribute -> KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS.equals(attribute.getName()));
        return request;
    }

    private String aliasOf(String keyCreationId) {
        List<String> aliases = keyDataRepository
                .findByKeyCreationId(keyCreationId)
                .stream()
                .map(KeyData::getName)
                .distinct()
                .toList();
        assertEquals(1, aliases.size(), "both halves of the pair carry one alias");
        return aliases.getFirst();
    }

    private static String derived(String keyCreationId) {
        return UUID.nameUUIDFromBytes(keyCreationId.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private static DataAttributeProperties properties(BaseAttribute attribute) {
        return ((DataAttributeV2) attribute).getProperties();
    }
}
