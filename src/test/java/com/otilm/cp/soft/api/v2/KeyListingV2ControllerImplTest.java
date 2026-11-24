package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import com.otilm.api.model.connector.cryptography.v2.key.KeyHandleV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyResolutionV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeysRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeysResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyEntryV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyPairV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ResolveKeysRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ResolveKeysResponseV2Dto;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.KeyTypeNotListableException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A listed pair carries the handle and descriptors its creation returned, so the platform onboards it like a key it
 * created.
 */
@SpringBootTest
class KeyListingV2ControllerImplTest {

    private KeyV2ControllerImpl controller;

    private KeyDataRepository keyDataRepository;

    @Autowired
    void setController(KeyV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @Test
    void listsEachPairWithTheHandleAndDescriptorsItsCreationReturned() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list");
        KeyPairDataResponseV2Dto created = create(KeyRequestFixtures.rsaKeyPair(token, "only"));

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 0, 10));

        // then
        assertEquals(1L, page.getTotalItems());
        ListedKeyEntryV2Dto entry = page.getItems().get(0);
        assertEquals(KeyEntryStatus.AVAILABLE, entry.getStatus());
        assertEquals("only", entry.getStorageName());
        ListedKeyPairV2Dto pair = (ListedKeyPairV2Dto) entry.getKey();
        assertEquals(created.getKeyPairMeta().toString(), pair.getKeyPairMeta().toString());
        assertSameDescriptors(created.getPrivateKeyData(), created.getPublicKeyData(), pair);
    }

    @Test
    void pagesThePairsInTheOrderOfTheirAliases() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-page");
        for (String alias : List.of("charlie", "alpha", "bravo")) {
            create(KeyRequestFixtures.rsaKeyPair(token, alias));
        }

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 1, 1));

        // then
        assertEquals(3L, page.getTotalItems());
        assertEquals(List.of("bravo"), page.getItems().stream().map(ListedKeyEntryV2Dto::getStorageName).toList());
    }

    /** Each half is a key of its own, so a pair can outlive its public half. */
    @Test
    void listsAPairWhosePublicHalfIsGoneWithoutPublicKeyData() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-lone");
        CreateKeyRequestV2Dto creation = KeyRequestFixtures
                .keyPair(token, "lone", List
                        .of(TokenContextFixtures
                                .string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, KeyAlgorithm.ECDSA.getCode()),
                                TokenContextFixtures
                                        .string(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE,
                                                EcdsaCurveName.secp256r1.name())));
        KeyPairDataResponseV2Dto created = create(creation);
        controller.destroyKey(destroyRequest(creation.getTokenAttributes(), created.getPublicKeyData().getKeyMeta()));

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 0, 10));

        // then
        ListedKeyEntryV2Dto entry = page.getItems().get(0);
        assertEquals(KeyEntryStatus.AVAILABLE, entry.getStatus());
        ListedKeyPairV2Dto pair = (ListedKeyPairV2Dto) entry.getKey();
        assertNull(pair.getPublicKeyData());
        assertEquals(created.getPrivateKeyData().getKeyMeta().toString(),
                pair.getPrivateKeyData().getKeyMeta().toString());
        assertArrayEquals(created.getPrivateKeyData().getKeyData().getAlgorithmIdentifier(),
                pair.getPrivateKeyData().getKeyData().getAlgorithmIdentifier());
    }

    /** A keystore reads an alias without regard to case. Two keys whose aliases differ only in case share one. */
    @Test
    void listsKeysSharingAnAliasAsUnaddressable() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-shared");
        KeyPairDataResponseV2Dto shared = create(KeyRequestFixtures.rsaKeyPair(token, "shared"));
        KeyPairDataResponseV2Dto other = create(KeyRequestFixtures.rsaKeyPair(token, "other"));
        rename(other, "SHARED");

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 0, 10));

        // then
        assertEquals(List.of(KeyEntryStatus.UNADDRESSABLE, KeyEntryStatus.UNADDRESSABLE),
                page.getItems().stream().map(ListedKeyEntryV2Dto::getStatus).toList());
        page.getItems().forEach(entry -> assertNotNull(entry.getDiagnostic()));
        page
                .getItems()
                .forEach(entry -> assertSamePrivateKeyDescriptor(shared.getPrivateKeyData().getKeyData(),
                        (PrivateKeyDataV2Dto) entry.getKeyData()));
    }

    /** The keystore folds only ASCII letters, so aliases that differ in any other case address a key each. */
    @Test
    void listsKeysWhoseAliasesDifferOnlyInNonAsciiCaseAsAvailable() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-non-ascii");
        rename(create(KeyRequestFixtures.rsaKeyPair(token, "upper")), "\u00c9quipe");
        rename(create(KeyRequestFixtures.rsaKeyPair(token, "lower")), "\u00e9quipe");

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 0, 10));

        // then
        assertEquals(List.of(KeyEntryStatus.AVAILABLE, KeyEntryStatus.AVAILABLE),
                page.getItems().stream().map(ListedKeyEntryV2Dto::getStatus).toList());
        for (ListedKeyEntryV2Dto listed : page.getItems()) {
            KeyResolutionV2Dto resolved = controller
                    .resolveKeys(resolveRequest(token, new KeyHandleV2Dto("0", listed.getKey().handle())))
                    .getResults()
                    .get(0);
            assertEquals(listed.getStorageName(), resolved.getStorageName());
        }
    }

    /** V1 creates post-quantum keys in parameter sets no platform signature algorithm names. */
    @Test
    void listsAKeyNoPlatformSignatureAlgorithmNamesAsUnsupported() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-unsupported");
        KeyPairDataResponseV2Dto created = create(KeyRequestFixtures.mldsaKeyPair(token, "prehashed"));
        KeyData privateKey = half(created, KeyType.PRIVATE_KEY);
        HashMap<String, String> parameters = new HashMap<>(((CustomKeyValue) privateKey.getValue()).getValues());
        parameters.put("prehash", "true");
        CustomKeyValue prehashed = new CustomKeyValue();
        prehashed.setValues(parameters);
        privateKey.setValue(prehashed);
        keyDataRepository.saveAndFlush(privateKey);

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 0, 10));

        // then
        ListedKeyEntryV2Dto entry = page.getItems().get(0);
        assertEquals(KeyEntryStatus.UNSUPPORTED_TYPE, entry.getStatus());
        assertNotNull(entry.getDiagnostic());
        assertNull(entry.getKey());
        assertSamePrivateKeyDescriptor(created.getPrivateKeyData().getKeyData(),
                (PrivateKeyDataV2Dto) entry.getKeyData());
    }

    /** A row whose parameters cannot be read blocks only its own entry. */
    @Test
    void listsAKeyWhoseParametersCannotBeReadAsUnreadable() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-unreadable-params");
        KeyPairDataResponseV2Dto created = create(KeyRequestFixtures.mldsaKeyPair(token, "broken"));
        create(KeyRequestFixtures.rsaKeyPair(token, "intact"));
        KeyData privateKey = half(created, KeyType.PRIVATE_KEY);
        HashMap<String, String> parameters = new HashMap<>(((CustomKeyValue) privateKey.getValue()).getValues());
        parameters.remove("prehash");
        CustomKeyValue withoutPrehash = new CustomKeyValue();
        withoutPrehash.setValues(parameters);
        privateKey.setValue(withoutPrehash);
        keyDataRepository.saveAndFlush(privateKey);

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 0, 10));

        // then
        assertEquals(List.of(KeyEntryStatus.UNREADABLE, KeyEntryStatus.AVAILABLE),
                page.getItems().stream().map(ListedKeyEntryV2Dto::getStatus).toList());
        ListedKeyEntryV2Dto entry = page.getItems().get(0);
        assertNotNull(entry.getDiagnostic());
        assertSamePrivateKeyDescriptor(created.getPrivateKeyData().getKeyData(),
                (PrivateKeyDataV2Dto) entry.getKeyData());
    }

    @Test
    void listsAPairWhosePublicKeyCannotBeReadAsUnreadable() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-unreadable");
        KeyPairDataResponseV2Dto created = create(KeyRequestFixtures.rsaKeyPair(token, "garbled"));
        KeyData publicKey = half(created, KeyType.PUBLIC_KEY);
        publicKey.setValue(new SpkiKeyValue("AAAA"));
        keyDataRepository.saveAndFlush(publicKey);

        // when
        ListKeysResponseV2Dto page = controller.listKeys(listRequest(token, 0, 10));

        // then
        ListedKeyEntryV2Dto entry = page.getItems().get(0);
        assertEquals(KeyEntryStatus.UNREADABLE, entry.getStatus());
        assertEquals("garbled", entry.getStorageName());
        assertNotNull(entry.getDiagnostic());
        PrivateKeyDataV2Dto keyData = (PrivateKeyDataV2Dto) entry.getKeyData();
        assertEquals(KeyAlgorithm.RSA, keyData.getAlgorithm());
        assertNull(keyData.getAlgorithmIdentifier());
    }

    @Test
    void resolvesAListedHandleToTheEntryTheListingReturned() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-resolve");
        create(KeyRequestFixtures.rsaKeyPair(token, "resolved"));
        ListedKeyEntryV2Dto listed = controller.listKeys(listRequest(token, 0, 10)).getItems().get(0);

        // when
        ResolveKeysResponseV2Dto resolved = controller
                .resolveKeys(resolveRequest(token, new KeyHandleV2Dto("0", listed.getKey().handle())));

        // then
        KeyResolutionV2Dto result = resolved.getResults().get(0);
        assertEquals("0", result.getIdentifier());
        assertEquals(KeyEntryStatus.AVAILABLE, result.getStatus());
        assertEquals(listed.getKey().toString(), result.getKey().toString());
        ListedKeyPairV2Dto listedPair = (ListedKeyPairV2Dto) listed.getKey();
        assertSameDescriptors(listedPair.getPrivateKeyData(), listedPair.getPublicKeyData(),
                (ListedKeyPairV2Dto) result.getKey());
    }

    /** Each handle is answered on its own, so a handle this connector did not issue fails only its own result. */
    @Test
    void resolvesEveryHandleOfABatchUnderItsIdentifier() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-resolve-batch");
        create(KeyRequestFixtures.rsaKeyPair(token, "kept"));
        ListedKeyEntryV2Dto listed = controller.listKeys(listRequest(token, 0, 10)).getItems().get(0);
        MetadataAttribute objectValued = KeyAttributes.buildAliasMetadata("kept");
        objectValued.setContent(List.of(new BaseAttributeContentV2<>("alias", new HashMap<>(Map.of("alias", "kept")))));
        MetadataAttribute twoValues = KeyAttributes.buildAliasMetadata("kept");
        twoValues.setContent(List.of(new StringAttributeContentV2("kept"), new StringAttributeContentV2("absent")));

        // when
        ResolveKeysResponseV2Dto resolved = controller
                .resolveKeys(resolveRequest(token, new KeyHandleV2Dto("available", listed.getKey().handle()),
                        new KeyHandleV2Dto("missing", List.of(KeyAttributes.buildAliasMetadata("absent"))),
                        new KeyHandleV2Dto("objectValued", List.of(objectValued)),
                        new KeyHandleV2Dto("repeated",
                                List
                                        .of(KeyAttributes.buildAliasMetadata("kept"),
                                                KeyAttributes.buildAliasMetadata("absent"))),
                        new KeyHandleV2Dto("twoValues", List.of(twoValues))));

        // then
        assertEquals(
                Map
                        .of("available", KeyEntryStatus.AVAILABLE, "missing", KeyEntryStatus.NOT_FOUND, "objectValued",
                                KeyEntryStatus.INVALID_HANDLE, "repeated", KeyEntryStatus.INVALID_HANDLE, "twoValues",
                                KeyEntryStatus.INVALID_HANDLE),
                resolved
                        .getResults()
                        .stream()
                        .collect(Collectors.toMap(KeyResolutionV2Dto::getIdentifier, KeyResolutionV2Dto::getStatus)));
    }

    @Test
    void resolvesAnAliasTheTokenDoesNotHoldAsNotFound() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-resolve-missing");
        create(KeyRequestFixtures.rsaKeyPair(token, "present"));

        // when
        ResolveKeysResponseV2Dto resolved = controller
                .resolveKeys(resolveRequest(token,
                        new KeyHandleV2Dto("0", List.of(KeyAttributes.buildAliasMetadata("absent")))));

        // then
        assertEquals(KeyEntryStatus.NOT_FOUND, resolved.getResults().get(0).getStatus());
    }

    @Test
    void resolvesAHandleNamingNoAliasAsInvalid() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-resolve-invalid");
        KeyPairDataResponseV2Dto created = create(KeyRequestFixtures.rsaKeyPair(token, "keyed"));
        List<MetadataAttribute> withoutAlias = created
                .getPrivateKeyData()
                .getKeyMeta()
                .stream()
                .filter(item -> !KeyAttributes.ATTRIBUTE_META_KEY_ALIAS.equals(item.getName()))
                .toList();

        // when
        ResolveKeysResponseV2Dto resolved = controller
                .resolveKeys(resolveRequest(token, new KeyHandleV2Dto("0", withoutAlias)));

        // then
        assertEquals(KeyEntryStatus.INVALID_HANDLE, resolved.getResults().get(0).getStatus());
    }

    @Test
    void refusesToListOrResolveSecretKeys() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-list-secret");
        ListKeysRequestV2Dto listRequest = listRequest(token, 0, 10);
        listRequest.setKeyRequestType(KeyRequestType.SECRET);
        ResolveKeysRequestV2Dto resolveRequest = resolveRequest(token,
                new KeyHandleV2Dto("0", List.of(KeyAttributes.buildAliasMetadata("any"))));
        resolveRequest.setKeyRequestType(KeyRequestType.SECRET);

        // when
        // then
        assertThrows(KeyTypeNotListableException.class, () -> controller.listKeys(listRequest));
        assertThrows(KeyTypeNotListableException.class, () -> controller.resolveKeys(resolveRequest));
    }

    private static void assertSameDescriptors(PrivateKeyDataResponseV2Dto expectedPrivate,
            PublicKeyDataResponseV2Dto expectedPublic, ListedKeyPairV2Dto actual) {
        assertEquals(expectedPrivate.getKeyMeta().toString(), actual.getPrivateKeyData().getKeyMeta().toString());
        assertSamePrivateKeyDescriptor(expectedPrivate.getKeyData(), actual.getPrivateKeyData().getKeyData());
        assertEquals(expectedPublic.getKeyMeta().toString(), actual.getPublicKeyData().getKeyMeta().toString());
        assertEquals(expectedPublic.getKeyData().getAlgorithm(), actual.getPublicKeyData().getKeyData().getAlgorithm());
        assertArrayEquals(expectedPublic.getKeyData().getPublicKeySpki(),
                actual.getPublicKeyData().getKeyData().getPublicKeySpki());
    }

    private static void assertSamePrivateKeyDescriptor(PrivateKeyDataV2Dto expected, PrivateKeyDataV2Dto actual) {
        assertEquals(expected.getAlgorithm(), actual.getAlgorithm());
        assertEquals(expected.getLength(), actual.getLength());
        assertArrayEquals(expected.getAlgorithmIdentifier(), actual.getAlgorithmIdentifier());
    }

    private KeyPairDataResponseV2Dto create(CreateKeyRequestV2Dto request) {
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) controller.createKey(request).getBody();
        assertNotNull(created);
        return created;
    }

    private KeyData half(KeyPairDataResponseV2Dto created, KeyType type) {
        List<MetadataAttribute> keyMeta = type == KeyType.PRIVATE_KEY
                ? created.getPrivateKeyData().getKeyMeta()
                : created.getPublicKeyData().getKeyMeta();
        String reference = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(KeyAttributes.ATTRIBUTE_META_KEY_REFERENCE, keyMeta,
                        StringAttributeContentV2.class)
                .getData();
        return keyDataRepository.findByUuid(UUID.fromString(reference)).orElseThrow();
    }

    private void rename(KeyPairDataResponseV2Dto created, String alias) {
        for (KeyType type : List.of(KeyType.PRIVATE_KEY, KeyType.PUBLIC_KEY)) {
            KeyData key = half(created, type);
            key.setName(alias);
            keyDataRepository.saveAndFlush(key);
        }
    }

    private static ListKeysRequestV2Dto listRequest(String token, int offset, int limit) {
        ListKeysRequestV2Dto request = new ListKeysRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(token));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setOffset(offset);
        request.setLimit(limit);
        return request;
    }

    private static ResolveKeysRequestV2Dto resolveRequest(String token, KeyHandleV2Dto... handles) {
        ResolveKeysRequestV2Dto request = new ResolveKeysRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(token));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setKeys(List.of(handles));
        return request;
    }

    private static DestroyKeyRequestV2Dto destroyRequest(List<RequestAttribute> tokenAttributes,
            List<MetadataAttribute> keyMeta) {
        DestroyKeyRequestV2Dto request = new DestroyKeyRequestV2Dto();
        request.setTokenAttributes(tokenAttributes);
        request.setTokenProfileAttributes(List.of());
        request.setKeyMeta(keyMeta);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        return request;
    }
}
