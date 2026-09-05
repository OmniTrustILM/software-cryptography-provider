package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.MLKEMAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import jakarta.transaction.Transactional;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Transactional
class KeyManagementServiceImplTest {

    public static final String PASSWORD = "123";

    @Autowired
    KeyManagementService keyManagementService;

    @Autowired
    TokenInstanceRepository tokenInstanceRepository;
    @Autowired
    KeyDataRepository keyDataRepository;

    TokenInstance tokenInstance;

    @BeforeEach
    void setUp() {
        tokenInstance = new TokenInstance();
        tokenInstance.setCode(PASSWORD);
        tokenInstance.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        tokenInstanceRepository.save(tokenInstance);
    }

    @Test
    void testMLDSAKey()
            throws NotFoundException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        String alias = "alias";
        List<RequestAttribute> createKeyAttributes = new ArrayList<>(
                getCreateKeyCommonAttributes(alias, KeyAlgorithm.MLDSA.getCode()));

        RequestAttributeV2 mldsaLevel = new RequestAttributeV2();
        mldsaLevel.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL);
        mldsaLevel.setContentType(AttributeContentType.INTEGER);

        IntegerAttributeContentV2 mldsaLevelContent = new IntegerAttributeContentV2();
        mldsaLevelContent.setReference(MLDSASecurityCategory.MLDSA_44.name());
        mldsaLevelContent.setData(MLDSASecurityCategory.MLDSA_44.getNistSecurityCategory());
        mldsaLevel.setContent(List.of(mldsaLevelContent));
        createKeyAttributes.add(mldsaLevel);

        RequestAttributeV2 mldsaUsePrehash = new RequestAttributeV2();
        mldsaUsePrehash.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH);
        mldsaUsePrehash.setContentType(AttributeContentType.BOOLEAN);

        BooleanAttributeContentV2 mldsaUsePrehashContent = new BooleanAttributeContentV2();
        mldsaUsePrehashContent.setData(false);
        mldsaUsePrehash.setContent(List.of(mldsaUsePrehashContent));
        createKeyAttributes.add(mldsaUsePrehash);

        createKeyRequestDto.setCreateKeyAttributes(createKeyAttributes);

        KeyPairDataResponseDto response = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.MLDSA, response.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.MLDSA, response.getPublicKeyData().getKeyData().getAlgorithm());

        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), PASSWORD);
        Key privateKey;
        Assertions.assertNotNull(privateKey = keyStore.getKey(alias, PASSWORD.toCharArray()));
        Assertions.assertEquals("ML-DSA-44", privateKey.getAlgorithm());
    }

    @Test
    void testSLHDSAKey()
            throws NotFoundException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        String alias = "alias";
        List<RequestAttribute> createKeyAttributes = new ArrayList<>(
                getCreateKeyCommonAttributes(alias, KeyAlgorithm.SLHDSA.getCode()));

        RequestAttributeV2 slhdsaSecurityCategory = new RequestAttributeV2();
        slhdsaSecurityCategory.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY);
        slhdsaSecurityCategory.setContentType(AttributeContentType.STRING);

        StringAttributeContentV2 slhdsaLevelContent = new StringAttributeContentV2();
        slhdsaLevelContent.setReference(SLHDSASecurityCategory.CATEGORY_1.name());
        slhdsaLevelContent.setData(SLHDSASecurityCategory.CATEGORY_1.getNistSecurityCategory());
        slhdsaSecurityCategory.setContent(List.of(slhdsaLevelContent));
        createKeyAttributes.add(slhdsaSecurityCategory);

        RequestAttributeV2 slhdsaUsePrehash = new RequestAttributeV2();
        slhdsaUsePrehash.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH);
        slhdsaUsePrehash.setContentType(AttributeContentType.BOOLEAN);

        BooleanAttributeContentV2 slhdsaUsePrehashContent = new BooleanAttributeContentV2();
        slhdsaUsePrehashContent.setData(true);
        slhdsaUsePrehash.setContent(List.of(slhdsaUsePrehashContent));
        createKeyAttributes.add(slhdsaUsePrehash);

        RequestAttributeV2 slhdsaHash = new RequestAttributeV2();
        slhdsaHash.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH);
        slhdsaHash.setContentType(AttributeContentType.STRING);
        slhdsaHash.setContent(List.of(new StringAttributeContentV2(SLHDSAHash.SHAKE256.name())));
        createKeyAttributes.add(slhdsaHash);

        RequestAttributeV2 slhdsaSignatureMode = new RequestAttributeV2();
        slhdsaSignatureMode.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE);
        slhdsaSignatureMode.setContentType(AttributeContentType.STRING);
        slhdsaSignatureMode.setContent(List.of(new StringAttributeContentV2(SLHDSASignatureMode.FAST.name())));
        createKeyAttributes.add(slhdsaSignatureMode);

        createKeyRequestDto.setCreateKeyAttributes(createKeyAttributes);

        KeyPairDataResponseDto response = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.SLHDSA, response.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.SLHDSA, response.getPublicKeyData().getKeyData().getAlgorithm());

        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), PASSWORD);
        Key privateKey;
        Assertions.assertNotNull(privateKey = keyStore.getKey(alias, PASSWORD.toCharArray()));
        Assertions.assertEquals("SLH-DSA-SHAKE-128F-WITH-SHAKE128", privateKey.getAlgorithm());
    }

    @Test
    void testGeneratingAndStoringMLKEMKeyPair()
            throws NotFoundException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        String alias = "alias";
        List<RequestAttribute> createKeyAttributes = new ArrayList<>(
                getCreateKeyCommonAttributes(alias, KeyAlgorithm.MLKEM.getCode()));

        RequestAttributeV2 mlkemLevel = new RequestAttributeV2();
        mlkemLevel.setName(MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL);
        mlkemLevel.setContentType(AttributeContentType.INTEGER);

        IntegerAttributeContentV2 mlkemLevelContent = new IntegerAttributeContentV2();
        mlkemLevelContent.setReference(MLKEMSecurityCategory.CATEGORY_3.name());
        mlkemLevelContent.setData(MLKEMSecurityCategory.CATEGORY_3.getNistSecurityCategory());
        mlkemLevel.setContent(List.of(mlkemLevelContent));
        createKeyAttributes.add(mlkemLevel);

        createKeyRequestDto.setCreateKeyAttributes(createKeyAttributes);

        KeyPairDataResponseDto keyPairDataResponseDto = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);
        Assertions
                .assertEquals(KeyAlgorithm.MLKEM,
                        keyPairDataResponseDto.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions
                .assertEquals(KeyAlgorithm.MLKEM,
                        keyPairDataResponseDto.getPublicKeyData().getKeyData().getAlgorithm());

        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), PASSWORD);
        Key privateKey;
        Assertions.assertNotNull(privateKey = keyStore.getKey(alias, PASSWORD.toCharArray()));
        Assertions.assertEquals("ML-KEM-768", privateKey.getAlgorithm());
    }

    List<RequestAttribute> getCreateKeyCommonAttributes(String alias, String algorithm) {
        List<RequestAttribute> attributes = new ArrayList<>();
        RequestAttributeV2 keyAlias = new RequestAttributeV2();
        keyAlias.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS);
        keyAlias.setContentType(AttributeContentType.STRING);
        keyAlias.setContent(List.of(new StringAttributeContentV2(alias)));
        attributes.add(keyAlias);

        RequestAttributeV2 keyAlgorithm = new RequestAttributeV2();
        keyAlgorithm.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM);
        keyAlgorithm.setContentType(AttributeContentType.STRING);

        BaseAttributeContentV2<String> algorithmContent = new StringAttributeContentV2();
        algorithmContent.setReference(algorithm);
        algorithmContent.setData(algorithm);
        keyAlgorithm.setContent(List.of(algorithmContent));
        attributes.add(keyAlgorithm);

        return attributes;
    }

    /**
     * Every other algorithm names its parameter set through an enumeration and so refuses one this connector does not
     * hold. An RSA size is a plain number, and a request for a key of a size no attribute offers reached the generator.
     */
    @Test
    void refusesAnRsaKeyOfASizeItDoesNotOffer() {
        CreateKeyRequestDto request = new CreateKeyRequestDto();
        List<RequestAttribute> attributes = new ArrayList<>(
                getCreateKeyCommonAttributes("alias", KeyAlgorithm.RSA.getCode()));

        RequestAttributeV2 keySize = new RequestAttributeV2();
        keySize.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        keySize.setContentType(AttributeContentType.INTEGER);
        keySize.setContent(List.of(new IntegerAttributeContentV2("1536", 1536)));
        attributes.add(keySize);
        request.setCreateKeyAttributes(attributes);

        UUID token = tokenInstance.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> keyManagementService.createKeyPair(token, request));
    }

    /** Both generations serve the same keys, so a key created through either has to be nameable through the other. */
    @Test
    void namesEveryKeyItCreatesByTheReferenceTheV2InterfacesAddressItBy() throws NotFoundException {
        CreateKeyRequestDto request = new CreateKeyRequestDto();
        List<RequestAttribute> attributes = new ArrayList<>(
                getCreateKeyCommonAttributes("v1-reachable", KeyAlgorithm.RSA.getCode()));

        RequestAttributeV2 keySize = new RequestAttributeV2();
        keySize.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        keySize.setContentType(AttributeContentType.INTEGER);
        keySize.setContent(List.of(new IntegerAttributeContentV2("2048", 2048)));
        attributes.add(keySize);
        request.setCreateKeyAttributes(attributes);

        KeyPairDataResponseDto created = keyManagementService.createKeyPair(tokenInstance.getUuid(), request);

        for (var half : List.of(created.getPublicKeyData(), created.getPrivateKeyData())) {
            String named = AttributeDefinitionUtils
                    .getSingleItemAttributeContentValue(KeyAttributes.ATTRIBUTE_META_KEY_REFERENCE,
                            half.getKeyData().getMetadata(), StringAttributeContentV2.class)
                    .getData();
            Assertions.assertEquals(half.getUuid(), named, "the reference has to name the key it was published on");
        }
    }

    @Test
    void testNotActivatedToken() {
        tokenInstance.setCode(null);
        KeyData keyData = new KeyData();
        keyData.setTokenInstance(tokenInstance);
        keyData.setType(KeyType.PRIVATE_KEY);
        keyDataRepository.save(keyData);
        UUID keyUuid = keyData.getUuid();

        UUID tokenInstanceUuid = tokenInstance.getUuid();
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        Assertions
                .assertThrows(TokenInstanceException.class,
                        () -> keyManagementService.createKeyPair(tokenInstanceUuid, createKeyRequestDto));
        Assertions
                .assertThrows(TokenInstanceException.class,
                        () -> keyManagementService.destroyKey(tokenInstanceUuid, keyUuid));
    }

}
