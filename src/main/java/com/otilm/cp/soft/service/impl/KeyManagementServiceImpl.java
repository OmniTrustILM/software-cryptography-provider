package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.KeyValue;
import com.otilm.api.model.connector.cryptography.key.value.RawKeyValue;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.*;
import com.otilm.cp.soft.collection.*;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.service.KeyDataCacheService;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.service.TokenInstanceService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.util.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class KeyManagementServiceImpl implements KeyManagementService {

    private TokenInstanceService tokenInstanceService;
    private KeyDataRepository keyDataRepository;
    private KeyDataCacheService keyDataCacheService;

    @Override
    public KeyPairDataResponseDto createKeyPair(UUID uuid, CreateKeyRequestDto request) throws NotFoundException {
        // check if the token instance exists
        TokenInstance tokenInstance = tokenInstanceService.getTokenInstanceEntity(uuid);

        if (tokenInstance.getCode() == null) throw new TokenInstanceException("Token is not activated.");

        // load the keystore
        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), tokenInstance.getCode());

        // generate key inside the keystore
        final String algorithm = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, request.getCreateKeyAttributes(), StringAttributeContentV2.class).getData();

        KeyAlgorithm cryptographicAlgorithm = KeyAlgorithm.findByCode(algorithm);

        // alias should be always present for every key
        final String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, request.getCreateKeyAttributes(), StringAttributeContentV2.class).getData();

        // check if the alias is already used in the keystore
        if (!keyDataRepository.findByNameAndTokenInstanceUuid(alias, uuid).isEmpty()) {
            throw new KeyManagementException("Key with alias '" + alias + "' already exists.");
        }

        KeyPairDataResponseDto response = new KeyPairDataResponseDto();
        KeyData publicKey;
        KeyData privateKey;

        List<MetadataAttribute> metadata = new ArrayList<>();
        metadata.add(KeyAttributes.buildAliasMetadata(alias));

        String association = RandomStringUtils.secure().nextAlphanumeric(16);

        switch (cryptographicAlgorithm) {
            case RSA -> {
                final int keySize = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE, request.getCreateKeyAttributes(), IntegerAttributeContentV2.class).getData();
                KeyStoreUtil.generateRsaKey(keyStore, alias, keySize, tokenInstance.getCode());

                // create public key
                publicKey = createAndSaveKeyData(
                        alias, association, KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, KeyFormat.SPKI,
                        KeyStoreUtil.spkiKeyValueFromKeyStore(keyStore, alias),
                        keySize, metadata, tokenInstance);

                // create private key
                CustomKeyValue customKeyValue = new CustomKeyValue();
                HashMap<String, String> customKeyValues = new HashMap<>();
                customKeyValues.put("location", "managed by external token");
                customKeyValue.setValues(customKeyValues);

                privateKey = createAndSaveKeyData(alias, association, KeyType.PRIVATE_KEY, KeyAlgorithm.RSA,
                        KeyFormat.CUSTOM, customKeyValue, keySize, metadata, tokenInstance);
            }
            case ECDSA -> {
                final EcdsaCurveName curveName = EcdsaCurveName.valueOf(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE, request.getCreateKeyAttributes(), StringAttributeContentV2.class)
                                .getReference()
                );

                KeyStoreUtil.generateEcdsaKey(keyStore, alias, curveName, tokenInstance.getCode());

                // create public key
                publicKey = createAndSaveKeyData(
                        alias, association, KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, KeyFormat.SPKI,
                        KeyStoreUtil.spkiKeyValueFromKeyStore(keyStore, alias),
                        curveName.getSize()*2, metadata, tokenInstance);

                // create private key
                CustomKeyValue customKeyValue = new CustomKeyValue();
                HashMap<String, String> customKeyValues = new HashMap<>();
                customKeyValues.put("curve.name", curveName.name());
                customKeyValues.put("curve.description", curveName.getDescription());
                customKeyValue.setValues(customKeyValues);

                privateKey = createAndSaveKeyData(alias, association, KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA,
                        KeyFormat.CUSTOM, customKeyValue, curveName.getSize(), metadata, tokenInstance);

            }
            case FALCON -> {
                final int degree = AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE, request.getCreateKeyAttributes(), IntegerAttributeContentV2.class).getData();
                FalconDegree falconDegree = FalconDegree.resolve(degree);

                KeyStoreUtil.generateFalconKey(keyStore, alias, falconDegree, tokenInstance.getCode());

                // add metadata
                metadata.add(FalconKeyAttributes.buildFalconDegreeMetadata(degree));

                // prepare public key
                assert falconDegree != null;
                publicKey = createAndSaveKeyData(
                        alias, association, KeyType.PUBLIC_KEY, KeyAlgorithm.FALCON, KeyFormat.SPKI,
                        KeyStoreUtil.spkiKeyValueFromKeyStore(keyStore, alias),
                        falconDegree.getPublicKeySize(), metadata, tokenInstance);

                CustomKeyValue customKeyValue = new CustomKeyValue();
                HashMap<String, String> customKeyValues = new HashMap<>();
                customKeyValues.put("degree", Integer.toString(degree));
                customKeyValue.setValues(customKeyValues);

                // prepare private key
                privateKey = createAndSaveKeyData(alias, association, KeyType.PRIVATE_KEY, KeyAlgorithm.FALCON,
                        KeyFormat.CUSTOM, customKeyValue, falconDegree.getPrivateKeySize(), metadata, tokenInstance);
            }
            case MLDSA -> {
                final MLDSASecurityCategory level = MLDSASecurityCategory.valueOf(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL, request.getCreateKeyAttributes(), IntegerAttributeContentV2.class)
                                .getData()
                );

                final boolean forPreHash =
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH, request.getCreateKeyAttributes(), BooleanAttributeContentV2.class).getData();

                KeyStoreUtil.generateMLDSAKey(keyStore, alias, level, forPreHash, tokenInstance.getCode());

                // add metadata

                // prepare public key
                publicKey = createAndSaveKeyData(
                        alias, association, KeyType.PUBLIC_KEY, KeyAlgorithm.MLDSA, KeyFormat.SPKI,
                        KeyStoreUtil.spkiKeyValueFromPrivateKey(keyStore, alias, tokenInstance.getCode()),
                        level.getPublicKeySize(), metadata, tokenInstance);

                CustomKeyValue customKeyValue = new CustomKeyValue();
                HashMap<String, String> customKeyValues = new HashMap<>();
                customKeyValues.put("level", Integer.toString(level.getNistSecurityCategory()));
                customKeyValues.put("prehash", String.valueOf(forPreHash));
                customKeyValue.setValues(customKeyValues);

                // prepare private key
                privateKey = createAndSaveKeyData(alias, association, KeyType.PRIVATE_KEY, KeyAlgorithm.MLDSA,
                        KeyFormat.CUSTOM, customKeyValue, level.getPrivateKeySize(), metadata, tokenInstance);
            }
            case SLHDSA -> {
                final SLHDSAHash hash = SLHDSAHash.valueOf(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH, request.getCreateKeyAttributes(), StringAttributeContentV2.class)
                                .getReference()
                );

                final SLHDSASecurityCategory slhDsaSecurityCategory = SLHDSASecurityCategory.valueOf(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY, request.getCreateKeyAttributes(), StringAttributeContentV2.class)
                                .getReference()
                );

                final SLHDSASignatureMode tradeoff = SLHDSASignatureMode.valueOf(AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE, request.getCreateKeyAttributes(), StringAttributeContentV2.class)
                        .getReference()
                );

                final boolean preHashKey =
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH, request.getCreateKeyAttributes(), BooleanAttributeContentV2.class).getData();


                KeyStoreUtil.generateSlhDsaKey(keyStore, alias, hash, slhDsaSecurityCategory, tradeoff, preHashKey, tokenInstance.getCode());

                // add metadata

                // prepare public key
                publicKey = createAndSaveKeyData(
                        alias, association, KeyType.PUBLIC_KEY, KeyAlgorithm.SLHDSA, KeyFormat.SPKI,
                        KeyStoreUtil.spkiKeyValueFromKeyStore(keyStore, alias),
                        slhDsaSecurityCategory.getPublicKeySize(), metadata, tokenInstance);

                CustomKeyValue customKeyValue = new CustomKeyValue();
                HashMap<String, String> customKeyValues = new HashMap<>();
                customKeyValues.put("securityCategory", slhDsaSecurityCategory.getNistSecurityCategory());
                customKeyValues.put("hash", hash.getHashName());
                customKeyValues.put("tradeoff", tradeoff.name());
                customKeyValues.put("prehash", String.valueOf(preHashKey));
                customKeyValue.setValues(customKeyValues);

                // prepare private key
                privateKey = createAndSaveKeyData(alias, association, KeyType.PRIVATE_KEY, KeyAlgorithm.SLHDSA,
                        KeyFormat.CUSTOM, customKeyValue, slhDsaSecurityCategory.getPrivateKeySize(), metadata, tokenInstance);
            }
            case MLKEM -> {
                final MLKEMSecurityCategory securityCategory = MLKEMSecurityCategory.valueOf(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(
                                        MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL, request.getCreateKeyAttributes(), IntegerAttributeContentV2.class)
                                .getData()
                );

                BCMLKEMPublicKey kemPublicKey =  KeyStoreUtil.generateMLKEMKey(keyStore, alias, securityCategory, tokenInstance.getCode());
                RawKeyValue keyValue = new RawKeyValue(Base64.getEncoder().encodeToString(kemPublicKey.getEncoded()));
                publicKey = createAndSaveKeyData(alias, association, KeyType.PUBLIC_KEY, KeyAlgorithm.MLKEM, KeyFormat.SPKI, keyValue, securityCategory.getPublicKeySize(), metadata, tokenInstance);

                CustomKeyValue customKeyValue = new CustomKeyValue();
                HashMap<String, String> customKeyValues = new HashMap<>();
                customKeyValues.put("securityCategory", String.valueOf(securityCategory.getNistSecurityCategory()));
                customKeyValue.setValues(customKeyValues);

                // prepare private key
                privateKey = createAndSaveKeyData(alias, association, KeyType.PRIVATE_KEY, KeyAlgorithm.MLKEM,
                        KeyFormat.CUSTOM, customKeyValue, securityCategory.getPrivateKeySize(), metadata, tokenInstance);

            }
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        // store key inside token
        byte[] data = KeyStoreUtil.saveKeystore(keyStore, tokenInstance.getCode());
        tokenInstance.setData(data);

        // save token and return
        // Note: saveTokenInstance already schedules keystore cache eviction internally
        // (see TokenInstanceServiceImpl.saveTokenInstance), so no explicit evict call is needed here.
        tokenInstanceService.saveTokenInstance(tokenInstance);

        response.setPublicKeyData(publicKey.toKeyDataResponseDto());
        response.setPrivateKeyData(privateKey.toKeyDataResponseDto());

        return response;
    }

    @Override
    public void destroyKey(UUID uuid, UUID keyUuid) throws NotFoundException {

        KeyData key = keyDataRepository.findByUuid(keyUuid)
                .orElseThrow(() -> new NotFoundException(KeyData.class, keyUuid));

        // remove key from the keystore only if it is private key
        // public key is removed automatically when private key is removed, however, we can keep it in the database
        if (key.getType() == KeyType.PRIVATE_KEY) {
            removeKeyFromKeyStore(uuid, key.getName());
        }

        // delete key from the database
        keyDataRepository.delete(key);
        keyDataCacheService.evictAfterCommit(keyUuid);
    }

    private void removeKeyFromKeyStore(UUID tokenInstanceUuid, String alias) throws NotFoundException {
        // check if the token exists and if it is activated
        TokenInstance tokenInstance = tokenInstanceService.getTokenInstanceEntity(tokenInstanceUuid);
        if (tokenInstance.getCode() == null) throw new TokenInstanceException("Token is not activated.");

        // load the token
        KeyStore keyStore = KeyStoreUtil.loadKeystore(tokenInstance.getData(), tokenInstance.getCode());

        // destroy key, it should exist when it is found in the database
        KeyStoreUtil.deleteAliasFromKeyStore(keyStore, alias);

        // store updated token
        byte[] data = KeyStoreUtil.saveKeystore(keyStore, tokenInstance.getCode());
        tokenInstance.setData(data);

        // save token and return
        tokenInstanceService.saveTokenInstance(tokenInstance);
    }

    @Override
    public List<KeyDataResponseDto> listKeys(UUID uuid) throws NotFoundException {
        List<KeyData> keys = listKeyEntities(uuid);
        return keys.stream().map(KeyData::toKeyDataResponseDto).toList();
    }

    @Override
    public List<KeyData> listKeyEntities(UUID uuid) throws NotFoundException {
        TokenInstance tokenInstance = tokenInstanceService.getTokenInstanceEntity(uuid);
        return keyDataRepository.findAllByTokenInstanceUuid(tokenInstance.getUuid());
    }

    @Override
    public KeyDataResponseDto getKey(UUID uuid, UUID keyUuid) throws NotFoundException {
        KeyData key = getKeyEntity(uuid, keyUuid);
        return key.toKeyDataResponseDto();
    }

    @Override
    public KeyData getKeyEntity(UUID uuid, UUID keyUuid) throws NotFoundException {
        return keyDataRepository.findByUuid(keyUuid)
                .orElseThrow(() -> new NotFoundException(KeyData.class, keyUuid));
    }

    private KeyData createAndSaveKeyData(
            String alias, String association, KeyType type,
            KeyAlgorithm algorithm,
            KeyFormat format,
            KeyValue value,
            int length,
            List<MetadataAttribute> metadata,
            TokenInstance tokenInstance) {
        KeyData keyData = new KeyData();
        keyData.setUuid(UUID.randomUUID());
        keyData.setName(alias);
        keyData.setAssociation(association);
        keyData.setType(type);
        keyData.setAlgorithm(algorithm);
        keyData.setFormat(format);
        keyData.setValue(value);
        keyData.setLength(length);
        keyData.setMetadata(metadata);
        keyData.setTokenInstance(tokenInstance);

        keyDataRepository.save(keyData);
        keyDataCacheService.evictAfterCommit(keyData.getUuid());

        return keyData;
    }

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    public void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @Autowired
    public void setKeyDataCacheService(KeyDataCacheService keyDataCacheService) {
        this.keyDataCacheService = keyDataCacheService;
    }
}
