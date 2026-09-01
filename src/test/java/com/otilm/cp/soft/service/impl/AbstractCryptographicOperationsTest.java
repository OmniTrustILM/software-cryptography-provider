package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import jakarta.transaction.Transactional;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Transactional
abstract class AbstractCryptographicOperationsTest {

    protected static final String PASSWORD = "123";

    @Autowired
    protected KeyManagementService keyManagementService;

    @Autowired
    protected CryptographicOperationsService cryptographicOperationsService;

    @Autowired
    protected TokenInstanceRepository tokenInstanceRepository;

    protected TokenInstance tokenInstance;

    @BeforeEach
    void setUp() {
        tokenInstance = new TokenInstance();
        tokenInstance.setCode(PASSWORD);
        tokenInstance.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        tokenInstanceRepository.save(tokenInstance);
    }

    protected RequestAttributeV2 buildAliasAttribute(String alias) {
        RequestAttributeV2 keyAlias = new RequestAttributeV2();
        keyAlias.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS);
        keyAlias.setContentType(AttributeContentType.STRING);
        keyAlias.setContent(List.of(new StringAttributeContentV2(alias)));
        return keyAlias;
    }

    protected RequestAttributeV2 buildAlgorithmAttribute(KeyAlgorithm algorithm) {
        RequestAttributeV2 keyAlgorithm = new RequestAttributeV2();
        keyAlgorithm.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM);
        keyAlgorithm.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 algorithmContent = new StringAttributeContentV2();
        algorithmContent.setReference(algorithm.getCode());
        algorithmContent.setData(algorithm.getCode());
        keyAlgorithm.setContent(List.of(algorithmContent));
        return keyAlgorithm;
    }
}
