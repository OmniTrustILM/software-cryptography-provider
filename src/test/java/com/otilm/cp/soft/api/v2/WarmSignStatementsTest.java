package com.otilm.cp.soft.api.v2;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.api.CryptographicOperationsControllerImpl;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.SignatureFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import jakarta.persistence.EntityManagerFactory;
import java.util.List;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * A warm signature reads only the version of its token's row. That version tells cached material from a token another
 * process has since changed.
 */
@SpringBootTest(properties = "spring.jpa.properties.hibernate.generate_statistics=true")
class WarmSignStatementsTest {

    private KeyV2ControllerImpl keys;

    private OperationsV2ControllerImpl operations;

    private CryptographicOperationsControllerImpl v1Operations;

    private TokenInstanceRepository tokenInstanceRepository;

    private Statistics statistics;

    @Autowired
    void setKeys(KeyV2ControllerImpl keys) {
        this.keys = keys;
    }

    @Autowired
    void setOperations(OperationsV2ControllerImpl operations) {
        this.operations = operations;
    }

    @Autowired
    void setV1Operations(CryptographicOperationsControllerImpl v1Operations) {
        this.v1Operations = v1Operations;
    }

    @Autowired
    void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Autowired
    void setEntityManagerFactory(EntityManagerFactory entityManagerFactory) {
        this.statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
    }

    @Test
    void warmV2SignatureWithAnRsaKeyReadsOnlyTheTokenVersion() {
        // given
        SignDataRequestV2Dto signing = v2Signing(KeyRequestFixtures.rsaKeyPair(uniqueName(), alias()),
                SignatureAlgorithm.SHA256_WITH_RSA);
        operations.signData(signing);
        statistics.clear();

        // when
        operations.signData(signing);

        // then
        assertEquals(1, statistics.getPrepareStatementCount(), "a warm signature reads the token version only");
    }

    @Test
    void warmV2SignatureWithAnMldsaKeyReadsOnlyTheTokenVersion() {
        // given
        SignDataRequestV2Dto signing = v2Signing(KeyRequestFixtures.mldsaKeyPair(uniqueName(), alias()),
                SignatureAlgorithm.ML_DSA_65);
        operations.signData(signing);
        statistics.clear();

        // when
        operations.signData(signing);

        // then
        assertEquals(1, statistics.getPrepareStatementCount(), "a warm signature reads the token version only");
    }

    @Test
    void warmV1SignatureReadsOnlyTheTokenVersion() throws NotFoundException {
        // given
        String tokenName = uniqueName();
        KeyPairDataResponseV2Dto created = created(KeyRequestFixtures.rsaKeyPair(tokenName, alias()));
        String token = tokenInstanceRepository.findVersionByName(tokenName).orElseThrow().uuid().toString();
        String key = keyReference(created.getPrivateKeyData().getKeyMeta());
        SignDataRequestDto signing = SignatureFixtures.v1RsaSigning();
        v1Operations.signData(token, key, signing);
        statistics.clear();

        // when
        v1Operations.signData(token, key, signing);

        // then
        assertEquals(1, statistics.getPrepareStatementCount(), "a warm signature reads the token version only");
    }

    private SignDataRequestV2Dto v2Signing(CreateKeyRequestV2Dto creation, SignatureAlgorithm algorithm) {
        return SignatureFixtures
                .v2Signing(creation.getTokenAttributes(), created(creation).getPrivateKeyData().getKeyMeta(),
                        algorithm);
    }

    private KeyPairDataResponseV2Dto created(CreateKeyRequestV2Dto creation) {
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) keys.createKey(creation).getBody();
        assertNotNull(created);
        return created;
    }

    private static String keyReference(List<MetadataAttribute> keyMeta) {
        return AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(KeyAttributes.ATTRIBUTE_META_KEY_REFERENCE, keyMeta,
                        StringAttributeContentV2.class)
                .getData();
    }

    private static String uniqueName() {
        return TokenContextFixtures.uniqueName("warm-sign");
    }

    private static String alias() {
        return "key-" + System.nanoTime();
    }
}
