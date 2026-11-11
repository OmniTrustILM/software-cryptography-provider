package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.service.CryptographicKeyV2Service;
import com.otilm.cp.soft.service.CryptographicOperationsV2Service;
import com.otilm.cp.soft.service.TokenInstanceService;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.SignatureFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A V2 operation on a token in use takes the token's material from the cache. The request is still held to the token's
 * code and to the keys the token holds.
 */
@SpringBootTest
class OperationTokenTest {

    private static final String ALIAS = "shared";

    private CryptographicKeyV2Service keys;

    private CryptographicOperationsV2Service operations;

    private TokenInstanceService tokenInstanceService;

    private TokenInstanceRepository tokenInstanceRepository;

    @Autowired
    void setKeys(CryptographicKeyV2Service keys) {
        this.keys = keys;
    }

    @Autowired
    void setOperations(CryptographicOperationsV2Service operations) {
        this.operations = operations;
    }

    @Autowired
    void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    /**
     * The other token holds a key under the same alias. Its material therefore has a key the request could sign with.
     */
    @Test
    void refusesAKeyOfAnotherTokenUnderTheSameAlias() {
        // given
        String owner = TokenContextFixtures.uniqueName("v2-op-owner");
        String other = TokenContextFixtures.uniqueName("v2-op-other");
        KeyPairDataResponseV2Dto owned = keys.createKey(KeyRequestFixtures.rsaKeyPair(owner, ALIAS));
        keys.createKey(KeyRequestFixtures.rsaKeyPair(other, ALIAS));
        SignDataRequestV2Dto signing = signing(TokenContextFixtures.newToken(other), owned);

        // when
        // then
        assertThrows(ResourceMissingException.class, () -> operations.signData(signing));
    }

    @Test
    void refusesACodeThatIsNotTheTokensOwnOnceItsMaterialIsKept() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-op-code");
        KeyPairDataResponseV2Dto created = keys.createKey(KeyRequestFixtures.rsaKeyPair(name, ALIAS));
        operations.signData(signing(TokenContextFixtures.newToken(name), created));
        SignDataRequestV2Dto wrongCode = signing(TokenContextFixtures.newToken(name, "87654321"), created);

        // when
        // then
        assertThrows(TokenInstanceException.class, () -> operations.signData(wrongCode));
    }

    @Test
    void signsWithATokenDeactivatedThroughV1() throws NotFoundException {
        // given
        String name = TokenContextFixtures.uniqueName("v2-op-deactivated");
        KeyPairDataResponseV2Dto created = keys.createKey(KeyRequestFixtures.rsaKeyPair(name, ALIAS));
        SignDataRequestV2Dto signing = signing(TokenContextFixtures.newToken(name), created);
        operations.signData(signing);
        UUID token = tokenInstanceRepository.findVersionByName(name).orElseThrow().uuid();
        tokenInstanceService.deactivateTokenInstance(token);

        // when
        SignDataResponseV2Dto signed = operations.signData(signing);

        // then
        assertNotNull(signed.getSignatures().get(0).getData(), "the request's code has to bring the token back");
        assertEquals(TokenInstanceStatus.ACTIVATED, tokenInstanceService.getTokenInstanceStatus(token).getStatus(),
                "the token has to stay usable through V1");
    }

    private static SignDataRequestV2Dto signing(List<RequestAttribute> tokenAttributes, KeyPairDataResponseV2Dto pair) {
        return SignatureFixtures
                .v2Signing(tokenAttributes, pair.getPrivateKeyData().getKeyMeta(), SignatureAlgorithm.SHA256_WITH_RSA);
    }
}
