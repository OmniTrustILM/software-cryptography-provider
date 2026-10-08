package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A signature selection the key cannot make, over the wire: the platform acts on the status and the error code, so
 * those are what a refusal has to carry.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SignatureSelectionWireTest {

    private MockMvc mockMvc;

    private KeyV2ControllerImpl keys;

    private JsonMapper jsonMapper;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Autowired
    void setKeys(KeyV2ControllerImpl keys) {
        this.keys = keys;
    }

    @Autowired
    void setJsonMapper(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Test
    void refusesASelectionTheKeyCannotMakeAsAnUnsupportedParameter() throws Exception {
        // given
        CreateKeyRequestV2Dto creation = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-wire-selection"), "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) keys.createKey(creation).getBody();
        assertNotNull(created);

        SignatureDataV2Dto item = new SignatureDataV2Dto();
        item.setIdentifier("one");
        item.setData(new byte[]{1});
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        signing.setTokenAttributes(creation.getTokenAttributes());
        signing.setTokenProfileAttributes(List.of());
        signing.setKeyMeta(created.getPrivateKeyData().getKeyMeta());
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing
                .setSignatureAttributes(
                        List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_ECDSA)));
        signing.setData(List.of(item));
        String body = jsonMapper.writeValueAsString(signing);

        // when
        // then
        mockMvc
                .perform(post("/v2/cryptographyProvider/operations/sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.PARAMETER_UNSUPPORTED.name()));
    }
}
