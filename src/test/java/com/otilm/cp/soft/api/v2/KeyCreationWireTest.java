package com.otilm.cp.soft.api.v2;

import com.jayway.jsonpath.JsonPath;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Key creation over the wire, with the exportable intent stated through the writer the platform uses and written by the
 * JSON mapper its connector client uses, next to this provider's own attributes as v2 attributes.
 */
@SpringBootTest
@AutoConfigureMockMvc
class KeyCreationWireTest {

    /** A v3 attribute names its version, and each of its content items names its content type. */
    private static final String V3_INTENT = "$.createKeyAttributes[?(@.name == '" + KeyExportableAttribute.NAME
            + "' && @.version == 'v3' && @.content[0].contentType == 'boolean')]";

    private MockMvc mockMvc;
    private KeyDataRepository keyDataRepository;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Autowired
    void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void createsTheKeyAsExportableAsTheV3IntentStates(boolean exportable) throws Exception {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-wire-intent"), "key-" + System.nanoTime());
        request.getCreateKeyAttributes().add(KeyExportableAttribute.request(exportable));
        String body = Jackson2ObjectMapperBuilder.json().build().writeValueAsString(request);
        List<Object> intents = JsonPath.read(body, V3_INTENT);
        assertEquals(1, intents.size(), "the intent travels as a v3 attribute: " + body);

        // when
        mockMvc
                .perform(post("/v2/cryptographyProvider/keys").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        // then
        List<KeyData> created = keyDataRepository.findByKeyCreationId(request.getKeyCreationId());
        assertEquals(2, created.size());
        assertTrue(created.stream().allMatch(half -> half.isExportable() == exportable),
                "both halves of the pair carry the stated intent");
    }
}
