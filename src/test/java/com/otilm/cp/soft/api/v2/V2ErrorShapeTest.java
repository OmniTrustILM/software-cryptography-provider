package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.common.error.ErrorCode;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The V2 interfaces answer every failure as a problem document carrying an {@code errorCode}, and the V1 surface keeps
 * the error shape it has always had. Both advices are on the same application, so which one answers is what these
 * check: a failure the V2 advice does not name would otherwise be answered by the connector-wide one, in a shape a V2
 * caller cannot read.
 */
@SpringBootTest
@AutoConfigureMockMvc
class V2ErrorShapeTest {

    private static final String OPERATIONS = "/v2/cryptographyProvider/operations";

    private MockMvc mockMvc;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Test
    void aBodyThatCannotBeReadIsAProblemDocument() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(post(OPERATIONS + "/encrypt/attributes")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tokenAttributes\":"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.BAD_REQUEST.name()))
                .andExpect(jsonPath("$.type").exists());
    }

    /** A V2 document names every property it accepts, so one it does not is the caller's mistake, not a failure. */
    @Test
    void aPropertyTheContractDoesNotNameIsAProblemDocument() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(post(OPERATIONS + "/encrypt/attributes")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tokenAttributes\":[],\"keyMeta\":[],\"unexpected\":\"value\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.BAD_REQUEST.name()));
    }

    @Test
    void aBrokenFieldRuleIsAProblemDocument() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(post(OPERATIONS + "/encrypt/attributes").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.VALIDATION_FAILED.name()));
    }

    /** Everything a caller branches on has to survive to the wire, not just to the document this connector builds. */
    @Test
    void aProblemDocumentCarriesWhatACallerBranchesOn() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(post(OPERATIONS + "/encrypt/attributes").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(jsonPath("$.errorCode").exists())
                .andExpect(jsonPath("$.type").exists())
                .andExpect(jsonPath("$.title").exists())
                .andExpect(jsonPath("$.detail").exists())
                .andExpect(jsonPath("$.status").value(HttpStatus.UNPROCESSABLE_ENTITY.value()))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.retryable").exists());
    }

    /**
     * The V1 surface is unchanged by the V2 advice, which takes precedence over the connector-wide one and would
     * otherwise answer V1 callers in a shape they do not read.
     */
    @Test
    void theV1SurfaceKeepsItsOwnErrorShape() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v1/cryptographyProvider/tokens/{uuid}", UUID.randomUUID()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").doesNotExist())
                .andExpect(jsonPath("$.message").exists());
    }
}
