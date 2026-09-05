package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.common.error.ErrorCode;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A V2 request that never reaches an operation is answered as a problem document all the same.
 *
 * <p>
 * A method, a media type or a path no route serves is refused before any controller is chosen, so nothing scoped to the
 * V2 controllers can see it. Without this the connector-wide advice answers, in the V1 error shape and as an internal
 * error, and a V2 caller has nothing to branch on.
 * </p>
 */
@SpringBootTest
@AutoConfigureMockMvc
class V2DispatchFailureAdviceTest {

    private static final String KEYS = "/v2/cryptographyProvider/keys";

    private static final MediaType PROBLEM = MediaType.APPLICATION_PROBLEM_JSON;

    private MockMvc mockMvc;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    /** The methods the route does serve are named back, which is what a caller refused this way looks for. */
    @Test
    void refusesAMethodTheRouteDoesNotServeAndSaysWhichItDoes() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get(KEYS + "/create/attributes"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM))
                .andExpect(header().string(HttpHeaders.ALLOW, "POST"))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OPERATION_NOT_SUPPORTED.name()))
                .andExpect(jsonPath("$.status").value(405))
                .andExpect(jsonPath("$.correlationId").exists());
    }

    @Test
    void refusesAMethodNoRouteUnderThePathServes() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(delete(KEYS + "/import"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OPERATION_NOT_SUPPORTED.name()));
    }

    @Test
    void refusesABodyInAMediaTypeTheRouteDoesNotRead() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(post(KEYS + "/create/attributes").contentType(MediaType.TEXT_PLAIN).content("not json"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.BAD_REQUEST.name()))
                .andExpect(jsonPath("$.status").value(415));
    }

    @Test
    void refusesToAnswerInAMediaTypeTheRouteDoesNotServe() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v2/attributes").header(HttpHeaders.ACCEPT, "text/csv"))
                .andExpect(status().isNotAcceptable())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.BAD_REQUEST.name()));
    }

    @Test
    void answersAPathItServesNothingUnderAsNotFound() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v2/cryptographyProvider/nothingIsHere"))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.RESOURCE_NOT_FOUND.name()));
    }

    /**
     * Not every V2 interface is under {@code /v2}: the metrics a collector scrapes are served where the interfaces put
     * them, which is under {@code /v1}. Which generation a request belongs to is therefore read off the routes this
     * connector serves rather than from its path, and a route the V2 controllers serve is answered their way wherever
     * it sits.
     */
    @Test
    void answersForEveryRouteTheV2ControllersServeAndNotOnlyThoseUnderV2() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(delete("/v1/metrics"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OPERATION_NOT_SUPPORTED.name()));
    }

    /**
     * The V1 surface answers as it always has. It has its own error shape and its own callers, so a refusal it used to
     * answer one way must not start being answered another because the V2 interfaces were added beside it.
     */
    @Test
    void leavesTheV1SurfaceAnsweringAsItDid() throws Exception {
        // given
        String key = "/v1/cryptographyProvider/tokens/" + UUID.randomUUID() + "/keys";

        // when
        // then
        mockMvc
                .perform(delete(key))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value(99))
                .andExpect(jsonPath("$.errorCode").doesNotExist());
    }

    @Test
    void leavesTheV1SurfaceAnsweringAsItDidForAMediaTypeItDoesNotRead() throws Exception {
        // given
        String activate = "/v1/cryptographyProvider/tokens/" + UUID.randomUUID() + "/activate";

        // when
        // then
        mockMvc
                .perform(patch(activate).contentType(MediaType.TEXT_PLAIN).content("x"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value(99))
                .andExpect(jsonPath("$.errorCode").doesNotExist());
    }

    /**
     * The V1 error shape is JSON, which a caller accepting nothing this connector produces cannot be sent, so it is
     * refused with no body at all — as it was before. A V2 problem document is sent in that same case, since a problem
     * document falls back on its own media type rather than the request being turned away.
     */
    @Test
    void leavesTheV1SurfaceAnsweringAsItDidForAMediaTypeItCannotAnswerIn() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v1/cryptographyProvider/tokens").header(HttpHeaders.ACCEPT, "text/csv"))
                .andExpect(status().isNotAcceptable())
                .andExpect(content().string(""));
    }

    @Test
    void leavesAPathOutsideTheV2InterfacesAnsweringAsItDid() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v1/cryptographyProvider/nothingIsHere"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value(99))
                .andExpect(jsonPath("$.errorCode").doesNotExist());
    }
}
