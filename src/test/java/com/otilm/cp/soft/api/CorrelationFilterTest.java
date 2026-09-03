package com.otilm.cp.soft.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A caller matches what this connector logs and answers to its own record of the request by the identifier the request
 * is known by. It is sent back so the caller learns the one that was used.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CorrelationFilterTest {

    private static final String HEADER = "correlation-id";

    private static final String TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";

    private static final String TRACEPARENT = "00-" + TRACE_ID + "-00f067aa0ba902b7-01";

    private MockMvc mockMvc;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Test
    void sendsBackTheIdentifierTheCallerStated() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v2/info").header(HEADER, "core-7f3a2b19"))
                .andExpect(status().isOk())
                .andExpect(header().string(HEADER, "core-7f3a2b19"));
    }

    @Test
    void acceptsTheRequestIdentifierHeaderToo() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v2/info").header("X-Request-Id", "core-991"))
                .andExpect(header().string(HEADER, "core-991"));
    }

    /**
     * A trace context identifies the trace as a whole in its second field, which is the part that correlates. The
     * context itself belongs to the caller's trace and is not sent back.
     */
    @Test
    void takesTheTraceIdentifierFromATraceContext() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v2/info").header("traceparent", TRACEPARENT))
                .andExpect(header().string(HEADER, TRACE_ID))
                .andExpect(header().doesNotExist("traceparent"));
    }

    /** A request carrying nothing to correlate on is given something, so every log line can still be traced back. */
    @Test
    void givesARequestWithoutOneAnIdentifierOfItsOwn() throws Exception {
        // given
        // when
        // then
        mockMvc.perform(get("/v2/info")).andExpect(header().exists(HEADER));
    }

    /** The platform accepts an identifier of up to 128 characters, so a longer one is cut rather than refused. */
    @Test
    void shortensAnIdentifierThePlatformWouldNotAccept() throws Exception {
        // given
        String overlong = "c".repeat(200);

        // when
        // then
        mockMvc.perform(get("/v2/info").header(HEADER, overlong)).andExpect(header().string(HEADER, "c".repeat(128)));
    }

    /** A malformed trace context says nothing about the trace, so the request is given an identifier instead. */
    @Test
    void ignoresATraceContextItCannotRead() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get("/v2/info").header("traceparent", "not-a-trace-context"))
                .andExpect(header().exists(HEADER))
                .andExpect(header().string(HEADER, org.hamcrest.Matchers.not("not-a-trace-context")));
    }
}
