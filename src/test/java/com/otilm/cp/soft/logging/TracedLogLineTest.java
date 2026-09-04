package com.otilm.cp.soft.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.cp.soft.api.CorrelationFilter;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * A caller states the trace its request is part of, and everything said while serving it has to be gathered under that
 * trace rather than under one of this connector's own. The trace is not sent back: it belongs to the caller's, which
 * reads its own span from where it made the request.
 */
@SpringBootTest
@AutoConfigureMockMvc
class TracedLogLineTest {

    private static final String TRACEPARENT = "traceparent";

    private static final String TRACESTATE = "tracestate";

    private static final String TRACE = "4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1";

    private static final String SPAN = "f1a2b3c4d5e6f789";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private MockMvc mockMvc;

    private Logger served;

    private ByteArrayOutputStream written;

    private OutputStreamAppender<ILoggingEvent> lines;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @BeforeEach
    void readWhatIsWritten() {
        served = (Logger) LoggerFactory.getLogger("com.otilm.cp.soft");
        written = new ByteArrayOutputStream();

        LoggingEventCompositeJsonEncoder encoder = new LoggingEventCompositeJsonEncoder();
        encoder.setContext(served.getLoggerContext());
        encoder.getProviders().addProvider(new ConnectorLogFields());
        encoder.start();

        lines = new OutputStreamAppender<>();
        lines.setContext(served.getLoggerContext());
        lines.setEncoder(encoder);
        lines.setOutputStream(written);
        lines.start();

        served.setLevel(Level.DEBUG);
        served.addAppender(lines);
    }

    @AfterEach
    void stopReading() {
        served.detachAppender(lines);
        served.setLevel(null);
        lines.stop();
    }

    @Test
    void saysWhatItServedUnderTheTraceTheCallerStated() throws Exception {
        // given
        // when
        served("00-" + TRACE + "-" + SPAN + "-01", null);

        // then
        JsonNode line = said().orElseThrow(() -> new AssertionError("nothing was written"));
        assertEquals(TRACE, line.path("trace_id").asText());
        assertEquals(SPAN, line.path("span_id").asText());
        assertEquals("01", line.path("trace_flags").asText());
    }

    /** The trace belongs to the caller's own, which reads its span from where it made the request. */
    @Test
    void sendsBackNeitherTraceHeader() throws Exception {
        // given
        // when
        MvcResult answered = mockMvc
                .perform(get("/v2/info")
                        .header(TRACEPARENT, "00-" + TRACE + "-" + SPAN + "-01")
                        .header(TRACESTATE, "vendor=opaque"))
                .andReturn();

        // then
        assertEquals(200, answered.getResponse().getStatus());
        assertNull(answered.getResponse().getHeader(TRACEPARENT));
        assertNull(answered.getResponse().getHeader(TRACESTATE));
    }

    /** A request that states no trace is given one, so what was said about it is still gathered together. */
    @Test
    void saysWhatItServedUnderATraceOfItsOwnWhenTheCallerStatedNone() throws Exception {
        // given
        // when
        served(null, null);

        // then
        JsonNode line = said().orElseThrow(() -> new AssertionError("nothing was written"));
        assertTrue(line.path("trace_id").asText().matches("[0-9a-f]{32}"), line::toString);
        assertTrue(line.path("span_id").asText().matches("[0-9a-f]{16}"), line::toString);
        assertEquals("00", line.path("trace_flags").asText(), "nothing is recording a trace of its own");
        assertNotEquals(TRACE, line.path("trace_id").asText());
    }

    /** A trace this connector cannot read leaves the request with one of its own rather than with nothing. */
    @Test
    void saysWhatItServedUnderATraceOfItsOwnWhenTheCallerStatedOneItCannotRead() throws Exception {
        // given
        // when
        served("00-not-a-trace-01", null);

        // then
        JsonNode line = said().orElseThrow(() -> new AssertionError("nothing was written"));
        assertTrue(line.path("trace_id").asText().matches("[0-9a-f]{32}"), line::toString);
        assertEquals("00", line.path("trace_flags").asText(), "nothing is recording a trace of its own");
    }

    /** Vendor state stated beside the trace is nothing this reads from, and nothing it refuses a request for. */
    @Test
    void saysWhatItServedForARequestThatStatesVendorStateBesideTheTrace() throws Exception {
        // given
        // when
        served("00-" + TRACE + "-" + SPAN + "-01", "vendor=opaque,other=state");

        // then
        assertEquals(TRACE, said().orElseThrow().path("trace_id").asText());
    }

    /**
     * A request thread is used again. What was said about one request must not be attributed to what is said on that
     * thread afterwards, so what the request put there is taken away when it is done.
     */
    @Test
    void leavesNothingOfTheRequestBehindOnTheThreadThatServedIt() throws Exception {
        // given
        served("00-" + TRACE + "-" + SPAN + "-01", null);

        // when
        // then
        assertNull(MDC.get(CorrelationFilter.TRACE_ID), "the trace was left on the thread");
        assertNull(MDC.get(CorrelationFilter.SPAN_ID));
        assertNull(MDC.get(CorrelationFilter.TRACE_FLAGS));
        assertNull(MDC.get(CorrelationFilter.CORRELATION_ID));
    }

    /**
     * A request this connector says something about while serving, which is what a log line can be read from. What it
     * is refused for is beside the point: the trace is stated on the way in either way.
     */
    private void served(String traceparent, String tracestate) throws Exception {
        var request = post("/v2/cryptographyProvider/operations/encrypt/attributes")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"tokenAttributes\":");
        if (traceparent != null) {
            request = request.header(TRACEPARENT, traceparent);
        }
        if (tracestate != null) {
            request = request.header(TRACESTATE, tracestate);
        }
        mockMvc.perform(request).andReturn();
    }

    /** The first line written that carries a trace, which is one said while the request was being served. */
    private Optional<JsonNode> said() {
        return written
                .toString(StandardCharsets.UTF_8)
                .lines()
                .map(TracedLogLineTest::read)
                .flatMap(Optional::stream)
                .filter(line -> !line.path("trace_id").asText().isEmpty())
                .findFirst();
    }

    private static Optional<JsonNode> read(String line) {
        try {
            return Optional.of(MAPPER.readTree(line));
        } catch (JsonProcessingException e) {
            return Optional.empty();
        }
    }
}
