package com.otilm.cp.soft.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A failure is answered with the identifier the request is known by and logged under the same one, which is what lets
 * the line and the answer be put side by side. They would drift the moment either read the identifier from anywhere but
 * the one place it is kept.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CorrelatedLogLineTest {

    private static final String HEADER = "correlation-id";

    private static final String KNOWN_BY = "req-3c59a3";

    private MockMvc mockMvc;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Logger advice;

    private ByteArrayOutputStream written;

    private OutputStreamAppender<ILoggingEvent> lines;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @BeforeEach
    void readWhatIsWritten() {
        advice = (Logger) LoggerFactory.getLogger("com.otilm.cp.soft.api.v2");
        written = new ByteArrayOutputStream();

        LoggingEventCompositeJsonEncoder encoder = new LoggingEventCompositeJsonEncoder();
        encoder.setContext(advice.getLoggerContext());
        encoder.getProviders().addProvider(new ConnectorLogFields());
        encoder.start();

        lines = new OutputStreamAppender<>();
        lines.setContext(advice.getLoggerContext());
        lines.setEncoder(encoder);
        lines.setOutputStream(written);
        lines.start();

        advice.setLevel(Level.DEBUG);
        advice.addAppender(lines);
    }

    @AfterEach
    void stopReading() {
        advice.detachAppender(lines);
        advice.setLevel(null);
        lines.stop();
    }

    @Test
    void logsAFailureUnderTheIdentifierItIsAnsweredWith() throws Exception {
        // given
        // when
        mockMvc
                .perform(post("/v2/cryptographyProvider/operations/encrypt/attributes")
                        .header(HEADER, KNOWN_BY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tokenAttributes\":"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.correlationId").value(KNOWN_BY));

        // then
        String said = written.toString(StandardCharsets.UTF_8);
        assertTrue(said.lines().anyMatch(line -> KNOWN_BY.equals(correlationIdOf(line))),
                () -> "no line was written under " + KNOWN_BY + ", only " + said);
    }

    /** What the line itself carries, which is what a collector reads it by. */
    private static String correlationIdOf(String line) {
        try {
            return MAPPER.readTree(line).path("correlation_id").asText(null);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
