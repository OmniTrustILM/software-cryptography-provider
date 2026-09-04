package com.otilm.cp.soft.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.cp.soft.api.CorrelationFilter;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The platform reads a log line against a schema that names every field it accepts and refuses the rest, so what is
 * written has to carry all the schema requires and nothing it does not name.
 */
class ConnectorLogFieldsTest {

    /** Every field the schema names, and no others may be written. */
    private static final Set<String> NAMED_BY_THE_SCHEMA = Set
            .of("schema", "@timestamp", "severity", "message", "service", "trace_id", "span_id", "trace_flags",
                    "correlation_id", "attributes");

    /** What the schema requires of every line. */
    private static final List<String> REQUIRED = List.of("schema", "@timestamp", "severity", "message", "service");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @AfterEach
    void forgetTheRequest() {
        MDC.clear();
    }

    @Test
    void writesEveryFieldTheSchemaRequires() {
        // given
        // when
        JsonNode line = encode(event(Level.INFO, "a key was created"));

        // then
        for (String field : REQUIRED) {
            assertTrue(line.has(field), () -> "expected " + field + ", got " + line);
        }
        assertEquals("connector.log", line.path("schema").path("name").asText());
        assertEquals(1, line.path("schema").path("version").asInt());
        assertEquals("INFO", line.path("severity").asText());
        assertEquals("a key was created", line.path("message").asText());
        assertFalse(line.path("service").path("name").asText().isEmpty());
    }

    @Test
    void writesNoFieldTheSchemaDoesNotName() {
        // given
        MDC.put(CorrelationFilter.CORRELATION_ID, "req-1");
        MDC.put("traceId", "4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1");
        MDC.put("spanId", "f1a2b3c4d5e6f789");
        MDC.put("traceFlags", "01");

        // when
        JsonNode line = encode(event(Level.ERROR, "the token could not be opened"));

        // then
        line
                .fieldNames()
                .forEachRemaining(field -> assertTrue(NAMED_BY_THE_SCHEMA.contains(field),
                        () -> "the schema does not name " + field));
    }

    @Test
    void writesTheTimestampAsAnInstant() {
        // given
        // when
        JsonNode line = encode(event(Level.INFO, "anything"));

        // then
        assertDoesNotThrow(() -> Instant.parse(line.path("@timestamp").asText()));
    }

    @Test
    void carriesTheIdentifierTheRequestIsKnownBy() {
        // given
        MDC.put(CorrelationFilter.CORRELATION_ID, "req-3c59a3");

        // when
        JsonNode line = encode(event(Level.INFO, "serving"));

        // then
        assertEquals("req-3c59a3", line.path("correlation_id").asText());
    }

    /** A trace this connector is part of is written only in the shape the schema states. */
    @Test
    void carriesATraceStatedInTheShapeTheSchemaRequires() {
        // given
        MDC.put("traceId", "4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1");
        MDC.put("spanId", "f1a2b3c4d5e6f789");
        MDC.put("traceFlags", "01");

        // when
        JsonNode line = encode(event(Level.INFO, "serving"));

        // then
        assertEquals("4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1", line.path("trace_id").asText());
        assertEquals("f1a2b3c4d5e6f789", line.path("span_id").asText());
        assertEquals("01", line.path("trace_flags").asText());
    }

    /**
     * A malformed identifier correlates with nothing and would make the line one the platform refuses, so it is left
     * out rather than written as it arrived.
     */
    @Test
    void leavesOutATraceThatIsNotTheShapeTheSchemaRequires() {
        // given
        MDC.put("traceId", "not-a-trace-id");
        MDC.put("spanId", "0F1A2B3C4D5E6F78");
        MDC.put("traceFlags", "99");

        // when
        JsonNode line = encode(event(Level.INFO, "serving"));

        // then
        assertFalse(line.has("trace_id"), () -> "expected no trace, got " + line);
        assertFalse(line.has("span_id"), "an upper-case identifier is not the stated shape");
        assertFalse(line.has("trace_flags"));
    }

    /**
     * The schema requires every line to carry a complete trace pair or a correlation identifier, so a line said outside
     * a request carries this run of the process rather than nothing.
     */
    @Test
    void carriesThisRunForALineSaidOutsideARequest() {
        // given
        // when
        JsonNode line = encode(event(Level.INFO, "started"));

        // then
        assertTrue(line.has("correlation_id"), () -> "the schema accepts no line without one: " + line);
        assertFalse(line.path("correlation_id").asText().isEmpty());
        assertFalse(line.has("trace_id"), "there is no trace outside a request");
    }

    /** Every line of one run is correlated by the same identifier, or it correlates nothing. */
    @Test
    void saysEveryLineOfOneRunUnderTheSameIdentifier() {
        // given
        // when
        String first = encode(event(Level.INFO, "started")).path("correlation_id").asText();
        String second = encode(event(Level.INFO, "ready")).path("correlation_id").asText();

        // then
        assertEquals(first, second);
    }

    /** An identifier the platform would refuse for its length is written as much of it as the schema accepts. */
    @Test
    void writesNoMoreOfTheIdentifierThanTheSchemaAccepts() {
        // given
        MDC.put(CorrelationFilter.CORRELATION_ID, "r".repeat(200));

        // when
        JsonNode line = encode(event(Level.INFO, "serving"));

        // then
        assertEquals(128, line.path("correlation_id").asText().length());
    }

    /** Which process said it, which several processes writing to one sink cannot be told apart without. */
    @Test
    void saysWhichProcessSaidIt() {
        // given
        // when
        JsonNode line = encode(event(Level.INFO, "serving"));

        // then
        assertEquals(String.valueOf(ProcessHandle.current().pid()), line.path("attributes").path("pid").asText());
    }

    /** The provider is what every line passes through, so it is where what must not be written down is taken out. */
    @Test
    void takesOutOfTheMessageWhatMustNotBeWrittenDown() {
        // given
        // when
        JsonNode line = encode(event(Level.WARN, "cannot open keystore, passphrase=00000000-the-code-itself"));

        // then
        assertFalse(line.path("message").asText().contains("00000000-the-code-itself"), line.toString());
        assertTrue(line.path("message").asText().contains("[redacted]"));
    }

    @Test
    void takesOutOfTheStackWhatMustNotBeWrittenDown() {
        // given
        LoggingEvent failed = event(Level.ERROR, "the keystore could not be read");
        failed
                .setThrowableProxy(new ch.qos.logback.classic.spi.ThrowableProxy(
                        new IllegalStateException("passphrase=00000000-the-code-itself")));

        // when
        JsonNode line = encode(failed);

        // then
        assertFalse(line.path("attributes").path("stack").asText().contains("00000000-the-code-itself"),
                line.toString());
    }

    /** What the build says about itself is what names the service, so a line states it without being told. */
    @Test
    void namesTheServiceFromWhatTheBuildSaysAboutItself() {
        // given
        ConnectorLogFields untold = new ConnectorLogFields();

        // when
        JsonNode line = encode(untold, event(Level.INFO, "serving"));

        // then
        assertEquals("software-cryptography-provider", line.path("service").path("name").asText());
        assertFalse(line.path("service").path("version").asText().isEmpty(), "the build states a version");
    }

    /** The schema names no field for a stack, and accepts none it does not name. */
    @Test
    void writesTheStackOfAFailureAmongTheAttributes() {
        // given
        LoggingEvent failed = event(Level.ERROR, "the keystore could not be read");
        failed.setThrowableProxy(new ch.qos.logback.classic.spi.ThrowableProxy(new IllegalStateException("no code")));

        // when
        JsonNode line = encode(failed);

        // then
        assertTrue(line.path("attributes").path("stack").asText().contains("IllegalStateException"));
        assertFalse(line.has("stack"), "the schema names no field for it");
    }

    @Test
    void saysSomethingForALineThatSaysNothing() {
        // given
        // when
        JsonNode line = encode(event(Level.INFO, ""));

        // then
        assertFalse(line.path("message").asText().isEmpty(), "the schema requires a message of some length");
    }

    private static LoggingEvent event(Level level, String message) {
        LoggerContext context = new LoggerContext();
        LoggingEvent event = new LoggingEvent();
        event.setLoggerContext(context);
        event.setLoggerName("com.otilm.cp.soft.Example");
        event.setLevel(level);
        event.setMessage(message);
        event.setThreadName("main");
        event.setTimeStamp(System.currentTimeMillis());
        return event;
    }

    private static JsonNode encode(LoggingEvent event) {
        ConnectorLogFields fields = new ConnectorLogFields();
        fields.setServiceName("software-cryptography-provider");
        fields.setServiceVersion("1.4.0");
        return encode(fields, event);
    }

    private static JsonNode encode(ConnectorLogFields fields, LoggingEvent event) {
        LoggerContext context = new LoggerContext();
        LoggingEventCompositeJsonEncoder encoder = new LoggingEventCompositeJsonEncoder();
        encoder.setContext(context);
        encoder.getProviders().addProvider(fields);
        encoder.start();
        try {
            return MAPPER.readTree(encoder.encode(event));
        } catch (Exception e) {
            throw new IllegalStateException("the line could not be read back", e);
        } finally {
            encoder.stop();
        }
    }
}
