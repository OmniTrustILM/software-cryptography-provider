package com.otilm.cp.soft.logging;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.encoder.Encoder;
import ch.qos.logback.core.status.Status;
import java.util.Iterator;
import java.util.List;
import net.logstash.logback.composite.JsonProvider;
import net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The schema covers every line, so the configuration has to put the fields on the root of the logger tree rather than
 * on this connector's own loggers: what the key technology, the persistence layer and the framework say is collected
 * and read the same way, and is where material could reach a log at all.
 */
@SpringBootTest
class ConnectorLogWiringTest {

    @Test
    void writesEveryLineThroughTheSchemaFields() {
        // given
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

        // when
        Iterator<Appender<ILoggingEvent>> appenders = context
                .getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME)
                .iteratorForAppenders();

        // then
        assertTrue(appenders.hasNext(), "the root of the logger tree writes nowhere");
        Appender<ILoggingEvent> appender = appenders.next();
        assertFalse(appenders.hasNext(), "a second appender would write lines the schema never saw");
        assertEquals("CONNECTOR_LOG", appender.getName());
        assertTrue(statesTheSchemaFields(appender), "the appender does not write the schema's fields");
    }

    /** A configuration logback could not read leaves the lines unwritten, so nothing about it may have failed. */
    @Test
    void isAConfigurationLogbackRead() {
        // given
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

        // when
        List<Status> reported = context.getStatusManager().getCopyOfStatusList();

        // then
        assertTrue(reported.stream().noneMatch(status -> status.getLevel() == Status.ERROR),
                () -> "logback reported " + reported.stream().filter(s -> s.getLevel() == Status.ERROR).toList());
    }

    private static boolean statesTheSchemaFields(Appender<ILoggingEvent> appender) {
        Encoder<ILoggingEvent> encoder = encoderOf(appender);
        assertNotNull(encoder, "the appender writes without an encoder");
        if (encoder instanceof LoggingEventCompositeJsonEncoder composite) {
            for (JsonProvider<ILoggingEvent> provider : composite.getProviders().getProviders()) {
                if (provider instanceof ConnectorLogFields) {
                    return true;
                }
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static Encoder<ILoggingEvent> encoderOf(Appender<ILoggingEvent> appender) {
        if (appender instanceof ch.qos.logback.core.OutputStreamAppender<ILoggingEvent> writing) {
            return writing.getEncoder();
        }
        return null;
    }
}
