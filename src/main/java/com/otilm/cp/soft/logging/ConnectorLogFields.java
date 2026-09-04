package com.otilm.cp.soft.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import com.fasterxml.jackson.core.JsonGenerator;
import com.otilm.cp.soft.api.CorrelationFilter;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Pattern;
import net.logstash.logback.composite.AbstractJsonProvider;
import org.slf4j.MDC;

/**
 * Writes a log line as the object the platform reads.
 *
 * <p>
 * The schema states which fields a line carries and accepts no others, so everything this connector has to say beyond
 * them goes under {@code attributes}: which logger said it, on which thread, and the stack of a failure where there is
 * one.
 * </p>
 *
 * <p>
 * Everything written from the event itself passes through {@link Redaction} first. Every line this connector emits is
 * written here, so this is the one place all of them can be held to that.
 * </p>
 *
 * <p>
 * A trace or span identifier is written only in the shape the schema states, since a malformed one cannot be correlated
 * with anything and would make the line invalid rather than merely incomplete.
 * </p>
 *
 * <p>
 * The schema requires every line to carry either a complete trace pair or a correlation identifier, so a correlation
 * identifier is always written. A line said while serving a request carries that request's; one said outside a request
 * — starting up, migrating, or on a thread of the connector's own — carries this run of the process, which is what such
 * lines can be correlated by.
 * </p>
 */
public class ConnectorLogFields extends AbstractJsonProvider<ILoggingEvent> {

    /** The identifiers the schema states the shape of. */
    private static final Pattern TRACE_ID = Pattern.compile("[0-9a-f]{32}");

    private static final Pattern SPAN_ID = Pattern.compile("[0-9a-f]{16}");

    private static final Pattern TRACE_FLAGS = Pattern.compile("0[01]");

    /** The longest correlation identifier the schema accepts. */
    private static final int CORRELATION_ID_LIMIT = 128;

    private static final String SCHEMA_NAME = "connector.log";

    private static final int SCHEMA_VERSION = 1;

    /** A line the schema would refuse for saying nothing, which is what a message of no length would be. */
    private static final String NOTHING_SAID = "(no message)";

    /** Which process said it, which the pattern this replaced carried and several processes to one sink need. */
    private static final String PROCESS_ID = String.valueOf(ProcessHandle.current().pid());

    /** What the build says about itself, which is where the service the line came from is taken from. */
    private static final Properties BUILD = build();

    /** What a line said outside any request is correlated by, which is this run of the process. */
    private static final String THIS_RUN = UUID.randomUUID().toString();

    private String serviceName = BUILD.getProperty("build.artifact", "connector");

    private String serviceVersion = BUILD.getProperty("build.version");

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public void setServiceVersion(String serviceVersion) {
        this.serviceVersion = serviceVersion;
    }

    @Override
    public void writeTo(JsonGenerator generator, ILoggingEvent event) throws IOException {
        generator.writeObjectFieldStart("schema");
        generator.writeStringField("name", SCHEMA_NAME);
        generator.writeNumberField("version", SCHEMA_VERSION);
        generator.writeEndObject();

        generator.writeStringField("@timestamp", Instant.ofEpochMilli(event.getTimeStamp()).toString());
        generator.writeStringField("severity", event.getLevel().toString());
        generator.writeStringField("message", said(event));

        generator.writeObjectFieldStart("service");
        generator.writeStringField("name", serviceName);
        if (isStated(serviceVersion)) {
            generator.writeStringField("version", serviceVersion);
        }
        generator.writeEndObject();

        writeShaped(generator, "trace_id", MDC.get(CorrelationFilter.TRACE_ID), TRACE_ID);
        writeShaped(generator, "span_id", MDC.get(CorrelationFilter.SPAN_ID), SPAN_ID);
        writeShaped(generator, "trace_flags", MDC.get(CorrelationFilter.TRACE_FLAGS), TRACE_FLAGS);
        writeCorrelationId(generator, correlationId());

        writeAttributes(generator, event);
    }

    /** What the line says, which the schema requires to be something, and which may not say everything. */
    private static String said(ILoggingEvent event) {
        String message = Redaction.of(event.getFormattedMessage());
        return isStated(message) ? message : NOTHING_SAID;
    }

    /**
     * What the schema has no field of its own for. A stack is written here rather than beside the message because the
     * schema accepts no field it does not name.
     */
    private static void writeAttributes(JsonGenerator generator, ILoggingEvent event) throws IOException {
        generator.writeObjectFieldStart("attributes");
        generator.writeStringField("logger", event.getLoggerName());
        generator.writeStringField("thread", event.getThreadName());
        generator.writeStringField("pid", PROCESS_ID);
        IThrowableProxy failure = event.getThrowableProxy();
        if (failure != null) {
            generator.writeStringField("stack", Redaction.of(ThrowableProxyUtil.asString(failure)));
        }
        generator.writeEndObject();
    }

    private static void writeShaped(JsonGenerator generator, String field, String value, Pattern shape)
            throws IOException {
        if (value != null && shape.matcher(value).matches()) {
            generator.writeStringField(field, value);
        }
    }

    /** The request this line was said while serving, or this run of the process where it was said outside one. */
    private static String correlationId() {
        String stated = MDC.get(CorrelationFilter.CORRELATION_ID);
        return isStated(stated) ? stated : THIS_RUN;
    }

    /** An identifier longer than the schema accepts is written as much of it as the schema accepts. */
    private static void writeCorrelationId(JsonGenerator generator, String value) throws IOException {
        generator
                .writeStringField("correlation_id",
                        value.length() > CORRELATION_ID_LIMIT ? value.substring(0, CORRELATION_ID_LIMIT) : value);
    }

    private static boolean isStated(String value) {
        return value != null && !value.isBlank();
    }

    /**
     * The build information the packaged connector carries. A build that states none leaves the service named as the
     * schema's least, which is a name and no version.
     */
    private static Properties build() {
        Properties stated = new Properties();
        try (InputStream in = ConnectorLogFields.class.getResourceAsStream("/META-INF/build-info.properties")) {
            if (in != null) {
                stated.load(in);
            }
        } catch (IOException e) {
            // Nothing can be logged about it here: this runs while the logging itself is being built.
            return stated;
        }
        return stated;
    }
}
