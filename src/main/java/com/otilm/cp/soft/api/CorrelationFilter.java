package com.otilm.cp.soft.api;

import com.otilm.cp.soft.logging.TraceParent;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Gives every request an identifier that ties what this connector logs and answers to the caller's own record of it.
 *
 * <p>
 * A caller states that identifier itself, or a trace context it is part of. A request carrying neither is given one
 * here, so a log line can always be traced back to the request that produced it. The identifier is sent back, which is
 * how the caller learns the one this connector used; a trace context is not, since it belongs to the caller's trace
 * rather than to this response.
 * </p>
 *
 * <p>
 * What a caller states reaches both a log line and a response header, so a value carrying a line break could forge a
 * log entry or a header of its own. An identifier is used as it arrived only when it is plain text of a length the
 * platform accepts, and the request is given one of its own otherwise.
 * </p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@Component
public class CorrelationFilter extends OncePerRequestFilter {

    /** The keys a log line carries the request's identifiers under. */
    public static final String CORRELATION_ID = "correlation_id";

    public static final String TRACE_ID = "traceId";

    public static final String SPAN_ID = "spanId";

    public static final String TRACE_FLAGS = "traceFlags";

    private static final String CORRELATION_HEADER = "correlation-id";

    private static final String TRACE_HEADER = "traceparent";

    /** How long the platform accepts an identifier to be. */
    private static final int LIMIT = 128;

    /** An identifier of plain printable text, which is all that can safely reach a log line and a header. */
    private static final Pattern PLAIN = Pattern.compile("[\\x20-\\x7e]{1," + LIMIT + "}");

    /** Headers a caller states its own identifier for the request in, most specific first. */
    private static final List<String> STATED = List.of(CORRELATION_HEADER, "X-Request-Id");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        TraceParent trace = TraceParent.of(request.getHeader(TRACE_HEADER));
        String correlationId = resolve(request, trace);

        MDC.put(CORRELATION_ID, correlationId);
        MDC.put(TRACE_ID, trace.traceId());
        MDC.put(SPAN_ID, trace.spanId());
        MDC.put(TRACE_FLAGS, trace.flags());
        // The identifier is sent back and the trace is not: the trace belongs to the caller's own, and a caller
        // reads its own span from where it made the request rather than from what answered it.
        response.setHeader(CORRELATION_HEADER, correlationId);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(CORRELATION_ID);
            MDC.remove(TRACE_ID);
            MDC.remove(SPAN_ID);
            MDC.remove(TRACE_FLAGS);
        }
    }

    /**
     * What the request is known by. A caller that states one is taken at its word; otherwise the trace as a whole is
     * what correlates, and a request that stated no trace either is known by the trace it was given.
     */
    private static String resolve(HttpServletRequest request, TraceParent trace) {
        for (String header : STATED) {
            String stated = request.getHeader(header);
            if (stated != null && PLAIN.matcher(stated).matches()) {
                return stated;
            }
        }
        return trace.traceId();
    }

}
