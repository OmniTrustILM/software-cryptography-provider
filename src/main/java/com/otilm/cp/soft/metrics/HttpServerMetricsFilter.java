package com.otilm.cp.soft.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Counts and times the requests this connector serves, under the names the interfaces require.
 *
 * <p>
 * The instrumentation a Spring application brings publishes its own readings of the same requests, but under its own
 * names. A collector is told to read the names the interfaces state, so those are recorded here: one counter of
 * requests by the status they were answered with, and one distribution of how long they took, over the buckets the
 * interfaces state.
 * </p>
 *
 * <p>
 * It sits outermost so that what it measures is the whole of the work, and it counts a request that reached no handler
 * as well, since that request was served too.
 * </p>
 *
 * <p>
 * Both labels are drawn from a fixed set rather than from what the caller wrote: a caller can name a method as freely
 * as it can name a path, and a series for each name it invents would grow without limit.
 * </p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
@Component
public class HttpServerMetricsFilter extends OncePerRequestFilter {

    /** The methods HTTP itself defines, which are the only ones the label carries. */
    private static final Set<String> DEFINED_METHODS = Arrays
            .stream(HttpMethod.values())
            .map(HttpMethod::name)
            .collect(Collectors.toUnmodifiableSet());

    private static final String OTHER_METHOD = "other";

    private final MeterRegistry registry;

    public HttpServerMetricsFilter(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long started = System.nanoTime();
        boolean answered = false;
        try {
            chain.doFilter(request, response);
            answered = true;
        } finally {
            measure(request, response, answered, Duration.ofNanos(System.nanoTime() - started));
        }
    }

    private void measure(HttpServletRequest request, HttpServletResponse response, boolean answered, Duration took) {
        String route = RequestRoute.of(request);
        String method = method(request);

        Counter
                .builder(MetricContract.HTTP_REQUESTS_TOTAL)
                .description("Requests this connector has served")
                .tag("method", method)
                .tag("route", route)
                .tag("status", status(response, answered))
                .register(registry)
                .increment();

        Timer
                .builder(MetricContract.HTTP_REQUEST_DURATION_SECONDS)
                .description("How long this connector took to serve a request")
                .tag("method", method)
                .tag("route", route)
                .serviceLevelObjectives(MetricContract.httpServerBuckets())
                .register(registry)
                .record(took);
    }

    /**
     * The status the caller was answered with. A failure that escaped the whole chain has not reached the response yet,
     * and the container answers such a request as an internal error, so that is what it is counted as.
     */
    private static String status(HttpServletResponse response, boolean answered) {
        return String.valueOf(answered ? response.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR.value());
    }

    /** The method the caller used, where HTTP defines it, and one label for everything else. */
    private static String method(HttpServletRequest request) {
        String method = request.getMethod();
        return DEFINED_METHODS.contains(method) ? method : OTHER_METHOD;
    }
}
