package com.otilm.cp.soft.metrics;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import jakarta.servlet.ServletException;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerMapping;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What a request is counted under is what an operator alerts on, so it has to say what the caller was actually answered
 * with, and it has to come from a set this connector controls rather than from what the caller wrote.
 */
class HttpServerMetricsFilterTest {

    private static final String ROUTE = "/v2/keys/create";

    private PrometheusMeterRegistry registry;

    private HttpServerMetricsFilter filter;

    @BeforeEach
    void freshRegistry() {
        registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        filter = new HttpServerMetricsFilter(registry);
    }

    @Test
    void countsARequestUnderTheStatusItWasAnsweredWith() throws ServletException, IOException {
        // given
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(404);

        // when
        filter.doFilter(request("POST"), response, new MockFilterChain());

        // then
        assertCounted("method=\"POST\",route=\"" + ROUTE + "\",status=\"404\"");
    }

    /**
     * A failure that escapes the whole chain has not reached the response, which still reads as the status it was
     * created with. The container answers such a request as an internal error, so counting the response would say the
     * caller was answered with something it never saw.
     */
    @Test
    void countsARequestWhoseFailureEscapedAsTheErrorTheCallerIsAnsweredWith() {
        // given
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        assertThrows(ServletException.class, () -> filter.doFilter(request("POST"), response, (in, out) -> {
            throw new ServletException("the token could not be opened");
        }));

        // then
        assertCounted("method=\"POST\",route=\"" + ROUTE + "\",status=\"500\"");
    }

    /**
     * HTTP lets a caller name a method as freely as it names a path, so a caller that invented one would otherwise add
     * a series for every name it invents.
     */
    @Test
    void countsAMethodItDoesNotKnowUnderOneLabel() throws ServletException, IOException {
        // given
        // when
        filter.doFilter(request("WHATEVER-1"), new MockHttpServletResponse(), new MockFilterChain());
        filter.doFilter(request("WHATEVER-2"), new MockHttpServletResponse(), new MockFilterChain());

        // then
        assertCounted("method=\"other\",route=\"" + ROUTE + "\",status=\"200\"} 2.0");
        String exposition = registry.scrape();
        assertTrue(!exposition.contains("WHATEVER"), () -> "expected no invented method, got " + exposition);
    }

    @Test
    void timesARequestOverTheBucketsTheInterfacesStateAndNothingElse() throws ServletException, IOException {
        // given
        // when
        filter.doFilter(request("GET"), new MockHttpServletResponse(), new MockFilterChain());

        // then
        String exposition = registry.scrape();
        for (java.time.Duration bucket : MetricContract.httpServerBuckets()) {
            String le = "http_request_duration_seconds_bucket{method=\"GET\",route=\"" + ROUTE + "\",le=\""
                    + seconds(bucket) + "\"}";
            assertTrue(exposition.contains(le), () -> "expected " + le + ", got " + exposition);
        }
    }

    /** The buckets are stated in seconds, which is how the exposition names them. */
    private static String seconds(java.time.Duration bucket) {
        double value = bucket.toNanos() / 1_000_000_000d;
        return value == Math.rint(value) ? String.valueOf(value) : String.valueOf((float) value);
    }

    private static MockHttpServletRequest request(String method) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, ROUTE);
        request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, ROUTE);
        return request;
    }

    private void assertCounted(String series) {
        String exposition = registry.scrape();
        assertTrue(exposition.contains("http_requests_total{" + series),
                () -> "expected http_requests_total{" + series + ", got " + exposition);
    }
}
