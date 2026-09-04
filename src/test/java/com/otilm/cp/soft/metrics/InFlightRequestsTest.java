package com.otilm.cp.soft.metrics;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerMapping;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A request counted in and never counted out would leave the reading climbing for as long as the connector runs, so
 * every way a request can leave gives back what arriving took.
 */
class InFlightRequestsTest {

    private PrometheusMeterRegistry registry;

    private InFlightRequests inFlight;

    @BeforeEach
    void freshRegistry() {
        registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        inFlight = new InFlightRequests(registry);
    }

    @Test
    void countsARequestWhileItIsBeingServed() {
        // given
        HttpServletRequest request = arriving("/v2/keys/create");

        // when
        inFlight.preHandle(request, new MockHttpServletResponse(), this);

        // then
        assertServing("/v2/keys/create", 1);
    }

    @Test
    void stopsCountingItOnceItIsServed() {
        // given
        HttpServletRequest request = arriving("/v2/keys/create");
        inFlight.preHandle(request, new MockHttpServletResponse(), this);

        // when
        inFlight.afterCompletion(request, new MockHttpServletResponse(), this, null);

        // then
        assertServing("/v2/keys/create", 0);
    }

    /**
     * A request handed off to be finished later is counted again when it resumes, so it is given back at the hand-off.
     */
    @Test
    void stopsCountingItWhenItIsHandedOffToBeFinishedLater() {
        // given
        HttpServletRequest request = arriving("/v2/keys/create");
        inFlight.preHandle(request, new MockHttpServletResponse(), this);

        // when
        inFlight.afterConcurrentHandlingStarted(request, new MockHttpServletResponse(), this);

        // then
        assertServing("/v2/keys/create", 0);
    }

    /** A path with no route behind it is counted under one label, since counting each path would have no limit. */
    @Test
    void countsARequestThatMatchedNoRouteUnderOneLabel() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/nothing/here");

        // when
        inFlight.preHandle(request, new MockHttpServletResponse(), this);

        // then
        assertServing("unmatched", 1);
    }

    private static MockHttpServletRequest arriving(String route) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", route);
        request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, route);
        return request;
    }

    private void assertServing(String route, int expected) {
        String series = "http_server_in_flight_requests{route=\"" + route + "\"} " + expected + ".0";
        String exposition = registry.scrape();
        assertTrue(exposition.contains(series), () -> "expected " + series + ", got " + exposition);
    }
}
