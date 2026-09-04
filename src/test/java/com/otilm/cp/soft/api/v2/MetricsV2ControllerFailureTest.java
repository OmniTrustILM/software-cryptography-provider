package com.otilm.cp.soft.api.v2;

import com.otilm.cp.soft.exception.MetricsUnavailableException;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.metrics.core.metrics.GaugeWithCallback;
import io.prometheus.metrics.expositionformats.OpenMetricsTextFormatWriter;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A scrape that cannot be answered is reported as a service that is momentarily unavailable, and nothing about the
 * format it would have been answered in is declared, since the answer is a problem document instead.
 */
class MetricsV2ControllerFailureTest {

    @Test
    void reportsMetricsThatCouldNotBeReadAsUnavailable() {
        // given
        MockHttpServletResponse response = new MockHttpServletResponse();
        MetricsV2ControllerImpl controller = new MetricsV2ControllerImpl(unreadable(), asking(), response);

        // when
        // then
        assertThrows(MetricsUnavailableException.class, controller::getMetrics);
        assertNull(response.getContentType(), "an exposition that was not written is not declared either");
    }

    /**
     * A registry holding two readings of the same name, which is refused when the exposition is written rather than
     * when the readings are taken.
     */
    private static PrometheusMeterRegistry unreadable() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        Gauge.builder("two_of_these", () -> 1).description("one of them").register(registry);
        GaugeWithCallback
                .builder()
                .name("two_of_these")
                .help("the other")
                .callback(reading -> reading.call(1))
                .register(registry.getPrometheusRegistry());
        return registry;
    }

    private static MockHttpServletRequest asking() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/metrics");
        request.addHeader(HttpHeaders.ACCEPT, OpenMetricsTextFormatWriter.CONTENT_TYPE);
        return request;
    }
}
