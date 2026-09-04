package com.otilm.cp.soft.metrics;

import com.otilm.api.interfaces.connector.common.v2.MetricsController;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * The metrics the connector interfaces require, read from the interfaces themselves.
 *
 * <p>
 * The names and the buckets are part of the contract rather than choices made here, so they are taken from the
 * machine-readable specification the interfaces publish instead of written out again. A metric the interfaces stop
 * requiring, or rename, fails this connector at startup rather than leaving it publishing a metric nothing scrapes.
 * </p>
 */
final class MetricContract {

    static final String APP_BUILD_INFO = name("app_build_info");

    static final String PROCESS_CPU_SECONDS_TOTAL = name("process_cpu_seconds_total");

    static final String PROCESS_RESIDENT_MEMORY_BYTES = name("process_resident_memory_bytes");

    static final String HTTP_REQUESTS_TOTAL = name("http_requests_total");

    static final String HTTP_REQUEST_DURATION_SECONDS = name("http_request_duration_seconds");

    static final String HTTP_SERVER_IN_FLIGHT_REQUESTS = name("http_server_in_flight_requests");

    static final String CONNECTOR_EVENTS_TOTAL = name("connector_events_total");

    /** The buckets stated for the latency of a request this connector serves, which are stated in seconds. */
    private static final List<Duration> HTTP_SERVER_BUCKETS = buckets("http_server_latency_buckets_seconds");

    private static final double NANOSECONDS_PER_SECOND = 1_000_000_000d;

    private MetricContract() {
    }

    static Duration[] httpServerBuckets() {
        return HTTP_SERVER_BUCKETS.toArray(new Duration[0]);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> required() {
        return (List<Map<String, Object>>) MetricsController.METRICS_CONFIG.get("required");
    }

    private static String name(String required) {
        return required()
                .stream()
                .map(metric -> String.valueOf(metric.get("name")))
                .filter(required::equals)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(required + " is not a metric the interfaces require"));
    }

    @SuppressWarnings("unchecked")
    private static List<Duration> buckets(String histogram) {
        Map<String, Object> histograms = (Map<String, Object>) MetricsController.METRICS_CONFIG.get("histograms");
        List<Double> seconds = (List<Double>) histograms.get(histogram);
        if (seconds == null) {
            throw new IllegalStateException(histogram + " is not a histogram the interfaces describe");
        }
        return seconds.stream().map(bucket -> Duration.ofNanos(Math.round(bucket * NANOSECONDS_PER_SECOND))).toList();
    }
}
