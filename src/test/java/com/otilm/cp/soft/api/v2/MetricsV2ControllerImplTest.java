package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.common.v2.MetricsController;
import io.prometheus.metrics.expositionformats.OpenMetricsTextFormatWriter;
import io.prometheus.metrics.expositionformats.PrometheusTextFormatWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A collector reads this connector's metrics here. What it reads has to carry the metrics the interfaces require, under
 * the names they state, in whichever of the two exposition formats it asked for.
 */
@SpringBootTest
@AutoConfigureMockMvc
class MetricsV2ControllerImplTest {

    private static final String METRICS = "/v1/metrics";

    /**
     * The two metrics of outbound calls are the interfaces' only requirements this connector does not answer: it makes
     * no outbound calls of its own, and a metric of calls that cannot happen would tell a collector nothing.
     */
    private static final Set<String> NOT_APPLICABLE = Set
            .of("http_client_requests_total", "http_client_request_duration_seconds");

    private MockMvc mockMvc;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    /**
     * Each one has to be there under the name the interfaces give it and as the kind of metric they say it is, so both
     * are read from the specification rather than written out here.
     */
    @Test
    void exposesEveryMetricTheInterfacesRequireOfThisConnector() throws Exception {
        // given
        String exposition = scrapeAfterARequest();

        // when
        // then
        for (Map<String, Object> required : requiredMetricsAsDescribed()) {
            String name = String.valueOf(required.get("name"));
            if (!NOT_APPLICABLE.contains(name)) {
                String declared = "# TYPE " + name + " " + required.get("type");
                assertTrue(exposition.contains(declared), () -> "expected " + declared + ", got " + exposition);
            }
        }
    }

    @Test
    void leavesOutTheMetricsOfOutboundCallsItNeverMakes() throws Exception {
        // given
        String exposition = scrapeAfterARequest();

        // when
        // then
        for (String notApplicable : NOT_APPLICABLE) {
            assertFalse(exposition.contains(notApplicable),
                    () -> "expected no " + notApplicable + ", got " + exposition);
        }
        assertTrue(requiredMetrics().containsAll(NOT_APPLICABLE), "the interfaces no longer require these at all");
    }

    /** In either format, since a collector is told it may read either and the build is what identifies the process. */
    @Test
    void namesTheBuildItIsRunningInEitherFormat() throws Exception {
        // given
        String named = "(?s).*app_build_info\\{commit=\"[^\"]+\",runtime=\"java-\\d+\"," + "version=\"[^\"]+\"\\} 1.*";

        // when
        // then
        assertTrue(scrape().matches(named), "expected the build in the Prometheus text format");
        assertTrue(scrape(OpenMetricsTextFormatWriter.CONTENT_TYPE).matches(named),
                "expected the build in the OpenMetrics format");
    }

    @Test
    void answersInOpenMetricsWhenTheCollectorAsksForIt() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get(METRICS).header(HttpHeaders.ACCEPT, OpenMetricsTextFormatWriter.CONTENT_TYPE))
                .andExpect(status().isOk())
                .andExpect(result -> assertEquals(OpenMetricsTextFormatWriter.CONTENT_TYPE,
                        result.getResponse().getContentType()))
                .andExpect(result -> assertTrue(result.getResponse().getContentAsString().endsWith("# EOF\n")));
    }

    @Test
    void answersInPrometheusTextWhenTheCollectorAsksForIt() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get(METRICS).header(HttpHeaders.ACCEPT, PrometheusTextFormatWriter.CONTENT_TYPE))
                .andExpect(status().isOk())
                .andExpect(result -> assertEquals(PrometheusTextFormatWriter.CONTENT_TYPE,
                        result.getResponse().getContentType()))
                .andExpect(result -> assertFalse(result.getResponse().getContentAsString().contains("# EOF")));
    }

    /** A collector that asks for anything in particular gets what it asked for, whatever it puts it beside. */
    @Test
    void answersInTheFormatWithTheHighestQualityTheCollectorGaveIt() throws Exception {
        // given
        String accept = "application/openmetrics-text; version=1.0.0; charset=utf-8; q=0.75,"
                + "text/plain; version=0.0.4; charset=utf-8; q=0.5,*/*; q=0.1";

        // when
        // then
        mockMvc
                .perform(get(METRICS).header(HttpHeaders.ACCEPT, accept))
                .andExpect(status().isOk())
                .andExpect(result -> assertEquals(OpenMetricsTextFormatWriter.CONTENT_TYPE,
                        result.getResponse().getContentType()));
    }

    @Test
    void answersInPrometheusTextWhenThatIsTheFormatWithTheHighestQuality() throws Exception {
        // given
        String accept = "text/plain; version=0.0.4; charset=utf-8; q=0.9,"
                + "application/openmetrics-text; version=1.0.0; charset=utf-8; q=0.5";

        // when
        // then
        mockMvc
                .perform(get(METRICS).header(HttpHeaders.ACCEPT, accept))
                .andExpect(status().isOk())
                .andExpect(result -> assertEquals(PrometheusTextFormatWriter.CONTENT_TYPE,
                        result.getResponse().getContentType()));
    }

    /**
     * A collector that states no preference, asks for something neither format satisfies, or sends a header that cannot
     * be read at all is answered in the preferred format rather than turned away: it is here to read metrics, and
     * metrics it can read are worth more to it than a refusal.
     */
    @Test
    void answersInThePreferredFormatWhenTheCollectorAsksForNothingItServes() throws Exception {
        // given
        List<String> asked = List.of("*/*", "application/json", "text/html,*/*;q=0.8", "not a media type", "");

        // when
        // then
        for (String accept : asked) {
            mockMvc
                    .perform(get(METRICS).header(HttpHeaders.ACCEPT, accept))
                    .andExpect(status().isOk())
                    .andExpect(result -> assertEquals(OpenMetricsTextFormatWriter.CONTENT_TYPE,
                            result.getResponse().getContentType(), () -> "asked for " + accept));
        }
    }

    @Test
    void answersInThePreferredFormatWhenTheCollectorAsksForNothing() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get(METRICS))
                .andExpect(status().isOk())
                .andExpect(result -> assertEquals(OpenMetricsTextFormatWriter.CONTENT_TYPE,
                        result.getResponse().getContentType()));
    }

    /**
     * A path carries token and key identifiers, and a series for each of them would grow without limit, so a request is
     * labelled by the route it matched.
     */
    @Test
    void labelsARequestByItsRouteRatherThanThePathItAskedFor() throws Exception {
        // given
        UUID token = UUID.randomUUID();
        mockMvc.perform(get("/v1/cryptographyProvider/tokens/" + token + "/keys"));

        // when
        String exposition = scrape();

        // then
        assertTrue(exposition.contains("route=\"/v1/cryptographyProvider/tokens/{uuid}/keys\""),
                () -> "expected the route, got " + exposition);
        assertFalse(exposition.contains(token.toString()), () -> "expected no identifier, got " + exposition);
    }

    @Test
    void reportsHowManyRequestsItIsServingWhileItIsServingThisOne() throws Exception {
        // given
        // when
        String exposition = scrape();

        // then
        assertTrue(exposition.contains("http_server_in_flight_requests{route=\"" + METRICS + "\"} 1.0"),
                () -> "expected this request to be in flight, got " + exposition);
    }

    @Test
    void timesARequestOverTheBucketsTheInterfacesState() throws Exception {
        // given
        String exposition = scrapeAfterARequest();

        // when
        // then
        for (Object bucket : buckets()) {
            assertTrue(exposition.contains("le=\"" + bucket + "\""),
                    () -> "expected the bucket " + bucket + ", got " + exposition);
        }
    }

    /** The count and the timing of a request are recorded once it is served, so one has to have been served first. */
    private String scrapeAfterARequest() throws Exception {
        mockMvc.perform(get(METRICS)).andExpect(status().isOk());
        return scrape();
    }

    private String scrape() throws Exception {
        return scrape(PrometheusTextFormatWriter.CONTENT_TYPE);
    }

    private String scrape(String format) throws Exception {
        return mockMvc
                .perform(get(METRICS).header(HttpHeaders.ACCEPT, format))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private static List<String> requiredMetrics() {
        return requiredMetricsAsDescribed().stream().map(metric -> String.valueOf(metric.get("name"))).toList();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> requiredMetricsAsDescribed() {
        return (List<Map<String, Object>>) MetricsController.METRICS_CONFIG.get("required");
    }

    @SuppressWarnings("unchecked")
    private static List<Double> buckets() {
        return (List<Double>) ((Map<String, Object>) MetricsController.METRICS_CONFIG.get("histograms"))
                .get("http_server_latency_buckets_seconds");
    }
}
